package zhou.solab.tools

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * R9 自动验收（蓝图 Week 3~4）：端侧安装通道。
 *
 * SoLab 本身运行在设备上，"adb install" 的等价物是 PackageInstaller 会话：
 * 流式写入 APK → commit（带 PendingIntent 回执）→ 系统安装器执行安装并做
 * 系统验签 → 广播回传结构化状态。STATUS_PENDING_USER_ACTION 时拉起系统
 * 确认页（安装由用户在屏幕上确认，符合纪律：自动检查不绕过人工同意）。
 *
 * 状态口径：install SUCCESS 才构成 Verified 的设备侧证据（蓝图 §5.4 /
 * §10.5）；任何失败都带机器可读 failureReason（§5.4「安装失败原因结构化」）。
 */
object ApkInstallTool {

    const val ACTION_INSTALL_STATUS = "zhou.solab.INSTALL_STATUS"

    /** 用户确认页可能停留很久：默认 5 分钟超时（结构化 TIMEOUT，可重试）。 */
    const val DEFAULT_TIMEOUT_MS = 5L * 60 * 1000

    private val pending =
        ConcurrentHashMap<Int, (Map<String, Any?>) -> Unit>()

    // lazy：单测只测纯映射函数时不触发 Looper 桩（unit test android.jar 无实现）。
    private val mainHandler: Handler by lazy { Handler(Looper.getMainLooper()) }

    @Volatile
    private var receiverRegistered = false

    /** PackageInstaller 状态码 → 结构化标签（纯函数，可单测）。 */
    fun statusLabel(status: Int): String =
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> "PENDING_USER_ACTION"
            PackageInstaller.STATUS_SUCCESS -> "SUCCESS"
            PackageInstaller.STATUS_FAILURE -> "FAILURE"
            PackageInstaller.STATUS_FAILURE_BLOCKED -> "BLOCKED"
            PackageInstaller.STATUS_FAILURE_ABORTED -> "ABORTED"
            PackageInstaller.STATUS_FAILURE_INVALID -> "INVALID"
            PackageInstaller.STATUS_FAILURE_CONFLICT -> "CONFLICT"
            PackageInstaller.STATUS_FAILURE_STORAGE -> "STORAGE"
            PackageInstaller.STATUS_FAILURE_INCOMPATIBLE -> "INCOMPATIBLE"
            else -> "UNKNOWN"
        }

    /** 结构化安装失败原因（蓝图 §5.4「安装失败原因结构化」；纯函数，可单测）。 */
    fun failureReason(label: String): String =
        when (label) {
            "BLOCKED" -> "INSTALL_BLOCKED_BY_SOURCE"
            "CONFLICT" -> "INSTALL_CONFLICT_SIGNATURE_OR_VERSION"
            "INVALID" -> "INSTALL_INVALID_APK"
            "STORAGE" -> "INSTALL_STORAGE_FULL"
            "INCOMPATIBLE" -> "INSTALL_INCOMPATIBLE_ABI_OR_SDK"
            "ABORTED" -> "INSTALL_ABORTED_BY_USER"
            "TIMEOUT" -> "INSTALL_USER_CONFIRMATION_TIMEOUT"
            "SESSION_ERROR" -> "INSTALL_SESSION_ERROR"
            "PENDING_USER_ACTION", "SUCCESS" -> ""
            else -> "INSTALL_FAILED"
        }

    /**
     * 安装 APK：commit 后挂起等待广播终端状态（或超时）。
     * [onStatus] 恰好被调用一次；调用方可安全地在 MethodChannel 上回复。
     */
    fun install(
        context: Context,
        apkPath: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        onStatus: (Map<String, Any?>) -> Unit,
    ) {
        val apk = File(apkPath)
        if (!apk.isFile) {
            onStatus(
                mapOf(
                    "installStatus" to "APK_NOT_FOUND",
                    "failureReason" to "ARTIFACT_MISSING",
                    "message" to "APK 不存在: $apkPath",
                ),
            )
            return
        }
        ensureReceiver(context)
        val sessionParams =
            PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        var session: PackageInstaller.Session? = null
        try {
            val sessionId =
                context.packageManager.packageInstaller.createSession(sessionParams)
            session = context.packageManager.packageInstaller.openSession(sessionId)
            session.openWrite("solab_apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val intent =
                Intent(ACTION_INSTALL_STATUS).setPackage(context.packageName)
            val pi =
                PendingIntent.getBroadcast(
                    context,
                    sessionId,
                    intent,
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
            pending[sessionId] = onStatus
            scheduleTimeout(context, sessionId, timeoutMs)
            session.commit(pi.intentSender)
            session = null
        } catch (e: Exception) {
            runCatching { session?.abandon() }
            onStatus(
                mapOf(
                    "installStatus" to "SESSION_ERROR",
                    "failureReason" to failureReason("SESSION_ERROR"),
                    "message" to "${e.javaClass.simpleName}: ${e.message ?: "安装会话创建失败"}",
                ),
            )
        }
    }

    private fun scheduleTimeout(context: Context, sessionId: Int, timeoutMs: Long) {
        mainHandler.postDelayed(
            {
                val waiting = pending.remove(sessionId)
                if (waiting != null) {
                    // C14（阶段 0）：超时必须放弃会话——此前只移除回调不 abandon，
                    // 系统侧会话仍活着：用户迟点确认页会真装上，但广播回来时
                    // pending 已空、迟到终端状态被丢，报告（TIMEOUT）与设备实际
                    // （可能已安装）不一致。abandon 让确认页失效、会话终止。
                    runCatching {
                        context.packageManager.packageInstaller.abandonSession(sessionId)
                    }
                    waiting(
                        mapOf(
                            "installStatus" to "TIMEOUT",
                            "failureReason" to failureReason("TIMEOUT"),
                            "sessionId" to sessionId,
                            "message" to "用户确认超时（${timeoutMs / 1000}s）：会话已放弃，如需安装请重新发起（可重试）",
                        ),
                    )
                }
            },
            timeoutMs,
        )
    }

    private fun ensureReceiver(context: Context) {
        if (receiverRegistered) return
        synchronized(this) {
            if (receiverRegistered) return
            val receiver =
                object : BroadcastReceiver() {
                    override fun onReceive(ctx: Context, intent: Intent) {
                        val sessionId =
                            intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)
                        val callback = pending.remove(sessionId) ?: return
                        val status =
                            intent.getIntExtra(
                                PackageInstaller.EXTRA_STATUS,
                                PackageInstaller.STATUS_FAILURE,
                            )
                        val label = statusLabel(status)
                        if (label == "PENDING_USER_ACTION") {
                            // 系统确认页：拉起后继续等待终端状态（不完成回调）。
                            pending[sessionId] = callback
                            @Suppress("DEPRECATION")
                            val confirm =
                                intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                            if (confirm != null) {
                                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                runCatching { ctx.startActivity(confirm) }
                            }
                            return
                        }
                        val message =
                            intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                        callback(
                            buildMap {
                                put("installStatus", label)
                                put("sessionId", sessionId)
                                if (message != null) put("message", message)
                                if (label != "SUCCESS") {
                                    put("failureReason", failureReason(label))
                                }
                            },
                        )
                    }
                }
            val filter = IntentFilter(ACTION_INSTALL_STATUS)
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                context.registerReceiver(receiver, filter)
            }
            receiverRegistered = true
        }
    }
}
