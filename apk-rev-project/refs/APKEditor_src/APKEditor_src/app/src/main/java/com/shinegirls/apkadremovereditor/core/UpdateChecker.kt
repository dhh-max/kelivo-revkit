package com.shinegirls.apkadremovereditor.core

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

/**
 * 应用更新检测器。
 *
 * 从配置的版本清单地址拉取最新版本信息，与当前安装版本比对：
 * - 无更新：提示已是最新版本
 * - 有普通更新：弹出更新对话框，用户可选择"稍后"或"立即更新"
 * - 有强制更新：弹出不可取消的强制更新对话框，必须更新后才能继续使用
 *
 * 远程版本清单为 JSON 格式，字段如下：
 * {
 *   "versionCode": 2,              // 最新版本号（整数，必须大于当前版本才提示）
 *   "versionName": "1.1",          // 最新版本名称（展示用）
 *   "force": false,                // 是否强制更新
 *   "description": "更新内容...",  // 更新说明
 *   "url": "https://.../app.apk"   // 新版 APK 下载地址
 * }
 */
object UpdateChecker {

    /** 默认版本清单地址（如无自建服务器，可替换为自己的地址）。 */
    const val DEFAULT_CHECK_URL =
        "https://raw.githubusercontent.com/shinegirls/apk-ad-remover/master/version.json"

    private const val PREFS_NAME = "update_checker"

    /** 网络超时（毫秒）。 */
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 15_000

    /** 最新版本信息。 */
    data class UpdateInfo(
        val versionCode: Long,
        val versionName: String,
        val forceUpdate: Boolean,
        val description: String,
        val downloadUrl: String
    )

    /**
     * 获取当前自己管理的检查地址。
     */
    fun getCheckUrl(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString("check_url", DEFAULT_CHECK_URL) ?: DEFAULT_CHECK_URL
    }

    /**
     * 保存检查地址。
     */
    fun setCheckUrl(context: Context, url: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString("check_url", url.trim())
            .apply()
    }

    /**
     * 获取当前安装版本号（versionCode）。
     */
    fun getCurrentVersionCode(context: Context): Long {
        return try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionCode.toLong()
        } catch (_: PackageManager.NameNotFoundException) {
            0L
        }
    }

    /**
     * 获取当前安装版本名称（versionName）。
     */
    fun getCurrentVersionName(context: Context): String {
        return try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "1.0"
        } catch (_: PackageManager.NameNotFoundException) {
            "1.0"
        }
    }

    /**
     * 从远程地址拉取版本清单并解析（同步调用，需在子线程执行）。
     *
     * @return 解析后的 UpdateInfo；网络失败、JSON 非法返回 null。
     */
    fun fetchLatestUpdate(checkUrl: String): UpdateInfo? {
        return try {
            val url = URL(checkUrl)
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "APKAdRemoverEditor/1.0")
                instanceFollowRedirects = true
            }
            try {
                val code = conn.responseCode
                if (code !in 200..299) return null
                val sb = StringBuilder()
                BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8)).use { reader ->
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        sb.append(line).append('\n')
                    }
                }
                parseUpdateInfo(sb.toString().trim())
            } finally {
                conn.disconnect()
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun parseUpdateInfo(jsonStr: String): UpdateInfo? {
        return try {
            val json = JSONObject(jsonStr)
            if (!json.has("versionCode") || !json.has("url")) return null
            UpdateInfo(
                versionCode = json.getLong("versionCode"),
                versionName = json.optString("versionName", ""),
                forceUpdate = json.optBoolean("force", false),
                description = json.optString("description", ""),
                downloadUrl = json.getString("url")
            )
        } catch (_: Exception) {
            null
        }
    }

    /**
     * 在 UI 线程显示更新结果对话框。
     *
     * @param activity 宿主 Activity
     * @param info 已拉取到的最新版本信息，null 表示网络/解析失败
     */
    fun showResult(activity: Activity, info: UpdateInfo?) {
        if (info == null) {
            Toast.makeText(activity, "检查更新失败，请检查网络后重试", Toast.LENGTH_SHORT).show()
            return
        }

        val currentCode = getCurrentVersionCode(activity)
        if (info.versionCode <= currentCode) {
            Toast.makeText(activity, "已是最新版本 (${getCurrentVersionName(activity)})", Toast.LENGTH_SHORT).show()
            return
        }

        val versionText = if (info.versionName.isBlank()) "${info.versionCode}" else "${info.versionName} (${info.versionCode})"
        val message = buildString {
            append("发现新版本 v$versionText\n\n")
            if (info.description.isNotBlank()) {
                append("更新内容：\n${info.description}\n\n")
            }
            append("当前版本：v${getCurrentVersionName(activity)}")
        }

        val builder = AlertDialog.Builder(activity)
            .setTitle(if (info.forceUpdate) "发现新版本（必须更新）" else "发现新版本")
            .setMessage(message)

        if (info.forceUpdate) {
            // 强制更新：禁止取消，点"立即更新"跳转下载
            builder.setCancelable(false)
                .setPositiveButton("立即更新") { _, _ -> openDownload(activity, info.downloadUrl) }
                .show()
        } else {
            // 普通更新：可"稍后"
            builder.setCancelable(true)
                .setPositiveButton("立即更新") { _, _ -> openDownload(activity, info.downloadUrl) }
                .setNegativeButton("稍后再说", null)
                .show()
        }
    }

    /**
     * 用系统浏览器打开新版 APK 下载地址。
     */
    private fun openDownload(activity: Activity, url: String) {
        try {
            activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (_: Exception) {
            Toast.makeText(activity, "无法打开下载地址", Toast.LENGTH_SHORT).show()
        }
    }
}