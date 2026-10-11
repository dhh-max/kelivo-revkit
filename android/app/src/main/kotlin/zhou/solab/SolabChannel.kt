package zhou.solab

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.util.Locale
import java.util.LinkedHashMap
import java.util.zip.ZipFile
import zhou.solab.tools.SolabJadxTool
import zhou.solab.tools.SolabApkBuildTool
import zhou.solab.tools.FridaGadgetTool
import zhou.solab.tools.SolabApkEditorTool
import zhou.solab.tools.SolabDexKitTool
import zhou.solab.tools.SolabStringScanTool
import zhou.solab.tools.ApkArchiveTool
import zhou.solab.tools.ApkZipCache
import zhou.solab.tools.DexXrefEngine
import zhou.solab.tools.ClassOutlineEngine
import zhou.solab.tools.SmaliReadTool
import zhou.solab.engine.FieldRefsIndexStore
import zhou.solab.engine.BlutterSearchIndex
import zhou.solab.engine.NativeSoEngine
import zhou.solab.tools.err
import zhou.solab.tools.DexIo
import zhou.solab.tools.ApkAdRules
import zhou.solab.tools.ApkInstallTool
import zhou.solab.tools.ApkRulesStore
import zhou.solab.tools.SettingsStore

/** SoLab APK 的确定性本地分析入口；不上传 APK，也不执行未确认的删除。 */
class SolabChannel(
    private val context: Context,
    messenger: BinaryMessenger,
) : MethodChannel.MethodCallHandler {

    // ── APK ZipFile 进程级缓存 ────────────────────────────────────────────
    // 见 ApkZipCache：句柄按 path+mtime+size 指纹失效 + 引用计数 pin
    // （防 2 个 worker 轮转第 3 个 APK 时 LRU 驱逐 close 掉另一线程正在
    // 遍历的 ZipFile）。调用点一律 withApkZip，不再各自 use-close。
    @PublishedApi
    internal val apkZipCache: ApkZipCache = ApkZipCache.shared

    inline fun <R> withApkZip(source: File, block: (ZipFile) -> R): R =
        apkZipCache.withZip(source, block)
    private val channel = MethodChannel(messenger, "solab/workspace")
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * 重型工具名（走 heavyExecutor）：dex 全量解析/blutter/重建/签名/安装。
     *
     * 为什么必须与轻量工具分开（2026-09-15 真机 P0）：Agent 按策略会把多个
     * 只读探针压在**同一轮**并发发出，共享池一旦被 blutter/dex 全量解析占满，
     * `file(action=write)`、能力查询这类毫秒级调用就要排队 46s+，看起来像
     * 「工具挂了」。两池隔离后，轻量工具永远不排在重型分析后面。
     */
    private val heavyMethods = setOf(
        "patchDexMethods", "patchDexStrings", "patchManifest", "apkRebuild",
        "jadxDecompile", "dexSearch", "soAnalyze", "analyzeApk",
        "apkSign", "signatureBypass", "installApk",
        "classOutline", "dexXref", "smaliRead", "stringScan", "fieldXref",
    )

    private val lightSoAnalyzeActions = setOf(
        "read_elf", "read_stats", "hexdump", "strings", "list", "overview",
        "analysis_report", "crypto_scan", "jni_bridge",
        "workspaces", "list_sources", "list_builds", "list_audits",
        "asset_status", "suggest", "capabilities", "handles",
        "diff", "rz_diff", "audit", "audit_load", "status",
    )

    private val lightBlutterActions = setOf(
        "pool", "status", "result", "report", "packages",
        "xref", "callers", "disasm", "raw_strings", "inspect", "locate",
    )

    // MethodChannel 不只由 MCP 调用；设置页、快捷入口和自动任务可以绕过 Dart
    // 侧的 heavy gate。这里是原生最终闸门，确保两条高峰路径不会在同一进程叠加。
    // 它只串行重工具，所有轻工具仍走独立线程池，不牺牲交互能力。
    private val heavyExecutionGate = java.util.concurrent.Semaphore(1, true)

    private fun daemonThreadFactory(name: String) = java.util.concurrent.ThreadFactory { runnable ->
        Thread(runnable, name).apply { isDaemon = true }
    }

    /** 轻量工具池：至少 2 条线程（交互面不能被单个任务卡住），随档位放大。 */
    private val lightExecutor: java.util.concurrent.ExecutorService by lazy {
        java.util.concurrent.Executors.newFixedThreadPool(
            maxOf(2, zhou.solab.tools.DeviceProfile.asyncTaskThreads()),
            daemonThreadFactory("solab-light"),
        )
    }

    /** 重型工具池：并行度按设备档位（低端 1 = 串行，中端 2，旗舰 3）。 */
    private val heavyExecutor: java.util.concurrent.ExecutorService by lazy {
        java.util.concurrent.Executors.newFixedThreadPool(
            zhou.solab.tools.DeviceProfile.asyncTaskThreads(),
            daemonThreadFactory("solab-heavy"),
        )
    }

    private fun executorFor(name: String): java.util.concurrent.ExecutorService =
        if (name in heavyMethods) heavyExecutor else lightExecutor

    private fun needsHeavyPermit(name: String, call: MethodCall?): Boolean {
        if (name !in heavyMethods || name != "soAnalyze") return name in heavyMethods
        val args = call?.arguments as? Map<*, *> ?: return true
        val action = args["action"]?.toString() ?: return true
        if (action == "blutter") return args["blutterAction"]?.toString() !in lightBlutterActions
        if (action == "search") {
            val scope = args["scope"]?.toString()?.lowercase(Locale.ROOT) ?: "pp"
            return scope != "pp"
        }
        return action !in lightSoAnalyzeActions
    }

    /** 直连原生入口也必须经过重任务闸门，不能绕过 runAsync。 */
    private fun executeHeavy(block: () -> Unit) {
        heavyExecutor.execute {
            heavyExecutionGate.acquireUninterruptibly()
            try {
                block()
            } finally {
                heavyExecutionGate.release()
            }
        }
    }

    /** 分析进度事件通道（Dart 侧监听进度条；analyze 线程内 emit）。 */
    private val progressChannel = EventChannel(messenger, "solab/progress")
    private var progressSink: EventChannel.EventSink? = null

    /** SO 引擎进度事件通道（so_analyze 长任务阶段上报）。 */
    private val soProgressChannel = EventChannel(messenger, "so_analyze/progress")
    private var soProgressSink: EventChannel.EventSink? = null

    init {
        channel.setMethodCallHandler(this)
        progressChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                progressSink = events
            }

            override fun onCancel(arguments: Any?) {
                progressSink = null
            }
        })
        soProgressChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                soProgressSink = events
            }

            override fun onCancel(arguments: Any?) {
                soProgressSink = null
            }
        })
    }

    /** 从工作线程发进度事件（主线程回调，避免线程竞争）。 */
    private fun emitProgress(percent: Int, stage: String) {
        val sink = progressSink ?: return
        mainHandler.post {
            try {
                sink.success(mapOf("percent" to percent, "stage" to stage))
            } catch (_: Exception) {}
        }
    }

    /** SO 引擎进度（阶段 + percent）。 */
    private fun emitSoProgress(percent: Int, stage: String) {
        val sink = soProgressSink ?: return
        mainHandler.post {
            try {
                sink.success(mapOf("percent" to percent, "stage" to stage, "channel" to "so"))
            } catch (_: Exception) {}
        }
    }

    /** UI 线程安全回复：通道已销毁或重复回复时吞掉异常，避免崩 App。 */
    private fun replySafely(result: MethodChannel.Result, block: () -> Unit) {
        mainHandler.post {
            try {
                block()
            } catch (_: IllegalStateException) {
                // 通道已回复或已销毁：无投递目标，静默丢弃。
            } catch (_: Exception) {
                // 陈旧回复的其它异常同样不得崩 UI 线程。
            }
        }
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        // 输入体积预算：参数携带的文件输入（path/contentFile/locator）相对当前
        // 可用堆过大时提前拒绝——参数进入就把内存吃掉一大截、还没到工具执行。
        // 6 倍系数覆盖 zip 复制 + dex 展开的常规膨胀；普通几十 MB 的 APK 远够不着。
        checkInputBudget(call)?.let { budget ->
            result.success(budget)
            return
        }
        when (call.method) {
            // 工具耗时统计快照（C 批逐域体检 / D4 三指标读数出口；只读无副作用）
            // 必须经 jsonToMap 转成 Map/List：StandardMethodCodec 不能编码
            // org.json.JSONObject —— 直接回 JSONObject 会让通道抛编码异常、
            // Dart 侧 catch 后拿到空表（"toolStats 永远是 {}"的真根因，2026-09-20）。
            "toolStats" -> result.success(
                mapOf(
                    "ok" to true,
                    "stats" to jsonToMap(zhou.solab.tools.KotlinToolStats.snapshot()),
                ),
            )
            // 打断：AI 对话停止 / 用户取消时置位；新任务入口自动 reset
            "cancelTask" -> {
                zhou.solab.tools.TaskCancel.cancel()
                result.success(mapOf("ok" to true, "cancelled" to true))
            }
            "analyzeApk" -> {
                val path = arg(call, "path") as? String
                if (path.isNullOrBlank()) {
                    result.error("invalid_args", "缺少 APK 路径", null)
                } else {
                    executeHeavy {
                        try {
                            // 分析保持零附加负担：字段引用索引改为惰性后台构建
                            // （首次 field_xref 时触发，不阻塞查询），见 FieldRefsIndexStore。
                            val report = analyze(File(path))
                            replySafely(result) { result.success(report) }
                        } catch (error: Exception) {
                            replySafely(result) {
                                result.error(
                                    "analyze_failed",
                                    "${error.javaClass.simpleName}: ${error.message ?: "未知分析错误"}",
                                    error.stackTraceToString(),
                                )
                            }
                        } catch (error: Throwable) {
                            // Error 级兜底：OOM 逃逸出 catch(Exception) 会杀死进程（见 runAsync 同款注释）
                            replySafely(result) {
                                result.error(
                                    if (error is OutOfMemoryError) "JVM_OOM" else "analyze_fatal",
                                    "${error.javaClass.simpleName}: 堆耗尽或严重错误，任务已终止。等待释放后重试或重启 App 清堆。",
                                    null,
                                )
                            }
                        }
                    }
                }
            }

            "deleteZipEntries" -> runAsync(result, "deleteZipEntries") { deleteZipEntries(call) }

            "writeZipEntry" -> runAsync(result, "writeZipEntry") { writeZipEntry(call) }

            "buildApk" -> runAsync(result, "buildApk") { buildApk(call) }

            "listLibEntries" -> runAsync(result, "listLibEntries") { listLibEntries(call) }

            "patchDexMethods" -> runAsync(result, "patchDexMethods", call) { patchDexMethods(call) }

            "patchDexStrings" -> runAsync(result, "patchDexStrings", call) { patchDexStrings(call) }

            "setUserRules" -> runAsync(result, "setUserRules") { setUserRules(call) }

            // FieldRefs 模式（自适应三态，2026-09-02）：无参 = 查询当前模式；
            // 传 mode（auto/on/off）= 切换并持久化（SettingsStore 落库 + 进程内
            // 立即生效）。auto（默认）= 自适应：冷启动扫描开工，同一 APK 字段
            // 查询重复 ≥2 次后台自动建索引，建好后自动切索引查询；on = 始终预建；
            // off = 始终扫描。
            "fieldRefsIndexMode" -> {
                val mode = arg(call, "mode") as? String
                val settings = SettingsStore(context)
                if (mode != null) {
                    settings.fieldRefsIndexMode = mode
                    FieldRefsIndexStore.indexMode = settings.fieldRefsIndexMode
                } else {
                    FieldRefsIndexStore.indexMode = settings.fieldRefsIndexMode
                }
                result.success(mapOf("ok" to true, "mode" to FieldRefsIndexStore.indexMode))
            }

            // 语义索引是否跳过数据性/生成代码子树（B2-3，默认 false）：
            // 与 fieldRefsIndexMode 同款——传 enabled 写盘 + 同步进程镜像，不传只回读。
            // 改了开关会让已建索引判定为未就绪（meta 记了构建口径）并自动重建。
            "semanticIndexSkipNoisyPaths" -> {
                val settings = SettingsStore(context)
                val enabled = arg(call, "enabled")
                if (enabled is Boolean) {
                    settings.semanticIndexSkipNoisyPaths = enabled
                    BlutterSearchIndex.skipNoisySubtrees = enabled
                } else {
                    BlutterSearchIndex.skipNoisySubtrees = settings.semanticIndexSkipNoisyPaths
                }
                result.success(
                    mapOf("ok" to true, "enabled" to BlutterSearchIndex.skipNoisySubtrees),
                )
            }

            "restoreSourceApk" -> runAsync(result, "restoreSourceApk") { restoreSourceApk(call) }

            "checkStoragePermission" -> result.success(checkStoragePermission())

            "requestStoragePermission" -> result.success(requestStoragePermission())

            "patchManifest" -> runAsync(result, "patchManifest") { patchManifest(call) }

            "cleanAdAssets" -> runAsync(result, "cleanAdAssets") { cleanAdAssets(call) }

            // AI 按需分析：委托 ApkModuleAnalyzer（独立文件），一次只分析一个模块。
            "analyzeModule" -> {
                val path = arg(call, "path") as? String
                val module = arg(call, "module") as? String ?: ""
                val classPrefix = (arg(call, "classPrefix") as? String)?.trim() ?: ""
                // 问题2：methods 分页（36 dex 大包下 500 条上限配合 offset 取全量）
                val offset = (arg(call, "offset") as? Number)?.toInt() ?: 0
                val limit = (arg(call, "limit") as? Number)?.toInt() ?: 500
                if (path.isNullOrBlank()) {
                    result.error("invalid_args", "缺少 APK 路径", null)
                } else if (module !in ApkModuleAnalyzer.MODULES) {
                    result.error("invalid_module", "未知模块: $module（支持 ${ApkModuleAnalyzer.MODULES}）", null)
                } else {
                    executeHeavy {
                        try {
                            val payload = ApkModuleAnalyzer.analyzeModule(
                                context, File(path), module, classPrefix,
                                offset = offset, limit = limit,
                            )
                            replySafely(result) { result.success(payload) }
                        } catch (error: Exception) {
                            replySafely(result) {
                                result.error(
                                    "analyze_module_failed",
                                    "${error.javaClass.simpleName}: ${error.message ?: "分析失败"}",
                                    error.stackTraceToString(),
                                )
                            }
                        }
                    }
                }
            }

            // R9 自动验收（蓝图 Week 3~4）：PackageInstaller 会话安装 +
            // 系统验签。PENDING_USER_ACTION 拉起系统确认页（安装由用户在
            // 屏幕确认，不绕过人工同意）；终端状态或 5 分钟超时才完成通道
            // 回复，失败原因结构化（蓝图 §5.4）。
            "installApk" -> {
                val path = (arg(call, "path") as? String)?.trim() ?: ""
                if (path.isEmpty()) {
                    result.success(
                        mapOf(
                            "ok" to false,
                            "error" to mapOf(
                                "code" to "INVALID_ARGUMENT",
                                "message" to "缺少 path",
                                "recoverable" to true,
                            ),
                        ),
                    )
                } else {
                    executeHeavy {
                        ApkInstallTool.install(context, path) { status ->
                            val ok = status["installStatus"] == "SUCCESS"
                            replySafely(result) {
                                result.success(
                                    mapOf(
                                        "ok" to ok,
                                        "data" to status,
                                        if (!ok) {
                                            "error" to mapOf(
                                                "code" to (status["failureReason"] as? String ?: "INSTALL_FAILED"),
                                                "message" to (status["message"] ?: "安装未完成"),
                                                "recoverable" to true,
                                            )
                                        } else {
                                            "message" to "真机安装成功，系统验签通过"
                                        },
                                    ),
                                )
                            }
                        }
                    }
                }
            }

            // ===== M1: 玄星逆核工具链移植 =====
            // 信封契约：{ok:true,...} / {ok:false, error:{code,message,...}}，业务错误走 success
            "jadxDecompile" -> portedTool(call, result) { SolabJadxTool.handle(context, it) }
            "apkSign" -> portedTool(call, result) { SolabApkBuildTool.apkSign(context, it) }
            // Frida gadget 宿主侧：取件（下载+解压+校验）与注入（代理 Application + lib）
            "fridaGadget" -> portedTool(call, result) { FridaGadgetTool.handle(context, it) }
            // APKEditor 长任务：劫持其日志转进度事件（分钟级 decode/build 工作台可见实时进度）
            "apkRebuild" -> {
                val args = (call.arguments as? Map<*, *>)?.let { JSONObject(it) } ?: JSONObject()
                runAsync(result, "apkRebuild", call) {
                    @Suppress("UNCHECKED_CAST")
                    jsonToMap(SolabApkEditorTool.handle(context, args) { pct, stage ->
                        emitProgress(pct.coerceIn(1, 100), "APKEditor: $stage")
                    }) as Map<String, Any>
                }
            }
            "dexSearch" -> cachedReadEngine(call, result, "dexSearch") { SolabDexKitTool.handle(context, it) }
            "stringScan" -> cachedReadEngine(call, result, "stringScan") { SolabStringScanTool.handle(context, it) }
            "apkArchive" -> cachedReadEngine(call, result, "apkArchive") { ApkArchiveTool.handle(it) }
            "scanSignatureCheck" -> cachedReadEngine(call, result, "scanSignatureCheck") {
                // 显式 JSONArray 包装：Android org.json 对裸 Collection 走
                // value.toString()（产生 "[a, b]" 字符串）而非 JSONArray 包装，
                // 曾致 Dart 侧 hits 形状漂移为 String（真机 4 词命中被压扁）。
                org.json.JSONObject().put("ok", true)
                    .put("hits", org.json.JSONArray(scanSignatureCheck(File(it.optString("path")))))
            }
            // ===== M2: 自研引擎 =====
            "dexXref" -> cachedReadEngine(call, result, "dexXref") {
                DexXrefEngine.xref(
                    context = context,
                    apkPath = it.optString("path"),
                    target = it.optString("target"),
                    direction = it.optString("direction", "to"),
                    callerPrefix = it.optString("callerPrefix").ifBlank { it.optString("classPrefix") },
                    offset = it.optInt("offset", 0),
                    limit = it.optInt("limit", 50),
                    includeGraph = it.optBoolean("includeGraph", false),
                    callSiteOffset = it.optInt("callSiteOffset", 0),
                    callSiteLimit = it.optInt("callSiteLimit", 300),
                )
            }
            "fieldXref" -> cachedReadEngine(call, result, "fieldXref") {
                DexXrefEngine.fieldXref(
                    context = context,
                    apkPath = it.optString("path"),
                    fieldTarget = it.optString("fieldTarget"),
                    offset = if (it.has("offset") && !it.isNull("offset")) it.optInt("offset") else null,
                    limit = if (it.has("limit") && !it.isNull("limit")) it.optInt("limit") else null,
                )
            }
            "classOutline" -> cachedReadEngine(call, result, "classOutline") {
                ClassOutlineEngine.outline(
                    context = context,
                    apkPath = it.optString("path"),
                    className = it.optString("className"),
                    offset = it.optInt("offset", 0),
                    limit = it.optInt("limit", 200),
                    // 字段独立游标（2026-09-21）：缺省 0 与旧行为一致。
                    fieldsOffset = it.optInt("fieldsOffset", 0),
                )
            }
            "smaliRead" -> portedTool(call, result) {
                SmaliReadTool.smali(
                    context = context,
                    apkPath = it.optString("path"),
                    qualifiedId = it.optString("qualifiedId"),
                )
            }
            // ===== M3: SO 引擎 =====
            "soAnalyze" -> portedTool(call, result) { soEngineDispatch(it) }
            // ===== 文件管理（读写工作目录任意格式/压缩解压）=====
            "fileOps" -> portedTool(call, result) { zhou.solab.tools.FileOpsTool.handle(it) }

            else -> result.notImplemented()
        }
    }

    private fun analyze(apk: File): Map<String, Any> {
        require(apk.isFile && apk.length() > 0) { "APK 文件不存在或为空" }
        // 输入防护（借鉴玄星 ApkAnalyzer）：超限直接拒绝，避免大包拖垮内存
        if (apk.length() > MAX_ANALYZE_BYTES) {
            throw IllegalArgumentException("APK 超过 ${MAX_ANALYZE_BYTES / 1024 / 1024} MiB 分析上限，请先精简或改用按需分析")
        }
        val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or
            PackageManager.GET_PERMISSIONS or PackageManager.GET_META_DATA or
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }
        @Suppress("DEPRECATION")
        val packageInfo = context.packageManager.getPackageArchiveInfo(apk.absolutePath, flags)
        val appInfo = packageInfo?.applicationInfo?.apply {
            sourceDir = apk.absolutePath
            publicSourceDir = apk.absolutePath
        }
        // manifest 字节在主循环命中 AndroidManifest.xml 条目时顺手读入，
        // 摘要解析移到循环后（原先这里先整读一次 zip，循环后又开 ZipFile）。
        var manifestBytes: ByteArray? = null
        val rules = loadRules()
        val matchedPatterns = linkedSetOf<String>()
        val dexPatternMatches = linkedMapOf<String, List<String>>()
        val abis = linkedSetOf<String>()
        val candidates = mutableListOf<Map<String, Any>>()
        // 有界 top-20：10 万条目上限下全量累积 10 万个小 Map 再排序纯浪费。
        // （实现收敛到 ApkShared.offerLargest；调用处见下方 offerLargest(largestFiles, ...)）
        val largestFiles = mutableListOf<Map<String, Any>>()
        val nativeLibraryFiles = mutableListOf<Map<String, Any>>()
        val shellNames = linkedSetOf<String>()
        val shellLibs = mutableListOf<Map<String, Any>>()
        val fileTypeCounts = linkedMapOf<String, Int>()
        // v5 新增：DEX header 详情 / v1 签名文件 / Flutter 应用识别
        val dexDetails = mutableListOf<Map<String, Any>>()
        val v1SignatureFiles = mutableListOf<String>()
        val flutterAbis = linkedSetOf<String>()
        var flutterAssetCount = 0
        val runtimeEngines = linkedMapOf<String, MutableList<String>>()
        fun markEngine(engine: String, signal: String) {
            runtimeEngines.getOrPut(engine) { mutableListOf() }.add(signal)
        }
        var dex = 0
        var resources = 0
        var assets = 0
        var so = 0
        var totalFiles = 0
        var uncompressedBytes = 0L
        var compressedBytes = 0L

        withApkZip(apk) { zip ->
        val entryCount = zip.entries().asSequence().count { !it.isDirectory }
        emitProgress(5, "扫描 APK 结构")
        var processedEntries = 0
        zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
            processedEntries++
            totalFiles++
            if (totalFiles > MAX_ANALYZE_ENTRIES) {
                throw IllegalArgumentException("APK 条目数超过 $MAX_ANALYZE_ENTRIES，超出安全分析上限")
            }
            // 进度：文件扫描 5%→85%（按条目数折算）
            if (entryCount > 0 && processedEntries % 20 == 0) {
                val percent = 5 + (80L * processedEntries / entryCount).toInt()
                emitProgress(percent.coerceIn(5, 85), "扫描文件 $processedEntries/$entryCount")
            }
                val name = entry.name
                val lower = name.lowercase(Locale.ROOT)
                val size = entry.size.coerceAtLeast(0L)
                val compressedSize = entry.compressedSize.coerceAtLeast(0L)
                uncompressedBytes += size
                compressedBytes += compressedSize
                val extension = name.substringAfterLast('.', "(none)").lowercase(Locale.ROOT)
                fileTypeCounts[extension] = (fileTypeCounts[extension] ?: 0) + 1
                offerLargest(
                    largestFiles,
                    mapOf(
                        "path" to name,
                        "size" to size,
                        "compressedSize" to compressedSize,
                    ),
                )
                when {
                    name == "AndroidManifest.xml" -> {
                        runCatching {
                            manifestBytes = zip.getInputStream(entry).use { it.readBytes() }
                        }
                    }

                    lower.endsWith(".dex") -> {
                        dex++
                        val stream = zip.getInputStream(entry)
                        try {
                            val headerBytes = ByteArray(0x70)
                            var headerOff = 0
                            while (headerOff < headerBytes.size) {
                                val r = stream.read(headerBytes, headerOff, headerBytes.size - headerOff)
                                if (r < 0) break
                                headerOff += r
                            }
                            dexDetails += parseDexHeaderBytes(headerBytes, name)
                            val entryMatches = ApkPatternScanner.scan(stream, rules.searchPatterns)
                            if (entryMatches.isNotEmpty()) {
                                matchedPatterns += entryMatches
                                dexPatternMatches[name] = entryMatches.sorted()
                            }
                        } finally {
                            stream.close()
                        }
                    }

                    lower.startsWith("assets/flutter_assets/") -> {
                        flutterAssetCount++
                        markEngine("Flutter", "assets/flutter_assets/")
                    }

                    lower.startsWith("assets/index.android.bundle") ->
                        markEngine("React Native", "assets/index.android.bundle")

                    lower.startsWith("assets/www/") -> markEngine("H5 Hybrid", "assets/www/")

                    lower.contains("global-metadata.dat") ->
                        markEngine("Unity IL2CPP", "global-metadata.dat")

                    lower.startsWith("assets/bin/data/managed/") && lower.endsWith(".dll") ->
                        markEngine("Unity Mono", "assets/bin/Data/Managed/*.dll")

                    lower.endsWith(".jsc") || lower.startsWith("assets/src/") ->
                        markEngine("Cocos Creator", "${entry.name}")

                    lower.startsWith("res/") -> resources++
                    lower.startsWith("assets/") -> assets++
                    lower.startsWith("lib/") && lower.endsWith(".so") -> {
                        so++
                        name.split('/').getOrNull(1)?.let(abis::add)
                        nativeLibraryFiles += mapOf("path" to name, "size" to size)
                        // Flutter 应用识别：libapp.so / libflutter.so 存在即 AOT 模式
                        val soName = name.substringAfterLast('/').lowercase(Locale.ROOT)
                        if (soName == "libapp.so" || soName == "libflutter.so") {
                            name.split('/').getOrNull(1)?.let(flutterAbis::add)
                            markEngine("Flutter", soName)
                        }
                        if (soName == "libil2cpp.so") {
                            markEngine("Unity IL2CPP", soName)
                        }
                        if (soName == "libmonodroid.so") {
                            markEngine("Xamarin/MAUI", soName)
                        }
                        if (soName == "libcocos2djs.so") {
                            markEngine("Cocos Creator", soName)
                        }
                        // 加固壳检测：lib/*/lib*.so 文件名子串匹配（大小写不敏感）
                        for ((signature, label) in mergedShellSignatures()) {
                            if (soName.contains(signature)) {
                                shellNames += label
                                shellLibs += mapOf("path" to name, "shell" to label, "size" to size)
                            }
                        }
                    }
                }
                // v1 签名文件枚举（JAR 签名：.RSA/.DSA/.EC/.SF/MANIFEST.MF）
                if (lower.startsWith("meta-inf/") &&
                    (lower.endsWith(".rsa") || lower.endsWith(".dsa") || lower.endsWith(".ec") ||
                        lower.endsWith(".sf") || lower.endsWith("manifest.mf"))
                ) {
                    v1SignatureFiles += name
                }
                val safety = when {
                    size == 0L -> "safe"
                    lower.endsWith(".proto") || lower.endsWith(".pb") ||
                        lower.endsWith(".bin") -> "review"
                    lower.startsWith("lib/") && lower.endsWith(".so") -> "high_risk"
                    lower.startsWith("../") || lower.contains("/../") ||
                        lower.startsWith('/') -> "high_risk"
                    else -> null
                }
                if (safety != null) {
                    candidates += mapOf(
                        "path" to name,
                        "size" to size,
                        "safety" to safety,
                        "reason" to when {
                            size == 0L -> "空文件"
                            lower.endsWith(".proto") || lower.endsWith(".pb") ||
                                lower.endsWith(".bin") -> "未知配置文件，需检查 DEX 和动态路径引用"
                            lower.endsWith(".so") -> "原生库可能由 JNI 或动态路径加载"
                            else -> "ZIP 路径异常，需检查打包安全性"
                        },
                    )
                }
            }
        }
        emitProgress(90, "解析组件与权限")
        val signatureCheckHits = scanSignatureCheck(apk)
        emitProgress(92, "扫描签名校验")
        val manifestSummary = manifestBytes?.let { bytes ->
            runCatching { ApkAxmlEditor.readManifestSummary(bytes) }.getOrNull()
        }

        val activities = packageInfo?.activities?.mapNotNull { it.name }
            ?: manifestSummary?.components
                ?.filter { it.tag == "activity" || it.tag == "activity-alias" }
                ?.map { it.name }
            ?: emptyList()
        val services = packageInfo?.services?.mapNotNull { it.name }
            ?: manifestSummary?.components?.filter { it.tag == "service" }?.map { it.name }
            ?: emptyList()
        val receivers = packageInfo?.receivers?.mapNotNull { it.name }
            ?: manifestSummary?.components?.filter { it.tag == "receiver" }?.map { it.name }
            ?: emptyList()
        val providers = packageInfo?.providers?.mapNotNull { it.name }
            ?: manifestSummary?.components?.filter { it.tag == "provider" }?.map { it.name }
            ?: emptyList()
        val exportedComponents = if (packageInfo != null) {
            buildList<Map<String, String>> {
                addExported("activity", packageInfo.activities)
                addExported("service", packageInfo.services)
                addExported("receiver", packageInfo.receivers)
                addExported("provider", packageInfo.providers)
            }
        } else {
            manifestSummary?.components
                ?.filter { it.exported == true }
                ?.map { mapOf("type" to it.tag, "name" to it.name) }
                ?: emptyList()
        }
        val permissions = packageInfo?.requestedPermissions?.toList()
            ?: manifestSummary?.permissions
            ?: emptyList()
        val dangerousPermissions = permissions.filter { it in ApkRulesStore.highRiskPermissions }
        val componentText = (activities + services + receivers + providers)
            .joinToString("\n")
            .lowercase(Locale.ROOT)
        val adSdkStringMatches = matchedPatterns.filter { it in rules.sdkPackageSet }.sorted()
        val dexSdkClassMatches = linkedSetOf<String>()
        runCatching {
            val prefixes = rules.sdkPackages.associateWith {
                it.trim().trimEnd('.').replace('.', '/').lowercase(Locale.ROOT)
            }
            DexIo.eachDex(context, apk) { _, dexFile ->
                for (classDef in dexFile.classes) {
                    val type = classDef.type
                        .removePrefix("L")
                        .removeSuffix(";")
                        .lowercase(Locale.ROOT)
                    for ((rule, prefix) in prefixes) {
                        if (type == prefix || type.startsWith("$prefix/")) {
                            dexSdkClassMatches += rule
                        }
                    }
                }
            }
        }
        val componentSdkMatches = rules.sdkPackages.filter { componentText.contains(it) }
        val componentClassMatches = rules.classPatterns.filter { componentText.contains(it) }
        val adSdkMatches = (dexSdkClassMatches + componentSdkMatches)
            .distinct()
            .sorted()
        val adClassMatches = (matchedPatterns.filter { it in rules.classPatternSet } + componentClassMatches)
            .distinct()
            .sorted()
        // 入口方法（init*/register*/manager*）：改一处可杜绝一类，优先改。
        val adEntryMethodMatches = matchedPatterns.filter { it in rules.entryMethodSet }.sorted()
        // 普通方法命中（load/show 等调用点）：需逐个改，非入口。
        val adMethodMatches = matchedPatterns
            .filter { it in rules.methodPatternSet && it !in rules.entryMethodSet }
            .sorted()
        val adUrlMatches = matchedPatterns.filter { it in rules.urlPatternSet }.sorted()
        val vipMethodCandidates = matchedPatterns.filter { it in rules.forceTrueMethodSet }.sorted()
        val timeMethodCandidates = matchedPatterns.filter { it in rules.timeMethodSet }.sorted()
        val certificateSha256 = signingCertificateSha256(packageInfo)
        val metadata = appInfo?.metaData?.keySet()?.sorted()
            ?: manifestSummary?.metaData?.map { it.name }?.sorted()
            ?: emptyList()
        val appLabel = runCatching {
            appInfo?.loadLabel(context.packageManager)?.toString().orEmpty()
        }.getOrDefault("").ifEmpty { manifestSummary?.appLabel.orEmpty() }
        // 一次读文件解析 v2/v3 签名块（避免两次 RandomAccessFile 开销）。
        val signingSchemes = signingSchemeFlags(apk)
        val localSchemeUnreliable = signingSchemes[0] == false &&
            signingSchemes[1] == false && v1SignatureFiles.isNotEmpty()
        // 签名方案单一事实源（2026-09-15 真机 P1）：报告此前只用手写的 EOCD/
        // 签名块解析——遇到 ZIP64 或异常布局会静默返回空集，于是把 v2/v3 写成
        // false；而 apk_archive(certificates) 用平台验签（apksig）报「V2 验签
        // 通过」。同一事实两种结论会直接误导定位（改完签名反而"没签名"）。
        // 现在以平台验签为准，手写解析仅作快路径（验签不可用时的降级）。
        val signatureVerification = runCatching {
            com.android.apksig.ApkVerifier.Builder(apk).build().verify()
        }.getOrNull()

        emitProgress(100, "分析完成")
        // sha256 整包流式读一遍只算一次（大包 IO 明显），两处共用。
        val apkSha256 = sha256(apk)
        // R1：analysisVersion=19（阶段 0 引擎输出变更：outline CFG 真值/smali
        // 寄存器/xref 截断标记/lambda 边/unsupported 标注）——旧报告缓存失效。
        return mapOf(
            "analysisVersion" to 19,
            "path" to apk.absolutePath,
            "fileName" to apk.name,
            "appLabel" to appLabel,
            "size" to apk.length(),
            "sha256" to apkSha256,
            // T1：sourceApk 供报告一致性核对（文件名 + sha256 + 分析时间）
            "sourceApk" to mapOf(
                "path" to apk.absolutePath,
                "fileName" to apk.name,
                "sha256" to apkSha256,
                "size" to apk.length(),
                "lastModified" to apk.lastModified(),
                "analyzedAt" to System.currentTimeMillis(),
            ),
            "certificateSha256" to certificateSha256,
            "packageName" to (packageInfo?.packageName ?: manifestSummary?.packageName.orEmpty()),
            "versionName" to (packageInfo?.versionName ?: manifestSummary?.versionName.orEmpty()),
            "versionCode" to if (packageInfo == null) manifestSummary?.versionCode ?: 0L else if (
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
            ) packageInfo.longVersionCode else {
                @Suppress("DEPRECATION")
                packageInfo.versionCode.toLong()
            },
            "minSdk" to (appInfo?.minSdkVersion ?: manifestSummary?.minSdk ?: 0),
            "targetSdk" to (appInfo?.targetSdkVersion ?: manifestSummary?.targetSdk ?: 0),
            "debuggable" to if (appInfo != null) {
                appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            } else {
                manifestSummary?.debuggable ?: false
            },
            "allowBackup" to if (appInfo != null) {
                appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0
            } else {
                manifestSummary?.allowBackup ?: false
            },
            "metaData" to metadata,
            "permissions" to permissions,
            "dangerousPermissions" to dangerousPermissions,
            "activities" to activities,
            "services" to services,
            "receivers" to receivers,
            "providers" to providers,
            "exportedComponents" to exportedComponents,
            "totalFiles" to totalFiles,
            "uncompressedBytes" to uncompressedBytes,
            "compressedBytes" to compressedBytes,
            "compressionRatio" to if (uncompressedBytes == 0L) 1.0 else
                compressedBytes.toDouble() / uncompressedBytes.toDouble(),
            "dexFiles" to dex,
            "dexDetails" to dexDetails,
            "resourceFiles" to resources,
            "assetFiles" to assets,
            "nativeLibraries" to so,
            "abis" to abis.toList(),
            "flutterApp" to mapOf(
                "detected" to (flutterAbis.isNotEmpty() || flutterAssetCount > 0),
                "abis" to flutterAbis.toList(),
                "assetCount" to flutterAssetCount,
                "engine" to if (flutterAbis.isNotEmpty() || flutterAssetCount > 0) "aot" else "unknown",
                // P0-1 双轨道路由：Flutter=双层逻辑，按目标所属层选工具链
                // A. Dart 业务层（会员/VIP/播放器UI/业务判定）→ libapp.so（Dart AOT）
                // B. 原生层（广告SDK/下载/权限/系统调用）→ dex+assets+Manifest
                "dualTrackRouting" to if (flutterAbis.isNotEmpty() || flutterAssetCount > 0) mapOf(
                    "dartLayer" to "Dart 业务判定 → libapp.so：blutter locate 收敛语义键；字段名被混淆或判断函数脱钩时用 trace 追踪键引用→字段写入→读取→寄存器消费，只把进入比较、分支或返回的 high/medium 候选交给验证",
                    "nativeLayer" to "原生业务 → dex_search(auto) 自动组合并切换类、方法、字段、字符串、数字和指令证据 → 按 nextActions 验证真实代码与调用关系 → patch_apk_dex_methods / patch_apk_manifest",
                    "rule" to "修改位置因版本和混淆而异：名称与用户提示只作线索，工具必须用字段数据流、常量、返回语义和调用位置验证后再修改；Dart 业务在 dex 搜不到是正常现象",
                ) else emptyMap<String, String>(),
            ),
            "runtimeEngines" to runtimeEngines.map { (engine, signals) ->
                mapOf("engine" to engine, "signals" to signals.distinct())
            },
            "signingScheme" to mapOf(
                "v1" to (signatureVerification?.isVerifiedUsingV1Scheme
                    ?: v1SignatureFiles.isNotEmpty()),
                "v2" to when {
                    signatureVerification != null -> signatureVerification.isVerifiedUsingV2Scheme
                    localSchemeUnreliable -> "unknown"
                    else -> signingSchemes[0]
                },
                "v3" to when {
                    signatureVerification != null -> signatureVerification.isVerifiedUsingV3Scheme
                    localSchemeUnreliable -> "unknown"
                    else -> signingSchemes[1]
                },
                if (signatureVerification != null)
                    "verified" to signatureVerification.isVerified
                else
                    "verified" to JSONObject.NULL,
                "schemeSource" to if (signatureVerification != null)
                    "apksig_verify" else "apk_signing_block_parse(降级：验签不可用)",
                "v1SignatureFiles" to v1SignatureFiles,
                // B1 兜底：本地 v2/v3 均未检出而 v1 存在时，判定不可靠
                // （解析对异常布局可能漏检），标记后调用方应以 MT 验签为准
                "localSchemeUnreliable" to localSchemeUnreliable,
                // v8-D10（2026-10-04 真机）：v1 报 false 却并列列出 v1 签名文件、
                // note 在真值下仍宣称「已输出 unknown」——三处不自洽。现在：
                // ①apksig 可用时 v2/v3 就是验签真值，note 按真值说；
                // ②v1 验签未过但 META-INF 有 v1 文件时，追加 v1Conflict 显式
                // 说明两口径为何不同（v1 文件在场 ≠ v1 验签通过），并指路 MT。
                // v12 复测：只说「常见于…」不够——矛盾场景下再跑一次**只验 v1**
                // 的 apksig（关掉 v2/v3），把条目级失败原因落进 v1ConflictDetail。
                *listOfNotNull(
                    if (signatureVerification != null &&
                        !signatureVerification.isVerifiedUsingV1Scheme &&
                        v1SignatureFiles.isNotEmpty())
                        "v1Conflict" to
                            ("META-INF 存在 v1 签名文件（${v1SignatureFiles.joinToString()}）但 apksig 判定 " +
                                "v1 未通过（常见于 v1 摘要未覆盖全部条目/后续增改文件）。以 apksig 的 v1=false 为准判断" +
                                "「v1 是否可信」；需要第三方交叉验证时用 MT 验签。" +
                                (v1IssueDetails(signatureVerification).takeIf { it.isNotEmpty() }?.let { issues ->
                                    " 同次验签给出的 v1 具体判定：${issues.joinToString("；")}"
                                } ?: ""))
                    else null,
                ).toTypedArray(),
                "note" to if (signatureVerification != null) {
                    "以 apksig 验签为准：v1/v2/v3 均为验签真值（${
                        listOfNotNull(
                            "v1=${signatureVerification.isVerifiedUsingV1Scheme}",
                            "v2=${signatureVerification.isVerifiedUsingV2Scheme}",
                            "v3=${signatureVerification.isVerifiedUsingV3Scheme}",
                        ).joinToString()
                    }）；v1SignatureFiles 只是 META-INF 枚举结果，文件在场不等于该方案验签通过。"
                } else if (localSchemeUnreliable) {
                    "本地无法可靠判断 v2/v3，已输出 unknown；以 MT 验签为准"
                } else {
                    "v1 由 META-INF JAR 签名文件枚举判定；v2/v3 由 APK Signing Block 头部解析（magic 'APK Sig Block 42' 下的 v2/v3 块）"
                },
            ),
            // 签名校验检测：命中说明重打包签名后可能闪退，修改时启用签名兼容注入。
            "signatureCheck" to mapOf(
                "detected" to false,
                "hits" to signatureCheckHits,
                "stringHints" to signatureCheckHits,
                "hitLevel" to "string_hint",
                "methodLevelConfirmed" to false,
                "requiresMethodVerification" to signatureCheckHits.isNotEmpty(),
                "note" to "字符串可能来自微信/支付等第三方 SDK，不能证明 App 自校验。交给 dex_search(auto) 自动定位使用者并验证真实代码；只有确认读取自身签名并参与放行/退出分支时才判定。",
                "risk" to if (signatureCheckHits.isNotEmpty()) {
                    "存在待验证字符串线索，尚未确认重打包风险"
                } else {
                    "未检测到常见签名校验特征"
                },
            ),
            "fileTypeCounts" to fileTypeCounts.entries
                .sortedByDescending { it.value }
                .associate { it.key to it.value },
            "largestFiles" to largestFiles.sortedByDescending { (it["size"] as Long) },
            "nativeLibraryFiles" to nativeLibraryFiles.sortedByDescending { (it["size"] as Long) },
            "shellPacking" to mapOf(
                "detected" to shellNames.isNotEmpty(),
                "shells" to shellNames.toList(),
                "libs" to shellLibs,
            ),
            "adSdkMatches" to adSdkMatches,
            "adSdkStringMatches" to adSdkStringMatches,
            "adClassMatches" to adClassMatches,
            "adEntryMethodMatches" to adEntryMethodMatches,
            "adMethodMatches" to adMethodMatches,
            "adUrlMatches" to adUrlMatches,
            "vipMethodCandidates" to vipMethodCandidates,
            "timeMethodCandidates" to timeMethodCandidates,
            "dexPatternMatches" to dexPatternMatches.map { (dexName, patterns) ->
                mapOf("dex" to dexName, "patterns" to patterns)
            },
            "ruleStats" to mapOf(
                "sdkPackages" to rules.sdkPackages.size,
                "classPatterns" to rules.classPatterns.size,
                "methodPatterns" to rules.methodPatterns.size,
                "urlPatterns" to rules.urlPatterns.size,
                "forceTrueMethods" to rules.forceTrueMethods.size,
                "timeMethods" to rules.timeMethods.size,
                "totalSearchPatterns" to rules.searchPatterns.size,
            ),
            "candidates" to candidates.sortedWith(
                compareBy<Map<String, Any>> { ApkRulesStore.safetyOrder[it["safety"]] ?: 9 }
                    .thenByDescending { it["size"] as Long },
            ),
        )
    }

    private fun MutableList<Map<String, String>>.addExported(
        type: String,
        components: Array<out ComponentInfo>?,
    ) {
        components?.filter { it.exported }?.forEach {
            add(mapOf("type" to type, "name" to it.name))
        }
    }

    private fun loadRules(): ApkAdRules = ApkRulesStore.load(context)

    /** 用户自定义规则的原生私有 SP（经 setUserRules 通道写入）。 */
    private fun userRulesPrefs() =
        context.getSharedPreferences("apk_mod_user_rules", Context.MODE_PRIVATE)

    /** 核心 SO 白名单：应用运行必需，精确删除也拦（广告 SDK 的 so 不在其中，可删）。 */
    private fun isCoreSo(name: String): Boolean {
        val soName = name.substringAfterLast('/').lowercase(Locale.ROOT)
        if (!name.startsWith("lib/") || !soName.endsWith(".so")) return false
        // Flutter 引擎 + 加固壳，删除必崩。
        if (soName == "libflutter.so" || soName == "libapp.so") return true
        for ((signature, _) in mergedShellSignatures()) {
            if (soName.contains(signature)) return true
        }
        return false
    }

    /** 检查是否有写公共存储的权限（Android 11+ 需「所有文件访问」）。 */
    private fun checkStoragePermission(): Map<String, Any> {
        val granted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            @Suppress("DEPRECATION")
            context.checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED
        }
        return mapOf("granted" to granted)
    }

    /** 跳转系统设置页，引导用户授予「所有文件访问」权限。 */
    private fun requestStoragePermission(): Map<String, Any> {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val intent = Intent(
                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.fromParts("package", context.packageName, null),
                )
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
            } else {
                @Suppress("DEPRECATION")
                val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                intent.data = Uri.fromParts("package", context.packageName, null)
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
            }
            mapOf("ok" to true)
        } catch (error: Exception) {
            mapOf("ok" to false, "error" to (error.message ?: "无法打开设置页"))
        }
    }

    /**
     * 一键回滚：把源 APK（已知良好的已签名原版）复制到输出目录，
     * 命名 <原名>_original.apk。源包从未被修改，这是最可靠的回滚方式。
     */
    private fun restoreSourceApk(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        // 输出目录必填：与 structuralOutput 一致，避免落到内部 cache。
        val outputDir = outputDirArg(call)
            ?: throw StructuralError(
                "output_dir_required",
                "请先在 APK 工作台设置「工作目录」（需与 MT 工作目录一致）",
            )
        val dirFile = File(outputDir)
        if (!dirFile.isDirectory) {
            throw StructuralError("invalid_output_dir", "输出目录不存在: $outputDir")
        }
        val name = "${source.nameWithoutExtension}_original.apk"
        val target = File(dirFile, name)
        source.copyTo(target, overwrite = true)
        return mapOf(
            "ok" to true,
            "outputPath" to target.absolutePath,
            "message" to "已把原版（已签名）复制到工作目录，可直接安装回滚",
        )
    }

    /** 用户自定义壳特征（so 文件名 → 壳名），经 setUserRules 的 shell_signatures 键写入。 */
    private fun userShellSignatures(): Map<String, String> {
        val custom = userRulesPrefs().getStringSet("shell_signatures", emptySet())
            ?: return emptyMap()
        val result = linkedMapOf<String, String>()
        for (raw in custom) {
            // 格式：so文件名=壳名（如 libmyshell.so=自研壳）
            val eq = raw.indexOf('=')
            if (eq > 0) {
                val so = raw.substring(0, eq).trim().lowercase(Locale.ROOT)
                val label = raw.substring(eq + 1).trim()
                if (so.isNotEmpty() && label.isNotEmpty()) result[so] = label
            }
        }
        return result
    }

    /** 合并后的壳特征（内置 + 用户自定义，用户优先同名覆盖）。 */
    private fun mergedShellSignatures(): Map<String, String> =
        ApkRulesStore.shellSignatures + userShellSignatures()

    /**
     * 用户规则同步入口：Dart 规则库在 syncRulesToPreferences 后调用，
     * 把启用中的规则全量推给原生（避免直接读 FlutterSharedPreferences 的
     * flutter. 前缀文件）。以 Set 存储，读侧统一小写去重。
     */
    private fun setUserRules(call: MethodCall): Map<String, Any> {
        val raw = arg(call, "rules") as? Map<*, *> ?: return mapOf(
            "ok" to false,
            "error" to "invalid_args",
            "message" to "缺少 rules 参数",
        )
        val prefs = userRulesPrefs()
        val editor = prefs.edit()
        for ((key, value) in raw) {
            val list = (value as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
            editor.putStringSet(key.toString(), list.toSet())
        }
        editor.apply()
        // 用户规则变更 → 失效缓存，下次 loadRules 重新合并。
        ApkRulesStore.invalidate()
        return mapOf("ok" to true, "storedKeys" to raw.keys.size)
    }

    private val SIGNATURE_CHECK_KEYWORDS = listOf(
        "get_signatures", "getsignatures", "checksignature", "checkappsignature",
        "verifysignature", "signaturevalid", "appsignature", "signaturedigest",
        "signingcertificate", "signinginfo", "getpackagesignature", "packagesignature",
        "signature.tobytearray", "getsigningcertificates", "signaturecheck", "signatureverify",
    )

    private fun scanSignatureCheck(source: File): List<String> {
        val matched = linkedSetOf<String>()
        withApkZip(source) { zip ->
            zip.entries().asSequence().filterNot { it.isDirectory }
                .filter { it.name.lowercase(Locale.ROOT).endsWith(".dex") }
                .forEach { entry ->
                    val hits = zip.getInputStream(entry).use { input ->
                        ApkAhoCorasick(SIGNATURE_CHECK_KEYWORDS).scanStream(input)
                    }
                    matched += hits
                }
        }
        return matched.sorted()
    }

    /**
     * 解析 DEX 头部（借鉴玄星 ApkAnalyzer.parseDexHeader）：只读前 0x70 字节，
     * 解析 magic/版本/校验标志/各 id 表数量。零全量 IO、不加载 dexlib2。
     * 入参为已读入的头部字节（由调用方在流上先读 0x70，避免流二次打开）。
     */
    private fun parseDexHeaderBytes(header: ByteArray, entryName: String): Map<String, Any> {
        fun u32(at: Int): Long {
            if (at + 4 > header.size) return 0
            return (header[at].toLong() and 0xff) or
                ((header[at + 1].toLong() and 0xff) shl 8) or
                ((header[at + 2].toLong() and 0xff) shl 16) or
                ((header[at + 3].toLong() and 0xff) shl 24)
        }
        val magic = if (header.size >= 8) {
            String(header.copyOfRange(0, 8), Charsets.ISO_8859_1).replace("\u0000", "\\0")
        } else {
            ""
        }
        val valid = header.size >= 0x70 && header[0] == 'd'.code.toByte() &&
            header[1] == 'e'.code.toByte() && header[2] == 'x'.code.toByte() &&
            header[3] == '\n'.code.toByte()
        return mapOf(
            "entry" to entryName,
            "magic" to magic,
            "valid" to valid,
            "fileSize" to u32(0x20),
            "headerSize" to u32(0x24),
            "endianTag" to "0x${u32(0x28).toString(16)}",
            "stringIds" to u32(0x38),
            "typeIds" to u32(0x40),
            "protoIds" to u32(0x48),
            "fieldIds" to u32(0x50),
            "methodIds" to u32(0x58),
            "classDefs" to u32(0x60),
        )
    }

    // ---- 结构级操作执行器（deleteZipEntries / writeZipEntry / buildApk）----

    private data class EntryOp(
        val locator: String,
        val name: String,
        val action: String,
        val content: ByteArray?,
        val contentFile: File?,
        val contentSource: String,
        val allowShrink: Boolean = false,
    )

    private class StructuralError(val stage: String, message: String) : RuntimeException(message)

    // dex 全量解析类方法：dexlib2/jadx 加载展开膨胀实测 ~4 倍（54MB 包
    // jadx 单类峰值 209MB ≈ 3.9× 校准）；zip 复制/条目改写类 ~2.5 倍
    // （57MB 包 manifest patch 稳定跑过）。
    private val dexFullParseMethods =
        setOf("patchDexMethods", "patchDexStrings", "jadxDecompile", "apkRebuild")

    // 功能型 meta-data 关键词（小写 contains 匹配）：地图/定位/推送/支付
    // 能力 Key。auto 去广告规则命中公司前缀（com.baidu/com.amap 等）时，
    // 这些键被白名单保护不删除，并在 protectedMetaData 里如实回报。
    private val functionalMetaDataKeywords = setOf(
        "lbsapi", "baidumap", "baidolbs", "amap", "google.android.geo",
        "com.google.android.maps", "jpush", "getui", "mipush", "push",
        "wxapi", "weixin", "alipay", "tenpay", "com.tencent.map",
    )

    private fun isFunctionalMetaDataKey(name: String): Boolean {
        val lower = name.lowercase()
        return functionalMetaDataKeywords.any { lower.contains(it) }
    }

    /**
     * 输入成本基数：估"本次实际要动的数据量"，不是输入包大小
     * （2026-09-15 用户基线 L5：峰值 ≈ 实际进堆数据 × 膨胀系数）。
     * 返回 (bytes, basis)。
     *
     * - patchDexMethods/patchDexStrings：引擎已是逐 dex（AC 流式预检 +
     *   单 dex 落盘加载，[ApkDexPatcher.patch] 收 dexFile），实际峰值 =
     *   最大单个 dex 条目 × 膨胀。此前拿整包体积当基数，把 100-200MB
     *   的正常包全部挡死（512MB 堆 ÷ 4 ≈ 76MB 门槛）——基数算错对象。
     *   path 指向裸 .dex 时直接取文件大小。
     * - jadxDecompile：带 dexName 按"该 dex 条目"口径；无则 APKEditor
     *   全量 decode，按整包。
     * - apkRebuild：**按 action 分派**（2026-09-15 修正）。decode 解压全量条目
     *   进堆，基数 = APK 解压后内容量（拿不到条目表则整包 × 2.5 估算）；
     *   build 的 path 是 decode 出的目录，`File.length()` 对目录恒为 0，旧
     *   实现基数算成 0 直接绕过预算（静默漏洞），改为累加目录内容字节；
     *   merge/refactor 只寻表不展开，沿用整包。均配套 allowOversize 放行。
     */
    private fun inputBasisBytes(call: MethodCall, args: Map<*, *>): Pair<Long, String> {
        val path = (args["path"] as? String)?.trim().orEmpty()
        val pathFile = if (path.isNotEmpty()) File(path) else null
        when (call.method) {
            "patchDexMethods", "patchDexStrings" -> {
                // 裸 dex 形态：path 就是本次进堆的那一个 dex
                if (pathFile != null && pathFile.isFile && path.endsWith(".dex")) {
                    return pathFile.length() to "单 dex 文件"
                }
                val apk = pathFile?.takeIf { it.isFile }
                if (apk != null) {
                    val maxDex = dexEntrySizes(apk).values.maxOrNull()
                    if (maxDex != null && maxDex > 0) {
                        return maxDex to "最大单 dex 条目"
                    }
                }
            }
            "jadxDecompile" -> {
                val action = (args["action"] as? String)?.trim().orEmpty().ifBlank { "save" }
                if (action == "list") {
                    return 0L to "DEX 类目录（直接读取，不启动 Jadx）"
                }
                val dexName = (args["dexName"] as? String)?.trim().orEmpty()
                val apk = pathFile?.takeIf { it.isFile }
                if (dexName.isNotEmpty() && apk != null) {
                    val size = try {
                        java.util.zip.ZipFile(apk).use { zip ->
                            zip.getEntry(dexName)?.let {
                                if (it.size >= 0) it.size else it.compressedSize
                            }
                        }
                    } catch (_: Exception) {
                        null
                    }
                    if (size != null && size > 0) return size to "单 dex（$dexName）"
                }
                if (action == "class" && apk != null) {
                    val maxDex = dexEntrySizes(apk).values.maxOrNull()
                    if (maxDex != null && maxDex > 0) {
                        return maxDex to "最大单 dex（逐 dex 查找目标类）"
                    }
                }
            }
            // apkRebuild 四个 action 的内存画像完全不同，此前一律走整包兜底，
            // 实测暴露两个方向的错误：
            //   - build：path 是 decode 出的**目录**，`File(v).isFile` 为 false
            //     → 基数 0 → checkInputBudget 直接放过，超大 decode 目录零防护
            //     （静默漏洞，不是保守误拒）。
            //   - decode：真正进堆的是解压后的全量条目（资源 + dex + so），
            //     拿压缩包体量当基数系统性低估。
            // 分别给基数：build 用目录实际字节（不含 apk 产物），decode 用
            // 解压后内容量估算，merge/refactor 沿用整包（只寻表、不展开）。
            "apkRebuild" -> {
                val action = (args["action"] as? String)?.trim().orEmpty().ifBlank { "decode" }
                val path = pathFile
                when {
                    action == "build" && path != null && path.isDirectory -> {
                        val bytes = directoryContentBytes(path)
                        if (bytes > 0) return bytes to "decode 目录内容（${path.name}）"
                    }
                    action == "decode" && path != null && path.isFile -> {
                        // 解压后膨胀以中央目录的 uncompressed size 为准（只读条目表，
                        // 不进数据区）；拿不到时退回压缩体积 × 经验系数 2.5。
                        val inflated = apkUncompressedBytes(path)
                        if (inflated > 0) return inflated to "APK 解压后内容量"
                        if (path.length() > 0) {
                            return (path.length() * 5 / 2) to "APK 整包 × 2.5（解压估算）"
                        }
                    }
                }
            }
        }
        // 兜底 / apkRebuild(merge,refactor)：整包口径（path/contentFile/locator 取最大）
        val whole = listOf("path", "contentFile", "locator").maxOfOrNull { key ->
            (args[key] as? String)?.let { v ->
                val f = File(v)
                if (f.isFile) f.length() else 0L
            } ?: 0L
        } ?: 0L
        return whole to "APK 整包"
    }

    /**
     * 目录内容总字节（递归）。apkRebuild build 的输入形态，`File.length()`
     * 对目录恒为 0，必须显式累加，否则体积预算形同虚设。
     * 用 walkTopDown 但按条目累加而非读内容，只碰元数据，不触发 IO 放大。
     */
    private fun directoryContentBytes(dir: File): Long {
        return try {
            dir.walkTopDown()
                .filter { it.isFile }
                .sumOf { it.length() }
        } catch (_: Exception) {
            0L
        }
    }

    /** APK 内全部条目解压后体积（只读中央目录，不进数据区）。 */
    private fun apkUncompressedBytes(apk: File): Long {
        return try {
            java.util.zip.ZipFile(apk).use { zip ->
                zip.entries().asSequence()
                    .filterNot { it.isDirectory }
                    .sumOf { if (it.size >= 0) it.size else it.compressedSize }
            }
        } catch (_: Exception) {
            0L
        }
    }

    /** APK 内 dex 条目（未压缩）体积：只读中央目录条目表，不进数据区。 */
    private fun dexEntrySizes(apk: File): Map<String, Long> {
        return try {
            java.util.zip.ZipFile(apk).use { zip ->
                zip.entries().asSequence()
                    .filterNot { it.isDirectory }
                    .filter { it.name.matches(DexIo.classesDexRegex) }
                    .associate { it.name to (if (it.size >= 0) it.size else it.compressedSize) }
            }
        } catch (_: Exception) {
            emptyMap()
        }
    }

    /**
     * 输入体积预算：只对"把输入整读进 Java 堆全量解析"的工具生效
     * （dexlib2/jadx/APKEditor 加载展开，膨胀实测 ~4 倍）。超过
     * "min(当前可用堆 × 0.8, 堆上限 × 0.6) ÷ 4"时拒绝执行；通过则返回 null。
     * 基数按 [inputBasisBytes]（实际进堆数据量），不是输入包大小。
     *
     * 流式/子进程类工具（apkArchive 条目流复制、so_analyze blutter 子进程、
     * so_patch/signature_bypass 流式 zip 改写、patchManifest 单条目 AXML）
     * 不整读输入进堆，Java 堆占用与输入体积无关——豁免。native 堆风险由
     * MemPressure 执行预检兜底，不在文件体积层重复设卡。
     *
     * 双因子：当前可用 × 0.8 让预算随堆状态伸缩；堆上限 × 0.6 封顶防任务
     * 间隙 free 快照虚高导致放行后半程 OOM。膨胀系数用 jadx 实测校准。
     * 硬拒时提供 allowOversize 显式放行（用户基线 L5：override 自担风险，
     * 而不是把唯一路径焊死）。
     */
    private fun checkInputBudget(call: MethodCall): Map<String, Any>? {
        if (call.method !in dexFullParseMethods) return null
        val args = call.arguments as? Map<*, *> ?: return null
        // 用户基线 L5：显式 override——模型/用户确认后自担 OOM 风险放行
        if ((args["allowOversize"] as? Boolean) == true) return null
        val multiplier = heapMultiplierFor(call.method)
        val heapMb = zhou.solab.tools.MemPressure.heapLimitMb()
        // 读数前先 GC：ART 的 freeMemory() 在"GC 还没跑"时会偏小、任务间隙又偏大，
        // 实测出现过可用堆读数为 0 的假象。强制一次 GC 让读数尽量贴近真实。
        System.gc()
        val rt = Runtime.getRuntime()
        val freeMb =
            (rt.maxMemory() - rt.totalMemory() + rt.freeMemory()) / (1024.0 * 1024.0)
        val (inputBytes, basis) = inputBasisBytes(call, args)
        val inputMb = inputBytes / (1024.0 * 1024.0)
        // 判定全在纯函数里（可单测）：读数不可信 / 预算为 0 / 峰值装不下，三种都拒绝。
        // 关键：`availableMb <= 0` 时**无论 multiplier 是多少都拒绝**（fail-closed），
        // 不再依赖"这次恰好算出了非零预算"——第二轮 budgetMb=0 仍放行就是这么漏的。
        val decision = zhou.solab.tools.InputBudgetPolicy.decide(
            inputMb = inputMb,
            availableMb = freeMb,
            heapLimitMb = heapMb,
            multiplier = multiplier,
        )
        if (decision.allow) return null
        // 基数推不出体积（inputBytes == 0）且预算健康时，维持原语义放行：
        // 无法估算不等于"装不下"，拒绝它会把小参数调用全部误杀。
        if (decision.code == zhou.solab.tools.InputBudgetDecision.INPUT_TOO_LARGE && inputBytes == 0L) return null
        val inputMib = "%.1f".format(inputMb)
        val peakMib = "%.0f".format(decision.peakMb)
        val shared = mapOf(
            "availableMb" to freeMb.toInt(),
            "heapLimitMb" to heapMb,
            "budgetMb" to decision.budgetMb.toInt(),
            "budgetSufficient" to false,
            "readingTrustworthy" to decision.readingTrustworthy,
        )
        return when (decision.code) {
            zhou.solab.tools.InputBudgetDecision.UNTRUSTWORTHY_READING -> shared + mapOf(
                "ok" to false,
                "error" to "MEMORY_READING_UNTRUSTWORTHY",
                "message" to
                    "可用堆读数不可信（${freeMb.toInt()} MiB < ${zhou.solab.tools.InputBudgetPolicy.MIN_TRUSTWORTHY_AVAILABLE_MB.toInt()} MiB 下限）：" +
                    "GC 后仍算不出可信余量，本调用按 fail-closed 拒绝，不进实际分配。" +
                    "同参数重试不会改变读数，不要重试。" +
                    "替代动作：① 先释放内存（关闭大目录分析 / 清理 blutter 产物）再重试；" +
                    "② 换更小粒度入口——逐 dex（dexName）或 dex_search 替代整包解析；" +
                    "③ 只取单条目用 apk_archive(action=read, entry=...)；" +
                    "④ 确认自担风险时带 allowOversize:true（每次携带都会放行，无一次性限制；进程可能被杀）。",
            )
            zhou.solab.tools.InputBudgetDecision.BUDGET_EXHAUSTED -> shared + mapOf(
                "ok" to false,
                "error" to "MEMORY_BUDGET_EXHAUSTED",
                "message" to
                    "当前内存预算为 0（可用 ${freeMb.toInt()} MiB × ${zhou.solab.tools.InputBudgetPolicy.FREE_SHARE} " +
                    "与堆上限 ${heapMb} MiB × ${zhou.solab.tools.InputBudgetPolicy.HEAP_SHARE} " +
                    "取小后除以膨胀系数 $multiplier ≤ 0）：先释放内存再进实际分配，本调用已拒绝。" +
                    "同参数重试不会改变预算，不要重试。" +
                    "替代动作（Agent 可直接执行）：① 换更小粒度入口——逐 dex（dexName）或 dex_search " +
                    "替代整包解析；② 只取单条目用 apk_archive(action=read, entry=...)；" +
                    "③ 释放内存后重试（关闭大目录分析/清理 blutter 产物），" +
                    "或确认自担风险时带 allowOversize:true（每次携带都会放行，无一次性限制；进程可能被杀）。",
            )
            else -> shared + mapOf(
                "ok" to false,
                "error" to "INPUT_TOO_LARGE",
                "inputMb" to inputMib,
                "message" to
                    "本次进堆数据 $inputMib MiB（$basis）超过 ${call.method} 当前执行预算" +
                    "（${decision.budgetMb.toInt()} MiB = min(可用 ${freeMb.toInt()} MiB × " +
                    "${zhou.solab.tools.InputBudgetPolicy.FREE_SHARE}, 堆上限 $heapMb MiB × " +
                    "${zhou.solab.tools.InputBudgetPolicy.HEAP_SHARE})" +
                    " ÷ 膨胀系数 $multiplier，峰值估算 $peakMib MiB）。" +
                    "执行大概率中途 OOM，已拒绝；同参数重试不会改变预算，不要重试。" +
                    // F-34（v6 D19）：apk_rebuild 的 decode/build 是**整包唯一路径**，
                    // 「换更小粒度入口」对它不成立——旧文案没说清这点，导致调用方
                    // 以为还有别的整包入口而放弃往返验证。这里把两条路讲清楚：
                    // 条目级替代（不需要整包进堆）与一次性的 allowOversize 放行。
                    (if (call.method == "apkRebuild") {
                        "apk_rebuild 的 decode/build 是**整包往返的唯一入口**，没有更小的同类入口；" +
                        "可执行的替代路线：① 只改单个条目——lib/<abi>/*.so 走 so_patch_into_apk 流式回填、" +
                        "其它条目用 apk_archive(action=read, entry=...) 读取；② 逐 dex 用 jadx(dexName=…)/dex_search；" +
                        "③ 确认必须整包往返时，带 allowOversize:true 重试（每次携带都会放行，OOM 风险自担、进程可能被杀）。"
                    } else {
                        "替代动作（Agent 可直接执行）：① 更小粒度入口——jadx 传 dexName 逐 dex、" +
                        "dex_search 替代整包扫描；② 改 lib/<abi>/*.so 改用 so_patch_into_apk " +
                        "流式回填（逐条目改写，不整包进堆；其它条目暂无流式入口）；" +
                        "③ 确认必须整包执行时，重试一次并携带" +
                        " allowOversize:true（OOM 风险自担，进程可能被杀；每次携带都会放行，无一次性限制）。"
                    }),
            )
        }
    }

    /**
     * 每工具的"进堆输入 → 峰值堆占用"膨胀系数（**实测标定**，不是拍脑袋）。
     *
     * 2026-09-21 真机实测把系数 4.0 的问题钉死了：`apk_rebuild decode`
     * 输入 20.2MB APK（解压后 49.0MB）→ 预算判 49.0 ≤ 76.8MB 放行 →
     * 堆一路长满到 512MB（growth limit），最后在 vivo 自己的
     * `VivoStatsImpl` 分配 40 字节处 Java 层 OOM → **main 线程 FATAL → 进程死
     * → MCP 服务整体不可用约 48s**（用户报告的现象）。
     * 真实倍数 ≈ 512/49 = **10.4**，取 12 留余量。
     *
     * 4.0 是 dex 解析的量级；rebuild 要展开并重打包**全部**条目（含 22.5MB 的
     * libapp/libflutter），量级不同，套用同一系数就是系统性低估。
     * **其余方法保持 4.0**——没有实测数据就不动，别用一个猜的数替换另一个猜的数。
     */
    private fun heapMultiplierFor(method: String): Double = when (method) {
        "apkRebuild" -> 12.0
        else -> 4.0
    }

    /** 预算快照（不拒绝）：dexFullParseMethods 工具成功响应附带的 inputBudget 字段。 */
    private fun inputBudgetSnapshot(call: MethodCall): Map<String, Any>? {
        if (call.method !in dexFullParseMethods) return null
        val args = call.arguments as? Map<*, *> ?: return null
        val rt = Runtime.getRuntime()
        val availableMb =
            (rt.maxMemory() - rt.totalMemory() + rt.freeMemory()) / (1024.0 * 1024.0)
        val heapMb = zhou.solab.tools.MemPressure.heapLimitMb()
        val (inputBytes, basis) = inputBasisBytes(call, args)
        val inputMb = inputBytes / (1024.0 * 1024.0)
        // 快照与判定走**同一个纯策略**：展示与生效不允许两套口径（第二轮
        // "budgetMb=0 却仍执行"的可疑点之一就是两者不同源）。
        val d = zhou.solab.tools.InputBudgetPolicy.decide(
            inputMb = inputMb,
            availableMb = availableMb,
            heapLimitMb = heapMb,
            multiplier = heapMultiplierFor(call.method),
        )
        // headroom 重定义为**余量比 = budgetMb ÷ inputMb**（用户第 5 点）：
        // 旧实现是 inputMb ÷ budgetMb，预算趋 0 时会给出 880.51 这种伪正数，被读成
        // "余量充足"。现在无意义时**不给这个键**，并显式带 readingTrustworthy。
        return buildMap<String, Any> {
            put("basis", if (inputBytes == 0L) "unavailable" else basis)
            put("budgetMb", d.budgetMb.toInt())
            put("availableMb", availableMb.toInt())
            put("heapLimitMb", heapMb)
            put("multiplier", heapMultiplierFor(call.method))
            put("readingTrustworthy", d.readingTrustworthy)
            // F-45（2026-10-04）：basis=unavailable（推不出进堆体积）时不再回
            // budgetSufficient:true——那是"没算过却说装得下"（真机 v8 D10：
            // jadx list 自认 unavailable 却放行 true，读的人无从判断）。此处
            // 如实回 null（JSON 空值），判定留给调用方。
            if (inputBytes == 0L) {
                put("budgetSufficient", org.json.JSONObject.NULL)
            } else {
                put("budgetSufficient", d.allow)
            }
            if (inputBytes != 0L) {
                put("inputMb", inputMb.toInt())
                put("peakMb", d.peakMb.toInt())
            }
            d.headroomRatio?.let { put("headroomRatio", "%.2f".format(it)) }
            // 用户第 ② 条的可落地版本：**改路由**而不是改解码器。
            // `apk_rebuild` 的 decode/build 来自第三方 com.reandroid:ARSCLib，
            // 其内存行为改不了；能改的是"大输入别走它"。这里只在**放行但余量吃紧**
            // 时给路由建议（不拦截——阈值判断留给调用方，避免误杀）。
            val spendableMb = minOf(availableMb * zhou.solab.tools.InputBudgetPolicy.FREE_SHARE,
                                    heapMb * zhou.solab.tools.InputBudgetPolicy.HEAP_SHARE)
            if (inputBytes != 0L && d.allow && d.peakMb > spendableMb * 0.5) {
                put("routingHint",
                    "本次峰值估算 ${d.peakMb.toInt()} MiB，已吃掉可花上限（${spendableMb.toInt()} MiB）的一半以上。" +
                        "整包 decode/build 的解码器是第三方 ARSCLib（内存行为不可改），大输入建议改走更省内存的路由：" +
                        "① lib/<abi>/*.so 用 so_patch_into_apk 逐条目回填（不整包进堆）；" +
                        "② jadx 传 dexName 逐 dex 反编译；③ 只要单条目内容用 apk_archive(action=read, entry=...)。" +
                        "同一份数据在整包路径里会同时存在多份拷贝，这是膨胀倍数偏高的根源。")
            }
            put("note", when {
                !d.readingTrustworthy ->
                    "可用堆读数不可信（低于 ${zhou.solab.tools.InputBudgetPolicy.MIN_TRUSTWORTHY_AVAILABLE_MB.toInt()} MiB 下限）：" +
                        "不给 headroomRatio（会是无意义的数）。重内存调用会在闸门处按 fail-closed 拒绝。"
                d.code == zhou.solab.tools.InputBudgetDecision.BUDGET_EXHAUSTED ->
                    "预算不足：可用堆与堆上限取小后为 0，不给 headroomRatio。重内存调用会被拒（MEMORY_BUDGET_EXHAUSTED）。"
                inputBytes == 0L ->
                    "本次入参推不出进堆体积（basis=unavailable）：budgetSufficient=null、不给 headroomRatio——" +
                        "未做任何体积核算，不代表装得下。列出目录等轻量动作不受影响；整包 decode/build 前请先用更小粒度入口。"
                else -> ""
            })
        }
    }

    /** 在后台线程执行结构操作；错误统一返回 {ok:false, error, message}，不产出半成品。 */
    private fun runAsync(
        result: MethodChannel.Result,
        name: String,
        call: MethodCall? = null,
        block: () -> Map<String, Any>,
    ) {
        zhou.solab.tools.TaskCancel.reset()
        executorFor(name).execute {
            val needsHeavyPermit = needsHeavyPermit(name, call)
            var heavyPermitAcquired = false
            try {
                if (needsHeavyPermit) {
                    heavyExecutionGate.acquire()
                    heavyPermitAcquired = true
                }
                // 堆压保底：GC 后可用堆低于 growth limit 的 10% 时拒绝重任务并给出明确
                // 错误，而不是让任务在执行中途抛 OOM 直接杀死进程（实测 7 次
                // pool-9-thread OOM 闪退均为堆耗尽后未捕获）。基准取 largeHeap 抬高后的
                // growth limit（ActivityManager.largeMemoryClass），阈值按百分比随设备
                // 堆上限伸缩，512MB 堆上 ≈ 51MB：覆盖 dexlib2 首个临时分配高峰，避免
                // "边跑边饿死"。历史内存峰值超阈值的动态重工具（MemPressure 收录）
                // 保底翻倍，新重工具不靠写死名单也能拿到更严保护。
                System.gc()
                val runtime = Runtime.getRuntime()
                val freeMb =
                    (runtime.maxMemory() - runtime.totalMemory() + runtime.freeMemory()) / (1024L * 1024L)
                val heapMb = zhou.solab.tools.MemPressure.heapLimitMb()
                val minFreeMb = heapMb / 10
                val floorMb = if (zhou.solab.tools.MemPressure.isDynamicallyHeavy(name)) minFreeMb * 2 else minFreeMb
                if (freeMb < floorMb) {
                    replySafely(result) {
                        result.success(
                            mapOf(
                                "ok" to false,
                                "error" to "MEM_PRESSURED",
                                "message" to "服务进程堆压力过大（可用 ${freeMb}MB / 上限 ${heapMb}MB，低于保底线 ${floorMb}MB），已拒绝执行以免 OOM 闪退。" +
                                    "建议：稍候重试（等待其他任务释放内存），或重启 App 彻底清空堆。",
                            ),
                        )
                    }
                    return@execute
                }
                // 进程内存预检（2026-09-15 度量修正）：判据是进程 PSS（Java+
                // native+图形+文件映射的常驻合计，系统判杀看的就是它），
                // 分配器记账只在可信时兜底——实测有设备把记账报成 4083MB 而
                // 进程远没到 1GB（Scudo/Dart VM 的地址空间记账），按记账判压力
                // 会让 App 一旦越线就只能重启（清理钩子放不掉分配器账）。
                val pressure = zhou.solab.tools.MemPressure.relievePressure()
                if (pressure.overLine) {
                    val detail =
                        "常驻内存 PSS ${pressure.pssMb}MB 超过预算 ${pressure.pssBudgetMb}MB" +
                            "（native 记账 ${pressure.nativeAllocatedMb}MB，设备 ${zhou.solab.tools.DeviceProfile.tierName()} 档/" +
                            "${zhou.solab.tools.DeviceProfile.totalRamMb()}MB）"
                    replySafely(result) {
                        result.success(
                            mapOf(
                                "ok" to false,
                                "error" to "NATIVE_PRESSURED",
                                "message" to "服务进程内存水位过高（$detail），已拒绝执行以免系统杀进程。" +
                                    "建议：稍候重试（清理与 GC 后有释放延迟），或重启 App 彻底清空。",
                                // 同参数重试有意义（等清理生效即可），必须显式声明：
                                // 默认 false 会让执行端把可自愈的拒绝当终局失败。
                                "retrySameArguments" to true,
                                "pressure" to pressure.toMap(),
                                "device" to zhou.solab.tools.DeviceProfile.toMap(),
                            ),
                        )
                    }
                    return@execute
                }
                val memoryRun = zhou.solab.tools.MemPressure.startToolRun()
                val payload = try {
                    block()
                } catch (t: Throwable) {
                    // 失败路径同样记录：峰值最大的往往是中途失败的执行，漏记会
                    // 低估动态重名单与 SoLabMem 曲线（OOM 恢复正是靠名单加倍保底）
                    zhou.solab.tools.MemPressure.record(name, memoryRun)
                    throw t
                }
                val memoryPeak = zhou.solab.tools.MemPressure.record(name, memoryRun)
                // 预算透明化：整读入堆类工具即使通过预算也回 inputBudget 快照——
                // 调用方能区分"勉强通过"（headroom≈1）与"宽裕"，并追踪动态预算
                // 随堆水位的抖动（实测 51/52MB 摆动难以从外部归因）。
                val finalPayload =
                    if (call == null) LinkedHashMap(payload).apply {
                        put("memoryPeak", memoryPeak.toMap())
                    }
                    else inputBudgetSnapshot(call)?.let { b ->
                        LinkedHashMap(payload).apply {
                            put("inputBudget", b)
                            put("memoryPeak", memoryPeak.toMap())
                        }
                    } ?: LinkedHashMap(payload).apply {
                        put("memoryPeak", memoryPeak.toMap())
                    }
                replySafely(result) { result.success(finalPayload) }
            } catch (error: java.util.concurrent.CancellationException) {
                replySafely(result) {
                    result.success(mapOf("ok" to false, "error" to "TASK_CANCELLED", "message" to "任务已被打断（对话停止或手动取消）"))
                }
            } catch (error: StructuralError) {
                replySafely(result) {
                    result.success(mapOf("ok" to false, "error" to error.stage, "message" to error.message))
                }
            } catch (error: Exception) {
                replySafely(result) {
                    result.success(
                        mapOf(
                            "ok" to false,
                            "error" to "structural_failed",
                            "message" to "${error.javaClass.simpleName}: ${error.message ?: "未知错误"}",
                        ),
                    )
                }
            } catch (error: Throwable) {
                // Error 级兜底（OutOfMemoryError/StackOverflowError 等）：
                // Exception 接不住 Error，逃逸到线程池就是未捕获异常 → 进程闪退
                //（实测并发/重任务 OOM 全走这条路径）。转结构化错误，进程存活、
                // 堆随任务结束释放，客户端可重试。OOM 后先清缓存/引擎（纯释放）
                // 再 GC，避免缓存半写、句柄泄漏导致进程带病运行。
                if (error is OutOfMemoryError) {
                    zhou.solab.tools.MemPressure.cleanupAll("oom-recovery")
                    System.gc()
                }
                replySafely(result) {
                    result.success(
                        mapOf(
                            "ok" to false,
                            "error" to if (error is OutOfMemoryError) "JVM_OOM" else "FATAL_ERROR",
                            "message" to "${error.javaClass.simpleName}: ${error.message ?: "无详情"}。" +
                                if (error is OutOfMemoryError)
                                    "堆耗尽（上限 ${zhou.solab.tools.MemPressure.heapLimitMb()}MB）。等待其他任务释放后重试，或重启 App 清空堆；" +
                                        "重内存工具已互斥，若单工具仍 OOM 属峰值超限，建议改用更小的动作粒度（如 jadx 指定 dexName 逐 dex）。"
                                else "执行中发生严重错误，任务已终止",
                        ),
                    )
                }
            } finally {
                if (heavyPermitAcquired) heavyExecutionGate.release()
            }
        }
    }

    /** 从方法参数 Map 中取指定 key 的值（K2 对 Java 泛型方法 argument<T> 推断有缺陷，改用此模式）。 */
    private fun arg(call: MethodCall, key: String): Any? =
        (call.arguments as? Map<*, *>)?.get(key)

    /** M1 移植工具统一分发：参数转 JSONObject，返回信封 JSON 转 Map（MethodChannel 不支持 org.json 类型）。 */

    // ── 只读引擎结果缓存（dex 层） ────────────────────────────────────
    // dexSearch/stringScan/xref/outline 对同一 (参数, APK 状态) 的重复调用
    // （agent 收窄查询 / 重试 / 多轮追问）成本是整包扫描级。键含
    // path+mtime+size：任何补丁/重打包后自动失效。驱逐按总字节数
    // （READ_ENGINE_CACHE_CHARS ≈ 6MB）而非条数——单条结果体积差三个数量级。
    private val readEngineCache = LinkedHashMap<String, String>(16, 0.75f, true)

    init {
        // 注册进 MemPressure 清理链：onTrimMemory / native 压力 / OOM 恢复时整体清空
        zhou.solab.tools.MemPressure.registerCleanup("read-engine-cache") {
            synchronized(readEngineCache) { readEngineCache.clear() }
        }
    }

    private fun cacheKey(action: String, args: JSONObject, sourcePath: String?): String {
        val src = if (sourcePath.isNullOrBlank()) "" else {
            val f = java.io.File(sourcePath)
            "${f.canonicalPath}|${f.lastModified()}|${f.length()}"
        }
        return "$action|$src|${args}"
    }

    private fun cachedReadEngine(
        call: MethodCall,
        result: MethodChannel.Result,
        action: String,
        invoke: (JSONObject) -> JSONObject,
    ) {
        val args = (call.arguments as? Map<*, *>)?.let { JSONObject(it) } ?: JSONObject()
        val key = cacheKey("read:$action", args, args.optString("path"))
        synchronized(readEngineCache) { readEngineCache[key] }?.let { hit ->
            runAsync(result, "$action:cache-hit") { jsonToMap(JSONObject(hit)) as Map<String, Any> }
            return
        }
        runAsync(result, action) {
            val out = invoke(args).toString()
            synchronized(readEngineCache) {
                readEngineCache[key] = out
                // 体积制驱逐：整包扫描结果 JSON 可达数 MB，按总字节数封顶
                // （≈6MB，12 条 LRU 上限下曾经 12×3MB 无压力地占住 36MB 堆）。
                var total = readEngineCache.values.sumOf { it.length }
                while (readEngineCache.size > 1 && total > READ_ENGINE_CACHE_CHARS) {
                    val evicted = readEngineCache.remove(readEngineCache.keys.first()) ?: break
                    total -= evicted.length
                }
            }
            jsonToMap(JSONObject(out)) as Map<String, Any>
        }
    }

    private fun portedTool(
        call: MethodCall,
        result: MethodChannel.Result,
        invoke: (JSONObject) -> JSONObject,
    ) {
        val args = (call.arguments as? Map<*, *>)?.let { JSONObject(it) } ?: JSONObject()
        // 泛型擦除下 Any?→Any 转换运行时安全（值非空已由 jsonValue 归一）
        runAsync(result, call.method, call) { jsonToMap(invoke(args)) as Map<String, Any> }
    }

    /** M3: SO 引擎单例（工作区状态跨调用保持）。 */
    private val soEngine: NativeSoEngine by lazy { NativeSoEngine.shared(context) }

    /**
     * edit_* 的 edits 参数归一化：模型可能传 string[]（每项 JSON 文本）或 object[]，
     * 部分 Android 版本 JSONObject(Map) 也不递归 wrap 嵌套 List。统一转成
     * JSONArray[JSONObject]，非法元素返回结构化错误而不是抛 JSONException。
     */
    private fun normalizeEdits(args: JSONObject): JSONArray {
        fun wrapItem(item: Any?): Any = when (item) {
            is JSONObject, is String, is Number, is Boolean -> item
            is Map<*, *> -> JSONObject(item)
            is List<*> -> JSONArray(item)
            null -> JSONObject.NULL
            else -> item.toString()
        }
        val raw = args.opt("edits")
        if (raw == null) {
            val direct = JSONObject()
            listOf(
                "mode", "value", "returnType", "writeAsm", "newAsm", "asm",
                "assembly", "byteLength", "instructionCount", "instructionIndex",
                "byteOffset", "offset", "address", "overrideStackCheck",
            ).forEach { key -> if (args.has(key)) direct.put(key, args.opt(key)) }
            return if (direct.length() == 0) JSONArray() else JSONArray().put(direct)
        }
        val src: JSONArray = when (raw) {
            is JSONArray -> raw
            is List<*> -> JSONArray(raw.map(::wrapItem))
            is String -> runCatching { JSONArray(raw) }.getOrElse { return JSONArray() }
            else -> JSONArray()
        }
        val out = JSONArray()
        for (i in 0 until src.length()) {
            val item = src.opt(i)
            out.put(
                when (item) {
                    is JSONObject -> item
                    is String -> runCatching { JSONObject(item) }.getOrElse {
                        throw IllegalArgumentException("edits[$i] is a string but not a valid JSON object: ${item.take(120)}")
                    }
                    is Map<*, *> -> JSONObject(item)
                    else -> throw IllegalArgumentException("edits[$i] must be a JSON object, got ${item?.javaClass?.simpleName ?: "null"}")
                },
            )
        }
        return out
    }

    /** M3: SO 引擎分发（完整域：workspace/read/edit/emulate/backend/blutter）。 */
    private fun soEngineDispatch(args: JSONObject): JSONObject {
        // B4：blutterAction 在场但 action 缺失时归位 blutter，防静默默认 open
        // 把 blutter 子动作顶替成工作区打开（与 Dart 侧 _handleSoAnalyze 同款）。
        val action = if (args.optString("action").isBlank() &&
            args.optString("blutterAction").isNotBlank()
        ) {
            args.put("action", "blutter")
            "blutter"
        } else {
            args.optString("action", "open")
        }
        val start = System.nanoTime()
        zhou.solab.tools.TaskCancel.check()
        emitSoProgress(5, "so_analyze:$action")
        val result = dispatchSoAction(args, action)
        val workspaceId = args.optString("workspaceId")
        val editSessionId = args.optString("editSessionId")
        if (action in setOf("read_elf", "crypto_scan", "jni_bridge", "read_stats", "disasm", "hexdump", "strings", "search", "list", "overview", "analysis_report") &&
            result.optBoolean("ok") && workspaceId.isNotBlank()) {
            result.optJSONObject("data")?.put("readState", soEngine.readState(workspaceId, editSessionId))
        }
        emitSoProgress(100, "so_analyze:$action:done")
        val micros = (System.nanoTime() - start) / 1000
        zhou.solab.tools.KotlinToolStats.record(
            "so_analyze:$action",
            result.optBoolean("ok"),
            micros,
            result.optJSONObject("error")?.optString("message").orEmpty(),
        )
        return result
    }

    /// F-43（2026-10-04）：退役动作在**接受面**统一早退，与 Dart 侧
    /// kSoAnalyzeRetiredActions 同口径（reason + instead）。此前只有 Dart 执行前
    /// 拦截，Kotlin 分发层还留着活分支照常执行——进程统计里 25+ 次纯浪费调用，
    /// 且 capabilities 的裸回执被统计记成"失败且 lastError 空串"。现在任何入口
    /// 都拿到「已知不可用 + 怎么改」。
    private fun retiredActionError(action: String): JSONObject? = when (action) {
        "capabilities" -> err(
            "RETIRED_ACTION",
            "capabilities 已退役：本动作未接通（能力清单改由工具地图发布）。改用 " +
                "get_solab_tool_map(tool=\"so_analyze\") 读完整动作目录；Blutter runner 矩阵用 " +
                "so_analyze(action=\"blutter\", blutterAction=\"packages\")。",
            "action", action
        )
        "open_url" -> err(
            "RETIRED_ACTION",
            "open_url 已退役（另有 SSRF 守卫：仅公网 http(s)，内网/回环/明文跳转一律拒绝）。" +
                "先把 .so/ELF 落到工作目录（file(action=\"write\") 或 out-of-band 下载），再 " +
                "so_analyze(action=\"open\", path=\"<工作目录内的文件>\")。",
            "action", action
        )
        "emulate", "emulate_dump", "emulation_status" -> err(
            "RETIRED_ACTION",
            "emulate 族已退役：JNI_OnLoad 未导出，进程内仿真入口不成立。走 " +
                "so_analyze(action=\"unidbg_dispatch\" / \"unidbg_batch\") 全仿真；只读导出函数用 " +
                "action=\"jni_bridge\" + call_export。",
            "action", action
        )
        "lief_dispatch", "lief_patch_address", "lief_add_export", "lief_remove_symbol" -> err(
            "RETIRED_ACTION",
            "lief_* 已退役：LIEF 增删改入口未接通。改用 so_analyze(action=\"edit_hex\"/\"edit_asm\"/" +
                "\"edit_symbol\") 内置原生编辑通道（支持等长与变长写），落产物用 action=\"build\"。",
            "action", action
        )
        else -> null
    }

    /// v8-D7（2026-10-04 真机）：不需要 workspaceId 的动作（打开/列举/资产/关闭）。
    private val workspaceOptionalActions = setOf(
        "set_work_dir", "open", "open_url", "workspaces", "handles",
        "list_sources", "close", "asset_status", "asset_download",
    )

    private fun dispatchSoAction(args: JSONObject, action: String): JSONObject {
        val ws = args.optString("workspaceId")
        val es = args.optString("editSessionId")
        retiredActionError(action)?.let { return it }
        // v8-D7：空 workspaceId 与"工作区失效"语义分开——前者是 workspace_required
        // （没传参数），后者才是 workspace_not_found。过去 edit_hex/edit_asm 对
        // 两者都回 not_found + 让人去重开 SO，把调用方带偏。
        if (ws.isBlank() && action !in workspaceOptionalActions) {
            return err(
                "WORKSPACE_REQUIRED",
                "No workspaceId was provided. Call so_analyze(action=open) first and use its returned workspaceId.",
                "workspaceId",
                "",
            )
        }
        return when (action) {
            // workspace
            "set_work_dir" -> {
                // 统一工作路径：Dart 侧把 APK 工作目录同步给 SO 引擎（path 模式，免 SAF）
                val dir = args.optString("path").ifBlank { args.optString("workDir") }
                if (dir.isBlank()) err("INVALID_ARGUMENT", "缺少 path(工作目录)", "path", "")
                else {
                    soEngine.setWorkDirectoryPath(dir)
                    zhou.solab.tools.ok(JSONObject().put("workDir", dir).put("pathMode", true))
                }
            }
            "open" -> soEngine.open(args.optString("path"), args.optBoolean("temporary", true))
            // 下载远程 SO 到工作目录后打开（引擎 openUrl 一直有，此前分发层漏接）
            "open_url" -> soEngine.openUrl(args.optString("url"), args.optString("outputName"), args.optBoolean("temporary", false))
            "workspaces" -> soEngine.listWorkspaces()
            // D20：句柄映射——由 workspaceId 查对应 Blutter jobId（反之亦然），
            // 不必再靠人工比对 VA/fileOffset 判断"是不是同一个产物"。
            "handles" -> soEngine.handles()
            "close" -> soEngine.close(ws)
            "list_sources" -> soEngine.listAvailableSos(args.optString("prefix"), args.optInt("limit", 50), args.optString("cursor"))
            "analyze_apk" -> soEngine.analyzeApk(args.optString("path"), args.optInt("entryLimit", 500))
            // read
            "read_elf" -> soEngine.readElf(ws, es)
            "crypto_scan" -> soEngine.cryptoScan(ws, es)
            "jni_bridge" -> soEngine.jniBridge(ws, es)
            "read_stats" -> soEngine.readStats(ws, es)
            "disasm" -> soEngine.disasm(ws, es, locatorOrVa(args), args.optInt("limit", 100), args.optString("cursor"), args.optInt("instructionOffset"), args.optInt("byteOffset"), args.optInt("maxBytes", args.optInt("bytes", 4096)), args.optString("addr").ifBlank { args.optString("va") }, if (args.has("thumb")) args.optBoolean("thumb") else null, args.optString("mode", "auto"), args.optString("vaEnd"), args.optBoolean("includePseudocode", false))
            // 阶段 0（C1/C16）：outline/xref_symbol/xref_string 此前是死代码入口
            // （引擎函数存在但无路由不可达）——接入后 C1 的 rizin 真值 outline
            // 与 C16 的 arm64 unsupported 标注才对调用方生效。
            "outline" -> soEngine.outline(ws, es, locatorOrVa(args), args.optInt("limit", 100))
            "xref_symbol" -> soEngine.xrefSymbol(ws, es, locatorOrVa(args), args.optString("direction", "to"), args.optInt("limit", 100))
            "xref_string" -> soEngine.xrefString(ws, es, locatorOrVa(args), args.optInt("limit", 100))
            "hexdump" -> soEngine.hexdump(ws, es, locatorOrVa(args), args.optInt("byteOffset"), args.optInt("maxBytes", 512))
            "strings" -> soEngine.strings(ws, es, args.optString("locator"), args.optString("prefix"), args.optInt("limit", 100), cursor = args.optString("cursor"), regex = args.optBoolean("regex"), ignoreCase = args.optBoolean("ignoreCase", true), encoding = args.optString("encoding"), minConfidence = args.optDouble("minConfidence", 0.0))
            "search" -> soEngine.search(ws, es, args.optString("target", "overview"), args.optString("query"), args.optInt("limit", 50), args.optString("pathHint"), args.optString("cursor"))
            "list" -> soEngine.list(ws, es, args.optString("view", "sections"), args.optString("prefix"), args.optInt("limit", 100), args.optString("pathHint"), args.optString("cursor"))
            "overview" -> soEngine.overview(ws, es)
            "analysis_report" -> soEngine.analysisReport(ws, es, args.optBoolean("writeToFile", true))
            // edit session
            "edit_open" -> soEngine.editOpen(ws)
            "edit_snapshot" -> soEngine.editSnapshot(ws, es, args.optString("label"))
            "edit_rollback" -> args.optString("snapshotId").takeIf { it.isNotBlank() }
                ?.let { soEngine.editRollbackById(ws, es, it) }
                ?: soEngine.editRollback(ws, es, args.optInt("snapshotIndex", -1))
            "edit_undo" -> soEngine.editUndo(ws, es, args.optInt("count", 1))
            "edit_redo" -> soEngine.editRedo(ws, es, args.optInt("count", 1))
            "edit_reset" -> soEngine.editReset(ws, es)
            "edit_hex" -> {
                // VA 模式：va+patchHex 走会话内 VA 补丁（有 dryRun/审计/undo，比 lief_patch_address 更安全）
                val vaStr = args.optString("va")
                if (vaStr.isNotBlank()) {
                    val va = zhou.solab.tools.HexCodec.long(vaStr)
                        ?: return err("INVALID_ARGUMENT", "va must be a hex address", "va", vaStr)
                    val patch = zhou.solab.tools.HexCodec.bytes(args.optString("patchHex"))
                        ?: return err("INVALID_HEX", "patchHex must contain valid byte pairs", "patchHex", args.optString("patchHex"))
                    soEngine.editHexVa(ws, es, va, patch, args.optBoolean("dryRun", true), args.optString("targetVersion"))
                } else {
                    // v8-D3（2026-10-04 真机）：locator+patchHex 简写形态过去被
                    // 静默忽略（normalizeEdits 只看 edits 数组）→ dryRun 恒空预览，
                    // 而空预览会被"无变化预览"契约判成不可用。这里补简写展开：
                    // byteOffset=0（相对 locator 起点），与 edits[].byteOffset 语义一致。
                    val patchHex = args.optString("patchHex")
                    val editsArray = args.optJSONArray("edits")
                    val normalized = if (patchHex.isNotBlank() &&
                        (editsArray == null || editsArray.length() == 0)) {
                        JSONArray().put(JSONObject().put("byteOffset", 0).put("newHex", patchHex))
                    } else {
                        normalizeEdits(args)
                    }
                    soEngine.editHex(ws, es, args.optString("locator"), normalized, args.optBoolean("dryRun", true), args.optString("targetVersion"))
                }
            }
            "edit_asm" -> soEngine.editAsm(ws, es, locatorOrVa(args), normalizeEdits(args), args.optBoolean("dryRun", true), args.optString("targetVersion"))
            "edit_symbol" -> soEngine.editSymbol(ws, es, args.optString("locator"), normalizeEdits(args), args.optBoolean("dryRun", true), args.optString("targetVersion"))
            "edit_check" -> soEngine.editCheck(ws, es)
            "fix_sections" -> soEngine.fixSections(ws, es)
            // build/diff/audit
            "build" -> soEngine.build(ws, es, args.optString("outputName", "patched.so"), args.optString("conflictStrategy"), if (args.has("writeReport")) args.optBoolean("writeReport") else null, if (args.has("writeToWorkDir")) args.optBoolean("writeToWorkDir") else null)
            // 多变体构建（一次输出多个补丁变体，引擎 buildMany 此前分发层漏接）
            "build_many" -> soEngine.buildMany(ws, es, args.optJSONArray("outputs") ?: JSONArray(), args.optString("conflictStrategy"), if (args.has("writeReport")) args.optBoolean("writeReport") else null, if (args.has("writeToWorkDir")) args.optBoolean("writeToWorkDir") else null)
            "list_builds" -> soEngine.listBuildOutputs(args.optString("prefix"), args.optInt("limit", 200))
            "diff" -> soEngine.diff(ws, es, args.optInt("limit", 200), args.optString("compareSessionId"), args.optString("compareWorkspaceId"))
            // 两个工作区结构化对比（Rizin 字节级 + 函数相似度，引擎 rzDiff 此前分发层漏接）
            "rz_diff" -> soEngine.rzDiff(ws, es, args.optString("workspaceIdB"), args.optString("editSessionIdB"))
            "audit" -> soEngine.editAudit(ws, es)
            // 审计持久化/回读（引擎 persistAudit/loadAudit 此前分发层漏接）
            "audit_persist" -> soEngine.persistAudit(ws, es)
            "audit_load" -> soEngine.loadAudit(args.optString("file"))
            "list_audits" -> soEngine.listAudits(args.optString("prefix"), args.optInt("limit", 100))
            // backend
            "rz_functions" -> soEngine.rzFunctions(ws, es, args.optInt("limit", 100), args.optString("cursor"), args.optInt("offset"))
            "rz_xrefs" -> soEngine.rzXrefs(ws, es, args.optString("locator").ifBlank { args.optString("target") }.ifBlank { args.optString("addr") }.ifBlank { args.optString("va") }, args.optString("direction", "to"))
            "rz_decompile" -> soEngine.rzDecompile(ws, es, args.optString("locator"), args.optBoolean("strict", true))
            "rz_crypto" -> soEngine.rzScanCrypto(ws, es)
            "rz_cfg" -> soEngine.rzCfg(ws, es, args.optString("locator"))
            "rz_esil" -> soEngine.rzEsilStep(ws, es, args.optString("locator"), args.optInt("stepCount", 1))
            "rz_search_bytes" -> soEngine.rzSearchBytes(ws, es, args.optString("pattern"), zhou.solab.tools.HexCodec.long(args.optString("fromVa")) ?: 0L, zhou.solab.tools.HexCodec.long(args.optString("toVa")) ?: 0L)
            "rz_command" -> soEngine.rzCommand(ws, es, args.optString("command"), args.optBoolean("unsafe", false))
            // 显式触发 Rizin 重新分析（引擎 rzAnalyze 此前分发层漏接；rz_* 结果稀疏/过期时先跑它）
            "rz_analyze" -> soEngine.rzAnalyze(ws, es)
            // 独立汇编（不在编辑会话内，引擎 assembleRaw 此前分发层漏接）
            "rz_asm" -> soEngine.assembleRaw(ws, es, args.optString("asm"), zhou.solab.tools.HexCodec.long(args.optString("addr")) ?: 0L, if (args.has("thumb")) args.optBoolean("thumb") else null, args.optString("mode", "auto"))
            "xanso_dispatch" -> soEngine.xansoDispatch(ws, es, args.optString("op", "status"))
            // xAnSo 节区头重建（引擎 xansoBuildSections 此前分发层漏接；fix_sections 走 LIEF，这里走 xAnSo 上游算法，force=true 可重建已有节表）
            "xanso_build_sections" -> soEngine.xansoBuildSections(ws, es, args.optBoolean("force", false))
            "lief_dispatch" -> soEngine.liefDispatch(ws, es, args.optString("op"), args.optString("objectPath"), args.optString("method"), args.optJSONArray("args") ?: JSONArray(), args.optBoolean("dryRun"))
            // LIEF 快捷 VA 补丁/导出管理（引擎方法此前分发层漏接；edit_hex 走偏移，这里走 VA）
            "lief_patch_address" -> {
                val va = zhou.solab.tools.HexCodec.long(args.optString("va"))
                    ?: return err("INVALID_ARGUMENT", "va must be a hex address", "va", args.optString("va"))
                val patch = zhou.solab.tools.HexCodec.bytes(args.optString("patchHex"))
                    ?: return err("INVALID_HEX", "patchHex must contain valid byte pairs", "patchHex", args.optString("patchHex"))
                soEngine.liefPatchAddress(ws, es, va, patch)
            }
            "lief_add_export" -> {
                val va = zhou.solab.tools.HexCodec.long(args.optString("va"))
                    ?: return err("INVALID_ARGUMENT", "va must be a hex address", "va", args.optString("va"))
                soEngine.liefAddExportedFunction(ws, es, va, args.optString("name"))
            }
            "lief_remove_symbol" -> soEngine.liefRemoveSymbol(ws, es, args.optString("name"))
            // emulate
            "emulate" -> soEngine.emulate(ws, es, args.optString("symbolName"), args.optJSONArray("args") ?: JSONArray(), args.optBoolean("trace"))
            "emulate_dump" -> soEngine.dumpMemory(ws, es, zhou.solab.tools.HexCodec.long(args.optString("addr")) ?: 0L, args.optInt("size", 256))
            "emulation_status" -> soEngine.emulationStatus()
            "unidbg_dispatch" -> soEngine.unidbgDispatch(ws, es, args.optString("op"), args.optString("method"), args.optJSONArray("args") ?: JSONArray())
            "unidbg_batch" -> soEngine.unidbgBatch(ws, es, args)
            // blutter
            // so_analyze(action=blutter) 的语义是"跑 Flutter 离线分析"，
            // coordinator 侧 action 命名空间不同（inspect/analyze/status/...），
            // 这里改写：默认 analyze，blutterAction 可选覆盖做 job 管理。
            "blutter" -> soEngine.flutterBlutter(
                JSONObject(args.toString()).put("action", args.optString("blutterAction", "analyze"))
            )
            // capability
            "capabilities" -> soEngine.capabilityRegistry()
            // 上下文感知建议（借鉴玄星逆核 meta_info action=suggest；任何 action 报错后带 workspaceId 重调拿替代路径）
            "suggest" -> soEngine.soSuggest(ws, es)
            // 按需下载（体积控制：lite 版重型资源按需拉取）
            "asset_status" -> {
                val names = args.optJSONArray("names")?.let { arr ->
                    (0 until arr.length()).map { arr.optString(it) }
                } ?: listOf("rizin/plugins/rz_ghidra_sleigh/.keep")
                zhou.solab.tools.AssetDownloader.status(context, names)
            }
            "asset_download" -> {
                val url = args.optString("url")
                val name = args.optString("name")
                val sha = args.optString("sha256")
                if (name.isBlank()) err("INVALID_ARGUMENT", "缺少 name(资源名)", "name", "")
                else zhou.solab.tools.AssetDownloader.download(context, url, name, sha)
                    ?: zhou.solab.tools.ok(JSONObject()
                        .put("tool", "asset_download")
                        .put("action", "download")
                        .put("name", name)
                        .put("downloaded", true)
                        .put("path", zhou.solab.tools.AssetDownloader.assetFile(context, name)?.absolutePath)
                        .put("hint", "资源已就绪，可立即使用（blutter/ghidra 运行时自动发现）"))
            }
            else -> err(
                "UNKNOWN_ACTION",
                "未知 soAnalyze action: $action。**域名不是动作**（read / edit / blutter / emulate " +
                    "是域）：读取域的实际动作是 overview / list / read_elf / read_stats / hexdump / " +
                    "strings / search；编辑域是 edit_open / edit_hex / edit_asm / edit_symbol / " +
                    "edit_snapshot / edit_undo / edit_redo / edit_check / edit_diff / audit / build；" +
                    "其他常用动作 blutter / rz_functions / rz_xrefs / rz_crypto / disasm / diff / " +
                    "unidbg_dispatch。完整目录见 get_solab_tool_map(tool=so_analyze)。",
                "action",
                action,
            )
        }
    }

    private fun locatorOrVa(args: JSONObject): String = args.optString("locator")
        .ifBlank { args.optString("va") }
        .ifBlank { args.optString("addr") }

    /** 递归把 org.json 结构转成 MethodChannel 可编码的 Map/List。 */
    private fun jsonToMap(obj: JSONObject): Map<String, Any?> {
        val map = LinkedHashMap<String, Any?>()
        obj.keys().forEach { k ->
            map[k] = jsonValue(obj.get(k))
        }
        return map
    }

    private fun jsonValue(v: Any?): Any? = when {
        v == null || v == JSONObject.NULL -> null
        v is JSONObject -> jsonToMap(v)
        v is JSONArray -> (0 until v.length()).map { jsonValue(v.get(it)) }
        else -> v
    }

    private fun resolveSource(call: MethodCall): File {
        val path = arg(call, "path") as? String
        if (path.isNullOrBlank()) throw StructuralError("invalid_args", "缺少 APK 路径")
        val file = File(path)
        if (!file.isFile || file.length() <= 0L) {
            throw StructuralError("invalid_path", "APK 文件不存在或为空: ${file.absolutePath}")
        }
        return file
    }

    /**
     * 输出路径：优先用显式 outputDir（MT 工作目录等可访问位置），否则 APK 同目录。
     *
     * D8（2026-09-21 自检）两处修正：
     * 1) `outputName` 过去**收下却忽略**（永远回 `<stem>_v<N>.apk`）——静默吞参。
     *    现在真用它；同名已存在时在该名字自己的版本空间里递增，绝不静默覆盖。
     * 2) 新增 [nameTag]：给某类操作独立命名空间（去签按 mode 分），
     *    版本号各算各的，避免与其它类型的中间包重名——实测去签产物复用了上一轮
     *    已被清理的 `_v1.apk` 路径，两个不同内容先后占同一个名字。
     */
    private fun structuralOutput(
        source: File,
        outputName: String? = null,
        outputDir: String? = null,
        nameTag: String? = null,
    ): File {
        // 输出目录必填：产物必须落用户选定的「工作目录」（与 MT 工作目录一致），
        // 否则会落到 FilePicker 的内部 cache，无 root 拿不到、MT 也索引不到。
        if (outputDir.isNullOrBlank()) {
            throw StructuralError(
                "output_dir_required",
                "请先在 APK 工作台设置「工作目录」（需与 MT 工作目录一致），产物才能落外部可访问位置",
            )
        }
        val dirFile = File(outputDir)
        if (dirFile.exists() && !dirFile.isDirectory) {
            throw StructuralError("invalid_output_dir", "工作目录不存在或不是目录: $outputDir")
        }
        if (!dirFile.exists() && !dirFile.mkdirs()) {
            throw StructuralError("invalid_output_dir", "无法创建工作目录: $outputDir")
        }
        if (!outputName.isNullOrBlank()) {
            val cleaned = File(outputName).name
            if (cleaned.isBlank() || cleaned == "." || cleaned == "..") {
                throw StructuralError("invalid_args", "outputName 非法: $outputName")
            }
            val requested = File(dirFile, cleaned)
            if (!requested.isFile) return requested
            // 显式名字已占用：在该名字自己的版本空间里递增（不覆盖既有产物）。
            val explicitStem = requested.nameWithoutExtension
            val explicitVersion = nextTaggedVersion(dirFile, explicitStem, "")
            return File(dirFile, "${explicitStem}_v$explicitVersion.apk")
        }
        val stem = intermediateStem(source, dirFile)
        val tag = nameTag?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { "_${it.lowercase(Locale.ROOT)}" } ?: ""
        return File(dirFile, "${stem}${tag}_v${nextTaggedVersion(dirFile, stem, tag)}.apk")
    }

    private fun intermediateStem(source: File, outputDir: File): String {
        val stem = source.nameWithoutExtension
        val match = Regex("^(.*)_v\\d+$", RegexOption.IGNORE_CASE).matchEntire(stem)
        val previous = match?.groupValues?.getOrNull(1).orEmpty()
        return if (previous.isNotBlank() && File(outputDir, "$previous.apk").isFile) previous else stem
    }

    /** 在 `<stem><tag>_v<N>.apk` 这个**带标签的独立命名空间**里取下一个版本号。 */
    private fun nextTaggedVersion(outputDir: File, stem: String, tag: String): Int {
        val pattern = Regex("^${Regex.escape(stem)}$tag" + "_v(\\d+)\\.apk$", RegexOption.IGNORE_CASE)
        val maxVersion = outputDir.listFiles().orEmpty().mapNotNull { file ->
            pattern.matchEntire(file.name)?.groupValues?.getOrNull(1)?.toIntOrNull()
        }.maxOrNull() ?: 0
        return maxVersion + 1
    }

    private fun nextIntermediateVersion(source: File, outputDir: File): Int {
        val stem = intermediateStem(source, outputDir)
        return nextTaggedVersion(outputDir, stem, "")
    }

    private fun productStem(source: File, outputDir: File): String = intermediateStem(source, outputDir)

    /** 从调用参数取输出目录（可空）。 */
    private fun outputDirArg(call: MethodCall): String? =
        (arg(call, "outputDir") as? String)?.takeIf { it.isNotBlank() }

    // ---- APK Signing Block 解析（v2/v3 真伪检测，零依赖） ----

    /** 返回 [v2, v3] 两个布尔标志（一次读文件，避免两次 RandomAccessFile）。 */
    private fun signingSchemeFlags(apk: File): List<Boolean> {
        val ids = signingBlockIds(apk)
        return listOf(ids.contains(0x7109871aL), ids.contains(0xf05368c0L))
    }

    /**
     * v1 失败的具体条目/原因（v12 复测 F-19）。
     *
     * 场景：META-INF 有 v1 签名文件、但 apksig 整体验签判定 v1 未通过。
     * 完整验签以 v2/v3 为准通过，v1 的失败原因被「已验证」结论盖住——报告里
     * 只剩「常见于 v1 摘要未覆盖全部条目/后续增改文件」的推测。这里从**同一次
     * 验签结果**里取 v1 签名器与整体错误的 Issue（枚举名 + 参数），去重后至多
     * 5 条，让「为什么 v1=false」有本次包的实际证据（不额外跑第二遍验签）。
     */
    private fun v1IssueDetails(
        result: com.android.apksig.ApkVerifier.Result,
    ): List<String> = runCatching {
        val issues = buildList {
            addAll(result.v1SchemeSigners.flatMap { it.errors })
            addAll(result.v1SchemeIgnoredSigners.flatMap { it.errors })
            if (isEmpty()) {
                addAll(result.errors.filter { it.issue.name.startsWith("JAR_SIG") })
            }
        }
        issues
            .map { issue ->
                val params = issue.params.joinToString(", ") {
                    it?.toString().orEmpty()
                }
                if (params.isBlank()) issue.issue.name else "${issue.issue.name}[$params]"
            }
            .distinct()
            .take(5)
    }.getOrDefault(emptyList())

    /**
     * 解析 APK Signing Block 中全部签名块 id。
     * 原理：EOCD 末尾找签名块大小 → 定位 'APK Sig Block 42' magic → 顺序读各 id+len 对。
     */
    private fun signingBlockIds(apk: File): Set<Long> {
        return try {
            val eocdSize = 22
            val reader = java.io.RandomAccessFile(apk, "r")
            try {
                val fileLen = reader.length()
                if (fileLen < eocdSize + 16) return emptySet()
                // B1：EOCD 不一定在 fileLen-22（ZIP 允许 comment，部分分发渠道会加）。
                // 从末尾向前最多扫描 64KB 找 EOCD 签名 0x06054b50，并用 commentLen
                // 字段校验位置正确（commentLen == fileLen - eocdOffset - 22）。
                val eocd = ByteArray(eocdSize)
                fun isEocd(bytes: ByteArray): Boolean =
                    (bytes[0].toInt() and 0xff) == 0x50 &&
                        (bytes[1].toInt() and 0xff) == 0x4b &&
                        (bytes[2].toInt() and 0xff) == 0x05 &&
                        (bytes[3].toInt() and 0xff) == 0x06
                var eocdOffset = fileLen - eocdSize
                var found = false
                if (eocdOffset >= 0) {
                    reader.seek(eocdOffset)
                    reader.readFully(eocd)
                    if (isEocd(eocd) && readU16(eocd, 20) == (fileLen - eocdOffset - eocdSize).toLong()) {
                        found = true
                    }
                }
                if (!found) {
                    val scanStart = maxOf(0L, fileLen - eocdSize - 65535L)
                    var off = fileLen - eocdSize - 1
                    while (off >= scanStart) {
                        reader.seek(off)
                        reader.readFully(eocd)
                        if (isEocd(eocd) && readU16(eocd, 20) == (fileLen - off - eocdSize).toLong()) {
                            eocdOffset = off
                            found = true
                            break
                        }
                        off--
                    }
                }
                if (!found) return emptySet()
                // EOCD 签名 0x06054b50 已在定位阶段校验
                val cdOffset = readU32(eocd, 16)
                val cdSize = readU32(eocd, 12)
                val signingBlockSizeFieldEnd = cdOffset
                if (signingBlockSizeFieldEnd < 8 || signingBlockSizeFieldEnd > fileLen - 16) {
                    return emptySet()
                }
                // 签名块 size 字段（8 字节，紧邻中央目录之前）
                reader.seek(signingBlockSizeFieldEnd - 8)
                val sizeField = ByteArray(8)
                reader.readFully(sizeField)
                val blockSize = readU64(sizeField)
                if (blockSize < 24 || blockSize > (fileLen - cdSize)) return emptySet()
                val blockStart = signingBlockSizeFieldEnd - blockSize
                if (blockStart < 0) return emptySet()
                // magic 'APK Sig Block 42' 在块尾 16 字节
                reader.seek(signingBlockSizeFieldEnd - 16)
                val magic = ByteArray(16)
                reader.readFully(magic)
                val expected = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
                if (!magic.contentEquals(expected)) return emptySet()
                // 从块头开始遍历 id+len 对（头 8 字节 = 块大小，跳过）
                val ids = mutableSetOf<Long>()
                var pos = blockStart + 8
                // 遍历终点 = magic 起点 = 块尾 - 16（不能用 -24：最后一个 pair
                // 紧邻 magic 前，-24 会把 v2 块（通常最后一个 pair）截掉，误判 v1-only）
                val end = signingBlockSizeFieldEnd - 16
                while (pos + 8 <= end) {
                    reader.seek(pos)
                    val lenBytes = ByteArray(8)
                    reader.readFully(lenBytes)
                    val len = readU64(lenBytes)
                    reader.seek(pos + 8)
                    val idBytes = ByteArray(4)
                    reader.readFully(idBytes)
                    ids += readU32(idBytes, 0).toLong() and 0xffffffffL
                    if (len <= 0 || pos + 8 + len > end) break
                    pos += 8 + len
                }
                ids
            } finally {
                reader.close()
            }
        } catch (_: Exception) {
            emptySet()
        }
    }

    private fun readU32(bytes: ByteArray, offset: Int): Long =
        ((bytes[offset].toLong() and 0xff)) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8) or
            ((bytes[offset + 2].toLong() and 0xff) shl 16) or
            ((bytes[offset + 3].toLong() and 0xff) shl 24)

    private fun readU16(bytes: ByteArray, offset: Int): Long =
        ((bytes[offset].toLong() and 0xff)) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8)

    private fun readU64(bytes: ByteArray): Long {
        var value = 0L
        for (i in 0 until 8) {
            value = value or ((bytes[i].toLong() and 0xff) shl (8 * i))
        }
        return value
    }

    /** A1: 精确条目 + 目录前缀删除，流式重打包为未签名中间包。 */
    private fun deleteZipEntries(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        val outputDir = outputDirArg(call)
        val entries = (arg(call, "entries") as? List<*>)
            ?.mapNotNull { it as? String } ?: emptyList()
        val prefixes = (arg(call, "prefixes") as? List<*>)
            ?.mapNotNull { it as? String } ?: emptyList()
        val dryRun = arg(call, "dryRun") as? Boolean ?: false

        entries.forEach { name ->
            if (ApkStructuralOps.normalizeEntryName(name) == null) {
                throw StructuralError("invalid_entry_name", "非法条目名: $name")
            }
        }
        prefixes.forEach { prefix ->
            val trimmed = prefix.trimEnd('/')
            if (trimmed.isEmpty() || ApkStructuralOps.normalizeEntryName(trimmed) == null) {
                throw StructuralError("invalid_entry_name", "非法目录前缀: $prefix")
            }
        }
        val exact = LinkedHashSet(entries)
        val protectedHit = exact.any { ApkStructuralOps.isProtected(it) } ||
            prefixes.any { p ->
                val trimmed = p.trimEnd('/')
                ApkStructuralOps.isProtected(trimmed) ||
                    ApkStructuralOps.isProtected(trimmed + "/") ||
                    // 只保护「整个 lib/」目录；lib/<abi>/ 单 ABI 目录删除是正当的（ABI 过滤），放行
                    trimmed == "lib"
            }
        // 核心 so 白名单：这些是应用运行必需的，精确删除也拦（防误删导致闪退）。
        val coreSoExact = exact.any { isCoreSo(it) }
        if (protectedHit || coreSoExact) {
            throw StructuralError(
                "protected_entry",
                "AndroidManifest.xml / resources.arsc / classes*.dex / 核心 SO（libflutter/libapp/壳）受保护，不可删除",
            )
        }

        if (dryRun) {
            val (prefixCount, prefixBytes) = countDropped(source, prefixes)
            // P1-1 previewCount 只统计实际可删条目：exact 逐个核对 zip 是否存在，
            // 不存在的明确提示（防「deleted 空 但 previewCount=请求数」虚高误导）
            var exactBytes = 0L
            val exactMissing = mutableListOf<String>()
            withApkZip(source) { zip ->
                val names = HashMap<String, Long>()
                zip.entries().asSequence().filterNot { it.isDirectory }.forEach { e ->
                    ApkStructuralOps.normalizeEntryName(e.name)?.let { names[it] = e.size }
                }
                exact.forEach { name ->
                    val size = names[name]
                    if (size == null) exactMissing += name else exactBytes += size
                }
            }
            return mapOf(
                "ok" to true,
                "dryRun" to true,
                "deleted" to emptyList<Map<String, Any>>(),
                "savedBytes" to (prefixBytes + exactBytes),
                "previewCount" to (prefixCount + (exact.size - exactMissing.size)),
                "missingEntries" to exactMissing,
                "message" to if (exactMissing.isEmpty()) ""
                else "以下 ${exactMissing.size} 个条目在 APK 中不存在，已从预览计数排除: ${exactMissing.joinToString(", ")}",
            )
        }

        val output = structuralOutput(source, outputDir = outputDir)
        if (output.absolutePath == source.absolutePath) {
            throw StructuralError("invalid_args", "输出路径不能等于源 APK 路径")
        }
        val result = ApkStructuralOps.repack(
            source,
            output,
            dropExact = exact,
            dropPrefixes = prefixes,
        )
        return mapOf(
            "ok" to true,
            "outputPath" to output.absolutePath,
            "dryRun" to false,
            "deleted" to result.dropped.map { mapOf("path" to it.name, "size" to it.size) },
            "savedBytes" to result.droppedBytes,
        )
    }

    private fun writeZipEntry(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        val outputDir = outputDirArg(call)
        val rawOps = (arg(call, "entries") as? List<*>) ?: emptyList<Any?>()
        val dryRun = arg(call, "dryRun") as? Boolean ?: false
        if (rawOps.isEmpty()) throw StructuralError("invalid_args", "缺少 entries 操作列表")

        val ops = ArrayList<EntryOp>()
        rawOps.forEachIndexed { index, raw ->
            val op = raw as? Map<*, *> ?: throw StructuralError("invalid_args", "第 $index 个操作不是对象")
            val locator = op["locator"] as? String
                ?: throw StructuralError("invalid_args", "第 $index 个操作缺少 locator")
            val action = (op["action"] as? String)?.lowercase(Locale.ROOT)
                ?: throw StructuralError("invalid_args", "第 $index 个操作缺少 action")
            if (action !in ENTRY_ACTIONS) {
                throw StructuralError("invalid_args", "第 $index 个操作 action 非法: $action")
            }
            val name = if (locator.startsWith("zip_entry:")) {
                locator.substringAfter("zip_entry:")
            } else {
                locator
            }
            if (ApkStructuralOps.normalizeEntryName(name) == null) {
                throw StructuralError("invalid_entry_name", "非法条目名: $name")
            }
            val contentFile = if (action == "delete") null else try {
                entryContentFile(op["content"])
            } catch (e: StructuralError) {
                throw e
            } catch (e: Exception) {
                throw StructuralError("invalid_content", "条目 $name 本地文件无效: ${e.message}")
            }
            val content = if (action == "delete" || contentFile != null) {
                null
            } else {
                try {
                    ApkStructuralOps.decodeContent(op["content"])
                } catch (e: Exception) {
                    throw StructuralError("invalid_content", "条目 $name 内容解码失败: ${e.message}")
                } ?: throw StructuralError("invalid_args", "条目 $name 缺少 content(base64/hex 或本地 path)")
            }
            ops += EntryOp(
                locator = locator,
                name = name,
                action = action,
                content = content,
                contentFile = contentFile,
                contentSource = if (contentFile != null) "local_file" else if (action == "delete") "none" else "inline_payload",
                allowShrink = op["allowShrink"] as? Boolean ?: false,
            )
        }
        if (ops.map { it.name }.distinct().size != ops.size) {
            throw StructuralError("duplicate_entry", "同一条目只能操作一次，请合并后重试")
        }

        // 硬保护：签名文件不可写入；Manifest/arsc/dex 不可删除
        ops.forEach { op ->
            if (ApkStructuralOps.isSignatureEntry(op.name)) {
                if (op.action != "delete") {
                    throw StructuralError("protected_entry", "META-INF 签名文件不可写入: ${op.name}")
                }
            } else if (op.action == "delete" && ApkStructuralOps.isProtected(op.name)) {
                throw StructuralError("protected_entry", "禁止删除受保护条目: ${op.name}")
            }
        }

        // 载荷类型交叉校验（A2）：写 lib/**/*.so 必须是 ELF，写 *.dex 必须是
        // dex 魔数——防止把文本/错误文件静默写进结构条目毁产物。
        ops.forEach { op ->
            if (op.action == "delete") return@forEach
            val head = payloadMagic(op) ?: return@forEach
            val want: ByteArray? = when {
                op.name.startsWith("lib/") && op.name.endsWith(".so") -> byteArrayOf(0x7F, 0x45, 0x4C, 0x46)
                op.name.endsWith(".dex") -> "dex\n".toByteArray(Charsets.US_ASCII)
                else -> null
            }
            if (want != null && !head.copyOfRange(0, minOf(4, head.size)).contentEquals(want)) {
                throw StructuralError(
                    "payload_type_mismatch",
                    "载荷与目标条目类型不匹配：${op.name} 要求 " +
                        (if (op.name.endsWith(".dex")) "dex 魔数" else "ELF 魔数") +
                        "，实际头部 " + head.joinToString(" ") { "%02X".format(it) } +
                        "。请确认 soPath/content 指向正确的文件。",
                )
            }
        }

        // 预扫描：源条目名 + 未压缩 size（存在性 / 冲突 / 体积骤变守卫）
        val sourceNames = LinkedHashSet<String>()
        val sourceSizes = HashMap<String, Long>()
        withApkZip(source) { zip ->
            zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
                ApkStructuralOps.normalizeEntryName(entry.name)?.let { name ->
                    sourceNames.add(name)
                    sourceSizes[name] = entry.size
                }
            }
        }

        val overrides = LinkedHashMap<String, ByteArray>()
        val overrideFiles = LinkedHashMap<String, File>()
        val additions = LinkedHashMap<String, ByteArray>()
        val additionFiles = LinkedHashMap<String, File>()
        val deletes = LinkedHashSet<String>()
        val hashTargets = LinkedHashSet<String>()
        ops.forEach { op ->
            when (op.action) {
                "overwrite" -> {
                    if (op.name !in sourceNames) {
                        throw StructuralError("entry_not_found", "条目不存在，无法覆盖: ${op.name}")
                    }
                    // 体积骤变守卫（A3）：覆盖后缩小超过 90% 几乎必然出错
                    // （如 25MB so 被 26 字节文本覆盖），需显式 allowShrink 确认。
                    if (!op.allowShrink) {
                        val oldSize = sourceSizes[op.name] ?: 0L
                        val newSize = entryContentSize(op)
                        if (oldSize > 1024 && newSize in 1 until oldSize / 10) {
                            throw StructuralError(
                                "shrink_ratio_guard",
                                "覆盖将使 ${op.name} 从 $oldSize 字节缩到 $newSize 字节" +
                                    "（缩减 ${"%.1f".format((1 - newSize.toDouble() / oldSize) * 100)}%），" +
                                    "大概率是载荷选错。确认无误请传 allowShrink:true 重新执行。",
                            )
                        }
                    }
                    op.contentFile?.let { overrideFiles[op.name] = it }
                        ?: run { overrides[op.name] = op.content!! }
                    hashTargets += op.name
                }
                "add" -> {
                    if (op.name in sourceNames) {
                        throw StructuralError("entry_exists", "条目已存在，无法新增: ${op.name}")
                    }
                    op.contentFile?.let { additionFiles[op.name] = it }
                        ?: run { additions[op.name] = op.content!! }
                }
                "delete" -> {
                    if (op.name !in sourceNames) {
                        throw StructuralError("entry_not_found", "条目不存在，无法删除: ${op.name}")
                    }
                    if (!ApkStructuralOps.isSignatureEntry(op.name)) {
                        deletes += op.name
                    }
                    hashTargets += op.name
                }
            }
        }

        // before 哈希 + 源压缩元数据：一次 ZipFile 同时取两类信息
        // （原先 beforeHashes 和 dryRun 的压缩对比各开一次 zip 遍历同一批条目）。
        val beforeHashes = HashMap<String, ApkStructuralOps.SourceHash>()
        val sourceCompression = HashMap<String, Pair<Long, Int>>()
        if (hashTargets.isNotEmpty()) {
            withApkZip(source) { zip ->
                hashTargets.forEach { name ->
                    zip.getEntry(name)?.let { entry ->
                        beforeHashes[name] = ApkStructuralOps.readSourceHash(zip, entry)
                        sourceCompression[name] = entry.compressedSize to entry.method
                    }
                }
            }
        }

        val output = structuralOutput(source, outputDir = outputDir)
        val results = ops.map { op ->
            val before = beforeHashes[op.name]
            when (op.action) {
                "overwrite" -> resultEntry(
                    op, "overwrite",
                    before?.sha256 ?: "", entryContentSha256(op),
                    before?.size ?: 0L, entryContentSize(op),
                )
                "add" -> resultEntry(
                    op, "add",
                    "", entryContentSha256(op),
                    0L, entryContentSize(op),
                )
                "delete" -> if (op.name in deletes) {
                    resultEntry(op, "delete", before?.sha256 ?: "", "", before?.size ?: 0L, 0L)
                } else {
                    // META-INF 签名文件：自动跳过
                    resultEntry(op, "skipped", before?.sha256 ?: "", "", before?.size ?: 0L, 0L)
                }
                else -> throw IllegalStateException("unreachable action: ${op.action}")
            }
        }

        if (dryRun) {
            // P0 压缩体积对比：预览阶段暴露 STORED/DEFLATED 差异导致的体积膨胀
            // （sourceCompression 已在 beforeHashes 同一次 ZipFile 遍历中取得）
            val enriched = results.map { r ->
                val name = (r["locator"] as String).removePrefix("zip_entry:")
                if (r["action"] == "overwrite" || r["action"] == "add") {
                    val op = ops.firstOrNull { it.name == name }
                    val (beforeComp, method) = sourceCompression[name] ?: (0L to -1)
                    val afterEstimate = op?.let { runCatching { estimateDeflatedSize(it) }.getOrDefault(-1L) } ?: -1L
                    r + mapOf(
                        "beforeCompressedSize" to beforeComp,
                        "afterCompressedSizeEstimate" to afterEstimate,
                        "sourceCompressionMethod" to when (method) {
                            java.util.zip.ZipEntry.STORED -> "STORED"
                            java.util.zip.ZipEntry.DEFLATED -> "DEFLATED"
                            else -> "NEW"
                        },
                        "sizeNote" to "afterCompressedSizeEstimate 按 DEFLATED 预估；重打包会沿用源条目压缩方式，源 DEFLATED 不会被升级为 STORED",
                    )
                } else {
                    r
                }
            }
            return mapOf(
                "ok" to true,
                "dryRun" to true,
                "outputPath" to output.absolutePath,
                "results" to enriched,
            )
        }

        ApkStructuralOps.repack(
            source = source,
            output = output,
            dropExact = deletes,
            overrides = overrides,
            overrideFiles = overrideFiles,
            additions = additions,
            additionFiles = additionFiles,
        )
        // A5：坏包不出厂——中央目录/dex 魔数自检不过直接抛错。注意 repack
        // 内部已经 atomicMove 提交过产物，所以这里必须把坏包删掉再抛，
        // 否则 `_vN.apk` 会留在工作目录里（用户可能直接安装它）。
        try {
            verifyApkIntegrity(output)
        } catch (e: StructuralError) {
            output.delete()
            throw e
        }
        return mapOf("ok" to true, "outputPath" to output.absolutePath, "results" to results)
    }

    /** T1: 列出 APK 内 lib 目录下各 ABI 的 so 条目（so_patch_into_apk 自动定位回填目标）。 */
    private fun listLibEntries(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        val libs = ArrayList<Map<String, Any>>()
        val abis = LinkedHashSet<String>()
        withApkZip(source) { zip ->
            zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
                val name = ApkStructuralOps.normalizeEntryName(entry.name) ?: return@forEach
                if (!name.startsWith("lib/") || !name.endsWith(".so")) return@forEach
                val rest = name.removePrefix("lib/")
                if (!rest.contains('/')) return@forEach
                val abi = rest.substringBefore('/')
                if (abi.isEmpty()) return@forEach
                abis += abi
                libs.add(
                    mapOf(
                        "name" to name,
                        "abi" to abi,
                        "soName" to rest.substringAfter('/'),
                        "size" to entry.size,
                    )
                )
            }
        }
        return mapOf(
            "ok" to true,
            "count" to libs.size,
            "abis" to abis.toList(),
            "entries" to libs,
        )
    }

    /** A3: 只保留 keepAbis，过滤 lib/<其他 ABI>/ 全部条目后重打包。 */
    private fun buildApk(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        val outputDir = outputDirArg(call)
        val keepAbis = (arg(call, "keepAbis") as? List<*>)
            ?.map { it.toString().trim().lowercase(Locale.ROOT) }
            ?.filter { it.isNotEmpty() }
            ?.toSet() ?: emptySet()
        val outputName = (arg(call, "outputName") as? String)?.takeIf { it.isNotBlank() }
        val dryRun = arg(call, "dryRun") as? Boolean ?: false
        // M1: sign=true 时重打包后链式内置签名（玄星逆核 apk_sign），出可直接安装的签名包
        val sign = arg(call, "sign") as? Boolean ?: false
        keepAbis.forEach { abi ->
            if (abi.contains('/') || abi.contains('\\') || abi == "." || abi == "..") {
                throw StructuralError("invalid_args", "非法 ABI: $abi")
            }
        }

        // 预扫描：源包中实际存在的 ABI 目录
        val presentAbis = LinkedHashSet<String>()
        withApkZip(source) { zip ->
            zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
                val name = ApkStructuralOps.normalizeEntryName(entry.name) ?: return@forEach
                if (name.startsWith("lib/")) {
                    val abi = name.removePrefix("lib/").substringBefore('/')
                    if (abi.isNotEmpty()) presentAbis += abi
                }
            }
        }
        val filteredAbis = presentAbis.filterNot { it in keepAbis }.sorted()
        val dropPrefixes = filteredAbis.map { "lib/$it/" }

        val output = structuralOutput(source, outputName, outputDir)
        if (output.absolutePath == source.absolutePath) {
            throw StructuralError("invalid_args", "输出文件名不能与源 APK 相同")
        }
        // 签名产物命名：统一「源名_成品.apk」，中间包只保留连续 v 号。
        val signedOutput = File(output.parentFile, "${productStem(source, output.parentFile)}_成品.apk")

        if (dryRun) {
            val (count, bytes) = countDropped(source, dropPrefixes)
            return mapOf(
                "ok" to true,
                "dryRun" to true,
                "outputPath" to output.absolutePath,
                "filteredAbis" to filteredAbis,
                "filteredEntries" to count,
                "savedBytes" to bytes,
                "sign" to sign,
                "signedPath" to signedOutput.absolutePath,
            )
        }

        val result = ApkStructuralOps.repack(source = source, output = output, dropPrefixes = dropPrefixes)
        val base = mapOf(
            "ok" to true,
            "outputPath" to output.absolutePath,
            "filteredAbis" to filteredAbis,
            "filteredEntries" to result.dropped.size,
            "savedBytes" to result.droppedBytes,
        )
        if (!sign) return base

        // M1: 链式内置签名
        signedOutput.delete()
        val signed = SolabApkBuildTool.apkSign(
            context,
            JSONObject()
                .put("inputApk", output.absolutePath)
                .put("outputApk", signedOutput.absolutePath),
        )
        if (signed.optBoolean("ok")) {
            return base + mapOf(
                "signed" to true,
                "signedPath" to signedOutput.absolutePath,
            )
        }
        val errObj = signed.optJSONObject("error")
        return mapOf(
            "ok" to false,
            "error" to (errObj?.optString("code") ?: "apk_sign_failed"),
            "message" to (errObj?.optString("message") ?: signed.optString("message", "签名失败")),
            "intermediatePath" to output.absolutePath,
        )
    }

    /** B1/B2/B3/B4 + B5：按明确方法名修改 DEX，NOP 广告库加载；原包不覆盖，产出未签名中间包。 */
    private fun patchDexMethods(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        val outputDir = outputDirArg(call)
        fun methodTargets(key: String): Set<String> =
            (arg(call, key) as? List<*>)
                ?.map { it.toString().trim().lowercase(Locale.ROOT) }
                ?.map(ApkDexPatcher::normalizeMethodTarget)
                ?.filter { it.isNotEmpty() }
                ?.toSet() ?: emptySet()
        val voidMethods = methodTargets("voidMethods")
        // B3：会员/VIP 状态方法强制返回 true（仅处理返回 boolean/int 的方法）
        val trueMethods = methodTargets("trueMethods")
        val falseMethods = methodTargets("falseMethods")
        // B5：SDK 包名 → so 加载关键词（NOP 目标）
        val sdkPackages = (arg(call, "sdkPackages") as? List<*>)
            ?.map { it.toString().trim().lowercase(Locale.ROOT) }
            ?.filter { it.isNotEmpty() }
            ?.toSet() ?: emptySet()
        val libKeywords = if (sdkPackages.isNotEmpty()) {
            ApkDexPatcher.buildSdkLibKeywords(sdkPackages)
        } else {
            emptySet()
        }
        // 检测规避：VPN/模拟器检测方法强制 false（方法名 contains 关键词）
        // 关键词 = 内置集合 ∪ 用户自定义（规则库 detection_* 类别）。
        val userRules = loadRules()
        val removeVpnDetection = arg(call, "removeVpnDetection") as? Boolean ?: false
        val removeEmulatorDetection = arg(call, "removeEmulatorDetection") as? Boolean ?: false
        val vpnKeywords = if (removeVpnDetection) {
            (ApkDexPatcher.VPN_DETECT_KEYWORDS + userRules.detectionVpn).toSet()
        } else {
            emptySet()
        }
        val emulatorKeywords = if (removeEmulatorDetection) {
            (ApkDexPatcher.EMULATOR_DETECT_KEYWORDS + userRules.detectionEmulator).toSet()
        } else {
            emptySet()
        }
        // Root/反调试检测规避（关键词 contains，强制 false）
        val removeRootDetection = arg(call, "removeRootDetection") as? Boolean ?: false
        val removeDebugDetection = arg(call, "removeDebugDetection") as? Boolean ?: false
        val rootKeywords = if (removeRootDetection) {
            (ApkDexPatcher.ROOT_DETECT_KEYWORDS + userRules.detectionRoot).toSet()
        } else {
            emptySet()
        }
        val debugKeywords = if (removeDebugDetection) {
            (ApkDexPatcher.DEBUG_DETECT_KEYWORDS + userRules.detectionDebug).toSet()
        } else {
            emptySet()
        }
        // 截屏/录屏检测规避（关键词 contains + 证据双条件，强制 false）
        val removeScreenCaptureDetection = arg(call, "removeScreenCaptureDetection") as? Boolean ?: false
        val screenCaptureKeywords = if (removeScreenCaptureDetection) {
            ApkDexPatcher.SCREEN_CAPTURE_DETECT_KEYWORDS.toSet()
        } else {
            emptySet()
        }
        // FLAG_SECURE 剥离：清除流入 Window.setFlags/addFlags 常量中的该位，
        // 恢复允许截屏/录屏；同常量其他 flag 位保留
        val removeFlagSecure = arg(call, "removeFlagSecure") as? Boolean ?: false
        // 时间劫持：到期/剩余时间方法（long 返回）强制远期 0xffffff
        val timeMethods = methodTargets("timeMethods")
        // REQ-06：对象返回方法存根返回 null（"nullMethods"）
        val nullMethods = methodTargets("nullMethods")
        // 方法级定位（缺陷 1/2）：按全限定标识定位任意方法。
        // 接受 Lpkg/Class;->name 或 pkg.Class.methodName；归一化为 lpkg/class;->name。
        val classMethods = (arg(call, "classMethods") as? List<*>)
            ?.mapNotNull { normalizeClassMethod(it.toString()) }
            ?.filter { it.isNotEmpty() }
            ?.toSet() ?: emptySet()
        // 开屏广告倒计时缩短：splash 类中 ≥1000ms 的延迟常量置 0
        val shortenSplashCountdown = arg(call, "shortenSplashCountdown") as? Boolean ?: false
        // 签名兼容：默认普通注入；普通模式实际失败后才允许升级为原包模式。
        val signatureBypass = arg(call, "signatureBypass") as? Boolean ?: true
        // DEF-03（2026-09-19 全量复测）：省略 mode 时描述承诺「跟随工作台设置」，
        // 而工作台的值可能是 off/skip（未开启去签）——旧实现把它原样送进
        // normalizeMode，抛 IllegalStateException（出口只剩 structural_failed）。
        // 这里统一归一：空/off/skip/none/disabled → 默认 normal；其余非法值给
        // 结构化 invalid_args（带允许值），不再外泄异常。
        val rawSignatureMode = (arg(call, "signatureBypassMode") as? String)
            ?.trim().orEmpty()
        val normalizedSignatureMode = when (rawSignatureMode.lowercase()) {
            "", "off", "skip", "none", "disabled", "auto" ->
                ApkSignatureBypassInjector.MODE_NORMAL
            else -> rawSignatureMode
        }
        if (normalizedSignatureMode !in setOf(
                ApkSignatureBypassInjector.MODE_NORMAL,
                ApkSignatureBypassInjector.MODE_ORIGINAL_APK,
                ApkSignatureBypassInjector.MODE_DPATCH,
            )
        ) {
            throw StructuralError(
                "invalid_args",
                "signatureBypassMode=\"$rawSignatureMode\" 非法：允许 normal / original_apk / dpatch" +
                    "（留空则按工作台设置，工作台未开启时按 normal 处理）",
            )
        }
        val signatureBypassMode = normalizedSignatureMode
        val originalApk = (arg(call, "originalApkPath") as? String)
            ?.takeIf { it.isNotBlank() }
            ?.let(::File)
        // 体积优化（借鉴 2.9）：写回时全量剥离 debug info（行号/局部变量表），
        // 减小 DEX 体积 5%~15%；仅对本次修改写回的 DEX 生效
        val stripDebugInfo = arg(call, "stripDebugInfo") as? Boolean ?: false
        val dryRun = arg(call, "dryRun") as? Boolean ?: false
        if (voidMethods.isEmpty() && trueMethods.isEmpty() && falseMethods.isEmpty() &&
            libKeywords.isEmpty() && vpnKeywords.isEmpty() && emulatorKeywords.isEmpty() &&
            rootKeywords.isEmpty() && debugKeywords.isEmpty() && screenCaptureKeywords.isEmpty() &&
            !removeFlagSecure && timeMethods.isEmpty() &&
            nullMethods.isEmpty() && classMethods.isEmpty() && !shortenSplashCountdown &&
            !signatureBypass && !stripDebugInfo
        ) {
            throw StructuralError(
                "invalid_args",
                "至少提供一个 voidMethods、trueMethods、falseMethods、sdkPackages、检测移除开关、" +
                    "removeFlagSecure、timeMethods、nullMethods、classMethods、shortenSplashCountdown、" +
                    "stripDebugInfo 或 signatureBypass 规则",
            )
        }
        // T3 护栏：≤2 字符的短方法名存在爆炸风险（混淆短名 c/d/b 会命中数百个无关类），
        // 拒绝并强制走 classMethods 类限定定位。带 -> 的完整 qualifiedId 是已验证
        // 标识（混淆包短名是常态），不受此限（2026-09-14 缺陷汇报 C1）。
        val shortNameTargets = (voidMethods + trueMethods + falseMethods)
            .filter { it.length <= 2 && !it.contains("->") }
        if (shortNameTargets.isNotEmpty()) {
            throw StructuralError(
                "name_too_short",
                "短方法名（≤2 字符）存在大规模误伤风险：${shortNameTargets.joinToString("、")}。" +
                    "请先用 dex_search → class_outline/dex_xref → smali_read 获取并验证真实 qualifiedId（Lpkg/Class;->name），" +
                    "再走 classMethods 类限定匹配（完整 qualifiedId 不受短名护栏限制）。",
            )
        }
        if (dryRun) {
            val signaturePreview = if (signatureBypass) {
                val directory = Files.createTempDirectory("apk_signature_preview_").toFile()
                try {
                    prepareSignatureBypass(
                        source,
                        signatureBypassMode,
                        originalApk,
                        directory,
                    ).toMap()
                } finally {
                    directory.deleteRecursively()
                }
            } else {
                null
            }
            // 一次遍历收集全部预览命中（避免 6 次独立解压全量 dex 的开销）。
            val preview = scanPatchCandidates(
                source = source,
                voidMethods = voidMethods,
                trueMethods = trueMethods,
                falseMethods = falseMethods,
                libKeywords = libKeywords,
                vpnKeywords = vpnKeywords,
                emulatorKeywords = emulatorKeywords,
                rootKeywords = rootKeywords,
                debugKeywords = debugKeywords,
                screenCaptureKeywords = screenCaptureKeywords,
                removeFlagSecure = removeFlagSecure,
                timeMethods = timeMethods,
                nullMethods = nullMethods,
                shortenSplashCountdown = shortenSplashCountdown,
            )
            // classMethods 逐条解析：真实方法定义 resolved / 未找到 unresolved
            val classResolved = resolveClassMethods(source, classMethods)
            // B1：0 命中必须可推理——给结构化计数与原因码，
            // 杜绝「resolved 失败 / 类不存在 / 方法不存在」不可区分。
            val resolvedCount = classResolved.count { it["resolved"] == true }
            val unresolvedCount = classResolved.size - resolvedCount
            val matchedCount = preview.voidMethods.size + preview.matchedMethods.size +
                preview.falseMethods.size + preview.literalLoadLibrary.size +
                preview.vpnDetection.size + preview.emulatorDetection.size +
                preview.rootDetection.size + preview.debugDetection.size +
                preview.screenCaptureDetection.size + preview.flagSecureTargets.size +
                preview.timeMethods.size + preview.nullMethods.size +
                preview.splashCountdownTargets.size
            val anyHit = matchedCount > 0 ||
                classResolved.any { it["resolved"] == true } || signaturePreview != null
            // 覆盖全部规则输入：此前只数 void/true/false/classMethods，于是
            // 只传 timeMethods/nullMethods/sdkPackages/检测开关的 0 命中调用
            // 既没有 noHitReason 也没有 warning——正是「0 命中不可推理」。
            val rulesProvided = voidMethods.isNotEmpty() || trueMethods.isNotEmpty() ||
                falseMethods.isNotEmpty() || classMethods.isNotEmpty() ||
                timeMethods.isNotEmpty() || nullMethods.isNotEmpty() ||
                sdkPackages.isNotEmpty() ||
                removeVpnDetection || removeEmulatorDetection ||
                removeRootDetection || removeDebugDetection ||
                removeScreenCaptureDetection || removeFlagSecure ||
                shortenSplashCountdown
            // 缺陷 3：0 命中不再静默——给出结构化 warning 并强制走定位流程
            val warning = if (!anyHit && rulesProvided) {
                mapOf(
                    "type" to "no_method_hits",
                    "suggestion" to "字符串/规则命中不等于真实方法定义。请先按 dex_search → class_outline/dex_xref → smali_read 获取真实 qualifiedId，再用全限定标识（Lpkg/Class;->name）重试",
                )
            } else {
                null
            }
            val noHitReason = if (!anyHit && rulesProvided) {
                when {
                    classMethods.isNotEmpty() && resolvedCount == 0 -> "class_not_found"
                    else -> "method_not_found"
                }
            } else {
                null
            }
            // T3 护栏：classMethods 裸输入（无 ->）命中类数过多 → 泛化警告，
            // 防止 contains 匹配误伤大量无关类。
            val resolvedClasses = classResolved
                .filter { it["resolved"] == true }
                .map { it["className"].toString() }
                .toSet()
            val genericWarning = if (resolvedClasses.size > 20) {
                mapOf(
                    "type" to "name_too_generic",
                    "matchedClasses" to resolvedClasses.size,
                    "suggestion" to "裸输入命中 ${resolvedClasses.size} 个类（>20），contains 匹配过于泛化。请改用完整 qualifiedId（Lpkg/Class;->name）精确限定目标类，再走 classMethods。",
                )
            } else {
                null
            }
            return buildMap<String, Any> {
                put("ok", true)
                put("dryRun", true)
                put("voidMethodRules", voidMethods.size)
                put("trueMethodRules", trueMethods.size)
                put("falseMethodRules", falseMethods.size)
                put("libKeywordRules", libKeywords.size)
                put("voidMethods", preview.voidMethods)
                put("literalLoadLibrary", preview.literalLoadLibrary)
                put("nullMethodRules", nullMethods.size)
                put("matchedMethods", preview.matchedMethods)
                put("falseMethods", preview.falseMethods)
                put("vpnDetection", preview.vpnDetection)
                put("emulatorDetection", preview.emulatorDetection)
                put("rootDetection", preview.rootDetection)
                put("debugDetection", preview.debugDetection)
                put("screenCaptureDetection", preview.screenCaptureDetection)
                put("flagSecureTargets", preview.flagSecureTargets)
                put("timeMethods", preview.timeMethods)
                put("nullMethods", preview.nullMethods)
                if (shortenSplashCountdown) {
                    // F-42（2026-10-04）：splash 命中清单现在有真明细——与 apply
                    // 侧**同一检测源**（ApkDexPatcher.previewSplashCountdownTargets
                    // 复用 shortenSplashCountdownImpl 的只读判定），清单即应用对象。
                    put("splashCountdownTargets", preview.splashCountdownTargets)
                    // v12 复测：空数组的含义要写明——「本包 0 命中」不等于
                    // 「工具不支持列目标」；命中时这里逐条列出。
                    if (preview.splashCountdownTargets.isEmpty()) {
                        put(
                            "splashCountdownTargetsNote",
                            "本包 0 命中：按倒计时特征未匹配到 splash 方法（不是工具不支持列目标）。" +
                                "命中时本字段逐条列出将被修改的方法（与应用同源，列出即会被改）。",
                        )
                    }
                }
                put("classMethods", classResolved)
                put("matchedCount", matchedCount)
                put("resolvedClassMethodCount", resolvedCount)
                put("unresolvedClassMethodCount", unresolvedCount)
                if (unresolvedCount > 0) {
                    put(
                        "unresolvedTargets",
                        classResolved.filter { it["resolved"] != true }
                            .map { it["raw"] ?: it["target"] ?: it.toString() },
                    )
                }
                if (noHitReason != null) put("noHitReason", noHitReason)
                if (signaturePreview != null) put("signatureBypass", signaturePreview)
                // F-42（2026-10-04）：dryRun 的命中清单只是**候选**——按名批量
                // 匹配不等于真实方法定义，动手前逐条取证（这是产品纪律）。
                put(
                    "candidatesAreNotEvidence",
                    "本清单是按名/子串匹配的候选，不是补丁目标：先逐条核验（qualifiedId/返回类型/所在类），" +
                        "再用 classMethods 或 locator 精确指定后 confirmed 应用。splash 清单例外：它与应用同源，列出即会被改。",
                )
                if (warning != null) put("warning", warning)
                if (genericWarning != null) put("warning", genericWarning)
                put("message", "预览校验规则并统计命中。loadLibrary 只会修改能静态追踪到广告库字符串的调用；运行时参数调用不会修改，应改用已分析到的上游初始化方法。classMethods 中 resolved=false 的条目表示 DEX 中不存在该标识。")
            }
        }

        val temporaryDirectory = Files.createTempDirectory("solab_apk_dex_").toFile()
        try {
            // 内存优化：patched dex 留在临时目录，只记录文件映射——重打包时流式
            // 读取，多 dex 大包内存峰值从「所有修改 dex 字节总和」降为「单 dex」。
            val overrides = linkedMapOf<String, File>()
            val byteOverrides = linkedMapOf<String, ByteArray>()
            val additions = linkedMapOf<String, ByteArray>()
            val additionFiles = linkedMapOf<String, File>()
            val signaturePlan = if (signatureBypass) {
                prepareSignatureBypass(
                    source,
                    signatureBypassMode,
                    originalApk,
                    temporaryDirectory,
                ).also { plan ->
                    byteOverrides.putAll(plan.byteOverrides)
                    overrides.putAll(plan.overrides)
                    additions.putAll(plan.additions)
                    additionFiles.putAll(plan.additionFiles)
                }
            } else {
                null
            }
            var voidCount = 0
            var trueCount = 0
            var falseCount = 0
            var nopCount = 0
            var vpnCount = 0
            var emulatorCount = 0
            var rootCount = 0
            var debugCount = 0
            var screenCaptureCount = 0
            var flagSecureCount = 0
            var timeCount = 0
            var nullCount = 0
            var classHandled = 0
            var classSkipped = 0
            var splashCountdown = 0
            // AC 预检模式与自动机构建一次即够：原写在 per-dex 循环内，
            // 多 dex 大包每个 dex 重建数百模式的自动机纯属浪费。
            val precheckPatterns = (
                voidMethods + trueMethods + falseMethods +
                    libKeywords + vpnKeywords + emulatorKeywords +
                    rootKeywords + debugKeywords + screenCaptureKeywords + timeMethods +
                    nullMethods + classMethods +
                    (if (shortenSplashCountdown) setOf("splash") else emptySet()) +
                    (if (removeFlagSecure) setOf("setFlags", "addFlags") else emptySet())
                ).map { it.substringAfter("->", it) }.toSet()
            val precheckAutomaton =
                if (precheckPatterns.isEmpty()) null
                else ApkAhoCorasick(precheckPatterns.toList())
            withApkZip(source) { zip ->
                zip.entries().asSequence()
                    .filterNot { it.isDirectory }
                    .filter { it.name.matches(DexIo.classesDexRegex) }
                    .forEach { entry ->
                        // 性能优化：无广告 DEX 自动跳过。
                        // 先在 zip 流上做 AC 预检，未命中任何模式的 dex 直接跳过，
                        // 不落盘、不加载 dexlib2——多 dex 大包省下绝大部分 IO。
                        if (precheckAutomaton != null) {
                            val preHit = zip.getInputStream(entry).use { input ->
                                precheckAutomaton.scanStream(input)
                            }
                            if (preHit.isEmpty()) return@forEach
                        }
                        val dex = overrides[entry.name] ?: File(temporaryDirectory, File(entry.name).name).also { file ->
                            zip.getInputStream(entry).use { input -> file.outputStream().use(input::copyTo) }
                        }
                        val patched = ApkDexPatcher.patch(
                            dexFile = dex,
                            voidMethodNames = voidMethods,
                            trueMethodNames = trueMethods,
                            falseMethodNames = falseMethods,
                            libKeywords = libKeywords,
                            vpnDetectKeywords = vpnKeywords,
                            emulatorDetectKeywords = emulatorKeywords,
                            timeMethodNames = timeMethods,
                            rootDetectKeywords = rootKeywords,
                            debugDetectKeywords = debugKeywords,
                            screenCaptureDetectKeywords = screenCaptureKeywords,
                            removeFlagSecure = removeFlagSecure,
                            nullMethodNames = nullMethods,
                            exactClassMethods = classMethods,
                            shortenSplashCountdown = shortenSplashCountdown,
                            stripDebugInfo = stripDebugInfo,
                        )
                        if (patched.changed > 0) {
                            overrides[entry.name] = dex
                            voidCount += patched.voidMethods
                            trueCount += patched.forcedTrue
                            falseCount += patched.forcedFalse
                            nopCount += patched.nopLoadLibrary
                            vpnCount += patched.vpnNeutralized
                            emulatorCount += patched.emulatorNeutralized
                            rootCount += patched.rootNeutralized
                            debugCount += patched.debugNeutralized
                            screenCaptureCount += patched.screenCaptureNeutralized
                            flagSecureCount += patched.flagSecureCleared
                            timeCount += patched.forcedTime
                            nullCount += patched.nullStubbed
                            classHandled += patched.classMethodsHandled
                            classSkipped += patched.classMethodsSkipped
                            splashCountdown += patched.splashCountdownShortened
                        }
                        // 每个 DEX 处理后无条件 GC：下一个 DEX 的加载
                        // 与写回在干净的堆上进行，防多 dex 大包内存累积。
                        System.gc()
                    }
            }
            if (overrides.isEmpty() && byteOverrides.isEmpty() &&
                additions.isEmpty() && additionFiles.isEmpty()
            ) {
                val signatureVerification = signaturePlan?.let {
                    ApkSignatureBypassInjector.verifyPrepared(source, it)
                }
                return mapOf(
                    "ok" to true,
                    "dryRun" to false,
                    "changed" to false,
                    "voidMethods" to 0,
                    "trueMethods" to 0,
                    "falseMethods" to 0,
                    "nopLoadLibrary" to 0,
                    "vpnDetection" to 0,
                    "emulatorDetection" to 0,
                    "rootDetection" to 0,
                    "debugDetection" to 0,
                    "screenCaptureDetection" to 0,
                    "flagSecure" to 0,
                    "timeMethods" to 0,
                    "nullMethods" to 0,
                    "classMethods" to 0,
                    "classMethodsSkipped" to 0,
                    "splashCountdown" to 0,
                    "signatureBypass" to (signaturePlan?.toMap() ?: emptyMap<String, Any>()),
                    "signatureBypassVerification" to (signatureVerification ?: emptyMap<String, Any>()),
                    "message" to if (signaturePlan?.alreadyInjected == true) {
                        "签名兼容已处理，后续补丁直接复用，未重复生成 APK"
                    } else {
                        "未找到可安全修改的方法，未生成新 APK"
                    },
                )
            }
            // D8：去签产物按 mode 独立命名空间（`<stem>_bypass_<mode>_vN.apk`），
            // 不再与 dexpatch/structural 等中间包共用一个版本序列——共用会让
            // 去签复用上一轮已被清理的 `_v1.apk` 路径名（同名字不同内容）。
            val output = structuralOutput(
                source,
                outputDir = outputDir,
                nameTag = if (signatureBypass) "bypass_$signatureBypassMode" else null,
            )
            ApkStructuralOps.repack(
                source = source,
                output = output,
                overrides = byteOverrides,
                overrideFiles = overrides,
                additions = additions,
                additionFiles = additionFiles,
            )
            if (signaturePlan?.mode == ApkSignatureBypassInjector.MODE_ORIGINAL_APK) {
                ApkSignatureBypassInjector.optimizeEmbeddedOriginalApk(output)
            }
            val signatureVerification = signaturePlan?.let {
                ApkSignatureBypassInjector.verifyPrepared(output, it)
            }
            return mapOf(
                "ok" to true,
                "dryRun" to false,
                "changed" to true,
                "outputPath" to output.absolutePath,
                "voidMethods" to voidCount,
                "trueMethods" to trueCount,
                "falseMethods" to falseCount,
                "nopLoadLibrary" to nopCount,
                "vpnDetection" to vpnCount,
                "emulatorDetection" to emulatorCount,
                "rootDetection" to rootCount,
                "debugDetection" to debugCount,
                "screenCaptureDetection" to screenCaptureCount,
                "flagSecure" to flagSecureCount,
                "timeMethods" to timeCount,
                "nullMethods" to nullCount,
                "classMethods" to classHandled,
                "classMethodsSkipped" to classSkipped,
                "splashCountdown" to splashCountdown,
                "signatureBypass" to (signaturePlan?.toMap() ?: emptyMap<String, Any>()),
                "signatureBypassVerification" to (signatureVerification ?: emptyMap<String, Any>()),
                "modifiedDexFiles" to overrides.keys.sorted(),
            )
        } finally {
            temporaryDirectory.deleteRecursively()
        }
    }

    /**
     * C6：dex 字符串池补丁。把 dex 中 const-string 引用的字符串精确替换为
     * 新字符串（URL/文案/水印等），秒级完成，无需 decode→smali→build 全量
     * 重建。dryRun=true 只扫命中不写盘；apply 走 备份→tmp→rename 原子替换，
     * 原包不覆盖，产出未签名中间包。
     */
    private fun patchDexStrings(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        val outputDir = outputDirArg(call)
        val dryRun = arg(call, "dryRun") as? Boolean ?: false
        val replacements = (arg(call, "replacements") as? List<*>)
            ?.mapNotNull { item ->
                when (item) {
                    is Map<*, *> -> {
                        val from = item["from"]?.toString()
                        val to = item["to"]?.toString()
                        if (from.isNullOrEmpty() || to == null) null
                        else from to to
                    }
                    is List<*> -> {
                        if (item.size >= 2 && item[0] != null && item[1] != null) {
                            item[0].toString() to item[1].toString()
                        } else null
                    }
                    else -> null
                }
            }
            ?.filter { it.first != it.second }
            ?.distinctBy { it.first }
            ?: emptyList()
        if (replacements.isEmpty()) {
            throw StructuralError(
                "invalid_args",
                "replacements 必填：非空 {from,to} 列表（from != to）。",
            )
        }

        val temporaryDirectory = Files.createTempDirectory("solab_apk_dexstr_").toFile()
        try {
            val overrides = LinkedHashMap<String, File>()
            val matchedByString = LinkedHashMap<String, Int>()
            var totalMatched = 0
            val fromSet = replacements.map { it.first }.toSet()
            val precheckAutomaton = ApkAhoCorasick(fromSet.toList())
            // B1 三态诊断：记录每个目标串在哪些 dex 字节级出现（串池/子串/死数据
            // 都算），用于失配时区分"串不存在"与"存在但无 const-string 引用"
            val bytePresence = LinkedHashMap<String, MutableSet<String>>()

            withApkZip(source) { zip ->
                zip.entries().asSequence()
                    .filterNot { it.isDirectory }
                    .filter { it.name.matches(DexIo.classesDexRegex) }
                    .forEach { entry ->
                        // 流式预检：原串未命中的 dex 直接跳过（不落盘不加载）。
                        val preHit = zip.getInputStream(entry).use { input ->
                            precheckAutomaton.scanStream(input)
                        }
                        if (preHit.isEmpty()) return@forEach
                        for (key in preHit) {
                            bytePresence.getOrPut(key) { LinkedHashSet() }.add(entry.name)
                        }
                        val dex = File(temporaryDirectory, File(entry.name).name).also { file ->
                            zip.getInputStream(entry).use { input ->
                                file.outputStream().use(input::copyTo)
                            }
                        }
                        // B1 口径统一：预览与写入都用 dexlib2 const-string 精确
                        // 匹配计数（此前预览用字节级 AC 预检，会把"池内存在但无
                        // const-string 引用/仅子串命中"虚报为可改，apply 却
                        // 0 命中 → changed:false）。dryRun 下临时 dex 被覆盖写
                        // 无副作用（finally 统一清理临时目录）。
                        val result = ApkDexPatcher.patchStrings(dex, replacements)
                        if (result != null) {
                            if (!dryRun) overrides[entry.name] = dex
                            val byString = result["byString"] as? Map<*, *>
                            if (byString != null) {
                                for ((k, v) in byString) {
                                    val key = k.toString()
                                    val count = (v as? Number)?.toInt() ?: 0
                                    matchedByString[key] = (matchedByString[key] ?: 0) + count
                                    totalMatched += count
                                }
                            }
                        }
                        System.gc()
                    }
            }

            // 子串 miss 的完整字面量候选：对字节级命中但 const-string 0 引用的
            // key，扫 APK 内 dex 串池找"包含它"的完整串（调用方直接拿真实完整
            // 字面量重试，省一轮手工找 haystack）。预览路径没有临时 dex 落盘，
            // 必须从 APK zip 条目流式读 dex 字节扫描（上一版扫 temporaryDirectory
            // 在 dryRun 时扑空，实测 literalCandidates 不出现）。
            val literalCandidates = run {
                val missKeys = fromSet.filter {
                    (matchedByString[it] ?: 0) == 0 && bytePresence[it].orEmpty().isNotEmpty()
                }.toSet()
                if (missKeys.isEmpty()) emptyMap()
                else {
                    val acc = LinkedHashMap<String, MutableSet<String>>()
                    ApkZipCache.shared.withZip(source) { zip ->
                        zip.entries().asSequence()
                            .filter { !it.isDirectory && it.name.matches(DexIo.classesDexRegex) }
                            .sortedBy { it.name }
                            .forEach { entry ->
                                val dexBytes = zip.getInputStream(entry).use { s -> s.readBytes() }
                                val found = ApkDexPatcher.findStringsContaining(dexBytes, missKeys)
                                for ((k, v) in found) acc.getOrPut(k) { LinkedHashSet() }.addAll(v)
                            }
                    }
                    acc.mapValues { it.value.toList().take(5) }
                }
            }

            if (totalMatched == 0 || (!dryRun && overrides.isEmpty())) {
                // B1 诊断补全：失配也要回 totalMatched=0 与逐 key 计数（未命中补 0），
                // 让调用方能区分"串不存在"和"哪些 key 零命中"，而不是拿到
                // matchedStrings:{} + totalMatched 缺失的哑响应。
                val perKey = LinkedHashMap<String, Int>()
                val diagnostics =
                    dexStringMissDiagnostics(fromSet, matchedByString, bytePresence, perKey, literalCandidates)
                val response = LinkedHashMap<String, Any>()
                response["ok"] = true
                response["dryRun"] = dryRun
                response["changed"] = false
                response["matchedStrings"] = perKey
                response["totalMatched"] = 0
                if (diagnostics.isNotEmpty()) response["diagnostics"] = diagnostics
                response["message"] = if (dryRun)
                    "预览：没有任何 const-string 指令精确引用目标字符串（预览与写入同口径，逐 key 计数见 matchedStrings，三态归因见 diagnostics）。" +
                        "可先用 apk_archive(action=strings) 交叉确认。"
                else "未命中任何目标字符串，未生成新 APK"
                return response
            }
            if (dryRun) {
                // 部分命中同样要给未命中 key 补 0 + 归因——只回命中项会让
                // 调用方无法区分"零命中项"与"参数没传对"（实测复现过的反馈缺口）。
                val perKey = LinkedHashMap<String, Int>()
                val diagnostics =
                    dexStringMissDiagnostics(fromSet, matchedByString, bytePresence, perKey, literalCandidates)
                val response = LinkedHashMap<String, Any>(
                    mapOf(
                        "ok" to true,
                        "dryRun" to true,
                        "changed" to false,
                        "matchedStrings" to perKey,
                        "totalMatched" to totalMatched,
                        "message" to "预览：命中 ${matchedByString.size}/${fromSet.size} 个目标字符串（共 $totalMatched 处引用）。确认后以相同参数 + applyAfterPreview=true 执行。",
                    ),
                )
                if (diagnostics.isNotEmpty()) response["diagnostics"] = diagnostics
                return response
            }

            val output = structuralOutput(source, outputDir = outputDir)
            ApkStructuralOps.repack(
                source = source,
                output = output,
                overrideFiles = overrides,
            )
            val perKey = LinkedHashMap<String, Int>()
            val diagnostics =
                dexStringMissDiagnostics(fromSet, matchedByString, bytePresence, perKey, literalCandidates)
            val response = LinkedHashMap<String, Any>(
                mapOf(
                    "ok" to true,
                    "dryRun" to false,
                    "changed" to true,
                    "outputPath" to output.absolutePath,
                    "matchedStrings" to perKey,
                    "totalMatched" to totalMatched,
                    "modifiedDexFiles" to overrides.keys.sorted(),
                    "message" to "dex 字符串已替换（$totalMatched 处），产出未签名中间包；请先签名再安装。",
                ),
            )
            if (diagnostics.isNotEmpty()) response["diagnostics"] = diagnostics
            return response
        } finally {
            temporaryDirectory.deleteRecursively()
        }
    }

    /**
     * 逐 key 计数（未命中补 0）与未命中项三态诊断。
     * ABSENT = 所有 dex 字节级均无此串；PRESENT_NO_CONST_REF = 字节级存在
     * （串池/死数据/子串）但无 const-string 指令精确引用。
     * 三个响应分支（全 0 / 部分命中 dryRun / 写入成功）共用，保证未命中 key
     * 在任何情况下都有归因。
     */
    private fun dexStringMissDiagnostics(
        fromSet: Set<String>,
        matchedByString: Map<String, Int>,
        bytePresence: Map<String, Set<String>>,
        perKeyOut: LinkedHashMap<String, Int>,
        literalCandidates: Map<String, List<String>> = emptyMap(),
    ): LinkedHashMap<String, Map<String, Any>> {
        for (from in fromSet) perKeyOut[from] = matchedByString[from] ?: 0
        val diagnostics = LinkedHashMap<String, Map<String, Any>>()
        for (from in fromSet) {
            if ((matchedByString[from] ?: 0) > 0) continue
            val dexes = bytePresence[from].orEmpty().sorted()
            diagnostics[from] = if (dexes.isEmpty()) {
                mapOf(
                    "status" to "ABSENT",
                    "hint" to "未在任何 classes*.dex 字节级命中：该串不在 DEX 内（查 resources.arsc/assets/so 层）",
                )
            } else {
                val candidates = literalCandidates[from].orEmpty()
                mapOf(
                    "status" to "PRESENT_NO_CONST_REF",
                    "bytePresentInDex" to dexes,
                    if (candidates.isEmpty())
                        "hint" to "字符串在 DEX 字节中存在，但没有任何 const-string 指令精确引用它（死条目/其他字符串的子串/非代码引用）；字符串替换触不到它"
                    else
                        "literalCandidates" to candidates,
                )
            }
        }
        return diagnostics
    }

    private fun prepareSignatureBypass(
        source: File,
        mode: String,
        originalApk: File?,
        temporaryDirectory: File,
    ): ApkSignatureBypassInjector.Plan = try {
        ApkSignatureBypassInjector.prepare(
            context = context,
            source = source,
            requestedMode = mode,
            originalApk = originalApk,
            temporaryDirectory = temporaryDirectory,
        )
    } catch (error: IllegalArgumentException) {
        throw StructuralError("signature_bypass_failed", error.message ?: "签名兼容处理失败")
    }

    /** 预览结果：各修改类型命中的方法清单（按 dex 分组）。 */
    private data class PatchPreview(
        val voidMethods: List<Map<String, Any>>,
        val matchedMethods: List<Map<String, Any>>,
        val falseMethods: List<Map<String, Any>>,
        val literalLoadLibrary: List<Map<String, Any>>,
        val vpnDetection: List<Map<String, Any>>,
        val emulatorDetection: List<Map<String, Any>>,
        val rootDetection: List<Map<String, Any>>,
        val debugDetection: List<Map<String, Any>>,
        val screenCaptureDetection: List<Map<String, Any>>,
        val flagSecureTargets: List<Map<String, Any>>,
        val timeMethods: List<Map<String, Any>>,
        val nullMethods: List<Map<String, Any>>,
        // F-42（2026-10-04）：splash 倒计时命中清单（与 apply 同检测源）。
        val splashCountdownTargets: List<Map<String, Any>>,
    )

    /**
     * 一次遍历扫描全部预览命中（会员 true / VPN / 模拟器 / Root / 反调试 / 时间）。
     * 只解压一次 dex、加载一次 dexlib2，替代原先 6 个各自全量解压的扫描函数。
     * AC 字节预检用全部 pattern 并集粗筛，未命中直接跳过不加载 dexlib2。
     */
    private fun scanPatchCandidates(
        source: File,
        voidMethods: Set<String>,
        trueMethods: Set<String>,
        falseMethods: Set<String>,
        libKeywords: Set<String>,
        vpnKeywords: Set<String>,
        emulatorKeywords: Set<String>,
        rootKeywords: Set<String>,
        debugKeywords: Set<String>,
        screenCaptureKeywords: Set<String>,
        removeFlagSecure: Boolean,
        timeMethods: Set<String>,
        nullMethods: Set<String>,
        // F-42：splash 预览开关（与 apply 侧预检同口径：开启时把 "splash"
        // 加入 AC 预检模式，否则纯 splash 调用会被 allPatterns.isEmpty 早退）。
        shortenSplashCountdown: Boolean = false,
    ): PatchPreview {
        val allPatterns = (
            voidMethods + trueMethods + falseMethods + libKeywords + vpnKeywords + emulatorKeywords + rootKeywords +
                debugKeywords + screenCaptureKeywords + timeMethods + nullMethods +
                (if (removeFlagSecure) setOf("setFlags", "addFlags") else emptySet()) +
                (if (shortenSplashCountdown) setOf("splash") else emptySet())
            ).map { it.substringAfter("->", it) }.distinct()
        if (allPatterns.isEmpty()) {
            return PatchPreview(
                voidMethods = emptyList(),
                matchedMethods = emptyList(),
                falseMethods = emptyList(),
                literalLoadLibrary = emptyList(),
                vpnDetection = emptyList(),
                emulatorDetection = emptyList(),
                rootDetection = emptyList(),
                debugDetection = emptyList(),
                screenCaptureDetection = emptyList(),
                flagSecureTargets = emptyList(),
                timeMethods = emptyList(),
                nullMethods = emptyList(),
                splashCountdownTargets = emptyList(),
            )
        }
        val voidMatched = mutableListOf<Map<String, Any>>()
        val trueMatched = mutableListOf<Map<String, Any>>()
        val falseMatched = mutableListOf<Map<String, Any>>()
        val literalLoadLibrary = mutableListOf<Map<String, Any>>()
        val vpnMatched = mutableListOf<Map<String, Any>>()
        val emulatorMatched = mutableListOf<Map<String, Any>>()
        val rootMatched = mutableListOf<Map<String, Any>>()
        val debugMatched = mutableListOf<Map<String, Any>>()
        val screenCaptureMatched = mutableListOf<Map<String, Any>>()
        val flagSecureMatched = mutableListOf<Map<String, Any>>()
        val timeMatched = mutableListOf<Map<String, Any>>()
        val nullMatched = mutableListOf<Map<String, Any>>()
        val splashMatched = mutableListOf<Map<String, Any>>()

        val temporaryDirectory = Files.createTempDirectory("solab_apk_preview_").toFile()
        try {
            withApkZip(source) { zip ->
                zip.entries().asSequence()
                    .filterNot { it.isDirectory }
                    .filter { it.name.matches(DexIo.classesDexRegex) }
                    .forEach { entry ->
                        // 性能优化：zip 流上先 AC 预检，未命中不落盘不加载 dexlib2。
                        if (ApkAhoCorasick(allPatterns).scanStream(zip.getInputStream(entry)).isEmpty()) {
                            return@forEach
                        }
                        val dex = File(temporaryDirectory, File(entry.name).name)
                        zip.getInputStream(entry).use { input -> dex.outputStream().use(input::copyTo) }
                        val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
                        val libHit = ApkDexPatcher.literalLoadLibraryMatches(dexFile, libKeywords)
                        val flagSecureHit = if (removeFlagSecure) {
                            ApkDexPatcher.flagSecurePreviewTargets(dexFile)
                        } else {
                            emptySet()
                        }
                        // 匹配用小写，返回始终保留 DEX 原始方法标识，避免 getisvip
                        // 被误认为 APK 内确实存在的小写符号，也避免依赖猜测混淆类名。
                        val voidHit = linkedSetOf<String>()
                        val trueHit = linkedMapOf<String, String>()
                        val falseHit = linkedSetOf<String>()
                        val vpnHit = linkedMapOf<String, String>()
                        val emulatorHit = linkedMapOf<String, String>()
                        val rootHit = linkedMapOf<String, String>()
                        val debugHit = linkedMapOf<String, String>()
                        val screenCaptureHit = linkedMapOf<String, String>()
                        val timeHit = linkedMapOf<String, String>()
                        val nullHit = linkedMapOf<String, String>()
                        for (classDef in dexFile.classes) {
                            val classType = classDef.type.lowercase()
                            for (method in classDef.methods) {
                                val name = method.name.lowercase()
                                val target = "${classDef.type}->${method.name}"
                                val ret = method.returnType
                                val boolInt = ret == "Z" || ret == "I"
                                if (ret == "V" && ApkDexPatcher.matchesMethodTarget(name, classType, voidMethods)) {
                                    voidHit += target
                                }
                                if (boolInt && ApkDexPatcher.matchesMethodTarget(name, classType, trueMethods)) {
                                    trueHit[target.lowercase()] = target
                                }
                                if (boolInt && ApkDexPatcher.matchesMethodTarget(name, classType, falseMethods)) {
                                    falseHit += target
                                }
                                // B3 口径统一：与 apply 侧（ApkDexPatcher.patch）一致，
                                // 检测命中 = 名字匹配 + 方法体证据双条件，防止预览虚报
                                // "可改"（如 hasRootXML 名字命中但无检测证据）。
                                val impl = method.implementation
                                val hasEvidence = impl != null &&
                                    ApkDexPatcher.methodHasDetectionEvidence(impl)
                                if (boolInt && hasEvidence && vpnKeywords.any { name.contains(it) }) vpnHit[name] = method.name
                                if (boolInt && hasEvidence && emulatorKeywords.any { name.contains(it) }) emulatorHit[name] = method.name
                                if (boolInt && hasEvidence && rootKeywords.any { name.contains(it) }) rootHit[name] = method.name
                                if (boolInt && hasEvidence && debugKeywords.any { name.contains(it) }) debugHit[name] = method.name
                                if (boolInt && hasEvidence && screenCaptureKeywords.any { name.contains(it) }) screenCaptureHit[name] = method.name
                                if (ApkDexPatcher.matchesMethodTarget(name, classType, timeMethods) && ret == "J") timeHit[name] = method.name
                                if (ApkDexPatcher.matchesMethodTarget(name, classType, nullMethods) && ret.startsWith("L") && ret != "V") nullHit[name] = method.name
                            }
                        }
                        if (voidHit.isNotEmpty()) {
                            voidMatched += mapOf("dex" to entry.name, "methods" to voidHit.sorted())
                        }
                        if (trueHit.isNotEmpty()) {
                            trueMatched += mapOf("dex" to entry.name, "methods" to trueHit.values.sorted())
                        }
                        if (falseHit.isNotEmpty()) {
                            falseMatched += mapOf("dex" to entry.name, "methods" to falseHit.sorted())
                        }
                        if (libHit.isNotEmpty()) {
                            literalLoadLibrary += mapOf("dex" to entry.name, "methods" to libHit.sorted())
                        }
                        if (vpnHit.isNotEmpty()) {
                            vpnMatched += mapOf("dex" to entry.name, "methods" to vpnHit.values.sorted())
                        }
                        if (emulatorHit.isNotEmpty()) {
                            emulatorMatched += mapOf("dex" to entry.name, "methods" to emulatorHit.values.sorted())
                        }
                        if (rootHit.isNotEmpty()) {
                            rootMatched += mapOf("dex" to entry.name, "methods" to rootHit.values.sorted())
                        }
                        if (debugHit.isNotEmpty()) {
                            debugMatched += mapOf("dex" to entry.name, "methods" to debugHit.values.sorted())
                        }
                        if (screenCaptureHit.isNotEmpty()) {
                            screenCaptureMatched += mapOf("dex" to entry.name, "methods" to screenCaptureHit.values.sorted())
                        }
                        if (flagSecureHit.isNotEmpty()) {
                            flagSecureMatched += mapOf("dex" to entry.name, "methods" to flagSecureHit.sorted())
                        }
                        if (timeHit.isNotEmpty()) {
                            timeMatched += mapOf("dex" to entry.name, "methods" to timeHit.values.sorted())
                        }
                        if (nullHit.isNotEmpty()) {
                            nullMatched += mapOf("dex" to entry.name, "methods" to nullHit.values.sorted())
                        }
                        // F-42：splash 命中清单（与 apply 同检测源；只读预览）。
                        if (shortenSplashCountdown) {
                            val splashHits = linkedSetOf<String>()
                            for (classDef in dexFile.classes) {
                                splashHits += ApkDexPatcher.previewSplashCountdownTargets(classDef)
                            }
                            if (splashHits.isNotEmpty()) {
                                splashMatched += mapOf("dex" to entry.name, "methods" to splashHits.sorted())
                            }
                        }
                    }
            }
        } finally {
            temporaryDirectory.deleteRecursively()
        }
        return PatchPreview(
            voidMatched, trueMatched, falseMatched, literalLoadLibrary, vpnMatched, emulatorMatched,
            rootMatched, debugMatched, screenCaptureMatched, flagSecureMatched, timeMatched, nullMatched,
            splashMatched,
        )
    }

    /**
     * 方法定位标识归一化：接受 Lpkg/Class;->name、pkg.Class->name、pkg.Class.methodName，
     * 统一为小写 lpkg/class;->name（与 ApkDexPatcher 匹配语义一致）。
     */
    private fun normalizeClassMethod(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return ""
        val (classPart, methodPart) = if (trimmed.contains("->")) {
            trimmed.split("->", limit = 2).let { it[0] to it[1] }
        } else {
            val dot = trimmed.lastIndexOf('.')
            if (dot <= 0) return trimmed.lowercase(Locale.ROOT)
            trimmed.substring(0, dot) to trimmed.substring(dot + 1)
        }
        // 缺陷修复：描述符必须是大写 L 前缀 + 分号结尾（Lcom/x/Y;）。
        // 不能整体 lowercase，否则 L 变 l 生成非法描述符（lcom/x/y;），
        // 定位必然失败。这里先剥掉任意大小写的 L 前缀和 ; 后缀，
        // 再统一拼回大写 L + 小写类名 + ;。
        var cls = classPart.trim()
        if (cls.startsWith("l", ignoreCase = true)) cls = cls.substring(1)
        if (cls.endsWith(";")) cls = cls.dropLast(1)
        cls = cls.replace('.', '/').lowercase(Locale.ROOT)
        cls = "L$cls;"
        // A3：方法部分剥签名（A3 后 qualifiedId 为 ->name(params)ret；兼容
        // 旧的无签名传法——两者都归一为方法名，按名匹配）
        var name = methodPart.trim().lowercase(Locale.ROOT)
        val paren = name.indexOf('(')
        if (paren > 0) name = name.substring(0, paren)
        if (name.isEmpty()) return ""
        return "$cls->$name"
    }

    /** 解析 classMethods 每个标识在 DEX 中的真实定义（resolved/unresolved）。 */
    private fun resolveClassMethods(source: File, targets: Set<String>): List<Map<String, Any>> {
        if (targets.isEmpty()) return emptyList()
        val results = mutableListOf<Map<String, Any>>()
        val temporaryDirectory = Files.createTempDirectory("solab_apk_resolve_").toFile()
        try {
            withApkZip(source) { zip ->
                zip.entries().asSequence()
                    .filterNot { it.isDirectory }
                    .filter { it.name.matches(DexIo.classesDexRegex) }
                    .forEach { entry ->
                        // 性能优化：zip 流上先 AC 预检，未命中不落盘不加载 dexlib2。
                        val targetKeywords = targets.map { it.substringAfter("->", it) }
                        if (ApkAhoCorasick(targetKeywords).scanStream(zip.getInputStream(entry)).isEmpty()) {
                            return@forEach
                        }
                        val dex = File(temporaryDirectory, File(entry.name).name)
                        zip.getInputStream(entry).use { input -> dex.outputStream().use(input::copyTo) }
                        val dexFile = DexFileFactory.loadDexFile(dex, Opcodes.getDefault())
                        for (classDef in dexFile.classes) {
                            // 与 normalizeClassMethod 同规则归一化（大写 L + 小写类名 + ;）
                            val classType = ApkDexPatcher.classTypeForMatch(classDef.type)
                            for (method in classDef.methods) {
                                val name = method.name.lowercase()
                                // 精确匹配（全限定）或裸输入 contains 兜底（方法名或类名，
                                // 长度≥4）：ksadsdk/ttadsdk 类名片段也能命中
                                val matched = "$classType->$name" in targets ||
                                    (name.length >= 4 &&
                                        targets.any { !it.contains("->") && name.contains(it) }) ||
                                    (classType.length >= 6 &&
                                        targets.any { !it.contains("->") && classType.contains(it) })
                                if (matched) {
                                    results += mapOf(
                                        "target" to "${classDef.type}->${method.name}",
                                        "resolved" to true,
                                        "className" to classDef.type,
                                        "methodName" to method.name,
                                        "returnType" to method.returnType,
                                        "isVoid" to (method.returnType == "V"),
                                        "isCallback" to ApkDexPatcher.isCallbackOrListener(name),
                                        "dexFile" to entry.name,
                                    )
                                }
                            }
                        }
                    }
            }
        } finally {
            temporaryDirectory.deleteRecursively()
        }
        // 未解析的请求补全为 unresolved（保持与入参一一对应）
        val resolvedIds = results.map { it["target"].toString().lowercase(Locale.ROOT) }.toSet()
        for (target in targets) {
            val resolved = if (target.contains("->")) {
                target.lowercase(Locale.ROOT) in resolvedIds
            } else {
                // 裸输入：任一 resolved 结果的 methodName 或 className contains 即视为命中
                results.any {
                    it["methodName"].toString().lowercase(Locale.ROOT).contains(target) ||
                        it["className"].toString().lowercase(Locale.ROOT).contains(target)
                }
            }
            if (!resolved) {
                results += mapOf(
                    "target" to target,
                    "resolved" to false,
                    "className" to "",
                    "methodName" to "",
                    "returnType" to "",
                    "isVoid" to false,
                    "isCallback" to false,
                    "dexFile" to "",
                )
            }
        }
        return results
    }

    /** 读取 APK 内第一个 AndroidManifest.xml 条目字节（不区分大小写）。 */
    private fun readManifestBytes(source: File): ByteArray {        withApkZip(source) { zip ->
            val entry = zip.entries().asSequence()
                .firstOrNull { !it.isDirectory && it.name.equals("AndroidManifest.xml", ignoreCase = true) }
                ?: throw StructuralError("invalid_apk", "未找到 AndroidManifest.xml")
            return zip.getInputStream(entry).use { input -> input.readBytes() }
        }
    }

    /**
     * B6/B7：二进制 AXML 编辑 Manifest，移除广告组件（需用户显式确认，有跳转崩溃风险）
     * 与广告权限。dryRun 返回命中清单，确认后产出 <原名>_manifest.apk 未签名中间包。
     * auto=true 时按规则库自动计算命中（sdk_packages + 广告组件类 + ad_permissions），
     * 避免调用方手填完整组件名。
     */
    private fun patchManifest(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        val outputDir = outputDirArg(call)
        val removeComponents = (arg(call, "removeComponents") as? List<*>)
            ?.map { it.toString().trim().lowercase(Locale.ROOT) }
            ?.filter { it.isNotEmpty() }
            ?.toSet() ?: emptySet()
        val removePermissions = (arg(call, "removePermissions") as? List<*>)
            ?.map { it.toString().trim().lowercase(Locale.ROOT) }
            ?.filter { it.isNotEmpty() }
            ?.toSet() ?: emptySet()
        // 移除广告 SDK 的 meta-data 配置项（如 com.qq.e.comm.AppId）：SDK 初始化
        // 拿不到配置即不加载广告，比删组件更安全（无跳转崩溃风险）。值为配置键。
        val removeMetaData = (arg(call, "removeMetaData") as? List<*>)
            ?.map { it.toString().trim().lowercase(Locale.ROOT) }
            ?.filter { it.isNotEmpty() }
            ?.toSet() ?: emptySet()
        // C7：application 元素布尔属性设置（如 debuggable=false / allowBackup=false
        // / usesCleartextTraffic=false）。值为 Map<String, Boolean>（attrName→目标值）。
        val applicationFlags = (arg(call, "applicationFlags") as? Map<*, *>)
            ?.mapNotNull { (k, v) ->
                val name = k?.toString()?.trim()?.lowercase(Locale.ROOT)
                val value = when (v) {
                    is Boolean -> v
                    is Number -> v.toInt() != 0
                    is String -> v.equals("true", ignoreCase = true) ||
                        v == "1"
                    else -> null
                }
                if (name.isNullOrEmpty() || value == null) null else name to value
            }
            ?.toMap() ?: emptyMap()
        val auto = arg(call, "auto") as? Boolean ?: false
        val dryRun = arg(call, "dryRun") as? Boolean ?: false
        if (!auto && removeComponents.isEmpty() && removePermissions.isEmpty() &&
            removeMetaData.isEmpty() && applicationFlags.isEmpty()
        ) {
            // 空参数缺省 = 不动语义：不抛错、不产出新包，显式回执未做任何改动
            return mapOf(
                "ok" to true,
                "dryRun" to dryRun,
                "changed" to false,
                "nothingRequested" to true,
                "message" to
                    "未提供任何修改项（removeComponents/removePermissions/removeMetaData/applicationFlags " +
                    "均空且 auto=false），未做任何改动",
            )
        }

        val manifest = readManifestBytes(source)
        if (!ApkAxmlEditor.isAxml(manifest)) {
            throw StructuralError("invalid_manifest", "AndroidManifest.xml 不是二进制 AXML 格式，无法安全编辑")
        }

        val allComponents = ApkAxmlEditor.listComponents(manifest)
        val allPermissions = ApkAxmlEditor.listPermissions(manifest)
        val allMetaData = ApkAxmlEditor.listMetaData(manifest)

        // 目标集合：显式清单 + auto 规则命中（sdk 包前缀 / 广告组件关键词 / ad_permissions）
        var targetComponents = removeComponents
        var targetPermissions = removePermissions
        var targetMetaData = removeMetaData
        val excludedBusinessComponents = mutableListOf<String>()
        val protectedMetaData = mutableListOf<String>()
        if (auto) {
            val rules = loadRules()
            val matchedComponents = allComponents
                .filter { ApkAxmlEditor.isAdComponentName(it.name, rules.sdkPackages, rules.classPatterns) }
                .map { it.name.lowercase() }
            targetComponents = targetComponents + matchedComponents
            targetPermissions = targetPermissions + rules.adPermissionSet
            // meta-data 配置键命中 SDK 包前缀/关键词（如 com.qq.e.comm.AppId 命中 com.qq.e 前缀）。
            // 功能型 meta-data 白名单优先：SDK 前缀按公司词匹配时（com.baidu 同时
            // 覆盖广告 SDK 与地图 LBS），com.baidu.lbsapi.API_KEY 这类地图/定位/
            // 推送/支付 Key 被误删会直接破坏业务功能（实测产物 v5.apk）。
            val matchedMetaData = allMetaData
                .filter { ApkAxmlEditor.isAdComponentName(it.name, rules.sdkPackages, rules.classPatterns) }
                .partition { isFunctionalMetaDataKey(it.name) }
            protectedMetaData += matchedMetaData.first.map { it.name }
            targetMetaData = targetMetaData + matchedMetaData.second.map { it.name.lowercase() }
            // A1：含业务特征词（vpn/openvpn/ics 等）的组件默认不删除，标黄提示；
            // D2：distinct 去重（manifest 中同名组件多次声明时只提示一次）
            excludedBusinessComponents += allComponents
                .filter { ApkAxmlEditor.isBusinessExcludedComponent(it.name) }
                .map { it.name }
                .distinct()
        }

        val matchedComponents = allComponents
            .filter { it.name.lowercase() in targetComponents }
            .map { mapOf("tag" to it.tag, "name" to it.name) }
        val matchedPermissions = allPermissions
            .filter { it.lowercase() in targetPermissions }
        val matchedMetaData = allMetaData
            .filter { it.name.lowercase() in targetMetaData }
            .map { mapOf("name" to it.name, "value" to (it.value ?: "")) }

        if (dryRun) {
            // C7：applicationFlags 命中预览——属性当前是否存在于 application 元素
            val summary = ApkAxmlEditor.readManifestSummary(manifest)
            val flagPreviews = applicationFlags.map { (name, value) ->
                mapOf(
                    "attribute" to name,
                    "targetValue" to value,
                    // 读 summary 里已有的布尔属性（debuggable/allowBackup 已解析）；
                    // 其余属性按"无法预读"处理，dryRun 只承诺存在性由实际写时判定。
                    "currentValue" to when (name) {
                        "debuggable" -> summary.debuggable
                        "allowbackup" -> summary.allowBackup
                        else -> null
                    },
                )
            }
            return mapOf(
                "ok" to true,
                "dryRun" to true,
                "componentRules" to targetComponents.size,
                "permissionRules" to targetPermissions.size,
                "metaDataRules" to targetMetaData.size,
                "applicationFlags" to flagPreviews,
                "matchedComponents" to matchedComponents,
                "matchedPermissions" to matchedPermissions,
                "matchedMetaData" to matchedMetaData,
                // 功能型 meta-data 白名单：被保护不删的键（地图/定位/推送/支付 Key）
                "protectedMetaData" to protectedMetaData,
                // A1：疑似业务组件（含 vpn/openvpn/ics 等特征词）标黄提示，默认不删除
                "excludedBusinessComponents" to excludedBusinessComponents,
                "totalComponents" to allComponents.size,
                "totalPermissions" to allPermissions.size,
                // v8-D15（2026-10-04 真机）：口径显式化——这里数的是 AXML 里
                // <uses-permission> 的**元素数**（含重复声明）；重新分析报告的
                // permissionCount 来自框架 requestedPermissions（可能去重/不含
                // uses-permission-sdk-N）。两者差 1 时先对照 distinct 值判断是
                // 重复声明还是口径差，不再当"不一致"直接修。
                "distinctPermissions" to allPermissions.toSet().size,
                "permissionCountNote" to
                    // v9-N9（2026-10-05 复测）：本包 total==distinct（无重复声明）
                    // 仍差 1——重复声明不是唯一解释，改列全部已知口径差。
                    "totalPermissions=AXML <uses-permission> **元素数**；distinctPermissions=去重后。" +
                        "报告 permissionCount 来自框架 requestedPermissions，与 AXML 元素数的已知口径差：" +
                        "① 框架可能合并/去重同 id 声明；② <uses-permission-sdk-23> 等条件声明按 SDK 过滤；" +
                        "③ <permission> 自定义**定义**不计入 uses-permission（本包有一条 DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION 属此列的邻近情况需逐条对照）。" +
                        "差值 ≠ 修改失败；以 AXML 元素清单为准做增删对照。",
                "totalMetaData" to allMetaData.size,
                "message" to "预览仅校验命中；确认后才会重写 Manifest。applicationFlags 仅在属性已存在时改写（不存在则跳过并如实报告）。excludedBusinessComponents 为疑似业务组件（默认不删），如需删除请显式传入 removeComponents",
            )
        }
        if (matchedComponents.isEmpty() && matchedPermissions.isEmpty() &&
            matchedMetaData.isEmpty() && applicationFlags.isEmpty()
        ) {
            return mapOf(
                "ok" to true,
                "dryRun" to false,
                "changed" to false,
                "removedComponents" to emptyList<Map<String, String>>(),
                "removedPermissions" to emptyList<String>(),
                "removedMetaData" to emptyList<Map<String, String>>(),
                "appliedFlags" to emptyList<Map<String, Any>>(),
                "message" to "Manifest 中未命中任何待移除项，未生成新 APK",
            )
        }

        var edited = manifest
        if (targetComponents.isNotEmpty()) {
            edited = ApkAxmlEditor.removeComponents(edited, targetComponents)
        }
        if (targetPermissions.isNotEmpty()) {
            edited = ApkAxmlEditor.removePermissions(edited, targetPermissions)
        }
        if (targetMetaData.isNotEmpty()) {
            edited = ApkAxmlEditor.removeMetaData(edited, targetMetaData)
        }
        // C7：application 布尔属性改写。属性不存在时如实跳过（不新增属性——
        // 新增需重建字符串池，超出本原语范围）。
        val appliedFlags = mutableListOf<Map<String, Any>>()
        val skippedFlags = mutableListOf<Map<String, Any>>()
        for ((name, value) in applicationFlags) {
            val r = ApkAxmlEditor.setElementBooleanAttribute(edited, "application", name, value)
            if (r != null) {
                edited = r
                appliedFlags.add(mapOf("attribute" to name, "value" to value))
            } else {
                skippedFlags.add(
                    mapOf(
                        "attribute" to name,
                        "value" to value,
                        "reason" to "application 元素上不存在该属性（不新增，避免字符串池重建）",
                    ),
                )
            }
        }
        if (edited.contentEquals(manifest)) {
            return mapOf(
                "ok" to true,
                "dryRun" to false,
                "changed" to false,
                "removedComponents" to emptyList<Map<String, String>>(),
                "removedPermissions" to emptyList<String>(),
                "removedMetaData" to emptyList<Map<String, String>>(),
                "appliedFlags" to appliedFlags,
                "skippedFlags" to skippedFlags,
                "message" to if (skippedFlags.isNotEmpty())
                    "Manifest 无实际变化；applicationFlags 属性不存在被跳过：${
                        skippedFlags.joinToString { it["attribute"].toString() }
                    }"
                else "Manifest 编辑后无变化，未生成新 APK",
            )
        }

        val output = structuralOutput(source, outputDir = outputDir)
        ApkStructuralOps.repack(
            source = source,
            output = output,
            overrides = mapOf("AndroidManifest.xml" to edited),
        )
        return mapOf(
            "ok" to true,
            "dryRun" to false,
            "changed" to true,
            "outputPath" to output.absolutePath,
            "removedComponents" to matchedComponents,
            "removedPermissions" to matchedPermissions,
            "removedMetaData" to matchedMetaData,
            "protectedMetaData" to protectedMetaData,
            "appliedFlags" to appliedFlags,
            "skippedFlags" to skippedFlags,
            "message" to "Manifest 已编辑；删除组件后请实机验证跳转，避免 ActivityNotFoundException",
        )
    }

    /**
     * B8：清理广告 assets 资源。匹配规则（ad_asset_files + SDK 关键词）且未被 DEX 引用的删除；
     * 被引用的只报告不删（先查引用后删）。dryRun 返回候选清单，确认后产出 <原名>_assets.apk。
     */
    private fun cleanAdAssets(call: MethodCall): Map<String, Any> {
        val source = resolveSource(call)
        val outputDir = outputDirArg(call)
        val dryRun = arg(call, "dryRun") as? Boolean ?: false
        val rules = loadRules()
        if (rules.adAssetFiles.isEmpty() && rules.sdkPackages.isEmpty()) {
            throw StructuralError("invalid_args", "规则库缺少 ad_asset_files / sdk_packages，无法清理")
        }

        val configuredPatterns = rules.adAssetFiles.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
        val pkgKeywords = ApkAssetScanner.buildAssetKeywords(rules.sdkPackages)

        // 扫描 DEX 字符串引用（先查引用）
        val temporaryDirectory = Files.createTempDirectory("solab_apk_asset_").toFile()
        val dexReferencedAssets = try {
            val dexFiles = mutableListOf<File>()
            withApkZip(source) { zip ->
                zip.entries().asSequence()
                    .filterNot { it.isDirectory }
                    .filter { it.name.matches(DexIo.classesDexRegex) }
                    .forEach { entry ->
                        val dex = File(temporaryDirectory, File(entry.name).name)
                        zip.getInputStream(entry).use { input -> dex.outputStream().use(input::copyTo) }
                        dexFiles.add(dex)
                    }
            }
            ApkAssetScanner.collectDexReferencedAssets(dexFiles)
        } finally {
            temporaryDirectory.deleteRecursively()
        }

        // 收集候选：匹配 + 引用标记。规则命中（用户明确配置）允许直接删除；
        // 仅 SDK 关键词启发式命中的保留 DEX 引用保护（推断项可能误删）。
        data class AssetCandidate(val entryName: String, val relativePath: String, val size: Long, val referenced: Boolean, val matchedConfigured: Boolean, val reason: String)

        val candidates = mutableListOf<AssetCandidate>()
        withApkZip(source) { zip ->
            zip.entries().asSequence()
                .filterNot { it.isDirectory }
                .filter { it.name.startsWith("assets/") }
                .forEach { entry ->
                    val relativePath = entry.name.removePrefix("assets/")
                    val lowerPath = relativePath.lowercase()
                    val fileName = entry.name.substringAfterLast('/').lowercase()

                    val matchedConfigured = configuredPatterns.any { pattern ->
                        lowerPath == pattern || fileName.contains(pattern) || lowerPath.contains("/$pattern")
                    }
                    val matchedBySdk = pkgKeywords.any { kw ->
                        fileName.contains(kw) && fileName.containsAny(ApkAssetScanner.ASSET_AD_HINTS)
                    }
                    if (!matchedConfigured && !matchedBySdk) return@forEach

                    val isDexReferenced = fileName in dexReferencedAssets || lowerPath in dexReferencedAssets
                    val reason = when {
                        matchedConfigured && matchedBySdk -> "规则命中+SDK关键词"
                        matchedConfigured -> "规则命中"
                        else -> "SDK关键词"
                    }
                    candidates.add(
                        AssetCandidate(entry.name, relativePath, entry.size, isDexReferenced, matchedConfigured, reason),
                    )
                }
        }
        candidates.sortBy { it.relativePath }

        // 规则命中的直接删（用户已确认为广告）；仅 SDK 关键词命中且被 DEX 引用的跳过
        val deletable = candidates.filter { it.matchedConfigured || !it.referenced }
        val referenced = candidates.filter { !it.matchedConfigured && it.referenced }

        // C1：res/ 疑似广告资源统计（仅 dryRun 提示，不删除——res 被 R 类
        // 引用，删除有崩溃风险；assets 清理不覆盖 res/ 是刻意的边界）
        val resSuspected = mutableListOf<Map<String, Any>>()
        val resAdHints = listOf(
            "admob", "gdt", "baidu", "ttad", "ksad", "pangle", "ironsource",
            "applovin", "yandex", "mopub", "unityads", "vungle", "ad_", "advert",
        )
        withApkZip(source) { zip ->
            zip.entries().asSequence()
                .filterNot { it.isDirectory }
                .filter { it.name.startsWith("res/") }
                .forEach { entry ->
                    val fileName = entry.name.substringAfterLast('/').lowercase()
                    if (resAdHints.any { fileName.contains(it) }) {
                        resSuspected.add(mapOf("path" to entry.name, "size" to entry.size))
                    }
                }
        }
        resSuspected.sortBy { (it["path"] as String) }

        if (dryRun) {
            return mapOf(
                "ok" to true,
                "dryRun" to true,
                "candidates" to candidates.map {
                    mapOf("path" to it.relativePath, "size" to it.size, "referenced" to it.referenced, "reason" to it.reason)
                },
                "deletableCount" to deletable.size,
                "referencedCount" to referenced.size,
                "savedBytes" to deletable.sumOf { it.size },
                // C1：res/ 疑似广告资源（未纳入清理范围）
                "resSuspectedCount" to resSuspected.size,
                "resSuspected" to resSuspected.take(20),
                "message" to "预览仅统计；规则命中的广告资源直接删除（即使被 DEX 引用），仅 SDK 关键词命中且被 DEX 引用的跳过。确认后清理 assets。res/ 下疑似广告资源（${resSuspected.size} 个）未纳入清理：res 被 R 类引用，删除有崩溃风险，需人工评估",
            )
        }

        if (deletable.isEmpty()) {
            return mapOf(
                "ok" to true,
                "dryRun" to false,
                "changed" to false,
                "deleted" to emptyList<Map<String, Any>>(),
                "referenced" to referenced.map { it.relativePath },
                "message" to "没有可安全删除的广告资源（全部被引用或无命中），未生成新 APK",
            )
        }

        val output = structuralOutput(source, outputDir = outputDir)
        val dropExact = deletable.map { it.entryName }.toSet()
        val result = ApkStructuralOps.repack(source = source, output = output, dropExact = dropExact)
        return mapOf(
            "ok" to true,
            "dryRun" to false,
            "changed" to true,
            "outputPath" to output.absolutePath,
            "deleted" to result.dropped.map { mapOf("path" to it.name, "size" to it.size) },
            "referenced" to referenced.map { it.relativePath },
            "savedBytes" to result.droppedBytes,
        )
    }

    private fun countDropped(source: File, dropPrefixes: List<String>): Pair<Long, Long> {
        if (dropPrefixes.isEmpty()) return 0L to 0L
        var count = 0L
        var bytes = 0L
        withApkZip(source) { zip ->
            zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
                val name = ApkStructuralOps.normalizeEntryName(entry.name) ?: return@forEach
                if (dropPrefixes.any { ApkStructuralOps.prefixMatches(name, it) }) {
                    count++
                    bytes += entry.size
                }
            }
        }
        return count to bytes
    }

    private fun entryContentFile(content: Any?): File? {
        val map = content as? Map<*, *> ?: return null
        val raw = map["path"] as? String ?: return null
        if (raw.isBlank()) {
            throw StructuralError("invalid_content", "本地 content.path 不能为空")
        }
        if (!File(raw).isAbsolute || raw.split('/', '\\').any { it == ".." }) {
            throw StructuralError("invalid_content", "本地 content.path 必须是合法的绝对路径")
        }
        val file = File(raw)
        if (!file.isFile || file.length() <= 0L) {
            throw StructuralError("invalid_content", "本地 content.path 不存在、不是文件或为空: ${file.absolutePath}")
        }
        return file
    }

    private fun entryContentSize(op: EntryOp): Long =
        op.contentFile?.length() ?: op.content?.size?.toLong()
        ?: throw IllegalStateException("缺少条目内容")

    /** 载荷头部魔数（最多 4 字节；无内容或读取失败返回 null，交由后续流程兜底）。 */
    private fun payloadMagic(op: EntryOp): ByteArray? {
        op.content?.let { return it.copyOfRange(0, minOf(4, it.size)) }
        val f = op.contentFile ?: return null
        if (!f.isFile || f.length() <= 0L) return null
        val head = ByteArray(4)
        val read = f.inputStream().use { it.read(head) }
        return if (read <= 0) null else head.copyOf(read)
    }

    /**
     * 产物结构自检（A5）：重打包落盘后用 ZipFile 校验中央目录可解析，
     * 且所有 classes*.dex 条目保留 dex 魔数——防止坏包被晋升为 active
     * 或推荐为下一步输入。失败抛 output_corrupt，产物不产生。
     */
    private fun verifyApkIntegrity(file: File) {
        try {
            java.util.zip.ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name
                    if (name.endsWith(".dex") &&
                        name.substringAfterLast('/').startsWith("classes")
                    ) {
                        zip.getInputStream(entry).use { input ->
                            val head = ByteArray(4)
                            var off = 0
                            while (off < 4) {
                                val n = input.read(head, off, 4 - off)
                                if (n < 0) break
                                off += n
                            }
                            val magic = "dex\n".toByteArray(Charsets.US_ASCII)
                            if (off < 4 || !head.contentEquals(magic)) {
                                throw StructuralError(
                                    "output_corrupt",
                                    "产物自检失败：${file.name} 中 $name 缺少 dex 魔数，" +
                                        "重打包结果损坏，已拒绝产出（保护源包完好）。",
                                )
                            }
                        }
                    }
                }
            }
        } catch (e: StructuralError) {
            throw e
        } catch (e: Exception) {
            throw StructuralError(
                "output_corrupt",
                "产物自检失败：${file.name} 无法作为 zip 解析（${e.message}），已拒绝产出。",
            )
        }
    }

    private fun entryContentSha256(op: EntryOp): String =
        op.contentFile?.let(::sha256) ?: op.content?.let(::sha256)
        ?: throw IllegalStateException("缺少条目内容")

    /** dryRun 压缩体积预估：对新内容跑一次 DEFLATED，返回压缩后字节数（失败 -1）。 */
    private fun estimateDeflatedSize(op: EntryOp): Long {
        val deflater = java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true)
        try {
            var total = 0L
            val buffer = ByteArray(64 * 1024)
            if (op.content != null) {
                deflater.setInput(op.content)
                deflater.finish()
                while (!deflater.finished()) {
                    total += deflater.deflate(buffer)
                }
            } else if (op.contentFile != null) {
                op.contentFile.inputStream().use { input ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) {
                            deflater.finish()
                            while (!deflater.finished()) {
                                total += deflater.deflate(buffer)
                            }
                            break
                        }
                        deflater.setInput(buffer, 0, read)
                        while (!deflater.needsInput() && !deflater.finished()) {
                            total += deflater.deflate(buffer)
                        }
                    }
                }
            } else {
                return -1L
            }
            return total
        } finally {
            deflater.end()
        }
    }

    private fun resultEntry(
        op: EntryOp,
        action: String,
        beforeSha256: String,
        afterSha256: String,
        beforeSize: Long,
        afterSize: Long,
    ): Map<String, Any> = mapOf(
        "locator" to op.locator,
        "action" to action,
        "beforeSha256" to beforeSha256,
        "afterSha256" to afterSha256,
        "beforeSize" to beforeSize,
        "afterSize" to afterSize,
        "contentSource" to op.contentSource,
        "afterSizeMeaning" to if (op.contentSource == "inline_payload") {
            "已传入 base64/hex payload 的真实解码大小；若要预览本地二进制大小，请使用 contentPath"
        } else {
            "本地文件真实大小"
        },
    )

    companion object {
        private val ENTRY_ACTIONS = setOf("overwrite", "add", "delete")

        /** 全量分析输入防护（借鉴玄星 ApkAnalyzer）：APK 大小与条目数上限。 */
        private const val MAX_ANALYZE_BYTES = 512L * 1024L * 1024L
        private const val MAX_ANALYZE_ENTRIES = 100_000

        /** 读引擎结果缓存总预算（chars ≈ bytes）：整包扫描单条可达数 MB。 */
        private const val READ_ENGINE_CACHE_CHARS = 6L * 1024 * 1024
    }
}
