package zhou.solab.tools

import android.content.Context
import com.reandroid.apkeditor.compile.BuildOptions
import com.reandroid.apkeditor.decompile.DecompileOptions
import com.reandroid.apkeditor.decompile.Decompiler
import com.reandroid.apkeditor.merge.MergerOptions
import com.reandroid.apkeditor.refactor.RefactorOptions
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.File

/**
 * A6: APKEditor 完整回编/合并/去混淆（移植自玄星逆核 ApkEditorTool.kt）。
 *
 * action: decode(APK→目录) / build(目录→APK) / merge(拆分包→单APK) / refactor(去混淆)。
 * 回编后需用 apk_sign 签名再安装。
 *
 * dex 参数语义（对齐 APKEditor -dex 原义 raw_dex）：
 * true=保留原始 dex 不反编译（快速路径，资源/Manifest 修改默认，秒级~十几秒）；
 * false=反编译 dex→smali（分钟级，仅需要改 smali 代码时显式传）。
 */
object SolabApkEditorTool {

    fun interface OnProgress {
        fun onProgress(percent: Int, stage: String)
    }

    private val percentRegex = Regex("""(\d+)\s*%""")

    /** APKEditor 日志行 → 进度回调；无百分比时 percent=-1（分发层钳位为 1 表示已启动）。 */
    private fun logToProgress(onProgress: OnProgress?, msg: String?) {
        if (onProgress == null || msg.isNullOrBlank()) return
        val pct = percentRegex.find(msg)?.groupValues?.get(1)?.toIntOrNull() ?: -1
        onProgress.onProgress(pct, msg.trim().take(120))
    }

    fun handle(context: Context, args: JSONObject, onProgress: OnProgress? = null): JSONObject {
        val action = args.str("action", "decode")
        val inputPath = args.str("path").ifBlank { args.str("filePath") }
        if (inputPath.isBlank()) {
            return err("INVALID_ARGUMENT", "缺少参数 path(输入 APK 或目录)", "path", "")
        }
        val input = File(inputPath)
        if (!input.exists()) {
            return err("FILE_NOT_FOUND", "输入不存在: $inputPath", "path", inputPath)
        }

        val outRoot = outputRoot(context, args, "output/apkeditor").apply { mkdirs() }
        val sourceName = if (input.isDirectory) input.name.removeSuffix("_decode") else input.nameWithoutExtension
        val baseName = safeArtifactName(sourceName, "apk")
        val force = args.bool("force", false)
        val startedAt = System.currentTimeMillis()
        // D25：本次是否清理了"上次未完成"的残留（回执要如实说明）。
        var recoveredFromStale = false
        var staleNote = ""

        fun elapsed(extra: JSONObject?): JSONObject {
            val e = extra ?: JSONObject()
            return e.put("elapsedMs", System.currentTimeMillis() - startedAt)
        }

        return runCatching {
            when (action) {
                "decode" -> {
                    val out = resolveOutput(args, outRoot, "${baseName}_decode")
                    // 写入标记（D25，2026-09-21 独立复验）：decode 是分钟级任务，超时/被杀会
                    // 留下半截目录（复验方实测 57MB 包残留 26,984 个文件），此后一律
                    // DECODE_DIR_EXISTS —— 把"上次崩了"误报成"你自己改过、要保护"。
                    // 用 `path-map.json`（成功收尾才写）区分：有标记文件=完成品，
                    // 无标记=未完成残留，可以安全清建、并在回执里说明。
                    val marker = File(out, "path-map.json")
                    if (out.isDirectory && !force) {
                        if (!marker.isFile) {
                            val staleCount = out.walkTopDown().count { it.isFile }
                            runCatching { out.deleteRecursively() }
                            recoveredFromStale = true
                            staleNote = "上次 decode 未完成（缺 path-map.json）：已清理残留 " +
                                "$staleCount 个文件并重新开始。若那是你要保护的手工修改，" +
                                "下次请给它留一份 path-map.json 或改用 output= 指定新目录。"
                        } else {
                            // 破坏性防护：重复 decode 会清掉解码目录里手工替换过的文件
                            // （曾丢过补丁版 libapp.so）。已完成目录必须显式 force 或换 output。
                            val fileCount = out.walkTopDown().count { it.isFile }
                            return@runCatching err(
                                "DECODE_DIR_EXISTS",
                                "解码目录已存在且含 $fileCount 个文件，覆盖会清空其全部内容（可能包含你的手工修改）。传 force=true 强制覆盖，或改传 output= 指定新目录。",
                                "path", out.absolutePath,
                                "fileCount" to fileCount,
                                "recoverable" to true,
                            )
                        }
                    }
                    val opt = DecompileOptions().apply {
                        inputFile = input
                        outputFile = out
                        this.force = force
                        type = args.str("type", "json")
                        dex = args.bool("dex", true)
                    }
                    // 子类化劫持 APKEditor 日志 → 进度事件（runCommand 本身无回调）
                    object : Decompiler(opt) {
                        override fun logMessage(msg: String?) { logToProgress(onProgress, msg) }
                        override fun logVerbose(msg: String?) { logToProgress(onProgress, msg) }
                        override fun logMessage(tag: String?, msg: String?) { logToProgress(onProgress, msg) }
                        override fun logVerbose(tag: String?, msg: String?) { logToProgress(onProgress, msg) }
                    }.runCommand()
                    val fileCount = if (out.isDirectory) out.walkTopDown().count { it.isFile } else 0
                    val layout = writePathMap(input, out)
                    val hint = if (opt.dex) {
                        "已反编译到目录（保留原始 dex 未解 smali，快速路径）。改资源/Manifest 后 action=build 回编；需改 smali 代码时传 dex=false（分钟级全量反编译）。"
                    } else {
                        "已反编译到目录（含全量 smali，耗时较长）。可编辑资源/smali 后用 action=build 回编。注意：全量 smali 是分钟级任务，MCP 客户端可能超时断开，任务仍在后台执行，可用 file(action=list) 查产物目录确认。"
                    }
                    result("decode", out, hint,
                        elapsed(
                            JSONObject()
                                .put("files", fileCount)
                                .put("rawDex", opt.dex)
                                .put("decodeRoot", layout.optString("decodeRoot"))
                                .put("nativeLibraryRoot", layout.optString("nativeLibraryRoot"))
                                .put("pathMap", layout.optString("pathMap"))
                                .put("pathMapEntries", layout.optInt("entries"))
                                // 未完成残留被自动清建时如实上报（D25）。
                                .apply {
                                    if (recoveredFromStale) {
                                        put("recoveredFromStaleDecode", true)
                                        put("recoveredFromStaleNote", staleNote)
                                    }
                                },
                        ))
                }

                "build" -> {
                    if (!input.isDirectory) {
                        return@runCatching err("INVALID_ARGUMENT", "build 的 path 必须是 decode 出的目录", "path", inputPath)
                    }
                    val pathMap = normalizePathMap(input)
                    val out = resolveOutput(args, outRoot, "${baseName}_rebuilt.apk")
                    prepareOutput(out, force, "回编 APK 产物")?.let { return@runCatching it }
                    val opt = BuildOptions().apply {
                        inputFile = input
                        outputFile = out
                        this.force = force
                        type = args.str("type", "json")
                    }
                    object : com.reandroid.apkeditor.compile.Builder(opt) {
                        override fun logMessage(msg: String?) { logToProgress(onProgress, msg) }
                        override fun logVerbose(msg: String?) { logToProgress(onProgress, msg) }
                        override fun logMessage(tag: String?, msg: String?) { logToProgress(onProgress, msg) }
                        override fun logVerbose(tag: String?, msg: String?) { logToProgress(onProgress, msg) }
                    }.runCommand()
                    result("build", out, "已回编成完整 APK。必须用 apk_sign 签名后才能安装。", elapsed(pathMap))
                }

                "merge" -> {
                    val out = resolveOutput(args, outRoot, "${baseName}_merged.apk")
                    prepareOutput(out, force, "合并 APK 产物")?.let { return@runCatching it }
                    val opt = MergerOptions().apply {
                        inputFile = input
                        outputFile = out
                        this.force = force
                        cleanMeta = args.bool("cleanMeta", true)
                    }
                    opt.newCommandExecutor().runCommand()
                    result("merge", out, "已把拆分包合并成单个 APK。用 apk_sign 签名后可安装。", elapsed(null))
                }

                "refactor" -> {
                    val out = resolveOutput(args, outRoot, "${baseName}_refactored.apk")
                    prepareOutput(out, force, "混淆还原 APK 产物")?.let { return@runCatching it }
                    val opt = RefactorOptions().apply {
                        inputFile = input
                        outputFile = out
                        this.force = force
                        cleanMeta = args.bool("cleanMeta", true)
                        fixTypeNames = args.bool("fixTypeNames", false)
                    }
                    opt.newCommandExecutor().runCommand()
                    result("refactor", out, "已还原混淆的资源名。", elapsed(null))
                }

                else -> err("UNKNOWN_ACTION", "未知 action: $action", "action", action)
            }
        }.getOrElse { e ->
            err("APKEDITOR_FAILED", "APKEditor $action 失败: ${e.message ?: e.javaClass.simpleName}", "path", inputPath)
        }
    }

    private fun resolveOutput(args: JSONObject, outRoot: File, defaultName: String): File {
        val custom = args.str("output")
        val workDir = File(args.str("workDir")).canonicalFile
        val out = if (custom.isBlank()) {
            File(outRoot, defaultName)
        } else {
            val requested = File(custom)
            if (requested.isAbsolute) requested else File(workDir, custom)
        }.canonicalFile
        require(out.path == workDir.path || out.path.startsWith(workDir.path + File.separator)) {
            "OUTPUT_OUTSIDE_WORKDIR: output must stay inside the work directory"
        }
        // C7（阶段 0）：不再无条件删旧产物（此前 build 失败会毁掉已存在的好 APK）。
        // 删除门控上移到各 action：目录产物（decode）由 force 决定是否覆盖；
        // 文件产物（build/merge/refactor）非 force 时已存在 → 报错让用户换 output
        // 或显式 force（force 才在构建成功后原子替换）。
        out.parentFile?.mkdirs()
        return out
    }

    /// C7：目标产物已存在时，非 force 直接报错（不删不覆盖），force 才清。
    private fun prepareOutput(out: File, force: Boolean, what: String): JSONObject? {
        if (!out.exists()) return null
        if (!force) {
            return err(
                "OUTPUT_EXISTS",
                "$what 已存在: ${out.absolutePath}。传 force=true 覆盖，或改传 output= 指定新路径（默认不覆盖，防误删好产物）。",
                "path", out.absolutePath,
                "recoverable" to true,
            )
        }
        if (out.isDirectory) out.deleteRecursively() else out.delete()
        return null
    }

    private fun result(action: String, out: File, hint: String, extra: JSONObject?): JSONObject {
        val body = JSONObject()
            .put("tool", "apk_rebuild")
            .put("action", action)
            .put("output", out.absolutePath)
            .put("outputKind", if (out.isDirectory) "directory" else "file")
            .put("sizeBytes", if (out.isFile) out.length() else 0L)
            .put("hint", hint)
        extra?.keys()?.forEach { body.put(it, extra.get(it)) }
        return ok(body)
    }

    private fun writePathMap(input: File, out: File): JSONObject {
        val root = File(out, "root")
        val entries = JSONArray()
        if (root.isDirectory) {
            ApkZipCache.shared.withZip(input) { zip ->
                zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
                    val name = entry.name
                    if (name.startsWith('/') || name.contains('\\') || name.split('/').contains("..")) return@forEach
                    val decoded = File(root, name)
                    if (!decoded.isFile) return@forEach
                    entries.put(
                        JSONObject()
                            .put("zipEntry", name)
                            .put("decodedPath", decoded.relativeTo(out).path.replace(File.separatorChar, '/'))
                            .put("sourceSize", entry.size)
                            .put("decodedSize", decoded.length()),
                    )
                }
            }
        }
        val mapFile = File(out, "path-map.json")
        mapFile.writeText(entries.toString(), Charsets.UTF_8)
        return JSONObject()
            .put("decodeRoot", root.absolutePath)
            .put("nativeLibraryRoot", File(root, "lib").absolutePath)
            .put("pathMap", mapFile.absolutePath)
            .put("entries", entries.length())
    }

    private fun normalizePathMap(input: File): JSONObject? {
        val mapFile = File(input, "path-map.json")
        if (!mapFile.isFile) return null
        val bytes = mapFile.readBytes()
        val text = when {
            bytes.size >= 2 && bytes[0] == 0xff.toByte() && bytes[1] == 0xfe.toByte() ->
                String(bytes, 2, bytes.size - 2, Charsets.UTF_16LE)
            bytes.size >= 2 && bytes[0] == 0xfe.toByte() && bytes[1] == 0xff.toByte() ->
                String(bytes, 2, bytes.size - 2, Charsets.UTF_16BE)
            else -> String(bytes, Charsets.UTF_8).removePrefix("\uFEFF")
        }
        val parsed = JSONTokener(text).nextValue()
        val entries = when (parsed) {
            is JSONArray -> parsed
            is JSONObject -> parsed.optJSONArray("entries")
                ?: throw IllegalArgumentException("path-map.json 缺少 entries 数组")
            else -> throw IllegalArgumentException("path-map.json 必须是数组")
        }
        mapFile.writeText(entries.toString(), Charsets.UTF_8)
        return JSONObject().put("pathMapEntries", entries.length()).put("pathMapNormalized", true)
    }
}
