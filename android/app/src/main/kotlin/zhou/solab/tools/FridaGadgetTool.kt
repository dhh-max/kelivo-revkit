package zhou.solab.tools

import android.content.Context
import org.json.JSONObject
import org.tukaani.xz.XZInputStream
import zhou.solab.ApkSignatureBypassInjector
import zhou.solab.ApkStructuralOps
import java.io.File
import java.security.MessageDigest

/**
 * Frida gadget 的取件与宿主侧注入（无 root 动态插桩的前半段）。
 *
 * 分工（见 docs/架构方向-能力双边分配与Frida接入.md）：
 *  - 宿主：下载/校验/解压 gadget、把 gadget 与代理 Application 注入目标 APK、重建产物；
 *  - 沙盒（P2）：跑 python frida 客户端连目标进程里 gadget 监听的 loopback 端口。
 *
 * 版本与校验值在这里钉死：注入别人安装包里的二进制必须是可复核的固定版本。
 */
object FridaGadgetTool {
    const val VERSION = "17.19.0"
    const val DOWNLOAD_URL =
        "https://github.com/frida/frida/releases/download/$VERSION/frida-gadget-$VERSION-android-arm64.so.xz"
    const val XZ_SHA256 = "da55241ed73873176997298f2d00aa02729fc6ce935850923b6a28c587a1d9aa"
    const val XZ_SIZE = 6_969_732L
    const val XZ_NAME = "frida-gadget-$VERSION-android-arm64.so.xz"
    const val GADGET_NAME = "frida-gadget-android-arm64.so"

    /** SolabChannel `portedTool` 契约：入参与出参都是 JSONObject。 */
    fun handle(context: Context, args: JSONObject): JSONObject {
        val map = LinkedHashMap<String, Any?>()
        args.keys().forEach { key -> map[key] = args.opt(key) }
        return JSONObject(handle(context, map))
    }

    fun handle(context: Context, args: Map<String, Any?>): Map<String, Any> {
        val action = args["action"]?.toString()?.trim().orEmpty().ifEmpty { "status" }
        return when (action) {
            "status" -> status(context, args)
            "install_gadget" -> installGadget(context, args)
            "inject" -> inject(context, args)
            else -> mapOf(
                "ok" to false,
                "error" to mapOf(
                    "code" to "UNKNOWN_ACTION",
                    "message" to "Unknown frida action: $action",
                    "allowedValues" to listOf("status", "install_gadget", "inject"),
                ),
            )
        }
    }

    /**
     * 候选下载源（用户实测报告 ⑤）：GitHub 不可达时 `install_gadget` 过去只有一条
     * 死路。现在由调用方（Dart 侧 FridaGadgetSources）按「显式 source → 镜像前缀
     * 套官方地址 → 官方地址」给出有序候选，这里逐个尝试。
     *
     * 安全性不变：无论从哪个源下载，都要过同一个钉死的 [XZ_SHA256]（校验在
     * [AssetDownloader.download] 内），镜像被投毒也换不掉二进制。
     */
    private fun candidateSources(args: Map<String, Any?>): List<String> {
        val raw = args["sources"]
        val list = when (raw) {
            is List<*> -> raw.mapNotNull { it?.toString()?.trim() }
            is org.json.JSONArray -> (0 until raw.length()).mapNotNull {
                raw.optString(it).trim().ifEmpty { null }
            }
            is String -> raw.split('\n').map { it.trim() }
            else -> emptyList()
        }.filter { it.isNotEmpty() }
        return if (list.isEmpty()) listOf(DOWNLOAD_URL) else list.distinct()
    }

    fun status(context: Context, args: Map<String, Any?> = emptyMap()): Map<String, Any> {
        val gadget = gadgetFile(context)
        val xz = File(AssetDownloader.assetDir(context), XZ_NAME)
        return mapOf(
            "ok" to true,
            "tool" to "frida",
            "action" to "status",
            "pinnedVersion" to VERSION,
            "downloadUrl" to DOWNLOAD_URL,
            "candidateSources" to candidateSources(args),
            "xzSha256" to XZ_SHA256,
            "gadget" to mapOf(
                "name" to GADGET_NAME,
                "path" to gadget.absolutePath,
                "present" to gadget.isFile,
                "size" to (if (gadget.isFile) gadget.length() else 0L),
                "sha256" to (if (gadget.isFile) sha256(gadget) else ""),
                "arm64Elf" to (gadget.isFile && isArm64Elf(gadget)),
            ),
            "archive" to mapOf(
                "name" to XZ_NAME,
                "path" to xz.absolutePath,
                "present" to xz.isFile,
                "size" to (if (xz.isFile) xz.length() else 0L),
            ),
            "hostCapabilities" to listOf("inject"),
            "sandboxCapabilities" to listOf("open", "hook", "call", "read", "backtrace", "close"),
            "note" to "gadget 默认交互为 listen 127.0.0.1:27042；端口/脚本配置与运行期驱动属 P2（需 Linux 沙盒）",
            "nextActions" to when {
                // F-46（2026-10-04）：归档已在本地时**别再让调用方去下载**——
                // 真机 v8 D11：archive.present=true 而 nextActions 仍说"下载并解压"，
                // 在 GitHub 不可达的设备上纯浪费一轮。正确动作是带 localPath 解压。
                !gadget.isFile && xz.isFile -> listOf(
                    "安装归档已在本地（${xz.absolutePath}，${xz.length()} B，sha256 已钉死）：" +
                        "直接调用 frida(action=install_gadget, localPath=\"${xz.absolutePath}\") 解压安装，" +
                        "不要再走网络下载"
                )
                !gadget.isFile -> listOf(
                    "调用 frida(action=install_gadget) 下载并解压 gadget（约 7 MB，sha256 已钉死）"
                )
                else -> listOf(
                    "frida(action=inject, apkPath=<工作目录内的 apk>) 生成注入版，再 apk_sign 重签"
                )
            },
        )
    }

    fun installGadget(context: Context, args: Map<String, Any?> = emptyMap()): Map<String, Any> {
        val dir = AssetDownloader.assetDir(context)
        val xz = File(dir, XZ_NAME)
        // 缓存有效性 = 长度 + **内容哈希**（此前只比长度：同长度损坏文件会绕过
        // 校验直接进解压，随后只报一个无证据的 INSTALL_FAILED）。
        val cacheValid = xz.isFile && xz.length() == XZ_SIZE &&
            runCatching { sha256(xz).equals(XZ_SHA256, ignoreCase = true) }
                .getOrDefault(false)
        if (!cacheValid) {
            // ① 本地文件兜底：GitHub 与所有镜像都不可达时，用户可以把 .xz 手动放好
            //    再传 localPath。仍然按钉死的 sha256 校验，不降低任何标准。
            val localPath = args["localPath"]?.toString()?.trim().orEmpty()
            if (localPath.isNotEmpty()) {
                val source = File(localPath)
                if (!source.isFile) {
                    return mapOf(
                        "ok" to false,
                        "error" to mapOf(
                            "code" to "FRIDA_GADGET_LOCAL_NOT_FOUND",
                            "message" to "localPath 不是文件：$localPath",
                        ),
                        "recoverable" to true,
                        "nextActions" to listOf(
                            "检查路径拼写（工作目录内文件用沙盒路径 /mounts/… 或宿主绝对路径）",
                            "或换 frida(action=install_gadget, source=https://<镜像>/) 走下载",
                        ),
                    )
                }
                val actual = sha256(source)
                if (!actual.equals(XZ_SHA256, ignoreCase = true)) {
                    return mapOf(
                        "ok" to false,
                        "error" to mapOf(
                            "code" to "FRIDA_GADGET_LOCAL_HASH_MISMATCH",
                            "message" to "localPath 的 sha256 与钉死值不符（可能下到了 .xz 之外的载荷）",
                            "expectedSha256" to XZ_SHA256,
                            "actualSha256" to actual,
                            "actualBytes" to source.length(),
                            "first4Hex" to runCatching {
                                source.inputStream().use { it.readNBytes(4) }
                                    .joinToString(" ") { b -> "%02x".format(b) }
                            }.getOrDefault(""),
                        ),
                        "recoverable" to true,
                        "nextActions" to listOf(
                            "核对版本：必须是钉死 sha256=$XZ_SHA256 的 $XZ_NAME（版本不匹配不算可用兜底）",
                            "34.9 字节的 HTML/JSON 文本通常是错误页：重新下载或换镜像",
                        ),
                    )
                }
                source.copyTo(xz, overwrite = true)
            } else {
                // ② 按序尝试候选源（Dart 侧给出的镜像顺序；sha256 在 download 内校验）。
                val sources = candidateSources(args)
                val attempts = mutableListOf<Map<String, Any?>>()
                var lastFailure: JSONObject? = null
                var installed = false
                for (source in sources) {
                    val failure = AssetDownloader.download(context, source, XZ_NAME, XZ_SHA256)
                    if (failure == null) {
                        installed = true
                        break
                    }
                    lastFailure = failure
                    val error = failure.optJSONObject("error")
                    // F-29：把下载器写进 diagnostics 的可诊断证据透传出来
                    // （HTTP 状态 / Content-Length / 首 4 字节 / 实际 sha256）——
                    // 没有这些时，"下到错误页"会被误诊成 ABI 不匹配。
                    val diag = error?.optJSONObject("diagnostics")
                    attempts.add(
                        mapOf(
                            "source" to source,
                            "code" to (error?.optString("code") ?: "DOWNLOAD_FAILED"),
                            "message" to (error?.optString("message") ?: ""),
                            "httpStatus" to diag?.optInt("httpStatus", -1),
                            "contentLength" to (diag?.opt("contentLength") ?: -1L),
                            "contentType" to (diag?.optString("contentType") ?: ""),
                            "finalUrl" to (diag?.optString("finalUrl") ?: ""),
                            "first4Hex" to (diag?.optString("first4Hex") ?: ""),
                            "actualSha256" to (diag?.optString("actualSha256") ?: ""),
                            "partialBytes" to (diag?.opt("partialBytes") ?: -1L),
                        ),
                    )
                }
                if (!installed) {
                    return mapOf(
                        "ok" to false,
                        "action" to "install_gadget",
                        "error" to mapOf(
                            "code" to "FRIDA_GADGET_DOWNLOAD_FAILED",
                            "message" to
                                "所有候选下载源都失败（${sources.size} 个）。" +
                                "GitHub 不可达时可用镜像，或手动下载后用 localPath 指定。",
                            "attemptedSources" to attempts,
                        ),
                        "recoverable" to true,
                        "nextActions" to listOf(
                            "frida(action=install_gadget, source=https://<你的镜像>/) 指定可用镜像",
                            "手动下载 $XZ_NAME（sha256=$XZ_SHA256）后 " +
                                "frida(action=install_gadget, localPath=<本地 .xz 路径>)",
                            "失败明细见 error.attemptedSources（哪个源、什么错）",
                        ),
                        "lastFailure" to (lastFailure?.toString() ?: ""),
                    )
                }
            }
        }
        val gadget = File(dir, GADGET_NAME)
        val temp = File(dir, "$GADGET_NAME.tmp-${System.nanoTime()}")
        try {
            XZInputStream(xz.inputStream().buffered()).use { input ->
                temp.outputStream().buffered().use { output -> input.copyTo(output) }
            }
            require(temp.length() > 0) { "FRIDA_GADGET_DECOMPRESS_EMPTY" }
            require(isArm64Elf(temp)) {
                val head = runCatching {
                    temp.inputStream().use { it.readNBytes(20) }
                        .joinToString(" ") { b -> "%02x".format(b) }
                }.getOrDefault("")
                "FRIDA_GADGET_ABI_MISMATCH: expected a 64-bit arm64 ELF " +
                    "(actual bytes=${temp.length()}, first20Hex=$head; a text header like 3c 21 44 4f / 7b 22 means the payload is an HTML/JSON page, not the gadget)"
            }
            if (gadget.exists()) gadget.delete()
            if (!temp.renameTo(gadget)) {
                temp.copyTo(gadget, overwrite = true)
                temp.delete()
            }
        } catch (error: Exception) {
            temp.delete()
            return mapOf(
                "ok" to false,
                "error" to mapOf(
                    "code" to "FRIDA_GADGET_INSTALL_FAILED",
                    "message" to (error.message ?: error.javaClass.simpleName),
                ),
                // v8-D6（2026-10-04）：失败体也带归档实况——过去失败路径没有
                // archive 字段，Dart 侧诊断只能默认 present=false，与随后
                // frida(status) 的 present=true 自相矛盾（会误导去重下载，
                // 而沙盒里 GitHub 往往不可达）。
                "archive" to mapOf(
                    "name" to XZ_NAME,
                    "path" to xz.absolutePath,
                    "present" to xz.isFile,
                    "size" to (if (xz.isFile) xz.length() else 0L),
                ),
            )
        }
        return mapOf(
            "ok" to true,
            "action" to "install_gadget",
            "version" to VERSION,
            "path" to gadget.absolutePath,
            "size" to gadget.length(),
            "sha256" to sha256(gadget),
            // v9-N5（2026-10-05）：成功体也带归档实况——过去只有失败体带，
            // Dart 侧诊断在成功路径上拿不到 archive 字段，archivePresent 恒
            // false，与随后 frida(status) 的 present=true 自相矛盾。
            "archive" to mapOf(
                "name" to XZ_NAME,
                "path" to xz.absolutePath,
                "present" to xz.isFile,
                "size" to (if (xz.isFile) xz.length() else 0L),
            ),
            "nextActions" to listOf("frida(action=inject, apkPath=...)"),
        )
    }

    private fun inject(context: Context, args: Map<String, Any?>): Map<String, Any> {
        // 越权面铁律：只接受"工作目录 + 纯文件名"两个入参。文件名里出现路径分隔符、
        // .. 或 NUL 一律拒绝（工作目录本身也不得含 ..），因此不存在把原始路径直接
        // 交给文件系统的写法；随后再用 normalize + startsWith 做二次包含判定。
        val workDirRaw: String = args["workDir"]?.toString().orEmpty()
        if (workDirRaw.isEmpty() || workDirRaw.contains("..") || workDirRaw.contains('\u0000')) {
            return mapOf(
                "ok" to false,
                "error" to mapOf(
                    "code" to "INVALID_ARGUMENT",
                    "message" to "workDir is required（统一工作目录，由调用方注入；不得含 ..）",
                ),
            )
        }
        val name: String = args["apkName"]?.toString().orEmpty()
        if (name.isEmpty() || name != name.trim() || name == "." ||
            name.contains('/') || name.contains('\\') || name.contains("..") || name.contains('\u0000')
        ) {
            return mapOf(
                "ok" to false,
                "error" to mapOf(
                    "code" to "PATH_OUTSIDE_WORKSPACE",
                    "message" to "apkName 必须是工作目录内的纯文件名（不含路径分隔符或 ..）",
                ),
            )
        }
        val root = java.nio.file.Paths.get(workDirRaw).toAbsolutePath().normalize()
        val candidate = root.resolve(name).normalize()
        if (!candidate.startsWith(root)) {
            return mapOf(
                "ok" to false,
                "error" to mapOf("code" to "PATH_OUTSIDE_WORKSPACE", "message" to "apkName 越界：$name"),
            )
        }
        val source = candidate.toFile()
        if (!source.isFile) {
            return mapOf(
                "ok" to false,
                "error" to mapOf("code" to "APK_NOT_FOUND", "message" to "apkPath does not exist: $name"),
            )
        }
        val gadget = gadgetFile(context)
        if (!gadget.isFile) {
            return mapOf(
                "ok" to false,
                "error" to mapOf(
                    "code" to "FRIDA_GADGET_MISSING",
                    "message" to "gadget 尚未安装：先调用 frida(action=install_gadget)",
                ),
            )
        }
        if (!isArm64Elf(gadget)) {
            return mapOf(
                "ok" to false,
                "error" to mapOf("code" to "FRIDA_GADGET_ABI_MISMATCH", "message" to "gadget 不是 arm64 ELF"),
            )
        }
        val outputDir = candidate.parent?.toFile() ?: root.toFile()
        outputDir.mkdirs()
        val temporaryDirectory = File(context.cacheDir, "frida-inject-${System.nanoTime()}").apply { mkdirs() }
        return try {
            val plan = ApkSignatureBypassInjector.prepare(
                context = context,
                source = source,
                requestedMode = ApkSignatureBypassInjector.MODE_GADGET,
                originalApk = null,
                temporaryDirectory = temporaryDirectory,
                gadgetLib = gadget,
            )
            val output = uniqueOutput(outputDir, source.nameWithoutExtension + "_frida_gadget.apk")
            ApkStructuralOps.repack(
                source = source,
                output = output,
                overrides = plan.byteOverrides,
                overrideFiles = plan.overrides,
                additions = plan.additions,
                additionFiles = plan.additionFiles,
            )
            val verification = ApkSignatureBypassInjector.verifyPrepared(output, plan)
            mapOf(
                "ok" to true,
                "action" to "inject",
                "outputPath" to output.absolutePath,
                "gadgetVersion" to VERSION,
                "gadgetSha256" to sha256(gadget),
                "injection" to plan.toMap(),
                "verification" to verification,
                "analysedArtifact" to "injected",
                "note" to "这是注入版（manifest application 已被替换为代理类，包内新增 libfrida-gadget.so）：" +
                    "不要把它的结论与原始包的静态分析混在一起。产物未重签，需 apk_sign 后才能安装。",
                "nextActions" to listOf(
                    "apk_sign(apkPath=<outputPath>) 重签",
                    "安装后由 Linux 沙盒里的 python frida 客户端连 127.0.0.1:27042（P2 提供工具动作）",
                ),
            )
        } catch (error: Exception) {
            mapOf(
                "ok" to false,
                "error" to mapOf(
                    "code" to (error.message?.substringBefore(':') ?: "FRIDA_INJECT_FAILED"),
                    "message" to (error.message ?: error.javaClass.simpleName),
                ),
            )
        } finally {
            temporaryDirectory.deleteRecursively()
        }
    }

    private fun gadgetFile(context: Context): File =
        File(AssetDownloader.assetDir(context), GADGET_NAME)

    private fun uniqueOutput(dir: File, name: String): File {
        var candidate = File(dir, name)
        var index = 2
        while (candidate.exists()) {
            candidate = File(dir, name.removeSuffix(".apk") + "_v$index.apk")
            index++
        }
        return candidate
    }

    /** 只接受 64 位 arm64 ELF（注入到目标包里的东西必须对得上 ABI）。 */
    fun isArm64Elf(file: File): Boolean = runCatching {
        val header = ByteArray(20)
        file.inputStream().use { if (it.read(header) != header.size) return false }
        // v8-D5（2026-10-04 真机实锤）：e_machine 的 AArch64 是 **0x00B7=183**，
        // 这里过去写成 0xA7（167）——凡是 arm64 gadget 全被判假阴性，报
        // FRIDA_GADGET_ABI_MISMATCH（审计回执里 b7 00 与错误信息同框自证）。
        // 保留 ELFCLASS64（header[4]==2）+ 小端数据编码（header[5]==1）双校验。
        header[0] == 0x7f.toByte() && header[1] == 'E'.code.toByte() &&
            header[2] == 'L'.code.toByte() && header[3] == 'F'.code.toByte() &&
            header[4] == 2.toByte() && header[5] == 1.toByte() &&
            (header[18].toInt() and 0xff) == 0xB7 && (header[19].toInt() and 0xff) == 0x00
    }.getOrDefault(false)

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(256 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}

private fun JSONObject.toMap(): Map<String, Any> {
    val out = LinkedHashMap<String, Any>()
    keys().forEach { key -> out[key] = opt(key) ?: "" }
    return out
}
