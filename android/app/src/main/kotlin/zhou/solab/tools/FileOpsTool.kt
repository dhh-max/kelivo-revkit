package zhou.solab.tools

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * 通用文件操作工具（AI 读写工作目录任意格式文件）。
 *
 * action:
 *  - read:    读文本（UTF-8 按行分页 offset/limit）或二进制（hex 字节窗口），不受整文件大小限制
 *  - write:   写文本文件（覆盖/新建；需 dryRun→confirm）
 *  - list:    列目录（名称/类型/大小/修改时间）；path 指向 APK/ZIP 时列包内条目
 *             （offset/limit 分页 + entryPrefix 前缀过滤，全量可达）
 *  - delete:  删除文件（需 dryRun→confirm）
 *  - info:    文件/目录元信息
 *  - zip:     压缩文件/目录 → zip（同目录或指定输出）
 *  - unzip:   解压 zip → 目录（zip-slip 防护 + 条目/总量限制）
 *  - diff:    比对两个文件（unified diff 风格变更块）
 *  - mkdir:   创建目录（含父目录，幂等）
 *
 * 安全：拒绝 `..` 路径穿越；读窗口预算 200KB/4096B、写上限 16MB、解压 5000 条目/256MB。
 */
object FileOpsTool {

    private const val MAX_TEXT_PREVIEW = 200 * 1024
    private const val MAX_GREP_FILES = 2000
    // 512MB：Blutter 大包的 pp.txt/objs.txt 这类参考账本能到几百 MB，旧值 256MB
    // 会把它们静默挡在搜索之外（调用方拿到 0 命中）。maxFileBytes 参数可在
    // [1KB, 2GB] 内显式放宽。
    private const val MAX_GREP_FILE_BYTES = 512L * 1024 * 1024
    private const val MAX_GREP_FILE_BYTES_CEILING = 2048L * 1024 * 1024
    private const val MAX_REPLACE_FILE_BYTES = 16L * 1024 * 1024
    private const val MAX_STRINGS_FILE_BYTES = 128L * 1024 * 1024
    private const val MAX_WRITE_BYTES = 16 * 1024 * 1024
    private const val MAX_UNZIP_ENTRIES = 5000
    private const val MAX_UNZIP_TOTAL = 256L * 1024 * 1024
    private const val MAX_DIFF_FILE_BYTES = 16L * 1024 * 1024

    fun handle(args: JSONObject): JSONObject {
        val action = args.optString("action", "read")
        return when (action) {
            "read" -> read(args)
            "write" -> write(args)
            "list" -> list(args)
            "delete" -> delete(args)
            "info" -> info(args)
            "zip" -> zip(args)
            "unzip" -> unzip(args)
            "copy" -> copy(args)
            "rename" -> rename(args)
            "diff" -> diff(args)
            "mkdir" -> mkdir(args)
            "grep" -> grep(args)
            "replace" -> replace(args)
            "strings" -> strings(args)
            else -> err("UNKNOWN_ACTION", "未知 action: $action（支持 read/write/list/delete/info/zip/unzip/copy/rename/diff/mkdir/grep/replace/strings）", "action", action)
        }
    }

    /** 路径防护：绝对路径，原始段与 normalize 后均不含 .. 段。 */
    private fun safeFile(raw: String): File? {
        val path = raw.trim()
        if (path.isBlank()) return null
        if (path.split('/', '\\').any { it == ".." }) return null
        val f = File(path)
        if (!f.isAbsolute) return null
        val segments = f.toPath().normalize().toString().split('/', '\\')
        if (segments.contains("..")) return null
        return f
    }

    /**
     * Blutter 产物识别（pp.txt / 清单 jsonl / asm 目录下的 .dart）：描述里写了
     * "never read them page by page"，但 read 一直照单全收——把约定变成
     * 可执行提示（不硬拦：单点窗口读取仍有正当用途，拦死会挡掉合法调试）。
     */
    private fun blutterArtifactRedirect(f: File): Pair<JSONArray, String>? {
        val name = f.name.lowercase()
        val normalized = f.absolutePath.replace('\\', '/').lowercase()
        val isAsm = normalized.contains("/asm/") && name.endsWith(".dart")
        val isPp = name == "pp.txt"
        val isInventory = name == "libraries.jsonl" || name == "classes.jsonl" || name == "functions.jsonl"
        if (!isAsm && !isPp && !isInventory) return null
        val actions = JSONArray()
        actions.put(
            JSONObject().put("action", "file").put("target", "grep")
                .put("reason", "在 $name 里按关键词取命中行，比分页 read 快几个数量级")
                .put("arguments", JSONObject().put("action", "grep").put("path", f.absolutePath).put("query", "<关键词>")),
        )
        if (isPp) {
            actions.put(
                JSONObject().put("action", "so_analyze").put("target", "blutterAction=search scope=pp")
                    .put("reason", "pp.txt 有倒排索引（亚秒级），按关键词直接回类/函数/Code VA")
                    .put("arguments", JSONObject().put("action", "blutter").put("blutterAction", "search").put("scope", "pp").put("query", "<关键词>")),
            )
        } else if (isAsm) {
            actions.put(
                JSONObject().put("action", "so_analyze").put("target", "blutterAction=search scope=asm")
                    .put("reason", "asm 维度走语义索引，可按类名/包路径过滤（includePath），不必逐文件读")
                    .put("arguments", JSONObject().put("action", "blutter").put("blutterAction", "search").put("scope", "asm").put("includePath", "<类名或包路径>")),
            )
        } else {
            actions.put(
                JSONObject().put("action", "so_analyze").put("target", "blutterAction=result")
                    .put("reason", "清单文件按需分页取（kind 直接给文件名），不需要整读")
                    .put("arguments", JSONObject().put("action", "blutter").put("blutterAction", "result").put("kind", name.removeSuffix(".jsonl"))),
            )
        }
        val warning = "这是 Blutter 产物（$name）：定位请用 file(grep) 或 so_analyze 的索引检索，分页 read 会把几千个文件的检索做成分钟级。"
        return actions to warning
    }

    private fun attachBlutterRedirect(payload: JSONObject, f: File): JSONObject {
        val redirect = blutterArtifactRedirect(f) ?: return payload
        payload.put("nextActions", redirect.first)
        payload.put("warning", redirect.second)
        return payload
    }

    private fun read(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        // 报告 2-4：目录过去走 FILE_NOT_FOUND（「文件不存在」），把「类型不符」
            // 说成「不存在」，排查方向直接跑偏。现在单独给 NOT_A_FILE + 替代路径。
        if (f.isDirectory) {
            return err(
                    "NOT_A_FILE",
                "path 指向目录（${f.absolutePath}），不是文件。列目录请用 action=list；读文件请给具体文件路径。",
                "path",
                f.absolutePath,
            )
            }
        if (!f.isFile) return err("FILE_NOT_FOUND", "文件不存在: ${f.absolutePath}", "path", f.absolutePath)
        val offset = args.optLong("offset", 0L).coerceAtLeast(0L)
        val limit = args.optInt("limit", 0).coerceAtLeast(0)
        // 文本探测（采样前 64KB，无需整文件载入）
        val sampleSize = minOf(64 * 1024L, f.length()).toInt()
        val sample = f.inputStream().use { readExactly(it, sampleSize) }
        val nulCount = sample.count { it == 0.toByte() }
        // 与 isTextFile 一致：UTF-8 多字节（>=0x80，如中文）也算可打印，
        // 否则中文文档会被误判为二进制走 hex 窗口。
        val printable = sample.count {
            val b = it.toInt() and 0xff
            b in 0x09..0x0d || b in 0x20..0x7e || b >= 0x80
        }
        val isText = nulCount == 0 && sample.isNotEmpty() && printable >= sample.size * 4 / 5
        if (isText) {
            // 文本按行分页：offset=起始行(0 基)，limit=行数（默认 500，上限 5000），窗口内容再受字符预算约束
            val lineLimit = if (limit > 0) minOf(limit, 5000) else 500
            val sb = StringBuilder()
            var lineNo = 0L
            var appended = 0
            var truncated = false
            var totalLines = -1L
            f.useLines { lines ->
                for (line in lines) {
                    if (lineNo >= offset) {
                        if (appended >= lineLimit || sb.length + line.length > MAX_TEXT_PREVIEW) { truncated = true; break }
                        sb.appendLine(line)
                        appended++
                    }
                    lineNo++
                }
                if (!truncated) totalLines = lineNo
            }
            return ok(attachBlutterRedirect(JSONObject()
                .put("tool", "file_ops")
                .put("action", "read")
                .put("path", f.absolutePath)
                .put("size", f.length())
                .put("encoding", "UTF-8")
                .put("offset", offset)
                .put("lines", appended)
                .put("truncated", truncated)
                .put("content", sb.toString())
                .put("hint", if (truncated) "已按 limit/字符预算截断，用 offset=${offset + appended} 续读" else if (offset > 0 || appended < totalLines) "当前行区间 [$offset, ${offset + appended})" else ""), f))
        }
        // 二进制：hex 窗口（offset=起始字节，limit=字节数，默认 256 上限 4096）
        val byteLimit = if (limit > 0) minOf(limit, 4096) else 256
        if (offset >= f.length()) return err("INVALID_ARGUMENT", "offset 超出文件大小 ${f.length()}", "offset", offset.toString())
        val windowLen = minOf(byteLimit.toLong(), f.length() - offset).toInt()
        val window = f.inputStream().use { ins ->
            var skipped = 0L
            while (skipped < offset) {
                val n = ins.skip(offset - skipped)
                if (n <= 0) break
                skipped += n
            }
            readExactly(ins, windowLen)
        }
        return ok(attachBlutterRedirect(JSONObject()
            .put("tool", "file_ops")
            .put("action", "read")
            .put("path", f.absolutePath)
            .put("size", f.length())
            .put("encoding", "binary")
            .put("offset", offset)
            .put("bytes", window.size)
            .put("hexPreview", window.joinToString(" ") { "%02X".format(it) })
            .put("isText", false)
            .put("hint", "二进制窗口 [${offset}, ${offset + window.size})；文件过大时用 offset/limit 分窗读取"), f))
    }

    private fun write(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        // C12（阶段 0）：支持二进制写入（contentEncoding=base64/hex，缺省 utf8）——
        // 此前能读二进制 hex 窗口却只能写文本，读写不对称。
        val encoding = args.optString("contentEncoding", "utf8").lowercase()
        val content = args.optString("content")
        val bytes = when (encoding) {
            "base64" -> runCatching { java.util.Base64.getDecoder().decode(content.trim()) }.getOrElse {
                return err("INVALID_CONTENT", "contentEncoding=base64 但 content 不是合法 Base64", "content", "")
            }
            "hex" -> runCatching {
                val hex = content.trim().replace(" ", "").replace("\n", "")
                require(hex.length % 2 == 0)
                hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            }.getOrElse {
                return err("INVALID_CONTENT", "contentEncoding=hex 但 content 不是合法十六进制（偶数长度 0-9a-f）", "content", "")
            }
            else -> content.toByteArray(Charsets.UTF_8)
        }
        if (bytes.size > MAX_WRITE_BYTES) return err("FILE_TOO_LARGE", "写入内容超过 ${MAX_WRITE_BYTES / 1024 / 1024}MiB 上限", "path", f.absolutePath)
        val dryRun = args.optBoolean("dryRun", true)
        val existed = f.exists()
        if (dryRun) {
            return ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "write")
                .put("dryRun", true)
                .put("path", f.absolutePath)
                .put("contentEncoding", encoding)
                .put("wouldCreate", !existed)
                .put("wouldOverwrite", existed)
                .put("size", bytes.size)
                .put("preview", content.take(500))
                .put("hint", "确认后再次调用并传 dryRun=false 执行写入"))
        }
        f.parentFile?.mkdirs()
        // C12：原子写——先写同目录 tmp 再 moveReplace，中断/失败不留半截文件
        // 毁掉原内容（与 copy 的原子路径同源）。
        val tmp = File(f.parentFile, ".${f.name}.${System.nanoTime()}.writing")
        try {
            tmp.writeBytes(bytes)
            moveReplace(tmp, f, overwrite = true)
        } finally {
            if (tmp.exists()) tmp.delete()
        }
        return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "write")
            .put("path", f.absolutePath)
            .put("contentEncoding", encoding)
            .put("created", !existed)
            .put("overwritten", existed)
            .put("size", bytes.size)
            .put("hint", "文件已写入工作目录（tmp+原子替换）"))
    }

    private fun list(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        // APK/ZIP 包内条目列表：包体差异排查/改点核对需要按条目对比，
        // 以前这里只会报 DIR_NOT_FOUND，Agent 没有包内清单入口。
        if (f.isFile && f.name.lowercase().let { it.endsWith(".apk") || it.endsWith(".zip") }) {
            return listZipEntries(f, args)
        }
        if (!f.isDirectory) {
            // 路径存在但是**文件**：报"目录不存在"会把人带偏（2026-09-15 真机：
            // Agent 拿 asm 下的 .dart 文件路径来 list，收到一句"目录不存在"）。
            // 明确说清是文件、该用哪个动作；Blutter 产物再附索引检索的改道建议。
            if (f.isFile) {
                val parent = f.parentFile?.absolutePath ?: ""
                val envelope = err(
                    "PATH_IS_FILE",
                    "${f.absolutePath} 是文件不是目录：查看内容用 action=read；" +
                        "列它所在目录请把 path 换成父目录 $parent。",
                    "path", f.absolutePath,
                )
                attachBlutterRedirect(envelope, f)
                return envelope
            }
            return err("DIR_NOT_FOUND", "目录不存在: ${f.absolutePath}（APK/ZIP 包内条目请直接对包文件 list）", "path", f.absolutePath)
        }
        // C10（阶段 0）：目录 list 补齐 offset/nextOffset 稳定分页——此前只按
        // limit 截断、newDirectoryStream 无序，hint 说"分页读取"但二次调用会
        // 重排重读首页。改为：条目先收集排序（名称稳定序）再 offset/limit 切片。
        val offset = args.optInt("offset", 0).coerceAtLeast(0)
        val limit = args.optInt("limit", 200).coerceIn(1, 2000)
        val all = mutableListOf<JSONObject>()
        Files.newDirectoryStream(f.toPath()).use { entries ->
            for (entry in entries) {
                val c = entry.toFile()
                all.add(JSONObject()
                    .put("name", c.name)
                    .put("path", c.absolutePath)
                    .put("isDirectory", c.isDirectory)
                    .put("size", if (c.isFile) c.length() else 0L)
                    .put("modified", c.lastModified()))
            }
        }
        // 稳定序：目录在前按名称，文件在后按名称——跨页不重排。
        all.sortWith(compareBy({ !it.optBoolean("isDirectory") }, { it.optString("name") }))
        val items = JSONArray()
        var scanned = 0
        for (i in offset until all.size) {
            if (items.length() >= limit) break
            items.put(all[i])
            scanned++
        }
        val hasMore = offset + items.length() < all.size
        val total = all.size
        return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "list")
            .put("path", f.absolutePath)
            .put("total", total)
            .put("offset", offset)
            .put("returned", items.length())
            .put("hasMore", hasMore)
            .put("nextOffset", if (hasMore) offset + items.length() else JSONObject.NULL)
            .put("items", items)
            .put("hint", if (hasMore)
                "目录还有更多条目：用 offset=${offset + items.length()} 翻页（条目按 目录在前/名称序 稳定排列）"
                else if (offset > 0) "当前页为末页"
                else ""))
    }

    /** APK/ZIP 条目列表：central directory 直读不解压；全量计数 + 窗口分页。 */
    private fun listZipEntries(f: File, args: JSONObject): JSONObject {
        val offset = args.optInt("offset", 0).coerceAtLeast(0)
        val limit = args.optInt("limit", 200).coerceIn(1, 2000)
        val prefix = args.optString("entryPrefix", "").trim().ifEmpty { null }
        val zipCache = ApkZipCache()
        return zipCache.withZip(f) { zip ->
            val names = zip.entries().asSequence()
                .filterNot { it.isDirectory }
                .map { it.name }
                .filter { prefix == null || it.startsWith(prefix) }
                .sorted()
                .toList()
            val window = names.drop(offset.coerceAtMost(names.size))
                .take(limit)
            val items = JSONArray()
            for (name in window) {
                val entry = zip.getEntry(name)
                items.put(
                    JSONObject()
                        .put("name", name)
                        .put("size", entry?.size ?: 0L)
                        .put("compressedSize", entry?.compressedSize ?: 0L)
                        .put("modified", entry?.time ?: 0L),
                )
            }
            val hasMore = offset + limit < names.size
            ok(
                JSONObject()
                    .put("tool", "file_ops")
                    .put("action", "list")
                    .put("kind", "zip_entries")
                    .put("path", f.absolutePath)
                    .put("total", names.size)
                    .put("offset", offset)
                    .put("returned", items.length())
                    .put("hasMore", hasMore)
                    .put("nextOffset", if (hasMore) offset + limit else JSONObject.NULL)
                    .put("items", items)
                    .put(
                        "hint",
                        if (hasMore) {
                            "包内共 ${names.size} 个文件条目，用 offset=${offset + limit} 继续翻页；entryPrefix 可按前缀缩小范围（如 dex/、res/、lib/）"
                        } else if (prefix != null) {
                            "entryPrefix=$prefix 过滤后 ${names.size} 条"
                        } else {
                            ""
                        },
                    ),
            )
        }
    }

    private fun delete(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        if (!f.exists()) return err("FILE_NOT_FOUND", "不存在: ${f.absolutePath}", "path", f.absolutePath)
        if (args.optBoolean("dryRun", true)) {
            return ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "delete")
                .put("dryRun", true)
                .put("path", f.absolutePath)
                .put("isDirectory", f.isDirectory)
                .put("size", if (f.isFile) f.length() else 0L)
                .put("hint", "确认后再次调用并传 dryRun=false 删除（目录需 recursive=true）"))
        }
        val recursive = args.optBoolean("recursive", false)
        val deleted = if (f.isDirectory) {
            if (!recursive) return err("INVALID_ARGUMENT", "删除目录需 recursive=true", "path", f.absolutePath)
            f.deleteRecursively()
        } else {
            f.delete()
        }
        if (!deleted) return err("DELETE_FAILED", "删除失败（权限或占用）", "path", f.absolutePath)
        return ok(JSONObject().put("tool", "file_ops").put("action", "delete").put("path", f.absolutePath).put("deleted", true))
    }

    private fun info(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        if (!f.exists()) return err("FILE_NOT_FOUND", "不存在: ${f.absolutePath}", "path", f.absolutePath)
        return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "info")
            .put("path", f.absolutePath)
            .put("name", f.name)
            .put("isDirectory", f.isDirectory)
            .put("isFile", f.isFile)
            .put("size", if (f.isFile) f.length() else 0L)
            .put("modified", f.lastModified())
            .put("extension", f.extension.ifBlank { JSONObject.NULL }))
    }

    private fun copy(args: JSONObject): JSONObject {
        val source = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        val target = safeFile(args.optString("target")) ?: return err("INVALID_PATH", "target 必须是合法的绝对路径（不含 ..）", "target", args.optString("target"))
        if (!source.exists()) return err("FILE_NOT_FOUND", "源文件或目录不存在: ${source.absolutePath}", "path", source.absolutePath)
        if (source.canonicalPath == target.canonicalPath) return err("INVALID_ARGUMENT", "源路径与目标路径相同", "target", target.absolutePath)
        val overwrite = args.optBoolean("overwrite", false)
        val targetExisted = target.exists()
        if (targetExisted && !overwrite) return err("TARGET_EXISTS", "目标已存在；如需替换请传 overwrite=true", "target", target.absolutePath)
        val stats = treeStats(source)
        val dryRun = args.optBoolean("dryRun", true)
        if (dryRun) {
            return ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "copy")
                .put("dryRun", true)
                .put("path", source.absolutePath)
                .put("target", target.absolutePath)
                .put("isDirectory", source.isDirectory)
                .put("files", stats.first)
                .put("size", stats.second)
                .put("wouldOverwrite", targetExisted)
                .put("hint", "确认后再次调用并传 dryRun=false 复制文件"))
        }
        return runCatching {
            target.parentFile?.mkdirs()
            if (source.isDirectory) {
                if (target.exists() && overwrite) target.deleteRecursively()
                copyDirectory(source, target)
            } else {
                val tmp = File(target.parentFile, ".${target.name}.${System.nanoTime()}.copying")
                try {
                    source.inputStream().use { input -> tmp.outputStream().use { input.copyTo(it) } }
                    moveReplace(tmp, target, overwrite)
                } finally {
                    if (tmp.exists()) tmp.delete()
                }
            }
            ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "copy")
                .put("path", source.absolutePath)
                .put("target", target.absolutePath)
                .put("isDirectory", source.isDirectory)
                .put("files", stats.first)
                .put("size", stats.second)
                .put("overwritten", targetExisted)
                .put("hint", "文件已原样复制"))
        }.getOrElse { e -> err("COPY_FAILED", "复制失败: ${e.message}", "target", target.absolutePath) }
    }

    private fun rename(args: JSONObject): JSONObject {
        val source = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        val target = safeFile(args.optString("target")) ?: return err("INVALID_PATH", "target 必须是合法的绝对路径（不含 ..）", "target", args.optString("target"))
        if (!source.exists()) return err("FILE_NOT_FOUND", "源文件或目录不存在: ${source.absolutePath}", "path", source.absolutePath)
        if (source.canonicalPath == target.canonicalPath) return err("INVALID_ARGUMENT", "源路径与目标路径相同", "target", target.absolutePath)
        val overwrite = args.optBoolean("overwrite", false)
        val targetExisted = target.exists()
        if (targetExisted && !overwrite) return err("TARGET_EXISTS", "目标已存在；如需替换请传 overwrite=true", "target", target.absolutePath)
        val dryRun = args.optBoolean("dryRun", true)
        if (dryRun) {
            return ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "rename")
                .put("dryRun", true)
                .put("path", source.absolutePath)
                .put("target", target.absolutePath)
                .put("isDirectory", source.isDirectory)
                .put("files", treeStats(source).first)
                .put("size", treeStats(source).second)
                .put("wouldOverwrite", targetExisted)
                .put("hint", "确认后再次调用并传 dryRun=false 重命名文件"))
        }
        return runCatching {
            target.parentFile?.mkdirs()
            if (source.isDirectory && target.exists() && overwrite) target.deleteRecursively()
            moveReplace(source, target, overwrite)
            ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "rename")
                .put("path", source.absolutePath)
                .put("target", target.absolutePath)
                .put("isDirectory", target.isDirectory)
                .put("size", if (target.isFile) target.length() else 0L)
                .put("overwritten", targetExisted)
                .put("hint", "文件已重命名"))
        }.getOrElse { e -> err("RENAME_FAILED", "重命名失败: ${e.message}", "target", target.absolutePath) }
    }

    /** diff：比对两个文本文件，输出 unified diff 风格变更块（上下文 3 行）。
     *  公共前后缀剥离后，中间段做受预算约束的 LCS；超预算退化为整段替换。 */
    private fun diff(args: JSONObject): JSONObject {
        val source = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        val target = safeFile(args.optString("target")) ?: return err("INVALID_PATH", "target 必须是合法的绝对路径（不含 ..）", "target", args.optString("target"))
        if (!source.isFile) return err("FILE_NOT_FOUND", "源文件不存在: ${source.absolutePath}", "path", source.absolutePath)
        if (!target.isFile) return err("FILE_NOT_FOUND", "目标文件不存在: ${target.absolutePath}", "target", target.absolutePath)
        if (source.canonicalPath == target.canonicalPath) return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "diff")
            .put("path", source.absolutePath)
            .put("target", target.absolutePath)
            .put("identical", true)
            .put("added", 0)
            .put("removed", 0)
            .put("hint", "两个路径指向同一文件"))
        if (source.length() > MAX_DIFF_FILE_BYTES || target.length() > MAX_DIFF_FILE_BYTES) {
            return err("FILE_TOO_LARGE", "diff 支持的文件上限为 ${MAX_DIFF_FILE_BYTES / 1024 / 1024}MiB", "path", source.absolutePath)
        }
        val a = runCatching { source.readLines() }.getOrElse { return err("READ_FAILED", "读取源文件失败: ${it.message}", "path", source.absolutePath) }
        val b = runCatching { target.readLines() }.getOrElse { return err("READ_FAILED", "读取目标文件失败: ${it.message}", "target", target.absolutePath) }
        val ops = diffOps(a, b)
        val context = args.optInt("context", 3).coerceIn(0, 16)
        val hunks = buildHunks(ops, context)
        val added = ops.count { it.op == DiffOp.INSERT }
        val removed = ops.count { it.op == DiffOp.DELETE }
        val rendered = JSONArray()
        for (hunk in hunks) rendered.put(hunk)
        return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "diff")
            .put("path", source.absolutePath)
            .put("target", target.absolutePath)
            .put("identical", added == 0 && removed == 0)
            .put("linesA", a.size)
            .put("linesB", b.size)
            .put("added", added)
            .put("removed", removed)
            .put("hunks", hunks.size)
            .put("diff", rendered)
            .put("hint", if (added == 0 && removed == 0) "两个文件内容一致" else "unified diff：- 为源文件独有，+ 为目标文件独有"))
    }

    /** mkdir：创建目录（含父目录）。已存在且为目录时幂等成功。
     *
     * D10（2026-09-21 自检）：dryRun 缺省 true，与 write/delete/copy/rename/zip/
     * replace 同款契约。此前 mkdir 没有 dryRun 分支，调用方传 dryRun=true 也会
     * 真的落盘——预览契约说一套做一套。预览时只回报"将要创建"的路径。
     */
    private fun mkdir(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        val dryRun = args.optBoolean("dryRun", true)
        if (f.exists()) {
            if (f.isDirectory) return ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "mkdir")
                .put("dryRun", dryRun)
                .put("path", f.absolutePath)
                .put("created", false)
                .put("hint", "目录已存在（幂等成功）"))
            return err("PATH_CONFLICT", "同路径已存在文件（非目录）: ${f.absolutePath}", "path", f.absolutePath)
        }
        if (dryRun) {
            return ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "mkdir")
                .put("dryRun", true)
                .put("path", f.absolutePath)
                .put("created", false)
                .put("wouldCreate", true)
                .put("hint", "预览：目录尚未创建。确认后用同一参数传 dryRun=false 执行。"))
        }
        val created = f.mkdirs()
        if (!created) return err("MKDIR_FAILED", "目录创建失败（权限或路径非法）", "path", f.absolutePath)
        return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "mkdir")
            .put("dryRun", false)
            .put("path", f.absolutePath)
            .put("created", true)
            .put("hint", "目录已创建（含父目录）"))
    }

    private enum class DiffOp { EQUAL, DELETE, INSERT }
    private data class DiffStep(val op: DiffOp, val aLine: Int, val bLine: Int, val text: String)

    /** 剥公共前后缀后做 LCS（预算内），超预算把中间段整块标记为替换。 */
    private fun diffOps(a: List<String>, b: List<String>): List<DiffStep> {
        val steps = ArrayList<DiffStep>()
        var start = 0
        while (start < a.size && start < b.size && a[start] == b[start]) start++
        var endA = a.size
        var endB = b.size
        while (endA > start && endB > start && a[endA - 1] == b[endB - 1]) { endA--; endB-- }
        for (i in 0 until start) steps.add(DiffStep(DiffOp.EQUAL, i, i, a[i]))
        val midA = a.subList(start, endA)
        val midB = b.subList(start, endB)
        val lcsBudget = 4_000_000L
        if (midA.size.toLong() * midB.size > lcsBudget) {
            for (i in midA.indices) steps.add(DiffStep(DiffOp.DELETE, start + i, -1, midA[i]))
            for (j in midB.indices) steps.add(DiffStep(DiffOp.INSERT, -1, start + j, midB[j]))
        } else {
            val lcs = lcsIsCommon(midA, midB)
            var i = 0
            var j = 0
            for (step in lcs) {
                while (i < midA.size && midA[i] != step) { steps.add(DiffStep(DiffOp.DELETE, start + i, -1, midA[i])); i++ }
                while (j < midB.size && midB[j] != step) { steps.add(DiffStep(DiffOp.INSERT, -1, start + j, midB[j])); j++ }
                steps.add(DiffStep(DiffOp.EQUAL, start + i, start + j, step))
                i++; j++
            }
            while (i < midA.size) { steps.add(DiffStep(DiffOp.DELETE, start + i, -1, midA[i])); i++ }
            while (j < midB.size) { steps.add(DiffStep(DiffOp.INSERT, -1, start + j, midB[j])); j++ }
        }
        for (k in endA until a.size) steps.add(DiffStep(DiffOp.EQUAL, k, endB + (k - endA), a[k]))
        return steps
    }

    /** LCS 公共子序列（行级）；空串哨兵行保证唯一比较。 */
    private fun lcsIsCommon(a: List<String>, b: List<String>): List<String> {
        val n = a.size
        val m = b.size
        val dp = Array(n + 1) { IntArray(m + 1) }
        for (i in n - 1 downTo 0) {
            for (j in m - 1 downTo 0) {
                dp[i][j] = if (a[i] == b[j]) dp[i + 1][j + 1] + 1 else maxOf(dp[i + 1][j], dp[i][j + 1])
            }
        }
        val out = ArrayList<String>()
        var i = 0
        var j = 0
        while (i < n && j < m) {
            when {
                a[i] == b[j] -> { out.add(a[i]); i++; j++ }
                dp[i + 1][j] >= dp[i][j + 1] -> i++
                else -> j++
            }
        }
        return out
    }

    /** 把 DiffStep 序列折叠成 unified diff hunks（@@ -a,b +c,d @@ 块）。 */
    private fun buildHunks(steps: List<DiffStep>, context: Int): List<JSONObject> {
        val hunks = ArrayList<JSONObject>()
        var i = 0
        while (i < steps.size) {
            if (steps[i].op == DiffOp.EQUAL) { i++; continue }
            // 变更起点：回退 context 行
            var hunkStart = (i - context).coerceAtLeast(0)
            // 变更终点：吞掉紧邻变更串（间隔 <= 2*context 的合并）
            var hunkEnd = i
            while (hunkEnd < steps.size && steps[hunkEnd].op != DiffOp.EQUAL) hunkEnd++
            while (true) {
                var equalRun = 0
                val probe = hunkEnd
                while (probe + equalRun < steps.size && steps[probe + equalRun].op == DiffOp.EQUAL) equalRun++
                if (probe + equalRun < steps.size && equalRun <= 2 * context) {
                    hunkEnd = probe + equalRun
                    while (hunkEnd < steps.size && steps[hunkEnd].op != DiffOp.EQUAL) hunkEnd++
                } else break
            }
            hunkEnd = (hunkEnd + context).coerceAtMost(steps.size)
            val body = JSONArray()
            var aCount = 0
            var bCount = 0
            var aStart = -1
            var bStart = -1
            for (k in hunkStart until hunkEnd) {
                val s = steps[k]
                val prefix = when (s.op) {
                    DiffOp.EQUAL -> " "
                    DiffOp.DELETE -> "-"
                    DiffOp.INSERT -> "+"
                }
                if (s.op != DiffOp.INSERT) {
                    if (aStart < 0) aStart = s.aLine
                    aCount++
                }
                if (s.op != DiffOp.DELETE) {
                    if (bStart < 0) bStart = s.bLine
                    bCount++
                }
                body.put("$prefix${s.text.take(500)}")
            }
            hunks.add(JSONObject()
                .put("aStart", (aStart.coerceAtLeast(0)) + 1)
                .put("aCount", aCount)
                .put("bStart", (bStart.coerceAtLeast(0)) + 1)
                .put("bCount", bCount)
                .put("lines", body))
            i = hunkEnd
        }
        return hunks
    }

    private fun moveReplace(source: File, target: File, overwrite: Boolean) {
        try {
            val options = if (overwrite) {
                arrayOf(StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } else {
                arrayOf(StandardCopyOption.ATOMIC_MOVE)
            }
            Files.move(source.toPath(), target.toPath(), *options)
        } catch (_: AtomicMoveNotSupportedException) {
            if (overwrite) {
                Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            } else {
                Files.move(source.toPath(), target.toPath())
            }
        }
    }

    private fun treeStats(root: File): Pair<Int, Long> {
        if (root.isFile) return 1 to root.length()
        var files = 0
        var bytes = 0L
        root.walkTopDown().forEach { item ->
            if (item.isFile) {
                files++
                bytes += item.length()
            }
        }
        return files to bytes
    }

    private fun copyDirectory(source: File, target: File) {
        source.walkTopDown().forEach { item ->
            val relative = source.toPath().relativize(item.toPath()).toString()
            val destination = if (relative.isEmpty()) target else File(target, relative)
            if (item.isDirectory) destination.mkdirs()
            else {
                destination.parentFile?.mkdirs()
                item.inputStream().use { input -> destination.outputStream().use { input.copyTo(it) } }
            }
        }
    }

    private fun zip(args: JSONObject): JSONObject {
        val src = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        if (!src.exists()) return err("FILE_NOT_FOUND", "不存在: ${src.absolutePath}", "path", src.absolutePath)
        val outputRaw = args.optString("output")
        val output = if (outputRaw.isNotBlank()) {
            safeFile(outputRaw) ?: return err("INVALID_PATH", "output 必须是合法的绝对路径", "output", outputRaw)
        } else {
            File(src.parentFile, "${src.nameWithoutExtension}.zip")
        }
        if (args.optBoolean("dryRun", true)) {
            return ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "zip")
                .put("dryRun", true)
                .put("path", src.absolutePath)
                .put("output", output.absolutePath)
                .put("hint", "确认后压缩（目录递归打包）"))
        }
        return runCatching {
            var entryCount = 0
            var totalBytes = 0L
            ZipOutputStream(output.outputStream()).use { zos ->
                if (src.isFile) {
                    entryCount = 1
                    totalBytes = src.length()
                    checkZipBudget(entryCount, totalBytes)
                    zos.putNextEntry(ZipEntry(src.name))
                    src.inputStream().use { it.copyTo(zos) }
                    zos.closeEntry()
                } else {
                    val base = src.parentFile ?: src
                    val outputPath = runCatching { output.canonicalPath }
                        .getOrDefault(output.absolutePath)
                    // 排除输出包自身（2026-10-03 报告 F-22：输出落在 src 树内时
                    // 会把自己的写入快照收进归档，产生截断的自包含条目）。
                    src.walkTopDown().filter { it.isFile }.forEach { f ->
                        val candidate = runCatching { f.canonicalPath }
                            .getOrDefault(f.absolutePath)
                        if (candidate == outputPath) return@forEach
                        entryCount++
                        totalBytes += f.length()
                        checkZipBudget(entryCount, totalBytes)
                        val rel = base.toPath().relativize(f.toPath()).toString()
                        zos.putNextEntry(ZipEntry(rel))
                        f.inputStream().use { it.copyTo(zos) }
                        zos.closeEntry()
                    }
                }
            }
            ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "zip")
                .put("output", output.absolutePath)
                .put("entries", entryCount)
                .put("size", output.length())
                .put("hint", "压缩完成，产物在输出路径"))
        }.getOrElse { e -> err("ZIP_FAILED", "压缩失败: ${e.message}", "path", src.absolutePath) }
    }

    /** 循环读取至多 maxBytes（流不足时返回实际读到的长度），兼容低 API 无 readNBytes。 */
    private fun readExactly(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val buffer = ByteArray(maxBytes)
        var filled = 0
        while (filled < maxBytes) {
            val n = input.read(buffer, filled, maxBytes - filled)
            if (n <= 0) break
            filled += n
        }
        return if (filled == maxBytes) buffer else buffer.copyOf(filled)
    }

    /** zip 预算：与解压同限（5000 条目 / 256MB），防止超大目录失控。 */
    private fun checkZipBudget(entries: Int, totalBytes: Long) {
        if (entries > MAX_UNZIP_ENTRIES) throw IllegalStateException("压缩条目超过 $MAX_UNZIP_ENTRIES 上限")
        if (totalBytes > MAX_UNZIP_TOTAL) throw IllegalStateException("压缩总量超过 ${MAX_UNZIP_TOTAL / 1024 / 1024}MiB 上限")
    }

    private fun unzip(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        if (!f.isFile) return err("FILE_NOT_FOUND", "zip 不存在: ${f.absolutePath}", "path", f.absolutePath)
        val destRaw = args.optString("outputDir")
        val dest = if (destRaw.isNotBlank()) {
            safeFile(destRaw) ?: return err("INVALID_PATH", "outputDir 必须是合法的绝对路径", "outputDir", destRaw)
        } else {
            File(f.parentFile, f.nameWithoutExtension)
        }
        if (args.optBoolean("dryRun", true)) {
            return ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "unzip")
                .put("dryRun", true)
                .put("path", f.absolutePath)
                .put("outputDir", dest.absolutePath)
                .put("hint", "确认后解压（zip-slip 防护 + 5000 条目/256MB 限制）"))
        }
        // v10-N1（2026-10-05 v11 复测）：目录里出现过「.md.zip 内容是 Markdown 正文」
        // 的假 zip（与 .md 同 sha256——典型的改名复制，非本工具产物：本工具一律走
        // ZipOutputStream，不可能写出纯文本）。这里按容器魔数硬校验，把
        // ZipException 之类的模糊报错提前成一句能自解释的拒绝。
        val magic = ByteArray(4)
        val magicRead = runCatching {
            f.inputStream().use { input -> input.read(magic) }
        }.getOrDefault(0)
        val isZipMagic = magicRead == 4 &&
            magic[0] == 0x50.toByte() && magic[1] == 0x4B.toByte() &&
            (magic[2] == 0x03.toByte() || magic[2] == 0x05.toByte() || magic[2] == 0x07.toByte())
        if (!isZipMagic) {
            return err(
                "INVALID_ZIP",
                "不是 zip 容器（缺 PK 魔数）：${f.absolutePath}。这通常是**改名复制**的文件"
                    + "（例如把 .md/.apk 直接复制成 .zip）——请核对来源文件名与内容；"
                    + "本工具的 zip 产物一律是标准 PK 压缩包，不会产出这种副本。",
                "path", f.absolutePath,
            )
        }
        return runCatching {
            var total = 0L
            var count = 0
            ApkZipCache.shared.withZip(f) { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    count++
                    if (count > MAX_UNZIP_ENTRIES) throw IllegalStateException("解压条目超过 $MAX_UNZIP_ENTRIES 上限")
                    total += entry.size
                    if (total > MAX_UNZIP_TOTAL) throw IllegalStateException("解压总量超过 ${MAX_UNZIP_TOTAL / 1024 / 1024}MiB 上限")
                    // zip-slip 防护
                    val name = entry.name.replace('\\', '/')
                    if (name.startsWith("/") || name.split('/').contains("..")) throw IllegalStateException("zip 包含非法路径: $name")
                    val outFile = File(dest, name)
                    outFile.parentFile?.mkdirs()
                    zip.getInputStream(entry).use { input -> outFile.outputStream().use { input.copyTo(it) } }
                }
            }
            ok(JSONObject()
                .put("tool", "file_ops")
                .put("action", "unzip")
                .put("outputDir", dest.absolutePath)
                .put("extracted", count)
                .put("size", total)
                .put("hint", "解压完成，文件在 outputDir"))
        }.getOrElse { e ->
            if (e is IllegalStateException) err("UNZIP_REJECTED", e.message ?: "解压被拒绝", "path", f.absolutePath)
            else err("UNZIP_FAILED", "解压失败: ${e.message}", "path", f.absolutePath)
        }
    }

    /** grep：在文件或目录（递归文本文件）中按正则搜内容，返回 文件:行号:命中行。 */
    private fun grep(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        if (!f.exists()) return err("FILE_NOT_FOUND", "路径不存在: ${f.absolutePath}", "path", f.absolutePath)
        val pattern = args.optString("pattern").trim()
        if (pattern.isEmpty()) return err("PATTERN_REQUIRED", "pattern 是必填的正则表达式", "pattern", "")
        val regex = runCatching { Regex(pattern) }.getOrElse { return err("PATTERN_INVALID", "正则无效: ${it.message}", "pattern", pattern) }
        val maxResults = args.optInt("limit", 200).coerceIn(1, 1000)
        val includes = extensionFilter(args)
        // 大参考账本（Blutter pp.txt / objs.txt 这类）常常超过默认上限，或被文本
        // 探测判成"非文本"（前 4096 字节里出现 NUL 即弃）。这两条路过去都静默
        // 变成 0 命中，调用方读成"这个串没有被引用"——2026-09-21 真机复盘的
        // 最危险一条缺陷。现在：默认上限放宽到 512MB，并允许显式 forceText
        // 跳过探测；无论如何，被跳过的文件都会逐条列出来。
        // 报告 2-2：这里过去是 coerceIn(1024L, …)，调用方传 5 会被静默抬到 1024，
        // 「参数无效但没人告诉调用方」。现在只兜底非正值（下限 1），并把**实际生效值**
        // 回传，参数与行为不再对不上。
        val maxFileBytesRequested = args.optLong("maxFileBytes", MAX_GREP_FILE_BYTES)
        val maxFileBytes = maxFileBytesRequested.coerceIn(1L, MAX_GREP_FILE_BYTES_CEILING)
        val forceText = args.optBoolean("forceText", false)
        val collected = collectTextFiles(f, includes, maxFileBytes, forceText)
            ?: return err("TOO_MANY_FILES", "目录文本文件超过 $MAX_GREP_FILES 上限，请缩小范围", "path", f.absolutePath)
        val targets = collected.files
        val matches = JSONArray()
        var truncated = false
        var total = 0
        for (file in targets) {
            file.useLines { lines ->
                var lineNo = 0
                for (raw in lines) {
                    lineNo++
                    if (!regex.containsMatchIn(raw)) continue
                    total++
                    if (matches.length() < maxResults) {
                        matches.put(JSONObject()
                            .put("file", file.absolutePath)
                            .put("line", lineNo)
                            .put("text", raw.trim().take(300)))
                    } else if (!truncated) {
                        truncated = true
                        return@useLines
                    }
                }
            }
            if (truncated) break
        }
        val skipped = JSONArray()
        collected.skipped.take(20).forEach { item ->
            skipped.put(JSONObject()
                .put("path", item.path)
                .put("reason", item.reason)
                .put("bytes", item.bytes))
        }
        // searchPerformed 是给调用方判"负结论能不能用"的开关：false 表示一个文件
        // 都没真正读过，此时 count=0 不能当成"没有命中"的证据。
        val performed = targets.isNotEmpty()
        val hint = when {
            truncated -> "命中超 limit 已截断"
            !performed && collected.skipped.isNotEmpty() ->
                "没有任何文件被真正搜索（全部被跳过）：count=0 不是'没有命中'的证据。看 skipped[] 的原因——size_exceeds_limit 可提高 maxFileBytes 重试，non_text_or_binary 可加 forceText=true 重试。"
            !performed -> "路径下没有可搜索的文本文件：count=0 不是'没有命中'的证据。"
            collected.skipped.isNotEmpty() ->
                "${collected.skipped.size} 个文件被跳过（见 skipped[]），本次命中只来自其余 ${targets.size} 个文件。"
            else -> ""
        }
        return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "grep")
            .put("path", f.absolutePath)
            .put("pattern", pattern)
            .put("files", targets.size)
            .put("searchPerformed", performed)
            .put("skippedBySize", collected.skippedBySize)
            .put("skippedNonText", collected.skippedNonText)
            .put("skippedByInclude", collected.skippedByInclude)
            // 报告 2-3：skippedTotal 过去等于**账本长度**（还会被 200 截断），
            // 而 skippedByInclude 只计数不入账，于是 skippedTotal < 各分项之和，
            // 调用方按 skippedTotal 判断覆盖率会漏判。现在：
            //   skippedTotal = 三类跳过的真实总数
            //   skippedListed = 本次真正返回的账本条目数（≤200 截断）
            .put(
                "skippedTotal",
                collected.skippedBySize + collected.skippedNonText + collected.skippedByInclude,
            )
            .put("skippedListed", skipped.length())
            .put("skippedTruncated", collected.skipped.size > skipped.length())
            .put("effectiveMaxFileBytes", maxFileBytes)
            .put("maxFileBytesRequested", maxFileBytesRequested)
            .put("skipped", skipped)
            .put("count", total)
            .put("returned", matches.length())
            .put("truncated", truncated)
            .put("matches", matches)
            .put("hint", hint)
            .put("nextActions", if (!performed && collected.skipped.isNotEmpty())
                JSONArray()
                    .put("提高 maxFileBytes 或加 forceText=true 重试同一 pattern")
                    .put("这是 Blutter 产物时优先用 so_analyze(action=blutter, blutterAction=pool) 按池偏移取原文")
                else JSONArray()))
    }

    /** replace：文件或目录（递归）内按正则替换文本内容；dryRun=false 直接执行（工作目录内文件级操作）。 */
    private fun replace(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        if (!f.exists()) return err("FILE_NOT_FOUND", "路径不存在: ${f.absolutePath}", "path", f.absolutePath)
        val find = args.optString("find").trim()
        if (find.isEmpty()) return err("FIND_REQUIRED", "find 是必填的正则表达式", "find", "")
        val regex = runCatching { Regex(find) }.getOrElse { return err("FIND_INVALID", "find 正则无效: ${it.message}", "find", find) }
        val replacement = args.optString("replacement")
        val dryRun = args.optBoolean("dryRun", false)
        val includes = extensionFilter(args)
        val targets = collectTextFiles(f, includes, MAX_REPLACE_FILE_BYTES)?.files ?: return err("TOO_MANY_FILES", "目录文本文件超过 $MAX_GREP_FILES 上限，请缩小范围", "path", f.absolutePath)
        val changed = JSONArray()
        var totalReplacements = 0
        for (file in targets) {
            val content = file.readText()
            var count = 0
            val updated = regex.replace(content) { count++; replacement }
            if (count == 0) continue
            totalReplacements += count
            if (!dryRun) file.writeText(updated)
            changed.put(JSONObject()
                .put("file", file.absolutePath)
                .put("replacements", count))
            if (changed.length() >= 200) break
        }
        return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "replace")
            .put("dryRun", dryRun)
            .put("path", f.absolutePath)
            .put("find", find)
            .put("filesScanned", targets.size)
            .put("filesChanged", changed.length())
            .put("totalReplacements", totalReplacements)
            .put("changed", changed)
            .put("hint", if (dryRun) "dryRun 预览，确认后传 dryRun=false 执行" else "替换已完成"))
    }

    /** 从二进制文件提取 UTF-8/UTF-16 字符串，适用于 AndroidManifest.xml 与 resources.arsc 字符串池。 */
    private fun strings(args: JSONObject): JSONObject {
        val f = safeFile(args.optString("path")) ?: return err("INVALID_PATH", "path 必须是合法的绝对路径（不含 ..）", "path", args.optString("path"))
        if (!f.isFile) return err("FILE_NOT_FOUND", "文件不存在: ${f.absolutePath}", "path", f.absolutePath)
        if (f.length() > MAX_STRINGS_FILE_BYTES) return err("FILE_TOO_LARGE", "strings 支持的文件上限为 ${MAX_STRINGS_FILE_BYTES / 1024 / 1024}MiB", "path", f.absolutePath)
        val encoding = args.optString("encoding", "auto").lowercase()
        if (encoding !in setOf("auto", "utf8", "utf16le", "utf16be")) {
            return err("INVALID_ARGUMENT", "encoding 仅支持 auto/utf8/utf16le/utf16be", "encoding", encoding)
        }
        val query = args.optString("query").trim().lowercase()
        val minLength = args.optInt("minLength", 3).coerceIn(1, 256)
        val limit = args.optInt("limit", 500).coerceIn(1, 2000)
        val bytes = f.readBytes()
        val matches = LinkedHashMap<String, String>()
        // 目标是压缩容器（APK/ZIP/JAR/AAR）时扫的是**压缩字节**，随机段拼出的
        // 伪字符串是纯噪音——在通用质量闸之上再加「ASCII 纯度」闸（v14 复测：
        // 60%/3 连仍放过夹少量非 ASCII 的乱码 sMҞTX+cvH、JԤ>MiCgzҟa 一类）。
        // 普通文本文件不加这道闸：中文/其它语言的正常字符串必须能扫出来。
        val containerScan = listOf(".apk", ".zip", ".jar", ".aar").any {
            f.name.endsWith(it, ignoreCase = true)
        }
        // 可打印判定（2026-10-03 报告 F-21）：控制符之外还过滤替代符、代理区与
        // 私用区——`auto` 对任意二进制盲跑 UTF-16 解码时，错位字节会成片解出
        // 私用区/孤立半代理「伪字符串」，全是噪音。
        fun isNoise(character: Char): Boolean {
            if (character == '�' || character.isISOControl()) return true
            val code = character.code
            if (code in 0xE000..0xF8FF) return true            // 私用区
            if (code in 0xD800..0xDFFF) return true            // 未配对的代理
            return false
        }
        fun collect(source: String, charset: java.nio.charset.Charset) {
            val text = bytes.toString(charset)
            val current = StringBuilder()
            fun flush() {
                val value = current.toString().trim()
                current.setLength(0)
                if (value.length < minLength || (query.isNotEmpty() && !value.lowercase().contains(query))) return
                // F-21/v9 复测（2026-10-05）：文本质量闸——字母数字占比 ≥60%
                // 且至少含一段 3 连字母数字。压缩/加密段的随机字节能拼出全可打印
                // 乱码（"u\"]3{{GΊ"、"sMҞTX+cvH"），长度、噪声过滤与 40% 阈值都
                // 拦不住；v13 复测把阈值从 40%/2 连提到 60%/3 连。
                val alnum = value.count { it.isLetterOrDigit() }
                if (alnum * 10 < value.length * 6) return
                var run = 0
                var maxRun = 0
                for (character in value) {
                    if (character.isLetterOrDigit()) {
                        run++
                        if (run > maxRun) maxRun = run
                    } else {
                        run = 0
                    }
                }
                if (maxRun < 3) return
                // 容器盲扫再要求 ASCII 纯度 + 4 连小写字母：v14 漏网的是夹非 ASCII
                // 的乱码；v16 复测剩下的全是**纯可打印 ASCII 的随机串**
                // （oHGF~ /a、G(UhDkz0、0COIDzJR…）——真实字符串（META-INF/… 路径、
                // 类名、属性键）几乎都含 4 连小写字母，随机混合大小写串极少凑出。
                if (containerScan) {
                    val nonAscii = value.count { it.code > 0x7E }
                    if (nonAscii * 10 > value.length) return
                    var lowerRun = 0
                    var maxLowerRun = 0
                    for (character in value) {
                        if (character in 'a'..'z') {
                            lowerRun++
                            if (lowerRun > maxLowerRun) maxLowerRun = lowerRun
                        } else {
                            lowerRun = 0
                        }
                    }
                    if (maxLowerRun < 4) return
                }
                matches.putIfAbsent(value, source)
            }
            for (character in text) {
                if (!isNoise(character)) current.append(character) else flush()
            }
            flush()
        }
        if (encoding == "auto" || encoding == "utf8") collect("utf8", Charsets.UTF_8)
        // auto 只在**有对应 BOM** 时才跑 UTF-16 解码：无 BOM 的盲跑是噪音主源；
        // 真要宽字符内容就显式传 encoding=utf16le/utf16be。
        val hasUtf16LeBom = bytes.size >= 2 &&
            bytes[0] == 0xFF.toByte() && bytes[1] == 0xFE.toByte()
        val hasUtf16BeBom = bytes.size >= 2 &&
            bytes[0] == 0xFE.toByte() && bytes[1] == 0xFF.toByte()
        if (encoding == "utf16le" || (encoding == "auto" && hasUtf16LeBom)) {
            collect("utf16le", Charsets.UTF_16LE)
        }
        if (encoding == "utf16be" || (encoding == "auto" && hasUtf16BeBom)) {
            collect("utf16be", Charsets.UTF_16BE)
        }
        val output = JSONArray()
        for ((value, source) in matches.entries.take(limit)) {
            output.put(JSONObject().put("encoding", source).put("text", value.take(2000)))
        }
        return ok(JSONObject()
            .put("tool", "file_ops")
            .put("action", "strings")
            .put("path", f.absolutePath)
            .put("size", f.length())
            .put("query", query)
            .put("count", matches.size)
            .put("returned", output.length())
            .put("truncated", matches.size > output.length())
            // F-21（v11 复测）：质量闸的自述——审计要能看出"低置信条目已过滤"，
            // 而不是以为工具把乱码当字符串照单全收。
            .put(
                "qualityGate",
                "已过滤：字母数字占比 <60% 或缺 3 连字母数字的串不返回；压缩容器盲扫再要求"
                    + "非 ASCII ≤10% 且含 4 连小写字母（随机字节拼出的乱码）。文本文件"
                    + "不设容器闸，中文等非 ASCII 正常字符串照常返回。",
            )
            // F-21/v9：对 APK/压缩包整包盲扫的是**压缩字节**——扫出的"串"大多
            // 无意义。指路 apk_archive(strings, entry=...)（解压后逐条目提取）。
            .put(
                "note",
                if (f.name.endsWith(".apk", true) || f.name.endsWith(".zip", true) ||
                    f.name.endsWith(".jar", true) || f.name.endsWith(".aar", true))
                    "目标是压缩容器：扫到的是压缩后的字节，串可信度低。提取真实字符串请用 "
                        + "apk_archive(action=strings, entry=<容器内条目>) 逐条目解压后扫描。"
                else JSONObject.NULL,
            )
            .put("strings", output))
    }

    /** collectTextFiles 的产出：真正会搜的文件 + 被跳过的文件及原因。 */
    private data class SkippedFile(val path: String, val reason: String, val bytes: Long)

    private class CollectedFiles(
        val files: List<File>,
        val skipped: List<SkippedFile>,
        val skippedBySize: Int,
        val skippedNonText: Int,
        val skippedByInclude: Int,
    )

    /**
     * 递归收集文本文件（二进制按采样探测跳过）；超上限返回 null。
     *
     * 被跳过的文件一律记进 skipped[]——过去这里是三处裸 return@forEach，
     * 跳过了什么都不说，调用方只看到 files:0 / count:0，等于把"我没搜"伪装成
     * "搜了没有"。forceText=true 时跳过文本探测（大账本文件含 NUL 时用）。
     */
    private fun collectTextFiles(root: File, includes: Set<String>?, maxFileBytes: Long, forceText: Boolean = false): CollectedFiles? {
        val skipped = ArrayList<SkippedFile>()
        var bySize = 0
        var nonText = 0
        var byInclude = 0
        fun accept(file: File): Boolean {
            if (file.length() > maxFileBytes) { bySize++; skipped += SkippedFile(file.absolutePath, "size_exceeds_limit", file.length()); return false }
            if (includes != null && !includes.contains(file.extension.lowercase())) { byInclude++; skipped += SkippedFile(file.absolutePath, "not_in_include_filter", file.length()); return false }
            if (!forceText && !isTextFile(file)) { nonText++; skipped += SkippedFile(file.absolutePath, "non_text_or_binary", file.length()); return false }
            return true
        }
        if (root.isFile) {
            val files = if (accept(root)) listOf(root) else emptyList()
            return CollectedFiles(files, skipped, bySize, nonText, byInclude)
        }
        val found = ArrayList<File>()
        root.walkTopDown().forEach { file ->
            if (!file.isFile) return@forEach
            if (file.length() > maxFileBytes) { bySize++; if (skipped.size < 200) skipped += SkippedFile(file.absolutePath, "size_exceeds_limit", file.length()); return@forEach }
            if (includes != null && !includes.contains(file.extension.lowercase())) {
                byInclude++
                // 报告 2-3：这里过去只加计数不记账，skipped[] 与 skippedByInclude 对不上。
                if (skipped.size < 200) skipped += SkippedFile(file.absolutePath, "not_in_include_filter", file.length())
                return@forEach
            }
            if (!forceText && !isTextFile(file)) { nonText++; if (skipped.size < 200) skipped += SkippedFile(file.absolutePath, "non_text_or_binary", file.length()); return@forEach }
            if (found.size >= MAX_GREP_FILES) return null
            found.add(file)
        }
        return CollectedFiles(found, skipped, bySize, nonText, byInclude)
    }

    private fun isTextFile(file: File): Boolean {
        val sample = file.inputStream().use { readExactly(it, minOf(4096, file.length().toInt().coerceAtLeast(1))) }
        if (sample.isEmpty()) return false
        val nul = sample.count { it == 0.toByte() }
        if (nul > 0) return false
        val printable = sample.count { (it.toInt() and 0xff) in 0x09..0x0d || (it.toInt() and 0xff) in 0x20..0x7e || it.toInt() and 0xff >= 0x80 }
        return printable >= sample.size * 95 / 100
    }

    /** include 参数：逗号分隔扩展名（无点），如 "dart,java,xml"；空则不过滤。 */
    private fun extensionFilter(args: JSONObject): Set<String>? =
        args.optString("include").trim().takeIf { it.isNotEmpty() }?.split(',')?.map { it.trim().removePrefix(".").lowercase() }?.filter { it.isNotEmpty() }?.toSet()
}
