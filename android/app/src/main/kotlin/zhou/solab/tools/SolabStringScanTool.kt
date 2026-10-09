package zhou.solab.tools

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream

/**
 * A9: 敏感信息扫描（移植自玄星逆核 StringScanTool.kt，纯 Kotlin 零依赖）。
 *
 * URL/IP/邮箱/JWT/私钥/云 AK-SK(AWS/Google/阿里云)/密钥字段 9 类正则；
 * APK/ZIP 逐条目扫描，单条目 >32MB 跳过。
 */
object SolabStringScanTool {

    private const val SCAN_CACHE_MAX = 8
    private val scanCache = object : LinkedHashMap<String, String>(SCAN_CACHE_MAX, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean =
            size > SCAN_CACHE_MAX
    }

    /** 一次"原始命中"：值 + 来源条目 + 所在文本段长度（段长用于按 minLen 复筛）。 */
    internal data class RawHit(val entry: String, val value: String, val runLength: Int)

    internal data class RawScan(
        val scannedEntries: Int,
        /** F-49：包内非目录条目总数与三类跳过计数（覆盖报账）。 */
        val totalEntries: Int,
        val skippedByExtension: Int,
        val skippedOversize: Int,
        val skippedErrors: Int,
        /** 类别 → 去重命中（保持首次发现顺序 = 结果顺序）。 */
        val byCategory: Map<String, List<RawHit>>,
    )

    /** 原始命中缓存：键 = 指纹 + includePrivate（噪音口径），最多留 2 个产物。 */
    private val rawScanCache = object : LinkedHashMap<String, RawScan>(2, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, RawScan>?): Boolean =
            size > 2
    }

    /** 原始扫描口径：最宽（minLen 最小、全类别、上限拉满），复筛只做内存过滤。 */
    private const val RAW_MIN_LEN = 3
    private const val RAW_LIMIT = 5000

    /**
     * 按**最宽口径**扫一遍，把逐类命中连"所在文本段长度"一起留下（供复筛）。
     * 返回 null 表示文件超限（与旧的 FILE_TOO_LARGE 分支同义）。
     */
    internal fun buildRawScan(input: File, includePrivate: Boolean): RawScan? {
        val found = LinkedHashMap<String, LinkedHashMap<String, RawHit>>()
        patterns.forEach { found[it.first] = LinkedHashMap() }
        var scannedEntries = 0
        val maxBytesPerEntry = 32L * 1024 * 1024

        fun scanValue(s: String, entryName: String, runLength: Int) {
            for ((cat, re) in patterns) {
                val set = found[cat] ?: continue
                val anchorsForCat = anchors[cat].orEmpty()
                if (anchorsForCat.isNotEmpty() &&
                    anchorsForCat.none { s.contains(it, ignoreCase = true) }
                ) {
                    continue
                }
                re.findAll(s).forEach { m ->
                    if (set.size >= RAW_LIMIT) return@forEach
                    val noise = (cat == "ip" && isNoiseIp(m.value, includePrivate)) ||
                        (cat == "url" && isNoiseUrl(m.value)) ||
                        (cat == "email" && isNoiseEmail(m.value))
                    val value = m.value.take(300)
                    // 按值去重；只记首次发现（locations 与 values 一一对应，与旧实现一致）
                    if (!noise && !set.containsKey(value)) {
                        set[value] = RawHit(entryName, value, runLength)
                    }
                }
            }
        }

        fun scanInput(stream: InputStream, entryName: String) {
            val bytes = ByteArray(64 * 1024)
            val text = StringBuilder(8192)
            fun flush(keepTail: Boolean) {
                if (text.length >= RAW_MIN_LEN) scanValue(text.toString(), entryName, text.length)
                if (keepTail) {
                    val tail = text.takeLast(512)
                    text.setLength(0)
                    text.append(tail)
                } else {
                    text.setLength(0)
                }
            }
            while (true) {
                val count = stream.read(bytes)
                if (count < 0) break
                for (index in 0 until count) {
                    val value = bytes[index].toInt() and 0xFF
                    if (value in 0x20..0x7E) {
                        text.append(value.toChar())
                        if (text.length >= 8192) flush(keepTail = true)
                    } else if (text.isNotEmpty()) {
                        flush(keepTail = false)
                    }
                }
            }
            if (text.isNotEmpty()) flush(keepTail = false)
        }

        val isZip = input.name.endsWith(".apk", true) || input.name.endsWith(".jar", true) ||
            input.name.endsWith(".aar", true) || input.name.endsWith(".zip", true) ||
            input.name.endsWith(".xapk", true) || input.name.endsWith(".apks", true)

        // F-49（2026-10-04）：覆盖报账——每类跳过都计数并在回执里声明。
        // 旧回执只给 scannedEntries（真机 v8 D14：330 vs 包内 611 文件，差额
        // 无痕消失），零命中时读不出「没扫到」还是「没扫这部分」。
        var totalEntries = 0
        var skippedByExtension = 0
        var skippedOversize = 0
        var skippedErrors = 0

        if (isZip) {
            ApkZipCache.shared.withZip(input) { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    if (e.isDirectory) continue
                    totalEntries++
                    if (!shouldScanEntry(e.name)) {
                        skippedByExtension++
                        continue
                    }
                    if (e.size > maxBytesPerEntry) {
                        skippedOversize++
                        continue
                    }
                    runCatching {
                        zip.getInputStream(e).use { scanInput(it, e.name) }
                        scannedEntries++
                    }.onFailure { skippedErrors++ }
                }
            }
        } else {
            totalEntries = 1
            if (input.length() > maxBytesPerEntry) return null
            input.inputStream().use { scanInput(it, input.name) }
            scannedEntries = 1
        }

        return RawScan(
            scannedEntries = scannedEntries,
            totalEntries = totalEntries,
            skippedByExtension = skippedByExtension,
            skippedOversize = skippedOversize,
            skippedErrors = skippedErrors,
            byCategory = found.mapValues { (_, map) -> map.values.toList() },
        )
    }

    private val skippedArchiveExtensions = setOf(
        "png", "jpg", "jpeg", "webp", "gif", "bmp", "ico",
        "mp3", "mp4", "m4a", "aac", "wav", "ogg", "flac", "webm",
        "ttf", "otf", "woff", "woff2",
    )

    internal fun shouldScanEntry(name: String): Boolean {
        val extension = name.substringAfterLast('.', "").lowercase()
        return extension !in skippedArchiveExtensions
    }

    // 每个正则的稳定字面锚点（预筛用：不含锚点的字符串直接跳过正则匹配，提速数倍）
    private val anchors: Map<String, List<String>> = mapOf(
        "url" to listOf("http"),
        "ip" to listOf("."),
        "email" to listOf("@"),
        "jwt" to listOf("eyJ"),
        "private_key" to listOf("-----BEGIN"),
        "aws_ak" to listOf("AKIA"),
        "google_api" to listOf("AIza"),
        "aliyun_ak" to listOf("LTAI"),
        "secret_field" to listOf("=", ":", "'", "\""),
    )

    // 敏感模式(类别 → 正则)
    private val patterns: List<Pair<String, Regex>> = listOf(
        "url" to Regex("""https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+""", RegexOption.IGNORE_CASE),
        "ip" to Regex("""\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"""),
        "email" to Regex("""[\w.+\-]+@[\w\-]+\.[\w\-.]+"""),
        "jwt" to Regex("""eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"""),
        "private_key" to Regex("""-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"""),
        "aws_ak" to Regex("""AKIA[0-9A-Z]{16}"""),
        "google_api" to Regex("""AIza[0-9A-Za-z_\-]{35}"""),
        "aliyun_ak" to Regex("""LTAI[0-9A-Za-z]{12,22}"""),
        // 收紧：键后必须紧跟 = 或 :（可夹引号/空白），排除"password your_text_here"式纯文案误报
        "secret_field" to Regex("""(?i)(?:api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key|app[_-]?secret|private[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9_\-./+=]{6,}"""),
    )

    /**
     * email 噪音过滤（2026-09-19 全量复测 DEF-15）：Flutter/Dart AOT 的符号
     * 形如 `_GrowableList@0150898._literal`、`p@A.1`，旧正则把它们当邮箱，
     * 「扫描结论可不可信」因此打折。规则：
     * - TLD 必须是 2..24 位纯字母（排除 `@A.1` 这类数字结尾）；
     * - @ 前的主体与域名首段都必须含字母（排除纯数字域 `@0150898`）。
     */
    internal fun isNoiseEmail(value: String): Boolean {
        val at = value.lastIndexOf('@')
        if (at <= 0 || at == value.length - 1) return true
        val local = value.substring(0, at)
        if (local.none { it.isLetter() }) return true
        val domain = value.substring(at + 1)
        val host = domain.substringBefore('.')
        if (host.isEmpty() || host.none { it.isLetter() }) return true
        val tld = domain.substringAfterLast('.', "")
        if (tld.length !in 2..24 || !tld.all { it.isLetter() }) return true
        return false
    }

    /** ip 噪音过滤：本地回环/未指定/广播/链路本地地址恒排除；私网段默认排除（includePrivate=true 保留）。 */
    private fun isNoiseIp(ip: String, includePrivate: Boolean): Boolean {
        val seg = ip.split('.').map { it.toInt() }
        if (seg[0] == 0 || seg[0] == 127 || seg[0] == 255) return true          // 0.x / 127.x / 255.x（含 0.0.0.0、255.255.255.255）
        if (seg[0] == 169 && seg[1] == 254) return true                          // 链路本地
        if (!includePrivate) {
            if (seg[0] == 10) return true                                       // 10.0.0.0/8
            if (seg[0] == 192 && seg[1] == 168) return true                     // 192.168.0.0/16
            if (seg[0] == 172 && seg[1] in 16..31) return true                  // 172.16.0.0/12
        }
        return false
    }

    /** url 噪音过滤：主机名缺有效点分结构（如 "https://x" 这类截断片段）排除。
     *  保留 localhost 与 IP 字面量主机；TLD 须为 >=2 位纯字母。 */
    private fun isNoiseUrl(url: String): Boolean {
        val host = url.substringAfter("://", "").lowercase()
            .substringBefore('/').substringBefore('?').substringBefore('#')
            .substringBefore(':')
        if (host.isEmpty()) return true
        if (host == "localhost" || host.endsWith(".localhost")) return false
        if (host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))) return false // IP 主机保留
        if (!host.contains('.')) return true // 无点主机（https://x）= 截断/占位片段
        val tld = host.substringAfterLast('.')
        return tld.length < 2 || !tld.all { it.isLetter() } // TLD 过短或含非字母 = 截断
    }

    private fun fingerprint(input: File): String =
        listOf(input.absolutePath, input.length(), input.lastModified()).joinToString("|")

    fun handle(context: Context, args: JSONObject): JSONObject {
        val (input, inputErr) = resolveInputFile(args)
        if (inputErr != null) return inputErr
        val inputPath = input!!.absolutePath

        val minLen = args.intValue("minLen", 5).coerceIn(3, 64)
        val limit = args.intValue("limit", 100).coerceIn(1, 5000)
        val onlyCat = args.str("category", "all").ifBlank { "all" }
        val includePrivate = args.optBoolean("includePrivate", false)
        val activePatterns = if (onlyCat == "all") patterns else patterns.filter { it.first == onlyCat }
        if (activePatterns.isEmpty()) return err("INVALID_ARGUMENT", "未知 category: $onlyCat", "category", onlyCat)

        val cacheKey = listOf(
            input.absolutePath,
            input.length(),
            input.lastModified(),
            minLen,
            limit,
            onlyCat,
            includePrivate,
        ).joinToString("|")
        synchronized(scanCache) {
            scanCache[cacheKey]?.let { cached ->
                return JSONObject(cached).put("cache", "hit").put("elapsedMs", 0)
            }
        }

        return runCatching {
            val startedAt = System.nanoTime()
            // 原始命中（按指纹缓存，最宽口径一次扫完）：换 category/minLen/limit 只做内存复筛，
            // 不再重扫整包（真机实测 4.7s → 毫秒级）。
            val rawKey = "${fingerprint(input)}|$includePrivate"
            val cachedRaw = synchronized(rawScanCache) { rawScanCache[rawKey] }
            val raw = cachedRaw ?: run {
                val built = buildRawScan(input, includePrivate)
                    ?: return@runCatching err("FILE_TOO_LARGE", "文件超过 32MB 扫描上限", "path", inputPath)
                synchronized(rawScanCache) { rawScanCache[rawKey] = built }
                built
            }

            val cats = JSONObject()
            val locationJson = JSONObject()
            var totalHits = 0
            for ((cat, _) in activePatterns) {
                val taken = ArrayList<RawHit>()
                for (hit in raw.byCategory[cat].orEmpty()) {
                    if (hit.runLength < minLen) continue
                    if (taken.size >= limit) break
                    taken.add(hit)
                }
                if (taken.isEmpty()) continue
                cats.put(cat, JSONArray(taken.map { it.value }))
                locationJson.put(
                    cat,
                    JSONArray(
                        taken.map {
                            JSONObject().put("entry", it.entry).put("value", it.value)
                        },
                    ),
                )
                totalHits += taken.size
            }

            val body = JSONObject()
                .put("tool", "string_scan")
                .put("path", inputPath)
                .put("scannedEntries", raw.scannedEntries)
                // F-49（2026-10-04）：覆盖报账——总数与三类跳过显式声明，
                // 零命中时能区分「没扫到」与「没扫这部分」（真机 v8 D14：
                // 330/611 的差额过去无痕消失）。
                .put("totalEntries", raw.totalEntries)
                .put(
                    "skipped",
                    JSONObject()
                        .put("byExtension", raw.skippedByExtension)
                        .put("oversize", raw.skippedOversize)
                        .put("errors", raw.skippedErrors)
                        .put(
                            "note",
                            "媒体/字体类扩展名不参与扫描（byExtension）；> maxBytesPerEntry 的条目跳过（oversize）；"
                                + "读取失败计数（errors）。scanned=total-skipped 才是本次实际覆盖。",
                        ),
                )
                .put("totalHits", totalHits)
                .put("categories", cats)
                .put("locations", locationJson)
                // 三态如实上报（2026-09-21 复测 D5）：过去"原始扫描被复用、只做内存
                // 复筛"也写 cache=miss，而 elapsedMs 只算复筛耗时——两者一起读像
                // 自相矛盾（"miss 却 0ms"），也看不出省掉了一次整包扫描。
                .put("cache", if (cachedRaw != null) "raw-hit" else "miss")
                .put("cacheNote", if (cachedRaw != null) "原始扫描复用，仅内存复筛" else "整包扫描")
                .put("elapsedMs", (System.nanoTime() - startedAt) / 1_000_000)
                .put(
                    "hint",
                    if (totalHits == 0) {
                        "未命中敏感模式(可调小 minLen 或换 category)"
                    } else {
                        "locations 给出 APK 条目来源；DEX 命中再用 dex_search 反查方法"
                    },
                )
            val response = ok(body)
            synchronized(scanCache) { scanCache[cacheKey] = response.toString() }
            response
        }.getOrElse { e ->
            err("SCAN_FAILED", "扫描失败: ${e.message ?: e.javaClass.simpleName}", "path", inputPath)
        }
    }
}
