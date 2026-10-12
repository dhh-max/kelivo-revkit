package zhou.solab.tools

import com.android.apksig.ApkVerifier
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Locale

object ApkArchiveTool {
    private const val DEFAULT_LIST_LIMIT = 100
    private const val MAX_LIST_LIMIT = 500
    private const val DEFAULT_READ_LIMIT = 4096
    private const val MAX_READ_LIMIT = 64 * 1024
    private const val TEXT_SAMPLE_LIMIT = 8192
    private const val DEFAULT_STRING_LIMIT = 100
    private const val MAX_STRING_LIMIT = 1000

    fun handle(args: JSONObject): JSONObject {
        val (apk, inputError) = resolveInputFile(args)
        if (inputError != null) return inputError
        if (!apk!!.name.endsWith(".apk", ignoreCase = true)) {
            return err("INVALID_ARGUMENT", "path 必须指向 APK 文件", "path", apk.absolutePath)
        }
        return when (args.str("action", "list").lowercase(Locale.ROOT)) {
            "list" -> list(apk, args)
            "read" -> read(apk, args)
            "strings" -> strings(apk, args)
            "certificates" -> certificates(apk)
            "resources" -> resources(apk, args)
            else -> err("UNKNOWN_ACTION", "未知 action（支持 list/read/strings/certificates/resources）", "action", args.str("action"))
        }
    }

    /**
     * 本工具链内置签名证书 SHA-256（android/key.properties keystore，
     * 从 dist 成品提取）。命中即说明该 APK 是本工具链 apk_sign 签名的
     * 产物——不是第三方原包。公开指纹，非敏感信息。
     */
    val BUILTIN_CERT_SHA256 =
        "5A:69:17:AB:87:D8:4A:81:FB:83:8E:C6:1F:73:7C:A3:9A:D7:0B:85:35:82:01:D1:39:66:A9:3A:77:21:A5:49"

    /** 去签兼容注入的代理 Application 类名（ApkSignatureBypassInjector.PROXY_CLASS）。 */
    private const val SIGNATURE_PROXY_CLASS = "zhou.solab.signature.SignatureProxyApplication"

    /** 任一签名证书指纹等于内置证书 → 该包是本工具链签名的产物。 */
    internal fun isBuiltinCert(fp: String): Boolean =
        fp.replace(":", "").equals(BUILTIN_CERT_SHA256.replace(":", ""), ignoreCase = true)

    /**
     * manifest 字节里找签名代理 Application 痕迹。AXML 字符串池是 UTF-8 或
     * UTF-16LE 编码，两种字节序列都查；纯子串搜索，不做 AXML 解析。
     */
    internal fun manifestContainsProxy(bytes: ByteArray): Boolean {
        fun indexOf(haystack: ByteArray, needle: ByteArray): Boolean {
            if (needle.isEmpty() || haystack.size < needle.size) return false
            outer@ for (i in 0..haystack.size - needle.size) {
                for (j in needle.indices) {
                    if (haystack[i + j] != needle[j]) continue@outer
                }
                return true
            }
            return false
        }
        val utf8 = SIGNATURE_PROXY_CLASS.toByteArray(Charsets.UTF_8)
        val utf16 = SIGNATURE_PROXY_CLASS.toByteArray(Charsets.UTF_16LE)
        return indexOf(bytes, utf8) || indexOf(bytes, utf16)
    }

    private fun list(apk: File, args: JSONObject): JSONObject = runCatching {
        val query = args.str("query").trim().lowercase(Locale.ROOT)
        // 前缀过滤（2026-09-21 复测 D1）：schema 早已声明 entryPrefix，但这一侧
        // 过去只读 query —— 调用方按名字过滤，拿到的是全量条目（连 META-INF 都在），
        // 会误判「过滤生效了」。与 query 同为包含式之外的收窄条件。
        val entryPrefix = args.str("entryPrefix").trim()
        val offset = args.intValue("offset", 0).coerceAtLeast(0)
        val limit = args.intValue("limit", DEFAULT_LIST_LIMIT).coerceIn(1, MAX_LIST_LIMIT)
        // 引用标记（2026-09-19 复测待办）：withReferences=true 时逐条目判断
        // 「路径或文件名是否出现在 dex 字符串池里」——用于回答「这个 assets/so
        // 条目还有没有代码引用」。需要一次全 dex 串扫描（按指纹缓存），默认关。
        val withReferences = args.optBoolean("withReferences", false)
        val entries = JSONArray()
        var referenced = 0
        var total = 0
        ApkZipCache.shared.withZip(apk) { zip ->
            val dexStrings = if (withReferences) dexStringsOf(zip, apk) else emptySet()
            zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
                if (query.isNotEmpty() && !entry.name.lowercase(Locale.ROOT).contains(query)) return@forEach
                if (entryPrefix.isNotEmpty() && !entry.name.startsWith(entryPrefix)) return@forEach
                if (total >= offset && entries.length() < limit) {
                    val item = JSONObject()
                        .put("path", entry.name)
                        .put("size", entry.size.coerceAtLeast(0L))
                        .put("compressedSize", entry.compressedSize.coerceAtLeast(0L))
                        .put("compressionMethod", if (entry.method == 0) "stored" else "deflated")
                    if (withReferences) {
                        val basename = entry.name.substringAfterLast('/')
                        val hit = dexStrings.contains(entry.name) || dexStrings.contains(basename)
                        item.put("referencedFromDex", hit)
                        if (hit) referenced++
                    }
                    entries.put(item)
                }
                total++
            }
        }
        ok(
            JSONObject()
                .put("tool", "apk_archive")
                .put("action", "list")
                .put("path", apk.absolutePath)
                .put("query", query)
                .put("entryPrefix", entryPrefix)
                .put(
                    "prefixNote",
                    if (entryPrefix.isEmpty()) {
                        "传 entryPrefix 可按前缀收窄（如 lib/、res/、classes），与 query 是**交集**语义。"
                    } else if (total == 0) {
                        "entryPrefix=$entryPrefix 命中 0 条：前缀是**严格区分大小写**的 zip 路径前缀" +
                            "（LIB/ 与 lib/ 不同），也确认结尾的 / 是否写对（lib/ 会命中 lib/... 而 lib 会命中 lib、library 两类前缀）。"
                    } else {
                        "entryPrefix=$entryPrefix 命中 $total 条（与 query 为交集语义，大小写敏感）。"
                    },
                )
                .put("offset", offset)
                .put("limit", limit)
                .put("total", total)
                .put("entries", entries)
                .put("withReferences", withReferences)
                .put(
                    "referencesNote",
                    if (withReferences) {
                        "referencedFromDex=true 表示该条目路径/文件名出现在 dex 字符串池中（代码可能引用它）；" +
                            "保守判据：只认字面命中，可能漏报拼接路径。已标记 $referenced 条。"
                    } else {
                        "传 withReferences=true 可标记「条目是否出现在 dex 字符串池」（需一次全 dex 串扫描）。"
                    },
                )
                .put("nextOffset", if (offset + entries.length() < total) offset + entries.length() else JSONObject.NULL),
        )
    }.getOrElse { error ->
        err("ARCHIVE_READ_FAILED", error.message ?: "无法读取 APK 条目")
    }

    private fun read(apk: File, args: JSONObject): JSONObject {
        val name = args.str("entry").trim()
        if (name.isEmpty() || name.startsWith('/') || name.split('/').any { it == ".." }) {
            return err(
                "INVALID_ARGUMENT",
                "read/strings 动作必须传 entry（APK 内的合法文件路径，如 classes.dex / resources.arsc）。" +
                    "不确定条目名时先调 apk_archive(action=list) 查看；未传 entry 而非路径非法时填 entry 即可",
                "entry", name,
            )
        }
        val offset = args.optLong("offset", 0L).coerceAtLeast(0L)
        val limit = args.intValue("limit", DEFAULT_READ_LIMIT).coerceIn(1, MAX_READ_LIMIT)
        return runCatching {
            ApkZipCache.shared.withZip(apk) { zip ->
                val entry = zip.getEntry(name) ?: return@withZip err("ENTRY_NOT_FOUND", "APK 内不存在条目: $name", "entry", name)
                if (entry.isDirectory) return@withZip err("INVALID_ARGUMENT", "entry 必须是文件，不能是目录", "entry", name)
                val size = entry.size.coerceAtLeast(0L)
                if (offset > size) return@withZip err("INVALID_ARGUMENT", "offset 超出条目大小 $size", "offset", offset)
                val window = zip.getInputStream(entry).use { input ->
                    skipFully(input, offset)
                    readUpTo(input, minOf(limit.toLong(), size - offset).toInt())
                }
                val sample = zip.getInputStream(entry).use { input ->
                    readUpTo(input, minOf(TEXT_SAMPLE_LIMIT.toLong(), size).toInt())
                }
                val text = isText(sample)
                ok(
                    JSONObject()
                        .put("tool", "apk_archive")
                        .put("action", "read")
                        .put("path", apk.absolutePath)
                        .put("entry", name)
                        .put("size", size)
                        .put("compressedSize", entry.compressedSize.coerceAtLeast(0L))
                        .put("offset", offset)
                        .put("bytes", window.size)
                        .put("truncated", offset + window.size < size)
                        .put("encoding", if (text) "UTF-8" else "binary")
                        .put("content", if (text) String(window, Charsets.UTF_8) else JSONObject.NULL)
                        .put("hexPreview", if (text) JSONObject.NULL else window.joinToString(" ") { "%02X".format(it) })
                        .put("nextOffset", if (offset + window.size < size) offset + window.size else JSONObject.NULL),
                )
            }
        }.getOrElse { error ->
            err("ARCHIVE_READ_FAILED", error.message ?: "无法读取 APK 条目")
        }
    }

    private fun certificates(apk: File): JSONObject = runCatching {
        val result = ApkVerifier.Builder(apk).build().verify()
        val certificates = JSONArray()
        result.signerCertificates.forEach { certificates.put(certificateJson(it)) }
        // 已处理产物身份检测：内置证书指纹命中 = 本工具链 apk_sign 的产物，
        // 不是第三方原包；manifest 含签名代理类 = 已做过 signature_bypass 注入。
        val selfSigned = result.signerCertificates.any {
            isBuiltinCert(fingerprint(it, "SHA-256"))
        }
        val proxyInjected = ApkZipCache.shared.withZip(apk) { zip ->
            val entry = zip.entries().asSequence()
                .firstOrNull { it.name == "AndroidManifest.xml" }
            entry ?: return@withZip false
            val bytes = zip.getInputStream(entry).use { it.readBytes() }
            manifestContainsProxy(bytes)
        }
        ok(
            JSONObject()
                .put("tool", "apk_archive")
                .put("action", "certificates")
                .put("path", apk.absolutePath)
                .put("verified", result.isVerified)
                .put("verifiedUsingV1", result.isVerifiedUsingV1Scheme)
                .put("verifiedUsingV2", result.isVerifiedUsingV2Scheme)
                .put("verifiedUsingV3", result.isVerifiedUsingV3Scheme)
                .put("selfSignedByToolchain", selfSigned)
                .put("signatureProxyInjected", proxyInjected)
                .put("processedArtifact", selfSigned || proxyInjected)
                .put("certificates", certificates),
        )
    }.getOrElse { error ->
        err("CERTIFICATE_READ_FAILED", error.message ?: "无法读取 APK 签名证书")
    }

    /**
     * 资源表读取（2026-09-19 复测对照的缺口能力）。
     *
     * action=resources：按 query（名字/类型/值子串）或 id（0x7f010000 / @string/app_name）
     * 查询 resources.arsc，返回 0xPPTTEEEE 资源 id、类型、名字与各配置的值
     * （同一 id 的多语言/多密度会各返回一条，不展开完整配置矩阵；复杂值为空）。
     */
    private fun resources(apk: File, args: JSONObject): JSONObject {
        val query = args.str("query").trim()
        val idRaw = args.str("id").trim()
        val limit = args.intValue("limit", DEFAULT_LIST_LIMIT).coerceIn(1, MAX_LIST_LIMIT)
        val targetId = if (idRaw.isEmpty()) null else parseResourceId(idRaw)
        if (idRaw.isNotEmpty() && targetId == null) {
            return err(
                "INVALID_ARGUMENT",
                "id 需为 0xPPTTEEEE 形式（如 0x7f010000）或十进制数值；" +
                    "按名字/类型/值查找请改用 query（例如 query=app_name）。",
                "id", idRaw,
            )
        }
        return runCatching {
            ApkZipCache.shared.withZip(apk) { zip ->
                val entry = zip.getEntry("resources.arsc")
                    ?: return@withZip err("ENTRY_NOT_FOUND", "APK 内没有 resources.arsc", "entry", "resources.arsc")
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                val parsed = ArscResourceReader.read(bytes)
                var items = parsed.entries
                if (targetId != null) {
                    items = items.filter { it.id == targetId }
                } else if (query.isNotEmpty()) {
                    items = items.filter {
                        it.name.contains(query, ignoreCase = true) ||
                            it.typeName.contains(query, ignoreCase = true) ||
                            it.value.contains(query, ignoreCase = true)
                    }
                }
                val returned = items.take(limit)
                val array = JSONArray()
                for (item in returned) {
                    array.put(
                        JSONObject()
                            .put("id", "0x%08x".format(item.id))
                            .put("type", item.typeName)
                            .put("name", item.name)
                            .put("valueType", item.dataTypeName)
                            .put("value", item.value)
                            .put("package", item.packageName),
                    )
                }
                ok(
                    JSONObject()
                        .put("tool", "apk_archive")
                        .put("action", "resources")
                        .put("path", apk.absolutePath)
                        .put("query", query)
                        .put("id", idRaw)
                        .put("total", items.size)
                        .put("returned", returned.size)
                        .put("truncated", items.size > returned.size)
                        .put("types", JSONArray(parsed.typeNames))
                        .put(
                            "note",
                            // F-26/v9 复测：note 与行为对齐——多语言/多密度**会**
                            // 返回多条（同一资源 id 每个配置一条），只是不展开
                            // 完整配置矩阵；复杂值（item_list/attr）value 为空，
                            // 可看 valueType=complex。
                            "同一资源 id 的每个配置各返回一条（如中英两个 app_name 会并列），"
                                + "不展开完整配置矩阵；复杂值（item_list/attr）value 为空，可看 valueType=complex。",
                        )
                        .put("entries", array),
                )
            }
        }.getOrElse { error -> err("ARCHIVE_READ_FAILED", error.message ?: "无法读取 resources.arsc") }
    }

    /**
     * 资源 id 解析（A6，2026-09-19 审核）：
     * - 带 0x/@0x 前缀 → 十六进制；
     * - **裸数字按十进制**（旧实现一律按 16 进制，"123" 被当成 0x123 = 291）；
     * - `@string/app_name` 这类名字形式返回 null，由调用方提示改用 query。
     */
    internal fun parseResourceId(raw: String): Int? {
        if (raw.startsWith("@") && raw.contains('/')) return null
        val lower = raw.lowercase()
        val isHex = lower.startsWith("0x") || lower.startsWith("@0x")
        val text = raw.removePrefix("@").removePrefix("0x").removePrefix("0X")
        val value = if (isHex) text.toLongOrNull(16) else text.toLongOrNull(10)
        return value?.toInt()?.takeIf { it != 0 }
    }

    /** APK 内 dex 字符串集（按 mtime+size 指纹缓存）：归档引用标记用。 */
    private val dexStringCache = LinkedHashMap<String, Set<String>>()

    private fun dexStringsOf(zip: java.util.zip.ZipFile, apk: File): Set<String> {
        val key = apk.canonicalPath + "|" + apk.lastModified() + "|" + apk.length()
        dexStringCache[key]?.let { return it }
        val out = HashSet<String>()
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (entry.isDirectory || !entry.name.endsWith(".dex", ignoreCase = true)) continue
            val bytes = zip.getInputStream(entry).use { it.readBytes() }
            if (DexStringPool.looksLikeDex(bytes)) {
                out += DexStringPool.read(bytes, minLen = 3, limit = 200_000)
            }
        }
        if (dexStringCache.size >= 4) {
            dexStringCache.remove(dexStringCache.keys.first())
        }
        dexStringCache[key] = out
        return out
    }

    private fun strings(apk: File, args: JSONObject): JSONObject {
        val name = args.str("entry").trim()
        if (name.isEmpty() || name.startsWith('/') || name.split('/').any { it == ".." }) {
            return err(
                "INVALID_ARGUMENT",
                "read/strings 动作必须传 entry（APK 内的合法文件路径，如 classes.dex / resources.arsc）。" +
                    "不确定条目名时先调 apk_archive(action=list) 查看；未传 entry 而非路径非法时填 entry 即可",
                "entry", name,
            )
        }
        val minLen = args.intValue("minLen", 4).coerceIn(3, 64)
        val limit = args.intValue("limit", DEFAULT_STRING_LIMIT).coerceIn(1, MAX_STRING_LIMIT)
        val query = args.str("query").trim()
        return runCatching {
            ApkZipCache.shared.withZip(apk) { zip ->
                val entry = zip.getEntry(name) ?: return@withZip err("ENTRY_NOT_FOUND", "APK 内不存在条目: $name", "entry", name)
                if (entry.isDirectory) return@withZip err("INVALID_ARGUMENT", "entry 必须是文件，不能是目录", "entry", name)
                // DEX 走字符串池直读（2026-09-19 复测 DEF-11）：字节扫串对 dex
                // 只会命中 id 表噪音（真实字符串在 data 区，顺序扫永远到不了）。
                if (name.endsWith(".dex", ignoreCase = true)) {
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    if (DexStringPool.looksLikeDex(bytes)) {
                        val pool = DexStringPool.read(bytes, minLen, limit, query)
                        return@withZip ok(
                            JSONObject()
                                .put("tool", "apk_archive")
                                .put("action", "strings")
                                .put("path", apk.absolutePath)
                                .put("entry", name)
                                .put("source", "dex_string_pool")
                                .put("minLen", minLen)
                                .put("limit", limit)
                                .put("query", query)
                                .put("returned", pool.size)
                                .put("truncated", pool.size >= limit)
                                .put("strings", JSONArray(pool)),
                        )
                    }
                }
                val values = LinkedHashSet<String>()
                fun add(value: StringBuilder) {
                    if (value.length >= minLen && values.size < limit) {
                        val text = value.toString().take(512)
                        if (query.isEmpty() ||
                            text.contains(query, ignoreCase = true)
                        ) {
                            values += text
                        }
                    }
                    value.clear()
                }
                zip.getInputStream(entry).use { input ->
                    val buffer = ByteArray(64 * 1024)
                    val ascii = StringBuilder()
                    val utf16 = StringBuilder()
                    var lowByte = -1
                    while (values.size < limit) {
                        val count = input.read(buffer)
                        if (count <= 0) break
                        for (index in 0 until count) {
                            val value = buffer[index].toInt() and 0xff
                            if (value in 0x20..0x7e) ascii.append(value.toChar()) else add(ascii)
                            if (lowByte < 0) {
                                lowByte = value
                            } else {
                                if (value == 0 && lowByte in 0x20..0x7e) utf16.append(lowByte.toChar()) else add(utf16)
                                lowByte = -1
                            }
                        }
                    }
                    add(ascii)
                    add(utf16)
                }
                ok(
                    JSONObject()
                        .put("tool", "apk_archive")
                        .put("action", "strings")
                        .put("path", apk.absolutePath)
                        .put("entry", name)
                        // 非 DEX 条目仍是顺序字节扫串（stored 文本/二进制条目适用）；
                        // 如实标注来源，调用方据此判断可信度。
                        .put("source", "byte_scan")
                        .put("minLen", minLen)
                        .put("limit", limit)
                        .put("query", query)
                        .put("returned", values.size)
                        .put("truncated", values.size >= limit)
                        .put("strings", JSONArray(values.toList())),
                )
            }
        }.getOrElse { error ->
            err("ARCHIVE_READ_FAILED", error.message ?: "无法读取 APK 条目")
        }
    }

    private fun certificateJson(certificate: X509Certificate): JSONObject = JSONObject()
        .put("subject", certificate.subjectX500Principal.name)
        .put("issuer", certificate.issuerX500Principal.name)
        .put("serialNumber", certificate.serialNumber.toString(16).uppercase(Locale.ROOT))
        .put("signatureAlgorithm", certificate.sigAlgName)
        .put("publicKeyAlgorithm", certificate.publicKey.algorithm)
        .put("validFrom", certificate.notBefore.time)
        .put("validTo", certificate.notAfter.time)
        .put("sha256", fingerprint(certificate, "SHA-256"))
        .put("sha1", fingerprint(certificate, "SHA-1"))

    private fun fingerprint(certificate: X509Certificate, algorithm: String): String =
        MessageDigest.getInstance(algorithm).digest(certificate.encoded)
            .joinToString(":") { "%02X".format(it) }

    private fun isText(bytes: ByteArray): Boolean {
        if (bytes.isEmpty() || bytes.any { it == 0.toByte() }) return false
        val printable = bytes.count { byte ->
            val value = byte.toInt() and 0xff
            value in 0x09..0x0d || value in 0x20..0x7e || value >= 0x80
        }
        return printable * 5 >= bytes.size * 4
    }

    private fun skipFully(input: InputStream, offset: Long) {
        var skipped = 0L
        while (skipped < offset) {
            val count = input.skip(offset - skipped)
            if (count > 0) {
                skipped += count
            } else if (input.read() == -1) {
                break
            } else {
                skipped++
            }
        }
    }

    private fun readUpTo(input: InputStream, size: Int): ByteArray {
        val output = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val count = input.read(output, offset, size - offset)
            if (count <= 0) break
            offset += count
        }
        return if (offset == size) output else output.copyOf(offset)
    }
}
