package zhou.solab.tools

/**
 * 资源表（resources.arsc）最小读取器。
 *
 * 背景（2026-09-19 全量复测对照 MT）：MT 有 `mt_apk_resource_read` /
 * `mt_apk_resource_xref`，我们完全没有资源域能力，只能靠 AXML/字符串间接推。
 * 本文件只做「够用」的两件事，不追求完整 ARSC 语义：
 *   1) 列出资源（package → type → entry，带 0xPPTTEEEE 资源 id）；
 *   2) 按 id 或名字读值（字符串/引用/整型/布尔/颜色/浮点）。
 *
 * 已知边界（如实体现在返回里）：只取每个 entry 的**首个**配置值（不做多语言
 * 枚举），复杂值（item_list/attr）只报类型不展开。
 *
 * 格式要点（AOSP 资源二进制规范）：
 *   RES_TABLE(0x0002) → 全局字符串池(0x0001) + RES_TABLE_PACKAGE(0x0200)
 *   package 头里给出 typeStrings/keyStrings 两个池的偏移
 *   type(0x0201) 给出 entryCount/entriesStart + 变长 config，条目偏移表后
 *   每条 = ResTable_entry(size,flags,key) [+ Res_value(size,res0,type,data)]
 */
object ArscResourceReader {

    private const val TYPE_TABLE = 0x0002
    private const val TYPE_STRING_POOL = 0x0001
    private const val TYPE_PACKAGE = 0x0200
    private const val TYPE_TYPE = 0x0201
    private const val TYPE_TYPE_SPEC = 0x0202

    private const val NO_ENTRY = 0xFFFFFFFF.toInt()

    /** 一条资源记录。 */
    data class Entry(
        val id: Int,
        val packageName: String,
        val typeName: String,
        val name: String,
        val dataType: Int,
        val dataTypeName: String,
        val value: String,
    )

    /** 解析结果：entries + 全局字符串池（引用值就近解析用）。 */
    class Parsed(val entries: List<Entry>, val typeNames: List<String>)

    fun read(bytes: ByteArray): Parsed {
        val entries = ArrayList<Entry>()
        val allTypeNames = ArrayList<String>()
        if (bytes.size < 12) return Parsed(entries, allTypeNames)
        if (u16(bytes, 0) != TYPE_TABLE) return Parsed(entries, allTypeNames)

        var strings: List<String> = emptyList()
        var offset = u16(bytes, 2) // headerSize
        while (offset + 8 <= bytes.size) {
            val chunkType = u16(bytes, offset)
            val headerSize = u16(bytes, offset + 2)
            val chunkSize = i32(bytes, offset + 4)
            if (chunkSize <= 0 || offset + chunkSize > bytes.size) break
            when (chunkType) {
                TYPE_STRING_POOL -> strings = readStringPool(bytes, offset)
                TYPE_PACKAGE -> entries += readPackage(bytes, offset, chunkSize, strings, allTypeNames)
            }
            offset += chunkSize
            if (headerSize <= 0) break
        }
        return Parsed(entries, sanitizeTypeNames(allTypeNames))
    }

    /**
     * F-54（2026-10-05 复测仍在）：类型名池直接倒出时，解码错位条目会以
     * "?14" 这类非标识符形态混进 `types` 数组（我此前的逐条兜底只修了
     * readPackage 内部的 typeName 取值，没覆盖这里）。统一消毒：非标识符
     * 条目按位替换成 type$index，调用方拿到的是干净可读的类型名。
     */
    internal fun sanitizeTypeNames(names: List<String>): List<String> = names.mapIndexed { index, name ->
        if (name.isValidTypeName()) name else "type${index + 1}"
    }

    // ------------------------------------------------------------------ package
    private fun readPackage(
        bytes: ByteArray,
        base: Int,
        chunkSize: Int,
        globalStrings: List<String>,
        allTypeNames: MutableList<String>,
    ): List<Entry> {
        val out = ArrayList<Entry>()
        val headerSize = u16(bytes, base + 2)
        val packageId = i32(bytes, base + 8)
        val packageName = readUtf16Name(bytes, base + 12)
        val typeStringsOff = i32(bytes, base + 12 + 256)
        val keyStringsOff = i32(bytes, base + 12 + 256 + 8)
        val typeNames = readStringPool(bytes, base + typeStringsOff)
        val keyNames = readStringPool(bytes, base + keyStringsOff)
        if (typeNames.isNotEmpty()) allTypeNames += typeNames

        var offset = base + headerSize
        val end = base + chunkSize
        while (offset + 8 <= end) {
            val chunkType = u16(bytes, offset)
            val chunkHeaderSize = u16(bytes, offset + 2)
            val cSize = i32(bytes, offset + 4)
            if (cSize <= 0 || offset + cSize > end) break
            if (chunkType == TYPE_TYPE && chunkHeaderSize >= 20) {
                val typeId = bytes[offset + 8].toInt() and 0xff
                // A5：entry 数按本 chunk 剩余空间钳制（畸形/截断 arsc 防超长空转）
                val maxEntries = ((cSize - chunkHeaderSize) - 4) / 4
                val entryCount = minOf(i32(bytes, offset + 12), maxOf(maxEntries, 0))
                val entriesStart = i32(bytes, offset + 16)
                val typeName = if (typeId >= 1) {
                    // F-54（2026-10-04 复查再修）：合法类型名必须是标识符
                    // （[A-Za-z_][A-Za-z0-9_]*）。真机 v8 报告里的 "?14"/"?17"
                    // 就是池里存在但**解出来不是标识符**的条目（解码错位/
                    // 占位符）——这类"有名但不可用"的条目要和缺失一样处理：
                    // 回退全局表，再兜底 type$id，绝不把乱码当类型名回给调用方。
                    val local = typeNames.getOrNull(typeId - 1)?.takeIf { it.isValidTypeName() }
                    val global = allTypeNames.getOrNull(typeId - 1)?.takeIf { it.isValidTypeName() }
                    local ?: global ?: "type$typeId"
                } else {
                    "type$typeId"
                }
                val entriesBase = offset + entriesStart
                if (entriesBase <= offset || entriesBase >= bytes.size) {
                    offset += cSize
                    continue
                }
                for (index in 0 until entryCount) {
                    val entryOffset = i32(bytes, offset + chunkHeaderSize + index * 4)
                    if (entryOffset == NO_ENTRY) continue
                    val entryPos = entriesBase + entryOffset
                    if (entryPos + 8 > bytes.size) continue
                    val entrySize = u16(bytes, entryPos)
                    val flags = u16(bytes, entryPos + 2)
                    val keyIndex = i32(bytes, entryPos + 4)
                    val name = keyNames.getOrNull(keyIndex) ?: "entry$index"
                    val isComplex = flags and 0x0001 != 0
                    val valuePos = entryPos + entrySize
                    var dataType = -1
                    var value = ""
                    if (!isComplex && valuePos + 8 <= bytes.size) {
                        dataType = bytes[valuePos + 3].toInt() and 0xff
                        val data = i32(bytes, valuePos + 4)
                        value = decodeValue(dataType, data, globalStrings)
                    }
                    out += Entry(
                        id = (packageId shl 24) or (typeId shl 16) or index,
                        packageName = packageName,
                        typeName = typeName,
                        name = name,
                        dataType = dataType,
                        dataTypeName = typeNameOf(dataType),
                        value = value,
                    )
                }
            }
            offset += cSize
        }
        return out
    }

    // ------------------------------------------------------------------ value
    private fun typeNameOf(dataType: Int): String = when (dataType) {
        0x00 -> "null"
        0x01 -> "reference"
        0x02 -> "attribute"
        0x03 -> "string"
        0x04 -> "float"
        0x05 -> "dimension"
        0x06 -> "fraction"
        0x10 -> "int_dec"
        0x11 -> "int_hex"
        0x12 -> "int_boolean"
        0x1c -> "int_color_argb8"
        0x1d -> "int_color_rgb8"
        0x1e -> "int_color_argb4"
        0x1f -> "int_color_rgb4"
        -1 -> "complex"
        else -> "type0x%02x".format(dataType)
    }

    private fun decodeValue(dataType: Int, data: Int, strings: List<String>): String =
        when (dataType) {
            0x03 -> strings.getOrNull(data) ?: "@string/$data"
            0x01 -> "@0x%08x".format(data)
            0x02 -> "?0x%08x".format(data)
            0x12 -> if (data != 0) "true" else "false"
            0x1c, 0x1d, 0x1e, 0x1f -> "#%08x".format(data)
            0x04 -> Float.fromBits(data).toString()
            0x00 -> ""
            -1 -> ""
            else -> data.toString()
        }

    // ------------------------------------------------------------------ strings
    /// F-54（2026-10-04）：类型名合法性——必须是标识符，否则视为未解析
    /// （池里的解码错位条目会产出 "?14" 这类乱码，不能当类型名回给调用方）。
    private val typeNamePattern = Regex("^[A-Za-z_][A-Za-z0-9_]*$")
    private fun String.isValidTypeName(): Boolean = typeNamePattern.matches(this)

    /** ResStringPool：支持 UTF-8 与 UTF-16 两种编码（internal 以便单测直测）。 */
    internal fun readStringPool(bytes: ByteArray, base: Int): List<String> {
        if (base < 0 || base + 28 > bytes.size) return emptyList()
        if (u16(bytes, base) != TYPE_STRING_POOL) return emptyList()
        var count = i32(bytes, base + 8)
        val flags = i32(bytes, base + 16)
        val stringsStart = i32(bytes, base + 20)
        if (count <= 0) return emptyList()
        // A5（2026-09-19 审核）：头长度按 headerSize 取（规范允许扩展），不再
        // 硬编码 28；并把条数按剩余字节钳制，畸形 arsc 不会越界/空转。
        val headerSize = u16(bytes, base + 2).coerceAtLeast(28)
        val offsetsBase = base + headerSize
        // 本 chunk 的硬边界：字符串数据不得越界（畸形/截断 arsc 防走飞空转）
        val chunkSize = i32(bytes, base + 4)
        val end = if (chunkSize > 0 && base + chunkSize <= bytes.size) {
            base + chunkSize
        } else {
            bytes.size
        }
        val available = (end - offsetsBase).coerceAtLeast(0) / 4
        if (available <= 0) return emptyList()
        if (count > available) count = available
        if (count > 1_000_000) count = 1_000_000
        val isUtf8 = flags and 0x00000100 != 0
        val dataBase = base + stringsStart
        val out = ArrayList<String>(count)
        for (index in 0 until count) {
            val rel = i32(bytes, offsetsBase + index * 4)
            val pos = dataBase + rel
            if (pos < dataBase || pos >= end) {
                out += ""
                continue
            }
            out += if (isUtf8) readUtf8String(bytes, pos, end) else readUtf16String(bytes, pos, end)
        }
        return out
    }

    private fun readUtf8String(bytes: ByteArray, pos: Int, end: Int): String {
        var cursor = pos
        // 两个长度：UTF-16 单元数、字节数（各自 uleb128 风格，高位续读）
        var ignored = 0
        while (cursor < end) {
            val b = bytes[cursor].toInt() and 0xff
            cursor++
            ignored = (ignored shl 7) or (b and 0x7f)
            if (b and 0x80 == 0) break
        }
        var length = 0
        while (cursor < end) {
            val b = bytes[cursor].toInt() and 0xff
            cursor++
            length = (length shl 7) or (b and 0x7f)
            if (b and 0x80 == 0) break
        }
        if (length <= 0 || cursor + length > end) return ""
        return String(bytes, cursor, length, Charsets.UTF_8)
    }

    private fun readUtf16String(bytes: ByteArray, pos: Int, end: Int): String {
        if (pos + 2 > end) return ""
        var cursor = pos
        var length: Int
        val unit = u16(bytes, cursor)
        cursor += 2
        if (unit and 0x8000 != 0) {
            // A1（2026-09-19 审核）：高位置 1 时长度是 32 位——((unit & 0x7fff) << 16)
            // | next。旧实现写成 shl 8，>32767 单元的字符串长度算错（会截断/越界）。
            if (cursor + 2 > end) return ""
            length = ((unit and 0x7fff) shl 16) or u16(bytes, cursor)
            cursor += 2
        } else {
            length = unit
        }
        if (length <= 0 || cursor + length * 2 > end) return ""
        return String(bytes, cursor, length * 2, Charsets.UTF_16LE)
    }

    private fun readUtf16Name(bytes: ByteArray, pos: Int): String {
        if (pos + 256 > bytes.size) return ""
        val raw = String(bytes, pos, 256, Charsets.UTF_16LE)
        val nul = raw.indexOf('\u0000')
        return if (nul >= 0) raw.substring(0, nul) else raw
    }

    // ------------------------------------------------------------------ ints
    private fun u16(bytes: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 2 > bytes.size) return 0
        return (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8)
    }

    private fun i32(bytes: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 4 > bytes.size) return -1
        return (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)
    }
}
