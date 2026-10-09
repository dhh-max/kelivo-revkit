package zhou.solab.tools

/**
 * DEX 字符串池读取（纯字节解析，不依赖 dexlib2 的映射句柄）。
 *
 * 背景（2026-09-19 全量复测 DEF-11）：`apk_archive(action=strings)` 过去对
 * 任意条目做「从头顺序扫可打印串」——对 DEX 而言，文件前段是
 * header + string_ids/type_ids/proto_ids/field_ids/method_ids 这些全字节的
 * 二进制表，真正的字符串数据在 data 区。于是 `classes.dex` 的字符串结果全是
 * `>!>0>G>n>` 这类 id 表噪音（stored 的 libapp.so 因为明文在前所以看着正常），
 * 调用方据此得出的结论不可信。
 *
 * 这里按 DEX 格式直读 string_ids → string_data_item：
 *   header.string_ids_size(0x38) / string_ids_off(0x3C)（小端 u4）
 *   string_data_item = uleb128 utf16_size + MUTF-8 字节
 * MUTF-8 的 0xC0 0x80（NUL）与 1/2/3 字节序列都按规范解，长度用完即止。
 */
object DexStringPool {

    private const val HEADER_MIN = 0x40
    private const val STRING_IDS_SIZE_OFF = 0x38
    private const val STRING_IDS_OFF_OFF = 0x3C

    /** 是否为 DEX 条目（按 magic 判断，兼容各版本）。 */
    fun looksLikeDex(bytes: ByteArray): Boolean =
        bytes.size >= 8 &&
            bytes[0] == 'd'.code.toByte() &&
            bytes[1] == 'e'.code.toByte() &&
            bytes[2] == 'x'.code.toByte() &&
            bytes[3] == 0x0a.toByte()

    /**
     * 顺序读出字符串池（按 string_ids 下标，即 DEX 内的原始顺序）。
     *
     * @param minLen 最小字符数（含）
     * @param limit  最多返回条数（含）
     * @param query  非空时只保留包含该子串的项（忽略大小写）
     */
    fun read(
        bytes: ByteArray,
        minLen: Int,
        limit: Int,
        query: String = "",
    ): List<String> {
        if (bytes.size < HEADER_MIN || !looksLikeDex(bytes)) return emptyList()
        val count = u32(bytes, STRING_IDS_SIZE_OFF)
        val base = u32(bytes, STRING_IDS_OFF_OFF)
        if (count <= 0 || base <= 0 || base >= bytes.size) return emptyList()
        val needle = query.trim().lowercase()
        val out = LinkedHashSet<String>()
        var index = 0L
        while (index < count && out.size < limit) {
            val entryOff = base + index * 4
            if (entryOff + 4 > bytes.size) break
            val dataOff = u32(bytes, entryOff.toInt())
            if (dataOff <= 0 || dataOff >= bytes.size) {
                index++
                continue
            }
            val value = readStringData(bytes, dataOff.toInt())
            if (value != null &&
                value.length >= minLen &&
                (needle.isEmpty() || value.lowercase().contains(needle))
            ) {
                out += value
            }
            index++
        }
        return out.toList()
    }

    /** 读一条 string_data_item；越界或非法长度返回 null。 */
    private fun readStringData(bytes: ByteArray, offset: Int): String? {
        var cursor = offset
        val length = readUleb128(bytes, cursor) ?: return null
        cursor += length.second
        if (length.first < 0 || length.first > 1 shl 20) return null
        val builder = StringBuilder(length.first)
        var produced = 0
        while (produced < length.first && cursor < bytes.size) {
            val first = bytes[cursor].toInt() and 0xff
            when {
                first == 0 -> return builder.toString()
                first < 0x80 -> {
                    builder.append(first.toChar())
                    cursor += 1
                }
                first and 0xE0 == 0xC0 -> {
                    if (cursor + 1 >= bytes.size) return builder.toString()
                    val second = bytes[cursor + 1].toInt() and 0x3f
                    builder.append((((first and 0x1f) shl 6) or second).toChar())
                    cursor += 2
                }
                first and 0xF0 == 0xE0 -> {
                    if (cursor + 2 >= bytes.size) return builder.toString()
                    val second = bytes[cursor + 1].toInt() and 0x3f
                    val third = bytes[cursor + 2].toInt() and 0x3f
                    builder.append(
                        (((first and 0x0f) shl 12) or (second shl 6) or third).toChar(),
                    )
                    cursor += 3
                }
                else -> return builder.toString()
            }
            produced++
        }
        return builder.toString()
    }

    /** uleb128：返回值 = (数值, 占用字节数)，越界返回 null。 */
    private fun readUleb128(bytes: ByteArray, offset: Int): Pair<Int, Int>? {
        var result = 0
        var shift = 0
        var cursor = offset
        while (cursor < bytes.size && shift < 32) {
            val value = bytes[cursor].toInt() and 0xff
            result = result or ((value and 0x7f) shl shift)
            cursor++
            if (value and 0x80 == 0) return result to (cursor - offset)
            shift += 7
        }
        return null
    }

    /** 小端 u4 → Long（用 Long 承载避免符号位问题）。 */
    private fun u32(bytes: ByteArray, offset: Int): Long {
        if (offset < 0 || offset + 4 > bytes.size) return -1
        return (bytes[offset].toLong() and 0xff) or
            ((bytes[offset + 1].toLong() and 0xff) shl 8) or
            ((bytes[offset + 2].toLong() and 0xff) shl 16) or
            ((bytes[offset + 3].toLong() and 0xff) shl 24)
    }
}
