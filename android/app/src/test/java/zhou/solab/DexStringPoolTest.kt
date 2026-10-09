package zhou.solab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import zhou.solab.tools.DexStringPool
import java.io.ByteArrayOutputStream

/**
 * DEX 字符串池读取回归（2026-09-19 全量复测 DEF-11）。
 *
 * 复测现象：`apk_archive(action=strings, entry=classes.dex)` 返回
 * `>!>0>G>n>` 这类 id 表噪音——因为它对任意条目做「从头顺序扫可打印串」，
 * 而 DEX 的字符串数据在 data 区，前面全是二进制 id 表。
 */
class DexStringPoolTest {

    /** 手工构造最小 DEX：header + string_ids + string_data（含中文/长串/重复）。 */
    private fun buildDex(strings: List<String>): ByteArray {
        val headerSize = 0x70
        val stringIdsOff = headerSize
        val dataOff = stringIdsOff + strings.size * 4
        val data = ByteArrayOutputStream()
        val offsets = IntArray(strings.size)
        strings.forEachIndexed { index, value ->
            offsets[index] = dataOff + data.size()
            val bytes = value.toByteArray(Charsets.UTF_8)
            // uleb128(utf16 长度)：测试串都短于 128
            data.write(value.length)
            data.write(bytes)
        }
        val stringData = data.toByteArray()

        val out = ByteArray(headerSize + strings.size * 4 + stringData.size)
        // magic + version
        "dex\n035\u0000".toByteArray(Charsets.US_ASCII).copyInto(out, 0)
        fun writeU4(offset: Int, value: Int) {
            out[offset] = (value and 0xff).toByte()
            out[offset + 1] = ((value shr 8) and 0xff).toByte()
            out[offset + 2] = ((value shr 16) and 0xff).toByte()
            out[offset + 3] = ((value shr 24) and 0xff).toByte()
        }
        writeU4(0x20, out.size) // file_size
        writeU4(0x24, headerSize) // header_size
        writeU4(0x28, 0x12345678) // endian_tag
        writeU4(0x38, strings.size) // string_ids_size
        writeU4(0x3C, stringIdsOff) // string_ids_off
        strings.indices.forEach { index ->
            writeU4(stringIdsOff + index * 4, offsets[index])
        }
        stringData.copyInto(out, stringIdsOff + strings.size * 4)
        return out
    }

    @Test
    fun `读取字符串池并保持 dex 内顺序`() {
        val dex = buildDex(listOf("alpha", "beta-gamma", "delta"))
        assertTrue(DexStringPool.looksLikeDex(dex))
        assertEquals(
            listOf("alpha", "beta-gamma", "delta"),
            DexStringPool.read(dex, minLen = 3, limit = 10),
        )
    }

    @Test
    fun `minLen 与 limit 生效`() {
        val dex = buildDex(listOf("a", "bb", "ccc", "dddd", "eeeee"))
        assertEquals(
            listOf("ccc", "dddd", "eeeee"),
            DexStringPool.read(dex, minLen = 3, limit = 10),
        )
        assertEquals(
            listOf("ccc", "dddd"),
            DexStringPool.read(dex, minLen = 3, limit = 2),
        )
    }

    @Test
    fun `query 过滤不再被忽略`() {
        val dex = buildDex(listOf("https://example.com/api", "com.example.app", "unrelated"))
        assertEquals(
            listOf("https://example.com/api"),
            DexStringPool.read(dex, minLen = 4, limit = 10, query = "HTTP"),
        )
        assertEquals(
            listOf("com.example.app"),
            DexStringPool.read(dex, minLen = 4, limit = 10, query = "com.example"),
        )
    }

    @Test
    fun `UTF-8 多字节串（中文）按长度正确截断`() {
        val dex = buildDex(listOf("会员状态栏", "vip_", "普通用户列表"))
        // minLen=5 排除 4 字符的 "vip_"，只留 5/6 字的中文串
        val values = DexStringPool.read(dex, minLen = 5, limit = 10)
        assertEquals(listOf("会员状态栏", "普通用户列表"), values)
    }

    @Test
    fun `非 DEX 字节不被误判`() {
        assertFalse(DexStringPool.looksLikeDex("PK\u0003\u0004".toByteArray()))
        assertTrue(DexStringPool.read(ByteArray(16), minLen = 3, limit = 5).isEmpty())
    }
}
