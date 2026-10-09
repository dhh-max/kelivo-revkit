package zhou.solab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import zhou.solab.tools.ArscResourceReader
import zhou.solab.tools.ApkArchiveTool
import java.io.ByteArrayOutputStream

/**
 * A 批回归（2026-09-19 代码审核新发现）。
 *
 * A1：UTF-16 字符串池里 >32767 单元的长串，长度高字节必须 `shl 16`（AOSP 规范）。
 * A5：字符串池头按 headerSize、条数按剩余字节钳制；畸形样本不越界不空转。
 * A6：裸十进制 id 不再被当十六进制；`@string/x` 走 query。
 */
class ArscRobustnessTest {

    /** 造一个只含字符串池的 ResChunk（够 A1/A5 直测 readStringPool）。 */
    private fun stringPool(
        strings: List<String>,
        utf8: Boolean,
        declaredCount: Int = strings.size,
        headerSize: Int = 28,
    ): ByteArray {
        val encoded = strings.map { value ->
            if (utf8) {
                // 规范：UTF-8 池的 string_data 是**两个**长度——UTF-16 单元数 + 字节数
                val bytes = value.toByteArray(Charsets.UTF_8)
                byteArrayOf(value.length.toByte(), bytes.size.toByte()) + bytes + byteArrayOf(0)
            } else {
                if (value.length > 0x7fff) {
                    val bytes = value.toByteArray(Charsets.UTF_16LE)
                    byteArrayOf(
                        ((0x8000 or (value.length ushr 16)) and 0xff).toByte(),
                        (((0x8000 or (value.length ushr 16)) ushr 8) and 0xff).toByte(),
                        (value.length and 0xff).toByte(),
                        ((value.length ushr 8) and 0xff).toByte(),
                    ) + bytes + byteArrayOf(0, 0)
                } else {
                    val bytes = value.toByteArray(Charsets.UTF_16LE)
                    byteArrayOf((value.length and 0xff).toByte(), ((value.length ushr 8) and 0xff).toByte()) +
                        bytes + byteArrayOf(0, 0)
                }
            }
        }
        // 规范：offset 表里的值是「相对字符串数据起点（stringsStart）」的偏移
        val stringsStart = headerSize + encoded.size * 4
        val offsets = IntArray(encoded.size)
        var cursor = 0
        for (index in encoded.indices) {
            offsets[index] = cursor
            cursor += encoded[index].size
        }
        val out = ByteArrayOutputStream()
        fun u16(v: Int) {
            out.write(v and 0xff); out.write((v ushr 8) and 0xff)
        }
        fun u32(v: Int) {
            out.write(v and 0xff); out.write((v ushr 8) and 0xff)
            out.write((v ushr 16) and 0xff); out.write((v ushr 24) and 0xff)
        }
        u16(0x0001); u16(headerSize); u32(stringsStart + cursor)
        u32(declaredCount); u32(0)
        u32(if (utf8) 0x00000100 else 0x00000000)
        u32(stringsStart); u32(0)
        for (index in encoded.indices) u32(offsets[index])
        for (index in encoded.indices) out.write(encoded[index])
        return out.toByteArray()
    }

    @Test
    fun `A1 超过 32767 单元的 UTF-16 长串长度按 shl 16 解码`() {
        val long = "A".repeat(40000)   // >0x7fff，必须走 0x8000 标志分支
        val bytes = stringPool(listOf("short", long), utf8 = false)
        val pool = ArscResourceReader.readStringPool(bytes, 0)
        assertEquals(2, pool.size)
        assertEquals("short", pool[0])
        assertEquals(40000, pool[1].length)
        assertTrue(pool[1].all { it == 'A' })
    }

    @Test
    fun `A5 声明条数超过实际剩余字节时被钳制且不崩`() {
        val bytes = stringPool(listOf("alpha", "beta"), utf8 = true, declaredCount = 9999)
        val pool = ArscResourceReader.readStringPool(bytes, 0)
        assertEquals("alpha", pool[0])
        assertEquals("beta", pool[1])
        // 头部谎报条数：读取必须被钳制在 chunk 内，不得按 9999 空转
        assertTrue("条数应被钳制（实际 ${pool.size}）", pool.size <= 8)
    }

    @Test
    fun `A5 畸形 arsc 不越界不空转`() {
        val garbage = ByteArray(128) { (it * 7 % 251).toByte() }
        // 头部声明为 RES_TABLE 但后续 chunk 全是垃圾：必须快速返回而不是空转
        val fake = ByteArray(64)
        fake[0] = 0x02; fake[1] = 0x00      // RES_TABLE_TYPE
        fake[2] = 0x0c; fake[3] = 0x00      // headerSize=12
        fake[4] = 0xff.toByte(); fake[5] = 0xff.toByte()
        fake[6] = 0xff.toByte(); fake[7] = 0xff.toByte()
        val started = System.currentTimeMillis()
        assertTrue(ArscResourceReader.read(fake).entries.isEmpty())
        assertTrue(ArscResourceReader.read(garbage).entries.isEmpty())
        assertTrue("不应超时空转", System.currentTimeMillis() - started < 2000)
    }

    @Test
    fun `A6 裸十进制按十进制解析、0x 前缀按十六进制、名字形式交给 query`() {
        assertEquals(123, ApkArchiveTool.parseResourceId("123"))
        assertEquals(0x123, ApkArchiveTool.parseResourceId("0x123"))
        assertEquals(0x7f010000, ApkArchiveTool.parseResourceId("0x7f010000"))
        assertEquals(0x7f010000, ApkArchiveTool.parseResourceId("@0x7f010000"))
        assertNull(ApkArchiveTool.parseResourceId("@string/app_name"))
        assertNull(ApkArchiveTool.parseResourceId("not-a-number"))
    }
}
