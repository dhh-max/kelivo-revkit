package zhou.solab.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B1-1 回归：`functionVa` 解析从正则换成手写扫描后，语义必须**逐字节等价**。
 *
 * 这里用原正则作为 oracle 对拍：索引是百万行级，解析器是查询热路径，
 * 一旦不等价就是「搜得到变搜不到」的静默错误。
 */
class BlutterFunctionVaFastPathTest {

    /** oracle = 被替换掉的那条正则（逐字节等价是这次改动的验收条件）。 */
    private val oracle = Regex("\"functionVa\":\"([0-9a-f]+)\"")

    private fun expected(raw: String): Long? =
        oracle.find(raw)?.groupValues?.get(1)?.toLongOrNull(16)

    private val samples = listOf(
        """{"type":"asm","functionVa":"13a4f0","insn":"ldr x0,[x1,#0x10]"}""",
        """{"type":"function","functionVa":"0","function":"main"}""",
        """{"type":"reference","functionVa":"ffffffff","text":"pool 0x1a"}""",
        """{"functionVa":"ABCDEF"}""",                       // 大写十六进制
        """{"type":"asm","insn":"no va here"}""",            // 无字段
        """{"functionVa":""}""",                             // 空值
        """{"functionVa":"12g4"}""",                         // 非十六进制截断
        """{"functionVa":"7fffffffffffffff"}""",             // 大值
        """{"other":"x","functionVa":"ff","tail":"y"}""",
    )

    @Test
    fun `手写解析与原正则逐例等价`() {
        for (raw in samples) {
            assertEquals("sample=$raw", expected(raw), BlutterSearchIndex.functionVaOf(raw))
        }
    }

    @Test
    fun `无字段与空值都返回 null，不误报 0`() {
        assertNull(BlutterSearchIndex.functionVaOf("""{"type":"asm"}"""))
        assertNull(BlutterSearchIndex.functionVaOf("""{"functionVa":""}"""))
        assertTrue(BlutterSearchIndex.functionVaOf("""{"functionVa":"0"}""") == 0L)
    }

    @Test
    fun `大值不溢出（Long 承载 64 位）`() {
        assertEquals(0x7fffffffffffffffL, BlutterSearchIndex.functionVaOf("""{"functionVa":"7fffffffffffffff"}"""))
    }
}
