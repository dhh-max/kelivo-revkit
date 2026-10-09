package zhou.solab

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import zhou.solab.tools.SolabStringScanTool

/**
 * C1 复查项：email 误报过滤（DEF-15 / isNoiseEmail）不能反过来误杀正常邮箱。
 *
 * 背景：Flutter 包扫描里 Dart AOT 符号（`p@A.1`、`_GrowableList@0150898._literal`）
 * 会被旧正则当邮箱，扫描结论因此不可信；收紧后必须仍然保留正常短域地址。
 */
class StringScanEmailNoiseTest {

    @Test
    fun `正常邮箱（含短域）不被当噪音`() {
        assertFalse(SolabStringScanTool.isNoiseEmail("a@b.co"))
        assertFalse(SolabStringScanTool.isNoiseEmail("user@example.com"))
        assertFalse(SolabStringScanTool.isNoiseEmail("first.last+tag@sub.example.org"))
        assertFalse(SolabStringScanTool.isNoiseEmail("support@x.io"))
    }

    @Test
    fun `Dart AOT 符号与伪邮箱被当噪音`() {
        assertTrue(SolabStringScanTool.isNoiseEmail("p@A.1"))            // TLD 为数字
        assertTrue(SolabStringScanTool.isNoiseEmail("p@A.B4i"))          // TLD 含数字
        assertTrue(SolabStringScanTool.isNoiseEmail("_GrowableList@0150898._literal")) // 域为纯数字
        assertTrue(SolabStringScanTool.isNoiseEmail("android@android.com0"))          // TLD 含数字
        assertTrue(SolabStringScanTool.isNoiseEmail("@example.com"))     // 本地部分为空
        assertTrue(SolabStringScanTool.isNoiseEmail("user@"))            // 域为空
        assertTrue(SolabStringScanTool.isNoiseEmail("user@host"))        // 无 TLD
    }
}
