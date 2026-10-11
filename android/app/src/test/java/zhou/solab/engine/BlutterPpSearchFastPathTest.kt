package zhou.solab.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * B1-4 回归（2026-09-19）：pp.txt 搜索的行 lowercase 单趟化。
 *
 * 旧实现对每个词条各调一次 `contains`，忽略大小写时**每词重转一次整行**
 * lowercase（几十万行 × N 词 = 数百万次大字符串分配）。改成整行只转一次后
 * 语义必须不变——这里用旧实现（`contains`）作 oracle 逐行对拍，并锁住
 * 命中行的 300 字符截断与 limit 截断标记。
 */
class BlutterPpSearchFastPathTest {

    private fun resultDir(lines: List<String>): File {
        val dir = Files.createTempDirectory("blutter-pp-search-").toFile()
        File(dir, "pp.txt").writeText(lines.joinToString("\n") + "\n")
        return dir
    }

    @Test
    fun `行级多词命中与旧实现逐行等价（含大小写与多词）`() {
        val lines = listOf(
            "[pp+0x1234] Vip Member State",
            "[pp+0x2222] vip only",
            "[pp+0x3333] MEMBER and vip",
            "[pp+0x4444] nothing here",
            "[pp+0x5555] vip member 混合 会员 member",
        )
        // searchQueries 在忽略大小写时会先把词条小写化，这里模拟同样的输入
        val queries = listOf("vip", "member")
        for (line in lines) {
            val oracle = queries.filter {
                BlutterSearchIndex.contains(line, it, caseInsensitive = true)
            }
            assertEquals(
                "line=$line",
                oracle,
                BlutterSearchIndex.matchedQueriesOf(line, queries, caseInsensitive = true),
            )
        }
    }

    @Test
    fun `大小写敏感路径不做 lowercase，语义与旧实现一致`() {
        val line = "[pp+0x1234] Vip Member"
        assertEquals(
            listOf("Vip"),
            BlutterSearchIndex.matchedQueriesOf(
                line, listOf("Vip", "vip"), caseInsensitive = false,
            ),
        )
        assertTrue(
            BlutterSearchIndex.matchedQueriesOf(
                line, listOf("vip"), caseInsensitive = false,
            ).isEmpty(),
        )
    }

    @Test
    fun `searchPp 命中行截断到 300 字符且 limit 触发 truncated`() {
        val long = "x".repeat(900)
        val dir = resultDir(
            listOf(
                "[pp+0x11] vip $long",
                "[pp+0x22] vip second",
                "[pp+0x33] vip third",
            ),
        )
        val result = BlutterSearchIndex.searchPp(dir, "vip", caseInsensitive = true, limit = 2)
        assertEquals(2, result.optInt("count"))
        assertTrue("到达 limit 必须自报 truncated", result.optBoolean("truncated"))
        val first = result.optJSONArray("matches")!!.optJSONObject(0)!!
        assertTrue("命中行必须截断输出", first.optString("text").length <= 300)
        assertEquals("0x11", first.optString("offset"))
        assertFalse(first.optJSONArray("matchedQueries")!!.length() == 0)
    }
}
