package zhou.solab.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * B1-2 倒排回归（2026-09-19）。
 *
 * 最要紧的两条性质：
 * 1. **并集语义**——批量查询是 OR（命中任一即算），候选必须取各词元 postings 的并集；
 *    取"最稀有词元"会漏掉只命中其它词的行（这正是第一次实现触发
 *    BlutterSearchIndexTest.asmSearchBatchesTermsAndAvoidsRawDirectoryScanByDefault 的根因）。
 * 2. **缺词回退**——任一词元不在倒排里就返回 null（整体回退扫描），绝不当作零命中。
 */
class SemanticPostingsTest {

    @Test
    fun `词元化：小写、切分、CJK 保留、过短丢弃、有上限`() {
        val tokens = SemanticPostings.tokens("Vip_Member.isPremium 会员状态 a b c")
        assertTrue(tokens.contains("vip_member"))
        assertTrue(tokens.contains("ispremium"))
        assertTrue(tokens.contains("会员状态"))
        assertTrue(tokens.none { it.length < 3 })
        val many = SemanticPostings.tokens((1..200).joinToString(" ") { "token$it" })
        assertTrue(many.size <= 48)
        assertEquals(many.size, many.distinct().size)
    }

    @Test
    fun `候选取并集而不是最稀有词元`() {
        val postings = mapOf(
            "vip" to intArrayOf(1, 5, 9),
            "member" to intArrayOf(5),
        )
        // OR 语义：vip 或 member 命中的行都要进候选（并集 = {1,5,9}）
        assertEquals(
            listOf(1, 5, 9),
            SemanticPostings.candidates(postings, listOf("vip", "member"))!!.toList(),
        )
        // 单侧命中同样在候选里
        assertTrue(SemanticPostings.candidates(postings, listOf("member"))!!.toList() == listOf(5))
    }

    @Test
    fun `任一词元缺失一律回退（不产生假阴性）`() {
        val postings = mapOf("vip" to intArrayOf(1))
        assertNull(SemanticPostings.candidates(postings, listOf("vip", "absent_term")))
        assertNull(SemanticPostings.candidates(postings, emptyList()))
        assertNull(SemanticPostings.candidates(null, listOf("vip")))
    }

    @Test
    fun `写读往返：升序 rowId 与词条一致`() {
        val dir = Files.createTempDirectory("postings-roundtrip-").toFile()
        SemanticPostings.write(
            dir,
            mapOf(
                "vip" to intArrayOf(0, 3, 7),
                "会员状态" to intArrayOf(42),
            ),
        )
        val loaded = SemanticPostings.read(dir)!!
        assertEquals(listOf(0, 3, 7), loaded["vip"]!!.toList())
        assertEquals(listOf(42), loaded["会员状态"]!!.toList())
    }

    @Test
    fun `倒排文件缺失时读取返回 null（回退而非报错）`() {
        val dir = Files.createTempDirectory("postings-absent-").toFile()
        assertNull(SemanticPostings.read(dir))
    }
}
