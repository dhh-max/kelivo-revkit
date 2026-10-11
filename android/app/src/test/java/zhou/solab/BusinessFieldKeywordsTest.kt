package zhou.solab

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 业务敏感字段词表回归锁。
 *
 * 起因（真机实测缺陷）：`analyze_business_state(isProxy)` 把腾讯网络栈的
 * `Lanet/channel/statist/SessionStatistic;->isProxy:I` 当成会员字段，
 * 并以 0.95 + writer_confirmed 的高置信呈现给下游 Agent。
 * 根因之一是词表裸子串匹配 `ispro` ⊂ `isproxy`。
 *
 * 本测试锁两件事：
 * 1. 段边界语义（假阳性不再出现）
 * 2. 词表可覆写 + 规范化行为
 */
class BusinessFieldKeywordsTest {

    @After
    fun tearDown() {
        // 静态状态必须复位，否则污染后续用例。
        BusinessFieldKeywords.overrideWith(null)
    }

    // ---- 默认词表 ----

    @Test
    fun defaultTableCoversVipAndExpireFamilies() {
        val kw = BusinessFieldKeywords.effective()
        assertTrue(kw.contains("isvip"))
        assertTrue(kw.contains("viplevel"))
        assertTrue(kw.contains("vipexpire"))
        assertTrue(kw.contains("expiretime"))
        assertTrue(kw.contains("ismember"))
    }

    @Test
    fun defaultTableEntriesAreNormalized() {
        // 词表项必须全小写、无分隔符——否则永远匹配不上段拼接结果。
        for (kw in BusinessFieldKeywords.effective()) {
            assertEquals("词表项未小写: $kw", kw, kw.lowercase())
            assertFalse("词表项含下划线: $kw", kw.contains("_"))
            assertFalse("词表项含美元符: $kw", kw.contains("\$"))
            assertFalse("词表项含空格: $kw", kw.contains(" "))
        }
    }

    /**
     * 段边界核心回归：`ispro` 不得匹配 `isProxy` 这类更长单词。
     *
     * 这里复刻 `ApkModuleAnalyzer.matchFieldName` 的判定逻辑，
     * 保证词表与匹配器的契约一致。
     */
    @Test
    fun isproDoesNotMatchIsProxyFamily() {
        val keywords = BusinessFieldKeywords.effective()
        // 这些字段在真机上是腾讯网络栈/无关业务，绝不能被 ispro 收进来。
        for (name in listOf("isProxy", "isProtected", "isProduct", "isPromise")) {
            assertFalse(
                "段边界失效：$name 被词表误收",
                matches(name, keywords),
            )
        }
    }

    @Test
    fun vipFamilyStillMatchesAfterSegmentBoundaryRule() {
        // 真阳性不能因收紧规则而丢失。
        val keywords = BusinessFieldKeywords.effective()
        for (name in listOf("isVip", "vipLevel", "userVipFlag", "vipExpireTime")) {
            assertTrue("真阳性丢失：$name 未命中", matches(name, keywords))
        }
    }

    /**
     * recall 缺口回归（本测试最初抓到的真实缺陷）：
     * `userVipFlag` 拆成 [user, vip, flag]，词表项 `vipflag` 需匹配
     * **连续段子序列** `vip`+`flag`，而不是整名拼接 `uservipflag`。
     */
    @Test
    fun prefixedFieldStillMatchesInnerContiguousSegments() {
        val keywords = BusinessFieldKeywords.effective()
        assertTrue("userVipFlag 未命中（段子序列逻辑缺失）", matches("userVipFlag", keywords))
        assertTrue("user_vip_expire_time 未命中", matches("user_vip_expire_time", keywords))
        assertTrue("currentMemberExpire 未命中", matches("currentMemberExpire", keywords))
    }

    // ---- 覆写 ----

    @Test
    fun overrideReplacesDefaults() {
        BusinessFieldKeywords.overrideWith(listOf("trial", "freespin"))
        val kw = BusinessFieldKeywords.effective()
        assertEquals(2, kw.size)
        assertTrue(kw.contains("trial"))
        // 默认词表被整体替换，不是追加。
        assertFalse(kw.contains("isvip"))
    }

    @Test
    fun overrideNormalizesSeparatorsAndCase() {
        // 调用方写成 vip_level / IS_VIP 也应能命中——统一规范化。
        // 注意 `IS$VIP` 里的 $ 在 Kotlin 字符串模板中要转义。
        BusinessFieldKeywords.overrideWith(
            listOf("  VIP_Level  ", "IS\$VIP", "is trial"),
        )
        val kw = BusinessFieldKeywords.effective()
        assertTrue(kw.contains("viplevel"))
        assertTrue(kw.contains("isvip"))
        assertTrue(kw.contains("istrial"))
    }

    @Test
    fun overrideDedupsAndDropsBlanks() {
        BusinessFieldKeywords.overrideWith(listOf("vip", "VIP", " vip ", "", "   "))
        assertEquals(listOf("vip"), BusinessFieldKeywords.effective())
    }

    @Test
    fun nullOrEmptyOverrideRestoresDefault() {
        BusinessFieldKeywords.overrideWith(listOf("trial"))
        BusinessFieldKeywords.overrideWith(null)
        assertEquals(BusinessFieldKeywords.default, BusinessFieldKeywords.effective())

        BusinessFieldKeywords.overrideWith(listOf("x"))
        BusinessFieldKeywords.overrideWith(emptyList())
        assertEquals(BusinessFieldKeywords.default, BusinessFieldKeywords.effective())

        // 全空白等同空——不能把词表清成空导致全量候选丢失。
        BusinessFieldKeywords.overrideWith(listOf("  ", ""))
        assertEquals(BusinessFieldKeywords.default, BusinessFieldKeywords.effective())
    }

    // ---- 辅助：直接调用生产实现的段边界判定 ----

    /**
     * 用**生产代码**的判定函数，不在测试里复刻逻辑——
     * 复刻会让两边漂移，测试绿了但线上仍是坏的。
     */
    private fun matches(rawName: String, keywords: List<String>): Boolean =
        ApkModuleAnalyzer.matchBusinessFieldNameForTest(rawName, keywords)
}
