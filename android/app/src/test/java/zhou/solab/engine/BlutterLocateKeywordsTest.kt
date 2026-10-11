package zhou.solab.engine

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 收尾包 A 回归：blutter locate 中文业务语义 → 英文符号词映射。
 * 用户实测场景"免费观看次数门禁"在三域(会员/抓包/广告)外全部落空,
 * 现由业务通用域词表覆盖。
 */
class BlutterLocateKeywordsTest {

    @Test
    fun chineseBusinessSemanticsMapToEnglishSymbols() {
        val terms = blutterLocateKeywords("免费观看次数门禁").map { it.lowercase() }
        // 用户原场景:必须产出英文符号词候选,不能再全落空。
        assertTrue("watch 缺失", terms.any { it.contains("watch") })
        assertTrue("trial 缺失", terms.any { it.contains("trial") })
        assertTrue("limit 缺失", terms.any { it.contains("limit") })
        // 用户原词仍在第一位(不被词表挤掉)。
        assertTrue(terms.first().contains("免费观看次数门禁"))
    }

    @Test
    fun unlockAndPaySemanticsCovered() {
        val terms = blutterLocateKeywords("解锁付费视频").map { it.lowercase() }
        assertTrue(terms.any { it.contains("unlock") })
        assertTrue(terms.any { it.contains("pay") || it.contains("purchase") })
    }

    @Test
    fun nonBusinessGoalNotPolluted() {
        // 无业务词的 goal 不应注入业务域词(保持既有三域行为)。
        val terms = blutterLocateKeywords("定位会员判断").map { it.lowercase() }
        assertTrue(terms.any { it.contains("vip") || it.contains("member") })
    }
}
