package zhou.solab

import org.junit.Assert.assertTrue
import org.junit.Test
import zhou.solab.tools.KotlinToolStats

/**
 * C 批/D4 读数出口回归：`KotlinToolStats.record` 之后 `snapshot()` 必须能看到。
 *
 * 背景：blutter 语义索引的三指标（构建耗时 / 索引体积 / 查询耗时）此前只落
 * SharedPreferences，**没有任何对外出口**——设备恢复后也读不到数，优化只能靠体感。
 * 现在通过 `get_workspace_policy(includeToolStats=true)` 暴露，这条测试锁住
 * "记账 → 快照可见"这条链不断。
 */
class KotlinToolStatsTest {

    @Test
    fun `record 之后 snapshot 能看到该工具的次数与耗时`() {
        KotlinToolStats.record(tool = "blutter.index.search", success = true, micros = 1234)
        KotlinToolStats.record(tool = "blutter.index.search", success = false, micros = 4321, error = "boom")
        val snapshot = KotlinToolStats.snapshot()
        val tools = snapshot.optJSONArray("tools") ?: snapshot.optJSONArray("stats")
        assertTrue("快照必须包含 tools/stats 数组", tools != null)
        var found = false
        for (index in 0 until tools!!.length()) {
            val item = tools.optJSONObject(index) ?: continue
            if (item.optString("tool") != "blutter.index.search") continue
            found = true
            assertTrue("调用次数应 >= 2", item.optInt("calls") >= 2)
            assertTrue("应记录失败次数", item.optInt("failed") >= 1)
        }
        assertTrue("快照里应能看到刚记账的工具", found)
    }
}
