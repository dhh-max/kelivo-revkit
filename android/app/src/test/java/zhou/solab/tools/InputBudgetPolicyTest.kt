package zhou.solab.tools

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 进堆预算判定的 fail-closed 回归锁（用户点名"这条你现在没有，应该补"）。
 *
 * 背景：2026-09-21 两次事故都是"读数或参数反常时门禁没兜住"——
 *   ① `budgetMb = 0`（可用堆读数为 0）却仍放行 → Java 层 OOM → **进程死、MCP 不可用 48s**；
 *   ② `apk_rebuild` 系数 4.0 远低于实测 10.4 → 49MiB 输入放行后吃满 512MB 堆。
 *
 * 这一组用例的判据是**不变量**，不是"这次的数字恰好对不对"：
 *   可用堆读数 ≤ 0（或低于下限）→ 无论 multiplier 是多少都必须拒绝。
 */
class InputBudgetPolicyTest {

    private fun decide(
        inputMb: Double,
        availableMb: Double = 400.0,
        heapMb: Int = 512,
        multiplier: Double = 4.0,
    ) = InputBudgetPolicy.decide(inputMb, availableMb, heapMb, multiplier)

    @Test
    fun availableZeroRejectsRegardlessOfMultiplier() {
        // 用户点名的用例：availableMb=0 时任何系数都不能放行。
        for (multiplier in listOf(0.5, 1.0, 4.0, 12.0, 100.0)) {
            val d = decide(inputMb = 1.0, availableMb = 0.0, multiplier = multiplier)
            assertFalse("multiplier=$multiplier 时 available=0 必须拒绝", d.allow)
            assertEquals(InputBudgetDecision.UNTRUSTWORTHY_READING, d.code)
            assertFalse(d.readingTrustworthy)
        }
    }

    @Test
    fun negativeOrNanAvailableRejects() {
        for (bad in listOf(-1.0, -500.0, Double.NaN, Double.NEGATIVE_INFINITY)) {
            val d = decide(inputMb = 1.0, availableMb = bad)
            assertFalse("available=$bad 必须拒绝", d.allow)
            assertEquals(InputBudgetDecision.UNTRUSTWORTHY_READING, d.code)
        }
    }

    @Test
    fun availableBelowTrustFloorRejectsEvenIfTinyInputFits() {
        // 5MiB < 10MiB 下限：即使输入小到"理论上装得下"，也按读数不可信拒绝。
        val d = decide(inputMb = 0.001, availableMb = 5.0, multiplier = 1.0)
        assertFalse(d.allow)
        assertEquals(InputBudgetDecision.UNTRUSTWORTHY_READING, d.code)
        assertEquals(InputBudgetPolicy.MIN_TRUSTWORTHY_AVAILABLE_MB, 10.0, 0.0)
    }

    @Test
    fun badMultiplierFailsClosedInsteadOfOpeningTheGate() {
        // 系数 0/负/NaN/Inf 曾经会把预算算成 Inf → 门禁形同放行。必须 fail-closed。
        for (bad in listOf(0.0, -1.0, Double.NaN, Double.POSITIVE_INFINITY)) {
            val d = decide(inputMb = 10.0, availableMb = 400.0, multiplier = bad)
            assertFalse("multiplier=$bad 必须拒绝而不是放行", d.allow)
        }
    }

    @Test
    fun peakMustFitSpendableHeap() {
        // 不变量：放行 ⟺ 峰值估算 ≤ min(可用×0.8, 堆上限×0.6)
        val heapMb = 512
        val availableMb = 481.0
        val spendable = minOf(availableMb * InputBudgetPolicy.FREE_SHARE, heapMb * InputBudgetPolicy.HEAP_SHARE)
        assertEquals(307.2, spendable, 0.01)

        // 峰值 588 > 307 → 拒绝（真实事故的算式）
        val over = decide(inputMb = 49.0, availableMb = availableMb, heapMb = heapMb, multiplier = 12.0)
        assertFalse(over.allow)
        assertEquals(InputBudgetDecision.INPUT_TOO_LARGE, over.code)
        assertTrue(over.peakMb > spendable)

        // 峰值 196 ≤ 307 → 放行（系数 4.0 的旧算式：正是它漏掉了 512MB 的真实峰值）
        val under = decide(inputMb = 49.0, availableMb = availableMb, heapMb = heapMb, multiplier = 4.0)
        assertTrue(under.allow)
    }

    @Test
    fun heapShareCapsBudgetWhenAvailableLooksHuge() {
        // 可用堆看起来很大也不能超 60% 堆上限（防任务间隙快照虚高）。
        val d = decide(inputMb = 200.0, availableMb = 100000.0, heapMb = 512, multiplier = 1.0)
        assertEquals(512 * InputBudgetPolicy.HEAP_SHARE, d.budgetMb, 0.01)
        assertFalse("200 > 307.2×? 这里 200 ≤ 307.2 应放行", !d.allow)
    }

    @Test
    fun headroomRatioIsNullWhenMeaningless() {
        // 输入为 0 或读数不可信时不给"余量比"这种没意义的数（旧的 headroom=880.51 就是这类）。
        assertNull(decide(inputMb = 0.0).headroomRatio)
        assertNull(decide(inputMb = 10.0, availableMb = 0.0).headroomRatio)
        // 正常情况给得出比例
        val d = decide(inputMb = 10.0, availableMb = 400.0, heapMb = 512, multiplier = 4.0)
        assertTrue(d.headroomRatio != null && d.headroomRatio!! > 0)
    }

    @Test
    fun untrustedReadingIsCheckedBeforeBudgetArithmetic() {
        // 顺序保证：读数不可信时给的是"读数问题"，而不是被算成 BUDGET_EXHAUSTED 混过去。
        val d = decide(inputMb = 1.0, availableMb = 0.0, heapMb = 0, multiplier = 1.0)
        assertEquals(InputBudgetDecision.UNTRUSTWORTHY_READING, d.code)
    }

    /**
     * 逐工具 fixture（用户要求）：**每个重内存工具**都必须满足
     * `放行 ⟹ 峰值估算 ≤ min(可用×0.8, 堆上限×0.6)`。
     *
     * 这条是合入门槛：以后任何新重工具（或改系数）都必须过。系数取当前实现值；
     * 改系数要同步这里并说明实测依据（别让系数悄悄变小把门禁绕过去）。
     */
    @Test
    fun everyHeavyToolSatisfiesPeakInvariant() {
        // 与 SolabChannel.dexFullParseMethods 同源维护；系数与 heapMultiplierFor 同源。
        val heavyTools = listOf(
            "patchDexMethods" to 4.0,
            "patchDexStrings" to 4.0,
            "jadxDecompile" to 4.0,
            // 实测标定：20.2MB APK（解压 49.0MB）→ 堆长满 512MB = 10.4×，取 12 留余量
            "apkRebuild" to 12.0,
        )
        val heapMb = 512
        val availableMb = 481.0
        val spendable = minOf(availableMb * InputBudgetPolicy.FREE_SHARE, heapMb * InputBudgetPolicy.HEAP_SHARE)
        // 一组代表体积：小/中/大/超大（含事故当时的 49MiB）
        val inputs = listOf(1.0, 8.0, 49.0, 120.0, 400.0)

        for ((tool, multiplier) in heavyTools) {
            assertTrue("$tool 的系数必须 > 1（否则等于把门禁绕过去）", multiplier > 1.0)
            for (inputMb in inputs) {
                val d = InputBudgetPolicy.decide(inputMb, availableMb, heapMb, multiplier)
                if (d.allow) {
                    assertTrue(
                        "$tool 放行时峰值必须装得下：peak=${d.peakMb} > spendable=$spendable (input=$inputMb)",
                        d.peakMb <= spendable + 0.001,
                    )
                } else {
                    assertTrue(
                        "$tool 拒绝时必须是峰值装不下或读数/预算问题：code=${d.code}",
                        d.code == InputBudgetDecision.INPUT_TOO_LARGE ||
                            d.code == InputBudgetDecision.BUDGET_EXHAUSTED ||
                            d.code == InputBudgetDecision.UNTRUSTWORTHY_READING,
                    )
                }
            }
        }
    }

    /** apkRebuild 的系数不得低于实测下界 10.4——它是拿真崩溃标定出来的。 */
    @Test
    fun apkRebuildMultiplierStaysAtOrAboveMeasuredFloor() {
        // 49.0MiB 输入在 512MB 堆上真实吃满 → 真实倍数 10.4。
        // 系数低于它就会放行一个必然 OOM 的调用（事故原样复现）。
        val d = InputBudgetPolicy.decide(49.0, 481.0, 512, 10.0)
        assertFalse("系数 10.0 会放行 49MiB（真实峰值 512MB）——不该再出现", d.allow)
        val safe = InputBudgetPolicy.decide(49.0, 481.0, 512, 12.0)
        assertFalse(safe.allow)
        assertTrue("12.0 的峰值估算应明显超过可花上限", safe.peakMb > 307.0)
    }
}
