package zhou.solab.tools

/**
 * 进堆预算判定（**纯函数，无 Android 依赖**，可单测）。
 *
 * 为什么单独抽出来：判定原先内联在 `SolabChannel.checkInputBudget` 里，只能靠
 * 真机跑一次崩溃来发现漏洞。而 2026-09-21 的两次事故都指向同一类问题——
 * **读数或参数反常时门禁没有 fail-closed**：
 *   - 第一次：`budgetMb = 0`（可用堆读数为 0）却仍然放行，任务跑到 16 字节分配处
 *     Java 层 OOM，整个进程死、MCP 服务不可用约 48s；
 *   - 第二次：`apk_rebuild` 的膨胀系数 4.0 远低于实测 10.4，49MiB 输入被放行后
 *     吃满 512MB 堆。
 *
 * 现在把"读数不可信"与"峰值装不下"都做成显式拒绝分支，并配纯函数用例：
 * 只要 `availableMb <= 0`（或低于 [MIN_TRUSTWORTHY_AVAILABLE_MB]），**无论
 * multiplier 是多少都必须拒绝**——不依赖"这次恰好算出了非零预算"。
 */
internal data class InputBudgetDecision(
    val allow: Boolean,
    /** 空串表示放行；否则是机器可读的拒绝原因码。 */
    val code: String,
    val inputMb: Double,
    val budgetMb: Double,
    val availableMb: Double,
    val heapLimitMb: Int,
    val multiplier: Double,
    /** 峰值估算 = inputMb × multiplier。 */
    val peakMb: Double,
    /** 余量比 = budgetMb ÷ inputMb；输入为 0 或读数不可信时为 null（不输出无意义的数）。 */
    val headroomRatio: Double?,
    /** 可用堆读数是否可信（低于阈值即判不可信）。 */
    val readingTrustworthy: Boolean,
) {
    companion object {
        const val OK = ""
        const val UNTRUSTWORTHY_READING = "MEMORY_READING_UNTRUSTWORTHY"
        const val BUDGET_EXHAUSTED = "MEMORY_BUDGET_EXHAUSTED"
        const val INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    }
}

internal object InputBudgetPolicy {
    /**
     * 可用堆读数的最低可信阈值（MB）。低于它一律 fail-closed。
     *
     * 为什么要有这条：ART 的可用堆读数本身会骗人——GC 还没跑时 `freeMemory()` 偏小、
     * 任务间隙又偏大，实测出现过 `budgetMb=0`。与其"信任一个可疑的 0 去参与
     * min() 运算"，不如直接判"读数不可信 → 拒绝"，把不确定性挡在分配之前。
     */
    const val MIN_TRUSTWORTHY_AVAILABLE_MB = 10.0

    /** 只花剩余可增长堆的 80%，留 20% 给 Flutter 引擎与运行时自身分配。 */
    const val FREE_SHARE = 0.8

    /** 无论看起来多空都不许超过总堆的 60%，防"任务间隙快照虚高"。 */
    const val HEAP_SHARE = 0.6

    fun decide(
        inputMb: Double,
        availableMb: Double,
        heapLimitMb: Int,
        multiplier: Double,
    ): InputBudgetDecision {
        // 系数异常（0/负/NaN/Inf）一律按"最保守"处理：预算趋 0 → 拒绝。
        // 别让一个坏参数把门禁变成放行开关。
        val safeMultiplier =
            if (multiplier.isFinite() && multiplier > 0.0) multiplier else Double.MAX_VALUE
        val safeAvailable = if (availableMb.isFinite()) availableMb else 0.0
        val safeHeap = if (heapLimitMb > 0) heapLimitMb.toDouble() else 0.0
        val safeInput = if (inputMb.isFinite() && inputMb > 0) inputMb else 0.0

        val spendable = minOf(safeAvailable * FREE_SHARE, safeHeap * HEAP_SHARE)
        val budgetMb = if (spendable > 0.0) spendable / safeMultiplier else 0.0
        val peakMb = safeInput * safeMultiplier
        val trustworthy = safeAvailable >= MIN_TRUSTWORTHY_AVAILABLE_MB

        fun decision(allow: Boolean, code: String) = InputBudgetDecision(
            allow = allow,
            code = code,
            inputMb = safeInput,
            budgetMb = budgetMb,
            availableMb = safeAvailable,
            heapLimitMb = heapLimitMb,
            multiplier = multiplier,
            peakMb = peakMb,
            headroomRatio = if (safeInput > 0.0 && budgetMb > 0.0) budgetMb / safeInput else null,
            readingTrustworthy = trustworthy,
        )

        // 顺序刻意：先判"读数可不可信"，再判"预算够不够"，最后判"峰值装不装得下"。
        if (!trustworthy) return decision(false, InputBudgetDecision.UNTRUSTWORTHY_READING)
        if (budgetMb <= 0.0) return decision(false, InputBudgetDecision.BUDGET_EXHAUSTED)
        if (safeInput > budgetMb) return decision(false, InputBudgetDecision.INPUT_TOO_LARGE)
        return decision(true, InputBudgetDecision.OK)
    }
}
