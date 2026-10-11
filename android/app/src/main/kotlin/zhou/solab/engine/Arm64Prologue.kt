package zhou.solab.engine

/**
 * AArch64 函数序言解码（纯函数，可单测）。
 *
 * 用途：`rz_decompile` 的 `frameBase` 声明（用户报告 #7）需要把"函数入口做了多少栈调整、
 * 以哪个寄存器为帧基"告诉调用方——伪代码的变量基与原始反汇编的 `fp/x29` 不是同一个基，
 * 不换算就整体错一格（实测把 `isVip` 判成字段 0x13，产出能跑但无效的补丁）。
 *
 * 两次踩坑（都由真机/单测暴露，别再踩）：
 *  ① `imm7` 是**有符号** 7 位：`stp x29,x30,[sp,#-16]!` 的 imm7 = -2，当无符号算会得到 +1008。
 *  ② 帧基**不一定是 sp**：Dart AOT 实测序言是 `stp x29, x30, [x15, #-16]!` —— 基址是
 *     **x15**（就是伪代码里 `in_x15` 那个寄存器）。把 `Rn == sp` 写死进掩码会一条都匹配不上，
 *     于是"有真序言的 1492 字节函数"也被报成 `no_prologue_found`（真机实测）。
 *     现在只匹配指令**形状**，基址寄存器读出来并如实声明。
 */
internal object Arm64Prologue {

    /** 一条指令的帧基结论。 */
    internal data class Result(
        /** 栈调整字节数（负数表示向下增长）。 */
        val spAdjustBytes: Int,
        /** 帧基寄存器名：`sp` 或 `x<N>`（Dart AOT 常见 x15）。 */
        val baseRegister: String,
        /** 保存的第二个寄存器（通常是 x30 = LR），无则 null。 */
        val savedLinkRegister: String?,
        val text: String,
    )

    /** STP 的形状位（bit31-22）：64 位、STP、pre-index、store。 */
    private const val STP_PREINDEX_SHAPE = 0xA9800000.toInt()
    private const val STP_SHAPE_MASK = 0xFFC00000.toInt()

    /** SUB (immediate) 的形状位，且 Rn = Rd = sp。 */
    private const val SUB_SP_SHAPE = 0xD10003FF.toInt()
    private const val SUB_SP_MASK = 0xFF8003FF.toInt()

    private fun regName(index: Int): String = if (index == 31) "sp" else "x$index"

    /**
     * 在 [insns]（地址 → 指令字）里找第一条标准序言。
     * 找不到返回 null（叶子函数 / 未用帧指针 / 起点不是函数头——都是正常情形，
     * 调用方应如实回 "未识别到序言" 而不是猜一个数）。
     */
    internal fun decode(insns: List<Pair<Long, Int>>): Result? {
        for ((addr, insn) in insns) {
            // stp x29, <lr>, [<base>, #imm7*8]!  —— pre-index 写回，保存 x29 = 帧指针
            if ((insn and STP_SHAPE_MASK) == STP_PREINDEX_SHAPE) {
                val rt = insn and 0x1F
                // 只认"保存 x29"的形态：x19/x20 之类的普通寄存器保存不是帧序言
                if (rt == 29) {
                    val rawImm = (insn ushr 15) and 0x7F
                    val imm = if (rawImm >= 0x40) rawImm - 0x80 else rawImm
                    val adjust = imm * 8
                    val rt2 = (insn ushr 10) and 0x1F
                    val rn = (insn ushr 5) and 0x1F
                    val base = regName(rn)
                    val lr = if (rt2 == 30) "x30" else regName(rt2)
                    return Result(
                        spAdjustBytes = adjust,
                        baseRegister = base,
                        savedLinkRegister = lr,
                        text = "stp x29, $lr, [$base, #%d]! @ 0x%x".format(adjust, addr),
                    )
                }
            }
            // sub sp, sp, #imm12[, lsl #12]  —— 无帧指针的纯栈分配
            if ((insn and SUB_SP_MASK) == SUB_SP_SHAPE) {
                val imm12 = (insn ushr 10) and 0xFFF
                val shift = (insn ushr 22) and 0x3
                val adjust = imm12 shl (12 * shift)
                return Result(
                    spAdjustBytes = adjust,
                    baseRegister = "sp",
                    savedLinkRegister = null,
                    text = "sub sp, sp, #0x%x @ 0x%x".format(adjust, addr),
                )
            }
        }
        return null
    }
}
