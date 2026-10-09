package zhou.solab.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AArch64 序言解码的回归锁（用户报告 #7 的 `frameBase` 依赖它）。
 *
 * 第一版实现把 `stp x29,x30,[sp,#-16]!` 的 imm7 当无符号算 → 得到 **+1008** 而不是
 * **-16**（imm7 是有符号 7 位）。这个错不会让任何调用失败，只会让调用方拿着一个
 * 错的栈调整量去换算字段偏移——正是 #7 要消除的那类"整体错一格"。
 *
 * ⚠ 用例里的指令字是**按编码公式算出来的**，不是手写的：
 * `stp x29,x30,[sp,#N]!` = `0xA9800000 | ((N/8 & 0x7F) << 15) | (30<<10) | (31<<5) | 29`
 * （手写十六进制极容易把 -32 写成 -64——第一次就写错了，被这条测试拦下）。
 */
class Arm64PrologueTest {

    private fun decode(vararg insns: Pair<Long, Int>) = Arm64Prologue.decode(insns.toList())

    private fun stpFrame(offsetBytes: Int): Int =
        0xA9800000.toInt() or (((offsetBytes / 8) and 0x7F) shl 15) or (30 shl 10) or (31 shl 5) or 29

    private fun subSp(imm12: Int, shift: Int = 0): Int =
        0xD1000000.toInt() or (shift shl 22) or (imm12 shl 10) or (31 shl 5) or 31

    @Test
    fun stpPreIndexNegativeImmediateIsDecodedSigned() {
        // 标准帧：stp x29, x30, [sp, #-16]!
        assertEquals(0xA9BF7BFD.toInt(), stpFrame(-16))
        val r = decode(0x3d897cL to stpFrame(-16))!!
        assertEquals(-16, r.spAdjustBytes)
        assertTrue(r.text.contains("stp x29, x30, [sp, #-16]!"))
    }

    @Test
    fun stpPreIndexOtherFrameSizesAlsoSigned() {
        // 每一档都必须解出负数（旧实现会给出 +8 / +16 这类正数）
        for (off in listOf(-8, -16, -32, -64, -128)) {
            val r = decode(0x1000L to stpFrame(off))!!
            assertEquals("off=$off 必须解成 $off", off, r.spAdjustBytes)
        }
    }

    @Test
    fun subSpImmediateIsDecoded() {
        assertEquals(0xD10043FF.toInt(), subSp(0x10))
        assertEquals(0x10, decode(0x2000L to subSp(0x10))!!.spAdjustBytes)
        assertEquals(0x40, decode(0x2000L to subSp(0x40))!!.spAdjustBytes)
        // 带 lsl #12：imm12=1, shift=1 → 0x1000
        assertEquals(0xD14007FF.toInt(), subSp(1, 1))
        assertEquals(0x1000, decode(0x2000L to subSp(1, 1))!!.spAdjustBytes)
    }

    @Test
    fun skipsUnrelatedLeadingInstructionsThenFindsPrologue() {
        // 前面夹两条无关指令（如 adrp/ldr 常量池），第 3 条才是序言
        val r = decode(
            0x3000L to 0x90000000.toInt(),
            0x3004L to 0xF9400000.toInt(),
            0x3008L to stpFrame(-16),
        )!!
        assertEquals(-16, r.spAdjustBytes)
        assertTrue("应报告真实地址", r.text.contains("0x3008"))
    }

    @Test
    fun leafFunctionWithoutPrologueReturnsNullInsteadOfGuessing() {
        // 全是普通指令 → 必须回 null（调用方据此如实说"未识别到序言"），不许猜一个数
        assertNull(decode(
            0x4000L to 0xAA0103E0.toInt(), // mov x0, x1
            0x4004L to 0xD65F03C0.toInt(), // ret
        ))
        assertNull(decode())
    }

    @Test
    fun doesNotMistakeOtherStpPairsForTheFramePrologue() {
        // stp x19, x20, [sp, #-16]! 是普通寄存器保存，不是帧序言（Rt != x29）
        val stpX19X20 = 0xA9800000.toInt() or (((-16 / 8) and 0x7F) shl 15) or (20 shl 10) or (31 shl 5) or 19
        assertNull("只认保存 x29 的形态", decode(0x5000L to stpX19X20))
    }

    /**
     * 真机实测形态（第二次踩坑）：Dart AOT 的序言基址**不是 sp**，是 **x15** ——
     * 本设备 libapp.so 里 0x3d897c 的头 8 字节就是 `FD 79 BF A9` = `stp x29, x30, [x15, #-16]!`。
     * 旧实现把 `Rn == sp` 写死进掩码 → 一条都匹配不上 → 1492 字节的真函数被报
     * `no_prologue_found`。现在只匹配形状并**声明基址寄存器**。
     */
    @Test
    fun dartAotPrologueWithX15BaseIsRecognisedAndBaseIsDeclared() {
        val real = 0xA9BF79FD.toInt()   // 设备上 0x3d897c 的首指令
        val r = decode(0x3d897cL to real)!!
        assertEquals(-16, r.spAdjustBytes)
        assertEquals("x15", r.baseRegister)
        assertEquals("x30", r.savedLinkRegister)
        assertTrue(r.text.contains("[x15, #-16]!"))
    }

    @Test
    fun spBasedPrologueStillDeclaresSpAsBase() {
        val r = decode(0x1000L to stpFrame(-16))!!
        assertEquals("sp", r.baseRegister)
        assertEquals(-16, r.spAdjustBytes)
    }
}
