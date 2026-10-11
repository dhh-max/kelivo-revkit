package zhou.solab

import org.jf.dexlib2.AccessFlags
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.immutable.ImmutableClassDef
import org.jf.dexlib2.immutable.ImmutableDexFile
import org.jf.dexlib2.immutable.ImmutableMethod
import org.jf.dexlib2.immutable.ImmutableMethodImplementation
import org.jf.dexlib2.immutable.ImmutableMethodParameter
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction10x
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction21c
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction31c
import org.jf.dexlib2.immutable.reference.ImmutableStringReference
import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * C6：dex 字符串池补丁硬证据测试。真实构建 DEX（const-string/const-string/jumbo）
 * → patchStrings 替换 → 重读验证。覆盖等长与变长（MUTF-8 重排）两种写路径。
 */
class ApkDexPatcherStringPoolTest {

    private fun buildDexWithStrings(
        strings: List<String>,
        useJumbo: Boolean = false,
    ): File {
        val insns = ArrayList<org.jf.dexlib2.iface.instruction.Instruction>()
        strings.forEachIndexed { i, s ->
            if (useJumbo) {
                insns.add(
                    ImmutableInstruction31c(
                        Opcode.CONST_STRING_JUMBO,
                        i,
                        ImmutableStringReference(s),
                    ),
                )
            } else {
                insns.add(
                    ImmutableInstruction21c(
                        Opcode.CONST_STRING,
                        i,
                        ImmutableStringReference(s),
                    ),
                )
            }
        }
        insns.add(ImmutableInstruction10x(Opcode.RETURN_VOID))
        val method = ImmutableMethod(
            "Lcom/x/Main;",
            "run",
            listOf(
                ImmutableMethodParameter("I", emptySet(), "p0"),
            ),
            "V",
            AccessFlags.PUBLIC.value,
            emptySet<org.jf.dexlib2.iface.Annotation>(),
            emptySet<org.jf.dexlib2.HiddenApiRestriction>(),
            ImmutableMethodImplementation(strings.size + 1, insns, emptyList(), emptyList()),
        )
        val classDef = ImmutableClassDef(
            "Lcom/x/Main;",
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            listOf(method),
        )
        val root = Files.createTempDirectory("stringpool").toFile()
        val out = File(root, "classes.dex")
        DexFileFactory.writeDexFile(out.absolutePath, ImmutableDexFile(Opcodes.getDefault(), listOf(classDef)))
        return out
    }

    private fun readStrings(dexFile: File): List<String> {
        val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
        val impl = dex.classes.first().methods.first().implementation!!
        return impl.instructions
            .filter { it.opcode == Opcode.CONST_STRING || it.opcode == Opcode.CONST_STRING_JUMBO }
            .map { ((it as ReferenceInstruction).reference as StringReference).string }
    }

    @Test
    fun replacesExactStringEqualLength() {
        val dex = buildDexWithStrings(listOf("https://old.example.com/api"))
        try {
            val result = ApkDexPatcher.patchStrings(
                dex,
                listOf("https://old.example.com/api" to "https://new.example.com/api"),
            )
            assertNotNull("必须命中", result)
            assertEquals(1, result!!["changed"])
            assertEquals(listOf("https://new.example.com/api"), readStrings(dex))
        } finally {
            dex.parentFile.deleteRecursively()
        }
    }

    @Test
    fun replacesStringVariableLengthMutf8Reshuffle() {
        val dex = buildDexWithStrings(listOf("旧短文案", "https://keep.example.com/x", "中文长文案待替换AAAA"))
        try {
            val result = ApkDexPatcher.patchStrings(
                dex,
                listOf(
                    "旧短文案" to "这是一个明显更长的替换文案",
                    "中文长文案待替换AAAA" to "短",
                ),
            )
            assertNotNull(result)
            assertEquals(2, result!!["changed"])
            val after = readStrings(dex)
            assertEquals("这是一个明显更长的替换文案", after[0])
            assertEquals("https://keep.example.com/x", after[1]) // 未命中保持不变
            assertEquals("短", after[2])
        } finally {
            dex.parentFile.deleteRecursively()
        }
    }

    @Test
    fun constStringJumboReplaced() {
        val dex = buildDexWithStrings(listOf("watermark_a1b2c3"), useJumbo = true)
        try {
            val result = ApkDexPatcher.patchStrings(dex, listOf("watermark_a1b2c3" to "watermark_removed"))
            assertNotNull(result)
            assertEquals(1, result!!["changed"])
            assertEquals(listOf("watermark_removed"), readStrings(dex))
        } finally {
            dex.parentFile.deleteRecursively()
        }
    }

    @Test
    fun noMatchReturnsNullAndDoesNotRewrite() {
        val dex = buildDexWithStrings(listOf("keep_me"))
        try {
            val result = ApkDexPatcher.patchStrings(dex, listOf("absent_string" to "replacement"))
            assertNull("无命中必须返回 null（不假成功、不重写）", result)
            assertEquals(listOf("keep_me"), readStrings(dex))
        } finally {
            dex.parentFile.deleteRecursively()
        }
    }

    @Test
    fun emptyAndIdentityReplacementsSkipped() {
        val dex = buildDexWithStrings(listOf("abc"))
        try {
            val result = ApkDexPatcher.patchStrings(
                dex,
                listOf("" to "x", "abc" to "abc", "xyz" to "abc"),
            )
            // "" 与 abc→abc 被跳过；xyz 不命中 → 无有效替换 → null
            assertNull(result)
        } finally {
            dex.parentFile.deleteRecursively()
        }
    }
}
