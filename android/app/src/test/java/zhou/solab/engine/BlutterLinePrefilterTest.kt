package zhou.solab.engine

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B2-1 回归：构建期两级预筛（先便宜判定、后正则）的**必要性**判定。
 *
 * 预筛只做一件事——跳过"正则必然不命中"的行。所以正确性条件是：
 *
 *     预筛返回 false  ⇒  对应正则不命中（含 matches / find 两种口径）
 *
 * 这里用**改造前的原正则作 oracle**，对一大批真实形态 + 大小写/缩进/空白的
 * 变异行逐例对拍。一旦哪条预筛收得比正则还紧，等价性就被这条测试钉死。
 *
 * 注意：预筛允许"比正则宽"（多跑几次正则，只慢不错），因此断言方向是单向的。
 */
class BlutterLinePrefilterTest {

    // ---------------------------------------------------------------- oracle（改造前正则）
    private val funcAddr = Regex("^\\s*// \\*\\* addr: 0x([0-9a-fA-F]+), size: -?0x([0-9a-fA-F]+).*$", RegexOption.IGNORE_CASE)
    private val ref = Regex("\\[pp\\+0x([0-9a-fA-F]+)]", RegexOption.IGNORE_CASE)
    private val ldrFrom = Regex("\\bldr\\w*\\s+[^,]+,\\s*\\[(x\\d+),\\s*#(0x[0-9a-fA-F]+|\\d+)]", RegexOption.IGNORE_CASE)
    private val valueInstruction = Regex(
        "^\\s*//\\s+0x([0-9a-fA-F]+):\\s+(mov|movz|movn|cmp|cmn)\\s+[^,]+,\\s*#(-?0x[0-9a-fA-F]+|-?\\d+)\\b",
        RegexOption.IGNORE_CASE,
    )
    private val memoryImmediate = Regex(
        "^\\s*//\\s+0x[0-9a-fA-F]+:\\s+(?:ldr|ldur|str|stur|ldrb|ldrh|strb|strh)\\w*\\s+.*\\[[^]]*#(-?0x[0-9a-fA-F]+|-?\\d+)[^]]*]",
        RegexOption.IGNORE_CASE,
    )
    private val memoryAccess = Regex(
        "^\\s*(?://\\s*)?0x([0-9a-fA-F]+):\\s+((?:ldr|ldur|str|stur|ldrb|ldrh|strb|strh)\\w*)\\s+([^,]+),\\s*\\[([a-z0-9]+),\\s*#(-?0x[0-9a-fA-F]+|-?\\d+)[^]]*]",
        RegexOption.IGNORE_CASE,
    )
    private val arm64Instruction = Regex(
        "^\\s*(?://\\s*)?0x([0-9a-fA-F]+):\\s+([a-z][a-z0-9.]*)\\s*(.*)$",
        RegexOption.IGNORE_CASE,
    )
    private val insnAddr = Regex("^\\s*(?://\\s*)?0x([0-9a-fA-F]+):")
    private val leadingAddrPrefix = Regex("^\\s*(?://\\s*)?0x[0-9a-fA-F]+:\\s?")
    private val addPp = Regex("\\badd\\s+(x\\d+),\\s*x27,\\s*#(0x[0-9a-fA-F]+|\\d+),\\s*lsl\\s*#12", RegexOption.IGNORE_CASE)

    /** 与生产代码 [BlutterSearchIndex] 里的助记符词表一致（此处独立列出，避免"借实现证实现"）。 */
    private val memoryMnemonics = listOf("ldr", "ldur", "str", "stur", "ldrb", "ldrh", "strb", "strh")
    private val valueMnemonics = listOf("mov", "movz", "movn", "cmp", "cmn")

    private fun mnemonicsAt(raw: String, at: Int, literals: List<String>): Boolean =
        at >= 0 && literals.any { raw.regionMatches(at, it, 0, it.length, ignoreCase = true) }

    // ---------------------------------------------------------------- 被测预筛（与生产代码同源）

    private data class GateCase(
        val name: String,
        val gate: (String) -> Boolean,
        val hits: (String) -> Boolean,
    )

    private val cases: List<GateCase> = listOf(
        GateCase(
            "FUNC_ADDR（processAsmFile / ensureFunctionHeaderIndex 分支）",
            { raw -> raw.trim().startsWith("// ** ") },
            { raw -> funcAddr.matches(raw) },
        ),
        GateCase(
            "FUNC_ADDR（headerAddrSize 分支，不分配 trim）",
            { raw -> BlutterSearchIndex.startsWithAfterSpace(raw, "// ** ") },
            { raw -> funcAddr.matches(raw) },
        ),
        GateCase("REF", { BlutterSearchIndex.hasPpAnnotation(it) }, { ref.containsMatchIn(it) }),
        GateCase("LDR_FROM", { BlutterSearchIndex.hasLdrFromForm(it) }, { ldrFrom.containsMatchIn(it) }),
        GateCase(
            "INSN_ADDR",
            { BlutterSearchIndex.instructionColonIndex(it, requireComment = false) >= 0 },
            { insnAddr.containsMatchIn(it) },
        ),
        GateCase(
            "LEADING_ADDR_PREFIX",
            // 门必须与它保护的正则判**同一个字符串**：生产里 LEADING_ADDR_PREFIX 在
            // rawTrimmed 上求值（HEAD 亦如此），拿 raw 判门会因 trim 的白空集更宽而漏判
            // （U+00A0/U+2028/U+3000 等 22 个字符）。
            { raw -> BlutterSearchIndex.instructionColonIndex(raw.trim(), requireComment = false) >= 0 },
            { raw -> leadingAddrPrefix.containsMatchIn(raw.trim()) },
        ),
        GateCase(
            "ARM64_INSTRUCTION",
            { BlutterSearchIndex.instructionMnemonicStart(it) >= 0 },
            { arm64Instruction.matches(it) },
        ),
        GateCase(
            "MEMORY_ACCESS",
            { raw ->
                val at = BlutterSearchIndex.instructionMnemonicStart(raw)
                mnemonicsAt(raw, at, memoryMnemonics) && raw.indexOf('[') >= 0 && raw.indexOf('#') >= 0
            },
            { memoryAccess.containsMatchIn(it) },
        ),
        GateCase(
            "MEMORY_IMMEDIATE",
            { raw ->
                val at = BlutterSearchIndex.instructionMnemonicStart(raw, requireComment = true)
                mnemonicsAt(raw, at, memoryMnemonics) && raw.indexOf('[') >= 0 && raw.indexOf('#') >= 0
            },
            { memoryImmediate.containsMatchIn(it) },
        ),
        GateCase(
            "VALUE_INSTRUCTION",
            { raw ->
                val at = BlutterSearchIndex.instructionMnemonicStart(raw, requireComment = true)
                mnemonicsAt(raw, at, valueMnemonics) && raw.indexOf('#') >= 0
            },
            { valueInstruction.containsMatchIn(it) },
        ),
        GateCase("ADD_PP", { BlutterSearchIndex.hasPoolAddForm(it) }, { addPp.containsMatchIn(it) }),
    )

    /** 真实 asm 形态 + 各条正则的边界/病态输入。 */
    private val baseLines = listOf(
        "// lib: url 'package:app/src/main.dart'",
        "class Account {",
        "  bool dyn:get:isVip(Account) {",
        "  }",
        "",
        "   ",
        "\r",
        "    // ** addr: 0x1000, size: 0x20",
        "// ** addr: 0x1000, size: 0x20",
        "// ** ADDR: 0X1000, SIZE: -0x20",
        "\t// ** addr: 0x1000, size: -0x20",
        "\u000B// ** addr: 0x1000, size: 0x1",
        "\u0001// ** addr: 0x1000, size: 0x1",
        "// ** addr: 0x1000, size: 0x20 extra",
        "// ** addr: 0x, size: 0x",
        "// ** addr: 0x1000,size: 0x20",
        "  //     0x1000: ldr x0, [x27, #0x10] // [pp+0x10] String: \"isVip\"",
        "  //     0x1000: ldr x0, [x27, #0x10] // [PP+0X10] String: \"isVip\"",
        "  //     0x1000: ldr x0, [x27, #0x10] // [pP+0x10] String: \"isVip\"",
        "  //     0x1000: ldr x0, [x27, #0x10] // [pp+10] String: \"isVip\"",
        "  //     0x1000: ldr x0, [x27, #0x10] // [pp+0x] String: \"isVip\"",
        "  //     0x1000: LDR X0, [X27, #0x10] // [pp+0x10] String: \"isVip\"",
        "  //     0x1000: ldr x0, [x27, #0x10]",
        "0x1000: ldr x0, [x27, #0x10]",
        "//0x1000: ldr x0, [x27, #0x10]",
        "// 0x1000:ldr x0, [x27, #0x10]",
        "  // 0x1000:  ldr x0, [x27, #0x10]",
        "  //0x1000: ldr x0, [x27, #0x10]",
        "  // 0x1000: add x9, x27, #0x1a, lsl #12",
        "  // 0x1000: ADD X9, X27, #0x1a, LSL #12",
        "  // 0x1000: add x9, x27, #0x1a, lsl #12 // [pp+0x1aba8] String: \"x\"",
        "  // 0x1000: lsl w0, w1, #12",
        "\t// 0x1000: add x9, x27, #0x1a, lsl #12",
        "  // data: ldr x0, [x27, #0x10]",
        "  // \"ldr x0, [x27, #0x10]\"",
        "  // [pp+0x1234] String: \"x\"",
        "  // [PP+0X1234] String: \"x\"",
        "  // [pp+0x1234]",
        "  // note: pp+0x1234 without bracket",
        "  // 0x1000: mov x0, #0x5",
        "  // 0x1000: MOVZ x0, #-0x5",
        "  // 0x1000: movn x0, #0x5",
        "  // 0x1000: cmp x0, #0xa",
        "  // 0x1000: cmn x0, #0x1",
        "  // 0x1000: mov x0, w1",
        "  // 0x1000: strb w0, [x1, #0x3]",
        "  // 0x1000: ldur x0, [x1]",
        "  // 0x1000: stur x0, [x29, #-0x8]",
        "  // 0x1000: strh w2, [x0, #0x6]",
        "  // 0x1000: ret",
        "  // 0x1000: b.eq #0x1010",
        "  // 0x1000: bl #0x20",
        "  // 0x1000: blr x3",
        "  // 0x1000: cbz x0, #0x1010",
        "  // 0x1000: cset w0, eq",
        "  // 0x1000: x27, #12, lsl",
        "  // 0x1000: #12",
        "  // 0x1000: 1234",
        "  // 0x1000: 0x1234:",
        "  // 0x: ldr x0, [x27, #0x10]",
        "  // 0x1000 : ldr x0, [x27, #0x10]",
        "  //** addr: 0x1000, size: 0x1",
        "  // **addr: 0x1000, size: 0x1",
        "LDR X0, [X27, #0X10]",
        "// ** addr: 0x7fffffffffffffff, size: 0xffffffff",
        // 非 ASCII 空白：Kotlin trim() 会去掉、JVM 正则 `\s` 不会；设备上是 ICU
        // （`\s` 含 \p{Z}），折叠也按 Unicode。门的谓词必须是两边的超集。
        "\u00A0//     0x1000: ldr x0, [x27, #0x10] // [pp+0x10] String: \"nbsp\"",
        "\u00A0//     0x1000: ldr x0, [x27, #0x10]",
        "\u2028//     0x1000: mov x0, #0x5",
        "\u3000// ** addr: 0x1000, size: 0x20",
        "\u2000// 0x1000: add x9, x27, #0x1a, lsl #12",
        "  \u00A0//     0x1000: ldr x0, [x27, #0x10] // [pp+0x10] String: \"nbsp2\"",
        "//\u00A00x1000: ldr x0, [x27, #0x10]",
        "//\u3000\u20000x1000: mov x0, #0x5",
        "//     0x1000: \u017Ftr x0, [x27, #0x10]",
        "//     0x1000: add x9, x27, #0x1a, l\u017Fl #12",
    )

    /** 变异：大小写 / 缩进 / 尾随空白——预筛里的 ASCII 折叠与 `\s` 集必须与正则一致。 */
    private val corpus: List<String> = baseLines.flatMap { line ->
        listOf(line, line.uppercase(), "  $line", "\t$line", "$line\r", "$line  ")
    }

    @Test
    fun `预筛返回 false 时对应正则必然不命中`() {
        var checked = 0
        for (case in cases) {
            for (line in corpus) {
                checked++
                if (!case.hits(line)) continue
                assertTrue(
                    "预筛比正则更紧：${case.name} 对 ${line.toPrintable()} 返回 false 但正则命中",
                    case.gate(line),
                )
            }
        }
        assertTrue("语料规模异常", checked > 2000)
    }

    /** 反向护栏：语料必须真的覆盖到"命中"一侧，否则上面的断言恒真（假绿）。 */
    @Test
    fun `语料对每条正则都有命中样本`() {
        for (case in cases) {
            assertTrue(
                "语料未覆盖 ${case.name} 的命中样本，必要性断言会退化为恒真",
                corpus.any(case.hits),
            )
        }
    }

    private fun String.toPrintable(): String =
        '"' + replace("\\", "\\\\").replace("\r", "\\r").replace("\t", "\\t").replace("\u000B", "\\v").replace("\u0001", "\\u0001") + '"'
}
