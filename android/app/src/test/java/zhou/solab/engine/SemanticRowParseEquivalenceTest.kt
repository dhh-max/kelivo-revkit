package zhou.solab.engine

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * B2-1 回归：构建期行级预筛（先便宜判定、后正则）**不得改变任何一行产出**。
 *
 * 做法：把改造前 `processAsmFile` 的逐行逻辑按原样（原正则逐字复制）实现成 oracle，
 * 对同一批 asm 语料分别跑两侧，逐行比较 `SemanticRow.toJson().toString()`——
 * 行数、type、各字段值、以及"字段缺失 vs JSON null"的区分全部覆盖。
 *
 * 语料刻意包含触发全部行型与全部分支的形态：函数头（有/无签名、类内/类外、负 size、
 * 大写、缩进）、reference（asm_annotation / arm64_add_ldr_fallback / 非指令行上的池注解）、
 * immediate（mov/movz/movn/cmp/cmn、负数、缺 `#`）、addressing_immediate 聚合尾部，
 * 以及数据行里"看起来像指令"的字符串（预筛必须放行）、超长行（> [MAX_PARSE_LINE_CHARS] 跳过解析）、
 * CRLF 文件与空文件。
 *
 * 说明：本用例只比较语义行；function-header / memory-access / field-slice 三个旁路索引
 * 由同一次逐行扫描写出，其不变性由 AsmFastIndexTest / BlutterSearchIndexTest 既有用例
 * 与改造时的"全产物 sha256 逐字节 diff"共同覆盖。
 */
class SemanticRowParseEquivalenceTest {

    private val maxParseLineChars = 8192

    @Test
    fun `构建产出与改造前逐行 oracle 全等`() {
        val resultDir = Files.createTempDirectory("solab-b2-oracle-").toFile()
        try {
            val fixture = writeFixture(resultDir)
            BlutterSearchIndex.ensureSemanticIndex(resultDir, force = true, shardOverride = 1)

            val expected = mutableListOf<String>()
            // 生产侧行序：asm/ 下按绝对路径排序，单分片顺序处理（与 ensureSemanticIndex 一致）；
            // addressing_immediate 是**全局**聚合，全部文件处理完统一落尾部。
            // 分片 map（单分片：本 map 收全部文件的 +count）→ 归并 map（与生产侧同构，
            // 连尾部行的 HashMap 迭代序都对齐；尾部顺序本身不是语义，但能钉住整段行为）
            val addressing = HashMap<Long, Int>()
            fixture.sortedBy { it.first }.forEach { (rel, lines) ->
                // 与生产侧的 rel 口径一致：`"asm/${file.relativeTo(asmDir).path}"`（子目录用平台分隔符）
                val expectedRel = "asm/" + rel.removePrefix("asm/").replace('/', File.separatorChar)
                expected += LegacySemanticRows(expectedRel, lines, addressing).rows()
            }
            val merged = HashMap<Long, Int>()
            addressing.forEach { (value, count) -> merged.merge(value, count, Int::plus) }
            merged.forEach { (value, count) ->
                expected += JSONObject()
                    .put("type", "addressing_immediate")
                    .put("value", value)
                    .put("count", count)
                    .toString()
            }
            val actual = readRows(File(resultDir, "blutter-semantic-v3.bin.gz"))

            if (expected.size != actual.size) {
                println("EXPECTED=${expected.joinToString("\n")}")
                println("ACTUAL=${actual.joinToString("\n")}")
            }
            assertEquals("语义行数", expected.size, actual.size)
            assertEquals("行类型分布", typeHistogram(expected), typeHistogram(actual))
            expected.forEachIndexed { index, row ->
                assertEquals("row #$index 字段不等价", row, actual[index])
            }
        } finally {
            resultDir.deleteRecursively()
        }
    }

    private fun typeHistogram(rows: List<String>): Map<String, Int> = rows
        .groupingBy { org.json.JSONObject(it).optString("type") }
        .eachCount()

    private fun readRows(index: File): List<String> {
        val out = mutableListOf<String>()
        SemanticRowReader.open(index).use { reader ->
            while (true) {
                val row = reader.next() ?: break
                out += row.toJson().toString()
            }
        }
        return out
    }

    // ------------------------------------------------------------------ 语料

    private fun writeFixture(resultDir: File): List<Pair<String, List<String>>> {
        val asmDir = File(resultDir, "asm").apply { mkdirs() }
        File(asmDir, "package%3Aapp").mkdirs()
        File(resultDir, "result.json").writeText("{}")
        val fixture = listOf(
            "asm/main.dart" to listOf(
                "// lib: url 'package:app/src/main.dart'",
                "class Account {",
                "  bool dyn:get:isVip(Account) {",
                "    // ** addr: 0x1000, size: 0x40",
                "    //     0x1000: ldr x0, [x27, #0x10] // [pp+0x10] String: \"isVip\"",
                "    //     0x1004: mov x0, #0x5",
                "    //     0x1008: cmp x0, #0x2",
                "    //     0x100c: add x9, x27, #0x1a, lsl #12",
                "    //     0x1010: ldr x0, [x9, #0xba8]",
                "    //     0x1014: bl #0x2000",
                "    //     0x1018: ret",
                "  }",
                "  Map<String, dynamic> toJson() {",
                "    // ** addr: 0x2000, size: -0x20",
                "    //     0x2000: MOVZ X1, #-0x5",
                "    //     0x2004: cmn x1, #0x1",
                "    //     0x2008: strb w2, [x3, #0x3]",
                "    //     0x200c: stur x4, [x29, #-0x8]",
                "    //     0x2010: ldur w5, [x6]",
                "    //     0x2014: lsl w6, w7, #12",
                "  }",
                "}",
                "// ** addr: 0x3000, size: 0x10",
                "//     0x3000: mov x0, #-0x1",
                "//     0x3004: mov x0, w1",
                "//     0x3008: movn x0, #0x3",
            ),
            "asm/package%3Aapp/upper.dart" to listOf(
                "// lib: url 'package:app/src/upper.dart'",
                "// ** ADDR: 0X4000, SIZE: -0X20",
                "//     0x4000: ADD X9, X27, #0x1a, LSL #12",
                "//     0x4004: ldr x0, [x9, #0xba8]",
                "//     0x4008: LDR X0, [X27, #0x18] // [PP+0X18] String: \"VipExpired\"",
                "//     0x400c: \"ldr x0, [x27, #0x1c]\" data string",
                "//     0x4010: add x9, x27, #0x1c, lsl #12",
                "//     0x4014: ldr x0, [x9, #0xb04]",
                "// " + "x".repeat(maxParseLineChars + 8),
                "//     0x4018: mov x0, #0x7 // [pp+0x18]",
                "  //     0x401c: ldr x1, [x2, #0x20]",
                "\t//     0x4020: add x9, x27, #0x1d, lsl #12",
                "\t//     0x4024: ldr x3, [x9, #0xb40] // [pp+0x1d]",
                "// [pp+0x1234] String: \"no instruction prefix here\"",
                "// if x27 then #12 else lsl",
                "// ** addr: 0x5000, size: 0x8",
                "//     0x5000: str x0, [x1, #0x24]",
            ),
            "asm/crlf.dart" to listOf(
                "// lib: url 'package:app/src/crlf.dart'",
                "class Crlf {",
                "  void run() {",
                "    // ** addr: 0x6000, size: 0x20",
                "    //     0x6000: ldr x0, [x27, #0x2c] // [pp+0x2c] String: \"crlf\"",
                "    //     0x6004: add x9, x27, #0x1e, lsl #12",
                "    //     0x6008: ldr x0, [x9, #0xb80]",
                "    //     0x600c: b.eq #0x6020",
                "  }",
                "}",
            ),
            "asm/empty.dart" to emptyList(),
            "asm/comments-only.dart" to listOf(
                "// lib: url 'package:app/src/comments_only.dart'",
                "// nothing but comments",
            ),
            // 非 ASCII 空白缩进/前缀：Kotlin trim() 去掉、JVM 正则 `\s` 不去（设备 ICU 会去）。
            // 行级预筛必须与它保护的正则判同一个字符串，否则 insn 前缀剥离会与改造前不同。
            "asm/nbsp.dart" to listOf(
                "// lib: url 'package:app/src/nbsp.dart'",
                "\u00A0// ** addr: 0x7000, size: 0x20",
                "\u00A0//     0x7000: ldr x0, [x27, #0x30] // [pp+0x30] String: \"nbsp\"",
                "  \u00A0//     0x7004: ldr x0, [x27, #0x34] // [pp+0x34] String: \"nbsp2\"",
                "//\u00A0\u30000x7008: add x9, x27, #0x21, lsl #12",
                "//     0x700c: ldr x0, [x9, #0x840]",
                "\u2000//     0x7010: mov x0, #0x9",
                "\u2028//     0x7014: cmp x0, #0x4",
            ),
        )
        fixture.forEach { (rel, lines) ->
            val target = File(resultDir, rel)
            val text = lines.joinToString("\n", postfix = "\n")
            // crlf.dart 用 CRLF 落盘：`matches()` 系解析对行尾 \r 的行为两侧必须一致
            val bytes = if (rel.endsWith("crlf.dart")) text.replace("\n", "\r\n").toByteArray() else text.toByteArray()
            target.parentFile?.mkdirs()
            target.writeBytes(bytes)
        }
        assertTrue(asmDir.isDirectory)
        return fixture
    }

    // ------------------------------------------------------------------ oracle

    /**
     * 改造前 `processAsmFile` 的逐行逻辑（正则逐字复制自 eff1cf2f 的实现）。
     * 只产出语义行（function / reference / immediate / addressing_immediate）；
     * field-slice 与 memory-access 的旁路写入不影响行集合，故不在此复刻。
     */
    private class LegacySemanticRows(
        private val rel: String,
        private val lines: List<String>,
        private val addressingImmediates: HashMap<Long, Int>,
    ) {

        private val funcAddr = Regex("^\\s*// \\*\\* addr: 0x([0-9a-fA-F]+), size: -?0x([0-9a-fA-F]+).*$", RegexOption.IGNORE_CASE)
        private val ref = Regex("\\[pp\\+0x([0-9a-fA-F]+)]", RegexOption.IGNORE_CASE)
        private val ldrFrom = Regex("\\bldr\\w*\\s+[^,]+,\\s*\\[(x\\d+),\\s*#(0x[0-9a-fA-F]+|\\d+)]", RegexOption.IGNORE_CASE)
        private val valueInstruction = Regex(
            "^\\s*//\\s+0x([0-9a-fA-F]+):\\s+(mov|movz|movn|cmp|cmn)\\s+[^,]+,\\s*#(-?0x[0-9a-fA-F]+|-?\\d+)\\b",
            RegexOption.IGNORE_CASE,
        )
        private val insnAddr = Regex("^\\s*(?://\\s*)?0x([0-9a-fA-F]+):")
        private val leadingAddrPrefix = Regex("^\\s*(?://\\s*)?0x[0-9a-fA-F]+:\\s?")
        private val addPp = Regex("\\badd\\s+(x\\d+),\\s*x27,\\s*#(0x[0-9a-fA-F]+|\\d+),\\s*lsl\\s*#12", RegexOption.IGNORE_CASE)

        private var currentClass: String? = null
        private var pendingSignature: String? = null
        private var currentFunctionVa: String? = null
        private var pendingPoolAdd: Pair<String, Long>? = null

        fun rows(): List<String> {
            val out = mutableListOf<String>()
            lines.forEachIndexed { lineIndex, raw -> out += parseLine(raw, lineIndex) }
            return out
        }

        private fun parseLine(raw: String, lineIndex: Int): List<String> {
            val rows = mutableListOf<String>()
            val trimmed = raw.trim()
            if (trimmed.startsWith("class ")) currentClass = className(trimmed)
            if (funcAddr.matches(raw)) {
                currentFunctionVa = funcAddr.matchEntire(raw)!!.groupValues[1].lowercase()
                val functionSize = funcAddr.matchEntire(raw)!!.groupValues[2].lowercase()
                rows += JSONObject().apply {
                    put("type", "function")
                    put("va", currentFunctionVa)
                    put("size", functionSize)
                    if (pendingSignature != null) put("function", pendingSignature) else put("function", JSONObject.NULL)
                    if (currentClass != null) put("class", currentClass) else put("class", JSONObject.NULL)
                    put("file", rel)
                    put("line", lineIndex + 1)
                }.toString()
            } else if (raw.startsWith("  ") && BlutterSearchIndex.isFunctionSignature(trimmed)) {
                pendingSignature = trimmed.trimEnd('{', ' ', ';')
            }
            if (raw.length > 8192) return rows
            var explicitReference = false
            val refMatch = ref.findAll(raw).toList()
            if (refMatch.isNotEmpty()) {
                for (match in refMatch) {
                    explicitReference = true
                    rows += referenceRow(match.groupValues[1], raw, currentFunctionVa, "asm_annotation")
                }
            }
            if (!explicitReference) {
                val ldr = ldrFrom.find(raw)
                val pending = pendingPoolAdd
                if (ldr != null && pending != null && ldr.groupValues[1].equals(pending.first, true)) {
                    val offset = pending.second + parseImmediate(ldr.groupValues[2])
                    rows += referenceRow(offset.toString(16), raw, currentFunctionVa, "arm64_add_ldr_fallback")
                }
            }
            valueEvidence(raw)?.let { evidence ->
                rows += JSONObject().apply {
                    put("type", "immediate")
                    put("functionVa", currentFunctionVa ?: JSONObject.NULL)
                    put("instructionVa", evidence.optString("instructionVa"))
                    put("mnemonic", evidence.optString("mnemonic"))
                    put("kind", evidence.optString("kind"))
                    put("value", evidence.optLong("value"))
                    put("valueHex", evidence.optString("valueHex"))
                    put("text", evidence.optString("text"))
                }.toString()
            }
            memoryImmediateValue(raw)?.let { value ->
                addressingImmediates[value] = (addressingImmediates[value] ?: 0) + 1
            }
            pendingPoolAdd = addPp.find(raw)?.let { add ->
                add.groupValues[1] to (parseImmediate(add.groupValues[2]) shl 12)
            }
            return rows
        }

        private fun referenceRow(offset: String, raw: String, functionVa: String?, mode: String): String {
            val instructionVa = insnAddr.find(raw)?.groupValues?.get(1)?.lowercase()
            val rawTrimmed = raw.trim()
            val leading = leadingAddrPrefix.find(rawTrimmed)
            val insn = if (leading != null) rawTrimmed.substring(leading.range.last + 1) else rawTrimmed
            return JSONObject().apply {
                put("type", "reference")
                put("offset", offset.lowercase())
                val va = instructionVa ?: functionVa
                if (va != null) put("va", va) else put("va", JSONObject.NULL)
                if (functionVa != null) put("functionVa", functionVa) else put("functionVa", JSONObject.NULL)
                put("insn", insn.take(300))
                put("referenceMode", mode)
            }.toString()
        }

        private fun valueEvidence(raw: String): JSONObject? {
            val match = valueInstruction.find(raw) ?: return null
            val value = parseNumeric(match.groupValues[3]) ?: return null
            val mnemonic = match.groupValues[2].lowercase()
            return JSONObject()
                .put("instructionVa", "0x${match.groupValues[1].lowercase()}")
                .put("mnemonic", mnemonic)
                .put("kind", if (mnemonic == "cmp" || mnemonic == "cmn") "comparison" else "assignment")
                .put("value", value)
                .put("valueHex", signedHex(value))
                .put("text", raw.trim().take(300))
        }

        private val memoryImmediate = Regex(
            "^\\s*//\\s+0x[0-9a-fA-F]+:\\s+(?:ldr|ldur|str|stur|ldrb|ldrh|strb|strh)\\w*\\s+.*\\[[^]]*#(-?0x[0-9a-fA-F]+|-?\\d+)[^]]*]",
            RegexOption.IGNORE_CASE,
        )

        private fun memoryImmediateValue(raw: String): Long? =
            memoryImmediate.find(raw)?.groupValues?.get(1)?.let(::parseNumeric)

        private fun className(line: String): String =
            line.removePrefix("class ").substringBefore('{').substringBefore("//")
                .substringBefore(" extends ").substringBefore(" implements ").substringBefore(" with ").substringBefore(" on ").trim()

        private fun parseImmediate(raw: String): Long =
            if (raw.startsWith("0x", true)) raw.substring(2).toLongOrNull(16) ?: 0L
            else raw.toLongOrNull() ?: 0L

        private fun parseNumeric(raw: String): Long? {
            val text = raw.trim().lowercase()
            return when {
                text.startsWith("-0x") -> text.removePrefix("-0x").toLongOrNull(16)?.let { -it }
                text.startsWith("0x") -> text.removePrefix("0x").toLongOrNull(16)
                else -> text.toLongOrNull()
            }
        }

        private fun signedHex(value: Long): String =
            if (value < 0) "-0x${(-value).toString(16)}" else "0x${value.toString(16)}"
    }
}
