package zhou.solab.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * B3-1（§14.8）行格式二进制化回归。
 *
 * 三道闸门：
 * 1. **逐字段往返**——写入 → 读回后 `functionVa`/`line`/`insn`/`text`/`offset`/`value`
 *    /`count` 逐字段等于写入值，含差分边界（同函数连续行 / 跨函数 / 极大值）与
 *    JSON null vs 字段缺失的区分；
 * 2. **体积断言**——同一 fixture 下新格式裸字节数 < 旧 JSONL 裸字节数
 *    （防「改了格式却没瘦」）；
 * 3. **双读兼容**——v6 二进制与旧 v5 gz JSONL / v1 明文 JSONL 都产出同一个
 *    [SemanticRow] 模型（读取端一个解析器，消费点不各自 `JSONObject(raw)`）。
 */
class SemanticRowFormatTest {

    // ------------------------------------------------------------ 往返（单元级）

    @Test
    fun `二进制行逐字段往返（四种行型 + 差分边界 + 极大值）`() {
        val dir = Files.createTempDirectory("semantic-row-roundtrip-").toFile()
        try {
            val rows = listOf(
                functionRow(0x1000, "40", "bool isVip(Account)", "Account", "asm/a.dart", 4),
                referenceRow(0x1000, "10", "1004", "ldr x0, [x27, #0x10] // [pp+0x10] String: \"isVip\"", "asm_annotation"),
                // 同函数连续行：functionVa 差分为 0、offset/va 差分为增量
                referenceRow(0x1000, "18", "1008", "ldr x1, [x27, #0x18] // [pp+0x18] Object", "arm64_add_ldr_fallback"),
                immediateRow(0x1000, "0x100c", "cmp", "comparison", 10, "// 0x100c: cmp w0, #0xa"),
                // 跨函数（含回跳：下一个函数 VA 更小，差分为负）
                functionRow(0x200000000L, "20", "void big()", null, "asm/b.dart", 900),
                referenceRow(0x200000000L, "1aba8", "200000004", "ldr x0, [x27, #0x1aba8] // [pp+0x1aba8] String: \"去领取会员\"", "asm_annotation"),
                immediateRow(0x200000000L, "0x200000008", "mov", "assignment", -1L, "// 0x200000008: mov w2, #-0x1"),
                // 极大值 / 边界值
                functionRow(Long.MAX_VALUE, "ffffffff", "void extreme()", "Edge", "asm/c.dart", Int.MAX_VALUE),
                referenceRow(Long.MAX_VALUE, "ffffffffffffff", "7fffffffffffffff", "ldr x9, [x27, #0xffffffffffffff]", "asm_annotation"),
                addressingRow(Long.MAX_VALUE, Int.MAX_VALUE),
                addressingRow(-1L, 1),
                // JSON null（与「字段缺失」不同：optString 分别返回 "null" 与 ""）
                functionRow(0x3000, "4", null, null, "asm/d.dart", 1),
                referenceRow(0x3000, "20", null, "ldr x0, [x27, #0x20]", "asm_annotation"),
            )
            val file = writeSemanticBinary(dir.resolve("roundtrip.bin"), rows)

            val read = readAllRows(file)
            assertEquals("行数", rows.size, read.size)
            rows.forEachIndexed { index, expected ->
                assertEquals("row $index type", expected.type, read[index].type)
                // 逐字段（不只比 toJson 字符串，防止两侧同错）
                assertEquals("row $index functionVa", expected.functionVa, read[index].functionVa)
                assertEquals("row $index functionVaText", expected.functionVaText, read[index].functionVaText)
                assertEquals("row $index line", expected.line, read[index].line)
                assertEquals("row $index insn", expected.insn, read[index].insn)
                assertEquals("row $index text", expected.text, read[index].text)
                assertEquals("row $index offset", expected.offsetText, read[index].offsetText)
                assertEquals("row $index va", expected.vaText, read[index].vaText)
                assertEquals("row $index value", expected.value, read[index].value)
                assertEquals("row $index count", expected.count, read[index].count)
                assertEquals("row $index size", expected.sizeText, read[index].sizeText)
                assertEquals("row $index function", expected.function, read[index].function)
                assertEquals("row $index class", expected.className, read[index].className)
                assertEquals("row $index file", expected.file, read[index].file)
                assertEquals("row $index referenceMode", expected.referenceMode, read[index].referenceMode)
                assertEquals("row $index mnemonic", expected.mnemonic, read[index].mnemonic)
                assertEquals("row $index kind", expected.kind, read[index].kind)
                assertEquals("row $index instructionVa", expected.instructionVaText, read[index].instructionVaText)
                // 旧消费方视角的等价 JSON（键序与写入点一致，immediate 证据输出依赖它）
                assertEquals("row $index json", expected.toJson().toString(), read[index].toJson().toString())
            }
            // JSON null 与缺字段必须仍然可分（旧行为：optString 分别给 "null" 与 ""）。
            // 注：单测 JVM 里 JSONL 行用的是 org.json 参考实现（JSON null → ""），而设备上
            // android.jar 的 JSONObject 给 "null"；二进制行按设备口径固定为 "null"。
            val nullClass = read[11]
            assertEquals("null", nullClass.optString("class"))
            assertEquals("null", nullClass.optString("function"))
            assertEquals("", nullClass.optString("insn"))
            val nullVa = read[12]
            assertEquals("null", nullVa.optString("va"))
            assertEquals("20", nullVa.offsetText)
            // 极大值真的落到位（不是被截断成 0）
            assertEquals(Long.MAX_VALUE, read[7].functionVa!!.toLong())
            assertEquals("ffffffffffffff", read[8].offsetText)
            assertEquals("7fffffffffffffff", read[8].vaText)
            assertEquals(Long.MAX_VALUE, read[9].value!!.toLong())
            assertEquals(Int.MAX_VALUE, read[9].count!!.toInt())
            assertEquals(-1L, read[10].value!!.toLong())
        } finally {
            dir.deleteRecursively()
        }
    }

    /** 分片归并按字节拼接：每片首行 segmentStart 必须让读取端重算差分基准。 */
    @Test
    fun `分片拼接后差分基准在片首重算`() {
        val dir = Files.createTempDirectory("semantic-row-segments-").toFile()
        try {
            val first = listOf(
                functionRow(0x1000, "10", "void a()", "A", "asm/a.dart", 1),
                referenceRow(0x1000, "10", "1004", "ldr x0, [x27, #0x10]", "asm_annotation"),
            )
            val second = listOf(
                // 第二片首行的 VA 比第一片末尾更小：没有 segmentStart 就会解出错误差分
                functionRow(0x800, "10", "void b()", "B", "asm/b.dart", 2),
                referenceRow(0x800, "10", "804", "ldr x0, [x27, #0x10]", "asm_annotation"),
            )
            val file = File(dir, "segments.bin")
            DataOutputStream(BufferedOutputStream(FileOutputStream(file))).use { out ->
                out.writeInt(SemanticRowFormat.MAGIC)
                out.writeInt(SemanticRowFormat.VERSION)
                out.writeInt((first + second).size)
                val encoderFirst = SemanticRowEncoder(out)
                first.forEach { encoderFirst.write(it) }
                val encoderSecond = SemanticRowEncoder(out)
                second.forEach { encoderSecond.write(it) }
            }
            val rows = readAllRows(file)
            assertEquals((first + second).map { it.functionVa }, rows.map { it.functionVa })
            assertEquals(listOf("1000", "1000", "800", "800"), rows.map { it.functionVaText })
            assertEquals(listOf(null, "10", null, "10"), rows.map { it.offsetText })
            assertEquals(listOf("1004", "804"), listOf(rows[1].vaText, rows[3].vaText))
        } finally {
            dir.deleteRecursively()
        }
    }

    // ------------------------------------------------------------ 体积（单元 + 端到端）

    /**
     * 体积回归（两种口径都测，防「改了格式却没瘦」）：
     * 1. **裸行格式**：v6 二进制 < v5 JSONL 文本（§14.8 测试计划的口径）；
     * 2. **现网产物**：v6 `.bin.gz` < v5 `.jsonl.gz`（同批行按 v5 键序/类型渲染后同级别 gzip）。
     *    只比裸字节是恒真的空断言（旧产物本身就是 gz，2026-09-19 独立复核点名），
     *    这里补上 gz 基线。
     *
     * 实测值（跨语料，如实记录，不写成「达标」）：
     * - 本用例 fixture（43 行）：裸 3114B vs JSONL 6988B = −55.4%；gz 217B vs 444B = −51.1%；
     * - 重复度高语料 37,264 行：裸 −66.8% / gz −65.4%；
     * - 多样性高语料 211,095 行（近唯一字符串、随机池槽）：裸 −65.9% / gz −35.4%；
     * - 独立复核 24,340 行 fixture：gz −54.4%。
     * 即：对旧**行格式**稳定 ≈66%；对旧 **gz 产物**随语料多样性在 35%~65% 浮动，
     * **不保证** §14.8 的 60%（该目标按「每行重复键名」的裸 JSONL 估算）。故这里只钉
     * 「严格更小 + ≥25%」这一到处都成立的下界，真机数字待设备取数。
     */
    @Test
    fun `同一 fixture 下二进制字节数小于旧格式（裸 JSONL 与 gz 两种口径）`() {
        val dir = Files.createTempDirectory("semantic-row-size-").toFile()
        try {
            val rows = buildString {
                append("class Account {\n")
                append("  bool isAppVip(Account) {\n")
                append("// ** addr: 0x1000, size: 0x40\n")
                repeat(40) { index ->
                    append("// 0x${(0x1004 + index * 4).toString(16)}: ldr x0, [x27, #0x10] // [pp+0x10] String: \"VipExpired\"\n")
                }
                append("// 0x1104: cmp w0, #0xa\n")
                append("  }\n")
                append("}\n")
            }
            File(dir, "asm").mkdirs()
            File(dir, "asm/main.dart").writeText(rows)
            BlutterSearchIndex.ensureSemanticIndex(dir)

            val index = File(dir, "blutter-semantic-v3.bin.gz")
            assertTrue("索引产出：$index", index.isFile)
            val rawBinary = decompress(index)
            val modelRows = readAllRows(index)
            assertTrue("行数应 > 0", modelRows.size > 0)
            val jsonlBytes = jsonlBytesOf(modelRows)
            assertTrue(
                "二进制裸字节 ${rawBinary.size} 应小于 JSONL 裸字节 $jsonlBytes（行数 ${modelRows.size}）",
                rawBinary.size < jsonlBytes,
            )

            // 旧产物口径：同一批行按 v5 行格式渲染后 gzip（默认压缩级别，与旧 writer 一致）
            val v5Gz = File(dir, "v5-format-measure.jsonl.gz")
            GZIPOutputStream(BufferedOutputStream(FileOutputStream(v5Gz))).use { gz ->
                modelRows.forEach { gz.write((it.toJson().toString() + "\n").toByteArray(Charsets.UTF_8)) }
            }
            val ratio = index.length().toDouble() / v5Gz.length()
            assertTrue(
                "v6 gz ${index.length()} 应小于 v5 gz ${v5Gz.length()}" +
                    "（降幅 ${"%.1f".format((1 - ratio) * 100)}%，行数 ${modelRows.size}）",
                index.length() < v5Gz.length(),
            )
            assertTrue(
                "本 fixture 降幅应 ≥25%：ratio=$ratio v6=${index.length()} v5gz=${v5Gz.length()}",
                ratio < 0.75,
            )
            v5Gz.delete()
        } finally {
            dir.deleteRecursively()
        }
    }

    // ------------------------------------------------------------ 双读兼容

    @Test
    fun `双读：v6 二进制与 v5 gz JSONL、v1 明文 JSONL 同源可读`() {
        val dir = Files.createTempDirectory("semantic-row-dualread-").toFile()
        try {
            val binaryRow = functionRow(0x1000, "40", "bool isVip(Account)", "Account", "asm/main.dart", 3)
            val binaryFile = writeSemanticBinary(dir.resolve("v6.bin"), listOf(binaryRow))

            // v5（gz JSONL）：行内只带 function/class/file 之外的字段，与 v5 写入点一致
            val v5File = File(dir, "blutter-semantic-v2.jsonl.gz")
            GZIPOutputStream(BufferedOutputStream(FileOutputStream(v5File))).use { gz ->
                gz.write(
                    (
                        """{"type":"function","va":"1000","size":"40","function":"bool isVip(Account)","class":"Account","file":"asm/main.dart","line":3}""" + "\n" +
                            """{"type":"reference","offset":"10","va":"1004","functionVa":"1000","insn":"ldr x0, [x27, #0x10]","referenceMode":"asm_annotation"}""" + "\n" +
                            """{"type":"immediate","functionVa":"1000","instructionVa":"0x100c","mnemonic":"cmp","kind":"comparison","value":10,"valueHex":"0xa","text":"// 0x100c: cmp w0, #0xa"}""" + "\n"
                        ).toByteArray(Charsets.UTF_8),
                )
            }

            // v1（明文 JSONL，带旧的内嵌 function/file 字段与 null 值）
            val v1File = File(dir, "blutter-semantic-v1.jsonl")
            v1File.writeText(
                """{"type":"reference","offset":"10","va":"1004","functionVa":"1000","function":"bool isVip()","file":"asm/main.dart","insn":"ldr x0, [x27, #0x10]","referenceMode":null}""" + "\n",
            )

            val binary = readAllRows(binaryFile)
            assertEquals(1, binary.size)
            assertEquals(0x1000L, binary[0].functionVa!!.toLong())
            assertEquals("1000", binary[0].functionVaText)
            assertEquals("bool isVip(Account)", binary[0].function)
            assertEquals(3, binary[0].line!!.toInt())

            val v5 = readAllRows(v5File)
            assertEquals(3, v5.size)
            assertEquals(SemanticRowFormat.TYPE_FUNCTION, v5[0].type)
            assertEquals(0x1000L, v5[0].functionVa!!.toLong())
            assertEquals("40", v5[0].sizeText)
            assertEquals(3, v5[0].line!!.toInt())
            assertEquals(SemanticRowFormat.TYPE_REFERENCE, v5[1].type)
            assertEquals("10", v5[1].offsetText)
            assertEquals("1004", v5[1].vaText)
            assertEquals(0x1000L, v5[1].functionVa!!.toLong())
            assertEquals("ldr x0, [x27, #0x10]", v5[1].insn)
            assertEquals("asm_annotation", v5[1].referenceMode)
            assertEquals(SemanticRowFormat.TYPE_IMMEDIATE, v5[2].type)
            assertEquals(10L, v5[2].value!!.toLong())
            assertEquals("0xa", v5[2].optString("valueHex"))
            // 旧写入点没写 valueHex 之外的键也不能凭空多出来
            assertEquals("", v5[1].optString("size"))

            val v1 = readAllRows(v1File)
            assertEquals(1, v1.size)
            assertEquals("10", v1[0].offsetText)
            assertEquals(0x1000L, v1[0].functionVa!!.toLong())
            assertEquals("ldr x0, [x27, #0x10]", v1[0].insn)
            // 旧行的额外键（function/file）与显式 null 不丢
            assertEquals("bool isVip()", v1[0].optString("function"))
            assertEquals("asm/main.dart", v1[0].optString("file"))
            assertNull(v1[0].referenceMode)
            assertTrue(v1[0].toJson().has("referenceMode"))
            assertTrue(v1[0].toJson().isNull("referenceMode"))
        } finally {
            dir.deleteRecursively()
        }
    }

    /** §14.7 三条消费链路的字段基座：reference.offset / immediate.value / addressing.value+count。 */
    @Test
    fun `三条消费链路的行字段在二进制索引里逐字段到位`() {
        val dir = Files.createTempDirectory("semantic-row-consumers-").toFile()
        try {
            File(dir, "asm").mkdirs()
            File(dir, "pp.txt").writeText("[pp+0x10] String:\"isVip\"\n")
            File(dir, "asm/main.dart").writeText(
                """
                class Account {
                  bool isVip(Account) {
                  // ** addr: 0x1000, size: 0x40
                  // 0x1004: ldr x0, [x27, #0x10] // [pp+0x10] String: "isVip"
                  // 0x1008: cmp w0, #0xa
                  }
                }
                """.trimIndent(),
            )
            BlutterSearchIndex.ensureSemanticIndex(dir)
            val rows = readAllRows(File(dir, "blutter-semantic-v3.bin.gz"))

            val reference = rows.single { it.type == SemanticRowFormat.TYPE_REFERENCE }
            assertEquals("10", reference.offsetText)
            assertEquals("1004", reference.vaText)
            assertEquals(0x1000L, reference.functionVa!!.toLong())
            assertEquals("asm_annotation", reference.referenceMode)
            assertTrue(reference.insn.orEmpty().contains("[pp+0x10]"))

            val immediate = rows.single { it.type == SemanticRowFormat.TYPE_IMMEDIATE }
            assertEquals(10L, immediate.value!!.toLong())
            assertEquals("0x1008", immediate.instructionVaText)
            assertEquals("cmp", immediate.mnemonic)
            assertEquals("comparison", immediate.kind)
            assertTrue(immediate.text.orEmpty().contains("cmp w0, #0xa"))

            val addressing = rows.single { it.type == SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE }
            assertEquals(0x10L, addressing.value!!.toLong())
            assertEquals(1, addressing.count!!.toInt())

            // 三条链路的查询结果仍要能取到（既有语义未变）
            val xref = BlutterSearchIndex.xrefMany(dir, listOf(0x10), 4)
            assertEquals(1, xref.getJSONObject("refsByOffset").getJSONArray("0x10").length())
            val locate = BlutterSearchIndex.searchImmediateValues(
                dir, listOf(10L), emptyList(), emptyList(), emptyList(), 10,
            )
            // 立即数命中链路仍走通：cmp w0, #0xa 的 value=10 必须能被按值命中，
            // 且它与 ldr [x27,#0x10] 的寻址立即数计数（value=16/count=1）互不串味
            assertEquals(10L, locate.getJSONArray("values").getLong(0))
            assertEquals(0, locate.getInt("addressingOffsetsExcluded"))
            val addressingHit = BlutterSearchIndex.searchImmediateValues(
                dir, listOf(16L), emptyList(), emptyList(), emptyList(), 10,
            )
            assertEquals(1, addressingHit.getInt("addressingOffsetsExcluded"))
        } finally {
            dir.deleteRecursively()
        }
    }

    /**
     * P2.2（2026-09-19 独立复核）：损坏/截断索引**不得静默少行**。
     *
     * 旧实现 `catch (_: Exception) return null` 把中途解码异常当成流结束 → 查询少命中、
     * 不报错、也没有 truncated 标记，是最难查的一类回归。现在只有「行首 EOF 且行数与
     * 头部声明一致」才算正常结束。
     */
    @Test
    fun `索引截断或行数声明不符时抛错而不是静默少行`() {
        val dir = Files.createTempDirectory("semantic-row-corrupt-").toFile()
        try {
            val rows = listOf(
                functionRow(0x1000, "40", "bool isVip(Account)", "Account", "asm/a.dart", 2),
                referenceRow(0x1000, "10", "1004", "ldr x0, [x27, #0x10]", "asm_annotation"),
                immediateRow(0x1000, "0x1008", "cmp", "comparison", 10, "// 0x1008: cmp w0, #0xa"),
            )
            val ok = writeSemanticBinary(dir.resolve("ok.bin"), rows)
            assertEquals(3, readAllRows(ok).size)

            // (a) 头部 rowCount 大于实际行数（截断/漏写的等价形态）
            val overDeclared = File(dir, "over-declared.bin")
            val patched = ok.readBytes()
            patched[8] = 0; patched[9] = 0; patched[10] = 0; patched[11] = 9
            overDeclared.writeBytes(patched)
            val declaredFailure = assertThrows(SemanticIndexCorruptException::class.java) {
                readAllRows(overDeclared)
            }
            assertTrue(
                "异常信息应可读：${declaredFailure.message}",
                declaredFailure.message.orEmpty().contains("已读 3 行") &&
                    declaredFailure.message.orEmpty().contains("声明 9 行"),
            )

            // (b) 尾部截断（切在最后一行中间）
            val truncated = File(dir, "truncated.bin")
            val full = ok.readBytes()
            truncated.writeBytes(full.copyOf(full.size - 5))
            assertThrows(SemanticIndexCorruptException::class.java) { readAllRows(truncated) }
        } finally {
            dir.deleteRecursively()
        }
    }

    /** P2.1（独立复核）：function 行「无签名」不得让 `va` 变 JSON null（旧 v5 恒为 hex 文本）。 */
    @Test
    fun `function 行无签名时 va 仍是 hex 文本`() {
        val dir = Files.createTempDirectory("semantic-row-no-signature-").toFile()
        try {
            val rows = listOf(functionRow(0x1a2b3c4d, "40", null, null, "asm/a.dart", 7))
            val read = readAllRows(writeSemanticBinary(dir.resolve("no-signature.bin"), rows))

            assertEquals("1a2b3c4d", read[0].toJson().getString("va"))
            assertEquals("1a2b3c4d", read[0].optString("va"))
            assertNull(read[0].function)
            assertTrue("function 字段才是 JSON null", read[0].toJson().isNull("function"))
            assertTrue(read[0].toJson().isNull("class"))
            assertEquals(0x1a2b3c4dL, read[0].functionVa!!.toLong())
        } finally {
            dir.deleteRecursively()
        }
    }

    /** P2.5(a)：v6 端到端——function 行的 line/size/class 与 searchAsm 命中返回的 line 一致。 */
    @Test
    fun `v6 端到端 function 行的 line size class 与 searchAsm 返回一致`() {
        val dir = Files.createTempDirectory("semantic-row-function-fields-").toFile()
        try {
            File(dir, "asm").mkdirs()
            // 函数头在第 3 行（1-based：class / 签名 / addr 注释）
            File(dir, "asm/main.dart").writeText(
                """
                class Account {
                  bool isAppVip(Account) {
                  // ** addr: 0x1000, size: 0x40
                  // 0x1004: ldr x0, [x27, #0x10] // [pp+0x10] String: "VipExpired"
                  // 0x1008: cmp w0, #0xa
                  }
                }
                """.trimIndent(),
            )
            val meta = BlutterSearchIndex.ensureSemanticIndex(dir)
            assertEquals(1, meta.optInt("scannedFiles"))

            val rows = readAllRows(File(dir, "blutter-semantic-v3.bin.gz"))
            val function = rows.single { it.type == SemanticRowFormat.TYPE_FUNCTION }
            assertEquals(3, function.line)
            assertEquals("40", function.sizeText)
            assertEquals("Account", function.className)
            assertEquals("bool isAppVip(Account)", function.function)
            assertEquals(0x1000L, function.functionVa!!.toLong())

            // v5 JSONL 渲染口径也必须一致（同键同值）
            assertEquals(3, function.toJson().getInt("line"))
            assertEquals("40", function.toJson().getString("size"))
            assertEquals("Account", function.toJson().getString("class"))

            val search = BlutterSearchIndex.searchAsm(dir, "isAppVip", caseInsensitive = true, limit = 20)
            val matchedLines = (0 until search.getJSONArray("matches").length()).map { index ->
                search.getJSONArray("matches").getJSONObject(index).getInt("line")
            }
            assertTrue(
                "searchAsm 命中行里应出现函数行的 line=3（实际 $matchedLines，整包=$search）",
                matchedLines.contains(3),
            )
            // 函数头索引（disasm 用）与语义 function 行必须指向同一个函数
            val disasm = BlutterSearchIndex.disasmFunction(dir, 0x1004, 5)
            assertTrue(disasm.toString(), disasm.getBoolean("found"))
            val disasmFunction = disasm.getJSONObject("function")
            assertEquals("bool isAppVip(Account)", disasmFunction.getString("name"))
            assertEquals("Account", disasmFunction.getString("class"))
            assertEquals("asm/main.dart", disasmFunction.getString("file"))
            assertEquals("0x1000", disasmFunction.getString("addr"))
        } finally {
            dir.deleteRecursively()
        }
    }

    /** P2.5(b)：`scannedRows` 等于索引行数；limit 打满时 `truncated` 为 true。 */
    @Test
    fun `scannedRows 与索引行数一致且 limit 打满时 truncated`() {
        val dir = Files.createTempDirectory("semantic-row-scan-count-").toFile()
        try {
            File(dir, "asm").mkdirs()
            File(dir, "asm/main.dart").writeText(
                """
                class Account {
                  bool isAppVip(Account) {
                  // ** addr: 0x1000, size: 0x40
                  // 0x1004: ldr x0, [x27, #0x10] // [pp+0x10] String: "VipExpired"
                  // 0x1008: mov w1, #0x5
                  }
                }
                """.trimIndent(),
            )
            BlutterSearchIndex.ensureSemanticIndex(dir)
            val total = readAllRows(File(dir, "blutter-semantic-v3.bin.gz")).size
            assertTrue("行数应 >= 3：$total", total >= 3)

            // 未打满：必须读完整条行流（scannedRows == 行数），且不报 truncated
            val full = BlutterSearchIndex.searchAsm(dir, "isAppVip", caseInsensitive = true, limit = 20)
            assertEquals(total, full.getInt("scannedRows"))
            assertFalse(full.getBoolean("truncated"))

            // 打满：limit=1 时命中 >= 2 行 → truncated=true
            val capped = BlutterSearchIndex.searchAsm(dir, "isAppVip", caseInsensitive = true, limit = 1)
            assertEquals(1, capped.getJSONArray("matches").length())
            assertTrue("limit 打满应报 truncated：$capped", capped.getBoolean("truncated"))
        } finally {
            dir.deleteRecursively()
        }
    }

    /** B1-2 联动：倒排必须与查询侧共用同一行解析器（否则 rowId 对不上 → 漏命中）。 */
    @Test
    fun `倒排与 v6 索引同源（candidateMode 自报与缺词回退）`() {
        val dir = Files.createTempDirectory("semantic-row-postings-").toFile()
        try {
            File(dir, "asm").mkdirs()
            File(dir, "asm/main.dart").writeText(
                """
                class Account {
                  bool isAppVip(Account) {
                  // ** addr: 0x1000, size: 0x20
                  // 0x1000: ldr x0, [x27, #0x10] // [pp+0x10] String: "VipExpired"
                  }
                }
                """.trimIndent(),
            )
            BlutterSearchIndex.ensureSemanticIndex(dir)
            assertTrue(File(dir, "blutter-semantic-postings-v1.bin").isFile)
            val postings = SemanticPostings.read(dir)!!
            assertTrue("词元应来自 v6 行文本：${postings.keys}", postings.containsKey("isappvip"))
            // rowId 升序：0 = function 行（函数名命中），1 = 引用行（header 上下文命中）
            assertEquals(listOf(0, 1), postings["isappvip"]!!.toList())

            val hit = BlutterSearchIndex.searchAsm(dir, "isAppVip", caseInsensitive = true, limit = 20)
            assertEquals("postings", hit.getString("candidateMode"))
            assertTrue(hit.getJSONArray("matches").length() >= 1)

            // 缺词 → 整体回退扫描（不产生假阴性），自报 prefilter
            val miss = BlutterSearchIndex.searchAsm(dir, "zzz_absent_term", caseInsensitive = true, limit = 20)
            assertEquals("prefilter", miss.getString("candidateMode"))
            assertEquals(0, miss.getJSONArray("matches").length())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `值编码与空字段在二进制下不改变 opt 语义`() {
        val dir = Files.createTempDirectory("semantic-row-opt-").toFile()
        try {
            val rows = listOf(
                functionRow(0x1000, "40", "void a()", null, "asm/a.dart", 1),
                immediateRow(0x1000, "0x1004", "mov", "assignment", 0, "// 0x1004: mov w0, #0x0"),
                addressingRow(0, 0),
            )
            val read = readAllRows(writeSemanticBinary(dir.resolve("opt.bin"), rows))
            assertEquals(0L, read[1].optLong("value"))
            assertEquals(0, read[1].optInt("value", -1))
            assertEquals(0L, read[2].optLong("value"))
            assertEquals(0, read[2].optInt("count", -1))
            // 缺字段与 JSON null 在二进制下仍可分
            assertEquals("", read[0].optString("insn"))
            assertEquals("null", read[0].optString("class"))
            assertEquals("void a()", read[0].optString("function"))
            assertEquals("func", read[0].optString("missingField", "func"))
            // JSON null 给 "null"（与设备端 android.jar 的 optString 一致），缺字段才给 fallback
            assertEquals("null", read[0].optString("class", "fallback"))
            assertEquals("void a()", read[0].optString("function", "field"))
            assertNull(read[0].className)
            assertNotEquals(0, read[0].toJson().length())
        } finally {
            dir.deleteRecursively()
        }
    }

    // ------------------------------------------------------------ 测试辅助

    private fun functionRow(
        va: Long,
        size: String,
        function: String?,
        className: String?,
        file: String,
        line: Int,
    ) = SemanticRow().apply {
        type = SemanticRowFormat.TYPE_FUNCTION
        functionVa = va
        functionVaText = va.toString(16)
        this.function = function
        if (function == null) markJsonNull(SemanticRowFormat.FN_FUNCTION)
        this.className = className
        if (className == null) markJsonNull(SemanticRowFormat.FN_CLASS)
        this.file = file
        sizeText = size
        this.line = line
    }

    private fun referenceRow(
        functionVa: Long?,
        offset: String,
        va: String?,
        insn: String,
        mode: String,
    ) = SemanticRow().apply {
        type = SemanticRowFormat.TYPE_REFERENCE
        this.functionVa = functionVa
        functionVaText = functionVa?.toString(16)
        offsetText = offset
        vaText = va
        if (va == null) markJsonNull(SemanticRowFormat.REF_VA)
        this.insn = insn
        referenceMode = mode
    }

    private fun immediateRow(
        functionVa: Long?,
        instructionVa: String,
        mnemonic: String,
        kind: String,
        value: Long,
        text: String,
    ) = SemanticRow().apply {
        type = SemanticRowFormat.TYPE_IMMEDIATE
        this.functionVa = functionVa
        functionVaText = functionVa?.toString(16)
        instructionVaText = instructionVa
        this.mnemonic = mnemonic
        this.kind = kind
        this.value = value
        this.text = text
    }

    private fun addressingRow(value: Long, count: Int) = SemanticRow().apply {
        type = SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE
        this.value = value
        this.count = count
    }
}

/** 写一个最小 v6 容器（magic/version/rowCount + 行流），供往返与体积用例共用。 */
internal fun writeSemanticBinary(file: File, rows: List<SemanticRow>): File {
    DataOutputStream(BufferedOutputStream(FileOutputStream(file))).use { out ->
        out.writeInt(SemanticRowFormat.MAGIC)
        out.writeInt(SemanticRowFormat.VERSION)
        out.writeInt(rows.size)
        val encoder = SemanticRowEncoder(out)
        rows.forEach(encoder::write)
    }
    return file
}

/** 走统一解析器读回全部行（自动识别 v6 二进制 / gz JSONL / 明文 JSONL）。 */
internal fun readAllRows(file: File): List<SemanticRow> {
    val rows = mutableListOf<SemanticRow>()
    SemanticRowReader.open(file).use { reader ->
        while (true) {
            val row = reader.next() ?: break
            rows += row
        }
    }
    return rows
}

/** 按旧 JSONL 行格式渲染同一批行的字节数（体积断言的对照口径）。 */
internal fun jsonlBytesOf(rows: List<SemanticRow>): Long {
    var total = 0L
    rows.forEach { row ->
        total += row.toJson().toString().toByteArray(Charsets.UTF_8).size + 1
    }
    return total
}

internal fun decompress(file: File): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    if (file.readBytes().take(2) == listOf(0x1f.toByte(), 0x8b.toByte())) {
        GZIPInputStream(BufferedInputStream(file.inputStream())).use { it.copyTo(out) }
    } else {
        file.inputStream().use { it.copyTo(out) }
    }
    return out.toByteArray()
}

/** 头部校验：v6 容器头（magic/version/rowCount）。 */
internal fun readSemanticHeader(file: File): Triple<Int, Int, Int> {
    DataInputStream(GZIPInputStream(BufferedInputStream(file.inputStream()))).use { input ->
        return Triple(input.readInt(), input.readInt(), input.readInt())
    }
}
