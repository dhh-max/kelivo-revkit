package zhou.solab.engine

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * B2-3 回归：数据性/生成代码子树可选不建语义行（用户可配，**默认关闭**）。
 *
 * 覆盖四件事：
 *  1. 默认关闭＝行为不变（既不该跳文件，meta 里也不该出现开关键）；
 *  2. 打开后：词表命中的文件整文件不建行，meta 记录开关与跳过文件数；
 *  3. 开关改变会让旧索引判定为未就绪 → 自动重建（不会"改了开关还读旧索引"）；
 *  4. 召回抽查：被跳过的子树用 `fullScan=true` 仍能全量扫描命中（原文没被删除），
 *     未跳过子树的语义召回不受影响。
 *
 * 同时把"索引行数下降比例"实测值打印出来（B2-3 的验收口径）。
 */
class SemanticNoiseSubtreeSkipTest {

    @After
    fun resetFlag() {
        BlutterSearchIndex.skipNoisySubtrees = false
    }

    @Test
    fun `默认关闭不变，打开后跳过噪音子树并如实回报降幅`() {
        val resultDir = Files.createTempDirectory("solab-b2-3-noise-").toFile()
        try {
            writeFixture(resultDir)

            // ---- 1) 默认关闭：与改造前一致 ----
            val off = BlutterSearchIndex.ensureSemanticIndex(resultDir, force = true, shardOverride = 1)
            assertFalse("默认关闭时不应写 skipNoisyPaths", off.has("skipNoisyPaths"))
            assertFalse("默认关闭时不应写 skippedNoisyFiles", off.has("skippedNoisyFiles"))
            val cached = BlutterSearchIndex.ensureSemanticIndex(resultDir)
            assertTrue("关闭态索引应命中缓存", cached.optBoolean("cacheHit"))
            val rowsOff = readRows(resultDir)
            assertTrue("关闭态应包含噪音子树的行", rowsOff.any { it.contains(NOISY_L10N_FILE) })

            // ---- 2) 打开开关：旧索引判定未就绪 → 重建 ----
            BlutterSearchIndex.skipNoisySubtrees = true
            assertFalse(
                "开关变化后旧索引必须判定未就绪（semanticIndexReady）",
                BlutterSearchIndex.semanticIndexReady(resultDir),
            )
            val on = BlutterSearchIndex.ensureSemanticIndex(resultDir, shardOverride = 1)
            assertFalse("开关变化后不得直接命中缓存", on.optBoolean("cacheHit"))
            assertTrue(on.optBoolean("skipNoisyPaths"))
            assertEquals("跳过的噪音文件数", 4, on.optInt("skippedNoisyFiles"))
            assertTrue(BlutterSearchIndex.semanticIndexReady(resultDir))

            val rowsOn = readRows(resultDir)
            // fixture 自检：四个噪音文件必须被"独立实现的词表判定"认定为噪音（防止断言自我实现）
            noisyFiles.forEach { assertTrue("fixture 判定自检失败：$it", fixtureIsNoisy(it)) }
            // 被跳过子树的文件不再有任何行（reference/immediate 行不带 file，靠 function 行分段归属）
            val onFiles = filesOf(rowsOn)
            onFiles.forEach { assertFalse("被跳过的子树不应有行：$it", fixtureIsNoisy(it)) }
            // 未跳过部分的行逐字段不变（文件顺序保持，仅少了被跳过的文件的行）
            assertEquals(
                "未跳过文件的语义行必须逐字段不变",
                dropNoisyFiles(rowsOff),
                dropNoisyFiles(rowsOn),
            )

            // ---- 3) 行数下降比例（B2-3 验收口径）----
            val drop = (rowsOff.size - rowsOn.size).toDouble() / rowsOff.size
            println("B2_3_ROW_DROP rowsOff=${rowsOff.size} rowsOn=${rowsOn.size} ratio=${"%.4f".format(drop)}")
            assertTrue("打开开关后行数必须下降", rowsOn.size < rowsOff.size)
            assertTrue("降幅应等于被跳过子树的占比", drop > 0.3)

            // ---- 4) 召回抽查 ----
            val noisyMarker = BlutterSearchIndex.searchAsm(resultDir, NOISY_MARKER, caseInsensitive = true, limit = 20)
            assertEquals("语义索引不再召回被跳过子树", 0, noisyMarker.getJSONArray("matches").length())
            val stillFoundByRawScan = BlutterSearchIndex.searchAsm(
                resultDir,
                NOISY_MARKER,
                caseInsensitive = true,
                limit = 20,
                fullScan = true,
                includeThirdParty = true,
            )
            assertTrue(
                "fullScan=true 仍应扫到原文（原文未被删除）",
                stillFoundByRawScan.getJSONArray("matches").length() > 0,
            )
            val firstPartyMarker = BlutterSearchIndex.searchAsm(resultDir, FIRST_PARTY_MARKER, caseInsensitive = true, limit = 20)
            assertTrue(
                "未跳过子树的召回不受影响",
                firstPartyMarker.getJSONArray("matches").length() > 0,
            )

            // ---- 5) 关闭开关：再次识别为未就绪并重建回全量 ----
            BlutterSearchIndex.skipNoisySubtrees = false
            val backOff = BlutterSearchIndex.ensureSemanticIndex(resultDir, shardOverride = 1)
            assertFalse("关回默认后不得命中缓存", backOff.optBoolean("cacheHit"))
            assertFalse(backOff.has("skipNoisyPaths"))
            assertEquals("关回默认后行数恢复", rowsOff.size, readRows(resultDir).size)
        } finally {
            resultDir.deleteRecursively()
        }
    }

    @Test
    fun `开关打开时仅剩 v1 旧索引必须判定未就绪，且搜索如实自报跳过`() {
        val resultDir = Files.createTempDirectory("solab-b2-3-legacy-").toFile()
        try {
            // v1 旧索引没有构建选项记录，无法证明是"当前开关口径"建出来的：
            // 路由层若据此判 ready 就会短路，search/xref/classOutline 永远读旧口径索引。
            File(resultDir, "blutter-semantic-v1.jsonl").writeText("{\"type\":\"function\",\"va\":\"1000\"}\n")
            File(resultDir, "blutter-semantic-v1.meta.json").writeText(JSONObject().put("version", 1).toString())

            assertTrue("开关关闭时 v1 索引可直接复用", BlutterSearchIndex.semanticIndexReady(resultDir))
            BlutterSearchIndex.skipNoisySubtrees = true
            assertFalse(
                "开关打开时 v1 索引必须判定未就绪（与 ensureSemanticIndex 的 legacy 分支同口径）",
                BlutterSearchIndex.semanticIndexReady(resultDir),
            )
        } finally {
            BlutterSearchIndex.skipNoisySubtrees = false
            resultDir.deleteRecursively()
        }
    }

    @Test
    fun `索引跳过了噪音子树时搜索结果必须自报`() {
        val resultDir = Files.createTempDirectory("solab-b2-3-report-").toFile()
        try {
            writeFixture(resultDir)
            // 关闭态：响应不得出现开关键（默认关闭的返回体与改造前逐字节一致）
            BlutterSearchIndex.ensureSemanticIndex(resultDir, force = true, shardOverride = 1)
            val off = BlutterSearchIndex.searchAsm(resultDir, FIRST_PARTY_MARKER, caseInsensitive = true, limit = 20)
            assertFalse("默认关闭时不得出现 skipNoisyPaths", off.has("skipNoisyPaths"))
            assertFalse("默认关闭时不得出现 skippedNoisyFiles", off.has("skippedNoisyFiles"))

            // 打开态：少行不自报会让调用方把"没建索引"读成"确实没有"
            BlutterSearchIndex.skipNoisySubtrees = true
            BlutterSearchIndex.ensureSemanticIndex(resultDir, shardOverride = 1)
            val on = BlutterSearchIndex.searchAsm(resultDir, FIRST_PARTY_MARKER, caseInsensitive = true, limit = 20)
            assertTrue("打开态必须自报 skipNoisyPaths", on.optBoolean("skipNoisyPaths"))
            assertEquals("打开态必须自报跳过文件数", 4, on.optInt("skippedNoisyFiles"))
            assertTrue("提示里应指向 fullScan 兜底", on.optString("hint").contains("fullScan"))
        } finally {
            BlutterSearchIndex.skipNoisySubtrees = false
            resultDir.deleteRecursively()
        }
    }

    @Test
    fun `路径判定覆盖 URL 编码与真实目录两种形态`() {
        // 词表按真实目录写（/l10n/、highlighter/languages/），而 blutter 的 asm 文件是
        // URL 编码的平铺名——两种形态都必须命中，否则开关是空操作。
        assertTrue(BlutterSearchIndex.isNoisyAsmPath("package%3Aapp%2Fl10n%2Fapp_localizations.dart"))
        assertTrue(BlutterSearchIndex.isNoisyAsmPath("package%3Aapp%2Fhighlighter%2Flanguages%2Fgml.dart"))
        assertTrue(BlutterSearchIndex.isNoisyAsmPath("package%3Aintl%2Fsrc%2Fintl%2Fmessages.dart"))
        assertTrue(BlutterSearchIndex.isNoisyAsmPath("generated/json_serializers.dart"))
        assertTrue(BlutterSearchIndex.isNoisyAsmPath("pkg\\l10n\\x.dart"))
        // 反例：相似但不该命中
        assertFalse(BlutterSearchIndex.isNoisyAsmPath("main.dart"))
        assertFalse(BlutterSearchIndex.isNoisyAsmPath("package%3Aapp%2Fgenerated_code.dart"))
        assertFalse(BlutterSearchIndex.isNoisyAsmPath("package%3Aapp%2Fl10n_utils%2Fx.dart"))
        assertFalse(BlutterSearchIndex.isNoisyAsmPath("package%3Aapp%2Fintl%2Fmessage.dart"))
    }

    // ------------------------------------------------------------------ fixture

    private val noisyFiles = listOf(
        NOISY_L10N_FILE,
        NOISY_HIGHLIGHTER_FILE,
        NOISY_INTL_FILE,
        NOISY_GENERATED_FILE,
    )

    /**
     * 独立实现的词表判定（只用于 fixture 自检与行过滤，不调用生产代码）：
     * 与 NOISY_LIBRARY_PATH 同词表，并按 blutter 的 URL 编码平铺名解码。
     */
    private fun fixtureIsNoisy(relativePath: String): Boolean {
        val decoded = relativePath.replace('\\', '/').lowercase().replace("%3a", ":").replace("%2f", "/")
        // 词表按目录边界写；路径首段同样按边界处理（与生产实现一致的宽松方向）
        val bounded = "/$decoded"
        return listOf("/l10n/", "highlighter/languages/", "/intl/messages", "/generated/")
            .any(bounded::contains)
    }

    private fun writeFixture(resultDir: File) {
        val asmDir = File(resultDir, "asm").apply { mkdirs() }
        File(resultDir, "result.json").writeText("{}")
        File(resultDir, "pp.txt").writeText("[pp+0x10] String: \"isVip\"\n")
        // 未跳过：一等公民代码（含 FIRST_PARTY_MARKER）
        writeAsm(asmDir, "main.dart", "FirstPartyThing", FIRST_PARTY_MARKER)
        writeAsm(asmDir, "package%3Aapp%2Fmodule.dart", "AppModule", "moduleMarker")
        // 未跳过：名字相似但不在词表里（/generated/ 需要目录边界）
        writeAsm(asmDir, "package%3Aapp%2Fgenerated_code.dart", "GeneratedCode", "generatedCodeMarker")
        // 跳过：encoded 平铺名 + 真实目录名，各两条
        writeAsm(asmDir, NOISY_L10N_FILE, "AppLocalizations", NOISY_MARKER)
        writeAsm(asmDir, NOISY_HIGHLIGHTER_FILE, "GmlKeywords", NOISY_MARKER)
        writeAsm(asmDir, NOISY_INTL_FILE, "IntlMessages", NOISY_MARKER)
        writeAsm(File(asmDir, "generated"), "json_serializers.dart", "JsonSerializer", NOISY_MARKER)
        // 每个噪音文件都多铺一些行，让"跳过降幅"可测
        noisyFiles.forEach { file ->
            val target = File(asmDir, file)
            val filler = buildString {
                for (block in 0 until 6) {
                    val base = 0x8000 + block * 0x100
                    append("  void noisy$block() {\n")
                    append("    // ** addr: 0x${base.toString(16)}, size: 0x40\n")
                    append("    //     0x${base.toString(16)}: ldr x0, [x27, #0x${(0x30 + block).toString(16)}] // [pp+0x${(0x30 + block).toString(16)}] String: \"$NOISY_MARKER-$block\"\n")
                    append("    //     0x${(base + 4).toString(16)}: mov x1, #0x${block + 1}\n")
                    append("    //     0x${(base + 8).toString(16)}: add x9, x27, #0x1a, lsl #12\n")
                    append("    //     0x${(base + 12).toString(16)}: ldr x2, [x9, #0xba8]\n")
                    append("    //     0x${(base + 16).toString(16)}: cmp x1, #0x2\n")
                    append("    //     0x${(base + 20).toString(16)}: ret\n")
                    append("  }\n")
                }
            }
            target.writeText(target.readText() + filler)
        }
    }

    private fun writeAsm(asmDir: File, rel: String, className: String, marker: String) {
        val target = File(asmDir, rel)
        target.parentFile?.mkdirs()
        target.writeText(
            """
            class $className {
              void run$className() {
                // ** addr: 0x1000, size: 0x20
                //     0x1000: ldr x0, [x27, #0x10] // [pp+0x10] String: "$marker"
                //     0x1004: mov x1, #0x1
                //     0x1008: ret
              }
            }
            """.trimIndent() + "\n",
        )
    }

    /** 行流里各 function 行声明的文件（reference/immediate 行不带 file，按段归属其前的 function）。 */
    private fun filesOf(rows: List<String>): List<String> = rows.mapNotNull { row ->
        val obj = JSONObject(row)
        if (obj.optString("type") != "function") null else obj.optString("file").removePrefix("asm/")
    }

    /**
     * 去掉"噪音子树声明的函数段"的行（function 行 + 其后的 reference/immediate 行），
     * 用于对比开关前后未跳过部分的行；addressing_immediate 是全局聚合，两侧都剔除。
     */
    private fun dropNoisyFiles(rows: List<String>): List<String> {
        val out = mutableListOf<String>()
        var noisy = false
        for (row in rows) {
            val obj = JSONObject(row)
            val type = obj.optString("type")
            if (type == "function") noisy = fixtureIsNoisy(obj.optString("file").removePrefix("asm/"))
            if (type == "addressing_immediate") continue
            if (!noisy) out += row
        }
        return out
    }

    private fun readRows(resultDir: File): List<String> {
        val index = File(resultDir, "blutter-semantic-v3.bin.gz")
        val rows = mutableListOf<String>()
        SemanticRowReader.open(index).use { reader ->
            while (true) {
                val row = reader.next() ?: break
                rows += row.toJson().toString()
            }
        }
        return rows
    }

    private companion object {
        const val NOISY_L10N_FILE = "package%3Aapp%2Fl10n%2Fapp_localizations.dart"
        const val NOISY_HIGHLIGHTER_FILE = "package%3Aflutter_highlight%2Fhighlighter%2Flanguages%2Fgml.dart"
        const val NOISY_INTL_FILE = "package%3Aintl%2Fsrc%2Fintl%2Fmessages.dart"
        const val NOISY_GENERATED_FILE = "generated/json_serializers.dart"
        const val NOISY_MARKER = "noisySubtreeMarker"
        const val FIRST_PARTY_MARKER = "firstPartyMarker"
    }
}
