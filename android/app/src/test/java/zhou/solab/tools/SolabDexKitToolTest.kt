package zhou.solab.tools

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class SolabDexKitToolTest {

    @Test
    fun parsesBoundedDistinctMultiStringQuery() {
        assertEquals(
            listOf("token", "signature", "endpoint"),
            SolabDexKitTool.parseKeywords("token|signature\nendpoint|token"),
        )
    }

    @Test
    fun canonicalMethodQidAppendsSignatureDescriptor() {
        assertEquals(
            "Lp4/a;->j(LH4/l;LQ1/a;)V",
            SolabDexKitTool.canonicalMethodQid("p4.a", "j", "(LH4/l;LQ1/a;)V"),
        )
    }

    @Test
    fun canonicalMethodQidPreservesFullDescriptor() {
        assertEquals(
            "Lp4/a;->j(LH4/l;LQ1/a;)V",
            SolabDexKitTool.canonicalMethodQid(
                "p4.a",
                "j",
                "Lp4/a;->j(LH4/l;LQ1/a;)V",
            ),
        )
    }

    @Test
    fun parsesBoundedMixedNumericFeatures() {
        val parsed = SolabDexKitTool.parseNumbers(JSONObject()
            .put("numbers", JSONArray().put(5).put("0x37").put(-2).put(3.5).put(5)))

        assertEquals(listOf<Number>(5, 55L, -2, 3.5), parsed)
    }

    @Test
    fun parsesDistinctCodeAndSymbolTerms() {
        assertEquals(
            listOf("fieldA", "fieldB", "if-eq"),
            SolabDexKitTool.parseFeatureTerms("fieldA|fieldB,if-eq|fieldA"),
        )
    }

    // D24（2026-09-21 独立复验）：含字面竖线的目标串必须能表达。过去无条件拆段，
    // 于是 matchType=Equals 退化成"逐片段精确匹配"，把"不是独立池条目"误报成
    // "无引用"——而当时的 stringMatchNote 正教人用 Equals 复核，两者叠加会得出
    // 错误结论。现在 `\|` 是字面竖线。
    @Test
    fun keepsEscapedPipeAsLiteralPartOfOneTerm() {
        assertEquals(
            listOf("(?i:http|https|rtsp)://"),
            SolabDexKitTool.parseKeywords("(?i:http\\|https\\|rtsp)://"),
        )
    }

    @Test
    fun escapedPipeDoesNotBreakOtherSeparatorsOrPlainTerms() {
        // 未转义的 | 仍分词；`\|` 只影响它自己那一段；`,` 仍是 feature 分隔符。
        assertEquals(
            listOf("a|b", "c"),
            SolabDexKitTool.parseKeywords("a\\|b|c"),
        )
        assertEquals(
            listOf("a|b", "fieldB"),
            SolabDexKitTool.parseFeatureTerms("a\\|b,fieldB"),
        )
    }

    @Test
    fun keepsBackslashLiteralWhenNotEscapingASeparator() {
        // Windows 路径/正则里的反斜杠不该被吃掉（只有紧邻分隔符的 \ 才是转义）。
        assertEquals(
            listOf("C:\\tmp\\x", "y"),
            SolabDexKitTool.parseKeywords("C:\\tmp\\x|y"),
        )
        assertEquals(
            listOf("\\d+"),
            SolabDexKitTool.parseKeywords("\\d+"),
        )
    }

    @Test
    fun ranksIndependentDimensionsBeforeRepeatedSameKindEvidence() {
        assertEquals(201, SolabDexKitTool.autoCandidateScore(2, 1))
        assertEquals(103, SolabDexKitTool.autoCandidateScore(1, 3))
    }
}
