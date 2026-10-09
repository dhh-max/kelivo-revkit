package zhou.solab.engine

import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.util.zip.GZIPInputStream

/**
 * B3-1 语义索引行格式二进制化（2026-09-19，`SEMANTIC_VERSION` 5 → 6）。
 *
 * ## 为什么要改
 *
 * v5 落盘为 gz JSONL（`blutter-semantic-v2.jsonl.gz`），每行重复键名，百万行级
 * 索引里键名/引号/逗号是纯冗余。v6 把*行格式*二进制化：类型 1 字节 + 字段位掩码 +
 * varint（地址类字段走差分），自由文本按 UTF-8 长度前缀内联，外层仍套 GZIP。
 *
 * ## 行格式（逻辑布局，外层 GZIP 包裹）
 *
 * ```
 * magic(4) = 'SEM3'(0x53454D33) | version(4)=6 | rowCount(4)
 * rows...   （rowCount 条；各构建分片的行流顺序拼接，见下）
 *
 * row:
 *   header(1B)  bit0-1 类型 0=function 1=reference 2=immediate 3=addressing_immediate
 *               bit2   hasFunctionVa（该行带函数 VA）
 *               bit3   segmentStart（重算差分基准：每个构建分片的首行置位）
 *   functionVa  varint(zigzag(va - 上一行 va))；segmentStart 行相对于 0
 *   mask(1B)    字段存在位（位序 = 该行型字段表下标，见下）
 *   字段值      按字段表顺序：
 *                 STRING   varint(0)=JSON null；varint((len<<1)|1) + UTF-8 字节
 *                 HEX      varint(zigzag(数值)+1)；0=JSON null；文本由数值还原
 *                          （toString(16)，指令地址带 0x 前缀）
 *                 LONG     varint(zigzag(数值)+1)；0=JSON null
 * ```
 *
 * 数值字段统一 +1 偏置（0 保留给 JSON null，与「字段缺失」由掩码位区分）；偏置在
 * 常见取值区间不增加字节数。`Long.MIN_VALUE` 不可表示（保留值冲突），索引里不存在
 * 该量级（地址/计数/立即数）。
 *
 * 字段表（位序即掩码位）：
 * - `function`             : function, class, file, size(HEX), line(LONG)
 * - `reference`            : offset(HEX 差分，池偏移), va(HEX 差分，指令地址), insn, referenceMode
 * - `immediate`            : instructionVa(HEX 差分), mnemonic, kind, value(LONG), text
 * - `addressing_immediate` : value(LONG), count(LONG)
 *
 * `valueHex` 不入盘（= `signedHex(value)`，纯函数，读出时还原）。
 *
 * ## 逐字段保真（§14.7 的 B3-3 审计结论，违反即静默回归）
 *
 * | 行型 | 必须保真 | 消费方 |
 * | --- | --- | --- |
 * | reference | offset | pool offset 扫描 / xref 专用过滤遍 |
 * | immediate | value | 立即数按值命中 |
 * | addressing_immediate | value, count | 立即数排除计数 |
 * | 全部 | functionVa / line / insn / text（按写入点实际存在的字段） | 命中行输出与上下文反查 |
 *
 * ## 关于差分基准与分片
 *
 * 构建期按文件分片并行写入，归并只做字节拼接，因此每片首行置 `segmentStart`
 * 重算差分基准——读取端不需要知道分片边界也能正确解码（这也是归并能保持
 * 「纯拼接」的原因）。
 *
 * ## 兼容（双读）
 *
 * 读取端按内容识别三种来源：v6 二进制（magic）、v5 gz JSONL、v1 明文 JSONL，
 * 统一产出 [SemanticRow]。旧格式走 [SemanticRow.fromJson]，`opt*` 访问器原样
 * 委派回原 JSONObject，保证旧索引的读取行为与改造前逐字段一致。
 */
internal class SemanticRow {

    /** 行类型，取值见 [SemanticRowFormat.TYPE_FUNCTION] 等；旧 JSONL 里未知类型为 [SemanticRowFormat.TYPE_UNKNOWN]。 */
    var type: Int = SemanticRowFormat.TYPE_FUNCTION

    /** 函数 VA：`function` 行取 `va`，其余行取 `functionVa`；无法解析（旧文件里非十六进制）为 null。 */
    var functionVa: Long? = null

    /** [functionVa] 的文本形态（旧 JSONL 原样、二进制由数值还原），hex 无 `0x` 前缀。 */
    var functionVaText: String? = null

    // ---- function ----
    var function: String? = null
    var className: String? = null
    var file: String? = null
    var sizeText: String? = null
    var line: Int? = null

    // ---- reference ----
    var offsetText: String? = null
    var vaText: String? = null
    var insn: String? = null
    var referenceMode: String? = null

    // ---- immediate ----
    var instructionVaText: String? = null
    var mnemonic: String? = null
    var kind: String? = null
    var value: Long? = null
    var text: String? = null

    // ---- addressing_immediate ----
    var count: Int? = null

    /**
     * 显式 JSON null 的字段位（位序 = 该行型字段表下标）。
     *
     * 必须与「字段缺失」区分：旧写入点会写 `"class":null`（函数无类时），而
     * `JSONObject.optString("class")` 对 JSON null 返回字符串 `"null"`、对缺字段
     * 返回 `""`。消费者（如 functionHeaders 兜底）据此分支，合并两者就是行为漂移。
     */
    var nullMask: Int = 0

    /** 旧 JSONL 来源：`opt*` 委派回原对象，[toJson] 原样返回（含未知键与键序）。 */
    private var source: JSONObject? = null

    fun isNullAt(index: Int): Boolean = (nullMask and (1 shl index)) != 0

    /** 旧 JSONL 状态：字段值以原始对象为准（未知键/键序都保真）。 */
    fun markJsonNull(index: Int) {
        nullMask = nullMask or (1 shl index)
    }

    // ---------------------------------------------------------------- 访问器

    /** 等价 `JSONObject.optString(name)`（缺字段 `""`、JSON null `"null"`）。 */
    fun optString(name: String): String {
        source?.let { return it.optString(name) }
        val value = fieldValue(name) ?: return if (isNullField(name)) "null" else ""
        return value.toString()
    }

    /** 等价 `JSONObject.optString(name, fallback)`（缺字段给 fallback、JSON null 仍给 `"null"`）。 */
    fun optString(name: String, fallback: String): String {
        source?.let { return it.optString(name, fallback) }
        val value = fieldValue(name)
        if (value != null) return value.toString()
        return if (isNullField(name)) "null" else fallback
    }

    /** 等价 `JSONObject.optLong(name)`（缺字段/JSON null/非数值 → 0）。 */
    fun optLong(name: String): Long {
        source?.let { return it.optLong(name) }
        return (fieldValue(name) as? Long) ?: 0L
    }

    /** 等价 `JSONObject.optInt(name, fallback)`。 */
    fun optInt(name: String, fallback: Int): Int {
        source?.let { return it.optInt(name, fallback) }
        return (fieldValue(name) as? Long)?.toInt() ?: fallback
    }

    private fun fieldValue(name: String): Any? = when (name) {
        "type" -> SemanticRowFormat.typeName(type)
        "functionVa" -> if (type == SemanticRowFormat.TYPE_FUNCTION) null else functionVaText
        "va" -> if (type == SemanticRowFormat.TYPE_FUNCTION) functionVaText else vaText
        "function" -> function
        "class" -> className
        "file" -> file
        "size" -> sizeText
        "line" -> line?.toLong()
        "offset" -> offsetText
        "insn" -> insn
        "referenceMode" -> referenceMode
        "instructionVa" -> instructionVaText
        "mnemonic" -> mnemonic
        "kind" -> kind
        "value" -> value
        "valueHex" -> value?.let { SemanticRowFormat.signedHexOf(it) }
        "text" -> text
        "count" -> count?.toLong()
        else -> null
    }

    /** 字段名在本行型字段表里的位序；不属于本行型返回 -1（避免位序跨行型串味）。 */
    private fun ownFieldIndex(name: String): Int = when (type) {
        SemanticRowFormat.TYPE_FUNCTION -> when (name) {
            "function", "va" -> SemanticRowFormat.FN_FUNCTION
            "class" -> SemanticRowFormat.FN_CLASS
            "file" -> SemanticRowFormat.FN_FILE
            "size" -> SemanticRowFormat.FN_SIZE
            "line" -> SemanticRowFormat.FN_LINE
            else -> -1
        }
        SemanticRowFormat.TYPE_REFERENCE -> when (name) {
            "offset" -> SemanticRowFormat.REF_OFFSET
            "va" -> SemanticRowFormat.REF_VA
            "insn" -> SemanticRowFormat.REF_INSN
            "referenceMode" -> SemanticRowFormat.REF_MODE
            else -> -1
        }
        SemanticRowFormat.TYPE_IMMEDIATE -> when (name) {
            "instructionVa" -> SemanticRowFormat.IMM_INSTRUCTION_VA
            "mnemonic" -> SemanticRowFormat.IMM_MNEMONIC
            "kind" -> SemanticRowFormat.IMM_KIND
            "value" -> SemanticRowFormat.IMM_VALUE
            "text" -> SemanticRowFormat.IMM_TEXT
            else -> -1
        }
        SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE -> when (name) {
            "value" -> SemanticRowFormat.ADDR_VALUE
            "count" -> SemanticRowFormat.ADDR_COUNT
            else -> -1
        }
        else -> -1
    }

    private fun isNullField(name: String): Boolean {
        val index = ownFieldIndex(name)
        return index >= 0 && isNullAt(index)
    }

    /**
     * 行级预筛（B1-1）：命中判定所用字段里任一命中即通过。
     *
     * 旧实现是对 JSONL 原文做子串匹配；v6 二进制没有原文，改为逐字段匹配。
     * 两者都**只是行内字段的超集**，不是「命中判定文本」的完整超集：跨字段带空格的
     * query（如 `"cmp w0, #0xa <类名>"`）在拼装后的判定文本里能中，在逐字段预筛里
     * 全不中——与旧实现对 JSONL 原文预筛的表现一致（原文里字段间是 `","` 分隔，
     * 同样不含跨字段 span），不是本批回归。预筛只用来省掉 lowercase 与上下文拼装，
     * 通过与否不改变最终命中判定（判定始终在拼装后的文本上做）。
     * 覆盖范围：function 行 = function/class/file/insn/text；其余行 = insn/text；
     * 非 function 行的 header 上下文由调用侧兜底分支处理。
     */
    fun prefilterHit(prefilter: Regex): Boolean = if (type == SemanticRowFormat.TYPE_FUNCTION) {
        prefilter.containsMatchIn(function.orEmpty()) ||
            prefilter.containsMatchIn(className.orEmpty()) ||
            prefilter.containsMatchIn(file.orEmpty()) ||
            prefilter.containsMatchIn(insn.orEmpty()) ||
            prefilter.containsMatchIn(text.orEmpty())
    } else {
        prefilter.containsMatchIn(insn.orEmpty()) || prefilter.containsMatchIn(text.orEmpty())
    }

    /** 等价旧 `JSONObject(row.toString())`：键序与写入点一致（immediate 证据输出依赖它）。 */
    fun toJson(): JSONObject {
        source?.let { return it }
        val json = JSONObject()
        json.put("type", SemanticRowFormat.typeName(type))
        when (type) {
            SemanticRowFormat.TYPE_FUNCTION -> {
                // `va` 与 `function` 字段的 JSON null 相互独立：无签名（function=null）时
                // va 仍是 hex 文本（旧 v5 恒如此），只有 va 本身缺失才是 JSON null。
                putString(json, "va", functionVaText, functionVaText == null)
                putString(json, "size", sizeText, isNullAt(SemanticRowFormat.FN_SIZE))
                putString(json, "function", function, isNullAt(SemanticRowFormat.FN_FUNCTION))
                putString(json, "class", className, isNullAt(SemanticRowFormat.FN_CLASS))
                putString(json, "file", file, isNullAt(SemanticRowFormat.FN_FILE))
                putInt(json, "line", line, isNullAt(SemanticRowFormat.FN_LINE))
            }
            SemanticRowFormat.TYPE_REFERENCE -> {
                putString(json, "offset", offsetText, isNullAt(SemanticRowFormat.REF_OFFSET))
                putString(json, "va", vaText, isNullAt(SemanticRowFormat.REF_VA))
                putString(json, "functionVa", functionVaText, functionVaText == null)
                putString(json, "insn", insn, isNullAt(SemanticRowFormat.REF_INSN))
                putString(json, "referenceMode", referenceMode, isNullAt(SemanticRowFormat.REF_MODE))
            }
            SemanticRowFormat.TYPE_IMMEDIATE -> {
                putString(json, "functionVa", functionVaText, functionVaText == null)
                putString(json, "instructionVa", instructionVaText, isNullAt(SemanticRowFormat.IMM_INSTRUCTION_VA))
                putString(json, "mnemonic", mnemonic, isNullAt(SemanticRowFormat.IMM_MNEMONIC))
                putString(json, "kind", kind, isNullAt(SemanticRowFormat.IMM_KIND))
                putNumber(json, "value", value, isNullAt(SemanticRowFormat.IMM_VALUE))
                putString(json, "valueHex", value?.let { SemanticRowFormat.signedHexOf(it) }, value == null && isNullAt(SemanticRowFormat.IMM_VALUE))
                putString(json, "text", text, isNullAt(SemanticRowFormat.IMM_TEXT))
            }
            SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE -> {
                putNumber(json, "value", value, isNullAt(SemanticRowFormat.ADDR_VALUE))
                putInt(json, "count", count, isNullAt(SemanticRowFormat.ADDR_COUNT))
            }
        }
        return json
    }

    private fun putString(json: JSONObject, key: String, value: String?, jsonNull: Boolean) {
        if (value != null) json.put(key, value) else if (jsonNull) json.put(key, JSONObject.NULL)
    }

    private fun putNumber(json: JSONObject, key: String, value: Long?, jsonNull: Boolean) {
        if (value != null) json.put(key, value) else if (jsonNull) json.put(key, JSONObject.NULL)
    }

    private fun putInt(json: JSONObject, key: String, value: Int?, jsonNull: Boolean) {
        if (value != null) json.put(key, value) else if (jsonNull) json.put(key, JSONObject.NULL)
    }

    companion object {
        /**
         * 旧 JSONL 行 → [SemanticRow]。
         *
         * 与旧读取点逐字段等价：`functionVa` 只认 `"functionVa":"<hex>"`；function 行的
         * `va` 同义（旧消费方用 `optString("functionVa").ifBlank { optString("va") }`）。
         * 保留原 JSONObject（[source]）供未知键与键序保真。
         */
        fun fromJson(json: JSONObject): SemanticRow {
            val row = SemanticRow()
            row.source = json
            val typeName = json.optString("type")
            row.type = SemanticRowFormat.typeOf(typeName)
            val isFunction = row.type == SemanticRowFormat.TYPE_FUNCTION
            val rawVa = if (isFunction) json.textOrNull("va") else json.textOrNull("functionVa")
            if (rawVa != null) {
                row.functionVaText = rawVa
                row.functionVa = rawVa.toLongOrNull(16)
            }
            when (row.type) {
                SemanticRowFormat.TYPE_FUNCTION -> {
                    row.function = json.textOrNull("function")
                    row.className = json.textOrNull("class")
                    row.file = json.textOrNull("file")
                    row.sizeText = json.textOrNull("size")
                    if (json.has("line")) row.line = json.optInt("line", 0)
                }
                SemanticRowFormat.TYPE_REFERENCE -> {
                    row.offsetText = json.textOrNull("offset")
                    row.vaText = json.textOrNull("va")
                    row.insn = json.textOrNull("insn")
                    row.referenceMode = json.textOrNull("referenceMode")
                }
                SemanticRowFormat.TYPE_IMMEDIATE -> {
                    row.instructionVaText = json.textOrNull("instructionVa")
                    row.mnemonic = json.textOrNull("mnemonic")
                    row.kind = json.textOrNull("kind")
                    if (json.has("value")) row.value = json.optLong("value")
                    row.text = json.textOrNull("text")
                }
                SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE -> {
                    if (json.has("value")) row.value = json.optLong("value")
                    if (json.has("count")) row.count = json.optInt("count", 1)
                }
            }
            return row
        }

        /**
         * JSON 字符串字段：缺字段/JSON null/空串都归一为 null。
         *
         * 只作用于类型化镜像（[toJson] 与 `opt*` 对 JSONL 行仍原样委派原对象），
         * 因而不改变旧索引的读取行为；且抹平单测 JVM（org.json 参考实现）与设备
         * （android.jar）对 JSON null 的 `optString` 差异。
         */
        private fun JSONObject.textOrNull(name: String): String? {
            val value = runCatching { optString(name) }.getOrNull() ?: return null
            return value.takeIf { it.isNotEmpty() && it != "null" }
        }
    }
}

/** v6 二进制行格式常量与字段表；编解码共用同一张表，避免两侧位序漂移。 */
internal object SemanticRowFormat {

    const val MAGIC = 0x53454D33 // 'SEM3'
    const val VERSION = 6

    const val TYPE_FUNCTION = 0
    const val TYPE_REFERENCE = 1
    const val TYPE_IMMEDIATE = 2
    const val TYPE_ADDRESSING_IMMEDIATE = 3
    const val TYPE_UNKNOWN = -1

    // 字段位序（掩码位就是这里的下标）
    const val FN_FUNCTION = 0
    const val FN_CLASS = 1
    const val FN_FILE = 2
    const val FN_SIZE = 3
    const val FN_LINE = 4

    const val REF_OFFSET = 0
    const val REF_VA = 1
    const val REF_INSN = 2
    const val REF_MODE = 3

    const val IMM_INSTRUCTION_VA = 0
    const val IMM_MNEMONIC = 1
    const val IMM_KIND = 2
    const val IMM_VALUE = 3
    const val IMM_TEXT = 4

    const val ADDR_VALUE = 0
    const val ADDR_COUNT = 1

    const val FLAG_HAS_FUNCTION_VA = 0x04
    const val FLAG_SEGMENT_START = 0x08

    /** 单字段字符串上限（字节）。索引里单字段物理上不会超过它；超限视为损坏。 */
    const val MAX_FIELD_BYTES = 1 shl 20

    fun typeName(type: Int): String = when (type) {
        TYPE_FUNCTION -> "function"
        TYPE_REFERENCE -> "reference"
        TYPE_IMMEDIATE -> "immediate"
        TYPE_ADDRESSING_IMMEDIATE -> "addressing_immediate"
        else -> ""
    }

    fun typeOf(name: String): Int = when (name) {
        "function" -> TYPE_FUNCTION
        "reference" -> TYPE_REFERENCE
        "immediate" -> TYPE_IMMEDIATE
        "addressing_immediate" -> TYPE_ADDRESSING_IMMEDIATE
        else -> TYPE_UNKNOWN
    }

    fun signedHexOf(value: Long): String =
        if (value < 0) "-0x${(-value).toString(16)}" else "0x${value.toString(16)}"
}

/**
 * 查询侧与倒排共用的可搜索文本口径（B1-2 §14.6：两侧必须同源，否则倒排收窄会漏行）。
 *
 * 与改造前 `searchSemanticAsm` 的拼装逐字一致：
 * - function 行：function/class/file/insn/text（不含 header 上下文）
 * - 其余行：insn/text + 函数头上下文（function/class/file）
 */
internal fun semanticSearchableText(row: SemanticRow, context: String): String {
    val parts = if (row.type == SemanticRowFormat.TYPE_FUNCTION) {
        listOf(row.function, row.className, row.file, row.insn, row.text)
    } else {
        listOf(row.insn, row.text, context.takeIf(String::isNotBlank))
    }
    return parts.filterNotNull().filter { it.isNotBlank() && it != "null" }.joinToString(" ")
}

/**
 * 行写入器（构建期分片 / 归并尾部聚合共用）。
 *
 * 差分基准（functionVa / 指令地址 / 池偏移）在实例内连续；每片首个行置
 * segmentStart，读取端据此重置基准——所以归并只做字节拼接。
 */
internal class SemanticRowEncoder(out: DataOutputStream) {

    private val out: DataOutputStream = out
    private var previousFunctionVa = 0L
    private var previousInstructionVa = 0L
    private var previousPoolOffset = 0L
    private var started = false

    fun write(row: SemanticRow) {
        var head = row.type and 0x03
        if (row.functionVa != null) head = head or SemanticRowFormat.FLAG_HAS_FUNCTION_VA
        if (!started) {
            head = head or SemanticRowFormat.FLAG_SEGMENT_START
            started = true
            previousFunctionVa = 0L
            previousInstructionVa = 0L
            previousPoolOffset = 0L
        }
        out.writeByte(head)
        row.functionVa?.let { va ->
            writeSigned(out, va - previousFunctionVa)
            previousFunctionVa = va
        }
        val mask = fieldMask(row)
        out.writeByte(mask)
        when (row.type) {
            SemanticRowFormat.TYPE_FUNCTION -> {
                writeString(out, row.function, mask, SemanticRowFormat.FN_FUNCTION)
                writeString(out, row.className, mask, SemanticRowFormat.FN_CLASS)
                writeString(out, row.file, mask, SemanticRowFormat.FN_FILE)
                writeHexText(out, row.sizeText, mask, SemanticRowFormat.FN_SIZE)
                writeNumber(out, row.line?.toLong(), mask, SemanticRowFormat.FN_LINE)
            }
            SemanticRowFormat.TYPE_REFERENCE -> {
                writeHexText(out, row.offsetText, mask, SemanticRowFormat.REF_OFFSET) { value ->
                    val delta = value - previousPoolOffset
                    previousPoolOffset = value
                    delta
                }
                writeHexText(out, row.vaText, mask, SemanticRowFormat.REF_VA) { value ->
                    val delta = value - previousInstructionVa
                    previousInstructionVa = value
                    delta
                }
                writeString(out, row.insn, mask, SemanticRowFormat.REF_INSN)
                writeString(out, row.referenceMode, mask, SemanticRowFormat.REF_MODE)
            }
            SemanticRowFormat.TYPE_IMMEDIATE -> {
                writeHexText(out, row.instructionVaText, mask, SemanticRowFormat.IMM_INSTRUCTION_VA) { value ->
                    val delta = value - previousInstructionVa
                    previousInstructionVa = value
                    delta
                }
                writeString(out, row.mnemonic, mask, SemanticRowFormat.IMM_MNEMONIC)
                writeString(out, row.kind, mask, SemanticRowFormat.IMM_KIND)
                writeNumber(out, row.value, mask, SemanticRowFormat.IMM_VALUE)
                writeString(out, row.text, mask, SemanticRowFormat.IMM_TEXT)
            }
            SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE -> {
                writeNumber(out, row.value, mask, SemanticRowFormat.ADDR_VALUE)
                writeNumber(out, row.count?.toLong(), mask, SemanticRowFormat.ADDR_COUNT)
            }
        }
    }

    private fun fieldMask(row: SemanticRow): Int = when (row.type) {
        SemanticRowFormat.TYPE_FUNCTION ->
            bit(row.function != null, row, SemanticRowFormat.FN_FUNCTION) or
                bit(row.className != null, row, SemanticRowFormat.FN_CLASS) or
                bit(row.file != null, row, SemanticRowFormat.FN_FILE) or
                bit(row.sizeText != null, row, SemanticRowFormat.FN_SIZE) or
                bit(row.line != null, row, SemanticRowFormat.FN_LINE)
        SemanticRowFormat.TYPE_REFERENCE ->
            bit(row.offsetText != null, row, SemanticRowFormat.REF_OFFSET) or
                bit(row.vaText != null, row, SemanticRowFormat.REF_VA) or
                bit(row.insn != null, row, SemanticRowFormat.REF_INSN) or
                bit(row.referenceMode != null, row, SemanticRowFormat.REF_MODE)
        SemanticRowFormat.TYPE_IMMEDIATE ->
            bit(row.instructionVaText != null, row, SemanticRowFormat.IMM_INSTRUCTION_VA) or
                bit(row.mnemonic != null, row, SemanticRowFormat.IMM_MNEMONIC) or
                bit(row.kind != null, row, SemanticRowFormat.IMM_KIND) or
                bit(row.value != null, row, SemanticRowFormat.IMM_VALUE) or
                bit(row.text != null, row, SemanticRowFormat.IMM_TEXT)
        SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE ->
            bit(row.value != null, row, SemanticRowFormat.ADDR_VALUE) or
                bit(row.count != null, row, SemanticRowFormat.ADDR_COUNT)
        else -> 0
    }

    private fun bit(hasValue: Boolean, row: SemanticRow, index: Int): Int =
        if (hasValue || row.isNullAt(index)) 1 shl index else 0

    private fun writeString(out: DataOutputStream, value: String?, mask: Int, index: Int) {
        if (mask and (1 shl index) == 0) return
        if (value == null) {
            writeVarLong(out, 0L) // JSON null
            return
        }
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeVarLong(out, (bytes.size.toLong() shl 1) or 1L)
        out.write(bytes)
    }

    /** 数值字段：`varint(zigzag(value)+1)`，0 保留给 JSON null。 */
    private fun writeNumber(out: DataOutputStream, value: Long?, mask: Int, index: Int) {
        if (mask and (1 shl index) == 0) return
        if (value == null) {
            writeVarLong(out, 0L) // JSON null
            return
        }
        writeVarLong(out, zigzag(value) + 1L)
    }

    /** hex 文本字段：解析成数值后按 `transform` 差分（无需差分时直接给绝对数值）。 */
    private inline fun writeHexText(
        out: DataOutputStream,
        text: String?,
        mask: Int,
        index: Int,
        transform: (Long) -> Long = { it },
    ) {
        if (mask and (1 shl index) == 0) return
        if (text == null) {
            writeVarLong(out, 0L) // JSON null
            return
        }
        writeVarLong(out, zigzag(transform(parseHex(text))) + 1L)
    }
}

/** 行读取源（v6 二进制 / 旧 JSONL 两种实现）。 */
private interface SemanticRowSource {
    fun next(): SemanticRow?
}

/**
 * 语义索引行流：按内容自动识别 v6 二进制（magic）、v5 gz JSONL、v1 明文 JSONL。
 *
 * 流式为不变式：一次只持有一行，不把百万行驻留堆内（既有 O(1) 内存口径）。
 */
internal class SemanticRowReader private constructor(
    private val closeable: Closeable,
    private val source: SemanticRowSource,
) : Closeable {

    fun next(): SemanticRow? = source.next()

    override fun close() {
        runCatching { closeable.close() }
    }

    companion object {
        fun open(file: File): SemanticRowReader {
            val raw = BufferedInputStream(FileInputStream(file), 1 shl 16)
            var stream: InputStream = raw
            try {
                // 探测读到的字节会原样回放（PrefixInputStream），不足长度时退化为 JSONL
                // 而不是抛错：空文件/超短旧索引在改造前也是「读不到行」而非失败。
                val first = ByteArray(2)
                val firstRead = readUpTo(stream, first, 2)
                val gzip = firstRead == 2 && first[0] == 0x1f.toByte() && first[1] == 0x8b.toByte()
                stream = if (gzip) GZIPInputStream(PrefixInputStream(first, stream)) else PrefixInputStream(first, stream)
                val head = ByteArray(4)
                val headRead = readUpTo(stream, head, 4)
                val magic = if (headRead == 4) {
                    ((head[0].toInt() and 0xFF) shl 24) or ((head[1].toInt() and 0xFF) shl 16) or
                        ((head[2].toInt() and 0xFF) shl 8) or (head[3].toInt() and 0xFF)
                } else {
                    0
                }
                return if (magic == SemanticRowFormat.MAGIC) {
                    val input = DataInputStream(PrefixInputStream(head, stream))
                    input.readInt() // 已读 magic
                    input.readInt() // version（格式版本随 SEMANTIC_VERSION 走，读取端不设拒绝分支）
                    val declaredRows = input.readInt() // rowCount：截断/漏写的对账基准
                    SemanticRowReader(input, BinaryRowSource(input, declaredRows))
                } else {
                    val reader = BufferedReader(InputStreamReader(PrefixInputStream(head, stream), Charsets.UTF_8))
                    SemanticRowReader(reader, JsonRowSource(reader))
                }
            } catch (e: Exception) {
                runCatching { stream.close() }
                throw e
            }
        }
    }
}

/**
 * 语义索引损坏（读端）。带可读原因，调用方/工具面据此报错而不是静默给出较少命中。
 */
internal class SemanticIndexCorruptException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

/**
 * 二进制行源。
 *
 * 结束条件只有一个：**行首**读不到 head 字节（EOF），且已读行数与头部声明的 rowCount
 * 一致。中途任何解码异常（半行、字段长度越界、gzip 截断）一律上抛
 * [SemanticIndexCorruptException]——绝不静默少行：静默截断会表现为「搜得到变搜不到」，
 * 既不报错也没有 truncated 标记，是最难查的一类回归（2026-09-19 独立复核点名）。
 */
private class BinaryRowSource(
    private val input: DataInputStream,
    private val declaredRows: Int,
) : SemanticRowSource {

    private var previousFunctionVa = 0L
    private var previousInstructionVa = 0L
    private var previousPoolOffset = 0L
    private var rowsRead = 0

    override fun next(): SemanticRow? {
        val head = try {
            input.readUnsignedByte()
        } catch (e: EOFException) {
            // 行首 EOF = 正常结束；但行数必须与头部声明对得上，否则是截断/漏写。
            if (rowsRead != declaredRows) {
                throw SemanticIndexCorruptException(
                    "SEMANTIC_INDEX_CORRUPT: 行流提前结束，已读 $rowsRead 行 / 头部声明 $declaredRows 行",
                    e,
                )
            }
            return null
        }
        val row = try {
            decodeRow(head)
        } catch (e: Exception) {
            throw SemanticIndexCorruptException(
                "SEMANTIC_INDEX_CORRUPT: 第 ${rowsRead + 1} 行解码失败（${e.javaClass.simpleName}: ${e.message}）",
                e,
            )
        }
        rowsRead++
        return row
    }

    private fun decodeRow(head: Int): SemanticRow {
        if (head and SemanticRowFormat.FLAG_SEGMENT_START != 0) {
            previousFunctionVa = 0L
            previousInstructionVa = 0L
            previousPoolOffset = 0L
        }
        val row = SemanticRow()
        row.type = head and 0x03
        if (head and SemanticRowFormat.FLAG_HAS_FUNCTION_VA != 0) {
            val va = previousFunctionVa + readSigned(input)
            previousFunctionVa = va
            row.functionVa = va
            row.functionVaText = va.toString(16)
        }
        val mask = input.readUnsignedByte()
        fun string(index: Int): String? {
            if (mask and (1 shl index) == 0) return null
            return readString(input)
        }
        fun markNullIfPresent(index: Int) {
            if (mask and (1 shl index) != 0) row.markJsonNull(index)
        }
        when (row.type) {
            SemanticRowFormat.TYPE_FUNCTION -> {
                row.function = string(SemanticRowFormat.FN_FUNCTION)
                if (row.function == null) markNullIfPresent(SemanticRowFormat.FN_FUNCTION)
                row.className = string(SemanticRowFormat.FN_CLASS)
                if (row.className == null) markNullIfPresent(SemanticRowFormat.FN_CLASS)
                row.file = string(SemanticRowFormat.FN_FILE)
                if (row.file == null) markNullIfPresent(SemanticRowFormat.FN_FILE)
                if (mask and (1 shl SemanticRowFormat.FN_SIZE) != 0) {
                    val size = readNumeric(input)
                    if (size != null) row.sizeText = size.toString(16) else markNullIfPresent(SemanticRowFormat.FN_SIZE)
                }
                if (mask and (1 shl SemanticRowFormat.FN_LINE) != 0) {
                    val line = readNumeric(input)
                    if (line != null) row.line = line.toInt() else markNullIfPresent(SemanticRowFormat.FN_LINE)
                }
            }
            SemanticRowFormat.TYPE_REFERENCE -> {
                if (mask and (1 shl SemanticRowFormat.REF_OFFSET) != 0) {
                    val delta = readNumeric(input)
                    if (delta != null) {
                        previousPoolOffset += delta
                        row.offsetText = previousPoolOffset.toString(16)
                    } else {
                        markNullIfPresent(SemanticRowFormat.REF_OFFSET)
                    }
                }
                if (mask and (1 shl SemanticRowFormat.REF_VA) != 0) {
                    val delta = readNumeric(input)
                    if (delta != null) {
                        previousInstructionVa += delta
                        row.vaText = previousInstructionVa.toString(16)
                    } else {
                        markNullIfPresent(SemanticRowFormat.REF_VA)
                    }
                }
                row.insn = string(SemanticRowFormat.REF_INSN)
                if (row.insn == null) markNullIfPresent(SemanticRowFormat.REF_INSN)
                row.referenceMode = string(SemanticRowFormat.REF_MODE)
                if (row.referenceMode == null) markNullIfPresent(SemanticRowFormat.REF_MODE)
            }
            SemanticRowFormat.TYPE_IMMEDIATE -> {
                if (mask and (1 shl SemanticRowFormat.IMM_INSTRUCTION_VA) != 0) {
                    val delta = readNumeric(input)
                    if (delta != null) {
                        previousInstructionVa += delta
                        row.instructionVaText = "0x${previousInstructionVa.toString(16)}"
                    } else {
                        markNullIfPresent(SemanticRowFormat.IMM_INSTRUCTION_VA)
                    }
                }
                row.mnemonic = string(SemanticRowFormat.IMM_MNEMONIC)
                if (row.mnemonic == null) markNullIfPresent(SemanticRowFormat.IMM_MNEMONIC)
                row.kind = string(SemanticRowFormat.IMM_KIND)
                if (row.kind == null) markNullIfPresent(SemanticRowFormat.IMM_KIND)
                if (mask and (1 shl SemanticRowFormat.IMM_VALUE) != 0) {
                    row.value = readNumeric(input)
                    if (row.value == null) markNullIfPresent(SemanticRowFormat.IMM_VALUE)
                }
                row.text = string(SemanticRowFormat.IMM_TEXT)
                if (row.text == null) markNullIfPresent(SemanticRowFormat.IMM_TEXT)
            }
            SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE -> {
                if (mask and (1 shl SemanticRowFormat.ADDR_VALUE) != 0) {
                    row.value = readNumeric(input)
                    if (row.value == null) markNullIfPresent(SemanticRowFormat.ADDR_VALUE)
                }
                if (mask and (1 shl SemanticRowFormat.ADDR_COUNT) != 0) {
                    val count = readNumeric(input)
                    if (count != null) row.count = count.toInt() else markNullIfPresent(SemanticRowFormat.ADDR_COUNT)
                }
            }
        }
        return row
    }

    /** 已按掩码确认字段存在：0 = JSON null，否则 `unzigzag(token-1)`。 */
    private fun readNumeric(input: DataInputStream): Long? {
        val token = readVarLong(input)
        if (token == 0L) return null
        return unzigzag(token - 1L)
    }

    private fun readString(input: DataInputStream): String? {
        val token = readVarLong(input)
        if (token == 0L) return null // JSON null（与「字段缺失」由掩码位区分）
        val length = (token ushr 1).toInt()
        if (length < 0 || length > SemanticRowFormat.MAX_FIELD_BYTES) throw IllegalStateException("CORRUPT_FIELD_LENGTH")
        val bytes = ByteArray(length)
        input.readFully(bytes)
        return String(bytes, Charsets.UTF_8)
    }
}

/** 旧 JSONL 行源：解析失败的行与改造前一致地跳过。 */
private class JsonRowSource(private val reader: BufferedReader) : SemanticRowSource {
    override fun next(): SemanticRow? {
        while (true) {
            val line = reader.readLine() ?: return null
            val json = runCatching { JSONObject(line) }.getOrNull() ?: continue
            return SemanticRow.fromJson(json)
        }
    }
}

/** 已读字节回放流（用于「先探测 magic 再决定解析器」，不依赖 mark/reset 支持）。 */
private class PrefixInputStream(
    private val prefix: ByteArray,
    private val rest: InputStream,
) : InputStream() {

    private var position = 0

    override fun read(): Int {
        if (position < prefix.size) return prefix[position++].toInt() and 0xFF
        return rest.read()
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        if (position < prefix.size) {
            val count = minOf(length, prefix.size - position)
            System.arraycopy(prefix, position, buffer, offset, count)
            position += count
            return count
        }
        return rest.read(buffer, offset, length)
    }

    override fun close() {
        rest.close()
    }
}

/** 最多读满 [length] 字节，读到 EOF 提前收工（返回实读数）。 */
private fun readUpTo(stream: InputStream, buffer: ByteArray, length: Int): Int {
    var read = 0
    while (read < length) {
        val count = stream.read(buffer, read, length - read)
        if (count < 0) break
        read += count
    }
    return read
}

/** hex 文本 → 数值；非法返回 0（写入端只产出自己 toString(16) 的形态，不会走到这里）。 */
private fun parseHex(text: String): Long {
    val trimmed = text.trim()
    return runCatching {
        val body = if (trimmed.startsWith("-")) trimmed.substring(1) else trimmed
        val value = body.removePrefix("0x").removePrefix("0X").toLong(16)
        if (trimmed.startsWith("-")) -value else value
    }.getOrDefault(0L)
}

internal fun writeSigned(out: DataOutputStream, value: Long) {
    writeVarLong(out, zigzag(value))
}

private fun writeVarLong(out: DataOutputStream, value: Long) {
    var remaining = value
    while (true) {
        if (remaining and -0x80L == 0L) {
            out.writeByte(remaining.toInt())
            return
        }
        out.writeByte(((remaining and 0x7F) or 0x80).toInt())
        remaining = remaining ushr 7
    }
}

private fun readSigned(input: DataInputStream): Long = unzigzag(readVarLong(input))

private fun readVarLong(input: DataInputStream): Long {
    var result = 0L
    var shift = 0
    while (true) {
        val byte = input.readUnsignedByte()
        result = result or ((byte and 0x7F).toLong() shl shift)
        if (byte and 0x80 == 0) return result
        shift += 7
        if (shift > 63) return result
    }
}

private fun zigzag(value: Long): Long = (value shl 1) xor (value shr 63)

private fun unzigzag(value: Long): Long = (value ushr 1) xor -(value and 1L)
