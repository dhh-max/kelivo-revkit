package zhou.solab.engine

import zhou.solab.tools.KotlinToolStats
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.PriorityQueue
import java.util.zip.GZIPOutputStream

internal data class PpFeatureGroup(
    val id: String,
    val label: String,
    val keywords: List<String>,
    val weight: Int,
)

/**
 * Blutter 产物的精准查询（定位补丁点用）：基于 results/<key>/ 下的 pp.txt 与 asm/ 反汇编树。
 *
 *  - searchPp:  pp.txt 按子串过滤，返回池偏移 + 整行（query=is_vip → [pp+0x1aba8] String:"is_vip"）
 *  - searchAsm: asm/**/*.dart 按子串过滤，命中行附带所在类/函数与文件位置
 *  - xref:      池偏移 → 引用该池项的指令 VA + 所属函数。blutter 已在 asm 里为每条
 *               池引用写了 [pp+0x...] 注释（等价于内存扫 add PP,#hi,lsl #12 + ldr 指令对），
 *               离线即可完成定位，无需 libapp.so 在手。
 */
internal object BlutterSearchIndex {
    // 数据性库路径（高亮语言关键词表 / 国际化文案 / 生成代码）天然包含大量英文
    // 词表，一个长串即可撞中多个业务词条（如 gml.dart 的关键词表命中
    // subscribe/purchase），按词数计分时会压过真实业务候选。命中这些路径的
    // 候选整体降权（保留可见性，只沉底）。
    private val NOISY_LIBRARY_PATH = Regex(
        "highlighter/languages/|/intl/messages|/l10n/|/generated/",
        RegexOption.IGNORE_CASE,
    )
    private const val NOISY_SCORE_FACTOR = 0.35

    /** 词堆判定阈值：单串命中 ≥3 个不同词条即视为词表/文案清单特征。 */
    private const val KEYWORD_PILE_TERMS = 3

    /**
     * 超长数据串阈值：≥2 词条且串长超过此值视为符号表/词表特征——
     * 如 Mathematica 内置符号表（"AASTriangle AbelianGroup Abort …"）
     * 一条几百字符的串命中 2 个词条，正常业务文案极少这么长。
     */
    private const val NOISY_LONG_STRING_CHARS = 240

    /** 词堆/超长数据串判定（与路径无关，纯内容串也能识别）。 */
    private fun isKeywordPile(rawLine: String, matchedTermCount: Int): Boolean =
        matchedTermCount >= KEYWORD_PILE_TERMS ||
            (matchedTermCount >= 2 && rawLine.length >= NOISY_LONG_STRING_CHARS)

    /**
     * 词表/符号表串判定（2026-09-19 真机 QA D6 实测补）：
     * Mathematica 符号表、Steam WebAPI 名称表、Arma 脚本命令表、SQLSTATE 列表这类
     * 数据块**只撞中一个词条**（如整张表里有一个 `member`），所以 [isKeywordPile]
     * 的"≥3 词 / ≥2 词且超长"两条都盖不住它们。
     * 特征很稳定：长串 + 由大量空白分隔的**短 token**（平均 ≤10 字符）。正常业务
     * 文案不会在 200 字符里塞 24 个空格分隔的短词。
     */
    private fun looksLikeWordList(text: String): Boolean {
        if (text.length < NOISY_WORDLIST_MIN_CHARS) return false
        var tokens = 0
        var i = 0
        while (i < text.length && tokens < NOISY_WORDLIST_MIN_TOKENS) {
            while (i < text.length && text[i].isWhitespace()) i++
            if (i >= text.length) break
            while (i < text.length && !text[i].isWhitespace()) i++
            tokens++
        }
        return tokens >= NOISY_WORDLIST_MIN_TOKENS
    }

    private const val NOISY_WORDLIST_MIN_CHARS = 200
    private const val NOISY_WORDLIST_MIN_TOKENS = 24

    /**
     * 数据性库候选整体降权，避免词表/文案串淹没真实业务候选。三类信号：
     * 1) 路径命中数据性库（highlighter/languages、intl、l10n、generated）；
     * 2) 词堆——单串命中 ≥3 个不同词条（如 gml.dart 关键词表一条串撞中
     *    subscribe/subscribed/purchase 多词形）；
     * 3) 超长数据串——≥2 词条且串长 ≥240（符号表/词表拼接串）。
     */
    private fun noiseAdjustedScore(
        base: Int,
        rawLine: String,
        matchedTermCount: Int = 0,
    ): Int =
        if (NOISY_LIBRARY_PATH.containsMatchIn(rawLine) || isKeywordPile(rawLine, matchedTermCount)) {
            (base * NOISY_SCORE_FACTOR).toInt()
        } else {
            base
        }

    /** 供函数级聚合层复用：路径命中数据性库（词表/文案/生成代码）时整体降权。 */
    internal fun isNoisyLibraryPath(path: String): Boolean =
        NOISY_LIBRARY_PATH.containsMatchIn(path)

    /**
     * B2-3（用户可配，默认关闭）：语义索引构建是否跳过数据性/生成代码子树。
     *
     * 打开后，asm/ 下命中 [NOISY_LIBRARY_PATH] 词表的**文件整文件不建语义行**
     * （高亮词表 / l10n 文案 / 生成的 json 代码等——它们是索引体积与构建耗时的
     * 大头，业务定位收益极低）。默认 false = 与改造前逐字节一致。
     *
     * 进程内镜像由 [BlutterCoordinator] 每次工具调用时从
     * `SettingsStore.semanticIndexSkipNoisyPaths` 回读；开关状态写进索引 meta
     * （`skipNoisyPaths`）并参与就绪判定，改开关后自动触发重建。
     */
    @Volatile
    internal var skipNoisySubtrees: Boolean = false

    /**
     * asm 相对路径是否属于数据性/生成代码子树（B2-3 判定，与 [NOISY_LIBRARY_PATH] 同词表）。
     *
     * 必须同时判两种形态：blutter 的 asm 文件名是 **URL 编码的平铺名**
     * （`package%3Aarchive%2Fzip.dart`，见既有测试语料与 [isLikelyThirdParty] 的
     * 同款解码），而词表是按真实目录写的（`/l10n/`、`highlighter/languages/`）——
     * 不解码就永远匹配不上，开关会变成空操作。
     */
    internal fun isNoisyAsmPath(relativePath: String): Boolean {
        // 先折大小写再解码：blutter/既有代码里的编码形态大小写不统一（%3A / %3a），
        // 词表本身 IGNORE_CASE，折大小写不改变判定语义（与 [isLikelyThirdParty] 同款）。
        val normalized = relativePath.replace('\\', '/').lowercase()
        if (matchesNoisyLibraryWordlist(normalized)) return true
        val decoded = normalized.replace("%3a", ":").replace("%2f", "/")
        return decoded != normalized && matchesNoisyLibraryWordlist(decoded)
    }

    /**
     * 词表按目录边界写（`/l10n/`、`highlighter/languages/`），路径**首段**同样要有边界：
     * 否则 `asm/l10n/x.dart` 这类顶层子树会漏判（首段前没有 `/`）。
     * 直接调用（与 [isNoisyLibraryPath] 同口径）之外再补一次带前导斜杠的判定，只放宽不收紧。
     */
    private fun matchesNoisyLibraryWordlist(path: String): Boolean =
        NOISY_LIBRARY_PATH.containsMatchIn(path) || NOISY_LIBRARY_PATH.containsMatchIn("/$path")

    internal const val NOISY_SCORE_FACTOR_VALUE = 0.35
    private const val ARM64_POOL_INDEX = "pp-xref-arm64.jsonl"
    private const val ARM64_POOL_INDEX_V2 = "pp-xref-arm64-v2.bin"
    private const val ARM64_POOL_INDEX_MAGIC = 0x42585232
    private const val ARM64_CLOSURE_CALL_INDEX = "pp-xref-arm64-closure-calls-v1.bin"
    private const val ARM64_CLOSURE_CALL_INDEX_MAGIC = 0x42584331
    private const val ARM64_FUNCTION_INDEX = "arm64-functions.jsonl"
    private const val ASM_PATH_INDEX = "blutter-asm-paths-v1.txt"
    private const val FUNCTION_HEADER_INDEX = "blutter-function-headers-v2.bin"
    private const val FUNCTION_HEADER_INDEX_MAGIC = 0x42464832
    private const val MEMORY_ACCESS_INDEX = "blutter-memory-access-v2.bin"
    private const val MEMORY_ACCESS_INDEX_MAGIC = 0x424d4132
    private const val FIELD_SLICE_INDEX = "blutter-field-slice-v1.bin"
    private const val FIELD_SLICE_INDEX_MAGIC = 0x42465331
    private const val SEMANTIC_INDEX = "blutter-semantic-v3.bin.gz"
    private const val SEMANTIC_META = "blutter-semantic-v3.meta.json"
    private const val SEMANTIC_VERSION = 6
    // 双读兼容（B3-1，一个版本周期）：v5 = gz JSONL，v1 = 明文 JSONL（其 meta version=1）。
    private const val V5_SEMANTIC_INDEX = "blutter-semantic-v2.jsonl.gz"
    private const val V5_SEMANTIC_META = "blutter-semantic-v2.meta.json"
    private const val LEGACY_SEMANTIC_INDEX = "blutter-semantic-v1.jsonl"
    private const val LEGACY_SEMANTIC_META = "blutter-semantic-v1.meta.json"
    private const val FIELD_SLICE_WINDOW = 24
    private const val NO_SLICE_VALUE = Long.MIN_VALUE
    private const val SLICE_COMPARISON = 1
    private const val SLICE_DIRECT_BRANCH = 2
    private const val SLICE_FLAGS_BRANCH = 3
    private const val SLICE_BOOLEAN_RESULT = 4
    private const val SLICE_RETURN = 5
    private const val SLICE_CALL_ARGUMENT = 6
    private const val QUERY_CACHE_LIMIT = 4
    private const val HEAVY_QUERY_CACHE_LIMIT = 2
    private const val PP_LINES_CACHE_LIMIT = 1
    // pp.txt 驻留缓存上限：缓存原始字节（内存 = 文件大小，避免 List<String>
    // 双份缓存打爆 largeHeap）。超过此大小走流式逐行扫描（内存 O(1)）。
    // 128MB 覆盖 200MB 级 APK 的 pp.txt，二次查询从内存解码比磁盘 IO 快 10-100 倍。
    private const val PP_CACHE_MAX_BYTES = 128L * 1024L * 1024L
    private val INSN_VA = Regex("//\\s*0x([0-9a-fA-F]+):")
    private val PP_OFFSET = Regex("^\\s*\\[pp\\+0x([0-9a-fA-F]+)]", RegexOption.IGNORE_CASE)
    private val REF = Regex("\\[pp\\+0x([0-9a-fA-F]+)]", RegexOption.IGNORE_CASE)
    /** 紧凑 JSONL 原始行上的 functionVa 快速提取（避免逐行 jsonDecode；NULL 形态不匹配）。 */
    /**
     * `"functionVa":"<hex>"` 的手写解析（B1-1，2026-09-19）。
     *
     * 语义等价于原正则 `"functionVa":"([0-9a-f]+)"`，但省掉每行一次的正则引擎
     * 调用——语义索引是百万行级，这是查询热路径。
     */
    internal fun functionVaOf(raw: String): Long? {
        val key = "\"functionVa\":\""
        val at = raw.indexOf(key)
        if (at < 0) return null
        var value = 0L
        var digits = 0
        var i = at + key.length
        while (i < raw.length) {
            val c = raw[i]
            val d = when (c) {
                in '0'..'9' -> c - '0'
                in 'a'..'f' -> c - 'a' + 10
                else -> -1
            }
            if (d < 0) break
            value = (value shl 4) or d.toLong()
            digits++
            i++
        }
        // 必须是被引号完整包裹的十六进制串（与旧正则 `"([0-9a-f]+)"` 等价）：
        // 缺引号说明行被截断/损坏，返回 null 而不是取前缀——否则损坏行会被
        // 归到某个不相干的函数上，产生「搜得到但结果错」的静默错误。
        if (digits == 0 || i >= raw.length || raw[i] != '"') return null
        return value
    }
    /** asm 行首的地址前缀（blutter 格式 `0x1234:`，可带 `//`）——offset/va 字段已单独存，insn 里是纯冗余。 */
    private val LEADING_ADDR_PREFIX = Regex("^\\s*(?://\\s*)?0x[0-9a-fA-F]+:\\s?")
    private val FUNC_ADDR = Regex("^\\s*// \\*\\* addr: 0x([0-9a-fA-F]+), size: -?0x([0-9a-fA-F]+).*$", RegexOption.IGNORE_CASE)
    private val CALL_TARGET_RE = Regex("\\b(bl|b)\\s+#?0x([0-9a-fA-F]+)", RegexOption.IGNORE_CASE)
    private val INSN_ADDR = Regex("^\\s*(?://\\s*)?0x([0-9a-fA-F]+):")
    private val VALUE_INSTRUCTION = Regex(
        "^\\s*//\\s+0x([0-9a-fA-F]+):\\s+(mov|movz|movn|cmp|cmn)\\s+[^,]+,\\s*#(-?0x[0-9a-fA-F]+|-?\\d+)\\b",
        RegexOption.IGNORE_CASE,
    )
    private val MEMORY_IMMEDIATE = Regex(
        "^\\s*//\\s+0x[0-9a-fA-F]+:\\s+(?:ldr|ldur|str|stur|ldrb|ldrh|strb|strh)\\w*\\s+.*\\[[^]]*#(-?0x[0-9a-fA-F]+|-?\\d+)[^]]*]",
        RegexOption.IGNORE_CASE,
    )
    private val MEMORY_ACCESS = Regex(
        "^\\s*(?://\\s*)?0x([0-9a-fA-F]+):\\s+((?:ldr|ldur|str|stur|ldrb|ldrh|strb|strh)\\w*)\\s+([^,]+),\\s*\\[([a-z0-9]+),\\s*#(-?0x[0-9a-fA-F]+|-?\\d+)[^]]*]",
        RegexOption.IGNORE_CASE,
    )
    private val ARM64_INSTRUCTION = Regex(
        "^\\s*(?://\\s*)?0x([0-9a-fA-F]+):\\s+([a-z][a-z0-9.]*)\\s*(.*)$",
        RegexOption.IGNORE_CASE,
    )
    private val ARM64_REGISTER = Regex("\\b[wx](\\d{1,2})\\b", RegexOption.IGNORE_CASE)
    private val ARM64_IMMEDIATE = Regex("#(-?0x[0-9a-fA-F]+|-?\\d+)", RegexOption.IGNORE_CASE)
    private val POOL_INTEGER = Regex(
        "^\\s*\\[pp\\+0x([0-9a-fA-F]+)]\\s+(Mint|Smi|Int|Integer):\\s*(-?0x[0-9a-fA-F]+|-?\\d+)\\s*$",
        RegexOption.IGNORE_CASE,
    )
    private val ADD_PP = Regex("\\badd\\s+(x\\d+),\\s*x27,\\s*#(0x[0-9a-fA-F]+|\\d+),\\s*lsl\\s*#12", RegexOption.IGNORE_CASE)
    private val LDR_FROM = Regex("\\bldr\\w*\\s+[^,]+,\\s*\\[(x\\d+),\\s*#(0x[0-9a-fA-F]+|\\d+)]", RegexOption.IGNORE_CASE)
    /**
     * 单行解析上限。asm 指令行物理上不可能超过几 KB；巨行是字符串字面量/数据。
     * ICU 正则（Android java.util.regex 底层）对无锚 find 的回溯栈按行长线性
     * 撑——巨行直接把 native 内存打爆（2026-09-15 真机 Scudo OOM，栈在
     * processAsmFile 的 Matcher.find → UVector64::expandCapacity 实锤）。
     * 超长行跳过指令级解析：pp 池项行/指令行都是短行，语义零损失。
     */
    private const val MAX_PARSE_LINE_CHARS = 8192
    private val NON_OBJECT_BASE_REGISTERS = setOf(15, 26, 27, 28, 29, 30, 31, 32, 127)

    /**
     * ICU Matcher 热路径复用：Android java.util.regex 底层是 ICU4C，Matcher 的
     * 回溯栈（UVector64）在 **native 堆**分配，Java 对象被 GC 后经 ReferenceQueue
     * 才回收 native 侧。构建期逐行解析每行创建 6-8 个短命 Matcher，6 线程几分钟
     * 内产生数千万个——GC 追不上产生速度，native 堆单调堆积直到 Scudo abort
     * （2026-09-15 真机：build 期间 native 涨至 11GB，cleanupAll 无效后崩溃，
     * 崩溃线程正是 ReferenceQueueD）。reset() 复用已分配的回溯栈，每线程每
     * 正则仅一个实例，从源头消灭堆积。仅用于 build/扫描热路径；低频查询路径
     * 的 Matcher 量级小，维持原样。
     */
    private class ReusableMatcher(regex: Regex) {
        private val local = ThreadLocal.withInitial<java.util.regex.Matcher> { regex.toPattern().matcher("") }
        val m: java.util.regex.Matcher get() = local.get()!!
        /** 从头 find；false 时不得读分组。 */
        fun find(input: String): Boolean { val mm = local.get()!!; mm.reset(input); return mm.find() }
        /** 全串匹配（等价 matchEntire）；false 时不得读分组。 */
        fun matches(input: String): Boolean { val mm = local.get()!!; mm.reset(input); return mm.matches() }
        /** 续扫：find 返回 true 后不带参循环调用取全部命中（等价 findAll）。 */
        fun more(): Boolean = local.get()!!.find()
    }

    // build 热路径的线程本地 Matcher（声明与上方 Regex 一一对应）
    private val funcAddrM = ReusableMatcher(FUNC_ADDR)
    private val refM = ReusableMatcher(REF)
    private val ldrFromM = ReusableMatcher(LDR_FROM)
    private val valueInstructionM = ReusableMatcher(VALUE_INSTRUCTION)
    private val memoryAccessM = ReusableMatcher(MEMORY_ACCESS)
    private val memoryImmediateM = ReusableMatcher(MEMORY_IMMEDIATE)
    private val addPpM = ReusableMatcher(ADD_PP)
    private val arm64InsnM = ReusableMatcher(ARM64_INSTRUCTION)
    private val arm64RegM = ReusableMatcher(ARM64_REGISTER)
    private val insnAddrM = ReusableMatcher(INSN_ADDR)
    private val leadingAddrM = ReusableMatcher(LEADING_ADDR_PREFIX)
    private val arm64ImmM = ReusableMatcher(ARM64_IMMEDIATE)
    /** headerAddrSize 专用（被 AsmFastIndex 逐行调用，见该函数注释）。 */
    private val headerAddrM = ReusableMatcher(FUNC_ADDR)

    // ---------------------------------------------------------------- B2-1 行级预筛
    //
    // 构建期原先对每行**无条件**跑 7~9 条正则（百万行级 = 数千万次 ICU 调用），是构建
    // 耗时的大头。这里改成两级：先用便宜的字符/子串判定排除"不可能命中"的行，只对
    // "可能命中"的行跑正则。
    //
    // 硬约束：下面每个谓词都是对应正则命中的**必要条件**（superset）——返回 false 时
    // 正则必然不命中，因此跳过只省时间，不改变任何一行的解析结果（产出逐字节不变）。
    // 必要性由 `BlutterLinePrefilterTest` 以原正则作 oracle 逐例钉住。
    //
    // 大小写与空白口径（**故意取超集**）：这些正则跑在 ICU 上（Android 的
    // java.util.regex 由 PatternNative 实现，JVM 侧匹配机器被整段替换）——
    // AOSP Pattern.java 明写 UNICODE_CASE 被忽略、CASE_INSENSITIVE 恒按 Unicode
    // 标准折叠，`\s` 也不是 JVM 的 ASCII 集。因此：
    //   折叠：除 ASCII 外还须认 ICU 简单折叠的额外等价类（本文件用到的字面量里
    //         只有 `s`/`k` 有多码点等价：U+017F ſ、U+212A K）；
    //   空白：取 ASCII 集 ∪ isWhitespace ∪ isSpaceChar（\p{Z}），覆盖两个平台
    //         各自认的空白。
    // 单测跑在 JVM 上，只会用到其中较窄的一边；宽出的部分让谓词始终是
    // "正则命中"的超集——宁可多跑一条正则，也不能漏判（漏判 = 静默少行）。

    /** java.util.regex 默认 `\s` 的 ASCII 集（JVM 语义）。 */
    private fun isAsciiSpace(c: Char): Boolean =
        c == ' ' || c == '\t' || c == '\n' || c == '\u000B' || c == '\u000C' || c == '\r'

    /** 正则 `\s` 的平台超集：ASCII 集 ∪ Unicode 空白（ICU `[\t\n\f\r\p{Z}]` 亦包含于内）。 */
    private fun isRegexSpace(c: Char): Boolean =
        isAsciiSpace(c) || Character.isWhitespace(c) || Character.isSpaceChar(c)

    /** 大小写折叠（Unicode 简单折叠的等价类，含 ICU 的 U+017F/U+212A）。 */
    private fun foldAsciiCase(c: Char): Char = when (c) {
        in 'A'..'Z' -> (c.code + 32).toChar()
        '\u017F' -> 's'
        '\u212A' -> 'k'
        else -> c
    }

    private fun sameAsciiIgnoringCase(a: Char, b: Char): Boolean = a == b || foldAsciiCase(a) == foldAsciiCase(b)

    /** ASCII 大小写不敏感子串判定（预筛专用；字面量都很短）。 */
    private fun containsIgnoringAsciiCase(haystack: String, needle: String): Boolean {
        if (needle.isEmpty()) return true
        val last = haystack.length - needle.length
        var i = 0
        while (i <= last) {
            if (sameAsciiIgnoringCase(haystack[i], needle[0])) {
                var k = 1
                while (k < needle.length && sameAsciiIgnoringCase(haystack[i + k], needle[k])) k++
                if (k == needle.length) return true
            }
            i++
        }
        return false
    }

    /** 跳过 `\s`（平台超集，见 [isRegexSpace]）后的下标；行首判定用，避免为预筛分配 trim 副本。 */
    private fun skipAsciiSpace(raw: String, from: Int): Int {
        var i = from
        while (i < raw.length && isRegexSpace(raw[i])) i++
        return i
    }

    /** 行首（允许 `\s*`）是否以给定字面量开头——FUNC_ADDR 预筛，无分配。 */
    internal fun startsWithAfterSpace(raw: String, literal: String): Boolean {
        val start = skipAsciiSpace(raw, 0)
        return raw.length - start >= literal.length && raw.startsWith(literal, start)
    }

    private fun isHexDigitChar(c: Char): Boolean =
        (c in '0'..'9') || (c in 'a'..'f') || (c in 'A'..'F')

    /**
     * `[\s]*(//\s*)?0x<hex>:` 形态扫描，返回 `:` 的下标，否则 -1。
     * [requireComment] = true 时只认 `//` 注释形态（VALUE_INSTRUCTION / MEMORY_IMMEDIATE 用）。
     */
    internal fun instructionColonIndex(raw: String, requireComment: Boolean): Int {
        var i = skipAsciiSpace(raw, 0)
        if (i + 1 < raw.length && raw[i] == '/' && raw[i + 1] == '/') {
            i = skipAsciiSpace(raw, i + 2)
        } else if (requireComment) {
            return -1
        }
        if (i + 1 >= raw.length || raw[i] != '0' || !sameAsciiIgnoringCase(raw[i + 1], 'x')) return -1
        i += 2
        val digitsStart = i
        while (i < raw.length && isHexDigitChar(raw[i])) i++
        if (i == digitsStart || i >= raw.length || raw[i] != ':') return -1
        return i
    }

    /**
     * 指令助记符起始下标（`:` 后至少一个 `\s`，且首字符是字母）；不满足返回 -1。
     * 是 ARM64_INSTRUCTION / MEMORY_ACCESS / MEMORY_IMMEDIATE / VALUE_INSTRUCTION
     * 四条指令级正则的必要条件。
     */
    internal fun instructionMnemonicStart(raw: String, requireComment: Boolean = false): Int {
        val colon = instructionColonIndex(raw, requireComment)
        if (colon < 0) return -1
        val spaceStart = colon + 1
        val i = skipAsciiSpace(raw, spaceStart)
        if (i == spaceStart || i >= raw.length) return -1
        // `[a-z]` + IGNORE_CASE 会连折叠后落在 a-z 的字符一起接受（JVM 实测 U+017F
        // 命中，设备 ICU 亦然），所以这里必须用折叠后的判定，否则会漏判整条指令行。
        val folded = foldAsciiCase(raw[i])
        return if (folded in 'a'..'z') i else -1
    }

    /** 助记符是否以给定字面量开头（ASCII 大小写不敏感）。 */
    private fun mnemonicStartsWith(raw: String, at: Int, literal: String): Boolean {
        if (at < 0 || at + literal.length > raw.length) return false
        for (k in literal.indices) if (!sameAsciiIgnoringCase(raw[at + k], literal[k])) return false
        return true
    }

    private fun anyMnemonicAt(raw: String, at: Int, literals: Array<String>): Boolean {
        if (at < 0) return false
        for (literal in literals) if (mnemonicStartsWith(raw, at, literal)) return true
        return false
    }

    /** REF 预筛：行内含 `[pp+0x`（IGNORE_CASE）——`\[pp\+0x([0-9a-fA-F]+)]` 的必要条件。 */
    internal fun hasPpAnnotation(raw: String): Boolean {
        var index = raw.indexOf('[')
        while (index >= 0) {
            if (index + 6 <= raw.length &&
                sameAsciiIgnoringCase(raw[index + 1], 'p') && sameAsciiIgnoringCase(raw[index + 2], 'p') &&
                raw[index + 3] == '+' && raw[index + 4] == '0' && sameAsciiIgnoringCase(raw[index + 5], 'x')
            ) return true
            index = raw.indexOf('[', index + 1)
        }
        return false
    }

    /** LDR_FROM 预筛：同时含 `ldr` 与 `[x<数字>`——该正则的必要条件。 */
    internal fun hasLdrFromForm(raw: String): Boolean {
        if (!containsIgnoringAsciiCase(raw, "ldr")) return false
        var index = raw.indexOf('[')
        while (index >= 0) {
            if (index + 3 <= raw.length &&
                sameAsciiIgnoringCase(raw[index + 1], 'x') && raw[index + 2] in '0'..'9'
            ) return true
            index = raw.indexOf('[', index + 1)
        }
        return false
    }

    /** ADD_PP 预筛：含 `lsl`（IGNORE_CASE）——`...lsl\s*#12` 的必要条件。 */
    internal fun hasPoolAddForm(raw: String): Boolean = containsIgnoringAsciiCase(raw, "lsl")

    private val VALUE_MNEMONICS = arrayOf("mov", "movz", "movn", "cmp", "cmn")
    private val MEMORY_MNEMONICS = arrayOf("ldr", "ldur", "str", "stur", "ldrb", "ldrh", "strb", "strh")

    private data class ActiveFieldSlice(
        val sourceVa: Long,
        val fieldOffset: Long,
        val sourceRegister: Int,
        val registers: MutableSet<Int>,
        var remaining: Int = FIELD_SLICE_WINDOW,
        var flagsTainted: Boolean = false,
    )
    // 语义索引（blutter-semantic-v1.jsonl）按 asm 指令逐行落盘，中型 Flutter app 可达
    // 百万行级；解析成 List<JSONObject> 驻留缓存会打爆 largeHeap（实测 locate 即 OOM）。
    // 语义查询一律流式逐行解析（内存 O(1)），只有函数头（几千条、极小）允许驻留缓存。
    private data class FunctionHeaderCacheKey(val path: String, val modified: Long, val size: Long)
    private data class Arm64FunctionsCacheKey(val path: String, val modified: Long, val size: Long)
    private data class PpLinesCacheKey(val path: String, val modified: Long, val size: Long)
    private data class PpCacheKey(val path: String, val modified: Long, val size: Long, val query: String)
    private data class AsmSearchCacheKey(
        val path: String,
        val sourceFingerprint: String,
        val query: String,
        val caseInsensitive: Boolean,
        val limit: Int,
        val fullScan: Boolean,
        val includePaths: List<String>,
        val excludePaths: List<String>,
        val includeThirdParty: Boolean,
    )
    private val functionHeaderCache = object : LinkedHashMap<FunctionHeaderCacheKey, List<FunctionHeader>>(HEAVY_QUERY_CACHE_LIMIT, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FunctionHeaderCacheKey, List<FunctionHeader>>?): Boolean = size > HEAVY_QUERY_CACHE_LIMIT
    }
    private val ppProfileCache = object : LinkedHashMap<PpCacheKey, JSONObject>(QUERY_CACHE_LIMIT, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PpCacheKey, JSONObject>?): Boolean = size > QUERY_CACHE_LIMIT
    }
    private val ppLocateCache = object : LinkedHashMap<PpCacheKey, JSONObject>(QUERY_CACHE_LIMIT, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PpCacheKey, JSONObject>?): Boolean = size > QUERY_CACHE_LIMIT
    }
    private val ppSearchCache = object : LinkedHashMap<PpCacheKey, JSONObject>(QUERY_CACHE_LIMIT, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PpCacheKey, JSONObject>?): Boolean = size > QUERY_CACHE_LIMIT
    }
    private val ppContextCache = object : LinkedHashMap<PpCacheKey, JSONObject>(QUERY_CACHE_LIMIT, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PpCacheKey, JSONObject>?): Boolean = size > QUERY_CACHE_LIMIT
    }
    private val ppLocatePipelineCache = object : LinkedHashMap<PpCacheKey, JSONObject>(QUERY_CACHE_LIMIT, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PpCacheKey, JSONObject>?): Boolean = size > QUERY_CACHE_LIMIT
    }
    private val ppLinesCache = object : LinkedHashMap<PpLinesCacheKey, ByteArray>(PP_LINES_CACHE_LIMIT, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<PpLinesCacheKey, ByteArray>?): Boolean = size > PP_LINES_CACHE_LIMIT
    }
    private val asmSearchCache = object : LinkedHashMap<AsmSearchCacheKey, JSONObject>(8, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<AsmSearchCacheKey, JSONObject>?): Boolean = size > 8
    }
    private val arm64FunctionsCache = object : LinkedHashMap<Arm64FunctionsCacheKey, List<Long>>(HEAVY_QUERY_CACHE_LIMIT, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Arm64FunctionsCacheKey, List<Long>>?): Boolean = size > HEAVY_QUERY_CACHE_LIMIT
    }

    @JvmField
    internal var ppScanCount = 0

    @Synchronized
    internal fun resetQueryCacheForTest() {
        functionHeaderCache.clear()
        arm64FunctionsCache.clear()
        ppProfileCache.clear()
        ppLocateCache.clear()
        ppSearchCache.clear()
        ppContextCache.clear()
        ppLocatePipelineCache.clear()
        ppLinesCache.clear()
        asmSearchCache.clear()
        ppScanCount = 0
    }

    fun firstPartyAsmRoots(resultDir: File): Set<String> {
        val libraries = File(resultDir, "libraries.jsonl")
        if (!libraries.isFile) return emptySet()
        return libraries.useLines { lines ->
            lines.mapNotNull { raw ->
                val name = runCatching { JSONObject(raw).optString("name") }.getOrNull().orEmpty()
                if (!name.startsWith("file:///")) return@mapNotNull null
                val path = name.replace('\\', '/')
                val marker = "/.dart_tool/"
                val markerIndex = path.indexOf(marker)
                if (markerIndex < 0) return@mapNotNull null
                path.substring(0, markerIndex).substringAfterLast('/').takeIf(String::isNotBlank)
            }.toSet()
        }
    }

    /**
     * 语义索引是否**已就绪**（只读检查，不触发构建）。
     *
     * 用于"要不要先后台建索引"的路由判断：ensureSemanticIndex 自身在未命中
     * 缓存时会同步全量扫 asm/（大包数分钟），不能被当成探针用。
     */
    fun semanticIndexReady(resultDir: File): Boolean {
        val index = File(resultDir, SEMANTIC_INDEX)
        val meta = File(resultDir, SEMANTIC_META)
        if (index.isFile && meta.isFile && File(resultDir, MEMORY_ACCESS_INDEX).isFile &&
            File(resultDir, FIELD_SLICE_INDEX).isFile
        ) {
            val stored = runCatching { JSONObject(meta.readText()) }.getOrNull()
            if (semanticMetaMatchesCurrentOptions(stored)) return true
        }
        val legacyIndex = File(resultDir, LEGACY_SEMANTIC_INDEX)
        val legacyMeta = File(resultDir, LEGACY_SEMANTIC_META)
        // v1 索引没有构建选项记录，无法证明它是"当前开关口径"建出来的：
        // 开关打开时必须判未就绪（与 ensureSemanticIndex 的 legacy 分支同口径），
        // 否则路由层会拿到 ready 而直接短路，search/xref/classOutline 永远读旧口径
        // 索引 —— 开关形同空转且不自报。
        if (!skipNoisySubtrees && legacyIndex.isFile && legacyMeta.isFile) {
            val stored = runCatching { JSONObject(legacyMeta.readText()) }.getOrNull()
            if (stored?.optInt("version") == 1) return true
        }
        return false
    }

    // asm 文件 → `// lib:` 库 URL 的小缓存：候选标注按需读文件首部，重复
    // 候选不重复读盘。
    private val libraryUrlCache = object : LinkedHashMap<String, String>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean = size > 256
    }

    /** 读 asm 文件首部的 `// lib: url '...'`（只读前若干行，带缓存）。 */
    fun libraryUrlOf(asmFile: File): String? {
        if (!asmFile.isFile) return null
        val key = "${asmFile.absolutePath}:${asmFile.lastModified()}"
        synchronized(this) { libraryUrlCache[key]?.let { return it.ifEmpty { null } } }
        val url = runCatching {
            asmFile.useLines { seq ->
                seq.take(12)
                    .firstOrNull { it.trimStart().startsWith("// lib:") || it.contains("// lib: url") }
                    ?.let { line ->
                        Regex("url\\s*[:=]?\\s*'([^']+)'").find(line)?.groupValues?.get(1)
                            ?.takeIf(String::isNotBlank)
                            ?: line.substringAfter("// lib:").removePrefix("url").trim().trim(':', '\'', ' ')
                    }
            }
        }.getOrNull().orEmpty()
        synchronized(this) { libraryUrlCache[key] = url }
        return url.ifEmpty { null }
    }

    /** 从库 URL 取 Dart 包名：`package:dio/src/x.dart` → `dio`；无 package: 前缀返回 null。 */
    fun packageOfLibraryUrl(url: String?): String? {
        val value = url?.trim().orEmpty()
        if (!value.startsWith("package:")) return null
        val rest = value.removePrefix("package:")
        return rest.substringBefore('/').takeIf(String::isNotBlank)
    }

    /**
     * 候选函数的位置与归属标注：VA → (file, class, name) + 库 URL/包名。
     * 索引未就绪或 VA 不在索引里时跳过该条（返回的 map 里没有它）。
     */
    fun annotateFunctions(resultDir: File, vas: Collection<Long>): Map<Long, JSONObject> {
        if (vas.isEmpty()) return emptyMap()
        if (!File(resultDir, FUNCTION_HEADER_INDEX).isFile) return emptyMap()
        val wanted = vas.toHashSet()
        val asmDir = File(resultDir, "asm")
        val out = LinkedHashMap<Long, JSONObject>()
        functionHeaders(resultDir).forEach { header ->
            if (header.va !in wanted || out.containsKey(header.va)) return@forEach
            val libraryUrl = libraryUrlOf(File(asmDir, header.file.removePrefix("asm/")))
            out[header.va] = JSONObject()
                .put("file", header.file)
                .put("class", header.className.orEmpty())
                .put("name", header.name.orEmpty())
                .apply {
                    if (libraryUrl != null) {
                        put("libraryUrl", libraryUrl)
                        put("sourcePackage", packageOfLibraryUrl(libraryUrl) ?: JSONObject.NULL)
                    }
                }
        }
        return out
    }

    /**
     * 推断 App 自有 Dart 包：**入口 main 所在库**的包名（AOT dump 里一定有
     * 应用入口，而依赖库不会有 app 的 main）。比"按名字猜哪些包是依赖"
     * 可靠得多；推不出来返回 null——宁可标"未知"也不给错结论。
     */
    fun appPackage(resultDir: File): String? {
        if (!File(resultDir, FUNCTION_HEADER_INDEX).isFile) return null
        val asmDir = File(resultDir, "asm")
        val entry = functionHeaders(resultDir).firstOrNull { header ->
            val name = header.name.orEmpty()
            Regex("(^|[^A-Za-z0-9_])main\\s*\\(").containsMatchIn(name)
        } ?: return null
        val url = libraryUrlOf(File(asmDir, entry.file.removePrefix("asm/"))) ?: return null
        return packageOfLibraryUrl(url)
    }

    /**
     * 类方法清单（走函数头索引，不扫 asm/）：Dart 类查询的快速路径。
     *
     * 命中判定：类名大小写不敏感精确相等，或对 `pkg.Class` 形态取最后一段
     * 相等；同时接受 `名字片段` 的包含匹配但排在精确命中之后。索引未就绪
     * 时返回 null（调用方负责预热/重试，不在这里同步建索引）。
     */
    fun classOutline(resultDir: File, className: String, limit: Int = 200): JSONObject? {
        val wanted = className.trim()
        if (wanted.isEmpty()) return null
        if (!File(resultDir, FUNCTION_HEADER_INDEX).isFile) return null
        val wantedLower = wanted.lowercase()
        val wantedShort = wanted.substringAfterLast('/').substringAfterLast('.').lowercase()
        val exact = JSONArray()
        val loose = JSONArray()
        var total = 0
        functionHeaders(resultDir).forEach { header ->
            val clazz = header.className?.trim().orEmpty()
            if (clazz.isEmpty()) return@forEach
            val clazzLower = clazz.lowercase()
            val clazzShort = clazzLower.substringAfterLast('/').substringAfterLast('.')
            val isExact = clazzLower == wantedLower || clazzShort == wantedShort
            val isLoose = !isExact && clazzLower.contains(wantedLower)
            if (!isExact && !isLoose) return@forEach
            total++
            val row = JSONObject()
                .put("name", header.name.orEmpty())
                .put("va", "0x${header.va.toString(16)}")
                .put("size", header.size)
                .put("class", clazz)
                .put("file", header.file)
            if (isExact) {
                if (exact.length() < limit) exact.put(row)
            } else if (loose.length() < limit) {
                loose.put(row)
            }
        }
        if (total == 0) return null
        val methods = JSONArray()
        for (index in 0 until exact.length()) methods.put(exact.opt(index))
        for (index in 0 until loose.length()) methods.put(loose.opt(index))
        return JSONObject()
            .put("className", wanted)
            .put("matchMode", if (exact.length() > 0) "class_exact" else "class_substring")
            .put("methodCount", total)
            .put("returned", methods.length())
            .put("truncated", total > methods.length())
            .put("methods", methods)
            .put("source", "blutter-function-header-index")
    }

    /** 语义索引构建进度（已扫文件数）。 */
    internal val semanticIndexDone = java.util.concurrent.atomic.AtomicInteger(0)

    /** 语义索引构建进度（总文件数）；<=0 表示当前无构建在跑。 */
    @Volatile
    internal var semanticIndexTotal: Int = 0
        private set

    /**
     * 语义索引构建锁。查询入口用 tryLock：拿不到说明构建在跑，秒回 indexing
     * 状态信封而不是干等到 MCP 超时（2026-09-15 用户问「构建期间其他工具是否
     * 被禁用、工具是否知道」——现在工具明确知道，且非索引类工具从未受影响）。
     */
    private val buildLock = java.util.concurrent.locks.ReentrantLock()

    /** 构建中的秒回信封：AI 直接可读，带进度与可用工具指引。 */
    internal fun indexingEnvelope(): JSONObject {
        val total = semanticIndexTotal
        val done = semanticIndexDone.get()
        val progress = if (total > 0) "（$done/$total 个 asm 文件）" else ""
        return JSONObject()
            .put("ok", false)
            .put("indexing", true)
            .put("code", "SEMANTIC_INDEX_BUILDING")
            .put("message", "语义索引正在后台构建$progress。构建期间语义检索类查询" +
                "（search_asm/disasm 语义部分/xref/values/trace）暂不可用；" +
                "file 读写、dex 列表、包体分析、pp 定位等工具均不受影响。" +
                "请稍后重试同一查询。")
    }

    /**
     * 索引 meta 与**当前构建选项**是否一致（B3-1 的版本号 + B2-3 的噪音子树开关）。
     *
     * `skipNoisyPaths` 缺省视为 false：旧索引（无该键）在开关关闭时照样就绪，
     * 开关打开时判定为不一致 → 触发重建。
     */
    private fun semanticMetaMatchesCurrentOptions(stored: JSONObject?): Boolean {
        if (stored == null || stored.optInt("version") != SEMANTIC_VERSION) return false
        return stored.optBoolean("skipNoisyPaths", false) == skipNoisySubtrees
    }

    /**
     * 查询入口专用：索引就绪返回 meta；正在构建返回 null（调用方转 indexingEnvelope）。
     * 与 [ensureSemanticIndex] 的差别只在「需要构建且锁被别人持有」时不等待。
     */
    internal fun ensureSemanticIndexIfReady(resultDir: File): JSONObject? {
        val index = File(resultDir, SEMANTIC_INDEX)
        val meta = File(resultDir, SEMANTIC_META)
        if (index.isFile && meta.isFile &&
            File(resultDir, MEMORY_ACCESS_INDEX).isFile && File(resultDir, FIELD_SLICE_INDEX).isFile) {
            val stored = runCatching { JSONObject(meta.readText()) }.getOrNull()
            if (semanticMetaMatchesCurrentOptions(stored)) {
                return JSONObject(stored.toString()).put("cacheHit", true)
            }
        }
        if (!buildLock.tryLock()) return null
        return try { ensureSemanticIndex(resultDir) } finally { buildLock.unlock() }
    }

    /**
     * 语义索引构建的文件分片切分：保持顺序、不重不漏，允许存在空片。
     *
     * 起点必须 clamp——[files].size 可能小于 i*per（2026-09-15 审核实测：
     * 分片数 6 时文件数 19 会走到 subList(20, 19) 抛 IllegalArgumentException，
     * 20/25 会切出空尾片，两种情况都让整个语义索引构建硬失败）。高配机
     * （>6 核且 ≥8GB）scanThreads 恒为 6，是常态档位，不是边角场景。
     */
    internal fun semanticShardParts(files: List<File>, chunkCount: Int): List<List<File>> {
        if (chunkCount <= 1) return listOf(files)
        val per = (files.size + chunkCount - 1) / chunkCount
        return List(chunkCount) { i ->
            val from = (i * per).coerceAtMost(files.size)
            val to = ((i + 1) * per).coerceAtMost(files.size)
            files.subList(from, to)
        }
    }

    /**
     * @param shardOverride 仅供测试：强制分片数覆盖设备档位（0 = 按档位取值）。
     *   分片算法的边界（空尾片 / 起点越界）只在特定 文件数×分片数 组合出现，
     *   靠真机档位复现不稳定，留这个口子给回归测试。
     */
    fun ensureSemanticIndex(resultDir: File, force: Boolean = false, shardOverride: Int = 0): JSONObject {
        // B4-1：构建耗时打点（只在真正进入构建路径后才有意义；缓存命中提前返回）
        val startedAtMillis = System.currentTimeMillis()
        val index = File(resultDir, SEMANTIC_INDEX)
        val meta = File(resultDir, SEMANTIC_META)
        // 快路径无锁读：meta/index 均由 moveAtomic 原子替换，读到旧或新都完整
        if (!force && index.isFile && meta.isFile && File(resultDir, MEMORY_ACCESS_INDEX).isFile &&
            File(resultDir, FIELD_SLICE_INDEX).isFile) {
            val stored = runCatching { JSONObject(meta.readText()) }.getOrNull()
            if (semanticMetaMatchesCurrentOptions(stored)) return JSONObject(stored.toString()).put("cacheHit", true)
        }
        val legacyIndex = File(resultDir, LEGACY_SEMANTIC_INDEX)
        val legacyMeta = File(resultDir, LEGACY_SEMANTIC_META)
        // v1 旧索引没有构建选项记录：仅在开关关闭（默认）时可直接复用；
        // 开关打开时必须重建，否则"跳过噪音子树"对旧目录永远不生效。
        if (!force && !skipNoisySubtrees && legacyIndex.isFile && legacyMeta.isFile) {
            val stored = runCatching { JSONObject(legacyMeta.readText()) }.getOrNull()
            if (stored?.optInt("version") == 1) {
                return JSONObject(stored.toString())
                    .put("index", LEGACY_SEMANTIC_INDEX)
                    .put("legacy", true)
                    .put("cacheHit", true)
            }
        }
        buildLock.lock()
        try {
            // 双检：等锁期间可能已被其他线程建好
            if (!force && index.isFile && meta.isFile &&
                File(resultDir, MEMORY_ACCESS_INDEX).isFile && File(resultDir, FIELD_SLICE_INDEX).isFile) {
                val stored = runCatching { JSONObject(meta.readText()) }.getOrNull()
                if (semanticMetaMatchesCurrentOptions(stored)) {
                    return JSONObject(stored.toString()).put("cacheHit", true)
                }
            }
        val asmDir = File(resultDir, "asm")
        require(asmDir.isDirectory) { "ASM_RESULT_NOT_FOUND" }
        resultDir.mkdirs()
        val tempIndex = File(resultDir, "$SEMANTIC_INDEX.tmp")
        val functionIndex = File(resultDir, FUNCTION_HEADER_INDEX)
        val tempFunctionIndex = File(resultDir, "$FUNCTION_HEADER_INDEX.tmp")
        val memoryIndex = File(resultDir, MEMORY_ACCESS_INDEX)
        val tempMemoryIndex = File(resultDir, "$MEMORY_ACCESS_INDEX.tmp")
        val fieldSliceIndex = File(resultDir, FIELD_SLICE_INDEX)
        val tempFieldSliceIndex = File(resultDir, "$FIELD_SLICE_INDEX.tmp")

        // 文件级分片并行：每线程独立写分片（线程间零共享），主线程按片序归并。
        // 单线程逐行扫百万行 asm 是 20 分钟构建时间的大头（2026-09-15 真机），
        // scanThreads 按设备分级给出并行度（低端 1 线程自动退化为串行）。
        // B2-3：开关打开时，数据性/生成代码子树（词表/文案/生成代码）整文件不建语义行。
        // 默认关闭 → files 与改造前完全一致（连文件顺序都不变）。
        val allFiles = asmDir.walkTopDown().filter { it.isFile && it.extension == "dart" }
            .toList().sortedBy { it.absolutePath }
        val skipNoisy = skipNoisySubtrees
        val files = if (!skipNoisy) allFiles else allFiles.filterNot { isNoisyAsmPath(it.relativeTo(asmDir).path) }
        val skippedNoisyFiles = allFiles.size - files.size
        // 并行度三重闸门：文件数 → 设备档位 → 实时内存水位。2026-09-15 真机崩溃
        // （raster 线程 Vulkan 分配失败，整机高压 + 启动 186s 即崩）：status 轮询
        // 自动预热索引，并行扫描推高 PSS 会加速撞线——水位过 3/4 预算直接串行。
        val pressure = zhou.solab.tools.MemPressure.pressureSnapshot()
        val highWater = pressure.pssMb > pressure.pssBudgetMb * 3 / 4
        val chunkCount =
            if (shardOverride > 0) shardOverride
            else when {
                files.size < 16 -> 1
                highWater -> 1
                else -> zhou.solab.tools.DeviceProfile.scanThreads().coerceIn(1, 6)
            }
        // 日志记录并行度/水位：真机再出 Scudo OOM 时一眼定位当时状态。
        // runCatching：unit test 的 android.util.Log 是 stub，裸调必炸。
        runCatching {
            android.util.Log.i(
                "SoLabIndex",
                "semantic build: files=${files.size} threads=$chunkCount tier=${zhou.solab.tools.DeviceProfile.tier()} " +
                    "pss=${pressure.pssMb}/${pressure.pssBudgetMb}MB highWater=$highWater",
            )
        }
        val chunks = List(chunkCount) { SemanticChunk(resultDir, it) }
        var addressingImmediateTotal = 0
        // 进度上报：indexingEnvelope 秒回时 AI 能看到实时进度
        semanticIndexTotal = files.size
        semanticIndexDone.set(0)
        // 构建期水位中止：入口闸门只查一次，真机实况是 build 启动后 20 秒内
        // native 涨 6GB（Matcher 堆积期）——每 32 文件复查，超 3/4 预算全员
        // 协作退出，宁可索引重建也不能让进程被杀（2026-09-15 真机教训）。
        val pressureAborted = java.util.concurrent.atomic.AtomicBoolean(false)
        // 分片切分见 semanticShardParts（起点 clamp，允许空尾片）。
        val parts = semanticShardParts(files, chunkCount)
        try {
            val pool = java.util.concurrent.Executors.newFixedThreadPool(chunkCount) { r ->
                Thread({
                    runCatching {
                        android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
                    }
                    r.run()
                }, "blutter-semantic-scan").apply { isDaemon = true; priority = Thread.MIN_PRIORITY }
            }
            try {
                // 分片与 chunks 严格 1:1（不用 filter+mapIndexed：过滤会把下标整体
                // 前移，让第 i 片的数据落进 chunks[i-1]，并使归并去读不存在的尾
                // 分片文件——2026-09-15 审核实测 FileNotFoundException）。
                // 空分片只意味着 chunks[idx] 不产出文件，归并侧跳过即可。
                val futures = ArrayList<java.util.concurrent.Future<*>>(parts.size)
                parts.forEachIndexed { idx, part ->
                    if (part.isEmpty()) return@forEachIndexed
                    futures += pool.submit {
                        for ((fileIdx, file) in part.withIndex()) {
                            if (pressureAborted.get()) break
                            if (fileIdx > 0 && fileIdx % 32 == 0) {
                                val p = zhou.solab.tools.MemPressure.pressureSnapshot()
                                if (p.pssMb > p.pssBudgetMb * 3 / 4) {
                                    pressureAborted.set(true)
                                    runCatching {
                                        android.util.Log.w(
                                            "SoLabIndex",
                                            "semantic build aborted: pss=${p.pssMb}/${p.pssBudgetMb}MB at file $fileIdx/${part.size}",
                                        )
                                    }
                                    break
                                }
                            }
                            processAsmFile(file, "asm/${file.relativeTo(asmDir).path}", chunks[idx])
                            semanticIndexDone.incrementAndGet()
                        }
                    }
                }
                futures.forEach { it.get() }
                if (pressureAborted.get()) {
                    throw IllegalStateException(
                        "MEMORY_PRESSURE_ABORT: 语义索引构建因内存水位过高主动中止" +
                            "（分片已清理，不会残留半成品）。这不是执行故障：稍候重试同一调用即可续建。",
                    )
                }
                // 空分片不产生文件（写入器从未打开），归并侧必须跳过——直接
                // copy 会 FileNotFoundException（2026-09-15 审核实测）。
                // 注意：必须在 closeWriters() **之前**取快照，close 会把
                // 写入器引用清空，之后 hasOutput() 恒为 false。
                val live = chunks.filter { it.hasOutput() }
                chunks.forEach { it.closeWriters() }
                // 归并（主线程）：magic 头 + 按片序拼接分片数据。
                DataOutputStream(BufferedOutputStream(FileOutputStream(tempFieldSliceIndex))).use { out ->
                    out.writeInt(FIELD_SLICE_INDEX_MAGIC)
                    live.forEach { it.copyFieldSliceTo(out) }
                }
                DataOutputStream(BufferedOutputStream(FileOutputStream(tempMemoryIndex))).use { out ->
                    out.writeInt(MEMORY_ACCESS_INDEX_MAGIC)
                    live.forEach { it.copyMemoryTo(out) }
                }
                DataOutputStream(BufferedOutputStream(FileOutputStream(tempFunctionIndex))).use { out ->
                    out.writeInt(FUNCTION_HEADER_INDEX_MAGIC)
                    live.forEach { it.copyFunctionsTo(out) }
                }
                // addressing_immediate 聚合记录：各分片 map 相加合并后统一落尾部
                val addressingImmediateCounts = HashMap<Long, Int>()
                chunks.forEach { chunk ->
                    chunk.addressingImmediates.forEach { (value, count) ->
                        addressingImmediateCounts.merge(value, count, Int::plus)
                    }
                }
                // addressingImmediateValues 取合并后的去重数量（meta 与行流都要用）
                addressingImmediateTotal = addressingImmediateCounts.size
                // B3-1：magic/version/rowCount 头 + 各分片行流字节拼接（分片首行 segmentStart 已内建，
                // 读取端据此重算差分基准，所以归并仍是纯字节拼接）。
                // 外层保持 GZIP：体积断言见 SemanticRowFormatTest（裸二进制 < 裸 JSONL）。
                GZIPOutputStream(BufferedOutputStream(FileOutputStream(tempIndex))).use { gz ->
                    DataOutputStream(BufferedOutputStream(gz, 1 shl 16)).use { out ->
                        out.writeInt(SemanticRowFormat.MAGIC)
                        out.writeInt(SemanticRowFormat.VERSION)
                        out.writeInt(live.sumOf { it.semanticRowCount } + addressingImmediateTotal)
                        live.forEach { it.copySemanticTo(out) }
                        val tailEncoder = SemanticRowEncoder(out)
                        addressingImmediateCounts.forEach { (value, count) ->
                            tailEncoder.write(SemanticRow().apply {
                                type = SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE
                                this.value = value
                                this.count = count
                            })
                        }
                    }
                }
            } finally {
                pool.shutdownNow()
            }
        } finally {
            chunks.forEach { it.cleanup() }
        }
        var scannedFiles = 0
        var functionCount = 0
        var referenceCount = 0
        var immediateCount = 0
        var memoryAccessCount = 0
        var fieldSliceCount = 0
        chunks.forEach { chunk ->
            scannedFiles += chunk.scannedFiles
            functionCount += chunk.functionCount
            referenceCount += chunk.referenceCount
            immediateCount += chunk.immediateCount
            memoryAccessCount += chunk.memoryAccessCount
            fieldSliceCount += chunk.fieldSliceCount
        }
        moveAtomic(tempIndex, index)
        moveAtomic(tempFunctionIndex, functionIndex)
        moveAtomic(tempMemoryIndex, memoryIndex)
        moveAtomic(tempFieldSliceIndex, fieldSliceIndex)
        File(resultDir, "blutter-memory-access-v1.bin").delete()
        // B1-2：倒排（term → rowIds）。构建失败只记不算错——查询侧会回退扫描。
        // 失败时清掉旧倒排文件：它按旧索引的 rowId 编号，留着会让候选收窄指向错行。
        runCatching { buildSemanticPostings(resultDir, index) }
            .onFailure { runCatching { File(resultDir, SemanticPostings.FILE_NAME).delete() } }
        // B4-1：三指标入账（构建耗时 / 索引体积）。查询侧耗时在 searchSemanticAsm
        // 里另记 `blutter.index.search`——后续优化用数据说话，不靠体感。
        runCatching {
            KotlinToolStats.record(
                tool = "blutter.index.build",
                success = true,
                micros = (System.currentTimeMillis() - startedAtMillis) * 1000,
            )
            KotlinToolStats.record(
                tool = "blutter.index.sizeBytes",
                success = true,
                micros = index.length(),
            )
        }
        val generated = JSONObject()
            .put("version", SEMANTIC_VERSION)
            .put("buildMillis", System.currentTimeMillis() - startedAtMillis)
            .put("indexBytes", index.length())
            .put("index", SEMANTIC_INDEX)
            .put("scannedFiles", scannedFiles)
            .put("functions", functionCount)
            .put("references", referenceCount)
            .put("immediates", immediateCount)
            .put("memoryAccesses", memoryAccessCount)
            .put("fieldSliceSinks", fieldSliceCount)
            .put("addressingImmediateValues", addressingImmediateTotal)
            .put("functionIndex", FUNCTION_HEADER_INDEX)
            .put("functionIndexBytes", functionIndex.length())
            .put("memoryAccessIndex", MEMORY_ACCESS_INDEX)
            .put("memoryAccessIndexBytes", memoryIndex.length())
            .put("fieldSliceIndex", FIELD_SLICE_INDEX)
            .put("fieldSliceIndexBytes", fieldSliceIndex.length())
            .put("indexBytes", index.length())
            .put("cacheHit", false)
            // B2-3：仅在开关打开时落键——默认关闭的 meta 与改造前逐字节一致；键存在
            // 与否参与就绪判定（改了开关就重建，不会读到旧口径索引）。
            .apply {
                if (skipNoisy) {
                    put("skipNoisyPaths", true)
                    put("skippedNoisyFiles", skippedNoisyFiles)
                }
            }
        val tempMeta = File(resultDir, "$SEMANTIC_META.tmp")
        tempMeta.writeText(generated.toString())
        moveAtomic(tempMeta, meta)
        legacyIndex.delete()
        legacyMeta.delete()
        // v6 已完整落盘（索引 + meta 均原子替换），旧 v5 JSONL 是纯冗余：清理。
        // 运维含义：回滚到旧代码不会缺数据——旧代码看到没有 v5 产物会**从 asm/ 全量重建**
        // （asm 目录是原始输入，索引都是派生数据），只是要付一次重建耗时。
        // 读取端仍保留 v5/v1 双读路径（B3-1 兼容期）：v6 缺失的目录照样能读旧索引。
        File(resultDir, V5_SEMANTIC_INDEX).delete()
        File(resultDir, V5_SEMANTIC_META).delete()
        clearSemanticQueryCache(resultDir)
        return generated
        } finally {
            semanticIndexTotal = 0
            buildLock.unlock()
        }
    }

    /** 单分片写上下文：每线程独立一套输出与计数，归并时按片序拼接（线程间零共享）。 */
    private class SemanticChunk(resultDir: File, tag: Int) {
        private val semanticFile = File(resultDir, "$SEMANTIC_INDEX.chunk$tag.tmp")
        private val functionFile = File(resultDir, "$FUNCTION_HEADER_INDEX.chunk$tag.tmp")
        private val memoryFile = File(resultDir, "$MEMORY_ACCESS_INDEX.chunk$tag.tmp")
        private val fieldSliceFile = File(resultDir, "$FIELD_SLICE_INDEX.chunk$tag.tmp")

        // 分片保持明文（多成员 .gz 拼接 Java GZIPInputStream 读不全），归并时统一压缩。
        // B3-1：分片落 v6 二进制行（magic/version/rowCount 只在归并后的成品里写一次）。
        private var semantic: DataOutputStream? = null
        private var semanticEncoder: SemanticRowEncoder? = null
        private var functions: DataOutputStream? = null
        private var memory: DataOutputStream? = null
        private var fieldSlice: DataOutputStream? = null

        val addressingImmediates = HashMap<Long, Int>()
        var scannedFiles = 0
        var functionCount = 0
        var referenceCount = 0
        var immediateCount = 0
        var memoryAccessCount = 0
        var fieldSliceCount = 0
        var semanticRowCount = 0

        fun semanticOut(): DataOutputStream =
            semantic ?: DataOutputStream(
                BufferedOutputStream(java.io.FileOutputStream(semanticFile), 1 shl 16),
            ).also { semantic = it }

        /** 写一行 v6 二进制语义行（分片首行自带 segmentStart，归并只需字节拼接）。 */
        fun writeSemanticRow(row: SemanticRow) {
            val encoder = semanticEncoder ?: SemanticRowEncoder(semanticOut()).also { semanticEncoder = it }
            encoder.write(row)
            semanticRowCount++
        }

        fun functionsOut(): DataOutputStream =
            functions ?: DataOutputStream(BufferedOutputStream(java.io.FileOutputStream(functionFile))).also { functions = it }

        fun memoryOut(): DataOutputStream =
            memory ?: DataOutputStream(BufferedOutputStream(java.io.FileOutputStream(memoryFile))).also { memory = it }

        fun fieldSliceOut(): DataOutputStream =
            fieldSlice ?: DataOutputStream(BufferedOutputStream(java.io.FileOutputStream(fieldSliceFile))).also { fieldSlice = it }

        /**
         * 该分片是否产出过文件（写入器被打开过）。
         *
         * 空分片（文件数 < 分片数时尾部那几个）从未打开写入器，分片文件不存在；
         * 归并侧必须跳过，否则 FileNotFoundException 让整次构建硬失败。
         */
        fun hasOutput(): Boolean =
            semantic != null || functions != null || memory != null || fieldSlice != null

        fun closeWriters() {
            runCatching { semantic?.flush() }
            runCatching { semantic?.close() }
            runCatching { functions?.close() }
            runCatching { memory?.close() }
            runCatching { fieldSlice?.close() }
            semantic = null; semanticEncoder = null; functions = null; memory = null; fieldSlice = null
        }

        /**
         * 拷贝该分片的语义行流。
         *
         * **必须判存在性**：semantic writer 是惰性的（写出过语义行才建文件），而
         * [hasOutput] 只要任一 writer 被打开就为 true —— 只含注释、不产出任何语义行的
         * .dart（依赖包文件）独占一片时，该分片在 live 里但没有语义行文件；不判就会
         * FileNotFoundException 让整次构建失败且不写 meta（该 resultDir 永久不可用）。
         * 跳过是安全的：该分片 semanticRowCount 本来就是 0，头里的 rowCount 不会失真。
         */
        fun copySemanticTo(target: java.io.OutputStream) {
            if (!semanticFile.isFile) return
            FileInputStream(semanticFile).use { it.copyTo(target, 1 shl 16) }
        }

        fun copyFunctionsTo(target: DataOutputStream) {
            FileInputStream(functionFile).use { it.copyTo(target, 1 shl 16) }
        }

        fun copyMemoryTo(target: DataOutputStream) {
            FileInputStream(memoryFile).use { it.copyTo(target, 1 shl 16) }
        }

        fun copyFieldSliceTo(target: DataOutputStream) {
            FileInputStream(fieldSliceFile).use { it.copyTo(target, 1 shl 16) }
        }

        fun cleanup() {
            closeWriters()
            listOf(semanticFile, functionFile, memoryFile, fieldSliceFile).forEach { f ->
                runCatching { if (f.exists()) f.delete() }
            }
        }
    }

    /** 处理单个 asm 文件，写入分片上下文。与旧 ensureSemanticIndex 单文件逻辑逐行等价。 */
    private fun processAsmFile(file: File, rel: String, chunk: SemanticChunk) {
        val functionOut = chunk.functionsOut()
        val memoryOut = chunk.memoryOut()
        val fieldSliceOut = chunk.fieldSliceOut()
        var currentClass: String? = null
        var pendingSignature: String? = null
        var currentFunctionVa: String? = null
        var pendingPoolAdd: Pair<String, Long>? = null
        val activeFieldSlices = mutableListOf<ActiveFieldSlice>()
        file.useLines { lines ->
            lines.forEachIndexed { lineIndex, raw ->
                val trimmed = raw.trim()
                if (trimmed.startsWith("class ")) currentClass = className(trimmed)
                // B2-1 预筛：函数头恒为 `// ** addr: 0x...` 形态；FUNC_ADDR 带 `.*$` 全串
                // 匹配，是逐行最贵的一条，非该形态的行必然不命中。
                if (trimmed.startsWith("// ** ") && funcAddrM.matches(raw)) {
                    val hm = funcAddrM.m
                    activeFieldSlices.clear()
                    currentFunctionVa = hm.group(1)?.lowercase()
                    val functionSize = hm.group(2)?.lowercase().orEmpty()
                    chunk.writeSemanticRow(SemanticRow().apply {
                        type = SemanticRowFormat.TYPE_FUNCTION
                        functionVa = currentFunctionVa!!.toLong(16)
                        functionVaText = currentFunctionVa
                        sizeText = functionSize
                        function = pendingSignature
                        if (pendingSignature == null) markJsonNull(SemanticRowFormat.FN_FUNCTION)
                        className = currentClass
                        if (currentClass == null) markJsonNull(SemanticRowFormat.FN_CLASS)
                        this.file = rel
                        line = lineIndex + 1
                    })
                    functionOut.writeLong(currentFunctionVa!!.toLong(16))
                    functionOut.writeLong(if (functionSize.startsWith("-")) 0L else functionSize.toLong(16))
                    functionOut.writeUTF(pendingSignature.orEmpty())
                    functionOut.writeUTF(currentClass.orEmpty())
                    functionOut.writeUTF(rel)
                    chunk.functionCount++
                } else if (raw.startsWith("  ") && isFunctionSignature(trimmed)) {
                    pendingSignature = trimmed.trimEnd('{', ' ', ';')
                }
                // 超长行到此为止：函数头/签名判定走锚定正则不受影响，
                // 下方全部 find 系解析跳过（防 ICU 回溯栈撑爆 native 内存）。
                if (raw.length > MAX_PARSE_LINE_CHARS) return@forEachIndexed
                // B2-1 预筛：指令行形态（`[\s]*(//\s*)?0x<hex>:` + 助记符首字母）一次
                // 扫描，供下方指令级正则族复用；数据/字符串行（asm 体积大头）直接落空。
                val mnemonicAt = instructionMnemonicStart(raw)
                val commentedMnemonicAt = instructionMnemonicStart(raw, requireComment = true)
                var explicitReference = false
                if (hasPpAnnotation(raw) && refM.find(raw)) {
                    do {
                        explicitReference = true
                        writeSemanticReference(chunk, refM.m.group(1) ?: "", raw, currentFunctionVa, "asm_annotation")
                        chunk.referenceCount++
                    } while (refM.more())
                }
                if (!explicitReference && hasLdrFromForm(raw) && ldrFromM.find(raw)) {
                    val pending = pendingPoolAdd
                    val lm = ldrFromM.m
                    if (pending != null && lm.group(1).equals(pending.first, true)) {
                        val offset = pending.second + parseImmediate(lm.group(2))
                        writeSemanticReference(chunk, offset.toString(16), raw, currentFunctionVa, "arm64_add_ldr_fallback")
                        chunk.referenceCount++
                    }
                }
                valueEvidence(raw, null)?.let { evidence ->
                    // v5 瘦身：immediate 记录只留 value/functionVa，函数上下文走反查。
                    chunk.writeSemanticRow(SemanticRow().apply {
                        type = SemanticRowFormat.TYPE_IMMEDIATE
                        functionVa = currentFunctionVa?.toLongOrNull(16)
                        functionVaText = currentFunctionVa
                        instructionVaText = evidence.optString("instructionVa")
                        mnemonic = evidence.optString("mnemonic")
                        kind = evidence.optString("kind")
                        value = evidence.optLong("value")
                        text = evidence.optString("text")
                    })
                    chunk.immediateCount++
                }
                currentFunctionVa?.toLongOrNull(16)?.let { functionVa ->
                    chunk.fieldSliceCount += advanceFieldSlices(raw, functionVa, activeFieldSlices, fieldSliceOut)
                }
                // B2-1 预筛：内存助记符 + 索引寻址（`[` 与 `#` 同时出现）才可能命中。
                if (anyMnemonicAt(raw, mnemonicAt, MEMORY_MNEMONICS) &&
                    raw.indexOf('[') >= 0 && raw.indexOf('#') >= 0 && memoryAccessM.find(raw)
                ) {
                    val access = memoryAccessM.m
                    val mnemonic = access.group(2).lowercase()
                    val fieldOffset = parseNumeric(access.group(5))
                    val functionVa2 = currentFunctionVa?.toLongOrNull(16)
                    val baseRegister = registerNumber(access.group(4))
                    val dataRegister = registerNumber(access.group(3))
                    if (fieldOffset != null && functionVa2 != null && baseRegister !in NON_OBJECT_BASE_REGISTERS) {
                        memoryOut.writeLong(access.group(1).toLong(16))
                        memoryOut.writeLong(functionVa2)
                        memoryOut.writeLong(fieldOffset)
                        memoryOut.writeBoolean(mnemonic.startsWith("st"))
                        memoryOut.writeByte(baseRegister)
                        memoryOut.writeByte(dataRegister)
                        chunk.memoryAccessCount += 1
                        if (!mnemonic.startsWith("st") && dataRegister in 0..30 && fieldOffset in 1..0x4000) {
                            activeFieldSlices += ActiveFieldSlice(
                                access.group(1).toLong(16),
                                fieldOffset,
                                dataRegister,
                                mutableSetOf(dataRegister),
                            )
                        }
                    }
                }
                // B2-1 预筛：MEMORY_IMMEDIATE 要求**注释形态**指令行 + 内存助记符。
                if (anyMnemonicAt(raw, commentedMnemonicAt, MEMORY_MNEMONICS) &&
                    raw.indexOf('[') >= 0 && raw.indexOf('#') >= 0 && memoryImmediateM.find(raw)
                ) {
                    val value = parseNumeric(memoryImmediateM.m.group(1))
                    if (value != null) chunk.addressingImmediates[value] = (chunk.addressingImmediates[value] ?: 0) + 1
                }
                // B2-1 预筛：ADD_PP 恒定含 `lsl #12`。
                pendingPoolAdd = if (hasPoolAddForm(raw) && addPpM.find(raw)) {
                    val add = addPpM.m
                    add.group(1) to (parseImmediate(add.group(2)) shl 12)
                } else null
            }
        }
        chunk.scannedFiles++
    }

    internal fun ensureFunctionHeaderIndex(resultDir: File, force: Boolean = false): JSONObject {
        // 与 semantic 构建互斥：两者都会写 $FUNCTION_HEADER_INDEX.tmp 同名临时文件。
        // 这里保持阻塞语义（函数头索引构建快，等 semantic 建完顺带就有了）。
        buildLock.lock()
        try {
        val index = File(resultDir, FUNCTION_HEADER_INDEX)
        if (!force && index.isFile) {
            return JSONObject()
                .put("cacheHit", true)
                .put("functions", functionHeaderCount(resultDir))
                .put("functionIndex", FUNCTION_HEADER_INDEX)
                .put("functionIndexBytes", index.length())
        }
        val asmDir = File(resultDir, "asm")
        require(asmDir.isDirectory) { "ASM_RESULT_NOT_FOUND" }
        val tempIndex = File(resultDir, "$FUNCTION_HEADER_INDEX.tmp")
        var scannedFiles = 0
        var functionCount = 0
        DataOutputStream(BufferedOutputStream(FileOutputStream(tempIndex))).use { out ->
            out.writeInt(FUNCTION_HEADER_INDEX_MAGIC)
            asmDir.walkTopDown().filter { it.isFile && it.extension == "dart" }.forEach { file ->
                val rel = "asm/${file.relativeTo(asmDir).path}"
                var currentClass: String? = null
                var pendingSignature: String? = null
                file.useLines { lines ->
                    lines.forEach { raw ->
                        val trimmed = raw.trim()
                        if (trimmed.startsWith("class ")) currentClass = className(trimmed)
                        // B2-1 预筛：同 processAsmFile（函数头恒为 `// ** addr:` 形态）。
                        if (trimmed.startsWith("// ** ") && funcAddrM.matches(raw)) {
                            val header = funcAddrM.m
                            val rawSize = header.group(2).lowercase()
                            out.writeLong(header.group(1).toLong(16))
                            out.writeLong(if (rawSize.startsWith("-")) 0L else rawSize.toLong(16))
                            out.writeUTF(pendingSignature.orEmpty())
                            out.writeUTF(currentClass.orEmpty())
                            out.writeUTF(rel)
                            functionCount++
                        } else if (raw.startsWith("  ") && isFunctionSignature(trimmed)) {
                            pendingSignature = trimmed.trimEnd('{', ' ', ';')
                        }
                    }
                }
                scannedFiles++
            }
        }
        moveAtomic(tempIndex, index)
        clearSemanticQueryCache(resultDir)
        return JSONObject()
            .put("cacheHit", false)
            .put("scannedFiles", scannedFiles)
            .put("functions", functionCount)
            .put("functionIndex", FUNCTION_HEADER_INDEX)
            .put("functionIndexBytes", index.length())
        } finally {
            buildLock.unlock()
        }
    }

    private fun moveAtomic(source: File, target: File) {
        runCatching { Files.move(source.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING) }
            .getOrElse { Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING) }
    }

    private fun writeSemanticReference(
        chunk: SemanticChunk,
        offset: String,
        raw: String,
        functionVa: String?,
        mode: String,
    ) {
        // B2-1 预筛：本函数的门与其保护的正则必须读**同一个字符串**——
        // INSN_ADDR 在 raw 上求值，LEADING_ADDR_PREFIX 在 rawTrimmed 上求值，
        // 两者各配各的门（Kotlin trim() 的空白集比正则 `\s` 宽，混用会漏判）。
        val instructionVa = if (instructionColonIndex(raw, requireComment = false) >= 0 &&
            insnAddrM.find(raw)
        ) insnAddrM.m.group(1).lowercase() else null
        // v5 瘦身：不再每条重复 function/class/file（索引曾为源 asm 的 2 倍体积）。
        // 反查走 functionHeader 索引（按 functionVa），查询侧 searchSemanticAsm /
        // xref fallback 已同步改为反查填充。地址前缀同剥（offset/va 已单独存）。
        // 前缀剥离走 substring（replaceFirst 每次新建 Matcher，热路径禁用）。
        val rawTrimmed = raw.trim()
        val insn = if (instructionColonIndex(rawTrimmed, requireComment = false) >= 0 &&
            leadingAddrM.find(rawTrimmed)
        ) rawTrimmed.substring(leadingAddrM.m.end()) else rawTrimmed
        chunk.writeSemanticRow(SemanticRow().apply {
            type = SemanticRowFormat.TYPE_REFERENCE
            offsetText = offset.lowercase()
            // 旧语义：instructionVa ?: functionVa ?: JSONObject.NULL（无函数上下文时为 null）
            vaText = instructionVa ?: functionVa
            if (instructionVa == null && functionVa == null) markJsonNull(SemanticRowFormat.REF_VA)
            functionVaText = functionVa
            this.functionVa = functionVa?.toLongOrNull(16)
            this.insn = insn.take(300)
            referenceMode = mode
        })
    }

    private fun clearSemanticQueryCache(resultDir: File) {
        val path = resultDir.absoluteFile.normalize().path
        synchronized(this) {
            functionHeaderCache.keys.removeAll { it.path.startsWith(path) }
            arm64FunctionsCache.keys.removeAll { it.path.startsWith(path) }
            asmSearchCache.keys.removeAll { it.path.startsWith(path) }
        }
    }

    private fun ppCacheKey(resultDir: File, query: String): PpCacheKey {
        val pp = File(resultDir, "pp.txt")
        return PpCacheKey(pp.absoluteFile.normalize().path, pp.lastModified(), pp.length(), query)
    }

    /**
     * pp.txt 行遍历：≤PP_CACHE_MAX_BYTES 的文件读为原始字节驻留缓存跨查询复用；
     * 超过上限走流式逐行回调（内存 O(1)）。回调返回 false 提前终止（等价 break）。
     */
    private fun forEachPpLine(resultDir: File, block: (String) -> Boolean) {
        val pp = File(resultDir, "pp.txt")
        val key = PpLinesCacheKey(pp.absoluteFile.normalize().path, pp.lastModified(), pp.length())
        synchronized(this) {
            ppLinesCache[key]?.let { cached ->
                ByteArrayInputStream(cached).bufferedReader().use { reader ->
                    while (true) {
                        val line = reader.readLine() ?: break
                        if (!block(line)) break
                    }
                }
                return
            }
        }
        if (pp.length() <= PP_CACHE_MAX_BYTES) {
            val bytes = pp.readBytes()
            synchronized(this) {
                ppLinesCache[key] = bytes
                ppScanCount++
            }
            ByteArrayInputStream(bytes).bufferedReader().use { reader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    if (!block(line)) break
                }
            }
        } else {
            synchronized(this) { ppScanCount++ }
            pp.bufferedReader().use { reader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    if (!block(line)) break
                }
            }
        }
    }

    /**
     * 流式遍历语义索引：逐行解析逐行回调，不把百万行索引驻留堆内。
     *
     * B3-1 起统一走 [SemanticRowReader]：v6 二进制与旧 JSONL 两种来源产出同一个
     * [SemanticRow]，消费点不再各自 `JSONObject(raw)`。
     */
    private inline fun forEachSemanticRow(resultDir: File, block: (SemanticRow) -> Unit): JSONObject {
        val meta = ensureSemanticIndex(resultDir)
        val index = semanticIndexFile(resultDir)
        SemanticRowReader.open(index).use { rows ->
            while (true) {
                val row = rows.next() ?: break
                block(row)
            }
        }
        return meta
    }

    /** 函数头列表（几千条、极小）允许驻留缓存；disasmFunction 高频调用不再全量扫索引。 */
    private fun functionHeaders(resultDir: File): List<FunctionHeader> {
        val compactIndex = File(resultDir, FUNCTION_HEADER_INDEX)
        if (!compactIndex.isFile && File(resultDir, "asm").isDirectory) ensureFunctionHeaderIndex(resultDir)
        if (compactIndex.isFile) {
            val key = FunctionHeaderCacheKey(compactIndex.absoluteFile.normalize().path, compactIndex.lastModified(), compactIndex.length())
            synchronized(this) { functionHeaderCache[key]?.let { return it } }
            val headers = readFunctionHeaders(compactIndex)
            synchronized(this) { functionHeaderCache[key] = headers }
            return headers
        }
        val index = semanticIndexFile(resultDir)
        val key = FunctionHeaderCacheKey(index.absoluteFile.normalize().path, index.lastModified(), index.length())
        synchronized(this) {
            functionHeaderCache[key]?.let { return it }
        }
        val headers = mutableListOf<FunctionHeader>()
        forEachSemanticRow(resultDir) { row ->
            if (row.type != SemanticRowFormat.TYPE_FUNCTION) return@forEachSemanticRow
            val rawSize = row.optString("size").trim()
            val size = if (rawSize.startsWith("-")) 0L else rawSize.removePrefix("0x").removePrefix("0X").toLongOrNull(16) ?: 0L
            headers += FunctionHeader(
                row.optString("va").toLongOrNull(16) ?: 0L,
                size,
                row.optString("function").takeIf(String::isNotBlank),
                row.optString("class").takeIf(String::isNotBlank),
                row.optString("file"),
            )
        }
        synchronized(this) {
            functionHeaderCache[key] = headers
        }
        return headers
    }

    private fun readFunctionHeaders(index: File): List<FunctionHeader> {
        val headers = mutableListOf<FunctionHeader>()
        DataInputStream(BufferedInputStream(index.inputStream())).use { input ->
            if (input.readInt() != FUNCTION_HEADER_INDEX_MAGIC) return emptyList()
            while (true) {
                try {
                    headers += FunctionHeader(
                        input.readLong(),
                        input.readLong(),
                        input.readUTF().takeIf(String::isNotBlank),
                        input.readUTF().takeIf(String::isNotBlank),
                        input.readUTF(),
                    )
                } catch (_: EOFException) {
                    break
                }
            }
        }
        return headers
    }

    private data class MemoryAccess(
        val instructionVa: Long,
        val functionVa: Long,
        val offset: Long,
        val write: Boolean,
        val baseRegister: Int,
        val dataRegister: Int,
    )

    private data class FieldSliceSink(
        val sourceVa: Long,
        val functionVa: Long,
        val fieldOffset: Long,
        val sinkVa: Long,
        val kind: Int,
        val sourceRegister: Int,
        val value: Long,
    )

    private inline fun forEachMemoryAccess(resultDir: File, block: (MemoryAccess) -> Unit) {
        ensureSemanticIndex(resultDir)
        val index = File(resultDir, MEMORY_ACCESS_INDEX)
        if (!index.isFile) return
        DataInputStream(BufferedInputStream(index.inputStream())).use { input ->
            if (input.readInt() != MEMORY_ACCESS_INDEX_MAGIC) return
            while (true) {
                try {
                    block(MemoryAccess(
                        input.readLong(),
                        input.readLong(),
                        input.readLong(),
                        input.readBoolean(),
                        input.readUnsignedByte(),
                        input.readUnsignedByte(),
                    ))
                } catch (_: EOFException) {
                    break
                }
            }
        }
    }

    private inline fun forEachFieldSlice(resultDir: File, block: (FieldSliceSink) -> Unit) {
        ensureSemanticIndex(resultDir)
        val index = File(resultDir, FIELD_SLICE_INDEX)
        if (!index.isFile) return
        DataInputStream(BufferedInputStream(index.inputStream())).use { input ->
            if (input.readInt() != FIELD_SLICE_INDEX_MAGIC) return
            while (true) {
                try {
                    block(FieldSliceSink(
                        input.readLong(),
                        input.readLong(),
                        input.readLong(),
                        input.readLong(),
                        input.readUnsignedByte(),
                        input.readUnsignedByte(),
                        input.readLong(),
                    ))
                } catch (_: EOFException) {
                    break
                }
            }
        }
    }

    private fun advanceFieldSlices(
        raw: String,
        functionVa: Long,
        active: MutableList<ActiveFieldSlice>,
        out: DataOutputStream,
    ): Int {
        // B2-1 预筛：非指令行（数据/字符串行，asm 体积大头）不必跑 ARM64_INSTRUCTION。
        if (instructionMnemonicStart(raw) < 0) return 0
        if (!arm64InsnM.matches(raw)) return 0
        val instruction = arm64InsnM.m
        val sinkVa = instruction.group(1)?.toLongOrNull(16) ?: return 0
        val mnemonic = instruction.group(2).lowercase()
        val operands = instruction.group(3)
        val registers = mutableSetOf<Int>()
        if (arm64RegM.find(operands)) {
            do { registers.add(arm64RegM.m.group(1).toInt()) } while (arm64RegM.more())
        }
        val firstOperand = operands.substringBefore(',').trim()
        val destination = registerNumber(firstOperand).takeIf { it in 0..30 }
        val sourceRegisters = mutableSetOf<Int>()
        val operandRest = operands.substringAfter(',', "")
        if (arm64RegM.find(operandRest)) {
            do { sourceRegisters.add(arm64RegM.m.group(1).toInt()) } while (arm64RegM.more())
        }
        val immediate = if (arm64ImmM.find(operands)) parseNumeric(arm64ImmM.m.group(1)) else null
        var emitted = 0
        val iterator = active.iterator()
        while (iterator.hasNext()) {
            val slice = iterator.next()
            slice.remaining -= 1
            if (slice.remaining < 0 || slice.registers.isEmpty()) {
                iterator.remove()
                continue
            }
            var terminate = false
            val taintedOperand = registers.any(slice.registers::contains)
            when {
                mnemonic in setOf("cmp", "cmn", "tst") -> {
                    slice.flagsTainted = taintedOperand
                    if (taintedOperand) {
                        writeFieldSlice(out, slice, functionVa, sinkVa, SLICE_COMPARISON, immediate)
                        emitted++
                    }
                }
                mnemonic in setOf("cbz", "cbnz", "tbz", "tbnz") -> {
                    if (registerNumber(firstOperand) in slice.registers) {
                        writeFieldSlice(out, slice, functionVa, sinkVa, SLICE_DIRECT_BRANCH, immediate)
                        emitted++
                        terminate = true
                    }
                }
                mnemonic.startsWith("b.") -> {
                    if (slice.flagsTainted) {
                        writeFieldSlice(out, slice, functionVa, sinkVa, SLICE_FLAGS_BRANCH, null)
                        emitted++
                        terminate = true
                    }
                }
                mnemonic == "ret" -> {
                    if (0 in slice.registers) {
                        writeFieldSlice(out, slice, functionVa, sinkVa, SLICE_RETURN, null)
                        emitted++
                    }
                    terminate = true
                }
                mnemonic == "b" || mnemonic == "br" -> terminate = true
                mnemonic == "bl" || mnemonic == "blr" -> {
                    if (slice.registers.any { it in 0..7 }) {
                        writeFieldSlice(out, slice, functionVa, sinkVa, SLICE_CALL_ARGUMENT, null)
                        emitted++
                    }
                    slice.registers.removeAll(0..18)
                }
                destination != null && instructionWritesDestination(mnemonic) -> {
                    val flagsDerived = slice.flagsTainted && (mnemonic == "cset" || mnemonic.startsWith("cs"))
                    val registerDerived = sourceRegisters.any(slice.registers::contains)
                    slice.registers.remove(destination)
                    if (flagsDerived || registerDerived) slice.registers.add(destination)
                    if (flagsDerived) {
                        writeFieldSlice(out, slice, functionVa, sinkVa, SLICE_BOOLEAN_RESULT, null)
                        emitted++
                    }
                    if (mnemonic in setOf("adds", "subs", "ands")) {
                        slice.flagsTainted = registerDerived
                    }
                }
            }
            if (terminate || slice.registers.isEmpty()) iterator.remove()
        }
        return emitted
    }

    private fun instructionWritesDestination(mnemonic: String): Boolean =
        !mnemonic.startsWith("st") && mnemonic !in setOf(
            "cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz",
            "b", "br", "bl", "blr", "ret", "nop", "prfm",
        ) && !mnemonic.startsWith("b.")

    private fun writeFieldSlice(
        out: DataOutputStream,
        slice: ActiveFieldSlice,
        functionVa: Long,
        sinkVa: Long,
        kind: Int,
        value: Long?,
    ) {
        out.writeLong(slice.sourceVa)
        out.writeLong(functionVa)
        out.writeLong(slice.fieldOffset)
        out.writeLong(sinkVa)
        out.writeByte(kind)
        out.writeByte(slice.sourceRegister)
        out.writeLong(value ?: NO_SLICE_VALUE)
    }

    private fun fieldSliceKind(kind: Int): String = when (kind) {
        SLICE_COMPARISON -> "comparison"
        SLICE_DIRECT_BRANCH -> "direct_conditional_branch"
        SLICE_FLAGS_BRANCH -> "flags_conditional_branch"
        SLICE_BOOLEAN_RESULT -> "boolean_result"
        SLICE_RETURN -> "return"
        SLICE_CALL_ARGUMENT -> "call_argument"
        else -> "unknown"
    }

    /**
     * 语义索引文件（读取端）：v6 二进制优先；缺失时回退 v5 gz JSONL、v1 明文 JSONL。
     * 格式识别由 [SemanticRowReader] 按内容完成，不依赖文件名。
     *
     * 注意 v5 分支的生产可达性（2026-09-19 独立复核确认）：**基本不可达**。v5-only 目录在
     * [ensureSemanticIndex] 里因 meta version != 6 必然触发重建，查询侧走不到这里；它保留的
     * 意义是（a）回滚能力——旧代码产物/手工放置的 v5 索引仍能被本读端解析，（b）格式迁移期
     * 若 v6 缺失而 v5 仍在（如重建中断在 moveAtomic 之前）时读取端不会踩空。v1 分支（
     * LEGACY_SEMANTIC_INDEX）同理，靠 legacy meta version==1 走快路径，是活路径。
     */
    private fun semanticIndexFile(resultDir: File): File {
        val current = File(resultDir, SEMANTIC_INDEX)
        if (current.isFile) return current
        val v5 = File(resultDir, V5_SEMANTIC_INDEX)
        if (v5.isFile) return v5
        return File(resultDir, LEGACY_SEMANTIC_INDEX)
    }

    private inline fun forEachFunctionHeaderRow(
        resultDir: File,
        block: (addr: Long, size: Long, name: String?, className: String?, file: String) -> Unit,
    ) {
        functionHeaders(resultDir).forEach { block(it.va, it.size, it.name, it.className, it.file) }
    }

    internal fun isFunctionSignature(line: String): Boolean {
        if (line.startsWith("//") || line.startsWith("class ")) return false
        val open = line.indexOf('(')
        return open > 0 && line.indexOf(')', open) > open && (line.endsWith("{") || line.endsWith(";"))
    }

    /**
     * libapp.so 原始 UTF-8 串扫描（Blutter asm 未写 pp 注释时的兜底）。
     *
     * 噪声口径（2026-09-19 真机 QA D6）：大块词表数据（Mathematica 符号表、Steam
     * WebAPI 名称表、Arma 脚本命令表、SQLSTATE 列表）里一个长串就能撞中
     * member/subscription/privilege 等多个词条，数量上直接淹没真实 Dart 符号。
     * 复用语义索引侧的「词堆」判据（[KEYWORD_PILE_TERMS] / [NOISY_LONG_STRING_CHARS]）
     * 给命中行打 `noisy` 标记：默认把词堆行沉到结果末尾并计数自报，只有
     * `includeNoisy=true` 才把它们与正常命中一起按偏移输出——不静默丢弃，
     * 但也不再让它们占据 limit 名额。
     */
    fun rawStringSearch(
        bytes: ByteArray,
        queries: List<String>,
        limit: Int,
        includeNoisy: Boolean = false,
    ): JSONObject {
        val started = System.nanoTime()
        val needles = queries.map(String::trim).filter(String::isNotEmpty).distinctBy(String::lowercase)
        val matches = JSONArray()
        val noisyMatches = JSONArray()
        var start = -1
        fun inspect(end: Int) {
            if (start < 0 || end - start < 3) return
            if (matches.length() + noisyMatches.length() >= limit) return
            val text = runCatching { String(bytes, start, end - start, Charsets.UTF_8) }.getOrNull()?.trim().orEmpty()
            if (text.isEmpty() || text.contains('\uFFFD')) return
            val matched = needles.filter { containsTerm(text, it) }
            if (matched.isEmpty()) return
            val noisy = isKeywordPile(text, matched.size) || looksLikeWordList(text)
            val row = JSONObject()
                .put("fileOffset", "0x${start.toString(16)}")
                .put("text", text.take(300))
                .put("matchedTerms", JSONArray(matched))
                .apply { if (noisy) put("noisy", true) }
            if (noisy) noisyMatches.put(row) else matches.put(row)
        }
        for (index in bytes.indices) {
            val value = bytes[index].toInt() and 0xff
            val printable = value in 0x20..0x7e || value >= 0x80
            if (printable) {
                if (start < 0) start = index
                if (index - start >= 1024) {
                    inspect(index)
                    start = index
                }
            } else if (start >= 0) {
                inspect(index)
                start = -1
                if (matches.length() + noisyMatches.length() >= limit) break
            }
        }
        if (matches.length() + noisyMatches.length() < limit) inspect(bytes.size)
        // 正常命中在前、词堆行在后：limit 名额先给信号，噪声只计数不静默丢弃。
        val out = JSONArray()
        for (i in 0 until matches.length()) out.put(matches.get(i))
        if (includeNoisy) {
            for (i in 0 until noisyMatches.length()) out.put(noisyMatches.get(i))
        }
        return JSONObject()
            .put("queries", JSONArray(needles))
            .put("matches", out)
            .put("count", out.length())
            .put("noisyCount", noisyMatches.length())
            .put("includeNoisy", includeNoisy)
            .apply {
                if (!includeNoisy && noisyMatches.length() > 0) {
                    put(
                        "noisyNote",
                        "另有 ${noisyMatches.length()} 条命中是大块词表/符号表数据（单词表串撞中多个词条），" +
                            "默认沉底不输出；需要时用 includeNoisy=true 取回。",
                    )
                }
            }
            .put("scannedBytes", bytes.size)
            .put("elapsedMs", (System.nanoTime() - started) / 1_000_000)
            .put("source", "libapp.so raw UTF-8 strings")
    }

    /**
     * 直接扫描 libapp.so，覆盖 Blutter asm 未写 pp 注释时的 ARM64 取池引用。
     * 指令模式对齐 PPTool（github.com/Kirlif/PPTool, Apache-2.0）Instruct64 的三条路径：
     *  ① 单指令 ldr xN, [x27, #imm*scale] —— 池前 32KB 直接寻址，无需 add 指令对
     *  ② add xN, x27, #hi[, lsl #12] + 1..6 条内 ldr [xN, #imm*scale]（6 种 load 宽度）
     *  ③ 双 add 拆分：add xN, x27, #hi + add xM, xN, #lo + ldr [xM]（低位非 8 对齐时）
     * 目标寄存器走 PPTool 白名单（x15/x18/x21/x22/x26/x28/x29 为 Dart/平台保留，不作出址目标）。
     */
    fun buildArm64PoolIndex(libapp: ByteArray, resultDir: File) {
        val executableRanges = arm64ExecutableRanges(libapp)
        DataOutputStream(BufferedOutputStream(File(resultDir, ARM64_POOL_INDEX_V2).outputStream())).use { out ->
            DataOutputStream(BufferedOutputStream(File(resultDir, ARM64_CLOSURE_CALL_INDEX).outputStream())).use { calls ->
            out.writeInt(ARM64_POOL_INDEX_MAGIC)
            calls.writeInt(ARM64_CLOSURE_CALL_INDEX_MAGIC)
            executableRanges.forEach { range ->
                var offset = range.fileOffset
                while (offset + 28 <= range.fileEnd) {
                    val word = arm64Word(libapp, offset)
                    val va = range.virtualAddress + offset - range.fileOffset
                    // ① 单指令 ldr xN, [x27, #imm]：基址就是 PP(x27)
                    ldrPoolScale(word, 27)?.let { scale ->
                        val rd = word and 31
                        if (validPoolTarget(rd)) {
                            val poolOffset = ((word ushr 10) and 0xfff).toLong() * scale
                            writeRawPoolReference(out, poolOffset, va, offset, 1)
                        }
                    }
                    // ①-LDP：ldp xRt, xRt2, [x27, #imm*8]（PPTool 未覆盖，Dart AOT
                    // 闭包+代码对的成对池加载——xref 对闭包槽 0x21ad0/0x21ad8 落空的根因）。
                    ldpPoolPair(word, 27)?.let { (rt, rt2, scale) ->
                        // LDP 的 imm7 在 bit21:15（不是 LDR 的 imm12 位置）
                        val poolBase = ldpPoolOffset(word, scale)
                        if (validPoolTarget(rt)) {
                            writeRawPoolReference(out, poolBase, va, offset, 4)
                        }
                        if (validPoolTarget(rt2)) {
                            writeRawPoolReference(out, poolBase + 8, va, offset, 4)
                        }
                        findBlrAfter(libapp, offset, rt, rt2)?.let { (callOffset, targetRegister) ->
                            val callVa = va + callOffset - offset
                            writeRawClosureCall(calls, poolBase, va, callVa, offset, callOffset, targetRegister, 4)
                            writeRawClosureCall(calls, poolBase + 8, va, callVa, offset, callOffset, targetRegister, 4)
                        }
                    }
                    // ②/③ add xN, x27, #hi[, lsl #12] 路径（PPTool 仅匹配 64 位 sf=1 编码）
                    val baseRegister = (word ushr 5) and 31
                    if ((word and 0xff000000.toInt()) == 0x91000000.toInt() && baseRegister == 27 && validPoolTarget(word and 31)) {
                        val targetRegister = word and 31
                        val high = ((word ushr 10) and 0xfff).toLong() shl if ((word and 0x00400000) != 0) 12 else 0
                        var secondAddLow = -1L
                        var secondAddReg = -1
                        for (step in 1..6) {
                            val next = arm64Word(libapp, offset + step * 4)
                            ldpPoolPair(next, targetRegister)?.takeIf { secondAddLow < 0 }?.let { (rt, rt2, scale) ->
                                val loadOffset = offset + step * 4
                                val loadVa = va + step * 4
                                val poolBase = high + ldpPoolOffset(next, scale)
                                if (validPoolTarget(rt)) writeRawPoolReference(out, poolBase, loadVa, loadOffset, 5)
                                if (validPoolTarget(rt2)) writeRawPoolReference(out, poolBase + 8, loadVa, loadOffset, 5)
                                findBlrAfter(libapp, loadOffset, rt, rt2)?.let { (callOffset, targetRegister) ->
                                    val callVa = va + callOffset - offset
                                    writeRawClosureCall(calls, poolBase, loadVa, callVa, loadOffset, callOffset, targetRegister, 5)
                                    writeRawClosureCall(calls, poolBase + 8, loadVa, callVa, loadOffset, callOffset, targetRegister, 5)
                                }
                                return@let
                            }
                            if (secondAddLow < 0 && ldpPoolPair(next, targetRegister) != null) break
                            // ② 紧随的 ldr [targetRegister, #imm*scale]
                            val directScale = ldrPoolScale(next, targetRegister)
                            if (directScale != null) {
                                val poolOffset = high + (((next ushr 10) and 0xfff).toLong() * directScale)
                                writeRawPoolReference(out, poolOffset, va, offset, 2)
                                break
                            }
                            // ③ 双 add 拆分：add xM, xN, #lo（64 位无 shift）记忆，等后续 ldr [xM]
                            if (secondAddLow < 0 && (next and 0xff000000.toInt()) == 0x91000000.toInt() &&
                                ((next ushr 5) and 31) == targetRegister && (next and 0x00400000) == 0) {
                                secondAddLow = ((next ushr 10) and 0xfff).toLong()
                                secondAddReg = next and 31
                                continue
                            }
                            if (secondAddLow >= 0) {
                                ldpPoolPair(next, secondAddReg)?.let { (rt, rt2, scale) ->
                                    val loadOffset = offset + step * 4
                                    val loadVa = va + step * 4
                                    val poolBase = high + secondAddLow + ldpPoolOffset(next, scale)
                                    if (validPoolTarget(rt)) writeRawPoolReference(out, poolBase, loadVa, loadOffset, 5)
                                    if (validPoolTarget(rt2)) writeRawPoolReference(out, poolBase + 8, loadVa, loadOffset, 5)
                                    findBlrAfter(libapp, loadOffset, rt, rt2)?.let { (callOffset, targetRegister) ->
                                        val callVa = va + callOffset - offset
                                        writeRawClosureCall(calls, poolBase, loadVa, callVa, loadOffset, callOffset, targetRegister, 5)
                                        writeRawClosureCall(calls, poolBase + 8, loadVa, callVa, loadOffset, callOffset, targetRegister, 5)
                                    }
                                    return@let
                                }
                                if (ldpPoolPair(next, secondAddReg) != null) break
                                val followScale = ldrPoolScale(next, secondAddReg)
                                if (followScale != null) {
                                    val poolOffset = high + secondAddLow + (((next ushr 10) and 0xfff).toLong() * followScale)
                                    writeRawPoolReference(out, poolOffset, va, offset, 3)
                                    break
                                }
                            }
                        }
                    }
                    offset += 4
                }
            }
            }
        }
        File(resultDir, ARM64_POOL_INDEX).delete()
        File(resultDir, ARM64_FUNCTION_INDEX).bufferedWriter().use { out ->
            executableRanges.forEach { range ->
                var offset = range.fileOffset
                while (offset + 4 <= range.fileEnd) {
                    if (isArm64FramePrologue(arm64Word(libapp, offset))) {
                        val va = range.virtualAddress + offset - range.fileOffset
                        out.write(JSONObject().put("va", va.toString(16)).put("mode", "arm64_frame_prologue").toString())
                        out.newLine()
                    }
                    offset += 4
                }
            }
        }
    }

    /** 大型 libapp.so 的分块扫描版本，避免为整份库分配连续大数组。 */
    fun buildArm64PoolIndex(libapp: File, resultDir: File) {
        val ranges = arm64ExecutableRanges(libapp)
        val chunkSize = 1024 * 1024
        RandomAccessFile(libapp, "r").use { input ->
            DataOutputStream(BufferedOutputStream(File(resultDir, ARM64_POOL_INDEX_V2).outputStream())).use { out ->
                DataOutputStream(BufferedOutputStream(File(resultDir, ARM64_CLOSURE_CALL_INDEX).outputStream())).use { calls ->
                out.writeInt(ARM64_POOL_INDEX_MAGIC)
                calls.writeInt(ARM64_CLOSURE_CALL_INDEX_MAGIC)
                    ranges.forEach { range ->
                        var chunkStart = range.fileOffset
                        while (chunkStart < range.fileEnd) {
                            val scanEnd = minOf(chunkStart + chunkSize, range.fileEnd)
                            val readEnd = minOf(scanEnd + 64, range.fileEnd)
                            val bytes = ByteArray(readEnd - chunkStart)
                            input.seek(chunkStart.toLong())
                            input.readFully(bytes)
                            var offset = 0
                            val scanBytes = scanEnd - chunkStart
                            while (offset + 4 <= scanBytes && offset + 28 <= bytes.size) {
                                val word = arm64Word(bytes, offset)
                                val fileOffset = chunkStart + offset
                                val va = range.virtualAddress + fileOffset - range.fileOffset
                                ldrPoolScale(word, 27)?.let { scale ->
                                    val rd = word and 31
                                    if (validPoolTarget(rd)) writeRawPoolReference(out, ((word ushr 10) and 0xfff).toLong() * scale, va, fileOffset, 1)
                                }
                                ldpPoolPair(word, 27)?.let { (rt, rt2, scale) ->
                                    val poolBase = ldpPoolOffset(word, scale)
                                    if (validPoolTarget(rt)) writeRawPoolReference(out, poolBase, va, fileOffset, 4)
                                    if (validPoolTarget(rt2)) writeRawPoolReference(out, poolBase + 8, va, fileOffset, 4)
                                    findBlrAfter(bytes, offset, rt, rt2)?.let { (callOffset, targetRegister) ->
                                        val absoluteCallOffset = fileOffset + callOffset - offset
                                        val callVa = va + callOffset - offset
                                        writeRawClosureCall(calls, poolBase, va, callVa, fileOffset, absoluteCallOffset, targetRegister, 4)
                                        writeRawClosureCall(calls, poolBase + 8, va, callVa, fileOffset, absoluteCallOffset, targetRegister, 4)
                                    }
                                }
                                val baseRegister = (word ushr 5) and 31
                                if ((word and 0xff000000.toInt()) == 0x91000000.toInt() && baseRegister == 27 && validPoolTarget(word and 31)) {
                                    val targetRegister = word and 31
                                    val high = ((word ushr 10) and 0xfff).toLong() shl if ((word and 0x00400000) != 0) 12 else 0
                                    var secondAddLow = -1L
                                    var secondAddReg = -1
                                    for (step in 1..6) {
                                        val next = arm64Word(bytes, offset + step * 4)
                                        ldpPoolPair(next, targetRegister)?.takeIf { secondAddLow < 0 }?.let { (rt, rt2, scale) ->
                                            val loadOffset = offset + step * 4
                                            val loadFileOffset = fileOffset + step * 4
                                            val loadVa = va + step * 4
                                            val poolBase = high + ldpPoolOffset(next, scale)
                                            if (validPoolTarget(rt)) writeRawPoolReference(out, poolBase, loadVa, loadFileOffset, 5)
                                            if (validPoolTarget(rt2)) writeRawPoolReference(out, poolBase + 8, loadVa, loadFileOffset, 5)
                                            findBlrAfter(bytes, loadOffset, rt, rt2)?.let { (callOffset, targetRegister) ->
                                                val absoluteCallOffset = fileOffset + callOffset - offset
                                                val callVa = va + callOffset - offset
                                                writeRawClosureCall(calls, poolBase, loadVa, callVa, loadFileOffset, absoluteCallOffset, targetRegister, 5)
                                                writeRawClosureCall(calls, poolBase + 8, loadVa, callVa, loadFileOffset, absoluteCallOffset, targetRegister, 5)
                                            }
                                            return@let
                                        }
                                        if (secondAddLow < 0 && ldpPoolPair(next, targetRegister) != null) break
                                        val directScale = ldrPoolScale(next, targetRegister)
                                        if (directScale != null) {
                                            writeRawPoolReference(out, high + (((next ushr 10) and 0xfff).toLong() * directScale), va, fileOffset, 2)
                                            break
                                        }
                                        if (secondAddLow < 0 && (next and 0xff000000.toInt()) == 0x91000000.toInt() && ((next ushr 5) and 31) == targetRegister && (next and 0x00400000) == 0) {
                                            secondAddLow = ((next ushr 10) and 0xfff).toLong()
                                            secondAddReg = next and 31
                                            continue
                                        }
                                        if (secondAddLow >= 0) {
                                            ldpPoolPair(next, secondAddReg)?.let { (rt, rt2, scale) ->
                                                val loadOffset = offset + step * 4
                                                val loadFileOffset = fileOffset + step * 4
                                                val loadVa = va + step * 4
                                                val poolBase = high + secondAddLow + ldpPoolOffset(next, scale)
                                                if (validPoolTarget(rt)) writeRawPoolReference(out, poolBase, loadVa, loadFileOffset, 5)
                                                if (validPoolTarget(rt2)) writeRawPoolReference(out, poolBase + 8, loadVa, loadFileOffset, 5)
                                                findBlrAfter(bytes, loadOffset, rt, rt2)?.let { (callOffset, targetRegister) ->
                                                    val absoluteCallOffset = fileOffset + callOffset - offset
                                                    val callVa = va + callOffset - offset
                                                    writeRawClosureCall(calls, poolBase, loadVa, callVa, loadFileOffset, absoluteCallOffset, targetRegister, 5)
                                                    writeRawClosureCall(calls, poolBase + 8, loadVa, callVa, loadFileOffset, absoluteCallOffset, targetRegister, 5)
                                                }
                                                return@let
                                            }
                                            if (ldpPoolPair(next, secondAddReg) != null) break
                                            val followScale = ldrPoolScale(next, secondAddReg)
                                            if (followScale != null) {
                                                writeRawPoolReference(out, high + secondAddLow + (((next ushr 10) and 0xfff).toLong() * followScale), va, fileOffset, 3)
                                                break
                                            }
                                        }
                                    }
                                }
                                offset += 4
                            }
                            chunkStart = scanEnd
                        }
                }
                }
            }
        }
        File(resultDir, ARM64_POOL_INDEX).delete()
        File(resultDir, ARM64_FUNCTION_INDEX).bufferedWriter().use { functions ->
            RandomAccessFile(libapp, "r").use { input ->
                val bytes = ByteArray(chunkSize)
                ranges.forEach { range ->
                    var chunkStart = range.fileOffset
                    while (chunkStart < range.fileEnd) {
                        val count = minOf(bytes.size, range.fileEnd - chunkStart)
                        input.seek(chunkStart.toLong())
                        input.readFully(bytes, 0, count)
                        var offset = 0
                        while (offset + 4 <= count) {
                            if (isArm64FramePrologue(arm64Word(bytes, offset))) {
                                val va = range.virtualAddress + chunkStart + offset - range.fileOffset
                                functions.write(JSONObject().put("va", va.toString(16)).put("mode", "arm64_frame_prologue").toString())
                                functions.newLine()
                            }
                            offset += 4
                        }
                        chunkStart += count
                    }
                }
            }
        }
    }

    /** LDP (immediate signed offset, 64-bit)：ldp xRt, xRt2, [base, #imm*8]。返回 (Rt, Rt2, scale=8) 或 null。 */
    private fun ldpPoolPair(word: Int, base: Int): Triple<Int, Int, Long>? {
        // 64-bit LDP 立即数偏移家族：基掩码 0x7FC00000 取 (opc=10, 101 0010, L=1)
        // → 0x29400000；屏蔽符号位 bit31（0x7F 高字节=0x29 来自 0xA9 & 0x7F）。
        if ((word and 0x7fc00000.toInt()) != 0x29400000.toInt()) return null
        if (((word ushr 5) and 31) != base) return null
        val loadStore = (word ushr 22) and 1 // L=1 为加载（已含在 0x29 高位）
        if (loadStore != 1) return null
        val rt = word and 31
        val rt2 = (word ushr 10) and 31
        return Triple(rt, rt2, 8L)
    }

    private fun ldpPoolOffset(word: Int, scale: Long): Long {
        val imm7 = (word ushr 15) and 0x7f
        return (if (imm7 and 0x40 != 0) imm7 - 0x80 else imm7).toLong() * scale
    }

    /** LDR (immediate, unsigned offset) 家族：按基址寄存器过滤，返回寻址 scale（字节宽度），非本家族返回 null。PPTool 全宽度对齐。 */
    private fun ldrPoolScale(word: Int, base: Int): Long? {
        if (((word ushr 5) and 31) != base) return null
        return when (word and 0xffc00000.toInt()) {
            0xf9400000.toInt() -> 8L  // ldr x
            0xfd400000.toInt() -> 8L  // ldr d
            0xb9400000.toInt() -> 4L  // ldr w
            0xbd400000.toInt() -> 4L  // ldr s
            0x79400000.toInt() -> 2L  // ldrh
            0x39400000.toInt() -> 1L  // ldrb
            0x3dc00000 -> 16L         // ldr q（128 位）
            else -> null
        }
    }

    /** PPTool 同款出址目标白名单：x0-x14, x16,x17,x19,x20,x23,x24,x25,x30。 */
    private fun validPoolTarget(reg: Int): Boolean =
        reg in 0..14 || reg == 16 || reg == 17 || reg == 19 || reg == 20 || reg == 23 || reg == 24 || reg == 25 || reg == 30

    private fun findBlrAfter(bytes: ByteArray, ldpOffset: Int, firstRegister: Int, secondRegister: Int): Pair<Int, Int>? {
        for (step in 1..16) {
            val offset = ldpOffset + step * 4
            if (offset + 4 > bytes.size) break
            val register = blrRegister(arm64Word(bytes, offset)) ?: continue
            if (register == firstRegister || register == secondRegister) return offset to register
        }
        return null
    }

    private fun blrRegister(word: Int): Int? =
        if ((word and 0xfffffc1f.toInt()) == 0xd63f0000.toInt()) (word ushr 5) and 31 else null

    private fun writeRawPoolReference(
        out: DataOutputStream,
        poolOffset: Long,
        va: Long,
        fileOffset: Int,
        mode: Int,
    ) {
        out.writeLong(poolOffset)
        out.writeLong(va)
        out.writeInt(fileOffset)
        out.writeByte(mode)
    }

    private fun writeRawClosureCall(
        out: DataOutputStream,
        poolOffset: Long,
        loadVa: Long,
        callVa: Long,
        loadFileOffset: Int,
        callFileOffset: Int,
        targetRegister: Int,
        mode: Int,
    ) {
        out.writeLong(poolOffset)
        out.writeLong(loadVa)
        out.writeLong(callVa)
        out.writeInt(loadFileOffset)
        out.writeInt(callFileOffset)
        out.writeByte(targetRegister)
        out.writeByte(mode)
    }

    private data class RawPoolReference(
        val poolOffset: Long,
        val va: Long,
        val fileOffset: Int,
        val mode: String,
    )

    private data class RawClosureCall(
        val poolOffset: Long,
        val loadVa: Long,
        val callVa: Long,
        val loadFileOffset: Int,
        val callFileOffset: Int,
        val targetRegister: Int,
        val mode: Int,
    )

    private fun forEachRawClosureCall(resultDir: File, block: (RawClosureCall) -> Unit) {
        val binary = File(resultDir, ARM64_CLOSURE_CALL_INDEX)
        if (!binary.isFile) return
        DataInputStream(BufferedInputStream(binary.inputStream())).use { input ->
            if (input.readInt() != ARM64_CLOSURE_CALL_INDEX_MAGIC) return
            while (true) {
                val row = try {
                    RawClosureCall(
                        input.readLong(), input.readLong(), input.readLong(),
                        input.readInt(), input.readInt(), input.readUnsignedByte(), input.readUnsignedByte(),
                    )
                } catch (_: EOFException) {
                    break
                }
                block(row)
            }
        }
    }

    private fun forEachRawPoolReference(resultDir: File, block: (RawPoolReference) -> Unit) {
        val binary = File(resultDir, ARM64_POOL_INDEX_V2)
        if (binary.isFile) {
            DataInputStream(BufferedInputStream(binary.inputStream())).use { input ->
                if (input.readInt() != ARM64_POOL_INDEX_MAGIC) return
                while (true) {
                    val row = try {
                        RawPoolReference(
                            input.readLong(),
                            input.readLong(),
                            input.readInt(),
                            when (input.readUnsignedByte()) {
                                1 -> "arm64_raw_ldr_pp"
                                2 -> "arm64_raw_add_ldr"
                                3 -> "arm64_raw_add_add_ldr"
                                4 -> "arm64_raw_ldp_pp"
                                5 -> "arm64_raw_add_ldp_pp"
                                else -> "arm64_raw_unknown"
                            },
                        )
                    } catch (_: EOFException) {
                        break
                    }
                    block(row)
                }
            }
            return
        }
        val legacy = File(resultDir, ARM64_POOL_INDEX)
        if (!legacy.isFile) return
        legacy.forEachLine { line ->
            val row = runCatching { JSONObject(line) }.getOrNull() ?: return@forEachLine
            val poolOffset = row.optString("offset").toLongOrNull(16) ?: return@forEachLine
            val va = row.optString("va").toLongOrNull(16) ?: return@forEachLine
            val fileOffset = row.optString("fileOffset").toIntOrNull(16) ?: return@forEachLine
            block(RawPoolReference(poolOffset, va, fileOffset, row.optString("mode")))
        }
    }

    fun searchPp(resultDir: File, query: String, caseInsensitive: Boolean, limit: Int): JSONObject {
        val queries = searchQueries(query, caseInsensitive)
        val cacheKey = ppCacheKey(resultDir, "search:${queries.joinToString("|")}:$caseInsensitive:$limit")
        synchronized(this) { ppSearchCache[cacheKey]?.let { return JSONObject(it.toString()) } }
        val matches = JSONArray()
        var truncated = false
        // 倒排快路径：所有查询串的词元都可精确索引时，只复核候选行。
        val fastLoaded = if (caseInsensitive) PpPostings.get(resultDir) else null
        val fastIds = fastLoaded?.let { loaded ->
            val termGroups = queries.map { it.trim().lowercase().split(Regex("\\s+")) }
            PpPostings.candidateIdsForAny(loaded, termGroups)
        }
        if (fastIds != null) {
            for (id in fastIds) {
                val raw = PpPostings.readLine(fastLoaded!!, id) ?: continue
                val matchedQueries = matchedQueriesOf(raw, queries, caseInsensitive)
                if (matchedQueries.isEmpty()) continue
                if (matches.length() >= limit) { truncated = true; break }
                val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)
                matches.put(JSONObject()
                    .put("offset", offset?.let { "0x${it.lowercase()}" } ?: JSONObject.NULL)
                    .put("matchedQueries", JSONArray(matchedQueries))
                    .put("text", raw.trim().take(300)))
            }
            val resultF = JSONObject().put("queries", JSONArray(queries)).put("matches", matches)
                .put("count", matches.length()).put("truncated", truncated)
                .put("fastPath", true)
            synchronized(this) { ppSearchCache[cacheKey] = JSONObject(resultF.toString()) }
            return resultF
        }
        forEachPpLine(resultDir) { raw ->
            val matchedQueries = matchedQueriesOf(raw, queries, caseInsensitive)
            if (matchedQueries.isEmpty()) return@forEachPpLine true
            if (matches.length() >= limit) {
                truncated = true
                return@forEachPpLine false
            }
            val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)
            matches.put(JSONObject()
                .put("offset", offset?.let { "0x${it.lowercase()}" } ?: JSONObject.NULL)
                .put("matchedQueries", JSONArray(matchedQueries))
                .put("text", raw.trim().take(300)))
            true
        }
        val result = JSONObject().put("queries", JSONArray(queries)).put("matches", matches)
            .put("count", matches.length()).put("truncated", truncated)
        synchronized(this) { ppSearchCache[cacheKey] = JSONObject(result.toString()) }
        return result
    }

    /** locate 首轮同时完成业务体系统计与池项排名，pp.txt 只读一次。 */
    fun profileAndLocatePp(
        resultDir: File,
        groups: List<PpFeatureGroup>,
        primaryQueries: List<String>,
        fallbackQueries: List<String>,
        limit: Int,
        excludedGroupId: String? = null,
        sampleLimit: Int = 6,
    ): JSONObject {
        data class Term(val value: String, val lower: String)
        data class State(
            var hits: Int = 0,
            val termCounts: LinkedHashMap<String, Int> = linkedMapOf(),
            val samples: MutableList<PpCandidate> = mutableListOf(),
        )
        data class Row(
            val offset: String,
            val text: String,
            val lower: String,
            val matchedTerms: Set<String>,
            // 数据性库（高亮词表/文案/生成代码）命中标记：locate 段重算分时
            // 与 profile 段同口径降权，否则 poolMatches 展示仍挂原始高分
            val noisy: Boolean,
        )

        val normalized = groups.associateWith { group ->
            group.keywords.map(String::trim).filter(String::isNotEmpty)
                .distinctBy(String::lowercase).map { Term(it, it.lowercase()) }
        }
        // 预计算全部词条的小写形式：原实现每行对每个词条调 lowercase()，
        // 百万行 × 数百词条 = 上亿次字符串分配（GC 风暴），这是体系判断慢的根源
        val allTermList = (groups.flatMap(PpFeatureGroup::keywords) + primaryQueries + fallbackQueries)
            .map(String::trim).filter(String::isNotEmpty).distinctBy(String::lowercase)
            .map { Term(it, it.lowercase()) }
        val allTermPrefilter = anyOfRegex(allTermList.map(Term::lower), ignoreCase = true)
        val cacheQuery = buildString {
            append("pipeline:")
            append(groups.joinToString("|") { group ->
                "${group.id}:${group.weight}:${group.keywords.joinToString(",")}"
            })
            append(":primary=").append(primaryQueries.joinToString("|"))
            append(":fallback=").append(fallbackQueries.joinToString("|"))
            append(":exclude=").append(excludedGroupId)
            // nz=1：噪声库降权版本戳——行为变更后旧缓存结果作废
            append(":nz=1")
            append(":limit=").append(limit).append(":sample=").append(sampleLimit)
        }
        val cacheKey = ppCacheKey(resultDir, cacheQuery)
        synchronized(this) {
            ppLocatePipelineCache[cacheKey]?.let {
                return JSONObject(it.toString()).put("cacheHit", true).put("scanElapsedMs", 0)
            }
        }

        val states = groups.associateWith { State() }
        val rows = mutableListOf<Row>()
        var scanned = 0L
        val started = System.nanoTime()
        // 倒排快路径：全部词条可精确索引时仅复核候选行，逐行逻辑与旧路径一致。
        val plFastLoaded = PpPostings.get(resultDir)
        val plFastIds = plFastLoaded?.let { PpPostings.candidateIds(it, allTermList.map(Term::lower)) }
        if (plFastIds != null) {
            for (id in plFastIds) {
                val raw = PpPostings.readLine(plFastLoaded!!, id) ?: continue
                scanned++
                val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)?.lowercase() ?: continue
                val lower = raw.lowercase()
                val matchedAll = allTermList.filter { term ->
                    lower.contains(term.lower) && containsTerm(raw, term.value)
                }.mapTo(linkedSetOf(), Term::lower)
                if (matchedAll.isEmpty()) continue
                rows += Row(offset, raw.trim().take(300), lower, matchedAll, NOISY_LIBRARY_PATH.containsMatchIn(raw))
                groups.forEach { group ->
                    val matched = normalized.getValue(group).filter { term -> term.lower in matchedAll }
                    if (matched.isEmpty()) return@forEach
                    val state = states.getValue(group)
                    state.hits++
                    matched.forEach { term ->
                        state.termCounts[term.value] = (state.termCounts[term.value] ?: 0) + 1
                    }
                    val specificity = matched.sumOf { it.value.length.coerceAtMost(24) * 3 }
                    val base = group.weight + matched.size * 100 + specificity +
                        if (lower.contains("string:")) 20 else 0
                    state.samples += PpCandidate(
                        offset, raw.trim().take(300), matched.map(Term::value),
                        noiseAdjustedScore(base, raw, matched.size),
                    )
                    state.samples.sortWith(compareByDescending<PpCandidate> { it.score }
                        .thenBy { it.offset.toLongOrNull(16) ?: Long.MAX_VALUE })
                    if (state.samples.size > sampleLimit) state.samples.removeLast()
                }
            }
        } else forEachPpLine(resultDir) { raw ->
                scanned++
                val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)?.lowercase() ?: return@forEachPpLine true
                // 行级预筛：整行不含任何词条即跳过（正则无命中 => 无词出现，超集安全）
                if (allTermPrefilter != null && !allTermPrefilter.containsMatchIn(raw)) return@forEachPpLine true
                val lower = raw.lowercase()
                val matchedAll = allTermList.filter { term ->
                    lower.contains(term.lower) && containsTerm(raw, term.value)
                }.mapTo(linkedSetOf(), Term::lower)
                if (matchedAll.isNotEmpty()) {
                    rows += Row(offset, raw.trim().take(300), lower, matchedAll, NOISY_LIBRARY_PATH.containsMatchIn(raw))
                }
                groups.forEach { group ->
                    val matched = normalized.getValue(group).filter { term ->
                        term.lower in matchedAll
                    }
                    if (matched.isEmpty()) return@forEach
                    val state = states.getValue(group)
                    state.hits++
                    matched.forEach { term ->
                        state.termCounts[term.value] = (state.termCounts[term.value] ?: 0) + 1
                    }
                    val specificity = matched.sumOf { it.value.length.coerceAtMost(24) * 3 }
                    val base = group.weight + matched.size * 100 + specificity +
                        if (lower.contains("string:")) 20 else 0
                    state.samples += PpCandidate(
                        offset, raw.trim().take(300), matched.map(Term::value),
                        noiseAdjustedScore(base, raw, matched.size),
                    )
                    state.samples.sortWith(compareByDescending<PpCandidate> { it.score }
                        .thenBy { it.offset.toLongOrNull(16) ?: Long.MAX_VALUE })
                    if (state.samples.size > sampleLimit) state.samples.removeLast()
                }
                true
        }

        val systems = groups.map { group ->
            val state = states.getValue(group)
            val uniqueTerms = state.termCounts.size
            val evidenceScore = group.weight + state.hits.coerceAtMost(20) * 5 + uniqueTerms * 15
            val matchedKeywords = normalized.getValue(group).map(Term::value).filter(state.termCounts::containsKey)
            JSONObject()
                .put("id", group.id)
                .put("label", group.label)
                .put("hitCount", state.hits)
                .put("uniqueKeywordCount", uniqueTerms)
                .put("evidenceScore", if (state.hits == 0) 0 else evidenceScore)
                .put("matchedKeywords", JSONArray(matchedKeywords))
                .put("keywordCounts", JSONObject(state.termCounts as Map<*, *>))
                .put("samples", JSONArray(state.samples.map { candidate ->
                    JSONObject().put("offset", "0x${candidate.offset}").put("text", candidate.text)
                        .put("matchedTerms", JSONArray(candidate.matchedTerms)).put("score", candidate.score)
                }))
        }.filter { it.optInt("hitCount") > 0 }
            .sortedWith(compareByDescending<JSONObject> { it.optInt("evidenceScore") }
                .thenByDescending { it.optInt("hitCount") })
        val selected = systems.firstOrNull()
        val runnerUp = systems.getOrNull(1)
        val ambiguous = selected != null && runnerUp != null &&
            selected.optInt("evidenceScore") - runnerUp.optInt("evidenceScore") < 20
        val profile = JSONObject()
            .put("scannedLines", scanned)
            .put("systems", JSONArray(systems))
            .put("selectedSystem", selected ?: JSONObject.NULL)
            .put("ambiguous", ambiguous)
            .put("classificationStatus", when {
                selected == null -> "not_found"
                ambiguous -> "ambiguous"
                else -> "clear"
            })
        val selectedSystems = systems.take(if (ambiguous) 2 else 1)
        val selectedIds = selectedSystems.map { it.optString("id") }
        val profileTerms = (primaryQueries + selectedSystems.flatMap { system ->
            val terms = system.optJSONArray("matchedKeywords") ?: JSONArray()
            (0 until terms.length()).map(terms::optString)
        }).filter(String::isNotBlank).distinct().take(32)
        val exclusions = excludedGroupId?.takeIf { it !in selectedIds }
            ?.let { id -> groups.firstOrNull { it.id == id }?.keywords }.orEmpty()
        var keywordStage = if (profileTerms.isNotEmpty()) "intent_profile" else "exact"

        fun locate(queries: List<String>, excluded: List<String>): JSONObject {
            val needles = queries.map(String::trim).filter(String::isNotEmpty).distinctBy(String::lowercase)
            val excludedTerms = excluded.map(String::trim).filter(String::isNotEmpty).distinctBy(String::lowercase)
            val worstFirst = compareBy<PpCandidate> { it.score }
                .thenByDescending { it.offset.toLongOrNull(16) ?: Long.MAX_VALUE }
            val candidates = PriorityQueue(worstFirst)
            val representatives = linkedMapOf<String, PpCandidate>()
            val maxCandidates = limit * 8
            var matchedCount = 0
            rows.forEach { row ->
                val matched = needles.filter { it.lowercase() in row.matchedTerms }
                if (matched.isEmpty() || excludedTerms.any { it.lowercase() in row.matchedTerms }) return@forEach
                matchedCount++
                val rawScore = matched.size * 100 + (if (row.lower.contains("string:")) 20 else 0) +
                    (if (row.lower.contains("is_")) 10 else 0)
                // 与 profile 段同口径：数据性库行 + 词堆/超长数据串都降权，
                // 防止 poolMatches 展示层仍挂 500+ 原始分误导排序归因
                val score = if (row.noisy || isKeywordPile(row.text, matched.size)) {
                    (rawScore * NOISY_SCORE_FACTOR).toInt()
                } else {
                    rawScore
                }
                val candidate = PpCandidate(row.offset, row.text, matched, score)
                matched.forEach { term ->
                    val previous = representatives[term]
                    if (previous == null || worstFirst.compare(candidate, previous) > 0) representatives[term] = candidate
                }
                if (candidates.size < maxCandidates) candidates += candidate
                else if (worstFirst.compare(candidate, candidates.peek()) > 0) {
                    candidates.poll()
                    candidates += candidate
                }
            }
            val ranked = candidates.sortedWith(compareByDescending<PpCandidate> { it.score }
                .thenBy { it.offset.toLongOrNull(16) ?: Long.MAX_VALUE })
            val top = buildList {
                representatives.values.forEach { candidate ->
                    if (none { existing: PpCandidate -> existing.offset == candidate.offset }) add(candidate)
                }
                ranked.forEach { candidate ->
                    if (size < limit && none { existing: PpCandidate -> existing.offset == candidate.offset }) add(candidate)
                }
            }.take(limit)
            return JSONObject().put("queries", JSONArray(needles)).put("excludedQueries", JSONArray(excludedTerms))
                .put("scannedLines", scanned).put("matched", matchedCount).put("truncated", matchedCount > top.size)
                .put("candidates", JSONArray(top.map { candidate ->
                    JSONObject().put("offset", "0x${candidate.offset}").put("text", candidate.text)
                        .put("matchedTerms", JSONArray(candidate.matchedTerms)).put("score", candidate.score)
                }))
        }

        var located = locate(profileTerms.ifEmpty { primaryQueries }, exclusions)
        if (located.optInt("matched") == 0 && profileTerms.isEmpty()) {
            keywordStage = "domain_fallback"
            located = locate(fallbackQueries, emptyList())
        }
        val result = JSONObject()
            .put("profile", profile)
            .put("locate", located)
            .put("keywordStage", keywordStage)
            .put("cacheHit", false)
            .put("scanElapsedMs", (System.nanoTime() - started) / 1_000_000)
            .put("scannedLines", scanned)
        synchronized(this) { ppLocatePipelineCache[cacheKey] = JSONObject(result.toString()) }
        return result
    }

    /** 单次流式扫描 pp.txt：按用户意图的多个关键词返回最相关池项，绝不把 pp.txt 整体交给模型。 */
    fun locatePp(
        resultDir: File,
        queries: List<String>,
        limit: Int,
        excludeQueries: List<String> = emptyList(),
    ): JSONObject {
        val needles = queries.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.distinct()
        val exclusions = excludeQueries.map(String::trim).filter(String::isNotEmpty).distinctBy(String::lowercase)
        val cacheKey = ppCacheKey(resultDir, "locate:${needles.joinToString("|")}:${exclusions.joinToString("|")}:$limit")
        synchronized(this) { ppLocateCache[cacheKey]?.let { return JSONObject(it.toString()) } }
        val worstFirst = compareBy<PpCandidate> { it.score }
            .thenByDescending { it.offset.toLongOrNull(16) ?: Long.MAX_VALUE }
        val candidates = PriorityQueue(worstFirst)
        val representatives = linkedMapOf<String, PpCandidate>()
        val maxCandidates = limit * 8
        var scanned = 0L
        var matchedCount = 0
        // 倒排快路径候选集（词条任一不可索引则回退全量扫描）
        val fastLoaded = PpPostings.get(resultDir)
        val fastIds = fastLoaded?.let { PpPostings.candidateIds(it, needles) }
        fun processCandidate(raw: String): Boolean {
            val lower = raw.lowercase()
            val matched = needles.filter { containsTerm(raw, it) }
            if (matched.isEmpty()) return true
            if (exclusions.any { containsTerm(raw, it) }) return true
            val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)?.lowercase() ?: return true
            scanned++
            val score = matched.size * 100 +
                (if (lower.contains("string:")) 20 else 0) +
                (if (lower.contains("is_")) 10 else 0)
            // 词堆/超长数据串降权：词表、文案、符号表特征，与 profile 段同口径
            val adjusted = if (isKeywordPile(raw, matched.size)) (score * NOISY_SCORE_FACTOR).toInt() else score
            val candidate = PpCandidate(offset, raw.trim().take(300), matched, adjusted)
            matched.forEach { term ->
                val previous = representatives[term]
                if (previous == null || worstFirst.compare(candidate, previous) > 0) representatives[term] = candidate
            }
            if (candidates.size < maxCandidates) {
                candidates += candidate
            } else if (worstFirst.compare(candidate, candidates.peek()) > 0) {
                candidates.poll()
                candidates += candidate
            }
            matchedCount++
            return true
        }
        if (fastIds != null && exclusions.all { PpPostings.EXACT_TERM.matches(it.trim().lowercase()) }) {
            fastIds.forEach { id ->
                val raw = PpPostings.readLine(fastLoaded!!, id) ?: return@forEach
                processCandidate(raw)
            }
        } else forEachPpLine(resultDir) { raw ->
            scanned++
            val lower = raw.lowercase()
            val matched = needles.filter { containsTerm(raw, it) }
            if (matched.isEmpty()) return@forEachPpLine true
            if (exclusions.any { containsTerm(raw, it) }) return@forEachPpLine true
            val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)?.lowercase() ?: return@forEachPpLine true
            matchedCount++
            val score = matched.size * 100 +
                (if (lower.contains("string:")) 20 else 0) +
                (if (lower.contains("is_")) 10 else 0)
            // 词堆/超长数据串降权：词表、文案、符号表特征，与 profile 段同口径
            val adjusted = if (isKeywordPile(raw, matched.size)) (score * NOISY_SCORE_FACTOR).toInt() else score
            val candidate = PpCandidate(offset, raw.trim().take(300), matched, adjusted)
            matched.forEach { term ->
                val previous = representatives[term]
                if (previous == null || worstFirst.compare(candidate, previous) > 0) representatives[term] = candidate
            }
            if (candidates.size < maxCandidates) {
                candidates += candidate
            } else if (worstFirst.compare(candidate, candidates.peek()) > 0) {
                candidates.poll()
                candidates += candidate
            }
            true
        }
        val ranked = candidates
            .sortedWith(compareByDescending<PpCandidate> { it.score }.thenBy { it.offset.toLongOrNull(16) ?: Long.MAX_VALUE })
        val top = buildList {
            representatives.values.forEach { candidate -> if (this.none { existing: PpCandidate -> existing.offset == candidate.offset }) add(candidate) }
            ranked.forEach { candidate -> if (size < limit && this.none { existing: PpCandidate -> existing.offset == candidate.offset }) add(candidate) }
        }.take(limit)
        val result = JSONObject()
            .put("queries", JSONArray(needles))
            .put("excludedQueries", JSONArray(exclusions))
            .put("scannedLines", scanned)
            .put("matched", matchedCount)
            .put("truncated", matchedCount > top.size)
            .put("candidates", JSONArray(top.map { candidate ->
                JSONObject()
                    .put("offset", "0x${candidate.offset}")
                    .put("text", candidate.text)
                    .put("matchedTerms", JSONArray(candidate.matchedTerms))
                    .put("score", candidate.score)
            }))
        synchronized(this) { ppLocateCache[cacheKey] = JSONObject(result.toString()) }
        return result
    }

    /** 单次扫描 pp.txt，统计各中英文特征组并判断当前 App 实际使用的业务体系。 */
    fun profilePp(resultDir: File, groups: List<PpFeatureGroup>, sampleLimit: Int = 6): JSONObject {
        data class State(
            var hits: Int = 0,
            val termCounts: LinkedHashMap<String, Int> = linkedMapOf(),
            val samples: MutableList<PpCandidate> = mutableListOf(),
        )
        data class Term(val value: String, val lower: String)

        val normalized = groups.associateWith { group ->
            group.keywords.map(String::trim).filter(String::isNotEmpty).distinctBy(String::lowercase)
                .map { Term(it, it.lowercase()) }
        }
        val cacheKey = ppCacheKey(resultDir, "profile:${groups.joinToString("|") { group -> "${group.id}:${group.weight}:${group.keywords.joinToString(",")}" }}:$sampleLimit")
        synchronized(this) { ppProfileCache[cacheKey]?.let { return JSONObject(it.toString()) } }
        val states = groups.associateWith { State() }
        val profilePrefilter = anyOfRegex(
            groups.flatMap { group -> normalized.getValue(group) }.map(Term::lower),
            ignoreCase = true,
        )
        var scanned = 0L
        val pFastLoaded = PpPostings.get(resultDir)
        val pFastIds = pFastLoaded?.let { PpPostings.candidateIds(it, normalized.values.flatten().map(Term::lower)) }
        if (pFastIds != null) {
            for (id in pFastIds) {
                val raw = PpPostings.readLine(pFastLoaded!!, id) ?: continue
                scanned++
                val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)?.lowercase() ?: continue
                val lower = raw.lowercase()
                groups.forEach { group ->
                    val matched = normalized.getValue(group).filter { term ->
                        lower.contains(term.lower) && containsTerm(raw, term.value)
                    }
                    if (matched.isEmpty()) return@forEach
                    val state = states.getValue(group)
                    state.hits++
                    matched.forEach { term ->
                        state.termCounts[term.value] = (state.termCounts[term.value] ?: 0) + 1
                    }
                    val specificity = matched.sumOf { it.value.length.coerceAtMost(24) * 3 }
                    val score = group.weight + matched.size * 100 + specificity +
                        if (lower.contains("string:")) 20 else 0
                    val candidate = PpCandidate(offset, raw.trim().take(300), matched.map(Term::value), score)
                    state.samples += candidate
                    state.samples.sortWith(compareByDescending<PpCandidate> { it.score }
                        .thenBy { it.offset.toLongOrNull(16) ?: Long.MAX_VALUE })
                    if (state.samples.size > sampleLimit) state.samples.removeLast()
                }
            }
        } else forEachPpLine(resultDir) { raw ->
            scanned++
            val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)?.lowercase() ?: return@forEachPpLine true
            // 行级预筛：整行不含任何组词条即跳过（超集安全，精确匹配仍在下方逐词执行）
            if (profilePrefilter != null && !profilePrefilter.containsMatchIn(raw)) return@forEachPpLine true
            val lower = raw.lowercase()
            groups.forEach { group ->
                val matched = normalized.getValue(group).filter { term ->
                    lower.contains(term.lower) && containsTerm(raw, term.value)
                }
                if (matched.isEmpty()) return@forEach
                val state = states.getValue(group)
                state.hits++
                matched.forEach { term ->
                    state.termCounts[term.value] = (state.termCounts[term.value] ?: 0) + 1
                }
                val specificity = matched.sumOf { it.value.length.coerceAtMost(24) * 3 }
                val score = group.weight + matched.size * 100 + specificity + if (lower.contains("string:")) 20 else 0
                val candidate = PpCandidate(offset, raw.trim().take(300), matched.map(Term::value), score)
                state.samples += candidate
                state.samples.sortWith(compareByDescending<PpCandidate> { it.score }.thenBy { it.offset.toLongOrNull(16) ?: Long.MAX_VALUE })
                if (state.samples.size > sampleLimit) state.samples.removeLast()
            }
            true
        }
        val systems = groups.map { group ->
            val state = states.getValue(group)
            val uniqueTerms = state.termCounts.size
            val evidenceScore = group.weight + state.hits.coerceAtMost(20) * 5 + uniqueTerms * 15
            val matchedKeywords = normalized.getValue(group)
                .map(Term::value)
                .filter(state.termCounts::containsKey)
            JSONObject()
                .put("id", group.id)
                .put("label", group.label)
                .put("hitCount", state.hits)
                .put("uniqueKeywordCount", uniqueTerms)
                .put("evidenceScore", if (state.hits == 0) 0 else evidenceScore)
                .put("matchedKeywords", JSONArray(matchedKeywords))
                .put("keywordCounts", JSONObject(state.termCounts as Map<*, *>))
                .put("samples", JSONArray(state.samples.map { candidate ->
                    JSONObject()
                        .put("offset", "0x${candidate.offset}")
                        .put("text", candidate.text)
                        .put("matchedTerms", JSONArray(candidate.matchedTerms))
                        .put("score", candidate.score)
                }))
        }.filter { it.optInt("hitCount") > 0 }
            .sortedWith(compareByDescending<JSONObject> { it.optInt("evidenceScore") }.thenByDescending { it.optInt("hitCount") })
        val selected = systems.firstOrNull()
        val runnerUp = systems.getOrNull(1)
        val ambiguous = selected != null && runnerUp != null &&
            selected.optInt("evidenceScore") - runnerUp.optInt("evidenceScore") < 20
        val result = JSONObject()
            .put("scannedLines", scanned)
            .put("systems", JSONArray(systems))
            .put("selectedSystem", selected ?: JSONObject.NULL)
            .put("ambiguous", ambiguous)
            .put("classificationStatus", when {
                selected == null -> "not_found"
                ambiguous -> "ambiguous"
                else -> "clear"
            })
        synchronized(this) { ppProfileCache[cacheKey] = JSONObject(result.toString()) }
        return result
    }

    fun ppContexts(resultDir: File, poolOffsets: List<Long>, radius: Int = 4): JSONObject {
        data class Capture(
            val offset: String,
            val lines: MutableList<String>,
            var remaining: Int,
        )

        val targets = poolOffsets.map { it.toString(16) }.toSet()
        val cacheKey = ppCacheKey(resultDir, "context:${targets.sorted().joinToString(",")}:$radius")
        synchronized(this) { ppContextCache[cacheKey]?.let { return JSONObject(it.toString()) } }
        val before = ArrayDeque<String>()
        val active = mutableListOf<Capture>()
        val captures = linkedMapOf<String, Capture>()
        forEachPpLine(resultDir) { raw ->
            active.toList().forEach { capture ->
                capture.lines += raw.trim().take(300)
                capture.remaining--
                if (capture.remaining == 0) active.remove(capture)
            }
            val offset = PP_OFFSET.find(raw)?.groupValues?.get(1)?.lowercase()
            if (offset != null && offset in targets && offset !in captures) {
                val capture = Capture(offset, (before.toList() + raw.trim().take(300)).toMutableList(), radius)
                captures[offset] = capture
                active += capture
            }
            before += raw.trim().take(300)
            if (before.size > radius) before.removeFirst()
            true
        }
        val typeArguments = Regex("""TypeArguments?:\s*<([^>]+)>""")
        val listType = Regex("""\bList<([^>]+)>""")
        val closureType = Regex("""Closure:.*?=>\s*([A-Za-z_][A-Za-z0-9_]*)\s+from""")
        val fieldType = Regex("""Field\s+<([A-Za-z_][A-Za-z0-9_]*)[.@]""")
        val identifier = Regex("""[A-Za-z_][A-Za-z0-9_]*""")
        val builtIns = setOf("dynamic", "String", "int", "double", "bool", "Object", "List", "Map", "Set", "Function")
        val rows = captures.values.map { capture ->
            val symbols = linkedSetOf<String>()
            capture.lines.forEach { line ->
                sequenceOf(typeArguments.find(line), listType.find(line)).filterNotNull().forEach { match ->
                    identifier.findAll(match.groupValues[1]).map { it.value }.forEach(symbols::add)
                }
                closureType.find(line)?.groupValues?.get(1)?.let(symbols::add)
                fieldType.find(line)?.groupValues?.get(1)?.let(symbols::add)
            }
            symbols.removeAll(builtIns)
            symbols.removeAll { it.length < 2 || it.length > 24 || it.none(Char::isUpperCase) }
            JSONObject()
                .put("offset", "0x${capture.offset}")
                .put("symbols", JSONArray(symbols.toList()))
                .put("lines", JSONArray(capture.lines))
        }
        val result = JSONObject()
            .put("contexts", JSONArray(rows))
            .put("symbols", JSONArray(rows.flatMap { row ->
                val symbols = row.getJSONArray("symbols")
                (0 until symbols.length()).map(symbols::getString)
            }.distinct()))
        synchronized(this) { ppContextCache[cacheKey] = JSONObject(result.toString()) }
        return result
    }

    fun outlineClasses(resultDir: File, classNames: List<String>, semanticHints: List<String>, limit: Int): JSONObject {
        val targets = classNames.toSet()
        val hints = semanticHints.map(String::trim).filter(String::isNotEmpty).distinctBy(String::lowercase)
        val methods = functionHeaders(resultDir).mapNotNull { header ->
            val owner = header.className?.takeIf(String::isNotBlank) ?: return@mapNotNull null
            val signature = header.name?.takeIf(String::isNotBlank) ?: return@mapNotNull null
            if (owner !in targets) return@mapNotNull null
            val matchedHints = hints.filter { containsTerm(signature, it) }
            JSONObject()
                .put("class", owner)
                .put("function", signature)
                .put("functionVa", "0x${header.va.toString(16)}")
                .put("file", header.file)
                .put("semanticMatch", matchedHints.isNotEmpty())
                .put("matchedHints", JSONArray(matchedHints))
                .put("score", matchedHints.size * 100 + if (signature.contains("dyn:get:")) 20 else 0)
        }
        val ranked = methods.sortedWith(
            compareByDescending<JSONObject> { it.optBoolean("semanticMatch") }
                .thenByDescending { it.optInt("score") }
                .thenBy { it.optString("functionVa") },
        ).take(limit)
        return JSONObject()
            .put("classes", JSONArray(targets.toList()))
            .put("methods", JSONArray(ranked))
            .put("lookupMode", "compact_function_index")
    }

    fun searchAsm(
        resultDir: File,
        query: String,
        caseInsensitive: Boolean,
        limit: Int,
        fullScan: Boolean = false,
        includePaths: List<String> = emptyList(),
        excludePaths: List<String> = emptyList(),
        includeThirdParty: Boolean = false,
    ): JSONObject {
        val queries = searchQueries(query, caseInsensitive)
        // 路径过滤的新鲜度指纹：只覆盖「实际匹配 include 过滤的文件」——
        // 命中文件内容变化（mtime/size）必须使缓存键失效；无关文件不参与
        // 指纹（避免为整包 asm 全量 stat）。选择在前、缓存检查在后。
        val pathSelection = if (includePaths.isEmpty()) null
        else asmPathSelection(resultDir, includePaths, excludePaths)
        val sourceFingerprint = if (pathSelection == null) {
            val index = semanticIndexFile(resultDir)
            "${index.absolutePath}:${index.lastModified()}:${index.length()}"
        } else {
            val asmDir = File(resultDir, "asm")
            pathSelection
                .filter { matchesPathFilters(it, includePaths, excludePaths) }
                .joinToString(separator = "|") { rel ->
                    val file = File(asmDir, rel.removePrefix("asm/"))
                    "$rel:${file.lastModified()}:${file.length()}"
                }
        }
        val cacheKey = asmSearchCacheKey(
            resultDir,
            sourceFingerprint,
            queries,
            caseInsensitive,
            limit,
            fullScan,
            includePaths,
            excludePaths,
            includeThirdParty,
        )
        synchronized(this) {
            asmSearchCache[cacheKey]?.let {
                return JSONObject(it.toString()).put("cacheHit", true).put("scanElapsedMs", 0)
            }
        }
        val started = System.nanoTime()
        val result = if (pathSelection != null) {
            searchAsmFiles(resultDir, queries, caseInsensitive, limit, includePaths, excludePaths, includeThirdParty, pathSelection)
                .put("lookupMode", "asm_path_filtered_scan")
                .put("fullScan", fullScan)
        } else {
            val indexed = searchSemanticAsm(resultDir, queries, caseInsensitive, limit, includePaths, excludePaths)
            // 构建中信封：透传给 AI（带进度与可用工具指引），不落缓存、不走 fallback
            if (indexed.optBoolean("indexing")) return indexed
            if (indexed.getJSONArray("matches").length() > 0 || !fullScan) indexed
            else searchAsmFiles(resultDir, queries, caseInsensitive, limit, includePaths, excludePaths, includeThirdParty)
                .put("semanticMiss", true)
        }
        result.put("cacheHit", false).put("scanElapsedMs", (System.nanoTime() - started) / 1_000_000)
        synchronized(this) { asmSearchCache[cacheKey] = JSONObject(result.toString()) }
        return result
    }

    private fun asmSearchCacheKey(
        resultDir: File,
        sourceFingerprint: String,
        queries: List<String>,
        caseInsensitive: Boolean,
        limit: Int,
        fullScan: Boolean,
        includePaths: List<String>,
        excludePaths: List<String>,
        includeThirdParty: Boolean,
    ): AsmSearchCacheKey {
        return AsmSearchCacheKey(
            resultDir.absoluteFile.normalize().path,
            sourceFingerprint,
            queries.joinToString("|"),
            caseInsensitive,
            limit,
            fullScan,
            includePaths.map(String::lowercase),
            excludePaths.map(String::lowercase),
            includeThirdParty,
        )
    }

    private fun searchSemanticAsm(
        resultDir: File,
        queries: List<String>,
        caseInsensitive: Boolean,
        limit: Int,
        includePaths: List<String>,
        excludePaths: List<String>,
    ): JSONObject {
        // 构建中不干等：秒回 SEMANTIC_INDEX_BUILDING 信封（上层转 preparing 提示），
        // 等锁会吃满 MCP 超时后伪装成 tool_busy_timeout，AI 分不清是在排队还是查询本身慢。
        val meta = ensureSemanticIndexIfReady(resultDir) ?: return indexingEnvelope()
        val index = semanticIndexFile(resultDir)
        val matches = JSONArray()
        var scannedRows = 0
        var truncated = false
        // 行级预筛：行的可搜索字段都不含任何词条时跳过后续处理（超集安全——
        // 正则无命中 => 词不在命中判定文本里）。v6 二进制行本身已无 JSON 解析开销，
        // 预筛保留是为了省略 lowercase 与上下文拼装。
        val prefilter = if (queries.any { it.any { c -> c == '"' || c == '\\' } }) null
        else anyOfRegex(queries, ignoreCase = true)
        // path 过滤词预小写一次（与 matchesPathFilters 的小写语义等价）
        val includesLc = includePaths.map(String::lowercase)
        val excludesLc = excludePaths.map(String::lowercase)
        // v5 瘦身：reference/immediate 行不再内嵌 function/class/file，按 functionVa
        // 从 functionHeader 索引反查（几千条、有驻留缓存）。反查文本串按函数缓存，
        // 百万行扫描中同一函数只拼一次。
        val headersByVa = HashMap<Long, FunctionHeader>()
        functionHeaders(resultDir).forEach { headersByVa[it.va] = it }
        val contextTextCache = HashMap<Long, String>()
        fun contextText(functionVa: Long): String = contextTextCache.getOrPut(functionVa) {
            val h = headersByVa[functionVa]
            listOfNotNull(h?.name, h?.className, h?.file?.takeIf(String::isNotBlank))
                .joinToString(" ")
        }
        // B1-1：context 命中判定按函数缓存（同一函数的成百上千条指令行只判一次）
        val contextPrefilterCache = HashMap<Long, Boolean>()
        // B1-2 候选收窄：词元全部在倒排里时只处理候选行（并集语义，见 SemanticPostings）；
        // 缺词/无倒排 → null 回退扫描。命中判定始终由复核逻辑完成，故无假阴性。
        val candidateIds = SemanticPostings.candidates(
            if (caseInsensitive) SemanticPostings.read(resultDir) else null,
            SemanticPostings.tokens(queries.joinToString(" ")),
        )
        var candidateIndex = 0
        val scanStartedAt = System.currentTimeMillis()
        SemanticRowReader.open(index).use { rows ->
            while (true) {
                val row = rows.next() ?: break
                val rowId = scannedRows
                scannedRows++
                if (candidateIds != null) {
                    // 不提前结束读取（scannedRows 语义要保住）；收益来自跳过逐行匹配。
                    if (candidateIds.isEmpty()) continue
                    while (candidateIndex < candidateIds.size &&
                        candidateIds[candidateIndex] < rowId
                    ) {
                        candidateIndex++
                    }
                    if (candidateIndex >= candidateIds.size) continue
                    if (candidateIds[candidateIndex] != rowId) continue
                }
                // 快路径（B1-1）：先对行内文本做子串预筛（v6 二进制没有 JSON 原文，
                // 预筛文本 = 该行可搜索字段，仍是「命中判定文本」的超集）。
                // 只有预筛未命中、且该行是「非 function 行」（function/class/file
                // 不在行内）时，才回落到 functionVa → context 兜底。直接把 functionVa
                // 解析后移会丢掉「按函数名/类名命中指令行」这条语义，故保留兜底分支。
                val functionVa = row.functionVa
                if (prefilter != null && !row.prefilterHit(prefilter)) {
                    if (row.type == SemanticRowFormat.TYPE_FUNCTION) continue
                    val ctxHit = functionVa != null &&
                        contextPrefilterCache.getOrPut(functionVa) {
                            val ctx = contextText(functionVa)
                            ctx.isNotEmpty() && prefilter.containsMatchIn(ctx)
                        }
                    if (!ctxHit) continue
                }
                val context = functionVa?.let(::contextText).orEmpty()
                val searchable = semanticSearchableText(row, context)
                // lowercase 一次复用给 path 过滤与词条匹配（原实现每行每词各转一次，
                // 百万行 × N 词 = 数百万次大字符串分配，GC 风暴）
                val haystackLc = searchable.lowercase()
                if (includesLc.isNotEmpty() && includesLc.none { haystackLc.contains(it) }) continue
                if (excludesLc.isNotEmpty() && excludesLc.any { haystackLc.contains(it) }) continue
                val matchedQueries = if (caseInsensitive) queries.filter { haystackLc.contains(it) }
                else queries.filter { searchable.contains(it) }
                if (matchedQueries.isEmpty()) continue
                if (matches.length() >= limit) {
                    truncated = true
                    break
                }
                val header = functionVa?.let { headersByVa[it] }
                matches.put(JSONObject()
                    .put("file", header?.file.orEmpty())
                    .put("line", row.optInt("line", 0))
                    .put("function", header?.name ?: JSONObject.NULL)
                    .put("class", header?.className ?: JSONObject.NULL)
                    .put("text", row.optString("insn").ifBlank { row.optString("text") }
                        .ifBlank { header?.name.orEmpty() }.take(300))
                    .put("matchedQueries", JSONArray(matchedQueries)))
            }
        }
        val scanMillis = System.currentTimeMillis() - scanStartedAt
        runCatching {
            KotlinToolStats.record(
                tool = "blutter.index.search",
                success = true,
                micros = scanMillis * 1000,
            )
        }
        // B2-3：开关打开时索引里**根本没有**那些噪音子树的语义行，调用方无法分辨
        // "确实没有"还是"没建索引"——少行必须自报（与截断自报同一条纪律）。
        // 默认关闭时这两个字段不出现，响应与改造前逐字节一致。
        val skippedNoisy = meta.optInt("skippedNoisyFiles", 0)
        val skipNoisy = meta.optBoolean("skipNoisyPaths", false) || skippedNoisy > 0
        val hint = if (matches.length() == 0) {
            if (skipNoisy) {
                "索引未命中。索引已按设置跳过 $skippedNoisy 个噪音子树文件（searchSemanticAsm 的 skipNoisyPaths 范围），" +
                    "需要搜这些文件时用 fullScan=true；不要逐词重复全目录扫描。"
            } else {
                "索引未命中。只有确需搜索非语义原始行时才用 fullScan=true，禁止逐词重复全目录扫描。"
            }
        } else if (skipNoisy) {
            "相关词可用 | 合并为一次查询。（索引已按设置跳过 $skippedNoisy 个噪音子树文件，需要时用 fullScan=true 搜原文）"
        } else {
            "相关词可用 | 合并为一次查询。"
        }
        return JSONObject()
            .put("queries", JSONArray(queries))
            .put("matches", matches)
            .put("count", matches.length())
            .put("scanMillis", scanMillis)
            .put("candidateMode", if (candidateIds != null) "postings" else "prefilter")
            .put("indexBytes", index.length())
            .put("scannedFiles", meta.optInt("scannedFiles"))
            .put("scannedRows", scannedRows)
            .put("lookupMode", "semantic_index")
            .put("truncated", truncated)
            .put("fullScan", false)
            .put("includePath", JSONArray(includePaths))
            .put("excludePath", JSONArray(excludePaths))
            .apply {
                if (skipNoisy) {
                    put("skipNoisyPaths", true)
                    put("skippedNoisyFiles", skippedNoisy)
                }
            }
            .put("hint", hint)
    }

    /**
     * B1-2 构建倒排：与查询侧共用同一行解析器（[SemanticRowReader]）与同一文本口径
     * （[semanticSearchableText]），否则 rowId / 词元集合对不上就是「搜得到变搜不到」。
     */
    private fun buildSemanticPostings(resultDir: File, index: File) {
        val headersByVa = HashMap<Long, FunctionHeader>()
        runCatching { functionHeaders(resultDir).forEach { headersByVa[it.va] = it } }
        val postings = SemanticPostings.collect(
            index = index,
            headerText = { va ->
                headersByVa[va]?.let { header ->
                    listOfNotNull(
                        header.name,
                        header.className,
                        header.file?.takeIf(String::isNotBlank),
                    ).joinToString(" ")
                }.orEmpty()
            },
        )
        SemanticPostings.write(resultDir, postings)
    }

    private fun asmPathSelection(resultDir: File, includePaths: List<String>, excludePaths: List<String>): List<String> {
        val index = File(resultDir, ASM_PATH_INDEX)
        // 索引新鲜度：asm 目录比索引新（新文件出现/删除）时重建——否则
        // 新增的 .dart 文件永远不会被 includePaths 扫描命中。
        val asmDir = File(resultDir, "asm")
        if (!index.isFile || asmDir.lastModified() > index.lastModified()) {
            val paths = asmDir.walkTopDown()
                .filter { it.isFile && it.extension == "dart" }
                .map { "asm/${it.relativeTo(asmDir).path.replace('\\', '/')}" }
                .sorted()
                .toList()
            val temporary = File(resultDir, "$ASM_PATH_INDEX.tmp")
            temporary.writeText(paths.joinToString(separator = "\n", postfix = if (paths.isEmpty()) "" else "\n"))
            runCatching {
                Files.move(temporary.toPath(), index.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            }.getOrElse {
                Files.move(temporary.toPath(), index.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        }
        // 返回全量 asm 路径；include/exclude 过滤与 skipped 计数在
        // searchAsmFiles 内部完成（否则被过滤文件永远进不了 skip 分支，
        // skippedFiles 恒为 0，测试与统计口径都失真）。
        return index.useLines { lines ->
            lines.map(String::trim)
                .filter(String::isNotEmpty)
                .toList()
        }
    }

    private fun searchAsmFiles(
        resultDir: File,
        queries: List<String>,
        caseInsensitive: Boolean,
        limit: Int,
        includePaths: List<String>,
        excludePaths: List<String>,
        includeThirdParty: Boolean,
        candidatePaths: List<String>? = null,
    ): JSONObject {
        val asmDir = File(resultDir, "asm")
        val matches = JSONArray()
        var truncated = false
        var scanned = 0
        var skippedFiles = 0
        val files = candidatePaths?.asSequence()
            ?.map { File(asmDir, it.removePrefix("asm/")) }
            ?.filter { it.isFile && it.extension == "dart" }
            ?: asmDir.walkTopDown().filter { it.isFile && it.extension == "dart" }
        files.forEach { file ->
            if (truncated) return@forEach
            val rel = "asm/${file.relativeTo(asmDir).path}"
            if (!matchesPathFilters(rel, includePaths, excludePaths) ||
                (includePaths.isEmpty() && !includeThirdParty && isLikelyThirdParty(rel))) {
                skippedFiles++
                return@forEach
            }
            var currentClass: String? = null
            var currentFunction: String? = null
            var pendingSignature: String? = null
            file.useLines { lines ->
                lines.forEachIndexed { index, raw ->
                    val trimmed = raw.trim()
                    if (trimmed.startsWith("class ")) currentClass = className(trimmed)
                    val addrHeader = FUNC_ADDR.matchEntire(raw)
                    when {
                        addrHeader != null -> currentFunction = pendingSignature
                        raw.startsWith("  ") && !trimmed.startsWith("//") && trimmed.isNotEmpty() -> pendingSignature = trimmed.trimEnd('{', ' ', ';')
                    }
                    val searchable = if (caseInsensitive) raw.lowercase() else raw
                    val matchedQueries = queries.filter(searchable::contains)
                    if (matchedQueries.isEmpty()) return@forEachIndexed
                    if (matches.length() >= limit) { truncated = true; return@forEachIndexed }
                    matches.put(JSONObject()
                        .put("file", rel)
                        .put("line", index + 1)
                        .put("function", currentFunction ?: JSONObject.NULL)
                        .put("class", currentClass ?: JSONObject.NULL)
                        .put("matchedQueries", JSONArray(matchedQueries))
                        .put("text", trimmed.take(300)))
                }
            }
            scanned++
        }
        return JSONObject()
            .put("queries", JSONArray(queries))
            .put("matches", matches)
            .put("count", matches.length())
            .put("scannedFiles", scanned)
            .put("skippedFiles", skippedFiles)
            .put("lookupMode", "asm_full_scan")
            .put("fullScan", true)
            .put("includePath", JSONArray(includePaths))
            .put("excludePath", JSONArray(excludePaths))
            .put("includeThirdParty", includeThirdParty)
            .put("truncated", truncated)
    }

    private fun matchesPathFilters(value: String, includes: List<String>, excludes: List<String>): Boolean {
        // 常见路径：无过滤条件，免去每行 lowercase 分配
        if (includes.isEmpty() && excludes.isEmpty()) return true
        val normalized = value.lowercase()
        if (includes.isNotEmpty() && includes.none { normalized.contains(it.lowercase()) }) return false
        return excludes.none { normalized.contains(it.lowercase()) }
    }

    private fun isLikelyThirdParty(value: String): Boolean {
        val normalized = value.lowercase().replace("%3a", ":").replace("%2f", "/")
        return listOf(
            "dart:",
            "package:flutter/",
            "package:archive/",
            "package:dio/",
            "package:http/",
            "package:crypto/",
            "package:collection/",
            "package:extended_image/",
            "package:path_provider/",
            "package:shared_preferences/",
        ).any(normalized::contains)
    }

    /**
     * Blutter may recover pool references but omit large AOT function bodies.
     * Inspect the current libapp bytes directly and join three independent facts:
     * display string branch values, direct calls, and small-integer return ladders.
     */
    fun rawDecisionFlow(
        libapp: ByteArray,
        verificationWindows: JSONArray,
        refsByOffset: JSONObject,
        poolTextByOffset: Map<String, String>,
        requestedValues: List<Long>,
        limit: Int = 5,
    ): JSONObject {
        data class RawFunction(
            val start: Long,
            val end: Long,
            val comparisons: MutableList<Pair<Long, Long>> = mutableListOf(),
            val returnedValues: LinkedHashSet<Long> = linkedSetOf(),
            val returnSites: MutableList<Pair<Long, Long>> = mutableListOf(),
            val calls: LinkedHashSet<Long> = linkedSetOf(),
        )

        val codeRanges = arm64ExecutableRanges(libapp)
        fun fileOffset(va: Long): Int? = codeRanges.firstOrNull { range ->
            va >= range.virtualAddress && va - range.virtualAddress < range.fileEnd - range.fileOffset
        }?.let { range -> range.fileOffset + (va - range.virtualAddress).toInt() }
        fun wordAt(va: Long): Int? = fileOffset(va)?.takeIf { it >= 0 && it + 4 <= libapp.size }
            ?.let { arm64Word(libapp, it) }
        fun movzX0(word: Int): Long? {
            if ((word and 0xffe0001f.toInt()) != 0xd2800000.toInt()) return null
            val shift = (word ushr 21 and 0x3) * 16
            return ((word ushr 5 and 0xffff).toLong() shl shift)
        }
        fun cmpX0(word: Int): Long? {
            if ((word and 0xffc003ff.toInt()) != 0xf100001f.toInt()) return null
            val shift = if (word and (1 shl 22) != 0) 12 else 0
            return ((word ushr 10 and 0xfff).toLong() shl shift)
        }
        fun branchTarget(va: Long, word: Int): Long? {
            if ((word and 0xfc000000.toInt()) != 0x94000000.toInt()) return null
            var immediate = word and 0x03ffffff
            if (immediate and 0x02000000 != 0) immediate = immediate or 0xfc000000.toInt()
            return va + immediate.toLong() * 4L
        }

        val windows = (0 until verificationWindows.length()).mapNotNull { index ->
            val row = verificationWindows.optJSONObject(index) ?: return@mapNotNull null
            val start = row.optString("verificationVa").removePrefix("0x").toLongOrNull(16)
                ?: return@mapNotNull null
            val size = row.optInt("maxBytes", 1024).coerceIn(64, 0x4000)
            start to start + size
        }.distinct()
        val functionStarts = linkedSetOf<Long>()
        windows.forEach { (start, end) ->
            var va = start and -4L
            while (va + 4 <= end) {
                val word = wordAt(va) ?: break
                if (word == 0xa9bf79fd.toInt() || isArm64FramePrologue(word)) functionStarts += va
                va += 4
            }
        }
        val orderedStarts = functionStarts.sorted()
        val functions = orderedStarts.mapIndexed { index, start ->
            val windowEnd = windows.filter { start >= it.first && start < it.second }
                .minOfOrNull { it.second } ?: (start + 0x400)
            val next = orderedStarts.drop(index + 1).firstOrNull { it < windowEnd } ?: windowEnd
            RawFunction(start, next)
        }
        functions.forEach { function ->
            var lastX0: Pair<Long, Long>? = null
            var va = function.start
            while (va + 4 <= function.end) {
                val word = wordAt(va) ?: break
                movzX0(word)?.let { lastX0 = va to it }
                cmpX0(word)?.let { function.comparisons += va to it }
                branchTarget(va, word)?.let(function.calls::add)
                if (word == 0xd65f03c0.toInt()) {
                    lastX0?.takeIf { va - it.first <= 16 }?.let {
                        function.returnedValues += it.second
                        function.returnSites += va to it.second
                    }
                }
                va += 4
            }
        }
        val byStart = functions.associateBy(RawFunction::start)
        fun callPath(from: Long, target: Long, depth: Int, visited: Set<Long> = emptySet()): List<Long>? {
            if (from == target) return listOf(from)
            if (depth == 0 || from in visited) return null
            val function = byStart[from] ?: return null
            for (callee in function.calls) {
                if (callee !in byStart) continue
                val tail = callPath(callee, target, depth - 1, visited + from) ?: continue
                return listOf(from) + tail
            }
            return null
        }

        data class ValueMapping(
            val value: Long,
            val consumer: Long,
            val comparisonVa: Long,
            val labels: LinkedHashSet<String> = linkedSetOf(),
            val poolOffsets: LinkedHashSet<String> = linkedSetOf(),
        )
        val mappings = linkedMapOf<Pair<Long, Long>, ValueMapping>()
        refsByOffset.keys().forEach { offset ->
            val rows = refsByOffset.optJSONArray(offset) ?: return@forEach
            (0 until rows.length()).mapNotNull(rows::optJSONObject).forEach { row ->
                val referenceVa = row.optString("va").removePrefix("0x").toLongOrNull(16) ?: return@forEach
                val function = functions.firstOrNull { referenceVa in it.start until it.end } ?: return@forEach
                val comparison = function.comparisons.lastOrNull { (va, _) -> va < referenceVa && referenceVa - va <= 0x20 }
                    ?: return@forEach
                val mapping = mappings.getOrPut(function.start to comparison.second) {
                    ValueMapping(comparison.second, function.start, comparison.first)
                }
                poolTextByOffset[offset]?.let(mapping.labels::add)
                mapping.poolOffsets += offset
            }
        }
        val requested = requestedValues.toSet()
        val candidates = functions.asSequence()
            .filter { it.returnedValues.size >= 2 }
            .map { function ->
                val related = mappings.values.mapNotNull { mapping ->
                    val path = callPath(mapping.consumer, function.start, 3) ?: return@mapNotNull null
                    if (mapping.value !in function.returnedValues) return@mapNotNull null
                    mapping to path
                }
                val mappedValues = related.map { it.first.value }.toSet()
                val requestedMatches = function.returnedValues.filter(requested::contains)
                val score = function.returnedValues.size * 100 + mappedValues.size * 350 +
                    requestedMatches.size * 500 + related.size * 80
                Triple(function, related, score)
            }
            .filter { it.second.isNotEmpty() || requested.any(it.first.returnedValues::contains) }
            .sortedByDescending(Triple<RawFunction, List<Pair<ValueMapping, List<Long>>>, Int>::third)
            .take(limit.coerceIn(1, 20))
            .toList()
        val output = JSONArray()
        candidates.forEach { (function, related, score) ->
            val targetMappings = JSONArray()
            related.groupBy { it.first.value }.toSortedMap().forEach { (value, rows) ->
                targetMappings.put(JSONObject()
                    .put("value", value)
                    .put("labels", JSONArray(rows.flatMap { it.first.labels }.distinct()))
                    .put("poolOffsets", JSONArray(rows.flatMap { it.first.poolOffsets }.distinct()))
                    .put("comparisonVas", JSONArray(rows.map { "0x${it.first.comparisonVa.toString(16)}" }.distinct()))
                    .put("consumerFunctionVas", JSONArray(rows.map { "0x${it.first.consumer.toString(16)}" }.distinct())))
            }
            val matchedRequested = function.returnedValues.filter(requested::contains)
            val confidence = when {
                related.map { it.first.value }.distinct().size >= 2 -> "high"
                related.isNotEmpty() && matchedRequested.isNotEmpty() -> "high"
                else -> "medium"
            }
            output.put(JSONObject()
                .put("functionVa", "0x${function.start.toString(16)}")
                .put("functionEndVa", "0x${function.end.toString(16)}")
                .put("returnedValues", JSONArray(function.returnedValues.toList().sorted()))
                .put("returnSites", JSONArray(function.returnSites.map { (va, value) ->
                    JSONObject().put("va", "0x${va.toString(16)}").put("value", value)
                }))
                .put("matchedRequestedValues", JSONArray(matchedRequested))
                .put("targetMappings", targetMappings)
                .put("callChains", JSONArray(related.map { (_, path) ->
                    JSONArray(path.map { "0x${it.toString(16)}" })
                }.distinctBy(JSONArray::toString)))
                .put("score", score)
                .put("confidence", confidence)
                .put("evidenceLevel", "L3")
                .put("evidenceSource", "current_libapp_raw_arm64_decision_flow")
                .put("returnEncoding", "native")
                .apply {
                    if (matchedRequested.size == 1) put("patchHint", JSONObject()
                        .put("mode", "force_return_constant")
                        .put("value", matchedRequested.single())
                        .put("returnType", "int")
                        .put("valueEncoding", "native"))
                })
        }
        return JSONObject()
            .put("status", if (output.length() > 0) "decision_flow_found" else "not_found")
            .put("currentBytesVerified", true)
            .put("inspectedWindowCount", windows.size)
            .put("functionCount", functions.size)
            .put("candidates", output)
            .put("candidateCount", output.length())
    }

    private fun searchQueries(query: String, caseInsensitive: Boolean): List<String> =
        query.split('|').map(String::trim).filter(String::isNotEmpty)
            .distinctBy { if (caseInsensitive) it.lowercase() else it }
            .take(16)
            .map { if (caseInsensitive) it.lowercase() else it }

    fun functionValueEvidence(lines: List<String>, requestedValues: Set<Long>? = null): JSONArray {
        val evidence = JSONArray()
        lines.forEach { raw ->
            valueEvidence(raw, requestedValues)?.let(evidence::put)
        }
        return evidence
    }

    private fun valueEvidence(raw: String, requestedValues: Set<Long>?): JSONObject? {
        // B2-1 预筛：VALUE_INSTRUCTION 要求注释形态指令行 + mov/movz/movn/cmp/cmn + `#`。
        val mnemonicAt = instructionMnemonicStart(raw, requireComment = true)
        if (!anyMnemonicAt(raw, mnemonicAt, VALUE_MNEMONICS)) return null
        if (raw.indexOf('#') < 0) return null
        if (!valueInstructionM.find(raw)) return null
        val match = valueInstructionM.m
        val value = parseNumeric(match.group(3)) ?: return null
        if (requestedValues != null && value !in requestedValues) return null
        val mnemonic = match.group(2).lowercase()
        return JSONObject()
            .put("instructionVa", "0x${match.group(1).lowercase()}")
            .put("mnemonic", mnemonic)
            .put("kind", if (mnemonic == "cmp" || mnemonic == "cmn") "comparison" else "assignment")
            .put("value", value)
            .put("valueHex", signedHex(value))
            .put("text", raw.trim().take(300))
    }

    fun searchImmediateValues(
        resultDir: File,
        values: List<Long>,
        semanticHints: List<String>,
        contextClasses: List<String>,
        relevantPoolOffsets: List<Long>,
        limit: Int,
    ): JSONObject {
        data class FunctionScan(
            val file: String,
            val clazz: String?,
            val function: String?,
            val functionVa: String,
            val evidence: JSONArray = JSONArray(),
            val poolOffsets: LinkedHashSet<Long> = linkedSetOf(),
        )

        val logicalValues = values.distinct()
        val immediateMatches = linkedMapOf<Long, LinkedHashSet<Long>>()
        logicalValues.forEach { value ->
            immediateMatches.getOrPut(value) { linkedSetOf() }.add(value)
            if (value in (Long.MIN_VALUE / 2)..(Long.MAX_VALUE / 2)) {
                immediateMatches.getOrPut(value shl 1) { linkedSetOf() }.add(value)
            }
        }
        val requested = immediateMatches.keys
        val logicalValueSet = logicalValues.toSet()
        val hints = semanticHints.filter(String::isNotBlank).distinctBy(String::lowercase)
        val classes = contextClasses.filter(String::isNotBlank).toSet()
        val relevantOffsets = relevantPoolOffsets.toSet()
        val scansByVa = linkedMapOf<String, FunctionScan>()
        var excludedAddressingOffsets = 0
        val meta = forEachSemanticRow(resultDir) { row ->
            val functionVa = row.optString("functionVa").ifBlank { row.optString("va") }
            when (row.type) {
                SemanticRowFormat.TYPE_FUNCTION -> scansByVa.putIfAbsent(functionVa, FunctionScan(
                    row.optString("file"),
                    row.optString("class").takeIf(String::isNotBlank),
                    row.optString("function").takeIf(String::isNotBlank),
                    "0x$functionVa",
                ))
                SemanticRowFormat.TYPE_REFERENCE -> row.optString("offset").toLongOrNull(16)?.let { scansByVa[functionVa]?.poolOffsets?.add(it) }
                SemanticRowFormat.TYPE_IMMEDIATE -> if (row.optLong("value") in requested) {
                    val immediate = row.optLong("value")
                    val matchedValues = immediateMatches[immediate].orEmpty()
                    scansByVa[functionVa]?.evidence?.put(row.toJson().apply {
                        remove("type"); remove("functionVa"); remove("function"); remove("class"); remove("file")
                        put("requestedValues", JSONArray(matchedValues))
                        put("valueEncoding", when {
                            immediate in logicalValueSet && matchedValues.size == 1 -> "raw"
                            immediate !in logicalValueSet && matchedValues.size == 1 -> "dart_smi"
                            else -> "raw_or_dart_smi"
                        })
                    })
                }
                SemanticRowFormat.TYPE_ADDRESSING_IMMEDIATE -> if (row.optLong("value") in requested) {
                    excludedAddressingOffsets += row.optInt("count", 1)
                }
            }
        }
        val candidates = scansByVa.values.filter { it.evidence.length() > 0 }.map { scan ->
            val matchedHints = hints.filter { hint ->
                containsTerm(scan.function.orEmpty(), hint) ||
                    containsTerm(scan.clazz.orEmpty(), hint) ||
                    scan.file.contains(hint, ignoreCase = true)
            }
            val relatedOffsets = scan.poolOffsets.filter { it in relevantOffsets }
            val matchedContextClasses = classes.filter { contextClass ->
                scan.clazz == contextClass || containsTerm(scan.function.orEmpty(), contextClass)
            }
            val contextClass = matchedContextClasses.isNotEmpty()
            val kinds = (0 until scan.evidence.length()).map { scan.evidence.getJSONObject(it).getString("kind") }
            val score = (if (contextClass) 300 else 0) + matchedHints.size * 160 +
                relatedOffsets.size.coerceAtMost(3) * 120 + kinds.sumOf { if (it == "comparison") 50 else 40 }
            JSONObject()
                .put("functionVa", scan.functionVa)
                .put("function", scan.function ?: JSONObject.NULL)
                .put("class", scan.clazz ?: JSONObject.NULL)
                .put("file", scan.file)
                .put("score", score)
                .put("contextClass", contextClass)
                .put("matchedContextClasses", JSONArray(matchedContextClasses))
                .put("matchedHints", JSONArray(matchedHints))
                .put("relatedPoolOffsets", JSONArray(relatedOffsets.map { "0x${it.toString(16)}" }))
                .put("values", JSONArray((0 until scan.evidence.length()).flatMap { index ->
                    val matched = scan.evidence.getJSONObject(index).optJSONArray("requestedValues") ?: JSONArray()
                    (0 until matched.length()).map(matched::getLong)
                }.distinct()))
                .put("evidence", scan.evidence)
        }.sortedWith(compareByDescending<JSONObject> { it.optInt("score") }
            .thenBy { it.optString("functionVa") })
        val poolMatches = JSONArray()
        File(resultDir, "pp.txt").forEachLine { raw ->
            val match = POOL_INTEGER.matchEntire(raw) ?: return@forEachLine
            val value = parseNumeric(match.groupValues[3]) ?: return@forEachLine
            if (value !in logicalValueSet || poolMatches.length() >= limit) return@forEachLine
            poolMatches.put(JSONObject()
                .put("offset", "0x${match.groupValues[1].lowercase()}")
                .put("type", match.groupValues[2])
                .put("value", value)
                .put("valueHex", signedHex(value))
                .put("text", raw.trim().take(300)))
        }
        val poolOffsets = (0 until poolMatches.length()).mapNotNull { index ->
            poolMatches.optJSONObject(index)?.optString("offset")?.removePrefix("0x")?.toLongOrNull(16)
        }
        val poolValueReferences = if (poolOffsets.isEmpty()) JSONObject()
        else xrefMany(resultDir, poolOffsets, perOffsetLimit = 4)
        return JSONObject()
            .put("values", JSONArray(logicalValues))
            .put("searchedImmediateValues", JSONArray(requested))
            .put("candidates", JSONArray(candidates.take(limit)))
            .put("candidateCount", candidates.size)
            .put("poolIntegerMatches", poolMatches)
            .put("poolValueReferences", poolValueReferences)
            .put("addressingOffsetsExcluded", excludedAddressingOffsets)
            .put("scannedFiles", meta.optInt("scannedFiles"))
            .put("lookupMode", "semantic_index")
            .put("truncated", candidates.size > limit)
    }

    /**
     * 从字段键的对象池引用现场推导对象字段写入，再按“相同偏移 + 类型/文件/数值语境”
     * 反查读取者。这里不依赖业务词表、固定字段名或固定数值，可用于任意混淆后的 Dart 模型。
     */
    fun traceFieldFlow(
        resultDir: File,
        anchorReferences: Map<Long, List<Long>>,
        values: List<Long>,
        semanticHints: List<String>,
        contextClasses: List<String>,
        fileHints: List<String>,
        limit: Int,
        excludePatterns: List<String> = emptyList(),
    ): JSONObject {
        // consumers 噪声过滤：命中排除模式（对 function/class/file 全路径
        // 的不区分大小写子串匹配）的函数直接剔除，避免 pointycastle 等
        // 第三方加密库淹没业务消费方。
        val excludes = excludePatterns.map(String::trim).filter(String::isNotEmpty)
            .map(String::lowercase).distinct()

        data class FieldWrite(
            val offset: Long,
            val functionVa: Long,
            val instructionVa: Long,
            val anchorVa: Long,
            val distance: Long,
            val function: String,
            val clazz: String,
            val file: String,
            val insn: String,
        )
        data class Consumer(
            val functionVa: Long,
            val function: String,
            val clazz: String,
            val file: String,
            val offsets: LinkedHashSet<Long> = linkedSetOf(),
            val reads: JSONArray = JSONArray(),
            val values: JSONArray = JSONArray(),
            val decisionEvidence: JSONArray = JSONArray(),
        )

        val normalizedAnchors = anchorReferences
            .filterKeys { it >= 0 }
            .mapValues { (_, refs) -> refs.filter { it >= 0 }.distinct().sorted() }
            .filterValues(List<Long>::isNotEmpty)
        if (normalizedAnchors.isEmpty()) {
            return JSONObject().put("fieldWrites", JSONArray()).put("consumers", JSONArray())
                .put("reason", "ANCHOR_REFERENCE_REQUIRED")
        }
        val headers = functionHeaders(resultDir).associateBy(FunctionHeader::va)
        val writes = mutableListOf<FieldWrite>()
        val contextTypes = linkedSetOf<String>()
        contextClasses.filter(String::isNotBlank).forEach(contextTypes::add)
        forEachMemoryAccess(resultDir) { access ->
            val anchors = normalizedAnchors[access.functionVa] ?: return@forEachMemoryAccess
            val header = headers[access.functionVa] ?: return@forEachMemoryAccess
            header.name?.takeIf(String::isNotBlank)?.let { signature ->
                extractSignatureTypes(signature).forEach(contextTypes::add)
            }
            if (!access.write) return@forEachMemoryAccess
            if (access.offset <= 0 || access.offset > 0x4000) return@forEachMemoryAccess
            val anchor = anchors.lastOrNull { it <= access.instructionVa } ?: return@forEachMemoryAccess
            val distance = access.instructionVa - anchor
            if (distance > 0x180) return@forEachMemoryAccess
            writes += FieldWrite(
                access.offset, access.functionVa, access.instructionVa, anchor, distance,
                header.name.orEmpty(), header.className.orEmpty(), header.file,
                "store [x${access.baseRegister}, #0x${access.offset.toString(16)}]",
            )
        }
        val rankedWrites = writes.distinctBy { Triple(it.functionVa, it.instructionVa, it.offset) }
            .sortedWith(compareBy<FieldWrite> { it.distance }.thenBy { it.offset })
        val fieldOffsets = rankedWrites.map(FieldWrite::offset).distinct().take(24).toSet()
        if (fieldOffsets.isEmpty()) {
            return JSONObject().put("fieldWrites", JSONArray()).put("consumers", JSONArray())
                .put("reason", "NO_NEARBY_OBJECT_FIELD_WRITE")
        }

        val logicalValues = values.distinct()
        val encodedValues = linkedSetOf<Long>().apply {
            logicalValues.forEach { value ->
                add(value)
                if (value in (Long.MIN_VALUE / 2)..(Long.MAX_VALUE / 2)) add(value shl 1)
            }
        }
        val consumers = linkedMapOf<Long, Consumer>()
        val valuesByFunction = linkedMapOf<Long, JSONArray>()
        forEachMemoryAccess(resultDir) { access ->
            if (access.write || access.offset !in fieldOffsets) return@forEachMemoryAccess
            val header = headers[access.functionVa] ?: return@forEachMemoryAccess
            val consumer = consumers.getOrPut(access.functionVa) {
                Consumer(access.functionVa, header.name.orEmpty(), header.className.orEmpty(), header.file)
            }
            consumer.offsets += access.offset
            if (consumer.reads.length() < 12) consumer.reads.put(JSONObject()
                .put("instructionVa", "0x${access.instructionVa.toString(16)}")
                .put("fieldOffset", "0x${access.offset.toString(16)}")
                .put("dataRegister", "x${access.dataRegister}")
                .put("insn", "load x${access.dataRegister}, [x${access.baseRegister}, #0x${access.offset.toString(16)}]"))
        }
        forEachFieldSlice(resultDir) { sink ->
            if (sink.fieldOffset !in fieldOffsets) return@forEachFieldSlice
            val consumer = consumers[sink.functionVa] ?: return@forEachFieldSlice
            if (consumer.decisionEvidence.length() >= 24) return@forEachFieldSlice
            val matchedValues = logicalValues.filter { value ->
                sink.value != NO_SLICE_VALUE && (sink.value == value ||
                    (value in (Long.MIN_VALUE / 2)..(Long.MAX_VALUE / 2) && sink.value == value shl 1))
            }
            consumer.decisionEvidence.put(JSONObject()
                .put("sourceInstructionVa", "0x${sink.sourceVa.toString(16)}")
                .put("sinkInstructionVa", "0x${sink.sinkVa.toString(16)}")
                .put("fieldOffset", "0x${sink.fieldOffset.toString(16)}")
                .put("sourceRegister", "x${sink.sourceRegister}")
                .put("kind", fieldSliceKind(sink.kind))
                .apply {
                    if (sink.value != NO_SLICE_VALUE) {
                        put("value", sink.value)
                        put("valueHex", signedHex(sink.value))
                    }
                    if (matchedValues.isNotEmpty()) {
                        put("requestedValues", JSONArray(matchedValues))
                        put("valueEncoding", if (sink.value in matchedValues) "raw" else "dart_smi")
                    }
                })
        }
        if (encodedValues.isNotEmpty()) {
            forEachSemanticRow(resultDir) { row ->
                val functionVa = row.optString("functionVa").toLongOrNull(16) ?: return@forEachSemanticRow
                when (row.type) {
                    SemanticRowFormat.TYPE_IMMEDIATE -> if (row.optLong("value") in encodedValues) {
                        valuesByFunction.getOrPut(functionVa) { JSONArray() }.put(row.toJson().apply {
                            remove("type"); remove("functionVa"); remove("function"); remove("class"); remove("file")
                        })
                    }
                }
            }
        }
        consumers.forEach { (functionVa, consumer) ->
            val evidence = valuesByFunction[functionVa] ?: return@forEach
            (0 until evidence.length()).forEach { consumer.values.put(evidence.getJSONObject(it)) }
        }
        val hints = semanticHints.filter(String::isNotBlank).distinctBy(String::lowercase)
        val normalizedFiles = fileHints.map { it.replace('\\', '/').substringAfterLast('/').lowercase() }
            .filter(String::isNotBlank).distinct()
        val consumerRows = consumers.values.mapNotNull { consumer ->
            val signatureContext = contextTypes.filter { type ->
                containsTerm(consumer.function, type) || containsTerm(consumer.clazz, type)
            }
            val matchedHints = hints.filter { hint ->
                containsTerm(consumer.function, hint) || containsTerm(consumer.clazz, hint) ||
                    consumer.file.contains(hint, ignoreCase = true)
            }
            val matchedFiles = normalizedFiles.filter { consumer.file.lowercase().endsWith(it) }
            val decisionKinds = (0 until consumer.decisionEvidence.length()).map { index ->
                consumer.decisionEvidence.getJSONObject(index).optString("kind")
            }
            val decisionScore = decisionKinds.sumOf { kind -> when (kind) {
                "comparison" -> 220
                "direct_conditional_branch", "flags_conditional_branch" -> 260
                "boolean_result" -> 180
                "return" -> 160
                "call_argument" -> 60
                else -> 0
            } }
            val score = signatureContext.size * 300 + matchedFiles.size * 260 + matchedHints.size * 100 +
                consumer.offsets.size * 80 + consumer.reads.length() * 25 + consumer.values.length() * 180 +
                decisionScore + if (consumer.function.contains("bool", ignoreCase = true)) 60 else 0
            if (excludes.isNotEmpty()) {
                val haystack = "${consumer.function} ${consumer.clazz} ${consumer.file}".lowercase()
                if (excludes.any { haystack.contains(it) }) null
            }
            val hasDecisionSink = decisionKinds.any { it != "call_argument" }
            val confidence = when {
                decisionKinds.any { it == "direct_conditional_branch" || it == "flags_conditional_branch" } -> "high"
                hasDecisionSink -> "medium"
                else -> "low"
            }
            JSONObject()
                .put("functionVa", "0x${consumer.functionVa.toString(16)}")
                .put("function", consumer.function.ifBlank { JSONObject.NULL })
                .put("class", consumer.clazz.ifBlank { JSONObject.NULL })
                .put("file", consumer.file)
                .put("score", score)
                .put("fieldOffsets", JSONArray(consumer.offsets.map { "0x${it.toString(16)}" }))
                .put("matchedTypes", JSONArray(signatureContext))
                .put("matchedFiles", JSONArray(matchedFiles))
                .put("matchedHints", JSONArray(matchedHints))
                .put("fieldReads", consumer.reads)
                .put("valueEvidence", consumer.values)
                .put("decisionEvidence", consumer.decisionEvidence)
                .put("hasDecisionSink", hasDecisionSink)
                .put("sliceConfidence", confidence)
        }.sortedWith(compareByDescending<JSONObject> { it.optInt("score") }
            .thenBy { it.optString("functionVa") })
        val writeRows = rankedWrites.take(24).map { write -> JSONObject()
            .put("fieldOffset", "0x${write.offset.toString(16)}")
            .put("functionVa", "0x${write.functionVa.toString(16)}")
            .put("instructionVa", "0x${write.instructionVa.toString(16)}")
            .put("anchorVa", "0x${write.anchorVa.toString(16)}")
            .put("distanceBytes", write.distance)
            .put("function", write.function.ifBlank { JSONObject.NULL })
            .put("class", write.clazz.ifBlank { JSONObject.NULL })
            .put("file", write.file)
            .put("insn", write.insn)
        }
        return JSONObject()
            .put("fieldWrites", JSONArray(writeRows))
            .put("fieldOffsets", JSONArray(fieldOffsets.map { "0x${it.toString(16)}" }))
            .put("inferredTypes", JSONArray(contextTypes))
            .put("consumers", JSONArray(consumerRows.take(limit)))
            .put("consumerCount", consumerRows.size)
            .put("consumerClusters", run {
                val byDir = LinkedHashMap<String, Int>()
                for (row in consumerRows) {
                    val f = row.optString("file")
                    val dirKey = f.substringBeforeLast('/', f).ifBlank { f }
                    byDir[dirKey] = (byDir[dirKey] ?: 0) + 1
                }
                JSONArray(byDir.entries.sortedByDescending { it.value }
                    .take(8)
                    .map { JSONObject().put("dir", it.key).put("count", it.value) })
            })
            .put("excludedConsumers", excludes.size)
            .put("truncated", consumerRows.size > limit)
            .put("lookupMode", "semantic_field_data_flow_with_register_slice")
            .put("sliceWindowInstructions", FIELD_SLICE_WINDOW)
    }

    private fun extractSignatureTypes(signature: String): List<String> {
        val ignored = setOf("static", "dynamic", "void", "bool", "int", "double", "string", "object", "closure")
        val tokens = Regex("[A-Za-z_$][A-Za-z0-9_$]*")
            .findAll(signature.substringBefore('('))
            .map(MatchResult::value)
            .toList()
            .dropLast(1)
        return tokens.asSequence()
            .filter { it.lowercase() !in ignored && (it.firstOrNull()?.isUpperCase() == true || it.any(Char::isUpperCase)) }
            .distinct()
            .toList()
    }

    private fun parseNumeric(raw: String): Long? {
        val text = raw.trim().lowercase()
        return when {
            text.startsWith("-0x") -> text.removePrefix("-0x").toLongOrNull(16)?.let { -it }
            text.startsWith("0x") -> text.removePrefix("0x").toLongOrNull(16)
            else -> text.toLongOrNull()
        }
    }

    private fun signedHex(value: Long): String = if (value < 0) "-0x${(-value).toString(16)}" else "0x${value.toString(16)}"

    fun xref(resultDir: File, poolOffset: Long, limit: Int): JSONObject {
        val asmDir = File(resultDir, "asm")
        val target = poolOffset.toString(16)
        val addressMap = addressMap(resultDir)
        val refs = JSONArray()
        var truncated = false
        var scanned = 0
        asmDir.walkTopDown().filter { it.isFile && it.extension == "dart" }.forEach { file ->
            if (truncated) return@forEach
            val rel = "asm/${file.relativeTo(asmDir).path}"
            var currentClass: String? = null
            var currentFunction: String? = null
            var currentFunctionVa: String? = null
            var pendingSignature: String? = null
            file.useLines { lines ->
                lines.forEach { raw ->
                    val trimmed = raw.trim()
                    if (trimmed.startsWith("class ")) currentClass = className(trimmed)
                    FUNC_ADDR.matchEntire(raw)?.let { header ->
                        currentFunction = pendingSignature
                        currentFunctionVa = "0x${header.groupValues[1].lowercase()}"
                    } ?: run {
                        if (raw.startsWith("  ") && !trimmed.startsWith("//") && trimmed.isNotEmpty()) {
                            pendingSignature = trimmed.trimEnd('{', ' ', ';')
                        }
                    }
                    val hit = REF.findAll(raw).firstOrNull { it.groupValues[1].lowercase() == target } ?: return@forEach
                    if (refs.length() >= limit) { truncated = true; return@forEach }
                    val instructionVa = INSN_ADDR.find(raw)?.groupValues?.get(1)?.toLongOrNull(16)
                    val functionVa = currentFunctionVa?.removePrefix("0x")?.toLongOrNull(16)
                    val va = instructionVa ?: functionVa
                    val fileOffset = va?.let(addressMap::fileOffset)
                    refs.put(JSONObject()
                        .put("va", va?.let { "0x${it.toString(16)}" } ?: currentFunctionVa ?: JSONObject.NULL)
                        .put("elfVa", va?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                        .put("fileOffset", fileOffset?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                        .put("patchLocator", va?.let { "0x${it.toString(16)}" } ?: currentFunctionVa ?: JSONObject.NULL)
                        .put("function", currentFunction ?: JSONObject.NULL)
                        .put("class", currentClass ?: JSONObject.NULL)
                        .put("file", rel)
                        .put("insn", trimmed.take(300))
                        .put("poolEntry", hit.value))
                }
            }
            scanned++
        }
        return JSONObject().put("refs", refs).put("count", refs.length()).put("scannedFiles", scanned).put("truncated", truncated).put("addressMapping", addressMap.status)
    }

    /** 多个池偏移共用一次 asm 扫描，避免每个候选都重复遍历巨大反汇编目录。 */
    fun xrefMany(resultDir: File, poolOffsets: List<Long>, perOffsetLimit: Int): JSONObject {
        val targets = poolOffsets.associateBy { it.toString(16) }
        val refsByOffset = targets.keys.associateWith { JSONArray() }.toMutableMap()
        // C2（阶段 0）：截断可见化——每个 offset 收集满 perOffsetLimit 后，后续
        // 命中不再静默丢弃：truncatedHits 记录被截断的命中数（下界），返回带
        // perOffsetTruncated / truncatedTotal，调用方据此知道证据被截。
        val truncatedHits = targets.keys.associateWith { 0 }.toMutableMap()
        val addressMap = addressMap(resultDir)
        val functionHeaders = functionHeaders(resultDir).sortedBy(FunctionHeader::va)
        val rawIndexAvailable = File(resultDir, ARM64_POOL_INDEX_V2).isFile || File(resultDir, ARM64_POOL_INDEX).isFile || File(resultDir, ARM64_CLOSURE_CALL_INDEX).isFile
        if (rawIndexAvailable) {
            val nativeFunctions = arm64Functions(resultDir)
            forEachRawClosureCall(resultDir) { row ->
                val offsetKey = row.poolOffset.toString(16)
                val rows = refsByOffset[offsetKey] ?: return@forEachRawClosureCall
                if (rows.length() >= perOffsetLimit) {
                    if (truncatedHits.containsKey(offsetKey)) truncatedHits[offsetKey] = truncatedHits[offsetKey]!! + 1
                    return@forEachRawClosureCall
                }
                val boundary = resolveBoundary(functionHeaders, row.loadVa)
                val verifiedBlutterFunction = boundary.header
                val nativeFunction = longAtOrBefore(nativeFunctions, row.loadVa)
                val nextNativeFunction = longAfter(nativeFunctions, row.loadVa)
                rows.put(JSONObject()
                    .put("va", "0x${row.loadVa.toString(16)}")
                    .put("verificationVa", "0x${row.loadVa.toString(16)}")
                    .put("functionVa", verifiedBlutterFunction?.va?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("fileOffset", (addressMap.fileOffset(row.loadVa) ?: row.loadFileOffset.toLong()).let { "0x${it.toString(16)}" })
                    .put("function", verifiedBlutterFunction?.name ?: JSONObject.NULL)
                    .put("class", verifiedBlutterFunction?.className ?: JSONObject.NULL)
                    .put("file", verifiedBlutterFunction?.file ?: "libapp.so")
                    .put("functionEvidence", if (boundary.status == "verified") "blutter_function_range_verified" else "raw_reference_requires_native_boundary")
                    .put("boundaryStatus", boundary.status)
                    .put("boundaryBasis", boundary.basis ?: JSONObject.NULL)
                    .put("artifactFunctionHint", verifiedBlutterFunction?.let { JSONObject()
                        .put("addr", "0x${it.va.toString(16)}")
                        .put("size", boundary.size?.let { size -> "0x${size.toString(16)}" } ?: JSONObject.NULL)
                        .put("name", it.name ?: JSONObject.NULL)
                        .put("class", it.className ?: JSONObject.NULL)
                        .put("file", it.file) } ?: JSONObject.NULL)
                    .put("nativeFunctionHint", nativeFunction?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("nextFunctionVa", nextNativeFunction?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("insn", if (row.mode == 4) "ldp xN, xM, [x27, #imm]; blr x${row.targetRegister}（闭包+代码对的寄存器间接调用）" else "add xN, x27, #hi; ldp xM, xK, [xN, #imm]; blr x${row.targetRegister}（闭包+代码对的寄存器间接调用）")
                    .put("referenceMode", if (row.mode == 4) "arm64_raw_ldp_pp_blr" else "arm64_raw_add_ldp_pp_blr")
                    .put("indirectCall", true)
                    .put("callVa", "0x${row.callVa.toString(16)}")
                    .put("callFileOffset", "0x${row.callFileOffset.toString(16)}")
                    .put("callRegister", "x${row.targetRegister}"))
            }
            forEachRawPoolReference(resultDir) { row ->
                val offsetKey = row.poolOffset.toString(16)
                val rows = refsByOffset[offsetKey] ?: return@forEachRawPoolReference
                if (rows.length() >= perOffsetLimit) {
                    if (truncatedHits.containsKey(offsetKey)) truncatedHits[offsetKey] = truncatedHits[offsetKey]!! + 1
                    return@forEachRawPoolReference
                }
                val va = row.va
                val boundary = resolveBoundary(functionHeaders, va)
                val verifiedBlutterFunction = boundary.header
                val nativeFunction = longAtOrBefore(nativeFunctions, va)
                val nextNativeFunction = longAfter(nativeFunctions, va)
                val rawFileOffset = row.fileOffset.toLong()
                rows.put(JSONObject()
                    .put("va", "0x${va.toString(16)}")
                    .put("verificationVa", "0x${va.toString(16)}")
                    .put("functionVa", verifiedBlutterFunction?.va?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("fileOffset", (addressMap.fileOffset(va) ?: rawFileOffset)?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("function", verifiedBlutterFunction?.name ?: JSONObject.NULL)
                    .put("class", verifiedBlutterFunction?.className ?: JSONObject.NULL)
                    .put("file", verifiedBlutterFunction?.file ?: "libapp.so")
                    .put("functionEvidence", if (boundary.status == "verified") "blutter_function_range_verified" else "raw_reference_requires_native_boundary")
                    .put("boundaryStatus", boundary.status)
                    .put("boundaryBasis", boundary.basis ?: JSONObject.NULL)
                    .put("artifactFunctionHint", verifiedBlutterFunction?.let { JSONObject()
                        .put("addr", "0x${it.va.toString(16)}")
                        .put("size", boundary.size?.let { size -> "0x${size.toString(16)}" } ?: JSONObject.NULL)
                        .put("name", it.name ?: JSONObject.NULL)
                        .put("class", it.className ?: JSONObject.NULL)
                        .put("file", it.file) } ?: JSONObject.NULL)
                    .put("nativeFunctionHint", nativeFunction?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("nextFunctionVa", nextNativeFunction?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("insn", when (row.mode) {
                        "arm64_raw_ldr_pp" -> "ldr xN, [x27, #imm]（单指令池寻址，PPTool 同源路径）"
                        "arm64_raw_ldp_pp" -> "ldp xN, xM, [x27, #imm]（闭包+代码对成对池加载）"
                        "arm64_raw_add_ldp_pp" -> "add xN, x27, #hi; ldp xM, xK, [xN, #imm]（闭包+代码对成对池加载）"
                        "arm64_raw_add_add_ldr" -> "add xN,x27,#hi; add xM,xN,#lo; ldr [xM,#imm]（双 add 拆分）"
                        else -> "add xN, x27, #hi; ldr [xN, #imm]（add+ldr 池寻址）"
                    })
                    .put("referenceMode", row.mode))
            }
        }
        val missingSemanticTargets = refsByOffset.filterValues { it.length() == 0 }.keys
        // fallback 统一流式语义索引：ensureSemanticIndex 已把所有 asm 注解引用
        // (asm_annotation) 与 add+ldr 池寻址 (arm64_add_ldr_fallback) 写入索引,
        // 与 walkTopDown + useLines 全量扫描 asm 目录等价, 但避免 2700+ 文件
        // 重复遍历 (单次 locate 节省数十秒)。语义索引不存在时由 ensureSemanticIndex
        // 一次性构建并持久化, 后续命中 cache。
        var fallbackScannedRows = 0
        if (missingSemanticTargets.isNotEmpty()) {
            // v5 瘦身：reference 行不再内嵌 function/class/file，按 functionVa 反查。
            val orderedHeaders = functionHeaders(resultDir)
            val headersByVa = HashMap<Long, FunctionHeader>()
            orderedHeaders.forEach { headersByVa[it.va] = it }
            forEachSemanticRow(resultDir) { row ->
                fallbackScannedRows++
                if (row.type != SemanticRowFormat.TYPE_REFERENCE) return@forEachSemanticRow
                val offset = row.optString("offset")
                if (offset !in missingSemanticTargets) return@forEachSemanticRow
                val rows = refsByOffset[offset] ?: return@forEachSemanticRow
                if (rows.length() >= perOffsetLimit) {
                    if (truncatedHits.containsKey(offset)) truncatedHits[offset] = truncatedHits[offset]!! + 1
                    return@forEachSemanticRow
                }
                val va = row.optString("va").toLongOrNull(16)
                val annotatedVa = row.optString("functionVa").toLongOrNull(16)
                // boundaryStatus 在全通路只有一个含义：产物 size 是否自证了边界。
                // 语义索引的 functionVa 来自 asm 函数体内部走文本时记下的归属
                // （引用指令物理上就落在那个函数体里），它是**选取**函数头的依据，
                // 不改变边界的证据等级——否则同一状态在两条通路上意味着两件事，
                // 调用方按 boundaryStatus 判断就会踩空。
                val resolvedBoundary = va?.let { resolveBoundary(orderedHeaders, it) }
                val header = resolvedBoundary?.header ?: annotatedVa?.let { headersByVa[it] }
                val boundaryStatus = when {
                    header == null -> "unverified"
                    resolvedBoundary?.status == "inferred_next_header" -> "inferred_next_header"
                    else -> "verified"
                }
                val boundaryBasis = when {
                    header == null -> null
                    resolvedBoundary?.basis != null -> resolvedBoundary.basis
                    annotatedVa != null && resolvedBoundary?.header == null -> "asm_body_membership"
                    else -> null
                }
                rows.put(JSONObject()
                    .put("va", va?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("functionVa", header?.va?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("fileOffset", va?.let(addressMap::fileOffset)?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("function", header?.name ?: JSONObject.NULL)
                    .put("class", header?.className ?: JSONObject.NULL)
                    .put("file", header?.file.orEmpty())
                    .put("functionEvidence", if (boundaryStatus == "verified") "blutter_function_range_verified" else "raw_reference_requires_native_boundary")
                    .put("boundaryStatus", boundaryStatus)
                    .put("boundaryBasis", boundaryBasis ?: JSONObject.NULL)
                    .put("insn", row.optString("insn"))
                    .put("referenceMode", row.optString("referenceMode")))
            }
        }
        val result = JSONObject()
        refsByOffset.forEach { (offset, refs) -> result.put("0x$offset", refs) }
        // C2：per-offset 截断可见化（truncatedHits 是超限后被跳过命中的下界计数，
        // 非 0 即该 offset 的证据被截，调用方应提示用户或提高 perOffsetLimit）。
        val truncatedSummary = JSONObject()
        truncatedHits.forEach { (offset, n) -> if (n > 0) truncatedSummary.put("0x$offset", n) }
        // 边界证据分级汇总：verified=产物函数头带 size 且在范围内；
        // inferred_next_header=产物没带 size，用下一个函数头推出区间（有据推断，
        // 但不是产物自证）；unverified=连所属函数头都没有，functionVa 必为 null，
        // 依赖边界的下一步（trace/locate）不成立——调用方看到计数就知道该不该继续。
        val boundaryCounts = linkedMapOf<String, Int>()
        for (refs in refsByOffset.values) {
            for (index in 0 until refs.length()) {
                val ref = refs.optJSONObject(index) ?: continue
                // 只统计显式声明了的行：缺字段（旧产物）按"未声明"处理，
                // 不当成 unverified，否则汇总会虚报边界不可用。
                val status = ref.optString("boundaryStatus")
                if (status.isBlank()) continue
                boundaryCounts[status] = (boundaryCounts[status] ?: 0) + 1
            }
        }
        val unverifiedRefs = boundaryCounts["unverified"] ?: 0
        return JSONObject()
            .put("refsByOffset", result)
            .put("scannedFiles", fallbackScannedRows)
            .put("perOffsetLimit", perOffsetLimit)
            .put("perOffsetTruncated", truncatedSummary)
            .put("truncatedTotal", truncatedSummary.length())
            .put("truncatedHint", if (truncatedSummary.length() > 0)
                "${truncatedSummary.length()} 个池偏移的引用被 perOffsetLimit=$perOffsetLimit 截断（每个偏移丢 ${truncatedSummary.keys().asSequence().joinToString(",") { "0x$it:${truncatedSummary.optInt(it)}" }} 条以上）；热字符串引用数被低估，函数排名基于截断集合。需要完整证据请提高 perOffsetLimit 或对该偏移单独 xref()" else "")
            .put("boundarySummary", JSONObject(boundaryCounts as Map<*, *>))
            .put("boundaryHint", if (unverifiedRefs > 0)
                "$unverifiedRefs 条引用的所属函数边界不可用（functionVa=null，连函数头都没匹配上）。这些行只能用 va/verificationVa 走原始反汇编（so_analyze action=disasm），不要拿它们做 trace/locate 的锚点。" else "")
            .put("lookupMode", when {
                rawIndexAvailable && missingSemanticTargets.isEmpty() -> "compact_pool_index"
                rawIndexAvailable -> "compact_pool_index_with_semantic_fallback"
                else -> "semantic_index"
            })
            .put("addressMapping", addressMap.status)
    }

    private fun functionAtOrBefore(headers: List<FunctionHeader>, va: Long): FunctionHeader? {
        val found = headers.binarySearchBy(va, selector = FunctionHeader::va)
        val index = if (found >= 0) found else -found - 2
        return headers.getOrNull(index)
    }

    /**
     * 解析某个 VA 所属的函数边界，并把"边界是哪种证据得来的"讲清楚。
     *
     * 背景（2026-09-21 真机复盘）：Dart 版本回退 runner 产出的 asm 函数头不带
     * size（rawSize 以 "-" 开头，见 functionHeaders 的解析）。旧实现只认
     * `size > 0 && va in [va, va+size)`，于是回退模式下**每一个**引用都被判
     * unverified，functionVa 直接回 null；而 blutterReferenceAnchors 只认
     * functionVa，于是 trace/locate 一律 ANCHOR_REFERENCE_REQUIRED。
     * 一个根因，两个症状，都不是"锚点指令形态不认"。
     *
     * size 缺失时并非无据可依：asm 里下一个函数头就是本次函数体的终点（反汇编
     * 器按此切分，disasmFunction 也是这么走 body 的），因此
     * [header.va, nextHeader.va) 是一个有据的推断边界。降级的是**标签**，不是能力。
     */
    private fun resolveBoundary(headers: List<FunctionHeader>, va: Long): BoundaryResolution {
        val found = headers.binarySearchBy(va, selector = FunctionHeader::va)
        val index = if (found >= 0) found else -found - 2
        val header = headers.getOrNull(index)
        if (header == null || va < header.va) return BoundaryResolution(null, "unverified", null, null)
        if (header.size > 0) {
            return if (va < header.va + header.size) {
                BoundaryResolution(header, "verified", header.size, null)
            } else {
                BoundaryResolution(null, "unverified", null, null)
            }
        }
        val next = headers.getOrNull(index + 1)
        val inferredSize = next?.va?.takeIf { it > header.va }?.minus(header.va)
            ?: return BoundaryResolution(header, "unverified", null, null)
        return if (va < header.va + inferredSize) {
            BoundaryResolution(header, "inferred_next_header", inferredSize, "artifact_function_size_absent_derived_from_next_header")
        } else {
            BoundaryResolution(null, "unverified", null, null)
        }
    }

    private data class BoundaryResolution(
        val header: FunctionHeader?,
        val status: String,
        val size: Long?,
        val basis: String?,
    )

    private fun longAtOrBefore(values: List<Long>, va: Long): Long? {
        val found = values.binarySearch(va)
        val index = if (found >= 0) found else -found - 2
        return values.getOrNull(index)
    }

    private fun longAfter(values: List<Long>, va: Long): Long? {
        val found = values.binarySearch(va)
        val index = if (found >= 0) found + 1 else -found - 1
        return values.getOrNull(index)
    }

    /**
     * 按 VA 读取 blutter asm 中所属函数的完整反汇编体（含 [pp+0x...] 内联注释）。
     * 官方工作流核心一步：xref 拿到函数 VA 后读 asm 树下的函数文件，每条 ldr x?, [x27, #off]
     * 后的池对象注释（String:"is_vip" 等）直接可见，无需盲猜指令语义。
     * 命中规则：优先取 addr <= va < addr+size 的函数头；无精确命中时回退到
     * addr <= va 的最近函数头（matchMode=nearest）。
     */
    fun disasmFunction(
        resultDir: File,
        va: Long,
        maxLines: Int,
        lineOffset: Int = 0,
        vaUntil: Long = 0,
    ): JSONObject {
        // vaUntil>0：只输出 VA < vaUntil 的行（大函数按分支/判定区间取窗口），
        // 行数预算仍受 maxLines 约束。

        val asmDir = File(resultDir, "asm")
        var exact: FunctionHit? = null
        var nearest: FunctionHit? = null
        // 函数头走小体积缓存（列表仅几千条），避免每次 disasm 都流式全扫语义索引。
        // size 信息在索引的 function 行里，缓存结构需带 size。
        forEachFunctionHeaderRow(resultDir) { addr, size, name, className, file ->
            val hit = FunctionHit(addr, size, name, className, file)
            if (size > 0 && va >= addr && va < addr + size) exact = hit
            if (addr <= va && (nearest == null || addr > nearest!!.addr)) nearest = hit
        }
        var hit = exact
        if (hit == null) hit = nearest
        if (hit == null) {
            return JSONObject()
                .put("found", false)
                .put("reason", "VA_NOT_IN_ASM")
                .put("hint", "blutter 未还原该地址所在函数（可能是桩/未分析区域）。改用 so_analyze(action=disasm, addr=...) 看裸反汇编。")
        }
        // 二次读取：函数头行 → 下一个函数头（或文件尾）。
        // 流式读取：原先 readLines() 把整个 asm 文件读进内存只为切出一个
        // 函数体（asm 单文件可达数 MB）；收集到 maxLines 行后多看一行即可
        // 判定截断，无需读全文件。
        val targetFile = File(asmDir, hit.file.removePrefix("asm/"))
        val body = mutableListOf<String>()
        var headerFound = false
        var truncated = false
        var minInstructionVa: Long? = null
        var maxInstructionVa: Long? = null
        var requestedVaObserved = false
        var totalInstructionCount = 0
        // lineCount = 函数总行数（含截断后的未返回部分，只计数不驻留内存）。
        var totalLines = 0
        targetFile.useLines { seq ->
            for (raw in seq) {
                if (!headerFound) {
                    val m = FUNC_ADDR.matchEntire(raw)
                    if (m != null && m.groupValues[1].toLongOrNull(16) == hit.addr) {
                        headerFound = true
                        totalLines = 1
                        if (lineOffset == 0) body += raw
                    }
                    continue
                }
                if (FUNC_ADDR.matchEntire(raw) != null) break // 下一个函数头：函数体结束
                totalLines++
                val lineVa = INSN_VA.find(raw)?.groupValues?.get(1)?.toLongOrNull(16)
                if (lineVa != null) {
                    minInstructionVa = minInstructionVa?.let { minOf(it, lineVa) } ?: lineVa
                    maxInstructionVa = maxInstructionVa?.let { maxOf(it, lineVa) } ?: lineVa
                    requestedVaObserved = requestedVaObserved || lineVa == va
                    totalInstructionCount++
                }
                if (vaUntil > va) {
                    if (lineVa != null && lineVa >= vaUntil) {
                        truncated = true
                        break
                    }
                }
                if (totalLines > lineOffset && body.size < maxLines) {
                    body += raw
                } else if (totalLines > lineOffset) {
                    truncated = true // 已满 maxLines 行仍未到函数尾
                }
            }
        }
        if (!headerFound) return JSONObject().put("found", false).put("reason", "HEADER_LINE_NOT_FOUND")
        val returnedInstructionCount = body.count { Regex("//\\s*0x[0-9a-fA-F]+:").containsMatchIn(it) }
        val observedStart = minInstructionVa
        val observedEnd = maxInstructionVa?.plus(4)
        // 边界成立与否，看的是"指令体自己作不作证"，不是产物里有没有 size 字段：
        // 从 hit.addr 逐行走到下一个函数头，如果请求的 VA 就出现在这段指令流里，
        // 那它属于本函数是**被反汇编体直接证实**的（回退 runner 不写 size 时
        // 旧实现一律拒绝，把唯一可用的证据也丢了）。
        val bodyProvesMembership = totalInstructionCount > 0 && requestedVaObserved
        if (!bodyProvesMembership) {
            val reason = when {
                totalInstructionCount == 0 -> "FUNCTION_BODY_UNAVAILABLE"
                hit.size <= 0 || exact == null -> "FUNCTION_BOUNDARY_UNVERIFIED"
                else -> "VA_NOT_IN_FUNCTION_BODY"
            }
            return JSONObject()
                .put("found", false)
                .put("usable", false)
                .put("reason", reason)
                .put("va", "0x${va.toString(16)}")
                .put("rawDisasmRequired", true)
                .put("rawDisasmVa", "0x${va.toString(16)}")
                .put("observedRange", if (observedStart != null && observedEnd != null) JSONObject().put("startAddr", "0x${observedStart.toString(16)}").put("endAddr", "0x${observedEnd.toString(16)}") else JSONObject.NULL)
                .put("function", JSONObject()
                    .put("addr", "0x${hit.addr.toString(16)}")
                    .put("size", if (hit.size > 0) "0x${hit.size.toString(16)}" else JSONObject.NULL)
                    .put("name", hit.name ?: JSONObject.NULL)
                    .put("class", hit.className ?: JSONObject.NULL)
                    .put("file", hit.file))
                .put("hint", if (reason == "VA_NOT_IN_FUNCTION_BODY")
                    "该 VA 不在所匹配函数体的指令流中（可能传错了函数或桩区域）。用返回的 observedRange 判断真实范围，或对该 VA 直接 so_analyze(action=disasm)。"
                    else "Blutter 函数边界未被指令体证实。请从该字符串引用指令 VA 做原生反汇编，不要把该函数头或大小当补丁边界。")
        }
        // 条件分支检测：会员判断最常见载体（tbnz/tbz/b.cond/cbz/cbnz）。
        // 写状态/void 函数不能 force_return_constant，分支改写是首选手法。
        val condBranchRe = Regex("\\b(tbnz|tbz|b\\.(eq|ne|gt|lt|ge|le|hi|lo|hs|ls)|cbz|cbnz)\\b", RegexOption.IGNORE_CASE)
        val rawCondBranchLines = body.withIndex().filter { condBranchRe.containsMatchIn(it.value) }
        val guardMarkers = listOf("CheckStackOverflow", "BoxInt64Instr", "AllocateMint", "RangeError", "NullError")
        val condBranchLines = rawCondBranchLines.filter { indexed ->
            body.subList(maxOf(0, indexed.index - 5), indexed.index + 1)
                .none { line -> guardMarkers.any(line::contains) }
        }.map { it.value }
        val patchHint = if (condBranchLines.isEmpty()) {
            "函数体无业务条件分支；栈检查、装箱和运行时保护分支已排除。先确认返回值确属目标状态/等级；只有返回类型和目标常量都明确时，才用 force_return_constant dryRun。"
        } else {
            "检测到 ${condBranchLines.size} 条非运行时保护条件分支。逐条确认比较值和成功分支后才能 dryRun；禁止仅凭分支数量直接 nop 或改跳转。"
        }
        val hasMore = totalLines > lineOffset + body.size
        return JSONObject()
            .put("found", true)
            .put("usable", true)
            .put("lookupMode", "compact_function_index")
            .put("matchMode", "exact")
            // 边界证据来源显式化：产物自带 size 才算"产物+指令双重证实"；
            // size 缺失时结论由指令体自证（VA 出现在 hit.addr 起的指令流中），
            // 仍然是硬证据，只是不再冒称产物提供了边界。
            .put("boundaryConfidence", if (hit.size > 0) "artifact_and_instruction_verified" else "instruction_body_verified")
            .put("boundaryBasis", if (hit.size > 0) "artifact_function_size" else "observed_instruction_body")
            .put("functionSizeAbsent", hit.size <= 0)
            .put("va", "0x" + va.toString(16))
            .put("function", JSONObject()
                .put("addr", "0x" + hit.addr.toString(16))
                .put("size", "0x" + hit.size.toString(16))
                .put("name", hit.name ?: JSONObject.NULL)
                .put("class", hit.className ?: JSONObject.NULL)
                .put("file", hit.file))
            .put("lines", JSONArray(body))
            .put("lineCount", totalLines)
            .put("returnedLines", body.size)
            .put("offset", lineOffset)
            .put("hasMore", hasMore)
            .put("nextOffset", if (hasMore) lineOffset + body.size else JSONObject.NULL)
            .put("instructionCount", totalInstructionCount)
            .put("returnedInstructionCount", returnedInstructionCount)
            .put("truncated", truncated || lineOffset > 0)
            .put("hasBusinessConditionalBranch", condBranchLines.isNotEmpty())
            .put("businessConditionalBranchCount", condBranchLines.size)
            .put("ignoredGuardBranchCount", rawCondBranchLines.size - condBranchLines.size)
            .put("poolHint", "lines 中 [pp+0x...] 是 x27 对象池引用注释（String:\"...\"/Object 等），即该指令加载的 Dart 对象；修改判断逻辑前先读完整个函数体。")
            .put("patchHint", patchHint)
    }

    private data class FunctionHit(val addr: Long, val size: Long, val name: String?, val className: String?, val file: String)

    /**
     * 反向引用（函数 → 调用者）：扫全部 asm，找 bl / 尾调用 b 直接跳转到目标 VA 的调用点。
     * 与 xref（池偏移 → 引用指令）互为反向：xref 答"这个字符串/对象被谁用"，
     * callers 答"这个函数被谁调"。补丁后验证影响面 / 逆向追调用链均用它一次拿全。
     */
    fun callersOf(resultDir: File, va: Long, limit: Int, poolOffsets: List<Long> = emptyList()): JSONObject {
        val asmDir = File(resultDir, "asm")
        val target = va.toString(16)
        val callers = JSONArray()
        var truncated = false
        var scanned = 0
        asmDir.walkTopDown().filter { it.isFile && it.extension == "dart" }.forEach { file ->
            if (truncated) return@forEach
            val rel = "asm/${file.relativeTo(asmDir).path}"
            var currentClass: String? = null
            var currentFunction: String? = null
            var currentFunctionVa: String? = null
            var pendingSignature: String? = null
            file.useLines { lines ->
                lines.forEach { raw ->
                    val trimmed = raw.trim()
                    if (trimmed.startsWith("class ")) currentClass = className(trimmed)
                    FUNC_ADDR.matchEntire(raw)?.let { header ->
                        currentFunction = pendingSignature
                        currentFunctionVa = "0x${header.groupValues[1].lowercase()}"
                    } ?: run {
                        if (raw.startsWith("  ") && !trimmed.startsWith("//") && trimmed.isNotEmpty()) {
                            pendingSignature = trimmed.trimEnd('{', ' ', ';')
                        }
                    }
                    // 行级预筛：bl/b 目标为 target 的行必然包含该 hex 子串（超集安全），
                    // 数千万行只对极少数候选行跑正则
                    if (!raw.contains(target, ignoreCase = true)) return@forEach
                    val hit = CALL_TARGET_RE.findAll(raw).firstOrNull { it.groupValues[2].lowercase() == target } ?: return@forEach
                    if (callers.length() >= limit) { truncated = true; return@forEach }
                    val callVa = INSN_ADDR.find(raw)?.groupValues?.get(1)?.toLongOrNull(16)
                    callers.put(JSONObject()
                        .put("callVa", callVa?.let { "0x${it.toString(16)}" } ?: currentFunctionVa ?: JSONObject.NULL)
                        .put("functionVa", currentFunctionVa ?: JSONObject.NULL)
                        .put("function", currentFunction ?: JSONObject.NULL)
                        .put("class", currentClass ?: JSONObject.NULL)
                        .put("file", rel)
                        .put("insn", trimmed.take(300))
                        .put("callType", "direct"))
                }
            }
            scanned++
        }
        val directCount = callers.length()
        val inferredPoolOffsets = closurePoolOffsetsForCodeVa(resultDir, va)
        val closurePoolOffsets = (poolOffsets + inferredPoolOffsets).distinct()
        if (!truncated && closurePoolOffsets.isNotEmpty()) {
            val closureTargets = closurePoolOffsets.toSet()
            val headers = functionHeaders(resultDir).sortedBy(FunctionHeader::va)
            val nativeFunctions = arm64Functions(resultDir)
            val addressMap = addressMap(resultDir)
            forEachRawClosureCall(resultDir) { row ->
                if (truncated || row.poolOffset !in closureTargets) return@forEachRawClosureCall
                if (callers.length() >= limit) {
                    truncated = true
                    return@forEachRawClosureCall
                }
                val blutterFunction = functionAtOrBefore(headers, row.loadVa)
                val nativeFunction = longAtOrBefore(nativeFunctions, row.loadVa)
                val functionVa = blutterFunction?.va ?: nativeFunction
                callers.put(JSONObject()
                    .put("callVa", "0x${row.callVa.toString(16)}")
                    .put("functionVa", functionVa?.let { "0x${it.toString(16)}" } ?: JSONObject.NULL)
                    .put("function", blutterFunction?.name ?: JSONObject.NULL)
                    .put("class", blutterFunction?.className ?: JSONObject.NULL)
                    .put("file", blutterFunction?.file ?: "libapp.so")
                    .put("fileOffset", (addressMap.fileOffset(row.callVa) ?: row.callFileOffset.toLong()).let { "0x${it.toString(16)}" })
                    .put("poolOffset", "0x${row.poolOffset.toString(16)}")
                    .put("insn", "blr x${row.targetRegister}（对象池闭包代码间接调用）")
                    .put("callType", "closure_indirect")
                    .put("referenceMode", if (row.mode == 4) "arm64_raw_ldp_pp_blr" else "arm64_raw_add_ldp_pp_blr"))
            }
        }
        return JSONObject()
            .put("callers", callers)
            .put("count", callers.length())
            .put("directCallersCount", directCount)
            .put("indirectClosureCallersCount", callers.length() - directCount)
            .put("closurePoolOffsets", JSONArray(closurePoolOffsets.map { "0x${it.toString(16)}" }))
            .put("closurePoolOffsetSource", when {
                poolOffsets.isNotEmpty() && inferredPoolOffsets.isNotEmpty() -> "explicit_and_pp_code_entry"
                poolOffsets.isNotEmpty() -> "explicit"
                inferredPoolOffsets.isNotEmpty() -> "pp_code_entry"
                else -> "none"
            })
            .put("scannedFiles", scanned)
            .put("truncated", truncated)
    }

    private fun closurePoolOffsetsForCodeVa(resultDir: File, va: Long): List<Long> {
        val needle = "0x${va.toString(16)}"
        val offsets = linkedSetOf<Long>()
        forEachPpLine(resultDir) { line ->
            if (line.contains(needle, ignoreCase = true)) {
                PP_OFFSET.find(line)?.groupValues?.getOrNull(1)?.toLongOrNull(16)?.let(offsets::add)
            }
            true
        }
        return offsets.toList()
    }

    private data class PpCandidate(
        val offset: String,
        val text: String,
        val matchedTerms: List<String>,
        val score: Int,
    )

    private data class FunctionHeader(val va: Long, val size: Long, val name: String?, val className: String?, val file: String)

    private data class CodeRange(val fileOffset: Int, val fileEnd: Int, val virtualAddress: Long)

    private fun arm64Functions(resultDir: File): List<Long> {
        val index = File(resultDir, ARM64_FUNCTION_INDEX)
        if (!index.isFile) return emptyList()
        val key = Arm64FunctionsCacheKey(index.absoluteFile.normalize().path, index.lastModified(), index.length())
        synchronized(this) { arm64FunctionsCache[key]?.let { return it } }
        val functions = index.useLines { lines -> lines.mapNotNull { runCatching { JSONObject(it).optString("va").toLongOrNull(16) }.getOrNull() }.sorted().toList() }
        synchronized(this) { arm64FunctionsCache[key] = functions }
        return functions
    }

    private fun arm64ExecutableRanges(bytes: ByteArray): List<CodeRange> {
        if (bytes.size < 64 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()) return listOf(CodeRange(0, bytes.size, 0))
        val phoff = u64(bytes, 32).toInt()
        val entrySize = u16(bytes, 54)
        val count = u16(bytes, 56)
        if (entrySize < 56 || phoff < 0 || phoff + entrySize * count > bytes.size) return listOf(CodeRange(0, bytes.size, 0))
        return (0 until count).mapNotNull { index ->
            val at = phoff + index * entrySize
            val type = u32(bytes, at)
            val flags = u32(bytes, at + 4)
            val fileOffset = u64(bytes, at + 8).toInt()
            val virtualAddress = u64(bytes, at + 16)
            val fileSize = u64(bytes, at + 32).toInt()
            if (type == 1 && flags and 1 != 0 && fileOffset >= 0 && fileSize > 0 && fileOffset + fileSize <= bytes.size) CodeRange(fileOffset, fileOffset + fileSize, virtualAddress) else null
        }
    }

    private fun arm64ExecutableRanges(file: File): List<CodeRange> = runCatching {
        RandomAccessFile(file, "r").use { input ->
            val length = input.length()
            if (length < 64) return@use listOf(CodeRange(0, length.toInt(), 0))
            val header = ByteArray(64)
            input.readFully(header)
            if (header[0] != 0x7f.toByte() || header[1] != 'E'.code.toByte() || header[2] != 'L'.code.toByte() || header[3] != 'F'.code.toByte()) {
                return@use listOf(CodeRange(0, length.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), 0))
            }
            val phoff = u64(header, 32).toInt()
            val entrySize = u16(header, 54)
            val count = u16(header, 56)
            val tableBytes = entrySize.toLong() * count
            if (entrySize < 56 || phoff < 0 || tableBytes > 8L * 1024 * 1024 || phoff.toLong() + tableBytes > length) {
                return@use listOf(CodeRange(0, length.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), 0))
            }
            val table = ByteArray(tableBytes.toInt())
            input.seek(phoff.toLong())
            input.readFully(table)
            (0 until count).mapNotNull { index ->
                val at = index * entrySize
                val type = u32(table, at)
                val flags = u32(table, at + 4)
                val fileOffset = u64(table, at + 8).toInt()
                val virtualAddress = u64(table, at + 16)
                val fileSize = u64(table, at + 32).toInt()
                if (type == 1 && flags and 1 != 0 && fileOffset >= 0 && fileSize > 0 && fileOffset.toLong() + fileSize <= length) CodeRange(fileOffset, fileOffset + fileSize, virtualAddress) else null
            }
        }
    }.getOrElse {
        listOf(CodeRange(0, file.length().coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), 0))
    }

    private fun isArm64FramePrologue(word: Int): Boolean = (word and 0xffc07c1f.toInt()) == 0xa980781d.toInt()

    private fun u16(bytes: ByteArray, offset: Int): Int = (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun u32(bytes: ByteArray, offset: Int): Int = arm64Word(bytes, offset)

    private fun u64(bytes: ByteArray, offset: Int): Long = (u32(bytes, offset).toLong() and 0xffffffffL) or ((u32(bytes, offset + 4).toLong() and 0xffffffffL) shl 32)

    private fun addressMap(resultDir: File): AddressMap {
        val result = runCatching { JSONObject(File(resultDir, "result.json").readText()) }.getOrNull() ?: return AddressMap.empty
        val segments = result.optJSONArray("libappLoadSegments") ?: return AddressMap.empty
        return AddressMap((0 until segments.length()).mapNotNull { index ->
            segments.optJSONObject(index)?.let { row ->
                val va = row.optString("virtualAddress").removePrefix("0x").toLongOrNull(16)
                val offset = row.optString("fileOffset").removePrefix("0x").toLongOrNull(16)
                val size = row.optString("fileSize").removePrefix("0x").toLongOrNull(16)
                if (va != null && offset != null && size != null) LoadSegment(va, offset, size) else null
            }
        })
    }

    private data class LoadSegment(val virtualAddress: Long, val fileOffset: Long, val fileSize: Long)

    private class AddressMap(private val segments: List<LoadSegment>) {
        // 地址体系说明：blutter asm 中的地址就是 libapp.so 的 ELF VA；
        // fileOffset 是经 PT_LOAD 段换算的 ELF 文件偏移，与 edit_asm/edit_hex
        // 的裸 VA 同体系，可直接作 locator 使用（edit 前先 hexdump 核对 oldHex）。
        val status: String = if (segments.isEmpty()) "unavailable" else "elf_load_segments:va=libapp_elf_va;fileOffset=elf_file_offset;patchLocator=elf_va_usable_as_edit_locator"

        fun fileOffset(va: Long): Long? = segments.firstOrNull {
            va >= it.virtualAddress && va - it.virtualAddress < it.fileSize
        }?.let { it.fileOffset + va - it.virtualAddress }

        companion object {
            val empty = AddressMap(emptyList())
        }
    }

    private fun className(line: String): String =
        line.removePrefix("class ").substringBefore('{').substringBefore("//")
            .substringBefore(" extends ").substringBefore(" implements ").substringBefore(" with ").substringBefore(" on ").trim()

    private fun parseImmediate(raw: String): Long =
        if (raw.startsWith("0x", true)) raw.substring(2).toLongOrNull(16) ?: 0L
        else raw.toLongOrNull() ?: 0L

    private fun registerNumber(raw: String): Int {
        val register = raw.trim().lowercase()
        if (register == "sp") return 32
        return register.dropWhile { it == 'x' || it == 'w' }.toIntOrNull() ?: 127
    }

    private fun arm64Word(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    internal fun contains(haystack: String, needle: String, caseInsensitive: Boolean): Boolean =
        if (caseInsensitive) haystack.lowercase().contains(needle) else haystack.contains(needle)

    /**
     * 一次调用里多词命中判定（B1-4，2026-09-19）。
     *
     * 旧路径对每个词条各调一次 [contains]，忽略大小写时**每词都重转一次整行**
     * lowercase——pp.txt 是几十万~百万行级，行 × 词 = 数百万次大字符串分配，
     * 是 pp 搜索 GC 抖动的主因。这里改成整行只转一次，再对全部词条做子串判定。
     *
     * 注意：词条本身在 caseInsensitive 时已经被 [searchQueries] 小写化，语义不变。
     */
    internal fun matchedQueriesOf(
        raw: String,
        queries: List<String>,
        caseInsensitive: Boolean,
    ): List<String> {
        if (!caseInsensitive) return queries.filter { raw.contains(it) }
        val lower = raw.lowercase()
        return queries.filter { lower.contains(it) }
    }


    /** 统计函数头二进制条目数（轻量流式读，用于 cacheHit 分支回填计数）。 */
    @Synchronized
    internal fun functionHeaderCount(resultDir: File): Int {
        val index = File(resultDir, FUNCTION_HEADER_INDEX)
        if (!index.isFile) return 0
        var n = 0
        runCatching {
            DataInputStream(index.inputStream().buffered()).use { inp ->
                if (inp.readInt() != FUNCTION_HEADER_INDEX_MAGIC) return 0
                while (true) {
                    inp.readLong(); inp.readLong(); inp.readUTF(); inp.readUTF(); inp.readUTF()
                    n++
                }
            }
        }
        return n
    }

    /**
     * asm 函数头行 "// ** addr: 0x..., size: -0x..." → (va,size)；非头返回 null。
     * 供合并索引器（AsmFastIndex）与 diff 复用。
     *
     * **必须走线程本地 Matcher**（2026-09-16 审核）：此前的 `FUNC_ADDR.matchEntire`
     * 每次调用新建 Matcher，而 AsmFastIndex 对每个 asm 文件的**每一行**都调这里
     * ——正是 918fad69 修掉的那类 ICU native 回溯栈堆积（短命 Matcher 靠 GC 异步
     * 回收，逐行产生速度远超回收 → native 单调涨到 Scudo abort），修 processAsmFile
     * 时漏掉了这条同样在并行扫描里的路径。独立 Matcher 与 funcAddrM 分开，
     * 避免将来出现嵌套调用互相 reset。
     */
    internal fun headerAddrSize(rawLine: String): Pair<Long, Long>? {
        // B2-1 预筛（AsmFastIndex 对每个 asm 文件的**每一行**都调这里，收益同 processAsmFile）：
        // `// ** addr:` 字面量先行，非该形态的行跳过全串正则。
        if (!startsWithAfterSpace(rawLine, "// ** ")) return null
        if (!headerAddrM.matches(rawLine)) return null
        val m = headerAddrM.m
        // 注意：FUNC_ADDR 把可选负号放在捕获组**之外**（`size: -?0x(...)`），
        // 所以 group(2) 恒为无符号十六进制——`size: -0x8` 在这里得到 8 而不是 0。
        // 这是既有行为（旧实现里的 `startsWith("-")` 分支是永远走不到的死代码），
        // 且语义索引与 diff 两条消费路径口径一致；不要在此处"修正"成 0，
        // 那会让同一份 asm 在两处解析出不同尺寸。
        val sizeRaw = m.group(2)?.lowercase() ?: return null
        return m.group(1)?.toLongOrNull(16)!! to (sizeRaw.toLongOrNull(16) ?: 0L)
    }


    /**
     * 多词预过滤正则：任一词在文本中出现即命中。只作行级预筛（超集），
     * 精确匹配仍在调用方逐词执行，结果与无预筛完全一致：
     * 正则无命中 => 任何词都不在文本中出现（词面量经 Pattern.quote 转义）。
     */
    private fun anyOfRegex(needles: List<String>, ignoreCase: Boolean): Regex? {
        val literals = needles.filter(String::isNotEmpty)
            .map { java.util.regex.Pattern.quote(it) }
        if (literals.isEmpty()) return null
        return Regex(literals.joinToString("|"), if (ignoreCase) setOf(RegexOption.IGNORE_CASE) else emptySet())
    }

    /** 短词用词边界，避免 tun 命中 opportunity、ad 命中无关单词。 */
    private fun containsTerm(haystack: String, needle: String): Boolean {
        if (needle.any { it.code > 0x7f }) return haystack.contains(needle, ignoreCase = true)
        var start = haystack.indexOf(needle, ignoreCase = true)
        while (start >= 0) {
            val end = start + needle.length
            val leftOk = if (needle.length <= 3) {
                start == 0 || !haystack[start - 1].isLetter()
            } else {
                start == 0 || !haystack[start - 1].isLetterOrDigit() ||
                    (haystack[start].isUpperCase() && haystack[start - 1].isLowerCase())
            }
            val rightOk = if (needle.length <= 3) {
                end == haystack.length || !haystack[end].isLetter()
            } else {
                end == haystack.length || !haystack[end].isLetterOrDigit() ||
                    (haystack[end].isUpperCase() && haystack[end - 1].isLowerCase())
            }
            if (leftOk && rightOk) return true
            start = haystack.indexOf(needle, start + 1, ignoreCase = true)
        }
        return false
    }
}
