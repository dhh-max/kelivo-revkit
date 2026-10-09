package zhou.solab.engine

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * B1-2 语义索引倒排（term → rowIds）。
 *
 * 设计约束（决定了这里的接口形态）：
 * - **只用于收窄候选**：命中判定仍由查询侧既有复核完成，倒排缺失/不全只是回退扫描；
 * - **并集语义**：批量查询是 OR（命中任一即算），所以候选 = 各词元 postings 的并集；
 *   取"最稀有词元"会漏掉只命中其它词的行（2026-09-19 实测回归根因）；
 * - **任一词元缺索引即整体回退**（返回 null）：该词可能命中倒排未覆盖的行。
 *
 * 文本口径必须与查询侧一致（行内可搜索文本 + functionHeader 上下文），否则会出现
 * "查询词不在倒排里"的假阴性——这也是候选回退存在的原因。
 */
internal object SemanticPostings {

    const val FILE_NAME = "blutter-semantic-postings-v1.bin"
    const val MAGIC = 0x534D504F // 'SMPO'
    private const val MIN_TERM_LEN = 3
    private const val MAX_TERMS_PER_ROW = 48

    /** 词元化：按非字母数字/下划线切分并小写；CJK 连写整体保留。 */
    fun tokens(text: String): List<String> {
        val out = LinkedHashSet<String>()
        val buffer = StringBuilder()
        fun flush() {
            if (buffer.length >= MIN_TERM_LEN) out += buffer.toString()
            buffer.setLength(0)
        }
        for (ch in text) {
            if (ch.isLetterOrDigit() || ch == '_') buffer.append(ch.lowercaseChar()) else flush()
            if (out.size >= MAX_TERMS_PER_ROW) return out.toList()
        }
        flush()
        return out.toList()
    }

    /**
     * 流式扫一遍语义索引，收集 term → rowId（升序、去重）。
     *
     * B3-1 起与查询侧共用同一行解析器（[SemanticRowReader]）与同一文本口径
     * （[semanticSearchableText]）：词元集合必须与查询侧一致，否则候选收窄会漏行。
     *
     * @param headerText 由 functionVa 取上下文文本（函数名/类名/文件名）
     */
    fun collect(
        index: File,
        headerText: (Long) -> String,
    ): Map<String, IntArray> {
        val postings = HashMap<String, MutableList<Int>>()
        var rowId = 0
        val complete = runCatching {
            SemanticRowReader.open(index).use { rows ->
                while (true) {
                    val row = rows.next() ?: break
                    val context = row.functionVa?.let(headerText).orEmpty()
                    val text = semanticSearchableText(row, context)
                    for (term in tokens(text)) {
                        val ids = postings.getOrPut(term) { ArrayList(4) }
                        if (ids.isEmpty() || ids.last() != rowId) ids.add(rowId)
                    }
                    rowId++
                }
            }
        }.isSuccess
        // 半截倒排会让候选收窄指向漏行（静默假阴性）：宁可整体不要倒排，退回全量扫描。
        if (!complete) return emptyMap()
        return postings.mapValues { (_, ids) -> ids.toIntArray() }
    }

    fun write(dir: File, postings: Map<String, IntArray>) {
        val temp = File(dir, "$FILE_NAME.tmp")
        val target = File(dir, FILE_NAME)
        DataOutputStream(BufferedOutputStream(FileOutputStream(temp))).use { out ->
            out.writeInt(MAGIC)
            out.writeInt(postings.size)
            for ((term, ids) in postings) {
                out.writeUTF(term)
                out.writeInt(ids.size)
                var previous = 0
                for (id in ids) {
                    writeVarInt(out, id - previous)
                    previous = id
                }
            }
        }
        // 必须 REPLACE_EXISTING + 失败即抛（B2-3 实测，2026-09-19）：原 `renameTo` 在
        // 目标已存在时（Windows 的 MoveFile 语义，且返回值被忽略）**静默不替换**——
        // 索引原地重建（如切换"跳过噪音子树"开关）后倒排仍按旧 rowId 编号，候选收窄
        // 会指向错行 → 搜索静默漏结果。改为 Files.move：Android 上同为空操作 rename
        // 覆盖（rename(2) 本就覆盖），失败则抛给调用方（ensureSemanticIndex 会删掉
        // 倒排并回退全量扫描，见该处注释），不再留"看着有、实际错"的倒排。
        runCatching {
            java.nio.file.Files.move(
                temp.toPath(),
                target.toPath(),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
        }.getOrElse {
            java.nio.file.Files.move(
                temp.toPath(),
                target.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
        }
    }

    /** 读取倒排；缺失/损坏返回 null（调用方回退扫描）。 */
    fun read(dir: File): Map<String, IntArray>? {
        val file = File(dir, FILE_NAME)
        if (!file.isFile) return null
        return runCatching {
            DataInputStream(BufferedInputStream(FileInputStream(file))).use { input ->
                if (input.readInt() != MAGIC) return null
                val count = input.readInt()
                if (count < 0 || count > 5_000_000) return null
                val map = HashMap<String, IntArray>(count * 2)
                repeat(count) {
                    val term = input.readUTF()
                    val size = input.readInt()
                    if (size < 0) return null
                    val ids = IntArray(size)
                    var previous = 0
                    for (index in 0 until size) {
                        previous += readVarInt(input)
                        ids[index] = previous
                    }
                    map[term] = ids
                }
                map
            }
        }.getOrNull()
    }

    /**
     * 候选行 = 各词元 postings 的**并集**（OR 语义）。
     * 任一词元缺索引 → null（整体回退，避免假阴性）。
     */
    fun candidates(postings: Map<String, IntArray>?, tokens: List<String>): IntArray? {
        if (postings == null || tokens.isEmpty()) return null
        val merged = sortedSetOf<Int>()
        for (term in tokens) {
            val ids = postings[term] ?: return null
            ids.forEach { merged.add(it) }
        }
        return merged.toIntArray()
    }

    private fun writeVarInt(out: DataOutputStream, value: Int) {
        var remaining = value
        while (true) {
            if (remaining and 0x7F.inv() == 0) {
                out.writeByte(remaining)
                return
            }
            out.writeByte((remaining and 0x7F) or 0x80)
            remaining = remaining ushr 7
        }
    }

    private fun readVarInt(input: DataInputStream): Int {
        var result = 0
        var shift = 0
        while (true) {
            val byte = input.readUnsignedByte()
            result = result or ((byte and 0x7F) shl shift)
            if (byte and 0x80 == 0) return result
            shift += 7
            if (shift > 28) return result
        }
    }
}
