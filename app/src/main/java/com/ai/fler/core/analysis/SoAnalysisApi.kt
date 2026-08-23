package com.ai.fler.core.analysis

import android.util.Log
import com.ai.fler.core.mcp.AddressAxis
import com.ai.fler.core.mcp.AddressAxisResolver
import com.ai.fler.data.dao.DartMethodDao
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.inject.Inject
import javax.inject.Singleton

/**
 * SO 反编译/分析本地 API。
 *
 * 提供强类型 Kotlin 接口，供 App 内部（ViewModel / UI / 其他 Service）直接调用，
 * 无需经过 MCP JSON-RPC 协议层。所有方法均为 suspend，调用方需在协程作用域中使用。
 *
 * 使用前需先调用 [open] 打开 so 文件分析会话。
 */
@Singleton
class SoAnalysisApi @Inject constructor(
    private val session: AnalysisSession,
    private val axisResolver: AddressAxisResolver,
    private val dartMethodDao: DartMethodDao,
) {
    companion object {
        private const val TAG = "SoAnalysisApi"

        // ARM64 NOP = 0xD503201F (little-endian: 1F 20 03 D5)
        private val NOP_BYTES = byteArrayOf(0x1F, 0x20, 0x03, 0xD5.toByte())

        // SVC #0 = 0xD4000001 (little-endian: 01 00 00 D4)
        private val SVC_HEX = "010000D4"

        private val ANTI_DEBUG_STRING_PATTERNS = mapOf(
            "/proc/self/status" to "proc-status",
            "TracerPid" to "tracer-pid",
            "ptrace" to "ptrace-string",
            "frida" to "frida-detect",
            "Xposed" to "xposed-detect",
            "/data/local/tmp" to "tmp-dir-check",
            "/system/bin/su" to "root-detect",
            "magisk" to "magisk-detect",
            "debugger" to "debugger-detect",
            "isDebuggerConnected" to "java-debugger-check",
            "ro.debuggable" to "debuggable-prop",
            "gum-js" to "frida-gum",
            "lsp" to "lsposed-detect",
        )

        private val SUSPICIOUS_IMPORTS = setOf(
            "ptrace", "fork", "kill", "raise", "signal", "abort",
            "exit", "_exit", "pthread_create", "dlopen", "dlsym",
            "access", "stat", "open", "readlink", "read",
            "getpid", "getppid", "sysconf",
        )
    }

    // ==================== 会话管理 ====================

    /** 打开 so 分析会话。autoAnalyze=true 时自动执行 Rizin aaa。 */
    suspend fun open(soPath: String, autoAnalyze: Boolean = true): Boolean = withContext(Dispatchers.IO) {
        val caps = mutableListOf<AnalysisCapability>()
        if (autoAnalyze) caps += AnalysisCapability.FUNCTION_ANALYSIS
        caps += AnalysisCapability.ELF_PARSING
        caps += AnalysisCapability.BYTE_EDIT
        val result = session.open(soPath, requireCaps = caps)
        result is com.ai.fler.core.analysis.OpenResult.Success
    }

    /** 关闭当前分析会话。 */
    suspend fun close(): Unit = withContext(Dispatchers.IO) {
        session.closeAll()
    }

    // ==================== 导入符号 ====================

    /** 列出动态导入符号。 */
    suspend fun listImports(
        query: String? = null,
        type: String? = null,
        limit: Int = 500,
    ): List<ImportInfo> = withContext(Dispatchers.IO) {
        val all = session.getImports()
        all.asSequence()
            .filter { query == null || it.name.contains(query, ignoreCase = true) }
            .filter { type == null || it.type.equals(type, ignoreCase = true) }
            .take(limit.coerceIn(1, 5000))
            .toList()
    }

    // ==================== init_array / fini_array ====================

    /** init/fini array 条目。 */
    data class InitArrayEntry(
        val section: String,
        val sectionOffset: Long,
        val sectionAddress: Long,
        val sectionSize: Long,
        val index: Int,
        val vaddr: Long,
        val fileOffset: Long,
    )

    /** 解析 .init_array / .fini_array / .preinit_array / .ctors / .dtors。 */
    suspend fun listInitArray(): List<InitArrayEntry> = withContext(Dispatchers.IO) {
        val sections = session.getSections()
        val targetSections = listOf(".init_array", ".fini_array", ".preinit_array", ".ctors", ".dtors")
        val ptrSize = session.getFileInfo()?.bits?.let { it / 8 } ?: 8
        if (ptrSize <= 0) return@withContext emptyList()

        val result = mutableListOf<InitArrayEntry>()
        for (secName in targetSections) {
            val sec = sections.find { it.name == secName } ?: continue
            if (sec.size <= 0) continue
            val count = (sec.size / ptrSize).toInt()
            val bytes = session.readBytes(sec.offset, sec.size)
            if (bytes.isEmpty()) continue
            for (i in 0 until count) {
                val base = i * ptrSize
                if (base + ptrSize > bytes.size) break
                val value: Long = if (ptrSize == 8) {
                    ByteBuffer.wrap(bytes, base, 8).order(ByteOrder.LITTLE_ENDIAN).long
                } else {
                    ByteBuffer.wrap(bytes, base, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                }
                result.add(InitArrayEntry(
                    section = secName,
                    sectionOffset = sec.offset,
                    sectionAddress = sec.address,
                    sectionSize = sec.size,
                    index = i,
                    vaddr = value,
                    fileOffset = value,
                ))
            }
        }
        result
    }

    // ==================== 函数圈复杂度 ====================

    /** 函数复杂度分析结果。 */
    data class ComplexityResult(
        val address: Long,
        val cyclomaticComplexity: Int,
        val basicBlocks: Int,
        val edges: Int,
        val totalInstructions: Int,
        val risk: String, // trivial / low / medium / high / critical
    )

    /** 计算函数圈复杂度。address 为 vaddr 或文件偏移（自动识别）。 */
    suspend fun functionComplexity(address: Long): ComplexityResult? = withContext(Dispatchers.IO) {
        val addr = normalizeToVaddr(address) ?: return@withContext null
        val bbs = session.getFunctionCfg(addr)
        if (bbs.isEmpty()) return@withContext null
        val nodes = bbs.size
        val edges = bbs.sumOf { it.succs.size }
        val complexity = edges - nodes + 2
        val totalInstrs = bbs.sumOf { it.nInstr }
        ComplexityResult(
            address = addr,
            cyclomaticComplexity = complexity,
            basicBlocks = nodes,
            edges = edges,
            totalInstructions = totalInstrs,
            risk = when {
                complexity > 20 -> "critical"
                complexity > 15 -> "high"
                complexity > 10 -> "medium"
                complexity > 5 -> "low"
                else -> "trivial"
            },
        )
    }

    // ==================== 批量反编译 ====================

    /** 批量反编译结果项。 */
    data class DecompileItem(
        val name: String,
        val address: Long,
        val ok: Boolean,
        val decompiled: String?,
        val truncated: Boolean,
        val reason: String? = null,
    )

    /** 按名称模糊匹配批量反编译函数（pdc pseudo-C）。 */
    suspend fun batchDecompile(
        query: String,
        maxFunctions: Int = 10,
    ): List<DecompileItem> = withContext(Dispatchers.IO) {
        val q = query.lowercase()
        val maxFuncs = maxFunctions.coerceIn(1, 50)

        val rizin = session.listFunctions()
        val seen = HashSet<Long>(rizin.size + 16)
        rizin.forEach { seen.add(it.vaddr) }
        val dartFuncs = dartFunctionsList()
        val merged = buildList {
            addAll(rizin)
            addAll(dartFuncs.mapNotNull { d -> if (seen.add(d.vaddr)) d.toFunctionInfo() else null })
        }
        val matched = merged.filter { it.name.lowercase().contains(q) }.take(maxFuncs)
        if (matched.isEmpty()) return@withContext emptyList()

        matched.map { f ->
            val hexAddr = "0x${f.vaddr.toString(16)}"
            val pseudoC = session.cmdStr("pdc @ $hexAddr")
            DecompileItem(
                name = f.name,
                address = f.vaddr,
                ok = !pseudoC.isNullOrBlank(),
                decompiled = pseudoC?.trim()?.take(8192),
                truncated = (pseudoC?.length ?: 0) > 8192,
                reason = if (pseudoC.isNullOrBlank()) "pdc 不可用或该地址无函数" else null,
            )
        }
    }

    // ==================== NOP 补丁 ====================

    /** NOP 补丁结果。 */
    data class PatchNopResult(
        val offset: Long,
        val count: Int,
        val bytesWritten: Int,
        val originalHex: String,
        val patchedHex: String,
        val ok: Boolean,
        val reason: String? = null,
    )

    /** 在指定地址写入 ARM64 NOP 指令。offset 自动识别为文件偏移。 */
    suspend fun patchNop(offset: Long, count: Int = 1): PatchNopResult = withContext(Dispatchers.IO) {
        val fileOff = normalizeToFileOffset(offset) ?: offset
        val cnt = count.coerceIn(1, 256)
        val nopBytes = ByteArray(cnt * 4)
        for (i in 0 until cnt) {
            System.arraycopy(NOP_BYTES, 0, nopBytes, i * 4, 4)
        }
        val original = session.readBytes(fileOff, cnt * 4L)
        val ok = session.writeBytes(fileOff, nopBytes, soNameHint = "")
        PatchNopResult(
            offset = fileOff,
            count = cnt,
            bytesWritten = cnt * 4,
            originalHex = original.toHex(),
            patchedHex = nopBytes.toHex(),
            ok = ok,
            reason = if (!ok) "写入失败（文件只读或权限不足）" else null,
        )
    }

    // ==================== 反调试检测 ====================

    /** 反调试检测结果。 */
    data class AntiDebugResult(
        val categoryCount: Int,
        val findings: List<Finding>,
        val note: String? = null,
    )

    /** 单个检测发现。 */
    data class Finding(
        val category: String, // string / import / instruction
        val label: String,
        val pattern: String? = null,
        val matchCount: Int,
        val matches: List<MatchEntry>,
    )

    data class MatchEntry(
        val address: Long,
        val info: String, // string content / import name / instruction text
    )

    /** 扫描 so 中常见反调试/反逆向模式。 */
    suspend fun detectAntiDebug(
        scanStrings: Boolean = true,
        scanImports: Boolean = true,
        scanSvc: Boolean = true,
    ): AntiDebugResult = withContext(Dispatchers.IO) {
        val findings = mutableListOf<Finding>()

        // 1) 字符串模式
        if (scanStrings) {
            for ((pattern, label) in ANTI_DEBUG_STRING_PATTERNS) {
                val strs = session.scanStrings(StringScanOptions(minLen = pattern.length, maxLen = 512))
                val matches = strs.filter { it.string.contains(pattern, ignoreCase = true) }.take(20)
                if (matches.isNotEmpty()) {
                    findings.add(Finding(
                        category = "string",
                        label = label,
                        pattern = pattern,
                        matchCount = matches.size,
                        matches = matches.map { MatchEntry(it.address, it.string.take(256)) },
                    ))
                }
            }
        }

        // 2) 导入符号
        if (scanImports) {
            val imports = session.getImports()
            val matched = imports.filter { imp ->
                SUSPICIOUS_IMPORTS.any { imp.name.equals(it, ignoreCase = true) || imp.name.contains(it, ignoreCase = true) }
            }
            if (matched.isNotEmpty()) {
                findings.add(Finding(
                    category = "import",
                    label = "suspicious-imports",
                    matchCount = matched.size,
                    matches = matched.map { MatchEntry(it.address, "${it.type} ${it.name}") },
                ))
            }
        }

        // 3) SVC 指令扫描
        if (scanSvc) {
            val output = session.cmdStr("/x ${SVC_HEX}") ?: ""
            val svcMatches = output.lines().mapNotNull { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty()) return@mapNotNull null
                val colonIdx = trimmed.indexOf(':')
                if (colonIdx < 0) return@mapNotNull null
                trimmed.substring(0, colonIdx).trim().removePrefix("0x").toLongOrNull(16)
            }.filter { it > 0 }.take(100)
            if (svcMatches.isNotEmpty()) {
                findings.add(Finding(
                    category = "instruction",
                    label = "svc-syscall",
                    matchCount = svcMatches.size,
                    matches = svcMatches.map { MatchEntry(it, "SVC #0") },
                ))
            }
        }

        AntiDebugResult(
            categoryCount = findings.size,
            findings = findings,
            note = if (findings.isEmpty()) "未检测到常见反调试模式（不代表一定没有）" else null,
        )
    }

    // ==================== 函数导出 ====================

    /** 函数导出结果。 */
    data class ExportFunctionResult(
        val name: String?,
        val address: Long,
        val fileOffset: Long,
        val functionSize: Long?,
        val readSize: Int,
        val hex: String?,
        val disasm: List<DisasmEntry>?,
        val decompiled: String?,
        val decompTruncated: Boolean,
    )

    data class DisasmEntry(
        val address: Long,
        val mnemonic: String,
        val opStr: String,
        val size: Int,
    )

    /** 导出函数完整信息：原始字节 + 反汇编 + pdc 伪代码。 */
    suspend fun exportFunction(
        address: Long,
        maxSize: Int = 8192,
        includeDisasm: Boolean = true,
        includeDecomp: Boolean = true,
    ): ExportFunctionResult = withContext(Dispatchers.IO) {
        val addr = normalizeToVaddr(address) ?: address
        val hexAddr = "0x${addr.toString(16)}"
        val maxSz = maxSize.coerceIn(64, 65536)

        val func = session.findFunctionContaining(addr)
        val funcSize = func?.size?.takeIf { it > 0 }?.toInt() ?: maxSz
        val readSize = minOf(funcSize, maxSz)

        val fileOff = normalizeToFileOffset(address) ?: address
        val bytes = session.readBytes(fileOff, readSize.toLong())

        val disasm = if (includeDisasm && bytes.isNotEmpty()) {
            val insns = session.disassemble(addr, readSize.toLong())
            insns.map { DisasmEntry(it.address, it.mnemonic, it.opStr, it.size) }
        } else null

        val pseudoCRaw = if (includeDecomp) session.cmdStr("pdc @ $hexAddr") else null
        val decompResult = if (pseudoCRaw != null && pseudoCRaw.isNotBlank()) pseudoCRaw.trim().take(16384) else null
        val decompTruncated = pseudoCRaw != null && pseudoCRaw.length > 16384

        ExportFunctionResult(
            name = func?.name,
            address = addr,
            fileOffset = fileOff,
            functionSize = func?.size,
            readSize = bytes.size,
            hex = if (bytes.isNotEmpty()) bytes.toHex() else null,
            disasm = disasm,
            decompiled = decompResult,
            decompTruncated = decompTruncated,
        )
    }

    // ==================== 入口点列表 ====================

    /** 入口点。 */
    data class EntryPoint(
        val type: String, // elf_entry / init_array / fini_array / ...
        val index: Int? = null,
        val section: String? = null,
        val address: Long,
        val preview: String? = null,
    )

    /** 列出 so 的所有入口点，每个附带前 16 条指令预览。 */
    suspend fun listEntryPoints(disasmPreview: Boolean = true): List<EntryPoint> = withContext(Dispatchers.IO) {
        val sections = session.getSections()
        val entries = mutableListOf<EntryPoint>()

        // ELF entry
        val elfEntry = session.cmdStr("iej") ?: ""
        if (elfEntry.isNotBlank()) {
            val entryAddr = elfEntry.trim()
                .removePrefix("[").removeSuffix("]")
                .removePrefix("\"").removeSuffix("\"")
                .toLongOrNull(16)
            if (entryAddr != null && entryAddr > 0) {
                val preview = if (disasmPreview) disasmPreview(entryAddr, 16) else null
                entries.add(EntryPoint(type = "elf_entry", address = entryAddr, preview = preview))
            }
        }

        // init/fini arrays
        val arraySections = mapOf(
            ".init_array" to "init_array",
            ".fini_array" to "fini_array",
            ".preinit_array" to "preinit_array",
            ".ctors" to "ctors",
            ".dtors" to "dtors",
        )
        val ptrSize = session.getFileInfo()?.bits?.let { it / 8 } ?: 8

        for ((secName, label) in arraySections) {
            val sec = sections.find { it.name == secName } ?: continue
            if (sec.size <= 0) continue
            val count = (sec.size / ptrSize).toInt()
            val bytes = session.readBytes(sec.offset, sec.size)
            if (bytes.isEmpty()) continue
            for (i in 0 until count) {
                val base = i * ptrSize
                if (base + ptrSize > bytes.size) break
                val value: Long = if (ptrSize == 8) {
                    ByteBuffer.wrap(bytes, base, 8).order(ByteOrder.LITTLE_ENDIAN).long
                } else {
                    ByteBuffer.wrap(bytes, base, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
                }
                if (value <= 0L) continue
                val preview = if (disasmPreview) disasmPreview(value, 16) else null
                entries.add(EntryPoint(
                    type = label,
                    index = i,
                    section = secName,
                    address = value,
                    preview = preview,
                ))
            }
        }
        entries
    }

    // ==================== 正则字符串搜索 ====================

    /** 正则字符串搜索结果项。 */
    data class StringMatch(
        val address: Long,
        val paddr: Long?,
        val string: String,
    )

    /** 用正则表达式扫描 so 中的字符串。 */
    suspend fun searchStringsRegex(
        regex: String,
        minLen: Int = 4,
        limit: Int = 200,
    ): List<StringMatch> = withContext(Dispatchers.IO) {
        val compiled = try { Regex(regex, RegexOption.IGNORE_CASE) }
        catch (_: Exception) { return@withContext emptyList() }
        val strs = session.scanStrings(StringScanOptions(minLen = minLen.coerceAtLeast(1), maxLen = 4096))
        strs.asSequence()
            .filter { compiled.containsMatchIn(it.string) }
            .take(limit.coerceIn(1, 2000))
            .map { StringMatch(it.address, if (it.paddr != it.address) it.paddr else null, it.string.take(512)) }
            .toList()
    }

    // ==================== 动态节区 ====================

    /** 获取 .dynamic 节区原始内容（JSON 或文本）。 */
    suspend fun getDynamicSection(): Pair<String, String?> = withContext(Dispatchers.IO) {
        val json = session.cmdStr("irj") ?: ""
        if (json.isNotBlank()) {
            "json" to json.take(8192)
        } else {
            val text = session.cmdStr("ir") ?: ""
            if (text.isNotBlank()) "text" to text.take(8192)
            else "none" to null
        }
    }

    // ==================== 内部辅助 ====================

    private suspend fun normalizeToVaddr(input: Long): Long? {
        val soPath = session.currentFilePath() ?: return input
        val res = axisResolver.resolve(soPath, input) ?: return input
        return when (res.inputAxis) {
            AddressAxis.VADDR, AddressAxis.NONE -> input
            AddressAxis.FILE_OFFSET -> res.vaddr
            AddressAxis.AMBIGUOUS -> {
                Log.w(TAG, "地址 0x${input.toString(16)} 坐标歧义，按 vaddr 处理")
                input
            }
        }
    }

    private suspend fun normalizeToFileOffset(input: Long): Long? {
        val soPath = session.currentFilePath() ?: return input
        val res = axisResolver.resolve(soPath, input) ?: return input
        return when (res.inputAxis) {
            AddressAxis.VADDR -> res.fileOffset
            AddressAxis.FILE_OFFSET, AddressAxis.NONE -> input
            AddressAxis.AMBIGUOUS -> {
                Log.w(TAG, "地址 0x${input.toString(16)} 坐标歧义，按文件偏移处理")
                input
            }
        }
    }

    private suspend fun disasmPreview(addr: Long, maxInstrs: Int): String {
        val insns = session.disassemble(addr, 64)
        return insns.take(maxInstrs).joinToString("\n") {
            "  0x${it.address.toString(16)}: ${it.mnemonic} ${it.opStr}"
        }
    }

    // ---- Dart 函数合并（与 EngineMcpToolRegistry 逻辑一致） ----

    private data class DartFunction(val vaddr: Long, val paddr: Long, val name: String, val size: Long)

    private val dartFunctionCache = java.util.concurrent.ConcurrentHashMap<String, List<DartFunction>>()

    private suspend fun dartFunctionsList(): List<DartFunction> {
        val soPath = session.currentFilePath() ?: return emptyList()
        dartFunctionCache[soPath]?.let { return it }
        val methods = try { dartMethodDao.getMethodsBySoPathLight(soPath) }
        catch (_: Exception) { emptyList() }
        if (methods.isEmpty()) return emptyList()
        val funcs = methods.mapNotNull { m ->
            val vaddr = m.functionOffset ?: return@mapNotNull null
            if (vaddr <= 0L) return@mapNotNull null
            val name = if (m._className.isNotBlank()) "${m._className}.${m.methodName}" else m.methodName
            val paddr = axisResolver.resolve(soPath, vaddr)?.fileOffset ?: vaddr
            DartFunction(vaddr, paddr, name, m.functionSize ?: 0L)
        }.sortedBy { it.vaddr }
        dartFunctionCache[soPath] = funcs
        return funcs
    }

    private fun DartFunction.toFunctionInfo(): FunctionInfo =
        FunctionInfo(name = name, offset = paddr, vaddr = vaddr, size = size)

    // ---- 扩展 ----

    private fun ByteArray.toHex(): String =
        joinToString(" ") { it.toUByte().toString(16).padStart(2, '0') }
}
