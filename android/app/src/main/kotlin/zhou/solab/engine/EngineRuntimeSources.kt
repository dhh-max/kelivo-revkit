package zhou.solab.engine

import android.net.Uri
import zhou.solab.tools.AppLog
import zhou.solab.tools.SettingsStore
import zhou.solab.tools.err
import zhou.solab.tools.ok
import zhou.solab.nativecore.NativeEngine
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

internal fun EngineRuntime.setWorkDirectory(uri: Uri) {
    if (workDirUri == uri && workDir != null) return
    workDirUri = uri
    workDir = WorkDirectory(context, uri)
    sources = emptyList()
    sourceFingerprint = emptyList()
    sourceSummaryCache.clear()
    workspaceBySourceKey.clear()
    pageStore.clear()
    searchCache.clear()
    AppLog.i("Work directory selected: ${WorkDirectory.displayPath(uri)}")
}

/** path 模式工作目录（统一工作路径：与 APK 工作目录一致，无需 SAF）。 */
internal fun EngineRuntime.setWorkDirectoryPath(path: String) {
    val canonical = File(path).canonicalPath
    val existing = workDir
    if (existing?.isPathMode == true && existing.rootPath == canonical) return
    workDirUri = null
    workDir = WorkDirectory(context, null, canonical)
    sources = emptyList()
    sourceFingerprint = emptyList()
    sourceSummaryCache.clear()
    workspaceBySourceKey.clear()
    pageStore.clear()
    searchCache.clear()
    AppLog.i("Work directory (path mode): $canonical")
}

internal fun EngineRuntime.listAvailableSos(prefix: String = "", limit: Int = 50, cursor: String = ""): JSONObject = guarded {
    val dir = workDir ?: return@guarded err("SO_NOT_FOUND", "No work directory selected")
    val currentSources = ensureSources(dir)
    val boundedLimit = limit.coerceIn(1, 500)
    val start = cursor.removePrefix("source:").toIntOrNull()?.coerceAtLeast(0) ?: 0
    val filtered = currentSources.filter { prefix.isBlank() || it.path.startsWith(prefix) || it.name.startsWith(prefix) }
    val items = JSONArray()
    filtered.asSequence()
        .drop(start)
        .take(boundedLimit)
        .forEach { src ->
            val meta = sourceSummary(dir, src)
            items.put(JSONObject()
                .put("path", src.path)
                .put("filePath", src.path)
                .put("openPath", src.path)
                .put("source", src.source)
                .put("apkPath", src.apkPath)
                .put("apkEntry", src.apkEntry)
                .put("abi", src.abi)
                .put("size", src.size)
                .put("modified", src.modified)
                .put("architecture", meta.architecture)
                .put("bits", meta.bits)
                .put("endian", meta.endian)
                .put("soname", JSONObject.NULL)
                .put("hasDebugInfo", meta.hasDebugInfo)
                .put("stripped", meta.stripped))
        }
    val nextOffset = start + items.length()
    val nextCursor = if (nextOffset < filtered.size) "source:$nextOffset" else null
    ok(JSONObject()
        .put("items", items)
        .put("usage", "Call so_analyze(action=open) with path or filePath from any item. Use the returned workspaceId for later actions.")
        .put("pagination", pagination(nextCursor != null, nextCursor, items.length(), boundedLimit, filtered.size)))
}

internal fun EngineRuntime.open(path: String, temporary: Boolean): JSONObject = guarded {
    if (path.isBlank()) return@guarded err("INVALID_ARGUMENT", "Missing SO path. Pass path or filePath to so_analyze(action=open).", "path", path)
    val ws = openWorkspace(path, temporary)
    val elf = ws.elf
    val src = ws.source
    val symbolFunctions = (elf.symbols + elf.dynSymbols).filter { it.type == "FUNC" && !it.imported }.distinctBy { it.name to it.value }
    val exportedFunctions = elf.dynSymbols.filter { it.type == "FUNC" && !it.imported && it.value > 0 }.distinctBy { it.name to it.value }
    val analyzedFunctions = if (NativeEngine.active().available()) runCatching { JSONArray(NativeEngine.active().functions(ws.data, elf.architecture)).length() }.getOrDefault(symbolFunctions.size) else symbolFunctions.size
    val pltStubs = elf.relocations.count { it.section.contains("plt", true) }
    ok(JSONObject()
        .put("workspaceId", ws.id)
        .put("temporary", temporary)
        .put("soFileName", src.name)
        .put("source", src.source)
        .put("inputPath", src.path)
        .put("apkPath", src.apkPath)
        .put("apkEntry", src.apkEntry)
        .put("abi", src.abi)
        .put("architecture", elf.architecture)
        .put("bits", elf.bits)
        .put("endian", elf.endian)
        // F-54：映射后的类型名 + 原始 code 一并给（与 machine 的映射口径对齐）。
        .put("elfType", elf.typeName)
        .put("elfTypeCode", elf.type)
        .put("machine", elf.machineName)
        .put("entryPoint", hex(elf.entry))
        .put("analysisInput", JSONObject().put("source", ws.analysisInputSource).put("originalSha256", ws.originalSha256).put("analysisSha256", sha256(ws.data)).put("structureRecovery", ws.structureRecovery))
        .put("counts", JSONObject().put("sections", elf.sections.size).put("symbols", elf.symbols.size).put("dynsyms", elf.dynSymbols.size).put("relocations", elf.relocations.size).put("functions", symbolFunctions.size).put("functionsMeaning", "symbolFunctions").put("symbolFunctions", symbolFunctions.size).put("exportedFunctions", exportedFunctions.size).put("analyzedFunctions", analyzedFunctions).put("pltStubs", pltStubs).put("strings", elf.strings.size))
        .put("capabilities", JSONObject().put("canDisassemble", true).put("canEditAsm", true).put("canEditHex", true).put("canResolveRelocs", elf.relocations.isNotEmpty()).put("hasPltGot", elf.sections.any { it.name in setOf(".plt", ".got") }).put("canSearchStrings", elf.strings.isNotEmpty()).put("hasDebugInfo", elf.sections.any { it.name.startsWith(".debug") }).put("hasEhFrame", elf.sections.any { it.name in setOf(".eh_frame", ".ARM.exidx") }))
        .put("checksums", checksums(ws.data)))
}

internal fun EngineRuntime.analyzeApk(path: String, entryLimit: Int = 500): JSONObject = guarded {
    if (path.isBlank()) return@guarded err("INVALID_ARGUMENT", "APK path is required", "path", path)
    val local = File(path)
    if (local.isFile && local.length() > ApkAnalyzer.MAX_INPUT_BYTES) return@guarded err("APK_LIMIT_EXCEEDED", "APK exceeds ${ApkAnalyzer.MAX_INPUT_BYTES / 1024 / 1024} MiB input limit", "path", path)
    if (local.isFile) {
        return@guarded try {
            local.inputStream().use { input ->
                val header = ByteArray(2)
                if (input.read(header) != 2 || header[0] != 0x50.toByte() || header[1] != 0x4b.toByte()) {
                    return@guarded err("APK_INVALID", "Input is not a ZIP/APK file", "path", path)
                }
            }
            ok(ApkAnalyzer.analyze(local, path, entryLimit))
        } catch (error: ApkAnalysisLimitException) {
            err("APK_LIMIT_EXCEEDED", error.message ?: "APK exceeds analysis limits", "path", path)
        }
    }
    val bytes = try {
        (workDir ?: return@guarded err("WORK_DIRECTORY_NOT_SELECTED", "APK path is not a local file and no work directory is selected", "path", path)).readFile(path, ApkAnalyzer.MAX_INPUT_BYTES)
    } catch (error: ApkAnalysisLimitException) {
        return@guarded err("APK_LIMIT_EXCEEDED", error.message ?: "APK exceeds analysis limits", "path", path)
    }
    if (bytes.size < 4 || bytes[0] != 0x50.toByte() || bytes[1] != 0x4b.toByte()) return@guarded err("APK_INVALID", "Input is not a ZIP/APK file", "path", path)
    try {
        ok(ApkAnalyzer.analyze(bytes, path, entryLimit))
    } catch (error: ApkAnalysisLimitException) {
        err("APK_LIMIT_EXCEEDED", error.message ?: "APK exceeds analysis limits", "path", path)
    }
}

internal fun EngineRuntime.openUrl(url: String, outputName: String = "", temporary: Boolean = false): JSONObject = guarded {
    val dir = workDir ?: return@guarded err("WORK_DIRECTORY_NOT_SELECTED", "A work directory must be selected before downloading a SO URL")
    val parsed = runCatching { URL(url.trim()) }.getOrNull() ?: return@guarded err("INVALID_ARGUMENT", "url must be a valid http(s) URL", "url", url)
    val timeout = SettingsStore(context).requestTimeoutMs
    val maxBytes = 256L * 1024L * 1024L

    // 逐跳校验后再跟随重定向（2026-09-18 安全加固）：此前开
    // instanceFollowRedirects，302 一跳就能绕过目标检查打到内网/本机地址，
    // 所以关闭自动跟随，自己跟并在每一跳复用 UrlTargetGuard。
    var target = parsed
    var redirects = 0
    var conn: HttpURLConnection
    while (true) {
        if (target.protocol !in setOf("http", "https")) return@guarded err("UNSUPPORTED_URL_SCHEME", "Only http and https URLs are supported", "url", url)
        UrlTargetGuard.rejectReason(target)?.let { reason ->
            return@guarded err("URL_TARGET_BLOCKED", "Download target rejected: $reason", "url", target.toString())
        }
        conn = (target.openConnection() as HttpURLConnection).apply { connectTimeout = timeout.coerceAtMost(30_000); readTimeout = timeout; instanceFollowRedirects = false; requestMethod = "GET" }
        val status = conn.responseCode
        if (status !in 300..399) break
        val location = conn.getHeaderField("Location")
        conn.disconnect()
        if (location.isNullOrBlank()) return@guarded err("DOWNLOAD_FAILED", "HTTP $status redirect without a Location header", "url", target.toString())
        if (++redirects > 3) return@guarded err("TOO_MANY_REDIRECTS", "Download redirected more than 3 times", "url", url)
        target = runCatching { URL(target, location) }.getOrNull()
            ?: return@guarded err("INVALID_ARGUMENT", "redirect target is not a valid URL", "url", location)
    }
    val status = conn.responseCode
    if (status !in 200..299) return@guarded err("DOWNLOAD_FAILED", "HTTP download failed with status $status", "url", target.toString())
    if (conn.contentLengthLong > maxBytes) return@guarded err("DOWNLOAD_TOO_LARGE", "SO download exceeds 256 MiB limit", "contentLength", conn.contentLengthLong)
    val bytes = conn.inputStream.use { input -> java.io.ByteArrayOutputStream().apply { val buf = ByteArray(64 * 1024); var total = 0L; while (true) { val n = input.read(buf); if (n < 0) break; total += n; if (total > maxBytes) return@guarded err("DOWNLOAD_TOO_LARGE", "SO download exceeds 256 MiB limit", "url", url); write(buf, 0, n) } }.toByteArray() }
    if (bytes.size < 4 || bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()) return@guarded err("NOT_ELF_SO", "Downloaded file is not an ELF/SO file", "url", url)
    val rawName = outputName.ifBlank { target.path.substringAfterLast('/').substringBefore('?').ifBlank { "downloaded.so" } }
    val safeName = rawName.substringAfterLast('/').substringAfterLast('\\').let { if (it.endsWith(".so", ignoreCase = true)) it else "$it.so" }
    val source = dir.writeRootFile(safeName, bytes)
    sources = (sources.filterNot { it.path == source.path } + source).sortedBy { it.path }
    sourceFingerprint = emptyList()
    sourceSummaryCache.clear()
    open(source.path, temporary).put("download", JSONObject().put("url", target.toString()).put("savedAs", source.path).put("size", bytes.size).put("sha256_16", sha256(bytes).take(16)))
}

internal fun EngineRuntime.listWorkspaces(): JSONObject = guarded {
    val items = JSONArray()
    workspaces.values.sortedBy { it.source.path }.forEach { ws -> items.put(JSONObject().put("workspaceId", ws.id).put("path", ws.source.path).put("filePath", ws.source.path).put("soFileName", ws.source.name).put("source", ws.source.source).put("apkPath", ws.source.apkPath).put("apkEntry", ws.source.apkEntry).put("abi", ws.source.abi).put("architecture", ws.elf.architecture).put("bits", ws.elf.bits).put("temporary", ws.temporary)) }
    ok(JSONObject().put("items", items).put("count", items.length()))
}

/**
 * D20（2026-09-21 自检）：句柄映射——一次调用把两类句柄的对应关系说清楚。
 *
 * 背景：`jobId`（Blutter）与 `workspaceId`（Rizin/SO 引擎）互不可推，也不共享
 * 生命周期；调用方为了确认"两者是不是同一个产物"只能自己比对 VA 与 fileOffset
 * （实测多花 3~4 次调用）。这里按**输入路径**对齐两侧（同一 APK / 同一 .so 就是
 * 同一产物），并显式给出对齐依据与两侧各自的地址口径说明，不必再手工推断。
 *
 * 只读：不改任何句柄状态。
 */
internal fun EngineRuntime.handles(blutterJobs: JSONArray): JSONObject = guarded {
    val workspacesJson = listWorkspaces()
    linkArtifactHandles(
        workspacesJson.optJSONArray("items") ?: JSONArray(),
        blutterJobs,
    )
}

/**
 * D20 的对齐逻辑（纯函数，可单测）：按输入路径把两类句柄配成对。
 *
 * 对齐依据只用**规范化后的输入路径**（同一 APK / 同一 .so 即同一产物）——
 * 不猜、不用 VA 反推。配不上的两侧都如实列出并说明原因，而不是静默丢弃。
 */
internal fun linkArtifactHandles(workspaceItems: JSONArray, blutterJobs: JSONArray): JSONObject {
    fun norm(path: String): String = path.replace('\\', '/').trimEnd('/').lowercase()

    val links = JSONArray()
    val unmatchedWorkspaces = JSONArray()
    val matchedJobIds = linkedSetOf<String>()

    for (i in 0 until workspaceItems.length()) {
        val ws = workspaceItems.optJSONObject(i) ?: continue
        val wsKeys = linkedSetOf<String>()
        ws.optString("apkPath").takeIf { it.isNotBlank() }?.let { wsKeys.add(norm(it)) }
        ws.optString("path").takeIf { it.isNotBlank() }?.let { wsKeys.add(norm(it)) }
        var matched: JSONObject? = null
        for (j in 0 until blutterJobs.length()) {
            val job = blutterJobs.optJSONObject(j) ?: continue
            val jobPath = job.optString("requestPath").takeIf { it.isNotBlank() } ?: continue
            if (norm(jobPath) in wsKeys) {
                matched = job
                break
            }
        }
        if (matched == null) {
            unmatchedWorkspaces.put(JSONObject()
                .put("workspaceId", ws.optString("workspaceId"))
                .put("apkPath", ws.optString("apkPath"))
                .put("path", ws.optString("path"))
                .put("note", "没有输入路径相同的 Blutter job。要么还没对该包跑过 blutter，要么它是以 APK 内条目方式打开的（apkEntry 非空时 requestPath 记的是 APK，不是条目）。"))
            continue
        }
        matchedJobIds.add(matched.optString("jobId"))
        links.put(JSONObject()
            .put("workspaceId", ws.optString("workspaceId"))
            .put("jobId", matched.optString("jobId"))
            .put("matchBasis", "input_path")
            .put("apkPath", ws.optString("apkPath"))
            .put("soPath", ws.optString("path"))
            .put("soFileName", ws.optString("soFileName"))
            .put("apkEntry", ws.optString("apkEntry"))
            .put("jobHasResult", matched.optBoolean("hasResult"))
            .put("jobResultKey", matched.opt("resultKey") ?: JSONObject.NULL)
            .put("addressNote",
                "两侧地址口径不同，不要互相套用：workspaceId 侧的 locator/VA 是 **该 .so 的 ELF 虚拟地址**" +
                    "（PT_LOAD 映射后的 vaddr）；Blutter 的 poolOffset 是**对象池偏移**（pp+0x…），" +
                    "它的引用 VA 才与 ELF vaddr 同域。要拿文件偏移用 refs[].fileOffset 或 " +
                    "so_analyze(action=blutter, blutterAction=pool) 返回的 ledger 原文，不要手工做 VA↔fileOffset 换算。"))
    }

    val orphanJobs = JSONArray()
    for (j in 0 until blutterJobs.length()) {
        val job = blutterJobs.optJSONObject(j) ?: continue
        if (job.optString("jobId") in matchedJobIds) continue
        orphanJobs.put(JSONObject()
            .put("jobId", job.optString("jobId"))
            .put("requestPath", job.optString("requestPath"))
            .put("status", job.optString("status"))
            .put("hasResult", job.optBoolean("hasResult"))
            .put("note", "没有对应的打开工作区（Rizin 侧会话可能已关闭或从未打开）。直接用 jobId 调 blutterAction=pool/xref/disasm 即可，不必先开工作区。"))
    }

    return ok(JSONObject()
        .put("workspaces", workspaceItems)
        .put("blutterJobs", blutterJobs)
        .put("links", links)
        .put("linkCount", links.length())
        .put("unmatchedWorkspaces", unmatchedWorkspaces)
        .put("orphanBlutterJobs", orphanJobs)
        .put("lifecycleNote",
            "两类句柄生命周期独立：workspaceId 随 Rizin 会话（close/清缓存即失效），" +
                "jobId 随工作目录下的产物（<工作目录>/SoLab/blutter/v1，验证后清理不再删它，只在源包变化或显式 prune 时清）。" +
                "要跨会话复用请用 jobId + 输入路径，不要依赖 workspaceId。"))
}

internal fun EngineRuntime.close(workspaceId: String): JSONObject = guarded {
    workspaces.remove(workspaceId)?.let { workspace ->
        workspace.edits.values.forEach(::clearSessionSnapshots)
        workspaceBySourceKey.entries.removeAll { it.value == workspaceId }
    }
    pageStore.clear()
    searchCache.clear()
    AppLog.i("Closed $workspaceId")
    ok(JSONObject().put("success", true))
}

internal fun EngineRuntime.clearCaches() {
    emulatorSessions.values.forEach { session -> session.live?.let(unidbg::closeSession) }
    emulatorSessions.clear()
    // 内存压力/切后台清理（v6 D1 / F-05 根因）：**带编辑会话的工作区不能清**——
    // 编辑会话只活在内存里，清掉后 edit_hex 必报 EDIT_SESSION_NOT_FOUND
    // （真机上表现为 edit_open 之后立刻失效：每次工具执行前的 relievePressure
    // 与 UI_HIDDEN 的 cleanupAll 都会走到这里）。只回收没有编辑会话的干净工作区；
    // 有会话的保留数据与 edits，其余缓存照常清。
    val kept = workspaces.values.filter { it.edits.isNotEmpty() }
    val keptIds = kept.map { it.id }.toSet()
    workspaces.values.removeIf { it.edits.isEmpty() }
    if (kept.isNotEmpty()) {
        AppLog.i("Index caches cleared; kept ${kept.size} workspace(s) with live edit sessions")
    }
    sources = emptyList()
    sourceFingerprint = emptyList()
    sourceSummaryCache.clear()
    // 索引只保留指向保活工作区的映射，其余清掉（清空全部会让重开同一文件
    // 走不到保活对象，见 openWorkspace 的按 id 命中兜底）。
    workspaceBySourceKey.entries.removeIf { it.value !in keptIds }
    pageStore.clear()
    searchCache.clear()
    unidbg.clearTempFiles()
    workDir?.clearPersistentCache()
    AppLog.i("Index caches cleared")
}

internal fun EngineRuntime.openWorkspace(path: String, temporary: Boolean): Workspace {
    val archiveEntry = path.substringAfterLast('!', "")
    if (archiveEntry.isNotBlank() && !archiveEntry.endsWith(".so", ignoreCase = true)) error("NOT_ELF_INPUT: $path is an APK/JAR entry, not an ELF SO file. Use apk_analyze or an APK MCP tool.")
    // 裸 APK 路径：禁止静默取 sources 索引的第一个 SO（真实踩坑：打开广告
    // SDK 的 libPglbizssdk_ml.so 而非业务主库）。多 so 时优先 libapp.so
    // （Flutter Dart 快照主库，绝大多数修改任务的目标）；无 libapp 则
    // 报错列出全部条目，要求显式传 '<apk>!<entry>'。
    var apkResolved: SoSource? = null
    val bare = path.substringBefore('!')
    if (archiveEntry.isBlank() && bare.substringAfterLast('/', "").lowercase().endsWith(".apk")) {
        workDir?.let { ensureSources(it) }
        val apkName = bare.substringAfterLast('/')
        val entries = sources.filter { it.source == "apk" && it.apkPath?.substringAfterLast('/') == apkName }
        apkResolved = when {
            entries.size == 1 -> entries.first()
            entries.size > 1 -> entries.firstOrNull { it.apkEntry?.endsWith("libapp.so") == true }
                ?: error("AMBIGUOUS_APK_ENTRY: $apkName 含 ${entries.size} 个 SO 条目且无 libapp.so，禁止静默选择第一个。请用完整条目路径 '<apk>!<entry>' 显式指定。可用条目: ${entries.joinToString(", ") { it.apkEntry ?: it.name }}")
            else -> null
        }
    }
    val keyFallback = "local:$path"
    val src = apkResolved ?: (findSource(path) ?: resolveLocalSoSource(path) ?: error("SO path not found: $path"))
    val key = sourceKey(src).ifBlank { keyFallback }
    workspaceBySourceKey[key]?.let { existingId -> workspaces[existingId]?.let {
        it.lastAccessMillis = System.currentTimeMillis()
        return it
    } }
    // id 是确定性的（见下），清理内存缓存后索引可能被裁剪——按 id 再命中一次，
    // 命中即复用（**保留其中的编辑会话**），并顺手修复索引。
    val derivedId = "so-ws-" + sha256(key.toByteArray()).take(16)
    workspaces[derivedId]?.let { existing ->
        existing.lastAccessMillis = System.currentTimeMillis()
        workspaceBySourceKey[key] = derivedId
        return existing
    }
    val original = when (src.source) { "build_output", "local_file", "extracted" -> runCatching { File(src.path).readBytes() }.getOrElse { error("SO path not found: $path") }; else -> (workDir ?: error("No work directory selected")).readSource(src) }
    require(original.size >= 4 && original[0] == 0x7f.toByte() && original[1] == 'E'.code.toByte() && original[2] == 'L'.code.toByte() && original[3] == 'F'.code.toByte()) { "NOT_ELF_INPUT: ${src.path} is not an ELF SO file. Use apk_analyze or an APK MCP tool." }
    val prepared = prepareAnalysisInput(original)
    // id 由 sourceKey 确定性派生（非随机 UUID）：进程被杀重启后重新 open
    // 同一文件得到相同 id，AI 手里的旧 workspaceId 直接复活，长任务跨
    // 进程重启不断链（WORKSPACE_NOT_FOUND 只需重 open 一次）。
    val ws = Workspace("so-ws-" + sha256(key.toByteArray()).take(16), src, prepared.first, lief.parse(prepared.first), temporary, sha256(original), prepared.second, prepared.third)
    while (workspaces.size >= EngineRuntime.MAX_WORKSPACES) {
        if (!evictWorkspaceForOpen()) error("WORKSPACE_CAPACITY_REACHED: close an active edit session before opening another workspace")
    }
    workspaces[ws.id] = ws
    workspaceBySourceKey[key] = ws.id
    AppLog.i("Opened ${src.path} as ${ws.id}")
    return ws
}

internal fun EngineRuntime.prepareAnalysisInput(original: ByteArray): Triple<ByteArray, String, JSONObject> {
    val before = lief.parse(original)
    val facts = JSONObject().put("attempted", false).put("changed", false).put("sectionsBefore", before.sections.size).put("programHeadersBefore", before.programHeaders.size).put("symbolsBefore", before.symbols.size).put("dynSymbolsBefore", before.dynSymbols.size).put("functionSymbolsRecovered", false)
    if (before.sections.isNotEmpty()) return Triple(original, "original", facts.put("reason", "section_table_present"))
    if (original.size < 5 || !xanso.available()) return Triple(original, "original", facts.put("reason", if (original.size < 5) "invalid_elf_ident" else "xanso_unavailable"))
    facts.put("attempted", true)
    val recovered = when (original[4].toInt() and 0xff) { 1 -> xanso.buildSections(original); 2 -> xanso.recoverElf64Sections(original)?.let { lief.fixSections(it) }; else -> null }
    if (recovered == null || recovered.isEmpty()) return Triple(original, "original", facts.put("reason", "xanso_recovery_failed"))
    val after = lief.parse(recovered)
    if (after.sections.isEmpty()) return Triple(original, "original", facts.put("reason", "recovered_section_table_not_parseable"))
    facts.put("changed", !recovered.contentEquals(original)).put("reason", "missing_section_table").put("recoveryMode", if ((original[4].toInt() and 0xff) == 1) "xanso32_section_fix" else "xanso64_section_recovery_lief_finalize").put("sectionsAfter", after.sections.size).put("programHeadersAfter", after.programHeaders.size).put("symbolsAfter", after.symbols.size).put("dynSymbolsAfter", after.dynSymbols.size).put("functionSymbolsRecovered", after.symbols.count { it.type == "FUNC" } > before.symbols.count { it.type == "FUNC" })
    return Triple(recovered, "xanso_recovered_sections", facts)
}

internal fun EngineRuntime.resolveLocalSoSource(rawPath: String): SoSource? {
    if (rawPath.isBlank()) return null
    val file = File(rawPath)
    if (!file.exists() || !file.isFile) return null
    val extDir = context.getExternalFilesDir(null)?.canonicalPath
    val intDir = context.filesDir.canonicalPath
    val workDirPath = workDir?.takeIf { it.isPathMode }?.rootPath
    val canonical = runCatching { file.canonicalPath }.getOrDefault(rawPath)
    // 统一工作路径：应用私有目录 或 工作目录内的 .so 均可打开（修复"AI 工具识别不到"）
    val allowed = listOfNotNull(extDir, intDir, workDirPath).any { canonical.startsWith(it) }
    if (!allowed || !file.name.endsWith(".so", ignoreCase = true)) return null
    // canonical 只用于白名单判定（/data/user/0 等符号链接形态也能命中 /data/data 白名单）；
    // 对外保留调用方传入的原始路径，避免 inputPath 被重写成调用方不认识的形态。
    // v6 D15/F-28：来源标注此前一律 "build_output"（连从 APK 解出来的 so 也这么标）。
    // 按位置分类：工作目录下 SO 解包区（so/、unzip*/、extracted*/、assets/…）标
    // "extracted"；其余本地文件标 "local_file"；build_output 只留给构建产物。
    val lower = canonical.replace('\\', '/').lowercase()
    val inExtractionArea = workDirPath != null &&
        canonical.startsWith(workDirPath) &&
        listOf("/so/", "/unzip", "/extracted", "/apk_extract", "/assets/")
            .any { lower.contains(it) }
    val source = if (inExtractionArea) "extracted" else "local_file"
    // v6 D21 / F-16：回执里 sourcePath 曾与 outputPath 拼写不一致
    //（/data/user/0 vs /data/data，同一文件两种根）。统一返回 canonical，
    // 与 outputPath（workDir 的 canonical 根）同一套拼写；解析入参不受影响
    //（调用方仍可用原路径重开）。
    return SoSource(canonical, source, file.name, file.length(), file.lastModified(), null)
}

internal fun EngineRuntime.findSource(rawPath: String): SoSource? {
    if (rawPath.isBlank()) return null
    val path = rawPath.trim().removePrefix("/")
    workDir?.let { ensureSources(it) }
    val apkUri = rawPath.trim().removePrefix("content://apk/")
    if (apkUri != rawPath.trim() && apkUri.isNotBlank()) {
        val separator = apkUri.indexOf('/')
        if (separator > 0) sources.firstOrNull { it.source == "apk" && it.apkPath?.substringAfterLast('/') == apkUri.substring(0, separator) && it.apkEntry == apkUri.substring(separator + 1) }?.let { return it }
    }
    return sources.firstOrNull { it.path == rawPath || it.path == path } ?: sources.firstOrNull { it.name == rawPath || it.name == path } ?: sources.firstOrNull { it.apkEntry == rawPath || it.apkEntry == path } ?: sources.firstOrNull { it.path.endsWith("/$path") || it.path.contains(path) }
}

internal fun EngineRuntime.ensureSources(dir: WorkDirectory): List<SoSource> {
    val settings = SettingsStore(context)
    val options = scanOptions(settings)
    if (!settings.indexCacheEnabled) { sources = dir.listSos(options); sourceFingerprint = sources.map { FileFingerprint(it.path, it.size, it.modified) }; return sources }
    val nextFingerprint = dir.fingerprint(options)
    if (sources.isNotEmpty() && nextFingerprint == sourceFingerprint) return sources
    sources = dir.listSos(options)
    sourceFingerprint = nextFingerprint
    pageStore.clear()
    AppLog.i("Scanned ${sources.size} SO entries")
    return sources
}

internal fun EngineRuntime.scanOptions(settings: SettingsStore): ScanOptions = ScanOptions(settings.scanApks, settings.scanSubdirectories, settings.maxScanDepth, settings.skipFilesLargerThanMb.toLong() * 1024L * 1024L)

internal fun EngineRuntime.sourceSummary(dir: WorkDirectory, src: SoSource): SourceSummary {
    if (!SettingsStore(context).parseMetadataInList) return SourceSummary("unknown", 0, "little", false, false)
    return sourceSummaryCache.getOrPut(sourceKey(src)) {
        dir.cachedSummary(src)?.let { return@getOrPut SourceSummary(it.architecture, it.bits, it.endian, it.hasDebugInfo, it.stripped) }
        runCatching { lief.parse(dir.readSource(src)).let { elf -> SourceSummary(elf.architecture, elf.bits, elf.endian, elf.sections.any { it.name.startsWith(".debug") }, elf.symbols.isEmpty()).also { dir.putCachedSummary(src, CachedSourceSummary(it.architecture, it.bits, it.endian, it.hasDebugInfo, it.stripped)) } } }.getOrElse { SourceSummary("unknown", 0, "little", false, true) }
    }
}

internal fun EngineRuntime.sourceKey(src: SoSource): String = "${src.path}|${src.size}|${src.modified}"
