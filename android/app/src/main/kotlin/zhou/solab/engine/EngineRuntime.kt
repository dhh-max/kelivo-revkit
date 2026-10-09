package zhou.solab.engine

import android.content.Context
import android.net.Uri
import zhou.solab.tools.AppLog
import zhou.solab.tools.err
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CancellationException
import java.util.concurrent.ConcurrentHashMap

internal class EngineRuntime(internal val context: Context) {
    companion object {
        internal const val MAX_WORKSPACES = 3
    }
    internal val lief = LiefEngine()
    internal val xanso = XAnSoEngine(context)
    internal val unidbg = UnidbgEmulator(context)
    internal val blutter = BlutterCoordinator(context)
    internal var workDir: WorkDirectory? = null
    internal var workDirUri: Uri? = null
    internal var sources: List<SoSource> = emptyList()
    internal var sourceFingerprint: List<FileFingerprint> = emptyList()
    internal val sourceSummaryCache = ConcurrentHashMap<String, SourceSummary>()
    internal val workspaceBySourceKey = ConcurrentHashMap<String, String>()
    internal val pageStore = PageStore()
    internal val emulatorSessions = ConcurrentHashMap<String, EmulatorSession>()
    internal val searchCache = ConcurrentHashMap<String, List<JSONObject>>()
    internal val workspaces = ConcurrentHashMap<String, Workspace>()

    internal fun evictWorkspaceForOpen(): Boolean {
        val victim = workspaces.values
            .filter { it.edits.isEmpty() }
            .minByOrNull { it.lastAccessMillis }
            ?: return false
        workspaces.remove(victim.id)
        workspaceBySourceKey.entries.removeAll { it.value == victim.id }
        victim.edits.values.forEach(::clearSessionSnapshots)
        pageStore.clear()
        searchCache.clear()
        return true
    }

    internal fun guarded(block: () -> JSONObject): JSONObject = try {
        block()
    } catch (error: CancellationException) {
        throw error
    } catch (error: Exception) {
        AppLog.e("Tool failed", error)
        val message = error.message ?: "Tool failed"
        when {
            message.startsWith("Workspace not found") && message.substringAfterLast(": ", "").isBlank() -> err("WORKSPACE_REQUIRED", "No workspaceId was provided. Call so_analyze(action=open) first and use its returned workspaceId.", "workspaceId", "")
            message.startsWith("Workspace not found") -> err("WORKSPACE_NOT_FOUND", "$message. Call so_analyze(action=open) again and use its returned workspaceId.", "workspaceId", message.substringAfterLast(": ", ""))
            message.startsWith("No work directory selected") -> err("WORK_DIRECTORY_NOT_SELECTED", message)
            message.startsWith("NOT_ELF_INPUT") -> err("NOT_ELF_INPUT", message.substringAfter(": ").ifBlank { "The selected entry is not an ELF SO file." })
            message.startsWith("SO path not found") -> err("SO_NOT_FOUND", message, "path", message.substringAfter(": ", ""))
            // F-44（2026-10-04）：编辑会话消失的抛出点（Read.kt 的 dataFor 等）
            // 过去落进 else 被误转成 ELF_CORRUPTED——错误码指向"文件损坏"，
            // 调用方会去重析 SO 而不是重开会话。
            message.startsWith("Edit session not found") -> err("EDIT_SESSION_NOT_FOUND", "$message. Edit sessions do NOT survive process restarts or memory cleanup — call so_analyze(action=edit_open) again and redo previews with the fresh session.", "editSessionId", message.substringAfterLast(": ", ""))
            message.contains("Invalid URI", ignoreCase = true) -> err("INVALID_WORK_DIRECTORY", message)
            else -> err("ELF_CORRUPTED", message)
        }
    }

    internal fun hex(v: Long) = "0x${v.toString(16)}"
    internal fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    internal fun checksums(bytes: ByteArray) = JSONObject().put("sha256", sha256(bytes)).put("size", bytes.size)

    internal fun artifactDir(kind: String): File {
        val root = workDir?.takeIf { it.isPathMode }?.rootPath
            ?: error("No work directory selected. Configure a filesystem work directory before writing artifacts.")
        val dir = File(root, "SoLab/output/$kind")
        if (!dir.exists() && !dir.mkdirs()) error("Cannot create artifact directory: ${dir.absolutePath}")
        return dir
    }
}
