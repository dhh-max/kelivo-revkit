package com.psyche.kelivo.workspace

import android.app.Activity
import android.content.Intent
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.StatFs
import android.util.Log
import android.view.WindowManager
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.util.concurrent.Executors

class WorkspacePlugin(private val context: Context) {
    private var attachedActivity: Activity? = null
    fun attachActivity(activity: Activity) {
        attachedActivity = activity
        directories.attachActivity(activity)
    }
    fun detachActivity(activity: Activity) {
        if (attachedActivity !== activity) return
        attachedActivity = null
        directories.detachActivity(activity)
    }
    companion object {
        const val CHANNEL_NAME = "app.workspace"
        const val EVENT_CHANNEL_NAME = "app.workspace/events"

        // A 32-bit APK can run on an ARM64 device. Match the app's native
        // libraries, not the device's preferred ABI, when selecting a rootfs.
        internal fun runtimeAbi(
            is64Bit: Boolean = Process.is64Bit(),
            abis: Array<String> = Build.SUPPORTED_ABIS,
        ): String {
            val supported = if (is64Bit) listOf("arm64-v8a", "x86_64") else listOf("armeabi-v7a")
            return abis.firstOrNull { it in supported } ?: ""
        }
    }

    private val executor = Executors.newCachedThreadPool()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val events = WorkspaceEvents()
    private val execRunner = ExecRunner(events)
    private val ptySessions = PtySessions(events)
    private val directories = WorkspaceDirectoryAccess(context)
    private var externalMounts = emptyList<BindMount>()
    private var environmentBusy = false

    fun configure(messenger: BinaryMessenger) {
        EventChannel(messenger, EVENT_CHANNEL_NAME).setStreamHandler(events)
        MethodChannel(messenger, CHANNEL_NAME).setMethodCallHandler { call, result ->
            try {
                when (call.method) {
                    "probe" -> result.success(probe())
                    "setEnvironmentBusy" -> {
                        environmentBusy = asMap(call.arguments)["busy"] == true
                        if (environmentBusy) {
                            execRunner.cancelAll()
                            ptySessions.closeAll()
                        }
                        result.success(null)
                    }
                    "inspectRootfs" -> runAsync(result, "invalid_rootfs") {
                        val args = asMap(call.arguments)
                        RootfsInfo.inspect(File(requiredString(args, "rootfsDir")), requiredString(args, "arch"))
                    }
                    "setExternalMounts" -> {
                        val next = parseBinds(asMap(call.arguments)["mounts"])
                        validateExternalMounts(next)
                        if (next != externalMounts) {
                            execRunner.cancelAll()
                            ptySessions.closeAll()
                            externalMounts = next
                        }
                        result.success(null)
                    }
                    "hasDirectoryStorageAccess" -> result.success(directories.hasStorageAccess())
                    "requestDirectoryStorageAccess" -> directories.requestStorageAccess(result)
                    "pickDirectory" -> directories.pick(result)
                    "resolveDirectory" -> runAsync(result, "external_folder_unavailable") {
                        directories.resolve(requiredString(asMap(call.arguments), "token"))
                    }
                    "releaseDirectory" -> runAsync(result) {
                        directories.release(requiredString(asMap(call.arguments), "token"))
                        null
                    }
                    "exec" -> {
                        require(!environmentBusy) { "environment is being replaced" }
                        exec(asMap(call.arguments))
                        result.success(mapOf("started" to true))
                    }
                    "stdinWrite" -> runAsync(result) {
                        val args = asMap(call.arguments)
                        execRunner.writeStdin(requiredString(args, "runId"), args["data"] as ByteArray)
                        null
                    }
                    "cancel" -> {
                        val runId = asMap(call.arguments)["runId"]?.toString().orEmpty()
                        result.success(runId.isNotEmpty() && execRunner.cancel(runId))
                    }
                    "ptyOpen" -> {
                        require(!environmentBusy) { "environment is being replaced" }
                        result.success(mapOf("pid" to ptyOpen(asMap(call.arguments))))
                    }
                    "ptyWrite" -> {
                        ptyWrite(asMap(call.arguments))
                        result.success(null)
                    }
                    "ptyResize" -> {
                        ptyResize(asMap(call.arguments))
                        result.success(null)
                    }
                    "ptyClose" -> {
                        val sessionId = asMap(call.arguments)["sessionId"]?.toString().orEmpty()
                        if (sessionId.isNotEmpty()) ptySessions.close(sessionId)
                        result.success(null)
                    }
                    "extractRootfs" -> runAsync(result) { extractRootfs(asMap(call.arguments)) }
                    "patchRootfs" -> runAsync(result) { patchRootfs(asMap(call.arguments)) }
                    "sha256File" -> runAsync(result) {
                        Sha256.file(asMap(call.arguments)["path"]?.toString().orEmpty())
                    }
                    "keepScreenOn" -> {
                        keepScreenOn(asMap(call.arguments)["enabled"] == true)
                        result.success(null)
                    }
                    "freeSpace" -> result.success(freeSpace(asMap(call.arguments)))
                    else -> result.notImplemented()
                }
            } catch (error: IllegalArgumentException) {
                result.error("invalid_args", error.message, null)
            } catch (error: Exception) {
                result.error("workspace", error.message, null)
            }
        }
    }

    fun dispose() {
        directories.dispose()
        execRunner.cancelAll()
        ptySessions.closeAll()
        executor.shutdownNow()
    }

    fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean =
        directories.onActivityResult(requestCode, resultCode, data)

    fun onRequestPermissionsResult(requestCode: Int): Boolean =
        directories.onRequestPermissionsResult(requestCode)

    /**
     * Extra directories searched for the packaged PRoot loader.
     * The primary location is `applicationInfo.nativeLibraryDir`, which only
     * contains libs the current APK ABI built for. Older / mixed-ABI installs
     * (e.g. an armeabi-v7a-only APK on an arm64 device) leave the loader
     * missing there and would report a false "proot missing" failure. We
     * fall back to a few well-known locations used by sibling builds, by
     * third-party apps that ship PRoot, and by common file managers.
     * User-supplied paths can be added via `extraProotSearchDirs`.
     */
    private val extraProotSearchDirs: List<String> =
        runCatching {
            val prefs = context.getSharedPreferences("workspace", context.MODE_PRIVATE)
            val raw = prefs.getString("extraProotSearchDirs", "") ?: ""
            val defaults = listOf(
                "/data/local/tmp",
                "/data/local/tmp/proot",
                "/data/data/${context.packageName}/files/proot",
                "/data/data/${context.packageName}/files",
                "/sdcard/Android/data/${context.packageName}/files/proot",
                "/sdcard/Android/data/${context.packageName}/files",
            )
            val user = raw.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
            defaults + user
        }.getOrDefault(
            listOf(
                "/data/local/tmp",
                "/data/local/tmp/proot",
                "/data/data/${context.packageName}/files/proot",
                "/data/data/${context.packageName}/files",
            ),
        )

    /**
     * Directory that actually contains the PRoot bundle the app will exec.
     * Populated by [probe]; used by [exec] / [ptyOpen] to construct argv. When
     * the primary `applicationInfo.nativeLibraryDir` does not ship the loader
     * (stale ABI builds), this can be a fallback search-root that does.
     */
    private var resolvedProotDir: File? = null

    private fun probe(): Map<String, Any?> {
        val nativeLibDir = File(context.applicationInfo.nativeLibraryDir)
        // Search the bundled lib dir first; fall back to well-known / user-
        // specified locations so that installs with a stale nativeLibraryDir
        // (e.g. missing arm64 jniLibs) do not fail with a false proot-missing.
        val searchRoots = listOf(nativeLibDir) + extraProotSearchDirs
            .map { File(it) }.filter { it.isDirectory }

        fun findIn(dirs: List<File>, names: List<String>): File? {
            for (d in dirs) for (n in names) {
                val f = File(d, n)
                if (f.isFile) return f
            }
            return null
        }

        val proot = findIn(searchRoots, listOf(ProotCommand.EXEC_LIB, "libproot.so"))
            ?: runCatching {
                // Last resort: a shell `proot` on PATH (usually needs root).
                val envPath = System.getenv("PATH") ?: "/usr/bin:/bin:/system/bin"
                envPath.split(':').map { File(it, "proot") }.firstOrNull { it.isFile && it.canExecute() }
            }.getOrNull()
        val prootDir = proot?.parentFile ?: nativeLibDir
        val loader = findIn(listOf(prootDir, nativeLibDir) + searchRoots,
            listOf(ProotCommand.LOADER_LIB, "libproot.so", "libproot-loader.so"))
        val talloc = findIn(listOf(prootDir, nativeLibDir) + searchRoots,
            listOf(ProotCommand.TALLOC_LIB, ProotCommand.TALLOC_SONAME, "libtalloc.so.2"))
        val shmem = findIn(listOf(prootDir, nativeLibDir) + searchRoots,
            listOf(ProotCommand.SHMEM_LIB, "libshmem.so"))

        proot?.let { if (it.isFile) it.setExecutable(true, false) }
        loader?.let { if (it.isFile) it.setExecutable(true, false) }

        val prootOk = proot != null && proot.isFile && proot.canExecute()
        val loaderOk = loader != null && loader.isFile && loader.canExecute()
        val tallocOk = talloc != null && talloc.isFile
        val shmemOk = shmem != null && shmem.isFile
        val supported = prootOk && loaderOk && tallocOk && shmemOk
        resolvedProotDir = if (supported) prootDir else null

        val missing = mutableListOf<String>()
        if (!prootOk) missing += "proot"
        if (!loaderOk) missing += "loader"
        if (!tallocOk) missing += "libtalloc"
        if (!shmemOk) missing += "libandroid-shmem"

        val reason = when {
            supported -> null
            !prootOk -> "proot missing or not executable (searched: ${searchRoots.map { it.absolutePath }})"
            !loaderOk -> "loader missing or not executable"
            !tallocOk -> "proot dependency missing: ${ProotCommand.TALLOC_LIB}"
            else -> "proot dependency missing: ${ProotCommand.SHMEM_LIB}"
        }

        Log.i("WorkspacePlugin", "probe: supported=$supported abi=${runtimeAbi()} " +
            "nativeLibDir=${nativeLibDir.absolutePath} " +
            "searchRoots=${searchRoots.map { it.absolutePath }} " +
            "proot=${proot?.absolutePath} loader=${loader?.absolutePath} " +
            "talloc=${talloc?.absolutePath} shmem=${shmem?.absolutePath} " +
            "missing=${missing.joinToString(",")} reason=$reason")

        return hashMapOf(
            "supported" to supported,
            "abi" to runtimeAbi(),
            "prootPath" to proot?.absolutePath,
            "loaderPath" to loader?.absolutePath,
            "nativeLibDir" to nativeLibDir.absolutePath,
            "reason" to reason,
            "missing" to missing.toList(),
            "searched" to searchRoots.map { it.absolutePath },
        )
    }

    private fun exec(args: Map<*, *>) {
        val runId = requiredString(args, "runId")
        execRunner.start(
            ExecRequest(
                runId = runId,
                nativeLibDir = resolvedProotDir ?: File(context.applicationInfo.nativeLibraryDir),
                rootfsDir = File(requiredString(args, "rootfsDir")),
                tmpDir = File(requiredString(args, "tmpDir")),
                binds = commandBinds(args),
                cwd = ProotCommand.validateGuestCwd(requiredString(args, "cwd")),
                command = requiredString(args, "command"),
                env = parseEnv(args["env"]),
                timeoutMs = number(args["timeoutMs"], 60_000L),
                keepStdinOpen = args["keepStdinOpen"] == true,
                prootArguments = parseStringList(args["prootArguments"]),
                shell = args["shell"]?.toString(),
            ),
        )
    }

    private fun ptyOpen(args: Map<*, *>): Int {
        return ptySessions.open(
            sessionId = requiredString(args, "sessionId"),
            nativeLibDir = resolvedProotDir ?: File(context.applicationInfo.nativeLibraryDir),
            rootfsDir = File(requiredString(args, "rootfsDir")),
            tmpDir = File(requiredString(args, "tmpDir")),
            binds = commandBinds(args),
            cwd = ProotCommand.validateGuestCwd(requiredString(args, "cwd")),
            env = parseEnv(args["env"]),
            cols = number(args["cols"], 80L).toInt(),
            rows = number(args["rows"], 24L).toInt(),
            prootArguments = parseStringList(args["prootArguments"]),
            shell = args["shell"]?.toString(),
        )
    }

    private fun ptyWrite(args: Map<*, *>) {
        val sessionId = requiredString(args, "sessionId")
        val data = args["data"] as? ByteArray ?: ByteArray(0)
        ptySessions.write(sessionId, data)
    }

    private fun ptyResize(args: Map<*, *>) {
        ptySessions.resize(
            sessionId = requiredString(args, "sessionId"),
            cols = number(args["cols"], 80L).toInt(),
            rows = number(args["rows"], 24L).toInt(),
        )
    }

    private fun extractRootfs(args: Map<*, *>): Map<String, Any> {
        val destDir = requiredString(args, "destDir")
        val format = requiredString(args, "format")
        var lastEmit = 0L
        RootfsExtractor.extract(
            archive = File(requiredString(args, "archivePath")),
            destDir = File(destDir),
            format = format,
        ) { entries, bytes, currentEntry ->
            val now = System.currentTimeMillis()
            if (now - lastEmit < 200L && currentEntry.isNotEmpty()) return@extract
            lastEmit = now
            events.emit(
                hashMapOf(
                    "type" to "extract",
                    "destDir" to destDir,
                    "entries" to entries,
                    "bytes" to bytes,
                    "currentEntry" to currentEntry,
                ),
            )
        }
        return mapOf("ok" to true)
    }

    private fun patchRootfs(args: Map<*, *>): Map<String, Any> {
        RootfsPatcher.patch(
            rootfsDir = File(requiredString(args, "rootfsDir")),
            dnsServers = parseStringList(args["dnsServers"]),
            hostname = args["hostname"]?.toString()?.trim().orEmpty().ifBlank { "localhost" },
            aptMirrorBaseUrl = args["aptMirrorBaseUrl"]?.toString()?.trim()?.takeIf { it.isNotEmpty() },
            ubuntuCodename = args["ubuntuCodename"]?.toString().orEmpty(),
            arch = requiredString(args, "arch"),
            // Dart declares the Android network GIDs it needs mapped into the
            // guest; /proc/self/status is only a fallback (it is empty when the
            // app process has no supplementary groups, e.g. no INTERNET).
            groupIds = (parseLongList(args["gids"]) + RootfsPatcher.readSupplementaryGids()).distinct(),
        )
        return mapOf("ok" to true)
    }

    /**
     * Disk pre-check for the Dart rootfs installer. Walks to the nearest
     * existing ancestor of [path] and reports space the app can still use.
     */
    private fun freeSpace(args: Map<*, *>): Map<String, Long> {
        val raw = requiredString(args, "path")
        var target = File(raw)
        while (!target.exists()) {
            target = target.parentFile
                ?: throw IllegalArgumentException("no existing ancestor for $raw")
        }
        val stat = StatFs(target.absolutePath)
        return mapOf(
            "freeBytes" to stat.availableBytes,
            "totalBytes" to stat.totalBytes,
        )
    }

    private fun keepScreenOn(enabled: Boolean) {
        val window = attachedActivity?.window ?: return
        if (enabled) {
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
    }

    private fun runAsync(result: MethodChannel.Result, errorCode: String = "workspace", block: () -> Any?) {
        executor.execute {
            try {
                val value = block()
                mainHandler.post { result.success(value) }
            } catch (error: Exception) {
                mainHandler.post { result.error(errorCode, error.message, null) }
            }
        }
    }

    private fun asMap(value: Any?): Map<*, *> = value as? Map<*, *> ?: emptyMap<Any, Any>()

    private fun requiredString(args: Map<*, *>, key: String): String {
        // Validate blank-ness but hand back the raw value: trimming here rewrote
        // protocol arguments silently (a directory named "my project " then
        // resolved to a different path in shell than in the file tools).
        val text = args[key]?.toString().orEmpty()
        require(text.isNotBlank()) { "missing $key" }
        return text
    }

    private fun number(value: Any?, fallback: Long): Long = when (value) {
        is Number -> value.toLong()
        is String -> value.toLongOrNull() ?: fallback
        else -> fallback
    }

    private fun parseEnv(raw: Any?): Map<String, String> {
        val map = raw as? Map<*, *> ?: return emptyMap()
        val out = LinkedHashMap<String, String>()
        for ((key, value) in map) {
            if (key == null || value == null) continue
            out[key.toString()] = value.toString()
        }
        return out
    }

    private fun parseStringList(raw: Any?): List<String> {
        val list = raw as? List<*> ?: return emptyList()
        return list.mapNotNull { it?.toString()?.trim()?.takeIf { item -> item.isNotEmpty() } }
    }

    private fun parseLongList(raw: Any?): List<Long> {
        val list = raw as? List<*> ?: return emptyList()
        return list.mapNotNull { entry ->
            when (entry) {
                is Number -> entry.toLong()
                is String -> entry.trim().toLongOrNull()
                else -> null
            }
        }
    }

    private fun parseBinds(raw: Any?): List<BindMount> {
        val list = raw as? List<*> ?: return emptyList()
        return list.mapNotNull { item ->
            val map = item as? Map<*, *> ?: return@mapNotNull null
            val host = map["host"]?.toString().orEmpty()
            val guest = map["guest"]?.toString().orEmpty()
            if (host.isBlank() || guest.isBlank()) return@mapNotNull null
            BindMount(host, guest, map["readOnly"] == true)
        }
    }

    private fun commandBinds(args: Map<*, *>): List<BindMount> {
        val rootfs = File(requiredString(args, "rootfsDir"))
        val mountRoot = File(rootfs, "mounts")
        require(mountRoot.canonicalPath.startsWith(rootfs.canonicalPath + "/"))
        mountRoot.mkdirs()
        val names = externalMounts.map { it.guest.substringAfterLast('/') }.toSet()
        // Only remove empty placeholders left by renamed or detached mounts.
        mountRoot.listFiles()?.filter { it.name !in names && it.isDirectory && it.list()?.isEmpty() == true }?.forEach { it.delete() }
        for (mount in externalMounts) {
            val target = File(mountRoot, mount.guest.substringAfterLast('/'))
            require(target.canonicalFile.parentFile == mountRoot.canonicalFile)
            target.mkdirs()
        }
        MountWriteGuards.install(rootfs, externalMounts)
        return parseBinds(args["binds"]).filterNot {
            it.guest.startsWith("/mounts/")
        } + externalMounts
    }
}
