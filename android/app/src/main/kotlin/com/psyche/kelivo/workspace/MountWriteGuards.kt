package com.psyche.kelivo.workspace

import java.io.File

/** Best-effort guards for common shell commands, like Minis. Not a sandbox. */
internal object MountWriteGuards {
    private const val MARKER = "# kelivo-mount-readonly-guard"
    private const val CONFIG = "/run/kelivo/mount-readonly-prefixes"
    private val commands = listOf("touch", "tee", "cp", "mv", "mkdir", "rm", "rmdir", "ln", "dd")

    fun install(rootfs: File, mounts: List<BindMount>) {
        val prefixes = mounts.filter { it.readOnly }.map { it.guest }.toMutableList()
        // F-01（2026-10-05 复测仍现）：/skills 是**内置只读区**，但它的挂载走
        // Dart 侧 _workspaceMounts（不含在 externalMounts 里），过去守卫配置
        // 里从来没有 /skills——`touch /skills/x` 直接穿透。这里硬编码加上：
        // /skills 在这个产品里永远是只读的，与 file 通道的 skills_readonly 对齐。
        if ("/skills" !in prefixes) prefixes.add("/skills")
        val root = rootfs.canonicalFile.toPath()
        // Canonical paths follow links, and an imported image may contain
        // guest-absolute ones (e.g. /usr/local/bin -> /sdcard). Install only
        // when the targets resolve inside the rootfs, never through a link.
        val bin = File(rootfs, "usr/local/bin").canonicalFile.takeIf { it.toPath().startsWith(root) }
        val config = File(rootfs, CONFIG.removePrefix("/")).canonicalFile.takeIf { it.toPath().startsWith(root) }
        if (bin == null || config == null) {
            android.util.Log.w(
                "KelivoWorkspace",
                "skipping mount write guards: ${rootfs.absolutePath} has a link escaping the rootfs",
            )
            return
        }
        // 空前缀列表**不清除**已装守卫（2026-10-03 报告 F-01「/skills 护栏失效」的
        // 一类真因：安装顺序不稳定时，先带空 mounts 的调用会把守卫全删掉，
        // 之后即使只读挂载到位也没有守卫了）。改为写入空配置——守卫脚本在运行时
        // 读配置，空配置下自然放行，下一次带只读挂载的调用会把前缀写回来。
        //
        // 2026-10-04 复查再加固（F-01 仍未修的真因之一）：**配置只增不减**。
        // 若某次 install 拿到的 mounts 列表不含 /skills（列表不完整/顺序抖动），
        // 覆盖写会把已生效的 /skills 前缀抹掉——真机 `touch /skills/x` 就是在
        // 这种状态下成功的。改为与现有配置**求并集**：只读前缀一旦声明过就
        // 持续生效（数据安全方向 fail-closed），只读挂载真的去掉时由 rootfs
        // 重装自然清空。
        config.parentFile!!.mkdirs()
        val existing = runCatching {
            config.readText().lines().map { it.trim() }.filter { it.isNotEmpty() }
        }.getOrDefault(emptyList())
        val merged = LinkedHashSet<String>(existing).apply { addAll(prefixes) }
        config.writeText(merged.joinToString("\n", postfix = "\n"))
        bin.mkdirs()
        for (name in commands) {
            val wrapper = File(bin, name)
            // Do not replace user-installed commands or symlinks.
            if (wrapper.canonicalFile != wrapper.absoluteFile) continue
            if (wrapper.exists() && !isOurWrapper(wrapper)) continue
            val script = commandScript(name)
            if (!wrapper.exists() || wrapper.readText() != script) wrapper.writeText(script)
            check(wrapper.setExecutable(true, false)) { "Cannot install mount write guard" }
        }
    }

    private fun isOurWrapper(file: File): Boolean {
        if (!file.isFile || file.canonicalFile != file.absoluteFile) return false
        return file.inputStream().use { input ->
            val prefix = ByteArray(80)
            val size = input.read(prefix)
            size > 0 && String(prefix, 0, size, Charsets.UTF_8).startsWith("#!/bin/sh\n$MARKER\n")
        }
    }

    internal fun commandScript(name: String, config: String = CONFIG): String {
        require(name in commands)
        val quotedConfig = "'" + config.replace("'", "'\"'\"'") + "'"
        return """#!/bin/sh
            |$MARKER
            |cfg=$quotedConfig
            |check_target() {
            |    [ -f "${'$'}cfg" ] || return 0
            |    # GNU realpath supports missing parents; BusyBox readlink handles
            |    # existing symlink parents without requiring coreutils on Alpine.
            |    resolved=${'$'}(PATH=/usr/bin:/bin realpath -m -- "${'$'}1" 2>/dev/null) ||
            |        resolved=${'$'}(PATH=/usr/bin:/bin readlink -f -- "${'$'}1" 2>/dev/null) || resolved="${'$'}1"
            |    case "${'$'}resolved" in /*) ;; *) resolved="${'$'}PWD/${'$'}resolved";; esac
            |    while IFS= read -r prefix; do
            |        [ -n "${'$'}prefix" ] || continue
            |        case "${'$'}resolved" in
            |            "${'$'}prefix"|"${'$'}prefix"/*)
            |                printf '%s\n' "$name: ${'$'}1: read-only mounted folder; enable writes in Environment settings" >&2
            |                exit 1;;
            |        esac
            |    done < "${'$'}cfg"
            |}
            |# Match Minis' common-command coverage. Redirection, interpreters,
            |# absolute executable paths and other programs can bypass wrappers.
            |for arg do
            |    case "${'$'}arg" in
            |        -*) continue;;
            |    esac
            |    if [ "$name" = dd ]; then
            |        case "${'$'}arg" in of=*) check_target "${'$'}{arg#of=}";; esac
            |    else
            |        check_target "${'$'}arg"
            |    fi
            |done
            |PATH=/usr/bin:/bin exec $name "${'$'}@"
            |""".trimMargin()
    }
}
