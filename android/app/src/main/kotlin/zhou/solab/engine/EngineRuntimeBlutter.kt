package zhou.solab.engine

import org.json.JSONObject

internal fun EngineRuntime.flutterBlutter(args: JSONObject): JSONObject = guarded { blutter.handle(args, workDir) }

/**
 * D20：Blutter job 列举（供 so_analyze(action=handles) 做句柄映射）。
 * 先绑 Blutter 根（与 handle 入口一致），否则工作目录下列不到东西。
 */
internal fun EngineRuntime.blutterJobs(): JSONObject = guarded {
    blutter.bindRoot(workDir)
    blutter.listJobs()
}
