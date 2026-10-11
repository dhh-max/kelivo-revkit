package com.psyche.kelivo

import android.app.Application
import com.psyche.kelivo.background.BackgroundRuntime
import com.psyche.kelivo.workspace.WorkspacePlugin
import com.psyche.kelivo.scheduled.ScheduledTasks
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.dart.DartExecutor

/** One Dart isolate and database owner per process, independent of its UI. */
class KelivoApplication : Application() {
    val backgroundRuntime by lazy { BackgroundRuntime(this) }
    val scheduledTasks by lazy { ScheduledTasks(this) }
    val workspace by lazy { WorkspacePlugin(this) }
    val deviceTools by lazy { DeviceLocalToolsHandler(this) }

    private val engineHolder = lazy {
        FlutterEngine(this).also { engine ->
            val messenger = engine.dartExecutor.binaryMessenger
            // 手建引擎不会走 FlutterActivity.configureFlutterEngine 的
            // GeneratedPluginRegistrant（release 版对宿主提供的引擎还直接短路），
            // 必须**在 Dart 入口前**显式注册，否则这条 isolate 上的
            // shared_preferences 等通道全部 MissingPluginException。
            io.flutter.plugins.GeneratedPluginRegistrant.registerWith(engine)
            backgroundRuntime.configure(messenger)
            scheduledTasks.configure(messenger)
            workspace.configure(messenger)
            deviceTools.configure(messenger)
            engine.dartExecutor.executeDartEntrypoint(DartExecutor.DartEntrypoint.createDefault())
        }
    }

    val hasEngine get() = engineHolder.isInitialized()
    val engine: FlutterEngine get() = engineHolder.value
}
