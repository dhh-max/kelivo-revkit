package zhou.solab

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.PixelFormat
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.Icon
import android.provider.Settings
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.ImageView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import com.psyche.kelivo.KelivoApplication
import com.psyche.kelivo.background.BackgroundOverlayAppearance
import com.psyche.kelivo.background.OverlayIconFactory
import com.psyche.kelivo.background.OverlayPet
import com.psyche.kelivo.background.OverlayProgressRing
import com.psyche.kelivo.background.PetAssets
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject

/**
 * 自研保活前台服务（替代停更的 flutter_background.IsolateHolderService）。
 *
 * 保活四件套：
 * 1. FGS — 提升进程优先级，系统不轻易回收。类型按版本分派：
 *    API 35+ 用 SPECIAL_USE（Android 15 对 dataSync 有 6h 强限时，到时 FGS
 *    被停→进程降级为 cached→被 freezer 冻结→后台 MCP 工具全部无响应，
 *    曾致「进程还在但后台工具失效」）；API 29-34 用 DATA_SYNC（无限时）。
 * 2. PARTIAL_WAKE_LOCK — 防 Doze/国产 ROM 限流 CPU 导致流式输出与工具执行卡死
 * 3. WIFI_LOCK(low-latency) — 防 Wi-Fi radio 进省电模式后入站 TCP 连接收不到
 *    （MCP server 依赖局域网入站连接，radio 睡眠=后台连接全部超时）
 * 4. START_STICKY — 进程被杀后系统尝试重建
 *
 * agent 模式（生成期持有）与 MCP 模式（常驻开关）共用此服务。
 */
class KeepAliveService : Service(), LifecycleOwner {
    companion object {
        const val CHANNEL_ID = "solab_keepalive"
        const val NOTIFICATION_ID = 20260816
        const val ACTION_START = "zhou.solab.KEEPALIVE_START"
        const val ACTION_STOP = "zhou.solab.KEEPALIVE_STOP"

        /** Kotlin → Dart 的回传通道（与 Dart 侧 AndroidBackgroundManager 同名）。 */
        private const val BRIDGE_CHANNEL = "app.background"
        private const val STATE_PREFS = "keepalive_state"
        private const val KEY_TITLE = "title"
        private const val KEY_TEXT = "text"
        private const val KEY_NETWORK_REQUIRED = "network_required"

        /** 浮窗外观跟随上游设置：BackgroundRuntime 每次 sync 会把图标与
         * 贴边开关写进这里，小标记据此渲染（大肥鱼动画也走同一套取值）。 */
        internal const val OVERLAY_PREFS = "keepalive_overlay"
        internal const val KEY_OVERLAY_ENABLED = "enabled"
        internal const val KEY_ICON_KIND = "icon_kind"
        internal const val KEY_ICON_VALUE = "icon_value"
        internal const val KEY_SNAP_TO_EDGE = "snap_to_edge"
        internal const val KEY_APPEARANCE = "appearance"

        /** 贴边隐藏时露在屏幕内的图标宽度比例。 */
        private const val PET_EDGE_PEEK_RATIO = 0.55f

        @Volatile
        var isRunning = false
            private set

        @Volatile
        private var wakeLock: PowerManager.WakeLock? = null

        @Volatile
        private var wifiLock: WifiManager.WifiLock? = null

        @Volatile
        private var currentService: KeepAliveService? = null

        @Volatile
        private var overlayEnabled = true

        internal fun attachFlutterEngineToService() {
            currentService?.attachFlutterEngineIfNeeded()
        }

        internal fun detachFlutterEngineFromService() {
            currentService?.detachFlutterEngine()
        }

        internal fun onActivityVisibilityChanged(visible: Boolean) {
            currentService?.updateOverlayVisibility(visible)
        }

        internal fun refreshOverlay() {
            currentService?.updateOverlayVisibility(MainActivity.hasVisibleActivity())
        }

        fun isOverlayEnabled(context: Context): Boolean =
            context.getSharedPreferences(OVERLAY_PREFS, Context.MODE_PRIVATE)
                .getBoolean(KEY_OVERLAY_ENABLED, true)

        fun setOverlayEnabled(context: Context, enabled: Boolean) {
            overlayEnabled = enabled
            context.getSharedPreferences(OVERLAY_PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_OVERLAY_ENABLED, enabled).apply()
            currentService?.updateOverlayVisibility(MainActivity.hasVisibleActivity())
        }

        fun start(
            context: Context,
            title: String,
            text: String,
            networkRequired: Boolean,
        ) {
            val intent = Intent(context, KeepAliveService::class.java).apply {
                action = ACTION_START
                putExtra("title", title)
                putExtra("text", text)
                putExtra("networkRequired", networkRequired)
            }
            // 调用时机都在前台或进程已持 FGS（生成期/常驻开启），
            // startForegroundService 合法；Android 12+ 后台启动限制不在此路径。
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE)
                .edit().clear().apply()
            releaseLocks()
            context.stopService(Intent(context, KeepAliveService::class.java))
        }

        fun isReady(networkRequired: Boolean): Boolean =
            isRunning &&
                (!networkRequired ||
                    (wakeLock?.isHeld == true && wifiLock?.isHeld == true))

        private fun releaseLocks() {
            wakeLock?.let { if (it.isHeld) it.release() }
            wakeLock = null
            wifiLock?.let { if (it.isHeld) it.release() }
            wifiLock = null
            isRunning = false
        }
    }

    private val lifecycleRegistry = LifecycleRegistry(this)
    private var attachedEngine: FlutterEngine? = null
    private var overlayView: View? = null
    private var overlayIconView: View? = null
    private var overlayParams: WindowManager.LayoutParams? = null
    private var overlayIconKey = ""
    private val overlayHandler = Handler(Looper.getMainLooper())
    private val snapOverlayRunnable = Runnable { snapOverlayToEdge() }
    private var pet: OverlayPet? = null
    override val lifecycle: Lifecycle get() = lifecycleRegistry

    private fun overlayPrefs() =
        getSharedPreferences(OVERLAY_PREFS, Context.MODE_PRIVATE)

    // 用户 2026-10-05：默认大肥鱼圆形（与 Dart 端 MobileBackgroundSettings 同口径）
    private fun iconKind() = overlayPrefs().getString(KEY_ICON_KIND, "fish") ?: "fish"

    private fun iconValue() = overlayPrefs().getString(KEY_ICON_VALUE, "") ?: ""

    /** 贴边开关也算进图标指纹：改开关要就地重建，否则要等下次进出后台。 */
    private fun currentIconKey(): String {
        val store = overlayPrefs()
        val snap = store.getBoolean(KEY_SNAP_TO_EDGE, true)
        val appearance = store.getString(KEY_APPEARANCE, "") ?: ""
        return "${iconKind()}:${iconValue()}:$snap:$appearance"
    }

    private fun snapEnabled() = overlayPrefs().getBoolean(KEY_SNAP_TO_EDGE, true)

    /** 外观设置：由 BackgroundRuntime 每次 sync 落库，缺省用默认外观。 */
    private fun overlayAppearance(): BackgroundOverlayAppearance = runCatching {
        val raw = overlayPrefs().getString(KEY_APPEARANCE, null) ?: return@runCatching null
        val json = JSONObject(raw)
        BackgroundOverlayAppearance(
            json.keys().asSequence().associateWith { json.get(it) },
        )
    }.getOrNull() ?: BackgroundOverlayAppearance(emptyMap<String, Any>())

    /** 上游胶囊（任务/常驻）在屏幕上时让位：两条鱼叠一起没有意义。 */
    private fun capsuleVisible(): Boolean = runCatching {
        (application as KelivoApplication).backgroundRuntime.capsuleVisible()
    }.getOrDefault(false)

    /** 有任务在跑时才画进度环，和上游胶囊同一口径。 */
    private fun hasRunningTask(): Boolean = runCatching {
        (application as KelivoApplication).backgroundRuntime.tasks
            .any { it.outcome.isEmpty() }
    }.getOrDefault(false)

    /** 小标记播用户选的默认动作（key 里存的就是动作名），非法名回落 idle。 */
    private fun defaultClip(): String {
        val configured = iconValue()
        return if (configured.isNotEmpty() && PetAssets.clip(this, configured) != null) {
            configured
        } else {
            "idle"
        }
    }

    override fun onCreate() {
        super.onCreate()
        currentService = this
        overlayEnabled = isOverlayEnabled(applicationContext)
        lifecycleRegistry.handleLifecycleEvent(Lifecycle.Event.ON_CREATE)
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // 用户在常驻通知上点「关闭」（2026-09-21 用户要求）。
            // 先让 Dart 侧退出 MCP 模式——引擎在（MCP 常驻的常态）就立即生效；
            // 不在就只停服务（进程随后被系统回收，行为一致）。
            // 再清掉持久化文案并停服务，避免下次重启沿用旧的模式/端口文本。
            runCatching {
                val messenger = attachedEngine?.dartExecutor?.binaryMessenger
                if (messenger != null) {
                    MethodChannel(messenger, BRIDGE_CHANNEL)
                        .invokeMethod("keepAliveStoppedByUser", null)
                }
            }
            getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE)
                .edit().clear().apply()
            stopSelf()
            return START_NOT_STICKY
        }
        val state = getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE)
        val title = intent?.getStringExtra("title")
            ?: state.getString(KEY_TITLE, null)
            ?: "SoLab"
        val text = intent?.getStringExtra("text")
            ?: state.getString(KEY_TEXT, null)
            ?: "后台任务保活中"
        val networkRequired = if (intent?.hasExtra("networkRequired") == true) {
            intent.getBooleanExtra("networkRequired", false)
        } else {
            state.getBoolean(KEY_NETWORK_REQUIRED, false)
        }
        state.edit()
            .putString(KEY_TITLE, title)
            .putString(KEY_TEXT, text)
            .putBoolean(KEY_NETWORK_REQUIRED, networkRequired)
            .apply()

        val notification = buildNotification(title, text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            // Android 15+：dataSync 有 6h 系统限时，用 specialUse 免限时
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        // WakeLock 与 FGS 生命周期绑定；服务停止时统一释放。
        if (networkRequired && wakeLock == null) {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "solab:keepalive",
            ).apply {
                setReferenceCounted(false)
                acquire()
            }
        }
        // WifiLock：MCP server 依赖局域网入站连接；后台时 Wi-Fi radio 省电
        // 会让入站 SYN 收不到，表现为「进程活着但工具全部超时」。
        if (networkRequired && wifiLock == null) {
            @Suppress("DEPRECATION")
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            if (wm != null) {
                @Suppress("DEPRECATION")
                wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "solab:mcpserver").apply {
                    setReferenceCounted(false)
                    acquire()
                }
            }
        }
        if (!networkRequired) {
            wakeLock?.let { if (it.isHeld) it.release() }
            wakeLock = null
            wifiLock?.let { if (it.isHeld) it.release() }
            wifiLock = null
        }
        isRunning = true
        updateOverlayVisibility(MainActivity.hasVisibleActivity())
        if (networkRequired) {
            // FGS 只能保住进程。任务界面被移除时 FlutterActivity 会销毁，若不保留
            // Dart 引擎，进程和通知仍在但 MCP socket/工具执行器已经消失。
            // 缓存引擎覆盖界面移除；START_STICKY 重建服务时在无界面状态补建引擎。
            MainActivity.ensurePersistentFlutterEngine(applicationContext)
            lifecycleRegistry.handleLifecycleEvent(Lifecycle.Event.ON_START)
            attachFlutterEngineIfNeeded()
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        Handler(Looper.getMainLooper()).postDelayed(
            { attachFlutterEngineIfNeeded() },
            250,
        )
        super.onTaskRemoved(rootIntent)
    }

    // FGS 类型系统限时兜底（specialUse 正常不触发；防系统策略变化导致 crash）
    override fun onTimeout(startId: Int, fgsType: Int) {
        stopSelf()
    }

    override fun onDestroy() {
        removeOverlay()
        detachFlutterEngine()
        lifecycleRegistry.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        lifecycleRegistry.handleLifecycleEvent(Lifecycle.Event.ON_DESTROY)
        if (currentService === this) currentService = null
        releaseLocks()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun attachFlutterEngineIfNeeded() {
        if (!isRunning || MainActivity.hasAttachedActivity()) return
        val engine = MainActivity.ensurePersistentFlutterEngine(applicationContext)
        if (attachedEngine === engine) {
            engine.lifecycleChannel.appIsResumed()
            return
        }
        detachFlutterEngine()
        engine.serviceControlSurface.attachToService(this, lifecycle, true)
        engine.lifecycleChannel.appIsResumed()
        attachedEngine = engine
    }

    private fun detachFlutterEngine() {
        val engine = attachedEngine ?: return
        runCatching { engine.serviceControlSurface.detachFromService() }
        attachedEngine = null
    }

    private fun updateOverlayVisibility(activityVisible: Boolean) {
        if (!snapEnabled()) overlayHandler.removeCallbacks(snapOverlayRunnable)
        // 「应用内也显示」打开时，SoLab 在前台也保留小标记（默认只退到后台才显示）。
        val hideForForeground = activityVisible && !overlayAppearance().showInApp
        if (!isRunning || !overlayEnabled || hideForForeground || capsuleVisible() ||
            Build.VERSION.SDK_INT < Build.VERSION_CODES.M ||
            !Settings.canDrawOverlays(this)
        ) {
            removeOverlay()
            return
        }
        var keepX: Int? = null
        var keepY: Int? = null
        if (overlayView != null) {
            // 图标跟随上游设置：换了图标就地重建，否则要等下次进出后台才生效。
            // 重建沿用原来的落点，不让用户拖好的位置被图标切换重置。
            if (overlayIconKey == currentIconKey()) return
            overlayParams?.let { keepX = it.x; keepY = it.y }
            removeOverlay()
        }

        val density = resources.displayMetrics.density
        // 尺寸与形状完全跟随上游外观设置：窗口 = width×height，图标 = iconSize
        // 按徽标比例缩放，背景/边框/圆角照抄——设置页预览看到什么，这里就是什么。
        val appearance = overlayAppearance()
        val availableWidth =
            resources.displayMetrics.widthPixels / density - 16f
        val geometry = appearance.layout(availableWidth)
        val windowWidth = (geometry.width * density).toInt().coerceAtLeast(1)
        val windowHeight = (appearance.height * density).toInt().coerceAtLeast(1)
        val scale = geometry.badge / appearance.badgeSize
        val iconSize = (appearance.iconSize * scale * density).toInt().coerceAtLeast(1)
        val icon = OverlayIconFactory.create(this, iconKind(), iconValue(), iconSize)
        icon.contentDescription = applicationInfo.loadLabel(packageManager)
        val dark = resources.configuration.uiMode and
            Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        val badge = FrameLayout(this).apply {
            clipChildren = true
            if (appearance.showBackground || appearance.showBorder) {
                background = GradientDrawable().apply {
                    setColor(
                        if (!appearance.showBackground) {
                            Color.TRANSPARENT
                        } else if (dark) {
                            Color.rgb(31, 33, 39)
                        } else {
                            Color.rgb(249, 250, 253)
                        },
                    )
                    cornerRadius = appearance.cornerRadius * density
                    if (appearance.showBorder) {
                        setStroke(
                            (density).toInt().coerceAtLeast(1),
                            if (dark) Color.rgb(93, 97, 107) else Color.rgb(200, 204, 213),
                        )
                    }
                }
            }
            addView(
                icon,
                FrameLayout.LayoutParams(iconSize, iconSize, Gravity.CENTER),
            )
            // 进度环：跟着「显示进度」开关和任务有无走，和上游胶囊同一口径。
            if (appearance.showProgress && hasRunningTask()) {
                val ringSize = (appearance.progressSize * scale * density).toInt()
                addView(
                    OverlayProgressRing(
                        this@KeepAliveService,
                        (appearance.progressStrokeWidth * scale * density)
                            .coerceAtLeast(1f),
                    ),
                    FrameLayout.LayoutParams(ringSize, ringSize, Gravity.CENTER),
                )
            }
        }
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        val params = WindowManager.LayoutParams(
            windowWidth,
            windowHeight,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            val (screenWidth, screenHeight) = overlayScreenSize()
            x = keepX ?: (screenWidth - windowWidth)
            y = keepY ?: ((screenHeight - windowHeight) / 2)
        }
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        var downRawX = 0f
        var downRawY = 0f
        var downEventTime = 0L
        var downX = 0
        var downY = 0
        badge.setOnTouchListener { view, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    downEventTime = event.eventTime
                    overlayHandler.removeCallbacks(snapOverlayRunnable)
                    icon.animate().cancel()
                    icon.translationX = 0f
                    // 手一搭上就播拖拽动作，别让鱼一动不动被拖走。
                    pet?.react("dragging")
                    downRawX = event.rawX
                    downRawY = event.rawY
                    downX = params.x
                    downY = params.y
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = event.rawX - downRawX
                    val dy = event.rawY - downRawY
                    val (screenWidth, screenHeight) = overlayScreenSize()
                    params.x = (downX + dx.toInt()).coerceIn(0, screenWidth - windowWidth)
                    params.y = (downY + dy.toInt()).coerceIn(0, screenHeight - windowHeight)
                    runCatching { wm.updateViewLayout(view, params) }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    // 短按不离位 = "戳一下"：播 poke（八套动作里的那一套此前
                    // 只在另一套悬浮窗接过，这套实际在用的没接，用户看不到）。
                    val tapMs = event.eventTime - downEventTime
                    val moved = kotlin.math.abs(params.x - downX) +
                        kotlin.math.abs(params.y - downY)
                    if (tapMs < 250L && moved < 12) {
                        pet?.react("poke")
                    } else {
                        pet?.react("dragging_release")
                    }
                    syncPet()
                    true
                }
                MotionEvent.ACTION_CANCEL -> {
                    pet?.endReact()
                    syncPet()
                    true
                }
                else -> false
            }
        }
        runCatching { wm.addView(badge, params) }
            .onSuccess {
                overlayView = badge
                overlayIconView = icon
                overlayParams = params
                overlayIconKey = currentIconKey()
                syncPet()
            }
    }

    /** 小标记就是纯图标窗：大肥鱼在这里循环播放待机动作，拖动/点击有反应。 */
    private fun syncPet() {
        val artwork = overlayIconView as? ImageView
        if (artwork == null || iconKind() != "fish") {
            pet?.stop()
            pet = null
            scheduleOverlaySnap()
            return
        }
        val engine = pet ?: OverlayPet(this, artwork).also { pet = it }
        engine.setState(defaultClip())
        engine.start()
        scheduleOverlaySnap()
    }

    private fun removeOverlay() {
        overlayHandler.removeCallbacks(snapOverlayRunnable)
        val view = overlayView ?: return
        pet?.stop()
        pet = null
        overlayView = null
        overlayIconView = null
        overlayParams = null
        overlayIconKey = ""
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        runCatching { wm.removeView(view) }
    }

    private fun scheduleOverlaySnap() {
        overlayHandler.removeCallbacks(snapOverlayRunnable)
        if (!snapEnabled()) return
        overlayHandler.postDelayed(snapOverlayRunnable, 3_000)
    }

    private fun snapOverlayToEdge() {
        val view = overlayView ?: return
        val params = overlayParams ?: return
        val icon = overlayIconView ?: return
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val (screenWidth, _) = overlayScreenSize()
        // 探出量按图标比例给：精灵图四周有透明留白，固定 10dp 会正好露出
        // 透明区，看上去像整个消失。取图标宽度的 45%（下限 12dp）保证露在
        // 屏幕上的是一块实体，能看见也能再拖出来。
        val density = resources.displayMetrics.density
        val visibleWidth = maxOf(
            (12 * density).toInt(),
            (icon.width * PET_EDGE_PEEK_RATIO).toInt(),
        )
        val snapLeft = params.x + params.width / 2 < screenWidth / 2
        params.x = if (snapLeft) {
            0
        } else {
            screenWidth - params.width
        }
        runCatching { wm.updateViewLayout(view, params) }
        // 窗口现在可以比图标大（尺寸跟随外观设置），位移要按图标在窗口里的
        // 内缩重算，才能保证贴边后恰好留 visibleWidth 露在屏幕内。
        val inset = ((params.width - icon.width) / 2).coerceAtLeast(0)
        val slide = if (snapLeft) {
            visibleWidth - icon.width - inset
        } else {
            params.width - visibleWidth - inset
        }
        icon.animate()
            .translationX(slide.toFloat())
            .setDuration(160)
            .start()
    }

    private fun overlayScreenSize(): Pair<Int, Int> {
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val bounds = wm.currentWindowMetrics.bounds
            bounds.width() to bounds.height()
        } else {
            @Suppress("DEPRECATION")
            resources.displayMetrics.run { widthPixels to heightPixels }
        }
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "后台保活",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setShowBadge(false)
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(title: String, text: String): Notification {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pending = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setContentIntent(pending)
            // 「关闭」动作（2026-09-21 用户要求）：常驻通知不能划掉，得给一个
            // 明确的出口。点击 → 本服务 ACTION_STOP → 回传 Dart 退出 MCP 模式。
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(
                        this,
                        android.R.drawable.ic_menu_close_clear_cancel,
                    ),
                    "关闭",
                    PendingIntent.getService(
                        this,
                        1,
                        Intent(this, KeepAliveService::class.java).apply {
                            action = ACTION_STOP
                        },
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                    ),
                ).build(),
            )
            .build()
    }
}
