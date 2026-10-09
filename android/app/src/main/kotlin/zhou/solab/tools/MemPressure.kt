package zhou.solab.tools

import android.app.ActivityManager
import android.content.Context
import android.os.Debug
import android.os.SystemClock
import android.util.Log
import java.util.LinkedHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * 进程级内存水位监控（单例）。
 *
 * - 快照：Java 堆以 largeHeap 之后的 growth limit 为基准；native 堆单独监控
 *   （Debug.getNativeHeapAllocatedSize——C 库 malloc 不受 Java 堆管，Java 堆
 *   压下来了 native 还在涨照样被 lmkd 杀，两本账必须分开看）。
 * - 动态重工具名单：每次工具执行记录内存增量，超阈值自动收录。按历史峰值
 *   动态判定，新增重工具不漏，重工具名单不靠写死。
 * - 清理分发：onTrimMemory / native 压力 / OOM 恢复时逐个调用注册的清理钩子。
 *   钩子必须是纯释放操作（clear/evict/close），不得做内存分配。
 * - 内存曲线经 logcat tag=SoLabMem 输出，供压测脚本 adb logcat 自动采集。
 */
object MemPressure {

    /** 单工具单次执行内存增量（Java 堆或 native 取大者）达到该值即收录动态重名单 */
    const val DYNAMIC_HEAVY_DELTA_MB = 48L

    @Volatile private var heapLimit: Int = 0
    private val lock = Any()
    private val cleanupHooks = LinkedHashMap<String, () -> Unit>()
    // tool -> 最近 8 次 [endHeap,endNative,peakHeap,peakNative,peakPss,costMs]，作为后续优化依据
    private val toolMemHistory = LinkedHashMap<String, ArrayDeque<LongArray>>()
    @Volatile private var dynamicHeavy: Set<String> = emptySet()
    @Volatile private var deviceTotalRamMb: Long = 0L
    private const val PEAK_SAMPLE_PERIOD_MS = 125L
    private val peakSampler = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "solab-memory-sampler").apply { isDaemon = true }
    }

    fun init(context: Context) {
        if (heapLimit > 0) return
        // 设备档位是并发/预算的共同来源：初始化一次，内存与线程数用同一份事实。
        DeviceProfile.init(context)
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        heapLimit = am?.largeMemoryClass ?: ((Runtime.getRuntime().maxMemory() / (1024L * 1024L)).toInt())
        deviceTotalRamMb = DeviceProfile.totalRamMb()
    }

    /** largeHeap 之后的堆 growth limit（MB）；未 init 时退回 Runtime 实测。 */
    fun heapLimitMb(): Int =
        if (heapLimit > 0) heapLimit
        else (Runtime.getRuntime().maxMemory() / (1024L * 1024L)).toInt()

    /** native 堆已分配量（MB，分配器记账）。runCatching：unit test 的 android.os.Debug 是 stub。 */
    fun nativeHeapMb(): Long =
        runCatching { Debug.getNativeHeapAllocatedSize() / (1024L * 1024L) }.getOrDefault(0L)

    /**
     * 进程常驻内存（PSS，MB）：Java 堆 + native + 图形 + 文件映射的合计，
     * 也就是系统判杀（lmkd）看的那个量。
     *
     * 为什么要它：native 记账（[nativeHeapMb]）在某些设备/分配器上会记成
     * **地址空间**而不是实际占用——实测有设备报 4083MB 而进程 PSS 远低于
     * 1GB（Scudo 的 region 记账 + Dart VM/Skia 的映射）。拿记账量当压力
     * 判据会把 App 永久锁死在「只能重启」的状态（2026-09-15 审核）。
     */
    fun processPssMb(): Long = runCatching { Debug.getPss() / 1024L }.getOrDefault(0L)

    /**
     * native 记账额度（只用于报告，**不参与判压力**）。
     *
     * 历史：它曾是第二道闸门（max(256, 堆上限×3/4)）。实测该口径在重分析设备上
     * 必然误报——native 记账 4277MB / PSS 4340MB，两者一致说明是真占用（Dart VM +
     * rizin/LIEF + asm 索引都在 native 侧），而按 Java 堆推出来的 480MB 额度只会
     * 把能干活的应用锁死。Dart 应用的 native 用量与 Java 堆无关，唯一有意义的
     * 判据是进程 PSS（见 [pssBudgetMb]）。
     */
    fun nativeBudgetMb(): Long = maxOf(256L, heapLimitMb() * 3L / 4L)

    /**
     * PSS 预算：进程常驻内存的管理线。按设备档位取值（2026-09-15 用户点名
     * 「不要写死，按设备来」）：
     * - low（≤4GB/≤4 核）：min(max(512, 堆上限×1.5), 内存/5) —— 小设备本来就
     *   没有余量，管理线要更早亮；
     * - mid：min(max(768, 堆上限×2), 内存/4)；
     * - high（≥8GB/≥7 核）：min(max(1024, 堆上限×3), 内存/4) —— 有余量就放开，
     *   别把旗舰机当成小内存机拦。
     */
    fun pssBudgetMb(): Long {
        val heap = heapLimitMb().toLong()
        val device = deviceTotalRamMb
        // 高档（大内存设备）：额度按**设备内存**给——15GB 机器上应用真占 4.3GB 是
        // 正常分析开销，用 Java 堆推出的 1.5GB 天花板会把能干活的应用锁死
        // （2026-09-15 真机：PSS 4340MB 被 1536MB 拦住）。仍保留封顶 8GB 防失控增长。
        if (DeviceProfile.tier() == DeviceProfile.Tier.high && device > 0) {
            return minOf(maxOf(3072L, device * 40L / 100L), 8192L)
        }
        val byHeap = when (DeviceProfile.tier()) {
            DeviceProfile.Tier.low -> maxOf(512L, heap * 3L / 2L)
            else -> maxOf(1024L, heap * 2L)
        }
        val byDevice = if (device > 0) maxOf(512L, device / 4L) else Long.MAX_VALUE
        return minOf(byHeap, byDevice)
    }

    /**
     * 记账可信度：分配器记账不可能超过进程实际常驻的 2 倍（native 只是 PSS
     * 的一部分）。超过即判定为地址空间记账，忽略之（只报告不判压力）。
     */
    fun nativeAccountingPlausible(nativeMb: Long, pssMb: Long): Boolean =
        nativeMb <= 0L || pssMb <= 0L || nativeMb <= pssMb * 2L

    /** 一次内存水位快照：判定与文案都从这里取，保证口径一致。 */
    data class PressureSnapshot(
        val pssMb: Long,
        val pssBudgetMb: Long,
        val nativeAllocatedMb: Long,
        val nativeBudgetMb: Long,
        val nativeAccountingPlausible: Boolean,
    ) {
        val overPss: Boolean get() = pssMb > pssBudgetMb

        /** 是否越过管理线：只看 PSS（native 记账与 PSS 同源，重复设卡只会误报）。 */
        val overLine: Boolean get() = overPss

        fun toMap(): Map<String, Any> = linkedMapOf(
            "pssMb" to pssMb,
            "pssBudgetMb" to pssBudgetMb,
            "nativeAllocatedMb" to nativeAllocatedMb,
            "nativeBudgetMb" to nativeBudgetMb,
            "nativeAccountingPlausible" to nativeAccountingPlausible,
        )
    }

    fun pressureSnapshot(): PressureSnapshot = PressureSnapshot(
        pssMb = processPssMb(),
        pssBudgetMb = pssBudgetMb(),
        nativeAllocatedMb = nativeHeapMb(),
        nativeBudgetMb = nativeBudgetMb(),
        nativeAccountingPlausible = nativeAccountingPlausible(nativeHeapMb(), processPssMb()),
    )

    fun registerCleanup(tag: String, hook: () -> Unit) {
        synchronized(lock) { cleanupHooks[tag] = hook }
    }

    /**
     * 内存压力释放：越线才清缓存 + GC + 短暂等待，返回处置后的快照
     * （未越线则原样返回，不误伤缓存）。
     */
    fun relievePressure(): PressureSnapshot {
        val before = pressureSnapshot()
        if (!before.overLine) return before
        cleanupAll("pressure")
        System.gc()
        runCatching { Thread.sleep(120) }
        return pressureSnapshot()
    }

    /** 系统内存回调：RUNNING_LOW(10) 及更严重级别触发清理（UI_HIDDEN=20 也在内）。 */
    fun onTrimMemory(level: Int) {
        if (level >= 10) cleanupAll("trim:$level")
    }

    fun cleanupAll(reason: String) {
        val hooks = synchronized(lock) { cleanupHooks.toList() }
        hooks.forEach { (tag, hook) ->
            runCatching { hook() }.onFailure { Log.w("SoLabMem", "cleanup[$tag] failed: ${it.message}") }
        }
        Log.i("SoLabMem", "cleanupAll done ($reason), native=${nativeHeapMb()}MB")
    }

    data class ToolMemoryPeak internal constructor(
        val beforeFreeHeapMb: Long,
        val afterFreeHeapMb: Long,
        val lowestFreeHeapMb: Long,
        val beforeNativeMb: Long,
        val afterNativeMb: Long,
        val peakNativeMb: Long,
        val beforePssMb: Long,
        val afterPssMb: Long,
        val peakPssMb: Long,
        val samples: Long,
        val costMs: Long,
    ) {
        val endHeapDeltaMb: Long get() = (beforeFreeHeapMb - afterFreeHeapMb).coerceAtLeast(0L)
        val endNativeDeltaMb: Long get() = (afterNativeMb - beforeNativeMb).coerceAtLeast(0L)
        val peakHeapDeltaMb: Long get() = (beforeFreeHeapMb - lowestFreeHeapMb).coerceAtLeast(0L)
        val peakNativeDeltaMb: Long get() = (peakNativeMb - beforeNativeMb).coerceAtLeast(0L)
        val peakPssDeltaMb: Long get() = (peakPssMb - beforePssMb).coerceAtLeast(0L)

        fun toMap(): Map<String, Any> = linkedMapOf(
            "peakHeapDeltaMb" to peakHeapDeltaMb,
            "peakNativeDeltaMb" to peakNativeDeltaMb,
            "peakPssDeltaMb" to peakPssDeltaMb,
            "peakPssMb" to peakPssMb,
            "samples" to samples,
            "costMs" to costMs,
        )
    }

    class ToolRun internal constructor(
        private val beforeFreeHeapMb: Long,
        private val beforeNativeMb: Long,
        private val beforePssMb: Long,
        private val startedAtMs: Long,
    ) {
        private val lowestFreeHeapMb = AtomicLong(beforeFreeHeapMb)
        private val peakNativeMb = AtomicLong(beforeNativeMb)
        private val peakPssMb = AtomicLong(beforePssMb)
        private val samples = AtomicLong(0)
        private val closed = AtomicBoolean(false)
        private var future: ScheduledFuture<*>? = null

        internal fun start() {
            future = peakSampler.scheduleWithFixedDelay(
                ::sample,
                PEAK_SAMPLE_PERIOD_MS,
                PEAK_SAMPLE_PERIOD_MS,
                TimeUnit.MILLISECONDS,
            )
        }

        private fun sample() {
            if (closed.get()) return
            val runtime = Runtime.getRuntime()
            val freeMb =
                (runtime.maxMemory() - runtime.totalMemory() + runtime.freeMemory()) / (1024L * 1024L)
            lowestFreeHeapMb.accumulateAndGet(freeMb) { old, value -> minOf(old, value) }
            peakNativeMb.accumulateAndGet(nativeHeapMb()) { old, value -> maxOf(old, value) }
            peakPssMb.accumulateAndGet(processPssMb()) { old, value -> maxOf(old, value) }
            samples.incrementAndGet()
        }

        internal fun finish(): ToolMemoryPeak {
            if (closed.compareAndSet(false, true)) future?.cancel(false)
            val runtime = Runtime.getRuntime()
            val afterFree =
                (runtime.maxMemory() - runtime.totalMemory() + runtime.freeMemory()) / (1024L * 1024L)
            val afterNative = nativeHeapMb()
            val afterPss = processPssMb()
            lowestFreeHeapMb.accumulateAndGet(afterFree) { old, value -> minOf(old, value) }
            peakNativeMb.accumulateAndGet(afterNative) { old, value -> maxOf(old, value) }
            peakPssMb.accumulateAndGet(afterPss) { old, value -> maxOf(old, value) }
            samples.incrementAndGet()
            return ToolMemoryPeak(
                beforeFreeHeapMb = beforeFreeHeapMb,
                afterFreeHeapMb = afterFree,
                lowestFreeHeapMb = lowestFreeHeapMb.get(),
                beforeNativeMb = beforeNativeMb,
                afterNativeMb = afterNative,
                peakNativeMb = peakNativeMb.get(),
                beforePssMb = beforePssMb,
                afterPssMb = afterPss,
                peakPssMb = peakPssMb.get(),
                samples = samples.get(),
                costMs = SystemClock.elapsedRealtime() - startedAtMs,
            )
        }
    }

    fun startToolRun(): ToolRun {
        val rt = Runtime.getRuntime()
        val beforeFree = (rt.maxMemory() - rt.totalMemory() + rt.freeMemory()) / (1024L * 1024L)
        return ToolRun(
            beforeFreeHeapMb = beforeFree,
            beforeNativeMb = nativeHeapMb(),
            beforePssMb = processPssMb(),
            startedAtMs = SystemClock.elapsedRealtime(),
        ).also { it.start() }
    }

    /**
     * 记录完整执行期的峰值，而非只比较结束时残留量。短命临时对象即使已被回收，
     * 也会被采样捕获并进入动态重工具判定。
     */
    fun record(tool: String, run: ToolRun): ToolMemoryPeak {
        val peak = run.finish()
        synchronized(lock) {
            val q = toolMemHistory.getOrPut(tool) { ArrayDeque() }
            q.addLast(
                longArrayOf(
                    peak.endHeapDeltaMb,
                    peak.endNativeDeltaMb,
                    peak.peakHeapDeltaMb,
                    peak.peakNativeDeltaMb,
                    peak.peakPssDeltaMb,
                    peak.costMs,
                ),
            )
            if (q.size > 8) q.removeFirst()
            if (maxOf(peak.peakHeapDeltaMb, peak.peakNativeDeltaMb, peak.peakPssDeltaMb) >= DYNAMIC_HEAVY_DELTA_MB) {
                dynamicHeavy = dynamicHeavy + tool
            }
        }
        Log.i(
            "SoLabMem",
            "tool=$tool endHeap=${peak.endHeapDeltaMb}MB endNative=${peak.endNativeDeltaMb}MB " +
                "peakHeap=${peak.peakHeapDeltaMb}MB peakNative=${peak.peakNativeDeltaMb}MB " +
                "peakPss=${peak.peakPssDeltaMb}MB samples=${peak.samples} cost=${peak.costMs}ms " +
                "free=${peak.afterFreeHeapMb}MB limit=${heapLimitMb()}MB native=${peak.afterNativeMb}MB pss=${peak.afterPssMb}MB",
        )
        return peak
    }

    fun isDynamicallyHeavy(tool: String): Boolean = dynamicHeavy.contains(tool)
}
