package zhou.solab.tools

import android.app.ActivityManager
import android.content.Context

/**
 * 设备档位（单例）：把"并发度/预算"从写死常量改成按设备能力取值。
 *
 * 背景（2026-09-15 用户点名的方向）：同一套参数在低端机上会 OOM/被杀，在
 * 旗舰机上又白白浪费核数——判据应该来自设备本身。档位只用两个稳定信号
 * （总内存 + CPU 核数），不依赖任何需要联网或 root 的探测。
 *
 * 取值口径：
 * - low ：总内存 < 4GB 或核数 ≤ 4 —— 单线程、串行、预算收紧
 * - mid ：总内存 < 8GB 或核数 ≤ 6 —— 小并发（2~3）
 * - high：其余 —— 放开并行（最多 6）
 *
 * 所有调用点都要"少并发也不出错、多并发只更快"，档位只影响吞吐与水位，
 * 不能改变结果正确性。
 */
object DeviceProfile {

    enum class Tier { low, mid, high }

    @Volatile private var totalRamMb: Long = 0L
    @Volatile private var cores: Int = 0
    @Volatile private var tier: Tier = Tier.mid

    fun init(context: Context) {
        if (cores > 0 && totalRamMb > 0) return
        if (cores <= 0) cores = Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        if (am != null) {
            val info = ActivityManager.MemoryInfo()
            runCatching { am.getMemoryInfo(info) }
                .onSuccess { totalRamMb = info.totalMem / (1024L * 1024L) }
        }
        tier = when {
            (totalRamMb in 1 until 4096L) || cores <= 4 -> Tier.low
            (totalRamMb in 1 until 8192L) || cores <= 6 -> Tier.mid
            else -> Tier.high
        }
    }

    fun tier(): Tier = tier

    fun tierName(): String = tier.name

    fun totalRamMb(): Long = totalRamMb

    fun cores(): Int = if (cores > 0) cores else Runtime.getRuntime().availableProcessors().coerceAtLeast(1)

    /** 是否已知设备信息（未 init 时调用方应按 mid 处理，不阻塞）。 */
    fun known(): Boolean = totalRamMb > 0 && cores > 0

    /**
     * 全量扫描类并行度（asm 索引构建等）：低端单线程，中端 2~3，高端最多 6。
     * 内存越紧越不该并行——并行的峰值是单线程的倍数，低端机上就是 OOM。
     */
    fun scanThreads(): Int = when (tier) {
        Tier.low -> 1
        Tier.mid -> (cores() - 1).coerceIn(2, 3)
        Tier.high -> cores().coerceIn(3, 6)
    }

    /** 通用后台任务并行度（异步工具执行）。低端串行，避免多个重工具互相抢内存。 */
    fun asyncTaskThreads(): Int = when (tier) {
        Tier.low -> 1
        Tier.mid -> 2
        Tier.high -> 3
    }

    /** 外部 runner（blutter 等子进程）worker 数：越低越省内存，越高越快。 */
    fun runnerWorkers(): Int = when (tier) {
        Tier.low -> 1
        Tier.mid -> 2
        Tier.high -> 4
    }

    /**
     * 是否允许"重工具并发"（同轮多个重工具同时跑）。
     * 低端机禁止：宁可排队也不要两个全量解析同时在堆里。
     */
    fun allowHeavyToolConcurrency(): Boolean = tier != Tier.low

    /** 诊断用快照（写进工具信封/日志，出问题能一眼看出设备档位）。 */
    fun toMap(): Map<String, Any> = linkedMapOf(
        "tier" to tier.name,
        "totalRamMb" to totalRamMb,
        "cores" to cores(),
        "scanThreads" to scanThreads(),
        "asyncTaskThreads" to asyncTaskThreads(),
        "runnerWorkers" to runnerWorkers(),
        "heavyToolConcurrency" to allowHeavyToolConcurrency(),
    )
}
