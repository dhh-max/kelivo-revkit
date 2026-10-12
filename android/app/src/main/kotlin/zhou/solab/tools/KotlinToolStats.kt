package zhou.solab.tools

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * SO/工具调用统计（玄星逆核 ToolStats 精简版）。
 * 内存聚合 + SP 持久化（15s 限频落盘）；Dart 侧可经 stats 模块读取。
 * engine_stats_rows（drift schema 7）为 Dart 侧持久化目标，接入点见
 * 工具调用统计（后续可双写）。
 *
 * 开关（2026-09-18 接通）：`collectToolStats` 关闭时不再记账（省掉每次调用的
 * 同步与样本维护），`toolStatsPersist` 关闭时只聚合不落盘。此前两个设置项
 * 在 SettingsStore 里可读可写、却没有任何代码读它——配置项等于谎言。
 */
object KotlinToolStats {

    private data class Stat(
        var calls: Int = 0,
        var ok: Int = 0,
        var failed: Int = 0,
        var totalMicros: Long = 0,
        var maxMicros: Long = 0,
        var lastError: String = "",
        var lastAt: Long = 0,
        val recentMicros: ArrayDeque<Long> = ArrayDeque(),
    )

    private val lock = Any()
    private val stats = HashMap<String, Stat>()
    private var app: Context? = null
    private var settings: SettingsStore? = null
    @Volatile private var lastFlushAt = 0L
    private const val FLUSH_MIN_GAP_MS = 15_000L
    private const val PREFS = "solab_tool_stats"
    private const val RECENT_SAMPLE_LIMIT = 64

    fun init(context: Context) {
        app = context.applicationContext
        settings = SettingsStore(context.applicationContext)
        loadFromDisk()
    }

    /** 记账开关：关掉就完全不产生统计开销（连内存样本都不维护）。 */
    private fun collectEnabled(): Boolean = settings?.collectToolStats ?: true

    /** 落盘开关：关掉只保留内存聚合。 */
    private fun persistEnabled(): Boolean = settings?.toolStatsPersist ?: true

    /**
     * 统计键清洗（用户实测报告 2-7）。
     *
     * 键是调用方拼的（例如 `"so_analyze:\$action"`，action 直接来自入参），过去不做
     * 任何校验：参数畸形时账本里会出现 `so_analyze:blutter<tool_sep:…"rz_command":…`
     * 这类伪工具，慢工具/失败率排名里混进噪声。这里只保留 [A-Za-z0-9_.:-]，其余一律
     * 折叠成 `_`，并限长 64；清洗后为空记 `unknown`。
     */
    internal fun sanitizeToolKey(tool: String): String {
        val sb = StringBuilder(tool.length.coerceAtMost(64))
        for (ch in tool) {
            if (sb.length >= 64) break
            val keep = ch.isLetterOrDigit() && ch.code < 128 || ch == '_' || ch == '.' || ch == ':' || ch == '-'
            sb.append(if (keep) ch else '_')
        }
        val cleaned = sb.toString().trim('_')
        return cleaned.ifEmpty { "unknown" }
    }

    fun record(tool: String, success: Boolean, micros: Long, error: String = "") {
        if (!collectEnabled()) return
        val tool = sanitizeToolKey(tool)
        val now = System.currentTimeMillis()
        synchronized(lock) {
            val s = stats.getOrPut(tool) { Stat() }
            s.calls++
            if (success) s.ok++ else s.failed++
            s.totalMicros += micros
            if (micros > s.maxMicros) s.maxMicros = micros
            s.recentMicros.addLast(micros)
            if (s.recentMicros.size > RECENT_SAMPLE_LIMIT) s.recentMicros.removeFirst()
            if (error.isNotBlank()) s.lastError = error
            s.lastAt = now
        }
        maybeFlush()
    }

    fun snapshot(): JSONObject {
        val items = JSONArray()
        val slowest = JSONArray()
        var totalCalls = 0
        var totalOk = 0
        var totalFailed = 0
        synchronized(lock) {
            val rows = stats.map { (tool, stat) -> tool to statRow(tool, stat) }
            rows.sortedByDescending { stats.getValue(it.first).lastAt }.forEach { (_, row) ->
                val s = stats.getValue(row.getString("tool"))
                totalCalls += s.calls
                totalOk += s.ok
                totalFailed += s.failed
                items.put(row)
            }
            rows.sortedWith(compareByDescending<Pair<String, JSONObject>> { it.second.optLong("p95Ms") }
                .thenByDescending { it.second.optLong("maxMs") })
                .forEach { (_, row) -> slowest.put(JSONObject(row.toString())) }
        }
        return JSONObject()
            .put("tools", items)
            .put("slowestTools", slowest)
            .put("distinctTools", items.length())
            .put("totalCalls", totalCalls)
            .put("totalOk", totalOk)
            .put("totalFailed", totalFailed)
    }

    private fun statRow(tool: String, stat: Stat): JSONObject {
        val samples = stat.recentMicros.sorted()
        return JSONObject()
            .put("tool", tool)
            .put("calls", stat.calls)
            .put("ok", stat.ok)
            .put("failed", stat.failed)
            .put("avgMs", if (stat.calls > 0) (stat.totalMicros / 1000 / stat.calls) else 0)
            .put("p50Ms", percentileMicros(samples, 0.50) / 1000)
            .put("p95Ms", percentileMicros(samples, 0.95) / 1000)
            .put("maxMs", stat.maxMicros / 1000)
            .put("sampleCount", samples.size)
            .put("lastError", stat.lastError)
            .put("lastAt", stat.lastAt)
    }

    private fun percentileMicros(sorted: List<Long>, percentile: Double): Long {
        if (sorted.isEmpty()) return 0
        val index = kotlin.math.ceil(percentile * sorted.size).toInt().coerceIn(1, sorted.size) - 1
        return sorted[index]
    }

    fun reset() {
        synchronized(lock) { stats.clear() }
        runCatching { app?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)?.edit()?.clear()?.apply() }
    }

    private fun maybeFlush() {
        val now = System.currentTimeMillis()
        if (now - lastFlushAt < FLUSH_MIN_GAP_MS) return
        lastFlushAt = now
        flush()
    }

    private fun flush() {
        if (!persistEnabled()) return
        val ctx = app ?: return
        runCatching {
            val snapshot = synchronized(lock) {
                JSONObject().apply {
                    stats.forEach { (tool, s) ->
                        put(tool, JSONObject()
                            .put("calls", s.calls)
                            .put("ok", s.ok)
                            .put("failed", s.failed)
                            .put("totalMicros", s.totalMicros)
                            .put("maxMicros", s.maxMicros)
                            .put("lastError", s.lastError)
                            .put("lastAt", s.lastAt)
                            .put("recentMicros", JSONArray(s.recentMicros.toList())))
                    }
                }
            }
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString("stats", snapshot.toString())
                .apply()
        }
    }

    private fun loadFromDisk() {
        val ctx = app ?: return
        runCatching {
            val raw = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("stats", "{}") ?: "{}"
            val obj = JSONObject(raw)
            synchronized(lock) {
                obj.keys().forEach { tool ->
                    val s = obj.optJSONObject(tool) ?: return@forEach
                    stats[tool] = Stat(
                        calls = s.optInt("calls"),
                        ok = s.optInt("ok"),
                        failed = s.optInt("failed"),
                        totalMicros = s.optLong("totalMicros"),
                        maxMicros = s.optLong("maxMicros"),
                        lastError = s.optString("lastError"),
                        lastAt = s.optLong("lastAt"),
                    ).also { stat ->
                        val recent = s.optJSONArray("recentMicros") ?: JSONArray()
                        val start = (recent.length() - RECENT_SAMPLE_LIMIT).coerceAtLeast(0)
                        for (index in start until recent.length()) {
                            stat.recentMicros.addLast(recent.optLong(index))
                        }
                    }
                }
            }
        }
    }
}
