import 'dart:math' as math;

/// Dart 面工具调用耗时聚合（C 批 / §14.15.6）。
///
/// 为什么需要它：`KotlinToolStats` 只覆盖 Kotlin 原生工具（`so_analyze:*` /
/// `blutter.*`），Dart 面五个域（dex/归档/构建/编排/系统）在真机上**没有任何
/// 运行时耗时记录**——每次体检都要靠仓库外的 harness 扫一遍，且扫的是端到端
/// 含 MCP 往返的口径，混着网络与排队。
///
/// 与 Kotlin 侧的差异（有意为之，不是漏做）：
/// - **不落盘、不读设置开关**。Dart 侧记账只做一次 map 更新（微秒级），没有
///   磁盘 I/O 可省；加一个只在真机上才生效的开关，就是 Kotlin 那处注释里
///   说过的"配置项等于谎言"。内存有界（每个工具 64 个样本、最多 256 个工具），
///   不需要内存压力钩子——上限本身就把占用钉死了。
/// - **记发布名**（`analyzer_open` 而不是内部名 `analyzer.open`），与
///   `tools/list`、`get_solab_tool_map` 的读法一致，避免同一工具两套叫法。
///
/// 快照字段名与 Kotlin 侧逐字段对齐（tool/calls/ok/failed/avgMs/p50Ms/p95Ms/
/// maxMs/sampleCount/lastError/lastAt），读法只有一套。
class DartToolStats {
  DartToolStats._();

  /// 每工具保留的最近样本数。与 Kotlin 侧同一口径（p50/p95 由窗口内样本算，
  /// 不是全历史——统计的用途是"最近慢不慢"，不是永久账本）。
  static const int recentSampleLimit = 64;

  /// 工具种类上限。超限时丢弃**最久未更新**的工具，保证长跑不无界增长。
  static const int maxTools = 256;

  static final Map<String, _Stat> _stats = <String, _Stat>{};

  /// 记一次调用。[micros] 为端到端耗时（含作用域与运行时层）。
  /// 统计键清洗（用户实测报告 2-7）：键由调用方拼装，畸形参数会在账本里留下
  /// `so_analyze:blutter<tool_sep:…` 这类伪工具。只保留 [A-Za-z0-9_.:-]，其余折叠
  /// 成 `_`，限长 64；清洗后为空记 unknown。与 Kotlin 侧同一口径。
  static String sanitizeToolKey(String tool) {
    final buffer = StringBuffer();
    for (final unit in tool.codeUnits) {
      if (buffer.length >= 64) break;
      final isAsciiAlnum =
          (unit >= 0x30 && unit <= 0x39) ||
          (unit >= 0x41 && unit <= 0x5A) ||
          (unit >= 0x61 && unit <= 0x7A);
      final ch = String.fromCharCode(unit);
      final keep = isAsciiAlnum || ch == '_' || ch == '.' || ch == ':' || ch == '-';
      buffer.write(keep ? ch : '_');
    }
    final cleaned = buffer.toString().replaceAll(RegExp(r'^_+|_+$'), '');
    return cleaned.isEmpty ? 'unknown' : cleaned;
  }

  static void record(String tool, bool ok, int micros, {String error = ''}) {
    tool = sanitizeToolKey(tool);
    final now = DateTime.now().millisecondsSinceEpoch;
    final stat = _stats.putIfAbsent(tool, _Stat.new);
    stat.calls++;
    if (ok) {
      stat.ok++;
    } else {
      stat.failed++;
      if (error.isNotEmpty) stat.lastError = error;
    }
    stat.totalMicros += micros;
    if (micros > stat.maxMicros) stat.maxMicros = micros;
    stat.recentMicros.add(micros);
    if (stat.recentMicros.length > recentSampleLimit) {
      stat.recentMicros.removeAt(0);
    }
    stat.lastAt = now;
    if (_stats.length > maxTools) _evictOldest();
  }

  /// 清空（测试与真机复测的"从零起算"用）。
  static void reset() => _stats.clear();

  /// 快照：与 Kotlin `KotlinToolStats.snapshot()` 同形，便于调用方一套读法。
  static Map<String, Object?> snapshot() {
    final rows = <Map<String, Object?>>[];
    var totalCalls = 0;
    var totalOk = 0;
    var totalFailed = 0;
    for (final entry in _stats.entries) {
      final stat = entry.value;
      totalCalls += stat.calls;
      totalOk += stat.ok;
      totalFailed += stat.failed;
      rows.add(_row(entry.key, stat));
    }
    rows.sort((a, b) => (b['lastAt'] as int).compareTo(a['lastAt'] as int));
    final slowest = List<Map<String, Object?>>.from(rows)
      ..sort((a, b) {
        final byP95 = (b['p95Ms'] as int).compareTo(a['p95Ms'] as int);
        if (byP95 != 0) return byP95;
        return (b['maxMs'] as int).compareTo(a['maxMs'] as int);
      });
    return <String, Object?>{
      'tools': rows,
      'slowestTools': slowest,
      'distinctTools': rows.length,
      'totalCalls': totalCalls,
      'totalOk': totalOk,
      'totalFailed': totalFailed,
    };
  }

  static Map<String, Object?> _row(String tool, _Stat stat) {
    final samples = List<int>.from(stat.recentMicros)..sort();
    return <String, Object?>{
      'tool': tool,
      'calls': stat.calls,
      'ok': stat.ok,
      'failed': stat.failed,
      'avgMs': stat.calls > 0 ? stat.totalMicros ~/ 1000 ~/ stat.calls : 0,
      'p50Ms': _percentileMs(samples, 0.50),
      'p95Ms': _percentileMs(samples, 0.95),
      'maxMs': stat.maxMicros ~/ 1000,
      'sampleCount': samples.length,
      'lastError': stat.lastError,
      'lastAt': stat.lastAt,
    };
  }

  /// 与 Kotlin 侧同式：`ceil(p * n) - 1`，n=0 时 0。
  static int _percentileMs(List<int> sortedMicros, double percentile) {
    if (sortedMicros.isEmpty) return 0;
    final index = (percentile * sortedMicros.length).ceil().clamp(
      1,
      sortedMicros.length,
    ) - 1;
    return sortedMicros[index] ~/ 1000;
  }

  static void _evictOldest() {
    String? oldestKey;
    var oldestAt = 1 << 62;
    for (final entry in _stats.entries) {
      if (entry.value.lastAt < oldestAt) {
        oldestAt = entry.value.lastAt;
        oldestKey = entry.key;
      }
    }
    if (oldestKey != null) _stats.remove(oldestKey);
  }

  /// 失败样本的短线索。两种形状都要认（真机实测，2026-09-21）：
  ///
  /// - `"code":"invalid_args"` —— analyzer / 归一后的结构化形式；
  /// - `"error":"STEP_FAILED"` —— handler 在**咽喉处**的原样形式（`code` 对象是
  ///   MCP 归一层后来才加的，所以只看前者会让 lastError 常年为空）。
  ///
  /// 值必须是**码样**（单 token、无空格、≤40 字符）才收；一串人话消息不算。
  /// 只在失败时扫一次且限长 64KB——成功路径不做任何额外解析
  /// （[ToolCallLoopGuard.succeeded] 的快路径本就为省掉 512KB 全量 decode 而
  /// 存在，这里不能再把它抵消掉）。找不到就留空，不猜。
  static String errorHint(String output) {
    if (output.length > 64 * 1024) return '';
    return _valueAfter(output, '"code":"') ??
        _valueAfter(output, '"error":"') ??
        '';
  }

  static String? _valueAfter(String output, String marker) {
    final start = output.indexOf(marker);
    if (start < 0) return null;
    final from = start + marker.length;
    final end = output.indexOf('"', from);
    if (end < 0) return null;
    final value = output.substring(from, end);
    if (value.isEmpty || value.length > 40) return null;
    for (final codeUnit in value.codeUnits) {
      final c = String.fromCharCode(codeUnit);
      final isWord = (codeUnit >= 0x30 && codeUnit <= 0x39) ||
          (codeUnit >= 0x41 && codeUnit <= 0x5A) ||
          (codeUnit >= 0x61 && codeUnit <= 0x7A);
      if (!isWord && c != '_' && c != '.' && c != '-') return null;
    }
    return value;
  }

  /// 供单测断言"确实有界"，不参与业务判定。
  static int get trackedToolCount => _stats.length;

  /// 仅测试用：把样本压到接近上限后验证淘汰，不必真跑 256 个工具。
  static void debugTrimTo(int keepCount) {
    while (_stats.length > math.max(1, keepCount)) {
      _evictOldest();
    }
  }
}

class _Stat {
  int calls = 0;
  int ok = 0;
  int failed = 0;
  int totalMicros = 0;
  int maxMicros = 0;
  String lastError = '';
  int lastAt = 0;
  final List<int> recentMicros = <int>[];
}
