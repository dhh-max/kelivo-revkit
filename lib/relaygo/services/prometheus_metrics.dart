/// Prometheus 文本格式指标生成器
///
/// 输出标准 Prometheus 文本格式，供 Prometheus + Grafana 抓取。
/// 指标为进程级快照（多 worker 下各进程独立）。
class PrometheusMetrics {
  final List<String> _lines = [];
  final Set<String> _seen = {};

  void gauge(String name, num value, String helpText, {String labels = ''}) {
    _addMetric(name, value, helpText, 'gauge', labels);
  }

  void counter(String name, num value, String helpText, {String labels = ''}) {
    _addMetric(name, value, helpText, 'counter', labels);
  }

  void _addMetric(String name, num value, String helpText, String type,
      String labels) {
    if (!_seen.contains(name)) {
      _lines.add('# HELP $name $helpText');
      _lines.add('# TYPE $name $type');
      _seen.add(name);
    }
    final lbl = labels.isNotEmpty ? '{$labels}' : '';
    _lines.add('$name$lbl $value');
  }

  String build() => '${_lines.join('\n')}\n';

  /// 从 ProxyServer 状态生成完整指标文本
  static String generate({
    required int totalKeys,
    required int activeKeys,
    required int requestsToday,
    required int errorsToday,
    required int tokensToday,
    required int modelsCount,
    required int cacheHits,
    required int cacheMisses,
    required int cacheEntries,
    required double uptimeSeconds,
    required List<Map<String, dynamic>> perKeyStats,
  }) {
    final m = PrometheusMetrics();
    m.gauge('relaygo_keys_total', totalKeys, 'Key 总数');
    m.gauge('relaygo_keys_active', activeKeys, '可用 Key 数');
    m.counter('relaygo_requests_today', requestsToday, '今日请求数');
    m.counter('relaygo_errors_today', errorsToday, '今日错误数');
    m.counter('relaygo_tokens_today', tokensToday, '今日消耗 token');
    m.gauge('relaygo_models_count', modelsCount, '已启用模型数');
    m.counter('relaygo_cache_hits', cacheHits, '缓存命中数');
    m.counter('relaygo_cache_misses', cacheMisses, '缓存未命中数');
    m.gauge('relaygo_cache_entries', cacheEntries, '缓存条目数');
    m.gauge('relaygo_uptime_seconds', uptimeSeconds, '运行时长(秒)');

    // 每 Key 用量（带标签）
    for (final k in perKeyStats) {
      final keyId = k['key_id'] as String? ?? '';
      final provider = k['provider'] as String? ?? '';
      final labels = 'key_id="$keyId",provider="$provider"';
      m.counter('relaygo_key_requests_today',
          k['requests_today'] as int? ?? 0, '各 Key 今日请求数',
          labels: labels);
      m.counter('relaygo_key_errors_today',
          k['errors_today'] as int? ?? 0, '各 Key 今日错误数',
          labels: labels);
      m.counter('relaygo_key_tokens_today',
          k['tokens_today'] as int? ?? 0, '各 Key 今日消耗 token',
          labels: labels);
    }

    return m.build();
  }
}