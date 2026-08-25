/// Search API Key Rotator
///
/// 移植自 Solab 项目（solab-open-source）的 SearchApiKeyRotator。
/// 为搜索服务提供多 key 轮换：支持批量解析、去重、掩码显示。
///
/// 能力：
/// - [select] 按 serviceId 轮换选择下一个 key（round-robin）
/// - [parseBatch] 批量解析（换行/逗号/分号/空格分隔，去重保序）
/// - [mask] 掩码 key（首尾各保留 4 字符）
/// - [rotationPool] 获取轮换池
class SearchApiKeyRotator {
  SearchApiKeyRotator._();
  static final SearchApiKeyRotator instance = SearchApiKeyRotator._();
  final Map<String, int> _indices = {}; // serviceId -> next pool index

  /// Picks the key to use for the next request of [serviceId].
  String select(String serviceId, String primary, List<String> extras) {
    final pool = _pool(primary, extras);
    if (pool.isEmpty) return primary;
    if (pool.length == 1) return pool.first;
    final current = _indices[serviceId] ?? 0;
    final index = current % pool.length;
    _indices[serviceId] = (index + 1) % pool.length;
    return pool[index];
  }

  /// All keys that participate in rotation, in rotation order.
  static List<String> rotationPool(String primary, List<String> extras) =>
      _pool(primary, extras);

  /// Splits a batch paste into individual keys.
  static List<String> parseBatch(String input) {
    final seen = <String>{};
    final keys = <String>[];
    for (final part in input.split(RegExp(r'[\s,;]+'))) {
      final key = part.trim();
      if (key.isEmpty || !seen.add(key)) continue;
      keys.add(key);
    }
    return keys;
  }

  /// Masks a key for display, keeping the first and last four characters.
  static String mask(String key) {
    final trimmed = key.trim();
    if (trimmed.length <= 8) return '••••••••';
    return '${trimmed.substring(0, 4)}••••${trimmed.substring(trimmed.length - 4)}';
  }

  static List<String> _pool(String primary, List<String> extras) {
    final seen = <String>{};
    final pool = <String>[];
    void add(String key) {
      final trimmed = key.trim();
      if (trimmed.isEmpty || !seen.add(trimmed)) return;
      pool.add(trimmed);
    }
    add(primary);
    for (final key in extras) {
      add(key);
    }
    return pool;
  }
}