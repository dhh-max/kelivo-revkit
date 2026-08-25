/// Custom Request Merger
///
/// 移植自 Solab 项目（solab-open-source）的 CustomRequestMerger。
/// 多层级 HTTP 请求头合并：base → assistant → providerAutomatic → provider → model → protected。
/// 受保护的 assistant 头（如 x-conversation-id）始终最后写入，不可被其他层覆盖。
///
/// 同时提供请求体合并：assistant → providerRows → model，值支持字符串覆盖表达式。
class CustomRequestMerger {
  static const Set<String> _protectedAssistantHeaders = {'x-conversation-id'};

  /// 多层级合并请求头。优先级从低到高：
  /// base → assistant(ordinary) → providerAutomatic → provider → model → assistant(protected)
  static Map<String, String> mergeHeaders({
    Map<String, String> base = const <String, String>{},
    Map<String, String>? assistant,
    Map<String, String> providerAutomatic = const <String, String>{},
    Map<String, String> provider = const <String, String>{},
    Map<String, String> model = const <String, String>{},
  }) {
    final protected = <String, String>{};
    final ordinaryAssistant = <String, String>{};
    if (assistant != null) {
      for (final entry in assistant.entries) {
        if (_protectedAssistantHeaders.contains(entry.key.toLowerCase())) {
          protected[entry.key] = entry.value;
        } else {
          ordinaryAssistant[entry.key] = entry.value;
        }
      }
    }
    final merged = <String, String>{};
    for (final layer in <Map<String, String>>[
      base,
      ordinaryAssistant,
      providerAutomatic,
      provider,
      model,
      protected,
    ]) {
      _addHeadersCaseInsensitive(merged, layer);
    }
    return merged;
  }

  /// 合并请求体：assistant → providerRows → model。
  /// assistant 层的字符串值支持覆盖表达式（如 "$.temperature=0.7"）。
  static Map<String, dynamic> mergeBody({
    Map<String, dynamic>? assistant,
    Object? providerRows,
    Map<String, dynamic> model = const <String, dynamic>{},
  }) {
    final merged = <String, dynamic>{};
    if (assistant != null) {
      for (final entry in assistant.entries) {
        final value = entry.value;
        merged[entry.key] = value is String
            ? _parseOverrideValue(value)
            : value;
      }
    }
    if (providerRows is Map) {
      for (final entry in providerRows.entries) {
        merged[entry.key.toString()] = entry.value;
      }
    }
    for (final entry in model.entries) {
      merged[entry.key] = entry.value;
    }
    return merged;
  }

  static void _addHeadersCaseInsensitive(
      Map<String, String> target, Map<String, String> source) {
    for (final entry in source.entries) {
      final key = entry.key;
      final existingKey = target.keys
          .cast<String?>()
          .firstWhere(
            (k) => k?.toLowerCase() == key.toLowerCase(),
            orElse: () => null,
          );
      if (existingKey != null) {
        target[existingKey] = entry.value;
      } else {
        target[key] = entry.value;
      }
    }
  }

  /// 解析覆盖表达式。如果值以 "$." 开头，视为 JSON path 覆盖；
  /// 否则直接返回原始值。
  static dynamic _parseOverrideValue(String value) {
    // 简化版：Solab 的 ModelOverridePayloadParser 支持更复杂的表达式，
    // 此处仅做透传，保留扩展能力。
    return value;
  }
}