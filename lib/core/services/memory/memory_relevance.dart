import '../../models/memory_entry.dart';

/// 记忆**相关性**打分（取长补短自 ZCode：它用每条记忆的 `description` 判断 recall
/// 相关性，我们过去只按时间取最近 N 条——真正相关的老记忆会被新的无关条目挤掉）。
///
/// 打分只做确定性关键词命中，不引入模型调用：命中摘要（相当于 ZCode 的
/// description）权重更高，其次正文；拉丁词按词、CJK 按二元组切分。
abstract final class MemoryRelevance {
  MemoryRelevance._();

  /// 摘要命中权重（摘要就是给人/模型判断相关性的那一行）。
  static const int summaryHitWeight = 3;

  /// 正文命中权重。
  static const int contentHitWeight = 2;

  /// 切词：拉丁/数字取长度 ≥2 的词；CJK 连续段取二元组（中文没有空格）。
  static List<String> tokenize(String text) {
    final lower = text.toLowerCase();
    final tokens = <String>{};
    final latin = RegExp(r'[a-z0-9_]{2,}');
    for (final match in latin.allMatches(lower)) {
      tokens.add(match.group(0)!);
    }
    final cjkRuns = RegExp(r'[\u3400-\u9fff\u3040-\u30ff]{2,}').allMatches(lower);
    for (final run in cjkRuns) {
      final value = run.group(0)!;
      for (var i = 0; i + 2 <= value.length; i++) {
        tokens.add(value.substring(i, i + 2));
      }
    }
    return tokens.toList(growable: false);
  }

  /// 单条记忆对 [query] 的命中分（0 = 不相关）。
  static int score(MemoryEntry entry, String query) {
    final tokens = tokenize(query);
    if (tokens.isEmpty) return 0;
    final content = entry.content.toLowerCase();
    final summary = entry.summary.toLowerCase();
    var score = 0;
    for (final token in tokens) {
      if (summary.contains(token)) score += summaryHitWeight;
      if (content.contains(token)) score += contentHitWeight;
    }
    return score;
  }

  /// 批量打分（查询为空返回空表 = 调用方退回纯时间序）。
  static Map<String, int> scoreAll(
    List<MemoryEntry> entries,
    String? query,
  ) {
    final text = query?.trim() ?? '';
    if (text.isEmpty) return const <String, int>{};
    final result = <String, int>{};
    for (final entry in entries) {
      final value = score(entry, text);
      if (value > 0) result[entry.id] = value;
    }
    return result;
  }
}
