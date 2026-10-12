/// 关键词命中判定——T4.2 的收敛点：三个路由器（ApkTaskRouter / TaskRouter /
/// ApkAnalysisGuard）此前各写一份，语义已经漂移（有的裸 `contains`，有的带边界）。
///
/// 规则：**短 ASCII 词**（长度 ≤ 3，且只含小写字母或数字）必须按词边界命中。
/// 裸子串匹配会把 `so`/`apk`/`vip` 命中到 `also`、`flapkapk`、`viptools`
/// 这类无关串上，用户一句普通的话就能被判成 APK 任务并挂上整套工具面。含 CJK
/// 或符号的其它关键词仍走子串匹配：中文没有词边界，而带符号/较长的英文词已经
/// 足够具体（`libapp`、`.so`、`manifest`）。
///
/// 判定前统一把待匹配文本与关键词转小写，因此调用方不必先 lowercase。
library;

/// 是否在 [text] 中命中 [keyword]。
bool containsKeyword(String text, String keyword) {
  if (keyword.isEmpty) return false;
  final lowerText = text.toLowerCase();
  final lowerKeyword = keyword.toLowerCase();
  if (_needsWordBoundary(lowerKeyword)) {
    return RegExp(
      '(^|[^a-z0-9])${RegExp.escape(lowerKeyword)}([^a-z0-9]|\$)',
    ).hasMatch(lowerText);
  }
  return lowerText.contains(lowerKeyword);
}

/// 是否命中 [keywords] 中的任意一个。
bool containsAnyKeyword(String text, Iterable<String> keywords) =>
    keywords.any((keyword) => containsKeyword(text, keyword));

bool _needsWordBoundary(String keyword) {
  if (keyword.length > 3) return false;
  for (final unit in keyword.codeUnits) {
    final isLower = unit >= 0x61 && unit <= 0x7a;
    final isDigit = unit >= 0x30 && unit <= 0x39;
    if (!isLower && !isDigit) return false;
  }
  return true;
}
