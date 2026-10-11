/// 路由器共用的关键词匹配：大小写不敏感；对非 ASCII 关键词直接 `contains`，
/// 对 ASCII 关键词加词边界（避免 `vip` 匹配到 `supervisor`）。
bool containsAnyKeyword(String text, List<String> values) {
  if (text.isEmpty || values.isEmpty) return false;
  final lower = text.toLowerCase();
  for (final raw in values) {
    final kw = raw.trim().toLowerCase();
    if (kw.isEmpty) continue;
    final hasAscii = kw.contains(RegExp(r'[a-z0-9]'));
    if (!hasAscii) {
      if (lower.contains(kw)) return true;
    } else {
      final pattern = RegExp('\b' + RegExp.escape(kw) + '\b');
      if (pattern.hasMatch(lower)) return true;
    }
  }
  return false;
}
