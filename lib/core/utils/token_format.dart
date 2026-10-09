/// 紧凑 token 计数：`517` / `12.2K` / `517K` / `1.2M`。
///
/// 对齐 deepseek-harness `client/ui-chat/chat/token-format.ts` 的标准：
/// 小于 1000 原样；千位 `K`、百万位 `M`；缩放值 ≥100 取整，否则保留一位小数
/// （整数不留 `.0`）。
String formatTokenCount(int tokens) {
  if (tokens < 1000) return '$tokens';
  if (tokens < 1000000) return '${_compact(tokens / 1000)}K';
  return '${_compact(tokens / 1000000)}M';
}

String _compact(double value) {
  if (value >= 100) return '${value.round()}';
  final rounded = (value * 10).round() / 10;
  return rounded == rounded.roundToDouble()
      ? '${rounded.round()}'
      : rounded.toStringAsFixed(1);
}
