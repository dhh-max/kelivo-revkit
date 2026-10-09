/// 把 JSON 相关异常翻译成用户能看懂的中文，并尽量指出出错位置。
///
/// 2026-09-29 体验修复：以前 MCP 的 JSON 导入/编辑直接把
/// `FormatException: Unexpected character (at character 42)` 这类英文原文
/// 贴在界面上，用户既看不懂也不知道改哪儿。
String describeJsonError(Object error) {
  if (error is FormatException) {
    final offset = error.offset;
    final source = error.source;
    var where = '';
    if (offset is int && offset >= 0 && source is String && offset <= source.length) {
      final line = '\n'.allMatches(source.substring(0, offset)).length + 1;
      final lineStart = source.lastIndexOf('\n', offset - 1) + 1;
      final column = offset - lineStart + 1;
      where = '（第 $line 行第 $column 列）';
    }
    final message = error.message.trim();
    return message.isEmpty ? 'JSON 格式有误$where' : 'JSON 格式有误$where：$message';
  }
  final text = error.toString().replaceFirst('Exception: ', '').trim();
  return text.isEmpty ? 'JSON 格式有误' : text;
}
