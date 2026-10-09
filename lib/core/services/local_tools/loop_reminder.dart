import 'dart:convert';

/// 把环路提醒注入工具结果：JSON 对象加字段，纯文本追加一行。
///
/// 环路闸门从「首次重复就拦」改为「先提醒、达阈值再拦」后，提醒必须真的到达
/// 调用方（模型），否则等于没提醒。输入输出都是 `String?`（MCP 工具结果的形态），
/// 空提醒或空结果原样返回。
String? appendLoopReminder(String? output, String reminder) {
  if (reminder.isEmpty || output == null) return output;
  final trimmed = output.trimRight();
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      final decoded = jsonDecode(trimmed);
      if (decoded is Map) {
        return jsonEncode(<String, dynamic>{
          ...decoded.cast<String, dynamic>(),
          'loopReminder': reminder,
        });
      }
    } catch (_) {
      // 不是合法 JSON：按纯文本追加。
    }
  }
  return '$output\n\n$reminder';
}
