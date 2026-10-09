import '../../../core/models/instruction_injection.dart';

/// 把指令注入按 [InstructionInjectionPosition] 落到请求消息上。
///
/// 抽成纯函数是为了可单测：调用方只负责提供待发送的 `apiMessages` 与选中项，
/// 以及给落位消息打上下文分段标签的回调。
class InstructionInjectionPlacement {
  const InstructionInjectionPlacement._();

  /// 落位并返回各位置实际写入的条数（未产生内容的记 0）。
  static Map<InstructionInjectionPosition, int> apply(
    List<Map<String, dynamic>> apiMessages,
    List<InstructionInjection> items, {
    void Function(Map<String, dynamic> message, int length)? tag,
  }) {
    final counts = <InstructionInjectionPosition, int>{
      for (final position in InstructionInjectionPosition.values) position: 0,
    };
    if (items.isEmpty) return counts;

    for (final position in InstructionInjectionPosition.values) {
      final text = items
          .where((item) => item.position == position)
          .map((item) => item.prompt.trim())
          .where((value) => value.isNotEmpty)
          .join('\n\n');
      if (text.isEmpty) continue;
      counts[position] = _write(apiMessages, text, position, tag);
    }
    return counts;
  }

  static int _write(
    List<Map<String, dynamic>> apiMessages,
    String text,
    InstructionInjectionPosition position,
    void Function(Map<String, dynamic> message, int length)? tag,
  ) {
    switch (position) {
      case InstructionInjectionPosition.beforeSystem:
        if (apiMessages.isNotEmpty && apiMessages.first['role'] == 'system') {
          final existing = (apiMessages.first['content'] ?? '') as String;
          apiMessages.first['content'] = '$text\n\n$existing';
          tag?.call(apiMessages.first, text.length + 2);
          return 1;
        }
        final message = <String, dynamic>{'role': 'system', 'content': text};
        tag?.call(message, text.length);
        apiMessages.insert(0, message);
        return 1;

      case InstructionInjectionPosition.afterSystem:
        if (apiMessages.isNotEmpty && apiMessages.first['role'] == 'system') {
          apiMessages.first['content'] =
              "${(apiMessages.first['content'] ?? '') as String}\n\n$text";
          tag?.call(apiMessages.first, text.length + 2);
          return 1;
        }
        final message = <String, dynamic>{'role': 'system', 'content': text};
        tag?.call(message, text.length);
        apiMessages.insert(0, message);
        return 1;

      case InstructionInjectionPosition.conversationStart:
        final message = <String, dynamic>{'role': 'user', 'content': text};
        tag?.call(message, text.length);
        var index = 0;
        while (index < apiMessages.length &&
            apiMessages[index]['role'] == 'system') {
          index++;
        }
        apiMessages.insert(index, message);
        return 1;

      case InstructionInjectionPosition.beforeLatestUser:
        final message = <String, dynamic>{'role': 'user', 'content': text};
        tag?.call(message, text.length);
        var index = -1;
        for (var i = apiMessages.length - 1; i >= 0; i--) {
          if (apiMessages[i]['role'] == 'user') {
            index = i;
            break;
          }
        }
        if (index < 0) {
          apiMessages.add(message);
        } else {
          apiMessages.insert(index, message);
        }
        return 1;
    }
  }
}
