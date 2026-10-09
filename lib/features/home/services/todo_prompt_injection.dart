import 'dart:convert';

import 'todo_store.dart';

/// 会话任务清单注入（用户 2026-10-02：「客户端待办模块没有注入，agent 也没办法建待办」）。
///
/// 为什么需要它：`todo_write` / `todo_read` 两个工具本身可用，但**清单内容从没进过
/// 上下文**——模型看不到「这个会话已有任务清单」，自然也不会去维护它，表现就是
/// 「待办功能用不了」。这里把清单（或「清单为空」这一事实）按上下文分段注入，
/// 与指令注入同一套分段标记，便于面板里分项统计。
class TodoPromptInjection {
  const TodoPromptInjection._();

  /// 注入文案；返回注入的 token 长度（0 表示未注入）。
  static Future<int> inject(
    List<Map<String, dynamic>> apiMessages, {
    String? conversationId,
    void Function(Map<String, dynamic> message, int length)? tag,
    TodoStore? store,
  }) async {
    final id = conversationId?.trim() ?? '';
    if (id.isEmpty) return 0;

    final todos = await (store ?? TodoStore()).read(id);
    final text = _render(todos);
    if (text.isEmpty) return 0;

    final message = <String, dynamic>{'role': 'system', 'content': text};
    tag?.call(message, text.length);
    if (apiMessages.isNotEmpty && apiMessages.first['role'] == 'system') {
      apiMessages.first['content'] =
          '${(apiMessages.first['content'] ?? '') as String}\n\n$text';
      tag?.call(apiMessages.first, text.length + 2);
      return text.length;
    }
    apiMessages.insert(0, message);
    return text.length;
  }

  static String _render(List<TodoItem> todos) {
    if (todos.isEmpty) {
      return '<task_list>\n（当前会话任务清单为空）\n</task_list>\n'
          '多步任务先用 todo_write 登记整表再动手；单步问题不用登记。';
    }
    final lines = <String>[
      for (final item in todos) '- [${item.status.title}] ${item.text}',
    ];
    return '<task_list>\n${lines.join('\n')}\n</task_list>\n'
        '这是本会话的任务清单（todo_write 维护，整表替换语义）：'
        '开工前登记，完成一步立即更新状态，收尾时回读确认。';
  }

  /// 供测试/调试：直接拿到注入文本。
  static String render(List<TodoItem> todos) => _render(todos);

  /// 供测试：把清单序列化成 JSON（与 TodoStore 同格式）。
  static String encode(List<TodoItem> todos) =>
      jsonEncode([for (final item in todos) item.toJson()]);
}
