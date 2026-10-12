import 'dart:convert';

import '../../../../core/services/local_tools/local_tool_names.dart';
import 'todo_store.dart';

/// Todo 工具（模型侧任务清单）。
///
/// - `todo_write`：**整表替换**（不是增量），条目形如 `{text, status}`；
/// - `todo_read`：读回当前会话的清单。
///
/// 清单是会话级状态，长任务（尤其配合子代理）靠它做外部记忆。
class TodoToolHandler {
  TodoToolHandler({TodoStore? store}) : _store = store ?? TodoStore();

  final TodoStore _store;

  Future<String> handle(
    String toolName,
    Map<String, dynamic> args, {
    required String? conversationId,
  }) async {
    final scope = conversationId?.trim() ?? '';
    if (scope.isEmpty) {
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'conversation_required',
        'message': '任务清单是会话级的，当前没有会话上下文',
      });
    }
    switch (toolName) {
      case LocalToolNames.todoRead:
        final items = await _store.read(scope);
        return jsonEncode(<String, dynamic>{
          'ok': true,
          'todos': items.map((item) => item.toJson()).toList(growable: false),
          'counts': _counts(items),
          'rendered': renderTodoList(items),
        });
      case LocalToolNames.todoWrite:
        final raw = args['todos'];
        if (raw is! List) {
          return jsonEncode(<String, dynamic>{
            'ok': false,
            'error': 'invalid_arguments',
            'message': 'todos 必须是数组，元素形如 {"text": "...", "status": "pending|in_progress|done"}',
          });
        }
        // 逐条严格校验（用户实测报告 2-9：非法 status 被静默改写成 pending、
        // 缺 text 的条目被静默丢弃，连写两轮都没修）。契约是「无损转换才静默，
        // 其余返回结构化错误」：缺 status 默认 pending 属无损；status 非法、
        // text 缺失/超长都是**有损**，必须整批拒绝并回报下标，让调用方修。
        const maxItems = 100;
        const maxTextLength = 500;
        if (raw.length > maxItems) {
          return jsonEncode(<String, dynamic>{
            'ok': false,
            'error': 'invalid_arguments',
            'message': 'todos 条目过多：${raw.length} > $maxItems',
            'maxItems': maxItems,
          });
        }
        final items = <TodoItem>[];
        final problems = <Map<String, dynamic>>[];
        for (var i = 0; i < raw.length; i++) {
          final entry = raw[i];
          if (entry is! Map) {
            problems.add(<String, dynamic>{'index': i, 'reason': 'not_an_object'});
            continue;
          }
          final text = entry['text']?.toString().trim() ?? '';
          if (text.isEmpty) {
            problems.add(<String, dynamic>{'index': i, 'reason': 'missing_text'});
            continue;
          }
          if (text.length > maxTextLength) {
            problems.add(<String, dynamic>{
              'index': i,
              'reason': 'text_too_long',
              'length': text.length,
              'maxTextLength': maxTextLength,
            });
            continue;
          }
          var status = TodoStatus.pending;
          final rawStatus = entry['status'];
          if (rawStatus != null && rawStatus.toString().trim().isNotEmpty) {
            final wire = rawStatus.toString().trim();
            final matched = TodoStatus.values
                .where((s) => s.wireName == wire || s.name == wire)
                .firstOrNull;
            if (matched == null) {
              problems.add(<String, dynamic>{
                'index': i,
                'reason': 'invalid_status',
                'value': rawStatus,
                'allowed': TodoStatus.values
                    .map((s) => s.wireName)
                    .toList(growable: false),
              });
              continue;
            }
            status = matched;
          }
          items.add(TodoItem(text: text, status: status));
        }
        if (problems.isNotEmpty) {
          return jsonEncode(<String, dynamic>{
            'ok': false,
            'error': 'invalid_arguments',
            'message':
                '有 ${problems.length} 条不合法，**整批未写入**（避免静默丢数据）：'
                '每条必须有非空 text（≤$maxTextLength 字）与合法 status；'
                '缺 status 视为 pending。',
            'problems': problems,
            'acceptedCount': items.length,
            'rejectedCount': problems.length,
          });
        }
        await _store.write(scope, items);
        return jsonEncode(<String, dynamic>{
          'ok': true,
          'todos': items.map((item) => item.toJson()).toList(growable: false),
          'counts': _counts(items),
          'rendered': renderTodoList(items),
          'note': '整表替换成功；下次更新请带上全部条目（含已完成的）',
        });
      default:
        return jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'unknown_tool',
          'message': 'Unsupported todo tool: $toolName',
        });
    }
  }

  static Map<String, int> _counts(List<TodoItem> items) => <String, int>{
        'total': items.length,
        'pending': items.where((item) => item.status == TodoStatus.pending).length,
        'inProgress': items.where((item) => item.status == TodoStatus.inProgress).length,
        'done': items.where((item) => item.status == TodoStatus.done).length,
      };
}
