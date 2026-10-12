import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/foundation.dart';

/// Todo 工具的状态。
enum TodoStatus {
  pending('pending', '未开始'),
  inProgress('in_progress', '进行中'),
  done('done', '已完成');

  const TodoStatus(this.wireName, this.title);

  final String wireName;
  final String title;

  static TodoStatus fromWire(String? value) => TodoStatus.values.firstWhere(
        (status) => status.wireName == value || status.name == value,
        orElse: () => TodoStatus.pending,
      );
}

class TodoItem {
  const TodoItem({required this.text, required this.status});

  final String text;
  final TodoStatus status;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'text': text,
        'status': status.wireName,
      };

  static TodoItem? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final text = raw['text']?.toString().trim() ?? '';
    if (text.isEmpty) return null;
    return TodoItem(text: text, status: TodoStatus.fromWire(raw['status']?.toString()));
  }
}

/// 会话级任务清单（todo_write / todo_read 两个工具的落点）。
///
/// 存 prefs（按会话 id 索引）而不是 Conversation 生成模型——加字段要跑
/// build_runner 还牵连迁移，收益不值当。
class TodoStore {
  TodoStore({SharedPreferences? preferences}) : _injected = preferences;

  static const String prefsKey = 'session_todos_v1';

  /// 清单变更广播（值 = 变更次数）。
  ///
  /// 会话级任务清单要有 UI：面板挂在输入 dock 上，`todo_write` 落地后必须立刻
  /// 重读，否则用户会看到「建了待办但界面没反应」（用户 2026-10-03 实测）。
  /// 存的是 prefs，本身没有通知通道，这里补一个自增计数。
  static final ValueNotifier<int> revision = ValueNotifier<int>(0);

  final SharedPreferences? _injected;
  SharedPreferences? _prefs;

  Future<SharedPreferences> _open() async =>
      _injected ?? (_prefs ??= await SharedPreferences.getInstance());

  Future<List<TodoItem>> read(String conversationId) async {
    if (conversationId.isEmpty) return const <TodoItem>[];
    final prefs = await _open();
    final raw = prefs.getString(prefsKey);
    if (raw == null || raw.isEmpty) return const <TodoItem>[];
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return const <TodoItem>[];
      final list = decoded[conversationId];
      if (list is! List) return const <TodoItem>[];
      return list
          .map(TodoItem.fromJson)
          .whereType<TodoItem>()
          .toList(growable: false);
    } catch (_) {
      return const <TodoItem>[];
    }
  }

  Future<List<TodoItem>> write(String conversationId, List<TodoItem> items) async {
    if (conversationId.isEmpty) return items;
    final prefs = await _open();
    Map<String, dynamic> map;
    try {
      final decoded = jsonDecode(prefs.getString(prefsKey) ?? '{}');
      map = decoded is Map ? Map<String, dynamic>.from(decoded) : <String, dynamic>{};
    } catch (_) {
      map = <String, dynamic>{};
    }
    if (items.isEmpty) {
      map.remove(conversationId);
    } else {
      map[conversationId] = items.map((item) => item.toJson()).toList(growable: false);
    }
    await prefs.setString(prefsKey, jsonEncode(map));
    revision.value++;
    return items;
  }
}

/// 把清单渲染成给模型/用户看的一段纯文本。
String renderTodoList(List<TodoItem> items) {
  if (items.isEmpty) return '（当前没有任务）';
  final buffer = StringBuffer();
  for (final item in items) {
    final mark = switch (item.status) {
      TodoStatus.done => '[x]',
      TodoStatus.inProgress => '[~]',
      TodoStatus.pending => '[ ]',
    };
    buffer.writeln('$mark ${item.text}');
  }
  return buffer.toString().trimRight();
}
