import 'dart:convert';

import '../../../core/services/local_tools/local_tool_names.dart';
import 'session_mode.dart';

/// 目标工具：把「目标模式」（用户侧的 `/goal`）交给模型自己建/读/推进。
///
/// 语义与用户可见的会话模式完全一致（目标模式 = 免审执行）：
/// - `create_goal`：写入目标并切到目标模式；
/// - `get_goal`：读回模式、状态、目标与「是否免审」；
/// - `update_goal`：`edit` 改目标 / `pause` 退出目标模式但保留目标 /
///   `resume` 重新进入 / `complete` 退出并清空目标（真收尾）。
///
/// 错误一律结构化返回（`{error: CODE, message: ...}`）：不抛异常、不用空结果
/// 冒充成功（与 R5 的结构化错误纪律一致）。
class GoalTools {
  GoalTools({SessionModeStore? store}) : _store = store ?? SessionModeStore();

  final SessionModeStore _store;

  /// 目标文本上限：够写两条验收标准，又不会被塞进整篇文档冒充「目标」。
  static const int maxObjectiveLength = 2000;

  static const Set<String> actions = <String>{
    'edit',
    'pause',
    'resume',
    'complete',
  };

  Future<String> handle(
    String toolName,
    Map<String, dynamic> args, {
    required String? conversationId,
  }) async {
    final id = conversationId?.trim() ?? '';
    if (id.isEmpty) {
      return _encode(const <String, dynamic>{
        'error': 'CONVERSATION_REQUIRED',
        'message': '目标按会话保存，需要 conversationId。',
      });
    }
    return switch (toolName) {
      LocalToolNames.goalGet => _encode(await _snapshot(id)),
      LocalToolNames.goalCreate => _create(id, args),
      LocalToolNames.goalUpdate => _update(id, args),
      _ => _encode(<String, dynamic>{'error': 'UNKNOWN_TOOL', 'tool': toolName}),
    };
  }

  Future<String> _create(
    String conversationId,
    Map<String, dynamic> args,
  ) async {
    final objective = (args['objective'] ?? '').toString().trim();
    final invalid = _validateObjective(objective);
    if (invalid != null) return _encode(invalid);

    await _apply(conversationId, SessionMode.goal, objective);
    return _encode(<String, dynamic>{
      ...await _snapshot(conversationId),
      'created': true,
      'note': '已进入目标模式：不再逐工具审批，请按目标自行推进并汇报证据。',
    });
  }

  Future<String> _update(
    String conversationId,
    Map<String, dynamic> args,
  ) async {
    final action = (args['action'] ?? '').toString().trim();
    if (!actions.contains(action)) {
      return _encode(<String, dynamic>{
        'error': 'INVALID_ARGUMENT',
        'message': 'action 必须是 ${actions.join(' / ')} 之一。',
        'action': action,
      });
    }

    final current = await _store.goalOf(conversationId);
    switch (action) {
      case 'edit':
        final objective = (args['objective'] ?? '').toString().trim();
        final invalid = _validateObjective(objective);
        if (invalid != null) return _encode(invalid);
        await _apply(conversationId, SessionMode.goal, objective);
      case 'pause':
        if (current.isEmpty) return _encode(_noGoal);
        await _apply(conversationId, SessionMode.build, current);
      case 'resume':
        if (current.isEmpty) return _encode(_noGoal);
        await _apply(conversationId, SessionMode.goal, current);
      case 'complete':
        await _apply(conversationId, SessionMode.build, '');
      default:
        return _encode(const <String, dynamic>{
          'error': 'INVALID_ARGUMENT',
          'message': 'unknown action',
        });
    }

    return _encode(<String, dynamic>{
      ...await _snapshot(conversationId),
      'action': action,
    });
  }

  static const Map<String, dynamic> _noGoal = <String, dynamic>{
    'error': 'NO_GOAL',
    'message': '当前没有目标；先用 create_goal 建立目标。',
  };

  Map<String, dynamic>? _validateObjective(String objective) {
    if (objective.isEmpty) {
      return const <String, dynamic>{
        'error': 'INVALID_ARGUMENT',
        'message': 'objective 不能为空。',
      };
    }
    if (objective.length > maxObjectiveLength) {
      return <String, dynamic>{
        'error': 'INVALID_ARGUMENT',
        'message': 'objective 过长（上限 $maxObjectiveLength 字符）。',
        'length': objective.length,
      };
    }
    return null;
  }

  Future<void> _apply(
    String conversationId,
    SessionMode mode,
    String goal,
  ) async {
    await _store.setGoal(conversationId, goal);
    await _store.setMode(conversationId, mode);
    // 进程内策略必须同步刷新：审批放行、工具面过滤与提示词都读它。
    SessionModeRuntime.apply(
      conversationId,
      SessionModePolicy(mode: mode, goal: goal),
    );
  }

  Future<Map<String, dynamic>> _snapshot(String conversationId) async {
    final mode = await _store.modeOf(conversationId);
    final goal = await _store.goalOf(conversationId);
    return <String, dynamic>{
      'mode': mode.wireName,
      'status': switch (mode) {
        SessionMode.goal => 'active',
        _ when goal.isNotEmpty => 'paused',
        _ => 'none',
      },
      'objective': goal,
      'bypassesApproval': mode == SessionMode.goal,
      // F-55（2026-10-04）：mode 是**会话工作模式**（build=默认档），不是
      // 「有无目标」；无目标时回 mode:"build" 曾被读成"处于构建模式"。
      // goalSet 显式给出目标有无，hint 说明两字段分工。
      'goalSet': goal.isNotEmpty,
      'hint': goal.isEmpty
          ? '当前没有设定目标（mode=build 只是默认工作档位，不代表在构建）。'
              '目标按会话生效；用户可用 /goal、/build、/plan 直接切换。'
          : '目标按会话生效；用户可用 /goal、/build、/plan 直接切换。',
    };
  }

  static String _encode(Map<String, dynamic> payload) => jsonEncode(payload);
}
