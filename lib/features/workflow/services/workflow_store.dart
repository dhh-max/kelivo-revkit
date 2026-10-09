import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import '../models/workflow_models.dart';

/// 工作流定义存储（prefs JSON 列表，与子代理注册表同一套纪律）。
///
/// 只存定义；运行状态（哪次运行跑到哪）不落盘——它是易失的观测面，
/// 重启后重跑即可（与 SubAgentRunMonitor 的取向一致）。
///
/// 2026-10-03 起不再内置模板（用户定性：内置的没用）：全部条目都是
/// 用户在页面里手建或 **AI 生成**（[WorkflowGeneration]）落库的。
class WorkflowStore {
  WorkflowStore({SharedPreferences? preferences}) : _injected = preferences;

  static const String prefsKey = 'workflows_v1';

  final SharedPreferences? _injected;
  SharedPreferences? _prefs;

  Future<SharedPreferences> _open() async =>
      _injected ?? (_prefs ??= await SharedPreferences.getInstance());

  /// 全部工作流（用户数据，列表即 prefs 原序：新存的在前）。
  Future<List<WorkflowDefinition>> all() async => _custom();

  /// 对话面可见的工作流：只含开了单开关的条目（run_workflow 清单/执行用）。
  Future<List<WorkflowDefinition>> enabled() async =>
      (await _custom()).where((flow) => flow.enabled).toList(growable: false);

  Future<List<WorkflowDefinition>> _custom() async {
    final prefs = await _open();
    try {
      final decoded = jsonDecode(prefs.getString(prefsKey) ?? '[]');
      if (decoded is! List) return <WorkflowDefinition>[];
      return <WorkflowDefinition>[
        for (final entry in decoded)
          if (WorkflowDefinition.fromJson(entry) case final flow?) flow,
      ];
    } catch (_) {
      // 脏数据不阻断：退回空列表。
      //
      // 注意必须是**可增长**的列表：save/delete 会在这个返回值上原地
      // insert/removeWhere，返回 const [] 会让它们抛 UnsupportedError
      // （脏数据把「读」救回来了，却让「写」炸掉）。
      return <WorkflowDefinition>[];
    }
  }

  Future<WorkflowDefinition?> byId(String id) async {
    for (final flow in await all()) {
      if (flow.id == id) return flow;
    }
    return null;
  }

  /// 新增或覆盖（按 id 匹配）。
  Future<void> save(WorkflowDefinition flow) async {
    final prefs = await _open();
    final list = await _custom();
    final stamped = flow.copyWith(updatedAt: DateTime.now().millisecondsSinceEpoch);
    final index = list.indexWhere((item) => item.id == stamped.id);
    if (index >= 0) {
      list[index] = stamped;
    } else {
      list.insert(0, stamped);
    }
    await _write(prefs, list);
  }

  Future<void> delete(String id) async {
    final prefs = await _open();
    final list = await _custom()..removeWhere((flow) => flow.id == id);
    await _write(prefs, list);
  }

  Future<void> _write(
    SharedPreferences prefs,
    List<WorkflowDefinition> list,
  ) async {
    await prefs.setString(
      prefsKey,
      jsonEncode(list.map((flow) => flow.toJson()).toList(growable: false)),
    );
  }
}
