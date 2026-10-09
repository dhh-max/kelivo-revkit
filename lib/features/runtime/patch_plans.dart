/// 修改计划视图（§14.3 Patch Plan、§14.4 Dry Run、§14.5 修改验证）。
///
/// 计划本身写在事件流里（`patch.planned`），Dry Run 结果写在 `patch.dry_run`。
/// 这里把两者拼成一份**可读、可核对**的视图：改哪里、依据是什么、改成什么样、
/// 检查过没有。§14.1 要求「修改前必须生成 Patch Plan」，所以这张表就是
/// 「凭什么这么改」的唯一凭据。
library;

import 'task_runtime.dart';

/// Dry Run 状态。
class DryRunState {
  DryRunState._();

  static const notRun = 'not_run';
  static const passed = 'passed';
  static const failed = 'failed';
}

/// 一条修改计划的可读视图。
class PatchPlanView {
  final String patchId;
  final String targetArtifact;
  final String targetMethod;
  final String operation;
  final String reason;
  final String risk;
  final List<String> preconditions;
  final List<String> evidenceIds;
  final String before;
  final String after;
  final String rollback;
  final String dryRun;
  final List<Map<String, Object?>> dryRunChecks;
  final int createdAt;

  const PatchPlanView({
    required this.patchId,
    this.targetArtifact = '',
    this.targetMethod = '',
    this.operation = '',
    this.reason = '',
    this.risk = 'medium',
    this.preconditions = const [],
    this.evidenceIds = const [],
    this.before = '',
    this.after = '',
    this.rollback = '',
    this.dryRun = DryRunState.notRun,
    this.dryRunChecks = const [],
    this.createdAt = 0,
  });

  /// 是否可以直接执行：必须先过 Dry Run（§14.4）。
  bool get readyToApply => dryRun == DryRunState.passed;

  /// 是否有预览内容可看。
  bool get hasPreview => before.isNotEmpty || after.isNotEmpty;

  /// 是否高风险（§14.6：high/critical 要用户确认）。
  bool get needsConfirmation => risk == 'high' || risk == 'critical';

  Map<String, Object?> toJson() => {
        'patchId': patchId,
        'targetArtifact': targetArtifact,
        'targetMethod': targetMethod,
        'operation': operation,
        'reason': reason,
        'risk': risk,
        'preconditions': preconditions,
        'evidenceIds': evidenceIds,
        'before': before,
        'after': after,
        'rollback': rollback,
        'dryRun': dryRun,
        'dryRunChecks': dryRunChecks,
        'readyToApply': readyToApply,
        'createdAt': createdAt,
      };
}

/// 从事件流里还原修改计划。
class PatchPlanStore {
  PatchPlanStore(this._runtime);

  final TaskRuntime _runtime;

  Future<List<PatchPlanView>> list(String taskId) async {
    final events = await _runtime.store.loadEvents(taskId);

    // Dry Run 结果按 patchId 归并（同一计划可能跑了多次，最后一次说了算）
    final dryRun = <String, Map<String, Object?>>{};
    for (final e in events) {
      if (e.type != 'patch.dry_run') continue;
      final id = e.payload['patchId']?.toString() ?? '';
      if (id.isNotEmpty) dryRun[id] = e.payload;
    }

    final out = <PatchPlanView>[];
    for (final e in events) {
      if (e.type != 'patch.planned') continue;
      final p = e.payload;
      final patchId = p['patchId']?.toString() ?? '';
      final preview = p['preview'];
      final before = preview is Map ? preview['before']?.toString() ?? '' : '';
      final after = preview is Map ? preview['after']?.toString() ?? '' : '';
      final run = dryRun[patchId];
      final passed = run?['passed'];
      out.add(PatchPlanView(
        patchId: patchId,
        targetArtifact: p['targetArtifact']?.toString() ?? '',
        targetMethod: p['targetMethod']?.toString() ?? '',
        operation: p['operation']?.toString() ?? '',
        reason: p['reason']?.toString() ?? '',
        risk: p['risk']?.toString() ?? 'medium',
        preconditions: _strList(p['preconditions']),
        evidenceIds: _strList(p['evidenceIds']),
        before: before,
        after: after,
        rollback: p['rollback']?.toString() ?? '',
        dryRun: run == null
            ? DryRunState.notRun
            : (passed == true ? DryRunState.passed : DryRunState.failed),
        dryRunChecks: [
          for (final c in (run?['checks'] as List? ?? const []))
            if (c is Map) Map<String, Object?>.from(c)
        ],
        createdAt: e.createdAt,
      ));
    }
    out.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    return out;
  }

  static List<String> _strList(Object? raw) => [
        for (final x in (raw as List? ?? const [])) x.toString(),
      ];
}
