/// 子 Agent 引入门槛（§20.2）。
///
/// 文档原话：只有在满足若干条件时才引入子 Agent，并且「没有可靠的单 Agent，
/// 不进入 P3」。所以这不是「要不要做」的开关，而是一道**可检查的门**：
/// 哪些条件是结构上已经满足的，哪些必须由人来判断。
///
/// 关键立场：「单 Agent 内核已经稳定」这条**系统不能自己给自己发合格证**。
/// 这里只把可量化的证据摆出来，由人确认。
library;

import 'task_runtime.dart';

/// 单条条件的判定。
enum ConditionStatus {
  /// 结构上已经具备，且有代码/测试为证。
  met('met', '已满足'),

  /// 还不具备。
  notMet('not_met', '未满足'),

  /// 得由人拍板（系统无法自证）。
  needsJudgement('needs_judgement', '需人工判断');

  const ConditionStatus(this.id, this.label);
  final String id;
  final String label;
}

class ReadinessCondition {
  /// 对应文档里的哪一条。
  final String requirement;
  final ConditionStatus status;

  /// 判定依据（代码位置、测试名、或实测量）。
  final String evidence;

  const ReadinessCondition({
    required this.requirement,
    required this.status,
    this.evidence = '',
  });

  Map<String, Object?> toJson() => {
        'requirement': requirement,
        'status': status.id,
        'evidence': evidence,
      };
}

/// 就绪度评估结果。
class SubagentReadiness {
  final List<ReadinessCondition> conditions;

  /// 当前任务的实测量，供人判断「内核稳不稳」。
  final Map<String, Object?> measurements;

  const SubagentReadiness({
    this.conditions = const [],
    this.measurements = const {},
  });

  List<ReadinessCondition> get blockers =>
      conditions.where((c) => c.status == ConditionStatus.notMet).toList();

  List<ReadinessCondition> get pendingJudgement => conditions
      .where((c) => c.status == ConditionStatus.needsJudgement)
      .toList();

  /// 是否可以开始引入 LLM 子 Agent。
  ///
  /// 有阻塞项、或还有人没拍板的条件时为 false——**系统不自证稳定**。
  bool get canIntroduce =>
      blockers.isEmpty && pendingJudgement.isEmpty;

  Map<String, Object?> toJson() => {
        'canIntroduce': canIntroduce,
        'conditions': [for (final c in conditions) c.toJson()],
        'blockers': [for (final b in blockers) b.requirement],
        'pendingJudgement':
            [for (final p in pendingJudgement) p.requirement],
        'measurements': measurements,
      };
}

/// 门槛评估器。
class SubagentGate {
  SubagentGate(this._runtime);

  final TaskRuntime _runtime;

  /// [stabilityConfirmed] 由人给出：单 Agent 内核是否已经稳定。
  /// 不传就视为「还没拍板」。
  Future<SubagentReadiness> evaluate({
    required String taskId,
    bool? stabilityConfirmed,
  }) async {
    final task = await _runtime.get(taskId);
    final metrics = await _runtime.metrics.collect(taskId);
    final conflicts = (await _runtime.evidence.loadConflicts(taskId))
        .where((c) => c.resolvedBy.isEmpty)
        .length;

    final conditions = <ReadinessCondition>[
      // 这几条是结构性的，代码里已经具备
      const ReadinessCondition(
        requirement: '子任务可以独立定义输入和输出',
        status: ConditionStatus.met,
        evidence: 'workers.dart: RouteExploreContext（输入）/ WorkerResult（输出）',
      ),
      const ReadinessCondition(
        requirement: '子任务结果可以结构化交接',
        status: ConditionStatus.met,
        evidence: 'WorkerResult 按 §20.4 固定字段交接（含成本与未解决问题）',
      ),
      const ReadinessCondition(
        requirement: '子任务有明确预算',
        status: ConditionStatus.met,
        evidence: '子探针走主循环，成本计入 TaskBudget（§12.3）',
      ),
      const ReadinessCondition(
        requirement: '子任务失败不会污染主任务',
        status: ConditionStatus.met,
        evidence: 'RouteWorker.guard 把异常收成 status=failed，其余路线照常',
      ),
      const ReadinessCondition(
        requirement: '子任务有明确的终止条件',
        status: ConditionStatus.met,
        evidence: '探针成本上限 + 任务预算耗尽即停',
      ),
      const ReadinessCondition(
        requirement: '子任务拥有独立上下文',
        status: ConditionStatus.needsJudgement,
        evidence: '当前 Worker 是确定性引擎，不持有对话上下文；'
            '若换成 LLM 子 Agent 需要专门设计其上下文边界',
      ),
      ReadinessCondition(
        requirement: '单 Agent 内核已经稳定',
        status: stabilityConfirmed == true
            ? ConditionStatus.met
            : ConditionStatus.needsJudgement,
        evidence: stabilityConfirmed == true
            ? '已由人工确认'
            : '系统不能自证稳定；参考实测量后由人拍板',
      ),
    ];

    return SubagentReadiness(
      conditions: conditions,
      measurements: {
        ...metrics.toJson(),
        'unresolvedConflicts': conflicts,
        if (task != null) 'status': task.status.label,
        if (task != null) 'phase': task.phase.id,
      },
    );
  }
}
