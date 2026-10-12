/// 任务运行时（§5 Agent Runtime 的确定性部分）。
///
/// 只做三件事，但都是模型不能代劳的：
/// 1. 推进状态——带进入条件校验，模型不能伪造（§13.4）；
/// 2. 记账——工具调用与预算（§12.3）；
/// 3. 落证据与事件——一切结论可回溯（§11.6）。
///
/// 注意：这里**不调用模型**。模型循环仍在 ChatEngine，本类只提供被它调用的
/// 确定性接口，符合「模型负责推理，系统负责确定性工作」（§2.3）。
library;

import 'package:uuid/uuid.dart';
import 'package:path/path.dart' as p;
import 'dart:io';

import 'capability_manifest.dart';
import 'artifact_store.dart';
import 'evidence_store.dart';
import 'failure_memory.dart';
import 'multi_dex.dart';
import 'metrics.dart';
import 'model_gateway.dart';
import 'patch_plans.dart';
import 'subagent_gate.dart';
import 'models/evidence.dart';
import 'models/task.dart';
import 'models/task_event.dart';
import 'task_store.dart';
import 'workspace_manager.dart';

/// 一次状态推进被拒绝的原因。
class AdvanceRejection implements Exception {
  final TaskStatus from;
  final TaskStatus to;
  final String reason;

  const AdvanceRejection(this.from, this.to, this.reason);

  @override
  String toString() => '状态不能从 ${from.label} 推进到 ${to.label}：$reason';
}

class TaskRuntime {
  TaskRuntime({
    TaskStore? store,
    EvidenceStore? evidence,
    WorkspaceManager? workspace,
    FailureMemoryStore? failures,
    UsageLedger? usage,
    ArtifactStore? artifacts,
    String Function()? idFactory,
    int Function()? clock,
  })  : _newId = idFactory ?? (() => const Uuid().v4()),
        _now = clock ?? (() => DateTime.now().millisecondsSinceEpoch) {
    // 三个 store 必须共用同一个 TaskStore 实例，否则事件/证据/工作区会写散。
    this.store = store ?? TaskStore();
    this.evidence = evidence ?? EvidenceStore(this.store);
    this.workspace = workspace ?? WorkspaceManager(this.store);
    this.failures = failures ?? FailureMemoryStore(this.store);
    this.usage = usage ?? UsageLedger(this.store);
    metrics = MetricsCollector(this);
    patchPlans = PatchPlanStore(this);
    subagentGate = SubagentGate(this);
    this.artifacts = artifacts ?? ArtifactStore(this.store);
  }

  late final TaskStore store;
  late final EvidenceStore evidence;
  late final WorkspaceManager workspace;
  late final FailureMemoryStore failures;
  late final UsageLedger usage;
  late final MetricsCollector metrics;
  late final PatchPlanStore patchPlans;
  late final SubagentGate subagentGate;
  late final ArtifactStore artifacts;

  final String Function() _newId;
  final int Function() _now;

  /// 创建任务并立刻建立工作区，推进到 Prepared。
  ///
  /// 身份确认（APK 存在且可读）不通过时不建任务——避免留下半截工作区。
  Future<Task> createTask({
    required String goal,
    required String inputApk,
    String? title,
    TaskConstraints constraints = const TaskConstraints(),
    TaskBudget budget = const TaskBudget(),
    /// 本任务顶替了哪条旧任务（换目标包重建时由 [TaskSession.ensureTask] 传入）。
    /// 只进事件溯源，不改 schema——审计看到同一作用域先后出现两个 taskId 时，
    /// 能从这里读出「为什么换、换掉了谁」（v9-N2：v11 起被当成不一致）。
    String replacesTaskId = '',
    String replaceReason = '',
  }) async {
    final now = _now();
    final id = 'task_${_short(_newId())}';
    var task = Task(
      id: id,
      title: title ?? _titleFromGoal(goal),
      contract: TaskContract(
        goal: goal,
        inputApk: inputApk,
        constraints: constraints,
      ),
      status: TaskStatus.created,
      phase: TaskPhase.prepare,
      budget: budget,
      createdAt: now,
      updatedAt: now,
    );
    await store.save(task);
    await store.appendEvent(TaskEvent(
      id: 'evt_${_newId()}',
      taskId: id,
      type: TaskEventType.created,
      phase: TaskPhase.prepare.id,
      payload: {
        'goal': goal,
        'inputApk': inputApk,
        if (replacesTaskId.isNotEmpty) 'replacesTaskId': replacesTaskId,
        if (replaceReason.isNotEmpty) 'replaceReason': replaceReason,
      },
      createdAt: now,
    ));

    final ws = await workspace.prepare(
      taskId: id,
      sourceApkPath: inputApk,
      now: now,
    );
    task = task.copyWith(workspacePath: ws.path, updatedAt: _now());
    await store.save(task);

    // 源包登记（§23.3）：产物血缘链的起点，指向工作区内的只读副本。
    // F-13/F-16（v11 复测）：同时记下设备原件路径（originPath）——交付报告
    // 引用的是设备原包，不能让 runtime 副本路径成为交付源头。
    final copy = File(p.join(ws.path, 'input', p.basename(inputApk)));
    await artifacts.register(
      taskId: id,
      kind: ArtifactKind.inputApk,
      path: copy.path,
      now: now,
      idFactory: 'art_input_$id',
      originPath: inputApk,
    );

    await store.appendEvent(TaskEvent(
      id: 'evt_${_newId()}',
      taskId: id,
      type: TaskEventType.workspacePrepared,
      phase: TaskPhase.prepare.id,
      payload: {'workspacePath': ws.path},
      createdAt: _now(),
    ));
    return advance(id, TaskStatus.prepared, reason: '工作区已建立，输入 APK 已登记');
  }

  Future<Task?> get(String taskId) => store.load(taskId);

  /// 推进状态。校验不通过抛 [AdvanceRejection]（不静默失败）。
  Future<Task> advance(
    String taskId,
    TaskStatus next, {
    required String reason,
  }) async {
    final task = await store.load(taskId);
    if (task == null) {
      throw StateError('任务不存在：$taskId');
    }
    if (!task.status.canAdvanceTo(next)) {
      throw AdvanceRejection(task.status, next, '状态机不允许这一步');
    }

    final gate = await _entryGuard(task, next);
    if (gate != null) {
      throw AdvanceRejection(task.status, next, gate);
    }

    final updated = task.copyWith(
      status: next,
      phase: _phaseForStatus(next, task.phase),
      updatedAt: _now(),
    );
    await store.save(updated);
    await store.appendEvent(TaskEvent(
      id: 'evt_${_newId()}',
      taskId: taskId,
      type: TaskEventType.statusChanged,
      phase: updated.phase.id,
      payload: {
        'from': task.status.label,
        'to': next.label,
        'reason': reason,
      },
      createdAt: _now(),
    ));
    return updated;
  }

  /// 进入条件校验（§13.2 的「进入条件」列）。
  ///
  /// 返回 null 表示放行，返回字符串表示拒绝原因。
  Future<String?> _entryGuard(Task task, TaskStatus next) async {
    switch (next) {
      case TaskStatus.prepared:
        if (task.contract.inputApk.trim().isEmpty) return '未登记输入 APK';
        if (task.workspacePath.trim().isEmpty) return '工作区未建立';
        return null;

      case TaskStatus.analyzed:
        final events = await store.loadEvents(task.id);
        // v7 D7/F-06：与 task_session._isAnalysisTool 同一口径——so_analyze 与
        // analyzer.* 也是分析入口（旧判据只认 'analyze*' 前缀，用 so_analyze 做的
        // 分析在这里查不到 → task_update(analyzed) 被误拒）。
        final ran = events.any((e) {
          if (e.type != TaskEventType.toolCalled) return false;
          final tool = (e.payload['tool']?.toString() ?? '').trim().toLowerCase();
          if (tool.isEmpty) return false;
          return tool.startsWith('analyze') ||
              tool == 'so_analyze' ||
              tool.startsWith('analyzer');
        });
        return ran ? null : '尚未执行过基础分析';

      case TaskStatus.located:
        // 定位的硬门槛：至少一条 Observed 以上、且没有未决冲突（§11.3 / §11.4）。
        if (await evidence.hasUnresolved(task.id)) {
          return '存在未决的证据冲突，需先用第三个独立证据解决';
        }
        final level = await evidence.highestLevel(task.id);
        if (level == null) return '证据库为空，定位无依据';
        if (level < EvidenceLevel.observed) {
          return '证据等级只有 ${level.label}，不足以认定已定位';
        }
        return null;

      case TaskStatus.planned:
        final events = await store.loadEvents(task.id);
        final planned = events.any((e) => e.type == TaskEventType.patchPlanned);
        return planned ? null : '尚未生成 Patch Plan';

      case TaskStatus.dryRunVerified:
        final events = await store.loadEvents(task.id);
        final ok = events.any((e) =>
            e.type == TaskEventType.patchDryRun && e.payload['passed'] == true);
        return ok ? null : 'Dry Run 未通过，禁止修改';

      case TaskStatus.modified:
        if (!task.contract.constraints.allowModification) {
          return '该任务未授权修改 APK';
        }
        return null;

      case TaskStatus.built:
      case TaskStatus.signed:
      case TaskStatus.verified:
      case TaskStatus.delivered:
        return null;

      default:
        return null;
    }
  }

  /// 状态 → 阶段（§6.4 阶段划分）。
  TaskPhase _phaseForStatus(TaskStatus s, TaskPhase fallback) {
    switch (s) {
      case TaskStatus.created:
      case TaskStatus.prepared:
        return TaskPhase.prepare;
      case TaskStatus.analyzed:
        return TaskPhase.analyze;
      case TaskStatus.located:
        return TaskPhase.locate;
      case TaskStatus.planned:
      case TaskStatus.dryRunVerified:
      case TaskStatus.modified:
        return TaskPhase.modify;
      case TaskStatus.built:
      case TaskStatus.signed:
      case TaskStatus.verified:
      case TaskStatus.delivered:
        return TaskPhase.deliver;
      case TaskStatus.paused:
      case TaskStatus.waitingConfirmation:
      case TaskStatus.failedRecoverable:
      case TaskStatus.failedTerminal:
        return fallback;
    }
  }

  /// 暂停 / 恢复（§13.3）。
  Future<Task> pause(String taskId, {String reason = ''}) =>
      advance(taskId, TaskStatus.paused, reason: reason.isEmpty ? '用户暂停' : reason);

  Future<Task> resume(String taskId) async {
    final task = await store.load(taskId);
    if (task == null) throw StateError('任务不存在：$taskId');
    if (task.status != TaskStatus.paused &&
        task.status != TaskStatus.failedRecoverable) {
      throw AdvanceRejection(task.status, task.status, '当前状态无需恢复');
    }
    // 回到进入异常态之前的最后一个主链路状态（§13.3「可恢复」）。
    // 事件流是唯一依据：倒着找最近一次「推进到主链路状态」的记录。
    final events = await store.loadEvents(taskId);
    var target = TaskStatus.prepared;
    for (final e in events.reversed) {
      if (e.type != TaskEventType.statusChanged) continue;
      final to = TaskStatus.fromLabel(e.payload['to']?.toString() ?? '');
      if (to.isLinear) {
        target = to;
        break;
      }
    }
    return advance(taskId, target, reason: '恢复任务');
  }

  /// 等待用户确认（§18 高风险操作）。
  Future<Task> awaitConfirmation(String taskId, {required String reason}) =>
      advance(taskId, TaskStatus.waitingConfirmation, reason: reason);

  /// 记录失败（§17）：更新状态并写入 Failure Memory。
  Future<Task> recordFailure({
    required String taskId,
    required String pattern,
    required String lesson,
    String operation = '',
    String action = '',
    String scope = FailureScope.tool,
    Map<String, Object?> evidencePayload = const {},
    bool recoverable = true,
  }) async {
    final task = await store.load(taskId);
    if (task == null) throw StateError('任务不存在：$taskId');
    final now = _now();

    await failures.recordFailure(
      id: 'fail_${_newId()}',
      taskId: taskId,
      pattern: pattern,
      now: now,
      phase: task.phase.id,
      operation: operation,
      evidence: evidencePayload,
      action: action,
      outcome: recoverable ? FailureOutcome.pending : FailureOutcome.blocked,
      lesson: lesson,
      scope: scope,
    );
    await store.appendEvent(TaskEvent(
      id: 'evt_${_newId()}',
      taskId: taskId,
      type: TaskEventType.failureRecorded,
      phase: task.phase.id,
      payload: {
        'pattern': pattern,
        'operation': operation,
        'lesson': lesson,
        'recoverable': recoverable,
      },
      createdAt: now,
    ));
    return advance(
      taskId,
      recoverable ? TaskStatus.failedRecoverable : TaskStatus.failedTerminal,
      reason: pattern,
    );
  }

  // ------------------------------------------------------------- 证据与记账

  /// 写入一条证据。等级默认 Candidate——需要更强证据时显式给（§11.3）。
  Future<Evidence> addEvidence({
    required String taskId,
    required String claim,
    required EvidenceSource source,
    String type = '',
    EvidenceLevel level = EvidenceLevel.candidate,
    Map<String, Object?> rawRef = const {},
    List<Map<String, Object?>> relations = const [],
    String toolCallId = '',
  }) async {
    final ev = Evidence(
      id: 'ev_${_short(_newId())}',
      taskId: taskId,
      type: type.isNotEmpty ? type : EvidenceKind.string.label,
      level: level,
      claim: claim,
      source: source,
      rawRef: rawRef,
      relations: relations,
      toolCallId: toolCallId,
      createdAt: _now(),
    );
    return evidence.add(ev);
  }

  /// 记一次工具调用：扣预算 + 写事件（§8.4 每个结果都有稳定 ID）。
  ///
  /// 返回调用 id（写到证据的 toolCallId 上）。
  Future<String> recordToolCall({
    required String taskId,
    required String tool,
    required Map<String, Object?> arguments,
    required int cost,
    bool ok = true,
    String? errorCode,
    Map<String, Object?> extra = const {},
  }) async {
    final invocationId = 'inv_${_short(_newId())}';

    // 预算扣减必须和快照读取在同一队列名额里完成。原先的 load → save 会让并发
    // 工具调用各自读到同一份旧快照、各自写回，把彼此的 spend 整份覆盖（预算就
    // 形同不设限）。updateTask 内部已经处理「任务不存在」的 null。
    final task = await store.updateTask(
      taskId,
      (current) => current.copyWith(
        budget: current.budget.spend(calls: 1, cost: cost),
        updatedAt: _now(),
      ),
    );
    if (task == null) throw StateError('任务不存在: $taskId');
    await store.appendEvent(TaskEvent(
      id: 'evt_$invocationId',
      taskId: taskId,
      type: ok ? TaskEventType.toolCalled : TaskEventType.toolFailed,
      phase: task.phase.id,
      payload: {
        'invocationId': invocationId,
        'tool': tool,
        'cost': cost,
        if (arguments.isNotEmpty) 'args': arguments,
        if (errorCode != null) 'errorCode': errorCode,
        ...extra,
      },
      createdAt: _now(),
    ));
    return invocationId;
  }

  /// 当前阶段允许的工具名（§6.4 阶段化 Capability Manifest）。
  Future<Set<String>> allowedTools(String taskId) async {
    final task = await store.load(taskId);
    if (task == null) return const {};
    return CapabilityManifest.forPhase(task.phase);
  }

  /// 高风险工具的授权检查（§18.3）。返回 null 表示放行。
  ///
  /// [args] 用于参数级门控：装机授权不在工具名上，而在
  /// run_task_command(install=true) / apk_sign(install=true) 的参数上。
  Future<String?> checkPermission(
    String taskId,
    String tool, {
    Map<String, dynamic> args = const {},
  }) async {
    final task = await store.load(taskId);
    if (task == null) return '任务不存在';
    return CapabilityManifest.denialReason(
      tool,
      task.contract.constraints,
      args: args,
    );
  }

  /// 当前任务相关的失败经验（注入上下文用，§17.4）。
  Future<List<FailureRecord>> relevantFailures(String taskId) async {
    return failures.lookup(taskId: taskId, now: _now());
  }

  // ------------------------------------------------------------ DEX 范围

  /// APK 里一共有几个 DEX（§7.7）。
  ///
  /// 来自历次工具调用报告的扫描数取最大值——工具遍历全部 DEX 时会把
  /// 数量带回来，这就是「总共有几个」的可靠下界。
  Future<int?> knownDexCount(String taskId) async {
    final events = await store.loadEvents(taskId);
    int? best;
    for (final e in events) {
      final v = e.payload['dexCount'];
      if (v is num) {
        final n = v.toInt();
        if (n > 0 && (best == null || n > best)) best = n;
      }
    }
    return best;
  }

  /// 记下某次工具看到的 DEX 数量（供后续查询判断「搜完没有」）。
  Future<void> noteDexCount(String taskId, int count) async {
    if (count <= 0) return;
    final known = await knownDexCount(taskId);
    if (known != null && known >= count) return; // 没有新信息就不写事件
    await store.appendEvent(TaskEvent(
      id: 'evt_${_newId()}',
      taskId: taskId,
      type: 'dex.scope',
      payload: {'dexCount': count},
      createdAt: _now(),
    ));
  }

  /// 一次查询实际扫了几个 DEX（工具返回里带的话）。
  static int? searchedDexOf(Map<String, Object?> data) =>
      MultiDexGuard.searchedOf(data);

  static String _titleFromGoal(String goal) {
    final t = goal.trim().replaceAll('\n', ' ');
    if (t.isEmpty) return '未命名任务';
    return t.length > 24 ? '${t.substring(0, 24)}…' : t;
  }

  /// 把 id 裁到 12 位（去掉 uuid 的连字符）。id 源可能返回短串，这里不假定长度。
  static String _short(String raw) {
    final s = raw.replaceAll('-', '');
    if (s.isEmpty) return 'x';
    return s.length > 12 ? s.substring(0, 12) : s;
  }
}
