/// 指标自动采集（§25）。
///
/// §25.3 的硬要求：**所有指标必须从 TaskEvent、ToolCall、Evidence、Patch 和
/// Delivery 中自动采集，不允许手工估算**。所以这里不引入任何新埋点，
/// 只把已有的事件流、证据库、用量账本换算成指标。
///
/// 算不出来的指标一律返回 null，并说明原因——绝不用占位数字充数。
library;

import 'models/task.dart';
import 'task_runtime.dart';

/// 一个任务的指标快照。
class TaskMetrics {
  final String taskId;

  /// 拿到第一条有效证据（Observed 及以上）耗时。
  final int? timeToFirstUsefulEvidenceMs;

  /// 进入 Located 的耗时。
  final int? timeToLocateMs;

  /// 工具调用总次数（成功 + 失败）。
  final int toolCalls;

  /// 无效调用率：失败调用 / 总调用。参数错、权限拒、预算拒都算。
  final double invalidCallRate;

  /// 失败后恢复率：失败的下一次同名工具调用成功的比例。
  final double? recoveryRate;

  /// 上下文成本：本任务累计 Token。
  final int promptTokens;
  final int completionTokens;

  /// 截断处理率：截断结果里用了续读的比例。
  final double? truncationHandlingRate;

  /// 多 DEX 覆盖完整率：查询时确定搜完全部 DEX 的比例。
  final double? multiDexCoverage;

  /// Dry Run 通过率。
  final double? dryRunPassRate;

  /// 行为验证完成率。
  final double? behaviorVerificationRate;

  /// 工程验证是否通过（null 表示没验证过）。
  final bool? engineeringVerified;

  /// 虚报完成风险：走到 Delivered 但行为没验证 → 1，否则 0。
  final double falseCompletionRisk;

  /// 证据充分性：达到 Located 时是否至少有 Observed 级证据。
  final bool evidenceBacked;

  /// 清理是否执行过。
  final bool cleanupPerformed;

  /// 最慢的一次工具调用（性能定位：哪个工具值得优化）。
  /// null = 事件流里没有耗时数据（老任务，或调用没走 ToolBridge）。
  final String? slowestTool;
  final int? slowestToolMs;

  /// 慢调用次数（单次 ≥ [MetricsCollector.slowCallThresholdMs]）。
  final int slowToolCalls;

  /// 工具执行总耗时（所有已记账的 durationMs 之和，串行口径）。
  final int toolTimeMs;

  const TaskMetrics({
    required this.taskId,
    this.timeToFirstUsefulEvidenceMs,
    this.timeToLocateMs,
    this.toolCalls = 0,
    this.invalidCallRate = 0,
    this.recoveryRate,
    this.promptTokens = 0,
    this.completionTokens = 0,
    this.truncationHandlingRate,
    this.multiDexCoverage,
    this.dryRunPassRate,
    this.behaviorVerificationRate,
    this.engineeringVerified,
    this.falseCompletionRisk = 0,
    this.evidenceBacked = false,
    this.cleanupPerformed = false,
    this.slowestTool,
    this.slowestToolMs,
    this.slowToolCalls = 0,
    this.toolTimeMs = 0,
  });

  Map<String, Object?> toJson() => {
        'taskId': taskId,
        if (timeToFirstUsefulEvidenceMs != null)
          'timeToFirstUsefulEvidenceMs': timeToFirstUsefulEvidenceMs,
        if (timeToLocateMs != null) 'timeToLocateMs': timeToLocateMs,
        'toolCalls': toolCalls,
        'invalidCallRate': double.parse(invalidCallRate.toStringAsFixed(3)),
        if (recoveryRate != null)
          'recoveryRate': double.parse(recoveryRate!.toStringAsFixed(3)),
        'promptTokens': promptTokens,
        'completionTokens': completionTokens,
        if (truncationHandlingRate != null)
          'truncationHandlingRate':
              double.parse(truncationHandlingRate!.toStringAsFixed(3)),
        if (multiDexCoverage != null)
          'multiDexCoverage':
              double.parse(multiDexCoverage!.toStringAsFixed(3)),
        if (dryRunPassRate != null)
          'dryRunPassRate': double.parse(dryRunPassRate!.toStringAsFixed(3)),
        if (behaviorVerificationRate != null)
          'behaviorVerificationRate':
              double.parse(behaviorVerificationRate!.toStringAsFixed(3)),
        if (engineeringVerified != null)
          'engineeringVerified': engineeringVerified,
        'falseCompletionRisk': falseCompletionRisk,
        'evidenceBacked': evidenceBacked,
        'cleanupPerformed': cleanupPerformed,
        if (slowestTool != null) 'slowestTool': slowestTool,
        if (slowestToolMs != null) 'slowestToolMs': slowestToolMs,
        if (slowToolCalls > 0) 'slowToolCalls': slowToolCalls,
        if (toolTimeMs > 0) 'toolTimeMs': toolTimeMs,
      };
}

/// 从事件流算指标。
class MetricsCollector {
  MetricsCollector(this.runtime);

  /// 「慢调用」判据：单次工具调用 ≥ 3s。低于这个量级的多是正常 IO，
  /// 值得单独拎出来的通常是引擎分析/重打包一类。
  static const int slowCallThresholdMs = 3000;

  final TaskRuntime runtime;

  Future<TaskMetrics> collect(String taskId) async {
    final task = await runtime.get(taskId);
    if (task == null) return TaskMetrics(taskId: taskId);

    final events = await runtime.store.loadEvents(taskId);
    final evidence = await runtime.evidence.load(taskId);
    final usage = await runtime.usage.summary(taskId);

    final created = task.createdAt;

    // ---- 工具调用 ----
    final called = <Map<String, Object?>>[];
    final failed = <Map<String, Object?>>[];
    var truncatedCount = 0;
    var dexScopes = 0;
    var dexComplete = 0;
    var dryRunTotal = 0;
    var dryRunPassed = 0;
    var verifyTotal = 0;
    var behaviorPassed = 0;
    bool? engineeringOk;
    var cleanup = false;
    int? locatedAt;

    // ---- 耗时账（性能定位）----
    // durationMs 由 ToolBridge 在成功/失败/超时三条路径都写了（2026-09-16），
    // 此前没人读；这里聚合成"哪个工具最慢 / 有多少次慢调用"，让优化有据可依。
    var toolTimeMs = 0;
    var slowToolCalls = 0;
    String? slowestTool;
    int? slowestToolMs;
    void accountDuration(Map<String, Object?> payload) {
      final ms = _int(payload['durationMs']);
      if (ms == null || ms <= 0) return;
      toolTimeMs += ms;
      if (ms >= slowCallThresholdMs) slowToolCalls++;
      final current = slowestToolMs;
      if (current == null || ms > current) {
        slowestToolMs = ms;
        slowestTool = payload['tool']?.toString();
      }
    }

    for (final e in events) {
      switch (e.type) {
        case 'tool.called':
          called.add(e.payload);
          accountDuration(e.payload);
          if (e.payload['truncated'] == true) truncatedCount++;
          final scope = e.payload['queryScope'];
          if (scope is Map) {
            dexScopes++;
            final searched = _int(scope['searchedDexCount']);
            final total = _int(scope['totalDexCount']);
            final failedDex = _int(scope['failedDexCount']) ?? 0;
            final skipped = _int(scope['skippedDexCount']) ?? 0;
            if (searched != null &&
                total != null &&
                searched >= total &&
                failedDex == 0 &&
                skipped == 0) {
              dexComplete++;
            }
          }
          break;
        case 'tool.failed':
          failed.add(e.payload);
          accountDuration(e.payload);
          break;
        case 'task.status_changed':
          if (e.payload['to'] == TaskStatus.located.label && locatedAt == null) {
            locatedAt = e.createdAt;
          }
          break;
        case 'patch.dry_run':
          dryRunTotal++;
          if (e.payload['passed'] == true) dryRunPassed++;
          break;
        case 'verify.completed':
          verifyTotal++;
          if (e.payload['behavior'] == 'pass') behaviorPassed++;
          // 最后一次验证的工程结论说了算
          engineeringOk = e.payload['engineering'] == 'pass';
          break;
        case 'workspace.cleanup':
          cleanup = true;
          break;
      }
    }

    // ---- 第一条有效证据 ----
    int? firstUseful;
    for (final e in events) {
      if (e.type != 'evidence.recorded') continue;
      final level = e.payload['level']?.toString() ?? '';
      if (level == 'Observed' || level == 'Correlated' || level == 'Verified') {
        firstUseful = e.createdAt;
        break;
      }
    }

    // ---- 恢复率：失败之后同名工具是否成功过 ----
    // ---- 截断处理率：截断之后有没有人带着续读令牌接着读 ----
    var continuedCount = 0;
    for (var i = 0; i < events.length; i++) {
      if (events[i].type != 'tool.called') continue;
      if (events[i].payload['truncated'] != true) continue;
      final tool = events[i].payload['tool']?.toString() ?? '';
      for (var j = i + 1; j < events.length; j++) {
        if (events[j].type != 'tool.called') continue;
        if ((events[j].payload['tool']?.toString() ?? '') != tool) continue;
        final a = events[j].payload['args'];
        if (a is Map && (a['continuation'] ?? '').toString().isNotEmpty) {
          continuedCount++;
          break;
        }
      }
    }

    double? recoveryRate;
    if (failed.isNotEmpty) {
      var recovered = 0;
      for (var i = 0; i < events.length; i++) {
        if (events[i].type != 'tool.failed') continue;
        final tool = events[i].payload['tool']?.toString() ?? '';
        for (var j = i + 1; j < events.length; j++) {
          if (events[j].type != 'tool.called') continue;
          if ((events[j].payload['tool']?.toString() ?? '') == tool) {
            recovered++;
            break;
          }
        }
      }
      recoveryRate = recovered / failed.length;
    }

    final totalCalls = called.length + failed.length;
    final behaviorVerified =
        task.status == TaskStatus.verified || behaviorPassed > 0;

    return TaskMetrics(
      taskId: taskId,
      timeToFirstUsefulEvidenceMs:
          firstUseful == null ? null : (firstUseful - created).clamp(0, 1 << 40),
      timeToLocateMs:
          locatedAt == null ? null : (locatedAt - created).clamp(0, 1 << 40),
      toolCalls: totalCalls,
      invalidCallRate: totalCalls == 0 ? 0 : failed.length / totalCalls,
      recoveryRate: recoveryRate,
      promptTokens: usage.promptTokens,
      completionTokens: usage.completionTokens,
      truncationHandlingRate:
          truncatedCount == 0 ? null : (continuedCount / truncatedCount).clamp(0, 1),
      multiDexCoverage: dexScopes == 0 ? null : dexComplete / dexScopes,
      dryRunPassRate: dryRunTotal == 0 ? null : dryRunPassed / dryRunTotal,
      behaviorVerificationRate:
          verifyTotal == 0 ? null : behaviorPassed / verifyTotal,
      engineeringVerified: engineeringOk,
      falseCompletionRisk:
          (task.status == TaskStatus.delivered && !behaviorVerified) ? 1 : 0,
      evidenceBacked: evidence.any((e) => e.level.rank >= 1),
      cleanupPerformed: cleanup,
      slowestTool: slowestTool,
      slowestToolMs: slowestToolMs,
      slowToolCalls: slowToolCalls,
      toolTimeMs: toolTimeMs,
    );
  }

  static int? _int(Object? v) {
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v);
    return null;
  }
}
