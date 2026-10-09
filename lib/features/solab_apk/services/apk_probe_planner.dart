import 'dart:convert';

/// 薄版 Probe Planner（蓝图 v2.1 §5.3，Week 4~5）。
///
/// 把「字符串 → 字段 → Xref → 方法体」从 Prompt 经验建议变成**程序可执行
/// 规则**：固定 cost 表 + 蓝图五条基本规则，纯函数、零 IO、可单测。
///
/// 第一版只做规则。明确不做：在线 RL、信息论优化、Bayesian search、
/// 大型图搜索、自动学习型调度器。
///
/// 重要约束（蓝图原文）：**减少探针数量不是目标，减少无意义探针才是目标。**
/// Calls ↓ 不得导致 Evidence Quality ↓ —— 由 R2（patch 门禁）与
/// R4（有直接证据才停）共同保证下限；decisions[] 全量落日志，可观察。
abstract final class ApkProbePlanner {
  /// 每链默认探针预算（cost 单位 = 蓝图 §5.3 示意代价）。
  static const int defaultBudget = 15;

  /// 决策入口：给定当前证据状态，返回下一个动作。纯函数。
  ///
  /// 规则优先级（先命中先生效）：
  ///   R4 停止条件（直接证据即停，caller 摘要作为最后补全）
  ///   R5 预算耗尽 → 收束报缺口
  ///   R1 缺 writer → FIELD_USAGE
  ///   R2 只读无写入方 → 收束 + patch 禁止
  ///   R3 多写入方 → METHOD_BODY 判别性第三探针
  ///   R6 唯一写入方 → METHOD_BODY 升级直接证据
  static PlannerDecision decide(ProbeEvidenceState s, {int seq = 1}) {
    final remaining = s.costRemaining;

    // R4：精确 locator + 方法体直接证据 → 停止继续探索（蓝图规则 4）。
    // caller 摘要属于链序「caller/数据流」补全，预算够则先取再停。
    if (s.hasMethodBody) {
      if (!s.hasCallers && remaining >= ApkProbeCost.xref) {
        return _probe(s, seq, ApkProbeKind.xref, Rules.r4bCallersContext,
            '已有方法体直接证据；补 caller/数据流上下文后收束（预算内 R4B）');
      }
      return _stop(s, seq, Rules.r4StopOnDirectEvidence,
          '已有精确 locator + 方法体直接证据 → 停止继续探索（蓝图规则 4）');
    }

    // R5：预算不足且没有信息增益 → 收束并报告缺口（蓝图规则 5）。
    // 剩余预算付不起最便宜的后续探针（FIELD_USAGE=2 / METHOD_BODY=5）。
    final cheapestNext = s.hasFieldUsage
        ? ApkProbeCost.methodBody
        : ApkProbeCost.fieldUsage;
    if (remaining < cheapestNext) {
      return _stop(
        s,
        seq,
        Rules.r5BudgetExhausted,
        '预算不足（剩余 $remaining < $cheapestNext）且无信息增益 → 收束并报告缺口（蓝图规则 5）',
        gap: 'BUDGET_EXHAUSTED',
      );
    }

    // R1：缺 writer 证据 → 优先 FIELD_USAGE（蓝图规则 1）。
    if (!s.hasFieldUsage) {
      return _probe(s, seq, ApkProbeKind.fieldUsage, Rules.r1NoWriterEvidence,
          '缺 writer → 优先 FIELD_USAGE（蓝图规则 1）');
    }

    // R2：FIELD_USAGE 已跑但只有读取（无写入方）→ 收束 + patch 禁止。
    // （蓝图规则 2 的字段域映射：无写入点 = 无可定位的状态来源。）
    if (s.writes == 0) {
      return _stop(
        s,
        seq,
        Rules.r2NoPatchWithoutDirectEvidence,
        '字段只有读取证据、无写入方（NO_WRITER）：不允许进入 patch，收束并报告缺口',
        gap: 'NO_WRITER',
      );
    }

    // R3 / R6：有写入方且未读方法体 → METHOD_BODY（写入方优先）。
    // 多个写入方时即蓝图规则 3 的「独立第三探针」（判别性）。
    return _probe(
      s,
      seq,
      ApkProbeKind.methodBody,
      s.writes > 1
          ? Rules.r3CompetingTargets
          : Rules.r6WriterBody,
      s.writes > 1
          ? '存在 ${s.writes} 个竞争写入方 → 增加独立第三探针（蓝图规则 3，读权威写入方方法体判别）'
          : '唯一写入方：读方法体把间接证据升级为直接证据',
    );
  }

  static PlannerDecision _probe(
    ProbeEvidenceState s,
    int seq,
    String kind,
    String rule,
    String reason,
  ) {
    return PlannerDecision(
      seq: seq,
      action: 'probe',
      nextProbe: kind,
      rule: rule,
      reason: reason,
      costSpent: s.costSpent,
      costRemaining: s.costRemaining,
      patchAllowed: false, // 探针阶段一律不允许 patch（证据未收束）
    );
  }

  static PlannerDecision _stop(
    ProbeEvidenceState s,
    int seq,
    String rule,
    String reason, {
    String? gap,
  }) {
    return PlannerDecision(
      seq: seq,
      action: 'stop',
      rule: rule,
      reason: reason,
      costSpent: s.costSpent,
      costRemaining: s.costRemaining,
      // R2 门禁：patch 需要方法体直接证据 + 至少一个写入方。
      // 只有字符串证据（hasStringEvidence 且无方法体/写入方）恒为禁止。
      patchAllowed: s.hasMethodBody && s.writes > 0,
      gap: gap,
    );
  }
}

/// 探针固定 cost 表（蓝图 §5.3 示意代价，禁止运行时改写）。
abstract final class ApkProbeCost {
  static const int stringRule = 1;
  static const int fieldUsage = 2;
  static const int xref = 3;
  static const int methodBody = 5;
}

/// 探针种类（与 cost 表一一对应）。
abstract final class ApkProbeKind {
  static const stringRule = 'STRING_RULE';
  static const fieldUsage = 'FIELD_USAGE';
  static const xref = 'XREF_CALLERS';
  static const methodBody = 'METHOD_BODY';

  static int costOf(String kind) => switch (kind) {
    fieldUsage => ApkProbeCost.fieldUsage,
    xref => ApkProbeCost.xref,
    methodBody => ApkProbeCost.methodBody,
    _ => ApkProbeCost.stringRule,
  };
}

/// 规则标签（决策日志可观察性：每条决策必带 rule + reason）。
abstract final class Rules {
  /// R1：缺 writer 证据 → 优先 FIELD_USAGE（蓝图规则 1）。
  static const r1NoWriterEvidence = 'R1_NO_WRITER_EVIDENCE';

  /// R2：只有字符串证据 / 无写入方 → 不允许进入 patch（蓝图规则 2）。
  static const r2NoPatchWithoutDirectEvidence = 'R2_NO_PATCH_WITHOUT_DIRECT_EVIDENCE';

  /// R3：存在多个竞争写入方 → 独立第三探针（METHOD_BODY 判别；蓝图规则 3）。
  static const r3CompetingTargets = 'R3_COMPETING_TARGETS';

  /// R4：已有精确 locator + 方法体直接证据 → 停止继续探索（蓝图规则 4）。
  static const r4StopOnDirectEvidence = 'R4_STOP_ON_DIRECT_EVIDENCE';

  /// R4 补全：caller/数据流上下文摘要（蓝图链序的一环，取完即停）。
  static const r4bCallersContext = 'R4B_CALLERS_CONTEXT';

  /// R5：预算不足且没有信息增益 → 收束并报告缺口（蓝图规则 5）。
  static const r5BudgetExhausted = 'R5_BUDGET_EXHAUSTED';

  /// 唯一写入方：读方法体升级为直接证据（R1/R4 之间的推进步）。
  static const r6WriterBody = 'R6_WRITER_BODY';
}

/// 当前证据状态（planner 的唯一输入；不可变，copyWith 推进）。
class ProbeEvidenceState {
  const ProbeEvidenceState({
    this.hasFieldUsage = false,
    this.writes = 0,
    this.reads = 0,
    this.hasMethodBody = false,
    this.hasCallers = false,
    this.hasStringEvidence = false,
    this.costSpent = 0,
    this.costBudget = ApkProbePlanner.defaultBudget,
  });

  /// FIELD_USAGE 是否已跑。
  final bool hasFieldUsage;

  /// WRITE_FIELD 命中数（竞争写入方数量）。
  final int writes;

  /// 只读命中数。
  final int reads;

  /// 已取得精确 locator + 方法体直接证据（蓝图规则 4 的停止条件）。
  final bool hasMethodBody;

  /// caller/数据流摘要是否已取。
  final bool hasCallers;

  /// 是否只有字符串级命中（R2 patch 门禁输入）。
  final bool hasStringEvidence;

  final int costSpent;
  final int costBudget;

  int get costRemaining => costBudget - costSpent;

  ProbeEvidenceState copyWith({
    bool? hasFieldUsage,
    int? writes,
    int? reads,
    bool? hasMethodBody,
    bool? hasCallers,
    bool? hasStringEvidence,
    int? costSpent,
  }) {
    return ProbeEvidenceState(
      hasFieldUsage: hasFieldUsage ?? this.hasFieldUsage,
      writes: writes ?? this.writes,
      reads: reads ?? this.reads,
      hasMethodBody: hasMethodBody ?? this.hasMethodBody,
      hasCallers: hasCallers ?? this.hasCallers,
      hasStringEvidence: hasStringEvidence ?? this.hasStringEvidence,
      costSpent: costSpent ?? this.costSpent,
      costBudget: costBudget,
    );
  }

  Map<String, dynamic> toLog() => <String, dynamic>{
    'hasFieldUsage': hasFieldUsage,
    'writes': writes,
    'reads': reads,
    'hasMethodBody': hasMethodBody,
    'hasCallers': hasCallers,
    'costSpent': costSpent,
    'costRemaining': costRemaining,
  };
}

/// planner 的一个决策：继续探针（action=probe，给出 nextProbe + cost）
/// 或收束（action=stop，给出缺口）。rule/reason 全量入日志（蓝图验收：
/// 「日志可观察 Planner 的决策」）。
class PlannerDecision {
  const PlannerDecision({
    required this.seq,
    required this.action,
    this.nextProbe,
    this.rule,
    this.reason,
    required this.costSpent,
    required this.costRemaining,
    required this.patchAllowed,
    this.gap,
  });

  final int seq;

  /// 'probe' | 'stop'
  final String action;

  /// action=probe 时的探针种类（ApkProbeKind 常量）。
  final String? nextProbe;

  /// 触发的规则标签（R1/R2/R3/R4/R5 体系）。
  final String? rule;
  final String? reason;
  final int costSpent;
  final int costRemaining;

  /// R2 门禁：当前证据是否允许进入 patch。只有字符串证据或无写入方时
  /// 恒为 false——「只有字符串证据不允许直接进入 patch」（蓝图规则 2）。
  final bool patchAllowed;

  /// action=stop 时的缺口标记（NO_WRITER / BUDGET_EXHAUSTED / null）。
  final String? gap;

  int get nextProbeCost =>
      action == 'probe' ? ApkProbeKind.costOf(nextProbe ?? '') : 0;

  Map<String, dynamic> toLog() => <String, dynamic>{
    'seq': seq,
    'action': action,
    if (nextProbe != null) 'nextProbe': nextProbe,
    if (nextProbe != null) 'cost': nextProbeCost,
    if (rule != null) 'rule': rule,
    if (reason != null) 'reason': reason,
    'costSpent': costSpent,
    'costRemaining': costRemaining,
    'patchAllowed': patchAllowed,
    if (gap != null) 'gap': gap,
  };

  String encode() => jsonEncode(toLog());
}
