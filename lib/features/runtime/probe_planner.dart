/// 探针规划器（§12）。
///
/// 每次选择探针都要回答一个问题：
/// **当前最缺哪一条证据？哪个探针能以最低成本补上它？**
/// 而不是「还有什么工具可以调用」。
///
/// 这个类只产出**建议**，不执行工具：模型可以采纳也可以不采纳（§8.4
/// 「工具可建议下一步，但不能强迫模型照做」）。
library;

import '../../core/services/local_tools/local_tool_names.dart';
import 'capability_manifest.dart';
import 'failure_memory.dart';
import 'models/evidence.dart';
import 'models/task.dart';

/// 一条探针建议（§12.2 探针定义）。
class ProbeSuggestion {
  /// 建议调用的工具名。
  final String probe;

  /// 这次探针要回答的问题。
  final String purpose;

  /// 成本（§12.3），用于比较相对代价而非绝对耗时。
  final int cost;

  /// high / medium / low —— 补上当前缺口的能力。
  final String expectedValue;

  /// 前置条件。
  final List<String> requires;

  /// 预期返回什么。
  final List<String> returns;

  /// 为什么现在选它。
  final String rationale;

  const ProbeSuggestion({
    required this.probe,
    required this.purpose,
    required this.cost,
    this.expectedValue = 'medium',
    this.requires = const [],
    this.returns = const [],
    this.rationale = '',
  });

  Map<String, Object?> toJson() => {
        'probe': probe,
        'purpose': purpose,
        'cost': cost,
        'expectedValue': expectedValue,
        if (requires.isNotEmpty) 'requires': requires,
        if (returns.isNotEmpty) 'returns': returns,
        if (rationale.isNotEmpty) 'rationale': rationale,
      };
}

/// 证据族：用于「冲突时必须换一个独立来源」（§12.5 第 3 步）。
class EvidenceFamily {
  EvidenceFamily._();

  static const search = 'search';
  static const field = 'field';
  static const xref = 'xref';
  static const body = 'body';
  static const native = 'native';
  static const runtime = 'runtime';

  /// 证据类型 → 族。
  static String ofType(String type) {
    switch (type.toUpperCase()) {
      case 'STRING':
      case 'STRUCTURE':
        return search;
      case 'FIELD_USAGE':
        return field;
      case 'XREF':
        return xref;
      case 'METHOD_BODY':
        return body;
      case 'OBSERVED':
        return native;
      default:
        return search;
    }
  }

  /// 族 → 候选工具（按成本升序）。
  static const Map<String, List<String>> tools = {
    search: ['dex_search', 'string_scan', 'class_outline'],
    field: ['field_xref'],
    xref: ['dex_xref'],
    body: ['smali_read', 'jadx_decompile'],
    native: ['so_analyze'],
    // 装机验证链是 run_task_command(command=VERIFY_ARTIFACT, install=true)：
    // 没有 install_apk 这个工具，旧名会让候选被阶段白名单过滤掉。
    runtime: [LocalToolNames.runTaskCommand, 'verify_apk'],
  };

  /// 族 → 这一族解决的问题。
  static const Map<String, String> purpose = {
    search: '缩小范围：目标大概在哪些类/方法/字符串附近',
    field: '确认字段的读写点与所在方法',
    xref: '确认调用关系与调用位置',
    body: '看清方法体逻辑与实际分支',
    native: '确认原生层引用与实现',
    runtime: '确认目标行为是否真的改变',
  };

  static const Map<String, List<String>> returns = {
    search: ['class_hits', 'string_hits'],
    field: ['read_sites', 'write_sites', 'method_refs'],
    xref: ['callers', 'call_sites'],
    body: ['instructions', 'branches'],
    native: ['symbols', 'xrefs'],
    runtime: ['behavior_result'],
  };

  /// 能产出 Observed 级证据的工具（§11.3：真实读写点 / 调用关系 / 方法体）。
  ///
  /// 用途：当理想升级探针不在当前阶段时，退而求其次也要挑一个**真能提升
  /// 证据等级**的工具，而不是随便挑个便宜的查询。
  static const levelUpTools = <String>{
    'jadx_decompile',
    'smali_read',
    'dex_xref',
    'field_xref',
    'so_analyze',
  };
}

class ProbePlanner {
  ProbePlanner({this._costs});

  /// 测试可覆盖成本；默认用 [CapabilityManifest.costOf]。
  final Map<String, int>? _costs;

  int _costOf(String tool) => _costs?[tool] ?? CapabilityManifest.costOf(tool);

  /// 给出最多 [limit] 条建议，按「先解决问题、再比成本」排序。
  ///
  /// [allowedTools] 为当前阶段实际可调用的工具——建议了调不了的工具等于没建议。
  List<ProbeSuggestion> suggest({
    required Task task,
    required List<Evidence> evidence,
    required List<EvidenceConflict> conflicts,
    List<FailureRecord> failures = const [],
    Set<String>? allowedTools,
    int limit = 3,
  }) {
    final allowed = allowedTools ?? CapabilityManifest.forPhase(task.phase);
    final out = <ProbeSuggestion>[];

    // 1) 有未决冲突：最高优先级是换一个**独立来源**（§12.5）
    final open = conflicts.where((c) => c.resolvedBy.isEmpty).toList();
    if (open.isNotEmpty) {
      final used = <String>{};
      for (final c in open) {
        for (final id in c.evidenceIds) {
          for (final e in evidence) {
            if (e.id == id) used.add(EvidenceFamily.ofType(e.type));
          }
        }
      }
      for (final entry in EvidenceFamily.tools.entries) {
        if (used.contains(entry.key)) continue; // 要的是独立来源
        for (final tool in entry.value) {
          if (!allowed.contains(tool)) continue;
          out.add(_make(
            tool: tool,
            purpose: '解决未决冲突：${_conflictPurpose(open.first.claim)}',
            expectedValue: 'high',
            rationale: '两侧证据来自 ${used.join('/')}，需要第三个独立来源裁决',
          ));
        }
        if (out.isNotEmpty) break;
      }
      if (out.isNotEmpty) return _rank(out, failures, task, limit);
    }

    // 2) 没有证据：先把范围缩下来（STRING / CLASS，成本最低）
    if (evidence.isEmpty) {
      for (final tool in EvidenceFamily.tools[EvidenceFamily.search]!) {
        if (!allowed.contains(tool)) continue;
        out.add(_make(
          tool: tool,
          purpose: EvidenceFamily.purpose[EvidenceFamily.search]!,
          expectedValue: 'high',
          rationale: '当前没有任何证据，先定位候选范围',
        ));
      }
      if (out.isEmpty) return const [];
      return _rank(out, failures, task, limit);
    }

    // 3) 按当前最高等级决定「下一级证据」（§11.4 升级链）
    final level = _highest(evidence);
    final nextFamilies = _nextFamilies(level);
    for (final family in nextFamilies) {
      for (final tool in EvidenceFamily.tools[family]!) {
        if (!allowed.contains(tool)) continue;
        out.add(_make(
          tool: tool,
          purpose: EvidenceFamily.purpose[family]!,
          expectedValue: level == EvidenceLevel.candidate ? 'high' : 'medium',
          rationale: '当前最高证据等级是 ${level.label}，'
              '需要升到下一级才有资格下结论',
        ));
      }
    }

    // 4) 理想探针不在本阶段：先挑「能提升证据等级」的工具
    if (out.isEmpty) {
      for (final tool in allowed) {
        if (!EvidenceFamily.levelUpTools.contains(tool)) continue;
        out.add(_make(
          tool: tool,
          purpose: '把证据从 ${level.label} 提到 Observed 以上',
          expectedValue: 'medium',
          rationale: '本阶段的理想升级探针不可用，'
              '先用能产生真实关系的工具推进',
        ));
      }
    }

    // 5) 还是没有：退回该阶段能用的最便宜查询
    if (out.isEmpty) {
      for (final tool in allowed) {
        final c = _costOf(tool);
        if (c > 3) continue;
        out.add(_make(
          tool: tool,
          purpose: '在当前阶段继续收集相关事实',
          expectedValue: 'low',
          rationale: '本阶段没有更贴合的升级探针',
        ));
        if (out.length >= 2) break;
      }
    }
    return _rank(out, failures, task, limit);
  }

  /// 沿用失败记忆里的教训：同族工具刚失败过就降权（§17.4）。
  List<ProbeSuggestion> _rank(
    List<ProbeSuggestion> items,
    List<FailureRecord> failures,
    Task task,
    int limit,
  ) {
    final penalized = <String>{
      for (final f in failures)
        if (f.operation.isNotEmpty) f.operation,
    };
    final valueScore = {'high': 0, 'medium': 1, 'low': 2};

    final sorted = [...items]..sort((a, b) {
        final pa = penalized.contains(a.probe) ? 1 : 0;
        final pb = penalized.contains(b.probe) ? 1 : 0;
        if (pa != pb) return pa - pb;
        final va = valueScore[a.expectedValue] ?? 1;
        final vb = valueScore[b.expectedValue] ?? 1;
        if (va != vb) return va - vb;
        return a.cost.compareTo(b.cost);
      });

    // 预算不够就别建议做不起的探针（§12.6）
    final affordable =
        sorted.where((s) => s.cost <= task.budget.remainingCost).toList();
    // 一条都做不起时返回空：宁可明说「预算不够」，也不诱导模型去跑
    // 一个会被 Runtime 拦下的高成本探针。
    if (affordable.isEmpty) return const [];
    return affordable.take(limit).toList();
  }

  ProbeSuggestion _make({
    required String tool,
    required String purpose,
    required String expectedValue,
    required String rationale,
  }) =>
      ProbeSuggestion(
        probe: tool,
        purpose: purpose,
        cost: _costOf(tool),
        expectedValue: expectedValue,
        requires: const ['artifact_available'],
        returns: EvidenceFamily.returns[
                _familyOfTool(tool)] ??
            const ['facts'],
        rationale: rationale,
      );

  static String _familyOfTool(String tool) {
    for (final e in EvidenceFamily.tools.entries) {
      if (e.value.contains(tool)) return e.key;
    }
    return EvidenceFamily.search;
  }

  static EvidenceLevel _highest(List<Evidence> list) {
    var best = EvidenceLevel.candidate;
    for (final e in list) {
      if (e.level.rank > best.rank) best = e.level;
    }
    return best;
  }

  /// 当前等级 → 应该补哪一族证据。
  static List<String> _nextFamilies(EvidenceLevel level) {
    switch (level) {
      case EvidenceLevel.candidate:
        // 候选 → 需要真实关系：字段读写点 / 调用关系
        return [EvidenceFamily.field, EvidenceFamily.xref];
      case EvidenceLevel.observed:
        // 已观察 → 需要方法体，看实际分支
        return [EvidenceFamily.body, EvidenceFamily.native];
      case EvidenceLevel.correlated:
        // 已关联 → 只剩行为验证
        return [EvidenceFamily.runtime];
      case EvidenceLevel.verified:
        return const [];
    }
  }

  static String _conflictPurpose(String claim) =>
      claim.isEmpty ? '证据互相矛盾' : claim;
}
