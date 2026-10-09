/// 模型接入层（§21）。
///
/// 要解决的问题：SoLab 不该是「某个模型 + 一份 Prompt」（§21.1），
/// 而应该是可替换模型的外壳。这里收拢三件事：
/// - **分层选型**：确定性/简单工作不用最强模型，复杂证据综合才用（§21.3/§21.4）；
/// - **用量记账**：每次调用记 Token 与估算成本，落到任务上（§21.2）；
/// - **失败重试策略**：哪些失败值得重试、退避多久（§21.2 重试策略）。
///
/// 实际的 HTTP 与流式解析仍在 ChatEngine；本模块不碰网络。
library;

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../chat/chat_models.dart';
import 'models/task.dart';
import 'task_store.dart';

/// 模型分层（§21.3）。
enum ModelTier {
  /// 强推理：复杂路线判断、证据综合、修改方案。
  strong('strong', '强推理'),

  /// 快速：分类、摘要、候选排序。
  fast('fast', '快速'),

  /// 专项：结构化提取、轻量判断。
  specialized('specialized', '专项'),

  /// 本地：离线任务、脱敏摘要。
  local('local', '本地');

  const ModelTier(this.id, this.label);
  final String id;
  final String label;
}

/// 阶段 → 推荐档位（§21.4）。
///
/// 分析阶段大量是「看事实」，快模型就够；定位与修改要综合证据、权衡风险，
/// 用强推理模型。准备与交付偏流程，交给快模型。
class ModelRouting {
  ModelRouting._();

  static ModelTier tierForPhase(TaskPhase phase) {
    switch (phase) {
      case TaskPhase.prepare:
      case TaskPhase.analyze:
        return ModelTier.fast;
      case TaskPhase.locate:
      case TaskPhase.modify:
        return ModelTier.strong;
      case TaskPhase.deliver:
        return ModelTier.fast;
    }
  }

  /// 当前该用哪个模型：配了对应档位就用它，否则回退到当前激活模型。
  static String resolve({
    required TaskPhase phase,
    required String activeModel,
    Map<ModelTier, String> overrides = const {},
  }) {
    final want = tierForPhase(phase);
    final mapped = overrides[want];
    if (mapped != null && mapped.trim().isNotEmpty) return mapped.trim();
    return activeModel;
  }
}

/// 单价（每百万 Token）。没配就是 0 = 不估算成本。
class TokenPricing {
  final int inputPerMillion;
  final int outputPerMillion;
  final int cachedPerMillion;

  const TokenPricing({
    this.inputPerMillion = 0,
    this.outputPerMillion = 0,
    this.cachedPerMillion = 0,
  });

  bool get configured => inputPerMillion > 0 || outputPerMillion > 0;

  /// 估算成本（同单位，取整）。
  int estimate({
    required int promptTokens,
    required int completionTokens,
    required int cachedTokens,
  }) {
    if (!configured) return 0;
    final fresh = (promptTokens - cachedTokens).clamp(0, promptTokens);
    var micros = fresh * inputPerMillion;
    micros += cachedTokens * cachedPerMillion;
    micros += completionTokens * outputPerMillion;
    return micros ~/ 1000000;
  }
}

/// 一次模型调用的用量记录。
class UsageRecord {
  final String taskId;
  final String model;
  final ModelTier tier;
  final int promptTokens;
  final int completionTokens;
  final int cachedTokens;
  final int estimatedCost;
  final int createdAt;

  const UsageRecord({
    required this.taskId,
    required this.model,
    this.tier = ModelTier.strong,
    this.promptTokens = 0,
    this.completionTokens = 0,
    this.cachedTokens = 0,
    this.estimatedCost = 0,
    this.createdAt = 0,
  });

  Map<String, Object?> toJson() => {
        'taskId': taskId,
        'model': model,
        'tier': tier.id,
        'promptTokens': promptTokens,
        'completionTokens': completionTokens,
        'cachedTokens': cachedTokens,
        'estimatedCost': estimatedCost,
        'createdAt': createdAt,
      };

  static UsageRecord fromJson(Object? raw) {
    if (raw is! Map) throw const FormatException('usage 不是对象');
    return UsageRecord(
      taskId: raw['taskId']?.toString() ?? '',
      model: raw['model']?.toString() ?? '',
      tier: ModelTier.values.firstWhere(
        (t) => t.id == raw['tier']?.toString(),
        orElse: () => ModelTier.strong,
      ),
      promptTokens: (raw['promptTokens'] as num?)?.toInt() ?? 0,
      completionTokens: (raw['completionTokens'] as num?)?.toInt() ?? 0,
      cachedTokens: (raw['cachedTokens'] as num?)?.toInt() ?? 0,
      estimatedCost: (raw['estimatedCost'] as num?)?.toInt() ?? 0,
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
    );
  }
}

/// 一个任务的用量汇总。
class UsageSummary {
  final int calls;
  final int promptTokens;
  final int completionTokens;
  final int cachedTokens;
  final int estimatedCost;

  const UsageSummary({
    this.calls = 0,
    this.promptTokens = 0,
    this.completionTokens = 0,
    this.cachedTokens = 0,
    this.estimatedCost = 0,
  });

  double get cacheHitRate =>
      promptTokens == 0 ? 0 : cachedTokens / promptTokens;

  Map<String, Object?> toJson() => {
        'calls': calls,
        'promptTokens': promptTokens,
        'completionTokens': completionTokens,
        'cachedTokens': cachedTokens,
        'estimatedCost': estimatedCost,
      };
}

/// 用量账本：按任务落盘，JSONL 追加。
class UsageLedger {
  UsageLedger(this._tasks, {Map<String, TokenPricing>? pricing})
      : _pricing = pricing ?? const {};

  final TaskStore _tasks;

  /// 按模型名前缀匹配单价；没配就记 0（不编造价钱）。
  final Map<String, TokenPricing> _pricing;

  Future<File> _file(String taskId) async =>
      File(p.join((await _tasks.taskDir(taskId)).path, 'usage.jsonl'));

  TokenPricing pricingFor(String model) {
    final m = model.toLowerCase();
    for (final e in _pricing.entries) {
      if (m.startsWith(e.key.toLowerCase())) return e.value;
    }
    return const TokenPricing();
  }

  Future<UsageRecord> record({
    required String taskId,
    required String model,
    required int promptTokens,
    required int completionTokens,
    int cachedTokens = 0,
    ModelTier tier = ModelTier.strong,
    int now = 0,
  }) async {
    final cost = pricingFor(model).estimate(
      promptTokens: promptTokens,
      completionTokens: completionTokens,
      cachedTokens: cachedTokens,
    );
    final r = UsageRecord(
      taskId: taskId,
      model: model,
      tier: tier,
      promptTokens: promptTokens,
      completionTokens: completionTokens,
      cachedTokens: cachedTokens,
      estimatedCost: cost,
      createdAt: now == 0 ? DateTime.now().millisecondsSinceEpoch : now,
    );
    final f = await _file(taskId);
    await f.parent.create(recursive: true);
    await f.writeAsString(
      '${jsonEncode(r.toJson())}\n',
      mode: FileMode.append,
      flush: true,
    );
    return r;
  }

  Future<List<UsageRecord>> load(String taskId) async {
    final f = await _file(taskId);
    if (!await f.exists()) return const [];
    final out = <UsageRecord>[];
    for (final line in await f.readAsLines()) {
      final t = line.trim();
      if (t.isEmpty) continue;
      try {
        out.add(UsageRecord.fromJson(jsonDecode(t)));
      } catch (_) {
        // 跳过坏行
      }
    }
    return out;
  }

  Future<UsageSummary> summary(String taskId) async {
    final all = await load(taskId);
    var prompt = 0, completion = 0, cached = 0, cost = 0;
    for (final r in all) {
      prompt += r.promptTokens;
      completion += r.completionTokens;
      cached += r.cachedTokens;
      cost += r.estimatedCost;
    }
    return UsageSummary(
      calls: all.length,
      promptTokens: prompt,
      completionTokens: completion,
      cachedTokens: cached,
      estimatedCost: cost,
    );
  }
}

/// 重试策略（§21.2）。
///
/// 只有「换个时间就会好」的失败才重试：网络、超时、服务端 5xx。
/// 参数错、鉴权错、额度耗尽，重试多少次都是浪费。
class RetryPolicy {
  RetryPolicy._();

  /// 该失败最多重试几次（不含首次）。
  static int attemptsFor(ChatFailureKind kind) {
    switch (kind) {
      case ChatFailureKind.network:
      case ChatFailureKind.timeout:
      case ChatFailureKind.server:
        return 2;
      default:
        return 0;
    }
  }

  static bool shouldRetry(ChatFailureKind kind, int attempt) =>
      attempt < attemptsFor(kind);

  /// 指数退避：1s、2s、4s…
  static Duration backoffFor(int attempt) =>
      Duration(seconds: 1 << attempt.clamp(0, 5));
}
