/// 统一工具返回协议（§8）。
///
/// 目标：Agent 不需要为每个工具学一套返回格式（§8.4）。
/// 所有工具——无论 Dart 侧还是 Kotlin 通道——都收敛到 [ToolEnvelope]。
library;

import 'dart:convert';

import '../../../../core/services/local_tools/tool_error_policy.dart';

/// 工具调用的整体状态。
enum ToolStatus {
  success('success'),
  partial('partial'),
  error('error');

  const ToolStatus(this.id);
  final String id;

  static ToolStatus fromId(String id) => ToolStatus.values.firstWhere(
        (s) => s.id == id,
        orElse: () => ToolStatus.error,
      );
}

/// 结构化错误（§8.3）。
class ToolError {
  final String code;
  final String message;

  /// 重试是否有意义：参数错、临时故障的区别。
  final bool retryable;

  /// 建议的替代动作（工具名或动作名），供模型换路线。
  final List<String> suggestedActions;

  const ToolError({
    required this.code,
    required this.message,
    this.retryable = false,
    this.suggestedActions = const [],
  });

  Map<String, Object?> toJson() => {
        'code': code,
        'message': message,
        'retryable': retryable,
        if (suggestedActions.isNotEmpty) 'suggestedActions': suggestedActions,
      };

  static ToolError fromJson(Object? raw) {
    if (raw is! Map) {
      return ToolError(code: 'unknown', message: raw?.toString() ?? '未知错误');
    }
    return ToolError(
      code: raw['code']?.toString() ?? 'unknown',
      message: raw['message']?.toString() ?? '',
      retryable: raw['retryable'] == true,
      suggestedActions: [
        for (final a in (raw['suggestedActions'] as List? ?? const []))
          a.toString()
      ],
    );
  }
}

/// 截断续读信息（§8.2）。
///
/// 有 continuation 就代表结果不完整——不许当完整结果用（§8.4）。
class ToolContinuation {
  /// page / range / cursor 等。
  final String type;

  /// 续读令牌，回传给下一次调用。
  final String token;

  /// 供人读的下一位置描述。
  final String nextCursor;

  const ToolContinuation({
    required this.type,
    required this.token,
    this.nextCursor = '',
  });

  Map<String, Object?> toJson() => {
        'type': type,
        'token': token,
        if (nextCursor.isNotEmpty) 'nextCursor': nextCursor,
      };

  static ToolContinuation? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final token = raw['token']?.toString() ?? '';
    if (token.isEmpty) return null;
    return ToolContinuation(
      type: raw['type']?.toString() ?? 'page',
      token: token,
      nextCursor: raw['nextCursor']?.toString() ?? '',
    );
  }
}

/// 工具建议的下一步（工具可以建议，但不能强迫模型照做，§8.4）。
class ToolNextAction {
  final String action;
  final String? target;
  final String? reason;

  /// 可直接重发的调用参数（对标 MT MCP 的 `{tool, arguments}` 形状）。
  /// 2026-09-19 全量复测：过去只给动作名 + 一句泛化理由，调用方拿不到
  /// 「照抄就能走」的参数。
  final Map<String, dynamic>? arguments;

  const ToolNextAction({
    required this.action,
    this.target,
    this.reason,
    this.arguments,
  });

  Map<String, Object?> toJson() => {
        'action': action,
        if (target != null) 'target': target,
        if (reason != null) 'reason': reason,
        if (arguments != null && arguments!.isNotEmpty) 'arguments': arguments,
      };

  static ToolNextAction fromJson(Object? raw) {
    if (raw is! Map) return ToolNextAction(action: raw?.toString() ?? '');
    final args = raw['arguments'];
    return ToolNextAction(
      action: raw['action']?.toString() ?? '',
      target: raw['target']?.toString(),
      reason: raw['reason']?.toString(),
      arguments: args is Map ? args.cast<String, dynamic>() : null,
    );
  }
}

/// 工具返回元信息（§8.1 meta）。
class ToolMeta {
  final int durationMs;

  /// 本次调用计入的成本（§12.3）。
  final int cost;

  /// 多 DEX 查询范围报告（§7.7）——避免「没找到」其实是没搜完。
  final Map<String, Object?> queryScope;

  const ToolMeta({
    this.durationMs = 0,
    this.cost = 0,
    this.queryScope = const {},
  });

  Map<String, Object?> toJson() => {
        'durationMs': durationMs,
        'cost': cost,
        if (queryScope.isNotEmpty) 'queryScope': queryScope,
      };

  static ToolMeta fromJson(Object? raw) {
    if (raw is! Map) return const ToolMeta();
    return ToolMeta(
      durationMs: (raw['durationMs'] as num?)?.toInt() ?? 0,
      cost: (raw['cost'] as num?)?.toInt() ?? 0,
      queryScope: raw['queryScope'] is Map
          ? Map<String, Object?>.from(raw['queryScope'] as Map)
          : const {},
    );
  }
}

/// 统一结果信封（§8.1）。
class ToolEnvelope {
  final bool ok;
  final ToolStatus status;
  final String tool;
  final String invocationId;
  final String requestId;
  final String summary;

  /// 结构化载荷。
  final Map<String, Object?> data;

  /// 本次调用产生的证据 id。
  final List<String> evidenceIds;

  /// 本次调用产生的产物引用。
  final List<Map<String, Object?>> artifacts;

  /// 非致命问题：结果可用，但有需要知道的情况。
  final List<String> warnings;

  final List<ToolError> errors;

  final bool truncated;
  final ToolContinuation? continuation;
  final List<ToolNextAction> nextActions;
  final ToolMeta meta;

  const ToolEnvelope({
    required this.ok,
    required this.status,
    required this.tool,
    this.invocationId = '',
    this.requestId = '',
    this.summary = '',
    this.data = const {},
    this.evidenceIds = const [],
    this.artifacts = const [],
    this.warnings = const [],
    this.errors = const [],
    this.truncated = false,
    this.continuation,
    this.nextActions = const [],
    this.meta = const ToolMeta(),
  });

  /// 成功结果。
  factory ToolEnvelope.success({
    required String tool,
    String summary = '',
    Map<String, Object?> data = const {},
    List<String> evidenceIds = const [],
    List<Map<String, Object?>> artifacts = const [],
    List<String> warnings = const [],
    bool truncated = false,
    ToolContinuation? continuation,
    List<ToolNextAction> nextActions = const [],
    ToolMeta meta = const ToolMeta(),
    String invocationId = '',
    String requestId = '',
  }) =>
      ToolEnvelope(
        ok: true,
        status: truncated ? ToolStatus.partial : ToolStatus.success,
        tool: tool,
        invocationId: invocationId,
        requestId: requestId,
        summary: summary,
        data: data,
        evidenceIds: evidenceIds,
        artifacts: artifacts,
        warnings: warnings,
        truncated: truncated,
        continuation: continuation,
        nextActions: nextActions,
        meta: meta,
      );

  /// 失败结果。
  factory ToolEnvelope.failure({
    required String tool,
    required String code,
    required String message,
    bool retryable = false,
    List<String> suggestedActions = const [],
    List<String> warnings = const [],
    String invocationId = '',
    String requestId = '',
    ToolMeta meta = const ToolMeta(),
    /// 失败时仍要交给调用方的结构化信息（报告 2-9：`patch_plan` 已落库却因状态
    /// 推进被拒而丢掉 patchId，调用方再也拿不到那个 id 继续 `dry_run_patch`）。
    Map<String, Object?> data = const <String, Object?>{},
  }) =>
      ToolEnvelope(
        ok: false,
        status: ToolStatus.error,
        tool: tool,
        invocationId: invocationId,
        requestId: requestId,
        summary: message,
        warnings: warnings,
        data: data,
        errors: [
          ToolError(
            code: code,
            message: message,
            retryable: retryable,
            suggestedActions: suggestedActions,
          ),
        ],
        meta: meta,
      );

  /// 续读是否可用 —— 有 token 才算数。
  bool get canContinue => truncated && (continuation?.token.isNotEmpty ?? false);

  /// 只替换 meta（调用方补耗时/成本时用，不改其余字段）。
  ToolEnvelope copyWithMeta(ToolMeta m) => ToolEnvelope(
        ok: ok,
        status: status,
        tool: tool,
        invocationId: invocationId,
        requestId: requestId,
        summary: summary,
        data: data,
        evidenceIds: evidenceIds,
        artifacts: artifacts,
        warnings: warnings,
        errors: errors,
        truncated: truncated,
        continuation: continuation,
        nextActions: nextActions,
        meta: m,
      );

  /// 只合并 additional 的 nextActions（Recovery 建议用，不覆盖原有字段）。
  ToolEnvelope withNextActions(List<ToolNextAction> extra) => ToolEnvelope(
        ok: ok,
        status: status,
        tool: tool,
        invocationId: invocationId,
        requestId: requestId,
        summary: summary,
        data: data,
        evidenceIds: evidenceIds,
        artifacts: artifacts,
        warnings: warnings,
        errors: errors,
        truncated: truncated,
        continuation: continuation,
        nextActions: [...nextActions, ...extra],
        meta: meta,
      );

  Map<String, Object?> toJson() {
    final payload = <String, Object?>{
      'ok': ok,
      'status': status.id,
      'tool': tool,
      if (invocationId.isNotEmpty) 'invocationId': invocationId,
      if (requestId.isNotEmpty) 'requestId': requestId,
      if (summary.isNotEmpty) 'summary': summary,
      if (data.isNotEmpty) 'data': data,
      if (evidenceIds.isNotEmpty) 'evidenceIds': evidenceIds,
      if (artifacts.isNotEmpty) 'artifacts': artifacts,
      if (warnings.isNotEmpty) 'warnings': warnings,
      // F-39（2026-10-04）：失败时把机器可读码提到**顶层**（code 取首个错误）——
      // 过去 A 形信封的码只在内层 errors[]，只读顶层的关系拿不到（v7 D7 同形未改）。
      // v16（2026-10-05）：顶层 `retryable` 别名**移除**——与工具族统一用
      // unifyFailure 补出的 `retrySameArguments`（内层 errors[].retryable 保留，
      // 那是本族自己的数组字段，无人按 JSON 顶层键读取它）。
      if (!ok && errors.isNotEmpty) 'code': errors.first.code,
      if (errors.isNotEmpty) 'errors': [for (final e in errors) e.toJson()],
      'truncated': truncated,
      if (continuation != null) 'continuation': continuation!.toJson(),
      if (nextActions.isNotEmpty)
        'nextActions': [for (final a in nextActions) a.toJson()],
      'meta': meta.toJson(),
    };
    if (ok) return payload;
    // F-39 任务族收口（v13 复测）：ToolEnvelope 过去走自己的失败形状
    // （status/errors[]/data/retryable），与工具族的规范失败形只差一层语义。
    // 出口统一过 ToolErrorPolicy.unifyFailure：补齐 error{code,message,severity,
    // recoverable,retrySameArguments,diagnostics} 与顶层 code/message/recoverable
    // 镜像——errors[]/data/summary/status/retryable 等原有字段全部保留。
    return ToolErrorPolicy.unifyFailure(Map<String, dynamic>.from(payload));
  }

  /// 回填给模型看的文本（工具消息内容）。
  String toToolText() => jsonEncode(toJson());

  static ToolEnvelope fromJson(Object? raw) {
    if (raw is! Map) {
      return ToolEnvelope.failure(
        tool: '',
        code: 'malformed_result',
        message: '工具返回不是对象',
      );
    }
    return ToolEnvelope(
      ok: raw['ok'] == true,
      status: ToolStatus.fromId(raw['status']?.toString() ?? 'error'),
      tool: raw['tool']?.toString() ?? '',
      invocationId: raw['invocationId']?.toString() ?? '',
      requestId: raw['requestId']?.toString() ?? '',
      summary: raw['summary']?.toString() ?? '',
      data: raw['data'] is Map
          ? Map<String, Object?>.from(raw['data'] as Map)
          : const {},
      evidenceIds: [
        for (final e in (raw['evidenceIds'] as List? ?? const [])) e.toString()
      ],
      artifacts: [
        for (final a in (raw['artifacts'] as List? ?? const []))
          if (a is Map) Map<String, Object?>.from(a)
      ],
      warnings: [
        for (final w in (raw['warnings'] as List? ?? const [])) w.toString()
      ],
      errors: [
        for (final e in (raw['errors'] as List? ?? const [])) ToolError.fromJson(e)
      ],
      truncated: raw['truncated'] == true,
      continuation: ToolContinuation.fromJson(raw['continuation']),
      nextActions: [
        for (final a in (raw['nextActions'] as List? ?? const []))
          ToolNextAction.fromJson(a)
      ],
      meta: ToolMeta.fromJson(raw['meta']),
    );
  }
}
