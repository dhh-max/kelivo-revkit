/// 多 DEX 查询范围（§7.7）。
///
/// 要防的是一句最危险的结论：**「没找到」其实只是没搜完**。
///
/// APK 可能有 classes.dex 到 classesN.dex，跨 DEX 的查询必须说清搜了几个、
/// 命中几个、失败几个、跳过几个；说不清就不能把空结果当结论。
/// 这里在 Dart 侧把工具返回统一成这个契约，不改 Kotlin 工具本身。
library;

import 'models/tool_result.dart';

/// 一次查询的范围报告（§7.7 的 queryScope 块）。
class DexQueryScope {
  /// ALL_DEX / SPECIFIED / UNKNOWN。
  final String queryScope;

  final int? searchedDexCount;
  final int? totalDexCount;
  final int? matchedDexCount;
  final int? failedDexCount;
  final int? skippedDexCount;
  final bool truncated;

  const DexQueryScope({
    required this.queryScope,
    this.searchedDexCount,
    this.totalDexCount,
    this.matchedDexCount,
    this.failedDexCount,
    this.skippedDexCount,
    this.truncated = false,
  });

  /// 搜了几个、总共几个都清楚。
  bool get scopeKnown => searchedDexCount != null && totalDexCount != null;

  /// 是否**确定**搜完了：覆盖全部 DEX，且没有失败/跳过。
  bool get complete =>
      scopeKnown &&
      searchedDexCount! >= totalDexCount! &&
      (failedDexCount ?? 0) == 0 &&
      (skippedDexCount ?? 0) == 0;

  /// 空结果能不能当结论——只有搜完才有资格说「没有」。
  bool get emptyResultIsTrustworthy => complete && !truncated;

  Map<String, Object?> toJson() => {
        'queryScope': queryScope,
        if (searchedDexCount != null) 'searchedDexCount': searchedDexCount,
        if (totalDexCount != null) 'totalDexCount': totalDexCount,
        if (matchedDexCount != null) 'matchedDexCount': matchedDexCount,
        if (failedDexCount != null) 'failedDexCount': failedDexCount,
        if (skippedDexCount != null) 'skippedDexCount': skippedDexCount,
        'truncated': truncated,
      };
}

/// 跨 DEX 查询的守卫：补范围报告，并在「没搜完的空结果」上踩刹车。
class MultiDexGuard {
  MultiDexGuard._();

  /// 会跨 DEX 扫描的工具。
  static const dexTools = <String>{
    'dex_search',
    'string_scan',
    'field_xref',
    'dex_xref',
    'class_outline',
    'jadx_decompile',
    'smali_read',
  };

  /// 从工具返回里挖出「扫了几个 DEX」。
  ///
  /// 兼容几种现状：顶层 dexCount、summary.dexCount、queryScope 里的字段。
  static int? searchedOf(Map<String, Object?> data) {
    for (final k in const [
      'searchedDexCount',
      'dexCount',
      'scannedDexCount',
    ]) {
      final v = _intOf(data[k]);
      if (v != null) return v;
    }
    final summary = data['summary'];
    if (summary is Map) {
      for (final k in const ['dexCount', 'searchedDexCount', 'scannedDexCount']) {
        final v = _intOf(summary[k]);
        if (v != null) return v;
      }
    }
    final scope = data['queryScope'];
    if (scope is Map) {
      final v = _intOf(scope['searchedDexCount']);
      if (v != null) return v;
    }
    return null;
  }

  /// 命中条数：不同工具叫法不一样，这里统一猜一次。
  static int hitsOf(Map<String, Object?> data) {
    for (final k in const [
      'count',
      'total',
      'hitCount',
      'matches',
      'totalRefs',
      'totalMatches',
      'found',
    ]) {
      final v = _intOf(data[k]);
      if (v != null) return v;
    }
    final summary = data['summary'];
    if (summary is Map) {
      final v = hitsOf(Map<String, Object?>.from(summary));
      if (v > 0) return v;
    }
    // 没给计数就看列表长度
    for (final k in const ['items', 'rows', 'results', 'classes', 'methods']) {
      final v = data[k];
      if (v is List) return v.length;
    }
    return 0;
  }

  /// 组装范围报告。
  static DexQueryScope scopeOf({
    required String tool,
    required Map<String, Object?> data,
    int? knownTotalDex,
    bool truncated = false,
  }) {
    final searched = searchedOf(data);
    final explicitScope = data['queryScope'];
    final explicitTotal = explicitScope is Map
        ? _intOf(explicitScope['totalDexCount'])
        : _intOf(data['totalDexCount']);
    final total = explicitTotal ?? knownTotalDex;

    final failed = explicitScope is Map
        ? _intOf(explicitScope['failedDexCount'])
        : _intOf(data['failedDexCount']);
    final skipped = explicitScope is Map
        ? _intOf(explicitScope['skippedDexCount'])
        : _intOf(data['skippedDexCount']);
    final matched = explicitScope is Map
        ? _intOf(explicitScope['matchedDexCount'])
        : _intOf(data['matchedDexCount']);

    final label = explicitScope is String
        ? explicitScope
        : (searched != null ? 'ALL_DEX' : 'UNKNOWN');

    return DexQueryScope(
      queryScope: label,
      searchedDexCount: searched,
      totalDexCount: total,
      matchedDexCount: matched,
      failedDexCount: failed,
      skippedDexCount: skipped,
      truncated: truncated,
    );
  }

  /// 给信封补范围报告，并在必要时把「空结果」降级为不可信。
  ///
  /// 规则：
  /// - 非 DEX 工具：原样返回；
  /// - 命中 > 0：只补范围报告；
  /// - 命中 = 0 且**确定搜完**：保持成功，摘要写明覆盖范围；
  /// - 命中 = 0 且搜没搜完不清楚：降级 partial + 警告 + 下一步建议。
  static ToolEnvelope apply(
    ToolEnvelope env, {
    required String tool,
    int? knownTotalDex,
  }) {
    if (!dexTools.contains(tool)) return env;

    final scope = scopeOf(
      tool: tool,
      data: env.data,
      knownTotalDex: knownTotalDex,
      truncated: env.truncated,
    );
    final hits = hitsOf(env.data);
    final meta = ToolMeta(
      durationMs: env.meta.durationMs,
      cost: env.meta.cost,
      queryScope: scope.toJson(),
    );

    // 有命中，或本来就是失败：只补范围，不改结论
    if (hits > 0 || !env.ok) {
      return env.copyWithMeta(meta);
    }

    if (scope.emptyResultIsTrustworthy) {
      return _rebuild(
        env,
        meta: meta,
        summary: '已扫描全部 ${scope.totalDexCount} 个 DEX，未命中',
      );
    }

    final coverage = scope.totalDexCount == null
        ? '工具没有报告扫描范围'
        : '只确认扫了 ${scope.searchedDexCount} / ${scope.totalDexCount} 个 DEX';
    return _rebuild(
      env,
      meta: meta,
      statusOverride: ToolStatus.partial,
      summary: '未命中，但搜索范围不完整（$coverage）',
      extraWarnings: [
        '「没找到」此刻不可信：$coverage。'
            '先确认包里有几个 DEX，再决定换关键词还是换路线。',
      ],
      extraActions: const [
        ToolNextAction(
          action: 'apk_archive',
          reason: '先列出包内 classes*.dex，确认一共有几个 DEX',
        ),
        ToolNextAction(
          action: 'dex_search',
          reason: '换关键词或扩大范围后再搜一次',
        ),
      ],
    );
  }

  static ToolEnvelope _rebuild(
    ToolEnvelope env, {
    required ToolMeta meta,
    ToolStatus? statusOverride,
    String? summary,
    List<String> extraWarnings = const [],
    List<ToolNextAction> extraActions = const [],
  }) =>
      ToolEnvelope(
        ok: env.ok,
        status: statusOverride ?? env.status,
        tool: env.tool,
        invocationId: env.invocationId,
        requestId: env.requestId,
        summary: summary ?? env.summary,
        data: env.data,
        evidenceIds: env.evidenceIds,
        artifacts: env.artifacts,
        warnings: [...env.warnings, ...extraWarnings],
        errors: env.errors,
        truncated: env.truncated,
        continuation: env.continuation,
        nextActions: [...env.nextActions, ...extraActions],
        meta: meta,
      );

  static int? _intOf(Object? v) {
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v);
    return null;
  }
}
