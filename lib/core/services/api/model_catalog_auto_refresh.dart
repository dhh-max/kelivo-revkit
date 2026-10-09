import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import '../../providers/model_provider.dart';
import '../../providers/settings_provider.dart';
import 'model_route_resolver.dart';

/// 模型目录自动刷新。
///
/// 用户诉求（2026-09-21）：厂家上新模型后，不该还要人手去模型列表里"获取/
/// 添加"。内置厂家（OpenCode Zen、Command Code）与所有配了 key 的厂家，每
/// [minInterval] 自动拉一次 `GET {baseUrl}/models`，把**新出现的** id 追加进
/// 该厂家的模型列表。
///
/// 三条纪律：
/// - **只增不减**：接口没回的老模型、用户手动加的、已禁用的，一概不动（删除
///   仍在模型列表里手动做）——自动删除会把用户的配置悄悄吃掉。
/// - **失败静默记账**：单家失败不影响其它家，结果与时间戳落盘，供诊断查看。
/// - **不阻塞启动**：由启动路径 `unawaited` 调用，逐家串行、单家 12s 上限。
abstract final class ModelCatalogAutoRefresh {
  const ModelCatalogAutoRefresh._();

  /// 刷新间隔：三天一次足够跟上上新节奏，又不会天天打接口。
  static const Duration minInterval = Duration(days: 3);

  /// 单家拉取上限：卡住的厂家不拖住后面所有家。
  static const Duration perProviderTimeout = Duration(seconds: 12);

  static const String _lastRunKey = 'model_catalog_auto_refresh_v1';
  static const String _reportKey = 'model_catalog_auto_refresh_report_v1';

  /// 免 key 即可列模型的厂家（官方 `/models` 公开）。
  static const Set<String> publicCatalogProviders = <String>{
    'opencode',
    'commandcode',
    'command code',
  };

  /// 到点才刷新；[force] 供"立即刷新"入口使用。返回一份可打印/可入账的报告。
  static Future<Map<String, Object?>> maybeRefresh(
    SettingsProvider settings, {
    bool force = false,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    final lastRunAt = prefs.getInt(_lastRunKey) ?? 0;
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    if (!force && nowMs - lastRunAt < minInterval.inMilliseconds) {
      return const <String, Object?>{'skipped': true, 'reason': 'withinInterval'};
    }

    final addedByProvider = <String, int>{};
    final failed = <String, String>{};
    var added = 0;
    var scanned = 0;

    for (final cfg in settings.providerConfigs.values) {
      if (cfg.baseUrl.trim().isEmpty) continue;
      final idLower = cfg.id.toLowerCase();
      final isPublicCatalog = publicCatalogProviders.any(idLower.contains);
      final hasKey =
          cfg.apiKey.trim().isNotEmpty ||
          (cfg.apiKeys ?? const []).any(
            (entry) => entry.key.trim().isNotEmpty && entry.isEnabled,
          );
      // 没配 key 的第三方厂家不试（必 401，白打接口）；两家内置目录公开。
      if (!hasKey && !isPublicCatalog && !cfg.enabled) continue;
      scanned++;
      try {
        final models = await ProviderManager.listModels(
          cfg,
        ).timeout(perProviderTimeout);
        final known = cfg.models.toSet();
        final excluded = manualExclusions(cfg);
        final fresh = <String>[
          for (final model in models)
            if (model.id.trim().isNotEmpty &&
                !known.contains(model.id) &&
                !excluded.contains(model.id.trim()))
              model.id.trim(),
        ];
        // 端点元数据：模型自报能走哪条协议（Command Code 的
        // supported_endpoints）写进 modelOverrides，供 ModelRouteResolver
        // 决定每个模型用 /chat/completions 还是 /responses。
        final endpoints = await _fetchDeclaredEndpoints(cfg);
        if (fresh.isEmpty && endpoints.isEmpty) continue;
        final overrides = <String, dynamic>{...cfg.modelOverrides};
        for (final entry in endpoints.entries) {
          final existing = overrides[entry.key];
          overrides[entry.key] = existing is Map
              ? <String, dynamic>{...existing, ...entry.value as Map}
              : entry.value;
        }
        await settings.setProviderConfig(
          cfg.id,
          cfg.copyWith(
            models: <String>[...cfg.models, ...fresh],
            modelOverrides: overrides,
          ),
        );
        addedByProvider[cfg.id] = fresh.length;
        added += fresh.length;
        debugPrint(
          '[ModelCatalogAutoRefresh] ${cfg.id}: +${fresh.length} '
          '(${fresh.take(5).join(', ')}${fresh.length > 5 ? '…' : ''})',
        );
      } catch (error) {
        failed[cfg.id] = error.toString();
        debugPrint('[ModelCatalogAutoRefresh] ${cfg.id} 刷新失败: $error');
      }
    }

    final report = <String, Object?>{
      'at': nowMs,
      'scanned': scanned,
      'added': added,
      'addedByProvider': addedByProvider,
      'failed': failed,
    };
    await prefs.setInt(_lastRunKey, nowMs);
    await prefs.setString(_reportKey, jsonEncode(report));
    return report;
  }

  /// 用户手动剔除过的模型（墓碑）：自动刷新**不得**把它们加回来。
  ///
  /// 用户在模型列表里删掉的模型会留 `autoExcluded` 标记（见
  /// `SettingsProvider.deleteModels`）；只有用户手动加回时才清除。
  /// 这里同时认"配置里已声明过的"与"墓碑标记"两种，前者保证老模型不被
  /// 误加，后者保证用户删过的不回潮。
  @visibleForTesting
  static Set<String> manualExclusions(ProviderConfig cfg) => <String>{
    for (final entry in cfg.modelOverrides.entries)
      if (entry.value is Map &&
          (entry.value as Map)[SettingsProvider.modelAutoExcludedKey] == true)
        entry.key,
  };

  /// 直连 `GET {baseUrl}/models` 取每个模型自报的 `supported_endpoints`。
  ///
  /// 不走 ProviderManager.listModels 是因为 ModelInfo 只带 id/模态/能力，
  /// 没有地方装端点声明；而这两家的 /models 公开可读，一次 GET 就够。
  /// 拿不到（401/超时/字段缺失）就返回空表，不影响模型清单的合并。
  static Future<Map<String, dynamic>> _fetchDeclaredEndpoints(
    ProviderConfig cfg,
  ) async {
    final base = cfg.baseUrl.trim().replaceAll(RegExp(r'/\$'), '');
    if (base.isEmpty) return const <String, dynamic>{};
    try {
      final response = await http
          .get(
            Uri.parse('$base/models'),
            headers: <String, String>{
              if (cfg.apiKey.trim().isNotEmpty)
                'Authorization': 'Bearer ${cfg.apiKey.trim()}',
            },
          )
          .timeout(perProviderTimeout);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        return const <String, dynamic>{};
      }
      final decoded = jsonDecode(response.body);
      final data = (decoded is Map ? decoded['data'] : null);
      if (data is! List) return const <String, dynamic>{};
      final out = <String, dynamic>{};
      for (final entry in data) {
        if (entry is! Map) continue;
        final id = entry['id']?.toString().trim() ?? '';
        final declared = entry[ModelRouteResolver.supportedEndpointsKey];
        if (id.isEmpty || declared is! List) continue;
        final paths = <String>[
          for (final item in declared)
            if (item.toString().trim().isNotEmpty) item.toString().trim(),
        ];
        if (paths.isEmpty) continue;
        out[id] = <String, dynamic>{
          ModelRouteResolver.supportedEndpointsKey: paths,
        };
      }
      return out;
    } catch (error) {
      debugPrint('[ModelCatalogAutoRefresh] ${cfg.id} 端点声明拉取失败: $error');
      return const <String, dynamic>{};
    }
  }

  /// 上次刷新的报告（时间戳 / 新增 / 失败），供设置页或诊断使用。
  static Future<Map<String, Object?>> lastReport() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_reportKey);
    if (raw == null || raw.isEmpty) return const <String, Object?>{};
    try {
      final decoded = jsonDecode(raw);
      if (decoded is Map) {
        return decoded.map((key, value) => MapEntry(key.toString(), value));
      }
    } catch (_) {}
    return const <String, Object?>{};
  }
}
