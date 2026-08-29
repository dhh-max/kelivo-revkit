import 'dart:convert';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:Kelivo/relaygo/config/constants.dart';
import 'package:Kelivo/relaygo/database/database_helper.dart';
import 'package:Kelivo/relaygo/models/api_key.dart';

/// 模型路由规则：某模型只走指定 Key
///
/// 持久化到 Hive settings box，格式：
/// { "model_name": { "key_ids": ["id1","id2"], "enabled": true, "note": "" } }
class ModelRoute {
  final String model;
  final List<String> keyIds;
  final bool enabled;
  final String note;

  const ModelRoute({
    required this.model,
    this.keyIds = const [],
    this.enabled = true,
    this.note = '',
  });

  Map<String, dynamic> toJson() => {
        'key_ids': keyIds,
        'enabled': enabled,
        'note': note,
      };
}

/// 模型路由服务
class ModelRouteService {
  final Box _box;

  ModelRouteService([Box? box])
      : _box = box ?? DatabaseHelper.settings;

  static const String _key = 'model_routes';

  Map<String, ModelRoute> _routes = {};
  bool _loaded = false;

  void _ensureLoaded() {
    if (_loaded) return;
    final data = _box.get(_key);
    if (data is Map) {
      _routes = {
        for (final e in data.entries)
          if (e.value is Map)
            e.key.toString(): ModelRoute(
              model: e.key.toString(),
              keyIds: (e.value['key_ids'] as List?)
                      ?.map((x) => x.toString())
                      .toList() ??
                  [],
              enabled: e.value['enabled'] as bool? ?? true,
              note: e.value['note'] as String? ?? '',
            ),
      };
    }
    _loaded = true;
  }

  /// 获取全部路由规则
  Map<String, ModelRoute> getRoutes() {
    _ensureLoaded();
    return Map.from(_routes);
  }

  /// 按模型查找路由规则。返回 null 表示无规则或未启用。
  ModelRoute? routeFor(String model) {
    if (model.isEmpty) return null;
    _ensureLoaded();
    final r = _routes[model];
    if (r == null || !r.enabled) return null;
    return r;
  }

  /// 返回路由指定的候选 Key ID 列表（enabled 且有 keyIds）
  List<String> keyIdsFor(String model) {
    final r = routeFor(model);
    return r?.keyIds ?? [];
  }

  /// 设置/更新模型路由
  Future<void> setRoute(
    String model,
    List<String> keyIds, {
    bool enabled = true,
    String note = '',
  }) async {
    _ensureLoaded();
    _routes[model] = ModelRoute(
      model: model,
      keyIds: keyIds,
      enabled: enabled,
      note: note,
    );
    await _persist();
  }

  /// 删除模型路由
  Future<void> deleteRoute(String model) async {
    _ensureLoaded();
    _routes.remove(model);
    await _persist();
  }

  Future<void> _persist() async {
    final data = <String, dynamic>{};
    for (final e in _routes.entries) {
      data[e.key] = e.value.toJson();
    }
    await _box.put(_key, data);
  }
}