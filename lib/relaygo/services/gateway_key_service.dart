import 'package:hive_flutter/hive_flutter.dart';
import 'package:Kelivo/relaygo/database/database_helper.dart';

/// 附加网关密钥模型
class GatewayKey {
  final String key;
  final String name;
  final String permission; // full / readonly / models
  final List<String> models;
  final bool enabled;
  final String note;

  const GatewayKey({
    required this.key,
    this.name = '',
    this.permission = 'full',
    this.models = const [],
    this.enabled = true,
    this.note = '',
  });

  Map<String, dynamic> toJson() => {
        'key': key,
        'name': name,
        'permission': permission,
        'models': models,
        'enabled': enabled,
        'note': note,
      };

  /// 脱敏视图（不返回完整密钥）
  Map<String, dynamic> toMaskedJson() {
    final raw = key;
    final masked = raw.length > 8
        ? '${raw.substring(0, 4)}••••${raw.substring(raw.length - 4)}'
        : '••••';
    return {
      'name': name,
      'permission': permission,
      'models': models,
      'enabled': enabled,
      'note': note,
      'key_masked': masked,
    };
  }

  factory GatewayKey.fromJson(Map<String, dynamic> json) {
    return GatewayKey(
      key: (json['key'] ?? '').toString().trim(),
      name: (json['name'] ?? '').toString().trim(),
      permission: (json['permission'] ?? 'full').toString(),
      models: (json['models'] as List?)
              ?.map((x) => x.toString())
              .toList() ??
          [],
      enabled: json['enabled'] as bool? ?? true,
      note: (json['note'] ?? '').toString(),
    );
  }
}

/// 附加网关密钥管理服务
///
/// 持久化到 Hive settings box。网关鉴权热路径直接读内存缓存，
/// 控制台改动时即时失效。
class GatewayKeyService {
  final Box _box;
  static const String _key = 'gateway_keys';

  List<GatewayKey> _cache = [];
  bool _loaded = false;

  GatewayKeyService([Box? box]) : _box = box ?? DatabaseHelper.settings;

  void _ensureLoaded() {
    if (_loaded) return;
    final data = _box.get(_key);
    if (data is List) {
      _cache = data
          .whereType<Map>()
          .map((e) => GatewayKey.fromJson(Map<String, dynamic>.from(e)))
          .where((k) => k.key.isNotEmpty)
          .toList();
    }
    _loaded = true;
  }

  List<GatewayKey> get all {
    _ensureLoaded();
    return List.from(_cache);
  }

  /// 获取脱敏列表（不返回完整密钥）
  List<Map<String, dynamic>> get maskedAll {
    _ensureLoaded();
    return _cache.map((k) => k.toMaskedJson()).toList();
  }

  /// 设置全部附加密钥（覆盖写入）
  Future<void> setAll(List<GatewayKey> keys) async {
    _cache = keys.where((k) => k.key.isNotEmpty).toList();
    _loaded = true;
    await _persist();
  }

  /// 从 JSON 列表设置全部密钥
  Future<void> setAllFromJson(List<dynamic> jsonList) async {
    final keys = jsonList
        .whereType<Map>()
        .map((e) => GatewayKey.fromJson(Map<String, dynamic>.from(e)))
        .toList();
    await setAll(keys);
  }

  Future<void> _persist() async {
    await _box.put(_key, _cache.map((k) => k.toJson()).toList());
  }

  /// 查找匹配的附加密钥。返回权限信息，未匹配返回 null。
  ({String permission, String name, List<String> models})? match(
      String presented) {
    if (presented.isEmpty) return null;
    _ensureLoaded();
    for (final gk in _cache) {
      if (!gk.enabled) continue;
      if (presented == gk.key) {
        return (
          permission: gk.permission,
          name: gk.name,
          models: gk.models,
        );
      }
    }
    return null;
  }
}