import 'dart:developer' as developer;

import 'package:shared_preferences/shared_preferences.dart';

import 'business_data.dart';
import 'business_repository.dart';
import 'business_settings_router.dart';

abstract interface class LegacyBusinessPreferences {
  Future<Map<String, Object?>> snapshot();

  Future<void> remove(String key);
}

final class SharedPreferencesLegacyBusinessPreferences
    implements LegacyBusinessPreferences {
  SharedPreferencesLegacyBusinessPreferences(this._preferences);

  final SharedPreferences _preferences;

  static Future<SharedPreferencesLegacyBusinessPreferences> open() async =>
      SharedPreferencesLegacyBusinessPreferences(
        await SharedPreferences.getInstance(),
      );

  @override
  Future<Map<String, Object?>> snapshot() async => {
    for (final key in _preferences.getKeys()) key: _preferences.get(key),
  };

  @override
  Future<void> remove(String key) async {
    if (_preferences.containsKey(key) && !await _preferences.remove(key)) {
      throw StateError('business_migration_cleanup:$key');
    }
  }
}

enum BusinessMigrationResult {
  migrated,
  freshInstall,
  alreadyComplete,
  cleanedAfterReceipt,
  deferredCleanup,
}

final class BusinessMigrationEngine {
  BusinessMigrationEngine({
    required this.repository,
    required this.legacyPreferences,
    this._checkpoint,
  });

  final BusinessRepository repository;
  final LegacyBusinessPreferences legacyPreferences;
  final Future<bool> Function()? _checkpoint;

  Future<BusinessMigrationResult> run() async {
    final legacy = await legacyPreferences.snapshot();
    // 首跑：未知键会在本次 run 里被导出进 SQLite，清 legacy 副本安全。
    final cleanupKeys = _cleanupKeys(legacy.keys, includeUnknown: true);
    if (await repository.hasMigrationReceipt()) {
      // 收据阶段：只清「有 SQLite 副本或明确作废」的键；未知键一律保留
      // （见 _cleanupKeys 注释：那是应用自有 Store 的运行时写入）。
      final receiptCleanup = _cleanupKeys(
        legacy.keys,
        includeUnknown: false,
      );
      if (receiptCleanup.isEmpty) {
        return BusinessMigrationResult.alreadyComplete;
      }
      if (!await _durabilityBarrierAchieved()) {
        return BusinessMigrationResult.deferredCleanup;
      }
      await _cleanup(receiptCleanup);
      return BusinessMigrationResult.cleanedAfterReceipt;
    }

    final hasBusinessData = cleanupKeys.isNotEmpty;
    BusinessSnapshot route(Map<String, Object?> source) =>
        BusinessSettingsRouter.normalizeAndRoute(
          source,
          preserveExplicitEmptyInstructionList: true,
          assumePreV3EmbeddingMigrationWhenVersionMissing: true,
        );

    late final BusinessSnapshot routed;
    try {
      routed = route(legacy);
    } on FormatException catch (error) {
      if (error.message != BusinessEntityKind.searchService.sourceKey) {
        rethrow;
      }
      routed = route(Map<String, Object?>.from(legacy)..remove(error.message));
    }
    await repository.replaceSnapshotForMigration(
      routed,
      validatePersisted: (stored) {
        _validateEntityCounts(routed, stored);
        final expected = BusinessSettingsRouter.exportSnapshot(routed);
        final actual = BusinessSettingsRouter.exportSnapshot(stored);
        if (!_deepEquals(expected, actual)) {
          throw StateError('business_migration_export_mismatch');
        }
      },
    );

    if (await _durabilityBarrierAchieved()) {
      await _cleanup(cleanupKeys);
    }
    return hasBusinessData
        ? BusinessMigrationResult.migrated
        : BusinessMigrationResult.freshInstall;
  }

  Future<bool> _durabilityBarrierAchieved() async {
    try {
      return await (_checkpoint ?? repository.checkpoint)();
    } catch (error, stackTrace) {
      developer.log(
        'Business migration durability barrier failed; '
        'deferring legacy cleanup.',
        name: 'SoLab.business.migration',
        error: error,
        stackTrace: stackTrace,
      );
      return false;
    }
  }

  /// 迁移完成后该从 legacy 插件 prefs 里清掉的键。
  ///
  /// 只清「**存在 SQLite 副本或明确作废**」的键：entity / providerOrder /
  /// preference（已迁移）；discarded（显式废弃）；首跑时的 unknownPreference
  /// （同一次 run 刚把它们导出进 SQLite，清 legacy 副本是既有设计）。
  ///
  /// **拿到收据之后不再清未知键**：那时的未知键都是应用自有 Store 的运行时写入
  /// （如 workflows_v1 —— 2026-10-05 事故里每次开机被清、且没有任何副本，
  /// 表现为「工作流/目标/待办重启即丢」）。发现未知键应该去注册表登记，
  /// 而不是删数据。localOnly 两阶段都不清。
  static Set<String> _cleanupKeys(
    Iterable<String> keys, {
    required bool includeUnknown,
  }) => {
    for (final key in keys)
      if (_isMigratedDisposition(BusinessKeyRegistry.classify(key)) ||
          BusinessKeyRegistry.discardedKeys.contains(key) ||
          (includeUnknown &&
              BusinessKeyRegistry.classify(key) ==
                  BusinessKeyDisposition.unknownPreference))
        key,
  };

  static bool _isMigratedDisposition(BusinessKeyDisposition disposition) =>
      disposition == BusinessKeyDisposition.entity ||
      disposition == BusinessKeyDisposition.providerOrder ||
      disposition == BusinessKeyDisposition.preference;

  Future<void> _cleanup(Set<String> keys) async {
    final ordered = keys.toList()..sort();
    for (final key in ordered) {
      await legacyPreferences.remove(key);
    }
  }

  static void _validateEntityCounts(
    BusinessSnapshot expected,
    BusinessSnapshot actual,
  ) {
    for (final kind in BusinessEntityKind.values) {
      if (expected.entityCount(kind) != actual.entityCount(kind)) {
        throw StateError('business_migration_count:${kind.sourceKey}');
      }
    }
  }
}

bool _deepEquals(Object? left, Object? right) {
  if (identical(left, right) || left == right) return true;
  if (left is List && right is List) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (!_deepEquals(left[index], right[index])) return false;
    }
    return true;
  }
  if (left is Map && right is Map) {
    if (left.length != right.length) return false;
    for (final entry in left.entries) {
      if (!right.containsKey(entry.key) ||
          !_deepEquals(entry.value, right[entry.key])) {
        return false;
      }
    }
    return true;
  }
  return false;
}
