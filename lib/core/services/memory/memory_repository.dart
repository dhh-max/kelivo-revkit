import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import '../../models/memory_entry.dart';
import '../../models/user_profile_field.dart';

/// Revkit-adapted MemoryRepository.
///
/// Same public contract as the master-branch `MemoryRepository`
/// (create / createMany / updateContent / updateScope / archive / restore /
/// hardDelete / hardDeleteMany / linkBidirectional / putProfileField /
/// removeProfileField), but backed by a single `SharedPreferences` blob.
class MemoryRepository {
  MemoryRepository(this._prefs);

  final SharedPreferences _prefs;

  static const String _memoriesKey = 'revkit_memory_entries_v1';
  static const String _profilesKey = 'revkit_user_profile_fields_v1';

  // ─── low-level persistence ─────────────────────────────────────────────
  Future<List<MemoryEntry>> readAll() async {
    final raw = _prefs.getString(_memoriesKey);
    if (raw == null || raw.isEmpty) return <MemoryEntry>[];
    try {
      final decoded = jsonDecode(raw) as List<dynamic>;
      return [
        for (final item in decoded)
          MemoryEntry.fromPayload((item as Map).cast<String, dynamic>()),
      ];
    } catch (_) {
      return <MemoryEntry>[];
    }
  }

  Future<void> writeAll(List<MemoryEntry> entries) async {
    await _prefs.setString(
      _memoriesKey,
      jsonEncode([for (final e in entries) e.toPayload()]),
    );
  }

  Future<_ExclusiveGuard> _lock() async => _ExclusiveGuard();

  // NOTE: SharedPreferences is already serialized per isolate; to keep the
  // master's read-modify-write semantics simple we rely on that here.

  // ─── writes ────────────────────────────────────────────────────────────
  Future<MemoryEntry> create({
    required MemoryScope scope,
    String? assistantId,
    required MemoryType type,
    required String content,
    required MemorySource source,
    List<String> relatedIds = const [],
  }) async {
    _validateScope(scope, assistantId);
    final all = await readAll();
    final taken = {for (final entry in all) entry.id};
    final id = _newUniqueId(taken);
    final now = DateTime.now().toUtc();
    final entry = MemoryEntry(
      id: id,
      scope: scope,
      assistantId: assistantId,
      type: type,
      status: MemoryStatus.active,
      content: content,
      source: source,
      relatedIds: List<String>.of(relatedIds),
      createdAt: now,
      updatedAt: now,
    );
    all.add(entry);
    await writeAll(all);
    return entry;
  }

  Future<MemoryCreateManyResult> createMany(List<MemoryCreateDraft> drafts) async {
    if (drafts.isEmpty) {
      return const MemoryCreateManyResult(created: 0, skipped: 0);
    }
    for (final draft in drafts) {
      _validateScope(draft.scope, draft.assistantId);
      if (draft.migrationId != null && draft.migrationId!.trim().isEmpty) {
        throw ArgumentError.value(
          draft.migrationId,
          'migrationId',
          'Must not be empty',
        );
      }
    }
    final all = await readAll();
    final takenIds = {for (final entry in all) entry.id};
    final knownMigrationIds = <String>{
      for (final entry in all) ...entry.migrationIds,
    };
    final contentIndexes = <String, int>{};
    for (var i = 0; i < all.length; i++) {
      contentIndexes.putIfAbsent(
        _contentKey(all[i].scope, all[i].assistantId, all[i].content),
        () => i,
      );
    }
    final now = DateTime.now().toUtc();
    var created = 0;
    var skipped = 0;
    var changed = false;
    for (final draft in drafts) {
      final migrationId = draft.migrationId;
      if (migrationId != null && knownMigrationIds.contains(migrationId)) {
        skipped++;
        continue;
      }
      final contentKey = _contentKey(
        draft.scope,
        draft.assistantId,
        draft.content,
      );
      final existingIndex = contentIndexes[contentKey];
      if (existingIndex != null) {
        skipped++;
        if (migrationId != null) {
          final existing = all[existingIndex];
          all[existingIndex] = existing.copyWith(
            migrationIds: [...existing.migrationIds, migrationId],
          );
          knownMigrationIds.add(migrationId);
          changed = true;
        }
        continue;
      }
      final id = _newUniqueId(takenIds);
      takenIds.add(id);
      final entry = MemoryEntry(
        id: id,
        scope: draft.scope,
        assistantId: draft.assistantId,
        type: draft.type,
        status: MemoryStatus.active,
        content: draft.content,
        source: draft.source,
        relatedIds: List<String>.of(draft.relatedIds),
        migrationIds:
            migrationId == null ? const <String>[] : <String>[migrationId],
        createdAt: now,
        updatedAt: now,
      );
      all.add(entry);
      contentIndexes[contentKey] = all.length - 1;
      if (migrationId != null) knownMigrationIds.add(migrationId);
      created++;
      changed = true;
    }
    if (changed) await writeAll(all);
    return MemoryCreateManyResult(created: created, skipped: skipped);
  }

  Future<MemoryEntry?> updateContent(String id, String content) async {
    final all = await readAll();
    final index = all.indexWhere((entry) => entry.id == id);
    if (index == -1) return null;
    final updated = all[index].copyWith(
      content: content,
      updatedAt: DateTime.now().toUtc(),
    );
    all[index] = updated;
    await writeAll(all);
    return updated;
  }

  Future<MemoryEntry?> updateScope(
    String id, {
    required MemoryScope scope,
    String? assistantId,
  }) async {
    if (scope == MemoryScope.global && assistantId != null) {
      throw ArgumentError.value(
        assistantId,
        'assistantId',
        'Must be null when scope is global',
      );
    }
    if (scope == MemoryScope.assistant &&
        (assistantId == null || assistantId.isEmpty)) {
      throw ArgumentError.value(
        assistantId,
        'assistantId',
        'Required when scope is assistant',
      );
    }
    final all = await readAll();
    final index = all.indexWhere((entry) => entry.id == id);
    if (index == -1) return null;
    final updated = all[index].copyWith(
      scope: scope,
      assistantId: assistantId,
      clearAssistantId: scope == MemoryScope.global,
      updatedAt: DateTime.now().toUtc(),
    );
    all[index] = updated;
    await writeAll(all);
    return updated;
  }

  Future<bool> archive(String id) async {
    final all = await readAll();
    final index = all.indexWhere((entry) => entry.id == id);
    if (index == -1) return false;
    if (all[index].status != MemoryStatus.archived) {
      all[index] = all[index].copyWith(
        status: MemoryStatus.archived,
        updatedAt: DateTime.now().toUtc(),
      );
    }
    _stripReverseRelatedIds(all, id);
    await writeAll(all);
    return true;
  }

  Future<bool> restore(String id) async {
    final all = await readAll();
    final index = all.indexWhere((entry) => entry.id == id);
    if (index == -1) return false;
    if (all[index].status == MemoryStatus.active) return true;
    all[index] = all[index].copyWith(
      status: MemoryStatus.active,
      updatedAt: DateTime.now().toUtc(),
    );
    await writeAll(all);
    return true;
  }

  Future<bool> hardDelete(String id) async {
    final all = await readAll();
    final before = all.length;
    all.removeWhere((entry) => entry.id == id);
    if (all.length == before) return false;
    _stripReverseRelatedIds(all, id);
    await writeAll(all);
    return true;
  }

  Future<int> hardDeleteMany(List<String> ids) async {
    if (ids.isEmpty) return 0;
    final remove = ids.toSet();
    final all = await readAll();
    final before = all.length;
    all.removeWhere((entry) => remove.contains(entry.id));
    final deleted = before - all.length;
    if (deleted == 0) return 0;
    for (final id in remove) {
      _stripReverseRelatedIds(all, id);
    }
    await writeAll(all);
    return deleted;
  }

  Future<void> linkBidirectional(String a, String b) async {
    if (a == b) return;
    final all = await readAll();
    final indexA = all.indexWhere((entry) => entry.id == a);
    final indexB = all.indexWhere((entry) => entry.id == b);
    if (indexA == -1 || indexB == -1) return;
    var changed = false;
    final entryA = all[indexA];
    final entryB = all[indexB];
    if (!entryA.relatedIds.contains(b)) {
      all[indexA] = entryA.copyWith(relatedIds: [...entryA.relatedIds, b]);
      changed = true;
    }
    if (!entryB.relatedIds.contains(a)) {
      all[indexB] = entryB.copyWith(relatedIds: [...entryB.relatedIds, a]);
      changed = true;
    }
    if (changed) await writeAll(all);
  }

  // ─── profile fields ────────────────────────────────────────────────────
  Future<void> putProfileField(
    String key,
    String value,
    MemorySource source,
  ) async {
    if (!UserProfileField.isValidKey(key)) {
      throw ArgumentError.value(key, 'key', 'Invalid profile field key');
    }
    final trimmed = value.trim();
    if (trimmed.isEmpty) {
      throw ArgumentError.value(
        value,
        'value',
        'Empty value clears a field; use removeProfileField',
      );
    }
    final fields = await readProfileFields();
    final index = fields.indexWhere((field) => field.key == key);
    final next = UserProfileField(
      key: key,
      value: trimmed,
      source: source,
      updatedAt: DateTime.now().toUtc(),
    );
    if (index == -1) {
      fields.add(next);
    } else {
      fields[index] = next;
    }
    await _writeProfileFields(fields);
  }

  Future<bool> removeProfileField(String key) async {
    final fields = await readProfileFields();
    final before = fields.length;
    fields.removeWhere((field) => field.key == key);
    if (fields.length == before) return false;
    await _writeProfileFields(fields);
    return true;
  }

  Future<List<UserProfileField>> readProfileFields() async {
    final raw = _prefs.getString(_profilesKey);
    if (raw == null || raw.isEmpty) return <UserProfileField>[];
    try {
      final decoded = jsonDecode(raw) as List<dynamic>;
      return [
        for (final item in decoded)
          UserProfileField.fromPayload((item as Map).cast<String, dynamic>()),
      ];
    } catch (_) {
      return <UserProfileField>[];
    }
  }

  Future<void> _writeProfileFields(List<UserProfileField> fields) async {
    await _prefs.setString(
      _profilesKey,
      jsonEncode(fields.map((field) => field.toPayload()).toList()),
    );
  }

  // ─── queries (master-compatible contract) ─────────────────────────────
  /// OR token search: entries whose content contains any escaped token.
  /// Filters: visibility (active + scope rule), optional assistantId and type.
  Future<List<MemoryEntry>> searchMemories({
    required String? assistantId,
    required List<String> tokens,
    MemoryType? type,
    bool matchAll = false,
    int limit = 5,
  }) async {
    final all = await readAll();
    if (tokens.isEmpty) return const <MemoryEntry>[];
    final visible =
        all.where((e) => _isVisible(e, visibilityAssistantId: assistantId))
            .toList();
    if (type != null) {
      visible.removeWhere((e) => e.type != type);
    }
    final scored = <(MemoryEntry, int)>[];
    for (final e in visible) {
      final lower = e.content.toLowerCase();
      var hits = 0;
      var matchedAll = true;
      for (final t in tokens) {
        final needle = t
            .replaceAll(r'\%', '%')
            .replaceAll(r'\_', '_')
            .replaceAll(r'\\', r'\');
        if (lower.contains(needle)) {
          hits++;
        } else {
          matchedAll = false;
        }
      }
      if (matchAll && !matchedAll) continue;
      if (hits == 0) continue;
      scored.add((e, hits));
    }
    scored.sort((a, b) {
      final byHits = b.$2.compareTo(a.$2);
      if (byHits != 0) return byHits;
      final byUpdated = b.$1.updatedAt.compareTo(a.$1.updatedAt);
      if (byUpdated != 0) return byUpdated;
      return a.$1.id.compareTo(b.$1.id);
    });
    return [for (final s in scored) s.$1].take(limit).toList();
  }
  /// Active entries visible to [visibilityAssistantId] (global + own assistant).
  Future<List<MemoryEntry>> queryVisibleMemories({
    String? assistantId,
    MemoryType? type,
    bool includeArchived = false,
  }) async {
    final all = await readAll();
    final out = all.where((e) {
      if (!includeArchived && e.status != MemoryStatus.active) return false;
      if (e.scope == MemoryScope.global) return true;
      if (e.scope == MemoryScope.assistant &&
          e.assistantId == assistantId) {
        return true;
      }
      return false;
    }).toList();
    if (type != null) out.removeWhere((e) => e.type != type);
    return out;
  }
  /// Active visible entries count grouped by [MemoryType] (§12.5).
  Future<Map<MemoryType, int>> countVisibleMemoriesByType({
    String? assistantId,
  }) async {
    final result = <MemoryType, int>{
      for (final t in MemoryType.values) t: 0,
    };
    final visible = await queryVisibleMemories(assistantId: assistantId);
    for (final e in visible) {
      result[e.type] = (result[e.type] ?? 0) + 1;
    }
    return result;
  }
  /// Exact normalized-content match within visible entries of [type].
  Future<MemoryEntry?> findExactMemory({
    required String? assistantId,
    required MemoryType type,
    required String contentNormalized,
  }) async {
    final all = await readAll();
    for (final e in all) {
      if (e.status != MemoryStatus.active) continue;
      if (e.type != type) continue;
      if (!_isVisible(e, visibilityAssistantId: assistantId)) continue;
      if (MemoryEntry.normalizeContent(e.content) == contentNormalized) {
        return e;
      }
    }
    return null;
  }
  /// Fetch entries by ids (missing ids ignored).
  Future<List<MemoryEntry>> memoriesByIds(List<String> ids) async {
    if (ids.isEmpty) return const <MemoryEntry>[];
    final want = ids.toSet();
    final all = await readAll();
    return [for (final e in all) if (want.contains(e.id)) e];
  }
  static bool _isVisible(MemoryEntry e, {required String? visibilityAssistantId}) {
    if (e.status != MemoryStatus.active) return false;
    if (e.scope == MemoryScope.global) return true;
    if (e.scope == MemoryScope.assistant &&
        e.assistantId == visibilityAssistantId) {
      return true;
    }
    return false;
  }
  // ─── helpers ───────────────────────────────────────────────────────────
  static void _validateScope(MemoryScope scope, String? assistantId) {
    if (scope == MemoryScope.global && assistantId != null) {
      throw ArgumentError.value(
        assistantId,
        'assistantId',
        'Must be null when scope is global',
      );
    }
    if (scope == MemoryScope.assistant &&
        (assistantId == null || assistantId.isEmpty)) {
      throw ArgumentError.value(
        assistantId,
        'assistantId',
        'Required when scope is assistant',
      );
    }
  }

  static String _newUniqueId(Set<String> taken) {
    var id = MemoryEntry.newId();
    for (var attempt = 0; taken.contains(id) && attempt < 16; attempt++) {
      id = MemoryEntry.newId();
    }
    if (taken.contains(id)) throw StateError('memory_id_collision');
    return id;
  }

  static String _contentKey(
    MemoryScope scope,
    String? assistantId,
    String content,
  ) {
    return '${MemoryEntry.scopeToString(scope)}\u0000${assistantId ?? ''}\u0000'
        '${MemoryEntry.normalizeContent(content)}';
  }

  static void _stripReverseRelatedIds(List<MemoryEntry> all, String targetId) {
    for (var i = 0; i < all.length; i++) {
      final entry = all[i];
      if (!entry.relatedIds.contains(targetId)) continue;
      all[i] = entry.copyWith(
        relatedIds:
            entry.relatedIds.where((id) => id != targetId).toList(growable: false),
      );
    }
  }
}

class _ExclusiveGuard {}

class MemoryCreateDraft {
  const MemoryCreateDraft({
    required this.scope,
    this.assistantId,
    required this.type,
    required this.content,
    required this.source,
    this.relatedIds = const <String>[],
    this.migrationId,
  });

  final MemoryScope scope;
  final String? assistantId;
  final MemoryType type;
  final String content;
  final MemorySource source;
  final List<String> relatedIds;
  final String? migrationId;
}

class MemoryCreateManyResult {
  const MemoryCreateManyResult({required this.created, required this.skipped});

  final int created;
  final int skipped;
}