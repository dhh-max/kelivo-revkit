import 'package:flutter/foundation.dart';

import '../database/chat_database_repository.dart';
import '../models/memory_entry.dart';
import '../models/user_profile_field.dart';
import '../services/memory/memory_repository.dart';

/// UI-facing ChangeNotifier for memory system V1 (§13.7).
///
/// Intentionally not named [MemoryProvider] — that class remains the legacy
/// read-only store for §14.5. Mixing the two via `context.read` would silently
/// wire the wrong system.
class MemoryProviderV2 extends ChangeNotifier {
  MemoryProviderV2({required this.repository, required this.chatRepository});

  final MemoryRepository repository;
  final ChatDatabaseRepository chatRepository;

  List<MemoryEntry> _entries = const <MemoryEntry>[];
  List<UserProfileField> _profileFields = const <UserProfileField>[];
  int _orphanCount = 0;
  String? _focusAssistantId;
  bool _loadAll = false;
  bool _initialized = false;
  Future<void>? _initializationFuture;

  /// Full cached entry list from the last [refresh] / [refreshAll].
  List<MemoryEntry> get entries => List<MemoryEntry>.unmodifiable(_entries);

  List<UserProfileField> get profileFields =>
      List<UserProfileField>.unmodifiable(_profileFields);

  int get orphanCount => _orphanCount;

  /// Active memories visible for [assistantId] (global ∪ assistant).
  List<MemoryEntry> visibleFor(String? assistantId) {
    return _entries
        .where(
          (entry) =>
              entry.status == MemoryStatus.active &&
              _isVisible(entry, assistantId),
        )
        .toList(growable: false);
  }

  /// Archived memories visible for [assistantId] (global ∪ assistant).
  List<MemoryEntry> archivedFor(String? assistantId) {
    return _entries
        .where(
          (entry) =>
              entry.status == MemoryStatus.archived &&
              _isVisible(entry, assistantId),
        )
        .toList(growable: false);
  }

  Future<void> initialize({String? assistantId, bool loadAll = false}) {
    if (_initialized &&
        assistantId == _focusAssistantId &&
        loadAll == _loadAll) {
      return Future<void>.value();
    }
    return _initializationFuture ??= _initialize(
      assistantId: assistantId,
      loadAll: loadAll,
    );
  }

  Future<void> _initialize({String? assistantId, bool loadAll = false}) async {
    try {
      await refresh(assistantId: assistantId, loadAll: loadAll);
      _initialized = true;
    } finally {
      _initializationFuture = null;
    }
  }

  /// Reloads caches from the typed-column read path (§13.1 / §13.3).
  ///
  /// Pass [assistantId] to include that assistant's scoped entries alongside
  /// globals. `null` loads globals only unless [loadAll] is true.
  Future<void> refresh({String? assistantId, bool loadAll = false}) async {
    _focusAssistantId = assistantId;
    _loadAll = loadAll;
    try {
      final entries = loadAll
          ? await chatRepository.queryAllMemories(includeArchived: true)
          : await chatRepository.queryVisibleMemories(
              assistantId: assistantId,
              includeArchived: true,
            );
      final profile = await chatRepository.readProfileFields();
      final orphans = await chatRepository.countOrphanAssistantMemories();
      _entries = entries;
      _profileFields = profile;
      _orphanCount = orphans;
      notifyListeners();
    } catch (e) {
      debugPrint('MemoryProviderV2.refresh failed: $e');
      _entries = const <MemoryEntry>[];
      _profileFields = const <UserProfileField>[];
      _orphanCount = 0;
      notifyListeners();
    }
  }

  /// Convenience for the global management UI (§14.4).
  Future<void> refreshAll() => refresh(loadAll: true);

  /// Re-read without changing which entries the UI is currently showing.
  ///
  /// Background work has no business narrowing the visible set: it knows which
  /// assistant it ran for, but the user may be looking at every assistant, and
  /// passing that id to [refresh] would make the other entries vanish until the
  /// page is reopened.
  Future<void> reloadCurrentScope() =>
      refresh(assistantId: _focusAssistantId, loadAll: _loadAll);

  /// Search via §5.9 token AND. When [acrossAll] is true, searches every
  /// assistant; otherwise respects [assistantId] visibility.
  Future<List<MemoryEntry>> search({
    required List<String> tokens,
    String? assistantId,
    bool acrossAll = false,
    MemoryType? type,
    bool includeArchived = false,
    int limit = 200,
  }) {
    if (acrossAll) {
      return chatRepository.searchAllMemories(
        tokens: tokens,
        type: type,
        includeArchived: includeArchived,
        limit: limit,
      );
    }
    return chatRepository.searchMemories(
      assistantId: assistantId,
      tokens: tokens,
      type: type,
      matchAll: true,
      limit: limit,
    );
  }

  Future<MemoryEntry> create({
    required MemoryScope scope,
    String? assistantId,
    required MemoryType type,
    required String content,
    required MemorySource source,
    List<String> relatedIds = const [],
    /// 显式项目（工作区）标记：null = 按当前环境态项目打标（旧行为）。
    /// UI 手动新建时传用户正在看的工作区，避免写到「上一次生成」的工作区。
    String? projectId,
  }) async {
    final entry = await repository.create(
      scope: scope,
      assistantId: assistantId,
      type: type,
      content: content,
      source: source,
      relatedIds: relatedIds,
      extraJson: projectId == null
          ? null
          : <String, dynamic>{'projectId': projectId},
    );
    await _refreshAfterWrite();
    return entry;
  }

  Future<MemoryEntry?> updateContent(String id, String content) async {
    final entry = await repository.updateContent(id, content);
    await _refreshAfterWrite();
    return entry;
  }

  Future<MemoryEntry?> updateType(String id, MemoryType type) async {
    final entry = await repository.updateType(id, type);
    await _refreshAfterWrite();
    return entry;
  }

  Future<MemoryEntry?> updateScope(
    String id, {
    required MemoryScope scope,
    String? assistantId,
  }) async {
    final entry = await repository.updateScope(
      id,
      scope: scope,
      assistantId: assistantId,
    );
    await _refreshAfterWrite();
    return entry;
  }

  Future<bool> archive(String id) async {
    final ok = await repository.archive(id);
    await _refreshAfterWrite();
    return ok;
  }

  Future<bool> restore(String id) async {
    final ok = await repository.restore(id);
    await _refreshAfterWrite();
    return ok;
  }

  Future<bool> hardDelete(String id) async {
    final ok = await repository.hardDelete(id);
    await _refreshAfterWrite();
    return ok;
  }

  Future<int> hardDeleteMany(List<String> ids) async {
    final count = await repository.hardDeleteMany(ids);
    await _refreshAfterWrite();
    return count;
  }

  Future<void> linkBidirectional(String a, String b) async {
    await repository.linkBidirectional(a, b);
    await _refreshAfterWrite();
  }

  Future<int> deleteOrphanAssistantMemories() async {
    final count = await repository.deleteOrphanAssistantMemories();
    await _refreshAfterWrite();
    return count;
  }

  /// 孤儿项目记忆（工作区已删除）：[liveProjectIds] = 现存工作区 id 全集。
  ///
  /// 需要调用方给「现存工作区」而不是反过来查 provider：记忆层不依赖工作区层
  /// （core/services/memory 不该反向依赖 workspace provider）。
  List<MemoryEntry> orphanProjectEntries(Set<String> liveProjectIds) =>
      MemoryRepository.orphanProjectEntries(_entries, liveProjectIds);

  Future<int> deleteOrphanProjectMemories(Set<String> liveProjectIds) async {
    final count = await repository.deleteOrphanProjectMemories(liveProjectIds);
    await _refreshAfterWrite();
    return count;
  }

  /// 删除某个工作区的全部项目记忆（删工作区时用户选择「一并删除」）。
  Future<int> deleteProjectMemories(String projectId) async {
    final all = await repository.readAll();
    final ids = <String>{
      for (final entry in all)
        if (entry.projectId == projectId) entry.id,
    };
    final count = await repository.hardDeleteIds(ids);
    await _refreshAfterWrite();
    return count;
  }

  /// 交接：把某个工作区的记忆转为全局（[toProjectId] 为空）或迁移到别的工作区。
  Future<int> releaseProjectMemories(
    String projectId, {
    String? toProjectId,
  }) async {
    final count = await repository.releaseProjectMemories(
      projectId,
      toProjectId: toProjectId,
    );
    await _refreshAfterWrite();
    return count;
  }

  Future<void> putProfileField(
    String key,
    String value,
    MemorySource source,
  ) async {
    await repository.putProfileField(key, value, source);
    await _refreshAfterWrite();
  }

  Future<bool> removeProfileField(String key) async {
    final ok = await repository.removeProfileField(key);
    await _refreshAfterWrite();
    return ok;
  }

  Future<void> _refreshAfterWrite() => reloadCurrentScope();

  static bool _isVisible(MemoryEntry entry, String? assistantId) =>
      entry.isVisibleFor(assistantId);
}
