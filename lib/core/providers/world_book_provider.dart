import 'package:flutter/foundation.dart';

import '../models/world_book.dart';
import '../database/business_preferences.dart';
import '../services/world_book_store.dart';

class WorldBookProvider with ChangeNotifier {
  WorldBookProvider({BusinessPreferences? preferences})
    : _store = preferences != null
        ? WorldBookStore(preferences)
        : (_fallbackPreferences != null
            ? WorldBookStore(_fallbackPreferences!)
            : WorldBookStore.fallback());
  
  static BusinessPreferences? _fallbackPreferences;
  static void setFallbackPreferences(BusinessPreferences prefs) {
    _fallbackPreferences = prefs;
  }
  
  final WorldBookStore _store;
  List<WorldBook> _books = const <WorldBook>[];
  bool _initialized = false;
  Map<String, List<String>> _activeIdsByAssistant =
      const <String, List<String>>{};
  Map<String, bool> _collapsedBooks = const <String, bool>{};

  List<WorldBook> get books => List<WorldBook>.unmodifiable(_books);

  WorldBook? getById(String id) {
    try {
      return _books.firstWhere((e) => e.id == id);
    } catch (_) {
      return null;
    }
  }

  List<String> activeBookIdsFor(String? assistantId) {
    final key = WorldBookStore.assistantKey(assistantId);
    if (_activeIdsByAssistant.containsKey(key)) {
      return List<String>.unmodifiable(_activeIdsByAssistant[key]!);
    }
    final fallback =
        _activeIdsByAssistant[WorldBookStore.assistantKey(null)] ??
        const <String>[];
    return List<String>.unmodifiable(fallback);
  }

  bool isBookActive(String id, {String? assistantId}) =>
      activeBookIdsFor(assistantId).contains(id);

  bool isBookCollapsed(String id) => _collapsedBooks[id] ?? false;

  Future<void> initialize() async {
    if (_initialized) return;
    await loadAll();
    _initialized = true;
  }

  Future<void> loadAll() async {
    try {
      _books = await _store.getAll();
      _activeIdsByAssistant = await _store.getActiveIdsByAssistant();
      final collapsed = await _store.getCollapsedBooksMap();
      final knownIds = _books.map((e) => e.id).toSet();
      final cleanedCollapsed = <String, bool>{
        for (final entry in collapsed.entries)
          if (knownIds.contains(entry.key)) entry.key: entry.value,
      };
      _collapsedBooks = cleanedCollapsed;

      if (cleanedCollapsed.length != collapsed.length) {
        await _store.setCollapsedMap(cleanedCollapsed);
      }

      notifyListeners();
    } catch (e) {
      debugPrint('Failed to load world books: $e');
      _books = const <WorldBook>[];
      _activeIdsByAssistant = const <String, List<String>>{};
      _collapsedBooks = const <String, bool>{};
      notifyListeners();
    }
  }

  Future<void> addBook(WorldBook book) async {
    await _store.add(book);
    await loadAll();
  }

  Future<void> updateBook(WorldBook book) async {
    if (!book.enabled) {
      try {
        final map = await _store.getActiveIdsByAssistant();
        final next = <String, List<String>>{};
        bool changed = false;
        for (final entry in map.entries) {
          final filtered = entry.value
              .where((e) => e != book.id)
              .toList(growable: false);
          if (filtered.length != entry.value.length) changed = true;
          next[entry.key] = filtered;
        }
        if (changed) {
          await _store.setActiveIdsMap(next);
        }
      } catch (_) {}
    }
    await _store.update(book);
    await loadAll();
  }

  Future<void> deleteBook(String id) async {
    await _store.delete(id);
    await loadAll();
  }

  Future<void> clear() async {
    await _store.clear();
    _books = const <WorldBook>[];
    _activeIdsByAssistant = const <String, List<String>>{};
    _collapsedBooks = const <String, bool>{};
    notifyListeners();
  }

  Future<void> reorderBooks({
    required int oldIndex,
    required int newIndex,
  }) async {
    if (_books.isEmpty) return;
    if (oldIndex < 0 || oldIndex >= _books.length) return;
    if (newIndex < 0 || newIndex >= _books.length) return;
    final list = List<WorldBook>.from(_books);
    final item = list.removeAt(oldIndex);
    list.insert(newIndex, item);
    _books = list;
    notifyListeners();
    await _store.save(_books);
  }

  Future<void> reorderEntries({
    required String bookId,
    required int oldIndex,
    required int newIndex,
  }) async {
    final bookIndex = _books.indexWhere((e) => e.id == bookId);
    if (bookIndex == -1) return;
    final book = _books[bookIndex];
    final entries = List<WorldBookEntry>.from(book.entries);
    if (entries.isEmpty) return;
    if (oldIndex < 0 || oldIndex >= entries.length) return;
    if (newIndex < 0 || newIndex >= entries.length) return;
    final item = entries.removeAt(oldIndex);
    entries.insert(newIndex, item);
    final nextBook = book.copyWith(entries: entries);
    final nextBooks = List<WorldBook>.from(_books);
    nextBooks[bookIndex] = nextBook;
    _books = nextBooks;
    notifyListeners();
    await _store.save(_books);
  }

  Future<void> setBookCollapsed(String id, bool collapsed) async {
    final key = id.trim();
    if (key.isEmpty) return;

    final next = Map<String, bool>.from(_collapsedBooks);
    next[key] = collapsed;
    _collapsedBooks = next;
    notifyListeners();
    await _store.setCollapsed(key, collapsed);
  }

  Future<void> toggleBookCollapsed(String id) async {
    await setBookCollapsed(id, !isBookCollapsed(id));
  }

  Future<void> setActiveBookIds(List<String> ids, {String? assistantId}) async {
    final key = WorldBookStore.assistantKey(assistantId);
    final nextMap = Map<String, List<String>>.from(_activeIdsByAssistant);
    nextMap[key] = ids.toSet().toList(growable: false);
    _activeIdsByAssistant = nextMap;
    notifyListeners();
    await _store.setActiveIds(ids, assistantId: assistantId);
  }

  Future<void> toggleActiveBookId(String id, {String? assistantId}) async {
    final set = activeBookIdsFor(assistantId).toSet();
    if (set.contains(id)) {
      set.remove(id);
    } else {
      final book = getById(id);
      if (book == null) return;
      if (!book.enabled) return;
      set.add(id);
    }
    await setActiveBookIds(
      set.toList(growable: false),
      assistantId: assistantId,
    );
  }

  /// 按 Agent 已激活的知识书和任务主题返回少量相关条目。
  List<Map<String, dynamic>> retrieveActiveEntries({
    required String? assistantId,
    required List<String> topics,
    int limit = 3,
  }) {
    const genericTopics = <String>{
      'apk', '工作流', 'workflow', '规则', 'rules',
      '工具', '定位', '分析', '验证', '文件',
    };
    final normalizedTopics = topics
        .map((topic) => topic.trim().toLowerCase())
        .where((topic) => topic.isNotEmpty && !genericTopics.contains(topic))
        .toSet();
    if (limit <= 0) return const <Map<String, dynamic>>[];
    final activeIds = activeBookIdsFor(assistantId).toSet();
    final candidates = <Map<String, dynamic>>[];
    for (final book in _books) {
      if (!book.enabled || !activeIds.contains(book.id)) continue;
      for (final entry in book.entries) {
        if (!entry.enabled || entry.content.trim().isEmpty) continue;
        final name = entry.name.toLowerCase();
        final content = entry.content.toLowerCase();
        final keywords = entry.keywords
            .map((keyword) => keyword.trim().toLowerCase())
            .where((keyword) => keyword.isNotEmpty)
            .toList(growable: false);
        var score = 0;
        if (entry.constantActive) score += 1;
        for (final topic in normalizedTopics) {
          if (name.contains(topic)) score += 8;
          if (content.contains(topic)) score += 2;
          for (final keyword in keywords) {
            if (keyword.contains(topic) || topic.contains(keyword)) score += 6;
          }
        }
        if (score == 0) continue;
        candidates.add({
          'bookId': book.id,
          'bookName': book.name,
          'entryId': entry.id,
          'entryName': entry.name,
          'priority': entry.priority,
          'constantActive': entry.constantActive,
          'score': score,
          'content': entry.content,
        });
      }
    }
    candidates.sort((a, b) {
      final alwaysOrder = ((b['constantActive'] as bool) ? 1 : 0).compareTo(
        (a['constantActive'] as bool) ? 1 : 0,
      );
      if (alwaysOrder != 0) return alwaysOrder;
      final scoreOrder = (b['score'] as int).compareTo(a['score'] as int);
      if (scoreOrder != 0) return scoreOrder;
      return (b['priority'] as int).compareTo(a['priority'] as int);
    });
    return candidates.take(limit.clamp(1, 5).toInt()).toList(growable: false);
  }
}
