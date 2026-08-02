import 'package:flutter/foundation.dart';
import '../models/custom_prompt.dart';
import '../services/custom_prompt_store.dart';

/// Provider for managing user-defined custom prompts.
class CustomPromptProvider with ChangeNotifier {
  List<CustomPrompt> _prompts = [];
  bool _initialized = false;
  String _searchQuery = '';

  List<CustomPrompt> get prompts => List.unmodifiable(_prompts);

  List<CustomPrompt> get favorites =>
      _prompts.where((p) => p.isFavorite).toList();

  String get searchQuery => _searchQuery;

  /// Get prompts filtered by current search query.
  List<CustomPrompt> get filteredPrompts {
    if (_searchQuery.isEmpty) return prompts;
    final q = _searchQuery.toLowerCase();
    return _prompts.where((p) {
      return p.title.toLowerCase().contains(q) ||
          p.content.toLowerCase().contains(q) ||
          (p.description?.toLowerCase().contains(q) ?? false) ||
          p.tags.any((t) => t.toLowerCase().contains(q));
    }).toList();
  }

  /// Get prompts by tag.
  List<CustomPrompt> getByTag(String tag) =>
      _prompts.where((p) => p.tags.contains(tag)).toList();

  /// Get all unique tags.
  List<String> get allTags {
    final tags = <String>{};
    for (final p in _prompts) {
      tags.addAll(p.tags);
    }
    return tags.toList()..sort();
  }

  Future<void> initialize() async {
    if (_initialized) return;
    await loadAll();
    _initialized = true;
  }

  Future<void> loadAll() async {
    try {
      _prompts = await CustomPromptStore.getAll();
      notifyListeners();
    } catch (e) {
      debugPrint('Failed to load custom prompts: $e');
      _prompts = [];
      notifyListeners();
    }
  }

  void setSearchQuery(String query) {
    _searchQuery = query;
    notifyListeners();
  }

  Future<void> add(CustomPrompt prompt) async {
    await CustomPromptStore.add(prompt);
    _prompts.add(prompt);
    notifyListeners();
  }

  Future<void> update(CustomPrompt prompt) async {
    final updated = prompt.copyWith(updatedAt: DateTime.now());
    await CustomPromptStore.update(updated);
    final idx = _prompts.indexWhere((p) => p.id == updated.id);
    if (idx >= 0) {
      _prompts[idx] = updated;
      notifyListeners();
    }
  }

  Future<void> delete(String id) async {
    await CustomPromptStore.delete(id);
    _prompts.removeWhere((p) => p.id == id);
    notifyListeners();
  }

  Future<void> toggleFavorite(String id) async {
    final idx = _prompts.indexWhere((p) => p.id == id);
    if (idx < 0) return;
    final updated = _prompts[idx].copyWith(
      isFavorite: !_prompts[idx].isFavorite,
      updatedAt: DateTime.now(),
    );
    await CustomPromptStore.update(updated);
    _prompts[idx] = updated;
    notifyListeners();
  }

  Future<void> reorder(int oldIndex, int newIndex) async {
    if (oldIndex == newIndex) return;
    final item = _prompts.removeAt(oldIndex);
    _prompts.insert(newIndex > oldIndex ? newIndex - 1 : newIndex, item);
    await CustomPromptStore.saveAll(_prompts);
    notifyListeners();
  }

  Future<void> clear() async {
    await CustomPromptStore.clear();
    _prompts = [];
    notifyListeners();
  }

  /// Import prompts from JSON list (for backup/restore).
  Future<int> importFromJson(List<dynamic> jsonList) async {
    int imported = 0;
    for (final item in jsonList) {
      if (item is Map<String, dynamic>) {
        try {
          final prompt = CustomPrompt.fromJson(item);
          // Skip duplicates by ID
          if (!_prompts.any((p) => p.id == prompt.id)) {
            _prompts.add(prompt);
            imported++;
          }
        } catch (_) {}
      }
    }
    if (imported > 0) {
      await CustomPromptStore.saveAll(_prompts);
      notifyListeners();
    }
    return imported;
  }

  /// Export all prompts as JSON-encodable list.
  List<Map<String, dynamic>> exportAsJson() =>
      _prompts.map((p) => p.toJson()).toList();
}