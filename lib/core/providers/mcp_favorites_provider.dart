import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// A saved parameter template for a specific tool.
class ToolParamTemplate {
  final String id;
  final String toolName;
  final String serverId;
  final String label;
  final Map<String, dynamic> params;
  final DateTime createdAt;

  const ToolParamTemplate({
    required this.id,
    required this.toolName,
    required this.serverId,
    required this.label,
    required this.params,
    required this.createdAt,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'toolName': toolName,
    'serverId': serverId,
    'label': label,
    'params': params,
    'createdAt': createdAt.toIso8601String(),
  };

  factory ToolParamTemplate.fromJson(Map<String, dynamic> json) =>
      ToolParamTemplate(
        id: json['id'] as String? ?? '',
        toolName: json['toolName'] as String? ?? '',
        serverId: json['serverId'] as String? ?? '',
        label: json['label'] as String? ?? '',
        params: (json['params'] as Map?)?.cast<String, dynamic>() ?? {},
        createdAt: DateTime.tryParse(json['createdAt'] as String? ?? '') ??
            DateTime.now(),
      );
}

/// Manages tool favorites and parameter templates.
class McpFavoritesProvider extends ChangeNotifier {
  static const String _favoritesKey = 'kelivo_mcp_tool_favorites_v1';
  static const String _templatesKey = 'kelivo_mcp_tool_templates_v1';

  /// Set of favorite tool identifiers (format: "serverId::toolName")
  Set<String> _favorites = {};

  /// Saved parameter templates
  List<ToolParamTemplate> _templates = [];

  Set<String> get favorites => Set.unmodifiable(_favorites);
  List<ToolParamTemplate> get templates => List.unmodifiable(_templates);

  McpFavoritesProvider() {
    _load();
  }

  bool isFavorite(String serverId, String toolName) =>
      _favorites.contains('$serverId::$toolName');

  Future<void> toggleFavorite(String serverId, String toolName) async {
    final key = '$serverId::$toolName';
    if (_favorites.contains(key)) {
      _favorites.remove(key);
    } else {
      _favorites.add(key);
    }
    notifyListeners();
    await _persist();
  }

  Future<void> addFavorite(String serverId, String toolName) async {
    final key = '$serverId::$toolName';
    if (_favorites.add(key)) {
      notifyListeners();
      await _persist();
    }
  }

  Future<void> removeFavorite(String serverId, String toolName) async {
    final key = '$serverId::$toolName';
    if (_favorites.remove(key)) {
      notifyListeners();
      await _persist();
    }
  }

  /// Get templates for a specific tool.
  List<ToolParamTemplate> templatesForTool(String serverId, String toolName) =>
      _templates
          .where((t) => t.serverId == serverId && t.toolName == toolName)
          .toList();

  Future<void> addTemplate(ToolParamTemplate template) async {
    _templates.insert(0, template);
    notifyListeners();
    await _persist();
  }

  Future<void> removeTemplate(String id) async {
    _templates.removeWhere((t) => t.id == id);
    notifyListeners();
    await _persist();
  }

  Future<void> updateTemplate(String id, {String? label, Map<String, dynamic>? params}) async {
    final idx = _templates.indexWhere((t) => t.id == id);
    if (idx == -1) return;
    final old = _templates[idx];
    _templates[idx] = ToolParamTemplate(
      id: old.id,
      toolName: old.toolName,
      serverId: old.serverId,
      label: label ?? old.label,
      params: params ?? old.params,
      createdAt: old.createdAt,
    );
    notifyListeners();
    await _persist();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    // Favorites
    final favRaw = prefs.getStringList(_favoritesKey);
    if (favRaw != null) {
      _favorites = favRaw.toSet();
    }
    // Templates
    final tplRaw = prefs.getString(_templatesKey);
    if (tplRaw != null && tplRaw.isNotEmpty) {
      try {
        final list = jsonDecode(tplRaw) as List;
        _templates = list
            .map((e) => ToolParamTemplate.fromJson(e as Map<String, dynamic>))
            .toList();
      } catch (_) {}
    }
    notifyListeners();
  }

  Future<void> _persist() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setStringList(_favoritesKey, _favorites.toList());
    await prefs.setString(
      _templatesKey,
      jsonEncode(_templates.map((t) => t.toJson()).toList()),
    );
  }
}
