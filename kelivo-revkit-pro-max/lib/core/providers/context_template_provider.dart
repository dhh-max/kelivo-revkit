import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';
import '../models/context_template.dart';

/// 上下文模板Provider
///
/// 管理上下文模板的增删改查，支持内置模板和用户自定义模板。
class ContextTemplateProvider extends ChangeNotifier {
  static const String _prefsKey = 'context_templates_v1';

  List<ContextTemplate> _templates = [];
  bool _initialized = false;

  bool get initialized => _initialized;
  List<ContextTemplate> get templates => List.unmodifiable(_templates);
  List<ContextTemplate> get userTemplates =>
      _templates.where((t) => !t.isBuiltin).toList(growable: false);
  List<ContextTemplate> get builtinTemplates =>
      _templates.where((t) => t.isBuiltin).toList(growable: false);

  ContextTemplateProvider();

  Future<void> init() async {
    if (_initialized) return;
    await _load();
    _initialized = true;
    notifyListeners();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_prefsKey);

    final List<ContextTemplate> loaded = [];

    // 先加载内置模板
    loaded.addAll(ContextTemplate.builtinTemplates);

    // 再加载用户自定义模板
    if (raw != null && raw.isNotEmpty) {
      try {
        final userTemplates = ContextTemplate.decodeList(raw);
        loaded.addAll(userTemplates);
      } catch (_) {}
    }

    _templates = loaded;
  }

  Future<void> _persistUserTemplates() async {
    final prefs = await SharedPreferences.getInstance();
    final userTemplates = _templates.where((t) => !t.isBuiltin).toList();
    await prefs.setString(_prefsKey, ContextTemplate.encodeList(userTemplates));
  }

  /// 获取模板通过ID
  ContextTemplate? getById(String id) {
    for (final t in _templates) {
      if (t.id == id) return t;
    }
    return null;
  }

  /// 搜索模板
  List<ContextTemplate> search(String query) {
    final q = query.trim().toLowerCase();
    if (q.isEmpty) return List.unmodifiable(_templates);

    return _templates.where((t) {
      return t.name.toLowerCase().contains(q) ||
          t.description.toLowerCase().contains(q) ||
          t.tags.any((tag) => tag.toLowerCase().contains(q));
    }).toList(growable: false);
  }

  /// 添加用户自定义模板
  Future<String> addTemplate({
    required String name,
    String description = '',
    String systemPrompt = '',
    List<String> presetMessages = const [],
    List<String> tags = const [],
  }) async {
    final id = const Uuid().v4();
    final now = DateTime.now();
    final template = ContextTemplate(
      id: id,
      name: name.trim(),
      description: description.trim(),
      systemPrompt: systemPrompt,
      presetMessages: List.of(presetMessages),
      tags: List.of(tags),
      createdAt: now,
      updatedAt: now,
      isBuiltin: false,
    );

    _templates = [..._templates, template];
    await _persistUserTemplates();
    notifyListeners();
    return id;
  }

  /// 更新模板
  Future<void> updateTemplate(ContextTemplate updated) async {
    if (updated.isBuiltin) return; // 不能修改内置模板

    final idx = _templates.indexWhere((t) => t.id == updated.id);
    if (idx < 0) return;

    final newTemplate = updated.copyWith(updatedAt: DateTime.now());
    _templates = List.of(_templates)..[idx] = newTemplate;
    await _persistUserTemplates();
    notifyListeners();
  }

  /// 删除模板
  Future<void> deleteTemplate(String id) async {
    final template = getById(id);
    if (template == null || template.isBuiltin) return; // 不能删除内置模板

    _templates = _templates.where((t) => t.id != id).toList(growable: false);
    await _persistUserTemplates();
    notifyListeners();
  }

  /// 复制模板（基于现有模板创建新的用户模板）
  Future<String> duplicateTemplate(String sourceId, {String? newName}) async {
    final source = getById(sourceId);
    if (source == null) {
      throw StateError('Template not found: $sourceId');
    }

    final name = newName ?? '${source.name} (副本)';
    return addTemplate(
      name: name,
      description: source.description,
      systemPrompt: source.systemPrompt,
      presetMessages: List.of(source.presetMessages),
      tags: List.of(source.tags),
    );
  }

  /// 导出模板为JSON
  String exportTemplates(List<String> templateIds) {
    final selected = templateIds
        .map((id) => getById(id))
        .whereType<ContextTemplate>()
        .toList();

    return ContextTemplate.encodeList(selected);
  }

  /// 从JSON导入模板
  Future<int> importTemplates(String jsonStr) async {
    try {
      final imported = ContextTemplate.decodeList(jsonStr);
      if (imported.isEmpty) return 0;

      var count = 0;
      for (final template in imported) {
        // 导入的模板都作为用户模板，重置ID避免冲突
        await addTemplate(
          name: template.name,
          description: template.description,
          systemPrompt: template.systemPrompt,
          presetMessages: List.of(template.presetMessages),
          tags: List.of(template.tags),
        );
        count++;
      }

      return count;
    } catch (_) {
      return 0;
    }
  }
}
