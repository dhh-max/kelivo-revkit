import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';
import '../../utils/sandbox_path_resolver.dart';
import '../models/assistant.dart';
import '../models/assistant_regex.dart';
import '../models/preset_message.dart';
import '../services/chat/chat_service.dart';
import '../../l10n/app_localizations.dart';
import '../../utils/avatar_cache.dart';
import '../../utils/app_directories.dart';

class AssistantProvider extends ChangeNotifier {
  static const String _assistantsKey = 'assistants_v1';
  static const String _currentAssistantKey = 'current_assistant_id_v1';
  static const String _legacySearchEnabledKey = 'search_enabled_v1';

  final List<Assistant> _assistants = <Assistant>[];
  String? _currentAssistantId;
  final ChatService? chatService;

  List<Assistant> get assistants => List.unmodifiable(_assistants);
  String? get currentAssistantId => _currentAssistantId;
  Assistant? get currentAssistant {
    final idx = _assistants.indexWhere((a) => a.id == _currentAssistantId);
    if (idx != -1) return _assistants[idx];
    if (_assistants.isNotEmpty) return _assistants.first;
    return null;
  }

  bool get currentSearchEnabled => currentAssistant?.searchEnabled ?? false;

  AssistantProvider({this.chatService}) {
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_assistantsKey);
    if (raw != null && raw.isNotEmpty) {
      final legacySearchEnabled = prefs.getBool(_legacySearchEnabledKey);
      final migrated = _decodeAssistantsWithLegacySearch(
        raw,
        legacySearchEnabled: legacySearchEnabled,
      );
      bool migratedSearchEnabled = false;
      _assistants
        ..clear()
        ..addAll(migrated.assistants);
      migratedSearchEnabled = migrated.didApplyLegacySearch;
      // Fix any sandboxed local paths (avatars/backgrounds) imported from other platforms
      bool changed = migratedSearchEnabled;
      for (int i = 0; i < _assistants.length; i++) {
        final a = _assistants[i];
        String? av = a.avatar;
        String? bg = a.background;
        if (av != null &&
            av.isNotEmpty &&
            (av.startsWith('/') || av.contains(':')) &&
            !av.startsWith('http')) {
          final fixed = SandboxPathResolver.fix(av);
          if (fixed != av) {
            av = fixed;
            changed = true;
          }
        }
        if (bg != null &&
            bg.isNotEmpty &&
            (bg.startsWith('/') || bg.contains(':')) &&
            !bg.startsWith('http')) {
          final fixedBg = SandboxPathResolver.fix(bg);
          if (fixedBg != bg) {
            bg = fixedBg;
            changed = true;
          }
        }
        if (changed) {
          _assistants[i] = a.copyWith(avatar: av, background: bg);
        }
      }
      if (changed) {
        try {
          await _persist();
        } catch (_) {}
      }
    }
    // Do not create defaults here because localization is not available.
    // Defaults will be ensured later via ensureDefaults(context).
    // Restore current assistant if present
    final savedId = prefs.getString(_currentAssistantKey);
    if (savedId != null && _assistants.any((a) => a.id == savedId)) {
      _currentAssistantId = savedId;
    } else {
      _currentAssistantId = null;
    }
    notifyListeners();
  }

  _AssistantDecodeResult _decodeAssistantsWithLegacySearch(
    String raw, {
    required bool? legacySearchEnabled,
  }) {
    try {
      final decoded = jsonDecode(raw) as List<dynamic>;
      bool didApplyLegacySearch = false;
      final assistants = [
        for (final e in decoded)
          if (e is Map)
            (() {
              final json = e.cast<String, dynamic>();
              if (legacySearchEnabled != null &&
                  !json.containsKey('searchEnabled')) {
                json['searchEnabled'] = legacySearchEnabled;
                didApplyLegacySearch = true;
              }
              return Assistant.fromJson(json);
            })(),
      ];
      return _AssistantDecodeResult(
        assistants: assistants,
        didApplyLegacySearch: didApplyLegacySearch,
      );
    } catch (_) {
      return const _AssistantDecodeResult(
        assistants: <Assistant>[],
        didApplyLegacySearch: false,
      );
    }
  }

  /// 内置输出限制规则：剥离 AI 常见开场白、结尾套话与英文 filler。
  /// persist 模式（visualOnly=false, replaceOnly=false）——
  /// 在消息存储时即生效，后续展示和发送均使用已过滤版本。
  static List<AssistantRegex> _builtinOutputFilterRules() => <AssistantRegex>[
    AssistantRegex(
      id: 'builtin-no-filler-open-zh',
      name: '开场白过滤',
      pattern: r'(?m)^(好的[，。、！]\s*(?:我来|让我)[^\n]*|当然可以[，。！]?\s*$|当然可以[，。！]\s*(?:我来|让我)[^\n]*|当然[，。！]\s*(?:我来|让我|可以)[^\n]*|没问题[，。！]?\s*$|让我来[帮为你][^\n]*|我来帮[^\n]*)$\n?',
      replacement: '',
      scopes: const <AssistantRegexScope>[AssistantRegexScope.assistant],
      enabled: true,
    ),
    AssistantRegex(
      id: 'builtin-no-filler-close-zh',
      name: '结尾套话过滤',
      pattern: r'(?m)^(希望[对这能][^\n]{0,30}有帮助[^\n]{0,20}|如果你还[^\n]{0,40}问题[^\n]{0,30}|以上就是[^\n]{0,40}(?:内容|全部内容)[。！]?|如有[^\n]{0,30}疑问[^\n]{0,30})$\n?',
      replacement: '',
      scopes: const <AssistantRegexScope>[AssistantRegexScope.assistant],
      enabled: true,
    ),
    AssistantRegex(
      id: 'builtin-no-filler-en',
      name: 'English Filler Filter',
      pattern: r'''(?m)^(Sure[,!.][^\n]{0,60}|Of course[,!.]?\s*$|Of course[,!.]?\s*(?:I'll|let me)[^\n]{0,60}|Let me help[^\n]{0,60}|I hope this helps[^\n]{0,40})$\n?''',
      replacement: '',
      scopes: const <AssistantRegexScope>[AssistantRegexScope.assistant],
      enabled: true,
    ),
  ];

  Assistant _defaultAssistant(AppLocalizations l10n) => Assistant(
    id: const Uuid().v4(),
    name: l10n.assistantProviderDefaultAssistantName,
    systemPrompt:
        '直接输出最终结果，不展示中间推理、工具调用步骤、验证过程等任何中间过程。'
        '禁止输出与正文无关的内容：不要开场白、不要结尾套话、不要解释自己做了什么。'
        '用户要求什么，一步到位给出最终答案。',
    thinkingBudget: null,
    temperature: 0.6,
    topP: null,
    regexRules: _builtinOutputFilterRules(),
  );

  // Ensure localized default assistants exist; call this after localization is ready.
  Future<void> ensureDefaults(dynamic context) async {
    if (_assistants.isNotEmpty) return;
    final l10n = AppLocalizations.of(context)!;
    // 1) 默认助手
    _assistants.add(_defaultAssistant(l10n));
    // 2) 示例助手（带提示词模板）
    _assistants.add(
      Assistant(
        id: const Uuid().v4(),
        name: l10n.assistantProviderSampleAssistantName,
        systemPrompt: l10n.assistantProviderSampleAssistantSystemPrompt(
              '{model_name}',
            ) +
            '\n\n直接输出最终结果，不展示中间推理、工具调用步骤、验证过程等任何中间过程。'
            '禁止输出与正文无关的内容：不要开场白、不要结尾套话、不要解释自己做了什么。'
            '用户要求什么，一步到位给出最终答案。',
        temperature: 0.6,
        topP: null,
        regexRules: _builtinOutputFilterRules(),
      ),
    );
    // 3) 逆向分析师 — 绑定 @kelivo/reverse 聚合逆向 MCP
    _assistants.add(
      Assistant(
        id: const Uuid().v4(),
        name: (Localizations.localeOf(context).languageCode == 'zh')
            ? '逆向分析师'
            : 'Reverse Analyst',
        systemPrompt: (Localizations.localeOf(context).languageCode == 'zh')
            ? '你是一名专业的 Android 逆向分析工程师。你擅长：APK 结构分析、DEX/ODEX 字节码反编译、SO/ELF 原生库逆向、Manifest 权限与组件审计、JNI 接口分析、反混淆与加壳识别。请使用内置的 @kelivo/reverse 工具集进行系统化分析，并在回复中引用工具输出作为证据。\n\n直接输出最终结果，不展示中间推理、工具调用步骤、验证过程等任何中间过程。禁止输出与正文无关的内容：不要开场白、不要结尾套话、不要解释自己做了什么。用户要求什么，一步到位给出最终答案。'
            : 'You are a professional Android reverse engineering analyst. You excel at: APK structure analysis, DEX/ODEX bytecode decompilation, SO/ELF native library reverse engineering, Manifest permission and component auditing, JNI interface analysis, deobfuscation and packer identification. Use the built-in @kelivo/reverse toolset for systematic analysis and cite tool outputs as evidence in your responses.\n\nOutput the final result directly. Do not include intermediate reasoning, tool call steps, or verification processes. Do not output content unrelated to the main text: no opening pleasantries, no closing remarks, no explanations of what you did. Whatever the user asks, deliver the final answer in one step.',
        temperature: 0.3,
        topP: null,
        mcpServerIds: const [], // MCP 按需手动启用，不默认绑定
        regexRules: _builtinOutputFilterRules(),
      ),
    );
    await _persist();
    // Set current assistant if not set
    if (_currentAssistantId == null && _assistants.isNotEmpty) {
      _currentAssistantId = _assistants.first.id;
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_currentAssistantKey, _currentAssistantId!);
    }
    notifyListeners();
  }

  String _buildCopyName(Assistant source, AppLocalizations? l10n) {
    final suffix = (l10n?.assistantSettingsCopySuffix ?? 'Copy').trim();
    final baseName = source.name.trim().isEmpty
        ? (l10n?.assistantProviderNewAssistantName ?? 'Assistant')
        : source.name.trim();
    final existingNames = _assistants.map((a) => a.name).toSet();

    String candidate = suffix.isEmpty ? baseName : '$baseName $suffix';
    int counter = 2;
    while (existingNames.contains(candidate)) {
      final counterSuffix = suffix.isEmpty ? '$counter' : '$suffix $counter';
      candidate = '$baseName $counterSuffix';
      counter++;
    }
    return candidate;
  }

  Future<String?> _duplicateLocalFile(
    String? rawPath, {
    required bool isAvatar,
    required String newId,
  }) async {
    final raw = (rawPath ?? '').trim();
    if (raw.isEmpty) return rawPath;
    if (raw.startsWith('http') || raw.startsWith('data:')) return rawPath;
    final fixed = SandboxPathResolver.fix(raw);
    final src = File(fixed);
    if (!await src.exists()) return rawPath;

    try {
      final dir = isAvatar
          ? await AppDirectories.getAvatarsDirectory()
          : await AppDirectories.getImagesDirectory();
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }
      String ext = '';
      final dot = fixed.lastIndexOf('.');
      if (dot != -1 && dot < fixed.length - 1) {
        ext = fixed.substring(dot + 1).toLowerCase();
        if (ext.length > 6) ext = 'jpg';
      } else {
        ext = 'jpg';
      }
      final prefix = isAvatar ? 'assistant' : 'background';
      final dest = File(
        '${dir.path}/${prefix}_${newId}_${DateTime.now().millisecondsSinceEpoch}.$ext',
      );
      await src.copy(dest.path);
      return dest.path;
    } catch (_) {
      return rawPath;
    }
  }

  Future<void> _persist() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_assistantsKey, Assistant.encodeList(_assistants));
  }

  Future<void> setCurrentAssistant(String id) async {
    if (_currentAssistantId == id) return;
    _currentAssistantId = id;
    notifyListeners();
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_currentAssistantKey, id);
  }

  Assistant? getById(String id) {
    final idx = _assistants.indexWhere((a) => a.id == id);
    if (idx == -1) return null;
    return _assistants[idx];
  }

  // Lightweight accessor so callers don't depend on Assistant.presetMessages symbol
  List<Map<String, String>> getPresetMessagesForAssistant(String? assistantId) {
    Assistant? a;
    if (assistantId != null) {
      a = getById(assistantId);
    } else {
      a = currentAssistant;
    }
    if (a == null) return const <Map<String, String>>[];
    return [
      for (final m in a.presetMessages) {'role': m.role, 'content': m.content},
    ];
  }

  Future<String> addAssistant({String? name, dynamic context}) async {
    final a = Assistant(
      id: const Uuid().v4(),
      name:
          (name ??
          (context != null
              ? AppLocalizations.of(context)!.assistantProviderNewAssistantName
              : 'New Assistant')),
      systemPrompt:
          '直接输出最终结果，不展示中间推理、工具调用步骤、验证过程等任何中间过程。'
          '禁止输出与正文无关的内容：不要开场白、不要结尾套话、不要解释自己做了什么。'
          '用户要求什么，一步到位给出最终答案。',
      temperature: 0.6,
      topP: null,
      mcpServerIds: const [], // 默认不绑定任何 MCP，用户按需手动启用
      regexRules: _builtinOutputFilterRules(),
    );
    _assistants.add(a);
    await _persist();
    notifyListeners();
    return a.id;
  }

  Future<String?> duplicateAssistant(
    String id, {
    AppLocalizations? l10n,
  }) async {
    final idx = _assistants.indexWhere((a) => a.id == id);
    if (idx == -1) return null;
    final source = _assistants[idx];
    final newId = const Uuid().v4();

    final avatarCopy = await _duplicateLocalFile(
      source.avatar,
      isAvatar: true,
      newId: newId,
    );
    final backgroundCopy = await _duplicateLocalFile(
      source.background,
      isAvatar: false,
      newId: newId,
    );

    final copy = source.copyWith(
      id: newId,
      name: _buildCopyName(source, l10n),
      avatar: avatarCopy,
      background: backgroundCopy,
      mcpServerIds: List<String>.of(source.mcpServerIds),
      localToolIds: List<String>.of(source.localToolIds),
      skillIds: List<String>.of(source.skillIds),
      customHeaders: source.customHeaders
          .map((e) => Map<String, String>.from(e))
          .toList(),
      customBody: source.customBody
          .map((e) => Map<String, String>.from(e))
          .toList(),
      presetMessages: source.presetMessages
          .map((m) => PresetMessage(role: m.role, content: m.content))
          .toList(),
      regexRules: source.regexRules
          .map(
            (r) => AssistantRegex(
              id: const Uuid().v4(),
              name: r.name,
              pattern: r.pattern,
              replacement: r.replacement,
              scopes: List<AssistantRegexScope>.of(r.scopes),
              visualOnly: r.visualOnly,
              replaceOnly: r.replaceOnly,
              enabled: r.enabled,
            ),
          )
          .toList(),
    );

    _assistants.insert(idx + 1, copy);
    await _persist();
    notifyListeners();
    return copy.id;
  }

  Future<void> updateAssistant(Assistant updated) async {
    final idx = _assistants.indexWhere((a) => a.id == updated.id);
    if (idx == -1) return;

    var next = updated;

    // If avatar changed and is a local file path (from gallery/cache),
    // copy it to persistent Documents/avatars and store that path.
    try {
      final prev = _assistants[idx];
      final raw = (updated.avatar ?? '').trim();
      final prevRaw = (prev.avatar ?? '').trim();
      final changed = raw != prevRaw;
      final isLocalPath =
          raw.isNotEmpty &&
          (raw.startsWith('/') || raw.contains(':')) &&
          !raw.startsWith('http');
      // Skip if it's already under our avatars folder
      if (changed &&
          isLocalPath &&
          !raw.contains('/avatars/') &&
          !raw.contains('\\avatars\\')) {
        final fixedInput = SandboxPathResolver.fix(raw);
        final src = File(fixedInput);
        if (await src.exists()) {
          final avatarsDir = await AppDirectories.getAvatarsDirectory();
          if (!await avatarsDir.exists()) {
            await avatarsDir.create(recursive: true);
          }
          String ext = '';
          final dot = fixedInput.lastIndexOf('.');
          if (dot != -1 && dot < fixedInput.length - 1) {
            ext = fixedInput.substring(dot + 1).toLowerCase();
            if (ext.length > 6) ext = 'jpg';
          } else {
            ext = 'jpg';
          }
          final filename =
              'assistant_${updated.id}_${DateTime.now().millisecondsSinceEpoch}.$ext';
          final dest = File('${avatarsDir.path}/$filename');
          await src.copy(dest.path);

          // Optionally remove old stored avatar if it lives in our avatars folder
          if (prevRaw.isNotEmpty &&
              (prevRaw.contains('/avatars/') ||
                  prevRaw.contains('\\avatars\\'))) {
            try {
              final old = File(prevRaw);
              if (await old.exists() && old.path != dest.path) {
                await old.delete();
              }
            } catch (_) {}
          }

          next = updated.copyWith(avatar: dest.path);
        }
      }

      // Prefetch URL avatar to allow offline display later
      if (changed && raw.startsWith('http')) {
        try {
          await AvatarCache.getPath(raw);
        } catch (_) {}
      }

      // Handle background persistence similar to avatar, but under images/
      final bgRaw = (updated.background ?? '').trim();
      final prevBgRaw = (prev.background ?? '').trim();
      final bgChanged = bgRaw != prevBgRaw;
      final bgIsLocal =
          bgRaw.isNotEmpty &&
          (bgRaw.startsWith('/') || bgRaw.contains(':')) &&
          !bgRaw.startsWith('http');
      if (bgChanged &&
          bgIsLocal &&
          !bgRaw.contains('/images/') &&
          !bgRaw.contains('\\images\\')) {
        final fixedBg = SandboxPathResolver.fix(bgRaw);
        final srcBg = File(fixedBg);
        if (await srcBg.exists()) {
          final imagesDir = await AppDirectories.getImagesDirectory();
          if (!await imagesDir.exists()) {
            await imagesDir.create(recursive: true);
          }
          String ext = '';
          final dot = fixedBg.lastIndexOf('.');
          if (dot != -1 && dot < fixedBg.length - 1) {
            ext = fixedBg.substring(dot + 1).toLowerCase();
            if (ext.length > 6) ext = 'jpg';
          } else {
            ext = 'jpg';
          }
          final filename =
              'background_${updated.id}_${DateTime.now().millisecondsSinceEpoch}.$ext';
          final destBg = File('${imagesDir.path}/$filename');
          await srcBg.copy(destBg.path);

          // Clean old stored background if it lived in images/
          if (prevBgRaw.isNotEmpty &&
              (prevBgRaw.contains('/images/') ||
                  prevBgRaw.contains('\\images\\'))) {
            try {
              final oldBg = File(prevBgRaw);
              if (await oldBg.exists() && oldBg.path != destBg.path) {
                await oldBg.delete();
              }
            } catch (_) {}
          }

          next = next.copyWith(background: destBg.path);
        }
      } else if (bgChanged && bgRaw.isEmpty && prevBgRaw.contains('/images/')) {
        // If background cleared, optionally remove previous stored file
        try {
          final oldBg = File(prevBgRaw);
          if (await oldBg.exists()) {
            await oldBg.delete();
          }
        } catch (_) {}
      }
    } catch (_) {
      // On any failure, fall back to the provided value unchanged.
    }

    _assistants[idx] = next;
    await _persist();
    notifyListeners();
  }

  Future<void> setSearchEnabledForCurrentAssistant(bool enabled) async {
    final a = currentAssistant;
    if (a == null || a.searchEnabled == enabled) return;
    await updateAssistant(a.copyWith(searchEnabled: enabled));
  }

  Future<void> reorderAssistantRegex({
    required String assistantId,
    required int oldIndex,
    required int newIndex,
  }) async {
    final idx = _assistants.indexWhere((a) => a.id == assistantId);
    if (idx == -1) return;
    final list = List<AssistantRegex>.of(_assistants[idx].regexRules);
    if (oldIndex < 0 || oldIndex >= list.length) return;
    if (newIndex < 0 || newIndex >= list.length) return;
    final item = list.removeAt(oldIndex);
    list.insert(newIndex, item);
    _assistants[idx] = _assistants[idx].copyWith(regexRules: list);
    notifyListeners();
    await _persist();
  }

  Future<bool> deleteAssistant(String id) async {
    final idx = _assistants.indexWhere((a) => a.id == id);
    if (idx == -1) return false;
    // Do not allow deleting the last remaining assistant
    if (_assistants.length <= 1) return false;

    await chatService?.deleteConversationsForAssistant(id);

    final removingCurrent = _assistants[idx].id == _currentAssistantId;
    _assistants.removeAt(idx);
    if (removingCurrent) {
      _currentAssistantId = _assistants.isNotEmpty
          ? _assistants.first.id
          : null;
    }
    await _persist();
    final prefs = await SharedPreferences.getInstance();
    if (_currentAssistantId != null) {
      await prefs.setString(_currentAssistantKey, _currentAssistantId!);
    } else {
      await prefs.remove(_currentAssistantKey);
    }
    notifyListeners();
    return true;
  }

  Future<void> reorderAssistants(int oldIndex, int newIndex) async {
    if (oldIndex == newIndex) return;
    if (oldIndex < 0 || oldIndex >= _assistants.length) return;
    if (newIndex < 0 || newIndex >= _assistants.length) return;

    final assistant = _assistants.removeAt(oldIndex);
    _assistants.insert(newIndex, assistant);

    // Notify listeners immediately for smooth UI update
    notifyListeners();

    // Then persist the changes
    await _persist();
  }

  // Reorder only within a subset (e.g., assistants belonging to a tag group or ungrouped).
  // subsetIds defines the set and order boundary; other assistants remain in place.
  Future<void> reorderAssistantsWithin({
    required List<String> subsetIds,
    required int oldIndex,
    required int newIndex,
  }) async {
    if (oldIndex == newIndex) return;
    if (subsetIds.isEmpty) return;

    // Build subset indices in the master list preserving current order
    final idSet = subsetIds.toSet();
    final subsetIndices = <int>[];
    for (int i = 0; i < _assistants.length; i++) {
      if (idSet.contains(_assistants[i].id)) subsetIndices.add(i);
    }
    if (subsetIndices.isEmpty) return;
    if (oldIndex < 0 || oldIndex >= subsetIndices.length) return;
    if (newIndex < 0 || newIndex >= subsetIndices.length) return;

    // Extract subset in current order
    final subset = subsetIndices
        .map((i) => _assistants[i])
        .toList(growable: true);
    final moved = subset.removeAt(oldIndex);
    subset.insert(newIndex, moved);

    // Merge back into master list
    final merged = <Assistant>[];
    int take = 0;
    for (int i = 0; i < _assistants.length; i++) {
      final a = _assistants[i];
      if (idSet.contains(a.id)) {
        merged.add(subset[take++]);
      } else {
        merged.add(a);
      }
    }
    _assistants
      ..clear()
      ..addAll(merged);

    notifyListeners();
    await _persist();
  }
}

class _AssistantDecodeResult {
  const _AssistantDecodeResult({
    required this.assistants,
    required this.didApplyLegacySearch,
  });

  final List<Assistant> assistants;
  final bool didApplyLegacySearch;
}
