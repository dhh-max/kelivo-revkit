part of 'assistant_provider.dart';

/// SoLab 内置助手（「逆向助手」+「开发助手」）的**播种与版本升级**。
///
/// 上游把 `assistant_provider` 整体重写后只保留了「默认助手 + 示例助手」，
/// 我方这两个内置助手及其版本升级策略（改过名/提示词也随模板强刷）随之丢失。
/// 这里以同库扩展接回来：`ensureDefaults()` 会在上游的「列表为空才播种」之前
/// 调用本方法，因此已装用户也能拿到模板升级。
extension SolabBuiltInAssistants on AssistantProvider {
  Assistant _solabApkModAssistant() => BuiltinApkMod.definition().copyWith(
        systemPrompt: BuiltinApkMod.systemPrompt,
        localToolIds: BuiltinApkMod.toolIds,
      );

  Assistant _solabDevAssistant() => BuiltinDevAssistant.definition().copyWith(
        systemPrompt: BuiltinDevAssistant.systemPrompt,
        localToolIds: BuiltinDevAssistant.toolIds,
      );

  /// 播种缺失的内置助手，并把已存在的内置助手升级到当前模板版本。
  Future<void> ensureSolabBuiltInAssistants() async {
    await loaded;
    var changed = false;

    if (_assistants.isEmpty) {
      // 两个内置助手：逆向助手（APK 逆向改包）+ 开发助手（普通软件开发）。
      _assistants.add(_solabApkModAssistant());
      changed = true;
    }
    if (_assistants.every((assistant) => assistant.id != AssistantProvider.apkModAssistantId)) {
      _assistants.add(_solabApkModAssistant());
      changed = true;
    }
    if (_assistants.every(
      (assistant) => assistant.id != BuiltinDevAssistant.assistantId,
    )) {
      _assistants.add(_solabDevAssistant());
      changed = true;
    }

    // 开发助手升级：改名/核心提示也随版本强刷。
    final devStoredVersion =
        preferences.getInt(BuiltinDevAssistant.versionKey) ?? 0;
    if (_assistants.any((a) => a.id == BuiltinDevAssistant.assistantId) &&
        devStoredVersion < BuiltinDevAssistant.version) {
      final index = _assistants.indexWhere(
        (assistant) => assistant.id == BuiltinDevAssistant.assistantId,
      );
      final template = _solabDevAssistant();
      final existing = _assistants[index];
      _assistants[index] = existing.copyWith(
        name: template.name,
        systemPrompt: template.systemPrompt,
        systemPromptCore: template.systemPromptCore,
        localToolIds: template.localToolIds,
        searchEnabled: template.searchEnabled,
        enableMemory: existing.enableMemory,
        // 记忆能力字段跟随模板（与逆向助手同规矩）：v5 起打开自动整理并把
        // 写作用域收到本助手，老装机也能刷到（用户 2026-10-03）。
        autoOrganizeMemory: template.autoOrganizeMemory,
        memoryOrganizeEveryNTurns: template.memoryOrganizeEveryNTurns,
        memorySmartAddMode: template.memorySmartAddMode,
        memoryWriteScope: template.memoryWriteScope,
        // v6（2026-10-04）：上下文条数限制跟随模板（默认改为不限——有自动
        // 压缩；限条数会让窗口永不满足压缩阈值，超出部分直接丢失）。
        contextMessageSize: template.contextMessageSize,
        limitContextMessages: template.limitContextMessages,
        allowPastConversationRecall: template.allowPastConversationRecall,
        generateConversationSummary: template.generateConversationSummary,
      );
      changed = true;
    }
    if (devStoredVersion < BuiltinDevAssistant.version) {
      await preferences.setInt(
        BuiltinDevAssistant.versionKey,
        BuiltinDevAssistant.version,
      );
    }

    // 逆向助手升级：内置助手的身份由模板唯一决定，用户改过的名字/提示词
    // 也会被强刷（v70 起系统提示词强同步，v102 起名字也强刷）。
    final storedVersion = preferences.getInt(BuiltinApkMod.versionKey) ?? 0;
    if (_assistants.any((a) => a.id == AssistantProvider.apkModAssistantId) &&
        storedVersion < BuiltinApkMod.version) {
      final index =
          _assistants.indexWhere((a) => a.id == AssistantProvider.apkModAssistantId);
      final template = _solabApkModAssistant();
      final existing = _assistants[index];
      _assistants[index] = existing.copyWith(
        name: template.name,
        systemPrompt: template.systemPrompt,
        systemPromptCore: template.systemPromptCore,
        contextMessageSize: template.contextMessageSize,
        limitContextMessages: template.limitContextMessages,
        searchEnabled: template.searchEnabled,
        // 上游把思考预算换成了 reasoning；用户没有显式设置时跟随模板。
        reasoning: existing.reasoning ?? template.reasoning,
        mcpServerIds: <String>{
          ...existing.mcpServerIds,
          ...template.mcpServerIds,
        }.toList(growable: false),
        localToolIds: template.localToolIds,
        enableMemory: template.enableMemory,
        autoOrganizeMemory: template.autoOrganizeMemory,
        memoryOrganizeEveryNTurns: template.memoryOrganizeEveryNTurns,
        memorySmartAddMode: template.memorySmartAddMode,
        memoryWriteScope: template.memoryWriteScope,
        allowPastConversationRecall: template.allowPastConversationRecall,
        generateConversationSummary: template.generateConversationSummary,
        recentChatsSummaryMessageCount:
            template.recentChatsSummaryMessageCount,
        // v105：作业约定开关随模板（默认开；只对本助手生效）。
        operatorConventionsEnabled: template.operatorConventionsEnabled,
      );
      changed = true;
    }
    if (storedVersion < BuiltinApkMod.version) {
      await preferences.setInt(BuiltinApkMod.versionKey, BuiltinApkMod.version);
    }

    if (changed) await _persist();
    if (_currentAssistantId == null && _assistants.isNotEmpty) {
      _currentAssistantId = _assistants.first.id;
      await preferences.setString(AssistantProvider._currentAssistantKey, _currentAssistantId!);
    }
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }
}
