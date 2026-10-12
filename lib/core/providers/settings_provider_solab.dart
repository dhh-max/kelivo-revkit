part of 'settings_provider.dart';

/// 安卓后台聊天模式（我方原定义在被上游整体重写的 settings_provider.dart 末尾，
/// 迁移到本 part 文件的库级位置）。
enum AndroidBackgroundChatMode { off, on, onNotify }

// SoLab 追加设置（上游没有、我方自研的部分）
//
// 上游把 settings_provider 整体重写后，我方原有的这些设置项（MCP 主机模式、
// iOS 后台、聊天步进等）没法由 part 追加进**类体**（part 只能在库级拼接），
// 所以这里用「同库扩展 + 库级状态」实现：part 与主库同属一个 library，
// 扩展里可以直接访问主库类的私有成员 `_preferences`。
//
// 读取是惰性的：第一次访问任一成员时从 prefs 载入一次；写回即时持久化。

// ===== MCP server（局域网工具端点）=====
const String _solabMcpEnabledKey = 'mcp_server_enabled_v1';
const String _solabMcpPortKey = 'mcp_server_port_v1';
const String _solabMcpTokenKey = 'mcp_server_token_v2';
const String _solabMcpAuthExplicitDisabledKey =
    'mcp_server_auth_explicit_disabled_v1';
// 用户 2026-10-06：MCP 可能是别的工具在调，而子代理/AI 工作流花的是本机
// 模型的额度（App 里的 token），所以默认不允许，要显式打开。
const String _solabMcpAllowQuotaToolsKey = 'mcp_server_allow_quota_tools_v1';
// 用户 2026-10-06：作业约定（同一份工作台约定文本）也给 MCP 面一个开关，
// 打开后随 initialize 的 instructions 下发。默认关（MCP 常被外部工具连）。
const String _solabMcpOperatorConventionsKey =
    'mcp_server_operator_conventions_v1';

/// 与 `McpHttpServer.defaultPort` 保持一致（这里不引 import，避免环依赖）。
const int _solabMcpDefaultPort = 8800;

/// MCP 访问令牌：128 位随机（uuid v4 的 16 字节）取十六进制 → **32 字符**。
/// 长度是对外契约（UI 展示与用例都按 32 断言），不要改成拼接多个 uuid。
String _solabGenerateMcpToken() => Uuid().v4().replaceAll('-', '');

extension SolabMcpSettings on SettingsProvider {
  // 取值一律直读 `_preferences`（内存缓存，同步可读），不保留库级状态：
  // 否则同一个进程里第二个 SettingsProvider 实例会读到上一个实例的缓存。

  bool get mcpServerEnabled =>
      _preferences.getBool(_solabMcpEnabledKey) ?? false;

  int get mcpServerPort =>
      _preferences.getInt(_solabMcpPortKey) ?? _solabMcpDefaultPort;

  String get mcpServerToken =>
      _preferences.getString(_solabMcpTokenKey) ?? '';

  /// MCP 客户端是否可使用「花本机模型额度」的工具（子代理 / AI 工作流）。
  /// 默认 **关闭**：MCP 面常被第三方工具连接，子代理走的是本机配置的模型
  /// 额度（用户 2026-10-06 点名要求）。
  bool get mcpServerAllowQuotaTools =>
      _preferences.getBool(_solabMcpAllowQuotaToolsKey) ?? false;

  Future<void> setMcpServerAllowQuotaTools(bool v) async {
    if (mcpServerAllowQuotaTools == v) return;
    await _preferences.setBool(_solabMcpAllowQuotaToolsKey, v);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  /// MCP 面是否随 initialize 下发「作业约定」块（与端内逆向助手同一份文本）。
  /// 默认关闭：MCP 面可能是第三方工具在连，是否采用操作者约定由机主显式决定。
  bool get mcpServerOperatorConventions =>
      _preferences.getBool(_solabMcpOperatorConventionsKey) ?? false;

  Future<void> setMcpServerOperatorConventions(bool v) async {
    if (mcpServerOperatorConventions == v) return;
    await _preferences.setBool(_solabMcpOperatorConventionsKey, v);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  bool get mcpServerAuthEnabled => mcpServerToken.isNotEmpty;

  bool get _solabMcpAuthExplicitlyDisabled =>
      _preferences.getBool(_solabMcpAuthExplicitDisabledKey) ?? false;

  /// 开启主机模式即默认生成鉴权 token（T1.2：避免「开启即裸奔」）。
  /// 逃生口：显式 `setMcpServerAuthEnabled(false)` 后置位「我方显式关闭」标记，
  /// 之后再开服务不会自动补 token。
  Future<void> setMcpServerEnabled(bool v) async {
    if (mcpServerEnabled == v) return;
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
    await _preferences.setBool(_solabMcpEnabledKey, v);
    if (v && mcpServerToken.isEmpty && !_solabMcpAuthExplicitlyDisabled) {
      // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
      notifyListeners();
      await _preferences.setString(_solabMcpTokenKey, _solabGenerateMcpToken());
    }
  }

  /// 访问保护开关：关闭时清空 token 并标记「显式关闭」。
  Future<void> setMcpServerAuthEnabled(bool v) async {
    final current = mcpServerToken;
    final next = v ? (current.isEmpty ? _solabGenerateMcpToken() : current) : '';
    await _preferences.setBool(_solabMcpAuthExplicitDisabledKey, !v);
    if (current == next) return;
    await _preferences.setString(_solabMcpTokenKey, next);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  Future<void> setMcpServerPort(int port) async {
    final p = port.clamp(1024, 65535);
    if (mcpServerPort == p) return;
    await _preferences.setInt(_solabMcpPortKey, p);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  Future<void> regenerateMcpServerToken() async {
    await _preferences.setString(_solabMcpTokenKey, _solabGenerateMcpToken());
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }
}

// Linux 标题栏偏好（桌面栈已裁剪，仅保留偏好读写）
const String _solabLinuxHideTitleBarKey = 'linux_hide_title_bar_v1';

// ===== 后台与聊天步进（我方设置项）=====
const String _solabAndroidBgChatModeKey = 'android_background_chat_mode_v1';
const String _solabStepsSharedBubbleKey = 'chat_steps_shared_bubble_v1';
const String _solabIosBgNotificationsKey =
    'ios_background_notifications_enabled_v1';
const String _solabIosBgTaskRefreshKey =
    'ios_background_task_refresh_enabled_v1';
const String _solabIosBgGenerationKey =
    'ios_background_generation_enabled_v1';
const String _solabIosLiveActivityKey = 'ios_live_activity_enabled_v1';

extension SolabBackgroundSettings on SettingsProvider {
  AndroidBackgroundChatMode get androidBackgroundChatMode {
    final mode = _preferences.getString(_solabAndroidBgChatModeKey);
    return switch (mode) {
      'on_notify' => AndroidBackgroundChatMode.onNotify,
      'on' => AndroidBackgroundChatMode.on,
      _ => AndroidBackgroundChatMode.off,
    };
  }

  Future<void> setAndroidBackgroundChatMode(
    AndroidBackgroundChatMode mode,
  ) async {
    if (androidBackgroundChatMode == mode) return;
    final v = switch (mode) {
      AndroidBackgroundChatMode.onNotify => 'on_notify',
      AndroidBackgroundChatMode.on => 'on',
      AndroidBackgroundChatMode.off => 'off',
    };
    await _preferences.setString(_solabAndroidBgChatModeKey, v);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  bool get chatStepsSharedBubble =>
      _preferences.getBool(_solabStepsSharedBubbleKey) ?? false;

  Future<void> setChatStepsSharedBubble(bool value) async {
    if (chatStepsSharedBubble == value) return;
    await _preferences.setBool(_solabStepsSharedBubbleKey, value);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  bool get iosBackgroundNotificationsEnabled =>
      _preferences.getBool(_solabIosBgNotificationsKey) ?? false;

  Future<void> setIosBackgroundNotificationsEnabled(bool v) async {
    if (iosBackgroundNotificationsEnabled == v) return;
    await _preferences.setBool(_solabIosBgNotificationsKey, v);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  bool get iosBackgroundTaskRefreshEnabled =>
      _preferences.getBool(_solabIosBgTaskRefreshKey) ?? false;

  Future<void> setIosBackgroundTaskRefreshEnabled(bool v) async {
    if (iosBackgroundTaskRefreshEnabled == v) return;
    await _preferences.setBool(_solabIosBgTaskRefreshKey, v);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  bool get iosBackgroundGenerationEnabled =>
      _preferences.getBool(_solabIosBgGenerationKey) ?? false;

  Future<void> setIosBackgroundGenerationEnabled(bool v) async {
    if (iosBackgroundGenerationEnabled == v) return;
    await _preferences.setBool(_solabIosBgGenerationKey, v);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  bool get iosLiveActivityEnabled =>
      _preferences.getBool(_solabIosLiveActivityKey) ?? false;

  Future<void> setIosLiveActivityEnabled(bool v) async {
    if (iosLiveActivityEnabled == v) return;
    await _preferences.setBool(_solabIosLiveActivityKey, v);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }
}

// ===== 建议生成开关的 setter（上游只有字段/读取，没有公开 setter）=====
extension SolabSuggestionSettings on SettingsProvider {
  Future<void> setSuggestionGenerationEnabled(bool value) async {
    if (_suggestionGenerationEnabled == value) return;
    _suggestionGenerationEnabled = value;
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
    await _preferences.setBool(SettingsProvider._suggestionGenerationEnabledKey, value);
  }
}

// ===== 内置 provider 的「删除 / 恢复」=====
//
// 内置厂家的目录是静态的，删掉后必须在「重新播种」和「目录渲染」两处都被认出来，
// 否则会出现「删了又回来 / 删不掉」。所以墓碑必须**显式落盘**
// （`deleted_builtin_providers_v1`），而不是靠「内置键不在配置表里」推导——
// 推导会把「从未播种过的内置键」也算成已删除。
const String _solabDeletedBuiltInsKey = 'deleted_builtin_providers_v1';

extension SolabProviderTombstone on SettingsProvider {
  Set<String> get _solabTombstones =>
      (_preferences.getStringList(_solabDeletedBuiltInsKey) ??
              const <String>[])
          .toSet();

  bool isProviderDeleted(String key) => _solabTombstones.contains(key);

  Set<String> get deletedBuiltInProviderKeys =>
      Set<String>.unmodifiable(_solabTombstones);

  /// 删除内置厂家时落墓碑（由 `removeProviderConfig` 在删除后调用）。
  Future<void> markSolabBuiltInProviderDeleted(String key) async {
    if (!SettingsProvider._builtInProviderKeysInOrder.contains(key)) return;
    final next = _solabTombstones..add(key);
    await _preferences.setStringList(
      _solabDeletedBuiltInsKey,
      next.toList(growable: false),
    );
  }

  /// 恢复：清墓碑 + 重新播种默认配置 + 归位顺序表（三项都要落盘）。
  Future<void> restoreBuiltInProvider(String key) async {
    if (!SettingsProvider._builtInProviderKeysInOrder.contains(key)) return;
    final tombstones = _solabTombstones..remove(key);
    await _preferences.setStringList(
      _solabDeletedBuiltInsKey,
      tombstones.toList(growable: false),
    );
    if (!_providerConfigs.containsKey(key)) {
      ensureProviderConfig(key, defaultName: key);
      final configs = _providerConfigs.map((k, v) => MapEntry(k, v.toJson()));
      await _preferences.setString(
        SettingsProvider._providerConfigsKey,
        jsonEncode(configs),
      );
    }
    final restoredOrder = List<String>.from(_providersOrder);
    if (!restoredOrder.contains(key)) restoredOrder.add(key);
    _providersOrder = restoredOrder;
    _cleanupProviderOrderAndGrouping();
    await _preferences.setStringList(
      SettingsProvider._providersOrderKey,
      _providersOrder,
    );
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }
}

// ===== 模型剔除墓碑的清除（我方自研：用户手动把模型加回来时清墓碑）=====
extension SolabModelExclusions on SettingsProvider {
  Future<void> clearModelAutoExclusions(
    String providerKey,
    Set<String> modelIds,
  ) async {
    if (modelIds.isEmpty) return;
    final old = _providerConfigs[providerKey];
    if (old == null) return;
    final nextOverrides = <String, dynamic>{...old.modelOverrides};
    var changed = false;
    for (final modelId in modelIds) {
      final existing = nextOverrides[modelId];
      if (existing is! Map ||
          existing[SettingsProvider.modelAutoExcludedKey] != true) {
        continue;
      }
      final next = Map<String, dynamic>.from(existing)
        ..remove(SettingsProvider.modelAutoExcludedKey);
      if (next.isEmpty) {
        nextOverrides.remove(modelId);
      } else {
        nextOverrides[modelId] = next;
      }
      changed = true;
    }
    if (!changed) return;
    _providerConfigs[providerKey] = old.copyWith(modelOverrides: nextOverrides);
    final configs = _providerConfigs.map((k, v) => MapEntry(k, v.toJson()));
    await _preferences.setString(
      SettingsProvider._providerConfigsKey,
      jsonEncode(configs),
    );
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }
}

// ===== 上下文自动化：自动压缩 / 自动重连 =====
const String _solabAutoCompactEnabledKey = 'solab_auto_compact_enabled_v1';
const String _solabAutoCompactThresholdKey =
    'solab_auto_compact_threshold_percent_v1';

/// 自动压缩阈值允许范围（上下文窗口百分比）。
const int kSolabAutoCompactMinPercent = 30;
const int kSolabAutoCompactMaxPercent = 95;
const int kSolabAutoCompactDefaultPercent = 80;

extension SolabContextAutomationSettings on SettingsProvider {
  /// 自动压缩：本轮请求前，若上下文占用达到 [autoCompactThresholdPercent]
  /// 就先压缩历史。默认关闭（压缩会调用模型，必须显式开启）。
  bool get autoCompactEnabled =>
      _preferences.getBool(_solabAutoCompactEnabledKey) ?? false;

  int get autoCompactThresholdPercent =>
      (_preferences.getInt(_solabAutoCompactThresholdKey) ??
              kSolabAutoCompactDefaultPercent)
          .clamp(kSolabAutoCompactMinPercent, kSolabAutoCompactMaxPercent);

  Future<void> setAutoCompactEnabled(bool v) async {
    if (autoCompactEnabled == v) return;
    await _preferences.setBool(_solabAutoCompactEnabledKey, v);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  Future<void> setAutoCompactThresholdPercent(int v) async {
    final next = v.clamp(
      kSolabAutoCompactMinPercent,
      kSolabAutoCompactMaxPercent,
    );
    if (autoCompactThresholdPercent == next) return;
    await _preferences.setInt(_solabAutoCompactThresholdKey, next);
    // ignore: invalid_use_of_protected_member, invalid_use_of_visible_for_testing_member
    notifyListeners();
  }

  /// 自动重连：复用上游 AutoRetryOptions 的持久化与运行时装配
  /// （默认 3 次、网络错误与 429/5xx 才重试）。
  Future<void> setAutoRetryEnabled(bool v) => setAutoRetryOptions(
    AutoRetryOptions.fromJson(<String, dynamic>{
      ...autoRetryOptions.toJson(),
      'enabled': v,
    }),
  );

  Future<void> setAutoRetryMaxRetries(int v) => setAutoRetryOptions(
    AutoRetryOptions.fromJson(<String, dynamic>{
      ...autoRetryOptions.toJson(),
      'maxRetries': v,
    }),
  );
}
