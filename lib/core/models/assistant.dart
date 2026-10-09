import 'dart:convert';
import 'app_control_policy.dart';
import 'assistant_regex.dart';
import 'health_data_type.dart';
import 'preset_message.dart';
import 'reasoning_request.dart';

enum MemorySmartAddMode { batched, perItem }

enum DefaultWorkspaceSetup { automatic, suggest, completed }

enum MemoryWriteScope {
  alwaysGlobal,
  alwaysAssistant,
  toolDefaultGlobal,
  toolDefaultAssistant,
}

class Assistant {
  static const int defaultRecentChatsSummaryMessageCount = 5;
  static const int defaultMemoryOrganizeEveryNTurns = 1;
  static const int minMemoryOrganizeEveryNTurns = 1;
  static const int maxMemoryOrganizeEveryNTurns = 20;
  static const double defaultTemperature = 1.0;
  static const double defaultGradientBackgroundPhase = 7.0;
  static const int minContextMessageSize = 1;
  static const int maxContextMessageSize = 4096;
  static const List<int> recentChatsSummaryMessageCountOptions = <int>[
    1,
    3,
    5,
    10,
    20,
    50,
  ];

  final String id;
  final String name;
  final String? avatar; // path/url/base64, null for initial-letter avatar
  final bool
  useAssistantAvatar; // replace model icon in chat with assistant avatar
  final bool useAssistantName; // replace model name in chat with assistant name
  final String? chatModelProvider; // null -> use global default
  final String? chatModelId; // null -> use global default
  final double? temperature; // null to disable; else 0.0 - 2.0
  final double? topP; // null to disable; else 0.0 - 1.0
  final int contextMessageSize; // number of previous messages to include
  final bool limitContextMessages; // whether to enforce contextMessageSize
  final bool streamOutput; // streaming responses
  final ReasoningRequest? reasoning; // null = no assistant default
  final int? maxTokens; // null = unlimited
  final String systemPrompt;
  final bool allowConversationSystemPrompt;
  final bool allowConversationPromptInjection;
  final String messageTemplate; // e.g. "{{ message }}"
  final bool searchEnabled; // per-assistant external web search switch
  final List<String> mcpServerIds; // bound MCP server IDs
  final List<String> localToolIds; // enabled local tool IDs

  /// Whether this assistant may dispatch expert teams — the `team` / `members`
  /// form of the `subagent` tool (2026-09-29). On by default; turning it off
  /// narrows delegation to single jobs and is enforced in both the published
  /// schema and the dispatch path. Serialised, so it survives a restart.
  final bool subagentTeamsEnabled;

  /// 仅内置逆向助手（`BuiltinApkMod.assistantId`）使用：开启后，本轮系统提示
  /// 追加「作业约定」块（授权范围内直接执行、不重复索权/说教；越界只说明一次
  /// 并给替代；交付=产物路径+回执+证据+下一步）。
  ///
  /// 用户 2026-10-06：只给逆向助手一个这样的提示词/开关，其它助手不受影响。
  /// 注入侧有双重判据（助手 id + 本开关），改这里不会串到别的助手。序列化。
  final bool operatorConventionsEnabled;

  /// Per-capability AI switches for the assistant (2026-09-29): keyed by
  /// `AgentCapabilityPolicy.todoKey` / `skillsKey` / `verifyKey`, value false =
  /// the capability is off for this assistant. Missing key means on, so an
  /// existing assistant keeps every capability after the upgrade. Subagent and
  /// expert-team capability keep their own fields above. Serialised.
  final Map<String, bool> agentCapabilities;

  /// 允许该助手调用「应用控制」类工具（打开/关闭/跳转到 App 设置等）。
  final bool appControlEnabled;

  /// 应用控制的目标级别策略（哪些页面/操作允许）。
  final AppControlPolicy appControlPolicy;

  /// 0 = 关闭，null = 跟随全局默认。> 0 为思考预算 token 数。
  final int? thinkingBudget;

  /// 是否在提示中附带最近会话标题（已并入 allowPastConversationRecall，
  /// 保留该字段只为兼容旧序列化数据）。
  final bool enableRecentChatsReference;

  /// 助手在「纯聊天/无工具」轮次（ToolLoadPolicy.none）使用的精简核心提示。
  ///
  /// 2026-09-29（助手隔离）：闲聊轮此前对所有助手硬编码内置 APK 助手的核心
  /// 提示，导致开发助手/自建助手在「你好」这类轮次被替换成 SoLab 的身份与
  /// 授权边界文字（串提示词任务）。这里给每个助手留自己的精简提示位；为空时
  /// 回落到该助手自身的 systemPrompt，绝不回落到别的内置助手。序列化。
  final String systemPromptCore;

  /// Default workspace for new conversations started with this assistant.
  final String? defaultWorkspaceId;

  /// New assistants remember the first binding; existing assistants only suggest it.
  final DefaultWorkspaceSetup defaultWorkspaceSetup;

  /// Runtime-only identity for default-workspace edits, including selecting the
  /// same value. Unrelated edits preserve it; it is not serialized.
  final Object? defaultWorkspaceChangeToken;

  /// Enabled skill IDs. `null` means every installed skill is available.
  final List<String>? skillIds;

  /// HealthKit metric IDs this collaborator may read. Kept when the health
  /// master toggle is off so turning it back on restores the selection.
  final List<String> healthDataTypeIds;
  final String? background; // chat background (color/image ref)
  final bool useGradientBackground;
  final bool gradientBackgroundAnimated;
  final double gradientBackgroundPhase;
  final double gradientBackgroundOffsetX;
  final double gradientBackgroundOffsetY;
  // Custom request overrides (per assistant)
  final List<Map<String, String>>
  customHeaders; // [{name:'X-Header', value:'v'}]
  final List<Map<String, String>> customBody; // [{key:'foo', value:'{"a":1}'}]
  // Memory features (§4.1)
  final bool enableMemory;
  final bool autoOrganizeMemory;
  final int memoryOrganizeEveryNTurns;
  final MemorySmartAddMode memorySmartAddMode;
  final MemoryWriteScope memoryWriteScope;
  final bool allowPastConversationRecall;
  final bool generateConversationSummary;
  final int
  recentChatsSummaryMessageCount; // refresh summary after N new messages
  final bool appendCurrentTimeToUserMessage;
  final bool useIso8601TimeFormat;
  // Preset conversation messages (ordered)
  final List<PresetMessage> presetMessages;
  // Regex replacement rules
  final List<AssistantRegex> regexRules;

  const Assistant({
    required this.id,
    required this.name,
    this.avatar,
    this.useAssistantAvatar = false,
    this.useAssistantName = false,
    this.chatModelProvider,
    this.chatModelId,
    this.temperature,
    this.topP,
    this.contextMessageSize = 64,
    this.limitContextMessages = false,
    this.streamOutput = true,
    this.reasoning,
    this.maxTokens,
    this.systemPrompt = '',
    this.allowConversationSystemPrompt = false,
    this.allowConversationPromptInjection = false,
    this.messageTemplate = '{{ message }}',
    this.searchEnabled = false,
    this.mcpServerIds = const <String>[],
    this.localToolIds = const <String>[],
    this.subagentTeamsEnabled = true,
    this.operatorConventionsEnabled = false,
    this.agentCapabilities = const <String, bool>{},
    this.appControlEnabled = false,
    this.appControlPolicy = const AppControlPolicy(),
    this.thinkingBudget,
    this.enableRecentChatsReference = false,
    this.systemPromptCore = '',
    this.defaultWorkspaceId,
    this.defaultWorkspaceSetup = DefaultWorkspaceSetup.automatic,
    this.defaultWorkspaceChangeToken,
    this.skillIds,
    this.healthDataTypeIds = HealthDataTypeIds.defaultSelected,
    this.background,
    this.useGradientBackground = false,
    this.gradientBackgroundAnimated = true,
    this.gradientBackgroundPhase = defaultGradientBackgroundPhase,
    this.gradientBackgroundOffsetX = 0,
    this.gradientBackgroundOffsetY = 0,
    this.customHeaders = const <Map<String, String>>[],
    this.customBody = const <Map<String, String>>[],
    this.enableMemory = false,
    this.autoOrganizeMemory = false,
    this.memoryOrganizeEveryNTurns = defaultMemoryOrganizeEveryNTurns,
    this.memorySmartAddMode = MemorySmartAddMode.batched,
    this.memoryWriteScope = MemoryWriteScope.alwaysGlobal,
    this.allowPastConversationRecall = false,
    this.generateConversationSummary = false,
    this.recentChatsSummaryMessageCount = defaultRecentChatsSummaryMessageCount,
    this.appendCurrentTimeToUserMessage = false,
    this.useIso8601TimeFormat = false,
    this.presetMessages = const <PresetMessage>[],
    this.regexRules = const <AssistantRegex>[],
  });

  Assistant copyWith({
    String? id,
    String? name,
    String? avatar,
    bool? useAssistantAvatar,
    bool? useAssistantName,
    String? chatModelProvider,
    String? chatModelId,
    double? temperature,
    double? topP,
    int? contextMessageSize,
    bool? limitContextMessages,
    bool? streamOutput,
    ReasoningRequest? reasoning,
    int? maxTokens,
    String? systemPrompt,
    String? systemPromptCore,
    bool? allowConversationSystemPrompt,
    bool? allowConversationPromptInjection,
    String? messageTemplate,
    bool? searchEnabled,
    List<String>? mcpServerIds,
    List<String>? localToolIds,
    bool? subagentTeamsEnabled,
    bool? operatorConventionsEnabled,
    Map<String, bool>? agentCapabilities,
    bool? appControlEnabled,
    AppControlPolicy? appControlPolicy,
    int? thinkingBudget,
    bool? enableRecentChatsReference,
    bool clearThinkingBudget = false,
    String? defaultWorkspaceId,
    DefaultWorkspaceSetup? defaultWorkspaceSetup,
    List<String>? skillIds,
    List<String>? healthDataTypeIds,
    String? background,
    bool? useGradientBackground,
    bool? gradientBackgroundAnimated,
    double? gradientBackgroundPhase,
    double? gradientBackgroundOffsetX,
    double? gradientBackgroundOffsetY,
    List<Map<String, String>>? customHeaders,
    List<Map<String, String>>? customBody,
    bool? enableMemory,
    bool? autoOrganizeMemory,
    int? memoryOrganizeEveryNTurns,
    MemorySmartAddMode? memorySmartAddMode,
    MemoryWriteScope? memoryWriteScope,
    bool? allowPastConversationRecall,
    bool? generateConversationSummary,
    int? recentChatsSummaryMessageCount,
    bool? appendCurrentTimeToUserMessage,
    bool? useIso8601TimeFormat,
    List<PresetMessage>? presetMessages,
    List<AssistantRegex>? regexRules,
    bool clearChatModel = false,
    bool clearDefaultWorkspaceId = false,
    bool clearSkillIds = false,
    bool clearAvatar = false,
    bool clearTemperature = false,
    bool clearTopP = false,
    bool clearReasoning = false,
    bool clearMaxTokens = false,
    bool clearBackground = false,
  }) {
    return Assistant(
      id: id ?? this.id,
      name: name ?? this.name,
      avatar: clearAvatar ? null : (avatar ?? this.avatar),
      useAssistantAvatar: useAssistantAvatar ?? this.useAssistantAvatar,
      useAssistantName: useAssistantName ?? this.useAssistantName,
      chatModelProvider: clearChatModel
          ? null
          : (chatModelProvider ?? this.chatModelProvider),
      chatModelId: clearChatModel ? null : (chatModelId ?? this.chatModelId),
      temperature: clearTemperature ? null : (temperature ?? this.temperature),
      topP: clearTopP ? null : (topP ?? this.topP),
      contextMessageSize: contextMessageSize ?? this.contextMessageSize,
      limitContextMessages: limitContextMessages ?? this.limitContextMessages,
      streamOutput: streamOutput ?? this.streamOutput,
      reasoning: clearReasoning ? null : (reasoning ?? this.reasoning),
      maxTokens: clearMaxTokens ? null : (maxTokens ?? this.maxTokens),
      systemPrompt: systemPrompt ?? this.systemPrompt,
      systemPromptCore: systemPromptCore ?? this.systemPromptCore,
      allowConversationSystemPrompt:
          allowConversationSystemPrompt ?? this.allowConversationSystemPrompt,
      allowConversationPromptInjection:
          allowConversationPromptInjection ??
          this.allowConversationPromptInjection,
      messageTemplate: messageTemplate ?? this.messageTemplate,
      searchEnabled: searchEnabled ?? this.searchEnabled,
      mcpServerIds: mcpServerIds ?? this.mcpServerIds,
      localToolIds: localToolIds ?? this.localToolIds,
      subagentTeamsEnabled: subagentTeamsEnabled ?? this.subagentTeamsEnabled,
      operatorConventionsEnabled:
          operatorConventionsEnabled ?? this.operatorConventionsEnabled,
      agentCapabilities: agentCapabilities ?? this.agentCapabilities,
      appControlEnabled: appControlEnabled ?? this.appControlEnabled,
      appControlPolicy: appControlPolicy ?? this.appControlPolicy,
      thinkingBudget: clearThinkingBudget
          ? null
          : (thinkingBudget ?? this.thinkingBudget),
      enableRecentChatsReference:
          enableRecentChatsReference ?? this.enableRecentChatsReference,
      defaultWorkspaceId: clearDefaultWorkspaceId
          ? null
          : (defaultWorkspaceId ?? this.defaultWorkspaceId),
      defaultWorkspaceSetup:
          defaultWorkspaceSetup ??
          (clearDefaultWorkspaceId || defaultWorkspaceId != null
              ? DefaultWorkspaceSetup.completed
              : this.defaultWorkspaceSetup),
      defaultWorkspaceChangeToken:
          clearDefaultWorkspaceId ||
              defaultWorkspaceId != null ||
              defaultWorkspaceSetup != null
          ? Object()
          : defaultWorkspaceChangeToken,
      skillIds: clearSkillIds ? null : (skillIds ?? this.skillIds),
      healthDataTypeIds: healthDataTypeIds ?? this.healthDataTypeIds,
      background: clearBackground ? null : (background ?? this.background),
      useGradientBackground:
          useGradientBackground ?? this.useGradientBackground,
      gradientBackgroundAnimated:
          gradientBackgroundAnimated ?? this.gradientBackgroundAnimated,
      gradientBackgroundPhase:
          gradientBackgroundPhase ?? this.gradientBackgroundPhase,
      gradientBackgroundOffsetX:
          gradientBackgroundOffsetX ?? this.gradientBackgroundOffsetX,
      gradientBackgroundOffsetY:
          gradientBackgroundOffsetY ?? this.gradientBackgroundOffsetY,
      customHeaders: customHeaders ?? this.customHeaders,
      customBody: customBody ?? this.customBody,
      enableMemory: enableMemory ?? this.enableMemory,
      autoOrganizeMemory: autoOrganizeMemory ?? this.autoOrganizeMemory,
      memoryOrganizeEveryNTurns:
          memoryOrganizeEveryNTurns ?? this.memoryOrganizeEveryNTurns,
      memorySmartAddMode: memorySmartAddMode ?? this.memorySmartAddMode,
      memoryWriteScope: memoryWriteScope ?? this.memoryWriteScope,
      allowPastConversationRecall:
          allowPastConversationRecall ?? this.allowPastConversationRecall,
      generateConversationSummary:
          generateConversationSummary ?? this.generateConversationSummary,
      recentChatsSummaryMessageCount:
          recentChatsSummaryMessageCount ?? this.recentChatsSummaryMessageCount,
      appendCurrentTimeToUserMessage:
          appendCurrentTimeToUserMessage ?? this.appendCurrentTimeToUserMessage,
      useIso8601TimeFormat: useIso8601TimeFormat ?? this.useIso8601TimeFormat,
      presetMessages: presetMessages ?? this.presetMessages,
      regexRules: regexRules ?? this.regexRules,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'avatar': avatar,
    'useAssistantAvatar': useAssistantAvatar,
    'useAssistantName': useAssistantName,
    'chatModelProvider': chatModelProvider,
    'chatModelId': chatModelId,
    'temperature': temperature,
    'topP': topP,
    'contextMessageSize': contextMessageSize,
    'limitContextMessages': limitContextMessages,
    'streamOutput': streamOutput,
    'reasoning': reasoning?.toJson(),
    'maxTokens': maxTokens,
    'systemPrompt': systemPrompt,
    'systemPromptCore': systemPromptCore,
    'allowConversationSystemPrompt': allowConversationSystemPrompt,
    'allowConversationPromptInjection': allowConversationPromptInjection,
    'messageTemplate': messageTemplate,
    'searchEnabled': searchEnabled,
    'mcpServerIds': mcpServerIds,
    'localToolIds': localToolIds,
    'subagentTeamsEnabled': subagentTeamsEnabled,
    'operatorConventionsEnabled': operatorConventionsEnabled,
    'agentCapabilities': agentCapabilities,
    'appControlEnabled': appControlEnabled,
    'appControlPolicy': appControlPolicy
        .copyWith(enabled: appControlEnabled)
        .toJson(),
    'thinkingBudget': thinkingBudget,
    'enableRecentChatsReference': enableRecentChatsReference,
    'defaultWorkspaceId': defaultWorkspaceId,
    'defaultWorkspaceSetup': defaultWorkspaceSetup.name,
    'skillIds': skillIds,
    'healthDataTypeIds': healthDataTypeIds,
    'background': background,
    'useGradientBackground': useGradientBackground,
    'gradientBackgroundAnimated': gradientBackgroundAnimated,
    'gradientBackgroundPhase': gradientBackgroundPhase,
    'gradientBackgroundOffsetX': gradientBackgroundOffsetX,
    'gradientBackgroundOffsetY': gradientBackgroundOffsetY,
    'customHeaders': customHeaders,
    'customBody': customBody,
    'enableMemory': enableMemory,
    'autoOrganizeMemory': autoOrganizeMemory,
    'memoryOrganizeEveryNTurns': memoryOrganizeEveryNTurns,
    'memorySmartAddMode': memorySmartAddModeToString(memorySmartAddMode),
    'memoryWriteScope': memoryWriteScopeToString(memoryWriteScope),
    'allowPastConversationRecall': allowPastConversationRecall,
    'generateConversationSummary': generateConversationSummary,
    'recentChatsSummaryMessageCount': recentChatsSummaryMessageCount,
    'appendCurrentTimeToUserMessage': appendCurrentTimeToUserMessage,
    'useIso8601TimeFormat': useIso8601TimeFormat,
    'presetMessages': PresetMessage.encodeList(presetMessages),
    'regexRules': regexRules.map((e) => e.toJson()).toList(),
  };

  static ReasoningRequest? _readReasoning(Object? value) {
    if (value is Map) return ReasoningRequest.fromJson(value);
    return null;
  }

  static double _readGradientBackgroundPhase(Object? value) =>
      value is num && value.isFinite && value >= 0
      ? value.toDouble()
      : defaultGradientBackgroundPhase;

  static Assistant fromJson(Map<String, dynamic> json) => Assistant(
    id: json['id'] as String,
    name: (json['name'] as String?) ?? '',
    avatar: json['avatar'] as String?,
    useAssistantAvatar: json['useAssistantAvatar'] as bool? ?? false,
    useAssistantName: json['useAssistantName'] as bool? ?? false,
    chatModelProvider: json['chatModelProvider'] as String?,
    chatModelId: json['chatModelId'] as String?,
    temperature: (json['temperature'] as num?)?.toDouble(),
    topP: (json['topP'] as num?)?.toDouble(),
    contextMessageSize: (json['contextMessageSize'] as num?)?.toInt() ?? 64,
    limitContextMessages: json['limitContextMessages'] as bool? ?? false,
    streamOutput: json['streamOutput'] as bool? ?? true,
    reasoning: _readReasoning(json['reasoning']),
    maxTokens: (json['maxTokens'] as num?)?.toInt(),
    systemPrompt: (json['systemPrompt'] as String?) ?? '',
    systemPromptCore: (json['systemPromptCore'] as String?) ?? '',
    allowConversationSystemPrompt:
        (json['allowConversationSystemPrompt'] as bool?) ?? false,
    allowConversationPromptInjection:
        (json['allowConversationPromptInjection'] as bool?) ?? false,
    messageTemplate: (json['messageTemplate'] as String?) ?? '{{ message }}',
    searchEnabled: json['searchEnabled'] as bool? ?? false,
    mcpServerIds:
        (json['mcpServerIds'] as List?)?.cast<String>() ?? const <String>[],
    localToolIds:
        (json['localToolIds'] as List?)?.cast<String>() ?? const <String>[],
    subagentTeamsEnabled: json['subagentTeamsEnabled'] as bool? ?? true,
    operatorConventionsEnabled:
        json['operatorConventionsEnabled'] as bool? ?? false,
    agentCapabilities: json['agentCapabilities'] == null
        ? const <String, bool>{}
        : (json['agentCapabilities'] as Map).map(
            (key, value) => MapEntry(key.toString(), value == true),
          ),
    appControlEnabled: json['appControlEnabled'] as bool? ?? false,
    appControlPolicy: (json['appControlPolicy'] is Map)
        ? AppControlPolicy.fromJson(
            (json['appControlPolicy'] as Map).cast<String, dynamic>(),
          )
        : const AppControlPolicy(),
    thinkingBudget: (json['thinkingBudget'] as num?)?.toInt(),
    enableRecentChatsReference:
        json['enableRecentChatsReference'] as bool? ?? false,
    defaultWorkspaceId: json['defaultWorkspaceId'] as String?,
    defaultWorkspaceSetup:
        DefaultWorkspaceSetup.values
            .where((value) => value.name == json['defaultWorkspaceSetup'])
            .firstOrNull ??
        ((json['defaultWorkspaceId'] as String?)?.isNotEmpty == true
            ? DefaultWorkspaceSetup.completed
            : DefaultWorkspaceSetup.suggest),
    skillIds: json['skillIds'] == null
        ? null
        : (json['skillIds'] as List).map((e) => e.toString()).toList(),
    healthDataTypeIds: HealthDataTypeIds.parseStoredIds(
      json['healthDataTypeIds'],
    ),
    background: json['background'] as String?,
    useGradientBackground: json['useGradientBackground'] as bool? ?? false,
    gradientBackgroundAnimated:
        json['gradientBackgroundAnimated'] as bool? ?? true,
    gradientBackgroundPhase: _readGradientBackgroundPhase(
      json['gradientBackgroundPhase'],
    ),
    gradientBackgroundOffsetX:
        ((json['gradientBackgroundOffsetX'] as num?)?.toDouble() ?? 0).clamp(
          -1.0,
          1.0,
        ),
    gradientBackgroundOffsetY:
        ((json['gradientBackgroundOffsetY'] as num?)?.toDouble() ?? 0).clamp(
          -1.0,
          1.0,
        ),
    customHeaders: (() {
      final raw = json['customHeaders'];
      if (raw is List) {
        return raw
            .whereType<Map>()
            .map(
              (e) => {
                'name': (e['name'] ?? e['key'] ?? '').toString(),
                'value': (e['value'] ?? '').toString(),
              },
            )
            .toList();
      }
      return const <Map<String, String>>[];
    })(),
    customBody: (() {
      final raw = json['customBody'];
      if (raw is List) {
        return raw
            .whereType<Map>()
            .map(
              (e) => {
                'key': (e['key'] ?? e['name'] ?? '').toString(),
                'value': (e['value'] ?? '').toString(),
              },
            )
            .toList();
      }
      return const <Map<String, String>>[];
    })(),
    enableMemory: json['enableMemory'] as bool? ?? false,
    autoOrganizeMemory: json['autoOrganizeMemory'] as bool? ?? false,
    memoryOrganizeEveryNTurns: (() {
      final raw = (json['memoryOrganizeEveryNTurns'] as num?)?.toInt();
      if (raw == null ||
          raw < minMemoryOrganizeEveryNTurns ||
          raw > maxMemoryOrganizeEveryNTurns) {
        return defaultMemoryOrganizeEveryNTurns;
      }
      return raw;
    })(),
    memorySmartAddMode: memorySmartAddModeFromString(
      json['memorySmartAddMode'] as String?,
    ),
    memoryWriteScope: memoryWriteScopeFromString(
      json['memoryWriteScope'] as String?,
    ),
    // Legacy `enableRecentChatsReference` maps onto allowPastConversationRecall.
    allowPastConversationRecall:
        json['allowPastConversationRecall'] as bool? ??
        json['enableRecentChatsReference'] as bool? ??
        false,
    generateConversationSummary:
        json['generateConversationSummary'] as bool? ?? false,
    recentChatsSummaryMessageCount: (() {
      final raw = (json['recentChatsSummaryMessageCount'] as num?)?.toInt();
      if (raw == null || raw < 1) {
        return defaultRecentChatsSummaryMessageCount;
      }
      return raw;
    })(),
    appendCurrentTimeToUserMessage:
        json['appendCurrentTimeToUserMessage'] as bool? ?? false,
    useIso8601TimeFormat: json['useIso8601TimeFormat'] as bool? ?? false,
    presetMessages: (() {
      try {
        return PresetMessage.decodeList(json['presetMessages']);
      } catch (_) {
        return const <PresetMessage>[];
      }
    })(),
    regexRules: (() {
      final raw = json['regexRules'];
      if (raw is List) {
        return raw
            .whereType<Map>()
            .map((e) => AssistantRegex.fromJson(e.cast<String, dynamic>()))
            .toList();
      }
      return const <AssistantRegex>[];
    })(),
  );

  static String memorySmartAddModeToString(MemorySmartAddMode mode) {
    switch (mode) {
      case MemorySmartAddMode.batched:
        return 'batched';
      case MemorySmartAddMode.perItem:
        return 'perItem';
    }
  }

  static MemorySmartAddMode memorySmartAddModeFromString(String? value) {
    switch (value) {
      case 'perItem':
        return MemorySmartAddMode.perItem;
      case 'batched':
      default:
        return MemorySmartAddMode.batched;
    }
  }

  static String memoryWriteScopeToString(MemoryWriteScope scope) {
    switch (scope) {
      case MemoryWriteScope.alwaysGlobal:
        return 'alwaysGlobal';
      case MemoryWriteScope.alwaysAssistant:
        return 'alwaysAssistant';
      case MemoryWriteScope.toolDefaultGlobal:
        return 'toolDefaultGlobal';
      case MemoryWriteScope.toolDefaultAssistant:
        return 'toolDefaultAssistant';
    }
  }

  static MemoryWriteScope memoryWriteScopeFromString(String? value) {
    switch (value) {
      case 'alwaysAssistant':
        return MemoryWriteScope.alwaysAssistant;
      case 'toolDefaultGlobal':
        return MemoryWriteScope.toolDefaultGlobal;
      case 'toolDefaultAssistant':
        return MemoryWriteScope.toolDefaultAssistant;
      case 'alwaysGlobal':
      default:
        return MemoryWriteScope.alwaysGlobal;
    }
  }

  static String encodeList(List<Assistant> list) =>
      jsonEncode(list.map((e) => e.toJson()).toList());
  static List<Assistant> decodeList(String raw) {
    try {
      final arr = jsonDecode(raw) as List<dynamic>;
      return [
        for (final e in arr) Assistant.fromJson(e as Map<String, dynamic>),
      ];
    } catch (_) {
      return const <Assistant>[];
    }
  }
}
