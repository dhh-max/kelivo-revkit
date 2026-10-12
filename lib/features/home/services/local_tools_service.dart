import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:math_expressions/math_expressions.dart';
import 'package:path/path.dart' as p;
import '../../../core/services/local_tools/tool_arg_echo.dart';
import '../../../core/services/local_tools/tool_paging.dart';
import '../../solab_apk/analyzer/analyzer_tools.dart';
import '../../solab_apk/services/apk_report_normalizer.dart';
import '../../../core/models/health_data_type.dart';
import '../../../core/models/assistant.dart';
import '../../../core/providers/assistant_provider.dart';
import '../../../core/providers/agent_skill_provider.dart';
import '../../../core/providers/instruction_injection_provider.dart';
import '../../../core/providers/world_book_provider.dart';
import '../../../core/services/chat/chat_service.dart';
import '../../../core/services/local_tools/local_tool_names.dart';
import '../../workflow/services/workflow_tools_handler.dart';
import 'agent_capability_policy.dart';
import 'frida_tool_handler.dart';
import 'session_mode.dart';
import 'subagent_registry.dart';
import 'subagent_tool_handler.dart';
import '../../../core/services/local_tools/fs_observation_guard.dart';
import 'goal_tools.dart';
import 'todo_tool_handler.dart';
import '../../../core/services/local_tools/dart_tool_stats.dart';
import '../../../core/services/mcp_server/tool_argument_guard.dart';
import '../../../core/services/local_tools/tool_call_loop_guard.dart';
import '../../../core/services/local_tools/workspace_policy_contract.dart';
import '../../../core/services/memory/memory_audit.dart';
import '../../../core/services/sandbox/environment_dependencies.dart';
import '../../../core/services/workspace/workspace_tools_service.dart';
import '../../../core/services/local_tools/local_tool_registry.dart';
import '../../../core/services/local_tools/tool_error_policy.dart';
import '../../../core/services/memory/memory_quality.dart';
import '../../../core/services/memory/memory_repository.dart';
import '../../chat/runtime_tools.dart';
import '../../runtime/runtime_bridge.dart';
import '../../solab_apk/services/apk_analysis_service.dart';
import '../../solab_apk/services/apk_agent_policy.dart';
import '../../solab_apk/services/apk_artifact_identity_service.dart';
import '../../solab_apk/services/apk_mutation_preview_service.dart';
import '../../solab_apk/services/apk_patch_memory_service.dart';
import '../../solab_apk/services/apk_failure_memory_service.dart';
import '../../solab_apk/services/apk_workspace_binding_service.dart';
import '../../solab_apk/services/apk_project_service.dart';
import '../../solab_apk/services/apk_rule_service.dart';
import '../../solab_apk/services/apk_structural_service.dart';
import '../../solab_apk/services/apk_task_chain_service.dart';
import '../../solab_apk/services/apk_toolchain_service.dart';
import 'task_router.dart';
import 'tool_session_state.dart';
import '../../solab_apk/services/apk_workspace_service.dart';
import '../../solab_apk/services/value_calc_service.dart';
import '../../skills_builtin/solab_builtin_skills.dart';

/// 上游把 `LocalToolNames` **定义**在本文件里，因此 `import
/// 'local_tools_service.dart'` 即可见到它（上游的 local_tool_labels /
/// local_tool_toggle / chat_tools_sheet 都这么用）。本 fork 把它拆到了
/// `core/services/local_tools/local_tool_names.dart`（承重结构，不动），
/// 这里 re-export 保持上游调用方的写法可用——将来拉取上游时这批文件不用改。
export '../../../core/services/local_tools/local_tool_names.dart'
    show LocalToolNames;

part 'local_tool_schemas.dart';
part 'local_tool_handlers.dart';
part 'device_local_tools.dart';
part 'device_local_tool_schemas.dart';

typedef TextToSpeechStarter = Future<void> Function(String text);

typedef ToolHandler =
    Future<String?> Function(Map<String, dynamic> args, ToolContext context);

class ToolContext {
  const ToolContext({
    required this.assistant,
    this.chatService,
    this.memoryRepository,
    this.worldBookProvider,
    this.agentSkillProvider,
    this.instructionInjectionProvider,
    this.conversationId,
    this.onSpeakText,
    required this.analyzerContextKey,
  });

  final Assistant assistant;
  final ChatService? chatService;
  final MemoryRepository? memoryRepository;
  final WorldBookProvider? worldBookProvider;
  final AgentSkillProvider? agentSkillProvider;
  final InstructionInjectionProvider? instructionInjectionProvider;
  final String? conversationId;
  final TextToSpeechStarter? onSpeakText;
  final String analyzerContextKey;

  /// 运行时任务作用域键（与 [LocalToolsService.tryHandleToolCall] 的 scopeId 同口径）。
  ///
  /// 端内对话按 conversationId 隔离；MCP host 固定 'mcp-host'（产物/索引是工作
  /// 目录里的物理状态，按 HTTP 会话切分会让签名登记跨会话不可见）；工作台
  /// （analyzerContextKey == 'app'）用 'workbench'，与 wrapOrRun 的兜底一致。
  String get runtimeScopeKey {
    final id = conversationId?.trim();
    if (id != null && id.isNotEmpty) return id;
    if (analyzerContextKey.startsWith('mcp:')) return 'mcp-host';
    if (analyzerContextKey == 'app') return 'workbench';
    return analyzerContextKey;
  }
}

/// 本地工具开关页 UI 元数据（工具 ID → 标题/简述）。
///
/// 与 [LocalToolsService.buildToolDefinitions] 的工具集合保持一致——
/// 新增工具时需同步登记，避免助手设置页缺失开关。
final Map<String, ({String title, String subtitle})> kLocalToolUiMetadata =
    LocalToolRegistry.uiMetadata;

class LocalToolsService {
  const LocalToolsService._();

  /// 该本地工具在当前平台是否可用（与助手「本地工具」页签的判定一致）。
  ///
  /// 上游 1.2.6 引入：设备类工具（使用时长/日历/定位/天气/健康/提醒）
  /// 在不同平台支持度不同，UI 与工具装配都走这一个判定口。
  static bool isAvailableOnThisPlatform(String name) {
    switch (name) {
      case LocalToolNames.phoneControl:
        return DeviceLocalTools.phoneControlSupported;
      case LocalToolNames.screenTime:
        return DeviceLocalTools.screenTimeSupported;
      case LocalToolNames.calendarQuery:
      case LocalToolNames.calendarCreate:
        return DeviceLocalTools.calendarSupported;
      case LocalToolNames.currentLocation:
        return DeviceLocalTools.locationSupported;
      case LocalToolNames.weather:
        return DeviceLocalTools.weatherSupported;
      case LocalToolNames.healthSummary:
        return DeviceLocalTools.healthSupported;
      case LocalToolNames.remindersQuery:
      case LocalToolNames.remindersCreate:
      case LocalToolNames.remindersComplete:
        return DeviceLocalTools.remindersSupported;
      default:
        return true;
    }
  }

  static String? _lastSyncedSoWorkDir;
  static const _apkCheckpointTools = <String>{
    LocalToolNames.routeTask,
    LocalToolNames.apkAnalyzeWorkspace,
    LocalToolNames.apkArchive,
    LocalToolNames.apkExportReport,
    LocalToolNames.dexSearch,
    LocalToolNames.stringScan,
    LocalToolNames.dexXref,
    LocalToolNames.classOutline,
    LocalToolNames.smaliRead,
    LocalToolNames.soAnalyze,
    LocalToolNames.jadxDecompile,
    LocalToolNames.apkPatchDex,
    LocalToolNames.apkPatchDexStrings,
    LocalToolNames.apkSignatureBypass,
    LocalToolNames.apkPatchManifest,
    LocalToolNames.soPatchIntoApk,
    LocalToolNames.apkRebuild,
    LocalToolNames.apkSign,
  };

  static const _apkPathParameter = <String, Object>{
    'apkPath': {
      'type': 'string',
      'description':
          'Local APK path. Accepts either (1) an absolute path INSIDE the unified work directory (outside paths are rejected with PATH_OUTSIDE_WORKSPACE), or (2) a relative path / file name resolved against the work directory. If omitted, the latest patch output or analyzed source APK is used. Use file(action=list) to discover file names. If no work directory is set, stop and ask the user to set it in APK 工作台.',
    },
  };

  /// INPUT_TOO_LARGE 的一次性放行位。凡是被 native 输入体积预算覆盖的方法
  /// （patchDexMethods/patchDexStrings/jadxDecompile/apkRebuild）都必须声明并
  /// 透传它——只声明不接通会让错误文案里「携带 allowOversize:true 重试」变成
  /// 死路（2026-09-15 审核修复）。
  static const _allowOversizeParameter = <String, Object>{
    'allowOversize': {
      'type': 'boolean',
      'description':
          'Set true ONLY after an INPUT_TOO_LARGE rejection and only when no smaller-granularity path exists: runs despite the memory budget (the decoded input can OOM and kill the process). One-shot pass; do not retry with it after a crash.',
    },
  };

  static List<Map<String, dynamic>> buildToolDefinitions({
    required Assistant? assistant,
    required bool supportsTools,
  }) => buildLocalToolSchemas(
    assistant: assistant,
    supportsTools: supportsTools,
    apkPathParameter: _apkPathParameter,
    allowOversizeParameter: _allowOversizeParameter,
    deviceTimezoneHint: _deviceTimezoneHint,
  );

  static Map<String, Map<String, dynamic>>? _definitionIndex;

  /// 单个本地工具的默认 schema（按工具名查）。
  ///
  /// 上游 1.2.6 的 `built_in_tool_catalog` 用它构建「内置工具目录」，
  /// 上游那边是同一个文件里的一串 const 定义 + switch；本 fork 的 schema 由
  /// [buildToolDefinitions] 统一产出（依赖 assistant 的启用集），
  /// 因此这里用一个「全量启用」的临时 assistant 生成一次并建索引缓存
  /// （目录只读、进程内不变，缓存安全）。
  static Map<String, dynamic> definitionFor(String name) {
    final index = _definitionIndex ??= () {
      final all = buildToolDefinitions(
        assistant: Assistant(
          id: '__builtin_catalog__',
          name: 'builtin',
          localToolIds: LocalToolNames.all,
        ),
        supportsTools: true,
      );
      final map = <String, Map<String, dynamic>>{};
      for (final def in all) {
        final fn = def['function'];
        if (fn is! Map) continue;
        final toolName = fn['name']?.toString() ?? '';
        if (toolName.isEmpty) continue;
        // 保存完整定义（含 type/function 外壳）：工具描述页按 ['function'] 读取
        // description/parameters，只存内层 function 映射会让整组显示为空。
        map[toolName] = def;
      }
      return map;
    }();
    // 设备工具的定义来自上游 1.2.7 原文（含定位/日历/健康/提醒/天气/屏幕时间）。
    final deviceDef = DeviceLocalToolSchemas.definitionFor(name);
    if (deviceDef != null) return deviceDef;
    return index[name] ??
        <String, dynamic>{
          'type': 'function',
          'function': <String, dynamic>{'name': name},
        };
  }

  /// 会话任务清单工具（todo_write / todo_read）共用一份 store。
  static final TodoToolHandler _todoHandler = TodoToolHandler();
  static final GoalTools _goalTools = GoalTools();

  /// 子代理工具（subagent）。模型调用口由应用层在能解析 settings/provider 的
  /// 地方注册（ToolHandlerService.buildToolDefinitions）。
  static final SubAgentToolHandler subAgentHandler = SubAgentToolHandler();
  static final SubAgentToolHandler _subAgentHandler = subAgentHandler;

  /// 工作流工具（run_workflow）。引擎调用口同样由应用层在
  /// ToolHandlerService.buildToolDefinitions 里注册（那里才有 provider/model）。
  static final WorkflowToolsHandler workflowHandler = WorkflowToolsHandler();
  static final WorkflowToolsHandler _workflowHandler = workflowHandler;

  static final Map<String, ToolHandler>
  _toolHandlers = Map<String, ToolHandler>.unmodifiable(<String, ToolHandler>{
    for (final name in AnalyzerToolNames.all)
      name: (args, context) =>
          _handleAnalyzerTool(name, args, context.analyzerContextKey),
    LocalToolNames.timeInfo: (args, context) => Future<String?>.value(
      jsonEncode(_buildTimeInfoPayload(DateTime.now())),
    ),
    LocalToolNames.clipboard: (args, context) => _handleClipboardTool(args),
    LocalToolNames.textToSpeech: (args, context) =>
        _handleTextToSpeechTool(args, context.onSpeakText),
    LocalToolNames.askUser: (args, context) => Future<String?>.value(null),
    LocalToolNames.calculate: (args, context) =>
        Future<String?>.value(_handleCalculateTool(args)),
    LocalToolNames.valueCalc: (args, context) =>
        Future<String?>.value(_handleValueCalc(args)),
    // 仅在 Android 且无障碍服务可用时接线；其余平台保持"工具不存在"
    // （返回 null，与 DeviceLocalToolSchemas.tryHandle 的语义一致）。
    LocalToolNames.phoneControl: (args, context) =>
        DeviceLocalTools.phoneControlSupported
        ? _invokeDeviceTool('phoneControl', args)
        : Future<String?>.value(null),
    LocalToolNames.screenTime: (args, context) =>
        DeviceLocalTools.screenTimeSupported
        ? _invokeDeviceTool('getScreenTime', args)
        : _deviceToolNotAvailable(
            LocalToolNames.screenTime,
            'screen-time usage stats require an Android device with usage-access permission',
          ),
    LocalToolNames.calendarQuery: (args, context) =>
        DeviceLocalTools.calendarSupported
        ? _invokeDeviceTool('queryCalendar', args)
        : _deviceToolNotAvailable(
            LocalToolNames.calendarQuery,
            'calendar access requires a mobile device with calendar permission',
          ),
    LocalToolNames.calendarCreate: (args, context) =>
        DeviceLocalTools.calendarSupported
        ? _invokeDeviceTool('createCalendarEvent', args)
        : _deviceToolNotAvailable(
            LocalToolNames.calendarCreate,
            'calendar access requires a mobile device with calendar permission',
          ),
    LocalToolNames.agentRuntimeGuide: (args, context) =>
        _handleAgentRuntimeGuide(
          args,
          context.assistant,
          context.memoryRepository,
          context.worldBookProvider,
          context.agentSkillProvider,
          context.instructionInjectionProvider,
        ),
    LocalToolNames.apkReport: (args, context) => ApkWorkspaceService.readForAi(
      (args['section'] ?? 'summary').toString(),
      currentConversationId: context.conversationId,
      // F-40（2026-10-04）：读报告必须是纯读——过去跨作用域救援会把
      // activeApk 静默改绑到报告源包并把报告写进当前作用域（真机 v8 D3：
      // 读一次报告后 get_workspace_policy 的 activeApk 从 null 变成报告路径）。
      // 「读类工具不得产生写类副作用」；改绑只属于 analyze/写链路。
      adoptRescue: false,
    ),
    LocalToolNames.apkSkill: (args, context) => Future<String?>.value(
      SolabBuiltinSkills.read((args['skill'] ?? '').toString()),
    ),
    LocalToolNames.apkKnowledge: (args, context) => _handleApkKnowledge(
      args,
      context.assistant,
      context.worldBookProvider,
      conversationId: context.conversationId,
    ),
    LocalToolNames.installedSkills: (args, context) =>
        _handleInstalledSkills(args, context.agentSkillProvider),
    LocalToolNames.apkProjectInfo: (args, context) =>
        _handleApkProjectInfo(context),
    LocalToolNames.apkRules: (args, context) =>
        _handleListApkRules(args, context.chatService),
    LocalToolNames.soPatchIntoApk: (args, context) => _handleSoPatchIntoApk(
      args,
      context.chatService,
      context.memoryRepository,
    ),
    LocalToolNames.apkPatchDex: (args, context) =>
        _handleApkPatchDex(args, context.chatService),
    LocalToolNames.apkPatchDexStrings: (args, context) =>
        _handleApkPatchDexStrings(args, context.chatService),
    LocalToolNames.apkSignatureBypass: (args, context) =>
        _handleApkSignatureBypass(
          args,
          context.chatService,
          context.memoryRepository,
        ),
    LocalToolNames.apkPatchManifest: (args, context) => _handleApkPatchManifest(
      args,
      context.chatService,
      context.memoryRepository,
    ),
    LocalToolNames.apkToolMap: (args, context) =>
        Future<String?>.value(_handleApkToolMap(context.assistant, args)),
    LocalToolNames.apkPatchMemory: (args, context) => _handleApkPatchMemory(
      args,
      context.chatService,
      context.memoryRepository,
    ),
    LocalToolNames.apkSavePatchMemory: (args, context) =>
        _handleApkSavePatchMemory(
          args,
          context.chatService,
          context.memoryRepository,
        ),
    LocalToolNames.apkRecordPatchVerification: (args, context) =>
        _handleApkRecordPatchVerification(
          args,
          context.chatService,
          context.memoryRepository,
        ),
    LocalToolNames.apkListBuilds: (args, context) => _handleApkListBuilds(),
    LocalToolNames.apkCleanupBuilds: (args, context) =>
        _handleApkCleanupBuilds(args),
    LocalToolNames.apkNoteRead: (args, context) => _handleApkNoteRead(),
    LocalToolNames.apkNoteWrite: (args, context) => _handleApkNoteWrite(args),
    LocalToolNames.apkListWorkspace: (args, context) =>
        _handleApkListWorkspace(),
    LocalToolNames.apkAnalyzeWorkspace: (args, context) =>
        _handleApkAnalyzeWorkspace(
          args,
          context.chatService,
          context.conversationId,
        ),
    LocalToolNames.workspacePolicy: (args, context) =>
        _handleWorkspacePolicy(args),
    LocalToolNames.runTaskCommand: (args, context) => _handleRunTaskCommand(
      args,
      context.analyzerContextKey,
      context.memoryRepository,
    ),
    // D12：apk_archive(action=certificates) 的 processedArtifact 要与
    // get_apk_project_info 的 isProcessedArtifact 同源，故需要 context 里的
    // 记忆仓（产物台账是第三个证据源）。
    LocalToolNames.apkArchive: (args, context) =>
        _handleApkArchive(args, context),
    LocalToolNames.apkExportReport: (args, context) =>
        _handleApkExportReport(args, context),
    LocalToolNames.jadxDecompile: (args, context) => _handleJadxDecompile(args),
    LocalToolNames.apkSign: (args, context) => _handleApkSign(args),
    LocalToolNames.apkRebuild: (args, context) => _handleApkRebuild(args),
    LocalToolNames.dexSearch: (args, context) => _handleDexSearch(args),
    LocalToolNames.stringScan: (args, context) => _handleStringScan(args),
    LocalToolNames.dexXref: (args, context) =>
        _handleDexXref(args, context.chatService),
    LocalToolNames.classOutline: (args, context) => _handleClassOutline(args),
    LocalToolNames.smaliRead: (args, context) => _handleSmaliRead(args),
    LocalToolNames.soAnalyze: (args, context) => _handleSoAnalyze(args),
    LocalToolNames.frida: (args, context) => handleFridaTool(args),
    LocalToolNames.todoWrite: (args, context) => _todoHandler.handle(
      LocalToolNames.todoWrite,
      args,
      conversationId: _todoScope(context),
    ),
    LocalToolNames.todoRead: (args, context) => _todoHandler.handle(
      LocalToolNames.todoRead,
      args,
      conversationId: _todoScope(context),
    ),
    // 目标（会话模式 /goal）的模型侧入口：建/读/推进。
    LocalToolNames.goalGet: (args, context) => _goalTools.handle(
      LocalToolNames.goalGet,
      args,
      conversationId: _todoScope(context),
    ),
    LocalToolNames.goalCreate: (args, context) => _goalTools.handle(
      LocalToolNames.goalCreate,
      args,
      conversationId: _todoScope(context),
    ),
    LocalToolNames.goalUpdate: (args, context) => _goalTools.handle(
      LocalToolNames.goalUpdate,
      args,
      conversationId: _todoScope(context),
    ),
    // 助手是唯一来源：工具面（类别 ∩ 助手工具）、专家团开关、域、主提示
    // 全在 SubAgentToolHandler 里由它派生——斜杠命令 /subagent 走同一个入口，
    // 两条通道不再各拼一套（2026-09-29）。
    LocalToolNames.subagent: (args, context) => _subAgentHandler.handle(
      args,
      conversationId: _subAgentScope(context),
      assistant: context.assistant,
    ),
    LocalToolNames.runWorkflow: (args, context) => _workflowHandler.handle(
      args,
      conversationId: _subAgentScope(context),
    ),
    LocalToolNames.file: (args, context) => _handleFileUnified(args),
    LocalToolNames.routeTask: _handleRouteTask,
    // 运行时控制面（§7.4 核心控制）：模型可见名 → RuntimeTools.handle。
    // 执行点在 wrapOrRun 之内，任务已按 scopeKey 绑定好；状态推进一律经
    // TaskRuntime.advance 的进入条件校验，模型改不动状态（§13.4）。
    for (final name in RuntimeTools.names)
      if (name != LocalToolNames.routeTask)
        name: (args, context) => RuntimeTools.handle(
          name,
          args,
          session: RuntimeBridge.instance.session,
          scopeKey: context.runtimeScopeKey,
        ),
  });

  /// 子代理的作用域：显式 conversationId 优先，其次当前打开的会话，最后是
  /// MCP 面的固定作用域。
  ///
  /// 为什么必须有兜底：runner 的「每会话并发上限」与监看/按会话取消都按这个
  /// id 记账，拿不到时它只能跳过闸门（等于无限并发）；真机修复前这里还是
  /// null，因为工具定义装配那一步漏传了会话 id。
  static String? _subAgentScope(ToolContext context) {
    final explicit = context.conversationId?.trim();
    if (explicit != null && explicit.isNotEmpty) return explicit;
    final current = context.chatService?.currentConversationId?.trim();
    if (current != null && current.isNotEmpty) return current;
    if (context.analyzerContextKey.startsWith('mcp:')) return 'mcp-host';
    return null;
  }

  /// 任务清单的会话作用域：显式 conversationId 优先，退回到"当前打开的会话"。
  ///
  /// 只认 chatService 会让两条真实链路必失败（返回 conversation_required）：
  /// 子代理循环的 invokeTool 只传 conversationId（不传 chatService），MCP 面同理。
  /// 与 subagent 分支的取法保持一致，避免同一份上下文两套口径。
  ///
  /// 2026-10-02 增补第三级兜底：端内链路过去连 conversationId 都没传，会话级工具
  /// 直接不可用（用户实测 todo_read/todo_write 全失败）。兜底解析器由 App 启动时
  /// 注入（指向当前打开的会话），使端内/MCP/子代理三条链路都能拿到同一个 scope。
  static String? Function()? conversationFallbackResolver;

  static String? _todoScope(ToolContext context) {
    final explicit = context.conversationId?.trim();
    if (explicit != null && explicit.isNotEmpty) return explicit;
    final fromService = context.chatService?.currentConversationId?.trim();
    if (fromService != null && fromService.isNotEmpty) return fromService;
    try {
      final fallback = conversationFallbackResolver?.call()?.trim();
      if (fallback != null && fallback.isNotEmpty) return fallback;
    } catch (_) {
      // 兜底解析器不允许把工具调用炸掉。
    }
    return null;
  }

  /// Agent 面参数守卫（A4）：与 MCP 面共用 ToolArgumentGuard 与同一 schema 来源。
  ///
  /// schema 按「助手启用集签名」缓存：换助手/换工具集自动重建，避免陈旧声明
  /// 把合法调用拦下（这类缓存失效遗漏在生产上很难查）。
  static Map<String, Map<String, dynamic>>? _argumentSchemaCache;
  static String _argumentSchemaCacheKey = '';

  static Map<String, dynamic>? _guardArguments(
    String name,
    Map<String, dynamic> args,
    Assistant assistant,
  ) {
    // 键 = 助手启用集 + 能力开关签名：只看 localToolIds 时，翻开
    // AgentCapabilityPolicy 的开关不会让陈旧 schema 表失效，新打开能力的
    // 工具就会在本次进程内静默跳过参数校验（2026-09-29 助手隔离）。
    final key =
        '${assistant.localToolIds.join(',')}#'
        '${AgentCapabilityPolicy.signatureOf(assistant)}';
    var usable = _argumentSchemaCache != null && _argumentSchemaCacheKey == key;
    if (!usable) {
      final built = <String, Map<String, dynamic>>{};
      var builtOk = false;
      try {
        for (final definition in buildToolDefinitions(
          assistant: assistant,
          supportsTools: true,
        )) {
          final function = definition['function'];
          if (function is Map && function['name'] is String) {
            final parameters = function['parameters'];
            if (parameters is Map) {
              built[function['name'] as String] = parameters
                  .cast<String, dynamic>();
            }
          }
        }
        builtOk = true;
      } catch (_) {
        // schema 构建失败不阻断调用：本次退化为不校验（与改造前一致）。
      }
      // D7（2026-09-28 审查）：只在整表构建成功后落缓存。
      // 旧实现无论 try 里是否抛异常都写缓存，而 key 只认「助手启用集」，
      // 于是某次构建中途失败留下的半张/空表会把之后的合法调用一直判成
      // 「参数不合法」，且 key 未变、永远不会自愈。
      if (builtOk) {
        _argumentSchemaCache = built;
        _argumentSchemaCacheKey = key;
        usable = true;
      }
    }
    if (!usable) return null;
    final schema = _argumentSchemaCache![name];
    if (schema == null) return null;
    final fault = ToolArgumentGuard.check(schema, args);
    if (fault == null) return null;
    return <String, dynamic>{
      'ok': false,
      'data': null,
      'error': fault.toError(),
      'nextActions': <dynamic>[
        <String, dynamic>{
          'action': 'fix_argument',
          'tool': name,
          'reason': '按 parameter/expected/allowedValues 修正参数后重试同工具。',
          'arguments': args,
        },
      ],
    };
  }

  static Set<String> get handledToolNames =>
      Set<String>.unmodifiable(_toolHandlers.keys);

  /// MCP 面可调用名单（互斥双模分区，2026-09-13 收口）。
  ///
  /// 设计契约：**agent 模式与 MCP 模式互斥，同一时间只用一种**；MCP 是
  /// 纯工具执行面，Agent 独有的上下文/技能扩展不对外暴露——被剔除的四
  /// 个正是 route_task `modeCapabilities.agentContextTools` 建模的扩展
  /// （缺席时 route_task 已优雅降级为 mode=mcp，不推荐、不引用）：
  /// - get_agent_runtime_guide：报告注入/记忆等 Agent 侧管线状态；
  /// - get_solab_skill / get_apk_knowledge / get_installed_skills：
  ///   Agent 按需技能与知识扩展。
  /// 补丁经验（get/save/record_apk_patch_memory）与笔记是**改包工作流的
  /// 状态件**（产物指纹反查有真机回归锁），归共享执行核心，不在此列。
  static Set<String> get mcpCallableToolNames {
    final schemaToolNames = LocalToolRegistry.specs
        .map((spec) => spec.name)
        .toSet();
    return Set<String>.unmodifiable(
      handledToolNames.intersection(schemaToolNames).difference(<String>{
        LocalToolNames.askUser,
        LocalToolNames.textToSpeech,
        LocalToolNames.agentRuntimeGuide,
        LocalToolNames.apkSkill,
        LocalToolNames.apkKnowledge,
        LocalToolNames.installedSkills,
        // 运行时控制面走 Agent 面：MCP 侧的状态口只有 mcp_task_status，
        // 把 task_status/evidence_query/... 一并发到 MCP 面会出现两套口径
        // （第 72 项定案：运行时控制 = Agent 面能力）。
        ...LocalToolNames.runtimeControl,
        // 目标工具改的是会话模式（免审执行），同属运行时控制面，不发到 MCP。
        LocalToolNames.goalGet,
        LocalToolNames.goalCreate,
        LocalToolNames.goalUpdate,
      }),
    );
  }

  /// 三个「环境级」provider 的进程级兜底（报告 ⑤-b）。
  ///
  /// 病根：这些工具的参数是 `ToolContext` 上的可选 provider，而**两条真实链路都没
  /// 传**——端内 Agent 面只传 chatService，MCP 面的 worldBookGetter/agentSkillGetter/
  /// instructionInjectionGetter 从未 configure。于是 `get_apk_knowledge` /
  /// `get_installed_skills` / 指令注入类工具在真机上一律回
  /// world_book_unavailable / skill_store_unavailable，功能明明做了却用不了。
  ///
  /// 兜底值在**实例化点**注入（main.dart 的 create 回调里），单实例、不动生命周期；
  /// 显式传入的 context 值优先。
  static WorldBookProvider Function()? worldBookResolver;

  /// 聊天服务兜底（`get_apk_patch_memory` 等按会话读库的工具用它）。
  ///
  /// 与上面的三个同源：子代理/工作台/MCP 面不传 chatService 时，
  /// 工具只会回 `chat_service_unavailable`。进程级注入点与 ChatService 的创建点
  /// 相同（main.dart），保证各面拿到同一个实例。
  static ChatService Function()? chatServiceResolver;

  /// 记忆库兜底（F-36，2026-10-04）：端内 Agent 面分发时从不传
  /// memoryRepository、也没有兜底 resolver，导致 `get_apk_patch_memory`
  /// 的「补丁经验检索」整条必挂（且被误报成 chat_service_unavailable）。
  /// 注入点与 chatServiceResolver 同在 main.dart 的进程级创建点。
  static MemoryRepository Function()? memoryRepositoryResolver;

  /// 助手列表兜底（MCP 面选作用域用）。与其它 resolver 同理：后台/Activity 被回收
  /// 时 `rootNavigatorKey.currentContext` 为 null，走 context 读会整条失败。
  static AssistantProvider Function()? assistantResolver;
  static AgentSkillProvider Function()? agentSkillResolver;
  static InstructionInjectionProvider Function()? instructionInjectionResolver;

  static Future<String?> tryHandleToolCall(
    String name,
    Map<String, dynamic> args,
    Assistant? assistant, {
    TextToSpeechStarter? onSpeakText,
    ChatService? chatService,
    WorldBookProvider? worldBookProvider,
    AgentSkillProvider? agentSkillProvider,
    InstructionInjectionProvider? instructionInjectionProvider,
    String? conversationId,
    MemoryRepository? memoryRepository,
    String analyzerContextKey = 'app',
  }) async {
    // 模型调用的是发布名（analyzer_open 等）；localToolIds 存内部名
    // （analyzer.open 等），先反查归一，声明/分派/检查点全用内部名。
    name = AnalyzerToolNames.internalName(name);
    // 参数表必须可写：ToolArgumentGuard 的归一（别名搬运、integer/bool 转换）
    // 是**原地**写回，传 const 字面量 / Map.unmodifiable 时它会抛
    // `Unsupported operation: Cannot modify unmodifiable map`——守卫自己把调用
    // 打死，且是非结构化异常（与 DEF-02 同类，2026-09-20 本批测试实测）。
    // 只在这种情况下复制；常规路径（jsonDecode 出来的可变表）零复制。
    args = _writableArgs(args);
    if (assistant == null || !assistant.localToolIds.contains(name)) {
      return null;
    }
    final context = ToolContext(
      assistant: assistant,
      chatService: chatService ?? chatServiceResolver?.call(),
      memoryRepository: memoryRepository ?? memoryRepositoryResolver?.call(),
      // 显式入参优先；没传就取进程级兜底（见上面的 resolver 注释）。
      worldBookProvider: worldBookProvider ?? worldBookResolver?.call(),
      agentSkillProvider: agentSkillProvider ?? agentSkillResolver?.call(),
      instructionInjectionProvider:
          instructionInjectionProvider ?? instructionInjectionResolver?.call(),
      conversationId: conversationId,
      onSpeakText: onSpeakText,
      analyzerContextKey: analyzerContextKey,
    );
    // A4（2026-09-19 审核）：参数预校验过去只在 MCP 面接（mcp_http_server），
    // Agent 面（应用内直分发）没接 —— DEF-02 那类 `as num?` 未捕获异常在
    // 端内链路仍可复现，两面两套口径。这里用**同一份 schema 来源**
    // （buildToolDefinitions）在分发前校验一次；MCP 面已有自己的快路径，
    // 第二遍看到的是已被归一过的参数，无副作用。
    final argumentFault = _guardArguments(name, args, assistant);
    if (argumentFault != null) {
      return jsonEncode(argumentFault);
    }
    // 会话模式（输入框斜杠命令 /plan /goal）在**唯一咽喉**处拦变更类工具：
    // PLAN 直接只读拒绝，GOAL 未设目标前拒绝。工具面那侧已把这些工具摘掉，
    // 这里是执行期的第二道（MCP 面与直连都过这条）。
    final modeDenial = SessionModeRuntime.denyReason(conversationId, name);
    if (modeDenial != null) {
      return jsonEncode(modeDenial);
    }
    // AI 能力开关（2026-09-29 用户：除目标模式、计划模式外，其余能力面都做成
    // 开关，开了由 AI 自己判断）：开关关掉的工具，工具面那侧已摘 schema，这里
    // 是执行期第二道，防止残留提示词/手滑调用绕过开关。
    final capabilityDenial = AgentCapabilityPolicy.denyReason(assistant, name);
    if (capabilityDenial != null) {
      return jsonEncode(capabilityDenial);
    }
    final handler = _toolHandlers[name];
    if (handler != null) {
      // 作用域规则：端内对话按 conversationId 隔离；MCP host 模式固定
      // 'mcp-host' 单一作用域——产物/索引是工作目录里的物理状态，按 HTTP
      // 会话切分会导致签名登记跨会话不可见（实测 finding A-3）。
      final scopeId = conversationId?.trim().isNotEmpty == true
          ? conversationId
          : (analyzerContextKey == 'app'
                ? null
                : analyzerContextKey.startsWith('mcp:')
                ? 'mcp-host'
                : analyzerContextKey);
      // C 批 / §14.15.6：Dart 面工具耗时记账。本函数是**两面对共用的唯一咽喉**
      // （Agent 面经 tool_handler_service、MCP 面经 mcp_http_server），所以计时
      // 只在这里加一层 .then，不改内部逻辑。记发布名（analyzer_open 等），
      // 与 tools/list 同叫法；只在失败时取一次短错误码，成功路径零额外解析。
      final statsTool = AnalyzerToolNames.publishedName(name);
      final statsWatch = Stopwatch()..start();
      return ApkWorkspaceBindingService.runInScope(scopeId, () async {
        // 运行时层（§5/§8/§11/§18）：每次工具调用都过一遍信封、证据、
        // 预算和审计。wrapOrRun 保证业务只执行一次；没选定 APK 或运行时
        // 不可用时退化为裸执行，保持原有行为不变。
        final output = await RuntimeBridge.instance.wrapOrRun(
          tool: name,
          args: args,
          scopeKey: scopeId ?? 'workbench',
          // 任务绑定到本次实际处理的包：工作台记的「当前 APK」可能已过期，
          // 以工具参数为准才不会出现「任务里的包跟正在分析的对不上」。
          apkPath: (args['apkPath'] ?? args['path'])?.toString(),
          allowExternalMcp: analyzerContextKey.startsWith('mcp:'),
          run: () => handler(args, context),
        );
        if (output != null &&
            assistant.id == 'builtin-apk-mod' &&
            _apkCheckpointTools.contains(name)) {
          try {
            await ApkWorkspaceBindingService.recordToolCheckpoint(
              tool: name,
              arguments: args,
              result: output,
            );
          } catch (_) {
            // 续接快照失败不影响工具本身的结果。
          }
        }
        // R5：统一补齐 recoverable，不再依赖每个 handler 自觉带标记。
        // MCP 面跳过：出口 _normalizeToolOutput 对所有错误信封统一套用
        // 同一 ToolErrorPolicy 判定（recovery 契约由归一层保证），这里再
        // enrich 是对同一payload的第二次全量解码（结果可达 512KB）。
        return output == null
            ? null
            : (analyzerContextKey.startsWith('mcp:')
                  ? output
                  : ToolErrorPolicy.enrich(output));
      }).then(
        (output) {
          statsWatch.stop();
          final ok = output != null && ToolCallLoopGuard.succeeded(output);
          DartToolStats.record(
            statsTool,
            ok,
            statsWatch.elapsedMicroseconds,
            // 只有失败样本才扫一次错误码（成功路径零额外解析）。
            error: !ok && output != null ? DartToolStats.errorHint(output) : '',
          );
          return output;
        },
        onError: (Object error, StackTrace stackTrace) {
          // 抛异常也要成为一条失败样本（TOOL_EXCEPTION 那类正是长尾要抓的
          // 东西），记完按原栈抛回，调用方看到的行为不变。
          statsWatch.stop();
          DartToolStats.record(
            statsTool,
            false,
            statsWatch.elapsedMicroseconds,
            error: error.toString(),
          );
          Error.throwWithStackTrace(error, stackTrace);
        },
      );
    }
    // 设备工具（定位/日历/健康/提醒/天气/屏幕时间）：契约与分发取自上游 1.2.7。
    return DeviceLocalToolSchemas.tryHandle(name, args, assistant);
  }

  /// 保证参数表可写（见 [tryHandleToolCall] 里的说明）。
  ///
  /// 探测方式：写一个探针键再删掉——`Map` 没有 `isModifiable`，这是唯一
  /// 不复制就能判断的办法。探针键存在（极罕见）时不冒险，直接复制。
  static Map<String, dynamic> _writableArgs(Map<String, dynamic> args) {
    const probe = '__solab_writable_probe__';
    if (args.containsKey(probe)) return Map<String, dynamic>.of(args);
    try {
      args[probe] = null;
      args.remove(probe);
      return args;
    } on UnsupportedError {
      return Map<String, dynamic>.of(args);
    } on TypeError {
      // 调用方传的是 Map<String, String> 这类收窄的值类型（测试与内部调用常见），
      // 写 null 探针会抛 TypeError——同样走复制路径，别让守卫把它当致命错误。
      return Map<String, dynamic>.of(args);
    }
  }
}
