import 'dart:async';
import 'dart:convert';

import 'package:flutter/widgets.dart';
import 'package:provider/provider.dart';
import '../../../core/models/assistant.dart';
import '../../../core/models/model_spec.dart';
import '../../../core/models/reasoning_request.dart';
import '../../../core/providers/assistant_provider.dart';
import '../../../core/providers/environment_provider.dart';
import '../../../core/providers/mcp_provider.dart';
import '../../../core/providers/memory_provider.dart';
import '../../../core/providers/memory_provider_v2.dart';
import '../../../core/providers/settings_provider.dart';
import '../../../core/providers/tts_provider.dart';
import '../../../core/services/api/chat_api_service.dart';
import '../../../core/services/api/json_schema_utils.dart';
import '../../../core/services/model_spec/model_spec_resolver.dart';
import '../../../features/solab_apk/services/apk_workspace_binding_service.dart';
import '../../../core/services/chat/chat_service.dart';
import '../../../core/services/mcp/mcp_tool_service.dart';
import '../../../core/services/memory/memory_pipeline.dart';
import '../../../core/services/memory/memory_tools.dart';
import '../../../core/services/search/search_tool_service.dart';
import '../../../core/services/tools/tool_schema_overrides.dart';
import '../../../core/services/skills/skills_service.dart';
import '../../../core/services/workspace/tool_run_registry.dart';
import '../../../core/services/workspace/workspace_runtime.dart';
import '../../../core/services/workspace/workspace_tools_service.dart';
import '../../../core/providers/workspace_provider.dart';
import 'apk_analysis_guard.dart';
import 'ask_user_interaction_service.dart';
import 'built_in_tool_names.dart';
import 'local_tools_service.dart';
import 'tool_approval_service.dart';
import 'subagent_registry.dart';
import 'subagent_loop.dart';
import 'session_mode.dart';
import '../../workflow/engine/workflow_engine.dart';
import '../../../core/services/local_tools/tool_call_loop_guard.dart';
import '../../../core/services/api/api_session_scope.dart';

/// 工具调用处理服务
///
/// 处理各类工具调用：
/// - MCP 工具
/// - Memory 工具 (§10)
/// - Search 工具
class ToolHandlerService {
  ToolHandlerService({required this.contextProvider});

  /// Build context (used for accessing providers)
  final BuildContext contextProvider;

  // ===== SoLab：APK 分析预算守卫（任务级状态）=====
  //
  // 守卫按**会话**持有：同一任务里的多次工具调用共享预算、阶段与证据状态；
  // 上游把工具链重写后这条链丢了（见 docs/上游对接进度.md §12.5-A）。
  // 非 APK 工具在 `before()` 里直接放行，因此不影响其它工具的调用路径。
  final Map<String, ApkAnalysisGuard> _solabApkGuards = <String, ApkAnalysisGuard>{};

  ApkAnalysisGuard _solabApkGuardFor(String? conversationId) =>
      _solabApkGuards.putIfAbsent(
        conversationId ?? '__default__',
        ApkAnalysisGuard.new,
      );

  /// 会话级 MCP 白名单闸门（SoLab 自研）：`Conversation.mcpServerIds` 非空时
  /// 对助手可见的 MCP 服务集合**求交收窄**；为空/取不到会话则返回 null（不收窄）。
  ///
  /// 上游把 `buildToolCallHandler` 整体重写后这条链丢了（见
  /// `docs/上游对接进度.md` §12.6），而 `McpToolService` 侧的 `_narrowServers`
  /// 仍在，所以只需在调用点把会话白名单算出来传下去。
  Set<String>? _conversationMcpGate(String? conversationId) {
    if (conversationId == null || conversationId.isEmpty) return null;
    final ChatService chat;
    try {
      chat = contextProvider.read<ChatService>();
    } catch (_) {
      return null;
    }
    final ids = chat.getConversationMcpServers(conversationId);
    return ids.isEmpty ? null : ids.toSet();
  }

  WorkspaceToolsService _workspaceTools() =>
      ToolHandlerService.workspaceToolsFor(contextProvider);

  /// 用一棵 provider 树构建工作区工具服务（聊天面与 MCP 面共用同一份构造）。
  ///
  /// MCP 面没有会话/BuildContext：main 在构建 provider 树时调用它一次并缓存，
  /// 通过 [WorkspaceToolsService.sharedInstanceResolver] 交给 MCP 执行链路。
  static WorkspaceToolsService workspaceToolsFor(BuildContext contextProvider) {
    try {
      final chat = contextProvider.read<ChatService>();
      final workspaces = contextProvider.read<WorkspaceProvider>();
      Future<void> Function(String skillId)? onSkillRead;
      Future<void> Function()? onShellCompleted;
      try {
        final skills = contextProvider.read<SkillsService>();
        onSkillRead = skills.incrementUseCount;
        onShellCompleted = skills.rescan;
      } catch (_) {}
      return WorkspaceToolsService(
        registry: contextProvider.read<ToolRunRegistry>(),
        runtimeProvider: contextProvider.read<WorkspaceRuntimeProvider>(),
        updateConversationExtras: chat.updateConversationExtras,
        touchLastUsed: workspaces.touchLastUsed,
        onSkillRead: onSkillRead,
        onShellCompleted: onShellCompleted,
        loadEnvironment: contextProvider
            .read<EnvironmentProvider?>()
            ?.loadExecutionConfig,
        isToolEnabled: (id, name) =>
            workspaces.byId(id)?.isToolEnabled(name) ?? false,
      );
    } catch (_) {
      return WorkspaceToolsService();
    }
  }

  // ============================================================================
  // Tool Schema Sanitization
  // ============================================================================

  /// Sanitize/translate JSON Schema to each provider's accepted subset.
  ///
  /// Different providers (Google, OpenAI, Claude) have different requirements
  /// for tool parameter schemas. This method normalizes schemas to work across
  /// all providers.
  static Map<String, dynamic> sanitizeToolParametersForProvider(
    Map<String, dynamic> schema,
    ProviderKind kind,
  ) {
    Map<String, dynamic> clone = _deepCloneMap(schema);
    // Inline local $ref targets first: the allow-list below drops $ref/$defs,
    // so an unresolved reference would reach the model as an empty schema and
    // the whole nested object would silently vanish from the tool call.
    clone = resolveJsonSchemaRefs(
      clone,
      expandAdditionalProperties: kind != ProviderKind.google,
    );
    clone = _sanitizeNode(clone, kind) as Map<String, dynamic>;
    return clone;
  }

  static dynamic _sanitizeNode(dynamic node, ProviderKind kind) {
    if (node is List) {
      return node.map((e) => _sanitizeNode(e, kind)).toList();
    }
    if (node is! Map) return node;

    final m = Map<String, dynamic>.from(node);
    // Remove $schema as it's not needed for tool definitions
    m.remove(r'$schema');

    // Convert 'const' to 'enum' for compatibility
    if (m.containsKey('const')) {
      final v = m['const'];
      if (v is String || v is num || v is bool) {
        m['enum'] = [v];
        // Keep the declared type in sync so a non-string const is not mistaken
        // for a string enum downstream.
        if (m['type'] == null) {
          if (v is bool) {
            m['type'] = 'boolean';
          } else if (v is int) {
            m['type'] = 'integer';
          } else if (v is num) {
            m['type'] = 'number';
          } else {
            m['type'] = 'string';
          }
        }
      }
      m.remove('const');
    }

    // Flatten anyOf/oneOf/allOf to first variant for simplicity
    for (final key in [
      'anyOf',
      'oneOf',
      'allOf',
      'any_of',
      'one_of',
      'all_of',
    ]) {
      if (m[key] is List && (m[key] as List).isNotEmpty) {
        final first = (m[key] as List).first;
        final flattened = _sanitizeNode(first, kind);
        m.remove(key);
        if (flattened is Map<String, dynamic>) {
          m
            ..remove('type')
            ..remove('properties')
            ..remove('items');
          m.addAll(flattened);
        }
      }
    }

    // Normalize type array to single type
    final t = m['type'];
    if (t is List && t.isNotEmpty) m['type'] = t.first.toString();

    // Normalize items array to single item
    final items = m['items'];
    if (items is List && items.isNotEmpty) m['items'] = items.first;
    if (m['items'] is Map) m['items'] = _sanitizeNode(m['items'], kind);

    // Recursively sanitize properties
    if (m['properties'] is Map) {
      final props = Map<String, dynamic>.from(m['properties']);
      final norm = <String, dynamic>{};
      props.forEach((k, v) {
        norm[k] = _sanitizeNode(v, kind);
      });
      m['properties'] = norm;
    }

    // additionalProperties can itself be a schema.
    if (m['additionalProperties'] is Map) {
      m['additionalProperties'] = _sanitizeNode(
        m['additionalProperties'],
        kind,
      );
    }

    // Keep only allowed keys based on provider
    Set<String> allowed;
    switch (kind) {
      case ProviderKind.google:
        allowed = {
          'type',
          'description',
          'properties',
          'required',
          'items',
          'enum',
        };
        break;
      case ProviderKind.openai:
      case ProviderKind.claude:
        allowed = {
          'type',
          'description',
          'properties',
          'required',
          'items',
          'enum',
          'additionalProperties',
        };
        break;
    }
    m.removeWhere((k, v) => !allowed.contains(k));
    return m;
  }

  static Map<String, dynamic> _deepCloneMap(Map<String, dynamic> input) {
    return jsonDecode(jsonEncode(input)) as Map<String, dynamic>;
  }

  /// SoLab：把 APK 分析守卫的拦截决定转成**工具错误信封**（纯函数，便于单测）。
  ///
  /// - `canRequestBudget`：预算耗尽但可申请追加 → 返回带 `ask_user` 提问参数的信封，
  ///   MCP 调用方没有提问工具时走 `mcpFallback` 文字授权。
  /// - 其余拦截 → `apk_analysis_guard_blocked` + 换路径指引。

  static bool _isPollingToolCall(String name, Map<String, dynamic> arguments) {
    // 工作区工具（shell/read_file/…）不在环路闸门覆盖范围：它们的语义由上游
    // 决定，且同一条命令在「装 → 改 → 删」这类多步流程里被重复执行是正常的，
    // 拦下来会把合法流程判成循环。
    if (WorkspaceToolsService.toolNames.contains(name)) return true;
    if (name == 'mcp_task_status' || name == 'open') return true;
    if (name == LocalToolNames.soAnalyze) {
      if (arguments['action'] == 'status' ||
          arguments['blutterAction'] == 'status') {
        return true;
      }
      // 带 jobId 的后台结果轮询：后台任务结果随时间合法变化，同参重查是正常
      // 轮询不是循环（2026-09-15 真机 P2：blutter locate 曾被误拦）。
      if (arguments['jobId']?.toString().isNotEmpty ?? false) return true;
      return false;
    }
    // 任何携带 jobId 的调用都是后台任务轮询语义。
    return (arguments['jobId'] ?? arguments['job_id'])?.toString().isNotEmpty ??
        false;
  }

  static String apkGuardBlockEnvelope(
    ApkAnalysisGuardDecision decision,
    String tool,
  ) {
    if (decision.canRequestBudget) {
      return jsonEncode(<String, dynamic>{
        'type': 'tool_error',
        'error': 'apk_analysis_budget_authorization_required',
        'message': decision.message,
        'tool': tool,
        'nextRequiredTool': LocalToolNames.askUser,
        'questionArguments': const <String, dynamic>{
          'questions': <Map<String, dynamic>>[
            <String, dynamic>{
              'id': 'apk_budget_extension',
              'question': '当前 APK 分析预算已用完，是否授权追加一部分预算继续定位？',
              'type': 'single',
              'options': <String>['追加 40 次', '追加 80 次', '停止并汇报'],
            },
          ],
        },
        'mcpFallback': 'MCP 调用方没有提问工具时，用文字取得用户明确授权后再继续。',
      });
    }
    return _toolError(
      error: 'apk_analysis_guard_blocked',
      message: decision.message,
      tool: tool,
      instruction:
          '不要重复调用。根据已有报告、候选和失败状态切换到返回结果中的替代路径；没有新证据时直接报告当前结论。',
    );
  }

  static String _toolError({
    required String error,
    required String message,
    required String tool,
    String? instruction,
  }) {
    return jsonEncode({
      'type': 'tool_error',
      'error': error,
      'message': message,
      'tool': tool,
      if (instruction != null) 'instruction': instruction,
    });
  }

  // ============================================================================
  // Tool Definitions Builder
  // ============================================================================

  McpToolRouteSnapshot captureMcpToolRoutes(Assistant? assistant) {
    return contextProvider.read<McpToolService>().captureRoutesForAssistant(
      contextProvider.read<McpProvider>(),
      contextProvider.read<AssistantProvider>(),
      assistantId: assistant?.id,
      reservedNames: BuiltInToolNames.all,
    );
  }

  /// Build tool definitions for API call.
  ///
  /// Returns a list of tool definitions including:
  /// - Search tool (if enabled and model supports tools)
  /// - Memory tools (if assistant has memory / past-recall enabled)
  /// - MCP tools (from selected servers for the assistant)
  /// Whether the chat being generated is a throwaway one.
  ///
  /// Scheduled sends can target a different conversation from the visible one.
  bool _isTemporaryConversation(String? conversationId) {
    try {
      final chatService = contextProvider.read<ChatService>();
      return chatService.isTemporaryConversation(
        conversationId ?? chatService.currentConversationId,
      );
    } catch (_) {
      return false;
    }
  }

  List<Map<String, dynamic>> buildToolDefinitions(
    SettingsProvider settings,
    Assistant? assistant,
    String providerKey,
    String modelId,
    bool hasBuiltInSearch, {
    required bool Function(String providerKey, String modelId) isToolModel,
    McpToolRouteSnapshot? mcpRouteSnapshot,
    WorkspaceToolContext? workspaceContext,
    String? conversationId,
    // SoLab：本轮只声明这些工具（null=全量；空集=不声明任何工具）。
    // 由 ToolRouter/APK 任务直通计算，见 docs/上游对接进度.md §12.5-C。
    Set<String>? includeToolNames,
  }) {
    final List<Map<String, dynamic>> toolDefs = <Map<String, dynamic>>[];
    final supportsTools = isToolModel(providerKey, modelId);

    // Search tool (skip when Gemini built-in search is active)
    if (assistant?.searchEnabled == true &&
        !hasBuiltInSearch &&
        supportsTools) {
      toolDefs.add(SearchToolService.getToolDefinition());
    }

    // Memory tools (§10.1)
    if (settings.legacyMemoryMode) {
      if (assistant?.enableMemory == true && supportsTools) {
        toolDefs.addAll(
          MemoryTools.legacyDefinitions(settings.resolvedMemoryPromptLang),
        );
      }
    } else if (supportsTools && assistant != null) {
      toolDefs.addAll(
        MemoryTools.buildDefinitions(
          lang: settings.resolvedMemoryPromptLang,
          writeScope: assistant.memoryWriteScope,
          enableMemory: assistant.enableMemory,
          allowPastConversationRecall: assistant.allowPastConversationRecall,
          allowMemoryWrites: !_isTemporaryConversation(conversationId),
        ),
      );
    }

    // ===== SoLab 注册口（上游重写本方法时整块丢失，见 docs/上游对接进度.md §12.6）=====
    // 这里已经解析出 settings + provider/model + 会话，与主对话同源，不需要再造一套
    // provider 解析；少任何一处，对应能力在真机上直接不可用（子代理会回
    // 「模型调用口尚未注册」，工作流 ai_generate 节点会报 host 缺失）。
    LocalToolsService.subAgentHandler.generator =
        ({
          required String prompt,
          required String systemPrompt,
          required String? conversationId,
        }) async {
          final config = settings.getProviderConfig(providerKey);
          return ApiSessionScope.run(
            () => ChatApiService.generateText(
              config: config,
              modelId: modelId,
              prompt: systemPrompt.isEmpty
                  ? prompt
                  : '$systemPrompt\n\n---\n\n$prompt',
              skipImageParsing: true,
            ),
            conversationId,
          );
        };

    // 带工具循环的驱动器：子代理因此能真的读写查，而不是只做一次模型调用。
    // 子代理是「再进一次模型循环」的入口，必须补齐与主链路同源的闸门，
    // 否则等于给模型留了一条不受控的重试/探测后门。
    final subAgentLoopGuard = ToolCallLoopGuard();
    final subAgentAnalysisGuard = conversationId == null
        ? ApkAnalysisGuard()
        : _solabApkGuardFor(conversationId);
    LocalToolsService.subAgentHandler.loopDriver = SubAgentLoopDriver(
      allowedToolIds: assistant?.localToolIds.toSet(),
      step: ({required messages, required tools}) async {
        final result = await ApiSessionScope.run(
          () => ChatApiService.generateMessage(
            config: settings.getProviderConfig(providerKey),
            modelId: modelId,
            conversationId: conversationId,
            messages: messages,
            tools: tools.isEmpty ? null : tools,
            skipImageParsing: true,
            allowImagesApiRouting: false,
            builtInSearchOnly: false,
          ),
          conversationId,
        );
        return SubAgentStep.fromParts(result.parts);
      },
      invokeTool: (name, args) async {
        // 会话上下文以循环放进 Zone 的派发会话为准（比注册时的快照更准）。
        final scopeConversationId =
            SubAgentDispatchScope.conversationId ?? conversationId;
        final loopDecision = subAgentLoopGuard.check(
          name,
          args,
          polling: _isPollingToolCall(name, args),
          readOnly: !ToolCallLoopGuard.changesState(name, args),
        );
        if (!loopDecision.allowed) {
          return _toolError(
            error: 'loop_detected',
            message: loopDecision.message,
            tool: name,
            instruction: '直接使用上一次结果，或改变参数与分析路径；不要再重复同一调用。',
          );
        }
        if (name == LocalToolNames.routeTask) {
          subAgentAnalysisGuard.begin((args['goal'] ?? '').toString());
        }
        final budget = subAgentAnalysisGuard.before(name, args);
        if (!budget.allowed) {
          return _toolError(
            error: 'apk_analysis_guard_blocked',
            message: budget.message,
            tool: name,
            instruction:
                '不要重复调用。根据已有报告与失败状态切换到替代路径；没有新证据时直接报告当前结论。',
          );
        }
        final result = await LocalToolsService.tryHandleToolCall(
          name,
          args,
          assistant,
          conversationId: scopeConversationId,
        );
        if (result != null) {
          if (ToolCallLoopGuard.changesState(name, args) &&
              ToolCallLoopGuard.succeeded(result)) {
            subAgentLoopGuard.advanceState(name, args);
          }
          subAgentAnalysisGuard.record(name, args, result);
        }
        return result ??
            '{"ok":false,"error":"tool_unavailable","message":"子代理的工具 $name 当前不可用"}';
      },
      definitionFor: LocalToolsService.definitionFor,
    );

    // 工作流引擎调用口（同子代理模式）：ai_generate 节点走与主对话同源的
    // provider/model；命令节点需要沙盒会话，host 里明确报未接线。
    // 按会话注册：闭包捕获注册这一刻的 provider/model/conversationId，只留一个
    // 进程级槽位会让 B 会话的 AI 节点用 A 的模型生成、把账记在 A 的会话上。
    LocalToolsService.workflowHandler.registerHost(
      conversationId,
      _WorkflowToolHost(
        onGenerate: ({required prompt, system}) async {
          final config = settings.getProviderConfig(providerKey);
          final merged = (system == null || system.isEmpty)
              ? prompt
              : '''$system

---

$prompt''';
          return ApiSessionScope.run(
            () => ChatApiService.generateText(
              config: config,
              modelId: modelId,
              prompt: merged,
              skipImageParsing: true,
            ),
            conversationId,
          );
        },
        onCommand: (command) async {
          // 面向 Agent/MCP 面的错误文案用英文（同 mcp_http_server 的约定）。
          throw StateError(
            'Command nodes need a sandbox session (not wired yet).',
          );
        },
      ),
    );

    // 会话模式（输入框斜杠命令 /plan /goal）决定模型看到的工具面：
    // PLAN 与未设目标的 GOAL 会把变更类工具摘掉（执行期兜底在
    // LocalToolsService.tryHandleToolCall 的同一处咽喉）。
    final solabLocalTools =
        SessionModeRuntime.policyFor(conversationId).filterDefinitions(
              LocalToolsService.buildToolDefinitions(
                assistant: assistant,
                supportsTools: supportsTools,
              ),
            );

    // Local tools（已按会话模式 /plan /goal 过滤，见上方 solabLocalTools）
    toolDefs.addAll(solabLocalTools);

    // MCP tools
    final mcpTools = _buildMcpToolDefinitions(
      settings: settings,
      assistant: assistant,
      providerKey: providerKey,
      supportsTools: supportsTools,
      mcpRouteSnapshot: mcpRouteSnapshot,
    );
    toolDefs.addAll(mcpTools);

    if (supportsTools && workspaceContext != null) {
      final canImageInput = ModelSpecResolver.instance
          .spec(settings.getProviderConfig(providerKey), modelId)
          .input
          .contains(Modality.image);
      toolDefs.addAll(
        _workspaceTools()
            .buildToolDefinitions(workspaceContext)
            .where(
              (definition) =>
                  canImageInput ||
                  (definition['function'] as Map)['name'] != 'view_image',
            ),
      );
    }

    final overrides = settings.toolSchemaOverrides;
    final resolved = overrides.isEmpty
        ? toolDefs
        : ToolSchemaOverrides.apply(toolDefs, overrides);
    return applyToolSelection(resolved, includeToolNames);
  }

  /// SoLab：按本轮选中集合**过滤出口工具声明**（纯函数，便于单测）。
  ///
  /// - `null`：全量（保持上游行为）
  /// - 空集：本轮不声明任何工具（纯闲聊轮）
  /// - 非空集：只声明集合里的名字
  ///
  /// 只做出口过滤，不改上游的组装顺序与 schema 覆盖逻辑（§12.5-C）。
  static List<Map<String, dynamic>> applyToolSelection(
    List<Map<String, dynamic>> defs,
    Set<String>? includeToolNames,
  ) {
    if (includeToolNames == null) return defs;
    if (includeToolNames.isEmpty) {
      return const <Map<String, dynamic>>[];
    }
    return defs
        .where((definition) {
          final fn = definition['function'];
          final name = fn is Map ? fn['name']?.toString() : null;
          return name != null && includeToolNames.contains(name);
        })
        .toList(growable: false);
  }

  /// Build MCP tool definitions from connected servers.
  List<Map<String, dynamic>> _buildMcpToolDefinitions({
    required SettingsProvider settings,
    required Assistant? assistant,
    required String providerKey,
    required bool supportsTools,
    McpToolRouteSnapshot? mcpRouteSnapshot,
  }) {
    if (!supportsTools) return [];

    final mcp = contextProvider.read<McpProvider>();
    final toolSvc = contextProvider.read<McpToolService>();
    final tools = toolSvc.listAvailableToolsForAssistant(
      mcp,
      contextProvider.read<AssistantProvider>(),
      assistant?.id,
      routeSnapshot: mcpRouteSnapshot,
      reservedNames: BuiltInToolNames.all,
    );

    if (tools.isEmpty) return [];

    final providerCfg = settings.getProviderConfig(providerKey);
    final providerKind = ProviderConfig.classify(
      providerCfg.id,
      explicitType: providerCfg.providerType,
    );

    return tools.map((t) {
      Map<String, dynamic> baseSchema;
      if (t.schema != null && t.schema!.isNotEmpty) {
        baseSchema = Map<String, dynamic>.from(t.schema!);
      } else {
        final props = <String, dynamic>{
          for (final p in t.params) p.name: {'type': (p.type ?? 'string')},
        };
        final required = [
          for (final p in t.params.where((e) => e.required)) p.name,
        ];
        baseSchema = {
          'type': 'object',
          'properties': props,
          if (required.isNotEmpty) 'required': required,
        };
      }
      final sanitized = sanitizeToolParametersForProvider(
        baseSchema,
        providerKind,
      );
      return {
        'type': 'function',
        'function': {
          'name': t.name,
          if ((t.description ?? '').isNotEmpty) 'description': t.description,
          'parameters': sanitized,
        },
      };
    }).toList();
  }

  // ============================================================================
  // Tool Call Handler
  // ============================================================================

  /// Build tool call handler function.
  ///
  /// Returns a function that handles tool calls by name and arguments.
  /// Supports:
  /// - Search tool calls
  /// - Memory tool calls (§10)
  /// - MCP tool calls
  /// 读不到 ChatService 时返回 null（而不是抛 ProviderNotFoundException）。
  ///
  /// 工具链的可选依赖不该让整条链炸掉：撤销权限/测试环境/后台恢复都可能没有
  /// Provider，兜底交给进程级 resolver。
  ChatService? _maybeReadChatService(BuildContext contextProvider) {
    try {
      return contextProvider.read<ChatService>();
    } catch (_) {
      return null;
    }
  }
  ToolCallHandler? buildToolCallHandler(
    SettingsProvider settings,
    Assistant? assistant, {
    ToolApprovalService? approvalService,
    AskUserInteractionService? askUserService,
    String? conversationId,
    McpToolRouteSnapshot? mcpRouteSnapshot,
    WorkspaceToolContext? workspaceContext,
  }) {
    final mcp = contextProvider.read<McpProvider>();
    final toolSvc = contextProvider.read<McpToolService>();
    // 会话级工具（任务清单）需要 ChatService：在异步间隙**之前**取好，避免
    // 跨 await 使用 BuildContext。
    //
    // 容错读取（同类缺陷扫查）：这里过去是硬 read，缺 Provider 时整条工具链直接抛
    // ProviderNotFoundException（phone_control 的「撤销权限后不得触达原生」用例就是
    // 这么炸的）。现在读不到就退回进程级兜底（main.dart 注入的同一实例）；
    // 都没有则按 null 往下走，由工具自己回 conversation_required / chat_service_unavailable。
    final localToolChatService =
        _maybeReadChatService(contextProvider) ??
        LocalToolsService.chatServiceResolver?.call();
    // Capture AssistantProvider reference before async gap to avoid
    // use_build_context_synchronously warning
    final assistantProvider = contextProvider.read<AssistantProvider>();
    // SoLab：本会话的 APK 分析守卫；每轮用户回合复位「回合内」状态。
    final solabApkGuard = _solabApkGuardFor(conversationId);
    solabApkGuard.beginUserTurn();
    final routes =
        mcpRouteSnapshot ??
        toolSvc.captureRoutesForAssistant(
          mcp,
          assistantProvider,
          assistantId: assistant?.id,
          reservedNames: BuiltInToolNames.all,
          conversationServerIds: _conversationMcpGate(conversationId),
        );

    String approvalIdFor(String name, String? toolCallId) {
      final trimmed = toolCallId?.trim();
      if (trimmed != null && trimmed.isNotEmpty) return trimmed;
      return '${name}_${DateTime.now().microsecondsSinceEpoch}';
    }

    Future<Object?> approveAndExecuteMcp(
      String name,
      Map<String, dynamic> args, {
      String? toolCallId,
    }) async {
      if (approvalService != null &&
          toolSvc.toolNeedsApprovalForAssistant(
            mcp,
            assistantProvider,
            assistantId: assistant?.id,
            toolName: name,
            routeSnapshot: routes,
            reservedNames: BuiltInToolNames.all,
            conversationServerIds: _conversationMcpGate(conversationId),
          )) {
        final result = await approvalService.requestApproval(
          toolCallId: approvalIdFor(name, toolCallId),
          toolName: name,
          arguments: args,
          conversationId: conversationId,
        );
        if (!result.approved) {
          return _toolError(
            error: 'approval_denied',
            message: result.denyReason ?? 'User denied the tool call',
            tool: name,
          );
        }
      }

      return toolSvc.callToolForAssistant(
        mcp,
        assistantProvider,
        assistantId: assistant?.id,
        toolName: name,
        arguments: args,
        routeSnapshot: routes,
        reservedNames: BuiltInToolNames.all,
        conversationServerIds: _conversationMcpGate(conversationId),
      );
    }

    final workspaceTools = workspaceContext == null ? null : _workspaceTools();

    return (name, args, {toolCallId}) async {
      try {
        if (workspaceContext != null &&
            workspaceTools != null &&
            WorkspaceToolsService.toolNames.contains(name)) {
          return await workspaceTools.handle(
            workspaceContext,
            name,
            args,
            toolCallId: toolCallId ?? '',
            approvalService: approvalService,
            conversationId: conversationId,
          );
        }

        if (routes.containsExposedName(name)) {
          return await approveAndExecuteMcp(name, args, toolCallId: toolCallId);
        }

        // Search tool
        if (name == SearchToolService.toolName &&
            assistant?.searchEnabled == true) {
          final q = (args['query'] ?? '').toString();
          return await SearchToolService.executeSearch(q, settings);
        }

        // Memory tools
        final memoryResult = await _handleMemoryToolCall(
          name,
          args,
          assistant,
          conversationId: conversationId,
        );
        if (memoryResult != null) {
          return memoryResult;
        }

        // Creating calendar events or changing reminders modifies user data,
        // so those tools always require explicit user approval first.
        if (LocalToolNames.requiresUserApproval.contains(name) &&
            assistant != null &&
            assistant.localToolIds.contains(name) &&
            approvalService != null) {
          final approval = await approvalService.requestApproval(
            toolCallId: approvalIdFor(name, toolCallId),
            toolName: name,
            arguments: args,
            conversationId: conversationId,
          );
          if (!approval.approved) {
            return _toolError(
              error: 'approval_denied',
              message: approval.denyReason ?? 'User denied the tool call',
              tool: name,
            );
          }
        }

        // Re-read phone-control permission on every call so disabling it also
        // stops a tool loop that was built with an older assistant snapshot.
        if (name == LocalToolNames.phoneControl) {
          final current = assistant == null
              ? null
              : assistantProvider.getById(assistant.id);
          if (current == null || !current.localToolIds.contains(name)) {
            return _toolError(
              error: 'permission_denied',
              message: 'Phone control is disabled for this assistant.',
              tool: name,
            );
          }
        }

        // SoLab：APK 分析预算守卫（任务级，见 docs/上游对接进度.md §12.5-A）。
        // `route_task` 开新目标时重置预算与阶段；非 APK 工具 `before()` 直接放行。
        if (name == LocalToolNames.routeTask) {
          solabApkGuard.begin((args['goal'] ?? '').toString());
        }
        final solabBudget = solabApkGuard.before(name, args);
        if (!solabBudget.allowed) {
          return apkGuardBlockEnvelope(solabBudget, name);
        }

        // Local tools
        // 2026-10-02 修复（用户实测：端内两种 agent 模式调 todo_read/todo_write 都
        // 返回 conversation_required）：这里过去没把会话上下文传下去，于是会话级
        // 工具（任务清单）永远拿不到 scope。askUser 就在同一个作用域里取
        // conversationId，本地工具没有理由不传。
        // 项目隔离（用户 2026-10-03：「不同项目绝对不能互通」）：把本会话绑定的
        // 工作区根目录压进作用域，APK 文件族（file/grep/replace/frida…）的
        // `ApkWorkspaceBindingService.workDir()` 因此按工作区取值——换项目后不会
        // 再落到上一个项目的目录里。未绑定工作区时保持原有全局目录行为。
        final localResult = await ApkWorkspaceBindingService.runInWorkspaceRoot(
          workspaceContext?.paths.workspaceHostRoot,
          // P1「工作区即项目」：默认工作区（未绑定会话自动落它）**不参与记忆隔离**
          // —— id 传 null，记忆仍按全局处理。否则未绑定会话的记忆会突然只在一个
          // 项目里可见、也不再进全局画像蒸馏（用户 2026-10-03 定的记忆口径不能动）。
          id: (workspaceContext?.workspace.isDefault ?? true)
              ? null
              : workspaceContext?.workspace.id,
          // force：这条会话没绑工作区时，zone 里必须是「明确无项目」，
          // 不能让记忆/文件工具回落到上一个会话的工作区。
          force: true,
          () => LocalToolsService.tryHandleToolCall(
            name,
            args,
            assistant,
            conversationId: conversationId,
            chatService: localToolChatService,
            onSpeakText: (text) async {
              final tts = contextProvider.read<TtsProvider>();
              if (!tts.isAvailable) {
                throw StateError('Text-to-speech is unavailable.');
              }
              unawaited(
                tts.speak(text).catchError((Object error, StackTrace stack) {
                  FlutterError.reportError(
                    FlutterErrorDetails(
                      exception: error,
                      stack: stack,
                      library: 'Kelivo local tools',
                      context: ErrorDescription('while playing text-to-speech'),
                    ),
                  );
                }),
              );
            },
          ),
        );
        if (localResult != null) {
          // SoLab：记账（文本预算/阶段状态），并把守卫回填的快照交给模型。
          return solabApkGuard.record(name, args, localResult);
        }

        if (name == LocalToolNames.askUser &&
            assistant != null &&
            assistant.localToolIds.contains(LocalToolNames.askUser)) {
          if (askUserService == null) {
            return _toolError(
              error: 'ask_user_unavailable',
              message: 'Ask user interaction service is unavailable.',
              tool: name,
            );
          }
          try {
            final result = await askUserService.requestAnswer(
              toolCallId: (toolCallId?.trim().isNotEmpty == true)
                  ? toolCallId!.trim()
                  : '${name}_${DateTime.now().microsecondsSinceEpoch}',
              arguments: args,
              conversationId: conversationId,
            );
            return result.toJsonString();
          } on AskUserInvalidRequestException catch (e) {
            return _toolError(
              error: 'invalid_ask_user_request',
              message: e.message,
              tool: name,
            );
          }
        }

        return await approveAndExecuteMcp(name, args, toolCallId: toolCallId);
      } catch (e) {
        // Catch unexpected exceptions and return error JSON to LLM
        // This prevents tool failures from terminating the chat flow
        return _toolError(
          error: 'execution_error',
          message: e.toString(),
          tool: name,
          instruction:
              'The tool execution failed unexpectedly. You may try again with different parameters or inform the user about the issue.',
        );
      }
    };
  }

  /// Handle memory tool calls (§10).
  ///
  /// Returns null if the tool is not a memory tool or the relevant gate is off.
  Future<String?> _handleMemoryToolCall(
    String name,
    Map<String, dynamic> args,
    Assistant? assistant, {
    String? conversationId,
  }) async {
    final settings = contextProvider.read<SettingsProvider>();
    if (settings.legacyMemoryMode) {
      if (MemoryTools.allToolNames.contains(name)) return null;
      return _handleLegacyMemoryToolCall(name, args, assistant);
    }

    if (assistant == null) return null;
    if (!MemoryTools.allToolNames.contains(name)) return null;

    final memoryV2 = contextProvider.read<MemoryProviderV2>();
    ChatService? chatService;
    try {
      chatService = contextProvider.read<ChatService>();
    } catch (_) {
      chatService = null;
    }

    MemoryPipelineService? pipeline;
    try {
      pipeline = contextProvider.read<MemoryPipelineService>();
    } catch (_) {
      pipeline = null;
    }

    Future<String> Function(String prompt)? memoryLlmCall;
    final provKey = settings.memoryModelProvider;
    final mdlId = settings.memoryModelId;
    if (provKey != null && mdlId != null) {
      final cfg = settings.getProviderConfig(provKey);
      final reasoning = settings.memoryModelThinkingEnabled
          ? (assistant.reasoning ?? ReasoningRequest.auto)
          : ReasoningRequest.off;
      memoryLlmCall = (prompt) => ChatApiService.generateText(
        conversationId: conversationId,
        config: cfg,
        modelId: mdlId,
        prompt: prompt,
        reasoning: reasoning,
      );
    }

    final temporary =
        chatService?.isTemporaryConversation(conversationId) ?? false;
    return MemoryTools.handle(
      name: name,
      args: args,
      assistant: assistant,
      repository: memoryV2.repository,
      chatRepository: memoryV2.chatRepository,
      chatService: chatService,
      conversationId: conversationId,
      // Reload without changing which assistants the open memory UI is showing.
      onMutated: memoryV2.reloadCurrentScope,
      smartAdd: pipeline?.smartAdd,
      promptLang: settings.resolvedMemoryPromptLang,
      memoryLlmCall: memoryLlmCall,
      smartAddPromptZh: settings.memorySmartAddPromptZh,
      smartAddPromptEn: settings.memorySmartAddPromptEn,
      // Temporary chats are discarded on exit; their tool traces must not linger.
      traceRecorder: temporary ? null : pipeline?.traceRecorder,
      conversationTitle: conversationId == null
          ? null
          : chatService?.getConversation(conversationId)?.title,
    );
  }

  /// Handle legacy create/edit/delete_memory calls via [MemoryProvider].
  ///
  /// Returns null if memory is disabled or [name] is not a legacy memory tool.
  Future<String?> _handleLegacyMemoryToolCall(
    String name,
    Map<String, dynamic> args,
    Assistant? assistant,
  ) async {
    if (assistant?.enableMemory != true) return null;
    if (name != 'create_memory' &&
        name != 'edit_memory' &&
        name != 'delete_memory') {
      return null;
    }

    try {
      final mp = contextProvider.read<MemoryProvider>();

      if (name == 'create_memory') {
        final content = (args['content'] ?? '').toString();
        if (content.isEmpty) {
          return _toolError(
            error: 'invalid_memory_content',
            message: 'Memory content must not be empty.',
            tool: name,
          );
        }
        final m = await mp.add(assistantId: assistant!.id, content: content);
        return m.content;
      } else if (name == 'edit_memory') {
        final id = (args['id'] as num?)?.toInt() ?? -1;
        final content = (args['content'] ?? '').toString();
        if (id <= 0) {
          return _toolError(
            error: 'invalid_memory_id',
            message: 'Memory id must be a positive integer.',
            tool: name,
          );
        }
        if (content.isEmpty) {
          return _toolError(
            error: 'invalid_memory_content',
            message: 'Memory content must not be empty.',
            tool: name,
          );
        }
        final m = await mp.update(id: id, content: content);
        if (m == null) {
          return _toolError(
            error: 'memory_not_found',
            message: 'No memory record was found for id $id.',
            tool: name,
            instruction:
                'Use the available memory records shown in context, or create a new memory instead of editing a missing one.',
          );
        }
        return m.content;
      } else if (name == 'delete_memory') {
        final id = (args['id'] as num?)?.toInt() ?? -1;
        if (id <= 0) {
          return _toolError(
            error: 'invalid_memory_id',
            message: 'Memory id must be a positive integer.',
            tool: name,
          );
        }
        final ok = await mp.delete(id: id);
        if (!ok) {
          return _toolError(
            error: 'memory_not_found',
            message: 'No memory record was found for id $id.',
            tool: name,
            instruction:
                'Use the available memory records shown in context, or skip deleting a missing memory.',
          );
        }
        return 'deleted';
      }
    } catch (e) {
      return _toolError(
        error: 'memory_execution_error',
        message: e.toString(),
        tool: name,
        instruction:
            'The memory tool failed. Retry only after correcting the parameters, or inform the user about the issue.',
      );
    }

    return null;
  }
}

/// 工作流引擎的宿主适配（SoLab 自研）：把引擎的 `generateText/runCommand`
/// 接到本进程已装配好的 provider/model 上。
class _WorkflowToolHost implements WorkflowExecutorHost {
  const _WorkflowToolHost({
    required this.onGenerate,
    required this.onCommand,
  });

  final Future<String> Function({required String prompt, String? system})
      onGenerate;
  final Future<String> Function(String command) onCommand;

  /// App 侧的沙盒命令通道还没接到引擎（onCommand 是明确的未接线错误），
  /// 所以预检会把图里的命令节点直接标成致命问题。
  @override
  bool get supportsCommands => false;

  @override
  Future<String> generateText({required String prompt, String? system}) =>
      onGenerate(prompt: prompt, system: system);

  @override
  Future<String> runCommand(String command) => onCommand(command);
}
