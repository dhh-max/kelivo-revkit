import 'dart:async';
import 'dart:convert';
import 'dart:isolate';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path/path.dart' as p;
import 'dart:io';

import '../../../features/home/services/local_tools_service.dart';
import '../../../features/solab_apk/analyzer/analyzer_tools.dart';
import '../../../features/solab_apk/services/apk_agent_policy.dart';
import '../../../features/solab_apk/services/apk_workspace_binding_service.dart';
import '../../models/assistant.dart';
import '../../providers/agent_skill_provider.dart';
import '../../providers/instruction_injection_provider.dart';
import '../../providers/world_book_provider.dart';
import '../../services/chat/chat_service.dart';
import '../../services/local_tools/local_tool_registry.dart';
import '../../services/local_tools/loop_reminder.dart';
import '../../services/local_tools/tool_call_loop_guard.dart';
import '../../services/local_tools/tool_lane_policy.dart';
import '../../services/local_tools/tool_error_policy.dart';
import 'tool_argument_guard.dart';
import '../../services/memory/memory_repository.dart';
import '../../services/workspace/workspace_tools_service.dart';
import '../../../features/solab_apk/assistant/operator_conventions.dart';

/// 把本机作为 MCP Server 对外暴露，局域网内的 AI 客户端
/// （Claude Code / Cursor / Cherry Studio 等）可直接连接调用内置 SoLab 工具。
///
/// 支持两种标准传输：
/// 1. Streamable HTTP（MCP 2025-03-26 / 2025-06-18）：
///    POST /mcp（JSON 或 SSE 响应）+ Mcp-Session-Id 会话头。
/// 2. HTTP+SSE（MCP 2024-11-05）：GET /sse 建立长连接，
///    服务器下发 endpoint 事件，客户端 POST /messages?sessionId=...，
///    响应通过 SSE 流异步推回。
///
/// 鉴权可选：token 为空则不鉴权（默认，局域网直连）；
/// 配置 token 后需 `Authorization: Bearer <token>` 或 `?token=`。
/// 工具：复用 LocalToolsService 的 schema 与执行链路，单一来源不漂移。
class McpHttpServer extends ChangeNotifier {
  McpHttpServer._() {
    // autoClean 借用 guard：先完成的写任务不得删除仍被排队/执行中任务
    // 引用的输入包（否则同批并发多 patch 会出现链式消耗 invalid_apk_path）。
    ApkWorkspaceBindingService.pendingInputGuard = _pathBorrowedByPendingTasks;
  }

  /// 该路径是否被排队/执行中的任务以输入参数引用（精确路径相等，
  /// 非子串匹配，避免误伤同前缀路径）。
  bool _pathBorrowedByPendingTasks(String path) {
    String norm(String v) => p.normalize(p.absolute(v));
    final target = norm(path);
    return _toolTasks.values.any(
      (task) =>
          (task.status == _McpTaskStatus.queued ||
              task.status == _McpTaskStatus.running) &&
          task.arguments.values.any(
            (v) => v is String && v.length > 4 && norm(v) == target,
          ),
    );
  }

  static final McpHttpServer instance = McpHttpServer._();

  static const int maxRequestBytes = 8 * 1024 * 1024; // 8MB

  /// MCP 面单条结果上限。此前钉在 maxVisibleToolResultChars(16000)——
  /// 真机实测 so_analyze 参数目录 16.6KB 被截断，且 MCP 面没有
  /// get_tool_result 续读工具，尾部永久不可达。MCP 消费方多为程序型
  /// Agent，与 App 内 LLM 的 16KB 内联预算诉求不同：提到 512KB（与
  /// ToolHandlerService 结果存储上限一致），超过才走预览截断硬边界。
  static const int maxResultChars = 512 * 1024;
  static const int defaultPort = 8800;
  static const Duration sseHeartbeat = Duration(seconds: 25);
  static const String taskStatusTool = 'mcp_task_status';
  static const Duration taskRetention = Duration(minutes: 30);

  static const Set<String> supportedProtocolVersions = <String>{
    '2024-11-05',
    '2025-03-26',
    '2025-06-18',
  };

  HttpServer? _server;
  String _token = '';
  int _port = defaultPort;
  DateTime _startedAt = DateTime.now();
  List<String> _lanIps = const <String>[];
  final Map<String, _SseSession> _sseSessions = <String, _SseSession>{};

  /// 外部客户端活动登记（2026-09-21 用户实测：全屏页的"是否已连接"永远是 0）。
  ///
  /// `sseSessionCount` 只数 legacy `GET /sse` 会话，而现代客户端（Claude Code /
  /// Cursor / 我们自己的复测 harness）走的都是 **Streamable HTTP（POST /mcp，
  /// 无状态）**——过去完全不计入，页面于是永远写着"等待外部 AI 客户端连接"，
  /// 用户据此以为没连上。这里按会话 id 登记最近活动时间。
  ///
  /// 无状态协议没有断开信号，只能按活动时间收敛（[clientIdleWindow]），
  /// 否则计数只增不减。
  final Map<String, DateTime> _clientSessions = <String, DateTime>{};
  DateTime? _lastClientActivityAt;
  DateTime _lastClientNotifyAt = DateTime.fromMillisecondsSinceEpoch(0);

  /// 会话多久没动静就不再算"已连接"。
  static const Duration clientIdleWindow = Duration(minutes: 5);
  final Map<String, _McpToolTask> _toolTasks = <String, _McpToolTask>{};
  final Random _random = Random.secure();
  Future<String>? _serverVersion;

  /// 出站网络心跳：部分厂商 ROM（vivo 等）在应用切后台后会用 uid=0 代答
  /// 入站 socket 但不向应用投递数据。周期性出站 TCP 流量可维持应用在
  /// 系统网络管理侧的活跃标记，降低入站连接被冻结的概率。
  Timer? _netHeartbeatTimer;
  String? _netHeartbeatGateway;

  Future<void> _writeToolGate = Future<void>.value();

  /// 重内存互斥：加载 DEX/SO 或重建 APK 的工具峰值内存可达数百 MB，
  /// 读写 lane 并发时两个峰值叠加会耗尽 512MB Java 堆（实测 7 次
  /// pool-9-thread OOM 崩溃全部由并发批触发）。重内存工具彼此互斥
  /// （无论在哪条 lane），轻读工具（file/status/calculate 等）不受影响。
  Future<void> _heavyOpsGate = Future<void>.value();

  // 4 个读 gate：客户端并发发多个只读请求时不再排队（此前 2 个，
  // 第 3 个起 head-of-line 等待；先完成的仍按请求独立回包）
  final List<Future<void>> _readToolGates = List<Future<void>>.filled(
    4,
    Future<void>.value(),
  );
  int _nextReadGate = 0;
  String? _blockedWriteToolName;
  DateTime? _blockedWriteSince;
  final List<String?> _blockedReadToolNames = List<String?>.filled(4, null);
  final List<DateTime?> _blockedReadSince = List<DateTime?>.filled(4, null);

  /// 超时熔断的自动恢复冷却：挂死超此时长后放弃等待僵尸 Future，重置
  /// 执行通道放行新调用。原实现隔离无期限，一次 native 挂死 = 整个 MCP
  /// 模式永久不可用，只能重启。
  static const Duration _laneRecoveryCooldown = Duration(minutes: 2);

  /// tool_batch 批次序号：内层闸门桶 = `<会话>#batch#<序号>`（A3）。
  ///
  /// 改造前桶键是常驻的 `<会话>#batch`：一个会话里**第二批**的相同调用会被
  /// 上一批留下的指纹拦住（跨批误拦）；批次序号让每批拿到全新滑窗，同时
  /// 保留「批内重复要被拦」的语义。
  int _batchSeq = 0;

  /// 循环检测按 MCP 客户端会话隔离。
  ///
  /// 原实现是单个共享实例，并在每次 `initialize` 无条件 `reset()` 兜底跨客户端
  /// 误判——那是以一个新客户端的正确性换另一个客户端的正确性：
  ///   - 客户端 B 连接 → 抹掉 A 的滑窗 → **A 的循环检测静默失效**；
  ///   - A/B 交替调用 → 互相污染指纹 → **双方都可能拿到假的 LOOP_DETECTED**。
  /// 滑窗语义本就是"同一会话内的近期调用"，跨会话共享在语义上就是错的。
  /// 改为按 session 分桶：互不干扰，且无需在 initialize 时清空别人的窗。
  final Map<String, ToolCallLoopGuard> _loopGuardsBySession =
      <String, ToolCallLoopGuard>{};

  /// MCP 会话上限：单机 MCP 场景客户端数远小于此，只为防异常客户端
  /// 反复 initialize 造成 Map 无界增长。
  static const int _maxLoopGuardSessions = 32;

  ToolCallLoopGuard _loopGuardFor(String sessionKey) {
    final existing = _loopGuardsBySession[sessionKey];
    if (existing != null) return existing;
    // LRU 淘汰：Map 保持插入序，超限时丢最旧会话（其滑窗本就已过期）。
    if (_loopGuardsBySession.length >= _maxLoopGuardSessions) {
      _loopGuardsBySession.remove(_loopGuardsBySession.keys.first);
    }
    final created = ToolCallLoopGuard();
    _loopGuardsBySession[sessionKey] = created;
    return created;
  }

  static const Duration _defaultToolTimeout = Duration(seconds: 45);
  static const Duration _fileToolTimeout = Duration(seconds: 15);
  static const Duration _heavyToolTimeout = Duration(minutes: 5);
  static const Duration _adaptiveInlineWindow = Duration(milliseconds: 300);
  static const Set<String> _adaptiveToolIds = <String>{
    LocalToolNames.apkPatchDex,
    LocalToolNames.apkPatchDexStrings,
    LocalToolNames.apkSignatureBypass,
    LocalToolNames.apkPatchManifest,
    LocalToolNames.jadxDecompile,
    LocalToolNames.apkSign,
    LocalToolNames.apkRebuild,
    LocalToolNames.dexSearch,
    LocalToolNames.stringScan,
    LocalToolNames.dexXref,
    LocalToolNames.classOutline,
    LocalToolNames.smaliRead,
    LocalToolNames.soAnalyze,
    LocalToolNames.soPatchIntoApk,
  };

  /// 当前 Assistant 提供者（工具执行需要；由 app 层在启动时注入）。
  Assistant? Function()? _assistantGetter;

  /// 聊天服务提供者：项目记录类工具需要数据库仓库。
  ChatService? Function()? _chatServiceGetter;

  /// 记忆仓库提供者：patch 记忆 / 笔记类工具需要。
  MemoryRepository? Function()? _memoryRepositoryGetter;

  /// 世界书提供者：get_apk_knowledge / 运行时指南需要。
  WorldBookProvider? Function()? _worldBookGetter;

  /// 用户 Skill 提供者：get_installed_skills / 运行时指南需要。
  AgentSkillProvider? Function()? _agentSkillGetter;

  /// 指令注入提供者：运行时指南需要。
  InstructionInjectionProvider? Function()? _instructionInjectionGetter;

  Future<bool> Function()? _keepAliveEnsurer;

  /// 对外暴露的全部工具（互斥双模分区，2026-09-13）：本地工具剔除
  /// - ask_user_input_v0 / text_to_speech——依赖 App 内弹窗与 TTS 回调；
  /// - get_agent_runtime_guide / get_solab_skill / get_apk_knowledge /
  ///   get_installed_skills——Agent 独有的上下文与技能扩展
  ///   （route_task modeCapabilities.agentContextTools，MCP 缺席时优雅降级）。
  /// MCP initialize 标准指令：注入外部 agent 系统提示，教它入口链路与
  /// 分层判定（尤其 Blutter：外部 agent 不懂何时该走 Dart 层）。
  /// 使用英文短文本：避免外部网页端/客户端对 UTF-8 中文错误解码显示乱码。
  static const String _mcpInstructions =
      '''
Local APK analysis/modification toolchain (runs on this Android device).
Rules:
0. Reply to the user in Chinese; fill tool arguments by schema field names.
${ApkAgentPolicy.sharedDecisionPolicy}
1. Only listed tools are callable, and the source APK stays read-only. Warning or no-change previews are never applied: for an authorized exact change pass dryRun=true with applyAfterPreview=true once, then continue from nextInputPath and drop previews of the old APK.
2. Read error.code before recovering, and change the evidence dimension instead of retrying identical arguments. Poll queued work with mcp_task_status rather than repeating the original call. Send array-style sweeps (N files, keywords, xref offsets, status polls) through tool_batch or the per-tool batch parameters.
3. apk_rebuild is only for decoded resource/Manifest/smali-directory edits — never for a direct DEX patch output.
4. tools/list schemas are compacted; when a parameter or action is missing call get_solab_tool_map instead of guessing names.''';

  static String get mcpInstructions => _mcpInstructions;

  /// MCP 面「作业约定」开关读取器（main.dart 注入，读设置实时值）。
  /// 打开时 initialize 下发的 instructions 追加同一份工作台约定（端内助手与
  /// MCP 面共用一段文本，单一事实源）。未注入 = 关闭。
  static bool Function()? operatorConventionsResolver;

  /// initialize 实际下发的指令文本（工具纪律 + 可选作业约定）。
  static String get effectiveMcpInstructions {
    final enabled = operatorConventionsResolver?.call() ?? false;
    if (!enabled) return _mcpInstructions;
    return '$_mcpInstructions\n\n${OperatorConventions.prompt}';
  }

  /// MCP 与 Agent 共用本地工具处理器的可调用名单；仅排除依赖 App 内弹窗
  /// 或 TTS 回调的 UI 工具。参数 schema 仍由 LocalToolsService 单一生成。
  static final List<String> exposedToolIds = List<String>.unmodifiable(
    <String>[
      ...LocalToolsService.mcpCallableToolNames,
      AnalyzerToolNames.open,
      AnalyzerToolNames.globalSearch,
      AnalyzerToolNames.fieldUsage,
      AnalyzerToolNames.businessState,
    ]..sort(),
  );

  /// 会消耗**本机模型额度**的工具（子代理/AI 工作流走 App 里配置的 token）。
  /// 用户 2026-10-06：MCP 面可能是别的工具在调，默认不允许，要显式打开。
  static const Set<String> _quotaToolNames = <String>{
    LocalToolNames.subagent,
    LocalToolNames.runWorkflow,
  };

  /// 读取「MCP 允许子代理/AI 工作流」开关（main.dart 注入，读设置实时值）；
  /// 未注入时 fail-closed。名单内的工具照常发布——被拒时给出可执行的错误，
  /// 而不是让调用方以为工具不存在（点名机制的教训）。
  static bool Function()? quotaToolsAllowedResolver;

  static bool _quotaToolAllowed(String name) {
    if (!_quotaToolNames.contains(name)) return true;
    return quotaToolsAllowedResolver?.call() ?? false;
  }

  /// 工作区/沙盒族在 MCP 出口的静态标注。族的读工具过去没标注，而 MCP 规范里
  /// destructiveHint 缺省就是 true —— 客户端于是把 read_file 也当破坏性工具，
  /// 每次调用都弹确认（用户 2026-10-06 实测「别的工具一直弹授权」）。
  static final Set<String> _workspaceDestructiveNames = <String>{
    'shell',
    'write_file',
    'edit_file',
  };
  static final Set<String> _workspaceReadOnlyNames = WorkspaceToolsService.toolNames
      .difference(_workspaceDestructiveNames);

  static const Map<String, String> _publishedToolAliases = <String, String>{
    AnalyzerToolNames.open: 'analyzer_open',
    AnalyzerToolNames.globalSearch: 'analyzer_global_search',
    AnalyzerToolNames.fieldUsage: 'analyzer_find_field_usage',
    AnalyzerToolNames.businessState: 'analyzer_analyze_business_state',
  };

  static final Map<String, String> _internalToolAliases = <String, String>{
    for (final entry in _publishedToolAliases.entries) entry.value: entry.key,
  };

  static final Set<String> _readOnlyToolIds = Set<String>.unmodifiable(<String>{
    ...LocalToolRegistry.readOnlyToolIds(),
    AnalyzerToolNames.open,
    AnalyzerToolNames.globalSearch,
    AnalyzerToolNames.fieldUsage,
    AnalyzerToolNames.businessState,
    taskStatusTool,
  });

  /// 静态名单盖不住、但**确实可能变更环境 / 花外部配额**的四个工具（第 54 项）：
  ///
  /// MCP 的 annotations 是**静态**提示（readOnlyHint 默认 false、
  /// destructiveHint 默认 true），客户端拿它决定要不要给确认提示；而
  /// [_readOnlyToolIds] 来自注册表 `readOnly`——那个字段首先是**车道**语义
  /// （读 lane / 写 lane），不是给客户端的安全承诺。于是这四个「按参数/按委派
  /// 才变更」的工具在 MCP 面上被说成了只读：
  ///
  /// - `run_task_command`：注册表 `readOnly: true`（local_tool_registry.dart:288），
  ///   它多数时候只跑探针；但 `command=VERIFY_ARTIFACT` + `install=true` 是全仓
  ///   **唯一**的自动安装路径（apk_task_chain_service.dart:1436 →
  ///   ApkToolchainService.installApk），会覆盖设备上已装的同名包；
  /// - `subagent`：注册表 `readOnly: true`（local_tool_registry.dart:400），
  ///   但它派发的子代理类别含 `write`/`shell`（subagent_registry.dart:194/:225），
  ///   能顺着写类工具改产物；
  /// - `frida`：注册表本就没声明 readOnly（local_tool_registry.dart:384-393），
  ///   `action=inject` 会往目标 APK 里塞 libfrida-gadget.so 与代理 Application
  ///   （frida_tool_handler.dart:67-120），仓库自己在会话模式里也把它算作变更类
  ///   （session_mode.dart:37-38）；
  /// - `run_workflow`：注册表 `readOnly: true`（local_tool_registry.dart:416），
  ///   但它会花模型配额（ai_generate 节点）、发外部 HTTP（http_request 节点），
  ///   命令节点接线后还会执行 shell——不能当只读承诺。
  ///
  /// 只影响 MCP 面元数据：**不动** [_readOnlyToolIds]，否则
  /// `ToolLanePolicy.isReadOnlyCall` 的读/写车道路由会连坐变化（N2 的排队
  /// 结论：轻读动作不能落写 lane）。
  static const Set<String> _mcpAnnotationMutators = <String>{
    LocalToolNames.runTaskCommand,
    LocalToolNames.subagent,
    LocalToolNames.frida,
    LocalToolNames.runWorkflow,
  };

  /// 纯计算/纯本地信息工具（D2，2026-09-21 自检）：不占内存、不碰文件、不做
  /// 设备 IO，与 APK 工具链零资源竞争。它们不应进入任何互斥 lane——此前只有
  /// 显式声明 readOnly 的工具才豁免，calculate/value_calc/get_time_info 落到
  /// **写 lane**，于是任何写类超时的 2 分钟冷却都会连坐它们（实测：clipboard
  /// 挂起后 get_time_info 一起被堵住）。
  ///
  /// 来源 = 注册表声明（`LocalToolSpec.resourceClass`），不再是这里的写死名单：
  /// 新增工具必须在注册表里声明资源类型，否则落 `unclassified`、进写 lane，
  /// 并被 `local_tool_registry_resource_class_test.dart` 的一致性检查拦住。
  static final Set<String> _computeOnlyToolIds =
      LocalToolRegistry.namesWithResourceClass(ToolResourceClass.computeOnly);

  /// 设备 IO 工具（D1）：走平台通道（剪贴板/TTS/系统查询），既不是重内存也
  /// 不是文件写，单独一条 lane。
  ///
  /// 关键点：这类调用的"挂起"意味着平台通道没回，**没有僵尸原生命令在跑**，
  /// 所以超时后必须立刻解除 lane 占用，不能像重内存工具那样保留 2 分钟冷却
  /// ——否则一次剪贴板挂起就污染整条通道（实测阻塞 file 写类与 so_analyze
  /// 读动作约 120s，而 45s 的默认超时对平台通道也过长）。
  static final Set<String> _deviceIoToolIds =
      LocalToolRegistry.namesWithResourceClass(ToolResourceClass.deviceIo);

  /// 设备 IO 硬超时：远低于默认 45s。平台通道该秒回的调用，5s 不回就是坏了。
  static const Duration _deviceIoToolTimeout = Duration(seconds: 5);

  bool _isReadOnlyCall(String name, Map<String, dynamic> args) =>
      ToolLanePolicy.isReadOnlyCall(
        name,
        args,
        readOnlyToolIds: _readOnlyToolIds,
      );

  /// 重内存判定：**按 action**，不按工具名（2026-09-21 用户报告 #3）。
  ///
  /// 工具名级别的判定把 `so_analyze` 的纯读动作（hexdump/strings/workspaces/pool/
  /// handles）也塞进全局堆互斥，于是一个 `apk_rebuild` 跑着，这些读动作实测排队
  /// **27s+**。只读动作不产生堆峰值，不该与重任务互斥。
  /// 注意与 lane 判定**不是同一件事**：blutter `analyze` 归读 lane（避免超时连坐
  /// 写链路）但仍是重内存（它真会起 runner + 建索引）。
  bool _isHeavyCall(String name, Map<String, dynamic> args) =>
      ToolLanePolicy.isHeavyCall(name, args);

  bool get isRunning => _server != null;
  int get port => _port;
  bool get authRequired => _token.isNotEmpty;

  /// 仅测试用：当前生效的访问令牌。
  ///
  /// 令牌本身**不进**模型上下文（见安全约束），这里只暴露给测试断言
  /// 「轮换后服务端确实拿到了新值」。
  @visibleForTesting
  String get debugToken => _token;

  int get sseSessionCount => _sseSessions.length;

  /// 最近 [clientIdleWindow] 内露过面的外部客户端数（SSE 会话 + Streamable 会话）。
  int get activeClientCount {
    final now = DateTime.now();
    _clientSessions.removeWhere(
      (_, at) => now.difference(at) > clientIdleWindow,
    );
    return _sseSessions.length + _clientSessions.length;
  }

  /// 最近一次收到外部客户端请求的时间（null = 本次运行还没有客户端来过）。
  DateTime? get lastClientActivityAt => _lastClientActivityAt;

  void _noteClientActivity(String key) {
    final now = DateTime.now();
    _lastClientActivityAt = now;
    _clientSessions[key] = now;
    // 重建节流：一个客户端会在一次会话里发几十上百个请求，页面没必要跟着抖；
    // 每秒最多通知一次（计数与"最近活动"都够用）。
    if (now.difference(_lastClientNotifyAt) < const Duration(seconds: 1)) {
      return;
    }
    _lastClientNotifyAt = now;
    notifyListeners();
  }

  /// 连接地址（启动时缓存；为空表示当前无网络）。
  /// 服务绑定 0.0.0.0，本地回环始终可用（adb reverse / 本机客户端），
  /// 因此固定首个返回 127.0.0.1，其后为局域网地址。
  List<String> get lanUrls => <String>[
    'http://127.0.0.1:$_port/mcp',
    ..._lanIps.map((ip) => 'http://$ip:$_port/mcp'),
  ];

  void configure({
    Assistant? Function()? assistantGetter,
    ChatService? Function()? chatServiceGetter,
    MemoryRepository? Function()? memoryRepositoryGetter,
    WorldBookProvider? Function()? worldBookGetter,
    AgentSkillProvider? Function()? agentSkillGetter,
    InstructionInjectionProvider? Function()? instructionInjectionGetter,
    Future<bool> Function()? keepAliveEnsurer,
    int? port,
    String? token,
  }) {
    if (assistantGetter != null) _assistantGetter = assistantGetter;
    if (chatServiceGetter != null) _chatServiceGetter = chatServiceGetter;
    if (memoryRepositoryGetter != null) {
      _memoryRepositoryGetter = memoryRepositoryGetter;
    }
    if (worldBookGetter != null) _worldBookGetter = worldBookGetter;
    if (agentSkillGetter != null) _agentSkillGetter = agentSkillGetter;
    if (instructionInjectionGetter != null) {
      _instructionInjectionGetter = instructionInjectionGetter;
    }
    if (keepAliveEnsurer != null) _keepAliveEnsurer = keepAliveEnsurer;
    if (port != null && port > 0 && port < 65536) _port = port;
    _token = token ?? _token;
  }

  /// 构造"全量工具" Assistant 视图：以当前助手为底，localToolIds 放开为 exposedToolIds。
  /// getter 未注入/未就绪（如设置页开关路径先于 main 启动）时合成最小 Assistant，
  /// 保证 tools/list 永远返回完整目录而不是空列表。
  Assistant _fullToolAssistant() {
    final base = _assistantGetter?.call();
    if (base != null) {
      return base.copyWith(localToolIds: exposedToolIds);
    }
    return const Assistant(
      id: '__mcp_server__',
      name: 'MCP Server',
      localToolIds: <String>[],
    ).copyWith(localToolIds: exposedToolIds);
  }

  Future<bool> start() async {
    if (_server != null) return true;
    debugPrintSafely(
      '[McpHttpServer] start() called: port=$_port chatGetter=${_chatServiceGetter != null}\n'
      '${StackTrace.current}',
    );
    try {
      if (Platform.isAndroid && await _keepAliveEnsurer?.call() != true) {
        debugPrintSafely(
          '[McpHttpServer] start blocked: keep-alive is not ready',
        );
        return false;
      }
      final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
      server.listen(
        (req) => _handleRequest(req),
        onError: (Object error) {
          debugPrintSafely('[McpHttpServer] listen error: $error');
        },
        cancelOnError: false,
      );
      _server = server;
      _startedAt = DateTime.now();
      _lanIps = await _resolveLanIps();
      _startNetHeartbeat();
      debugPrintSafely(
        '[McpHttpServer] listening on 0.0.0.0:$_port/mcp (lan: ${_lanIps.join(", ")})',
      );
      notifyListeners();
      return true;
    } catch (error) {
      debugPrintSafely('[McpHttpServer] start failed: $error');
      notifyListeners();
      return false;
    }
  }

  Future<void> stop() async {
    debugPrintSafely('[McpHttpServer] stop() called');
    _netHeartbeatTimer?.cancel();
    _netHeartbeatTimer = null;
    final server = _server;
    _server = null;
    for (final id in _sseSessions.keys.toList(growable: false)) {
      _removeSseSession(id);
    }
    // 客户端登记同样清空：停服后"最近活动"不该还停在停服前那次请求上。
    _clientSessions.clear();
    _lastClientActivityAt = null;
    await server?.close(force: true);
    notifyListeners();
    debugPrintSafely('[McpHttpServer] stopped');
  }

  // ---------------------------------------------------------------------------
  // HTTP routing
  // ---------------------------------------------------------------------------

  Future<void> _handleRequest(HttpRequest req) async {
    try {
      // T1.3：Host 校验——只放行本机/局域网已知地址，防 DNS rebinding
      // 与任意 Host 伪造；非法 Host 直接 403（CORS 头也不加）。
      if (!_hostAllowed(req)) {
        req.response.statusCode = HttpStatus.forbidden;
        req.response.headers.contentType = ContentType.json;
        req.response.write('{"error":"host_not_allowed"}');
        await req.response.close();
        return;
      }
      _addCorsHeaders(req);
      final path = req.uri.path;
      final method = req.method;
      switch (path) {
        case '/':
        case '/.well-known/mcp':
          if (method == 'GET') return await _respondJson(req, _discovery());
          break;
        case '/health':
          if (method == 'GET') {
            return await _respondJson(req, <String, dynamic>{
              'ok': true,
              'server': 'kelivo',
              'endpoint': '/mcp',
              'sseEndpoint': '/sse',
              'sseSessionCount': _sseSessions.length,
              'uptimeMillis': DateTime.now()
                  .difference(_startedAt)
                  .inMilliseconds,
            });
          }
          break;
        // Streamable HTTP 端点
        case '/mcp':
          if (method == 'OPTIONS') return _respondNoContent(req);
          if (method == 'POST') return await _handleStreamablePost(req);
          if (method == 'DELETE') {
            // 同路由 GET 需要鉴权，DELETE 也必须鉴权：否则任意能连上端口的人
            // 凭一个 session-id 就能踢掉别人的 SSE 会话（此前无 _authorized）。
            if (!_authorized(req)) {
              return await _respondJson(
                req,
                _authError(),
                status: HttpStatus.unauthorized,
              );
            }
            // 客户端终止会话：SSE 会话按头清理；Streamable 本地无状态，直接确认。
            final sid = req.headers.value('mcp-session-id');
            if (sid != null && sid.isNotEmpty) _removeSseSession(sid);
            return await _respondJson(req, <String, dynamic>{'ok': true});
          }
          if (method == 'GET') {
            if (!_authorized(req)) {
              return await _respondJson(
                req,
                _authError(),
                status: HttpStatus.unauthorized,
              );
            }
            final accept = req.headers.value(HttpHeaders.acceptHeader) ?? '';
            if (accept.contains('text/event-stream')) {
              // 服务器不提供 GET 推送流；按规范返回 405，客户端回退到 POST 模式。
              return await _respondJson(req, <String, dynamic>{
                'ok': false,
                'error': 'method_not_allowed',
              }, status: HttpStatus.methodNotAllowed);
            }
            return await _respondJson(req, _discovery());
          }
          break;
        // 旧版 HTTP+SSE 传输端点
        case '/sse':
          if (method == 'OPTIONS') return _respondNoContent(req);
          if (method == 'GET') return await _handleSseConnect(req);
          break;
        case '/messages':
          if (method == 'OPTIONS') return _respondNoContent(req);
          if (method == 'POST') return await _handleLegacyMessagesPost(req);
          break;
        // 便捷 JSON-RPC 端点（与 /mcp POST 等价，供脚本快速调用）
        case '/rpc':
          if (method == 'OPTIONS') return _respondNoContent(req);
          if (method == 'POST') return await _handleStreamablePost(req);
          break;
        default:
          break;
      }
      await _respondJson(req, <String, dynamic>{
        'ok': false,
        'error': 'not_found',
        'path': path,
      }, status: HttpStatus.notFound);
    } catch (error) {
      debugPrintSafely('[McpHttpServer] request error: $error');
      try {
        await _respondJson(req, <String, dynamic>{
          'ok': false,
          'error': 'internal_error',
          'detail': error.toString(),
        }, status: HttpStatus.internalServerError);
      } catch (_) {}
    }
  }

  /// 有界读取请求体：chunked 编码下 contentLength 为 -1，`contentLength >
  /// maxRequestBytes` 预检会被整个跳过，而 `utf8.decoder.bind(req).join()` 会
  /// 先把任意大的包读进内存再事后判长——服务绑定 0.0.0.0，局域网内可据此打爆
  /// 内存。这里边读边计数，超限立即停止读取并返回 null，由调用方回 413。
  static Future<String?> _readBoundedBody(HttpRequest req) async {
    if (req.contentLength > maxRequestBytes) return null;
    final bytes = <int>[];
    var total = 0;
    await for (final chunk in req) {
      total += chunk.length;
      if (total > maxRequestBytes) return null;
      bytes.addAll(chunk);
    }
    return utf8.decode(bytes);
  }

  // ---------------------------------------------------------------------------
  // Streamable HTTP（POST /mcp）
  // ---------------------------------------------------------------------------

  Future<void> _handleStreamablePost(HttpRequest req) async {
    if (!_authorized(req)) {
      return _respondJson(req, _authError(), status: HttpStatus.unauthorized);
    }
    final String body;
    try {
      final read = await _readBoundedBody(req);
      if (read == null) {
        await _respondJson(
          req,
          _rpcError(null, -32002, 'Request body too large (max 8MB)'),
          status: HttpStatus.requestEntityTooLarge,
        );
        return;
      }
      body = read;
    } on FormatException catch (error) {
      // 非 UTF-8 请求体过去冒到顶层变成 500 internal_error，调用方只看到
      // "internal_error" 而不知道是编码问题（2026-10-05：Windows 客户端按本地
      // 代码页发送中文参数实测）。给可诊断的 400。
      return _respondJson(
        req,
        _rpcError(
          null,
          -32700,
          'INVALID_ENCODING: request body must be UTF-8 '
              '(${error.message}). Escape non-ASCII as \\uXXXX if your '
              'client cannot send UTF-8.',
        ),
        status: HttpStatus.badRequest,
      );
    }

    // initialize 请求：按 Streamable HTTP 规范在响应头下发会话 ID。
    final clientSession = req.headers.value('mcp-session-id') ?? '';
    if (clientSession.isEmpty && _isInitializeBody(body)) {
      final issued = _newSessionId();
      req.response.headers.add('mcp-session-id', issued);
      // 提示客户端服务器不提供 GET 事件流（405），避免其长时间挂等。
      req.response.headers.add('mcp-protocol-hint', 'no-server-push');
      // 新会话在这里登记：之后的请求都带这个 id（见 else 分支）。
      _noteClientActivity(issued);
    } else {
      _noteClientActivity(
        clientSession.isEmpty
            // 不带会话 id 的调用（裸探针、单次调用）按来源地址归并成一个"会话"，
            // 否则每个请求都会算出一个新客户端。
            ? 'anon:${req.connectionInfo?.remoteAddress.address ?? 'unknown'}'
            : clientSession,
      );
    }

    final response = await _dispatchBody(
      body,
      analyzerContextKey: clientSession.isEmpty
          ? 'mcp-anonymous'
          : 'mcp:$clientSession',
    );
    if (response == null) {
      // 全 notification：按规范回 202 Accepted 空体
      req.response.statusCode = HttpStatus.accepted;
      req.response.close();
      return;
    }
    final accept = req.headers.value(HttpHeaders.acceptHeader) ?? '';
    if (accept.contains('text/event-stream')) {
      // charset 必须 utf-8：dart:io 对无 charset 的 text/* 用 Latin-1 编码，
      // 含中文的工具描述会抛 "Contains invalid characters"（曾致 MCP 客户端连接失败）。
      return _respondText(
        req,
        'event: message\ndata: ${await _encodeJsonBody(response)}\n\n',
        ContentType('text', 'event-stream', charset: 'utf-8'),
      );
    }
    return _respondJson(req, response);
  }

  bool _isInitializeBody(String body) {
    final trimmed = body.trimLeft();
    if (trimmed.isEmpty || trimmed.startsWith('[')) return false;
    try {
      final decoded = jsonDecode(trimmed);
      return decoded is Map<String, dynamic> &&
          decoded['method'] == 'initialize';
    } catch (_) {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // 旧版 HTTP+SSE 传输（GET /sse + POST /messages）
  // ---------------------------------------------------------------------------

  Future<void> _handleSseConnect(HttpRequest req) async {
    if (!_authorized(req)) {
      return _respondJson(req, _authError(), status: HttpStatus.unauthorized);
    }
    final res = req.response;
    final sessionId = _newSessionId();
    res.statusCode = HttpStatus.ok;
    res.headers.contentType = ContentType(
      'text',
      'event-stream',
      charset: 'utf-8',
    );
    res.headers.set(HttpHeaders.cacheControlHeader, 'no-cache');
    res.persistentConnection = true;

    final session = _SseSession(sessionId, res);
    _sseSessions[sessionId] = session;
    debugPrintSafely(
      '[McpHttpServer] SSE session open: $sessionId (${_sseSessions.length} total)',
    );
    notifyListeners();
    session.heartbeat = Timer.periodic(sseHeartbeat, (_) {
      if (session.closed) {
        _removeSseSession(sessionId);
        return;
      }
      session.push(': ping\n\n');
    });

    // 规范要求：第一个事件为 endpoint，data 为消息回传 URI（字符串）。
    await session.push(
      'event: endpoint\ndata: /messages?sessionId=$sessionId\n\n',
    );

    try {
      await res.done;
    } catch (_) {}
    _removeSseSession(sessionId);
  }

  Future<void> _handleLegacyMessagesPost(HttpRequest req) async {
    if (!_authorized(req)) {
      return _respondJson(req, _authError(), status: HttpStatus.unauthorized);
    }
    final sessionId = req.uri.queryParameters['sessionId'] ?? '';
    final session = _sseSessions[sessionId];
    if (session == null || session.closed) {
      return _respondJson(req, <String, dynamic>{
        'ok': false,
        'error': 'unknown_session',
      }, status: HttpStatus.badRequest);
    }
    final String body;
    try {
      final read = await _readBoundedBody(req);
      if (read == null) {
        await _respondJson(
          req,
          _rpcError(null, -32002, 'Request body too large (max 8MB)'),
          status: HttpStatus.requestEntityTooLarge,
        );
        return;
      }
      body = read;
    } on FormatException catch (error) {
      // 非 UTF-8 请求体过去冒到顶层变成 500 internal_error，调用方只看到
      // "internal_error" 而不知道是编码问题（2026-10-05：Windows 客户端按本地
      // 代码页发送中文参数实测）。给可诊断的 400。
      return _respondJson(
        req,
        _rpcError(
          null,
          -32700,
          'INVALID_ENCODING: request body must be UTF-8 '
              '(${error.message}). Escape non-ASCII as \\uXXXX if your '
              'client cannot send UTF-8.',
        ),
        status: HttpStatus.badRequest,
      );
    }
    final response = await _dispatchBody(
      body,
      analyzerContextKey: 'mcp:$sessionId',
    );
    if (response != null) {
      if (response is List) {
        for (final item in response) {
          await session.push(
            'event: message\ndata: ${await _encodeJsonBody(item)}\n\n',
          );
        }
      } else {
        await session.push(
          'event: message\ndata: ${await _encodeJsonBody(response)}\n\n',
        );
      }
    }
    // 按规范回 202 Accepted，真正响应走 SSE 流。
    req.response.statusCode = HttpStatus.accepted;
    req.response.headers.contentLength = 0;
    await req.response.close();
  }

  void _removeSseSession(String id) {
    final session = _sseSessions.remove(id);
    if (session == null) return;
    session.heartbeat?.cancel();
    session.closed = true;
    try {
      session.response.close();
    } catch (_) {}
    debugPrintSafely(
      '[McpHttpServer] SSE session closed: $id (${_sseSessions.length} remaining)',
    );
    // 会话增删过去不发通知：页面上的客户端数只会在下一次别的刷新时才对上。
    notifyListeners();
  }

  String _newSessionId() {
    final bytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  // ---------------------------------------------------------------------------
  // JSON-RPC dispatch
  // ---------------------------------------------------------------------------

  Future<dynamic> _dispatchBody(
    String body, {
    String analyzerContextKey = 'mcp-anonymous',
  }) async {
    final trimmed = body.trim();
    if (trimmed.isEmpty) return _rpcError(null, -32700, 'Parse error');
    if (trimmed.startsWith('[')) {
      dynamic arr;
      try {
        arr = jsonDecode(trimmed);
      } catch (_) {
        return _rpcError(null, -32700, 'Parse error');
      }
      if (arr is! List || arr.isEmpty) {
        return _rpcError(null, -32600, 'Invalid Request');
      }
      final out = <dynamic>[];
      var allNotifications = true;
      for (final item in arr) {
        if (item is! Map<String, dynamic>) {
          out.add(_rpcError(null, -32600, 'Invalid Request'));
          allNotifications = false;
          continue;
        }
        final res = await _dispatch(
          item,
          analyzerContextKey: analyzerContextKey,
        );
        out.add(res);
        if (res != null) allNotifications = false;
      }
      // 全是 notification（无 id）→ 202 空体
      return allNotifications ? null : out;
    }
    dynamic req;
    try {
      req = jsonDecode(trimmed);
    } catch (_) {
      return _rpcError(null, -32700, 'Parse error');
    }
    if (req is! Map<String, dynamic>) {
      return _rpcError(null, -32600, 'Invalid Request');
    }
    return _dispatch(req, analyzerContextKey: analyzerContextKey);
  }

  Future<Map<String, dynamic>?> _dispatch(
    Map<String, dynamic> req, {
    required String analyzerContextKey,
  }) async {
    final id = req['id'];
    final method = (req['method'] ?? '').toString();
    if (req['jsonrpc'] != '2.0' || method.isEmpty) {
      return _rpcError(id, -32600, 'Invalid Request');
    }
    // JSON-RPC notification（无 id）→ 返回 null，HTTP 层回 202 空体
    if (id == null) return null;
    final params = (req['params'] is Map<String, dynamic>)
        ? req['params'] as Map<String, dynamic>
        : <String, dynamic>{};
    dynamic result;
    switch (method) {
      case 'initialize':
        // 协议版本协商：客户端请求的版本受支持则回显，否则回落最新版。
        // 循环检测已按会话分桶（见 _loopGuardsBySession），新连接不再需要
        // 清空别人的滑窗——旧实现在这里无条件 reset()，代价是 B 一连上就把
        // A 的循环检测抹掉。
        final requested = (params['protocolVersion'] ?? '').toString();
        final negotiated = supportedProtocolVersions.contains(requested)
            ? requested
            : '2025-06-18';
        final serverVersion = await _readServerVersion();
        result = <String, dynamic>{
          'protocolVersion': negotiated,
          'capabilities': <String, dynamic>{
            'tools': <String, dynamic>{'listChanged': false},
          },
          'serverInfo': <String, dynamic>{
            'name': 'SoLab',
            'version': serverVersion,
          },
          'instructions': effectiveMcpInstructions,
          '_meta': <String, dynamic>{
            // DEF-07（2026-09-19 复测）：自报数必须与实际目录一致——tools/list
            // 还会追加 tool_batch 与 mcp_task_status 两个面级工具（另一条路径
            // 早已用 +2，这里补齐，否则客户端拿 44 去校验 46 必然对不上）。
            'fullToolCount': exposedToolIds.length + 2,
            'decisionPolicyVersion': ApkAgentPolicy.version,
            'hint':
                'tools/list advertises the complete built-in SoLab catalog '
                '(SO/Dex/APK/file). SO tasks: so_analyze(action=open) first, keep workspaceId.',
          },
        };
        break;
      case 'notifications/initialized':
        // Notification: no response envelope needed, but returning an empty
        // result keeps strict JSON-RPC clients happy.
        result = <String, dynamic>{};
        break;
      case 'ping':
        result = <String, dynamic>{'ok': true};
        break;
      case 'resources/list':
        result = <String, dynamic>{'resources': <dynamic>[]};
        break;
      case 'prompts/list':
        result = <String, dynamic>{'prompts': <dynamic>[]};
        break;
      case 'tools/list':
        await _refreshWorkspaceToolContextIfStale();
        result = _toolsList();
        break;
      case 'tools/call':
        result = await _callTool(
          params,
          analyzerContextKey: analyzerContextKey,
        );
        break;
      default:
        return _rpcError(id, -32601, 'Method not found');
    }
    return <String, dynamic>{'jsonrpc': '2.0', 'id': id, 'result': result};
  }

  Future<String> _readServerVersion() {
    return _serverVersion ??= _loadServerVersion();
  }

  Future<String> _loadServerVersion() async {
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      final version = packageInfo.version.trim();
      final buildNumber = packageInfo.buildNumber.trim();
      if (version.isEmpty) return buildNumber.isEmpty ? '0.0.0' : buildNumber;
      if (buildNumber.isEmpty || version.endsWith('+$buildNumber')) {
        return version;
      }
      return '$version+$buildNumber';
    } catch (_) {
      return '0.0.0';
    }
  }

  /// schema 保持全量的工具：写操作三件套（dryRun/confirm 契约本身在
  /// schema 里）与流程入口。其余工具描述截断，全量按需从
  /// get_solab_tool_map 读取（与 App 内 Schema 懒加载同思路）。
  static const Set<String> _schemaKeepFullIds = <String>{
    LocalToolNames.routeTask,
    LocalToolNames.apkPatchDex,
    LocalToolNames.apkSignatureBypass,
    LocalToolNames.apkPatchManifest,
    LocalToolNames.soPatchIntoApk,
    LocalToolNames.file,
    LocalToolNames.apkRebuild,
    LocalToolNames.apkToolMap,
  };

  /// tools/list 描述压缩上限（工具级 / 属性级）。
  static const int _maxToolDescriptionChars = 480;
  static const int _maxPropertyDescriptionChars = 240;

  static String _truncateSchemaText(String text, int max) {
    if (text.length <= max) return text;
    var cut = text.substring(0, max);
    final boundary = cut.lastIndexOf(RegExp(r'[\n。.!?;；]'));
    if (boundary > max ~/ 2) {
      cut = cut.substring(0, boundary + 1);
    }
    return '$cut…';
  }

  /// 压缩单个工具的 MCP schema：描述截断 + 属性描述截断。
  /// 参数名/类型/enum 值一律保留（调用合法性所需），只减描述文本。
  static Map<String, dynamic> _compactMcpToolSchema(
    String internalName,
    Map<String, dynamic> function,
  ) {
    if (_schemaKeepFullIds.contains(internalName) ||
        internalName == taskStatusTool) {
      return function;
    }
    final next = Map<String, dynamic>.from(function);
    final description = function['description']?.toString() ?? '';
    next['description'] =
        '${_truncateSchemaText(description, _maxToolDescriptionChars)}\n'
        '[Full parameters: call get_solab_tool_map once.]';
    final parameters = function['parameters'];
    if (parameters is Map) {
      final params = Map<String, dynamic>.from(parameters);
      final properties = params['properties'];
      if (properties is Map) {
        final compactedProps = <String, dynamic>{};
        properties.forEach((key, value) {
          if (value is Map && value['description'] != null) {
            final prop = Map<String, dynamic>.from(value);
            prop['description'] = _truncateSchemaText(
              value['description'].toString(),
              _maxPropertyDescriptionChars,
            );
            compactedProps[key] = prop;
          } else {
            compactedProps[key] = value;
          }
        });
        params['properties'] = compactedProps;
      }
      next['parameters'] = params;
    }
    return next;
  }

  /// 工具标题（对标 MT MCP 的 `title`：客户端列表与确认弹窗读它）。
  /// 注册表早就有中文短标题，此前只差上架；不在注册表里的四个 analyzer
  /// 与 tool_batch / mcp_task_status 在这里补。
  ///
  /// **两个命名形态**（§14.11"4 个 analyzer 缺 title"的真根因，2026-09-20 修）：
  /// 注册表与这里的键都是**内部名**（`analyzer.open`），而
  /// `AnalyzerGatewayTools.buildDefinitions` 声明的 `function.name` 是
  /// **发布名**（`analyzer_open`）——只按内部名查表时那四个永远取不到标题。
  /// 故下面统一走 [_titleOf]，两种形态各查一次。
  static final Map<String, String> _toolTitles = <String, String>{
    for (final spec in LocalToolRegistry.specs) spec.name: spec.title,
    AnalyzerToolNames.open: '分析器 · 打开会话',
    AnalyzerToolNames.globalSearch: '分析器 · 全局检索',
    AnalyzerToolNames.fieldUsage: '分析器 · 字段引用',
    AnalyzerToolNames.businessState: '分析器 · 业务状态',
    LocalToolNames.toolBatch: '批量工具调用',
    taskStatusTool: '任务状态',
  };

  /// 按内部名或发布名取标题（见 [_toolTitles] 的说明）。
  static String? _titleOf(String name) =>
      _toolTitles[name] ?? _toolTitles[AnalyzerToolNames.internalName(name)];

  /// tools/list 已发布 schema 的缓存（名称 → inputSchema）。
  ///
  /// 参数预校验必须与发布契约同源：schema 改了校验跟着改，不再出现「声明与
  /// 实现两套口径」。MCP 助手固定（_fullToolAssistant），schema 运行期不变。
  Map<String, Map<String, dynamic>>? _publishedSchemaCache;

  Map<String, Map<String, dynamic>> _publishedSchemas() {
    final cached = _publishedSchemaCache;
    if (cached != null) return cached;
    final built = <String, Map<String, dynamic>>{};
    var builtOk = true;
    try {
      final listed = _toolsList()['tools'];
      if (listed is List) {
        for (final item in listed) {
          if (item is Map &&
              item['name'] is String &&
              item['inputSchema'] is Map) {
            built[item['name'] as String] = (item['inputSchema'] as Map)
                .cast<String, dynamic>();
          }
        }
      }
    } catch (e) {
      // 构建失败仍不阻断调用（校验退化为不校验，保持可用性），但**绝不缓存**：
      // 把空表写进缓存会让参数预校验永久失效且无人察觉，后续调用也无法自愈。
      builtOk = false;
      debugPrint('[McpHttpServer] published schema build failed: $e');
    }
    if (!builtOk) return built;
    return _publishedSchemaCache = built;
  }

  /// 工作区上下文短 TTL 缓存：tools/list 是同步构建（schema 缓存链路不能变
  /// async），沙盒上下文的解析却是异步的——handler 入口先按 TTL 刷新一次，
  /// 同步构建读缓存。执行路径不读缓存（每次现解析，保证状态新鲜）。
  WorkspaceToolContext? _workspaceCtxCache;
  int _workspaceCtxCachedAt = 0;
  static const int _workspaceCtxTtlMs = 5000;

  Future<void> _refreshWorkspaceToolContextIfStale() async {
    final now = DateTime.now().millisecondsSinceEpoch;
    if (now - _workspaceCtxCachedAt < _workspaceCtxTtlMs) return;
    try {
      _workspaceCtxCache =
          await WorkspaceToolsService.resolveDefaultFromResolvers();
    } catch (_) {
      _workspaceCtxCache = null;
    }
    _workspaceCtxCachedAt = now;
  }

  Map<String, dynamic> _toolsList() {
    final assistant = _fullToolAssistant();
    // T9 后 buildToolDefinitions 返回不可变列表：先复制为可变再并入
    // analyzer 高阶 API，否则对定长 list 调 addAll 抛
    // "Cannot add to a fixed-length list"（tools/list 整体 internal_error）。
    final definitions = <Map<String, dynamic>>[
      ...LocalToolsService.buildToolDefinitions(
        assistant: assistant,
        supportsTools: true,
      ),
    ];
    // 只并入白名单里的 analyzer 高阶 API（open/global_search/
    // find_field_usage/analyze_business_state），其余 18 个桩不暴露。
    final analyzerWhitelisted = AnalyzerToolNames.all
        .where(exposedToolIds.contains)
        .toSet();
    definitions.addAll(
      AnalyzerGatewayTools.buildDefinitions(analyzerWhitelisted),
    );
    // 工作区/沙盒工具族（用户 2026-10-06：「MCP 模式连沙盒环境都找不着」）：
    // 过去只发 LocalToolsService 那批工具，工作区族（shell/read_file/write_file/
    // list_dir/glob/grep/view_image/edit_file）在 MCP 面根本不存在。现在用
    // 「设置里配置的默认工作区」上下文发布——MCP 无会话，默认工作区就是它的
    // 项目；环境不可用时执行会如实回报，不假装可用。
    try {
      final workspaceCtx = _workspaceCtxCache;
      final workspaceTools = WorkspaceToolsService.sharedInstanceResolver?.call();
      if (workspaceCtx != null && workspaceTools != null) {
        definitions.addAll(workspaceTools.buildToolDefinitions(workspaceCtx));
      }
    } catch (e) {
      debugPrint('[McpHttpServer] workspace tool family unavailable: $e');
    }
    final tools = <dynamic>[];
    // 按发布名去重：analyzer 四工具的声明在 buildLocalToolSchemas 里已经追加过
    // 一次，这里再 addAll 同一 builder 会得到重复条目（tools/list 曾返回 51 个
    // 而白名单只有 46 个，目录计数校验因此恒挂）。同名只保留首次出现的定义。
    final emitted = <String>{};
    for (final def in definitions) {
      final rawFunction = (def['function'] as Map?)?.cast<String, dynamic>();
      if (rawFunction == null) continue;
      final internalName = rawFunction['name'].toString();
      final function = _compactMcpToolSchema(internalName, rawFunction);
      final inputSchema = Map<String, dynamic>.from(
        (function['parameters'] as Map?)?.cast<String, dynamic>() ??
            const <String, dynamic>{
              'type': 'object',
              'properties': <String, dynamic>{},
            },
      );
      if (function['name'] == LocalToolNames.apkRebuild) {
        inputSchema['properties'] = <String, dynamic>{
          ...((inputSchema['properties'] as Map?)?.cast<String, dynamic>() ??
              const <String, dynamic>{}),
          'async': <String, dynamic>{
            'type': 'boolean',
            'description':
                'MCP only: queue the task and return taskId immediately; poll mcp_task_status for its result.',
          },
        };
      }
      inputSchema.putIfAbsent('additionalProperties', () => false);
      final publishedName = _publishedToolAliases[internalName] ?? internalName;
      if (!emitted.add(publishedName)) continue;
      final entry = <String, dynamic>{
        'name': publishedName,
        if (_titleOf(internalName) case final title?) 'title': title,
        'description': function['description'].toString().replaceAll(
          'analyzer.',
          'analyzer_',
        ),
        'inputSchema': inputSchema,
        'outputSchema': _toolOutputSchema,
        'annotations': <String, dynamic>{
          'readOnlyHint':
              (_readOnlyToolIds.contains(internalName) &&
                  !_mcpAnnotationMutators.contains(internalName)) ||
              _workspaceReadOnlyNames.contains(internalName),
          // 破坏性提示（对标 MT MCP 的 annotations，2026-09-19 对比结论）：
          // 会改产物/写记忆/清构建的工具标出来，客户端才能给出合适的确认与
          // 风险提示，而不是把所有工具一视同仁。名单来自单一事实源
          // ApkAgentPolicy.mutationToolNames。
          if (ApkAgentPolicy.mutationToolNames.contains(internalName) ||
              _mcpAnnotationMutators.contains(internalName) ||
              _workspaceDestructiveNames.contains(internalName))
            'destructiveHint': true,
        },
      };
      tools.add(entry);
    }
    tools.add(<String, dynamic>{
      'name': LocalToolNames.toolBatch,
      'title': _toolTitles[LocalToolNames.toolBatch] ?? 'Batch',
      'description':
          'Batch runner: execute up to 8 tool calls in ONE round trip — '
          'each entry is {tool, args} exactly as a standalone call. Inner '
          'calls run sequentially and reuse full per-call semantics (lane '
          'queuing, timeout, loop guard, async queueing). A failed inner '
          'call stays as an isError entry without aborting the batch; total '
          'budget 120s, overrun entries are skipped. Use for array-style '
          'sweeps (read N files, search N keywords, xref N offsets, poll '
          'status). Do NOT put long tasks (locate/analyze/rebuild) in a '
          'batch unless passing their async flags; tool_batch cannot nest '
          'itself.',
      'inputSchema': <String, dynamic>{
        'type': 'object',
        'additionalProperties': false,
        'properties': <String, dynamic>{
          'calls': <String, dynamic>{
            'type': 'array',
            'items': <String, dynamic>{
              'type': 'object',
              'properties': <String, dynamic>{
                'tool': <String, dynamic>{
                  'type': 'string',
                  'description': 'Tool name exactly as listed by tools/list.',
                },
                'args': <String, dynamic>{
                  'type': 'object',
                  'description':
                      'Arguments object identical to the standalone call.',
                },
              },
              'required': <String>['tool'],
            },
            'description':
                'Up to 8 calls; extras are truncated with a note. Read-heavy '
                'batches stay read-only per inner call lane routing.',
          },
        },
        'required': <String>['calls'],
      },
      'outputSchema': _toolOutputSchema,
    });
    tools.add(<String, dynamic>{
      'name': taskStatusTool,
      'title': _toolTitles[taskStatusTool] ?? 'Task status',
      'description':
          'Poll a SoLab asynchronous MCP task. apk_rebuild with dex=false is queued automatically; pass async=true to queue another long local tool call.',
      'inputSchema': <String, dynamic>{
        'type': 'object',
        'additionalProperties': false,
        'properties': <String, dynamic>{
          'taskId': <String, dynamic>{
            'type': 'string',
            'description': 'The taskId returned by the queued tool call.',
          },
        },
        'required': <String>['taskId'],
      },
      'outputSchema': _toolOutputSchema,
      'annotations': const <String, dynamic>{'readOnlyHint': true},
    });
    return <String, dynamic>{
      'tools': tools,
      '_meta': <String, dynamic>{
        'returnedCount': tools.length,
        'fullToolCount': exposedToolIds.length + 2,
        'hint':
            'All tools are local on this device. Use mcp_task_status to poll an async APK rebuild task.',
      },
    };
  }

  /// 统一批量 runner：一次 HTTP 往返串行执行 ≤8 个任意工具调用。
  /// 每个内层调用完整复用 _callTool 语义（lane 排队、超时、loop guard、
  /// async 队列、adaptive），单项失败不炸批；整体 120s 预算，超时后
  /// 剩余项标记 skipped——数组遍历场景几十次亚秒连调压成一次往返。
  Future<Map<String, dynamic>> _toolBatch(
    Map<String, dynamic> args, {
    required String analyzerContextKey,
  }) async {
    final rawCalls = args['calls'];
    if (rawCalls is! List || rawCalls.isEmpty) {
      return _toolTextResult(
        _toolErrorOutput(
          'invalid_args',
          'calls must be a non-empty array of {tool, args} objects',
        ),
        isError: true,
      );
    }
    final selected = rawCalls.take(8).toList();
    const deadline = Duration(seconds: 120);
    final startedAt = DateTime.now();
    final results = <Map<String, dynamic>>[];
    var succeeded = 0;
    var blockedByLoopGuard = 0;
    final batchGuardKey = '$analyzerContextKey#batch#${_batchSeq++}';
    for (final raw in selected) {
      if (results.isNotEmpty &&
          DateTime.now().difference(startedAt) > deadline) {
        results.add(const <String, dynamic>{
          'skipped': true,
          'reason':
              'BATCH_DEADLINE: 120s batch budget exhausted; run the '
              'remaining calls in a follow-up batch',
        });
        continue;
      }
      if (raw is! Map) {
        results.add(const <String, dynamic>{
          'error': 'invalid_call',
          'reason': 'each call must be an object {tool, args}',
        });
        continue;
      }
      final innerName = (raw['tool'] ?? raw['name'] ?? '').toString();
      if (innerName == LocalToolNames.toolBatch) {
        results.add(<String, dynamic>{
          'tool': innerName,
          'error': 'nested_batch_forbidden',
        });
        continue;
      }
      final innerArgs = _toolArguments(raw['args'] ?? raw['arguments']);
      // DEF-13（2026-09-19 复测）：内层调用过去与主会话共享环路滑窗，批内
      // 重复同参（或与近期调用同参）会被判 loop_detected，聚合结果成
      // 「executed:8, succeeded:0」——像批处理坏了。批内改用独立闸门桶：
      // 环路语义（一轮内不要重复同一份证据）本就属于外层会话。
      final result = await _callTool(
        <String, dynamic>{'name': innerName, 'arguments': innerArgs},
        analyzerContextKey: analyzerContextKey,
        loopGuardKey: batchGuardKey,
      );
      final isError = result['isError'] == true;
      if (!isError) succeeded++;
      final content = result['content'];
      // 聚合层区分「被环路闸门拦」与「真失败」（A3）：两者的处置完全不同
      // ——前者换参数即可，后者要查原因；过去都只体现为 isError。
      final blockedByGuard = _contentMentionsLoopGuard(content);
      if (blockedByGuard) blockedByLoopGuard++;
      results.add(<String, dynamic>{
        'tool': innerName,
        'isError': isError,
        if (blockedByGuard) 'blockedByLoopGuard': true,
        'result': content,
      });
    }
    return _toolTextResult(
      jsonEncode(<String, dynamic>{
        'ok': succeeded > 0,
        'batch': true,
        'requested': rawCalls.length,
        'executed': selected.length,
        'succeeded': succeeded,
        'blockedByLoopGuard': blockedByLoopGuard,
        'elapsedMs': DateTime.now().difference(startedAt).inMilliseconds,
        'results': results,
        if (rawCalls.length > 8) 'note': '超出上限 8 的调用已截断，请分批重试其余调用',
      }),
      isError: succeeded == 0,
    );
  }

  Future<Map<String, dynamic>> _callTool(
    Map<String, dynamic> params, {
    required String analyzerContextKey,
    String? loopGuardKey,
  }) async {
    final requestedName = (params['name'] ?? '').toString();
    final name = _internalToolAliases[requestedName] ?? requestedName;
    final args = _toolArguments(params['arguments']);
    if (name == LocalToolNames.apkToolMap) {
      final requestedTool = args['tool']?.toString();
      final internalTool = _internalToolAliases[requestedTool];
      if (internalTool != null) args['tool'] = internalTool;
    }
    try {
      // 系统工具（tool_batch / mcp_task_status）与发布名有别名的 analyzer
      // 工具都必须先过同一份 tools/list 契约：前者不能提前返回绕过必填
      // 校验，后者归一为内部名后仍要能找到以发布名缓存的 schema。
      final schemas = _publishedSchemas();
      final publishedSchema = schemas[requestedName] ?? schemas[name];
      if (publishedSchema != null) {
        final fault = ToolArgumentGuard.check(publishedSchema, args);
        if (fault != null) {
          return _toolTextResult(
            _toolErrorOutput(
              fault.code,
              fault.message,
              details: fault.toError(),
            ),
            isError: true,
          );
        }
      }
      // FGS/WakeLock 在 server.start() 前已确认。这里不能再把每个工具调用
      // 同步绑到 Activity 的 MethodChannel：任务界面被移除后原生服务仍在，
      // 但该通道可能不再回包，曾导致 HTTP 与 tools/list 正常、所有工具永久挂起。
      if (name == taskStatusTool) return _taskStatus(args);
      if (name == LocalToolNames.toolBatch) {
        return await _toolBatch(args, analyzerContextKey: analyzerContextKey);
      }
      // 工作区/沙盒族（用户 2026-10-06）：必须在发布白名单之外单独放行——
      // exposedToolIds 是静态集合，工区族是按「默认工作区是否可用」条件发布的，
      // 过去这里会把已发布的族又拒成 tool_not_found（发布与分发两套名单）。
      final isWorkspaceFamilyTool = WorkspaceToolsService.toolNames.contains(name);
      if (!exposedToolIds.contains(name) && !isWorkspaceFamilyTool) {
        return _toolTextResult(
          _toolErrorOutput(
            'tool_not_found',
            'TOOL_NOT_FOUND: $requestedName. Call tools/list for the catalog.',
          ),
          isError: true,
        );
      }
      // 额度闸门（用户 2026-10-06）：子代理/AI 工作流花的是本机模型的额度，
      // 而 MCP 面可能是别的工具在调。开关关着时给可执行错误，不静默执行。
      if (!_quotaToolAllowed(name)) {
        return _toolTextResult(
          _toolErrorOutput(
            'mcp_quota_tools_disabled',
            'MCP 面当前不允许使用 $requestedName：它用的是本机 App 里配置的模型'
                '额度。要允许请到 设置 → MCP 服务器 → 「允许子代理」打开后重试。',
            tool: name,
          ),
          isError: true,
        );
      }
      final isReadOnly = _isReadOnlyCall(name, args);
      final readGateIndex = isReadOnly
          ? _nextReadGate++ % _readToolGates.length
          : null;
      // D17：隔离只对重内存工具生效。读 gate 的存在意义是防"第二个重内存
      // 峰值"叠加；轻量读工具（file/status/policy 等）不产生峰值，却会因
      // 别人的超时被连坐——4 个读 gate 轮转下表现为同一条调用"时好时坏"。
      final heavyTool = _isHeavyCall(name, args);
      final blockedTool = isReadOnly
          ? _blockedReadToolNames[readGateIndex!]
          : _blockedWriteToolName;
      // D1/D2：lane-free 工具（纯计算 + 设备 IO）与 APK 工具链零资源竞争，
      // 既不排队也不被隔离标记连坐——一次剪贴板挂起不该让 calculate 也等两分钟。
      final laneFree =
          _computeOnlyToolIds.contains(name) || _deviceIoToolIds.contains(name);
      if (blockedTool != null && !laneFree) {
        final blockedFor = DateTime.now().difference(
          (isReadOnly
                  ? _blockedReadSince[readGateIndex!]
                  : _blockedWriteSince) ??
              DateTime.now(),
        );
        if (blockedFor >= _laneRecoveryCooldown) {
          // 冷却期满自动解封：放弃等待僵尸 Future，重置执行通道。
          if (isReadOnly) {
            _blockedReadToolNames[readGateIndex!] = null;
            _blockedReadSince[readGateIndex] = null;
            _readToolGates[readGateIndex] = Future<void>.value();
          } else {
            _blockedWriteToolName = null;
            _blockedWriteSince = null;
            _writeToolGate = Future<void>.value();
          }
        } else if (isReadOnly && !heavyTool) {
          // D17：轻量读放行（见上）。写 lane 不放行——写 lane 拦的是
          // "原生命令仍在跑时再写"，那是数据安全问题，与堆峰值无关。
        } else {
          final waitSeconds = (_laneRecoveryCooldown - blockedFor).inSeconds;
          return _toolTextResult(
            _toolErrorOutput(
              'tool_lane_blocked',
              'MCP_TOOL_LANE_BLOCKED: $blockedTool is still running after its '
                  'timeout${isReadOnly ? '，本调用是重内存工具' : ''}. '
                  'The lane auto-recovers in ~$waitSeconds s; wait, '
                  'poll mcp_task_status, or restart MCP mode to recover now. '
                  'Do not repeat the same call after recovery — narrow it first.',
              tool: name,
              details: <String, dynamic>{
                'blockedTool': blockedTool,
                'lane': isReadOnly ? 'read' : 'write',
                'retryAfterSeconds': waitSeconds,
                'cooldownSeconds': _laneRecoveryCooldown.inSeconds,
                'laneBlockedScope': isReadOnly
                    ? 'heavy-memory tools routed to this read gate'
                    : 'all write-lane tools',
                if (isReadOnly)
                  'laneBlockedNote': heavyTool
                      ? '本次被隔离是因为它本身也是重内存工具；轻量读工具走其它读 gate，不受影响。'
                      : '本 gate 已隔离，重试本调用会被拒；冷却期满自动恢复。',
              },
            ),
            isError: true,
          );
        }
      }
      final loopGuard = _loopGuardFor(loopGuardKey ?? analyzerContextKey);
      final loopDecision = loopGuard.check(
        name,
        args,
        polling: _isPollingCall(name, args),
        // 只读调用不进环路窗口（用户报告 #1）：读是新观测，不是重复证据。
        //
        // ⚠ 判据用 changesState 的反面，**不是** isReadOnly：后者是"车道"口径
        // （工具名/白名单），`clipboard_tool` 不在注册表 readOnly 名单里，用它判会
        // 返回 false → 只读豁免失效（真机实测第二次读仍被拦）。环路窗口要防的是
        // "重复改状态"，所以窗口成员 = 改状态的调用。
        readOnly: !ToolCallLoopGuard.changesState(name, args),
      );
      if (!loopDecision.allowed) {
        // 只读幂等工具的重复调用：不再硬拦，改为回放上次结果（不重复执行）。
        // 环路闸门要防的是"重复验证同一证据"的浪费，而不是让"重发同参核对"
        // 变成错误；回执里显式标注 replayedFromCache，调用方能区分"新结果"
        // 与"复用结果"，写操作会清空缓存（写后读必须重新执行）。
        final replayed = _replayIfAvailable(
          loopGuardKey ?? analyzerContextKey,
          name,
          args,
          isReadOnly: isReadOnly,
        );
        if (replayed != null) return replayed;
        return _toolTextResult(
          _toolErrorOutput('loop_detected', loopDecision.message, tool: name),
          isError: true,
        );
      }
      final assistant = _fullToolAssistant();
      debugPrintSafely(
        '[McpHttpServer] call $name: chatGetter=${_chatServiceGetter != null} '
        'repoGetter=${_memoryRepositoryGetter != null}',
      );
      if (_shouldRunAsync(name, args)) {
        return _startAsyncToolCall(
          name,
          args,
          assistant,
          analyzerContextKey: analyzerContextKey,
          loopGuardKey: loopGuardKey,
          readGateIndex: readGateIndex,
          isReadOnly: isReadOnly,
        );
      }
      if (_shouldRunAdaptive(name, args)) {
        return await _startAdaptiveToolCall(
          name,
          args,
          assistant,
          analyzerContextKey: analyzerContextKey,
          loopGuardKey: loopGuardKey,
          readGateIndex: readGateIndex,
          isReadOnly: isReadOnly,
        );
      }
      // 打开工作区只读取已缓存报告并更新内存状态，不依赖底层分析引擎。
      // 让它绕过长构建任务的队列，保证连接和工作区复用即时可用。
      final output = name == AnalyzerToolNames.open
          ? await _runTool(
              name,
              args,
              assistant,
              analyzerContextKey: analyzerContextKey,
              loopGuardKey: loopGuardKey,
            )
          : await _enqueueToolCall(
              name,
              args,
              () => _runTool(
                name,
                args,
                assistant,
                analyzerContextKey: analyzerContextKey,
                loopGuardKey: loopGuardKey,
              ),
              readGateIndex: readGateIndex,
              isReadOnly: isReadOnly,
            );
      // 环路分级：首次/二次重复放行，但把提醒注入结果带给模型。
      final result = _completedToolResult(
        name,
        appendLoopReminder(output, loopDecision.reminder),
      );
      _rememberReadResult(
        loopGuardKey ?? analyzerContextKey,
        name,
        args,
        isReadOnly: isReadOnly,
        result: result,
      );
      return result;
    } catch (error, stack) {
      // 失败重连（网络原因等）：超时/异常的调用没有可信结果，移除其
      // 指纹，客户端网络恢复后可用相同参数重试而不被 LOOP_DETECTED 拦。
      _loopGuardFor(loopGuardKey ?? analyzerContextKey).forget(name, args);
      final message = error is TimeoutException
          ? 'TOOL_BUSY_TIMEOUT: $name did not finish within '
                '${error.duration?.inSeconds ?? 0}s. This is NOT a tool '
                'failure: the call was likely still queued behind a heavy '
                'task (blutter/dex/rebuild) or simply running long. The '
                'native task keeps running; retry the same call after a '
                'short wait.'
          : 'TOOL_EXCEPTION: $name :: ${error.toString()} :: $stack';
      return _toolTextResult(
        _toolErrorOutput(
          error is TimeoutException ? 'tool_busy_timeout' : 'tool_exception',
          message,
          tool: name,
          details: <String, dynamic>{'toolName': name},
        ),
        isError: true,
      );
    }
  }

  Map<String, dynamic> _toolArguments(Object? raw) {
    if (raw is Map) {
      return raw.map((key, value) => MapEntry(key.toString(), value));
    }
    if (raw is String) {
      try {
        final decoded = jsonDecode(raw);
        if (decoded is Map) {
          return decoded.map((key, value) => MapEntry(key.toString(), value));
        }
      } catch (_) {}
    }
    return <String, dynamic>{};
  }

  bool _shouldRunAsync(String name, Map<String, dynamic> args) =>
      name == LocalToolNames.apkAnalyzeWorkspace ||
      args['async'] == true ||
      (name == LocalToolNames.apkRebuild && args['dex'] == false);

  bool _shouldRunAdaptive(String name, Map<String, dynamic> args) {
    if (name == LocalToolNames.soAnalyze &&
        args['action'] == 'blutter' &&
        const {'analyze', 'status', 'cancel'}.contains(args['blutterAction'])) {
      // Blutter 自己已经是 job 模型。analyze 只需完成检查并返回 jobId；
      // status(wait=true) 最多等一个心跳。再包一层 MCP task 会吞掉真实阶段。
      return false;
    }
    if (_adaptiveToolIds.contains(name) ||
        AnalyzerToolNames.all.contains(name)) {
      return true;
    }
    if (name != LocalToolNames.file) return false;
    return !const {'list', 'info'}.contains(args['action']);
  }

  /// 内层结果里是否出现环路闸门拦截（用于聚合层分开计数）。
  bool _contentMentionsLoopGuard(Object? content) {
    if (content is! List) return false;
    for (final item in content) {
      if (item is Map &&
          (item['text']?.toString().contains('loop_detected') ?? false)) {
        return true;
      }
    }
    return false;
  }

  /// 轮询类调用：参数相同但结果随时间变化（异步任务状态查询），豁免循环检测。
  bool _isPollingCall(String name, Map<String, dynamic> args) {
    if (name == taskStatusTool) return true;
    // async=true 的重复调用是状态轮询（复用同指纹任务，不重新入队），豁免
    // 循环检测——否则文档契约的重试查状态会被 LOOP_DETECTED 拦住。
    if (args['async'] == true) return true;
    // so_analyze 全 action 豁免：Kotlin 侧有 jobId/editSession 级任务复用，
    // 同参重试要么复用运行中任务返回状态，要么命中 reused 报告/类缓存，
    // 是真实的轮询语义（实测 locate 重试被 LOOP_DETECTED 误拦）。
    // 不豁免整个自适应集合：自适应路径没有 MCP 级指纹复用（每次调用新建
    // 任务，快路径完成即删），豁免会让 jadx/patch/file 等重工具的同参循环
    // 既真跑又不受守卫约束，重开 OOM 压力向量。
    if (name == LocalToolNames.soAnalyze) return true;
    // analyzer.open 幂等（重复调用复用，结果稳定），豁免循环检测。
    if (name == AnalyzerToolNames.open) {
      return true;
    }
    return false;
  }

  Future<String?> _runTool(
    String name,
    Map<String, dynamic> args,
    Assistant assistant, {
    required String analyzerContextKey,
    String? loopGuardKey,
  }) async {
    final detachBlutterWait =
        name == LocalToolNames.soAnalyze &&
        args['action'] == 'blutter' &&
        args['blutterAction'] == 'analyze' &&
        args['wait'] == true;
    final executionArgs = detachBlutterWait
        ? <String, dynamic>{...args, 'wait': false}
        : args;
    // 工作区/沙盒族：MCP 面无会话，用默认工作区上下文执行（与聊天面同一实现）。
    // 用户 2026-10-06：MCP 模式必须真的能用沙盒，不是只把工具列出来。
    if (WorkspaceToolsService.toolNames.contains(name)) {
      final workspaceCtx =
          await WorkspaceToolsService.resolveDefaultFromResolvers();
      final workspaceTools = WorkspaceToolsService.sharedInstanceResolver?.call();
      if (workspaceCtx == null || workspaceTools == null) {
        return _toolErrorOutput(
          'workspace_not_bound',
          'MCP 面没有可用的工作区：先在设置 → 工作区里配置默认工作目录'
              '（工作区家族依赖它解析沙盒挂载与路径）。',
          tool: name,
        );
      }
      try {
        final result = await workspaceTools.handle(
          workspaceCtx,
          name,
          executionArgs,
          toolCallId: 'mcp_${DateTime.now().microsecondsSinceEpoch}',
          conversationId: WorkspaceToolsService.mcpHostConversationId,
        );
        return _workspaceFamilyMcpOutput(result, tool: name);
      } catch (e) {
        return _toolErrorOutput(
          'workspace_tool_failed',
          '工作区工具执行失败：$e',
          tool: name,
        );
      }
    }
    final output = await LocalToolsService.tryHandleToolCall(
      name,
      executionArgs,
      assistant,
      chatService: _chatServiceGetter?.call(),
      memoryRepository: _memoryRepositoryGetter?.call(),
      worldBookProvider: _worldBookGetter?.call(),
      agentSkillProvider: _agentSkillGetter?.call(),
      instructionInjectionProvider: _instructionInjectionGetter?.call(),
      analyzerContextKey: analyzerContextKey,
    );
    if (output == null) return null;
    final normalizedOutput = name == LocalToolNames.apkToolMap
        ? _publishToolMapAliases(output)
        : output;
    if (ToolCallLoopGuard.changesState(name, executionArgs) &&
        ToolCallLoopGuard.succeeded(normalizedOutput)) {
      _loopGuardFor(
        loopGuardKey ?? analyzerContextKey,
      ).advanceState(name, executionArgs);
    }
    if (!detachBlutterWait) return normalizedOutput;
    return _annotateDetachedBlutterWait(normalizedOutput);
  }

  /// 工作区族（shell/read_file/…）端内返回 [ClientToolResult]：成功时
  /// `{content, metadata}`，失败时 content 字符串里才是 tool_error 信封。
  /// 照原样透给 MCP 出口时失败信号埋在 `data.content` 里，
  /// `_normalizeToolOutput` 只能看到 `{content, metadata}`——isError 恒 false，
  /// 真机实测 `approval_denied` 被报成成功（2026-10-05）。这里把失败信封摊到
  /// 顶层走同一套 ToolErrorPolicy 裁决；成功结果保持原形。
  String _workspaceFamilyMcpOutput(Object? result, {required String tool}) {
    final text = result is String ? result : jsonEncode(result);
    var inner = text;
    if (result is! String) {
      try {
        final decoded = jsonDecode(text);
        if (decoded is Map) inner = decoded['content']?.toString() ?? '';
      } catch (_) {
        return text;
      }
    }
    final trimmed = inner.trim();
    if (!trimmed.startsWith('{')) return text;
    try {
      final decoded = jsonDecode(trimmed);
      if (decoded is Map) {
        final map = Map<String, dynamic>.from(
          decoded.map((key, value) => MapEntry(key.toString(), value)),
        );
        if (map['ok'] == false || map['type'] == 'tool_error') {
          final unified = ToolErrorPolicy.unifyFailure(map, tool: tool);
          // 与其它工具族的失败形对齐（data:null + error{} + nextActions），
          // 让出口的规范形归一走"已是标准 envelope"快分支。
          if (!unified.containsKey('data')) unified['data'] = null;
          return jsonEncode(unified);
        }
      }
    } catch (_) {}
    return text;
  }

  String _publishToolMapAliases(String output) {
    try {
      final decoded = jsonDecode(output);
      if (decoded is! Map) return output;
      final root = Map<String, dynamic>.from(
        decoded.map((key, value) => MapEntry(key.toString(), value)),
      );
      final rawData = root['data'];
      final data = rawData is Map
          ? Map<String, dynamic>.from(
              rawData.map((key, value) => MapEntry(key.toString(), value)),
            )
          : root;
      final tools = data['tools'];
      if (tools is List) {
        data['tools'] = <dynamic>[
          for (final tool in tools)
            if (tool is Map)
              <String, dynamic>{
                ...tool.map((key, value) => MapEntry(key.toString(), value)),
                if (tool['name'] case final String internalName)
                  'name': _publishedToolAliases[internalName] ?? internalName,
              }
            else
              tool,
        ];
      }
      final callableNames = data['callableToolNames'];
      if (callableNames is List) {
        data['callableToolNames'] = <dynamic>[
          for (final value in callableNames)
            if (value is String)
              _publishedToolAliases[value] ?? value
            else
              value,
        ];
      }
      if (rawData is Map) root['data'] = data;
      return jsonEncode(root);
    } catch (_) {
      return output;
    }
  }

  String _annotateDetachedBlutterWait(String output) {
    try {
      final decoded = jsonDecode(output);
      if (decoded is! Map) return output;
      final raw = Map<String, dynamic>.from(
        decoded.map((key, value) => MapEntry(key.toString(), value)),
      );
      final note = <String, dynamic>{
        'waitDetached': true,
        'message':
            'MCP 已将长 Blutter 分析转为后台任务。使用返回的 jobId 调 blutterAction=status 查询真实阶段。',
      };
      final data = raw['data'];
      if (data is Map) {
        raw['data'] = <String, dynamic>{
          ...data.map((key, value) => MapEntry(key.toString(), value)),
          'mcpExecution': note,
        };
      } else {
        raw['mcpExecution'] = note;
      }
      return jsonEncode(raw);
    } catch (_) {
      return output;
    }
  }

  Map<String, dynamic> _startAsyncToolCall(
    String name,
    Map<String, dynamic> args,
    Assistant assistant, {
    required String analyzerContextKey,
    String? loopGuardKey,
    required int? readGateIndex,
    required bool isReadOnly,
  }) {
    _pruneFinishedTasks();
    // async=true 的重试语义是查状态（schema 契约："Retry the same async call
    // to poll"）：同指纹任务还在时直接返回其当前状态，不重新入队——否则每轮
    // 重试都会白跑一遍完整 pipeline。
    for (final task in _toolTasks.values) {
      if (task.tool == name && task.fingerprint == jsonEncode(args)) {
        final done =
            task.status == _McpTaskStatus.completed ||
            task.status == _McpTaskStatus.failed;
        return _toolTextResult(
          _normalizeToolOutput(
            jsonEncode(<String, dynamic>{
              ...task.toJson(),
              // 复用已有任务而非重新入队——显式标记让调用方能区分
              // "真跑了"与"命中去重返回旧结果"（实测去重会伪装成成功）。
              'deduplicated': true,
              'stillRunning': !done,
              'pollTool': taskStatusTool,
              'message': done
                  ? '任务已结束（命中去重，未重新执行），用 mcp_task_status(taskId) 读取完整结果；需要强制重跑请改变参数。'
                  : '任务仍在执行：重试同一 async 调用或用 mcp_task_status 查状态。',
            }),
          ).$1,
          isError: false,
        );
      }
    }
    final task = _McpToolTask(_newSessionId(), name, args);
    _toolTasks[task.id] = task;
    unawaited(() async {
      try {
        await _enqueueToolCall(
          name,
          args,
          () async {
            task.start();
            try {
              final output = await _runTool(
                name,
                args,
                assistant,
                analyzerContextKey: analyzerContextKey,
                loopGuardKey: loopGuardKey,
              );
              task.complete(output ?? 'TOOL_NOT_HANDLED: $name');
            } catch (error) {
              task.fail(error.toString());
            }
          },
          readGateIndex: readGateIndex,
          isReadOnly: isReadOnly,
        );
      } catch (error) {
        task.fail(error.toString());
      }
    }());
    return _queuedTaskResult(task);
  }

  Future<Map<String, dynamic>> _startAdaptiveToolCall(
    String name,
    Map<String, dynamic> args,
    Assistant assistant, {
    required String analyzerContextKey,
    String? loopGuardKey,
    required int? readGateIndex,
    required bool isReadOnly,
  }) async {
    _pruneFinishedTasks();
    final task = _McpToolTask(_newSessionId(), name, args);
    _toolTasks[task.id] = task;
    final inline = Completer<_McpAdaptiveResult>();
    unawaited(() async {
      try {
        final output = await _enqueueToolCall(
          name,
          args,
          () async {
            task.start();
            return _runTool(
              name,
              args,
              assistant,
              analyzerContextKey: analyzerContextKey,
              loopGuardKey: loopGuardKey,
            );
          },
          readGateIndex: readGateIndex,
          isReadOnly: isReadOnly,
        );
        task.complete(output ?? 'TOOL_NOT_HANDLED: $name');
        if (!inline.isCompleted) {
          inline.complete(_McpAdaptiveResult(output: output));
        }
      } catch (error) {
        task.fail(error.toString());
        if (!inline.isCompleted) {
          inline.complete(_McpAdaptiveResult(error: error));
        }
      }
    }());
    final raced = await Future.any<Object?>(<Future<Object?>>[
      inline.future,
      Future<Object?>.delayed(_adaptiveInlineWindow),
    ]);
    if (raced is _McpAdaptiveResult) {
      _toolTasks.remove(task.id);
      if (raced.error != null) throw raced.error!;
      return _completedToolResult(name, raced.output);
    }
    return _queuedTaskResult(task);
  }

  Map<String, dynamic> _completedToolResult(String name, String? output) {
    if (output == null) {
      return _toolTextResult('TOOL_NOT_HANDLED: $name', isError: true);
    }
    final limit = _isPromptLikeTool(name) ? 4000 : maxResultChars;
    final (normalized, isFailed) = _normalizeToolOutput(output, tool: name);
    return _toolTextResult(
      _truncate(_injectArtifactAliases(normalized), limitOverride: limit),
      isError: isFailed,
    );
  }

  /// 产物路径字段别名（契约统一，2026-09-19 复测）。
  ///
  /// 各写工具历史上各叫各的：`outputPath` / `nextInputPath` / `output` /
  /// `outputApk` / `signedPath`——调用方回读时得逐工具猜字段名（复测中我至少
  /// 踩了三次）。这里在出口统一补 `outputPath` 与 `nextInputPath` 两个规范字段
  /// （原地别名，不改动原有键），任何工具拿到的产物路径都能用同一套字段读。
  ///
  /// 快路径：文本里没有别名键、或已经同时带两个规范字段时不解析 JSON。
  static const List<String> _artifactAliasKeys = <String>[
    'outputApk',
    'signedPath',
    'signedApk',
    'output',
    'artifactPath',
  ];

  String _injectArtifactAliases(String text) {
    if (text.contains('"outputPath"') && text.contains('"nextInputPath"')) {
      return text;
    }
    if (!_artifactAliasKeys.any(text.contains)) return text;
    try {
      final decoded = jsonDecode(text);
      if (decoded is! Map) return text;
      final map = Map<String, dynamic>.from(
        decoded.map((key, value) => MapEntry(key.toString(), value)),
      );
      final data = map['data'];
      if (data is! Map) return text;
      String? alias;
      for (final key in _artifactAliasKeys) {
        final value = data[key];
        if (value is String && value.startsWith('/')) {
          alias = value;
          break;
        }
      }
      if (alias == null) return text;
      if (data['outputPath'] == null) data['outputPath'] = alias;
      if (data['nextInputPath'] == null) data['nextInputPath'] = alias;
      return jsonEncode(map);
    } catch (_) {
      return text;
    }
  }

  Map<String, dynamic> _queuedTaskResult(_McpToolTask task) {
    return _toolTextResult(
      _normalizeToolOutput(
        tool: task.tool,
        jsonEncode(<String, dynamic>{
          ...task.toJson(),
          'pollTool': taskStatusTool,
          'message': '任务已排队。请用 mcp_task_status 轮询 taskId，完成后读取 result。',
        }),
      ).$1,
      isError: false,
    );
  }

  Map<String, dynamic> _taskStatus(Map<String, dynamic> args) {
    _pruneFinishedTasks();
    final taskId = (args['taskId'] ?? '').toString().trim();
    final task = _toolTasks[taskId];
    if (task == null) {
      return _toolTextResult(
        _toolErrorOutput('task_not_found', 'TASK_NOT_FOUND: $taskId'),
        isError: true,
      );
    }
    return _toolTextResult(
      _normalizeToolOutput(jsonEncode(task.toJson()), tool: task.tool).$1,
      isError: task.status == _McpTaskStatus.failed,
    );
  }

  void _pruneFinishedTasks() {
    final now = DateTime.now();
    _toolTasks.removeWhere((_, task) {
      final finishedAt = task.finishedAt;
      return finishedAt != null && now.difference(finishedAt) > taskRetention;
    });
  }

  Duration _toolTimeoutFor(String name, Map<String, dynamic> args) {
    // D1：设备 IO（剪贴板/TTS/询问用户）走平台通道，5s 硬超时——45s 的默认值
    // 让一次通道挂起就吃掉整条链路两分钟。
    if (_deviceIoToolIds.contains(name)) return _deviceIoToolTimeout;
    if (name == LocalToolNames.file &&
        const {
          'read',
          'list',
          'info',
          'copy',
          'rename',
        }.contains(args['action'])) {
      return _fileToolTimeout;
    }
    if (name == LocalToolNames.soAnalyze ||
        name == LocalToolNames.apkAnalyzeWorkspace ||
        name == LocalToolNames.apkPatchDex ||
        name == LocalToolNames.apkSignatureBypass ||
        name == LocalToolNames.apkRebuild ||
        // 工作流是用户自建的图：delay 节点最长 300s、HTTP 30s，还能串多个
        // AI 节点——45s 默认档必然误杀（超时后整条通道还要隔离冷却）。
        name == LocalToolNames.runWorkflow ||
        args['async'] == true) {
      return _heavyToolTimeout;
    }
    return _defaultToolTimeout;
  }

  /// 排队执行：任一工具超时后隔离整个执行通道，避免挂起 Future 永久堵住
  /// 后续请求；隔离期间拒绝新任务，不冒险并发写入原生工具链。
  Future<T> _enqueueToolCall<T>(
    String name,
    Map<String, dynamic> args,
    Future<T> Function() task, {
    required int? readGateIndex,
    required bool isReadOnly,
  }) {
    // D1/D2（2026-09-21 自检）：lane-free 工具直接执行——不排 gate、不参与
    // 隔离标记与重内存互斥。
    //   纯计算（calculate/value_calc/get_time_info）：无内存/文件/设备资源，
    //     排队纯属被连坐；
    //   设备 IO（clipboard_tool/text_to_speech/ask_user）：走平台通道，超时
    //     只是"通道没回"，**没有僵尸原生命令占内存**，所以既不设隔离标记也不
    //     保留"仍在运行"状态——旧实现让它占写 lane，一次挂起就锁死整条写链路
    //     加 2 分钟冷却（实测 file 写类、so_analyze 读动作一起等 120s）。
    // 两者仍带硬超时（设备 IO 为 5s，见 _toolTimeoutFor）。
    if (_computeOnlyToolIds.contains(name) || _deviceIoToolIds.contains(name)) {
      final laneFreeTask = task();
      // 超时后底层 Future 仍可能以错误收尾，显式吞掉避免未处理异常。
      laneFreeTask.then((_) {}, onError: (Object _, StackTrace __) {});
      return laneFreeTask.timeout(_toolTimeoutFor(name, args));
    }
    final gateIndex = isReadOnly ? readGateIndex! : -1;
    final gate = isReadOnly ? _readToolGates[gateIndex] : _writeToolGate;
    final timeout = _toolTimeoutFor(name, args);
    final heavy = _isHeavyCall(name, args);
    // 任务真正结束时：解除本工具造成的 lane 隔离 + 释放重内存互斥。
    // 隔离标记只在"仍是本工具留下的"时才清——冷却期满后别的工具可能已经
    // 重新置了标记，不能替它解封。
    void settle() {
      if (isReadOnly) {
        if (_blockedReadToolNames[gateIndex] == name) {
          _blockedReadToolNames[gateIndex] = null;
          _blockedReadSince[gateIndex] = null;
        }
      } else if (_blockedWriteToolName == name) {
        _blockedWriteToolName = null;
        _blockedWriteSince = null;
      }
    }

    Future<T> attempt(Completer<void>? heavyHold) {
      final running = task();
      running.then(
        (_) {
          settle();
          _releaseHeavyHold(heavyHold);
        },
        onError: (Object _, StackTrace __) {
          settle();
          _releaseHeavyHold(heavyHold);
        },
      );
      return running.timeout(
        timeout,
        onTimeout: () {
          // 用户报告 #3：超时后**立即解除 lane 标记**，不要留"仍在运行"120s。
          //
          // 重内存工具是例外，而这个例外是拿代价换来的：它的原生任务可能仍在跑并
          // 占着数百 MB 堆，此时放行下一个重内存工具会让峰值叠加（历史 7 次 OOM
          // 崩溃就是这么来的，见下面 D17 注释）。所以分两类：
          //   - 非重内存（文件写锁类 / 只读类）：**立刻解除**占用标记。它们不持有
          //     大块原生内存，挂着"仍在运行"只会连坐无关调用。
          //   - 重内存：保留隔离 + 冷却兜底（任务结束或冷却期满才放行）。
          if (!heavy) {
            settle();
            throw TimeoutException('$name timed out', timeout);
          }
          if (isReadOnly) {
            _blockedReadToolNames[gateIndex] = name;
            _blockedReadSince[gateIndex] = DateTime.now();
          } else {
            _blockedWriteToolName = name;
            _blockedWriteSince = DateTime.now();
          }
          if (heavyHold != null) {
            // D17：超时只结束"调用方的等待"，原生任务仍在跑并占着数百 MB
            // 堆。旧实现在超时点就释放重内存互斥，于是僵尸任务与下一个重
            // 内存工具的峰值叠加——7 次 OOM 崩溃正是这么来的。现在改为：
            // 任务真正结束（上面两个回调）或冷却期满（兜底，防僵尸永久占
            // 位把重内存工具链彻底堵死）才放行。
            Timer(_laneRecoveryCooldown, () => _releaseHeavyHold(heavyHold));
          }
          throw TimeoutException('$name timed out', timeout);
        },
      );
    }

    final guarded = gate.then((_) {
      if (!heavy) return attempt(null);
      // heavy：额外与全局 _heavyOpsGate 互斥，等前一个重内存工具释放后再执行
      final hold = Completer<void>();
      final heavyPrev = _heavyOpsGate;
      _heavyOpsGate = heavyPrev.then((_) => hold.future);
      return heavyPrev.then((_) => attempt(hold));
    });
    final nextGate = guarded.then((_) {}, onError: (_) {});
    if (isReadOnly) {
      _readToolGates[gateIndex] = nextGate;
    } else {
      _writeToolGate = nextGate;
    }
    return guarded;
  }

  /// 只读幂等调用的重放缓存（见 `_replayIfAvailable`）。
  ///
  /// 上限 64 条：MCP 会话里"重发同参核对"是零星动作，不需要长历史；满了丢最旧。
  final Map<String, Map<String, dynamic>> _readReplayCache =
      <String, Map<String, dynamic>>{};
  static const int _maxReadReplayEntries = 64;

  /// 可重放的只读工具：**贵**且**由工作区状态唯一决定**。
  ///
  /// 放宽只给这一类：它们的重复调用是"重复验证同一证据"（浪费一次整包扫描），
  /// 回放上次结果即可满足核对需求。刻意**不含**时间/剪贴板/设备/定位/任务状态
  /// 这类"每次调用结果本就该变"的廉价读——那些重复仍按原样拦截，避免用旧值
  /// 冒充新值。
  static const Set<String> _replayableReadTools = <String>{
    LocalToolNames.apkToolMap,
    LocalToolNames.workspacePolicy,
    LocalToolNames.apkReport,
    LocalToolNames.apkProjectInfo,
    LocalToolNames.apkPatchMemory,
    LocalToolNames.apkListBuilds,
    LocalToolNames.apkArchive,
    LocalToolNames.dexSearch,
    LocalToolNames.dexXref,
    LocalToolNames.classOutline,
    LocalToolNames.stringScan,
    LocalToolNames.smaliRead,
    LocalToolNames.jadxDecompile,
    LocalToolNames.soAnalyze,
    AnalyzerToolNames.globalSearch,
    AnalyzerToolNames.fieldUsage,
    AnalyzerToolNames.businessState,
    AnalyzerToolNames.open,
  };

  /// 记下一次成功的只读调用结果，供被环路闸门拦下的重复调用回放。
  void _rememberReadResult(
    String sessionKey,
    String name,
    Map<String, dynamic> args, {
    required bool isReadOnly,
    required Map<String, dynamic> result,
  }) {
    if (!isReadOnly) {
      // 写操作会改变读取结果：写后读必须重新执行，缓存清零。
      _readReplayCache.clear();
      return;
    }
    if (ToolCallLoopGuard.changesState(name, args)) return;
    if (!_replayableReadTools.contains(name)) return;
    if (result['isError'] == true) return;
    final key =
        '$sessionKey\u0000${ToolCallLoopGuard.fingerprintOf(name, args)}';
    _readReplayCache.remove(key);
    _readReplayCache[key] = result;
    while (_readReplayCache.length > _maxReadReplayEntries) {
      _readReplayCache.remove(_readReplayCache.keys.first);
    }
  }

  /// 环路闸门拦下的调用若是"只读 + 不改状态 + 有缓存"，回放上次结果。
  ///
  /// 返回 null 表示没有可回放的结果（调用方仍回 loop_detected 硬错误）。
  Map<String, dynamic>? _replayIfAvailable(
    String sessionKey,
    String name,
    Map<String, dynamic> args, {
    required bool isReadOnly,
  }) {
    if (!isReadOnly) return null;
    if (!_replayableReadTools.contains(name)) return null;
    if (ToolCallLoopGuard.changesState(name, args)) return null;
    final key =
        '$sessionKey\u0000${ToolCallLoopGuard.fingerprintOf(name, args)}';
    final cached = _readReplayCache[key];
    if (cached == null) return null;
    final content = cached['content'];
    if (content is! List || content.isEmpty) return null;
    return <String, dynamic>{
      ...cached,
      'content': <dynamic>[
        for (final item in content)
          if (item is Map && item['type'] == 'text')
            <String, dynamic>{
              ...item,
              'text': _annotateReplay(item['text']?.toString() ?? ''),
            }
          else
            item,
      ],
    };
  }

  /// 回放结果必须自报家门：调用方能区分"新执行"与"复用上次结果"。
  static String _annotateReplay(String text) {
    try {
      final decoded = jsonDecode(text);
      if (decoded is Map) {
        final map = Map<String, dynamic>.from(
          decoded.map((key, value) => MapEntry(key.toString(), value)),
        );
        return jsonEncode(<String, dynamic>{
          ...map,
          'replayedFromCache': true,
          'replayNote':
              '同参在同一会话的最近窗口里已执行过：本次直接复用上次结果，未重复执行。'
              '需要最新数据就改一个参数（分页游标/范围/timeout）再发，或等窗口滑过。',
        });
      }
    } catch (_) {}
    return '$text\n\n[replayedFromCache: 同参已执行过，本条为复用结果，未重复执行]';
  }

  /// 释放重内存互斥。幂等：任务结束与冷却兜底定时器会先后到达，先到者生效。
  static void _releaseHeavyHold(Completer<void>? hold) {
    if (hold == null || hold.isCompleted) return;
    hold.complete();
  }

  /// 仅供测试：把读/写 lane 摆成"超时隔离中"。
  ///
  /// 隔离状态只有在真有工具跑超时才会出现（最短 15s），单测等不起；用这个缝
  /// 把状态直接摆出来，锁住 D17 的隔离范围：轻量读不受影响、重内存读被拒且
  /// 带可执行细节、写 lane 一律不放行。
  @visibleForTesting
  void debugBlockLanes(String toolName) {
    for (var i = 0; i < _blockedReadToolNames.length; i++) {
      _blockedReadToolNames[i] = toolName;
      _blockedReadSince[i] = DateTime.now();
    }
    _blockedWriteToolName = toolName;
    _blockedWriteSince = DateTime.now();
  }

  /// 仅供测试：清掉测试摆出的隔离状态。
  @visibleForTesting
  void debugClearLanes() {
    for (var i = 0; i < _blockedReadToolNames.length; i++) {
      _blockedReadToolNames[i] = null;
      _blockedReadSince[i] = null;
    }
    _blockedWriteToolName = null;
    _blockedWriteSince = null;
  }

  Map<String, dynamic> _toolTextResult(String text, {required bool isError}) {
    return <String, dynamic>{
      'isError': isError,
      'content': <dynamic>[
        <String, dynamic>{'type': 'text', 'text': text},
      ],
    };
  }

  static const Map<String, dynamic> _toolOutputSchema = <String, dynamic>{
    'type': 'object',
    'additionalProperties': false,
    'properties': <String, dynamic>{
      'ok': <String, dynamic>{'type': 'boolean'},
      'data': <String, dynamic>{},
      'error': <String, dynamic>{
        'type': <String>['object', 'null'],
        'properties': <String, dynamic>{
          'code': <String, dynamic>{'type': 'string'},
          'message': <String, dynamic>{'type': 'string'},
          'recoverable': <String, dynamic>{'type': 'boolean'},
          'retrySameArguments': <String, dynamic>{'type': 'boolean'},
        },
        'required': <String>[
          'code',
          'message',
          'recoverable',
          'retrySameArguments',
        ],
      },
      'nextActions': <String, dynamic>{'type': 'array'},
    },
    'required': <String>['ok', 'data', 'error', 'nextActions'],
  };

  /// 归一并返回 (文本, 是否失败)。返回 record 而非裸 String：调用方
  /// （_completedToolResult）需要 ok 判定 isError，此前靠归一后再
  /// jsonDecode 一次——512KB 结果第三遍解码纯属浪费。
  /// 已是「无需修补」的标准信封时原样透传（零重编码）：成功信封
  /// （error:null）与已带 recoverable 的失败信封（Kotlin err() 契约恒带）
  /// 都不会因归一改变内容。
  (String, bool) _normalizeToolOutput(String output, {String? tool}) {
    try {
      final decoded = jsonDecode(output);
      if (decoded is Map) {
        final raw = Map<String, dynamic>.from(
          decoded.map((key, value) => MapEntry(key.toString(), value)),
        );
        if (raw.containsKey('data') &&
            raw.containsKey('error') &&
            raw.containsKey('nextActions') &&
            raw['ok'] is bool) {
          final failed = raw['ok'] == false;
          final rawError = raw['error'];
          final alreadyComplete =
              rawError == null ||
              (rawError is Map && rawError.containsKey('recoverable'));
          if (alreadyComplete && rawError == null) return (output, failed);
          // 已是标准 envelope：补齐 recoverable + 归一错误码 + 空动作兜底，
          // 其余原样透传（D7/D8：过去"已有 recoverable"会整份原样返回，
          // 于是原生大写码与空 nextActions 就这么漏给了调用方）。
          return (
            jsonEncode(
              _alignErrorEnvelope(
                ToolErrorPolicy.enrichEnvelope(raw),
                tool: tool,
              ),
            ),
            failed,
          );
        }
        final rawError = raw['error'];
        final failed = raw['ok'] == false || rawError != null;
        var data = Map<String, dynamic>.from(raw)
          ..remove('ok')
          ..remove('error')
          ..remove('nextActions')
          // recoverable 已提升到 error 对象内，避免在数据里重复出现。
          ..remove('recoverable');
        // 平铺（2026-09-19 复测 DEF-19）：handler 自己就有 `data` 字段时
        // （patch_apk_manifest 等写工具），再包一层会变成 data.data —— 与其它
        // 写工具的单词层不一致，调用方容易取错。判据收紧：仅当同级键**全是
        // 标量**（无数组/对象）时才认定「外层只是信封」，把内层摊到顶层。
        final nested = data['data'];
        if (nested is Map &&
            data.length > 1 &&
            data.entries.every(
              (entry) =>
                  entry.key == 'data' ||
                  entry.value == null ||
                  entry.value is String ||
                  entry.value is num ||
                  entry.value is bool,
            )) {
          data = <String, dynamic>{
            for (final entry in data.entries)
              if (entry.key != 'data') entry.key: entry.value,
            ...nested.map((key, value) => MapEntry(key.toString(), value)),
          };
        }
        // R5：recoverable 由错误码判定。此前一律 true，会让客户端对
        // unsupported_platform 这类原样重试必然再次失败的错误反复重试。
        final errorCode = rawError is Map
            ? (rawError['code'] ?? 'tool_failed').toString()
            : rawError is String && rawError.isNotEmpty
            ? rawError
            : 'tool_failed';
        final errorRecoverable = raw['recoverable'] is bool
            ? raw['recoverable'] as bool
            : ToolErrorPolicy.recoverableFor(errorCode);
        final envelope = <String, dynamic>{
          'ok': !failed,
          'data': data,
          'error': failed
              ? <String, dynamic>{
                  'code': errorCode,
                  'message': rawError is Map
                      ? (rawError['message'] ?? rawError).toString()
                      : (raw['message'] ?? rawError ?? '工具执行失败').toString(),
                  'recoverable': errorRecoverable,
                  'retrySameArguments': false,
                }
              : null,
          'nextActions': raw['nextActions'] is List
              ? raw['nextActions']
              : const <dynamic>[],
        };
        return (
          failed
              ? jsonEncode(_alignErrorEnvelope(envelope, tool: tool))
              : jsonEncode(envelope),
          failed,
        );
      }
      return (
        jsonEncode(<String, dynamic>{
          'ok': true,
          'data': decoded,
          'error': null,
          'nextActions': const <dynamic>[],
        }),
        false,
      );
    } catch (_) {
      return (
        jsonEncode(<String, dynamic>{
          'ok': true,
          'data': output,
          'error': null,
          'nextActions': const <dynamic>[],
        }),
        false,
      );
    }
  }

  /// MCP 侧自产错误的 recoverable 必须走 ToolErrorPolicy 单一判定（R5），
  /// 不得硬编码 true——unsupported/not_available 类错误原样重试必然再败，
  /// 假标记会让远端 agent 空耗轮次。
  ///
  /// [details] 用于参数类错误：把 parameter / expected / actual / allowedValues
  /// 一并带回（2026-09-19 全量复测 DEF-02/06：错误必须指得出是哪个参数、允许
  /// 值是什么，调用方才能一趟改对）。
  ///
  /// [nextActions] 同理——MCP 自产错误过去一律空数组，调用方只能自己猜
  /// （DEF 复核时实测 `loop_detected`/`tool_not_found` 都无动作建议）。这里
  /// 按错误码给一条可执行动作，形状与 MT 的 `{tool, reason}` 对齐。
  String _toolErrorOutput(
    String code,
    String message, {
    Map<String, dynamic>? details,
    String? tool,
  }) {
    // D7：错误码风格统一为 lower_snake（生产端历史上有全大写/驼峰/自由文本
    // 三种拼法），原始写法保留在 rawCode 便于按老码翻日志。
    final normalized = ToolErrorPolicy.normalizeCode(code);
    final action = _recoveryActionFor(normalized, tool: tool, details: details);
    // F-39（2026-10-05）：MCP 自产错误同样走唯一裁决点——否则它就是第五种
    // 失败形状（缺 error.severity/diagnostics 与顶层镜像）。
    return jsonEncode(ToolErrorPolicy.unifyFailure(<String, dynamic>{
      'ok': false,
      'data': null,
      'error': <String, dynamic>{
        'code': normalized,
        if (normalized != code.trim()) 'rawCode': code,
        'message': message,
        for (final entry in (details ?? const <String, dynamic>{}).entries)
          if (entry.key != 'code' && entry.key != 'message')
            entry.key: entry.value,
        'recoverable': ToolErrorPolicy.recoverableFor(normalized),
        'retrySameArguments': false,
      },
      'nextActions': <dynamic>[if (action != null) action],
    }, tool: tool));
  }

  /// D7/D8 + F-39：把已成型 envelope 收敛到**唯一规范失败形**（含错误码归一、
  /// rawCode 保留、顶层 code/message/recoverable 镜像、nextActions 兜底），
  /// 再给"有码无动作"的失败补一条可执行恢复动作。成功回执原样返回。
  Map<String, dynamic> _alignErrorEnvelope(
    Map<String, dynamic> envelope, {
    String? tool,
  }) {
    // F-39 收口（2026-10-05 v11 复测）：三种失败形状（file/so_analyze/
    // patch_apk_dex_strings 各缺不同顶层字段）统一交给 ToolErrorPolicy.unifyFailure
    // 一处裁决——包括「无码失败」合成 missing_error_code。
    final unified = ToolErrorPolicy.unifyFailure(
      envelope,
      tool: tool ?? envelope['tool']?.toString(),
    );
    final errRaw = unified['error'];
    if (errRaw is! Map) return unified;
    final errMap = Map<String, dynamic>.from(
      errRaw.map((key, value) => MapEntry(key.toString(), value)),
    );
    final code = ToolErrorPolicy.normalizeCode(ToolErrorPolicy.codeOf(errMap));
    final actions = unified['nextActions'];
    if (actions is List && actions.isNotEmpty) {
      return unified;
    }
    final action = _recoveryActionFor(code, tool: tool, details: errMap);
    if (action == null) return unified;
    return <String, dynamic>{
      ...unified,
      'nextActions': <dynamic>[action],
    };
  }

  /// MCP 自产错误 → 一条可执行恢复动作（工具名 + 理由）。
  ///
  /// 动作必须"可照抄"：带 tool 时调用方直接换工具重发；需要参数的带
  /// `arguments`/`retryAfterSeconds`；没有对应工具的就不给动作（宁可空，
  /// 也不给一条执行不了的空壳）。
  Map<String, dynamic>? _recoveryActionFor(
    String code, {
    String? tool,
    Map<String, dynamic>? details,
  }) {
    switch (code) {
      case 'loop_detected':
        return <String, dynamic>{
          'action': 'change_evidence',
          if (tool != null) 'tool': tool,
          'reason': '同参在滑窗内已执行过：换参数/地址/分页游标/分析路径，或直接使用已有结果；不要原样重发。',
        };
      case 'tool_not_found':
        return <String, dynamic>{
          'action': 'list_tools',
          'tool': LocalToolNames.apkToolMap,
          'reason': '先取可用工具名单与全参（tools/list 只给压缩 schema）。',
        };
      case 'tool_busy_timeout':
        return <String, dynamic>{
          'action': 'poll_or_wait',
          if (details?['taskId'] != null)
            'arguments': <String, dynamic>{'taskId': details!['taskId']},
          'tool': taskStatusTool,
          'reason':
              '任务仍在后台执行（超时只结束等待，不结束任务）：有 taskId 用 mcp_task_status 轮询；'
              '没有 taskId 说明是同步调用，等一会再发同一调用（该调用已从环路滑窗移除，允许重发）。',
        };
      case 'tool_lane_blocked':
        return <String, dynamic>{
          'action': 'wait_then_narrow',
          if (details?['retryAfterSeconds'] is num)
            'retryAfterSeconds': details!['retryAfterSeconds'],
          if (details?['blockedTool'] != null)
            'blockedTool': details!['blockedTool'],
          'reason':
              '同通道的前一个重型任务超时后仍在跑，重内存工具暂缓（轻量读工具不受影响）。'
              '按 retryAfterSeconds 等待后重发，并把上次的调用收窄（更小范围/分页）再试。',
        };
      case 'task_not_found':
        return <String, dynamic>{
          'action': 'restart',
          if (tool != null) 'tool': tool,
          'reason': '任务已完成并被回收（或 taskId 写错）：确认后重新发起原调用。',
        };
      case 'missing_argument':
      case 'invalid_argument_type':
      case 'invalid_argument_value':
      case 'invalid_args':
        return <String, dynamic>{
          'action': 'fix_argument',
          if (tool != null) 'tool': tool,
          'reason': '按 parameter/expected/allowedValues 修正参数后重试同工具。',
        };
      case 'confirmation_required':
      case 'preview_required':
      case 'preview_token_required':
        return <String, dynamic>{
          'action': 'preview_then_apply',
          if (tool != null) 'tool': tool,
          'reason':
              '写工具要先预览再落地：dryRun=true 拿到预览与 previewToken（用户已明确授权本次精确修改时，'
              '可在 dryRun=true 的同一次调用里加 applyAfterPreview=true 一次完成），'
              '然后以预览回执里的 nextInputPath 继续，不要对旧包重发。',
        };
      case 'apk_not_found':
      case 'invalid_apk_path':
      case 'so_path_not_found':
      case 'path_outside_workspace':
      case 'path_required':
      case 'so_path_required':
        return <String, dynamic>{
          'action': 'inspect_workspace',
          'tool': LocalToolNames.file,
          'arguments': <String, dynamic>{'action': 'inventory'},
          'reason':
              '路径不存在或不在工作目录内：先用 file(action=inventory) 取工作目录里的实际文件名，'
              '再传绝对路径重发（相对名会按工作目录解析）。',
        };
      case 'stale_report':
      case 'report_not_ready':
      case 'no_apk_selected':
      case 'project_not_ready':
      case 'no_result':
        return <String, dynamic>{
          'action': 'refresh_report',
          'tool': LocalToolNames.apkAnalyzeWorkspace,
          'reason':
              '当前 APK 报告过期或缺失：先重跑 analyze_apk_workspace（或在工作台重新选择 APK）再调用本工具。',
        };
      case 'work_dir_required':
      case 'work_dir_not_set':
      case 'output_dir_required':
      case 'workspace_not_set':
      case 'workspace_required':
        return <String, dynamic>{
          'action': 'configure_workspace',
          'tool': LocalToolNames.workspacePolicy,
          'reason': '工作目录/工作区未设置：先用 get_workspace_policy 看当前要求与设置入口，再重发本调用。',
        };
      case 'tool_exception':
      case 'tool_failed':
        return <String, dynamic>{
          'action': 'retry_or_report',
          if (tool != null) 'tool': tool,
          'reason': '工具内部异常（非参数问题）：修正输入后重试一次；连续两次失败换实现路径并报缺陷。',
        };
      case 'no_match':
        return <String, dynamic>{
          'action': 'change_evidence',
          if (tool != null) 'tool': tool,
          'reason':
              '0 命中：换关键词、把 matchType 从 Equals 放宽到 Contains、或换证据维度，不要原样重发。',
        };
      default:
        return null;
    }
  }

  /// 分级截断：长提示词/长结果按工具类别用不同上限，防止撑爆远端 AI 上下文。
  /// [limitOverride] 为指定工具的更低上限（如内部技能/知识提示词）。
  String _truncate(String text, {int? limitOverride}) {
    final limit = limitOverride ?? maxResultChars;
    if (text.length <= limit) return text;
    try {
      final decoded = jsonDecode(text);
      if (decoded is Map) {
        final envelope = <String, dynamic>{
          'ok': decoded['ok'] is bool ? decoded['ok'] : true,
          'data': <String, dynamic>{
            'truncated': true,
            'originalLength': text.length,
            'preview': '',
          },
          'error': decoded['error'],
          // 截断必须自报家门并给续读路径（2026-09-19 复测：过去只回
          // truncated/originalLength + 半截 preview，nextActions 原样透传，
          // MCP 客户端拿不到「怎么取回余下内容」）。
          'nextActions': <dynamic>[
            ...(decoded['nextActions'] is List
                ? decoded['nextActions'] as List
                : const <dynamic>[]),
            <String, dynamic>{
              'action': 'narrow_scope',
              'reason':
                  '结果超过 ${limit ~/ 1024}KB 上限已被截断（原始 ${text.length} 字符，'
                  '下方 preview 只是前半截）：对该调用补 limit/offset/分页游标/'
                  '关键词过滤后重发同一工具，或改用 tool_batch 分批；'
                  '不要把这份结果当完整结果使用。',
            },
          ],
        };
        var previewLength = limit ~/ 2;
        while (previewLength > 0) {
          (envelope['data'] as Map<String, dynamic>)['preview'] = text
              .substring(0, previewLength);
          final encoded = jsonEncode(envelope);
          if (encoded.length <= limit) return encoded;
          previewLength ~/= 2;
        }
        (envelope['data'] as Map<String, dynamic>)['preview'] = '';
        return jsonEncode(envelope);
      }
    } catch (_) {}
    return jsonEncode(<String, dynamic>{
      'ok': true,
      'data': <String, dynamic>{
        'truncated': true,
        'originalLength': text.length,
        'preview': text.substring(0, limit ~/ 2),
      },
      'error': null,
      'nextActions': const <dynamic>[],
    });
  }

  /// 内部提示词类工具（技能正文/知识条目）：仅给远端 AI 摘要，不吐全文。
  static bool _isPromptLikeTool(String name) =>
      name == LocalToolNames.apkSkill ||
      name == LocalToolNames.apkKnowledge ||
      name == LocalToolNames.installedSkills;

  // ---------------------------------------------------------------------------
  // Discovery / auth / responses
  // ---------------------------------------------------------------------------

  Map<String, dynamic> _discovery() {
    return <String, dynamic>{
      'ok': true,
      'name': 'SoLab',
      'protocol': 'MCP JSON-RPC 2.0',
      'transports': <dynamic>['streamable-http', 'http+sse'],
      'streamableHttpEndpoint': '/mcp',
      'sseEndpoint': '/sse',
      'messagesEndpoint': '/messages',
      'methods': <dynamic>[
        'initialize',
        'notifications/initialized',
        'ping',
        'tools/list',
        'tools/call',
        'resources/list',
        'prompts/list',
      ],
      'lanUrls': _lanIps.map((ip) => 'http://$ip:$_port/mcp').toList(),
      'authRequired': authRequired,
      'hint':
          'Streamable HTTP: POST JSON-RPC to /mcp. '
          'Legacy SSE: GET /sse then POST /messages?sessionId=... (responses via SSE).',
    };
  }

  Future<List<String>> _resolveLanIps() async {
    try {
      final interfaces = await NetworkInterface.list(
        type: InternetAddressType.IPv4,
      );
      return interfaces
          .expand((i) => i.addresses)
          .map((a) => a.address)
          .where((a) => !a.startsWith('127.'))
          .toList(growable: false);
    } catch (_) {
      return const <String>[];
    }
  }

  /// 心跳周期 20s：低于 vivo 等厂商约 30s 的后台网络代答阈值。
  void _startNetHeartbeat() {
    _netHeartbeatTimer?.cancel();
    _netHeartbeatTimer = Timer.periodic(const Duration(seconds: 20), (_) {
      _runNetHeartbeat();
    });
  }

  /// 向网关发起短连接：无论成功/被拒/超时，出站 SYN 已产生，
  /// 足以维持系统侧的网络活跃标记。连通过的网关会被缓存。
  Future<void> _runNetHeartbeat() async {
    if (_lanIps.isEmpty) return;
    final parts = _lanIps.first.split('.');
    if (parts.length != 4) return;
    final gateway =
        _netHeartbeatGateway ?? '${parts[0]}.${parts[1]}.${parts[2]}.1';
    try {
      final socket = await Socket.connect(
        gateway,
        80,
        timeout: const Duration(seconds: 4),
      );
      socket.destroy();
      _netHeartbeatGateway ??= gateway;
    } catch (_) {
      // 出站流量已产生，心跳目的达成
    }
  }

  bool _authorized(HttpRequest req) {
    if (!authRequired) return true;
    final auth = req.headers.value(HttpHeaders.authorizationHeader) ?? '';
    final bearer = auth.startsWith('Bearer ') ? auth.substring(7).trim() : '';
    if (bearer.isNotEmpty) return constTimeEquals(bearer, _token);
    // query token 已停用（2026-09-15）。原实现作为兼容保留，但 URL query 会
    // 原样落进客户端历史、代理日志、服务端 access log 与浏览器地址栏——
    // 令牌一旦进日志就等于长期有效泄露。这里显式拒绝而非静默忽略：静默
    // 忽略会表现为"带了 token 仍 401"，调用方无从判断是 token 错还是
    // 通道错；显式报错 + 引导改用 Header 才能自解释。
    final queryToken = req.uri.queryParameters['token'] ?? '';
    _lastAuthRejectedQueryToken = queryToken.isNotEmpty;
    return false;
  }

  /// 上一次鉴权失败是否因使用了已停用的 query token——用于给出针对性引导。
  bool _lastAuthRejectedQueryToken = false;

  /// 恒定时间字符串比较：全程遍历、不因首字符不同短路，且不因长度不同
  /// 提前返回——原实现开头就 'if (a.length != b.length) return false;'，
  /// 响应时间随「长度是否相等、前缀匹配多远」变化，是可被利用的时序侧信道
  /// （探测令牌长度）。现在把长度差折进 diff，并按较长串长度跑满循环。
  @visibleForTesting
  static bool constTimeEquals(String a, String b) {
    var diff = a.length ^ b.length;
    final n = a.length > b.length ? a.length : b.length;
    for (var i = 0; i < n; i++) {
      final ca = i < a.length ? a.codeUnitAt(i) : 0;
      final cb = i < b.length ? b.codeUnitAt(i) : 0;
      diff |= ca ^ cb;
    }
    return diff == 0;
  }

  Map<String, dynamic> _authError() => _rpcError(
    null,
    -32001,
    _lastAuthRejectedQueryToken
        ? 'Unauthorized: the ?token= query parameter is no longer supported '
              '(URLs leak into client history, proxy logs and browser address '
              'bars). Send the token in the Authorization header instead: '
              'Authorization: Bearer <token>.'
        : 'Unauthorized: missing or invalid token',
  );

  Map<String, dynamic> _rpcError(dynamic id, int code, String message) {
    return <String, dynamic>{
      'jsonrpc': '2.0',
      'id': id,
      'error': <String, dynamic>{'code': code, 'message': message},
    };
  }

  void _addCorsHeaders(HttpRequest req) {
    final headers = req.response.headers;
    // T1.3：CORS 收窄——默认只放行本机回环；局域网 Origin（本机已知
    // LAN IP 上的页面）额外放行。不再无条件 `*`（防浏览器跨域直打 /mcp）。
    final origin = req.headers.value('Origin') ?? '';
    final host = req.headers.value(HttpHeaders.hostHeader) ?? '';
    final originAllowed = _originAllowed(origin, host);
    if (originAllowed) {
      headers.set('Access-Control-Allow-Origin', origin);
    }
    // 不在白名单时**不下发** ACAO：绝不能写死 'null'——沙箱 iframe / data: /
    // file:// 页面发出的正是 `Origin: null`，浏览器会把它与字面量 'null' 判为
    // 匹配，于是拒绝路径反而变成放行路径（可跨域读 /mcp 响应）。
    headers.set('Vary', 'Origin');
    headers.set('Access-Control-Allow-Credentials', 'false');
    headers.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    headers.set(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Mcp-Session-Id, Last-Event-ID',
    );
  }

  /// Host 白名单：空 Host（HTTP/1.0）放行；否则仅放行
  /// 127.0.0.1 / localhost / [::1] / 本机局域网 IP。
  bool _hostAllowed(HttpRequest req) {
    final host = req.headers.value(HttpHeaders.hostHeader) ?? '';
    if (host.isEmpty) return true;
    final hostname = _hostNameOf(host);
    if (hostname == '127.0.0.1' ||
        hostname == 'localhost' ||
        hostname == '::1') {
      return true;
    }
    return _lanIps.any((ip) => ip == hostname);
  }

  /// 从 Host 头取主机名。`Host: [::1]:8800` 用 `split(':').first` 只会得到
  /// `[`，IPv6 回环连不上任何白名单分支而一律 403 host_not_allowed；交给 Uri
  /// 解析能得到真正的 `::1`。畸形 Host 回退到旧行为，由白名单拒绝而不是抛异常。
  static String _hostNameOf(String host) {
    try {
      final parsed = Uri.parse('http://$host').host;
      if (parsed.isNotEmpty) return parsed.toLowerCase();
    } catch (_) {}
    return host.split(':').first.toLowerCase();
  }

  /// Origin 白名单：无 Origin（非浏览器/curl）放行；有 Origin 时仅放行
  /// 与本机 host 或本机回环/局域网地址同源的 Origin。
  bool _originAllowed(String origin, String host) {
    if (origin.isEmpty) return true;
    try {
      final o = Uri.parse(origin);
      final oHost = o.host.toLowerCase();
      if (oHost == '127.0.0.1' ||
          oHost == 'localhost' ||
          oHost == '[::1]' ||
          oHost == '::1') {
        return true;
      }
      if (_lanIps.any((ip) => ip == oHost)) return true;
      // Origin host 与请求 Host 同源也放行（本机页面经局域网 IP 访问）。
      final h = _hostNameOf(host);
      return oHost == h;
    } catch (_) {
      return false;
    }
  }

  void _respondNoContent(HttpRequest req) {
    req.response.statusCode = HttpStatus.noContent;
    req.response.close();
  }

  /// 大 payload（工具结果可达数 MB）的 jsonEncode 移到后台 isolate，
  /// 避免主 isolate 同步编码造成 UI 卡顿；小对象保持同步编码零开销。
  static const int _isolateEncodeThresholdChars = 256 * 1024;

  static int _estimateJsonSize(Object? value, [int depth = 0]) {
    if (value is String) return value.length + 2;
    if (value is num || value is bool) return 8;
    if (value == null) return 4;
    if (depth > 6) return 64;
    if (value is Map) {
      var total = 0;
      value.forEach((k, v) {
        total += k.toString().length + 4 + _estimateJsonSize(v, depth + 1);
      });
      return total;
    }
    if (value is List) {
      var total = 0;
      for (final item in value) {
        total += 2 + _estimateJsonSize(item, depth + 1);
      }
      return total;
    }
    return 32;
  }

  Future<String> _encodeJsonBody(Object? body) async {
    if (_estimateJsonSize(body) <= _isolateEncodeThresholdChars) {
      return jsonEncode(body);
    }
    try {
      return await Isolate.run(() => jsonEncode(body));
    } catch (_) {
      // isolate 编码失败（不可发送对象等）退回同步编码，保证功能不受影响
      return jsonEncode(body);
    }
  }

  Future<void> _respondJson(
    HttpRequest req,
    dynamic body, {
    int status = HttpStatus.ok,
  }) async {
    await _respondText(
      req,
      await _encodeJsonBody(body),
      ContentType.json,
      status: status,
    );
  }

  Future<void> _respondText(
    HttpRequest req,
    String text,
    ContentType type, {
    int status = HttpStatus.ok,
  }) async {
    req.response.statusCode = status;
    req.response.headers.contentType = type;
    final acceptEncoding =
        req.headers.value(HttpHeaders.acceptEncodingHeader) ?? '';
    final doGzip = text.length > 4096 && acceptEncoding.contains('gzip');
    if (!doGzip) {
      req.response.write(text);
      await req.response.close();
      return;
    }
    // 流式 gzip：utf8 分块 → gzip 增量压缩 → chunked 发送。全程只有块级
    // 缓冲，不再同时驻留"完整 JSON + 完整 gzip"两份大内存（工具结果可达
    // 数 MB，原来两份串行拷贝直接翻倍峰值）；头部先 flush，客户端更早收到
    // 响应头与首批压缩数据，首字节延迟同步下降。小响应压缩反耗 CPU。
    req.response.headers.set(HttpHeaders.contentEncodingHeader, 'gzip');
    await req.response.flush();
    final gzipSink = gzip.encoder.startChunkedConversion(
      _ChunkForwardSink(req.response.add),
    );
    const chunkChars = 128 * 1024;
    for (var start = 0; start < text.length; start += chunkChars) {
      var end = start + chunkChars;
      if (end > text.length) {
        end = text.length;
      } else if (text.codeUnitAt(end - 1) >= 0xD800 &&
          text.codeUnitAt(end - 1) <= 0xDBFF) {
        // 不拆散 UTF-16 代理对：块尾若是高代理项，回退 1 个 char
        end -= 1;
      }
      gzipSink.add(utf8.encode(text.substring(start, end)));
    }
    gzipSink.close();
    await req.response.close();
  }
}

/// gzip 增量压缩输出的转发 sink：每块压缩字节直接写入 HTTP 响应。
class _ChunkForwardSink implements Sink<List<int>> {
  _ChunkForwardSink(this._add);

  final void Function(List<int> chunk) _add;

  @override
  void add(List<int> chunk) => _add(chunk);

  @override
  void close() {}
}

/// 一条旧版 HTTP+SSE 传输的客户端长连接。
class _SseSession {
  _SseSession(this.id, this.response);

  final String id;
  final HttpResponse response;
  Timer? heartbeat;
  bool closed = false;

  Future<void> push(String chunk) async {
    if (closed) return;
    try {
      response.write(chunk);
      await response.flush();
    } catch (_) {
      closed = true;
    }
  }
}

enum _McpTaskStatus { queued, running, completed, failed }

class _McpToolTask {
  _McpToolTask(this.id, this.tool, this.arguments)
    : action = arguments['action']?.toString(),
      subAction = arguments['blutterAction']?.toString(),
      fingerprint = jsonEncode(arguments),
      createdAt = DateTime.now();

  final String id;
  final String tool;
  final Map<String, dynamic> arguments;
  final String? action;
  final String? subAction;
  final String fingerprint;
  final DateTime createdAt;
  _McpTaskStatus status = _McpTaskStatus.queued;
  DateTime? startedAt;
  DateTime? finishedAt;
  String? result;
  String? error;

  void start() {
    status = _McpTaskStatus.running;
    startedAt = DateTime.now();
  }

  void complete(String value) {
    result = value;
    status = _McpTaskStatus.completed;
    finishedAt = DateTime.now();
  }

  void fail(String value) {
    error = value;
    status = _McpTaskStatus.failed;
    finishedAt = DateTime.now();
  }

  Map<String, dynamic> toJson() {
    final end = finishedAt ?? DateTime.now();
    final phase = switch (status) {
      _McpTaskStatus.queued => 'queued',
      _McpTaskStatus.running => 'executing',
      _McpTaskStatus.completed || _McpTaskStatus.failed => 'finished',
    };
    final progressPercent = switch (status) {
      _McpTaskStatus.queued => 0,
      _McpTaskStatus.running => null,
      _McpTaskStatus.completed || _McpTaskStatus.failed => 100,
    };
    return <String, dynamic>{
      'ok': status != _McpTaskStatus.failed,
      'taskId': id,
      'tool': tool,
      'status': status.name,
      'phase': phase,
      if (progressPercent != null) 'progressPercent': progressPercent,
      if (status == _McpTaskStatus.running) 'progressIndeterminate': true,
      'elapsedMs': end.difference(createdAt).inMilliseconds,
      if (action != null) 'action': action,
      if (subAction != null) 'subAction': subAction,
      'createdAt': createdAt.millisecondsSinceEpoch,
      if (startedAt != null) 'startedAt': startedAt!.millisecondsSinceEpoch,
      if (finishedAt != null) 'finishedAt': finishedAt!.millisecondsSinceEpoch,
      if (result != null) 'result': result,
      if (error != null) 'error': error,
    };
  }
}

class _McpAdaptiveResult {
  const _McpAdaptiveResult({this.output, this.error});

  final String? output;
  final Object? error;
}

void debugPrintSafely(String message) {
  // ignore: avoid_print
  print(message);
}
