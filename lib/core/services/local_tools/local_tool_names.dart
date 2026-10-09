abstract final class LocalToolNames {
  static const timeInfo = 'get_time_info';
  static const clipboard = 'clipboard_tool';
  static const textToSpeech = 'text_to_speech';
  static const askUser = 'ask_user_input_v0';
  static const calculate = 'calculate';

  /// 数值/字节级计算（自研）：进制与位宽换算、位运算、字节序、IEEE754、
  /// 编解码、哈希/CRC、大数模运算，支持 steps[] 链式引用一次算完。
  static const valueCalc = 'value_calc';
  static const screenTime = 'get_screen_time';
  static const calendarQuery = 'calendar_query';
  static const calendarCreate = 'calendar_create';
  static const remindersComplete = 'reminders_complete';
  static const remindersCreate = 'reminders_create';
  static const remindersQuery = 'reminders_query';

  /// 会修改用户数据的设备工具：调用前必须走显式审批。
  static const Set<String> requiresUserApproval = <String>{
    calendarCreate,
    remindersCreate,
    remindersComplete,
  };
  static const healthSummary = 'get_health_summary';
  static const weather = 'get_weather';
  static const currentLocation = 'get_current_location';

  /// 无障碍「手机控制」（上游 1.3.0）：仅 Android，需用户在系统设置里启用服务，
  /// 且按助手单独开关，默认关。
  static const phoneControl = 'phone_control';
  static const apkReport = 'get_current_apk_report';
  static const apkSkill = 'get_solab_skill';
  static const apkKnowledge = 'get_apk_knowledge';
  static const installedSkills = 'get_installed_skills';
  static const agentRuntimeGuide = 'get_agent_runtime_guide';
  static const apkProjectInfo = 'get_apk_project_info';
  static const apkRules = 'list_apk_rules';
  static const apkPatchDex = 'patch_apk_dex_methods';
  static const apkPatchDexStrings = 'patch_apk_dex_strings';
  static const apkSignatureBypass = 'signature_bypass';
  static const apkPatchManifest = 'patch_apk_manifest';
  static const apkToolMap = 'get_solab_tool_map';
  static const apkPatchMemory = 'get_apk_patch_memory';
  static const apkSavePatchMemory = 'save_apk_patch_memory';
  static const apkRecordPatchVerification = 'record_apk_patch_verification';
  static const apkListBuilds = 'list_apk_builds';
  static const apkCleanupBuilds = 'cleanup_apk_builds';
  static const apkNoteRead = 'apk_note_read';
  static const apkNoteWrite = 'apk_note_write';
  static const apkListWorkspace = 'list_workspace_apks';
  static const apkAnalyzeWorkspace = 'analyze_apk_workspace';

  /// 工作区策略自省（自研，只读）：能碰哪些路径、哪些工具要用户授权、
  /// 预览契约与结果上限。对标 MT MCP 的 mt_file_access_policy。
  static const workspacePolicy = 'get_workspace_policy';
  static const runTaskCommand = 'run_task_command';
  static const runWorkflow = 'run_workflow';
  static const apkArchive = 'apk_archive';
  static const apkExportReport = 'export_apk_report';
  static const jadxDecompile = 'jadx_decompile';
  static const apkSign = 'apk_sign';
  static const apkRebuild = 'apk_rebuild';
  static const dexSearch = 'dex_search';
  static const stringScan = 'string_scan';
  static const dexXref = 'dex_xref';
  static const classOutline = 'class_outline';
  static const smaliRead = 'smali_read';
  static const soAnalyze = 'so_analyze';
  static const soPatchIntoApk = 'so_patch_into_apk';

  /// Frida gadget（自研，无 root 动态插桩入口）：
  /// status / install_gadget（下载+校验+解压）/ inject（注入版 APK）。
  /// 运行期驱动在 Linux 沙盒里（P2），未装沙盒时只提供宿主侧两个动作。
  static const frida = 'frida';

  /// 会话级任务清单（长任务/子代理的外部记忆）。
  static const todoWrite = 'todo_write';
  static const todoRead = 'todo_read';

  /// 目标（会话模式 `/goal`）的模型侧工具：建/读/推进。目标模式 = 免审执行，
  /// 所以这三个工具让模型自己立目标、推进、收尾，而不是只能等用户打斜杠命令。
  static const goalGet = 'get_goal';
  static const goalCreate = 'create_goal';
  static const goalUpdate = 'update_goal';

  /// 子代理派发（一个工具 + agent 参数，见 docs/设计-斜杠命令与子代理.md）。
  static const subagent = 'subagent';
  static const file = 'file';
  static const routeTask = 'route_task';

  // ---- 运行时控制面（§7.4 核心控制；由 features/chat/runtime_tools.dart 分发）----
  // 这些工具不改 APK，只改任务状态或读运行时数据。发布到 **Agent 面**；
  // MCP 面不发布（MCP 侧只有 mcp_task_status 一个状态口，见
  // LocalToolsService.mcpCallableToolNames 的排除集）。
  static const taskStatus = 'task_status';
  static const taskUpdate = 'task_update';
  static const evidenceQuery = 'evidence_query';
  static const artifactRead = 'artifact_read';
  static const patchPlan = 'patch_plan';
  static const dryRunPatch = 'dry_run_patch';
  static const planProbes = 'plan_probes';
  static const verifyApk = 'verify_apk';
  static const collectDelivery = 'collect_delivery';
  static const workspaceCleanup = 'workspace_cleanup';
  static const requestConfirmation = 'request_confirmation';

  /// 运行时控制面的发布名全集（不含 route_task：它有自己的专用 schema/处理器）。
  static const runtimeControl = <String>[
    taskStatus,
    taskUpdate,
    evidenceQuery,
    artifactRead,
    patchPlan,
    dryRunPatch,
    planProbes,
    verifyApk,
    collectDelivery,
    workspaceCleanup,
    requestConfirmation,
  ];

  // ---- 系统级内置工具（不进 LocalToolRegistry，由 ToolHandlerService 直接分发；
  //      仅供 ToolRouter 等路由层引用，避免名单散落成裸字符串）----
  static const memoryRead = 'memory_read';
  static const memoryUpdate = 'memory_update';
  static const memorySearchProfile = 'memory_search_profile';
  static const memoryEdit = 'memory_edit';
  static const memoryDelete = 'memory_delete';
  static const updateUserProfile = 'update_user_profile';
  static const chatSearch = 'chat_search';
  static const getToolResult = 'get_tool_result';

  /// 批量工具调用（ToolHandlerService 直接分发，见 tool_batch 契约）。
  static const toolBatch = 'tool_batch';

  /// 服务端搜索工具（provider 流内建，见 stream_chunk_handler），非本地注册表工具。
  static const searchWeb = 'search_web';

  static const builtin = <String>[
    memoryRead,
    memoryUpdate,
    memorySearchProfile,
    memoryEdit,
    memoryDelete,
    updateUserProfile,
    chatSearch,
    getToolResult,
    searchWeb,
    toolBatch,
  ];

  static const all = <String>[
    timeInfo,
    clipboard,
    textToSpeech,
    askUser,
    calculate,
    valueCalc,
    screenTime,
    calendarQuery,
    calendarCreate,
    remindersComplete,
    remindersCreate,
    remindersQuery,
    healthSummary,
    weather,
    currentLocation,
    phoneControl,
    apkReport,
    apkSkill,
    apkKnowledge,
    installedSkills,
    agentRuntimeGuide,
    apkProjectInfo,
    apkRules,
    apkPatchDex,
    apkPatchDexStrings,
    apkSignatureBypass,
    apkPatchManifest,
    apkToolMap,
    apkPatchMemory,
    apkSavePatchMemory,
    apkRecordPatchVerification,
    apkListBuilds,
    apkCleanupBuilds,
    apkNoteRead,
    apkNoteWrite,
    apkListWorkspace,
    apkAnalyzeWorkspace,
    workspacePolicy,
    runTaskCommand,
    apkArchive,
    apkExportReport,
    jadxDecompile,
    apkSign,
    apkRebuild,
    dexSearch,
    stringScan,
    dexXref,
    classOutline,
    smaliRead,
    soAnalyze,
    soPatchIntoApk,
    frida,
    todoWrite,
    todoRead,
    goalGet,
    goalCreate,
    goalUpdate,
    subagent,
    runWorkflow,
    file,
    routeTask,
    ...runtimeControl,
  ];
}
