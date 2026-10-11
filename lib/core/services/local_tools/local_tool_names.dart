abstract final class LocalToolNames {
  // 通用工具
  static const timeInfo = 'get_time_info';
  static const clipboard = 'clipboard_tool';
  static const textToSpeech = 'text_to_speech';
  static const askUser = 'ask_user_input_v0';
  static const calculate = 'calculate';
  static const valueCalc = 'value_calc';
  static const screenTime = 'get_screen_time';
  static const calendarQuery = 'calendar_query';
  static const calendarCreate = 'calendar_create';
  static const searchWeb = 'search_web';
  static const currentLocation = 'current_location';
  static const weather = 'weather';
  static const phoneControl = 'phone_control';
  static const getToolResult = 'get_tool_result';

  // 记忆 / 待办
  static const memoryRead = 'memory_read';
  static const memoryUpdate = 'memory_update';
  static const todoRead = 'todo_read';
  static const todoWrite = 'todo_write';

  // Agent / 任务
  static const agentRuntimeGuide = 'get_agent_runtime_guide';
  static const taskStatus = 'task_status';
  static const taskUpdate = 'task_update';
  static const subagent = 'subagent';
  static const runWorkflow = 'run_workflow';

  // APK 基础信息 / 知识
  static const apkReport = 'get_current_apk_report';
  static const apkSkill = 'get_solab_skill';
  static const apkKnowledge = 'get_apk_knowledge';
  static const installedSkills = 'get_installed_skills';
  static const apkProjectInfo = 'get_apk_project_info';
  static const apkRules = 'list_apk_rules';
  static const apkToolMap = 'get_solab_tool_map';
  static const apkListWorkspace = 'list_workspace_apks';
  static const apkAnalyzeWorkspace = 'analyze_apk_workspace';
  static const apkExportReport = 'export_apk_report';
  static const apkArchive = 'apk_archive';
  static const workspacePolicy = 'workspace_policy';

  // APK 修改 / 补丁
  static const apkPatchDex = 'patch_apk_dex_methods';
  static const apkPatchDexStrings = 'patch_apk_dex_strings';
  static const apkSignatureBypass = 'signature_bypass';
  static const apkPatchManifest = 'patch_apk_manifest';
  static const apkPatchMemory = 'get_apk_patch_memory';
  static const apkSavePatchMemory = 'save_apk_patch_memory';
  static const apkRecordPatchVerification = 'record_apk_patch_verification';
  static const apkListBuilds = 'list_apk_builds';
  static const apkCleanupBuilds = 'cleanup_apk_builds';
  static const apkNoteRead = 'apk_note_read';
  static const apkNoteWrite = 'apk_note_write';
  static const apkSign = 'apk_sign';
  static const apkRebuild = 'apk_rebuild';

  // 逆向工具
  static const jadxDecompile = 'jadx_decompile';
  static const dexSearch = 'dex_search';
  static const stringScan = 'string_scan';
  static const dexXref = 'dex_xref';
  static const classOutline = 'class_outline';
  static const smaliRead = 'smali_read';
  static const soAnalyze = 'so_analyze';
  static const soPatchIntoApk = 'so_patch_into_apk';
  static const frida = 'frida';

  // 文件 / 路由
  static const file = 'file';
  static const routeTask = 'route_task';
  static const runTaskCommand = 'run_task_command';

  // 运行时探针 / 交付
  static const planProbes = 'plan_probes';
  static const verifyApk = 'verify_apk';
  static const collectDelivery = 'collect_delivery';
  static const workspaceCleanup = 'workspace_cleanup';
  static const requestConfirmation = 'request_confirmation';

  // 交付 / 证据 / 产物
  static const artifactRead = 'artifact_read';
  static const evidenceQuery = 'evidence_query';
  static const patchPlan = 'patch_plan';
  static const dryRunPatch = 'dry_run_patch';

  // 目标
  static const goalGet = 'goal_get';
  static const goalCreate = 'goal_create';
  static const goalUpdate = 'goal_update';

  /// SoLab 逆向助手运行时控制类工具集合（任务、计划、探针、验证、交付等）。
  static const runtimeControl = <String>[
    taskStatus,
    taskUpdate,
    routeTask,
    evidenceQuery,
    artifactRead,
    requestConfirmation,
    planProbes,
    verifyApk,
    collectDelivery,
    workspaceCleanup,
    patchPlan,
    dryRunPatch,
  ];

  /// 全部本地注册工具名。
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
    searchWeb,
    currentLocation,
    weather,
    phoneControl,
    getToolResult,
    memoryRead,
    memoryUpdate,
    todoRead,
    todoWrite,
    agentRuntimeGuide,
    taskStatus,
    taskUpdate,
    subagent,
    runWorkflow,
    apkReport,
    apkSkill,
    apkKnowledge,
    installedSkills,
    apkProjectInfo,
    apkRules,
    apkToolMap,
    apkListWorkspace,
    apkAnalyzeWorkspace,
    apkExportReport,
    apkArchive,
    workspacePolicy,
    apkPatchDex,
    apkPatchDexStrings,
    apkSignatureBypass,
    apkPatchManifest,
    apkPatchMemory,
    apkSavePatchMemory,
    apkRecordPatchVerification,
    apkListBuilds,
    apkCleanupBuilds,
    apkNoteRead,
    apkNoteWrite,
    apkSign,
    apkRebuild,
    jadxDecompile,
    dexSearch,
    stringScan,
    dexXref,
    classOutline,
    smaliRead,
    soAnalyze,
    soPatchIntoApk,
    frida,
    file,
    routeTask,
    runTaskCommand,
    planProbes,
    verifyApk,
    collectDelivery,
    workspaceCleanup,
    requestConfirmation,
    artifactRead,
    evidenceQuery,
    patchPlan,
    dryRunPatch,
    goalGet,
    goalCreate,
    goalUpdate,
  ];
}
