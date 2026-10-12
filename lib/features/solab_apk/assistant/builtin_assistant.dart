import '../../../core/models/assistant.dart';
import '../../../core/services/local_tools/local_tool_names.dart';
import '../services/apk_agent_policy.dart';
import '../../../core/models/reasoning_request.dart';

/// SoLab 内置助手（builtin-apk-mod）定义与常量。
///
/// T2.2 外移：从 assistant_provider.dart 抽出，使通用 provider 只留
/// 「加载内置助手」的挂载点。prompt / toolIds / 助手定义是本仓库自研
/// 逻辑（上游 kelivo 无 APK 助手），集中在 solab_apk 便于 sync_upstream
/// 冲突隔离。
abstract final class BuiltinApkMod {
  /// 内置 SoLab APK 助手 id（跨 provider 共享的统一标识）。
  static const String assistantId = 'builtin-apk-mod';

  /// 内置助手模板版本：迁移机制据它强刷已安装助手。
  /// 变更助手定义/prompt/toolIds 时 bump。
  /// v102（2026-09-29）：助手改名「逆向助手」（各司其职定案：与开发助手
  /// 对称的领域名），提示词身份句同步；id 不变（跨 provider 统一标识）。
  /// v103（2026-10-03）：提示词补齐会话模式（含目标自动推进协议）与工作流用法。
  /// v105（2026-10-06）：新增「作业约定」开关（operatorConventionsEnabled，
  /// 默认开）——只随本助手注入，见 operator_conventions.dart。
  static const String versionKey = 'builtin_apk_mod_assistant_version';
  static const int version = 105;

  /// 系统提示（完整 APK 工作流纪律）。
  ///
  /// 2026-09-18 精简：删掉过程微管理（分节的过程叙述规则、"Before each
  /// substantive action…" 的检查清单），只留身份/授权边界、判断契约引用、
  /// 记忆入口、术语纪律与叙述节奏各一句——把判断空间还给模型。
  static const String systemPrompt =
      '''You are 逆向助手 (SoLab), the built-in Android APK reverse-engineering and modification agent. Only assist with packages the user is authorized to analyze, modify, and distribute.

${ApkAgentPolicy.sharedDecisionPolicy}

## Memory

Genuinely new task: before locating, check `get_apk_patch_memory` for verified experience of the exact current app. A `verifiedExperience` entry in the injected resume state means one exists — read it first and follow its pitfall notes; do not guess from the title. Resumed task: conversation checkpoints win; do not read patch memory just because generation was interrupted.

## Session modes

The user picks a mode with composer slash commands. /plan: research only and produce a plan document plus todo list — artifact-changing tools are withdrawn; do not pretend work was executed. /goal <target>: autonomous execution (approvals are bypassed for artifact changes). In goal mode the app auto-advances you round after round: end your reply's last line with `[目标完成]` once the target is truly done and verified, or `[目标受阻] <reason>` when you cannot proceed; never fake completion to stop early. When a request is clearly a large multi-round objective, you may open goal mode yourself by putting `[启用目标模式] <target>` on its own line.

## Workflows

`run_workflow` with no arguments lists the workflows the user enabled for chat (each has its own switch in the workflow page; disabled ones answer `workflow_disabled`); pass `workflow` (id or name) plus `input` to run one, and prefer a saved workflow over re-improvising a routine it already encodes.

## Style

Use tool and API names exactly as the available tools and skills define them — never invent translated names or parameters. Before a round of tool calls, say in one short line what you are about to check and why (the user follows the timeline); keep answers concise and continue the task without waiting to be asked.''';

  /// 系统提示「静态核心」段：纯闲聊/Tool-Free（ToolLoadPolicy.none）时使用。
  ///
  /// 刻意精炼：只含身份、回答规范与诚实原则，不含 APK 工作流/重型工具纪律
  /// （那一整段只在本轮真正挂载工具时注入，避免「你好」也背上 5k 提示文字）。
  static const String systemPromptCore =
      '''你是逆向助手（SoLab），只协助用户处理其有权分析、修改和分发的 Android 安装包。

当前对话为纯聊天/打招呼场景，本轮不使用任何工具。请自然、简洁地用简体中文
回应用户；代码、命令、路径、工具名与接口报错原文可保留英文。
仅基于已知信息回答：不确定的明确说明，不编造事实。''';

  /// 内置助手启用的本地工具清单（与 MCP 暴露的执行工具一致）。
  ///
  /// 唯一例外：`phone_control`（无障碍手机控制）不进默认清单 —— 它是
  /// 独立产品面，需系统无障碍服务，仍由「按助手的工具开关」按需开启。
  static const List<String> toolIds = <String>[
    // 与 MCP 完全一致的执行工具。
    LocalToolNames.routeTask,
    LocalToolNames.apkReport,
    LocalToolNames.apkAnalyzeWorkspace,
    LocalToolNames.workspacePolicy,
    LocalToolNames.runTaskCommand,
    LocalToolNames.apkArchive,
    LocalToolNames.apkExportReport,
    LocalToolNames.dexSearch,
    LocalToolNames.dexXref,
    LocalToolNames.classOutline,
    LocalToolNames.smaliRead,
    LocalToolNames.jadxDecompile,
    LocalToolNames.stringScan,
    LocalToolNames.file,
    LocalToolNames.apkPatchDex,
    LocalToolNames.apkPatchDexStrings,
    LocalToolNames.apkSignatureBypass,
    LocalToolNames.apkPatchManifest,
    LocalToolNames.apkRebuild,
    LocalToolNames.apkSign,
    LocalToolNames.soAnalyze,
    LocalToolNames.soPatchIntoApk,
    LocalToolNames.frida,
    'analyzer.open',
    'analyzer.global_search',
    'analyzer.find_field_usage',
    'analyzer.analyze_business_state',
    LocalToolNames.timeInfo,
    LocalToolNames.clipboard,
    LocalToolNames.calculate,
    LocalToolNames.valueCalc,
    LocalToolNames.screenTime,
    LocalToolNames.calendarQuery,
    LocalToolNames.calendarCreate,
    // Agent 专用交互与上下文资源。
    LocalToolNames.askUser,
    LocalToolNames.agentRuntimeGuide,
    LocalToolNames.apkToolMap,
    LocalToolNames.apkListWorkspace,
    LocalToolNames.apkProjectInfo,
    LocalToolNames.apkListBuilds,
    LocalToolNames.apkCleanupBuilds,
    LocalToolNames.apkSkill,
    LocalToolNames.apkKnowledge,
    LocalToolNames.installedSkills,
    // 自定义特征规则与跨会话经验/笔记。
    LocalToolNames.apkRules,
    LocalToolNames.apkPatchMemory,
    LocalToolNames.apkSavePatchMemory,
    LocalToolNames.apkRecordPatchVerification,
    LocalToolNames.apkNoteRead,
    LocalToolNames.apkNoteWrite,
    // 会话级任务清单 + 子代理：MCP 执行面一直暴露这三个（见
    // LocalToolsService.mcpCallableToolNames），内置助手却没挂 —— 端内 Agent
    // 因此既写不了待办也派不了子代理（用户视角「功能用不了」的根因）。
    // 2026-09-29 补齐；v99 版本迁移会把新清单刷到已装助手。
    LocalToolNames.todoWrite,
    LocalToolNames.todoRead,
    // 目标：长任务自己立目标并推进（目标模式 = 免审执行）。
    LocalToolNames.goalGet,
    LocalToolNames.goalCreate,
    LocalToolNames.goalUpdate,
    LocalToolNames.subagent,
    LocalToolNames.runWorkflow,
    // 运行时控制面（§7.4 核心控制）：查状态/推进/查证据/读产物/提计划/
    // Dry Run/探针建议/工程验证/收交付/清工作区/请求确认。此前只在
    // RuntimeTools 里有实现，模型面既没有 schema 也没有分派 —— 报告 §二第 11
    // 条「有实现无入口」。第 72 项接线；v101 版本迁移会把新清单刷到已装助手。
    ...LocalToolNames.runtimeControl,
  ];

  /// 内置助手模板定义（systemPrompt 由调用方经 copyWith 注入覆盖）。
  static Assistant definition() => const Assistant(
    id: assistantId,
    name: '逆向助手',
    // 助手隔离：闲聊轮只注入本助手自己的精简核心提示。
    systemPromptCore: systemPromptCore,
    useAssistantName: true,
    reasoning: ReasoningRequest.auto,
    temperature: 0.2,
    // 用户 2026-10-04：「都有自动压缩了，默认不要限制，不然会丢记忆」——
    // 限制上下文条数会让窗口永远不满（自动压缩永不触发），超出的消息被直接
    // 丢弃 = 静默丢上下文。默认改为不限：由摘要+压缩管线接管上下文增长；
    // 用户仍可在助手设置里自己设条数（自设即自担）。
    contextMessageSize: 24,
    limitContextMessages: false,
    // v71：工具默认开启——内置搜索 + 内置 fetch（solab_fetch 内存 MCP）。
    searchEnabled: true,
    mcpServerIds: <String>['solab_fetch'],
    // v105：作业约定默认开（只对本助手生效；其它助手该字段恒为 false，
    // 注入侧还有 id 判据兜底）。
    operatorConventionsEnabled: true,
    // systemPrompt 唯一事实源是 systemPrompt（definition 经 copyWith
    // 覆盖注入）；此处不重复内联，避免两份提示词漂移。
    localToolIds: toolIds,
    enableMemory: true,
    autoOrganizeMemory: true,
    memoryWriteScope: MemoryWriteScope.alwaysAssistant,
    // 会话上下文压缩：开启摘要生成（每 N 条新消息自动总结旧消息），
    // 上下文满时用摘要替换已总结旧消息继续追加（不再硬裁失忆）
    allowPastConversationRecall: true,
    generateConversationSummary: true,
  );
}
