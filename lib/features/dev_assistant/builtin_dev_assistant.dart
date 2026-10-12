import '../../../core/models/assistant.dart';
import '../../../core/services/local_tools/local_tool_names.dart';
import '../../core/models/reasoning_request.dart';

/// 内置「开发助手」（builtin-dev-agent）：普通软件开发场景的常驻助手。
///
/// 与内置逆向助手（SoLab）**各司其职**（用户 2026-09-28）：逆向助手管 APK
/// 逆向/改包，这个管日常软件开发——写代码/写文档/维护待办/调研，可按会话切
/// /plan 计划模式与 /goal 目标模式。这里不放任何 APK 工具，避免两套能力互相污染。
abstract final class BuiltinDevAssistant {
  static const String assistantId = 'builtin-dev-agent';
  static const String versionKey = 'builtin_dev_assistant_version';
  /// v6（2026-10-04）：上下文默认不限制条数（有自动压缩，限条数会静默丢
  /// 记忆，用户点名）；v5 记忆对齐逆向助手；v4 目标模式自动推进协议。
  static const int version = 6;

  /// 系统提示（以英文为模型契约，与仓内其它提示一致）。
  static const String systemPrompt =
      '''You are the development assistant: a general software engineering agent working inside the user's workspace. The reverse-engineering assistant (逆向助手, SoLab) handles Android package analysis and modification; do not take those over — stay on software development.

Working discipline:
- Read before you write (list_dir / glob / grep / read_file). Never rewrite a file you have not read in this task.
- Keep a task list with todo_write: concrete, verifiable steps; mark a step done the moment it is verified, and return the full list on every update.
- Put plans and design notes into workspace documents (write_file / edit_file) instead of long chat messages; keep chat replies short — the user follows the timeline.
- Prefer small, reviewable changes; after changing code, run the relevant check (test / analyzer / build) before claiming it works. Say so plainly when something is unverified.
- Use tools and parameters by their exact documented names; never invent translated names.

Session modes (the user picks them with composer slash commands):
- /plan: research and produce a plan document plus todo list; change nothing.
- /goal <target>: autonomous execution — treat the target as the direction the user entrusted to you, not a checklist. The app auto-advances you round after round: end your reply's last line with `[目标完成]` once the target is truly done, or `[目标受阻] <reason>` when you cannot proceed. Never fake completion to stop early.
- When a request is clearly a large multi-round objective, you may open goal mode yourself by putting `[启用目标模式] <target>` on its own line.

Workflows: call `run_workflow` with no arguments to list the workflows the user enabled for chat, then run one with `workflow` (id or name) plus `input`; prefer a saved workflow over re-improvising a routine it already encodes.''';

  /// 纯聊天/无工具场景用的精简提示。
  static const String systemPromptCore =
      '''你是开发助手，负责普通软件开发（写代码、写文档、维护待办、调研）。
APK 逆向与改包由逆向助手（SoLab）负责，各司其职。

当前对话为纯聊天场景，本轮不使用任何工具。请自然、简洁地用简体中文回应；
代码、命令、路径、工具名与报错原文保留英文。不确定的明确说明，不编造。''';

  /// 开发场景的本地工具清单：**通用层**（与业务域无关的原语）。
  ///
  /// 这里**只放本地注册表里的工具**（LocalToolNames.all），与 SoLab 助手同规矩：
  /// - `search_web` 是 provider 流内建的服务端工具，靠 searchEnabled 打开；
  /// - `memory_*` 由 enableMemory 打开（MemoryTools 自行声明与分发）。
  /// 把这两类名字写进 localToolIds 只会得到"声明了却挂不上"的假工具。
  ///
  /// 2026-10-02：补齐通用层——之前只挂了 8 个，导致开发助手**读不到自己的技能**
  /// （`get_solab_skill`/`get_installed_skills`）、看不到工具地图、也没有任务状态与
  /// 交付整理。工具按能力域划分见 `LocalToolDomains`（通用 / 设备 / 逆向）：
  /// 逆向域只在逆向助手有意义，设备域按需另开，这里给的是通用原语。
  static const List<String> toolIds = <String>[
    // 运行时与自省
    LocalToolNames.routeTask,
    LocalToolNames.workspacePolicy,
    LocalToolNames.agentRuntimeGuide,
    LocalToolNames.apkToolMap,
    LocalToolNames.apkSkill,
    LocalToolNames.installedSkills,
    // 工作：文件、待办、任务状态
    LocalToolNames.file,
    LocalToolNames.todoWrite,
    LocalToolNames.todoRead,
    // 目标：长任务自己立目标并推进（目标模式 = 免审执行）。
    LocalToolNames.goalGet,
    LocalToolNames.goalCreate,
    LocalToolNames.goalUpdate,
    LocalToolNames.taskStatus,
    LocalToolNames.taskUpdate,
    // 委派与编排
    LocalToolNames.subagent,
    LocalToolNames.runWorkflow,
    // 交付与收尾
    LocalToolNames.collectDelivery,
    LocalToolNames.workspaceCleanup,
    LocalToolNames.requestConfirmation,
    // 通用小工具
    LocalToolNames.askUser,
    LocalToolNames.calculate,
    LocalToolNames.valueCalc,
    LocalToolNames.timeInfo,
  ];

  static Assistant definition() => const Assistant(
    id: assistantId,
    name: '开发助手',
    // 助手隔离：闲聊轮注入开发助手自己的精简核心提示（v2 迁移会刷到已装助手）。
    systemPromptCore: systemPromptCore,
    useAssistantName: true,
    // 写代码要稳：低温度 + 关闭超长思考预算（-1 交给模型默认）。
    temperature: 0.2,
    reasoning: ReasoningRequest.auto,
    // 用户 2026-10-04：与逆向助手同规矩——有自动压缩就不默认限条数
    // （限制会让窗口永不满足压缩阈值，超出部分直接丢 = 静默丢记忆）。
    contextMessageSize: 24,
    limitContextMessages: false,
    searchEnabled: true,
    localToolIds: toolIds,
    enableMemory: true,
    // 用户 2026-10-03：开发助手也要有自己的记忆（此前 autoOrganize=false，
    // 记忆页面永远是空的——「逆向有专属分类、开发的就没有」）。自动整理只写
    // 经验类（workflow），不会把语气/身份类自动写进来。
    autoOrganizeMemory: true,
    // 与逆向助手同规矩：本助手的记忆只进本助手作用域，不串台。
    memoryWriteScope: MemoryWriteScope.alwaysAssistant,
    allowPastConversationRecall: true,
    generateConversationSummary: true,
  );
}
