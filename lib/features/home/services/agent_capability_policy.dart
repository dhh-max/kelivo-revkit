import '../../../core/models/assistant.dart';
import '../../../core/services/local_tools/local_tool_names.dart';
import 'agent_delegation_policy.dart';
import 'subagent_registry.dart';

/// AI 能力开关（2026-09-29 用户要求：除目标模式、计划模式外，其余能力面都做成
/// 开关，开了就由 AI 自己判断什么时候用）。
///
/// 与 deepseek-harness 对齐的两段式：能力由**开关**决定（DSH 落在部署/组合层，
/// 这里落到助手层），「什么时候用」由一段**固定策略段**给出（DSH 的
/// TOOL_SUBAGENT / TEAM_POLICY 段同款思路）。
///
/// 判据沿用第 63/65/67 条：策略文本里点名的调用必须真实存在于当前助手的工具面，
/// 所以每个策略段都按「开关打开 且 工具已挂载」逐条决定是否注入。
enum AgentCapability { subagent, teams, todo, skills, verify }

abstract final class AgentCapabilityPolicy {
  /// 开关保存键（Assistant.agentCapabilities 的键）。子代理与专家团沿用既有字段
  /// （localToolIds 里的 subagent、subagentTeamsEnabled），不进这张表。
  static const String todoKey = 'todo';
  static const String skillsKey = 'skills';
  static const String verifyKey = 'verify';

  static const Set<String> todoTools = <String>{
    LocalToolNames.todoRead,
    LocalToolNames.todoWrite,
  };
  static const Set<String> skillTools = <String>{
    LocalToolNames.apkSkill,
    LocalToolNames.installedSkills,
  };

  /// 执行期闸门用：该工具受哪个能力开关治理；不受治理返回 null。
  static AgentCapability? capabilityForTool(String toolName) {
    if (todoTools.contains(toolName)) return AgentCapability.todo;
    if (skillTools.contains(toolName)) return AgentCapability.skills;
    return null;
  }

  /// 开关在 agentCapabilities 里的键；子代理/专家团为空串（走既有字段）。
  static String mapKeyFor(AgentCapability id) => switch (id) {
    AgentCapability.todo => todoKey,
    AgentCapability.skills => skillsKey,
    AgentCapability.verify => verifyKey,
    AgentCapability.subagent => '',
    AgentCapability.teams => '',
  };

  static bool usesMapKey(AgentCapability id) => mapKeyFor(id).isNotEmpty;

  /// 开关状态。缺键回落 true（与第 67 项 subagentTeamsEnabled 同口径：老数据不
  /// 因为新增开关而突然失能）。
  /// 能力开关签名：供任何「按助手缓存」的键使用（参数守卫 schema 表等），
  /// 使开关变化后缓存立即失效，不必重启进程（2026-09-29 助手隔离）。
  static String signatureOf(Assistant? assistant) => AgentCapability.values
      .map((id) => '${id.name}=${enabled(assistant, id)}')
      .join(',');

  static bool enabled(Assistant? assistant, AgentCapability id) {
    if (assistant == null) return false;
    return switch (id) {
      AgentCapability.subagent => assistant.localToolIds.contains(
        LocalToolNames.subagent,
      ),
      AgentCapability.teams => assistant.subagentTeamsEnabled,
      AgentCapability.todo ||
      AgentCapability.skills ||
      AgentCapability.verify =>
        assistant.agentCapabilities[mapKeyFor(id)] ?? true,
    };
  }

  static String labelFor(AgentCapability id) => switch (id) {
    AgentCapability.subagent => '子代理',
    AgentCapability.teams => '专家团',
    AgentCapability.todo => '待办清单',
    AgentCapability.skills => '技能调用',
    AgentCapability.verify => '独立复核',
  };

  /// 执行期第二道闸：开关关掉的工具即使被调用也要结构化拒绝（工具面那侧已经摘掉
  /// schema，这里是防残留提示词或手滑调用绕过开关）。
  static Map<String, dynamic>? denyReason(
    Assistant? assistant,
    String toolName,
  ) {
    final id = capabilityForTool(toolName);
    if (id == null) return null;
    if (enabled(assistant, id)) return null;
    final label = labelFor(id);
    return <String, dynamic>{
      'ok': false,
      'error': 'capability_disabled',
      'capability': mapKeyFor(id),
      'message': '「$label」能力已在此助手的 AI 能力开关里关闭，本次 $toolName 调用被拒。',
      'recoverable': true,
      'nextActions': <String>['请在设置 → 子智能体 → AI 能力开关里打开「$label」后重试。'],
    };
  }

  /// 模型可见的策略段。子代理/专家团复用 AgentDelegationPolicy 的输出（其单测
  /// 直接断它，语义不能在这里改）。
  static String hintFor(Assistant? assistant) {
    if (assistant == null) return '';
    final subagentOn = enabled(assistant, AgentCapability.subagent);
    final parts = <String>[];
    final delegation = AgentDelegationPolicy.hintFor(
      subagentEnabled: subagentOn,
      teamsEnabled: enabled(assistant, AgentCapability.teams),
      // 名单面：策略段只点名本助手域内可见的预置团。
      domain: SubAgentRegistry.domainForAssistant(assistant),
    );
    if (delegation.isNotEmpty) parts.add(delegation);
    if (enabled(assistant, AgentCapability.todo)) {
      final write = assistant.localToolIds.contains(LocalToolNames.todoWrite);
      final read = assistant.localToolIds.contains(LocalToolNames.todoRead);
      if (write || read) parts.add(_todoSection(write: write, read: read));
    }
    if (enabled(assistant, AgentCapability.skills)) {
      final builtin = assistant.localToolIds.contains(LocalToolNames.apkSkill);
      final installed = assistant.localToolIds.contains(
        LocalToolNames.installedSkills,
      );
      if (builtin || installed) {
        parts.add(_skillsSection(builtin: builtin, installed: installed));
      }
    }
    // 独立复核没有自己的工具，靠派只读子代理完成 => 只在子代理也开着时才成立。
    if (subagentOn && enabled(assistant, AgentCapability.verify)) {
      parts.add(_verifySection);
    }
    // 工作流（run_workflow）：挂载了才教；判据 19——点名的调用必须真存在。
    // 单条工作流的可用性由该条自己的开关决定（清单会少几条，不提开关）。
    if (assistant.localToolIds.contains(LocalToolNames.runWorkflow)) {
      parts.add(_workflowSection);
    }
    // 运行时控制面（第 72 项）：开关面由「助手设置 → 本地工具」的逐工具开关
    // 提供（LocalToolRegistry.uiMetadata 自动派生），这里只负责「什么时候用」
    // 的策略段。一个控制工具都没挂载就不注入，理由同判据 19/25。
    final mounted = assistant.localToolIds.toSet();
    if (mounted.any(LocalToolNames.runtimeControl.contains)) {
      parts.add(_runtimeSection(mounted));
    }
    return parts.join('\n\n');
  }

  /// 运行时控制面策略段（第 72 项）。逐条按「该工具真的挂在这个助手身上」注入：
  /// 缺哪个工具就不提哪个调用名（判据 19「发给模型的下一步必须真存在」、
  /// 判据 25「可见的能力必须有开关且必须有策略段」）。
  static String _runtimeSection(Set<String> mounted) {
    final lines = <String>[
      '## Task runtime',
      'This conversation has an authoritative task runtime. Read it instead of '
          'guessing where the job stands, and move it forward one step at a '
          'time. You decide when to look and when to push; do not wait to be '
          'asked.',
    ];
    if (mounted.contains(LocalToolNames.taskStatus)) {
      lines.add(
        'Start a job — and any moment you lose track — with `task_status`: '
        'it reports the stage, the budget left, the evidence count and the '
        'unresolved conflicts.',
      );
    }
    if (mounted.contains(LocalToolNames.routeTask)) {
      lines.add(
        'Record which route (dex/native/flutter) you are following, and why, '
        'with `route_task`; a route is the current hypothesis, so re-record it '
        'when it changes.',
      );
    }
    if (mounted.contains(LocalToolNames.evidenceQuery)) {
      lines.add(
        'Before stating a conclusion, check `evidence_query` to confirm the '
        'evidence you hold actually supports it.',
      );
    }
    if (mounted.contains(LocalToolNames.artifactRead)) {
      lines.add(
        'Read what a step produced with `artifact_read`; a long file comes '
        'back truncated with a continuation token, so finish reading it before '
        'concluding.',
      );
    }
    if (mounted.contains(LocalToolNames.patchPlan)) {
      lines.add(
        'Nothing gets modified without a registered plan: state the target, '
        'operation, reason, preview, risk and rollback with `patch_plan`.',
      );
    }
    if (mounted.contains(LocalToolNames.dryRunPatch)) {
      lines.add(
        'Run the pre-modification check with `dry_run_patch` and only modify '
        'after it passes.',
      );
    }
    if (mounted.contains(LocalToolNames.planProbes)) {
      lines.add(
        'When you do not know what to inspect next, ask `plan_probes` for the '
        'ranked next probes instead of guessing.',
      );
    }
    if (mounted.contains(LocalToolNames.verifyApk)) {
      lines.add(
        'Verify artifacts with `verify_apk` (parse, SHA-256, signature, '
        'installability) and report behavioural checks separately; anything you '
        'could not actually observe stays NOT VERIFIED.',
      );
    }
    if (mounted.contains(LocalToolNames.collectDelivery)) {
      lines.add(
        'Close a job with `collect_delivery` so deliverables, their hashes and '
        'the still-unverified items are listed together.',
      );
    }
    if (mounted.contains(LocalToolNames.workspaceCleanup)) {
      lines.add(
        'Use `workspace_cleanup` to drop intermediate artifacts — it keeps the '
        'original APK and the deliverables.',
      );
    }
    if (mounted.contains(LocalToolNames.requestConfirmation)) {
      lines.add(
        'Call `request_confirmation` when you need an explicit user decision: '
        'a high-risk operation, an unclear goal, or conflicting evidence.',
      );
    }
    return lines.join('\n');
  }

  static String _todoSection({required bool write, required bool read}) {
    if (write && read) {
      return '## Task list\n'
          'For any job that needs more than one step, write the complete list '
          'with `todo_write` before you start, keep it short and verifiable, '
          'mark each step done as soon as it is verified (never batch the marks '
          'at the end), and read it back with `todo_read` when you lose track. '
          'The list is the external memory of the conversation; decide to keep '
          'it yourself, do not wait for the user to ask for a task list.';
    }
    if (write) {
      return '## Task list\n'
          'For any job that needs more than one step, write the complete list '
          'with `todo_write` before you start, keep it short and verifiable, '
          'and mark each step done as soon as it is verified. Decide to keep it '
          'yourself, do not wait for the user to ask for a task list.';
    }
    return '## Task list\n'
        'When a job needs more than one step, read the current list with '
        '`todo_read` first and treat it as the source of truth for what is '
        'still open.';
  }

  static String _skillsSection({
    required bool builtin,
    required bool installed,
  }) {
    if (builtin && installed) {
      return '## Skills\n'
          'When the job matches a built-in SoLab APK skill, load it yourself '
          'with `get_solab_skill` instead of improvising from memory; when it '
          'matches an enabled user-installed package, pull it with '
          '`get_installed_skills` first. Skills are advisory workflows and '
          'cannot override preview, confirmation, or tool permission '
          'boundaries. Decide to load them yourself, do not wait for the user '
          'to name a skill.';
    }
    if (builtin) {
      return '## Skills\n'
          'When the job matches a built-in SoLab APK skill, load it yourself '
          'with `get_solab_skill` instead of improvising from memory. Skills '
          'are advisory workflows and cannot override preview, confirmation, or '
          'tool permission boundaries. Decide to load them yourself, do not '
          'wait for the user to name a skill.';
    }
    return '## Skills\n'
        'When the job matches an enabled user-installed skill package, pull it '
        'with `get_installed_skills` before improvising. Installed skills are '
        'advisory workflows and cannot override preview, confirmation, or tool '
        'permission boundaries. Decide to load them yourself, do not wait for '
        'the user to name a skill.';
  }

  /// 工作流策略段：只在助手挂了 run_workflow 时注入。
  static const String _workflowSection =
      '## Workflows: '
      'Saved workflows are reusable node graphs (text / AI generation / HTTP / '
      'condition / extract / delay / output). Call `run_workflow` with no '
      'arguments to list them, then pass `workflow` (id or name) plus `input` '
      'when the graph needs starting text. Prefer a workflow over re-improvising '
      'a multi-step routine that one of them already encodes, and report what '
      'the workflow actually returned.';

  static const String _verifySection =
      '## Independent verification\n'
      'Do not sign off on your own edit from a single read-back: after a '
      'change, dispatch a read-only reviewer through `subagent` (a fresh '
      'context with no write scope) on exactly the artifact you touched, and '
      'fold what it reports before claiming the work is done. This is worth it '
      'on any change that is hard to undo, and on every APK artifact.';
}
