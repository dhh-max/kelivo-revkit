import 'dart:convert';

import '../../../../core/models/assistant.dart';
import '../../../../core/services/local_tools/local_tool_names.dart';
import 'agent_capability_policy.dart';
import 'session_mode.dart';
import 'subagent_loop.dart';
import 'subagent_registry.dart';
import 'subagent_runner.dart';
import 'subagent_team.dart';

/// `subagent` 工具：把一件事派给独立实例去做（调研/审核/独立复核/动手），
/// 支持两种形态——
/// - 单发：`{agent, task}`，一个子代理干一件事；
/// - 专家团：`{team}`（预置团队）或 `{members:[…]}`（自定义成员），
///   成员可按 `blockedBy` 串成依赖链，写范围重叠的成员自动串行（见 subagent_team.dart）。
///
/// 设计取舍见 docs/设计-斜杠命令与子代理.md：子代理用一个工具 + `agent` 参数
/// 表达，而不是每个子代理一个工具名——本 fork 的工具注册表要五处同步 + 过
/// 一致性测试，动态工具名会把新增子代理的边际成本抬得比收益还高。
///
/// 能力边界（用户 2026-09-28「各司其职」）：
/// - 子代理的工具面 = 定义里的类别 ∩ **派发它的助手自己声明的工具**。
///   开发助手的子代理拿不到 APK 工具，逆向助手的子代理也拿不到开发工具；
/// - 只读子代理连 `file` 的写类动作也会被拦（类别只到工具名粒度，动作级再拦一次）；
/// - 开了「派发前需要我确认」的写类子代理，只能在 /goal（免审批目标模式）下派——
///   后台没有审批界面，与其跑几步再失败，不如在派发前就说清楚。
class SubAgentToolHandler {
  SubAgentToolHandler({SubAgentRegistry? registry, SubAgentRunner? runner})
      : _registry = registry ?? SubAgentRegistry(),
        _runner = runner ?? SubAgentRunner(),
        _teams = SubAgentTeamRegistry();

  final SubAgentRegistry _registry;
  final SubAgentRunner _runner;
  final SubAgentTeamRegistry _teams;

  /// 应用层用它注册模型调用口（那里才能解析 settings/provider）。
  set generator(SubAgentGenerator? value) => _runner.generator = value;

  /// 应用层用它注册「带工具循环」的驱动器；注册后优先走循环。
  set loopDriver(SubAgentLoopDriver? value) => _runner.loopDriver = value;

  bool get hasGenerator => _runner.hasGenerator;

  /// [assistant] 是派发者的单一来源（2026-09-29）：给了它就自动派生
  /// 工具面（类别 ∩ 助手自己的工具）、专家团开关与域，调用方不必各自
  /// 拼一遍——斜杠命令 /subagent 此前只传 conversationId，于是它派出的
  /// 子代理既不按域过滤、也不受专家团开关约束，和工具面两条口径。
  /// 显式传入的 [allowedToolIds] / [teamsEnabled] / [domain] 优先（MCP 面
  /// 与单测没有助手上下文时用）。
  Future<String> handle(
    Map<String, dynamic> args, {
    required String? conversationId,
    Assistant? assistant,
    String? mainSystemPrompt,
    Set<String>? allowedToolIds,
    bool? teamsEnabled,
    SubAgentDomain? domain,
  }) async {
    final resolvedAllowed =
        allowedToolIds ?? assistant?.localToolIds.toSet();
    final resolvedTeams =
        teamsEnabled ?? assistant?.subagentTeamsEnabled ?? true;
    final resolvedDomain =
        domain ?? SubAgentRegistry.domainForAssistant(assistant);
    // 助手级能力开关同样在斜杠面生效：关掉「子代理」后再打 /subagent，
    // 不能因为绕过了工具面就照跑（第 68 项：开关要在三条通道上都成立）。
    if (assistant != null &&
        !AgentCapabilityPolicy.enabled(assistant, AgentCapability.subagent)) {
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'capability_disabled',
        'message': '当前助手的「子代理」能力已关闭（设置 → 子智能体 → AI 能力开关）。',
        'recoverable': true,
      });
    }
    // 深度闸门（对齐 deepseek-harness 的 depth）：到上限直接结构化拒绝，
    // 而不是让子代理再派子代理一路递归下去。
    if (SubAgentDepth.current >= kSubAgentMaxDepth) {
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'subagent_depth_exceeded',
        'message': '子代理嵌套已达上限（$kSubAgentMaxDepth 层）：不能再往下派，'
            '这一步请自己做，或把结论交给主代理由它决定。',
        'recoverable': true,
      });
    }
    final resolvedMainPrompt =
        mainSystemPrompt ?? assistant?.systemPrompt;
    final rawMembers = args['members'];
    final teamKey = (args['team'] ?? '').toString().trim();
    if ((rawMembers is List && rawMembers.isNotEmpty) || teamKey.isNotEmpty) {
      // 助手级专家团开关（设置 → 子智能体 → 派发开关）。schema 那侧已经把
      // team/members 摘掉；这里是执行期的第二道——MCP 面与旧会话仍可能带着
      // 老参数来，静默按单发跑会丢掉一半成员。
      if (!resolvedTeams) {
        return jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'teams_disabled',
          'message': '当前助手已关闭专家团：改用单发（agent + task），'
              '或在「设置 → 子智能体」打开专家团。',
          'nextActions': <String>[
            '用 agent + task 重新派单发',
            '或让用户在设置里打开专家团',
          ],
        });
      }
      return _handleTeam(
        args,
        teamKey: teamKey,
        rawMembers: rawMembers,
        conversationId: conversationId,
        mainSystemPrompt: resolvedMainPrompt,
        allowedToolIds: resolvedAllowed,
        domain: resolvedDomain,
      );
    }
    return _handleSingle(
      args,
      conversationId: conversationId,
      mainSystemPrompt: resolvedMainPrompt,
      allowedToolIds: resolvedAllowed,
      domain: resolvedDomain,
    );
  }

  Future<String> _handleSingle(
    Map<String, dynamic> args, {
    required String? conversationId,
    String? mainSystemPrompt,
    Set<String>? allowedToolIds,
    SubAgentDomain domain = SubAgentDomain.any,
  }) async {
    final agentKey = (args['agent'] ?? SubAgentRegistry.generalId).toString().trim();
    final task = (args['task'] ?? '').toString().trim();
    if (task.isEmpty) {
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'invalid_arguments',
        'message': 'task 不能为空：子代理只做交给它的那一件事。',
      });
    }
    final definition = await _registry.bySlug(agentKey);
    if (definition == null) {
      return _unknownAgent(agentKey, domain);
    }

    Set<SubAgentCategory>? override;
    Set<String>? namedToolFilter;
    final rawTools = args['tools'];
    if (rawTools is List && rawTools.isNotEmpty) {
      if (!definition.builtIn) {
        return jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'invalid_arguments',
          'message': '只有内置子代理允许在调用时指定 tools；自定义子代理的工具类别在定义里固定。',
        });
      }
      // 报告 2-10：`tools` 过去只认**类别**（read/write/shell），传 ["read"] 会展开成
      // 一批工具（实测拿到 5 个，含可再嵌套的 subagent）——想用它做「只读隔离」的
      // 调用方以为收窄了，实际没有。现在两类都认：
      //   类别（read/write/shell）→ 按类别展开；
      //   显式工具名（file/grep/todo_read…）→ 与展开结果**求交**，真正收窄。
      // 既不是类别也不是已知工具名 → 结构化报错并列出可选值。
      final parsed = <SubAgentCategory>{};
      final namedTools = <String>{};
      for (final entry in rawTools) {
        final raw = entry?.toString().trim() ?? '';
        final category = SubAgentCategory.fromWire(raw);
        if (category != null) {
          parsed.add(category);
          continue;
        }
        final internal = LocalToolNames.all.contains(raw) ? raw : null;
        if (internal != null) {
          namedTools.add(internal);
          continue;
        }
        return jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'invalid_arguments',
          'message': 'tools 只支持类别 read / write / shell，或显式工具名（file、grep、'
              'string_scan、todo_read …）。收到「$raw」两者都不是。',
          'parameter': 'tools',
          'actual': raw,
        });
      }
      if (parsed.isNotEmpty) override = parsed;
      if (namedTools.isNotEmpty) namedToolFilter = namedTools;
    }

    final categories = override ?? definition.categories;
    final blocked = _preflight(
      definition: definition,
      categories: categories,
      allowedToolIds: allowedToolIds,
      conversationId: conversationId,
      domain: domain,
    );
    if (blocked != null) return jsonEncode(blocked);

    // C2（2026-10-01 真机实测）：timeoutMs / maxSteps / maxToolCalls 此前
    // 传了不生效也不提示。现在真正生效（带边界钳制），并把生效值回显在返回
    // 里——调用方不该以为自己设了限制而实际没设。
    final timeoutOverride = _boundedInt(
      args['timeoutMs'],
      min: 1000,
      max: 1800000,
    );
    final maxStepsOverride = _boundedInt(args['maxSteps'], min: 1, max: 200);
    // 0 / 未传 = 不限（与循环判定一致）；显式传值才作为预算。
  final maxToolCalls = _boundedInt(args['maxToolCalls'], min: 0, max: 500) ?? 0;
    final request = SubAgentRunRequest(
      definition: definition,
      task: task,
      context: args['context']?.toString(),
      label: args['label']?.toString() ?? '',
      conversationId: conversationId,
      categoriesOverride: override,
      mainSystemPrompt: mainSystemPrompt,
      maxToolCalls: maxToolCalls,
      maxStepsOverride: maxStepsOverride,
      timeoutMsOverride: timeoutOverride,
    );
    final outcome = await _runner.run(request);
    final granted = SubAgentRegistry.toolNamesFor(
      categories,
      allowed: allowedToolIds,
      skills: definition.enabledSkills,
    ).toList(growable: false)
      ..sort();
    // 报告 2-10：显式工具名与类别展开结果求交，调用方写什么就是什么。
    final effective = namedToolFilter == null
        ? granted
        : granted.where(namedToolFilter.contains).toList(growable: false);
    final droppedByFilter = namedToolFilter == null
        ? <String>[]
        : namedToolFilter
              .where((name) => !granted.contains(name))
              .toList()
          ..sort();
    final truncated = outcome.truncated;
    return jsonEncode(<String, dynamic>{
      'ok': outcome.ok,
      if (truncated) 'truncated': true,
      if (truncated)
        'truncatedReason': outcome.finishReason == 'max_tool_calls'
            ? '工具调用预算用尽（maxToolCalls=$maxToolCalls）'
            : '步数用尽（maxSteps=${request.effectiveMaxSteps}）',
      if (truncated && outcome.text.trim().isEmpty)
        'truncationError': 'subagent_truncated',
      if (truncated && outcome.text.trim().isEmpty)
        'nextActions': <String>[
          '提高 maxToolCalls / maxSteps 后重派，或把任务拆小一点',
          '先看 steps/toolCalls 判断卡在哪一步，再决定补跑还是换策略',
        ],
      'agent': definition.slug,
      if ((args['label']?.toString() ?? '').isNotEmpty)
        'label': args['label']?.toString(),
      'grantedTools': effective,
      'toolsRequested': rawTools == null
          ? null
          : [for (final e in rawTools as List) e?.toString() ?? ''],
      'toolCategoriesEffective': categories
          .map((c) => c.name)
          .toList()
        ..sort(),
      if (namedToolFilter != null)
        'toolNameFilter': namedToolFilter.toList()..sort(),
      // 类别展开容易超出预期（read 会带出 subagent 等），把「展开前/收窄后」
      // 讲清楚；列表**完整**给出（2026-10-03 报告 F-07：省略号截断会掩盖缺失）。
      if (namedToolFilter == null && granted.length > categories.length)
        'toolsNote':
            'tools 是**类别**：${categories.map((c) => c.name).join('/')} 展开为 '
            '${granted.length} 个工具（${granted.join('、')}）。'
            '文件读取/检索在 file 工具里（action=list/read/grep/info/strings）。'
            '要精确控制就传显式工具名。',
      if (categories.contains(SubAgentCategory.shell))
        'toolsNoteShell':
            'shell 类目当前不授予任何工具：沙盒 shell 属工作区工具面，不在子代理工具面内（会被忽略）。',
      if (droppedByFilter.isNotEmpty)
        'toolsNoteFiltered':
            '这些名字不在该子代理的工具面内，已忽略：${droppedByFilter.join('、')}',
      'effectiveLimits': <String, dynamic>{
        'timeoutMs': request.effectiveTimeoutMs,
        'maxSteps': request.effectiveMaxSteps,
        // 未设置就不返回（2026-10-03 报告 F-25：0 会被读成「一次调用都不行」）。
        if (maxToolCalls > 0) 'maxToolCalls': maxToolCalls,
      },
      ...outcome.toJson(),
      // 超时错误码：机读码固定 ASCII（2026-10-03 报告 F-09——自由文本码把
      // 中文空格替换成下划线还把步数内嵌进 code，无法作稳定枚举键）。
      if (outcome.status == SubAgentStatus.timeout)
        'error': <String, dynamic>{
          'code': 'SUBAGENT_TIMEOUT',
          'message': outcome.error ?? '子代理超时',
          'detail': <String, dynamic>{
            'steps': outcome.steps,
            'toolCalls': outcome.toolCalls.length,
            'elapsedMs': outcome.elapsedMs,
            'timeoutMs': request.effectiveTimeoutMs,
          },
          'recoverable': true,
        },
      // 字段口径（2026-10-03 报告 F-10：steps 23 vs toolCalls 45 无法解释）。
      if (outcome.steps > 0)
        'fieldsNote': 'steps=模型轮次数；toolCalls=实际执行的工具调用次数'
            '（一轮可发多次调用，所以两者通常不相等）；elapsedMs=墙钟耗时。',
      // 零工具调用而工具面非空：如实标注。用户 2026-09-30 报的核心形态就是
      // 「说 OK 但没干活」——ok:true 之外必须能让主代理分清「真做完了」和
      // 「只说了句话」。纯问答任务不调工具是合法的，所以是 warning 不是错误。
      if (outcome.ok && outcome.toolCalls.isEmpty && granted.isNotEmpty)
        'warning': '该子代理没有调用任何工具（可用 ${granted.length} 个）：'
            '若这项任务本应动手，把它当作未完成——自己接着做，或缩小范围后重派。',
      if (outcome.status == SubAgentStatus.cancelled)
        'nextActions': <String>[
          '用户已中止这次子代理运行：不要自动重派，等他明确要求再继续',
          '需要接着做就缩小范围后再派一次，或直接在主对话里说明续做位置',
        ]
      else if (!outcome.ok)
        'nextActions': <String>[
          '把任务拆小后重试；或直接在主对话里自己做这一步',
          ..._teamHintFor(domain, enabled: true),
        ],
    });
  }

  /// 读一个正整数控制参数并钳到边界（null = 未传，用默认）。
  static int? _boundedInt(Object? raw, {required int min, required int max}) {
    if (raw == null) return null;
    final value =
        raw is num ? raw.toInt() : int.tryParse(raw.toString().trim());
    if (value == null) return null;
    return value.clamp(min, max);
  }

  /// 单发失败后的团队提示按域给：只提本域能用的预置团（判据 19——点名的
  /// 调用必须真存在于当前助手的名单面）。
  static List<String> _teamHintFor(SubAgentDomain domain, {required bool enabled}) {
    if (!enabled) return <String>[];
    return switch (domain) {
      SubAgentDomain.dev => const <String>['要多个角色协作时改用专家团：team=dev-team'],
      SubAgentDomain.apk => const <String>['要多个角色协作时改用专家团：team=apk-team'],
      SubAgentDomain.any => const <String>[
          '要多个角色协作时改用专家团：team=dev-team / apk-team，或自定义 members',
        ],
    };
  }

  Future<String> _handleTeam(
    Map<String, dynamic> args, {
    required String teamKey,
    required Object? rawMembers,
    required String? conversationId,
    String? mainSystemPrompt,
    Set<String>? allowedToolIds,
    SubAgentDomain domain = SubAgentDomain.any,
  }) async {
    final goal = (args['task'] ?? '').toString().trim();
    List<SubAgentTeamMember> members;
    String teamName;
    if (rawMembers is List && rawMembers.isNotEmpty) {
      teamName = teamKey.isEmpty ? '临时专家团' : teamKey;
      if (rawMembers.length > kTeamMaxMembers) {
        return jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'team_too_large',
          'message': '一次最多 $kTeamMaxMembers 个成员（当前 ${rawMembers.length}）：'
              '成员各跑一轮模型，人多不等于快。',
        });
      }
      members = <SubAgentTeamMember>[];
      for (final entry in rawMembers) {
        final member = SubAgentTeamMember.fromJson(entry);
        if (member == null) {
          return jsonEncode(<String, dynamic>{
            'ok': false,
            'error': 'invalid_member',
            'message': '每个成员都要有 name / agent / task：$entry',
          });
        }
        members.add(member);
      }
    } else {
      final team = await _teams.byKey(teamKey);
      if (team == null) {
        final available = (await _teams.all())
            .where((item) => SubAgentTeamRegistry.visibleInDomain(item, domain))
            .map((item) => item.id)
            .toList(growable: false);
        return jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'unknown_team',
          'message': '没有名为 $teamKey 的专家团',
          'availableTeams': available,
        });
      }
      // 名单面第二道闸：域外预置团（如开发助手点名 apk-team）结构化拒绝。
      if (!SubAgentTeamRegistry.visibleInDomain(team, domain)) {
        final available = (await _teams.all())
            .where((item) => SubAgentTeamRegistry.visibleInDomain(item, domain))
            .map((item) => item.id)
            .toList(growable: false);
        return jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'team_domain_mismatch',
          'message': '专家团「${team.name}」属于${team.domain == SubAgentDomain.apk ? '逆向' : '开发'}域，'
              '而当前助手不在该域（各司其职）。',
          'availableTeams': available,
        });
      }
      teamName = team.name;
      members = team.members;
    }

    // 解析成员 → 定义，并做存在性 / 域 / 审批 / 授予非空的预检。
    final definitions = <String, SubAgentDefinition>{};
    final missing = <String>[];
    for (final member in members) {
      final definition = await _registry.bySlug(member.agent);
      if (definition == null) {
        missing.add(member.name);
        continue;
      }
      final blocked = _preflight(
        definition: definition,
        categories: definition.categories,
        allowedToolIds: allowedToolIds,
        conversationId: conversationId,
        domain: domain,
        memberName: member.name,
      );
      if (blocked != null) return jsonEncode(blocked);
      definitions[member.agent] = definition;
    }
    if (missing.isNotEmpty) {
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'unknown_subagent',
        'message': '这些成员指向的子代理不存在：${missing.join(', ')}',
        'availableAgents': (await _registry.all())
            .where((item) => SubAgentRegistry.visibleInDomain(item, domain))
            .map((item) => item.slug)
            .toList(growable: false),
      });
    }

    try {
      final outcome = await runSubAgentTeam(
        teamName: teamName,
        goal: goal,
        members: members,
        definitions: definitions,
        runner: _runner,
        conversationId: conversationId,
        mainSystemPrompt: mainSystemPrompt,
      );
      return jsonEncode(outcome.toJson());
    } on StateError catch (error) {
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'invalid_dependency_graph',
        'message': error.message,
      });
    }
  }

  /// 派发前预检：域不匹配 / 工具面为空 / 写类子代理没开免审批 → 结构化拒绝。
  Map<String, dynamic>? _preflight({
    required SubAgentDefinition definition,
    required Set<SubAgentCategory> categories,
    required Set<String>? allowedToolIds,
    /// 派发它的会话：免审批按会话查，没有 id 一律按需要审批处理。
    String? conversationId,
    SubAgentDomain domain = SubAgentDomain.any,
    String? memberName,
  }) {
    final who = memberName == null || memberName.isEmpty
        ? definition.slug
        : '$memberName(${definition.slug})';
    // 与循环同口径：启用的技能也会带来技能读取工具，预检不能漏算。
    final granted = SubAgentRegistry.toolNamesFor(
      categories,
      allowed: allowedToolIds,
      skills: definition.enabledSkills,
    );
    // 名单面第二道闸：域外子代理即使被点名（MCP 面/旧会话残留提示词）也不放行。
    if (!SubAgentRegistry.visibleInDomain(definition, domain)) {
      return _domainMismatch(definition, domain, memberName: memberName);
    }
    if (granted.isEmpty) {
      return <String, dynamic>{
        'ok': false,
        'error': 'subagent_no_tools',
        'message': '子代理「$who」按类别要的工具，当前助手一个都没有：'
            '子代理只能用派发它的助手自己也有的工具。',
      };
    }
    if (definition.requiresApproval &&
        categories.contains(SubAgentCategory.write) &&
        !SessionModeRuntime.policyFor(conversationId).bypassesApproval) {
      return <String, dynamic>{
        'ok': false,
        'error': 'subagent_approval_required',
        'message': '子代理「$who」开了「派发前需要我确认」，而子代理在后台跑、没有审批界面：'
            '先用 /goal <目标> 切到免审批目标模式再派，或把它的写权限关掉（改成只读角色）。',
      };
    }
    return null;
  }

  /// 域不匹配的结构化拒绝（双方向通用：开发助手点逆向域、逆向助手点开发域都拦）。
  Map<String, dynamic> _domainMismatch(
    SubAgentDefinition definition,
    SubAgentDomain domain, {
    String? memberName,
  }) {
    final who = memberName == null || memberName.isEmpty
        ? definition.slug
        : '$memberName(${definition.slug})';
    final defDomain = definition.domain == SubAgentDomain.apk ? '逆向' : '开发';
    final curDomain = switch (domain) {
      SubAgentDomain.apk => '逆向',
      SubAgentDomain.dev => '开发',
      SubAgentDomain.any => '通用',
    };
    // 域标签拼成「逆向域」这种整词：既有单测断的就是这个词。
    final defLabel = '$defDomain域';
    final curLabel = '$curDomain域';
    return <String, dynamic>{
      'ok': false,
      'error': 'subagent_domain_mismatch',
      'message': '子代理「$who」是$defLabel角色，而当前助手属$curLabel（各司其职：'
          '两套角色不互相借用）。换成本域角色，或切到$defLabel助手再派。',
    };
  }

  Future<String> _unknownAgent(String agentKey, SubAgentDomain domain) async {
    final available = (await _registry.all())
        .where((item) => SubAgentRegistry.visibleInDomain(item, domain))
        .map((item) => item.slug)
        .toList(growable: false);
    return jsonEncode(<String, dynamic>{
      'ok': false,
      'error': 'unknown_subagent',
      'message': '没有名为 $agentKey 的子代理',
      'availableAgents': available,
    });
  }

  static const String toolName = LocalToolNames.subagent;
}
