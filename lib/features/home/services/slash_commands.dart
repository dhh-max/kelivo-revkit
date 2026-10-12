import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'session_mode.dart';
import 'subagent_registry.dart';

/// 斜杠命令的执行上下文。UI 只提供回调，命令本身不依赖具体页面。
class SlashCommandContext {
  const SlashCommandContext({
    required this.conversationId,
    required this.modeStore,
    this.sendMessage,
    this.openSkills,
    this.clearContext,
    this.dispatchSubAgent,
  });

  final String conversationId;
  final SessionModeStore modeStore;

  /// 以用户身份发一条消息（`/review` `/todo` 这类把请求交给主 Agent 的命令）。
  final Future<void> Function(String message)? sendMessage;

  /// 打开技能面板（复用输入框已有的 onOpenSkills）。
  final VoidCallback? openSkills;

  /// 派发一个子代理（`/subagent <slug> <任务>`），返回工具侧的 JSON 字符串。
  final Future<String> Function(String agent, String task)? dispatchSubAgent;

  /// 清理本会话的上下文快照（预览令牌、工具快照）。
  final Future<void> Function()? clearContext;
}

class SlashCommandResult {
  const SlashCommandResult({
    this.handled = true,
    this.notice,
    this.draft,
    this.isError = false,
  });

  /// true = 命令已被消化，不要把原文当普通消息发出去。
  final bool handled;

  /// 给用户的一行反馈（输入框上方的状态条）。
  final String? notice;

  /// 反馈是不是失败（状态条据此着色，用户一眼能分清「做完了」和「没做成」）。
  final bool isError;

  /// 需要写回输入框的文本（例如 `/goal` 缺目标时给出待补模板，或选中技能后的模板）。
  final String? draft;
}

/// 命令面板里一行的类别：命令 / 技能 / 子代理。
///
/// 面板形态对齐其他 agent CLI：输入 `/` 在输入框上方弹出浮层，可搜索命令、
/// 技能或子代理（用户 2026-09-28 指定）。
enum SlashPaletteKind { command, skill, subagent }

class SlashPaletteEntry {
  const SlashPaletteEntry({
    required this.kind,
    required this.name,
    required this.description,
    required this.insertText,
    this.commandName = '',
  });

  final SlashPaletteKind kind;

  /// 展示名：命令不带斜杠（`plan`），技能/子代理用原名。
  final String name;
  final String description;

  /// 选中后写回输入框的文本。
  final String insertText;

  /// 命令类才有：选中后直接执行（无参数命令）或回草稿（需要参数）。
  final String commandName;

  String get displayName => kind == SlashPaletteKind.command ? '/$name' : name;
}

/// 统一搜索：命令 + 技能 + 子代理。
///
/// - [query] 是输入框里去掉开头的 `/` 之后的文本；
/// - 命令按前缀匹配（`/pl` → plan）；技能/子代理按名称或描述的子串匹配；
/// - 空 query 时只列命令（避免一打开就淹没在技能里）。
List<SlashPaletteEntry> buildSlashPalette({
  required String query,
  List<({String name, String description})> skills = const [],
  List<({String slug, String description})> subagents = const [],
  int commandLimit = 12,
  int otherLimit = 6,
}) {
  final normalized = query.trim().toLowerCase();
  final entries = <SlashPaletteEntry>[];

  final commands = SlashCommands.all
      .where((command) => normalized.isEmpty || command.name.startsWith(normalized))
      .take(commandLimit);
  for (final command in commands) {
    entries.add(SlashPaletteEntry(
      kind: SlashPaletteKind.command,
      name: command.name,
      description: command.subtitle,
      // 模式命令也要留出分隔空格：面板写入的是纯文本 /plan，用户接着打字会拼成
      // /plan你好——那不是命令，整串会被当普通消息发出（用户 2026-09-29 报：
      // 选了模式却发不出命令）。留空格后 /plan 你好 才是「切模式 + 这条消息」。
      insertText:
          '/${command.name}${command.takesArgument || command.changesSession ? ' ' : ''}',
      commandName: command.name,
    ));
  }

  if (normalized.isNotEmpty) {
    for (final skill in skills
        .where((skill) =>
            skill.name.toLowerCase().contains(normalized) ||
            skill.description.toLowerCase().contains(normalized))
        .take(otherLimit)) {
      entries.add(SlashPaletteEntry(
        kind: SlashPaletteKind.skill,
        name: skill.name,
        description: skill.description,
        insertText: '/skill ${skill.name} ',
      ));
    }
    for (final agent in subagents
        .where((agent) =>
            agent.slug.toLowerCase().contains(normalized) ||
            agent.description.toLowerCase().contains(normalized))
        .take(otherLimit)) {
      entries.add(SlashPaletteEntry(
        kind: SlashPaletteKind.subagent,
        name: agent.slug,
        description: agent.description,
        insertText: '/subagent ${agent.slug} ',
      ));
    }
  }

  return entries;
}

class SlashCommand {
  const SlashCommand({
    required this.name,
    required this.title,
    required this.subtitle,
    this.takesArgument = false,
    this.changesSession = false,
    this.longRunning = false,
    required this.run,
  });

  /// 不含斜杠的命令名。
  final String name;
  final String title;
  final String subtitle;
  final bool takesArgument;

  /// 是否改变会话状态（模式类 = true，动作类 = false）。
  final bool changesSession;

  /// 是否需要等待（派发/审核类命令要跑模型或子代理，动辄几十秒）：
  /// 输入框上方先亮「正在执行」，结束后再换成结果或失败——过去这类命令
  /// 全程零反馈，用户只能猜它到底有没有跑。
  final bool longRunning;
  final Future<SlashCommandResult> Function(SlashCommandContext ctx, String args) run;
}

/// 斜杠命令注册表（单一数据源）。输入框只负责匹配与展示。
///
/// 用户 2026-09-28 定性：模式是命令不是权限；见
/// docs/设计-斜杠命令与子代理.md。
class SlashCommands {
  const SlashCommands._();

  static final List<SlashCommand> all = List<SlashCommand>.unmodifiable(<SlashCommand>[
    for (final mode in SessionMode.values)
      SlashCommand(
        name: mode.wireName,
        title: '切换到 ${mode.title}模式',
        subtitle: mode.subtitle,
        takesArgument: mode == SessionMode.goal,
        changesSession: true,
        run: (ctx, args) => _switchMode(ctx, mode, args),
      ),
    SlashCommand(
      name: 'review',
      title: '审核',
      subtitle: '对当前工作目录与最近产物做一次审核',
      run: (ctx, args) => _relay(
        ctx,
        '请对本会话做一次审核：'
        '① 用审计工具列出工作目录内最近改动与产物（audit / list_builds / analyze_apk_workspace）；'
        '② 对照目标指出风险与不一致（签名、去签、补丁是否真的生效）；'
        '③ 输出「结论 / 证据 / 建议下一步」三段，不要只说没问题。',
        '已发起审核',
      ),
      longRunning: true,
    ),
    SlashCommand(
      name: 'todo',
      title: '任务清单',
      subtitle: '让助手用 todo 工具维护当前任务清单',
      run: (ctx, args) => _relay(
        ctx,
        '请用 todo 工具把当前任务拆成可勾选的清单并更新状态，'
        '每完成一项就更新；清单要具体到可验证的动作。',
        '已请求更新任务清单',
      ),
      longRunning: true,
    ),
    SlashCommand(
      name: 'subagent',
      title: '派发子代理',
      subtitle: '/subagent [agent] <任务> —— 让独立实例做调研/审核',
      takesArgument: true,
      longRunning: true,
      run: (ctx, args) => _dispatchSubAgent(ctx, args),
    ),
    SlashCommand(
      name: 'team',
      title: '专家团',
      subtitle: '/team <任务> —— 专家团（分析→动手→复核）协作完成',
      takesArgument: true,
      longRunning: true,
      run: (ctx, args) => _dispatchTeam(ctx, args),
    ),
    SlashCommand(
      name: 'skill',
      title: '使用技能',
      subtitle: '/skill <技能名> —— 让助手按该技能的方法做',
      takesArgument: true,
      longRunning: true,
      run: (ctx, args) => _useSkill(ctx, args),
    ),
    SlashCommand(
      name: 'skills',
      title: '技能',
      subtitle: '打开技能面板',
      run: (ctx, args) async {
        if (ctx.openSkills == null) {
          return const SlashCommandResult(
            handled: false,
            notice: '当前页面不支持打开技能面板',
          );
        }
        ctx.openSkills!.call();
        return const SlashCommandResult(notice: '已打开技能面板');
      },
    ),
    SlashCommand(
      name: 'clear',
      title: '清理会话上下文',
      subtitle: '清掉本会话的工具快照与预览令牌，保留聊天记录',
      run: (ctx, args) async {
        if (ctx.clearContext == null) {
          return const SlashCommandResult(handled: false, notice: '当前页面不支持清理上下文');
        }
        await ctx.clearContext!.call();
        return const SlashCommandResult(notice: '已清理本会话的工具快照与预览令牌');
      },
    ),
    SlashCommand(
      name: 'help',
      title: '帮助',
      subtitle: '列出全部斜杠命令',
      run: (ctx, args) async => const SlashCommandResult(
        notice: '输入 / 选择命令；模式命令会改变后续轮次的工具面。',
      ),
    ),
  ]);

  static SlashCommand? byName(String name) {
    for (final command in all) {
      if (command.name == name) return command;
    }
    return null;
  }

  /// 输入框里以 `/` 开头时的候选（未输入参数前）。
  static List<SlashCommand> candidates(String text) {
    if (!text.startsWith('/')) return const <SlashCommand>[];
    final body = text.substring(1);
    if (body.contains(' ') || body.contains('\n')) return const <SlashCommand>[];
    if (body.isEmpty) return all;
    return all.where((command) => command.name.startsWith(body.toLowerCase())).toList();
  }

  /// 解析一条完整输入：`/plan`、`/goal 修好登录`。
  /// 返回 null 表示不是命令（按普通消息处理）。
  static ({SlashCommand command, String args})? parse(String text) {
    final trimmed = text.trim();
    if (!trimmed.startsWith('/')) return null;
    final withoutSlash = trimmed.substring(1);
    final spaceAt = withoutSlash.indexOf(RegExp(r'\s'));
    final name = (spaceAt < 0 ? withoutSlash : withoutSlash.substring(0, spaceAt)).toLowerCase();
    if (name.isEmpty) return null;
    final command = byName(name);
    if (command == null) return null;
    final args = spaceAt < 0 ? '' : withoutSlash.substring(spaceAt + 1).trim();
    return (command: command, args: args);
  }

  static Future<SlashCommandResult> _useSkill(
    SlashCommandContext ctx,
    String args,
  ) async {
    final name = args.trim();
    if (name.isEmpty) {
      return const SlashCommandResult(
        notice: '用法：/skill <技能名>（可先输入 / 从面板里挑）',
        draft: '/skill ',
      );
    }
    return _relay(
      ctx,
      '请使用技能「$name」的方法完成接下来的任务；'
      '先用 use_skill 读取该技能，再按它的步骤执行并在结尾说明引用了哪条技能。',
      '已请求使用技能：$name',
    );
  }

  /// `/team <任务>`：让主助手用 subagent 工具的专家团形态干活。
  ///
  /// 走 model relay 而不是直接编排出队：团队由主模型按任务自己拆（它才知道
  /// 需要几个角色、有没有依赖），我们只把"用团队、按域选预置、跑完给结论"说清楚。
  static Future<SlashCommandResult> _dispatchTeam(
    SlashCommandContext ctx,
    String args,
  ) async {
    final trimmed = args.trim();
    if (trimmed.isEmpty) {
      return const SlashCommandResult(
        notice: '用法：/team <任务>（用预置专家团：调研/分析 → 动手 → 复核）',
        draft: '/team ',
      );
    }
    return _relay(
      ctx,
      '请用 subagent 工具的专家团形态完成下面这件事，不要自己一个人从头做到尾：\n'
          '任务：$trimmed\n'
          '要求：① 按当前助手的领域选预置团（开发场景 team=dev-team，逆向场景 team=apk-team），'
          '需要别的分工时用 members 自定义，成员最多 4 个；'
          '② 有先后依赖的用 blockedBy 串起来，两个成员改同一片区域时给 writeScope，'
          '免得并行互相覆盖；③ 跑完先读 members 里每个成员的状态与 warnings，'
          '再对照 merged 给出结论：做成了什么、证据是什么、还有什么没验证。',
      '已发起专家团',
    );
  }

  static Future<SlashCommandResult> _dispatchSubAgent(
    SlashCommandContext ctx,
    String args,
  ) async {
    final trimmed = args.trim();
    if (trimmed.isEmpty) {
      return const SlashCommandResult(
        notice: '用法：/subagent [agent] <任务>（不带 agent 时用内置 general）',
        draft: '/subagent ',
      );
    }
    if (ctx.dispatchSubAgent == null) {
      return const SlashCommandResult(handled: false, notice: '当前页面不支持派发子代理');
    }
    // 第一个词**真的是已注册的子代理**时才算 agent，否则整串都是任务。
    // 历史行为是「只要有两个词就把第一个当 agent」——中文任务里带个空格
    // （/subagent 帮我看看 这个包）就会被当成未知子代理直接报错。
    final parts = trimmed.split(RegExp(r'\s+'));
    var agent = 'general';
    var task = trimmed;
    if (parts.length > 1 && !parts.first.contains('，')) {
      final candidate = await SubAgentRegistry().bySlug(parts.first);
      if (candidate != null) {
        agent = parts.first;
        task = trimmed.substring(parts.first.length).trim();
      }
    }
    // 派发本身可能抛（模型口未注册、网络异常…）：命令层必须收成可读反馈，
    // 否则异常直接冒到 _handleSend 之外，用户那边就是「点了没反应」。
    final String raw;
    try {
      raw = await ctx.dispatchSubAgent!.call(agent, task);
    } catch (error) {
      return SlashCommandResult(
        handled: true,
        isError: true,
        notice: '子代理派发失败：$error',
      );
    }
    Map<String, dynamic> decoded = const <String, dynamic>{};
    try {
      final parsed = jsonDecode(raw);
      if (parsed is Map) decoded = Map<String, dynamic>.from(parsed);
    } catch (_) {
      // 工具侧返回非 JSON 时按原文展示。
    }
    if (decoded.isEmpty) {
      return SlashCommandResult(handled: true, notice: '子代理已返回（非结构化结果）');
    }
    if (decoded['ok'] != true) {
      final message = decoded['message']?.toString() ??
          decoded['error']?.toString() ??
          '子代理未能完成';
      final next = decoded['nextActions'];
      final hint = next is List && next.isNotEmpty
          ? '（${next.first}）'
          : '';
      return SlashCommandResult(
        handled: true,
        isError: true,
        notice: '子代理未完成：$message$hint',
      );
    }
    final text = decoded['text']?.toString().trim() ?? '';
    final preview = text.length > 200 ? '${text.substring(0, 200)}…' : text;
    // 结果摘要要能回答「它到底干了什么」：状态 + 步数 + 用过的工具。
    final steps = decoded['steps'];
    final calls = decoded['toolCalls'];
    final trail = calls is List && calls.isNotEmpty
        ? '，用了 ${calls.take(4).join('、')}${calls.length > 4 ? ' 等' : ''}'
        : '';
    final head = '子代理「$agent」完成'
        '${steps is int && steps > 0 ? '（$steps 步$trail）' : ''}';
    return SlashCommandResult(
      handled: true,
      notice: preview.isEmpty ? '$head：没有给出结论' : '$head：$preview',
    );
  }

  static Future<SlashCommandResult> _switchMode(
    SlashCommandContext ctx,
    SessionMode mode,
    String args,
  ) async {
    if (mode == SessionMode.goal) {
      final goal = args.trim();
      // 显式清除：此前目标只能被新目标覆盖，一旦设下就没有"忘掉它"的路
      // （空参数分支会沿用它），陈目标会一直参与 goal 模式的免审批与提示注入。
      if (goal.toLowerCase() == 'clear') {
        final existing = await ctx.modeStore.goalOf(ctx.conversationId);
        await ctx.modeStore.setGoal(ctx.conversationId, '');
        // 目标没了，goal 模式本身就不成立（policy 会返回 goal_not_set）——
        // 若当前正处在 goal 模式，必须同时退回 build，不留半开状态。
        final current = await ctx.modeStore.modeOf(ctx.conversationId);
        if (current == SessionMode.goal) {
          await ctx.modeStore.setMode(ctx.conversationId, SessionMode.build);
        }
        return SlashCommandResult(
          notice: existing.isEmpty
              ? '本会话没有设置目标，无需清除（发 /goal <目标描述> 可进入目标模式）'
              : '已清除目标并退出目标模式：$existing',
        );
      }
      if (goal.isEmpty) {
        final existing = await ctx.modeStore.goalOf(ctx.conversationId);
        if (existing.isNotEmpty) {
          await ctx.modeStore.setMode(ctx.conversationId, SessionMode.goal);
          return SlashCommandResult(
            notice: '目标模式已启用，沿用既有目标：$existing'
                '（发 /goal <新目标> 可更换，发 /goal clear 可清除）',
          );
        }
        return const SlashCommandResult(
          notice: '目标模式需要目标文本：输入 /goal <目标描述>',
          draft: '/goal ',
        );
      }
      await ctx.modeStore.setGoal(ctx.conversationId, goal);
      await ctx.modeStore.setMode(ctx.conversationId, SessionMode.goal);
      // 用户 2026-10-03 实测：plan 切 goal 后「只会把横幅改成目标，消息不发出去」。
      // 对齐 /plan 的语义——目标文字同时作为**第一条消息**发出（模型收到任务
      // 才会围绕目标开工；否则用户还得再发一条，看起来就是命令没生效）。
      if (ctx.sendMessage == null) {
        return SlashCommandResult(
          notice: '已进入目标模式（免审批）：$goal；当前页面不能自动发送，目标已记录',
        );
      }
      await ctx.sendMessage!.call('/goal $goal');
      return SlashCommandResult(
        notice: '已进入目标模式，并把目标作为消息发送：$goal',
      );
    }
    await ctx.modeStore.setMode(ctx.conversationId, mode);
    // 模式命令后面的文字不能吞掉（用户 2026-09-29 真机反馈：选了模式后接着
    // 打字再发送，文字就没了）。语义：/plan 帮我看看 = 切到计划模式 +
    // 把「帮我看看」作为消息发出；页面没有发送通道时退回草稿，宁可留在输入框。
    final trailing = args.trim();
    if (trailing.isEmpty) {
      // plan 的提示给用户可验收的预期（用户 2026-09-29：要确保真的会出计划）。
      return SlashCommandResult(
        notice: mode == SessionMode.plan
            ? '已切换到 计划模式：只调研、产出分步计划，不动产物'
            : '已切换到 ${mode.title}模式（${mode.subtitle}）',
      );
    }
    if (ctx.sendMessage == null) {
      return SlashCommandResult(
        notice: '已切换到 ${mode.title}模式；当前页面不能自动发送，文字已留在输入框',
        draft: '/${mode.wireName} $trailing',
      );
    }
    // 消息里保留命令前缀（对齐参考 CLI：命令原文随消息一起出现在消息列表，
    // 用户 2026-10-03 实测「列表里只有文字、左侧没有 plan」），模式切换照常生效。
    await ctx.sendMessage!.call('/${mode.wireName} $trailing');
    return SlashCommandResult(
      notice: '已切换到 ${mode.title}模式，并把后面的内容作为消息发出',
    );
  }

  static Future<SlashCommandResult> _relay(
    SlashCommandContext ctx,
    String message,
    String notice,
  ) async {
    if (ctx.sendMessage == null) {
      return const SlashCommandResult(handled: false, notice: '当前页面不支持直接发送消息');
    }
    await ctx.sendMessage!.call(message);
    return SlashCommandResult(notice: notice);
  }
}
