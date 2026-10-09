import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../solab_apk/services/apk_agent_policy.dart';
import '../../../core/services/local_tools/local_tool_names.dart';
import 'tool_approval_service.dart';

/// 会话工作模式。
///
/// 用户 2026-09-28 定性：**这是斜杠命令，不是权限设置**——输入框打 `/` 选中
/// `/plan` `/goal` 即切换（用户 2026-09-28 定稿：只保留这两档）；「审批」只是模式带来的效果
/// 效果。设计见 docs/设计-斜杠命令与子代理.md。
enum SessionMode {
  build('build', '普通', '按工具自身配置审批'),
  // 说明对齐参考 CLI 的 plan/goal 语义（用户 2026-10-03：四字版
  // 「只出计划/免审执行」看不出与参考项目的对应关系）。
  plan('plan', '计划', '先出分步计划，经确认再执行'),
  goal('goal', '目标', '围绕目标自主推进（免审批）');

  const SessionMode(this.wireName, this.title, this.subtitle);

  final String wireName;
  final String title;
  final String subtitle;

  static SessionMode fromWire(String? value) => SessionMode.values.firstWhere(
    (m) => m.wireName == value,
    orElse: () => SessionMode.build,
  );
}

/// 目标循环哨兵标记（2026-10-03，对齐参考 CLI 的 goal 自动推进协议）。
abstract final class GoalLoopProtocol {
  static const String done = '[目标完成]';
  static const String stuck = '[目标受阻]';
  static const String enable = '[启用目标模式]';
  static const String autoContinue = '[自动推进]';
  static const int maxAutoRounds = 8;

  /// 解析一条回复的终局标记。只看尾部 600 字符：协议要求标记写在结尾，
  /// 正文里引用协议文字（教程/引用）不应误触发。
  ///
  /// 评审批 P1（2026-10-04）：哨兵必须**独立成行**（trim 后整行等于标记，
  /// 或以 stuck/enable 标记开头）。过去是尾部窗口内 contains 子串——而 build
  /// 模式提示词自己把 `[启用目标模式] <目标>` 教给了模型，模型在普通回答里
  /// 复述/引用该字样就会被误判：静默切进免审 goal 并自动续跑、引用
  /// `[目标完成]` 提前停车。
  static GoalTurnOutcome parse(String replyText) {
    final text = replyText.trimRight();
    final tail = text.length > 600 ? text.substring(text.length - 600) : text;
    var doneSeen = false;
    var stuckSeen = false;
    String? stuckReason;
    String? enableGoal;
    for (final rawLine in tail.split('\n')) {
      final line = rawLine.trim();
      if (line.isEmpty) continue;
      if (line == GoalLoopProtocol.done) {
        doneSeen = true;
        continue;
      }
      if (line.startsWith(GoalLoopProtocol.stuck)) {
        stuckSeen = true;
        final reason = line
            .substring(GoalLoopProtocol.stuck.length)
            .replaceFirst(RegExp(r'^[：:\s]+'), '')
            .trim();
        if (reason.isNotEmpty) stuckReason = reason;
        continue;
      }
      if (line.startsWith(GoalLoopProtocol.enable)) {
        final rest = line
            .substring(GoalLoopProtocol.enable.length)
            .replaceFirst(RegExp(r'^[：:\s]+'), '')
            .trim();
        if (rest.isNotEmpty) enableGoal = rest;
      }
    }
    return GoalTurnOutcome(
      done: doneSeen,
      stuck: stuckSeen,
      stuckReason: stuckReason,
      enableGoal: enableGoal,
    );
  }
}

/// 一条回复解析出的目标循环状态。
class GoalTurnOutcome {
  const GoalTurnOutcome({
    required this.done,
    required this.stuck,
    this.stuckReason,
    this.enableGoal,
  });

  final bool done;
  final bool stuck;
  final String? stuckReason;

  /// 非空 = 模型请求进入目标模式，值为目标描述。
  final String? enableGoal;

  bool get terminal => done || stuck;
}

/// 变更类工具（单一来源，勿在别处再抄一份）：PLAN 下从工具面摘掉，
/// GOAL 未设定目标前同样摘掉。基础集合复用 APK 侧已有的 mutationToolNames，
/// 再补上 Frida 注入入口；文档/笔记/待办**不在**拦截名单里。
///
/// 一致性测试会断言这里每个名字都真实存在于 [LocalToolNames.all]，
/// 工具改名后不同步就会红（Rikkahub-Next 的注释里也踩过同一个坑）。
final Set<String> kMutatingToolNames = <String>{
  ...ApkAgentPolicy.mutationToolNames,
  LocalToolNames.frida,
  // 第 72 项：运行时控制面里只有 workspace_cleanup 真删文件（中间产物），
  // 计划模式下不能给模型这把扫帚；其余控制工具只读状态/登记计划，不拦。
  LocalToolNames.workspaceCleanup,
  // 用户 2026-09-28：建立文档、记笔记、维护待办在计划模式下也要能正常用，
  // 所以把这些从"产物改动"里摘出去（产物类 = APK/补丁/签名/注入）。
  LocalToolNames.file,
  LocalToolNames.apkNoteWrite,
}..removeAll(<String>{LocalToolNames.file, LocalToolNames.apkNoteWrite});

/// 会话模式的持久化与策略。
///
/// 存放在独立 prefs 键里（按会话 id 索引），不动 Conversation 生成模型——
/// 模型加字段要跑 build_runner 且牵连迁移，收益不值当。
class SessionModeStore {
  SessionModeStore({SharedPreferences? preferences}) : _injected = preferences;

  static const String prefsKey = 'session_mode_v1';
  static const String _goalsKey = 'session_goals_v1';

  final SharedPreferences? _injected;
  SharedPreferences? _prefs;

  Future<SharedPreferences> _open() async =>
      _injected ?? (_prefs ??= await SharedPreferences.getInstance());

  Future<SessionMode> modeOf(String conversationId) async {
    if (conversationId.isEmpty) return SessionMode.build;
    final prefs = await _open();
    final raw = prefs.getString(prefsKey);
    if (raw == null || raw.isEmpty) return SessionMode.build;
    try {
      final map = jsonDecode(raw) as Map<String, dynamic>;
      return SessionMode.fromWire(map[conversationId]?.toString());
    } catch (_) {
      return SessionMode.build;
    }
  }

  Future<void> setMode(String conversationId, SessionMode mode) async {
    if (conversationId.isEmpty) return;
    final prefs = await _open();
    final map = _decodeMap(prefs.getString(prefsKey));
    map[conversationId] = mode.wireName;
    await prefs.setString(prefsKey, jsonEncode(map));
  }

  /// GOAL 模式的目标文本；非空才允许改动。
  Future<String> goalOf(String conversationId) async {
    if (conversationId.isEmpty) return '';
    final prefs = await _open();
    final map = _decodeMap(prefs.getString(_goalsKey));
    return map[conversationId]?.toString().trim() ?? '';
  }

  Future<void> setGoal(String conversationId, String goal) async {
    if (conversationId.isEmpty) return;
    final prefs = await _open();
    final map = _decodeMap(prefs.getString(_goalsKey));
    if (goal.trim().isEmpty) {
      map.remove(conversationId);
    } else {
      map[conversationId] = goal.trim();
    }
    await prefs.setString(_goalsKey, jsonEncode(map));
  }

  /// 会话删除时清掉「模式 + 目标」两条记录。
  ///
  /// 历史（已修，勿回退）：这两处 prefs 只写不清 —— 会话删掉后
  /// `session_mode_v1` / `session_goals_v1` 里的键永久残留（每建一个会话、
  /// 切过一次模式就多两条），且 `SessionModeRuntime.reset(id)` 的文档写着
  /// 「会话删除」但全仓没有任何删除路径调用它，进程内策略与免审批登记
  /// 也一起留在静态表里。现由 main.dart 的 onConversationDeleted 钩子调用。
  Future<void> clearConversation(String conversationId) async {
    final id = conversationId.trim();
    if (id.isEmpty) return;
    final prefs = await _open();
    final modes = _decodeMap(prefs.getString(prefsKey));
    final goals = _decodeMap(prefs.getString(_goalsKey));
    final hadMode = modes.remove(id) != null;
    final hadGoal = goals.remove(id) != null;
    if (!hadMode && !hadGoal) return;
    await prefs.setString(prefsKey, jsonEncode(modes));
    await prefs.setString(_goalsKey, jsonEncode(goals));
  }

  static Map<String, dynamic> _decodeMap(String? raw) {
    if (raw == null || raw.isEmpty) return <String, dynamic>{};
    try {
      final decoded = jsonDecode(raw);
      return decoded is Map
          ? Map<String, dynamic>.from(decoded)
          : <String, dynamic>{};
    } catch (_) {
      return <String, dynamic>{};
    }
  }
}

/// 进程内的会话模式（**按会话隔离**）。
///
/// 由聊天页在「切会话 / 执行斜杠命令 / 会话恢复」时写入；工具分发入口与审批门
/// 按 conversationId 查。作用域是"当前会话"——与 scopeId（产物物理状态）不同，
/// 模式是纯会话态，所以这里以会话 id 为键存策略。
///
/// 历史（已修，勿回退）：这里曾是一个进程级静态策略 + 一个全局开关
/// `ToolApprovalService.bypassAllApprovals`，后果是 A 会话 `/goal` 之后 B 会话的
/// 高风险工具（patch/sign/install）也全部免审——跨会话泄漏。现在策略与免审登记
/// 都按 id 查，**没有会话上下文的调用一律按 build 处理（不跳过审批）**：
/// 宁可多问一次，也不让来路不明的调用静默放行。
class SessionModeRuntime {
  SessionModeRuntime._();

  static final Map<String, SessionModePolicy> _policies =
      <String, SessionModePolicy>{};

  /// 模式变更广播（2026-10-03）：模型自启用目标模式/自动推进改模式时，
  /// 输入框上方的模式横幅要跟着刷新。只在模式或目标**真的变了**时 +1，
  /// 消费方（composer）按值比对后重载——两边互相 apply 不会成环。
  static final ValueNotifier<int> revision = ValueNotifier<int>(0);

  /// 查某会话的策略；未登记（含空 id）按默认 build。
  static SessionModePolicy policyFor(String? conversationId) =>
      _policies[conversationId?.trim() ?? ''] ??
      const SessionModePolicy(mode: SessionMode.build);

  static SessionMode modeFor(String? conversationId) =>
      policyFor(conversationId).mode;

  /// 写入某会话的策略（切会话 / 执行斜杠命令 / 会话恢复时调用）。
  /// 空 id 不登记——模式必须绑定到具体会话，否则会退化成全局开关。
  static void apply(String conversationId, SessionModePolicy policy) {
    final id = conversationId.trim();
    if (id.isEmpty) return;
    final previous = _policies[id];
    _policies[id] = policy;
    ToolApprovalService.setBypassApprovals(id, policy.bypassesApproval);
    if (previous?.mode != policy.mode || previous?.goal != policy.goal) {
      revision.value++;
    }
  }

  /// 清掉某会话的模式（会话删除 / 切走）。不传则清空全部（登出与测试用）。
  static void reset([String? conversationId]) {
    final id = conversationId?.trim() ?? '';
    if (id.isEmpty) {
      _policies.clear();
      ToolApprovalService.clearBypassApprovals();
      revision.value++;
      return;
    }
    if (_policies.remove(id) != null) revision.value++;
    ToolApprovalService.setBypassApprovals(id, false);
  }

  /// 工具分发前的只读拦截：null = 放行。
  static Map<String, dynamic>? denyReason(
    String? conversationId,
    String toolName,
  ) => policyFor(conversationId).denyReason(toolName);

  /// 某会话模式的系统提示片段（空串表示无需注入）。
  static String promptHintFor(String? conversationId) =>
      policyFor(conversationId).promptHint;
}

class SessionModePolicy {
  const SessionModePolicy({required this.mode, this.goal = ''});

  final SessionMode mode;
  final String goal;

  bool get allowsMutation => switch (mode) {
    SessionMode.build => true,
    SessionMode.plan => false,
    SessionMode.goal => goal.trim().isNotEmpty,
  };

  /// 是否跳过审批（YOLO / GOAL 免审批；PLAN 不放行变更类工具，谈不上审批）。
  bool get bypassesApproval => mode == SessionMode.goal;

  /// 执行期拦截：返回 null 表示放行，否则返回结构化拒绝（模型能据此自我纠正）。
  Map<String, dynamic>? denyReason(String toolName) {
    if (!kMutatingToolNames.contains(toolName)) return null;
    if (allowsMutation) return null;
    return switch (mode) {
      SessionMode.plan => {
        'ok': false,
        'error': 'plan_mode_readonly',
        'message':
            '当前是 /plan（计划模式）：变更类工具 $toolName 不可用。'
            '先只调研并给出计划；用户发 /build 回到普通模式，或发 /goal <目标> '
            '切到目标模式后才能执行改动。',
        'recoverable': true,
      },
      SessionMode.goal => {
        'ok': false,
        'error': 'goal_not_set',
        'message':
            '当前是 /goal 模式但还没有设定目标：先用 /goal <目标描述> 定下目标，'
            '或用 /build 回到普通模式，然后才能调用 $toolName。',
        'recoverable': true,
      },
      _ => null,
    };
  }

  /// 从工具面摘掉当前不允许的变更类工具（模式变化时模型看到的工具就变了，
  /// 不必等执行期才报错）。
  List<Map<String, dynamic>> filterDefinitions(
    List<Map<String, dynamic>> definitions,
  ) {
    if (allowsMutation) return definitions;
    return definitions
        .where((definition) {
          final fn = definition['function'];
          final name = fn is Map ? fn['name']?.toString() ?? '' : '';
          return !kMutatingToolNames.contains(name);
        })
        .toList(growable: false);
  }

  /// 注入系统提示的模式约束段。
  ///
  /// 用户 2026-09-29 定性：plan 模式必须**真的产出计划**（给出产出规格与
  /// 落点，而不是一句"出个计划"的空约束）；goal 模式的目标是用户私下交给
  /// 模型的方向，不是必须逐条达成的验收条件。
  String get promptHint => switch (mode) {
    SessionMode.build =>
      // 自启用契约（用户 2026-10-03：参考项目里模型能自己开目标模式）：
      // 只在用户交来的是需要多轮自主推进的大目标时才宣告，普通问答不要用。
      '如果用户交给你的是一个**需要多轮自主推进的大目标**（而不是一两轮就能答完的'
          '问题），你可以在回复里**单独一行**输出 `${GoalLoopProtocol.enable} <目标描述>`：'
          '系统会把本会话切到目标模式（免审批）并自动接续推进直到你宣告完成。'
          '其余情况不要输出该标记；用普通问答即可。',
    SessionMode.plan =>
      '当前处于计划模式（用户用 /plan 切换）：只做调研与分析，不要尝试改动'
          '文件或产物（变更类工具已下线）。本模式的核心产出是一份计划，必须真的'
          '给出，不能泛泛而谈：① 先用只读工具（或子代理）把现状摸清，不要凭空编；'
          '② 计划分步列出，每一步写清做什么、动哪些文件/产物、用什么工具、'
          '完成后如何验证；③ 把计划落成文档（file 工具写入工作区 plans/ 目录，'
          '方便用户找到），并用 todo_write 登记成待办清单，方便执行阶段逐项跟进；'
          '④ 明确标注「以上是计划，'
          '尚未执行」。用户发 /build 回到普通模式，或发 /goal <目标> 切到'
          '目标模式后才能执行改动。',
    SessionMode.goal =>
      goal.trim().isEmpty
          ? '当前处于目标模式（用户用 /goal 切换）但尚未设定目标：先向用户确认目标，'
                '或提示用户用 /goal <目标> 设定；目标设定前不要改动任何东西。'
          : '当前处于目标模式。用户把目标交给了你：$goal——这是你自主推进的方向，'
                '不是必须逐条达成的验收条件：围绕它调研、改动、验证，遇到歧义按目标'
                '取舍，不必逐步请示；若发现更优路径或目标本身不成立，先说清你的判断'
                '再行动。外部 MCP 工具与 shell、删除类操作仍会交给用户确认——那是'
                '留给用户的最后一道闸，等待确认结果即可，不要重试或试图绕过。\n'
                '自动推进协议：每轮结束后系统会**自动**让你继续推进（不用问用户'
                '"要不要继续"）。终局时在回复**最后单独一行**输出标记：'
                '① 目标已完成 → `${GoalLoopProtocol.done}`（可附一句结论/证据）；'
                '② 被外部条件卡住、自己无法推进 → `${GoalLoopProtocol.stuck}` + 原因。'
                '仍在推进中就不要输出标记。不要为了收工而假报完成——假报比多跑几轮更糟。',
  };
}
