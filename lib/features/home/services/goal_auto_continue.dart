import 'session_mode.dart';

/// 目标模式的**自动推进循环**（2026-10-03，对齐参考 CLI 的 goal 循环）。
///
/// 协议：目标模式的系统提示里已告诉模型——每轮结束系统会自动让它继续；
/// 模型在终局时于回复末尾单独一行输出哨兵（见 [GoalLoopProtocol]）：
/// - `[目标完成]` → 停车并提示用户；
/// - `[目标受阻]` + 原因 → 停车并提示；
/// - 都没有 → 自动发一条接续消息跑下一轮，直到上限 [maxAutoRounds]。
///
/// 模型自启用：任何模式下回复里出现 `[启用目标模式] <目标>` 就把本会话切到
/// 目标模式并接续推进（参考项目里模型可以自己开目标模式）。
///
/// 边界：只在**当前激活会话**上自动接续（切走即暂停，避免后台无限烧钱）；
/// 上限计数在用户手动发消息时清零（用户重新给方向 = 新的一程）。
class GoalAutoContinue {
  GoalAutoContinue({SessionModeStore? store})
    : _store = store ?? SessionModeStore();

  final SessionModeStore _store;

  /// conversationId -> 已连续自动推进的轮数。
  final Map<String, int> _rounds = <String, int>{};

  static const int maxAutoRounds = GoalLoopProtocol.maxAutoRounds;

  int roundsOf(String conversationId) => _rounds[conversationId] ?? 0;

  /// 用户手动发送：新的一程，连跑计数清零。
  void noteUserSend(String conversationId) {
    _rounds.remove(conversationId.trim());
  }

  /// 断言/测试用。
  void resetAll() => _rounds.clear();

  /// 一轮回答收尾后的判定；调用方据 [GoalTurnDecision] 决定是否续跑。
  Future<GoalTurnDecision> onTurnCompleted({
    required String conversationId,
    required String replyText,
    required bool isActiveConversation,
  }) async {
    final id = conversationId.trim();
    if (id.isEmpty) return const GoalTurnDecision();

    final outcome = GoalLoopProtocol.parse(replyText);
    var mode = await _store.modeOf(id);
    var goal = await _store.goalOf(id);

    // ① 模型自启用目标模式（任何模式下都认；已在目标模式则不重复切）。
    final requestedGoal = outcome.enableGoal;
    if (requestedGoal != null &&
        requestedGoal.isNotEmpty &&
        (mode != SessionMode.goal || goal != requestedGoal)) {
      await _store.setGoal(id, requestedGoal);
      await _store.setMode(id, SessionMode.goal);
      SessionModeRuntime.apply(
        id,
        SessionModePolicy(mode: SessionMode.goal, goal: requestedGoal),
      );
      mode = SessionMode.goal;
      goal = requestedGoal;
      _rounds[id] = 0;
      return GoalTurnDecision(
        notice: '已自动进入目标模式并接续推进：$requestedGoal',
        continueNow: true,
        continuationMessage: _continuation(1),
        round: 1,
      );
    }

    if (mode != SessionMode.goal) return const GoalTurnDecision();

    // ② 终局：完成 / 受阻 → 停车（不自动退出模式——用户可继续追问或用
    //    /build、横幅 X 退出）。
    if (outcome.done) {
      _rounds.remove(id);
      return const GoalTurnDecision(
        notice: '目标已完成，自动推进停止（发消息可继续，/build 退出目标模式）',
        terminal: true,
      );
    }
    if (outcome.stuck) {
      _rounds.remove(id);
      final reason = outcome.stuckReason;
      return GoalTurnDecision(
        notice: '目标受阻，自动推进停止'
            '${reason == null || reason.isEmpty ? '' : '：$reason'}'
            '（发消息给出新线索可继续）',
        terminal: true,
      );
    }

    // ③ 仍在推进中：自动接续。
    if (!isActiveConversation) {
      _rounds.remove(id);
      return const GoalTurnDecision(
        notice: '目标模式自动推进已暂停（切回该会话后发消息即可续跑）',
        terminal: true,
      );
    }
    final next = roundsOf(id) + 1;
    if (next > maxAutoRounds) {
      _rounds.remove(id);
      return GoalTurnDecision(
        notice: '自动推进已达上限（$maxAutoRounds 轮），发送消息可继续',
        terminal: true,
      );
    }
    _rounds[id] = next;
    return GoalTurnDecision(
      continueNow: true,
      continuationMessage: _continuation(next),
      round: next,
    );
  }

  String _continuation(int round) =>
      '${GoalLoopProtocol.autoContinue} $round/$maxAutoRounds 继续推进目标；'
      '已完成输出 ${GoalLoopProtocol.done}，受阻输出 ${GoalLoopProtocol.stuck}。';
}

/// 一次收尾判定的结果。
class GoalTurnDecision {
  const GoalTurnDecision({
    this.continueNow = false,
    this.terminal = false,
    this.continuationMessage,
    this.notice,
    this.round = 0,
  });

  /// 是否立即自动发送 [continuationMessage] 跑下一轮。
  final bool continueNow;

  /// 循环在本轮结束（完成/受阻/暂停/触顶）。
  final bool terminal;

  final String? continuationMessage;

  /// 给用户看的一行提示（可选）。
  final String? notice;

  final int round;
}
