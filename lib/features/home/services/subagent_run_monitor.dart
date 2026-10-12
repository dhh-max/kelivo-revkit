import 'package:flutter/foundation.dart';

import 'subagent_loop.dart';

/// 正在跑（或刚跑完）的一个子代理实例（监看/回看用）。
class SubAgentRun {
  SubAgentRun({
    required this.id,
    required this.agent,
    required this.label,
    required this.startedAt,
    this.task = '',
    this.conversationId,
    this.stage = '启动中',
  });

  final String id;
  final String agent;
  final String label;
  final DateTime startedAt;

  /// 派发给它的任务原文（展开弹窗的标题与上下文）。
  final String task;

  /// 派发它的会话：会话级「停止生成」据此把在跑的子代理一起收口。
  final String? conversationId;

  /// 用户已经请求中止这一次运行（由监看面板或会话级停止写入）。
  /// 循环在下一个步骤边界读到它就收口——模型请求不可中断，但不会再发下一次。
  bool cancelRequested = false;

  String stage;

  /// 终局状态（finish 时写入）：'ok' / 'timeout' / 'error' / 'cancelled' /
  /// 'unavailable'。在跑时为 null——队列弹窗据此区分「进行中」与「结局」。
  String? outcomeStatus;
  String? outcomeError;

  /// 对话历史（思考内容 / 每步输出 / 工具调用与结果），循环逐步写入。
  /// 用户 2026-10-01：展开要能看到它干了什么，不能静默。
  final List<SubAgentTranscriptEntry> transcript = <SubAgentTranscriptEntry>[];

  Duration get elapsed => DateTime.now().difference(startedAt);

  String get title {
    final name = label.isEmpty ? agent : '$agent（$label）';
    return '子代理 $name · $stage';
  }
}

/// 子代理运行监看（进程内）：谁在跑、跑到哪一步、跑了多久、**中止**，以及
/// 跑完的记录回看（最近 [recentLimit] 条，含完整对话历史）。
///
/// 与 Rikkahub-Next 的 SubAgentRunMonitor 同职责。历史（已修，勿回退）：
/// 这里曾经没有任何取消入口——用户按「停止」只切断主会话订阅，子代理挂在
/// 工具调用后面继续跑（继续烧额度，/goal 下继续写工作区）。现在取消是显式的：
/// 面板按实例中止，会话级停止按会话收口。2026-10-01 起跑完的实例不再直接
/// 丢弃，而是进 [recent] 供状态条点开回看（队列 + 对话历史）。
class SubAgentRunMonitor extends ChangeNotifier {
  SubAgentRunMonitor._();

  static final SubAgentRunMonitor instance = SubAgentRunMonitor._();

  /// 跑完的实例最多保留几条（含对话历史；完整历史不小，滚动淘汰）。
  static const int recentLimit = 8;

  final Map<String, SubAgentRun> _active = <String, SubAgentRun>{};
  final List<SubAgentRun> _recent = <SubAgentRun>[];

  List<SubAgentRun> get active => _active.values.toList(growable: false);

  /// 最近跑完的实例（新的在前），供队列弹窗回看。
  List<SubAgentRun> get recent => List<SubAgentRun>.unmodifiable(_recent);

  /// 会话隔离（2026-10-01 用户点名）：灯条/队列/卡片只看**当前会话**的
  /// 子代理。传入空串 = 不过滤（MCP 面与无会话上下文时）。
  List<SubAgentRun> activeFor(String? conversationId) {
    final cid = conversationId?.trim() ?? '';
    if (cid.isEmpty) return active;
    return <SubAgentRun>[
      for (final run in _active.values)
        if (run.conversationId == cid) run,
    ];
  }

  List<SubAgentRun> recentFor(String? conversationId) {
    final cid = conversationId?.trim() ?? '';
    if (cid.isEmpty) return recent;
    return <SubAgentRun>[
      for (final run in _recent)
        if (run.conversationId == cid) run,
    ];
  }

  bool hasActivityFor(String? conversationId) =>
      activeFor(conversationId).isNotEmpty ||
      recentFor(conversationId).isNotEmpty;

  bool get hasActive => _active.isNotEmpty;

  SubAgentRun? runById(String id) {
    final active = _active[id];
    if (active != null) return active;
    for (final run in _recent) {
      if (run.id == id) return run;
    }
    return null;
  }

  void begin({
    required String id,
    required String agent,
    required String label,
    String task = '',
    String? conversationId,
  }) {
    _active[id] = SubAgentRun(
      id: id,
      agent: agent,
      label: label,
      task: task,
      startedAt: DateTime.now(),
      conversationId: conversationId,
    );
    notifyListeners();
  }

  void updateStage(String id, String stage) {
    final run = _active[id];
    if (run == null || run.stage == stage) return;
    run.stage = stage;
    notifyListeners();
  }

  /// 循环逐步写入对话历史（只有还在跑的实例接受写入）。
  void appendTranscript(String id, SubAgentTranscriptEntry entry) {
    final run = _active[id];
    if (run == null) return;
    run.transcript.add(entry);
    notifyListeners();
  }

  void finish(String id, {String? status, String? error}) {
    final run = _active.remove(id);
    if (run != null) {
      run
        ..outcomeStatus = status
        ..outcomeError = error;
      _recent.insert(0, run);
      while (_recent.length > recentLimit) {
        _recent.removeLast();
      }
      notifyListeners();
    }
  }

  /// 用户点了某一行的「中止」：标记这个实例，循环会在下一个步骤边界收口。
  /// 返回 false = 这次运行已经跑完了（不要弹一个中止成功的假象）。
  bool requestCancel(String id) {
    final run = _active[id];
    if (run == null) return false;
    if (run.cancelRequested) return true;
    run.cancelRequested = true;
    notifyListeners();
    return true;
  }

  /// 会话级停止：把该会话下所有在跑的子代理一起标成中止。
  /// 返回这次新标了几个（已经标过的不重复计数）——调用方据此判断要不要提示用户。
  int requestCancelForConversation(String? conversationId) {
    final cid = conversationId?.trim() ?? '';
    if (cid.isEmpty) return 0;
    var marked = 0;
    for (final run in _active.values) {
      if (run.conversationId != cid) continue;
      if (run.cancelRequested) continue;
      run.cancelRequested = true;
      marked++;
    }
    if (marked > 0) notifyListeners();
    return marked;
  }

  /// 循环轮询用：某个实例是否已被请求中止（跑完摘除后恒为 false）。
  bool isCancelRequested(String id) => _active[id]?.cancelRequested ?? false;

  /// 测试与异常兜底用：清空所有在跑的记录。
  void clear() {
    if (_active.isEmpty && _recent.isEmpty) return;
    _active.clear();
    _recent.clear();
    notifyListeners();
  }
}
