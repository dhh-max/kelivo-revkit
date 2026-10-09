import 'dart:async';

import 'subagent_loop.dart';
import 'subagent_registry.dart';
import 'subagent_run_monitor.dart';

/// 子代理的一次运行请求。
class SubAgentRunRequest {
  const SubAgentRunRequest({
    required this.definition,
    required this.task,
    this.context,
    this.label = '',
    this.conversationId,
    this.categoriesOverride,
    this.mainSystemPrompt,
    this.bypassConcurrencyGate = false,
    this.maxToolCalls = 0,
    this.maxStepsOverride,
    this.timeoutMsOverride,
  });

  final SubAgentDefinition definition;
  final String task;

  /// 主代理给的背景（可选）：子代理本身看不到主对话时用它补上下文。
  final String? context;

  /// 监看面板用来区分同一子代理的多个实例。
  final String label;
  final String? conversationId;

  /// 自由子代理（general）调用时可覆盖类别。
  final Set<SubAgentCategory>? categoriesOverride;

  /// 主对话的系统提示（可选，用于对齐口径）。
  final String? mainSystemPrompt;

  /// 团队编排自己限流（见 subagent_team.dart）：团队成员不再各占单发派发的
  /// 每会话名额，否则 4 人团队会被单发上限直接拒掉。
  final bool bypassConcurrencyGate;

  /// 工具调用总数上限（0 = 用定义默认/不限）。真机实测 C2：调用侧此前无法
  /// 压低单成员预算，只能等 120s 硬超时。
  final int maxToolCalls;

  /// 调用侧覆盖（null = 用定义里的值）。同样来自 C2：maxSteps/timeoutMs
  /// 此前传了也不生效。
  final int? maxStepsOverride;
  final int? timeoutMsOverride;

  int get effectiveMaxSteps => maxStepsOverride ?? definition.maxSteps;
  int get effectiveTimeoutMs => timeoutMsOverride ?? definition.timeoutMs;

  Set<SubAgentCategory> get categories =>
      categoriesOverride ?? definition.categories;

  String get systemPrompt {
    final buffer = StringBuffer(definition.systemPrompt.trim());
    if (buffer.isNotEmpty) buffer.write('\n\n');
    // 执行纪律（2026-09-30）：lane 修好之后，「模型只回一句计划就收工」是子代理
    // 剩下的主要假完成形态。给一条明确的行动要求，并把"不需要工具"的出口留着
    // （纯问答类任务也是合法用法）。
    buffer.write(
      'Execute the task with the tools you have instead of describing what you '
      'would do next; answer directly only when the task genuinely needs no '
      'tool. Report what you actually did, with the evidence you used, and '
      'state plainly what you could not do.\n',
    );
    buffer.write('可用工具类别：${categories.map((category) => category.wireName).join(' / ')}。');
    buffer.write('\n步数上限 ${definition.maxSteps}，超时 ${definition.timeoutMs ~/ 1000}s。');
    final main = mainSystemPrompt?.trim() ?? '';
    if (main.isNotEmpty) {
      buffer.write('\n\n主对话上下文（只读参考）：\n$main');
    }
    return buffer.toString();
  }

  String get userPrompt {
    final context = this.context?.trim() ?? '';
    if (context.isEmpty) return task;
    return '$task\n\n背景：\n$context';
  }
}

class SubAgentOutcome {
  const SubAgentOutcome({
    required this.status,
    this.text = '',
    this.error,
    this.elapsedMs = 0,
    this.steps = 0,
    this.toolCalls = const <String>[],
    this.finishReason = 'completed',
  });

  final SubAgentStatus status;
  final String text;
  final String? error;
  final int elapsedMs;

  /// 循环跑了几步（单发模式恒为 1）。
  final int steps;

  /// 轨迹里实际用到的工具名（按调用顺序，含被拒绝的）。
  final List<String> toolCalls;

  /// 收口原因（B2）：completed / max_steps / max_tool_calls / timeout /
  /// cancelled / error / no_output。调用方据此区分「完成」与「提前退出」。
  final String finishReason;

  /// 预算/步数用尽导致的截断（报告 2-17）：不是失败，也不等于有结论。
  bool get truncated =>
      finishReason == 'max_tool_calls' || finishReason == 'max_steps';

  /// 有结论才算成功；截断且无文本 → 不算成功（与 SubAgentLoopResult 同口径）。
  bool get ok =>
      status == SubAgentStatus.ok && !(truncated && text.trim().isEmpty);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'status': status.name,
        if (text.isNotEmpty) 'text': text,
        if (error != null) 'error': error,
        'elapsedMs': elapsedMs,
        'finishReason': finishReason,
        if (steps > 0) 'steps': steps,
        if (toolCalls.isNotEmpty) 'toolCalls': toolCalls,
      };
}

/// 子代理的模型调用口：由应用层注入（那里才有 settings/providers 的解析权）。
typedef SubAgentGenerator = Future<String> Function({
  required String prompt,
  required String systemPrompt,
  required String? conversationId,
});

/// 子代理运行器。
///
/// 与 Rikkahub-Next 的差异（有意）：他们每个子代理是一个独立工具名
/// （`subagent_<slug>`），我们收敛成一个 `subagent` 工具 + `agent` 参数——
/// 本 fork 的工具注册表是"五处登记 + 一致性测试"的纪律，动态工具名会让每次
/// 新增子代理都要改代码并过测试，反而更贵。
class SubAgentRunner {
  SubAgentRunner({this._generator});

  /// 每对话同时运行的子代理上限（超出直接拒绝，避免悄悄排队拖长整轮）。
  static const int concurrencyLimitPerConversation = 2;

  static final Map<String, int> _running = <String, int>{};

  SubAgentGenerator? _generator;

  /// 带工具循环的驱动器（优先于单发生成口）。两者都没注册时返回 unavailable。
  SubAgentLoopDriver? loopDriver;

  /// 由应用层在能解析 settings/provider 的地方注册（见 ToolHandlerService）。
  set generator(SubAgentGenerator? value) => _generator = value;

  bool get hasGenerator => _generator != null || loopDriver != null;

  static int runningCount(String conversationId) => _running[conversationId] ?? 0;

  Future<SubAgentOutcome> run(SubAgentRunRequest request) async {
    final driver = loopDriver;
    final generator = _generator;
    if (driver == null && generator == null) {
      // 注册点在「构建本轮工具定义」里，所以进程启动后还没发过任何消息时
      // 这里必然为空。错误文案要给出可执行的下一步，而不是让用户/模型猜。
      return const SubAgentOutcome(
        status: SubAgentStatus.unavailable,
        error: '子代理的模型调用口尚未注册：本进程还没有完成过一轮模型装配。'
            '先在对话里发一条消息（内容随意）再派子代理即可；'
            'MCP 面同理，需要手机端先跑过一轮对话。',
      );
    }
    final scope = request.conversationId?.trim() ?? '';
    final running = runningCount(scope);
    if (!request.bypassConcurrencyGate &&
        scope.isNotEmpty &&
        running >= concurrencyLimitPerConversation) {
      return SubAgentOutcome(
        status: SubAgentStatus.error,
        error: '同一会话同时运行的子代理已达上限'
            '（$concurrencyLimitPerConversation），等前面的跑完再派。',
      );
    }
    if (!request.bypassConcurrencyGate && scope.isNotEmpty) {
      _running[scope] = running + 1;
    }
    final started = DateTime.now();
    // 监看：谁在跑、跑到哪一步。跑完/异常都在 finally 里摘除；摘除前实例
    // 带着完整对话历史进 recent 存档（状态条点开可回看，2026-10-01）。
    final runId = 'sub-${started.microsecondsSinceEpoch}-${request.definition.slug}';
    SubAgentRunMonitor.instance.begin(
      id: runId,
      agent: request.definition.slug,
      label: request.label,
      task: request.userPrompt,
      // 会话级「停止生成」据此把在跑的子代理一并收口（见 ChatActions.cancelStreaming）。
      conversationId: scope.isEmpty ? null : scope,
    );
    // 监看面板的中止按钮写这个标志；循环只在步骤边界读它。
    bool isCancelled() => SubAgentRunMonitor.instance.isCancelRequested(runId);
    // 所有 return 路径都先落这个变量：finally 摘除时把终局状态写进监看存档
    // （队列弹窗据此区分成功/超时/失败/中止，进度不造假）。
    var outcome = SubAgentOutcome(
      status: SubAgentStatus.error,
      error: '子代理未完成',
      elapsedMs: 0,
    );
    try {
      if (driver != null) {
        // 进这一层子代理的作用域：循环里的嵌套工具调用据此知道「我是第几层」
        // （SubAgentDepth.current），到 kSubAgentMaxDepth 就不再授予 subagent，
        // 从根上断掉递归派发。异常路径由 runZoned 自己还原。
        final loop = await SubAgentDepth.run(
          SubAgentDepth.current + 1,
          () => runSubAgentLoop(
            driver: driver,
            categories: request.categories,
            maxSteps: request.effectiveMaxSteps,
            timeoutMs: request.effectiveTimeoutMs,
            maxToolCalls: request.maxToolCalls,
            systemPrompt: request.systemPrompt,
            userPrompt: request.userPrompt,
            // enabledSkills 真正生效：授予技能读取工具 + 在提示里点名它们
            // （2026-09-29，此前这份字段只是存得下、没人用）。
            skills: request.definition.enabledSkills,
            conversationId: request.conversationId,
            isCancelled: isCancelled,
            onStage: (stage) =>
                SubAgentRunMonitor.instance.updateStage(runId, stage),
            // 对话历史逐步进监看（展开弹窗渲染思考内容/工具轨迹的数据源）。
            onTranscript: (entry) =>
                SubAgentRunMonitor.instance.appendTranscript(runId, entry),
          ),
        );
        outcome = SubAgentOutcome(
          status: loop.status,
          text: loop.text,
          error: loop.error,
          elapsedMs: DateTime.now().difference(started).inMilliseconds,
          steps: loop.steps,
          toolCalls: loop.transcript.map((call) => call.name).toList(growable: false),
          finishReason: loop.finishReason,
        );
        return outcome;
      }
      // 单发生成口没有步骤边界：请求前与回包后各查一次，用户中止就丢弃这次产出。
      if (isCancelled()) {
        outcome = SubAgentOutcome(
          status: SubAgentStatus.cancelled,
          error: '用户已中止这次子代理运行',
          elapsedMs: DateTime.now().difference(started).inMilliseconds,
          finishReason: 'cancelled',
        );
        return outcome;
      }
      SubAgentRunMonitor.instance.updateStage(runId, '等待模型');
      final text = await generator!(
        prompt: request.userPrompt,
        systemPrompt: request.systemPrompt,
        conversationId: request.conversationId,
      ).timeout(Duration(milliseconds: request.effectiveTimeoutMs));
      if (isCancelled()) {
        outcome = SubAgentOutcome(
          status: SubAgentStatus.cancelled,
          error: '用户已中止这次子代理运行（模型回包已丢弃）',
          elapsedMs: DateTime.now().difference(started).inMilliseconds,
          steps: 1,
          finishReason: 'cancelled',
        );
        return outcome;
      }
      SubAgentRunMonitor.instance.appendTranscript(
        runId,
        SubAgentTranscriptEntry.assistant(text: text.trim()),
      );
      // B1 平台侧（真机实测：首轮派发只回开场白却报 ok:true）：零工具调用
      // 且文本为空 = 静默失败，不按 ok 上报。
      final trimmed = text.trim();
      outcome = trimmed.isEmpty
          ? SubAgentOutcome(
              status: SubAgentStatus.error,
              error: '子代理没有产出任何结论（subagent_empty_completion）',
              elapsedMs: DateTime.now().difference(started).inMilliseconds,
              steps: 1,
              finishReason: 'no_output',
            )
          : SubAgentOutcome(
              status: SubAgentStatus.ok,
              text: trimmed,
              elapsedMs: DateTime.now().difference(started).inMilliseconds,
              steps: 1,
            );
      return outcome;
    } on TimeoutException {
      outcome = SubAgentOutcome(
        status: SubAgentStatus.timeout,
        error: '子代理超时（${request.effectiveTimeoutMs ~/ 1000}s）',
        elapsedMs: DateTime.now().difference(started).inMilliseconds,
        finishReason: 'timeout',
      );
      return outcome;
    } catch (error) {
      outcome = SubAgentOutcome(
        status: SubAgentStatus.error,
        error: error.toString(),
        elapsedMs: DateTime.now().difference(started).inMilliseconds,
        finishReason: 'error',
      );
      return outcome;
    } finally {
      SubAgentRunMonitor.instance.finish(
        runId,
        status: outcome.status.name,
        error: outcome.error,
      );
      if (!request.bypassConcurrencyGate && scope.isNotEmpty) {
        final left = (_running[scope] ?? 1) - 1;
        if (left <= 0) {
          _running.remove(scope);
        } else {
          _running[scope] = left;
        }
      }
    }
  }
}
