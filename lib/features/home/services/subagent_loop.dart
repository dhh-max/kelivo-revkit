import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../../../core/services/local_tools/local_tool_names.dart';
import 'session_mode.dart';
import 'subagent_registry.dart';

/// 子代理一次运行的结局。
enum SubAgentStatus { ok, timeout, error, unavailable, cancelled }

/// 子代理循环里的一个工具调用（从模型回包里解析出来）。
class SubAgentToolCall {
  const SubAgentToolCall({required this.id, required this.name, required this.arguments});

  final String id;
  final String name;
  final Map<String, dynamic> arguments;

  static Map<String, dynamic> asArguments(Object? raw) {
    if (raw is Map) return Map<String, dynamic>.from(raw);
    if (raw is String && raw.trim().isNotEmpty) {
      try {
        final decoded = jsonDecode(raw);
        if (decoded is Map) return Map<String, dynamic>.from(decoded);
      } catch (_) {
        // 参数不是合法 JSON 时按空表处理，交给工具自己的参数校验报错。
      }
    }
    return <String, dynamic>{};
  }
}

/// 子代理对话历史的一条记录（监看弹窗的数据源）。
///
/// 用户 2026-10-01：「我要看到它的思考内容、它的对话历史之类的，现在的
/// 都是静默的。」assistant 条目 = 一步模型输出（思考 + 文本 + 工具调用）；
/// tool 条目 = 一次工具执行（名字 + 参数 + 结果）。循环逐步回传给监看器，
/// 跑完也不丢（监看器保留最近若干条运行记录供展开回看）。
class SubAgentTranscriptEntry {
  const SubAgentTranscriptEntry._({
    required this.role,
    this.text = '',
    this.reasoning = '',
    this.toolCalls = const <SubAgentToolCall>[],
    this.toolName = '',
    this.args = const <String, dynamic>{},
    this.result = '',
  });

  factory SubAgentTranscriptEntry.assistant({
    String text = '',
    String reasoning = '',
    List<SubAgentToolCall> toolCalls = const <SubAgentToolCall>[],
  }) =>
      SubAgentTranscriptEntry._(
        role: 'assistant',
        text: text,
        reasoning: reasoning,
        toolCalls: toolCalls,
      );

  factory SubAgentTranscriptEntry.tool({
    required String name,
    Map<String, dynamic> args = const <String, dynamic>{},
    String result = '',
  }) =>
      SubAgentTranscriptEntry._(
        role: 'tool',
        toolName: name,
        args: args,
        result: result,
      );

  /// 'assistant' | 'tool'。
  final String role;
  final String text;
  final String reasoning;
  final List<SubAgentToolCall> toolCalls;
  final String toolName;
  final Map<String, dynamic> args;
  final String result;
}

/// 一步模型输出：要么是最终文本，要么是一批工具调用。
class SubAgentStep {
  const SubAgentStep({
    this.text = '',
    this.reasoning = '',
    this.toolCalls = const <SubAgentToolCall>[],
  });

  final String text;

  /// 模型的思考内容（reasoning parts 拼接；展开弹窗要用——用户 2026-10-01
  /// 点名「我要看到它的思考内容、它的对话历史，现在的都是静默的」）。
  final String reasoning;

  final List<SubAgentToolCall> toolCalls;

  bool get hasToolCalls => toolCalls.isNotEmpty;

  /// 从 message parts 里抽出思考、文本与工具调用。
  ///
  /// ToolCallPart 的 payload 形状见 StreamChunkHandler：
  /// `{id, name, arguments, content, server, metadata}`。
  static SubAgentStep fromParts(List<dynamic> parts) {
    final buffer = StringBuffer();
    final reasoning = StringBuffer();
    final calls = <SubAgentToolCall>[];
    for (final part in parts) {
      final kind = (part as dynamic).kind?.toString();
      if (kind == 'tool_call') {
        final payload = _decode((part as dynamic).payloadJson?.toString() ?? '');
        if (payload == null) continue;
        final name = payload['name']?.toString().trim() ?? '';
        if (name.isEmpty) continue;
        calls.add(SubAgentToolCall(
          id: payload['id']?.toString() ?? 'call_${calls.length}',
          name: name,
          arguments: SubAgentToolCall.asArguments(payload['arguments']),
        ));
      } else if (kind == 'text') {
        final text = (part as dynamic).text?.toString() ?? '';
        if (text.isNotEmpty) buffer.write(text);
      } else if (kind == 'reasoning') {
        final piece = (part as dynamic).text?.toString() ?? '';
        if (piece.isNotEmpty) reasoning.write(piece);
      }
    }
    return SubAgentStep(
      text: buffer.toString().trim(),
      reasoning: reasoning.toString().trim(),
      toolCalls: calls,
    );
  }

  static Map<String, dynamic>? _decode(String raw) {
    if (raw.trim().isEmpty) return null;
    try {
      final decoded = jsonDecode(raw);
      return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
    } catch (_) {
      return null;
    }
  }
}

/// 循环驱动：模型一步 + 执行一个工具。
///
/// 由应用层注入（那里才有 provider/settings 与工具分发的上下文），
/// 单测里用假的实现即可完整验证循环语义。
class SubAgentLoopDriver {
  const SubAgentLoopDriver({
    required this.step,
    required this.invokeTool,
    this.definitionFor,
    this.allowedToolIds,
  });

  /// 走一次模型（带 tools）；返回文本或工具调用。
  final Future<SubAgentStep> Function({
    required List<Map<String, dynamic>> messages,
    required List<Map<String, dynamic>> tools,
  }) step;

  /// 执行一个工具，返回工具结果（JSON 字符串或纯文本）。
  ///
  /// 调用期间 [SubAgentDispatchScope] 里带着**派发这次子代理的会话 id**：
  /// 嵌套工具调用必须按它走，否则子代理里的写类工具查不到 /goal 免审批、
  /// todo 工具报 conversation_required、按会话取消也失效——2026-09-29
  /// 真机复现的根因就在这条链上（会话上下文只在注册驱动时带一次不够，
  /// 派发点自己知道得最准）。用 Zone 而不是加参数：不破坏既有驱动实现与单测。
  final Future<String> Function(String name, Map<String, dynamic> args) invokeTool;

  /// 取某个工具的定义（schema）。缺失时该工具不声明给子代理。
  final Map<String, dynamic>? Function(String name)? definitionFor;

  /// 派发方（当前助手）自己声明的工具集：子代理的工具面取它与类别的交集。
  ///
  /// 各司其职的**能力**保证——开发助手的子代理拿不到 APK 工具，反之亦然。
  /// null = 不做这一层过滤（MCP 等没有助手上下文的面）。
  final Set<String>? allowedToolIds;
}

class SubAgentLoopResult {
  const SubAgentLoopResult({
    required this.status,
    this.text = '',
    this.error,
    this.steps = 0,
    this.transcript = const <SubAgentToolCall>[],
    this.finishReason = 'completed',
  });

  final SubAgentStatus status;
  final String text;
  final String? error;
  final int steps;
  final List<SubAgentToolCall> transcript;

  /// 收口原因（2026-10-01 真机实测 B2：返回体没有任何「提前退出/未收敛」
  /// 信号，调用方只能自己拼启发式判据）：
  /// completed / max_steps / max_tool_calls / timeout / cancelled / error。
  final String finishReason;

  /// 预算/步数触顶导致的**截断**（不是任务失败，也不是正常完成）。
  ///
  /// 报告 2-17：`maxToolCalls` 触顶过去返回 `status ok + text ''`——上层看到成功
  /// 却拿不到结论，只能靠 finishReason 猜。现在截断有独立信号，且**没有结论时
  /// 不算成功**（`ok`），与 `maxSteps` 的口径一致。
  bool get truncated =>
      finishReason == 'max_tool_calls' || finishReason == 'max_steps';

  /// 有结论才算成功；截断且无文本 → 不算成功（调用方据此走补跑/换策略）。
  bool get ok =>
      status == SubAgentStatus.ok && !(truncated && text.trim().isEmpty);
}

/// 跑一条子代理循环。
///
/// 与主循环的差别（有意收窄）：
///  - 可用工具由 [SubAgentRegistry.toolNamesFor] 按类别算出，未授予的调用直接
///    拒绝并回结构化结果（不是悄悄丢掉）；
///  - 变更类工具只在 /goal（免审批的目标模式）下放行——子代理在后台
///    跑，没有 UI 可以弹审批，宁可拒绝也不要挂住；
///  - 步数上限 = 子代理定义的 maxSteps，整体超时 = timeoutMs（每步吃剩余时间）；
///  - [isCancelled] 每次发模型请求前与每次执行工具前都会问一次：用户中止后
///    循环在最近的步骤边界收口，返回 [SubAgentStatus.cancelled]。
Future<SubAgentLoopResult> runSubAgentLoop({
  required SubAgentLoopDriver driver,
  required Set<SubAgentCategory> categories,
  required int maxSteps,
  required int timeoutMs,
  required String systemPrompt,
  required String userPrompt,
  /// 该角色启用的技能（SubAgentDefinition.enabledSkills）：非空且技能工具
  /// 真的授予了，才在系统提示里点名「先用哪个工具读技能」——不点名没挂上的调用。
  Set<String> skills = const <String>{},
  /// 工具调用总数上限（0 = 不限）。真机实测 C2：这个参数此前完全没实现，
  /// 模型可以一路深挖到步数上限。
  int maxToolCalls = 0,
  /// 派发它的会话：会话模式（/goal 免审批）按会话查，没有 id 就按 build 处理。
  String? conversationId,
  /// 用户是否已请求中止（监看面板 / 会话级停止写入）。
  bool Function()? isCancelled,
  void Function(String stage)? onStage,
  /// 对话历史逐步回传（监看弹窗渲染「思考内容 / 对话历史」的数据源）。
  /// assistant 步在模型回包后记，tool 步在每个工具执行后记。
  void Function(SubAgentTranscriptEntry entry)? onTranscript,
}) async {
  // 本层的嵌套深度：循环在 SubAgentRunner 里被放进 SubAgentDepth.run(depth)，
  // 所以这里读到的就是「我是第几层」。工具面据此摘掉 subagent（到上限就不再
  // 授予），与 SubAgentToolHandler 的入口闸门读同一个值。
  final depth = SubAgentDepth.current;
  final granted = SubAgentRegistry.toolNamesFor(
    categories,
    allowed: driver.allowedToolIds,
    skills: skills,
    depth: depth,
  );
  final tools = <Map<String, dynamic>>[];
  for (final name in granted) {
    final definition = driver.definitionFor?.call(name);
    if (definition != null) tools.add(definition);
  }
  final messages = <Map<String, dynamic>>[
    <String, dynamic>{
      'role': 'system',
      'content': _withSkillHint(systemPrompt, skills, granted),
    },
    <String, dynamic>{'role': 'user', 'content': userPrompt},
  ];
  final transcript = <SubAgentToolCall>[];
  final deadline = DateTime.now().add(Duration(milliseconds: timeoutMs));
  var steps = 0;
  var toolCallCount = 0;
  // 非正常终局（超时/中止/预算用尽）也要把**已产出的中间文本**交出去
  // （2026-10-03 报告 F-08：超时回执 text 缺失＝失败即全损，23 步白跑）。
  final partialText = StringBuffer();
  void collectPartial(String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return;
    if (partialText.isNotEmpty) partialText.write('\n\n');
    partialText.write(trimmed);
  }
  // 用户中止时的统一收口：带上已跑步数、已执行的工具与部分结论。
  SubAgentLoopResult cancelledResult() => SubAgentLoopResult(
        status: SubAgentStatus.cancelled,
        text: partialText.toString(),
        error: '用户已中止这次子代理运行（已跑 $steps 步）',
        steps: steps,
        transcript: transcript,
        finishReason: 'cancelled',
      );
  try {
    while (steps < maxSteps) {
      // 中止优先于超时/步数判定：在步骤边界收口，不再发下一次模型请求。
      if (isCancelled?.call() ?? false) return cancelledResult();
      final remaining = deadline.difference(DateTime.now());
      if (remaining.isNegative || remaining == Duration.zero) {
        return SubAgentLoopResult(
          status: SubAgentStatus.timeout,
          text: partialText.toString(),
          // 机读码在信封层给（SUBAGENT_TIMEOUT）；这里只留人读文案。
          error: '子代理超时（${timeoutMs ~/ 1000}s，已跑 $steps 步）',
          steps: steps,
          transcript: transcript,
          finishReason: 'timeout',
        );
      }
      // 工具调用预算（C2）：到顶就收口，不再执行新工具——先把已有结论交出去。
      if (maxToolCalls > 0 && toolCallCount >= maxToolCalls) {
        return SubAgentLoopResult(
          // 截断不是失败，但**也不等于成功**：这里保持 ok 状态 + 空文本，
          // 由 SubAgentLoopResult.ok getter 判定为「未成功（截断无结论）」。
          status: SubAgentStatus.ok,
          text: '',
          error: '工具调用已达上限（$maxToolCalls 次，已跑 $steps 步）',
          steps: steps,
          transcript: transcript,
          finishReason: 'max_tool_calls',
        );
      }
      steps++;
      onStage?.call('step $steps/$maxSteps');
      final step = await driver
          .step(messages: messages, tools: tools)
          .timeout(remaining);
      if (!step.hasToolCalls) {
        onTranscript?.call(
          SubAgentTranscriptEntry.assistant(
            text: step.text,
            reasoning: step.reasoning,
          ),
        );
        return SubAgentLoopResult(
          status: SubAgentStatus.ok,
          text: step.text,
          steps: steps,
          transcript: transcript,
          finishReason: 'completed',
        );
      }
      onTranscript?.call(
        SubAgentTranscriptEntry.assistant(
          text: step.text,
          reasoning: step.reasoning,
          toolCalls: step.toolCalls,
        ),
      );
      // 带工具调用的中间步骤文本：非正常终局时要交出去（部分结论）。
      collectPartial(step.text);
      messages.add(<String, dynamic>{
        'role': 'assistant',
        'content': step.text,
        'tool_calls': <Map<String, dynamic>>[
          for (final call in step.toolCalls)
            <String, dynamic>{
              'id': call.id,
              'type': 'function',
              'function': <String, dynamic>{
                'name': call.name,
                'arguments': jsonEncode(call.arguments),
              },
            },
        ],
      });
      for (final call in step.toolCalls) {
        // 一批工具可能有好几个：每执行一个之前再问一次，未执行的调用不进 transcript。
        if (isCancelled?.call() ?? false) return cancelledResult();
        transcript.add(call);
        toolCallCount++;
        final result = await _runTool(
          driver,
          granted,
          categories,
          call,
          conversationId,
        );
        onTranscript?.call(
          SubAgentTranscriptEntry.tool(
            name: call.name,
            args: call.arguments,
            result: result,
          ),
        );
        // 形状按我们 OpenAI 兼容层的要求（chat_completions_api._sanitizeMessages）：
        // 只保留 role/tool_call_id/content。tool 消息带 name 会被严格网关
        // （OpenCode Zen / Command Code）整条拒收，且我们的层本来也会剥掉它。
        messages.add(<String, dynamic>{
          'role': 'tool',
          'tool_call_id': call.id,
          'content': result,
        });
      }
    }
    return SubAgentLoopResult(
      status: SubAgentStatus.error,
      text: partialText.toString(),
      error: '子代理达到步数上限（$maxSteps），没有给出结论',
      steps: steps,
      transcript: transcript,
      finishReason: 'max_steps',
    );
  } on TimeoutException {
    return SubAgentLoopResult(
      status: SubAgentStatus.timeout,
      text: partialText.toString(),
      error: '子代理超时（${timeoutMs ~/ 1000}s，已跑 $steps 步）',
      steps: steps,
      transcript: transcript,
      finishReason: 'timeout',
    );
  } catch (error) {
    return SubAgentLoopResult(
      status: SubAgentStatus.error,
      error: error.toString(),
      steps: steps,
      transcript: transcript,
      finishReason: 'error',
    );
  }
}

/// 技能提示段：只在技能工具**真的授予了**的时候点名它们（判据 19/63：
/// 说给模型的调用名必须真存在）。技能是提示词级工作流，子代理要么读得到，
/// 要么就不该被承诺「你启用了这些技能」。
String _withSkillHint(
  String systemPrompt,
  Set<String> skills,
  Set<String> granted,
) {
  if (skills.isEmpty) return systemPrompt;
  final readers = <String>[
    if (granted.contains(LocalToolNames.apkSkill)) 'get_solab_skill',
    if (granted.contains(LocalToolNames.installedSkills))
      'get_installed_skills',
  ];
  if (readers.isEmpty) return systemPrompt;
  final list = (skills.toList()..sort()).join('、');
  final readerText = readers.join(' 或 ');
  return '$systemPrompt\n\n本角色启用的技能：$list。'
      '开始动手前先用 $readerText 读取对应技能，按它的步骤做；'
      '技能只是工作流建议，不能越过只读/写范围与审批边界。';
}

Future<String> _runTool(
  SubAgentLoopDriver driver,
  Set<String> granted,
  Set<SubAgentCategory> categories,
  SubAgentToolCall call,
  String? conversationId,
) async {
  if (!granted.contains(call.name)) {
    return jsonEncode(<String, dynamic>{
      'ok': false,
      'error': 'tool_not_granted',
      'message': '子代理没有 ${call.name} 的工具权限（可用：'
          '${(granted.toList()..sort()).join(', ')}）。'
          '需要的工具请让主代理直接调用。',
    });
  }
  // `file` 一个工具同时承载读类与写类动作（类别只到工具名粒度），
  // 所以这里按动作再拦一次：只读子代理不许借 file 落盘。
  if (!categories.contains(SubAgentCategory.write) &&
      SubAgentRegistry.isWriteAction(call.name, call.arguments)) {
    return jsonEncode(<String, dynamic>{
      'ok': false,
      'error': 'subagent_readonly_write_blocked',
      'message': '这个子代理是只读的：${call.name}('
          '${call.arguments['action']}) 属写类动作，已拒绝。'
          '要么把它改成读类动作（read/list/grep…），要么由主代理来改。',
    });
  }
  if (kMutatingToolNames.contains(call.name) &&
      !SessionModeRuntime.policyFor(conversationId).bypassesApproval) {
    return jsonEncode(<String, dynamic>{
      'ok': false,
      'error': 'subagent_write_requires_mode',
      'message': '子代理在后台没有审批界面：$call.name 属变更类工具，'
          '当前会话模式不允许免审批执行。请让主代理执行这一步，'
          '或先用 /goal <目标> 切到免审批的目标模式。',
    });
  }
  try {
    final result = await SubAgentDispatchScope.run(
      conversationId,
      () => driver.invokeTool(call.name, call.arguments),
    );
    return result.trim().isEmpty ? '{"ok":true}' : result;
  } catch (error) {
    debugPrint('subagent tool failed: $error');
    return jsonEncode(<String, dynamic>{
      'ok': false,
      'error': 'tool_failed',
      'message': error.toString(),
    });
  }
}
