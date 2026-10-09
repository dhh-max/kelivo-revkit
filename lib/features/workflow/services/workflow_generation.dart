import 'dart:convert';

import '../../../../core/models/assistant.dart';
import '../../../../core/models/conversation.dart';
import '../../../../core/models/reasoning_request.dart';
import '../../../../core/providers/settings_provider.dart';
import '../../../../core/services/api/chat_api_service.dart';
import '../../../../core/services/api/stream/stream_chunk.dart';
import '../../home/utils/model_display_helper.dart';
import '../engine/workflow_validation.dart';
import '../models/workflow_models.dart';
import 'workflow_generation_stream.dart';
import 'workflow_layout.dart';

/// AI 生成工作流（用户 2026-10-03：内置模板没用，要在工作流页面让 AI 生成）。
///
/// 链路：用户一句需求 → 用当前对话模型按**工作流 DSL 规格**生成 JSON →
/// 提取/解码/静态校验 → 存进 [WorkflowStore]。生成失败给结构化错误，
/// 不写半成品。
abstract final class WorkflowGeneration {
  /// 节点类型与配置键的规格说明（生成提示词与文档共用一份，防止漂移）。
  static String get dslSpec {
    final types = <String>[
      for (final type in WorkflowNodeType.values)
        if (type != WorkflowNodeType.start && type != WorkflowNodeType.end)
          '- ${type.wireName}(${type.defaultName})'
              ' 配置键: ${type.configKeys.isEmpty ? '无' : type.configKeys.join(', ')}'
              ' 输出端口: ${type.outputPorts.join('/')}'
              ' 输入端口: ${type.inputPorts.join('/')}'
              '${type == WorkflowNodeType.condition ? '（true/false 两条出口都要接，或只接需要的并明确省略另一条）' : ''}',
    ].join('\n');
    return '''
节点类型（type 用 wireName）：
$types

配置约定：
- text.text / output.template：正文支持 {{start}} 与 {{节点id}} 占位（引用上游输出）。
- ai_generate.prompt：该步骤的指令；可引用 {{start}} / {{节点id}}。system 可选。
- http_request：url 必填，method 默认 GET，body 仅 POST/PUT。
- condition.expression：对上游文本的判定表达式，按 true/false 选择出口分支；
  上游文本会原样传给下游（判定结果只记在运行日志），条件可以串在主链里做检查。
- extract.pattern：从上游文本提取的正则（第一个捕获组为该节点输出）。
- loop.items：上游输出按行拆分逐项跑子链。
- delay.seconds：数字。
- merge.separator：合并两路输入的分隔符，默认 \\n\\n。

图规则：
- 恰好一个 start（无配置），至少一个 output；边用 nodeId 连接；
- 有向无环；悬空边/自环/端口对不上都会被静态校验拒绝。
- 坐标 x/y 可省略（系统会自动排版）；不要为了布局浪费输出。
''';
  }

  /// 生成提示词：要求**只输出一个 JSON 对象**，便于解析。
  static String buildPrompt(String description) => '''
你要把用户的需求编排成一条工作流（节点图）。只输出一个 JSON 对象，不要解释、不要代码围栏。

$dslSpec
JSON 结构：
{"name":"工作流名(中文，不超过12字)","nodes":[{"id":"n1","type":"start","name":"开始"},{"id":"n2","type":"...","name":"...","config":{...}}],"edges":[{"id":"n1-n2-out","fromNodeId":"n1","fromPort":"out","toNodeId":"n2","toPort":"in"}]}

用户需求：$description''';

  /// 从模型输出里提取工作流定义。容忍代码围栏与前后废话；
  /// 结构或静态校验不过时返回带原因的失败。
  static WorkflowGenerationResult parse(String raw) {
    final jsonText = _extractJson(raw);
    if (jsonText == null) {
      return const WorkflowGenerationResult(
        error: '模型输出里没有找到 JSON 工作流定义',
      );
    }
    Object? decoded;
    try {
      decoded = jsonDecode(jsonText);
    } catch (_) {
      return const WorkflowGenerationResult(error: '工作流 JSON 解析失败');
    }
    if (decoded is! Map) {
      return const WorkflowGenerationResult(error: '工作流 JSON 不是对象');
    }
    // AI 生成的 JSON 不带 id（id 是本机存储语义）：就地补一个。
    // 评审批 P2（2026-10-04）：模型自带 id 或 wf<millis> 撞上已存工作流时，
    // store.save() 按 id 覆盖会静默顶掉用户旧流程——生成用微秒级时间戳降撞
    // 概率，最终兜底在落库点（workflow_list_page 落库前查重换新 id）。
    final map = Map<String, dynamic>.from(decoded);
    map['id'] = 'wf${DateTime.now().microsecondsSinceEpoch}';
    final flow = WorkflowDefinition.fromJson(map);
    if (flow == null || flow.nodes.isEmpty) {
      return const WorkflowGenerationResult(error: '工作流结构不完整（缺 nodes）');
    }
    final cleaned = sanitize(flow);
    final validation = validateWorkflow(cleaned);
    if (!validation.ok) {
      return WorkflowGenerationResult(
        error: '生成的工作流没有通过校验：${validation.fatalMessage}',
      );
    }
    return WorkflowGenerationResult(flow: cleaned, warnings: validation.warnings);
  }

  /// 结构清理（AI 产出的常见小毛病，全在解析层兜住，不进画布/引擎）：
  /// - 重复节点 id（保留第一个）；
  /// - 悬挂边（两端节点必须都在）与重复边（同源同端口同目标）；
  /// - 坐标不可用（多个节点重叠/全 0）时按有向图分层自动排布。
  static WorkflowDefinition sanitize(WorkflowDefinition flow) {
    final nodes = <WorkflowNode>[];
    final seenIds = <String>{};
    for (final node in flow.nodes) {
      if (seenIds.add(node.id)) nodes.add(node);
    }
    final edges = <WorkflowEdge>[];
    final seenEdges = <String>{};
    for (final edge in flow.edges) {
      if (!seenIds.contains(edge.fromNodeId) ||
          !seenIds.contains(edge.toNodeId)) {
        continue;
      }
      final key =
          '${edge.fromNodeId}|${edge.fromPort}|${edge.toNodeId}|${edge.toPort}';
      if (seenEdges.add(key)) edges.add(edge);
    }
    final cleaned = flow.copyWith(nodes: nodes, edges: edges);
    if (WorkflowLayout.needsLayout(cleaned)) {
      return WorkflowLayout.apply(cleaned);
    }
    return cleaned;
  }

  /// 调当前对话模型生成一条工作流（不落库——落库由调用方决定）。
  static Future<WorkflowGenerationResult> generate({
    required String description,
    required SettingsProvider settings,
    Conversation? conversation,
    Assistant? assistant,
  }) async {
    WorkflowDoneEvent? done;
    await for (final event in stream(
      description: description,
      settings: settings,
      conversation: conversation,
      assistant: assistant,
    )) {
      if (event is WorkflowDoneEvent) done = event;
    }
    return WorkflowGenerationResult(
      flow: done?.flow,
      error: done?.error,
      warnings: done?.warnings ?? const <WorkflowIssue>[],
    );
  }

  /// 流式生成：边收边解析（节点/连线实时上画布），终态事件给权威结果。
  ///
  /// 2026-10-04 真机反馈「生成要等半天 / 想直接在画布上实时看到」——与
  /// [generate] 的区别：
  /// - 走 `stream: true`：首字即可见，不再等整段 JSON 生成完；
  /// - `textOnly`：禁掉图片路由与内置工具注入（utility 生成不该多一轮搜索）；
  /// - [WorkflowStreamParser] 增量解析只管「先显示」，最终仍以完整文本的
  ///   [parse] 为准（坏输出不会被半截数据掩盖）。
  static Stream<WorkflowGenerationEvent> stream({
    required String description,
    required SettingsProvider settings,
    Conversation? conversation,
    Assistant? assistant,
    String? requestId,
  }) async* {
    final model = resolveChatModel(
      settings,
      conversation: conversation,
      assistant: assistant,
    );
    final providerKey = model.providerKey;
    final modelId = model.modelId;
    if (providerKey == null ||
        providerKey.isEmpty ||
        modelId == null ||
        modelId.isEmpty) {
      yield const WorkflowDoneEvent(error: '当前没有可用的对话模型');
      return;
    }
    final config = settings.getProviderConfig(providerKey);
    final parser = WorkflowStreamParser();
    final buffer = StringBuffer();
    try {
      await for (final chunk in ChatApiService.sendMessageStream(
        config: config,
        modelId: modelId,
        messages: <Map<String, dynamic>>[
          {'role': 'user', 'content': buildPrompt(description)},
        ],
        stream: true,
        textOnly: true,
        // 结构化输出任务默认**关思考**（与标题/摘要/压缩等工具任务的既定口径
        // 一致——它们的开关默认也是关）。带思考的模型在生成 5-6 节点 JSON 前
        // 会先烧一大段推理 token，这是「生成速率慢」的主因之一；DSL 规格在
        // 提示词里已写全，关思考不影响结构正确性，流的实时上屏也不受影响。
        reasoning: ReasoningRequest.off,
        skipImageParsing: true,
        allowImagesApiRouting: false,
        requestId: requestId,
      )) {
        if (chunk is TextDelta) {
          buffer.write(chunk.text);
          for (final event in parser.feed(chunk.text)) {
            yield event;
          }
        } else if (chunk is RetryPending) {
          yield WorkflowProgressEvent(
            '网络波动，正在重试（${chunk.attempt}/${chunk.maxRetries}）…',
          );
        }
      }
    } catch (error) {
      yield WorkflowDoneEvent(error: '生成失败：$error');
      return;
    }
    final result = parse(buffer.toString());
    yield WorkflowDoneEvent(
      flow: result.flow,
      error: result.error,
      warnings: result.warnings,
    );
  }

  /// 提取第一段平衡的 JSON 对象文本（容忍 ```json 围栏与前后说明文字）。
  static String? _extractJson(String raw) {
    var text = raw.trim();
    final fence = RegExp(r'```(?:json)?\s*([\s\S]*?)```').firstMatch(text);
    if (fence != null) text = fence.group(1)!.trim();
    final begin = text.indexOf('{');
    if (begin < 0) return null;
    var depth = 0;
    var inString = false;
    var escaped = false;
    for (var i = begin; i < text.length; i++) {
      final ch = text[i];
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (ch == '\\') {
          escaped = true;
        } else if (ch == '"') {
          inString = false;
        }
        continue;
      }
      if (ch == '"') {
        inString = true;
      } else if (ch == '{') {
        depth++;
      } else if (ch == '}') {
        depth--;
        if (depth == 0) return text.substring(begin, i + 1);
      }
    }
    return null;
  }
}

/// 一次生成的结果：成功带定义（+非致命告警），失败带可读原因。
class WorkflowGenerationResult {
  const WorkflowGenerationResult({this.flow, this.error, this.warnings = const []});

  final WorkflowDefinition? flow;

  /// 失败原因（flow == null 时必有）。
  final String? error;

  /// 静态校验的非致命告警（照常可用，但值得提示）。
  final List<WorkflowIssue> warnings;

  bool get ok => flow != null;
}
