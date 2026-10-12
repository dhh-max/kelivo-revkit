import 'dart:convert';

import '../engine/workflow_engine.dart';
import '../models/workflow_models.dart';
import 'workflow_store.dart';

/// `run_workflow` 工具：让 AI（以及 MCP 面）运行一条已保存的工作流。
///
/// 与子代理同构的两段式：**引擎调用口由应用层注册**（那里才能解析
/// settings/provider 做 AI 生成节点），本类只负责参数解析、清单查询与
/// 结果信封。工作流节点里的 `ai_generate` 走注册进来的 host；`command`
/// 节点在 host 里明确报「未接线」而不是假装执行。
///
/// host 缺失不等于整条工作流不可用：文本/HTTP/条件/提取/延迟/输出这些节点
/// 本来就不需要外部能力，照跑；只有 `ai_generate` 会在执行点报缺模型调用口
/// （纯 MCP 会话就是这种情形，见 [_LocalOnlyWorkflowHost]）。
class WorkflowToolsHandler {
  WorkflowToolsHandler({WorkflowStore? store}) : _store = store ?? WorkflowStore();

  final WorkflowStore _store;

  /// 会话级 host 的容量上限：超出丢最旧（Map 保有插入序）。
  static const int _maxHosts = 8;

  /// 按会话存引擎调用口：注册闭包捕获的是**注册那一刻**的 provider/model/
  /// conversationId。此前只有一个进程级槽位，B 会话（或 MCP 面）调用会拿 A
  /// 的模型生成、把账记在 A 的会话上。
  final Map<String, WorkflowExecutorHost> _hosts =
      <String, WorkflowExecutorHost>{};

  /// 无会话归属（conversationId 为空/空白）的调用口。
  WorkflowExecutorHost? _fallbackHost;

  /// 注册/刷新某个会话的引擎调用口；conversationId 为空时进兜底槽。
  void registerHost(String? conversationId, WorkflowExecutorHost host) {
    final key = conversationId?.trim() ?? '';
    if (key.isEmpty) {
      _fallbackHost = host;
      return;
    }
    // 重新注册 = 刷新到最新一轮装配：先删再加，超限时丢的才是真正最旧的会话。
    _hosts.remove(key);
    if (_hosts.length >= _maxHosts) {
      _hosts.remove(_hosts.keys.first);
    }
    _hosts[key] = host;
  }

  /// 取本会话的调用口；本会话没有就退回兜底槽（仍可能为 null，由 [handle]
  /// 用不依赖外部能力的兜底 host 接住）。
  WorkflowExecutorHost? hostFor(String? conversationId) {
    final key = conversationId?.trim() ?? '';
    if (key.isNotEmpty) {
      final scoped = _hosts[key];
      if (scoped != null) return scoped;
    }
    return _fallbackHost;
  }

  Future<String> handle(
    Map<String, dynamic> args, {
    required String? conversationId,
  }) async {
    final key = (args['workflow'] ?? args['id'] ?? args['name'] ?? '')
        .toString()
        .trim();
    // 2026-10-03 单开关：清单与执行都只看**开着**的条目；关掉的写到
    // disabledWorkflows 里，模型知道「有这条但被用户关了」而不是查无此流。
    final allFlows = await _store.all();
    final flows = allFlows.where((flow) => flow.enabled).toList(growable: false);
    if (key.isEmpty) {
      // 不带参数 = 列清单（模型先看一眼有哪些可用，再决定跑哪条）。
      return jsonEncode(<String, dynamic>{
        'ok': true,
        'workflows': <Map<String, dynamic>>[
          for (final flow in flows)
            <String, dynamic>{
              'id': flow.id,
              'name': flow.name,
              'nodes': flow.nodes.length,
            },
        ],
        // F-55（2026-10-04）：空目录显式说明——过去 `{"workflows":[]}` 加一句
        // 通用提示，读起来像「工具不存在」；实际是用户还没建/没启用工作流。
        if (flows.isEmpty)
          'emptyCatalogNote':
              '当前没有任何已启用的工作流（内置模板已移除，工作流由用户在'
                  '「工作流」页用 AI 生成并按条启用）。如需固化一个常规流程，'
                  '引导用户去工作流页生成；本次调用方按常规能力继续即可。',
        'note':
            'Pass workflow (id or exact name) with optional input to run one of them.',
      });
    }
    final flow = _find(flows, key);
    if (flow == null) {
      final disabled = _find(
        allFlows.where((item) => !item.enabled).toList(growable: false),
        key,
      );
      if (disabled != null) {
        return jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'workflow_disabled',
          'message':
              'Workflow "${disabled.name}" is switched off for chat in the '
              'workflow page. Ask the user to turn it on there.',
          'nextActions': <String>[
            'The user can enable it with the per-workflow switch in the workflow page.',
          ],
        });
      }
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'unknown_workflow',
        'message': 'No workflow matches "$key".',
        'availableWorkflows': <Map<String, dynamic>>[
          for (final item in flows)
            <String, dynamic>{'id': item.id, 'name': item.name},
        ],
      });
    }
    final registered = hostFor(conversationId);
    final input = (args['input'] ?? args['text'] ?? '').toString();
    // 没有注册口也照跑：不需要外部能力的节点引擎自己就能执行完，AI 节点到
    // 执行点才如实报「缺模型调用口」。
    final result = await WorkflowEngine(
      host: registered ?? const _LocalOnlyWorkflowHost(),
    ).run(definition: flow, input: input);
    // 缺模型调用口导致的失败仍回原来的错误码（语义不变），引擎原文放进
    // message：兜底改变的是「还能跑什么」，不是「错误码叫什么」。
    final seamMissing =
        registered == null &&
        (result.error?.contains(_LocalOnlyWorkflowHost.modelSeamMessage) ??
            false);
    return jsonEncode(<String, dynamic>{
      'ok': result.ok,
      'workflow': flow.name,
      'output': result.output,
      if (result.error != null)
        'error': seamMissing ? 'workflow_engine_unavailable' : result.error,
      if (seamMissing) 'message': result.error,
      'steps': result.logs.length,
      if (result.skipped.isNotEmpty)
        'skipped': <Map<String, dynamic>>[
          for (final id in result.skipped)
            <String, dynamic>{
              'id': id,
              'name': <String, String>{
                for (final node in flow.nodes) node.id: node.name,
              }[id] ??
                  id,
            },
        ],
      if (result.cancelled) 'cancelled': true,
      if (result.issues.isNotEmpty)
        'warnings': <Map<String, dynamic>>[
          for (final issue in result.issues)
            if (!issue.fatal) issue.toJson(),
        ],
      'trail': <Map<String, dynamic>>[
        for (final entry in result.logs)
          <String, dynamic>{
            'node': entry.nodeName,
            'type': entry.type.wireName,
            'status': entry.status,
            if (entry.status == 'failed' && entry.error != null)
              'error': entry.error,
          },
      ],
      if (!result.ok)
        'nextActions': <String>[
          if (seamMissing)
            'This call path has no model seam, so AI generate nodes cannot run '
                'here (run that workflow from the app instead); other node '
                'types still work.'
          else
            'Inspect the failed node in trail (prompt / URL / condition '
                'expression) and retry.',
          'Or open this workflow in the workflow page and debug it node by node.',
        ],
    });
  }

  WorkflowDefinition? _find(List<WorkflowDefinition> flows, String key) {
    final wanted = key.toLowerCase();
    for (final flow in flows) {
      if (flow.id.toLowerCase() == wanted ||
          flow.name.toLowerCase() == wanted) {
        return flow;
      }
    }
    return null;
  }

  static const String toolName = 'run_workflow';
}

/// 无 host 兜底：不依赖外部能力的节点照常执行，缺外部能力的节点在**执行点**
/// 如实报错，而不是让整条工作流一刀切成不可用。
class _LocalOnlyWorkflowHost implements WorkflowExecutorHost {
  const _LocalOnlyWorkflowHost();

  /// AI 节点缺模型调用口的消息；[WorkflowToolsHandler.handle] 用它把错误码收敛
  /// 回 `workflow_engine_unavailable`（错误码稳定，不因多了一个兜底而改名）。
  static const String modelSeamMessage =
      'AI generate node needs a model call seam (no provider assembled for this session)';

  /// 没有沙盒会话 → 命令节点由引擎预检拦下（不是跑到那一步才抛）。
  @override
  bool get supportsCommands => false;

  @override
  Future<String> generateText({required String prompt, String? system}) async {
    throw StateError(modelSeamMessage);
  }

  @override
  Future<String> runCommand(String command) async {
    throw StateError(
      'Command node needs a sandbox session (no command runner assembled for '
      'this session)',
    );
  }
}
