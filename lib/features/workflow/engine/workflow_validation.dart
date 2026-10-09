import '../models/workflow_models.dart';

/// 工作流静态校验（运行前预检）。
///
/// 与引擎同源放在 engine/ 下：编辑器「运行」前、`run_workflow` 工具被调用时、
/// 以及测试都吃这一套判据——问题在跑之前就变成结构化清单，而不是跑到一半
/// 才炸在某个节点上。
///
/// 两级判据：
/// - **fatal**：拒绝运行（空图 / 缺开始节点 / 悬空边 / 端口对不上 / 自环 /
///   成环 / 命令节点且当前环境没接线）；
/// - **warning**：照跑，但编辑器要在运行面板里提示（条件分支没接出口、
///   节点缺必填配置、不可达节点、多个开始节点）。
class WorkflowIssue {
  const WorkflowIssue({
    required this.code,
    required this.message,
    this.nodeId,
    this.fatal = false,
  });

  /// 稳定错误码（工具面按码分流，不解析文案）。
  final String code;

  /// 面向人的说明（UI 直接显示；引擎的致命错误也用这几条拼）。
  final String message;

  /// 出问题的节点（图级问题为 null）。
  final String? nodeId;

  final bool fatal;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'code': code,
        'message': message,
        if (nodeId != null) 'nodeId': nodeId,
        'fatal': fatal,
      };
}

class WorkflowValidationResult {
  const WorkflowValidationResult(this.issues);

  final List<WorkflowIssue> issues;

  /// 没有 fatal 问题即可运行。
  bool get ok => !issues.any((issue) => issue.fatal);

  List<WorkflowIssue> get fatalIssues =>
      <WorkflowIssue>[for (final issue in issues) if (issue.fatal) issue];

  List<WorkflowIssue> get warnings =>
      <WorkflowIssue>[for (final issue in issues) if (!issue.fatal) issue];

  /// 致命问题的合并文案（引擎 result.error 与工具面 message 共用）。
  String? get fatalMessage {
    final fatal = fatalIssues;
    if (fatal.isEmpty) return null;
    return fatal.map((issue) => issue.message).join('；');
  }
}

/// 节点类型必填的配置键（缺失只告警：引擎多数节点有兜底语义，但用户多半是
/// 忘了填）。
const Map<WorkflowNodeType, String> _requiredConfigKey =
    <WorkflowNodeType, String>{
  WorkflowNodeType.text: 'text',
  WorkflowNodeType.aiGenerate: 'prompt',
  WorkflowNodeType.httpRequest: 'url',
  WorkflowNodeType.extract: 'pattern',
};

/// 校验一条工作流。[supportsCommands] 由宿主给出：App 侧沙盒未接线时为 false，
/// 此时图里的命令节点是 fatal，而不是跑到那个节点才抛异常。
WorkflowValidationResult validateWorkflow(
  WorkflowDefinition definition, {
  bool supportsCommands = false,
}) {
  final issues = <WorkflowIssue>[];

  if (definition.nodes.isEmpty) {
    return const WorkflowValidationResult(<WorkflowIssue>[
      WorkflowIssue(
        code: 'empty_graph',
        message: '工作流里没有任何节点',
        fatal: true,
      ),
    ]);
  }

  final nodesById = <String, WorkflowNode>{};
  final duplicateIds = <String>{};
  for (final node in definition.nodes) {
    if (nodesById.containsKey(node.id)) {
      duplicateIds.add(node.id);
    } else {
      nodesById[node.id] = node;
    }
  }
  for (final id in duplicateIds) {
    issues.add(WorkflowIssue(
      code: 'duplicate_node_id',
      message: '节点 id 重复：$id',
      nodeId: id,
      fatal: true,
    ));
  }

  final starts = <WorkflowNode>[
    for (final node in definition.nodes)
      if (node.type == WorkflowNodeType.start) node,
  ];
  if (starts.isEmpty) {
    issues.add(const WorkflowIssue(
      code: 'missing_start',
      message: '工作流缺少「开始」节点',
      fatal: true,
    ));
  } else if (starts.length > 1) {
    issues.add(WorkflowIssue(
      code: 'multiple_start',
      message: '有 ${starts.length} 个「开始」节点，它们会各跑一条链',
      nodeId: starts.first.id,
    ));
  }

  final outgoing = <String, List<WorkflowEdge>>{};
  final incoming = <String, List<WorkflowEdge>>{};
  for (final edge in definition.edges) {
    final from = nodesById[edge.fromNodeId];
    final to = nodesById[edge.toNodeId];
    if (from == null || to == null) {
      issues.add(WorkflowIssue(
        code: 'edge_unknown_node',
        message: '连线 ${edge.id} 指向了不存在的节点'
            '（${from == null ? edge.fromNodeId : edge.toNodeId}）',
        nodeId: from == null ? edge.toNodeId : edge.fromNodeId,
        fatal: true,
      ));
      continue;
    }
    if (edge.fromNodeId == edge.toNodeId) {
      issues.add(WorkflowIssue(
        code: 'self_edge',
        message: '连线 ${edge.id} 把「${from.name}」连到了自己',
        nodeId: from.id,
        fatal: true,
      ));
      continue;
    }
    if (!from.type.outputPorts.contains(edge.fromPort)) {
      issues.add(WorkflowIssue(
        code: 'edge_unknown_port',
        message: '「${from.name}」没有输出端口 ${edge.fromPort}',
        nodeId: from.id,
        fatal: true,
      ));
      continue;
    }
    if (!to.type.inputPorts.contains(edge.toPort)) {
      issues.add(WorkflowIssue(
        code: 'edge_unknown_port',
        message: '「${to.name}」没有输入端口 ${edge.toPort}',
        nodeId: to.id,
        fatal: true,
      ));
      continue;
    }
    (outgoing[edge.fromNodeId] ??= <WorkflowEdge>[]).add(edge);
    (incoming[edge.toNodeId] ??= <WorkflowEdge>[]).add(edge);
  }

  // 成环：依赖驱动执行下，环上的节点永远等不到输入齐，必须提前拒绝
  // （不能像 v1 那样静默跳过）。
  final visiting = <String>{};
  final done = <String>{};
  var hasCycle = false;
  void visit(String id) {
    if (hasCycle || done.contains(id)) return;
    if (!visiting.add(id)) {
      hasCycle = true;
      final node = nodesById[id];
      issues.add(WorkflowIssue(
        code: 'cycle',
        message: '工作流里存在环：${node?.name ?? id} 回到了自己',
        nodeId: id,
        fatal: true,
      ));
      return;
    }
    for (final edge in outgoing[id] ?? const <WorkflowEdge>[]) {
      visit(edge.toNodeId);
    }
    visiting.remove(id);
    done.add(id);
  }

  for (final start in starts) {
    visit(start.id);
  }

  // 可达性：只有从「开始」节点走得到的节点才会被执行。
  final reachable = <String>{};
  final queue = <String>[for (final start in starts) start.id];
  while (queue.isNotEmpty) {
    final id = queue.removeLast();
    if (!reachable.add(id)) continue;
    for (final edge in outgoing[id] ?? const <WorkflowEdge>[]) {
      queue.add(edge.toNodeId);
    }
  }

  for (final node in definition.nodes) {
    if (!reachable.contains(node.id)) {
      issues.add(WorkflowIssue(
        code: 'unreachable_node',
        message: '「${node.name}」从开始节点走不到，运行时不会执行',
        nodeId: node.id,
      ));
      continue;
    }
    if (node.type == WorkflowNodeType.command && !supportsCommands) {
      issues.add(WorkflowIssue(
        code: 'command_not_wired',
        message: '「${node.name}」是命令节点，需要沙盒环境（当前环境未接线）',
        nodeId: node.id,
        fatal: true,
      ));
    }
    if (node.type == WorkflowNodeType.condition) {
      final branches = <String>{
        for (final edge in outgoing[node.id] ?? const <WorkflowEdge>[])
          edge.fromPort,
      };
      if (!branches.contains('true') && !branches.contains('false')) {
        issues.add(WorkflowIssue(
          code: 'condition_no_branch',
          message: '条件节点「${node.name}」的 true/false 出口都没接，走到这里就断了',
          nodeId: node.id,
        ));
      }
    }
    final requiredKey = _requiredConfigKey[node.type];
    if (requiredKey != null) {
      final value = node.config[requiredKey]?.toString().trim() ?? '';
      if (value.isEmpty) {
        issues.add(WorkflowIssue(
          code: 'missing_config',
          message: '「${node.name}」还没填「$requiredKey」',
          nodeId: node.id,
        ));
      }
    }
  }

  return WorkflowValidationResult(issues);
}
