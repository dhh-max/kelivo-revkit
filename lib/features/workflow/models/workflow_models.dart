import 'dart:convert';
import 'dart:ui';

/// 工作流节点类型（对齐 n8n / Dify 一类节点的最小可用集）。
///
/// `wireName` 是持久化与执行引擎共用的稳定标识；改名不许动它。
///
/// 模型层只放**数据**：界面文案（类型名/说明/字段标签）在
/// `pages/workflow_labels.dart` 里走 l10n，别在这里塞中文 UI 文案。
enum WorkflowNodeType {
  start('start', '开始'),
  text('text', '文本'),
  aiGenerate('ai_generate', 'AI 生成'),
  command('command', '命令'),
  httpRequest('http_request', 'HTTP 请求'),
  condition('condition', '条件分支'),
  loop('loop', '循环'),
  merge('merge', '汇聚'),
  extract('extract', '提取'),
  delay('delay', '延迟'),
  output('output', '输出'),
  end('end', '结束');

  const WorkflowNodeType(this.wireName, this.defaultName);

  final String wireName;

  /// 数据层兜底名：新建节点/JSON 缺 name 时写进用户数据的默认名，
  /// **不随界面语言变化**（它已经落进 prefs，跟着语言变会让历史数据漂移）。
  final String defaultName;

  /// 该类型可编辑的配置键（顺序即配置面板里的顺序）。
  List<String> get configKeys => switch (this) {
        WorkflowNodeType.text => const <String>['text'],
        WorkflowNodeType.aiGenerate => const <String>['prompt', 'system'],
        WorkflowNodeType.command => const <String>['command'],
        WorkflowNodeType.httpRequest => const <String>['url', 'method', 'body'],
        WorkflowNodeType.condition => const <String>['expression'],
        WorkflowNodeType.loop => const <String>['items'],
        WorkflowNodeType.extract => const <String>['pattern'],
        WorkflowNodeType.delay => const <String>['seconds'],
        WorkflowNodeType.output => const <String>['template'],
        WorkflowNodeType.merge => const <String>['separator'],
        WorkflowNodeType.start || WorkflowNodeType.end => const <String>[],
      };

  static WorkflowNodeType? fromWire(String? value) {
    for (final type in WorkflowNodeType.values) {
      if (type.wireName == value || type.name == value) return type;
    }
    return null;
  }

  /// 该类型是否可以有多个输入/输出端口（条件分支有两个输出）。
  List<String> get outputPorts => switch (this) {
        WorkflowNodeType.condition => const <String>['true', 'false'],
        WorkflowNodeType.end => const <String>[],
        _ => const <String>['out'],
      };

  List<String> get inputPorts => switch (this) {
        WorkflowNodeType.start => const <String>[],
        WorkflowNodeType.merge => const <String>['a', 'b'],
        _ => const <String>['in'],
      };
}

/// 工作流里的一个节点。
class WorkflowNode {
  const WorkflowNode({
    required this.id,
    required this.type,
    required this.name,
    this.config = const <String, dynamic>{},
    this.position = Offset.zero,
  });

  final String id;
  final WorkflowNodeType type;
  final String name;

  /// 该类型自己的配置（文本内容 / 提示词 / 命令 / URL / 条件表达式…）。
  final Map<String, dynamic> config;

  /// 画布坐标（持久化用）。
  final Offset position;

  WorkflowNode copyWith({
    String? name,
    Map<String, dynamic>? config,
    Offset? position,
  }) =>
      WorkflowNode(
        id: id,
        type: type,
        name: name ?? this.name,
        config: config ?? this.config,
        position: position ?? this.position,
      );

  Map<String, dynamic> toJson() => <String, dynamic>{
        'id': id,
        'type': type.wireName,
        'name': name,
        if (config.isNotEmpty) 'config': config,
        'x': position.dx,
        'y': position.dy,
      };

  static WorkflowNode? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id']?.toString().trim() ?? '';
    final type = WorkflowNodeType.fromWire(raw['type']?.toString());
    if (id.isEmpty || type == null) return null;
    final config = raw['config'];
    return WorkflowNode(
      id: id,
      type: type,
      name: raw['name']?.toString().trim() ?? type.defaultName,
      config: config is Map
          ? Map<String, dynamic>.from(config)
          : const <String, dynamic>{},
      position: Offset(
        (raw['x'] as num?)?.toDouble() ?? 0,
        (raw['y'] as num?)?.toDouble() ?? 0,
      ),
    );
  }
}

/// 节点之间的一条连线。
class WorkflowEdge {
  const WorkflowEdge({
    required this.id,
    required this.fromNodeId,
    required this.fromPort,
    required this.toNodeId,
    required this.toPort,
  });

  final String id;
  final String fromNodeId;

  /// 输出端口名（'out' / 'true' / 'false'）。
  final String fromPort;
  final String toNodeId;

  /// 输入端口名（'in' / 'a' / 'b'）。
  final String toPort;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'id': id,
        'from': fromNodeId,
        'fromPort': fromPort,
        'to': toNodeId,
        'toPort': toPort,
      };

  static WorkflowEdge? fromJson(Object? raw) {
    if (raw is! Map) return null;
    // 2026-10-04 真机反馈「AI 生成的工作流没有连线」的根因：生成提示词的
    // DSL 用 fromNodeId/toNodeId（n8n 风格），解析却只认 from/to——AI 返回的
    // 边在这里整批判空静默丢弃，画布上只剩一堆没连线的节点。两种键名都收，
    // 顺带兼容 source/target 与被导出工具改写过端口键的形态。
    String pick(List<String> keys) {
      for (final key in keys) {
        final value = raw[key]?.toString().trim() ?? '';
        if (value.isNotEmpty) return value;
      }
      return '';
    }

    final from = pick(const <String>['from', 'fromNodeId', 'source', 'sourceNodeId']);
    final to = pick(const <String>['to', 'toNodeId', 'target', 'targetNodeId']);
    if (from.isEmpty || to.isEmpty) return null;
    return WorkflowEdge(
      id: raw['id']?.toString() ?? 'e-$from-$to',
      fromNodeId: from,
      fromPort: _normalizePort(
        raw['fromPort'] ?? raw['sourcePort'] ?? raw['sourcePortId'],
        'out',
      ),
      toNodeId: to,
      toPort: _normalizePort(
        raw['toPort'] ?? raw['targetPort'] ?? raw['targetPortId'],
        'in',
      ),
    );
  }

  /// 端口名别名归一：模型各写各的（input/output/default/yes/no…），统一成
  /// 引擎认识的 'in'/'out'/'true'/'false'，否则端口对不上会被静态校验拒绝。
  static String _normalizePort(Object? raw, String fallback) {
    final value = raw?.toString().trim().toLowerCase() ?? '';
    return switch (value) {
      '' => fallback,
      'input' || 'inputport' || 'inport' => 'in',
      'output' || 'outputport' || 'outport' || 'default' || 'main' => 'out',
      'yes' || 'then' || 'success' || 'passed' || 'pass' => 'true',
      'no' || 'else' || 'failure' || 'failed' || 'fail' => 'false',
      _ => value,
    };
  }
}

/// 一条工作流。
class WorkflowDefinition {
  const WorkflowDefinition({
    required this.id,
    required this.name,
    this.nodes = const <WorkflowNode>[],
    this.edges = const <WorkflowEdge>[],
    this.updatedAt = 0,
    this.enabled = true,
  });

  final String id;
  final String name;
  final List<WorkflowNode> nodes;
  final List<WorkflowEdge> edges;
  final int updatedAt;

  /// 对话里的 AI 能否读/跑这一条（用户 2026-10-03：要的是**单开关**不是总开关）。
  /// 关掉的条目仍留在工作流页面可编辑/可运行，只是不进 run_workflow 的清单。
  final bool enabled;

  WorkflowDefinition copyWith({
    String? name,
    List<WorkflowNode>? nodes,
    List<WorkflowEdge>? edges,
    int? updatedAt,
    bool? enabled,
  }) =>
      WorkflowDefinition(
        id: id,
        name: name ?? this.name,
        nodes: nodes ?? this.nodes,
        edges: edges ?? this.edges,
        updatedAt: updatedAt ?? this.updatedAt,
        enabled: enabled ?? this.enabled,
      );

  Map<String, dynamic> toJson() => <String, dynamic>{
        'id': id,
        'name': name,
        'nodes': nodes.map((node) => node.toJson()).toList(growable: false),
        'edges': edges.map((edge) => edge.toJson()).toList(growable: false),
        'updatedAt': updatedAt,
        'enabled': enabled,
      };

  String encode() => jsonEncode(toJson());

  static WorkflowDefinition? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id']?.toString().trim() ?? '';
    if (id.isEmpty) return null;
    return WorkflowDefinition(
      id: id,
      name: raw['name']?.toString().trim() ?? '未命名工作流',
      nodes: <WorkflowNode>[
        if (raw['nodes'] is List)
          for (final entry in raw['nodes'] as List)
            if (WorkflowNode.fromJson(entry) case final node?) node,
      ],
      edges: <WorkflowEdge>[
        if (raw['edges'] is List)
          for (final entry in raw['edges'] as List)
            if (WorkflowEdge.fromJson(entry) case final edge?) edge,
      ],
      updatedAt: (raw['updatedAt'] as num?)?.toInt() ?? 0,
      // 缺键回落为开（老数据默认可用，与「缺键回落为开」的助手开关同纪律）。
      enabled: raw['enabled'] is bool ? raw['enabled'] as bool : true,
    );
  }

  static WorkflowDefinition? decode(String raw) {
    if (raw.trim().isEmpty) return null;
    try {
      return fromJson(jsonDecode(raw));
    } catch (_) {
      return null;
    }
  }
}
