import 'dart:ui';

import '../models/workflow_models.dart';

/// 画布自动布局。
///
/// 2026-10-04 真机反馈「工作流卡片粘在一起」的根因：AI 生成的 JSON 基本不给
/// 坐标（DSL 示例里 x/y 就是 0,0），[WorkflowNode.fromJson] 缺省也落 (0,0)——
/// 所有节点精确重叠成一叠卡片，适配视图后只看得见一张。这里在解析后按有向图
/// 分层排布。
///
/// 排布方向是**纵向**（层号 → y 递增），兄弟节点沿 x 横向展开。原因是真机
/// 验证发现：单行横向链在手机上「适配视图」也看不全——编辑器最小缩放 0.6
/// 是「端口点得中」的下限（不能降），而手机屏宽在 0.6 缩放下只容得下约 3 个
/// 节点宽（节点 176 + 间距 120）。纵向排布在手机上天然富余，一屏就能看全
/// 主流的分步流水线。
abstract final class WorkflowLayout {
  /// 与编辑器 `_nodeWidth/_nodeHeight` 对齐（模型层不 import UI，常量这里自带）。
  static const double nodeWidth = 176;
  static const double nodeHeight = 84;
  static const double _hGap = 120;
  static const double _vGap = 64;

  /// 相邻兄弟节点/相邻层的步长（流式生成时给新节点占位也用这两个值）。
  static const double stepX = nodeWidth + _hGap;
  static const double stepY = nodeHeight + _vGap;

  /// 是否需要自动排布：有两个以上节点坐标完全相同（含「全都没给坐标」的全
  /// (0,0)）就认为数据没有可用坐标。用户手动排过的图不会被它覆盖。
  static bool needsLayout(WorkflowDefinition flow) {
    if (flow.nodes.length < 2) return false;
    final seen = <String>{};
    for (final node in flow.nodes) {
      final key = '${node.position.dx},${node.position.dy}';
      if (!seen.add(key)) return true;
    }
    return false;
  }

  /// 分层排布并返回带坐标的新定义（不改原对象）。
  static WorkflowDefinition apply(
    WorkflowDefinition flow, {
    Offset origin = const Offset(80, 80),
  }) {
    if (flow.nodes.isEmpty) return flow;
    final ids = <String>{for (final node in flow.nodes) node.id};
    // 悬浮边不参与分层（它本来也连不起来）。
    final edges = <WorkflowEdge>[
      for (final edge in flow.edges)
        if (ids.contains(edge.fromNodeId) && ids.contains(edge.toNodeId)) edge,
    ];
    final outgoing = <String, List<String>>{
      for (final node in flow.nodes) node.id: <String>[],
    };
    final incoming = <String, List<String>>{
      for (final node in flow.nodes) node.id: <String>[],
    };
    for (final edge in edges) {
      outgoing[edge.fromNodeId]!.add(edge.toNodeId);
      incoming[edge.toNodeId]!.add(edge.fromNodeId);
    }
    final level = <String, int>{for (final node in flow.nodes) node.id: 0};
    // Kahn 拓扑序：层号 = 最长上游路径（同一列里合并的分支会对齐到同一层）。
    final indegree = <String, int>{
      for (final node in flow.nodes) node.id: incoming[node.id]!.length,
    };
    final queue = <String>[
      for (final node in flow.nodes)
        if (indegree[node.id] == 0) node.id,
    ];
    final order = <String>[];
    while (queue.isNotEmpty) {
      final id = queue.removeAt(0);
      order.add(id);
      for (final next in outgoing[id]!) {
        final candidate = level[id]! + 1;
        if (candidate > level[next]!) level[next] = candidate;
        indegree[next] = indegree[next]! - 1;
        if (indegree[next] == 0) queue.add(next);
      }
    }
    // 环上的节点等不到入度归零：按原始顺序补进队尾，不让布局卡死。
    for (final node in flow.nodes) {
      if (!order.contains(node.id)) order.add(node.id);
    }
    final byLevel = <int, List<String>>{};
    for (final id in order) {
      byLevel.putIfAbsent(level[id]!, () => <String>[]).add(id);
    }
    final levels = byLevel.keys.toList()..sort();
    final positions = <String, Offset>{};
    for (final levelIndex in levels) {
      final idsInLevel = byLevel[levelIndex]!;
      for (var i = 0; i < idsInLevel.length; i++) {
        positions[idsInLevel[i]] = Offset(
          // 兄弟节点横向展开、层号向下递增：手机竖屏一屏看全。
          origin.dx + (i - (idsInLevel.length - 1) / 2) * stepX,
          origin.dy + levelIndex * stepY,
        );
      }
    }
    return flow.copyWith(
      nodes: <WorkflowNode>[
        for (final node in flow.nodes)
          node.copyWith(position: positions[node.id] ?? node.position),
      ],
    );
  }
}
