import 'dart:convert';

import '../models/workflow_models.dart';
import '../engine/workflow_validation.dart';

/// AI 生成工作流的流式事件（2026-10-04：生成要在画布上实时可见）。
///
/// 事件是**增量上屏**用的：能先显示就先显示；终态 [WorkflowDoneEvent] 一定
/// 会来一次，且它的 flow 以完整文本的整段解析为准——增量解析只负责「先看到」，
/// 不负责「最终算数」。
sealed class WorkflowGenerationEvent {
  const WorkflowGenerationEvent();
}

/// 顶层 name 先于 nodes 出现时提前上屏（标题栏实时更新）。
final class WorkflowNameEvent extends WorkflowGenerationEvent {
  const WorkflowNameEvent(this.name);

  final String name;
}

/// 解析出一个完整节点（数组元素闭合且可解码）。
final class WorkflowNodeEvent extends WorkflowGenerationEvent {
  const WorkflowNodeEvent(this.node);

  final WorkflowNode node;
}

/// 解析出一条完整连线。
final class WorkflowEdgeEvent extends WorkflowGenerationEvent {
  const WorkflowEdgeEvent(this.edge);

  final WorkflowEdge edge;
}

/// 进度提示（如自动重试等待），message 直接展示。
final class WorkflowProgressEvent extends WorkflowGenerationEvent {
  const WorkflowProgressEvent(this.message);

  final String message;
}

/// 终态：ok = flow 非空；失败带原因；warnings 为非致命静态校验告警。
final class WorkflowDoneEvent extends WorkflowGenerationEvent {
  const WorkflowDoneEvent({
    this.flow,
    this.error,
    this.warnings = const <WorkflowIssue>[],
  });

  final WorkflowDefinition? flow;
  final String? error;
  final List<WorkflowIssue> warnings;

  bool get ok => flow != null;
}

/// 流式增量 JSON 解析器。
///
/// 模型按 `{"name":…,"nodes":[{…},{…}],"edges":[{…}]}` 流式产出；这里不做
/// 「半个对象」的猜测，只在**数组元素花括号闭合且能 jsonDecode** 时把它当作
/// 一个完整节点/连线发出去。最终结果仍由完整文本整段解析裁决，所以：
/// - 增量只影响「多快看到」，不影响正确性；
/// - 解码失败的条目直接跳过（真坏了，整段解析也会失败并给出错误）。
class WorkflowStreamParser {
  final StringBuffer _buffer = StringBuffer();

  /// `"nodes"` / `"edges"` 数组内容起点（'[' 的下一格）；-1 = 还没出现。
  int _nodesStart = -1;
  int _edgesStart = -1;

  /// 已处理到的位置（上一个发出的条目的右花括号之后）。
  int _nodeCursor = -1;
  int _edgeCursor = -1;

  bool _nameEmitted = false;

  /// 喂入一个流式片段，返回本次新解析出的完整条目事件。
  List<WorkflowGenerationEvent> feed(String delta) {
    if (delta.isEmpty) return const <WorkflowGenerationEvent>[];
    _buffer.write(delta);
    final text = _buffer.toString();
    final events = <WorkflowGenerationEvent>[];

    // 先定位段落再抽 name：段落起点要用来把「顶层 name」与「节点自带的
    // name 字段」切开，否则会把第一个节点的名字当成工作流名提前上屏。
    if (_nodesStart < 0) _nodesStart = _sectionArrayStart(text, 'nodes');
    if (!_nameEmitted) {
      final name = _earlyName(text);
      if (name != null && name.trim().isNotEmpty) {
        _nameEmitted = true;
        events.add(WorkflowNameEvent(name.trim()));
      }
    }
    if (_nodesStart >= 0) {
      for (final item in _completeItems(
        text,
        _nodeCursor < 0 ? _nodesStart : _nodeCursor,
      )) {
        _nodeCursor = item.end;
        final node = WorkflowNode.fromJson(item.value);
        if (node != null) events.add(WorkflowNodeEvent(node));
      }
    }
    if (_edgesStart < 0) _edgesStart = _sectionArrayStart(text, 'edges');
    if (_edgesStart >= 0) {
      for (final item in _completeItems(
        text,
        _edgeCursor < 0 ? _edgesStart : _edgeCursor,
      )) {
        _edgeCursor = item.end;
        final edge = WorkflowEdge.fromJson(item.value);
        if (edge != null) events.add(WorkflowEdgeEvent(edge));
      }
    }
    return events;
  }

  /// 找 `"key"` `:` `[` 并返回数组内容起点；没出现返回 -1。
  int _sectionArrayStart(String text, String key) {
    final index = text.indexOf('"$key"');
    if (index < 0) return -1;
    var i = index + key.length + 2;
    while (i < text.length && _isSpace(text.codeUnitAt(i))) {
      i++;
    }
    if (i >= text.length || text.codeUnitAt(i) != 0x3A /* : */) return -1;
    i++;
    while (i < text.length && _isSpace(text.codeUnitAt(i))) {
      i++;
    }
    if (i >= text.length || text.codeUnitAt(i) != 0x5B /* [ */) return -1;
    return i + 1;
  }

  /// 顶层 name（只在 nodes 段落之前找，避免命中节点自带的 name）。
  String? _earlyName(String text) {
    final boundary = _nodesStart >= 0 ? _nodesStart : text.length;
    final head = text.substring(0, boundary);
    final match = RegExp(r'"name"\s*:\s*"((?:[^"\\]|\\.)*)"').firstMatch(head);
    if (match == null) return null;
    try {
      return jsonDecode('"${match.group(1)}"').toString();
    } catch (_) {
      return match.group(1);
    }
  }

  /// 从 [from] 起扫描数组元素：遇到闭合花括号且能解码才算一个完整条目。
  List<_ParsedItem> _completeItems(String text, int from) {
    final items = <_ParsedItem>[];
    var i = from;
    while (i < text.length) {
      final ch = text.codeUnitAt(i);
      if (_isSpace(ch) || ch == 0x2C /* , */) {
        i++;
        continue;
      }
      if (ch == 0x5D /* ] */) break;
      if (ch != 0x7B /* { */) break;
      final end = _objectEnd(text, i);
      if (end < 0) break;
      Object? value;
      try {
        value = jsonDecode(text.substring(i, end + 1));
      } catch (_) {
        value = null;
      }
      if (value != null) items.add(_ParsedItem(value, end + 1));
      i = end + 1;
    }
    return items;
  }

  /// 花括号配平（字符串/转义感知），返回对象右花括号的位置；未闭合返回 -1。
  int _objectEnd(String text, int start) {
    var depth = 0;
    var inString = false;
    var escaped = false;
    for (var i = start; i < text.length; i++) {
      final ch = text.codeUnitAt(i);
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (ch == 0x5C /* \ */) {
          escaped = true;
        } else if (ch == 0x22 /* " */) {
          inString = false;
        }
        continue;
      }
      if (ch == 0x22) {
        inString = true;
      } else if (ch == 0x7B) {
        depth++;
      } else if (ch == 0x7D) {
        depth--;
        if (depth == 0) return i;
      }
    }
    return -1;
  }

  static bool _isSpace(int ch) =>
      ch == 0x20 || ch == 0x09 || ch == 0x0A || ch == 0x0D;
}

class _ParsedItem {
  const _ParsedItem(this.value, this.end);

  final Object? value;

  /// 该条目右花括号之后的位置。
  final int end;
}
