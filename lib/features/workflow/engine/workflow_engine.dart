import 'dart:collection';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models/workflow_models.dart';
import 'workflow_validation.dart';

/// 工作流执行引擎（纯 Dart，无 UI 依赖）。
///
/// **执行语义（v2，依赖驱动）**：先做一次静态预检（workflow_validation.dart），
/// 再过图——每个节点等它的**全部有效入边**到齐才执行，执行完把输出沿出边投递；
/// 汇聚节点（merge）拿到多路输入后按分隔符拼接（默认换行）。条件分支只投递
/// 被选中的那一侧，另一侧标记为「跳过」，而不是让下游干等。
///
/// 与 v1 的三处实质差别：
/// 1. **汇聚真的会汇聚**：v1 是一条入边跑一次节点，merge 会被跑两遍、后写覆盖
///    前写；现在每个节点只跑一次，多入边按边序拼好再进节点。
/// 2. **成环提前拒绝**：v1 递归时静默跳过环上的重复进入；现在预检直接判 fatal，
///    不会出现「看起来跑了、其实少跑一截」。
/// 3. **可取消 + 步数上限**：长链路（AI/HTTP/延迟）能中途停止，并有硬上限兜底，
///    不会因为图写错而无休止跑下去。
///
/// v1 遗留边界（诚实标注）：loop 节点把输入（或配置的 items 表达式）按行拆成
/// 带序号的列表透传，**子图重复执行**仍未做——它需要「循环体」这个结构概念，
/// 不是当前定义模型能表达的。
class WorkflowEngine {
  WorkflowEngine({required this.host});

  /// 外部能力注入（AI 生成走当前 provider/model，命令走沙盒工具链）。
  final WorkflowExecutorHost host;

  /// 跑一条工作流。日志实时回调（编辑器运行面板用），control 用于取消。
  Future<WorkflowRunResult> run({
    required WorkflowDefinition definition,
    String? input,
    void Function(WorkflowRunLogEntry entry)? onLog,
    WorkflowRunControl? control,
    int maxSteps = 500,
  }) async {
    final validation = validateWorkflow(
      definition,
      supportsCommands: host.supportsCommands,
    );
    if (!validation.ok) {
      return WorkflowRunResult(
        ok: false,
        error: validation.fatalMessage,
        output: '',
        logs: const <WorkflowRunLogEntry>[],
        issues: validation.issues,
      );
    }

    final runInput = input?.trim() ?? '';
    final nodesById = <String, WorkflowNode>{
      for (final node in definition.nodes) node.id: node,
    };
    final outgoing = <String, List<WorkflowEdge>>{};
    final incoming = <String, List<WorkflowEdge>>{};
    for (final edge in definition.edges) {
      if (!nodesById.containsKey(edge.fromNodeId) ||
          !nodesById.containsKey(edge.toNodeId)) {
        continue;
      }
      (outgoing[edge.fromNodeId] ??= <WorkflowEdge>[]).add(edge);
      (incoming[edge.toNodeId] ??= <WorkflowEdge>[]).add(edge);
    }

    final logs = <WorkflowRunLogEntry>[];
    final outputs = <String, String>{};
    final executed = <String>{};
    final failed = <String>{};
    final failureMessages = <String, String>{};
    final skippedEdges = <String>{};
    final arrived = <String, String>{};
    final queued = <String>{};
    final queue = ListQueue<String>();
    String? terminalOutput;
    var steps = 0;
    var cancelled = false;
    var budgetExceeded = false;

    void log(WorkflowRunLogEntry entry) {
      logs.add(entry);
      onLog?.call(entry);
    }

    // 入边全部到齐才跑；入边全被跳过（条件没走这侧）等于这条链到此为止。
    bool isReady(String nodeId) {
      final edges = incoming[nodeId] ?? const <WorkflowEdge>[];
      if (edges.isEmpty) return true;
      final active = <WorkflowEdge>[
        for (final edge in edges)
          if (!skippedEdges.contains(edge.id)) edge,
      ];
      if (active.isEmpty) return false;
      for (final edge in active) {
        if (!arrived.containsKey(edge.id)) return false;
      }
      return true;
    }

    String joinedInput(String nodeId) {
      final node = nodesById[nodeId];
      final edges = incoming[nodeId] ?? const <WorkflowEdge>[];
      final values = <String>[
        for (final edge in edges)
          if (arrived.containsKey(edge.id)) arrived[edge.id]!,
      ];
      if (values.isEmpty) return runInput;
      if (node?.type == WorkflowNodeType.merge) {
        final separator = (node?.config['separator'] ?? '').toString();
        return values.join(separator.isEmpty ? '\n' : separator);
      }
      return values.join('\n');
    }

    void enqueue(String nodeId) {
      if (executed.contains(nodeId) ||
          failed.contains(nodeId) ||
          !queued.add(nodeId)) {
        return;
      }
      queue.add(nodeId);
    }

    for (final node in definition.nodes) {
      if (node.type == WorkflowNodeType.start) enqueue(node.id);
    }

    while (queue.isNotEmpty) {
      final nodeId = queue.removeFirst();
      if (executed.contains(nodeId) || failed.contains(nodeId)) continue;
      if (control?.isCancelled ?? false) {
        cancelled = true;
        break;
      }
      if (steps >= maxSteps) {
        budgetExceeded = true;
        break;
      }
      final node = nodesById[nodeId]!;
      final nodeInput = joinedInput(nodeId);
      steps++;

      log(WorkflowRunLogEntry(
        nodeId: nodeId,
        nodeName: node.name,
        type: node.type,
        status: 'running',
      ));

      String output = '';
      String? error;
      try {
        output = await _execute(node, nodeInput, outputs, host);
      } catch (err) {
        error = err.toString();
      }

      // 条件节点：**判定只用来选边（并留在运行日志里），数据原样透传**。
      //
      // 2026-10-05 真机：用户把「AI 生成 → 条件判断 → 汇聚 → 输出」串成一条链，
      // 旧实现把条件节点的输出替换成字面量 "false"，文本在条件处被吃掉，最终
      // 输出只剩「生成结果：false」。条件的作用是分流，不该吃掉上游数据——
      // 下游（含 {{节点id}} 引用）收到的都是上游文本。
      final isCondition = node.type == WorkflowNodeType.condition;
      outputs[nodeId] = isCondition ? nodeInput : output;
      log(WorkflowRunLogEntry(
        nodeId: nodeId,
        nodeName: node.name,
        type: node.type,
        status: error == null ? 'success' : 'failed',
        output: error == null && isCondition
            ? '判定 $output（上游文本原样透传给下游）'
            : output,
        error: error,
      ));

      if (error != null) {
        failed.add(nodeId);
        failureMessages[nodeId] = error;
        continue; // 本链终止：出边永不投递，下游不会被触发
      }

      executed.add(nodeId);
      if (node.type == WorkflowNodeType.end) {
        terminalOutput ??= output;
        continue;
      }

      final branch = isCondition ? output.trim() : null;
      final delivered = isCondition ? nodeInput : output;
      final edges = outgoing[nodeId] ?? const <WorkflowEdge>[];
      for (final edge in edges) {
        if (branch != null && edge.fromPort != branch) {
          skippedEdges.add(edge.id); // 条件没走的那一侧
          continue;
        }
        arrived[edge.id] = delivered;
      }
      for (final edge in edges) {
        if (isReady(edge.toNodeId)) enqueue(edge.toNodeId);
      }
    }

    // 没跑到的节点：区分「被上游失败/条件挡住的」与「本来就不可达的」。
    final reachable = <String>{};
    final walk = <String>[
      for (final node in definition.nodes)
        if (node.type == WorkflowNodeType.start) node.id,
    ];
    while (walk.isNotEmpty) {
      final id = walk.removeLast();
      if (!reachable.add(id)) continue;
      for (final edge in outgoing[id] ?? const <WorkflowEdge>[]) {
        walk.add(edge.toNodeId);
      }
    }
    final skipped = <String>[
      for (final node in definition.nodes)
        if (reachable.contains(node.id) &&
            !executed.contains(node.id) &&
            !failed.contains(node.id))
          node.id,
    ];

    final failureText = failureMessages.entries
        .map((entry) =>
            '${nodesById[entry.key]?.name ?? entry.key}: ${entry.value}')
        .join('；');
    final String? error;
    if (cancelled) {
      error = '运行已取消';
    } else if (budgetExceeded) {
      error = '节点执行超过 $maxSteps 步上限，已中止（检查图是不是写成了环或扇出过大）';
    } else if (failureMessages.isNotEmpty) {
      error = failureText;
    } else {
      error = null;
    }

    return WorkflowRunResult(
      ok: !cancelled && !budgetExceeded && failureMessages.isEmpty,
      error: error,
      output: terminalOutput ?? _lastMeaningfulOutput(logs, outputs),
      logs: logs,
      skipped: skipped,
      cancelled: cancelled,
      steps: steps,
      issues: validation.issues,
    );
  }

  /// 条件分支的走向（true/false 输出口）。
  String branchOf(WorkflowNode node, String input, String output) {
    final expression = (node.config['expression'] ?? '').toString().trim();
    final source = input.isNotEmpty ? input : output;
    return evaluateCondition(expression, source) ? 'true' : 'false';
  }

  String _lastMeaningfulOutput(
    List<WorkflowRunLogEntry> logs,
    Map<String, String> outputs,
  ) {
    for (final entry in logs.reversed) {
      if (entry.status == 'success' && entry.output.trim().isNotEmpty) {
        return entry.output;
      }
    }
    return '';
  }

  Future<String> _execute(
    WorkflowNode node,
    String input,
    Map<String, String> outputs,
    WorkflowExecutorHost host,
  ) async {
    String resolve(String raw) => interpolate(raw, outputs);
    switch (node.type) {
      case WorkflowNodeType.start:
        return input;
      case WorkflowNodeType.text:
        return resolve((node.config['text'] ?? '').toString());
      case WorkflowNodeType.aiGenerate:
        final prompt = resolve((node.config['prompt'] ?? '').toString());
        final system = resolve((node.config['system'] ?? '').toString());
        return host.generateText(
          prompt: prompt.isEmpty ? input : prompt,
          system: system.isEmpty ? null : system,
        );
      case WorkflowNodeType.command:
        return host.runCommand(
          resolve((node.config['command'] ?? '').toString()),
        );
      case WorkflowNodeType.httpRequest:
        return _http(node, resolve);
      case WorkflowNodeType.condition:
        return branchOf(node, input, input);
      case WorkflowNodeType.loop:
        // v1：把输入（或 items 表达式）按行拆成带序号的列表透传。子图重复
        // 执行需要「循环体」结构，见类注释。
        final items = (node.config['items'] ?? '').toString().trim();
        final source = items.isEmpty ? input : resolve(items);
        final lines = <String>[
          for (final line in source.split('\n'))
            if (line.trim().isNotEmpty) line.trim(),
        ];
        return <String>[
          for (var i = 0; i < lines.length; i++) '${i + 1}. ${lines[i]}',
        ].join('\n');
      case WorkflowNodeType.merge:
        // 多入边的拼接已在调度器里按边序完成（merge 只按分隔符收口）。
        return input;
      case WorkflowNodeType.extract:
        return extract(node, input);
      case WorkflowNodeType.delay:
        final seconds =
            int.tryParse(resolve((node.config['seconds'] ?? '0').toString())) ??
                0;
        if (seconds > 0) {
          await Future<void>.delayed(Duration(seconds: seconds.clamp(0, 300)));
        }
        return input;
      case WorkflowNodeType.output:
        final template = (node.config['template'] ?? '').toString();
        // 没填模板 = 原样透传（不能再 resolve 一次：上游内容里的 {{...}}
        // 是数据，不是变量引用）。
        return template.trim().isEmpty ? input : resolve(template);
      case WorkflowNodeType.end:
        return input;
    }
  }

  Future<String> _http(
    WorkflowNode node,
    String Function(String) resolve,
  ) async {
    final url = resolve((node.config['url'] ?? '').toString()).trim();
    if (url.isEmpty) {
      throw StateError('HTTP 节点没有配置 URL');
    }
    final method = resolve((node.config['method'] ?? 'GET').toString())
        .trim()
        .toUpperCase();
    final body = resolve((node.config['body'] ?? '').toString());
    final uri = Uri.tryParse(url);
    if (uri == null || !uri.hasScheme) {
      throw StateError('HTTP URL 无效：$url');
    }
    final request = http.Request(method, uri)
      ..headers['content-type'] = 'application/json';
    if (method != 'GET' && method != 'HEAD' && body.isNotEmpty) {
      request.body = body;
    }
    final response =
        await http.Response.fromStream(await request.send()).timeout(
      const Duration(seconds: 30),
    );
    if (response.statusCode >= 400) {
      throw StateError('HTTP ${response.statusCode}');
    }
    final text = utf8.decode(response.bodyBytes, allowMalformed: true);
    return text.length > 20000 ? '${text.substring(0, 20000)}…' : text;
  }
}

/// 条件表达式求值（v1 支持三种前缀形式，满足绝大多数分支需求）：
/// contains:关键词 / regex:正则 / equals:a|b；空表达式恒为 true。
bool evaluateCondition(String expression, String source) {
  final expr = expression.trim();
  if (expr.isEmpty) return true;
  if (expr.startsWith('contains:')) {
    return source.contains(expr.substring('contains:'.length).trim());
  }
  if (expr.startsWith('regex:')) {
    try {
      return RegExp(expr.substring('regex:'.length)).hasMatch(source);
    } catch (_) {
      return false;
    }
  }
  if (expr.startsWith('equals:')) {
    final options = expr
        .substring('equals:'.length)
        .split('|')
        .map((option) => option.trim());
    return options.contains(source.trim());
  }
  return source.contains(expr);
}

/// 从节点输出里提取（v1：re:正则（首个捕获组或整段匹配）与 $.a.b JSON
/// 点路径），无前缀按整段透传。
String extract(WorkflowNode node, String input) {
  final pattern = (node.config['pattern'] ?? '').toString().trim();
  if (pattern.isEmpty) return input;
  if (pattern.startsWith('re:')) {
    try {
      final match = RegExp(pattern.substring(3)).firstMatch(input);
      if (match == null) return '';
      return (match.groupCount > 0 ? match.group(1) : match.group(0)) ?? '';
    } catch (_) {
      return input;
    }
  }
  if (pattern.startsWith(r'$.')) {
    try {
      dynamic cursor = jsonDecode(input);
      for (final key in pattern.substring(2).split('.')) {
        if (cursor is Map) {
          cursor = cursor[key];
        } else if (cursor is List) {
          final idx = int.tryParse(key);
          cursor = idx == null
              ? null
              : cursor.elementAt(idx.clamp(0, cursor.length - 1));
        } else {
          return '';
        }
      }
      return cursor?.toString() ?? '';
    } catch (_) {
      return input;
    }
  }
  return input;
}

/// {{nodeId}} 模板替换：把配置里引用的上游输出内联进来。
String interpolate(String raw, Map<String, String> outputs) {
  if (!raw.contains('{{')) return raw;
  return raw.replaceAllMapped(RegExp(r'\{\{([a-zA-Z0-9_]+)\}\}'), (match) {
    return outputs[match.group(1)] ?? '';
  });
}

/// 引擎对外部能力的依赖（UI 层注入：AI 走当前 provider，命令走沙盒）。
abstract class WorkflowExecutorHost {
  Future<String> generateText({required String prompt, String? system});

  Future<String> runCommand(String command);

  /// 当前宿主能不能真的执行命令。App 侧沙盒未接线时返回 false——此时图里的
  /// 命令节点在**预检**阶段就被拦下，而不是跑到那一步才抛异常。
  bool get supportsCommands => false;
}

/// 单次运行的取消开关（编辑器运行面板的「停止」用它收口）。
class WorkflowRunControl {
  bool _cancelled = false;

  bool get isCancelled => _cancelled;

  void cancel() => _cancelled = true;
}

/// 一次运行的一条日志。
class WorkflowRunLogEntry {
  const WorkflowRunLogEntry({
    required this.nodeId,
    required this.nodeName,
    required this.type,
    required this.status,
    this.output = '',
    this.error,
  });

  final String nodeId;
  final String nodeName;
  final WorkflowNodeType type;

  /// running / success / failed。
  final String status;
  final String output;
  final String? error;
}

/// 一次运行的结局。
class WorkflowRunResult {
  const WorkflowRunResult({
    required this.ok,
    required this.output,
    required this.logs,
    this.error,
    this.skipped = const <String>[],
    this.cancelled = false,
    this.steps = 0,
    this.issues = const <WorkflowIssue>[],
  });

  final bool ok;

  /// 最终输出：end 节点的输出；没有 end 时取最后一条非空成功输出。
  final String output;
  final String? error;
  final List<WorkflowRunLogEntry> logs;

  /// 可达但没执行的节点（被上游失败或条件分支挡住）——如实上报，别让调用方
  /// 以为整张图都跑过了。
  final List<String> skipped;

  final bool cancelled;

  /// 实际执行的节点数。
  final int steps;

  /// 预检结论（含非致命告警）。
  final List<WorkflowIssue> issues;
}
