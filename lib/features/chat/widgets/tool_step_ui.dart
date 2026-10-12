import 'dart:convert';

import 'package:flutter/material.dart';

import '../../../core/services/local_tools/local_tool_names.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../theme/app_font_weights.dart';
import '../../home/services/todo_store.dart';
import 'solab_todo_panel.dart';
import 'workspace_tool_ui.dart';

/// 工具步骤的**族**（对齐 dsh 的 `ToolRowVariant` / ZCode 的 renderer family）。
///
/// 用户 2026-10-04：「运行命令、思考、读取任务、输出、读取、写入、编辑，这些都没有
/// 反馈」——根因是本地 agent 工具全部走通用卡（只有标题「调用工具: file」，且
/// 结果摘要默认关闭）。这里把工具按族归类，标题/摘要/结果块都按族给形状。
enum ToolStepFamily {
  shell,
  read,
  write,
  edit,
  search,
  todo,
  task,
  goal,
  memory,
  delivery,
  apk,
  workflow,
  subagent,
  web,
  other,
}

ToolStepFamily toolStepFamilyOf(String name, Map<String, dynamic> args) {
  switch (name) {
    case 'shell':
      return ToolStepFamily.shell;
    case 'read_file':
      return ToolStepFamily.read;
    case 'write_file':
      return ToolStepFamily.write;
    case 'edit_file':
      return ToolStepFamily.edit;
    case 'list_dir':
    case 'glob':
    case 'grep':
      return ToolStepFamily.search;
    case LocalToolNames.file:
      // 统一 file 工具按 action 分族（读/写/搜索是三种完全不同的反馈）。
      return switch ((args['action'] ?? '').toString()) {
        'read' ||
        'list' ||
        'info' ||
        'inventory' ||
        'diff' ||
        'strings' => ToolStepFamily.read,
        'write' ||
        'copy' ||
        'mkdir' ||
        'rename' ||
        'move' ||
        'zip' ||
        'unzip' ||
        'delete' => ToolStepFamily.write,
        'grep' || 'replace' => ToolStepFamily.search,
        _ => ToolStepFamily.other,
      };
    case LocalToolNames.todoWrite:
    case LocalToolNames.todoRead:
      return ToolStepFamily.todo;
    case LocalToolNames.taskStatus:
    case LocalToolNames.taskUpdate:
    case LocalToolNames.evidenceQuery:
    case LocalToolNames.artifactRead:
    case LocalToolNames.patchPlan:
    case LocalToolNames.dryRunPatch:
    case LocalToolNames.planProbes:
    case LocalToolNames.verifyApk:
    case LocalToolNames.runTaskCommand:
    case LocalToolNames.routeTask:
      return ToolStepFamily.task;
    case LocalToolNames.goalGet:
    case LocalToolNames.goalCreate:
    case LocalToolNames.goalUpdate:
      return ToolStepFamily.goal;
    case LocalToolNames.memoryRead:
    case LocalToolNames.memoryUpdate:
    case LocalToolNames.memorySearchProfile:
    case LocalToolNames.memoryEdit:
    case LocalToolNames.memoryDelete:
    case LocalToolNames.updateUserProfile:
    case LocalToolNames.apkPatchMemory:
    case LocalToolNames.apkSavePatchMemory:
    case LocalToolNames.apkRecordPatchVerification:
    case LocalToolNames.apkNoteRead:
    case LocalToolNames.apkNoteWrite:
      return ToolStepFamily.memory;
    case LocalToolNames.collectDelivery:
    case LocalToolNames.workspaceCleanup:
    case LocalToolNames.apkExportReport:
      return ToolStepFamily.delivery;
    case LocalToolNames.subagent:
      return ToolStepFamily.subagent;
    case LocalToolNames.runWorkflow:
      return ToolStepFamily.workflow;
    case LocalToolNames.searchWeb:
    case LocalToolNames.chatSearch:
      return ToolStepFamily.web;
    case LocalToolNames.dexSearch:
    case LocalToolNames.stringScan:
    case LocalToolNames.dexXref:
    case LocalToolNames.classOutline:
    case LocalToolNames.smaliRead:
    case LocalToolNames.soAnalyze:
    case LocalToolNames.jadxDecompile:
    case LocalToolNames.apkArchive:
    case LocalToolNames.apkAnalyzeWorkspace:
    case LocalToolNames.apkReport:
    case LocalToolNames.apkProjectInfo:
    case LocalToolNames.apkRules:
    case LocalToolNames.apkListBuilds:
    case LocalToolNames.apkCleanupBuilds:
    case LocalToolNames.apkListWorkspace:
    case LocalToolNames.apkToolMap:
    case LocalToolNames.frida:
    case LocalToolNames.apkPatchDex:
    case LocalToolNames.apkPatchDexStrings:
    case LocalToolNames.apkSignatureBypass:
    case LocalToolNames.apkPatchManifest:
    case LocalToolNames.apkSign:
    case LocalToolNames.apkRebuild:
    case LocalToolNames.soPatchIntoApk:
    case LocalToolNames.workspacePolicy:
    case LocalToolNames.agentRuntimeGuide:
    case LocalToolNames.installedSkills:
    case LocalToolNames.apkSkill:
    case LocalToolNames.apkKnowledge:
      return ToolStepFamily.apk;
    default:
      return ToolStepFamily.other;
  }
}

/// 该族是否参与「连续同族聚合」。
///
/// 只聚合**高重复、同质**的族（读文件 / 搜索 / 跑命令），对齐 ZCode 出厂配置：
/// `ENABLE_EXPLORE_TOOL_CALL_GROUPING = true`（read/search）、
/// `ENABLE_TERMINAL_TOOL_CALL_GROUPING = true`（shell）、
/// `ENABLE_CHANGES_TOOL_CALL_GROUPING = false`（write/edit 不聚合）。
/// 记忆 / 任务 / 目标 / 子代理这类**每次调用语义都不同**的族也不聚合：聚起来就
/// 把用户要看的标题藏掉了（用户 2026-10-04 要的正是「有反馈」）。
bool toolStepFamilyGroupsConsecutive(ToolStepFamily family) =>
    family == ToolStepFamily.shell ||
    family == ToolStepFamily.read ||
    family == ToolStepFamily.search;

/// 聚合判定：workspace 工具（读取/写入/命令/搜索）**不聚合**。
///
/// 它们本来就有一套富卡片（`WorkspaceToolCardBody`：路径 chip、行数、变更文件、
/// 输出尾巴），聚成一行反而把它藏了——真机实测（用户 2026-10-04）「读取写入这些
/// 没有和我原本的逻辑互通起来」说的就是这个。返回 null 表示不聚合。
ToolStepFamily? toolStepGroupableFamily(
  String toolName,
  Map<String, dynamic> args,
) {
  if (isWorkspaceToolName(toolName)) return null;
  final family = toolStepFamilyOf(toolName, args);
  return toolStepFamilyGroupsConsecutive(family) ? family : null;
}

/// 连续同族工具步骤的聚合计划：同族、连续、**≥2 个**才成组。
///
/// **渲染与高度估算必须共用这一份规则**（消息列表按估算高度虚拟化，两边不一致
/// 就会滚动跳变）。[families] 里 null 表示非工具步骤（思考），会切断连续段。
({Map<int, List<int>> groups, Set<int> hidden}) planToolStepGroups(
  List<ToolStepFamily?> families,
) {
  final groups = <int, List<int>>{};
  final hidden = <int>{};
  var i = 0;
  while (i < families.length) {
    final family = families[i];
    if (family == null || !toolStepFamilyGroupsConsecutive(family)) {
      i++;
      continue;
    }
    final run = <int>[i];
    var j = i + 1;
    while (j < families.length && families[j] == family) {
      run.add(j);
      j++;
    }
    if (run.length >= 2) {
      groups[i] = run;
      for (var k = 1; k < run.length; k++) {
        hidden.add(run[k]);
      }
    }
    i = j;
  }
  return (groups: groups, hidden: hidden);
}

/// 该状态下是否有可显示的尾标。
///
/// 折叠态每一步都有渲染对象预算（见 timeline_step_memo_test）：为空时**不要**挂
/// 一个 SizedBox.shrink，那也会占一个渲染对象。
bool toolStepHasStatusExtra(ToolStepStatus status, Duration? duration) =>
    status == ToolStepStatus.failed ||
    status == ToolStepStatus.stopped ||
    (status == ToolStepStatus.ok && duration != null);

/// 类型化结果块的行数（高度估算用；上限与渲染一致 = 6 行）。
int estimateToolStepBlockLines({
  required ToolStepFamily family,
  required Map<String, dynamic> arguments,
  required String? result,
}) {
  if (!toolStepFamilyHasBlock(family)) return 0;
  switch (family) {
    case ToolStepFamily.edit:
    case ToolStepFamily.write:
      return toolStepDiffLines(arguments, maxLines: 6).length;
    case ToolStepFamily.todo:
      final items = ToolStepTodoList.parse(result);
      return items.length > 6 ? 6 : items.length;
    default:
      final body = toolStepTextBody(result, maxLines: 6);
      if (body == null) return 0;
      final lines = body.split('\n').length;
      return lines > 6 ? 6 : lines;
  }
}

/// 该族是否有「类型化结果块」（渲染与估算共用）。
bool toolStepFamilyHasBlock(ToolStepFamily family) => const <ToolStepFamily>{
  ToolStepFamily.edit,
  ToolStepFamily.write,
  ToolStepFamily.todo,
  ToolStepFamily.read,
  ToolStepFamily.search,
  ToolStepFamily.shell,
  ToolStepFamily.task,
  ToolStepFamily.apk,
}.contains(family);

IconData toolStepFamilyIcon(ToolStepFamily family) {
  switch (family) {
    case ToolStepFamily.shell:
      return Lucide.Terminal;
    case ToolStepFamily.read:
      return Lucide.FileText;
    case ToolStepFamily.write:
      return Lucide.FilePlus;
    case ToolStepFamily.edit:
      return Lucide.FileDiff;
    case ToolStepFamily.search:
      return Lucide.Search;
    case ToolStepFamily.todo:
      return Lucide.ListChecks;
    case ToolStepFamily.task:
      return Lucide.ListOrdered;
    case ToolStepFamily.goal:
      return Lucide.CheckCircle;
    case ToolStepFamily.memory:
      return Lucide.bookHeart;
    case ToolStepFamily.delivery:
      return Lucide.Package;
    case ToolStepFamily.apk:
      return Lucide.HardDrive;
    case ToolStepFamily.workflow:
      return Lucide.Workflow;
    case ToolStepFamily.subagent:
      return Lucide.Bot;
    case ToolStepFamily.web:
      return Lucide.Earth;
    case ToolStepFamily.other:
      return Lucide.Wrench;
  }
}

/// 工具步骤标题：**就是工具自己的名字**（沿用上游 `调用工具: {name}` 文案）。
///
/// 用户 2026-10-04：「调用工具，你就显示调用工具的名称啊，你全部都显示什么分析、
/// 什么分析、不要这个字段行不行」——曾经试过按族给「APK 分析 / 任务状态」这类
/// 自造标题，一族多工具时反而看不出跑的是哪个，已按用户要求去掉。
String toolStepFallbackTitle(
  AppLocalizations l10n,
  String name, {
  required bool isResult,
}) => isResult
    ? l10n.chatMessageWidgetToolResult(name)
    : l10n.chatMessageWidgetToolCall(name);

String _pick(Map<String, dynamic> args, List<String> keys) {
  for (final key in keys) {
    final value = args[key]?.toString().trim() ?? '';
    if (value.isNotEmpty) return value;
  }
  return '';
}

String _fileName(String path) {
  if (path.isEmpty) return '';
  final parts = path.split(RegExp(r'[\\/]'));
  return parts.isEmpty ? path : parts.last;
}

/// 标题后面的关键参数（路径/命令/查询/模式）。
String toolStepSubject(ToolStepFamily family, Map<String, dynamic> args) {
  switch (family) {
    case ToolStepFamily.shell:
      return _pick(args, const ['command']);
    case ToolStepFamily.read:
    case ToolStepFamily.write:
    case ToolStepFamily.edit:
      return _fileName(_pick(args, const ['path', 'filePath', 'file', 'source']));
    case ToolStepFamily.search:
      return _pick(args, const ['pattern', 'query', 'glob', 'keyword', 'path']);
    case ToolStepFamily.web:
      return _pick(args, const ['query', 'url']);
    case ToolStepFamily.apk:
      return _fileName(
        _pick(args, const ['apkPath', 'path', 'target', 'query', 'symbol']),
      );
    case ToolStepFamily.subagent:
      return _pick(args, const ['agent', 'team']);
    case ToolStepFamily.todo:
    case ToolStepFamily.task:
    case ToolStepFamily.goal:
    case ToolStepFamily.memory:
    case ToolStepFamily.delivery:
    case ToolStepFamily.workflow:
    case ToolStepFamily.other:
      return '';
  }
}

/// 步骤状态（对齐 dsh 的 preparing/running/ok/error/stopped）。
enum ToolStepStatus { running, ok, failed, stopped }

/// 结果 JSON 里的 `ok/error` 是工具契约的权威判据；文本兜底只认前缀。
ToolStepStatus toolStepStatusOf({required bool loading, required String? result}) {
  if (loading) return ToolStepStatus.running;
  final text = result?.trim() ?? '';
  if (text.isEmpty) return ToolStepStatus.ok;
  try {
    final decoded = jsonDecode(text);
    if (decoded is Map) {
      final error = (decoded['error'] ?? '').toString();
      if (decoded['ok'] == false || error.isNotEmpty) {
        return error == 'interrupted' || error == 'cancelled'
            ? ToolStepStatus.stopped
            : ToolStepStatus.failed;
      }
      return ToolStepStatus.ok;
    }
  } catch (_) {
    // 非 JSON 结果（子代理结论、纯文本工具）按成功处理。
  }
  return ToolStepStatus.ok;
}

String toolStepStatusLabel(AppLocalizations l10n, ToolStepStatus status) {
  switch (status) {
    case ToolStepStatus.running:
      return l10n.toolStepStatusRunning;
    case ToolStepStatus.ok:
      return l10n.toolStepStatusDone;
    case ToolStepStatus.failed:
      return l10n.toolStepStatusFailed;
    case ToolStepStatus.stopped:
      return l10n.toolStepStatusStopped;
  }
}

/// 失败时的**首行**（折叠态直接显示它，不用点开就知道为什么失败——
/// 对齐 dsh 的 `errorSummary = firstLine(output)`）。
String? toolStepErrorLine(String? result) {
  final text = result?.trim() ?? '';
  if (text.isEmpty) return null;
  try {
    final decoded = jsonDecode(text);
    if (decoded is Map) {
      final message = (decoded['message'] ?? '').toString().trim();
      if (message.isNotEmpty) return message.split('\n').first.trim();
      final error = (decoded['error'] ?? '').toString().trim();
      if (error.isNotEmpty) return error;
      if (decoded['ok'] == false) return text.split('\n').first.trim();
      return null;
    }
  } catch (_) {
    return null;
  }
  return null;
}

Map<String, dynamic>? _decodeResult(String? result) {
  final text = result?.trim() ?? '';
  if (text.isEmpty) return null;
  try {
    final decoded = jsonDecode(text);
    if (decoded is Map) return Map<String, dynamic>.from(decoded);
  } catch (_) {}
  return null;
}

/// 结果是不是「机器看的 JSON」。
///
/// 真机实测（用户 2026-10-04 截图）：把原始 JSON 倒进聊天里既读不懂、又和
/// 卡片材质打架。JSON 只允许出现在「点开详情」里，聊天行内一律给结构化字段。
bool toolStepLooksLikeJson(String text) {
  final trimmed = text.trimLeft();
  if (trimmed.isEmpty) return false;
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

/// 工具结果里适合当一行摘要的短句（过滤掉 ok/error 这类状态词）。
String? _shortPhrase(String value) {
  final text = value.trim();
  if (text.isEmpty) return null;
  if (toolStepLooksLikeJson(text)) return null;
  final lower = text.toLowerCase();
  const statusTokens = {'ok', 'error', 'success', 'failed', 'true', 'false'};
  if (statusTokens.contains(lower)) return null;
  final firstLine = text.split('\n').first.trim();
  if (firstLine.isEmpty) return null;
  return firstLine.length <= 80 ? firstLine : '${firstLine.substring(0, 80)}…';
}

int _lineCount(String text) {
  if (text.isEmpty) return 0;
  return text.split('\n').length;
}

/// 结果的**一行摘要**（按族派生）。返回 null = 没有可说的（不要占位）。
String? toolStepResultSummary({
  required ToolStepFamily family,
  required Map<String, dynamic> args,
  required String? result,
  required AppLocalizations l10n,
}) {
  final decoded = _decodeResult(result);
  switch (family) {
    case ToolStepFamily.edit:
    case ToolStepFamily.write:
      final stat = toolStepDiffStat(args, decoded);
      if (stat != null) {
        return '+${stat.added} −${stat.removed}';
      }
      final bytes = decoded?['bytes'];
      if (bytes is num) return '${bytes.toInt()} B';
      return null;
    case ToolStepFamily.read:
      final total = decoded?['totalLines'] ?? decoded?['lines'];
      if (total is num) return l10n.toolStepLines(total.toInt());
      final content = (decoded?['content'] ?? decoded?['text'] ?? '').toString();
      if (content.isNotEmpty) return l10n.toolStepLines(_lineCount(content));
      final batch = decoded?['succeeded'];
      if (batch is num) return l10n.toolStepFiles(batch.toInt());
      return null;
    case ToolStepFamily.search:
      final matches = decoded?['matches'] ?? decoded?['results'] ?? decoded?['hits'];
      if (matches is List) return l10n.toolStepMatches(matches.length);
      final count = decoded?['count'] ?? decoded?['total'];
      if (count is num) return l10n.toolStepMatches(count.toInt());
      final text = (result ?? '').trim();
      if (text.isEmpty) return null;
      final lines = text
          .split('\n')
          .where((line) => line.trim().isNotEmpty)
          .length;
      return lines == 0 ? null : l10n.toolStepMatches(lines);
    case ToolStepFamily.todo:
      final counts = decoded?['counts'];
      if (counts is Map) {
        final done = (counts['done'] as num?)?.toInt() ?? 0;
        final total = counts.values
            .whereType<num>()
            .fold<int>(0, (sum, value) => sum + value.toInt());
        return l10n.toolStepTodos(done, total);
      }
      final todos = decoded?['todos'];
      if (todos is List) {
        final done = todos
            .whereType<Map>()
            .where((item) => item['status'] == 'done')
            .length;
        return l10n.toolStepTodos(done, todos.length);
      }
      return null;
    case ToolStepFamily.task:
    case ToolStepFamily.goal:
      // 只认「人话」字段；`status` 这种机器词（ok/error）不当摘要——
      // 真机实测里 task_status 失败时行内只显示了一个 "error"，等于没说。
      for (final key in const [
        'summary',
        'message',
        'nextAction',
        'next',
        'stage',
        'verdict',
        'claimableStatus',
      ]) {
        final phrase = _shortPhrase((decoded?[key] ?? '').toString());
        if (phrase != null) return phrase;
      }
      return null;
    case ToolStepFamily.delivery:
      final artifacts = decoded?['artifacts'] ?? decoded?['files'];
      if (artifacts is List && artifacts.isNotEmpty) {
        return l10n.toolStepFiles(artifacts.length);
      }
      return null;
    case ToolStepFamily.shell:
    case ToolStepFamily.memory:
    case ToolStepFamily.apk:
    case ToolStepFamily.workflow:
    case ToolStepFamily.subagent:
    case ToolStepFamily.web:
    case ToolStepFamily.other:
      // 兜底：结果第一行（旧的「显示工具结果摘要」行为），但**绝不倒 JSON**——
      // 结构化结果由族字段或详情面板负责。
      return _shortPhrase(result ?? '');
  }
}

/// 写入/编辑的 `+N −M`：优先用结果里的真实 diff，缺失时从参数推导。
({int added, int removed})? toolStepDiffStat(
  Map<String, dynamic> args,
  Map<String, dynamic>? result,
) {
  final diffs = result?['diffs'];
  if (diffs is List && diffs.isNotEmpty) {
    var added = 0;
    var removed = 0;
    for (final entry in diffs) {
      if (entry is! Map) continue;
      final add = entry['added'] ?? entry['addedLines'];
      final remove = entry['removed'] ?? entry['removedLines'];
      if (add is num) added += add.toInt();
      if (remove is num) removed += remove.toInt();
    }
    if (added > 0 || removed > 0) return (added: added, removed: removed);
  }
  final oldText = (args['old_string'] ?? args['oldText'] ?? '').toString();
  final newText = (args['new_string'] ?? args['newText'] ?? '').toString();
  if (oldText.isNotEmpty || newText.isNotEmpty) {
    return (
      added: newText.isEmpty ? 0 : _lineCount(newText),
      removed: oldText.isEmpty ? 0 : _lineCount(oldText),
    );
  }
  final content = (args['content'] ?? '').toString();
  if (content.isNotEmpty) {
    return (added: _lineCount(content), removed: 0);
  }
  return null;
}

/// diff 行（`-` 旧 / `+` 新），最多 [maxLines] 行。
List<({String marker, String text})> toolStepDiffLines(
  Map<String, dynamic> args, {
  int maxLines = 6,
}) {
  final oldText = (args['old_string'] ?? args['oldText'] ?? '').toString();
  final newText = (args['new_string'] ?? args['newText'] ?? '').toString();
  final lines = <({String marker, String text})>[];
  void add(String text, String marker) {
    for (final line in text.split('\n')) {
      if (lines.length >= maxLines) return;
      if (line.trim().isEmpty && lines.isEmpty) continue;
      lines.add((marker: marker, text: line));
    }
  }

  add(oldText, '-');
  add(newText, '+');
  if (lines.isNotEmpty) return lines;
  final content = (args['content'] ?? '').toString();
  if (content.isNotEmpty) add(content, '+');
  return lines;
}

/// 结果里可读的文本（read/write 的 content、search 的命中行…）。
///
/// JSON 结果**不算**可读文本：结构化结果只走详情面板，聊天行内不倒 JSON。
String? toolStepTextBody(String? result, {int maxLines = 8}) {
  final decoded = _decodeResult(result);
  final body = (decoded?['content'] ?? decoded?['text'] ?? '').toString();
  if (body.trim().isNotEmpty && !toolStepLooksLikeJson(body)) {
    final lines = body.split('\n').take(maxLines).join('\n');
    return lines.trimRight();
  }
  return null;
}

/// 工具步骤的状态点（对齐 dsh 的 `StateDot`）。
class ToolStepStatusDot extends StatelessWidget {
  const ToolStepStatusDot({
    super.key,
    required this.status,
    this.size = 8,
    this.color,
  });

  final ToolStepStatus status;
  final double size;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final resolved =
        color ??
        switch (status) {
          ToolStepStatus.running => cs.primary,
          ToolStepStatus.ok => cs.onSurface.withValues(alpha: 0.35),
          ToolStepStatus.failed => cs.error,
          ToolStepStatus.stopped => const Color(0xFFD79A2B),
        };
    if (status == ToolStepStatus.running) {
      return SizedBox(
        width: size,
        height: size,
        child: CircularProgressIndicator(
          strokeWidth: 1.6,
          valueColor: AlwaysStoppedAnimation<Color>(resolved),
        ),
      );
    }
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(color: resolved, shape: BoxShape.circle),
    );
  }
}

/// 状态 + 耗时的尾标（本地工具此前只有转圈，没有结果状态与耗时）。
///
/// [compactWhenOk]（默认）：正常完成只显示耗时，不写「完成」——每一行都挂状态词
/// 是噪音（对齐 dsh：正常行不加状态词，失败/中断才染色说明）。
///
/// **只放短词**（失败/已中断）：它挂在步骤标题行右侧，长文本（错误原文）会把标题
/// 挤出卡片（用户 2026-10-04 实测「红色报错跑到气泡外面去了」）。错误首行走正文
/// （宽度受卡片约束）。
class ToolStepStatusChip extends StatelessWidget {
  const ToolStepStatusChip({
    super.key,
    required this.status,
    this.duration,
    this.compactWhenOk = true,
  });

  final ToolStepStatus status;
  final Duration? duration;
  final bool compactWhenOk;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    if (status == ToolStepStatus.running) return const SizedBox.shrink();
    if (status == ToolStepStatus.ok && compactWhenOk) {
      if (duration == null) return const SizedBox.shrink();
      return Text(
        formatToolStepDuration(duration!),
        style: TextStyle(
          fontSize: 11,
          color: cs.onSurface.withValues(alpha: 0.45),
        ),
      );
    }
    final color = switch (status) {
      ToolStepStatus.running => cs.primary,
      ToolStepStatus.ok => cs.onSurface.withValues(alpha: 0.45),
      ToolStepStatus.failed => cs.error,
      ToolStepStatus.stopped => const Color(0xFFD79A2B),
    };
    final label = toolStepStatusLabel(l10n, status);
    final text = duration == null
        ? label
        : '$label · ${formatToolStepDuration(duration!)}';
    return Text(
      text,
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
      style: TextStyle(
        fontSize: 11.5,
        fontWeight: AppFontWeights.medium,
        color: color,
      ),
    );
  }
}

String formatToolStepDuration(Duration duration) {
  if (duration.inSeconds < 1) return '${duration.inMilliseconds}ms';
  if (duration.inMinutes < 1) {
    return '${(duration.inMilliseconds / 1000).toStringAsFixed(1)}s';
  }
  final minutes = duration.inMinutes;
  final seconds = duration.inSeconds % 60;
  return '${minutes}m${seconds}s';
}

/// 待办清单块（todo_read / todo_write）：与输入框上方的任务清单面板
/// **共用 [SolabTodoRow]**（同款状态点、配色与删除线）。
class ToolStepTodoList extends StatelessWidget {
  const ToolStepTodoList({
    super.key,
    required this.items,
    this.maxItems = 8,
  });

  final List<Map<String, dynamic>> items;
  final int maxItems;

  static List<Map<String, dynamic>> parse(String? result) {
    final decoded = _decodeResult(result);
    final raw = decoded?['todos'];
    if (raw is! List) return const <Map<String, dynamic>>[];
    return [
      for (final item in raw)
        if (item is Map) Map<String, dynamic>.from(item),
    ];
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final shown = items.take(maxItems).toList(growable: false);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final item in shown)
          Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: SolabTodoRow(
              text: (item['text'] ?? '').toString(),
              status: TodoStatus.fromWire((item['status'] ?? '').toString()),
            ),
          ),
        if (items.length > maxItems)
          Text(
            '…',
            style: TextStyle(
              fontSize: 12,
              color: cs.onSurface.withValues(alpha: 0.5),
            ),
          ),
      ],
    );
  }
}

/// 类型化结果块（P1）：diff / 文本体 / 待办清单。
///
/// 只在折叠态显示前若干行；完整内容仍走「点开详情」（避免把聊天流撑爆）。
class ToolStepResultBlock extends StatelessWidget {
  const ToolStepResultBlock({
    super.key,
    required this.family,
    required this.arguments,
    required this.result,
    this.maxLines = 6,
  });

  final ToolStepFamily family;
  final Map<String, dynamic> arguments;
  final String? result;
  final int maxLines;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    switch (family) {
      case ToolStepFamily.edit:
      case ToolStepFamily.write:
        final lines = toolStepDiffLines(arguments, maxLines: maxLines);
        if (lines.isEmpty) return const SizedBox.shrink();
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            for (final line in lines)
              Text(
                '${line.marker} ${line.text}',
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 11.5,
                  height: 1.35,
                  fontFamily: 'monospace',
                  color: line.marker == '-'
                      ? cs.error.withValues(alpha: 0.85)
                      : cs.primary.withValues(alpha: 0.9),
                ),
              ),
          ],
        );
      case ToolStepFamily.todo:
        final items = ToolStepTodoList.parse(result);
        if (items.isEmpty) return const SizedBox.shrink();
        return ToolStepTodoList(items: items, maxItems: maxLines);
      case ToolStepFamily.read:
      case ToolStepFamily.search:
      case ToolStepFamily.shell:
      case ToolStepFamily.task:
      case ToolStepFamily.apk:
        final body = toolStepTextBody(result, maxLines: maxLines);
        if (body == null) return const SizedBox.shrink();
        return Text(
          body,
          maxLines: maxLines,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: 11.5,
            height: 1.4,
            color: cs.onSurface.withValues(alpha: 0.75),
          ),
        );
      case ToolStepFamily.goal:
      case ToolStepFamily.memory:
      case ToolStepFamily.delivery:
      case ToolStepFamily.workflow:
      case ToolStepFamily.subagent:
      case ToolStepFamily.web:
      case ToolStepFamily.other:
        return const SizedBox.shrink();
    }
  }
}
