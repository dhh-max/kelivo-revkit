import 'dart:async';

import 'dart:convert';
import '../../../core/database/business_preferences.dart';
import 'package:provider/provider.dart';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/custom_bottom_sheet.dart';
import '../../../shared/widgets/snackbar.dart';
import '../../../theme/app_font_weights.dart';
import '../../scheduled_tasks/widgets/scheduled_tasks_scaffold.dart';
import '../models/workflow_models.dart';
import '../services/workflow_store.dart';
import 'workflow_editor_page.dart';
import 'workflow_generate_sheet.dart';
import 'workflow_name_sheet.dart';

/// 工作流列表：AI 生成 / 新建 / 运行 / 编辑 / 重命名 / 复制 / 导出导入 / 删除。
///
/// 2026-10-03 起没有内置模板（用户定性：内置的没用）——所有条目都是用户
/// 手建或 AI 生成落库的；列表顶部常驻一张「AI 生成」入口卡。
class WorkflowListPage extends StatefulWidget {
  const WorkflowListPage({super.key, this.store});

  final WorkflowStore? store;

  @override
  State<WorkflowListPage> createState() => _WorkflowListPageState();
}

class _WorkflowListPageState extends State<WorkflowListPage> {
  late final WorkflowStore _store = widget.store ?? WorkflowStore();
  List<WorkflowDefinition> _flows = const <WorkflowDefinition>[];
  bool _loading = true;
  bool _sheetOpen = false;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    var flows = await _store.all();
    if (flows.isEmpty) {
      // 存量抢救（2026-10-05 数据事故）：早期版本把 `workflows_v1` 当「未知键」
      // 在首跑迁移里导出进 SQLite 并清掉了插件 prefs 副本——老数据可能还在
      // 业务偏好表里躺着。插件 prefs 为空且那边有内容时导回（导回即写进插件
      // prefs 常驻，只做一次）。
      final salvaged = await _salvageFromBusinessPreferences();
      if (salvaged.isNotEmpty) {
        for (final flow in salvaged.reversed) {
          await _store.save(flow);
        }
        flows = await _store.all();
      }
    }
    if (!mounted) return;
    setState(() {
      _flows = flows;
      _loading = false;
    });
  }

  /// 从业务偏好表（SQLite）里找回被旧版迁移清掉的工作流快照。
  Future<List<WorkflowDefinition>> _salvageFromBusinessPreferences() async {
    try {
      final prefs = context.read<BusinessPreferences>();
      final raw = prefs.getString(WorkflowStore.prefsKey);
      if (raw == null || raw.trim().isEmpty) return const <WorkflowDefinition>[];
      final decoded = jsonDecode(raw);
      if (decoded is! List) return const <WorkflowDefinition>[];
      return <WorkflowDefinition>[
        for (final entry in decoded)
          if (WorkflowDefinition.fromJson(entry) case final flow?) flow,
      ];
    } catch (_) {
      // 偏好表不可用（如测试环境没挂 Provider）不影响正常工作流读取。
      return const <WorkflowDefinition>[];
    }
  }

  Future<void> _create() async {
    final l10n = AppLocalizations.of(context)!;
    final flow = WorkflowDefinition(
      id: 'wf${DateTime.now().millisecondsSinceEpoch}',
      name: l10n.workflowNew,
    );
    await _store.save(flow);
    if (!mounted) return;
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => WorkflowEditorPage(workflow: flow, store: _store),
      ),
    );
    await _reload();
  }

  /// AI 生成：先问需求，然后**直接进编辑器画布**流式生成——节点/连线实时
  /// 上屏，成功后编辑器自己落库（2026-10-04 用户要求：不要弹窗干等）。
  Future<void> _generateByAi() async {
    if (_sheetOpen) return;
    _sheetOpen = true;
    String? description;
    try {
      description = await showWorkflowGenerateDialog(context);
    } finally {
      _sheetOpen = false;
    }
    if (!mounted || description == null || description.trim().isEmpty) return;
    final l10n = AppLocalizations.of(context)!;
    // 占位定义：id/名字在生成成功时会被真实结果替换后落库；生成中途退出
    // 不会留下空条目（编辑器只在成功时 save）。
    final placeholder = WorkflowDefinition(
      id: 'wf${DateTime.now().microsecondsSinceEpoch}',
      name: l10n.workflowGenerateRunning,
    );
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => WorkflowEditorPage(
          workflow: placeholder,
          store: _store,
          generateFrom: description,
        ),
      ),
    );
    await _reload();
  }

  Future<void> _toggleEnabled(WorkflowDefinition flow, bool value) async {
    await _store.save(flow.copyWith(enabled: value));
    await _reload();
  }

  Widget _generateEntryCard(ColorScheme cs, AppLocalizations l10n) => Card(
    elevation: 0,
    color: cs.primary.withValues(alpha: 0.08),
    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    child: ListTile(
      onTap: () => unawaited(_generateByAi()),
      leading: Icon(
        Lucide.Sparkles,
        size: 24,
        color: cs.primary,
      ),
      title: Text(
        l10n.workflowGenerateEntry,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(
          fontSize: 14,
          fontWeight: AppFontWeights.emphasis,
          color: cs.primary,
        ),
      ),
      subtitle: Text(
        l10n.workflowGenerateEntrySub,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant),
      ),
      trailing: Icon(
        Lucide.ChevronRight,
        size: 18,
        color: cs.onSurfaceVariant,
      ),
    ),
  );

  Future<void> _open(WorkflowDefinition flow, {bool autoRun = false}) async {
    await Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) =>
            WorkflowEditorPage(workflow: flow, store: _store, autoRun: autoRun),
      ),
    );
    await _reload();
  }

  Future<void> _rename(WorkflowDefinition flow) async {
    if (_sheetOpen) return;
    _sheetOpen = true;
    String? picked;
    try {
      await showCustomBottomSheet<void>(
        context: context,
        title: AppLocalizations.of(context)!.workflowRename,
        builder: (sheetContext, scrollController) => WorkflowNameSheet(
          scrollController: scrollController,
          initial: flow.name,
          onDone: (value) {
            picked = value;
            final route = ModalRoute.of(sheetContext);
            if (route != null && route.isActive) {
              Navigator.of(sheetContext).removeRoute(route);
            }
          },
        ),
      );
    } finally {
      _sheetOpen = false;
    }
    final value = picked?.trim();
    if (value == null || value.isEmpty || value == flow.name) return;
    await _store.save(flow.copyWith(name: value));
    await _reload();
  }

  Future<void> _duplicate(WorkflowDefinition flow) async {
    final l10n = AppLocalizations.of(context)!;
    await _store.save(
      WorkflowDefinition(
        id: 'wf${DateTime.now().millisecondsSinceEpoch}',
        name: l10n.workflowCopySuffix(flow.name),
        nodes: flow.nodes,
        edges: flow.edges,
      ),
    );
    await _reload();
  }

  Future<void> _export(WorkflowDefinition flow) async {
    final l10n = AppLocalizations.of(context)!;
    await Clipboard.setData(ClipboardData(text: flow.encode()));
    if (!mounted) return;
    // 标准通知样式（顶部主题卡片），不再用黑色原生 SnackBar。
    showAppSnackBar(
      context,
      message: l10n.workflowExported,
      type: NotificationType.success,
    );
  }

  Future<void> _import() async {
    final l10n = AppLocalizations.of(context)!;
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    final decoded = WorkflowDefinition.decode(data?.text ?? '');
    if (decoded == null) {
      if (!mounted) return;
      showAppSnackBar(
        context,
        message: l10n.workflowImportFailed,
        type: NotificationType.error,
      );
      return;
    }
    // 导入一律换新 id：直接沿用原 id 会顶掉同名的本地工作流（含内置模板）。
    await _store.save(
      WorkflowDefinition(
        id: 'wf${DateTime.now().millisecondsSinceEpoch}',
        name: decoded.name,
        nodes: decoded.nodes,
        edges: decoded.edges,
      ),
    );
    await _reload();
  }

  Future<void> _delete(WorkflowDefinition flow) async {
    final l10n = AppLocalizations.of(context)!;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        content: Text(l10n.workflowDeleteConfirm(flow.name)),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: Text(MaterialLocalizations.of(context).cancelButtonLabel),
          ),
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: Text(
              l10n.workflowDelete,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await _store.delete(flow.id);
    await _reload();
  }

  Future<void> _showMenu(WorkflowDefinition flow) async {
    if (_sheetOpen) return;
    _sheetOpen = true;
    String? action;
    try {
      await showCustomBottomSheet<void>(
        context: context,
        title: flow.name,
        builder: (sheetContext, scrollController) => _FlowMenuSheet(
          scrollController: scrollController,
          onAction: (picked) {
            action = picked;
            final route = ModalRoute.of(sheetContext);
            if (route != null && route.isActive) {
              Navigator.of(sheetContext).removeRoute(route);
            }
          },
        ),
      );
    } finally {
      _sheetOpen = false;
    }
    if (!mounted || action == null) return;
    switch (action) {
      case 'run':
        await _open(flow, autoRun: true);
      case 'rename':
        await _rename(flow);
      case 'duplicate':
        await _duplicate(flow);
      case 'export':
        await _export(flow);
      case 'delete':
        await _delete(flow);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return Scaffold(
      body: ScheduledTasksScaffold(
        title: l10n.workflowTitle,
        actionIcon: Lucide.ClipboardPaste,
        actionLabel: l10n.workflowImport,
        onAction: () => unawaited(_import()),
        child: Stack(
          children: [
            _loading
                ? const Center(child: CircularProgressIndicator())
                : ListView.builder(
                    padding: const EdgeInsets.fromLTRB(16, 12, 16, 96),
                    itemCount: _flows.length + 1,
                    itemBuilder: (context, index) {
                      if (index == 0) {
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: _generateEntryCard(cs, l10n),
                        );
                      }
                      final flow = _flows[index - 1];
                      return Padding(
                        padding: const EdgeInsets.only(bottom: 8),
                        child: Card(
                          elevation: 0,
                          color: cs.surfaceContainerHighest.withValues(
                            alpha: 0.5,
                          ),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: ListTile(
                            onTap: () => _open(flow),
                            leading: Icon(
                              Lucide.Workflow,
                              size: 24,
                              color: cs.primary.withValues(alpha: 0.85),
                            ),
                            title: Text(
                              flow.name,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                fontSize: 14,
                                fontWeight: AppFontWeights.emphasis,
                              ),
                            ),
                            subtitle: Text(
                              l10n.workflowNodesCount(flow.nodes.length),
                              style: TextStyle(
                                fontSize: 12,
                                color: cs.onSurfaceVariant,
                              ),
                            ),
                            // 单开关（用户 2026-10-03）：这一条在**对话里**是否
                            // 可用（run_workflow 清单与执行只看开着的）；关掉的
                            // 仍可在这里编辑/运行。
                            trailing: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Switch(
                                  value: flow.enabled,
                                  onChanged: (value) =>
                                      unawaited(_toggleEnabled(flow, value)),
                                ),
                                IconButton(
                                  tooltip: l10n.workflowMore,
                                  icon: Icon(
                                    Lucide.MoreVertical,
                                    size: 18,
                                    color: cs.onSurfaceVariant,
                                  ),
                                  onPressed: () => _showMenu(flow),
                                ),
                              ],
                            ),
                          ),
                        ),
                      );
                    },
                  ),
            Positioned(
              right: 16,
              bottom: 16,
              child: FloatingActionButton(
                onPressed: _create,
                tooltip: l10n.workflowNew,
                child: const Icon(Lucide.Plus),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// 列表项动作菜单（移动端用底部弹层，不用右键菜单）。
class _FlowMenuSheet extends StatelessWidget {
  const _FlowMenuSheet({
    required this.scrollController,
    required this.onAction,
  });

  final ScrollController scrollController;
  final ValueChanged<String> onAction;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    Widget row(IconData icon, String label, String value, {Color? color}) =>
        ListTile(
          dense: true,
          contentPadding: EdgeInsets.zero,
          leading: Icon(icon, size: 20, color: color ?? cs.primary),
          title: Text(label, style: TextStyle(fontSize: 14, color: color)),
          onTap: () => onAction(value),
        );
    // 同编辑器：ListTile 需要最近的 Material 祖先（弹层内容外面是 ColoredBox）。
    return Material(
      color: Colors.transparent,
      child: ListView(
        controller: scrollController,
        shrinkWrap: true,
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          row(Lucide.Play, l10n.workflowRun, 'run'),
          row(Lucide.Pencil, l10n.workflowRename, 'rename'),
          row(Lucide.Copy, l10n.workflowDuplicate, 'duplicate'),
          row(Lucide.Export, l10n.workflowExport, 'export'),
          row(Lucide.Trash2, l10n.workflowDelete, 'delete', color: cs.error),
        ],
      ),
    );
  }
}
