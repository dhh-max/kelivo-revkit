import 'dart:async';
import 'dart:io';

import 'package:Kelivo/core/models/workspace.dart';
import 'package:Kelivo/core/providers/memory_provider_v2.dart';
import 'package:Kelivo/core/providers/workspace_provider.dart';
import 'package:Kelivo/core/providers/environment_provider.dart';
import 'package:Kelivo/core/models/environment_state.dart';
import 'package:Kelivo/core/services/haptics.dart';
import 'package:Kelivo/desktop/menu_anchor.dart';
import 'package:Kelivo/features/settings/widgets/custom_theme_widgets.dart';
import 'package:Kelivo/features/workspace/pages/workspace_files_page.dart';
import 'package:Kelivo/features/workspace/pages/workspaces_desktop_layout.dart';
import 'package:Kelivo/features/workspace/pages/workspaces_mobile_layout.dart';
import 'package:Kelivo/features/workspace/widgets/desktop_workspace_create_dialog.dart';
import 'package:Kelivo/features/workspace/widgets/desktop_workspace_button.dart';
import 'package:Kelivo/features/workspace/widgets/desktop_workspaces_view.dart';
import 'package:Kelivo/features/workspace/widgets/files/workspace_prompts.dart';
import 'package:Kelivo/features/solab_apk/services/apk_workspace_binding_service.dart';
import 'package:Kelivo/features/workspace/workspace_layout.dart';
import 'package:Kelivo/icons/lucide_adapter.dart';
import 'package:Kelivo/l10n/app_localizations.dart';
import 'package:Kelivo/shared/widgets/action_sheet.dart';
import 'package:Kelivo/shared/widgets/form_sheet.dart';
import 'package:Kelivo/shared/widgets/ios_checkbox.dart';
import 'package:Kelivo/shared/widgets/ios_form_text_field.dart';
import 'package:Kelivo/shared/widgets/ios_settings_rows.dart';
import 'package:Kelivo/shared/widgets/ios_tactile.dart';
import 'package:Kelivo/shared/widgets/ios_tile_button.dart';
import 'package:Kelivo/shared/widgets/section_card.dart';
import 'package:Kelivo/shared/widgets/snackbar.dart';
import 'package:Kelivo/shared/widgets/task_progress_dialog.dart';
import 'package:Kelivo/theme/app_font_weights.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:path/path.dart' as p;
import 'package:permission_handler/permission_handler.dart';
import 'package:provider/provider.dart';

enum _CreateWorkspaceMode { managed, importFromFolder }

class _CreateWorkspaceDraft {
  const _CreateWorkspaceDraft({required this.name, required this.mode});

  final String name;
  final _CreateWorkspaceMode mode;
}

/// Opens the create-workspace sheet (mobile) or dialog (desktop).
Future<Workspace?> showCreateWorkspaceFlow(BuildContext context) async {
  if (useDesktopWorkspaceLayout(context)) {
    return showAppDialog<Workspace>(
      context,
      maxWidth: 540,
      child: DesktopWorkspaceCreateDialog(
        provider: context.read<WorkspaceProvider>(),
      ),
    );
  }
  final draft = await _promptCreateWorkspace(context);
  if (draft == null || !context.mounted) return null;
  return _materializeWorkspace(context, draft);
}

Future<void> openWorkspacesPage(BuildContext context) {
  if (useDesktopWorkspaceLayout(context)) {
    return showAppDialog<void>(
      context,
      maxWidth: 1120,
      child: SizedBox(
        height: MediaQuery.sizeOf(context).height * 0.82,
        child: Column(
          children: [
            AppDialogHeader(
              title: AppLocalizations.of(context)!.workspacesTitle,
            ),
            const Expanded(child: WorkspacesPane(showHeader: false)),
          ],
        ),
      ),
    );
  }
  return Navigator.of(
    context,
  ).push<void>(MaterialPageRoute<void>(builder: (_) => const WorkspacesPage()));
}

class WorkspacesPage extends StatelessWidget {
  const WorkspacesPage({super.key});

  @override
  Widget build(BuildContext context) {
    if (useDesktopWorkspaceLayout(context)) {
      return const WorkspacesDesktopLayout();
    }
    return const WorkspacesMobileLayout();
  }
}

class WorkspacesPane extends StatefulWidget {
  const WorkspacesPane({super.key, this.showHeader = true});

  final bool showHeader;

  static const Key createKey = ValueKey<String>('workspaces-create');
  static const Key emptyKey = ValueKey<String>('workspaces-empty');
  static const Key listKey = ValueKey<String>('workspaces-list');

  static Key itemKey(String id) => ValueKey<String>('workspaces-item-$id');

  static Key itemMoreKey(String id) =>
      ValueKey<String>('workspaces-item-more-$id');

  static Key actionKey(String name) =>
      ValueKey<String>('workspaces-action-$name');

  @override
  State<WorkspacesPane> createState() => WorkspacesPaneState();
}

class WorkspacesPaneState extends State<WorkspacesPane> {
  @visibleForTesting
  Future<Workspace> createManaged(String name) async {
    // P1「工作区即项目」：新建工作区默认落在**用户可见目录**
    // （`/storage/emulated/0/SoLab/<名字>`），产物取出来不需要 root；拿不到外部
    // 存储（没授权/异常）时回落到 app 私有目录，不阻断创建。
    final provider = context.read<WorkspaceProvider>();
    final visible = await WorkspaceProvider.visibleRootFor(name);
    return provider.create(name: name, hostPath: visible);
  }

  List<Workspace> _sorted(List<Workspace> workspaces) {
    final copy = List<Workspace>.from(workspaces);
    copy.sort((a, b) {
      final aUsed = a.lastUsedAt;
      final bUsed = b.lastUsedAt;
      if (aUsed == null && bUsed == null) {
        return a.name.toLowerCase().compareTo(b.name.toLowerCase());
      }
      if (aUsed == null) return 1;
      if (bUsed == null) return -1;
      return bUsed.compareTo(aUsed);
    });
    return copy;
  }

  Future<void> _createWorkspace() async {
    await showCreateWorkspaceFlow(context);
  }

  Future<void> _rename(Workspace workspace) async {
    final l10n = AppLocalizations.of(context)!;
    final name = await showWorkspaceNamePrompt(
      context: context,
      title: l10n.workspaceFilesRename,
      label: l10n.workspacesNameLabel,
      hint: l10n.workspacesNameHint,
      confirmLabel: l10n.workspaceFilesSave,
      initial: workspace.name,
    );
    if (name == null || !mounted) return;
    await context.read<WorkspaceProvider>().update(
      workspace.copyWith(name: name),
    );
  }

  Future<void> _editSettings(Workspace workspace) async {
    await showWorkspaceSettingsEditor(context, workspace);
  }

  Future<void> _delete(Workspace workspace) async {
    final l10n = AppLocalizations.of(context)!;
    final linked = workspace.kind == WorkspaceKind.linked;
    var deleteFiles = !linked;
    // 项目记忆（按工作区隔离的一般记忆）在工作区消失后会变成孤儿：既不会被
    // 注入、工具也读不到。删除前先把条数摆出来，让用户决定去向（用户 2026-10-04）。
    // 可空读取：独立挂载（测试、设置页预览）可能没有 MemoryProviderV2，缺了就
    // 按「没有项目记忆」处理，不能因此把删除功能整个打没。
    final memoryProvider = context.read<MemoryProviderV2?>();
    var projectMemoryCount = 0;
    try {
      final all = await memoryProvider?.repository.readAll();
      projectMemoryCount = (all ?? const [])
          .where((entry) => entry.projectId == workspace.id)
          .length;
    } catch (_) {
      projectMemoryCount = 0;
    }
    if (!mounted) return;
    var memoryAction = _ProjectMemoryAction.keep;
    final confirmed = await showWorkspaceConfirm(
      context: context,
      title: linked ? l10n.workspacesUnlinkTitle : l10n.workspacesDeleteTitle,
      message: linked
          ? l10n.workspacesUnlinkMessage(workspace.name)
          : l10n.workspacesDeleteMessage(workspace.name),
      confirmLabel: linked ? l10n.workspacesUnlink : l10n.workspaceFilesDelete,
      destructive: true,
      extra: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (projectMemoryCount > 0) ...[
            _ProjectMemoryChoice(
              count: projectMemoryCount,
              value: memoryAction,
              onChanged: (value) => memoryAction = value,
            ),
            const SizedBox(height: 10),
          ],
          if (!linked)
            _DeleteFilesToggle(
              label: l10n.workspacesDeleteAlsoFiles,
              value: deleteFiles,
              onChanged: (value) => deleteFiles = value,
            ),
        ],
      ),
    );
    if (!confirmed || !mounted) return;
    // 记忆先处理（此时工作区 id 还在，语义清楚）。
    if (projectMemoryCount > 0 && memoryProvider != null) {
      switch (memoryAction) {
        case _ProjectMemoryAction.keep:
          break;
        case _ProjectMemoryAction.release:
          await memoryProvider.releaseProjectMemories(workspace.id);
        case _ProjectMemoryAction.delete:
          await memoryProvider.deleteProjectMemories(workspace.id);
      }
    }
    if (!mounted) return;
    await context.read<WorkspaceProvider>().delete(
      workspace.id,
      deleteFiles: linked ? false : deleteFiles,
    );
  }

  void _openFiles(Workspace workspace) {
    unawaited(WorkspaceFilesPage.open(context, workspaceId: workspace.id));
  }

  Future<void> _showItemActions(
    Workspace workspace, {
    Offset? globalPosition,
  }) async {
    final l10n = AppLocalizations.of(context)!;
    await showAdaptiveActionMenu(
      context,
      anchor: globalPosition ?? DesktopMenuAnchor.positionOrCenter(context),
      title: l10n.workspacesItemMore,
      items: [
        ActionSheetItem(
          icon: Lucide.Pencil,
          label: l10n.workspaceFilesRename,
          onTap: () => unawaited(_rename(workspace)),
        ),
        ActionSheetItem(
          icon: Lucide.Settings,
          label: l10n.workspacesSettings,
          onTap: () => unawaited(_editSettings(workspace)),
        ),
        // 默认工作区不可删除/解绑（用户 2026-10-04 明确要求）：它是「不挂环境、
        // 直接可用」的常驻兜底，删了未绑定会话就没有根。
        if (!workspace.isDefault)
          ActionSheetItem(
            icon: Lucide.Trash,
            label: workspace.kind == WorkspaceKind.linked
                ? l10n.workspacesUnlink
                : l10n.workspaceFilesDelete,
            destructive: true,
            onTap: () => unawaited(_delete(workspace)),
          ),
      ],
    );
  }

  Widget _header(AppLocalizations l10n, ColorScheme cs) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(4, 0, 4, 8),
      child: Row(
        children: [
          Expanded(
            child: Text(
              l10n.workspacesTitle,
              style: TextStyle(
                fontSize: 16,
                fontWeight: AppFontWeights.emphasis,
                color: cs.onSurface,
              ),
            ),
          ),
          IosIconButton(
            key: WorkspacesPane.createKey,
            icon: Lucide.Plus,
            tooltip: l10n.workspaceMgmtNewWorkspace,
            semanticLabel: l10n.workspaceMgmtNewWorkspace,
            onTap: () {
              Haptics.light();
              unawaited(_createWorkspace());
            },
          ),
        ],
      ),
    );
  }

  Widget _emptyState(AppLocalizations l10n, ColorScheme cs) {
    final child = Padding(
      key: WorkspacesPane.emptyKey,
      padding: const EdgeInsets.symmetric(vertical: 48, horizontal: 24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Lucide.FolderCode,
            size: 44,
            color: cs.onSurface.withValues(alpha: 0.26),
          ),
          const SizedBox(height: 12),
          Text(
            l10n.workspacesEmpty,
            textAlign: TextAlign.center,
            style: TextStyle(
              fontSize: 15,
              fontWeight: AppFontWeights.semibold,
              color: cs.onSurface.withValues(alpha: 0.72),
            ),
          ),
          const SizedBox(height: 6),
          Text(
            l10n.workspaceMgmtEmptyHint,
            textAlign: TextAlign.center,
            style: TextStyle(
              fontSize: 12.5,
              color: cs.onSurface.withValues(alpha: 0.52),
            ),
          ),
          const SizedBox(height: 16),
          IosTileButton(
            icon: Lucide.Plus,
            label: l10n.workspaceMgmtNewWorkspace,
            onTap: () => unawaited(_createWorkspace()),
          ),
        ],
      ),
    );
    return child.animate().fadeIn(duration: 200.ms);
  }

  Widget _list(List<Workspace> workspaces, AppLocalizations l10n) {
    return SectionCard(
      key: WorkspacesPane.listKey,
      children: [
        for (var i = 0; i < workspaces.length; i++) ...[
          if (i > 0) const IosRowDivider(),
          _WorkspaceRow(
            workspace: workspaces[i],
            // 还没设目录的默认工作区：点它直接进设置去选目录（不是打开文件浏览器
            // ——那时根本没根）。
            onOpen: () => workspaces[i].needsRoot
                ? unawaited(_editSettings(workspaces[i]))
                : _openFiles(workspaces[i]),
            onMore: (pos) =>
                unawaited(_showItemActions(workspaces[i], globalPosition: pos)),
          ),
        ],
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final provider = context.watch<WorkspaceProvider>();
    final workspaces = _sorted(provider.workspaces);
    if (useDesktopWorkspaceLayout(context)) {
      return DesktopWorkspacesView(
        workspaces: workspaces,
        showHeader: widget.showHeader,
        onCreate: () => showCreateWorkspaceFlow(context),
        onMore: (workspace, position) =>
            unawaited(_showItemActions(workspace, globalPosition: position)),
      );
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final header = widget.showHeader ? _header(l10n, cs) : null;
        if (workspaces.isEmpty) {
          final empty = _emptyState(l10n, cs);
          if (!constraints.hasBoundedHeight) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              mainAxisSize: MainAxisSize.min,
              children: [if (header != null) header, empty],
            );
          }
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (header != null) header,
              Expanded(
                child: LayoutBuilder(
                  builder: (context, inner) {
                    return SingleChildScrollView(
                      child: ConstrainedBox(
                        constraints: BoxConstraints(minHeight: inner.maxHeight),
                        child: Center(child: empty),
                      ),
                    );
                  },
                ),
              ),
            ],
          );
        }

        final list = _list(workspaces, l10n);
        // 默认工作区还没设目录：在列表上方把话说清楚（别让用户以为"哪里不对"）。
        final needsRootHint = workspaces.any((workspace) => workspace.needsRoot)
            ? Padding(
                padding: const EdgeInsets.fromLTRB(4, 0, 4, 8),
                child: Text(
                  '默认工作区还没设置工作目录：点它选一个可见目录'
                  '（把 APK 放进去就能直接改），或者新建一个工作区做项目隔离。',
                  style: TextStyle(
                    fontSize: 12.5,
                    height: 1.4,
                    color: cs.error,
                  ),
                ),
              )
            : null;
        if (!constraints.hasBoundedHeight) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            mainAxisSize: MainAxisSize.min,
            children: [
              if (header != null) header,
              if (needsRootHint != null) needsRootHint,
              list,
            ],
          );
        }
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (header != null) header,
            if (needsRootHint != null) needsRootHint,
            Expanded(child: SingleChildScrollView(child: list)),
          ],
        );
      },
    );
  }
}

class _WorkspaceRow extends StatelessWidget {
  const _WorkspaceRow({
    required this.workspace,
    required this.onOpen,
    required this.onMore,
  });

  final Workspace workspace;
  final VoidCallback onOpen;
  final ValueChanged<Offset?> onMore;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    // 默认工作区（常驻、不可删除）：用户 2026-10-04「搞一个默认的，就是不能删除的
    // 一个，用来不挂环境、直接可用」——它在列表里必须一眼可辨。
    final isDefault = workspace.isDefault;
    // 还没设目录时**提示去设置**（用户 2026-10-04：「没有就让设置啊，别默认」）。
    final needsRoot = workspace.needsRoot;
    // 用户 2026-10-06：副标题要如实反映「挂载/直连 + 虚拟环境可用性」——
    // 默认工作区过去固定写「不挂环境」，与它真实的 envMode 已经对不上了。
    final envReady = _environmentReady(context);
    final kind = needsRoot
        ? '未设置工作目录 · 点这里选一个'
        : workspace.envMode == WorkspaceEnvMode.sandbox
        ? (envReady == null
              ? l10n.workspaceRowSandboxUnknown
              : envReady
              ? l10n.workspaceRowSandboxReady
              : l10n.workspaceRowSandboxUnavailable)
        : isDefault
        ? l10n.workspaceRowDirectDefault
        : workspace.kind == WorkspaceKind.linked
        ? l10n.workspaceFilesKindLinked
        : l10n.workspaceFilesKindManaged;
    final used = workspace.lastUsedAt;
    final detail = (isDefault || needsRoot)
        ? kind
        : used == null
        ? l10n.workspaceMgmtRowDetailNever(kind)
        : l10n.workspaceMgmtRowDetail(
            kind,
            workspaceMgmtRelativeTime(l10n, used),
          );

    final row = IosNavRow(
      key: WorkspacesPane.itemKey(workspace.id),
      icon: isDefault
          ? Lucide.Bookmark
          : workspace.kind == WorkspaceKind.linked
          ? Lucide.Link
          : Lucide.FolderCode,
      label: workspace.name,
      labelWeight: AppFontWeights.medium,
      subtitle: detail,
      onTap: onOpen,
      onLongPress: () => onMore(null),
      trailing: Builder(
        builder: (buttonContext) {
          return IosIconButton(
            key: WorkspacesPane.itemMoreKey(workspace.id),
            icon: Lucide.Ellipsis,
            size: 18,
            tooltip: l10n.workspacesItemMore,
            semanticLabel: l10n.workspacesItemMore,
            onTap: () {
              final box = buttonContext.findRenderObject();
              if (box is RenderBox) {
                onMore(box.localToGlobal(box.size.center(Offset.zero)));
              } else {
                onMore(null);
              }
            },
          );
        },
      ),
    );
    return GestureDetector(
      onSecondaryTapDown: (details) {
        DesktopMenuAnchor.setPosition(details.globalPosition);
        onMore(details.globalPosition);
      },
      child: row,
    );
  }
}

/// 删工作区时项目记忆的去向。
enum _ProjectMemoryAction { keep, release, delete }

/// 项目记忆去向选择（只在确实有项目记忆时出现）。
///
/// 用户 2026-10-04：删工作区后项目记忆会变成「谁都看不到、也找不到入口清理」的
/// 孤儿，所以删除前必须给出选择——默认「保留」（最安全，之后可在记忆页处理）。
class _ProjectMemoryChoice extends StatefulWidget {
  const _ProjectMemoryChoice({
    required this.count,
    required this.value,
    required this.onChanged,
  });

  final int count;
  final _ProjectMemoryAction value;
  final ValueChanged<_ProjectMemoryAction> onChanged;

  @override
  State<_ProjectMemoryChoice> createState() => _ProjectMemoryChoiceState();
}

class _ProjectMemoryChoiceState extends State<_ProjectMemoryChoice> {
  late _ProjectMemoryAction _value = widget.value;

  void _select(_ProjectMemoryAction value) {
    setState(() => _value = value);
    widget.onChanged(value);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    return Container(
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest.withValues(alpha: 0.45),
        borderRadius: BorderRadius.circular(12),
      ),
      padding: const EdgeInsets.fromLTRB(12, 10, 12, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Lucide.bookHeart, size: 16, color: cs.primary),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  l10n.workspacesDeleteMemoryCount(widget.count),
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: AppFontWeights.semibold,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          for (final action in _ProjectMemoryAction.values)
            IosCardPress(
              onTap: () => _select(action),
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                children: [
                  IosCheckbox(
                    value: _value == action,
                    semanticLabel: switch (action) {
                      _ProjectMemoryAction.keep =>
                        l10n.workspacesDeleteMemoryKeep,
                      _ProjectMemoryAction.release =>
                        l10n.workspacesDeleteMemoryRelease,
                      _ProjectMemoryAction.delete =>
                        l10n.workspacesDeleteMemoryDelete,
                    },
                    onChanged: (_) => _select(action),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      switch (action) {
                        _ProjectMemoryAction.keep =>
                          l10n.workspacesDeleteMemoryKeep,
                        _ProjectMemoryAction.release =>
                          l10n.workspacesDeleteMemoryRelease,
                        _ProjectMemoryAction.delete =>
                          l10n.workspacesDeleteMemoryDelete,
                      },
                      style: const TextStyle(fontSize: 13, height: 1.3),
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}

class _DeleteFilesToggle extends StatefulWidget {
  const _DeleteFilesToggle({
    required this.label,
    required this.value,
    required this.onChanged,
  });

  final String label;
  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  State<_DeleteFilesToggle> createState() => _DeleteFilesToggleState();
}

class _DeleteFilesToggleState extends State<_DeleteFilesToggle> {
  late bool _value = widget.value;

  @override
  Widget build(BuildContext context) {
    return IosCardPress(
      onTap: () {
        setState(() => _value = !_value);
        widget.onChanged(_value);
      },
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          IosCheckbox(
            value: _value,
            semanticLabel: widget.label,
            onChanged: (value) {
              setState(() => _value = value);
              widget.onChanged(value);
            },
          ),
          const SizedBox(width: 8),
          Expanded(child: Text(widget.label)),
        ],
      ),
    );
  }
}

Future<_CreateWorkspaceDraft?> _promptCreateWorkspace(
  BuildContext context,
) async {
  return showFormSheet<_CreateWorkspaceDraft>(
    context,
    builder: (ctx) => const _CreateWorkspaceForm(),
  );
}

class _CreateWorkspaceForm extends StatefulWidget {
  const _CreateWorkspaceForm();

  @override
  State<_CreateWorkspaceForm> createState() => _CreateWorkspaceFormState();
}

class _CreateWorkspaceFormState extends State<_CreateWorkspaceForm> {
  final TextEditingController _nameController = TextEditingController();
  _CreateWorkspaceMode _mode = _CreateWorkspaceMode.managed;

  @override
  void dispose() {
    _nameController.dispose();
    super.dispose();
  }

  void _submit() {
    final name = _nameController.text.trim();
    if (name.isEmpty) return;
    Navigator.of(context).pop(_CreateWorkspaceDraft(name: name, mode: _mode));
  }

  Widget _kindCheck(bool selected) {
    final cs = Theme.of(context).colorScheme;
    return selected
        ? Icon(Lucide.Check, size: 18, color: cs.primary)
        : const SizedBox.shrink();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final canCreate = _nameController.text.trim().isNotEmpty;
    final children = <Widget>[
      SectionCard(
        children: [
          IosFormTextField(
            label: l10n.workspacesNameLabel,
            controller: _nameController,
            hintText: l10n.workspacesNameHint,
            inlineLabel: false,
            autofocus: true,
            onChanged: (_) => setState(() {}),
          ),
        ],
      ),
      IosSectionHeader(text: l10n.workspaceMgmtKindSection),
      SectionCard(
        children: [
          IosNavRow(
            icon: Lucide.FolderCode,
            label: l10n.workspaceMgmtKindManagedTitle,
            subtitle: l10n.workspaceMgmtKindManagedSubtitle,
            labelWeight: AppFontWeights.medium,
            trailing: _kindCheck(_mode == _CreateWorkspaceMode.managed),
            onTap: () => setState(() => _mode = _CreateWorkspaceMode.managed),
          ),
          const IosRowDivider(),
          IosNavRow(
            icon: Lucide.FolderInput,
            label: l10n.workspaceMgmtImportFromFolder,
            subtitle: l10n.workspaceMgmtImportFromFolderSubtitle,
            labelWeight: AppFontWeights.medium,
            trailing: _kindCheck(
              _mode == _CreateWorkspaceMode.importFromFolder,
            ),
            onTap: () =>
                setState(() => _mode = _CreateWorkspaceMode.importFromFolder),
          ),
        ],
      ),
    ];
    final actions = FormSheetActions(
      key: const ValueKey<String>('workspaces-create-confirm'),
      cancelLabel: l10n.workspaceFilesCancel,
      confirmLabel: l10n.workspaceMgmtCreate,
      onCancel: () => Navigator.of(context).pop(),
      onConfirm: canCreate ? _submit : null,
    );

    return FormSheet(
      title: l10n.workspacesCreateTitle,
      actions: actions,
      children: children,
    );
  }
}

Future<Workspace?> _materializeWorkspace(
  BuildContext context,
  _CreateWorkspaceDraft draft,
) async {
  final provider = context.read<WorkspaceProvider>();
  switch (draft.mode) {
    case _CreateWorkspaceMode.managed:
      // P1：新建默认落可见目录（取产物不需要 root）；拿不到就回落到私有目录。
      final visible = await WorkspaceProvider.visibleRootFor(draft.name);
      return provider.create(name: draft.name, hostPath: visible);
    case _CreateWorkspaceMode.importFromFolder:
      return _importFromFolder(context, draft.name);
  }
}

Future<Workspace?> _importFromFolder(BuildContext context, String name) async {
  final l10n = AppLocalizations.of(context)!;
  String? path;
  try {
    path = await FilePicker.platform.getDirectoryPath(
      dialogTitle: l10n.workspaceMgmtImportFromFolder,
    );
  } catch (_) {
    path = null;
  }
  if (!context.mounted) return null;
  if (path == null) {
    showAppSnackBar(
      context,
      message: l10n.workspaceMgmtFolderPickerUnavailable,
      type: NotificationType.info,
    );
    return null;
  }

  final provider = context.read<WorkspaceProvider>();
  var fraction = 0.0;
  var outcome = TaskProgressOutcome.running;
  var phase = l10n.workspaceMgmtImportProgressPhase;
  Object? error;
  VoidCallback? refresh;

  final dialogFuture = showAppDialog<void>(
    context,
    dismissible: false,
    child: StatefulBuilder(
      builder: (ctx, setLocal) {
        refresh = () => setLocal(() {});
        return Padding(
          padding: const EdgeInsets.fromLTRB(20, 20, 20, 16),
          child: TaskProgressDialogCard(
            title: l10n.workspaceMgmtImportProgressTitle,
            phaseLabel: phase,
            fraction: fraction,
            phaseIcon: Lucide.FolderInput,
            cancellable: false,
            outcome: outcome,
            onAcknowledge: outcome == TaskProgressOutcome.failure
                ? () => Navigator.of(ctx).pop()
                : null,
            acknowledgeLabel: l10n.workspaceFilesCancel,
          ),
        );
      },
    ),
  );

  Workspace? created;
  try {
    created = await provider.create(name: name);
    final dest = await provider.hostRootFor(created);
    await _copyDirectoryTree(
      Directory(path),
      Directory(dest),
      onProgress: (value) {
        fraction = value;
        refresh?.call();
      },
    );
    outcome = TaskProgressOutcome.success;
    phase = l10n.workspaceMgmtImportDone(name);
    refresh?.call();
    await Future<void>.delayed(const Duration(milliseconds: 280));
    if (context.mounted) Navigator.of(context, rootNavigator: true).pop();
    if (context.mounted) {
      showAppSnackBar(
        context,
        message: l10n.workspaceMgmtImportDone(name),
        type: NotificationType.success,
      );
    }
  } catch (e) {
    error = e;
    outcome = TaskProgressOutcome.failure;
    phase = l10n.workspaceMgmtImportFailed;
    refresh?.call();
    if (created != null) {
      await provider.delete(created.id, deleteFiles: true);
      created = null;
    }
  }
  await dialogFuture;
  if (error != null && context.mounted) {
    showAppSnackBar(
      context,
      message: l10n.workspaceMgmtImportFailed,
      type: NotificationType.error,
    );
  }
  return created;
}

Future<void> _copyDirectoryTree(
  Directory source,
  Directory dest, {
  required ValueChanged<double> onProgress,
}) async {
  if (!await dest.exists()) {
    await dest.create(recursive: true);
  }
  final files = <File>[];
  await for (final entity in source.list(recursive: true, followLinks: false)) {
    if (entity is File) files.add(entity);
    if (entity is Directory) {
      final rel = p.relative(entity.path, from: source.path);
      await Directory(p.join(dest.path, rel)).create(recursive: true);
    }
  }
  if (files.isEmpty) {
    onProgress(1);
    return;
  }
  var done = 0;
  for (final file in files) {
    final rel = p.relative(file.path, from: source.path);
    final target = File(p.join(dest.path, rel));
    await target.parent.create(recursive: true);
    await file.copy(target.path);
    done += 1;
    onProgress(done / files.length);
  }
}

/// 选一个宿主目录（工作区根 / 默认工作区目录）。
///
/// Android 11+ 需要「所有文件访问」（`MANAGE_EXTERNAL_STORAGE`）：拒绝/受限时当场
/// 提示并返回 null，不要静默失败。返回 null = 用户取消或没权限。
Future<String?> pickHostDirectory(BuildContext context) async {
  final manage = Permission.manageExternalStorage;
  final current = await manage.status;
  var granted = current.isGranted;
  if (current.isRestricted) {
    // Android 10 及以下没有「所有文件访问」开关：走旧版存储运行时权限。
    granted = (await Permission.storage.request()).isGranted;
  } else if (!granted) {
    // request() 在部分 ROM 会抛 PlatformException，不能让它中断流程。
    await manage.request().onError((_, __) => manage.status);
    granted = await manage.isGranted;
  }
  if (!granted) {
    if (context.mounted) {
      showAppSnackBar(
        context,
        message: '需要「所有文件访问」权限才能选择目录',
        type: NotificationType.error,
      );
    }
    return null;
  }
  final path = await FilePicker.platform.getDirectoryPath();
  if (path == null || path.trim().isEmpty) return null;
  return path.trim();
}

Future<void> showWorkspaceSettingsEditor(
  BuildContext context,
  Workspace workspace,
) async {
  final l10n = AppLocalizations.of(context)!;
  if (useDesktopWorkspaceLayout(context)) {
    await showAppDialog<void>(
      context,
      maxWidth: 480,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          AppDialogHeader(title: l10n.workspacesSettingsTitle),
          Flexible(
            child: SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(20, 0, 20, 16),
              child: _WorkspaceSettingsForm(
                workspaceId: workspace.id,
                desktop: true,
              ),
            ),
          ),
        ],
      ),
    );
    return;
  }
  await showFormSheet<void>(
    context,
    builder: (ctx) =>
        _WorkspaceSettingsForm(workspaceId: workspace.id, desktop: false),
  );
}

class _WorkspaceSettingsForm extends StatefulWidget {
  const _WorkspaceSettingsForm({
    required this.workspaceId,
    required this.desktop,
  });

  final String workspaceId;
  final bool desktop;

  @override
  State<_WorkspaceSettingsForm> createState() => _WorkspaceSettingsFormState();
}

class _WorkspaceSettingsFormState extends State<_WorkspaceSettingsForm> {
  TextEditingController? _nameController;
  bool? _shellNeedsApproval;
  String? _defaultCwd;
  WorkspaceEnvMode? _envMode;
  String? _hostPath;
  bool _cwdBusy = false;

  Workspace? get _workspace =>
      context.read<WorkspaceProvider>().byId(widget.workspaceId);

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final workspace = context.read<WorkspaceProvider>().byId(
      widget.workspaceId,
    );
    if (workspace == null) return;
    _nameController ??= TextEditingController(text: workspace.name);
    _shellNeedsApproval ??= workspace.shellNeedsApproval;
    _defaultCwd ??= workspace.defaultCwd;
    _envMode ??= workspace.envMode;
    _hostPath ??= workspace.hostPath;
  }

  /// 选工作区根目录。默认工作区同时同步「工作台目录」旧键（APK 工具链在无会话
  /// 上下文时仍读它，两处必须一致）。
  Future<void> _pickHostPath() async {
    final picked = await pickHostDirectory(context);
    if (picked == null || !mounted) return;
    setState(() => _hostPath = picked);
    if (_workspace?.isDefault ?? false) {
      await ApkWorkspaceBindingService.setWorkDir(picked);
    }
  }

  @override
  void dispose() {
    _nameController?.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final workspace = _workspace;
    final controller = _nameController;
    if (workspace == null || controller == null) return;
    final name = controller.text.trim();
    if (name.isEmpty) return;
    await context.read<WorkspaceProvider>().update(
      workspace.copyWith(
        name: name,
        envMode: _envMode ?? workspace.envMode,
        hostPath: _hostPath ?? workspace.hostPath,
        shellNeedsApproval: _shellNeedsApproval ?? workspace.shellNeedsApproval,
        defaultCwd: _defaultCwd ?? workspace.defaultCwd,
      ),
    );
    if (mounted) Navigator.of(context).pop();
  }

  Future<void> _pickCwd() async {
    final workspace = _workspace;
    if (workspace == null || _cwdBusy) return;
    setState(() => _cwdBusy = true);
    try {
      final l10n = AppLocalizations.of(context)!;
      final root = await context.read<WorkspaceProvider>().hostRootFor(
        workspace,
      );
      if (!mounted) return;
      final picked = await showWorkspaceFolderPicker(
        context,
        root: root,
        initialRelPath: _defaultCwd ?? workspace.defaultCwd,
        title: l10n.workspaceMgmtPickCwdTitle,
      );
      if (picked == null || !mounted) return;
      setState(() => _defaultCwd = picked);
    } finally {
      if (mounted) setState(() => _cwdBusy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final workspace = context.watch<WorkspaceProvider>().byId(
      widget.workspaceId,
    );
    if (workspace == null) {
      return const SizedBox.shrink();
    }
    final controller = _nameController;
    final approval = _shellNeedsApproval ?? workspace.shellNeedsApproval;
    final cwdRaw = _defaultCwd ?? workspace.defaultCwd;
    if (controller == null) {
      return const Center(child: CupertinoActivityIndicator(radius: 12));
    }
    final cwd = cwdRaw.trim().isEmpty
        ? l10n.workspaceMgmtDefaultCwdRoot
        : cwdRaw;
    final canSave = controller.text.trim().isNotEmpty;
    final children = <Widget>[
      SectionCard(
        children: [
          IosFormTextField(
            label: l10n.workspacesNameLabel,
            controller: controller,
            hintText: l10n.workspacesNameHint,
            inlineLabel: false,
            onChanged: (_) => setState(() {}),
          ),
        ],
      ),
      const SizedBox(height: 12),
      SectionCard(
        children: [
          // 工作区根目录（用户 2026-10-04：工作目录归工作区管，APK 工作台里那行删了）。
          // 默认工作区在这里改就是改「本机目录」；其它工作区改就是换根。
          IosNavRow(
            icon: Lucide.FolderOpen,
            label: '工作目录',
            subtitle: ((_hostPath ?? workspace.hostPath) ?? '').trim().isEmpty
                ? '应用私有目录（未指定）'
                : (_hostPath ?? workspace.hostPath)!,
            onTap: () => unawaited(_pickHostPath()),
          ),
          const IosRowDivider(),
          // P1「工作区即项目」：环境模式是**工作区的属性**（用户 2026-10-04 批准）。
          // 关 = 直连 Android 文件系统（就是「APK 工作台目录」那套，产物用户自己
          // 就能取出）；开 = 挂 Linux（PRoot）环境，工作区根成为沙盒 /workspace。
          FormSheetSwitchRow(
            label: '挂载 Linux 环境（沙盒）',
            value: (_envMode ?? workspace.envMode) == WorkspaceEnvMode.sandbox,
            onChanged: (value) => setState(
              () => _envMode = value
                  ? WorkspaceEnvMode.sandbox
                  : WorkspaceEnvMode.direct,
            ),
          ),
          if ((_envMode ?? workspace.envMode) == WorkspaceEnvMode.sandbox)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              child: Text(
                _environmentReady(context) == true
                    ? l10n.workspaceEnvMountHintReady
                    : l10n.workspaceEnvMountHintUnavailable,
                style: TextStyle(
                  fontSize: 12,
                  height: 1.35,
                  color: _environmentReady(context) == true
                      ? Theme.of(context).colorScheme.primary
                      : Theme.of(context).colorScheme.error,
                ),
              ),
            ),
          const IosRowDivider(),
          FormSheetSwitchRow(
            label: l10n.workspacesShellNeedsApproval,
            value: approval,
            onChanged: (value) => setState(() => _shellNeedsApproval = value),
          ),
          const IosRowDivider(),
          IosNavRow(
            icon: Lucide.FolderCode,
            label: l10n.workspacesDefaultCwd,
            detailText: cwd,
            trailing: _cwdBusy
                ? const CupertinoActivityIndicator(radius: 8)
                : null,
            onTap: _cwdBusy ? null : () => unawaited(_pickCwd()),
          ),
        ],
      ),
    ];
    final actions = FormSheetActions(
      cancelLabel: l10n.workspaceFilesCancel,
      confirmLabel: l10n.workspaceFilesSave,
      onCancel: () => Navigator.of(context).pop(),
      onConfirm: canSave ? () => unawaited(_save()) : null,
    );

    if (widget.desktop) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ...children,
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              DesktopWorkspaceButton(
                label: l10n.workspaceFilesCancel,
                icon: Lucide.X,
                onPressed: () => Navigator.of(context).pop(),
              ),
              const SizedBox(width: 8),
              DesktopWorkspaceButton(
                label: l10n.workspaceFilesSave,
                icon: Lucide.Check,
                primary: true,
                onPressed: canSave ? () => unawaited(_save()) : null,
              ),
            ],
          ),
        ],
      );
    }

    return FormSheet(
      title: l10n.workspacesSettingsTitle,
      actions: actions,
      children: children,
    );
  }
}

/// 虚拟环境是否就绪（null = 读不到 provider，按未知显示）。
bool? _environmentReady(BuildContext context) {
  try {
    return context.watch<EnvironmentProvider>().state.phase ==
        EnvironmentPhase.ready;
  } catch (_) {
    return null;
  }
}

String workspaceMgmtRelativeTime(AppLocalizations l10n, DateTime at) {
  final delta = DateTime.now().difference(at.toLocal());
  if (delta.inMinutes < 1) return l10n.workspaceMgmtLastUsedJustNow;
  if (delta.inHours < 1) {
    return l10n.workspaceMgmtLastUsedMinutesAgo(delta.inMinutes);
  }
  if (delta.inDays < 1) {
    return l10n.workspaceMgmtLastUsedHoursAgo(delta.inHours);
  }
  return l10n.workspaceMgmtLastUsedDaysAgo(delta.inDays);
}

List<Widget> workspaceMgmtCreateActions(BuildContext context, {Key? key}) {
  final l10n = AppLocalizations.of(context)!;
  final cs = Theme.of(context).colorScheme;
  return [
    IosIconButton(
      key: key ?? WorkspacesPane.createKey,
      icon: Lucide.Plus,
      color: cs.onSurface,
      size: 22,
      minSize: 44,
      tooltip: l10n.workspaceMgmtNewWorkspace,
      semanticLabel: l10n.workspaceMgmtNewWorkspace,
      onTap: () {
        Haptics.light();
        unawaited(showCreateWorkspaceFlow(context));
      },
    ),
    const SizedBox(width: 12),
  ];
}
