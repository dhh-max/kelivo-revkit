import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:Kelivo/theme/app_font_weights.dart';

import '../../../core/models/memory_entry.dart';
import '../../../core/providers/assistant_provider.dart';
import '../../../core/providers/memory_provider_v2.dart';
import '../../../core/providers/workspace_provider.dart';
import '../../../core/services/memory/memory_tools.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/ios_tactile.dart';
import '../widgets/memory_ui.dart';

/// Global memory list with search, filters, batch delete, orphan cleanup (§14.4).
class MemoryEntriesPage extends StatelessWidget {
  const MemoryEntriesPage({super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return Scaffold(
      backgroundColor: cs.surface,
      appBar: AppBar(
        leading: Tooltip(
          message: l10n.settingsPageBackButton,
          child: IosIconButton(
            icon: Lucide.ArrowLeft,
            color: cs.onSurface,
            size: 22,
            minSize: 44,
            semanticLabel: l10n.settingsPageBackButton,
            onTap: () => Navigator.of(context).maybePop(),
          ),
        ),
        title: Text(l10n.memoryEntriesPageTitle),
      ),
      body: const MemoryEntriesContent(),
    );
  }
}

class MemoryEntriesContent extends StatefulWidget {
  const MemoryEntriesContent({super.key, this.padding});

  final EdgeInsetsGeometry? padding;

  @override
  State<MemoryEntriesContent> createState() => _MemoryEntriesContentState();
}

enum _ScopeFilter { all, global, assistant }

enum _StatusFilter { all, active, archived }

class _MemoryEntriesContentState extends State<MemoryEntriesContent> {
  final _search = TextEditingController();
  _ScopeFilter _scope = _ScopeFilter.all;
  /// 类型筛选键：null = 全部；`'apk'` = APK 三类合并；其它 = [MemoryEntry.typeToString]。
  ///
  /// 用字符串键而不是 `MemoryType?`：APK 三类要能合并成一个筛选项
  /// （用户 2026-10-04「三种类型会不会过多」），单个枚举装不下「一组」。
  String? _typeKey;
  _StatusFilter _status = _StatusFilter.all;
  String? _assistantFilterId;
  /// 工作区（项目）过滤：null = 全部；非 null = 只显示在该工作区里可见的记忆
  /// （全局 + 该项目的结论 + 逆向经验）。用**选中的工作区**而不是进程级活动
  /// 项目——管理页与「最后一次生成」无关。
  String? _projectFilterId;
  final Set<String> _selected = {};
  bool _selecting = false;
  List<MemoryEntry>? _searchResults;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      context.read<MemoryProviderV2>().refreshAll();
    });
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _runSearch(String query) async {
    final q = query.trim();
    if (q.isEmpty) {
      setState(() => _searchResults = null);
      return;
    }
    final tokens = MemoryTools.searchTokens(q);
    if (tokens.isEmpty) {
      setState(() => _searchResults = null);
      return;
    }
    final results = await context.read<MemoryProviderV2>().search(
      tokens: tokens,
      acrossAll: true,
      includeArchived: true,
      type: _searchType,
    );
    if (!mounted) return;
    setState(() => _searchResults = results);
  }

  /// 搜索下推的单一类型（APK 合并组下推 null，由 [_filtered] 在本地收口）。
  MemoryType? get _searchType {
    final key = _typeKey;
    if (key == null || key == _apkTypeGroupKey) return null;
    return MemoryEntry.typeFromString(key);
  }

  static const String _apkTypeGroupKey = 'apk';

  /// 单列的一般记忆类型（APK 三类走合并项 [_apkTypeGroupKey]）。
  static const List<MemoryType> _plainMemoryTypes = <MemoryType>[
    MemoryType.identity,
    MemoryType.workflow,
    MemoryType.voice,
    MemoryType.instruction,
  ];

  /// APK 三类是**工具管理**的结构化记忆，通用编辑器只改 content（不动
  /// extraJson）：笔记的 content 是 notes[] 的投影、失败的 content 是自动摘要，
  /// 改正文对工具链无效 → 这两类在通用列表里只读（经验走 [_showEditSheet] 的
  /// lockStructure 只改正文）。
  static bool _readOnlyInList(MemoryEntry e) =>
      e.type == MemoryType.apkNote || e.type == MemoryType.apkFailure;

  List<MemoryEntry> _filtered(List<MemoryEntry> source) {
    return source
        .where((e) {
          // 工作区可见性：全局/经验类任何工作区都可见，项目结论只在自己的
          // 工作区可见（判定唯一事实源是 MemoryEntry.visibleInProject）。
          if (_projectFilterId != null &&
              !e.visibleInProject(_projectFilterId)) {
            return false;
          }
          final key = _typeKey;
          if (key != null) {
            if (key == _apkTypeGroupKey) {
              if (!MemoryEntry.apkTypes.contains(e.type)) return false;
            } else if (MemoryEntry.typeToString(e.type) != key) {
              return false;
            }
          }
          switch (_scope) {
            case _ScopeFilter.all:
              break;
            case _ScopeFilter.global:
              if (e.scope != MemoryScope.global) return false;
            case _ScopeFilter.assistant:
              if (e.scope != MemoryScope.assistant) return false;
              if (_assistantFilterId != null &&
                  e.assistantId != _assistantFilterId) {
                return false;
              }
          }
          switch (_status) {
            case _StatusFilter.all:
              break;
            case _StatusFilter.active:
              if (e.status != MemoryStatus.active) return false;
            case _StatusFilter.archived:
              if (e.status != MemoryStatus.archived) return false;
          }
          return true;
        })
        .toList(growable: false);
  }

  Future<void> _showEditSheet({MemoryEntry? existing}) {
    final lockStructure =
        existing != null && existing.type == MemoryType.apkPatch;
    return showMemoryEntryEditor(
      context,
      existing: existing,
      allowAssistantPicker: !lockStructure,
      // 按某个工作区筛选时，新建的记忆就落在这个工作区（不跟「上一次生成」走）。
      projectId: existing == null ? _projectFilterId : null,
      // APK 经验改正文有意义（content = solution），但类型/范围锁死——
      // 通用编辑器改类型会让 extraJson 与正文脱节。
      lockStructure: lockStructure,
    );
  }

  Future<void> _toggleBatchDelete() async {
    if (!_selecting) {
      setState(() => _selecting = true);
      return;
    }
    if (_selected.isEmpty) {
      setState(() {
        _selecting = false;
        _selected.clear();
      });
      return;
    }
    final mp = context.read<MemoryProviderV2>();
    final ids = _selected.toList();
    if (!await confirmBatchHardDelete(context, count: ids.length)) {
      return;
    }
    if (!mounted) return;
    await mp.hardDeleteMany(ids);
    setState(() {
      _selected.clear();
      _selecting = false;
    });
  }

  Widget _mobileToolbar(
    AppLocalizations l10n,
    AssistantProvider ap,
    WorkspaceProvider? wp,
  ) {
    return MemoryFadingHorizontalScroll(
      padding: const EdgeInsets.fromLTRB(16, 4, 16, 4),
      child: Row(
        children: [
          _FilterChip(
            label: switch (_scope) {
              _ScopeFilter.all => l10n.memoryFilterScopeAll,
              _ScopeFilter.global => l10n.memoryFilterScopeGlobal,
              _ScopeFilter.assistant => l10n.memoryFilterScopeAssistant,
            },
            onTap: () async {
              final next = await showMemoryOptionPicker<_ScopeFilter>(
                context,
                title: l10n.memoryEntryScopeLabel,
                selected: _scope,
                options: [
                  for (final v in _ScopeFilter.values)
                    MemoryPickerOption(
                      value: v,
                      label: switch (v) {
                        _ScopeFilter.all => l10n.memoryFilterScopeAll,
                        _ScopeFilter.global => l10n.memoryFilterScopeGlobal,
                        _ScopeFilter.assistant =>
                          l10n.memoryFilterScopeAssistant,
                      },
                    ),
                ],
              );
              if (next != null) setState(() => _scope = next);
            },
          ),
          if (_scope == _ScopeFilter.assistant) ...[
            const SizedBox(width: 8),
            _FilterChip(
              label: _assistantFilterId == null
                  ? l10n.memoryUiAssistantAll
                  : (ap.getById(_assistantFilterId!)?.name ??
                        l10n.memoryUiAssistantAll),
              onTap: () async {
                final next = await showMemoryOptionPicker<String?>(
                  context,
                  title: l10n.memoryUiAssistantLabel,
                  selected: _assistantFilterId,
                  options: [
                    MemoryPickerOption(
                      value: null,
                      label: l10n.memoryUiAssistantAll,
                    ),
                    for (final a in ap.assistants)
                      MemoryPickerOption(value: a.id, label: a.name),
                  ],
                );
                if (!mounted) return;
                setState(() => _assistantFilterId = next);
              },
            ),
          ],
          // 工作区筛选只在真的有工作区时出现：没有工作区（或宿主没挂
          // WorkspaceProvider）时这个筛选没有意义，也会把工具栏挤长。
          if (wp != null && wp.workspaces.isNotEmpty) ...[
            const SizedBox(width: 8),
            _FilterChip(
              label: _projectFilterId == null
                  ? l10n.memoryProjectFilterAll
                  : (wp.byId(_projectFilterId!)?.name ??
                        l10n.memoryProjectUnknown),
              onTap: () async {
                final next = await showMemoryOptionPicker<String?>(
                  context,
                  title: l10n.memoryProjectFilterTitle,
                  selected: _projectFilterId,
                  options: [
                    MemoryPickerOption(
                      value: null,
                      label: l10n.memoryProjectFilterAll,
                    ),
                    for (final w in wp.workspaces)
                      MemoryPickerOption(value: w.id, label: w.name),
                  ],
                );
                if (!mounted) return;
                setState(() => _projectFilterId = next);
              },
            ),
          ],
          const SizedBox(width: 8),
          _FilterChip(
            label: switch (_typeKey) {
              null => l10n.memoryFilterTypeAll,
              _apkTypeGroupKey => 'APK 记忆',
              final key => memoryTypeLabel(l10n, MemoryEntry.typeFromString(key)),
            },
            onTap: () async {
              final next = await showMemoryOptionPicker<String?>(
                context,
                title: l10n.memoryEntryTypeLabel,
                selected: _typeKey,
                options: [
                  MemoryPickerOption(
                    value: null,
                    label: l10n.memoryFilterTypeAll,
                  ),
                  for (final t in _plainMemoryTypes)
                    MemoryPickerOption(
                      value: MemoryEntry.typeToString(t),
                      label: memoryTypeLabel(l10n, t),
                    ),
                  // APK 三类合并成一项：生命周期不同但都是「工具管理的结构化
                  // 记忆」，筛选里分开列只会让列表看起来更长。
                  const MemoryPickerOption(
                    value: _apkTypeGroupKey,
                    label: 'APK 记忆（经验 · 笔记 · 失败）',
                  ),
                ],
              );
              if (!mounted) return;
              setState(() => _typeKey = next);
              if (_search.text.trim().isNotEmpty) {
                await _runSearch(_search.text);
              }
            },
          ),
          const SizedBox(width: 8),
          _FilterChip(
            label: switch (_status) {
              _StatusFilter.all => l10n.memoryFilterStatusAll,
              _StatusFilter.active => l10n.memoryFilterStatusActive,
              _StatusFilter.archived => l10n.memoryFilterStatusArchived,
            },
            onTap: () async {
              final next = await showMemoryOptionPicker<_StatusFilter>(
                context,
                title: l10n.memoryUiStatusLabel,
                selected: _status,
                options: [
                  for (final v in _StatusFilter.values)
                    MemoryPickerOption(
                      value: v,
                      label: switch (v) {
                        _StatusFilter.all => l10n.memoryFilterStatusAll,
                        _StatusFilter.active => l10n.memoryFilterStatusActive,
                        _StatusFilter.archived =>
                          l10n.memoryFilterStatusArchived,
                      },
                    ),
                ],
              );
              if (next != null) setState(() => _status = next);
            },
          ),
          const SizedBox(width: 8),
          _FilterChip(
            label: _selecting
                ? l10n.memoryEntryActionBatchDelete
                : l10n.providersPageMultiSelectTooltip,
            emphasized: _selecting,
            onTap: _toggleBatchDelete,
          ),
          const SizedBox(width: 8),
          _FilterChip(
            label: l10n.memoryEntryActionAdd,
            emphasized: true,
            onTap: () => _showEditSheet(),
          ),
        ],
      ),
    );
  }

  /// 工作区徽标：label 截断（徽标行不能被长工作区名撑破），tooltip 给全名与语义。
  ///
  /// 未打标 = 全局/逆向经验 → 无徽标（那是默认状态，标出来只会是噪音）。
  ({String label, String tooltip})? _projectBadge(
    MemoryEntry entry,
    WorkspaceProvider? wp,
    AppLocalizations l10n,
  ) {
    final id = entry.projectId;
    if (id == null) return null;
    final name = (wp?.byId(id)?.name ?? '').trim();
    final full = name.isEmpty ? l10n.memoryProjectUnknown : name;
    final label = full.length <= 12 ? full : '${full.substring(0, 12)}…';
    return (label: label, tooltip: '$full · ${l10n.memoryProjectBadgeTooltip}');
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final mp = context.watch<MemoryProviderV2>();
    final ap = context.watch<AssistantProvider>();
    // 可选：桌面/独立嵌入场景不一定挂了 WorkspaceProvider（测试亦然），
    // 缺省时只是没有工作区徽标与筛选项，不影响列表本身。
    final wp = context.watch<WorkspaceProvider?>();
    final source = _searchResults ?? mp.entries;
    final filtered = _filtered(source);
    final active = filtered
        .where((e) => e.status == MemoryStatus.active)
        .toList();
    final archived = filtered
        .where((e) => e.status == MemoryStatus.archived)
        .toList();
    final listPadding = widget.padding ?? const EdgeInsets.only(bottom: 24);

    return Column(
      children: [
        Padding(
          padding: widget.padding == null
              ? const EdgeInsets.fromLTRB(16, 8, 16, 4)
              : const EdgeInsets.fromLTRB(0, 0, 0, 4),
          child: MemorySearchField(
            controller: _search,
            hintText: l10n.memorySearchHint,
            onChanged: _runSearch,
          ),
        ),
        _mobileToolbar(l10n, ap, wp),
        const MemoryOrphanBanner(),
        // 工作区删掉后项目记忆会变成孤儿（谁都看不到、也没有入口清理）：
        // 这里给「转为全局 / 删除」两个出口（用户 2026-10-04）。
        // 只有工作区 provider 在场时才判断：不在场时拿不到现存 id 全集，
        // 会把所有项目记忆误判成孤儿。
        if (wp != null)
          MemoryOrphanProjectBanner(
            liveProjectIds: <String>{
              for (final workspace in wp.workspaces) workspace.id,
            },
          ),
        Expanded(
          child: filtered.isEmpty
              ? Center(
                  child: Text(
                    _searchResults != null
                        ? l10n.memorySearchEmpty
                        : l10n.memoryEntryEmpty,
                    style: TextStyle(
                      color: cs.onSurface.withValues(alpha: 0.55),
                    ),
                  ),
                )
              : ListView(
                  padding: listPadding,
                  children: [
                    ...active.map(
                      (e) {
                        final project = _projectBadge(e, wp, l10n);
                        return MemoryEntryCard(
                          entry: e,
                          assistantName: resolveAssistantName(
                            context,
                            e.assistantId,
                          ),
                          projectLabel: project?.label,
                          projectTooltip: project?.tooltip,
                          selectable: _selecting,
                          selected: _selected.contains(e.id),
                          onSelectedChanged: (v) {
                            setState(() {
                              if (v) {
                                _selected.add(e.id);
                              } else {
                                _selected.remove(e.id);
                              }
                            });
                          },
                          onEdit: _readOnlyInList(e) ? null : () => _showEditSheet(existing: e),
                        );
                      },
                    ),
                    if (archived.isNotEmpty &&
                        (_status == _StatusFilter.all ||
                            _status == _StatusFilter.archived)) ...[
                      Padding(
                        padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
                        child: Text(
                          l10n.memoryEntryArchivedSection,
                          style: TextStyle(
                            fontSize: 15,
                            fontWeight: AppFontWeights.emphasis,
                          ),
                        ),
                      ),
                      ...archived.map(
                        (e) {
                          final project = _projectBadge(e, wp, l10n);
                          return MemoryEntryCard(
                            entry: e,
                            assistantName: resolveAssistantName(
                              context,
                              e.assistantId,
                            ),
                            projectLabel: project?.label,
                            projectTooltip: project?.tooltip,
                            selectable: _selecting,
                            selected: _selected.contains(e.id),
                            onSelectedChanged: (v) {
                              setState(() {
                                if (v) {
                                  _selected.add(e.id);
                                } else {
                                  _selected.remove(e.id);
                                }
                              });
                            },
                            onEdit: _readOnlyInList(e) ? null : () => _showEditSheet(existing: e),
                          );
                        },
                      ),
                    ],
                  ],
                ),
        ),
      ],
    );
  }
}

class _FilterChip extends StatelessWidget {
  const _FilterChip({
    required this.label,
    required this.onTap,
    this.emphasized = false,
  });

  final String label;
  final VoidCallback onTap;
  final bool emphasized;

  @override
  Widget build(BuildContext context) {
    return MemorySelectChip(
      label: label,
      emphasized: emphasized,
      trailingIcon: Lucide.ChevronDown,
      onTap: onTap,
    );
  }
}

