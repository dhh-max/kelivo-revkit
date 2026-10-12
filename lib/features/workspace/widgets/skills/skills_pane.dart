import 'dart:async';

import 'package:solab/core/models/agent_skill.dart';
import 'package:solab/core/providers/agent_skill_provider.dart';
import 'package:solab/core/services/haptics.dart';
import 'package:solab/core/services/skills/skills_service.dart';
import 'package:solab/features/workspace/widgets/skills/skill_detail.dart';
import 'package:solab/features/workspace/widgets/skills/skill_import.dart';
import 'package:solab/features/workspace/widgets/skills/skill_labels.dart';
import 'package:solab/icons/lucide_adapter.dart';
import 'package:solab/l10n/app_localizations.dart';
import 'package:solab/shared/widgets/ios_settings_rows.dart';
import 'package:solab/shared/widgets/ios_switch.dart';
import 'package:solab/shared/widgets/ios_tactile.dart';
import 'package:solab/shared/widgets/ios_tile_button.dart';
import 'package:solab/shared/widgets/section_card.dart';
import 'package:solab/theme/app_font_weights.dart';
import 'package:solab/theme/app_semantic_colors.dart';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:provider/provider.dart';
import '../../../skills_builtin/solab_builtin_skills.dart';

/// Embeddable skills list for the Skills page and desktop settings.
///
/// When [showHeader] is false the pane renders the list only — no ＋ row.
class SkillsPane extends StatefulWidget {
  const SkillsPane({super.key, this.padding, this.showHeader = true});

  final EdgeInsetsGeometry? padding;
  final bool showHeader;

  static const Key emptyKey = SkillsKeys.empty;
  static const Key listKey = SkillsKeys.list;
  static const Key searchKey = SkillsKeys.search;
  static const Key importKey = SkillsKeys.import;
  static const Key importPasteKey = SkillsKeys.importPaste;
  static const Key importFileKey = SkillsKeys.importFile;
  static const Key importGitHubKey = SkillsKeys.importGitHub;
  static const Key importSubmitKey = SkillsKeys.importSubmit;
  static const Key importErrorKey = SkillsKeys.importError;
  static const Key deleteKey = SkillsKeys.delete;
  static const Key emptyCtasKey = SkillsKeys.emptyCtas;

  static Key itemKey(String id) => SkillsKeys.item(id);

  static Key enableKey(String id) => SkillsKeys.enable(id);

  @override
  State<SkillsPane> createState() => SkillsPaneState();
}

class SkillsPaneState extends State<SkillsPane> {
  final TextEditingController _searchController = TextEditingController();

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  List<AgentSkill> _filteredOur(List<AgentSkill> skills) {
    final query = _searchController.text.trim().toLowerCase();
    if (query.isEmpty) return skills;
    return skills
        .where(
          (s) =>
              s.name.toLowerCase().contains(query) ||
              s.description.toLowerCase().contains(query) ||
              s.topics.any((t) => t.toLowerCase().contains(query)),
        )
        .toList(growable: false);
  }

  List<Skill> _filtered(List<Skill> skills) {
    final query = _searchController.text.trim().toLowerCase();
    if (query.isEmpty) return skills;
    return [
      for (final skill in skills)
        if (skill.name.toLowerCase().contains(query) ||
            skill.description.toLowerCase().contains(query))
          skill,
    ];
  }

  Widget _emptyState(AppLocalizations l10n, ColorScheme cs) {
    final child = Center(
      key: SkillsPane.emptyKey,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 420),
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 48),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                Lucide.WandSparkles,
                size: 44,
                color: cs.onSurface.withValues(alpha: 0.26),
              ),
              const SizedBox(height: 12),
              Text(
                l10n.skillsEmptyTitle,
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 15,
                  fontWeight: AppFontWeights.semibold,
                  color: cs.onSurface.withValues(alpha: 0.72),
                ),
              ),
              const SizedBox(height: 6),
              Text(
                l10n.skillsEmptyHint,
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 12.5,
                  height: 1.35,
                  color: cs.onSurface.withValues(alpha: 0.52),
                ),
              ),
              const SizedBox(height: 16),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
                decoration: BoxDecoration(
                  color: context.appColors.surfaceFill,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  l10n.skillsEmptyFormat,
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    height: 1.4,
                    color: cs.onSurface.withValues(alpha: 0.72),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              SizedBox(
                key: SkillsKeys.emptyCtas,
                width: 260,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    IosTileButton(
                      key: SkillsKeys.importPaste,
                      icon: Lucide.ClipboardPaste,
                      label: l10n.skillsImportPaste,
                      onTap: () => unawaited(showSkillPasteImport(context)),
                    ),
                    const SizedBox(height: 8),
                    IosTileButton(
                      key: SkillsKeys.importFile,
                      icon: Lucide.FileUp,
                      label: l10n.skillsImportFile,
                      onTap: () => unawaited(importSkillFromFile(context)),
                    ),
                    const SizedBox(height: 8),
                    IosTileButton(
                      key: SkillsKeys.importGitHub,
                      leading: const GitHubGlyph(),
                      label: l10n.skillsImportGitHub,
                      onTap: () => unawaited(showSkillGitHubImport(context)),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
    return child.animate().fadeIn(duration: 200.ms);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final skills = context.watch<SkillsService>().skills;
    // 自研技能（AgentSkillProvider 源，工具链读取的就是这份存储）并入展示。
    final ourSkills = context.watch<AgentSkillProvider>().skills;
    final ourFiltered = _filteredOur(ourSkills);
    // 内置技能（自研方法论技能，随包发布、只读）：名称+适用提示。
    final query = _searchController.text.trim().toLowerCase();
    // 内置技能**全量展示**（用户 2026-10-02 定性）：切到任何助手都列全，只是按
    // 作用域分组——「通用」对所有助手生效，其余按归属助手分组。不做「切到开发就
    // 只显示开发」的过滤，否则用户看不到自己还有哪些能力可用。
    bool matchesQuery(String name) =>
        query.isEmpty ||
        name.toLowerCase().contains(query) ||
        (SolabBuiltinSkills.activationHints[name] ?? '').toLowerCase().contains(
          query,
        );
    final builtinGroups = <({String title, List<String> names})>[
      (
        title: l10n.skillsBuiltinGlobalSectionTitle,
        names: SolabBuiltinSkills.globalNames,
      ),
      for (final entry in SolabBuiltinSkills.assistantSkillNames.entries)
        (
          title: l10n.skillsBuiltinAssistantSectionTitle(
            SolabBuiltinSkills.assistantDisplayNames[entry.key] ??
                l10n.skillsBuiltinAssistantFallbackName,
          ),
          names: entry.value,
        ),
    ];
    final builtinFilteredGroups = <({String title, List<String> names})>[
      for (final group in builtinGroups)
        if (group.names.where(matchesQuery).isNotEmpty)
          (title: group.title, names: group.names.where(matchesQuery).toList()),
    ];
    final hasBuiltin = builtinFilteredGroups.isNotEmpty;
    final filtered = _filtered(skills);
    final showSearch = skills.length > 8;

    return Padding(
      padding: widget.padding ?? EdgeInsets.zero,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (widget.showHeader)
            Padding(
              padding: const EdgeInsets.fromLTRB(4, 0, 4, 8),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      l10n.skillsTitle,
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: AppFontWeights.emphasis,
                        color: cs.onSurface,
                      ),
                    ),
                  ),
                  const SkillsImportPlusButton(key: SkillsKeys.import),
                ],
              ),
            ),
          if (showSearch)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _SkillsSearchField(
                controller: _searchController,
                onChanged: () => setState(() {}),
              ),
            ),
          Expanded(
            child: (skills.isEmpty && ourFiltered.isEmpty && !hasBuiltin)
                ? _emptyState(l10n, cs)
                : ListView(
                    key: SkillsPane.listKey,
                    padding: const EdgeInsets.fromLTRB(0, 4, 0, 24),
                    children: [
                      if (filtered.isNotEmpty)
                        SectionCard(
                          children: [
                            for (var i = 0; i < filtered.length; i++) ...[
                              if (i > 0) const IosRowDivider(),
                              _SkillTile(skill: filtered[i]),
                            ],
                          ],
                        ),
                      if (ourFiltered.isNotEmpty) ...[
                        SizedBox(height: filtered.isEmpty ? 0 : 18),
                        Padding(
                          padding: const EdgeInsets.fromLTRB(4, 0, 4, 8),
                          child: Text(
                            l10n.skillsOurSectionTitle,
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: AppFontWeights.semibold,
                              color: cs.onSurface.withValues(alpha: 0.8),
                            ),
                          ),
                        ),
                        SectionCard(
                          children: [
                            for (var i = 0; i < ourFiltered.length; i++) ...[
                              if (i > 0) const IosRowDivider(),
                              _OurSkillTile(skill: ourFiltered[i]),
                            ],
                          ],
                        ),
                      ],
                      // 内置技能全量分组展示：通用 + 每个助手的专属（不随当前助手过滤）。
                      for (final group in builtinFilteredGroups) ...[
                        SizedBox(
                          height: (filtered.isEmpty &&
                                  ourFiltered.isEmpty &&
                                  group == builtinFilteredGroups.first)
                              ? 0
                              : 18,
                        ),
                        Padding(
                          padding: const EdgeInsets.fromLTRB(4, 0, 4, 8),
                          child: Text(
                            group.title,
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: AppFontWeights.semibold,
                              color: cs.onSurface.withValues(alpha: 0.8),
                            ),
                          ),
                        ),
                        SectionCard(
                          children: [
                            for (var i = 0; i < group.names.length; i++) ...[
                              if (i > 0) const IosRowDivider(),
                              _BuiltinSkillTile(name: group.names[i]),
                            ],
                          ],
                        ),
                      ],
                    ],
                  ),
          ),
        ],
      ),
    );
  }
}

class _SkillsSearchField extends StatelessWidget {
  const _SkillsSearchField({required this.controller, required this.onChanged});

  final TextEditingController controller;
  final VoidCallback onChanged;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    final hasText = controller.text.isNotEmpty;
    return TextField(
      key: SkillsPane.searchKey,
      controller: controller,
      onChanged: (_) => onChanged(),
      cursorColor: cs.primary,
      style: TextStyle(color: cs.onSurface),
      decoration: InputDecoration(
        hintText: l10n.skillsSearchHint,
        prefixIcon: Icon(
          Lucide.Search,
          size: 18,
          color: cs.onSurface.withValues(alpha: 0.6),
        ),
        suffixIcon: hasText
            ? Tooltip(
                message: l10n.skillsSearchClear,
                child: IosIconButton(
                  icon: Lucide.X,
                  size: 16,
                  semanticLabel: l10n.skillsSearchClear,
                  onTap: () {
                    Haptics.light();
                    controller.clear();
                    onChanged();
                  },
                ),
              )
            : null,
        isDense: true,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 12,
          vertical: 12,
        ),
        filled: true,
        fillColor: context.appColors.surfaceFill,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(
            color: cs.outlineVariant.withValues(alpha: 0.4),
          ),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(
            color: cs.outlineVariant.withValues(alpha: 0.4),
          ),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(color: cs.primary.withValues(alpha: 0.5)),
        ),
      ),
    );
  }
}

class _SkillTile extends StatelessWidget {
  const _SkillTile({required this.skill});

  final Skill skill;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final description = skill.description.trim();
    return IosNavRow(
      key: SkillsPane.itemKey(skill.record.id),
      icon: Lucide.WandSparkles,
      label: skill.name,
      labelWeight: AppFontWeights.medium,
      subtitle: description.isEmpty ? null : description,
      caption: l10n.skillsUsedCount(skill.record.useCount),
      onTap: () =>
          unawaited(showSkillDetail(context, skillId: skill.record.id)),
      trailing: IosSwitch(
        key: SkillsPane.enableKey(skill.record.id),
        value: skill.record.enabled,
        semanticLabel: l10n.skillsEnabled,
        onChanged: (value) {
          unawaited(
            context.read<SkillsService>().setEnabled(skill.record.id, value),
          );
        },
      ),
    );
  }
}

/// 自研技能（AgentSkillProvider 源）行：现有行样式 + 开关；点按看内容。
class _OurSkillTile extends StatelessWidget {
  const _OurSkillTile({required this.skill});

  final AgentSkill skill;

  @override
  Widget build(BuildContext context) {
    final description = skill.description.trim();
    final provider = context.read<AgentSkillProvider>();
    return IosNavRow(
      icon: Lucide.WandSparkles,
      label: skill.name.isEmpty ? skill.id : skill.name,
      labelWeight: AppFontWeights.medium,
      subtitle: description.isEmpty ? null : description,
      caption: skill.version.isEmpty ? null : 'v${skill.version}',
      trailing: IosSwitch(
        value: skill.enabled,
        onChanged: (v) => provider.save(skill.copyWith(enabled: v)),
      ),
      onTap: () => _showOurSkillSheet(context, skill),
    );
  }
}

Future<void> _showOurSkillSheet(BuildContext context, AgentSkill skill) {
  final l10n = AppLocalizations.of(context)!;
  final cs = Theme.of(context).colorScheme;
  return showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    backgroundColor: context.overlaySurface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(18)),
    ),
    builder: (sheetContext) {
      final content = skill.content.trim();
      return SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 14, 16, 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                skill.name.isEmpty ? skill.id : skill.name,
                style: TextStyle(
                  fontSize: 17,
                  fontWeight: AppFontWeights.semibold,
                  color: cs.onSurface,
                ),
              ),
              if (skill.description.trim().isNotEmpty) ...[
                const SizedBox(height: 6),
                Text(
                  skill.description.trim(),
                  style: TextStyle(
                    fontSize: 13,
                    height: 1.35,
                    color: cs.onSurface.withValues(alpha: 0.7),
                  ),
                ),
              ],
              const SizedBox(height: 12),
              Flexible(
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: cs.surfaceContainerHighest.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: SingleChildScrollView(
                    child: Text(
                      content.isEmpty ? l10n.skillsDetailBodyEmpty : content,
                      style: TextStyle(
                        fontSize: 13,
                        height: 1.4,
                        color: cs.onSurface.withValues(alpha: 0.85),
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: Text(
                      l10n.skillsEnabled,
                      style: TextStyle(fontSize: 15, color: cs.onSurface),
                    ),
                  ),
                  IosSwitch(
                    value: skill.enabled,
                    onChanged: (v) {
                      sheetContext.read<AgentSkillProvider>().save(
                        skill.copyWith(enabled: v),
                      );
                      Navigator.of(sheetContext).maybePop();
                    },
                  ),
                ],
              ),
            ],
          ),
        ),
      );
    },
  );
}

/// 内置方法论技能行（随包发布，只读）：点按看全文。
class _BuiltinSkillTile extends StatelessWidget {
  const _BuiltinSkillTile({required this.name});

  final String name;

  @override
  Widget build(BuildContext context) {
    final hint = SolabBuiltinSkills.activationHints[name] ?? '';
    return IosNavRow(
      icon: Lucide.BookOpen,
      label: name,
      labelWeight: AppFontWeights.medium,
      subtitle: hint.isEmpty ? null : hint,
      caption: null,
      onTap: () => _showBuiltinSkillSheet(context, name, hint),
    );
  }
}

Future<void> _showBuiltinSkillSheet(
  BuildContext context,
  String name,
  String hint,
) {
  final cs = Theme.of(context).colorScheme;
  final content = SolabBuiltinSkills.read(name);
  final rules = SolabBuiltinSkills.activationRules[name] ?? const <String>[];
  return showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    backgroundColor: context.overlaySurface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(18)),
    ),
    builder: (sheetContext) => SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 14, 16, 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              name,
              style: TextStyle(
                fontSize: 17,
                fontWeight: AppFontWeights.semibold,
                color: cs.onSurface,
              ),
            ),
            if (hint.isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(
                hint,
                style: TextStyle(
                  fontSize: 13,
                  height: 1.35,
                  color: cs.onSurface.withValues(alpha: 0.7),
                ),
              ),
            ],
            if (rules.isNotEmpty) ...[
              const SizedBox(height: 10),
              for (final rule in rules)
                Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Text(
                    '· $rule',
                    style: TextStyle(
                      fontSize: 12.5,
                      height: 1.35,
                      color: cs.onSurface.withValues(alpha: 0.75),
                    ),
                  ),
                ),
            ],
            const SizedBox(height: 12),
            Flexible(
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: cs.surfaceContainerHighest.withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: SingleChildScrollView(
                  child: Text(
                    content.isEmpty ? '—' : content,
                    style: TextStyle(
                      fontSize: 13,
                      height: 1.4,
                      color: cs.onSurface.withValues(alpha: 0.85),
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    ),
  );
}
