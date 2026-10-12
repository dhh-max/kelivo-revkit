import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/models/assistant.dart';
import '../../../core/providers/assistant_provider.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../theme/app_font_weights.dart';
import '../../../theme/app_semantic_colors.dart';
import '../../../core/services/local_tools/local_tool_names.dart';
import '../../home/services/agent_capability_policy.dart';
import '../../home/services/local_tool_toggle.dart';
import '../../home/services/subagent_registry.dart';
import '../../home/services/subagent_team.dart';

/// 子智能体管理页（用户 2026-09-28）。
///
/// 三条纪律：
/// 1. **文案必须对得上功能**——每一条能力声明都能追到真实的授予规则
///    （[SubAgentRegistry.toolNamesFor]，按类别 ∩ 当前助手的工具实算）；
/// 2. **各司其职**——内置角色分通用/开发/逆向三组，子代理只能用派发它的助手
///    自己也有的工具；
/// 3. 与其他设置页共用同一套视觉（surfaceCard 卡片 + 分组标题 + 细分隔线）。
class SubagentsSettingsPage extends StatefulWidget {
  const SubagentsSettingsPage({super.key});

  static Future<void> open(BuildContext context) {
    return Navigator.of(context, rootNavigator: true).push<void>(
      MaterialPageRoute(builder: (_) => const SubagentsSettingsPage()),
    );
  }

  @override
  State<SubagentsSettingsPage> createState() => _SubagentsSettingsPageState();
}

class _SubagentsSettingsPageState extends State<SubagentsSettingsPage> {
  final SubAgentRegistry _registry = SubAgentRegistry();
  final SubAgentTeamRegistry _teams = SubAgentTeamRegistry();
  List<SubAgentDefinition> _definitions = const <SubAgentDefinition>[];
  List<SubAgentTeam> _teamList = const <SubAgentTeam>[];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    final all = await _registry.all();
    final teams = await _teams.all();
    if (!mounted) return;
    setState(() {
      _definitions = all;
      _teamList = teams;
      _loading = false;
    });
  }

  List<SubAgentDefinition> get _custom => _definitions
      .where((definition) => !definition.builtIn)
      .toList(growable: false);

  List<SubAgentDefinition> _builtInsOf(SubAgentDomain domain) => _definitions
      .where((definition) => definition.builtIn && definition.domain == domain)
      .toList(growable: false);

  Future<void> _edit([SubAgentDefinition? existing]) async {
    final result = await Navigator.of(context).push<SubAgentDefinition>(
      MaterialPageRoute(
        builder: (_) => SubagentEditorPage(
          initial: existing,
          takenSlugs: <String>{
            for (final definition in _custom)
              if (definition.id != existing?.id) definition.slug,
          },
        ),
      ),
    );
    if (result == null || !mounted) return;
    await _registry.replaceAll(<SubAgentDefinition>[
      for (final definition in _custom)
        if (definition.id != result.id) definition,
      result,
    ]);
    if (!mounted) return;
    ScaffoldMessenger.maybeOf(context)?.showSnackBar(
      SnackBar(content: Text(AppLocalizations.of(context)!.subagentsSaved)),
    );
    await _reload();
  }

  Future<void> _delete(SubAgentDefinition definition) async {
    final l10n = AppLocalizations.of(context)!;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(l10n.subagentsDeleteConfirmTitle),
        content: Text(l10n.subagentsDeleteConfirmBody),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: Text(
              MaterialLocalizations.of(dialogContext).cancelButtonLabel,
            ),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: Text(l10n.subagentsDelete),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await _registry.replaceAll(<SubAgentDefinition>[
      for (final item in _custom)
        if (item.id != definition.id) item,
    ]);
    await _reload();
  }

  /// 写回一个 AI 能力开关（子代理/专家团走各自既有字段，不经这里）。
  void _setCapability(Assistant assistant, AgentCapability id, bool value) {
    final key = AgentCapabilityPolicy.mapKeyFor(id);
    if (key.isEmpty) return;
    final next = Map<String, bool>.from(assistant.agentCapabilities);
    next[key] = value;
    context.read<AssistantProvider>().updateAssistant(
      assistant.copyWith(agentCapabilities: next),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final assistant = context.watch<AssistantProvider>().currentAssistant;
    final allowed = assistant?.localToolIds.toSet();
    // 派发开关（2026-09-29 用户反馈「子智能体、专家团没有开关」）：两个都按助手
    // 保存。子代理开关就是 localToolIds 里的 `subagent`——工具面（schema）与
    // 执行期都认这一份，不存在"开关是假的"；专家团开关另存一个字段，同样在
    // schema 与派发两处生效。
    final subagentOn =
        assistant?.localToolIds.contains(LocalToolNames.subagent) ?? false;
    final teamsOn = assistant?.subagentTeamsEnabled ?? true;
    // AI 能力开关（2026-09-29 用户：除目标模式、计划模式外，其余能力面都做成开关，
    // 开了由 AI 自己判断）：待办 / 技能 / 独立复核三项存在 assistant.agentCapabilities，
    // 与派发、专家团一起在这里露出；关闭后在工具面（schema）与执行期两处生效。
    final todoOn = AgentCapabilityPolicy.enabled(
      assistant,
      AgentCapability.todo,
    );
    final skillsOn = AgentCapabilityPolicy.enabled(
      assistant,
      AgentCapability.skills,
    );
    final verifyOn = AgentCapabilityPolicy.enabled(
      assistant,
      AgentCapability.verify,
    );
    final custom = _custom;
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.settingsPageSubagents),
        actions: [
          IconButton(
            tooltip: l10n.subagentsAdd,
            icon: const Icon(Lucide.Plus),
            onPressed: () => _edit(),
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
              children: [
                _Section(
                  title: l10n.subagentsSwitchSection,
                  blocks: [
                    // _Section 的卡片是带背景色的 DecoratedBox：ListTile 直接放进去会
                    // 触发「背景色/水波纹可能不可见」断言，垫一层透明 Material 即可。
                    Material(
                      type: MaterialType.transparency,
                      child: SwitchListTile(
                        value: subagentOn,
                        title: Text(l10n.subagentsSwitchSubagentTitle),
                        subtitle: Text(l10n.subagentsSwitchSubagentSubtitle),
                        onChanged: assistant == null
                            ? null
                            : (value) {
                                setLocalToolEnabled(
                                  context,
                                  assistant: assistant,
                                  toolId: LocalToolNames.subagent,
                                  value: value,
                                );
                              },
                      ),
                    ),
                    Material(
                      type: MaterialType.transparency,
                      child: SwitchListTile(
                        value: teamsOn,
                        title: Text(l10n.subagentsSwitchTeamsTitle),
                        subtitle: Text(l10n.subagentsSwitchTeamsSubtitle),
                        onChanged: assistant == null
                            ? null
                            : (value) {
                                context
                                    .read<AssistantProvider>()
                                    .updateAssistant(
                                      assistant.copyWith(
                                        subagentTeamsEnabled: value,
                                      ),
                                    );
                              },
                      ),
                    ),
                    Material(
                      type: MaterialType.transparency,
                      child: SwitchListTile(
                        value: todoOn,
                        title: Text(l10n.subagentsSwitchTodoTitle),
                        subtitle: Text(l10n.subagentsSwitchTodoSubtitle),
                        onChanged: assistant == null
                            ? null
                            : (value) => _setCapability(
                                assistant,
                                AgentCapability.todo,
                                value,
                              ),
                      ),
                    ),
                    Material(
                      type: MaterialType.transparency,
                      child: SwitchListTile(
                        value: skillsOn,
                        title: Text(l10n.subagentsSwitchSkillsTitle),
                        subtitle: Text(l10n.subagentsSwitchSkillsSubtitle),
                        onChanged: assistant == null
                            ? null
                            : (value) => _setCapability(
                                assistant,
                                AgentCapability.skills,
                                value,
                              ),
                      ),
                    ),
                    Material(
                      type: MaterialType.transparency,
                      child: SwitchListTile(
                        value: verifyOn,
                        title: Text(l10n.subagentsSwitchVerifyTitle),
                        subtitle: Text(l10n.subagentsSwitchVerifySubtitle),
                        onChanged: assistant == null
                            ? null
                            : (value) => _setCapability(
                                assistant,
                                AgentCapability.verify,
                                value,
                              ),
                      ),
                    ),
                  ],
                  footnote: l10n.subagentsSwitchFootnote,
                ),
                const SizedBox(height: 18),
                _Section(
                  title: l10n.subagentsUsageTitle,
                  blocks: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            l10n.subagentsUsageBody,
                            style: TextStyle(
                              fontSize: 13,
                              height: 1.5,
                              color: cs.onSurface.withValues(alpha: 0.72),
                            ),
                          ),
                          const SizedBox(height: 10),
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 8,
                            ),
                            decoration: BoxDecoration(
                              color: cs.primary.withValues(alpha: 0.08),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              '/subagent <${l10n.subagentsSlugLabel}> <${l10n.subagentsTaskLabel}>'
                              '     /team <${l10n.subagentsTaskLabel}>',
                              style: TextStyle(
                                fontSize: 12.5,
                                color: cs.primary,
                                fontWeight: AppFontWeights.medium,
                              ),
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            l10n.subagentsUsageRules,
                            style: TextStyle(
                              fontSize: 12,
                              height: 1.5,
                              color: cs.onSurface.withValues(alpha: 0.6),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 18),
                _Section(
                  title:
                      '${l10n.subagentsCapabilityTitle}'
                      '${assistant == null ? '' : ' · ${assistant.name}'}',
                  blocks: [
                    _CategoryPreviewRow(
                      title: l10n.subagentsToolsRead,
                      detail: l10n.subagentsToolsGranted(
                        SubAgentRegistry.toolNamesFor(<SubAgentCategory>{
                          SubAgentCategory.read,
                        }, allowed: allowed).length,
                      ),
                    ),
                    _CategoryPreviewRow(
                      title: l10n.subagentsToolsWrite,
                      detail: l10n.subagentsToolsGranted(
                        SubAgentRegistry.toolNamesFor(<SubAgentCategory>{
                          SubAgentCategory.write,
                        }, allowed: allowed).length,
                      ),
                    ),
                    _CategoryPreviewRow(
                      title: l10n.subagentsToolsShell,
                      detail: l10n.subagentsCapabilityShellNote,
                    ),
                  ],
                  footnote: l10n.subagentsCapabilityFootnote,
                ),
                const SizedBox(height: 18),
                _Section(
                  title:
                      '${l10n.subagentsSectionBuiltIn} · ${l10n.subagentsDomainAny}',
                  blocks: [
                    for (final definition in _builtInsOf(SubAgentDomain.any))
                      _DefinitionRow(
                        definition: definition,
                        dispatchLabel: l10n.subagentsDispatchLabel,
                        builtInTag: l10n.subagentsBuiltInTag,
                        onTap: () => _showBuiltInInfo(definition),
                      ),
                  ],
                ),
                const SizedBox(height: 18),
                _Section(
                  title:
                      '${l10n.subagentsSectionBuiltIn} · ${l10n.subagentsDomainDev}',
                  blocks: [
                    for (final definition in _builtInsOf(SubAgentDomain.dev))
                      _DefinitionRow(
                        definition: definition,
                        dispatchLabel: l10n.subagentsDispatchLabel,
                        builtInTag: l10n.subagentsBuiltInTag,
                        onTap: () => _showBuiltInInfo(definition),
                      ),
                  ],
                  footnote: l10n.subagentsDevRosterNote,
                ),
                const SizedBox(height: 18),
                _Section(
                  title:
                      '${l10n.subagentsSectionBuiltIn} · ${l10n.subagentsDomainApk}',
                  blocks: [
                    for (final definition in _builtInsOf(SubAgentDomain.apk))
                      _DefinitionRow(
                        definition: definition,
                        dispatchLabel: l10n.subagentsDispatchLabel,
                        builtInTag: l10n.subagentsBuiltInTag,
                        onTap: () => _showBuiltInInfo(definition),
                      ),
                  ],
                  footnote: l10n.subagentsApkRosterNote,
                ),
                const SizedBox(height: 18),
                _Section(
                  title: l10n.subagentsSectionTeams,
                  blocks: [
                    for (final team in _teamList)
                      _TeamRow(
                        team: team,
                        dispatchLabel: l10n.subagentsDispatchLabel,
                      ),
                  ],
                  footnote: l10n.subagentsTeamsHint,
                ),
                const SizedBox(height: 18),
                _Section(
                  title: l10n.subagentsSectionCustom,
                  blocks: [
                    if (custom.isEmpty)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(14, 14, 14, 14),
                        child: Text(
                          l10n.subagentsCustomEmpty,
                          style: TextStyle(
                            fontSize: 13,
                            height: 1.4,
                            color: cs.onSurface.withValues(alpha: 0.6),
                          ),
                        ),
                      ),
                    for (final definition in custom)
                      _DefinitionRow(
                        definition: definition,
                        dispatchLabel: l10n.subagentsDispatchLabel,
                        builtInTag: l10n.subagentsBuiltInTag,
                        onTap: () => _edit(definition),
                        onDelete: () => _delete(definition),
                        deleteTooltip: l10n.subagentsDelete,
                      ),
                  ],
                ),
              ],
            ),
    );
  }

  void _showBuiltInInfo(SubAgentDefinition definition) {
    final l10n = AppLocalizations.of(context)!;
    final allowed = context
        .read<AssistantProvider>()
        .currentAssistant
        ?.localToolIds
        .toSet();
    final granted = SubAgentRegistry.toolNamesFor(
      definition.categories,
      allowed: allowed,
    ).toList(growable: false)..sort();
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (sheetContext) {
        final cs = Theme.of(sheetContext).colorScheme;
        return SafeArea(
          child: SingleChildScrollView(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '${definition.name}  ·  ${definition.domain.title}',
                    style: TextStyle(
                      fontSize: 17,
                      fontWeight: AppFontWeights.semibold,
                      color: cs.onSurface,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    definition.description,
                    style: TextStyle(
                      fontSize: 13,
                      height: 1.5,
                      color: cs.onSurface.withValues(alpha: 0.7),
                    ),
                  ),
                  const SizedBox(height: 14),
                  _KeyValue(l10n.subagentsSlugLabel, definition.slug),
                  _KeyValue(
                    l10n.subagentsTools,
                    definition.categories.map(_categoryLabel(l10n)).join(' / '),
                  ),
                  _KeyValue(l10n.subagentsMaxSteps, '${definition.maxSteps}'),
                  _KeyValue(
                    l10n.subagentsTimeout,
                    '${definition.timeoutMs ~/ 1000}',
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '${l10n.subagentsGrantedNow}（${granted.length}）：'
                    '${granted.isEmpty ? l10n.subagentsNoToolsNow : granted.join(', ')}',
                    style: TextStyle(
                      fontSize: 12,
                      height: 1.5,
                      color: cs.onSurface.withValues(alpha: 0.62),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Text(
                    l10n.subagentsBuiltInNote,
                    style: TextStyle(
                      fontSize: 12,
                      height: 1.4,
                      color: cs.onSurface.withValues(alpha: 0.55),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

/// 角色预设：填进编辑器的起点（内置角色不可改，这是"复制一份再改"的正规入口）。
class SubagentRolePreset {
  const SubagentRolePreset({
    required this.label,
    required this.categories,
    required this.systemPrompt,
  });

  final String label;
  final Set<SubAgentCategory> categories;
  final String systemPrompt;

  static const List<SubagentRolePreset> all = <SubagentRolePreset>[
    SubagentRolePreset(
      label: '调研',
      categories: <SubAgentCategory>{SubAgentCategory.read},
      systemPrompt: SubAgentRegistry.researcherPromptExample,
    ),
    SubagentRolePreset(
      label: '实现',
      categories: <SubAgentCategory>{
        SubAgentCategory.read,
        SubAgentCategory.write,
      },
      systemPrompt: SubAgentRegistry.implementerPromptExample,
    ),
    SubagentRolePreset(
      label: '复核',
      categories: <SubAgentCategory>{SubAgentCategory.read},
      systemPrompt: SubAgentRegistry.reviewerPromptExample,
    ),
    SubagentRolePreset(
      label: '逆向分析',
      categories: <SubAgentCategory>{SubAgentCategory.read},
      systemPrompt: SubAgentRegistry.apkAnalystPromptExample,
    ),
    SubagentRolePreset(
      label: '补丁',
      categories: <SubAgentCategory>{
        SubAgentCategory.read,
        SubAgentCategory.write,
      },
      systemPrompt: SubAgentRegistry.apkPatcherPromptExample,
    ),
  ];
}

/// 子代理编辑器（新建 / 编辑共用）。
class SubagentEditorPage extends StatefulWidget {
  const SubagentEditorPage({
    super.key,
    this.initial,
    this.takenSlugs = const <String>{},
  });

  final SubAgentDefinition? initial;

  /// 已被别的自定义子代理占用的标识（保存时查重）。
  final Set<String> takenSlugs;

  @override
  State<SubagentEditorPage> createState() => _SubagentEditorPageState();
}

class _SubagentEditorPageState extends State<SubagentEditorPage> {
  late final TextEditingController _name;
  late final TextEditingController _description;
  late final TextEditingController _systemPrompt;
  late final TextEditingController _maxSteps;
  late final TextEditingController _timeoutSeconds;
  /// 启用的技能（逗号/空格分隔）。2026-09-29 之前这个字段只有数据模型，
  /// 编辑器里根本没有入口——「启用技能」是个谁也点不到的空开关。
  late final TextEditingController _skills;
  late Set<SubAgentCategory> _categories;
  late bool _requiresApproval;
  late SubAgentDomain _domain;
  String? _nameError;
  String? _stepsError;
  String? _timeoutError;

  @override
  void initState() {
    super.initState();
    final initial = widget.initial;
    _name = TextEditingController(text: initial?.name ?? '');
    _description = TextEditingController(text: initial?.description ?? '');
    _systemPrompt = TextEditingController(text: initial?.systemPrompt ?? '');
    _maxSteps = TextEditingController(
      text: '${initial?.maxSteps ?? SubAgentDefinition.defaultMaxSteps}',
    );
    _timeoutSeconds = TextEditingController(
      text:
          '${(initial?.timeoutMs ?? SubAgentDefinition.defaultTimeoutMs) ~/ 1000}',
    );
    _skills = TextEditingController(
      text: (initial?.enabledSkills ?? const <String>{}).join('，'),
    );
    _categories = <SubAgentCategory>{
      ...(initial?.categories ??
          const <SubAgentCategory>{SubAgentCategory.read}),
    };
    _requiresApproval = initial?.requiresApproval ?? true;
    _domain = initial?.domain ?? SubAgentDomain.any;
    _name.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    _name.dispose();
    _description.dispose();
    _systemPrompt.dispose();
    _maxSteps.dispose();
    _timeoutSeconds.dispose();
    _skills.dispose();
    super.dispose();
  }

  String get _slug => SubAgentDefinition.slugify(_name.text.trim());

  void _applyPreset(SubagentRolePreset preset) {
    setState(() {
      if (_systemPrompt.text.trim().isEmpty) {
        _systemPrompt.text = preset.systemPrompt;
      }
      _categories = <SubAgentCategory>{...preset.categories};
      if (preset.categories.contains(SubAgentCategory.write)) {
        _requiresApproval = true;
      }
    });
  }

  /// 技能名分隔：中英文逗号、顿号、分号、空白都当分隔符（用户不会记格式）。
  static Set<String> _parseSkills(String raw) => <String>{
    for (final part in raw.split(RegExp(r'[,，、;；\s]+')))
      if (part.trim().isNotEmpty) part.trim(),
  };

  void _save() {
    final l10n = AppLocalizations.of(context)!;
    final name = _name.text.trim();
    final slug = SubAgentDefinition.slugify(name);
    final steps = int.tryParse(_maxSteps.text.trim());
    final timeout = int.tryParse(_timeoutSeconds.text.trim());
    setState(() {
      _nameError = name.isEmpty
          ? l10n.subagentsValidationName
          : (widget.takenSlugs.contains(slug) ? l10n.subagentsSlugTaken : null);
      _stepsError = (steps == null || steps < 1 || steps > 500)
          ? l10n.subagentsValidationSteps
          : null;
      _timeoutError = (timeout == null || timeout < 10 || timeout > 3600)
          ? l10n.subagentsValidationTimeout
          : null;
    });
    if (_nameError != null || _stepsError != null || _timeoutError != null) {
      return;
    }
    final definition = SubAgentDefinition(
      id: widget.initial?.id ?? 'sub-${DateTime.now().microsecondsSinceEpoch}',
      name: name,
      description: _description.text.trim(),
      systemPrompt: _systemPrompt.text.trim(),
      categories: _categories.isEmpty
          ? const <SubAgentCategory>{SubAgentCategory.read}
          : _categories,
      maxSteps: steps!,
      timeoutMs: timeout! * 1000,
      requiresApproval: _requiresApproval,
      domain: _domain,
      enabledSkills: _parseSkills(_skills.text),
    );
    Navigator.of(context).pop(definition);
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final allowed = context
        .watch<AssistantProvider>()
        .currentAssistant
        ?.localToolIds
        .toSet();
    return Scaffold(
      appBar: AppBar(
        title: Text(
          widget.initial == null ? l10n.subagentsAdd : l10n.subagentsEdit,
        ),
        actions: [
          TextButton(
            onPressed: _save,
            child: Text(MaterialLocalizations.of(context).saveButtonLabel),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
        children: [
          _Section(
            title: l10n.subagentsSectionBasic,
            blocks: [
              _FieldRow(
                child: TextField(
                  controller: _name,
                  decoration: InputDecoration(
                    labelText: l10n.subagentsName,
                    isDense: true,
                    border: InputBorder.none,
                    errorText: _nameError,
                  ),
                ),
              ),
              _FieldRow(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '${l10n.subagentsSlugLabel}  $_slug',
                      style: TextStyle(
                        fontSize: 12.5,
                        color: cs.onSurface.withValues(alpha: 0.6),
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      l10n.subagentsSlugHint,
                      style: TextStyle(
                        fontSize: 11.5,
                        height: 1.35,
                        color: cs.onSurface.withValues(alpha: 0.5),
                      ),
                    ),
                    const SizedBox(height: 10),
                    Text(
                      l10n.subagentsDomainLabel,
                      style: TextStyle(
                        fontSize: 12,
                        color: cs.onSurface.withValues(alpha: 0.6),
                      ),
                    ),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 6,
                      children: [
                        for (final domain in SubAgentDomain.values)
                          ChoiceChip(
                            label: Text(domain.title),
                            selected: _domain == domain,
                            onSelected: (_) => setState(() => _domain = domain),
                          ),
                      ],
                    ),
                  ],
                ),
              ),
              _FieldRow(
                child: TextField(
                  controller: _description,
                  minLines: 2,
                  maxLines: 4,
                  decoration: InputDecoration(
                    labelText: l10n.subagentsDescription,
                    isDense: true,
                    border: InputBorder.none,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          _Section(
            title: l10n.subagentsTools,
            blocks: [
              for (final category in SubAgentCategory.values)
                _CategoryRow(
                  category: category,
                  selected: _categories.contains(category),
                  grantedTools: SubAgentRegistry.toolNamesFor(
                    <SubAgentCategory>{category},
                    allowed: allowed,
                  ).length,
                  grantedLabel: l10n.subagentsToolsGranted(
                    SubAgentRegistry.toolNamesFor(<SubAgentCategory>{
                      category,
                    }, allowed: allowed).length,
                  ),
                  description: switch (category) {
                    SubAgentCategory.read => l10n.subagentsCategoryReadDesc,
                    SubAgentCategory.write => l10n.subagentsCategoryWriteDesc,
                    SubAgentCategory.shell => l10n.subagentsCategoryShellDesc,
                  },
                  onChanged: (selected) => setState(() {
                    if (selected) {
                      _categories.add(category);
                    } else {
                      _categories.remove(category);
                    }
                  }),
                ),
              _FieldRow(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    TextField(
                      controller: _skills,
                      decoration: const InputDecoration(
                        labelText: '启用的技能（可留空）',
                        hintText: '例如：so-lab，com.example.pack，用逗号分隔',
                        isDense: true,
                        border: InputBorder.none,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      '填了就在这个子代理的提示里点名这些技能，并授予技能读取工具'
                      '（get_solab_skill / get_installed_skills）；留空表示不启用。'
                      '技能只是工作流建议，不会绕过只读与审批边界。',
                      style: TextStyle(
                        fontSize: 11.5,
                        height: 1.35,
                        color: cs.onSurface.withValues(alpha: 0.5),
                      ),
                    ),
                  ],
                ),
              ),
            ],
            footnote: l10n.subagentsToolsFootnote,
          ),
          const SizedBox(height: 18),
          _Section(
            title: l10n.subagentsSectionBudget,
            blocks: [
              _FieldRow(
                child: Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _maxSteps,
                        keyboardType: TextInputType.number,
                        decoration: InputDecoration(
                          labelText: l10n.subagentsMaxSteps,
                          isDense: true,
                          border: InputBorder.none,
                          errorText: _stepsError,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: TextField(
                        controller: _timeoutSeconds,
                        keyboardType: TextInputType.number,
                        decoration: InputDecoration(
                          labelText: l10n.subagentsTimeout,
                          isDense: true,
                          border: InputBorder.none,
                          errorText: _timeoutError,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              _SwitchRow(
                title: l10n.subagentsRequiresApproval,
                subtitle: l10n.subagentsApprovalSubtitle,
                value: _requiresApproval,
                onChanged: (value) => setState(() => _requiresApproval = value),
              ),
            ],
            footnote: l10n.subagentsBudgetFootnote,
          ),
          const SizedBox(height: 18),
          _Section(
            title: l10n.subagentsSectionPrompt,
            blocks: [
              _FieldRow(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      l10n.subagentsPromptPresets,
                      style: TextStyle(
                        fontSize: 12,
                        color: cs.onSurface.withValues(alpha: 0.6),
                      ),
                    ),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 6,
                      runSpacing: 4,
                      children: [
                        for (final preset in SubagentRolePreset.all)
                          ActionChip(
                            label: Text(preset.label),
                            onPressed: () => _applyPreset(preset),
                          ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    TextField(
                      controller: _systemPrompt,
                      minLines: 6,
                      maxLines: 14,
                      style: const TextStyle(fontSize: 13, height: 1.45),
                      decoration: const InputDecoration(
                        isDense: true,
                        border: InputBorder.none,
                        hintText: '…',
                      ),
                    ),
                  ],
                ),
              ),
            ],
            footnote: l10n.subagentsPromptHint,
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// 页面内共用的小组件（与设置页其它页面同一套：surfaceCard 卡片 + 分组标题）。
// ---------------------------------------------------------------------------

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.blocks, this.footnote});

  final String title;
  final List<Widget> blocks;
  final String? footnote;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final isDark = theme.brightness == Brightness.dark;
    final bg = context.appColors.surfaceCard;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 6),
          child: Text(
            title,
            style: TextStyle(
              fontSize: 13,
              fontWeight: AppFontWeights.semibold,
              color: cs.onSurface.withValues(alpha: 0.8),
            ),
          ),
        ),
        Container(
          decoration: BoxDecoration(
            color: bg,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
              color: cs.outlineVariant.withValues(alpha: isDark ? 0.08 : 0.06),
              width: 0.6,
            ),
          ),
          clipBehavior: Clip.antiAlias,
          child: Column(
            children: [
              for (var i = 0; i < blocks.length; i++) ...[
                blocks[i],
                if (i != blocks.length - 1) const _Divider(),
              ],
            ],
          ),
        ),
        if (footnote != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
            child: Text(
              footnote!,
              style: TextStyle(
                fontSize: 11.5,
                height: 1.4,
                color: cs.onSurface.withValues(alpha: 0.55),
              ),
            ),
          ),
      ],
    );
  }
}

class _Divider extends StatelessWidget {
  const _Divider();

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return Padding(
      padding: const EdgeInsets.only(left: 14),
      child: Divider(
        height: 0.6,
        thickness: 0.6,
        color: cs.outlineVariant.withValues(alpha: isDark ? 0.08 : 0.06),
      ),
    );
  }
}

String Function(SubAgentCategory) _categoryLabel(AppLocalizations l10n) {
  return (category) => switch (category) {
    SubAgentCategory.read => l10n.subagentsToolsRead,
    SubAgentCategory.write => l10n.subagentsToolsWrite,
    SubAgentCategory.shell => l10n.subagentsToolsShell,
  };
}

class _Tag extends StatelessWidget {
  const _Tag({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: cs.primary.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 11,
          height: 1.2,
          color: cs.primary,
          fontWeight: AppFontWeights.medium,
        ),
      ),
    );
  }
}

class _CategoryPreviewRow extends StatelessWidget {
  const _CategoryPreviewRow({required this.title, required this.detail});

  final String title;
  final String detail;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 10, 14, 10),
      child: Row(
        children: [
          SizedBox(
            width: 88,
            child: Text(
              title,
              style: TextStyle(
                fontSize: 13.5,
                fontWeight: AppFontWeights.semibold,
                color: cs.onSurface.withValues(alpha: 0.85),
              ),
            ),
          ),
          Expanded(
            child: Text(
              detail,
              style: TextStyle(
                fontSize: 12.5,
                height: 1.35,
                color: cs.onSurface.withValues(alpha: 0.62),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _DefinitionRow extends StatelessWidget {
  const _DefinitionRow({
    required this.definition,
    required this.dispatchLabel,
    required this.builtInTag,
    this.onTap,
    this.onDelete,
    this.deleteTooltip,
  });

  final SubAgentDefinition definition;
  final String dispatchLabel;
  final String builtInTag;
  final VoidCallback? onTap;
  final VoidCallback? onDelete;
  final String? deleteTooltip;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 12, 12),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(
              definition.builtIn ? Lucide.Bot : Lucide.Sparkles,
              size: 20,
              color: cs.primary,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          definition.name,
                          style: TextStyle(
                            fontSize: 15,
                            fontWeight: AppFontWeights.semibold,
                            color: cs.onSurface.withValues(alpha: 0.9),
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      if (definition.builtIn) _Tag(label: builtInTag),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(
                    definition.description,
                    style: TextStyle(
                      fontSize: 12,
                      height: 1.3,
                      color: cs.onSurface.withValues(alpha: 0.62),
                    ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 6),
                  Wrap(
                    spacing: 6,
                    runSpacing: 4,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      for (final category in definition.categories)
                        _Tag(label: _categoryLabel(l10n)(category)),
                      Text(
                        '$dispatchLabel /subagent ${definition.slug}',
                        style: TextStyle(
                          fontSize: 11,
                          color: cs.onSurface.withValues(alpha: 0.45),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            if (onDelete != null)
              IconButton(
                tooltip: deleteTooltip,
                visualDensity: VisualDensity.compact,
                icon: Icon(
                  Lucide.Trash2,
                  size: 18,
                  color: cs.onSurface.withValues(alpha: 0.55),
                ),
                onPressed: onDelete,
              )
            else
              Icon(
                definition.builtIn ? Lucide.BadgeInfo : Lucide.ChevronRight,
                size: 18,
                color: cs.onSurface.withValues(alpha: 0.4),
              ),
          ],
        ),
      ),
    );
  }
}

class _TeamRow extends StatelessWidget {
  const _TeamRow({required this.team, required this.dispatchLabel});

  final SubAgentTeam team;
  final String dispatchLabel;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    final chain = <String>[];
    for (final member in team.members) {
      final waits = member.blockedBy.isEmpty
          ? ''
          : '（等 ${member.blockedBy.join('/')}）';
      chain.add('${member.name}$waits');
    }
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Lucide.ListTree, size: 18, color: cs.primary),
              const SizedBox(width: 10),
              Flexible(
                child: Text(
                  team.name,
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: AppFontWeights.semibold,
                    color: cs.onSurface.withValues(alpha: 0.9),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              _Tag(label: team.domain.title),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            team.description,
            style: TextStyle(
              fontSize: 12,
              height: 1.3,
              color: cs.onSurface.withValues(alpha: 0.62),
            ),
          ),
          const SizedBox(height: 6),
          Text(
            chain.join('  →  '),
            style: TextStyle(
              fontSize: 12,
              height: 1.35,
              color: cs.onSurface.withValues(alpha: 0.75),
            ),
          ),
          const SizedBox(height: 4),
          Text(
            '$dispatchLabel /team <${l10n.subagentsTaskLabel}>'
            '      subagent(team: ${team.id})',
            style: TextStyle(
              fontSize: 11,
              color: cs.onSurface.withValues(alpha: 0.45),
            ),
          ),
        ],
      ),
    );
  }
}

class _CategoryRow extends StatelessWidget {
  const _CategoryRow({
    required this.category,
    required this.selected,
    required this.grantedTools,
    required this.grantedLabel,
    required this.description,
    required this.onChanged,
  });

  final SubAgentCategory category;
  final bool selected;
  final int grantedTools;
  final String grantedLabel;
  final String description;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return InkWell(
      onTap: () => onChanged(!selected),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 10, 12, 10),
        child: Row(
          children: [
            Container(
              width: 20,
              height: 20,
              decoration: BoxDecoration(
                color: selected ? cs.primary : Colors.transparent,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(
                  color: selected
                      ? cs.primary
                      : cs.onSurface.withValues(alpha: 0.3),
                  width: 1.2,
                ),
              ),
              child: selected
                  ? Icon(Lucide.Check, size: 14, color: cs.onPrimary)
                  : null,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        _categoryLabel(l10n)(category),
                        style: TextStyle(
                          fontSize: 14.5,
                          fontWeight: AppFontWeights.semibold,
                          color: cs.onSurface.withValues(alpha: 0.9),
                        ),
                      ),
                      const SizedBox(width: 8),
                      if (grantedTools > 0)
                        _Tag(label: grantedLabel)
                      else
                        Text(
                          l10n.subagentsShellNoGrant,
                          style: TextStyle(
                            fontSize: 11,
                            color: cs.onSurface.withValues(alpha: 0.5),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 3),
                  Text(
                    description,
                    style: TextStyle(
                      fontSize: 12,
                      height: 1.3,
                      color: cs.onSurface.withValues(alpha: 0.62),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _SwitchRow extends StatelessWidget {
  const _SwitchRow({
    required this.title,
    required this.subtitle,
    required this.value,
    required this.onChanged,
  });

  final String title;
  final String subtitle;
  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 10, 12, 10),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 14.5,
                    fontWeight: AppFontWeights.semibold,
                    color: cs.onSurface.withValues(alpha: 0.9),
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  subtitle,
                  style: TextStyle(
                    fontSize: 12,
                    height: 1.3,
                    color: cs.onSurface.withValues(alpha: 0.62),
                  ),
                ),
              ],
            ),
          ),
          Switch.adaptive(value: value, onChanged: onChanged),
        ],
      ),
    );
  }
}

class _FieldRow extends StatelessWidget {
  const _FieldRow({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 10, 14, 10),
      child: child,
    );
  }
}

class _KeyValue extends StatelessWidget {
  const _KeyValue(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 72,
            child: Text(
              label,
              style: TextStyle(
                fontSize: 12.5,
                color: cs.onSurface.withValues(alpha: 0.55),
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                fontSize: 12.5,
                color: cs.onSurface.withValues(alpha: 0.85),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
