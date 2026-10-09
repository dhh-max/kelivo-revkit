import 'dart:async';
import '../../../shared/widgets/snackbar.dart';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/models/memory_entry.dart';
import '../../../core/providers/memory_provider_v2.dart';
import '../../../core/providers/settings_provider.dart';
import '../../../core/services/api/chat_api_service.dart';
import '../../../core/services/logging/flutter_logger.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../shared/widgets/settings_section.dart';
import '../../../shared/widgets/ios_tactile.dart';
import '../../../theme/app_font_weights.dart';
import '../../settings/pages/memory_entries_page.dart';
import 'apk_rule_page.dart';
import '../services/apk_memory_distill_service.dart';
import '../services/apk_patch_memory_service.dart';
import '../services/apk_progress_service.dart';
import '../services/apk_toolchain_service.dart';
import '../services/apk_workspace_binding_service.dart';
import '../../../core/models/reasoning_request.dart';

/// APK 工作台：工作目录管理 + 分析进度 + 补丁经验记忆入口。
class SolabApkPage extends StatefulWidget {
  const SolabApkPage({super.key});

  @override
  State<SolabApkPage> createState() => _SolabApkPageState();
}

class _SolabApkPageState extends State<SolabApkPage> {
  bool _distilling = false;
  String _signatureBypassDefault = 'off';
  String _fieldRefsMode = 'auto';
  bool _skipNoisySubtrees = false;

  @override
  void initState() {
    super.initState();
    _loadWorkspace();
  }

  Future<void> _loadWorkspace() async {
    final signatureBypassDefault =
        await ApkWorkspaceBindingService.signatureBypassDefaultMode();
    final fieldRefs = await ApkToolchainService.fieldRefsIndexMode();
    final fieldRefsMode = (fieldRefs.data?['mode'] as String?) ?? 'auto';
    final skipNoisy = await ApkToolchainService.semanticIndexSkipNoisyPaths();
    final skipNoisyEnabled = (skipNoisy.data?['enabled'] as bool?) ?? false;
    if (!mounted) return;
    setState(() {
      _signatureBypassDefault = signatureBypassDefault;
      _fieldRefsMode = fieldRefsMode;
      _skipNoisySubtrees = skipNoisyEnabled;
    });
  }



  Future<void> _pickSignatureBypassDefault() async {
    final selected = await showDialog<String>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: const Text('默认去签名'),
        children: [
          SimpleDialogOption(
            onPressed: () => Navigator.of(ctx).pop('off'),
            child: const Text('不开启'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.of(ctx).pop('normal'),
            child: const Text('普通去签'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.of(ctx).pop('original_apk'),
            child: const Text('原包去签'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.of(ctx).pop('dpatch'),
            child: const Text('DPatch 去签'),
          ),
        ],
      ),
    );
    if (selected == null) return;
    await ApkWorkspaceBindingService.setSignatureBypassDefaultMode(selected);
    if (mounted) setState(() => _signatureBypassDefault = selected);
  }

  String get _signatureBypassDefaultLabel => switch (_signatureBypassDefault) {
    'normal' => '普通去签',
    'original_apk' => '原包去签',
    'dpatch' => 'DPatch 去签',
    _ => '不开启（不去签名）',
  };

  String get _fieldRefsIndexLabel => switch (_fieldRefsMode) {
    'on' => '始终预建索引',
    'off' => '始终扫描',
    _ => '自适应（推荐）',
  };

  /// FieldRefs 模式切换（自适应三态，2026-09-02）：auto = 自适应（默认，
  /// 冷启动扫描开工，重复查询自动建索引后切索引查询）；on = 始终预建；
  /// off = 始终扫描。用户一般无需手动切换。
  Future<void> _pickFieldRefsMode() async {
    final selected = await showDialog<String>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: const Text('FieldRefs 索引模式'),
        children: [
          SimpleDialogOption(
            onPressed: () => Navigator.of(ctx).pop('auto'),
            child: const Text('自适应（推荐）：冷启动即开工，重复查询自动建索引'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.of(ctx).pop('on'),
            child: const Text('始终预建索引'),
          ),
          SimpleDialogOption(
            onPressed: () => Navigator.of(ctx).pop('off'),
            child: const Text('始终扫描（不建索引）'),
          ),
        ],
      ),
    );
    if (selected == null || selected == _fieldRefsMode) return;
    final res = await ApkToolchainService.fieldRefsIndexMode(mode: selected);
    if (!mounted) return;
    if (res.ok) {
      setState(
        () => _fieldRefsMode = (res.data?['mode'] as String?) ?? selected,
      );
    } else {
      showAppSnackBar(context, message: res.message ?? '切换 FieldRefs 模式失败', type: NotificationType.error);
    }
  }

  /// 语义索引是否跳过数据性/生成代码子树（B2-3，默认关闭）。
  /// 打开会让已建索引按新口径重建（体积/构建耗时下降，但被跳过的子树只能用
  /// `fullScan=true` 搜原文），所以先确认再落。
  Future<void> _toggleSkipNoisySubtrees(bool value) async {
    if (value) {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('跳过数据性/生成代码子树？'),
          content: const Text(
            '语义索引将不再为本地化文案、高亮词表、intl 消息、生成代码等文件建行，'
            '索引体积与构建耗时随之下降。\n\n'
            '代价：这些文件在语义检索里搜不到，需要时用 search scope=asm '
            'fullScan=true 扫原文。切换后索引会按新口径重建一次。',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('取消'),
            ),
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(true),
              child: const Text('开启'),
            ),
          ],
        ),
      );
      if (confirmed != true) return;
    }
    final res = await ApkToolchainService.semanticIndexSkipNoisyPaths(
      enabled: value,
    );
    if (!mounted) return;
    if (res.ok) {
      setState(
        () => _skipNoisySubtrees = (res.data?['enabled'] as bool?) ?? value,
      );
    } else {
      showAppSnackBar(
        context,
        message: res.message ?? '切换语义索引子树策略失败',
        type: NotificationType.error,
      );
    }
  }

  void _openPage(Widget page) {
    Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => page));
  }

  Future<void> _distill() async {
    final memoryProvider = context.read<MemoryProviderV2>();
    final repo = memoryProvider.repository;
    final settings = context.read<SettingsProvider>();
    final scan = await ApkMemoryDistillService.scan(repo);
    if (!mounted) return;
    final groups = scan.groups;
    if (groups.isEmpty) {
      showAppSnackBar(
        context,
        message: _noDistillReason(scan),
        type: NotificationType.success,
      );
      return;
    }

    // 构造记忆模型回调；模型未配置时降级为确定性合并。
    Future<String> Function(String)? llmCall;
    final provKey = settings.memoryModelProvider;
    final mdlId = settings.memoryModelId;
    if (provKey != null && mdlId != null) {
      final cfg = settings.getProviderConfig(provKey);
      final reasoning = settings.memoryModelThinkingEnabled
          ? ReasoningRequest.auto
          : ReasoningRequest.off;
      llmCall = (prompt) => ChatApiService.generateText(
        config: cfg,
        modelId: mdlId,
        prompt: prompt,
        reasoning: reasoning,
      );
    }

    setState(() => _distilling = true);
    // 先算出每组的合并草案（LLM 失败降级确定性合并），再交给用户预览确认。
    final drafts = <({List<MemoryEntry> group, ApkPatchMemory merged})>[];
    // 某组连降级合并都失败时此前静默消失，用户只看到组数变少。
    var skippedGroups = 0;
    for (final group in groups) {
      try {
        final merged = llmCall != null
            ? await ApkMemoryDistillService.distillGroupWithLlm(
                group: group,
                llmCall: llmCall,
              )
            : ApkMemoryDistillService.distillGroupDeterministic(group);
        drafts.add((group: group, merged: merged));
      } catch (_) {
        try {
          drafts.add((
            group: group,
            merged: ApkMemoryDistillService.distillGroupDeterministic(group),
          ));
        } catch (_) {
          skippedGroups++;
        }
      }
    }
    if (!mounted) return;
    setState(() => _distilling = false);
    if (drafts.isEmpty) {
      showAppSnackBar(context, message: '蒸馏失败：没有产出任何合并草案。', type: NotificationType.error);
      return;
    }

    // 预览确认：逐组展示「N 条 → 合并后」，勾选后写回（归档旧条目）。
    final confirmed = await showModalBottomSheet<List<int>>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) =>
          _DistillPreviewSheet(drafts: drafts, usedLlm: llmCall != null),
    );
    if (confirmed == null || confirmed.isEmpty) return;

    var distilled = 0;
    final failedTitles = <String>[];
    for (final i in confirmed) {
      final draft = drafts[i];
      try {
        await ApkMemoryDistillService.applyDistill(
          repo: repo,
          group: draft.group,
          merged: draft.merged,
        );
        distilled++;
      } catch (e, s) {
        // 此前 catch(_){} 直接吞掉：用户只看到成功数变少，无法知道是哪几条
        // 没整理成功、也无法确认原条目是否被动过。这里落日志并列出失败项。
        FlutterLogger.log(
          '蒸馏写回失败：${draft.merged.title}：$e\n$s',
          tag: 'ApkDistill',
        );
        failedTitles.add(draft.merged.title);
      }
    }
    await memoryProvider.reloadCurrentScope();
    if (!mounted) return;
    final skipNote = skippedGroups > 0 ? '；另有 $skippedGroups 组无法合并已跳过' : '';
    final message = (failedTitles.isEmpty
            ? '已整理 $distilled 个 APP，每个 APP 只保留一条完整经验'
            : '已整理 $distilled 个；${failedTitles.length} 个失败（原条目未改动）：'
                '${_summarizeTitles(failedTitles)}') +
        skipNote;
    // 成功也走 error 样式会让用户以为失败（2026-09-29 修复）：按失败数定类型。
    showAppSnackBar(
      context,
      message: message,
      type: failedTitles.isEmpty
          ? NotificationType.success
          : NotificationType.warning,
    );
  }

  /// 「无需整理」要说清为什么（用户 2026-10-04：只看到一句话等于黑盒）。
  String _noDistillReason(ApkDistillScan scan) {
    if (scan.activePatchCount == 0) return '暂无 APK 经验可整理。';
    final parts = <String>[
      if (scan.appsWithSingle > 0) '${scan.appsWithSingle} 个 APP 各只有一条经验',
      if (scan.withoutAppId > 0)
        '${scan.withoutAppId} 条缺包名（无法判定是否同一 APP，保守不合并）',
      if (scan.degenerate > 0) '${scan.degenerate} 条指纹退化（无厂商/无壳/无指纹）',
    ];
    if (parts.isEmpty) return '无需整理：当前每个 APP 已只有一条经验。';
    return '无需整理：${parts.join('；')}。';
  }

  /// 汇总失败条目标题：超过 3 条只列前 3 条，避免长标题把 SnackBar 撑爆。
  String _summarizeTitles(List<String> titles) {
    if (titles.length <= 3) return titles.join('、');
    return '${titles.take(3).join('、')} 等 ${titles.length} 个';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('APK 设置')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // 用户 2026-10-04：「原来的选择工作目录、还有它的说明文字，这个就不要了」
          // ——工作目录现在由**工作区**决定（默认工作区就是那个本地目录），
          // 这里只留 APK 专属设置。
          SettingsSectionCard(
            children: [
              SettingsActionRow(
                icon: Lucide.Shield,
                label: '默认去签名',
                detailText: _signatureBypassDefaultLabel,
                trailing: const Icon(Lucide.ChevronRight, size: 18),
                onTap: _pickSignatureBypassDefault,
              ),
              SettingsActionRow(
                icon: Lucide.Database,
                label: 'FieldRefs 索引模式',
                detailText: _fieldRefsIndexLabel,
                trailing: const Icon(Lucide.ChevronRight, size: 18),
                onTap: _pickFieldRefsMode,
              ),
              SettingsActionRow(
                icon: Lucide.Filter,
                label: '语义索引跳过噪音子树',
                detailText: _skipNoisySubtrees ? '已开启（重建后生效）' : '关闭（默认）',
                trailing: Switch(
                  value: _skipNoisySubtrees,
                  onChanged: _toggleSkipNoisySubtrees,
                ),
                onTap: () => _toggleSkipNoisySubtrees(!_skipNoisySubtrees),
              ),
            ],
          ),
          const SizedBox(height: 12),
          _ProgressCard(),
          const SizedBox(height: 12),
          SettingsSectionCard(
            children: [
              SettingsActionRow(
                icon: Lucide.ScanSearch,
                label: '自定义特征',
                detailText: '广告特征规则库：分类浏览 / 订阅同步 / 厂商开关',
                trailing: const Icon(Lucide.ChevronRight, size: 18),
                onTap: () => _openPage(const ApkRulePage()),
              ),
              SettingsActionRow(
                icon: Lucide.Bookmark,
                label: '记忆（经验 / 笔记）',
                detailText: 'APK 经验与修改笔记已并入记忆系统，统一管理',
                trailing: const Icon(Lucide.ChevronRight, size: 18),
                onTap: () => _openPage(const MemoryEntriesPage()),
              ),
              SettingsActionRow(
                icon: Lucide.Sparkles,
                label: '整理蒸馏经验',
                detailText: _distilling ? '正在生成合并草案…' : '同一 APP 的零散经验合并为唯一一条',
                trailing: _distilling
                    ? const SizedBox.square(
                        dimension: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Lucide.ChevronRight, size: 18),
                onTap: _distilling ? null : _distill,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

/// 蒸馏预览面板：逐组展示「N 条零散经验 → 合并后」，勾选确认后写回。
/// 返回选中的 draft 下标列表；取消返回 null。
class _DistillPreviewSheet extends StatefulWidget {
  const _DistillPreviewSheet({required this.drafts, required this.usedLlm});

  final List<({List<MemoryEntry> group, ApkPatchMemory merged})> drafts;
  final bool usedLlm;

  @override
  State<_DistillPreviewSheet> createState() => _DistillPreviewSheetState();
}

class _DistillPreviewSheetState extends State<_DistillPreviewSheet> {
  late final Set<int> _checked = {
    for (var i = 0; i < widget.drafts.length; i++) i,
  };

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return SafeArea(
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxHeight: MediaQuery.of(context).size.height * 0.72,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 16, 20, 8),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          '蒸馏预览（${widget.drafts.length} 组）',
                          style: TextStyle(
                            fontSize: 17,
                            fontWeight: AppFontWeights.semibold,
                            color: cs.onSurface,
                          ),
                        ),
                      ),
                      IosIconButton(
                        icon: Lucide.X,
                        color: cs.onSurface,
                        size: 20,
                        onTap: () => Navigator.of(context).pop(),
                      ),
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    widget.usedLlm
                        ? '由记忆模型合并；确认后只保留一条完整记忆'
                        : '未配置记忆模型，使用确定性完整合并',
                    style: TextStyle(
                      fontSize: 12,
                      color: cs.onSurface.withValues(alpha: .6),
                    ),
                  ),
                ],
              ),
            ),
            const Divider(height: 1),
            Flexible(
              // 不加 shrinkWrap：父级 Flexible 已给出有界高度，加上会让
              // ListView.builder 在布局阶段完整构建所有分组，失去懒加载。
              child: ListView.builder(
                padding: const EdgeInsets.symmetric(vertical: 8),
                itemCount: widget.drafts.length,
                itemBuilder: (ctx, i) {
                  final d = widget.drafts[i];
                  final checked = _checked.contains(i);
                  return CheckboxListTile(
                    value: checked,
                    dense: true,
                    controlAffinity: ListTileControlAffinity.leading,
                    contentPadding: const EdgeInsets.symmetric(horizontal: 16),
                    title: Text(
                      d.merged.title.isEmpty ? '（无标题）' : d.merged.title,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 14,
                        fontWeight: AppFontWeights.semibold,
                      ),
                    ),
                    subtitle: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '${d.group.length} 条 → ${d.merged.solution}',
                          maxLines: 3,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontSize: 12.5, height: 1.3),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          '${d.merged.outcome} · '
                          '${((d.merged.fingerprint['vendors'] as List?) ?? const []).join('+')}',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            fontSize: 11,
                            color: cs.onSurface.withValues(alpha: .5),
                          ),
                        ),
                      ],
                    ),
                    onChanged: (v) => setState(() {
                      if (v == true) {
                        _checked.add(i);
                      } else {
                        _checked.remove(i);
                      }
                    }),
                  );
                },
              ),
            ),
            const Divider(height: 1),
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 16),
              child: Row(
                children: [
                  Expanded(
                    child: FilledButton(
                      onPressed: _checked.isEmpty
                          ? null
                          : () => Navigator.of(context).pop(_checked.toList()),
                      child: Text(
                        '合并 ${_checked.length}/${widget.drafts.length} 组',
                      ),
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

/// 最近一次原生分析进度（EventChannel 'solab/progress'）。
class _ProgressCard extends StatefulWidget {
  @override
  State<_ProgressCard> createState() => _ProgressCardState();
}

class _ProgressCardState extends State<_ProgressCard> {
  @override
  void initState() {
    super.initState();
    ApkProgressService.instance.addListener(_onProgress);
  }

  @override
  void dispose() {
    ApkProgressService.instance.removeListener(_onProgress);
    super.dispose();
  }

  void _onProgress() {
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final progress = ApkProgressService.instance;
    if (!progress.hasProgress) return const SizedBox.shrink();
    // 原生进度从 5 起步、结束时发 100/"分析完成"（SolabChannel.kt:770；SO 引擎
    // 同理 :1756）。此前界面把任何非 0 进度都写成"分析中 N%"，收尾后仍挂着
    // "分析中 60%"，看起来像永远跑不完（2026-09-29 修复）。
    final done = progress.percent >= 100;
    // SO 引擎进度走另一条通道，此前界面从未读取（长任务看不到在动）。
    final soText = progress.hasSoProgress
        ? '${progress.soStage} ${progress.soPercent}%'
        : null;
    final text = done
        ? '分析已完成 · ${progress.stage}'
        : [
            '分析中 ${progress.percent}% · ${progress.stage}',
            if (soText != null) soText,
          ].join('  ·  ');
    return SettingsSectionCard(
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          child: Row(
            children: [
              if (done)
                Icon(Lucide.CheckCircle, size: 18, color: cs.primary)
              else
                SizedBox.square(
                  dimension: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2.5,
                    value: progress.percent / 100,
                    color: cs.primary,
                  ),
                ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  text,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(fontSize: 13, color: cs.onSurfaceVariant),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

/// 一次性生命周期观察者：应用回到前台（resume）时回调一次。

