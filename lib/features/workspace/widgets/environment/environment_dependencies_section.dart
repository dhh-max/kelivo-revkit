import 'dart:async';
import 'package:flutter/material.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';
import 'package:provider/provider.dart';

import 'package:solab/core/models/environment_state.dart';
import 'package:solab/core/providers/environment_provider.dart';
import 'package:solab/core/services/sandbox/environment_dependencies.dart';
import 'package:solab/core/services/sandbox/mirror_service.dart';
import 'package:solab/features/workspace/widgets/environment/environment_chrome.dart';
import 'package:solab/features/workspace/widgets/environment/environment_dialogs.dart';
import 'package:solab/features/workspace/widgets/environment/environment_labels.dart';
import 'package:solab/icons/lucide_adapter.dart';
import 'package:solab/l10n/app_localizations.dart';
import 'package:solab/shared/widgets/ios_settings_rows.dart';
import 'package:solab/shared/widgets/ios_tactile.dart';
import 'package:solab/shared/widgets/ios_tile_button.dart';
import 'package:solab/shared/widgets/section_card.dart';
import 'package:solab/shared/widgets/snackbar.dart';

String _title(AppLocalizations l10n, EnvironmentDependency dependency) =>
    switch (dependency) {
      EnvironmentDependency.python => 'Python',
      EnvironmentDependency.node => 'Node.js',
      EnvironmentDependency.git => 'Git',
      EnvironmentDependency.ssh => 'SSH',
      EnvironmentDependency.network => l10n.workspaceEnvDependencyNetwork,
      EnvironmentDependency.archive => l10n.workspaceEnvDependencyArchive,
      EnvironmentDependency.json => 'JSON CLI',
      EnvironmentDependency.search => '代码检索',
      EnvironmentDependency.build => '本机编译',
      EnvironmentDependency.java => 'OpenJDK',
      EnvironmentDependency.binutils => '二进制分析',
    };
String _detail(AppLocalizations l10n, EnvironmentDependency dependency) =>
    switch (dependency) {
      EnvironmentDependency.python => l10n.workspaceEnvDependencyPython,
      EnvironmentDependency.node => l10n.workspaceEnvDependencyNode,
      EnvironmentDependency.git => l10n.workspaceEnvDependencyGit,
      EnvironmentDependency.ssh => l10n.workspaceEnvDependencySsh,
      EnvironmentDependency.network => 'curl · wget',
      EnvironmentDependency.archive => 'zip · unzip',
      EnvironmentDependency.json => 'jq',
      EnvironmentDependency.search => 'ripgrep (rg)',
      EnvironmentDependency.build => 'GCC · G++ · make（约 300MB，原生模块/小型 C 工具）',
      EnvironmentDependency.java => 'java · javac（约 200MB，JVM/Gradle 构建用）',
      EnvironmentDependency.binutils => 'readelf · objdump',
    };
IconData _icon(EnvironmentDependency dependency) => switch (dependency) {
  EnvironmentDependency.python => Lucide.Code,
  EnvironmentDependency.node => Lucide.Boxes,
  EnvironmentDependency.git => LucideIcons.gitBranch,
  EnvironmentDependency.ssh => LucideIcons.key,
  EnvironmentDependency.network => Lucide.Globe,
  EnvironmentDependency.archive => LucideIcons.archive,
  EnvironmentDependency.json => Lucide.Braces,
  EnvironmentDependency.search => Lucide.Search,
  EnvironmentDependency.build => Lucide.Hammer,
  EnvironmentDependency.java => Lucide.Cpu,
  EnvironmentDependency.binutils => Lucide.Binary,
};
String _status(
  AppLocalizations l10n,
  EnvironmentDependencies service,
  EnvironmentDependency dependency,
) {
  if (service.installing == dependency) {
    return l10n.workspaceEnvDependencyInstalling;
  }
  return switch (service.status(dependency)) {
    DependencyStatus.installed => l10n.workspaceEnvDependencyInstalled,
    DependencyStatus.missing => l10n.workspaceEnvPhaseNotInstalled,
    DependencyStatus.unknown => l10n.workspaceEnvDependencyUnknown,
  };
}

String? _failure(AppLocalizations l10n, DependencyFailure? failure) =>
    switch (failure) {
      DependencyFailure.check => l10n.workspaceEnvDependencyCheckFailed,
      DependencyFailure.install => l10n.workspaceEnvDependencyInstallFailed,
      DependencyFailure.cancelled => l10n.workspaceEnvErrorCancelled,
      null => null,
    };

class EnvironmentDependenciesSection extends StatefulWidget {
  const EnvironmentDependenciesSection({
    super.key,
    required this.service,
    required this.enabled,
  });
  final EnvironmentDependencies service;
  final bool enabled;

  @override
  State<EnvironmentDependenciesSection> createState() =>
      _EnvironmentDependenciesSectionState();
}

class _EnvironmentDependenciesSectionState
    extends State<EnvironmentDependenciesSection> {
  bool _batchInstalling = false;
  int _batchIndex = 0;
  int _batchTotal = 0;

  /// 每个依赖安装前用哪几类源检测最快镜像（与单装逻辑同口径）。
  Set<MirrorCategory> _categoriesFor(
    EnvironmentDependencies service,
    EnvironmentDependency dependency,
  ) => <MirrorCategory>{
    service.alpine ? MirrorCategory.apk : MirrorCategory.apt,
    if (dependency == EnvironmentDependency.python) MirrorCategory.pip,
    if (dependency == EnvironmentDependency.node) MirrorCategory.npm,
  };

  /// 一键安装：只装**缺失**的依赖，按顺序来；**每个安装前自动检测最快镜像**
  /// （用户 2026-10-03：「依赖那么多，搞一个一键安装，每个安装前自动检测最快的」）。
  ///
  /// 失败即停：连着装失败通常意味着源/网络问题，继续装只会刷更多失败。
  Future<void> _installMissing() async {
    final service = widget.service;
    final pending = service.dependenciesToInstall();
    if (pending.isEmpty || _batchInstalling) return;
    final mirrors = context.read<MirrorService?>();
    setState(() {
      _batchInstalling = true;
      _batchTotal = pending.length;
      _batchIndex = 0;
    });
    try {
      for (var i = 0; i < pending.length; i++) {
        if (!mounted) return;
        setState(() => _batchIndex = i + 1);
        final dependency = pending[i];
        if (mirrors != null) {
          try {
            await runDetectFastMirrors(
              context: context,
              mirrors: mirrors,
              categories: _categoriesFor(service, dependency),
            );
          } catch (_) {
            // 检测失败不阻断安装：install() 会按当前选择/官方源继续。
          }
        }
        if (!mounted) return;
        await service.install(dependency);
        if (!mounted) return;
        if (service.failure != null) break;
      }
    } finally {
      if (mounted) {
        setState(() {
          _batchInstalling = false;
          _batchIndex = 0;
          _batchTotal = 0;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final service = widget.service;
    final enabled = widget.enabled;
    // 用户 2026-10-06：「一键安装缺失依赖点击没反应」——过去 onTap 在
    // enabled=false / 无缺失项时直接为 null，行外观不变但点了没反应。
    // 现在**永远可点**，点不动的情况给明确原因（未就绪/已装齐/安装中）。
    final envReady = service.env.state.phase == EnvironmentPhase.ready;
    final missing = service.dependenciesToInstall();
    final canRunBatch =
        enabled && !service.busy && envReady && service.supportsPackages;
    return ListenableBuilder(
      listenable: service,
      builder: (context, _) => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          IosSectionHeader(text: l10n.workspaceEnvDependencies),
          SectionCard(
            children: [
              for (final dependency in EnvironmentDependency.values) ...[
                if (dependency.index > 0) const EnvironmentRowDivider(),
                IosNavRow(
                  key: ValueKey('environment-dependency-${dependency.name}'),
                  icon: _icon(dependency),
                  label: _title(l10n, dependency),
                  subtitle: _detail(l10n, dependency),
                  detailText: _status(l10n, service, dependency),
                  onTap:
                      enabled &&
                          (!service.busy || service.installing == dependency)
                      ? () => Navigator.of(context).push(
                          MaterialPageRoute<void>(
                            builder: (_) => EnvironmentDependencyPage(
                              service: service,
                              dependency: dependency,
                            ),
                          ),
                        )
                      : null,
                ),
              ],
              const EnvironmentRowDivider(),
              // 一键安装：缺失的依赖按顺序装，每个安装前自动检测最快镜像。
              IosNavRow(
                key: const ValueKey('environment-dependency-install-missing'),
                icon: Lucide.Download,
                label: _batchInstalling
                    ? l10n.workspaceEnvInstallMissingProgress(
                        _batchIndex,
                        _batchTotal,
                      )
                    : (canRunBatch && missing.isNotEmpty
                          ? l10n.workspaceEnvInstallMissingCount(missing.length)
                          : l10n.workspaceEnvInstallMissing),
                subtitle: !envReady
                    ? l10n.workspaceEnvInstallMissingNotReady
                    : service.busy
                    ? l10n.workspaceEnvInstallMissingBusy
                    : missing.isEmpty
                    ? l10n.workspaceEnvInstallMissingNone
                    : l10n.workspaceEnvInstallMissingDetail,
                trailing: _batchInstalling
                    ? const EnvironmentInlineSpinner(radius: 8)
                    : null,
                // 永远可点：能装就装；不能装也一定有回应（原因见 subtitle）。
                onTap: () {
                  if (_batchInstalling) return;
                  if (!envReady || !service.supportsPackages) {
                    showAppSnackBar(
                      context,
                      message: l10n.workspaceEnvInstallMissingNotReady,
                      type: NotificationType.warning,
                    );
                    return;
                  }
                  if (service.busy) {
                    showAppSnackBar(
                      context,
                      message: l10n.workspaceEnvInstallMissingBusy,
                    );
                    return;
                  }
                  if (missing.isEmpty) {
                    showAppSnackBar(
                      context,
                      message: l10n.workspaceEnvInstallMissingNone,
                      type: NotificationType.success,
                    );
                    return;
                  }
                  unawaited(_installMissing());
                },
              ),
              const EnvironmentRowDivider(),
              IosNavRow(
                icon: Lucide.RefreshCw,
                label: service.busy && service.installing == null
                    ? l10n.workspaceEnvDependencyChecking
                    : l10n.workspaceEnvDependencyRefresh,
                trailing: service.busy && service.installing == null
                    ? const EnvironmentInlineSpinner(radius: 8)
                    : const SizedBox.shrink(),
                onTap: enabled && !service.busy
                    ? () => unawaited(service.refresh())
                    : null,
              ),
            ],
          ),
          IosSectionFooter(
            text: enabled
                ? l10n.workspaceEnvDependenciesDetail
                : l10n.workspaceEnvDependencyReadyFirst,
          ),
          if (_failure(l10n, service.failure) case final error?)
            IosSectionFooter(text: error),
        ],
      ),
    );
  }
}

class EnvironmentDependencyPage extends StatefulWidget {
  const EnvironmentDependencyPage({
    super.key,
    required this.service,
    required this.dependency,
  });
  final EnvironmentDependencies service;
  final EnvironmentDependency dependency;
  @override
  State<EnvironmentDependencyPage> createState() =>
      _EnvironmentDependencyPageState();
}

class _EnvironmentDependencyPageState extends State<EnvironmentDependencyPage> {
  bool _detecting = false;
  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final env = context.watch<EnvironmentProvider>();
    final mirrors = context.watch<MirrorService?>();
    final service = widget.service;
    final dependency = widget.dependency;
    final categories = <MirrorCategory>{
      service.alpine ? MirrorCategory.apk : MirrorCategory.apt,
      if (dependency == EnvironmentDependency.python) MirrorCategory.pip,
      if (dependency == EnvironmentDependency.node) MirrorCategory.npm,
    };
    return ListenableBuilder(
      listenable: service,
      builder: (context, _) {
        final enabled =
            env.state.phase == EnvironmentPhase.ready &&
            !service.busy &&
            !_detecting;
        return Scaffold(
          backgroundColor: cs.surface,
          appBar: AppBar(
            leading: IosIconButton(
              icon: Lucide.ArrowLeft,
              onTap: () => Navigator.of(context).maybePop(),
            ),
            title: Text(_title(l10n, dependency)),
          ),
          body: ListView(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
            children: [
              SectionCard(
                children: [
                  IosNavRow(
                    icon: _icon(dependency),
                    label: _title(l10n, dependency),
                    subtitle: _detail(l10n, dependency),
                    trailing: Text(
                      _status(l10n, service, dependency),
                      style: TextStyle(fontSize: 12, color: cs.primary),
                    ),
                  ),
                ],
              ),
              IosSectionHeader(text: l10n.workspaceEnvDependencySources),
              SectionCard(
                children: [
                  for (final category in categories) ...[
                    if (category != categories.first)
                      const EnvironmentRowDivider(),
                    IosNavRow(
                      icon: Lucide.Package,
                      label: workspaceEnvCategoryLabel(l10n, category),
                      detailText: workspaceEnvSelectionLabel(
                        l10n,
                        env.mirrors[category],
                        category: category,
                      ),
                      onTap: enabled && mirrors != null
                          ? () => unawaited(
                              openMirrorPage(context, category: category),
                            )
                          : null,
                    ),
                  ],
                  const EnvironmentRowDivider(),
                  IosNavRow(
                    icon: Lucide.Gauge,
                    label: l10n.workspaceEnvDetectFastMirrors,
                    trailing: const SizedBox.shrink(),
                    onTap: enabled && mirrors != null
                        ? () async {
                            setState(() => _detecting = true);
                            try {
                              await runDetectFastMirrors(
                                context: context,
                                mirrors: mirrors,
                                categories: categories,
                              );
                            } finally {
                              if (mounted) setState(() => _detecting = false);
                            }
                          }
                        : null,
                  ),
                ],
              ),
              IosSectionFooter(text: l10n.workspaceEnvDependencySourcesDetail),
              if (_failure(
                    l10n,
                    service.lastAttempt == dependency ? service.failure : null,
                  )
                  case final error?)
                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: Text(
                    error,
                    style: TextStyle(color: cs.error, fontSize: 13),
                  ),
                ),
              if (service.busy) ...[
                const EnvironmentInlineSpinner(radius: 10),
                const SizedBox(height: 12),
                IosTileButton(
                  icon: Lucide.X,
                  label: l10n.workspaceEnvCancel,
                  onTap: () => unawaited(service.cancel()),
                ),
              ] else if (service.status(dependency) !=
                  DependencyStatus.installed)
                IosTileButton(
                  key: const ValueKey('environment-dependency-install'),
                  icon: Lucide.Download,
                  label: service.failure == DependencyFailure.install
                      ? l10n.workspaceEnvRetry
                      : l10n.workspaceEnvInstall,
                  enabled: enabled,
                  backgroundColor: cs.primary,
                  onTap: () => unawaited(service.install(dependency)),
                ),
              if (service.log.isNotEmpty &&
                  service.lastAttempt == dependency) ...[
                IosSectionHeader(text: l10n.workspaceEnvDependencyLog),
                _InstallationLog(text: service.log),
              ],
            ],
          ),
        );
      },
    );
  }
}

class _InstallationLog extends StatefulWidget {
  const _InstallationLog({required this.text});

  final String text;

  @override
  State<_InstallationLog> createState() => _InstallationLogState();
}

class _InstallationLogState extends State<_InstallationLog> {
  final _scrollController = ScrollController();
  bool _followTail = true;
  bool _scrollScheduled = false;

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_trackPosition);
    _scrollToTail();
  }

  @override
  void didUpdateWidget(covariant _InstallationLog oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.text != oldWidget.text) _scrollToTail();
  }

  void _trackPosition() {
    _followTail = _scrollController.position.extentAfter <= 24;
  }

  void _scrollToTail() {
    if (!_followTail || _scrollScheduled) return;
    _scrollScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _scrollScheduled = false;
      if (!mounted || !_followTail || !_scrollController.hasClients) return;
      _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return SectionCard(
      child: SizedBox(
        key: const ValueKey('environment-dependency-log'),
        height: 240,
        width: double.infinity,
        child: Scrollbar(
          controller: _scrollController,
          child: SingleChildScrollView(
            controller: _scrollController,
            primary: false,
            padding: const EdgeInsets.all(12),
            child: SelectableText(
              widget.text,
              style: TextStyle(
                fontSize: 12,
                color: cs.onSurface.withValues(alpha: 0.7),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
