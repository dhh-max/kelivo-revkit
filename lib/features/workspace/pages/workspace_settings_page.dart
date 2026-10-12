import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:Kelivo/core/models/environment_state.dart';
import 'package:Kelivo/core/providers/environment_provider.dart';
import 'package:Kelivo/core/services/workspace/workspace_runtime.dart';
import 'package:Kelivo/features/solab_apk/pages/solab_apk_page.dart';
import 'package:Kelivo/features/workspace/pages/workspaces_page.dart';
import 'package:Kelivo/features/workspace/widgets/environment/environment_labels.dart';
import 'package:Kelivo/features/workspace/workspace_layout.dart';
import 'package:Kelivo/features/workspace/workspace_navigation.dart';
import 'package:Kelivo/icons/lucide_adapter.dart';
import 'package:Kelivo/l10n/app_localizations.dart';
import 'package:Kelivo/shared/widgets/ios_settings_rows.dart';
import 'package:Kelivo/shared/widgets/ios_tactile.dart';
import 'package:Kelivo/shared/widgets/section_card.dart';
import 'package:Kelivo/theme/app_font_weights.dart';

/// 工作台：**一个入口**（用户 2026-10-04：把「APK 工作台」和「工作区」两个一级入口
/// 合并成一个）。
///
/// 页面结构保持**紧凑**——上半部分环境只占**一行**（点进去才是完整环境页：安装、
/// 浏览文件系统、外部挂载、镜像、依赖），下半部分就是工作区列表。用户原话：
/// 「我上半部分环境，下半部分工作区刚刚好呀……你把环境和工作区都搞定了，我每次找
/// 工作区，我还得划那么长的一堆环境的东西」。
class WorkspaceSettingsPage extends StatefulWidget {
  const WorkspaceSettingsPage({super.key});

  @override
  State<WorkspaceSettingsPage> createState() => _WorkspaceSettingsPageState();
}

class _WorkspaceSettingsPageState extends State<WorkspaceSettingsPage> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      final runtime = context.read<WorkspaceRuntimeProvider>();
      if (runtime.runtime == null) return;
      if (runtime.lastStatus == null) {
        unawaited(runtime.refresh());
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    if (useDesktopWorkspaceLayout(context)) {
      return const WorkspacesPage();
    }
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final showEnv = !_envIsDesktopTarget();
    return Scaffold(
      backgroundColor: cs.surface,
      appBar: AppBar(
        leading: IosIconButton(
          icon: Lucide.ArrowLeft,
          color: cs.onSurface,
          size: 22,
          minSize: 44,
          tooltip: l10n.settingsPageBackButton,
          semanticLabel: l10n.settingsPageBackButton,
          onTap: () => Navigator.of(context).maybePop(),
        ),
        title: Text(l10n.settingsPageWorkspace),
        actions: workspaceMgmtCreateActions(context),
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
        children: [
          // 用户 2026-10-06：APK 设置排到**最上面**（原顺序是环境→工作区→APK，
          // 找它要划到最后）。
          IosSectionHeader(text: 'APK 设置', first: true),
          SectionCard(
            children: [
              IosNavRow(
                icon: Lucide.package2,
                label: 'APK 工作台设置',
                subtitle: '默认去签名 · FieldRefs · 规则库 · 记忆整理',
                onTap: () {
                  Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) => const SolabApkPage(),
                    ),
                  );
                },
              ),
            ],
          ),
          const SizedBox(height: 12),
          // 中：环境（**一行**，点进去是完整环境页）——不要把环境面板摊开，
          // 否则工作区被挤到很下面，用户每次找它都要划很久。
          if (showEnv) ...[
            IosSectionHeader(text: l10n.workspaceEnvTitle),
            const _EnvironmentNavRow(),
            const SizedBox(height: 12),
          ],
          // 下：工作区（默认工作区常驻、不可删；新建/导入都在这）。
          IosSectionHeader(text: l10n.workspacesTitle, first: !showEnv),
          const WorkspacesPane(showHeader: false),
          const SizedBox(height: 12),
        ],
      ),
    );
  }
}

/// 环境入口行：引擎/版本 + 阶段，点进去才是完整环境页。
class _EnvironmentNavRow extends StatelessWidget {
  const _EnvironmentNavRow();

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final env = context.watch<EnvironmentProvider>();
    final runtime = context.watch<WorkspaceRuntimeProvider>();
    final status = runtime.lastStatus;
    final phase = status?.ready == true
        ? EnvironmentPhase.ready
        : env.state.phase;
    final label = workspaceEnvEngineLabel(
      l10n: l10n,
      state: env.state,
      status: status,
    );
    return SectionCard(
      children: [
        IosNavRow(
          icon: workspaceEnvEngineIcon(state: env.state, status: status),
          label: label,
          subtitle: _phaseLabel(l10n, phase),
          labelWeight: AppFontWeights.medium,
          onTap: () => WorkspaceNavigation.openEnvironmentPage(context),
        ),
      ],
    );
  }
}

bool _envIsDesktopTarget() {
  return defaultTargetPlatform == TargetPlatform.macOS ||
      defaultTargetPlatform == TargetPlatform.windows ||
      defaultTargetPlatform == TargetPlatform.linux;
}

String _phaseLabel(AppLocalizations l10n, EnvironmentPhase phase) {
  switch (phase) {
    case EnvironmentPhase.notInstalled:
      return l10n.workspaceEnvPhaseNotInstalled;
    case EnvironmentPhase.downloading:
      return l10n.workspaceEnvPhaseDownloading;
    case EnvironmentPhase.verifying:
      return l10n.workspaceEnvPhaseVerifying;
    case EnvironmentPhase.extracting:
      return l10n.workspaceEnvPhaseExtracting;
    case EnvironmentPhase.patching:
      return l10n.workspaceEnvPhasePatching;
    case EnvironmentPhase.ready:
      return l10n.workspaceEnvPhaseReady;
    case EnvironmentPhase.error:
      return l10n.workspaceEnvPhaseError;
    case EnvironmentPhase.needsRestart:
      return l10n.workspaceEnvPhaseNeedsRestart;
  }
}
