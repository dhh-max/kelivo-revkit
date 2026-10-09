import 'package:solab/features/workspace/pages/workspaces_page.dart';
import 'package:solab/icons/lucide_adapter.dart';
import 'package:solab/l10n/app_localizations.dart';
import 'package:solab/shared/widgets/ios_tactile.dart';
import 'package:flutter/material.dart';

class WorkspacesDesktopLayout extends StatelessWidget {
  const WorkspacesDesktopLayout({super.key});

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
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
        title: Text(l10n.workspacesTitle),
      ),
      body: const WorkspacesPane(showHeader: false),
    );
  }
}
