import 'package:flutter/material.dart';

import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';

/// 已删除的内置厂家恢复面板（第 57 项）。
///
/// 内置厂家被删除后只留墓碑：目录把它隐去，且此前没有任何入口清掉墓碑，
/// 于是"删了就是永久删了"。这个面板把
/// [SettingsProvider.restoreBuiltInProvider] 暴露出来，补上那条缺失的回路。
Future<String?> showRestoreDeletedProvidersSheet(
  BuildContext context, {
  required List<({String key, String name})> items,
}) {
  final cs = Theme.of(context).colorScheme;
  return showModalBottomSheet<String?>(
    context: context,
    backgroundColor: cs.surface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
    ),
    builder: (ctx) => _RestoreDeletedProvidersSheet(items: items),
  );
}

class _RestoreDeletedProvidersSheet extends StatelessWidget {
  const _RestoreDeletedProvidersSheet({required this.items});

  final List<({String key, String name})> items;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 16, 20, 4),
            child: Text(
              l10n.providersPageRestoreDeletedTitle,
              style: TextStyle(
                fontSize: 17,
                fontWeight: FontWeight.w600,
                color: cs.onSurface,
              ),
            ),
          ),
          for (final item in items)
            ListTile(
              key: ValueKey<String>('restore-provider-${item.key}'),
              leading: Icon(Lucide.RotateCcw, size: 20, color: cs.primary),
              title: Text(item.name),
              subtitle: Text(item.key),
              trailing: TextButton(
                onPressed: () => Navigator.of(context).pop(item.key),
                child: Text(l10n.providersPageRestoreDeletedButton),
              ),
            ),
          const SizedBox(height: 8),
        ],
      ),
    );
  }
}
