import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/providers/settings_provider.dart';
import '../../../l10n/app_localizations.dart';

/// 安卓后台聊天模式的选择面板（SoLab 自研，上游没有这个入口）。
///
/// 从旧的 `display_settings_page` 搬到独立文件，供设置页复用；只依赖
/// material + l10n + 我方 SettingsProvider 扩展，不牵桌面组件。
Future<void> showAndroidBackgroundChatSheet(BuildContext context) async {
  final l10n = AppLocalizations.of(context)!;
  final settings = context.read<SettingsProvider>();
  final options = <(AndroidBackgroundChatMode, String, IconData)>[
    (
      AndroidBackgroundChatMode.onNotify,
      l10n.androidBackgroundOptionOnNotify,
      Icons.notifications_active_outlined,
    ),
    (
      AndroidBackgroundChatMode.on,
      l10n.androidBackgroundOptionOn,
      Icons.play_circle_outline,
    ),
    (
      AndroidBackgroundChatMode.off,
      l10n.androidBackgroundOptionOff,
      Icons.power_settings_new,
    ),
  ];

  final picked = await showModalBottomSheet<AndroidBackgroundChatMode>(
    context: context,
    showDragHandle: true,
    builder: (sheetContext) {
      final cs = Theme.of(sheetContext).colorScheme;
      return SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 4, 20, 12),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  l10n.displaySettingsPageAndroidBackgroundChatTitle,
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                    color: cs.onSurface,
                  ),
                ),
              ),
            ),
            for (final (mode, label, icon) in options)
              ListTile(
                leading: Icon(icon, size: 20, color: cs.onSurface),
                title: Text(label, style: const TextStyle(fontSize: 14.5)),
                trailing: settings.androidBackgroundChatMode == mode
                    ? Icon(Icons.check, size: 18, color: cs.primary)
                    : null,
                onTap: () => Navigator.of(sheetContext).pop(mode),
              ),
            const SizedBox(height: 8),
          ],
        ),
      );
    },
  );

  if (picked == null) return;
  await settings.setAndroidBackgroundChatMode(picked);
}
