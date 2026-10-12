import 'package:flutter/material.dart';
import 'package:Kelivo/theme/app_font_weights.dart';

import 'package:Kelivo/shared/services/haptics.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/ios_switch.dart';
import '../../../shared/widgets/ios_tactile.dart';
import 'package:Kelivo/theme/app_semantic_colors.dart';
import 'package:provider/provider.dart';
import '../../../core/providers/settings_provider.dart';
import 'context_usage_header.dart';

/// Bottom sheet for mobile: compress context or clear context.
class ContextManagementSheet extends StatefulWidget {
  const ContextManagementSheet({
    super.key,
    this.onCompress,
    this.onClear,
    this.messageCountLabel,
    this.conversationId,
    this.draftText = '',
  });

  final VoidCallback? onCompress;
  final VoidCallback? onClear;

  /// Messages currently in context, e.g. "12 messages". Shown on the clear row.
  final String? messageCountLabel;
  final String? conversationId;
  final String draftText;

  @override
  State<ContextManagementSheet> createState() => _ContextManagementSheetState();
}

class _ContextManagementSheetState extends State<ContextManagementSheet> {
  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final settings = context.watch<SettingsProvider>();
    final autoRetry = settings.autoRetryOptions;
    final bg = Theme.of(context).colorScheme.surface;
    final cs = Theme.of(context).colorScheme;

    return Container(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: const BorderRadius.only(
          topLeft: Radius.circular(20),
          topRight: Radius.circular(20),
        ),
        boxShadow: [
          BoxShadow(
            color: cs.shadow.withValues(alpha: 0.06),
            blurRadius: 20,
            offset: const Offset(0, -6),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Drag handle
          Container(
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: cs.onSurface.withValues(alpha: 0.2),
              borderRadius: BorderRadius.circular(999),
            ),
          ),
          const SizedBox(height: 16),
          Flexible(
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  ContextUsageHeader(
                    conversationId: widget.conversationId,
                    draftText: widget.draftText,
                  ),
                  const SizedBox(height: 16),
                  // 压缩只有**一项**（用户 2026-10-02）：点开弹窗里同时有
                  // 「立即压缩」与「自动压缩（开关+阈值）」，不在主列表里并排两条。
                  _OptionRow(
                    icon: Lucide.package2,
                    label: l10n.compressContext,
                    description: settings.autoCompactEnabled
                        ? l10n.contextCompactAutoState(
                            settings.autoCompactThresholdPercent,
                          )
                        : l10n.compressContextDesc,
                    onTap: () {
                      Haptics.light();
                      showContextCompressSheet(
                        context,
                        onCompressNow: widget.onCompress,
                        onChanged: () => setState(() {}),
                      );
                    },
                  ),
                  const SizedBox(height: 8),
                  _OptionRow(
                    icon: Lucide.Eraser,
                    label: l10n.bottomToolsSheetClearContext,
                    description: l10n.clearContextDesc,
                    trailing: widget.messageCountLabel,
                    onTap: () {
                      Haptics.light();
                      widget.onClear?.call();
                    },
                  ),
                  const SizedBox(height: 8),
                  _OptionRow(
                    icon: Lucide.RefreshCw,
                    label: l10n.contextAutoRetryTitle,
                    description: autoRetry.enabled
                        ? l10n.contextAutoRetryEnabledState(autoRetry.maxRetries)
                        : l10n.contextAutoRetryDisabledState,
                    onTap: () => showContextAutoRetrySheet(
                      context,
                      onChanged: () => setState(() {}),
                    ),
                  ),
                  const SizedBox(height: 8),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// 压缩的小面板（合并项，用户 2026-10-02）：
/// 一个入口里同时给「**立即压缩**」与「**自动压缩**（开关 + 阈值）」，
/// 主列表因此只有一行「压缩上下文」，不再并排两条。
Future<void> showContextCompressSheet(
  BuildContext context, {
  VoidCallback? onCompressNow,
  VoidCallback? onChanged,
}) => showModalBottomSheet<void>(
  context: context,
  backgroundColor: Theme.of(context).colorScheme.surface,
  shape: const RoundedRectangleBorder(
    borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
  ),
  builder: (ctx) {
    final l10n = AppLocalizations.of(ctx)!;
    final settings = ctx.watch<SettingsProvider>();
    final cs = Theme.of(ctx).colorScheme;
    return SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 标题行：立即压缩（手动）。
            Row(
              children: [
                Expanded(
                  child: Text(
                    l10n.compressContext,
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: AppFontWeights.semibold,
                      color: cs.onSurface,
                    ),
                  ),
                ),
                IosCardPress(
                  baseColor: cs.primary.withValues(alpha: 0.14),
                  borderRadius: BorderRadius.circular(999),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 14,
                    vertical: 6,
                  ),
                  onTap: () {
                    Haptics.light();
                    Navigator.of(ctx).maybePop();
                    onCompressNow?.call();
                  },
                  child: Text(
                    l10n.compressContext,
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: AppFontWeights.semibold,
                      color: cs.primary,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              l10n.compressContextDesc,
              style: TextStyle(
                fontSize: 12,
                height: 1.35,
                color: cs.onSurface.withValues(alpha: 0.6),
              ),
            ),
            const SizedBox(height: 16),
            Divider(
              height: 1,
              color: cs.outlineVariant.withValues(alpha: 0.3),
            ),
            const SizedBox(height: 14),
            // 自动压缩：开关 + 阈值。
            Row(
              children: [
                Expanded(
                  child: Text(
                    l10n.contextAutoCompactTitle,
                    style: TextStyle(
                      fontSize: 15,
                      fontWeight: AppFontWeights.semibold,
                      color: cs.onSurface,
                    ),
                  ),
                ),
                IosSwitch(
                  value: settings.autoCompactEnabled,
                  onChanged: (v) async {
                    await settings.setAutoCompactEnabled(v);
                    onChanged?.call();
                  },
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              l10n.contextAutoCompactDesc,
              style: TextStyle(
                fontSize: 12,
                height: 1.35,
                color: cs.onSurface.withValues(alpha: 0.6),
              ),
            ),
            const SizedBox(height: 14),
            Text(
              l10n.contextAutoCompactThreshold,
              style: TextStyle(
                fontSize: 13,
                fontWeight: AppFontWeights.medium,
                color: cs.onSurface.withValues(alpha: 0.75),
              ),
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final percent in const <int>[50, 60, 70, 80, 90])
                  _ChoiceChip(
                    label: '$percent%',
                    active: settings.autoCompactThresholdPercent == percent,
                    onTap: () async {
                      await settings.setAutoCompactThresholdPercent(percent);
                      // 点阈值即视为要启用（2026-10-05 用户实测：设了 50% 却不
                      // 触发——开关默认关、点芯片又不打开，等于白设）。
                      if (!settings.autoCompactEnabled) {
                        await settings.setAutoCompactEnabled(true);
                      }
                      onChanged?.call();
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

/// 自动重连的小面板：开关 + 次数。
Future<void> showContextAutoRetrySheet(
  BuildContext context, {
  VoidCallback? onChanged,
}) => showModalBottomSheet<void>(
  context: context,
  backgroundColor: Theme.of(context).colorScheme.surface,
  shape: const RoundedRectangleBorder(
    borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
  ),
  builder: (ctx) {
    final l10n = AppLocalizations.of(ctx)!;
    final settings = ctx.watch<SettingsProvider>();
    final retry = settings.autoRetryOptions;
    final cs = Theme.of(ctx).colorScheme;
    return SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    l10n.contextAutoRetryTitle,
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: AppFontWeights.semibold,
                      color: cs.onSurface,
                    ),
                  ),
                ),
                IosSwitch(
                  value: retry.enabled,
                  onChanged: (v) async {
                    await settings.setAutoRetryEnabled(v);
                    onChanged?.call();
                  },
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              l10n.contextAutoRetryDesc,
              style: TextStyle(
                fontSize: 12,
                height: 1.35,
                color: cs.onSurface.withValues(alpha: 0.6),
              ),
            ),
            const SizedBox(height: 14),
            Text(
              l10n.contextAutoRetryAttempts,
              style: TextStyle(
                fontSize: 13,
                fontWeight: AppFontWeights.medium,
                color: cs.onSurface.withValues(alpha: 0.75),
              ),
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final count in const <int>[1, 2, 3, 4, 5])
                  _ChoiceChip(
                    label: l10n.contextAutoRetryTimes(count),
                    active: retry.maxRetries == count,
                    onTap: () async {
                      await settings.setAutoRetryMaxRetries(count);
                      onChanged?.call();
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

class _ChoiceChip extends StatelessWidget {
  const _ChoiceChip({
    required this.label,
    required this.active,
    required this.onTap,
  });

  final String label;
  final bool active;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return IosCardPress(
      baseColor: active
          ? cs.primary.withValues(alpha: 0.16)
          : cs.onSurface.withValues(alpha: 0.05),
      borderRadius: BorderRadius.circular(999),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
      onTap: onTap,
      child: Text(
        label,
        style: TextStyle(
          fontSize: 13,
          fontWeight: active ? AppFontWeights.semibold : AppFontWeights.medium,
          color: active ? cs.primary : cs.onSurface.withValues(alpha: 0.8),
        ),
      ),
    );
  }
}

class _OptionRow extends StatelessWidget {
  const _OptionRow({
    required this.icon,
    required this.label,
    required this.description,
    this.onTap,
    this.trailing,
  });

  final IconData icon;
  final String label;
  final String description;
  final VoidCallback? onTap;
  final String? trailing;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final cardColor = context.appColors.surfaceFill;
    final radius = BorderRadius.circular(14);

    return IosCardPress(
      baseColor: cardColor,
      borderRadius: radius,
      pressedScale: 0.98,
      duration: const Duration(milliseconds: 260),
      onTap: onTap,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      child: Row(
        children: [
          Icon(icon, size: 22, color: cs.onSurface),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: AppFontWeights.semibold,
                    color: cs.onSurface,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  description,
                  style: TextStyle(
                    fontSize: 13,
                    color: cs.onSurface.withValues(alpha: 0.55),
                  ),
                ),
              ],
            ),
          ),
          if (trailing != null) ...[
            const SizedBox(width: 12),
            Text(
              trailing!,
              style: TextStyle(
                fontSize: 13,
                fontWeight: AppFontWeights.medium,
                color: cs.onSurface.withValues(alpha: 0.55),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
