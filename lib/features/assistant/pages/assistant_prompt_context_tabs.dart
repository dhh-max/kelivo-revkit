import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:Kelivo/core/providers/instruction_injection_provider.dart';
import 'package:Kelivo/core/providers/world_book_provider.dart';
import 'package:Kelivo/features/home/widgets/instruction_injection_sheet.dart';
import 'package:Kelivo/features/home/widgets/world_book_sheet.dart';
import 'package:Kelivo/icons/lucide_adapter.dart';
import 'package:Kelivo/l10n/app_localizations.dart';
import 'package:Kelivo/shared/widgets/ios_checkbox.dart';
import 'package:Kelivo/shared/widgets/ios_tactile.dart';
import 'package:Kelivo/shared/widgets/ios_tile_button.dart';
import 'package:Kelivo/shared/widgets/section_card.dart';
import 'package:Kelivo/theme/app_font_weights.dart';

/// 第 70 项：助手编辑页的「世界书」配置 tab。
///
/// 世界书的激活集合早已按 assistantId 分桶（`WorldBookStore` 的
/// `world_books_active_ids_by_assistant_v1`，无自有键时回落到 `__global__`），
/// 但此前只有聊天页底部弹层能改，助手设置里看不到自己的世界书配置。
/// 这个 tab 用 [assistantId] 直接读写该助手的分桶，绝不读当前助手。
class AssistantSettingsEditWorldBookTab extends StatelessWidget {
  const AssistantSettingsEditWorldBookTab({
    super.key,
    required this.assistantId,
  });

  final String assistantId;

  static const Key openManagerKey = Key('assistant-world-book-manager');

  static Key bookKey(String id) => Key('assistant-world-book-$id');

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final books = context.watch<WorldBookProvider>().books;
    final provider = context.read<WorldBookProvider>();
    final activeIds = provider.activeBookIdsFor(assistantId).toSet();

    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 20),
      children: [
        _AssistantScopeHint(text: l10n.assistantEditAssistantScopeHint),
        const SizedBox(height: 12),
        if (books.isEmpty)
          _AssistantTabEmptyHint(text: l10n.worldBookEmptyMessage)
        else
          SectionCard(
            dividers: true,
            children: [
              for (final book in books)
                _AssistantScopedRow(
                  rowKey: bookKey(book.id),
                  title: book.name.trim().isEmpty
                      ? l10n.worldBookUnnamed
                      : book.name,
                  subtitle: book.description,
                  selected: activeIds.contains(book.id),
                  enabled: book.enabled,
                  disabledHint: l10n.worldBookDisabledTag,
                  onChanged: book.enabled
                      ? (_) => unawaited(
                          provider.toggleActiveBookId(
                            book.id,
                            assistantId: assistantId,
                          ),
                        )
                      : null,
                ),
            ],
          ),
        const SizedBox(height: 16),
        IosTileButton(
          key: openManagerKey,
          icon: Lucide.BookOpen,
          label: l10n.assistantEditManage,
          onTap: () =>
              unawaited(showWorldBookSheet(context, assistantId: assistantId)),
        ),
      ],
    );
  }
}

/// 第 70 项：助手编辑页的「指令注入」配置 tab。
///
/// 与世界书同形：`instruction_injections_active_ids_by_assistant_v1` 按
/// assistantId 分桶，无自有键时回落 `__global__`。
class AssistantSettingsEditInstructionTab extends StatelessWidget {
  const AssistantSettingsEditInstructionTab({
    super.key,
    required this.assistantId,
  });

  final String assistantId;

  static const Key openManagerKey = Key('assistant-instruction-manager');

  static Key instructionKey(String id) => Key('assistant-instruction-$id');

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final items = context.watch<InstructionInjectionProvider>().items;
    final provider = context.read<InstructionInjectionProvider>();
    final activeIds = provider.activeIdsFor(assistantId).toSet();

    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 20),
      children: [
        _AssistantScopeHint(text: l10n.assistantEditAssistantScopeHint),
        const SizedBox(height: 12),
        if (items.isEmpty)
          _AssistantTabEmptyHint(text: l10n.instructionInjectionEmptyMessage)
        else
          SectionCard(
            dividers: true,
            children: [
              for (final item in items)
                _AssistantScopedRow(
                  rowKey: instructionKey(item.id),
                  title: item.title.trim().isEmpty
                      ? (item.group.trim().isEmpty
                            ? l10n.instructionInjectionTitle
                            : item.group.trim())
                      : item.title,
                  subtitle: item.prompt,
                  selected: activeIds.contains(item.id),
                  enabled: true,
                  disabledHint: '',
                  onChanged: (_) => unawaited(
                    provider.toggleActiveId(item.id, assistantId: assistantId),
                  ),
                ),
            ],
          ),
        const SizedBox(height: 16),
        IosTileButton(
          key: openManagerKey,
          icon: Lucide.MessageSquare,
          label: l10n.assistantEditManage,
          onTap: () => unawaited(
            showInstructionInjectionSheet(context, assistantId: assistantId),
          ),
        ),
      ],
    );
  }
}

class _AssistantScopeHint extends StatelessWidget {
  const _AssistantScopeHint({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 4),
      child: Text(
        text,
        style: TextStyle(
          fontSize: 12,
          height: 1.3,
          color: cs.onSurface.withValues(alpha: 0.62),
        ),
      ),
    );
  }
}

class _AssistantTabEmptyHint extends StatelessWidget {
  const _AssistantTabEmptyHint({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
      child: Text(
        text,
        style: TextStyle(color: cs.onSurface.withValues(alpha: 0.6)),
      ),
    );
  }
}

class _AssistantScopedRow extends StatelessWidget {
  const _AssistantScopedRow({
    required this.rowKey,
    required this.title,
    required this.subtitle,
    required this.selected,
    required this.enabled,
    required this.disabledHint,
    required this.onChanged,
  });

  final Key rowKey;
  final String title;
  final String subtitle;
  final bool selected;
  final bool enabled;
  final String disabledHint;
  final ValueChanged<bool>? onChanged;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final dim = !enabled;
    return IosCardPress(
      key: rowKey,
      onTap: onChanged == null ? null : () => onChanged!(!selected),
      padding: const EdgeInsets.fromLTRB(12, 11, 12, 11),
      child: Row(
        children: [
          IosCheckbox(
            value: enabled && selected,
            onChanged: onChanged,
            semanticLabel: title,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: AppFontWeights.medium,
                    color: dim
                        ? cs.onSurface.withValues(alpha: 0.42)
                        : cs.onSurface,
                  ),
                ),
                if (subtitle.trim().isNotEmpty) ...[
                  const SizedBox(height: 3),
                  Text(
                    subtitle.trim(),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 12,
                      height: 1.25,
                      color: cs.onSurface.withValues(alpha: dim ? 0.38 : 0.62),
                    ),
                  ),
                ],
                if (dim && disabledHint.trim().isNotEmpty) ...[
                  const SizedBox(height: 3),
                  Text(
                    disabledHint,
                    style: TextStyle(
                      fontSize: 12,
                      color: cs.onSurface.withValues(alpha: 0.45),
                    ),
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
