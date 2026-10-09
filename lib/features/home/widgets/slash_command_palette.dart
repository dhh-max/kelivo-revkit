import 'dart:ui' as ui;

import 'package:flutter/material.dart';

import '../../../icons/lucide_adapter.dart';
import '../../../theme/design_tokens.dart';
import '../services/slash_commands.dart';

/// 输入框上方的斜杠命令浮层（形态对齐主流 agent CLI，用户 2026-09-28 指定）：
/// 卡片式、命令名与说明同一行、首行高亮、底部一行搜索提示；可搜命令/技能/子代理。
/// 材质与输入框同款：同样的毛玻璃（BackdropFilter）与描边。
class SlashCommandPalette extends StatefulWidget {
  const SlashCommandPalette({
    super.key,
    required this.entries,
    required this.onSelect,
    required this.fillColor,
    required this.borderColor,
    this.selectedIndex = 0,
  });

  final List<SlashPaletteEntry> entries;
  final ValueChanged<SlashPaletteEntry> onSelect;

  /// 与输入框同款的填充色与描边色（由输入框自己的构建流程算好后传入）。
  final Color fillColor;
  final Color borderColor;

  /// 键盘/触摸高亮的行（默认第一行，与参考形态一致）。
  final int selectedIndex;

  @override
  State<SlashCommandPalette> createState() => _SlashCommandPaletteState();
}

class _SlashCommandPaletteState extends State<SlashCommandPalette> {
  // 必须显式从 0 开始：放在输入列里时列表曾被定位到底部（首屏是列表尾段），
  // 参考形态要求一打开就从第一行（高亮行）开始。
  final ScrollController _scroll = ScrollController(initialScrollOffset: 0);

  @override
  void initState() {
    super.initState();
    // 搜索词变化导致条目重排时，回到顶部让高亮行可见。
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients && _scroll.offset != 0) {
        _scroll.jumpTo(0);
      }
    });
  }

  @override
  void didUpdateWidget(covariant SlashCommandPalette oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.entries != widget.entries && _scroll.hasClients) {
      _scroll.jumpTo(0);
    }
  }

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (widget.entries.isEmpty) return const SizedBox.shrink();
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final entries = widget.entries;
    final highlight = widget.selectedIndex.clamp(0, entries.length - 1);

    return Container(
      margin: const EdgeInsets.only(bottom: AppSpacing.xs),
      // 与输入框同款材质：ClipRRect + BackdropFilter（同样的 blur 14）。
      child: ClipRRect(
        borderRadius: BorderRadius.circular(16),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 14, sigmaY: 14),
          child: Container(
            decoration: BoxDecoration(
              color: widget.fillColor,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: widget.borderColor, width: 1),
            ),
            child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            // 左内边距 = 列表 padding(6) + 行内 padding(10)，让标题/说明与行内容左对齐。
            padding: const EdgeInsets.fromLTRB(16, AppSpacing.sm, AppSpacing.sm, 2),
            child: Row(
              children: [
                Icon(Lucide.Sparkles, size: 15, color: colors.onSurfaceVariant),
                const SizedBox(width: 8),
                Text(
                  '命令',
                  style: theme.textTheme.labelMedium?.copyWith(
                    color: colors.onSurfaceVariant,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
          ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 236),
            child: ListView.builder(
              controller: _scroll,
              shrinkWrap: true,
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              itemCount: entries.length,
              itemBuilder: (context, index) {
                final entry = entries[index];
                final selected = index == highlight;
                return InkWell(
                  borderRadius: BorderRadius.circular(10),
                  onTap: () => widget.onSelect(entry),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
                    decoration: BoxDecoration(
                      color: selected ? colors.surfaceContainerHighest : null,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Row(
                      children: [
                        Icon(_iconFor(entry.kind), size: 15, color: colors.primary),
                        const SizedBox(width: 8),
                        // 参考形态是「命令名 + 空格 + 说明」的流式排版：
                        // 不设固定列宽，说明紧跟在命令名后面（不同命令名的起点一致、
                        // 说明起点随名字长短自然错开），避免固定列宽带来的空档与错位。
                        Text(
                          entry.displayName,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodyMedium?.copyWith(
                            fontWeight: FontWeight.w600,
                            fontFamily: 'monospace',
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            entry.description,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: colors.onSurfaceVariant,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, AppSpacing.sm, AppSpacing.sm),
            child: Row(
              children: [
                Icon(Lucide.BadgeInfo, size: 15, color: colors.onSurfaceVariant),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '输入内容以搜索命令、技能或子智能体',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: colors.onSurfaceVariant,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
            ),
          ),
        ),
      );
  }

  static IconData _iconFor(SlashPaletteKind kind) => switch (kind) {
        SlashPaletteKind.command => Lucide.Zap,
        SlashPaletteKind.skill => Lucide.Sparkles,
        SlashPaletteKind.subagent => Lucide.Bot,
      };
}
