import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/providers/settings_provider.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/ios_tactile.dart';
import '../../../shared/widgets/solab_glass_card.dart';
import '../../../theme/app_font_weights.dart';
import '../../home/services/todo_store.dart';
import 'frosted/chat_frosted_backdrop.dart';

/// 会话任务清单面板（对齐 deepseek-harness `skeleton/TodoPanel.tsx` 的行为）：
/// - 清单为空 → **完全不渲染**（不占位置）；
/// - 默认**折叠**，只显示「图标 + 标题 + 分状态计数」，点标题展开；
/// - 展开后逐条显示状态点 + 文本（已完成 / 进行中 / 未开始）；
/// - 位置：**输入框上方**。
///
/// 材质走 [SolabGlassCard]——与「上下文窗口」小卡片**同一套**（用户 2026-10-03：
/// 两块浮层必须同款 UI、同透明度）。
///
/// 数据来自 [TodoStore]（`todo_write` 的落点），并通过 [TodoStore.revision]
/// 在写入后立刻刷新——否则用户会看到「建了待办但界面没反应」。
class SolabTodoPanel extends StatefulWidget {
  const SolabTodoPanel({super.key, required this.conversationId});

  final String? conversationId;

  @override
  State<SolabTodoPanel> createState() => _SolabTodoPanelState();
}

class _SolabTodoPanelState extends State<SolabTodoPanel> {
  final TodoStore _store = TodoStore();
  bool _collapsed = true;

  @override
  Widget build(BuildContext context) {
    final id = widget.conversationId?.trim() ?? '';
    if (id.isEmpty) return const SizedBox.shrink();

    return ValueListenableBuilder<int>(
      valueListenable: TodoStore.revision,
      builder: (context, revision, _) => FutureBuilder<List<TodoItem>>(
        key: ValueKey<String>('solab-todo-$id-$revision'),
        future: _store.read(id),
        builder: (context, snapshot) {
          final todos = snapshot.data ?? const <TodoItem>[];
          if (todos.isEmpty) return const SizedBox.shrink();
          // 可空 watch：面板在测试/独立挂载时可能没有 SettingsProvider，缺了就用
          // 默认透明度（不能因此抛 ProviderNotFoundException）。
          final settings = context.watch<SettingsProvider?>();
          return Padding(
            // 面板在输入框上方：上留 2、下留 6（与输入卡片分开一点）。
            padding: const EdgeInsets.fromLTRB(12, 2, 12, 6),
            child: SolabGlassCard(
              borderRadius: 12,
              padding: EdgeInsets.zero,
              // 与聊天输入框**同款材质、同透明度**（用户 2026-10-04：输入框上方的
              // 任务清单/子代理条此前比输入卡片更实，一眼能看出两块不一样）。
              tint: SolabGlassCard.composerFill(
                theme: Theme.of(context),
                lightOpacity:
                    settings?.chatInputBackgroundOpacityLight ??
                    SettingsProvider.defaultChatInputBackgroundOpacityLight,
                darkOpacity:
                    settings?.chatInputBackgroundOpacityDark ??
                    SettingsProvider.defaultChatInputBackgroundOpacityDark,
                backgroundImageActive: ChatBackdropSpec.resolve(context).active,
              ),
              child: _TodoPanelBody(
                todos: todos,
                collapsed: _collapsed,
                onToggle: () => setState(() => _collapsed = !_collapsed),
              ),
            ),
          );
        },
      ),
    );
  }
}

class _TodoPanelBody extends StatelessWidget {
  const _TodoPanelBody({
    required this.todos,
    required this.collapsed,
    required this.onToggle,
  });

  final List<TodoItem> todos;
  final bool collapsed;
  final VoidCallback onToggle;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final done = todos.where((t) => t.status == TodoStatus.done).length;
    final active = todos.where((t) => t.status == TodoStatus.inProgress).length;
    final pending = todos.length - done - active;
    // 与参考项目一致：零计数的段省略，互不噪音。
    final progress = <String>[
      if (done > 0) l10n.todoPanelProgressDone(done),
      if (active > 0) l10n.todoPanelProgressActive(active),
      if (pending > 0) l10n.todoPanelProgressPending(pending),
    ].join(' · ');

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        IosCardPress(
          baseColor: Colors.transparent,
          pressedScale: 1,
          borderRadius: BorderRadius.circular(12),
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
          onTap: onToggle,
          child: Row(
            children: [
              Icon(Lucide.ListChecks, size: 14, color: cs.primary),
              const SizedBox(width: 7),
              Text(
                l10n.todoPanelTitle,
                style: TextStyle(
                  fontSize: 12.5,
                  fontWeight: AppFontWeights.semibold,
                  color: cs.onSurface,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  progress,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 11.5,
                    color: cs.onSurface.withValues(alpha: 0.6),
                  ),
                ),
              ),
              Icon(
                collapsed ? Lucide.ChevronUp : Lucide.ChevronDown,
                size: 14,
                color: cs.onSurface.withValues(alpha: 0.5),
              ),
            ],
          ),
        ),
        if (!collapsed)
          ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 168),
            child: SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(10, 0, 10, 8),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  for (final item in todos)
                    Padding(
                      padding: const EdgeInsets.only(top: 5),
                      child: SolabTodoRow(text: item.text, status: item.status),
                    ),
                ],
              ),
            ),
          ),
      ],
    );
  }
}

/// 单条待办的渲染。
///
/// **面板与聊天步骤内的清单块共用同一个部件**：真机实测（用户 2026-10-04）
/// 两处材质/配色不一致——同一份数据在两处长得不一样。
class SolabTodoRow extends StatelessWidget {
  const SolabTodoRow({super.key, required this.text, required this.status});

  final String text;
  final TodoStatus status;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(top: 4),
          child: Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: solabTodoStatusColor(cs, status),
            ),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: Text(
            text,
            style: TextStyle(
              fontSize: 12,
              height: 1.25,
              color: status == TodoStatus.done
                  ? cs.onSurface.withValues(alpha: 0.5)
                  : cs.onSurface,
              decoration: status == TodoStatus.done
                  ? TextDecoration.lineThrough
                  : null,
              decorationColor: cs.onSurface.withValues(alpha: 0.4),
            ),
          ),
        ),
      ],
    );
  }
}

Color solabTodoStatusColor(ColorScheme cs, TodoStatus status) =>
    switch (status) {
      TodoStatus.done => cs.primary,
      TodoStatus.inProgress => const Color(0xFFF57C00),
      TodoStatus.pending => cs.outline,
    };
