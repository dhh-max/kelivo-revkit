/// 对话页输入框上方的**子代理活动条**（2026-10-03 重构）。
///
/// 原「运行时状态条 + 运行时弹层」（进度/证据/预览/交付/诊断单页一览）已按
/// 用户要求**整体删除**（2026-10-03 点名：不要隐藏，直接删）——五分区的完整
/// 明细仍在「设置 → APK 工作台」里，聊天页不再有运行时入口。
///
/// 本条现在只服务子代理/专家团（该能力必须保留）：
/// - 谁在跑谁亮（成员灯），点单个灯看它的对话历史；
/// - 点整条看子代理队列；
/// - 会话隔离：别的会话的子代理不亮在本会话（2026-10-01 用户点名）。
///
/// 类名保留 `RuntimeStatusStrip`：home_page 与子代理条测试按这个名字挂载。
library;

import 'package:flutter/material.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';
import 'package:provider/provider.dart';

import '../../../core/providers/settings_provider.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/solab_glass_card.dart';
import '../../../theme/app_font_weights.dart';
import '../../../theme/design_tokens.dart';
import '../../chat/widgets/frosted/chat_frosted_backdrop.dart';
import '../../home/services/subagent_run_monitor.dart';
import 'subagent_sheets.dart';

/// 对话页输入框上方的子代理活动条。没有子代理活动时完全不出现。
class RuntimeStatusStrip extends StatefulWidget {
  const RuntimeStatusStrip({super.key, this.scopeKey});

  /// 当前会话 id（作用域键）。
  final String? scopeKey;

  @override
  State<RuntimeStatusStrip> createState() => _RuntimeStatusStripState();
}

class _RuntimeStatusStripState extends State<RuntimeStatusStrip> {
  @override
  Widget build(BuildContext context) {
    // 会话里绑定了 APK 任务也**不再**显示任务状态条（运行时弹层已删）；
    // 只在有子代理活动（在跑或刚跑完）时出现。
    return ListenableBuilder(
      listenable: SubAgentRunMonitor.instance,
      builder: (context, _) {
        final monitor = SubAgentRunMonitor.instance;
        if (!monitor.hasActivityFor(widget.scopeKey)) {
          return const SizedBox.shrink();
        }
        return _buildSubAgentStrip(context, monitor);
      },
    );
  }

  /// 子代理条：转圈/Bot + 文案 + 成员灯 + 队列入口。
  Widget _buildSubAgentStrip(
    BuildContext context,
    SubAgentRunMonitor monitor,
  ) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    final runs = monitor.activeFor(widget.scopeKey);
    final running = runs.isNotEmpty;
    // 可空 watch：独立挂载（测试）时可能没有 SettingsProvider。
    final settings = context.watch<SettingsProvider?>();
    // 进度并入本条：显示最近一个在跑实例的 stage（step N/M / 等待模型）。
    final stage = running ? runs.last.stage : '';
    return Padding(
      padding: const EdgeInsets.fromLTRB(
        AppSpacing.sm,
        AppSpacing.xs,
        AppSpacing.sm,
        AppSpacing.xs,
      ),
      child: SolabGlassCard(
        borderRadius: 12,
        padding: EdgeInsets.zero,
        // 与聊天输入框**同款材质、同透明度**（用户 2026-10-04）。
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
        child: InkWell(
          onTap: () => showSubAgentQueueSheet(
            context,
            conversationId: widget.scopeKey,
          ),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
            child: Row(children: [
              if (running)
                SizedBox(
                  width: 14,
                  height: 14,
                  child: CircularProgressIndicator(
                    strokeWidth: 1.6,
                    color: cs.primary,
                  ),
                )
              else
                Icon(LucideIcons.bot, size: 14, color: cs.primary),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  stage.isEmpty
                      ? l10n.subagentCardTitle
                      : '${l10n.subagentCardTitle} · $stage',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: AppFontWeights.medium,
                    color: cs.onSurface,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              _SubAgentLamps(
                conversationId: widget.scopeKey,
                onOpenQueue: () => showSubAgentQueueSheet(
                  context,
                  conversationId: widget.scopeKey,
                ),
              ),
              const SizedBox(width: 8),
              Icon(LucideIcons.chevronUp,
                  size: 15, color: cs.onSurface.withValues(alpha: 0.5)),
            ]),
          ),
        ),
      ),
    );
  }
}

class _SubAgentLamps extends StatelessWidget {
  const _SubAgentLamps({required this.onOpenQueue, this.conversationId});

  final VoidCallback onOpenQueue;

  /// 当前会话：只亮本会话的子代理（会话隔离，2026-10-01 用户点名）。
  final String? conversationId;

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: SubAgentRunMonitor.instance,
      builder: (context, _) {
        final runs = SubAgentRunMonitor.instance.activeFor(conversationId);
        if (runs.isEmpty) return const SizedBox.shrink();
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            for (final run in runs.take(5))
              _SubAgentLamp(run: run, onOpenQueue: onOpenQueue),
          ],
        );
      },
    );
  }
}

class _SubAgentLamp extends StatelessWidget {
  const _SubAgentLamp({required this.run, required this.onOpenQueue});

  final SubAgentRun run;
  final VoidCallback onOpenQueue;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final cancelling = run.cancelRequested;
    final name = run.label.isEmpty ? run.agent : '${run.agent} · ${run.label}';
    return Padding(
      padding: const EdgeInsets.only(left: 4),
      child: Tooltip(
        message: name,
        child: InkWell(
          onTap: () => showSubAgentHistorySheet(context, run),
          borderRadius: BorderRadius.circular(999),
          child: Container(
            width: 20,
            height: 20,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: cancelling
                  ? cs.onSurface.withValues(alpha: 0.12)
                  : cs.primary.withValues(alpha: 0.9),
              boxShadow: cancelling
                  ? null
                  : [
                      BoxShadow(
                        color: cs.primary.withValues(alpha: 0.35),
                        blurRadius: 6,
                        spreadRadius: 1,
                      ),
                    ],
            ),
            child: Icon(
              Lucide.Bot,
              size: 12,
              color: cancelling ? cs.onSurfaceVariant : cs.onPrimary,
            ),
          ),
        ),
      ),
    );
  }
}
