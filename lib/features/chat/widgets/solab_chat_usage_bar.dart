import 'dart:async';
import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/models/chat_message.dart';
import '../../../core/utils/token_format.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/context_usage_details.dart';
import '../../../shared/widgets/context_usage_ring.dart';
import '../../../theme/app_font_weights.dart';
import '../../home/services/context_usage_service.dart';

/// 对话页输入卡片正下方的统计 dock（贴紧输入框，上下各 2dp）。
///
/// 用户 2026-10-02 定稿：
/// - 环形占用 + 百分比 + 累计 token/缓存命中**连成一组居中**；
/// - **不另画进度条**——环本身就是占用指示；
/// - **没有对话历史时整条不显示**（不占位置）；
/// - 点它弹出**只含上下文图谱**的小卡片，位置在**环的正上方**（不是整屏弹层），
///   再点一次环或点空白处关闭；
/// - 卡片材质用**我们自己的**：与桌面玻璃 popover 同一套
///   （`AppOverlayColors.desktopPopoverSurface` + blur 20 + 发丝边）。
class SolabChatUsageBar extends StatefulWidget {
  const SolabChatUsageBar({
    super.key,
    required this.messages,
    this.snapshot,
    this.conversationId,
    // 真机像素校准（1440x3168 截图实测两轮）：输入卡片底 → dock 文字、dock 文字 →
    // 屏底。上 0 / 下 6dp 时两侧各约 28-30px（输入卡片自身的 2dp 底部留白算作上间距）。
    this.padding = const EdgeInsets.only(left: 16, right: 16, bottom: 6),
  });

  final List<ChatMessage> messages;
  final ContextUsageSnapshot? snapshot;

  /// 当前会话 id：打开图谱卡片时顺手补一次刷新——快照缺失/过时能自愈
  /// （refresh 有缓存命中短路，新鲜时零开销）。
  final String? conversationId;

  final EdgeInsets padding;

  @override
  State<SolabChatUsageBar> createState() => _SolabChatUsageBarState();
}

class _SolabChatUsageBarState extends State<SolabChatUsageBar> {
  final LayerLink _anchor = LayerLink();
  OverlayEntry? _entry;

  @override
  void didUpdateWidget(covariant SolabChatUsageBar oldWidget) {
    super.didUpdateWidget(oldWidget);
    // 打开期间数据变化（新回复/刷新）也要跟着更新卡片。
    _entry?.markNeedsBuild();
  }

  @override
  void dispose() {
    _dismiss();
    super.dispose();
  }

  void _dismiss() {
    _entry?.remove();
    _entry = null;
  }

  void _toggle() {
    if (_entry != null) {
      setState(_dismiss);
      return;
    }
    // 打开即补一次刷新（与加号菜单的弹窗同款自愈）：快照为空/过时的时候
    // 用户看到的不再是空卡片，而是刷新后的估算/精确数据。
    final conversationId = widget.conversationId;
    if (conversationId != null && conversationId.isNotEmpty) {
      try {
        final usage = context.read<ContextUsageService?>();
        if (usage != null) {
          unawaited(usage.refresh(conversationId));
        }
      } catch (_) {}
    }
    final overlay = Overlay.maybeOf(context);
    if (overlay == null) return;
    _entry = OverlayEntry(
      builder: (ctx) => _ContextUsageOverlay(
        anchor: _anchor,
        snapshot: widget.snapshot,
        onDismiss: () {
          if (!mounted) return;
          setState(_dismiss);
        },
      ),
    );
    overlay.insert(_entry!);
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    // 没有对话历史就完全不显示（用户要求：内容为空时不要占位置）——但**底部间距
    // 要留下**：用户 2026-10-04 实测「没有消息时不显示，输入框离最底部的间距就没了」
    // （这条 dock 原本带着 bottom 6 的下边距，一收起连下边距一起消失）。
    if (widget.messages.isEmpty) {
      return SizedBox(height: widget.padding.bottom);
    }

    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    // 读数三个口径**一起显示**（用户 2026-10-03 定稿）：①当前上下文用量
    // （与图谱/弹窗同一个数，带窗口分母）；②整场会话累计；③缓存命中。
    // 此前只显示一个口径，两边数字对不上被认为「统计不一致」。
    final snapshot = widget.snapshot;
    final cumulative = cumulativeTokens(widget.messages);
    final cacheHit = cacheHitLabel(widget.messages);
    final percent = contextUsedPercent(snapshot);
    final window = snapshot?.contextWindow;
    final String contextLabel;
    if (snapshot != null && window != null && window > 0) {
      contextLabel = l10n.chatUsageContext(
        formatTokenCount(snapshot.usedTokens),
        formatTokenCount(window),
      );
    } else {
      contextLabel = l10n.chatUsageTokens(
        formatTokenCount(snapshot?.usedTokens ?? cumulative),
      );
    }
    if (snapshot == null && cumulative <= 0 && percent == null) {
      return SizedBox(height: widget.padding.bottom);
    }

    final reading = <String>[
      contextLabel,
      if (cumulative > 0) l10n.chatUsageCumulative(formatTokenCount(cumulative)),
      // 命中为 0 或未知都不显示（用户 2026-10-03：挂个 0 很难看）——
      // 只有真的命中了才出现这一段（0.4% 这类小数照常显示）。
      if (cacheHit != null && cacheHit != '0')
        l10n.chatUsageCacheHit(cacheHit),
    ].join(' · ');
    final style = TextStyle(
      fontSize: 11,
      fontWeight: AppFontWeights.medium,
      color: cs.onSurface.withValues(alpha: 0.55),
    );

    return Padding(
      padding: widget.padding,
      child: Center(
        child: CompositedTransformTarget(
          link: _anchor,
          child: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: _toggle,
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (percent != null) ...[
                  ContextUsageRing(
                    snapshot: widget.snapshot,
                    onTap: _toggle,
                    size: 13,
                    hitSize: 24,
                  ),
                  const SizedBox(width: 5),
                  Text('$percent%', style: style),
                  const SizedBox(width: 8),
                ],
                Flexible(
                  child: Text(
                    reading,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: style,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// 环上方的小卡片：只放上下文图谱（不出现任何功能开关）。
class _ContextUsageOverlay extends StatelessWidget {
  const _ContextUsageOverlay({
    required this.anchor,
    required this.snapshot,
    required this.onDismiss,
  });

  final LayerLink anchor;
  final ContextUsageSnapshot? snapshot;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final media = MediaQuery.of(context);
    // 340 是实测下限：我们的统计行（标题 + 用量 + 状态）在 276 内容宽下会横向溢出 25px。
    final width = math.min(340.0, media.size.width - 24);
    return Stack(
      children: [
        // 点空白关闭。
        Positioned.fill(
          child: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: onDismiss,
          ),
        ),
        CompositedTransformFollower(
          link: anchor,
          showWhenUnlinked: false,
          targetAnchor: Alignment.topCenter,
          followerAnchor: Alignment.bottomCenter,
          offset: const Offset(0, -6),
          child: SizedBox(
            width: width,
            child: _ContextUsageGlassCard(
              child: ConstrainedBox(
                constraints: BoxConstraints(
                  maxHeight: math.min(320, media.size.height * 0.5),
                ),
                child: SingleChildScrollView(
                  padding: EdgeInsets.zero,
                  // 图谱（分段条 + 分桶明细）：用户明确要求**保留**这条进度条，
                  // 「删了我看什么」。底部 dock 那条多余的才是不画的那个。
                  child: ContextUsageBreakdown(snapshot: snapshot),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// 我们自己的玻璃材质（与桌面 popover 同款 blur + 发丝边，只调 alpha）。
class _ContextUsageGlassCard extends StatelessWidget {
  const _ContextUsageGlassCard({required this.child});

  final Widget child;

  /// 卡片填充：信息密度高，必须比 popover 菜单更实，否则背后聊天文字会透上来
  /// （用户实测「所有文字下面都有横线」）。
  static double fillAlpha({required bool isDark}) => isDark ? 0.9 : 0.95;

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final cs = Theme.of(context).colorScheme;
    const radius = BorderRadius.all(Radius.circular(14));
    final hairline = cs.onSurface.withValues(alpha: isDark ? 0.06 : 0.12);
    return ClipRRect(
      borderRadius: radius,
      child: BackdropFilter(
        filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
        child: DecoratedBox(
          decoration: BoxDecoration(
            color: cs.surface.withValues(alpha: fillAlpha(isDark: isDark)),
            borderRadius: radius,
            border: Border.all(color: hairline, width: 0.6),
          ),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
            // 必须有 Material + DefaultTextStyle 包裹：弹层挂在 Overlay 上，祖先只有
            // WidgetsApp 的 error fallback 文本样式（**黄色双下划线 decoration**）；
            // Text 只覆盖字号/颜色时会把那个 decoration 继承下来 → 「文字下两道黄线」。
            child: Material(
              type: MaterialType.transparency,
              child: DefaultTextStyle(
                style:
                    Theme.of(context).textTheme.bodyMedium ??
                    const TextStyle(fontSize: 14),
                child: child,
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// 累计 token（本轮会话所有回复的 totalTokens 之和）。
int cumulativeTokens(List<ChatMessage> messages) {
  var total = 0;
  for (final message in messages) {
    total += message.totalTokens ?? 0;
  }
  return total;
}

/// 缓存命中率的显示串（`99.7` / `100`）；无可用数据返回 null。
///
/// 用户 2026-10-04：命中率要**从会话开始累计**（换对话/重启不能重算）——
/// 过去只取最近一条回复的 cached/prompt，每轮刷新、重启后"看起来归零"。
/// 现在对全部上报过 usage 的回复求和：Σcached ÷ Σprompt。
/// 「未知」规则保留：最近一条上报 usage 却没有缓存字段（供应商未上报）时返回
/// null——不出来把未知画成 0%（2026-10-03 真机的"重开归零"另一半来源）。
/// 部分命中同样不冒充满分（≥100% 才算全中）。
String? cacheHitLabel(List<ChatMessage> messages) {
  // 先看最近一条**有 usage** 的回复是否缺缓存字段：缺就"当前未知"，不显示。
  for (var i = messages.length - 1; i >= 0; i--) {
    final message = messages[i];
    if ((message.promptTokens ?? 0) <= 0) continue;
    if (message.cachedTokens == null) return null;
    break;
  }
  var totalPrompt = 0;
  var totalCached = 0;
  for (final message in messages) {
    final prompt = message.promptTokens ?? 0;
    final cachedTokens = message.cachedTokens;
    if (prompt <= 0 || cachedTokens == null) continue;
    totalPrompt += prompt;
    totalCached += cachedTokens.clamp(0, prompt);
  }
  if (totalPrompt <= 0) return null;
  if (totalCached >= totalPrompt) return '100';
  var tenths = (totalCached * 2000 + totalPrompt) ~/ (2 * totalPrompt);
  if (tenths > 999) tenths = 999; // 部分命中最多 99.9%
  if (tenths % 10 == 0) return '${tenths ~/ 10}';
  return '${tenths ~/ 10}.${tenths % 10}';
}

/// 等价于 [cacheHitLabel] 的整数百分比（向下取整；无数据 null）。
int? cacheHitPercent(List<ChatMessage> messages) {
  final label = cacheHitLabel(messages);
  if (label == null) return null;
  return double.parse(label).floor();
}

/// 上下文占用百分比（0–100）；无窗口信息时返回 null。
int? contextUsedPercent(ContextUsageSnapshot? snapshot) {
  final window = snapshot?.contextWindow;
  if (snapshot == null || window == null || window <= 0) return null;
  final used = snapshot.usedTokens;
  return (used * 100 / window).round().clamp(0, 100);
}
