part of 'chat_message_widget.dart';

// ---------------------------------------------------------------------------
// 「上游原版」步骤渲染路由（设置项 chat_steps_shared_bubble_v1 打开时启用）
//
// 本文件是 chat_message_widget.dart 的 part：与主文件同属一个库，因此可以直接
// 复用那份文件里的私有步骤组件（_CachedTimelineStep、_ChainOfThoughtReasoningStep、
// _ChainOfThoughtToolStep …）、常量（_timelineIconColumnWidth / _timelineIconSize …）
// 与全部 import，无需把任何实现改成 public。
//
// 内容逐字照抄 upstream/master:lib/features/chat/widgets/chat_message_widget.dart
// 的对应片段（上游 4711-4904 行）：
//   _TimelineStepShell → _UpstreamTimelineStepShell
//   _TimelineIconColumn → _UpstreamTimelineIconColumn
//   _TimelineLinePainter → _UpstreamTimelineLinePainter
//   _timelineLineGap / _timelineLineX（上游有、我们默认路由 2026-09-14 删线时移除）
//
// 唯一改动：三个私有类名加 `Upstream` 前缀，避免与默认路由的同名类冲突。
// 渲染逻辑、变量名、参数、结构与上游逐行一致 —— 默认路由（开关关闭）完全不受
// 本文件影响；开关打开时步骤区整段走上游实现，串联线随上游实现一并回来。
// ---------------------------------------------------------------------------

/// 上游的时间轴串联线常量（上游同文件第 4357-4358 行）。
///
/// 不复用主文件的同名常量：它们在上游本就是同库同名的两套值，这里保持上游写法。
/// [_timelineIconColumnWidth] 与 [_timelineIconSize] 取自主文件（两版数值相同，
/// 均为 24 / 18）。
const double _timelineLineGap = 3;
const double _timelineLineX = (_timelineIconColumnWidth - 1) / 2;

/// 上游折叠行的内边距：只有纵向 6。默认路由额外补左右各 12 与卡片内边距对齐
/// （主文件里的 `_stepCardInsetX`），上游把这段对齐交给共享气泡的内边距。
const EdgeInsets _upstreamExpandRowPadding = EdgeInsets.symmetric(vertical: 6);

/// 开关：步骤区是否走上游原版渲染。
///
/// 与 `chat_surface.dart` 的 `_chatSurfaceStyleSelection` 同样兜底
/// [ProviderNotFoundException]：可能出现没有 SettingsProvider 的子树，
/// 此时按默认路由（关闭）处理，绝不因为读设置而炸渲染。
bool _upstreamStepsRoute(BuildContext context) {
  try {
    return context.select<SettingsProvider, bool>(
      (s) => s.chatStepsSharedBubble,
    );
  } on ProviderNotFoundException {
    return false;
  }
}

class _UpstreamTimelineStepShell extends StatelessWidget {
  const _UpstreamTimelineStepShell({
    required this.icon,
    required this.label,
    required this.isFirst,
    required this.isLast,
    this.onTap,
    this.extra,
    this.indicator,
    this.content,
    this.contentVisible = false,
    this.expectContent = false,
  });

  final Widget icon;
  final Widget label;
  final bool isFirst;
  final bool isLast;
  final VoidCallback? onTap;
  final Widget? extra;
  final Widget? indicator;
  final Widget? content;
  final bool contentVisible;

  /// Keep [AnimatedSize] mounted so a later result or expand can grow in.
  /// Finished steps with no body skip the slot entirely.
  final bool expectContent;

  @override
  Widget build(BuildContext context) {
    final fg = chatSurfaceForegroundPalette(context);
    final headerContent = Padding(
      padding: const EdgeInsets.symmetric(vertical: _timelineStepPaddingV),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          const SizedBox(
            width: _timelineIconColumnWidth,
            height: _timelineIconSize,
          ),
          const SizedBox(width: _timelineGap),
          Expanded(child: label),
          if (extra != null) ...[const SizedBox(width: 8), extra!],
          if (indicator != null) ...[const SizedBox(width: 6), indicator!],
        ],
      ),
    );

    final header = Stack(
      children: [
        headerContent,
        Positioned(
          left: 0,
          top: 0,
          bottom: 0,
          width: _timelineIconColumnWidth,
          child: _UpstreamTimelineIconColumn(
            icon: icon,
            isFirst: isFirst,
            isLast: isLast,
            lineColor: fg.divider,
          ),
        ),
      ],
    );

    final pressableHeader = IosCardPress(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      baseColor: Colors.transparent,
      pressedScale: 1,
      padding: const EdgeInsets.symmetric(horizontal: 0, vertical: 0),
      child: header,
    );
    if (content == null && !expectContent) {
      return KeyedSubtree(
        key: ValueKey<String>('chatMessageTimelineStepShell:$isFirst:$isLast'),
        child: pressableHeader,
      );
    }

    return KeyedSubtree(
      key: ValueKey<String>('chatMessageTimelineStepShell:$isFirst:$isLast'),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          pressableHeader,
          Stack(
            clipBehavior: Clip.none,
            children: [
              // 2026-10-02 修复（用户：「没有调用工具、只有思考时左边的线不显示；
              // 思考越多线应该越长」）：上游这里写的是 `if (!isLast)`，于是
              // **最后一步**（含「只有思考没有工具」的唯一一步）内容区完全不画线——
              // 而内容区正是随思考长度变高的那段，线反而在最需要它的地方缺席。
              // 改成「有可见内容就画」：线高 = 内容高，思考越长线越长。
              // 上游原本是 !isLast（多步时非末步有线）；补上「末步/唯一步有可见内容」
              // 也要有线，两者取并集，既不改上游语义又修好「只有思考时没线」。
              if (!isLast || (contentVisible && content != null))
                Positioned(
                  left: _timelineLineX,
                  top: 0,
                  bottom: 0,
                  child: SizedBox(
                    key: const ValueKey('chatMessageTimelineContentLine'),
                    width: 1,
                    child: ColoredBox(color: fg.divider),
                  ),
                ),
              AnimatedSize(
                duration: const Duration(milliseconds: 300),
                curve: const Cubic(0.2, 0.8, 0.2, 1),
                alignment: Alignment.topLeft,
                child: contentVisible
                    ? Padding(
                        padding: const EdgeInsets.only(
                          left: _timelineIconColumnWidth + _timelineGap,
                          top: 4,
                          bottom: 8,
                        ),
                        child: content,
                      )
                    : const SizedBox.shrink(),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _UpstreamTimelineIconColumn extends StatelessWidget {
  const _UpstreamTimelineIconColumn({
    required this.icon,
    required this.isFirst,
    required this.isLast,
    required this.lineColor,
  });

  final Widget icon;
  final bool isFirst;
  final bool isLast;
  final Color lineColor;

  @override
  Widget build(BuildContext context) {
    return CustomPaint(
      key: ValueKey<String>('chatMessageTimelineIconColumn:$isFirst:$isLast'),
      painter: _UpstreamTimelineLinePainter(
        isFirst: isFirst,
        isLast: isLast,
        lineColor: lineColor,
      ),
      child: SizedBox.expand(child: Center(child: icon)),
    );
  }
}

class _UpstreamTimelineLinePainter extends CustomPainter {
  const _UpstreamTimelineLinePainter({
    required this.isFirst,
    required this.isLast,
    required this.lineColor,
  });

  final bool isFirst;
  final bool isLast;
  final Color lineColor;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = lineColor
      ..strokeWidth = 1
      ..style = PaintingStyle.stroke;
    final x = size.width / 2;
    final iconTop = (size.height - _timelineIconSize) / 2;
    final iconBottom = iconTop + _timelineIconSize;
    if (!isFirst) {
      canvas.drawLine(
        Offset(x, 0),
        Offset(x, math.max(0, iconTop - _timelineLineGap)),
        paint,
      );
    }
    if (!isLast) {
      canvas.drawLine(
        Offset(x, math.min(size.height, iconBottom + _timelineLineGap)),
        Offset(x, size.height),
        paint,
      );
    }
  }

  @override
  bool shouldRepaint(covariant _UpstreamTimelineLinePainter oldDelegate) {
    return oldDelegate.isFirst != isFirst ||
        oldDelegate.isLast != isLast ||
        oldDelegate.lineColor != lineColor;
  }
}
