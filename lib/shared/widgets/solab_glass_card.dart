import 'dart:ui' as ui;

import 'package:flutter/material.dart';

import '../../core/providers/settings_provider.dart';

/// 输入区那一排浮层（统计 dock 的上下文卡片、任务清单面板、后续同类面板）**唯一**的
/// 玻璃材质来源。
///
/// 用户 2026-10-03：「待办清单和上下文窗口弹窗用同款 UI，为什么透明度又不一样」——
/// 之前两处各写了一套（一个 `surfaceContainerHighest 0.5`、一个 `surface 0.9/0.95`），
/// 视觉立刻能看出差异。现在只留这一个实现，改透明度只改这里。
///
/// 同时它是**必须**存在的包裹层：浮层挂在 Overlay 上，祖先只有 WidgetsApp 的 error
/// fallback 文本样式（黄色双下划线 decoration）；这里提供 Material +
/// DefaultTextStyle，`Text` 才不会被继承成两道黄线。
class SolabGlassCard extends StatelessWidget {
  const SolabGlassCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.fromLTRB(12, 10, 12, 10),
    this.borderRadius = 14,
    this.blurSigma = 20,
    this.tint,
  });

  final Widget child;
  final EdgeInsets padding;
  final double borderRadius;
  final double blurSigma;

  /// 额外着色（默认不额外着色，保持与输入框同一套表面色）。
  final Color? tint;

  /// 唯一的填充透明度口径：浅色 0.95 / 深色 0.88。
  ///
  /// 高于 popover 菜单那档（0.28/0.56）：这两块都是信息密集卡片，太透会让背后聊天
  /// 的文字与表格线透上来（用户实测反馈「文字下面都是横线」之一）。
  static double fillAlpha({required bool isDark}) => isDark ? 0.88 : 0.95;

  /// 输入框表面填充——**与输入卡片同一口径**。
  ///
  /// 用户 2026-10-04：「输入框上方的这些（任务清单、子代理条）要和我们的聊天框
  /// 使用相同的东西、相同的材质、相同的透明度」。输入卡片那套是用户可配的
  /// 「输入框背景透明度」（默认浅 0.8236 / 深 0.7396，比本卡的 0.95/0.88 透），
  /// 两处各写一份公式迟早又不一致，所以口径收敛到这里。
  static Color composerFill({
    required ThemeData theme,
    required double lightOpacity,
    required double darkOpacity,
    required bool backgroundImageActive,
  }) {
    final isDark = theme.brightness == Brightness.dark;
    final configuredOpacity = (isDark ? darkOpacity : lightOpacity)
        .clamp(0.0, 1.0)
        .toDouble();
    final backgroundRatio = isDark
        ? 0.545 / SettingsProvider.defaultChatInputBackgroundOpacityDark
        : 0.5296 / SettingsProvider.defaultChatInputBackgroundOpacityLight;
    final targetOpacity = backgroundImageActive
        ? configuredOpacity * backgroundRatio
        : configuredOpacity;
    final overlayAlpha = isDark ? (backgroundImageActive ? 0.09 : 0.07) : 0.02;
    final overlayTint = isDark
        ? theme.colorScheme.onSurface.withValues(alpha: overlayAlpha)
        : theme.colorScheme.primary.withValues(alpha: overlayAlpha);
    final baseAlpha = ((targetOpacity - overlayAlpha) / (1.0 - overlayAlpha))
        .clamp(0.0, 1.0)
        .toDouble();
    final base = theme.colorScheme.surface.withValues(alpha: baseAlpha);
    return Color.alphaBlend(overlayTint, base).withValues(alpha: targetOpacity);
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final cs = Theme.of(context).colorScheme;
    final radius = BorderRadius.circular(borderRadius);
    final fill = tint ?? cs.surface.withValues(alpha: fillAlpha(isDark: isDark));
    final hairline = cs.onSurface.withValues(alpha: isDark ? 0.06 : 0.12);
    return ClipRRect(
      borderRadius: radius,
      child: BackdropFilter(
        filter: ui.ImageFilter.blur(sigmaX: blurSigma, sigmaY: blurSigma),
        child: DecoratedBox(
          decoration: BoxDecoration(
            color: fill,
            borderRadius: radius,
            border: Border.all(color: hairline, width: 0.6),
          ),
          child: Padding(
            padding: padding,
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
