import 'package:flutter/material.dart';

class AppShadows {
  static List<BoxShadow> soft = [
    BoxShadow(
      color: Colors.black.withValues(alpha: 0.05),
      blurRadius: 18,
      offset: const Offset(0, 6),
    ),
  ];
}

class AppRadii {
  static const double capsule = 28;
}

/// 覆盖层（桌面 popover / 弹层）配色（上游 1.2.6 引入）。
///
/// 本 fork 是 Android-only，桌面 popover 虽已裁剪入口，但这些文件仍在上游
/// 同步面内、被 import 链引用，故保留定义以免编译断裂。
class AppOverlayColors {
  static const double desktopPopoverAlphaDark = 0.28;
  static const double desktopPopoverAlphaLight = 0.56;

  static Color desktopPopoverSurface(ColorScheme cs) {
    final isDark = cs.brightness == Brightness.dark;
    return cs.surface.withValues(
      alpha: isDark ? desktopPopoverAlphaDark : desktopPopoverAlphaLight,
    );
  }
}

class AppSpacing {
  static const double xxs = 4;
  static const double xs = 8;
  static const double sm = 12;
  static const double md = 16;
  static const double lg = 20;
}
