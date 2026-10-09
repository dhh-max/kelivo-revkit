import 'package:flutter/material.dart';

import '../../icons/lucide_adapter.dart';
import '../../theme/app_font_weights.dart';

/// 全 App 统一的子页外壳。
///
/// 之前每个页面各写一套 AppBar / 返回钮 / 内容限宽 / 内边距，导致
/// 「设置页一个样、技能页一个样、MCP 页又一个样」。统一走这里：
/// - 无边框 AppBar（背景=surface、无阴影），标题 18/w600
/// - 返回钮=圆形淡底图标钮（点击 200ms 无涟漪）
/// - 内容限宽 640 居中（平板/宽屏不拉满）
/// - 统一 16 外边距
class AppPageScaffold extends StatelessWidget {
  const AppPageScaffold({
    super.key,
    required this.title,
    required this.children,
    this.actions,
    this.scrollable = true,
    this.padding = const EdgeInsets.fromLTRB(16, 8, 16, 32),
  });

  final String title;
  final List<Widget> children;
  final List<Widget>? actions;

  /// true=ListView（内容可滚）；false=Column（调用方自己处理滚动/填充）。
  final bool scrollable;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) {
    final body = scrollable
        ? ListView(padding: padding, children: children)
        : Padding(
            padding: padding,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: children,
            ),
          );

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Lucide.ArrowLeft, size: 22),
          onPressed: () => Navigator.maybePop(context),
          // 不带底色——kelivo 的返回钮就是裸图标（视觉噪声最小）。
          style: IconButton.styleFrom(
            backgroundColor: Colors.transparent,
          ),
        ),
        title: Text(title),
        actions: actions,
      ),
      body: Align(
        alignment: Alignment.topCenter,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: body,
        ),
      ),
    );
  }
}

/// 小节标题 —— 对齐 kelivo `settings_page.dart` 的 `header()`：
/// 13 / semibold / onSurface α0.8，不做全大写。
/// （此前是 11.5 / α0.45 / 全大写，和设置页的组标题对不上，页面间观感不一致。）
class SectionLabel extends StatelessWidget {
  const SectionLabel({super.key, required this.text, this.trailing});

  final String text;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(left: 12, right: 12, bottom: 6),
      child: Row(children: [
        Text(text,
            style: TextStyle(
                fontSize: 13,
                fontWeight: AppFontWeights.semibold,
                color: cs.onSurface.withValues(alpha: 0.8))),
        const Spacer(),
        if (trailing != null) trailing!,
      ]),
    );
  }
}

/// 说明性脚注（每页底部统一）
class SectionFootnote extends StatelessWidget {
  const SectionFootnote(this.text, {super.key});
  final String text;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 4),
      child: Text(text,
          style: TextStyle(
              fontSize: 12,
              height: 1.65,
              color: cs.onSurface.withValues(alpha: 0.48))),
    );
  }
}
