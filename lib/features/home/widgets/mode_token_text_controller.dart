import 'package:flutter/material.dart';

import '../../../icons/lucide_adapter.dart';
import '../services/session_mode.dart';
import '../services/slash_commands.dart';

/// 输入框控制器：把开头的模式命令（`/plan` `/goal`）渲染成
/// **一枚不可编辑的胶囊**（用户 2026-09-28 要求：「我选择的命令在输入框，它应该
/// 属于一个不可被编辑的东西，你应该把它渲染一下」）。
///
/// 文本内容本身不动（还是 `/plan` 这样），所以解析/发送逻辑完全不变；
/// 变的只是绘制方式：前缀用 WidgetSpan 画成一枚胶囊（配色跟随主题色，
/// 不另造色板），只有 × 或整枚删除能去掉它。
class ModeTokenTextEditingController extends TextEditingController {
  ModeTokenTextEditingController({super.text});

  /// 当前是否处于「模式胶囊 + 正文」形态（发送逻辑据此判断）。
  SessionMode? get pendingMode {
    final parsed = SlashCommands.parse(text);
    if (parsed == null || !parsed.command.changesSession) return null;
    return SessionMode.fromWire(parsed.command.name);
  }

  /// 文本开头那段完整命令的长度（`/plan` = 5；面板写入时带一个分隔空格，
  /// 则把空格也算进胶囊 = 6）。没有则 null。
  ///
  /// 空格并入胶囊：用户 2026-10-03 实测「选完命令按退格，先吃掉的是空格，
  /// 胶囊还在，再按一下才整枚消失——光标像有问题」。把分隔空格视为胶囊的
  /// 一部分后，一次退格整枚拿掉，符合「不可编辑的东西」的直觉。
  int? get _tokenLength {
    final parsed = SlashCommands.parse(text);
    if (parsed == null || !parsed.command.changesSession) return null;
    final base = 1 + parsed.command.name.length;
    final withSpace =
        base < text.length && text.codeUnitAt(base) == 0x20 ? base + 1 : base;
    return withSpace.clamp(0, text.length);
  }

  /// 删除键切进胶囊时，把**整枚**去掉而不是退化成裸文本。
  ///
  /// 用户 2026-09-28 实测：胶囊形态下按退格会把 `/plan` 删成 `/pla`，胶囊消失、
  /// 又变回可编辑的一串字符——既然胶囊是"不可编辑的东西"，退格就该整枚拿掉
  /// （正文部分保持不动，光标落到正文开头）。只删正文、或正常打字不受影响。
  @override
  set value(TextEditingValue newValue) {
    final previous = value;
    final tokenLength = _tokenLength;
    if (tokenLength != null && newValue.text != previous.text) {
      // 用最小 diff 判断这次编辑到底动了哪一段：只有"真的删掉了胶囊内的字符"
      // 才接管。整段替换（全选粘贴）会跨出 token，插入字符则不删任何东西，
      // 都不会被误吃。
      final oldText = previous.text;
      final newText = newValue.text;
      var start = 0;
      while (start < oldText.length &&
          start < newText.length &&
          oldText[start] == newText[start]) {
        start++;
      }
      var endOld = oldText.length;
      var endNew = newText.length;
      while (endOld > start &&
          endNew > start &&
          oldText[endOld - 1] == newText[endNew - 1]) {
        endOld--;
        endNew--;
      }
      final deletesInsideToken =
          endOld > start && start < tokenLength && endOld <= tokenLength;
      if (deletesInsideToken) {
        final rest = oldText
            .substring(tokenLength)
            .replaceFirst(RegExp(r'^ +'), '');
        super.value = TextEditingValue(
          text: rest,
          selection: const TextSelection.collapsed(offset: 0),
        );
        return;
      }
    }
    super.value = newValue;
  }

  @override
  TextSpan buildTextSpan({
    required BuildContext context,
    TextStyle? style,
    required bool withComposing,
  }) {
    // 输入法组词中不接管绘制，避免打断中文/拼音输入。
    if (withComposing && value.composing.isValid && !value.composing.isCollapsed) {
      return super.buildTextSpan(context: context, style: style, withComposing: withComposing);
    }
    final mode = pendingMode;
    final tokenLength = _tokenLength;
    if (mode == null || tokenLength == null) {
      return super.buildTextSpan(context: context, style: style, withComposing: withComposing);
    }
    final rest = text.substring(tokenLength);

    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    // 两枚胶囊都跟随主题色（用户 2026-09-28：不要另造颜色）。
    final color = colors.primary;
    final icon = switch (mode) {
      SessionMode.goal => Lucide.Crosshair,
      _ => Lucide.Zap,
    };

    return TextSpan(
      style: style,
      children: <InlineSpan>[
        WidgetSpan(
          alignment: PlaceholderAlignment.middle,
          child: Container(
            margin: const EdgeInsets.only(right: 6),
            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.14),
              borderRadius: BorderRadius.circular(999),
              border: Border.all(color: color.withValues(alpha: 0.45), width: 1),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: <Widget>[
                Icon(icon, size: 12, color: color),
                const SizedBox(width: 3),
                Text(
                  '${mode.title}模式',
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: color,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(width: 3),
                // 只有这一枚 × 能去掉模式——正文部分照常可编辑。
                GestureDetector(
                  onTap: clear,
                  child: Icon(Lucide.X, size: 12, color: color),
                ),
              ],
            ),
          ),
        ),
        TextSpan(text: rest),
      ],
    );
  }
}
