import 'package:flutter/foundation.dart';

/// 会话面（composer 上方）**内联提示**的统一投递口。
///
/// 用户 2026-09-28 定过、2026-10-03 重申「**不要 toast**，输入框上方的
/// 反馈就是答案」，并点名「全局」——凡是**自动发生**的会话反馈（目标循环
/// 的完成/受阻、后台任务失败、发送失败、未选模型…）都走这里，由 composer
/// 渲染在输入框正上方的状态行（与斜杠命令反馈同一套 UI），不再弹底部
/// SnackBar。用户主动触发的工具确认类提示（复制成功/请先选择消息等）
/// 不受此约束。
///
/// 带会话 id：composer 只显示属于自己会话的提示。
abstract final class ComposerNotices {
  static final ValueNotifier<ComposerNotice?> latest =
      ValueNotifier<ComposerNotice?>(null);

  static void post(
    String? conversationId,
    String text, {
    bool isError = false,
    bool busy = false,
  }) {
    final id = conversationId?.trim() ?? '';
    if (id.isEmpty || text.trim().isEmpty) return;
    latest.value = ComposerNotice(
      conversationId: id,
      text: text,
      isError: isError,
      busy: busy,
    );
  }
}

/// 一条内联提示。
class ComposerNotice {
  const ComposerNotice({
    required this.conversationId,
    required this.text,
    this.isError = false,
    this.busy = false,
  });

  final String conversationId;
  final String text;
  final bool isError;
  final bool busy;
}
