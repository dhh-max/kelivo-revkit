import 'package:flutter/material.dart';

import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../theme/app_font_weights.dart';

/// 「AI 生成工作流」输入对话框：只收集需求描述，**不在弹窗里等生成**。
///
/// 2026-10-04 真机反馈「生成的时候可不可以直接在画布上，实时看到，而不是在
/// 弹窗这里等着」——生成改由编辑器页流式执行（节点/连线实时上屏），这里只
/// 负责问清需求：点「生成」即 pop 描述，由调用方带着它推进编辑器。
Future<String?> showWorkflowGenerateDialog(BuildContext context) {
  return showDialog<String>(
    context: context,
    builder: (_) => const _WorkflowGenerateDialog(),
  );
}

class _WorkflowGenerateDialog extends StatefulWidget {
  const _WorkflowGenerateDialog();

  @override
  State<_WorkflowGenerateDialog> createState() =>
      _WorkflowGenerateDialogState();
}

class _WorkflowGenerateDialogState extends State<_WorkflowGenerateDialog> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _submit() {
    final description = _controller.text.trim();
    if (description.isEmpty) return;
    Navigator.of(context).pop(description);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return AlertDialog(
      title: Row(
        children: [
          Icon(Lucide.Sparkles, size: 18, color: cs.primary),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              l10n.workflowGenerateTitle,
              style: TextStyle(
                fontSize: 16,
                fontWeight: AppFontWeights.emphasis,
              ),
            ),
          ),
        ],
      ),
      content: SizedBox(
        width: 420,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                l10n.workflowGenerateHint,
                style: TextStyle(fontSize: 12.5, color: cs.onSurfaceVariant),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: _controller,
                minLines: 3,
                maxLines: 6,
                autofocus: true,
                textInputAction: TextInputAction.newline,
                style: const TextStyle(fontSize: 14),
                decoration: InputDecoration(
                  hintText: l10n.workflowGeneratePlaceholder,
                  isDense: true,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(MaterialLocalizations.of(context).cancelButtonLabel),
        ),
        FilledButton.icon(
          onPressed: _submit,
          icon: const Icon(Lucide.Sparkles, size: 15),
          label: Text(
            l10n.workflowGenerateAction,
            style: const TextStyle(fontSize: 13.5),
          ),
        ),
      ],
    );
  }
}
