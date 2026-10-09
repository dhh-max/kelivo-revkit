import 'package:flutter/material.dart';

import '../../../l10n/app_localizations.dart';

/// 工作流命名弹层（新建后重命名 / 列表页重命名共用一套 UI）。
class WorkflowNameSheet extends StatefulWidget {
  const WorkflowNameSheet({
    super.key,
    required this.scrollController,
    required this.initial,
    required this.onDone,
  });

  final ScrollController scrollController;
  final String initial;
  final ValueChanged<String> onDone;

  @override
  State<WorkflowNameSheet> createState() => _WorkflowNameSheetState();
}

class _WorkflowNameSheetState extends State<WorkflowNameSheet> {
  late final TextEditingController _controller =
      TextEditingController(text: widget.initial);

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return ListView(
      controller: widget.scrollController,
      shrinkWrap: true,
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      children: [
        TextField(
          controller: _controller,
          autofocus: true,
          decoration: InputDecoration(
            labelText: l10n.workflowRename,
            border: const OutlineInputBorder(),
          ),
          onSubmitted: widget.onDone,
        ),
        const SizedBox(height: 16),
        FilledButton(
          onPressed: () => widget.onDone(_controller.text),
          child: Text(l10n.workflowDone),
        ),
      ],
    );
  }
}
