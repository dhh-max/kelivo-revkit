import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:uuid/uuid.dart';
import '../../../core/providers/tool_history_provider.dart';
import '../../../core/models/tool_call_history.dart';
import '../../../icons/lucide_adapter.dart';

/// Bottom sheet for managing auto-approval rules.
class McpAutoApprovalSheet extends StatelessWidget {
  const McpAutoApprovalSheet({super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final provider = context.watch<ToolHistoryProvider>();

    return DraggableScrollableSheet(
      initialChildSize: 0.6,
      minChildSize: 0.3,
      maxChildSize: 0.9,
      expand: false,
      builder: (ctx, scrollController) {
        return Container(
          decoration: BoxDecoration(
            color: cs.surface,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: Column(
            children: [
              // Handle
              Container(
                margin: const EdgeInsets.only(top: 8),
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: cs.outline.withValues(alpha: 0.4),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              // Title
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
                child: Row(
                  children: [
                    Icon(Lucide.ShieldCheck, size: 20, color: cs.primary),
                    const SizedBox(width: 8),
                    Text('Auto-Approval Rules',
                        style: Theme.of(context).textTheme.titleMedium),
                    const Spacer(),
                    FilledButton.tonalIcon(
                      icon: const Icon(Lucide.Plus, size: 16),
                      label: const Text('Add Rule'),
                      onPressed: () => _showAddRuleDialog(context),
                    ),
                  ],
                ),
              ),
              // Info banner
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: cs.primaryContainer.withValues(alpha: 0.3),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      Icon(Lucide.info, size: 14, color: cs.primary),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          'Rules are checked in order. First match wins. '
                          'Patterns support substring or regex matching.',
                          style: TextStyle(fontSize: 11, color: cs.onPrimaryContainer),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const Divider(height: 16),
              // Rules list
              Expanded(
                child: provider.rules.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Lucide.ShieldOff, size: 48, color: cs.outline),
                            const SizedBox(height: 12),
                            Text('No rules configured',
                                style: TextStyle(color: cs.outline)),
                            const SizedBox(height: 4),
                            Text('All tool calls require manual approval',
                                style: TextStyle(fontSize: 12, color: cs.outline)),
                          ],
                        ),
                      )
                    : ListView.builder(
                        controller: scrollController,
                        padding: const EdgeInsets.symmetric(horizontal: 12),
                        itemCount: provider.rules.length,
                        itemBuilder: (ctx, i) {
                          final rule = provider.rules[i];
                          return _RuleTile(
                            rule: rule,
                            index: i + 1,
                            canMoveUp: i > 0,
                            canMoveDown: i < provider.rules.length - 1,
                            onToggle: () => provider.toggleRule(rule.id),
                            onDelete: () => provider.removeRule(rule.id),
                            onMoveUp: () => provider.moveRule(rule.id, true),
                            onMoveDown: () => provider.moveRule(rule.id, false),
                          );
                        },
                      ),
              ),
            ],
          ),
        );
      },
    );
  }

  void _showAddRuleDialog(BuildContext context) {
    final serverCtrl = TextEditingController();
    final toolCtrl = TextEditingController();
    var approve = true;

    showDialog(
      context: context,
      builder: (ctx) {
        return StatefulBuilder(
          builder: (ctx, setSt) {
            return AlertDialog(
              title: const Text('New Auto-Approval Rule'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    controller: serverCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Server ID Pattern',
                      hintText: 'e.g. filesystem or .*',
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: toolCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Tool Name Pattern',
                      hintText: 'e.g. read_file or .*',
                    ),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Switch(
                        value: approve,
                        onChanged: (v) => setSt(() => approve = v),
                      ),
                      const SizedBox(width: 8),
                      Text(approve ? 'Auto-approve' : 'Auto-deny'),
                    ],
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(ctx).pop(),
                  child: const Text('Cancel'),
                ),
                FilledButton(
                  onPressed: () {
                    final provider = context.read<ToolHistoryProvider>();
                    provider.addRule(ToolAutoApprovalRule(
                      id: const Uuid().v4(),
                      serverIdPattern: serverCtrl.text.trim().isEmpty
                          ? null
                          : serverCtrl.text.trim(),
                      toolNamePattern: toolCtrl.text.trim().isEmpty
                          ? null
                          : toolCtrl.text.trim(),
                      approve: approve,
                      createdAt: DateTime.now(),
                    ));
                    Navigator.of(ctx).pop();
                  },
                  child: const Text('Create'),
                ),
              ],
            );
          },
        );
      },
    );
  }
}

class _RuleTile extends StatelessWidget {
  final ToolAutoApprovalRule rule;
  final int index;
  final bool canMoveUp;
  final bool canMoveDown;
  final VoidCallback onToggle;
  final VoidCallback onDelete;
  final VoidCallback onMoveUp;
  final VoidCallback onMoveDown;

  const _RuleTile({
    required this.rule,
    required this.index,
    required this.canMoveUp,
    required this.canMoveDown,
    required this.onToggle,
    required this.onDelete,
    required this.onMoveUp,
    required this.onMoveDown,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Card(
      margin: const EdgeInsets.only(bottom: 6),
      child: ListTile(
        leading: Container(
          width: 32,
          height: 32,
          alignment: Alignment.center,
          decoration: BoxDecoration(
            color: (rule.approve ? Colors.green : Colors.red)
                .withValues(alpha: rule.enabled ? 0.15 : 0.05),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(
            rule.approve ? Lucide.ShieldCheck : Lucide.ShieldX,
            size: 18,
            color: rule.approve ? Colors.green : Colors.red,
          ),
        ),
        title: Text(
          'Rule #$index',
          style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (rule.serverIdPattern != null)
              Text('Server: ${rule.serverIdPattern}',
                  style: TextStyle(fontSize: 11, color: cs.outline)),
            if (rule.toolNamePattern != null)
              Text('Tool: ${rule.toolNamePattern}',
                  style: TextStyle(fontSize: 11, color: cs.outline)),
          ],
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Priority reorder buttons
            Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                IconButton(
                  icon: Icon(Lucide.ChevronUp, size: 14),
                  constraints: const BoxConstraints(minWidth: 24, minHeight: 20),
                  padding: EdgeInsets.zero,
                  onPressed: canMoveUp ? onMoveUp : null,
                  color: cs.outline,
                ),
                IconButton(
                  icon: Icon(Lucide.ChevronDown, size: 14),
                  constraints: const BoxConstraints(minWidth: 24, minHeight: 20),
                  padding: EdgeInsets.zero,
                  onPressed: canMoveDown ? onMoveDown : null,
                  color: cs.outline,
                ),
              ],
            ),
            Switch(value: rule.enabled, onChanged: (_) => onToggle()),
            IconButton(
              icon: Icon(Lucide.Trash2, size: 16, color: cs.error),
              onPressed: onDelete,
            ),
          ],
        ),
      ),
    );
  }
}