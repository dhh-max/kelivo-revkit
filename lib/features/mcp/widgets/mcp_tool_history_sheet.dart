import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../core/models/tool_call_history.dart';
import '../../../core/providers/tool_history_provider.dart';
import '../../../icons/lucide_adapter.dart';

/// Bottom sheet showing MCP tool call history for the current session.
class McpToolHistorySheet extends StatelessWidget {
  final String? conversationId;

  const McpToolHistorySheet({super.key, this.conversationId});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final provider = context.watch<ToolHistoryProvider>();
    final history = conversationId != null
        ? provider.historyForConversation(conversationId!)
        : provider.history;
    final stats = provider.stats;

    return DraggableScrollableSheet(
      initialChildSize: 0.7,
      minChildSize: 0.3,
      maxChildSize: 0.95,
      expand: false,
      builder: (ctx, scrollController) {
        return Container(
          decoration: BoxDecoration(
            color: cs.surface,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: Column(
            children: [
              // Handle bar
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
                    Icon(Lucide.History, size: 20, color: cs.primary),
                    const SizedBox(width: 8),
                    Text('Tool Call History',
                        style: Theme.of(context).textTheme.titleMedium),
                    const Spacer(),
                    if (history.isNotEmpty)
                      TextButton.icon(
                        icon: const Icon(Lucide.Trash2, size: 16),
                        label: const Text('Clear'),
                        onPressed: () => provider.clearHistory(),
                      ),
                  ],
                ),
              ),
              // Stats bar
              if (history.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Row(
                    children: [
                      _StatChip(
                        label: 'Total',
                        value: '${stats['total']}',
                        color: cs.primary,
                        icon: Lucide.List,
                      ),
                      const SizedBox(width: 8),
                      _StatChip(
                        label: 'Success',
                        value: '${stats['success']}',
                        color: Colors.green,
                        icon: Lucide.CheckCircle,
                      ),
                      const SizedBox(width: 8),
                      _StatChip(
                        label: 'Error',
                        value: '${stats['error']}',
                        color: cs.error,
                        icon: Lucide.XCircle,
                      ),
                      const SizedBox(width: 8),
                      if (provider.avgDurationMs > 0)
                        _StatChip(
                          label: 'Avg',
                          value: '${provider.avgDurationMs}ms',
                          color: cs.tertiary,
                          icon: Lucide.Clock,
                        ),
                    ],
                  ),
                ),
              const Divider(height: 16),
              // History list
              Expanded(
                child: history.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Lucide.PackageOpen, size: 48, color: cs.outline),
                            const SizedBox(height: 12),
                            Text('No tool calls yet',
                                style: TextStyle(color: cs.outline)),
                          ],
                        ),
                      )
                    : ListView.builder(
                        controller: scrollController,
                        padding: const EdgeInsets.symmetric(horizontal: 12),
                        itemCount: history.length,
                        itemBuilder: (ctx, i) {
                          final r = history[i];
                          return _HistoryTile(record: r);
                        },
                      ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _StatChip extends StatelessWidget {
  final String label;
  final String value;
  final Color color;
  final IconData icon;

  const _StatChip({
    required this.label,
    required this.value,
    required this.color,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: color),
          const SizedBox(width: 4),
          Text('$value $label',
              style: TextStyle(fontSize: 11, color: color, fontWeight: FontWeight.w600)),
        ],
      ),
    );
  }
}

class _HistoryTile extends StatelessWidget {
  final ToolCallRecord record;

  const _HistoryTile({required this.record});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final isSuccess = record.isSuccess;
    final isError = record.isError;
    final isPending = record.isPending;

    Color statusColor;
    IconData statusIcon;
    if (isPending) {
      statusColor = Colors.orange;
      statusIcon = Lucide.Loader;
    } else if (isError) {
      statusColor = cs.error;
      statusIcon = Lucide.XCircle;
    } else {
      statusColor = Colors.green;
      statusIcon = Lucide.CheckCircle;
    }

    final durStr = record.duration != null
        ? '${record.duration!.inMilliseconds}ms'
        : '...';

    return Card(
      margin: const EdgeInsets.only(bottom: 6),
      child: ExpansionTile(
        leading: Icon(statusIcon, size: 20, color: statusColor),
        title: Text(
          record.toolName,
          style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Row(
          children: [
            Text(record.serverId,
                style: TextStyle(fontSize: 11, color: cs.outline)),
            const SizedBox(width: 8),
            Text(durStr,
                style: TextStyle(fontSize: 11, color: cs.outline)),
          ],
        ),
        trailing: !record.approved
            ? Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: Colors.orange.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: const Text('Denied',
                    style: TextStyle(fontSize: 10, color: Colors.orange)),
              )
            : null,
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
        children: [
          // Arguments
          Text('Arguments',
              style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: cs.outline)),
          const SizedBox(height: 4),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: cs.surfaceContainerHighest.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(8),
            ),
            child: SelectableText(
              _formatJson(record.arguments),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
            ),
          ),
          // Result
          if (record.result != null) ...[
            const SizedBox(height: 8),
            Text('Result',
                style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    color: cs.outline)),
            const SizedBox(height: 4),
            Container(
              width: double.infinity,
              constraints: const BoxConstraints(maxHeight: 200),
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.green.withValues(alpha: 0.05),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SingleChildScrollView(
                child: SelectableText(
                  record.result!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              ),
            ),
          ],
          // Error
          if (record.error != null) ...[
            const SizedBox(height: 8),
            Text('Error',
                style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    color: cs.error)),
            const SizedBox(height: 4),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: cs.error.withValues(alpha: 0.05),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                record.error!,
                style: TextStyle(
                    fontFamily: 'monospace', fontSize: 11, color: cs.error),
              ),
            ),
          ],
        ],
      ),
    );
  }

  String _formatJson(Map<String, dynamic> map) {
    try {
      return JsonEncoder.withIndent('  ').convert(map);
    } catch (_) {
      return map.toString();
    }
  }
}
