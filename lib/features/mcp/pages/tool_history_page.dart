import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../../../core/models/tool_call_history.dart';
import '../../../core/providers/tool_history_provider.dart';
import '../../../icons/lucide_adapter.dart';

/// Page showing MCP tool call history with stats and details.
class ToolHistoryPage extends StatefulWidget {
  const ToolHistoryPage({super.key});

  @override
  State<ToolHistoryPage> createState() => _ToolHistoryPageState();
}

class _ToolHistoryPageState extends State<ToolHistoryPage> {
  String _searchQuery = '';
  String _statusFilter = 'all'; // all | success | error | pending

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Lucide.ArrowLeft),
          onPressed: () => Navigator.of(context).pop(),
        ),
        title: const Text('Tool Call History'),
        actions: [
          IconButton(
            icon: const Icon(Lucide.Download),
            tooltip: 'Export JSON',
            onPressed: () {
              final json = context.read<ToolHistoryProvider>().exportJson();
              Clipboard.setData(ClipboardData(text: json));
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('History exported to clipboard (${json.length} bytes)'),
                  behavior: SnackBarBehavior.floating,
                ),
              );
            },
          ),
          IconButton(
            icon: const Icon(Lucide.Trash2),
            tooltip: 'Clear history',
            onPressed: () {
              context.read<ToolHistoryProvider>().clearHistory();
            },
          ),
        ],
      ),
      body: Consumer<ToolHistoryProvider>(
        builder: (ctx, provider, _) {
          final allHistory = provider.history;
          final stats = provider.stats;

          // Apply search + filter
          var history = allHistory;
          if (_searchQuery.isNotEmpty) {
            history = provider.search(_searchQuery);
          }
          if (_statusFilter != 'all') {
            history = history.where((r) {
              switch (_statusFilter) {
                case 'success': return r.isSuccess;
                case 'error': return r.isError;
                case 'pending': return r.isPending;
                default: return true;
              }
            }).toList();
          }

          return Column(
            children: [
              // Stats bar
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                color: cs.surfaceContainerHighest.withValues(alpha: 0.3),
                child: Row(
                  children: [
                    _StatChip(
                      label: 'Total',
                      value: '${stats["total"]}',
                      color: cs.primary,
                    ),
                    const SizedBox(width: 12),
                    _StatChip(
                      label: 'OK',
                      value: '${stats["success"]}',
                      color: Colors.green,
                    ),
                    const SizedBox(width: 12),
                    _StatChip(
                      label: 'Error',
                      value: '${stats["error"]}',
                      color: cs.error,
                    ),
                    const SizedBox(width: 12),
                    _StatChip(
                      label: 'Avg',
                      value: '${provider.avgDurationMs}ms',
                      color: cs.tertiary,
                    ),
                  ],
                ),
              ),
              // Search bar + filter chips
              Padding(
                padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
                child: Row(
                  children: [
                    Expanded(
                      child: TextField(
                        onChanged: (v) => setState(() => _searchQuery = v),
                        decoration: InputDecoration(
                          hintText: 'Search tool name, server, result...',
                          prefixIcon: Icon(Lucide.Search, size: 16, color: cs.outline),
                          isDense: true,
                          contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(10),
                            borderSide: BorderSide.none,
                          ),
                          filled: true,
                          fillColor: cs.surfaceContainerHighest.withValues(alpha: 0.5),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              // Filter chips
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                child: SizedBox(
                  height: 36,
                  child: ListView(
                    scrollDirection: Axis.horizontal,
                    children: [
                      _FilterChip(
                        label: 'All',
                        active: _statusFilter == 'all',
                        onTap: () => setState(() => _statusFilter = 'all'),
                      ),
                      _FilterChip(
                        label: 'Success',
                        active: _statusFilter == 'success',
                        color: Colors.green,
                        onTap: () => setState(() => _statusFilter = _statusFilter == 'success' ? 'all' : 'success'),
                      ),
                      _FilterChip(
                        label: 'Error',
                        active: _statusFilter == 'error',
                        color: cs.error,
                        onTap: () => setState(() => _statusFilter = _statusFilter == 'error' ? 'all' : 'error'),
                      ),
                      _FilterChip(
                        label: 'Pending',
                        active: _statusFilter == 'pending',
                        color: cs.tertiary,
                        onTap: () => setState(() => _statusFilter = _statusFilter == 'pending' ? 'all' : 'pending'),
                      ),
                    ],
                  ),
                ),
              ),
              const Divider(height: 1),
              // History list
              Expanded(
                child: history.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Lucide.History, size: 48, color: cs.outline),
                            const SizedBox(height: 12),
                            Text(
                              allHistory.isEmpty ? 'No tool calls yet' : 'No results match your filter',
                              style: TextStyle(color: cs.outline),
                            ),
                          ],
                        ),
                      )
                    : ListView.builder(
                        itemCount: history.length,
                        itemBuilder: (ctx, i) =>
                            _ToolCallTile(record: history[i]),
                      ),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _StatChip extends StatelessWidget {
  final String label;
  final String value;
  final Color color;

  const _StatChip({
    required this.label,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(value,
            style: TextStyle(
                fontWeight: FontWeight.bold, fontSize: 16, color: color)),
        Text(label, style: TextStyle(fontSize: 11, color: color.withValues(alpha: 0.7))),
      ],
    );
  }
}

class _ToolCallTile extends StatelessWidget {
  final ToolCallRecord record;

  const _ToolCallTile({required this.record});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final icon = record.isPending
        ? Lucide.Loader
        : record.isError
            ? Lucide.AlertCircle
            : Lucide.CheckCircle;
    final iconColor = record.isPending
        ? cs.tertiary
        : record.isError
            ? cs.error
            : Colors.green;

    return ListTile(
      leading: Icon(icon, color: iconColor, size: 20),
      title: Text(
        record.toolName,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(fontWeight: FontWeight.w500),
      ),
      subtitle: Text(
        record.serverId,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(fontSize: 12, color: cs.outline),
      ),
      trailing: record.duration != null
          ? Text(
              '${record.duration!.inMilliseconds}ms',
              style: TextStyle(fontSize: 12, color: cs.outline),
            )
          : record.isPending
              ? SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2, color: cs.tertiary),
                )
              : null,
      onTap: () => _showDetail(context),
    );
  }

  void _showDetail(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => DraggableScrollableSheet(
        initialChildSize: 0.6,
        minChildSize: 0.3,
        maxChildSize: 0.9,
        expand: false,
        builder: (ctx, scroll) => ListView(
          controller: scroll,
          padding: const EdgeInsets.all(16),
          children: [
            Center(
              child: Container(
                width: 40,
                height: 4,
                margin: const EdgeInsets.only(bottom: 16),
                decoration: BoxDecoration(
                  color: cs.outline.withValues(alpha: 0.3),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            Text(record.toolName,
                style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            Text('Server: ${record.serverId}',
                style: TextStyle(fontSize: 13, color: cs.outline)),
            Text(
              'Started: ${record.startedAt.toLocal().toString().substring(0, 19)}',
              style: TextStyle(fontSize: 13, color: cs.outline),
            ),
            if (record.duration != null)
              Text('Duration: ${record.duration!.inMilliseconds}ms',
                  style: TextStyle(fontSize: 13, color: cs.outline)),
            const Divider(height: 24),
            _SectionTitle(title: 'Arguments', onCopy: () {
              Clipboard.setData(ClipboardData(text: record.arguments.toString()));
            }),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: cs.surfaceContainerHighest.withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(8),
              ),
              child: SelectableText(
                _prettyJson(record.arguments),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
            if (record.result != null) ...[
              const SizedBox(height: 16),
              _SectionTitle(title: 'Result', onCopy: () {
                Clipboard.setData(ClipboardData(text: record.result!));
              }),
              Container(
                constraints: const BoxConstraints(maxHeight: 200),
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Colors.green.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SingleChildScrollView(
                  child: SelectableText(
                    record.result!.length > 2000
                        ? '${record.result!.substring(0, 2000)}\n... (truncated)'
                        : record.result!,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                ),
              ),
            ],
            if (record.error != null) ...[
              const SizedBox(height: 16),
              _SectionTitle(title: 'Error', onCopy: () {
                Clipboard.setData(ClipboardData(text: record.error!));
              }),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Colors.red.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SelectableText(
                  record.error!,
                  style: TextStyle(
                      fontFamily: 'monospace', fontSize: 12, color: cs.error),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  String _prettyJson(Map<String, dynamic> map) {
    try {
      const encoder = JsonEncoder.withIndent('  ');
      return encoder.convert(map);
    } catch (_) {
      return map.toString();
    }
  }
}

class _SectionTitle extends StatelessWidget {
  final String title;
  final VoidCallback? onCopy;

  const _SectionTitle({required this.title, this.onCopy});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Text(title,
            style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
        const Spacer(),
        if (onCopy != null)
          IconButton(
            icon: const Icon(Lucide.Copy, size: 14),
            onPressed: onCopy,
            tooltip: 'Copy',
          ),
      ],
    );
  }
}

class _FilterChip extends StatelessWidget {
  final String label;
  final bool active;
  final Color? color;
  final VoidCallback onTap;

  const _FilterChip({
    required this.label,
    required this.active,
    required this.onTap,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final c = color ?? cs.primary;
    return Padding(
      padding: const EdgeInsets.only(right: 6),
      child: GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          decoration: BoxDecoration(
            color: active ? c.withValues(alpha: 0.15) : cs.surfaceContainerHighest.withValues(alpha: 0.3),
            borderRadius: BorderRadius.circular(16),
            border: active ? Border.all(color: c.withValues(alpha: 0.4)) : null,
          ),
          child: Text(
            label,
            style: TextStyle(
              fontSize: 12,
              fontWeight: active ? FontWeight.w600 : FontWeight.w400,
              color: active ? c : cs.outline,
            ),
          ),
        ),
      ),
    );
  }
}
