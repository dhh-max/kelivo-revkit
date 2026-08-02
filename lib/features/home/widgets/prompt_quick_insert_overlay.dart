import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../core/models/custom_prompt.dart';
import '../../../core/providers/custom_prompt_provider.dart';
import '../../../icons/lucide_adapter.dart';

/// Overlay widget showing matching prompts when user types "/" in chat input.
///
/// Usage: place in a Stack above the input bar. Call [show] when "/" is typed,
/// [hide] when dismissed, [updateFilter] as user continues typing.
class PromptQuickInsertOverlay extends StatefulWidget {
  final ValueChanged<CustomPrompt> onSelect;
  final VoidCallback onDismiss;

  const PromptQuickInsertOverlay({
    super.key,
    required this.onSelect,
    required this.onDismiss,
  });

  @override
  State<PromptQuickInsertOverlay> createState() => PromptQuickInsertOverlayState();
}

class PromptQuickInsertOverlayState extends State<PromptQuickInsertOverlay> {
  String _filter = '';
  bool _visible = false;

  bool get isVisible => _visible;

  void show() {
    setState(() {
      _visible = true;
      _filter = '';
    });
  }

  void hide() {
    if (!_visible) return;
    setState(() => _visible = false);
  }

  void updateFilter(String query) {
    setState(() => _filter = query);
  }

  @override
  Widget build(BuildContext context) {
    if (!_visible) return const SizedBox.shrink();

    final cs = Theme.of(context).colorScheme;
    final provider = context.read<CustomPromptProvider>();
    final matches = provider.searchByPrefix(_filter);

    if (matches.isEmpty) {
      return const SizedBox.shrink();
    }

    return Positioned(
      left: 8,
      right: 8,
      bottom: 0,
      child: Material(
        elevation: 8,
        borderRadius: BorderRadius.circular(12),
        color: cs.surfaceContainer,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxHeight: 240),
          child: ListView.builder(
            shrinkWrap: true,
            padding: const EdgeInsets.symmetric(vertical: 4),
            itemCount: matches.length,
            itemBuilder: (ctx, i) {
              final prompt = matches[i];
              return ListTile(
                dense: true,
                leading: Icon(
                  prompt.isFavorite ? Lucide.Star : Lucide.MessageSquare,
                  size: 16,
                  color: prompt.isFavorite ? Colors.amber : cs.outline,
                ),
                title: Text(
                  prompt.title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontSize: 14),
                ),
                subtitle: prompt.description != null
                    ? Text(
                        prompt.description!,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(fontSize: 11, color: cs.outline),
                      )
                    : null,
                trailing: prompt.hasVariables
                    ? Icon(Lucide.Braces, size: 14, color: cs.tertiary)
                    : null,
                onTap: () {
                  widget.onSelect(prompt);
                  hide();
                },
              );
            },
          ),
        ),
      ),
    );
  }
}

/// Dialog to fill in prompt variables before inserting.
class PromptVariableDialog extends StatefulWidget {
  final CustomPrompt prompt;

  const PromptVariableDialog({super.key, required this.prompt});

  /// Show variable input dialog, returns resolved content or null if cancelled.
  static Future<String?> show(BuildContext context, CustomPrompt prompt) {
    if (!prompt.hasVariables) {
      return Future.value(prompt.resolveContent({}));
    }
    return showDialog<String>(
      context: context,
      builder: (ctx) => PromptVariableDialog(prompt: prompt),
    );
  }

  @override
  State<PromptVariableDialog> createState() => _PromptVariableDialogState();
}

class _PromptVariableDialogState extends State<PromptVariableDialog> {
  late final Map<String, TextEditingController> _controllers;

  @override
  void initState() {
    super.initState();
    _controllers = {
      for (final v in widget.prompt.variables)
        v.name: TextEditingController(text: v.defaultValue ?? ''),
    };
  }

  @override
  void dispose() {
    for (final c in _controllers.values) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.prompt.title),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: widget.prompt.variables.map((v) {
            return Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: TextField(
                controller: _controllers[v.name],
                decoration: InputDecoration(
                  labelText: v.name,
                  hintText: v.hint ?? v.defaultValue ?? 'Enter value...',
                ),
              ),
            );
          }).toList(),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () {
            final values = <String, String>{};
            for (final entry in _controllers.entries) {
              values[entry.key] = entry.value.text;
            }
            final resolved = widget.prompt.resolveContent(values);
            Navigator.of(context).pop(resolved);
          },
          child: const Text('Insert'),
        ),
      ],
    );
  }
}