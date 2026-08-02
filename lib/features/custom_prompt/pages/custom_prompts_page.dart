import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../../core/models/custom_prompt.dart';
import '../../../core/providers/custom_prompt_provider.dart';
import '../../../icons/lucide_adapter.dart';

/// Page for managing user custom prompts.
class CustomPromptsPage extends StatefulWidget {
  const CustomPromptsPage({super.key});

  @override
  State<CustomPromptsPage> createState() => _CustomPromptsPageState();
}

class _CustomPromptsPageState extends State<CustomPromptsPage> {
  @override
  void initState() {
    super.initState();
    context.read<CustomPromptProvider>().initialize();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final provider = context.watch<CustomPromptProvider>();
    final prompts = provider.filteredPrompts;
    final folders = provider.allFolders;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Prompts'),
        actions: [
          IconButton(
            icon: const Icon(Lucide.Plus),
            onPressed: () => _showEditDialog(context),
          ),
        ],
      ),
      body: Column(
        children: [
          // Search bar
          Padding(
            padding: const EdgeInsets.all(12),
            child: TextField(
              decoration: InputDecoration(
                hintText: 'Search prompts...',
                prefixIcon: const Icon(Lucide.Search, size: 18),
                isDense: true,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              onChanged: provider.setSearchQuery,
            ),
          ),
          // Folder + Tags filter row
          if (folders.isNotEmpty || provider.allTags.isNotEmpty)
            SizedBox(
              height: 36,
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 12),
                children: [
                  // "All" chip
                  Padding(
                    padding: const EdgeInsets.only(right: 6),
                    child: FilterChip(
                      label: const Text('All', style: TextStyle(fontSize: 12)),
                      selected: provider.activeFolder == null,
                      onSelected: (_) => provider.setActiveFolder(null),
                    ),
                  ),
                  // Folder chips
                  ...folders.map((folder) {
                    return Padding(
                      padding: const EdgeInsets.only(right: 6),
                      child: FilterChip(
                        label: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Lucide.Folder, size: 12, color: cs.primary),
                            const SizedBox(width: 4),
                            Text(folder, style: const TextStyle(fontSize: 12)),
                          ],
                        ),
                        selected: provider.activeFolder == folder,
                        onSelected: (sel) {
                          provider.setActiveFolder(sel ? folder : null);
                        },
                      ),
                    );
                  }),
                  // Tag chips
                  ...provider.allTags.map((tag) {
                    return Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: FilterChip(
                        label: Text(tag, style: const TextStyle(fontSize: 12)),
                        selected: provider.searchQuery == tag,
                        onSelected: (sel) {
                          provider.setSearchQuery(sel ? tag : '');
                        },
                      ),
                    );
                  }),
                ],
              ),
            ),
          const SizedBox(height: 8),
          // Prompt list
          Expanded(
            child: prompts.isEmpty
                ? Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Lucide.BookOpen, size: 48, color: cs.outline),
                        const SizedBox(height: 12),
                        Text(
                          'No prompts yet',
                          style: TextStyle(color: cs.outline),
                        ),
                        const SizedBox(height: 8),
                        TextButton.icon(
                          icon: const Icon(Lucide.Plus, size: 16),
                          label: const Text('Create one'),
                          onPressed: () => _showEditDialog(context),
                        ),
                      ],
                    ),
                  )
                : ReorderableListView.builder(
                    itemCount: prompts.length,
                    onReorder: provider.reorder,
                    itemBuilder: (ctx, i) {
                      final p = prompts[i];
                      return _PromptTile(
                        key: ValueKey(p.id),
                        prompt: p,
                        onTap: () => _showEditDialog(context, existing: p),
                        onToggleFavorite: () => provider.toggleFavorite(p.id),
                        onDelete: () => provider.delete(p.id),
                        onUse: () => _usePrompt(context, p),
                        onMoveToFolder: () => _showMoveToFolderDialog(context, p),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  void _usePrompt(BuildContext context, CustomPrompt prompt) async {
    final provider = context.read<CustomPromptProvider>();

    // If prompt has variables, show a dialog to fill them
    if (prompt.hasVariables) {
      final resolved = await _showVariableDialog(context, prompt);
      if (resolved == null) return; // cancelled
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Prompt "${prompt.title}" copied')),
      );
      Navigator.of(context).pop(resolved);
    } else {
      // No variables, resolve with built-in vars only
      final resolved = prompt.resolveContent({});
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Prompt "${prompt.title}" copied')),
      );
      Navigator.of(context).pop(resolved);
    }
  }

  Future<String?> _showVariableDialog(BuildContext context, CustomPrompt prompt) {
    final controllers = <String, TextEditingController>{};
    for (final v in prompt.variables) {
      controllers[v.name] = TextEditingController(text: v.defaultValue ?? '');
    }

    return showDialog<String>(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: Text('Fill: ${prompt.title}'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'This prompt has variables:',
                  style: TextStyle(fontSize: 12, color: Theme.of(ctx).colorScheme.outline),
                ),
                const SizedBox(height: 12),
                ...prompt.variables.map((v) {
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: TextField(
                      controller: controllers[v.name],
                      decoration: InputDecoration(
                        labelText: v.name,
                        hintText: v.hint ?? (v.defaultValue != null ? 'Default: ${v.defaultValue}' : 'Enter value...'),
                        isDense: true,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                      ),
                    ),
                  );
                }),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(null),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () {
                final values = <String, String>{};
                for (final entry in controllers.entries) {
                  values[entry.key] = entry.value.text.trim();
                }
                final resolved = prompt.resolveContent(values);
                Navigator.of(ctx).pop(resolved);
              },
              child: const Text('Insert'),
            ),
          ],
        );
      },
    );
  }

  Future<void> _showMoveToFolderDialog(BuildContext context, CustomPrompt prompt) async {
    final provider = context.read<CustomPromptProvider>();
    final folders = provider.allFolders;
    final ctrl = TextEditingController(text: prompt.folder ?? '');

    final result = await showDialog<String>(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: const Text('Move to folder'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (folders.isNotEmpty) ...[
                Wrap(
                  spacing: 6,
                  children: folders.map((f) {
                    return ActionChip(
                      label: Text(f),
                      onPressed: () => ctrl.text = f,
                    );
                  }).toList(),
                ),
                const SizedBox(height: 8),
              ],
              TextField(
                controller: ctrl,
                decoration: const InputDecoration(
                  labelText: 'Folder name',
                  hintText: 'e.g. coding, writing',
                  isDense: true,
                  border: OutlineInputBorder(),
                ),
              ),
              if (prompt.folder != null) ...[
                const SizedBox(height: 8),
                TextButton(
                  onPressed: () => Navigator.of(ctx).pop('__remove__'),
                  child: const Text('Remove from folder'),
                ),
              ],
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(null),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(ctx).pop(ctrl.text.trim()),
              child: const Text('Save'),
            ),
          ],
        );
      },
    );

    if (result == null) return;
    if (result == '__remove__') {
      await provider.moveToFolder(prompt.id, null);
    } else if (result.isNotEmpty) {
      await provider.moveToFolder(prompt.id, result);
    }
  }

  Future<void> _showEditDialog(BuildContext context, {CustomPrompt? existing}) async {
    final titleCtrl = TextEditingController(text: existing?.title ?? '');
    final contentCtrl = TextEditingController(text: existing?.content ?? '');
    final descCtrl = TextEditingController(text: existing?.description ?? '');
    final tagsCtrl = TextEditingController(text: existing?.tags.join(', ') ?? '');
    final folderCtrl = TextEditingController(text: existing?.folder ?? '');

    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: Text(existing == null ? 'New Prompt' : 'Edit Prompt'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: titleCtrl,
                  decoration: const InputDecoration(labelText: 'Title'),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: descCtrl,
                  decoration: const InputDecoration(labelText: 'Description (optional)'),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: contentCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Prompt content',
                    hintText: 'Use {{var}} for variables, {{var:default}} for defaults',
                  ),
                  maxLines: 6,
                  minLines: 3,
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: tagsCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Tags (comma separated)',
                    hintText: 'coding, writing, translate',
                  ),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: folderCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Folder (optional)',
                    hintText: 'e.g. coding',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(ctx).pop(true),
              child: Text(existing == null ? 'Create' : 'Save'),
            ),
          ],
        );
      },
    );

    if (result != true) return;
    if (!mounted) return;

    final title = titleCtrl.text.trim();
    final content = contentCtrl.text.trim();
    if (title.isEmpty || content.isEmpty) return;

    final tags = tagsCtrl.text
        .split(',')
        .map((t) => t.trim())
        .where((t) => t.isNotEmpty)
        .toList();

    final folder = folderCtrl.text.trim().isEmpty ? null : folderCtrl.text.trim();

    final provider = context.read<CustomPromptProvider>();
    if (existing == null) {
      await provider.add(CustomPrompt.create(
        title: title,
        content: content,
        description: descCtrl.text.trim().isNotEmpty ? descCtrl.text.trim() : null,
        tags: tags,
        folder: folder,
      ));
    } else {
      await provider.update(existing.copyWith(
        title: title,
        content: content,
        description: descCtrl.text.trim().isNotEmpty ? descCtrl.text.trim() : null,
        tags: tags,
        folder: folder,
      ));
    }
  }
}

class _PromptTile extends StatelessWidget {
  final CustomPrompt prompt;
  final VoidCallback onTap;
  final VoidCallback onToggleFavorite;
  final VoidCallback onDelete;
  final VoidCallback onUse;
  final VoidCallback onMoveToFolder;

  const _PromptTile({
    super.key,
    required this.prompt,
    required this.onTap,
    required this.onToggleFavorite,
    required this.onDelete,
    required this.onUse,
    required this.onMoveToFolder,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: ListTile(
        title: Row(
          children: [
            Flexible(
              child: Text(
                prompt.title,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
            if (prompt.folder != null) ...[
              const SizedBox(width: 6),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                decoration: BoxDecoration(
                  color: cs.primary.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  prompt.folder!,
                  style: TextStyle(fontSize: 10, color: cs.primary),
                ),
              ),
            ],
            if (prompt.hasVariables) ...[
              const SizedBox(width: 4),
              Icon(Lucide.Braces, size: 12, color: cs.tertiary),
            ],
          ],
        ),
        subtitle: Text(
          prompt.content,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(fontSize: 12, color: cs.outline),
        ),
        leading: IconButton(
          icon: Icon(
            prompt.isFavorite ? Lucide.Bookmark : Lucide.Star,
            color: prompt.isFavorite ? Colors.amber : cs.outline,
            size: 20,
          ),
          onPressed: onToggleFavorite,
        ),
        trailing: PopupMenuButton<String>(
          icon: const Icon(Lucide.MoreVertical, size: 18),
          onSelected: (action) {
            switch (action) {
              case 'use':
                onUse();
                break;
              case 'move':
                onMoveToFolder();
                break;
              case 'delete':
                onDelete();
                break;
            }
          },
          itemBuilder: (ctx) => [
            const PopupMenuItem(value: 'use', child: Row(
              children: [
                Icon(Lucide.Send, size: 16),
                SizedBox(width: 8),
                Text('Use'),
              ],
            )),
            const PopupMenuItem(value: 'move', child: Row(
              children: [
                Icon(Lucide.FolderInput, size: 16),
                SizedBox(width: 8),
                Text('Move to folder'),
              ],
            )),
            PopupMenuItem(value: 'delete', child: Row(
              children: [
                Icon(Lucide.Trash2, size: 16, color: cs.error),
                SizedBox(width: 8),
                Text('Delete', style: TextStyle(color: cs.error)),
              ],
            )),
          ],
        ),
        onTap: onTap,
        onLongPress: onMoveToFolder,
      ),
    );
  }
}