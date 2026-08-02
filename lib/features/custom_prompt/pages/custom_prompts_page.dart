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
          // Tags filter
          if (provider.allTags.isNotEmpty)
            SizedBox(
              height: 36,
              child: ListView(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 12),
                children: provider.allTags.map((tag) {
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
                }).toList(),
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
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  void _usePrompt(BuildContext context, CustomPrompt prompt) {
    // Copy to clipboard and go back
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Prompt "${prompt.title}" copied')),
    );
    Navigator.of(context).pop(prompt);
  }

  Future<void> _showEditDialog(BuildContext context, {CustomPrompt? existing}) async {
    final titleCtrl = TextEditingController(text: existing?.title ?? '');
    final contentCtrl = TextEditingController(text: existing?.content ?? '');
    final descCtrl = TextEditingController(text: existing?.description ?? '');
    final tagsCtrl = TextEditingController(text: existing?.tags.join(', ') ?? '');

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
                  decoration: const InputDecoration(labelText: 'Prompt content'),
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

    final provider = context.read<CustomPromptProvider>();
    if (existing == null) {
      await provider.add(CustomPrompt.create(
        title: title,
        content: content,
        description: descCtrl.text.trim().isNotEmpty ? descCtrl.text.trim() : null,
        tags: tags,
      ));
    } else {
      await provider.update(existing.copyWith(
        title: title,
        content: content,
        description: descCtrl.text.trim().isNotEmpty ? descCtrl.text.trim() : null,
        tags: tags,
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

  const _PromptTile({
    super.key,
    required this.prompt,
    required this.onTap,
    required this.onToggleFavorite,
    required this.onDelete,
    required this.onUse,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: ListTile(
        title: Text(
          prompt.title,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
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
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              icon: Icon(Lucide.Copy, size: 18, color: cs.primary),
              onPressed: onUse,
              tooltip: 'Use',
            ),
            IconButton(
              icon: Icon(Lucide.Trash2, size: 18, color: cs.error),
              onPressed: onDelete,
              tooltip: 'Delete',
            ),
          ],
        ),
        onTap: onTap,
      ),
    );
  }
}