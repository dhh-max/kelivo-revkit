import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../../../core/models/custom_prompt.dart';
import '../../../core/providers/custom_prompt_provider.dart';
import '../../../icons/lucide_adapter.dart';

/// An overlay that shows matching prompts when the user types `/` in the chat input.
/// Usage: attach to a TextField via onChanged, detect `/` prefix, show this overlay.
class QuickPromptOverlay {
  final OverlayEntry? _entry;
  QuickPromptOverlay._(this._entry);

  static QuickPromptOverlay? show({
    required BuildContext context,
    required LayerLink layerLink,
    required String query,
    required ValueChanged<String> onInsert,
    VoidCallback? onDismiss,
  }) {
    final provider = context.read<CustomPromptProvider>();
    final matches = provider.searchByPrefix(query);
    if (matches.isEmpty) return null;

    late OverlayEntry entry;
    late QuickPromptOverlay overlay;

    entry = OverlayEntry(
      builder: (ctx) => _QuickPromptList(
        layerLink: layerLink,
        prompts: matches,
        onInsert: (prompt) {
          onInsert(prompt.content);
          entry.remove();
          onDismiss?.call();
        },
        onDismiss: () {
          entry.remove();
          onDismiss?.call();
        },
      ),
    );

    Overlay.of(context).insert(entry);
    overlay = QuickPromptOverlay._(entry);
    return overlay;
  }

  void remove() {
    _entry?.remove();
  }

  bool get isShowing => _entry != null;
}

class _QuickPromptList extends StatefulWidget {
  final LayerLink layerLink;
  final List<CustomPrompt> prompts;
  final ValueChanged<CustomPrompt> onInsert;
  final VoidCallback onDismiss;

  const _QuickPromptList({
    required this.layerLink,
    required this.prompts,
    required this.onInsert,
    required this.onDismiss,
  });

  @override
  State<_QuickPromptList> createState() => _QuickPromptListState();
}

class _QuickPromptListState extends State<_QuickPromptList> {
  int _selectedIndex = 0;
  late final FocusNode _focusNode;

  @override
  void initState() {
    super.initState();
    _focusNode = FocusNode();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _focusNode.requestFocus();
    });
  }

  @override
  void dispose() {
    _focusNode.dispose();
    super.dispose();
  }

  void _handleKey(KeyEvent event) {
    if (event is! KeyDownEvent && event is! KeyRepeatEvent) return;
    final key = event.logicalKey;
    if (key == LogicalKeyboardKey.arrowDown) {
      setState(() {
        _selectedIndex = (_selectedIndex + 1) % widget.prompts.length;
      });
    } else if (key == LogicalKeyboardKey.arrowUp) {
      setState(() {
        _selectedIndex = (_selectedIndex - 1 + widget.prompts.length) % widget.prompts.length;
      });
    } else if (key == LogicalKeyboardKey.enter || key == LogicalKeyboardKey.numpadEnter) {
      widget.onInsert(widget.prompts[_selectedIndex]);
    } else if (key == LogicalKeyboardKey.escape) {
      widget.onDismiss();
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return KeyboardListener(
      focusNode: _focusNode,
      onKeyEvent: _handleKey,
      child: Stack(
        children: [
          // Tap barrier to dismiss
          GestureDetector(
            onTap: widget.onDismiss,
            behavior: HitTestBehavior.opaque,
            child: Container(color: Colors.transparent),
          ),
          CompositedTransformFollower(
            link: widget.layerLink,
            targetAnchor: Alignment.topLeft,
            followerAnchor: Alignment.bottomLeft,
            offset: const Offset(0, -4),
            child: Material(
              elevation: 8,
              borderRadius: BorderRadius.circular(12),
              color: cs.surface,
              child: ConstrainedBox(
                constraints: const BoxConstraints(
                  maxHeight: 280,
                  maxWidth: 320,
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Header
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                      decoration: BoxDecoration(
                        color: cs.primaryContainer.withValues(alpha: 0.3),
                        borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                      ),
                      child: Row(
                        children: [
                          Icon(Lucide.Command, size: 14, color: cs.primary),
                          const SizedBox(width: 6),
                          Text(
                            'Quick Prompts',
                            style: TextStyle(
                              fontSize: 11,
                              fontWeight: FontWeight.w600,
                              color: cs.primary,
                            ),
                          ),
                          const Spacer(),
                          Text(
                            '↑↓ 选择  ⏎ 确认  Esc 关闭',
                            style: TextStyle(
                              fontSize: 9,
                              color: cs.onSurface.withValues(alpha: 0.4),
                            ),
                          ),
                        ],
                      ),
                    ),
                    Flexible(
                      child: ListView.builder(
                        shrinkWrap: true,
                        padding: const EdgeInsets.symmetric(vertical: 4),
                        itemCount: widget.prompts.length,
                        itemBuilder: (ctx, i) {
                          final p = widget.prompts[i];
                          return _QuickPromptTile(
                            prompt: p,
                            isSelected: i == _selectedIndex,
                            onTap: () => widget.onInsert(p),
                          );
                        },
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _QuickPromptTile extends StatelessWidget {
  final CustomPrompt prompt;
  final VoidCallback onTap;
  final bool isSelected;

  const _QuickPromptTile({
    required this.prompt,
    required this.onTap,
    this.isSelected = false,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(6),
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(6),
          color: isSelected ? cs.primary.withValues(alpha: 0.12) : null,
        ),
        child: Row(
          children: [
            // Folder indicator dot
            if (prompt.folder != null)
              Container(
                width: 6,
                height: 6,
                margin: const EdgeInsets.only(right: 8),
                decoration: BoxDecoration(
                  color: cs.primary,
                  shape: BoxShape.circle,
                ),
              ),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          prompt.title,
                          style: const TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (prompt.hasVariables) ...[
                        const SizedBox(width: 4),
                        Icon(Lucide.Braces, size: 10, color: cs.tertiary),
                      ],
                    ],
                  ),
                  if (prompt.description != null)
                    Text(
                      prompt.description!,
                      style: TextStyle(fontSize: 10, color: cs.outline),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                ],
              ),
            ),
            if (prompt.isFavorite)
              Padding(
                padding: const EdgeInsets.only(left: 4),
                child: Icon(Lucide.Bookmark, size: 12, color: Colors.amber),
              ),
          ],
        ),
      ),
    );
  }
}
