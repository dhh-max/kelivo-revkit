import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import '../../../core/services/device_path_service.dart';
import '../../../icons/lucide_adapter.dart';

/// Bottom sheet for file operations: rename, copy, move, delete.
class FileOperationsSheet extends StatefulWidget {
  final DevicePathEntry entry;
  final VoidCallback onChanged;

  const FileOperationsSheet({
    super.key,
    required this.entry,
    required this.onChanged,
  });

  static Future<void> show(
    BuildContext context, {
    required DevicePathEntry entry,
    required VoidCallback onChanged,
  }) {
    return showModalBottomSheet(
      context: context,
      builder: (ctx) => FileOperationsSheet(entry: entry, onChanged: onChanged),
    );
  }

  @override
  State<FileOperationsSheet> createState() => _FileOperationsSheetState();
}

class _FileOperationsSheetState extends State<FileOperationsSheet> {
  bool _busy = false;
  String? _error;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final name = widget.entry.name;
    final isDir = widget.entry.isDirectory;

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Handle
            Container(
              width: 40,
              height: 4,
              margin: const EdgeInsets.only(bottom: 12),
              decoration: BoxDecoration(
                color: cs.outline.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            // File name
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Text(
                name,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
            ),
            const SizedBox(height: 4),
            Text(
              isDir ? 'Folder' : _formatSize(widget.entry.sizeBytes),
              style: TextStyle(fontSize: 12, color: cs.outline),
            ),
            const Divider(height: 16),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                child: Text(_error!, style: TextStyle(color: cs.error, fontSize: 12)),
              ),
            // Operations
            ListTile(
              leading: const Icon(Lucide.Pencil, size: 20),
              title: const Text('Rename'),
              enabled: !_busy,
              onTap: () => _rename(context),
            ),
            ListTile(
              leading: const Icon(Lucide.Copy, size: 20),
              title: const Text('Copy to...'),
              enabled: !_busy,
              onTap: () => _copyTo(context),
            ),
            ListTile(
              leading: const Icon(Lucide.FolderInput, size: 20),
              title: const Text('Move to...'),
              enabled: !_busy,
              onTap: () => _moveTo(context),
            ),
            ListTile(
              leading: Icon(Lucide.Trash2, size: 20, color: cs.error),
              title: Text('Delete', style: TextStyle(color: cs.error)),
              enabled: !_busy,
              onTap: () => _delete(context),
            ),
            ListTile(
              leading: const Icon(Lucide.Clipboard, size: 20),
              title: const Text('Copy path'),
              enabled: !_busy,
              onTap: () {
                Clipboard.setData(ClipboardData(text: widget.entry.path));
                Navigator.of(context).pop();
              },
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _rename(BuildContext context) async {
    final ctrl = TextEditingController(text: widget.entry.name);
    final result = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Rename'),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          decoration: const InputDecoration(labelText: 'New name'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(ctrl.text.trim()),
            child: const Text('Rename'),
          ),
        ],
      ),
    );
    if (result == null || result.isEmpty || result == widget.entry.name) return;
    if (!mounted) return;

    setState(() { _busy = true; _error = null; });
    try {
      final dir = p.dirname(widget.entry.path);
      final newPath = p.join(dir, result);
      if (widget.entry.isDirectory) {
        await Directory(widget.entry.path).rename(newPath);
      } else {
        await File(widget.entry.path).rename(newPath);
      }
      widget.onChanged();
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      setState(() { _error = e.toString(); _busy = false; });
    }
  }

  Future<void> _copyTo(BuildContext context) async {
    final dest = await _pickDestination(context, 'Copy to');
    if (dest == null) return;
    if (!mounted) return;

    setState(() { _busy = true; _error = null; });
    try {
      final newPath = p.join(dest, widget.entry.name);
      if (widget.entry.isDirectory) {
        await _copyDirectory(Directory(widget.entry.path), Directory(newPath));
      } else {
        await File(widget.entry.path).copy(newPath);
      }
      widget.onChanged();
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      setState(() { _error = e.toString(); _busy = false; });
    }
  }

  Future<void> _moveTo(BuildContext context) async {
    final dest = await _pickDestination(context, 'Move to');
    if (dest == null) return;
    if (!mounted) return;

    setState(() { _busy = true; _error = null; });
    try {
      final newPath = p.join(dest, widget.entry.name);
      if (widget.entry.isDirectory) {
        await Directory(widget.entry.path).rename(newPath);
      } else {
        await File(widget.entry.path).rename(newPath);
      }
      widget.onChanged();
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      setState(() { _error = e.toString(); _busy = false; });
    }
  }

  Future<void> _delete(BuildContext context) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete'),
        content: Text('Delete "${widget.entry.name}"? This cannot be undone.'),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Theme.of(ctx).colorScheme.error),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirm != true) return;
    if (!mounted) return;

    setState(() { _busy = true; _error = null; });
    try {
      if (widget.entry.isDirectory) {
        await Directory(widget.entry.path).delete(recursive: true);
      } else {
        await File(widget.entry.path).delete();
      }
      widget.onChanged();
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      setState(() { _error = e.toString(); _busy = false; });
    }
  }

  Future<String?> _pickDestination(BuildContext context, String title) async {
    final ctrl = TextEditingController(text: p.dirname(widget.entry.path));
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: ctrl,
          decoration: const InputDecoration(
            labelText: 'Destination folder',
            hintText: '/sdcard/Download',
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(ctrl.text.trim()),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  static Future<void> _copyDirectory(Directory source, Directory dest) async {
    await dest.create(recursive: true);
    await for (final entity in source.list(followLinks: false)) {
      final newPath = p.join(dest.path, p.basename(entity.path));
      if (entity is Directory) {
        await _copyDirectory(entity, Directory(newPath));
      } else if (entity is File) {
        await entity.copy(newPath);
      }
    }
  }

  String _formatSize(int? bytes) {
    if (bytes == null) return '';
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }
}