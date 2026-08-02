import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../../core/services/device_path_service.dart';
import '../../../icons/lucide_adapter.dart';

/// Page for browsing device file system paths.
///
/// Provides a file-manager-like interface for navigating
/// the device's storage, searching files, and previewing content.
class DevicePathBrowserPage extends StatefulWidget {
  const DevicePathBrowserPage({super.key, this.initialPath});

  final String? initialPath;

  @override
  State<DevicePathBrowserPage> createState() => _DevicePathBrowserPageState();
}

class _DevicePathBrowserPageState extends State<DevicePathBrowserPage> {
  String _currentPath = '/sdcard';
  List<DevicePathEntry> _entries = [];
  bool _loading = true;
  bool _showHidden = false;
  String _sortBy = 'name';

  final _searchController = TextEditingController();
  List<DevicePathEntry>? _searchResults;
  bool _searching = false;

  @override
  void initState() {
    super.initState();
    _currentPath = widget.initialPath ?? '/sdcard';
    _loadDirectory();
  }

  Future<void> _loadDirectory() async {
    setState(() {
      _loading = true;
      _searchResults = null;
    });
    final entries = await DevicePathService.listDirectory(
      _currentPath,
      showHidden: _showHidden,
      sortBy: _sortBy,
    );
    if (mounted) {
      setState(() {
        _entries = entries;
        _loading = false;
      });
    }
  }

  Future<void> _navigateTo(String path) async {
    _currentPath = path;
    await _loadDirectory();
  }

  Future<void> _goUp() async {
    if (_currentPath == '/' || _currentPath.isEmpty) return;
    final parts = _currentPath.split('/').where((s) => s.isNotEmpty).toList();
    if (parts.isEmpty) return;
    parts.removeLast();
    _currentPath = parts.isEmpty ? '/' : '/${parts.join('/')}';
    await _loadDirectory();
  }

  Future<void> _performSearch(String query) async {
    if (query.trim().isEmpty) {
      setState(() => _searchResults = null);
      return;
    }
    setState(() => _searching = true);
    final results = await DevicePathService.searchFiles(
      _currentPath,
      pattern: query.trim(),
      maxResults: 50,
      maxDepth: 4,
    );
    if (mounted) {
      setState(() {
        _searchResults = results;
        _searching = false;
      });
    }
  }

  Future<void> _previewFile(DevicePathEntry entry) async {
    final info = await DevicePathService.previewFile(entry.path);
    if (!mounted) return;
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(entry.name, maxLines: 1, overflow: TextOverflow.ellipsis),
        content: SizedBox(
          width: double.maxFinite,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text('Size: ${_formatBytes(info['size'] as int? ?? 0)}',
                    style: const TextStyle(fontSize: 12, color: Colors.grey)),
                const SizedBox(height: 4),
                Text('Modified: ${info['modified'] ?? 'N/A'}',
                    style: const TextStyle(fontSize: 12, color: Colors.grey)),
                const SizedBox(height: 4),
                Text('Type: ${info['type'] ?? 'unknown'}',
                    style: const TextStyle(fontSize: 12, color: Colors.grey)),
                const Divider(height: 16),
                if (info['type'] == 'text')
                  Container(
                    constraints: const BoxConstraints(maxHeight: 300),
                    child: SingleChildScrollView(
                      child: SelectableText(
                        info['preview'] as String? ?? '',
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                        ),
                      ),
                    ),
                  )
                else if (info['type'] == 'binary')
                  Text('Binary file\nHex: ${info['hexPreview'] ?? 'N/A'}',
                      style: const TextStyle(
                          fontFamily: 'monospace', fontSize: 11))
                else
                  Text('${info['type'] ?? 'Cannot preview'}'),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: entry.path));
              Navigator.of(ctx).pop();
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text('Path copied: ${entry.path}')),
              );
            },
            child: const Text('Copy Path'),
          ),
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024)
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final displayEntries = _searchResults ?? _entries;

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Lucide.ArrowLeft),
          onPressed: () => Navigator.of(context).pop(),
        ),
        title: Text(
          _currentPath == '/' ? 'Root' : _currentPath.split('/').last,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        actions: [
          IconButton(
            icon: Icon(_showHidden ? Lucide.Eye : Lucide.EyeOff),
            tooltip: 'Toggle hidden files',
            onPressed: () {
              _showHidden = !_showHidden;
              _loadDirectory();
            },
          ),
          PopupMenuButton<String>(
            icon: const Icon(Lucide.Settings2),
            onSelected: (v) {
              _sortBy = v;
              _loadDirectory();
            },
            itemBuilder: (ctx) => [
              const PopupMenuItem(value: 'name', child: Text('Sort by Name')),
              const PopupMenuItem(value: 'size', child: Text('Sort by Size')),
              const PopupMenuItem(
                  value: 'modified', child: Text('Sort by Modified')),
            ],
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(52),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 0, 12, 8),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _searchController,
                    decoration: InputDecoration(
                      hintText: 'Search in this folder...',
                      prefixIcon: const Icon(Lucide.Search, size: 18),
                      isDense: true,
                      suffixIcon: _searchController.text.isNotEmpty
                          ? IconButton(
                              icon: const Icon(Lucide.X, size: 16),
                              onPressed: () {
                                _searchController.clear();
                                _performSearch('');
                              },
                            )
                          : null,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    onSubmitted: _performSearch,
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  icon: const Icon(Lucide.ArrowUp),
                  onPressed: _goUp,
                  tooltip: 'Go up',
                ),
              ],
            ),
          ),
        ),
      ),
      body: Column(
        children: [
          // Breadcrumb / current path
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            color: cs.surfaceContainerHighest.withValues(alpha: 0.3),
            child: GestureDetector(
              onTap: () {
                Clipboard.setData(ClipboardData(text: _currentPath));
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text('Copied: $_currentPath')),
                );
              },
              child: Text(
                _currentPath,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 12,
                  color: cs.onSurface.withValues(alpha: 0.6),
                  fontFamily: 'monospace',
                ),
              ),
            ),
          ),
          // Quick access paths
          SizedBox(
            height: 40,
            child: ListView(
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.symmetric(horizontal: 8),
              children: DeviceKnownPaths.commonPaths.entries.map((e) {
                return TextButton(
                  onPressed: () => _navigateTo(e.value),
                  child: Text(e.key, style: const TextStyle(fontSize: 12)),
                );
              }).toList(),
            ),
          ),
          const Divider(height: 1),
          // File list
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _searching
                    ? const Center(child: Text('Searching...'))
                    : displayEntries.isEmpty
                        ? Center(
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(Lucide.FolderOpen,
                                    size: 48, color: cs.outline),
                                const SizedBox(height: 8),
                                Text('Empty or inaccessible',
                                    style: TextStyle(color: cs.outline)),
                              ],
                            ),
                          )
                        : ListView.builder(
                            itemCount: displayEntries.length,
                            itemBuilder: (ctx, i) {
                              final e = displayEntries[i];
                              return ListTile(
                                leading: Icon(
                                  e.isDirectory
                                      ? Lucide.Folder
                                      : _fileIcon(e.name),
                                  color: e.isDirectory
                                      ? cs.primary
                                      : cs.onSurface.withValues(alpha: 0.5),
                                  size: 22,
                                ),
                                title: Text(
                                  e.name,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                                subtitle: e.isDirectory
                                    ? null
                                    : Text(
                                        _formatBytes(e.sizeBytes ?? 0),
                                        style: TextStyle(
                                            fontSize: 12, color: cs.outline),
                                      ),
                                trailing: e.isDirectory
                                    ? const Icon(Lucide.ChevronRight, size: 18)
                                    : null,
                                onTap: () {
                                  if (e.isDirectory) {
                                    _navigateTo(e.path);
                                  } else {
                                    _previewFile(e);
                                  }
                                },
                                onLongPress: () {
                                  Clipboard.setData(
                                      ClipboardData(text: e.path));
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(content: Text('Copied: ${e.path}')),
                                  );
                                },
                              );
                            },
                          ),
          ),
        ],
      ),
    );
  }

  IconData _fileIcon(String name) {
    final ext = name.split('.').last.toLowerCase();
    switch (ext) {
      case 'png':
      case 'jpg':
      case 'jpeg':
      case 'gif':
      case 'webp':
      case 'heic':
        return Lucide.Image;
      case 'mp4':
      case 'avi':
      case 'mkv':
      case 'mov':
        return Lucide.Camera;
      case 'mp3':
      case 'wav':
      case 'flac':
        return Lucide.Volume2;
      case 'pdf':
        return Lucide.FileText;
      case 'zip':
      case 'rar':
      case '7z':
      case 'tar':
      case 'gz':
        return Lucide.Package;
      case 'apk':
      case 'dex':
        return Lucide.Box;
      case 'dart':
      case 'py':
      case 'java':
      case 'kt':
      case 'js':
      case 'ts':
      case 'go':
      case 'rs':
      case 'c':
      case 'cpp':
        return Lucide.Code;
      default:
        return Lucide.FileText;
    }
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }
}