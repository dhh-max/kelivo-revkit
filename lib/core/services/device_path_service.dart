import 'dart:io';
import 'package:path/path.dart' as p;

/// Represents a file system entry on the device.
class DevicePathEntry {
  final String path;
  final String name;
  final bool isDirectory;
  final int? sizeBytes;
  final DateTime? modified;

  const DevicePathEntry({
    required this.path,
    required this.name,
    required this.isDirectory,
    this.sizeBytes,
    this.modified,
  });

  Map<String, dynamic> toJson() => {
    'path': path,
    'name': name,
    'isDirectory': isDirectory,
    'sizeBytes': sizeBytes,
    'modified': modified?.toIso8601String(),
  };
}

/// Known device storage root paths for Android.
class DeviceKnownPaths {
  static const String internalStorage = '/sdcard';
  static const String root = '/';
  static const String data = '/data';
  static const String system = '/system';
  static const String storage = '/storage';

  /// Common user-accessible directories.
  static const Map<String, String> commonPaths = {
    'Internal Storage': '/sdcard',
    'Downloads': '/sdcard/Download',
    'DCIM': '/sdcard/DCIM',
    'Pictures': '/sdcard/Pictures',
    'Music': '/sdcard/Music',
    'Movies': '/sdcard/Movies',
    'Documents': '/sdcard/Documents',
    'Android/data': '/sdcard/Android/data',
    'Android/obb': '/sdcard/Android/obb',
  };

  /// System directories (may require root).
  static const Map<String, String> systemPaths = {
    'Root': '/',
    'System': '/system',
    'Data': '/data',
    'Storage': '/storage',
    'Vendor': '/vendor',
    'Proc': '/proc',
    'Tmp': '/tmp',
  };
}

/// Service for browsing device file system paths.
///
/// Provides listing, searching, and preview capabilities
/// separate from workspace/project paths.
class DevicePathService {
  /// List entries in a directory.
  ///
  /// [showHidden] whether to include dot-prefixed entries.
  /// [sortBy] can be 'name', 'size', 'modified'.
  static Future<List<DevicePathEntry>> listDirectory(
    String dirPath, {
    bool showHidden = false,
    String sortBy = 'name',
    bool dirsFirst = true,
  }) async {
    final dir = Directory(dirPath);
    if (!await dir.exists()) return [];

    final entries = <DevicePathEntry>[];
    try {
      await for (final entity in dir.list(followLinks: false)) {
        final name = p.basename(entity.path);
        if (!showHidden && name.startsWith('.')) continue;

        final isDir = entity is Directory;
        int? size;
        DateTime? modified;

        try {
          final stat = await entity.stat();
          size = isDir ? null : stat.size;
          modified = stat.modified;
        } catch (_) {}

        entries.add(DevicePathEntry(
          path: entity.path,
          name: name,
          isDirectory: isDir,
          sizeBytes: size,
          modified: modified,
        ));
      }
    } catch (_) {
      // Permission denied or other IO error
      return [];
    }

    // Sort
    entries.sort((a, b) {
      if (dirsFirst && a.isDirectory != b.isDirectory) {
        return a.isDirectory ? -1 : 1;
      }
      switch (sortBy) {
        case 'size':
          return (a.sizeBytes ?? 0).compareTo(b.sizeBytes ?? 0);
        case 'modified':
          return (b.modified ?? DateTime(0)).compareTo(a.modified ?? DateTime(0));
        default:
          return a.name.toLowerCase().compareTo(b.name.toLowerCase());
      }
    });

    return entries;
  }

  /// Search files recursively by name pattern.
  static Future<List<DevicePathEntry>> searchFiles(
    String rootPath, {
    required String pattern,
    int maxResults = 100,
    int maxDepth = 5,
    bool caseSensitive = false,
  }) async {
    final results = <DevicePathEntry>[];
    final regex = RegExp(
      _globToRegex(pattern),
      caseSensitive: caseSensitive,
    );

    await _searchRecursive(
      Directory(rootPath),
      regex,
      results,
      maxResults,
      maxDepth,
      0,
    );

    return results;
  }

  static Future<void> _searchRecursive(
    Directory dir,
    RegExp pattern,
    List<DevicePathEntry> results,
    int maxResults,
    int maxDepth,
    int currentDepth,
  ) async {
    if (results.length >= maxResults) return;
    if (currentDepth > maxDepth) return;

    try {
      await for (final entity in dir.list(followLinks: false)) {
        if (results.length >= maxResults) return;

        final name = p.basename(entity.path);
        if (pattern.hasMatch(name)) {
          final isDir = entity is Directory;
          int? size;
          DateTime? modified;
          try {
            final stat = await entity.stat();
            size = isDir ? null : stat.size;
            modified = stat.modified;
          } catch (_) {}

          results.add(DevicePathEntry(
            path: entity.path,
            name: name,
            isDirectory: isDir,
            sizeBytes: size,
            modified: modified,
          ));
        }

        if (entity is Directory) {
          await _searchRecursive(
            entity, pattern, results, maxResults, maxDepth, currentDepth + 1,
          );
        }
      }
    } catch (_) {
      // Permission denied — skip
    }
  }

  /// Get file preview info (first N bytes for text, metadata for binary).
  static Future<Map<String, dynamic>> previewFile(
    String filePath, {
    int maxBytes = 4096,
  }) async {
    final file = File(filePath);
    if (!await file.exists()) {
      return {'error': 'File not found', 'path': filePath};
    }

    final stat = await file.stat();
    final ext = p.extension(filePath).toLowerCase();
    final result = <String, dynamic>{
      'path': filePath,
      'name': p.basename(filePath),
      'size': stat.size,
      'modified': stat.modified.toIso8601String(),
      'extension': ext,
    };

    // Determine if likely text
    const textExts = {
      '.txt', '.md', '.json', '.xml', '.html', '.yml', '.yaml',
      '.dart', '.py', '.java', '.kt', '.js', '.ts', '.c', '.h',
      '.cpp', '.go', '.rs', '.rb', '.sh', '.bat', '.log', '.csv',
      '.toml', '.ini', '.cfg', '.conf', '.properties', '.smali',
      '.sql', '.proto', '.gradle',
    };

    if (textExts.contains(ext) || stat.size < maxBytes) {
      try {
        final bytes = await file.openRead(0, maxBytes.clamp(0, stat.size)).fold<List<int>>(
          [],
          (prev, chunk) => prev..addAll(chunk),
        );
        // Check if content is valid UTF-8
        try {
          final text = String.fromCharCodes(bytes);
          result['type'] = 'text';
          result['preview'] = text;
        } catch (_) {
          result['type'] = 'binary';
          result['hexPreview'] = bytes.take(64).map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
        }
      } catch (_) {
        result['type'] = 'unreadable';
      }
    } else {
      result['type'] = 'binary';
    }

    return result;
  }

  /// Get storage info for a path (total/used/free space).
  static Future<Map<String, int?>> getStorageInfo(String path) async {
    // On Android, we can try reading from statfs via ProcessResult
    try {
      final result = await Process.run('df', ['-B1', path]);
      if (result.exitCode == 0) {
        final lines = (result.stdout as String).split('\n');
        if (lines.length >= 2) {
          final parts = lines[1].split(RegExp(r'\s+'));
          if (parts.length >= 4) {
            return {
              'total': int.tryParse(parts[1]),
              'used': int.tryParse(parts[2]),
              'available': int.tryParse(parts[3]),
            };
          }
        }
      }
    } catch (_) {}
    return {'total': null, 'used': null, 'available': null};
  }

  /// Copy a file to a destination directory.
  static Future<bool> copyFile(String srcPath, String destDir) async {
    try {
      final srcFile = File(srcPath);
      if (!await srcFile.exists()) return false;
      final destPath = p.join(destDir, p.basename(srcPath));
      await srcFile.copy(destPath);
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Move a file or directory to a destination directory.
  static Future<bool> moveEntry(String srcPath, String destDir) async {
    try {
      final destPath = p.join(destDir, p.basename(srcPath));
      final srcFile = File(srcPath);
      final srcDir = Directory(srcPath);
      if (await srcFile.exists()) {
        await srcFile.rename(destPath);
        return true;
      } else if (await srcDir.exists()) {
        await srcDir.rename(destPath);
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  /// Delete a file or directory.
  static Future<bool> deleteEntry(String path) async {
    try {
      final file = File(path);
      if (await file.exists()) {
        await file.delete();
        return true;
      }
      final dir = Directory(path);
      if (await dir.exists()) {
        await dir.delete(recursive: true);
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  /// Rename a file or directory (same directory, new name).
  static Future<bool> renameEntry(String srcPath, String newName) async {
    try {
      final destPath = p.join(p.dirname(srcPath), newName);
      final file = File(srcPath);
      if (await file.exists()) {
        await file.rename(destPath);
        return true;
      }
      final dir = Directory(srcPath);
      if (await dir.exists()) {
        await dir.rename(destPath);
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  /// Check if a file is an image by extension.
  static bool isImageFile(String path) {
    final ext = p.extension(path).toLowerCase();
    return const {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.heic'}
        .contains(ext);
  }

  /// Get image dimensions without loading full image.
  static Future<Map<String, int?>?> getImageDimensions(String path) async {
    if (!isImageFile(path)) return null;
    try {
      final bytes = await File(path).readAsBytes();
      // Decode header to get dimensions
      // PNG: width at bytes 16-19, height at 20-23 (big endian)
      // JPEG: parse SOF marker
      // GIF: width at 6-7, height at 8-9 (little endian)
      // WebP: parse VP8/VP8L/VP8X headers
      if (bytes.length < 16) return null;

      final ext = p.extension(path).toLowerCase();
      int? width, height;

      if (ext == '.png' && bytes.length >= 24) {
        width = (bytes[16] << 24) | (bytes[17] << 16) | (bytes[18] << 8) | bytes[19];
        height = (bytes[20] << 24) | (bytes[21] << 16) | (bytes[22] << 8) | bytes[23];
      } else if (ext == '.gif' && bytes.length >= 10) {
        width = bytes[6] | (bytes[7] << 8);
        height = bytes[8] | (bytes[9] << 8);
      } else if (ext == '.jpg' || ext == '.jpeg') {
        // Find SOF0 (0xFFC0) or SOF2 (0xFFC2) marker
        int i = 2; // Skip SOI marker
        while (i < bytes.length - 9) {
          if (bytes[i] != 0xFF) {
            i++;
            continue;
          }
          final marker = bytes[i + 1];
          if (marker == 0xC0 || marker == 0xC2) {
            height = (bytes[i + 5] << 8) | bytes[i + 6];
            width = (bytes[i + 7] << 8) | bytes[i + 8];
            break;
          }
          // Skip this marker segment
          final segLen = (bytes[i + 2] << 8) | bytes[i + 3];
          i += 2 + segLen;
        }
      } else if (ext == '.webp' && bytes.length >= 30) {
        // Check for RIFF header
        if (bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46) {
          final chunkType = String.fromCharCodes(bytes.sublist(12, 16));
          if (chunkType == 'VP8 ' && bytes.length >= 30) {
            width = (bytes[26] | (bytes[27] << 8)) & 0x3FFF;
            height = (bytes[28] | (bytes[29] << 8)) & 0x3FFF;
          } else if (chunkType == 'VP8L' && bytes.length >= 25) {
            final b = bytes[21];
            width = 1 + ((bytes[22] | ((bytes[23] & 0x3F) << 8)));
            height = 1 + (((bytes[23] >> 6) | (bytes[24] << 2) | ((bytes[25] & 0x0F) << 10)));
          }
        }
      }

      if (width != null && height != null) {
        return {'width': width, 'height': height};
      }
    } catch (_) {}
    return null;
  }

  /// Get APK basic info (package name, version) via aapt if available.
  static Future<Map<String, String?>> getApkInfo(String path) async {
    try {
      final result = await Process.run('aapt', ['dump', 'badging', path]);
      if (result.exitCode == 0) {
        final output = result.stdout as String;
        String? package, versionName, appName;

        final pkgMatch = RegExp(r"package: name='([^']+)'").firstMatch(output);
        if (pkgMatch != null) package = pkgMatch.group(1);

        final verMatch = RegExp(r"versionName='([^']+)'").firstMatch(output);
        if (verMatch != null) versionName = verMatch.group(1);

        final appMatch = RegExp(r"application-label:'([^']+)'").firstMatch(output);
        if (appMatch != null) appName = appMatch.group(1);

        return {
          'package': package,
          'versionName': versionName,
          'appName': appName,
        };
      }
    } catch (_) {}
    return {};
  }

  /// Convert glob pattern to regex.
  static String _globToRegex(String glob) {
    final buf = StringBuffer('^');
    for (int i = 0; i < glob.length; i++) {
      final c = glob[i];
      switch (c) {
        case '*':
          buf.write('.*');
          break;
        case '?':
          buf.write('.');
          break;
        case '.':
        case '(':
        case ')':
        case '+':
        case '|':
        case '\\':
        case '\^':
        case '\$':
        case '{':
        case '}':
        case '[':
        case ']':
          buf.write('\\$c');
          break;
        default:
          buf.write(c);
      }
    }
    buf.write(r'$');
    return buf.toString();
  }
}