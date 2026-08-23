part of kelivo_reverse_server;

// =========================================================================
// APK 文件级操作 — 直接在 ZIP/APK 存档层面增删改文件，不依赖解包
// 移植自 Python apk_reverse_engine/core/apk_file_ops.py
// =========================================================================

class _ApkFileOps {
  /// 列出 APK 内所有文件路径（可选正则过滤）
  static List<String> listFiles(Uint8List apkBytes, {String? pattern}) {
    final archive = ZipDecoder().decodeBytes(apkBytes);
    final names = <String>[
      for (final f in archive)
        if (f.isFile) f.name
    ];
    if (pattern != null && pattern.isNotEmpty) {
      final re = RegExp(pattern);
      return names.where((n) => re.hasMatch(n)).toList();
    }
    return names;
  }

  /// 从 APK 中删除指定文件，输出新 APK
  static Map<String, dynamic> deleteFiles(
      Uint8List apkBytes, List<String> filePaths, String outputPath) async {
    final fileSet = filePaths.toSet();
    final srcArchive = ZipDecoder().decodeBytes(apkBytes);
    final archive = Archive();
    final deleted = <String>[];
    final notFound = <String>[];

    for (final f in srcArchive) {
      if (!f.isFile) continue;
      if (fileSet.contains(f.name)) {
        deleted.add(f.name);
      } else {
        archive.addFile(f);
        notFound.remove(f.name);
      }
    }
    for (final fp in fileSet) {
      if (!deleted.contains(fp)) notFound.add(fp);
    }

    final outBytes = ZipEncoder().encode(archive);
    if (outBytes == null) {
      return {'error': 'Failed to create APK'};
    }
    await File(outputPath).writeAsBytes(outBytes);
    return {
      'deleted': deleted,
      'not_found': notFound,
      'output': outputPath,
    };
  }

  /// 从 APK 中按正则匹配删除文件
  static Future<Map<String, dynamic>> deleteFilesByPattern(
      Uint8List apkBytes, String pattern, String outputPath) async {
    final re = RegExp(pattern);
    final srcArchive = ZipDecoder().decodeBytes(apkBytes);
    final archive = Archive();
    final deleted = <String>[];

    for (final f in srcArchive) {
      if (!f.isFile) continue;
      if (re.hasMatch(f.name)) {
        deleted.add(f.name);
      } else {
        archive.addFile(f);
      }
    }

    final outBytes = ZipEncoder().encode(archive);
    if (outBytes == null) {
      return {'error': 'Failed to create APK'};
    }
    await File(outputPath).writeAsBytes(outBytes);
    return {
      'deleted': deleted,
      'matched': deleted.length,
      'output': outputPath,
    };
  }

  /// 更新 APK 中指定文件的内容
  static Future<Map<String, dynamic>> updateFile(
      Uint8List apkBytes, String filePath, Uint8List data, String outputPath) async {
    final srcArchive = ZipDecoder().decodeBytes(apkBytes);
    final archive = Archive();
    var replaced = false;

    for (final f in srcArchive) {
      if (!f.isFile) continue;
      if (f.name == filePath) {
        archive.addFile(ArchiveFile(filePath, data.length, data));
        replaced = true;
      } else {
        archive.addFile(f);
      }
    }

    final outBytes = ZipEncoder().encode(archive);
    if (outBytes == null) {
      return {'error': 'Failed to create APK'};
    }
    await File(outputPath).writeAsBytes(outBytes);
    return {
      'updated': replaced ? filePath : null,
      'output': outputPath,
    };
  }

  /// 向 APK 中添加新文件（若已存在则覆盖）
  static Future<Map<String, dynamic>> addFile(
      Uint8List apkBytes, String filePath, Uint8List data, String outputPath) async {
    final srcArchive = ZipDecoder().decodeBytes(apkBytes);
    final archive = Archive();
    var overwritten = false;

    for (final f in srcArchive) {
      if (!f.isFile) continue;
      if (f.name == filePath) {
        archive.addFile(ArchiveFile(filePath, data.length, data));
        overwritten = true;
      } else {
        archive.addFile(f);
      }
    }
    if (!overwritten) {
      archive.addFile(ArchiveFile(filePath, data.length, data));
    }

    final outBytes = ZipEncoder().encode(archive);
    if (outBytes == null) {
      return {'error': 'Failed to create APK'};
    }
    await File(outputPath).writeAsBytes(outBytes);
    return {
      'added': filePath,
      'output': outputPath,
      'was_overwrite': overwritten,
    };
  }

  /// 批量向 APK 中添加/更新文件
  static Future<Map<String, dynamic>> addFilesBulk(
      Uint8List apkBytes, Map<String, Uint8List> fileEntries,
      String outputPath, {bool overwrite = true}) async {
    final srcArchive = ZipDecoder().decodeBytes(apkBytes);
    final archive = Archive();
    final existing = <String>{};
    final added = <String>[];
    final skipped = <String>[];

    for (final f in srcArchive) {
      if (!f.isFile) continue;
      existing.add(f.name);
      if (fileEntries.containsKey(f.name)) {
        if (overwrite) {
          archive.addFile(ArchiveFile(f.name, fileEntries[f.name]!.length,
              fileEntries[f.name]!));
          added.add(f.name);
        } else {
          archive.addFile(f);
          skipped.add(f.name);
        }
      } else {
        archive.addFile(f);
      }
    }
    for (final entry in fileEntries.entries) {
      if (!existing.contains(entry.key)) {
        archive.addFile(ArchiveFile(entry.key, entry.value.length, entry.value));
        added.add(entry.key);
      }
    }

    final outBytes = ZipEncoder().encode(archive);
    if (outBytes == null) {
      return {'error': 'Failed to create APK'};
    }
    await File(outputPath).writeAsBytes(outBytes);
    return {
      'added': added,
      'skipped': skipped,
      'output': outputPath,
    };
  }

  /// 提取 APK 内所有文件到指定目录
  static Future<Map<String, dynamic>> extractAll(
      Uint8List apkBytes, String outputDir,
      {String? pattern, bool parallel = false, bool incremental = false}) async {
    final archive = ZipDecoder().decodeBytes(apkBytes);
    final dir = Directory(outputDir);
    await dir.create(recursive: true);
    final re = (pattern != null && pattern.isNotEmpty) ? RegExp(pattern) : null;
    final extracted = <String>[];
    var totalSize = 0;

    for (final f in archive) {
      if (!f.isFile) continue;
      if (re != null && !re.hasMatch(f.name)) continue;
      final outPath = '${outputDir.endsWith('/') ? outputDir : '$outputDir/'}${f.name}';
      final outFile = File(outPath);
      await outFile.parent.create(recursive: true);
      if (incremental && await outFile.exists()) continue;
      final content = f.content;
      if (content is Uint8List) {
        await outFile.writeAsBytes(content);
        totalSize += content.length;
      }
      extracted.add(f.name);
    }

    return {
      'extracted': extracted.length,
      'files': extracted.take(100).toList(),
      'total_size': totalSize,
      'output_dir': outputDir,
    };
  }

  /// 提取 APK 内指定文件
  static Future<Map<String, dynamic>> extractFile(
      Uint8List apkBytes, String filePath, String outputPath) async {
    final archive = ZipDecoder().decodeBytes(apkBytes);
    for (final f in archive) {
      if (f.isFile && f.name == filePath) {
        final content = f.content;
        if (content is Uint8List) {
          await File(outputPath).writeAsBytes(content);
          return {
            'extracted': filePath,
            'size': content.length,
            'output': outputPath,
          };
        }
      }
    }
    return {'error': 'File not found in APK: $filePath'};
  }
}
