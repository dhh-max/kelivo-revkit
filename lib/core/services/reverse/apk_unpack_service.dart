import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:archive/archive.dart';

/// APK 解包服务，纯逻辑无外部依赖
class ApkUnpackService {
  const ApkUnpackService._();

  /// 从字节流解析 APK 结构
  static ApkInfo parse(Uint8List bytes) {
    final archive = ZipDecoder().decodeBytes(bytes);
    final entries = <ApkEntry>[];

    for (final f in archive) {
      if (f.isFile) {
        Uint8List? content;
        try {
          content = f.content as Uint8List?;
        } catch (_) {}
        entries.add(ApkEntry(
          name: f.name,
          size: f.size,
          content: content,
        ));
      }
    }

    return ApkInfo(entries: entries);
  }

  /// 从文件路径加载并解析 APK
  static Future<ApkInfo> fromFile(String path) async {
    final file = File(path);
    if (!await file.exists()) {
      throw ArgumentError('File not found: $path');
    }
    final bytes = await file.readAsBytes();
    return parse(bytes);
  }

  /// 过滤指定后缀的文件
  static List<ApkEntry> filterByExtension(ApkInfo apk, String extension) {
    return apk.entries.where((e) => e.name.endsWith(extension)).toList();
  }

  /// 提取 AndroidManifest.xml 摘要
  static String? extractManifestSummary(ApkInfo apk) {
    final entry = apk.entries.cast<ApkEntry?>().firstWhere(
          (e) => e!.name == 'AndroidManifest.xml',
          orElse: () => null,
        );
    if (entry == null || entry.content == null) return null;

    try {
      final text = _extractTextFromBytes(entry.content!);
      final sb = StringBuffer();

      for (final line in text.split('\n')) {
        final t = line.trim();
        if (t.contains('package=')) sb.writeln(t);
        if (t.contains('android:name=')) sb.writeln(t);
        if (t.contains('android:permission') || t.contains('.permission.')) sb.writeln(t);
        if (t.contains('action android:name=') || t.contains('category android:name=')) sb.writeln(t);
        if (t.contains('android:exported=')) sb.writeln(t);
        if (t.contains('android:launchMode=')) sb.writeln(t);
      }

      final result = sb.toString().trim();
      return result.isNotEmpty ? result : '(manifest extracted ${entry.content!.length} bytes, but no structured fields found)';
    } catch (_) {
      return '(binary/AXML, raw size: ${entry.content!.length} bytes)';
    }
  }

  /// 从二进制中提取可读文本片段
  static String _extractTextFromBytes(Uint8List bytes, {int maxLength = 4096}) {
    final sb = StringBuffer();
    for (var i = 0; i < bytes.length && sb.length < maxLength; i++) {
      final c = bytes[i];
      if (c >= 0x20 && c < 0x7f) {
        sb.writeCharCode(c);
      } else if (c == 0x0a || c == 0x0d || c == 0x09) {
        sb.writeCharCode(c);
      }
    }
    return sb.toString();
  }
}

/// APK 元信息
class ApkInfo {
  final List<ApkEntry> entries;

  const ApkInfo({required this.entries});

  List<ApkEntry> get dexFiles => ApkUnpackService.filterByExtension(this, '.dex');
  List<ApkEntry> get nativeLibs => ApkUnpackService.filterByExtension(this, '.so');
  ApkEntry? get manifest => entries.firstWhere((e) => e.name == 'AndroidManifest.xml', orElse: () => ApkEntry(name: '', size: 0, content: null));
  String? get manifestSummary => ApkUnpackService.extractManifestSummary(this);
}

/// APK 内部文件条目
class ApkEntry {
  final String name;
  final int size;
  final Uint8List? content;

  const ApkEntry({
    required this.name,
    required this.size,
    required this.content,
  });

  String get extension => name.split('.').last.toLowerCase();
  String? get abi {
    final parts = name.split('/');
    return parts.length > 2 ? parts[parts.length - 2] : null;
  }
}