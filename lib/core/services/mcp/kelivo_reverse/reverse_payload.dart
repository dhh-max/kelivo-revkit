part of kelivo_reverse_server;

// ---------------------------------------------------------------------------
// Payload: path or base64
// ---------------------------------------------------------------------------

class KelivoReverseRequestPayload {
  final Uint8List apkBytes;
  final String? apkPath;
  final int limit;
  final int minLength;

  KelivoReverseRequestPayload({
    required this.apkBytes,
    this.apkPath,
    this.limit = 1000,
    this.minLength = 4,
  });

  static Future<KelivoReverseRequestPayload> parse(Object? args) async {
    if (args is! Map) {
      throw ArgumentError('Invalid arguments: expected object with path|base64');
    }
    final map = args.cast<String, dynamic>();
    final int limit = _asInt(map['limit'], 1000).clamp(1, 100000) as int;
    final int minLength = _asInt(map['min_length'], 4).clamp(1, 256) as int;

    final b64 = (map['base64'] ?? '').toString().trim();
    if (b64.isNotEmpty) {
      final bytes = base64Decode(b64);
      return KelivoReverseRequestPayload(
        apkBytes: bytes, limit: limit, minLength: minLength,
      );
    }

    final path = (map['path'] ?? '').toString().trim();
    if (path.isEmpty) {
      throw ArgumentError('Missing "path" or "base64"');
    }
    final file = File(path);
    if (!await file.exists()) {
      throw ArgumentError('File not found: $path');
    }
    final bytes = await file.readAsBytes();
    return KelivoReverseRequestPayload(
      apkBytes: bytes, apkPath: path, limit: limit, minLength: minLength,
    );
  }

  static int _asInt(Object? v, int fallback) {
    if (v is int) return v;
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v.trim()) ?? fallback;
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// APK reader helpers
// ---------------------------------------------------------------------------

_ApkInfo _readApk(Uint8List bytes) {
  final archive = ZipDecoder().decodeBytes(bytes);
  final entries = <_ApkEntry>[];
  for (final f in archive) {
    if (f.isFile) {
      Uint8List? content;
      try {
        content = f.content as Uint8List?;
      } catch (_) {}
      entries.add(_ApkEntry(f.name, f.size, f.size, content));
    }
  }
  return _ApkInfo(entries);
}

List<_ApkEntry> _filterEntries(_ApkInfo apk, String pattern) {
  return apk.entries.where((e) => e.name.contains(pattern)).toList();
}

String? _findManifestXmlContent(_ApkInfo apk) {
  final entry = apk.entries.cast<_ApkEntry?>().firstWhere(
    (e) => e!.name == 'AndroidManifest.xml',
    orElse: () => null,
  );
  if (entry == null) return null;
  try {
    // Attempt to decode as plain text (may fail for AXML; return partial)
    return utf8.decode(entry.content!, allowMalformed: true);
  } catch (_) {
    return '(binary/AXML, raw size: ${entry.size} bytes)';
  }
}

String _extractTextFromBytes(Uint8List bytes, {int maxLength = 4096}) {
  // Extract human-readable ASCII/UTF-8 fragments
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

// ---------------------------------------------------------------------------
// Manifest summary from AXML (heuristic extraction)
// ---------------------------------------------------------------------------

String _manifestSummary(dynamic manifestBytes) {
  if (manifestBytes == null || (manifestBytes is Uint8List && manifestBytes.isEmpty) || (manifestBytes is String && manifestBytes.isEmpty)) return '(no manifest)';
  final text = manifestBytes is String ? manifestBytes : _extractTextFromBytes(manifestBytes as Uint8List);
  // Heuristic extraction of common manifest fields
  final sb = StringBuffer();
  for (final line in text.split('\n')) {
    final t = line.trim();
    // Match package name
    if (t.contains('package=')) sb.writeln(t);
    // Match android:name components
    if (t.contains('android:name=')) sb.writeln(t);
    // Match permissions
    if (t.contains('android:permission') || t.contains('.permission.')) sb.writeln(t);
    // Match intent filters
    if (t.contains('action android:name=') || t.contains('category android:name=')) sb.writeln(t);
    // Match launch mode / exported
    if (t.contains('android:exported=')) sb.writeln(t);
    if (t.contains('android:launchMode=')) sb.writeln(t);
  }
  final result = sb.toString().trim();
  final sizeStr = manifestBytes is Uint8List ? manifestBytes.length : (manifestBytes is String ? manifestBytes.length : 0);
  return result.isNotEmpty ? result : '(manifest extracted $sizeStr bytes, but no structured fields found)';
  /// 从 APK 中提取 resources.arsc 的字节
  Uint8List? get arscBytes {
    final info = _readApk(apkBytes);
    final entry = info.entries.cast<_ApkEntry?>().firstWhere(
      (e) => e!.name == 'resources.arsc',
      orElse: () => null,
    );
    return entry?.content;
  }

  /// 从 APK 中提取指定 SO 文件的字节（默认取第一个 arm64-v8a 的 .so）
  Uint8List? get soBytes {
    final info = _readApk(apkBytes);
    final soEntries = _filterEntries(info, '.so');
    if (soEntries.isEmpty) return null;
    // 优先选 arm64-v8a 的
    final arm64 = soEntries.where((e) => e.name.contains('arm64'));
    return (arm64.isNotEmpty ? arm64.first : soEntries.first).content;
  }

}
