import 'dart:io';
import 'package:http/http.dart' as http;
import './app_directories.dart';

class AvatarCache {
  AvatarCache._();

  /// 内存 memo 只是"少一次 stat / 少一次下载"的加速表，真相在磁盘缓存目录里。
  /// 此前它是只增不减的静态 Map（只随见过的 URL 增长），头像/头部图换得多了
  /// 就是一条常驻进程、永不回收的泄漏；这里给一个上限，超出按最久未用逐出
  /// （只逐出内存记录，磁盘文件不动，下次命中会从磁盘重新解析）。
  static const int maxMemoEntries = 256;

  /// 插入序即最近使用序：Dart 的 Map 字面量是 LinkedHashMap，
  /// [_remember] 先 remove 再写回，于是 keys.first 恒为最久未用。
  static final Map<String, String?> _memo = <String, String?>{};

  /// 供测试断言内存表规模；生产代码不应依赖这个数字。
  static int get memoEntryCount => _memo.length;

  static void _remember(String url, String? path) {
    _memo.remove(url);
    _memo[url] = path;
    while (_memo.length > maxMemoEntries) {
      _memo.remove(_memo.keys.first);
    }
  }

  static void clearMemory() {
    _memo.clear();
  }

  static Future<Directory> _cacheDir() async {
    return await AppDirectories.getAvatarCacheDirectory();
  }

  static String _safeName(String url) {
    // Use 64-bit FNV-1a hash to avoid collisions from common URL prefixes
    int h = 0xcbf29ce484222325; // FNV offset basis
    const int prime = 0x100000001b3; // FNV prime
    for (final c in url.codeUnits) {
      h ^= c;
      h = (h * prime) & 0xFFFFFFFFFFFFFFFF; // keep 64-bit
    }
    final hex = h.toRadixString(16).padLeft(16, '0');
    // Attempt to keep a reasonable extension (may help some platforms)
    final uri = Uri.tryParse(url);
    String ext = 'img';
    if (uri != null) {
      final seg = uri.pathSegments.isNotEmpty
          ? uri.pathSegments.last.toLowerCase()
          : '';
      final m = RegExp(
        r"\.(png|jpg|jpeg|webp|gif|bmp|ico|svg)",
      ).firstMatch(seg);
      if (m != null) ext = m.group(1)!;
    }
    return 'av_$hex.$ext';
  }

  /// Synchronous cache peek: returns the locally cached file path for [url]
  /// only if it is already memoized and the file still exists on disk.
  /// Returns null when not yet resolved (caller should fall back to [getPath]).
  static String? peek(String url) {
    if (url.isEmpty) return null;
    final cached = _memo[url];
    if (cached == null) return null;
    try {
      if (File(cached).existsSync()) {
        _remember(url, cached);
        return cached;
      }
    } catch (_) {}
    return null;
  }

  /// Ensures avatar at [url] is cached locally and returns the file path.
  /// On failure, returns null.
  static Future<String?> getPath(String url) async {
    if (url.isEmpty) return null;
    if (_memo.containsKey(url)) {
      final cached = _memo[url];
      if (cached == null) return null;
      try {
        final f = File(cached);
        if (await f.exists()) return cached;
      } catch (_) {}
      // Stale entry: file was deleted; re-resolve.
      _memo.remove(url);
    }
    try {
      final dir = await _cacheDir();
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }
      final name = _safeName(url);
      final file = File('${dir.path}/$name');
      if (await file.exists()) {
        _remember(url, file.path);
        return file.path;
      }
      // Download and save
      final res = await http.get(Uri.parse(url));
      if (res.statusCode >= 200 && res.statusCode < 300) {
        await file.writeAsBytes(res.bodyBytes, flush: true);
        _remember(url, file.path);
        return file.path;
      }
    } catch (_) {}
    _remember(url, null);
    return null;
  }

  static Future<void> evict(String url) async {
    try {
      final dir = await _cacheDir();
      if (!await dir.exists()) return;
      final name = _safeName(url);
      final file = File('${dir.path}/$name');
      if (await file.exists()) await file.delete();
    } catch (_) {}
    _memo.remove(url);
  }
}
