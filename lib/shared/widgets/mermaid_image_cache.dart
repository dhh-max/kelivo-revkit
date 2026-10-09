import 'dart:typed_data';

import '../cache/byte_lru_cache.dart';

/// 图表源码的唯一归一化口径（CRLF / 裸 CR 一律折成 LF，再去首尾空白）。
///
/// 缓存键与主题键必须共用它：此前主题键把裸 CR 折成 LF、缓存键只处理 CRLF，
/// 同一段代码（例如 Windows 粘贴的 `graph TD\rA-->B`）会算出两个不同的键，
/// 于是重复光栅化、内存里留两份位图，且两条键族永远互相查不到。
String normalizeDiagramSource(String code) =>
    code.replaceAll('\r\n', '\n').replaceAll('\r', '\n').trim();

String diagramImageCacheKey(
  String code,
  bool isDark,
  Map<String, String> themeVars, {
  bool isSvg = false,
}) {
  final entries = themeVars.entries.toList()
    ..sort((a, b) => a.key.compareTo(b.key));
  final themeSig = entries.map((e) => '${e.key}=${e.value}').join('&');
  final source = normalizeDiagramSource(code);
  return '${isDark ? 'dark' : 'light'}|$themeSig|${isSvg ? 'svg\n' : ''}$source';
}

class MermaidImageCache {
  static int _maxBytes = 24 << 20;
  static ByteLruCache<String, Uint8List> _cache = _newCache();

  static ByteLruCache<String, Uint8List> _newCache() => ByteLruCache(
    maxBytes: _maxBytes,
    sizeOf: (key, value) => key.length * 2 + value.lengthInBytes,
  );

  static String _normalize(String code) => normalizeDiagramSource(code);

  static void configure({int? maxBytes, int? maxSize}) {
    final requested = maxBytes ?? (maxSize == null ? null : maxSize * 200000);
    if (requested == null || requested <= 0 || requested == _maxBytes) return;
    _maxBytes = requested;
    _cache = _newCache();
  }

  static Uint8List? get(String code) => _cache.get(_normalize(code));

  static void put(String code, Uint8List bytes) {
    final key = _normalize(code);
    _cache.put(key, bytes);
  }

  static int get bytes => _cache.bytes;
  static int get evictions => _cache.evictions;

  static void clear() => _cache.clear();
}
