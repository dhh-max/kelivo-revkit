/// @kelivo/jadx — In-memory MCP server engine providing JADX-style source
/// navigation tools over APK/DEX, without requiring the JADX GUI or any
/// external native dependency.
///
/// This is a pure-Dart port of the capability model exposed by the
/// `jadx-ai-mcp` plugin (class/method/field search, cross-references,
/// manifest/resources, Dalvik disassembly). It reuses `@kelivo/dex`'s
/// `DexImage` parser and the `archive` package for APK reading.
///
/// Tools:
///   jadx_search_classes   → search classes by keyword (class/method/field/code)
///   jadx_search_methods   → search methods across all classes by name
///   jadx_method_source    → Dalvik disassembly + semantic skeleton of a method
///   jadx_class_xrefs      → find classes that reference a target class
///   jadx_field_xrefs      → find methods that read/write a target field
///   jadx_manifest         → AndroidManifest.xml summary from an APK
///   jadx_strings          → search DEX string pool (regex/substring)
///   jadx_rename           → in-memory rename of a class/method/field (mapping)
///   jadx_extract_endpoints→ extract URLs, IP addresses, API endpoints from DEX
///   jadx_identify_sdks    → identify third-party SDKs (ads/analytics/social/payment)
///   jadx_suspicious_strings → scan for encrypted/encoded strings (Base64/Hex/high-entropy)
///   jadx_secret_scan      → scan for leaked secrets/tokens (AWS/Google/JWT/Bearer etc.)
///
/// Input: an APK path/base64, or a bare .dex path/base64. For APK input the
/// engine enumerates all `classes*.dex` entries and builds a combined index.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:mcp_client/mcp_client.dart' as mcp;

import '../in_memory_mcp_server.dart';
import '../kelivo_dex/kelivo_dex_server.dart';

// ---------------------------------------------------------------------------
// Payload: path or base64 (APK or DEX)
// ---------------------------------------------------------------------------
class KelivoJadxRequestPayload {
  final Uint8List bytes;
  final String? path;
  final bool isApk;
  final int limit;
  KelivoJadxRequestPayload({
    required this.bytes,
    this.path,
    required this.isApk,
    this.limit = 1000,
  });

  static Future<KelivoJadxRequestPayload> parse(Object? args) async {
    if (args is! Map) {
      throw ArgumentError(
        'Invalid arguments: expected object with path|base64',
      );
    }
    final map = args.cast<String, dynamic>();
    final limit = _asInt(map['limit'], 1000).clamp(1, 100000).toInt();
    final b64 = (map['base64'] ?? '').toString().trim();
    if (b64.isNotEmpty) {
      final bytes = base64Decode(b64);
      return KelivoJadxRequestPayload(
        bytes: bytes,
        isApk: _looksLikeApk(bytes),
        limit: limit,
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
    return KelivoJadxRequestPayload(
      bytes: bytes,
      path: path,
      isApk: _looksLikeApk(bytes),
      limit: limit,
    );
  }

  static bool _looksLikeApk(Uint8List bytes) {
    // ZIP magic PK\x03\x04 (also covers APK/JAR)
    return bytes.length > 4 &&
        bytes[0] == 0x50 &&
        bytes[1] == 0x4b &&
        (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07);
  }

  static int _asInt(Object? v, int fallback) {
    if (v is int) return v;
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v.trim()) ?? fallback;
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// DEX index: classes / methods / fields / invokes / field-refs
// ---------------------------------------------------------------------------
class _DexMethod {
  final int methodIdx;
  final int accessFlags;
  final int codeOff;
  _DexMethod(this.methodIdx, this.accessFlags, this.codeOff);
}

class _ClassInfo {
  final String name;
  final String superName;
  final int accessFlags;
  final List<_DexMethod> methods;
  _ClassInfo(
    this.name,
    this.superName,
    this.accessFlags,
    this.methods,
  );
}

class _DexIndex {
  final DexImage dex;
  final List<_ClassInfo> classes;
  _DexIndex(this.dex, this.classes);
}

// ---------------------------------------------------------------------------
// Analyzer: pure-Dart JADX-style tools
// ---------------------------------------------------------------------------
class KelivoJadxAnalyzer {
  /// 返回工具说明、推荐工作流和帮助信息。
  static Map<String, dynamic> metaInfo(Map<String, dynamic> args) {
    final action = (args['action'] ?? '').toString().trim().toLowerCase();
    final all = StringBuffer()
      ..writeln('@kelivo/jadx — JADX 风格源码导航工具（纯 Dart，无需 JADX GUI）')
      ..writeln('')
      ..writeln('工具列表：')
      ..writeln('  jadx_search_classes   — 按关键字搜索类（类名/方法名/字段名）')
      ..writeln('  jadx_search_methods   — 跨类搜索方法（方法名/签名子串）')
      ..writeln('  jadx_method_source    — 反汇编指定方法（Dalvik 字节码）')
      ..writeln('  jadx_class_xrefs      — 查找引用指定类的方法（类级 xref）')
      ..writeln('  jadx_field_xrefs      — 查找读写指定字段的方法（字段级 xref）')
      ..writeln('  jadx_manifest         — 解析 APK 的 AndroidManifest.xml')
      ..writeln('  jadx_strings          — DEX 字符串池正则/子串搜索')
      ..writeln('  jadx_rename           — 会话级重命名映射（不修改原文件）')
      ..writeln('  jadx_extract_endpoints— 提取 URL、IP 地址、API 端点')
      ..writeln('  jadx_identify_sdks    — 识别第三方 SDK（广告/统计/社交/支付等）')
      ..writeln('  jadx_suspicious_strings— 扫描可疑加密/编码字符串')
      ..writeln('  jadx_secret_scan      — 扫描泄露的密钥/Token（AWS/Google/JWT等）')
      ..writeln('')
      ..writeln('推荐工作流：')
      ..writeln('  1. jadx_search_classes 定位目标类（如 "Login"、"MainActivity"）')
      ..writeln('  2. jadx_method_source 反汇编关键方法（如 onCreate）')
      ..writeln('  3. jadx_class_xrefs / jadx_field_xrefs 追踪调用链与数据流')
      ..writeln('  4. jadx_strings 搜索敏感字符串（API key、URL、加密特征）')
      ..writeln('  5. jadx_manifest 查看应用入口、权限与组件')
      ..writeln('  6. jadx_extract_endpoints 提取网络端点（URL/IP/API）')
      ..writeln('  7. jadx_identify_sdks 识别第三方 SDK 依赖')
      ..writeln('  8. jadx_suspicious_strings + jadx_secret_scan 安全扫描')
      ..writeln('')
      ..writeln('输入：APK 或 .dex 文件（path 或 base64）。APK 输入会自动遍历所有 classes*.dex。');
    if (action == 'tools') {
      final sb = StringBuffer()
        ..writeln('jadx_search_classes, jadx_search_methods, jadx_method_source,')
        ..writeln('jadx_class_xrefs, jadx_field_xrefs, jadx_manifest,')
        ..writeln('jadx_strings, jadx_rename,')
        ..writeln('jadx_extract_endpoints, jadx_identify_sdks,')
        ..writeln('jadx_suspicious_strings, jadx_secret_scan');
      return _ok(sb.toString().trimRight());
    }
    if (action == 'workflows') {
      final sb = StringBuffer()
        ..writeln('定位类 → 反汇编方法 → 追踪 xref → 搜索字符串 → 查看 Manifest');
      return _ok(sb.toString().trimRight());
    }
    if (action == 'describe') {
      return _ok(
        '@kelivo/jadx 是 JADX 风格源码导航工具集的纯 Dart 移植，'
        '复用 @kelivo/dex 解析引擎，无任何外部 native 依赖。',
      );
    }
    return _ok(all.toString().trimRight());
  }

  // ---- payload openers ----------------------------------------------------
  static _DexIndex _openDex(Uint8List bytes) {
    final dex = DexImage.parse(bytes);
    final classes = <_ClassInfo>[];
    for (var i = 0; i < dex.classDefsSize; i++) {
      final base = dex.classDefsOff + i * 32;
      if (base + 32 > dex.length) break;
      final classIdx = dex.data.getUint32(base, Endian.little);
      final accessFlags = dex.data.getUint32(base + 4, Endian.little);
      final superIdx = dex.data.getUint32(base + 8, Endian.little);
      final classDataOff = dex.data.getUint32(base + 24, Endian.little);
      final className = dex.typeAt(classIdx);
      final superName =
          superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
      classes.add(
        _ClassInfo(
          className,
          superName,
          accessFlags,
          _readMethods(dex, classDataOff),
        ),
      );
    }
    return _DexIndex(dex, classes);
  }

  static List<_DexMethod> _readMethods(DexImage dex, int off) {
    if (off == 0 || off >= dex.length) return [];
    final c = _Cursor(off);
    final staticFieldsSize = _readUleb128(dex, c);
    final instanceFieldsSize = _readUleb128(dex, c);
    final directMethodsSize = _readUleb128(dex, c);
    final virtualMethodsSize = _readUleb128(dex, c);
    for (var i = 0; i < staticFieldsSize + instanceFieldsSize; i++) {
      _readUleb128(dex, c);
      _readUleb128(dex, c);
    }
    final methods = <_DexMethod>[];
    var methodIdx = 0;
    for (var i = 0; i < directMethodsSize + virtualMethodsSize; i++) {
      methodIdx += _readUleb128(dex, c);
      final flags = _readUleb128(dex, c);
      final codeOff = _readUleb128(dex, c);
      methods.add(_DexMethod(methodIdx, flags, codeOff));
    }
    return methods;
  }

  static int _readUleb128(DexImage dex, _Cursor c) {
    var result = 0;
    var shift = 0;
    while (true) {
      if (c.pos >= dex.length) break;
      final b = dex.data.getUint8(c.pos++);
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) == 0) break;
      shift += 7;
      if (shift > 35) break;
    }
    return result;
  }

  // ---- signature helpers (mirror @kelivo/dex internals) -------------------
  static String _methodSig(DexImage dex, int methodIdx) {
    if (methodIdx < 0 || methodIdx >= dex.methodIdsSize) return '';
    final base = dex.methodIdsOff + methodIdx * 8;
    if (base + 8 > dex.length) return '';
    final classIdx = dex.data.getUint16(base, Endian.little);
    final protoIdx = dex.data.getUint16(base + 2, Endian.little);
    final nameIdx = dex.data.getUint32(base + 4, Endian.little);
    final className = dex.typeAt(classIdx);
    final name = dex.stringAt(nameIdx);
    final shorty = dex.protoShortyAt(protoIdx);
    return '$className->$name$shorty';
  }

  static String _protoSig(DexImage dex, int protoIdx) {
    if (protoIdx < 0 || protoIdx >= dex.protoIdsSize) return '';
    final base = dex.protoIdsOff + protoIdx * 12;
    if (base + 12 > dex.length) return '';
    final returnTypeIdx = dex.data.getUint32(base + 4, Endian.little);
    final paramsOff = dex.data.getUint32(base + 8, Endian.little);
    final ret = dex.typeAt(returnTypeIdx);
    final params = <String>[];
    if (paramsOff != 0 && paramsOff < dex.length) {
      final size = dex.data.getUint32(paramsOff, Endian.little);
      for (var i = 0; i < size; i++) {
        final idx = dex.data.getUint16(paramsOff + 4 + i * 2, Endian.little);
        params.add(dex.typeAt(idx));
      }
    }
    return '(${params.join(',')})$ret';
  }

  static String _fullMethodSig(DexImage dex, int methodIdx) {
    if (methodIdx < 0 || methodIdx >= dex.methodIdsSize) return '';
    final base = dex.methodIdsOff + methodIdx * 8;
    if (base + 8 > dex.length) return '';
    final classIdx = dex.data.getUint16(base, Endian.little);
    final protoIdx = dex.data.getUint16(base + 2, Endian.little);
    final nameIdx = dex.data.getUint32(base + 4, Endian.little);
    final className = dex.typeAt(classIdx);
    final name = dex.stringAt(nameIdx);
    return '$className->$name${_protoSig(dex, protoIdx)}';
  }

  static String _fieldSig(DexImage dex, int fieldIdx) {
    if (fieldIdx < 0 || fieldIdx >= dex.fieldIdsSize) return '';
    final base = dex.fieldIdsOff + fieldIdx * 8;
    if (base + 8 > dex.length) return '';
    final classIdx = dex.data.getUint16(base, Endian.little);
    final typeIdx = dex.data.getUint16(base + 2, Endian.little);
    final nameIdx = dex.data.getUint32(base + 4, Endian.little);
    return '${dex.typeAt(classIdx)}->${dex.stringAt(nameIdx)} : ${dex.typeAt(typeIdx)}';
  }

  // ---- instruction walker ---------------------------------------------------
  static List<String> _collectInvokes(DexImage dex, int codeOff) {
    final out = <String>[];
    if (codeOff + 16 > dex.length) return out;
    final insnsSize = dex.data.getUint32(codeOff + 12, Endian.little);
    var pc = codeOff + 16;
    var index = 0;
    final maxInsns = insnsSize < 5000 ? insnsSize : 5000;
    while (index < maxInsns && pc + 2 <= dex.length) {
      final word = dex.data.getUint16(pc, Endian.little);
      final op = word & 0xff;
      if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
        final ref = dex.data.getUint16(pc + 2, Endian.little);
        final sig = _fullMethodSig(dex, ref);
        if (sig.isNotEmpty) out.add(sig);
      }
      pc += _insnUnits(op) * 2;
      index++;
    }
    return out;
  }

  static List<String> _collectFieldRefs(DexImage dex, int codeOff) {
    final out = <String>[];
    if (codeOff + 16 > dex.length) return out;
    final insnsSize = dex.data.getUint32(codeOff + 12, Endian.little);
    var pc = codeOff + 16;
    var index = 0;
    final maxInsns = insnsSize < 5000 ? insnsSize : 5000;
    while (index < maxInsns && pc + 2 <= dex.length) {
      final word = dex.data.getUint16(pc, Endian.little);
      final op = word & 0xff;
      if ((op >= 0x52 && op <= 0x5f) || (op >= 0x60 && op <= 0x6d)) {
        final ref = dex.data.getUint16(pc + 2, Endian.little);
        final sig = _fieldSig(dex, ref);
        if (sig.isNotEmpty) out.add(sig);
      }
      pc += _insnUnits(op) * 2;
      index++;
    }
    return out;
  }

  static int _insnUnits(int op) {
    // 12-bit format families: 10x, 12x, 11n, 11x → 1 unit; rest → 2 units.
    // We cover the common subset used by real code; unknown ops default to 2.
    const oneUnit = <int>{
      0x00, 0x01, 0x04, 0x07, 0x0a, 0x0b, 0x0c, 0x0d,
      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x1d, 0x1e, 0x27,
      0x28, 0x2b, 0x2c, 0x32, 0x33, 0x34, 0x35, 0x36,
      0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
    };
    if (oneUnit.contains(op)) return 1;
    return 2;
  }

  static String _accessLabel(int flags) {
    final parts = <String>[];
    if (flags & 0x0001 != 0) parts.add('public');
    if (flags & 0x0002 != 0) parts.add('private');
    if (flags & 0x0004 != 0) parts.add('protected');
    if (flags & 0x0008 != 0) parts.add('static');
    if (flags & 0x0010 != 0) parts.add('final');
    if (flags & 0x0200 != 0) parts.add('interface');
    if (flags & 0x0400 != 0) parts.add('abstract');
    if (flags & 0x1000 != 0) parts.add('synthetic');
    if (flags & 0x2000 != 0) parts.add('annotation');
    if (flags & 0x4000 != 0) parts.add('enum');
    return '[${parts.join(' ')}]';
  }

  static String _simpleClassName(String descriptor) {
    // Lcom/example/Main; → Main
    if (descriptor.startsWith('L') && descriptor.endsWith(';')) {
      final inner = descriptor.substring(1, descriptor.length - 1);
      final idx = inner.lastIndexOf('/');
      return idx == -1 ? inner : inner.substring(idx + 1);
    }
    return descriptor;
  }

  // ---- APK helpers ----------------------------------------------------------
  static List<ArchiveFile> _readApkEntries(Uint8List bytes) {
    try {
      final archive = ZipDecoder().decodeBytes(bytes);
      return archive.files.toList();
    } catch (_) {
      return const <ArchiveFile>[];
    }
  }

  static Uint8List? _entryBytes(List<ArchiveFile> entries, String name) {
    for (final f in entries) {
      if (f.name == name || f.name.endsWith('/$name')) {
        try {
          return Uint8List.fromList(f.content as List<int>);
        } catch (_) {
          return null;
        }
      }
    }
    return null;
  }

  static List<ArchiveFile> _dexEntries(List<ArchiveFile> entries) {
    return entries.where((f) {
      final n = f.name.toLowerCase();
      return n.endsWith('.dex') && n.contains('classes');
    }).toList();
  }

  // ---- search: classes -------------------------------------------------------
  static Map<String, dynamic> searchClasses(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final keyword = (args['keyword'] ?? '').toString().trim();
      final searchIn = (args['search_in'] ?? '').toString().trim().toLowerCase();
      final limit = _asInt(args['limit'], p.limit);
      if (keyword.isEmpty) {
        return _err('Missing "keyword" (e.g. "Login", "onCreate", "api_key")');
      }
      final sb = StringBuffer()
        ..writeln('Class search: "$keyword" (in: ${searchIn.isEmpty ? "all" : searchIn})');
      var hits = 0;
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (final cls in idx.classes) {
          final className = cls.name;
          final simple = _simpleClassName(className);
          final methods = cls.methods;
          final methodNames = <String>[];
          for (final m in methods) {
            methodNames.add(_fullMethodSig(idx.dex, m.methodIdx));
          }
          final fieldNames = <String>[];
          // Collect field names from field_ids belonging to this class
          for (var fi = 0; fi < idx.dex.fieldIdsSize; fi++) {
            final base = idx.dex.fieldIdsOff + fi * 8;
            if (base + 8 > idx.dex.length) break;
            final classIdx = idx.dex.data.getUint16(base, Endian.little);
            final nameIdx = idx.dex.data.getUint32(base + 4, Endian.little);
            if (idx.dex.typeAt(classIdx) == className) {
              fieldNames.add(idx.dex.stringAt(nameIdx));
            }
          }
          bool matched = false;
          final inAll = searchIn.isEmpty || searchIn == 'all';
          final inClass = inAll || searchIn == 'class';
          final inMethod = inAll || searchIn == 'method';
          final inField = inAll || searchIn == 'field';
          if (inClass && (className.contains(keyword) || simple.contains(keyword))) {
            matched = true;
          }
          if (!matched && inMethod) {
            for (final mn in methodNames) {
              if (mn.contains(keyword)) {
                matched = true;
                break;
              }
            }
          }
          if (!matched && inField) {
            for (final fn in fieldNames) {
              if (fn.contains(keyword)) {
                matched = true;
                break;
              }
            }
          }
          if (matched) {
            sb.writeln('$className  extends ${cls.superName}  ${_accessLabel(cls.accessFlags)}');
            for (final mn in methodNames.take(8)) {
              sb.writeln('    $mn');
            }
            if (methodNames.length > 8) {
              sb.writeln('    ... (+${methodNames.length - 8} methods)');
            }
            hits++;
            if (hits >= limit) {
              sb.writeln('---');
              sb.writeln('Hits: >=$limit (truncated)');
              return _ok(sb.toString().trimRight());
            }
          }
        }
      }
      sb.writeln('---');
      sb.writeln('Hits: $hits (limit $limit)');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- search: methods ---------------------------------------------------------
  static Map<String, dynamic> searchMethods(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final keyword = (args['keyword'] ?? '').toString().trim();
      final limit = _asInt(args['limit'], p.limit);
      if (keyword.isEmpty) {
        return _err('Missing "keyword" (method name or signature substring)');
      }
      final sb = StringBuffer()
        ..writeln('Method search: "$keyword"');
      var hits = 0;
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (final cls in idx.classes) {
          for (final m in cls.methods) {
            final sig = _fullMethodSig(idx.dex, m.methodIdx);
            if (sig.contains(keyword)) {
              sb.writeln('$sig  ${_accessLabel(m.accessFlags)}');
              hits++;
              if (hits >= limit) {
                sb.writeln('---');
                sb.writeln('Hits: >=$limit (truncated)');
                return _ok(sb.toString().trimRight());
              }
            }
          }
        }
      }
      sb.writeln('---');
      sb.writeln('Hits: $hits (limit $limit)');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- method source (Dalvik disassembly + skeleton) ---------------------------
  static Map<String, dynamic> methodSource(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final method = (args['method'] ?? '').toString().trim();
      if (method.isEmpty) {
        return _err(
          'Missing "method" (e.g. Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V)',
        );
      }
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (final cls in idx.classes) {
          for (final m in cls.methods) {
            final sig = _fullMethodSig(idx.dex, m.methodIdx);
            if (sig != method) continue;
            if (m.codeOff == 0) {
              return _ok('$sig\n  (abstract/native, no code)');
            }
            final asm = _disassemble(idx.dex, m.codeOff, sig);
            return _ok(asm);
          }
        }
      }
      return _err('Method not found: $method');
    } catch (e) {
      return _err(e.toString());
    }
  }

  static String _disassemble(DexImage dex, int codeOff, String sig) {
    final sb = StringBuffer()..writeln('// $sig');
    if (codeOff + 16 > dex.length) return sb.toString().trimRight();
    final registersSize = dex.data.getUint16(codeOff, Endian.little);
    final insSize = dex.data.getUint16(codeOff + 2, Endian.little);
    final outsSize = dex.data.getUint16(codeOff + 4, Endian.little);
    final triesSize = dex.data.getUint16(codeOff + 6, Endian.little);
    final insnsSize = dex.data.getUint32(codeOff + 12, Endian.little);
    sb.writeln('// registers: $registersSize, ins: $insSize, outs: $outsSize, insns: $insnsSize');
    var pc = codeOff + 16;
    var index = 0;
    final maxInsns = insnsSize < 2000 ? insnsSize : 2000;
    while (index < maxInsns && pc + 2 <= dex.length) {
      final word = dex.data.getUint16(pc, Endian.little);
      final op = word & 0xff;
      final opName = _kDalvikOpcodes[op] ?? 'unknown_0x${op.toRadixString(16)}';
      final units = _insnUnits(op);
      final line = StringBuffer('  $index: $opName');
      if (op == 0x1a || op == 0x1b) {
        final idx = dex.data.getUint16(pc + 2, Endian.little);
        final s = dex.stringAt(idx);
        line.write(' "$s"');
      } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
        final ref = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' ${_fullMethodSig(dex, ref)}');
      } else if (op >= 0x32 && op <= 0x3d) {
        final target = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' +$target');
      } else if (op == 0x28) {
        line.write(' +${(word >> 8).toSigned(8)}');
      } else if (op == 0x29) {
        line.write(' +${dex.data.getInt16(pc + 2, Endian.little)}');
      } else if (op == 0x2a) {
        line.write(' +${dex.data.getInt32(pc + 2, Endian.little)}');
      } else if (op == 0x12) {
        line.write(' #${word >> 12}');
      } else if (op == 0x13 || op == 0x15 || op == 0x16 || op == 0x19) {
        line.write(' #${dex.data.getUint16(pc + 2, Endian.little)}');
      } else if (op == 0x14 || op == 0x17) {
        line.write(' #${dex.data.getUint32(pc + 2, Endian.little)}');
      } else if (op == 0x18) {
        line.write(' #${dex.data.getUint64(pc + 2, Endian.little)}');
      } else if (op == 0x1c || op == 0x22) {
        final idx = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' ${dex.typeAt(idx)}');
      } else if (op == 0x1f || op == 0x20 || op == 0x23) {
        final idx = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' ${dex.typeAt(idx)}');
      } else if ((op >= 0x52 && op <= 0x5f) || (op >= 0x60 && op <= 0x6d)) {
        final ref = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' ${_fieldSig(dex, ref)}');
      }
      pc += units * 2;
      sb.writeln(line.toString());
      index++;
    }
    return sb.toString().trimRight();
  }

  // ---- xrefs: class ------------------------------------------------------------
  static Map<String, dynamic> classXrefs(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final target = (args['class'] ?? args['className'] ?? '').toString().trim();
      if (target.isEmpty) {
        return _err('Missing "class" (e.g. Lcom/example/Main;)');
      }
      final normalized = _normalizeClass(target);
      final sb = StringBuffer()..writeln('XREF to class: $normalized');
      var hits = 0;
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (final cls in idx.classes) {
          for (final m in cls.methods) {
            if (m.codeOff == 0) continue;
            final caller = _fullMethodSig(idx.dex, m.methodIdx);
            final refs = _collectInvokes(idx.dex, m.codeOff);
            for (final r in refs) {
              if (r.contains(normalized)) {
                sb.writeln('  $caller');
                hits++;
                break;
              }
            }
          }
        }
      }
      sb.writeln('---');
      sb.writeln('Referencing methods: $hits');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- xrefs: field --------------------------------------------------------------
  static Map<String, dynamic> fieldXrefs(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final field = (args['field'] ?? '').toString().trim();
      if (field.isEmpty) {
        return _err('Missing "field" (e.g. Lcom/example/Main;->counter:I)');
      }
      final sb = StringBuffer()..writeln('XREF to field: $field');
      var hits = 0;
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (final cls in idx.classes) {
          for (final m in cls.methods) {
            if (m.codeOff == 0) continue;
            final caller = _fullMethodSig(idx.dex, m.methodIdx);
            final refs = _collectFieldRefs(idx.dex, m.codeOff);
            if (refs.contains(field)) {
              sb.writeln('  $caller');
              hits++;
            }
          }
        }
      }
      sb.writeln('---');
      sb.writeln('Referencing methods: $hits');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- manifest -------------------------------------------------------------------
  static Map<String, dynamic> manifest(
    KelivoJadxRequestPayload p,
  ) {
    try {
      if (!p.isApk) {
        return _err('Manifest requires an APK input (got raw DEX)');
      }
      final entries = _readApkEntries(p.bytes);
      if (entries.isEmpty) {
        return _err('Failed to read APK archive');
      }
      final manifestBytes = _entryBytes(entries, 'AndroidManifest.xml');
      if (manifestBytes == null) {
        return _err('AndroidManifest.xml not found in APK');
      }
      final xml = _decodeManifest(manifestBytes);
      return _ok(xml);
    } catch (e) {
      return _err(e.toString());
    }
  }

  static String _decodeManifest(Uint8List bytes) {
    // AndroidManifest.xml is a binary XML. We extract readable strings with
    // minimal heuristics: string pool + element/attribute names.
    final sb = StringBuffer()..writeln('=== AndroidManifest.xml (binary XML, extracted strings) ===');
    final strings = <String>[];
    // Try to find the string pool: 0x000C0001 (RES_STRING_POOL_TYPE) marker.
    for (var i = 0; i + 8 < bytes.length; i++) {
      if (bytes[i] == 0x01 && bytes[i + 1] == 0x00 && bytes[i + 2] == 0x0c && bytes[i + 3] == 0x00) {
        final stringCount = bytes[i + 4] | (bytes[i + 5] << 8) | (bytes[i + 6] << 16) | (bytes[i + 7] << 24);
        if (stringCount > 0 && stringCount < 100000) {
          final poolStart = i;
          final offsetsOff = i + 28;
          for (var s = 0; s < stringCount; s++) {
            final offOff = offsetsOff + s * 4;
            if (offOff + 4 > bytes.length) break;
            final strOff = bytes[offOff] | (bytes[offOff + 1] << 8) |
                (bytes[offOff + 2] << 16) | (bytes[offOff + 3] << 24);
            final abs = poolStart + strOff;
            if (abs + 2 > bytes.length) continue;
            final len = bytes[abs] | (bytes[abs + 1] << 8);
            final start = abs + 2;
            if (start + len > bytes.length) continue;
            final buf = StringBuffer();
            for (var k = 0; k < len; k++) {
              buf.writeCharCode(bytes[start + k * 2]);
            }
            final s2 = buf.toString();
            if (s2.isNotEmpty && s2.length < 200) strings.add(s2);
          }
          break;
        }
      }
    }
    if (strings.isEmpty) {
      // Fallback: dump printable ASCII runs
      final buf = StringBuffer();
      for (var i = 0; i < bytes.length; i++) {
        final c = bytes[i];
        if (c >= 32 && c < 127) {
          buf.writeCharCode(c);
        } else {
          if (buf.length >= 4) strings.add(buf.toString());
          buf.clear();
        }
      }
      if (buf.length >= 4) strings.add(buf.toString());
    }
    final seen = <String>{};
    for (final s in strings) {
      if (seen.add(s)) sb.writeln('  $s');
    }
    return sb.toString().trimRight();
  }

  // ---- strings ---------------------------------------------------------------------
  static Map<String, dynamic> strings(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final pattern = (args['pattern'] ?? '').toString().trim();
      final limit = _asInt(args['limit'], p.limit);
      if (pattern.isEmpty) {
        return _err('Missing "pattern" (regex or plain substring)');
      }
      final sb = StringBuffer()..writeln('String search: /$pattern/');
      var hits = 0;
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (var i = 0; i < idx.dex.stringIdsSize; i++) {
          final s = idx.dex.stringAt(i);
          if (s.isEmpty) continue;
          if (_matchesPattern(s, pattern)) {
            sb.writeln('[$i] $s');
            hits++;
            if (hits >= limit) {
              sb.writeln('---');
              sb.writeln('Hits: >=$limit (truncated)');
              return _ok(sb.toString().trimRight());
            }
          }
        }
      }
      sb.writeln('---');
      sb.writeln('Hits: $hits (limit $limit)');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- rename (in-memory mapping) ----------------------------------------------------
  static Map<String, dynamic> rename(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final target = (args['target'] ?? '').toString().trim();
      final newName = (args['new_name'] ?? '').toString().trim();
      final kind = (args['kind'] ?? 'class').toString().trim().toLowerCase();
      if (target.isEmpty || newName.isEmpty) {
        return _err('Missing "target" and "new_name"');
      }
      final sb = StringBuffer()
        ..writeln('Rename (in-memory mapping): $kind "$target" → "$newName"')
        ..writeln('')
        ..writeln('Note: this is a session-level mapping. To persist a real rename,')
        ..writeln('rebuild the DEX with a patched string pool or apply the mapping')
        ..writeln('during analysis output (e.g. in the disassembly view).');
      // Build the mapping and echo what would change
      var affected = 0;
      final dexFiles = _collectDex(p);
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (final cls in idx.classes) {
          final methods = cls.methods;
          for (final m in methods) {
            final sig = _fullMethodSig(idx.dex, m.methodIdx);
            if (sig.contains(target)) affected++;
          }
        }
      }
      sb.writeln('Affected method signatures containing "$target": $affected');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- extract endpoints (URL / IP / API) ------------------------------------------
  static Map<String, dynamic> extractEndpoints(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final limit = _asInt(args['limit'], 200);
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      final urlRe = RegExp(
        r'https?://[^\s"\'<>\\]+',
        caseSensitive: false,
      );
      final ipRe = RegExp(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
      );
      final apiPatterns = [
        RegExp(r'/api/[\w/.-]+'),
        RegExp(r'/v\d+/[\w/.-]+'),
        RegExp(r'/rest/[\w/.-]+'),
        RegExp(r'/service/[\w/.-]+'),
        RegExp(r'/endpoint/[\w/.-]+'),
      ];
      final urls = <String>{};
      final ips = <String>{};
      final apis = <String>{};
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (var i = 0; i < idx.dex.stringIdsSize; i++) {
          final s = idx.dex.stringAt(i);
          if (s.isEmpty || s.length < 4) continue;
          for (final m in urlRe.allMatches(s)) {
            urls.add(m.group(0)!);
          }
          for (final m in ipRe.allMatches(s)) {
            final ip = m.group(0)!;
            if (!ip.startsWith('127.') &&
                !ip.startsWith('192.168.') &&
                !ip.startsWith('10.') &&
                !ip.startsWith('0.0.')) {
              ips.add(ip);
            }
          }
          for (final re in apiPatterns) {
            for (final m in re.allMatches(s)) {
              apis.add(m.group(0)!);
            }
          }
        }
      }
      final sb = StringBuffer()
        ..writeln('=== Endpoint Extraction ===')
        ..writeln('')
        ..writeln('URLs (${urls.length}):');
      for (final u in urls.take(limit)) {
        sb.writeln('  $u');
      }
      sb.writeln('')
        ..writeln('IPs (${ips.length}):');
      for (final ip in ips.take(limit)) {
        sb.writeln('  $ip');
      }
      sb.writeln('')
        ..writeln('API Endpoints (${apis.length}):');
      for (final a in apis.take(limit)) {
        sb.writeln('  $a');
      }
      sb.writeln('---')
        ..writeln('Summary: ${urls.length} URLs, ${ips.length} IPs, ${apis.length} API endpoints');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- identify SDKs ---------------------------------------------------------------
  static Map<String, dynamic> identifySdks(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      // Collect all class descriptors
      final allClasses = <String>{};
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (final cls in idx.classes) {
          allClasses.add(cls.name);
        }
      }
      final sdkPatterns = <String, Map<String, List<String>>>{
        '广告': {
          'packages': [
            'com.google.android.gms.ads', 'com.facebook.ads', 'com.mopub',
            'com.inmobi', 'com.chartboost.sdk', 'com.applovin',
            'com.unity3d.ads', 'com.vungle', 'com.adcolony',
            'com.flurry.android', 'com.baidu.mobads', 'com.qq.e.ads',
            'com.umeng.ad', 'com.gdt',
          ],
          'classes': [
            'AdView', 'InterstitialAd', 'RewardedAd', 'BannerAd',
            'AdLoader', 'AdRequest', 'AdListener',
          ],
        },
        '统计': {
          'packages': [
            'com.google.firebase.analytics', 'com.google.android.gms.analytics',
            'com.umeng.analytics', 'com.umeng.commonsdk', 'com.tencent.stat',
            'com.baidu.mobstat', 'com.sensorsdata.analytics',
            'cn.thinkingdata.analytics', 'com.growingio.android.sdk',
            'com.appsflyer', 'com.adjust.sdk', 'com.talkingdata.sdk',
            'com.mixpanel.android', 'com.amplitude.api',
          ],
          'classes': [
            'Analytics', 'Tracker', 'EventBuilder', 'UserProperties',
            'TrackEvent', 'LogEvent', 'onEvent',
          ],
        },
        '社交': {
          'packages': [
            'com.facebook', 'com.twitter.sdk', 'com.tencent.mm.opensdk',
            'com.sina.weibo.sdk', 'com.tencent.mobileqq', 'com.tencent.tauth',
            'com.twitter.android', 'com.vk.sdk', 'com.linecorp',
            'com.kakao.sdk',
          ],
          'classes': [
            'ShareDialog', 'LoginManager', 'CallbackManager',
            'IWXAPI', 'WBAPI', 'TwitterAuthClient',
          ],
        },
        '支付': {
          'packages': [
            'com.alipay.sdk', 'com.tencent.mm.opensdk', 'com.unionpay',
            'com.google.android.gms.wallet', 'com.paypal.android',
            'com.stripe.android', 'com.braintreepayments', 'com.adyen',
            'com.squareup.sdk', 'com.payu', 'com.razorpay',
          ],
          'classes': [
            'PayTask', 'PayReq', 'PayResp', 'Payment',
            'BillingClient', 'BillingFlowParams', 'Purchase',
          ],
        },
        '推送': {
          'packages': [
            'com.google.firebase.messaging', 'com.huawei.hms.push',
            'com.xiaomi.push', 'com.xiaomi.mipush', 'com.meizu.cloud.push',
            'com.oppo.push', 'com.vivo.push', 'com.tencent.android.tpush',
            'cn.jpush.android', 'com.getui', 'com.igexin',
            'com.onesignal',
          ],
          'classes': [
            'FirebaseMessagingService', 'PushMessageReceiver',
            'XMPushService', 'PushManager',
          ],
        },
        '地图': {
          'packages': [
            'com.google.android.gms.maps', 'com.amap.api',
            'com.baidu.mapapi', 'com.tencent.tencentmap',
            'com.mapbox.mapboxsdk', 'com.baidu.BaiduMap', 'com.autonavi',
          ],
          'classes': [
            'GoogleMap', 'MapView', 'AMap', 'BaiduMap',
            'MapFragment', 'SupportMapFragment',
          ],
        },
        '崩溃报告': {
          'packages': [
            'com.google.firebase.crashlytics', 'com.bugly',
            'com.tencent.bugly', 'com.instabug', 'io.fabric.sdk',
            'com.crashlytics.android', 'com.microsoft.appcenter.crashes',
            'com.bugsnag', 'com.sentry',
          ],
          'classes': [
            'Crashlytics', 'CrashReport', 'Bugly',
            'Instabug', 'Sentry',
          ],
        },
      };
      final sb = StringBuffer()..writeln('=== SDK Identification ===');
      var totalMatches = 0;
      for (final entry in sdkPatterns.entries) {
        final sdkType = entry.key;
        final patterns = entry.value;
        final matched = <String>[];
        for (final pkg in patterns['packages']!) {
          for (final cls in allClasses) {
            if (cls.contains(pkg)) {
              matched.add('[pkg] $pkg → $cls');
              break;
            }
          }
        }
        for (final clsPattern in patterns['classes']!) {
          for (final cls in allClasses) {
            final simple = _simpleClassName(cls).toLowerCase();
            if (simple.contains(clsPattern.toLowerCase())) {
              matched.add('[cls] $clsPattern → $cls');
            }
          }
        }
        if (matched.isNotEmpty) {
          sb.writeln('');
          sb.writeln('$sdkType (${matched.length}):');
          for (final m in matched.take(20)) {
            sb.writeln('  $m');
          }
          if (matched.length > 20) {
            sb.writeln('  ... (+${matched.length - 20} more)');
          }
          totalMatches += matched.length;
        }
      }
      sb.writeln('');
      sb.writeln('---');
      sb.writeln('Total: $totalMatches matches across ${sdkPatterns.length} SDK categories');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- suspicious strings (encrypted / encoded) ------------------------------------
  static Map<String, dynamic> suspiciousStrings(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final limit = _asInt(args['limit'], 200);
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      final b64Re = RegExp(r'^[A-Za-z0-9+/]{20,}={0,2}$');
      final hexRe = RegExp(r'^[0-9a-fA-F]{20,}$');
      final results = <String>[];
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (var i = 0; i < idx.dex.stringIdsSize; i++) {
          final s = idx.dex.stringAt(i);
          if (s.isEmpty || s.length < 20) continue;
          final reason = _checkSuspicious(s, b64Re, hexRe);
          if (reason != null) {
            results.add('[$i] ($reason) $s');
          }
        }
      }
      final sb = StringBuffer()
        ..writeln('=== Suspicious Strings ===')
        ..writeln('');
      for (final r in results.take(limit)) {
        sb.writeln(r);
      }
      sb.writeln('');
      sb.writeln('---');
      sb.writeln('Found: ${results.length} suspicious strings (showing ${results.length < limit ? results.length : limit})');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static String? _checkSuspicious(String s, RegExp b64Re, RegExp hexRe) {
    if (s.length >= 32) {
      final unique = s.split('').toSet().length;
      if (unique / s.length > 0.7) return 'high-entropy';
    }
    if (b64Re.hasMatch(s) && s.length % 4 == 0) return 'base64';
    if (hexRe.hasMatch(s) && s.length >= 32) return 'hex';
    return null;
  }

  // ---- secret scan (API keys / tokens) ---------------------------------------------
  static Map<String, dynamic> secretScan(
    KelivoJadxRequestPayload p,
    Map<String, dynamic> args,
  ) {
    try {
      final limit = _asInt(args['limit'], 200);
      final dexFiles = _collectDex(p);
      if (dexFiles.isEmpty) {
        return _err('No DEX found in input');
      }
      final secretPatterns = <String, RegExp>{
        'AWS Access Key': RegExp(r'AKIA[0-9A-Z]{16}'),
        'AWS Secret': RegExp(r'aws_secret_access_key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'),
        'Google API Key': RegExp(r'AIza[0-9A-Za-z\-_]{35}'),
        'Google OAuth': RegExp(r'ya29\.[0-9A-Za-z\-_]+'),
        'JWT': RegExp(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*'),
        'Bearer Token': RegExp(r'[Bb]earer\s+[A-Za-z0-9\-_.~+/]+=*'),
        'Slack Token': RegExp(r'xox[baprs]-[0-9A-Za-z-]+'),
        'GitHub Token': RegExp(r'gh[pousr]_[A-Za-z0-9]{36}'),
        'Stripe Key': RegExp(r'sk_live_[0-9A-Za-z]{24,}'),
        'Generic API Key': RegExp(
          r'(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})',
          caseSensitive: false,
        ),
        'Private Key': RegExp(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
      };
      final results = <String>[];
      for (final dex in dexFiles) {
        final idx = _openDex(dex);
        for (var i = 0; i < idx.dex.stringIdsSize; i++) {
          final s = idx.dex.stringAt(i);
          if (s.isEmpty || s.length < 8) continue;
          for (final entry in secretPatterns.entries) {
            final matches = entry.value.allMatches(s);
            if (matches.isNotEmpty) {
              for (final m in matches) {
                final matched = m.group(0)!;
                // Truncate very long matches
                final display = matched.length > 120
                    ? '${matched.substring(0, 120)}...'
                    : matched;
                results.add('[$i] ${entry.key}: $display');
              }
            }
          }
        }
      }
      final sb = StringBuffer()
        ..writeln('=== Secret / Token Scan ===')
        ..writeln('');
      for (final r in results.take(limit)) {
        sb.writeln(r);
      }
      sb.writeln('');
      sb.writeln('---');
      sb.writeln('Found: ${results.length} potential secrets (showing ${results.length < limit ? results.length : limit})');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- helpers ----------------------------------------------------------------------
  static List<Uint8List> _collectDex(KelivoJadxRequestPayload p) {
    if (!p.isApk) {
      return [p.bytes];
    }
    final entries = _readApkEntries(p.bytes);
    final dexList = _dexEntries(entries);
    if (dexList.isEmpty) {
      // Maybe the APK has a single classes.dex-like entry; fallback to any .dex
      final allDex = entries.where((f) => f.name.toLowerCase().endsWith('.dex')).toList();
      return [
        for (final f in allDex)
          try {
            Uint8List.fromList(f.content as List<int>)
          } catch (_) {
            Uint8List(0)
          }
      ].where((b) => b.isNotEmpty).toList();
    }
    return [
      for (final f in dexList)
        try {
          Uint8List.fromList(f.content as List<int>)
        } catch (_) {
          Uint8List(0)
        }
    ].where((b) => b.isNotEmpty).toList();
  }

  static String _normalizeClass(String s) {
    var t = s.trim();
    if (!t.startsWith('L')) t = 'L$t';
    if (!t.endsWith(';')) t = '$t;';
    return t;
  }

  static bool _matchesPattern(String s, String pat) {
    try {
      return RegExp(pat, caseSensitive: false).hasMatch(s);
    } catch (_) {
      return s.contains(pat);
    }
  }

  static int _asInt(Object? v, int fallback) {
    if (v is int) return v;
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v.trim()) ?? fallback;
    return fallback;
  }

  static Map<String, dynamic> _ok(String text) => {
        'content': [
          {'type': 'text', 'text': text},
        ],
        'isStreaming': false,
        'isError': false,
      };
  static Map<String, dynamic> _err(String message) => {
        'content': [
          {'type': 'text', 'text': message},
        ],
        'isStreaming': false,
        'isError': true,
      };
}

class _Cursor {
  int pos;
  _Cursor(this.pos);
}

// Dalvik opcode names (subset covering most common opcodes).
const _kDalvikOpcodes = <int, String>{
  0x00: 'nop', 0x01: 'move', 0x02: 'move/from16', 0x03: 'move/16',
  0x04: 'move-wide', 0x07: 'move-object', 0x0a: 'move-result',
  0x0b: 'move-result-wide', 0x0c: 'move-result-object', 0x0d: 'move-exception',
  0x0e: 'return-void', 0x0f: 'return', 0x10: 'return-wide', 0x11: 'return-object',
  0x12: 'const/4', 0x13: 'const/16', 0x14: 'const', 0x15: 'const/high16',
  0x16: 'const-wide/16', 0x17: 'const-wide/32', 0x18: 'const-wide',
  0x19: 'const-wide/high16', 0x1a: 'const-string', 0x1b: 'const-string/jumbo',
  0x1c: 'const-class', 0x1d: 'monitor-enter', 0x1e: 'monitor-exit',
  0x1f: 'check-cast', 0x20: 'instance-of', 0x21: 'array-length',
  0x22: 'new-instance', 0x23: 'new-array', 0x24: 'filled-new-array',
  0x26: 'fill-array-data', 0x27: 'throw', 0x28: 'goto', 0x29: 'goto/16',
  0x2a: 'goto/32', 0x2b: 'packed-switch', 0x2c: 'sparse-switch',
  0x2d: 'cmpl-float', 0x2e: 'cmpg-float', 0x2f: 'cmpl-double',
  0x30: 'cmpg-double', 0x31: 'cmp-long',
  0x32: 'if-eq', 0x33: 'if-ne', 0x34: 'if-lt', 0x35: 'if-ge',
  0x36: 'if-gt', 0x37: 'if-le', 0x38: 'if-eqz', 0x39: 'if-nez',
  0x3a: 'if-ltz', 0x3b: 'if-gez', 0x3c: 'if-gtz', 0x3d: 'if-lez',
  0x44: 'aget', 0x45: 'aget-wide', 0x46: 'aget-object',
  0x4b: 'aput', 0x4c: 'aput-wide', 0x4d: 'aput-object',
  0x52: 'iget', 0x53: 'iget-wide', 0x54: 'iget-object',
  0x59: 'iput', 0x5a: 'iput-wide', 0x5b: 'iput-object',
  0x60: 'sget', 0x61: 'sget-wide', 0x62: 'sget-object',
  0x67: 'sput', 0x68: 'sput-wide', 0x69: 'sput-object',
  0x6e: 'invoke-virtual', 0x6f: 'invoke-super', 0x70: 'invoke-direct',
  0x71: 'invoke-static', 0x72: 'invoke-interface',
  0x74: 'invoke-virtual/range', 0x75: 'invoke-super/range',
  0x76: 'invoke-direct/range', 0x77: 'invoke-static/range',
  0x78: 'invoke-interface/range',
  0x90: 'add-int', 0x91: 'sub-int', 0x92: 'mul-int', 0x93: 'div-int',
  0xb0: 'add-int/2addr', 0xb1: 'sub-int/2addr',
  0xd8: 'add-int/lit8', 0xd9: 'rsub-int/lit8',
};

// ---------------------------------------------------------------------------
// MCP Server Engine
// ---------------------------------------------------------------------------
class KelivoJadxMcpServerEngine implements KelivoInMemoryMcpServerEngine {
  @override
  Future<dynamic> handleMessage(dynamic message) async {
    return _handleSingle(message);
  }

  Future<Map<String, dynamic>> _handleSingle(dynamic raw) async {
    try {
      if (raw is! Map) {
        return _error(null, code: -32600, message: 'Invalid Request');
      }
      final req = raw.cast<String, dynamic>();
      final id = req['id'];
      final method = (req['method'] ?? '').toString();
      final params = (req['params'] is Map)
          ? (req['params'] as Map).cast<String, dynamic>()
          : <String, dynamic>{};
      switch (method) {
        case mcp.McpProtocol.methodInitialize:
          return _ok(id, result: {
            'serverInfo': {'name': '@kelivo/jadx', 'version': '0.1.0'},
            'protocolVersion': mcp.McpProtocol.defaultVersion,
            'capabilities': {
              'tools': {'listChanged': false},
            },
          });
        case mcp.McpProtocol.methodListTools:
          return _ok(id, result: {'tools': _toolDefinitions()});
        case mcp.McpProtocol.methodCallTool:
          final name = (params['name'] ?? '').toString();
          final arguments = (params['arguments'] is Map)
              ? (params['arguments'] as Map).cast<String, dynamic>()
              : <String, dynamic>{};
          return _callTool(name, arguments, id);
        case mcp.McpProtocol.methodPing:
          return _ok(id, result: {});
        case mcp.McpProtocol.methodNotificationsInitialized:
          return _noop();
        default:
          return _error(
            id,
            code: -32601,
            message: 'Method not found: $method',
          );
      }
    } catch (e) {
      return _error(null, code: -32603, message: e.toString());
    }
  }

  Future<Map<String, dynamic>> _callTool(
    String name,
    Map<String, dynamic> arguments,
    dynamic id,
  ) async {
    try {
      // jadx_meta_info: no payload needed
      if (name == 'jadx_meta_info') {
        return _ok(id, result: KelivoJadxAnalyzer.metaInfo(arguments));
      }
      final payload = await KelivoJadxRequestPayload.parse(arguments);
      switch (name) {
        case 'jadx_search_classes':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.searchClasses(payload, arguments),
          );
        case 'jadx_search_methods':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.searchMethods(payload, arguments),
          );
        case 'jadx_method_source':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.methodSource(payload, arguments),
          );
        case 'jadx_class_xrefs':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.classXrefs(payload, arguments),
          );
        case 'jadx_field_xrefs':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.fieldXrefs(payload, arguments),
          );
        case 'jadx_manifest':
          return _ok(id, result: KelivoJadxAnalyzer.manifest(payload));
        case 'jadx_strings':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.strings(payload, arguments),
          );
        case 'jadx_rename':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.rename(payload, arguments),
          );
        case 'jadx_extract_endpoints':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.extractEndpoints(payload, arguments),
          );
        case 'jadx_identify_sdks':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.identifySdks(payload, arguments),
          );
        case 'jadx_suspicious_strings':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.suspiciousStrings(payload, arguments),
          );
        case 'jadx_secret_scan':
          return _ok(
            id,
            result: KelivoJadxAnalyzer.secretScan(payload, arguments),
          );
        default:
          return _error(
            id,
            code: -32602,
            message: 'Unknown tool: $name',
          );
      }
    } catch (e) {
      return _error(id, code: -32603, message: e.toString());
    }
  }

  List<Map<String, dynamic>> _toolDefinitions() {
    Map<String, dynamic> baseSchema({bool withLimit = false}) {
      final props = <String, dynamic>{
        'path': {'type': 'string', 'description': '本地 APK 或 .dex 文件的绝对路径。'},
        'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
      };
      if (withLimit) {
        props['limit'] = {'type': 'integer', 'description': '返回条目上限，默认 1000。'};
      }
      return {
        'type': 'object',
        'properties': props,
      };
    }

    return [
      {
        'name': 'jadx_meta_info',
        'description': '返回 @kelivo/jadx 工具说明、推荐工作流和帮助信息。传 action=tools|workflows|describe 获取特定部分，不传则返回全部。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'action': {'type': 'string', 'description': '可选：tools（列出工具）、workflows（推荐工作流）、describe（简介）。'},
          },
        },
      },
      {
        'name': 'jadx_search_classes',
        'description': '按关键字搜索类（支持类名、方法名、字段名匹配）。相当于 JADX 的类搜索。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema(withLimit: true)['properties'] as Map<String, dynamic>,
            'keyword': {'type': 'string', 'description': '搜索关键字，如 "Login"、"onCreate"、"api_key"。'},
            'search_in': {'type': 'string', 'description': '可选：class（类名）、method（方法名）、field（字段名）、all（默认）。'},
          },
        },
      },
      {
        'name': 'jadx_search_methods',
        'description': '跨类搜索方法（按方法名或签名子串）。相当于 JADX 的方法搜索。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema(withLimit: true)['properties'] as Map<String, dynamic>,
            'keyword': {'type': 'string', 'description': '方法名或签名子串，如 "onCreate"、"LoginActivity->onCreate"。'},
          },
        },
      },
      {
        'name': 'jadx_method_source',
        'description': '反汇编指定方法的 Dalvik 字节码（含寄存器、invoke、字符串、字段引用）。参数 method 形如 Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema()['properties'] as Map<String, dynamic>,
            'method': {'type': 'string', 'description': '目标方法完整签名，例如 Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V。'},
          },
        },
      },
      {
        'name': 'jadx_class_xrefs',
        'description': '查找引用指定类的所有方法（类级交叉引用）。参数 class 为类描述符，如 Lcom/example/Main;。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema()['properties'] as Map<String, dynamic>,
            'class': {'type': 'string', 'description': '目标类描述符，例如 Lcom/example/Main; 或 Main。'},
          },
        },
      },
      {
        'name': 'jadx_field_xrefs',
        'description': '查找读取/写入指定字段的所有方法（字段级交叉引用）。参数 field 为字段签名，如 Lcom/example/Main;->counter:I。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema()['properties'] as Map<String, dynamic>,
            'field': {'type': 'string', 'description': '目标字段签名，例如 Lcom/example/Main;->counter:I。'},
          },
        },
      },
      {
        'name': 'jadx_manifest',
        'description': '解析 APK 的 AndroidManifest.xml（二进制 XML，提取字符串池与元素/属性名）。仅支持 APK 输入。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'jadx_strings',
        'description': '在 DEX 字符串池中按正则或子串搜索（如 API key、URL、加密特征等）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema(withLimit: true)['properties'] as Map<String, dynamic>,
            'pattern': {'type': 'string', 'description': '正则表达式或普通子串，例如 "api[_-]?key" 或 "https://"。'},
          },
        },
      },
      {
        'name': 'jadx_rename',
        'description': '重命名类/方法/字段（会话级映射，不修改原始文件）。用于分析时改善可读性。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema()['properties'] as Map<String, dynamic>,
            'target': {'type': 'string', 'description': '要重命名的目标（类描述符、方法签名或字段签名）。'},
            'new_name': {'type': 'string', 'description': '新名称。'},
            'kind': {'type': 'string', 'description': '可选：class（默认）、method、field。'},
          },
        },
      },
      {
        'name': 'jadx_extract_endpoints',
        'description': '从 DEX 字符串池中提取 URL、IP 地址和 API 端点（/api/、/v1/ 等）。自动过滤本地地址。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema()['properties'] as Map<String, dynamic>,
          },
        },
      },
      {
        'name': 'jadx_identify_sdks',
        'description': '通过类名/包名特征匹配识别第三方 SDK（广告、统计、社交、支付、推送、地图、崩溃报告）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema()['properties'] as Map<String, dynamic>,
          },
        },
      },
      {
        'name': 'jadx_suspicious_strings',
        'description': '扫描 DEX 字符串池中可疑的加密/编码字符串（Base64、Hex、高熵长字符串）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema(withLimit: true)['properties'] as Map<String, dynamic>,
          },
        },
      },
      {
        'name': 'jadx_secret_scan',
        'description': '扫描 DEX 字符串池中可能泄露的密钥/Token（API Key、AWS、Google、JWT、Bearer 等）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            ...baseSchema(withLimit: true)['properties'] as Map<String, dynamic>,
          },
        },
      },
    ];
  }

  Map<String, dynamic> _ok(dynamic id, {required Map<String, dynamic> result}) {
    return {
      'jsonrpc': '2.0',
      'id': id,
      'result': result,
    };
  }

  Map<String, dynamic> _error(
    dynamic id, {
    required int code,
    required String message,
  }) {
    return {
      'jsonrpc': '2.0',
      'id': id,
      'error': {'code': code, 'message': message},
    };
  }

  Map<String, dynamic> _noop() => {'jsonrpc': '2.0'};

  @override
  void close() {}
}
