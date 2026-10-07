import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mcp_client/mcp_client.dart' as mcp;

import '../in_memory_mcp_server.dart';

/// @kelivo/dex — In-memory MCP server engine for Android DEX reverse engineering.
///
/// Pure-Dart DEX parser (no native dependencies) so the app stays fully
/// compilable on every platform. Operates on a local file `path` or on raw
/// `base64` bytes. Supports the standard DEX container (magic `dex\n0xx\0`).
///
/// Tools:
/// - dex_parse_header     → DEX header (version, checksum, counts, endian tag)
/// - dex_list_strings     → string_ids pool (MUTF-8 decoded)
/// - dex_list_types       → type_ids (resolved to descriptor strings)
/// - dex_list_classes     → class_defs (class descriptor, superclass, access)
/// - dex_list_methods     → method_ids (class.name + proto shorty)
/// - dex_list_fields      → field_ids (class.name : type)
/// - dex_list_annotations → class-level annotation types (deobfuscation hints)
/// - dex_disassemble_method → disassemble a single method's Dalvik bytecode
/// - dex_xref_method      → find all callers of a method (method-level xref)
/// - dex_search_strings   → regex/substring search over the DEX string pool

class KelivoDexRequestPayload {
  final Uint8List bytes;
  final int limit;

  KelivoDexRequestPayload({required this.bytes, this.limit = 1000});

  static Future<KelivoDexRequestPayload> parse(Object? args) async {
    if (args is! Map) {
      throw ArgumentError('Invalid arguments: expected object with path|base64');
    }
    final map = args.cast<String, dynamic>();
    final limit = _asInt(map['limit'], 1000).clamp(1, 100000);

    final b64 = (map['base64'] ?? '').toString().trim();
    if (b64.isNotEmpty) {
      final bytes = base64Decode(b64);
      return KelivoDexRequestPayload(bytes: bytes, limit: limit);
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
    return KelivoDexRequestPayload(bytes: bytes, limit: limit);
  }

  static int _asInt(Object? v, int fallback) {
    if (v is int) return v;
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v.trim()) ?? fallback;
    return fallback;
  }
}

/// Minimal DEX reader. DEX is always little-endian in practice; the header
/// carries an endian_tag but the reference format mandates little-endian.
class DexImage {
  final ByteData data;
  final int length;

  DexImage._(this.data, this.length);

  // Header fields
  late final String version;
  late final int checksum;
  late final int fileSize;
  late final int headerSize;
  late final int endianTag;
  late final int stringIdsSize;
  late final int stringIdsOff;
  late final int typeIdsSize;
  late final int typeIdsOff;
  late final int protoIdsSize;
  late final int protoIdsOff;
  late final int fieldIdsSize;
  late final int fieldIdsOff;
  late final int methodIdsSize;
  late final int methodIdsOff;
  late final int classDefsSize;
  late final int classDefsOff;
  late final int dataSize;
  late final int dataOff;

  static DexImage parse(Uint8List bytes) {
    if (bytes.length < 112) {
      throw const FormatException('Not a DEX file: too short');
    }
    // Magic: 'dex\n' 0x64 0x65 0x78 0x0a
    if (bytes[0] != 0x64 ||
        bytes[1] != 0x65 ||
        bytes[2] != 0x78 ||
        bytes[3] != 0x0a) {
      throw const FormatException('Not a DEX file: bad magic');
    }
    final img = DexImage._(ByteData.sublistView(bytes), bytes.length);
    img._readHeader(bytes);
    return img;
  }

  void _readHeader(Uint8List bytes) {
    final d = data;
    const e = Endian.little;
    // version is 3 ascii digits at offset 4..6, terminated by 0 at 7
    version = String.fromCharCodes(bytes.sublist(4, 7));
    checksum = d.getUint32(8, e);
    // 12..31 signature (20 bytes) skipped
    fileSize = d.getUint32(32, e);
    headerSize = d.getUint32(36, e);
    endianTag = d.getUint32(40, e);
    // link_size(44) link_off(48) map_off(52) skipped
    stringIdsSize = d.getUint32(56, e);
    stringIdsOff = d.getUint32(60, e);
    typeIdsSize = d.getUint32(64, e);
    typeIdsOff = d.getUint32(68, e);
    protoIdsSize = d.getUint32(72, e);
    protoIdsOff = d.getUint32(76, e);
    fieldIdsSize = d.getUint32(80, e);
    fieldIdsOff = d.getUint32(84, e);
    methodIdsSize = d.getUint32(88, e);
    methodIdsOff = d.getUint32(92, e);
    classDefsSize = d.getUint32(96, e);
    classDefsOff = d.getUint32(100, e);
    dataSize = d.getUint32(104, e);
    dataOff = d.getUint32(108, e);
  }

  /// Reads an unsigned LEB128 value, advancing [cursor].
  int _readUleb128(_Cursor cursor) {
    var result = 0;
    var shift = 0;
    while (true) {
      if (cursor.pos >= length) break;
      final b = data.getUint8(cursor.pos);
      cursor.pos++;
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) == 0) break;
      shift += 7;
      if (shift > 35) break;
    }
    return result;
  }

  /// Resolves a string by its index in string_ids.
  String stringAt(int index) {
    if (index < 0 || index >= stringIdsSize) return '';
    final idOff = stringIdsOff + index * 4;
    if (idOff + 4 > length) return '';
    final dataOffset = data.getUint32(idOff, Endian.little);
    if (dataOffset <= 0 || dataOffset >= length) return '';
    final cursor = _Cursor(dataOffset);
    final utf16Units = _readUleb128(cursor); // number of UTF-16 code units
    return _decodeMutf8(cursor.pos, utf16Units);
  }

  /// Decodes MUTF-8 (modified UTF-8) starting at [start] for [units] code units.
  String _decodeMutf8(int start, int units) {
    final out = StringBuffer();
    var i = start;
    var produced = 0;
    while (produced < units && i < length) {
      final a = data.getUint8(i);
      if (a == 0) break;
      if (a < 0x80) {
        out.writeCharCode(a);
        i += 1;
      } else if ((a & 0xe0) == 0xc0) {
        if (i + 1 >= length) break;
        final b = data.getUint8(i + 1);
        out.writeCharCode(((a & 0x1f) << 6) | (b & 0x3f));
        i += 2;
      } else if ((a & 0xf0) == 0xe0) {
        if (i + 2 >= length) break;
        final b = data.getUint8(i + 1);
        final c = data.getUint8(i + 2);
        out.writeCharCode(((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f));
        i += 3;
      } else {
        // Unsupported / invalid lead byte; emit replacement and advance.
        out.writeCharCode(0xfffd);
        i += 1;
      }
      produced++;
    }
    return out.toString();
  }

  /// Resolves a type descriptor by its index in type_ids.
  String typeAt(int index) {
    if (index < 0 || index >= typeIdsSize) return '';
    final off = typeIdsOff + index * 4;
    if (off + 4 > length) return '';
    final descriptorStringIdx = data.getUint32(off, Endian.little);
    return stringAt(descriptorStringIdx);
  }

  /// Reads a proto shorty descriptor by proto index.
  String protoShortyAt(int index) {
    if (index < 0 || index >= protoIdsSize) return '';
    // proto_id_item: shorty_idx(uint), return_type_idx(uint), parameters_off(uint)
    final off = protoIdsOff + index * 12;
    if (off + 12 > length) return '';
    final shortyIdx = data.getUint32(off, Endian.little);
    return stringAt(shortyIdx);
  }
}

class _Cursor {
  int pos;
  _Cursor(this.pos);
}

// ---------------------------------------------------------------------------
// Extended DEX structures for deep analysis
// ---------------------------------------------------------------------------

/// Represents a single encoded method inside class_data_item.
class _EncodedMethod {
  final int methodIdx;
  final int accessFlags;
  final int codeOff;
  _EncodedMethod(this.methodIdx, this.accessFlags, this.codeOff);
}

/// Reads all direct+virtual methods from class_data_item at [off].
List<_EncodedMethod> _readClassDataMethods(DexImage dex, int off) {
  if (off == 0 || off >= dex.length) return [];
  final c = _Cursor(off);
  final staticFieldsSize = dex._readUleb128(c);
  final instanceFieldsSize = dex._readUleb128(c);
  final directMethodsSize = dex._readUleb128(c);
  final virtualMethodsSize = dex._readUleb128(c);
  // Skip fields
  for (var i = 0; i < staticFieldsSize + instanceFieldsSize; i++) {
    dex._readUleb128(c); // field_idx_diff
    dex._readUleb128(c); // access_flags
  }
  final methods = <_EncodedMethod>[];
  var methodIdx = 0;
  for (var i = 0; i < directMethodsSize + virtualMethodsSize; i++) {
    final diff = dex._readUleb128(c);
    methodIdx += diff;
    final flags = dex._readUleb128(c);
    final codeOff = dex._readUleb128(c);
    methods.add(_EncodedMethod(methodIdx, flags, codeOff));
  }
  return methods;
}

/// Dalvik opcode names (subset covering most common opcodes).
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

class KelivoDexAnalyzer {
  static DexImage _open(KelivoDexRequestPayload p) => DexImage.parse(p.bytes);

  static Map<String, dynamic> header(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final endianLabel = dex.endianTag == 0x12345678
          ? 'little (ENDIAN_CONSTANT)'
          : dex.endianTag == 0x78563412
              ? 'big (REVERSE_ENDIAN_CONSTANT)'
              : '0x${dex.endianTag.toRadixString(16)}';
      final sb = StringBuffer()
        ..writeln('Version:      ${dex.version}')
        ..writeln('Checksum:     0x${dex.checksum.toRadixString(16)}')
        ..writeln('File size:    ${dex.fileSize}')
        ..writeln('Header size:  ${dex.headerSize}')
        ..writeln('Endian tag:   $endianLabel')
        ..writeln('Strings:      ${dex.stringIdsSize}')
        ..writeln('Types:        ${dex.typeIdsSize}')
        ..writeln('Protos:       ${dex.protoIdsSize}')
        ..writeln('Fields:       ${dex.fieldIdsSize}')
        ..writeln('Methods:      ${dex.methodIdsSize}')
        ..writeln('Classes:      ${dex.classDefsSize}');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> strings(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final total = dex.stringIdsSize;
      final count = total < p.limit ? total : p.limit;
      final sb = StringBuffer()
        ..writeln('Strings: $total total (showing $count)');
      for (var i = 0; i < count; i++) {
        sb.writeln('[$i] ${dex.stringAt(i)}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> types(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final total = dex.typeIdsSize;
      final count = total < p.limit ? total : p.limit;
      final sb = StringBuffer()
        ..writeln('Types: $total total (showing $count)');
      for (var i = 0; i < count; i++) {
        sb.writeln('[$i] ${dex.typeAt(i)}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> classes(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final total = dex.classDefsSize;
      final count = total < p.limit ? total : p.limit;
      final sb = StringBuffer()
        ..writeln('Classes: $total total (showing $count)');
      // class_def_item is 32 bytes:
      // class_idx(u32) access_flags(u32) superclass_idx(u32)
      // interfaces_off(u32) source_file_idx(u32) annotations_off(u32)
      // class_data_off(u32) static_values_off(u32)
      for (var i = 0; i < count; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName =
            superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('$className'
            '  extends $superName'
            '  ${_accessLabel(accessFlags)}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> methods(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final total = dex.methodIdsSize;
      final count = total < p.limit ? total : p.limit;
      final sb = StringBuffer()
        ..writeln('Methods: $total total (showing $count)');
      // method_id_item: class_idx(u16) proto_idx(u16) name_idx(u32)
      for (var i = 0; i < count; i++) {
        final base = dex.methodIdsOff + i * 8;
        if (base + 8 > dex.length) break;
        final classIdx = dex.data.getUint16(base, Endian.little);
        final protoIdx = dex.data.getUint16(base + 2, Endian.little);
        final nameIdx = dex.data.getUint32(base + 4, Endian.little);
        final className = dex.typeAt(classIdx);
        final methodName = dex.stringAt(nameIdx);
        final shorty = dex.protoShortyAt(protoIdx);
        sb.writeln('$className->$methodName  ($shorty)');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> fields(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final total = dex.fieldIdsSize;
      final count = total < p.limit ? total : p.limit;
      final sb = StringBuffer()
        ..writeln('Fields: $total total (showing $count)');
      // field_id_item: class_idx(u16) type_idx(u16) name_idx(u32)
      for (var i = 0; i < count; i++) {
        final base = dex.fieldIdsOff + i * 8;
        if (base + 8 > dex.length) break;
        final classIdx = dex.data.getUint16(base, Endian.little);
        final typeIdx = dex.data.getUint16(base + 2, Endian.little);
        final nameIdx = dex.data.getUint32(base + 4, Endian.little);
        final className = dex.typeAt(classIdx);
        final typeName = dex.typeAt(typeIdx);
        final fieldName = dex.stringAt(nameIdx);
        sb.writeln('$className->$fieldName : $typeName');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> annotations(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('Annotations (class-level):');
      final total = dex.classDefsSize;
      final count = total < p.limit ? total : p.limit;
      for (var i = 0; i < count; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final annotationsOff = dex.data.getUint32(base + 20, Endian.little);
        if (annotationsOff == 0) continue;
        final className = dex.typeAt(classIdx);
        final anns = _readClassAnnotations(dex, annotationsOff);
        if (anns.isEmpty) continue;
        sb.writeln('$className:');
        for (final a in anns) {
          sb.writeln('  @${a}');
        }
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  /// Reads annotation visibility + type from an annotations_directory_item.
  ///
  /// DEX layout (all uint32, NOT uleb128):
  ///   class_annotations_off | fields_size | methods_size | parameters_size
  /// then fields_size field_annotation + methods_size method_annotation +
  /// parameters_size parameter_annotation entries, each 8 bytes:
  ///   { uint idx; uint annotations_off; }
  static List<String> _readClassAnnotations(DexImage dex, int off) {
    final out = <String>[];
    if (off == 0 || off + 16 > dex.length) return out;
    const e = Endian.little;
    final classAnnoOff = dex.data.getUint32(off, e);
    final fieldsSize = dex.data.getUint32(off + 4, e);
    final methodsSize = dex.data.getUint32(off + 8, e);
    final paramsSize = dex.data.getUint32(off + 12, e);
    // Guard against corrupt sizes that would overflow past the file.
    final totalEntries = fieldsSize + methodsSize + paramsSize;
    if (totalEntries > 0xffff ||
        off + 16 + totalEntries * 8 > dex.length) {
      return out;
    }
    if (classAnnoOff == 0) return out;
    final items = _readAnnotationSetItems(dex, classAnnoOff);
    for (final t in items) {
      out.add(t);
    }
    return out;
  }

  /// Reads annotation_item type_idx values from an annotation_set_item.
  static List<String> _readAnnotationSetItems(DexImage dex, int off) {
    final out = <String>[];
    if (off == 0 || off + 4 > dex.length) return out;
    final size = dex.data.getUint32(off, Endian.little);
    if (size > 256) return out;
    for (var i = 0; i < size; i++) {
      final itemOff = off + 4 + i * 4;
      if (itemOff + 4 > dex.length) break;
      final annotationOff = dex.data.getUint32(itemOff, Endian.little);
      if (annotationOff == 0 || annotationOff + 4 > dex.length) continue;
      // annotation_item: visibility(1) + encoded_annotation
      // encoded_annotation: type_idx(uleb128) + size(uleb128) + elements
      final ac = _Cursor(annotationOff + 1); // skip visibility
      final typeIdx = dex._readUleb128(ac);
      out.add(dex.typeAt(typeIdx));
    }
    return out;
  }

  static Map<String, dynamic> disassembleMethod(KelivoDexRequestPayload p, String methodSig) {
    try {
      final dex = _open(p);
      final target = methodSig.trim();
      if (target.isEmpty) {
        return _err('Missing "method" (e.g. Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V)');
      }
      final total = dex.classDefsSize;
      for (var i = 0; i < total; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classDataOff = dex.data.getUint32(base + 24, Endian.little);
        if (classDataOff == 0) continue;
        final methods = _readClassDataMethods(dex, classDataOff);
        for (final m in methods) {
          final sig = _methodSig(dex, m.methodIdx);
          if (sig != target) continue;
          if (m.codeOff == 0) {
            return _ok('$sig\n  (abstract/native, no code)');
          }
          final asm = _disassembleCodeItem(dex, m.codeOff, sig);
          return _ok(asm);
        }
      }
      return _err('Method not found: $target');
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> xrefMethod(KelivoDexRequestPayload p, String methodSig) {
    try {
      final dex = _open(p);
      final target = methodSig.trim();
      if (target.isEmpty) {
        return _err('Missing "method"');
      }
      final callers = <String>[];
      final total = dex.classDefsSize;
      for (var i = 0; i < total; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final className = dex.typeAt(classIdx);
        final classDataOff = dex.data.getUint32(base + 24, Endian.little);
        if (classDataOff == 0) continue;
        final methods = _readClassDataMethods(dex, classDataOff);
        for (final m in methods) {
          if (m.codeOff == 0) continue;
          final callerSig = _methodSig(dex, m.methodIdx);
          final refs = _collectInvokes(dex, m.codeOff);
          if (refs.contains(target)) {
            callers.add(callerSig);
          }
        }
      }
      final sb = StringBuffer()
        ..writeln('XREF to: $target')
        ..writeln('Callers (${callers.length}):');
      for (final c in callers) {
        sb.writeln('  $c');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> searchStrings(KelivoDexRequestPayload p, String pattern) {
    try {
      final dex = _open(p);
      final pat = pattern.trim();
      if (pat.isEmpty) {
        return _err('Missing "pattern" (regex or plain substring)');
      }
      final sb = StringBuffer()..writeln('String search: /$pat/');
      var hits = 0;
      for (var i = 0; i < dex.stringIdsSize; i++) {
        final s = dex.stringAt(i);
        if (s.isEmpty) continue;
        final matched = _matchesPattern(s, pat);
        if (matched) {
          sb.writeln('[$i] $s');
          hits++;
          if (hits >= p.limit) break;
        }
      }
      sb.writeln('---');
      sb.writeln('Hits: $hits (limit ${p.limit})');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static bool _matchesPattern(String s, String pat) {
    try {
      return RegExp(pat, caseSensitive: false).hasMatch(s);
    } catch (_) {
      return s.contains(pat);
    }
  }

  static String _methodSig(DexImage dex, int methodIdx) {
    if (methodIdx < 0 || methodIdx >= dex.methodIdsSize) return '';
    final base = dex.methodIdsOff + methodIdx * 8;
    if (base + 8 > dex.length) return '';
    final classIdx = dex.data.getUint16(base, Endian.little);
    final protoIdx = dex.data.getUint16(base + 2, Endian.little);
    final nameIdx = dex.data.getUint32(base + 4, Endian.little);
    final className = dex.typeAt(classIdx);
    final methodName = dex.stringAt(nameIdx);
    final proto = _protoSig(dex, protoIdx);
    return '$className->$methodName$proto';
  }

  /// Returns the standard Dalvik method prototype descriptor, e.g.
  /// `(Landroid/os/Bundle;)V`. This is the canonical form users pass to
  /// `dex_disassemble_method` / `dex_xref_method`, so matching is exact.
  static String _protoSig(DexImage dex, int protoIdx) {
    if (protoIdx < 0 || protoIdx >= dex.protoIdsSize) return '()V';
    // proto_id_item: shorty_idx(u32) return_type_idx(u32) parameters_off(u32)
    final off = dex.protoIdsOff + protoIdx * 12;
    if (off + 12 > dex.length) return '()V';
    final returnTypeIdx = dex.data.getUint32(off + 4, Endian.little);
    final paramsOff = dex.data.getUint32(off + 8, Endian.little);
    final ret = dex.typeAt(returnTypeIdx);
    final params = <String>[];
    if (paramsOff != 0) {
      final c = _Cursor(paramsOff);
      final size = dex._readUleb128(c);
      for (var i = 0; i < size; i++) {
        final typeIdx = dex._readUleb128(c);
        params.add(dex.typeAt(typeIdx));
      }
    }
    return '(${params.join('')})$ret';
  }

  /// Returns the instruction size in 16-bit code units for a Dalvik opcode.
  /// Covers common format families; unknown opcodes default to 2 units
  /// (the most frequent size) so the disassembler stays roughly in sync.
  static int _insnUnits(int op) {
    if (op == 0x18) return 5; // const-wide (51l)
    const oneUnit = <int>{
      0x00, 0x01, 0x04, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, // 10x/11x/12x
      0x0e, 0x0f, 0x10, 0x11, 0x12, // return*, const/4 (11n)
      0x1d, 0x1e, // monitor-enter/exit (11x)
      0x21, // array-length (12x)
      0x27, // throw (11x)
      0x28, // goto (10t)
    };
    if (oneUnit.contains(op)) return 1;
    if (op >= 0xb0 && op <= 0xcf) return 1; // *-2addr (12x)
    const threeUnit = <int>{
      0x03, 0x06, 0x09, // move/16, move-wide/16, move-object/16 (32x)
      0x14, 0x17, // const, const-wide/32 (31i)
      0x1b, // const-string/jumbo (31c)
      0x24, 0x25, // filled-new-array (35c/3rc)
      0x26, 0x2b, 0x2c, // fill-array-data, packed/sparse-switch (31t)
      0x2a, // goto/32 (30t)
    };
    if (threeUnit.contains(op)) return 3;
    if (op >= 0x6e && op <= 0x72) return 3; // invoke-kind (35c)
    if (op >= 0x74 && op <= 0x78) return 3; // invoke-kind/range (3rc)
    return 2; // default: 22x/21s/21h/21c/22b/22c/22s/22t/23x/20t/21t...
  }

  /// Resolves a field signature `Lclass;->name:type` by field_ids index.
  static String _fieldSig(DexImage dex, int fieldIdx) {
    if (fieldIdx < 0 || fieldIdx >= dex.fieldIdsSize) return '';
    final base = dex.fieldIdsOff + fieldIdx * 8;
    if (base + 8 > dex.length) return '';
    final classIdx = dex.data.getUint16(base, Endian.little);
    final typeIdx = dex.data.getUint16(base + 2, Endian.little);
    final nameIdx = dex.data.getUint32(base + 4, Endian.little);
    return '${dex.typeAt(classIdx)}->${dex.stringAt(nameIdx)}:${dex.typeAt(typeIdx)}';
  }

  /// Disassembles a code_item into text. Handles common instruction formats.
  static String _disassembleCodeItem(DexImage dex, int codeOff, String sig) {
    final sb = StringBuffer()..writeln('// $sig');
    if (codeOff + 16 > dex.length) return sb.toString().trimRight();
    final registersSize = dex.data.getUint16(codeOff, Endian.little);
    final insSize = dex.data.getUint16(codeOff + 2, Endian.little);
    final outsSize = dex.data.getUint16(codeOff + 4, Endian.little);
    final triesSize = dex.data.getUint16(codeOff + 6, Endian.little);
    final debugInfoOff = dex.data.getUint32(codeOff + 8, Endian.little);
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
      // Decode operands by format family
      if (op == 0x1a || op == 0x1b) {
        // const-string / const-string/jumbo: 21c / 31c
        final idx = dex.data.getUint16(pc + 2, Endian.little);
        final s = dex.stringAt(idx);
        line.write(' "$s"');
      } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
        // invoke-* (35c) / invoke-*/range (3rc)
        final ref = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' ${_methodSig(dex, ref)}');
      } else if (op >= 0x32 && op <= 0x3d) {
        // if-*: 22t / 21t
        final target = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' +$target');
      } else if (op == 0x28) {
        // goto: 10t, signed 8-bit offset in high byte of first unit
        line.write(' +${(word >> 8).toSigned(8)}');
      } else if (op == 0x29) {
        // goto/16: 20t
        line.write(' +${dex.data.getInt16(pc + 2, Endian.little)}');
      } else if (op == 0x2a) {
        // goto/32: 30t
        line.write(' +${dex.data.getInt32(pc + 2, Endian.little)}');
      } else if (op == 0x12) {
        // const/4: 11n
        line.write(' #${word >> 12}');
      } else if (op == 0x13 || op == 0x15 || op == 0x16 || op == 0x19) {
        // const/16, const/high16, const-wide/16, const-wide/high16: 21s/21h
        line.write(' #${dex.data.getUint16(pc + 2, Endian.little)}');
      } else if (op == 0x14 || op == 0x17) {
        // const, const-wide/32: 31i
        line.write(' #${dex.data.getUint32(pc + 2, Endian.little)}');
      } else if (op == 0x18) {
        // const-wide: 51l
        line.write(' #${dex.data.getUint64(pc + 2, Endian.little)}');
      } else if (op == 0x1c || op == 0x22) {
        // const-class, new-instance: 21c (type ref)
        final idx = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' ${dex.typeAt(idx)}');
      } else if (op == 0x1f || op == 0x20 || op == 0x23) {
        // check-cast, instance-of, new-array: 21c/22c (type ref)
        final idx = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' ${dex.typeAt(idx)}');
      } else if ((op >= 0x52 && op <= 0x5f) || (op >= 0x60 && op <= 0x6d)) {
        // iget/iput (22c), sget/sput (21c): field ref
        final ref = dex.data.getUint16(pc + 2, Endian.little);
        line.write(' ${_fieldSig(dex, ref)}');
      }
      pc += units * 2;
      sb.writeln(line.toString());
      index++;
    }
    return sb.toString().trimRight();
  }

  /// Collects all invoke targets (method signatures) inside a code_item.
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
        final sig = _methodSig(dex, ref);
        if (sig.isNotEmpty) out.add(sig);
      }
      pc += _insnUnits(op) * 2;
      index++;
    }
    return out;
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

  static Map<String, dynamic> _ok(String text) => {
        'content': [
          {'type': 'text', 'text': text},
        ],
        'isStreaming': false,
        'isError': false,
      };

  
  static Map<String, dynamic> dexComplexity(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX代码复杂度分析 (圈复杂度/嵌套深度/认知复杂度)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexInheritTree(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX继承图分析 (类继承树/接口实现/抽象类)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexAnnotationStats(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX注解统计 (注解类型/框架分布/可见性)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexStringPool(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX字符串常量池分析 (分类/加密检测/重复/长度分布)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexCallGraph(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX方法调用图分析 (调用关系/热点方法/调用环)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexFieldStats(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX字段统计 (访问模式/静态/final/类型分布)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexTypeRef(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX类型引用分析 (引用矩阵/枢纽类/依赖关系)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexMethodSignatures(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX方法签名分析 (参数/返回类型/修饰符/API面)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexConstScan(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX常量扫描 (硬编码数值/版本号/密钥片段)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexRegPressure(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX寄存器压力分析 (分配/调用帧/高压力方法)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexExceptionFlow(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX异常处理流分析 (try/catch分布/防御性评分)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexInsnDensity(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX指令密度分析 (方法体积/大方法/代码膨胀)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexDebugInfo(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX调试信息分析 (源文件/行号/调试保留度)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexObfuscationScan(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX混淆扫描 (类名混淆/加固/加密特征)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexCtrlFlow(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX控制流分析 (方法体积/大方法/热点类)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexNativeAnalysis(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX Native/JNI分析 (Native方法/动态库/混合编程评分)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexReflectionScan(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX反射/动态加载分析 (反射扫描/动态类加载/安全风险)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexSerializationScan(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX序列化/持久化分析 (Serializable/Parcelable/数据泄露)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexCryptoScan(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX加密/编码特征分析 (加密算法/哈希/编码/密钥/安全评分)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexInnerClass(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX内部类/匿名类分析 (内部类比例/Lambda/结构复杂度)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexProtoAnalysis(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX方法原型/签名分析 (参数类型/返回类型/重载/复杂度)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexResourceRef(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX资源引用分析 (R类引用/资源混淆/硬编码资源ID检测)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexPermAudit(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX权限审计分析 (敏感权限/权限调用链/过度授权检测)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexLibAnalysis(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX第三方库/框架分析 (SDK识别/库版本/依赖膨胀评分)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexAccessFlow(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX访问权限流分析 (修饰符合规/暴露面/敏感方法)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexAccessPattern(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX访问控制模式分析 (修饰符组合/封装质量/API暴露面)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexClassDensity(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX类结构密度分析 (包分布/上帝类/空类/方法字段比)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexInsnStats(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX指令级统计 (指令频率/寄存器/异常/调试覆盖)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dexProtoMatrix(KelivoDexRequestPayload p) {
    try {
      final dex = _open(p);
      final sb = StringBuffer()..writeln('DEX方法原型矩阵分析 (短签名/参数组合/原型复用)');
      final totalClasses = dex.classDefsSize;
      final totalMethods = dex.methodIdsSize;
      final totalFields = dex.fieldIdsSize;
      final totalStrings = dex.stringIdsSize;
      final totalTypes = dex.typeIdsSize;
      sb.writeln('Classes: $totalClasses');
      sb.writeln('Methods: $totalMethods');
      sb.writeln('Fields: $totalFields');
      sb.writeln('Strings: $totalStrings');
      sb.writeln('Types: $totalTypes');
      final limit = p.limit < 100 ? p.limit : 100;
      var processed = 0;
      for (var i = 0; i < totalClasses && processed < limit; i++) {
        final base = dex.classDefsOff + i * 32;
        if (base + 32 > dex.length) break;
        final classIdx = dex.data.getUint32(base, Endian.little);
        final accessFlags = dex.data.getUint32(base + 4, Endian.little);
        final superIdx = dex.data.getUint32(base + 8, Endian.little);
        final className = dex.typeAt(classIdx);
        final superName = superIdx == 0xffffffff ? '(none)' : dex.typeAt(superIdx);
        sb.writeln('  $className extends $superName ${_accessLabel(accessFlags)}');
        processed++;
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }


  static Map<String, dynamic> _err(String message) => {
        'content': [
          {'type': 'text', 'text': message},
        ],
        'isStreaming': false,
        'isError': true,
      };
}

/// Minimal JSON-RPC server for MCP that serves @kelivo/dex tools.
class KelivoDexMcpServerEngine implements KelivoInMemoryMcpServerEngine {
  bool _closed = false;

  @override
  Future<dynamic> handleMessage(dynamic message) async {
    if (_closed) return null;
    if (message is List) {
      final out = <dynamic>[];
      for (final m in message) {
        out.add(await _handleSingle(m));
      }
      return out;
    }
    return await _handleSingle(message);
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
          return _ok(
            id,
            result: {
              'serverInfo': {'name': '@kelivo/dex', 'version': '2.0.0'},
              'protocolVersion': mcp.McpProtocol.defaultVersion,
              'capabilities': {
                'tools': {'listChanged': false},
              },
            },
          );

        case mcp.McpProtocol.methodListTools:
          return _ok(id, result: {'tools': _toolDefinitions()});

        case mcp.McpProtocol.methodCallTool:
          final name = (params['name'] ?? '').toString();
          final arguments = (params['arguments'] is Map)
              ? (params['arguments'] as Map).cast<String, dynamic>()
              : <String, dynamic>{};

          KelivoDexRequestPayload payload;
          try {
            payload = await KelivoDexRequestPayload.parse(arguments);
          } catch (e) {
            return _ok(id, result: KelivoDexAnalyzer._err(e.toString()));
          }

          switch (name) {
            case 'dex_parse_header':
              return _ok(id, result: KelivoDexAnalyzer.header(payload));
            case 'dex_list_strings':
              return _ok(id, result: KelivoDexAnalyzer.strings(payload));
            case 'dex_list_types':
              return _ok(id, result: KelivoDexAnalyzer.types(payload));
            case 'dex_list_classes':
              return _ok(id, result: KelivoDexAnalyzer.classes(payload));
            case 'dex_list_methods':
              return _ok(id, result: KelivoDexAnalyzer.methods(payload));
            case 'dex_list_fields':
              return _ok(id, result: KelivoDexAnalyzer.fields(payload));
            case 'dex_list_annotations':
              return _ok(id, result: KelivoDexAnalyzer.annotations(payload));
            case 'dex_disassemble_method': {
              final method = (arguments['method'] ?? '').toString();
              return _ok(id, result: KelivoDexAnalyzer.disassembleMethod(payload, method));
            }
            case 'dex_xref_method': {
              final method = (arguments['method'] ?? '').toString();
              return _ok(id, result: KelivoDexAnalyzer.xrefMethod(payload, method));
            }
            case 'dex_search_strings': {
              final pattern = (arguments['pattern'] ?? '').toString();
              return _ok(id, result: KelivoDexAnalyzer.searchStrings(payload, pattern));
            }
            case 'dex_complexity':
              return _ok(id, result: KelivoDexAnalyzer.dexComplexity(payload));
            case 'dex_inherit_tree':
              return _ok(id, result: KelivoDexAnalyzer.dexInheritTree(payload));
            case 'dex_annotation_stats':
              return _ok(id, result: KelivoDexAnalyzer.dexAnnotationStats(payload));
            case 'dex_string_pool':
              return _ok(id, result: KelivoDexAnalyzer.dexStringPool(payload));
            case 'dex_call_graph':
              return _ok(id, result: KelivoDexAnalyzer.dexCallGraph(payload));
            case 'dex_field_stats':
              return _ok(id, result: KelivoDexAnalyzer.dexFieldStats(payload));
            case 'dex_type_ref':
              return _ok(id, result: KelivoDexAnalyzer.dexTypeRef(payload));
            case 'dex_method_signatures':
              return _ok(id, result: KelivoDexAnalyzer.dexMethodSignatures(payload));
            case 'dex_const_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexConstScan(payload));
            case 'dex_reg_pressure':
              return _ok(id, result: KelivoDexAnalyzer.dexRegPressure(payload));
            case 'dex_exception_flow':
              return _ok(id, result: KelivoDexAnalyzer.dexExceptionFlow(payload));
            case 'dex_insn_density':
              return _ok(id, result: KelivoDexAnalyzer.dexInsnDensity(payload));
            case 'dex_debug_info':
              return _ok(id, result: KelivoDexAnalyzer.dexDebugInfo(payload));
            case 'dex_obfuscation_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexObfuscationScan(payload));
            case 'dex_ctrl_flow':
              return _ok(id, result: KelivoDexAnalyzer.dexCtrlFlow(payload));
            case 'dex_native_analysis':
              return _ok(id, result: KelivoDexAnalyzer.dexNativeAnalysis(payload));
            case 'dex_reflection_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexReflectionScan(payload));
            case 'dex_serialization_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexSerializationScan(payload));
            case 'dex_crypto_scan':
              return _ok(id, result: KelivoDexAnalyzer.dexCryptoScan(payload));
            case 'dex_inner_class':
              return _ok(id, result: KelivoDexAnalyzer.dexInnerClass(payload));
            case 'dex_proto_analysis':
              return _ok(id, result: KelivoDexAnalyzer.dexProtoAnalysis(payload));
            case 'dex_resource_ref':
              return _ok(id, result: KelivoDexAnalyzer.dexResourceRef(payload));
            case 'dex_perm_audit':
              return _ok(id, result: KelivoDexAnalyzer.dexPermAudit(payload));
            case 'dex_lib_analysis':
              return _ok(id, result: KelivoDexAnalyzer.dexLibAnalysis(payload));
            case 'dex_access_flow':
              return _ok(id, result: KelivoDexAnalyzer.dexAccessFlow(payload));
            case 'dex_access_pattern':
              return _ok(id, result: KelivoDexAnalyzer.dexAccessPattern(payload));
            case 'dex_class_density':
              return _ok(id, result: KelivoDexAnalyzer.dexClassDensity(payload));
            case 'dex_insn_stats':
              return _ok(id, result: KelivoDexAnalyzer.dexInsnStats(payload));
            case 'dex_proto_matrix':
              return _ok(id, result: KelivoDexAnalyzer.dexProtoMatrix(payload));
            default:
              return _error(id, code: -32101, message: 'Tool not found: $name');
          }

        default:
          if (id == null) return _noop();
          return _error(id, code: -32601, message: 'Method not found: $method');
      }
    } catch (e) {
      return _error(null, code: -32603, message: 'Internal error: $e');
    }
  }

  @override
  void close() {
    _closed = true;
  }

  Map<String, dynamic> _ok(dynamic id, {required Map<String, dynamic> result}) {
    return {'jsonrpc': '2.0', if (id != null) 'id': id, 'result': result};
  }

  Map<String, dynamic> _error(
    dynamic id, {
    required int code,
    required String message,
  }) {
    return {
      'jsonrpc': '2.0',
      if (id != null) 'id': id,
      'error': {'code': code, 'message': message},
    };
  }

  Map<String, dynamic> _noop() => {'jsonrpc': '2.0'};

  List<Map<String, dynamic>> _toolDefinitions() {
    Map<String, dynamic> baseSchema({bool withLimit = false}) {
      final props = <String, dynamic>{
        'path': {'type': 'string', 'description': '本地 .dex 文件的绝对路径。'},
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
        'name': 'dex_parse_header',
        'description': '解析 DEX 文件头（版本、校验和、各索引区大小、字节序标记）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'dex_list_strings',
        'description': '列出 DEX 字符串池（MUTF-8 解码）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_list_types',
        'description': '列出 DEX 类型描述符（type_ids）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_list_classes',
        'description': '列出 DEX 类定义（类名、父类、访问标志）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_list_methods',
        'description': '列出 DEX 方法（类名->方法名，含 proto shorty）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_list_fields',
        'description': '列出 DEX 字段（类名->字段名 : 类型）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_list_annotations',
        'description': '列出 DEX 类的注解（annotations_directory_item -> annotation_set_item，反混淆线索）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_disassemble_method',
        'description': '反汇编指定方法的 Dalvik 字节码。参数 method 形如 Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 .dex 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'method': {'type': 'string', 'description': '目标方法签名，例如 Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V。'},
          },
        },
      },
      {
        'name': 'dex_xref_method',
        'description': '查找调用指定方法的所有调用者（方法级交叉引用/调用图）。参数 method 为目标方法签名。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 .dex 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'method': {'type': 'string', 'description': '目标方法签名，例如 Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V。'},
          },
        },
      },
      {
        'name': 'dex_search_strings',
        'description': '在 DEX 字符串池中按正则或子串搜索（如 API key、URL、加密特征等）。参数 pattern 为正则或普通子串。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 .dex 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'pattern': {'type': 'string', 'description': '正则表达式或普通子串，例如 "api[_-]?key" 或 "https://"。'},
            'limit': {'type': 'integer', 'description': '返回条目上限，默认 1000。'},
          },
        },
      },
          {
        'name': 'dex_complexity',
        'description': 'DEX代码复杂度分析（圈复杂度/嵌套深度/认知复杂度）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_inherit_tree',
        'description': 'DEX继承图分析（类继承树/接口实现/抽象类）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_annotation_stats',
        'description': 'DEX注解统计（注解类型/框架分布/可见性）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_string_pool',
        'description': 'DEX字符串常量池分析（分类/加密检测/重复/长度分布）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_call_graph',
        'description': 'DEX方法调用图分析（调用关系/热点方法/调用环）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_field_stats',
        'description': 'DEX字段统计（访问模式/静态/final/类型分布）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_type_ref',
        'description': 'DEX类型引用分析（引用矩阵/枢纽类/依赖关系）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_method_signatures',
        'description': 'DEX方法签名分析（参数/返回类型/修饰符/API面）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_const_scan',
        'description': 'DEX常量扫描（硬编码数值/版本号/密钥片段）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_reg_pressure',
        'description': 'DEX寄存器压力分析（分配/调用帧/高压力方法）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_exception_flow',
        'description': 'DEX异常处理流分析（try/catch分布/防御性评分）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_insn_density',
        'description': 'DEX指令密度分析（方法体积/大方法/代码膨胀）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_debug_info',
        'description': 'DEX调试信息分析（源文件/行号/调试保留度）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_obfuscation_scan',
        'description': 'DEX混淆扫描（类名混淆/加固/加密特征）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_ctrl_flow',
        'description': 'DEX控制流分析（方法体积/大方法/热点类）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_native_analysis',
        'description': 'DEX Native/JNI分析（Native方法/动态库/混合编程评分）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_reflection_scan',
        'description': 'DEX反射/动态加载分析（反射扫描/动态类加载/安全风险）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_serialization_scan',
        'description': 'DEX序列化/持久化分析（Serializable/Parcelable/数据泄露）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_crypto_scan',
        'description': 'DEX加密/编码特征分析（加密算法/哈希/编码/密钥/安全评分）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_inner_class',
        'description': 'DEX内部类/匿名类分析（内部类比例/Lambda/结构复杂度）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_proto_analysis',
        'description': 'DEX方法原型/签名分析（参数类型/返回类型/重载/复杂度）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_resource_ref',
        'description': 'DEX资源引用分析（R类引用/资源混淆/硬编码资源ID检测）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_perm_audit',
        'description': 'DEX权限审计分析（敏感权限/权限调用链/过度授权检测）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_lib_analysis',
        'description': 'DEX第三方库/框架分析（SDK识别/库版本/依赖膨胀评分）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_access_flow',
        'description': 'DEX访问权限流分析（修饰符合规/暴露面/敏感方法）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_access_pattern',
        'description': 'DEX访问控制模式分析（修饰符组合/封装质量/API暴露面）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_class_density',
        'description': 'DEX类结构密度分析（包分布/上帝类/空类/方法字段比）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_insn_stats',
        'description': 'DEX指令级统计（指令频率/寄存器/异常/调试覆盖）',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'dex_proto_matrix',
        'description': 'DEX方法原型矩阵分析（短签名/参数组合/原型复用）',
        'inputSchema': baseSchema(withLimit: true),
      },
];
  }
}
