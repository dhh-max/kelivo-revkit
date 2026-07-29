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
/// - dex_parse_header  → DEX header (version, checksum, counts, endian tag)
/// - dex_list_strings  → string_ids pool (MUTF-8 decoded)
/// - dex_list_types    → type_ids (resolved to descriptor strings)
/// - dex_list_classes  → class_defs (class descriptor, superclass, access)
/// - dex_list_methods  → method_ids (class.name + proto shorty)
/// - dex_list_fields   → field_ids (class.name : type)

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
              'serverInfo': {'name': '@kelivo/dex', 'version': '0.1.0'},
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
    ];
  }
}
