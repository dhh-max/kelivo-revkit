part of kelivo_reverse_server;

// =========================================================================
// resources.arsc 完整资源表解析器 — 纯Dart实现
// 移植自 Python apk_reverse_engine/core/resource_parser.py
// =========================================================================

class _ArscParser {
  final Uint8List data;
  int pos = 0;
  late int n;
  List<String> stringPool = [];
  bool isUtf8 = false;
  int poolStringsOff = 0;
  List<Map<String, dynamic>> packages = [];
  Map<String, dynamic>? lastResult;

  _ArscParser(this.data) : n = data.length;

  static const int _chunkStringPool = 0x0001;
  static const int _chunkTable = 0x0002;
  static const int _chunkTablePackage = 0x0200;
  static const int _chunkTableType = 0x0201;
  static const int _chunkTableTypeSpec = 0x0202;
  static const int _chunkTableLibrary = 0x0203;

  static const Map<int, String> _typeNames = {
    0x00: 'null',
    0x01: 'reference',
    0x02: 'attribute',
    0x03: 'string',
    0x04: 'float',
    0x05: 'dimension',
    0x06: 'fraction',
    0x10: 'int_dec',
    0x11: 'int_hex',
    0x12: 'boolean',
    0x1c: 'color_argb8',
    0x1d: 'color_rgb8',
    0x1e: 'color_argb4',
    0x1f: 'color_rgb4',
  };

  static const Map<int, String> _altPkgNames = {0x01: 'android'};

  int r8() {
    final v = data[pos]; pos++; return v;
  }
  int r16() {
    final bd = ByteData.sublistView(data);
    final v = bd.getUint16(pos, Endian.little); pos += 2; return v;
  }
  int r32() {
    final bd = ByteData.sublistView(data);
    final v = bd.getUint32(pos, Endian.little); pos += 4; return v;
  }
  int peek32(int off) {
    if (off + 4 > n) return 0;
    final bd = ByteData.sublistView(data);
    return bd.getUint32(off, Endian.little);
  }

  String _readString(int off) {
    try {
      if (isUtf8) {
        var p = off;
        if (data[p] & 0x80 != 0) p += 2; else p += 1;
        int bc;
        if (data[p] & 0x80 != 0) {
          bc = ((data[p] & 0x7f) << 8) | data[p + 1]; p += 2;
        } else {
          bc = data[p]; p += 1;
        }
        if (bc == 0) return '';
        return String.fromCharCodes(data.sublist(p, p + bc));
      } else {
        final bd = ByteData.sublistView(data);
        final cc = bd.getUint16(off, Endian.little);
        var p = off + 2;
        if (cc == 0) return '';
        return String.fromCharCodes(
            data.sublist(p, p + cc * 2).buffer.asUint16List());
      }
    } catch (e) {
      return '';
    }
  }

  String _readStrAt(int off, bool utf8) {
    try {
      if (utf8) {
        var p = off;
        if (data[p] & 0x80 != 0) p += 2; else p += 1;
        int bc;
        if (data[p] & 0x80 != 0) {
          bc = ((data[p] & 0x7f) << 8) | data[p + 1]; p += 2;
        } else {
          bc = data[p]; p += 1;
        }
        if (bc == 0) return '';
        return String.fromCharCodes(data.sublist(p, p + bc));
      } else {
        final bd = ByteData.sublistView(data);
        final cc = bd.getUint16(off, Endian.little);
        var p = off + 2;
        if (cc == 0) return '';
        return String.fromCharCodes(
            data.sublist(p, p + cc * 2).buffer.asUint16List());
      }
    } catch (e) {
      return '';
    }
  }

  int _parseStringPool() {
    final bd = ByteData.sublistView(data);
    final chunkStart = pos;
    final chunkSize = r32();
    final stringCount = r32();
    final styleCount = r32();
    final flags = r32();
    final stringsStart = r32();
    final stylesStart = r32();
    isUtf8 = (flags & 0x100) != 0;

    final strOffsets = <int>[];
    for (var i = 0; i < stringCount; i++) {
      strOffsets.add(r32());
    }
    for (var i = 0; i < styleCount; i++) {
      r32();
    }

    final dataStart = chunkStart + stringsStart;
    final pool = <String>[];
    for (final off in strOffsets) {
      pool.add(_readString(dataStart + off));
    }
    stringPool = pool;
    poolStringsOff = dataStart;
    return chunkStart + chunkSize;
  }

  List<String> _readStringPoolAt(int off) {
    if (off + 8 > n) return [];
    final bd = ByteData.sublistView(data);
    final chunkSize = bd.getUint32(off + 4, Endian.little);
    final stringCount = bd.getUint32(off + 8, Endian.little);
    final styleCount = bd.getUint32(off + 12, Endian.little);
    final flags = bd.getUint32(off + 16, Endian.little);
    final stringsStart = bd.getUint32(off + 20, Endian.little);
    final utf8 = (flags & 0x100) != 0;

    final strOffsets = <int>[];
    for (var i = 0; i < stringCount; i++) {
      strOffsets.add(bd.getUint32(off + 28 + i * 4, Endian.little));
    }
    final dataStart = off + stringsStart;
    final pool = <String>[];
    for (final o in strOffsets) {
      pool.add(_readStrAt(dataStart + o, utf8));
    }
    return pool;
  }

  Map<String, dynamic> _parseConfig(int off) {
    final bd = ByteData.sublistView(data);
    final size = peek32(off);
    if (size < 4) return {};
    try {
      final v4 = peek32(off + 4);
      final v8 = peek32(off + 8);
      final v12 = peek32(off + 12);
      final v16 = peek32(off + 16);
      final v20 = peek32(off + 20);
      final v24 = peek32(off + 24);
      final v28 = peek32(off + 28);

      final cfg = <String, dynamic>{
        'size': size,
        'mcc': v4 & 0xffff,
        'mnc': (v4 >> 16) & 0xffff,
        'orientation': v8 & 0xff,
        'touchscreen': (v8 >> 8) & 0xff,
        'density': (v8 >> 16) & 0xffff,
        'keyboard': v12 & 0xff,
        'navigation': (v12 >> 8) & 0xff,
        'inputFlags': (v12 >> 16) & 0xff,
        'screenWidth': (v12 >> 24) & 0xff,
        'screenHeight': v16 & 0xff,
        'sdkVersion': v16 >> 16,
        'minorVersion': v20 & 0xff,
        'screenLayout': (v20 >> 8) & 0xff,
        'uiMode': (v20 >> 16) & 0xff,
        'smallestScreenWidthDp': v20 >> 24,
        'screenWidthDp': v24 & 0xffff,
        'screenHeightDp': v24 >> 16,
        'screenLayout2': v28 & 0xff,
        'colorMode': (v28 >> 8) & 0xff,
        'locale': '',
      };

      if (size >= 32) {
        final lo = peek32(off + 32);
        final lang = (lo & 0xff) != 0
            ? String.fromCharCode(lo & 0xff) +
                String.fromCharCode((lo >> 8) & 0xff)
            : '';
        final reg = ((lo >> 16) & 0xff) != 0
            ? String.fromCharCode((lo >> 16) & 0xff) +
                String.fromCharCode((lo >> 24) & 0xff)
            : '';
        if (lang.isNotEmpty || reg.isNotEmpty) {
          cfg['locale'] = [lang, reg].where((s) => s.isNotEmpty).join('-');
        }
      }
      return cfg;
    } catch (e) {
      return {};
    }
  }

  String _configDesc(Map<String, dynamic> cfg) {
    final parts = <String>[];
    if (cfg['locale'] != null && (cfg['locale'] as String).isNotEmpty) {
      parts.add(cfg['locale']);
    }
    final ori = cfg['orientation'] ?? 0;
    if (ori == 1) parts.add('port');
    else if (ori == 2) parts.add('land');
    final d = cfg['density'] ?? 0;
    if (d == 0xffff) parts.add('nodpi');
    else if (d == 120) parts.add('ldpi');
    else if (d == 160) parts.add('mdpi');
    else if (d == 240) parts.add('hdpi');
    else if (d == 320) parts.add('xhdpi');
    else if (d == 480) parts.add('xxhdpi');
    else if (d == 640) parts.add('xxxhdpi');
    else if (d > 0) parts.add('${d}dpi');
    final sw = cfg['smallestScreenWidthDp'] ?? 0;
    if (sw != 0) parts.add('sw${sw}dp');
    final swd = cfg['screenWidthDp'] ?? 0;
    if (swd != 0) parts.add('w${swd}dp');
    final shd = cfg['screenHeightDp'] ?? 0;
    if (shd != 0) parts.add('h${shd}dp');
    final sdk = cfg['sdkVersion'] ?? 0;
    if (cfg['screenWidth'] == 0 && sdk != 0) parts.add('v$sdk');
    return parts.isNotEmpty ? parts.join('-') : 'default';
  }

  Map<String, dynamic> _parseValue(int off) {
    final bd = ByteData.sublistView(data);
    final size = bd.getUint16(off, Endian.little);
    final res0 = data[off + 2];
    final dataType = data[off + 3];
    final vdata = bd.getUint32(off + 4, Endian.little);

    final result = <String, dynamic>{
      'size': size,
      'res0': res0,
      'type': _typeNames[dataType] ?? '0x${dataType.toRadixString(16).padLeft(2, '0')}',
      'type_raw': dataType,
      'data': vdata,
    };

    if (dataType == 0x03) {
      // TYPE_STRING
      result['value'] = (vdata >= 0 && vdata < stringPool.length)
          ? stringPool[vdata]
          : null;
    } else if (dataType == 0x01) {
      // TYPE_REFERENCE
      result['value'] = '@0x${vdata.toRadixString(16).padLeft(8, '0')}';
      result['ref_id'] = vdata;
    } else if (dataType == 0x12) {
      // TYPE_INT_BOOLEAN
      result['value'] = vdata != 0;
    } else if (dataType == 0x04) {
      // TYPE_FLOAT
      result['value'] = bd.getFloat32(off + 4, Endian.little);
    } else if (dataType == 0x10 || dataType == 0x11) {
      result['value'] = vdata;
    } else if (dataType >= 0x1c && dataType <= 0x1f) {
      result['value'] = '#${vdata.toRadixString(16).padLeft(8, '0')}';
    } else {
      result['value'] = vdata;
    }
    return result;
  }

  Map<String, dynamic> _parseTypeSpec(int off) {
    final bd = ByteData.sublistView(data);
    final hs = bd.getUint16(off + 2, Endian.little);
    final cs = bd.getUint32(off + 4, Endian.little);
    final id = bd.getUint32(off + 8, Endian.little);
    final entryCount = bd.getUint32(off + 12, Endian.little);
    var p = off + hs;
    final flags = <int>[];
    final maxFlags = (cs - hs) ~/ 4;
    for (var i = 0; i < entryCount && i < maxFlags; i++) {
      flags.add(bd.getUint32(p, Endian.little));
      p += 4;
    }
    return {
      'id': id,
      'entry_count': entryCount,
      'flags': flags,
    };
  }

  Map<String, dynamic> _parseType(int off) {
    final bd = ByteData.sublistView(data);
    final hs = bd.getUint16(off + 2, Endian.little);
    final cs = bd.getUint32(off + 4, Endian.little);
    final id = bd.getUint32(off + 8, Endian.little);
    final entryCount = bd.getUint32(off + 12, Endian.little);
    final entriesStart = bd.getUint32(off + 16, Endian.little);
    final config = _parseConfig(off + 20);
    final configDesc = _configDesc(config);

    var pOffsets = off + 20 + ((config['size'] ?? 0) as int);
    pOffsets = (pOffsets + 3) & ~3;
    final entryOffsets = <int>[];
    for (var i = 0; i < entryCount; i++) {
      entryOffsets.add(bd.getUint32(pOffsets, Endian.little));
      pOffsets += 4;
    }

    final entries = <Map<String, dynamic>>[];
    for (var i = 0; i < entryOffsets.length; i++) {
      final eo = entryOffsets[i];
      if (eo == 0xffffffff) {
        entries.add({'index': i, 'name': '', 'values': [], 'present': false});
        continue;
      }
      final ep = off + entriesStart + eo;
      final entry = _parseEntry(ep);
      entry['index'] = i;
      entry['present'] = true;
      entries.add(entry);
    }

    return {
      'id': id,
      'config': config,
      'config_desc': configDesc,
      'entry_count': entryCount,
      'entries_start': entriesStart,
      'entries': entries,
    };
  }

  Map<String, dynamic> _parseEntry(int off) {
    final bd = ByteData.sublistView(data);
    final size = bd.getUint16(off, Endian.little);
    final flags = bd.getUint16(off + 2, Endian.little);
    final keyIdx = bd.getUint32(off + 4, Endian.little);
    final isComplex = (flags & 0x0001) != 0;

    final entry = <String, dynamic>{
      'size': size,
      'flags': flags,
      'is_complex': isComplex,
      'key_idx': keyIdx,
      'values': <Map<String, dynamic>>[],
      'map': <Map<String, dynamic>>[],
    };

    if (isComplex) {
      final parent = bd.getUint32(off + 8, Endian.little);
      final count = bd.getUint32(off + 12, Endian.little);
      entry['parent'] = parent;
      entry['map_count'] = count;
      var p = off + 16;
      for (var i = 0; i < count; i++) {
        if (p + 12 > n) break;
        final nameRef = bd.getUint32(p, Endian.little);
        final val = _parseValue(p + 8);
        (entry['map'] as List).add({'name_ref': nameRef, 'value': val});
        p += 12;
      }
    } else {
      final val = _parseValue(off + 8);
      (entry['values'] as List).add(val);
    }
    return entry;
  }

  Map<String, dynamic> _parsePackage(int chunkStart) {
    final bd = ByteData.sublistView(data);
    final hs = bd.getUint16(chunkStart + 2, Endian.little);
    final cs = bd.getUint32(chunkStart + 4, Endian.little);
    final id = bd.getUint32(chunkStart + 8, Endian.little);
    final nameRaw = data.sublist(chunkStart + 12, chunkStart + 12 + 128);
    final nameEnd = nameRaw.indexOf(0);
    final name = String.fromCharCodes(
        nameRaw.sublist(0, nameEnd >= 0 ? nameEnd : nameRaw.length));
    final typeStringsOff = bd.getUint32(chunkStart + 268, Endian.little);
    final keyStringsOff = bd.getUint32(chunkStart + 276, Endian.little);

    final pkg = <String, dynamic>{
      'id': id,
      'id_hex': '0x${id.toRadixString(16).padLeft(2, '0')}',
      'name': name.isNotEmpty ? name : (_altPkgNames[id] ?? ''),
      'type_strings': <String>[],
      'key_strings': <String>[],
      'type_specs': <Map<String, dynamic>>[],
      'types': <Map<String, dynamic>>[],
    };

    final body = chunkStart + hs;
    if (typeStringsOff != 0) {
      pkg['type_strings'] = _readStringPoolAt(chunkStart + typeStringsOff);
    }
    if (keyStringsOff != 0) {
      pkg['key_strings'] = _readStringPoolAt(chunkStart + keyStringsOff);
    }

    var p = body;
    final end = chunkStart + cs;
    while (p + 8 <= end) {
      final ct = bd.getUint16(p, Endian.little);
      final hs2 = bd.getUint16(p + 2, Endian.little);
      final cs2 = bd.getUint32(p + 4, Endian.little);
      if (cs2 < 8) break;
      if (ct == _chunkTableTypeSpec) {
        (pkg['type_specs'] as List).add(_parseTypeSpec(p));
      } else if (ct == _chunkTableType) {
        (pkg['types'] as List).add(_parseType(p));
      }
      p += cs2;
    }

    pkg['resource_count'] = (pkg['types'] as List)
        .fold<int>(0, (sum, t) => sum + (t['entries'] as List).length);
    return pkg;
  }

  Map<String, dynamic> parse() {
    if (n < 12) {
      return {'error': 'Data too small', 'package_count': 0, 'packages': []};
    }
    final bd = ByteData.sublistView(data);
    var pos2 = 0;
    final chunkType = bd.getUint16(pos2, Endian.little);
    final headerSize = bd.getUint16(pos2 + 2, Endian.little);
    final chunkSize = bd.getUint32(pos2 + 4, Endian.little);
    final packageCount = bd.getUint32(pos2 + 8, Endian.little);
    pos2 = headerSize;

    final info = <String, dynamic>{
      'chunk_type': chunkType,
      'header_size': headerSize,
      'chunk_size': chunkSize,
      'package_count': packageCount,
      'global_strings': <String>[],
      'packages': <Map<String, dynamic>>[],
    };

    if (pos2 + 8 <= n) {
      pos = pos2;
      final ct = r16();
      r16(); // hs
      r32(); // cs
      if (ct == _chunkStringPool) {
        pos = pos2;
        final poolEnd = _parseStringPool();
        info['global_strings'] = stringPool;
        pos2 = poolEnd;
      }
    }

    while (pos2 + 8 <= n) {
      final ct = bd.getUint16(pos2, Endian.little);
      final hs = bd.getUint16(pos2 + 2, Endian.little);
      final cs = bd.getUint32(pos2 + 4, Endian.little);
      if (cs < 8) break;
      if (ct == _chunkTablePackage) {
        (info['packages'] as List).add(_parsePackage(pos2));
      }
      pos2 += cs;
    }

    lastResult = info;
    packages = info['packages'];
    return info;
  }

  List<String> getPackageNames() {
    if (lastResult == null) return [];
    return (lastResult!['packages'] as List)
        .map((p) => (p as Map<String, dynamic>)['name'] as String)
        .toList();
  }

  List<String> getResourceTypes() {
    if (lastResult == null) return [];
    final out = <String>{};
    for (final p in lastResult!['packages'] as List) {
      out.addAll(((p as Map<String, dynamic>)['type_strings'] as List).cast<String>());
    }
    return out.toList()..sort();
  }

  List<Map<String, dynamic>> getResources() {
    if (lastResult == null) return [];
    final out = <Map<String, dynamic>>[];
    for (final pkg in lastResult!['packages'] as List) {
      final p = pkg as Map<String, dynamic>;
      final typeNames = p['type_strings'] as List;
      final keyNames = p['key_strings'] as List;
      for (final t in p['types'] as List) {
        final tp = t as Map<String, dynamic>;
        final tid = tp['id'] as int;
        final typeName = tid - 1 < typeNames.length
            ? typeNames[tid - 1]
            : 'type$tid';
        for (final e in tp['entries'] as List) {
          final entry = e as Map<String, dynamic>;
          if (entry['present'] != true) continue;
          final keyIdx = entry['key_idx'] as int;
          final keyName = keyIdx < keyNames.length
              ? keyNames[keyIdx]
              : 'key$keyIdx';
          final resId = ((p['id'] as int) << 24) |
              (tid << 16) |
              ((entry['index'] as int) & 0xffff);
          final item = <String, dynamic>{
            'type': typeName,
            'name': keyName,
            'res_id': '0x${resId.toRadixString(16).padLeft(8, '0')}',
            'config': tp['config_desc'],
          };
          if ((entry['values'] as List).isNotEmpty) {
            final v = (entry['values'] as List)[0] as Map<String, dynamic>;
            item['value'] = v['value'];
            item['value_type'] = v['type'];
          } else if ((entry['map'] as List).isNotEmpty) {
            item['value'] = 'map(${(entry['map'] as List).length})';
          }
          out.add(item);
        }
      }
    }
    return out;
  }

  Map<String, dynamic>? findResource(int resId) {
    if (lastResult == null) return null;
    final pkgId = (resId >> 24) & 0xff;
    final typeId = (resId >> 16) & 0xff;
    final entryIdx = resId & 0xffff;

    for (final pkg in lastResult!['packages'] as List) {
      final p = pkg as Map<String, dynamic>;
      if (p['id'] != pkgId) continue;
      final typeNames = p['type_strings'] as List;
      final keyNames = p['key_strings'] as List;
      for (final t in p['types'] as List) {
        final tp = t as Map<String, dynamic>;
        if (tp['id'] != typeId) continue;
        final typeName = typeId - 1 < typeNames.length
            ? typeNames[typeId - 1]
            : 'type$typeId';
        for (final e in tp['entries'] as List) {
          final entry = e as Map<String, dynamic>;
          if (entry['index'] == entryIdx && entry['present'] == true) {
            final keyIdx = entry['key_idx'] as int;
            final keyName = keyIdx < keyNames.length
                ? keyNames[keyIdx]
                : 'key$keyIdx';
            return {
              'res_id': '0x${resId.toRadixString(16).padLeft(8, '0')}',
              'type': typeName,
              'name': keyName,
              'config': tp['config_desc'],
              'values': entry['values'],
              'map': entry['map'],
            };
          }
        }
      }
    }
    return null;
  }
}
