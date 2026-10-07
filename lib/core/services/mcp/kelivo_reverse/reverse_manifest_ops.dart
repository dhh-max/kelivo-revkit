part of kelivo_reverse_server;

// =========================================================================
// AXML 二进制标签操作 — 直接在二进制层面查找/删除/替换标签
// 移植自 Python apk_reverse_engine/core/manifest_ops.py
// =========================================================================

/// AXML 标签节点
class _AxmlNode {
  final String type; // 'start' | 'end'
  final String name;
  final List<Map<String, dynamic>> attrs;
  int startOffset;
  int endOffset;
  int headerSize;
  int chunkSize;
  int attrStart;

  _AxmlNode(this.type, this.name, [List<Map<String, dynamic>>? attrs])
      : attrs = attrs ?? [],
        startOffset = 0,
        endOffset = 0,
        headerSize = 0,
        chunkSize = 0,
        attrStart = 0;
}

/// AXML 二进制解析与操作工具类
class _ManifestOps {
  static const int _axmlMagic = 0x00080003;
  static const int _chunkStringPool = 0x001C0001;
  static const int _chunkStartTag = 0x00100102;
  static const int _chunkEndTag = 0x00100103;
  static const int _chunkResourceId = 0x00080180;
  static const int _attrHeaderSize = 20;

  /// 解析 AXML 二进制数据，返回标签列表
  static Map<String, dynamic> parseAxmlTags(Uint8List data,
      {bool offsets = false}) {
    final bd = ByteData.sublistView(data);
    int pos = 0;
    final n = data.length;

    int r32() {
      final v = bd.getUint32(pos, Endian.little);
      pos += 4;
      return v;
    }

    int r16() {
      final v = bd.getUint16(pos, Endian.little);
      pos += 2;
      return v;
    }

    final magic = r32();
    if (magic != _axmlMagic) {
      return {'error': 'Invalid AXML magic: 0x${magic.toRadixString(16)}'};
    }
    r32(); // file_size

    // ── 解析字符串池 ──
    final poolStart = pos;
    final poolChunkType = r32();
    final poolChunkSize = r32();
    final stringCount = r32();
    final styleCount = r32();
    final flags = r32();
    final isUtf8 = (flags & 0x100) != 0;
    final stringsOffset = r32();
    r32(); // styles_offset

    final strOffsets = <int>[];
    for (var i = 0; i < stringCount; i++) {
      strOffsets.add(r32());
    }
    for (var i = 0; i < styleCount; i++) {
      r32();
    }

    final stringsDataStart = poolStart + stringsOffset;
    final strings = <String>[];

    String readStr(int off) {
      if (off < 0 || off >= n) return '';
      try {
        if (isUtf8) {
          int cc;
          if (data[off] & 0x80 != 0) {
            cc = ((data[off] & 0x7f) << 8) | data[off + 1];
            off += 2;
          } else {
            cc = data[off];
            off += 1;
          }
          if (data[off] & 0x80 != 0) {
            final bc = ((data[off] & 0x7f) << 8) | data[off + 1];
            off += 2;
          } else {
            final bc = data[off];
            off += 1;
          }
          // bc is byte count
          final bc = data[off - 1] & 0x80 != 0
              ? ((data[off - 2] & 0x7f) << 8) | data[off - 1]
              : data[off - 1];
          if (bc == 0) return '';
          return String.fromCharCodes(data.sublist(off, off + bc));
        } else {
          final cc = bd.getUint16(off, Endian.little);
          off += 2;
          if (cc == 0) return '';
          final raw = data.sublist(off, off + cc * 2);
          return String.fromCharCodes(
              raw.buffer.asUint16List());
        }
      } catch (e) {
        return '';
      }
    }

    for (final o in strOffsets) {
      strings.add(readStr(stringsDataStart + o));
    }

    // 跳到 pool 末尾
    pos = poolStart + poolChunkSize;

    // 跳过 ResourceID 块
    while (pos + 8 <= n) {
      final ct = r16();
      final hs = r16();
      final cs = r32();
      if (ct == 0x0180) {
        pos += cs - 8;
      } else {
        pos -= 8;
        break;
      }
    }

    // ── 解析标签树 ──
    final tags = <_AxmlNode>[];
    final xmlns = <List<String>>[];

    while (pos + 8 <= n) {
      final ct = r16();
      final hs = r16();
      final cs = r32();
      final chunkStart = pos - 8;

      if (ct == 0x0100) {
        // START_NAMESPACE
        r32(); // line
        r32(); // comment
        final pi = r32();
        final ui = r32();
        final prefix =
            (pi >= 0 && pi < strings.length) ? strings[pi] : '';
        final uri =
            (ui >= 0 && ui < strings.length) ? strings[ui] : '';
        xmlns.add([prefix, uri]);
      } else if (ct == 0x0102) {
        // START_TAG
        r32(); // line
        r32(); // comment
        final nsIdx = r32();
        final nameIdx = r32();
        final attrStart = r16();
        final attrSize = r16();
        final attrCount = r16();
        r16(); // idIndex
        r16(); // classIndex
        r16(); // styleIndex

        final name = (nameIdx >= 0 && nameIdx < strings.length)
            ? strings[nameIdx]
            : '?$nameIdx';

        final attrs = <Map<String, dynamic>>[];
        var attrPos = chunkStart + hs + attrStart;

        for (var i = 0; i < attrCount; i++) {
          final ani = bd.getUint32(attrPos + 4, Endian.little);
          final vsi = bd.getUint32(attrPos + 8, Endian.little);
          final vt = bd.getUint32(attrPos + 12, Endian.little);
          final vd = bd.getUint32(attrPos + 16, Endian.little);
          final an = (ani >= 0 && ani < strings.length)
              ? strings[ani]
              : '?$ani';
          String val;
          if (vt >> 24 == 3) {
            val = (vsi >= 0 && vsi < strings.length)
                ? strings[vsi]
                : '?$vsi';
          } else {
            val = vd.toString();
          }
          attrs.add({
            'name': an,
            'value': val,
            'name_index': ani,
          });
          attrPos += _attrHeaderSize;
        }

        final node = _AxmlNode('start', name, attrs);
        if (offsets) {
          node.startOffset = chunkStart;
          node.endOffset = chunkStart + cs;
          node.headerSize = hs;
          node.chunkSize = cs;
          node.attrStart = attrStart;
        }
        tags.add(node);
      } else if (ct == 0x0103) {
        // END_TAG
        r32(); // line
        r32(); // comment
        final nsIdx = r32();
        final nameIdx = r32();
        final name = (nameIdx >= 0 && nameIdx < strings.length)
            ? strings[nameIdx]
            : '?$nameIdx';
        final node = _AxmlNode('end', name);
        if (offsets) {
          node.startOffset = chunkStart;
          node.endOffset = chunkStart + cs;
          node.headerSize = hs;
          node.chunkSize = cs;
        }
        tags.add(node);
      }
      pos = chunkStart + cs;
    }

    return {
      'tags': tags,
      'strings': strings,
      'is_utf8': isUtf8,
      'xmlns': xmlns,
    };
  }

  /// 在 AXML 中查找匹配的标签
  static List<Map<String, dynamic>> findTags(
    Uint8List axmlData, {
    String? tagName,
    String? attrName,
    String? attrValue,
  }) {
    final result = parseAxmlTags(axmlData, offsets: true);
    if (result.containsKey('error')) return [];
    final tags = result['tags'] as List<_AxmlNode>;
    final matched = <Map<String, dynamic>>[];

    for (final t in tags) {
      if (t.type != 'start') continue;
      if (tagName != null && t.name != tagName) continue;
      if (attrName != null) {
        var found = false;
        for (final a in t.attrs) {
          if (a['name'] == attrName) {
            if (attrValue == null || a['value'] == attrValue) {
              found = true;
            }
            break;
          }
        }
        if (!found) continue;
      }
      matched.add({
        'name': t.name,
        'attrs': t.attrs.map((a) => {'name': a['name'], 'value': a['value']}).toList(),
        'offset': t.startOffset,
        'size': t.chunkSize,
      });
    }
    return matched;
  }

  /// 从 AXML 中删除匹配的标签（及其子标签和对应的 END_TAG）
  static Uint8List removeTags(
    Uint8List axmlData,
    String tagName,
    String attrName,
    String attrValue,
  ) {
    final result = parseAxmlTags(axmlData, offsets: true);
    if (result.containsKey('error')) return axmlData;
    final tags = result['tags'] as List<_AxmlNode>;

    final startIndices = <int>[];
    for (var i = 0; i < tags.length; i++) {
      final t = tags[i];
      if (t.type != 'start') continue;
      if (t.name != tagName) continue;
      for (final a in t.attrs) {
        if (a['name'] == attrName && a['value'] == attrValue) {
          startIndices.add(i);
          break;
        }
      }
    }

    if (startIndices.isEmpty) return axmlData;

    final removes = <List<int>>[];
    for (final idx in startIndices) {
      final t = tags[idx];
      final start = t.startOffset;
      var depth = 0;
      var end = start + t.chunkSize;
      for (var j = idx; j < tags.length; j++) {
        if (tags[j].type == 'start') {
          depth++;
        } else if (tags[j].type == 'end') {
          depth--;
          if (depth == 0) {
            end = tags[j].endOffset;
            break;
          }
        }
      }
      removes.add([start, end]);
    }

    removes.sort((a, b) => b[0].compareTo(a[0]));
    final data = Uint8List.fromList(axmlData);
    final bd = ByteData.sublistView(data);

    for (final r in removes) {
      final start = r[0];
      final end = r[1];
      data.setRange(start, data.length - (end - start), data.sublist(end));
    }

    final newSize = data.length -
        removes.fold<int>(0, (sum, r) => sum + (r[1] - r[0]));
    final trimmed = data.sublist(0, newSize);
    final tbd = ByteData.sublistView(trimmed);
    tbd.setUint32(4, newSize, Endian.little);
    return trimmed;
  }

  /// 批量删除标签
  static Uint8List removeTagsByRule(
      Uint8List axmlData, List<List<String>> rules) {
    var data = axmlData;
    for (final rule in rules) {
      data = removeTags(data, rule[0], rule[1], rule[2]);
    }
    return data;
  }

  /// 替换 AXML 中指定标签的属性值（字符串池原地修改）
  static Uint8List replaceAttrValue(
    Uint8List axmlData,
    String tagName,
    String attrName,
    String oldValue,
    String newValue,
  ) {
    final result = parseAxmlTags(axmlData, offsets: true);
    if (result.containsKey('error')) return axmlData;
    final tags = result['tags'] as List<_AxmlNode>;
    final strings = result['strings'] as List<String>;
    final isUtf8 = result['is_utf8'] as bool;

    final replacements = <Map<String, dynamic>>[];
    for (final t in tags) {
      if (t.type != 'start') continue;
      if (tagName.isNotEmpty && t.name != tagName) continue;
      for (final a in t.attrs) {
        if (a['name'] == attrName && a['value'] == oldValue) {
          replacements.add({
            'string_index': a['name_index'],
            'old': oldValue,
            'new': newValue,
          });
        }
      }
    }

    if (replacements.isEmpty) return axmlData;

    final data = Uint8List.fromList(axmlData);
    final bd = ByteData.sublistView(data);
    final n = data.length;

    // 解析字符串池结构
    final poolStart = 8;
    if (bd.getUint32(poolStart, Endian.little) != _chunkStringPool) {
      return axmlData;
    }
    final poolChunkSize =
        bd.getUint32(poolStart + 4, Endian.little);
    final stringCount =
        bd.getUint32(poolStart + 8, Endian.little);
    final styleCount =
        bd.getUint32(poolStart + 12, Endian.little);
    final flags = bd.getUint32(poolStart + 16, Endian.little);
    final utf8 = (flags & 0x100) != 0;
    final stringsOff =
        bd.getUint32(poolStart + 20, Endian.little);

    final strOffsetsTableOff = poolStart + 28;
    final stringsDataStart = poolStart + stringsOff;

    final strOffsets = <int>[];
    for (var i = 0; i < stringCount; i++) {
      strOffsets.add(
          bd.getUint32(strOffsetsTableOff + i * 4, Endian.little));
    }

    for (final r in replacements) {
      final strIdx = r['string_index'] as int;
      final oldVal = r['old'] as String;
      final newVal = r['new'] as String;
      if (strIdx < 0 || strIdx >= strOffsets.length) continue;

      final strDataOff = stringsDataStart + strOffsets[strIdx];
      if (utf8) {
        // 跳过字符数和字节数头
        var off = strDataOff;
        if (data[off] & 0x80 != 0) {
          off += 2;
        } else {
          off += 1;
        }
        if (data[off] & 0x80 != 0) {
          off += 2;
        } else {
          off += 1;
        }
        final newEncoded = Uint8List.fromList(newVal.codeUnits);
        final oldEncoded = Uint8List.fromList(oldVal.codeUnits);
        if (newEncoded.length <= oldEncoded.length) {
          for (var i = 0; i < oldEncoded.length; i++) {
            data[off + i] = i < newEncoded.length
                ? newEncoded[i]
                : 0;
          }
        }
      } else {
        final off = strDataOff + 2;
        final newEncoded = <int>[];
        for (final c in newVal.codeUnits) {
          newEncoded.add(c & 0xFF);
          newEncoded.add((c >> 8) & 0xFF);
        }
        final oldEncoded = <int>[];
        for (final c in oldVal.codeUnits) {
          oldEncoded.add(c & 0xFF);
          oldEncoded.add((c >> 8) & 0xFF);
        }
        if (newEncoded.length <= oldEncoded.length) {
          for (var i = 0; i < oldEncoded.length; i++) {
            data[off + i] =
                i < newEncoded.length ? newEncoded[i] : 0;
          }
        }
      }
    }
    return data;
  }

  /// 获取第一个匹配标签的属性值
  static String? getAttrValue(
      Uint8List axmlData, String tagName, String attrName) {
    final tags = findTags(axmlData, tagName: tagName, attrName: attrName);
    if (tags.isEmpty) return null;
    for (final a in tags[0]['attrs'] as List) {
      if (a['name'] == attrName) return a['value'];
    }
    return null;
  }

  /// 获取所有匹配标签的属性值列表
  static List<String> getAllAttrValues(
      Uint8List axmlData, String tagName, String attrName) {
    final tags = findTags(axmlData, tagName: tagName, attrName: attrName);
    final values = <String>[];
    for (final t in tags) {
      for (final a in t['attrs'] as List) {
        if (a['name'] == attrName) values.add(a['value']);
      }
    }
    return values;
  }

  /// 删除指定组件声明
  static Uint8List removeComponent(
      Uint8List axmlData, String componentType, String className) {
    return removeTags(axmlData, componentType, 'name', className);
  }

  /// 替换启动 Activity 类名
  static Uint8List replaceLauncherActivity(
      Uint8List axmlData, String oldClass, String newClass) {
    return replaceAttrValue(
        axmlData, 'activity', 'name', oldClass, newClass);
  }
}
