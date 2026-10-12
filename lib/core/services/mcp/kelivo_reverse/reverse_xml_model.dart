part of kelivo_reverse_server;

class _AxmlStringPool {
  final List<String> _strings = [];
  final Map<String, int> _indexMap = {};

  int add(String s) {
    if (s.isEmpty && _strings.isNotEmpty) {
      // Don't add duplicate empty string
      if (_indexMap.containsKey('')) return _indexMap['']!;
    }
    if (_indexMap.containsKey(s)) return _indexMap[s]!;
    _indexMap[s] = _strings.length;
    _strings.add(s);
    return _indexMap[s]!;
  }

  int indexOf(String s) {
    return _indexMap[s] ?? 0;
  }

  Uint8List serialize() {
    final count = _strings.length;
    final stringBytes = <int>[];
    final offsets = <int>[];
    var currentOffset = 0;

    for (final s in _strings) {
      offsets.add(currentOffset);
      final encoded = s.codeUnits; // UTF-16LE approximation
      final charCount = s.length;
      _writeU16Buf(stringBytes, charCount);
      // Write UTF-16LE bytes
      for (int i = 0; i < s.length; i++) {
        stringBytes.add(s.codeUnitAt(i) & 0xff);
        stringBytes.add((s.codeUnitAt(i) >> 8) & 0xff);
      }
      stringBytes.add(0);
      stringBytes.add(0); // null terminator
      currentOffset += 2 + s.length * 2 + 2;
    }

    // 4-byte alignment
    final padding = (4 - (stringBytes.length % 4)) % 4;
    for (int i = 0; i < padding; i++) stringBytes.add(0);

    final offsetsSize = count * 4;
    final chunkSize = 28 + offsetsSize + stringBytes.length;

    final data = <int>[];
    _writeU16Buf(data, 0x0001); // CHUNK_STRING_POOL
    _writeU16Buf(data, 28); // headerSize
    _writeU32Buf(data, chunkSize);
    _writeU32Buf(data, count);
    _writeU32Buf(data, 0); // styleCount
    _writeU32Buf(data, 0x000); // flags (UTF-16)
    _writeU32Buf(data, 28 + offsetsSize); // stringsStart
    _writeU32Buf(data, 0); // stylesStart

    for (final off in offsets) {
      _writeU32Buf(data, off);
    }

    data.addAll(stringBytes);
    return Uint8List.fromList(data);
  }

  static void _writeU16Buf(List<int> buf, int v) {
    buf.add(v & 0xff);
    buf.add((v >> 8) & 0xff);
  }

  static void _writeU32Buf(List<int> buf, int v) {
    buf.add(v & 0xff);
    buf.add((v >> 8) & 0xff);
    buf.add((v >> 16) & 0xff);
    buf.add((v >> 24) & 0xff);
  }
}

class _XmlAttribute {
  final String name;
  final String value;
  _XmlAttribute(this.name, this.value);
}

class _XmlElement {
  final String tag;
  final List<_XmlAttribute> attrs;
  final List<_XmlElement> children;

  _XmlElement(this.tag, {List<_XmlAttribute>? attrs, List<_XmlElement>? children})
      : attrs = attrs ?? [],
        children = children ?? [];

  /// Lightweight regex-based XML parser sufficient for AndroidManifest.xml.
  static _XmlElement parse(String xml) {
    // Remove XML declaration
    xml = xml.replaceAll(RegExp(r'<\?xml[^>]*\?>'), '').trim();
    // Remove comments
    xml = xml.replaceAll(RegExp(r'<!--[\s\S]*?-->'), '').trim();

    int pos = 0;
    _XmlElement? parseElement() {
      // Find opening tag
      final openMatch = RegExp(r'<(\w[\w.-]*)').firstMatch(xml.substring(pos));
      if (openMatch == null) return null;
      final tagName = openMatch.group(1)!;
      pos += openMatch.end;

      // Parse attributes until >
      final attrs = <_XmlAttribute>[];
      while (pos < xml.length && xml[pos] != '>' && xml[pos] != '/') {
        // Skip whitespace
        while (pos < xml.length && ' \t\n\r'.contains(xml[pos])) pos++;
        if (pos >= xml.length || xml[pos] == '>' || xml[pos] == '/') break;
        // Read attr name
        final nameMatch = RegExp(r'([\w:.-]+)\s*=\s*"([^"]*)"').firstMatch(xml.substring(pos));
        if (nameMatch == null) break;
        attrs.add(_XmlAttribute(nameMatch.group(1)!, nameMatch.group(2)!));
        pos += nameMatch.end;
      }

      // Check for self-closing
      if (pos < xml.length && xml[pos] == '/') {
        pos += 2; // skip />
        return _XmlElement(tagName, attrs: attrs);
      }
      pos++; // skip >

      // Parse children until closing tag
      final children = <_XmlElement>[];
      while (pos < xml.length) {
        // Skip whitespace
        while (pos < xml.length && ' \t\n\r'.contains(xml[pos])) pos++;
        if (pos >= xml.length) break;
        // Check for closing tag
        if (xml[pos] == '<' && pos + 1 < xml.length && xml[pos + 1] == '/') {
          // Find end of closing tag
          final closeEnd = xml.indexOf('>', pos);
          pos = closeEnd + 1;
          break;
        }
        // Parse child element
        final child = parseElement();
        if (child != null) {
          children.add(child);
        } else {
          break;
        }
      }

      return _XmlElement(tagName, attrs: attrs, children: children);
    }

    final result = parseElement();
    return result ?? _XmlElement('manifest');
  }
}

