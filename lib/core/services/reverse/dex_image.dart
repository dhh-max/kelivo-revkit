import 'dart:typed_data';

/// Minimal DEX reader. DEX is always little-endian in practice.
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
    version = String.fromCharCodes(bytes.sublist(4, 7));
    checksum = d.getUint32(8, e);
    fileSize = d.getUint32(32, e);
    headerSize = d.getUint32(36, e);
    endianTag = d.getUint32(40, e);
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

  int _readUleb128(DexCursor cursor) {
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

  String stringAt(int index) {
    if (index < 0 || index >= stringIdsSize) return '';
    final idOff = stringIdsOff + index * 4;
    if (idOff + 4 > length) return '';
    final dataOffset = data.getUint32(idOff, Endian.little);
    if (dataOffset <= 0 || dataOffset >= length) return '';
    final cursor = DexCursor(dataOffset);
    final utf16Units = _readUleb128(cursor);
    return _decodeMutf8(cursor.pos, utf16Units);
  }

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
        out.writeCharCode(0xfffd);
        i += 1;
      }
      produced++;
    }
    return out.toString();
  }

  String typeAt(int index) {
    if (index < 0 || index >= typeIdsSize) return '';
    final off = typeIdsOff + index * 4;
    if (off + 4 > length) return '';
    final descriptorStringIdx = data.getUint32(off, Endian.little);
    return stringAt(descriptorStringIdx);
  }

  String protoShortyAt(int index) {
    if (index < 0 || index >= protoIdsSize) return '';
    final off = protoIdsOff + index * 12;
    if (off + 12 > length) return '';
    final shortyIdx = data.getUint32(off, Endian.little);
    return stringAt(shortyIdx);
  }
}

class DexCursor {
  int pos;
  DexCursor(this.pos);
}

/// Represents a single encoded method inside class_data_item.
class EncodedMethod {
  final int methodIdx;
  final int accessFlags;
  final int codeOff;
  EncodedMethod(this.methodIdx, this.accessFlags, this.codeOff);
}

/// Reads all direct+virtual methods from class_data_item at [off].
List<EncodedMethod> readClassDataMethods(DexImage dex, int off) {
  if (off == 0 || off >= dex.length) return [];
  final c = DexCursor(off);
  final staticFieldsSize = dex._readUleb128(c);
  final instanceFieldsSize = dex._readUleb128(c);
  final directMethodsSize = dex._readUleb128(c);
  final virtualMethodsSize = dex._readUleb128(c);
  for (var i = 0; i < staticFieldsSize + instanceFieldsSize; i++) {
    dex._readUleb128(c);
    dex._readUleb128(c);
  }
  final methods = <EncodedMethod>[];
  var methodIdx = 0;
  for (var i = 0; i < directMethodsSize + virtualMethodsSize; i++) {
    final diff = dex._readUleb128(c);
    methodIdx += diff;
    final flags = dex._readUleb128(c);
    final codeOff = dex._readUleb128(c);
    methods.add(EncodedMethod(methodIdx, flags, codeOff));
  }
  return methods;
}

/// Dalvik opcode names (subset covering most common opcodes).
const kDalvikOpcodes = <int, String>{
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