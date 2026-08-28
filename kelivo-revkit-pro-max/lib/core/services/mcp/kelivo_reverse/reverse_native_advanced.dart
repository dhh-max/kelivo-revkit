part of kelivo_reverse_server;

// =========================================================================
// 原生SO文件高级补丁工具 — ARM/Thumb/AArch64/x86/x86_64
// 移植自 Python apk_reverse_engine/patching/native_patcher.py
// =========================================================================

class _NativePatcher {
  // ARM 指令常量
  static const int _armNop = 0xe1a00000;
  static const int _armRet = 0xe12fff1e;
  static const int _armMovR0_0 = 0xe3a00000;
  static const int _armMovR0_1 = 0xe3a00001;

  // Thumb 指令常量
  static const int _thumbNop = 0x46c0;
  static const int _thumbRet = 0x4770;
  static const int _thumbMovR0_0 = 0x2000;
  static const int _thumbMovR0_1 = 0x2001;

  // AArch64 指令常量
  static const int _aarch64Nop = 0xd503201f;
  static const int _aarch64Ret = 0xd65f03c0;
  static const int _aarch64MovR0_0 = 0xd2800000;
  static const int _aarch64MovR0_1 = 0xd2800020;
  static const int _aarch64Bkpt = 0xd4200000;

  // x86 指令常量
  static const int _x86Nop = 0x90;
  static const int _x86Ret = 0xc3;
  static const int _x86XorEaxEax = 0x31c0;

  static String detectArch(Uint8List data, int offset) {
    if (offset < 0 || offset + 4 > data.length) return 'unknown';
    final bd = ByteData.sublistView(data);
    final word = bd.getUint32(offset, Endian.little);

    // AArch64
    if ((word & 0xfc000000) == 0x14000000) return 'aarch64';
    if ((word & 0xff000000) == 0x54000000) return 'aarch64';
    if ((word & 0x1f000000) == 0x10000000) return 'aarch64';

    // ARM
    final cond = (word >> 28) & 0xf;
    if (cond != 0xf && cond <= 0xe) {
      if ((word & 0x0c000000) != 0x0c000000) return 'arm';
    }

    // Thumb
    final low = word & 0xffff;
    if (low >= 0x4800 && low <= 0x4fff) return 'thumb';
    if ((low & 0xf800) == 0x2000 || (low & 0xf800) == 0x2800) return 'thumb';

    // x86
    if (data[offset] == 0x55 || data[offset] == 0x48) return 'x86_64';
    if (data[offset] == 0x90 || data[offset] == 0xc3) return 'x86';

    return 'unknown';
  }

  static Uint8List patchHex(Uint8List data, String oldHex, String newHex) {
    final old = _hexToBytes(oldHex);
    final newBytes = _hexToBytes(newHex);
    final result = Uint8List.fromList(data);
    var idx = _indexOf(result, old);
    while (idx >= 0) {
      for (var i = 0; i < newBytes.length && i < old.length; i++) {
        result[idx + i] = newBytes[i];
      }
      idx = _indexOf(result, old, idx + 1);
    }
    return result;
  }

  static Uint8List patchHexAt(
      Uint8List data, int offset, String hexStr) {
    final newBytes = _hexToBytes(hexStr);
    if (offset < 0 || offset + newBytes.length > data.length) {
      throw ArgumentError('Invalid offset $offset or size ${newBytes.length}');
    }
    final result = Uint8List.fromList(data);
    for (var i = 0; i < newBytes.length; i++) {
      result[offset + i] = newBytes[i];
    }
    return result;
  }

  static Uint8List patchString(
    Uint8List data,
    String oldStr,
    String newStr, {
    int maxReplace = 1,
  }) {
    final old = Uint8List.fromList([...oldStr.codeUnits, 0]);
    final newBytes = Uint8List.fromList([...newStr.codeUnits, 0]);
    final effective = newBytes.length > old.length
        ? newBytes.sublist(0, old.length)
        : newBytes;
    final result = Uint8List.fromList(data);
    var count = 0;
    var idx = _indexOf(result, old);
    while (idx >= 0 && count < maxReplace) {
      for (var i = 0; i < effective.length; i++) {
        result[idx + i] = effective[i];
      }
      count++;
      idx = _indexOf(result, old, idx + 1);
    }
    return result;
  }

  static Uint8List patchBytes(
      Uint8List data, int offset, List<int> newBytes) {
    if (offset < 0 || offset + newBytes.length > data.length) {
      throw ArgumentError(
          'Invalid offset $offset or size ${newBytes.length}');
    }
    final result = Uint8List.fromList(data);
    for (var i = 0; i < newBytes.length; i++) {
      result[offset + i] = newBytes[i];
    }
    return result;
  }

  static Uint8List patchWord(
    Uint8List data,
    int offset,
    int value, {
    bool littleEndian = true,
  }) {
    final bd = ByteData(4);
    bd.setUint32(0, value,
        littleEndian ? Endian.little : Endian.big);
    return patchBytes(data, offset, bd.buffer.asUint8List().toList());
  }

  static Uint8List patchQword(
    Uint8List data,
    int offset,
    int value, {
    bool littleEndian = true,
  }) {
    final bd = ByteData(8);
    bd.setUint64(0, value,
        littleEndian ? Endian.little : Endian.big);
    return patchBytes(data, offset, bd.buffer.asUint8List().toList());
  }

  static Uint8List nopOut(
    Uint8List data,
    int offset,
    int count, {
    String arch = 'aarch64',
  }) {
    if (count <= 0) return data;
    final a = arch == 'unknown' ? detectArch(data, offset) : arch;
    final bd = ByteData(4);
    final result = Uint8List.fromList(data);

    if (a == 'aarch64' || a == 'arm') {
      bd.setUint32(0, a == 'aarch64' ? _aarch64Nop : _armNop,
          Endian.little);
      final nopBytes = bd.buffer.asUint8List();
      for (var i = 0; i < count; i++) {
        for (var j = 0; j < 4 && offset + i * 4 + j < result.length; j++) {
          result[offset + i * 4 + j] = nopBytes[j];
        }
      }
    } else if (a == 'thumb') {
      final nopBytes = Uint8List.fromList(
          [_thumbNop & 0xff, (_thumbNop >> 8) & 0xff]);
      for (var i = 0; i < count; i++) {
        for (var j = 0; j < 2 && offset + i * 2 + j < result.length; j++) {
          result[offset + i * 2 + j] = nopBytes[j];
        }
      }
    } else if (a == 'x86' || a == 'x86_64') {
      for (var i = 0; i < count && offset + i < result.length; i++) {
        result[offset + i] = _x86Nop;
      }
    }
    return result;
  }

  static Uint8List patchBranchToRet(
    Uint8List data,
    int offset, {
    String arch = 'aarch64',
  }) {
    final a = arch == 'unknown' ? detectArch(data, offset) : arch;
    final bd = ByteData(4);

    if (a == 'aarch64') {
      bd.setUint32(0, _aarch64Ret, Endian.little);
      return patchBytes(data, offset, bd.buffer.asUint8List().toList());
    } else if (a == 'arm') {
      bd.setUint32(0, _armRet, Endian.little);
      return patchBytes(data, offset, bd.buffer.asUint8List().toList());
    } else if (a == 'thumb') {
      final ret = Uint8List.fromList(
          [_thumbRet & 0xff, (_thumbRet >> 8) & 0xff]);
      return patchBytes(data, offset, ret);
    } else if (a == 'x86' || a == 'x86_64') {
      return patchBytes(data, offset, [_x86Ret]);
    }
    return data;
  }

  static Uint8List patchBranchToMovR0(
    Uint8List data,
    int offset,
    int value, {
    String arch = 'aarch64',
  }) {
    final a = arch == 'unknown' ? detectArch(data, offset) : arch;
    final bd = ByteData(4);

    if (a == 'aarch64') {
      final mov = value == 0 ? _aarch64MovR0_0 : _aarch64MovR0_0 + value * 0x20;
      bd.setUint32(0, mov, Endian.little);
      final movBytes = Uint8List.fromList(bd.buffer.asUint8List());
      bd.setUint32(0, _aarch64Ret, Endian.little);
      final retBytes = Uint8List.fromList(bd.buffer.asUint8List());
      return patchBytes(
          patchBytes(data, offset, movBytes), offset + 4, retBytes);
    } else if (a == 'arm') {
      final mov = _armMovR0_0 + value;
      bd.setUint32(0, mov, Endian.little);
      final movBytes = Uint8List.fromList(bd.buffer.asUint8List());
      bd.setUint32(0, _armRet, Endian.little);
      final retBytes = Uint8List.fromList(bd.buffer.asUint8List());
      return patchBytes(
          patchBytes(data, offset, movBytes), offset + 4, retBytes);
    } else if (a == 'thumb') {
      final mov = _thumbMovR0_0 + value;
      final movBytes = Uint8List.fromList(
          [mov & 0xff, (mov >> 8) & 0xff]);
      final retBytes = Uint8List.fromList(
          [_thumbRet & 0xff, (_thumbRet >> 8) & 0xff]);
      return patchBytes(
          patchBytes(data, offset, movBytes), offset + 2, retBytes);
    } else if (a == 'x86_64') {
      final patch = Uint8List.fromList(
          [_x86XorEaxEax & 0xff, (_x86XorEaxEax >> 8) & 0xff, _x86Ret]);
      return patchBytes(data, offset, patch);
    }
    return data;
  }

  static Uint8List patchJniFunction(
    Uint8List data,
    String oldFuncName,
    String newFuncName,
  ) {
    return patchString(data, oldFuncName, newFuncName, maxReplace: 100);
  }

  static Uint8List findAndNopJniCalls(
      Uint8List data, String jniFuncName) {
    final nameBytes = Uint8List.fromList(jniFuncName.codeUnits);
    final nullBytes = Uint8List(nameBytes.length);
    final result = Uint8List.fromList(data);
    var idx = _indexOf(result, nameBytes);
    while (idx >= 0) {
      for (var i = 0; i < nullBytes.length; i++) {
        result[idx + i] = 0;
      }
      idx = _indexOf(result, nameBytes, idx + 1);
    }
    return result;
  }

  static Uint8List patchElfEntrypoint(
      Uint8List data, int newEntryOffset) {
    if (data.length < 64) return data;
    final is64 = data[4] == 2;
    final little = data[5] == 1;
    final endian = little ? Endian.little : Endian.big;
    final bd = ByteData.sublistView(data);
    if (is64) {
      bd.setUint64(24, newEntryOffset, endian);
    } else {
      bd.setUint32(24, newEntryOffset, endian);
    }
    return data;
  }

  static Uint8List patchArmBranch(
    Uint8List data,
    int offset,
    int targetOffset, {
    bool bl = false,
    String arch = 'aarch64',
  }) {
    if (offset < 0 || offset + 4 > data.length) return data;
    final bd = ByteData(4);

    if (arch == 'aarch64') {
      final diff = targetOffset - offset;
      if (diff % 4 != 0) return data;
      final imm = diff ~/ 4;
      if (imm < -0x2000000 || imm > 0x1ffffff) return data;
      final instr = (bl ? 0x94000000 : 0x14000000) | (imm & 0x3ffffff);
      bd.setUint32(0, instr, Endian.little);
      return patchBytes(data, offset, bd.buffer.asUint8List().toList());
    } else if (arch == 'arm') {
      final diff = targetOffset - offset - 8;
      if (diff % 4 != 0) return data;
      final imm = diff ~/ 4;
      if (imm < -0x800000 || imm > 0x7fffff) return data;
      final instr = (bl ? 0xeb000000 : 0xea000000) | (imm & 0xffffff);
      bd.setUint32(0, instr, Endian.little);
      return patchBytes(data, offset, bd.buffer.asUint8List().toList());
    }
    return data;
  }

  static Uint8List insertBreakpoint(
    Uint8List data,
    int offset, {
    String arch = 'aarch64',
  }) {
    final bd = ByteData(4);
    if (arch == 'aarch64') {
      bd.setUint32(0, _aarch64Bkpt, Endian.little);
      return patchBytes(data, offset, bd.buffer.asUint8List().toList());
    } else if (arch == 'arm') {
      bd.setUint32(0, 0xe1200070, Endian.little);
      return patchBytes(data, offset, bd.buffer.asUint8List().toList());
    } else if (arch == 'thumb') {
      return patchBytes(data, offset, [0x00, 0xbe]);
    } else if (arch == 'x86' || arch == 'x86_64') {
      return patchBytes(data, offset, [0xcc]);
    }
    return patchBytes(data, offset, [0xcc]);
  }

  static List<int> findPattern(Uint8List data, String patternHex) {
    final pattern = _hexToBytes(patternHex);
    final offsets = <int>[];
    var start = 0;
    while (true) {
      final idx = _indexOf(data, pattern, start);
      if (idx < 0) break;
      offsets.add(idx);
      start = idx + 1;
    }
    return offsets;
  }

  static List<int> findStringOffsets(Uint8List data, String targetStr) {
    final target = Uint8List.fromList(targetStr.codeUnits);
    final offsets = <int>[];
    var start = 0;
    while (true) {
      final idx = _indexOf(data, target, start);
      if (idx < 0) break;
      offsets.add(idx);
      start = idx + 1;
    }
    return offsets;
  }

  // ---- Helpers ----
  static Uint8List _hexToBytes(String hex) {
    final clean = hex.replaceAll(' ', '').replaceAll('\n', '');
    final bytes = <int>[];
    for (var i = 0; i < clean.length - 1; i += 2) {
      bytes.add(int.parse(clean.substring(i, i + 2), radix: 16));
    }
    return Uint8List.fromList(bytes);
  }

  static int _indexOf(Uint8List data, Uint8List pattern, [int start = 0]) {
    if (pattern.isEmpty || start >= data.length) return -1;
    for (var i = start; i <= data.length - pattern.length; i++) {
 var match = true;
      for (var j = 0; j < pattern.length; j++) {
        if (data[i + j] != pattern[j]) {
          match = false;
          break;
        }
      }
      if (match) return i;
    }
    return -1;
  }
}
