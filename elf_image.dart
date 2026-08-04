import 'dart:typed_data';

/// Minimal ELF reader supporting both 32-bit and 64-bit, LE and BE.
class ElfImage {
  final ByteData data;
  final int length;

  late final bool is64;
  late final Endian endian;
  late final int eType;
  late final int eMachine;
  late final int eEntry;
  late final int eShoff;
  late final int eShentsize;
  late final int eShnum;
  late final int eShstrndx;

  final List<ElfSection> sections = <ElfSection>[];

  ElfImage._(this.data, this.length);

  static ElfImage parse(Uint8List bytes) {
    if (bytes.length < 20) {
      throw const FormatException('Not an ELF file: too short');
    }
    if (bytes[0] != 0x7f ||
        bytes[1] != 0x45 ||
        bytes[2] != 0x4c ||
        bytes[3] != 0x46) {
      throw const FormatException('Not an ELF file: bad magic');
    }
    final img = ElfImage._(ByteData.sublistView(bytes), bytes.length);
    img.is64 = bytes[4] == 2;
    img.endian = bytes[5] == 2 ? Endian.big : Endian.little;
    img._readHeader();
    img._readSections();
    return img;
  }

  void _readHeader() {
    final d = data;
    final e = endian;
    eType = d.getUint16(16, e);
    eMachine = d.getUint16(18, e);
    if (is64) {
      eEntry = d.getUint64(24, e);
      eShoff = d.getUint64(40, e);
      eShentsize = d.getUint16(58, e);
      eShnum = d.getUint16(60, e);
      eShstrndx = d.getUint16(62, e);
    } else {
      eEntry = d.getUint32(24, e);
      eShoff = d.getUint32(32, e);
      eShentsize = d.getUint16(46, e);
      eShnum = d.getUint16(48, e);
      eShstrndx = d.getUint16(50, e);
    }
  }

  void _readSections() {
    if (eShoff == 0 || eShnum == 0) return;
    final d = data;
    final e = endian;
    for (var i = 0; i < eShnum; i++) {
      final base = eShoff + i * eShentsize;
      if (base + eShentsize > length) break;
      final nameOff = d.getUint32(base, e);
      final type = d.getUint32(base + 4, e);
      int addr;
      int offset;
      int size;
      int link;
      int info;
      int entsize;
      if (is64) {
        addr = d.getUint64(base + 16, e);
        offset = d.getUint64(base + 24, e);
        size = d.getUint64(base + 32, e);
        link = d.getUint32(base + 40, e);
        info = d.getUint32(base + 44, e);
        entsize = d.getUint64(base + 56, e);
      } else {
        addr = d.getUint32(base + 12, e);
        offset = d.getUint32(base + 16, e);
        size = d.getUint32(base + 20, e);
        link = d.getUint32(base + 24, e);
        info = d.getUint32(base + 28, e);
        entsize = d.getUint32(base + 36, e);
      }
      sections.add(ElfSection(
        nameOffset: nameOff,
        type: type,
        addr: addr,
        offset: offset,
        size: size,
        link: link,
        info: info,
        entsize: entsize,
      ));
    }
    if (eShstrndx < sections.length) {
      final shstr = sections[eShstrndx];
      for (final s in sections) {
        s.name = readAsciiz(shstr.offset + s.nameOffset);
      }
    }
  }

  /// Reads a NUL-terminated ASCII string starting at [offset].
  String readAsciiz(int offset) {
    if (offset < 0 || offset >= length) return '';
    final sb = StringBuffer();
    var i = offset;
    while (i < length) {
      final c = data.getUint8(i);
      if (c == 0) break;
      sb.writeCharCode(c);
      i++;
    }
    return sb.toString();
  }

  ElfSection? sectionByName(String name) {
    for (final s in sections) {
      if (s.name == name) return s;
    }
    return null;
  }

  String symbolAtAddr(int addr) {
    void check(ElfSection? symsec, ElfSection? strsec, List<ElfSymbol> out) {
      if (symsec == null || strsec == null) return;
      for (final s in readSymbols(symsec, strsec)) {
        if (s.value == addr && s.name.isNotEmpty) out.add(s);
      }
    }
    final matches = <ElfSymbol>[];
    check(sectionByName('.dynsym'), sectionByName('.dynstr'), matches);
    check(sectionByName('.symtab'), sectionByName('.strtab'), matches);
    return matches.isNotEmpty ? matches.first.name : '';
  }

  int? addrOfSymbol(String name) {
    void check(ElfSection? symsec, ElfSection? strsec, List<ElfSymbol> out) {
      if (symsec == null || strsec == null) return;
      for (final s in readSymbols(symsec, strsec)) {
        if (s.name == name) out.add(s);
      }
    }
    final matches = <ElfSymbol>[];
    check(sectionByName('.dynsym'), sectionByName('.dynstr'), matches);
    check(sectionByName('.symtab'), sectionByName('.strtab'), matches);
    return matches.isNotEmpty ? matches.first.value : null;
  }

  int? addrToFileOffset(int addr) {
    final d = data;
    final e = endian;
    final is64 = this.is64;
    final ePhoff = is64 ? d.getUint64(32, e) : d.getUint32(28, e);
    final ePhentsize = is64 ? d.getUint16(54, e) : d.getUint16(42, e);
    final ePhnum = is64 ? d.getUint16(56, e) : d.getUint16(44, e);
    if (ePhoff == 0 || ePhnum == 0) return null;
    for (var i = 0; i < ePhnum; i++) {
      final base = ePhoff + i * ePhentsize;
      if (base + ePhentsize > length) break;
      final pType = d.getUint32(base, e);
      if (pType != 1) continue;
      final pOffset = is64 ? d.getUint64(base + 8, e) : d.getUint32(base + 4, e);
      final pVaddr = is64 ? d.getUint64(base + 16, e) : d.getUint32(base + 8, e);
      final pFilesz = is64 ? d.getUint64(base + 32, e) : d.getUint32(base + 16, e);
      if (addr >= pVaddr && addr < pVaddr + pFilesz) {
        return (pOffset + (addr - pVaddr)).toInt();
      }
    }
    return null;
  }

  /// Converts a file offset to a virtual address via program headers.
  int? offsetToAddr(int offset) {
    final d = data;
    final e = endian;
    final is64 = this.is64;
    final ePhoff = is64 ? d.getUint64(32, e) : d.getUint32(28, e);
    final ePhentsize = is64 ? d.getUint16(54, e) : d.getUint16(42, e);
    final ePhnum = is64 ? d.getUint16(56, e) : d.getUint16(44, e);
    if (ePhoff == 0 || ePhnum == 0) return null;
    for (var i = 0; i < ePhnum; i++) {
      final base = ePhoff + i * ePhentsize;
      if (base + ePhentsize > length) break;
      final pType = d.getUint32(base, e);
      if (pType != 1) continue;
      final pOffset = is64 ? d.getUint64(base + 8, e) : d.getUint32(base + 4, e);
      final pVaddr = is64 ? d.getUint64(base + 16, e) : d.getUint32(base + 8, e);
      final pFilesz = is64 ? d.getUint64(base + 32, e) : d.getUint32(base + 16, e);
      if (offset >= pOffset && offset < pOffset + pFilesz) {
        return (pVaddr + (offset - pOffset)).toInt();
      }
    }
    // Fallback: check sections
    for (final sec in sections) {
      if (offset >= sec.offset && offset < sec.offset + sec.size) {
        return sec.addr + (offset - sec.offset);
      }
    }
    return null;
  }

  /// Reads a symbol name from .dynsym by symbol index.
  String readSymbolName(ElfSection strtab, int symIdx) {
    try {
      final dynsym = sectionByName('.dynsym');
      if (dynsym == null) return '';
      final entSize = is64 ? 24 : 16;
      final base = dynsym.offset + symIdx * entSize;
      if (base + 4 > length) return '';
      final nameOff = data.getUint32(base, endian);
      return readAsciiz(strtab.offset + nameOff);
    } catch (_) {
      return '';
    }
  }

  List<ElfSymbol> readSymbols(ElfSection symtab, ElfSection strtab) {
    final out = <ElfSymbol>[];
    final entSize = is64 ? 24 : 16;
    if (symtab.size == 0) return out;
    final count = symtab.size ~/ entSize;
    final d = data;
    final e = endian;
    for (var i = 0; i < count; i++) {
      final base = symtab.offset + i * entSize;
      if (base + entSize > length) break;
      int stName;
      int stInfo;
      int stShndx;
      int stValue;
      int stSize;
      if (is64) {
        stName = d.getUint32(base, e);
        stInfo = d.getUint8(base + 4);
        stShndx = d.getUint16(base + 6, e);
        stValue = d.getUint64(base + 8, e);
        stSize = d.getUint64(base + 16, e);
      } else {
        stName = d.getUint32(base, e);
        stValue = d.getUint32(base + 4, e);
        stSize = d.getUint32(base + 8, e);
        stInfo = d.getUint8(base + 12);
        stShndx = d.getUint16(base + 14, e);
      }
      final name = readAsciiz(strtab.offset + stName);
      if (name.isEmpty && stName == 0) continue;
      out.add(ElfSymbol(
        name: name,
        bind: stInfo >> 4,
        type: stInfo & 0xf,
        shndx: stShndx,
        value: stValue,
        size: stSize,
      ));
    }
    return out;
  }

  List<String> readNeeded() {
    final dyn = sectionByName('.dynamic');
    final dynstr = sectionByName('.dynstr');
    if (dyn == null || dynstr == null) return const <String>[];
    final out = <String>[];
    final entSize = is64 ? 16 : 8;
    final count = dyn.size ~/ entSize;
    final d = data;
    final e = endian;
    for (var i = 0; i < count; i++) {
      final base = dyn.offset + i * entSize;
      if (base + entSize > length) break;
      int tag;
      int val;
      if (is64) {
        tag = d.getUint64(base, e);
        val = d.getUint64(base + 8, e);
      } else {
        tag = d.getUint32(base, e);
        val = d.getUint32(base + 4, e);
      }
      if (tag == 0) break;
      if (tag == 1) {
        out.add(readAsciiz(dynstr.offset + val));
      }
    }
    return out;
  }

  String classLabel() => is64 ? 'ELF64' : 'ELF32';
  String endianLabel() => endian == Endian.big ? 'big' : 'little';
  String typeLabel() {
    switch (eType) {
      case 1: return 'REL (relocatable)';
      case 2: return 'EXEC (executable)';
      case 3: return 'DYN (shared object)';
      case 4: return 'CORE';
      default: return 'UNKNOWN ($eType)';
    }
  }

  String machineLabel() {
    switch (eMachine) {
      case 0x03: return 'x86';
      case 0x28: return 'ARM';
      case 0x3e: return 'x86-64';
      case 0xb7: return 'AArch64';
      case 0xf3: return 'RISC-V';
      case 0x08: return 'MIPS';
      default: return 'machine(0x${eMachine.toRadixString(16)})';
    }
  }
}

class ElfSection {
  final int nameOffset;
  final int type;
  final int addr;
  final int offset;
  final int size;
  final int link;
  final int info;
  final int entsize;
  String name = '';

  ElfSection({
    required this.nameOffset,
    required this.type,
    required this.addr,
    required this.offset,
    required this.size,
    required this.link,
    required this.info,
    required this.entsize,
  });

  String typeLabel() {
    switch (type) {
      case 0: return 'NULL';
      case 1: return 'PROGBITS';
      case 2: return 'SYMTAB';
      case 3: return 'STRTAB';
      case 4: return 'RELA';
      case 6: return 'DYNAMIC';
      case 7: return 'NOTE';
      case 8: return 'NOBITS';
      case 9: return 'REL';
      case 11: return 'DYNSYM';
      default: return 'type($type)';
    }
  }
}

class ElfSymbol {
  final String name;
  final int bind;
  final int type;
  final int shndx;
  final int value;
  final int size;

  ElfSymbol({
    required this.name,
    required this.bind,
    required this.type,
    required this.shndx,
    required this.value,
    required this.size,
  });

  bool get isUndefined => shndx == 0;
  bool get isGlobal => bind == 1 || bind == 2;
  bool get isFuncOrObject => type == 1 || type == 2;

  String bindLabel() {
    switch (bind) {
      case 0: return 'LOCAL';
      case 1: return 'GLOBAL';
      case 2: return 'WEAK';
      default: return 'bind($bind)';
    }
  }

  String typeLabel() {
    switch (type) {
      case 0: return 'NOTYPE';
      case 1: return 'OBJECT';
      case 2: return 'FUNC';
      case 3: return 'SECTION';
      case 4: return 'FILE';
      default: return 'type($type)';
    }
  }
}
