import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:mcp_client/mcp_client.dart' as mcp;

import '../in_memory_mcp_server.dart';

/// @kelivo/so — In-memory MCP server engine for ELF / .so reverse engineering.
///
/// Pure-Dart ELF parser (no native dependencies) so the app stays fully
/// compilable on every platform. Operates on a local file `path` or on
/// raw `base64` bytes.
///
/// Tools:
/// - so_parse_header       → ELF header (class, endianness, machine, type, entry)
/// - so_list_sections      → section headers (name, type, addr, offset, size)
/// - so_list_symbols       → .dynsym / .symtab entries (name, bind, type, value)
/// - so_list_imports       → undefined (imported) function/object symbols
/// - so_list_exports       → defined & globally-visible (exported) symbols
/// - so_list_dependencies  → DT_NEEDED shared-library dependencies
/// - so_list_strings       → printable ASCII strings (with a minimum length)
/// - so_read_hexdump       → hex dump at arbitrary offset/size
/// - so_analyze_segments   → program headers (segments)
/// - so_analyze_dynamic    → .dynamic section entries with named tags
/// - so_analyze_relocations → .rela.plt / .rel.dyn / .rela.dyn relocations
/// - so_search_bytes       → byte pattern search (hex string with ?? wildcard)
/// - so_section_details    → full hex+ascii dump of a named section
/// - so_search_strings     → regex/prefix search for printable strings
/// - so_symbol_lookup      → query symbol details by name (fuzzy match)
/// - so_section_search     → search for byte pattern within a specific section
/// - so_addr_to_offset     → convert virtual address to file offset
/// - so_offset_to_addr     → convert file offset to virtual address
/// - so_compare_headers    → compare ELF headers between two files
/// - so_list_notes         → list ELF notes (NT_*)

class KelivoSoRequestPayload {
  final Uint8List bytes;
  final int limit;
  final int minLength;

  KelivoSoRequestPayload({
    required this.bytes,
    this.limit = 1000,
    this.minLength = 4,
  });

  static Future<KelivoSoRequestPayload> parse(Object? args) async {
    if (args is! Map) {
      throw ArgumentError('Invalid arguments: expected object with path|base64');
    }
    final map = args.cast<String, dynamic>();
    final limit = _asInt(map['limit'], 1000).clamp(1, 100000);
    final minLength = _asInt(map['min_length'], 4).clamp(1, 256);

    final b64 = (map['base64'] ?? '').toString().trim();
    if (b64.isNotEmpty) {
      final bytes = base64Decode(b64);
      return KelivoSoRequestPayload(
        bytes: bytes,
        limit: limit,
        minLength: minLength,
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
    return KelivoSoRequestPayload(
      bytes: bytes,
      limit: limit,
      minLength: minLength,
    );
  }

  static int _asInt(Object? v, int fallback) {
    if (v is int) return v;
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v.trim()) ?? fallback;
    return fallback;
  }
}

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
    // Resolve section names via the section-header string table.
    if (eShstrndx < sections.length) {
      final shstr = sections[eShstrndx];
      for (final s in sections) {
        s.name = _readAsciiz(shstr.offset + s.nameOffset);
      }
    }
  }

  String _readAsciiz(int offset) {
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

  /// Reads symbols from a symbol table section (.dynsym or .symtab).
  /// [strtab] is the associated string table section.
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
      final name = _readAsciiz(strtab.offset + stName);
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

  /// Reads DT_NEEDED dependency names from the .dynamic section.
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
      if (tag == 0) break; // DT_NULL
      if (tag == 1) {
        // DT_NEEDED
        out.add(_readAsciiz(dynstr.offset + val));
      }
    }
    return out;
  }

  String classLabel() => is64 ? 'ELF64' : 'ELF32';
  String endianLabel() => endian == Endian.big ? 'big' : 'little';
  String typeLabel() {
    switch (eType) {
      case 1:
        return 'REL (relocatable)';
      case 2:
        return 'EXEC (executable)';
      case 3:
        return 'DYN (shared object)';
      case 4:
        return 'CORE';
      default:
        return 'UNKNOWN ($eType)';
    }
  }

  String machineLabel() {
    switch (eMachine) {
      case 0x03:
        return 'x86';
      case 0x28:
        return 'ARM';
      case 0x3e:
        return 'x86-64';
      case 0xb7:
        return 'AArch64';
      case 0xf3:
        return 'RISC-V';
      case 0x08:
        return 'MIPS';
      default:
        return 'machine(0x${eMachine.toRadixString(16)})';
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
      case 0:
        return 'NULL';
      case 1:
        return 'PROGBITS';
      case 2:
        return 'SYMTAB';
      case 3:
        return 'STRTAB';
      case 4:
        return 'RELA';
      case 6:
        return 'DYNAMIC';
      case 7:
        return 'NOTE';
      case 8:
        return 'NOBITS';
      case 9:
        return 'REL';
      case 11:
        return 'DYNSYM';
      default:
        return 'type($type)';
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

  bool get isUndefined => shndx == 0; // SHN_UNDEF
  bool get isGlobal => bind == 1 || bind == 2; // GLOBAL or WEAK
  bool get isFuncOrObject => type == 1 || type == 2; // OBJECT or FUNC

  String bindLabel() {
    switch (bind) {
      case 0:
        return 'LOCAL';
      case 1:
        return 'GLOBAL';
      case 2:
        return 'WEAK';
      default:
        return 'bind($bind)';
    }
  }

  String typeLabel() {
    switch (type) {
      case 0:
        return 'NOTYPE';
      case 1:
        return 'OBJECT';
      case 2:
        return 'FUNC';
      case 3:
        return 'SECTION';
      case 4:
        return 'FILE';
      default:
        return 'type($type)';
    }
  }
}

class KelivoSoAnalyzer {
  static ElfImage _open(KelivoSoRequestPayload p) => ElfImage.parse(p.bytes);

  static Map<String, dynamic> header(KelivoSoRequestPayload p) {
    try {
      final elf = _open(p);
      final sb = StringBuffer()
        ..writeln('Class:      ${elf.classLabel()}')
        ..writeln('Endianness: ${elf.endianLabel()}')
        ..writeln('Type:       ${elf.typeLabel()}')
        ..writeln('Machine:    ${elf.machineLabel()}')
        ..writeln('Entry:      0x${elf.eEntry.toRadixString(16)}')
        ..writeln('Sections:   ${elf.eShnum}');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> sections(KelivoSoRequestPayload p) {
    try {
      final elf = _open(p);
      final sb = StringBuffer();
      sb.writeln('Idx  Name                            Type       Addr        Off        Size');
      for (var i = 0; i < elf.sections.length; i++) {
        final s = elf.sections[i];
        sb.writeln('${i.toString().padRight(4)} '
            '${s.name.padRight(31)} '
            '${s.typeLabel().padRight(10)} '
            '0x${s.addr.toRadixString(16).padLeft(8, '0')}  '
            '0x${s.offset.toRadixString(16).padLeft(8, '0')} '
            '${s.size}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> symbols(KelivoSoRequestPayload p) {
    return _symbolsFiltered(p, (s) => true, 'symbols');
  }

  static Map<String, dynamic> imports(KelivoSoRequestPayload p) {
    return _symbolsFiltered(
      p,
      (s) => s.isUndefined && s.name.isNotEmpty && s.isFuncOrObject,
      'imported symbols',
    );
  }

  static Map<String, dynamic> exports(KelivoSoRequestPayload p) {
    return _symbolsFiltered(
      p,
      (s) =>
          !s.isUndefined && s.isGlobal && s.name.isNotEmpty && s.isFuncOrObject,
      'exported symbols',
    );
  }

  static Map<String, dynamic> _symbolsFiltered(
    KelivoSoRequestPayload p,
    bool Function(ElfSymbol) test,
    String label,
  ) {
    try {
      final elf = _open(p);
      final all = <ElfSymbol>[];
      // Prefer .dynsym (runtime symbols), also include .symtab if present.
      final dynsym = elf.sectionByName('.dynsym');
      final dynstr = elf.sectionByName('.dynstr');
      if (dynsym != null && dynstr != null) {
        all.addAll(elf.readSymbols(dynsym, dynstr));
      }
      final symtab = elf.sectionByName('.symtab');
      final strtab = elf.sectionByName('.strtab');
      if (symtab != null && strtab != null) {
        all.addAll(elf.readSymbols(symtab, strtab));
      }
      final filtered = all.where(test).toList();
      final total = filtered.length;
      final shown = filtered.take(p.limit).toList();
      final sb = StringBuffer()
        ..writeln('$label: $total total (showing ${shown.length})');
      for (final s in shown) {
        sb.writeln('${s.bindLabel().padRight(7)} '
            '${s.typeLabel().padRight(7)} '
            '0x${s.value.toRadixString(16).padLeft(8, '0')}  '
            '${s.name}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dependencies(KelivoSoRequestPayload p) {
    try {
      final elf = _open(p);
      final needed = elf.readNeeded();
      if (needed.isEmpty) return _ok('No DT_NEEDED dependencies found.');
      final sb = StringBuffer()..writeln('Dependencies (${needed.length}):');
      for (final n in needed) {
        sb.writeln('  $n');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> strings(KelivoSoRequestPayload p) {
    try {
      final bytes = p.bytes;
      final out = <String>[];
      final sb = StringBuffer();
      var count = 0;
      for (var i = 0; i < bytes.length && count < p.limit; i++) {
        final c = bytes[i];
        if (c >= 0x20 && c < 0x7f) {
          sb.writeCharCode(c);
        } else {
          if (sb.length >= p.minLength) {
            out.add(sb.toString());
            count++;
          }
          sb.clear();
        }
      }
      if (sb.length >= p.minLength && count < p.limit) out.add(sb.toString());
      final buf = StringBuffer()
        ..writeln('Strings (>= ${p.minLength} chars, showing ${out.length}):');
      for (final s in out) {
        buf.writeln(s);
      }
      return _ok(buf.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> hexdump(KelivoSoRequestPayload p, Map<String, dynamic> args) {
    try {
      final elf = _open(p);
      final offset = _asInt(args['offset'], 0).clamp(0, p.bytes.length - 1);
      final size = _asInt(args['size'], 512).clamp(1, 4096);
      final end = (offset + size).clamp(0, p.bytes.length);
      final sb = StringBuffer();
      sb.writeln('Hex dump at offset 0x${offset.toRadixString(16)}, $end bytes:');
      sb.writeln('      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII');
      for (var i = offset; i < end; i += 16) {
        final line = StringBuffer('0x${i.toRadixString(16).padLeft(8, '0')}  ');
        final ascii = StringBuffer();
        for (var j = 0; j < 16 && i + j < end; j++) {
          final byte = p.bytes[i + j];
          line.write('${byte.toRadixString(16).padLeft(2, '0')} ');
          ascii.write(byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.');
        }
        if (end - i < 16) {
          line.write('  ' * (16 - (end - i)));
        }
        sb.writeln('$line ${ascii.toString().padRight(16)}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> segments(KelivoSoRequestPayload p) {
    try {
      final elf = _open(p);
      final bytes = p.bytes;
      final is64 = elf.is64;
      final e = elf.endian;
      final d = elf.data;
      final ePhoff = is64 ? d.getUint64(32, e) : d.getUint32(28, e);
      final ePhentsize = is64 ? d.getUint16(54, e) : d.getUint16(42, e);
      final ePhnum = is64 ? d.getUint16(56, e) : d.getUint16(44, e);
      if (ePhoff == 0 || ePhnum == 0) return _ok('No program headers.');
      final sb = StringBuffer()
        ..writeln('Idx  Type       Flags  Offset          VirtAddr         FileSize         MemSize          Align');
      for (var i = 0; i < ePhnum; i++) {
        final base = ePhoff + i * ePhentsize;
        if (base + ePhentsize > bytes.length) break;
        final pType = d.getUint32(base, e);
        final pFlags = is64 ? d.getUint32(base + 4, e) : d.getUint32(base + 24, e);
        final pOffset = is64 ? d.getUint64(base + 8, e) : d.getUint32(base + 4, e);
        final pVaddr = is64 ? d.getUint64(base + 16, e) : d.getUint32(base + 8, e);
        final pFilesz = is64 ? d.getUint64(base + 32, e) : d.getUint32(base + 16, e);
        final pMemsz = is64 ? d.getUint64(base + 40, e) : d.getUint32(base + 20, e);
        final pAlign = is64 ? d.getUint64(base + 48, e) : d.getUint32(base + 28, e);
        final typeStr = <int, String>{
          0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE',
          5: 'SHLIB', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME',
          0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY',
        }[pType] ?? 'type($pType)';
        final flagsStr = StringBuffer()
          ..write(pFlags & 4 != 0 ? 'R' : ' ')
          ..write(pFlags & 2 != 0 ? 'W' : ' ')
          ..write(pFlags & 1 != 0 ? 'X' : ' ');
        sb.writeln('${i.toString().padLeft(3)}  ${typeStr.padRight(10)}  ${flagsStr.toString().padRight(5)}  '
            '0x${pOffset.toRadixString(16).padLeft(16, '0')}  '
            '0x${pVaddr.toRadixString(16).padLeft(16, '0')}  '
            '0x${pFilesz.toRadixString(16).padLeft(16, '0')}  '
            '0x${pMemsz.toRadixString(16).padLeft(16, '0')}  '
            '0x${pAlign.toRadixString(16)}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> dynamicSection(KelivoSoRequestPayload p) {
    try {
      final elf = _open(p);
      final bytes = p.bytes;
      final d = elf.data;
      final e = elf.endian;
      final is64 = elf.is64;
      final dyn = elf.sectionByName('.dynamic');
      final dynstr = elf.sectionByName('.dynstr');
      if (dyn == null) return _ok('No .dynamic section found.');
      final entSize = is64 ? 16 : 8;
      final count = dyn.size ~/ entSize;
      final sb = StringBuffer()..writeln('Dynamic section entries (count=$count):');
      for (var i = 0; i < count; i++) {
        final base = dyn.offset + i * entSize;
        if (base + entSize > bytes.length) break;
        int tag;
        int val;
        if (is64) {
          tag = d.getUint64(base, e);
          val = d.getUint64(base + 8, e);
        } else {
          tag = d.getUint32(base, e);
          val = d.getUint32(base + 4, e);
        }
        if (tag == 0) { sb.writeln('  (DT_NULL)'); break; }
        final tagName = <int, String>{
          1: 'DT_NEEDED', 2: 'DT_PLTRELSZ', 3: 'DT_PLTGOT', 4: 'DT_HASH',
          5: 'DT_STRTAB', 6: 'DT_SYMTAB', 7: 'DT_RELA', 8: 'DT_RELASZ',
          9: 'DT_RELAENT', 10: 'DT_STRSZ', 11: 'DT_SYMENT', 12: 'DT_INIT',
          13: 'DT_FINI', 14: 'DT_SONAME', 15: 'DT_RPATH', 16: 'DT_SYMBOLIC',
          17: 'DT_REL', 18: 'DT_RELSZ', 19: 'DT_RELENT', 21: 'DT_PLTREL',
          23: 'DT_JMPREL', 24: 'DT_BIND_NOW', 25: 'DT_INIT_ARRAY',
          26: 'DT_FINI_ARRAY', 27: 'DT_INIT_ARRAYSZ', 28: 'DT_FINI_ARRAYSZ',
          0x6ffffef5: 'DT_GNU_HASH', 0x6ffffff0: 'DT_VERSYM',
          0x6ffffff1: 'DT_RELACOUNT', 0x6ffffff9: 'DT_RELCOUNT',
        }[tag] ?? 'DT_?(0x${tag.toRadixString(16)})';
        if (tag == 1 && dynstr != null) {
          final name = elf._readAsciiz(dynstr.offset + val);
          sb.writeln('  $tagName: $name');
        } else {
          sb.writeln('  $tagName: 0x${val.toRadixString(16)} ($val)');
        }
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> relocations(KelivoSoRequestPayload p) {
    try {
      final elf = _open(p);
      final is64 = elf.is64;
      final sb = StringBuffer();
      var total = 0;
      for (final secName in ['.rela.plt', '.rel.plt', '.rela.dyn', '.rel.dyn']) {
        final sec = elf.sectionByName(secName);
        if (sec == null || sec.size == 0) continue;
        final isRela = secName.startsWith('.rela');
        final entSize = is64 ? (isRela ? 24 : 16) : (isRela ? 12 : 8);
        final count = sec.size ~/ entSize;
        final strtab = elf.sectionByName('.dynstr');
        sb.writeln('$secName: $count entries');
        final shown = count > p.limit ? p.limit : count;
        for (var i = 0; i < shown; i++) {
          final base = sec.offset + i * entSize;
          if (base + entSize > p.bytes.length) break;
          final d = elf.data;
          final e = elf.endian;
          int offset, info, addend = 0;
          if (is64) {
            offset = d.getUint64(base, e);
            info = d.getUint64(base + 8, e);
            if (isRela) addend = d.getUint64(base + 16, e);
          } else {
            offset = d.getUint32(base, e);
            info = d.getUint32(base + 4, e);
            if (isRela) addend = d.getUint32(base + 8, e);
          }
          final symIdx = is64 ? info >> 32 : info >> 8;
          final type = is64 ? info & 0xffffffff : info & 0xff;
          final symName = (strtab != null && symIdx > 0)
              ? _readSymbolName(elf, strtab, symIdx)
              : '';
          final relStr = isRela
              ? '0x${offset.toRadixString(16)}  type=$type  sym=$symIdx${symName.isNotEmpty ? '($symName)' : ''}  addend=0x${addend.toRadixString(16)}'
              : '0x${offset.toRadixString(16)}  type=$type  sym=$symIdx${symName.isNotEmpty ? '($symName)' : ''}';
          sb.writeln('  [$i] $relStr');
        }
        if (count > p.limit) sb.writeln('  ... and ${count - p.limit} more');
        total += count;
      }
      if (total == 0) return _ok('No relocation sections found.');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static String _readSymbolName(ElfImage elf, ElfSection strtab, int symIdx) {
    try {
      final dynsym = elf.sectionByName('.dynsym');
      if (dynsym == null) return '';
      final entSize = elf.is64 ? 24 : 16;
      final base = dynsym.offset + symIdx * entSize;
      if (base + 4 > elf.length) return '';
      final nameOff = elf.data.getUint32(base, elf.endian);
      return elf._readAsciiz(strtab.offset + nameOff);
    } catch (_) {
      return '';
    }
  }

  static Map<String, dynamic> searchBytes(KelivoSoRequestPayload p, Map<String, dynamic> args) {
    try {
      final rawPattern = (args['pattern'] ?? '').toString().trim();
      if (rawPattern.isEmpty) return _err('pattern is required');
      // Normalize: remove spaces, convert ?? to .
      final hex = rawPattern.replaceAll(RegExp(r'\s+'), '').toUpperCase();
      final limit = _asInt(args['limit'], 50).clamp(1, 500);
      final sb = StringBuffer()
        ..writeln('Searching for pattern: $rawPattern (normalized: $hex)');
      // Build byte and mask arrays
      final bytes = <int>[];
      final mask = <int>[];
      for (var i = 0; i < hex.length; i += 2) {
        if (i + 1 >= hex.length) break;
        final hi = hex[i];
        final lo = hex[i + 1];
        if (hi == '?' || lo == '?') {
          bytes.add(0);
          mask.add(0);
        } else {
          bytes.add(int.parse('$hi$lo', radix: 16));
          mask.add(0xFF);
        }
      }
      if (bytes.isEmpty) return _err('Invalid pattern');
      final matches = <int>[];
      final data = p.bytes;
      for (var i = 0; i <= data.length - bytes.length && matches.length < limit; i++) {
        var ok = true;
        for (var j = 0; j < bytes.length; j++) {
          if ((data[i + j] & mask[j]) != (bytes[j] & mask[j])) {
            ok = false;
            break;
          }
        }
        if (ok) matches.add(i);
      }
      if (matches.isEmpty) return _ok('No matches found.');
      sb.writeln('Found ${matches.length} match(es) (showing ${matches.length > limit ? limit : matches.length}):');
      for (var i = 0; i < matches.length && i < limit; i++) {
        final addr = matches[i];
        sb.writeln('  [$i] offset=0x${addr.toRadixString(16).padLeft(8, '0')}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> sectionDetails(KelivoSoRequestPayload p, Map<String, dynamic> args) {
    try {
      final elf = _open(p);
      final secName = (args['section'] ?? '').toString().trim();
      if (secName.isEmpty) return _err('section name is required');
      final sec = elf.sectionByName(secName);
      if (sec == null) return _ok('Section "$secName" not found.');
      final limit = _asInt(args['limit'], 256).clamp(1, 4096);
      final dataOffset = sec.offset;
      final dataSize = sec.size;
      final showSize = dataSize > limit ? limit : dataSize;
      final sb = StringBuffer()
        ..writeln('Section: $secName')
        ..writeln('  Type:   ${sec.typeLabel()}')
        ..writeln('  Addr:   0x${sec.addr.toRadixString(16).padLeft(8, '0')}')
        ..writeln('  Offset: 0x${sec.offset.toRadixString(16).padLeft(8, '0')}')
        ..writeln('  Size:   $dataSize bytes')
        ..writeln('')
        ..writeln('Hex dump (first $showSize bytes):');
      for (var i = 0; i < showSize; i += 16) {
        final line = StringBuffer('0x${(dataOffset + i).toRadixString(16).padLeft(8, '0')}  ');
        final ascii = StringBuffer();
        for (var j = 0; j < 16 && i + j < showSize; j++) {
          final byte = p.bytes[dataOffset + i + j];
          line.write('${byte.toRadixString(16).padLeft(2, '0')} ');
          ascii.write(byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.');
        }
        sb.writeln('$line  $ascii');
      }
      if (dataSize > limit) sb.writeln('... ($dataSize bytes total)');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> searchStrings(KelivoSoRequestPayload p, Map<String, dynamic> args) {
    try {
      final query = (args['query'] ?? '').toString().trim().toLowerCase();
      if (query.isEmpty) return _err('query is required');
      final limit = _asInt(args['limit'], 100).clamp(1, 10000);
      final minLen = _asInt(args['min_length'], 4).clamp(1, 256);
      final bytes = p.bytes;
      final matches = <String>[];
      final sb = StringBuffer();
      for (var i = 0; i < bytes.length && matches.length < limit; i++) {
        final c = bytes[i];
        if (c >= 0x20 && c < 0x7f) {
          sb.writeCharCode(c);
        } else {
          if (sb.length >= minLen) {
            final s = sb.toString();
            if (s.toLowerCase().contains(query)) {
              matches.add(s);
            }
          }
          sb.clear();
        }
      }
      if (sb.length >= minLen) {
        final s = sb.toString();
        if (s.toLowerCase().contains(query) && matches.length < limit) {
          matches.add(s);
        }
      }
      final out = StringBuffer()
        ..writeln('Strings matching "$query" (min_len=$minLen, showing ${matches.length}):');
      for (final m in matches) {
        out.writeln('  $m');
      }
      return _ok(out.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> symbolLookup(KelivoSoRequestPayload p, Map<String, dynamic> args) {
    try {
      final nameQuery = (args['name'] ?? '').toString().trim().toLowerCase();
      if (nameQuery.isEmpty) return _err('name is required');
      final limit = _asInt(args['limit'], 50).clamp(1, 500);
      final elf = _open(p);
      final results = <ElfSymbol>[];
      void collect(ElfSection? symsec, ElfSection? strsec) {
        if (symsec == null || strsec == null) return;
        for (final s in elf.readSymbols(symsec, strsec)) {
          if (s.name.toLowerCase().contains(nameQuery)) {
            results.add(s);
          }
        }
      }
      collect(elf.sectionByName('.dynsym'), elf.sectionByName('.dynstr'));
      collect(elf.sectionByName('.symtab'), elf.sectionByName('.strtab'));
      final total = results.length;
      final shown = results.take(limit).toList();
      final sb = StringBuffer()
        ..writeln('Symbols matching "$nameQuery": $total found (showing ${shown.length}):');
      for (final s in shown) {
        sb.writeln('  ${s.bindLabel().padRight(7)} ${s.typeLabel().padRight(7)} '
            '0x${s.value.toRadixString(16).padLeft(8, '0')}  size=${s.size}  ${s.name}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> sectionSearch(KelivoSoRequestPayload p, Map<String, dynamic> args) {
    try {
      final secName = (args['section'] ?? '').toString().trim();
      final rawPattern = (args['pattern'] ?? '').toString().trim();
      if (secName.isEmpty) return _err('section is required');
      if (rawPattern.isEmpty) return _err('pattern is required');
      final limit = _asInt(args['limit'], 50).clamp(1, 500);
      final elf = _open(p);
      final sec = elf.sectionByName(secName);
      if (sec == null) return _ok('Section "$secName" not found.');
      final hex = rawPattern.replaceAll(RegExp(r'\s+'), '').toUpperCase();
      final bytes = <int>[];
      final mask = <int>[];
      for (var i = 0; i + 1 < hex.length; i += 2) {
        final hi = hex[i];
        final lo = hex[i + 1];
        if (hi == '?' || lo == '?') {
          bytes.add(0);
          mask.add(0);
        } else {
          bytes.add(int.parse('$hi$lo', radix: 16));
          mask.add(0xFF);
        }
      }
      if (bytes.isEmpty) return _err('Invalid pattern');
      final data = p.bytes;
      final secEnd = sec.offset + sec.size;
      final matches = <int>[];
      for (var i = sec.offset; i <= secEnd - bytes.length && matches.length < limit; i++) {
        var ok = true;
        for (var j = 0; j < bytes.length; j++) {
          if ((data[i + j] & mask[j]) != (bytes[j] & mask[j])) {
            ok = false;
            break;
          }
        }
        if (ok) matches.add(i);
      }
      final sb = StringBuffer()
        ..writeln('Section "$secName": ${matches.length} match(es) (showing ${matches.length > limit ? limit : matches.length}):');
      for (var i = 0; i < matches.length && i < limit; i++) {
        sb.writeln('  [$i] offset=0x${matches[i].toRadixString(16).padLeft(8, '0')}');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> addrToOffset(KelivoSoRequestPayload p, Map<String, dynamic> args) {
    try {
      final addrStr = (args['address'] ?? '').toString().trim();
      if (addrStr.isEmpty) return _err('address is required');
      final addr = int.parse(addrStr.replaceFirst('0x', ''), radix: 16);
      final elf = _open(p);
      final phdr = _readProgramHeaders(elf);
      for (final seg in phdr) {
        if (seg.type == 1 /* PT_LOAD */ && addr >= seg.vaddr && addr < seg.vaddr + seg.filesz) {
          final offset = seg.offset + (addr - seg.vaddr);
          return _ok('VA 0x${addr.toRadixString(16)} -> file offset 0x${offset.toRadixString(16)} ($offset)');
        }
      }
      for (final sec in elf.sections) {
        if (addr >= sec.addr && addr < sec.addr + sec.size) {
          final offset = sec.offset + (addr - sec.addr);
          return _ok('VA 0x${addr.toRadixString(16)} -> file offset 0x${offset.toRadixString(16)} ($offset)');
        }
      }
      return _ok('Address 0x${addr.toRadixString(16)} not found in any segment/section.');
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> offsetToAddr(KelivoSoRequestPayload p, Map<String, dynamic> args) {
    try {
      final offset = _asInt(args['offset'], -1);
      if (offset < 0) return _err('offset is required and must be >= 0');
      final elf = _open(p);
      final phdr = _readProgramHeaders(elf);
      for (final seg in phdr) {
        if (seg.type == 1 /* PT_LOAD */ && offset >= seg.offset && offset < seg.offset + seg.filesz) {
          final addr = seg.vaddr + (offset - seg.offset);
          return _ok('File offset $offset (0x${offset.toRadixString(16)}) -> VA 0x${addr.toRadixString(16)}');
        }
      }
      for (final sec in elf.sections) {
        if (offset >= sec.offset && offset < sec.offset + sec.size) {
          final addr = sec.addr + (offset - sec.offset);
          return _ok('File offset $offset (0x${offset.toRadixString(16)}) -> VA 0x${addr.toRadixString(16)}');
        }
      }
      return _ok('Offset $offset not found in any segment/section.');
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Future<Map<String, dynamic>> compareHeaders(Map<String, dynamic> args) async {
    try {
      final p1 = await KelivoSoRequestPayload.parse(args);
      final path2 = (args['path2'] ?? '').toString().trim();
      final b64_2 = (args['base64_2'] ?? '').toString().trim();
      if (path2.isEmpty && b64_2.isEmpty) return _err('path2 or base64_2 is required for the second file');
      final Map<String, dynamic> args2 = {
        if (path2.isNotEmpty) 'path': path2,
        if (b64_2.isNotEmpty) 'base64': b64_2,
      };
      final p2 = await KelivoSoRequestPayload.parse(args2);
      final elf1 = _open(p1);
      final elf2 = _open(p2);
      final sb = StringBuffer()..writeln('--- ELF Header Comparison ---');
      for (final entry in [
        ['Class', elf1.classLabel(), elf2.classLabel()],
        ['Endianness', elf1.endianLabel(), elf2.endianLabel()],
        ['Machine', elf1.machineLabel(), elf2.machineLabel()],
        ['Type', elf1.typeLabel(), elf2.typeLabel()],
        ['Entry', '0x${elf1.eEntry.toRadixString(16)}', '0x${elf2.eEntry.toRadixString(16)}'],
        ['Sections', '${elf1.eShnum}', '${elf2.eShnum}'],
      ]) {
        final match = entry[1] == entry[2] ? 'OK' : 'DIFF';
        sb.writeln('  ${entry[0].padRight(12)} ${entry[1].padRight(24)} ${entry[2].padRight(24)} $match');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> listNotes(KelivoSoRequestPayload p) {
    try {
      final elf = _open(p);
      final sb = StringBuffer();
      var found = false;
      for (final sec in elf.sections) {
        if (sec.type == 4 /* SHT_NOTE */) {
          found = true;
          sb.writeln('NOTE section: ${sec.name} (offset=0x${sec.offset.toRadixString(16)}, size=${sec.size})');
          var pos = sec.offset;
          final end = sec.offset + sec.size;
          while (pos + 12 <= end) {
            final d = elf.data;
            final e = elf.endian;
            final namesz = d.getUint32(pos, e);
            final descsz = d.getUint32(pos + 4, e);
            final nType = d.getUint32(pos + 8, e);
            final nameOff = pos + 12;
            final nameEnd = nameOff + namesz;
            final name = (nameEnd <= end)
                ? elf._readAsciiz(nameOff)
                : '';
            final typeStr = <int, String>{
              1: 'NT_PRSTATUS', 2: 'NT_FPREGSET', 3: 'NT_PRPSINFO',
              4: 'NT_TASKSTRUCT', 5: 'NT_AUXV', 6: 'NT_PRXFPREG',
              0x54410001: 'NT_GNU_ABI_TAG', 0x54410002: 'NT_GNU_HWCAP',
              0x54410003: 'NT_GNU_BUILD_ID', 0x54410004: 'NT_GNU_GOLD_VERSION',
              0x54410006: 'NT_GNU_BUILD_ATTRIBUTE_OPEN',
            }[nType] ?? 'NT_?(0x${nType.toRadixString(16)})';
            sb.writeln('  namesz=$namesz descsz=$descsz type=$typeStr name="$name"');
            final entrySize = 12 + _align4(namesz) + _align4(descsz);
            pos += entrySize;
          }
        }
      }
      if (!found) return _ok('No NOTE sections found.');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  /// Internal helper: read program headers and return a list of segment descriptors.
  static List<_PhdrEntry> _readProgramHeaders(ElfImage elf) {
    final out = <_PhdrEntry>[];
    final d = elf.data;
    final e = elf.endian;
    final is64 = elf.is64;
    final ePhoff = is64 ? d.getUint64(32, e) : d.getUint32(28, e);
    final ePhentsize = is64 ? d.getUint16(54, e) : d.getUint16(42, e);
    final ePhnum = is64 ? d.getUint16(56, e) : d.getUint16(44, e);
    if (ePhoff == 0 || ePhnum == 0) return out;
    for (var i = 0; i < ePhnum; i++) {
      final base = ePhoff + i * ePhentsize;
      if (base + ePhentsize > elf.length) break;
      final pType = d.getUint32(base, e);
      final pOffset = is64 ? d.getUint64(base + 8, e) : d.getUint32(base + 4, e);
      final pVaddr = is64 ? d.getUint64(base + 16, e) : d.getUint32(base + 8, e);
      final pFilesz = is64 ? d.getUint64(base + 32, e) : d.getUint32(base + 16, e);
      final pMemsz = is64 ? d.getUint64(base + 40, e) : d.getUint32(base + 20, e);
      out.add(_PhdrEntry(type: pType, offset: pOffset, vaddr: pVaddr, filesz: pFilesz, memsz: pMemsz));
    }
    return out;
  }

  static int _align4(int v) => (v + 3) & ~3;

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

/// Minimal JSON-RPC server for MCP that serves @kelivo/so tools.
class KelivoSoMcpServerEngine implements KelivoInMemoryMcpServerEngine {
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
              'serverInfo': {'name': '@kelivo/so', 'version': '0.1.0'},
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

          KelivoSoRequestPayload payload;
          try {
            payload = await KelivoSoRequestPayload.parse(arguments);
          } catch (e) {
            return _ok(id, result: KelivoSoAnalyzer._err(e.toString()));
          }

          switch (name) {
            case 'so_parse_header':
              return _ok(id, result: KelivoSoAnalyzer.header(payload));
            case 'so_list_sections':
              return _ok(id, result: KelivoSoAnalyzer.sections(payload));
            case 'so_list_symbols':
              return _ok(id, result: KelivoSoAnalyzer.symbols(payload));
            case 'so_list_imports':
              return _ok(id, result: KelivoSoAnalyzer.imports(payload));
            case 'so_list_exports':
              return _ok(id, result: KelivoSoAnalyzer.exports(payload));
            case 'so_list_dependencies':
              return _ok(id, result: KelivoSoAnalyzer.dependencies(payload));
            case 'so_list_strings':
              return _ok(id, result: KelivoSoAnalyzer.strings(payload));
            case 'so_read_hexdump':
              return _ok(id, result: KelivoSoAnalyzer.hexdump(payload, arguments));
            case 'so_analyze_segments':
              return _ok(id, result: KelivoSoAnalyzer.segments(payload));
            case 'so_analyze_dynamic':
              return _ok(id, result: KelivoSoAnalyzer.dynamicSection(payload));
            case 'so_analyze_relocations':
              return _ok(id, result: KelivoSoAnalyzer.relocations(payload));
            case 'so_search_bytes':
              return _ok(id, result: KelivoSoAnalyzer.searchBytes(payload, arguments));
            case 'so_section_details':
              return _ok(id, result: KelivoSoAnalyzer.sectionDetails(payload, arguments));
            case 'so_search_strings':
              return _ok(id, result: KelivoSoAnalyzer.searchStrings(payload, arguments));
            case 'so_symbol_lookup':
              return _ok(id, result: KelivoSoAnalyzer.symbolLookup(payload, arguments));
            case 'so_section_search':
              return _ok(id, result: KelivoSoAnalyzer.sectionSearch(payload, arguments));
            case 'so_addr_to_offset':
              return _ok(id, result: KelivoSoAnalyzer.addrToOffset(payload, arguments));
            case 'so_offset_to_addr':
              return _ok(id, result: KelivoSoAnalyzer.offsetToAddr(payload, arguments));
            case 'so_compare_headers':
              return _ok(id, result: await KelivoSoAnalyzer.compareHeaders(arguments));
            case 'so_list_notes':
              return _ok(id, result: KelivoSoAnalyzer.listNotes(payload));
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
    Map<String, dynamic> baseSchema({bool withLimit = false, bool withMin = false, bool withOffset = false}) {
      final props = <String, dynamic>{
        'path': {'type': 'string', 'description': '本地 ELF/.so 文件的绝对路径。'},
        'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
      };
      if (withLimit) {
        props['limit'] = {'type': 'integer', 'description': '返回条目上限，默认 1000。'};
      }
      if (withMin) {
        props['min_length'] = {'type': 'integer', 'description': '字符串最小长度，默认 4。'};
      }
      if (withOffset) {
        props['offset'] = {'type': 'integer', 'description': '读取偏移量，默认 0。'};
        props['size'] = {'type': 'integer', 'description': '读取字节数，默认 512。'};
      }
      return {
        'type': 'object',
        'properties': props,
      };
    }

    return [
      {
        'name': 'so_parse_header',
        'description': '解析 ELF/.so 文件头（位数、字节序、机器架构、类型、入口地址）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'so_list_sections',
        'description': '列出 ELF 节区表（名称、类型、地址、偏移、大小）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'so_list_symbols',
        'description': '列出全部符号表条目（.dynsym / .symtab）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'so_list_imports',
        'description': '列出导入符号（未定义的外部函数/对象）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'so_list_exports',
        'description': '列出导出符号（已定义且全局可见的函数/对象）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'so_list_dependencies',
        'description': '列出动态依赖库（DT_NEEDED 条目）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'so_list_strings',
        'description': '提取文件中的可打印 ASCII 字符串。',
        'inputSchema': baseSchema(withLimit: true, withMin: true),
      },
      {
        'name': 'so_read_hexdump',
        'description': '读取 ELF 文件中指定偏移和大小的十六进制转储。',
        'inputSchema': baseSchema(withOffset: true),
      },
      {
        'name': 'so_analyze_segments',
        'description': '解析 ELF Program Headers（段表），显示类型、标志、偏移、虚拟地址、文件大小、内存大小和对齐。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'so_analyze_dynamic',
        'description': '解析 .dynamic 段，列出所有动态标签与值（DT_NEEDED、DT_INIT、DT_FINI 等）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'so_analyze_relocations',
        'description': '解析 .rela.plt / .rel.dyn / .rela.dyn 重定位表（偏移、类型、符号、加数）。',
        'inputSchema': baseSchema(withLimit: true),
      },
      {
        'name': 'so_search_bytes',
        'description': '在 ELF 文件内搜索指定字节序列（16 进制字符串，如 "5F2403D5"），返回匹配地址列表。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 ELF/.so 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'pattern': {'type': 'string', 'description': '要搜索的字节序列，16 进制字符串，如 "5F2403D5" 或 "5F24??D5"（?? 表示通配）。'},
            'limit': {'type': 'integer', 'description': '最大返回匹配数，默认 50。'},
          },
          'required': ['pattern'],
        },
      },
      {
        'name': 'so_section_details',
        'description': '获取指定节区的详细字节内容（十六进制 + ASCII）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 ELF/.so 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'section': {'type': 'string', 'description': '节区名称，如 .text、.rodata、.dynsym。'},
            'limit': {'type': 'integer', 'description': '显示字节上限，默认 256。'},
          },
          'required': ['section'],
        },
      },
      {
        'name': 'so_search_strings',
        'description': '在 ELF 中搜索匹配指定前缀/子串的可打印字符串。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 ELF/.so 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'query': {'type': 'string', 'description': '要搜索的字符串前缀或子串（大小写不敏感）。'},
            'limit': {'type': 'integer', 'description': '最大返回条目数，默认 100。'},
            'min_length': {'type': 'integer', 'description': '字符串最小长度，默认 4。'},
          },
          'required': ['query'],
        },
      },
      {
        'name': 'so_symbol_lookup',
        'description': '按名称模糊查找符号（.dynsym / .symtab），返回地址、绑定、类型、大小。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 ELF/.so 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'name': {'type': 'string', 'description': '符号名称关键字（模糊匹配）。'},
            'limit': {'type': 'integer', 'description': '最大返回条目数，默认 50。'},
          },
          'required': ['name'],
        },
      },
      {
        'name': 'so_section_search',
        'description': '在指定节区内搜索字节匹配。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 ELF/.so 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'section': {'type': 'string', 'description': '节区名称，如 .text。'},
            'pattern': {'type': 'string', 'description': '要搜索的字节序列，16 进制字符串，如 "5F2403D5" 或 "5F24??D5"。'},
            'limit': {'type': 'integer', 'description': '最大返回匹配数，默认 50。'},
          },
          'required': ['section', 'pattern'],
        },
      },
      {
        'name': 'so_addr_to_offset',
        'description': '将虚拟地址（VA）转换为文件偏移（file offset）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 ELF/.so 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'address': {'type': 'string', 'description': '虚拟地址（十六进制字符串，如 "0x1234" 或 "1234"）。'},
          },
          'required': ['address'],
        },
      },
      {
        'name': 'so_offset_to_addr',
        'description': '将文件偏移（file offset）转换为虚拟地址（VA）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 ELF/.so 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'},
            'offset': {'type': 'integer', 'description': '文件偏移量（十进制）。'},
          },
          'required': ['offset'],
        },
      },
      {
        'name': 'so_compare_headers',
        'description': '对比两个 ELF 文件的头部基本信息（类、字节序、机器、类型、入口、节区数）。需要两个 path。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '第一个 ELF/.so 文件的绝对路径。'},
            'base64': {'type': 'string', 'description': '可选：第一个文件的 Base64 字节。'},
            'path2': {'type': 'string', 'description': '第二个 ELF/.so 文件的绝对路径。'},
            'base64_2': {'type': 'string', 'description': '可选：第二个文件的 Base64 字节。'},
          },
        },
      },
      {
        'name': 'so_list_notes',
        'description': '列出 ELF 的 NOTE 段条目（NT_* 类型）。',
        'inputSchema': baseSchema(),
      },
    ];
  }
}

/// Internal helper: program header (segment) descriptor.
class _PhdrEntry {
  final int type;
  final int offset;
  final int vaddr;
  final int filesz;
  final int memsz;

  _PhdrEntry({
    required this.type,
    required this.offset,
    required this.vaddr,
    required this.filesz,
    required this.memsz,
  });
}
