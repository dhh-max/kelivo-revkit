import 'dart:convert';
import 'dart:typed_data';

import 'elf_image.dart';

/// SO (ELF) analysis service.
/// Pure Dart logic extracted from KelivoSoAnalyzer (MCP server).
/// All methods return String directly; exceptions propagate to caller.
class SoAnalyzerService {
  final Uint8List bytes;
  final int limit;
  final int minLength;
  late final ElfImage _elf;

  SoAnalyzerService({
    required this.bytes,
    this.limit = 1000,
    this.minLength = 4,
  }) {
    _elf = ElfImage.parse(bytes);
  }

  ElfImage get elf => _elf;

  /// Parse ELF header info.
  String header() {
    final sb = StringBuffer()
      ..writeln('Class:      ${_elf.classLabel()}')
      ..writeln('Endianness: ${_elf.endianLabel()}')
      ..writeln('Type:       ${_elf.typeLabel()}')
      ..writeln('Machine:    ${_elf.machineLabel()}')
      ..writeln('Entry:      0x${_elf.eEntry.toRadixString(16)}')
      ..writeln('Sections:   ${_elf.eShnum}');
    return sb.toString().trimRight();
  }

  /// List all ELF sections.
  String sections() {
    final sb = StringBuffer();
    sb.writeln('Idx  Name                            Type       Addr        Off        Size');
    for (var i = 0; i < _elf.sections.length; i++) {
      final s = _elf.sections[i];
      sb.writeln('${i.toString().padRight(4)} '
          '${s.name.padRight(31)} '
          '${s.typeLabel().padRight(10)} '
          '0x${s.addr.toRadixString(16).padLeft(8, '0')}  '
          '0x${s.offset.toRadixString(16).padLeft(8, '0')} '
          '${s.size}');
    }
    return sb.toString().trimRight();
  }

  /// List all symbols (from .dynsym and .symtab).
  String symbols() => _symbolsFiltered((s) => true, 'symbols');

  /// List imported (undefined) symbols.
  String imports() => _symbolsFiltered(
        (s) => s.isUndefined && s.name.isNotEmpty && s.isFuncOrObject,
        'imported symbols',
      );

  /// List exported (defined global) symbols.
  String exports() => _symbolsFiltered(
        (s) => !s.isUndefined && s.isGlobal && s.name.isNotEmpty && s.isFuncOrObject,
        'exported symbols',
      );


  String _symbolsFiltered(bool Function(ElfSymbol) test, String label) {
    final all = _readAllSymbols();
    final filtered = all.where(test).toList();
    final total = filtered.length;
    final shown = filtered.take(limit).toList();
    final sb = StringBuffer()
      ..writeln('$label: $total total (showing ${shown.length})');
    for (final s in shown) {
      sb.writeln('${s.bindLabel().padRight(7)} '
          '${s.typeLabel().padRight(7)} '
          '0x${s.value.toRadixString(16).padLeft(8, '0')}  '
          '${s.name}');
    }
    return sb.toString().trimRight();
  }

  List<ElfSymbol> _readAllSymbols() {
    final all = <ElfSymbol>[];
    final dynsym = _elf.sectionByName('.dynsym');
    final dynstr = _elf.sectionByName('.dynstr');
    if (dynsym != null && dynstr != null) {
      all.addAll(_elf.readSymbols(dynsym, dynstr));
    }
    final symtab = _elf.sectionByName('.symtab');
    final strtab = _elf.sectionByName('.strtab');
    if (symtab != null && strtab != null) {
      all.addAll(_elf.readSymbols(symtab, strtab));
    }
    return all;
  }

  /// List DT_NEEDED dependencies.
  String dependencies() {
    final needed = _elf.readNeeded();
    if (needed.isEmpty) return 'No DT_NEEDED dependencies found.';
    final sb = StringBuffer()..writeln('Dependencies (${needed.length}):');
    for (final n in needed) {
      sb.writeln('  $n');
    }
    return sb.toString().trimRight();
  }

  /// Extract readable strings from binary.
  String strings() {
    final out = <String>[];
    final sb = StringBuffer();
    var count = 0;
    for (var i = 0; i < bytes.length && count < limit; i++) {
      final c = bytes[i];
      if (c >= 0x20 && c < 0x7f) {
        sb.writeCharCode(c);
      } else {
        if (sb.length >= minLength) {
          out.add(sb.toString());
          count++;
        }
        sb.clear();
      }
    }
    if (sb.length >= minLength && count < limit) out.add(sb.toString());
    final buf = StringBuffer()
      ..writeln('Strings (>= $minLength chars, showing ${out.length}):');
    for (final s in out) {
      buf.writeln(s);
    }
    return buf.toString().trimRight();
  }

  /// Hex dump at given offset.
  String hexdump({int offset = 0, int size = 512}) {
    final end = (offset + size).clamp(0, bytes.length) as int;
    final sb = StringBuffer();
    sb.writeln('Hex dump at offset 0x${offset.toRadixString(16)}, $end bytes:');
    sb.writeln('      00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII');
    for (var i = offset; i < end; i += 16) {
      final line = StringBuffer('0x${i.toRadixString(16).padLeft(8, '0')}  ');
      final ascii = StringBuffer();
      for (var j = 0; j < 16 && i + j < end; j++) {
        final byte = bytes[i + j];
        line.write('${byte.toRadixString(16).padLeft(2, '0')} ');
        ascii.write(byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.');
      }
      if (end - i < 16) {
        line.write('   ' * (16 - (end - i)));
      }
      sb.writeln('$line ${ascii.toString().padRight(16)}');
    }
    return sb.toString().trimRight();
  }

  /// List program headers (segments).
  String segments() {
    final is64 = _elf.is64;
    final e = _elf.endian;
    final d = _elf.data;
    final ePhoff = is64 ? d.getUint64(32, e) : d.getUint32(28, e);
    final ePhentsize = is64 ? d.getUint16(54, e) : d.getUint16(42, e);
    final ePhnum = is64 ? d.getUint16(56, e) : d.getUint16(44, e);
    if (ePhoff == 0 || ePhnum == 0) return 'No program headers.';
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
    return sb.toString().trimRight();
  }

  /// Search symbols by keyword (case-insensitive substring match).
  String searchSymbols(String keyword) {
    final all = _readAllSymbols();
    final lower = keyword.toLowerCase();
    final matches = all
        .where((s) => s.name.isNotEmpty && s.name.toLowerCase().contains(lower))
        .take(limit)
        .toList();
    if (matches.isEmpty) return 'No symbols matching "$keyword".';
    final sb = StringBuffer()
      ..writeln('Symbols matching "$keyword" (${matches.length} shown):');
    for (final s in matches) {
      sb.writeln('${s.bindLabel().padRight(7)} '
          '${s.typeLabel().padRight(7)} '
          '0x${s.value.toRadixString(16).padLeft(8, '0')}  '
          '${s.name}');
    }
    return sb.toString().trimRight();
  }

  /// Lookup symbol name at a given address.
  String lookupAddress(int addr) {
    final name = _elf.symbolAtAddr(addr);
    if (name.isEmpty) return 'No symbol found at address 0x${addr.toRadixString(16)}.';
    return '0x${addr.toRadixString(16)} -> $name';
  }

  /// Lookup address of a given symbol name.
  String lookupSymbol(String name) {
    final addr = _elf.addrOfSymbol(name);
    if (addr == null) return 'Symbol "$name" not found.';
    final off = _elf.addrToFileOffset(addr);
    return '$name -> addr=0x${addr.toRadixString(16)}'
        '${off != null ? ' fileOffset=0x${off.toRadixString(16)}' : ''}';
  }

  // ---- dynamicSection ----
  String dynamicSection() {
    final d = _elf.data;
    final e = _elf.endian;
    final is64 = _elf.is64;
    final dyn = _elf.sectionByName('.dynamic');
    final dynstr = _elf.sectionByName('.dynstr');
    if (dyn == null) return 'No .dynamic section found.';
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
        final name = _elf.readAsciiz(dynstr.offset + val);
        sb.writeln('  $tagName: $name');
      } else {
        sb.writeln('  $tagName: 0x${val.toRadixString(16)} ($val)');
      }
    }
    return sb.toString().trimRight();
  }

  // ---- relocations ----
  String relocations() {
    final is64 = _elf.is64;
    final sb = StringBuffer();
    var total = 0;
    for (final secName in ['.rela.plt', '.rel.plt', '.rela.dyn', '.rel.dyn']) {
      final sec = _elf.sectionByName(secName);
      if (sec == null || sec.size == 0) continue;
      final isRela = secName.startsWith('.rela');
      final entSize = is64 ? (isRela ? 24 : 16) : (isRela ? 12 : 8);
      final count = sec.size ~/ entSize;
      final strtab = _elf.sectionByName('.dynstr');
      sb.writeln('$secName: $count entries');
      final shown = count > limit ? limit : count;
      for (var i = 0; i < shown; i++) {
        final base = sec.offset + i * entSize;
        if (base + entSize > bytes.length) break;
        final d = _elf.data;
        final e = _elf.endian;
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
            ? _elf.readSymbolName(strtab, symIdx)
            : '';
        final relStr = isRela
            ? '0x\${offset.toRadixString(16)}  type=\$type  sym=\$symIdx\${symName.isNotEmpty ? '(\$symName)' : ''}  addend=0x\${addend.toRadixString(16)}'
            : '0x\${offset.toRadixString(16)}  type=\$type  sym=\$symIdx\${symName.isNotEmpty ? '(\$symName)' : ''}';
        sb.writeln('  [\$i] \$relStr');
      }
      if (count > limit) sb.writeln('  ... and \${count - limit} more');
      total += count;
    }
    if (total == 0) return 'No relocation sections found.';
    return sb.toString().trimRight();
  }

  // ---- searchBytes ----
  String searchBytes(String pattern, {int? resultLimit}) {
    final rawPattern = pattern.trim();
    if (rawPattern.isEmpty) throw ArgumentError('pattern is required');
    final hex = rawPattern.replaceAll(RegExp(r'\s+'), '').toUpperCase();
    final lim = (resultLimit ?? 50).clamp(1, 500);
    final sb = StringBuffer()
      ..writeln('Searching for pattern: \$rawPattern (normalized: \$hex)');
    final patBytes = <int>[];
    final mask = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      if (i + 1 >= hex.length) break;
      final hi = hex[i];
      final lo = hex[i + 1];
      if (hi == '?' || lo == '?') {
        patBytes.add(0);
        mask.add(0);
      } else {
        patBytes.add(int.parse('\$hi\$lo', radix: 16));
        mask.add(0xFF);
      }
    }
    if (patBytes.isEmpty) throw ArgumentError('Invalid pattern');
    final matches = <int>[];
    for (var i = 0; i <= bytes.length - patBytes.length && matches.length < lim; i++) {
      var ok = true;
      for (var j = 0; j < patBytes.length; j++) {
        if ((bytes[i + j] & mask[j]) != (patBytes[j] & mask[j])) {
          ok = false;
          break;
        }
      }
      if (ok) matches.add(i);
    }
    if (matches.isEmpty) return 'No matches found.';
    sb.writeln('Found \${matches.length} match(es):');
    for (var i = 0; i < matches.length; i++) {
      sb.writeln('  [\$i] offset=0x\${matches[i].toRadixString(16).padLeft(8, '0')}');
    }
    return sb.toString().trimRight();
  }

  // ---- sectionDetails ----
  String sectionDetails(String sectionName, {int? resultLimit}) {
    final sec = _elf.sectionByName(sectionName);
    if (sec == null) return 'Section "\$sectionName" not found.';
    final lim = (resultLimit ?? 256).clamp(1, 4096);
    final showSize = sec.size > lim ? lim : sec.size;
    final sb = StringBuffer()
      ..writeln('Section: \$sectionName')
      ..writeln('  Type:   \${sec.typeLabel()}')
      ..writeln('  Addr:   0x\${sec.addr.toRadixString(16).padLeft(8, '0')}')
      ..writeln('  Offset: 0x\${sec.offset.toRadixString(16).padLeft(8, '0')}')
      ..writeln('  Size:   \${sec.size} bytes')
      ..writeln('')
      ..writeln('Hex dump (first \$showSize bytes):');
    for (var i = 0; i < showSize; i += 16) {
      final line = StringBuffer('0x\${(sec.offset + i).toRadixString(16).padLeft(8, '0')}  ');
      final ascii = StringBuffer();
      for (var j = 0; j < 16 && i + j < showSize; j++) {
        final byte = bytes[sec.offset + i + j];
        line.write('\${byte.toRadixString(16).padLeft(2, '0')} ');
        ascii.write(byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.');
      }
      sb.writeln('\$line  \$ascii');
    }
    if (sec.size > lim) sb.writeln('... (\${sec.size} bytes total)');
    return sb.toString().trimRight();
  }

  // ---- searchStrings ----
  String searchStrings(String query, {int? resultLimit, int? minLen}) {
    final q = query.trim().toLowerCase();
    if (q.isEmpty) throw ArgumentError('query is required');
    final lim = (resultLimit ?? 100).clamp(1, 10000);
    final ml = (minLen ?? 4).clamp(1, 256);
    final matches = <String>[];
    final sb = StringBuffer();
    for (var i = 0; i < bytes.length && matches.length < lim; i++) {
      final c = bytes[i];
      if (c >= 0x20 && c < 0x7f) {
        sb.writeCharCode(c);
      } else {
        if (sb.length >= ml) {
          final s = sb.toString();
          if (s.toLowerCase().contains(q)) {
            matches.add(s);
          }
        }
        sb.clear();
      }
    }
    if (sb.length >= ml) {
      final s = sb.toString();
      if (s.toLowerCase().contains(q) && matches.length < lim) {
        matches.add(s);
      }
    }
    final out = StringBuffer()
      ..writeln('Strings matching "\$q" (min_len=\$ml, showing \${matches.length}):');
    for (final m in matches) {
      out.writeln('  \$m');
    }
    return out.toString().trimRight();
  }

  // ---- symbolLookup ----
  String symbolLookup(String name, {int? resultLimit}) {
    final nameQuery = name.trim().toLowerCase();
    if (nameQuery.isEmpty) throw ArgumentError('name is required');
    final lim = (resultLimit ?? 50).clamp(1, 500);
    final results = <ElfSymbol>[];
    void collect(ElfSection? symsec, ElfSection? strsec) {
      if (symsec == null || strsec == null) return;
      for (final s in _elf.readSymbols(symsec, strsec)) {
        if (s.name.toLowerCase().contains(nameQuery)) {
          results.add(s);
        }
      }
    }
    collect(_elf.sectionByName('.dynsym'), _elf.sectionByName('.dynstr'));
    collect(_elf.sectionByName('.symtab'), _elf.sectionByName('.strtab'));
    final total = results.length;
    final shown = results.take(lim).toList();
    final sb = StringBuffer()
      ..writeln('Symbols matching "$nameQuery": $total found (showing ${shown.length}):');
    for (final s in shown) {
      sb.writeln('  ${s.bindLabel().padRight(7)} ${s.typeLabel().padRight(7)} '
          '0x${s.value.toRadixString(16).padLeft(8, '0')}  size=${s.size}  ${s.name}');
    }
    return sb.toString().trimRight();
  }

  // ---- sectionSearch ----
  String sectionSearch(String section, String pattern, {int? resultLimit}) {
    final secName = section.trim();
    final rawPattern = pattern.trim();
    if (secName.isEmpty) throw ArgumentError('section is required');
    if (rawPattern.isEmpty) throw ArgumentError('pattern is required');
    final lim = (resultLimit ?? 50).clamp(1, 500);
    final sec = _elf.sectionByName(secName);
    if (sec == null) return 'Section "$secName" not found.';
    final hex = rawPattern.replaceAll(RegExp(r'\s+'), '').toUpperCase();
    final patBytes = <int>[];
    final mask = <int>[];
    for (var i = 0; i + 1 < hex.length; i += 2) {
      final hi = hex[i];
      final lo = hex[i + 1];
      if (hi == '?' || lo == '?') {
        patBytes.add(0);
        mask.add(0);
      } else {
        patBytes.add(int.parse('$hi$lo', radix: 16));
        mask.add(0xFF);
      }
    }
    if (patBytes.isEmpty) throw ArgumentError('Invalid pattern');
    final secEnd = sec.offset + sec.size;
    final matches = <int>[];
    for (var i = sec.offset; i <= secEnd - patBytes.length && matches.length < lim; i++) {
      var ok = true;
      for (var j = 0; j < patBytes.length; j++) {
        if ((bytes[i + j] & mask[j]) != (patBytes[j] & mask[j])) {
          ok = false;
          break;
        }
      }
      if (ok) matches.add(i);
    }
    final sb = StringBuffer()
      ..writeln('Section "$secName": ${matches.length} match(es):');
    for (var i = 0; i < matches.length; i++) {
      sb.writeln('  [$i] offset=0x${matches[i].toRadixString(16).padLeft(8, '0')}');
    }
    return sb.toString().trimRight();
  }

  // ---- addrToOffset ----
  String addrToOffset(int addr) {
    final off = _elf.addrToFileOffset(addr);
    if (off != null) {
      return 'VA 0x${addr.toRadixString(16)} -> file offset 0x${off.toRadixString(16)} ($off)';
    }
    for (final sec in _elf.sections) {
      if (addr >= sec.addr && addr < sec.addr + sec.size) {
        final offset = sec.offset + (addr - sec.addr);
        return 'VA 0x${addr.toRadixString(16)} -> file offset 0x${offset.toRadixString(16)} ($offset)';
      }
    }
    return 'Address 0x${addr.toRadixString(16)} not found in any segment/section.';
  }

  // ---- offsetToAddr ----
  String offsetToAddr(int offset) {
    if (offset < 0) throw ArgumentError('offset must be >= 0');
    final addr = _elf.offsetToAddr(offset);
    if (addr != null) {
      return 'File offset $offset (0x${offset.toRadixString(16)}) -> VA 0x${addr.toRadixString(16)}';
    }
    return 'Offset $offset not found in any segment/section.';
  }

  // ---- listNotes ----
  String listNotes() {
    final sb = StringBuffer();
    var found = false;
    for (final sec in _elf.sections) {
      if (sec.type == 4) {
        found = true;
        sb.writeln('NOTE section: ${sec.name} (offset=0x${sec.offset.toRadixString(16)}, size=${sec.size})');
        var pos = sec.offset;
        final end = sec.offset + sec.size;
        while (pos + 12 <= end) {
          final d = _elf.data;
          final e = _elf.endian;
          final namesz = d.getUint32(pos, e);
          final descsz = d.getUint32(pos + 4, e);
          final nType = d.getUint32(pos + 8, e);
          final nameOff = pos + 12;
          final nameEnd = nameOff + namesz;
          final noteName = (nameEnd <= end) ? _elf.readAsciiz(nameOff) : '';
          final typeStr = <int, String>{
            1: 'NT_PRSTATUS', 2: 'NT_FPREGSET', 3: 'NT_PRPSINFO',
            4: 'NT_TASKSTRUCT', 5: 'NT_AUXV', 6: 'NT_PRXFPREG',
            0x54410001: 'NT_GNU_ABI_TAG', 0x54410002: 'NT_GNU_HWCAP',
            0x54410003: 'NT_GNU_BUILD_ID', 0x54410004: 'NT_GNU_GOLD_VERSION',
            0x54410006: 'NT_GNU_BUILD_ATTRIBUTE_OPEN',
          }[nType] ?? 'NT_?(0x${nType.toRadixString(16)})';
          sb.writeln('  namesz=$namesz descsz=$descsz type=$typeStr name="$noteName"');
          final entrySize = 12 + _align4(namesz) + _align4(descsz);
          pos += entrySize;
        }
      }
    }
    if (!found) return 'No NOTE sections found.';
    return sb.toString().trimRight();
  }

  // ---- listInitArray ----
  String listInitArray() {
    final sb = StringBuffer();
    var any = false;
    for (final arrName in ['.init_array', '.fini_array', '.preinit_array']) {
      final sec = _elf.sectionByName(arrName);
      if (sec == null || sec.size == 0) continue;
      any = true;
      final ptrSize = _elf.is64 ? 8 : 4;
      final count = sec.size ~/ ptrSize;
      sb.writeln('$arrName (offset=0x${sec.offset.toRadixString(16)}, count=$count):');
      final shown = count > limit ? limit : count;
      for (var i = 0; i < shown; i++) {
        final off = sec.offset + i * ptrSize;
        if (off + ptrSize > _elf.length) break;
        final addr = _elf.is64
            ? _elf.data.getUint64(off, _elf.endian)
            : _elf.data.getUint32(off, _elf.endian);
        final sym = _elf.symbolAtAddr(addr);
        final label = sym.isNotEmpty ? '  ; $sym' : '';
        sb.writeln('  [$i] 0x${addr.toRadixString(16)}$label');
      }
      if (count > shown) sb.writeln('  ... and ${count - shown} more');
    }
    if (!any) return 'No .init_array/.fini_array/.preinit_array found.';
    return sb.toString().trimRight();
  }

  // ---- xrefSymbol ----
  String xrefSymbol(String symbol, {int? resultLimit}) {
    final target = symbol.trim();
    if (target.isEmpty) throw ArgumentError('Missing "symbol" parameter.');
    final lim = (resultLimit ?? 100).clamp(1, 1000);
    final sb = StringBuffer()..writeln('XREF to symbol: $target');
    var hits = 0;
    for (final secName in ['.rela.plt', '.rel.plt', '.rela.dyn', '.rel.dyn']) {
      final sec = _elf.sectionByName(secName);
      if (sec == null || sec.size == 0) continue;
      final isRela = secName.startsWith('.rela');
      final entSize = _elf.is64 ? (isRela ? 24 : 16) : (isRela ? 12 : 8);
      final count = sec.size ~/ entSize;
      final strtab = _elf.sectionByName('.dynstr');
      for (var i = 0; i < count; i++) {
        final base = sec.offset + i * entSize;
        if (base + entSize > _elf.length) break;
        final d = _elf.data;
        final e = _elf.endian;
        final rOffset = _elf.is64
            ? d.getUint64(base, e)
            : d.getUint32(base, e);
        final info = _elf.is64
            ? d.getUint64(base + 8, e)
            : d.getUint32(base + 4, e);
        final symIdx = _elf.is64 ? info >> 32 : info >> 8;
        if (symIdx == 0) continue;
        final symName =
            (strtab != null) ? _elf.readSymbolName(strtab, symIdx) : '';
        if (symName.isEmpty || !symName.contains(target)) continue;
        sb.writeln('  [${sec.name}] 0x${rOffset.toRadixString(16)} -> $symName');
        hits++;
        if (hits >= lim) break;
      }
      if (hits >= lim) break;
    }
    sb.writeln('---');
    sb.writeln('Hits: $hits (limit $lim)');
    return sb.toString().trimRight();
  }

  // ---- detectPacker ----
  String detectPacker() {
    final sb = StringBuffer()..writeln('Packer / Protector Detection:');
    final detections = <String>[];
    final secNames = _elf.sections.map((s) => s.name).toSet();

    if (secNames.contains('UPX0') || secNames.contains('UPX1') ||
        secNames.contains('.upx')) {
      detections.add('UPX (UPX0/UPX1 sections)');
    }
    if (secNames.any((n) => n.contains('bangcle')) ||
        _bytesContain('libsecexe.so') ||
        _bytesContain('libsecmain.so')) {
      detections.add('Bangcle (梆梆加固)');
    }
    if (_bytesContain('ijiami') ||
        _bytesContain('libexec.so') ||
        secNames.any((n) => n.contains('ijiami'))) {
      detections.add('Ijiami (爱加密)');
    }
    if (_bytesContain('libprotectClass.so') ||
        _bytesContain('libjiagu') ||
        _bytesContain('360jiagu')) {
      detections.add('360 Jiagu (360加固)');
    }
    if (_bytesContain('libchaosvmp') ||
        _bytesContain('nagain')) {
      detections.add('Nagain (娜迦加固)');
    }
    if (_bytesContain('libshell') ||
        _bytesContain('legu') ||
        _bytesContain('libBugly')) {
      detections.add('Tencent Legu (乐固)');
    }
    if (_bytesContain('libbaiduprotect') ||
        _bytesContain('baiduprotect')) {
      detections.add('Baidu Protect (百度加固)');
    }
    if (_bytesContain('dexprotector') ||
        _bytesContain('dexguard')) {
      detections.add('DexProtector/DexGuard');
    }
    if (_bytesContain('aliprotect') ||
        _bytesContain('libmobisec')) {
      detections.add('Alibaba (阿里聚安全)');
    }
    if (secNames.any((n) => n.startsWith('.qihoo'))) {
      detections.add('Qihoo custom linker');
    }
    if (_elf.sections.length <= 1) {
      detections.add('Stripped section headers (possible anti-analysis)');
    }
    final initSec = _elf.sectionByName('.init_array');
    if (initSec != null && initSec.size > 0) {
      final ptrSize = _elf.is64 ? 8 : 4;
      final initCount = initSec.size ~/ ptrSize;
      if (initCount > 20) {
        detections.add('Large .init_array ($initCount entries — possible anti-debug)');
      }
    }

    if (detections.isEmpty) {
      sb.writeln('  No known packer signatures detected.');
    } else {
      for (final d in detections) {
        sb.writeln('  ⚠ $d');
      }
    }
    return sb.toString().trimRight();
  }

  // ---- disassemble ----
  String disassemble({String? symbol, int? offset, int? count}) {
    final cnt = (count ?? 32).clamp(1, 500);

    int fileOff;
    if (symbol != null && symbol.isNotEmpty) {
      final va = _elf.addrOfSymbol(symbol);
      if (va == null) throw ArgumentError('Symbol not found: $symbol');
      final fOff = _elf.addrToFileOffset(va);
      if (fOff == null) {
        throw ArgumentError('Cannot map symbol VA 0x${va.toRadixString(16)} to file offset');
      }
      fileOff = fOff;
    } else if (offset != null && offset >= 0) {
      fileOff = offset;
    } else {
      throw ArgumentError('Provide "symbol" or "offset" parameter.');
    }

    if (!_elf.is64) {
      throw ArgumentError('Disassembler currently supports AArch64 (64-bit) only.');
    }

    final sb = StringBuffer()
      ..writeln('Disassembly at file offset 0x${fileOff.toRadixString(16)}:');
    var pc = fileOff;
    for (var i = 0; i < cnt; i++) {
      if (pc + 4 > _elf.length) break;
      final insn = _elf.data.getUint32(pc, Endian.little);
      final hex = insn.toRadixString(16).padLeft(8, '0');
      final mnemonic = _decodeA64(insn);
      sb.writeln('  0x${pc.toRadixString(16)}: $hex  $mnemonic');
      pc += 4;
    }
    return sb.toString().trimRight();
  }

  // ---- gotPltAnalysis ----
  String gotPltAnalysis() {
    final sb = StringBuffer()..writeln('=== GOT/PLT Analysis ===');
    for (final name in ['.got', '.got.plt', '.plt', '.plt.got']) {
      final sec = _elf.sectionByName(name);
      if (sec == null || sec.size == 0) continue;
      sb.writeln('\n$name (addr=0x${sec.addr.toRadixString(16)}, '
          'offset=0x${sec.offset.toRadixString(16)}, size=${sec.size}):');
      final ptrSize = _elf.is64 ? 8 : 4;
      final count = sec.size ~/ ptrSize;
      final shown = count > limit ? limit : count;
      for (var i = 0; i < shown; i++) {
        final off = sec.offset + i * ptrSize;
        if (off + ptrSize > _elf.length) break;
        final addr = _elf.is64
            ? _elf.data.getUint64(off, _elf.endian)
            : _elf.data.getUint32(off, _elf.endian);
        final sym = _elf.symbolAtAddr(sec.addr + i * ptrSize);
        final target = _elf.symbolAtAddr(addr);
        final label = sym.isNotEmpty ? sym : (target.isNotEmpty ? '→ $target' : '');
        sb.writeln('  [$i] 0x${(sec.addr + i * ptrSize).toRadixString(16)}: '
            '0x${addr.toRadixString(16)}${label.isNotEmpty ? '  ; $label' : ''}');
      }
      if (count > shown) sb.writeln('  ... ($count total)');
    }
    return sb.toString().trimRight();
  }

  // ---- findAntiDebug ----
  String findAntiDebug() {
    final sb = StringBuffer()..writeln('=== Anti-Debug Detection ===');
    final findings = <String>[];

    final dynsym = _elf.sectionByName('.dynsym');
    final dynstr = _elf.sectionByName('.dynstr');
    final syms = <String>[];
    if (dynsym != null && dynstr != null) {
      for (final s in _elf.readSymbols(dynsym, dynstr)) {
        syms.add(s.name);
      }
    }

    if (syms.any((s) => s == 'ptrace')) {
      findings.add('⚠ Imports ptrace() — common anti-debug (self-attach)');
    }
    if (syms.any((s) => s.startsWith('inotify_'))) {
      findings.add('⚠ Imports inotify — may monitor /proc/self for debugger');
    }
    if (syms.contains('fork') && syms.contains('waitpid')) {
      findings.add('⚠ Imports fork+waitpid — possible anti-ptrace child watchdog');
    }
    if (syms.contains('kill') || syms.contains('raise')) {
      findings.add('⚡ Imports kill/raise — may self-terminate on debug detection');
    }

    final strChecks = <String, String>{
      '/proc/self/status': 'Reads /proc/self/status (TracerPid check)',
      '/proc/self/maps': 'Reads /proc/self/maps (memory mapping check)',
      '/proc/self/cmdline': 'Reads /proc/self/cmdline',
      'TracerPid': 'Searches for TracerPid string',
      'frida': 'References Frida (anti-Frida)',
      'xposed': 'References Xposed (anti-Xposed)',
      'substrate': 'References Cydia Substrate (anti-hook)',
      'magisk': 'References Magisk (anti-root)',
      'SIGTRAP': 'References SIGTRAP (breakpoint detection)',
    };

    for (final entry in strChecks.entries) {
      if (_bytesContain(entry.key)) {
        findings.add('⚠ ${entry.value}');
      }
    }

    final initSec = _elf.sectionByName('.init_array');
    if (initSec != null && initSec.size > 0) {
      final ptrSize = _elf.is64 ? 8 : 4;
      final count = initSec.size ~/ ptrSize;
      if (count > 10) {
        findings.add('⚠ Large .init_array ($count entries) — possible anti-debug init chain');
      }
    }

    if (findings.isEmpty) {
      sb.writeln('  No obvious anti-debug patterns detected.');
    } else {
      sb.writeln('  Findings (${findings.length}):');
      for (final f in findings) {
        sb.writeln('  $f');
      }
    }
    return sb.toString().trimRight();
  }

  // ---- Private helpers ----

  bool _bytesContain(String needle) {
    final encoded = utf8.encode(needle);
    if (encoded.length > bytes.length) return false;
    for (var i = 0; i <= bytes.length - encoded.length; i++) {
      var match = true;
      for (var j = 0; j < encoded.length; j++) {
        if (bytes[i + j] != encoded[j]) {
          match = false;
          break;
        }
      }
      if (match) return true;
    }
    return false;
  }

  static int _align4(int v) => (v + 3) & ~3;

  static String _decodeA64(int insn) {
    if (insn == 0xD503201F) return 'nop';
    if (insn == 0xD65F03C0) return 'ret';
    if ((insn & 0xFFE0001F) == 0xD4200000) {
      return 'brk #${(insn >> 5) & 0xFFFF}';
    }
    if ((insn & 0xFFE0001F) == 0xD4000001) {
      return 'svc #${(insn >> 5) & 0xFFFF}';
    }
    if ((insn & 0xFC000000) == 0x14000000) {
      final imm26 = insn & 0x03FFFFFF;
      final off = (imm26 << 2).toSigned(28);
      return 'b ${off >= 0 ? '+' : ''}$off';
    }
    if ((insn & 0xFC000000) == 0x94000000) {
      final imm26 = insn & 0x03FFFFFF;
      final off = (imm26 << 2).toSigned(28);
      return 'bl ${off >= 0 ? '+' : ''}$off';
    }
    if ((insn & 0x7F000000) == 0x54000000) {
      final cond = insn & 0xF;
      const conds = <String>[
        'eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc',
        'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv',
      ];
      final imm19 = (insn >> 5) & 0x7FFFF;
      final off = (imm19 << 2).toSigned(21);
      return 'b.${conds[cond]} $off';
    }
    if ((insn & 0xFF000000) == 0x91000000) {
      final rd = insn & 0x1F;
      final rn = (insn >> 5) & 0x1F;
      final imm12 = (insn >> 10) & 0xFFF;
      return 'add x$rd, x$rn, #$imm12';
    }
    if ((insn & 0xFF000000) == 0xD1000000) {
      final rd = insn & 0x1F;
      final rn = (insn >> 5) & 0x1F;
      final imm12 = (insn >> 10) & 0xFFF;
      return 'sub x$rd, x$rn, #$imm12';
    }
    if ((insn & 0xFF000000) == 0xF9400000) {
      final rt = insn & 0x1F;
      final rn = (insn >> 5) & 0x1F;
      final imm12 = ((insn >> 10) & 0xFFF) * 8;
      return 'ldr x$rt, [x$rn, #$imm12]';
    }
    if ((insn & 0xFF000000) == 0xF9000000) {
      final rt = insn & 0x1F;
      final rn = (insn >> 5) & 0x1F;
      final imm12 = ((insn >> 10) & 0xFFF) * 8;
      return 'str x$rt, [x$rn, #$imm12]';
    }
    if ((insn & 0xFFE0FFE0) == 0xAA0003E0) {
      final rd = insn & 0x1F;
      final rm = (insn >> 16) & 0x1F;
      return 'mov x$rd, x$rm';
    }
    if ((insn & 0xFFC00000) == 0xA9000000) {
      final rt = insn & 0x1F;
      final rt2 = (insn >> 10) & 0x1F;
      final rn = (insn >> 5) & 0x1F;
      final imm7 = ((insn >> 15) & 0x7F) * 8;
      return 'stp x$rt, x$rt2, [x$rn, #$imm7]';
    }
    if ((insn & 0xFFC00000) == 0xA9400000) {
      final rt = insn & 0x1F;
      final rt2 = (insn >> 10) & 0x1F;
      final rn = (insn >> 5) & 0x1F;
      final imm7 = ((insn >> 15) & 0x7F) * 8;
      return 'ldp x$rt, x$rt2, [x$rn, #$imm7]';
    }
    if ((insn & 0x7F000000) == 0x34000000) {
      final rt = insn & 0x1F;
      final imm19 = (insn >> 5) & 0x7FFFF;
      final off = (imm19 << 2).toSigned(21);
      return 'cbz x$rt, $off';
    }
    if ((insn & 0x7F000000) == 0x35000000) {
      final rt = insn & 0x1F;
      final imm19 = (insn >> 5) & 0x7FFFF;
      final off = (imm19 << 2).toSigned(21);
      return 'cbnz x$rt, $off';
    }
    return 'dc64 0x${insn.toRadixString(16).padLeft(8, '0')}';
  }
}
