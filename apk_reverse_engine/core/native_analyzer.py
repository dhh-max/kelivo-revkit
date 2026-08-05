import struct, re

class ElfSection:
    def __init__(self, name_offset, type_, addr, offset, size, link, info, entsize):
        self.name_offset = name_offset
        self.type = type_
        self.addr = addr
        self.offset = offset
        self.size = size
        self.link = link
        self.info = info
        self.entsize = entsize
        self.name = ''

    SECTION_TYPES = {0:'NULL',1:'PROGBITS',2:'SYMTAB',3:'STRTAB',4:'RELA',
                     5:'HASH',6:'DYNAMIC',7:'NOTE',8:'NOBITS',9:'REL',
                     10:'SHLIB',11:'DYNSYM',14:'INIT_ARRAY',15:'FINI_ARRAY',
                     16:'PREINIT_ARRAY',0x6ffffff6:'GNU_HASH',
                     0x6fffffff:'VERSYM',0x6ffffffc:'VERDEF',
                     0x6ffffffd:'VERNEED'}
    def type_label(self): return self.SECTION_TYPES.get(self.type, f'type({self.type})')

class ElfSymbol:
    def __init__(self, name, bind, type_, shndx, value, size):
        self.name = name
        self.bind = bind
        self.type = type_
        self.shndx = shndx
        self.value = value
        self.size = size
    @property
    def is_undefined(self): return self.shndx == 0
    @property
    def is_global(self): return self.bind in (1, 2)
    @property
    def is_func_or_object(self): return self.type in (1, 2)
    def bind_label(self): return {0:'LOCAL',1:'GLOBAL',2:'WEAK'}.get(self.bind, f'bind({self.bind})')
    def type_label(self): return {0:'NOTYPE',1:'OBJECT',2:'FUNC',3:'SECTION',4:'FILE'}.get(self.type, f'type({self.type})')

class ElfImage:
    """Pure-Python ELF parser supporting 32/64-bit, LE/BE"""
    
    MACHINE_TYPES = {0x03:'x86',0x08:'MIPS',0x28:'ARM',0x3E:'x86_64',0xB7:'AArch64',0xF3:'RISC-V'}
    SEGMENT_TYPES = {0:'NULL',1:'LOAD',2:'DYNAMIC',3:'INTERP',4:'NOTE',5:'SHLIB',6:'PHDR',7:'TLS',
                     0x6474e550:'GNU_EH_FRAME',0x6474e551:'GNU_STACK',0x6474e552:'GNU_RELRO',0x6474e553:'GNU_PROPERTY'}
    DYNAMIC_TAGS = {1:'DT_NEEDED',2:'DT_PLTRELSZ',3:'DT_PLTGOT',4:'DT_HASH',5:'DT_STRTAB',6:'DT_SYMTAB',
                    7:'DT_RELA',8:'DT_RELASZ',9:'DT_RELAENT',10:'DT_STRSZ',11:'DT_SYMENT',12:'DT_INIT',
                    13:'DT_FINI',14:'DT_SONAME',15:'DT_RPATH',16:'DT_SYMBOLIC',17:'DT_REL',18:'DT_RELSZ',
                    19:'DT_RELENT',21:'DT_PLTREL',23:'DT_JMPREL',24:'DT_BIND_NOW',25:'DT_INIT_ARRAY',
                    26:'DT_FINI_ARRAY',27:'DT_INIT_ARRAYSZ',28:'DT_FINI_ARRAYSZ',
                    0x6ffffef5:'DT_GNU_HASH',0x6ffffff0:'DT_VERSYM',
                    0x6ffffff1:'DT_RELACOUNT',0x6ffffff9:'DT_RELCOUNT'}

    def __init__(self, data):
        self.data = data
        self.length = len(data)
        self.is64 = False
        self.endian = '<'
        self.e_type = 0
        self.e_machine = 0
        self.e_entry = 0
        self.e_shoff = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0
        self.e_phoff = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.sections = []

    @staticmethod
    def parse(data):
        if len(data) < 20:
            raise ValueError('Not an ELF file: too short')
        if data[0:4] != b'\\x7fELF':
            raise ValueError('Not an ELF file: bad magic')
        img = ElfImage(data)
        img.is64 = data[4] == 2
        img.endian = '>' if data[5] == 2 else '<'
        img._read_header()
        img._read_sections()
        return img

    def _u16(self, off): return struct.unpack_from(self.endian + 'H', self.data, off)[0]
    def _u32(self, off): return struct.unpack_from(self.endian + 'I', self.data, off)[0]
    def _u64(self, off): return struct.unpack_from(self.endian + 'Q', self.data, off)[0]

    def _read_header(self):
        d = self.data; e = self.endian
        self.e_type = struct.unpack_from(e + 'H', d, 16)[0]
        self.e_machine = struct.unpack_from(e + 'H', d, 18)[0]
        if self.is64:
            self.e_entry = struct.unpack_from(e + 'Q', d, 24)[0]
            self.e_phoff = struct.unpack_from(e + 'Q', d, 32)[0]
            self.e_shoff = struct.unpack_from(e + 'Q', d, 40)[0]
            self.e_phentsize = struct.unpack_from(e + 'H', d, 54)[0]
            self.e_phnum = struct.unpack_from(e + 'H', d, 56)[0]
            self.e_shentsize = struct.unpack_from(e + 'H', d, 58)[0]
            self.e_shnum = struct.unpack_from(e + 'H', d, 60)[0]
            self.e_shstrndx = struct.unpack_from(e + 'H', d, 62)[0]
        else:
            self.e_entry = struct.unpack_from(e + 'I', d, 24)[0]
            self.e_phoff = struct.unpack_from(e + 'I', d, 28)[0]
            self.e_shoff = struct.unpack_from(e + 'I', d, 32)[0]
            self.e_phentsize = struct.unpack_from(e + 'H', d, 42)[0]
            self.e_phnum = struct.unpack_from(e + 'H', d, 44)[0]
            self.e_shentsize = struct.unpack_from(e + 'H', d, 46)[0]
            self.e_shnum = struct.unpack_from(e + 'H', d, 48)[0]
            self.e_shstrndx = struct.unpack_from(e + 'H', d, 50)[0]

    def _read_asciiz(self, offset):
        if offset < 0 or offset >= self.length: return ''
        end = self.data.index(b'\\x00', offset) if b'\\x00' in self.data[offset:offset+256] else self.length
        return self.data[offset:end].decode('utf-8', errors='replace')

    def _read_sections(self):
        if self.e_shoff == 0 or self.e_shnum == 0: return
        for i in range(self.e_shnum):
            base = self.e_shoff + i * self.e_shentsize
            if base + self.e_shentsize > self.length: break
            name_off = self._u32(base)
            type_ = self._u32(base + 4)
            if self.is64:
                addr = self._u64(base + 16)
                offset = self._u64(base + 24)
                size = self._u64(base + 32)
                link = self._u32(base + 40)
                info = self._u32(base + 44)
                entsize = self._u64(base + 56)
            else:
                addr = self._u32(base + 12)
                offset = self._u32(base + 16)
                size = self._u32(base + 20)
                link = self._u32(base + 24)
                info = self._u32(base + 28)
                entsize = self._u32(base + 36)
            self.sections.append(ElfSection(name_off, type_, addr, offset, size, link, info, entsize))
        if self.e_shstrndx < len(self.sections):
            shstr = self.sections[self.e_shstrndx]
            for s in self.sections:
                s.name = self._read_asciiz(shstr.offset + s.name_offset)

    def section_by_name(self, name):
        for s in self.sections:
            if s.name == name: return s
        return None

    def read_symbols(self, symtab, strtab):
        out = []
        ent_size = 24 if self.is64 else 16
        if symtab.size == 0: return out
        count = symtab.size // ent_size
        for i in range(count):
            base = symtab.offset + i * ent_size
            if base + ent_size > self.length: break
            if self.is64:
                st_name = self._u32(base)
                st_info = self.data[base + 4]
                st_shndx = self._u16(base + 6)
                st_value = self._u64(base + 8)
                st_size = self._u64(base + 16)
            else:
                st_name = self._u32(base)
                st_value = self._u32(base + 4)
                st_size = self._u32(base + 8)
                st_info = self.data[base + 12]
                st_shndx = self._u16(base + 14)
            name = self._read_asciiz(strtab.offset + st_name)
            if not name and st_name == 0: continue
            out.append(ElfSymbol(name, st_info >> 4, st_info & 0xf, st_shndx, st_value, st_size))
        return out

    def read_needed(self):
        dyn = self.section_by_name('.dynamic')
        dynstr = self.section_by_name('.dynstr')
        if not dyn or not dynstr: return []
        out = []
        ent_size = 16 if self.is64 else 8
        count = dyn.size // ent_size
        for i in range(count):
            base = dyn.offset + i * ent_size
            if base + ent_size > self.length: break
            tag = self._u64(base) if self.is64 else self._u32(base)
            val = self._u64(base + 8) if self.is64 else self._u32(base + 4)
            if tag == 0: break
            if tag == 1: out.append(self._read_asciiz(dynstr.offset + val))
        return out

    def read_dynamic_entries(self):
        dyn = self.section_by_name('.dynamic')
        if not dyn: return []
        out = []
        ent_size = 16 if self.is64 else 8
        count = dyn.size // ent_size
        dynstr = self.section_by_name('.dynstr')
        for i in range(count):
            base = dyn.offset + i * ent_size
            if base + ent_size > self.length: break
            tag = self._u64(base) if self.is64 else self._u32(base)
            val = self._u64(base + 8) if self.is64 else self._u32(base + 4)
            if tag == 0: break
            tag_name = self.DYNAMIC_TAGS.get(tag, f'DT_?(0x{tag:x})')
            if tag == 1 and dynstr:
                out.append({'tag': tag_name, 'value': self._read_asciiz(dynstr.offset + val)})
            else:
                out.append({'tag': tag_name, 'value': f'0x{val:x}'})
        return out

    def read_program_headers(self):
        if self.e_phoff == 0 or self.e_phnum == 0: return []
        out = []
        for i in range(self.e_phnum):
            base = self.e_phoff + i * self.e_phentsize
            if base + self.e_phentsize > self.length: break
            p_type = self._u32(base)
            if self.is64:
                p_flags = self._u32(base + 4)
                p_offset = self._u64(base + 8)
                p_vaddr = self._u64(base + 16)
                p_filesz = self._u64(base + 32)
                p_memsz = self._u64(base + 40)
                p_align = self._u64(base + 48)
            else:
                p_offset = self._u32(base + 4)
                p_vaddr = self._u32(base + 8)
                p_filesz = self._u32(base + 16)
                p_memsz = self._u32(base + 20)
                p_flags = self._u32(base + 24)
                p_align = self._u32(base + 28)
            flags_str = ''
            if p_flags & 4: flags_str += 'R'
            if p_flags & 2: flags_str += 'W'
            if p_flags & 1: flags_str += 'X'
            out.append({
                'index': i, 'type': self.SEGMENT_TYPES.get(p_type, f'0x{p_type:x}'),
                'flags': flags_str, 'offset': p_offset, 'vaddr': p_vaddr,
                'filesz': p_filesz, 'memsz': p_memsz, 'align': p_align
            })
        return out

    def read_relocations(self):
        out = []
        dynstr = self.section_by_name('.dynstr')
        for sec_name in ['.rela.plt', '.rel.plt', '.rela.dyn', '.rel.dyn']:
            sec = self.section_by_name(sec_name)
            if not sec or sec.size == 0: continue
            is_rela = sec_name.startswith('.rela')
            ent_size = 24 if self.is64 else 12 if is_rela else 8
            count = sec.size // ent_size
            for i in range(count):
                base = sec.offset + i * ent_size
                if base + ent_size > self.length: break
                if self.is64:
                    offset = self._u64(base)
                    info = self._u64(base + 8)
                    addend = self._u64(base + 16) if is_rela else 0
                else:
                    offset = self._u32(base)
                    info = self._u32(base + 4)
                    addend = self._u32(base + 8) if is_rela else 0
                sym_idx = info >> 32 if self.is64 else info >> 8
                rel_type = info & 0xffffffff if self.is64 else info & 0xff
                sym_name = ''
                if dynstr and sym_idx > 0:
                    sym_base = self.section_by_name('.dynsym').offset + sym_idx * (24 if self.is64 else 16)
                    if sym_base + 4 <= self.length:
                        sym_name = self._read_asciiz(dynstr.offset + self._u32(sym_base))
                out.append({'section': sec_name, 'offset': f'0x{offset:x}', 'type': rel_type,
                            'sym_idx': sym_idx, 'sym_name': sym_name, 'addend': f'0x{addend:x}' if is_rela else None})
        return out

    def addr_to_file_offset(self, addr):
        for seg in self.read_program_headers():
            if seg['type'] == 'LOAD' and seg['vaddr'] <= addr < seg['vaddr'] + seg['filesz']:
                return (seg['offset'] + (addr - seg['vaddr']))
        return None

    def file_offset_to_addr(self, offset):
        for seg in self.read_program_headers():
            if seg['type'] == 'LOAD' and seg['offset'] <= offset < seg['offset'] + seg['filesz']:
                return (seg['vaddr'] + (offset - seg['offset']))
        return None

    def symbol_at_addr(self, addr):
        for symsec_name in ['.dynsym', '.symtab']:
            strsec_name = '.dynstr' if symsec_name == '.dynsym' else '.strtab'
            symsec = self.section_by_name(symsec_name)
            strsec = self.section_by_name(strsec_name)
            if symsec and strsec:
                for s in self.read_symbols(symsec, strsec):
                    if s.value == addr and s.name:
                        return s.name
        return ''

    def addr_of_symbol(self, name):
        for symsec_name in ['.dynsym', '.symtab']:
            strsec_name = '.dynstr' if symsec_name == '.dynsym' else '.strtab'
            symsec = self.section_by_name(symsec_name)
            strsec = self.section_by_name(strsec_name)
            if symsec and strsec:
                for s in self.read_symbols(symsec, strsec):
                    if s.name == name:
                        return s.value
        return None

    def class_label(self): return 'ELF64' if self.is64 else 'ELF32'
    def endian_label(self): return 'big' if self.endian == '>' else 'little'
    def type_label(self):
        return {1:'REL (relocatable)',2:'EXEC (executable)',3:'DYN (shared object)',4:'CORE'}.get(self.e_type, f'UNKNOWN({self.e_type})')
    def machine_label(self):
        return self.MACHINE_TYPES.get(self.e_machine, f'machine(0x{self.e_machine:x})')

    def get_summary(self):
        """返回ELF解析摘要"""
        dynsym = self.section_by_name('.dynsym')
        dynstr = self.section_by_name('.dynstr')
        symtab = self.section_by_name('.symtab')
        strtab = self.section_by_name('.strtab')
        imports = []
        exports = []
        if dynsym and dynstr:
            for s in self.read_symbols(dynsym, dynstr):
                if s.is_undefined and s.name and s.is_func_or_object:
                    imports.append(s.name)
                if not s.is_undefined and s.is_global and s.name and s.is_func_or_object:
                    exports.append(s.name)
        needed = self.read_needed()
        return {
            'class': self.class_label(),
            'endian': self.endian_label(),
            'type': self.type_label(),
            'machine': self.machine_label(),
            'entry': hex(self.e_entry),
            'sections': len(self.sections),
            'segments': self.e_phnum,
            'import_count': len(imports),
            'exports_count': len(exports),
            'dependencies': needed,
            'imports': imports[:50],
            'exports': exports[:50],
        }


class NativeAnalyzer:
    """基于ElfImage的完整SO文件分析器"""

    @staticmethod
    def is_elf(data):
        return len(data) >= 4 and data[:4] == b'\\x7fELF'

    @staticmethod
    def analyze(data):
        if not NativeAnalyzer.is_elf(data):
            return {'error': 'not ELF file'}
        try:
            elf = ElfImage.parse(data)
            return elf.get_summary()
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def find_strings(data, min_len=4, limit=1000):
        strings = []
        buf = []
        for byte in data:
            if 0x20 <= byte < 0x7f:
                buf.append(chr(byte))
            else:
                if len(buf) >= min_len:
                    strings.append(''.join(buf))
                    if len(strings) >= limit: break
                buf = []
        if len(buf) >= min_len and len(strings) < limit:
            strings.append(''.join(buf))
        return strings

    @staticmethod
    def find_imports(data):
        try:
            elf = ElfImage.parse(data)
            dynsym = elf.section_by_name('.dynsym')
            dynstr = elf.section_by_name('.dynstr')
            if not dynsym or not dynstr: return []
            return [s.name for s in elf.read_symbols(dynsym, dynstr)
                    if s.is_undefined and s.name and s.is_func_or_object][:100]
        except:
            return []

    @staticmethod
    def find_exports(data):
        try:
            elf = ElfImage.parse(data)
            dynsym = elf.section_by_name('.dynsym')
            dynstr = elf.section_by_name('.dynstr')
            if not dynsym or not dynstr: return []
            return [s.name for s in elf.read_symbols(dynsym, dynstr)
                    if not s.is_undefined and s.is_global and s.name and s.is_func_or_object][:100]
        except:
            return []

    @staticmethod
    def detect_crypto(data):
        crypto_indicators = {
            'AES': ['AES_set_encrypt_key','AES_cbc_encrypt','AES256'],
            'RSA': ['RSA_public_encrypt','RSA_private_decrypt','RSA_generate_key'],
            'MD5': ['MD5_Init','MD5_Update','MD5_Final'],
            'SHA1': ['SHA1_Init','SHA1_Update','SHA1_Final'],
            'SHA256': ['SHA256_Init','SHA256_Update','SHA256_Final'],
            'HMAC': ['HMAC_Init','HMAC_Update','HMAC_Final'],
            'EVP': ['EVP_EncryptInit','EVP_DecryptInit','EVP_CipherInit'],
            'Base64': ['EVP_EncodeBlock','EVP_DecodeBlock'],
            'OpenSSL': ['OpenSSL_add_all_algorithms','SSL_library_init'],
            'BoringSSL': ['CRYPTO_new','BORINGSSL_'],
        }
        found = {}
        for name, indicators in crypto_indicators.items():
            matches = [i for i in indicators if i.encode() in data]
            if matches: found[name] = matches
        return found

    @staticmethod
    def detect_packer(data):
        """通过SO文件特征检测加固壳/保护"""
        indicators = {
            'UPX': ['UPX!', 'UPX0', 'UPX1', 'UPX2'],
            'OLLVM': ['llvm', 'obfuscator'],
            'Arxan': ['arxan', 'DEX', 'libprotect'],
            'Tencent': ['tcloud', 'TPRI'],
        }
        found = []
        for name, pats in indicators.items():
            for p in pats:
                if p.encode() in data:
                    found.append(name)
                    break
        return list(set(found))

    @staticmethod
    def parse_full(data):
        """返回完整的ELF解析结果"""
        try:
            elf = ElfImage.parse(data)
            return {
                'header': {
                    'class': elf.class_label(),
                    'endian': elf.endian_label(),
                    'type': elf.type_label(),
                    'machine': elf.machine_label(),
                    'entry': hex(elf.e_entry),
                    'sections': elf.e_shnum,
                    'segments': elf.e_phnum,
                    'section_header_offset': elf.e_shoff,
                    'program_header_offset': elf.e_phoff,
                },
                'sections': [{'name': s.name, 'type': s.type_label(), 'addr': hex(s.addr),
                              'offset': hex(s.offset), 'size': s.size} for s in elf.sections],
                'segments': elf.read_program_headers()[:20],
                'dynamic': elf.read_dynamic_entries()[:50],
                'dependencies': elf.read_needed(),
                'relocations': elf.read_relocations()[:100],
                'summary': elf.get_summary(),
            }
        except Exception as e:
            return {'error': str(e)}
