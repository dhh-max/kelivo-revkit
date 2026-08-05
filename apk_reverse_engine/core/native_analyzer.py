import re, struct

class NativeAnalyzer:
    ELF_MAGIC = b'\x7fELF'
    MACHINE_TYPES = {0: 'None', 2: 'SPARC', 3: 'x86', 8: 'MIPS', 40: 'ARM', 62: 'x86_64', 183: 'ARM64', 243: 'RISC-V'}
    SEGMENT_TYPES = {0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO'}

    @staticmethod
    def is_elf(data): return len(data) >= 4 and data[:4] == NativeAnalyzer.ELF_MAGIC

    @staticmethod
    def analyze(data):
        if not NativeAnalyzer.is_elf(data): return {'error': 'not ELF'}
        if len(data) < 64: return {'error': 'too small'}
        bit = data[4]; endian = '<' if data[5] == 1 else '>'
        machine = struct.unpack(endian + 'H', data[18:20])[0]
        is_64 = bit == 2
        e_type = struct.unpack(endian + 'H', data[16:18])[0]
        if is_64:
            entry = struct.unpack(endian + 'Q', data[24:32])[0]
            phoff = struct.unpack(endian + 'Q', data[32:40])[0]
            shoff = struct.unpack(endian + 'Q', data[40:48])[0]
            phnum = struct.unpack(endian + 'H', data[56:58])[0]
            phentsize = struct.unpack(endian + 'H', data[54:56])[0]
        else:
            entry = struct.unpack(endian + 'I', data[24:28])[0]
            phoff = struct.unpack(endian + 'I', data[28:32])[0]
            shoff = struct.unpack(endian + 'I', data[32:36])[0]
            phnum = struct.unpack(endian + 'H', data[44:46])[0]
            phentsize = struct.unpack(endian + 'H', data[42:44])[0]
        arch = NativeAnalyzer.MACHINE_TYPES.get(machine, f'unknown({machine})')
        etype_map = {0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN'}
        segments = []
        if phoff > 0 and phnum > 0:
            for i in range(min(phnum, 20)):
                seg_off = phoff + i * phentsize
                if seg_off + phentsize > len(data): break
                if is_64:
                    seg_type = struct.unpack(endian + 'I', data[seg_off:seg_off+4])[0]
                    seg_flags = struct.unpack(endian + 'I', data[seg_off+4:seg_off+8])[0]
                    seg_offset = struct.unpack(endian + 'Q', data[seg_off+8:seg_off+16])[0]
                    seg_vaddr = struct.unpack(endian + 'Q', data[seg_off+16:seg_off+24])[0]
                    seg_filesz = struct.unpack(endian + 'Q', data[seg_off+32:seg_off+40])[0]
                    seg_memsz = struct.unpack(endian + 'Q', data[seg_off+40:seg_off+48])[0]
                else:
                    seg_type = struct.unpack(endian + 'I', data[seg_off:seg_off+4])[0]
                    seg_offset = struct.unpack(endian + 'I', data[seg_off+4:seg_off+8])[0]
                    seg_vaddr = struct.unpack(endian + 'I', data[seg_off+8:seg_off+12])[0]
                    seg_filesz = struct.unpack(endian + 'I', data[seg_off+16:seg_off+20])[0]
                    seg_memsz = struct.unpack(endian + 'I', data[seg_off+20:seg_off+24])[0]
                    seg_flags = struct.unpack(endian + 'I', data[seg_off+24:seg_off+28])[0]
                segments.append({'index': i, 'type': NativeAnalyzer.SEGMENT_TYPES.get(seg_type, f'0x{seg_type:x}'), 'offset': seg_offset, 'vaddr': hex(seg_vaddr), 'filesz': seg_filesz, 'memsz': seg_memsz})
        imports = []
        common_funcs = ['malloc','free','memcpy','memset','strcpy','strlen','strcmp','printf','sprintf','fopen','fclose','fread','fwrite','open','close','read','write','mmap','munmap','socket','connect','bind','listen','accept','send','recv','dlopen','dlsym','dlclose','pthread_create','pthread_join','pthread_mutex_lock','JNI_OnLoad','Java_','NewStringUTF','FindClass','GetMethodID','AES_','MD5','SHA1','SHA256','RSA_','EVP_','HMAC','__android_log_print']
        for func in common_funcs:
            if func.encode() in data: imports.append(func)
        return {'bit': 64 if is_64 else 32, 'arch': arch, 'type': etype_map.get(e_type, 'unknown'), 'entry_point': hex(entry), 'segments': segments, 'import_count': len(imports), 'imports': list(set(imports))[:50], 'size': len(data)}

    @staticmethod
    def find_strings(data, min_len=4):
        strings = []
        for m in re.finditer(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', data):
            try: strings.append(m.group().decode('ascii', errors='replace'))
            except: pass
        return strings

    @staticmethod
    def find_imports(data): return NativeAnalyzer.analyze(data).get('imports', [])

    @staticmethod
    def detect_crypto(data):
        crypto_indicators = {'AES': ['AES_set_encrypt_key','AES_cbc_encrypt'], 'RSA': ['RSA_public_encrypt','RSA_private_decrypt'], 'MD5': ['MD5_Init','MD5_Update','MD5_Final'], 'SHA256': ['SHA256_Init','SHA256_Update','SHA256_Final'], 'HMAC': ['HMAC_Init','HMAC_Update'], 'OpenSSL': ['SSL_library_init','OpenSSL_add_all_algorithms']}
        found = {}
        for name, indicators in crypto_indicators.items():
            matches = [i for i in indicators if i.encode() in data]
            if matches: found[name] = matches
        return found
