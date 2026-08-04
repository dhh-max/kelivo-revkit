import re, struct
class NativeAnalyzer:
    """Native SO文件分析器"""
    ELF_MAGIC = b'\\x7fELF'
    @staticmethod
    def is_elf(data): return data[:4] == NativeAnalyzer.ELF_MAGIC
    @staticmethod
    def analyze(data):
        if not NativeAnalyzer.is_elf(data): return {'error': 'not ELF'}
        bit = data[4]
        endian = '<' if data[5] == 1 else '>'
        arch = {3: 'x86', 40: 'ARM', 62: 'x86_64', 183: 'ARM64', 243: 'RISC-V'}.get(data[18], 'unknown')
        return {'bit': 32 if bit == 1 else 64, 'arch': arch, 'endian': endian, 'size': len(data)}
    @staticmethod
    def find_strings(data, min_len=4):
        strings = []
        for m in re.finditer(rb'[\\x20-\\x7e]{' + str(min_len).encode() + rb',}', data):
            strings.append(m.group().decode('ascii', errors='replace'))
        return strings
    @staticmethod
    def find_imports(data):
        imports = []
        for m in re.finditer(rb'\x00([a-zA-Z_][a-zA-Z0-9_]*)\x00', data):
            s = m.group(1).decode('ascii', errors='replace')
            if len(s) > 2: imports.append(s)
        return list(set(imports))[:100]
