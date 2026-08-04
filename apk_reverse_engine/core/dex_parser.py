import struct, hashlib
class DexParser:
    """DEX文件解析器 - 解析classes.dex结构"""
    HEADER_FMT = '<8sIII4xIIIIIIII'
    def __init__(self, data): self.data = data
    def parse_header(self):
        if len(self.data) < 112: return {'error': 'data too small'}
        magic, version, checksum, sig_offset, sig_size, file_size, header_size, endian, link_size, link_off, map_off, str_ids_size, str_ids_off, type_ids_size, type_ids_off, proto_ids_size, proto_ids_off, field_ids_size, field_ids_off, method_ids_size, method_ids_off, class_defs_size, class_defs_off, data_size, data_off = struct.unpack_from(self.HEADER_FMT + 'IIIIIIII', self.data, 0)
        # fix: use correct format
        magic = self.data[0:8]
        version = self.data[4:8].decode('utf-8', errors='replace')
        checksum = struct.unpack_from('<I', self.data, 8)[0]
        file_size = struct.unpack_from('<I', self.data, 32)[0]
        header_size = struct.unpack_from('<I', self.data, 36)[0]
        endian = struct.unpack_from('<I', self.data, 40)[0]
        link_size = struct.unpack_from('<I', self.data, 44)[0]
        link_off = struct.unpack_from('<I', self.data, 48)[0]
        map_off = struct.unpack_from('<I', self.data, 52)[0]
        str_ids_size = struct.unpack_from('<I', self.data, 56)[0]
        str_ids_off = struct.unpack_from('<I', self.data, 60)[0]
        type_ids_size = struct.unpack_from('<I', self.data, 64)[0]
        type_ids_off = struct.unpack_from('<I', self.data, 68)[0]
        proto_ids_size = struct.unpack_from('<I', self.data, 72)[0]
        proto_ids_off = struct.unpack_from('<I', self.data, 76)[0]
        field_ids_size = struct.unpack_from('<I', self.data, 80)[0]
        field_ids_off = struct.unpack_from('<I', self.data, 84)[0]
        method_ids_size = struct.unpack_from('<I', self.data, 88)[0]
        method_ids_off = struct.unpack_from('<I', self.data, 92)[0]
        class_defs_size = struct.unpack_from('<I', self.data, 96)[0]
        class_defs_off = struct.unpack_from('<I', self.data, 100)[0]
        data_size = struct.unpack_from('<I', self.data, 104)[0]
        data_off = struct.unpack_from('<I', self.data, 108)[0]
        return {
            'magic': magic.decode('utf-8', errors='replace'),
            'version': version, 'checksum': hex(checksum),
            'file_size': file_size, 'header_size': header_size,
            'endian': '<' if endian == 0x12345678 else '>',
            'string_ids': str_ids_size, 'type_ids': type_ids_size,
            'proto_ids': proto_ids_size, 'field_ids': field_ids_size,
            'method_ids': method_ids_size, 'class_defs': class_defs_size,
            'sha1': hashlib.sha1(self.data[32:]).hexdigest()
        }
    def get_string(self, idx):
        h = self.parse_header()
        off = struct.unpack_from('<I', self.data, h['string_ids'] + idx * 4)[0]
        end = self.data.index(b'\x00', off)
        return self.data[off:end].decode('utf-8', errors='replace')
    def get_class_names(self):
        h = self.parse_header()
        classes = []
        for i in range(h['class_defs']):
            off = h['class_defs'] + i * 32
            if off + 32 > len(self.data): break
            ci = struct.unpack_from('<I', self.data, off)[0]
            classes.append(self.get_string(ci))
        return classes
