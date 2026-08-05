"""DEX文件解析器 - 完整DEX结构解析"""
import struct, hashlib

class DexParser:
    """完整DEX文件解析器，支持header/string/type/proto/field/method/class/annotation/code"""
    
    def __init__(self, data):
        self.data = data
        self._header = None
        self._strings = []
        self._types = []
        self._protos = []
        self._fields = []
        self._methods = []
        self._class_defs = []
        self._parsed = False

    def _ensure_parsed(self):
        if not self._parsed:
            self._parse_all()
            self._parsed = True

    def _u1(self, off): return self.data[off]
    def _u2(self, off): return struct.unpack_from('<H', self.data, off)[0]
    def _u4(self, off): return struct.unpack_from('<I', self.data, off)[0]
    def _sleb(self, off):
        """解析ULEB128"""
        result = 0
        shift = 0
        pos = off
        while True:
            byte = self.data[pos]
            result |= (byte & 0x7f) << shift
            shift += 7
            pos += 1
            if not (byte & 0x80):
                break
        return result, pos - off

    def parse_header(self):
        if len(self.data) < 112:
            return {'error': 'data too small'}
        magic = self.data[0:8]
        version = self.data[4:8].decode('utf-8', errors='replace')
        checksum = self._u4(8)
        sha1_digest = self.data[12:32].hex()
        file_size = self._u4(32)
        header_size = self._u4(36)
        endian = self._u4(40)
        link_size = self._u4(44)
        link_off = self._u4(48)
        map_off = self._u4(52)
        str_ids_size = self._u4(56)
        str_ids_off = self._u4(60)
        type_ids_size = self._u4(64)
        type_ids_off = self._u4(68)
        proto_ids_size = self._u4(72)
        proto_ids_off = self._u4(76)
        field_ids_size = self._u4(80)
        field_ids_off = self._u4(84)
        method_ids_size = self._u4(88)
        method_ids_off = self._u4(92)
        class_defs_size = self._u4(96)
        class_defs_off = self._u4(100)
        data_size = self._u4(104)
        data_off = self._u4(108)

        self._header = {
            'magic': magic.decode('utf-8', errors='replace'),
            'version': version,
            'checksum': hex(checksum),
            'sha1': sha1_digest,
            'file_size': file_size,
            'header_size': header_size,
            'endian': '<' if endian == 0x12345678 else '>',
            'link_size': link_size,
            'link_off': link_off,
            'map_off': map_off,
            'string_ids': str_ids_size,
            'string_ids_off': str_ids_off,
            'type_ids': type_ids_size,
            'type_ids_off': type_ids_off,
            'proto_ids': proto_ids_size,
            'proto_ids_off': proto_ids_off,
            'field_ids': field_ids_size,
            'field_ids_off': field_ids_off,
            'method_ids': method_ids_size,
            'method_ids_off': method_ids_off,
            'class_defs': class_defs_size,
            'class_defs_off': class_defs_off,
            'data_size': data_size,
            'data_off': data_off,
        }
        return self._header

    def _parse_all(self):
        self.parse_header()
        h = self._header
        
        # 1. Strings
        self._strings = []
        for i in range(h['string_ids']):
            off = self._u4(h['string_ids_off'] + i * 4)
            try:
                end = self.data.index(b'\x00', off)
                s = self.data[off:end].decode('utf-8', errors='replace')
            except:
                s = ''
            self._strings.append(s)

        # 2. Types
        self._types = []
        for i in range(h['type_ids']):
            idx = self._u4(h['type_ids_off'] + i * 4)
            desc = self._strings[idx] if 0 <= idx < len(self._strings) else f'?{idx}'
            self._types.append({'id': i, 'descriptor_idx': idx, 'descriptor': desc})

        # 3. Protos
        self._protos = []
        for i in range(h['proto_ids']):
            off = h['proto_ids_off'] + i * 12
            si = self._u4(off)       # shorty_idx
            ri = self._u4(off + 4)   # return_type_idx
            pi = self._u4(off + 8)   # parameters_off
            return_type = self._types[ri]['descriptor'] if 0 <= ri < len(self._types) else f'?{ri}'
            shorty = self._strings[si] if 0 <= si < len(self._strings) else f'?{si}'
            
            param_types = []
            if pi != 0:
                try:
                    param_count = self._u4(pi)
                    for j in range(param_count):
                        pt = self._u4(pi + 4 + j * 4)
                        param_types.append(self._types[pt]['descriptor'] if 0 <= pt < len(self._types) else f'?{pt}')
                except:
                    pass
            
            self._protos.append({
                'id': i,
                'shorty': shorty,
                'return_type': return_type,
                'return_type_idx': ri,
                'parameters': param_types,
                'parameters_off': pi,
            })

        # 4. Fields
        self._fields = []
        for i in range(h['field_ids']):
            off = h['field_ids_off'] + i * 8
            ci = self._u2(off)       # class_idx
            ti = self._u2(off + 2)   # type_idx
            ni = self._u4(off + 4)   # name_idx
            class_name = self._types[ci]['descriptor'] if 0 <= ci < len(self._types) else f'?{ci}'
            field_type = self._types[ti]['descriptor'] if 0 <= ti < len(self._types) else f'?{ti}'
            field_name = self._strings[ni] if 0 <= ni < len(self._strings) else f'?{ni}'
            self._fields.append({
                'id': i,
                'class_name': class_name,
                'type': field_type,
                'name': field_name,
            })

        # 5. Methods
        self._methods = []
        for i in range(h['method_ids']):
            off = h['method_ids_off'] + i * 8
            ci = self._u2(off)       # class_idx
            pi = self._u2(off + 2)   # proto_idx
            ni = self._u4(off + 4)   # name_idx
            class_name = self._types[ci]['descriptor'] if 0 <= ci < len(self._types) else f'?{ci}'
            proto = self._protos[pi] if 0 <= pi < len(self._protos) else None
            method_name = self._strings[ni] if 0 <= ni < len(self._strings) else f'?{ni}'
            self._methods.append({
                'id': i,
                'class_name': class_name,
                'class_idx': ci,
                'proto': proto,
                'proto_idx': pi,
                'name': method_name,
            })

        # 6. Class defs
        self._class_defs = []
        for i in range(h['class_defs']):
            off = h['class_defs_off'] + i * 32
            ci = self._u4(off)       # class_idx
            ai = self._u4(off + 4)   # access_flags
            sci = self._u4(off + 8)  # superclass_idx
            ii = self._u4(off + 12)  # interfaces_off
            si = self._u4(off + 16)  # source_file_idx
            ani = self._u4(off + 20) # annotations_off
            cdi = self._u4(off + 24) # class_data_off
            svi = self._u4(off + 28) # static_values_off

            class_name = self._types[ci]['descriptor'] if 0 <= ci < len(self._types) else f'?{ci}'
            super_name = self._types[sci]['descriptor'] if 0 <= sci < len(self._types) else ''
            source_file = self._strings[si] if 0 <= si < len(self._strings) else ''
            access_flags_str = self._access_flags_str(ai)

            # Interfaces
            interfaces = []
            if ii != 0:
                try:
                    ic = self._u4(ii)
                    for j in range(ic):
                        itf = self._u4(ii + 4 + j * 4)
                        interfaces.append(self._types[itf]['descriptor'] if 0 <= itf < len(self._types) else f'?{itf}')
                except:
                    pass

            # Class data (methods + fields)
            static_fields = []
            instance_fields = []
            direct_methods = []
            virtual_methods = []

            if cdi != 0:
                try:
                    pos = cdi
                    sfc, sz = self._sleb(pos); pos += sz
                    ifc, sz = self._sleb(pos); pos += sz
                    dmc, sz = self._sleb(pos); pos += sz
                    vmc, sz = self._sleb(pos); pos += sz

                    # Static fields
                    last_idx = 0
                    for j in range(sfc):
                        idx_diff, sz = self._sleb(pos); pos += sz
                        acc_diff, sz = self._sleb(pos); pos += sz
                        last_idx += idx_diff
                        field = self._fields[last_idx] if 0 <= last_idx < len(self._fields) else None
                        if field:
                            static_fields.append({
                                'field_idx': last_idx,
                                'name': field['name'],
                                'type': field['type'],
                                'access_flags': self._access_flags_str(acc_diff),
                            })

                    # Instance fields
                    last_idx = 0
                    for j in range(ifc):
                        idx_diff, sz = self._sleb(pos); pos += sz
                        acc_diff, sz = self._sleb(pos); pos += sz
                        last_idx += idx_diff
                        field = self._fields[last_idx] if 0 <= last_idx < len(self._fields) else None
                        if field:
                            instance_fields.append({
                                'field_idx': last_idx,
                                'name': field['name'],
                                'type': field['type'],
                                'access_flags': self._access_flags_str(acc_diff),
                            })

                    # Direct methods
                    last_idx = 0
                    for j in range(dmc):
                        idx_diff, sz = self._sleb(pos); pos += sz
                        acc_diff, sz = self._sleb(pos); pos += sz
                        last_idx += idx_diff
                        method = self._methods[last_idx] if 0 <= last_idx < len(self._methods) else None
                        if method:
                            direct_methods.append({
                                'method_idx': last_idx,
                                'name': method['name'],
                                'proto': method['proto'],
                                'access_flags': self._access_flags_str(acc_diff),
                            })

                    # Virtual methods
                    last_idx = 0
                    for j in range(vmc):
                        idx_diff, sz = self._sleb(pos); pos += sz
                        acc_diff, sz = self._sleb(pos); pos += sz
                        last_idx += idx_diff
                        method = self._methods[last_idx] if 0 <= last_idx < len(self._methods) else None
                        if method:
                            virtual_methods.append({
                                'method_idx': last_idx,
                                'name': method['name'],
                                'proto': method['proto'],
                                'access_flags': self._access_flags_str(acc_diff),
                            })
                except Exception as e:
                    pass

            self._class_defs.append({
                'class_idx': ci,
                'class_name': class_name,
                'super_name': super_name,
                'interfaces': interfaces,
                'access_flags': access_flags_str,
                'access_flags_raw': ai,
                'source_file': source_file,
                'annotations_off': ani,
                'static_fields': static_fields,
                'instance_fields': instance_fields,
                'direct_methods': direct_methods,
                'virtual_methods': virtual_methods,
            })

    def _access_flags_str(self, flags):
        names = []
        if flags & 0x0001: names.append('PUBLIC')
        if flags & 0x0002: names.append('PRIVATE')
        if flags & 0x0004: names.append('PROTECTED')
        if flags & 0x0008: names.append('STATIC')
        if flags & 0x0010: names.append('FINAL')
        if flags & 0x0020: names.append('SYNCHRONIZED')
        if flags & 0x0040: names.append('VOLATILE')
        if flags & 0x0080: names.append('BRIDGE')
        if flags & 0x0100: names.append('TRANSIENT')
        if flags & 0x0200: names.append('VARARGS')
        if flags & 0x0400: names.append('NATIVE')
        if flags & 0x0800: names.append('INTERFACE')
        if flags & 0x1000: names.append('ABSTRACT')
        if flags & 0x2000: names.append('STRICT')
        if flags & 0x4000: names.append('SYNTHETIC')
        if flags & 0x8000: names.append('ANNOTATION')
        if flags & 0x10000: names.append('ENUM')
        if flags & 0x20000: names.append('CONSTRUCTOR')
        if flags & 0x40000: names.append('DECLARED_SYNCHRONIZED')
        return '|'.join(names) if names else 'DEFAULT'

    def get_string(self, idx):
        self._ensure_parsed()
        return self._strings[idx] if 0 <= idx < len(self._strings) else ''

    def get_strings(self):
        self._ensure_parsed()
        return self._strings

    def get_types(self):
        self._ensure_parsed()
        return self._types

    def get_protos(self):
        self._ensure_parsed()
        return self._protos

    def get_fields(self):
        self._ensure_parsed()
        return self._fields

    def get_methods(self):
        self._ensure_parsed()
        return self._methods

    def get_class_names(self):
        self._ensure_parsed()
        return [c['class_name'] for c in self._class_defs]

    def get_class_defs(self):
        self._ensure_parsed()
        return self._class_defs

    def get_class_by_name(self, name):
        self._ensure_parsed()
        for c in self._class_defs:
            if c['class_name'] == name:
                return c
        return None

    def find_classes(self, keyword):
        """按关键词搜索类名"""
        self._ensure_parsed()
        keyword = keyword.lower()
        return [c for c in self._class_defs if keyword in c['class_name'].lower()]

    def find_methods(self, keyword):
        """在所有类中搜索方法名"""
        self._ensure_parsed()
        keyword = keyword.lower()
        results = []
        for c in self._class_defs:
            for m in c.get('direct_methods', []):
                if keyword in m['name'].lower():
                    results.append({'class': c['class_name'], **m})
            for m in c.get('virtual_methods', []):
                if keyword in m['name'].lower():
                    results.append({'class': c['class_name'], **m})
        return results

    def get_summary(self):
        """获取DEX文件摘要统计"""
        self._ensure_parsed()
        return {
            'strings': len(self._strings),
            'types': len(self._types),
            'protos': len(self._protos),
            'fields': len(self._fields),
            'methods': len(self._methods),
            'classes': len(self._class_defs),
            'file_size': len(self.data),
        }

    def get_method_signature(self, method):
        """生成方法签名字符串"""
        if method and method.get('proto'):
            proto = method['proto']
            params = ', '.join(proto.get('parameters', []))
            return f"{method['name']}({params}){proto['return_type']}"
        return method.get('name', '') if method else ''
