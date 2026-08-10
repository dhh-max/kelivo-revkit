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
    def _uleb(self, off):
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

    def _sleb(self, off):
        """解析SLEB128（有符号）"""
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
        if byte & 0x40:
            result |= -(1 << shift)
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
            except Exception:
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
                except Exception as e:
                    from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/core/dex_parser.py:151 suppressed: %s", e)
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
                except Exception as e:
                    from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/core/dex_parser.py:225 suppressed: %s", e)
                    pass

            # Class data (methods + fields)
            static_fields = []
            instance_fields = []
            direct_methods = []
            virtual_methods = []

            if cdi != 0:
                try:
                    pos = cdi
                    sfc, sz = self._uleb(pos); pos += sz
                    ifc, sz = self._uleb(pos); pos += sz
                    dmc, sz = self._uleb(pos); pos += sz
                    vmc, sz = self._uleb(pos); pos += sz
                    # Static fields
                    last_idx = 0
                    for j in range(sfc):
                        idx_diff, sz = self._uleb(pos); pos += sz
                        acc_diff, sz = self._uleb(pos); pos += sz
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
                        idx_diff, sz = self._uleb(pos); pos += sz
                        acc_diff, sz = self._uleb(pos); pos += sz
                        last_idx += idx_diff
                        field = self._fields[last_idx] if 0 <= last_idx < len(self._fields) else None
                        if field:
                            instance_fields.append({
                                'field_idx': last_idx,
                                'name': field['name'],
                                'type': field['type'],
                                'access_flags': self._access_flags_str(acc_diff),
                            })
                    # Direct methods (with code_item)
                    last_idx = 0
                    for j in range(dmc):
                        idx_diff, sz = self._uleb(pos); pos += sz
                        acc_diff, sz = self._uleb(pos); pos += sz
                        last_idx += idx_diff
                        # 后续跟 code_off (ULEB128)，如果有代码
                        code_off = 0
                        if not (acc_diff & 0x0400):  # 非 NATIVE
                            code_off, sz2 = self._uleb(pos); pos += sz2
                        method = self._methods[last_idx] if 0 <= last_idx < len(self._methods) else None
                        mi = {'method_idx': last_idx, 'name': method['name'] if method else f'?{last_idx}',
                              'proto': method['proto'] if method else None,
                              'access_flags': self._access_flags_str(acc_diff)}
                        if code_off:
                            mi['code_off'] = code_off
                            mi['code'] = self._parse_code_item(code_off)
                        direct_methods.append(mi)
                    # Virtual methods (with code_item)
                    last_idx = 0
                    for j in range(vmc):
                        idx_diff, sz = self._uleb(pos); pos += sz
                        acc_diff, sz = self._uleb(pos); pos += sz
                        last_idx += idx_diff
                        code_off = 0
                        if not (acc_diff & 0x0400):
                            code_off, sz2 = self._uleb(pos); pos += sz2
                        method = self._methods[last_idx] if 0 <= last_idx < len(self._methods) else None
                        mi = {'method_idx': last_idx, 'name': method['name'] if method else f'?{last_idx}',
                              'proto': method['proto'] if method else None,
                              'access_flags': self._access_flags_str(acc_diff)}
                        if code_off:
                            mi['code_off'] = code_off
                            mi['code'] = self._parse_code_item(code_off)
                        virtual_methods.append(mi)
                except Exception as e:
                    from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/core/dex_parser.py:304 suppressed: %s", e)
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

    # ── Code Item 解析 ──
    def _parse_code_item(self, off):
        """解析 code_item 结构，返回指令摘要"""
        try:
            n = len(self.data)
            if off + 16 > n:
                return {'error': 'code_item too small'}
            registers_size = self._u2(off)
            ins_size = self._u2(off + 2)
            outs_size = self._u2(off + 4)
            tries_size = self._u2(off + 6)
            debug_info_off = self._u4(off + 8)
            insns_size = self._u4(off + 12)
            insns_start = off + 16
            insns_end = insns_start + insns_size * 2
            if insns_end > n:
                insns_end = n

            # 提取指令字节（16位指令）
            raw_insns = self.data[insns_start:insns_end]

            # 提取 try/catch 信息
            tries = []
            handlers = []
            if tries_size > 0:
                # 对齐到 4 字节
                pos = insns_end
                if pos % 4 != 0:
                    pos += 4 - (pos % 4)
                for _ in range(tries_size):
                    if pos + 8 > n:
                        break
                    try_start = self._u4(pos)
                    try_count = self._u2(pos + 4)
                    handler_off = self._u2(pos + 6)
                    tries.append({
                        'start_addr': try_start,
                        'insn_count': try_count,
                        'handler_off': handler_off,
                    })
                    pos += 8
                # 解析 handlers
                if pos + 2 <= n:
                    handler_count = self._sleb(pos)[0]
                    pos += self._sleb(pos)[1] if handler_count >= 0 else 1
                    # 简化：只记录数量
                    handlers = {'count': handler_count}

            return {
                'registers_size': registers_size,
                'ins_size': ins_size,
                'outs_size': outs_size,
                'tries_size': tries_size,
                'debug_info_off': debug_info_off,
                'insns_size': insns_size,
                'insns_bytes': len(raw_insns),
                'insns_start': insns_start,
                'tries': tries,
                'handlers': handlers,
            }
        except Exception as e:
            return {'error': str(e)}

    # ── Annotation 解析 ──
    def _parse_annotations_off(self, off):
        """解析 annotations_directory_item"""
        try:
            if off <= 0 or off + 16 > len(self.data):
                return None
            class_annot_off = self._u4(off)
            field_size = self._u4(off + 4)
            method_size = self._u4(off + 8)
            param_size = self._u4(off + 12)
            result = {
                'class_annotation_off': class_annot_off,
                'field_annotations': [],
                'method_annotations': [],
                'parameter_annotations': [],
            }
            pos = off + 16
            for _ in range(field_size):
                if pos + 8 > len(self.data): break
                result['field_annotations'].append({
                    'field_idx': self._u4(pos),
                    'annotations_off': self._u4(pos + 4),
                })
                pos += 8
            for _ in range(method_size):
                if pos + 8 > len(self.data): break
                result['method_annotations'].append({
                    'method_idx': self._u4(pos),
                    'annotations_off': self._u4(pos + 4),
                })
                pos += 8
            for _ in range(param_size):
                if pos + 8 > len(self.data): break
                result['parameter_annotations'].append({
                    'method_idx': self._u4(pos),
                    'annotations_off': self._u4(pos + 4),
                })
                pos += 8
            return result
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger
            get_logger(__name__).warning("annotation dir parse failed: %s", e)
            return None

    def get_annotations(self, class_def):
        """获取指定类定义的注解信息"""
        self._ensure_parsed()
        ani = class_def.get('annotations_off', 0)
        if ani:
            return self._parse_annotations_off(ani)
        return None

    def get_annotation_set(self, off):
        """解析 annotation_set_item"""
        if off <= 0 or off + 4 > len(self.data):
            return []
        try:
            count = self._u4(off)
            annotations = []
            for i in range(count):
                if off + 4 + i * 4 + 4 > len(self.data):
                    break
                ao = self._u4(off + 4 + i * 4)
                annotations.append(self._get_annotation_off(ao))
            return annotations
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/core/dex_parser.py:473 suppressed: %s", e)
            return []

    def _get_annotation_off(self, off):
        """解析 annotation_item（简化）"""
        try:
            if off <= 0 or off + 4 > len(self.data):
                return {'error': 'invalid offset'}
            visibility = self._u1(off)
            vis_map = {0: 'build', 1: 'runtime', 2: 'system'}
            type_idx = self._uleb(off + 1)[0]
            type_name = self._types[type_idx]['descriptor'] if 0 <= type_idx < len(self._types) else f'?{type_idx}'
            return {
                'visibility': vis_map.get(visibility, f'unknown({visibility})'),
                'type_idx': type_idx,
                'type': type_name,
            }
        except Exception as e:
            return {'error': str(e)}

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

    # ── 增强：源文件 / 类统计 ──
    def get_source_files(self):
        """统计 DEX 中引用的源文件及使用类数"""
        self._ensure_parsed()
        from collections import Counter
        counter = Counter()
        for c in self._class_defs:
            sf = c.get('source_file') or ''
            if sf:
                counter[sf] += 1
        return [
            {'file': f, 'classes': n}
            for f, n in counter.most_common()
        ]

    def get_most_complex_classes(self, top=20):
        """按方法数/代码量返回最复杂的类"""
        self._ensure_parsed()
        scored = []
        for c in self._class_defs:
            methods = c.get('direct_methods', []) + c.get('virtual_methods', [])
            code_methods = [m for m in methods if m.get('code')]
            insns = sum((m.get('code', {}).get('insns_size', 0) for m in code_methods), 0)
            scored.append({
                'class': c['class_name'],
                'methods': len(methods),
                'code_methods': len(code_methods),
                'insns': insns,
                'static_fields': len(c.get('static_fields', [])),
                'instance_fields': len(c.get('instance_fields', [])),
            })
        scored.sort(key=lambda x: (x['insns'], x['methods']), reverse=True)
        return scored[:top]

    def get_class_hierarchy(self, class_name):
        """沿 superclass 链返回类继承关系"""
        self._ensure_parsed()
        chain = []
        cur = class_name
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            cls = self.get_class_by_name(cur)
            if not cls or not cls.get('super_name'):
                break
            cur = cls['super_name']
        return chain

    def find_reachable_from(self, class_name, max_depth=3):
        """BFS 扫描类引用拓扑（用于定位核心类/入口）"""
        self._ensure_parsed()
        cls = self.get_class_by_name(class_name)
        if not cls:
            return {'error': f'Class not found: {class_name}'}
        type_desc = set()
        # 收集方法 proto 与字段类型中的引用描述符
        for m in cls.get('direct_methods', []) + cls.get('virtual_methods', []):
            proto = m.get('proto')
            if proto:
                rt = proto.get('return_type', '')
                if rt.startswith('L') or rt.startswith('['):
                    type_desc.add(rt)
                for p in proto.get('parameters', []):
                    if p.startswith('L') or p.startswith('['):
                        type_desc.add(p)
        for f in cls.get('static_fields', []) + cls.get('instance_fields', []):
            ft = f.get('type', '')
            if ft.startswith('L') or ft.startswith('['):
                type_desc.add(ft)
        return {
            'class': class_name,
            'referenced_types': sorted(type_desc),
            'referenced_count': len(type_desc),
        }
