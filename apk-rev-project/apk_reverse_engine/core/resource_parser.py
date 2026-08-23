"""resources.arsc 完整资源表解析器 - 纯Python实现

解析 Android 资源编译表(ARSC)的二进制结构：
- 全局字符串池 (StringPool)
- 包表 (ResTable_package)
- 类型表 + 类型规格 (ResTable_typeSpec / ResTable_type)
- 包类型名称表 (ResTable_package_type_names)
- 配置项 (ResTable_config)
- 条目(entry)及条目值(values)

参考格式: https://justanapplication.wordpress.com/tag/resources-arsc/
"""

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import struct


# ═══════════════════════════════════════════════════════════════
# 块类型常量 (chunk type)
# ═══════════════════════════════════════════════════════════════
CHUNK_NULL = 0x0000
CHUNK_STRING_POOL = 0x0001
CHUNK_TABLE = 0x0002
CHUNK_XML = 0x0003
CHUNK_TABLE_PACKAGE = 0x0200
CHUNK_TABLE_TYPE = 0x0201
CHUNK_TABLE_TYPE_SPEC = 0x0202
CHUNK_TABLE_LIBRARY = 0x0203

# ═══════════════════════════════════════════════════════════════
# 数据类型 (Res_value dataType，高8位)
# ═══════════════════════════════════════════════════════════════
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_FIRST_INT = 0x10
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_INT_COLOR_ARGB8 = 0x1c
TYPE_INT_COLOR_RGB8 = 0x1d
TYPE_INT_COLOR_ARGB4 = 0x1e
TYPE_INT_COLOR_RGB4 = 0x1f
TYPE_LAST_COLOR_INT = 0x1f
TYPE_LAST_INT = 0x1f

TYPE_NAMES = {
    TYPE_NULL: 'null',
    TYPE_REFERENCE: 'reference',
    TYPE_ATTRIBUTE: 'attribute',
    TYPE_STRING: 'string',
    TYPE_FLOAT: 'float',
    TYPE_DIMENSION: 'dimension',
    TYPE_FRACTION: 'fraction',
    TYPE_INT_DEC: 'int_dec',
    TYPE_INT_HEX: 'int_hex',
    TYPE_INT_BOOLEAN: 'boolean',
    TYPE_INT_COLOR_ARGB8: 'color_argb8',
    TYPE_INT_COLOR_RGB8: 'color_rgb8',
    TYPE_INT_COLOR_ARGB4: 'color_argb4',
    TYPE_INT_COLOR_RGB4: 'color_rgb4',
}

# 常用系统资源包名
ALT_PACKAGE_NAME = {
    0x01: 'android',
}


class ResourceParser:
    """resources.arsc 解析器

    Args:
        data: resources.arsc 二进制数据 (bytes)
    """

    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.n = len(data)
        self.string_pool = []
        self.is_utf8 = False
        self.pool_strings_off = 0
        self.packages = []
        self.global_strings = []
        self._last_result = None

    # ── 基础读取 ──
    def r8(self):
        v = self.data[self.pos]; self.pos += 1; return v

    def r16(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]; self.pos += 2; return v

    def r32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v

    def _peek32(self, off):
        if off + 4 > self.n:
            return 0
        return struct.unpack_from('<I', self.data, off)[0]

    # ── 字符串池解析 ──
    def _parse_string_pool(self):
        """解析全局字符串池，返回块结束位置"""
        chunk_start = self.pos
        chunk_size = self.r32()
        string_count = self.r32()
        style_count = self.r32()
        flags = self.r32()
        strings_start = self.r32()
        styles_start = self.r32()
        self.is_utf8 = bool(flags & 0x100)

        str_offsets = [self.r32() for _ in range(string_count)]
        for _ in range(style_count):
            self.r32()

        data_start = chunk_start + strings_start
        pool = []
        for off in str_offsets:
            pool.append(self._read_string(data_start + off))
        self.string_pool = pool
        self.global_strings = pool
        self.pool_strings_off = data_start
        return chunk_start + chunk_size

    def _read_string(self, off):
        try:
            if self.is_utf8:
                if self.data[off] & 0x80:
                    cc = ((self.data[off] & 0x7f) << 8) | self.data[off + 1]
                    off += 2
                else:
                    cc = self.data[off]
                    off += 1
                if self.data[off] & 0x80:
                    bc = ((self.data[off] & 0x7f) << 8) | self.data[off + 1]
                    off += 2
                else:
                    bc = self.data[off]
                    off += 1
                if bc == 0:
                    return ''
                return self.data[off:off + bc].decode('utf-8', errors='replace')
            else:
                cc = struct.unpack_from('<H', self.data, off)[0]
                off += 2
                if cc == 0:
                    return ''
                raw = self.data[off:off + cc * 2]
                return raw.decode('utf-16-le', errors='replace')
        except Exception as e:
            logger.debug("apk_reverse_engine/core/resource_parser.py:157 suppressed: %s", e)
            return ''

    def get_string(self, idx):
        if 0 <= idx < len(self.string_pool):
            return self.string_pool[idx]
        return None

    # ── 配置解析 (ResTable_config) ──
    def _parse_config(self, off):
        """解析配置块，返回 (config_dict, consumed_bytes)"""
        size = self._peek32(off)
        if size < 4:
            return {}, 0
        try:
            cfg = {
                'size': size,
                'mcc': self._peek32(off + 4) & 0xffff,
                'mnc': (self._peek32(off + 4) >> 16) & 0xffff,
                'orientation': self._peek32(off + 8) & 0xff,
                'touchscreen': (self._peek32(off + 8) >> 8) & 0xff,
                'density': (self._peek32(off + 8) >> 16) & 0xffff,
                'keyboard': (self._peek32(off + 12) & 0xff),
                'navigation': (self._peek32(off + 12) >> 8) & 0xff,
                'inputFlags': (self._peek32(off + 12) >> 16) & 0xff,
                'screenWidth': (self._peek32(off + 12) >> 24) & 0xff,
                'screenHeight': self._peek32(off + 16) & 0xff,
                'sdkVersion': self._peek32(off + 16) >> 16,
                'minorVersion': self._peek32(off + 20) & 0xff,
                'screenLayout': self._peek32(off + 20) >> 8 & 0xff,
                'uiMode': (self._peek32(off + 20) >> 16) & 0xff,
                'smallestScreenWidthDp': self._peek32(off + 20) >> 24,
                'screenWidthDp': self._peek32(off + 24) & 0xffff,
                'screenHeightDp': self._peek32(off + 24) >> 16,
                'localeScript': '',
                'localeVariant': '',
                'screenLayout2': self._peek32(off + 28) & 0xff,
                'colorMode': (self._peek32(off + 28) >> 8) & 0xff,
                'screenConfig2': (self._peek32(off + 28) >> 16) & 0xff,
                'locale': '',
            }
            if size >= 32:
                lo = self._peek32(off + 32)
                lang = chr(lo & 0xff) + chr((lo >> 8) & 0xff) if (lo & 0xff) else ''
                reg = chr((lo >> 16) & 0xff) + chr((lo >> 24) & 0xff) if ((lo >> 16) & 0xff) else ''
                if lang or reg:
                    cfg['locale'] = f'{lang}-{reg}'.strip('-')
            return cfg, size
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger
            get_logger(__name__).warning("resource config parse failed: %s", e)
            return {}, 0

    def _config_desc(self, cfg):
        """生成配置的人类可读描述"""
        parts = []
        if cfg.get('locale'):
            parts.append(cfg['locale'])
        if cfg.get('orientation') == 1:
            parts.append('port')
        elif cfg.get('orientation') == 2:
            parts.append('land')
        d = cfg.get('density', 0)
        if d == 0xffff:
            parts.append('nodpi')
        elif d == 0:
            pass
        elif d == 120:
            parts.append('ldpi')
        elif d == 160:
            parts.append('mdpi')
        elif d == 240:
            parts.append('hdpi')
        elif d == 320:
            parts.append('xhdpi')
        elif d == 480:
            parts.append('xxhdpi')
        elif d == 640:
            parts.append('xxxhdpi')
        elif d > 0:
            parts.append(f'{d}dpi')
        if cfg.get('screenWidth') == 0 and cfg.get('sdkVersion'):
            parts.append(f'v{cfg["sdkVersion"]}')
        if cfg.get('smallestScreenWidthDp'):
            parts.append(f'sw{cfg["smallestScreenWidthDp"]}dp')
        if cfg.get('screenWidthDp'):
            parts.append(f'w{cfg["screenWidthDp"]}dp')
        if cfg.get('screenHeightDp'):
            parts.append(f'h{cfg["screenHeightDp"]}dp')
        return '-'.join(parts) if parts else 'default'

    # ── 条目值解析 (Res_value) ──
    def _parse_value(self, off):
        """解析 Res_value (8字节)，返回 dict"""
        size = struct.unpack_from('<H', self.data, off)[0]
        res0 = self.data[off + 2]
        data_type = self.data[off + 3]
        data = struct.unpack_from('<I', self.data, off + 4)[0]
        result = {
            'size': size,
            'res0': res0,
            'type': TYPE_NAMES.get(data_type, f'0x{data_type:02x}'),
            'type_raw': data_type,
            'data': data,
        }
        if data_type == TYPE_STRING:
            s = self.get_string(data)
            result['value'] = s
        elif data_type == TYPE_REFERENCE:
            result['value'] = '@0x%08x' % data
            result['ref_id'] = data
        elif data_type == TYPE_INT_BOOLEAN:
            result['value'] = bool(data)
        elif data_type == TYPE_FLOAT:
            import struct as _s
            try:
                result['value'] = _s.unpack('<f', _s.pack('<I', data))[0]
            except Exception:
                result['value'] = data
        elif data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
            result['value'] = data
        elif data_type in (TYPE_INT_COLOR_ARGB8, TYPE_INT_COLOR_RGB8,
                           TYPE_INT_COLOR_ARGB4, TYPE_INT_COLOR_RGB4):
            result['value'] = '#%08x' % data
        else:
            result['value'] = data
        return result

    # ── 主解析入口 ──
    def parse(self):
        if self.n < 12:
            return {'error': '数据过小', 'package_count': 0, 'packages': []}

        pos = 0
        chunk_type = struct.unpack_from('<H', self.data, pos)[0]
        header_size = struct.unpack_from('<H', self.data, pos + 2)[0]
        chunk_size = struct.unpack_from('<I', self.data, pos + 4)[0]
        package_count = struct.unpack_from('<I', self.data, pos + 8)[0]
        pos = header_size

        info = {
            'chunk_type': chunk_type,
            'header_size': header_size,
            'chunk_size': chunk_size,
            'package_count': package_count,
            'global_strings': [],
            'packages': [],
        }

        if pos + 8 <= self.n:
            self.pos = pos
            ct = self.r16()
            hs = self.r16()
            cs = self.r32()
            if ct == CHUNK_STRING_POOL:
                self.pos = pos
                pool_end = self._parse_string_pool()
                info['global_strings'] = self.string_pool
                pos = pool_end

        while pos + 8 <= self.n:
            ct = struct.unpack_from('<H', self.data, pos)[0]
            hs = struct.unpack_from('<H', self.data, pos + 2)[0]
            cs = struct.unpack_from('<I', self.data, pos + 4)[0]
            if cs < 8:
                break
            chunk_start = pos

            if ct == CHUNK_TABLE_PACKAGE:
                pkg = self._parse_package(chunk_start)
                info['packages'].append(pkg)
                pos = chunk_start + cs
            elif ct == CHUNK_TABLE_LIBRARY:
                pos = chunk_start + cs
            else:
                pos = chunk_start + cs

        self._last_result = info
        return info

    def _parse_package(self, chunk_start):
        """解析单个 ResTable_package"""
        pos = chunk_start
        hs = struct.unpack_from('<H', self.data, pos + 2)[0]
        cs = struct.unpack_from('<I', self.data, pos + 4)[0]
        id_ = struct.unpack_from('<I', self.data, pos + 8)[0]
        name_raw = self.data[pos + 12: pos + 12 + 128].split(b'\x00')[0]
        name = name_raw.decode('utf-8', errors='replace')
        type_strings_off = struct.unpack_from('<I', self.data, pos + 268)[0]
        last_public_type = struct.unpack_from('<I', self.data, pos + 272)[0]
        key_strings_off = struct.unpack_from('<I', self.data, pos + 276)[0]
        last_public_key = struct.unpack_from('<I', self.data, pos + 280)[0]

        pkg = {
            'id': id_,
            'id_hex': '0x%02x' % id_,
            'name': name or ALT_PACKAGE_NAME.get(id_, ''),
            'type_strings_off': type_strings_off,
            'key_strings_off': key_strings_off,
            'type_strings': [],
            'key_strings': [],
            'type_specs': [],
            'types': [],
        }

        body = chunk_start + hs
        if type_strings_off:
            p = chunk_start + type_strings_off
            pkg['type_strings'] = self._read_string_pool_at(p)
        if key_strings_off:
            p = chunk_start + key_strings_off
            pkg['key_strings'] = self._read_string_pool_at(p)

        p = body
        end = chunk_start + cs
        while p + 8 <= end:
            ct = struct.unpack_from('<H', self.data, p)[0]
            hs2 = struct.unpack_from('<H', self.data, p + 2)[0]
            cs2 = struct.unpack_from('<I', self.data, p + 4)[0]
            if cs2 < 8:
                break
            sub_start = p

            if ct == CHUNK_TABLE_TYPE_SPEC:
                pkg['type_specs'].append(self._parse_type_spec(sub_start))
            elif ct == CHUNK_TABLE_TYPE:
                pkg['types'].append(self._parse_type(sub_start))
            p = sub_start + cs2

        pkg['resource_count'] = sum(len(t.get('entries', [])) for t in pkg['types'])
        return pkg

    def _read_string_pool_at(self, off):
        """在指定偏移解析字符串池"""
        if off + 8 > self.n:
            return []
        chunk_size = struct.unpack_from('<I', self.data, off + 4)[0]
        string_count = struct.unpack_from('<I', self.data, off + 8)[0]
        style_count = struct.unpack_from('<I', self.data, off + 12)[0]
        flags = struct.unpack_from('<I', self.data, off + 16)[0]
        strings_start = struct.unpack_from('<I', self.data, off + 20)[0]
        is_utf8 = bool(flags & 0x100)

        str_offsets = [struct.unpack_from('<I', self.data, off + 28 + i * 4)[0]
                       for i in range(string_count)]
        data_start = off + strings_start
        pool = []
        for o in str_offsets:
            pool.append(self._read_str_at(data_start + o, is_utf8))
        return pool

    def _read_str_at(self, off, is_utf8):
        try:
            if is_utf8:
                if self.data[off] & 0x80:
                    cc = ((self.data[off] & 0x7f) << 8) | self.data[off + 1]
                    off += 2
                else:
                    cc = self.data[off]
                    off += 1
                if self.data[off] & 0x80:
                    bc = ((self.data[off] & 0x7f) << 8) | self.data[off + 1]
                    off += 2
                else:
                    bc = self.data[off]
                    off += 1
                if bc == 0:
                    return ''
                return self.data[off:off + bc].decode('utf-8', errors='replace')
            else:
                cc = struct.unpack_from('<H', self.data, off)[0]
                off += 2
                if cc == 0:
                    return ''
                return self.data[off:off + cc * 2].decode('utf-16-le', errors='replace')
        except Exception as e:
            logger.debug("apk_reverse_engine/core/resource_parser.py:432 suppressed: %s", e)
            return ''

    def _parse_type_spec(self, off):
        """解析 ResTable_typeSpec"""
        hs = struct.unpack_from('<H', self.data, off + 2)[0]
        cs = struct.unpack_from('<I', self.data, off + 4)[0]
        id_ = struct.unpack_from('<I', self.data, off + 8)[0]
        entry_count = struct.unpack_from('<I', self.data, off + 12)[0]
        p = off + hs
        flags = []
        for _ in range(min(entry_count, (cs - hs) // 4)):
            flags.append(struct.unpack_from('<I', self.data, p)[0])
            p += 4
        return {
            'id': id_,
            'name': '',
            'entry_count': entry_count,
            'flags': flags,
        }

    def _parse_type(self, off):
        """解析 ResTable_type"""
        hs = struct.unpack_from('<H', self.data, off + 2)[0]
        cs = struct.unpack_from('<I', self.data, off + 4)[0]
        id_ = struct.unpack_from('<I', self.data, off + 8)[0]
        entry_count = struct.unpack_from('<I', self.data, off + 12)[0]
        entries_start = struct.unpack_from('<I', self.data, off + 16)[0]
        config, _ = self._parse_config(off + 20)
        config_desc = self._config_desc(config)

        entries = []
        p_offsets = off + 20 + config.get('size', 0)
        p_offsets = (p_offsets + 3) & ~3
        entry_offsets = []
        for _ in range(entry_count):
            eo = struct.unpack_from('<I', self.data, p_offsets)[0]
            entry_offsets.append(eo)
            p_offsets += 4

        for i, eo in enumerate(entry_offsets):
            if eo == 0xffffffff:
                entries.append({'index': i, 'name': '', 'values': [], 'present': False})
                continue
            ep = off + entries_start + eo
            entry = self._parse_entry(ep)
            entry['index'] = i
            entry['present'] = True
            entries.append(entry)

        return {
            'id': id_,
            'name': '',
            'config': config,
            'config_desc': config_desc,
            'entry_count': entry_count,
            'entries_start': entries_start,
            'entries': entries,
        }

    def _parse_entry(self, off):
        """解析 ResTable_entry (+ 可能的 ResTable_map_entry)"""
        size = struct.unpack_from('<H', self.data, off)[0]
        flags = struct.unpack_from('<H', self.data, off + 2)[0]
        key_idx = struct.unpack_from('<I', self.data, off + 4)[0]
        is_complex = bool(flags & 0x0001)

        entry = {
            'size': size,
            'flags': flags,
            'is_complex': is_complex,
            'key_idx': key_idx,
            'values': [],
            'map': [],
        }

        if is_complex:
            parent = struct.unpack_from('<I', self.data, off + 8)[0]
            count = struct.unpack_from('<I', self.data, off + 12)[0]
            entry['parent'] = parent
            entry['map_count'] = count
            p = off + 16
            for _ in range(count):
                if p + 12 > self.n:
                    break
                name_ref = struct.unpack_from('<I', self.data, p)[0]
                val = self._parse_value(p + 8)
                entry['map'].append({'name_ref': name_ref, 'value': val})
                p += 12
        else:
            val = self._parse_value(off + 8)
            entry['values'].append(val)

        return entry

    # ── 便捷 API ──
    def get_package_names(self):
        if self._last_result:
            return [p['name'] for p in self._last_result.get('packages', [])]
        return []

    def get_resource_types(self):
        if self._last_result:
            out = set()
            for p in self._last_result.get('packages', []):
                out.update(p.get('type_strings', []))
            return sorted(out)
        return []

    def get_resources(self):
        """获取扁平化资源列表"""
        if not self._last_result:
            return []
        out = []
        for pkg in self._last_result.get('packages', []):
            type_names = pkg.get('type_strings', [])
            key_names = pkg.get('key_strings', [])
            for t in pkg.get('types', []):
                type_name = type_names[t['id'] - 1] if t['id'] - 1 < len(type_names) else f'type{t["id"]}'
                for e in t.get('entries', []):
                    if not e.get('present'):
                        continue
                    key_name = key_names[e['key_idx']] if e['key_idx'] < len(key_names) else f'key{e["key_idx"]}'
                    res_id = (pkg['id'] << 24) | (t['id'] << 16) | (e['index'] & 0xffff)
                    item = {
                        'type': type_name,
                        'name': key_name,
                        'res_id': '0x%08x' % res_id,
                        'config': t.get('config_desc'),
                    }
                    if e.get('values'):
                        item['value'] = e['values'][0].get('value')
                        item['value_type'] = e['values'][0].get('type')
                    elif e.get('map'):
                        item['value'] = 'map(%d)' % len(e['map'])
                    out.append(item)
        return out

    def find_resource(self, res_id):
        """按资源ID查找资源详情"""
        target = int(res_id, 16) if isinstance(res_id, str) else res_id
        pkg_id = (target >> 24) & 0xff
        type_id = (target >> 16) & 0xff
        entry_idx = target & 0xffff
        for pkg in self._last_result.get('packages', []):
            if pkg['id'] != pkg_id:
                continue
            type_names = pkg.get('type_strings', [])
            key_names = pkg.get('key_strings', [])
            for t in pkg.get('types', []):
                if t['id'] != type_id:
                    continue
                type_name = type_names[type_id - 1] if type_id - 1 < len(type_names) else f'type{type_id}'
                for e in t.get('entries', []):
                    if e.get('index') == entry_idx and e.get('present'):
                        key_name = key_names[e['key_idx']] if e['key_idx'] < len(key_names) else f'key{e["key_idx"]}'
                        return {
                            'res_id': '0x%08x' % target,
                            'type': type_name,
                            'name': key_name,
                            'config': t.get('config_desc'),
                            'values': e.get('values'),
                            'map': e.get('map'),
                        }
        return None

    def parse_all(self):
        """完整解析入口"""
        self._last_result = self.parse()
        return self._last_result