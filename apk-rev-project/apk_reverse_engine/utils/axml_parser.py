import struct
class AXMLParser:
    """Android Binary XML Parser - 修复版"""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.strings = []
        self.is_utf8 = False
    def _r32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v
    def _r16(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]; self.pos += 2; return v
    def _rstr(self, off):
        """读取字符串，自动处理UTF-8/UTF-16LE"""
        try:
            if self.is_utf8:
                # UTF-8: 变长编码字符数 + 变长编码字节数 + 数据 + 0x00
                # 读取字符数(1或2字节)
                if self.data[off] & 0x80:
                    char_count = ((self.data[off] & 0x7f) << 8) | self.data[off + 1]
                    off += 2
                else:
                    char_count = self.data[off]
                    off += 1
                # 读取字节数(1或2字节)
                if self.data[off] & 0x80:
                    byte_count = ((self.data[off] & 0x7f) << 8) | self.data[off + 1]
                    off += 2
                else:
                    byte_count = self.data[off]
                    off += 1
                if byte_count == 0:
                    return ""
                return self.data[off:off + byte_count].decode('utf-8', errors='replace')
            else:
                # UTF-16LE: 2字节字符数 + 数据 + 0x0000
                char_count = struct.unpack_from('<H', self.data, off)[0]
                off += 2
                if char_count == 0:
                    return ""
                raw = self.data[off:off + char_count * 2]
                return raw.decode('utf-16-le', errors='replace')
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/utils/axml_parser.py:43 suppressed: %s", e)
            return ""
    def parse(self):
        magic = self._r32()
        if magic != 0x00080003: return {"error": f"Invalid AXML magic=0x{magic:08x}"}
        file_size = self._r32()
        # 解析字符串池块 (chunk type 0x001C0001)
        sps = self.pos  # 字符串池块起始位置
        pool_chunk_type = self._r32()  # 0x001C0001
        pool_chunk_size = self._r32()  # 字符串池块总大小
        sc = self._r32()               # string_count
        style_count = self._r32()      # style_count
        flags = self._r32()            # flags
        self.is_utf8 = bool(flags & 0x100)  # UTF8_FLAG
        sdo = self._r32()              # strings_offset (从块起始)
        styles_offset = self._r32()    # styles_offset (从块起始)
        # 读取字符串偏移数组
        offs = [self._r32() for _ in range(sc)]
        # 跳过样式偏移数组
        for _ in range(style_count): self._r32()
        # 读取字符串数据
        sds = sps + sdo  # 字符串数据实际起始位置
        for o in offs: self.strings.append(self._rstr(sds + o))
        # 跳转到字符串池块末尾
        self.pos = sps + pool_chunk_size
        # 跳过可能的资源ID块 (chunk type 0x0180)
        while self.pos < len(self.data) - 8:
            ct = self._r16()
            if ct == 0x0180:  # 资源ID块
                hs = self._r16()
                cs = self._r32()
                self.pos += (cs - 8)  # 跳过整个块
            else:
                # 回退8字节，让_parse_tags重新读取这个块头
                self.pos -= 2  # 只回退已读取的2字节chunk type，非8字节
                break
        return self._parse_tags()
    def _parse_tags(self):
        tags = []
        xmlns = []
        while self.pos < len(self.data) - 8:
            ct = self._r16(); hs = self._r16(); cs = self._r32()
            chunk_start = self.pos - 8  # 当前块起始位置
            if ct == 0x00100:
                self._r32(); self._r32()
                pi = self._r32(); ui = self._r32()
                p = self.strings[pi] if 0 <= pi < len(self.strings) else ""
                u = self.strings[ui] if 0 <= ui < len(self.strings) else ""
                xmlns.append((p, u))
            elif ct == 0x00102:
                # Android Binary XML START_TAG 格式:
                # +0: lineNumber (u32), +4: commentIndex (u32)
                # +8: ns (u32), +12: name (u32)
                # +16: attrStart (u16), +18: attrSize (u16)
                # +20: attrCount (u16), +22: idIndex (u16)
                # +24: classIndex (u16), +26: styleIndex (u16)
                self._r32()  # lineNumber
                self._r32()  # commentIndex
                ni = self._r32()   # ns
                nai = self._r32()  # name
                attr_start = self._r16()  # attrStart (从块起始的偏移)
                attr_size = self._r16()   # attrSize (每个属性条目大小, 通常20)
                ac = self._r16()          # attrCount (属性数量)
                self._r16()  # idIndex
                self._r16()  # classIndex
                self._r16()  # styleIndex
                # headerSize = 36 (7 uint16 + 4 uint32 = 14+16=30... wait)
                # 实际上: 2(type)+2(hs)+4(cs)+4(line)+4(comment)+4(ns)+4(name)+2(attrStart)+2(attrSize)+2(attrCount)+2(id)+2(class)+2(style) = 36
                name = self.strings[nai] if 0 <= nai < len(self.strings) else f"?{nai}"
                attrs = []
                # 跳转到属性数据实际位置: chunk_start + headerSize + attrStart
                # attributeStart 是相对于 ResXMLTree_attrExt 结构体起始位置的偏移，
                # 该结构体从 chunk_start + hs (headerSize=16) 处开始
                self.pos = chunk_start + hs + attr_start
                for _ in range(ac):
                    ai = self._r32()   # namespace URI
                    ani = self._r32()  # name
                    vsi = self._r32()  # raw value
                    vt = self._r32()   # value type
                    vd = self._r32()   # value data
                    an = self.strings[ani] if 0 <= ani < len(self.strings) else f"?{ani}"
                    an_ns = self.strings[ai] if 0 <= ai < len(self.strings) else None
                    if vt >> 24 == 3:
                        val = self.strings[vsi] if 0 <= vsi < len(self.strings) else f"?{vsi}"
                    else:
                        val = str(vd)
                    attrs.append({'name': an, 'value': val, 'ns': an_ns})
                tags.append({'type': 'start', 'name': name, 'attrs': attrs})
                # 定位到块末尾
                self.pos = chunk_start + cs
            elif ct == 0x00103:
                self._r32(); self._r32(); self._r32(); nai = self._r32()
                name = self.strings[nai] if 0 <= nai < len(self.strings) else f"?{nai}"
                tags.append({'type': 'end', 'name': name})
            else:
                self.pos = chunk_start + cs  # 跳到块末尾继续
        return {'tags': tags, 'xmlns': xmlns}
    def get_manifest_simple(self):
        r = self.parse(); tags = r.get('tags', [])
        pkg = ""; sdk = {}; perms = []; comps = []
        # components 按 Activity/Service/Receiver/Provider 分类
        activities = []; services = []; receivers = []; providers = []
        for tag in tags:
            if tag['type'] == 'start' and tag['name'] == 'manifest':
                for a in tag['attrs']:
                    n = a['name'].lower()
                    if 'package' in n: pkg = a['value']
                    elif 'versioncode' in n: sdk['versionCode'] = a['value']
                    elif 'versionname' in n: sdk['versionName'] = a['value']
            # uses-sdk 标签
            if tag['type'] == 'start' and tag['name'] == 'uses-sdk':
                for a in tag['attrs']:
                    n = a['name'].lower()
                    if 'minsdk' in n: sdk['minSdk'] = a['value']
                    elif 'targetsdk' in n: sdk['targetSdk'] = a['value']
                    elif 'maxsdk' in n: sdk['maxSdk'] = a['value']
            if tag['type'] == 'start' and tag['name'] == 'uses-permission':
                for a in tag['attrs']:
                    if 'name' in a['name'].lower(): perms.append(a['value'])
            if tag['type'] == 'start' and tag['name'] == 'activity':
                c = {'type': 'activity', 'attrs': {a['name']:a['value'] for a in tag['attrs']}}
                comps.append(c)
                activities.append(c)
            if tag['type'] == 'start' and tag['name'] == 'service':
                c = {'type': 'service', 'attrs': {a['name']:a['value'] for a in tag['attrs']}}
                comps.append(c)
                services.append(c)
            if tag['type'] == 'start' and tag['name'] == 'receiver':
                c = {'type': 'receiver', 'attrs': {a['name']:a['value'] for a in tag['attrs']}}
                comps.append(c)
                receivers.append(c)
            if tag['type'] == 'start' and tag['name'] == 'provider':
                c = {'type': 'provider', 'attrs': {a['name']:a['value'] for a in tag['attrs']}}
                comps.append(c)
                providers.append(c)
        return {'package': pkg, 'sdk': sdk, 'permissions': perms,
                'components': comps,
                'activities': activities, 'services': services,
                'receivers': receivers, 'providers': providers}
