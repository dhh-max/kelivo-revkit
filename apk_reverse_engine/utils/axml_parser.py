import struct
class AXMLParser:
    """Android Binary XML Parser"""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.strings = []
    def _r32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v
    def _r16(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]; self.pos += 2; return v
    def _rstr(self, off):
        try:
            end = self.data.index(b'\x00', off)
            return self.data[off:end].decode('utf-8', errors='replace')
        except: return ""
    def parse(self):
        magic = self._r32()
        if magic != 0x00080003: return {"error": f"Invalid AXML magic=0x{magic:08x}"}
        size = self._r32()
        sps = self.pos
        self._r32(); self._r32(); sc = self._r32(); self._r32()
        self._r32(); self._r32(); sdo = self._r32()
        offs = [self._r32() for _ in range(sc)]
        sds = sps + sdo
        for o in offs: self.strings.append(self._rstr(sds + o))
        self.pos = sps + (self.pos - sps)
        # re-read chunk size
        self.pos = sps + 8
        csize = self._r32()
        self.pos = sps + csize
        return self._parse_tags()
    def _parse_tags(self):
        tags = []
        xmlns = []
        while self.pos < len(self.data) - 8:
            ct = self._r16(); hs = self._r16(); cs = self._r32()
            if ct == 0x00100:
                self._r32(); self._r32()
                pi = self._r32(); ui = self._r32()
                p = self.strings[pi] if 0 <= pi < len(self.strings) else ""
                u = self.strings[ui] if 0 <= ui < len(self.strings) else ""
                xmlns.append((p, u))
            elif ct == 0x00102:
                self._r32(); self._r32()
                ni = self._r32(); nai = self._r32()
                self._r16(); ac = self._r16(); self._r16()
                name = self.strings[nai] if 0 <= nai < len(self.strings) else f"?{nai}"
                attrs = []
                for _ in range(ac):
                    ai = self._r32(); ani = self._r32(); vsi = self._r32()
                    vt = self._r32(); vd = self._r32()
                    an = self.strings[ani] if 0 <= ani < len(self.strings) else f"?{ani}"
                    if vt >> 24 == 3:
                        val = self.strings[vsi] if 0 <= vsi < len(self.strings) else f"?{vsi}"
                    else: val = str(vd)
                    attrs.append({'name': an, 'value': val})
                tags.append({'type': 'start', 'name': name, 'attrs': attrs})
            elif ct == 0x00103:
                self._r32(); self._r32(); self._r32(); nai = self._r32()
                name = self.strings[nai] if 0 <= nai < len(self.strings) else f"?{nai}"
                tags.append({'type': 'end', 'name': name})
            else: break
        return {'tags': tags, 'xmlns': xmlns}
    def get_manifest_simple(self):
        r = self.parse(); tags = r.get('tags', [])
        pkg = ""; sdk = {}; perms = []; comps = []
        for tag in tags:
            if tag['type'] == 'start' and tag['name'] == 'manifest':
                for a in tag['attrs']:
                    n = a['name'].lower()
                    if 'package' in n: pkg = a['value']
                    elif 'versioncode' in n: sdk['versionCode'] = a['value']
                    elif 'versionname' in n: sdk['versionName'] = a['value']
                    elif 'minsdk' in n: sdk['minSdk'] = a['value']
                    elif 'targetsdk' in n: sdk['targetSdk'] = a['value']
            if tag['type'] == 'start' and tag['name'] == 'uses-permission':
                for a in tag['attrs']:
                    if 'name' in a['name'].lower(): perms.append(a['value'])
            if tag['type'] == 'start' and tag['name'] in ['activity','service','receiver','provider']:
                c = {'type': tag['name'], 'attrs': {a['name']:a['value'] for a in tag['attrs']}}
                comps.append(c)
        return {'package': pkg, 'sdk': sdk, 'permissions': perms, 'components': comps}
