import struct

class ResourceParser:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def r32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v
    def r16(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]; self.pos += 2; return v
    def r8(self):
        v = self.data[self.pos]; self.pos += 1; return v

    def parse(self):
        if len(self.data) < 12:
            return {'error': 'too small'}
        pkg_count = self.r16()
        self.pos = 0
        info = {'package_count': pkg_count, 'packages': []}
        self.pos = 12
        while self.pos < len(self.data) - 8:
            ct = self.r16(); hs = self.r16(); cs = self.r32()
            if ct == 0x0200:
                pi = self.r32()
                pn = self.data[self.pos:self.pos+256].decode('utf-16le', errors='replace').split('\x00')[0]
                self.pos += 256
                lsi = self.r32()
                info['packages'].append({'id': pi, 'name': pn, 'last_type': lsi})
            else:
                self.pos += cs - 8
        return info
