#!/usr/bin/env python3
"""检查AXML属性偏移"""
import sys
sys.path.insert(0, '/home')
import os, struct

apk = '/sdcard/Download/reqable-app-android-arm64.apk'
if not os.path.exists(apk): apk = '/sdcard/Download/app-release.apk'

from apk_reverse_engine.core.apk_context import APKContext

with APKContext(apk) as ctx:
    data = ctx.get_manifest_xml()

# 找到第一个START_TAG
pos = 8
pool_size = struct.unpack_from('<I', data, pos + 4)[0]
pos += pool_size
while pos < len(data) - 8:
    ct = struct.unpack_from('<H', data, pos)[0]
    cs = struct.unpack_from('<I', data, pos + 4)[0]
    if ct == 0x0180:
        pos += cs
    else:
        break

# 跳过START_NAMESPACE
if ct == 0x0100:
    pos += cs
    ct = struct.unpack_from('<H', data, pos)[0]
    cs = struct.unpack_from('<I', data, pos + 4)[0]

if ct == 0x0102:
    hs = struct.unpack_from('<H', data, pos + 2)[0]
    line = struct.unpack_from('<I', data, pos + 8)[0]
    comment = struct.unpack_from('<I', data, pos + 12)[0]
    ns = struct.unpack_from('<I', data, pos + 16)[0]
    name = struct.unpack_from('<I', data, pos + 20)[0]
    flags = struct.unpack_from('<H', data, pos + 24)[0]
    ac = struct.unpack_from('<H', data, pos + 26)[0]
    attr_start = struct.unpack_from('<H', data, pos + 28)[0]
    attr_end_off = struct.unpack_from('<H', data, pos + 30)[0]
    
    print(f"chunk_start={pos}, header_size={hs}, chunk_size={cs}")
    print(f"line={line}, comment={comment}")
    print(f"ns_uri_idx={ns}, name_idx={name}")
    print(f"flags={flags}, attr_count={ac}")
    print(f"attrStart={attr_start}, attrEnd={attr_end_off}")
    print(f"header_end={pos + 32}")
    print(f"attr_data_start={pos + attr_start}")
    
    # 读取属性
    if ac > 0:
        apos = pos + attr_start
        for i in range(min(ac, 5)):
            ai = struct.unpack_from('<I', data, apos)[0]
            ani = struct.unpack_from('<I', data, apos + 4)[0]
            vsi = struct.unpack_from('<I', data, apos + 8)[0]
            vt = struct.unpack_from('<I', data, apos + 12)[0]
            vd = struct.unpack_from('<I', data, apos + 16)[0]
            print(f"\nAttr[{i}] @ offset {apos - pos}:")
            print(f"  ns_uri_idx={ai} (0x{ai:08x})")
            print(f"  name_idx={ani} (0x{ani:08x})")
            print(f"  raw_value_idx={vsi} (0x{vsi:08x})")
            print(f"  type={vt} (0x{vt:08x})")
            print(f"  data={vd} (0x{vd:08x})")
            apos += 20

print("\n字符串池前20个:")
from apk_reverse_engine.utils.axml_parser import AXMLParser
parser = AXMLParser(data)
parser.parse()
for i, s in enumerate(parser.strings[:20]):
    print(f"  [{i}] = '{s}'")