#!/usr/bin/env python3
"""调试AXML解析器 - 检查parse结果"""
import sys
sys.path.insert(0, '/home')
import os

apk = '/sdcard/Download/reqable-app-android-arm64.apk'
if not os.path.exists(apk): apk = '/sdcard/Download/app-release.apk'

from apk_reverse_engine.core.apk_context import APKContext
from apk_reverse_engine.utils.axml_parser import AXMLParser

with APKContext(apk) as ctx:
    data = ctx.get_manifest_xml()

print(f"AXML data size: {len(data)}")

parser = AXMLParser(data)
result = parser.parse()

print(f"Tags count: {len(result.get('tags', []))}")
print(f"Error: {result.get('error')}")
print(f"Strings count: {len(parser.strings)}")
print(f"First 30 strings: {parser.strings[:30]}")
print()

if result.get('tags'):
    for i, tag in enumerate(result['tags'][:5]):
        print(f"Tag {i}: {tag['type']} name='{tag['name']}' attrs={tag.get('attrs', [])}")
else:
    print("NO TAGS PARSED!")
    # 手动检查第一个START_TAG之后发生了什么
    print(f"Parser pos after parse: {parser.pos}")
    print(f"Data length: {len(parser.data)}")
    
    # 在_parse_tags位置手动解析
    import struct
    # 重新解析
    pos = 8
    # 跳过字符串池
    pool_size = struct.unpack_from('<I', data, pos + 4)[0]
    pos += pool_size
    # 跳过资源ID
    while pos < len(data) - 8:
        ct = struct.unpack_from('<H', data, pos)[0]
        cs = struct.unpack_from('<I', data, pos + 4)[0]
        if ct == 0x0180:
            pos += cs
        else:
            break
    
    print(f"\nStarting manual parse at pos={pos}")
    ct = struct.unpack_from('<H', data, pos)[0]
    hs = struct.unpack_from('<H', data, pos + 2)[0]
    cs = struct.unpack_from('<I', data, pos + 4)[0]
    print(f"First chunk: type=0x{ct:04x}, headerSize={hs}, chunkSize={cs}")
    
    if ct == 0x0100:  # START_NAMESPACE
        # 跳过后面的数据
        pos += cs
        ct = struct.unpack_from('<H', data, pos)[0]
        cs = struct.unpack_from('<I', data, pos + 4)[0]
        print(f"Second chunk: type=0x{ct:04x}, chunkSize={cs}")
    
    if ct == 0x0102:  # START_TAG
        ns = struct.unpack_from('<I', data, pos + 16)[0]
        name = struct.unpack_from('<I', data, pos + 20)[0]
        flags = struct.unpack_from('<H', data, pos + 24)[0]
        ac = struct.unpack_from('<H', data, pos + 26)[0]
        print(f"  ns_index={ns}, name_index={name}, flags={flags}, attr_count={ac}")
        if 0 <= name < len(parser.strings):
            print(f"  tag_name='{parser.strings[name]}'")
        else:
            print(f"  name_index {name} out of range (strings={len(parser.strings)})")
        
        # 解析属性
        if ac > 0:
            attr_start = struct.unpack_from('<H', data, pos + 28)[0]
            print(f"  attr_start={attr_start}")
            for i in range(min(ac, 5)):
                apos = pos + attr_start + i * 20
                ai = struct.unpack_from('<I', data, apos)[0]
                ani = struct.unpack_from('<I', data, apos + 4)[0]
                vsi = struct.unpack_from('<I', data, apos + 8)[0]
                vt = struct.unpack_from('<I', data, apos + 12)[0]
                vd = struct.unpack_from('<I', data, apos + 16)[0]
                an = parser.strings[ani] if 0 <= ani < len(parser.strings) else f"?{ani}"
                val = parser.strings[vsi] if (vt >> 24 == 3) and 0 <= vsi < len(parser.strings) else str(vd)
                print(f"  attr[{i}]: name='{an}' value='{val}' type=0x{vt:08x}")