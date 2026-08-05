#!/usr/bin/env python3
"""检查AXML START_TAG正确的字段偏移"""
import sys
sys.path.insert(0, '/home')
import os, struct

apk = '/sdcard/Download/reqable-app-android-arm64.apk'
if not os.path.exists(apk): apk = '/sdcard/Download/app-release.apk'

from apk_reverse_engine.core.apk_context import APKContext

with APKContext(apk) as ctx:
    data = ctx.get_manifest_xml()

# 跳到第一个START_TAG
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
if ct == 0x0100:
    pos += cs
    ct = struct.unpack_from('<H', data, pos)[0]
    cs = struct.unpack_from('<I', data, pos + 4)[0]

print(f"First START_TAG at position {pos}")
print(f"Chunk header: type=0x{ct:04x}, headerSize={struct.unpack_from('<H', data, pos+2)[0]}, chunkSize={cs}")

# Dump the header bytes
print(f"\nRaw header bytes (offset 0-47 from chunk start):")
for i in range(0, 48, 2):
    if i + 1 < 48:
        val = struct.unpack_from('<H', data, pos + i)[0]
        print(f"  [{i:2d}-{i+1:2d}]: 0x{val:04x} ({val})")

# 已知Android AXML START_TAG格式:
# 0-1: type (uint16)
# 2-3: headerSize (uint16)  
# 4-7: chunkSize (uint32)
# 8-11: lineNumber (uint32)
# 12-15: commentIndex (uint32)
# 16-19: ns (uint32)
# 20-23: name (uint32)
# 24-25: attributeStart (uint16) - offset from chunk start to attribute data
# 26-27: attributeSize (uint16) - size of each attribute (usually 20)
# 28-29: attributeCount (uint16)
# 30-31: idIndex (uint16)
# 32-33: classIndex (uint16)
# 34-35: styleIndex (uint16)

attr_start = struct.unpack_from('<H', data, pos + 24)[0]
attr_size = struct.unpack_from('<H', data, pos + 26)[0]
attr_count = struct.unpack_from('<H', data, pos + 28)[0]
id_idx = struct.unpack_from('<H', data, pos + 30)[0]
class_idx = struct.unpack_from('<H', data, pos + 32)[0]
style_idx = struct.unpack_from('<H', data, pos + 34)[0]
name_idx = struct.unpack_from('<I', data, pos + 20)[0]

print(f"\nCorrect field parsing:")
print(f"  attrStart={attr_start}, attrSize={attr_size}, attrCount={attr_count}")
print(f"  idIndex={id_idx}, classIndex={class_idx}, styleIndex={style_idx}")
print(f"  nameIdx={name_idx}")

# 属性数据实际位置
attr_data_pos = pos + attr_start
print(f"\nAttribute data at: {attr_data_pos} (chunk offset {attr_start})")
print(f"Current pos after header (if we read all fields): {pos + 36}")

# 从字符串池读名字
from apk_reverse_engine.utils.axml_parser import AXMLParser
parser = AXMLParser(data)
parser.parse()
name = parser.strings[name_idx] if 0 <= name_idx < len(parser.strings) else f"?{name_idx}"
print(f"Tag name: '{name}'")

# 读取属性
print(f"\n--- Attributes ({attr_count}) ---")
for i in range(min(attr_count, 5)):
    apos = attr_data_pos + i * attr_size
    ns_idx = struct.unpack_from('<I', data, apos)[0]
    n_idx = struct.unpack_from('<I', data, apos + 4)[0]
    val_idx = struct.unpack_from('<I', data, apos + 8)[0]
    val_type = struct.unpack_from('<I', data, apos + 12)[0]
    val_data = struct.unpack_from('<I', data, apos + 16)[0]
    
    attr_name = parser.strings[n_idx] if 0 <= n_idx < len(parser.strings) else f"?{n_idx}"
    if val_type >> 24 == 3:  # TYPE_STRING
        val = parser.strings[val_idx] if 0 <= val_idx < len(parser.strings) else f"?{val_idx}"
    else:
        val = str(val_data)
    ns_uri = parser.strings[ns_idx] if 0 <= ns_idx < len(parser.strings) else ""
    print(f"  [{i}] ns='{ns_uri}' name='{attr_name}' value='{val}' type=0x{val_type:08x}")