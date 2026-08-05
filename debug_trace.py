#!/usr/bin/env python3
"""逐块跟踪AXML解析"""
import sys
sys.path.insert(0, '/home')
import os, struct

apk = '/sdcard/Download/reqable-app-android-arm64.apk'
if not os.path.exists(apk): apk = '/sdcard/Download/app-release.apk'

from apk_reverse_engine.core.apk_context import APKContext

with APKContext(apk) as ctx:
    data = ctx.get_manifest_xml()

# 跳过文件头
pos = 8
print(f"File header: magic=0x{struct.unpack_from('<I', data, 0)[0]:08x}, size={struct.unpack_from('<I', data, 4)[0]}")

# 跳过字符串池
pool_type = struct.unpack_from('<I', data, pos)[0]
pool_size = struct.unpack_from('<I', data, pos + 4)[0]
print(f"String pool: type=0x{pool_type:08x}, size={pool_size}")
pos += pool_size

# 跳过资源ID
while pos < len(data) - 8:
    ct = struct.unpack_from('<H', data, pos)[0]
    cs = struct.unpack_from('<I', data, pos + 4)[0]
    print(f"Chunk @{pos}: type=0x{ct:04x}, size={cs}")
    if ct == 0x0100:
        print(f"  -> START_NAMESPACE")
        pos += cs
    elif ct == 0x0102:
        print(f"  -> START_TAG")
        ni = struct.unpack_from('<I', data, pos + 12)[0]
        nai = struct.unpack_from('<I', data, pos + 16)[0]
        print(f"     ns_index={ni}, name_index={nai}")
        pos += cs
    elif ct == 0x0103:
        print(f"  -> END_TAG")
        pos += cs
    elif ct == 0x0180:
        print(f"  -> RESOURCE_ID")
        pos += cs
    else:
        print(f"  -> UNKNOWN! Breaking")
        break

print(f"\nTotal pos: {pos}, data len: {len(data)}")