#!/usr/bin/env python3
"""调试AXML解析器"""
import sys
sys.path.insert(0, '/home')
import os, struct

apk = '/sdcard/Download/reqable-app-android-arm64.apk'
if not os.path.exists(apk): apk = '/sdcard/Download/app-release.apk'

from apk_reverse_engine.core.apk_context import APKContext

with APKContext(apk) as ctx:
    data = ctx.get_manifest_xml()

print('size:', len(data))
print('magic:', hex(struct.unpack_from('<I', data, 0)[0]))
print('file_size:', struct.unpack_from('<I', data, 4)[0])

# 手动解析字符串池块
pos = 8
ct = struct.unpack_from('<H', data, pos)[0]
print('string_pool type:', hex(ct))
cs = struct.unpack_from('<I', data, pos + 4)[0]
print('string_pool chunk_size:', cs)

# 检查字符串池内容
sc = struct.unpack_from('<I', data, pos + 8)[0]
print('string_count:', sc)
flags = struct.unpack_from('<I', data, pos + 16)[0]
print('flags:', hex(flags), 'utf8:', bool(flags & 0x100))
sdo = struct.unpack_from('<I', data, pos + 20)[0]
print('strings_offset:', sdo)

# 读取第一个字符串偏移
first_off = struct.unpack_from('<I', data, pos + 28)[0]
print('first string offset:', first_off)
sds = pos + sdo
print('strings data start:', sds)

# 读取第一个字符串
if flags & 0x100:
    off = sds + first_off
    print('UTF-8 encoding')
    # 跳过字符数
    if data[off] & 0x80:
        off += 2
    else:
        off += 1
    # 跳过字节数
    if data[off] & 0x80:
        off += 2
    else:
        off += 1
    end = data.index(b'\x00', off)
    first_str = data[off:end].decode('utf-8', errors='replace')
    print('first string:', repr(first_str))
else:
    off = sds + first_off
    print('UTF-16LE encoding')
    char_count = struct.unpack_from('<H', data, off)[0]
    print('char_count:', char_count)
    off += 2
    if char_count > 0:
        raw = data[off:off + char_count * 2]
        first_str = raw.decode('utf-16-le', errors='replace')
        print('first string:', repr(first_str))

# 跳转到字符串池末尾
pos = 8 + cs
print('pos after string pool:', pos)

# 检查下一个块
if pos < len(data):
    nct = struct.unpack_from('<H', data, pos)[0]
    print('next chunk type:', hex(nct))
    ncs = struct.unpack_from('<I', data, pos + 4)[0]
    print('next chunk size:', ncs)
    
    # 如果是资源ID块，跳过
    if nct == 0x0180:
        print('skipping resource ID chunk')
        pos += ncs
        print('pos after res ID:', pos)
    
    # 读取第一个XML块
    if pos < len(data):
        xct = struct.unpack_from('<H', data, pos)[0]
        xhs = struct.unpack_from('<H', data, pos + 2)[0]
        xcs = struct.unpack_from('<I', data, pos + 4)[0]
        print('XML chunk type:', hex(xct), 'header_size:', xhs, 'chunk_size:', xcs)
        
        # 测试START_TAG解析
        if xct == 0x0102:
            ns = struct.unpack_from('<I', data, pos + 8)[0]
            name = struct.unpack_from('<I', data, pos + 12)[0]
            print('namespace_uri:', ns, 'name_index:', name)
            flag = struct.unpack_from('<H', data, pos + 16)[0]
            ac = struct.unpack_from('<H', data, pos + 18)[0]
            print('attr_count:', ac)
            if data[0x10] & 0x80:
                print('attr_start:', struct.unpack_from('<H', data, pos + 20)[0])

print()
print('Checking if parse succeeds...')
from apk_reverse_engine.utils.axml_parser import AXMLParser
parser = AXMLParser(data)
r = parser.parse()
print('parse result tags:', len(r.get('tags', [])))
print('parse error:', r.get('error'))
print('parsed strings count:', len(parser.strings))
print('first 5 strings:', parser.strings[:5])