#!/usr/bin/env python3
import sys; sys.path.insert(0,'/home')
from apk_reverse_engine import open_apk, analyze_elf
apk='/sdcard/Download/reqable-app-android-arm64.apk'
with open_apk(apk) as ctx:
    so_files = ctx.get_so_files()
    print('SO files count:', len(so_files))
    for s in so_files[:3]:
        data = ctx.read_file(s)
        magic = data[:4]
        is_elf = magic[0:1]==b'\x7f' and magic[1:4]==b'ELF'
        print(f'{s}: len={len(data)}, magic={magic.hex()}, is_elf={is_elf}')
    # 再看一个完整的
    import json
    if so_files:
        s = so_files[0]
        data = ctx.read_file(s)
        r = analyze_elf(data)
        print(f'analyze_elf({s}):', json.dumps(r)[:200])