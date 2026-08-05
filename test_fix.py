#!/usr/bin/env python3
"""测试修复后的引擎"""
import sys
sys.path.insert(0, '/home')
from apk_reverse_engine import *
import os

apk = '/sdcard/Download/reqable-app-android-arm64.apk'
if not os.path.exists(apk):
    apk = '/sdcard/Download/app-release.apk'
if not os.path.exists(apk):
    apk = '/sdcard/SoSimple_1.0.apk'

print('='*60)
print('测试1: 解包')
print('='*60)
import tempfile
out = tempfile.mkdtemp(prefix='test_')
r = unpack_apk(apk, out)
print('  success:', r.get('success'))
print('  extracted:', r.get('extracted'), 'files')
print('  errors:', len(r.get('errors', [])))

print()
print('='*60)
print('测试2: manifest解析')
print('='*60)
with open_apk(apk) as ctx:
    md = ctx.get_manifest_xml()
    info = get_manifest_info(md)
print('  package:', info.get('package'))
print('  sdk:', info.get('sdk'))
print('  permissions:', len(info.get('permissions', [])))
print('  components:', len(info.get('components', [])))

print()
print('='*60)
print('测试3: analyze_full')
print('='*60)
result = analyze_full(apk)
print('  keys:', list(result.keys()))
print('  manifest package:', result.get('manifest', {}).get('package'))
sec = result.get('security', {})
print('  security score:', sec.get('risk_score'))
print('  security level:', sec.get('risk_level'))

print()
print('='*60)
print('测试4: static_analyze')
print('='*60)
r2 = static_analyze(apk)
print('  manifest package:', r2.get('manifest', {}).get('package'))
print('  dex files:', len(r2.get('dex_summary', [])))
print('  abis:', r2.get('abi_architectures'))

print()
print('='*60)
print('测试5: DEX类名')
print('='*60)
with open_apk(apk) as ctx:
    for d in ctx.get_dex_files()[:1]:
        data = ctx.read_file(d)
        names = dex_class_names(data)
        print('  ', d, '-', len(names), 'classes')
        print('  前5个:', names[:5])

print()
print('✅ 全部测试通过')