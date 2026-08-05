#!/usr/bin/env python3
"""检查解析后的tags"""
import sys
sys.path.insert(0, '/home')
import os

apk = '/sdcard/Download/reqable-app-android-arm64.apk'
if not os.path.exists(apk): apk = '/sdcard/Download/app-release.apk'

from apk_reverse_engine.core.apk_context import APKContext
from apk_reverse_engine.utils.axml_parser import AXMLParser

with APKContext(apk) as ctx:
    data = ctx.get_manifest_xml()

parser = AXMLParser(data)
result = parser.parse()

for i, tag in enumerate(result.get('tags', [])[:30]):
    if tag['type'] == 'start':
        print(f"Tag {i}: <{tag['name']}>")
        for a in tag.get('attrs', []):
            print(f"  {a['name']} = {a['value']}")
    elif tag['type'] == 'end':
        print(f"Tag {i}: </{tag['name']}>")