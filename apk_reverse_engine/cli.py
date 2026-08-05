#!/usr/bin/env python3
"""APK Reverse Engineering Engine v2 - CLI (基于扁平化API)"""
import sys, os, json
sys.path.insert(0, '/home')

from apk_reverse_engine import *

def cmd_inspect(args):
    print(json.dumps(static_analyze(args.apk), indent=2, ensure_ascii=False))

def cmd_analyze(args):
    print(json.dumps(analyze_full(args.apk), indent=2, ensure_ascii=False))

def cmd_manifest(args):
    with open_apk(args.apk) as ctx:
        data = ctx.get_manifest_xml()
        print(json.dumps(get_manifest_info(data), indent=2, ensure_ascii=False))

def cmd_dex(args):
    with open_apk(args.apk) as ctx:
        for d in ctx.get_dex_files():
            data = ctx.read_file(d)
            h = dex_header(data)
            print(f"DEX: {d}")
            print(f"  Size: {len(data)} bytes")
            print(f"  Classes: {h.get('class_defs', 0)}")
            print(f"  Methods: {h.get('method_ids', 0)}")
            print(f"  Strings: {h.get('string_ids', 0)}")

def cmd_search(args):
    print(json.dumps(search_apk(args.apk, args.query, args.scope or "all", args.max or 100), indent=2, ensure_ascii=False))

def cmd_unpack(args):
    print(json.dumps(unpack_apk(args.apk, args.output), indent=2))

def cmd_decode(args):
    print(json.dumps(apktool_decode(args.apk, args.output, args.force or False), indent=2))

def cmd_build(args):
    print(json.dumps(apktool_build(args.input, args.output), indent=2))

def cmd_sign(args):
    print(json.dumps(sign_debug(args.apk, args.output), indent=2))

def cmd_jadx(args):
    print(json.dumps(jadx_decompile(args.apk, args.output, deobf=not args.no_deobf), indent=2))

def cmd_classes(args):
    with open_apk(args.apk) as ctx:
        for d in ctx.get_dex_files():
            data = ctx.read_file(d)
            names = dex_class_names(data)
            print(f"=== {d} ({len(names)} classes) ===")
            for n in names[:args.max]:
                print(f"  {n}")

def cmd_so(args):
    with open_apk(args.apk) as ctx:
        for s in ctx.get_so_files():
            data = ctx.read_file(s)
            r = analyze_elf(data)
            print(f"=== {s} ===")
            print(json.dumps(r, indent=2, ensure_ascii=False))

def cmd_patch(args):
    with open(args.apk, 'rb') as f:
        data = f.read()
    if args.type == 'hex':
        data = native_patch_hex(data, args.old, args.new)
    elif args.type == 'string':
        data = native_patch_string(data, args.old, args.new)
    elif args.type == 'ret':
        data = native_patch_ret(data, int(args.offset, 0), args.arch or 'aarch64')
    elif args.type == 'nop':
        data = native_nop_out(data, int(args.offset, 0), int(args.count or 4))
    safe_write(args.output, data)
    print(json.dumps({'success': True, 'output': args.output, 'size': len(data)}))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="APK Reverse Engineering Engine v2")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("inspect", help="Inspect APK基本信息")
    p.add_argument("apk"); p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("analyze", help="全面分析APK(含权限/混淆/加固/安全/SO)")
    p.add_argument("apk"); p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("manifest", help="解析AndroidManifest")
    p.add_argument("apk"); p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("dex", help="DEX文件分析")
    p.add_argument("apk"); p.set_defaults(func=cmd_dex)

    p = sub.add_parser("classes", help="列出DEX类名")
    p.add_argument("apk"); p.add_argument("--max", type=int, default=100)
    p.set_defaults(func=cmd_classes)

    p = sub.add_parser("so", help="分析SO文件")
    p.add_argument("apk"); p.set_defaults(func=cmd_so)

    p = sub.add_parser("search", help="在APK中搜索")
    p.add_argument("apk"); p.add_argument("query")
    p.add_argument("--scope", default="all"); p.add_argument("--max", type=int, default=100)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("unpack", help="解压APK")
    p.add_argument("apk"); p.add_argument("output"); p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("decode", help="Apktool解包")
    p.add_argument("apk"); p.add_argument("output")
    p.add_argument("--force", action="store_true"); p.set_defaults(func=cmd_decode)

    p = sub.add_parser("build", help="Apktool重打包")
    p.add_argument("input"); p.add_argument("output"); p.set_defaults(func=cmd_build)

    p = sub.add_parser("sign", help="签名APK")
    p.add_argument("apk"); p.add_argument("output"); p.set_defaults(func=cmd_sign)

    p = sub.add_parser("jadx", help="JADX反编译")
    p.add_argument("apk"); p.add_argument("output")
    p.add_argument("--no-deobf", action="store_true"); p.set_defaults(func=cmd_jadx)

    p = sub.add_parser("patch", help="原生SO补丁")
    p.add_argument("apk"); p.add_argument("output"); p.add_argument("--type", choices=['hex','string','ret','nop'], required=True)
    p.add_argument("--old", default=""); p.add_argument("--new", default="")
    p.add_argument("--offset", default="0"); p.add_argument("--count", default="4")
    p.add_argument("--arch", default="aarch64")
    p.set_defaults(func=cmd_patch)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()