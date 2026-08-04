#!/usr/bin/env python3
"""APK Reverse Engineering Engine v2 - CLI"""
import sys, os, json
sys.path.insert(0, '/home')

from apk_reverse_engine.core.apk_context import APKContext
from apk_reverse_engine.core.manifest_parser import ManifestParser
from apk_reverse_engine.core.dex_parser import DexParser
from apk_reverse_engine.analysis.static_analyzer import StaticAnalyzer
from apk_reverse_engine.analysis.permission_analyzer import PermissionAnalyzer
from apk_reverse_engine.analysis.obfuscation_detector import ObfuscationDetector
from apk_reverse_engine.analysis.security_analyzer import SecurityAnalyzer
from apk_reverse_engine.tools.unpacker import APKUnpacker
from apk_reverse_engine.tools.repacker import APKRepacker
from apk_reverse_engine.tools.signer import APKSigner
from apk_reverse_engine.tools.searcher import APKSearch
from apk_reverse_engine.tools.decompiler import APKDecompiler

def cmd_inspect(args):
    sa = StaticAnalyzer(args.apk)
    r = sa.analyze()
    sa.close()
    print(json.dumps(r, indent=2, ensure_ascii=False))

def cmd_analyze(args):
    sa = StaticAnalyzer(args.apk)
    r = sa.analyze()
    sa.close()
    perms = r.get("manifest", {}).get("permissions", [])
    r["permission_analysis"] = PermissionAnalyzer.analyze(perms)
    dex_names = []
    try:
        with APKContext(args.apk) as ctx:
            for d in ctx.get_dex_files():
                data = ctx.read_file(d)
                dp = DexParser(data)
                h = dp.parse_header()
                for ci in range(min(h.get("class_defs", 0), 200)):
                    dex_names.append(dp.get_string(ci))
    except: pass
    r["obfuscation"] = ObfuscationDetector.detect_class_names(dex_names)
    with APKContext(args.apk) as ctx:
        packers = ObfuscationDetector.detect_packer(ctx.zip)
    r["security"] = SecurityAnalyzer.analyze(
        r.get("manifest", {}), r["permission_analysis"],
        r["obfuscation"].get("score", 0), packers)
    print(json.dumps(r, indent=2, ensure_ascii=False))

def cmd_manifest(args):
    with APKContext(args.apk) as ctx:
        data = ctx.get_manifest_xml()
        r = ManifestParser.get_simple(data)
        print(json.dumps(r, indent=2, ensure_ascii=False))

def cmd_dex(args):
    with APKContext(args.apk) as ctx:
        for d in ctx.get_dex_files():
            data = ctx.read_file(d)
            dp = DexParser(data)
            h = dp.parse_header()
            print(f"DEX: {d}")
            print(f"  Size: {len(data)} bytes")
            print(f"  Classes: {h.get('class_defs', 0)}")
            print(f"  Methods: {h.get('method_ids', 0)}")
            print(f"  Strings: {h.get('string_ids', 0)}")

def cmd_search(args):
    r = APKSearch.search_in_apk(args.apk, args.query, args.scope or "all", args.max or 100)
    print(json.dumps(r, indent=2, ensure_ascii=False))

def cmd_unpack(args):
    r = APKUnpacker.extract_raw(args.apk, args.output)
    print(json.dumps(r, indent=2))

def cmd_decode(args):
    r = APKUnpacker.apktool_decode(args.apk, args.output, args.force or False)
    print(json.dumps(r, indent=2))

def cmd_build(args):
    r = APKRepacker.apktool_build(args.input, args.output)
    print(json.dumps(r, indent=2))

def cmd_sign(args):
    r = APKSigner.sign_debug(args.apk, args.output)
    print(json.dumps(r, indent=2))

def cmd_jadx(args):
    r = APKDecompiler.jadx_decompile(args.apk, args.output, deobf=not args.no_deobf)
    print(json.dumps(r, indent=2))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="APK Reverse Engineering Engine v2")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("inspect", help="Inspect APK基本信息")
    p.add_argument("apk"); p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("analyze", help="全面分析APK(含权限/混淆/安全)")
    p.add_argument("apk"); p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("manifest", help="解析AndroidManifest")
    p.add_argument("apk"); p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("dex", help="DEX文件分析")
    p.add_argument("apk"); p.set_defaults(func=cmd_dex)

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

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()