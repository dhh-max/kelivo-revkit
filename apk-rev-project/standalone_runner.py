#!/usr/bin/env python3
"""APK Standalone Runner - 专为 code_runner:run_python 设计
纯Python，零外部依赖，兼容第三方中转站
从同级 standalone_unpacker.py 导入，不依赖包路径

用法:
  python3 standalone_runner.py                          # 自动查找最新上传的APK
  python3 standalone_runner.py /path/to/app.apk         # 指定路径
  python3 standalone_runner.py --json                   # 输出JSON（默认输出自然语言摘要）
  python3 standalone_runner.py --inbox                  # 收件箱模式：批量扫描目录中的APK
"""
import sys, os, json, glob

_self_dir = os.path.dirname(os.path.abspath(__file__))
if _self_dir not in sys.path:
    sys.path.insert(0, _self_dir)
from standalone_unpacker import unpack_apk_standalone, _fmt_size, process_inbox, _generate_summary


def auto_find_apk():
    """自动扫描常见目录，返回最新上传的 APK 文件路径"""
    scan_dirs = [
        '/sdcard/Download',
        '/sdcard/MT2/apks',
        '/sdcard/MT2/backup',
        '/sdcard',
        '/home/kelivo-revkit/apk-rev-project',
        '/sdcard/Download/Operit/cleanOnExit',
        '/sdcard/Download/Operit',
    ]
    candidates = []
    for d in scan_dirs:
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    if f.lower().endswith('.apk'):
                        fp = os.path.join(d, f)
                        candidates.append((os.path.getmtime(fp), fp))
            except:
                pass
    if not candidates:
        for root_dir in ['/sdcard', '/home/kelivo-revkit']:
            for root, dirs, files in os.walk(root_dir):
                for f in files:
                    if f.lower().endswith('.apk'):
                        fp = os.path.join(root, f)
                        candidates.append((os.path.getmtime(fp), fp))
                if root.count(os.sep) > 4:
                    dirs.clear()
    if not candidates:
        return None
    candidates.sort(key=lambda x: -x[0])
    return candidates[0][1]


def analyze_apk(apk_path, mode='quick', output_json=False):
    """一站式APK分析入口
    
    Args:
        apk_path: APK文件路径
        mode: quick|social|sdk|full
        output_json: True=返回JSON dict, False=返回自然语言摘要
    
    Returns:
        str 或 dict：取决于 output_json 参数
    """
    r = unpack_apk_standalone(apk_path)
    if not r.get('success'):
        return json.dumps({'error': r.get('error', '分析失败')}, ensure_ascii=False) if output_json else f"❌ 分析失败: {r.get('error', '未知错误')}"
    
    if output_json:
        summary = {
            'success': True,
            'apk': os.path.basename(apk_path),
            'package': r.get('manifest', {}).get('package', ''),
            'size': r.get('structure', {}).get('size', 0),
            'size_human': _fmt_size(r.get('structure', {}).get('size', 0)),
            'dex_count': r.get('structure', {}).get('dex_count', 0),
            'so_count': r.get('structure', {}).get('so_count', 0),
            'total_files': r.get('structure', {}).get('total_files', 0),
            'total_classes': r.get('total_classes', 0),
            'obfuscation_level': r.get('obfuscation', {}).get('level', ''),
            'obfuscation_score': r.get('obfuscation', {}).get('score', 0),
            'packers': r.get('packers', []),
            'dangerous_permissions': r.get('dangerous_permissions', []),
            'security_issues': r.get('security_issues', []),
        }
        if mode in ('social', 'full'):
            summary['social_login'] = r.get('social_login', {})
        if mode in ('sdk', 'full'):
            summary['sdk_detected'] = r.get('sdk_detected', {})
        if mode == 'full':
            summary['findings'] = r.get('findings', {})
        return summary
    
    # 默认：返回自然语言摘要
    return _generate_summary(r)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='APK Standalone Analyzer')
    parser.add_argument('apk', nargs='?', default=None, help='APK file path (留空则自动查找最新上传的APK)')
    parser.add_argument('--mode', '-m', default='quick',
                        choices=['quick', 'full', 'social', 'sdk'],
                        help='Analysis mode (default: quick)')
    parser.add_argument('--json', '-j', action='store_true',
                        help='输出JSON格式（默认输出自然语言摘要）')
    parser.add_argument('--inbox', '-i', action='store_true',
                        help='收件箱模式：批量扫描目录中的APK并分析')
    parser.add_argument('--inbox-dir', default='/sdcard/Download/Operit/inbox',
                        help='收件箱目录（默认: /sdcard/Download/Operit/inbox）')
    parser.add_argument('--out-dir', default='/sdcard/Download/Operit/analyzed',
                        help='分析结果输出目录（默认: /sdcard/Download/Operit/analyzed）')
    parser.add_argument('--max-apks', type=int, default=10,
                        help='最多处理APK数量（默认: 10）')
    parser.add_argument('--delete-after', action='store_true',
                        help='分析完成后删除原APK')
    args = parser.parse_args()

    # 收件箱模式
    if args.inbox:
        report = process_inbox(
            inbox_dir=args.inbox_dir,
            output_dir=args.out_dir,
            mode=args.mode,
            max_apks=args.max_apks,
            delete_after=args.delete_after,
            output_json=args.json,
        )
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            for r in report.get('results', []):
                if r.get('success'):
                    print(r.get('summary', ''))
                    print()
            print(f"📊 共处理 {report.get('processed',0)} 个APK, {report.get('errors',0)} 个失败")
        sys.exit(0)

    apk_path = args.apk
    if not apk_path:
        apk_path = auto_find_apk()
        if not apk_path:
            msg = '❌ 未找到APK文件，请上传或指定路径'
            print(json.dumps({'success': False, 'error': msg}, ensure_ascii=False) if args.json else msg)
            sys.exit(1)

    result = analyze_apk(apk_path, args.mode, output_json=args.json)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result)