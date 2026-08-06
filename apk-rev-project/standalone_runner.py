#!/usr/bin/env python3
"""APK Standalone Runner - 专为 code_runner:run_python 设计
纯Python，零外部依赖，兼容第三方中转站
从同级 standalone_unpacker.py 导入，不依赖包路径

用法:
  python3 standalone_runner.py                          # 自动查找最新上传的APK
  python3 standalone_runner.py /path/to/app.apk         # 指定路径
  python3 standalone_runner.py --mode social            # 自动查找+社交登录检测
"""
import sys, os, json, glob

_self_dir = os.path.dirname(os.path.abspath(__file__))
if _self_dir not in sys.path:
    sys.path.insert(0, _self_dir)
from standalone_unpacker import unpack_apk_standalone, _fmt_size


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
        # 再广撒网搜一遍（限制深度防卡死）
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
    # 按修改时间排序，取最新的
    candidates.sort(key=lambda x: -x[0])
    return candidates[0][1]


def analyze_apk(apk_path, mode='quick'):
    """一站式APK分析入口"""
    r = unpack_apk_standalone(apk_path)
    if not r.get('success'):
        return r
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
        'total_strings': r.get('total_strings', 0),
        'obfuscation_level': r.get('obfuscation', {}).get('level', ''),
        'obfuscation_score': r.get('obfuscation', {}).get('score', 0),
        'packers': r.get('packers', []),
        'signature_v1': r.get('signature', {}).get('v1_valid', False),
        'abis': r.get('abis', []),
        'dangerous_permissions': r.get('dangerous_permissions', []),
        'security_issues': r.get('security_issues', []),
        'permission_count': r.get('permission_count', 0),
        'manifest': {
            'package': r.get('manifest', {}).get('package', ''),
            'sdk': r.get('manifest', {}).get('sdk', {}),
            'permissions_count': len(r.get('manifest', {}).get('permissions', [])),
            'activities_count': len(r.get('manifest', {}).get('activities', [])),
            'services_count': len(r.get('manifest', {}).get('services', [])),
        },
    }
    if mode in ('social', 'full'):
        summary['social_login'] = r.get('social_login', {})
    if mode in ('sdk', 'full'):
        summary['sdk_detected'] = r.get('sdk_detected', {})
    if mode == 'full':
        summary['findings'] = r.get('findings', {})
        summary['size_by_category'] = r.get('size_by_category', {})
    return summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='APK Standalone Analyzer')
    parser.add_argument('apk', nargs='?', default=None, help='APK file path (留空则自动查找最新上传的APK)')
    parser.add_argument('--mode', '-m', default='quick',
                        choices=['quick', 'full', 'social', 'sdk'],
                        help='Analysis mode (default: quick)')
    parser.add_argument('--compact', '-c', action='store_true', help='Compact JSON output')
    args = parser.parse_args()

    apk_path = args.apk
    if not apk_path:
        apk_path = auto_find_apk()
        if not apk_path:
            print(json.dumps({'success': False, 'error': '未找到APK文件，请上传或指定路径'}, ensure_ascii=False))
            sys.exit(1)

    result = analyze_apk(apk_path, args.mode)
    print(json.dumps(result, ensure_ascii=False, indent=None if args.compact else 2))