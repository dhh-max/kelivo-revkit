#!/usr/bin/env python3
"""APK Standalone Runner - 专为 code_runner:run_python 设计
纯Python，零外部依赖，兼容第三方中转站
从同级 standalone_unpacker.py 导入，不依赖包路径

用法:
  python3 standalone_runner.py /path/to/app.apk
  python3 standalone_runner.py /path/to/app.apk --mode social
"""
import sys, os, json

_self_dir = os.path.dirname(os.path.abspath(__file__))
if _self_dir not in sys.path:
    sys.path.insert(0, _self_dir)
from standalone_unpacker import unpack_apk_standalone, _fmt_size


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
    parser.add_argument('apk', help='APK file path')
    parser.add_argument('--mode', '-m', default='quick',
                        choices=['quick', 'full', 'social', 'sdk'],
                        help='Analysis mode (default: quick)')
    parser.add_argument('--compact', '-c', action='store_true', help='Compact JSON output')
    args = parser.parse_args()
    result = analyze_apk(args.apk, args.mode)
    print(json.dumps(result, ensure_ascii=False, indent=None if args.compact else 2))