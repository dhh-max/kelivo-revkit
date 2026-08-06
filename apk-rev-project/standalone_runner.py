#!/usr/bin/env python3
"""APK Standalone Runner - 专为 code_runner:run_python 设计
纯Python，零外部依赖，兼容第三方中转站

用法（通过 code_runner 执行）:
  python3 standalone_runner.py /path/to/app.apk
  python3 standalone_runner.py /path/to/app.apk --mode social
  python3 standalone_runner.py /path/to/app.apk --mode sdk

或者作为模块导入:
  import sys; sys.path.insert(0, '.')
  from standalone_runner import analyze_apk
  result = analyze_apk('/path/to/app.apk')
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from apk_reverse_engine.tools.standalone_unpacker import unpack_apk_standalone


def analyze_apk(apk_path, mode='quick'):
    """一站式APK分析入口
    
    Args:
        apk_path: APK文件路径
        mode: 'quick'|'full'|'social'|'sdk'
    
    Returns:
        dict: 分析结果
    """
    result = unpack_apk_standalone(apk_path)
    if not result.get('success'):
        return result

    summary = {
        'success': True,
        'apk': os.path.basename(apk_path),
        'package': result.get('manifest', {}).get('package', ''),
        'size': result.get('structure', {}).get('size', 0),
        'size_human': _fmt_size(result.get('structure', {}).get('size', 0)),
        'dex_count': result.get('structure', {}).get('dex_count', 0),
        'so_count': result.get('structure', {}).get('so_count', 0),
        'total_files': result.get('structure', {}).get('total_files', 0),
        'total_classes': result.get('total_classes', 0),
        'total_strings': result.get('total_strings', 0),
        'obfuscation_level': result.get('obfuscation', {}).get('level', ''),
        'obfuscation_score': result.get('obfuscation', {}).get('score', 0),
        'packers': result.get('packers', []),
        'signature_v1': result.get('signature', {}).get('v1_valid', False),
        'abis': result.get('abis', []),
        'dangerous_permissions': result.get('dangerous_permissions', []),
        'security_issues': result.get('security_issues', []),
        'permission_count': result.get('permission_count', 0),
    }

    # 读取所有DEX字符串用于分析
    all_strings = []
    for d_info in result.get('dex', {}).values():
        if isinstance(d_info, dict) and 'error' not in d_info:
            pass  # 字符串已包含在 findinds 中
    all_strings = list(result.get('findings', {}).get('urls', [])) + \
                  list(result.get('findings', {}).get('potential_keys', []))

    if mode in ('social', 'full'):
        summary['social_login'] = _detect_social_login(result)

    if mode in ('sdk', 'full'):
        summary['sdk_detected'] = _detect_sdks(result)

    if mode == 'full':
        summary['findings'] = result.get('findings', {})
        summary['size_by_category'] = result.get('size_by_category', {})

    summary['manifest'] = {
        'package': result.get('manifest', {}).get('package', ''),
        'sdk': result.get('manifest', {}).get('sdk', {}),
        'permissions_count': len(result.get('manifest', {}).get('permissions', [])),
        'activities_count': len(result.get('manifest', {}).get('activities', [])),
        'services_count': len(result.get('manifest', {}).get('services', [])),
    }
    return summary


def _fmt_size(s):
    for u in ('B','KB','MB','GB'): 
        if s < 1024: return f"{s:.1f}{u}"
        s /= 1024
    return f"{s:.1f}TB"


def _get_all_text(result):
    """从结果中提取所有文本用于模式匹配"""
    texts = []
    for d_info in result.get('dex', {}).values():
        if isinstance(d_info, dict) and 'error' not in d_info:
            pass
    texts.append(str(result.get('findings', {})))
    texts.append(str(result.get('packers', [])))
    return ' '.join(texts)


def _detect_social_login(result):
    """内置社交登录检测 - 从类名和字符串中检测"""
    # 从standalone_unpacker结果中无法直接获取类名和字符串
    # 需要重新读取DEX, 简化为基于已有信息的检测
    findings = result.get('findings', {})
    packers = result.get('packers', [])
    manifest = result.get('manifest', {})
    
    text = ' '.join(findings.get('urls', [])) + ' '
    text += ' '.join(findings.get('potential_keys', [])) + ' '
    text += ' '.join(packers) + ' '
    text += str(manifest)
    text = text.lower()

    platforms = {
        'wechat': {
            'name': '微信登录', 'icon': '💬', 'risk': '中',
            'patterns': ['wx[a-z0-9]{16}', 'wechat', 'weixin', 'com.tencent.mm', 'wxapi'],
        },
        'qq': {
            'name': 'QQ登录', 'icon': '🐧', 'risk': '中',
            'patterns': ['tencent', 'qq_login', 'connect.qq', 'mqqapi', 'qzone'],
        },
        'github': {
            'name': 'GitHub登录', 'icon': '🐙', 'risk': '低',
            'patterns': ['github', 'client_id', 'ghp_', 'octokit', 'oauth'],
        },
        'alipay': {
            'name': '支付宝登录', 'icon': '💳', 'risk': '中',
            'patterns': ['alipay', 'alipaysdk', 'alipaysec', 'auth_code'],
        },
        'weibo': {
            'name': '微博登录', 'icon': '📱', 'risk': '中',
            'patterns': ['weibo', 'sina', 'ssohandler'],
        },
        'google': {
            'name': 'Google登录', 'icon': '🔵', 'risk': '低',
            'patterns': ['google.signin', 'firebase.auth', 'gms.auth', 'googlelogin'],
        },
        'facebook': {
            'name': 'Facebook登录', 'icon': '👍', 'risk': '中',
            'patterns': ['facebook', 'fb_login', 'loginbutton'],
        },
        'apple': {
            'name': 'Apple登录', 'icon': '🍎', 'risk': '低',
            'patterns': ['apple', 'signinwithapple', 'apple_id'],
        },
        'twitter': {
            'name': 'Twitter登录', 'icon': '🐦', 'risk': '低',
            'patterns': ['twitter', 'fabric', 't.co'],
        },
        'douyin': {
            'name': '抖音登录', 'icon': '🎵', 'risk': '中',
            'patterns': ['douyin', 'bytedance', 'aweme', 'pangle'],
        },
        'dingtalk': {
            'name': '钉钉登录', 'icon': '🔷', 'risk': '中',
            'patterns': ['dingtalk', 'com.alibaba.dingtalk'],
        },
        'huawei': {
            'name': '华为登录', 'icon': '🌺', 'risk': '低',
            'patterns': ['huawei.hms', 'huawei.agconnect', 'huaweiid'],
        },
        'xiaomi': {
            'name': '小米登录', 'icon': '📱', 'risk': '低',
            'patterns': ['xiaomi.account', 'xiaomi.passport', 'milogin'],
        },
        'linkedin': {
            'name': 'LinkedIn登录', 'icon': '💼', 'risk': '低',
            'patterns': ['linkedin', 'org.linkedin'],
        },
        'line': {
            'name': 'Line登录', 'icon': '💚', 'risk': '低',
            'patterns': ['line.sdk', 'jp.line', 'linelogin'],
        },
    }

    detected = []
    for key, info in platforms.items():
        score = 0
        matched = []
        for p in info['patterns']:
            if re.search(p, text, re.I):
                score += 20
                matched.append(p)
        if score > 0:
            weight = 1.5 if info['risk'] == '高' else 1.2 if info['risk'] == '中' else 1.0
            detected.append({
                'key': key,
                'name': info['name'],
                'icon': info['icon'],
                'risk': info['risk'],
                'confidence': min(score, 100),
                'score': round(min(score, 100) * weight / 100 * 25, 1),
                'matched_patterns': matched[:5],
            })

    detected.sort(key=lambda x: -x['confidence'])
    total_score = sum(d['score'] for d in detected)
    
    return {
        'platforms': detected,
        'total': len(detected),
        'total_score': round(min(total_score, 100), 1),
        'level': '密集集成' if total_score >= 60 else '多平台集成' if total_score >= 30 else '少量集成' if total_score >= 10 else '无',
    }


def _detect_sdks(result):
    """内置SDK检测"""
    packers = result.get('packers', [])
    manifest = result.get('manifest', {})
    perms = [p.split('.')[-1] for p in manifest.get('permissions', [])]
    
    return {
        'packers': packers,
        'permission_count': len(perms),
        'dangerous_permissions': result.get('dangerous_permissions', []),
        'note': '完整SDK检测需读取DEX类名，请使用 reng sdk --standalone',
    }


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