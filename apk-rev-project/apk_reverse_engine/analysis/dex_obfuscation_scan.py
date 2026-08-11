"""DEX 混淆特征扫描 — 类名混淆/字符串加密/方法名混淆/混淆强度评估"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict
import re


class DexObfuscationScan:
    """DEX 混淆特征扫描 — 识别代码混淆/加固/加密迹象"""

    OBFUSCATED_PATTERNS = [
        (re.compile(r'^L[a-zA-Z]+/[a-zA-Z]+/[a-zA-Z];$'), '短混淆类名'),
        (re.compile(r'^L[a-z]+/[a-z]+/[a-z]+/[a-z]+/[a-z];$'), '深混淆包'),
        (re.compile(r'^L[a-z]+/[a-z]+/[a-z]+;.*[a-z]{1,2}$'), '缩写混淆'),
    ]
    STRING_ENCRYPT_PATTERNS = [
        'encrypt', 'decrypt', 'cipher', 'AES', 'DESede', 'RSA',
        'base64', 'decode', 'encode', 'XOR', 'xor_str', 'decoded',
        'StringEncrypt', 'EncryptUtil', 'JadxString', 'obfuscate',
    ]
    PACKER_PATTERNS = [
        'libjiagu', 'libDexHelper', 'libprotectClass', 'com/secneo/apkwrapper',
        'com/qihoo', 'com/stub', 'com/shell', 'bangcle', 'ijiami',
        'libshell', 'libshella', 'com/tencent/stub', 'libnesec', 'gnustl',
        'com/qq/e', 'com/baidu/protect', 'net/youmi', 'jiagu',
    ]

    @staticmethod
    def analyze(dex_parser):
        """扫描 DEX 混淆与加固特征"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        if not class_defs:
            return {'error': '无类定义数据'}
        class_names = [cd.get('class_name', '') for cd in class_defs]
        method_names = []
        for cd in class_defs:
            for m in ((cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])):
                method_names.append(m.get('name', ''))
        obfuscated_classes = []
        single_letter_methods = 0
        short_class_count = 0
        for cn in class_names:
            if not cn:
                continue
            for pat, desc in DexObfuscationScan.OBFUSCATED_PATTERNS:
                if pat.match(cn):
                    obfuscated_classes.append({'class': cn, 'reason': desc})
                    short_class_count += 1
                    break
        single_letter_pat = re.compile(r'^[a-z]$')
        for mn in method_names:
            if single_letter_pat.match(mn):
                single_letter_methods += 1
        enc_strings = Counter()
        for s in strings:
            if not s:
                continue
            for pat in DexObfuscationScan.STRING_ENCRYPT_PATTERNS:
                if pat.lower() in s.lower():
                    enc_strings[pat] += 1
        packer_hits = Counter()
        for s in strings:
            if not s:
                continue
            for pat in DexObfuscationScan.PACKER_PATTERNS:
                if pat in s:
                    packer_hits[pat] += 1
        obfuscation_score = 0
        obfuscation_score += min(short_class_count * 3, 40)
        obfuscation_score += min(single_letter_methods * 2, 30)
        obfuscation_score += min(len(enc_strings) * 5, 20)
        obfuscation_score += min(len(packer_hits) * 10, 30)
        obfuscation_score = min(100, obfuscation_score)
        if obfuscation_score >= 70:
            level = '严重混淆'
        elif obfuscation_score >= 40:
            level = '高度混淆'
        elif obfuscation_score >= 20:
            level = '中度混淆'
        elif obfuscation_score > 0:
            level = '轻度混淆'
        else:
            level = '未混淆'
        return {
            'total_classes': len(class_names),
            'total_methods': len(method_names),
            'obfuscated_class_count': len(obfuscated_classes),
            'obfuscation_rate': round(len(obfuscated_classes) / max(len(class_names), 1) * 100, 1),
            'single_letter_methods': single_letter_methods,
            'obfuscation_score': obfuscation_score,
            'obfuscation_level': level,
            'encrypt_string_patterns': [{'pattern': p, 'count': c} for p, c in enc_strings.most_common(15)],
            'packer_detected': [{'pattern': p, 'count': c} for p, c in packer_hits.most_common(10)],
            'packer_count': len(packer_hits),
            'sample_obfuscated_classes': obfuscated_classes[:20],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'obfuscation_level': result['obfuscation_level'],
            'obfuscation_score': result['obfuscation_score'],
            'obfuscated_class_count': result['obfuscated_class_count'],
            'obfuscation_rate': result['obfuscation_rate'],
            'packer_count': result['packer_count'],
            'top3_packers': result['packer_detected'][:3],
        }