"""DEX 字符串常量池深度分析 — 字符串引用追踪/字符串加密检测/常量模式"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict, Counter
import re

class DexStringPoolAnalyzer:
    """DEX 字符串常量池深度分析引擎"""

    # 敏感字符串模式
    SENSITIVE_PATTERNS = {
        'url': re.compile(r'https?://[^\s"\'<>]+', re.I),
        'ip': re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b'),
        'email': re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'),
        'phone': re.compile(r'1[3-9]\d{9}'),
        'jwt': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        'base64_long': re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
        'hex_long': re.compile(r'[0-9a-fA-F]{32,}'),
        'uuid': re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
        'package': re.compile(r'[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}'),
        'java_class': re.compile(r'L[a-z][a-z0-9_]*/[A-Za-z][A-Za-z0-9_]*;'),
        'json_fragment': re.compile(r'\{["\w]+:'),
        'xml_fragment': re.compile(r'<[a-zA-Z][a-zA-Z0-9]*[\s>]'),
        'sql': re.compile(r'(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\s', re.I),
        'regex': re.compile(r'^[\^\$\.\*\+\?\(\)\[\]\{\}\|\\]+$'),
        'file_path': re.compile(r'(/[a-zA-Z][a-zA-Z0-9_./-]+)+'),
        'android_permission': re.compile(r'android\.permission\.\w+'),
        'content_provider': re.compile(r'content://[\w./]+'),
        'intent_action': re.compile(r'(android\.intent\.action\.[A-Z_]+|com\.[a-z]+\.[a-z]+\.[A-Z_]+)'),
    }

    # 常见加密/混淆特征
    OBFUSCATION_PATTERNS = {
        'random_looking': re.compile(r'^[a-zA-Z0-9]{8,}$'),  # 无规律的长字符串
        'unicode_escape': re.compile(r'\\u[0-9a-fA-F]{4}'),
        'html_entity': re.compile(r'&#\d+;'),
        'rot13_hint': re.compile(r'[A-Za-z]{20,}'),  # 可能的ROT13
    }

    @staticmethod
    def analyze(dex_parser):
        """深度分析 DEX 字符串常量池"""
        dex_parser._ensure_parsed()
        strings = dex_parser.get_strings()

        if not strings:
            return {'error': '无可分析字符串'}

        total_count = len(strings)
        total_bytes = sum(len(s) for s in strings)

        # 分类统计
        category_stats = defaultdict(list)
        sensitive_findings = []

        for idx, s in enumerate(strings):
            if not s or len(s) < 2:
                continue

            matched = False
            for cat, pattern in DexStringPoolAnalyzer.SENSITIVE_PATTERNS.items():
                matches = pattern.findall(s)
                if matches:
                    matched = True
                    for m in matches:
                        category_stats[cat].append({
                            'string_idx': idx,
                            'value': m if len(m) < 200 else m[:200] + '...',
                            'full_string': s if len(s) < 300 else s[:300] + '...',
                        })

            if not matched:
                # 检查是否像类名/方法名
                if '/' in s and s.startswith('L') and s.endswith(';'):
                    category_stats['dex_type_descriptor'].append({'string_idx': idx, 'value': s[:200]})
                elif '.' in s and not s[0].isdigit() and not '/' in s:
                    if len(s) < 150:
                        category_stats['package_or_class'].append({'string_idx': idx, 'value': s[:200]})

        # 字符串长度分布
        length_buckets = {'1-10': 0, '11-30': 0, '31-50': 0, '51-100': 0, '101-200': 0, '200+': 0}
        for s in strings:
            l = len(s)
            if l <= 10: length_buckets['1-10'] += 1
            elif l <= 30: length_buckets['11-30'] += 1
            elif l <= 50: length_buckets['31-50'] += 1
            elif l <= 100: length_buckets['51-100'] += 1
            elif l <= 200: length_buckets['101-200'] += 1
            else: length_buckets['200+'] += 1

        # 字符集分析
        has_chinese = sum(1 for s in strings if any('\u4e00' <= c <= '\u9fff' for c in s))
        has_emoji = sum(1 for s in strings if any(ord(c) > 0x1F000 for c in s))
        has_base64 = sum(1 for s in strings if len(s) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', s))

        # 最长字符串
        longest = sorted(enumerate(strings), key=lambda x: len(x[1]), reverse=True)[:10]
        longest_strings = [{'idx': i, 'length': len(s), 'preview': s[:150] + ('...' if len(s) > 150 else '')} for i, s in longest]

        # 重复字符串检测
        string_counter = Counter(s for s in strings if len(s) > 5)
        duplicates = [(s, c) for s, c in string_counter.most_common(30) if c > 1]

        # 加密特征检测
        encrypted_candidates = []
        for idx, s in enumerate(strings):
            if len(s) > 16 and s.isprintable():
                # 高熵字符串（随机分布）
                char_freq = Counter(s)
                unique_ratio = len(char_freq) / len(s)
                if unique_ratio > 0.7 and len(s) > 20:
                    encrypted_candidates.append({
                        'idx': idx,
                        'length': len(s),
                        'unique_ratio': round(unique_ratio, 3),
                        'preview': s[:100] + ('...' if len(s) > 100 else ''),
                    })

        # 短摘要
        category_summary = {cat: len(items) for cat, items in category_stats.items()}

        return {
            'total_strings': total_count,
            'total_bytes': total_bytes,
            'avg_length': round(total_bytes / max(total_count, 1), 2),
            'length_distribution': length_buckets,
            'chinese_strings': has_chinese,
            'emoji_strings': has_emoji,
            'base64_candidates': has_base64,
            'category_summary': category_summary,
            'category_details': {
                cat: {'count': len(items), 'samples': items[:20]}
                for cat, items in sorted(category_stats.items(), key=lambda x: len(x[1]), reverse=True)
            },
            'longest_strings': longest_strings,
            'duplicate_strings': [{'value': s[:100], 'count': c} for s, c in duplicates[:20]],
            'encrypted_candidates': encrypted_candidates[:30],
            'encrypted_count': len(encrypted_candidates),
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_strings': result['total_strings'],
            'total_bytes': result['total_bytes'],
            'avg_length': result['avg_length'],
            'categories': result['category_summary'],
            'chinese_strings': result['chinese_strings'],
            'encrypted_candidates': result['encrypted_count'],
            'duplicates': len(result['duplicate_strings']),
        }