"""DEX 内部类/匿名类分析 — 内部类比例/匿名类分布/Lambda/类结构复杂度"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexInnerClassAnalyzer:
    """DEX 内部类与匿名类深度分析 — 内部类层级/匿名类统计/Lambda/结构复杂度评分"""

    LAMBDA_PATTERNS = [
        'lambda', 'Lambda', '$$Lambda$', '-$$Lambda$',
        'lambda$', 'Lambda$', 'function$',
    ]

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 内部类与匿名类分布"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        if not class_defs:
            return {'error': '无类定义数据'}
        total_classes = len(class_defs)
        top_level = 0
        inner_classes = []
        anonymous_classes = []
        lambda_classes = []
        dollar_levels = Counter()
        # 类名约定: Lpackage/Outer$Inner; 或 Lpackage/Outer$1; (匿名类)
        for cd in class_defs:
            cn = cd.get('class_name', '')
            cname = cn.replace('L', '').replace(';', '').replace('/', '.')
            flags = cd.get('access_flags', '')
            # 统计 $ 层级
            dollar_count = cn.count('$')
            if dollar_count > 0:
                dollar_levels[dollar_count] += 1
                inner_classes.append(cname)
                # 匿名类: 数字后缀 (Outer$1, Outer$2)
                parts = cn.split('$')
                last = parts[-1].replace(';', '')
                if last.isdigit():
                    anonymous_classes.append(cname)
                # Lambda 类
                if any(p in cn for p in DexInnerClassAnalyzer.LAMBDA_PATTERNS):
                    lambda_classes.append(cname)
            else:
                top_level += 1
        # 从字符串中扫描 Lambda 引用
        lambda_string_refs = 0
        for s in strings:
            if not s:
                continue
            for pat in DexInnerClassAnalyzer.LAMBDA_PATTERNS:
                if pat in s:
                    lambda_string_refs += 1
                    break
        # 结构复杂度评分
        inner_ratio = round(len(inner_classes) / max(total_classes, 1) * 100, 2)
        anonymous_ratio = round(len(anonymous_classes) / max(total_classes, 1) * 100, 2)
        deep_inner = sum(v for k, v in dollar_levels.items() if k >= 3)
        score = min(100, int(
            min(inner_ratio * 2, 30) +
            min(anonymous_ratio * 3, 25) +
            min(deep_inner * 5, 20) +
            min(len(lambda_classes) * 5, 15) +
            min(lambda_string_refs * 0.5, 10)
        ))
        if score >= 60:
            complexity = '高复杂度'
        elif score >= 30:
            complexity = '中复杂度'
        else:
            complexity = '低复杂度'
        return {
            'total_classes': total_classes,
            'top_level_class_count': top_level,
            'inner_class_count': len(inner_classes),
            'inner_ratio': inner_ratio,
            'anonymous_class_count': len(anonymous_classes),
            'anonymous_ratio': anonymous_ratio,
            'lambda_class_count': len(lambda_classes),
            'lambda_string_refs': lambda_string_refs,
            'deep_inner_classes': deep_inner,
            'dollar_level_dist': dict(sorted(dollar_levels.items())),
            'complexity_score': score,
            'complexity_level': complexity,
            'inner_classes': inner_classes[:30],
            'anonymous_classes': anonymous_classes[:20],
            'lambda_classes': lambda_classes[:15],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'inner_class_count': result['inner_class_count'],
            'inner_ratio': result['inner_ratio'],
            'anonymous_class_count': result['anonymous_class_count'],
            'lambda_class_count': result['lambda_class_count'],
            'complexity_score': result['complexity_score'],
            'complexity_level': result['complexity_level'],
        }