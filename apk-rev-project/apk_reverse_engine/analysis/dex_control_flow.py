"""DEX 控制流分析 — 方法复杂度分布/大方法检测/热点类/控制流评分"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexControlFlowAnalyzer:
    """DEX 控制流特征分析 — 方法大小分布/复杂度热点"""

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 控制流特征"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        if not class_defs:
            return {'error': '无类定义数据'}
        total_methods = 0
        methods_with_code = 0
        total_insns = 0
        insn_dist = Counter()
        insns_per_class = defaultdict(int)
        methods_per_class = Counter()
        large_methods = []
        boxes = [(0, 5, '微型(0-5)'), (6, 20, '小型(6-20)'), (21, 60, '中型(21-60)'),
                 (61, 150, '大型(61-150)'), (151, 400, '巨型(151-400)'), (401, 10**9, '超大(>400)')]
        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            for m in all_methods:
                total_methods += 1
                methods_per_class[cls_name] += 1
                code = m.get('code')
                if not code or isinstance(code, dict) and 'error' in code:
                    continue
                methods_with_code += 1
                insns = code.get('insns_size', 0)
                total_insns += insns
                insns_per_class[cls_name] += insns
                for lo, hi, label in boxes:
                    if lo <= insns <= hi:
                        insn_dist[label] += 1
                        break
                if insns >= 150:
                    large_methods.append({
                        'class': cls_name,
                        'method': m.get('name', '?'),
                        'insns': insns,
                        'regs': code.get('registers_size', 0),
                    })
        avg_insns = round(total_insns / max(methods_with_code, 1), 2)
        large_ratio = len(large_methods) / max(methods_with_code, 1)
        complexity_score = min(100, int(min(avg_insns * 0.8, 50) + min(large_ratio * 200, 50)))
        class_hotspots = sorted(
            [(k.replace('L', '').replace(';', '').replace('/', '.'), insns_per_class[k], methods_per_class[k])
             for k in insns_per_class],
            key=lambda x: x[1], reverse=True
        )[:20]
        large_methods.sort(key=lambda x: x['insns'], reverse=True)
        return {
            'total_methods': total_methods,
            'methods_with_code': methods_with_code,
            'total_insns': total_insns,
            'avg_insns_per_method': avg_insns,
            'complexity_score': complexity_score,
            'insn_distribution': dict(insn_dist),
            'large_method_count': len(large_methods),
            'large_method_ratio': round(large_ratio * 100, 2),
            'top_large_methods': large_methods[:20],
            'top_class_hotspots': [{'class': c, 'insns': i, 'methods': tm} for c, i, tm in class_hotspots],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_insns': result['total_insns'],
            'avg_insns_per_method': result['avg_insns_per_method'],
            'complexity_score': result['complexity_score'],
            'large_method_count': result['large_method_count'],
            'top3_hotspots': result['top_class_hotspots'][:3],
        }