"""DEX 方法原型/签名分析 — 参数类型分布/返回类型/重载/SDK兼容性/API签名复杂度"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexProtoAnalyzer:
    """DEX 方法原型与签名深度分析 — 参数/返回类型分布/重载/API 签名复杂度评分"""

    # DEX 类型描述符 -> 可读名
    PRIM_MAP = {
        'V': 'void', 'Z': 'boolean', 'B': 'byte', 'S': 'short',
        'C': 'char', 'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double',
    }

    @staticmethod
    def _type_readable(desc):
        """将 DEX 类型描述符转为可读形式"""
        if not desc:
            return '?'
        if desc in DexProtoAnalyzer.PRIM_MAP:
            return DexProtoAnalyzer.PRIM_MAP[desc]
        if desc.startswith('L') and desc.endswith(';'):
            return desc[1:-1].replace('/', '.')
        if desc.startswith('['):
            return DexProtoAnalyzer._type_readable(desc[1:]) + '[]'
        return desc

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 方法原型分布"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        protos = dex_parser.get_protos()
        if not class_defs:
            return {'error': '无类定义数据'}
        total_methods = 0
        param_type_counter = Counter()   # 参数类型（分类）
        return_type_counter = Counter()  # 返回类型
        param_count_dist = Counter()     # 参数个数分布
        overloads = Counter()            # 类内方法名 -> 重载次数
        method_name_counter = Counter()  # 全局方法名频率
        # 收集所有方法
        all_methods = []
        for cd in class_defs:
            cls = cd.get('class_name', '')
            for m in (cd.get('direct_methods', []) + cd.get('virtual_methods', [])):
                total_methods += 1
                name = m.get('name', '?')
                method_name_counter[name] += 1
                proto = m.get('proto') or {}
                if isinstance(proto, dict):
                    ret = proto.get('return_type', '')
                    params = proto.get('parameters', []) or []
                    return_type_counter[DexProtoAnalyzer._type_readable(ret)] += 1
                    param_count_dist[len(params)] += 1
                    for p in params:
                        param_type_counter[DexProtoAnalyzer._type_readable(p)] += 1
                all_methods.append((cls, name))
        # 统计重载（同名方法在同一类中）
        cls_method_names = defaultdict(Counter)
        for cls, name in all_methods:
            cls_method_names[cls][name] += 1
        for cls, cnt in cls_method_names.items():
            for name, c in cnt.items():
                if c > 1:
                    overloads[name] += 1
        # 参数类型分类
        param_categories = Counter()
        for ptype, cnt in param_type_counter.items():
            if any(k in ptype for k in ['String', 'int', 'long', 'boolean', 'Object']):
                param_categories['基础/常用'] += cnt
            elif '.List' in ptype or '.ArrayList' in ptype or '.Map' in ptype or '.Set' in ptype or '[]' in ptype:
                param_categories['集合/数组'] += cnt
            elif '.Context' in ptype or '.Activity' in ptype or '.Fragment' in ptype or '.View' in ptype:
                param_categories['Android组件'] += cnt
            elif '.Callback' in ptype or '.Listener' in ptype or '.Handler' in ptype:
                param_categories['回调/监听'] += cnt
            else:
                param_categories['自定义/其他'] += cnt
        # API 签名复杂度评分
        avg_params = sum(k * v for k, v in param_count_dist.items()) / max(total_methods, 1)
        overload_count = sum(overloads.values())
        complex_param = sum(v for k, v in param_count_dist.items() if k >= 5)
        score = min(100, int(
            min(avg_params * 15, 35) +
            min(overload_count * 2, 30) +
            min(complex_param * 3, 25) +
            min(len(param_type_counter) * 0.2, 10)
        ))
        if score >= 60:
            complexity = '高复杂度'
        elif score >= 30:
            complexity = '中复杂度'
        else:
            complexity = '低复杂度'
        return {
            'total_methods': total_methods,
            'total_protos': len(protos),
            'avg_params_per_method': round(avg_params, 2),
            'param_count_dist': dict(sorted(param_count_dist.items())),
            'top_return_types': [{'type': t, 'count': c} for t, c in return_type_counter.most_common(15)],
            'top_param_types': [{'type': t, 'count': c} for t, c in param_type_counter.most_common(20)],
            'param_categories': dict(param_categories.most_common()),
            'overload_count': overload_count,
            'top_overloads': [{'method': name, 'classes': c} for name, c in overloads.most_common(15)],
            'top_method_names': [{'method': name, 'count': c} for name, c in method_name_counter.most_common(15)],
            'complexity_score': score,
            'complexity_level': complexity,
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_methods': result['total_methods'],
            'avg_params_per_method': result['avg_params_per_method'],
            'overload_count': result['overload_count'],
            'complexity_score': result['complexity_score'],
            'complexity_level': result['complexity_level'],
        }