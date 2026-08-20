"""DEX 方法原型(Proto)矩阵分析 — 短签名分布/参数组合/原型复用"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict

class DexProtoMatrixAnalyzer:
    """分析 DEX proto_ids 表的短签名分布与原型复用模式"""

    # Java 类型描述符 → 人类可读
    TYPE_MAP = {
        'V': 'void', 'Z': 'boolean', 'B': 'byte', 'S': 'short',
        'C': 'char', 'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double',
    }

    @staticmethod
    def _human_type(desc):
        if not desc:
            return '?'
        if desc in DexProtoMatrixAnalyzer.TYPE_MAP:
            return DexProtoMatrixAnalyzer.TYPE_MAP[desc]
        if desc.startswith('L'):
            cls = desc[1:-1].replace('/', '.')
            # 简化：只取类名最后一段
            parts = cls.rsplit('.', 1)
            return parts[-1] if parts else cls
        if desc.startswith('['):
            inner = desc.lstrip('[')
            depth = len(desc) - len(inner)
            if inner in DexProtoMatrixAnalyzer.TYPE_MAP:
                return DexProtoMatrixAnalyzer.TYPE_MAP[inner] + '[]' * depth
            if inner.startswith('L'):
                cls = inner[1:-1].replace('/', '.')
                parts = cls.rsplit('.', 1)
                return (parts[-1] if parts else cls) + '[]' * depth
            return desc
        return desc

    @staticmethod
    def analyze(dex_parser):
        dex_parser._ensure_parsed()
        protos = dex_parser.get_protos()
        methods = dex_parser.get_methods()

        if not protos:
            return {'error': '无可分析 proto'}

        total_protos = len(protos)
        shorty_dist = Counter()
        param_count_dist = Counter()
        return_type_dist = Counter()
        param_type_combos = Counter()
        proto_reuse = Counter()  # proto → 使用次数
        no_param_count = 0
        single_param_count = 0
        multi_param_count = 0

        # 短签名 → 人类可读签名
        signature_dist = Counter()

        for p in protos:
            shorty = p.get('shorty', '')
            ret = p.get('return_type', '')
            params = p.get('parameters', [])
            param_count = len(params)

            shorty_dist[shorty] += 1
            param_count_dist[param_count] += 1
            return_type_dist[ret] += 1

            if param_count == 0:
                no_param_count += 1
            elif param_count == 1:
                single_param_count += 1
            else:
                multi_param_count += 1

            # 人类可读签名
            ret_h = DexProtoMatrixAnalyzer._human_type(ret)
            param_h = [DexProtoMatrixAnalyzer._human_type(p) for p in params]
            sig = f"{ret_h}({', '.join(param_h)})"
            signature_dist[sig] += 1

            # 参数类型组合
            if params:
                combo = '|'.join(sorted(params))
                param_type_combos[combo] += 1

        # 统计 proto 被方法引用的次数
        for m in methods:
            pi = m.get('proto_idx', -1)
            if 0 <= pi < total_protos:
                proto_reuse[pi] += 1

        # 原型复用统计
        reuse_dist = Counter()
        for cnt in proto_reuse.values():
            if cnt == 1: reuse_dist['unique'] += 1
            elif cnt <= 3: reuse_dist['low_reuse'] += 1
            elif cnt <= 10: reuse_dist['medium_reuse'] += 1
            elif cnt <= 50: reuse_dist['high_reuse'] += 1
            else: reuse_dist['very_high_reuse'] += 1

        # 最大参数数
        max_params = max(param_count_dist.keys()) if param_count_dist else 0

        return {
            'total_protos': total_protos,
            'shorty_distribution': dict(shorty_dist.most_common(20)),
            'param_count_dist': dict(sorted(param_count_dist.items())),
            'no_param_count': no_param_count,
            'single_param_count': single_param_count,
            'multi_param_count': multi_param_count,
            'max_param_count': max_params,
            'return_type_dist': [
                {'type': t, 'human': DexProtoMatrixAnalyzer._human_type(t), 'count': c}
                for t, c in return_type_dist.most_common(20)
            ],
            'top_signatures': [
                {'signature': s, 'count': c}
                for s, c in signature_dist.most_common(30)
            ],
            'top_param_combos': [
                {'combo': k, 'count': v}
                for k, v in param_type_combos.most_common(15)
            ],
            'proto_reuse_dist': dict(reuse_dist),
            'proto_per_method_ratio': round(total_protos / max(len(methods), 1), 3),
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_protos': result['total_protos'],
            'no_param_pct': round(result['no_param_count'] / max(result['total_protos'], 1) * 100, 1),
            'multi_param_pct': round(result['multi_param_count'] / max(result['total_protos'], 1) * 100, 1),
            'max_params': result['max_param_count'],
            'reuse_dist': result['proto_reuse_dist'],
            'top5_signatures': result['top_signatures'][:5],
        }
