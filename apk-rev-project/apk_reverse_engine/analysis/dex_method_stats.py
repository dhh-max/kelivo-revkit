"""DEX 方法签名概览 — 参数分布/返回类型/修饰符/API面统计"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict, Counter

class DexMethodStatsAnalyzer:
    """DEX 方法签名深度分析 — 方法形态/API 面/修饰符统计"""

    # 常见 Java 方法名模式
    METHOD_PATTERNS = {
        'getter': lambda n: n.startswith('get') or n.startswith('is') or n.startswith('has'),
        'setter': lambda n: n.startswith('set'),
        'constructor': lambda n: n == '<init>' or n == '<clinit>',
        'callback': lambda n: any(k in n for k in ('onClick', 'onCreate', 'onResume', 'onPause',
                                                    'onDestroy', 'onStart', 'onStop', 'onReceive',
                                                    'onBind', 'onServiceConnected', 'callback')),
        'listener': lambda n: n.endswith('Listener') or n.endswith('Callback') or 'OnClick' in n,
        'async': lambda n: any(k in n for k in ('Async', 'async', 'Thread', 'thread', 'Runnable', 'Coroutine')),
        'network': lambda n: any(k in n for k in ('Request', 'Response', 'Http', 'http', 'Url', 'URL', 'Socket', 'Api')),
        'io': lambda n: any(k in n for k in ('read', 'write', 'open', 'close', 'flush', 'load', 'save', 'InputStream', 'OutputStream')),
        'crypto': lambda n: any(k in n for k in ('encrypt', 'decrypt', 'cipher', 'Cipher', 'hash', 'digest', 'sign', 'verify', 'AES', 'RSA', 'encode', 'decode')),
        'reflection': lambda n: any(k in n for k in ('invoke', 'getMethod', 'getField', 'getClass', 'Class.forName', 'reflect')),
        'ui': lambda n: any(k in n for k in ('View', 'Layout', 'Activity', 'Fragment', 'Adapter', 'inflate', 'setContentView')),
        'database': lambda n: any(k in n for k in ('query', 'insert', 'update', 'delete', 'Cursor', 'SQLite', 'Database', 'ContentValues')),
    }

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 方法签名形态"""
        dex_parser._ensure_parsed()
        methods = dex_parser.get_methods()
        class_defs = dex_parser.get_class_defs()

        if not methods:
            return {'error': '无可分析方法'}

        total = len(methods)

        # 参数数量分布
        param_count_dist = Counter()
        return_type_dist = Counter()
        method_name_length = []
        pattern_stats = Counter()
        modifier_stats = Counter()
        access_modifier_stats = Counter()
        param_type_dist = Counter()
        class_method_counts = Counter()

        # 收集类定义中的方法（含修饰符）
        class_methods = {}
        for cd in class_defs:
            cls = cd.get('class_name', '')
            for m in (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or []):
                name = m.get('name', '')
                flags = m.get('access_flags', '')
                class_methods.setdefault(cls, []).append({'name': name, 'flags': flags})
                # 修饰符统计
                for mod in ['public', 'private', 'protected', 'static', 'final',
                            'synchronized', 'native', 'abstract', 'constructor', 'volatile']:
                    if mod in (flags or ''):
                        modifier_stats[mod] += 1
                if 'static' in (flags or ''):
                    access_modifier_stats['static'] += 1
                if 'abstract' in (flags or ''):
                    access_modifier_stats['abstract'] += 1
                if 'native' in (flags or ''):
                    access_modifier_stats['native'] += 1
                if 'synchronized' in (flags or ''):
                    access_modifier_stats['synchronized'] += 1

        # 类-方法数分布
        for cls, ms in class_methods.items():
            class_method_counts[cls] = len(ms)

        for m in methods:
            if not isinstance(m, dict):
                continue
            name = m.get('name', '')
            proto = m.get('proto') or {}
            params = proto.get('parameters', []) if isinstance(proto, dict) else []
            ret = proto.get('return_type', '') if isinstance(proto, dict) else ''

            param_count_dist[len(params)] += 1
            if ret:
                return_type_dist[ret] += 1
            method_name_length.append(len(name or ''))

            # 参数类型分布
            for p in params:
                param_type_dist[p] += 1

            # 方法名模式
            for pat, fn in DexMethodStatsAnalyzer.METHOD_PATTERNS.items():
                if fn(name):
                    pattern_stats[pat] += 1

        # 返回类型分类
        ret_categories = {
            'void': return_type_dist.get('V', 0),
            'primitive': sum(v for k, v in return_type_dist.items() if k and len(k) == 1 and k != 'V'),
            'object': sum(v for k, v in return_type_dist.items() if k and k.startswith('L')),
            'array': sum(v for k, v in return_type_dist.items() if k and k.startswith('[')),
        }

        # Top 方法最多的类
        top_classes = [
            {'class': cls.replace('L', '').replace(';', '').replace('/', '.'), 'count': cnt}
            for cls, cnt in class_method_counts.most_common(20)
        ]

        return {
            'total_methods': total,
            'param_count_dist': dict(sorted(param_count_dist.items())),
            'avg_param_count': round(sum(k * v for k, v in param_count_dist.items()) / max(total, 1), 2),
            'return_type_categories': ret_categories,
            'top_return_types': [{'type': t, 'count': c} for t, c in return_type_dist.most_common(20)],
            'top_param_types': [{'type': t, 'count': c} for t, c in param_type_dist.most_common(20)],
            'modifier_stats': dict(modifier_stats),
            'method_patterns': dict(pattern_stats),
            'avg_method_name_len': round(sum(method_name_length) / max(len(method_name_length), 1), 2),
            'top_classes_by_methods': top_classes,
            'classes_with_most_methods': len([c for c in class_method_counts.values() if c >= 50]),
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_methods': result['total_methods'],
            'avg_params': result['avg_param_count'],
            'return_categories': result['return_type_categories'],
            'modifiers': result['modifier_stats'],
            'patterns': result['method_patterns'],
            'top5_classes': result['top_classes_by_methods'][:5],
        }