"""DEX 异常处理流分析 — try/catch分布/异常类型/捕获模式/防御性编程评估"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict

class DexExceptionFlowAnalyzer:
    """DEX 异常处理深度分析 — try/catch 块统计/异常类型分布/防御性编程评分"""

    KNOWN_EXCEPTIONS = {
        'Ljava/lang/NullPointerException;': 'NullPointerException',
        'Ljava/lang/ClassCastException;': 'ClassCastException',
        'Ljava/lang/IndexOutOfBoundsException;': 'IndexOutOfBoundsException',
        'Ljava/lang/ArrayIndexOutOfBoundsException;': 'ArrayIndexOutOfBoundsException',
        'Ljava/lang/StringIndexOutOfBoundsException;': 'StringIndexOutOfBoundsException',
        'Ljava/lang/NumberFormatException;': 'NumberFormatException',
        'Ljava/lang/IllegalArgumentException;': 'IllegalArgumentException',
        'Ljava/lang/IllegalStateException;': 'IllegalStateException',
        'Ljava/lang/ArithmeticException;': 'ArithmeticException',
        'Ljava/lang/SecurityException;': 'SecurityException',
        'Ljava/lang/UnsupportedOperationException;': 'UnsupportedOperationException',
        'Ljava/lang/IOException;': 'IOException',
        'Ljava/lang/FileNotFoundException;': 'FileNotFoundException',
        'Ljava/lang/RuntimeException;': 'RuntimeException',
        'Ljava/lang/Exception;': 'Exception',
        'Ljava/lang/Throwable;': 'Throwable',
        'Ljava/lang/Error;': 'Error',
        'Ljava/lang/OutOfMemoryError;': 'OutOfMemoryError',
        'Ljava/lang/ClassNotFoundException;': 'ClassNotFoundException',
        'Ljava/lang/InterruptedException;': 'InterruptedException',
        'Ljava/net/SocketTimeoutException;': 'SocketTimeoutException',
        'Ljava/net/UnknownHostException;': 'UnknownHostException',
        'Ljava/sql/SQLException;': 'SQLException',
        'Lorg/json/JSONException;': 'JSONException',
        'Lorg/xmlpull/v1/XmlPullParserException;': 'XmlPullParserException',
    }

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 异常处理模式"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()

        if not class_defs:
            return {'error': '无类定义数据'}

        total_methods = 0
        methods_with_code = 0
        methods_with_try = 0
        total_try_blocks = 0
        total_handlers = 0
        exception_types = Counter()
        try_per_method_dist = Counter()
        class_try_stats = defaultdict(lambda: {'try_blocks': 0, 'methods_with_try': 0, 'total_methods': 0})
        methods_with_many_tries = []

        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            cs = class_try_stats[cls_name]
            for m in all_methods:
                total_methods += 1
                cs['total_methods'] += 1
                code = m.get('code')
                if not code or isinstance(code, dict) and 'error' in code:
                    continue
                methods_with_code += 1

                tries_size = code.get('tries_size', 0)
                tries = code.get('tries', [])
                handlers = code.get('handlers', {})

                if tries_size > 0 or tries:
                    methods_with_try += 1
                    cs['methods_with_try'] += 1
                    total_try_blocks += tries_size
                    cs['try_blocks'] += tries_size

                    handler_count = handlers.get('count', 0) if isinstance(handlers, dict) else 0
                    total_handlers += handler_count
                    try_per_method_dist[tries_size] += 1

                    method_name = m.get('name', '?')
                    proto = m.get('proto') or {}
                    ret = proto.get('return_type', '') if isinstance(proto, dict) else ''
                    params = proto.get('parameters', []) if isinstance(proto, dict) else []
                    sig = f"{method_name}({','.join(params)}){ret}"

                    entry = {
                        'class': cls_name,
                        'method': method_name,
                        'signature': sig,
                        'try_blocks': tries_size,
                        'handlers': handler_count,
                        'insns': code.get('insns_size', 0),
                    }
                    if tries_size >= 3:
                        methods_with_many_tries.append(entry)

        for s in strings:
            if not s:
                continue
            for desc, name in DexExceptionFlowAnalyzer.KNOWN_EXCEPTIONS.items():
                clean = desc.replace(';', '')
                if clean in s or name in s:
                    exception_types[name] += 1

        if methods_with_code > 0:
            try_ratio = methods_with_try / methods_with_code
            avg_tries = total_try_blocks / methods_with_code
            score = min(100, int(try_ratio * 50 + min(avg_tries * 20, 30) + min(len(exception_types) * 2, 20)))
        else:
            score = 0

        class_top = sorted(
            [(k.replace('L', '').replace(';', '').replace('/', '.'), v) for k, v in class_try_stats.items() if v['try_blocks'] > 0],
            key=lambda x: x[1]['try_blocks'], reverse=True
        )[:30]

        exc_top = [{'type': t, 'count': c} for t, c in exception_types.most_common(25)]
        methods_with_many_tries.sort(key=lambda x: x['try_blocks'], reverse=True)

        return {
            'total_methods': total_methods,
            'methods_with_code': methods_with_code,
            'methods_with_try': methods_with_try,
            'total_try_blocks': total_try_blocks,
            'total_handlers': total_handlers,
            'defensive_score': score,
            'try_coverage': round(methods_with_try / max(methods_with_code, 1) * 100, 1),
            'avg_tries_per_method': round(total_try_blocks / max(methods_with_code, 1), 2),
            'exception_types_found': len(exception_types),
            'top_exception_types': exc_top,
            'try_per_method_dist': dict(sorted(try_per_method_dist.items())),
            'methods_with_many_tries': methods_with_many_tries[:30],
            'top_classes_by_try': [
                {'class': c, 'try_blocks': s['try_blocks'], 'methods_with_try': s['methods_with_try'], 'total_methods': s['total_methods']}
                for c, s in class_top
            ],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'methods_with_try': result['methods_with_try'],
            'total_try_blocks': result['total_try_blocks'],
            'defensive_score': result['defensive_score'],
            'try_coverage': result['try_coverage'],
            'exception_types': result['exception_types_found'],
            'top5_exception_types': result['top_exception_types'][:5],
            'top5_classes': result['top_classes_by_try'][:5],
        }