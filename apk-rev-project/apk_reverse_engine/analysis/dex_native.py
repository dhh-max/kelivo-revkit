"""DEX 本地方法(JNI)分析 — Native方法分布/动态库引用/JNI注册/混合编程评估"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexNativeAnalyzer:
    """DEX Native(JNI)方法深度分析 — Native方法统计/动态库/签名特征"""

    # JNI 动态库加载特征
    LOADLIB_PATTERNS = [
        'System.loadLibrary', 'System.load', 'loadLibrary', 'load(',
        'nativeLoad', 'Runtime.getRuntime().load',
    ]
    # JNI 注册特征
    JNI_PATTERNS = [
        'RegisterNatives', 'registerNatives', 'JNI_OnLoad', 'JNIEnv',
        'jint', 'jobject', 'jclass', 'jnienv',
    ]

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中的 Native 方法"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        if not class_defs:
            return {'error': '无类定义数据'}
        total_methods = 0
        native_methods = []
        native_count = 0
        classes_with_native = set()
        field_usage = Counter()
        access_flags = Counter()
        top_classes = Counter()
        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            for m in ((cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])):
                total_methods += 1
                flags = m.get('access_flags', '')
                if 'NATIVE' in flags:
                    native_count += 1
                    classes_with_native.add(cls_name)
                    top_classes[cls_name] += 1
                    proto = m.get('proto') or {}
                    ret = proto.get('return_type', '') if isinstance(proto, dict) else ''
                    params = proto.get('parameters', []) if isinstance(proto, dict) else []
                    native_methods.append({
                        'class': cls_name,
                        'method': m.get('name', '?'),
                        'return': ret,
                        'params': len(params),
                        'signature': f"{m.get('name','?')}({','.join(params)}){ret}",
                    })
        # 字符串中动态库加载迹象
        load_libs = Counter()
        for s in strings:
            if not s:
                continue
            for pat in DexNativeAnalyzer.LOADLIB_PATTERNS:
                if pat in s:
                    load_libs[pat] += 1
        # Native 占比
        native_ratio = round(native_count / max(total_methods, 1) * 100, 2)
        # 混合编程评分
        if native_count == 0:
            mix_score = 0
            mix_level = '纯Java'
        else:
            score = min(100, int(native_ratio * 5 + min(len(classes_with_native) * 2, 30)))
            mix_score = score
            mix_level = '重度Native' if score >= 60 else '中度Native' if score >= 30 else '轻度Native'
        # 排序
        top_classes_sorted = [{'class': c.replace('L', '').replace(';', '').replace('/', '.'), 'native_methods': n}
                              for c, n in top_classes.most_common(20)]
        native_methods.sort(key=lambda x: (x['class'], x['method']))
        return {
            'total_methods': total_methods,
            'native_method_count': native_count,
            'native_ratio': native_ratio,
            'classes_with_native': len(classes_with_native),
            'mix_score': mix_score,
            'mix_level': mix_level,
            'load_lib_hits': [{'pattern': p, 'count': c} for p, c in load_libs.most_common(10)],
            'load_lib_count': len(load_libs),
            'top_classes_with_native': top_classes_sorted,
            'native_methods': native_methods[:30],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'native_method_count': result['native_method_count'],
            'native_ratio': result['native_ratio'],
            'mix_level': result['mix_level'],
            'classes_with_native': result['classes_with_native'],
            'top3_classes': result['top_classes_with_native'][:3],
        }