"""DEX 反射/动态加载分析 — 反射调用/动态类加载/隐藏API/安全风险"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexReflectionAnalyzer:
    """DEX 反射与动态加载分析 — 反射滥用/动态类加载/安全风险评分"""

    # 反射相关特征
    REFLECT_PATTERNS = [
        'Class.forName', 'getMethod', 'getDeclaredMethod', 'getField',
        'getDeclaredField', 'newInstance', 'getConstructor', 'getDeclaredConstructor',
        'invoke', 'setAccessible', 'getClass().getMethod', 'ClassLoader',
        'findClass', 'loadClass', 'defineClass', 'java.lang.reflect',
    ]
    # 动态加载特征
    DYNAMIC_PATTERNS = [
        'DexClassLoader', 'PathClassLoader', 'InMemoryDexClassLoader',
        'loadDex', 'openDexFile', 'dalvik.system', 'MultiDex',
        'AssetManager', 'addAssetPath', 'declareLibrary',
    ]

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 反射与动态加载使用情况"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        if not class_defs:
            return {'error': '无类定义数据'}
        reflect_hits = Counter()
        dynamic_hits = Counter()
        # 在字符串中扫描反射/动态加载特征
        for s in strings:
            if not s:
                continue
            for pat in DexReflectionAnalyzer.REFLECT_PATTERNS:
                if pat in s:
                    reflect_hits[pat] += 1
            for pat in DexReflectionAnalyzer.DYNAMIC_PATTERNS:
                if pat in s:
                    dynamic_hits[pat] += 1
        # 类名中识别反射辅助类
        reflect_classes = []
        for cd in class_defs:
            cn = cd.get('class_name', '')
            cname = cn.replace('L', '').replace(';', '').replace('/', '.')
            if any(k in cname for k in ['reflect', 'Reflection', 'DexClassLoader', 'ClassLoader']):
                reflect_classes.append(cname)
        # 风险评分
        reflect_count = sum(reflect_hits.values())
        dynamic_count = sum(dynamic_hits.values())
        risk_score = min(100, int(min(reflect_count * 0.5, 40) + min(dynamic_count * 2, 40) + min(len(reflect_classes) * 3, 20)))
        if risk_score >= 60:
            risk_level = '高风险'
        elif risk_score >= 30:
            risk_level = '中风险'
        elif risk_score > 0:
            risk_level = '低风险'
        else:
            risk_level = '无风险'
        return {
            'reflect_hits': [{'pattern': p, 'count': c} for p, c in reflect_hits.most_common(20)],
            'reflect_total': reflect_count,
            'dynamic_hits': [{'pattern': p, 'count': c} for p, c in dynamic_hits.most_common(15)],
            'dynamic_total': dynamic_count,
            'reflect_class_count': len(reflect_classes),
            'reflect_classes': reflect_classes[:20],
            'risk_score': risk_score,
            'risk_level': risk_level,
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'reflect_total': result['reflect_total'],
            'dynamic_total': result['dynamic_total'],
            'risk_level': result['risk_level'],
            'risk_score': result['risk_score'],
            'top3_reflect': result['reflect_hits'][:3],
        }