"""DEX 调试信息分析 — 源文件/行号信息/Debug信息保留度/去调试信息评估"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexDebugInfoAnalyzer:
    """DEX 调试信息深度分析 — 源文件保留/行号信息/调试可读性评分"""

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 调试信息保留程度"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        if not class_defs:
            return {'error': '无类定义数据'}
        total_classes = len(class_defs)
        classes_with_source = 0
        total_methods = 0
        methods_with_debug = 0
        methods_with_code = 0
        total_debug_info = 0
        source_files = Counter()
        classes_without_source = []
        class_stats = defaultdict(lambda: {'methods': 0, 'with_debug': 0, 'with_code': 0})
        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            src = cd.get('source_file', '')
            if src:
                classes_with_source += 1
                source_files[src] += 1
            else:
                classes_without_source.append(cls_name)
            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            cs = class_stats[cls_name]
            for m in all_methods:
                total_methods += 1
                cs['methods'] += 1
                code = m.get('code')
                if not code or isinstance(code, dict) and 'error' in code:
                    continue
                methods_with_code += 1
                cs['with_code'] += 1
                debug_off = code.get('debug_info_off', 0)
                if debug_off and debug_off > 0:
                    methods_with_debug += 1
                    cs['with_debug'] += 1
                    total_debug_info += 1
        source_retention = round(classes_with_source / max(total_classes, 1) * 100, 1)
        debug_retention = round(methods_with_debug / max(methods_with_code, 1) * 100, 1)
        readability = min(100, int(source_retention * 0.6 + debug_retention * 0.4))
        no_source_classes = [{
            'class': c,
            'methods': class_stats.get(c, {}).get('methods', 0),
        } for c in classes_without_source]
        no_source_classes.sort(key=lambda x: x['methods'], reverse=True)
        return {
            'total_classes': total_classes,
            'classes_with_source': classes_with_source,
            'source_retention': source_retention,
            'total_methods': total_methods,
            'methods_with_code': methods_with_code,
            'methods_with_debug': methods_with_debug,
            'debug_retention': debug_retention,
            'readability_score': readability,
            'avg_debug_per_method': round(total_debug_info / max(methods_with_code, 1), 2),
            'unique_source_files': len(source_files),
            'top_source_files': [{'file': f, 'count': c} for f, c in source_files.most_common(15)],
            'classes_without_source_count': len(classes_without_source),
            'top_classes_without_source': no_source_classes[:20],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'source_retention': result['source_retention'],
            'debug_retention': result['debug_retention'],
            'readability_score': result['readability_score'],
            'classes_without_source': result['classes_without_source_count'],
            'top3_source_files': result['top_source_files'][:3],
        }