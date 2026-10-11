"""DEX 类结构密度分析 — 包分布/类密度/方法字段比/空类/上帝类"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict

class DexClassDensityAnalyzer:
    """分析 DEX 类结构密度与代码分布健康度"""

    # 上帝类阈值
    GOD_CLASS_METHODS = 50
    GOD_CLASS_FIELDS = 30
    GOD_CLASS_INSNS = 5000

    @staticmethod
    def analyze(dex_parser):
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()

        if not class_defs:
            return {'error': '无可分析类定义'}

        total_classes = len(class_defs)
        package_dist = Counter()
        class_method_counts = []
        class_field_counts = []
        class_insn_counts = []
        god_classes = []
        empty_classes = 0
        interface_count = 0
        abstract_count = 0
        enum_count = 0
        annotation_count = 0
        final_class_count = 0
        public_class_count = 0
        method_field_ratios = []

        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            flags = cd.get('access_flags', '') or ''
            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            all_fields = (cd.get('static_fields') or []) + (cd.get('instance_fields') or [])

            # 包名提取
            if cls_name.startswith('L') and cls_name.endswith(';'):
                inner = cls_name[1:-1]
                parts = inner.rsplit('/', 1)
                pkg = parts[0].replace('/', '.') if len(parts) > 1 else '(default)'
                package_dist[pkg] += 1

            method_count = len(all_methods)
            field_count = len(all_fields)
            insn_count = sum((m.get('code', {}).get('insns_size', 0) for m in all_methods if m.get('code')), 0)

            class_method_counts.append(method_count)
            class_field_counts.append(field_count)
            class_insn_counts.append(insn_count)

            if method_count and field_count:
                method_field_ratios.append(round(method_count / field_count, 2))

            # 分类
            if 'INTERFACE' in flags:
                interface_count += 1
            if 'ABSTRACT' in flags:
                abstract_count += 1
            if 'ENUM' in flags:
                enum_count += 1
            if 'ANNOTATION' in flags:
                annotation_count += 1
            if 'FINAL' in flags:
                final_class_count += 1
            if 'PUBLIC' in flags:
                public_class_count += 1

            # 空类
            if method_count == 0 and field_count == 0:
                empty_classes += 1

            # 上帝类
            if (method_count >= DexClassDensityAnalyzer.GOD_CLASS_METHODS or
                field_count >= DexClassDensityAnalyzer.GOD_CLASS_FIELDS or
                insn_count >= DexClassDensityAnalyzer.GOD_CLASS_INSNS):
                def fmt(desc):
                    return desc.replace('L', '', 1).replace(';', '').replace('/', '.') if desc.startswith('L') else desc
                god_classes.append({
                    'class': fmt(cls_name),
                    'methods': method_count,
                    'fields': field_count,
                    'insns': insn_count,
                    'score': method_count + field_count + insn_count // 10,
                })

        # 排序上帝类
        god_classes.sort(key=lambda x: x['score'], reverse=True)

        # 统计
        avg_methods = round(sum(class_method_counts) / max(total_classes, 1), 1)
        avg_fields = round(sum(class_field_counts) / max(total_classes, 1), 1)
        avg_insns = round(sum(class_insn_counts) / max(total_classes, 1), 1)
        avg_ratio = round(sum(method_field_ratios) / max(len(method_field_ratios), 1), 2) if method_field_ratios else 0

        # 方法数分布
        method_dist = Counter()
        for c in class_method_counts:
            if c == 0: method_dist['0 (empty)'] += 1
            elif c <= 5: method_dist['1-5'] += 1
            elif c <= 15: method_dist['6-15'] += 1
            elif c <= 30: method_dist['16-30'] += 1
            elif c <= 50: method_dist['31-50'] += 1
            else: method_dist['50+ (god)'] += 1

        return {
            'total_classes': total_classes,
            'class_types': {
                'interface': interface_count,
                'abstract': abstract_count,
                'enum': enum_count,
                'annotation': annotation_count,
                'final': final_class_count,
                'public': public_class_count,
            },
            'empty_classes': empty_classes,
            'god_classes_count': len(god_classes),
            'avg_methods_per_class': avg_methods,
            'avg_fields_per_class': avg_fields,
            'avg_insns_per_class': avg_insns,
            'avg_method_field_ratio': avg_ratio,
            'method_count_distribution': dict(method_dist),
            'top_packages': [
                {'package': p, 'classes': c}
                for p, c in package_dist.most_common(30)
            ],
            'god_classes': god_classes[:20],
            'total_packages': len(package_dist),
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_classes': result['total_classes'],
            'total_packages': result['total_packages'],
            'empty_classes': result['empty_classes'],
            'god_classes': result['god_classes_count'],
            'avg_methods': result['avg_methods_per_class'],
            'avg_fields': result['avg_fields_per_class'],
            'class_types': result['class_types'],
            'top5_packages': result['top_packages'][:5],
            'top5_god_classes': result['god_classes'][:5],
        }