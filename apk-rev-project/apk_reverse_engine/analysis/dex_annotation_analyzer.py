"""DEX 注解分析器 — 提取并分析 DEX 中的注解信息"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict, Counter

class DexAnnotationAnalyzer:
    """DEX 注解分析引擎"""

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中所有类的注解信息"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        types = dex_parser.get_types()

        annotation_stats = {
            'class_annotations': [],
            'method_annotations': [],
            'field_annotations': [],
            'parameter_annotations': [],
        }

        type_counter = Counter()
        visibility_counter = Counter()
        class_annot_map = defaultdict(list)
        method_annot_map = defaultdict(list)
        field_annot_map = defaultdict(list)
        classes_with_annotations = 0
        total_annotations = 0

        for cd_idx, cd in enumerate(class_defs):
            class_name = dex_parser._get_type_string(cd) if hasattr(dex_parser, '_get_type_string') else f'class_{cd_idx}'
            if class_name.startswith('['):
                continue

            annot_dir = dex_parser.get_annotations(cd)
            if not annot_dir:
                continue

            has_any = False

            # 类级别注解
            class_annot_off = annot_dir.get('class_annotation_off', 0)
            if class_annot_off:
                annots = dex_parser.get_annotation_set(class_annot_off)
                if annots:
                    has_any = True
                    for a in annots:
                        if isinstance(a, dict) and 'type' in a:
                            total_annotations += 1
                            type_counter[a['type']] += 1
                            visibility_counter[a.get('visibility', 'unknown')] += 1
                            class_annot_map[class_name].append(a)
                            annotation_stats['class_annotations'].append({
                                'class': class_name,
                                'type': a['type'],
                                'visibility': a.get('visibility', 'unknown'),
                            })

            # 方法注解
            for ma in annot_dir.get('method_annotations', []):
                method_idx = ma.get('method_idx', 0)
                annots = dex_parser.get_annotation_set(ma.get('annotations_off', 0))
                if annots:
                    has_any = True
                    method_info = {}
                    methods = dex_parser.get_methods()
                    if 0 <= method_idx < len(methods):
                        method_info = methods[method_idx]
                    method_name, method_sig = dex_parser.get_method_signature(method_info) if method_info else (f'method_{method_idx}', '')
                    for a in annots:
                        if isinstance(a, dict) and 'type' in a:
                            total_annotations += 1
                            type_counter[a['type']] += 1
                            visibility_counter[a.get('visibility', 'unknown')] += 1
                            method_annot_map[class_name].append({
                                'method': method_name,
                                'type': a['type'],
                                'visibility': a.get('visibility', 'unknown'),
                            })
                            annotation_stats['method_annotations'].append({
                                'class': class_name,
                                'method': method_name,
                                'type': a['type'],
                                'visibility': a.get('visibility', 'unknown'),
                            })

            # 字段注解
            for fa in annot_dir.get('field_annotations', []):
                field_idx = fa.get('field_idx', 0)
                annots = dex_parser.get_annotation_set(fa.get('annotations_off', 0))
                if annots:
                    has_any = True
                    fields = dex_parser.get_fields()
                    field_name = ''
                    if 0 <= field_idx < len(fields):
                        f = fields[field_idx]
                        if isinstance(f, dict):
                            field_name = f.get('name', f'field_{field_idx}')
                    for a in annots:
                        if isinstance(a, dict) and 'type' in a:
                            total_annotations += 1
                            type_counter[a['type']] += 1
                            visibility_counter[a.get('visibility', 'unknown')] += 1
                            field_annot_map[class_name].append({
                                'field': field_name,
                                'type': a['type'],
                                'visibility': a.get('visibility', 'unknown'),
                            })
                            annotation_stats['field_annotations'].append({
                                'class': class_name,
                                'field': field_name,
                                'type': a['type'],
                                'visibility': a.get('visibility', 'unknown'),
                            })

            # 参数注解
            for pa in annot_dir.get('parameter_annotations', []):
                annots = dex_parser.get_annotation_set(pa.get('annotations_off', 0))
                if annots:
                    has_any = True
                    for a in annots:
                        if isinstance(a, dict) and 'type' in a:
                            total_annotations += 1
                            type_counter[a['type']] += 1
                            visibility_counter[a.get('visibility', 'unknown')] += 1
                            annotation_stats['parameter_annotations'].append({
                                'class': class_name,
                                'type': a['type'],
                                'visibility': a.get('visibility', 'unknown'),
                            })

            if has_any:
                classes_with_annotations += 1

        # 提取常见注解类型
        common_annotations = [
            'Ldalvik/annotation/AnnotationDefault;',
            'Ldalvik/annotation/EnclosingClass;',
            'Ldalvik/annotation/EnclosingMethod;',
            'Ldalvik/annotation/InnerClass;',
            'Ldalvik/annotation/MemberClasses;',
            'Ldalvik/annotation/Signature;',
            'Ldalvik/annotation/Throws;',
            'Ldalvik/annotation/MethodParameters;',
            'Lkotlin/Metadata;',
            'Lkotlin/coroutines/jvm/internal/DebugMetadata;',
            'Ljavax/annotation/Nullable;',
            'Ljavax/annotation/Nonnull;',
            'Landroid/annotation/SuppressLint;',
            'Landroid/annotation/TargetApi;',
            'Landroid/support/annotation/Nullable;',
            'Landroid/support/annotation/NonNull;',
            'Landroidx/annotation/Nullable;',
            'Landroidx/annotation/NonNull;',
            'Lbutterknife/',
            'Ldagger/',
            'Lretrofit2/',
            'Lcom/google/gson/annotations/SerializedName;',
            'Lorg/jetbrains/annotations/Nullable;',
            'Lorg/jetbrains/annotations/NotNull;',
        ]

        annotation_groups = {
            'kotlin': sum(c for t, c in type_counter.items() if 'kotlin' in t.lower()),
            'android_support': sum(c for t, c in type_counter.items() if 'android/support' in t.lower() or 'androidx' in t.lower()),
            'dagger': sum(c for t, c in type_counter.items() if 'dagger' in t.lower()),
            'butterknife': sum(c for t, c in type_counter.items() if 'butterknife' in t.lower()),
            'retrofit': sum(c for t, c in type_counter.items() if 'retrofit' in t.lower()),
            'gson': sum(c for t, c in type_counter.items() if 'gson' in t.lower()),
            'room': sum(c for t, c in type_counter.items() if 'androidx/room' in t.lower()),
            'realm': sum(c for t, c in type_counter.items() if 'realm' in t.lower()),
            'realm2': sum(c for t, c in type_counter.items() if 'io/realm' in t.lower()),
            'lombok': sum(c for t, c in type_counter.items() if 'lombok' in t.lower()),
            'jetbrains': sum(c for t, c in type_counter.items() if 'jetbrains' in t.lower()),
            'javax': sum(c for t, c in type_counter.items() if 'javax' in t.lower()),
            'dalvik': sum(c for t, c in type_counter.items() if 'dalvik' in t.lower()),
        }

        top_types = type_counter.most_common(30)

        return {
            'total_annotations': total_annotations,
            'classes_with_annotations': classes_with_annotations,
            'class_annotation_count': len(annotation_stats['class_annotations']),
            'method_annotation_count': len(annotation_stats['method_annotations']),
            'field_annotation_count': len(annotation_stats['field_annotations']),
            'parameter_annotation_count': len(annotation_stats['parameter_annotations']),
            'top_annotation_types': [{'type': t, 'count': c} for t, c in top_types],
            'visibility_distribution': dict(visibility_counter),
            'annotation_groups': annotation_groups,
            'top_classes_by_annotations': [
                {'class': cls, 'count': sum(len(v) for v in [class_annot_map.get(cls, []), method_annot_map.get(cls, []), field_annot_map.get(cls, [])])}
                for cls in sorted(set(list(class_annot_map.keys()) + list(method_annot_map.keys()) + list(field_annot_map.keys())),
                                  key=lambda c: len(class_annot_map.get(c, [])) + len(method_annot_map.get(c, [])) + len(field_annot_map.get(c, [])),
                                  reverse=True)[:20]
            ],
            'sample_class_annotations': annotation_stats['class_annotations'][:50],
            'sample_method_annotations': annotation_stats['method_annotations'][:50],
            'sample_field_annotations': annotation_stats['field_annotations'][:50],
        }

    @staticmethod
    def get_summary(result):
        """生成摘要"""
        return {
            'total_annotations': result['total_annotations'],
            'classes_with_annotations': result['classes_with_annotations'],
            'by_type': {
                'class': result['class_annotation_count'],
                'method': result['method_annotation_count'],
                'field': result['field_annotation_count'],
                'parameter': result['parameter_annotation_count'],
            },
            'top5_types': result['top_annotation_types'][:5],
            'groups': result['annotation_groups'],
        }
