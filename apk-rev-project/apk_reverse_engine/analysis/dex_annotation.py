"""DEX 注解分析器 — 提取并分析 DEX 中的注解信息"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict, Counter

class DexAnnotationAnalyzer:
    """DEX 注解分析引擎"""

    # 常见注解
    KNOWN_ANNOTATIONS = {
        'Landroid/annotation/',
        'Landroidx/annotation/',
        'Lcom/google/annotation/',
        'Lretrofit2/',
        'Lbutterknife/',
        'Ldagger/',
        'Ljavax/annotation/',
        'Lkotlin/',
        'Lkotlinx/',
        'Lcom/jakewharton/',
        'Lorg/jetbrains/',
        'Lcom/squareup/',
        'Lcom/google/gson/',
        'Lcom/bumptech/glide/',
        'Lio/reactivex/',
        'Llombok/',
        'Lorg/greenrobot/',
        'Lcom/raizlabs/',
        'Lcom/google/android/',
    }

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中所有类的注解"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()

        annotations_by_type = defaultdict(list)
        class_annotations = []
        method_annotations = []
        field_annotations = []
        total_annotated = 0
        annotation_types = Counter()

        for cd_idx, cd in enumerate(class_defs):
            class_name = dex_parser._get_type_string(cd) if hasattr(dex_parser, '_get_type_string') else f'class_{cd_idx}'
            if class_name.startswith('['):
                continue

            has_annotation = False

            # 类级注解
            annotations_off = cd.get('annotations_off', 0)
            if annotations_off:
                try:
                    ann_set = dex_parser.get_annotation_set(annotations_off)
                    if ann_set:
                        for ann_info in (ann_set if isinstance(ann_set, list) else [ann_set]):
                            ann_type = ''
                            if isinstance(ann_info, dict):
                                ann_type = ann_info.get('type', '')
                            elif isinstance(ann_info, str):
                                ann_type = ann_info

                            if ann_type:
                                has_annotation = True
                                annotation_types[ann_type] += 1
                                category = DexAnnotationAnalyzer._categorize_annotation(ann_type)
                                annotations_by_type[category].append({
                                    'class': class_name,
                                    'annotation': ann_type,
                                    'scope': 'class',
                                })
                                class_annotations.append({
                                    'class': class_name,
                                    'annotation': ann_type,
                                })
                except Exception as e:
                    logger.debug(f"解析类注解失败 {class_name}: {e}")

            # 方法注解
            methods = cd.get('methods', [])
            for m_idx, method in enumerate(methods):
                method_annotations_off = method.get('annotations_off', 0)
                if method_annotations_off:
                    try:
                        method_name, method_sig = dex_parser.get_method_signature(method)
                        ann_set = dex_parser.get_annotation_set(method_annotations_off)
                        if ann_set:
                            for ann_info in (ann_set if isinstance(ann_set, list) else [ann_set]):
                                ann_type = ann_info.get('type', '') if isinstance(ann_info, dict) else str(ann_info)
                                if ann_type:
                                    has_annotation = True
                                    annotation_types[ann_type] += 1
                                    category = DexAnnotationAnalyzer._categorize_annotation(ann_type)
                                    annotations_by_type[category].append({
                                        'class': class_name,
                                        'method': method_name,
                                        'annotation': ann_type,
                                        'scope': 'method',
                                    })
                                    method_annotations.append({
                                        'class': class_name,
                                        'method': method_name,
                                        'annotation': ann_type,
                                    })
                    except:
                        pass

            # 字段注解
            fields = cd.get('fields', [])
            for f_idx, field in enumerate(fields):
                field_annotations_off = field.get('annotations_off', 0)
                if field_annotations_off:
                    try:
                        field_name = field.get('name', f'field_{f_idx}')
                        ann_set = dex_parser.get_annotation_set(field_annotations_off)
                        if ann_set:
                            for ann_info in (ann_set if isinstance(ann_set, list) else [ann_set]):
                                ann_type = ann_info.get('type', '') if isinstance(ann_info, dict) else str(ann_info)
                                if ann_type:
                                    has_annotation = True
                                    annotation_types[ann_type] += 1
                                    category = DexAnnotationAnalyzer._categorize_annotation(ann_type)
                                    annotations_by_type[category].append({
                                        'class': class_name,
                                        'field': field_name,
                                        'annotation': ann_type,
                                        'scope': 'field',
                                    })
                                    field_annotations.append({
                                        'class': class_name,
                                        'field': field_name,
                                        'annotation': ann_type,
                                    })
                    except:
                        pass

            if has_annotation:
                total_annotated += 1

        total_classes = len(class_defs)
        total_annotations = len(class_annotations) + len(method_annotations) + len(field_annotations)

        # Top 注解类型
        top_annotations = annotation_types.most_common(30)

        return {
            'total_classes': total_classes,
            'annotated_classes': total_annotated,
            'annotation_coverage': round(total_annotated / max(total_classes, 1) * 100, 2),
            'total_annotations': total_annotations,
            'class_annotations_count': len(class_annotations),
            'method_annotations_count': len(method_annotations),
            'field_annotations_count': len(field_annotations),
            'top_annotation_types': [
                {'annotation': ann, 'count': cnt} for ann, cnt in top_annotations
            ],
            'annotations_by_category': {
                cat: items[:20] for cat, items in annotations_by_type.items()
            },
            'class_annotations': class_annotations[:50],
            'method_annotations': method_annotations[:50],
            'field_annotations': field_annotations[:50],
        }

    @staticmethod
    def _categorize_annotation(ann_type):
        """将注解归类"""
        for known_prefix in DexAnnotationAnalyzer.KNOWN_ANNOTATIONS:
            if ann_type.startswith(known_prefix):
                return known_prefix.rstrip('/').lstrip('L')
        if ann_type.startswith('L'):
            return ann_type.split('/')[0].lstrip('L') if '/' in ann_type else 'other'
        return 'other'

    @staticmethod
    def get_summary(result):
        return {
            'total_classes': result['total_classes'],
            'annotated_classes': result['annotated_classes'],
            'coverage': result['annotation_coverage'],
            'total_annotations': result['total_annotations'],
            'class_annotations': result['class_annotations_count'],
            'method_annotations': result['method_annotations_count'],
            'field_annotations': result['field_annotations_count'],
            'top5_annotations': result['top_annotation_types'][:5],
        }