"""DEX 资源引用分析 — R类引用/资源ID/资源混淆/硬编码资源检测"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict
import re


class DexResourceRefAnalyzer:
    """DEX 资源引用深度分析 — R类引用分布/资源混淆/硬编码资源ID"""

    R_CATEGORIES = {
        'R$layout': '布局',
        'R$id': '控件ID',
        'R$drawable': '图片/图标',
        'R$string': '字符串资源',
        'R$color': '颜色',
        'R$dimen': '尺寸',
        'R$menu': '菜单',
        'R$anim': '动画',
        'R$style': '样式',
        'R$attr': '属性',
        'R$raw': '原始文件',
        'R$xml': 'XML',
        'R$array': '数组',
        'R$bool': '布尔值',
        'R$integer': '整数',
    }

    # 硬编码资源ID前缀 (0x7f...)
    HARDCODED_ID_PATTERN = re.compile(r'0x7f[0-9a-fA-F]{4,6}')

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 资源引用特征"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        if not class_defs:
            return {'error': '无类定义数据'}

        total_classes = len(class_defs)
        r_class_refs = Counter()       # R$xxx -> 引用次数
        r_field_refs = Counter()       # 具体资源字段名 -> 次数
        r_class_names = set()          # 出现的R类名
        hardcoded_ids = []             # 硬编码资源ID
        resource_obfuscation_hits = 0  # 资源混淆线索
        total_refs = 0
        classes_with_r = set()

        # 扫描字符串池中的R类引用
        for s in strings:
            if not s:
                continue
            # 匹配 R$xxx.name 模式
            for rcls, cat in DexResourceRefAnalyzer.R_CATEGORIES.items():
                pattern = rcls.replace('$', r'\$')
                if re.search(pattern, s):
                    r_class_refs[rcls] += 1
                    r_class_names.add(rcls)
                    # 提取具体字段名
                    parts = s.split('/')
                    if len(parts) >= 2:
                        field = parts[-1]
                        if field and len(field) < 80:
                            r_field_refs[f'{rcls}.{field}'] += 1
                    total_refs += 1

            # 检测硬编码资源ID
            if DexResourceRefAnalyzer.HARDCODED_ID_PATTERN.search(s):
                hardcoded_ids.append(s)
                resource_obfuscation_hits += 1

        # 从类定义中查找继承R类的内部类
        r_inner_classes = []
        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            if '$R$' in cls_name or cls_name.endswith('$R'):
                r_inner_classes.append(cls_name)
                classes_with_r.add(cls_name)

        # 检测资源混淆：缺少R类引用但有很多资源相关字符串
        # 或者 R 类名被重命名（非标准模式）
        if total_refs == 0 and len(strings) > 1000:
            resource_obfuscation_hits = 1  # 疑似ProGuard资源混淆

        # 评估资源引用覆盖率
        r_category_count = len(r_class_refs)
        r_coverage = round(r_category_count / max(len(DexResourceRefAnalyzer.R_CATEGORIES), 1) * 100, 1)

        # 资源混淆评分
        obfuscation_score = 0
        if resource_obfuscation_hits > 0:
            obfuscation_score = min(100, resource_obfuscation_hits * 10)
        if total_refs == 0 and len(class_defs) > 50:
            obfuscation_score = max(obfuscation_score, 80)  # 很可能是资源混淆

        # 资源引用密度评分
        ref_density = round(total_refs / max(total_classes, 1), 2)
        density_score = min(100, int(ref_density * 20))

        return {
            'total_classes': total_classes,
            'total_r_refs': total_refs,
            'r_category_count': r_category_count,
            'r_coverage': r_coverage,
            'r_category_dist': dict(r_class_refs.most_common()),
            'top_r_fields': [{'field': k, 'count': v} for k, v in r_field_refs.most_common(20)],
            'r_inner_classes': r_inner_classes[:30],
            'hardcoded_id_count': len(hardcoded_ids),
            'hardcoded_id_samples': hardcoded_ids[:10],
            'obfuscation_score': obfuscation_score,
            'obfuscation_level': '严重混淆' if obfuscation_score >= 70 else '中度混淆' if obfuscation_score >= 30 else '正常',
            'ref_density': ref_density,
            'density_score': density_score,
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_r_refs': result['total_r_refs'],
            'r_category_count': result['r_category_count'],
            'r_coverage': result['r_coverage'],
            'obfuscation_score': result['obfuscation_score'],
            'obfuscation_level': result['obfuscation_level'],
            'hardcoded_id_count': result['hardcoded_id_count'],
        }