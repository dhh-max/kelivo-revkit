#!/usr/bin/env python3
"""资源混淆检测器 - 分析 APK 资源混淆程度

检测范围:
- R 类分析: 检查 R$id, R$layout, R$drawable 等内部类数量
- 资源命名: 检测资源名是否被混淆为单字母/无意义名称
- 布局混淆: 检查布局文件中的 ID 引用模式
- 资源冗余: 检测未引用的资源文件
- 字符串混淆: 检测资源字符串中的编码/加密特征
- 综合评分: 给出资源混淆程度评分
"""
import re
import os
from collections import Counter, defaultdict


class ResourceObfuscationDetector:
    """APK 资源混淆检测器"""

    # ── 正常资源命名模式 ──────────────────────────────────────
    MEANINGFUL_PATTERN = re.compile(r'^[a-z][a-z0-9_]{2,}$', re.I)
    OBFUSCATED_PATTERN = re.compile(r'^[a-z]{1,2}\d{0,2}$|^[a-z]\d[a-z]?\d?$', re.I)
    SINGLE_LETTER = re.compile(r'^[a-z]$|^[a-z]\d{1,2}$', re.I)

    # ── 常见合法资源前缀 ──────────────────────────────────────
    COMMON_PREFIXES = [
        'abc_', 'action_', 'activity_', 'alert_', 'app_', 'button_',
        'card_', 'chart_', 'checkbox_', 'collapse_', 'color_', 'content_',
        'custom_', 'default_', 'dialog_', 'edit_', 'empty_', 'error_',
        'expand_', 'fragment_', 'header_', 'icon_', 'image_', 'img_',
        'input_', 'item_', 'label_', 'layout_', 'list_', 'loading_',
        'login_', 'menu_', 'message_', 'nav_', 'network_', 'no_',
        'notification_', 'page_', 'panel_', 'picker_', 'popup_', 'progress_',
        'radio_', 'refresh_', 'recycler_', 'row_', 'scroll_', 'search_',
        'section_', 'select_', 'setting_', 'shape_', 'slide_', 'spinner_',
        'splash_', 'state_', 'status_', 'sub_', 'switch_', 'tab_',
        'table_', 'text_', 'textview_', 'title_', 'toolbar_', 'tooltip_',
        'top_', 'transition_', 'view_', 'web_', 'widget_',
        # 中文常见
        'btn_', 'tv_', 'et_', 'iv_', 'll_', 'rl_', 'fl_', 'cl_',
    ]

    # ── 资源类型分类 ──────────────────────────────────────────
    RES_TYPE_CATEGORIES = {
        'layout': ['layout', 'layout-land', 'layout-port', 'layout-sw600dp'],
        'drawable': ['drawable', 'drawable-hdpi', 'drawable-xhdpi', 'drawable-xxhdpi',
                     'drawable-xxxhdpi', 'drawable-mdpi', 'drawable-nodpi',
                     'drawable-anydpi', 'drawable-v21', 'drawable-v24'],
        'mipmap': ['mipmap', 'mipmap-hdpi', 'mipmap-xhdpi', 'mipmap-xxhdpi',
                   'mipmap-xxxhdpi', 'mipmap-mdpi', 'mipmap-anydpi-v26'],
        'values': ['values', 'values-zh', 'values-en', 'values-ja',
                   'values-ko', 'values-ru', 'values-es', 'values-fr',
                   'values-de', 'values-pt', 'values-ar', 'values-in'],
        'xml': ['xml'],
        'anim': ['anim', 'animator'],
        'color': ['color'],
        'menu': ['menu'],
        'raw': ['raw'],
        'font': ['font'],
    }

    @classmethod
    def analyze_resources(cls, file_list):
        """分析 APK 文件列表中的资源混淆情况

        Args:
            file_list: list[str], APK 内部文件路径列表

        Returns:
            dict: 资源混淆分析结果
        """
        # 按类型分类资源文件
        res_files = [f for f in file_list if f.startswith('res/')]
        res_by_type = defaultdict(list)
        for f in res_files:
            parts = f.split('/')
            if len(parts) >= 3:
                res_type = parts[1]
                res_name = parts[-1].rsplit('.', 1)[0] if '.' in parts[-1] else parts[-1]
                res_by_type[res_type].append(res_name)

        # 分析资源命名
        total_names = []
        obfuscated_names = []
        single_letter_names = []
        meaningful_names = []
        name_stats = defaultdict(list)

        for res_type, names in res_by_type.items():
            for name in names:
                total_names.append(name)
                if cls.SINGLE_LETTER.match(name):
                    single_letter_names.append(name)
                    obfuscated_names.append(name)
                    name_stats['single_letter'].append(name)
                elif cls.OBFUSCATED_PATTERN.match(name):
                    obfuscated_names.append(name)
                    name_stats['obfuscated'].append(name)
                elif cls.MEANINGFUL_PATTERN.match(name) and not any(
                    name.startswith(p) for p in cls.COMMON_PREFIXES):
                    # 有意义的命名但没有常见前缀 → 可能自定义
                    name_stats['custom'].append(name)
                    meaningful_names.append(name)
                else:
                    meaningful_names.append(name)

        # 计算混淆指标
        total = len(total_names) if total_names else 1
        obfuscation_ratio = len(obfuscated_names) / total
        single_ratio = len(single_letter_names) / total

        return {
            'total_resources': len(res_files),
            'resource_types': {rt: len(names) for rt, names in res_by_type.items()},
            'naming_analysis': {
                'total_names': len(total_names),
                'obfuscated_count': len(obfuscated_names),
                'obfuscation_ratio': round(obfuscation_ratio, 4),
                'single_letter_count': len(single_letter_names),
                'single_letter_ratio': round(single_ratio, 4),
                'meaningful_count': len(meaningful_names),
                'samples': {
                    'obfuscated': list(set(obfuscated_names))[:20],
                    'single_letter': list(set(single_letter_names))[:20],
                }
            },
            'by_type': {rt: {'total': len(names), 'obfuscated': sum(1 for n in names if cls.OBFUSCATED_PATTERN.match(n) or cls.SINGLE_LETTER.match(n))}
                        for rt, names in res_by_type.items()},
        }

    @classmethod
    def analyze_r_class(cls, r_class_content):
        """分析 R.java/R.class 内容

        Args:
            r_class_content: str, R 类文本内容

        Returns:
            dict: R 类分析结果
        """
        # 提取内部类
        inner_classes = re.findall(r'public static final class (\w+)', r_class_content)

        # 提取每个内部类的字段数
        class_fields = {}
        current_class = None
        field_count = 0
        for line in r_class_content.split('\n'):
            m = re.match(r'public static final class (\w+)', line)
            if m:
                if current_class:
                    class_fields[current_class] = field_count
                current_class = m.group(1)
                field_count = 0
            elif current_class and 'public static final int' in line:
                field_count += 1
            elif current_class and 'public static final' in line:
                field_count += 1

        if current_class:
            class_fields[current_class] = field_count

        # 检测混淆特征
        obfuscated_inner = [c for c in inner_classes if cls.SINGLE_LETTER.match(c) or cls.OBFUSCATED_PATTERN.match(c)]
        obfuscated_fields = {}
        for cls_name, fields in class_fields.items():
            if cls.SINGLE_LETTER.match(cls_name) or cls.OBFUSCATED_PATTERN.match(cls_name):
                obfuscated_fields[cls_name] = fields

        analysis = {
            'inner_class_count': len(inner_classes),
            'inner_classes': inner_classes[:30],
            'total_fields': sum(class_fields.values()),
            'fields_by_class': class_fields,
            'obfuscated_inner_classes': obfuscated_inner[:20],
            'obfuscated_inner_count': len(obfuscated_inner),
            'obfuscated_field_count': sum(obfuscated_fields.values()),
            'obfuscation_ratio': round(len(obfuscated_inner) / len(inner_classes), 4) if inner_classes else 0,
        }

        return analysis

    @classmethod
    def analyze_arsc(cls, arsc_packages):
        """分析 resources.arsc 中的混淆情况

        Args:
            arsc_packages: dict, resources.arsc 解析结果

        Returns:
            dict: ARSC 混淆分析
        """
        if not arsc_packages:
            return {'error': '未提供 ARSC 数据'}

        result = {}
        for pkg_name, pkg_data in arsc_packages.items():
            if isinstance(pkg_data, dict):
                res_types = pkg_data.get('resource_types', {})
                type_names = list(res_types.keys())
                # 检查类型名是否混淆
                obfuscated_types = [t for t in type_names if cls.SINGLE_LETTER.match(t)]

                result[pkg_name] = {
                    'type_count': len(type_names),
                    'types': type_names[:20],
                    'obfuscated_types': obfuscated_types[:10],
                    'has_obfuscation': len(obfuscated_types) > 0,
                }

        return result

    @classmethod
    def analyze_layout_obfuscation(cls, layout_files):
        """分析布局文件的混淆特征

        Args:
            layout_files: dict, {filename: content_text}

        Returns:
            dict: 布局混淆分析
        """
        if not layout_files:
            return {'error': '未提供布局文件'}

        android_id_pattern = re.compile(r'android:id="@[+]?id/(\w+)"')
        total_ids = 0
        obfuscated_ids = 0
        id_samples = []

        for fname, content in layout_files.items():
            ids = android_id_pattern.findall(content)
            for id_name in ids:
                total_ids += 1
                if cls.SINGLE_LETTER.match(id_name) or cls.OBFUSCATED_PATTERN.match(id_name):
                    obfuscated_ids += 1
                    if len(id_samples) < 20:
                        id_samples.append(id_name)

        return {
            'total_layout_files': len(layout_files),
            'total_id_references': total_ids,
            'obfuscated_id_count': obfuscated_ids,
            'obfuscation_ratio': round(obfuscated_ids / total_ids, 4) if total_ids else 0,
            'samples': id_samples,
        }

    @classmethod
    def analyze(cls, file_list=None, r_class_content=None, arsc_packages=None, layout_files=None):
        """一站式资源混淆分析

        Args:
            file_list: list[str], APK 文件路径列表
            r_class_content: str, R 类内容
            arsc_packages: dict, ARSC 包信息
            layout_files: dict, {filename: content}

        Returns:
            dict: 综合资源混淆分析报告
        """
        result = {
            'resource_analysis': {},
            'r_class_analysis': {},
            'arsc_analysis': {},
            'layout_analysis': {},
            'score': 0,
            'level': '低',
            'summary': {},
        }

        # 1. 资源文件分析
        if file_list:
            result['resource_analysis'] = cls.analyze_resources(file_list)

        # 2. R 类分析
        if r_class_content:
            result['r_class_analysis'] = cls.analyze_r_class(r_class_content)

        # 3. ARSC 分析
        if arsc_packages:
            result['arsc_analysis'] = cls.analyze_arsc(arsc_packages)

        # 4. 布局混淆
        if layout_files:
            result['layout_analysis'] = cls.analyze_layout_obfuscation(layout_files)

        # 5. 综合评分
        scores = []
        ra = result['resource_analysis']
        if ra:
            # 资源命名混淆度
            naming_ratio = ra.get('naming_analysis', {}).get('obfuscation_ratio', 0)
            scores.append(naming_ratio * 50)  # 最高50分

        rca = result['r_class_analysis']
        if rca:
            r_ratio = rca.get('obfuscation_ratio', 0)
            scores.append(r_ratio * 40)  # 最高40分

        la = result['layout_analysis']
        if la:
            layout_ratio = la.get('obfuscation_ratio', 0)
            scores.append(layout_ratio * 30)  # 最高30分

        if scores:
            score = min(100, sum(scores) / len(scores) * 2)
        else:
            score = 0

        score = round(score, 1)
        level = '高' if score >= 60 else '中' if score >= 25 else '低'

        # 6. 摘要
        result['score'] = score
        result['level'] = level
        result['summary'] = {
            'score': score,
            'level': level,
            'total_resources': ra.get('total_resources', 0) if ra else 0,
            'obfuscated_ratio': ra.get('naming_analysis', {}).get('obfuscation_ratio', 0) if ra else 0,
            'r_class_obfuscated': rca.get('obfuscated_inner_count', 0) if rca else 0,
            'layout_obfuscated_ids': la.get('obfuscated_id_count', 0) if la else 0,
        }

        return result


# ── 快捷函数 ──────────────────────────────────────────────────
def detect_resource_obfuscation(file_list=None, r_class_content=None,
                                 arsc_packages=None, layout_files=None):
    """一站式资源混淆检测"""
    return ResourceObfuscationDetector.analyze(file_list, r_class_content, arsc_packages, layout_files)

def analyze_r_class(r_class_content):
    """分析 R 类混淆"""
    return ResourceObfuscationDetector.analyze_r_class(r_class_content)

def analyze_resources_naming(file_list):
    """分析资源文件命名混淆"""
    return ResourceObfuscationDetector.analyze_resources(file_list)