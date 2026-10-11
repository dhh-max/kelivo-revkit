"""DEX 访问控制模式分析 — 修饰符组合/可见性/API暴露面/封装质量评估"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict

class DexAccessPatternAnalyzer:
    """DEX 访问控制模式深度分析 — 可见性分布/修饰符组合/API暴露面/封装质量"""

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 访问控制模式"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        methods = dex_parser.get_methods()
        fields = dex_parser.get_fields()

        # 类可见性统计
        class_visibility = Counter()
        class_modifiers = Counter()
        class_combo_patterns = Counter()

        for cd in class_defs:
            flags = cd.get('access_flags', '')
            raw = cd.get('access_flags_raw', 0)

            # 可见性
            if 'public' in flags:
                class_visibility['public'] += 1
            elif 'private' in flags:
                class_visibility['private'] += 1
            elif 'protected' in flags:
                class_visibility['protected'] += 1
            else:
                class_visibility['package'] += 1

            # 修饰符
            for mod in ['final', 'abstract', 'interface', 'static', 'enum', 'annotation', 'synthetic']:
                if mod in flags:
                    class_modifiers[mod] += 1

            # 组合模式
            combo_parts = []
            if 'public' in flags: combo_parts.append('public')
            if 'final' in flags: combo_parts.append('final')
            if 'abstract' in flags: combo_parts.append('abstract')
            if 'interface' in flags: combo_parts.append('interface')
            if 'static' in flags: combo_parts.append('static')
            if 'enum' in flags: combo_parts.append('enum')
            combo = '+'.join(combo_parts) if combo_parts else 'default'
            class_combo_patterns[combo] += 1

        # 方法可见性
        method_visibility = Counter()
        method_modifiers = Counter()
        method_combo_patterns = Counter()
        public_api_methods = []

        for cd in class_defs:
            cls_name = cd.get('class_name', '').replace('L', '').replace(';', '').replace('/', '.')
            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            for m in all_methods:
                flags = m.get('access_flags', '')

                if 'public' in flags:
                    method_visibility['public'] += 1
                    # 收集公开 API 方法（排除构造函数和系统方法）
                    name = m.get('name', '')
                    if name not in ('<init>', '<clinit>') and not name.startswith('access$'):
                        public_api_methods.append({
                            'class': cls_name,
                            'method': name,
                            'flags': flags,
                        })
                elif 'private' in flags:
                    method_visibility['private'] += 1
                elif 'protected' in flags:
                    method_visibility['protected'] += 1
                else:
                    method_visibility['package'] += 1

                for mod in ['static', 'final', 'synchronized', 'native', 'abstract', 'synthetic', 'bridge', 'varargs']:
                    if mod in flags:
                        method_modifiers[mod] += 1

                combo_parts = []
                for v in ['public', 'private', 'protected']:
                    if v in flags:
                        combo_parts.append(v)
                        break
                for mod in ['static', 'final', 'synchronized', 'native', 'abstract']:
                    if mod in flags:
                        combo_parts.append(mod)
                combo = '+'.join(combo_parts) if combo_parts else 'default'
                method_combo_patterns[combo] += 1

        # 字段可见性
        field_visibility = Counter()
        field_modifiers = Counter()
        exposed_fields = []

        for cd in class_defs:
            cls_name = cd.get('class_name', '').replace('L', '').replace(';', '').replace('/', '.')
            all_fields = (cd.get('static_fields') or []) + (cd.get('instance_fields') or [])
            for f in all_fields:
                flags = f.get('access_flags', '')

                if 'public' in flags:
                    field_visibility['public'] += 1
                    if 'static' in flags and 'final' not in flags:
                        exposed_fields.append({
                            'class': cls_name,
                            'field': f.get('name', ''),
                            'type': f.get('type', ''),
                            'flags': flags,
                        })
                elif 'private' in flags:
                    field_visibility['private'] += 1
                elif 'protected' in flags:
                    field_visibility['protected'] += 1
                else:
                    field_visibility['package'] += 1

                for mod in ['static', 'final', 'volatile', 'transient', 'synthetic', 'enum']:
                    if mod in flags:
                        field_modifiers[mod] += 1

        # 封装质量评分
        total_classes = len(class_defs)
        total_methods_count = sum(method_visibility.values())
        total_fields_count = sum(field_visibility.values())

        public_method_ratio = round(method_visibility.get('public', 0) / max(total_methods_count, 1) * 100, 1)
        public_field_ratio = round(field_visibility.get('public', 0) / max(total_fields_count, 1) * 100, 1)
        private_method_ratio = round(method_visibility.get('private', 0) / max(total_methods_count, 1) * 100, 1)
        private_field_ratio = round(field_visibility.get('private', 0) / max(total_fields_count, 1) * 100, 1)

        # 封装评分: private 比例越高越好
        encapsulation_score = round(
            (private_method_ratio * 0.4 + private_field_ratio * 0.4 +
             (100 - public_field_ratio) * 0.2), 1
        )

        return {
            'class_visibility': dict(class_visibility),
            'class_modifiers': dict(class_modifiers.most_common()),
            'class_combo_patterns': dict(class_combo_patterns.most_common(15)),
            'method_visibility': dict(method_visibility),
            'method_modifiers': dict(method_modifiers.most_common()),
            'method_combo_patterns': dict(method_combo_patterns.most_common(15)),
            'field_visibility': dict(field_visibility),
            'field_modifiers': dict(field_modifiers.most_common()),
            'public_api_method_count': len(public_api_methods),
            'public_api_methods': public_api_methods[:50],
            'exposed_field_count': len(exposed_fields),
            'exposed_fields': exposed_fields[:30],
            'encapsulation_quality': {
                'public_method_ratio': public_method_ratio,
                'private_method_ratio': private_method_ratio,
                'public_field_ratio': public_field_ratio,
                'private_field_ratio': private_field_ratio,
                'encapsulation_score': encapsulation_score,
                'rating': '优秀' if encapsulation_score >= 70 else '良好' if encapsulation_score >= 50 else '一般' if encapsulation_score >= 30 else '较差',
            },
        }

    @staticmethod
    def get_summary(result):
        eq = result['encapsulation_quality']
        return {
            'class_visibility': result['class_visibility'],
            'method_visibility': result['method_visibility'],
            'field_visibility': result['field_visibility'],
            'public_api_count': result['public_api_method_count'],
            'exposed_fields': result['exposed_field_count'],
            'encapsulation_score': eq['encapsulation_score'],
            'rating': eq['rating'],
        }