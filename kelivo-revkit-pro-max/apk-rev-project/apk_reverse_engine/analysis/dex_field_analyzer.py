"""DEX 字段分析器 - 提取并分析 DEX 中的静态字段、实例字段、常量"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
import re
from collections import defaultdict, Counter

class DexFieldAnalyzer:
    """DEX 字段深度分析"""

    # 敏感字段名模式
    SENSITIVE_PATTERNS = {
        'credential': re.compile(r'(password|passwd|pwd|secret|credential|token|apikey|api_key|auth)', re.I),
        'financial': re.compile(r'(account|balance|amount|payment|card|bank|wallet|currency|price|cost)', re.I),
        'personal': re.compile(r'(email|phone|address|name|ssid|identity|passport|license|birth|gender|age)', re.I),
        'crypto': re.compile(r'(encrypt|decrypt|cipher|aes|rsa|des|md5|sha|hmac|iv|salt|nonce)', re.I),
        'network': re.compile(r'(url|host|port|endpoint|server|api|proxy|socket|domain)', re.I),
        'device': re.compile(r'(imei|imsi|serial|uuid|device|android_id|mac|udid)', re.I),
        'config': re.compile(r'(config|setting|preference|flag|debug|test|mode|enable|disable)', re.I),
    }

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中的所有字段
        Args:
            dex_parser: DexParser 实例
        Returns:
            dict: {total_fields, by_access, sensitive_fields, by_class, constants, type_distribution}
        """
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        all_fields = []
        sensitive_fields = []
        constants = []
        access_counter = Counter()
        type_counter = Counter()
        class_field_map = defaultdict(list)

        for cd in class_defs:
            class_name = dex_parser._get_type_string(cd)
            if class_name.startswith('['):
                continue

            # 实例字段
            instance_fields = cd.get('instance_fields', [])
            static_fields = cd.get('static_fields', [])

            for field in instance_fields + static_fields:
                field_name = field.get('name', '')
                field_type = field.get('type', '')
                access_flags = field.get('access_flags', 0)
                is_static = bool(access_flags & 0x0008)
                is_final = bool(access_flags & 0x0010)
                is_public = bool(access_flags & 0x0001)
                is_private = bool(access_flags & 0x0002)

                field_info = {
                    'class': class_name,
                    'name': field_name,
                    'type': field_type,
                    'static': is_static,
                    'final': is_final,
                    'public': is_public,
                    'private': is_private,
                    'access_flags': access_flags,
                }
                all_fields.append(field_info)
                class_field_map[class_name].append(field_name)

                # 访问修饰符统计
                if is_public:
                    access_counter['public'] += 1
                elif is_private:
                    access_counter['private'] += 1
                else:
                    access_counter['other'] += 1

                if is_static:
                    access_counter['static'] += 1
                if is_final:
                    access_counter['final'] += 1

                # 类型统计
                type_counter[field_type] += 1

                # 敏感字段检测
                for cat, pattern in DexFieldAnalyzer.SENSITIVE_PATTERNS.items():
                    if pattern.search(field_name):
                        sensitive_fields.append({
                            **field_info,
                            'category': cat,
                            'reason': f'字段名匹配 {cat} 模式',
                        })
                        break

                # 常量字段 (static final + 基本类型/String)
                if is_static and is_final:
                    if field_type in ('I', 'J', 'F', 'D', 'Z', 'B', 'S', 'C') or field_type == 'Ljava/lang/String;':
                        constants.append({
                            'class': class_name,
                            'name': field_name,
                            'type': field_type,
                        })

        # 字段最多的类
        top_classes = sorted(
            [{'class': k, 'field_count': len(v)} for k, v in class_field_map.items()],
            key=lambda x: -x['field_count']
        )[:20]

        # 按敏感类别分组
        sensitive_by_cat = defaultdict(list)
        for sf in sensitive_fields:
            sensitive_by_cat[sf['category']].append(sf)

        return {
            'total_fields': len(all_fields),
            'total_classes_with_fields': len(class_field_map),
            'access_distribution': dict(access_counter),
            'type_distribution': dict(type_counter.most_common(20)),
            'sensitive_fields': sensitive_fields,
            'sensitive_count': len(sensitive_fields),
            'sensitive_by_category': {k: len(v) for k, v in sensitive_by_cat.items()},
            'constant_count': len(constants),
            'constants_sample': constants[:50],
            'top_20_classes_by_field_count': top_classes,
        }

    @staticmethod
    def get_summary(analysis_result):
        """生成简洁摘要"""
        return {
            'total_fields': analysis_result['total_fields'],
            'classes_with_fields': analysis_result['total_classes_with_fields'],
            'sensitive_count': analysis_result['sensitive_count'],
            'sensitive_categories': analysis_result['sensitive_by_category'],
            'constant_count': analysis_result['constant_count'],
            'access_distribution': analysis_result['access_distribution'],
            'top_5_field_heavy_classes': analysis_result['top_20_classes_by_field_count'][:5],
        }
