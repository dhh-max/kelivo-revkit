"""DEX 字段使用分析 — 字段访问模式/静态字段/final字段/字段类型分布"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict, Counter

class DexFieldUsageAnalyzer:
    """DEX 字段使用深度分析引擎"""

    # 字段访问指令
    IGET_OPCODES = {0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63}
    IPUT_OPCODES = {0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6d}
    SGET_OPCODES = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f}
    SPUT_OPCODES = {0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76}

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中字段的定义和使用"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        fields = dex_parser.get_fields()
        strings = dex_parser.get_strings()
        types = dex_parser.get_types()

        field_defs = []
        field_access_counter = Counter()  # field_name -> read count
        field_write_counter = Counter()   # field_name -> write count
        type_distribution = Counter()
        access_flag_stats = Counter()

        # 收集字段定义
        for cd_idx, cd in enumerate(class_defs):
            class_name = dex_parser._get_type_string(cd) if hasattr(dex_parser, '_get_type_string') else f'class_{cd_idx}'
            if class_name.startswith('['):
                continue

            cd_fields = cd.get('fields', [])
            for f_idx, field in enumerate(cd_fields):
                field_idx = field.get('field_idx', 0)
                access_flags = field.get('access_flags', 0)

                field_name = ''
                field_type = ''
                if 0 <= field_idx < len(fields):
                    f = fields[field_idx]
                    if isinstance(f, dict):
                        name_idx = f.get('name_idx', 0)
                        type_idx = f.get('type_idx', 0)
                        if 0 <= name_idx < len(strings):
                            field_name = strings[name_idx]
                        if 0 <= type_idx < len(types):
                            field_type = types[type_idx] if isinstance(types[type_idx], str) else str(types[type_idx])

                is_static = bool(access_flags & 0x0008)
                is_final = bool(access_flags & 0x0010)
                is_public = bool(access_flags & 0x0001)
                is_private = bool(access_flags & 0x0002)
                is_protected = bool(access_flags & 0x0004)
                is_volatile = bool(access_flags & 0x0040)
                is_transient = bool(access_flags & 0x0080)

                access_str = []
                if is_public: access_str.append('public')
                if is_private: access_str.append('private')
                if is_protected: access_str.append('protected')
                if is_static: access_str.append('static')
                if is_final: access_str.append('final')
                if is_volatile: access_str.append('volatile')
                if is_transient: access_str.append('transient')

                type_distribution[field_type] += 1
                access_flag_stats['static' if is_static else 'instance'] += 1
                if is_final: access_flag_stats['final'] += 1
                if is_volatile: access_flag_stats['volatile'] += 1
                if is_public: access_flag_stats['public'] += 1
                if is_private: access_flag_stats['private'] += 1

                field_defs.append({
                    'class': class_name,
                    'name': field_name,
                    'type': field_type,
                    'access_flags': ' '.join(access_str),
                    'is_static': is_static,
                    'is_final': is_final,
                    'is_volatile': is_volatile,
                })

        # 分析字段访问（从代码中）
        for cd_idx, cd in enumerate(class_defs):
            class_name = dex_parser._get_type_string(cd) if hasattr(dex_parser, '_get_type_string') else f'class_{cd_idx}'
            if class_name.startswith('['):
                continue
            cd_methods = cd.get('methods', [])
            for m_idx, method in enumerate(cd_methods):
                code_off = method.get('code_off', 0)
                if code_off == 0:
                    continue
                code_item = dex_parser._parse_code_item(code_off)
                if not code_item or not code_item.get('insns'):
                    continue

                for insn in code_item['insns']:
                    if isinstance(insn, (list, tuple)):
                        opcode = insn[0] if insn else 0
                    elif isinstance(insn, dict):
                        opcode = insn.get('opcode', 0)
                    else:
                        opcode = insn

                    if opcode in DexFieldUsageAnalyzer.IGET_OPCODES or opcode in DexFieldUsageAnalyzer.SGET_OPCODES:
                        field_access_counter['reads'] += 1
                    if opcode in DexFieldUsageAnalyzer.IPUT_OPCODES or opcode in DexFieldUsageAnalyzer.SPUT_OPCODES:
                        field_write_counter['writes'] += 1

        # 统计
        total_fields = len(field_defs)
        static_fields = sum(1 for f in field_defs if f['is_static'])
        final_fields = sum(1 for f in field_defs if f['is_final'])
        volatile_fields = sum(1 for f in field_defs if f['is_volatile'])

        # 按类统计字段数
        class_field_counts = Counter(f['class'] for f in field_defs)
        top_classes = class_field_counts.most_common(20)

        return {
            'total_fields': total_fields,
            'static_fields': static_fields,
            'instance_fields': total_fields - static_fields,
            'final_fields': final_fields,
            'volatile_fields': volatile_fields,
            'access_flag_stats': dict(access_flag_stats),
            'type_distribution': dict(type_distribution.most_common(20)),
            'field_reads': field_access_counter.get('reads', 0),
            'field_writes': field_write_counter.get('writes', 0),
            'top_classes_by_fields': [
                {'class': cls, 'field_count': cnt} for cls, cnt in top_classes
            ],
            'sample_fields': field_defs[:50],
        }

    @staticmethod
    def get_summary(result):
        return {
            'total_fields': result['total_fields'],
            'static': result['static_fields'],
            'instance': result['instance_fields'],
            'final': result['final_fields'],
            'volatile': result['volatile_fields'],
            'reads': result['field_reads'],
            'writes': result['field_writes'],
            'top5_types': list(result['type_distribution'].items())[:5],
            'top5_classes': result['top_classes_by_fields'][:5],
        }