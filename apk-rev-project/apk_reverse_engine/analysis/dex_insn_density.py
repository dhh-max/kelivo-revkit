"""DEX 方法指令密度分析 — 指令量分布/大方法检测/代码膨胀/方法体积热度图"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict

class DexInsnDensityAnalyzer:
    """DEX 指令密度深度分析 — 方法体积/代码膨胀/热区方法/类复杂度关联"""

    # 指令量阈值
    SMALL_METHOD = 10       # <10 指令 = 小方法
    MEDIUM_METHOD = 50      # 10-50 = 中等方法
    LARGE_METHOD = 100      # 50-100 = 大方法
    HUGE_METHOD = 200       # >200 = 巨型方法
    MEGA_METHOD = 500       # >500 = 超大方法

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中所有方法的指令密度与代码体积"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()

        if not class_defs:
            return {'error': '无类定义数据'}

        total_methods = 0
        methods_with_code = 0
        total_insns = 0
        insn_dist = Counter()             # 指令数分布
        size_categories = Counter()       # 方法体积分类
        huge_methods = []                 # 巨型方法列表
        mega_methods = []                 # 超大方法列表
        class_insn_stats = defaultdict(lambda: {'total_insns': 0, 'methods': 0, 'max_insns': 0, 'code_methods': 0})
        native_methods = []               # Native 方法
        abstract_methods = 0
        total_registers = 0

        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            cs = class_insn_stats[cls_name]
            for m in all_methods:
                total_methods += 1
                flags = m.get('access_flags', '')
                method_name = m.get('name', '?')
                proto = m.get('proto') or {}
                ret = proto.get('return_type', '') if isinstance(proto, dict) else ''
                params = proto.get('parameters', []) if isinstance(proto, dict) else []
                sig = f"{method_name}({','.join(params)}){ret}"

                # Native/Abstract
                if 'NATIVE' in (flags or ''):
                    native_methods.append({
                        'class': cls_name, 'method': method_name, 'signature': sig,
                        'flags': flags,
                    })
                    continue
                if 'ABSTRACT' in (flags or ''):
                    abstract_methods += 1
                    continue

                code = m.get('code')
                if not code or isinstance(code, dict) and 'error' in code:
                    continue
                methods_with_code += 1
                insns = code.get('insns_size', 0)
                regs = code.get('registers_size', 0)
                total_insns += insns
                total_registers += regs
                insn_dist[insns // 10 * 10] += 1  # 按10分组
                cs['total_insns'] += insns
                cs['methods'] += 1
                cs['code_methods'] += 1
                cs['max_insns'] = max(cs['max_insns'], insns)

                entry = {
                    'class': cls_name,
                    'method': method_name,
                    'signature': sig,
                    'insns': insns,
                    'registers': regs,
                    'flags': flags,
                }

                if insns >= DexInsnDensityAnalyzer.MEGA_METHOD:
                    mega_methods.append(entry)
                    size_categories['mega'] += 1
                elif insns >= DexInsnDensityAnalyzer.HUGE_METHOD:
                    huge_methods.append(entry)
                    size_categories['huge'] += 1
                elif insns >= DexInsnDensityAnalyzer.LARGE_METHOD:
                    size_categories['large'] += 1
                elif insns >= DexInsnDensityAnalyzer.SMALL_METHOD:
                    size_categories['medium'] += 1
                else:
                    size_categories['small'] += 1

        # 排序
        huge_methods.sort(key=lambda x: x['insns'], reverse=True)
        mega_methods.sort(key=lambda x: x['insns'], reverse=True)

        # 类级 Top
        class_top = sorted(
            [(k.replace('L', '').replace(';', '').replace('/', '.'), v) for k, v in class_insn_stats.items() if v['code_methods'] > 0],
            key=lambda x: x[1]['total_insns'], reverse=True
        )[:30]

        # 统计
        avg_insns = round(total_insns / max(methods_with_code, 1), 1)
        avg_regs = round(total_registers / max(methods_with_code, 1), 1)
        insn_per_class = round(total_insns / max(len(class_defs), 1), 1)

        return {
            'total_methods': total_methods,
            'methods_with_code': methods_with_code,
            'native_methods': len(native_methods),
            'abstract_methods': abstract_methods,
            'total_insns': total_insns,
            'avg_insns_per_method': avg_insns,
            'avg_regs_per_method': avg_regs,
            'avg_insns_per_class': insn_per_class,
            'size_categories': dict(size_categories),
            'huge_method_count': len(huge_methods),
            'mega_method_count': len(mega_methods),
            'top_huge_methods': huge_methods[:30],
            'top_mega_methods': mega_methods[:20],
            'top_classes_by_insns': [
                {'class': c, 'total_insns': s['total_insns'], 'max_insns': s['max_insns'],
                 'avg_insns': round(s['total_insns'] / max(s['code_methods'], 1), 1), 'methods': s['code_methods']}
                for c, s in class_top
            ],
            'native_method_list': native_methods[:30],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'methods_with_code': result['methods_with_code'],
            'total_insns': result['total_insns'],
            'avg_insns': result['avg_insns_per_method'],
            'huge_methods': result['huge_method_count'],
            'mega_methods': result['mega_method_count'],
            'native_methods': result['native_methods'],
            'size_categories': result['size_categories'],
            'top5_classes': result['top_classes_by_insns'][:5],
        }