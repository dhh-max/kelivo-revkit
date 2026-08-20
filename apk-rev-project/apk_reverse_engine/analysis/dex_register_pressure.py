"""DEX 寄存器压力分析 — 寄存器分配/参数寄存器/调用帧/高压力方法检测"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict

class DexRegisterPressureAnalyzer:
    """DEX 寄存器压力深度分析 — 识别高寄存器消耗方法/调用帧深度/方法复杂度关联"""

    # Dalvik 寄存器压力阈值
    HIGH_REG_THRESHOLD = 16    # >16 寄存器视为高压力
    VERY_HIGH_REG_THRESHOLD = 32  # >32 寄存器视为极高压力
    HIGH_OUTS_THRESHOLD = 8    # 调用帧 >8 视为深调用链

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中所有方法的寄存器使用模式"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()

        if not class_defs:
            return {'error': '无类定义数据'}

        total_methods = 0
        methods_with_code = 0
        reg_size_dist = Counter()       # 寄存器数量分布
        ins_size_dist = Counter()       # 参数寄存器分布
        outs_size_dist = Counter()      # 调用帧分布
        high_pressure = []              # 高寄存器压力方法
        very_high = []                  # 极高压力方法
        high_outs = []                  # 深调用链方法
        class_reg_stats = defaultdict(lambda: {'max_regs': 0, 'total_regs': 0, 'methods': 0})
        reg_vs_insns = []               # 寄存器 vs 指令数（散点数据）

        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            for m in all_methods:
                total_methods += 1
                code = m.get('code')
                if not code or isinstance(code, dict) and 'error' in code:
                    continue
                methods_with_code += 1

                regs = code.get('registers_size', 0)
                ins = code.get('ins_size', 0)
                outs = code.get('outs_size', 0)
                insns = code.get('insns_size', 0)
                tries = code.get('tries_size', 0)

                reg_size_dist[regs] += 1
                ins_size_dist[ins] += 1
                outs_size_dist[outs] += 1

                # 寄存器 vs 指令散点
                reg_vs_insns.append({'regs': regs, 'insns': insns})

                # 类统计
                cs = class_reg_stats[cls_name]
                cs['max_regs'] = max(cs['max_regs'], regs)
                cs['total_regs'] += regs
                cs['methods'] += 1

                # 高压力检测
                method_name = m.get('name', '?')
                proto = m.get('proto') or {}
                ret = proto.get('return_type', '') if isinstance(proto, dict) else ''
                params = proto.get('parameters', []) if isinstance(proto, dict) else []
                sig = f"{method_name}({','.join(params)}){ret}"

                entry = {
                    'class': cls_name,
                    'method': method_name,
                    'signature': sig,
                    'registers': regs,
                    'ins': ins,
                    'outs': outs,
                    'insns': insns,
                    'tries': tries,
                }

                if regs >= DexRegisterPressureAnalyzer.VERY_HIGH_REG_THRESHOLD:
                    very_high.append(entry)
                elif regs >= DexRegisterPressureAnalyzer.HIGH_REG_THRESHOLD:
                    high_pressure.append(entry)

                if outs >= DexRegisterPressureAnalyzer.HIGH_OUTS_THRESHOLD:
                    high_outs.append(entry)

        # 排序
        high_pressure.sort(key=lambda x: x['registers'], reverse=True)
        very_high.sort(key=lambda x: x['registers'], reverse=True)
        high_outs.sort(key=lambda x: x['outs'], reverse=True)

        # 类级寄存器统计 Top
        class_top = sorted(
            [(k.replace('L', '').replace(';', '').replace('/', '.'), v) for k, v in class_reg_stats.items()],
            key=lambda x: x[1]['max_regs'], reverse=True
        )[:30]

        # 寄存器区间统计
        reg_ranges = {
            '0-4': sum(v for k, v in reg_size_dist.items() if k <= 4),
            '5-8': sum(v for k, v in reg_size_dist.items() if 5 <= k <= 8),
            '9-12': sum(v for k, v in reg_size_dist.items() if 9 <= k <= 12),
            '13-16': sum(v for k, v in reg_size_dist.items() if 13 <= k <= 16),
            '17-24': sum(v for k, v in reg_size_dist.items() if 17 <= k <= 24),
            '25-32': sum(v for k, v in reg_size_dist.items() if 25 <= k <= 32),
            '33+': sum(v for k, v in reg_size_dist.items() if k >= 33),
        }

        # 调用帧区间
        outs_ranges = {
            '0-2': sum(v for k, v in outs_size_dist.items() if k <= 2),
            '3-4': sum(v for k, v in outs_size_dist.items() if 3 <= k <= 4),
            '5-6': sum(v for k, v in outs_size_dist.items() if 5 <= k <= 6),
            '7-8': sum(v for k, v in outs_size_dist.items() if 7 <= k <= 8),
            '9+': sum(v for k, v in outs_size_dist.items() if k >= 9),
        }

        # 平均值
        avg_regs = round(sum(k * v for k, v in reg_size_dist.items()) / max(methods_with_code, 1), 2)
        avg_outs = round(sum(k * v for k, v in outs_size_dist.items()) / max(methods_with_code, 1), 2)
        avg_ins = round(sum(k * v for k, v in ins_size_dist.items()) / max(methods_with_code, 1), 2)

        return {
            'total_methods': total_methods,
            'methods_with_code': methods_with_code,
            'avg_registers': avg_regs,
            'avg_ins': avg_ins,
            'avg_outs': avg_outs,
            'high_pressure_count': len(high_pressure),
            'very_high_pressure_count': len(very_high),
            'high_outs_count': len(high_outs),
            'register_ranges': reg_ranges,
            'outs_ranges': outs_ranges,
            'top_high_pressure': high_pressure[:30],
            'top_very_high': very_high[:20],
            'top_high_outs': high_outs[:20],
            'top_classes_by_regs': [
                {'class': c, 'max_regs': s['max_regs'], 'avg_regs': round(s['total_regs'] / max(s['methods'], 1), 1), 'methods': s['methods']}
                for c, s in class_top
            ],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'methods_with_code': result['methods_with_code'],
            'avg_regs': result['avg_registers'],
            'avg_outs': result['avg_outs'],
            'high_pressure': result['high_pressure_count'],
            'very_high': result['very_high_pressure_count'],
            'high_outs': result['high_outs_count'],
            'reg_ranges': result['register_ranges'],
        }
