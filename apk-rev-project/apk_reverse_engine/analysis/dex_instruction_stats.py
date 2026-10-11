"""DEX 指令级统计分析 — 指令频率/寄存器压力/异常处理/调试信息覆盖"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict

class DexInstructionStatsAnalyzer:
    """DEX 指令级深度分析 — 指令分布/寄存器使用/try-catch/调试覆盖率"""

    # Dalvik 指令分类
    OPCODE_CATEGORIES = {
        # 常量加载
        0x00: 'const', 0x01: 'const', 0x02: 'const', 0x03: 'const',
        0x04: 'const', 0x05: 'const', 0x06: 'const', 0x07: 'const',
        0x08: 'const', 0x09: 'const', 0x0A: 'const', 0x0B: 'const',
        0x0C: 'const', 0x0D: 'const', 0x0E: 'const',
        # 数组长度
        0x21: 'array',
        # 类型/实例
        0x1F: 'type_check', 0x20: 'type_check',
        # 字段访问
        0x52: 'field', 0x53: 'field', 0x54: 'field', 0x55: 'field',
        0x56: 'field', 0x57: 'field', 0x58: 'field', 0x59: 'field',
        0x5A: 'field', 0x5B: 'field', 0x5C: 'field', 0x5D: 'field',
        0x5E: 'field', 0x5F: 'field', 0x60: 'field', 0x61: 'field',
        0x62: 'field', 0x63: 'field', 0x64: 'field', 0x65: 'field',
        0x66: 'field', 0x67: 'field', 0x68: 'field', 0x69: 'field',
        # 方法调用
        0x6E: 'invoke', 0x6F: 'invoke', 0x70: 'invoke', 0x71: 'invoke',
        0x72: 'invoke', 0x74: 'invoke', 0x75: 'invoke', 0x76: 'invoke',
        0x77: 'invoke', 0x78: 'invoke',
        # 新实例/数组
        0x22: 'new', 0x23: 'new',
        # 算术运算
        0x7B: 'arith', 0x7C: 'arith', 0x7D: 'arith', 0x7E: 'arith',
        0x7F: 'arith', 0x80: 'arith', 0x81: 'arith', 0x82: 'arith',
        0x83: 'arith', 0x84: 'arith', 0x85: 'arith', 0x86: 'arith',
        0x87: 'arith', 0x88: 'arith', 0x89: 'arith', 0x8A: 'arith',
        0x8B: 'arith', 0x8C: 'arith', 0x8D: 'arith', 0x8E: 'arith',
        # 比较
        0x94: 'compare',
        # 分支跳转
        0x28: 'branch', 0x29: 'branch', 0x2A: 'branch', 0x2B: 'branch',
        0x2C: 'branch', 0x2D: 'branch', 0x2E: 'branch', 0x2F: 'branch',
        0x30: 'branch', 0x31: 'branch',
        # 比较/分支
        0x32: 'branch', 0x33: 'branch', 0x34: 'branch', 0x35: 'branch',
        # 返回
        0x0E: 'return', 0x0F: 'return', 0x10: 'return', 0x11: 'return',
        0x12: 'return',
        # 移动
        0x01: 'move', 0x02: 'move', 0x03: 'move', 0x04: 'move',
        0x05: 'move', 0x06: 'move', 0x07: 'move',
        # 异常
        0x27: 'throw',
        # 监视器
        0x1D: 'monitor', 0x1E: 'monitor',
        # 空操作
        0x00: 'nop',
    }

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 指令级统计"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()

        # 指令类别统计
        category_stats = Counter()
        opcode_stats = Counter()

        # 寄存器统计
        register_stats = {
            'max_registers': 0,
            'max_ins': 0,
            'max_outs': 0,
            'total_registers': 0,
            'total_methods_with_code': 0,
        }

        # try/catch 统计
        try_catch_stats = {
            'methods_with_try': 0,
            'total_try_blocks': 0,
            'total_handlers': 0,
        }

        # 调试信息统计
        debug_stats = {
            'methods_with_debug': 0,
            'methods_without_debug': 0,
        }

        # 指令量分布
        insn_count_dist = Counter()
        # 指令量最大的方法
        top_methods_by_insns = []

        total_methods = 0
        total_fields = 0

        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            total_methods += len(all_methods)
            total_fields += len(cd.get('static_fields') or []) + len(cd.get('instance_fields') or [])

            for m in all_methods:
                code = m.get('code')
                if not code:
                    continue

                register_stats['total_methods_with_code'] += 1
                regs = code.get('registers_size', 0)
                ins = code.get('ins_size', 0)
                outs = code.get('outs_size', 0)
                register_stats['total_registers'] += regs
                register_stats['max_registers'] = max(register_stats['max_registers'], regs)
                register_stats['max_ins'] = max(register_stats['max_ins'], ins)
                register_stats['max_outs'] = max(register_stats['max_outs'], outs)

                insns_size = code.get('insns_size', 0)
                if insns_size > 0:
                    insn_count_dist[
                        '0-5' if insns_size <= 5 else
                        '6-15' if insns_size <= 15 else
                        '16-50' if insns_size <= 50 else
                        '51-100' if insns_size <= 100 else
                        '101-500' if insns_size <= 500 else
                        '500+'
                    ] += 1

                # try/catch
                tries = code.get('tries') or []
                if tries:
                    try_catch_stats['methods_with_try'] += 1
                    try_catch_stats['total_try_blocks'] += len(tries)

                # 调试信息
                if code.get('debug_info_off', 0) != 0:
                    debug_stats['methods_with_debug'] += 1
                else:
                    debug_stats['methods_without_debug'] += 1

                # 解析指令字节提取 opcode
                insns_start = code.get('insns_start', 0)
                insns_bytes = code.get('insns_bytes', 0)
                if insns_start and insns_bytes:
                    data = dex_parser.data
                    end = min(insns_start + insns_bytes, len(data))
                    pos = insns_start
                    while pos + 2 <= end:
                        try:
                            opcode = data[pos] & 0xFF
                            category = DexInstructionStatsAnalyzer.OPCODE_CATEGORIES.get(opcode, 'other')
                            category_stats[category] += 1
                            opcode_stats[opcode] += 1
                            # 简化跳转：按最小指令宽度推进
                            pos += 2
                        except Exception:
                            pos += 2

                if insns_size > 0:
                    top_methods_by_insns.append({
                        'class': cls_name.replace('L', '').replace(';', '').replace('/', '.'),
                        'method': m.get('name', ''),
                        'insns': insns_size,
                        'registers': regs,
                        'tries': len(tries),
                    })

        top_methods_by_insns.sort(key=lambda x: x['insns'], reverse=True)

        # 寄存器平均值
        code_methods = register_stats['total_methods_with_code']
        avg_regs = round(register_stats['total_registers'] / max(code_methods, 1), 1)

        # 调试覆盖率
        debug_coverage = round(debug_stats['methods_with_debug'] / max(code_methods, 1) * 100, 1)

        # try-catch 覆盖率
        try_coverage = round(try_catch_stats['methods_with_try'] / max(code_methods, 1) * 100, 1)

        return {
            'total_methods': total_methods,
            'total_methods_with_code': code_methods,
            'total_fields': total_fields,
            'instruction_categories': dict(category_stats.most_common()),
            'top_opcodes': [
                {'opcode': hex(op), 'category': DexInstructionStatsAnalyzer.OPCODE_CATEGORIES.get(op, 'other'), 'count': cnt}
                for op, cnt in opcode_stats.most_common(20)
            ],
            'register_stats': {**register_stats, 'avg_registers': avg_regs},
            'try_catch_stats': {**try_catch_stats, 'coverage_pct': try_coverage},
            'debug_stats': {**debug_stats, 'coverage_pct': debug_coverage},
            'insn_count_distribution': dict(insn_count_dist),
            'top_methods_by_insns': top_methods_by_insns[:30],
        }

    @staticmethod
    def get_summary(result):
        return {
            'total_methods': result['total_methods'],
            'code_methods': result['total_methods_with_code'],
            'top_category': list(result['instruction_categories'].items())[:5],
            'max_registers': result['register_stats']['max_registers'],
            'avg_registers': result['register_stats']['avg_registers'],
            'try_coverage': result['try_catch_stats']['coverage_pct'],
            'debug_coverage': result['debug_stats']['coverage_pct'],
            'top5_methods': result['top_methods_by_insns'][:5],
        }
