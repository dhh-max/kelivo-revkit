"""DEX 代码复杂度分析 — 圈复杂度/嵌套深度/方法长度/认知复杂度"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict

class DexComplexityAnalyzer:
    """DEX 代码复杂度分析引擎"""

    # 分支/循环节点
    BRANCH_OPCODES = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
    }

    # try-catch 块
    TRY_OPCODE = 0x13  # sparse-switch

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中所有方法的复杂度"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        methods_result = []
        total_complexity = 0
        max_complexity = 0
        complexity_dist = {'low': 0, 'medium': 0, 'high': 0, 'extreme': 0}

        for cd_idx, cd in enumerate(class_defs):
            class_name = dex_parser._get_type_string(cd) if hasattr(dex_parser, '_get_type_string') else f'class_{cd_idx}'
            if class_name.startswith('['):
                continue
            methods = cd.get('methods', [])
            for m_idx, method in enumerate(methods):
                code_off = method.get('code_off', 0)
                if code_off == 0:
                    continue
                code_item = dex_parser._parse_code_item(code_off)
                if not code_item or not code_item.get('insns'):
                    continue
                insns = code_item['insns']
                registers_size = code_item.get('registers_size', 0)

                method_name, method_sig = dex_parser.get_method_signature(method)
                complexity = DexComplexityAnalyzer._calc_cyclomatic_complexity(insns)
                nesting = DexComplexityAnalyzer._estimate_nesting_depth(insns)
                method_len = len(insns)
                cognitive = complexity + nesting * 2

                total_complexity += complexity
                if complexity > max_complexity:
                    max_complexity = complexity

                if complexity <= 5:
                    complexity_dist['low'] += 1
                elif complexity <= 10:
                    complexity_dist['medium'] += 1
                elif complexity <= 20:
                    complexity_dist['high'] += 1
                else:
                    complexity_dist['extreme'] += 1

                methods_result.append({
                    'class': class_name,
                    'method': method_name,
                    'signature': method_sig,
                    'cyclomatic_complexity': complexity,
                    'nesting_depth': nesting,
                    'cognitive_complexity': cognitive,
                    'method_length': method_len,
                    'registers': registers_size,
                    'code_size_bytes': method_len * 2,
                })

        methods_result.sort(key=lambda x: x['cyclomatic_complexity'], reverse=True)
        total_methods = len(methods_result)
        avg_complexity = round(total_complexity / max(total_methods, 1), 2)

        return {
            'total_methods': total_methods,
            'avg_cyclomatic_complexity': avg_complexity,
            'max_cyclomatic_complexity': max_complexity,
            'complexity_distribution': complexity_dist,
            'top_complex_methods': methods_result[:20],
            'all_methods': methods_result if total_methods <= 200 else methods_result[:200],
        }

    @staticmethod
    def _calc_cyclomatic_complexity(insns):
        """计算圈复杂度 — 分支节点数 + 1"""
        branch_count = 1
        for insn in insns:
            if isinstance(insn, (list, tuple)):
                opcode = insn[0] if insn else 0
            elif isinstance(insn, dict):
                opcode = insn.get('opcode', 0)
            else:
                opcode = insn
            if opcode in DexComplexityAnalyzer.BRANCH_OPCODES:
                branch_count += 1
        return branch_count

    @staticmethod
    def _estimate_nesting_depth(insns):
        """估算最大嵌套深度 — 基于分支指令的嵌套"""
        depth = 0
        max_depth = 0
        for insn in insns:
            if isinstance(insn, (list, tuple)):
                opcode = insn[0] if insn else 0
            elif isinstance(insn, dict):
                opcode = insn.get('opcode', 0)
            else:
                opcode = insn
            if opcode in DexComplexityAnalyzer.BRANCH_OPCODES:
                depth += 1
                if depth > max_depth:
                    max_depth = depth
            # 简化的深度回退
            if opcode == 0x0e:  # return-void
                depth = max(0, depth - 1)
        return max_depth

    @staticmethod
    def get_summary(result):
        """生成摘要"""
        return {
            'total_methods': result['total_methods'],
            'avg_complexity': result['avg_cyclomatic_complexity'],
            'max_complexity': result['max_cyclomatic_complexity'],
            'distribution': result['complexity_distribution'],
            'top5_complex': [
                {
                    'method': f"{m['class']}->{m['method']}",
                    'cc': m['cyclomatic_complexity'],
                    'cognitive': m['cognitive_complexity'],
                    'length': m['method_length'],
                }
                for m in result['top_complex_methods'][:5]
            ],
        }
