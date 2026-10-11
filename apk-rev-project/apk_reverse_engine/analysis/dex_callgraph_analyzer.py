"""DEX 方法调用图分析 — 方法间调用关系/高频调用方法/调用环检测"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict, Counter

class DexCallGraphAnalyzer:
    """DEX 方法调用图分析引擎"""

    # 方法调用相关指令（invoke-*）
    INVOKE_OPCODES = {
        0x6e: 'invoke-virtual',
        0x6f: 'invoke-super',
        0x70: 'invoke-direct',
        0x71: 'invoke-static',
        0x72: 'invoke-interface',
        0x73: 'invoke-virtual/range',
        0x74: 'invoke-super/range',
        0x75: 'invoke-direct/range',
        0x76: 'invoke-static/range',
        0x77: 'invoke-interface/range',
    }

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中的方法调用图"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        methods = dex_parser.get_methods()
        strings = dex_parser.get_strings()

        # 构建调用图
        call_graph = defaultdict(list)  # caller -> [callees]
        reverse_call_graph = defaultdict(list)  # callee -> [callers]
        method_call_counts = Counter()  # callee -> call count
        caller_method_count = Counter()  # caller -> total calls made

        total_calls = 0
        total_methods_with_code = 0

        for cd_idx, cd in enumerate(class_defs):
            class_name = dex_parser._get_type_string(cd) if hasattr(dex_parser, '_get_type_string') else f'class_{cd_idx}'
            if class_name.startswith('['):
                continue

            cd_methods = cd.get('methods', [])
            for m_idx, method in enumerate(cd_methods):
                code_off = method.get('code_off', 0)
                if code_off == 0:
                    continue

                total_methods_with_code += 1
                code_item = dex_parser._parse_code_item(code_off)
                if not code_item or not code_item.get('insns'):
                    continue

                caller_name, caller_sig = dex_parser.get_method_signature(method)
                caller_key = f"{class_name}->{caller_name}{caller_sig}"

                for insn in code_item['insns']:
                    if isinstance(insn, (list, tuple)):
                        opcode = insn[0] if insn else 0
                    elif isinstance(insn, dict):
                        opcode = insn.get('opcode', 0)
                    else:
                        opcode = insn

                    if opcode in DexCallGraphAnalyzer.INVOKE_OPCODES:
                        # 尝试获取被调用的方法索引
                        callee_method_idx = None
                        if isinstance(insn, (list, tuple)) and len(insn) > 1:
                            callee_method_idx = insn[1] if isinstance(insn[1], int) else None
                        elif isinstance(insn, dict):
                            callee_method_idx = insn.get('method_idx') or insn.get('register')

                        callee_name = f"method_{callee_method_idx}" if callee_method_idx is not None else "unknown"
                        if callee_method_idx is not None and 0 <= callee_method_idx < len(methods):
                            try:
                                callee_method = methods[callee_method_idx]
                                callee_name, callee_sig = dex_parser.get_method_signature(callee_method)
                            except:
                                pass

                        call_graph[caller_key].append(callee_name)
                        reverse_call_graph[callee_name].append(caller_key)
                        method_call_counts[callee_name] += 1
                        caller_method_count[caller_key] += 1
                        total_calls += 1

        # 最被调用的方法（热点方法）
        most_called = method_call_counts.most_common(20)

        # 调用最多的方法（扇出最高）
        most_calling = caller_method_count.most_common(20)

        # 找出调用环（简化版 - 只检测2环和3环）
        cycles = DexCallGraphAnalyzer._detect_cycles(call_graph, max_depth=3)

        # 孤立方法（无调用者也未被调用）
        all_method_keys = set(caller_method_count.keys()) | set(method_call_counts.keys())
        methods_with_callers = set(reverse_call_graph.keys())
        methods_with_callees = set(call_graph.keys())

        # 统计
        unique_callers = len(caller_method_count)
        unique_callees = len(method_call_counts)

        return {
            'total_methods_with_code': total_methods_with_code,
            'total_calls': total_calls,
            'unique_callers': unique_callers,
            'unique_callees': unique_callees,
            'avg_calls_per_method': round(total_calls / max(total_methods_with_code, 1), 2),
            'most_called_methods': [
                {'method': m, 'call_count': c} for m, c in most_called
            ],
            'most_calling_methods': [
                {'method': m, 'calls_made': c} for m, c in most_calling
            ],
            'cycles_detected': cycles[:20],
            'cycle_count': len(cycles),
            'call_graph_size': len(call_graph),
            'reverse_graph_size': len(reverse_call_graph),
        }

    @staticmethod
    def _detect_cycles(graph, max_depth=3):
        """检测调用环（深度受限）"""
        cycles = []
        visited_global = set()

        for start in list(graph.keys())[:500]:  # 限制搜索范围
            if start in visited_global:
                continue
            DexCallGraphAnalyzer._dfs_cycle(start, start, graph, [], set(), cycles, max_depth, 0)
            visited_global.add(start)

        return cycles

    @staticmethod
    def _dfs_cycle(start, current, graph, path, visited, cycles, max_depth, depth):
        if depth >= max_depth:
            return
        if current in visited:
            return
        visited.add(current)
        path.append(current)

        for callee in graph.get(current, []):
            if callee == start and len(path) >= 2:
                cycles.append(list(path))
            elif callee not in visited:
                DexCallGraphAnalyzer._dfs_cycle(start, callee, graph, path, visited, cycles, max_depth, depth + 1)

        path.pop()
        visited.discard(current)

    @staticmethod
    def get_summary(result):
        return {
            'total_methods': result['total_methods_with_code'],
            'total_calls': result['total_calls'],
            'avg_calls_per_method': result['avg_calls_per_method'],
            'top5_called': result['most_called_methods'][:5],
            'top5_calling': result['most_calling_methods'][:5],
            'cycles': result['cycle_count'],
        }