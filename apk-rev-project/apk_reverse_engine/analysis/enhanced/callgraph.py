"""调用图构建器 - DEX方法间调用关系、类层次、可达性分析"""
from collections import defaultdict, deque

class CallGraphBuilder:
    """构建DEX方法间调用图，支持反向可达性分析"""

    # invoke opcode set
    INVOKE_OPS = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}

    @staticmethod
    def build_call_graph(dex_parser):
        """从 DexParser 构建全量调用图

        Returns:
            dict: {
                'nodes': [{class, method, proto, access_flags, is_external}],
                'edges': [{caller_class, caller_method, callee_class, callee_method, opcode, address}],
                'adjacency': {class.method -> [callee_class.method, ...]},
                'reverse_adjacency': {callee_class.method -> [caller_class.method, ...]},
            }
        """
        dp = dex_parser
        dp._ensure_parsed()

        nodes = []
        edges = []
        adjacency = defaultdict(list)
        reverse_adjacency = defaultdict(list)
        node_set = set()

        methods_meta = dp.get_methods()

        for cls in dp.get_class_defs():
            cls_name = cls['class_name']
            all_methods = cls.get('direct_methods', []) + cls.get('virtual_methods', [])

            for m in all_methods:
                node_id = f"{cls_name}.{m.get('name', '')}"
                if node_id not in node_set:
                    node_set.add(node_id)
                    nodes.append({
                        'id': node_id,
                        'class': cls_name,
                        'method': m.get('name'),
                        'proto': m.get('proto'),
                        'access_flags': m.get('access_flags'),
                        'is_external': False,
                    })

                # 解析方法体中的invoke指令
                code = m.get('code')
                if not code:
                    continue

                insns_start = code.get('insns_start', 0)
                insns_size = code.get('insns_size', 0)
                if insns_start == 0 or insns_size == 0:
                    continue

                from ..core.dex.instruction_decoder import InstructionDecoder
                data = dp.data
                insns_end = min(insns_start + insns_size * 2, len(data))
                pos = insns_start
                while pos < insns_end:
                    inst = InstructionDecoder.decode(data, pos)
                    if inst.opcode in CallGraphBuilder.INVOKE_OPS:
                        ref = inst.operands.get('ref', -1)
                        if methods_meta and 0 <= ref < len(methods_meta):
                            callee = methods_meta[ref]
                            callee_cls = callee.get('class_name', '?')
                            callee_name = callee.get('name', '?')
                            callee_proto = callee.get('proto', '')
                            callee_id = f"{callee_cls}.{callee_name}"

                            if callee_id not in node_set:
                                node_set.add(callee_id)
                                nodes.append({
                                    'id': callee_id,
                                    'class': callee_cls,
                                    'method': callee_name,
                                    'proto': callee_proto,
                                    'access_flags': '',
                                    'is_external': True,
                                })

                            edges.append({
                                'caller': node_id,
                                'callee': callee_id,
                                'callee_class': callee_cls,
                                'callee_method': callee_name,
                                'opcode': inst.opcode,
                                'opcode_name': inst.name,
                                'address': inst.address,
                            })
                            adjacency[node_id].append(callee_id)
                            reverse_adjacency[callee_id].append(node_id)

                    pos += inst.size * 2

        return {
            'nodes': nodes,
            'edges': edges,
            'adjacency': dict(adjacency),
            'reverse_adjacency': dict(reverse_adjacency),
            'total_nodes': len(nodes),
            'total_edges': len(edges),
            'external_nodes': sum(1 for n in nodes if n['is_external']),
            'internal_nodes': sum(1 for n in nodes if not n['is_external']),
        }

    @staticmethod
    def find_callers(call_graph, target_class, target_method=None):
        """反向查找谁调用了指定方法"""
        if target_method:
            target_id = f"{target_class}.{target_method}"
        else:
            target_id = target_class

        reverse_adj = call_graph.get('reverse_adjacency', {})
        direct_callers = set(reverse_adj.get(target_id, []))

        # BFS for transitive callers
        all_callers = set()
        queue = deque(direct_callers)
        while queue:
            caller = queue.popleft()
            if caller in all_callers:
                continue
            all_callers.add(caller)
            for c in reverse_adj.get(caller, []):
                if c not in all_callers:
                    queue.append(c)

        return {
            'target': target_id,
            'direct_callers': sorted(direct_callers),
            'transitive_callers': sorted(all_callers - direct_callers),
            'total_callers': len(all_callers),
        }

    @staticmethod
    def find_callees(call_graph, source_class, source_method=None):
        """正向查找指定方法调用了哪些方法"""
        if source_method:
            source_id = f"{source_class}.{source_method}"
        else:
            source_id = source_class

        adjacency = call_graph.get('adjacency', {})
        direct_callees = set(adjacency.get(source_id, []))

        # BFS for transitive callees
        all_callees = set()
        queue = deque(direct_callees)
        while queue:
            callee = queue.popleft()
            if callee in all_callees:
                continue
            all_callees.add(callee)
            for c in adjacency.get(callee, []):
                if c not in all_callees:
                    queue.append(c)

        return {
            'source': source_id,
            'direct_callees': sorted(direct_callees),
            'transitive_callees': sorted(all_callees - direct_callees),
            'total_callees': len(all_callees),
        }

    @staticmethod
    def find_entry_points(call_graph):
        """查找入口点 - 没有被任何方法调用的内部方法"""
        reverse_adj = call_graph.get('reverse_adjacency', {})
        entries = []
        for node in call_graph.get('nodes', []):
            if node['is_external']:
                continue
            callers = reverse_adj.get(node['id'], [])
            internal_callers = [c for c in callers if not c.startswith('?')]
            if not internal_callers:
                entries.append(node['id'])
        return sorted(entries)

    @staticmethod
    def find_hotspots(call_graph, top_n=20):
        """查找热点方法 - 被调用次数最多的方法"""
        reverse_adj = call_graph.get('reverse_adjacency', {})
        counts = []
        for node_id, callers in reverse_adj.items():
            internal_callers = [c for c in callers if not c.startswith('?')]
            counts.append({
                'method': node_id,
                'caller_count': len(internal_callers),
            })
        counts.sort(key=lambda x: x['caller_count'], reverse=True)
        return counts[:top_n]

    @staticmethod
    def detect_recursive(call_graph):
        """检测递归调用"""
        adjacency = call_graph.get('adjacency', {})
        recursive = []
        for node_id, callees in adjacency.items():
            if node_id in callees:
                recursive.append({
                    'method': node_id,
                    'type': 'direct_recursion',
                })
        # indirect recursion (cycles)
        for node_id in adjacency:
            visited = set()
            queue = deque(adjacency.get(node_id, []))
            while queue:
                callee = queue.popleft()
                if callee == node_id and callee not in visited:
                    recursive.append({
                        'method': node_id,
                        'type': 'indirect_recursion',
                    })
                    break
                if callee in visited:
                    continue
                visited.add(callee)
                queue.extend(adjacency.get(callee, []))
        return recursive