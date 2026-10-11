"""DEX 优化模式检测器

检测 Dalvik 字节码中的编译器优化模式与反模式：
1. 常量折叠检测（const + 运算 -> const）
2. 死代码消除检测（不可达指令）
3. 寄存器分配分析（寄存器重用效率）
4. 内联检测（方法体包含被内联的调用）
5. 指令模式统计与热点检测
6. 代码膨胀检测
7. Switch 优化模式
8. 循环不变量外提检测
"""
from collections import defaultdict, Counter


class OptimizationPatternDetector:
    """DEX 字节码优化模式检测器"""

    CONST_OPS = {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19}
    ARITH_OPS = set(range(0x90, 0xe3))  # 所有算术运算
    MOVE_OPS = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
    GOTO_OPS = {0x28, 0x29, 0x2a}
    RETURN_OPS = {0x0e, 0x0f, 0x10, 0x11}
    IF_OPS = set(range(0x32, 0x3e))
    INVOKE_OPS = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
    MOVE_RESULT_OPS = {0x0a, 0x0b, 0x0c}
    NOP_OP = 0x00

    @staticmethod
    def analyze_method(instructions, cfg=None, method_info=None):
        """分析单个方法的优化模式

        Args:
            instructions: Instruction 列表
            cfg: 预构建 CFG
            method_info: 方法元信息

        Returns:
            dict: 各种优化模式检测结果
        """
        if not instructions:
            return OptimizationPatternDetector._empty_result()

        if cfg is None:
            from ..core.dex.disassembler import Disassembler
            cfg = Disassembler.build_cfg(instructions)

        result = {
            'method': method_info.get('name', '') if method_info else '',
            'instruction_count': len(instructions),
            'block_count': len(cfg['blocks']),
        }

        result.update(OptimizationPatternDetector._detect_const_folding(instructions))
        result.update(OptimizationPatternDetector._detect_dead_code(instructions, cfg))
        result.update(OptimizationPatternDetector._analyze_register_usage(instructions))
        result.update(OptimizationPatternDetector._detect_inline_patterns(instructions))
        result.update(OptimizationPatternDetector._detect_code_bloat(instructions, cfg))
        result.update(OptimizationPatternDetector._detect_switch_optimization(instructions))
        result.update(OptimizationPatternDetector._detect_loop_invariants(instructions, cfg))
        result.update(OptimizationPatternDetector._instruction_hotspot(instructions, cfg))
        result.update(OptimizationPatternDetector._detect_peephole_patterns(instructions))

        return result

    @staticmethod
    def _detect_const_folding(instructions):
        """检测常量折叠——const 后紧跟运算被预计算"""
        folded = []
        for i in range(len(instructions) - 1):
            inst = instructions[i]
            next_inst = instructions[i + 1]

            # const vA, #lit 后跟使用 vA 的算术运算
            if inst.opcode in OptimizationPatternDetector.CONST_OPS:
                const_reg = inst.operands.get('vA', -1)
                const_val = inst.operands.get('lit', inst.operands.get('litB', 0))

                if next_inst.opcode in OptimizationPatternDetector.ARITH_OPS:
                    # 检查是否操作数之一是 const 寄存器
                    vA = next_inst.operands.get('vA', -1)
                    vB = next_inst.operands.get('vB', -1)
                    vC = next_inst.operands.get('vC', -1)

                    if const_reg in (vB, vC):
                        folded.append({
                            'addr': inst.address,
                            'pattern': 'const_foldable',
                            'description': f'const v{const_reg}, #{const_val} 后跟 {next_inst.name}——可常量折叠',
                            'const_value': const_val,
                            'arithmetic_op': next_inst.name,
                        })

        return {
            'const_folding': folded,
            'const_fold_count': len(folded),
        }

    @staticmethod
    def _detect_dead_code(instructions, cfg):
        """检测死代码——不可达指令"""
        # 从入口可达的块
        reachable = set()
        from collections import deque
        queue = deque([cfg.get('entry', 0)])
        reachable.add(cfg.get('entry', 0))

        while queue:
            bs = queue.popleft()
            for blk in cfg['blocks']:
                if blk['start'] == bs:
                    for succ in blk['successors']:
                        if succ not in reachable:
                            reachable.add(succ)
                            queue.append(succ)
                    break

        dead_blocks = []
        dead_instructions = 0
        for blk in cfg['blocks']:
            if blk['start'] not in reachable:
                dead_blocks.append({
                    'start': blk['start'],
                    'instruction_count': len(blk['instructions']),
                    'first_instruction': blk['instructions'][0].name if blk['instructions'] else '',
                })
                dead_instructions += len(blk['instructions'])

        # 检测 NOP 指令
        nop_count = sum(1 for inst in instructions if inst.opcode == OptimizationPatternDetector.NOP_OP)

        return {
            'dead_code': {
                'dead_blocks': dead_blocks,
                'dead_block_count': len(dead_blocks),
                'dead_instruction_count': dead_instructions,
                'nop_count': nop_count,
                'dead_code_ratio': dead_instructions / len(instructions) if instructions else 0,
            }
        }

    @staticmethod
    def _analyze_register_usage(instructions):
        """分析寄存器分配效率"""
        max_reg = 0
        reg_defs = defaultdict(int)  # 每个寄存器的定义次数
        reg_uses = defaultdict(int)  # 每个寄存器的使用次数

        from ..core.dex.reaching_defs import ReachingDefinitions

        for inst in instructions:
            defs, uses = ReachingDefinitions._extract_def_use(inst)
            for r in defs:
                reg_defs[r] += 1
                max_reg = max(max_reg, r)
            for r in uses:
                reg_uses[r] += 1
                max_reg = max(max_reg, r)

        # 检测寄存器重用模式
        reuse_patterns = []
        for reg in range(max_reg + 1):
            def_count = reg_defs.get(reg, 0)
            use_count = reg_uses.get(reg, 0)
            if def_count > 3:
                reuse_patterns.append({
                    'register': reg,
                    'def_count': def_count,
                    'use_count': use_count,
                    'pattern': 'high_reuse' if def_count > 5 else 'moderate_reuse',
                })

        # 未使用的寄存器
        unused_regs = [r for r in range(max_reg + 1) if reg_defs.get(r, 0) == 0 and reg_uses.get(r, 0) == 0]

        return {
            'register_analysis': {
                'max_register': max_reg,
                'register_count': max_reg + 1,
                'total_defs': sum(reg_defs.values()),
                'total_uses': sum(reg_uses.values()),
                'reuse_patterns': reuse_patterns,
                'unused_registers': unused_regs,
                'unused_count': len(unused_regs),
                'avg_defs_per_reg': sum(reg_defs.values()) / (max_reg + 1) if max_reg >= 0 else 0,
            }
        }

    @staticmethod
    def _detect_inline_patterns(instructions):
        """检测内联模式"""
        inline_candidates = []

        for i, inst in enumerate(instructions):
            if inst.opcode not in OptimizationPatternDetector.INVOKE_OPS:
                continue

            # 检查 invoke 后是否直接 return（尾调用）
            if i + 1 < len(instructions):
                next_inst = instructions[i + 1]
                if next_inst.opcode in OptimizationPatternDetector.RETURN_OPS or \
                   next_inst.opcode in OptimizationPatternDetector.MOVE_RESULT_OPS:
                    # 如果 invoke 后 move-result + return，这是可内联模式
                    if i + 2 < len(instructions) and \
                       instructions[i + 1].opcode in OptimizationPatternDetector.MOVE_RESULT_OPS and \
                       instructions[i + 2].opcode in OptimizationPatternDetector.RETURN_OPS:
                        inline_candidates.append({
                            'addr': inst.address,
                            'pattern': 'tail_call_inlineable',
                            'description': 'invoke -> move-result -> return：尾调用可内联',
                        })

            # 检查非常短的 invoke 序列
            method_idx = inst.operands.get('method_idx', inst.operands.get('ref', -1))
            regs = inst.operands.get('registers', [])
            if len(regs) <= 1 and inst.opcode in (0x71, 0x72, 0x77, 0x78):
                # static invoke 且参数少
                inline_candidates.append({
                    'addr': inst.address,
                    'pattern': 'simple_static_invoke',
                    'description': f'简单 static invoke（{len(regs)} 参数），内联候选',
                })

        return {
            'inline_patterns': inline_candidates,
            'inline_candidate_count': len(inline_candidates),
        }

    @staticmethod
    def _detect_code_bloat(instructions, cfg):
        """检测代码膨胀"""
        # 重复指令序列检测
        sequences = defaultdict(list)
        seq_len = 3  # 最小重复序列长度

        for i in range(len(instructions) - seq_len):
            # 使用 opcode 序列作为签名
            sig = tuple(instructions[i + j].opcode for j in range(seq_len))
            sequences[sig].append(i)

        duplicated = []
        for sig, positions in sequences.items():
            if len(positions) > 1:
                # 验证是否真的是重复序列（不仅 opcode 相同，操作数也相似）
                first_seq = [instructions[positions[0] + j].name for j in range(seq_len)]
                duplicated.append({
                    'positions': positions,
                    'instruction_sequence': first_seq,
                    'count': len(positions),
                })

        # 大方法检测
        inst_count = len(instructions)
        block_count = len(cfg['blocks'])
        avg_block_size = inst_count / block_count if block_count else 0

        # 检测过深嵌套
        max_depth = 0
        for blk in cfg['blocks']:
            depth = 0
            current = blk['start']
            visited = set()
            while current not in visited:
                visited.add(current)
                preds = [b for b in cfg['blocks'] if b['start'] == current]
                if not preds:
                    break
                preds = preds[0]['predecessors']
                if not preds:
                    break
                current = preds[0]
                depth += 1
                if depth > 100:
                    break
            max_depth = max(max_depth, depth)

        return {
            'code_bloat': {
                'instruction_count': inst_count,
                'block_count': block_count,
                'avg_block_size': round(avg_block_size, 2),
                'max_nesting_depth': max_depth,
                'duplicated_sequences': duplicated[:20],  # 限制输出
                'duplication_count': len(duplicated),
                'is_large_method': inst_count > 500,
                'is_bloated': inst_count > 1000 or avg_block_size > 30,
            }
        }

    @staticmethod
    def _detect_switch_optimization(instructions):
        """检测 switch 优化模式"""
        switches = []
        for i, inst in enumerate(instructions):
            if inst.opcode in (0x2b, 0x2c):  # packed-switch, sparse-switch
                switch_type = 'packed' if inst.opcode == 0x2b else 'sparse'
                targets = inst.operands.get('targets', [])
                switches.append({
                    'addr': inst.address,
                    'type': switch_type,
                    'target_count': len(targets) if targets else 0,
                    'is_dense': switch_type == 'packed',
                    'description': f'{switch_type}-switch with {len(targets) if targets else 0} targets',
                })

        return {
            'switch_patterns': switches,
            'switch_count': len(switches),
        }

    @staticmethod
    def _detect_loop_invariants(instructions, cfg):
        """检测循环不变量——循环内每次迭代计算相同值的表达式"""
        from ..core.dex.disassembler import Disassembler

        loops = Disassembler.detect_loops(instructions, cfg) if hasattr(Disassembler, 'detect_loops') else {'natural_loops': []}

        invariants = []
        for loop in loops.get('natural_loops', []):
            loop_blocks = loop.get('blocks', [])
            if not loop_blocks:
                continue

            # 收集循环内的所有指令
            loop_insts = []
            for bs in loop_blocks:
                for blk in cfg['blocks']:
                    if blk['start'] == bs:
                        loop_insts.extend(blk['instructions'])
                        break

            # 收集循环内定义的寄存器
            from ..core.dex.reaching_defs import ReachingDefinitions
            loop_def_regs = set()
            for inst in loop_insts:
                defs, _ = ReachingDefinitions._extract_def_use(inst)
                loop_def_regs |= defs

            # 检测不变量：使用的寄存器不在循环内定义
            for inst in loop_insts:
                _, uses = ReachingDefinitions._extract_def_use(inst)
                # const 指令在循环内是不变量
                if inst.opcode in OptimizationPatternDetector.CONST_OPS:
                    invariants.append({
                        'addr': inst.address,
                        'pattern': 'const_invariant',
                        'description': f'{inst.name} 在循环内是常量，可外提',
                    })
                # 运算指令且所有操作数都不在循环内定义
                elif inst.opcode in OptimizationPatternDetector.ARITH_OPS:
                    if all(r not in loop_def_regs for r in uses):
                        invariants.append({
                            'addr': inst.address,
                            'pattern': 'computation_invariant',
                            'description': f'{inst.name} 的操作数在循环外定义，可外提',
                        })

        return {
            'loop_invariants': invariants[:50],
            'invariant_count': len(invariants),
        }

    @staticmethod
    def _instruction_hotspot(instructions, cfg):
        """指令热点分析——基于循环和分支密度"""
        # 按基本块统计指令密度
        block_density = []
        for blk in cfg['blocks']:
            branch_count = sum(1 for inst in blk['instructions'] if inst.is_branch() or inst.is_switch())
            inst_count = len(blk['instructions'])
            density = branch_count / inst_count if inst_count else 0
            block_density.append({
                'block_start': blk['start'],
                'instruction_count': inst_count,
                'branch_count': branch_count,
                'branch_density': round(density, 3),
            })

        # opcode 频率统计
        opcode_freq = Counter(inst.name for inst in instructions)
        top_opcodes = opcode_freq.most_common(20)

        # 计算圈复杂度
        from ..core.dex.disassembler import Disassembler
        complexity = Disassembler.analyze_complexity(instructions, cfg) if hasattr(Disassembler, 'analyze_complexity') else {}
        cyclomatic = complexity.get('cyclomatic_complexity', 0)

        return {
            'hotspot_analysis': {
                'block_density': block_density,
                'top_opcodes': top_opcodes,
                'cyclomatic_complexity': cyclomatic,
                'avg_instruction_per_block': round(len(instructions) / max(len(cfg['blocks']), 1), 2),
            }
        }

    @staticmethod
    def _detect_peephole_patterns(instructions):
        """检测窥孔优化模式"""
        patterns = []

        for i in range(len(instructions) - 1):
            inst = instructions[i]
            next_inst = instructions[i + 1]

            # move vA, vB -> move vC, vA：冗余 move 链
            if inst.opcode in OptimizationPatternDetector.MOVE_OPS and \
               next_inst.opcode in OptimizationPatternDetector.MOVE_OPS:
                src1 = inst.operands.get('vA', -1)
                dst2 = next_inst.operands.get('vB', -1)
                if src1 == dst2:
                    patterns.append({
                        'addr': inst.address,
                        'pattern': 'redundant_move_chain',
                        'description': f'{inst.name} v{inst.operands.get("vA")}, v{inst.operands.get("vB")} -> {next_inst.name} v{next_inst.operands.get("vA")}, v{next_inst.operands.get("vB")}：冗余 move 链',
                    })

            # const vA, #0 -> if-eqz vA：const 0 后跟零比较
            if inst.opcode in OptimizationPatternDetector.CONST_OPS and \
               next_inst.opcode in OptimizationPatternDetector.IF_OPS:
                const_val = inst.operands.get('lit', inst.operands.get('litB', 0))
                const_reg = inst.operands.get('vA', -1)
                if_reg = next_inst.operands.get('vA', -1)
                if const_val == 0 and const_reg == if_reg and \
                   next_inst.opcode in (0x38, 0x39):
                    patterns.append({
                        'addr': inst.address,
                        'pattern': 'const_zero_compare',
                        'description': 'const vA, #0 -> if-eqz/ne vA：编译时常量比较，可消除',
                    })

            # const vA, #1 -> if-eqz vA：总是 false
            if inst.opcode in OptimizationPatternDetector.CONST_OPS and \
               next_inst.opcode == 0x38:  # if-eqz
                const_val = inst.operands.get('lit', inst.operands.get('litB', 0))
                const_reg = inst.operands.get('vA', -1)
                if_reg = next_inst.operands.get('vA', -1)
                if const_val != 0 and const_reg == if_reg:
                    patterns.append({
                        'addr': inst.address,
                        'pattern': 'dead_branch',
                        'description': f'const v{const_reg}, #{const_val} -> if-eqz v{if_reg}：分支永假，死分支',
                    })

            # goto 下一指令：无用 goto
            if inst.opcode in OptimizationPatternDetector.GOTO_OPS:
                offset = inst.operands.get('offset', 0)
                target = inst.address + offset
                next_addr = next_inst.address
                if target == next_addr:
                    patterns.append({
                        'addr': inst.address,
                        'pattern': 'useless_goto',
                        'description': f'goto 到下一条指令，可删除',
                    })

            # const + const：重复 const 到同一寄存器
            if inst.opcode in OptimizationPatternDetector.CONST_OPS and \
               next_inst.opcode in OptimizationPatternDetector.CONST_OPS:
                reg1 = inst.operands.get('vA', -1)
                reg2 = next_inst.operands.get('vA', -1)
                if reg1 == reg2:
                    patterns.append({
                        'addr': inst.address,
                        'pattern': 'redundant_const',
                        'description': f'连续 const 到同一寄存器 v{reg1}，前一条可删除',
                    })

        return {
            'peephole_patterns': patterns[:50],
            'peephole_count': len(patterns),
        }

    @staticmethod
    def _empty_result():
        return {
            'method': '',
            'instruction_count': 0,
            'block_count': 0,
            'const_folding': [],
            'const_fold_count': 0,
            'dead_code': {},
            'register_analysis': {},
            'inline_patterns': [],
            'inline_candidate_count': 0,
            'code_bloat': {},
            'switch_patterns': [],
            'switch_count': 0,
            'loop_invariants': [],
            'invariant_count': 0,
            'hotspot_analysis': {},
            'peephole_patterns': [],
            'peephole_count': 0,
        }

    @staticmethod
    def analyze_dex(dex_parser, max_methods=100):
        """分析整个 DEX 文件的优化模式

        Args:
            dex_parser: DexParser 实例
            max_methods: 最大分析方法数（避免过大文件耗时）

        Returns:
            dict: 全局优化统计
        """
        dp = dex_parser
        dp._ensure_parsed()

        from ..core.dex.instruction_decoder import InstructionDecoder

        strings = dp.get_strings()
        methods_ref = dp.get_methods()

        all_results = []
        method_count = 0

        for cls in dp.get_class_defs():
            cls_name = cls['class_name']
            all_methods = cls.get('direct_methods', []) + cls.get('virtual_methods', [])

            for m in all_methods:
                if method_count >= max_methods:
                    break

                code = m.get('code')
                if not code:
                    continue

                insns_start = code.get('insns_start', 0)
                insns_size = code.get('insns_size', 0)
                if insns_start == 0 or insns_size == 0:
                    continue

                try:
                    instructions = InstructionDecoder.decode(
                        dp.data, insns_start, insns_size, strings,
                        dp.get_type_ids(), dp.get_proto_ids(),
                        dp.get_field_ids(), methods_ref
                    )
                    result = OptimizationPatternDetector.analyze_method(
                        instructions,
                        method_info={'name': m.get('name', ''), 'class': cls_name}
                    )
                    all_results.append(result)
                    method_count += 1
                except Exception:
                    continue

            if method_count >= max_methods:
                break

        # 汇总统计
        total_const_fold = sum(r.get('const_fold_count', 0) for r in all_results)
        total_dead = sum(r.get('dead_code', {}).get('dead_instruction_count', 0) for r in all_results)
        total_inline = sum(r.get('inline_candidate_count', 0) for r in all_results)
        total_invariant = sum(r.get('invariant_count', 0) for r in all_results)
        total_peephole = sum(r.get('peephole_count', 0) for r in all_results)
        total_dup = sum(r.get('code_bloat', {}).get('duplication_count', 0) for r in all_results)

        # 最需要优化的方法
        optimization_candidates = []
        for r in all_results:
            score = (
                r.get('const_fold_count', 0) * 2 +
                r.get('dead_code', {}).get('dead_instruction_count', 0) * 1 +
                r.get('inline_candidate_count', 0) * 3 +
                r.get('invariant_count', 0) * 3 +
                r.get('peephole_count', 0) * 2 +
                r.get('code_bloat', {}).get('duplication_count', 0) * 1
            )
            if score > 0:
                optimization_candidates.append({
                    'method': r.get('method', ''),
                    'class': r.get('class', ''),
                    'optimization_score': score,
                    'instruction_count': r.get('instruction_count', 0),
                    'const_fold': r.get('const_fold_count', 0),
                    'dead_code': r.get('dead_code', {}).get('dead_instruction_count', 0),
                    'inline_candidates': r.get('inline_candidate_count', 0),
                    'loop_invariants': r.get('invariant_count', 0),
                    'peephole': r.get('peephole_count', 0),
                })

        optimization_candidates.sort(key=lambda x: x['optimization_score'], reverse=True)

        return {
            'analyzed_method_count': method_count,
            'total_const_foldable': total_const_fold,
            'total_dead_instructions': total_dead,
            'total_inline_candidates': total_inline,
            'total_loop_invariants': total_invariant,
            'total_peephole_patterns': total_peephole,
            'total_duplicated_sequences': total_dup,
            'optimization_candidates': optimization_candidates[:30],
            'methods': all_results,
        }
