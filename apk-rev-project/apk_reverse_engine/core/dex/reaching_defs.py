"""到达定义分析（Reaching Definitions）与活越变量分析（Live Variables）

为 DEX 方法级提供经典数据流分析：
- 到达定义分析：对于每个程序点，哪些定义（写操作）能够到达此处
- use-def 链与 def-use 链构建
- 活越变量分析：对于每个程序点，哪些变量的值会在后续被使用
- 未初始化寄存器检测
"""
from collections import defaultdict


class ReachingDefinitions:
    """到达定义分析器

    定义（Definition）= 对寄存器的写操作。
    使用前向数据流方程：
        IN[B]  = ∪ OUT[P]  for P ∈ pred(B)
        OUT[B] = gen[B] ∪ (IN[B] - kill[B])
    """

    @staticmethod
    def _extract_def_use(inst):
        """提取单条指令的 def 集和 use 集。
        返回 (def_regs: set, use_regs: set)
        """
        ops = inst.operands
        op = inst.opcode
        defs = set()
        uses = set()

        # const 类指令：def vA
        if op in (0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c):
            defs.add(ops.get('vA', -1))
        # move 类指令：def vA, use vB
        elif op in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09):
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        # move-result：def vA（use 隐含在前一条 invoke）
        elif op in (0x0a, 0x0b, 0x0c):
            defs.add(ops.get('vA', -1))
        # move-exception：def vA
        elif op == 0x0d:
            defs.add(ops.get('vA', -1))
        # iget/iput：iget def vA use vB；iput use vA vB
        elif op in (0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58):
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        elif op in (0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f):
            uses.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        # sget def vA；sput use vA
        elif op in (0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66):
            defs.add(ops.get('vA', -1))
        elif op in (0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d):
            uses.add(ops.get('vA', -1))
        # aget def vA use vB vC；aput use vA vB vC
        elif op in (0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a):
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
            uses.add(ops.get('vC', -1))
        elif op in (0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51):
            uses.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
            uses.add(ops.get('vC', -1))
        # 二元运算 23x：def vA use vB vC
        elif op in range(0x90, 0xb0):
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
            uses.add(ops.get('vC', -1))
        # 2addr 12x：def vA use vA vB
        elif op in range(0xb0, 0xd0):
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        # lit16/lit8 22s/22b：def vA use vB
        elif op in range(0xd0, 0xe3):
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        # unary 12x：def vA use vB
        elif op in range(0x7b, 0x90):
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        # invoke 35c/3rc：use 所有寄存器参数
        elif op in (0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
            for r in ops.get('registers', []):
                uses.add(r)
            if 'start_reg' in ops:
                for i in range(ops.get('reg_count', 0)):
                    uses.add(ops['start_reg'] + i)
        # filled-new-array：use 所有寄存器参数
        elif op in (0x24, 0x25):
            for r in ops.get('registers', []):
                uses.add(r)
            if 'start_reg' in ops:
                for i in range(ops.get('reg_count', 0)):
                    uses.add(ops['start_reg'] + i)
        # new-instance / new-array / check-cast：def vA（new-array use vB）
        elif op == 0x22:
            defs.add(ops.get('vA', -1))
        elif op == 0x23:
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        elif op == 0x1f:
            uses.add(ops.get('vA', -1))
        # instance-of：def vA use vB
        elif op == 0x20:
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        # array-length：def vA use vB
        elif op == 0x21:
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        # fill-array-data：use vA
        elif op == 0x26:
            uses.add(ops.get('vA', -1))
        # if 22t：use vA vB
        elif op in (0x32, 0x33, 0x34, 0x35, 0x36, 0x37):
            uses.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
        # if 21t：use vA
        elif op in (0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d):
            uses.add(ops.get('vA', -1))
        # return 11x：use vA
        elif op in (0x0f, 0x10, 0x11):
            uses.add(ops.get('vA', -1))
        # throw：use vA
        elif op == 0x27:
            uses.add(ops.get('vA', -1))
        # monitor-enter/exit：use vA
        elif op in (0x1d, 0x1e):
            uses.add(ops.get('vA', -1))
        # cmp：def vA use vB vC
        elif op in (0x2d, 0x2e, 0x2f, 0x30, 0x31):
            defs.add(ops.get('vA', -1))
            uses.add(ops.get('vB', -1))
            uses.add(ops.get('vC', -1))

        # 清除无效寄存器号
        defs.discard(-1)
        uses.discard(-1)
        return defs, uses

    @staticmethod
    def analyze(instructions, cfg=None):
        """运行到达定义分析。

        Args:
            instructions: Instruction 列表
            cfg: 预构建的 CFG（可选，若为 None 则自动构建）

        Returns:
            dict: {
                'def_use': {inst_addr: {'defs': set, 'uses': set}},
                'in_sets': {block_start: set of (reg, inst_addr)},
                'out_sets': {block_start: set of (reg, inst_addr)},
                'ud_chain': {inst_addr: {reg: [defining_inst_addrs]}},
                'du_chain': {def_inst_addr: {reg: [using_inst_addrs]}},
            }
        """
        if not instructions:
            return {'def_use': {}, 'in_sets': {}, 'out_sets': {},
                    'ud_chain': {}, 'du_chain': {}}

        # 构建 CFG
        if cfg is None:
            from .disassembler import Disassembler
            cfg = Disassembler.build_cfg(instructions)

        blocks = cfg['blocks']
        if not blocks:
            return {'def_use': {}, 'in_sets': {}, 'out_sets': {},
                    'ud_chain': {}, 'du_chain': {}}

        # 提取每条指令的 def/use
        def_use = {}
        for inst in instructions:
            defs, uses = ReachingDefinitions._extract_def_use(inst)
            def_use[inst.address] = {'defs': defs, 'uses': uses}

        # 为每个基本块计算 gen 和 kill
        # gen[B] = 块内最后一次对每个寄存器的定义
        # kill[B] = 其他块中对相同寄存器的定义
        block_gen = {}
        block_kill = {}

        # 收集所有定义：reg -> [(inst_addr, block_start)]
        all_defs_by_reg = defaultdict(list)
        for blk in blocks:
            for inst in blk['instructions']:
                for reg in def_use[inst.address]['defs']:
                    all_defs_by_reg[reg].append((inst.address, blk['start']))

        for blk in blocks:
            gen = {}  # reg -> inst_addr (块内最后定义)
            kill = set()
            for inst in blk['instructions']:
                for reg in def_use[inst.address]['defs']:
                    gen[reg] = inst.address
            # kill = 其他块中对 gen 中寄存器的定义
            for reg in gen:
                for (addr, bs) in all_defs_by_reg.get(reg, []):
                    if bs != blk['start']:
                        kill.add((reg, addr))
            block_gen[blk['start']] = {(reg, addr) for reg, addr in gen.items()}
            block_kill[blk['start']] = kill

        # 迭代数据流
        in_sets = {blk['start']: set() for blk in blocks}
        out_sets = {blk['start']: set() for blk in blocks}
        entry = cfg['entry']

        changed = True
        iteration = 0
        max_iter = 1000
        while changed and iteration < max_iter:
            changed = False
            iteration += 1
            for blk in blocks:
                bs = blk['start']
                if bs == entry:
                    new_in = set()
                else:
                    new_in = set()
                    for p in blk['predecessors']:
                        new_in |= out_sets.get(p, set())

                new_out = block_gen[bs] | (new_in - block_kill[bs])
                if new_in != in_sets[bs] or new_out != out_sets[bs]:
                    in_sets[bs] = new_in
                    out_sets[bs] = new_out
                    changed = True

        # 构建 use-def 链
        # 对每条指令使用的每个寄存器，找到到达该指令的定义
        ud_chain = {}
        du_chain = defaultdict(lambda: defaultdict(list))

        for blk in blocks:
            reaching = set(in_sets[blk['start']])  # (reg, def_addr)
            for inst in blk['instructions']:
                addr = inst.address
                du = def_use[addr]
                # use-def：当前 use 的寄存器，reaching 中的定义
                ud_entry = {}
                for reg in du['uses']:
                    defs = [d_addr for (r, d_addr) in reaching if r == reg]
                    ud_entry[reg] = defs
                if ud_entry:
                    ud_chain[addr] = ud_entry
                # 更新 reaching：kill 被覆盖的定义，add 新定义
                for reg in du['defs']:
                    reaching = {(r, a) for (r, a) in reaching if r != reg}
                    reaching.add((reg, addr))

        # 构建 def-use 链
        for addr, ud in ud_chain.items():
            for reg, def_addrs in ud.items():
                for d_addr in def_addrs:
                    du_chain[d_addr][reg].append(addr)

        return {
            'def_use': {a: {'defs': sorted(v['defs']), 'uses': sorted(v['uses'])}
                        for a, v in def_use.items()},
            'in_sets': {bs: sorted(v) for bs, v in in_sets.items()},
            'out_sets': {bs: sorted(v) for bs, v in out_sets.items()},
            'ud_chain': {a: {r: sorted(ds) for r, ds in ud.items()}
                         for a, ud in ud_chain.items()},
            'du_chain': {a: {r: sorted(us) for r, us in d.items()}
                         for a, d in du_chain.items()},
        }


class LiveVariables:
    """活越变量分析器

    使用后向数据流方程：
        OUT[B] = ∪ IN[S]  for S ∈ succ(B)
        IN[B]  = use[B] ∪ (OUT[B] - def[B])
    """

    @staticmethod
    def analyze(instructions, cfg=None):
        """运行活越变量分析。

        Returns:
            dict: {
                'live_in': {block_start: set of reg},
                'live_out': {block_start: set of reg},
                'dead_defs': [{addr, reg, instruction}],  # 死定义（写入后不再被读取）
            }
        """
        if not instructions:
            return {'live_in': {}, 'live_out': {}, 'dead_defs': []}

        if cfg is None:
            from .disassembler import Disassembler
            cfg = Disassembler.build_cfg(instructions)

        blocks = cfg['blocks']
        if not blocks:
            return {'live_in': {}, 'live_out': {}, 'dead_defs': []}

        # 提取每条指令的 def/use
        block_use = {}  # use[B] = 在块内被使用且之前未被定义的寄存器
        block_def = {}  # def[B] = 块内定义的所有寄存器

        for blk in blocks:
            defined = set()
            used_before_def = set()
            for inst in blk['instructions']:
                defs, uses = ReachingDefinitions._extract_def_use(inst)
                for reg in uses:
                    if reg not in defined:
                        used_before_def.add(reg)
                for reg in defs:
                    defined.add(reg)
            block_use[blk['start']] = used_before_def
            block_def[blk['start']] = defined

        # 后向迭代
        live_in = {blk['start']: set() for blk in blocks}
        live_out = {blk['start']: set() for blk in blocks}

        changed = True
        iteration = 0
        max_iter = 1000
        while changed and iteration < max_iter:
            changed = False
            iteration += 1
            for blk in reversed(blocks):
                bs = blk['start']
                new_out = set()
                for s in blk['successors']:
                    new_out |= live_in.get(s, set())
                new_in = block_use[bs] | (new_out - block_def[bs])
                if new_in != live_in[bs] or new_out != live_out[bs]:
                    live_in[bs] = new_in
                    live_out[bs] = new_out
                    changed = True

        # 检测死定义：在块内定义后不被后续指令使用也不在 live_out 中
        dead_defs = []
        for blk in blocks:
            live = set(live_out[blk['start']])
            # 逆序遍历
            for inst in reversed(blk['instructions']):
                defs, uses = ReachingDefinitions._extract_def_use(inst)
                for reg in defs:
                    if reg not in live:
                        dead_defs.append({
                            'addr': inst.address,
                            'reg': reg,
                            'instruction': inst.name,
                        })
                # 更新 live：def 移除，use 加入
                live -= defs
                live |= uses

        return {
            'live_in': {bs: sorted(v) for bs, v in live_in.items()},
            'live_out': {bs: sorted(v) for bs, v in live_out.items()},
            'dead_defs': dead_defs,
        }
