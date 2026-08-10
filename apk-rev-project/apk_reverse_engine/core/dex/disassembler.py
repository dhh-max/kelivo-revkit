"""DEX 反汇编器 - 完整方法体解析、try/catch、调试信息、Smali输出"""
import struct
from .opcode_table import get_opcode_name, get_opcode_size, OPCODE_FORMAT, OPCODE_NAMES
from .instruction_decoder import InstructionDecoder, Instruction

class DebugInfoParser:
    """DEX debug_info 解析器 - 行号/局部变量"""
    
    @staticmethod
    def decode_uleb128(data, offset):
        result = 0
        shift = 0
        pos = offset
        while True:
            byte = data[pos]
            result |= (byte & 0x7f) << shift
            shift += 7
            pos += 1
            if not (byte & 0x80):
                break
        return result, pos - offset
    
    @staticmethod
    def decode_sleb128(data, offset):
        result = 0
        shift = 0
        pos = offset
        while True:
            byte = data[pos]
            result |= (byte & 0x7f) << shift
            shift += 7
            pos += 1
            if not (byte & 0x80):
                break
        if byte & 0x40:
            result |= -(1 << shift)
        return result, pos - offset
    
    @staticmethod
    def parse(data, debug_info_off, strings=None):
        """解析 debug_info 段"""
        if not data or debug_info_off <= 0 or debug_info_off >= len(data):
            return {'line_start': 0, 'parameters': [], 'events': []}
        
        try:
            pos = debug_info_off
            line_start, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
            parameters_size, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
            
            parameters = []
            for i in range(parameters_size):
                param_idx, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                param_name = strings[param_idx] if strings and 0 <= param_idx < len(strings) else f'p{i}'
                parameters.append({'idx': param_idx, 'name': param_name})
            
            events = []
            addr = 0
            line = line_start
            while pos < len(data):
                opcode = data[pos]
                pos += 1
                if opcode == 0:  # DBG_END_SEQUENCE
                    break
                elif opcode == 1:  # DBG_ADVANCE_PC
                    adj, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    addr += adj
                elif opcode == 2:  # DBG_ADVANCE_LINE
                    adj, sz = DebugInfoParser.decode_sleb128(data, pos); pos += sz
                    line += adj
                elif opcode == 3:  # DBG_START_LOCAL
                    reg_num, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    name_idx, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    type_idx, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    name = strings[name_idx] if strings and 0 <= name_idx < len(strings) else f'name_{name_idx}'
                    type_desc = ''
                    events.append({'type': 'start_local', 'addr': addr, 'reg': reg_num, 'name': name, 'type_idx': type_idx})
                elif opcode == 4:  # DBG_START_LOCAL_EXTENDED
                    reg_num, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    name_idx, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    type_idx, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    sig_idx, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    name = strings[name_idx] if strings and 0 <= name_idx < len(strings) else f'name_{name_idx}'
                    events.append({'type': 'start_local_ext', 'addr': addr, 'reg': reg_num, 'name': name})
                elif opcode == 5:  # DBG_END_LOCAL
                    reg_num, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    events.append({'type': 'end_local', 'addr': addr, 'reg': reg_num})
                elif opcode == 6:  # DBG_RESTART_LOCAL
                    reg_num, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    events.append({'type': 'restart_local', 'addr': addr, 'reg': reg_num})
                elif opcode == 7:  # DBG_SET_PROLOGUE_END
                    events.append({'type': 'prologue_end', 'addr': addr})
                elif opcode == 8:  # DBG_SET_EPILOGUE_BEGIN
                    events.append({'type': 'epilogue_begin', 'addr': addr})
                elif opcode == 9:  # DBG_SET_FILE
                    name_idx, sz = DebugInfoParser.decode_uleb128(data, pos); pos += sz
                    name = strings[name_idx] if strings and 0 <= name_idx < len(strings) else f'file_{name_idx}'
                    events.append({'type': 'set_file', 'addr': addr, 'file': name})
                elif opcode >= 10:  # DBG_FIRST_SPECIAL = 0x0a
                    adjusted_opcode = opcode - 10
                    addr += adjusted_opcode // 15
                    line += -4 + (adjusted_opcode % 15)
                    events.append({'type': 'line', 'addr': addr, 'line': line})
            
            return {
                'line_start': line_start,
                'parameters': parameters,
                'events': events,
                'line_events': [e for e in events if e['type'] == 'line'],
                'locals': [e for e in events if 'local' in e['type']],
            }
        except Exception as e:
            return {'line_start': 0, 'parameters': [], 'events': [], 'error': str(e)}
    
    @staticmethod
    def build_line_map(debug_info):
        """构建地址到行号的映射"""
        line_map = {}
        for e in debug_info.get('events', []):
            if e['type'] == 'line':
                line_map[e['addr']] = e['line']
        return line_map


class TryCatchParser:
    """DEX try/catch 解析器"""
    
    @staticmethod
    def parse(data, tries_size, tries_off, handlers_size, handlers_off, strings=None, types=None):
        """解析 try/catch 信息"""
        if tries_size == 0 or tries_off <= 0:
            return {'tries': [], 'handlers': []}
        
        tries = []
        try:
            for i in range(tries_size):
                off = tries_off + i * 8
                start_addr = struct.unpack_from('<I', data, off)[0]
                insn_count = struct.unpack_from('<H', data, off + 4)[0]
                handler_off = struct.unpack_from('<H', data, off + 6)[0]
                tries.append({
                    'start_addr': start_addr,
                    'end_addr': start_addr + insn_count,
                    'insn_count': insn_count,
                    'handler_off': handler_off,
                })
        except Exception as e:
            return {'tries': [], 'handlers': [], 'error': str(e)}
        
        # 解析 handlers
        handlers = []
        if handlers_off > 0:
            try:
                pos = handlers_off
                for tri in tries:
                    handler_off = handlers_off + tri['handler_off']
                    if handler_off >= len(data):
                        continue
                    size = data[handler_off]
                    is_catch_all = size & 0x80
                    handler_count = size & 0x7f
                    handler_pos = handler_off + 1
                    
                    catch_handlers = []
                    for j in range(handler_count):
                        type_idx = struct.unpack_from('<H', data, handler_pos)[0]
                        handler_addr = struct.unpack_from('<I', data, handler_pos + 2)[0]
                        type_name = types[type_idx]['descriptor'] if types and 0 <= type_idx < len(types) else f'type_{type_idx}'
                        catch_handlers.append({
                            'type_idx': type_idx,
                            'type_name': type_name,
                            'handler_addr': handler_addr,
                        })
                        handler_pos += 6
                    
                    if is_catch_all:
                        catch_all_addr = struct.unpack_from('<I', data, handler_pos)[0]
                        handler_pos += 4
                        handlers.append({
                            'catch_handlers': catch_handlers,
                            'catch_all_addr': catch_all_addr,
                        })
                    else:
                        handlers.append({'catch_handlers': catch_handlers, 'catch_all_addr': None})
            except Exception as e:
                from apk_reverse_engine.utils.logutil import get_logger; get_logger(__name__).debug("apk_reverse_engine/core/dex/disassembler.py:184 suppressed: %s", e)
                pass
        
        return {'tries': tries, 'handlers': handlers}


class Disassembler:
    """DEX 完整反汇编引擎"""
    
    @staticmethod
    def parse_code_item(data, offset, strings=None, types=None, fields=None, methods=None):
        """解析 code_item 结构"""
        if not data or offset < 0 or offset + 16 > len(data):
            return None
        
        try:
            registers_size = struct.unpack_from('<H', data, offset)[0]
            ins_size = struct.unpack_from('<H', data, offset + 2)[0]
            outs_size = struct.unpack_from('<H', data, offset + 4)[0]
            tries_size = struct.unpack_from('<H', data, offset + 6)[0]
            debug_info_off = struct.unpack_from('<I', data, offset + 8)[0]
            insns_size = struct.unpack_from('<I', data, offset + 12)[0]
            insns_off = offset + 16
            
            # 计算 try/catch 偏移
            padding = 0
            if tries_size > 0:
                padding = (4 - (insns_size * 2) % 4) % 4
            tries_off = insns_off + insns_size * 2 + padding
            handlers_off = tries_off + tries_size * 8
            
            return {
                'registers_size': registers_size,
                'ins_size': ins_size,
                'outs_size': outs_size,
                'tries_size': tries_size,
                'debug_info_off': debug_info_off,
                'insns_size': insns_size,
                'insns_off': insns_off,
                'tries_off': tries_off,
                'handlers_off': handlers_off,
            }
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger
            get_logger(__name__).warning("code_item parse failed: %s", e)
            return None
    
    @staticmethod
    def disassemble_code_item(data, code_item, strings=None, types=None, fields=None, methods=None):
        """反汇编 code_item 中的指令"""
        if not code_item:
            return {'instructions': [], 'debug_info': {}, 'try_catch': {}}
        
        insns_off = code_item['insns_off']
        insns_size = code_item['insns_size']
        insns_end = insns_off + insns_size * 2
        
        # 解码指令
        instructions = []
        pos = insns_off
        while pos < insns_end and pos < len(data):
            inst = InstructionDecoder.decode(data, pos, strings, types, fields, methods)
            instructions.append(inst)
            pos += inst.size * 2
        
        # 解析 debug_info
        debug_info = {}
        if code_item['debug_info_off'] > 0 and code_item['debug_info_off'] < len(data):
            debug_info = DebugInfoParser.parse(data, code_item['debug_info_off'], strings)
        
        # 解析 try/catch
        try_catch = {}
        if code_item['tries_size'] > 0:
            try_catch = TryCatchParser.parse(
                data, code_item['tries_size'], code_item['tries_off'],
                0, code_item['handlers_off'], strings, types
            )
        
        return {
            'instructions': instructions,
            'debug_info': debug_info,
            'try_catch': try_catch,
            'registers': code_item['registers_size'],
            'ins_args': code_item['ins_size'],
            'outs_args': code_item['outs_size'],
        }
    
    @staticmethod
    def disassemble_method(method_data, offset=0, strings=None, types=None, fields=None, methods=None):
        """反汇编方法体（兼容旧接口）"""
        code_item = Disassembler.parse_code_item(method_data, offset, strings, types, fields, methods)
        if not code_item:
            return []
        result = Disassembler.disassemble_code_item(method_data, code_item, strings, types, fields, methods)
        return result.get('instructions', [])
    
    @staticmethod
    def disassemble_method_full(method_data, offset=0):
        """完整反汇编方法体（无跳转优化, 兼容旧接口）"""
        return InstructionDecoder.decode_all(method_data, offset)
    
    @staticmethod
    def format_instructions(instructions, strings=None, types=None, fields=None, methods=None):
        """格式化指令列表为文本"""
        return '\n'.join(inst.to_string(strings, types, fields, methods) for inst in instructions)
    
    @staticmethod
    def format_as_smali(code_result, class_name='', method_name='', access_flags='', signature='', line_map=None):
        """格式化为 Smali 风格输出"""
        lines = []
        if class_name:
            lines.append(f'# {class_name}')
        if method_name:
            lines.append(f'.method {access_flags} {method_name}{signature}')
            lines.append(f'    .registers {code_result.get("registers", 0)}')
        
        # 调试信息
        debug_info = code_result.get('debug_info', {})
        if debug_info.get('line_start', 0) > 0:
            lines.append(f'    .line {debug_info["line_start"]}')
        
        # 参数
        for param in debug_info.get('parameters', []):
            if param['name']:
                lines.append(f'    .param {param["name"]}, "{param["name"]}"')
        
        # 局部变量
        for local in debug_info.get('locals', []):
            if local['type'] == 'start_local':
                lines.append(f'    .local v{local["reg"]}, "{local.get("name", "")}"')
        
        # 指令
        instructions = code_result.get('instructions', [])
        line_map_dict = debug_info.get('line_events', [])
        line_by_addr = {}
        for e in line_map_dict:
            if e['type'] == 'line':
                line_by_addr[e['addr']] = e['line']
        
        for inst in instructions:
            addr = inst.address // 2  # 地址以 code_unit 为单位
            if addr in line_by_addr:
                lines.append(f'    .line {line_by_addr[addr]}')
            lines.append(f'    {inst.name} {Disassembler._format_operands_smali(inst)}')
        
        # try/catch
        try_catch = code_result.get('try_catch', {})
        for tri in try_catch.get('tries', []):
            lines.append(f'    .catch {tri["start_addr"]} .. {tri["end_addr"]}')
        
        if method_name:
            lines.append('.end method')
        
        return '\n'.join(lines)
    
    @staticmethod
    def _format_operands_smali(inst):
        """将指令操作数格式化为 Smali 风格"""
        ops = inst.operands
        if inst.format == '10x':
            return ''
        elif inst.format == '11n':
            return f'v{ops.get("vA")}, {ops.get("litB")}'
        elif inst.format == '11x':
            return f'v{ops.get("vA")}'
        elif inst.format == '12x':
            return f'v{ops.get("vA")}, v{ops.get("vB")}'
        elif inst.format == '21c':
            return f'v{ops.get("vA")}, type@0x{ops.get("ref", 0):x}'
        elif inst.format == '21s':
            return f'v{ops.get("vA")}, {ops.get("litB")}'
        elif inst.format == '22c':
            return f'v{ops.get("vA")}, v{ops.get("vB")}, type@0x{ops.get("ref", 0):x}'
        elif inst.format == '22t':
            return f'v{ops.get("vA")}, v{ops.get("vB")}, :cond_{inst.address + ops.get("offset", 0):x}'
        elif inst.format == '35c':
            regs = ops.get('registers', [])
            reg_str = ', '.join(f'v{r}' for r in regs)
            return f'{{{reg_str}}}, type@0x{ops.get("ref", 0):x}'
        elif inst.format == '3rc':
            start = ops.get('start_reg', 0)
            count = ops.get('reg_count', 0)
            return f'{{v{start} .. v{start+count-1}}}, type@0x{ops.get("ref", 0):x}'
        elif inst.format == '31i':
            return f'v{ops.get("vA")}, {ops.get("litB")}'
        elif inst.format == '51l':
            return f'v{ops.get("vA")}, {ops.get("litB")}'
        elif inst.format in ('10t', '20t', '30t'):
            return f':cond_{inst.address + ops.get("offset", 0):x}'
        elif inst.format == '31t':
            return f'v{ops.get("vA")}, :switch_{inst.address + ops.get("offset", 0):x}'
        else:
            return str(ops)
    
    @staticmethod
    def analyze_method(instructions):
        """分析方法指令统计（增强版）"""
        stats = {
            'total': len(instructions),
            'invokes': 0, 'fields': 0, 'consts': 0, 'returns': 0,
            'ifs': 0, 'gotos': 0, 'switches': 0, 'arrays': 0,
            'new_instances': 0, 'throws': 0, 'monitors': 0,
            'invoke_targets': [],
            'const_strings': [],
            'method_calls': [],
            'opcode_histogram': {},
        }
        for inst in instructions:
            op = inst.opcode
            stats['opcode_histogram'][op] = stats['opcode_histogram'].get(op, 0) + 1
            
            if op in {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}:
                stats['invokes'] += 1
                ref = inst.operands.get('ref', -1)
                if ref >= 0:
                    stats['invoke_targets'].append(ref)
                    stats['method_calls'].append(ref)
            elif op in {0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d}:
                stats['fields'] += 1
            elif op in {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c}:
                stats['consts'] += 1
                if op in (0x1a, 0x1b):
                    ref = inst.operands.get('ref', -1)
                    if ref >= 0:
                        stats['const_strings'].append(ref)
            elif op in {0x0e, 0x0f, 0x10, 0x11}:
                stats['returns'] += 1
            elif op in {0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d}:
                stats['ifs'] += 1
            elif op in {0x28, 0x29, 0x2a}:
                stats['gotos'] += 1
            elif op in {0x2b, 0x2c}:
                stats['switches'] += 1
            elif op in {0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51}:
                stats['arrays'] += 1
            elif op in {0x22, 0x23, 0x24, 0x25}:
                stats['new_instances'] += 1
            elif op == 0x27:
                stats['throws'] += 1
            elif op in {0x1d, 0x1e}:
                stats['monitors'] += 1
        
        stats['complexity'] = (
            stats['invokes'] * 2 + stats['ifs'] * 3 + stats['gotos'] * 2 +
            stats['switches'] * 4 + stats['fields'] + stats['consts']
        )
        return stats

    @staticmethod
    def build_cfg(instructions):
        """构建控制流图（CFG）。

        返回 dict：
        - 'blocks': [{'start', 'end', 'instructions', 'successors', 'predecessors'}]
        - 'entry': 起始基本块 start 地址
        - 'edges': [(from_start, to_start)]
        """
        if not instructions:
            return {'blocks': [], 'entry': None, 'edges': []}

        # 指令按地址索引
        by_addr = {inst.address: inst for inst in instructions}
        addresses = sorted(by_addr.keys())
        addr_index = {a: i for i, a in enumerate(addresses)}

        # 收集所有基本块起点：函数入口 + 分支目标
        leaders = {addresses[0]}
        for inst in instructions:
            target = inst.get_branch_target()
            if target is not None and target in by_addr:
                leaders.add(target)
            # 终结指令的下一条是 leader
            if inst.is_terminator():
                i = addr_index[inst.address]
                if i + 1 < len(addresses):
                    leaders.add(addresses[i + 1])

        # 构建基本块
        blocks = []
        cur_start = None
        cur_insts = []
        block_map = {}  # start -> block index

        def flush():
            nonlocal cur_start, cur_insts
            if cur_insts:
                idx = len(blocks)
                blocks.append({
                    'start': cur_start,
                    'end': cur_insts[-1].address,
                    'instructions': cur_insts,
                    'successors': [],
                    'predecessors': [],
                })
                block_map[cur_start] = idx
                cur_insts = []

        for inst in instructions:
            if inst.address in leaders and cur_insts:
                flush()
            if not cur_insts:
                cur_start = inst.address
            cur_insts.append(inst)
            if inst.is_terminator() or inst.is_branch() or inst.is_switch():
                flush()
        flush()

        # 连接边
        for i, blk in enumerate(blocks):
            last = blk['instructions'][-1]
            nxt_i = addr_index[blk['end']] + 1
            nxt_addr = addresses[nxt_i] if nxt_i < len(addresses) else None

            succ = []
            if last.is_switch():
                # switch 仅能解析 packed/sparse 数据，偏移即目标
                t = last.get_branch_target()
                if t is not None and t in block_map:
                    succ.append(t)
                if nxt_addr is not None and nxt_addr in block_map:
                    succ.append(nxt_addr)
            elif last.is_branch():
                t = last.get_branch_target()
                if t is not None and t in block_map:
                    succ.append(t)
                if nxt_addr is not None and nxt_addr in block_map:
                    succ.append(nxt_addr)
            elif last.is_terminator():
                if last.name == 'throw':
                    # 异常可被 catch 捕获，此处不连边
                    pass
                else:
                    # goto/goto/16/goto/32 连到目标
                    t = last.get_branch_target()
                    if t is not None and t in block_map:
                        succ.append(t)
            else:
                if nxt_addr is not None and nxt_addr in block_map:
                    succ.append(nxt_addr)
            blk['successors'] = succ

        for blk in blocks:
            for s in blk['successors']:
                blocks[block_map[s]]['predecessors'].append(blk['start'])

        edges = [(b['start'], s) for b in blocks for s in b['successors']]
        entry = blocks[0]['start'] if blocks else None
        return {'blocks': blocks, 'entry': entry, 'edges': edges}

    @staticmethod
    def get_reachable_instructions(instructions):
        """返回从入口可达的指令集合（用于裁剪死代码分析）"""
        cfg = Disassembler.build_cfg(instructions)
        if not cfg['blocks']:
            return set()
        reachable = set()
        stack = [cfg['entry']]
        seen = set()
        while stack:
            start = stack.pop()
            if start in seen:
                continue
            seen.add(start)
            blk = next(b for b in cfg['blocks'] if b['start'] == start)
            for inst in blk['instructions']:
                reachable.add(inst.address)
            for s in blk['successors']:
                stack.append(s)
        return reachable

    # ════════════════════════════════════════════════════════════
    # 支配树与自然循环检测
    # ════════════════════════════════════════════════════════════

    @staticmethod
    def build_dominator_tree(instructions):
        """构建支配树（Dominator Tree）。

        使用迭代数据流算法计算每个基本块的直接支配者（immediate dominator）。

        Returns:
            dict: {
                'idom': {block_start -> idom_block_start},
                'dominators': {block_start -> set of all dominators},
                'dom_tree_children': {block_start -> [children_starts]},
                'frontier': {block_start -> [frontier_starts]},  # 支配边界
            }
        """
        cfg = Disassembler.build_cfg(instructions)
        if not cfg['blocks']:
            return {'idom': {}, 'dominators': {}, 'dom_tree_children': {}, 'frontier': {}}

        blocks = cfg['blocks']
        entry = cfg['entry']
        block_starts = [b['start'] for b in blocks]
        start_set = set(block_starts)

        # 建立前驱映射
        preds = {b['start']: set(b['predecessors']) for b in blocks}

        # 初始化：entry 的支配者集合 = {entry}，其余 = 全集
        dom = {}
        for s in block_starts:
            dom[s] = set(block_starts)
        dom[entry] = {entry}

        # 迭代至不动点
        changed = True
        while changed:
            changed = False
            for s in block_starts:
                if s == entry:
                    continue
                ps = preds.get(s, set())
                if not ps:
                    dom[s] = {s}
                    continue
                new_dom = set.intersection(*[dom[p] for p in ps if p in dom]) if ps else set()
                new_dom = new_dom | {s}
                if new_dom != dom[s]:
                    dom[s] = new_dom
                    changed = True

        # 计算直接支配者 (idom)
        idom = {}
        for s in block_starts:
            if s == entry:
                continue
            strict_doms = dom[s] - {s}
            # idom 是 strict_doms 中被所有其他 strict_dom 支配的那个
            for d in strict_doms:
                if all(d in dom[other] for other in strict_doms if other != d):
                    idom[s] = d
                    break

        # 支配树子节点
        dom_tree_children = {s: [] for s in block_starts}
        for s, d in idom.items():
            dom_tree_children[d].append(s)

        # 支配边界 (Dominance Frontier)
        frontier = {s: set() for s in block_starts}
        for b in blocks:
            s = b['start']
            ps = preds.get(s, set())
            if len(ps) >= 2:
                for p in ps:
                    runner = p
                    while runner != idom.get(s, entry):
                        frontier[runner].add(s)
                        runner = idom.get(runner, entry)

        return {
            'idom': idom,
            'dominators': {s: sorted(v) for s, v in dom.items()},
            'dom_tree_children': {s: sorted(v) for s, v in dom_tree_children.items()},
            'frontier': {s: sorted(v) for s, v in frontier.items()},
        }

    @staticmethod
    def detect_loops(instructions):
        """检测自然循环（Natural Loops）。

        基于支配树和回边（Back Edge）识别自然循环。

        Returns:
            list of dict: 每个循环包含 {
                'header': 回边目标（循环头）,
                'tail': 回边源,
                'body': 循环体中所有基本块 start 地址列表,
                'body_instructions': 循环体内指令总数,
                'is_infinite': 是否为无限循环（无退出边）,
            }
        """
        cfg = Disassembler.build_cfg(instructions)
        if not cfg['blocks']:
            return []

        dom_info = Disassembler.build_dominator_tree(instructions)
        idom = dom_info['idom']
        block_starts = set(b['start'] for b in blocks) if False else set(b['start'] for b in cfg['blocks'])

        # 找回边：边 (u -> v) 中 v 支配 u
        back_edges = []
        for b in cfg['blocks']:
            u = b['start']
            for v in b['successors']:
                if v == u:
                    back_edges.append((u, v))  # 自环
                elif idom.get(u) == v:
                    back_edges.append((u, v))
                elif v in dom_info['dominators'].get(u, []):
                    back_edges.append((u, v))

        # 去重
        back_edges = list(set(back_edges))

        loops = []
        block_map = {b['start']: b for b in cfg['blocks']}

        for tail, header in back_edges:
            # 自然循环 = {header} ∪ {能到达 tail 且不经过 header 的所有节点}
            loop_body = {header}
            if tail != header:
                loop_body.add(tail)
                stack = [tail]
                visited = {header, tail}
                while stack:
                    node = stack.pop()
                    blk = block_map.get(node)
                    if not blk:
                        continue
                    for p in blk['predecessors']:
                        if p not in visited:
                            visited.add(p)
                            loop_body.add(p)
                            stack.append(p)

            # 统计指令数
            insn_count = sum(len(block_map[s]['instructions']) for s in loop_body if s in block_map)

            # 检查是否有退出边（循环体到非循环体的边）
            has_exit = False
            for s in loop_body:
                blk = block_map.get(s)
                if not blk:
                    continue
                for succ in blk['successors']:
                    if succ not in loop_body:
                        has_exit = True
                        break
                if has_exit:
                    break

            loops.append({
                'header': header,
                'tail': tail,
                'body': sorted(loop_body),
                'body_instructions': insn_count,
                'is_infinite': not has_exit,
                'exit_count': sum(
                    1 for s in loop_body
                    if s in block_map
                    for succ in block_map[s]['successors']
                    if succ not in loop_body
                ),
            })

        return loops

    # ════════════════════════════════════════════════════════════
    # 方法相似度 / 克隆检测
    # ════════════════════════════════════════════════════════════

    @staticmethod
    def compute_method_fingerprint(instructions):
        """计算方法指纹（opcode 序列哈希）。

        将方法中所有指令的 opcode 序列提取为指纹，用于快速比较方法相似度。
        忽略寄存器号和常量值，只保留操作语义。

        Returns:
            dict: {
                'opcode_sequence': [opcode1, opcode2, ...],
                'opcode_hash': 序列的哈希值（hex 字符串）,
                'normalized_sequence': 归一化后的 opcode 名称序列,
                'instruction_count': 指令总数,
                'unique_opcodes': 使用的不同 opcode 数,
            }
        """
        if not instructions:
            return {
                'opcode_sequence': [],
                'opcode_hash': '',
                'normalized_sequence': [],
                'instruction_count': 0,
                'unique_opcodes': 0,
            }

        opcodes = [inst.opcode for inst in instructions]
        opcode_names = [inst.name for inst in instructions]

        import hashlib
        seq_bytes = bytes(opcodes)
        h = hashlib.md5(seq_bytes).hexdigest()

        return {
            'opcode_sequence': opcodes,
            'opcode_hash': h,
            'normalized_sequence': opcode_names,
            'instruction_count': len(opcodes),
            'unique_opcodes': len(set(opcodes)),
        }

    @staticmethod
    def detect_method_clones(methods_data):
        """检测方法克隆/重复代码。

        Args:
            methods_data: list of dict, 每个包含:
                - 'class_name': 类名
                - 'method_name': 方法名
                - 'instructions': Instruction 列表
                - 'access_flags': 访问标志（可选）

        Returns:
            dict: {
                'clone_groups': [{fingerprint, count, methods: [...]}],
                'total_methods': int,
                'duplicated_methods': int,
                'duplication_ratio': float,
            }
        """
        from collections import defaultdict

        fingerprints = defaultdict(list)
        total = len(methods_data)

        for m in methods_data:
            insts = m.get('instructions', [])
            fp = Disassembler.compute_method_fingerprint(insts)
            if fp['instruction_count'] < 3:
                continue  # 忽略极短方法
            fingerprints[fp['opcode_hash']].append({
                'class': m.get('class_name', '?'),
                'method': m.get('method_name', '?'),
                'instruction_count': fp['instruction_count'],
                'access_flags': m.get('access_flags', ''),
            })

        clone_groups = []
        duplicated = 0
        for fp_hash, methods in fingerprints.items():
            if len(methods) >= 2:
                clone_groups.append({
                    'fingerprint': fp_hash,
                    'count': len(methods),
                    'instruction_count': methods[0]['instruction_count'],
                    'methods': methods,
                })
                duplicated += len(methods)

        clone_groups.sort(key=lambda x: x['count'] * x['instruction_count'], reverse=True)

        return {
            'clone_groups': clone_groups,
            'total_methods': total,
            'duplicated_methods': duplicated,
            'duplication_ratio': round(duplicated / total, 4) if total > 0 else 0.0,
        }

    # ════════════════════════════════════════════════════════════
    # 字符串交叉引用分析
    # ════════════════════════════════════════════════════════════

    @staticmethod
    def find_string_xrefs(instructions, strings=None, methods=None):
        """查找方法中对字符串常量的引用。

        扫描所有 const-string / const-string/jumbo 指令，
        记录每个字符串被引用的位置。

        Args:
            instructions: Instruction 列表
            strings: DEX 字符串表
            methods: DEX 方法表（用于解析引用上下文）

        Returns:
            list of dict: [{
                'string_idx': 字符串索引,
                'string_value': 字符串值,
                'address': 引用地址,
                'register': 寄存器,
                'instruction': 指令名,
            }]
        """
        xrefs = []
        for inst in instructions:
            if inst.opcode in (0x1a, 0x1b):  # const-string / const-string/jumbo
                ref = inst.operands.get('ref', -1)
                val = ''
                if strings and 0 <= ref < len(strings):
                    val = strings[ref]
                xrefs.append({
                    'string_idx': ref,
                    'string_value': val,
                    'address': inst.address,
                    'register': inst.operands.get('vA', -1),
                    'instruction': inst.name,
                })
        return xrefs

    @staticmethod
    def find_field_xrefs(instructions, fields=None):
        """查找方法中对字段（field）的引用。

        扫描所有 iget/iput/sget/sput 指令，
        记录每个字段被读/写的位置。

        Returns:
            list of dict: [{
                'field_idx': 字段索引,
                'field_name': 字段名,
                'class_name': 字段所属类,
                'access_type': 'read' | 'write',
                'address': 引用地址,
                'instruction': 指令名,
            }]
        """
        xrefs = []
        READ_OPS = {0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
                     0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66}
        WRITE_OPS = {0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                      0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d}

        for inst in instructions:
            if inst.opcode in READ_OPS or inst.opcode in WRITE_OPS:
                ref = inst.operands.get('ref', -1)
                field_info = None
                if fields and 0 <= ref < len(fields):
                    f = fields[ref]
                    if isinstance(f, dict):
                        field_info = f
                    else:
                        field_info = {'name': str(f), 'class_name': ''}

                xrefs.append({
                    'field_idx': ref,
                    'field_name': field_info.get('name', f'field@{ref}') if field_info else f'field@{ref}',
                    'class_name': field_info.get('class_name', '') if field_info else '',
                    'field_type': field_info.get('type', '') if field_info else '',
                    'access_type': 'read' if inst.opcode in READ_OPS else 'write',
                    'address': inst.address,
                    'instruction': inst.name,
                })
        return xrefs

    @staticmethod
    def find_type_xrefs(instructions, types=None):
        """查找方法中对类型（type）的引用。

        扫描 const-class / check-cast / instance-of / new-instance / new-array 等指令。

        Returns:
            list of dict: [{
                'type_idx': 类型索引,
                'type_desc': 类型描述符,
                'usage': 引用场景 (const-class/check-cast/instance-of/new-instance/new-array),
                'address': 引用地址,
            }]
        """
        TYPE_REF_OPS = {
            0x1c: 'const-class',
            0x1f: 'check-cast',
            0x20: 'instance-of',
            0x22: 'new-instance',
            0x23: 'new-array',
        }
        xrefs = []
        for inst in instructions:
            if inst.opcode in TYPE_REF_OPS:
                ref = inst.operands.get('ref', -1)
                type_desc = ''
                if types and 0 <= ref < len(types):
                    t = types[ref]
                    type_desc = t.get('descriptor', '') if isinstance(t, dict) else str(t)
                xrefs.append({
                    'type_idx': ref,
                    'type_desc': type_desc,
                    'usage': TYPE_REF_OPS[inst.opcode],
                    'address': inst.address,
                    'instruction': inst.name,
                })
        return xrefs

    # ════════════════════════════════════════════════════════════
    # 异常流分析 (Exception Flow Analysis)
    # ════════════════════════════════════════════════════════════

    @staticmethod
    def analyze_exception_flow(instructions, try_catch_info=None):
        """分析方法中的异常流。

        将 try/catch 信息与 CFG 结合，构建异常边，
        分析哪些基本块可能因异常而跳转到 catch handler。

        Args:
            instructions: Instruction 列表
            try_catch_info: TryCatchParser.parse() 的返回值

        Returns:
            dict: {
                'try_ranges': [{start, end, handlers: [...]}],
                'exception_edges': [{from_block, to_handler, exception_type}],
                'protected_blocks': 受 try 保护的基本块集合,
                'unprotected_throws': 不在 try 范围内的 throw 指令,
                'handler_count': catch handler 总数,
                'catch_all': 是否存在 catch-all,
            }
        """
        cfg = Disassembler.build_cfg(instructions)
        blocks = cfg.get('blocks', [])
        try_catch = try_catch_info or {}

        tries = try_catch.get('tries', [])
        handlers_list = try_catch.get('handlers', [])

        # 建立地址 -> 基本块映射
        addr_to_block = {}
        for b in blocks:
            for inst in b['instructions']:
                addr_to_block[inst.address] = b['start']

        # 处理每个 try 范围
        exception_edges = []
        protected_addrs = set()
        try_ranges = []
        catch_all_found = False
        handler_count = 0

        for i, tri in enumerate(tries):
            start_addr = tri.get('start_addr', 0)
            end_addr = tri.get('end_addr', 0)
            insn_count = tri.get('insn_count', 0)

            # 标记受保护的地址范围
            for addr in range(start_addr, start_addr + insn_count * 2, 2):
                protected_addrs.add(addr)

            # 获取对应的 handlers
            handler_info = handlers_list[i] if i < len(handlers_list) else {}
            catch_handlers = handler_info.get('catch_handlers', [])
            catch_all_addr = handler_info.get('catch_all_addr', None)

            handlers_detail = []
            for ch in catch_handlers:
                handler_count += 1
                type_name = ch.get('type_name', 'java/lang/Throwable')
                handler_addr = ch.get('handler_addr', 0)
                handlers_detail.append({
                    'type': type_name,
                    'handler_addr': handler_addr,
                })
                # 添加异常边：从受保护范围内的每个基本块到 handler
                for b in blocks:
                    blk_start = b['start']
                    blk_end = b['instructions'][-1].address if b['instructions'] else blk_start
                    # 检查基本块是否与 try 范围重叠
                    if blk_start >= start_addr and blk_end < (start_addr + insn_count * 2):
                        exception_edges.append({
                            'from_block': blk_start,
                            'to_handler': handler_addr,
                            'exception_type': type_name,
                        })

            if catch_all_addr is not None:
                catch_all_found = True
                handler_count += 1
                handlers_detail.append({
                    'type': 'catch_all',
                    'handler_addr': catch_all_addr,
                })
                for b in blocks:
                    blk_start = b['start']
                    blk_end = b['instructions'][-1].address if b['instructions'] else blk_start
                    if blk_start >= start_addr and blk_end < (start_addr + insn_count * 2):
                        exception_edges.append({
                            'from_block': blk_start,
                            'to_handler': catch_all_addr,
                            'exception_type': 'catch_all',
                        })

            try_ranges.append({
                'start': start_addr,
                'end': end_addr,
                'insn_count': insn_count,
                'handlers': handlers_detail,
            })

        # 查找不在 try 范围内的 throw 指令
        unprotected_throws = []
        for inst in instructions:
            if inst.opcode == 0x27:  # throw
                if inst.address not in protected_addrs:
                    unprotected_throws.append({
                        'address': inst.address,
                        'instruction': inst.name,
                    })

        # 去重异常边
        seen_edges = set()
        unique_edges = []
        for e in exception_edges:
            key = (e['from_block'], e['to_handler'], e['exception_type'])
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(e)

        return {
            'try_ranges': try_ranges,
            'exception_edges': unique_edges,
            'protected_blocks': sorted(set(
                addr_to_block[a] for a in protected_addrs if a in addr_to_block
            )),
            'unprotected_throws': unprotected_throws,
            'handler_count': handler_count,
            'catch_all': catch_all_found,
        }
