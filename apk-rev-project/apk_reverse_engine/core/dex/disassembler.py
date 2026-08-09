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
