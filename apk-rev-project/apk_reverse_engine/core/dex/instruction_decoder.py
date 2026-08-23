"""DEX 指令解码器 - 将字节码解码为指令对象"""
import struct
from .opcode_table import (
    Opcode, OPCODE_FORMAT, OPCODE_NAMES,
    get_opcode_name, get_opcode_format, get_opcode_size,
    is_invoke, is_field_access, is_const, is_return, is_if, is_goto, is_branch
)

def _u2(data, off):
    return struct.unpack_from('<H', data, off)[0]

def _u4(data, off):
    return struct.unpack_from('<I', data, off)[0]

def _i2(data, off):
    return struct.unpack_from('<h', data, off)[0]

def _i4(data, off):
    return struct.unpack_from('<i', data, off)[0]

def _q(data, off):
    return struct.unpack_from('<q', data, off)[0]

def _sbyte(b):
    return b - 256 if b >= 128 else b

class Instruction:
    """单条 Dalvik 指令"""
    __slots__ = ('address', 'opcode', 'name', 'format', 'size', 'operands', 'raw_bytes')
    
    def __init__(self, address, opcode, name, format_name, size, operands=None, raw_bytes=None):
        self.address = address
        self.opcode = opcode
        self.name = name
        self.format = format_name
        self.size = size
        self.operands = operands or {}
        self.raw_bytes = raw_bytes
    
    def __repr__(self):
        return f'{self.address:04x}: {self.name} {self.operands}'
    
    def get_branch_target(self):
        """返回分支目标地址（无条件/条件跳转、switch），非分支返回 None"""
        ops = self.operands
        if 'offset' in ops:
            return self.address + ops['offset']
        return None
    
    def is_terminator(self):
        """是否为基本块终止指令"""
        return self.name in ('return-void', 'return', 'return-wide', 'return-object',
                              'throw', 'goto', 'goto/16', 'goto/32')
    
    def is_branch(self):
        """是否为条件分支"""
        return self.name.startswith('if-')
    
    def is_switch(self):
        """是否为 switch 指令"""
        return self.name in ('packed-switch', 'sparse-switch')
    
    def to_string(self, strings=None, types=None, fields=None, methods=None):
        """格式化为可读指令字符串"""
        ops = self.operands
        if self.name == 'const-string/jumbo' and self.format == '31c':
            idx = ops.get('ref', 0)
            ref_str = ''
            if strings and idx < len(strings):
                ref_str = f' // {strings[idx]}'
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, type@0x{idx:x}{ref_str}'
        if self.format == '10x':
            return f'{self.address:04x}: {self.name}'
        elif self.format == '11n':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, #{ops.get("litB")}'
        elif self.format == '11x':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}'
        elif self.format == '12x':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, v{ops.get("vB")}'
        elif self.format == '21c':
            idx = ops.get('ref', 0)
            ref_str = ''
            if self.name == 'const-string' and strings and idx < len(strings):
                ref_str = f' // {strings[idx]}'
            elif self.name == 'const-class' and types and idx < len(types):
                ref_str = f' // {types[idx]}'
            elif self.name.startswith('sget') or self.name.startswith('sput'):
                if fields and idx < len(fields):
                    ref_str = f' // {fields[idx]}'
            elif self.name == 'check-cast' and types and idx < len(types):
                ref_str = f' // {types[idx]}'
            elif self.name == 'new-instance' and types and idx < len(types):
                ref_str = f' // {types[idx]}'
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, type@0x{idx:x}{ref_str}'
        elif self.format == '21s':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, #{ops.get("litB")}'
        elif self.format == '21h':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, #{ops.get("litB"):#06x}'
        elif self.format == '21t':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, :{self.address + ops.get("offset", 0):04x}'
        elif self.format == '22c':
            idx = ops.get('ref', 0)
            ref_str = ''
            if (self.name.startswith('iget') or self.name.startswith('iput')) and fields and idx < len(fields):
                ref_str = f' // {fields[idx]}'
            elif self.name == 'instance-of' and types and idx < len(types):
                ref_str = f' // {types[idx]}'
            elif self.name == 'new-array' and types and idx < len(types):
                ref_str = f' // {types[idx]}'
            elif types and idx < len(types):
                ref_str = f' // {types[idx]}'
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, v{ops.get("vB")}, type@0x{idx:x}{ref_str}'
        elif self.format == '22s':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, v{ops.get("vB")}, #{ops.get("litC")}'
        elif self.format == '22b':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, v{ops.get("vB")}, #{ops.get("litC")}'
        elif self.format == '22t':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, v{ops.get("vB")}, :{self.address + ops.get("offset", 0):04x}'
        elif self.format == '22x':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, v{ops.get("vB"):#x}'
        elif self.format == '23x':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, v{ops.get("vB")}, v{ops.get("vC")}'
        elif self.format == '30t':
            return f'{self.address:04x}: {self.name} :{self.address + ops.get("offset", 0):04x}'
        elif self.format == '31c':
            idx = ops.get('ref', 0)
            ref_str = ''
            if strings and idx < len(strings):
                ref_str = f' // {strings[idx]}'
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, type@0x{idx:x}{ref_str}'
        elif self.format == '31i':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, #{ops.get("litB"):#x}'
        elif self.format == '31t':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, :{self.address + ops.get("offset", 0):04x}'
        elif self.format == '32x':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, v{ops.get("vB")}'
        elif self.format == '35c':
            idx = ops.get('ref', 0)
            ref_str = ''
            if methods and idx < len(methods):
                ref_str = f' // {methods[idx]}'
            regs = ops.get('registers', [])
            reg_str = ', '.join(f'v{r}' for r in regs) if regs else '{}'
            return f'{self.address:04x}: {self.name} {{{reg_str}}}, type@0x{idx:x}{ref_str}'
        elif self.format == '3rc':
            idx = ops.get('ref', 0)
            ref_str = ''
            if methods and idx < len(methods):
                ref_str = f' // {methods[idx]}'
            start = ops.get('start_reg', 0)
            count = ops.get('reg_count', 0)
            return f'{self.address:04x}: {self.name} {{v{start} .. v{start+count-1}}}, type@0x{idx:x}{ref_str}'
        elif self.format == '51l':
            return f'{self.address:04x}: {self.name} v{ops.get("vA")}, #{ops.get("litB"):#018x}'
        elif self.format in ('10t', '20t'):
            return f'{self.address:04x}: {self.name} :{self.address + ops.get("offset", 0):04x}'
        else:
            return f'{self.address:04x}: {self.name} {ops}'

class InstructionDecoder:
    """DEX 指令解码器"""
    
    @staticmethod
    def decode(data, offset, strings=None, types=None, fields=None, methods=None):
        """解码单条指令"""
        opcode = data[offset]
        info = OPCODE_FORMAT.get(opcode)
        if not info:
            return Instruction(offset, opcode, f'unknown_0x{opcode:02x}', 'unknown', 1, {}, data[offset:offset+2])
        
        name, fmt, size = info
        operands = {}
        cu = offset  # code_unit offset (2-byte aligned)
        
        if fmt == '10x':
            pass
        elif fmt == '12x':
            vA = data[cu+1] & 0x0f
            vB = (data[cu+1] >> 4) & 0x0f
            operands['vA'] = vA; operands['vB'] = vB
        elif fmt == '11n':
            vA = data[cu+1] & 0x0f
            litB = (data[cu+1] >> 4) & 0x0f
            litB = _sbyte(litB) if litB & 0x8 else litB
            operands['vA'] = vA; operands['litB'] = litB
        elif fmt == '11x':
            operands['vA'] = data[cu+1]
        elif fmt == '10t':
            off = _sbyte(data[cu+1])
            operands['offset'] = off
        elif fmt == '20t':
            off = _i2(data, cu+2)
            operands['offset'] = off
        elif fmt == '21c':
            vA = data[cu+1]
            ref = _u2(data, cu+2)
            operands['vA'] = vA; operands['ref'] = ref
        elif fmt == '21s':
            vA = data[cu+1]
            litB = _i2(data, cu+2)
            operands['vA'] = vA; operands['litB'] = litB
        elif fmt == '21h':
            vA = data[cu+1]
            litB = _i2(data, cu+2)
            operands['vA'] = vA; operands['litB'] = litB
        elif fmt == '21t':
            vA = data[cu+1]
            off = _i2(data, cu+2)
            operands['vA'] = vA; operands['offset'] = off
        elif fmt == '22c':
            vA = data[cu+1] & 0x0f
            vB = (data[cu+1] >> 4) & 0x0f
            ref = _u2(data, cu+2)
            operands['vA'] = vA; operands['vB'] = vB; operands['ref'] = ref
        elif fmt == '22s':
            vA = data[cu+1] & 0x0f
            vB = (data[cu+1] >> 4) & 0x0f
            litC = _i2(data, cu+2)
            operands['vA'] = vA; operands['vB'] = vB; operands['litC'] = litC
        elif fmt == '22b':
            vA = data[cu+1]
            vB = data[cu+2]
            litC = _sbyte(data[cu+3])
            operands['vA'] = vA; operands['vB'] = vB; operands['litC'] = litC
        elif fmt == '22t':
            vA = data[cu+1] & 0x0f
            vB = (data[cu+1] >> 4) & 0x0f
            off = _i2(data, cu+2)
            operands['vA'] = vA; operands['vB'] = vB; operands['offset'] = off
        elif fmt == '22x':
            vA = data[cu+1]
            vB = _u2(data, cu+2)
            operands['vA'] = vA; operands['vB'] = vB
        elif fmt == '23x':
            vA = data[cu+1]
            vB = data[cu+2]
            vC = data[cu+3]
            operands['vA'] = vA; operands['vB'] = vB; operands['vC'] = vC
        elif fmt == '30t':
            off = _i4(data, cu+2)
            operands['offset'] = off
        elif fmt == '31c':
            vA = data[cu+1]
            ref = _u4(data, cu+2)
            operands['vA'] = vA; operands['ref'] = ref
        elif fmt == '31i':
            vA = data[cu+1]
            litB = _i4(data, cu+2)
            operands['vA'] = vA; operands['litB'] = litB
        elif fmt == '31t':
            vA = data[cu+1]
            off = _i4(data, cu+2)
            operands['vA'] = vA; operands['offset'] = off
        elif fmt == '32x':
            vA = _u2(data, cu+2)
            vB = _u2(data, cu+4)
            operands['vA'] = vA; operands['vB'] = vB
        elif fmt == '35c':
            reg_count = data[cu+1] & 0x0f
            ref = _u2(data, cu+4)
            operands['ref'] = ref
            regs = []
            if reg_count > 0: regs.append((data[cu+2] >> 4) & 0x0f)
            if reg_count > 1: regs.append(data[cu+2] & 0x0f)
            if reg_count > 2: regs.append((data[cu+3] >> 4) & 0x0f)
            if reg_count > 3: regs.append(data[cu+3] & 0x0f)
            if reg_count > 4: regs.append((data[cu+1] >> 4) & 0x0f)
            operands['registers'] = regs[:reg_count]
            operands['reg_count'] = reg_count
        elif fmt == '3rc':
            reg_count = data[cu+1]
            ref = _u2(data, cu+4)
            start_reg = _u2(data, cu+2)
            operands['ref'] = ref; operands['reg_count'] = reg_count; operands['start_reg'] = start_reg
        elif fmt == '51l':
            vA = data[cu+1]
            litB = _q(data, cu+2)
            operands['vA'] = vA; operands['litB'] = litB
        
        raw = data[offset:offset + size * 2]
        return Instruction(offset, opcode, name, fmt, size, operands, raw)
    
    @staticmethod
    def decode_all(data, offset=0, limit=None, strings=None, types=None, fields=None, methods=None):
        """解码所有指令直到边界"""
        instructions = []
        size = len(data)
        while offset < size and (limit is None or len(instructions) < limit):
            inst = InstructionDecoder.decode(data, offset, strings, types, fields, methods)
            instructions.append(inst)
            offset += inst.size * 2
        return instructions

    # ── Switch Payload 解码 ──────────────────────────────────────

    @staticmethod
    def decode_packed_switch(data, offset):
        """解析 packed-switch-payload 表。

        格式: ident(2) size(2) first_key(4) targets[size](4)
        返回: {'first_key', 'targets': [relative_offset, ...], 'absolute_targets': [abs_addr, ...]}
        """
        try:
            ident = _u2(data, offset)
            if ident != 0x0100:
                return {'error': f'非 packed-switch 负载 (ident=0x{ident:04x})'}
            size = _u2(data, offset + 2)
            first_key = _i4(data, offset + 4)
            targets = []
            pos = offset + 8
            for _ in range(size):
                targets.append(_i4(data, pos))
                pos += 4
            return {
                'type': 'packed',
                'first_key': first_key,
                'targets': targets,
                'size': size,
            }
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def decode_sparse_switch(data, offset):
        """解析 sparse-switch-payload 表。

        格式: ident(2) size(2) keys[size](4) targets[size](4)
        返回: {'keys': [...], 'targets': [relative_offset, ...], 'size': size}
        """
        try:
            ident = _u2(data, offset)
            if ident != 0x0200:
                return {'error': f'非 sparse-switch 负载 (ident=0x{ident:04x})'}
            size = _u2(data, offset + 2)
            keys = []
            targets = []
            pos = offset + 4
            for _ in range(size):
                keys.append(_i4(data, pos))
                pos += 4
            for _ in range(size):
                targets.append(_i4(data, pos))
                pos += 4
            return {
                'type': 'sparse',
                'keys': keys,
                'targets': targets,
                'size': size,
            }
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def decode_array_data(data, offset):
        """解析 fill-array-data-payload 表。

        格式: ident(2) element_width(2) size(4) data[element_width * size]
        返回: {'element_width', 'size', 'values': [...]}
        """
        try:
            ident = _u2(data, offset)
            if ident != 0x0300:
                return {'error': f'非 array-data 负载 (ident=0x{ident:04x})'}
            element_width = _u2(data, offset + 2)
            size = _u4(data, offset + 4)
            values = []
            pos = offset + 8
            for _ in range(size):
                raw = data[pos:pos + element_width]
                if element_width == 1:
                    values.append(raw[0])
                elif element_width == 2:
                    values.append(struct.unpack_from('<h', data, pos)[0])
                elif element_width == 4:
                    values.append(struct.unpack_from('<i', data, pos)[0])
                elif element_width == 8:
                    values.append(struct.unpack_from('<q', data, pos)[0])
                else:
                    values.append(raw.hex())
                pos += element_width
            return {
                'element_width': element_width,
                'size': size,
                'values': values,
                'raw_hex': data[offset + 8:offset + 8 + element_width * size].hex() if size <= 256 else None,
            }
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def resolve_switch_targets(data, switch_inst):
        """给定一条 packed-switch/sparse-switch 指令，解析其 payload 表
        并返回所有绝对跳转目标地址列表。

        Args:
            data: DEX 文件字节
            switch_inst: Instruction 对象（packed-switch 或 sparse-switch）

        Returns:
            list of int: 绝对目标地址列表
        """
        if not switch_inst or not switch_inst.is_switch():
            return []

        payload_off = switch_inst.operands.get('offset', 0)
        if payload_off == 0:
            return []

        abs_payload = switch_inst.address + payload_off
        if abs_payload < 0 or abs_payload >= len(data):
            return []

        if switch_inst.name == 'packed-switch':
            payload = InstructionDecoder.decode_packed_switch(data, abs_payload)
            targets = payload.get('targets', [])
        else:
            payload = InstructionDecoder.decode_sparse_switch(data, abs_payload)
            targets = payload.get('targets', [])

        # targets 是相对 switch 指令地址的偏移
        return [switch_inst.address + t for t in targets if t is not None]
