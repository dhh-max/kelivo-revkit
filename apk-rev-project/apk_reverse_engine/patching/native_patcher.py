"""原生SO文件高级补丁工具 - 支持ARM/Thumb/AArch64/x86/x86_64"""
import struct
import re

# ARM指令编码常量
ARM_NOP = 0xe1a00000       # mov r0, r0
ARM_RET = 0xe12fff1e        # bx lr
ARM_BX_LR = 0xe12fff1e
ARM_MOV_R0_0 = 0xe3a00000   # mov r0, #0
ARM_MOV_R0_1 = 0xe3a00001   # mov r0, #1

# Thumb指令编码常量
THUMB_NOP = 0x46c0          # nop (mov r8, r8)
THUMB_RET = 0x4770          # bx lr
THUMB_MOV_R0_0 = 0x2000     # movs r0, #0
THUMB_MOV_R0_1 = 0x2001     # movs r0, #1

# AArch64指令编码常量
AARCH64_NOP = 0xd503201f
AARCH64_RET = 0xd65f03c0
AARCH64_MOV_R0_0 = 0xd2800000  # mov x0, #0
AARCH64_MOV_R0_1 = 0xd2800020  # mov x0, #1
AARCH64_BKPT = 0xd4200000

# x86/x86_64指令编码常量
X86_NOP = 0x90
X86_RET = 0xc3
X86_RETF = 0xcb
X86_XOR_EAX_EAX = 0x31c0     # xor eax, eax
X86_MOV_EAX_0 = 0xb800000000  # mov eax, 0 (5 bytes)


class NativePatcher:
    """原生SO文件高级补丁工具"""

    @staticmethod
    def detect_arch(data, offset=0):
        """检测指定偏移处的指令集架构"""
        if offset < 0 or offset + 4 > len(data):
            return 'unknown'
        
        word = struct.unpack_from('<I', data, offset)[0]
        
        # AArch64: 指令编码特征
        if (word & 0xfc000000) == 0x14000000:  # B/BL
            return 'aarch64'
        if (word & 0xff000000) == 0x54000000:  # B.cond
            return 'aarch64'
        if (word & 0x1f000000) == 0x10000000:  # ADR/ADRP
            return 'aarch64'
        
        # ARM: 检查条件码（高位4位）
        cond = (word >> 28) & 0xf
        if cond != 0xf and cond <= 0xe:  # 条件码有效
            # 检查是否是ARM指令
            if (word & 0x0c000000) != 0x0c000000:  # 不是未定义
                return 'arm'
        
        # Thumb: 检查低位
        if (word & 0xffff) >= 0x4800 and (word & 0xffff) <= 0x4fff:  # LDR Rd, [PC, #imm]
            return 'thumb'
        if (word & 0xf800) in (0x2000, 0x2800):  # MOVS Rd, #imm8
            return 'thumb'
        
        # x86_64: 检查常见指令
        if data[offset] == 0x55:  # push rbp
            return 'x86_64'
        if data[offset] == 0x48:  # REX prefix
            return 'x86_64'
        if data[offset] == 0x90:  # nop
            return 'x86'
        if data[offset] == 0xc3:  # ret
            return 'x86'
        
        return 'unknown'

    @staticmethod
    def patch_hex(data, old_hex, new_hex):
        """十六进制替换"""
        old = bytes.fromhex(old_hex.replace(' ', ''))
        new = bytes.fromhex(new_hex.replace(' ', ''))
        return data.replace(old, new)

    @staticmethod
    def patch_hex_at(data, offset, hex_str):
        """在指定偏移处写入十六进制字节"""
        new_bytes = bytes.fromhex(hex_str.replace(' ', ''))
        if offset < 0 or offset + len(new_bytes) > len(data):
            raise ValueError(f'Invalid offset {offset} or size {len(new_bytes)}')
        return data[:offset] + new_bytes + data[offset + len(new_bytes):]

    @staticmethod
    def patch_string(data, old_str, new_str, max_replace=1):
        """字符串替换（保留空终止符）"""
        old = old_str.encode() + b'\x00'
        new = new_str.encode() + b'\x00'
        if len(new) > len(old):
            new = new[:len(old)]
        count = 0
        result = data
        while count < max_replace:
            idx = result.find(old)
            if idx == -1:
                break
            result = result[:idx] + new + result[idx + len(old):]
            count += 1
        return result

    @staticmethod
    def patch_bytes(data, offset, new_bytes):
        """在指定偏移处写入字节"""
        if offset < 0 or offset + len(new_bytes) > len(data):
            raise ValueError(f'Invalid offset {offset} or size {len(new_bytes)}')
        return data[:offset] + new_bytes + data[offset + len(new_bytes):]

    @staticmethod
    def patch_word(data, offset, value, little_endian=True):
        """在指定偏移处写入32位值"""
        fmt = '<I' if little_endian else '>I'
        return NativePatcher.patch_bytes(data, offset, struct.pack(fmt, value))

    @staticmethod
    def patch_qword(data, offset, value, little_endian=True):
        """在指定偏移处写入64位值"""
        fmt = '<Q' if little_endian else '>Q'
        return NativePatcher.patch_bytes(data, offset, struct.pack(fmt, value))

    @staticmethod
    def nop_out(data, offset, count=4, arch='aarch64'):
        """用NOP指令填充指定区域"""
        if count <= 0:
            return data
        
        if arch == 'aarch64':
            nop_bytes = struct.pack('<I', AARCH64_NOP)
            return data[:offset] + nop_bytes * count + data[offset + count * 4:]
        elif arch == 'arm':
            nop_bytes = struct.pack('<I', ARM_NOP)
            return data[:offset] + nop_bytes * count + data[offset + count * 4:]
        elif arch == 'thumb':
            nop_bytes = struct.pack('<H', THUMB_NOP)
            return data[:offset] + nop_bytes * count + data[offset + count * 2:]
        elif arch == 'x86_64' or arch == 'x86':
            return data[:offset] + bytes([X86_NOP]) * count + data[offset + count:]
        else:
            # 自动检测
            detected = NativePatcher.detect_arch(data, offset)
            return NativePatcher.nop_out(data, offset, count, detected)

    @staticmethod
    def patch_branch_to_ret(data, offset, arch='aarch64'):
        """将分支/调用指令替换为返回指令"""
        if arch == 'aarch64':
            ret_bytes = struct.pack('<I', AARCH64_RET)
        elif arch == 'arm':
            ret_bytes = struct.pack('<I', ARM_RET)
        elif arch == 'thumb':
            ret_bytes = struct.pack('<H', THUMB_RET)
        elif arch == 'x86_64':
            ret_bytes = bytes([X86_RET])
        elif arch == 'x86':
            ret_bytes = bytes([X86_RET])
        else:
            detected = NativePatcher.detect_arch(data, offset)
            return NativePatcher.patch_branch_to_ret(data, offset, detected)
        return NativePatcher.patch_bytes(data, offset, ret_bytes)

    @staticmethod
    def patch_branch_to_mov_r0(data, offset, value=0, arch='aarch64'):
        """将分支替换为 mov r0, #value + ret"""
        if arch == 'aarch64':
            mov = struct.pack('<I', AARCH64_MOV_R0_0 if value == 0 else AARCH64_MOV_R0_0 + (value * 0x20))
            ret = struct.pack('<I', AARCH64_RET)
            return data[:offset] + mov + ret + data[offset + 8:]
        elif arch == 'arm':
            mov = struct.pack('<I', ARM_MOV_R0_0 + value)
            ret = struct.pack('<I', ARM_RET)
            return data[:offset] + mov + ret + data[offset + 8:]
        elif arch == 'thumb':
            mov = struct.pack('<H', THUMB_MOV_R0_0 + value)
            ret = struct.pack('<H', THUMB_RET)
            return data[:offset] + mov + ret + data[offset + 4:]
        elif arch == 'x86_64':
            # xor eax, eax; ret
            patch = struct.pack('<H', X86_XOR_EAX_EAX) + bytes([X86_RET])
            return data[:offset] + patch + data[offset + 3:]
        else:
            detected = NativePatcher.detect_arch(data, offset)
            return NativePatcher.patch_branch_to_mov_r0(data, offset, value, detected)

    @staticmethod
    def patch_jni_function(data, old_func_name, new_func_name):
        """修改JNI函数名"""
        old = old_func_name.encode() + b'\x00'
        new = new_func_name.encode() + b'\x00'
        if len(new) > len(old):
            new = new[:len(old)]
        return data.replace(old, new)

    @staticmethod
    def find_and_nop_jni_calls(data, jni_func_name):
        """查找并NOP掉对指定JNI函数的调用"""
        return data.replace(jni_func_name.encode(), b'\x00' * len(jni_func_name))

    @staticmethod
    def patch_elf_entrypt(data, new_entry_offset):
        """修改ELF入口点"""
        if len(data) < 64:
            return data
        is64 = data[4] == 2
        endian = '<' if data[5] == 1 else '>'
        if is64:
            return data[:24] + struct.pack(endian + 'Q', new_entry_offset) + data[32:]
        else:
            return data[:24] + struct.pack(endian + 'I', new_entry_offset) + data[28:]

    @staticmethod
    def patch_arm_branch(data, offset, target_offset, bl=False, arch='aarch64'):
        """在指定偏移处写入跳转指令"""
        if offset < 0 or offset + 4 > len(data):
            return data
        
        if arch == 'aarch64':
            # 计算偏移（以4字节为单位）
            diff = target_offset - offset
            if diff % 4 != 0:
                return data
            imm = diff // 4
            if imm < -0x2000000 or imm > 0x1ffffff:
                return data  # 超出范围
            
            if bl:
                # BL: 0x94000000 | (imm & 0x3ffffff)
                instr = 0x94000000 | (imm & 0x3ffffff)
            else:
                # B: 0x14000000 | (imm & 0x3ffffff)
                instr = 0x14000000 | (imm & 0x3ffffff)
            return NativePatcher.patch_bytes(data, offset, struct.pack('<I', instr))
        
        elif arch == 'arm':
            diff = target_offset - offset - 8  # ARM流水线偏移
            if diff % 4 != 0:
                return data
            imm = diff // 4
            if imm < -0x800000 or imm > 0x7fffff:
                return data
            if bl:
                instr = 0xeb000000 | (imm & 0xffffff)
            else:
                instr = 0xea000000 | (imm & 0xffffff)
            return NativePatcher.patch_bytes(data, offset, struct.pack('<I', instr))
        
        return data

    @staticmethod
    def patch_arm_conditional_branch(data, offset, target_offset, condition='eq'):
        """写入条件分支指令（ARM模式）"""
        cond_map = {'eq': 0, 'ne': 1, 'hs': 2, 'lo': 3, 'mi': 4, 'pl': 5,
                    'vs': 6, 'vc': 7, 'hi': 8, 'ls': 9, 'ge': 10, 'lt': 11,
                    'gt': 12, 'le': 13, 'al': 14, 'nv': 15}
        cond = cond_map.get(condition, 14)
        
        diff = target_offset - offset - 8
        if diff % 4 != 0:
            return data
        imm = diff // 4
        if imm < -0x800000 or imm > 0x7fffff:
            return data
        
        instr = (cond << 28) | 0x0a000000 | (imm & 0xffffff)
        return NativePatcher.patch_bytes(data, offset, struct.pack('<I', instr))

    @staticmethod
    def insert_breakpoint(data, offset, arch='aarch64'):
        """在指定偏移处插入断点指令"""
        if arch == 'aarch64':
            bkpt = struct.pack('<I', AARCH64_BKPT)
        elif arch == 'arm':
            bkpt = struct.pack('<I', 0xe1200070)  # bkpt #0
        elif arch == 'thumb':
            bkpt = struct.pack('<H', 0xbe00)  # bkpt #0
        elif arch == 'x86_64' or arch == 'x86':
            bkpt = bytes([0xcc])  # int3
        else:
            bkpt = bytes([0xcc])
        return NativePatcher.patch_bytes(data, offset, bkpt)

    @staticmethod
    def patch_arm_ret_with_value(data, offset, value, arch='aarch64'):
        """替换为 mov r0, #value; ret"""
        return NativePatcher.patch_branch_to_mov_r0(data, offset, value, arch)

    @staticmethod
    def find_pattern(data, pattern_hex):
        """搜索十六进制模式"""
        pattern = bytes.fromhex(pattern_hex.replace(' ', ''))
        offsets = []
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets

    @staticmethod
    def find_string_offsets(data, target_str):
        """搜索字符串偏移"""
        target = target_str.encode()
        offsets = []
        start = 0
        while True:
            idx = data.find(target, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets
