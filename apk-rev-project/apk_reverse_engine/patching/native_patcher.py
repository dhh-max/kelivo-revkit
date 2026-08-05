import struct

class NativePatcher:
    """原生SO文件补丁工具"""

    @staticmethod
    def patch_hex(data, old_hex, new_hex):
        old = bytes.fromhex(old_hex.replace(' ', ''))
        new = bytes.fromhex(new_hex.replace(' ', ''))
        return data.replace(old, new)

    @staticmethod
    def patch_string(data, old_str, new_str, max_replace=1):
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
    def nop_out(data, offset, count=4):
        """用NOP指令填充指定区域 (AArch64 NOP = 0xd503201f, ARM NOP = 0xe1a00000, x86 NOP = 0x90)"""
        if count <= 0:
            return data
        # Try AArch64 NOP first
        nop_bytes = struct.pack('<I', 0xd503201f)
        return data[:offset] + nop_bytes * count + data[offset + count * 4:]

    @staticmethod
    def patch_branch_to_ret(data, offset, arch='aarch64'):
        """将分支指令替换为返回指令"""
        if arch == 'aarch64':
            # AArch64 RET = 0xd65f03c0
            ret_bytes = struct.pack('<I', 0xd65f03c0)
        elif arch == 'arm':
            # ARM BX LR = 0xe12fff1e
            ret_bytes = struct.pack('<I', 0xe12fff1e)
        elif arch == 'x86_64':
            # x86_64 ret = 0xc3
            ret_bytes = b'\xc3'
        else:
            ret_bytes = b'\xc3'  # x86 ret
        return NativePatcher.patch_bytes(data, offset, ret_bytes)

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
        # 在ARM64中，BL指令是0x94000000格式
        # 这需要更复杂的重定位分析，简单实现只做字符串替换
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
