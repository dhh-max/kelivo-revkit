"""Lite DEX 解析器 - 纯 Python 标准库
"""

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import struct

class LiteDexParser:
    """极简DEX解析器 - 只提取类名和字符串（带完整边界检查，杜绝越界范围错误）"""
    def __init__(self, data):
        self.data = data
        self.n = len(data)

    def _u4(self, off):
        # 越界安全读取：偏移+4 超出数据长度时返回 0
        if off < 0 or off + 4 > self.n:
            return 0
        return struct.unpack_from('<I', self.data, off)[0]

    def _read_cstr(self, off):
        """从 off 读取一条以 \0 结尾的字符串，越界安全"""
        if off < 0 or off >= self.n:
            return ''
        try:
            end = self.data.index(b'\x00', off)
            if end > self.n:  # 理论上 index 不会超出，防御
                end = self.n
            raw = self.data[off:end]
            if len(raw) > 4096:  # 单条超长字符串截断，防异常
                raw = raw[:4096]
            return raw.decode('utf-8', errors='replace')
        except Exception as e:
            logger.debug("apk_reverse_engine/lite/dex_parser.py:29 suppressed: %s", e)
            return ''

    def parse_strings(self):
        """提取DEX字符串池"""
        if self.n < 112:
            return []
        str_ids_size = self._u4(56)
        str_ids_off = self._u4(60)
        # 防御：字符串ID表大小受数据长度约束，防越界
        max_size = (self.n - str_ids_off) // 4 if str_ids_off > 0 and str_ids_off < self.n else 0
        str_ids_size = min(str_ids_size, max_size, 50000)
        strings = []
        for i in range(str_ids_size):
            off = self._u4(str_ids_off + i * 4)
            strings.append(self._read_cstr(off))
        return strings

    def parse_class_names(self):
        """提取类名"""
        if self.n < 112:
            return []
        str_ids_size = self._u4(56)
        str_ids_off = self._u4(60)
        type_ids_size = self._u4(64)
        type_ids_off = self._u4(68)
        class_defs_size = self._u4(96)
        class_defs_off = self._u4(100)

        # 防御：各表大小受数据长度约束
        str_max = (self.n - str_ids_off) // 4 if 0 < str_ids_off < self.n else 0
        str_ids_size = min(str_ids_size, str_max, 50000)
        type_max = (self.n - type_ids_off) // 4 if 0 < type_ids_off < self.n else 0
        type_ids_size = min(type_ids_size, type_max, 50000)
        cls_max = (self.n - class_defs_off) // 32 if 0 < class_defs_off < self.n else 0
        class_defs_size = min(class_defs_size, cls_max, 100000)

        # 先读字符串
        strings = []
        for i in range(str_ids_size):
            off = self._u4(str_ids_off + i * 4)
            strings.append(self._read_cstr(off))

        # 读类型描述符
        type_desc = []
        for i in range(type_ids_size):
            idx = self._u4(type_ids_off + i * 4)
            desc = strings[idx] if 0 <= idx < len(strings) else f'?{idx}'
            type_desc.append(desc)

        # 读类定义
        names = []
        for i in range(class_defs_size):
            off = class_defs_off + i * 32
            ci = self._u4(off)
            name = type_desc[ci] if 0 <= ci < len(type_desc) else f'?{ci}'
            names.append(name)
        return names
