"""AndroidManifest.xml 二进制操作基础工具 - 直接在 AXML 层面操作

不依赖解包/文本XML转换，直接解析/修改二进制 AXML 中的节点与属性。
"""
import struct, re


# ═══════════════════════════════════════════════════════════════
# 常量
# ═══════════════════════════════════════════════════════════════
AXML_MAGIC = 0x00080003
CHUNK_STRING_POOL = 0x001C0001
CHUNK_START_TAG = 0x00100102
CHUNK_END_TAG = 0x00100103
CHUNK_RESOURCEID = 0x00080180

ATTR_HEADER_SIZE = 20  # 每个属性 20 字节


# ═══════════════════════════════════════════════════════════════
# 基础解析 - 提取标签树结构
# ═══════════════════════════════════════════════════════════════
class _AXMLNode:
    """AXML 标签节点"""
    __slots__ = ('type', 'name', 'attrs', 'start_offset', 'end_offset',
                 'header_size', 'chunk_size', 'attr_start')

    def __init__(self, type_, name, attrs=None):
        self.type = type_  # 'start' | 'end'
        self.name = name
        self.attrs = attrs or []
        # 块偏移信息（用于原地修改）
        self.start_offset = 0
        self.end_offset = 0
        self.header_size = 0
        self.chunk_size = 0
        self.attr_start = 0


def _parse_axml_tags(data, offsets=False):
    """解析 AXML 二进制数据，返回标签列表

    Args:
        data: AXML 二进制数据
        offsets: True 时返回每个标签的字节偏移信息

    Returns:
        dict: {'tags': [...], 'strings': [...], 'is_utf8': bool}
    """
    pos = 0
    n = len(data)

    def r32():
        nonlocal pos
        v = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        return v

    def r16():
        nonlocal pos
        v = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        return v

    magic = r32()
    if magic != AXML_MAGIC:
        return {'error': f'Invalid AXML magic: 0x{magic:08x}'}
    _ = r32()  # file_size

    # ── 解析字符串池 ──
    pool_start = pos
    pool_chunk_type = r32()
    pool_chunk_size = r32()
    string_count = r32()
    style_count = r32()
    flags = r32()
    is_utf8 = bool(flags & 0x100)
    strings_offset = r32()  # 相对 pool_start 的偏移
    _ = r32()  # styles_offset

    # 读字符串偏移表
    str_offsets = [r32() for _ in range(string_count)]
    # 跳过样式偏移表
    for _ in range(style_count):
        r32()

    strings_data_start = pool_start + strings_offset
    strings = []

    def read_str(off):
        if off < 0 or off >= n:
            return ''
        try:
            if is_utf8:
                if data[off] & 0x80:
                    cc = ((data[off] & 0x7f) << 8) | data[off + 1]
                    off += 2
                else:
                    cc = data[off]
                    off += 1
                if data[off] & 0x80:
                    bc = ((data[off] & 0x7f) << 8) | data[off + 1]
                    off += 2
                else:
                    bc = data[off]
                    off += 1
                if bc == 0:
                    return ''
                raw = data[off:off + bc]
                return raw.decode('utf-8', errors='replace')
            else:
                char_count = struct.unpack_from('<H', data, off)[0]
                off += 2
                if char_count == 0:
                    return ''
                raw = data[off:off + char_count * 2]
                return raw.decode('utf-16-le', errors='replace')
        except Exception:
            return ''

    for o in str_offsets:
        strings.append(read_str(strings_data_start + o))

    # 跳转到 pool 末尾
    pos = pool_start + pool_chunk_size

    # ── 跳过资源ID块 ──
    while pos + 8 <= n:
        ct = r16()
        hs = r16()
        cs = r32()
        if ct == 0x0180:
            pos += cs - 8
        else:
            pos -= 8
            break

    # ── 解析标签树 ──
    tags = []
    xmlns = []
    while pos + 8 <= n:
        ct = r16()
        hs = r16()
        cs = r32()
        chunk_start = pos - 8

        if ct == 0x0100:  # START_NAMESPACE
            r32()  # line
            r32()  # comment
            pi = r32()
            ui = r32()
            prefix = strings[pi] if 0 <= pi < len(strings) else ''
            uri = strings[ui] if 0 <= ui < len(strings) else ''
            xmlns.append((prefix, uri))

        elif ct == 0x0102:  # START_TAG
            r32()  # line
            r32()  # comment
            ns_idx = r32()
            name_idx = r32()
            attr_start = r16()
            attr_size = r16()
            attr_count = r16()
            r16()  # idIndex
            r16()  # classIndex
            r16()  # styleIndex

            name = strings[name_idx] if 0 <= name_idx < len(strings) else f'?{name_idx}'
            attrs = []
            # 跳转到属性区
            attr_pos = chunk_start + hs + attr_start
            for _ in range(attr_count):
                ani = struct.unpack_from('<I', data, attr_pos + 4)[0]     # name index
                vsi = struct.unpack_from('<I', data, attr_pos + 8)[0]     # raw value index
                vt = struct.unpack_from('<I', data, attr_pos + 12)[0]     # value type
                vd = struct.unpack_from('<I', data, attr_pos + 16)[0]     # value data
                an = strings[ani] if 0 <= ani < len(strings) else f'?{ani}'
                if vt >> 24 == 3:  # TYPE_STRING
                    val = strings[vsi] if 0 <= vsi < len(strings) else f'?{vsi}'
                else:
                    val = str(vd)
                attrs.append({'name': an, 'value': val, 'name_index': ani})
                attr_pos += 20

            node = _AXMLNode('start', name, attrs)
            if offsets:
                node.start_offset = chunk_start
                node.end_offset = chunk_start + cs
                node.header_size = hs
                node.chunk_size = cs
                node.attr_start = attr_start
            tags.append(node)

        elif ct == 0x0103:  # END_TAG
            r32()  # line
            r32()  # comment
            ns_idx = r32()
            name_idx = r32()
            name = strings[name_idx] if 0 <= name_idx < len(strings) else f'?{name_idx}'
            node = _AXMLNode('end', name)
            if offsets:
                node.start_offset = chunk_start
                node.end_offset = chunk_start + cs
                node.header_size = hs
                node.chunk_size = cs
            tags.append(node)

        pos = chunk_start + cs

    return {'tags': tags, 'strings': strings, 'is_utf8': is_utf8, 'xmlns': xmlns}


# ═══════════════════════════════════════════════════════════════
# 查找标签
# ═══════════════════════════════════════════════════════════════
def find_tags(axml_data, tag_name=None, attr_name=None, attr_value=None):
    """在 AXML 二进制数据中查找匹配的标签

    Args:
        axml_data: AXML 二进制数据
        tag_name: 标签名过滤（如 'activity'）
        attr_name: 属性名过滤（如 'name'，不含命名空间前缀）
        attr_value: 属性值过滤

    Returns:
        list[dict]: 匹配的标签信息列表
    """
    result = _parse_axml_tags(axml_data, offsets=True)
    if 'error' in result:
        return result
    tags = result['tags']
    matched = []
    for t in tags:
        if t.type != 'start':
            continue
        if tag_name and t.name != tag_name:
            continue
        if attr_name:
            found = False
            for a in t.attrs:
                if a['name'] == attr_name:
                    if attr_value is None or a['value'] == attr_value:
                        found = True
                    break
            if not found:
                continue
        matched.append({
            'name': t.name,
            'attrs': t.attrs,
            'offset': t.start_offset,
            'size': t.chunk_size,
        })
    return matched


# ═══════════════════════════════════════════════════════════════
# 删除标签
# ═══════════════════════════════════════════════════════════════
def remove_tags(axml_data, tag_name, attr_name, attr_value):
    """从 AXML 二进制数据中删除匹配的标签（及其子标签、对应的 END_TAG）

    直接在二进制层面删除 chunk 数据，不经过文本转换。

    Args:
        axml_data: AXML 二进制数据
        tag_name: 要删除的标签名（如 'activity'）
        attr_name: 匹配属性名（如 'name'）
        attr_value: 匹配属性值（如 'com.tencent.tauth.AuthActivity'）

    Returns:
        bytes: 删除后的 AXML 数据
    """
    result = _parse_axml_tags(axml_data, offsets=True)
    if 'error' in result:
        return axml_data  # 解析失败，返回原数据

    tags = result['tags']

    # 找到所有匹配的 START_TAG 并计算要删除的区间
    start_indices = []
    for i, t in enumerate(tags):
        if t.type != 'start':
            continue
        if t.name != tag_name:
            continue
        for a in t.attrs:
            if a['name'] == attr_name and a['value'] == attr_value:
                start_indices.append(i)
                break

    if not start_indices:
        return axml_data  # 没有匹配

    # 计算每个匹配标签的删除区间（包含其所有子标签）
    removes = []  # [(start_offset, end_offset), ...]
    for idx in start_indices:
        t = tags[idx]
        start = t.start_offset
        # 找到对应的 END_TAG（嵌套计算）
        depth = 0
        end = start + t.chunk_size  # 默认
        for j in range(idx, len(tags)):
            if tags[j].type == 'start':
                depth += 1
            elif tags[j].type == 'end':
                depth -= 1
                if depth == 0:
                    end = tags[j].end_offset
                    break
        removes.append((start, end))

    # 按偏移从大到小排序，从后往前删（避免偏移变化）
    removes.sort(key=lambda x: -x[0])
    data = bytearray(axml_data)
    for start, end in removes:
        del data[start:end]

    # 更新文件大小头部
    new_size = len(data)
    struct.pack_into('<I', data, 4, new_size)

    return bytes(data)


def remove_tags_by_rule(axml_data, rules):
    """批量删除标签

    Args:
        axml_data: AXML 二进制数据
        rules: 规则列表，每个元素为 [tag_name, attr_name, attr_value]

    Returns:
        bytes: 删除后的 AXML 数据
    """
    data = axml_data
    for tag_name, attr_name, attr_value in rules:
        data = remove_tags(data, tag_name, attr_name, attr_value)
    return data


# ═══════════════════════════════════════════════════════════════
# 替换属性值
# ═══════════════════════════════════════════════════════════════
def replace_attr_value(axml_data, tag_name, attr_name, old_value, new_value):
    """在 AXML 二进制数据中替换指定标签的属性值

    仅在字符串池中修改对应字符串，不改变标签结构。

    Args:
        axml_data: AXML 二进制数据
        tag_name: 标签名过滤
        attr_name: 属性名
        old_value: 旧值
        new_value: 新值

    Returns:
        bytes: 修改后的 AXML 数据
    """
    result = _parse_axml_tags(axml_data, offsets=True)
    if 'error' in result:
        return axml_data

    tags = result['tags']
    strings = result['strings']
    is_utf8 = result['is_utf8']

    # 找到所有匹配的标签及其属性值索引
    replacements = []  # [(string_index, old_value, new_value), ...]
    for t in tags:
        if t.type != 'start':
            continue
        if tag_name and t.name != tag_name:
            continue
        for a in t.attrs:
            if a['name'] == attr_name and a['value'] == old_value:
                replacements.append((a['name_index'], old_value, new_value))

    if not replacements:
        return axml_data

    # 字符串池中替换字符串
    data = bytearray(axml_data)

    # 解析字符串池结构找到对应字符串的位置
    pos = 8  # 跳过 magic + file_size
    pool_start = pos
    # 确认是字符串池块
    if struct.unpack_from('<I', data, pos)[0] != CHUNK_STRING_POOL:
        return axml_data

    pool_chunk_type = struct.unpack_from('<I', data, pos)[0]
    pool_chunk_size = struct.unpack_from('<I', data, pos + 4)[0]
    string_count = struct.unpack_from('<I', data, pos + 8)[0]
    style_count = struct.unpack_from('<I', data, pos + 12)[0]
    flags = struct.unpack_from('<I', data, pos + 16)[0]
    is_utf8 = bool(flags & 0x100)
    strings_offset = struct.unpack_from('<I', data, pos + 20)[0]
    # styles_offset = struct.unpack_from('<I', data, pos + 24)[0]

    str_offsets_table_offset = pos + 28
    strings_data_start = pool_start + strings_offset

    # 读取字符串偏移表
    str_offsets = []
    for i in range(string_count):
        off = struct.unpack_from('<I', data, str_offsets_table_offset + i * 4)[0]
        str_offsets.append(off)

    # 对每个要替换的字符串，计算其在池中的实际位置
    for str_idx, old_val, new_val in replacements:
        if str_idx < 0 or str_idx >= len(str_offsets):
            continue
        if old_val not in strings:
            # 如果实际字符串不同，跳过
            continue

        str_data_off = strings_data_start + str_offsets[str_idx]
        if is_utf8:
            # 跳过字符数和字节数头
            if data[str_data_off] & 0x80:
                off = str_data_off + 2
            else:
                off = str_data_off + 1
            if data[off] & 0x80:
                off += 2
            else:
                off += 1
            # 在数据区替换
            new_encoded = new_val.encode('utf-8')
            old_encoded = old_val.encode('utf-8')
            if len(new_encoded) <= len(old_encoded):
                data[off:off + len(old_encoded)] = new_encoded.ljust(len(old_encoded), b'\x00')
            else:
                # 新值更长，无法原地替换，跳过
                pass
        else:
            # UTF-16LE: 跳过2字节字符数
            off = str_data_off + 2
            new_encoded = new_val.encode('utf-16-le')
            old_encoded = old_val.encode('utf-16-le')
            if len(new_encoded) <= len(old_encoded):
                data[off:off + len(old_encoded)] = new_encoded.ljust(len(old_encoded), b'\x00')
            else:
                # 新值更长，无法原地替换，跳过
                pass

    return bytes(data)


# ═══════════════════════════════════════════════════════════════
# 获取标签属性值
# ═══════════════════════════════════════════════════════════════
def get_attr_value(axml_data, tag_name, attr_name):
    """获取第一个匹配标签的属性值

    Args:
        axml_data: AXML 二进制数据
        tag_name: 标签名
        attr_name: 属性名

    Returns:
        str or None: 属性值，未找到则返回 None
    """
    tags = find_tags(axml_data, tag_name, attr_name)
    if isinstance(tags, dict) and 'error' in tags:
        return None
    if tags:
        for a in tags[0]['attrs']:
            if a['name'] == attr_name:
                return a['value']
    return None


def get_all_attr_values(axml_data, tag_name, attr_name):
    """获取所有匹配标签的属性值列表"""
    tags = find_tags(axml_data, tag_name, attr_name)
    if isinstance(tags, dict) and 'error' in tags:
        return []
    values = []
    for t in tags:
        for a in t['attrs']:
            if a['name'] == attr_name:
                values.append(a['value'])
    return values


# ═══════════════════════════════════════════════════════════════
# 一站式操作
# ═══════════════════════════════════════════════════════════════
def remove_component(axml_data, component_type, class_name):
    """从 AXML 中删除指定组件声明

    Args:
        axml_data: AXML 二进制数据
        component_type: 组件类型（'activity', 'service', 'receiver', 'provider', 'meta-data'）
        class_name: 组件类名或 meta-data 的 name 值

    Returns:
        bytes: 修改后的 AXML 数据
    """
    return remove_tags(axml_data, component_type, 'name', class_name)


def replace_launcher_activity(axml_data, old_class, new_class):
    """替换启动 Activity 类名

    Args:
        axml_data: AXML 二进制数据
        old_class: 旧类名（如 'com.tencent.a.SetupInfoActivity'）
        new_class: 新类名

    Returns:
        bytes: 修改后的 AXML 数据
    """
    return replace_attr_value(axml_data, 'activity', 'name', old_class, new_class)