"""AXML 二进制XML 反编译/编译工具 - 纯Python实现

功能:
  - decode:  将 AndroidBinaryXML 解码为可读文本 XML (纯Python)
  - encode:  将文本 XML 编译回 AndroidBinaryXML (纯Python，无需 aapt2)

用法:
  reng axml decode input.axml [output.xml]
  reng axml encode input.xml output.axml
  reng axml decode-apk app.apk [output.xml]     # 从APK中提取并解码Manifest
  reng axml encode-apk app.apk output.apk input.xml  # 替换APK中的Manifest
"""

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import os, struct, re, zipfile, copy
from xml.etree.ElementTree import ElementTree, Element, SubElement, tostring, fromstring
from xml.parsers.expat import ExpatError
from xml.sax.saxutils import escape as xml_escape, unescape as xml_unescape
# ============================================================
# AXML 常量
# ============================================================
AXML_MAGIC = 0x00080003
CHUNK_STRING_POOL = 0x0001      # type=0x0001, header_size=28(0x001C)
CHUNK_START_TAG = 0x0102        # type=0x0102, header_size=36(0x0024)
CHUNK_END_TAG = 0x0103          # type=0x0103, header_size=24(0x0018)

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INTEGER = 0x10
TYPE_BOOLEAN = 0x12

ANDROID_NS_URI = "http://schemas.android.com/apk/res/android"

# ============================================================
# 字符串池编码器
# ============================================================
class StringPool:
    """Android Binary XML 字符串池构建器 (UTF-16LE)"""

    def __init__(self):
        self.strings = []
        self.index_map = {}

    def add(self, s):
        if s is None:
            s = ""
        if s not in self.index_map:
            self.index_map[s] = len(self.strings)
            self.strings.append(s)
        return self.index_map[s]

    def get_index(self, s):
        if s is None:
            s = ""
        return self.index_map.get(s, 0)

    def serialize(self):
        data = bytearray()
        count = len(self.strings)

        # 计算每个字符串的 UTF-16LE 编码
        string_bytes_list = []
        for s in self.strings:
            encoded = s.encode('utf-16-le')
            char_count = len(encoded) // 2
            entry_size = 2 + len(encoded) + 2  # charCount + data + null
            string_bytes_list.append((char_count, encoded, entry_size))

        offsets_size = count * 4
        styles_offsets_size = 0

        # 构建字符串数据
        strings_data = bytearray()
        offsets = []
        current_offset = 0
        for char_count, encoded, entry_size in string_bytes_list:
            offsets.append(current_offset)
            strings_data.extend(struct.pack('<H', char_count))
            strings_data.extend(encoded)
            strings_data.extend(b'\x00\x00')
            current_offset += entry_size

        # 4字节对齐
        padding = (4 - (len(strings_data) % 4)) % 4
        strings_data.extend(b'\x00' * padding)

        chunk_size = 28 + offsets_size + styles_offsets_size + len(strings_data)

        data.extend(struct.pack('<H', CHUNK_STRING_POOL))
        data.extend(struct.pack('<H', 28))
        data.extend(struct.pack('<I', chunk_size))
        data.extend(struct.pack('<I', count))
        data.extend(struct.pack('<I', 0))
        data.extend(struct.pack('<I', 0x000))
        data.extend(struct.pack('<I', 28 + offsets_size + styles_offsets_size))
        data.extend(struct.pack('<I', 0))

        for off in offsets:
            data.extend(struct.pack('<I', off))

        data.extend(strings_data)
        return bytes(data)


# ============================================================
# AXML 编码器 (纯Python)
# ============================================================
class AXMLEncoder:
    """将文本 XML 编译为 Android Binary XML"""

    @staticmethod
    def _parse_xml(xml_text):
        """解析文本XML为元素树"""
        xml_text = re.sub(r'<\?xml[^>]*\?>', '', xml_text).strip()
        try:
            root = fromstring(xml_text)
        except ExpatError as e:
            xml_text = xml_text.replace('&', '&amp;')
            xml_text = xml_text.replace('android:&amp;', 'android:')
            try:
                root = fromstring(xml_text)
            except ExpatError as e2:
                raise ValueError(f"XML解析失败: {e2}")
        return root

    @staticmethod
    def _is_android_attr(attr_name):
        """判断是否为android命名空间属性（支持ET命名空间格式和android:格式）"""
        return (attr_name.startswith('android:') or
                attr_name.startswith('{http://schemas.android.com/apk/res/android}'))

    @staticmethod
    def _get_attr_name(attr_name):
        """提取属性名（去除命名空间前缀）"""
        if ':' in attr_name and not attr_name.startswith('{'):
            return attr_name.split(':', 1)[1]
        if attr_name.startswith('{') and '}' in attr_name:
            return attr_name.split('}', 1)[1]
        return attr_name

    @staticmethod
    def _encode_attr_value(attr_name, value, string_pool):
        """编码属性值，返回 (raw_value_index, value_type, value_data)"""
        # 布尔值
        if value.lower() in ('true', 'false'):
            vi = string_pool.add(value)
            vt = (TYPE_STRING << 24) | 0x08
            vd = 0xFFFFFFFF if value.lower() == 'true' else 0x00000000
            return vi, vt, vd

        # 纯数字
        if value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
            vi = string_pool.add(value)
            vt = (TYPE_INTEGER << 24) | 0x08
            vd = int(value) & 0xFFFFFFFF
            return vi, vt, vd

        # 十六进制
        if value.startswith('0x') or value.startswith('0X'):
            try:
                v = int(value, 16)
                vi = string_pool.add(value)
                vt = (TYPE_INTEGER << 24) | 0x08
                vd = v & 0xFFFFFFFF
                return vi, vt, vd
            except ValueError as e:
                logger.debug(f"e")

        # 引用
        if value.startswith('@'):
            vi = string_pool.add(value)
            vt = (TYPE_REFERENCE << 24) | 0x08
            try:
                vd = int(value[1:], 16) if value[1:].startswith('0x') else 0
            except Exception:
                vd = 0
            return vi, vt, vd

        # 默认字符串
        vi = string_pool.add(value)
        vt = (TYPE_STRING << 24) | 0x08
        vd = vi
        return vi, vt, vd

    @staticmethod
    def encode(xml_text):
        """将文本XML编译为二进制AXML数据"""
        root = AXMLEncoder._parse_xml(xml_text)
        string_pool = StringPool()

        # 预留索引0
        string_pool.add("")

        # 收集所有需要加入字符串池的字符串
        elem_names = []
        attr_names = set()
        attr_values = set()

        def collect(elem):
            elem_names.append(elem.tag)
            for attr_name, attr_val in elem.attrib.items():
                clean_name = AXMLEncoder._get_attr_name(attr_name)
                attr_names.add(clean_name)
                attr_values.add(attr_val)
            for child in elem:
                collect(child)

        collect(root)

        # 添加android命名空间相关字符串
        string_pool.add(ANDROID_NS_URI)
        string_pool.add("android")

        for name in elem_names:
            string_pool.add(name)
        for name in sorted(attr_names):
            string_pool.add(name)
        for val in sorted(attr_values):
            string_pool.add(val)

        pool_data = string_pool.serialize()

        # 构建XML树
        tree_data = bytearray()

        def encode_element(elem):
            tag = elem.tag
            attrs = list(elem.attrib.items())
            children = list(elem)

            tag_name_idx = string_pool.get_index(tag)
            attr_count = len(attrs)
            attr_data_size = attr_count * 20

            # START_TAG
            # 结构: chunk_header(8) + ResXMLTree_node(8) + ResXMLTree_attrExt(20) + attr_data
            start_tag_size = 8 + 8 + 20 + attr_data_size
            tree_data.extend(struct.pack('<H', CHUNK_START_TAG))
            tree_data.extend(struct.pack('<H', 16))  # hs = chunk_header(8) + node(8)
            tree_data.extend(struct.pack('<I', start_tag_size))
            tree_data.extend(struct.pack('<I', 0))       # lineNumber
            tree_data.extend(struct.pack('<I', 0xFFFFFFFF))  # commentIndex
            tree_data.extend(struct.pack('<I', 0xFFFFFFFF))  # ns
            tree_data.extend(struct.pack('<I', tag_name_idx))
            tree_data.extend(struct.pack('<H', 20))     # attrStart (从ResXMLTree_attrExt起始的偏移)
            tree_data.extend(struct.pack('<H', 20))     # attrSize
            tree_data.extend(struct.pack('<H', attr_count))
            tree_data.extend(struct.pack('<H', 0))      # idIndex
            tree_data.extend(struct.pack('<H', 0))      # classIndex
            tree_data.extend(struct.pack('<H', 0))      # styleIndex

            for attr_name, attr_val in attrs:
                clean_name = AXMLEncoder._get_attr_name(attr_name)
                ns_idx = 0xFFFFFFFF
                if AXMLEncoder._is_android_attr(attr_name):
                    ns_idx = string_pool.get_index(ANDROID_NS_URI)
                name_idx = string_pool.get_index(clean_name)
                raw_val_idx, val_type, val_data = AXMLEncoder._encode_attr_value(
                    attr_name, attr_val, string_pool
                )
                tree_data.extend(struct.pack('<I', ns_idx))
                tree_data.extend(struct.pack('<I', name_idx))
                tree_data.extend(struct.pack('<I', raw_val_idx))
                tree_data.extend(struct.pack('<I', val_type))
                tree_data.extend(struct.pack('<I', val_data))

            for child in children:
                encode_element(child)

            # END_TAG
            # 结构: chunk_header(8) + ResXMLTree_node(8) + ResXMLTree_endElement(8) = 24
            end_tag_size = 8 + 8 + 8
            tree_data.extend(struct.pack('<H', CHUNK_END_TAG))
            tree_data.extend(struct.pack('<H', 16))  # hs = chunk_header(8) + node(8)
            tree_data.extend(struct.pack('<I', end_tag_size))
            tree_data.extend(struct.pack('<I', 0))       # lineNumber
            tree_data.extend(struct.pack('<I', 0xFFFFFFFF))  # commentIndex
            tree_data.extend(struct.pack('<I', 0xFFFFFFFF))  # ns
            tree_data.extend(struct.pack('<I', tag_name_idx))

        encode_element(root)

        # 组合最终AXML
        result = bytearray()
        total_size = 8 + len(pool_data) + len(tree_data)
        result.extend(struct.pack('<I', AXML_MAGIC))
        result.extend(struct.pack('<I', total_size))
        result.extend(pool_data)
        result.extend(tree_data)

        return bytes(result)

    @staticmethod
    def encode_file(xml_path, output_path):
        with open(xml_path, 'r', encoding='utf-8') as f:
            xml_text = f.read()
        try:
            axml_data = AXMLEncoder.encode(xml_text)
        except Exception as e:
            return {'error': f'编码失败: {e}'}
        with open(output_path, 'wb') as f:
            f.write(axml_data)
        return {'success': True, 'output': output_path, 'size': len(axml_data)}


# ============================================================
# AXML 解码器 (纯Python)
# ============================================================
class AXMLDecoder:
    """将 Android Binary XML 解码为可读文本 XML"""

    @staticmethod
    def decode(axml_data):
        from apk_reverse_engine.utils.axml_parser import AXMLParser
        parser = AXMLParser(axml_data)
        result = parser.parse()
        if 'error' in result:
            return {'error': result['error']}

        tags = result.get('tags', [])
        xmlns = result.get('xmlns', [])

        # 检查是否有 android 命名空间
        has_android_ns = False
        ns_lines = []
        for prefix, uri in xmlns:
            if 'schemas.android.com/apk/res/android' in uri:
                has_android_ns = True
            ns_lines.append(f'xmlns:{prefix}="{uri}"')

        # 如果没有 xmlns 定义但属性中有 android: 前缀，手动添加
        if not has_android_ns:
            # 检查是否有任何属性使用了 android 命名空间
            for tag in tags:
                if tag['type'] == 'start':
                    for attr in tag.get('attrs', []):
                        an_ns = attr.get('ns')
                        if an_ns and 'schemas.android.com/apk/res/android' in an_ns:
                            has_android_ns = True
                            ns_lines.insert(0, 'xmlns:android="http://schemas.android.com/apk/res/android"')
                            break
                if has_android_ns:
                    break

        lines = ['<?xml version="1.0" encoding="utf-8"?>']

        indent = 0
        i = 0
        first_tag = True
        while i < len(tags):
            tag = tags[i]
            if tag['type'] == 'start':
                name = tag['name']
                attrs = tag.get('attrs', [])

                is_self_closing = False
                if i + 1 < len(tags) and tags[i + 1]['type'] == 'end' and tags[i + 1]['name'] == name:
                    is_self_closing = True

                indent_str = '  ' * indent
                attr_strs = []
                for attr in attrs:
                    an = attr['name']
                    val = attr['value']
                    an_ns = attr.get('ns')
                    # 如果属性有android命名空间，加android:前缀
                    if an_ns and 'schemas.android.com/apk/res/android' in an_ns:
                        an = f'android:{an}'
                    val_escaped = xml_escape(val)
                    attr_strs.append(f'{an}="{val_escaped}"')

                # 在第一个标签中插入 xmlns 声明
                ns_part = ''
                if first_tag and ns_lines:
                    ns_part = ' ' + ' '.join(ns_lines)
                    first_tag = False

                if is_self_closing:
                    attr_part = ' '.join(attr_strs)
                    if attr_part:
                        lines.append(f'{indent_str}<{name}{ns_part} {attr_part} />')
                    else:
                        lines.append(f'{indent_str}<{name}{ns_part} />')
                    i += 2
                    continue
                else:
                    attr_part = ' '.join(attr_strs)
                    if attr_part:
                        lines.append(f'{indent_str}<{name}{ns_part} {attr_part}>')
                    else:
                        lines.append(f'{indent_str}<{name}{ns_part}>')
                    indent += 1
                    i += 1
            elif tag['type'] == 'end':
                indent -= 1
                indent_str = '  ' * indent
                lines.append(f'{indent_str}</{tag["name"]}>')
                i += 1
            else:
                i += 1

        return '\n'.join(lines)

    @staticmethod
    def decode_file(axml_path, output_path=None):
        with open(axml_path, 'rb') as f:
            axml_data = f.read()
        result = AXMLDecoder.decode(axml_data)
        if isinstance(result, dict) and 'error' in result:
            return result
        if output_path is None:
            output_path = axml_path + '.xml'
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
        return {'success': True, 'output': output_path, 'size': len(result)}


# ============================================================
# 统一接口
# ============================================================
class AXMLConverter:
    """AXML 二进制<->文本XML转换器 (统一接口)"""

    @staticmethod
    def decode(axml_data):
        return AXMLDecoder.decode(axml_data)

    @staticmethod
    def decode_file(axml_path, output_path=None):
        return AXMLDecoder.decode_file(axml_path, output_path)

    @staticmethod
    def decode_apk_manifest(apk_path, output_path=None):
        if output_path is None:
            output_path = apk_path + '.xml'
        with zipfile.ZipFile(apk_path, 'r') as zf:
            try:
                axml_data = zf.read('AndroidManifest.xml')
            except KeyError:
                return {'error': 'APK中未找到AndroidManifest.xml'}
        result = AXMLDecoder.decode(axml_data)
        if isinstance(result, dict) and 'error' in result:
            return result
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
        return {'success': True, 'output': output_path, 'size': len(result), 'xml': result}

    @staticmethod
    def encode(xml_text):
        return AXMLEncoder.encode(xml_text)

    @staticmethod
    def encode_file(xml_path, output_path):
        return AXMLEncoder.encode_file(xml_path, output_path)

    @staticmethod
    def encode_apk_manifest(apk_path, output_apk, xml_text):
        try:
            axml_data = AXMLEncoder.encode(xml_text)
        except Exception as e:
            return {'error': f'XML编码失败: {e}'}
        try:
            with zipfile.ZipFile(apk_path, 'r') as zin:
                with zipfile.ZipFile(output_apk, 'w', zipfile.ZIP_DEFLATED) as zout:
                    for info in zin.infolist():
                        if info.filename == 'AndroidManifest.xml':
                            data = axml_data
                        else:
                            data = zin.read(info.filename)
                        zout.writestr(info, data)
            return {'success': True, 'output': output_apk, 'note': 'Manifest已替换，请重新签名后安装'}
        except Exception as e:
            return {'error': f'替换Manifest失败: {e}'}