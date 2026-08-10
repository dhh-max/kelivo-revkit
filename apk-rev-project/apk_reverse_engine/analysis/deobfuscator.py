"""自动化去混淆引擎 - 字符串解密、方法名还原、控制流平坦化检测"""

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import re
import base64
from collections import defaultdict
class Deobfuscator:
    """自动化去混淆引擎"""

    # ── 常见XOR密钥模式 ────────────────────────────────────────
    XOR_PATTERNS = [
        re.compile(r'v\d+\s*\^=\s*(0x[0-9a-fA-F]+|\d+)'),
        re.compile(r'xor\s*[-]?[0-9a-fA-Fx]+'),
        re.compile(r'\^\s*0x[0-9a-fA-F]+'),
    ]

    # ── 常见字符串解密模式 ──────────────────────────────────────
    DECRYPT_PATTERNS = [
        r'new byte\[\]\s*\{([^}]+)\}',
        r'const-string\s+v\d+,\s*"[^"]+"',
        r'const-string/jumbo\s+v\d+,\s*"[^"]+"',
    ]

    @staticmethod
    def find_xor_keys(data):
        """从数据中提取可能的XOR密钥"""
        keys = set()
        for pat in Deobfuscator.XOR_PATTERNS:
            for m in pat.finditer(data):
                val = m.group(1) if m.lastindex else m.group(0)
                try:
                    if '0x' in val:
                        keys.add(int(val, 16))
                    else:
                        keys.add(int(val))
                except Exception as e:
                    logger.debug("apk_reverse_engine/analysis/deobfuscator.py:35 suppressed: %s", e)
                    logger.debug(f"e")
        return sorted(keys)[:20]

    @staticmethod
    def try_xor_decrypt(data, key):
        """尝试XOR解密"""
        result = []
        for byte in data:
            if isinstance(byte, str):
                byte = ord(byte)
            result.append(chr(byte ^ key))
        return ''.join(result)

    @staticmethod
    def extract_byte_arrays(text):
        """提取byte数组定义"""
        arrays = []
        for m in re.finditer(r'new byte\[\]\s*\{([^}]+)\}', text):
            content = m.group(1)
            try:
                bytes_list = [int(b.strip()) for b in content.split(',') if b.strip()]
                if len(bytes_list) >= 4:
                    arrays.append({
                        'raw': content[:100],
                        'length': len(bytes_list),
                        'bytes': bytes_list[:50],
                        'hex': ' '.join(f'{b:02x}' for b in bytes_list[:20]),
                    })
            except Exception as e:
                logger.debug("apk_reverse_engine/analysis/deobfuscator.py:64 suppressed: %s", e)
                logger.debug(f"e")
        return arrays

    @staticmethod
    def try_decrypt_byte_array(byte_array, key=None):
        """尝试解密byte数组"""
        results = []
        
        # 直接尝试XOR
        if key is not None:
            decrypted = Deobfuscator.try_xor_decrypt(byte_array, key)
            if all(0x20 <= ord(c) <= 0x7e or c in '\n\r\t' for c in decrypted[:20]):
                results.append({'method': f'xor_0x{key:02x}', 'result': decrypted[:200]})
        
        # 尝试XOR 0x00-0xFF
        if not results:
            for k in range(256):
                decrypted = Deobfuscator.try_xor_decrypt(byte_array, k)
                if all(0x20 <= ord(c) <= 0x7e or c in '\n\r\t' for c in decrypted[:10]):
                    results.append({'method': f'xor_0x{k:02x}', 'result': decrypted[:200]})
                    if len(results) >= 3:
                        break
        
        return results

    @staticmethod
    def detect_control_flow_flattening(instructions):
        """检测控制流平坦化（OLLVM等）"""
        if not instructions:
            return {'detected': False, 'confidence': 0}
        
        # 特征1: 大量switch/if跳转
        branch_count = sum(1 for i in instructions if i.opcode in {0x2b, 0x2c, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d})
        goto_count = sum(1 for i in instructions if i.opcode in {0x28, 0x29, 0x2a})
        
        # 特征2: 大量const/4加载常量
        const_count = sum(1 for i in instructions if i.opcode in {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19})
        
        total = len(instructions)
        if total == 0:
            return {'detected': False, 'confidence': 0}
        
        branch_ratio = branch_count / total
        goto_ratio = goto_count / total
        const_ratio = const_count / total
        
        score = 0
        if branch_ratio > 0.15:
            score += 3
        if goto_ratio > 0.05:
            score += 2
        if const_ratio > 0.2:
            score += 2
        if branch_count > 20:
            score += 2
        if goto_count > 10:
            score += 1
        
        confidence = min(score / 10, 1.0)
        
        return {
            'detected': confidence > 0.4,
            'confidence': round(confidence, 2),
            'score': score,
            'branch_count': branch_count,
            'goto_count': goto_count,
            'const_count': const_count,
            'branch_ratio': round(branch_ratio, 3),
            'goto_ratio': round(goto_ratio, 3),
        }

    @staticmethod
    def detect_arithmetic_obfuscation(text):
        """检测算术混淆（常量展开、虚假控制流）"""
        indicators = []
        
        # 特征1: 大数值运算后取小值
        large_ops = re.findall(r'(?:add|sub|mul|div|rem|and|or|xor)[-]?\s*\d{5,}', text, re.IGNORECASE)
        if large_ops:
            indicators.append(f'大数值运算({len(large_ops)}个)')
        
        # 特征2: 冗余的if-else
        if_else_pairs = len(re.findall(r'if-', text))
        if if_else_pairs > 20:
            indicators.append(f'大量if分支({if_else_pairs}个)')
        
        # 特征3: 无意义的XOR运算
        xor_ops = re.findall(r'xor[-/]?\s*[a-z]\d+,\s*v\d+', text, re.IGNORECASE)
        if len(xor_ops) > 10:
            indicators.append(f'大量XOR运算({len(xor_ops)}个)')
        
        return {
            'detected': len(indicators) > 0,
            'indicators': indicators,
            'count': len(indicators),
        }

    @staticmethod
    def rename_obfuscated_classes(class_names):
        """为混淆类名生成可读名称"""
        mapping = {}
        counter = defaultdict(int)
        
        for c in class_names:
            simple_name = c.split('/')[-1]
            package = '/'.join(c.split('/')[:-1]) if '/' in c else ''
            
            # 检测是否为混淆名
            is_obfuscated = (
                len(simple_name) <= 3 and not simple_name in ['R', 'Manifest', 'BuildConfig']
            ) or re.match(r'^[a-z]\d+$', simple_name) or re.match(r'^[a-z]{1,2}$', simple_name)
            
            if is_obfuscated:
                counter[package] += 1
                new_name = f'Class{counter[package]:03d}'
                mapping[c] = f'{package}/{new_name}'
        
        return mapping

    @staticmethod
    def deobfuscate_strings(strings):
        """尝试对混淆字符串进行还原"""
        results = []
        
        for s in strings:
            if len(s) < 4:
                continue
            
            # 尝试Base64解码
            try:
                decoded = base64.b64decode(s).decode('utf-8', errors='replace')
                if decoded and len(decoded) > 3:
                    results.append({
                        'original': s[:50],
                        'decoded': decoded[:100],
                        'method': 'base64',
                    })
            except Exception as e:
                logger.debug("apk_reverse_engine/analysis/deobfuscator.py:202 suppressed: %s", e)
                logger.debug(f"e")
            
            # 尝试Hex解码
            if all(c in '0123456789abcdefABCDEF' for c in s) and len(s) % 2 == 0:
                try:
                    decoded = bytes.fromhex(s).decode('utf-8', errors='replace')
                    if decoded and len(decoded) > 3:
                        results.append({
                            'original': s[:50],
                            'decoded': decoded[:100],
                            'method': 'hex',
                        })
                except Exception as e:
                    logger.debug("apk_reverse_engine/analysis/deobfuscator.py:215 suppressed: %s", e)
                    logger.debug(f"e")
            
            # 尝试Unicode转义
            unicode_match = re.match(r'^\\u[0-9a-fA-F]{4}', s)
            if unicode_match:
                try:
                    decoded = s.encode('utf-8').decode('unicode_escape', errors='replace')
                    results.append({
                        'original': s[:50],
                        'decoded': decoded[:100],
                        'method': 'unicode_escape',
                    })
                except Exception as e:
                    logger.debug("apk_reverse_engine/analysis/deobfuscator.py:228 suppressed: %s", e)
                    logger.debug(f"e")
        
        return results[:20]

    @staticmethod
    def analyze_full(text, class_names=None, instructions=None):
        """一站式去混淆分析"""
        result = {
            'xor_keys': Deobfuscator.find_xor_keys(text),
            'byte_arrays': Deobfuscator.extract_byte_arrays(text),
            'arithmetic_obfuscation': Deobfuscator.detect_arithmetic_obfuscation(text),
        }
        
        if class_names:
            result['class_rename'] = Deobfuscator.rename_obfuscated_classes(class_names)
            result['obfuscated_class_count'] = len(result['class_rename'])
        
        if instructions:
            result['control_flow_flattening'] = Deobfuscator.detect_control_flow_flattening(instructions)
        
        return result


# ── 快捷函数 ──────────────────────────────────────────────────
def deobfuscate_analyze(text, class_names=None, instructions=None):
    """一站式去混淆分析"""
    return Deobfuscator.analyze_full(text, class_names, instructions)
