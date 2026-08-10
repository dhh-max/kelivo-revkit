"""字符串解密器 - 多模式自动解密 DEX/smali 中的加密字符串"""

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import re
import base64
import struct
class StringDecryptor:
    """多策略字符串自动解密引擎"""

    # 常见解密方法特征
    DECRYPT_METHOD_PATTERNS = [
        r'decrypt(?:String|Str)?\s*\(',
        r'deobf(?:uscate)?(?:String|Str)?\s*\(',
        r'unhide(?:String|Str)?\s*\(',
        r'reveal(?:String|Str)?\s*\(',
        r'decode(?:String|Str)?\s*\(',
        r'getString\s*\(',
        r'\bXOR\s*\(',
        r'a\s*\(',  # 常见单字母混淆方法
        r'o\d*\s*\(',  # o0, o1, etc.
    ]

    @staticmethod
    def xor_decrypt(data, key):
        """XOR解密"""
        if isinstance(data, str):
            data = data.encode('latin-1')
        if isinstance(key, str):
            key = key.encode('latin-1')
        if not key:
            return None
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    @staticmethod
    def auto_decrypt_bytes(byte_array):
        """自动尝试多种解密方式"""
        results = []

        # 1. XOR brute force (单字节)
        for key in range(256):
            decrypted = StringDecryptor.xor_decrypt(byte_array, key)
            if decrypted and StringDecryptor._is_printable(decrypted):
                text = decrypted.decode('utf-8', errors='replace')
                if len(text) >= 3:
                    results.append({
                        'method': f'xor_single_0x{key:02x}',
                        'result': text[:200],
                        'confidence': StringDecryptor._confidence_score(text),
                    })

        # 2. XOR multi-byte keys (2-4 bytes)
        for key_len in [2, 3, 4]:
            for key_start in range(256 ** min(key_len, 2)):
                if key_len == 2:
                    key = bytes([key_start & 0xff, (key_start >> 8) & 0xff])
                elif key_len == 3:
                    key = bytes([key_start & 0xff, (key_start >> 8) & 0xff, 0])
                else:
                    key = bytes([key_start & 0xff, (key_start >> 8) & 0xff, 0, 0])
                decrypted = StringDecryptor.xor_decrypt(byte_array, key)
                if decrypted and StringDecryptor._is_printable(decrypted):
                    text = decrypted.decode('utf-8', errors='replace')
                    if len(text) >= 4 and StringDecryptor._confidence_score(text) > 0.5:
                        results.append({
                            'method': f'xor_multi_{key_len}b_0x{key.hex()}',
                            'result': text[:200],
                            'confidence': StringDecryptor._confidence_score(text),
                        })
                if key_len > 2 and key_start > 255:
                    break

        # 3. Base64
        try:
            decoded = base64.b64decode(bytes(byte_array))
            text = decoded.decode('utf-8', errors='replace')
            if len(text) >= 3 and StringDecryptor._is_printable(decoded):
                results.append({
                    'method': 'base64',
                    'result': text[:200],
                    'confidence': StringDecryptor._confidence_score(text),
                })
        except Exception as e:
            logger.debug("apk_reverse_engine/analysis/enhanced/string_decrypt.py:81 suppressed: %s", e)
            logger.debug(f"e")

        # 4. ROT13
        try:
            text = bytes((b - 13) % 256 for b in byte_array).decode('utf-8', errors='replace')
            if StringDecryptor._is_printable(text.encode('latin-1')) and len(text) >= 3:
                results.append({
                    'method': 'rot13',
                    'result': text[:200],
                    'confidence': StringDecryptor._confidence_score(text),
                })
        except Exception as e:
            logger.debug("apk_reverse_engine/analysis/enhanced/string_decrypt.py:93 suppressed: %s", e)
            logger.debug(f"e")

        # 5. Add/Sub constant
        for shift in range(1, 256):
            decoded = bytes((b + shift) % 256 for b in byte_array)
            if StringDecryptor._is_printable(decoded):
                text = decoded.decode('utf-8', errors='replace')
                if len(text) >= 4 and StringDecryptor._confidence_score(text) > 0.5:
                    results.append({
                        'method': f'add_0x{shift:02x}',
                        'result': text[:200],
                        'confidence': StringDecryptor._confidence_score(text),
                    })

        # Sort by confidence
        results.sort(key=lambda x: x['confidence'], reverse=True)
        return results[:10]

    @staticmethod
    def _is_printable(data):
        """检查是否为可打印文本"""
        if isinstance(data, str):
            data = data.encode('latin-1')
        printable = sum(1 for b in data if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09))
        return len(data) > 0 and printable / len(data) > 0.8

    @staticmethod
    def _confidence_score(text):
        """评估解密结果的可信度"""
        if not text or len(text) < 2:
            return 0.0

        score = 0.0
        # 包含常见英文单词
        common_words = ['the', 'and', 'for', 'http', 'com', 'org', 'android',
                        'java', 'Intent', 'Activity', 'View', 'String',
                        'get', 'set', 'app', 'net', 'www']
        for word in common_words:
            if word.lower() in text.lower():
                score += 0.15

        # 包含URL特征
        if 'http' in text.lower() or '://' in text:
            score += 0.3
        # 包含类名特征
        if re.search(r'[a-z]+[A-Z][a-z]+', text):
            score += 0.2
        # 包含包名分隔符
        if '.' in text and text.count('.') >= 2:
            score += 0.15
        # 全部可打印
        printable = sum(1 for c in text if 0x20 <= ord(c) < 0x7f)
        if printable / len(text) > 0.9:
            score += 0.2

        return min(score, 1.0)

    @staticmethod
    def find_encrypted_strings_in_smali(smali_text):
        """在smali代码中查找加密字符串模式"""
        results = []

        # Pattern 1: byte array followed by XOR
        for m in re.finditer(r'new-array\s+v\d+,\s+v\d+,\s+\[B\s*\n((?:.*\n)*?)invoke-static.*\b(xor|decrypt|decode)\w*', smali_text, re.IGNORECASE):
            block = m.group(1)
            # Extract byte values
            bytes_match = re.findall(r'const\s+v\d+,\s+(?:0x)?([0-9a-fA-F]+)', block)
            if bytes_match:
                try:
                    byte_values = bytes(int(b, 16) if len(b) <= 2 else int(b) % 256 for b in bytes_match)
                    decrypted = StringDecryptor.auto_decrypt_bytes(list(byte_values))
                    if decrypted:
                        results.append({
                            'type': 'byte_array_xor',
                            'raw_bytes': byte_values[:20].hex(),
                            'decrypted': decrypted[:3],
                            'address': m.start(),
                        })
                except Exception as e:
                    logger.debug("apk_reverse_engine/analysis/enhanced/string_decrypt.py:172 suppressed: %s", e)
                    logger.debug(f"e")

        # Pattern 2: const-string with encoded value
        for m in re.finditer(r'const-string\s+v\d+,\s*"([^"]*)"', smali_text):
            s = m.group(1)
            if len(s) >= 4:
                # Try base64
                try:
                    decoded = base64.b64decode(s).decode('utf-8', errors='replace')
                    if StringDecryptor._confidence_score(decoded) > 0.3:
                        results.append({
                            'type': 'const_string_base64',
                            'original': s[:50],
                            'decrypted': [{'method': 'base64', 'result': decoded[:100],
                                           'confidence': StringDecryptor._confidence_score(decoded)}],
                            'address': m.start(),
                        })
                except Exception as e:
                    logger.debug("apk_reverse_engine/analysis/enhanced/string_decrypt.py:190 suppressed: %s", e)
                    logger.debug(f"e")

        # Pattern 3: invoke decrypt method with const
        for m in re.finditer(r'invoke-\w+\s+\{.*?\},\s+L[\w/]+;->(\w+)\(.*?\)Ljava/lang/String;', smali_text):
            method_name = m.group(1)
            if re.match(r'(decrypt|decode|deobf|reveal|unhide|xor|a$|o\d*$)', method_name, re.IGNORECASE):
                results.append({
                    'type': 'decrypt_method_call',
                    'method_name': method_name,
                    'address': m.start(),
                    'note': f'可能的字符串解密方法调用: {method_name}()',
                })

        return results

    @staticmethod
    def analyze_decrypt_pattern(dex_parser, class_name=None):
        """分析DEX中的解密模式"""
        dp = dex_parser
        dp._ensure_parsed()

        results = {
            'decrypt_methods': [],
            'encrypted_strings': [],
        }

        methods_meta = dp.get_methods()

        # 查找可能的解密方法
        for m in methods_meta:
            name = m.get('name', '')
            if re.match(r'(decrypt|decode|deobf|reveal|unhide|xor|a$|o\d*$)', name, re.IGNORECASE):
                results['decrypt_methods'].append({
                    'method': name,
                    'class': m.get('class_name', ''),
                    'proto': m.get('proto', ''),
                })

        # 查找byte数组常量
        strings = dp.get_strings()
        for i, s in enumerate(strings):
            if len(s) >= 8:
                # Check for hex-encoded strings
                if re.match(r'^[0-9a-fA-F]+$', s) and len(s) % 2 == 0:
                    try:
                        decoded = bytes.fromhex(s).decode('utf-8', errors='replace')
                        if StringDecryptor._confidence_score(decoded) > 0.3:
                            results['encrypted_strings'].append({
                                'string_idx': i,
                                'original': s[:50],
                                'decoded': decoded[:100],
                                'method': 'hex_decode',
                            })
                    except Exception as e:
                        logger.debug("apk_reverse_engine/analysis/enhanced/string_decrypt.py:244 suppressed: %s", e)
                        logger.debug(f"e")
                # Check for base64
                if re.match(r'^[A-Za-z0-9+/=]+$', s) and len(s) >= 8:
                    try:
                        decoded = base64.b64decode(s).decode('utf-8', errors='replace')
                        if StringDecryptor._confidence_score(decoded) > 0.3:
                            results['encrypted_strings'].append({
                                'string_idx': i,
                                'original': s[:50],
                                'decoded': decoded[:100],
                                'method': 'base64',
                            })
                    except Exception as e:
                        logger.debug("apk_reverse_engine/analysis/enhanced/string_decrypt.py:257 suppressed: %s", e)
                        logger.debug(f"e")

        return results