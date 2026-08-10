"""加密分析器 - 深度检测加密算法、密钥管理、加密模式、自定义加密"""

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import re
import struct
from collections import defaultdict
class CryptoAnalyzer:
    """加密/密码学深度分析器"""

    # 标准加密算法特征
    CRYPTO_ALGORITHMS = {
        'AES': {
            'patterns': [r'AES', r'Rijndael', r'AES_set_encrypt_key', r'AES_cbc_encrypt',
                         r'AES_encrypt', r'AES_decrypt', r'crypto/aes', r'Cipher.*AES'],
            'indicators': [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5],  # AES S-box first 8 bytes
            'mode': 'symmetric',
        },
        'DES': {
            'patterns': [r'\bDES\b', r'DES_set_key', r'des_encrypt', r'DES_ecb_encrypt',
                         r'DES_cbc_encrypt', r'Cipher.*DES', r'DESede', r'3DES'],
            'indicators': [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],  # DES initial permutation
            'mode': 'symmetric',
        },
        'RSA': {
            'patterns': [r'\bRSA\b', r'RSA_public_encrypt', r'RSA_private_decrypt',
                         r'RSA_generate_key', r'RSA_new', r'BN_mod_exp'],
            'indicators': [],
            'mode': 'asymmetric',
        },
        'ECC': {
            'patterns': [r'\bECC\b', r'EC_KEY_new', r'ECDSA_sign', r'EC_POINT_mul',
                         r'ec_curve', r'secp256r1', r'secp384r1', r'secp256k1'],
            'indicators': [],
            'mode': 'asymmetric',
        },
        'ChaCha20': {
            'patterns': [r'ChaCha20', r'ChaCha', r'chacha20', r'salsa20', r'Salsa20'],
            'indicators': [b'expand 32-byte k', b'expand 16-byte k'],
            'mode': 'symmetric',
        },
        'RC4': {
            'patterns': [r'\bRC4\b', r'RC4_set_key', r'rc4_encrypt', r'ARCFOUR', r'arcfour'],
            'indicators': [],
            'mode': 'symmetric',
        },
        'Blowfish': {
            'patterns': [r'Blowfish', r'BF_set_key', r'BF_encrypt', r'blowfish'],
            'indicators': [0x243, 0x853, 0x6c9, 0x9d5],  # Blowfish P-array
            'mode': 'symmetric',
        },
        'Camellia': {
            'patterns': [r'Camellia', r'Camellia_set_key', r'camellia_encrypt'],
            'indicators': [],
            'mode': 'symmetric',
        },
    }

    # 加密模式特征
    CRYPTO_MODES = {
        'ECB': [r'AES/ECB', r'DES/ECB', r'\"ECB\"', r'ENGINE.*ECB'],
        'CBC': [r'AES/CBC', r'DES/CBC', r'\"CBC\"', r'ENGINE.*CBC'],
        'CTR': [r'AES/CTR', r'\"CTR\"', r'ENGINE.*CTR'],
        'GCM': [r'AES/GCM', r'\"GCM\"', r'ENGINE.*GCM'],
        'CFB': [r'AES/CFB', r'\"CFB\"'],
        'OFB': [r'AES/OFB', r'\"OFB\"'],
    }

    # 哈希算法特征
    HASH_ALGORITHMS = {
        'MD5': [r'MD5', r'MD5_Init', r'MD5_Update', r'MD5_Final', r'md5'],
        'SHA1': [r'SHA1', r'SHA1_Init', r'SHA-1', r'sha1'],
        'SHA256': [r'SHA256', r'SHA-256', r'SHA256_Init', r'sha256'],
        'SHA512': [r'SHA512', r'SHA-512', r'sha512'],
        'HMAC': [r'HMAC', r'HMAC_Init', r'HMAC_Update', r'HMAC_Final'],
        'PBKDF2': [r'PBKDF2', r'PBKDF2WithHmac', r'pbkdf2'],
        'BCrypt': [r'\bBCrypt\b', r'bcrypt'],
        'Scrypt': [r'\bScrypt\b', r'scrypt'],
    }

    # 弱加密特征
    WEAK_CRYPTO_INDICATORS = {
        'weak_algorithm': [
            (r'DES(?!ede|3DES)', 'DES算法（已不安全）'),
            (r'\bRC4\b', 'RC4算法（已不安全）'),
            (r'MD5(?!.*HMAC)', 'MD5哈希（不适合安全验证）'),
            (r'SHA1(?!.*HMAC)', 'SHA1哈希（已不安全）'),
            (r'AES/ECB', 'ECB模式（不安全）'),
            (r'\"DES\"', 'DES加密'),
        ],
        'hardcoded_key': [
            (r'SecretKeySpec\s*\(\s*"[^"]+"', '硬编码密钥'),
            (r'new\s+SecretKeySpec\s*\(\s*[^,]+\.getBytes', '密钥来自字符串'),
            (r'KeyGenerator.*init\s*\(\s*\d+\s*\)', '密钥生成器初始化'),
            (r'IvParameterSpec\s*\(\s*"[^"]+"', '硬编码IV'),
        ],
        'weak_random': [
            (r'Random\s*\(', 'java.util.Random（非加密安全）'),
            (r'Math\.random', 'Math.random（非加密安全）'),
        ],
        'insecure_tls': [
            (r'TrustManager.*\{\s*\}', '空TrustManager'),
            (r'HostnameVerifier.*verify.*return\s+true', '空HostnameVerifier'),
            (r'setHostnameVerifier.*ALLOW_ALL', '允许所有主机名'),
            (r'ALLOW_ALL_HOSTNAME_VERIFIER', '允许所有主机名'),
            (r'checkServerTrusted.*\{\s*\}', '空证书验证'),
            (r'SSLContext\.getInstance.*\"SSL\"', '旧版SSL协议'),
        ],
    }

    @staticmethod
    def analyze(text=None, class_names=None, strings=None, native_data=None):
        """全面加密分析"""
        combined = ''
        if text:
            combined += text
        if strings:
            combined += '\n' + '\n'.join(str(s) for s in strings)

        results = {
            'algorithms': CryptoAnalyzer._detect_algorithms(combined, native_data),
            'modes': CryptoAnalyzer._detect_modes(combined),
            'hashes': CryptoAnalyzer._detect_hashes(combined),
            'weak_crypto': CryptoAnalyzer._detect_weak_crypto(combined),
            'key_management': CryptoAnalyzer._detect_key_management(combined),
            'native_crypto': CryptoAnalyzer._detect_native_crypto(native_data) if native_data else {},
        }

        # 风险评估
        weak = results['weak_crypto']
        algo_count = len(results['algorithms'])
        weak_count = sum(len(v) for v in weak.values())
        results['risk_assessment'] = {
            'algorithm_count': algo_count,
            'weak_indicator_count': weak_count,
            'level': 'critical' if weak_count > 5 else ('high' if weak_count > 2 else ('medium' if weak_count > 0 else 'low')),
            'recommendations': CryptoAnalyzer._generate_recommendations(results),
        }

        return results

    @staticmethod
    def _detect_algorithms(text, native_data=None):
        found = {}
        for algo, info in CryptoAnalyzer.CRYPTO_ALGORITHMS.items():
            matches = []
            for pat in info['patterns']:
                ms = re.findall(pat, text, re.IGNORECASE)
                if ms:
                    matches.extend(ms)
            # Check native indicators (S-box etc.)
            if native_data and info.get('indicators'):
                for indicator in info['indicators']:
                    if isinstance(indicator, int):
                        if struct.pack('B', indicator) in native_data:
                            matches.append(f'native_indicator_0x{indicator:02x}')
                    elif isinstance(indicator, bytes):
                        if indicator in native_data:
                            matches.append(f'native_indicator_{indicator}')
                    elif isinstance(indicator, list):
                        # Check for byte sequence
                        seq = bytes(indicator)
                        if seq in native_data:
                            matches.append('native_sbox_detected')
            if matches:
                found[algo] = {
                    'mode': info['mode'],
                    'match_count': len(matches),
                    'matches': list(set(matches))[:10],
                }
        return found

    @staticmethod
    def _detect_modes(text):
        found = {}
        for mode, patterns in CryptoAnalyzer.MODES.items():
            matches = []
            for pat in patterns:
                ms = re.findall(pat, text, re.IGNORECASE)
                if ms:
                    matches.extend(ms)
            if matches:
                found[mode] = {
                    'match_count': len(matches),
                    'secure': mode not in ('ECB',),
                }
        return found

    @staticmethod
    def _detect_hashes(text):
        found = {}
        for algo, patterns in CryptoAnalyzer.HASH_ALGORITHMS.items():
            matches = []
            for pat in patterns:
                ms = re.findall(pat, text, re.IGNORECASE)
                if ms:
                    matches.extend(ms)
            if matches:
                found[algo] = {'match_count': len(matches)}
        return found

    @staticmethod
    def _detect_weak_crypto(text):
        results = defaultdict(list)
        for category, patterns in CryptoAnalyzer.WEAK_CRYPTO_INDICATORS.items():
            for pat, desc in patterns:
                matches = re.findall(pat, text, re.IGNORECASE)
                if matches:
                    results[category].append({
                        'description': desc,
                        'pattern': pat,
                        'count': len(matches),
                    })
        return dict(results)

    @staticmethod
    def _detect_key_management(text):
        findings = []

        # KeyStore usage
        if re.search(r'KeyStore\.getInstance', text, re.IGNORECASE):
            findings.append({'type': 'keystore', 'description': '使用Android KeyStore'})
        # KeyGenerator
        if re.search(r'KeyGenerator\.getInstance', text, re.IGNORECASE):
            findings.append({'type': 'keygenerator', 'description': '使用密钥生成器'})
        # KeyPairGenerator
        if re.search(r'KeyPairGenerator\.getInstance', text, re.IGNORECASE):
            findings.append({'type': 'keypairgen', 'description': '使用密钥对生成器'})
        # SecureRandom
        if re.search(r'SecureRandom', text, re.IGNORECASE):
            findings.append({'type': 'securerandom', 'description': '使用安全随机数生成器'})
        # Hardcoded key
        hardcoded = re.findall(r'SecretKeySpec\s*\(\s*("[^"]+")\s*\.', text)
        if hardcoded:
            findings.append({'type': 'hardcoded_key', 'description': '硬编码密钥', 'values': hardcoded[:5]})

        return findings

    @staticmethod
    def _detect_native_crypto(data):
        """检测SO文件中的加密相关符号"""
        from ..core.native_analyzer import ElfImage
        results = {
            'crypto_functions': [],
            'crypto_strings': [],
        }

        try:
            elf = ElfImage.parse(data)
            dynsym = elf.section_by_name('.dynsym')
            dynstr = elf.section_by_name('.dynstr')

            if dynsym and dynstr:
                for sym in elf.read_symbols(dynsym, dynstr):
                    if not sym.name:
                        continue
                    name_lower = sym.name.lower()
                    crypto_keywords = ['aes', 'des', 'rsa', 'sha', 'md5', 'hmac', 'encrypt',
                                       'decrypt', 'cipher', 'key', 'sign', 'verify',
                                       'ssl', 'tls', 'crypto', 'hash', 'digest']
                    for kw in crypto_keywords:
                        if kw in name_lower:
                            results['crypto_functions'].append({
                                'name': sym.name,
                                'type': 'import' if sym.is_undefined else 'export',
                                'keyword': kw,
                            })
                            break

            # Search for crypto constants in data
            if b'expand 32-byte k' in data:
                results['crypto_strings'].append('ChaCha20 constant')
            if b'expand 16-byte k' in data:
                results['crypto_strings'].append('ChaCha20 (16-byte) constant')
            # AES S-box
            aes_sbox = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
            if aes_sbox in data:
                results['crypto_strings'].append('AES S-box detected')

        except Exception as e:
            logger.debug("apk_reverse_engine/analysis/enhanced/crypto_analyzer.py:278 suppressed: %s", e)

        return results

    @staticmethod
    def _generate_recommendations(results):
        recs = []
        weak = results.get('weak_crypto', {})
        if weak.get('weak_algorithm'):
            recs.append('替换弱加密算法（DES/RC4/MD5）为AES-GCM/SHA-256')
        if weak.get('hardcoded_key'):
            recs.append('移除硬编码密钥，使用Android KeyStore')
        if weak.get('insecure_tls'):
            recs.append('修复TLS验证，移除空TrustManager/HostnameVerifier')
        if weak.get('weak_random'):
            recs.append('使用SecureRandom替代Random/Math.random')
        if 'ECB' in results.get('modes', {}):
            recs.append('避免ECB模式，改用CBC/GCM')
        if not recs:
            recs.append('未发现明显加密安全问题')
        return recs