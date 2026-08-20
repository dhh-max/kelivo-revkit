"""DEX 加密/编码特征分析 — 加密算法引用/编码/哈希/密钥/安全加密评分"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter, defaultdict


class DexCryptoAnalyzer:
    """DEX 加密与编码特征分析 — 加密算法/哈希/编码/密钥检测/安全加密评分"""

    # 加密算法
    ENCRYPTION_ALGOS = [
        'AES', 'RSA', 'DES', 'DESede', 'Blowfish', 'Twofish',
        'PBE', 'ECIES', 'SM2', 'SM4', 'ChaCha20', 'ChaCha',
        'Cipher', 'SecretKeySpec', 'KeyGenerator', 'KeyPairGenerator',
        'KeyFactory', 'SecretKeyFactory', 'KeyAgreement',
        'javax.crypto', 'java.security.Key',
    ]
    # 哈希算法
    HASH_ALGOS = [
        'MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'SHA-384',
        'MessageDigest', 'SHA1', 'SHA256', 'SHA512',
        'PBKDF2', 'bcrypt', 'scrypt', 'argon2',
        'Mac', 'Hmac', 'HmacMD5', 'HmacSHA',
    ]
    # 编码
    ENCODING = [
        'Base64', 'Base64URL', 'Hex', 'encodeHex', 'decodeHex',
        'URLEncoder', 'URLDecoder', 'Base64.encode', 'Base64.decode',
        'android.util.Base64', 'java.util.Base64',
    ]
    # 不安全/弱算法
    WEAK_ALGOS = ['DES', 'MD5', 'SHA-1', 'PBE', 'DESede', 'Blowfish']

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 加密与编码特征"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        if not class_defs:
            return {'error': '无类定义数据'}
        encryption_hits = Counter()
        hash_hits = Counter()
        encoding_hits = Counter()
        weak_hits = Counter()
        # 关键词扫描
        for s in strings:
            if not s:
                continue
            for pat in DexCryptoAnalyzer.ENCRYPTION_ALGOS:
                if pat in s:
                    encryption_hits[pat] += 1
            for pat in DexCryptoAnalyzer.HASH_ALGOS:
                if pat in s:
                    hash_hits[pat] += 1
            for pat in DexCryptoAnalyzer.ENCODING:
                if pat in s:
                    encoding_hits[pat] += 1
            for pat in DexCryptoAnalyzer.WEAK_ALGOS:
                if pat in s:
                    weak_hits[pat] += 1
        # 查找加密相关类
        crypto_classes = []
        for cd in class_defs:
            cn = cd.get('class_name', '')
            cname = cn.replace('L', '').replace(';', '').replace('/', '.')
            if any(k in cname for k in ['crypto', 'Crypto', 'Cipher', 'Secure', 'Encrypt', 'Decrypt', 'Hash', 'Digest']):
                crypto_classes.append(cname)
        # 安全评分
        enc_total = sum(encryption_hits.values())
        hash_total = sum(hash_hits.values())
        weak_total = sum(weak_hits.values())
        has_strong = any(k in encryption_hits for k in ['AES', 'RSA', 'ChaCha20', 'ChaCha', 'SM2', 'SM4'])
        if enc_total == 0 and hash_total == 0:
            security_score = 0
            security_level = '无加密'
        else:
            strong_bonus = 20 if has_strong else 0
            weak_penalty = min(weak_total * 5, 40)
            coverage = min(enc_total * 2 + hash_total, 50)
            score = min(100, max(0, coverage + strong_bonus - weak_penalty))
            security_score = score
            if score >= 60 and weak_penalty < 20:
                security_level = '强加密'
            elif score >= 30:
                security_level = '中加密'
            else:
                security_level = '弱加密'
        return {
            'encryption_hits': [{'algo': p, 'count': c} for p, c in encryption_hits.most_common(20)],
            'encryption_total': enc_total,
            'hash_hits': [{'algo': p, 'count': c} for p, c in hash_hits.most_common(15)],
            'hash_total': hash_total,
            'encoding_hits': [{'encoding': p, 'count': c} for p, c in encoding_hits.most_common(15)],
            'encoding_total': sum(encoding_hits.values()),
            'weak_algo_hits': [{'algo': p, 'count': c} for p, c in weak_hits.most_common(10)],
            'weak_total': weak_total,
            'crypto_class_count': len(crypto_classes),
            'crypto_classes': crypto_classes[:20],
            'has_strong_encryption': has_strong,
            'security_score': security_score,
            'security_level': security_level,
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'encryption_total': result['encryption_total'],
            'hash_total': result['hash_total'],
            'weak_total': result['weak_total'],
            'has_strong_encryption': result['has_strong_encryption'],
            'security_score': result['security_score'],
            'security_level': result['security_level'],
        }