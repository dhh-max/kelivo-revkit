"""密钥/凭证深度扫描器 - 增强版敏感信息检测"""
import re

class KeyScanner:
    """密钥扫描引擎：检测硬编码密钥、令牌、凭证等敏感信息"""

    # 扩展的密钥模式
    KEY_PATTERNS = [
        # 通用凭证
        (r"""(?i)(?:password|passwd|pwd|secret|private_key|private\s*key)\s*[:=]\s*["']([^"']{8,})["']""", '密码/密钥'),
        (r"""(?i)(?:api[_-]?key|api_key|apikey)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']""", 'API密钥'),
        (r"""(?i)(?:token|access_token|auth_token|refresh_token|bearer)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{16,})["']""", '访问令牌'),
        (r"""(?i)(?:session[_-]?id|session_id|sid)\s*[:=]\s*["']([a-zA-Z0-9]{8,})["']""", '会话ID'),
        (r"""(?i)(?:jwt|json\s*web\s*token)\s*[:=]\s*["'](eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)["']""", 'JWT令牌'),
        (r"""(?i)secret\s*[:=]\s*["']([a-zA-Z0-9_\-+=/]{16,})["']""", 'Secret'),
        
        # 平台特定密钥
        (r'(?i)AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
        (r'(?i)sk-[0-9a-zA-Z]{32,}', 'OpenAI API Key'),
        (r'(?i)sk_live_[0-9a-zA-Z]{20,}', 'Stripe Live Key'),
        (r'(?i)sk_test_[0-9a-zA-Z]{20,}', 'Stripe Test Key'),
        (r'(?i)pk_live_[0-9a-zA-Z]{20,}', 'Stripe Publishable Key'),
        (r'(?i)pk_test_[0-9a-zA-Z]{20,}', 'Stripe Test Publishable'),
        (r'(?i)ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Token'),
        (r'(?i)gho_[0-9a-zA-Z]{36}', 'GitHub OAuth Token'),
        (r'(?i)github_token\s*[:=]\s*["\']([^"\']+)["\']', 'GitHub Token'),
        (r'(?i)AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']([^"\']+)["\']', 'AWS Secret Key'),
        (r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----', '私钥 (PEM)'),
        (r'(?i)-----BEGIN CERTIFICATE-----', '证书 (PEM)'),
        (r'(?i)-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH私钥'),
        (r'(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP私钥'),
        
        # 数据库连接
        (r'(?i)(?:jdbc|mysql|postgresql|mongodb|redis|sqlite)://[\w:]+@[\w.]+', '数据库连接串'),
        (r'(?i)mongodb\+srv://[\w:]+@[\w.]+', 'MongoDB连接串'),
        
        # 云服务密钥
        (r'(?i)azure[_-]?(?:storage|account)[_-]?(?:key|name)\s*[:=]\s*["\']([^"\']+)["\']', 'Azure密钥'),
        (r'(?i)tencent[_-]?(?:secret|key)[_-]?id\s*[:=]\s*["\']([^"\']+)["\']', '腾讯云SecretId'),
        (r'(?i)aliyun[_-]?(?:access[_-]?)?key[_-]?(?:id|secret)\s*[:=]\s*["\']([^"\']+)["\']', '阿里云密钥'),
        (r'(?i)huawei[_-]?(?:access|secret)[_-]?key\s*[:=]\s*["\']([^"\']+)["\']', '华为云密钥'),
        
        # Firebase
        (r'(?i)firebase[_-]?(?:url|database|storage|key|secret|sender|app)\s*[:=]\s*["\']([^"\']+)["\']', 'Firebase配置'),
        (r'(?i)google-services\.json', 'Firebase google-services.json'),
        
        # 通用
        (r'(?i)(?:encryption|decrypt|aes|rsa|des|3des)[_-]?(?:key|secret)\s*[:=]\s*["\']([a-fA-F0-9]{16,64})["\']', '加密密钥(Hex)'),
        (r'(?i)(?:salt|iv|nonce|init_vector)\s*[:=]\s*["\']([a-fA-F0-9]{8,64})["\']', '加密IV/Salt'),
        (r'(?i)(?:client[_-]?id|client[_-]?secret|app[_-]?id|app[_-]?secret)\s*[:=]\s*["\']([^"\']{8,})["\']', '客户端凭证'),
    ]

    # 安全存储类名特征
    STORAGE_CLASSES = [
        'SharedPreferences', 'SharedPrefs', 'DataStore', 'DataStore',
        'EncryptedSharedPreferences', 'KeyStore', 'AndroidKeyStore',
        'SQLiteOpenHelper', 'RoomDatabase', 'Realm',
    ]

    @staticmethod
    def scan_strings(strings):
        """从DEX字符串列表中扫描密钥"""
        if not strings:
            return {'keys': [], 'summary': {}}

        text = '\n'.join(strings)
        found_keys = []
        risk_score = 0

        for pattern, category in KeyScanner.KEY_PATTERNS:
            matches = re.finditer(pattern, text)
            for m in matches:
                # 获取匹配的完整内容作为上下文
                full_match = m.group(0)
                # 尝试获取第一个捕获组
                value = m.group(1) if m.lastindex else ''
                
                # 过滤掉显而易见的误报
                if value and len(value) < 4:
                    continue
                if value and value in ('true', 'false', 'null', 'nil', 'none', 'yes', 'no'):
                    continue
                if value and value.startswith('${') and value.endswith('}'):
                    continue  # 占位符
                if value and value.startswith('@string/'):
                    continue  # 资源引用

                found_keys.append({
                    'category': category,
                    'match': full_match[:120],
                    'value': value[:80] if value else '',
                    'severity': 'HIGH' if '私钥' in category or '密钥' in category or 'secret' in category.lower() or 'password' in category.lower()
                              else 'MEDIUM' if '令牌' in category or 'token' in category.lower() or '凭证' in category
                              else 'INFO',
                })

        # 计算风险评分
        high_count = sum(1 for k in found_keys if k['severity'] == 'HIGH')
        medium_count = sum(1 for k in found_keys if k['severity'] == 'MEDIUM')
        risk_score = min(100, high_count * 10 + medium_count * 3)

        return {
            'keys': found_keys,
            'summary': {
                'total': len(found_keys),
                'high': high_count,
                'medium': medium_count,
                'info': len(found_keys) - high_count - medium_count,
                'risk_score': risk_score,
                'risk_level': '严重' if risk_score >= 50 else '中等' if risk_score >= 20 else '低风险',
            }
        }

    @staticmethod
    def detect_weak_crypto(strings):
        """检测弱加密算法使用"""
        if not strings:
            return []
        text = '\n'.join(strings)
        weak_patterns = [
            (r'(?i)DESede/CBC/NoPadding', 'DESede/CBC (弱加密)'),
            (r'(?i)DES/CBC/NoPadding', 'DES/CBC (弱加密)'),
            (r'(?i)MD5\b', 'MD5 (已破解)'),
            (r'(?i)SHA-1\b|SHA1\b', 'SHA-1 (已破解)'),
            (r'(?i)RC4\b', 'RC4 (弱加密)'),
            (r'(?i)PBEWithMD5AndDES', 'PBE+MD5+DES (弱加密)'),
            (r'(?i)ECB\b', 'ECB模式 (不安全)'),
            (r'(?i)OAEP\b', 'OAEP填充 (安全)'),
            (r'(?i)GCM\b', 'GCM模式 (安全)'),
        ]
        results = []
        for pattern, desc in weak_patterns:
            if re.search(pattern, text):
                results.append(desc)
        return results