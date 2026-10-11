# -*- coding: utf-8 -*-
"""http_crypto — HTTP 请求体加解密 + URL 正则重写规则（源自 ProxyPin）

移植自 ProxyPin 的核心算法，Python 标准库 + 可选 pycryptodome：
  1. CryptoRule       — URL 正则 → 加解密规则（对齐 request_crypto_manager.dart）
  2. CryptoKeyConfig  — AES 参数（key/iv/mode/padding/keyLength/ivSource）
  3. aes_encrypt      — AES-CBC / AES-ECB，PKCS7 padding，返回 bytes
  4. aes_decrypt      — 反过程；自动去 padding
  5. RewriteItem      — 单条 replace（source→target，支持正则）
  6. RewriteRule      — URL 正则匹配 → 一组 RewriteItem
  7. apply_rewrite    — 对 URL 应用所有匹配规则，返回新 URL

外部依赖：AES 加解密需要 `pycryptodome`（`pip install pycryptodome`）。
        未安装时 aes_* 会抛 ImportError，其他功能不受影响。

对外 API:
  - CryptoRule(name, url_pattern, config, field=None, enabled=True).match(url)
  - CryptoKeyConfig(key, iv, iv_source, iv_prefix_length, mode, padding, key_length).is_ready
  - aes_encrypt(data, config) -> bytes
  - aes_decrypt(data, config) -> bytes
  - RewriteRule(name, url_pattern, items, method='*', enabled=True).match(url, method)
  - RewriteItem(source, target, is_regex=False, is_url=False)
  - apply_rewrite(url, rules, method='GET') -> str
"""
from __future__ import annotations
import re
import base64
import binascii
from typing import Optional, List


# ── CryptoKeyConfig ──────────────────────────────────────────
class CryptoKeyConfig:
    """AES 参数。对齐 ProxyPin CryptoKeyConfig。"""

    def __init__(self,
                 key: str = '',
                 iv: str = '',
                 iv_source: str = 'manual',    # 'manual' | 'prefix'
                 iv_prefix_length: int = 16,
                 mode: str = 'ECB',            # 'ECB' | 'CBC'
                 padding: str = 'PKCS7',       # 'PKCS7' | 'NoPadding'
                 key_length: int = 128):       # 128 | 192 | 256
        self.key = key
        self.iv = iv
        self.iv_source = iv_source
        self.iv_prefix_length = int(iv_prefix_length)
        self.mode = mode.upper()
        self.padding = padding
        self.key_length = int(key_length)

    @property
    def is_ready(self):
        if not self.key.strip():
            return False
        if self.mode != 'CBC':
            return True
        if self.iv_source == 'prefix':
            return True
        return bool(self.iv.strip())

    @classmethod
    def defaults(cls):
        return cls(key='', iv='', iv_source='manual', iv_prefix_length=16,
                   mode='ECB', padding='PKCS7', key_length=128)

    @classmethod
    def from_dict(cls, d):
        return cls(
            key=d.get('key', ''),
            iv=d.get('iv', ''),
            iv_source=d.get('ivSource', d.get('iv_source', 'manual')),
            iv_prefix_length=int(d.get('ivPrefixLength', d.get('iv_prefix_length', 16))),
            mode=d.get('mode', 'ECB'),
            padding=d.get('padding', 'PKCS7'),
            key_length=int(d.get('keyLength', d.get('key_length', 128))),
        )

    def to_dict(self):
        return {
            'key': self.key,
            'iv': self.iv,
            'ivSource': self.iv_source,
            'ivPrefixLength': self.iv_prefix_length,
            'mode': self.mode,
            'padding': self.padding,
            'keyLength': self.key_length,
        }

    def __repr__(self):
        return 'CryptoKeyConfig(mode=%s keyLen=%d ready=%s)' % (
            self.mode, self.key_length, self.is_ready)


# ── AES 加解密 ───────────────────────────────────────────────
_AES_BLOCK = 16


def _pad_pkcs7(data: bytes) -> bytes:
    if not data:
        data = b''
    pad_len = _AES_BLOCK - (len(data) % _AES_BLOCK)
    return data + bytes([pad_len]) * pad_len


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        return data
    last = data[-1]
    if last < 1 or last > _AES_BLOCK:
        return data
    return data[:-last]


def _key_bytes(config: CryptoKeyConfig) -> bytes:
    """把 config.key 转成 AES key bytes。str 优先按 hex 解析，失败回落 utf-8。"""
    k = config.key
    if isinstance(k, bytes):
        return k
    # 尝试 hex（长度必须为偶数且全 hex）
    if k and len(k) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in k):
        try:
            b = bytes.fromhex(k)
            if len(b) in (16, 24, 32):
                return b
        except ValueError:
            pass
    raw = k.encode('utf-8', 'replace')
    # 截断/补零到合法长度
    target = config.key_length // 8
    if len(raw) < target:
        raw = raw + b'\x00' * (target - len(raw))
    return raw[:target]


def _iv_bytes(config: CryptoKeyConfig, data: bytes = b'') -> Optional[bytes]:
    if config.mode != 'CBC':
        return None
    if config.iv_source == 'prefix':
        n = min(config.iv_prefix_length, len(data), _AES_BLOCK)
        return data[:n].ljust(_AES_BLOCK, b'\x00')
    v = config.iv
    if isinstance(v, bytes):
        return v[:_AES_BLOCK].ljust(_AES_BLOCK, b'\x00')
    if not v.strip():
        return b'\x00' * _AES_BLOCK
    # 尝试 hex
    if len(v) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in v):
        try:
            b = bytes.fromhex(v)
            if len(b) == _AES_BLOCK:
                return b
        except ValueError:
            pass
    return v.encode('utf-8', 'replace')[:_AES_BLOCK].ljust(_AES_BLOCK, b'\x00')


def aes_encrypt(data, config: CryptoKeyConfig) -> bytes:
    """AES 加密。data: str|bytes|list[str]（base64），返回 bytes。"""
    if isinstance(data, str):
        # 尝试 base64 解码；失败按 utf-8
        try:
            b = base64.b64decode(data, validate=False)
            if b:
                data = b
            else:
                data = data.encode('utf-8', 'replace')
        except (binascii.Error, ValueError):
            data = data.encode('utf-8', 'replace')
    if not isinstance(data, bytes):
        data = str(data).encode('utf-8', 'replace')
    key = _key_bytes(config)
    iv = _iv_bytes(config)
    if config.padding.upper() == 'PKCS7':
        data = _pad_pkcs7(data)
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise ImportError('AES requires pycryptodome: pip install pycryptodome')
    if config.mode == 'CBC':
        if iv is None:
            raise ValueError('CBC requires iv (manual iv or iv_source=prefix)')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(data)
    elif config.mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(data)
    raise ValueError('unsupported AES mode: %s' % config.mode)


def aes_decrypt(data, config: CryptoKeyConfig) -> bytes:
    """AES 解密。data: bytes|base64-str，返回 bytes。"""
    if isinstance(data, str):
        try:
            data = base64.b64decode(data, validate=False)
        except (binascii.Error, ValueError):
            data = data.encode('utf-8', 'replace')
    if not isinstance(data, bytes):
        data = str(data).encode('utf-8', 'replace')
    if config.padding.upper() == 'NoPadding':
        data = data[:len(data) // _AES_BLOCK * _AES_BLOCK]
    key = _key_bytes(config)
    iv = _iv_bytes(config, data)
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise ImportError('AES requires pycryptodome: pip install pycryptodome')
    if config.mode == 'CBC':
        if iv is None:
            raise ValueError('CBC requires iv')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = cipher.decrypt(data)
    elif config.mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        plain = cipher.decrypt(data)
    else:
        raise ValueError('unsupported AES mode: %s' % config.mode)
    if config.padding.upper() == 'PKCS7':
        return _unpad_pkcs7(plain)
    return plain


# ── CryptoRule ───────────────────────────────────────────────
class CryptoRule:
    """URL 正则 → CryptoKeyConfig。对齐 ProxyPin CryptoRule。"""

    def __init__(self, name='', url_pattern='', field=None,
                 enabled=True, config: Optional[CryptoKeyConfig] = None):
        self.name = name
        self.url_pattern = url_pattern
        self.field = field
        self.enabled = bool(enabled)
        self.config = config or CryptoKeyConfig.defaults()
        self._regex = None
        if url_pattern:
            try:
                self._regex = re.compile(url_pattern)
            except re.error:
                # 降级：正则子串匹配
                self._regex = None

    def match(self, url: str) -> bool:
        if not self.enabled or not url:
            return False
        if self._regex is not None:
            return bool(self._regex.search(url))
        return self.url_pattern in url

    @classmethod
    def from_dict(cls, d):
        config = CryptoKeyConfig.from_dict(d.get('config', {}) or {})
        return cls(
            name=d.get('name', ''),
            url_pattern=d.get('urlPattern', d.get('url_pattern', '')),
            field=d.get('field'),
            enabled=d.get('enabled', True),
            config=config,
        )

    def to_dict(self):
        return {
            'name': self.name,
            'urlPattern': self.url_pattern,
            'field': self.field,
            'enabled': self.enabled,
            'config': self.config.to_dict(),
        }

    def new_rule(cls=None):
        return CryptoRule(name='', url_pattern='', field='',
                          enabled=True, config=CryptoKeyConfig.defaults())


# ── RewriteItem ──────────────────────────────────────────────
class RewriteItem:
    """单条 rewrite：source→target。is_regex=True 时 source 是正则。"""

    def __init__(self, source='', target='', is_regex=False, is_url=False):
        self.source = source
        self.target = target
        self.is_regex = bool(is_regex)
        self.is_url = bool(is_url)
        self._regex = None
        if self.is_regex and self.source:
            try:
                self._regex = re.compile(self.source)
            except re.error:
                self._regex = None

    def apply(self, text: str) -> str:
        if not self.source:
            return text
        if self.is_regex and self._regex is not None:
            return self._regex.sub(self.target, text)
        return text.replace(self.source, self.target)

    @classmethod
    def from_dict(cls, d):
        return cls(
            source=d.get('source', ''),
            target=d.get('target', ''),
            is_regex=d.get('isRegex', d.get('is_regex', False)),
            is_url=d.get('isUrl', d.get('is_url', False)),
        )

    def to_dict(self):
        return {
            'source': self.source,
            'target': self.target,
            'isRegex': self.is_regex,
            'isUrl': self.is_url,
        }


# ── RewriteRule ──────────────────────────────────────────────
class RewriteRule:
    """URL 正则匹配 → 一组 RewriteItem。对齐 ProxyPin RequestRewriteRule。"""

    def __init__(self, name='', url_pattern='', method='*',
                 enabled=True, items: Optional[List[RewriteItem]] = None):
        self.name = name
        self.url_pattern = url_pattern
        self.method = method.upper() if isinstance(method, str) else method
        self.enabled = bool(enabled)
        self.items = list(items) if items else []
        self._regex = None
        if url_pattern:
            try:
                self._regex = re.compile(url_pattern)
            except re.error:
                self._regex = None

    def match(self, url, method=None):
        if not self.enabled or not url:
            return False
        if self.method not in ('*', '') and method is not None:
            if self.method != method.upper():
                return False
        if self._regex is not None:
            return bool(self._regex.search(url))
        return self.url_pattern in url

    def apply(self, text: str) -> str:
        for item in self.items:
            text = item.apply(text)
        return text

    @classmethod
    def from_dict(cls, d):
        items = [RewriteItem.from_dict(i) for i in (d.get('items', []) or [])]
        return cls(
            name=d.get('name', ''),
            url_pattern=d.get('urlPattern', d.get('url_pattern', '')),
            method=d.get('method', '*'),
            enabled=d.get('enabled', True),
            items=items,
        )

    def to_dict(self):
        return {
            'name': self.name,
            'urlPattern': self.url_pattern,
            'method': self.method,
            'enabled': self.enabled,
            'items': [i.to_dict() for i in self.items],
        }


def apply_rewrite(url: str, rules: List[RewriteRule], method: str = 'GET') -> str:
    """对 URL 应用所有匹配的 RewriteRule，按顺序执行。"""
    result = url
    for rule in rules:
        if rule.match(url, method=method):
            result = rule.apply(result)
    return result


def find_matching_rule(url: str, rules: List[CryptoRule]) -> Optional[CryptoRule]:
    """返回第一条匹配的 CryptoRule（用于决定用哪套 AES 配置）。"""
    for rule in rules:
        if rule.match(url):
            return rule
    return None


__all__ = [
    'CryptoKeyConfig',
    'CryptoRule',
    'RewriteItem',
    'RewriteRule',
    'aes_encrypt',
    'aes_decrypt',
    'apply_rewrite',
    'find_matching_rule',
]