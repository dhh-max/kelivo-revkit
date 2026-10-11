#!/usr/bin/env python3
"""DEX 字符串深度分析器 - 对字符串进行分类统计和模式提取

功能:
- 按类别分类: URL/Email/路径/文件/Base64/Hex/密码/密钥/IP/Java类名
- 敏感信息检测: API密钥/Token/密码/私钥/证书
- 统计摘要: 各类别数量、占比、去重统计
- 可疑模式: 硬编码凭证、内网地址、调试信息
"""
import re
import base64
from collections import Counter, defaultdict


class StringAnalyzer:
    """DEX 字符串深度分析器"""

    # ── 分类正则 ──────────────────────────────────────────────
    PATTERNS = {
        'url': re.compile(r'https?://[^\s"\']{4,}'),
        'domain': re.compile(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?'),
        'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'file_path': re.compile(r'(?:/[\w.-]+)+|(?:[A-Za-z]:\\[\\\w\s.-]+)'),
        'base64': re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'),
        'hex': re.compile(r'^[0-9a-fA-F]{8,}$'),
        'number': re.compile(r'^\d+$'),
        'java_class': re.compile(r'^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*(?:/[A-Z][a-zA-Z0-9]*)+$'),
        'package_name': re.compile(r'^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$'),
        'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),
        'phone': re.compile(r'^\+?1?\d{10,15}$'),
        'date': re.compile(r'^\d{4}-\d{2}-\d{2}(?:\s\d{2}:\d{2}(?::\d{2})?)?$'),
    }

    # ── 敏感信息关键词 ────────────────────────────────────────
    SENSITIVE_KEYWORDS = {
        'api_key': ['api_key', 'apikey', 'api-key', 'api.key', 'API_KEY'],
        'secret': ['secret', 'SECRET', 'client_secret', 'client.secret'],
        'token': ['token', 'TOKEN', 'access_token', 'refresh_token', 'auth_token'],
        'password': ['password', 'PASSWORD', 'passwd', 'pwd', 'pass'],
        'private_key': ['-----BEGIN', 'PRIVATE KEY', 'private.key', 'rsa_key'],
        'jwt': ['eyJ', 'eyJh', 'eyJ0'],  # JWT 头部
        'authorization': ['authorization', 'Authorization', 'Bearer ', 'Basic '],
        'debug': ['debug', 'DEBUG', 'logcat', 'Log.d', 'Log.e', 'System.out'],
    }

    # ── 内网地址模式 ──────────────────────────────────────────
    PRIVATE_IPS = re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
                             r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
                             r'192\.168\.\d{1,3}\.\d{1,3}|'
                             r'127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    @classmethod
    def classify_single(cls, s):
        """对单个字符串进行分类

        Args:
            s: 字符串

        Returns:
            str: 类别名，未识别返回 'other'
        """
        if not s or len(s) < 3:
            return 'short'

        # 按优先级检查
        if cls.PATTERNS['url'].match(s):
            return 'url'
        if cls.PATTERNS['email'].match(s):
            return 'email'
        if cls.PATTERNS['uuid'].match(s):
            return 'uuid'
        if cls.PATTERNS['phone'].match(s):
            return 'phone'
        if cls.PATTERNS['ipv4'].match(s):
            return 'ipv4'
        if cls.PATTERNS['date'].match(s):
            return 'date'
        if cls.PATTERNS['java_class'].match(s):
            return 'java_class'
        if cls.PATTERNS['package_name'].match(s):
            return 'package_name'
        if cls.PATTERNS['file_path'].match(s):
            return 'file_path'
        if cls.PATTERNS['hex'].match(s) and len(s) >= 16:
            return 'hex'
        if cls.PATTERNS['number'].match(s) and len(s) >= 4:
            return 'number'
        if cls.PATTERNS['domain'].match(s) and '.' in s:
            return 'domain'

        # 编码检测
        if len(s) >= 16 and cls.PATTERNS['base64'].match(s):
            # 排除纯数字base64
            if not cls.PATTERNS['number'].match(s):
                return 'base64'

        return 'other'

    @classmethod
    def classify_all(cls, strings):
        """批量分类，返回分类统计

        Args:
            strings: list[str], DEX 字符串列表

        Returns:
            dict: {
                'categories': {类别名: 数量},
                'classified': {类别名: [示例字符串]},
                'total': int,
                'unique': int,
            }
        """
        classified = defaultdict(list)
        seen = set()

        for s in strings:
            if s in seen:
                continue
            seen.add(s)
            cat = cls.classify_single(s)
            if len(classified[cat]) < 10:  # 仅保留前10个示例
                classified[cat].append(s)

        categories = {cat: len(items) for cat, items in classified.items()}

        return {
            'categories': dict(sorted(categories.items(), key=lambda x: -x[1])),
            'classified': dict(classified),
            'total': len(strings),
            'unique': len(seen),
        }

    @classmethod
    def detect_sensitive(cls, strings):
        """检测敏感信息

        Args:
            strings: list[str]

        Returns:
            list[dict]: 敏感信息列表
        """
        results = []
        seen = set()

        for s in strings:
            if len(s) < 6 or s in seen:
                continue
            s_lower = s.lower()

            for cat, keywords in cls.SENSITIVE_KEYWORDS.items():
                for kw in keywords:
                    if kw in s_lower or kw in s:
                        # 去重
                        key = (cat, s)
                        if key not in seen:
                            seen.add(key)
                            results.append({
                                'category': cat,
                                'value': s[:200],  # 截断过长字符串
                                'length': len(s),
                            })
                        break

        return results

    @classmethod
    def detect_private_ips(cls, strings):
        """检测内网IP地址

        Args:
            strings: list[str]

        Returns:
            list[str]: 内网IP列表
        """
        ips = set()
        for s in strings:
            matches = cls.PRIVATE_IPS.findall(s)
            for m in matches:
                ips.add(m)
        return sorted(ips)

    @classmethod
    def extract_urls(cls, strings):
        """提取所有URL

        Args:
            strings: list[str]

        Returns:
            dict: {
                'urls': list[str],
                'domains': list[str],
                'schemes': Counter,
            }
        """
        urls = set()
        domains = set()
        schemes = Counter()

        for s in strings:
            # URL 提取
            for m in cls.PATTERNS['url'].finditer(s):
                url = m.group()
                urls.add(url)
                # 提取 scheme
                if '://' in url:
                    scheme = url.split('://')[0]
                    schemes[scheme] += 1
                # 提取域名
                domain_match = re.search(r'://([^/:\s]+)', url)
                if domain_match:
                    domains.add(domain_match.group(1))

        return {
            'urls': sorted(urls)[:100],
            'domains': sorted(domains)[:50],
            'schemes': dict(schemes),
            'total_urls': len(urls),
        }

    @classmethod
    def analyze(cls, strings):
        """一站式字符串深度分析

        Args:
            strings: list[str]

        Returns:
            dict: 完整分析报告
        """
        if not strings:
            return {
                'total': 0,
                'unique': 0,
                'classification': {},
                'sensitive': [],
                'urls': {'urls': [], 'domains': [], 'schemes': {}, 'total_urls': 0},
                'private_ips': [],
                'summary': {},
            }

        # 分类统计
        classification = cls.classify_all(strings)

        # 敏感信息
        sensitive = cls.detect_sensitive(strings)

        # URL 提取
        urls = cls.extract_urls(strings)

        # 内网IP
        private_ips = cls.detect_private_ips(strings)

        # 统计摘要
        cat = classification['categories']
        summary = {
            'total_strings': len(strings),
            'unique_strings': classification['unique'],
            'url_count': cat.get('url', 0),
            'ip_count': cat.get('ipv4', 0),
            'email_count': cat.get('email', 0),
            'base64_count': cat.get('base64', 0),
            'hex_count': cat.get('hex', 0),
            'java_class_count': cat.get('java_class', 0) + cat.get('package_name', 0),
            'sensitive_count': len(sensitive),
            'private_ip_count': len(private_ips),
            'has_private_ips': len(private_ips) > 0,
            'has_sensitive': len(sensitive) > 0,
        }

        return {
            'total': len(strings),
            'unique': classification['unique'],
            'classification': classification,
            'sensitive': sensitive,
            'urls': urls,
            'private_ips': private_ips,
            'summary': summary,
        }


# ── 快捷函数 ──────────────────────────────────────────────────
def analyze_strings(strings):
    """一站式字符串深度分析"""
    return StringAnalyzer.analyze(strings)

def classify_strings(strings):
    """对字符串进行分类统计"""
    return StringAnalyzer.classify_all(strings)

def detect_sensitive_strings(strings):
    """检测敏感信息"""
    return StringAnalyzer.detect_sensitive(strings)

def extract_urls_from_strings(strings):
    """提取URL"""
    return StringAnalyzer.extract_urls(strings)