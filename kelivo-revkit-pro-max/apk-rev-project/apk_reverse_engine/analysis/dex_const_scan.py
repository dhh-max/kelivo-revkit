"""DEX 常量池扫描 — 硬编码数值/魔法数字/版本号/设备标识/密钥片段"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import Counter
import re

class DexConstScanAnalyzer:
    """从 DEX 字符串常量池中挖掘硬编码常量与敏感值"""

    # 数值模式
    NUM_PATTERNS = {
        'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'port': re.compile(r'\b(?:port|PORT)[:=]\s*(\d{1,5})\b'),
        'version': re.compile(r'\b\d+\.\d+(?:\.\d+)?(?:[-._]?(?:alpha|beta|rc|release))?\b', re.I),
        'phone': re.compile(r'\b1[3-9]\d{9}\b'),
        'id_num': re.compile(r'\b\d{15}(\d{2}[\dXx])?\b'),
        'lat_lng': re.compile(r'[-+]?\d{1,3}\.\d{4,}\s*[,，]\s*[-+]?\d{1,3}\.\d{4,}'),
        'hex_bytes': re.compile(r'\b(?:0x[0-9a-fA-F]{2})+[0-9a-fA-F]?\b'),
        'large_num': re.compile(r'\b\d{10,}\b'),
    }

    # 敏感关键字值
    KEYWORD_PATTERNS = {
        'api_key_var': re.compile(r'(api[_-]?key|apikey|secret|token|auth|password|passwd|pwd|credential)', re.I),
        'encrypt_key': re.compile(r'(aes|des|rsa|cipher|encrypt|decrypt|secret[key]?|private[key]?|public[key]?|signature)', re.I),
        'device_id': re.compile(r'(imei|imsi|device[_-]?id|android[_-]?id|mac[_-]?addr|serial[_-]?no)', re.I),
        'server': re.compile(r'(server|host|domain|base[_-]?url|endpoint|cdn|dns)', re.I),
        'third_party': re.compile(r'(qq|wechat|weixin|alipay|wxpay|facebook|google|github|twitter|apple)[-_.]?(id|key|secret|appid|app[_-]?id)', re.I),
    }

    @staticmethod
    def analyze(dex_parser):
        """扫描 DEX 字符串常量池中的硬编码常量"""
        dex_parser._ensure_parsed()
        strings = dex_parser.get_strings()

        if not strings:
            return {'error': '无可分析字符串'}

        num_findings = {}
        kw_findings = {}
        sample_map = {}

        for s in strings:
            if not s or len(s) > 300:
                continue

            # 数值模式
            for cat, pattern in DexConstScanAnalyzer.NUM_PATTERNS.items():
                for m in pattern.findall(s):
                    if isinstance(m, tuple):
                        m = m[0]
                    if not m:
                        continue
                    num_findings.setdefault(cat, Counter())[m] += 1
                    sample_map.setdefault(cat, set()).add(m)

            # 关键字模式（短字符串高置信）
            if len(s) <= 80:
                for cat, pattern in DexConstScanAnalyzer.KEYWORD_PATTERNS.items():
                    if pattern.search(s):
                        kw_findings.setdefault(cat, Counter())[s] += 1

        # 汇总
        num_summary = {}
        for cat, counter in num_findings.items():
            top = counter.most_common(15)
            num_summary[cat] = {
                'total': sum(counter.values()),
                'unique': len(counter),
                'samples': [{'value': v, 'count': c} for v, c in top],
            }

        kw_summary = {}
        for cat, counter in kw_findings.items():
            top = counter.most_common(15)
            kw_summary[cat] = {
                'total': sum(counter.values()),
                'unique': len(counter),
                'samples': [{'value': v, 'count': c} for v, c in top],
            }

        return {
            'numeric_constants': num_summary,
            'keyword_constants': kw_summary,
            'total_numeric_findings': sum(v['total'] for v in num_summary.values()),
            'total_keyword_findings': sum(v['total'] for v in kw_summary.values()),
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'numeric_findings': result['total_numeric_findings'],
            'keyword_findings': result['total_keyword_findings'],
            'categories': {k: v['total'] for k, v in result['numeric_constants'].items()},
            'keyword_categories': {k: v['total'] for k, v in result['keyword_constants'].items()},
        }