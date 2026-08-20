"""APK网络端点深度提取器 - 从DEX字符串中提取URL、API端点、IP、域名"""
import re
from collections import Counter

class EndpointExtractor:
    """网络端点提取引擎：从DEX字符串中提取并分类所有网络端点"""

    # 常见API路径模式
    API_PATTERNS = [
        r'/api/[\w/.-]+',
        r'/v\d+/[\w/.-]+',
        r'/rest/[\w/.-]+',
        r'/graphql[\w/.-]*',
        r'/ws/[\w/.-]+',
        r'/socket[\w/.-]*',
        r'/rpc/[\w/.-]+',
        r'/json[\w/.-]*',
        r'/soap[\w/.-]*',
        r'/oauth[\w/.-]*',
        r'/token[\w/.-]*',
        r'/auth[\w/.-]*',
        r'/login[\w/.-]*',
        r'/register[\w/.-]*',
        r'/upload[\w/.-]*',
        r'/download[\w/.-]*',
        r'/callback[\w/.-]*',
        r'/webhook[\w/.-]*',
        r'/notify[\w/.-]*',
        r'/push[\w/.-]*',
    ]

    # 云服务域名
    CLOUD_DOMAINS = [
        'amazonaws.com', 'azure.com', 'azureedge.net', 'azurefd.net',
        'cloudfront.net', 'aliyuncs.com', 'aliyundns.com',
        'qcloud.com', 'tencentcloud.com', 'huaweicloud.com',
        'googleapis.com', 'firebaseio.com', 'appspot.com',
        'herokuapp.com', 'netlify.com', 'vercel.app', 'fly.dev',
        'cloudflare.com', 'cloudflareworkers.com',
        'digitaloceanspaces.com', 'linode.com', 'vultr.com',
    ]

    # CDN域名特征
    CDN_KEYWORDS = ['cdn', 'static', 'assets', 'media', 'img', 'css', 'js']

    @staticmethod
    def extract_all(strings):
        """从DEX字符串列表中提取所有网络端点"""
        if not strings:
            return {}

        text = '\n'.join(strings)

        # 1. URL提取
        urls = list(set(re.findall(r'https?://[^\s"\'<>]+', text)))
        http_urls = [u for u in urls if u.startswith('http://')]
        https_urls = [u for u in urls if u.startswith('https://')]

        # 2. 域名提取
        domains = []
        for u in urls:
            m = re.search(r'https?://([^/\s"\'<>:]+)', u)
            if m:
                domains.append(m.group(1).lower())
        domains = list(set(domains))

        # 3. IP提取
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        # 过滤无效IP
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                valid_ips.append(ip)
        ips = valid_ips

        # 4. 分类IP
        private_ips = [ip for ip in ips if ip.startswith(('10.', '172.1', '192.168', '127.', '169.254'))]
        public_ips = [ip for ip in ips if ip not in private_ips]

        # 5. 端口提取
        ports = list(set(re.findall(r':(\d{2,5})(?=/|\s|$|"|\')', text)))
        ports = [p for p in ports if 1 <= int(p) <= 65535]
        port_counts = Counter(ports)

        # 6. API路径提取
        api_paths = []
        for pattern in EndpointExtractor.API_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            api_paths.extend(matches)
        api_paths = list(set(api_paths))[:50]

        # 7. 分类域名
        cloud_hosts = [h for h in domains if any(h.endswith(c) or c in h for c in EndpointExtractor.CLOUD_DOMAINS)]
        cdn_hosts = [h for h in domains if any(kw in h for kw in EndpointExtractor.CDN_KEYWORDS)]
        internal_hosts = [h for h in domains if any(h.endswith(s) for s in ['.local', '.internal', '.lan', 'localhost'])]

        # 8. 参数化URL (含查询参数)
        parameterized_urls = [u for u in urls if '?' in u]

        # 9. 协议分析
        protocols = {
            'http_only': len(http_urls),
            'https_only': len(https_urls),
            'insecure_ratio': round(len(http_urls) / max(1, len(urls)) * 100, 1),
        }

        # 10. Base64/编码URL
        encoded_urls = list(set(re.findall(r'[A-Za-z0-9+/=]{40,}', text)))
        # 粗略过滤：看起来像base64的
        encoded_urls = [e for e in encoded_urls if re.search(r'[A-Za-z0-9+/=]{40,}', e)][:20]

        return {
            'total_urls': len(urls),
            'urls': urls[:50],
            'http_urls': http_urls[:20],
            'https_urls': https_urls[:20],
            'domains': domains[:30],
            'cloud_hosts': cloud_hosts[:15],
            'cdn_hosts': cdn_hosts[:10],
            'internal_hosts': internal_hosts[:10],
            'ips': ips[:30],
            'public_ips': public_ips[:20],
            'private_ips': private_ips[:20],
            'ports': sorted(port_counts.keys(), key=lambda p: int(p))[:20],
            'api_paths': api_paths[:30],
            'parameterized_urls': parameterized_urls[:20],
            'protocols': protocols,
            'encoded_urls_candidates': encoded_urls[:10],
        }