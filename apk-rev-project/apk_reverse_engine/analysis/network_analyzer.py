#!/usr/bin/env python3
"""网络分析器增强版 - 网络协议深度分析 + SSL 钉扎检测 + 自定义协议 + 安全配置评估

功能:
  1. URL/IP/域名提取和分类 (保留原功能)
  2. SSL/TLS 配置检测 (cleartext, pinning, 降级)
  3. WebSocket 检测
  4. 自定义协议检测 (深层链接, intent, content)
  5. 网络安全配置评估 (network_security_config.xml)
  6. CDN/云服务分类
  7. 不安全的 HTTP 使用分析
  8. API 端点模式分析
"""
import re
from collections import Counter


class NetworkAnalyzer:
    """网络分析引擎 - 多维度网络行为分析"""

    # 不安全协议检测
    INSECURE_PROTOCOLS = [
        'http://', 'ftp://', 'telnet://', 'rtsp://',
    ]

    # 自定义协议 Scheme
    CUSTOM_SCHEMES = [
        'intent://', 'content://', 'file://', 'tel://', 'sms://',
        'mailto:', 'geo:', 'market://', 'whatsapp://',
        'weixin://', 'alipays://', 'taobao://', 'tmall://',
    ]

    # WebSocket 协议
    WS_PROTOCOLS = ['ws://', 'wss://']

    # SSL 相关类名/方法 (用于检测 SSL Pinning)
    SSL_PINNING_CLASSES = [
        'okhttp3.CertificatePinner', 'OkHttpClient.Builder.certificatePinner',
        'CertificatePinner', 'TrustManager', 'X509TrustManager',
        'SSLSocketFactory', 'HttpsURLConnection',
        'NetworkSecurityPolicy', 'SecurityProvider',
        'TrustManagerFactory', 'KeyStore',
        'PinningTrustManager', 'PinningX509TrustManager',
        'CertificateTransparency', 'PublicKeyPin',
    ]

    SSL_PINNING_STRINGS = [
        'certificatePinner', 'certificate_pinner', 'certPinner',
        'publicKeyPin', 'pin=' , 'sha256/', 'sha1/',
        'addPinnedCertificate', 'setPinnedCertificates',
        'certificatePinning', 'pinning',
    ]

    # 不安全的 SSL 配置
    UNSAFE_SSL_STRINGS = [
        'ALLOW_ALL_HOSTNAME_VERIFIER', 'allowAllHostnameVerifier',
        'AllowAllHostnameVerifier', 'setHostnameVerifier',
        'TrustAllCertificates', 'trustAllCertificates',
        'TrustAllCerts', 'trustAllCerts',
        'setTrustManager', 'SSLSocketFactory.getDefault',
        'NoSSLv3', 'TLSv1.0', 'TLSv1.1',
        'SSLContext.getInstance("SSL")',
        'setSecure(false)', 'allowUntrusted',
    ]

    # 网络安全配置检测
    NETWORK_SECURITY_STRINGS = [
        'network_security_config', 'NetworkSecurityConfig',
        'cleartextTrafficPermitted', 'cleartext_traffic',
        'usesCleartextTraffic',
    ]

    # 云服务域名
    CLOUD_PLATFORMS = {
        'amazonaws.com': 'AWS', 'azure.com': 'Azure', 'azureedge.net': 'Azure',
        'azurefd.net': 'Azure', 'cloudfront.net': 'AWS CloudFront',
        'aliyuncs.com': '阿里云', 'aliyundns.com': '阿里云',
        'qcloud.com': '腾讯云', 'tencentcloud.com': '腾讯云',
        'huaweicloud.com': '华为云',
        'googleapis.com': 'Google', 'firebaseio.com': 'Firebase',
        'appspot.com': 'Google App Engine', 'storage.googleapis.com': 'GCS',
        'herokuapp.com': 'Heroku', 'netlify.com': 'Netlify',
        'vercel.app': 'Vercel', 'fly.dev': 'Fly.io',
        'cloudflare.com': 'Cloudflare', 'cloudflareworkers.com': 'Cloudflare Workers',
        'digitaloceanspaces.com': 'DigitalOcean', 'linode.com': 'Linode',
        'vultr.com': 'Vultr', 'supabase.co': 'Supabase',
        'fly.io': 'Fly.io', 'render.com': 'Render',
        'railway.app': 'Railway', 'deno.dev': 'Deno Deploy',
        'workers.dev': 'Cloudflare Workers',
    }

    # API 端点路径模式
    API_PATH_PATTERNS = [
        r'/api/[\w/.-]+', r'/v\d+/[\w/.-]+', r'/rest/[\w/.-]+',
        r'/graphql[\w/.-]*', r'/ws/[\w/.-]+', r'/socket[\w/.-]*',
        r'/rpc/[\w/.-]+', r'/json[\w/.-]*', r'/soap[\w/.-]*',
        r'/oauth[\w/.-]*', r'/token[\w/.-]*', r'/auth[\w/.-]*',
        r'/login[\w/.-]*', r'/register[\w/.-]*',
        r'/upload[\w/.-]*', r'/download[\w/.-]*',
        r'/callback[\w/.-]*', r'/webhook[\w/.-]*',
        r'/notify[\w/.-]*', r'/push[\w/.-]*',
        r'/pay[\w/.-]*', r'/payment[\w/.-]*', r'/checkout[\w/.-]*',
        r'/health[\w/.-]*', r'/status[\w/.-]*', r'/metrics[\w/.-]*',
    ]

    # 端口频率映射
    COMMON_PORTS = {
        '80': 'HTTP', '443': 'HTTPS', '8080': 'HTTP-Alt', '8443': 'HTTPS-Alt',
        '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP',
        '53': 'DNS', '110': 'POP3', '143': 'IMAP', '389': 'LDAP',
        '465': 'SMTPS', '587': 'SMTP', '993': 'IMAPS', '995': 'POP3S',
        '3306': 'MySQL', '5432': 'PostgreSQL', '6379': 'Redis',
        '27017': 'MongoDB', '5672': 'AMQP', '1883': 'MQTT',
        '8883': 'MQTTS', '5222': 'XMPP', '5228': 'GCM/FCM',
        '3478': 'STUN', '5349': 'STUNS', '1935': 'RTMP',
    }

    @staticmethod
    def analyze(text, class_names=None, manifest=None):
        """多维度网络分析

        Args:
            text: DEX 字符串文本（合并后的字符串）
            class_names: 类名列表（用于 SSL Pinning 检测）
            manifest: Manifest 信息（用于网络安全配置检测）

        Returns:
            dict: 多维度网络分析结果
        """
        if not text:
            return {}

        result = {}

        # 1. 基础 URL/IP 提取（保留原功能）
        basic = NetworkAnalyzer._extract_basic(text)
        result.update(basic)

        # 2. 协议分析
        result['protocols'] = NetworkAnalyzer._analyze_protocols(text)

        # 3. SSL/TLS 检测
        result['ssl'] = NetworkAnalyzer._detect_ssl(text, class_names)

        # 4. WebSocket 检测
        result['websocket'] = NetworkAnalyzer._detect_websocket(text)

        # 5. 自定义协议/深层链接
        result['custom_schemes'] = NetworkAnalyzer._detect_custom_schemes(text)

        # 6. 网络安全配置评估
        sec_config = NetworkAnalyzer._analyze_security_config(text, manifest)
        if sec_config:
            result['security_config'] = sec_config

        # 7. API 端点模式
        result['api_endpoints'] = NetworkAnalyzer._extract_api_endpoints(text)

        # 8. 云平台分类
        result['cloud_platforms'] = NetworkAnalyzer._classify_cloud(text)

        # 9. 端口分析
        result['ports'] = NetworkAnalyzer._analyze_ports(text)

        # 10. 综合评估
        result['risk_assessment'] = NetworkAnalyzer._assess_risk(result)

        return result

    @staticmethod
    def _extract_basic(text):
        """基础 URL/IP/域名提取"""
        urls = list(set(re.findall(r'https?://[^\s"\'<>]+', text)))
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                valid_ips.append(ip)
        ips = valid_ips

        public_ips = [ip for ip in ips if not ip.startswith(
            ("10.", "172.1", "172.2", "172.3", "192.168", "127.", "0.", "169.254"))]
        private_ips = [ip for ip in ips if ip not in public_ips]

        hosts = list(set(re.findall(r'https?://([^/\s"\'<>:]+)', " ".join(urls))))
        internal_hosts = [h for h in hosts if any(
            h.endswith(s) for s in ['.local', '.internal', '.lan', 'localhost'])]

        http_urls = [u for u in urls if u.startswith('http://')]
        https_urls = [u for u in urls if u.startswith('https://')]

        hardcoded_ips = [ip for ip in public_ips if not ip.startswith('0.')]
        parameterized_urls = [u for u in urls if '?' in u]

        cloud_hosts = {}
        for h in hosts:
            for domain, provider in NetworkAnalyzer.CLOUD_PLATFORMS.items():
                if h.endswith(domain) or domain in h:
                    cloud_hosts.setdefault(provider, []).append(h)
                    break

        return {
            'total_urls': len(urls),
            'http_urls': http_urls[:20],
            'https_urls': https_urls[:20],
            'urls_sample': urls[:30],
            'hosts': hosts[:30],
            'internal_hosts': internal_hosts[:10],
            'total_ips': len(ips),
            'public_ips': public_ips[:20],
            'private_ips': private_ips[:20],
            'hardcoded_ips': hardcoded_ips[:20],
            'parameterized_urls': parameterized_urls[:20],
            'cloud_hosts': cloud_hosts,
            'insecure_http_ratio': round(len(http_urls) / max(1, len(urls)) * 100, 1),
        }

    @staticmethod
    def _analyze_protocols(text):
        """协议分析"""
        protocols_found = {}
        for proto in NetworkAnalyzer.INSECURE_PROTOCOLS:
            count = text.count(proto)
            if count > 0:
                protocols_found[proto.rstrip('://')] = count

        return {
            'insecure_protocols': protocols_found,
            'has_insecure': bool(protocols_found),
            'insecure_count': sum(protocols_found.values()),
        }

    @staticmethod
    def _detect_ssl(text, class_names=None):
        """SSL/TLS 配置检测"""
        ssl = {
            'has_ssl_pinning': False,
            'has_unsafe_ssl': False,
            'pinning_classes': [],
            'unsafe_patterns': [],
            'risk_level': '未知',
        }

        if class_names:
            for cls_name in class_names:
                for pin_class in NetworkAnalyzer.SSL_PINNING_CLASSES:
                    if pin_class.lower() in cls_name.lower():
                        ssl['pinning_classes'].append(cls_name)
                        ssl['has_ssl_pinning'] = True
                        break

        for pin_str in NetworkAnalyzer.SSL_PINNING_STRINGS:
            if pin_str.lower() in text.lower():
                ssl['pinning_classes'].append(pin_str)
                ssl['has_ssl_pinning'] = True

        for unsafe_str in NetworkAnalyzer.UNSAFE_SSL_STRINGS:
            if unsafe_str.lower() in text.lower():
                ssl['unsafe_patterns'].append(unsafe_str)
                ssl['has_unsafe_ssl'] = True

        ssl['pinning_classes'] = list(set(ssl['pinning_classes']))[:10]
        ssl['unsafe_patterns'] = list(set(ssl['unsafe_patterns']))[:10]

        if ssl['has_unsafe_ssl'] and not ssl['has_ssl_pinning']:
            ssl['risk_level'] = '高'
        elif ssl['has_unsafe_ssl'] and ssl['has_ssl_pinning']:
            ssl['risk_level'] = '中'
        elif ssl['has_ssl_pinning']:
            ssl['risk_level'] = '低'
        else:
            ssl['risk_level'] = '未知'

        return ssl

    @staticmethod
    def _detect_websocket(text):
        """WebSocket 检测"""
        ws_urls = []
        for ws in NetworkAnalyzer.WS_PROTOCOLS:
            matches = re.findall(rf'{re.escape(ws)}[^\s"\'<>]+', text)
            ws_urls.extend(matches)

        ws_classes = []
        ws_keywords = ['WebSocket', 'WebSocketClient', 'WebSocketListener',
                       'OkHttp WebSocket', 'Socket.IO', 'socket.io',
                       'SockJS', 'Netty WebSocket', 'Java-WebSocket']
        for kw in ws_keywords:
            if kw.lower() in text.lower():
                ws_classes.append(kw)

        return {
            'has_websocket': bool(ws_urls) or bool(ws_classes),
            'ws_urls': ws_urls[:10],
            'ws_classes': list(set(ws_classes))[:10],
            'ws_count': len(ws_urls),
        }

    @staticmethod
    def _detect_custom_schemes(text):
        """自定义协议/深层链接检测"""
        found = {}
        for scheme in NetworkAnalyzer.CUSTOM_SCHEMES:
            count = text.count(scheme)
            if count > 0:
                found[scheme.rstrip('://')] = count

        deep_links = re.findall(r'[a-zA-Z][a-zA-Z0-9+.-]{2,}://[^\s"\'<>]+', text)
        standard = {'http', 'https', 'ftp', 'ftps', 'ws', 'wss', 'file', 'mailto'}
        custom_deep_links = [d for d in deep_links
                             if d.split('://')[0] not in standard]

        return {
            'known_schemes': found,
            'custom_deep_links': list(set(custom_deep_links))[:20],
            'custom_scheme_count': len(custom_deep_links),
        }

    @staticmethod
    def _analyze_security_config(text, manifest=None):
        """网络安全配置评估"""
        findings = []

        if manifest:
            if manifest.get('usesCleartextTraffic'):
                findings.append('Manifest 允许明文流量 (usesCleartextTraffic=true)')

        for sec_str in NetworkAnalyzer.NETWORK_SECURITY_STRINGS:
            if sec_str.lower() in text.lower():
                findings.append(f'引用网络安全配置: {sec_str}')

        if 'cleartextTrafficPermitted' in text or 'cleartext_traffic' in text:
            findings.append('可能配置了明文流量允许')

        return {
            'findings': findings,
            'has_network_security_config': bool(findings),
            'finding_count': len(findings),
        }

    @staticmethod
    def _extract_api_endpoints(text):
        """API 端点提取"""
        endpoints = {}
        for pattern in NetworkAnalyzer.API_PATH_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                category = pattern.split('/')[1].split('[')[0]
                endpoints.setdefault(category, []).extend(matches)

        for k in endpoints:
            endpoints[k] = list(set(endpoints[k]))[:10]

        total = sum(len(v) for v in endpoints.values())
        categories = list(endpoints.keys())

        return {
            'total_endpoints': total,
            'categories': categories,
            'endpoints': endpoints,
        }

    @staticmethod
    def _classify_cloud(text):
        """云平台分类"""
        platforms = {}
        for domain, provider in NetworkAnalyzer.CLOUD_PLATFORMS.items():
            if domain.lower() in text.lower():
                platforms.setdefault(provider, 0)
                platforms[provider] += 1
        return platforms

    @staticmethod
    def _analyze_ports(text):
        """端口分析"""
        ports = list(set(re.findall(r':(\d{2,5})(?=/|\s|$|"|\')', text)))
        ports = [p for p in ports if 1 <= int(p) <= 65535]

        port_info = {}
        for p in ports:
            service = NetworkAnalyzer.COMMON_PORTS.get(p, '未知')
            port_info[p] = service

        return {
            'ports': port_info,
            'port_count': len(port_info),
            'non_standard': {p: s for p, s in port_info.items()
                             if s == '未知'},
        }

    @staticmethod
    def _assess_risk(network_result):
        """综合风险评估"""
        risks = []
        score = 0

        if network_result.get('protocols', {}).get('has_insecure'):
            risks.append('使用不安全协议 (HTTP/FTP等)')
            score += 20

        ssl = network_result.get('ssl', {})
        if ssl.get('has_unsafe_ssl') and not ssl.get('has_ssl_pinning'):
            risks.append('不安全的 SSL 配置 (信任所有证书)')
            score += 30
        elif ssl.get('has_unsafe_ssl'):
            risks.append('SSL 配置存在降级风险')
            score += 15

        hardcoded = network_result.get('hardcoded_ips', [])
        if len(hardcoded) > 5:
            risks.append(f'大量硬编码 IP 地址 ({len(hardcoded)}个)')
            score += 15
        elif hardcoded:
            risks.append(f'存在硬编码 IP 地址 ({len(hardcoded)}个)')
            score += 5

        http_ratio = network_result.get('insecure_http_ratio', 0)
        if http_ratio > 50:
            risks.append(f'高比例 HTTP 明文流量 ({http_ratio}%)')
            score += 20
        elif http_ratio > 20:
            risks.append(f'部分 HTTP 明文流量 ({http_ratio}%)')
            score += 10

        custom_count = network_result.get('custom_schemes', {}).get('custom_scheme_count', 0)
        if custom_count > 10:
            risks.append(f'大量自定义深层链接 ({custom_count}个)')
            score += 5

        non_std = network_result.get('ports', {}).get('non_standard', {})
        if non_std:
            risks.append(f'使用非标准端口: {list(non_std.keys())[:5]}')
            score += 5

        level = '高' if score >= 40 else '中' if score >= 15 else '低'

        return {
            'score': min(score, 100),
            'level': level,
            'risks': risks,
            'risk_count': len(risks),
        }