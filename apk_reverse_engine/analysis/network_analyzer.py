import re
class NetworkAnalyzer:
    @staticmethod
    def analyze(text):
        urls = list(set(re.findall(r'https?://[^\s"\'<>]+', text)))
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        public_ips = [ip for ip in ips if not ip.startswith(("10.", "172.1", "192.168", "127.", "0."))]
        hosts = list(set(re.findall(r'https?://([^/\s"\']+)', " ".join(urls))))
        return {
            "total_urls": len(urls),
            "http": [u for u in urls if u.startswith("http://")][:20],
            "https": [u for u in urls if u.startswith("https://")][:20],
            "hosts": hosts[:30], "public_ips": public_ips[:20], "all_urls": urls[:50],
        }