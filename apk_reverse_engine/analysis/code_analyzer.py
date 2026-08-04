import re
class CodeAnalyzer:
    @staticmethod
    def find_urls(text):
        return re.findall(r'https?://[^\s"\'<>]+', text)
    @staticmethod
    def find_ips(text):
        return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    @staticmethod
    def find_emails(text):
        return re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)
    @staticmethod
    def find_api_keys(text):
        patterns = [
            r'(?i)(?:api[_-]?key|apikey|secret|token|password|passwd)\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?i)AIza[0-9A-Za-z_-]{35}',
            r'(?i)sk-[0-9a-zA-Z]{32,}',
            r'(?i)ghp_[0-9a-zA-Z]{36}',
            r'(?i)AKIA[0-9A-Z]{16}',
        ]
        keys = []
        for p in patterns:
            for m in re.finditer(p, text):
                keys.append(m.group(1) if m.lastindex else m.group(0))
        return list(set(keys))
    @staticmethod
    def find_class_refs(text):
        return list(set(re.findall(r'L[\w/$]+;', text)))