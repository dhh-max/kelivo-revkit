import re

class CodeAnalyzer:
    API_KEY_PATTERNS = [
        (r'(?i)(?:api[_-]?key|apikey|secret|token|password|passwd|bearer|auth|access_key|private_key)\s*[:=]\s*[\"'\'']([^\"'\'']+)[\"'\'']', 'Credentials'),
        (r'(?i)AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
        (r'(?i)sk-[0-9a-zA-Z]{32,}', 'OpenAI API Key'),
        (r'(?i)ghp_[0-9a-zA-Z]{36}', 'GitHub Token'),
        (r'(?i)AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'Private Key'),
        (r'-----BEGIN CERTIFICATE-----', 'Certificate'),
    ]

    @staticmethod
    def find_urls(text): return list(set(re.findall(r'https?://[^\s"\'<>]+', text)))

    @staticmethod
    def find_ips(text): return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))

    @staticmethod
    def find_emails(text): return list(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)))

    @staticmethod
    def find_api_keys(text):
        keys = []
        for pat, _cat in CodeAnalyzer.API_KEY_PATTERNS:
            for m in re.finditer(pat, text):
                keys.append(m.group(1) if m.lastindex else m.group(0))
        return list(set(keys))

    @staticmethod
    def find_class_refs(text): return list(set(re.findall(r'L[\w/]+;', text)))

    @staticmethod
    def find_domains(text):
        urls = CodeAnalyzer.find_urls(text)
        domains = []
        for u in urls:
            m = re.search(r'https?://([^/\s"\'<>:]+)', u)
            if m: domains.append(m.group(1))
        return list(set(domains))

    @staticmethod
    def analyze_all(text):
        return {
            'urls': CodeAnalyzer.find_urls(text),
            'ips': CodeAnalyzer.find_ips(text),
            'emails': CodeAnalyzer.find_emails(text),
            'api_keys': CodeAnalyzer.find_api_keys(text),
            'class_refs': CodeAnalyzer.find_class_refs(text),
            'domains': CodeAnalyzer.find_domains(text),
        }
