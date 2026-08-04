import hashlib
class SignVerifier:
    """APK签名验证器"""
    @staticmethod
    def verify_v1(apk_zip):
        try:
            certs = [n for n in apk_zip.namelist() if n.startswith('META-INF/') and n.endswith('.RSA')]
            if not certs: return {'v1': False, 'reason': 'no RSA file'}
            return {'v1': True, 'cert_file': certs[0]}
        except: return {'v1': False, 'reason': 'error reading'}
    @staticmethod
    def verify_v2(apk_path):
        try:
            with open(apk_path, 'rb') as f:
                data = f.read()
                # APK Signing Block starts at -6 offset
                if len(data) < 12: return {'v2': False}
                magic = data[-8:]
                if magic == b'APK Sig Block 42':
                    return {'v2': True, 'method': 'APK Signature Scheme v2'}
                # Check for v3 block
                if data[-16:-8] == b'APK Sig Block 42':
                    return {'v2': True, 'method': 'APK Signature Scheme v3'}
            return {'v2': False}
        except: return {'v2': False, 'error': 'read error'}
