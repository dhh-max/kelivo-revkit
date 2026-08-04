import hashlib
class CertUtils:
    @staticmethod
    def get_cert_info(cert_data):
        try:
            return {
                'md5': hashlib.md5(cert_data).hexdigest(),
                'sha1': hashlib.sha1(cert_data).hexdigest(),
                'sha256': hashlib.sha256(cert_data).hexdigest(),
                'size': len(cert_data)
            }
        except: return {'error': 'failed to parse cert'}
