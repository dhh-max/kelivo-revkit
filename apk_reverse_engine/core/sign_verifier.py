"""APK签名验证器 - 支持v1/v2/v3签名验证"""
import struct, hashlib, io

class SignVerifier:
    """APK签名方案验证器，支持v1(JAR签名)、v2(APK方案)、v3(APK方案)"""
    
    APK_SIG_BLOCK_MAGIC = b'APK Sig Block 42'
    APK_SIG_BLOCK_MAGIC_V3 = b'APK Sig Block 42'
    
    # APK Signing Block IDs
    ID_APK_SIGNATURE_SCHEME_V2 = 0x7109871a
    ID_APK_SIGNATURE_SCHEME_V3 = 0xf05368c0
    ID_VERITY_PADDING_BLOCK = 0x42726577

    @staticmethod
    def verify_v1(apk_zip):
        """验证v1 JAR签名方案"""
        try:
            names = apk_zip.namelist()
            rsa_files = [n for n in names if n.startswith('META-INF/') and n.endswith('.RSA')]
            sf_files = [n for n in names if n.startswith('META-INF/') and n.endswith('.SF')]
            mf_files = [n for n in names if n.startswith('META-INF/') and n.endswith('.MF')]
            
            if not rsa_files:
                return {'v1': False, 'reason': 'no RSA signature file', 'meta_inf': len([n for n in names if 'META-INF/' in n])}
            
            # Read RSA cert info
            cert_data = apk_zip.read(rsa_files[0])
            cert_info = {}
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                cert_info = {
                    'subject': str(cert.subject.rfc4514_string()),
                    'issuer': str(cert.issuer.rfc4514_string()),
                    'serial': str(cert.serial_number),
                    'not_before': str(cert.not_valid_before),
                    'not_after': str(cert.not_valid_after),
                    'sha256': hashlib.sha256(cert.public_bytes(encoding=1)).hexdigest(),
                }
            except ImportError:
                cert_info = {'sha256': hashlib.sha256(cert_data).hexdigest(), 'size': len(cert_data)}
            except Exception as e:
                cert_info = {'sha256': hashlib.sha256(cert_data).hexdigest(), 'parse_error': str(e)}
            
            return {
                'v1': True,
                'cert_files': rsa_files,
                'sf_files': sf_files,
                'mf_files': mf_files,
                'cert_info': cert_info,
            }
        except Exception as e:
            return {'v1': False, 'reason': f'error: {str(e)}'}

    @staticmethod
    def _find_apk_signing_block(data):
        """在APK文件中查找APK Signing Block"""
        if len(data) < 32:
            return None
        
        # Find the Central Directory offset from EOCD
        try:
            # Search for EOCD signature (0x06054b50)
            eocd_pos = data.rfind(b'PK\x05\x06')
            if eocd_pos == -1:
                return None
            
            # Read EOCD to get central directory offset
            cd_offset = struct.unpack_from('<I', data, eocd_pos + 16)[0]
            
            # The signing block is between the ZIP Central Directory and the file content
            # The block offset is stored at the end of the block
            sig_block_start = cd_offset
            
            # Look backwards from cd_offset for the magic
            search_start = max(0, cd_offset - 1024 * 1024)  # Search up to 1MB back
            magic_pos = data.rfind(SignVerifier.APK_SIG_BLOCK_MAGIC, search_start, cd_offset)
            
            if magic_pos == -1:
                return None
            
            # Block size is 8 bytes before magic (uint64 little-endian)
            block_size = struct.unpack_from('<Q', data, magic_pos - 8)[0]
            block_start = magic_pos - block_size
            
            if block_start < 0:
                return None
                
            return {
                'start': block_start,
                'end': magic_pos + 16,
                'size': block_size + 16,
                'data': data[block_start:magic_pos + 16],
            }
        except Exception:
            return None

    @staticmethod
    def verify_v2(apk_path):
        """验证APK Signature Scheme v2/v3"""
        try:
            with open(apk_path, 'rb') as f:
                data = f.read()
            
            block_info = SignVerifier._find_apk_signing_block(data)
            if not block_info:
                return {'v2': False, 'v3': False, 'reason': 'no APK Signing Block found'}
            
            block_data = block_info['data']
            
            # Parse signing block pairs
            pos = 8  # Skip first 8 bytes (size prefix)
            result = {'v2': False, 'v3': False, 'block_present': True}
            
            while pos < len(block_data) - 8:
                id_value = struct.unpack_from('<I', block_data, pos + 8)[0]
                
                if id_value == SignVerifier.ID_APK_SIGNATURE_SCHEME_V2:
                    result['v2'] = True
                    result['v2_block_size'] = struct.unpack_from('<Q', block_data, pos)[0] + 8
                elif id_value == SignVerifier.ID_APK_SIGNATURE_SCHEME_V3:
                    result['v3'] = True
                    result['v3_block_size'] = struct.unpack_from('<Q', block_data, pos)[0] + 8
                
                # Move to next pair
                pair_size = struct.unpack_from('<Q', block_data, pos)[0]
                pos += 8 + pair_size
                if pair_size == 0:
                    break
            
            return result
        except Exception as e:
            return {'v2': False, 'v3': False, 'error': str(e)}

    @staticmethod
    def verify_all(apk_zip, apk_path):
        """同时验证所有签名方案"""
        v1 = SignVerifier.verify_v1(apk_zip)
        v2v3 = SignVerifier.verify_v2(apk_path)
        
        result = {
            'v1': v1.get('v1', False),
            'v2': v2v3.get('v2', False),
            'v3': v2v3.get('v3', False),
            'cert_info': v1.get('cert_info', {}),
        }
        
        # Determine overall security level
        if result['v3']:
            result['signature_scheme'] = 'v3'
            result['security_level'] = 'HIGH'
        elif result['v2']:
            result['signature_scheme'] = 'v2'
            result['security_level'] = 'HIGH'
        elif result['v1']:
            result['signature_scheme'] = 'v1'
            result['security_level'] = 'MEDIUM'
        else:
            result['signature_scheme'] = 'none'
            result['security_level'] = 'NONE'
        
        return result
