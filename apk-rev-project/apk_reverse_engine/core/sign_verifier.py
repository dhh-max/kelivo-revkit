"""APK签名验证器 - 支持v1/v2/v3签名验证"""

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

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
            
            logger.debug(f"e")
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
        except Exception as e:
            from apk_reverse_engine.utils.logutil import get_logger
            get_logger(__name__).warning("sign v1 block parse failed: %s", e)
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
    def _find_signing_block_pairs(data):
        """直接解析 APK Signing Block，返回 {scheme_id: bytes} 字典。

        移植自 RikkaMinis/scripts/apk_cert_sha256.py —— 只依赖 Python 标准库，
        无需 apksigner/keytool。定位 EOCD → 中央目录前的 Signing Block →
        逐对解析 scheme_id 与 payload。
        """
        eocd = data.rfind(b'PK\x05\x06')
        if eocd < 0:
            raise ValueError('not a zip/apk: no End Of Central Directory record')
        cd_offset = struct.unpack_from('<I', data, eocd + 16)[0]

        if data[cd_offset - 16:cd_offset] != SignVerifier.APK_SIG_BLOCK_MAGIC:
            raise ValueError('no APK Signing Block (unsigned, or v1/JAR-signed only)')

        footer_size = struct.unpack_from('<Q', data, cd_offset - 24)[0]
        block_start = cd_offset - footer_size - 8
        block_size = struct.unpack_from('<Q', data, block_start)[0]

        pairs = {}
        pos = block_start + 8
        end = block_start + 8 + block_size - 24  # stop before trailing size+magic
        while pos < end:
            pair_len = struct.unpack_from('<Q', data, pos)[0]
            pair_id = struct.unpack_from('<I', data, pos + 8)[0]
            pairs[pair_id] = data[pos + 12:pos + 8 + pair_len]
            pos += 8 + pair_len
        return pairs

    @staticmethod
    def _first_certificate(block):
        """从 v2/v3 block 中提取第一个签名者的叶子证书（DER）。

        布局（全部为 u32 长度前缀序列）：
            signers -> signer -> signed_data -> [digests][certificates]...
        """
        signer_len = struct.unpack_from('<I', block, 4)[0]  # 跳过外层 signers 长度
        signer = block[8:8 + signer_len]

        signed_data_len = struct.unpack_from('<I', signer, 0)[0]
        signed_data = signer[4:4 + signed_data_len]

        digests_len = struct.unpack_from('<I', signed_data, 0)[0]
        certs_off = 4 + digests_len  # 跳过 digests 序列
        cert_len = struct.unpack_from('<I', signed_data, certs_off + 4)[0]
        cert = signed_data[certs_off + 8:certs_off + 8 + cert_len]

        if not cert.startswith(b'\x30\x82'):
            raise ValueError('parsed bytes are not a DER certificate — layout changed?')
        return cert

    @staticmethod
    def extract_cert_sha256(apk_path, raw=False):
        """从 APK v2/v3 Signing Block 直接提取签名证书 SHA-256。

        移植自 RikkaMinis/scripts/apk_cert_sha256.py，纯标准库实现。
        返回第一个签名者叶子证书的 SHA-256（小写十六进制）。
        若 raw=True 则返回 DER 证书字节本身。

        >>> sha = SignVerifier.extract_cert_sha256('app.apk')
        >>> print(sha)  # e.g. fc0c40...b16113
        """
        with open(apk_path, 'rb') as f:
            data = f.read()

        pairs = SignVerifier._find_signing_block_pairs(data)
        for scheme_id in (0x7109871a, 0xf05368c0):  # v2, v3
            if scheme_id in pairs:
                cert = SignVerifier._first_certificate(pairs[scheme_id])
                if raw:
                    return cert
                return hashlib.sha256(cert).hexdigest()

        raise ValueError('APK has a signing block but no v2/v3 signature')

    @staticmethod
    def verify_v2(apk_path):
        """验证APK Signature Scheme v2/v3"""
        try:
            with open(apk_path, 'rb') as f:
                data = f.read()

            try:
                pairs = SignVerifier._find_signing_block_pairs(data)
            except ValueError as e:
                return {'v2': False, 'v3': False, 'reason': str(e)}

            result = {
                'v2': SignVerifier.ID_APK_SIGNATURE_SCHEME_V2 in pairs,
                'v3': SignVerifier.ID_APK_SIGNATURE_SCHEME_V3 in pairs,
                'block_present': True,
            }
            for sid, key in ((SignVerifier.ID_APK_SIGNATURE_SCHEME_V2, 'v2'),
                             (SignVerifier.ID_APK_SIGNATURE_SCHEME_V3, 'v3')):
                if sid in pairs:
                    result[f'{key}_block_size'] = len(pairs[sid]) + 8

            # 尝试提取签名证书 SHA-256（直接解析 Signing Block）
            try:
                for sid in (SignVerifier.ID_APK_SIGNATURE_SCHEME_V2,
                            SignVerifier.ID_APK_SIGNATURE_SCHEME_V3):
                    if sid in pairs:
                        cert = SignVerifier._first_certificate(pairs[sid])
                        result['cert_sha256'] = hashlib.sha256(cert).hexdigest()
                        result['cert_der_len'] = len(cert)
                        break
            except ValueError as e:
                logger.debug(f"e")

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

        # 合并 v2/v3 提取的证书 SHA-256（优先于 v1 JAR 签名）
        if v2v3.get('cert_sha256'):
            result['cert_sha256'] = v2v3['cert_sha256']
            result['cert_der_len'] = v2v3.get('cert_der_len')
        elif v1.get('cert_info', {}).get('sha256'):
            result['cert_sha256'] = v1['cert_info']['sha256']
        
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
