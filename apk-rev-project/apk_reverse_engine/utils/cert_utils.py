import hashlib, struct

class CertUtils:
    """X.509证书解析工具"""

    @staticmethod
    def _parse_der_length(data, pos):
        """解析DER长度"""
        if pos >= len(data): return 0, 0
        first = data[pos]
        if first < 0x80:
            return first, 1
        length_bytes = first & 0x7f
        if length_bytes == 0:
            return 0, 1
        length = 0
        for i in range(length_bytes):
            length = (length << 8) | data[pos + 1 + i]
        return length, 1 + length_bytes

    @staticmethod
    def _parse_der_integer(data, pos):
        """解析DER整数"""
        if data[pos] != 0x02:
            return None, 0
        length, len_len = CertUtils._parse_der_length(data, pos + 1)
        total = 1 + len_len + length
        value = int.from_bytes(data[pos + 1 + len_len:pos + 1 + len_len + length], 'big')
        return value, total

    @staticmethod
    def _parse_der_oid(data, pos):
        """解析DER OID"""
        if data[pos] != 0x06:
            return '', 0
        length, len_len = CertUtils._parse_der_length(data, pos + 1)
        oid_bytes = data[pos + 1 + len_len:pos + 1 + len_len + length]
        total = 1 + len_len + length
        # Decode OID
        oid_parts = []
        if oid_bytes:
            first = oid_bytes[0]
            oid_parts.append(str(first // 40))
            oid_parts.append(str(first % 40))
            value = 0
            for b in oid_bytes[1:]:
                if b & 0x80:
                    value = (value << 7) | (b & 0x7f)
                else:
                    value = (value << 7) | b
                    oid_parts.append(str(value))
                    value = 0
        return '.'.join(oid_parts), total

    @staticmethod
    def _read_der_string(data, pos):
        """读取DER字符串(IA5String/UTF8String/PrintableString)"""
        tag = data[pos]
        if tag not in (0x0c, 0x13, 0x16, 0x1e):  # UTF8, Printable, IA5, Visible
            return None, 0
        length, len_len = CertUtils._parse_der_length(data, pos + 1)
        s = data[pos + 1 + len_len:pos + 1 + len_len + length].decode('utf-8', errors='replace')
        return s, 1 + len_len + length

    @staticmethod
    def _parse_rdn(data, pos):
        """解析RDN (Relative Distinguished Name)"""
        if data[pos] != 0x31:  # SET
            return {}, 0
        length, len_len = CertUtils._parse_der_length(data, pos + 1)
        end = pos + 1 + len_len + length
        pos2 = pos + 1 + len_len
        result = {}
        while pos2 < end:
            if data[pos2] != 0x30:  # SEQUENCE
                pos2 += 1
                continue
            seq_len, seq_len_len = CertUtils._parse_der_length(data, pos2 + 1)
            seq_end = pos2 + 1 + seq_len_len + seq_len
            pos3 = pos2 + 1 + seq_len_len
            oid, _ = CertUtils._parse_der_oid(data, pos3)
            if oid:
                pos3 += _
                val, _ = CertUtils._read_der_string(data, pos3)
                if val:
                    oid_name = {
                        '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L',
                        '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
                        '1.2.840.113549.1.9.1': 'emailAddress',
                    }.get(oid, oid)
                    result[oid_name] = val
            pos2 = seq_end
        return result, pos2 - pos

    @staticmethod
    def parse_certificate(data):
        """解析X.509 DER证书 (basic)"""
        try:
            if data[0] != 0x30:  # SEQUENCE
                return {'error': '非 DER SEQUENCE'}
            length, len_len = CertUtils._parse_der_length(data, 1)
            pos = 1 + len_len

            # TBSCertificate
            if data[pos] != 0x30:
                return {'error': '缺少 TBSCertificate'}
            tbs_len, tbs_len_len = CertUtils._parse_der_length(data, pos + 1)
            tbs_start = pos + 1 + tbs_len_len
            tbs_end = tbs_start + tbs_len

            # Skip version (optional, context-specific [0])
            pos2 = tbs_start
            if data[pos2] == 0xa0:
                v_len, v_len_len = CertUtils._parse_der_length(data, pos2 + 1)
                pos2 = pos2 + 1 + v_len_len + v_len

            # Serial Number
            serial, ser_len = CertUtils._parse_der_integer(data, pos2)
            if serial is not None:
                pos2 += ser_len

            # Signature Algorithm
            if data[pos2] == 0x30:
                alg_len, alg_len_len = CertUtils._parse_der_length(data, pos2 + 1)
                pos2 = pos2 + 1 + alg_len_len + alg_len

            # Issuer
            if data[pos2] == 0x30:
                iss_len, iss_len_len = CertUtils._parse_der_length(data, pos2 + 1)
                iss_end = pos2 + 1 + iss_len_len + iss_len
                pos3 = pos2 + 1 + iss_len_len
                issuer = {}
                while pos3 < iss_end:
                    rdn, rdn_len = CertUtils._parse_rdn(data, pos3)
                    issuer.update(rdn)
                    pos3 += rdn_len if rdn_len > 0 else 1
                pos2 = iss_end

            # Validity (UTCTime + UTCTime or GeneralizedTime)
            validity = {}
            if pos2 < tbs_end and data[pos2] == 0x30:
                val_len, val_len_len = CertUtils._parse_der_length(data, pos2 + 1)
                val_end = pos2 + 1 + val_len_len + val_len
                pos3 = pos2 + 1 + val_len_len
                for label in ['not_before', 'not_after']:
                    if pos3 < val_end and data[pos3] in (0x17, 0x18):  # UTCTime, GeneralizedTime
                        t_len, t_len_len = CertUtils._parse_der_length(data, pos3 + 1)
                        t_str = data[pos3 + 1 + t_len_len:pos3 + 1 + t_len_len + t_len].decode('ascii', errors='replace')
                        validity[label] = t_str
                        pos3 += 1 + t_len_len + t_len
                pos2 = val_end

            # Subject
            if pos2 < tbs_end and data[pos2] == 0x30:
                sub_len, sub_len_len = CertUtils._parse_der_length(data, pos2 + 1)
                sub_end = pos2 + 1 + sub_len_len + sub_len
                pos3 = pos2 + 1 + sub_len_len
                subject = {}
                while pos3 < sub_end:
                    rdn, rdn_len = CertUtils._parse_rdn(data, pos3)
                    subject.update(rdn)
                    pos3 += rdn_len if rdn_len > 0 else 1

            hashes = {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(),
                'size': len(data),
            }

            result = {**hashes}
            if serial is not None:
                result['serial'] = str(serial)
            if 'issuer' in locals():
                result['issuer'] = issuer
            if 'subject' in locals():
                result['subject'] = subject
            if validity:
                result['validity'] = validity

            return result
        except Exception as e:
            return {'error': str(e), 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}

    @staticmethod
    def get_cert_info(cert_data):
        """兼容旧接口"""
        return CertUtils.parse_certificate(cert_data)

    @staticmethod
    def format_issuer_subject(dn_dict):
        """格式化DN为可读字符串"""
        if not dn_dict:
            return ''
        order = ['CN', 'O', 'OU', 'L', 'ST', 'C', 'emailAddress']
        parts = []
        for k in order:
            if k in dn_dict:
                parts.append(f'{k}={dn_dict[k]}')
        for k, v in dn_dict.items():
            if k not in order:
                parts.append(f'{k}={v}')
        return ', '.join(parts)
