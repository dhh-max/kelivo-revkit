"""证书深度分析器 - 增强版证书/签名分析与异常检测"""

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

from datetime import datetime
class CertDeepAnalyzer:
    """深度证书分析引擎：分析签名证书安全性、异常检测、兼容性评估"""

    # 已知的测试/调试证书特征
    TEST_CERT_SUBJECTS = [
        'CN=Android Debug', 'CN=Android', 'O=Android', 'CN=Test',
        'CN=Debug', 'OU=Test', 'O=Debug',
    ]

    # 知名CA签发者关键词
    KNOWN_CAS = [
        'Google', 'Apple', 'Symantec', 'VeriSign', 'GeoTrust', 'Comodo',
        'DigiCert', 'GlobalSign', 'Let\'s Encrypt', 'Entrust', 'GoDaddy',
        'Thawte', 'RapidSSL', 'AlphaSSL', 'Sectigo', 'Certum', 'TrustCor',
        'Amazon', 'Microsoft', 'SSL.com', 'Network Solutions',
    ]

    @staticmethod
    def analyze(cert_info):
        """深度分析证书安全性"""
        if not cert_info or 'error' in cert_info:
            return {'error': '无有效证书信息', 'risk_score': 100, 'issues': ['无法解析证书']}

        issues = []
        findings = []
        risk_score = 0

        # 1. 签发者分析
        issuer = cert_info.get('issuer', {})
        subject = cert_info.get('subject', {})

        issuer_str = ', '.join(f'{k}={v}' for k, v in sorted(issuer.items()))
        subject_str = ', '.join(f'{k}={v}' for k, v in sorted(subject.items()))

        # 1.1 检测调试证书
        is_debug = False
        for test_subj in CertDeepAnalyzer.TEST_CERT_SUBJECTS:
            if test_subj in subject_str or test_subj in issuer_str:
                is_debug = True
                break

        if is_debug:
            issues.append('❌ 使用调试证书签名 (Android Debug)')
            risk_score += 30
        else:
            findings.append('✅ 非调试证书')

        # 1.2 检测知名CA vs 自签名
        is_known_ca = any(ca in issuer_str for ca in CertDeepAnalyzer.KNOWN_CAS)
        if is_known_ca:
            findings.append(f'✅ 由知名CA签发')
        else:
            # 检查是否是自签名
            if issuer_str and subject_str and issuer_str == subject_str:
                issues.append('⚠️ 自签名证书')
                risk_score += 15
            else:
                issues.append('⚠️ 未知CA签发，需验证证书链')
                risk_score += 10

        # 2. 有效期检查
        validity = cert_info.get('validity', {})
        not_before = validity.get('not_before', '')
        not_after = validity.get('not_after', '')

        if not_before and not_after:
            try:
                # 尝试多种日期格式
                for fmt in ['%y%m%d%H%M%SZ', '%Y%m%d%H%M%SZ', '%Y-%m-%d %H:%M:%S', '%Y%m%d%H%M%S']:
                    try:
                        nb = datetime.strptime(not_before, fmt)
                        na = datetime.strptime(not_after, fmt)
                        break
                    except Exception:
                        continue
                else:
                    nb = na = None

                if nb and na:
                    now = datetime.now()
                    remaining = (na - now).days

                    if remaining < 0:
                        issues.append(f'❌ 证书已过期 (过期 {abs(remaining)} 天)')
                        risk_score += 25
                    elif remaining < 30:
                        issues.append(f'⚠️ 证书即将过期 (剩余 {remaining} 天)')
                        risk_score += 10
                    elif remaining < 365:
                        findings.append(f'✅ 证书有效，剩余 {remaining} 天')
                    else:
                        findings.append(f'✅ 证书有效期充足 (>1年)')

                    # 有效期总长度
                    total_days = (na - nb).days
                    if total_days > 365 * 5:  # 超过5年
                        issues.append(f'⚠️ 证书有效期过长 ({total_days} 天)，建议不超过3年')
                        risk_score += 5
            except Exception as e:
                logger.debug("apk_reverse_engine/analysis/cert_deep_analyzer.py:103 suppressed: %s", e)

        # 3. 哈希算法强度
        sha256 = cert_info.get('sha256', '')
        sha1 = cert_info.get('sha1', '')
        md5 = cert_info.get('md5', '')

        if md5:
            findings.append(f'MD5: {md5[:16]}...')
        if sha1:
            findings.append(f'SHA1: {sha1[:16]}...')
        if sha256:
            findings.append(f'SHA256: {sha256[:16]}...')

        # 4. 序列号检查
        serial = cert_info.get('serial', '')
        if serial:
            try:
                serial_int = int(serial)
                if serial_int < 16:  # 序列号太短
                    issues.append('⚠️ 证书序列号过短，可能是自签名')
                    risk_score += 5
            except Exception as e:
                logger.debug("apk_reverse_engine/analysis/cert_deep_analyzer.py:126 suppressed: %s", e)

        # 5. 签名方案兼容性
        findings.append('ℹ️ 建议使用v2/v3签名方案以确保Android 7.0+兼容性')

        # 6. 综合评估
        risk_level = '安全' if risk_score <= 10 else '低风险' if risk_score <= 20 else '中风险' if risk_score <= 40 else '高风险'

        return {
            'issuer': issuer,
            'subject': subject,
            'issuer_str': issuer_str,
            'subject_str': subject_str,
            'serial': serial,
            'validity': validity,
            'hashes': {'md5': md5, 'sha1': sha1, 'sha256': sha256},
            'is_debug': is_debug,
            'is_known_ca': is_known_ca,
            'issues': issues,
            'findings': findings,
            'risk_score': risk_score,
            'risk_level': risk_level,
        }

    @staticmethod
    def format_cert_summary(cert_analysis):
        """格式化证书分析结果为可读摘要"""
        if not cert_analysis or 'error' in cert_analysis:
            return '无法分析证书'

        lines = []
        lines.append(f"签发者: {cert_analysis.get('issuer_str', '?')}")
        lines.append(f"主体: {cert_analysis.get('subject_str', '?')}")
        lines.append(f"序列号: {cert_analysis.get('serial', '?')}")

        validity = cert_analysis.get('validity', {})
        if validity:
            lines.append(f"有效期: {validity.get('not_before', '?')} → {validity.get('not_after', '?')}")

        lines.append(f"风险评分: {cert_analysis.get('risk_score', 0)}/100 ({cert_analysis.get('risk_level', '?')})")

        for issue in cert_analysis.get('issues', []):
            lines.append(f"  {issue}")
        for finding in cert_analysis.get('findings', []):
            lines.append(f"  {finding}")

        return '\n'.join(lines)