"""APK 签名方案检测 — V1/V2/V3/V4 签名方案全面检测与建议"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
import struct, os, zipfile

class SignatureSchemeDetector:
    """APK 签名方案检测引擎"""

    # V2/V3 签名魔数
    APK_SIG_BLOCK_MAGIC = b'APK Sig Block 42'

    @staticmethod
    def detect(apk_path):
        """
        检测 APK 的签名方案
        Args:
            apk_path: APK 文件路径
        Returns:
            dict: {v1, v2, v3, v4, details, recommendations}
        """
        result = {
            'v1': False,
            'v2': False,
            'v3': False,
            'v4': False,
            'v1_details': {},
            'v2_details': {},
            'v3_details': {},
            'v4_details': {},
            'recommendations': [],
            'security_level': '低',
        }

        if not os.path.exists(apk_path):
            return {'error': f'文件不存在: {apk_path}'}

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # V1: META-INF 中的签名文件
                names = zf.namelist()
                sig_files = [n for n in names if n.startswith('META-INF/') and
                             (n.endswith('.RSA') or n.endswith('.DSA') or n.endswith('.EC'))]
                sf_files = [n for n in names if n.startswith('META-INF/') and n.endswith('.SF')]
                mf_file = any(n == 'META-INF/MANIFEST.MF' for n in names)

                if sig_files:
                    result['v1'] = True
                    result['v1_details'] = {
                        'signature_files': sig_files,
                        'sf_files': sf_files,
                        'has_manifest': mf_file,
                        'algorithm': [],
                    }
                    # 检测签名算法
                    for sf in sig_files:
                        if 'RSA' in sf:
                            result['v1_details']['algorithm'].append('RSA')
                        elif 'DSA' in sf:
                            result['v1_details']['algorithm'].append('DSA')
                        elif 'EC' in sf:
                            result['v1_details']['algorithm'].append('ECDSA')
                    result['v1_details']['algorithm'] = list(set(result['v1_details']['algorithm']))
        except zipfile.BadZipFile:
            return {'error': '无效的 ZIP/APK 文件'}
        except Exception as e:
            logger.warning(f'V1 签名检测失败: {e}')

        # V2/V3: APK Signing Block（在 ZIP 尾部之前）
        try:
            v2_v3 = SignatureSchemeDetector._check_v2_v3(apk_path)
            result.update(v2_v3)
        except Exception as e:
            logger.warning(f'V2/V3 签名检测失败: {e}')

        # V4: .idsig 文件
        idsig_path = apk_path + '.idsig'
        if os.path.exists(idsig_path):
            result['v4'] = True
            result['v4_details'] = {
                'idsig_file': idsig_path,
                'size': os.path.getsize(idsig_path),
            }

        # 安全等级评估
        schemes = sum([result['v1'], result['v2'], result['v3'], result['v4']])
        if result['v2'] and result['v3']:
            result['security_level'] = '高'
        elif result['v2']:
            result['security_level'] = '中'
        elif result['v1']:
            result['security_level'] = '低'
        else:
            result['security_level'] = '无签名'

        # 建议
        recs = []
        if not result['v1'] and not result['v2']:
            recs.append('❌ 未检测到任何签名方案，应用将无法安装')
        if result['v1'] and not result['v2']:
            recs.append('⚠️ 仅有 V1 签名，建议增加 V2 签名以提升安全性（Android 7.0+）')
        if result['v2'] and not result['v3']:
            recs.append('ℹ️ 可考虑增加 V3 签名以支持密钥轮换（Android 9.0+）')
        if result['v1_details'].get('algorithm'):
            for alg in result['v1_details']['algorithm']:
                if alg == 'DSA':
                    recs.append(f'⚠️ 使用 DSA 签名算法，建议使用 RSA-2048 或 ECDSA')
        if not recs:
            recs.append('✅ 签名方案配置良好')
        result['recommendations'] = recs

        return result

    @staticmethod
    def _check_v2_v3(apk_path):
        """检测 V2/V3 签名块"""
        result = {'v2': False, 'v3': False, 'v2_details': {}, 'v3_details': {}}
        try:
            with open(apk_path, 'rb') as f:
                # 定位 EOCD (End of Central Directory)
                f.seek(0, 2)
                file_size = f.tell()
                if file_size < 22:
                    return result

                # 搜索 EOCD
                f.seek(max(0, file_size - 65557))
                eocd_data = f.read()
                eocd_offset = eocd_data.rfind(b'\x50\x4b\x05\x06')
                if eocd_offset < 0:
                    return result

                eocd_abs = file_size - len(eocd_data) + eocd_offset
                # 读取 CD offset
                cd_offset = struct.unpack('<I', eocd_data[eocd_offset + 16:eocd_offset + 20])[0]

                # APK Signing Block 在 CD 之前
                # 检查是否有 APK Sig Block
                if cd_offset < 24:
                    return result

                f.seek(cd_offset - 24)
                magic = f.read(16)
                if magic != SignatureSchemeDetector.APK_SIG_BLOCK_MAGIC:
                    return result

                # 读取 block size
                f.seek(cd_offset - 8)
                block_size = struct.unpack('<Q', f.read(8))[0]

                # 读取 block 内容
                block_start = cd_offset - block_size - 8
                if block_start < 0:
                    return result

                f.seek(block_start + 8)  # 跳过 size of block (first)
                # 遍历 ID-value 对
                block_end = cd_offset - 24  # 魔数之前
                pos = block_start + 8
                f.seek(pos)

                while pos < block_end:
                    if pos + 12 > block_end:
                        break
                    pair_size = struct.unpack('<Q', f.read(8))[0]
                    if pair_size < 4 or pos + 8 + pair_size > block_end:
                        break
                    pair_id = struct.unpack('<I', f.read(4))[0]
                    pair_data_size = pair_size - 4

                    if pair_id == 0x7109871a:  # V2
                        result['v2'] = True
                        result['v2_details'] = {
                            'block_id': '0x7109871a',
                            'data_size': pair_data_size,
                        }
                    elif pair_id == 0xf05368c0:  # V3
                        result['v3'] = True
                        result['v3_details'] = {
                            'block_id': '0xf05368c0',
                            'data_size': pair_data_size,
                        }
                    elif pair_id == 0x1b93ad61:  # V3.1 (rotation)
                        result['v3'] = True
                        result['v3_details'] = {
                            'block_id': '0x1b93ad61 (V3.1)',
                            'data_size': pair_data_size,
                        }

                    # 跳到下一对
                    pos += 8 + pair_size
                    f.seek(pos)

        except Exception as e:
            logger.warning(f'V2/V3 签名块检测异常: {e}')

        return result