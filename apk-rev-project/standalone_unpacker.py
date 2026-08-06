#!/usr/bin/env python3
"""APK Standalone Unpacker - 不依赖super_admin:terminal，仅通过code_runner运行
兼容第三方中转站环境，输出紧凑JSON
"""
import sys, os, json, zipfile, hashlib, struct, re, base64
from collections import Counter

# ═══════════════════════════════════════════════════════════
# 轻量 DEX 解析器（纯Python，不依赖任何外部库）
# ═══════════════════════════════════════════════════════════
class LiteDexParser:
    """极简DEX解析器 - 只提取类名和字符串"""
    def __init__(self, data):
        self.data = data

    def _u4(self, off):
        return struct.unpack_from('<I', self.data, off)[0]

    def parse_strings(self):
        """提取DEX字符串池"""
        if len(self.data) < 112:
            return []
        str_ids_size = self._u4(56)
        str_ids_off = self._u4(60)
        strings = []
        for i in range(min(str_ids_size, 50000)):
            off = self._u4(str_ids_off + i * 4)
            try:
                end = self.data.index(b'\x00', off)
                s = self.data[off:end].decode('utf-8', errors='replace')
                strings.append(s)
            except:
                strings.append('')
        return strings

    def parse_class_names(self):
        """提取类名"""
        if len(self.data) < 112:
            return []
        str_ids_size = self._u4(56)
        str_ids_off = self._u4(60)
        type_ids_size = self._u4(64)
        type_ids_off = self._u4(68)
        class_defs_size = self._u4(96)
        class_defs_off = self._u4(100)

        # 先读字符串
        strings = []
        for i in range(min(str_ids_size, 50000)):
            off = self._u4(str_ids_off + i * 4)
            try:
                end = self.data.index(b'\x00', off)
                s = self.data[off:end].decode('utf-8', errors='replace')
                strings.append(s)
            except:
                strings.append('')

        # 读类型描述符
        type_desc = []
        for i in range(type_ids_size):
            idx = self._u4(type_ids_off + i * 4)
            desc = strings[idx] if 0 <= idx < len(strings) else f'?{idx}'
            type_desc.append(desc)

        # 读类定义
        names = []
        for i in range(class_defs_size):
            off = class_defs_off + i * 32
            ci = self._u4(off)
            name = type_desc[ci] if 0 <= ci < len(type_desc) else f'?{ci}'
            names.append(name)
        return names


# ═══════════════════════════════════════════════════════════
# 轻量 Manifest 解析器
# ═══════════════════════════════════════════════════════════
class LiteManifestParser:
    """极简AXML解析器 - 提取包名/版本/权限/组件"""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.strings = []
        self.result = {}

    def _u2(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return v

    def _u4(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]
        self.pos += 4
        return v

    def _read_string(self, idx):
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return f'?{idx}'

    def parse(self):
        if len(self.data) < 8:
            return {'error': 'data too small'}
        magic = self._u4()
        size = self._u4()
        if magic != 0x00080003:
            return {'error': f'not AXML: magic=0x{magic:08x}'}

        # 解析StringChunk
        self.pos = 8
        string_chunk_type = self._u4()
        string_chunk_size = self._u4()
        if string_chunk_type != 0x001C0001:
            return {'error': f'not string chunk: 0x{string_chunk_type:08x}'}

        string_start = self.pos
        string_count = self._u4()
        _ = self._u4()  # style_count
        _ = self._u4()  # flags
        string_pool_offset = self._u4()
        style_pool_offset = self._u4()

        # 读字符串偏移表
        offsets = []
        for i in range(string_count):
            offsets.append(self._u4())

        # 读字符串
        self.strings = []
        for i in range(string_count):
            off = string_start + string_pool_offset + offsets[i]
            self.pos = off
            if self.pos + 2 > len(self.data):
                self.strings.append('')
                continue
            char_len = self._u2()
            if char_len == 0:
                self.strings.append('')
                continue
            try:
                raw = self.data[self.pos:self.pos + char_len * 2]
                s = raw.decode('utf-16le', errors='replace')
                self.strings.append(s)
                self.pos += char_len * 2
            except:
                self.strings.append('')

        # 解析标签树 - 提取关键信息
        self.pos = string_start + string_chunk_size
        pkg = ''
        vn = ''
        vc = ''
        perms = []
        activities = []
        services = []
        receivers = []
        providers = []
        sdk_min = sdk_target = 0
        stack = []
        in_manifest = False
        in_application = False

        while self.pos + 8 <= len(self.data):
            chunk_type = self._u4()
            chunk_size = self._u4()
            if chunk_size == 0:
                break
            chunk_end = self.pos + chunk_size - 8

            if chunk_type == 0x00100102:  # START_TAG
                line = self._u4()
                _ = self._u4()  # comment
                ns_idx = self._u4()
                name_idx = self._u4()
                flags = self._u4()
                attr_count = self._u4()
                _ = self._u4()  # class_attribute

                name = self._read_string(name_idx)
                if name == 'manifest':
                    in_manifest = True
                elif name == 'application':
                    in_application = True

                # 解析属性
                attrs = {}
                for a in range(attr_count):
                    if self.pos + 20 > len(self.data):
                        break
                    ans = self._u4()  # namespace
                    an = self._u4()   # name
                    avs = self._u4()  # value string
                    avt = self._u4()  # type
                    avd = self._u4()  # data
                    attr_name = self._read_string(an)
                    if avt == 0x03:  # string
                        attr_val = self._read_string(avs)
                    elif avt == 0x10:
                        attr_val = str(avd)
                    elif avt == 0x12:
                        attr_val = 'true' if avd == -1 or avd == 0xFFFFFFFF else 'false'
                    else:
                        attr_val = str(avd)
                    attrs[attr_name] = attr_val

                # 提取信息
                if in_manifest and name == 'manifest':
                    pkg = attrs.get('package', '')
                elif name == 'uses-sdk':
                    sdk_min = int(attrs.get('minSdkVersion', 0))
                    sdk_target = int(attrs.get('targetSdkVersion', 0))
                elif name == 'uses-permission':
                    perm = attrs.get('name', '')
                    if perm:
                        perms.append(perm)

                stack.append(name)

            elif chunk_type == 0x00100103:  # END_TAG
                if stack:
                    ended = stack.pop()
                    if ended == 'manifest':
                        in_manifest = False
                    elif ended == 'application':
                        in_application = False

            self.pos = chunk_end

        return {
            'package': pkg,
            'version_name': vn,
            'version_code': vc,
            'sdk': {'minSdk': sdk_min, 'targetSdk': sdk_target},
            'permissions': perms,
            'activities': activities,
            'services': services,
            'receivers': receivers,
            'providers': providers,
        }


# ═══════════════════════════════════════════════════════════
# 主解包逻辑
# ═══════════════════════════════════════════════════════════
def unpack_apk_standalone(apk_path, output_dir=None, mode='analyze'):
    """解包APK（纯Python，不依赖外部工具）
    
    Args:
        apk_path: APK文件路径
        output_dir: 可选，解压目录
        mode: 'analyze'（仅分析）| 'extract'（提取文件）| 'full'（全量）
    
    Returns:
        dict: 分析结果JSON
    """
    result = {'apk_path': apk_path, 'success': False, 'error': ''}

    if not os.path.exists(apk_path):
        result['error'] = f'APK not found: {apk_path}'
        return result

    try:
        zf = zipfile.ZipFile(apk_path, 'r')
    except Exception as e:
        result['error'] = f'Cannot open APK: {e}'
        return result

    try:
        file_list = [n for n in zf.namelist() if not n.endswith('/')]
        file_size = os.path.getsize(apk_path)

        # SHA256
        sha = hashlib.sha256()
        with open(apk_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha.update(chunk)
        sha256 = sha.hexdigest()

        # 结构统计
        dex_files = [n for n in file_list if n.endswith('.dex')]
        so_files = [n for n in file_list if n.endswith('.so')]
        img_files = [n for n in file_list if n.lower().endswith(('.png','.jpg','.jpeg','.gif','.webp','.bmp'))]
        xml_files = [n for n in file_list if n.endswith('.xml')]
        arsc_files = [n for n in file_list if n.endswith('.arsc')]
        assets_files = [n for n in file_list if n.startswith('assets/')]
        res_files = [n for n in file_list if n.startswith('res/')]
        meta_files = [n for n in file_list if n.startswith('META-INF/')]

        # ABI架构
        abis = set()
        for s in so_files:
            parts = s.split('/')
            if len(parts) >= 2 and parts[0] == 'lib':
                abis.add(parts[1])
            elif '/' in s:
                abis.add(parts[0])

        result['structure'] = {
            'total_files': len(file_list),
            'dex_count': len(dex_files),
            'so_count': len(so_files),
            'image_count': len(img_files),
            'xml_count': len(xml_files),
            'arsc_count': len(arsc_files),
            'assets_count': len(assets_files),
            'res_count': len(res_files),
            'meta_inf_count': len(meta_files),
            'size': file_size,
            'sha256': sha256,
        }
        result['abis'] = sorted(abis)

        # 分类统计大小
        cat_sizes = Counter()
        for n in file_list:
            info = zf.getinfo(n)
            if n.endswith('.dex'):
                cat_sizes['dex'] += info.file_size
            elif n.endswith('.so'):
                cat_sizes['so'] += info.file_size
            elif n.startswith('res/') or n.startswith('assets/'):
                cat_sizes['resources'] += info.file_size
            elif n.startswith('META-INF/'):
                cat_sizes['meta_inf'] += info.file_size
            else:
                cat_sizes['other'] += info.file_size
        result['size_by_category'] = {k: v for k, v in cat_sizes.most_common()}

        # ── Manifest ──
        try:
            manifest_raw = zf.read('AndroidManifest.xml')
            result['manifest'] = LiteManifestParser(manifest_raw).parse()
        except Exception as e:
            result['manifest'] = {'error': str(e)}

        # ── DEX 分析 ──
        result['dex'] = {}
        all_class_names = []
        all_strings = []
        for d in dex_files[:10]:  # 最多分析10个DEX
            try:
                data = zf.read(d)
                lp = LiteDexParser(data)
                class_names = lp.parse_class_names()
                strings = lp.parse_strings()
                all_class_names.extend(class_names)
                all_strings.extend(strings)
                result['dex'][d] = {
                    'size': len(data),
                    'classes': len(class_names),
                    'strings': len(strings),
                }
            except Exception as e:
                result['dex'][d] = {'error': str(e)}

        # 类名去重统计
        result['total_classes'] = len(set(all_class_names))
        result['total_strings'] = len(all_strings)

        # ── 签名信息 ──
        rsa_files = [n for n in meta_files if n.upper().endswith('.RSA') or n.upper().endswith('.DSA') or n.upper().endswith('.EC')]
        sf_files = [n for n in meta_files if n.upper().endswith('.SF')]
        mf_files = [n for n in meta_files if n.upper().endswith('.MF')]
        result['signature'] = {
            'has_rsa': len(rsa_files) > 0,
            'has_sf': len(sf_files) > 0,
            'has_mf': len(mf_files) > 0,
            'rsa_files': rsa_files,
            'v1_valid': len(rsa_files) > 0 and len(sf_files) > 0 and len(mf_files) > 0,
        }

        # ── 混淆检测（基于类名） ──
        obf_score = 0
        obf_reasons = []
        if all_class_names:
            simple_names = [c.split('/')[-1].rstrip(';') for c in all_class_names if c]
            single_char = sum(1 for n in simple_names if len(n) <= 2 and n.isalpha())
            total_classes = len(set(all_class_names))
            if total_classes > 0:
                ratio = single_char / total_classes
                if ratio > 0.3:
                    obf_score = min(100, obf_score + 40)
                    obf_reasons.append(f'单字符类名占比{ratio:.0%}')
                if ratio > 0.6:
                    obf_score = min(100, obf_score + 30)
                    obf_reasons.append('高度混淆')
                # a.b.c 短路径检测
                short_paths = sum(1 for c in set(all_class_names) if c.count('/') <= 2 and len(c.split('/')[-1].rstrip(';')) <= 3)
                if short_paths > 50:
                    obf_score = min(100, obf_score + 20)
                    obf_reasons.append(f'短路径类{short_paths}个')
            result['obfuscation'] = {
                'score': round(obf_score, 1),
                'level': '高' if obf_score >= 60 else '中' if obf_score >= 30 else '低',
                'reasons': obf_reasons,
                'single_char_ratio': round(ratio, 3) if total_classes > 0 else 0,
                'total_classes': total_classes,
            }

        # ── 加固检测 ──
        packers = []
        packer_signals = {
            '360': ['com.qihoo', 'qihoo', 'stub', 'jiagu'],
            '腾讯': ['com.tencent.stub', 'tinker', 'protect', 'shell'],
            '梆梆': ['bangcle', 'secneo', 'shell'],
            '爱加密': ['ijiami', 'ijm', 'apkprotect'],
            '网易': ['com.netease', 'easy'],
            '娜迦': ['naga', 'nag'],
            '通付盾': ['net.duo', 'duo'],
            '乐固': ['legu', 'tencent.legu'],
            '阿里': ['com.alibaba.wireless', 'alipay'],
        }
        combined = ' '.join(all_class_names).lower()
        for name, signals in packer_signals.items():
            for sig in signals:
                if sig.lower() in combined:
                    packers.append(name)
                    break
        result['packers'] = list(set(packers))

        # ── 安全风险统计 ──
        sec_issues = []
        manifest = result.get('manifest', {})
        if manifest.get('sdk', {}).get('minSdk', 0) < 21:
            sec_issues.append('minSdk过低(支持Android 5以下)')
        if manifest.get('sdk', {}).get('targetSdk', 0) < 28:
            sec_issues.append('targetSdk过低(未适配Android 9+)')

        # 权限风险
        dangerous_perms = ['SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'RECORD_AUDIO', 
                          'CAMERA', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION',
                          'ACCESS_COARSE_LOCATION', 'READ_CALL_LOG', 'READ_PHONE_STATE',
                          'PROCESS_OUTGOING_CALLS', 'SYSTEM_ALERT_WINDOW']
        perms = [p.split('.')[-1] for p in manifest.get('permissions', [])]
        found_dangerous = [p for p in perms if p in dangerous_perms]
        result['dangerous_permissions'] = found_dangerous

        result['security_issues'] = sec_issues
        result['permission_count'] = len(perms)

        # ── 导出关键字符串（安全相关） ──
        url_pattern = re.compile(r'https?://[^\s\'\"<>]+')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        key_pattern = re.compile(r'(?:api_?key|api_?secret|app_?secret|secret|token|password|private_?key)', re.I)

        urls = set()
        ips = set()
        emails = set()
        keys = set()
        for s in all_strings:
            for m in url_pattern.finditer(s):
                urls.add(m.group())
            for m in ip_pattern.finditer(s):
                ips.add(m.group())
            for m in email_pattern.finditer(s):
                emails.add(m.group())
            if key_pattern.search(s):
                keys.add(s[:100])

        result['findings'] = {
            'urls': sorted(urls)[:50],
            'ips': sorted(ips)[:30],
            'emails': sorted(emails)[:20],
            'potential_keys': sorted(keys)[:20],
        }

        # ── 解压（可选） ──
        if output_dir and mode in ('extract', 'full'):
            os.makedirs(output_dir, exist_ok=True)
            extracted = 0
            for name in file_list:
                try:
                    dest = os.path.join(output_dir, name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with zf.open(name) as src, open(dest, 'wb') as dst:
                        while True:
                            chunk = src.read(1048576)
                            if not chunk:
                                break
                            dst.write(chunk)
                    if name.endswith('.so'):
                        os.chmod(dest, os.stat(dest).st_mode | 0o111)
                    extracted += 1
                except:
                    pass
            result['extracted'] = extracted
            result['output_dir'] = output_dir

        result['success'] = True

    except Exception as e:
        result['error'] = str(e)
        import traceback
        result['traceback'] = traceback.format_exc()
    finally:
        zf.close()

    return result


# ═══════════════════════════════════════════════════════════
# 命令行入口
# ═══════════════════════════════════════════════════════════
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Standalone APK Unpacker')
    parser.add_argument('apk', help='APK file path')
    parser.add_argument('-o', '--output', help='Output directory (optional)')
    parser.add_argument('-m', '--mode', default='analyze', choices=['analyze', 'extract', 'full'],
                        help='Mode: analyze/extract/full')
    parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    args = parser.parse_args()

    result = unpack_apk_standalone(args.apk, args.output, args.mode)
    print(json.dumps(result, ensure_ascii=False, indent=None if args.compact else 2))