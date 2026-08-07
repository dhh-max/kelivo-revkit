"""Lite 解包器 - 纯 Python 标准库解包 APK 提取关键信息
"""
import os, json, zipfile, hashlib, struct, re
from collections import Counter
from .dex_parser import LiteDexParser


def _fmt_size(s):
    for u in ('B','KB','MB','GB'):
        if s < 1024: return f"{s:.1f}{u}"
        s /= 1024
    return f"{s:.1f}TB"


def _compact_result(result):
    if not isinstance(result, dict):
        return result
    keep = {}
    for k in ('apk_path', 'success', 'error'):
        if k in result:
            keep[k] = result[k]
    st = result.get('structure') or {}
    keep['structure'] = {k: st.get(k, 0) for k in ('size','total_files','dex_count','so_count','image_count','xml_count','arsc_count','assets_count','res_count','meta_inf_count')}
    m = result.get('manifest') or {}
    keep['manifest'] = {'package': m.get('package',''), 'sdk': {'minSdk': m.get('sdk',{}).get('minSdk',0), 'targetSdk': m.get('sdk',{}).get('targetSdk',0)}}
    if result.get('abis'):
        keep['abis'] = result['abis']
    keep['packer_count'] = len(result.get('packers', []) or [])
    keep['packers'] = result.get('packers', [])
    keep['dangerous_permission_count'] = len(result.get('dangerous_permissions', []) or [])
    keep['dangerous_permissions'] = result.get('dangerous_permissions', [])
    keep['total_classes'] = result.get('total_classes', 0)
    keep['permission_count'] = result.get('permission_count', 0)
    if result.get('obfuscation'):
        keep['obfuscation'] = result['obfuscation']
    if result.get('security_issues'):
        keep['security_issues'] = result['security_issues']
        keep['security_issue_count'] = len(result['security_issues'])
    if result.get('size_by_category'):
        keep['size_by_category'] = result['size_by_category']
    return keep

PACKER_SIGNALS = {
    '360': ['com.qihoo', 'qihoo', 'stub', 'jiagu'],
    '腾讯': ['com.tencent.stub', 'tinker', 'protect', 'shell'],
    '棂棂': ['bangcle', 'secneo', 'shell'],
    '爱加密': ['ijiami', 'ijm', 'apkprotect'],
    '网易': ['com.netease', 'easy'],
    '娜贾': ['naga', 'nag'],
    '通付盾': ['net.duo', 'duo'],
    '乐固': ['legu', 'tencent.legu'],
    '阿里': ['com.alibaba.wireless', 'alipay'],
}
DANGEROUS_PERMS = ['SEND_SMS','RECEIVE_SMS','READ_SMS','RECORD_AUDIO','CAMERA','READ_CONTACTS','ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','READ_CALL_LOG','READ_PHONE_STATE','PROCESS_OUTGOING_CALLS','SYSTEM_ALERT_WINDOW']

class LiteManifestParser:
    """极简AXML解析器 - 提取包名/版本/权限/组件"""
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.strings = []
        self.result = {}

    def _safe(self, n):
        if self.pos + n > len(self.data):
            raise IndexError(f'LiteManifestParser: pos={self.pos}+{n} > len={len(self.data)}')
    def _u2(self):
        self._safe(2)
        v = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return v
    def _u1(self):
        self._safe(1)
        v = self.data[self.pos]
        self.pos += 1
        return v
    def _u4(self):
        self._safe(4)
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

        # stringsStart 字段是相对于 chunk 头部（文件偏移 8）的偏移
        string_start = 8  # chunk 在文件中的起始位置
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

                # 解析属性 (AXML 每个属性 20 字节: ns(4) + name(4) + rawValue(4) + typedValue_size(2) + res0(1) + dataType(1) + data(4))
                attrs = {}
                for a in range(attr_count):
                    if self.pos + 20 > len(self.data):
                        break
                    ans = self._u4()  # namespace string index
                    an = self._u4()   # name string index
                    avs = self._u4()  # raw value string index (-1 if none)
                    _ = self._u2()   # typedValue_size (should be 8)
                    _ = self._u1()   # res0 (should be 0)
                    avt = self._u1()  # dataType
                    avd = self._u4()  # data
                    attr_name = self._read_string(an)
                    if avt == 0x03:  # TYPE_STRING
                        attr_val = self._read_string(avs)
                    elif avt == 0x10:  # TYPE_INT_DEC
                        attr_val = str(avd)
                    elif avt == 0x12:  # TYPE_INT_BOOLEAN
                        attr_val = 'true' if avd == -1 or avd == 0xFFFFFFFF else 'false'
                    elif avt == 0x11:  # TYPE_INT_HEX
                        attr_val = f'0x{avd:x}'
                    else:
                        # 资源引用 (dataType 0x01 = TYPE_REFERENCE) 或未知类型
                        attr_val = f'@{avd}' if avt == 0x01 else str(avd)
                    attrs[attr_name] = attr_val

                # 提取信息
                if in_manifest and name == 'manifest':
                    pkg = attrs.get('package', '')
                    vn = attrs.get('versionName', '')
                    vc = attrs.get('versionCode', '')
                elif name == 'uses-sdk':
                    sdk_min = int(attrs.get('minSdkVersion', 0))
                    sdk_target = int(attrs.get('targetSdkVersion', 0))
                elif name == 'uses-permission':
                    perm = attrs.get('name', '')
                    if perm:
                        perms.append(perm)
                elif in_application and name == 'activity':
                    activities.append(attrs.get('name', ''))
                elif in_application and name == 'service':
                    services.append(attrs.get('name', ''))
                elif in_application and name == 'receiver':
                    receivers.append(attrs.get('name', ''))
                elif in_application and name == 'provider':
                    providers.append(attrs.get('name', ''))

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


# ═══════════════════════════════════════════════════════════════
# 常量与工具函数
# ═══════════════════════════════════════════════════════════════
DEFAULT_OUT_DIR = '/sdcard/Download/Operit/analyzed'


def _short_apk_name(apk_path):
    """返回安全的APK文件名基（不含路径和扩展名）"""
    return os.path.splitext(os.path.basename(apk_path))[0]


def write_result_file(full_result, apk_path, out_dir=None):
    """将全量分析结果写入JSON文件，返回文件路径
    
    Args:
        full_result: 全量分析结果dict
        apk_path: 原始APK路径
        out_dir: 输出目录（默认 DEFAULT_OUT_DIR）
    
    Returns:
        str: 写入的文件路径
    """
    out_dir = out_dir or DEFAULT_OUT_DIR
    os.makedirs(out_dir, exist_ok=True)
    safe = _short_apk_name(apk_path) or 'apk'
    result_path = os.path.join(out_dir, f'{safe}.analysis.json')
    with open(result_path, 'w', encoding='utf-8') as f:
        json.dump(full_result, f, ensure_ascii=False, indent=2)
    return result_path


# ═══════════════════════════════════════════════════════════════
# 上下文压缩 - 去掉verbose字段，只保留摘要所需最小集
# ═══════════════════════════════════════════════════════════════
def _compact_result(result):
    """压缩分析结果：剥离大体积verbose字段（findings列表/dex明细/size_by_category等），
    仅保留摘要所需的最小集合，大幅降低内存与上下文占用。

    压缩原则：
    - 列表字段（权限/加固/安全问题）→ 只保留计数，丢弃原文
    - 网络资产（URL/IP/邮箱/密钥）→ 只保留计数
    - 社交/SDK → 只保留平台名+风险（不保留置信度/匹配数等冗余）
    - structure 只保留摘要需要的数字字段（丢弃 sha256 等大字段）
    """
    if not isinstance(result, dict):
        return result

    keep = {}
    for k in ('apk_path', 'success', 'error'):
        if k in result:
            keep[k] = result[k]

    # structure：只保留『解包后的内容』（包信息 + 文件分类计数），丢弃 sha256/分类大小等大字段
    st = result.get('structure') or {}
    keep['structure'] = {
        'size': st.get('size', 0),
        'total_files': st.get('total_files', 0),
        'dex_count': st.get('dex_count', 0),
        'so_count': st.get('so_count', 0),
        'image_count': st.get('image_count', 0),
        'xml_count': st.get('xml_count', 0),
        'arsc_count': st.get('arsc_count', 0),
        'assets_count': st.get('assets_count', 0),
        'res_count': st.get('res_count', 0),
        'meta_inf_count': st.get('meta_inf_count', 0),
    }

    # manifest：只保留 package + sdk 数值
    m = result.get('manifest') or {}
    keep['manifest'] = {
        'package': m.get('package', ''),
        'sdk': {'minSdk': m.get('sdk', {}).get('minSdk', 0),
                'targetSdk': m.get('sdk', {}).get('targetSdk', 0)},
    }

    # abis：只保留架构列表（通常很短，保留）
    if result.get('abis'):
        keep['abis'] = result['abis']

    # 加固检测 + 危险权限 + 混淆 + 安全提示（用户关心的最终结论，全部保留）
    keep['packer_count'] = len(result.get('packers', []) or [])
    keep['packers'] = result.get('packers', [])
    keep['dangerous_permission_count'] = len(result.get('dangerous_permissions', []) or [])
    keep['dangerous_permissions'] = result.get('dangerous_permissions', [])
    keep['total_classes'] = result.get('total_classes', 0)
    keep['permission_count'] = result.get('permission_count', 0)
    if result.get('obfuscation'):
        keep['obfuscation'] = result['obfuscation']
    if result.get('security_issues'):
        keep['security_issues'] = result['security_issues']
        keep['security_issue_count'] = len(result['security_issues'])
    if result.get('size_by_category'):
        keep['size_by_category'] = result['size_by_category']
    return keep


# ═══════════════════════════════════════════════════════════════
# 主解包逻辑
# ═══════════════════════════════════════════════════════════════
def unpack_apk_standalone(apk_path, output_dir=None, mode='analyze', compact=True):
    """解包APK（纯Python，不依赖外部工具）
    
    Args:
        apk_path: APK文件路径
        output_dir: 可选，解压目录
        mode: 'analyze'（仅分析）| 'extract'（提取文件）| 'full'（全量）
        compact: True=不存储verbose字段(dex详情/findings列表/size_by_category)，减少内存和上下文占用
    
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

        # ── 社交登录检测 ──
        result['social_login'] = _standalone_detect_social(all_class_names, all_strings)

        # ── SDK检测 ──
        result['sdk_detected'] = _standalone_detect_sdk(all_class_names)

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

        # compact=True：返回压缩版（只保留摘要所需字段，大幅降低内存和上下文占用）
        # 全量数据已写入 file_data 供后续落盘
        if compact:
            result = _compact_result(result)

    except Exception as e:
        result['error'] = str(e)
        import traceback
        result['traceback'] = traceback.format_exc()
    finally:
        zf.close()

    return result


# ═══════════════════════════════════════════════════════════════
# 社交登录检测 (内置, 15个平台)
# ═══════════════════════════════════════════════════════════════
_SOCIAL_PLATFORMS = {
    'wechat':{'name':'微信登录','icon':'💬','risk':'中',
        'sdk':[r'com\.tencent\.mm\.opensdk',r'com\.tencent\.connect',r'com\.tencent\.tauth',r'wx[a-z0-9]{16,}'],
        'code':[r'WXEntryActivity',r'WXApi',r'IWXAPI',r'sendReq',r'wechat_login',r'wechat_token',r'wechat_openid',r'wechat_unionid',r'wx_login'],
        'str':[r'wx[a-z0-9]{16,}',r'wechat',r'weixin',r'openid',r'unionid',r'snsapi_userinfo',r'api\.weixin\.qq\.com',r'open\.weixin\.qq\.com'],
        'url':[r'api\.weixin\.qq\.com',r'open\.weixin\.qq\.com',r'wechat\.com']},
    'qq':{'name':'QQ登录','icon':'🐧','risk':'中',
        'sdk':[r'com\.tencent\.connect',r'com\.tencent\.open',r'com\.tencent\.tauth',r'mqqapi'],
        'code':[r'Tencent',r'QQLogin',r'qq_login',r'qq_token',r'qq_openid',r'IUiListener',r'TAuthActivity',r'qq_auth'],
        'str':[r'tencent[0-9]{5,}',r'qq',r'tencent',r'mqqapi://',r'graph\.qq\.com',r'openmobile\.qq\.com'],
        'url':[r'graph\.qq\.com',r'openmobile\.qq\.com',r'connect\.qq\.com']},
    'github':{'name':'GitHub登录','icon':'🐙','risk':'低',
        'sdk':[r'com\.github',r'github\.login',r'github\.oauth',r'github\.auth'],
        'code':[r'GitHubLogin',r'github_login',r'github_oauth',r'Octokit',r'GithubClient',r'ghp_[a-zA-Z0-9]{36,}'],
        'str':[r'github\.com/login',r'github\.com/oauth',r'api\.github\.com',r'client_id=',r'ghp_',r'gho_'],
        'url':[r'github\.com',r'api\.github\.com']},
    'alipay':{'name':'支付宝登录','icon':'💳','risk':'中',
        'sdk':[r'com\.alipay\.sdk',r'com\.alipay\.auth',r'alipaySdk',r'alipaysec'],
        'code':[r'AlipayLogin',r'alipay_login',r'alipay_auth',r'alipay_token',r'AuthResult',r'ali_auth'],
        'str':[r'alipay',r'alipay\.com',r'auth\.alipay\.com',r'openapi\.alipay\.com',r'app_id=[0-9]+',r'auth_code'],
        'url':[r'alipay\.com',r'alipaydev\.com',r'auth\.alipay\.com']},
    'weibo':{'name':'微博登录','icon':'📱','risk':'中',
        'sdk':[r'com\.sina\.weibo',r'com\.sina\.open',r'com\.weibo\.sdk'],
        'code':[r'WeiboLogin',r'weibo_login',r'weibo_auth',r'SsoHandler',r'AccessTokenKeeper'],
        'str':[r'weibo',r'api\.weibo\.com',r'open\.weibo\.com',r'client_id=[0-9]+',r'appkey=[0-9]+'],
        'url':[r'api\.weibo\.com',r'open\.weibo\.com',r'weibo\.com']},
    'google':{'name':'Google登录','icon':'🔵','risk':'低',
        'sdk':[r'com\.google\.android\.gms\.auth',r'com\.google\.firebase\.auth',r'com\.google\.android\.gms\.signin'],
        'code':[r'GoogleSignIn',r'GoogleSignInClient',r'FirebaseAuth',r'getIdToken',r'SignInButton',r'google_sign_in'],
        'str':[r'accounts\.google\.com',r'googleapis\.com/auth',r'googleusercontent\.com',r'firebase\.com',r'client_id=[0-9]+\.apps\.googleusercontent\.com'],
        'url':[r'accounts\.google\.com',r'googleapis\.com',r'google\.com']},
    'facebook':{'name':'Facebook登录','icon':'👍','risk':'中',
        'sdk':[r'com\.facebook\.login',r'com\.facebook\.auth',r'com\.facebook\.FBAuth'],
        'code':[r'FacebookLogin',r'facebook_login',r'LoginButton',r'LoginManager',r'AccessToken',r'CallbackManager'],
        'str':[r'facebook\.com/login',r'facebook\.com/dialog',r'graph\.facebook\.com',r'fb_app_id',r'facebook_app_id'],
        'url':[r'facebook\.com',r'graph\.facebook\.com',r'fbcdn\.net']},
    'apple':{'name':'Apple登录','icon':'🍎','risk':'低',
        'sdk':[r'com\.apple\.',r'apple\.signin',r'apple\.login'],
        'code':[r'AppleSignIn',r'apple_sign_in',r'ASAuthorization',r'SignInWithApple',r'apple_id_credential'],
        'str':[r'apple\.com/auth',r'appleid\.apple\.com',r'apple_id',r'sign_in_with_apple'],
        'url':[r'apple\.com',r'appleid\.apple\.com']},
    'twitter':{'name':'Twitter登录','icon':'🐦','risk':'低',
        'sdk':[r'com\.twitter\.sdk',r'com\.twitter\.android',r'com\.fabric\.sdk\.android'],
        'code':[r'TwitterLogin',r'twitter_login',r'TwitterAuth',r'TwitterSession',r'TwitterAuthClient'],
        'str':[r'twitter\.com/oauth',r'api\.twitter\.com',r'consumer_key',r'consumer_secret',r'oauth_token'],
        'url':[r'twitter\.com',r'api\.twitter\.com',r't\.co']},
    'douyin':{'name':'抖音登录','icon':'🎵','risk':'中',
        'sdk':[r'com\.bytedance\.',r'com\.douyin',r'com\.aweme'],
        'code':[r'DouYinLogin',r'douyin_login',r'DouYinAuth',r'douyin_auth',r'douyin_token',r'douyin_openid'],
        'str':[r'douyin',r'bytedance',r'aweme',r'pangle'],
        'url':[r'douyin\.com',r'pangle\.com']},
    'dingtalk':{'name':'钉钉登录','icon':'🔷','risk':'中',
        'sdk':[r'com\.alibaba\.android\.dingtalk',r'com\.alibaba\.dingtalk'],
        'code':[r'DingTalkLogin',r'dingtalk_login',r'DDLogin',r'dd_login'],
        'str':[r'dingtalk',r'com\.alibaba\.dingtalk'],
        'url':[r'dingtalk\.com']},
    'huawei':{'name':'华为登录','icon':'🌺','risk':'低',
        'sdk':[r'com\.huawei\.hms\.support\.account',r'com\.huawei\.hms\.feature\.account',r'com\.huawei\.agconnect'],
        'code':[r'HuaweiIdAuth',r'HuaweiIdAuthManager',r'HuaweiIdSignIn',r'signInWithHuawei',r'HMSLogin'],
        'str':[r'huawei\.hms',r'huawei\.agconnect',r'huaweiid'],
        'url':[r'huawei\.com',r'developer\.huawei\.com']},
    'xiaomi':{'name':'小米登录','icon':'📱','risk':'低',
        'sdk':[r'com\.xiaomi\.account',r'com\.xiaomi\.passport',r'com\.xiaomi\.sdk'],
        'code':[r'XiaomiLogin',r'xiaomi_login',r'MiLogin',r'mi_login',r'XiaomiAuth'],
        'str':[r'xiaomi\.account',r'xiaomi\.passport',r'milogin'],
        'url':[r'xiaomi\.com',r'account\.xiaomi\.com']},
    'linkedin':{'name':'LinkedIn登录','icon':'💼','risk':'低',
        'sdk':[r'com\.linkedin\.',r'org\.linkedin'],
        'code':[r'LinkedInLogin',r'linkedin_login',r'LinkedInAuth',r'linkedin_auth',r'LinkedInOAuth'],
        'str':[r'linkedin',r'org\.linkedin'],
        'url':[r'linkedin\.com']},
    'line':{'name':'Line登录','icon':'💚','risk':'低',
        'sdk':[r'line\.sdk',r'jp\.line'],
        'code':[r'LineLogin',r'line_login',r'LineAuth',r'line_auth',r'LineSDK'],
        'str':[r'line\.sdk',r'jp\.line',r'linelogin'],
        'url':[r'line\.me',r'api\.line\.me']},
    'kakao':{'name':'Kakao登录','icon':'💛','risk':'低',
        'sdk':[r'com\.kakao\.auth',r'com\.kakao\.sdk',r'com\.kakao\.talk'],
        'code':[r'KakaoLogin',r'kakao_login',r'KakaoAuth',r'kakao_auth',r'KakaoSDK'],
        'str':[r'kakao',r'kakao\.com',r'kapi\.kakao\.com'],
        'url':[r'kakao\.com',r'kapi\.kakao\.com']},
}

def _standalone_detect_social(class_names, strings):
    """内置社交登录检测 - 从类名和字符串中检测15个平台"""
    combined = ' '.join(c.replace('/','.').lstrip('L').rstrip(';') for c in (class_names or []))+' '+' '.join(strings or [])
    combined_lower = combined.lower()
    detected = []
    for key, info in _SOCIAL_PLATFORMS.items():
        score = 0
        matched_sdk = 0; matched_code = 0; matched_str = 0
        for p in info.get('sdk',[]):
            if re.search(p, combined): matched_sdk += 1; break
        for p in info.get('code',[]):
            if re.search(p, combined): matched_code += 1
        for p in info.get('str',[]):
            if re.search(p, combined_lower): matched_str += 1
        score = min(matched_sdk*40 + matched_code*20 + matched_str*15, 100)
        if score > 0:
            w = 1.5 if info['risk']=='高' else 1.2 if info['risk']=='中' else 1.0
            detected.append({'key':key,'name':info['name'],'icon':info['icon'],'risk':info['risk'],
                'confidence':score,'score':round(score*w/100*25,1),
                'sdk_count':matched_sdk,'code_count':matched_code,'string_count':matched_str})
    detected.sort(key=lambda x:-x['confidence'])
    ts = sum(d['score'] for d in detected)
    return {'platforms':detected,'total':len(detected),'total_score':round(min(ts,100),1),
        'level':'密集集成' if ts>=60 else '多平台集成' if ts>=30 else '少量集成' if ts>=10 else '无'}

# ═══════════════════════════════════════════════════════════════
# SDK检测 (内置, 40+ SDK)
# ═══════════════════════════════════════════════════════════════
_SDK_SIGNATURES = [
    (r'com\.google\.android\.gms\.ads','Google Ads','广告','高'),
    (r'com\.facebook\.ads','Facebook Ads','广告','高'),
    (r'com\.facebook\.','Facebook SDK','社交/追踪','高'),
    (r'com\.applovin\.','AppLovin','广告','高'),
    (r'com\.unity3d','Unity3D','游戏引擎','低'),
    (r'com\.vungle\.','Vungle','广告','高'),
    (r'com\.ironsource\.','IronSource','广告','高'),
    (r'com\.chartboost\.','Chartboost','广告','高'),
    (r'com\.adcolony\.','AdColony','广告','高'),
    (r'com\.inmobi\.','InMobi','广告','高'),
    (r'com\.bytedance\.','ByteDance/Pangle','广告','高'),
    (r'com\.mintegral\.','Mintegral','广告','高'),
    (r'com\.adjust\.sdk','Adjust','归因/追踪','高'),
    (r'com\.appsflyer\.','AppsFlyer','归因/追踪','高'),
    (r'com\.kochava\.','Kochava','归因/追踪','高'),
    (r'com\.google\.firebase\.','Firebase SDK','云服务','中'),
    (r'com\.google\.analytics','Google Analytics','分析','中'),
    (r'com\.mixpanel\.','Mixpanel','分析','中'),
    (r'com\.amplitude\.','Amplitude','分析','中'),
    (r'com\.flurry\.','Flurry','分析','中'),
    (r'com\.sentry\.','Sentry','错误追踪','低'),
    (r'com\.bugsnag\.','Bugsnag','错误追踪','低'),
    (r'com\.umeng\.','Umeng/友盟','分析','高'),
    (r'com\.tencent\.bugly','Tencent Bugly','错误追踪','低'),
    (r'com\.google\.firebase\.messaging','Firebase FCM','推送','中'),
    (r'com\.huawei\.hms\.push','Huawei Push','推送','中'),
    (r'com\.xiaomi\.push','Xiaomi Push','推送','中'),
    (r'com\.igexin\.push','GeTui Push','推送','中'),
    (r'com\.jpush\.','JPush','推送','中'),
    (r'com\.onesignal\.','OneSignal','推送','中'),
    (r'com\.stripe\.','Stripe','支付','中'),
    (r'com\.paypal\.','PayPal','支付','中'),
    (r'com\.alipay\.','Alipay','支付','中'),
    (r'com\.unionpay\.','UnionPay','支付','中'),
    (r'com\.squareup\.okhttp','OkHttp','网络','低'),
    (r'com\.bumptech\.glide','Glide','图片','低'),
    (r'com\.google\.gson','Gson','JSON','低'),
    (r'com\.google\.protobuf','Protobuf','序列化','低'),
    (r'com\.squareup\.retrofit','Retrofit','网络','低'),
    (r'com\.tencent\.mmkv','MMKV','存储','低'),
    (r'com\.alibaba\.fastjson','FastJson','JSON','低'),
    (r'com\.google\.android\.gms\.','Google Play Services','基础服务','低'),
    (r'com\.huawei\.hms\.','Huawei HMS','基础服务','低'),
    (r'com\.baidu\.','Baidu SDK','综合','中'),
    (r'com\.tencent\.','Tencent SDK','综合','中'),
    (r'com\.alibaba\.','Alibaba SDK','综合','中'),
]

def _standalone_detect_sdk(class_names):
    """内置SDK检测 - 从类名中检测40+ SDK"""
    combined = ' '.join(c.replace('/','.').lstrip('L').rstrip(';') for c in (class_names or []))
    detected = {}
    for pat, name, cat, risk in _SDK_SIGNATURES:
        if re.search(pat, combined):
            k = (name, cat)
            if k not in detected:
                detected[k] = {'name':name,'category':cat,'risk':risk,'count':0}
            detected[k]['count'] += 1
    sdks = sorted(detected.values(), key=lambda x:-x['count'])
    risk_count = {'高':0,'中':0,'低':0}
    for s in sdks: risk_count[s['risk']] = risk_count.get(s['risk'],0)+1
    return {'sdks':sdks,'total':len(sdks),'risk_summary':risk_count}


# ═══════════════════════════════════════════════════════════════
# 摘要输出 - 生成紧凑终端摘要，避免全量JSON撑爆上下文
# ═══════════════════════════════════════════════════════════════
def _generate_summary(result):
    """从分析结果中提取自然语言摘要（≈600B），适合直接输出给用户
    只输出『解包后的内容』（包信息 + 文件结构），不输出任何分析推导
    兼容压缩版(_compact_result)与全量版两种结构"""
    name = os.path.basename(result.get('apk_path', ''))
    s = result.get('structure', {})
    m = result.get('manifest', {})
    abis = result.get('abis') or []

    parts = [f"📦 {name} ({_fmt_size(s.get('size', 0))})"]
    
    # 包信息
    info = []
    if m.get('package'): info.append(m['package'])
    if m.get('sdk', {}).get('minSdk'): info.append(f"SDK {m['sdk']['minSdk']}→{m['sdk']['targetSdk']}")
    if abis: info.append(f"ABI: {'/'.join(abis)}")
    if info: parts.append(f"  📋 {' · '.join(info)}")
    
    # 解包后的文件结构（文件分类计数）
    files = []
    if s.get('total_files'): files.append(f"共{s['total_files']}文件")
    if s.get('dex_count'): files.append(f"DEX×{s['dex_count']}")
    if s.get('so_count'): files.append(f"SO×{s['so_count']}")
    if s.get('image_count'): files.append(f"图片×{s['image_count']}")
    if s.get('xml_count'): files.append(f"XML×{s['xml_count']}")
    if s.get('arsc_count'): files.append(f"ARSC×{s['arsc_count']}")
    if s.get('assets_count'): files.append(f"assets×{s['assets_count']}")
    if s.get('res_count'): files.append(f"res×{s['res_count']}")
    if s.get('meta_inf_count'): files.append(f"META-INF×{s['meta_inf_count']}")
    if files: parts.append(f"  📂 {' '.join(files)}")
    
    # 混淆 + 类数
    obf = result.get('obfuscation', {})
    tc = result.get('total_classes', 0)
    obf_line = []
    if tc: obf_line.append(f"类{tc}个")
    if obf.get('level') and obf.get('level') != '低':
        obf_line.append(f"混淆{obf['level']}({obf.get('score',0)}分)")
    if obf_line: parts.append(f"  🔍 {' '.join(obf_line)}")
    
    # 加固 + 危险权限 + 安全提示
    extras = []
    packers = result.get('packers', [])
    if packers: extras.append(f"🛡️{'/'.join(packers)}")
    dp = result.get('dangerous_permissions', [])
    if dp: extras.append(f"⚠️{' '.join(dp)}")
    if extras: parts.append(f"  {' '.join(extras)}")
    
    # 安全提示（单独一行，仅在有内容时）
    sec = result.get('security_issues', [])
    if sec:
        parts.append(f"  ⚡{' '.join(sec)}")

    return '\n'.join(parts)


# ═══════════════════════════════════════════════════════════════
# 收件箱模式 - 批量扫描目录中的APK并分析
# ═══════════════════════════════════════════════════════════════
def process_inbox(inbox_dir='/sdcard/Download/Operit/inbox',
                  output_dir='/sdcard/Download/Operit/analyzed',
                  mode='quick', max_apks=10, delete_after=False,
                  output_json=False):
    """扫描收件箱目录，批量分析APK，结果写入JSON文件
    
    Args:
        inbox_dir: 收件箱目录路径（自动创建）
        output_dir: 分析结果输出目录（自动创建）
        mode: 分析模式 quick|full|social|sdk
        max_apks: 最多处理APK数量
        delete_after: 分析完成后是否删除原APK
        output_json: 是否输出JSON格式（False=输出自然语言摘要）
    
    Returns:
        dict: {processed: int, errors: int, results: [summary_dict]}
    """
    # 确保目录存在
    os.makedirs(inbox_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # 扫描APK文件
    apks = []
    for f in sorted(os.listdir(inbox_dir)):
        if f.lower().endswith('.apk') and os.path.isfile(os.path.join(inbox_dir, f)):
            apks.append(os.path.join(inbox_dir, f))
        if len(apks) >= max_apks:
            break

    if not apks:
        return {'processed': 0, 'errors': 0, 'results': [],
                'message': f'收件箱({inbox_dir})中未找到APK文件'}

    results = []
    processed = 0
    errors = 0

    for apk_path in apks:
        try:
            # 分析：compact=False 拿全量用于落盘，压缩版用于对话输出
            full = unpack_apk_standalone(apk_path, compact=False)
            r = _compact_result(full) if full.get('success') else full
            if not r.get('success'):
                errors += 1
                results.append({'apk': os.path.basename(apk_path), 'success': False, 'error': r.get('error', '')})
                continue

            # 构建摘要（只保留解包内容 + 加固 + 危险权限）
            m = r.get('manifest', {})
            summary = {
                'success': True,
                'apk': os.path.basename(apk_path),
                'package': m.get('package', ''),
                'size': r.get('structure', {}).get('size', 0),
                'size_human': _fmt_size(r.get('structure', {}).get('size', 0)),
                'dex_count': r.get('structure', {}).get('dex_count', 0),
                'so_count': r.get('structure', {}).get('so_count', 0),
                'total_files': r.get('structure', {}).get('total_files', 0),
                'packers': r.get('packers', []),
                'packer_count': r.get('packer_count', 0),
                'dangerous_permissions': r.get('dangerous_permissions', []),
                'dangerous_permission_count': r.get('dangerous_permission_count', 0),
                'abis': r.get('abis', []),
                # 自然语言摘要（输出给用户看）
                'summary': _generate_summary(r),
            }

            # 写入精简结果文件（只保存关键字段，不是全量数据）
            safe_name = os.path.splitext(os.path.basename(apk_path))[0]
            result_path = os.path.join(output_dir, f'{safe_name}.analysis.json')
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(r, f, ensure_ascii=False, indent=2)

            summary['result_path'] = result_path
            results.append(summary)
            processed += 1

            # 可选删除原APK
            if delete_after:
                os.remove(apk_path)

        except Exception as e:
            errors += 1
            results.append({'apk': os.path.basename(apk_path), 'success': False, 'error': str(e)})

    # 写入汇总报告
    report_path = os.path.join(output_dir, '_inbox_report.json')
    report = {
        'timestamp': __import__('datetime').datetime.now().isoformat(),
        'inbox_dir': inbox_dir,
        'output_dir': output_dir,
        'mode': mode,
        'processed': processed,
        'errors': errors,
        'total': len(apks),
        'results': results,
    }
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    report['report_path'] = report_path
    return report


# ═══════════════════════════════════════════════════════════════
# 命令行入口
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Standalone APK Unpacker')
    parser.add_argument('apk', help='APK file path')
    parser.add_argument('-o', '--output', help='Output directory (optional)')
    parser.add_argument('-m', '--mode', default='analyze', choices=['analyze', 'extract', 'full'],
                        help='Mode: analyze/extract/full')
    parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    parser.add_argument('--summary', action='store_true',
                        help='摘要模式：全量JSON写文件，终端只输出紧凑摘要（避免撑爆上下文）')
    parser.add_argument('--summary-path', default=None,
                        help='摘要输出路径（默认：APK同目录下 *.analysis.json）')
    args = parser.parse_args()

    result = unpack_apk_standalone(args.apk, args.output, args.mode, compact=not args.summary)

    if args.summary:
        # 精简模式：compact=False 拿全量分析，但只写关键字段到文件，输出压缩摘要
        full = unpack_apk_standalone(args.apk, args.output, args.mode, compact=False)
        compact_r = _compact_result(full) if full.get('success') else full
        out_path = args.summary_path or os.path.splitext(args.apk)[0] + '.analysis.json'
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(compact_r, f, ensure_ascii=False, indent=2)
        # 终端只输出摘要
        print(_generate_summary(compact_r))
        print(f"\n📄 精简结果已保存: {out_path}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=None if args.compact else 2))

_SOCIAL_PLATFORMS = {
    'wechat':{'name':'微信登录','icon':'💬','risk':'中',
        'sdk':[r'com\.tencent\.mm\.opensdk',r'com\.tencent\.connect',r'com\.tencent\.tauth',r'wx[a-z0-9]{16,}'],
        'code':[r'WXEntryActivity',r'WXApi',r'IWXAPI',r'sendReq',r'wechat_login',r'wechat_token',r'wechat_openid',r'wechat_unionid',r'wx_login'],
        'str':[r'wx[a-z0-9]{16,}',r'wechat',r'weixin',r'openid',r'unionid',r'snsapi_userinfo',r'api\.weixin\.qq\.com',r'open\.weixin\.qq\.com'],
        'url':[r'api\.weixin\.qq\.com',r'open\.weixin\.qq\.com',r'wechat\.com']},
    'qq':{'name':'QQ登录','icon':'🐧','risk':'中',
        'sdk':[r'com\.tencent\.connect',r'com\.tencent\.open',r'com\.tencent\.tauth',r'mqqapi'],
        'code':[r'Tencent',r'QQLogin',r'qq_login',r'qq_token',r'qq_openid',r'IUiListener',r'TAuthActivity',r'qq_auth'],
        'str':[r'tencent[0-9]{5,}',r'qq',r'tencent',r'mqqapi://',r'graph\.qq\.com',r'openmobile\.qq\.com'],
        'url':[r'graph\.qq\.com',r'openmobile\.qq\.com',r'connect\.qq\.com']},
    'github':{'name':'GitHub登录','icon':'🐙','risk':'低',
        'sdk':[r'com\.github',r'github\.login',r'github\.oauth',r'github\.auth'],
        'code':[r'GitHubLogin',r'github_login',r'github_oauth',r'Octokit',r'GithubClient',r'ghp_[a-zA-Z0-9]{36,}'],
        'str':[r'github\.com/login',r'github\.com/oauth',r'api\.github\.com',r'client_id=',r'ghp_',r'gho_'],
        'url':[r'github\.com',r'api\.github\.com']},
    'alipay':{'name':'支付宝登录','icon':'💳','risk':'中',
        'sdk':[r'com\.alipay\.sdk',r'com\.alipay\.auth',r'alipaySdk',r'alipaysec'],
        'code':[r'AlipayLogin',r'alipay_login',r'alipay_auth',r'alipay_token',r'AuthResult',r'ali_auth'],
        'str':[r'alipay',r'alipay\.com',r'auth\.alipay\.com',r'openapi\.alipay\.com',r'app_id=[0-9]+',r'auth_code'],
        'url':[r'alipay\.com',r'alipaydev\.com',r'auth\.alipay\.com']},
    'weibo':{'name':'微博登录','icon':'📱','risk':'中',
        'sdk':[r'com\.sina\.weibo',r'com\.sina\.open',r'com\.weibo\.sdk'],
        'code':[r'WeiboLogin',r'weibo_login',r'weibo_auth',r'SsoHandler',r'AccessTokenKeeper'],
        'str':[r'weibo',r'api\.weibo\.com',r'open\.weibo\.com',r'client_id=[0-9]+',r'appkey=[0-9]+'],
        'url':[r'api\.weibo\.com',r'open\.weibo\.com',r'weibo\.com']},
    'google':{'name':'Google登录','icon':'🔵','risk':'低',
        'sdk':[r'com\.google\.android\.gms\.auth',r'com\.google\.firebase\.auth',r'com\.google\.android\.gms\.signin'],
        'code':[r'GoogleSignIn',r'GoogleSignInClient',r'FirebaseAuth',r'getIdToken',r'SignInButton',r'google_sign_in'],
        'str':[r'accounts\.google\.com',r'googleapis\.com/auth',r'googleusercontent\.com',r'firebase\.com',r'client_id=[0-9]+\.apps\.googleusercontent\.com'],
        'url':[r'accounts\.google\.com',r'googleapis\.com',r'google\.com']},
    'facebook':{'name':'Facebook登录','icon':'👍','risk':'中',
        'sdk':[r'com\.facebook\.login',r'com\.facebook\.auth',r'com\.facebook\.FBAuth'],
        'code':[r'FacebookLogin',r'facebook_login',r'LoginButton',r'LoginManager',r'AccessToken',r'CallbackManager'],
        'str':[r'facebook\.com/login',r'facebook\.com/dialog',r'graph\.facebook\.com',r'fb_app_id',r'facebook_app_id'],
        'url':[r'facebook\.com',r'graph\.facebook\.com',r'fbcdn\.net']},
    'apple':{'name':'Apple登录','icon':'🍎','risk':'低',
        'sdk':[r'com\.apple\.',r'apple\.signin',r'apple\.login'],
        'code':[r'AppleSignIn',r'apple_sign_in',r'ASAuthorization',r'SignInWithApple',r'apple_id_credential'],
        'str':[r'apple\.com/auth',r'appleid\.apple\.com',r'apple_id',r'sign_in_with_apple'],
        'url':[r'apple\.com',r'appleid\.apple\.com']},
    'twitter':{'name':'Twitter登录','icon':'🐦','risk':'低',
        'sdk':[r'com\.twitter\.sdk',r'com\.twitter\.android',r'com\.fabric\.sdk\.android'],
        'code':[r'TwitterLogin',r'twitter_login',r'TwitterAuth',r'TwitterSession',r'TwitterAuthClient'],
        'str':[r'twitter\.com/oauth',r'api\.twitter\.com',r'consumer_key',r'consumer_secret',r'oauth_token'],
        'url':[r'twitter\.com',r'api\.twitter\.com',r't\.co']},
    'douyin':{'name':'抖音登录','icon':'🎵','risk':'中',
        'sdk':[r'com\.bytedance\.',r'com\.douyin',r'com\.aweme'],
        'code':[r'DouYinLogin',r'douyin_login',r'DouYinAuth',r'douyin_auth',r'douyin_token',r'douyin_openid'],
        'str':[r'douyin',r'bytedance',r'aweme',r'pangle'],
        'url':[r'douyin\.com',r'pangle\.com']},
    'dingtalk':{'name':'钉钉登录','icon':'🔷','risk':'中',
        'sdk':[r'com\.alibaba\.android\.dingtalk',r'com\.alibaba\.dingtalk'],
        'code':[r'DingTalkLogin',r'dingtalk_login',r'DDLogin',r'dd_login'],
        'str':[r'dingtalk',r'com\.alibaba\.dingtalk'],
        'url':[r'dingtalk\.com']},
    'huawei':{'name':'华为登录','icon':'🌺','risk':'低',
        'sdk':[r'com\.huawei\.hms\.support\.account',r'com\.huawei\.hms\.feature\.account',r'com\.huawei\.agconnect'],
        'code':[r'HuaweiIdAuth',r'HuaweiIdAuthManager',r'HuaweiIdSignIn',r'signInWithHuawei',r'HMSLogin'],
        'str':[r'huawei\.hms',r'huawei\.agconnect',r'huaweiid'],
        'url':[r'huawei\.com',r'developer\.huawei\.com']},
    'xiaomi':{'name':'小米登录','icon':'📱','risk':'低',
        'sdk':[r'com\.xiaomi\.account',r'com\.xiaomi\.passport',r'com\.xiaomi\.sdk'],
        'code':[r'XiaomiLogin',r'xiaomi_login',r'MiLogin',r'mi_login',r'XiaomiAuth'],
        'str':[r'xiaomi\.account',r'xiaomi\.passport',r'milogin'],
        'url':[r'xiaomi\.com',r'account\.xiaomi\.com']},
    'linkedin':{'name':'LinkedIn登录','icon':'💼','risk':'低',
        'sdk':[r'com\.linkedin\.',r'org\.linkedin'],
        'code':[r'LinkedInLogin',r'linkedin_login',r'LinkedInAuth',r'linkedin_auth',r'LinkedInOAuth'],
        'str':[r'linkedin',r'org\.linkedin'],
        'url':[r'linkedin\.com']},
    'line':{'name':'Line登录','icon':'💚','risk':'低',
        'sdk':[r'line\.sdk',r'jp\.line'],
        'code':[r'LineLogin',r'line_login',r'LineAuth',r'line_auth',r'LineSDK'],
        'str':[r'line\.sdk',r'jp\.line',r'linelogin'],
        'url':[r'line\.me',r'api\.line\.me']},
    'kakao':{'name':'Kakao登录','icon':'💛','risk':'低',
        'sdk':[r'com\.kakao\.auth',r'com\.kakao\.sdk',r'com\.kakao\.talk'],
        'code':[r'KakaoLogin',r'kakao_login',r'KakaoAuth',r'kakao_auth',r'KakaoSDK'],
        'str':[r'kakao',r'kakao\.com',r'kapi\.kakao\.com'],
        'url':[r'kakao\.com',r'kapi\.kakao\.com']},
}

def _standalone_detect_social(class_names, strings):
    """内置社交登录检测 - 从类名和字符串中检测15个平台"""
    combined = ' '.join(c.replace('/','.').lstrip('L').rstrip(';') for c in (class_names or []))+' '+' '.join(strings or [])
    combined_lower = combined.lower()
    detected = []
    for key, info in _SOCIAL_PLATFORMS.items():
        score = 0
        matched_sdk = 0; matched_code = 0; matched_str = 0
        for p in info.get('sdk',[]):
            if re.search(p, combined): matched_sdk += 1; break
        for p in info.get('code',[]):
            if re.search(p, combined): matched_code += 1
        for p in info.get('str',[]):
            if re.search(p, combined_lower): matched_str += 1
        score = min(matched_sdk*40 + matched_code*20 + matched_str*15, 100)
        if score > 0:
            w = 1.5 if info['risk']=='高' else 1.2 if info['risk']=='中' else 1.0
            detected.append({'key':key,'name':info['name'],'icon':info['icon'],'risk':info['risk'],
                'confidence':score,'score':round(score*w/100*25,1),
                'sdk_count':matched_sdk,'code_count':matched_code,'string_count':matched_str})
    detected.sort(key=lambda x:-x['confidence'])
    ts = sum(d['score'] for d in detected)
    return {'platforms':detected,'total':len(detected),'total_score':round(min(ts,100),1),
        'level':'密集集成' if ts>=60 else '多平台集成' if ts>=30 else '少量集成' if ts>=10 else '无'}

# ═══════════════════════════════════════════════════════════════
# SDK检测 (内置, 40+ SDK)
# ═══════════════════════════════════════════════════════════════
_SDK_SIGNATURES = [
    (r'com\.google\.android\.gms\.ads','Google Ads','广告','高'),
    (r'com\.facebook\.ads','Facebook Ads','广告','高'),
    (r'com\.facebook\.','Facebook SDK','社交/追踪','高'),
    (r'com\.applovin\.','AppLovin','广告','高'),
    (r'com\.unity3d','Unity3D','游戏引擎','低'),
    (r'com\.vungle\.','Vungle','广告','高'),
    (r'com\.ironsource\.','IronSource','广告','高'),
    (r'com\.chartboost\.','Chartboost','广告','高'),
    (r'com\.adcolony\.','AdColony','广告','高'),
    (r'com\.inmobi\.','InMobi','广告','高'),
    (r'com\.bytedance\.','ByteDance/Pangle','广告','高'),
    (r'com\.mintegral\.','Mintegral','广告','高'),
    (r'com\.adjust\.sdk','Adjust','归因/追踪','高'),
    (r'com\.appsflyer\.','AppsFlyer','归因/追踪','高'),
    (r'com\.kochava\.','Kochava','归因/追踪','高'),
    (r'com\.google\.firebase\.','Firebase SDK','云服务','中'),
    (r'com\.google\.analytics','Google Analytics','分析','中'),
    (r'com\.mixpanel\.','Mixpanel','分析','中'),
    (r'com\.amplitude\.','Amplitude','分析','中'),
    (r'com\.flurry\.','Flurry','分析','中'),
    (r'com\.sentry\.','Sentry','错误追踪','低'),
    (r'com\.bugsnag\.','Bugsnag','错误追踪','低'),
    (r'com\.umeng\.','Umeng/友盟','分析','高'),
    (r'com\.tencent\.bugly','Tencent Bugly','错误追踪','低'),
    (r'com\.google\.firebase\.messaging','Firebase FCM','推送','中'),
    (r'com\.huawei\.hms\.push','Huawei Push','推送','中'),
    (r'com\.xiaomi\.push','Xiaomi Push','推送','中'),
    (r'com\.igexin\.push','GeTui Push','推送','中'),
    (r'com\.jpush\.','JPush','推送','中'),
    (r'com\.onesignal\.','OneSignal','推送','中'),
    (r'com\.stripe\.','Stripe','支付','中'),
    (r'com\.paypal\.','PayPal','支付','中'),
    (r'com\.alipay\.','Alipay','支付','中'),
    (r'com\.unionpay\.','UnionPay','支付','中'),
    (r'com\.squareup\.okhttp','OkHttp','网络','低'),
    (r'com\.bumptech\.glide','Glide','图片','低'),
    (r'com\.google\.gson','Gson','JSON','低'),
    (r'com\.google\.protobuf','Protobuf','序列化','低'),
    (r'com\.squareup\.retrofit','Retrofit','网络','低'),
    (r'com\.tencent\.mmkv','MMKV','存储','低'),
    (r'com\.alibaba\.fastjson','FastJson','JSON','低'),
    (r'com\.google\.android\.gms\.','Google Play Services','基础服务','低'),
    (r'com\.huawei\.hms\.','Huawei HMS','基础服务','低'),
    (r'com\.baidu\.','Baidu SDK','综合','中'),
    (r'com\.tencent\.','Tencent SDK','综合','中'),
    (r'com\.alibaba\.','Alibaba SDK','综合','中'),
]


_SDK_SIGNATURES = [
    (r'com\.google\.android\.gms\.ads','Google Ads','广告','高'),
    (r'com\.facebook\.ads','Facebook Ads','广告','高'),
    (r'com\.facebook\.','Facebook SDK','社交/追踪','高'),
    (r'com\.applovin\.','AppLovin','广告','高'),
    (r'com\.unity3d','Unity3D','游戏引擎','低'),
    (r'com\.vungle\.','Vungle','广告','高'),
    (r'com\.ironsource\.','IronSource','广告','高'),
    (r'com\.chartboost\.','Chartboost','广告','高'),
    (r'com\.adcolony\.','AdColony','广告','高'),
    (r'com\.inmobi\.','InMobi','广告','高'),
    (r'com\.bytedance\.','ByteDance/Pangle','广告','高'),
    (r'com\.mintegral\.','Mintegral','广告','高'),
    (r'com\.adjust\.sdk','Adjust','归因/追踪','高'),
    (r'com\.appsflyer\.','AppsFlyer','归因/追踪','高'),
    (r'com\.kochava\.','Kochava','归因/追踪','高'),
    (r'com\.google\.firebase\.','Firebase SDK','云服务','中'),
    (r'com\.google\.analytics','Google Analytics','分析','中'),
    (r'com\.mixpanel\.','Mixpanel','分析','中'),
    (r'com\.amplitude\.','Amplitude','分析','中'),
    (r'com\.flurry\.','Flurry','分析','中'),
    (r'com\.sentry\.','Sentry','错误追踪','低'),
    (r'com\.bugsnag\.','Bugsnag','错误追踪','低'),
    (r'com\.umeng\.','Umeng/友盟','分析','高'),
    (r'com\.tencent\.bugly','Tencent Bugly','错误追踪','低'),
    (r'com\.google\.firebase\.messaging','Firebase FCM','推送','中'),
    (r'com\.huawei\.hms\.push','Huawei Push','推送','中'),
    (r'com\.xiaomi\.push','Xiaomi Push','推送','中'),
    (r'com\.igexin\.push','GeTui Push','推送','中'),
    (r'com\.jpush\.','JPush','推送','中'),
    (r'com\.onesignal\.','OneSignal','推送','中'),
    (r'com\.stripe\.','Stripe','支付','中'),
    (r'com\.paypal\.','PayPal','支付','中'),
    (r'com\.alipay\.','Alipay','支付','中'),
    (r'com\.unionpay\.','UnionPay','支付','中'),
    (r'com\.squareup\.okhttp','OkHttp','网络','低'),
    (r'com\.bumptech\.glide','Glide','图片','低'),
    (r'com\.google\.gson','Gson','JSON','低'),
    (r'com\.google\.protobuf','Protobuf','序列化','低'),
    (r'com\.squareup\.retrofit','Retrofit','网络','低'),
    (r'com\.tencent\.mmkv','MMKV','存储','低'),
    (r'com\.alibaba\.fastjson','FastJson','JSON','低'),
    (r'com\.google\.android\.gms\.','Google Play Services','基础服务','低'),
    (r'com\.huawei\.hms\.','Huawei HMS','基础服务','低'),
    (r'com\.baidu\.','Baidu SDK','综合','中'),
    (r'com\.tencent\.','Tencent SDK','综合','中'),
    (r'com\.alibaba\.','Alibaba SDK','综合','中'),
]

def _standalone_detect_sdk(class_names):
    """内置SDK检测 - 从类名中检测40+ SDK"""
    combined = ' '.join(c.replace('/','.').lstrip('L').rstrip(';') for c in (class_names or []))
    detected = {}
    for pat, name, cat, risk in _SDK_SIGNATURES:
        if re.search(pat, combined):
            k = (name, cat)
            if k not in detected:
                detected[k] = {'name':name,'category':cat,'risk':risk,'count':0}
            detected[k]['count'] += 1
    sdks = sorted(detected.values(), key=lambda x:-x['count'])
    risk_count = {'高':0,'中':0,'低':0}
    for s in sdks: risk_count[s['risk']] = risk_count.get(s['risk'],0)+1
    return {'sdks':sdks,'total':len(sdks),'risk_summary':risk_count}


# ═══════════════════════════════════════════════════════════════
# 摘要输出 - 生成紧凑终端摘要，避免全量JSON撑爆上下文
# ═══════════════════════════════════════════════════════════════


def unpack_apk_lite(apk_path, output_dir=None, mode='analyze', compact=True):
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
        sha = hashlib.sha256()
        with open(apk_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha.update(chunk)
        sha256 = sha.hexdigest()
        dex_files = [n for n in file_list if n.endswith('.dex')]
        so_files = [n for n in file_list if n.endswith('.so')]
        img_files = [n for n in file_list if n.lower().endswith(('.png','.jpg','.jpeg','.gif','.webp','.bmp'))]
        xml_files = [n for n in file_list if n.endswith('.xml')]
        arsc_files = [n for n in file_list if n.endswith('.arsc')]
        assets_files = [n for n in file_list if n.startswith('assets/')]
        res_files = [n for n in file_list if n.startswith('res/')]
        meta_files = [n for n in file_list if n.startswith('META-INF/')]
        abis = set()
        for s in so_files:
            parts = s.split('/')
            if len(parts) >= 2 and parts[0] == 'lib':
                abis.add(parts[1])
            elif '/' in s:
                abis.add(parts[0])
        result['structure'] = {'total_files': len(file_list), 'dex_count': len(dex_files), 'so_count': len(so_files), 'image_count': len(img_files), 'xml_count': len(xml_files), 'arsc_count': len(arsc_files), 'assets_count': len(assets_files), 'res_count': len(res_files), 'meta_inf_count': len(meta_files), 'size': file_size, 'sha256': sha256}
        result['abis'] = sorted(abis)
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
        try:
            manifest_raw = zf.read('AndroidManifest.xml')
            result['manifest'] = LiteManifestParser(manifest_raw).parse()
        except Exception as e:
            result['manifest'] = {'error': str(e)}
        result['dex'] = {}
        all_class_names = []
        all_strings = []
        for d in dex_files[:10]:
            try:
                data = zf.read(d)
                lp = LiteDexParser(data)
                class_names = lp.parse_class_names()
                strings = lp.parse_strings()
                all_class_names.extend(class_names)
                all_strings.extend(strings)
                result['dex'][d] = {'size': len(data), 'classes': len(class_names), 'strings': len(strings)}
            except Exception as e:
                result['dex'][d] = {'error': str(e)}
        result['total_classes'] = len(set(all_class_names))
        result['total_strings'] = len(all_strings)
        rsa_files = [n for n in meta_files if n.upper().endswith(('.RSA','.DSA','.EC'))]
        sf_files = [n for n in meta_files if n.upper().endswith('.SF')]
        mf_files = [n for n in meta_files if n.upper().endswith('.MF')]
        result['signature'] = {'has_rsa': len(rsa_files) > 0, 'has_sf': len(sf_files) > 0, 'has_mf': len(mf_files) > 0, 'rsa_files': rsa_files, 'v1_valid': len(rsa_files) > 0 and len(sf_files) > 0 and len(mf_files) > 0}
        obf_score = 0
        obf_reasons = []
        if all_class_names:
            simple_names = [c.split('/')[-1].rstrip(';') for c in all_class_names if c]
            single_char = sum(1 for n in simple_names if len(n) <= 2 and n.isalpha())
            total_classes = len(set(all_class_names))
            if total_classes > 0:
                ratio = single_char / total_classes
                if ratio > 0.3:
                    obf_score = min(100, obf_score + 40); obf_reasons.append(f'单字符类名占比{ratio:.0%}')
                if ratio > 0.6:
                    obf_score = min(100, obf_score + 30); obf_reasons.append('高度混淆')
                short_paths = sum(1 for c in set(all_class_names) if c.count('/') <= 2 and len(c.split('/')[-1].rstrip(';')) <= 3)
                if short_paths > 50:
                    obf_score = min(100, obf_score + 20); obf_reasons.append(f'短路径类{short_paths}个')
            result['obfuscation'] = {'score': round(obf_score,1), 'level': '高' if obf_score >= 60 else '中' if obf_score >= 30 else '低', 'reasons': obf_reasons, 'single_char_ratio': round(ratio,3) if total_classes > 0 else 0, 'total_classes': total_classes}
        packers = []
        combined = ' '.join(all_class_names).lower()
        for name, signals in PACKER_SIGNALS.items():
            for sig in signals:
                if sig.lower() in combined:
                    packers.append(name); break
        result['packers'] = list(set(packers))
        sec_issues = []
        manifest = result.get('manifest', {})
        if manifest.get('sdk', {}).get('minSdk', 0) < 21:
            sec_issues.append('minSdk过低(支持Android 5以下)')
        if manifest.get('sdk', {}).get('targetSdk', 0) < 28:
            sec_issues.append('targetSdk过低(未适配Android 9+)')
        perms = [p.split('.')[-1] for p in manifest.get('permissions', [])]
        found_dangerous = [p for p in perms if p in DANGEROUS_PERMS]
        result['dangerous_permissions'] = found_dangerous
        result['security_issues'] = sec_issues
        result['permission_count'] = len(perms)
        result['social_login'] = _standalone_detect_social(all_class_names, all_strings)
        result['sdk_detected'] = _standalone_detect_sdk(all_class_names)
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
                except Exception:
                    pass
            result['extracted'] = extracted
            result['output_dir'] = output_dir
        result['success'] = True
        if compact:
            result = _compact_result(result)
    except Exception as e:
        result['error'] = str(e)
        import traceback
        result['traceback'] = traceback.format_exc()
    finally:
        zf.close()
    return result
