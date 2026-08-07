"""APK Reverse Engineering Engine v2 - 全模块基础功能API"""
import os, zipfile

__version__ = '2.2.0'

# ============================================================
# 核心模块 - Core
# ============================================================

# --- APK上下文 ---
from .core.apk_context import APKContext as _APKContext

def open_apk(apk_path):
    """打开APK文件，返回APKContext上下文对象"""
    return _APKContext(apk_path)

def list_apk_files(apk_path, pattern=None):
    """列出APK内所有文件，支持正则过滤"""
    with _APKContext(apk_path) as ctx:
        return ctx.list_files(pattern)

def read_apk_file(apk_path, file_path):
    """读取APK内指定文件内容(返回bytes)"""
    with _APKContext(apk_path) as ctx:
        return ctx.read_file(file_path)

def extract_apk(apk_path, output_dir):
    """解压APK到目录（稳健模式，逐文件提取）"""
    with _APKContext(apk_path) as ctx:
        r = ctx.extract_to(output_dir)
        return {'success': len(r.get('errors', [])) < r.get('extracted', 0) or r.get('extracted', 0) > 0,
                'dir': output_dir, 'extracted': r.get('extracted', 0), 'errors': r.get('errors', [])}

def apk_structure(apk_path):
    """获取APK结构摘要"""
    with _APKContext(apk_path) as ctx:
        return ctx.get_structure_summary()

# --- Manifest解析 ---
from .core.manifest_parser import ManifestParser as _ManifestParser
from .utils.axml_parser import AXMLParser as _AXMLParser
from .utils.axml_converter import AXMLConverter as _AXMLConverter
AXMLConverter = _AXMLConverter  # 公开别名

def parse_manifest(data):
    """解析AndroidManifest.xml二进制数据，返回完整标签树"""
    return _AXMLParser(data).parse()

def get_manifest_info(data):
    """快速获取Manifest关键信息(包名/SDK/权限/组件)"""
    return _AXMLParser(data).get_manifest_simple()

# --- DEX解析 ---
from .core.dex_parser import DexParser as _DexParser

def parse_dex(data):
    """解析DEX二进制数据，返回DexParser对象"""
    return _DexParser(data)

def dex_header(data):
    """解析DEX文件头信息"""
    dp = _DexParser(data)
    return dp.parse_header()

def dex_summary(data):
    """DEX文件摘要: strings/types/protos/fields/methods/classes数量"""
    dp = _DexParser(data)
    dp.parse_header()
    return dp.get_summary()

def dex_classes(data):
    """获取DEX中所有类定义"""
    dp = _DexParser(data)
    dp.parse_header()
    return dp.get_class_defs()

def dex_class_names(data):
    """获取DEX中所有类名"""
    dp = _DexParser(data)
    dp.parse_header()
    return dp.get_class_names()

def dex_search_classes(data, keyword):
    """按关键词搜索DEX类名"""
    dp = _DexParser(data)
    dp.parse_header()
    return dp.find_classes(keyword)

def dex_search_methods(data, keyword):
    """按关键词搜索DEX方法名"""
    dp = _DexParser(data)
    dp.parse_header()
    return dp.find_methods(keyword)

def dex_strings(data):
    """获取DEX中所有字符串"""
    dp = _DexParser(data)
    dp.parse_header()
    return dp.get_strings()

def dex_methods(data):
    """获取DEX中所有方法定义"""
    dp = _DexParser(data)
    dp.parse_header()
    return dp.get_methods()

# --- ELF/SO解析 ---
from .core.native_analyzer import NativeAnalyzer as _NativeAnalyzer
from .core.native_analyzer import ElfImage as _ElfImage

def is_elf(data):
    """检查数据是否为ELF文件"""
    return _NativeAnalyzer.is_elf(data)

def analyze_elf(data):
    """分析ELF文件，返回摘要(架构/入口/节区/导入导出/依赖)"""
    return _NativeAnalyzer.analyze(data)

def parse_elf(data):
    """完整解析ELF文件，返回header/sections/segments/dynamic/relocations"""
    return _NativeAnalyzer.parse_full(data)

def elf_imports(data):
    """获取ELF导入函数列表"""
    return _NativeAnalyzer.find_imports(data)

def elf_exports(data):
    """获取ELF导出函数列表"""
    return _NativeAnalyzer.find_exports(data)

def elf_find_strings(data, min_len=4, limit=1000):
    """从ELF文件中提取可读字符串"""
    return _NativeAnalyzer.find_strings(data, min_len, limit)

def elf_detect_crypto(data):
    """检测ELF中的加密库(AES/RSA/MD5/SHA等)"""
    return _NativeAnalyzer.detect_crypto(data)

def elf_detect_packer(data):
    """检测ELF加固壳(UPX/OLLVM/Arxan/Tencent)"""
    return _NativeAnalyzer.detect_packer(data)

# --- 签名验证 ---
from .core.sign_verifier import SignVerifier as _SignVerifier

def verify_signature_v1(apk_zip):
    """验证APK v1 JAR签名方案"""
    return _SignVerifier.verify_v1(apk_zip)

def verify_signature_v2(apk_path):
    """验证APK v2/v3签名方案"""
    return _SignVerifier.verify_v2(apk_path)

def verify_signature(apk_zip, apk_path):
    """同时验证APK v1+v2+v3所有签名方案"""
    return _SignVerifier.verify_all(apk_zip, apk_path)

def extract_cert_sha256(apk_path, raw=False):
    """从APK v2/v3签名块直接提取签名证书SHA-256（纯标准库，无需apksigner/keytool）

    移植自 RikkaMinis/scripts/apk_cert_sha256.py。
    返回第一个签名者叶子证书的 SHA-256（小写十六进制）；raw=True 时返回 DER 证书字节。
    无 v2/v3 签名时抛出 ValueError。
    """
    return _SignVerifier.extract_cert_sha256(apk_path, raw=raw)

# --- 资源解析 ---
from .core.resource_parser import ResourceParser as _ResourceParser

def parse_arsc(data):
    """解析resources.arsc，返回包信息"""
    return _ResourceParser(data).parse()

# ============================================================
# 分析模块 - Analysis
# ============================================================

from .analysis.clue_chain import ClueChain as _ClueChain
from .analysis.core_class_locator import CoreClassLocator as _CoreClassLocator

from .analysis.static_analyzer import StaticAnalyzer as _StaticAnalyzer
from .analysis.permission_analyzer import PermissionAnalyzer as _PermissionAnalyzer
from .analysis.obfuscation_detector import ObfuscationDetector as _ObfuscationDetector
from .analysis.security_analyzer import SecurityAnalyzer as _SecurityAnalyzer
from .analysis.code_analyzer import CodeAnalyzer as _CodeAnalyzer
from .analysis.network_analyzer import NetworkAnalyzer as _NetworkAnalyzer
from .analysis.apk_diff import APKDiffEngine as _APKDiffEngine
from .analysis.endpoint_extractor import EndpointExtractor as _EndpointExtractor
from .analysis.key_scanner import KeyScanner as _KeyScanner
from .analysis.cert_deep_analyzer import CertDeepAnalyzer as _CertDeepAnalyzer
from .analysis.apk_cleaner import APKCleaner as _APKCleaner
from .analysis.sdk_detector import SDKDetector as _SDKDetector
from .analysis.manifest_editor import ManifestEditor as _ManifestEditor
from .analysis.string_analyzer import StringAnalyzer as _StringAnalyzer
from .analysis.resource_obfuscation import ResourceObfuscationDetector as _ResourceObfuscationDetector
from .analysis.ad_detector import AdDetector as _AdDetector
from .analysis.deobfuscator import Deobfuscator as _Deobfuscator
from .analysis.social_login_detector import SocialLoginDetector as _SocialLoginDetector

def static_analyze(apk_path):
    """APK静态分析: 结构/Manifest/DEX摘要/签名/ABI"""
    sa = _StaticAnalyzer(apk_path)
    try:
        return sa.analyze()
    finally:
        sa.close()

def analyze_permissions(permissions):
    """分析权限风险，返回危险/正常/自定义权限分类"""
    return _PermissionAnalyzer.analyze(permissions)

def detect_obfuscation(class_names):
    """检测类名混淆程度"""
    return _ObfuscationDetector.detect_class_names(class_names)

def detect_packer(apk_zip):
    """通过APK文件列表检测加固壳"""
    return _ObfuscationDetector.detect_packer(apk_zip)

def detect_anti_tamper(text):
    """检测反篡改/反调试代码"""
    return _ObfuscationDetector.detect_anti_tamper(text)

def detect_reflection(text):
    """检测反射/动态加载代码"""
    return _ObfuscationDetector.detect_reflection(text)

def detect_string_encryption(text):
    """检测字符串加密特征"""
    return _ObfuscationDetector.detect_string_encryption(text)

def security_analyze(manifest_simple, permissions, obfuscation_score, packers):
    """综合安全风险评估"""
    return _SecurityAnalyzer.analyze(manifest_simple, permissions, obfuscation_score, packers)

def analyze_code(text):
    """分析代码中的密钥/敏感信息"""
    return _CodeAnalyzer.analyze_all(text)

def analyze_danger_summary(text):
    """危险调用摘要分析"""
    return _CodeAnalyzer.analyze_danger_summary(text)

def build_cfg(instructions):
    """构建DEX指令控制流图"""
    from .analysis.code_analyzer import CFGBuilder
    return CFGBuilder.analyze_method(instructions)

def analyze_method(instructions):
    """分析方法指令摘要"""
    from .analysis.code_analyzer import MethodAnalyzer
    return MethodAnalyzer.analyze_method_summary(instructions)

def deobfuscate_analyze(text, class_names=None, instructions=None):
    """一站式去混淆分析"""
    return _Deobfuscator.analyze_full(text, class_names, instructions)

def analyze_network(hosts):
    """分析网络地址(内网/公网IP分类)"""
    return _NetworkAnalyzer.analyze(hosts)

def analyze_full(apk_path):
    """一键全量分析：结构 + Manifest + DEX + 签名 + 权限 + 混淆 + 加固 + 安全 + SO

    单次打开APK，一次性完成所有分析，避免重复IO
    """
    result = {'apk_path': apk_path, 'file_size': os.path.getsize(apk_path)}

    with _APKContext(apk_path) as ctx:
        # 1. 结构摘要
        result['structure'] = ctx.get_structure_summary()

        # 2. Manifest
        try:
            md = ctx.get_manifest_xml()
            result['manifest'] = get_manifest_info(md)
        except Exception:
            result['manifest'] = {}

        # 3. DEX分析 + 类名 + 字符串提取（一次性完成）
        dex_files = ctx.get_dex_files()
        result['dex_summary'] = []
        class_names = []
        all_dex_strings = []  # 统一提取，避免重复IO
        for d in dex_files:
            try:
                data = ctx.read_file(d)
                dp = _DexParser(data)
                dp.parse_header()
                result['dex_summary'].append({'name': d, 'size': len(data), **dp.get_summary()})
                class_names.extend(dp.get_class_names())
                all_dex_strings.extend(dp.get_strings())
            except Exception as e:
                result['dex_summary'].append({'name': d, 'error': str(e)})

        # 4. 签名验证
        result['signature'] = _SignVerifier.verify_all(ctx.zip, apk_path)

        # 5. SO文件分析
        so_files = ctx.get_so_files()
        result['abi_architectures'] = list(set(s.split('/')[0] for s in so_files if '/' in s))
        result['native_analysis'] = {}
        for s in so_files:
            try:
                data = ctx.read_file(s)
                result['native_analysis'][s] = analyze_elf(data)
            except Exception as e:
                result['native_analysis'][s] = {'error': str(e)}

        # 6. 权限分析
        raw_perms = result['manifest'].get('permissions', [])
        perm_names = [p.split('.')[-1] if '.' in p else p for p in raw_perms]
        result['permissions'] = analyze_permissions(perm_names)

        # 7. 混淆检测
        result['obfuscation'] = detect_obfuscation(class_names)

        # 8. 加固检测
        packers = detect_packer(ctx.zip)
        result['packers'] = packers

        # 9. 安全评估
        result['security'] = security_analyze(
            result['manifest'],
            result['permissions'],
            result['obfuscation'].get('score', 0),
            packers,
        )

        # 10. 线索串联分析 - 自动发现跨模块可疑信号（使用已提取的字符串）
        all_files = ctx.list_files() if hasattr(ctx, 'list_files') else []
        try:
            assets_files = [f for f in all_files if f.startswith('assets/')]

            result['clue_chain'] = _ClueChain.analyze(
                manifest=result['manifest'],
                class_names=class_names,
                native_analysis=result.get('native_analysis'),
                so_files=[s.split('/')[-1] for s in so_files] if so_files else [],
                assets_files=assets_files,
                permissions=perm_names,
                packers=packers,
                obfuscation_score=result['obfuscation'].get('score', 0),
                signature=result['signature'],
                dex_strings=all_dex_strings,
                ad_analysis=result.get('ad_analysis'),
                string_analysis=result.get('string_analysis'),
                resource_obfuscation=result.get('resource_obfuscation'),
            )
        except Exception as e:
            result['clue_chain'] = {'error': str(e), 'clues': [], 'score': 0, 'level': 'unknown'}

        # 11. SDK检测（新增）
        try:
            result['sdk_analysis'] = _SDKDetector.analyze(
                class_names=class_names,
                strings=all_dex_strings,
                permissions=perm_names,
            )
        except Exception as e:
            result['sdk_analysis'] = {'error': str(e)}

        # 12. 字符串深度分析（新增）
        try:
            result['string_analysis'] = _StringAnalyzer.analyze(all_dex_strings)
        except Exception as e:
            result['string_analysis'] = {'error': str(e)}

        # 13. 资源混淆检测（新增）
        try:
            result['resource_obfuscation'] = _ResourceObfuscationDetector.analyze(file_list=all_files)
        except Exception as e:
            result['resource_obfuscation'] = {'error': str(e)}

        # 14. 广告检测（新增）
        try:
            result['ad_analysis'] = _AdDetector.analyze(
                class_names=class_names,
                strings=all_dex_strings,
                permissions=perm_names,
            )
        except Exception as e:
            result['ad_analysis'] = {'error': str(e)}

        # 15. 社交登录检测（微信/QQ/GitHub/支付宝等）
        try:
            result['social_login_analysis'] = _SocialLoginDetector.analyze(
                class_names=class_names,
                strings=all_dex_strings,
            )
        except Exception as e:
            result['social_login_analysis'] = {'error': str(e)}

    return result

def clue_chain_analyze(manifest=None, class_names=None, native_analysis=None,
                       so_files=None, assets_files=None, permissions=None,
                       packers=None, obfuscation_score=None, signature=None,
                       apk_structure=None, dex_strings=None, dex_summary=None,
                       ad_analysis=None, string_analysis=None,
                       resource_obfuscation=None):
    """线索串联分析 - 跨模块关联，自动发现可疑信号

    将 Manifest / DEX / SO / Assets / 权限 等维度的分析结果交叉关联，
    自动发现跨模块的可疑模式，生成综合风险评分和线索列表。

    返回:
        dict: {
            'clues': [...],    # 所有关联线索
            'risks': [...],    # 风险标记列表
            'tags': [...],     # 特征标签
            'score': 0-100,    # 综合风险评分
            'level': 'low'|'medium'|'high',
            'summary': {...},  # 总结
        }
    """
    return _ClueChain.analyze(
        manifest=manifest, class_names=class_names,
        native_analysis=native_analysis, so_files=so_files,
        assets_files=assets_files, permissions=permissions,
        packers=packers, obfuscation_score=obfuscation_score,
        signature=signature, apk_structure=apk_structure,
        dex_strings=dex_strings, dex_summary=dex_summary,
        ad_analysis=ad_analysis, string_analysis=string_analysis,
        resource_obfuscation=resource_obfuscation,
    )

# ============================================================
# 核心类定位 - Core Class Locator
# ============================================================

def locate_core_classes(dex_data, top_n=20, min_score=10, include_sdk=False):
    """从DEX原始数据中定位核心类（多维度启发式评分）

    Args:
        dex_data: DEX文件二进制数据
        top_n: 返回前N个
        min_score: 最低分数阈值
        include_sdk: 是否包含SDK类

    Returns:
        list[dict]: 按综合评分排序的核心类列表
    """
    from apk_reverse_engine.analysis.core_class_locator import locate_core_classes as _lcc
    return _lcc(dex_data, top_n=top_n, min_score=min_score, include_sdk=include_sdk)

def locate_core_classes_from_apk(apk_path, top_n=20, min_score=10, include_sdk=False, use_manifest=False):
    """从APK中读取所有DEX并定位核心类

    Args:
        apk_path: APK文件路径
        top_n: 返回前N个
        min_score: 最低分数
        include_sdk: 是否包含SDK类
        use_manifest: 是否结合Manifest信息

    Returns:
        dict: {'dex_files': {...}, 'merged': [...]}
    """
    from apk_reverse_engine.analysis.core_class_locator import locate_core_classes_from_apk as _lccfa
    return _lccfa(apk_path, top_n=top_n, min_score=min_score,
                   include_sdk=include_sdk, use_manifest=use_manifest)

# ============================================================
# 增强逆向新功能 - Analysis Extensions
# ============================================================

def compare_apks(apk1_path, apk2_path, manifest1=None, manifest2=None,
                 classes1=None, classes2=None, perms1=None, perms2=None):
    """对比两个APK的结构/文件/类/权限差异"""
    return _APKDiffEngine.compare_full(apk1_path, apk2_path, manifest1, manifest2,
                                        classes1, classes2, perms1, perms2)

def extract_endpoints(strings):
    """从DEX字符串中深度提取网络端点(URL/IP/域名/API路径/端口)"""
    return _EndpointExtractor.extract_all(strings)

def scan_keys(strings):
    """扫描DEX字符串中的硬编码密钥/凭证/令牌"""
    return _KeyScanner.scan_strings(strings)

def detect_weak_crypto(strings):
    """检测弱加密算法使用"""
    return _KeyScanner.detect_weak_crypto(strings)

def analyze_cert_deep(cert_info):
    """深度分析证书安全性(调试证书/有效期/CA/哈希)"""
    return _CertDeepAnalyzer.analyze(cert_info)

def analyze_apk_clean(apk_path):
    """分析APK冗余文件及清理优化建议"""
    return _APKCleaner.analyze(apk_path)

def clean_apk(apk_path, output_path, remove_debug=True, remove_meta=False, remove_backup=True):
    """清理APK冗余文件并输出新APK（清理后需重新签名）"""
    return _APKCleaner.clean_apk(apk_path, output_path, remove_debug, remove_meta, remove_backup)

def detect_sdks(class_names):
    """从DEX类名列表中检测第三方SDK/追踪器"""
    return _SDKDetector.detect_from_class_names(class_names)

def analyze_sdk_privacy(class_names=None, strings=None, permissions=None):
    """一站式SDK检测与隐私风险评估"""
    return _SDKDetector.analyze(class_names, strings, permissions)

def analyze_strings(strings):
    """DEX 字符串深度分析（分类/敏感信息/URL提取）"""
    return _StringAnalyzer.analyze(strings)

def detect_resource_obfuscation(file_list=None, r_class_content=None,
                                 arsc_packages=None, layout_files=None):
    """资源混淆检测"""
    return _ResourceObfuscationDetector.analyze(file_list, r_class_content, arsc_packages, layout_files)

def manifest_edit(xml_text, **changes):
    """批量修改 AndroidManifest 属性

    Args:
        xml_text: 文本格式的 AndroidManifest.xml
        **changes: 属性名=值，如 debuggable='true', allowBackup='false'

    Returns:
        str: 修改后的 XML 文本
    """
    return _ManifestEditor.batch_set(xml_text, changes)

def manifest_enable_debuggable(xml_text):
    """开启 debuggable"""
    return _ManifestEditor.enable_debuggable(xml_text)

def manifest_disable_debuggable(xml_text):
    """关闭 debuggable"""
    return _ManifestEditor.disable_debuggable(xml_text)

def manifest_set_exported(xml_text, component_name, exported=True):
    """设置组件 exported 属性"""
    return _ManifestEditor.set_exported(xml_text, component_name, exported)

def detect_ads(class_names=None, strings=None, permissions=None):
    """一站式广告检测 - 识别APK中的广告SDK/代码模式/权限/URL

    返回:
        dict: {
            'ad_sdks': [...],     # 检测到的广告SDK
            'code_patterns': {...}, # 广告代码模式
            'permissions': {...},   # 广告相关权限
            'ad_urls': {...},      # 广告网络URL
            'ad_strings': [...],   # 广告字符串特征
            'score': 0-100,        # 广告密度评分
            'level': '无广告/轻度广告/有广告/密集广告',
            'summary': {...},
        }
    """
    return _AdDetector.analyze(class_names, strings, permissions)

def detect_social_login(class_names=None, strings=None):
    """一站式社交登录检测 - 识别 APK 中的微信/QQ/GitHub/支付宝/Google/Facebook/Apple/Twitter/微博登录

    返回:
        dict: {
            'detected_platforms': {...},  # 各平台检测详情
            'platform_details': [...],    # 按置信度排序的平台列表
            'total_platforms': int,       # 检测到的平台数
            'score': 0-100,               # 综合集成评分
            'level': str,                 # 等级: 无/少量/多平台/密集
            'has_social_login': bool,
            'summary': {...},
        }
    """
    return _SocialLoginDetector.analyze(class_names, strings)

# ============================================================
# 基础操作工具 - APK 文件 & AXML Manifest
# ============================================================

from .core.apk_file_ops import (
    list_apk_files as apk_list_files,
    delete_files_from_apk,
    delete_files_by_pattern,
    update_file_in_apk,
    add_file_to_apk,
)
from .core.manifest_ops import (
    find_tags,
    remove_tags,
    remove_tags_by_rule,
    remove_component,
    replace_attr_value,
    replace_launcher_activity,
    get_attr_value,
    get_all_attr_values,
)

# ============================================================
# 弹窗去除模块 - Popup Remover（默认关闭，用户提出时启用）
# 启用方式: from apk_reverse_engine.popup_remover import remove_share_popup
# ============================================================
# 默认不导入，仅按需加载

# ============================================================
# 补丁模块 - Patching
# ============================================================

from .patching.smali_patcher import SmaliPatcher as _SmaliPatcher
from .patching.manifest_patcher import ManifestPatcher as _ManifestPatcher
from .patching.integrity_patcher import IntegrityPatcher as _IntegrityPatcher
from .patching.native_patcher import NativePatcher as _NativePatcher
from .patching.resource_patcher import ResourcePatcher as _ResourcePatcher

def smali_patch_return(smali_code, return_value):
    """在smali方法中注入return语句"""
    return _SmaliPatcher.inject_return(smali_code, return_value)

def smali_patch_condition(smali_code, target_label, always_jump=True):
    """修改smali条件跳转"""
    return _SmaliPatcher.modify_condition(smali_code, target_label, always_jump)

def smali_bypass_signature(smali_code):
    """绕过签名校验(将检查结果改为0)"""
    return _SmaliPatcher.bypass_signature_check(smali_code)

def manifest_patch(data, changes):
    """批量修改AndroidManifest属性(changes: {name: value})"""
    return _ManifestPatcher.batch_patch(data, changes)

def manifest_set_debuggable(data, enable=True):
    """设置android:debuggable"""
    return _ManifestPatcher.set_debuggable(data, enable)

def manifest_allow_backup(data, enable=True):
    """设置android:allowBackup"""
    return _ManifestPatcher.set_allow_backup(data, enable)

def integrity_patch_debug(data):
    """绕过反调试检查"""
    return _IntegrityPatcher.patch_anti_debug(data)

def integrity_patch_root(data):
    """绕过root检测"""
    return _IntegrityPatcher.patch_root_check(data)

def native_patch_hex(data, old_hex, new_hex):
    """SO文件16进制替换"""
    return _NativePatcher.patch_hex(data, old_hex, new_hex)

def native_patch_string(data, old_str, new_str, max_replace=1):
    """SO文件字符串替换"""
    return _NativePatcher.patch_string(data, old_str, new_str, max_replace)

def native_patch_bytes(data, offset, new_bytes):
    """SO文件指定偏移写入字节"""
    return _NativePatcher.patch_bytes(data, offset, new_bytes)

def native_patch_ret(data, offset, arch='aarch64'):
    """将分支指令替换为返回指令"""
    return _NativePatcher.patch_branch_to_ret(data, offset, arch)

def native_nop_out(data, offset, count=4):
    """用NOP填充指定区域"""
    return _NativePatcher.nop_out(data, offset, count)

def native_patch_elf_entry(data, new_entry_offset):
    """修改ELF入口点"""
    return _NativePatcher.patch_elf_entrypt(data, new_entry_offset)

def resource_patch_arsc(data, old_str, new_str):
    """替换ARSC中的UTF-16LE字符串"""
    return _ResourcePatcher.patch_arsc(data, old_str, new_str)

def resource_patch_package_name(data, new_package_name):
    """修改ARSC中的包名"""
    return _ResourcePatcher.patch_arsc_package_name(data, new_package_name)

# ============================================================
# 工具模块 - Tools
# ============================================================

from .tools.unpacker import APKUnpacker as _APKUnpacker
from .tools.repacker import APKRepacker as _APKRepacker
from .tools.signer import APKSigner as _APKSigner
from .tools.searcher import APKSearch as _APKSearch
from .tools.decompiler import APKDecompiler as _APKDecompiler
from .tools.converter import APKConverter as _APKConverter
from .tools.merger import APKMerger as _APKMerger

def unpack_apk(apk_path, output_dir, structure=True):
    """解压APK原始文件（支持分类归档）"""
    return _APKUnpacker.extract_raw(apk_path, output_dir, structure=structure)

def extract_selective(apk_path, output_dir, include_types=None, exclude_types=None,
                      include_pattern=None, exclude_pattern=None, structure=True):
    """选择性提取APK文件"""
    return _APKUnpacker.extract_selective(apk_path, output_dir, include_types, exclude_types,
                                          include_pattern, exclude_pattern, structure)

def extract_parallel(apk_path, output_dir, max_workers=4, structure=True):
    """多线程并行解压APK"""
    return _APKUnpacker.extract_parallel(apk_path, output_dir, max_workers, structure)

def extract_incremental(apk_path, output_dir, structure=True, flatten=False):
    """增量解压APK（跳过已存在且大小一致的文件）"""
    return _APKUnpacker.extract_incremental(apk_path, output_dir, structure, flatten)

def extract_by_category(apk_path, output_dir, categories=None, structure=True):
    """按分类提取APK文件（dex/lib/res/assets/meta_inf/all）"""
    return _APKUnpacker.extract_by_category(apk_path, output_dir, categories, structure)

def verify_unpack(apk_path, output_dir):
    """校验解压完整性"""
    return _APKUnpacker.verify_integrity(apk_path, output_dir)

def extract_dex(apk_path, output_dir):
    """提取APK中所有DEX文件"""
    return _APKUnpacker.extract_dex(apk_path, output_dir)

def extract_so(apk_path, output_dir):
    """提取APK中所有SO文件"""
    return _APKUnpacker.extract_so(apk_path, output_dir)

def extract_resources(apk_path, output_dir):
    """提取APK资源文件(res/ + assets/)"""
    return _APKUnpacker.extract_resources(apk_path, output_dir)

def apktool_decode(apk_path, output_dir, force=False, no_src=False, no_res=False):
    """使用apktool解包APK"""
    return _APKUnpacker.apktool_decode(apk_path, output_dir, force, no_src, no_res)

def apktool_build(decoded_dir, output_apk, force=False, aapt=None):
    """使用apktool重打包"""
    return _APKRepacker.apktool_build(decoded_dir, output_apk, force, aapt)

def zip_rebuild(input_dir, output_apk, compression=zipfile.ZIP_DEFLATED):
    """从目录重建APK/ZIP"""
    return _APKRepacker.zip_rebuild(input_dir, output_apk, compression)

def zip_update(apk_path, file_entries):
    """更新APK中的文件(file_entries: {arcname: data_bytes})"""
    return _APKRepacker.zip_update(apk_path, file_entries)

def zipalign(apk_path, output_path=None):
    """执行Zipalign 4字节对齐"""
    return _APKRepacker.zipalign(apk_path, output_path)

def sign_debug(apk_path, output_apk):
    """使用debug密钥签名APK"""
    return _APKSigner.sign_debug(apk_path, output_apk)

def sign_apk(apk_path, output_apk, keystore_path, keystore_pass, key_alias, key_pass):
    """使用自定义密钥签名APK"""
    return _APKSigner.sign_with_keystore(apk_path, output_apk, keystore_path, keystore_pass, key_alias, key_pass)

def search_apk(apk_path, query, scope='all', max_results=100):
    """在APK中搜索字符串/类名/方法名"""
    return _APKSearch.search_in_apk(apk_path, query, scope, max_results)

def jadx_decompile(apk_path, output_dir, deobf=True, show_inconsistent=False, options=None):
    """使用JADX反编译APK为Java源码"""
    return _APKDecompiler.jadx_decompile(apk_path, output_dir, deobf, show_inconsistent, options)

def androguard_analyze(apk_path, output_dir):
    """使用Androguard分析APK"""
    return _APKDecompiler.androguard_decompile(apk_path, output_dir)

def dex2jar(dex_path, output_jar):
    """DEX转JAR"""
    return _APKConverter.dex_to_jar(dex_path, output_jar)

def jar2dex(jar_path, output_dex):
    """JAR转DEX"""
    return _APKConverter.jar_to_dex(jar_path, output_dex)

def dex2smali(dex_path, output_dir):
    """DEX转Smali(baksmali)"""
    return _APKConverter.dex_to_smali(dex_path, output_dir)

def smali2dex(smali_dir, output_dex):
    """Smali转DEX(smali)"""
    return _APKConverter.smali_to_dex(smali_dir, output_dex)

def merge_apks(apk_list, output_path):
    """合并多个APK"""
    return _APKMerger.merge_apks(apk_list, output_path)

def merge_dex(apk_path, output_path):
    """合并多DEX为单个classes.dex"""
    return _APKMerger.merge_dex(apk_path, output_path)

# ============================================================
# 工具函数 - Utilities
# ============================================================

from .utils.file_utils import FileUtils as _FileUtils
from .utils.smali_utils import SMALIUtils as _SMALIUtils
from .utils.cert_utils import CertUtils as _CertUtils
from .utils.logger import Logger as _Logger
from .utils.i18n import _, set_lang, get_lang, LANGUAGES, LANG_CODES, save_lang, language_name, register as i18n_register
from .tools.resource_lang import ResourceLanguageTool

def ensure_dir(path):
    """确保目录存在，不存在则创建"""
    return _FileUtils.ensure_dir(path)

def safe_delete(path):
    """安全删除文件或目录"""
    return _FileUtils.safe_delete(path)

def get_temp_dir(prefix='reng_'):
    """创建临时目录"""
    return _FileUtils.get_temp_dir(prefix)

def copy_file(src, dst):
    """复制文件"""
    return _FileUtils.copy_file(src, dst)

def human_size(size):
    """格式化文件大小为可读字符串"""
    return _FileUtils.human_size(size)

def file_sha256(filepath):
    """计算文件SHA256"""
    return _FileUtils.file_hash(filepath, 'sha256')

def file_md5(filepath):
    """计算文件MD5"""
    return _FileUtils.file_hash(filepath, 'md5')

def safe_write(path, data, mode='wb'):
    """安全写入文件(先写临时文件再替换)"""
    return _FileUtils.safe_write(path, data, mode)

def merge_files(file_list, output_path):
    """合并多个文件"""
    return _FileUtils.merge_files(file_list, output_path)

def smali_parse_class(text):
    """解析smali类头信息"""
    return _SMALIUtils.parse_class_header(text)

def smali_find_methods(text):
    """查找smali中所有方法定义"""
    return _SMALIUtils.find_methods(text)

def smali_find_strings(text):
    """查找smali中所有字符串常量"""
    return _SMALIUtils.find_strings(text)

def smali_extract_method(text, method_name):
    """提取指定方法的smali代码"""
    return _SMALIUtils.extract_method_bodies(text, method_name)

def smali_find_invokes(text, target_class=None):
    """查找smali中所有invoke调用"""
    return _SMALIUtils.find_invoke(text, target_class)

def smali_analyze_method(method_smali):
    """全面分析smali方法(调用/字符串/寄存器/常量/条件)"""
    return _SMALIUtils.analyze_method(method_smali)

def cert_parse(data):
    """解析X.509 DER证书(序列号/签发者/主题/有效期/哈希)"""
    return _CertUtils.parse_certificate(data)

def cert_info(data):
    """获取证书摘要信息(兼容旧接口)"""
    return _CertUtils.get_cert_info(data)

Logger = _Logger
"""日志工具类，用法: log = Logger('name', 'INFO')"""

__all__ = [
    # Core
    'open_apk', 'list_apk_files', 'read_apk_file', 'extract_apk', 'apk_structure',
    'parse_manifest', 'get_manifest_info',
    'parse_dex', 'dex_header', 'dex_summary', 'dex_classes', 'dex_class_names',
    'dex_search_classes', 'dex_search_methods', 'dex_strings', 'dex_methods',
    'is_elf', 'analyze_elf', 'parse_elf', 'elf_imports', 'elf_exports',
    'elf_find_strings', 'elf_detect_crypto', 'elf_detect_packer',
    'verify_signature_v1', 'verify_signature_v2', 'verify_signature', 'extract_cert_sha256',
    'parse_arsc',
    # Analysis
    'static_analyze', 'analyze_permissions', 'detect_obfuscation', 'detect_packer',
    'detect_anti_tamper', 'detect_reflection', 'detect_string_encryption',
    'security_analyze', 'analyze_code', 'analyze_network', 'analyze_full',
    'clue_chain_analyze',
    # Analysis Extensions
    'compare_apks', 'extract_endpoints', 'scan_keys', 'detect_weak_crypto',
    'detect_sdks', 'analyze_sdk_privacy',
    'analyze_cert_deep', 'analyze_apk_clean', 'clean_apk',
    'analyze_strings', 'detect_resource_obfuscation',
    'manifest_edit', 'manifest_enable_debuggable', 'manifest_disable_debuggable',
    'manifest_set_exported',
    'detect_ads',
    'detect_social_login',
    # Deobfuscation
    'deobfuscate_analyze',
    # Code Analysis
    'analyze_code', 'analyze_danger_summary', 'build_cfg', 'analyze_method',
    # Patching
    'smali_patch_return', 'smali_patch_condition', 'smali_bypass_signature',
    'manifest_patch', 'manifest_set_debuggable', 'manifest_allow_backup',
    'integrity_patch_debug', 'integrity_patch_root',
    'native_patch_hex', 'native_patch_string', 'native_patch_bytes',
    'native_patch_ret', 'native_nop_out', 'native_patch_elf_entry',
    'resource_patch_arsc', 'resource_patch_package_name',
    # Tools
    'unpack_apk', 'extract_dex', 'extract_so', 'extract_resources',
'extract_selective', 'extract_parallel', 'extract_incremental', 'extract_by_category', 'verify_unpack',
    'apktool_decode', 'apktool_build', 'zip_rebuild', 'zip_update', 'zipalign',
    'sign_debug', 'sign_apk', 'search_apk',
    'jadx_decompile', 'androguard_analyze',
    'dex2jar', 'jar2dex', 'dex2smali', 'smali2dex',
    'merge_apks', 'merge_dex',
    # Utils
    'ensure_dir', 'safe_delete', 'get_temp_dir', 'copy_file', 'human_size',
    'file_sha256', 'file_md5', 'safe_write', 'merge_files',
    'smali_parse_class', 'smali_find_methods', 'smali_find_strings',
    'smali_extract_method', 'smali_find_invokes', 'smali_analyze_method',
    'cert_parse', 'cert_info', 'Logger', 'AXMLConverter',
    # i18n
    '_', 'set_lang', 'get_lang', 'LANGUAGES', 'LANG_CODES', 'save_lang', 'language_name', 'i18n_register',
    # Resource Language
    'ResourceLanguageTool',
    # Core Class Locator
    'locate_core_classes', 'locate_core_classes_from_apk',
]
