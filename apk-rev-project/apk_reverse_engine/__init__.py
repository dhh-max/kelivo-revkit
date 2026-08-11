"""APK Reverse Engineering Engine v2 - 全模块基础功能API"""
import os, zipfile

__version__ = '2.9.0'

# ============================================================
# 核心模块 - Core
# ============================================================

# --- APK上下文 ---
from .core.archive_context import ArchiveContext as _APKContext

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
from .analysis.ad_remover import AdRemover as _AdRemover
from .analysis.deobfuscator import Deobfuscator as _Deobfuscator
from .analysis.social_login_detector import SocialLoginDetector as _SocialLoginDetector
from .analysis.ad_ai_engine import AdAIEngine as _AdAIEngine
from .analysis.ad_ai_engine import DEFAULT_MODEL as _DEFAULT_MODEL
DEFAULT_MODEL = _DEFAULT_MODEL
from .analysis.ad_ai_engine import analyze_ad_code as _analyze_ad_code
from .analysis.ad_ai_engine import analyze_ad_code_stream as _analyze_ad_code_stream
from .analysis.ad_ai_engine import analyze_ad_code_stream_batch as _analyze_ad_code_stream_batch
from .analysis.ad_ai_engine import analyze_ad_code_batch as _analyze_ad_code_batch
from .analysis.ad_ai_engine import prefilter_ad_code as _prefilter_ad_code
from .analysis.ad_ai_engine import list_ai_models as _list_ai_models

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

# ── 增强分析模块 (DEX指令级深度分析) ──
from .analysis.enhanced import (
    DexDataFlowAnalyzer as _DexDataFlowAnalyzer,
    TaintTracker as _TaintTracker,
    CallGraphBuilder as _CallGraphBuilder,
    StringDecryptor as _StringDecryptor,
    AntiAnalysisDetector as _AntiAnalysisDetector,
    CryptoAnalyzer as _CryptoAnalyzer,
    HookGenerator as _HookGenerator,
    VulnerabilityScanner as _VulnerabilityScanner,
    OptimizationPatternDetector as _OptimizationPatternDetector,
    DexMetadataAnalyzer as _DexMetadataAnalyzer,
    MultiDexAnalyzer as _MultiDexAnalyzer,
    ReportGenerator as _ReportGenerator,
    NativeCrossRefAnalyzer as _NativeCrossRefAnalyzer,
)
from .core.dex.reaching_defs import ReachingDefinitions as _ReachingDefinitions
from .core.dex.reaching_defs import LiveVariables as _LiveVariables
from .core.dex.type_inference import TypeInference as _TypeInference

def analyze_dataflow(dex_parser, class_name, method_name=None):
    """DEX数据流分析 - 寄存器追踪、污点分析、常量传播"""
    return _DexDataFlowAnalyzer(dex_parser).analyze_method_dataflow(class_name, method_name)

def trace_register(dex_parser, class_name, method_name, target_reg):
    """追踪指定寄存器的所有读写位置"""
    return _DexDataFlowAnalyzer(dex_parser).trace_register(class_name, method_name, target_reg)

def propagate_constants(dex_parser, class_name, method_name):
    """常量传播分析 - 追踪方法内所有常量值的流动"""
    return _DexDataFlowAnalyzer(dex_parser).propagate_constants(class_name, method_name)

def build_call_graph(dex_parser):
    """从 DexParser 构建全量方法调用图"""
    return _CallGraphBuilder.build_call_graph(dex_parser)

def find_callers(call_graph, target_class, target_method=None):
    """反向查找谁调用了指定方法"""
    return _CallGraphBuilder.find_callers(call_graph, target_class, target_method)

def find_callees(call_graph, source_class, source_method=None):
    """正向查找指定方法调用了哪些方法"""
    return _CallGraphBuilder.find_callees(call_graph, source_class, source_method)

def find_entry_points(call_graph):
    """查找入口点 - 没有被任何内部方法调用的方法"""
    return _CallGraphBuilder.find_entry_points(call_graph)

def find_hotspots(call_graph, top_n=20):
    """查找热点方法 - 被调用次数最多的方法"""
    return _CallGraphBuilder.find_hotspots(call_graph, top_n)

def detect_recursive(call_graph):
    """检测递归调用（直接/间接）"""
    return _CallGraphBuilder.detect_recursive(call_graph)

def auto_decrypt_strings(byte_array):
    """自动尝试多种解密方式解密字节数组"""
    return _StringDecryptor.auto_decrypt_bytes(byte_array)

def find_encrypted_strings(smali_text):
    """在smali代码中查找加密字符串模式"""
    return _StringDecryptor.find_encrypted_strings_in_smali(smali_text)

def analyze_decrypt_pattern(dex_parser, class_name=None):
    """分析DEX中的解密模式"""
    return _StringDecryptor.analyze_decrypt_pattern(dex_parser, class_name)

def detect_anti_analysis(text, class_names=None, strings=None):
    """一站式检测所有反分析措施（反调试/反Root/反模拟器/完整性校验等）"""
    return _AntiAnalysisDetector.detect_all(text, class_names, strings)

def detect_timing_checks(instructions):
    """检测基于时间差的反调试"""
    return _AntiAnalysisDetector.detect_timing_checks(instructions)

def analyze_crypto(text=None, class_names=None, strings=None, native_data=None):
    """全面加密分析 - 算法/模式/哈希/弱加密/密钥管理"""
    return _CryptoAnalyzer.analyze(text, class_names, strings, native_data)

def generate_frida_hook(target_class, target_method=None, verbose=False,
                        trace_args=False, trace_return=False, bypass_flags=None):
    """生成Frida hook脚本"""
    return _HookGenerator.generate_frida_script(target_class, target_method, verbose,
                                                 trace_args, trace_return, bypass_flags)

def generate_xposed_module(package_name, target_class, target_method=None, bypass_flags=None):
    """生成Xposed模块代码"""
    return _HookGenerator.generate_xposed_module(package_name, target_class, target_method, bypass_flags)

def generate_smali_patch(target_class, target_method, patch_type='bypass_return', return_value='0x0'):
    """生成smali补丁代码片段"""
    return _HookGenerator.generate_smali_patch(target_class, target_method, patch_type, return_value)

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

def remove_ads(smali_root, assets_dir=None, manifest_path=None, options=None):
    """一键移除APK广告 - 8大SDK定向移除 + 9组正则通杀 + assets清理 + manifest清理

    支持: 腾讯/快手/穿山甲/百度/头条/Sigmob/谷歌/米盟 + 正则通杀 + assets清理

    Args:
        smali_root: 解码后的APK根目录（含smali/目录）
        assets_dir: assets目录路径（可选）
        manifest_path: AndroidManifest.xml路径（可选）
        options: 选项字典，控制各SDK开关

    Returns:
        dict: {
            'total_patched': int,    # 总补丁数
            'total_files': int,     # 修改文件数
            'sdks': {...},          # 各SDK移除详情
            'regex': {...},         # 正则通杀结果
            'assets': {...},        # assets清理结果
            'manifest': {...},      # manifest清理结果
        }
    """
    return _AdRemover.remove_all(smali_root, assets_dir, manifest_path, options)

def detect_ad_sdks(smali_root):
    """检测APK中集成的广告SDK

    Args:
        smali_root: 解码后的APK根目录

    Returns:
        list: 检测到的SDK key列表
    """
    return _AdRemover.detect_ad_sdks(smali_root)

def ai_analyze_ad_code(code, api_key, model=DEFAULT_MODEL,
                        source_language="smali", question="",
                        question_mode="direct", api_url="", options=None):
    """AI 广告识别分析 - 使用 LLM 智能分析代码中的广告接口（带自动重试和速率限制）

    Args:
        code: 待分析代码
        api_key: API 密钥（SiliconFlow/OpenAI 兼容）
        model: 模型ID
        source_language: 源语言 (smali/java/xml/javascript)
        question: 补充模式下的问题
        question_mode: 'direct' 直连分析 / 'supplement' 补充问答
        api_url: 自定义 API 地址
        options: 可选配置（SDK检测范围/自定义关键词等）

    Returns:
        AI 分析结果文本
    """
    return _analyze_ad_code(code, api_key, model, source_language, question, question_mode, api_url, options)

def ai_analyze_ad_code_stream(code, api_key, model=DEFAULT_MODEL,
                               source_language="smali", question="",
                               question_mode="direct", api_url="", options=None):
    """流式 AI 广告分析 - 逐步返回结果片段

    Args:
        同 ai_analyze_ad_code()

    Yields:
        str: 逐步返回的分析文本片段
    """
    yield from _analyze_ad_code_stream(code, api_key, model, source_language,
                                        question, question_mode, api_url, options)

def ai_prefilter_ad_code(code, class_name='', method_name='', custom_keywords=''):
    """智能预筛选代码片段是否包含广告相关内容

    使用 AdDetector 模式库快速预筛，减少不必要的 AI 分析调用

    Args:
        code: 代码片段
        class_name: 类名
        method_name: 方法名
        custom_keywords: 用户自定义关键词（逗号分隔）

    Returns:
        (is_ad_related, score): 是否广告相关, 相关度分数
    """
    return _prefilter_ad_code(code, class_name, method_name, custom_keywords)

def ai_list_ad_models(api_key="", api_url=""):
    """获取可用 AI 模型列表（用于广告分析）"""
    return _list_ai_models(api_key, api_url) or list(_AdAIEngine.FALLBACK_MODELS)


def ai_analyze_ad_code_batch(snippets, api_key, model=DEFAULT_MODEL,
                             source_language="smali", question="",
                             question_mode="direct", api_url="", options=None,
                             max_workers=0, on_complete=None, on_stream=None):
    """并发批量 AI 广告分析（最多5路同时输出）

    多个代码片段同时发送给 AI 分析，不同进程/对话可以同时使用同一供应商 API。
    使用线程池实现并发，最多 MAX_CONCURRENT（默认5）路同时请求。

    Args:
        snippets: 代码片段列表 [{'code': ..., 'class': ..., 'method': ..., 'score': ...}, ...]
        api_key: API 密钥
        model: 模型ID
        source_language: 源语言 (smali/java/xml/javascript)
        question: 补充问题
        question_mode: 'direct' 或 'supplement'
        api_url: 自定义 API 地址
        options: 可选配置
        max_workers: 并发数（0=自动使用 MAX_CONCURRENT=5）
        on_complete: 回调 fn(index, result_dict)
        on_stream: 回调 fn(index, text_chunk)，流式输出

    Returns:
        结果列表，顺序与输入一致
    """
    engine = _AdAIEngine(api_key=api_key, api_url=api_url)
    return engine.analyze_batch(snippets, source_language, model, question,
                                question_mode, options, max_workers, on_complete, on_stream)


def ai_analyze_ad_code_stream_batch(snippets, api_key, model=DEFAULT_MODEL,
                                    source_language="smali", question="",
                                    question_mode="direct", api_url="", options=None,
                                    max_workers=0):
    """并发流式批量 AI 广告分析 - 逐步 yield (index, text_chunk)

    多个代码片段同时流式分析，哪个先返回数据就先 yield，
    适合终端实时显示多路并发输出。

    Yields:
        (index, text_chunk): 片段索引和对应的文本片段
    """
    engine = _AdAIEngine(api_key=api_key, api_url=api_url)
    yield from engine.analyze_stream_batch(snippets, source_language, model,
                                           question, question_mode, options, max_workers)

def ai_save_analysis_to_kb(kb, code, analysis, class_name='', method_name='',
                            model='', score=0):
    """将 AI 广告分析结果保存到知识库（跨会话复用）

    Args:
        kb: KnowledgeBase 实例
        code: 原始代码片段
        analysis: AI 分析结果文本
        class_name: 类名
        method_name: 方法名
        model: 使用的模型
        score: 预筛选分数
    """
    engine = _AdAIEngine()
    return engine.save_analysis_to_kb(kb, code, analysis, class_name, method_name, model, score)

def ai_load_analysis_from_kb(kb, code, class_name='', method_name=''):
    """从知识库查找已保存的 AI 广告分析结果

    Args:
        kb: KnowledgeBase 实例
        code: 原始代码片段
        class_name: 类名
        method_name: 方法名

    Returns:
        分析结果文本，未找到返回 None
    """
    engine = _AdAIEngine()
    return engine.load_analysis_from_kb(kb, code, class_name, method_name)

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
# 弹窗去除模块 - Popup Remover（懒加载）
# ============================================================

def remove_share_popup(*args, **kwargs):
    """去除APK中的简单分享弹窗界面（懒加载 popup_remover 模块）"""
    from .popup_remover import remove_share_popup as _rsp
    return _rsp(*args, **kwargs)

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

def extract_manifest(apk_path, output_dir, manifest=None, structure=True,
                     fail_on_missing=True, verify=True):
    """按精确清单原子提取 + 校验"""
    return _APKUnpacker.extract_manifest(apk_path, output_dir, manifest,
                                         structure, fail_on_missing, verify)

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

# ============================================================
# 工作区管理 - Workspace（参照 Operit 工作区能力）
# ============================================================

from .workspace.manager import Workspace as _Workspace

def create_workspace(name, root=None, description='', apk_path=None):
    """创建新工作区"""
    return _Workspace.create(name, root, description, apk_path)

def list_workspaces(root=None):
    """列出所有工作区"""
    return _Workspace.list(root)

def open_workspace(name, root=None):
    """打开已有工作区"""
    return _Workspace.open(name, root)

def delete_workspace(name, root=None):
    """删除工作区"""
    return _Workspace.open(name, root).delete()

# ============================================================
# 设备集成 - ADB（参照 Operit 设备集成能力）
# ============================================================

from .device.adb import ADB as _ADB

def adb_devices():
    """列出已连接的 ADB 设备"""
    return _ADB.devices()

def adb_connect(host='127.0.0.1', port=5555):
    """连接 ADB 设备"""
    return _ADB().connect(host, port)

def adb_install(apk_path, device_id=None, reinstall=False, grant_permissions=False):
    """通过 ADB 安装 APK 到设备"""
    return _ADB(device_id).install(apk_path, reinstall, grant_permissions)

def adb_uninstall(package_name, device_id=None, keep_data=False):
    """通过 ADB 卸载设备上的应用"""
    return _ADB(device_id).uninstall(package_name, keep_data)

def adb_pull(remote, local, device_id=None):
    """从设备拉取文件到本地"""
    return _ADB(device_id).pull(remote, local)

def adb_push(local, remote, device_id=None):
    """推送本地文件到设备"""
    return _ADB(device_id).push(local, remote)

def adb_screenshot(output_path, device_id=None):
    """截取设备屏幕"""
    return _ADB(device_id).screenshot(output_path)

def adb_logcat(device_id=None, filter_spec=None, lines=50):
    """获取设备日志"""
    return _ADB(device_id).logcat(filter_spec, lines)

# ============================================================
# 知识库 - Knowledge Base（参照 Operit 持久记忆能力）
# ============================================================

from .knowledge.kb import KnowledgeBase as _KnowledgeBase
from .knowledge.kb import seed_default_knowledge as _seed_default_knowledge
from .knowledge.ad_templates import (
    get_template as _get_ad_template,
    get_sdk_template as _get_ad_sdk_template,
    format_analysis_prompt as _format_ad_analysis_prompt,
    get_blocking_suggestions as _get_ad_blocking_suggestions,
    get_common_keywords as _get_ad_common_keywords,
    get_obfuscated_analysis_guide as _get_ad_obfuscated_guide,
)

def create_knowledge_base(path=None):
    """创建或加载知识库"""
    return _KnowledgeBase(path)

def seed_knowledge(path=None):
    """写入内置加固/SDK/混淆特征到知识库"""
    return _seed_default_knowledge(path)

def get_ad_template(name):
    """按名称获取广告分析提示词模板"""
    return _get_ad_template(name)

def get_ad_sdk_template(sdk_key):
    """按SDK标识获取广告专项分析模板"""
    return _get_ad_sdk_template(sdk_key)

def format_ad_analysis_prompt(code_snippet, sdk_hint=''):
    """组装广告分析提示词（含SDK专项要点）"""
    return _format_ad_analysis_prompt(code_snippet, sdk_hint)

def get_ad_blocking_suggestions():
    """获取广告屏蔽建议模板"""
    return _get_ad_blocking_suggestions()

def get_ad_common_keywords():
    """获取广告常见关键词列表（用于预筛选）"""
    return _get_ad_common_keywords()

def get_ad_obfuscated_guide():
    """获取混淆代码分析指引模板"""
    return _get_ad_obfuscated_guide()

def get_all_ad_templates():
    """获取全部广告分析模板"""
    from .knowledge.ad_templates import get_all_templates as _gat
    return _gat()

def reload_ad_templates():
    """重新加载广告模板（XML 资源热更新）"""
    from .knowledge.ad_templates import reload as _rt
    return _rt()

# ============================================================
# 备份/恢复 - Snapshot（参照 Operit 本地备份能力）
# ============================================================

from .backup.snapshot import Snapshot as _Snapshot
from .backup.snapshot import export_analysis_result as _export_analysis_result

def export_workspace(workspace_dir, output_path=None, include_artifacts=False):
    """导出工作区为可移植 JSON 快照"""
    return _Snapshot.export(workspace_dir, output_path, include_artifacts)

def import_workspace(snapshot_path, target_dir=None, extract_artifacts=False):
    """从快照恢复工作区"""
    return _Snapshot.import_(snapshot_path, target_dir, extract_artifacts)

def export_analysis(apk_path, result, output_path=None, include_raw=False):
    """导出单次分析结果的可移植 JSON"""
    return _export_analysis_result(apk_path, result, output_path, include_raw)

# ============================================================
# Lite 模块 - 零外部依赖快速分析（懒加载）
# ============================================================

def unpack_apk_lite(apk_path, output_dir=None, **kwargs):
    """零依赖快速解包 APK（纯标准库，适合受限环境）

    Args:
        apk_path: APK 文件路径
        output_dir: 输出目录（默认自动生成临时目录）
        **kwargs: 额外参数透传

    Returns:
        dict: 解包结果摘要
    """
    from .lite.unpacker import unpack_apk_lite as _ual
    return _ual(apk_path, output_dir, **kwargs)

def analyze_apk_lite(apk_path, **kwargs):
    """零依赖快速分析 APK（结构/Manifest/DEX 摘要，纯标准库）
    Args:
        apk_path: APK 文件路径
        **kwargs: 额外参数透传
    Returns:
        dict: 分析结果
    """
    from .lite import analyze_apk_lite as _aal
    return _aal(apk_path, **kwargs)

def auto_find_apks(search_dir=None, **kwargs):
    """自动搜索目录中的 APK 文件
    Args:
        search_dir: 搜索目录（默认 /sdcard/Download）
        **kwargs: 额外参数透传
    Returns:
        list: 找到的 APK 路径列表
    """
    from .lite import auto_find_apks as _afa
    return _afa(search_dir, **kwargs)

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
    # Enhanced Analysis (DEX指令级深度分析)
    'analyze_dataflow', 'trace_register', 'propagate_constants',
    'build_call_graph', 'find_callers', 'find_callees',
    'find_entry_points', 'find_hotspots', 'detect_recursive',
    'auto_decrypt_strings', 'find_encrypted_strings', 'analyze_decrypt_pattern',
    'detect_anti_analysis', 'detect_timing_checks', 'analyze_crypto',
    'generate_frida_hook', 'generate_xposed_module', 'generate_smali_patch',
    # Deobfuscation
    'deobfuscate_analyze',
    # Code Analysis
    'analyze_danger_summary', 'build_cfg', 'analyze_method',
    # Patching
    'smali_patch_return', 'smali_patch_condition', 'smali_bypass_signature',
    'manifest_patch', 'manifest_set_debuggable', 'manifest_allow_backup',
    'integrity_patch_debug', 'integrity_patch_root',
    'native_patch_hex', 'native_patch_string', 'native_patch_bytes',
    'native_patch_ret', 'native_nop_out', 'native_patch_elf_entry',
    'resource_patch_arsc', 'resource_patch_package_name',
    # Tools
    'unpack_apk', 'extract_dex', 'extract_so', 'extract_resources',
'extract_selective', 'extract_parallel', 'extract_incremental', 'extract_by_category', 'verify_unpack', 'extract_manifest',
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
    # APK File Ops
    'apk_list_files', 'delete_files_from_apk', 'delete_files_by_pattern',
    'update_file_in_apk', 'add_file_to_apk',
    # Manifest Ops
    'find_tags', 'remove_tags', 'remove_tags_by_rule', 'remove_component',
    'replace_attr_value', 'replace_launcher_activity',
    'get_attr_value', 'get_all_attr_values',
    # i18n
    '_', 'set_lang', 'get_lang', 'LANGUAGES', 'LANG_CODES', 'save_lang', 'language_name', 'i18n_register',
    # Resource Language
    'ResourceLanguageTool',
    # Core Class Locator
    'locate_core_classes', 'locate_core_classes_from_apk',
    # Knowledge Base & Ad Templates
    'create_knowledge_base', 'seed_knowledge',
    'get_ad_template', 'get_ad_sdk_template', 'format_ad_analysis_prompt', 'get_ad_blocking_suggestions',
    'get_ad_common_keywords', 'get_ad_obfuscated_guide', 'get_all_ad_templates', 'reload_ad_templates',
    # Ad Remover
    'remove_ads', 'detect_ad_sdks',
    # Ad AI Engine
    'ai_analyze_ad_code', 'ai_analyze_ad_code_stream', 'ai_prefilter_ad_code', 'ai_list_ad_models',
    'ai_analyze_ad_code_batch', 'ai_analyze_ad_code_stream_batch',
    'ai_save_analysis_to_kb', 'ai_load_analysis_from_kb',
    # Popup Remover
    'remove_share_popup',
    # Lite（零依赖快速分析）
    'unpack_apk_lite', 'analyze_apk_lite', 'auto_find_apks',
    # 新增增强模块 API
    'analyze_reaching_defs', 'analyze_live_variables', 'infer_types',
    'scan_vulnerabilities', 'scan_vulnerabilities_strings',
    'scan_vulnerabilities_manifest', 'scan_vulnerabilities_dex',
    'analyze_optimization_patterns', 'analyze_method_optimization',
    # DEX 元数据深度分析
    'analyze_dex_metadata', 'analyze_annotations', 'analyze_debug_info',
    'detect_hidden_api', 'detect_annotation_processors', 'detect_serialization',
    # 多 DEX 关联分析
    'analyze_multidex', 'analyze_multidex_distribution',
    'analyze_cross_dex_references', 'detect_duplicate_classes',
    # Native-Java 交叉引用分析
    'analyze_native_crossref', 'analyze_native_methods', 'analyze_so_exports',
    'analyze_jni_callbacks', 'cross_reference_native',
    # 报告生成
    'generate_report', 'generate_json_report', 'generate_html_report',
    'generate_markdown_report',
]


# ============================================================
# 新增增强模块 API - Reaching Definitions / Live Variables / Type Inference / Vulnerability Scanner / Optimization Patterns
# ============================================================

def analyze_reaching_defs(instructions, cfg=None):
    """到达定义分析 - 对每个程序点计算哪些定义能到达此处

    Args:
        instructions: Instruction 列表
        cfg: 预构建 CFG（可选）

    Returns:
        dict: {def_use, in_sets, out_sets, ud_chain, du_chain}
    """
    return _ReachingDefinitions.analyze(instructions, cfg)

def analyze_live_variables(instructions, cfg=None):
    """活越变量分析 - 对每个程序点计算哪些变量在后续会被使用

    Args:
        instructions: Instruction 列表
        cfg: 预构建 CFG（可选）

    Returns:
        dict: {live_in, live_out, dead_defs}
    """
    return _LiveVariables.analyze(instructions, cfg)

def infer_types(instructions, cfg=None, strings=None, types=None, fields=None, methods=None):
    """DEX 寄存器类型推断 - 基于数据流推断每个程序点寄存器的类型

    Args:
        instructions: Instruction 列表
        cfg: 预构建 CFG（可选）
        strings: DEX 字符串池
        types: DEX 类型描述符列表
        fields: DEX 字段列表
        methods: DEX 方法列表

    Returns:
        dict: {register_types, type_changes, inconsistencies, parameter_types, wide_registers}
    """
    return _TypeInference.infer_method(instructions, cfg, strings, types, fields, methods)

def scan_vulnerabilities(strings_list=None, manifest_xml=None, dex_parser=None, call_graph=None):
    """安全漏洞扫描 - 基于静态分析检测 Android 安全漏洞

    扫描类别：组件暴露/Intent注入/SSL降级/WebView安全/SQLite注入/文件模式/动态加载/弱随机数/硬编码凭据

    Args:
        strings_list: DEX 字符串列表（可选）
        manifest_xml: Manifest XML 字符串（可选）
        dex_parser: DexParser 实例（可选，用于方法级扫描）
        call_graph: 预构建调用图（可选）

    Returns:
        dict: {total_findings, summary, categories, critical_findings, all_findings}
    """
    string_findings = []
    manifest_findings = []
    dex_findings = []

    if strings_list:
        string_findings = _VulnerabilityScanner.scan_strings(strings_list)
    if manifest_xml:
        manifest_findings = _VulnerabilityScanner.scan_manifest(manifest_xml)
    if dex_parser:
        dex_findings = _VulnerabilityScanner.scan_dex_methods(dex_parser, call_graph)

    return _VulnerabilityScanner.generate_report(string_findings, manifest_findings, dex_findings)

def scan_vulnerabilities_strings(strings_list):
    """扫描字符串池中的安全漏洞模式"""
    return _VulnerabilityScanner.scan_strings(strings_list)

def scan_vulnerabilities_manifest(manifest_xml):
    """扫描 AndroidManifest.xml 中的安全风险"""
    return _VulnerabilityScanner.scan_manifest(manifest_xml)

def scan_vulnerabilities_dex(dex_parser, call_graph=None):
    """扫描 DEX 方法中的安全漏洞"""
    return _VulnerabilityScanner.scan_dex_methods(dex_parser, call_graph)

def analyze_optimization_patterns(dex_parser, max_methods=100):
    """DEX 优化模式检测 - 检测 Dalvik 字节码中的编译器优化模式

    检测：常量折叠/死代码消除/寄存器分配/内联候选/代码膨胀/Switch优化/循环不变量/窥孔模式

    Args:
        dex_parser: DexParser 实例
        max_methods: 最大分析方法数

    Returns:
        dict: {analyzed_method_count, total_*, optimization_candidates, methods}
    """
    return _OptimizationPatternDetector.analyze_dex(dex_parser, max_methods)

def analyze_method_optimization(instructions, cfg=None, method_info=None):
    """分析单个方法的优化模式

    Args:
        instructions: Instruction 列表
        cfg: 预构建 CFG（可选）
        method_info: 方法元信息

    Returns:
        dict: 各种优化模式检测结果
    """
    return _OptimizationPatternDetector.analyze_method(instructions, cfg, method_info)

# ========== DEX 元数据深度分析 ==========

def analyze_dex_metadata(dex_parser, max_classes=200):
    """DEX 元数据深度分析 - Annotation/Debug/Hidden API 检测

    Args:
        dex_parser: DexParser 实例
        max_classes: 最大分析类数

    Returns:
        dict: {annotations, debug_info, hidden_api, annotation_processors, serialization}
    """
    return _DexMetadataAnalyzer.analyze(dex_parser, max_classes)

def analyze_annotations(dex_parser):
    """解析 DEX 中的注解信息（类/字段/方法/参数注解）"""
    return _DexMetadataAnalyzer.analyze_annotations(dex_parser)

def analyze_debug_info(dex_parser, max_classes=200):
    """提取 DEX 调试信息（行号映射、局部变量名、源文件）"""
    return _DexMetadataAnalyzer.analyze_debug_info(dex_parser, max_classes)

def detect_hidden_api(dex_parser):
    """检测 Hidden API 使用（内部 API、Dalvik 系统 API、反射模式）"""
    return _DexMetadataAnalyzer.detect_hidden_api(dex_parser)

def detect_annotation_processors(dex_parser):
    """检测注解处理器框架（ButterKnife/Dagger/Room/EventBus 等）"""
    return _DexMetadataAnalyzer.detect_annotation_processors(dex_parser)

def detect_serialization(dex_parser):
    """检测序列化框架使用（Parcelable/Gson/Moshi/Jackson 等）"""
    return _DexMetadataAnalyzer.detect_serialization(dex_parser)

# ========== 多 DEX 关联分析 ==========

def analyze_multidex(dex_parsers):
    """多 DEX 关联分析 - 跨 DEX 引用追踪、类分布、重复检测

    Args:
        dex_parsers: dict {dex_name: DexParser}

    Returns:
        dict: {distribution, cross_references, duplicates}
    """
    return _MultiDexAnalyzer.analyze(dex_parsers)

def analyze_multidex_distribution(dex_parsers):
    """分析多 DEX 文件的类分布统计"""
    return _MultiDexAnalyzer.analyze_dex_distribution(dex_parsers)

def analyze_cross_dex_references(dex_parsers):
    """分析跨 DEX 引用关系（DEX A 引用 DEX B 中的类）"""
    return _MultiDexAnalyzer.analyze_cross_references(dex_parsers)

def detect_duplicate_classes(dex_parsers):
    """检测重复类（同包名类名出现在多个 DEX）"""
    return _MultiDexAnalyzer.detect_duplicate_classes(dex_parsers)

# ========== Native-Java 交叉引用分析 ==========

def analyze_native_crossref(dex_parser=None, so_symbols_map=None, so_data=None):
    """Native-Java 交叉引用分析 - SO 与 DEX 之间的调用关系追踪

    Args:
        dex_parser: DexParser 实例（可选）
        so_symbols_map: dict {so_name: [symbol_names]}（可选）
        so_data: SO 文件二进制数据（可选，用于 JNI 回调分析）

    Returns:
        dict: {native_methods, so_exports, jni_callbacks, cross_reference}
    """
    return _NativeCrossRefAnalyzer.analyze(dex_parser, so_symbols_map, so_data)

def analyze_native_methods(dex_parser):
    """从 DEX 中提取 native 方法声明"""
    return _NativeCrossRefAnalyzer.analyze_native_methods(dex_parser)

def analyze_so_exports(so_symbols, so_name=''):
    """分析 SO 文件的导出符号（JNI 函数/危险模式）"""
    return _NativeCrossRefAnalyzer.analyze_so_exports(so_symbols, so_name)

def analyze_jni_callbacks(so_data):
    """分析 SO 中 JNI 回调 Java 的模式"""
    return _NativeCrossRefAnalyzer.analyze_jni_callbacks(so_data)

def cross_reference_native(dex_parser, so_symbols_map):
    """交叉引用分析 - DEX native 方法与 SO 导出符号匹配"""
    return _NativeCrossRefAnalyzer.cross_reference(dex_parser, so_symbols_map)

# ========== 报告生成 ==========

def generate_report(results, apk_name='', output_path=None, fmt='json'):
    """生成逆向分析报告（JSON/HTML/Markdown）

    Args:
        results: 分析结果
        apk_name: APK 文件名
        output_path: 输出路径（根据格式自动加扩展名）
        fmt: 格式 json/html/markdown

    Returns:
        str: 报告内容
    """
    return _ReportGenerator.generate(results, apk_name, output_path, fmt)

def generate_json_report(results, apk_name='', output_path=None):
    """生成 JSON 格式报告"""
    return _ReportGenerator.generate_json(results, apk_name, output_path)

def generate_html_report(results, apk_name='', output_path=None):
    """生成 HTML 格式报告（带样式）"""
    return _ReportGenerator.generate_html(results, apk_name, output_path)

def generate_markdown_report(results, apk_name='', output_path=None):
    """生成 Markdown 格式报告"""
    return _ReportGenerator.generate_markdown(results, apk_name, output_path)
