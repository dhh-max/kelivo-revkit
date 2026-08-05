"""APK Reverse Engineering Engine v2 - 全模块基础功能API"""

__version__ = '2.0.0'

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
    """解压APK到目录"""
    with _APKContext(apk_path) as ctx:
        ctx.extract_to(output_dir)
        return {'success': True, 'dir': output_dir}

def apk_structure(apk_path):
    """获取APK结构摘要"""
    with _APKContext(apk_path) as ctx:
        return ctx.get_structure_summary()

# --- Manifest解析 ---
from .core.manifest_parser import ManifestParser as _ManifestParser
from .utils.axml_parser import AXMLParser as _AXMLParser

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

# --- 资源解析 ---
from .core.resource_parser import ResourceParser as _ResourceParser

def parse_arsc(data):
    """解析resources.arsc，返回包信息"""
    return _ResourceParser(data).parse()

# ============================================================
# 分析模块 - Analysis
# ============================================================

from .analysis.static_analyzer import StaticAnalyzer as _StaticAnalyzer
from .analysis.permission_analyzer import PermissionAnalyzer as _PermissionAnalyzer
from .analysis.obfuscation_detector import ObfuscationDetector as _ObfuscationDetector
from .analysis.security_analyzer import SecurityAnalyzer as _SecurityAnalyzer
from .analysis.code_analyzer import CodeAnalyzer as _CodeAnalyzer
from .analysis.network_analyzer import NetworkAnalyzer as _NetworkAnalyzer

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
    return _CodeAnalyzer.analyze(text)

def analyze_network(hosts):
    """分析网络地址(内网/公网IP分类)"""
    return _NetworkAnalyzer.analyze(hosts)

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

def unpack_apk(apk_path, output_dir):
    """解压APK原始文件"""
    return _APKUnpacker.extract_raw(apk_path, output_dir)

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

def zip_rebuild(input_dir, output_apk):
    """从目录重建APK/ZIP"""
    return _APKRepacker.zip_rebuild(input_dir, output_apk)

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
    'verify_signature_v1', 'verify_signature_v2', 'verify_signature',
    'parse_arsc',
    # Analysis
    'static_analyze', 'analyze_permissions', 'detect_obfuscation', 'detect_packer',
    'detect_anti_tamper', 'detect_reflection', 'detect_string_encryption',
    'security_analyze', 'analyze_code', 'analyze_network',
    # Patching
    'smali_patch_return', 'smali_patch_condition', 'smali_bypass_signature',
    'manifest_patch', 'manifest_set_debuggable', 'manifest_allow_backup',
    'integrity_patch_debug', 'integrity_patch_root',
    'native_patch_hex', 'native_patch_string', 'native_patch_bytes',
    'native_patch_ret', 'native_nop_out', 'native_patch_elf_entry',
    'resource_patch_arsc', 'resource_patch_package_name',
    # Tools
    'unpack_apk', 'extract_dex', 'extract_so', 'extract_resources',
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
    'cert_parse', 'cert_info', 'Logger',
]
