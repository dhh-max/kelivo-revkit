"""Lite 模块 - 零外部依赖的 APK 快速分析
整合自 standalone_unpacker + standalone_runner，纯 Python 标准库，无第三方依赖。
适用于 code_runner 环境、无网络/受限环境下的快速分析。
"""
from .dex_parser import LiteDexParser
from .unpacker import (
    unpack_apk_lite,
    unpack_apk_standalone,
    process_inbox,
    LiteManifestParser,
    _fmt_size,
    _compact_result,
)
# ── 加固壳脱壳子模块（np / tosks） ──
from . import shells as _shells_pkg
from .shells import np_unpacker as _np_unpacker_mod
from .shells import tosks_unpacker as _tosks_unpacker_mod

# ── Flutter AOT 反汇编桥接（BlutterAndroid runner） ──
from . import blutter_bridge as _blutter_mod

# 兼容别名
_unpack_apk_lite = unpack_apk_lite


class ShellsUnpacker:
    """加固壳统一解包器（np / tosks）。

    用法：
        ShellsUnpacker.unpack(apk)                        # 自动识别
        ShellsUnpacker.detect(apk)                        # 只识别
        ShellsUnpacker.unpack(apk, shell='tosks')         # 强制 tosks
        ShellsUnpacker.unpack(apk, out_dir='/sdcard/..')  # 指定输出
    """
    @staticmethod
    def detect(apk_path):
        return _shells_pkg.detect(apk_path)
    @staticmethod
    def unpack(apk_path, out_dir=None, shell=None, log=None):
        return _shells_pkg.unpack(apk_path, out_dir=out_dir, shell=shell, log=log)
    @staticmethod
    def unpack_np(apk_path, out_dir=None, log=None):
        return _np_unpacker_mod.unpack(apk_path, out_dir, log=log)
    @staticmethod
    def unpack_tosks(apk_path, base_out=None, log=None):
        return _tosks_unpacker_mod.unpack(apk_path, base_out=base_out, log=log)


def shells_detect(apk_path):
    return _shells_pkg.detect(apk_path)


def shells_auto_unpack(apk_path, out_dir=None, shell=None, log=None):
    return _shells_pkg.unpack(apk_path, out_dir=out_dir, shell=shell, log=log)


def np_unpack(apk_path, out_dir, log=None):
    return _np_unpacker_mod.unpack(apk_path, out_dir, log=log)


def tosks_unpack(apk_path, base_out=None, log=None):
    return _tosks_unpacker_mod.unpack(apk_path, base_out=base_out, log=log)



# ── 限流（源自 RelayGo rate_limiter.dart） ──
from .rate_limiter import (
    TokenBucket, SlidingWindow, RateLimiter, RateLimitResult, ApiKey,
)

def rate_limiter(**kwargs):
    return RateLimiter(**kwargs)


# ── HTTP 请求体加解密 + 改写规则（源自 ProxyPin） ──
from .http_crypto import (
    CryptoKeyConfig, CryptoRule, RewriteItem, RewriteRule,
    aes_encrypt, aes_decrypt, apply_rewrite, find_matching_rule,
)

# ── 敏感信息脱敏（源自 TaiXu SecretRedactor） ──
from .redactor import (
    redact, redact_with_secrets, mask, Redactor,
)

# ── POSIX shell 单引号转义（源自 TaiXu ShellQuote） ──
from .shell_quote import (
    shell_quote, shell_join, quoted_of,
)

# ── Result 类型 + 错误码（源自 TaiXu AppResult / AppError） ──
from .app_result import (
    Success, Failure, fail, ErrorCode, AppError,
)

# ── 文件校验和（源自 TaiXu ChecksumVerifier） ──
from .checksum import (
    sha256_file, sha1_file, md5_file, verify_sha256, ChecksumMismatch,
)

# ── Flutter AOT（BlutterAndroid runner） ──
class FlutterAnalyzer:
    """Flutter AOT 产物分析器。

    用法：
        FlutterAnalyzer.detect(apk)                      # 识别 libapp.so/libflutter.so
        FlutterAnalyzer.analyze(apk, runners_dir, out)   # 一站式：识别→选 runner→exec
        FlutterAnalyzer.list_runners(runners_dir)        # 扫描可用 runner
    """
    @staticmethod
    def detect(apk_path, requested_abi='auto'):
        return _blutter_mod.detect_flutter(apk_path, requested_abi=requested_abi)
    @staticmethod
    def analyze(apk_path, runners_dir, out_dir, abi='auto', dart_version=None, log=None):
        return _blutter_mod.analyze_flutter(
            apk_path, runners_dir, out_dir,
            abi=abi, dart_version=dart_version, log=log,
        )
    @staticmethod
    def list_runners(runners_dir):
        return _blutter_mod.list_runners(runners_dir)
    @staticmethod
    def pick_runner(abi, dart_version, runners_dir):
        return _blutter_mod.pick_runner(abi, dart_version, runners_dir)
    @staticmethod
    def fingerprint(libapp_bytes):
        return _blutter_mod.fingerprint_dart(libapp_bytes)


def flutter_detect(apk_path, requested_abi='auto'):
    return _blutter_mod.detect_flutter(apk_path, requested_abi=requested_abi)


def flutter_analyze(apk_path, runners_dir, out_dir, abi='auto', dart_version=None, log=None):
    return _blutter_mod.analyze_flutter(
        apk_path, runners_dir, out_dir,
        abi=abi, dart_version=dart_version, log=log,
    )


def blutter_list_runners(runners_dir):
    return _blutter_mod.list_runners(runners_dir)


def LiteUnpacker(*args, **kwargs):
    """兼容别名 - 指向 unpack_apk_lite"""
    return _unpack_apk_lite(*args, **kwargs)


def analyze_apk_lite(apk_path, **kwargs):
    """零依赖快速分析 APK（结构/Manifest/DEX 摘要，纯标准库）

    Args:
        apk_path: APK 文件路径
        **kwargs: 额外参数透传

    Returns:
        dict: 分析结果
    """
    return _unpack_apk_lite(apk_path, mode='analyze', **kwargs)


def auto_find_apks(search_dir=None, **kwargs):
    """自动搜索目录中的 APK 文件

    Args:
        search_dir: 搜索目录（默认 /sdcard/Download）
        **kwargs: 额外参数

    Returns:
        list: 找到的 APK 路径列表
    """
    import os
    search_dir = search_dir or '/sdcard/Download'
    if not os.path.isdir(search_dir):
        return []
    return sorted(
        os.path.join(search_dir, f)
        for f in os.listdir(search_dir)
        if f.endswith('.apk') and os.path.isfile(os.path.join(search_dir, f))
    )


__all__ = [
    'LiteDexParser', 'LiteUnpacker', 'LiteManifestParser',
    'unpack_apk_lite', 'unpack_apk_standalone', 'analyze_apk_lite',
    'auto_find_apks', 'process_inbox',
    '_fmt_size', '_compact_result',
    # shells 子模块（np / tosks）
    'ShellsUnpacker', 'shells_detect', 'shells_auto_unpack',
    'np_unpack', 'tosks_unpack',
        # rate_limiter (RelayGo)
    'RateLimiter', 'TokenBucket', 'SlidingWindow', 'RateLimitResult', 'ApiKey', 'rate_limiter',
    # http_crypto (ProxyPin)
    'CryptoKeyConfig', 'CryptoRule', 'RewriteItem', 'RewriteRule', 'aes_encrypt', 'aes_decrypt', 'apply_rewrite', 'find_matching_rule',
    # TaiXu: redactor / shell_quote / app_result / checksum
    'redact', 'redact_with_secrets', 'mask', 'Redactor',
    'shell_quote', 'shell_join', 'quoted_of',
    'Success', 'Failure', 'fail', 'ErrorCode', 'AppError',
    'sha256_file', 'sha1_file', 'md5_file', 'verify_sha256', 'ChecksumMismatch',
# Flutter AOT（BlutterAndroid runner）
    'FlutterAnalyzer', 'flutter_detect', 'flutter_analyze', 'blutter_list_runners',
]