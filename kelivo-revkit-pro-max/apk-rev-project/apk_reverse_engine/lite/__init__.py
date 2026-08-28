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
# 兼容别名
_unpack_apk_lite = unpack_apk_lite


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
]