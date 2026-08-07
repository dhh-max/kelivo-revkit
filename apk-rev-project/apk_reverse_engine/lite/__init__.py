"""Lite 模块 - 零外部依赖的 APK 快速分析
整合自 standalone_unpacker + standalone_runner，纯 Python 标准库，无第三方依赖。
适用于 code_runner 环境、无网络/受限环境下的快速分析。
"""
from .dex_parser import LiteDexParser
from .unpacker import LiteUnpacker, unpack_apk_lite, _fmt_size, _compact_result
from .analyzer import LiteAnalyzer, analyze_apk_lite, auto_find_apks, process_inbox

__all__ = [
    'LiteDexParser', 'LiteUnpacker', 'LiteAnalyzer',
    'unpack_apk_lite', 'analyze_apk_lite',
    'auto_find_apks', 'process_inbox',
    '_fmt_size', '_compact_result',
]
