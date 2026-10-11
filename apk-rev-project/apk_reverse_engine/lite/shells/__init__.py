# -*- coding: utf-8 -*-
"""shells — 加固壳专用脱壳子模块

整合两个外部脚本进 KE Lite 生态：
  * np_unpacker.py    来自 np资源解密1.1.py
  * tosks_unpacker.py 来自 tosks_tool.py

统一入口：
  - detect(apk)         -> 'np' | 'tosks' | None
  - unpack(apk, out)    -> 结构化 dict
  - auto_unpack(apk)    -> 自动识别并调用对应解包器
"""
from . import np_unpacker
from . import tosks_unpacker


def detect(apk_path):
    """识别壳类型。返回 'tosks' / 'np' / None。"""
    if not apk_path:
        return None
    # tosks 特征明显（libtosks*.so / com.tosks），优先判断
    if tosks_unpacker.is_tosks(apk_path):
        return 'tosks'
    try:
        if np_unpacker.detect(apk_path):
            return 'np'
    except Exception:
        pass
    return None


def unpack(apk_path, out_dir=None, shell=None, log=None):
    """按壳类型调用对应解包器；shell=None 时自动检测。

    Args:
        apk_path: APK 路径
        out_dir:  输出根目录（None 时由解包器使用默认路径）
        shell:    强制指定 'np' / 'tosks'，跳过检测
        log:      日志回调 log(str)，默认 print

    Returns:
        dict（各解包器返回结构基本一致）
    """
    import os
    shell = shell or detect(apk_path)
    if shell == 'tosks':
        return tosks_unpacker.unpack(apk_path, base_out=out_dir, log=log)
    if shell == 'np':
        od = out_dir or (os.environ.get('OPERIT_OUT') or '/storage/emulated/0')
        return np_unpacker.unpack(apk_path, od, log=log)
    return {'ok': False, 'shell': None, 'note': '未识别到已知加固壳'}


# 别名：便于 lite 包外部直接 import
auto_unpack = unpack
np_unpack = np_unpacker.unpack
tosks_unpack = tosks_unpacker.unpack


__all__ = [
    'np_unpacker', 'tosks_unpacker',
    'detect', 'unpack', 'auto_unpack',
    'np_unpack', 'tosks_unpack',
]