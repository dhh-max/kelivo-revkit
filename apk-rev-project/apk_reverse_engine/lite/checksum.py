# -*- coding: utf-8 -*-
"""checksum — 文件校验和工具（源自 TaiXu core/network/ChecksumVerifier.kt）

用于校验 APK / runner / toolchain 下载后的完整性。

对齐 TaiXu ChecksumVerifier：
  - 64KB 缓冲流式读（避免大文件吃内存）
  - expectedSha256 空白时跳过校验
  - 不匹配时抛 ChecksumMismatch(expected, actual)

Python 标准库 hashlib 实现，零外部依赖。

对外 API:
  - sha256_file(path_or_buf)                 流式计算 SHA-256，返回小写 hex
  - sha1_file(path_or_buf)                  SHA-1
  - md5_file(path_or_buf)                   MD5（仅用于兼容性，不推荐新用）
  - verify_sha256(path, expected)           不匹配抛 ChecksumMismatch
  - ChecksumMismatch                        校验失败异常类
"""
from __future__ import annotations
import hashlib
from typing import Union

__all__ = [
    'sha256_file', 'sha1_file', 'md5_file', 'verify_sha256',
    'ChecksumMismatch', 'BUFFER_SIZE',
]


BUFFER_SIZE = 64 * 1024  # 64 KB


class ChecksumMismatch(Exception):
    """校验和不匹配。"""
    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(
            'checksum mismatch: expected=%s actual=%s' % (expected, actual)
        )


def _digest(stream, algo: str) -> str:
    """通用流式计算。stream 可以是文件路径(str) 或 二进制 file-like。"""
    h = hashlib.new(algo)
    if isinstance(stream, (str, bytes,)) and not hasattr(stream, 'read'):
        # 路径
        with open(stream, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                h.update(chunk)
    else:
        # file-like
        while True:
            chunk = stream.read(BUFFER_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_file(path_or_buf) -> str:
    """流式计算 SHA-256，返回小写 hex 字符串。"""
    return _digest(path_or_buf, 'sha256')


def sha1_file(path_or_buf) -> str:
    return _digest(path_or_buf, 'sha1')


def md5_file(path_or_buf) -> str:
    return _digest(path_or_buf, 'md5')


def verify_sha256(path_or_buf, expected: str) -> None:
    """校验文件 SHA-256；不匹配抛 ChecksumMismatch。

    expected 为空字符串或 None 时直接跳过（对齐 TaiXu `isBlank()` 语义）。
    """
    if not expected or not str(expected).strip():
        return
    exp = str(expected).strip().lower()
    actual = sha256_file(path_or_buf)
    if actual != exp:
        raise ChecksumMismatch(exp, actual)
