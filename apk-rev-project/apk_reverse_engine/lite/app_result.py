# -*- coding: utf-8 -*-
"""app_result — 结果类型 + 错误码（源自 TaiXu core/common/result/AppResult.kt）

用显式的 Result 对象替代 Python 异常传递，便于：
  - CLI/Agent 边界统一格式化错误码
  - 跨模块组合（map / fold）不吞掉错误上下文
  - 日志聚合（error.code 直接落分类）

对齐 TaiXu AppResult<AppError> sealed class：
    Success(data)
    Failure(error: AppError{code, message, cause})
    .is_success / .is_failure
    .map(fn)       成功则映射，失败透传
    .get_or_null() 成功返回值，失败返回 None
    .error_or_null()
    .fold(ok, err) 成功/失败分支消费

ErrorCode 覆盖 TaiXu 12 类；新增 SECURITY 用于脱敏失败场景。

Python 标准库实现，零外部依赖。

对外 API:
  - Success(data) / Failure(code, message, cause=None) / fail(code, msg, cause=None)
  - ErrorCode.IO / NETWORK / DOWNLOAD / CHECKSUM / SECURITY / ...  12 个字符串常量
  - result.is_success / result.is_failure
  - result.map(fn) / result.get_or_null() / result.error_or_null() / result.fold(ok, err)
  - result.to_dict() / result.__repr__
"""
from __future__ import annotations
from typing import Any, Callable, Optional, Union

__all__ = [
    'Success', 'Failure', 'fail', 'ErrorCode', 'Result', 'AppError',
    'SUCCESS', 'FAILURE',
]


# ── ErrorCode ───────────────────────────────────────────────
class ErrorCode:
    """错误分类常量（字符串值即可，便于 JSON 序列化）。"""
    UNKNOWN = 'UNKNOWN'
    IO = 'IO'
    NETWORK = 'NETWORK'
    DOWNLOAD = 'DOWNLOAD'
    CHECKSUM = 'CHECKSUM'
    RUNTIME_NOT_INITIALIZED = 'RUNTIME_NOT_INITIALIZED'
    UNSUPPORTED_ARCHITECTURE = 'UNSUPPORTED_ARCHITECTURE'
    INSUFFICIENT_STORAGE = 'INSUFFICIENT_STORAGE'
    INSTALLATION_FAILED = 'INSTALLATION_FAILED'
    DATABASE = 'DATABASE'
    SECURITY = 'SECURITY'


ERROR_CODES = (
    ErrorCode.UNKNOWN, ErrorCode.IO, ErrorCode.NETWORK, ErrorCode.DOWNLOAD,
    ErrorCode.CHECKSUM, ErrorCode.RUNTIME_NOT_INITIALIZED,
    ErrorCode.UNSUPPORTED_ARCHITECTURE, ErrorCode.INSUFFICIENT_STORAGE,
    ErrorCode.INSTALLATION_FAILED, ErrorCode.DATABASE, ErrorCode.SECURITY,
)


# ── AppError ────────────────────────────────────────────────
class AppError:
    """错误载体：code + message + optional cause（异常对象或字符串）。"""

    __slots__ = ('code', 'message', 'cause')

    def __init__(self, code: str, message: str = '', cause: Any = None):
        self.code = str(code) if code else ErrorCode.UNKNOWN
        self.message = str(message) if message else ''
        self.cause = cause

    @classmethod
    def unknown(cls, message='', cause=None):
        return cls(ErrorCode.UNKNOWN, message, cause)

    @classmethod
    def io(cls, message='', cause=None):
        return cls(ErrorCode.IO, message, cause)

    @classmethod
    def network(cls, message='', cause=None):
        return cls(ErrorCode.NETWORK, message, cause)

    @classmethod
    def checksum(cls, message='', cause=None):
        return cls(ErrorCode.CHECKSUM, message, cause)

    @classmethod
    def security(cls, message='', cause=None):
        return cls(ErrorCode.SECURITY, message, cause)

    def to_dict(self) -> dict:
        d = {'code': self.code, 'message': self.message}
        if self.cause is not None:
            d['cause'] = (type(self.cause).__name__ + ': ' + str(self.cause)) \
                if not isinstance(self.cause, str) else self.cause
        return d

    def __repr__(self):
        return 'AppError(code=%r, message=%r)' % (self.code, self.message)

    def __str__(self):
        if self.cause is not None:
            return '[%s] %s (%s)' % (self.code, self.message, self.cause)
        return '[%s] %s' % (self.code, self.message)

    def __eq__(self, other):
        if not isinstance(other, AppError):
            return False
        return (self.code == other.code and self.message == other.message)


# ── Result 基类 ─────────────────────────────────────────────
class Result:
    """Result 基类。具体使用 Success / Failure。"""

    __slots__ = ()

    @property
    def is_success(self) -> bool:
        return isinstance(self, Success)

    @property
    def is_failure(self) -> bool:
        return isinstance(self, Failure)

    def get_or_null(self) -> Any:
        raise NotImplementedError

    def error_or_null(self) -> Optional[AppError]:
        raise NotImplementedError

    def map(self, transform: Callable[[Any], Any]) -> 'Result':
        raise NotImplementedError

    def fold(self, on_success: Callable[[Any], Any], on_failure: Callable[[AppError], Any]) -> Any:
        raise NotImplementedError

    def to_dict(self) -> dict:
        raise NotImplementedError

    def __repr__(self):
        raise NotImplementedError


# ── Success ─────────────────────────────────────────────────
class Success(Result):
    __slots__ = ('data',)

    def __init__(self, data):
        self.data = data

    def get_or_null(self):
        return self.data

    def error_or_null(self):
        return None

    def map(self, transform):
        return Success(transform(self.data))

    def fold(self, on_success, on_failure):
        return on_success(self.data)

    def to_dict(self):
        return {'ok': True, 'data': self.data}

    def __repr__(self):
        return 'Success(%r)' % (self.data,)


# ── Failure ─────────────────────────────────────────────────
class Failure(Result):
    __slots__ = ('error',)

    def __init__(self, error: AppError):
        self.error = error if isinstance(error, AppError) else AppError(
            ErrorCode.UNKNOWN, str(error)
        )

    @classmethod
    def of(cls, code: str, message: str = '', cause: Any = None) -> 'Failure':
        return cls(AppError(code, message, cause))

    def get_or_null(self):
        return None

    def error_or_null(self):
        return self.error

    def map(self, transform):
        return self  # 失败透传

    def fold(self, on_success, on_failure):
        return on_failure(self.error)

    def to_dict(self):
        return {'ok': False, 'error': self.error.to_dict()}

    def __repr__(self):
        return 'Failure(%r)' % (self.error,)


# ── 工厂函数 ────────────────────────────────────────────────
def fail(code: str, message: str = '', cause: Any = None) -> Failure:
    """快速构造 Failure。"""
    return Failure.of(code, message, cause)


# ── 类型别名 ────────────────────────────────────────────────
AnyResult = Union[Success, Failure]

# 兼容常量：让老代码可以 `from app_result import SUCCESS, FAILURE`
SUCCESS = Success
FAILURE = Failure
