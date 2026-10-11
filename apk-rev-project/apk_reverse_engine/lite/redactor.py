# -*- coding: utf-8 -*-
"""redactor — 敏感信息脱敏器（源自 TaiXu core/security/SecretRedactor.kt）

对字符串中的 API key、token、密码、Bearer、手机费等做占位脱敏，可用于：
  - LLM 输出过滤器（避免把 prompt 里的密钥回显给用户）
  - 工具调用日志脱敏（super_admin / code_runner 参数外发前处理）
  - Agent 消息持久化前的清洗

对齐 TaiXu SecretRedactor.redact(value) 与 redact(value, secretValues, privacyMode)。

Python 标准库实现，零外部依赖。

对外 API:
  - redact(text)                          基础脱敏
  - redact_with_secrets(text, secrets, privacy_mode=True)
                                          追加显式 secret 值脱敏 + mask
  - Redactor class                        面向对象包装
  - mask(secret)                          前2 + *** + 后2 掩码
  - SECRET_FIELDS / BARE_SECRET_FIELDS / JSON_SECRET_VALUE / ...
                                          预编译正则（导出便于替换自定义规则）
"""
from __future__ import annotations
import re
from typing import Iterable, Collection, List

__all__ = [
    'redact', 'redact_with_secrets', 'mask', 'Redactor',
    'SECRET_FIELDS', 'BARE_SECRET_FIELDS', 'JSON_SECRET_VALUE',
    'SCRIPT_SECRET_ASSIGNMENT', 'MAINLAND_PHONE', 'BEARER_TOKEN',
    'COMMON_SECRET_ENV', 'WELL_KNOWN_KEY_PREFIX',
]

# ── 密钥字段名（用于 SECRET_FIELDS / BARE_SECRET_FIELDS 等正则内部） ──
_SECRET_KEYS = (
    r'password|passwd|pwd|passcode|secret|api[_-]?key'
    r'|access[_-]?token|refresh[_-]?token|authorization|cookie|session[_-]?token'
)

# ── 预编译正则 ──────────────────────────────────────────────
# JSON 字符串字面量形式："password": "***"
SECRET_FIELDS = re.compile(
    r'(?i)((?<![\w-])(?:--)?(?:[a-z0-9]+[_-])*(?:' + _SECRET_KEYS + r'|pass|token)(?:\*["\'])(?:\.value)?\s*(?:[=:]\s*|\s+))(\*["\'])(.*?)(\2)',
    re.DOTALL,
)

# 裸赋值形式：password=abc123 或 --api-key sk-xxx
BARE_SECRET_FIELDS = re.compile(
    r'(?i)((?<![\w-])(?:--)?(?:[a-z0-9]+[_-])*(?:' + _SECRET_KEYS + r'|pass|token)\s*[=:]\s*)([^\s,;"\']+\S*)',
)

# JSON 键值："password": "secretValue"
JSON_SECRET_VALUE = re.compile(
    r'(?i)(["\'](' + _SECRET_KEYS + r')["\']\s*:\s*)(["\'])(.*?)(\3)',
    re.DOTALL,
)

# JS / Python 脚本赋值：password = 'secretValue'
SCRIPT_SECRET_ASSIGNMENT = re.compile(
    r'(?i)(\b(' + _SECRET_KEYS + r')(?:\.value)?\s*=\s*)(["\'])(.*?)(\3)',
    re.DOTALL,
)

# 国内手机号 1[3-9]xxxxxxxxx
MAINLAND_PHONE = re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)')

# 常见环境变量赋值：OPENAI_API_KEY=xxx / api_key=xxx
COMMON_SECRET_ENV = re.compile(
    r'(?i)(OPENAI_API_KEY|API_KEY|TOKEN|AUTHORIZATION)\s*[=:]\s*\S+'
)

# Bearer 认证头
BEARER_TOKEN = re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+')

# 已知厂商密钥前缀：OpenAI(sk-)、Anthropic(sk-ant-)、Google(GEMINI/AIza)、Slack(xox[bp])-
WELL_KNOWN_KEY_PREFIX = re.compile(
    r'\b(?:sk-(?:ant-|proj-)?|AIza|xox[bap]-)[A-Za-z0-9._-]{12,}'
)


# ── 掩码工具 ────────────────────────────────────────────────
def mask(secret: str) -> str:
    """对显式 secret 值做「前2 + *** + 后2」掩码，短值全部星号。"""
    if secret is None:
        return ''
    s = str(secret)
    if len(s) < 8:
        return '*' * len(s)
    return s[:2] + '*' * (len(s) - 4) + s[-2:]


# ── 核心脱敏函数 ────────────────────────────────────────────
def _extract_labeled_secrets(value: str) -> List[str]:
    """从 `key="value"` / `key=value` 中提取字面量，供二次回扫。

    注意：BARE_SECRET_FIELDS 的正则会吃到尾部标点（如 `,` `.` `;`），
    需要在提取后剔除，才能与后续回扫时匹配。
    """
    TRAIL = ',.;:)]}>"\'\t\n\r '
    out = []
    for m in SECRET_FIELDS.finditer(value):
        v = m.group(3)
        if len(v) >= 5:
            out.append(v)
    for m in BARE_SECRET_FIELDS.finditer(value):
        v = m.group(2).rstrip(TRAIL)
        if len(v) >= 5:
            out.append(v)
    # 去重 + 按长度倒序（长优先，避免短的子串先替换）
    uniq = sorted(set(out), key=len, reverse=True)
    return uniq


def redact(value: str) -> str:
    """基础脱敏：所有已知 secret 字段/前缀/Bearer/手机号 → [REDACTED]。

    对齐 TaiXu SecretRedactor.redact() 完整流水线：
      1. 学习被 `key="value"` 形式标注过的 secret 字面量
      2. 替换 SECRET_FIELDS / BARE_SECRET_FIELDS 为 [REDACTED]
      3. 反向扫学习到的字面量，把回显也替换
      4. 环境变量形式、Bearer、已知厂商 key 前缀、JSON/script 内赋值
      5. 手机号 → [PHONE_REDACTED]
    """
    if not value:
        return value

    # 1. 学习标注过的 secret（用于后续反向替换回显）
    secrets = _extract_labeled_secrets(value)

    # 2. 替换标签化字段
    result = SECRET_FIELDS.sub(lambda m: '%s%s[REDACTED]%s' % (m.group(1), m.group(2), m.group(4)), value)
    result = BARE_SECRET_FIELDS.sub(lambda m: '%s[REDACTED]' % m.group(1), result)

    # 3. 反向替换学习到的字面量
    for s in secrets:
        if s in result:
            result = result.replace(s, '[REDACTED]')

    # 4. 环境变量 / Bearer / 厂商 key 前缀 / JSON / script
    result = COMMON_SECRET_ENV.sub(lambda m: m.group(1) + '=[REDACTED]', result)
    result = BEARER_TOKEN.sub('Bearer [REDACTED]', result)
    result = WELL_KNOWN_KEY_PREFIX.sub('[REDACTED]', result)
    result = JSON_SECRET_VALUE.sub(lambda m: '%s%s[REDACTED]%s' % (m.group(1), m.group(3), m.group(5)), result)
    result = SCRIPT_SECRET_ASSIGNMENT.sub(lambda m: '%s%s[REDACTED]%s' % (m.group(1), m.group(3), m.group(5)), result)

    # 5. 手机号
    result = MAINLAND_PHONE.sub('[PHONE_REDACTED]', result)

    return result


def redact_with_secrets(value: str,
                        secret_values: Collection[str] = (),
                        privacy_mode: bool = True) -> str:
    """附加显式 secret 值脱敏。

    隐私模式下：
      - 先把 value 基础脱敏
      - 再把 secret_values 中长度 >=5 的值按「前2 + *** + 后2」掩码
        （对齐 TaiXu mask(secret) 规则）
    隐私模式关闭时等价于 redact(value)。
    """
    if not privacy_mode:
        return redact(value)

    result = redact(value)

    # 收集 secret（>=5 长度），按长度倒序替换（长优先）
    seen = set()
    ordered = []
    for s in secret_values or []:
        s = str(s) if s is not None else ''
        if len(s) >= 5 and s not in seen:
            seen.add(s)
            ordered.append(s)
    ordered.sort(key=len, reverse=True)

    for s in ordered:
        if s in result:
            result = result.replace(s, mask(s))

    return result


# ── 面向对象包装 ────────────────────────────────────────────
class Redactor:
    """SensitiveDataRedactor 接口实现（对齐 TaiXu SecretRedactor 类）。

    用法：
        r = Redactor()
        r.redact(text)
        r.redact_with_secrets(text, secrets=['sk-xxx...'], privacy_mode=True)
    """

    def redact(self, value: str) -> str:
        return redact(value)

    def redact_with_secrets(self, value: str,
                            secret_values: Collection[str] = (),
                            privacy_mode: bool = True) -> str:
        return redact_with_secrets(value, secret_values=secret_values,
                                   privacy_mode=privacy_mode)

    def mask(self, secret: str) -> str:
        return mask(secret)


__all__.append('Redactor')
