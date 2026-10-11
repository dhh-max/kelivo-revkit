# -*- coding: utf-8 -*-
"""shell_quote — POSIX shell 单引号转义（源自 TaiXu core/common/shell/ShellQuote.kt）

KE 的 super_admin / code_runner / linux_ssh 会频繁拼接 shell 命令。手工写
`'xxx'` 遇到含单引号的值时会语法错误、遇到 `;` `$` `` ` `` 时可能注入。

ShellQuote 是全仓唯一实现（对齐 TaiXu 的收敛决策）：
    整体用单引号包裹；值内的每个 `'` 用 `'\''` 断开-转义-续接。

规则在 POSIX sh / bash / dash 下语义一致，不依赖外部 subprocess。

对外 API:
  - shell_quote(value)                转义单个值
  - shell_join(values)                转义后空格拼接，返回命令字符串
  - shell_join(values, prefix='')     支持前缀（如 'cd /x && '）
  - quoted_of(value)                  shell_quote 的兼容别名
"""
from __future__ import annotations
from typing import Iterable, List

__all__ = ['shell_quote', 'shell_join', 'quoted_of']


def shell_quote(value) -> str:
    """将 value 转义为可安全嵌入 POSIX shell 命令的单引号字面量。

    规则：整体用单引号包裹；值内的每个 `'` 用 `'\''` 断开-转义-续接。
    在 POSIX sh / bash / dash 下语义完全一致。
    """
    if value is None:
        return "''"
    s = str(value)
    return "'" + s.replace("'", "'\\''") + "'"


# 兼容别名（对齐 Kotlin 的 ShellQuote.of）
def quoted_of(value) -> str:
    return shell_quote(value)


def shell_join(values: Iterable, prefix: str = '') -> str:
    """批量转义并用空格拼接。

    例：
        shell_join(['ls', '-la', '/tmp/a b'])       →  "ls -la '/tmp/a b'"
        shell_join(['cat', f], prefix='cd /x && ')  →  "cd /x && cat '/path/f'"
    """
    parts: List[str] = []
    for v in values:
        parts.append(shell_quote(v))
    if prefix:
        return prefix + ' '.join(parts)
    return ' '.join(parts)
