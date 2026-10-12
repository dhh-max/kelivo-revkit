#!/usr/bin/env python3
"""最小 pkg-config 实现，供 Windows 上的 CMake FindPkgConfig 使用。

背景：Blutter 的 CMakeLists 用 `pkg_search_module(CAPSTONE REQUIRED capstone)`
定位 capstone，而本机没有 pkg-config 可执行文件（NDK 也不带）。本脚本只实现
CMake 需要的查询子集，读取 .pc 文件并回答。

路径处理：.pc 里的 prefix 是 Termux 绝对路径
（/data/data/com.termux/files/usr），通过 PKG_CONFIG_SYSROOT_DIR 前缀重写为
本地 sysroot 路径。

用法（由 tools/pkg-config.bat 转发，需在 PATH 上）:
  python tools/pkgconfig_shim.py --exists capstone
  python tools/pkgconfig_shim.py --cflags --libs capstone
"""

from __future__ import annotations

import os
import re
import sys

SYSROOT = os.environ.get("PKG_CONFIG_SYSROOT_DIR", "").rstrip("/\\")
VAR_RE = re.compile(r"^(\w+)=(.*)$")
TERMUX_PREFIX = "/data/data/com.termux/files/usr"


def search_dirs():
    dirs = []
    for key in ("PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR"):
        val = os.environ.get(key, "")
        if val:
            dirs.extend(p for p in val.split(os.pathsep) if p)
    return dirs


def parse_pc(path: str):
    """解析 .pc 文件并展开 ${var} 引用。"""
    raw = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line and not line.startswith("$"):
                key, _, value = line.partition(":")
                key = key.strip()
                if key and key.isidentifier():
                    raw[key] = value.strip()
                    continue
            m = VAR_RE.match(line)
            if m:
                raw[m.group(1)] = m.group(2)

    def expand(value: str, depth: int = 0) -> str:
        if depth > 8 or "${" not in value:
            return value
        return expand(
            re.sub(r"\$\{(\w+)\}", lambda m: raw.get(m.group(1), ""), value),
            depth + 1,
        )

    out = {k: expand(v) for k, v in raw.items()}
    for section in ("Name", "Description", "Version", "Libs", "Cflags"):
        if section in out:
            out[section.lower()] = out[section]
    return out


def rewrite(path: str) -> str:
    if not SYSROOT:
        return path
    p = path.replace("\\", "/")
    if TERMUX_PREFIX in p:
        p = p.replace(TERMUX_PREFIX, SYSROOT.replace("\\", "/"))
    return p


def main(argv) -> int:
    args = argv[1:]
    modules = []
    want = {"exists": False, "cflags": False, "libs": False, "modversion": False}
    variables = []
    version_checks = []

    for a in args:
        if a == "--exists":
            want["exists"] = True
        elif a in ("--cflags", "--cflags-only-I", "--cflags-only-other"):
            want["cflags"] = True
        elif a in ("--libs", "--libs-only-L", "--libs-only-l", "--libs-only-other"):
            want["libs"] = True
        elif a == "--modversion":
            want["modversion"] = True
        elif a.startswith("--variable="):
            variables.append(a.split("=", 1)[1])
        elif a.startswith("--atleast-version="):
            version_checks.append(("atleast", a.split("=", 1)[1]))
        elif a.startswith("--exact-version="):
            version_checks.append(("exact", a.split("=", 1)[1]))
        elif a.startswith("--max-version="):
            version_checks.append(("max", a.split("=", 1)[1]))
        elif a.startswith("--"):
            pass
        else:
            modules.append(a)

    if not modules:
        return 0

    infos = []
    for name in modules:
        found = None
        for d in search_dirs():
            candidate = os.path.join(d, name + ".pc")
            if os.path.isfile(candidate):
                found = parse_pc(candidate)
                break
        if found is None:
            sys.stderr.write(f"Package {name} not found\n")
            return 1
        infos.append(found)

    def ver_tuple(v: str):
        return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)[:4]]

    for info in infos:
        have = ver_tuple(info.get("version", "0"))
        for kind, target in version_checks:
            t = ver_tuple(target)
            if kind == "atleast" and not have >= t:
                return 1
            if kind == "exact" and not have == t:
                return 1
            if kind == "max" and not have <= t:
                return 1

    if want["modversion"]:
        for info in infos:
            print(info.get("version", ""))
        return 0

    if variables:
        hit = False
        for var in variables:
            for info in infos:
                if var in info:
                    print(rewrite(info[var]))
                    hit = True
        return 0 if hit else 1

    out = []
    if want["cflags"]:
        for info in infos:
            out.extend(rewrite(t) for t in info.get("cflags", "").split() if t)
    if want["libs"]:
        for info in infos:
            out.extend(rewrite(t) for t in info.get("libs", "").split() if t)
    if out:
        print(" ".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
