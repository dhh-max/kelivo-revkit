#!/usr/bin/env python3
"""Blutter runner 的 ICU soname 对齐工具。

Termux 的 libicuuc.so 自带 SONAME `libicuuc.so.78`，链接器会把它写进 runner 的
DT_NEEDED；而 App 打包的是无版本号的 `libicuuc.so`（jniLibs 里就叫这个名字），
Android 链接器按文件名精确匹配，`libicuuc.so.78` 会找不到。

处理方式：只改 .dynstr 里那一个字符串，用 NUL 补齐到原长度，字符串表大小不变。

路径安全：本工具只接受**裸文件名**（不含目录分隔符、不含 `..`），位置由 `--dir`
指定且必须是允许根目录的子目录；允许根 = 项目根 + BLUTTER_TOOL_ALLOWED_ROOTS。

用法:
  python tools/blutter_fix_icu_soname.py libblutter_3_13.so
  python tools/blutter_fix_icu_soname.py --dir build/blutter-toolchain libblutter_3_13.so
  python tools/blutter_fix_icu_soname.py libblutter_3_13.so --check   # 仅检查（有则退出码 1）
"""

from __future__ import annotations

import os
import pathlib
import re
import struct
import sys

PT_LOAD = 1
PT_DYNAMIC = 2
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.realpath(os.path.dirname(SCRIPT_DIR))
NAME_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")


def allowed_roots() -> list:
    """允许操作的目录白名单：项目根 + BLUTTER_TOOL_ALLOWED_ROOTS 追加项。"""
    roots = [PROJECT_ROOT]
    extra = os.environ.get("BLUTTER_TOOL_ALLOWED_ROOTS", "")
    roots.extend(p for p in extra.split(os.pathsep) if p)
    return [os.path.realpath(r) for r in roots]


def within_allowed(candidate: str) -> bool:
    canonical = os.path.realpath(candidate)
    return any(
        canonical == root or canonical.startswith(root + os.sep)
        for root in allowed_roots()
    )


def validate_dir(raw_dir: str) -> str:
    """校验目录参数：相对路径按项目根解析，结果必须落在允许根内。"""
    if ".." in raw_dir.replace("\\", "/").split("/"):
        raise SystemExit(f"refusing directory containing '..': {raw_dir}")
    base = raw_dir if os.path.isabs(raw_dir) else os.path.join(PROJECT_ROOT, raw_dir)
    if not within_allowed(base):
        raise SystemExit(f"directory outside allowed roots: {raw_dir}")
    if not os.path.isdir(base):
        raise SystemExit(f"not a directory: {raw_dir}")
    return os.path.realpath(base)


def validate_name(raw_name: str) -> str:
    """校验文件名：必须是裸文件名，不带任何目录成分。"""
    if raw_name != os.path.basename(raw_name):
        raise SystemExit(
            f"expected a bare file name (no directory part), got: {raw_name}"
        )
    if raw_name in ("", ".", "..") or not NAME_RE.match(raw_name):
        raise SystemExit(f"invalid file name: {raw_name}")
    return raw_name


def resolve_target(raw_dir: str, raw_name: str) -> pathlib.Path:
    """由已校验的目录 + 裸文件名构造目标路径。"""
    directory = validate_dir(raw_dir)
    name = validate_name(raw_name)
    target = pathlib.Path(directory) / name
    if not within_allowed(str(target)):
        raise SystemExit(f"target outside allowed roots: {name}")
    if not target.is_file():
        raise SystemExit(f"not a regular file: {name}")
    return target


def _read_dynamic(blob: bytearray):
    e_phoff = struct.unpack_from("<Q", blob, 32)[0]
    e_phentsize = struct.unpack_from("<H", blob, 54)[0]
    e_phnum = struct.unpack_from("<H", blob, 56)[0]

    load_segments = []
    dynamic = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", blob, off)[0]
        p_offset = struct.unpack_from("<Q", blob, off + 8)[0]
        p_vaddr = struct.unpack_from("<Q", blob, off + 16)[0]
        p_filesz = struct.unpack_from("<Q", blob, off + 32)[0]
        if p_type == PT_LOAD:
            load_segments.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)

    if dynamic is None:
        raise ValueError("no PT_DYNAMIC (statically linked?)")

    def vaddr_to_off(vaddr: int) -> int:
        for va, off, size in load_segments:
            if va <= vaddr < va + size:
                return off + (vaddr - va)
        raise ValueError(f"vaddr {vaddr:#x} not mapped by any PT_LOAD")

    d_off, d_size = dynamic
    entries = []
    for i in range(d_size // 16):
        off = d_off + i * 16
        tag = struct.unpack_from("<q", blob, off)[0]
        val = struct.unpack_from("<Q", blob, off + 8)[0]
        if tag == DT_NULL:
            break
        entries.append((tag, val))
    return entries, vaddr_to_off


def parse_args(argv):
    """解析参数：可选的 --dir，其余为裸文件名与 --check。"""
    raw_dir = "."
    name = None
    check_only = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--dir":
            i += 1
            if i >= len(argv):
                raise SystemExit("--dir requires a value")
            raw_dir = argv[i]
        elif arg == "--check":
            check_only = True
        elif arg in ("-h", "--help"):
            print(__doc__.strip())
            raise SystemExit(0)
        elif arg.startswith("-"):
            raise SystemExit(f"unknown option: {arg}")
        elif name is None:
            name = arg
        else:
            raise SystemExit(f"unexpected extra argument: {arg}")
        i += 1
    if name is None:
        print(__doc__.strip())
        raise SystemExit(2)
    return raw_dir, name, check_only


def patch_dynstr(blob: bytearray) -> int:
    """把 DT_NEEDED 里带版本号的 ICU 名改成无版本号形式，返回改动条数。"""
    entries, vaddr_to_off = _read_dynamic(blob)

    strtab_vaddr = None
    needed_offsets = []
    for tag, val in entries:
        if tag == DT_STRTAB:
            strtab_vaddr = val
        elif tag == DT_NEEDED:
            needed_offsets.append(val)

    if strtab_vaddr is None:
        raise ValueError("no DT_STRTAB")

    strtab_off = vaddr_to_off(strtab_vaddr)

    changed = 0
    for name_off in needed_offsets:
        start = strtab_off + name_off
        end = blob.index(b"\x00", start)
        needed_name = blob[start:end].decode("utf-8", "replace")
        if not needed_name.startswith("libicu") or ".so." not in needed_name:
            continue
        base = needed_name.split(".so.")[0] + ".so"
        if len(base) > len(needed_name):
            continue
        print(f"  {needed_name} -> {base}")
        blob[start:end] = base.encode() + b"\x00" * (len(needed_name) - len(base))
        changed += 1
    return changed


def main() -> int:
    raw_dir, raw_name, check_only = parse_args(sys.argv[1:])
    target = resolve_target(raw_dir, raw_name)
    blob = bytearray(target.read_bytes())

    if blob[:4] != b"\x7fELF":
        print(f"not an ELF file: {raw_name}")
        return 2

    changed = patch_dynstr(blob)

    if check_only:
        print(f"check: {changed} versioned ICU name(s) present")
        return 1 if changed else 0

    if not changed:
        print("nothing to patch")
        return 0

    target.write_bytes(bytes(blob))
    print(f"patched {changed} DT_NEEDED entry/entries in {raw_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
