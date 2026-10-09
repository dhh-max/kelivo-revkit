#!/usr/bin/env python3
"""把一个 Blutter runner 注册进 runners.json。

字段约定（与既有条目一致）：
  sha256          打包（strip 后）文件的哈希 —— Kotlin 侧校验 nativeLibraryDir 用
  packagedSha256  strip 前的构建产物哈希     —— 仅供溯源，不参与校验
  source          blutter-termux            —— 与其它 runner 同源

用法:
  python tools/blutter_register_runner.py <runners.json> <stripped.so> <unstripped.bin> <dartMinor> <libraryName>
例如:
  python tools/blutter_register_runner.py .../runners.json .../libblutter_3_13.so \\
      build/blutter-toolchain/blutter_3_13.unstripped.bin 3.13 blutter_3_13
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


def sha256_of(path: str) -> str:
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def version_key(value: str):
    try:
        return [int(x) for x in str(value).split(".")]
    except ValueError:
        return [0]


def main() -> int:
    manifest_path = pathlib.Path(sys.argv[1])
    stripped, unstripped, dart_minor, library_name = sys.argv[2:6]

    if not stripped or not pathlib.Path(stripped).is_file():
        print(f"stripped runner not found: {stripped}")
        return 2
    if not pathlib.Path(unstripped).is_file():
        print(f"unstripped runner not found: {unstripped}")
        return 2

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    runner_id = library_name.replace("blutter_", "exec-dart-").replace(".", "_")

    entry = {
        "abi": data.get("targetAbi", "arm64-v8a"),
        "analysis": True,
        "backend": "exec",
        "dartVersion": dart_minor,
        "libraryName": library_name,
        "protocolVersion": data.get("protocolVersion", 1),
        "runnerId": runner_id,
        "packagedSha256": sha256_of(unstripped),
        "sha256": sha256_of(stripped),
        "source": "blutter-termux",
        "status": "bundled",
    }

    runners = [r for r in data.get("runners", []) if r.get("dartVersion") != dart_minor]
    runners.append(entry)
    runners.sort(key=lambda r: version_key(r.get("dartVersion", "0")))
    data["runners"] = runners

    manifest_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"registered Dart {dart_minor} ({library_name}) -> {manifest_path}")
    print(f"  sha256         = {entry['sha256']}")
    print(f"  packagedSha256 = {entry['packagedSha256']}")
    print(f"  total runners  = {len(runners)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
