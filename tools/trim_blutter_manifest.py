#!/usr/bin/env python3
"""Blutter runners.json 防回升守卫（2026-09-14 重建，原脚本随 .git 损坏事故丢失）。

用户决策（勿回退）：保留 Dart 3.x 及以上 runner，2.x 及以下不打包、不进 manifest。
配套：build.gradle.kts packaging.excludes `libblutter_2_*.so`（打包期第二道）。

用法：
  python tools/trim_blutter_manifest.py            # 原地裁剪并写回
  python tools/trim_blutter_manifest.py --check    # 只检查，发现 2.x 时退出码 1

幂等：无 2.x 条目时不写文件、退出码 0。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent.parent / (
    "android/app/src/main/assets/blutter/runners.json"
)
MIN_MAJOR = 3


def main() -> int:
    if not MANIFEST.exists():
        print(f"manifest not found: {MANIFEST}")
        return 2
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    runners = data.get("runners") or []
    stale = [
        r
        for r in runners
        if int(str(r.get("dartVersion", "0")).split(".")[0]) < MIN_MAJOR
    ]
    if not stale:
        print(f"OK: {len(runners)} runners, all >= {MIN_MAJOR}.x")
        return 0
    for r in stale:
        print(f"stale: dart {r.get('dartVersion')} ({r.get('runnerId')})")
    if "--check" in sys.argv:
        print(f"CHECK FAILED: {len(stale)} pre-{MIN_MAJOR}.x entries present")
        return 1
    data["runners"] = [
        r for r in runners if r not in stale
    ]
    MANIFEST.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"trimmed: {len(runners)} -> {len(data['runners'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
