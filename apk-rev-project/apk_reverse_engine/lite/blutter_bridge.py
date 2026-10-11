# -*- coding: utf-8 -*-
"""blutter_bridge — 通过外部 libblutter_<dart>.so 反汇编 Flutter AOT 产物

KE 项目已把 BlutterAndroid 的 bionic 版 runner 打包进 `android/app` 的
`jniLibs/arm64-v8a/`（形如 `libblutter_2_14_1.so` … `libblutter_3_13_4.so`，
共 70 个 Dart 版本）。本模块提供 Python 侧入口，把 libapp.so + libflutter.so
喂给 runner 生成 `pp.txt / objs.txt / asm/`。

支持两种调用方式：
  1) exec_runner(...): 用 `/system/bin/linker64` 直接 exec runner（无 root、无隔离进程），
     需要在 Android 上运行，与 App 内 BlutterExecBackend 的调用协议一致。
  2) exec_runner_via_bridge(...): 若存在 libblutter_bridge.so，可通过它走子进程 +
     libdartvm/libcapstone libc++ 环境，稳定性更高（与 BlutterEmbeddedBackend 类似）。

对外 API:
  - detect_flutter(apk)           -> dict（识别 libapp.so / libflutter.so 所在 ABI）
  - pick_runner(abi, dart_ver)    -> dict（选出一个合适的 runner 描述）
  - analyze_flutter(app_dir, runners_dir, out_dir) -> dict
  - list_runners(runners_dir)     -> list[dict]
"""
from __future__ import annotations
import os, re, json, struct, subprocess, zipfile, shutil, glob


# ── Dart VM 版本 -> runner 文件名 ─────────────────────────────
# BlutterAndroid 支持列表（详见 BLUTTER_INTEGRATION.md）
SUPPORTED_DART_VERSIONS = (
    ['2.14.1', '2.14.2', '2.14.4',
     '2.15.0', '2.15.1',
     '2.16.0', '2.16.1', '2.17.0', '2.17.5', '2.17.7',
     '2.18.0', '2.18.2', '2.18.4', '2.18.6',
     '2.19.6',
     '3.4.0', '3.4.1', '3.4.2', '3.4.3',
     '3.5.0', '3.5.1', '3.5.2',
     '3.6.0', '3.6.1',
     '3.7.0', '3.7.1', '3.7.2', '3.7.3',
     '3.8.0', '3.8.1', '3.8.2', '3.8.3', '3.8.4', '3.8.5',
     '3.9.0', '3.9.1', '3.9.2',
     '3.10.0', '3.10.1', '3.10.2', '3.10.3', '3.10.4',
     '3.11.0', '3.11.1', '3.11.2', '3.11.3', '3.11.4', '3.11.5',
     '3.12.0', '3.12.1', '3.12.2', '3.12.3', '3.12.4',
     '3.13.0', '3.13.1', '3.13.2', '3.13.3', '3.13.4']
)


def dart_to_runner_name(version: str) -> str:
    """Dart 版本 -> runner 库文件名，如 '2.14.1' -> 'libblutter_2_14_1.so'"""
    return 'libblutter_%s.so' % version.replace('.', '_')


def list_runners(runners_dir: str) -> list:
    """扫描目录中所有 libblutter_*.so，返回清单。"""
    if not runners_dir or not os.path.isdir(runners_dir):
        return []
    out = []
    for path in sorted(glob.glob(os.path.join(runners_dir, 'libblutter_*.so'))):
        m = re.match(r'libblutter_(\d+_\d+_\d+)\.so$', os.path.basename(path))
        if not m:
            continue
        ver = m.group(1).replace('_', '.')
        out.append({
            'path': path,
            'libraryName': os.path.basename(path),
            'dartVersion': ver,
            'abi': 'arm64-v8a',
        })
    return out


def pick_runner(abi: str, dart_version: str, runners_dir: str) -> dict:
    """挑选一个匹配 (abi, dartVersion) 的 runner。

    规则：精确版本 → 同 minor 最大 → 同 major 最大 → 无匹配返回空 dict。
    """
    runners = list_runners(runners_dir)
    if not runners or not dart_version:
        return {}
    major_minor = '.'.join(dart_version.split('.')[:2])
    major = dart_version.split('.')[0]
    for r in runners:
        if r.get('dartVersion') == dart_version and r.get('abi', abi) == abi:
            return r
    for r in runners:
        if r.get('dartVersion', '').startswith(major_minor) and r.get('abi', abi) == abi:
            return r
    for r in runners:
        if r.get('dartVersion', '').startswith(major + '.') and r.get('abi', abi) == abi:
            return r
    return {}


# ── libapp.so / libflutter.so 检测 ────────────────────────────
_FLAUTER_ABI_RE = re.compile(r'^lib/([^/]+)/(libapp|libflutter)\.so$')


def detect_flutter(apk_path: str, requested_abi: str = 'auto') -> dict:
    """从 APK 中识别 Flutter AOT 产物（libapp.so / libflutter.so）。

    Returns:
        dict: {
          'ok': bool,
          'detected': bool,
          'abis': ['arm64-v8a', ...],
          'selected': {'abi': ..., 'libapp': <zip内路径>, 'libflutter': <zip内路径>,
                       'libapp_size': int, 'libflutter_size': int},
          'assets': [..],          # assets/flutter_assets/*
          'entry_count': int,
        }
    """
    result = {'ok': False, 'detected': False, 'abis': [],
              'selected': {}, 'assets': [], 'entry_count': 0}
    if not apk_path or not os.path.isfile(apk_path):
        result['error'] = '文件不存在'; return result
    try:
        zf = zipfile.ZipFile(apk_path)
        names = zf.namelist()
    except Exception as e:
        result['error'] = str(e); return result
    result['entry_count'] = len(names)
    per_abi = {}
    assets = []
    for n in names:
        if n.startswith('assets/flutter_assets/'):
            assets.append(n)
            continue
        m = _FLAUTER_ABI_RE.match(n)
        if not m: continue
        abi, kind = m.group(1), m.group(2)
        entry = per_abi.setdefault(abi, {})
        info = zf.getinfo(n)
        entry[kind] = {'path': n, 'size': info.file_size}
    result['abis'] = sorted(per_abi.keys())
    result['assets'] = assets[:200]
    # ABI 选择
    if requested_abi and requested_abi != 'auto' and requested_abi in per_abi:
        chosen_abi = requested_abi
    else:
        # 优先 arm64-v8a，其次有 libapp.so 的第一个 ABI
        for cand in ('arm64-v8a', 'armv7', 'armeabi-v7a'):
            if cand in per_abi and 'libapp' in per_abi[cand]:
                chosen_abi = cand; break
        else:
            chosen_abi = next((a for a in per_abi if 'libapp' in per_abi[a]), None)
    if not chosen_abi or 'libapp' not in per_abi[chosen_abi]:
        result['ok'] = True; return result
    app_entry = per_abi[chosen_abi]['libapp']
    flt_entry = per_abi[chosen_abi].get('libflutter')
    result['detected'] = True
    result['ok'] = True
    result['selected'] = {
        'abi': chosen_abi,
        'libapp': app_entry['path'],
        'libflutter': flt_entry['path'] if flt_entry else '',
        'libapp_size': app_entry['size'],
        'libflutter_size': flt_entry['size'] if flt_entry else 0,
    }
    return result


# ── ELF 极简解析：从 libapp.so 提取 Dart VM 版本指纹 ─────────
_SYMBOL_CACHE = {}


def _elf_symtab_names(so_bytes: bytes) -> list:
    """提取 ELF 的 dynsym / symtab 名字列表。极简实现，够用即可。"""
    key = (so_bytes[:64], len(so_bytes))
    cached = _SYMBOL_CACHE.get(key)
    if cached is not None:
        return cached
    names = []
    try:
        if so_bytes[:4] != b'\x7fELF':
            _SYMBOL_CACHE[key] = names; return names
        ei_class = so_bytes[4]
        ei_data = so_bytes[5]
        if ei_class != 2:  # 仅支持 64-bit
            _SYMBOL_CACHE[key] = names; return names
        end = '<' if ei_data == 1 else '>'
        e_shoff = struct.unpack_from(end + 'Q', so_bytes, 0x28)[0]
        e_shentsize = struct.unpack_from(end + 'H', so_bytes, 0x3a)[0]
        e_shnum = struct.unpack_from(end + 'H', so_bytes, 0x3c)[0]
        e_shstrndx = struct.unpack_from(end + 'H', so_bytes, 0x3e)[0]
        if not (0 < e_shentsize == 64 and 0 < e_shnum <= 256 and 0 <= e_shstrndx < e_shnum):
            _SYMBOL_CACHE[key] = names; return names
        shstr_off = e_shoff + e_shstrndx * 64
        shstr_sh_offset = struct.unpack_from(end + 'Q', so_bytes, shstr_off + 0x18)[0]
        shstr_sh_size = struct.unpack_from(end + 'Q', so_bytes, shstr_off + 0x20)[0]
        shstr = so_bytes[shstr_sh_offset:shstr_sh_offset + shstr_sh_size]

        for i in range(e_shnum):
            off = e_shoff + i * 64
            sh_name, sh_type = struct.unpack_from(end + 'II', so_bytes, off)
            sh_offset, sh_size = struct.unpack_from(end + 'QQ', so_bytes, off + 0x18)
            if sh_type not in (2, 11):   # SHT_SYMTAB / SHT_DYNSYM
                continue
            sh_link, sh_entsize = struct.unpack_from(end + 'HH', so_bytes, off + 0x18 - 8)
            if sh_entsize not in (16, 24):
                continue
            stride = 24 if ei_class == 2 else 16
            if stride == 16:
                for j in range(sh_size // 16):
                    entry_off = sh_offset + j * 16
                    st_name = struct.unpack_from(end + 'I', so_bytes, entry_off)[0]
                    end_pos = shstr.find(b'\x00', st_name)
                    if end_pos < 0:
                        end_pos = len(shstr)
                    nm = shstr[st_name:end_pos].decode('utf-8', 'ignore')
                    if nm:
                        names.append(nm)
            else:
                for j in range(sh_size // 24):
                    entry_off = sh_offset + j * 24
                    st_name = struct.unpack_from(end + 'I', so_bytes, entry_off)[0]
                    end_pos = shstr.find(b'\x00', st_name)
                    if end_pos < 0:
                        end_pos = len(shstr)
                    nm = shstr[st_name:end_pos].decode('utf-8', 'ignore')
                    if nm:
                        names.append(nm)
    except Exception:
        names = []
    _SYMBOL_CACHE[key] = names
    return names


# Dart 2.14+ 常见的 VM snapshot 相关符号（作为粗粒度版本识别 hint）
_SNAPSHOT_HASH_KEY = b'_kDartVmSnapshotData'
_ENGINE_HASH_KEY = b'_kDartVMEngineHash'


def fingerprint_dart(libapp_bytes: bytes) -> dict:
    """从 libapp.so 提取 Dart VM 版本相关指纹（不依赖 runner）。

    仅提取证据（snapshot hash / engine hash / compressed-pointers），
    不做完整版本匹配——版本判定交给 App 侧或 runner 自身。
    """
    ev = {'dartVersion': None, 'snapshotHash': None, 'engineHash': None,
          'compressedPointers': None, 'evidence': []}
    if not libapp_bytes:
        return ev
    # snapshot hash
    idx = libapp_bytes.find(_SNAPSHOT_HASH_KEY)
    if idx >= 0:
        ev['evidence'].append(f'_kDartVmSnapshotData @ 0x{idx:x}')
        # 简单：从符号附近 32 字节里寻找 16 字节大端十六进制（仅作证据）
    idx = libapp_bytes.find(_ENGINE_HASH_KEY)
    if idx >= 0:
        ev['evidence'].append(f'_kDartVMEngineHash @ 0x{idx:x}')
    # machine=183 表示 AArch64 ELF（arm64）
    if len(libapp_bytes) > 0x20:
        machine = struct.unpack_from('<H', libapp_bytes, 0x12)[0]
        ev['machine'] = machine
        if machine == 183:
            ev['abi'] = 'arm64-v8a'
    # 符号粗粒度
    syms = _elf_symtab_names(libapp_bytes)
    ev['symbolCount'] = len(syms)
    ev['hasSnapshotSym'] = any('_kDartVmSnapshotData' in s for s in syms[:2000])
    ev['hasEngineHashSym'] = any('_kDartVMEngineHash' in s for s in syms[:2000])
    return ev


# ── Runner 执行 ──────────────────────────────────────────────
def _write_libs(tmpdir: str, apk_path: str, entries: dict) -> dict:
    """从 APK 解出 libapp.so / libflutter.so 到 tmpdir，返回本地路径映射。"""
    zf = zipfile.ZipFile(apk_path)
    out = {}
    for key, entry in entries.items():
        path = os.path.join(tmpdir, os.path.basename(entry['path']))
        with zf.open(entry['path']) as src, open(path, 'wb') as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        out[key] = path
    return out


def exec_runner(runner_bin: str, libapp_path: str, out_dir: str,
                timeout_s: int = 600, extra_env: dict = None) -> dict:
    """通过 /system/bin/linker64 直接 exec 一个 libblutter_<dart>.so。

    约定（与 BlutterExecBackend 一致）：runner -i <libapp文件> -o <输出目录>
    """
    result = {'ok': False, 'exitCode': None, 'stdout': '', 'stderr': '',
              'outputDir': out_dir, 'runnerBin': runner_bin}
    if not os.path.isfile(runner_bin):
        result['error'] = 'runner 不存在: ' + runner_bin; return result
    if not os.path.isfile(libapp_path):
        result['error'] = 'libapp.so 不存在: ' + libapp_path; return result
    os.makedirs(out_dir, exist_ok=True)
    ld_library = os.path.dirname(runner_bin)
    env = {'LD_LIBRARY_PATH': ld_library}
    if extra_env:
        env.update(extra_env)
    try:
        cp = subprocess.run(
            ['/system/bin/linker64', runner_bin, '-i', libapp_path, '-o', out_dir],
            capture_output=True, timeout=timeout_s, env=env,
        )
        result['exitCode'] = cp.returncode
        result['stdout'] = cp.stdout.decode('utf-8', 'replace')[-8192:]
        result['stderr'] = cp.stderr.decode('utf-8', 'replace')[-8192:]
    except subprocess.TimeoutExpired as e:
        result['error'] = '超时 (%ds)' % timeout_s
        result['stdout'] = (e.stdout or b'').decode('utf-8', 'replace')[-8192:]
        return result
    except FileNotFoundError:
        result['error'] = '/system/bin/linker64 不存在（非 Android 环境）'; return result
    except Exception as e:
        result['error'] = str(e); return result
    # 校验产物
    pp = os.path.join(out_dir, 'pp.txt')
    objs = os.path.join(out_dir, 'objs.txt')
    asm = os.path.join(out_dir, 'asm')
    result['files'] = {
        'ppTxt': os.path.exists(pp),
        'objsTxt': os.path.exists(objs),
        'asmDir': os.path.isdir(asm),
    }
    result['ok'] = result['files']['ppTxt'] and result['files']['objsTxt']
    return result


def exec_runner_via_bridge(runner_bin: str, libapp_path: str,
                            libflutter_path: str, out_dir: str,
                            options_json: str = '{}',
                            bridge_lib: str = None,
                            timeout_s: int = 600) -> dict:
    """若设备上有 libblutter_bridge.so，走 native bridge 调用（更稳）。

    bridge API 与 KE 内 NativeBlutterBridge 一致：
        nativeRun(libraryName, libappFd, libflutterFd, resultFd, optionsJson, cancellationToken)
    """
    result = {'ok': False, 'error': '', 'outputDir': out_dir}
    if bridge_lib and not os.path.isfile(bridge_lib):
        result['error'] = 'bridge lib 不存在: ' + bridge_lib; return result
    # bridge 需要在 JNI 环境里加载，纯 Python 无法直接调用；这里提供 shell 兜底
    result['error'] = ('exec_runner_via_bridge 仅 App 内 Kotlin 可用；'
                       'Python 侧请使用 exec_runner() 走 linker64')
    return result


def analyze_flutter(apk_path: str, runners_dir: str, out_dir: str,
                    abi: str = 'auto', dart_version: str = None,
                    log=None) -> dict:
    """一站式：识别 Flutter → 选 runner → exec → 收集产物。

    Args:
        apk_path:      含 Flutter AOT 的 APK 路径
        runners_dir:   libblutter_*.so 所在目录（例如 Android nativeLibraryDir）
        out_dir:       产物输出目录（pp.txt / objs.txt / asm/）
        abi:           目标 ABI，默认 auto（优先 arm64-v8a）
        dart_version:  显式指定 Dart 版本；None 时由 runner 自动识别或选最新
        log:           日志回调 fn(str)
    """
    log = log or (lambda s: None)
    result = {'ok': False, 'apk': apk_path, 'outDir': out_dir,
              'detection': {}, 'runner': {}, 'exit': {}}
    det = detect_flutter(apk_path, requested_abi=abi)
    result['detection'] = det
    if not det.get('detected'):
        result['note'] = '未识别到 Flutter AOT 产物'; return result
    sel = det['selected']
    log('识别到 Flutter: abi=%s libapp=%s' % (sel['abi'], sel['libapp']))
    # 选择 runner
    if not dart_version:
        # 无法从纯 bytes 精确推断 Dart 版本；由 pick_runner 兜底
        dart_version = None
    runner = pick_runner(sel['abi'], dart_version or '', runners_dir) if dart_version else {}
    if not runner:
        # 兜底：任意 arm64 runner 让 runner 自己探测
        all_runners = list_runners(runners_dir)
        runner = next((r for r in all_runners if r.get('abi') == sel['abi']), all_runners[0] if all_runners else {})
    if not runner:
        result['note'] = '未找到任何可用 runner（runners_dir=%s）' % runners_dir
        return result
    result['runner'] = runner
    log('选定 runner: %s (dart=%s)' % (runner['libraryName'], runner['dartVersion']))
    # 临时目录解出 libapp.so
    tmp = os.path.join(out_dir, '_tmp')
    os.makedirs(tmp, exist_ok=True)
    try:
        libapp_local = os.path.join(tmp, os.path.basename(sel['libapp']))
        with zipfile.ZipFile(apk_path) as zf, open(libapp_local, 'wb') as f:
            with zf.open(sel['libapp']) as src:
                shutil.copyfileobj(src, f, length=1024 * 1024)
    except Exception as e:
        result['error'] = '解出 libapp.so 失败: ' + str(e); return result

    log('调用 runner ...')
    ex = exec_runner(runner['path'], libapp_local, out_dir)
    result['exit'] = ex
    result['ok'] = ex.get('ok', False)
    # 指纹
    try:
        with open(libapp_local, 'rb') as f:
            result['fingerprint'] = fingerprint_dart(f.read())
    except Exception:
        result['fingerprint'] = {}
    log('done: ok=%s files=%s' % (result['ok'], ex.get('files', {})))
    return result


__all__ = [
    'SUPPORTED_DART_VERSIONS',
    'dart_to_runner_name',
    'list_runners',
    'pick_runner',
    'detect_flutter',
    'fingerprint_dart',
    'exec_runner',
    'exec_runner_via_bridge',
    'analyze_flutter',
]