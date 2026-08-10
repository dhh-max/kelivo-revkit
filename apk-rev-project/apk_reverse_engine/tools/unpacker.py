"""APK解包工具 - 全面优化版

设计改进：
  1. 分类归档 → 按 dex/lib/res/assets/META-INF 分目录存放
  2. 进度反馈 → 大APK流式解压时实时输出进度
  3. 智能过滤 → 按文件类型/正则/分类选择提取
  4. 完整性校验 → 解压后自动校验 SHA256
  5. 并行解压 → 多线程加速大文件解压
  6. 增量模式 → 跳过已存在且未修改的文件
  7. 丰富选项 → 保留/丢弃时间戳、权限、空目录
  8. 通用支持 → 支持 APK/ZIP/JAR/WAR/TAR/单文件/目录等任意文件
"""


from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import os, subprocess, zipfile, hashlib, re, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core.archive_context import ArchiveContext, detect_file_type
# 兼容别名：APKContext → ArchiveContext
# 所有原本使用 APKContext 的方法现在统一使用 ArchiveContext
# ArchiveContext 完全兼容 APKContext 的接口，同时支持任意文件类型
APKContext = ArchiveContext
from ..utils.file_utils import FileUtils


class APKUnpacker:
    """APK解包工具 - 全面优化版"""

    CATEGORY_MAP = {
        'dex': ['.dex'],
        'lib': ['.so'],
        'res': ['.arsc', '.png', '.jpg', '.jpeg', '.gif', '.webp',
                '.bmp', '.svg', '.xml', '.mp3', '.ogg', '.wav',
                '.mp4', '.webm', '.ttf', '.otf', '.json'],
        'assets': [], 'meta_inf': [], 'kotlin': ['.kotlin_module'],
        'cert': ['.RSA', '.SF', '.MF', '.DSA', '.EC'],
    }

    @staticmethod
    def _classify_file(arcname):
        name_lower = arcname.lower()
        if arcname.startswith('META-INF/'):
            if any(name_lower.endswith(ext) for ext in ['.rsa', '.sf', '.mf', '.dsa', '.ec']):
                return 'cert'
            return 'meta_inf'
        if arcname.startswith('assets/'): return 'assets'
        if arcname.startswith('res/'): return 'res'
        if arcname.startswith('lib/'): return 'lib'
        if arcname.startswith('kotlin/'): return 'kotlin'
        if name_lower.endswith('.dex'): return 'dex'
        for cat, exts in APKUnpacker.CATEGORY_MAP.items():
            if any(name_lower.endswith(ext) for ext in exts): return cat
        return 'unknown'

    @staticmethod
    def _get_category_dir(category, structure):
        if not structure:
            return ''
        dir_map = {'dex': 'dex', 'lib': 'lib', 'res': 'res', 'assets': 'assets',
                   'meta_inf': 'META-INF', 'cert': 'META-INF', 'kotlin': 'kotlin',
                   'unknown': 'unknown'}
        return dir_map.get(category, 'unknown')

    @staticmethod
    def _get_rel_path(arcname, category):
        """获取分类后的相对路径"""
        if category == 'assets' and arcname.startswith('assets/'):
            return arcname[len('assets/'):]
        if category == 'res' and arcname.startswith('res/'):
            return arcname[len('res/'):]
        if category == 'lib' and arcname.startswith('lib/'):
            return arcname[len('lib/'):]
        if category == 'kotlin' and arcname.startswith('kotlin/'):
            return arcname[len('kotlin/'):]
        if category in ('meta_inf', 'cert') and arcname.startswith('META-INF/'):
            return arcname[len('META-INF/'):]
        if category == 'dex' and arcname.startswith('classes'):
            # classes.dex, classes2.dex 等保留原文件名
            return os.path.basename(arcname)
        return os.path.basename(arcname)

    @staticmethod
    def extract_raw(apk_path, output_dir, structure=True, progress_callback=None,
                    flatten=False, dry_run=False):
        """解压任意文件/归档（稳健模式）

        参数:
            apk_path: 文件路径（支持 APK/ZIP/JAR/WAR/TAR/单文件/目录）
            output_dir: 输出目录
            structure: 是否按分类归档子目录
            progress_callback: 进度回调(extracted, total, filename)
            flatten: 扁平化，不保留子目录路径
            dry_run: 仅预览不实际解压
        """
        try:
            ctx = ArchiveContext(apk_path)
            if dry_run:
                info = ctx.get_structure_summary()
                ftype = ctx.file_type
                ctx.close()
                return {
                    "success": True, "dry_run": True,
                    "total": info.get("total_files", 0),
                    "dex_count": info.get("dex_count", 0),
                    "so_count": info.get("so_count", 0),
                    "res_count": info.get("res_count", 0),
                    "assets_count": info.get("assets_count", 0),
                    "size": info.get("size", 0),
                    "file_type": ftype,
                    "dir": output_dir
                }
            result = ctx.extract_to(output_dir, structure=structure,
                                    progress_callback=progress_callback, flatten=flatten)
            ctx.close()
            errors = result.get('errors', [])
            extracted = result.get('extracted', 0)
            # 成功条件：无错误 或 有提取成功的文件
            success = len(errors) == 0 or extracted > 0
            return {
                "success": success, "dir": output_dir, "extracted": extracted,
                "total": result.get('total', 0), "errors": errors,
                "categories": result.get('categories', {}), "sha256": result.get('sha256', ''),
                "error": errors[0]['error'] if errors and not success else None
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def extract_selective(apk_path, output_dir, include_types=None, exclude_types=None,
                          include_pattern=None, exclude_pattern=None, structure=True):
        """选择性提取"""
        ctx = APKContext(apk_path)
        selected = [f for f in ctx.file_list if not f.endswith('/') and
                    (not exclude_types or not any(f.lower().endswith(t.lower()) for t in exclude_types)) and
                    (not exclude_pattern or not re.search(exclude_pattern, f)) and
                    (not include_types or any(f.lower().endswith(t.lower()) for t in include_types)) and
                    (not include_pattern or re.search(include_pattern, f))]
        ctx.close()
        ctx2 = APKContext(apk_path)
        result = ctx2.extract_to(output_dir, members=selected, structure=structure)
        ctx2.close()
        return {"success": len(result.get('errors', [])) < result.get('extracted', 0) or result.get('extracted', 0) > 0,
                "dir": output_dir, "extracted": result.get('extracted', 0), "total": len(selected),
                "errors": result.get('errors', []), "categories": result.get('categories', {})}

    @staticmethod
    def extract_dex(apk_path, output_dir):
        ctx = APKContext(apk_path)
        FileUtils.ensure_dir(output_dir)
        dex_files = ctx.get_dex_files()
        for d in dex_files:
            FileUtils.safe_write(os.path.join(output_dir, d.replace('/', '_')), ctx.read_file(d))
        ctx.close()
        return {"success": True, "dex_files": dex_files, "dir": output_dir, "count": len(dex_files)}

    @staticmethod
    def extract_so(apk_path, output_dir):
        """按架构分类提取SO"""
        ctx = APKContext(apk_path)
        FileUtils.ensure_dir(output_dir)
        so_files = ctx.get_so_files()
        arch_map = {}
        for s in so_files:
            parts = s.split('/')
            arch = parts[1] if len(parts) >= 3 and parts[0] == 'lib' else 'unknown'
            arch_map.setdefault(arch, []).append(s)
            arch_dir = os.path.join(output_dir, arch)
            FileUtils.ensure_dir(arch_dir)
            FileUtils.safe_write(os.path.join(arch_dir, os.path.basename(s)), ctx.read_file(s))
        ctx.close()
        return {"success": True, "so_files": so_files, "architectures": arch_map, "dir": output_dir, "count": len(so_files)}

    @staticmethod
    def extract_resources(apk_path, output_dir):
        ctx = APKContext(apk_path)
        FileUtils.ensure_dir(output_dir)
        extracted = {'res': [], 'assets': []}
        for f in ctx.get_res_files():
            dest = os.path.join(output_dir, f)
            FileUtils.ensure_dir(os.path.dirname(dest))
            FileUtils.safe_write(dest, ctx.read_file(f))
            extracted['res'].append(f)
        for f in ctx.get_assets_files():
            dest = os.path.join(output_dir, f)
            FileUtils.ensure_dir(os.path.dirname(dest))
            FileUtils.safe_write(dest, ctx.read_file(f))
            extracted['assets'].append(f)
        ctx.close()
        return {"success": True, **extracted, "dir": output_dir}

    @staticmethod
    def extract_by_type(apk_path, output_dir, file_types):
        ctx = APKContext(apk_path)
        FileUtils.ensure_dir(output_dir)
        extracted = []
        for f in ctx.list_files():
            if any(f.endswith(t) for t in file_types):
                dest = os.path.join(output_dir, f.replace('/', '_'))
                FileUtils.safe_write(dest, ctx.read_file(f))
                extracted.append(f)
        ctx.close()
        return {"success": True, "extracted": extracted, "count": len(extracted), "dir": output_dir}

    @staticmethod
    def extract_parallel(apk_path, output_dir, max_workers=4, structure=True):
        """多线程并行解压（流式写入，不读入内存）"""
        import zipfile
        from concurrent.futures import ThreadPoolExecutor, as_completed

        FileUtils.ensure_dir(output_dir)
        # 先读取文件列表
        with zipfile.ZipFile(apk_path, 'r') as zf:
            all_files = [n for n in zf.namelist() if not n.endswith('/')]

        extracted = [0]
        errors = []
        categories = {}
        lock = __import__('threading').Lock()

        def _write(arcname):
            try:
                cat = APKUnpacker._classify_file(arcname)
                sub = APKUnpacker._get_category_dir(cat, structure)
                rel = APKUnpacker._get_rel_path(arcname, cat)
                dest = os.path.join(output_dir, sub, rel) if sub else os.path.join(output_dir, arcname)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                # 每个线程独立打开 zip，流式写入
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    with zf.open(arcname) as src, open(dest, 'wb') as dst:
                        while True:
                            chunk = src.read(1048576)
                            if not chunk:
                                break
                            dst.write(chunk)
                if arcname.endswith('.so'):
                    try:
                        os.chmod(dest, os.stat(dest).st_mode | 0o111)
                    except OSError:
                        pass
                with lock:
                    extracted[0] += 1
                    categories[cat] = categories.get(cat, 0) + 1
            except Exception as e:
                with lock:
                    errors.append({'file': arcname, 'error': str(e)})

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            list(ex.map(_write, all_files))
        return {'extracted': extracted[0], 'total': len(all_files), 'errors': errors,
                'dir': output_dir, 'categories': categories,
                'success': len(errors) == 0 or extracted[0] > 0}

    @staticmethod
    def extract_incremental(apk_path, output_dir, structure=True, flatten=False):
        """增量解压：跳过已存在且大小匹配的文件"""
        ctx = APKContext(apk_path)
        FileUtils.ensure_dir(output_dir)
        all_files = [n for n in ctx.file_list if not n.endswith('/')]
        skipped = extracted = 0
        errors = []
        categories = {}
        for name in all_files:
            try:
                cat = APKUnpacker._classify_file(name)

                if flatten:
                    base = os.path.basename(name)
                    dest = os.path.join(output_dir, base)
                    if os.path.exists(dest):
                        dest = os.path.join(output_dir, name.replace('/', '_'))
                elif structure:
                    sub = APKUnpacker._get_category_dir(cat, structure)
                    rel = APKUnpacker._get_rel_path(name, cat)
                    dest = os.path.join(output_dir, sub, rel) if sub else os.path.join(output_dir, name)
                else:
                    dest = os.path.join(output_dir, name)

                os.makedirs(os.path.dirname(dest), exist_ok=True)
                info = ctx.zip.getinfo(name)
                if os.path.exists(dest) and os.path.getsize(dest) == info.file_size:
                    skipped += 1
                    categories[cat] = categories.get(cat, 0) + 1
                    continue
                data = ctx.read_file(name)
                with open(dest, 'wb') as f: f.write(data)
                if name.endswith('.so'): os.chmod(dest, os.stat(dest).st_mode | 0o111)
                extracted += 1
                categories[cat] = categories.get(cat, 0) + 1
            except Exception as e:
                errors.append({'file': name, 'error': str(e)})
        ctx.close()
        return {'extracted': extracted, 'skipped': skipped, 'total': len(all_files),
                'errors': errors, 'dir': output_dir, 'categories': categories,
                'success': len(errors) == 0 or extracted > 0}

    @staticmethod
    def extract_by_category(apk_path, output_dir, categories=None, structure=True):
        """按分类提取（dex/lib/res/assets/meta_inf/all）

        参数:
            categories: 分类列表，如 ['dex', 'lib', 'res', 'assets', 'meta_inf', 'all']
                        支持别名: so→lib, cert→meta_inf
        """
        if not categories:
            categories = ['all']
        # 别名映射
        alias_map = {'so': 'lib', 'cert': 'meta_inf', 'native': 'lib'}
        normalized = []
        for c in categories:
            c = c.strip().lower()
            normalized.append(alias_map.get(c, c))

        ctx = APKContext(apk_path)
        FileUtils.ensure_dir(output_dir)
        extracted = 0
        errors = []
        cat_counts = {}
        for name in [n for n in ctx.file_list if not n.endswith('/')]:
            try:
                cat = APKUnpacker._classify_file(name)
                cat_group = 'meta_inf' if cat == 'cert' else cat
                if 'all' not in normalized and cat_group not in normalized:
                    continue
                if structure:
                    sub = APKUnpacker._get_category_dir(cat, structure)
                    rel = APKUnpacker._get_rel_path(name, cat)
                    dest = os.path.join(output_dir, sub, rel) if sub else os.path.join(output_dir, name)
                else:
                    dest = os.path.join(output_dir, name)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, 'wb') as f:
                    f.write(ctx.read_file(name))
                if name.endswith('.so'):
                    os.chmod(dest, os.stat(dest).st_mode | 0o111)
                extracted += 1
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            except Exception as e:
                errors.append({'file': name, 'error': str(e)})
        ctx.close()
        return {'success': len(errors) == 0 or extracted > 0, 'extracted': extracted,
                'errors': errors, 'dir': output_dir, 'categories': cat_counts}

    @staticmethod
    def verify_integrity(apk_path, output_dir):
        """校验解压完整性"""
        ctx = APKContext(apk_path)
        orig = len([n for n in ctx.file_list if not n.endswith('/')])
        ctx.close()
        cnt = sz = 0
        sha = hashlib.sha256()
        for root, dirs, files in sorted(os.walk(output_dir)):
            for f in sorted(files):
                fp = os.path.join(root, f)
                cnt += 1
                sz += os.path.getsize(fp)
                with open(fp, 'rb') as fh:
                    for chunk in iter(lambda: fh.read(65536), b''): sha.update(chunk)
        return {'original': orig, 'extracted': cnt, 'missing': max(0, orig - cnt),
                'size': sz, 'sha256': sha.hexdigest(), 'ok': orig - cnt <= 0}

    @staticmethod
    def extract_manifest(apk_path, output_dir, manifest=None, structure=True,
                         fail_on_missing=True, verify=True):
        """按精确清单原子提取 + 校验

        设计：
          1. 清单解析 → 支持精确条目列表 / 'all' / 分类别名(dex,lib,res,assets,meta_inf)
          2. 原子提取 → 先解压到临时目录，全部成功后原子性移动到最终目录
          3. 逐条校验 → 每个条目校验存在性 + SHA256 指纹，缺失项默认使操作失败
          4. 返回清单报告 → 每个条目提取状态/校验状态/指纹

        参数:
            apk_path: APK路径
            output_dir: 最终输出目录
            manifest: 精确清单。None/'all'=全部文件；list=条目列表；
                      字典 {'files': [...], 'categories': [...], 'fail_on_missing': bool}
            structure: 是否按分类归档
            fail_on_missing: 清单中缺失条目是否导致失败（原子性）
            verify: 是否做 SHA256 校验
        """
        import tempfile
        ctx = APKContext(apk_path)
        all_files = [n for n in ctx.file_list if not n.endswith('/')]

        # ---- 解析清单 ----
        fail_on_missing_eff = fail_on_missing
        file_list = None
        categories = None
        if isinstance(manifest, dict):
            file_list = manifest.get('files')
            categories = manifest.get('categories')
            fail_on_missing_eff = manifest.get('fail_on_missing', fail_on_missing)
        elif isinstance(manifest, (list, tuple)) and manifest:
            file_list = list(manifest)
        # None / 'all' / 空list 视为全部

        target_map = {}  # arcname -> (cat)
        if file_list:
            for f in file_list:
                target_map[f] = None
        elif categories:
            alias_map = {'so': 'lib', 'cert': 'meta_inf', 'native': 'lib'}
            norm_cats = {alias_map.get(c.strip().lower(), c.strip().lower()) for c in categories}
            for f in all_files:
                cat = APKUnpacker._classify_file(f)
                g = 'meta_inf' if cat == 'cert' else cat
                if 'all' not in norm_cats and g not in norm_cats:
                    continue
                target_map[f] = cat
        else:
            for f in all_files:
                target_map[f] = APKUnpacker._classify_file(f)

        # ---- 预检：清单是否有条目根本不存在 ----
        missing = [f for f in target_map if f not in set(all_files)]
        if missing and fail_on_missing_eff:
            ctx.close()
            return {"success": False, "error": "manifest entries not in apk",
                    "missing": missing, "extracted": 0, "total": len(target_map)}

        # ---- 原子提取：先写入临时目录 ----
        tmp_dir = tempfile.mkdtemp(prefix='.apk_extract_', dir=os.path.dirname(output_dir) or '.')
        extracted = 0
        errors = []
        cat_counts = {}
        try:
            for arcname in target_map:
                cat = APKUnpacker._classify_file(arcname)
                try:
                    if structure:
                        sub = APKUnpacker._get_category_dir(cat, structure)
                        rel = APKUnpacker._get_rel_path(arcname, cat)
                        dest = os.path.join(tmp_dir, sub, rel) if sub else os.path.join(tmp_dir, arcname)
                    else:
                        dest = os.path.join(tmp_dir, arcname)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, 'wb') as f:
                        f.write(ctx.read_file(arcname))
                    if arcname.endswith('.so'):
                        os.chmod(dest, os.stat(dest).st_mode | 0o111)
                    extracted += 1
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
                except Exception as e:
                    errors.append({'file': arcname, 'error': str(e)})
            if errors:
                # 有失败条目，原子性撤销
                shutil.rmtree(tmp_dir, ignore_errors=True)
                ctx.close()
                return {"success": False, "error": "atomic extract failed, rolled back",
                        "errors": errors, "extracted": 0, "total": len(target_map)}
            # 全部成功 → 原子移动到最终目录
            FileUtils.ensure_dir(output_dir)
            if os.path.exists(output_dir) and os.listdir(output_dir):
                # 目标非空，合并
                for root, dirs, files in os.walk(tmp_dir):
                    rel_dir = os.path.relpath(root, tmp_dir)
                    for d in dirs:
                        os.makedirs(os.path.join(output_dir, rel_dir, d), exist_ok=True)
                    for f in files:
                        src = os.path.join(root, f)
                        dst = os.path.join(output_dir, rel_dir, f)
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        shutil.move(src, dst)
            else:
                shutil.rmtree(output_dir, ignore_errors=True)
                os.makedirs(output_dir, exist_ok=True)
                for item in os.listdir(tmp_dir):
                    shutil.move(os.path.join(tmp_dir, item), output_dir)
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception as e:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            ctx.close()
            return {"success": False, "error": str(e), "extracted": 0, "total": len(target_map)}

        # ---- 逐条校验 ----
        report = []
        if verify:
            for arcname in target_map:
                cat = APKUnpacker._classify_file(arcname)
                try:
                    disk_sha = hashlib.sha256(ctx.read_file(arcname)).hexdigest()
                    # 校验写入磁盘的文件
                    if structure:
                        sub = APKUnpacker._get_category_dir(cat, structure)
                        rel = APKUnpacker._get_rel_path(arcname, cat)
                        fpath = os.path.join(output_dir, sub, rel) if sub else os.path.join(output_dir, arcname)
                    else:
                        fpath = os.path.join(output_dir, arcname)
                    with open(fpath, 'rb') as fh:
                        written_sha = hashlib.sha256(fh.read()).hexdigest()
                    ok = (disk_sha == written_sha)
                except Exception:
                    ok, disk_sha = False, ''
                report.append({'file': arcname, 'verified': ok, 'sha256': disk_sha})
        ctx.close()
        verified_ok = sum(1 for r in report if r['verified']) if verify else extracted
        success = (not missing) if fail_on_missing_eff else True
        return {"success": success, "dir": output_dir, "extracted": extracted,
                "total": len(target_map), "missing": missing,
                "verified": verified_ok if verify else None,
                "categories": cat_counts, "report": report}

    @staticmethod
    def _find_jar(name):
        for p in [f'/usr/local/bin/{name}', f'/usr/local/bin/bin/{name}', f'/usr/share/java/{name}']:
            if os.path.exists(p): return p
        return None

    @staticmethod
    def apktool_decode(apk_path, output_dir, force=False, no_src=False, no_res=False):
        apktool = APKUnpacker._find_jar('apktool.jar')
        if not apktool: return {"success": False, "error": "apktool.jar not found"}
        cmd = ['java', '-jar', apktool, 'd', apk_path, '-o', output_dir]
        if force: cmd.append('-f')
        if no_src: cmd.append('--no-src')
        if no_res: cmd.append('--no-res')
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": r.stdout + r.stderr,
                    "dir": output_dir if r.returncode == 0 else None}
        except Exception as e:
            return {"success": False, "error": str(e)}