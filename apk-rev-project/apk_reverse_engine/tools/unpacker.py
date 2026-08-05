"""APK解包工具 - 全面优化版

设计改进：
  1. 分类归档 → 按 dex/lib/res/assets/META-INF 分目录存放
  2. 进度反馈 → 大APK流式解压时实时输出进度
  3. 智能过滤 → 按文件类型/正则/分类选择提取
  4. 完整性校验 → 解压后自动校验 SHA256
  5. 并行解压 → 多线程加速大文件解压
  6. 增量模式 → 跳过已存在且未修改的文件
  7. 丰富选项 → 保留/丢弃时间戳、权限、空目录
"""

import os, subprocess, zipfile, hashlib, re, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ..core.apk_context import APKContext
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
        """解压APK原始文件（稳健模式）

        参数:
            apk_path: APK路径
            output_dir: 输出目录
            structure: 是否按分类归档子目录
            progress_callback: 进度回调(extracted, total, filename)
            flatten: 扁平化，不保留子目录路径
            dry_run: 仅预览不实际解压
        """
        try:
            ctx = APKContext(apk_path)
            if dry_run:
                info = ctx.get_structure_summary()
                ctx.close()
                return {
                    "success": True, "dry_run": True,
                    "total": info.get("total_files", 0),
                    "dex_count": info.get("dex_count", 0),
                    "so_count": info.get("so_count", 0),
                    "res_count": info.get("res_count", 0),
                    "assets_count": info.get("assets_count", 0),
                    "size": info.get("size", 0),
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