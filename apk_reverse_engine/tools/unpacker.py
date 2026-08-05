import os, subprocess
from ..core.apk_context import APKContext
from ..utils.file_utils import FileUtils

class APKUnpacker:
    """APK解包工具"""

    @staticmethod
    def _find_jar(name):
        paths = [f'/usr/local/bin/{name}', f'/usr/local/bin/bin/{name}', f'/usr/share/java/{name}']
        for p in paths:
            if os.path.exists(p): return p
        return None

    @staticmethod
    def apktool_decode(apk_path, output_dir, force=False, no_src=False, no_res=False):
        apktool = APKUnpacker._find_jar('apktool.jar')
        if not apktool:
            return {"success": False, "error": "apktool.jar not found"}
        cmd = ['java', '-jar', apktool, 'd', apk_path, '-o', output_dir]
        if force: cmd.append('-f')
        if no_src: cmd.append('--no-src')
        if no_res: cmd.append('--no-res')
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": r.stdout + r.stderr, "dir": output_dir if r.returncode == 0 else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def extract_raw(apk_path, output_dir):
        ctx = APKContext(apk_path)
        ctx.extract_to(output_dir)
        ctx.close()
        return {"success": True, "dir": output_dir}

    @staticmethod
    def extract_dex(apk_path, output_dir):
        ctx = APKContext(apk_path)
        FileUtils.ensure_dir(output_dir)
        dex_files = ctx.get_dex_files()
        for d in dex_files:
            out_name = d.replace('/', '_')
            FileUtils.safe_write(os.path.join(output_dir, out_name), ctx.read_file(d))
        ctx.close()
        return {"success": True, "dex_files": dex_files, "dir": output_dir}

    @staticmethod
    def extract_so(apk_path, output_dir):
        ctx = APKContext(apk_path)
        FileUtils.ensure_dir(output_dir)
        so_files = ctx.get_so_files()
        for s in so_files:
            out_name = s.replace('/', '_')
            FileUtils.safe_write(os.path.join(output_dir, out_name), ctx.read_file(s))
        ctx.close()
        return {"success": True, "so_files": so_files, "dir": output_dir}

    @staticmethod
    def extract_resources(apk_path, output_dir):
        """提取资源文件(res/ + assets/)"""
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
        """按类型提取文件"""
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
