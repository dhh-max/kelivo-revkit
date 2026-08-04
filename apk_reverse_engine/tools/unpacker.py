
import os, subprocess
from ..core.apk_context import APKContext
from ..utils.file_utils import FileUtils

class APKUnpacker:
    @staticmethod
    def apktool_decode(apk_path, output_dir, force=False):
        cmd = ["java", "-jar", "/usr/local/bin/apktool.jar", "d", apk_path, "-o", output_dir]
        if force: cmd.append("-f")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": r.stdout + r.stderr, "dir": output_dir if r.returncode == 0 else None}
        except Exception as e: return {"success": False, "error": str(e)}
    @staticmethod
    def extract_raw(apk_path, output_dir):
        ctx = APKContext(apk_path); ctx.extract_to(output_dir); ctx.close()
        return {"success": True, "dir": output_dir}
    @staticmethod
    def extract_dex(apk_path, output_dir):
        ctx = APKContext(apk_path); FileUtils.ensure_dir(output_dir)
        dex_files = ctx.get_dex_files()
        for d in dex_files:
            with open(os.path.join(output_dir, d.replace("/", "_")), "wb") as f:
                f.write(ctx.read_file(d))
        ctx.close()
        return {"success": True, "dex_files": dex_files, "dir": output_dir}
    @staticmethod
    def extract_so(apk_path, output_dir):
        ctx = APKContext(apk_path); FileUtils.ensure_dir(output_dir)
        so_files = ctx.get_so_files()
        for s in so_files:
            with open(os.path.join(output_dir, s.replace("/", "_")), "wb") as f:
                f.write(ctx.read_file(s))
        ctx.close()
        return {"success": True, "so_files": so_files, "dir": output_dir}
