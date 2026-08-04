import os, shutil, tempfile
class FileUtils:
    @staticmethod
    def ensure_dir(path): os.makedirs(path, exist_ok=True); return path
    @staticmethod
    def safe_delete(path):
        if os.path.isfile(path): os.remove(path)
        elif os.path.isdir(path): shutil.rmtree(path, ignore_errors=True)
    @staticmethod
    def get_temp_dir(prefix="reng_"): return tempfile.mkdtemp(prefix=prefix)
    @staticmethod
    def copy_file(src, dst): shutil.copy2(src, dst); return dst
    @staticmethod
    def human_size(size):
        for u in ['B','KB','MB','GB']:
            if size < 1024: return f"{size:.1f}{u}"
            size /= 1024
        return f"{size:.1f}TB"
