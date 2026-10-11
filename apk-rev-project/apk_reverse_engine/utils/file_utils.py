import os, shutil, tempfile, hashlib

class FileUtils:
    """文件操作工具集"""

    @staticmethod
    def ensure_dir(path):
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def safe_delete(path):
        if os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)

    @staticmethod
    def get_temp_dir(prefix='reng_'):
        return tempfile.mkdtemp(prefix=prefix)

    @staticmethod
    def copy_file(src, dst):
        shutil.copy2(src, dst)
        return dst

    @staticmethod
    def human_size(size):
        for u in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f}{u}"
            size /= 1024
        return f"{size:.1f}TB"

    @staticmethod
    def file_hash(filepath, algorithm='sha256'):
        """计算文件哈希"""
        h = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def list_files_by_ext(directory, extensions):
        """按扩展名列出文件"""
        results = []
        for root, dirs, files in os.walk(directory):
            for f in files:
                if any(f.endswith(ext) for ext in extensions):
                    results.append(os.path.join(root, f))
        return results

    @staticmethod
    def get_file_info(filepath):
        """获取文件信息"""
        if not os.path.exists(filepath):
            return {'error': '文件未找到'}
        stat = os.stat(filepath)
        return {
            'path': filepath,
            'size': stat.st_size,
            'size_human': FileUtils.human_size(stat.st_size),
            'modified': stat.st_mtime,
            'is_file': os.path.isfile(filepath),
            'is_dir': os.path.isdir(filepath),
        }

    @staticmethod
    def safe_write(path, data, mode='wb'):
        """安全写入文件（先写临时文件再替换）"""
        dirname = os.path.dirname(path) or '.'
        FileUtils.ensure_dir(dirname)
        tmp = path + '.tmp'
        with open(tmp, mode) as f:
            f.write(data)
        os.replace(tmp, path)
        return path

    @staticmethod
    def merge_files(file_list, output_path):
        """合并多个文件"""
        with open(output_path, 'wb') as out:
            for f in file_list:
                with open(f, 'rb') as inf:
                    shutil.copyfileobj(inf, out)
        return output_path
