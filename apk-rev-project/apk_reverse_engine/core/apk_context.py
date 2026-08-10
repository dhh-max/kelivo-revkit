import zipfile, os, hashlib, tempfile, shutil, re
from datetime import datetime

from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

class APKContext:
    def __init__(self, apk_path):
        self.apk_path = os.path.abspath(apk_path)
        if not os.path.exists(self.apk_path): raise FileNotFoundError(f"APK not found: {self.apk_path}")
        self._temp_dir = None; self._zip = None; self._digest = None; self._file_list = None

    @property
    def zip(self):
        if self._zip is None: self._zip = zipfile.ZipFile(self.apk_path, 'r')
        return self._zip

    @property
    def digest(self):
        if self._digest is None:
            h = hashlib.sha256()
            with open(self.apk_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
            self._digest = h.hexdigest()
        return self._digest

    @property
    def file_size(self): return os.path.getsize(self.apk_path)

    @property
    def file_list(self):
        if self._file_list is None: self._file_list = self.zip.namelist()
        return self._file_list

    def list_files(self, pattern=None):
        if pattern: return [n for n in self.file_list if re.search(pattern, n)]
        return self.file_list

    def read_file(self, path): return self.zip.read(path)

    def extract_to(self, dest_dir, members=None, structure=False, progress_callback=None,
                   flatten=False):
        """稳健解压：逐文件提取，处理编码异常，保留SO可执行权限

        参数:
            dest_dir: 输出目录
            members: 可选，指定要解压的文件列表
            structure: 是否按分类归档子目录 (dex/lib/res/assets/META-INF)
            progress_callback: 进度回调(extracted, total, filename)
            flatten: 扁平化，不保留子目录路径，仅用文件名
        """
        os.makedirs(dest_dir, exist_ok=True)
        targets = members if members is not None else self.file_list
        targets = [t for t in targets if not t.endswith('/')]
        total = len(targets)
        errors = []
        extracted = 0
        categories = {}

        def _classify(name):
            n = name.lower()
            if name.startswith('META-INF/'):
                return 'cert' if any(n.endswith(e) for e in ['.rsa','.sf','.mf','.dsa','.ec']) else 'meta_inf'
            if name.startswith('assets/'): return 'assets'
            if name.startswith('res/'): return 'res'
            if name.startswith('lib/'): return 'lib'
            if name.startswith('kotlin/'): return 'kotlin'
            if n.endswith('.dex'): return 'dex'
            return 'unknown'

        _dir_map = {'dex':'dex','lib':'lib','res':'res','assets':'assets',
                    'meta_inf':'META-INF','cert':'META-INF','kotlin':'kotlin','unknown':'unknown'}

        for name in targets:
            try:
                # 处理非UTF-8编码文件名
                try:
                    decoded_name = name
                except UnicodeDecodeError:
                    decoded_name = name.encode('cp437').decode('utf-8', errors='replace')

                if flatten:
                    # 扁平化：只用文件名，冲突时加目录前缀
                    base = os.path.basename(decoded_name)
                    dest_path = os.path.join(dest_dir, base)
                    if os.path.exists(dest_path):
                        prefix = decoded_name.replace('/', '_')
                        dest_path = os.path.join(dest_dir, prefix)
                elif structure:
                    cat = _classify(decoded_name)
                    sub = _dir_map.get(cat, 'unknown')
                    if cat == 'assets' and decoded_name.startswith('assets/'):
                        rel = decoded_name[len('assets/'):]
                    elif cat == 'res' and decoded_name.startswith('res/'):
                        rel = decoded_name[len('res/'):]
                    elif cat == 'lib' and decoded_name.startswith('lib/'):
                        rel = decoded_name[len('lib/'):]
                    elif cat == 'kotlin' and decoded_name.startswith('kotlin/'):
                        rel = decoded_name[len('kotlin/'):]
                    elif cat in ('meta_inf', 'cert') and decoded_name.startswith('META-INF/'):
                        rel = decoded_name[len('META-INF/'):]
                    else:
                        rel = os.path.basename(decoded_name)
                    dest_path = os.path.join(dest_dir, sub, rel)
                    categories[cat] = categories.get(cat, 0) + 1
                else:
                    dest_path = os.path.join(dest_dir, decoded_name)
                    categories['all'] = categories.get('all', 0) + 1

                dest_dirname = os.path.dirname(dest_path)
                if dest_dirname and not os.path.exists(dest_dirname):
                    os.makedirs(dest_dirname, exist_ok=True)

                info = self.zip.getinfo(name)

                # 流式提取（1MB chunk，不一次性读入内存）
                with self.zip.open(name) as src, open(dest_path, 'wb') as dst:
                    while True:
                        chunk = src.read(1048576)
                        if not chunk:
                            break
                        dst.write(chunk)

                # 保留原始时间戳
                date_time = info.date_time
                if date_time and date_time != (0, 0, 0, 0, 0, 0):
                    try:
                        ts = datetime(*date_time).timestamp()
                        os.utime(dest_path, (ts, ts))
                    except Exception as e:
                        logger.debug(f"e")

                # SO文件加执行权限
                if name.endswith('.so'):
                    try:
                        os.chmod(dest_path, os.stat(dest_path).st_mode | 0o111)
                    except OSError as e:
                        logger.debug(f"e")

                extracted += 1
                if progress_callback:
                    progress_callback(extracted, total, name)

            except Exception as e:
                errors.append({'file': name, 'error': str(e)})
                if progress_callback:
                    progress_callback(extracted, total, name)

        # 计算解压后 SHA256
        sha = hashlib.sha256()
        sha_ok = False
        for root, dirs, files in sorted(os.walk(dest_dir)):
            for f in sorted(files):
                fp = os.path.join(root, f)
                try:
                    with open(fp, 'rb') as fh:
                        for chunk in iter(lambda: fh.read(65536), b''):
                            sha.update(chunk)
                    sha_ok = True
                except Exception as e:
                    logger.debug("apk_reverse_engine/core/apk_context.py:157 suppressed: %s", e)
                    logger.debug(f"e")

        return {
            'extracted': extracted, 'total': total, 'errors': errors,
            'dir': dest_dir, 'categories': categories,
            'sha256': sha.hexdigest() if sha_ok else ''
        }

    def get_temp_dir(self):
        if self._temp_dir is None: self._temp_dir = tempfile.mkdtemp(prefix='apk_ctx_')
        return self._temp_dir

    def get_dex_files(self): return [n for n in self.file_list if n.endswith('.dex')]
    def get_so_files(self): return [n for n in self.file_list if n.endswith('.so')]
    def get_arsc_files(self): return [n for n in self.file_list if n.endswith('.arsc')]
    def get_xml_files(self): return [n for n in self.file_list if n.endswith('.xml')]
    def get_image_files(self): return [n for n in self.file_list if n.lower().endswith(('.png','.jpg','.jpeg','.gif','.webp','.bmp','.svg'))]
    def get_meta_inf(self): return [n for n in self.file_list if n.startswith('META-INF/')]
    def get_assets_files(self): return [n for n in self.file_list if n.startswith('assets/')]
    def get_res_files(self): return [n for n in self.file_list if n.startswith('res/')]

    def get_signature_info(self):
        mi = self.get_meta_inf()
        return {'meta_inf_files': mi, 'has_rsa': any(n.endswith('.RSA') for n in mi), 'has_sf': any(n.endswith('.SF') for n in mi), 'has_mf': any(n.endswith('.MF') for n in mi)}

    def get_manifest_xml(self): return self.zip.read('AndroidManifest.xml')

    def get_structure_summary(self):
        return {'total_files': len(self.file_list), 'dex_count': len(self.get_dex_files()), 'so_count': len(self.get_so_files()), 'arsc_count': len(self.get_arsc_files()), 'xml_count': len(self.get_xml_files()), 'image_count': len(self.get_image_files()), 'meta_inf_count': len(self.get_meta_inf()), 'assets_count': len(self.get_assets_files()), 'res_count': len(self.get_res_files()), 'size': self.file_size, 'sha256': self.digest}

    def close(self):
        if self._zip: self._zip.close(); self._zip = None
        if self._temp_dir and os.path.exists(self._temp_dir): shutil.rmtree(self._temp_dir, ignore_errors=True); self._temp_dir = None

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
