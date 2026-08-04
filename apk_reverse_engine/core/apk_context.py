import zipfile, os, hashlib, tempfile, shutil
class APKContext:
    """APK上下文管理器 - 底层APK文件访问"""
    def __init__(self, apk_path):
        self.apk_path = os.path.abspath(apk_path)
        if not os.path.exists(self.apk_path): raise FileNotFoundError(f"APK not found: {self.apk_path}")
        self._temp_dir = None; self._zip = None; self._digest = None
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
    def list_files(self, pattern=None):
        names = self.zip.namelist()
        if pattern: import re; return [n for n in names if re.search(pattern, n)]
        return names
    def read_file(self, path): return self.zip.read(path)
    def extract_to(self, dest_dir, members=None):
        os.makedirs(dest_dir, exist_ok=True); self.zip.extractall(dest_dir, members); return dest_dir
    def get_temp_dir(self):
        if self._temp_dir is None: self._temp_dir = tempfile.mkdtemp(prefix='apk_ctx_')
        return self._temp_dir
    def get_dex_files(self): return [n for n in self.zip.namelist() if n.endswith('.dex')]
    def get_so_files(self): return [n for n in self.zip.namelist() if n.endswith('.so')]
    def get_arsc_files(self): return [n for n in self.zip.namelist() if n.endswith('.arsc')]
    def get_signature_info(self):
        mi = [n for n in self.zip.namelist() if n.startswith('META-INF/')]
        return {'meta_inf_files': mi, 'has_rsa': any(n.endswith('.RSA') for n in mi),
                'has_sf': any(n.endswith('.SF') for n in mi), 'has_mf': any(n.endswith('.MF') for n in mi)}
    def get_manifest_xml(self): return self.zip.read('AndroidManifest.xml')
    def close(self):
        if self._zip: self._zip.close(); self._zip = None
        if self._temp_dir and os.path.exists(self._temp_dir): shutil.rmtree(self._temp_dir, ignore_errors=True); self._temp_dir = None
    def __enter__(self): return self
    def __exit__(self, *args): self.close()
