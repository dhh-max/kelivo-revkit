"""通用归档上下文 - 支持任意文件/归档类型

支持格式:
  - APK / ZIP / JAR / WAR / EAR / AAR / XPI
  - TAR / TAR.GZ / TAR.BZ2 / TGZ
  - 单文件（直接复制）
  - 目录（递归列出）

用法与 APKContext 一致，但不依赖 APK 特有结构。
"""

import os, zipfile, hashlib, tempfile, shutil, re, tarfile, gzip, bz2
from datetime import datetime


# 支持的归档扩展名
ZIP_EXTS = {'.apk', '.zip', '.jar', '.war', '.ear', '.aar', '.xpi', '.whl', '.egg'}
TAR_EXTS = {'.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz'}
GZIP_EXTS = {'.gz', '.gzip'}


def detect_file_type(path):
    """检测文件类型，返回 ('zip'|'tar'|'gzip'|'file'|'dir', ext)"""
    if os.path.isdir(path):
        return 'dir', ''

    name_lower = path.lower()

    # 先按扩展名快速判断
    for ext in TAR_EXTS:
        if name_lower.endswith(ext):
            return 'tar', ext

    for ext in ZIP_EXTS:
        if name_lower.endswith(ext):
            return 'zip', ext

    # 检测 gzip（非 tar.gz）
    for ext in GZIP_EXTS:
        if name_lower.endswith(ext):
            return 'gzip', ext

    # 魔数检测
    try:
        with open(path, 'rb') as f:
            magic = f.read(8)
        if magic[:4] == b'PK\x03\x04' or magic[:4] == b'PK\x05\x06':
            return 'zip', '.zip'
        if magic[:2] == b'\x1f\x8b':
            # gzip - 可能是 tar.gz
            try:
                f = gzip.open(path, 'rb')
                inner = f.read(512)
                f.close()
                if len(inner) > 262 and inner[257:262] == b'ustar':
                    return 'tar', '.tar.gz'
            except Exception:
                pass
            return 'gzip', '.gz'
        if magic[:5] == b'ustar' or (len(magic) >= 6 and magic[257:262] == b'ustar'):
            return 'tar', '.tar'
    except Exception:
        pass

    return 'file', os.path.splitext(path)[1]


class ArchiveContext:
    """通用归档上下文 - 支持 ZIP/TAR/单文件/目录

    提供与 APKContext 兼容的接口：
      - file_list / file_size / digest
      - list_files(pattern) / read_file(path)
      - extract_to(dest_dir, ...)
      - get_dex_files() / get_so_files() / 等（通用过滤）
      - close()
    """

    def __init__(self, path):
        self.path = os.path.abspath(path)
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"File not found: {self.path}")

        self._file_type, self._ext = detect_file_type(self.path)
        self._temp_dir = None
        self._zip = None
        self._tar = None
        self._digest = None
        self._file_list = None

        if self._file_type == 'zip':
            self._zip = zipfile.ZipFile(self.path, 'r')
        elif self._file_type == 'tar':
            mode = 'r:*'
            self._tar = tarfile.open(self.path, mode)
        elif self._file_type == 'gzip':
            # 单文件 gzip 解压
            self._gzip_fp = None
        elif self._file_type == 'dir':
            pass  # 目录模式
        else:
            pass  # 单文件模式

    @property
    def file_type(self):
        return self._file_type

    @property
    def ext(self):
        return self._ext

    @property
    def is_archive(self):
        return self._file_type in ('zip', 'tar')

    @property
    def file_size(self):
        return os.path.getsize(self.path)

    @property
    def digest(self):
        if self._digest is None:
            h = hashlib.sha256()
            with open(self.path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            self._digest = h.hexdigest()
        return self._digest

    @property
    def file_list(self):
        if self._file_list is None:
            if self._file_type == 'zip':
                self._file_list = self._zip.namelist()
            elif self._file_type == 'tar':
                self._file_list = [m.name for m in self._tar.getmembers() if m.isfile()]
            elif self._file_type == 'dir':
                result = []
                for root, dirs, files in os.walk(self.path):
                    for f in files:
                        fp = os.path.join(root, f)
                        rel = os.path.relpath(fp, self.path)
                        result.append(rel)
                self._file_list = result
            elif self._file_type == 'gzip':
                # 解压后的原始文件名
                base = os.path.basename(self.path)
                for ext in ('.gz', '.gzip', '.GZ', '.GZIP'):
                    if base.endswith(ext):
                        base = base[:-len(ext)]
                        break
                self._file_list = [base]
            else:
                # 单文件
                self._file_list = [os.path.basename(self.path)]
        return self._file_list

    def list_files(self, pattern=None):
        if pattern:
            return [n for n in self.file_list if re.search(pattern, n)]
        return self.file_list

    def read_file(self, path):
        """读取归档内指定文件内容(返回bytes)"""
        if self._file_type == 'zip':
            return self._zip.read(path)
        elif self._file_type == 'tar':
            f = self._tar.extractfile(path)
            if f is None:
                raise KeyError(f"Cannot read: {path}")
            return f.read()
        elif self._file_type == 'dir':
            fp = os.path.join(self.path, path)
            with open(fp, 'rb') as f:
                return f.read()
        elif self._file_type == 'gzip':
            with gzip.open(self.path, 'rb') as f:
                return f.read()
        else:
            # 单文件 - path 应该是文件名
            with open(self.path, 'rb') as f:
                return f.read()

    # ── 兼容 APKContext 的 zip 属性 ──
    @property
    def zip(self):
        """兼容属性：返回 zipfile 对象（仅 zip 类型时可用）"""
        if self._file_type == 'zip':
            return self._zip
        raise AttributeError("zip property only available for zip-type archives")

    # ── 通用过滤方法 ──
    def get_files_by_ext(self, *exts):
        """按扩展名过滤文件"""
        exts_lower = tuple(e.lower() for e in exts)
        return [n for n in self.file_list if n.lower().endswith(exts_lower)]

    def get_files_by_prefix(self, prefix):
        """按路径前缀过滤"""
        return [n for n in self.file_list if n.startswith(prefix)]

    # ── APK 兼容方法 ──
    def get_dex_files(self):
        return self.get_files_by_ext('.dex')

    def get_so_files(self):
        return self.get_files_by_ext('.so')

    def get_arsc_files(self):
        return self.get_files_by_ext('.arsc')

    def get_xml_files(self):
        return self.get_files_by_ext('.xml')

    def get_image_files(self):
        return self.get_files_by_ext('.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg')

    def get_meta_inf(self):
        return self.get_files_by_prefix('META-INF/')

    def get_assets_files(self):
        return self.get_files_by_prefix('assets/')

    def get_res_files(self):
        return self.get_files_by_prefix('res/')

    def get_signature_info(self):
        mi = self.get_meta_inf()
        return {'meta_inf_files': mi,
                'has_rsa': any(n.endswith('.RSA') for n in mi),
                'has_sf': any(n.endswith('.SF') for n in mi),
                'has_mf': any(n.endswith('.MF') for n in mi)}

    def get_manifest_xml(self):
        """读取 AndroidManifest.xml（如果不是 APK 则抛出异常）"""
        if 'AndroidManifest.xml' in self.file_list:
            if self._file_type == 'zip':
                return self._zip.read('AndroidManifest.xml')
            elif self._file_type == 'tar':
                f = self._tar.extractfile('AndroidManifest.xml')
                return f.read() if f else b''
            elif self._file_type == 'dir':
                with open(os.path.join(self.path, 'AndroidManifest.xml'), 'rb') as f:
                    return f.read()
        raise KeyError("AndroidManifest.xml not found (not an APK?)")

    def get_structure_summary(self):
        return {'total_files': len(self.file_list),
                'dex_count': len(self.get_dex_files()),
                'so_count': len(self.get_so_files()),
                'arsc_count': len(self.get_arsc_files()),
                'xml_count': len(self.get_xml_files()),
                'image_count': len(self.get_image_files()),
                'meta_inf_count': len(self.get_meta_inf()),
                'assets_count': len(self.get_assets_files()),
                'res_count': len(self.get_res_files()),
                'size': self.file_size,
                'sha256': self.digest,
                'file_type': self._file_type}

    # ── 通用分类 ──
    CATEGORY_MAP = {
        'dex': ['.dex'],
        'lib': ['.so'],
        'res': ['.arsc', '.png', '.jpg', '.jpeg', '.gif', '.webp',
                '.bmp', '.svg', '.xml', '.mp3', '.ogg', '.wav',
                '.mp4', '.webm', '.ttf', '.otf', '.json'],
        'assets': [], 'meta_inf': [], 'kotlin': ['.kotlin_module'],
        'cert': ['.RSA', '.SF', '.MF', '.DSA', '.EC'],
        'java': ['.java', '.kt', '.scala', '.groovy'],
        'class': ['.class'],
        'config': ['.properties', '.yml', '.yaml', '.xml', '.json', '.toml', '.ini', '.conf', '.cfg'],
        'web': ['.html', '.htm', '.css', '.js', '.ts', '.jsx', '.tsx', '.vue'],
        'script': ['.sh', '.py', '.rb', '.pl', '.php', '.lua'],
        'doc': ['.md', '.txt', '.rst', '.pdf', '.docx'],
        'data': ['.csv', '.sql', '.db', '.sqlite'],
        'image': ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.ico'],
        'audio': ['.mp3', '.ogg', '.wav', '.flac', '.aac', '.m4a'],
        'video': ['.mp4', '.webm', '.avi', '.mkv', '.mov'],
        'archive': ['.zip', '.tar', '.gz', '.bz2', '.xz', '.jar', '.war'],
    }

    @staticmethod
    def _classify_file(arcname):
        """通用文件分类"""
        name_lower = arcname.lower()
        if arcname.startswith('META-INF/'):
            if any(name_lower.endswith(ext) for ext in ['.rsa', '.sf', '.mf', '.dsa', '.ec']):
                return 'cert'
            return 'meta_inf'
        if arcname.startswith('assets/'): return 'assets'
        if arcname.startswith('res/'): return 'res'
        if arcname.startswith('lib/'): return 'lib'
        if arcname.startswith('kotlin/'): return 'kotlin'

        # APK 特定
        if name_lower.endswith('.dex'): return 'dex'

        # 通用类型检测
        for cat, exts in ArchiveContext.CATEGORY_MAP.items():
            if any(name_lower.endswith(ext) for ext in exts):
                return cat
        return 'unknown'

    @staticmethod
    def _get_category_dir(category, structure):
        if not structure:
            return ''
        dir_map = {
            'dex': 'dex', 'lib': 'lib', 'res': 'res', 'assets': 'assets',
            'meta_inf': 'META-INF', 'cert': 'META-INF', 'kotlin': 'kotlin',
            'java': 'src', 'class': 'classes', 'config': 'config',
            'web': 'web', 'script': 'scripts', 'doc': 'docs',
            'data': 'data', 'image': 'images', 'audio': 'audio',
            'video': 'video', 'archive': 'archives',
            'unknown': 'misc'
        }
        return dir_map.get(category, 'misc')

    @staticmethod
    def _get_rel_path(arcname, category):
        """获取分类后的相对路径"""
        for prefix, cat in [('assets/', 'assets'), ('res/', 'res'),
                            ('lib/', 'lib'), ('kotlin/', 'kotlin'),
                            ('META-INF/', 'meta_inf')]:
            if category == cat and arcname.startswith(prefix):
                return arcname[len(prefix):]
        return os.path.basename(arcname)

    def extract_to(self, dest_dir, members=None, structure=False, progress_callback=None,
                   flatten=False):
        """通用解压 - 支持 ZIP/TAR/单文件/目录/ gzip

        参数:
            dest_dir: 输出目录
            members: 可选，指定要解压的文件列表
            structure: 是否按分类归档子目录
            progress_callback: 进度回调(extracted, total, filename)
            flatten: 扁平化，不保留子目录路径
        """
        os.makedirs(dest_dir, exist_ok=True)

        # 确定目标文件列表
        if members is not None:
            targets = [t for t in members if not t.endswith('/')]
        else:
            targets = [n for n in self.file_list if not n.endswith('/')]

        total = len(targets)
        errors = []
        extracted = 0
        categories = {}

        for name in targets:
            try:
                # 处理分类路径
                if flatten:
                    base = os.path.basename(name)
                    dest_path = os.path.join(dest_dir, base)
                    if os.path.exists(dest_path):
                        dest_path = os.path.join(dest_dir, name.replace('/', '_'))
                elif structure:
                    cat = self._classify_file(name)
                    sub = self._get_category_dir(cat, structure)
                    rel = self._get_rel_path(name, cat)
                    dest_path = os.path.join(dest_dir, sub, rel) if sub else os.path.join(dest_dir, name)
                    categories[cat] = categories.get(cat, 0) + 1
                else:
                    dest_path = os.path.join(dest_dir, name)
                    categories['all'] = categories.get('all', 0) + 1

                dest_dirname = os.path.dirname(dest_path)
                if dest_dirname and not os.path.exists(dest_dirname):
                    os.makedirs(dest_dirname, exist_ok=True)

                # 根据类型提取
                if self._file_type == 'zip':
                    info = self._zip.getinfo(name)
                    with self._zip.open(name) as src, open(dest_path, 'wb') as dst:
                        while True:
                            chunk = src.read(1048576)
                            if not chunk:
                                break
                            dst.write(chunk)
                    # 保留时间戳
                    date_time = info.date_time
                    if date_time and date_time != (0, 0, 0, 0, 0, 0):
                        try:
                            ts = datetime(*date_time).timestamp()
                            os.utime(dest_path, (ts, ts))
                        except (ValueError, OSError):
                            pass

                elif self._file_type == 'tar':
                    member = self._tar.getmember(name)
                    f = self._tar.extractfile(member)
                    if f:
                        with open(dest_path, 'wb') as dst:
                            while True:
                                chunk = f.read(1048576)
                                if not chunk:
                                    break
                                dst.write(chunk)
                    # 保留权限
                    try:
                        os.chmod(dest_path, member.mode)
                    except Exception:
                        pass

                elif self._file_type == 'dir':
                    src_path = os.path.join(self.path, name)
                    shutil.copy2(src_path, dest_path)

                elif self._file_type == 'gzip':
                    with gzip.open(self.path, 'rb') as src, open(dest_path, 'wb') as dst:
                        while True:
                            chunk = src.read(1048576)
                            if not chunk:
                                break
                            dst.write(chunk)

                else:
                    # 单文件
                    shutil.copy2(self.path, dest_path)

                # SO 文件加执行权限
                if name.endswith('.so'):
                    try:
                        os.chmod(dest_path, os.stat(dest_path).st_mode | 0o111)
                    except OSError:
                        pass

                extracted += 1
                if progress_callback:
                    progress_callback(extracted, total, name)

            except Exception as e:
                errors.append({'file': name, 'error': str(e)})
                if progress_callback:
                    progress_callback(extracted, total, name)

        # SHA256
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
                except Exception:
                    pass

        return {
            'extracted': extracted, 'total': total, 'errors': errors,
            'dir': dest_dir, 'categories': categories,
            'sha256': sha.hexdigest() if sha_ok else ''
        }

    def get_temp_dir(self):
        if self._temp_dir is None:
            self._temp_dir = tempfile.mkdtemp(prefix='archive_ctx_')
        return self._temp_dir

    def close(self):
        if self._zip:
            self._zip.close()
            self._zip = None
        if self._tar:
            self._tar.close()
            self._tar = None
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def open_archive(path):
    """打开任意归档/文件，返回 ArchiveContext 上下文对象"""
    return ArchiveContext(path)


def open_apk(path):
    """兼容函数：打开 APK/ZIP，返回 ArchiveContext

    对于真正的 APK，功能与原来一致。
    对于其他归档，Manifest 等方法会抛出 KeyError。
    """
    return ArchiveContext(path)
