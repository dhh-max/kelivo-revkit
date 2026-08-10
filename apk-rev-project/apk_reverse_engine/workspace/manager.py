"""工作区管理 - 多项目并行分析上下文隔离

参照 Operit 工作区能力：
- 每个工作区独立上下文，互不干扰
- 持久化分析结果/临时文件/配置
- 通过 workspace 路径访问（类似 mini s://workspace/）
"""
from datetime import datetime
import os, json, time, hashlib


class Workspace:
    """APK 分析工作区 - 隔离不同项目的分析上下文

    每个工作区包含：
      meta.json      工作区元信息（创建时间/APK指纹/说明）
      results/      分析结果快照
      artifacts/    中间产物（解包、smali、补丁等）
      config.json   工作区级配置
    """

    DEFAULT_ROOT = os.path.join(os.path.expanduser('~'), '.apk-rev', 'workspaces')

    def __init__(self, name, root=None):
        self.name = name
        self.root = root or Workspace.DEFAULT_ROOT
        self.dir = os.path.join(self.root, _safe(name))
        os.makedirs(os.path.join(self.dir, 'results'), exist_ok=True)
        os.makedirs(os.path.join(self.dir, 'artifacts'), exist_ok=True)

    # ---- 生命周期 ----
    @staticmethod
    def create(name, root=None, description='', apk_path=None):
        ws = Workspace(name, root)
        if not os.path.exists(os.path.join(ws.dir, 'meta.json')) or True:
            meta = {
                'name': name,
                'created': datetime.now().isoformat(),
                'description': description,
                'apk': {
                    'path': apk_path,
                    'sha256': _file_sha256(apk_path) if apk_path and os.path.exists(apk_path) else None,
                    'size': os.path.getsize(apk_path) if apk_path and os.path.exists(apk_path) else None,
                },
            }
            ws._write('meta.json', meta)
        return ws

    @staticmethod
    def list(root=None):
        """列出所有工作区"""
        root = root or Workspace.DEFAULT_ROOT
        if not os.path.isdir(root):
            return []
        out = []
        for name in os.listdir(root):
            mf = os.path.join(root, name, 'meta.json')
            if os.path.isfile(mf):
                with open(mf) as f:
                    meta = json.load(f)
                meta['dir'] = os.path.join(root, name)
                out.append(meta)
        return out

    @staticmethod
    def open(name, root=None):
        return Workspace(name, root)

    def delete(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)
        return True

    # ---- 数据写入 ----
    def save_result(self, key, data):
        """保存分析结果快照"""
        path = os.path.join(self.dir, 'results', _safe(key) + '.json')
        with open(path, 'w') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        return path

    def load_result(self, key):
        path = os.path.join(self.dir, 'results', _safe(key) + '.json')
        if not os.path.isfile(path):
            return None
        with open(path) as f:
            return json.load(f)

    def list_results(self):
        rdir = os.path.join(self.dir, 'results')
        return sorted(os.listdir(rdir)) if os.path.isdir(rdir) else []

    def artifact(self, subpath):
        """获取/创建 artifacts 下的路径"""
        p = os.path.join(self.dir, 'artifacts', subpath)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    # ---- 配置 ----
    def set_config(self, key, value):
        cfg = self.load_config()
        cfg[key] = value
        self._write('config.json', cfg)

    def get_config(self, key, default=None):
        return self.load_config().get(key, default)

    def load_config(self):
        p = os.path.join(self.dir, 'config.json')
        if os.path.isfile(p):
            with open(p) as f:
                return json.load(f)
        return {}

    # ---- 内部 ----
    def _write(self, fname, data):
        with open(os.path.join(self.dir, fname), 'w') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)

    def info(self):
        return {
            'name': self.name,
            'dir': self.dir,
            'results': self.list_results(),
            'config': self.load_config(),
            'meta': self._read('meta.json'),
        }

    def _read(self, fname):
        p = os.path.join(self.dir, fname)
        if os.path.isfile(p):
            with open(p) as f:
                return json.load(f)
        return None


def _safe(s):
    """文件名安全化"""
    return ''.join(c if c.isalnum() or c in '-_ ' else '_' for c in s).strip().replace(' ', '_')

def _file_sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()