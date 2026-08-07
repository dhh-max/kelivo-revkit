"""知识库 - 持久化加固/SDK/混淆模式数据库

参照 Operit 持久记忆能力：
- 跨会话保留已知的加固方案、SDK、混淆模式知识
- 支持自定义添加/查询/删除
- 本地 JSON 持久化，可备份恢复
"""
import os, json, time
from datetime import datetime


class KnowledgeBase:
    """APK 逆向知识库 - 增量学习与跨会话记忆

    分类：
      packer      加固方案特征
      sdk         第三方 SDK/追踪器
      obfuscator  混淆工具特征
      signature   已知签名指纹
      custom      自定义知识
    """

    DEFAULT_PATH = os.path.join(os.path.expanduser('~'), '.apk-rev', 'knowledge.json')

    def __init__(self, path=None):
        self.path = path or KnowledgeBase.DEFAULT_PATH
        self.data = self._load()

    def _load(self):
        if os.path.isfile(self.path):
            with open(self.path) as f:
                return json.load(f)
        return {
            'version': 1,
            'updated': datetime.now().isoformat(),
            'categories': {c: [] for c in ['packer', 'sdk', 'obfuscator', 'signature', 'custom']},
        }

    def _save(self):
        self.data['updated'] = datetime.now().isoformat()
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

    # ---- 增删查 ----
    def add(self, category, name, patterns=None, desc='', meta=None):
        """添加一条知识"""
        if category not in self.data['categories']:
            category = 'custom'
        entry = {
            'name': name,
            'patterns': patterns or [],
            'desc': desc,
            'meta': meta or {},
            'added': datetime.now().isoformat(),
        }
        # 去重
        for i, e in enumerate(self.data['categories'][category]):
            if e.get('name') == name:
                self.data['categories'][category][i] = entry
                self._save()
                return entry
        self.data['categories'][category].append(entry)
        self._save()
        return entry

    def remove(self, category, name):
        if category not in self.data['categories']:
            return False
        for i, e in enumerate(self.data['categories'][category]):
            if e.get('name') == name:
                del self.data['categories'][category][i]
                self._save()
                return True
        return False

    def query(self, category=None, keyword=None):
        """查询，支持分类过滤和关键词匹配"""
        cats = [category] if category else list(self.data['categories'].keys())
        out = []
        for cat in cats:
            for e in self.data['categories'].get(cat, []):
                if keyword:
                    hay = (e.get('name', '') + ' ' + e.get('desc', '') + ' ' +
                           ' '.join(e.get('patterns', []))).lower()
                    if keyword.lower() not in hay:
                        continue
                out.append({**e, 'category': cat})
        return out

    def match(self, category, haystack):
        """在给定文本中匹配知识库条目，返回命中的"""
        hits = []
        for e in self.data['categories'].get(category, []):
            for pat in e.get('patterns', []):
                if pat and pat.lower() in haystack.lower():
                    hits.append(e)
                    break
        return hits

    def stats(self):
        return {cat: len(items) for cat, items in self.data['categories'].items()}

    def export(self, path=None):
        """导出为 JSON（供备份）"""
        path = path or self.path + '.bak'
        with open(path, 'w') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        return path

    def import_from(self, path):
        with open(path) as f:
            data = json.load(f)
        if 'categories' in data:
            for cat, items in data['categories'].items():
                if cat not in self.data['categories']:
                    self.data['categories'][cat] = []
                self.data['categories'][cat] = items
            self._save()
            return True
        return False


# 预置常用知识条目
def seed_default_knowledge(path=None):
    """写入一批内置加固/SDK/混淆特征"""
    kb = KnowledgeBase(path)
    defaults = {
        'packer': [
            ('腾讯乐固', ['libshell', 'libshella', 'txsec', 'tencent protect', 'com.tencent.StubShell']),
            ('360加固', ['libjiagu.so', 'com.stub.StubApp', '360加固']),
            ('梆梆加固', ['libSecShell.so', 'com.secshell', 'bangcle']),
            ('爱加密', ['libexec.so', 'com.shell.SuperApplication', 'ijiami']),
            ('娜迦加固', ['libchaosvmp.so', 'com.nagainet', 'naga']),
            ('阿里聚安全', ['libsgmain.so', 'libsgsecuritybody.so', 'com.secsdk']),
            ('腾讯御安全', ['libtosprotection.so', 'wup']),
            ('百度加固', ['libbaiduprotect.so', 'com.baidu.protect']),
        ],
        'sdk': [
            ('友盟统计', ['com.umeng', 'umeng_analytics']),
            ('极光推送', ['cn.jpush', 'jpush']),
            ('个推', ['com.igexin', 'getui']),
            ('腾讯Bugly', ['com.tencent.bugly', 'bugly']),
            ('百度地图', ['com.baidu.mapapi', 'baidu.map']),
            ('高德地图', ['com.amap.api', 'locSDK']),
            ('微信SDK', ['com.tencent.mm.opensdk', 'wxapi']),
            ('支付宝SDK', ['com.alipay.sdk', 'alipay']),
            ('穿山甲广告', ['com.bytedance.sdk', 'pangle', 'tt_splash']),
            ('腾讯广告', ['com.qq.e', 'gdt']),
        ],
        'obfuscator': [
            ('ProGuard', ['proguard', 'obfuscated by proguard']),
            ('DexGuard', ['dexguard', 'android.util.Base64']),
            ('R8', ['r8', 'com.android.tools.r8']),
            ('Obfuscapk', ['obfuscapk']),
        ],
    }
    for cat, items in defaults.items():
        for name, patterns in items:
            kb.add(cat, name, patterns=patterns)
    return kb