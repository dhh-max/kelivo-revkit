
from ..core.apk_context import APKContext
from ..core.manifest_parser import ManifestParser
from ..core.dex_parser import DexParser
from ..core.sign_verifier import SignVerifier

class StaticAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.ctx = APKContext(apk_path)
    def analyze(self):
        r = {'apk_path': self.apk_path, 'file_size': self.ctx.file_size, 'sha256': self.ctx.digest}
        r['total_files'] = len(self.ctx.list_files())
        r['dex_count'] = len(self.ctx.get_dex_files())
        r['so_count'] = len(self.ctx.get_so_files())
        try:
            md = self.ctx.get_manifest_xml()
            r['manifest'] = ManifestParser.get_simple(md)
        except: r['manifest'] = {}
        dex_files = self.ctx.get_dex_files()
        r['dex_summary'] = []
        for d in dex_files:
            try:
                data = self.ctx.read_file(d)
                dp = DexParser(data)
                h = dp.parse_header()
                r['dex_summary'].append({'name': d, 'size': len(data), 'classes': h.get('class_defs', 0), 'methods': h.get('method_ids', 0)})
            except: r['dex_summary'].append({'name': d, 'error': 'parse failed'})
        r['signature'] = self.ctx.get_signature_info()
        r['signature']['v2'] = SignVerifier.verify_v2(self.apk_path)
        so_files = self.ctx.get_so_files()
        arches = {}
        for s in so_files:
            parts = s.split('/')
            if len(parts) >= 2: arches[parts[0]] = arches.get(parts[0], 0) + 1
        r['abi_architectures'] = list(arches.keys())
        r['so_count_by_abi'] = arches
        return r
    def close(self): self.ctx.close()
