from ..core.archive_context import ArchiveContext as APKContext
from ..core.manifest_parser import ManifestParser
from ..core.dex_parser import DexParser
from ..core.sign_verifier import SignVerifier

class StaticAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.ctx = APKContext(apk_path)

    def analyze(self):
        r = {'apk_path': self.apk_path, 'file_size': self.ctx.file_size, 'sha256': self.ctx.digest}
        r['structure'] = self.ctx.get_structure_summary()
        
        try:
            md = self.ctx.get_manifest_xml()
            r['manifest'] = ManifestParser.get_simple(md)
        except Exception:
            r['manifest'] = {}

        dex_files = self.ctx.get_dex_files()
        r['dex_summary'] = []
        for d in dex_files:
            try:
                data = self.ctx.read_file(d)
                dp = DexParser(data)
                h = dp.parse_header()
                summary = dp.get_summary()
                r['dex_summary'].append({'name': d, 'size': len(data), **summary})
            except Exception as e:
                r['dex_summary'].append({'name': d, 'error': str(e)})

        r['signature'] = SignVerifier.verify_all(self.ctx.zip, self.apk_path)

        so_files = self.ctx.get_so_files()
        arches = {}
        for s in so_files:
            parts = s.split('/')
            if len(parts) >= 2:
                arches[parts[0]] = arches.get(parts[0], 0) + 1
        r['abi_architectures'] = list(arches.keys())
        r['so_count_by_abi'] = arches

        return r

    def close(self):
        self.ctx.close()
