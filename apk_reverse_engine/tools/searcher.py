
import os, re
from ..core.apk_context import APKContext

class APKSearch:
    @staticmethod
    def search_in_files(directory, query, regex=False, case_insensitive=True, max_results=100, file_pattern=None):
        results = []
        flags = re.IGNORECASE if case_insensitive else 0
        pattern = re.compile(query, flags) if regex else re.compile(re.escape(query), flags)
        count = 0
        for root, dirs, files in os.walk(directory):
            if count >= max_results: break
            for f in files:
                if count >= max_results: break
                if file_pattern and not re.search(file_pattern, f): continue
                fp = os.path.join(root, f)
                try:
                    with open(fp, "r", errors="replace") as fh:
                        for i, line in enumerate(fh, 1):
                            if count >= max_results: break
                            if pattern.search(line):
                                results.append({"file": os.path.relpath(fp, directory), "line": i, "content": line.strip()[:200]})
                                count += 1
                except: pass
        return {"results": results, "total": len(results)}
    @staticmethod
    def search_in_apk(apk_path, query, scope="all", max_results=100):
        ctx = APKContext(apk_path)
        results = []; count = 0
        name_pattern = {"manifest": r"AndroidManifest\.xml", "dex": r"\.dex$", "so": r"\.so$", "res": r"res/"}.get(scope)
        for f in ctx.list_files(name_pattern):
            if count >= max_results: break
            try:
                data = ctx.read_file(f)
                if any(f.endswith(e) for e in [".xml",".txt",".json",".html",".smali"]):
                    text = data.decode("utf-8", errors="replace")
                    for i, line in enumerate(text.split("\n"), 1):
                        if query in line:
                            results.append({"file": f, "line": i, "content": line.strip()[:200]})
                            count += 1
                            if count >= max_results: break
                elif f.endswith(".dex"):
                    from ..core.dex_parser import DexParser
                    dp = DexParser(data); h = dp.parse_header()
                    for ci in range(min(h.get("class_defs", 0), 100)):
                        name = dp.get_string(ci)
                        if query.lower() in name.lower():
                            results.append({"file": f, "content": f"class: {name}"})
                            count += 1
            except: pass
        ctx.close()
        return {"results": results, "total": len(results)}
