
import subprocess, os

class APKConverter:
    @staticmethod
    def dex_to_jar(dex_path, output_jar):
        try:
            r = subprocess.run(["d2j-dex2jar", dex_path, "-o", output_jar], capture_output=True, text=True, timeout=60)
            return {"success": r.returncode == 0, "output": output_jar if r.returncode == 0 else None}
        except: return {"success": False, "error": "dex2jar not available"}
    @staticmethod
    def jar_to_dex(jar_path, output_dex):
        try:
            r = subprocess.run(["d2j-jar2dex", jar_path, "-o", output_dex], capture_output=True, text=True, timeout=60)
            return {"success": r.returncode == 0, "output": output_dex if r.returncode == 0 else None}
        except: return {"success": False, "error": "jar2dex not available"}
