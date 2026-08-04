
import subprocess, os

class APKDecompiler:
    @staticmethod
    def jadx_decompile(apk_path, output_dir, deobf=True, show_inconsistent=False):
        jadx_jar = "/usr/local/bin/bin/jadx.jar"
        if not os.path.exists(jadx_jar):
            jadx_jar = "/usr/local/bin/jadx.jar"
        if not os.path.exists(jadx_jar):
            return {"success": False, "error": "jadx.jar not found"}
        cmd = ["java", "-jar", jadx_jar, "-d", output_dir, "--show-bad-code"]
        if deobf: cmd.append("--deobf")
        if show_inconsistent: cmd.append("--show-inconsistent-code")
        cmd.append(apk_path)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return {"success": r.returncode == 0, "output": r.stdout + r.stderr, "dir": output_dir if r.returncode == 0 else None}
        except Exception as e: return {"success": False, "error": str(e)}
    @staticmethod
    def androguard_decompile(apk_path, output_dir):
        try:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(apk_path)
            os.makedirs(output_dir, exist_ok=True)
            classes = {}
            for cls in d.get_classes():
                name = cls.get_name()
                classes[name] = [str(m) for m in cls.get_methods()]
            return {"success": True, "classes": list(classes.keys())[:50], "total": len(classes), "dir": output_dir}
        except Exception as e: return {"success": False, "error": str(e)}
