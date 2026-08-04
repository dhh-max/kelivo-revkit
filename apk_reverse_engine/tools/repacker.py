
import subprocess, os, zipfile

class APKRepacker:
    @staticmethod
    def apktool_build(decoded_dir, output_apk):
        cmd = ["java", "-jar", "/usr/local/bin/apktool.jar", "b", decoded_dir, "-o", output_apk]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": r.stdout + r.stderr, "apk": output_apk if r.returncode == 0 else None}
        except Exception as e: return {"success": False, "error": str(e)}
    @staticmethod
    def zip_rebuild(input_dir, output_apk):
        with zipfile.ZipFile(output_apk, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(input_dir):
                for f in files:
                    fp = os.path.join(root, f)
                    arcname = os.path.relpath(fp, input_dir)
                    zf.write(fp, arcname)
        return {"success": True, "apk": output_apk}
