
import os, zipfile, shutil, tempfile

class APKMerger:
    @staticmethod
    def merge_apks(apk_list, output_path):
        tmp = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zout:
                written = set()
                for apk in apk_list:
                    with zipfile.ZipFile(apk, "r") as zin:
                        for item in zin.infolist():
                            if item.filename not in written and not item.filename.startswith("META-INF/"):
                                zout.writestr(item, zin.read(item.filename))
                                written.add(item.filename)
            return {"success": True, "output": output_path}
        except Exception as e: return {"success": False, "error": str(e)}
        finally: shutil.rmtree(tmp, ignore_errors=True)
