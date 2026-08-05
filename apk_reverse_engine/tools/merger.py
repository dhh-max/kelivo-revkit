import os, zipfile, shutil, tempfile

class APKMerger:
    """APK合并工具"""

    @staticmethod
    def merge_apks(apk_list, output_path):
        """合并多个APK，跳过META-INF"""
        tmp = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
                written = set()
                for apk in apk_list:
                    if not os.path.exists(apk):
                        continue
                    with zipfile.ZipFile(apk, 'r') as zin:
                        for item in zin.infolist():
                            if item.filename not in written and not item.filename.startswith('META-INF/'):
                                zout.writestr(item, zin.read(item.filename))
                                written.add(item.filename)
            return {"success": True, "output": output_path, "files_merged": len(apk_list)}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @staticmethod
    def merge_dex(apk_path, output_path):
        """合并多DEX为单个classes.dex (简单拼接)"""
        ctx = None
        try:
            from ..core.apk_context import APKContext
            ctx = APKContext(apk_path)
            dex_files = ctx.get_dex_files()
            if not dex_files:
                return {"success": False, "error": "no dex files found"}
            if len(dex_files) == 1:
                shutil.copy2(apk_path, output_path)
                return {"success": True, "message": "only one dex, copied directly"}
            
            # Merge: copy all non-dex files, then merge all dex data
            merged_dex = b''
            for d in dex_files:
                merged_dex += ctx.read_file(d)
            
            with zipfile.ZipFile(apk_path, 'r') as zin:
                with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        if item.filename.endswith('.dex'):
                            if item.filename == 'classes.dex':
                                zout.writestr(item, merged_dex)
                            # skip other dex files
                        else:
                            zout.writestr(item, zin.read(item.filename))
            return {"success": True, "output": output_path}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if ctx: ctx.close()
