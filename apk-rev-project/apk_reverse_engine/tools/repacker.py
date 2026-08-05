import subprocess, os, zipfile, shutil

class APKRepacker:
    """APK重打包工具"""

    @staticmethod
    def _find_jar(name):
        """查找工具可执行路径，支持.jar和PATH内可执行文件"""
        # 不带.jar后缀的可执行文件（shell wrapper / PATH命令）
        base = name.replace('.jar', '')
        import shutil
        which = shutil.which(base)
        if which:
            return which
        # .jar文件路径搜索
        paths = [
            f'/usr/local/bin/{name}',
            f'/usr/local/bin/bin/{name}',
            f'/home/kelivo-revkit/tools/{name}',
            f'/home/tools/{name}',
        ]
        for p in paths:
            if os.path.exists(p) and os.path.getsize(p) > 0:
                return p
        return None

    @staticmethod
    def apktool_build(decoded_dir, output_apk, force=False, aapt=None):
        apktool = APKRepacker._find_jar('apktool.jar')
        if not apktool:
            return {"success": False, "error": "apktool not found"}
        if apktool.endswith('.jar'):
            cmd = ['java', '-jar', apktool, 'b', decoded_dir, '-o', output_apk]
        else:
            cmd = [apktool, 'b', decoded_dir, '-o', output_apk]
        if force: cmd.append('-f')
        if aapt: cmd.extend(['--aapt', aapt])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": r.stdout + r.stderr, "apk": output_apk if r.returncode == 0 else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def zip_rebuild(input_dir, output_apk, compression=zipfile.ZIP_DEFLATED):
        """从目录重建ZIP/APK"""
        with zipfile.ZipFile(output_apk, 'w', compression) as zf:
            for root, dirs, files in os.walk(input_dir):
                for f in sorted(files):
                    fp = os.path.join(root, f)
                    arcname = os.path.relpath(fp, input_dir)
                    zf.write(fp, arcname)
        return {"success": True, "apk": output_apk}

    @staticmethod
    def zip_update(apk_path, file_entries):
        """更新APK中的文件 (file_entries: {arcname: data_bytes})"""
        import tempfile
        tmp = apk_path + '.tmp'
        with zipfile.ZipFile(apk_path, 'r') as zin:
            with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    if item.filename in file_entries:
                        zout.writestr(item, file_entries[item.filename])
                    else:
                        zout.writestr(item, zin.read(item.filename))
                for name, data in file_entries.items():
                    if name not in zin.namelist():
                        zout.writestr(name, data)
        shutil.move(tmp, apk_path)
        return {"success": True, "apk": apk_path}

    @staticmethod
    def zipalign(apk_path, output_path=None):
        """执行Zipalign对齐"""
        if output_path is None:
            output_path = apk_path
        try:
            r = subprocess.run(['zipalign', '-f', '4', apk_path, output_path],
                             capture_output=True, text=True, timeout=30)
            return {"success": r.returncode == 0, "output": output_path if r.returncode == 0 else None,
                    "message": r.stdout + r.stderr}
        except FileNotFoundError:
            return {"success": False, "error": "zipalign not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}
