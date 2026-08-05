import subprocess, os

class APKConverter:
    """格式转换工具"""

    @staticmethod
    def _find_tool(name):
        paths = [
            f'/usr/local/bin/{name}',
            f'/usr/local/bin/bin/{name}',
            f'/usr/bin/{name}',
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return name  # fallback to PATH

    @staticmethod
    def dex_to_jar(dex_path, output_jar):
        try:
            tool = APKConverter._find_tool('d2j-dex2jar')
            r = subprocess.run([tool, dex_path, '-o', output_jar],
                               capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": output_jar if r.returncode == 0 else None,
                    "message": r.stdout + r.stderr}
        except FileNotFoundError:
            return {"success": False, "error": "d2j-dex2jar not found. Install: https://github.com/pxb1988/dex2jar"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "dex2jar timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def jar_to_dex(jar_path, output_dex):
        try:
            tool = APKConverter._find_tool('d2j-jar2dex')
            r = subprocess.run([tool, jar_path, '-o', output_dex],
                               capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": output_dex if r.returncode == 0 else None,
                    "message": r.stdout + r.stderr}
        except FileNotFoundError:
            return {"success": False, "error": "d2j-jar2dex not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def dex_to_smali(dex_path, output_dir):
        """DEX转Smali (使用baksmali)"""
        try:
            baksmali = APKConverter._find_tool('baksmali.jar')
            if not os.path.exists(baksmali):
                baksmali = '/usr/local/bin/baksmali.jar'
            r = subprocess.run(['java', '-jar', baksmali, 'd', dex_path, '-o', output_dir],
                               capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": output_dir if r.returncode == 0 else None,
                    "message": r.stdout + r.stderr}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def smali_to_dex(smali_dir, output_dex):
        """Smali转DEX (使用smali)"""
        try:
            smali = APKConverter._find_tool('smali.jar')
            if not os.path.exists(smali):
                smali = '/usr/local/bin/smali.jar'
            r = subprocess.run(['java', '-jar', smali, 'a', smali_dir, '-o', output_dex],
                               capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": output_dex if r.returncode == 0 else None,
                    "message": r.stdout + r.stderr}
        except Exception as e:
            return {"success": False, "error": str(e)}
