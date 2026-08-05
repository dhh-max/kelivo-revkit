import subprocess, os, json

class APKDecompiler:
    """APK反编译工具集"""

    @staticmethod
    def _find_jar(name):
        paths = [
            f'/usr/local/bin/{name}',
            f'/usr/local/bin/bin/{name}',
            f'/usr/share/java/{name}',
            f'/opt/{name}',
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    @staticmethod
    def jadx_decompile(apk_path, output_dir, deobf=True, show_inconsistent=False, options=None):
        jadx_jar = APKDecompiler._find_jar('jadx.jar')
        if not jadx_jar:
            return {"success": False, "error": "jadx.jar not found. Install: https://github.com/skylot/jadx"}
        
        cmd = ["java", "-jar", jadx_jar, "-d", output_dir, "--show-bad-code"]
        if deobf:
            cmd.append("--deobf")
        if show_inconsistent:
            cmd.append("--show-inconsistent-code")
        
        # Additional options
        if options:
            for k, v in options.items():
                flag = f'--{k.replace("_", "-")}'
                if isinstance(v, bool) and v:
                    cmd.append(flag)
                elif isinstance(v, str):
                    cmd.extend([flag, v])
        
        cmd.append(apk_path)
        
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "success": r.returncode == 0,
                "output": r.stdout + r.stderr,
                "dir": output_dir if r.returncode == 0 else None,
                "command": ' '.join(cmd),
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "jadx timed out after 300s"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def jadx_gui(apk_path):
        """启动jadx-gui"""
        jadx_jar = APKDecompiler._find_jar('jadx.jar')
        if not jadx_jar:
            return {"success": False, "error": "jadx.jar not found"}
        try:
            subprocess.Popen(["java", "-jar", jadx_jar, "-gui", apk_path])
            return {"success": True, "message": "jadx-gui launched"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def androguard_decompile(apk_path, output_dir):
        try:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(apk_path)
            os.makedirs(output_dir, exist_ok=True)
            
            # Extract classes and methods
            classes = {}
            for cls in d.get_classes():
                name = cls.get_name()
                methods = []
                for m in cls.get_methods():
                    methods.append({
                        'name': m.get_name(),
                        'descriptor': m.get_descriptor(),
                        'access': m.get_access_flags_string(),
                    })
                classes[name] = methods
            
            # Extract permissions
            permissions = []
            if a:
                permissions = a.get_permissions()
            
            return {
                "success": True,
                "classes": classes,
                "total_classes": len(classes),
                "permissions": permissions,
                "dir": output_dir,
            }
        except ImportError:
            return {"success": False, "error": "androguard not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def apktool_decode(apk_path, output_dir, force=False, no_src=False, no_res=False):
        """使用apktool解包"""
        apktool = APKDecompiler._find_jar('apktool.jar')
        if not apktool:
            return {"success": False, "error": "apktool.jar not found"}
        cmd = ['java', '-jar', apktool, 'd', apk_path, '-o', output_dir]
        if force:
            cmd.append('-f')
        if no_src:
            cmd.append('--no-src')
        if no_res:
            cmd.append('--no-res')
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"success": r.returncode == 0, "output": r.stdout + r.stderr, "dir": output_dir if r.returncode == 0 else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def get_decompiled_source_summary(output_dir):
        """统计反编译结果"""
        if not os.path.exists(output_dir):
            return {'error': 'directory not found'}
        
        java_files = 0
        smali_files = 0
        total_lines = 0
        
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                fp = os.path.join(root, f)
                if f.endswith('.java'):
                    java_files += 1
                    try:
                        with open(fp, 'r', errors='replace') as fh:
                            total_lines += sum(1 for _ in fh)
                    except:
                        pass
                elif f.endswith('.smali'):
                    smali_files += 1
        
        return {
            'java_files': java_files,
            'smali_files': smali_files,
            'total_lines': total_lines,
            'dir': output_dir,
        }
