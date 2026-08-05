import subprocess, os, shutil

class APKSigner:
    @staticmethod
    def _find_tool(name):
        which = shutil.which(name)
        if which:
            return which
        paths = [
            f'/usr/local/bin/{name}',
            f'/usr/local/bin/bin/{name}',
            f'/usr/bin/{name}',
        ]
        return shutil.which(name)  # final fallback

    @staticmethod
    def sign_debug(apk_path, output_path):
        # 优先使用apksigner
        apksigner = shutil.which('apksigner')
        if apksigner:
            # 使用默认debug keystore
            keystore = os.path.expanduser('~/.android/debug.keystore')
            cmd = [apksigner, 'sign', '--ks', keystore,
                   '--ks-pass', 'pass:android',
                   '--ks-key-alias', 'androiddebugkey',
                   '--out', output_path, apk_path]
            if not os.path.exists(keystore):
                # 自动生成debug keystore
                keytool = shutil.which('keytool')
                if keytool:
                    os.makedirs(os.path.dirname(keystore), exist_ok=True)
                    subprocess.run([
                        keytool, '-genkey', '-v', '-keystore', keystore,
                        '-storepass', 'android', '-alias', 'androiddebugkey',
                        '-keypass', 'android', '-keyalg', 'RSA', '-validity', '10000',
                        '-dname', 'CN=Android Debug, OU=Android, O=Google, L=Mountain View, ST=California, C=US'
                    ], capture_output=True, timeout=30)
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                return {'success': r.returncode == 0, 'output': r.stdout + r.stderr,
                        'apk': output_path if r.returncode == 0 else None}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        # fallback: 尝试jar签名
        jar = APKSigner._find_tool('uber-apk-signer.jar')
        if jar and os.path.exists(jar):
            cmd = ['java', '-jar', jar, '--apks', apk_path, '--out', output_path]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                return {'success': r.returncode == 0, 'output': r.stdout + r.stderr,
                        'apk': output_path if r.returncode == 0 else None}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        return {'success': False, 'error': 'No signing tool found (apksigner or uber-apk-signer.jar)'}

    @staticmethod
    def sign_keystore(apk_path, output_path, keystore, storepass, alias, keypass=None):
        cmd = ['apksigner', 'sign', '--ks', keystore, '--ks-pass', f'pass:{storepass}', '--ks-key-alias', alias, '--out', output_path]
        if keypass: cmd.extend(['--key-pass', f'pass:{keypass}'])
        cmd.append(apk_path)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {'success': r.returncode == 0, 'output': r.stdout + r.stderr, 'apk': output_path if r.returncode == 0 else None}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def sign_with_zipadjust(apk_path, output_path):
        """使用zipalign+apksigner签名"""
        tmp = apk_path + '.aligned'
        try:
            subprocess.run(['zipalign', '-f', '4', apk_path, tmp], capture_output=True, timeout=30)
            return APKSigner.sign_debug(tmp, output_path)
        except Exception as e:
            return {'success': False, 'error': str(e)}
