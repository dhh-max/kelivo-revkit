import subprocess, os

class APKSigner:
    @staticmethod
    def sign_debug(apk_path, output_path):
        jar = '/usr/local/bin/uber-apk-signer.jar'
        if not os.path.exists(jar):
            jar = '/usr/local/bin/uber-apk-signer.jar'
        cmd = ['java', '-jar', jar, '--apks', apk_path, '--out', output_path]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {'success': r.returncode == 0, 'output': r.stdout + r.stderr, 'apk': output_path if r.returncode == 0 else None}
        except Exception as e:
            return {'success': False, 'error': str(e)}

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
