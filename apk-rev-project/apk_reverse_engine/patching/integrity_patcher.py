import re

class IntegrityPatcher:
    @staticmethod
    def disable_signature_check(smali_code):
        """禁用签名校验"""
        patterns = [
            (r'checkSignatures\(', '// disabled: checkSignatures('),
            (r'signatures\[.*?\].*?equals', '// disabled: signatures.equals'),
            (r'PackageManager;->checkSignatures', '// disabled: PackageManager->checkSignatures'),
            (r'PackageManager;->getPackageInfo', '// disabled: PackageManager->getPackageInfo'),
            (r'PackageManager;->getInstallerPackageName', '// disabled: getInstallerPackageName'),
        ]
        for pat, repl in patterns:
            smali_code = re.sub(pat, repl, smali_code)
        return smali_code

    @staticmethod
    def patch_verify_install(smali_code):
        """绕过安装验证"""
        return smali_code.replace(
            'invoke-static, {v0}, Landroid/app/Instrumentation;->newApplication',
            'invoke-static, {v0}, Lmy/app/Instrumentation;->newApplication')

    @staticmethod
    def disable_debug_check(smali_code):
        """禁用反调试检测"""
        patterns = [
            (r'Debug\.isDebuggerConnected\(\)', 'const/4 v0, 0x0'),
            (r'Debug\.waitForDebugger\(\)', 'return-void'),
            (r'android\.os\.Debug;->isDebuggerConnected', '// disabled'),
        ]
        for pat, repl in patterns:
            smali_code = re.sub(pat, repl, smali_code)
        return smali_code

    @staticmethod
    def disable_root_check(smali_code):
        """禁用Root检测"""
        patterns = [
            (r'[a-zA-Z]+\s*->\s*(isRooted|isDeviceRooted|checkRoot|detectRoot)\(', '// disabled: root check'),
            (r'[a-zA-Z]+\s*->\s*(isEmulator|isRunningInEmulator|detectEmulator)\(', '// disabled: emulator check'),
        ]
        for pat, repl in patterns:
            smali_code = re.sub(pat, repl, smali_code)
        return smali_code
