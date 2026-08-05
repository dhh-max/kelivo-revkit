import re

class SmaliPatcher:
    @staticmethod
    def find_and_replace(text, old, new):
        return text.replace(old, new)

    @staticmethod
    def insert_method(smali_code, method_smali, before_line=None):
        if before_line:
            lines = smali_code.split('\n')
            for i, line in enumerate(lines):
                if before_line in line:
                    lines.insert(i, method_smali)
                    return '\n'.join(lines)
        return smali_code + '\n' + method_smali

    @staticmethod
    def remove_method(smali_code, method_name):
        pattern = r'\.method\s+.*?' + re.escape(method_name) + r'[^\n]*\n.*?\.end\s+method'
        return re.sub(pattern, '', smali_code, flags=re.DOTALL)

    @staticmethod
    def add_log_inject(smali_code, method_name, tag='DEBUG', msg='injected'):
        pattern = r'(\.method\s+.*?' + re.escape(method_name) + r'[^\n]*\n)'
        inject = '    const-string v0, "' + tag + '"\n    const-string v1, "' + msg + '"\n    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n'
        return re.sub(pattern, r'\1' + inject, smali_code)

    @staticmethod
    def add_return_inject(smali_code, method_name, return_value='0'):
        """在方法开头注入返回值"""
        pattern = r'(\.method\s+.*?' + re.escape(method_name) + r'[^\n]*\n)'
        inject = '    const/4 v0, ' + return_value + '\n    return v0\n'
        return re.sub(pattern, r'\1' + inject, smali_code)

    @staticmethod
    def patch_if_condition(smali_code, old_cond, new_cond):
        """修改条件跳转指令"""
        return smali_code.replace(old_cond, new_cond)

    @staticmethod
    def bypass_signature_check(smali_code):
        """绕过签名校验 - 将检查结果直接改为true"""
        pats = [
            (r'invoke-virtual\{.*?\},\s*Landroid/content/pm/PackageManager;->checkSignatures\([^)]*\)I', 'const/4 v0, 0x0\n    return v0'),
            (r'invoke-virtual\{.*?\},\s*Landroid/content/pm/PackageManager;->getPackageInfo\([^)]*\)Landroid/content/pm/PackageInfo;', 'const/4 v0, 0x0\n    return v0'),
        ]
        for pat, repl in pats:
            smali_code = re.sub(pat, repl, smali_code)
        return smali_code
