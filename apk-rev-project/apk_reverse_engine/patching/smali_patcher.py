"""Smali 高级修补器 - 支持指令级修补、方法注入、NOP填充"""
import re

class SmaliPatcher:
    """Smali 高级修补引擎"""

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
        pattern = r'(\.method\s+.*?' + re.escape(method_name) + r'[^\n]*\n)'
        inject = '    const/4 v0, ' + return_value + '\n    return v0\n'
        return re.sub(pattern, r'\1' + inject, smali_code)

    @staticmethod
    def patch_if_condition(smali_code, old_cond, new_cond):
        return smali_code.replace(old_cond, new_cond)

    @staticmethod
    def bypass_signature_check(smali_code):
        pats = [
            (r'invoke-virtual\{.*?\},\s*Landroid/content/pm/PackageManager;->checkSignatures\([^)]*\)I', 'const/4 v0, 0x0\n    return v0'),
            (r'invoke-virtual\{.*?\},\s*Landroid/content/pm/PackageManager;->getPackageInfo\([^)]*\)Landroid/content/pm/PackageInfo;', 'const/4 v0, 0x0\n    return v0'),
        ]
        for pat, repl in pats:
            smali_code = re.sub(pat, repl, smali_code)
        return smali_code

    @staticmethod
    def nop_out_method(smali_code, method_name):
        """将方法体全部替换为 NOP"""
        pattern = r'(\.method\s+.*?' + re.escape(method_name) + r'[^\n]*\n)(.*?)(\.end\s+method)'
        def replacer(m):
            body = m.group(2)
            lines = body.strip().split('\n')
            nop_lines = []
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith('.') and not stripped.startswith('#'):
                    nop_lines.append('    nop')
                elif stripped:
                    nop_lines.append(line)
            return m.group(1) + '\n'.join(nop_lines) + '\n' + m.group(3)
        return re.sub(pattern, replacer, smali_code, flags=re.DOTALL)

    @staticmethod
    def replace_const_value(smali_code, old_value, new_value):
        """替换常量值"""
        patterns = [
            (r'const/4\s+v\d+,\s+' + old_value, f'const/4 v0, {new_value}'),
            (r'const/16\s+v\d+,\s+' + old_value, f'const/16 v0, {new_value}'),
            (r'const\s+v\d+,\s+' + old_value, f'const v0, {new_value}'),
            (r'const-string\s+v\d+,\s*"' + re.escape(old_value) + '"', f'const-string v0, "{new_value}"'),
        ]
        for pat, repl in patterns:
            smali_code = re.sub(pat, repl, smali_code)
        return smali_code

    @staticmethod
    def nop_out_invoke(smali_code, target_class=None, target_method=None):
        """将特定方法调用替换为 NOP"""
        lines = smali_code.split('\n')
        result = []
        for line in lines:
            stripped = line.strip()
            if 'invoke-' in stripped:
                match = re.search(r'invoke-\w+\s+\{[^}]*\},\s*([^;]+);->([^(]+)', stripped)
                if match:
                    cls = match.group(1)
                    method = match.group(2)
                    if target_class and target_class not in cls:
                        result.append(line)
                        continue
                    if target_method and target_method not in method:
                        result.append(line)
                        continue
                    result.append('    nop')
                    continue
            result.append(line)
        return '\n'.join(result)

    @staticmethod
    def generate_method_stub(return_type, method_name, params, access='public'):
        """生成方法存根代码"""
        param_regs = []
        reg_count = 1  # v0 for return
        for i, p in enumerate(params):
            param_regs.append(f'v{i+1}')
            reg_count = i + 2

        if return_type == 'V':
            body = '    return-void'
        elif return_type == 'Z':
            body = '    const/4 v0, 0x0\n    return v0'
        elif return_type in ('I', 'S', 'B', 'C'):
            body = '    const/4 v0, 0x0\n    return v0'
        elif return_type == 'J':
            body = '    const-wide/16 v0, 0x0\n    return-wide v0'
        elif return_type == 'F':
            body = '    const/4 v0, 0x0\n    return v0'
        elif return_type == 'D':
            body = '    const-wide/16 v0, 0x0\n    return-wide v0'
        elif return_type.startswith('L') or return_type.startswith('['):
            body = '    const/4 v0, 0x0\n    return-object v0'
        else:
            body = '    return-void'

        param_str = ''.join(params)
        return f'.method {access} {method_name}({param_str}){return_type}\n    .registers {reg_count}\n{body}\n.end method'

    @staticmethod
    def enable_debug(smali_code):
        """移除方法中的 .line 和 .source 调试信息"""
        smali_code = re.sub(r'\s*\.line\s+\d+\n', '\n', smali_code)
        smali_code = re.sub(r'\s*\.source\s+"[^"]*"\n', '\n', smali_code)
        smali_code = re.sub(r'\s*\.prologue\n', '\n', smali_code)
        return smali_code

    @staticmethod
    def patch_goto_direction(smali_code, old_target, new_target):
        """修改 goto 跳转目标"""
        return smali_code.replace(f':{old_target}', f':{new_target}')

    @staticmethod
    def find_methods_by_string(smali_code, search_string):
        """查找包含特定字符串引用的方法"""
        results = []
        current_method = None
        current_body = []
        for line in smali_code.split('\n'):
            if line.strip().startswith('.method'):
                if current_method and current_body:
                    body_text = '\n'.join(current_body)
                    if search_string in body_text:
                        results.append({'method': current_method, 'body': body_text[:200]})
                current_method = line.strip()
                current_body = []
            elif line.strip().startswith('.end method'):
                if current_method and current_body:
                    body_text = '\n'.join(current_body)
                    if search_string in body_text:
                        results.append({'method': current_method, 'body': body_text[:200]})
                current_method = None
                current_body = []
            elif current_method:
                current_body.append(line)
        return results
