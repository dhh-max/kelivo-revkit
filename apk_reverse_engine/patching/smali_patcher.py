
import re
class SmaliPatcher:
    @staticmethod
    def find_and_replace(text, old, new): return text.replace(old, new)
    @staticmethod
    def insert_method(smali_code, method_smali, before_line=None):
        if before_line:
            lines = smali_code.split("\n")
            for i, line in enumerate(lines):
                if before_line in line:
                    lines.insert(i, method_smali)
                    return "\n".join(lines)
        return smali_code + "\n" + method_smali
    @staticmethod
    def remove_method(smali_code, method_name):
        pattern = r"\.method\s+.*?" + re.escape(method_name) + r"[^\n]*\n.*?\.end\s+method"
        return re.sub(pattern, "", smali_code, flags=re.DOTALL)
    @staticmethod
    def add_log_inject(smali_code, method_name, tag="DEBUG", msg="injected"):
        pattern = r"(\.method\s+.*?" + re.escape(method_name) + r"[^\n]*\n)"
        inject = '    const-string v0, "' + tag + '"\n    const-string v1, "' + msg + '"\n    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n'
        return re.sub(pattern, r"\1" + inject, smali_code)
