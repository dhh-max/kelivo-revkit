import re

class SMALIUtils:
    """Smali代码分析工具集"""

    @staticmethod
    def parse_class_header(text):
        m = re.search(r'.class\s+(\S+)\s+(\S+)', text)
        return {'access': m.group(1) if m else '', 'class': m.group(2) if m else ''}

    @staticmethod
    def find_methods(text):
        return re.findall(r'\.method\s+(\S+)\s+(\S+(?:\([^)]*\))?[^\n]*)', text)

    @staticmethod
    def find_strings(text):
        return re.findall(r'\s+const-string(?:/jumbo)?\s+v\d+,\s+"([^"]*)"', text)

    @staticmethod
    def extract_method_bodies(smali, method_name):
        blocks = []
        pattern = rf'\.method\s+.*?{re.escape(method_name)}[^\n]*\n(.*?)\.end\s+method'
        for m in re.finditer(pattern, smali, re.DOTALL):
            blocks.append(m.group(0))
        return blocks

    @staticmethod
    def find_invoke(text, target_class=None):
        """查找所有invoke调用"""
        pattern = r'invoke-\w+\s+\{[^}]*\},\s*([^;]+);->([^(]+)\(([^)]*)\)([^\s]*)'
        matches = []
        for m in re.finditer(pattern, text):
            cls = m.group(1)
            method = m.group(2)
            params = m.group(3)
            ret = m.group(4)
            if target_class is None or target_class in cls:
                matches.append({'class': cls, 'method': method, 'params': params, 'return': ret})
        return matches

    @staticmethod
    def find_field_access(text, target_class=None):
        """查找字段访问 (iget/iput/sget/sput)"""
        pattern = r'(i|s)(get|put)\s+(?:\S+\s+){2}([^;]+);->([^:]+):([^\s]+)'
        matches = []
        for m in re.finditer(pattern, text):
            cls = m.group(3)
            field = m.group(4)
            ftype = m.group(5)
            if target_class is None or target_class in cls:
                matches.append({'access': f'{m.group(1)}{m.group(2)}', 'class': cls, 'field': field, 'type': ftype})
        return matches

    @staticmethod
    def find_const_values(text):
        """查找常量值"""
        consts = []
        for m in re.finditer(r'const(?:/[a-z]+)?\s+v\d+,\s+(-?\d+)', text):
            consts.append(int(m.group(1)))
        return consts

    @staticmethod
    def parse_annotation(text):
        """解析注解"""
        annotations = []
        for m in re.finditer(r'\.annotation\s+(\S+)\s*(?:L([^;]+);)?\n(.*?)\.end\s+annotation', text, re.DOTALL):
            annotations.append({'visibility': m.group(1), 'type': m.group(2) or '', 'body': m.group(3).strip()})
        return annotations

    @staticmethod
    def extract_registers(text):
        """提取方法中的寄存器使用"""
        regs = set()
        for m in re.finditer(r'v(\d+)', text):
            regs.add(int(m.group(1)))
        return sorted(regs)

    @staticmethod
    def find_switch_cases(text):
        """查找switch-case结构"""
        cases = []
        for m in re.finditer(r'switch(?:\s+(\S+))?', text):
            cases.append(m.group(0))
        return cases

    @staticmethod
    def find_if_conditions(text):
        """查找条件判断"""
        return re.findall(r'(if-[a-z]+)\s+[^,]+,\s*:([a-zA-Z_][\w]*)', text)

    @staticmethod
    def analyze_method(method_smali):
        """全面分析一个smali方法"""
        return {
            'invokes': SMALIUtils.find_invoke(method_smali),
            'strings': SMALIUtils.find_strings(method_smali),
            'registers': SMALIUtils.extract_registers(method_smali),
            'consts': SMALIUtils.find_const_values(method_smali),
            'ifs': SMALIUtils.find_if_conditions(method_smali),
            'field_access': SMALIUtils.find_field_access(method_smali),
        }
