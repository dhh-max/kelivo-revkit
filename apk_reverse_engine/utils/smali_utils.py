import re
class SMALIUtils:
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
