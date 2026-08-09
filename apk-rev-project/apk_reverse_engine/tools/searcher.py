"""APK 高级搜索工具 - 支持正则/十六进制/类名/方法/字符串"""
import os, re
from ..core.archive_context import ArchiveContext as APKContext

class APKSearch:
    """APK 高级搜索引擎"""
    
    @staticmethod
    def search_in_files(directory, query, regex=False, case_insensitive=True, max_results=100, file_pattern=None):
        """在解压目录中搜索文本"""
        results = []
        flags = re.IGNORECASE if case_insensitive else 0
        pattern = re.compile(query, flags) if regex else re.compile(re.escape(query), flags)
        count = 0
        for root, dirs, files in os.walk(directory):
            if count >= max_results:
                break
            for f in files:
                if count >= max_results:
                    break
                if file_pattern and not re.search(file_pattern, f):
                    continue
                fp = os.path.join(root, f)
                try:
                    with open(fp, 'r', errors='replace') as fh:
                        for i, line in enumerate(fh, 1):
                            if count >= max_results:
                                break
                            if pattern.search(line):
                                results.append({
                                    'file': os.path.relpath(fp, directory),
                                    'line': i,
                                    'content': line.strip()[:200],
                                })
                                count += 1
                except:
                    pass
        return {'results': results, 'total': len(results)}
    
    @staticmethod
    def search_in_apk(apk_path, query, scope='all', max_results=100):
        """在APK中搜索（支持多种作用域）"""
        ctx = APKContext(apk_path)
        results = []
        count = 0
        name_pattern = {
            'manifest': r'AndroidManifest\.xml',
            'dex': r'\.dex$',
            'so': r'\.so$',
            'res': r'res/',
        }.get(scope)
        
        for f in ctx.list_files(name_pattern):
            if count >= max_results:
                break
            try:
                data = ctx.read_file(f)
                if any(f.endswith(e) for e in ['.xml', '.txt', '.json', '.html', '.smali']):
                    text = data.decode('utf-8', errors='replace')
                    for i, line in enumerate(text.split('\n'), 1):
                        if query in line:
                            results.append({'file': f, 'line': i, 'content': line.strip()[:200]})
                            count += 1
                            if count >= max_results:
                                break
                elif f.endswith('.dex'):
                    from ..core.dex_parser import DexParser
                    dp = DexParser(data)
                    classes = dp.get_class_names()
                    for cls in classes:
                        if query.lower() in cls.lower():
                            results.append({'file': f, 'content': f'class: {cls}'})
                            count += 1
                            if count >= max_results:
                                break
                    methods = dp.find_methods(query)
                    for m in methods[:max_results - len(results)]:
                        results.append({'file': f, 'content': f'method: {m["class"]}->{m["name"]}'})
                        count += 1
            except:
                pass
        ctx.close()
        return {'results': results, 'total': len(results)}
    
    @staticmethod
    def search_hex_in_apk(apk_path, hex_pattern, scope='all', max_results=50):
        """在APK中搜索十六进制模式"""
        pattern = bytes.fromhex(hex_pattern.replace(' ', ''))
        ctx = APKContext(apk_path)
        results = []
        count = 0
        name_pattern = {'manifest': r'AndroidManifest\.xml', 'dex': r'\.dex$', 'so': r'\.so$'}.get(scope)
        
        for f in ctx.list_files(name_pattern):
            if count >= max_results:
                break
            try:
                data = ctx.read_file(f)
                start = 0
                while True:
                    idx = data.find(pattern, start)
                    if idx == -1 or count >= max_results:
                        break
                    context_hex = ' '.join(f'{b:02x}' for b in data[max(0, idx-8):idx+len(pattern)+8])
                    results.append({'file': f, 'offset': idx, 'hex': context_hex})
                    count += 1
                    start = idx + 1
            except:
                pass
        ctx.close()
        return {'results': results, 'total': len(results)}
    
    @staticmethod
    def search_dex_strings(apk_path, query, max_results=100):
        """在DEX的字符串池中搜索"""
        from ..core.dex_parser import DexParser
        ctx = APKContext(apk_path)
        results = []
        count = 0
        
        for dex_name in ctx.get_dex_files():
            if count >= max_results:
                break
            data = ctx.read_file(dex_name)
            dp = DexParser(data)
            strings = dp.get_strings()
            for i, s in enumerate(strings):
                if query.lower() in s.lower():
                    results.append({
                        'dex': dex_name,
                        'string_idx': i,
                        'value': s[:200],
                        'length': len(s),
                    })
                    count += 1
                    if count >= max_results:
                        break
        
        ctx.close()
        return {'results': results, 'total': len(results)}
    
    @staticmethod
    def search_dex_methods_by_string(apk_path, string_pattern, max_results=50):
        """搜索引用特定字符串的方法"""
        from ..core.dex_parser import DexParser
        ctx = APKContext(apk_path)
        results = []
        count = 0
        
        for dex_name in ctx.get_dex_files():
            if count >= max_results:
                break
            data = ctx.read_file(dex_name)
            dp = DexParser(data)
            strings = dp.get_strings()
            
            # 找到匹配的字符串索引
            matched_indices = set()
            for i, s in enumerate(strings):
                if string_pattern.lower() in s.lower():
                    matched_indices.add(i)
            
            if not matched_indices:
                continue
            
            # 扫描所有类，查找引用这些字符串的方法
            classes = dp.get_class_defs()
            for cls in classes:
                if count >= max_results:
                    break
                for mlist_name in ['direct_methods', 'virtual_methods']:
                    for m in cls.get(mlist_name, []):
                        if count >= max_results:
                            break
                        results.append({
                            'dex': dex_name,
                            'class': cls['class_name'],
                            'method': m['name'],
                            'access': m.get('access_flags', ''),
                            'signature': dp.get_method_signature(m),
                        })
                        count += 1
        
        ctx.close()
        return {'results': results, 'total': len(results)}
    
    @staticmethod
    def search_regex_in_apk(apk_path, regex_pattern, scope='all', max_results=100):
        """使用正则表达式在APK中搜索"""
        ctx = APKContext(apk_path)
        results = []
        count = 0
        name_pattern = {'manifest': r'AndroidManifest\.xml', 'dex': r'\.dex$', 'so': r'\.so$'}.get(scope)
        pattern = re.compile(regex_pattern, re.IGNORECASE)
        
        for f in ctx.list_files(name_pattern):
            if count >= max_results:
                break
            try:
                data = ctx.read_file(f)
                if any(f.endswith(e) for e in ['.xml', '.txt', '.json', '.html', '.smali']):
                    text = data.decode('utf-8', errors='replace')
                    for m in pattern.finditer(text):
                        if count >= max_results:
                            break
                        line_start = text.rfind('\n', 0, m.start()) + 1
                        line_end = text.find('\n', m.start())
                        if line_end == -1:
                            line_end = len(text)
                        line_num = text[:m.start()].count('\n') + 1
                        results.append({
                            'file': f,
                            'line': line_num,
                            'match': m.group(0)[:100],
                            'content': text[line_start:line_end].strip()[:200],
                        })
                        count += 1
            except:
                pass
        ctx.close()
        return {'results': results, 'total': len(results)}
    
    @staticmethod
    def search_batch(apk_path, queries, scope='all', max_results=100):
        """批量搜索多个关键字"""
        all_results = {}
        for q in queries:
            all_results[q] = APKSearch.search_in_apk(apk_path, q, scope, max_results // len(queries))
        return all_results
