"""DEX 方法访问权限流分析 — 访问修饰符合规性/暴露面/权限泄漏"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict, Counter

class DexAccessFlowAnalyzer:
    """分析 DEX 中方法/字段访问修饰符的安全合规性与暴露面"""

    # 危险方法名模式（public 暴露的敏感操作）
    SENSITIVE_PATTERNS = {
        'crypto': lambda n: any(k in n.lower() for k in ('encrypt', 'decrypt', 'cipher', 'aes', 'rsa', 'des', 'md5', 'sha', 'hmac')),
        'reflection': lambda n: any(k in n.lower() for k in ('forname', 'getmethod', 'getfield', 'invoke', 'getclass', 'getdeclared')),
        'runtime_exec': lambda n: any(k in n.lower() for k in ('exec', 'runtime', 'process', 'command', 'shell')),
        'file_io': lambda n: any(k in n.lower() for k in ('writefile', 'readfile', 'deletefile', 'mkdir', 'createdir', 'removefile')),
        'network': lambda n: any(k in n.lower() for k in ('http', 'url', 'request', 'connect', 'socket', 'download', 'upload')),
        'system': lambda n: any(k in n.lower() for k in ('getsystem', 'setsystem', 'system.', 'getprop', 'settings.', 'setting')),
        'serialization': lambda n: any(k in n.lower() for k in ('serialize', 'deserialize', 'writeobject', 'readobject', 'parcelable')),
        'database': lambda n: any(k in n.lower() for k in ('execsql', 'rawquery', 'insert', 'delete', 'update', 'query')),
        'clipboard': lambda n: 'clipboard' in n.lower(),
        'intent': lambda n: 'startactivity' in n.lower() or 'startservice' in n.lower() or 'sendbroadcast' in n.lower(),
    }

    @staticmethod
    def analyze(dex_parser):
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()

        if not class_defs:
            return {'error': '无可分析类定义'}

        total_methods = 0
        total_fields = 0
        public_methods = 0
        public_fields = 0
        private_methods = 0
        protected_methods = 0
        static_methods = 0
        native_methods = 0
        final_methods = 0
        abstract_methods = 0
        synchronized_methods = 0

        # 敏感 public 方法
        sensitive_public = []
        # public 但未 final 的方法（可被覆写）
        overridable_public = []
        # public static 方法
        public_static = []
        # public 字段（非 final，暴露状态）
        exposed_fields = []
        # public static final 常量
        public_constants = []
        # public native 方法（JNI 暴露）
        native_exposed = []
        # public 方法最多的类
        class_public_methods = Counter()

        for cd in class_defs:
            cls_name = cd.get('class_name', '')
            is_interface = 'INTERFACE' in (cd.get('access_flags', '') or '')
            is_abstract = 'ABSTRACT' in (cd.get('access_flags', '') or '')

            all_methods = (cd.get('direct_methods') or []) + (cd.get('virtual_methods') or [])
            all_fields = (cd.get('static_fields') or []) + (cd.get('instance_fields') or [])

            for m in all_methods:
                total_methods += 1
                flags = m.get('access_flags', '') or ''
                name = m.get('name', '')
                is_public = 'PUBLIC' in flags
                is_private = 'PRIVATE' in flags
                is_protected = 'PROTECTED' in flags
                is_static = 'STATIC' in flags
                is_native = 'NATIVE' in flags
                is_final = 'FINAL' in flags
                is_abstract = 'ABSTRACT' in flags
                is_sync = 'SYNCHRONIZED' in flags

                if is_public: public_methods += 1
                if is_private: private_methods += 1
                if is_protected: protected_methods += 1
                if is_static: static_methods += 1
                if is_native: native_methods += 1
                if is_final: final_methods += 1
                if is_abstract: abstract_methods += 1
                if is_sync: synchronized_methods += 1

                if is_public:
                    class_public_methods[cls_name] += 1
                    # 检查敏感模式
                    for cat, fn in DexAccessFlowAnalyzer.SENSITIVE_PATTERNS.items():
                        if fn(name):
                            sensitive_public.append({
                                'class': cls_name, 'method': name,
                                'flags': flags, 'category': cat,
                            })
                    # public 非 final 非 abstract → 可覆写
                    if not is_final and not is_abstract and not is_interface:
                        overridable_public.append({
                            'class': cls_name, 'method': name, 'flags': flags,
                        })
                    if is_static:
                        public_static.append({
                            'class': cls_name, 'method': name,
                        })
                    if is_native:
                        native_exposed.append({
                            'class': cls_name, 'method': name,
                        })

            for f in all_fields:
                total_fields += 1
                flags = f.get('access_flags', '') or ''
                fname = f.get('name', '')
                ftype = f.get('type', '')
                is_public = 'PUBLIC' in flags
                is_static = 'STATIC' in flags
                is_final = 'FINAL' in flags

                if is_public:
                    public_fields += 1
                    if is_static and is_final:
                        public_constants.append({
                            'class': cls_name, 'field': fname, 'type': ftype,
                        })
                    elif not is_final:
                        exposed_fields.append({
                            'class': cls_name, 'field': fname,
                            'type': ftype, 'flags': flags,
                        })

        def fmt(desc):
            return desc.replace('L', '', 1).replace(';', '').replace('/', '.') if desc.startswith('L') else desc

        return {
            'total_methods': total_methods,
            'total_fields': total_fields,
            'method_visibility': {
                'public': public_methods,
                'private': private_methods,
                'protected': protected_methods,
                'default': total_methods - public_methods - private_methods - protected_methods,
            },
            'method_modifiers': {
                'static': static_methods,
                'native': native_methods,
                'final': final_methods,
                'abstract': abstract_methods,
                'synchronized': synchronized_methods,
            },
            'public_fields': public_fields,
            'exposed_fields_count': len(exposed_fields),
            'public_constants_count': len(public_constants),
            'sensitive_public_methods': len(sensitive_public),
            'overridable_public_count': len(overridable_public),
            'native_exposed_count': len(native_exposed),
            'sensitive_methods': [
                {'class': fmt(s['class']), 'method': s['method'], 'category': s['category'], 'flags': s['flags']}
                for s in sensitive_public[:30]
            ],
            'overridable_public': [
                {'class': fmt(o['class']), 'method': o['method']}
                for o in overridable_public[:20]
            ],
            'native_exposed': [
                {'class': fmt(n['class']), 'method': n['method']}
                for n in native_exposed[:15]
            ],
            'exposed_fields': [
                {'class': fmt(e['class']), 'field': e['field'], 'type': e['type']}
                for e in exposed_fields[:20]
            ],
            'top_classes_by_public_methods': [
                {'class': fmt(c), 'count': cnt}
                for c, cnt in class_public_methods.most_common(20)
            ],
        }

    @staticmethod
    def get_summary(result):
        if 'error' in result:
            return result
        return {
            'total_methods': result['total_methods'],
            'public_methods': result['method_visibility']['public'],
            'sensitive_public': result['sensitive_public_methods'],
            'overridable_public': result['overridable_public_count'],
            'native_exposed': result['native_exposed_count'],
            'exposed_fields': result['exposed_fields_count'],
            'top5_public_classes': result['top_classes_by_public_methods'][:5],
        }
