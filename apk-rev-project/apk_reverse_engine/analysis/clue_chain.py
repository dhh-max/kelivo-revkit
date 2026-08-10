"""线索串联分析器 - 跨模块关联分析，自动发现可疑信号

核心思路：
  将 Manifest / DEX / SO / Assets / 权限 等不同维度的分析结果
  交叉关联，自动发现跨模块的可疑模式，实现"1+1>2"的检测效果。

设计哲学：
  单维度解析 → 只告诉你"有什么"
  线索串联   → 告诉你"这意味着什么"
"""


from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import re
from collections import Counter
class ClueChain:
    """串联线索分析器"""

    # SO 文件名关键词
    SO_KEYWORDS = {
        'crypto': '加密/解密', 'encode': '编码/加密', 'decrypt': '解密',
        'protect': '保护/加固', 'obfus': '代码混淆', 'shell': '加壳',
        'packer': '加固壳', 'vmp': '虚拟机保护', 'webapp': 'WebView 配套',
        'bridge': 'JNI 桥接', 'sign': '签名校验', 'verify': '校验/验证',
        'security': '安全模块', 'anti': '反检测/反调试', 'hook': 'Hook 框架',
        'inject': '注入', 'downloader': '下载器', 'network': '网络通信',
        'proxy': '代理/转发', 'tunnel': '隧道代理',
    }

    # 高危权限组合
    HIGH_RISK_PERMISSION_COMBOS = [
        {'perms': {'READ_CONTACTS', 'SEND_SMS', 'CALL_PHONE'},
         'name': '隐私窃取组合', 'desc': '读取联系人+发送短信+拨打电话，典型隐私窃取'},
        {'perms': {'CAMERA', 'RECORD_AUDIO', 'INTERNET'},
         'name': '监控组合', 'desc': '摄像头+麦克风+网络，可能用于监控录音上传'},
        {'perms': {'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'INTERNET'},
         'name': '位置追踪组合', 'desc': '精确定位+后台定位+网络，持续追踪用户位置'},
        {'perms': {'READ_SMS', 'RECEIVE_SMS', 'INTERNET'},
         'name': '短信拦截组合', 'desc': '读取短信+接收短信+网络，可能拦截验证码'},
        {'perms': {'INSTALL_PACKAGES', 'DELETE_PACKAGES'},
         'name': '应用管理组合', 'desc': '安装/卸载应用权限，可能静默安装恶意应用'},
        {'perms': {'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE'},
         'name': '覆盖攻击组合', 'desc': '悬浮窗+无障碍服务，典型钓鱼/点击劫持'},
        {'perms': {'READ_EXTERNAL_STORAGE', 'INTERNET', 'READ_CONTACTS'},
         'name': '数据收集组合', 'desc': '读取存储+网络+联系人，批量收集数据'},
    ]

    # 危险类名关键词
    DANGEROUS_CLASS_KEYWORDS = {
        'javascriptinterface': ('js_bridge', 'high', 'JS 桥接接口'),
        'beanshell': ('dynamic_exec', 'high', 'BeanShell 脚本引擎'),
        'bsh': ('dynamic_exec', 'high', 'BeanShell 运行时'),
        'dexclassloader': ('dynamic_load', 'high', 'DexClassLoader 动态加载'),
        'pathclassloader': ('dynamic_load', 'medium', 'PathClassLoader 动态加载'),
        'inject': ('injection', 'high', '注入操作'),
        'hook': ('hook', 'high', 'Hook 框架'),
        'root': ('root_check', 'medium', 'Root 检测'),
        'su': ('root_check', 'medium', 'su 命令检测'),
        'exec': ('command_exec', 'high', '命令执行'),
        'runtime.getruntime': ('command_exec', 'high', 'Runtime 命令执行'),
        'processbuilder': ('command_exec', 'high', 'ProcessBuilder 进程启动'),
        'reflect': ('reflection', 'low', '反射调用'),
        'proxy': ('proxy', 'medium', '代理/转发'),
        'socket': ('socket', 'low', 'Socket 通信'),
        'ssl': ('ssl_pinning', 'medium', 'SSL/TLS'),
        'webview': ('webview', 'low', 'WebView 组件'),
        'download': ('downloader', 'medium', '下载器'),
        'update': ('auto_update', 'medium', '自动更新'),
        'plugin': ('plugin', 'medium', '插件化'),
        'module': ('plugin', 'medium', '模块化'),
        'crypto': ('crypto', 'medium', '加密操作'),
        'cipher': ('crypto', 'medium', '加解密算法'),
        'aes': ('crypto', 'medium', 'AES 加密'),
        'rsa': ('crypto', 'medium', 'RSA 加密'),
        'base64': ('encode', 'low', 'Base64 编码'),
        'service': ('service', 'low', '后台服务'),
        'broadcast': ('broadcast', 'medium', '广播接收器'),
        'receiver': ('broadcast', 'medium', '广播接收器'),
    }

    @classmethod
    def analyze(cls, manifest=None, dex_summary=None, class_names=None,
                native_analysis=None, so_files=None, assets_files=None,
                permissions=None, packers=None, obfuscation_score=None,
                signature=None, apk_structure=None, dex_strings=None,
                ad_analysis=None, string_analysis=None,
                resource_obfuscation=None):
        """全量线索串联分析"""
        clues = []
        risks = set()
        tags = set()

        analyzers = [
            cls._webview_shell, cls._beanshell, cls._native_libs,
            cls._permission_abuse, cls._obfuscation_packer,
            cls._dynamic_loading, cls._signature, cls._structure,
            cls._sensitive_classes, cls._dex_strings,
            cls._broadcast_receivers, cls._background_network,
            cls._ad_integration, cls._string_risk,
            cls._resource_obfuscation_cross,
        ]

        for analyzer in analyzers:
            try:
                r = analyzer(manifest=manifest, dex_summary=dex_summary,
                             class_names=class_names, native_analysis=native_analysis,
                             so_files=so_files, assets_files=assets_files,
                             permissions=permissions, packers=packers,
                             obfuscation_score=obfuscation_score,
                             signature=signature, apk_structure=apk_structure,
                             dex_strings=dex_strings,
                             ad_analysis=ad_analysis, string_analysis=string_analysis,
                             resource_obfuscation=resource_obfuscation)
                clues.extend(r.get('clues', []))
                risks.update(r.get('risks', []))
                tags.update(r.get('tags', set()))
            except Exception as e:
                clues.append({'type': 'error', 'title': f'分析器异常: {analyzer.__name__}',
                              'detail': str(e), 'severity': 'info'})

        score = cls._calc_score(risks, clues, tags)
        summary = cls._gen_summary(clues, risks, score, tags)

        return {
            'clues': clues, 'risks': sorted(risks), 'tags': sorted(tags),
            'score': score,
            'level': 'high' if score >= 70 else ('medium' if score >= 35 else 'low'),
            'summary': summary, 'clue_count': len(clues), 'risk_count': len(risks),
        }

    # ============================================================
    # 分析器1: WebView 套壳 + JS Bridge
    # ============================================================
    @classmethod
    def _webview_shell(cls, **kw):
        clues, risks, tags = [], set(), set()
        class_names = kw.get('class_names') or []
        assets_files = kw.get('assets_files') or []
        manifest = kw.get('manifest') or {}

        has_webview = any('webview' in c.lower() for c in class_names)
        has_web_assets = any(a.startswith('assets/') and a.endswith(('.html', '.js', '.css')) for a in assets_files)
        has_js_bridge = any('javascriptinterface' in c.lower() for c in class_names)

        # components 可能是 dict 或 list
        components = manifest.get('components', {})
        if isinstance(components, dict):
            activities = components.get('activities', [])
        else:
            activities = components if isinstance(components, list) else []
        has_webview_act = any('webview' in str(comp.get('name', comp) if isinstance(comp, dict) else comp).lower()
                              for comp in activities)

        if has_webview and has_web_assets:
            html_count = len([a for a in assets_files if a.endswith('.html')])
            clues.append({
                'type': 'webview_shell', 'severity': 'info',
                'title': 'WebView 套壳应用',
                'detail': f'WebView 组件 + {html_count} 个 HTML 前端资源，核心逻辑在前端中',
                'cross_ref': ['assets/*.html', 'android.webkit.WebView'],
            })
            tags.add('webview_shell')

        if has_js_bridge:
            level = 'high' if has_webview_act else 'medium'
            clues.append({
                'type': 'js_bridge', 'severity': level,
                'title': 'JS Bridge 接口暴露',
                'detail': '@JavascriptInterface 允许 JS 调用 Java 方法，若未限制范围可能导致 XSS 攻击',
                'cross_ref': ['@JavascriptInterface', 'addJavascriptInterface()'],
            })
            tags.add('js_bridge')
            if level == 'high':
                risks.add('JS_BRIDGE_EXPOSED')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器2: BeanShell 动态执行
    # ============================================================
    @classmethod
    def _beanshell(cls, **kw):
        clues, risks, tags = [], set(), set()
        class_names = kw.get('class_names') or []
        assets_files = kw.get('assets_files') or []

        has_bsh_class = any('beanshell' in c.lower() or c.startswith('bsh/') for c in class_names)
        has_bsh_dir = any(a.startswith('bsh/') for a in assets_files)

        if has_bsh_class or has_bsh_dir:
            clues.append({
                'type': 'beanshell', 'severity': 'high',
                'title': 'BeanShell 脚本运行时',
                'detail': '内置 BeanShell Java 脚本解释器，可在运行时动态执行任意 Java 代码。'
                          '正常应用极少使用，多见于恶意软件/后门',
                'cross_ref': ['bsh/', 'bsh.Interpreter'],
            })
            tags.add('beanshell')
            risks.add('BEANSHELL_DYNAMIC_EXEC')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器3: SO 文件关联分析
    # ============================================================
    @classmethod
    def _native_libs(cls, **kw):
        clues, risks, tags = [], set(), set()
        native_analysis = kw.get('native_analysis') or {}
        so_files = kw.get('so_files') or []
        dex_strings = kw.get('dex_strings') or []

        if not so_files:
            return {'clues': clues, 'risks': risks, 'tags': tags}

        # SO 功能标签
        so_tags = []
        for so_name in so_files:
            for keyword, label in cls.SO_KEYWORDS.items():
                if keyword in so_name.lower():
                    so_tags.append(label)
        if so_tags:
            counter = Counter(so_tags)
            tags.update(so_tags)
            clues.append({
                'type': 'so_function_map', 'severity': 'info',
                'title': 'SO 功能分布',
                'detail': f'{len(so_files)} 个 SO 文件，标签: {dict(counter)}',
                'cross_ref': list(so_files),
            })

        # 可疑 API 检测
        suspicious_apis = {
            'dlopen': '动态加载SO', 'dlsym': '动态符号查找',
            'ptrace': '反调试', 'fork': '进程创建', 'system': '系统命令',
            'popen': '管道命令', 'mmap': '内存映射', 'mprotect': '内存保护修改',
            'socket': 'Socket通信', 'connect': '网络连接',
        }
        found_apis = {}
        for so_path, info in native_analysis.items():
            if isinstance(info, dict) and 'error' not in info:
                imports = info.get('imports', []) or []
                exports = info.get('exports', []) or []
                for api in suspicious_apis:
                    if any(api in (imp or '').lower() for imp in imports):
                        found_apis.setdefault(api, []).append(so_path)
                    if any(api in (exp or '').lower() for exp in exports):
                        found_apis.setdefault(api, []).append(so_path)

        if found_apis:
            high_risk = {k: v for k, v in found_apis.items()
                         if k in ('ptrace', 'dlopen', 'dlsym', 'system', 'fork', 'mprotect')}
            if high_risk:
                clues.append({
                    'type': 'native_suspicious', 'severity': 'high',
                    'title': 'Native 层高危 API',
                    'detail': ', '.join(f'{k}({len(v)}个SO)' for k, v in high_risk.items()),
                    'cross_ref': list(high_risk.keys()),
                })
                risks.add('NATIVE_SUSPICIOUS_API')
                tags.add('native_suspicious')

        # SO+DEX 加密交叉引用
        has_crypto_so = any('crypto' in s.lower() for s in so_files)
        has_crypto_dex = any('crypto' in s.lower() for s in dex_strings[:2000]) if dex_strings else False
        if has_crypto_so and has_crypto_dex:
            clues.append({
                'type': 'crypto_cross', 'severity': 'medium',
                'title': '加密逻辑: SO+DEX 双重加密',
                'detail': f'SO 层加密库 + DEX 字符串含加密关键词，建议重点分析加密实现',
                'cross_ref': [s for s in so_files if 'crypto' in s.lower()],
            })
            tags.add('crypto_usage')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器4: 权限滥用组合
    # ============================================================
    @classmethod
    def _permission_abuse(cls, **kw):
        clues, risks, tags = [], set(), set()
        permissions = kw.get('permissions') or []
        if not permissions:
            return {'clues': clues, 'risks': risks, 'tags': tags}

        perm_names = set(p.split('.')[-1].upper() if '.' in p else p.upper() for p in permissions)

        for combo in cls.HIGH_RISK_PERMISSION_COMBOS:
            matched = combo['perms'] & perm_names
            if len(matched) >= len(combo['perms']) * 0.66:
                clues.append({
                    'type': 'permission_abuse', 'severity': 'high',
                    'title': combo['name'],
                    'detail': f"{combo['desc']} ({', '.join(matched)})",
                    'cross_ref': list(matched),
                })
                risks.add('PERMISSION_ABUSE')
                tags.add('permission_abuse')

        high_risk_perms = {'READ_CONTACTS', 'SEND_SMS', 'CALL_PHONE', 'CAMERA',
                           'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'READ_SMS',
                           'INSTALL_PACKAGES', 'BIND_ACCESSIBILITY_SERVICE',
                           'SYSTEM_ALERT_WINDOW', 'READ_EXTERNAL_STORAGE'}
        found_high = perm_names & high_risk_perms
        if len(found_high) >= 3:
            clues.append({
                'type': 'excessive_permissions', 'severity': 'medium',
                'title': '高危权限过多',
                'detail': f'{len(found_high)} 个高危权限: {", ".join(sorted(found_high))}',
                'cross_ref': sorted(found_high),
            })
            tags.add('excessive_permissions')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器5: 混淆 + 加固关联
    # ============================================================
    @classmethod
    def _obfuscation_packer(cls, **kw):
        clues, risks, tags = [], set(), set()
        obfuscation_score = kw.get('obfuscation_score')
        packers = kw.get('packers') or []
        class_names = kw.get('class_names') or []

        has_packer = bool(packers)
        is_obfuscated = obfuscation_score is not None and obfuscation_score > 50
        class_count = len(class_names)

        if has_packer:
            clues.append({
                'type': 'packer', 'severity': 'high',
                'title': '加固壳检测',
                'detail': f'检测到: {", ".join(packers)}',
                'cross_ref': packers,
            })
            risks.add('PACKER_DETECTED')
            tags.add('packed')

        if is_obfuscated:
            clues.append({
                'type': 'obfuscation', 'severity': 'medium',
                'title': '代码混淆',
                'detail': f'混淆评分 {obfuscation_score}/100',
                'cross_ref': [f'score={obfuscation_score}'],
            })
            tags.add('obfuscated')

        if has_packer and is_obfuscated:
            clues.append({
                'type': 'heavy_protection', 'severity': 'high',
                'title': '加固+混淆双重保护',
                'detail': '同时使用加固壳和代码混淆，常见于恶意软件或商业应用保护核心逻辑',
                'cross_ref': ['packers', 'obfuscation'],
            })
            tags.add('heavy_protection')

        if has_packer and 0 < class_count < 50:
            clues.append({
                'type': 'stub_app', 'severity': 'high',
                'title': '存根应用(Stub)',
                'detail': f'仅 {class_count} 个类 + 加固壳，核心逻辑在运行时动态加载',
                'cross_ref': ['packers', 'few_classes'],
            })
            risks.add('STUB_APP')
            tags.add('stub_app')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器6: 动态加载/执行
    # ============================================================
    @classmethod
    def _dynamic_loading(cls, **kw):
        clues, risks, tags = [], set(), set()
        class_names = kw.get('class_names') or []

        found = []
        for keyword, (category, severity, label) in cls.DANGEROUS_CLASS_KEYWORDS.items():
            if category not in ('dynamic_load', 'command_exec', 'injection', 'hook'):
                continue
            matches = [c for c in class_names if keyword in c.lower()]
            if matches:
                found.append((label, severity, len(matches), category))

        if found:
            high = [f for f in found if f[1] == 'high']
            medium = [f for f in found if f[1] == 'medium']

            if high:
                clues.append({
                    'type': 'dynamic_loading', 'severity': 'high',
                    'title': '动态加载/执行',
                    'detail': ', '.join(f'{l}({c}处)' for l, _, c, _ in high),
                    'cross_ref': [l for l, _, _, _ in high],
                })
                risks.add('DYNAMIC_LOADING')
                tags.add('dynamic_loading')

            if medium:
                clues.append({
                    'type': 'dynamic_loading_medium', 'severity': 'medium',
                    'title': '动态加载/执行(中危)',
                    'detail': ', '.join(f'{l}({c}处)' for l, _, c, _ in medium),
                    'cross_ref': [l for l, _, _, _ in medium],
                })

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器7: 签名分析
    # ============================================================
    @classmethod
    def _signature(cls, **kw):
        clues, risks, tags = [], set(), set()
        signature = kw.get('signature') or {}
        class_names = kw.get('class_names') or []

        # signature 可能是 bool 或 dict
        if isinstance(signature, bool):
            v1 = v2 = v3 = signature
        else:
            v1 = bool(signature.get('v1', False))
            v2 = bool(signature.get('v2', False))
            v3 = bool(signature.get('v3', False))

        if not v2 and not v3:
            clues.append({
                'type': 'weak_signature', 'severity': 'medium',
                'title': '签名方案过旧',
                'detail': f'仅 V1(V1={v1}, V2={v2}, V3={v3})，V1 易被篡改',
                'cross_ref': ['V1', 'JAR signature'],
            })
            tags.add('weak_signature')

        if any('sign' in c.lower() and 'check' in c.lower() for c in class_names):
            clues.append({
                'type': 'sign_check', 'severity': 'info',
                'title': '签名校验代码',
                'detail': '应用内含签名校验相关类，可能用于防篡改',
                'cross_ref': [c for c in class_names if 'sign' in c.lower()],
            })
            tags.add('has_sign_check')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器8: 结构异常检测
    # ============================================================
    @classmethod
    def _structure(cls, **kw):
        clues, risks, tags = [], set(), set()
        assets_files = kw.get('assets_files') or []

        suspicious = []
        for af in assets_files:
            lower = af.lower()
            if lower.endswith('.dex'):
                suspicious.append(('dex', af, 'high', 'assets 中的 DEX 文件'))
            elif lower.endswith('.jar'):
                suspicious.append(('jar', af, 'high', 'assets 中的 JAR 文件'))
            elif lower.endswith('.so'):
                suspicious.append(('so', af, 'high', 'assets 中的 SO 文件'))
            elif lower.endswith('.apk'):
                suspicious.append(('apk', af, 'high', 'assets 中的 APK 文件'))

        high = [s for s in suspicious if s[2] == 'high']
        if high:
            clues.append({
                'type': 'suspicious_assets', 'severity': 'high',
                'title': 'assets 可疑文件',
                'detail': f'{len(high)} 个: {", ".join(s[1] for s in high[:5])}',
                'cross_ref': [s[1] for s in high],
            })
            risks.add('SUSPICIOUS_ASSETS')
            tags.add('suspicious_assets')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器9: 敏感类/API 综合检测
    # ============================================================
    @classmethod
    def _sensitive_classes(cls, **kw):
        clues, risks, tags = [], set(), set()
        class_names = kw.get('class_names') or []

        category_hits = {}
        for c in class_names:
            for keyword, (category, severity, label) in cls.DANGEROUS_CLASS_KEYWORDS.items():
                if keyword in c.lower():
                    category_hits.setdefault(category, set()).add(label)
                    break

        if category_hits:
            sensitive = {'crypto', 'hash', 'encode', 'reflection'}
            found_s = {k: v for k, v in category_hits.items() if k in sensitive}
            if found_s:
                clues.append({
                    'type': 'sensitive_ops', 'severity': 'info',
                    'title': '敏感操作',
                    'detail': ', '.join(f'{k}({len(v)}种)' for k, v in found_s.items()),
                    'cross_ref': list(found_s.keys()),
                })
                tags.add('sensitive_ops')

            high = {'command_exec', 'dynamic_exec', 'injection', 'hook', 'dynamic_load'}
            found_h = {k: v for k, v in category_hits.items() if k in high}
            if found_h:
                clues.append({
                    'type': 'high_risk_ops', 'severity': 'high',
                    'title': '高危操作',
                    'detail': ', '.join(f'{k}({len(v)}种)' for k, v in found_h.items()),
                    'cross_ref': list(found_h.keys()),
                })

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器10: DEX 字符串分析
    # ============================================================
    @classmethod
    def _dex_strings(cls, **kw):
        clues, risks, tags = [], set(), set()
        dex_strings = kw.get('dex_strings') or []
        if not dex_strings:
            return {'clues': clues, 'risks': risks, 'tags': tags}

        urls = [s for s in dex_strings[:5000] if s.startswith(('http://', 'https://'))]
        ips = [s for s in dex_strings[:5000] if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)]

        if urls:
            domains = Counter()
            for u in urls:
                try:
                    domains[u.split('/')[2]] += 1
                except Exception as e:
                    logger.debug("apk_reverse_engine/analysis/clue_chain.py:538 suppressed: %s", e)
                    logger.debug(f"e")
            top = domains.most_common(5)
            clues.append({
                'type': 'network_urls', 'severity': 'info',
                'title': 'DEX 中的网络地址',
                'detail': f'{len(urls)} 个 URL, {len(ips)} 个 IP。Top: {", ".join(f"{d}({c}次)" for d, c in top)}',
                'cross_ref': urls[:5],
            })
            tags.add('has_network_urls')

        keys = [s for s in dex_strings[:2000] if 16 <= len(s) <= 64 and
                any(k in s.lower() for k in ('key', 'secret', 'password', 'token', 'aes', 'iv='))]
        if keys:
            clues.append({
                'type': 'potential_keys', 'severity': 'medium',
                'title': '潜在密钥/密码',
                'detail': f'{len(keys)} 个疑似密钥字符串',
                'cross_ref': keys[:5],
            })
            tags.add('potential_keys')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器11: 广播接收器
    # ============================================================
    @classmethod
    def _broadcast_receivers(cls, **kw):
        clues, risks, tags = [], set(), set()
        manifest = kw.get('manifest') or {}
        components = manifest.get('components', {})
        if isinstance(components, dict):
            receivers = components.get('receivers', [])
        else:
            receivers = []
        if not receivers:
            return {'clues': clues, 'risks': risks, 'tags': tags}

        for r in receivers:
            name = r.get('name', '').lower()
            if 'sms' in name:
                clues.append({
                    'type': 'sms_receiver', 'severity': 'high',
                    'title': '短信广播接收器',
                    'detail': f'注册了短信广播接收器 {r["name"]}，可能拦截/读取短信',
                    'cross_ref': [r['name']],
                })
                risks.add('SMS_RECEIVER')
                tags.add('sms_receiver')
            if 'boot' in name or 'startup' in name:
                clues.append({
                    'type': 'boot_receiver', 'severity': 'medium',
                    'title': '开机自启',
                    'detail': f'注册了开机广播 {r["name"]}，应用可在后台自启动',
                    'cross_ref': [r['name']],
                })
                tags.add('boot_receiver')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器12: 后台网络行为
    # ============================================================
    @classmethod
    def _background_network(cls, **kw):
        clues, risks, tags = [], set(), set()
        manifest = kw.get('manifest') or {}
        permissions = kw.get('permissions') or []

        perm_set = set(p.upper() for p in permissions)
        components = manifest.get('components', {})
        if isinstance(components, dict):
            services = components.get('services', [])
        else:
            services = []
        has_internet = 'INTERNET' in perm_set or 'android.permission.INTERNET' in perm_set
        has_background = 'ACCESS_BACKGROUND_LOCATION' in perm_set
        has_service = len(services) > 0

        if has_internet and has_service and has_background:
            clues.append({
                'type': 'background_tracking', 'severity': 'high',
                'title': '后台定位+网络',
                'detail': f'{len(services)} 个后台服务 + 网络权限 + 后台定位，可在后台持续追踪位置并上传',
                'cross_ref': ['INTERNET', 'ACCESS_BACKGROUND_LOCATION', 'services'],
            })
            risks.add('BACKGROUND_TRACKING')
            tags.add('background_tracking')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 评分 & 总结
    # ============================================================
    @classmethod
    def _calc_score(cls, risks, clues, tags):
        """综合风险评分 0-100"""
        score = 0

        # 每个风险标记 +15
        score += len(risks) * 15

        # 高危线索 +5
        high_clues = sum(1 for c in clues if c.get('severity') == 'high')
        score += high_clues * 5

        # 特征标签加权
        high_risk_tags = {'beanshell', 'packed', 'heavy_protection', 'stub_app',
                          'dynamic_loading', 'native_suspicious', 'sms_receiver',
                          'background_tracking', 'permission_abuse', 'ad_heavy',
                          'string_sensitive_data', 'resource_obfuscated'}
        score += len(tags & high_risk_tags) * 8

        # 扣分项：纯 WebView 套壳且无其他风险 → 降低
        if tags == {'webview_shell'} and len(risks) == 0:
            score = max(score - 20, 0)

        return min(score, 100)

    @classmethod
    def _gen_summary(cls, clues, risks, score, tags):
        """生成分析总结"""
        level = 'high' if score >= 70 else ('medium' if score >= 35 else 'low')

        if level == 'high':
            conclusion = '⚠️ 高风险应用，建议谨慎处理'
        elif level == 'medium':
            conclusion = '⚡ 中等风险，建议进一步分析'
        else:
            conclusion = '✅ 低风险，常规应用'

        high_count = sum(1 for c in clues if c.get('severity') == 'high')
        medium_count = sum(1 for c in clues if c.get('severity') == 'medium')

        tag_labels = {
            'webview_shell': 'WebView 套壳', 'beanshell': 'BeanShell 动态执行',
            'packed': '加固保护', 'obfuscated': '代码混淆',
            'heavy_protection': '双重保护', 'stub_app': '存根应用',
            'dynamic_loading': '动态加载', 'permission_abuse': '权限滥用',
            'js_bridge': 'JS Bridge', 'sms_receiver': '短信拦截',
            'background_tracking': '后台追踪', 'native_suspicious': 'Native 可疑',
            'crypto_usage': '加密使用', 'suspicious_assets': '可疑资源',
            'ad_heavy': '密集广告集成', 'ad_present': '存在广告',
            'string_sensitive_data': '字符串敏感数据',
            'resource_obfuscated': '资源混淆',
        }
        tag_desc = [tag_labels.get(t, t) for t in tags if t in tag_labels]

        return {
            'level': level,
            'score': score,
            'conclusion': conclusion,
            'risk_count': len(risks),
            'clue_summary': f'{high_count} 高危, {medium_count} 中危, {len(clues) - high_count - medium_count} 信息',
            'tags': tag_desc,
        }

    # ============================================================
    # 分析器13: 广告集成串关联
    # ============================================================
    @classmethod
    def _ad_integration(cls, **kw):
        clues, risks, tags = [], set(), set()
        ad_analysis = kw.get('ad_analysis')
        class_names = kw.get('class_names') or []
        permissions = kw.get('permissions') or []

        if not ad_analysis or 'error' in ad_analysis:
            return {'clues': clues, 'risks': risks, 'tags': tags}

        ad_summary = ad_analysis.get('summary', {})
        ad_level = ad_summary.get('level', '无广告')
        ad_score = ad_summary.get('score', 0)
        ad_sdk_count = ad_summary.get('ad_sdk_count', 0)

        if ad_level == '密集广告' or ad_score >= 60:
            ad_types = []
            if ad_summary.get('has_banner'): ad_types.append('Banner')
            if ad_summary.get('has_interstitial'): ad_types.append('插屏')
            if ad_summary.get('has_rewarded'): ad_types.append('激励视频')
            if ad_summary.get('has_native'): ad_types.append('原生')
            if ad_summary.get('has_mediation'): ad_types.append('聚合广告')

            clues.append({
                'type': 'heavy_ad', 'severity': 'medium',
                'title': '密集广告集成',
                'detail': f'{ad_sdk_count}个广告SDK, 等级{ad_level}({ad_score}/100), '
                          f'类型: {", ".join(ad_types) if ad_types else "未知"}',
                'cross_ref': [s['name'] for s in ad_analysis.get('ad_sdks', [])[:5]],
            })
            tags.add('ad_heavy')

            # 广告 + 过多危险权限 → 隐私风险
            perm_set = set(p.upper() for p in permissions)
            high_risk_ad_perms = {'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION',
                                  'READ_CONTACTS', 'READ_SMS', 'CAMERA', 'RECORD_AUDIO',
                                  'READ_EXTERNAL_STORAGE', 'GET_ACCOUNTS'}
            found_ad_risk = perm_set & high_risk_ad_perms
            if len(found_ad_risk) >= 3:
                clues.append({
                    'type': 'ad_privacy_risk', 'severity': 'high',
                    'title': '广告SDK过度收集隐私',
                    'detail': f'密集广告 + {len(found_ad_risk)}个敏感权限: '
                              f'{", ".join(sorted(found_ad_risk))}',
                    'cross_ref': sorted(found_ad_risk),
                })
                risks.add('AD_PRIVACY_OVERCOLLECT')
                tags.add('ad_privacy_risk')

        elif ad_level == '有广告' or ad_score >= 30:
            clues.append({
                'type': 'ad_present', 'severity': 'info',
                'title': '集成广告SDK',
                'detail': f'{ad_sdk_count}个广告SDK, 评分{ad_score}/100',
                'cross_ref': [s['name'] for s in ad_analysis.get('ad_sdks', [])[:3]],
            })
            tags.add('ad_present')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器14: 字符串敏感数据风险
    # ============================================================
    @classmethod
    def _string_risk(cls, **kw):
        clues, risks, tags = [], set(), set()
        string_analysis = kw.get('string_analysis')
        class_names = kw.get('class_names') or []

        if not string_analysis or 'error' in string_analysis:
            return {'clues': clues, 'risks': risks, 'tags': tags}

        s = string_analysis.get('summary', {})

        # 敏感信息
        if s.get('has_sensitive'):
            sensitive_count = s.get('sensitive_count', 0)
            private_ip_count = s.get('private_ip_count', 0)
            url_count = s.get('url_count', 0)
            base64_count = s.get('base64_count', 0)

            severity = 'high' if sensitive_count > 10 or private_ip_count > 3 else 'medium'
            clues.append({
                'type': 'string_sensitive', 'severity': severity,
                'title': '字符串含敏感数据',
                'detail': f'敏感信息{sensitive_count}项, 内网IP{private_ip_count}个, '
                          f'URL{url_count}个, Base64{base64_count}个',
                'cross_ref': ['sensitive_strings', 'private_ips', 'urls', 'base64'],
            })
            tags.add('string_sensitive_data')

            if sensitive_count > 20:
                risks.add('EXCESSIVE_SENSITIVE_STRINGS')

        # 硬编码密钥 (来自 string_analysis 或 key_scanner)
        if s.get('has_hardcoded_keys'):
            key_count = s.get('hardcoded_key_count', 0)
            clues.append({
                'type': 'hardcoded_keys', 'severity': 'high',
                'title': '硬编码密钥/凭证',
                'detail': f'发现 {key_count} 个硬编码密钥或凭证',
                'cross_ref': ['hardcoded_keys'],
            })
            risks.add('HARDCODED_CREDENTIALS')
            tags.add('hardcoded_credentials')

        return {'clues': clues, 'risks': risks, 'tags': tags}

    # ============================================================
    # 分析器15: 资源混淆串关联
    # ============================================================
    @classmethod
    def _resource_obfuscation_cross(cls, **kw):
        clues, risks, tags = [], set(), set()
        resource_obfuscation = kw.get('resource_obfuscation')
        packers = kw.get('packers') or []
        obfuscation_score = kw.get('obfuscation_score')

        if not resource_obfuscation or 'error' in resource_obfuscation:
            return {'clues': clues, 'risks': risks, 'tags': tags}

        ro = resource_obfuscation.get('summary', {})
        ro_score = ro.get('score', 0)
        ro_level = ro.get('level', '低')

        if ro_level == '高' or ro_score >= 60:
            ratio = ro.get('obfuscated_ratio', 0)
            clues.append({
                'type': 'resource_obfuscation', 'severity': 'medium',
                'title': '资源混淆',
                'detail': f'评分{ro_score}/100 ({ro_level}), 混淆率{ratio:.1%}',
                'cross_ref': [f'ratio={ratio:.2f}', f'score={ro_score}'],
            })
            tags.add('resource_obfuscated')

            # 资源混淆 + 代码混淆 + 加固 = 三重保护
            if packers and (obfuscation_score or 0) > 50:
                clues.append({
                    'type': 'triple_protection', 'severity': 'high',
                    'title': '三重保护: 加固+代码混淆+资源混淆',
                    'detail': f'加固壳({", ".join(packers)}) + 代码混淆({obfuscation_score}/100) '
                              f'+ 资源混淆({ro_score}/100)',
                    'cross_ref': ['packers', 'obfuscation', 'resource_obfuscation'],
                })
                risks.add('TRIPLE_PROTECTION')
                tags.add('triple_protection')

        return {'clues': clues, 'risks': risks, 'tags': tags}