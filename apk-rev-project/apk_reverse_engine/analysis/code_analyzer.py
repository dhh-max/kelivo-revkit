"""深度代码分析器 - DEX指令级静态分析、方法调用图、控制流分析"""
import re
from collections import defaultdict, Counter

class CodeAnalyzer:
    """深度代码分析引擎：支持多种层次的分析"""
    
    # ── API密钥/凭证模式 ──────────────────────────────────────
    API_KEY_PATTERNS = [
        (r"""(?i)(?:api[_-]?key|apikey|secret|token|password|passwd|bearer|auth|access_key|private_key)\s*[:=]\s*["'\x60]([^"'\x60]+)["'\x60]""", 'Credentials'),
        (r'(?i)AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
        (r'(?i)sk-[0-9a-zA-Z]{32,}', 'OpenAI API Key'),
        (r'(?i)ghp_[0-9a-zA-Z]{36}', 'GitHub Token'),
        (r'(?i)AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'Private Key'),
        (r'(?i)-----BEGIN CERTIFICATE-----', 'Certificate'),
        (r'(?i)ghr_[0-9a-zA-Z]{36}', 'GitHub Refresh Token'),
        (r'(?i)github_pat_[0-9a-zA-Z_]{36,}', 'GitHub Fine-grained Token'),
        (r'(?i)xox[baprs]-[0-9a-zA-Z-]{24,}', 'Slack Token'),
        (r'(?i)sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Key'),
        (r'(?i)pk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Publishable Key'),
        (r'(?i)SG\.[0-9a-zA-Z_-]{22,}', 'SendGrid API Key'),
        (r'(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key'),
        (r'(?i)-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----', 'SSH Private Key'),
        (r'(?i)AAAA[0-9A-Za-z+/]{32,}={0,2}', 'Generic Base64 Key'),
    ]

    # ── 敏感API调用模式 ────────────────────────────────────────
    SENSITIVE_API_CALLS = {
        'location': [
            r'getLastKnownLocation', r'requestLocationUpdates', r'getLatitude',
            r'getLongitude', r'LocationManager', r'FusedLocationApi',
            r'getCurrentLocation', r'addProximityAlert',
        ],
        'camera': [
            r'Camera\.open', r'CameraManager', r'MediaRecorder',
            r'camera\.open', r'openCamera', r'Camera2',
        ],
        'microphone': [
            r'MediaRecorder\.AudioSource', r'startRecording',
            r'audioRecord', r'getAudioSource', r'captureAudio',
        ],
        'contacts': [
            r'ContactsContract', r'getContentResolver', r'query.*Contacts',
            r'READ_CONTACTS', r'getContactList',
        ],
        'sms': [
            r'SmsManager', r'sendTextMessage', r'sendMultipartTextMessage',
            r'Telephony\.Sms', r'READ_SMS', r'RECEIVE_SMS',
        ],
        'phone': [
            r'TelephonyManager', r'getDeviceId', r'getImei', r'getMeid',
            r'getSubscriberId', r'getLine1Number', r'getSimSerialNumber',
        ],
        'file_io': [
            r'FileOutputStream', r'FileInputStream', r'BufferedWriter',
            r'openFileOutput', r'getFilesDir', r'getExternalFilesDir',
            r'Environment\.getExternalStorage', r'WRITE_EXTERNAL_STORAGE',
        ],
        'network': [
            r'HttpURLConnection', r'OkHttpClient', r'Retrofit',
            r'Volley', r'AsyncHttpClient', r'WebSocket',
            r'Socket\(', r'ServerSocket', r'DatagramSocket',
        ],
        'crypto': [
            r'Cipher\.getInstance', r'SecretKeySpec', r'KeyGenerator',
            r'KeyPairGenerator', r'MessageDigest', r'Mac\.getInstance',
            r'Signature\.getInstance', r'KeyStore', r'KeyManagerFactory',
        ],
        'webview': [
            r'WebView', r'loadUrl', r'addJavascriptInterface',
            r'setJavaScriptEnabled', r'WebChromeClient', r'WebViewClient',
        ],
        'reflection': [
            r'Class\.forName', r'Method\.invoke', r'Field\.setAccessible',
            r'getDeclaredMethod', r'getDeclaredField', r'setAccessible',
            r'java\.lang\.reflect\.', r'DexClassLoader',
        ],
        'dynamic_code': [
            r'DexClassLoader', r'PathClassLoader', r'InMemoryDexClassLoader',
            r'loadDex', r'openDexFile', r'Runtime\.exec', r'ProcessBuilder',
            r'Runtime\.loadLibrary', r'System\.load',
        ],
    }

    # ── 危险API调用 ────────────────────────────────────────────
    DANGEROUS_API_CALLS = [
        (r'Runtime\.exec\s*\(', '命令执行'),
        (r'ProcessBuilder\s*\(', '命令执行'),
        (r'loadUrl\s*\(', 'WebView加载'),
        (r'addJavascriptInterface\s*\(', 'JS桥接'),
        (r'setJavaScriptEnabled\s*\(true\)', '启用JS'),
        (r'Cipher\.getInstance\s*\(\s*"(?:DES|RC4|MD5|SHA1)', '弱加密算法'),
        (r'SecretKeySpec\s*\([^,]+,\s*"(?:DES|RC4|AES/ECB)', '弱加密模式'),
        (r'HttpURLConnection\s*\([^)]*\)[^;]*setHostnameVerifier\s*\([^)]*AllowAll', '弱TLS验证'),
        (r'SSLSocketFactory\.getAllTrusted', '弱TLS验证'),
        (r'TrustManager[^}]*checkServerTrusted[^}]*\{[^}]*\}', '空TrustManager'),
        (r'HostnameVerifier[^}]*verify[^}]*\{[^}]*\}', '空HostnameVerifier'),
        (r'PROXY[^)]*\)[^;]*', '代理设置'),
        (r'SQLiteDatabase\.rawQuery\s*\(', 'SQL查询'),
        (r'execSQL\s*\(', 'SQL执行'),
        (r'openOrCreateDatabase\s*\(', '数据库操作'),
        (r'getSharedPreferences\s*\(', 'SharedPreferences'),
        (r'Log\.(?:d|e|i|v|w)\s*\(', '日志输出'),
        (r'System\.out\.println\s*\(', '控制台输出'),
        (r'printStackTrace\s*\(', '异常堆栈输出'),
        (r'android\.util\.Log', 'Log类引用'),
        (r'Toast\.makeText', 'Toast提示'),
        (r'NotificationManager', '通知管理'),
        (r'Vibrator', '振动器'),
        (r'BluetoothAdapter', '蓝牙'),
        (r'WifiManager', 'WiFi'),
        (r'NfcAdapter', 'NFC'),
        (r'UsbManager', 'USB'),
        (r'MediaPlayer', '媒体播放'),
        (r'AudioRecord', '录音'),
        (r'Camera\.open', '相机'),
        (r'BiometricPrompt', '生物识别'),
        (r'FingerprintManager', '指纹'),
        (r'AccountManager', '账户管理'),
        (r'ContentResolver\.query', 'ContentResolver查询'),
        (r'ContentValues', 'ContentValues'),
        (r'Intent\.(?:getExtras|putExtra|getStringExtra)', 'Intent数据传递'),
        (r'PendingIntent', 'PendingIntent'),
        (r'BroadcastReceiver', '广播接收'),
        (r'JobScheduler', 'JobScheduler'),
        (r'WorkManager', 'WorkManager'),
        (r'FirebaseAnalytics', 'Firebase分析'),
        (r'FirebaseMessaging', 'Firebase消息'),
        (r'Crashlytics', 'Crashlytics'),
        (r'Branch\.io', 'Branch'),
        (r'Adjust', 'Adjust'),
        (r'AppsFlyer', 'AppsFlyer'),
        (r'FacebookSdk', 'Facebook SDK'),
        (r'GoogleApiClient', 'Google API'),
    ]

    @staticmethod
    def find_urls(text):
        return list(set(re.findall("https?://[^\\s\"'<>]+", text)))

    @staticmethod
    def find_ips(text):
        return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))

    @staticmethod
    def find_emails(text):
        return list(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)))

    @staticmethod
    def find_api_keys(text):
        """查找API密钥和凭证"""
        keys = []
        for pat, cat in CodeAnalyzer.API_KEY_PATTERNS:
            for m in re.finditer(pat, text):
                keys.append({
                    'category': cat,
                    'value': m.group(1) if m.lastindex else m.group(0),
                    'match': m.group(0)[:100],
                })
        return keys

    @staticmethod
    def find_class_refs(text):
        return list(set(re.findall(r'L[\w/$;]+', text)))

    @staticmethod
    def find_domains(text):
        urls = CodeAnalyzer.find_urls(text)
        domains = []
        for u in urls:
            m = re.search("https?://([^/\\s\"'<>:]+)", u)
            if m:
                domains.append(m.group(1))
        return list(set(domains))

    @staticmethod
    def detect_sensitive_apis(text):
        """检测敏感API调用，按类别分组"""
        results = defaultdict(list)
        for category, patterns in CodeAnalyzer.SENSITIVE_API_CALLS.items():
            for pat in patterns:
                matches = re.findall(pat, text, re.IGNORECASE)
                if matches:
                    results[category].append({'pattern': pat, 'count': len(matches)})
        return dict(results)

    @staticmethod
    def detect_dangerous_apis(text):
        """检测危险/可疑API调用"""
        findings = []
        for pat, desc in CodeAnalyzer.DANGEROUS_API_CALLS:
            matches = re.findall(pat, text, re.IGNORECASE)
            if matches:
                findings.append({
                    'description': desc,
                    'pattern': pat,
                    'count': len(matches),
                    'severity': 'high' if desc in ['命令执行', '弱TLS验证', '空TrustManager', '弱加密算法'] else 'medium',
                })
        return findings

    @staticmethod
    def analyze_all(text):
        """一站式全面代码分析"""
        return {
            'urls': CodeAnalyzer.find_urls(text),
            'ips': CodeAnalyzer.find_ips(text),
            'emails': CodeAnalyzer.find_emails(text),
            'api_keys': CodeAnalyzer.find_api_keys(text),
            'class_refs': CodeAnalyzer.find_class_refs(text),
            'domains': CodeAnalyzer.find_domains(text),
            'sensitive_apis': CodeAnalyzer.detect_sensitive_apis(text),
            'dangerous_apis': CodeAnalyzer.detect_dangerous_apis(text),
        }

    @staticmethod
    def analyze_danger_summary(text):
        """生成危险调用摘要"""
        dangerous = CodeAnalyzer.detect_dangerous_apis(text)
        sensitive = CodeAnalyzer.detect_sensitive_apis(text)
        
        high_risk = [d for d in dangerous if d['severity'] == 'high']
        medium_risk = [d for d in dangerous if d['severity'] == 'medium']
        
        return {
            'dangerous_api_count': len(dangerous),
            'high_risk_count': len(high_risk),
            'medium_risk_count': len(medium_risk),
            'high_risk_items': high_risk[:10],
            'medium_risk_items': medium_risk[:10],
            'sensitive_categories': list(sensitive.keys()),
            'total_sensitive_api_calls': sum(
                sum(m['count'] for m in matches) for matches in sensitive.values()
            ) if sensitive else 0,
        }


class CFGBuilder:
    """DEX指令控制流图构建器"""
    
    @staticmethod
    def build_basic_blocks(instructions):
        """将指令列表分割为基本块"""
        if not instructions:
            return []
        
        # 标记领导者（leader）指令
        leaders = set()
        leaders.add(0)  # 第一条指令是领导者
        
        for i, inst in enumerate(instructions):
            opcode = inst.opcode
            # 分支指令的目标是领导者
            if opcode in {0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d}:
                offset = inst.operands.get('offset', 0)
                target_idx = None
                target_addr = inst.address + offset
                # 查找目标地址对应的索引
                for j, inst2 in enumerate(instructions):
                    if inst2.address == target_addr:
                        target_idx = j
                        break
                if target_idx is not None:
                    leaders.add(target_idx)
                # 分支指令的下一条也是领导者
                if i + 1 < len(instructions):
                    leaders.add(i + 1)
            # return/throw 指令的下一条是领导者
            elif opcode in {0x0e, 0x0f, 0x10, 0x11, 0x27}:
                if i + 1 < len(instructions):
                    leaders.add(i + 1)

        # 分割基本块
        blocks = []
        sorted_leaders = sorted(leaders)
        for idx, start in enumerate(sorted_leaders):
            end = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else len(instructions)
            block_instructions = instructions[start:end]
            if block_instructions:
                blocks.append({
                    'start_idx': start,
                    'end_idx': end - 1,
                    'start_addr': block_instructions[0].address,
                    'end_addr': block_instructions[-1].address,
                    'instructions': block_instructions,
                    'size': len(block_instructions),
                })

        return blocks

    @staticmethod
    def build_cfg(blocks):
        """构建基本块之间的控制流边"""
        edges = []
        for i, block in enumerate(blocks):
            last_inst = block['instructions'][-1]
            opcode = last_inst.opcode
            
            if opcode in {0x0e, 0x0f, 0x10, 0x11}:  # return
                edges.append({'from': i, 'to': None, 'type': 'return'})
            elif opcode == 0x27:  # throw
                edges.append({'from': i, 'to': None, 'type': 'throw'})
            elif opcode in {0x28, 0x29, 0x2a}:  # goto
                offset = last_inst.operands.get('offset', 0)
                target_addr = last_inst.address + offset
                target_block = None
                for j, b in enumerate(blocks):
                    if b['start_addr'] <= target_addr <= b['end_addr']:
                        target_block = j
                        break
                if target_block is not None:
                    edges.append({'from': i, 'to': target_block, 'type': 'unconditional'})
            elif opcode in {0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d}:  # if-*z
                offset = last_inst.operands.get('offset', 0)
                target_addr = last_inst.address + offset
                target_block = None
                for j, b in enumerate(blocks):
                    if b['start_addr'] <= target_addr <= b['end_addr']:
                        target_block = j
                        break
                if target_block is not None:
                    edges.append({'from': i, 'to': target_block, 'type': 'conditional'})
                # 下一条指令（fall-through）
                if i + 1 < len(blocks):
                    edges.append({'from': i, 'to': i + 1, 'type': 'fallthrough'})
            elif opcode in {0x2b, 0x2c}:  # switch
                edges.append({'from': i, 'to': i + 1, 'type': 'fallthrough'}) if i + 1 < len(blocks) else None
            else:
                # 无条件顺序执行
                if i + 1 < len(blocks):
                    edges.append({'from': i, 'to': i + 1, 'type': 'sequential'})

        return edges

    @staticmethod
    def analyze_method(instructions):
        """完整分析方法：指令统计 + 基本块 + CFG"""
        if not instructions:
            return {'error': 'no instructions'}

        blocks = CFGBuilder.build_basic_blocks(instructions)
        edges = CFGBuilder.build_cfg(blocks)

        stats = {
            'total_instructions': len(instructions),
            'total_blocks': len(blocks),
            'total_edges': len(edges),
            'block_sizes': [b['size'] for b in blocks],
            'avg_block_size': round(sum(b['size'] for b in blocks) / len(blocks), 2) if blocks else 0,
            'max_block_size': max(b['size'] for b in blocks) if blocks else 0,
            'min_block_size': min(b['size'] for b in blocks) if blocks else 0,
            'edge_types': dict(Counter(e['type'] for e in edges)),
            'instructions': [],
            'blocks': [{'id': i, 'start_addr': hex(b['start_addr']), 
                        'end_addr': hex(b['end_addr']), 'size': b['size']} 
                       for i, b in enumerate(blocks)],
            'edges': edges,
        }

        # 指令级统计
        opcode_counts = Counter(inst.opcode for inst in instructions)
        stats['opcode_counts'] = dict(opcode_counts)
        stats['unique_opcodes'] = len(opcode_counts)

        return stats

    @staticmethod
    def format_cfg_text(blocks, edges):
        """将CFG格式化为文本"""
        lines = []
        lines.append(f"CFG: {len(blocks)} blocks, {len(edges)} edges")
        lines.append("")
        
        for i, block in enumerate(blocks):
            lines.append(f"BB{i} (0x{block['start_addr']:x}-0x{block['end_addr']:x}, {block['size']} ins):")
            for inst in block['instructions']:
                lines.append(f"  {inst.address:04x}: {inst.name} {inst.operands}")
            
            # 输出边
            out_edges = [e for e in edges if e['from'] == i]
            if out_edges:
                for e in out_edges:
                    if e['to'] is not None:
                        lines.append(f"  -> BB{e['to']} [{e['type']}]")
                    else:
                        lines.append(f"  -> [end] [{e['type']}]")
            lines.append("")
        
        return '\n'.join(lines)


class MethodAnalyzer:
    """DEX方法深度分析器"""
    
    @staticmethod
    def classify_method(method_name, instructions):
        """根据指令特征分类方法"""
        if not instructions:
            return 'unknown'
        
        opcodes = [inst.opcode for inst in instructions]
        
        # 初始化方法
        if method_name == '<init>':
            return 'constructor'
        if method_name == '<clinit>':
            return 'static_initializer'
        
        # Getter/Setter
        if len(instructions) <= 3:
            if any(op in {0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66} for op in opcodes):
                return 'getter'
            if any(op in {0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d} for op in opcodes):
                return 'setter'
            return 'simple'
        
        # 加密方法
        crypto_ops = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
                      0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                      0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}
        if sum(1 for op in opcodes if op in crypto_ops) > 5:
            return 'crypto_calculation'
        
        # 大量const-string = 字符串处理
        const_strings = sum(1 for op in opcodes if op in {0x1a, 0x1b})
        if const_strings > 10:
            return 'string_processing'
        
        # 网络请求
        invoke_ops = [i for i in range(len(instructions)) if instructions[i].opcode in {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}]
        if len(invoke_ops) > 5:
            return 'heavy_invoke'
        
        # 大量分支
        branch_ops = {0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d}
        branches = sum(1 for op in opcodes if op in branch_ops)
        if branches > 10:
            return 'complex_branching'
        
        if len(instructions) > 100:
            return 'large_method'
        
        return 'normal'

    @staticmethod
    def analyze_method_summary(instructions):
        """分析方法摘要"""
        if not instructions:
            return {}
        
        opcodes = [inst.opcode for inst in instructions]
        
        invoke_count = sum(1 for op in opcodes if op in {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78})
        field_count = sum(1 for op in opcodes if op in {0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d})
        const_count = sum(1 for op in opcodes if op in {0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c})
        return_count = sum(1 for op in opcodes if op in {0x0e, 0x0f, 0x10, 0x11})
        branch_count = sum(1 for op in opcodes if op in {0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d})
        new_count = sum(1 for op in opcodes if op in {0x22, 0x23, 0x24, 0x25})
        
        return {
            'total_instructions': len(instructions),
            'invoke_count': invoke_count,
            'field_access_count': field_count,
            'const_count': const_count,
            'return_count': return_count,
            'branch_count': branch_count,
            'new_instance_count': new_count,
            'complexity_score': invoke_count * 2 + branch_count * 3 + field_count + const_count,
        }


# ── 快捷函数 ──────────────────────────────────────────────────
def analyze_code(text):
    """一站式代码分析"""
    return CodeAnalyzer.analyze_all(text)

def analyze_danger_summary(text):
    """危险调用摘要"""
    return CodeAnalyzer.analyze_danger_summary(text)

def build_cfg(instructions):
    """构建控制流图"""
    return CFGBuilder.analyze_method(instructions)

def analyze_method(instructions):
    """分析方法指令"""
    return MethodAnalyzer.analyze_method_summary(instructions)
