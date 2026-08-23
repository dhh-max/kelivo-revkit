"""DEX 数据流分析器 - 寄存器追踪、污点分析、常量传播"""
import struct
from ..code_analyzer import CFGBuilder

class TaintTracker:
    """污点追踪引擎 - 追踪数据从来源到目的的传播路径"""

    # 污点来源
    TAINT_SOURCES = {
        'intent': ['Intent.getExtras', 'getStringExtra', 'getIntExtra', 'getBooleanExtra',
                    'getParcelableExtra', 'getSerializableExtra', 'getExtras'],
        'input_stream': ['InputStream.read', 'readBytes', 'readLine', 'BufferedReader.readLine'],
        'network': ['HttpURLConnection.getInputStream', 'OkHttpClient.newCall',
                     'Response.body', 'ResponseBody.string', 'getString'],
        'content_provider': ['ContentResolver.query', 'Cursor.getString',
                              'Cursor.getInt', 'Cursor.moveToNext'],
        'preferences': ['SharedPreferences.getString', 'SharedPreferences.getInt',
                         'SharedPreferences.getBoolean', 'SharedPreferences.getAll'],
        'telephony': ['TelephonyManager.getDeviceId', 'getImei', 'getMeid',
                      'getSubscriberId', 'getLine1Number', 'getSimSerialNumber',
                      'TelephonyManager.getCellLocation'],
        'system_service': ['getSystemService', 'getSharedPreferences'],
        'webview': ['WebView.getUrl', 'getOriginalUrl', 'evaluateJavascript'],
        'clipboard': ['ClipboardManager.getText', 'getPrimaryClip'],
        'file': ['FileInputStream.read', 'readBytes', 'FileReader.read'],
    }

    # 危险汇点
    TAINT_SINKS = {
        'exec': ['Runtime.exec', 'ProcessBuilder.start', 'ProcessBuilder.command'],
        'network_out': ['HttpURLConnection.getOutputStream', 'OutputStream.write',
                         'OkHttp.newCall', 'Response.execute'],
        'file_write': ['FileOutputStream.write', 'writeBytes', 'BufferedWriter.write'],
        'webview_load': ['WebView.loadUrl', 'loadDataWithBaseURL', 'loadData'],
        'sql_query': ['SQLiteDatabase.rawQuery', 'execSQL', 'SQLiteDatabase.query'],
        'intent_send': ['Intent.setComponent', 'setClassName', 'putExtra',
                        'startActivity', 'startService', 'sendBroadcast'],
        'log': ['Log.d', 'Log.e', 'Log.i', 'Log.v', 'Log.w', 'System.out.println'],
        'reflection': ['Method.invoke', 'Class.forName', 'getDeclaredMethod'],
        'dynamic_load': ['DexClassLoader.loadClass', 'loadDex', 'System.load', 'System.loadLibrary'],
    }

    def __init__(self):
        self.taint_map = {}  # register -> taint labels
        self.propagation_graph = []  # [{from, to, instruction, method}]

    def analyze_method(self, instructions, method_name='', strings=None, methods=None):
        """分析单个方法中的污点传播"""
        results = {
            'sources': [],
            'sinks': [],
            'propagations': [],
            'tainted_registers': set(),
        }

        # 扫描invoke指令
        for inst in instructions:
            if not hasattr(inst, 'opcode') or inst.opcode not in {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}:
                continue

            # 获取方法引用
            ref = inst.operands.get('ref', -1)
            method_name_str = ''
            if methods and 0 <= ref < len(methods):
                m = methods[ref]
                method_name_str = f"{m.get('name', '')}({m.get('proto', '')})" if isinstance(m, dict) else str(m)

            # 检查污点来源
            for source_cat, patterns in self.TAINT_SOURCES.items():
                for pat in patterns:
                    if pat.lower() in method_name_str.lower():
                        reg = inst.operands.get('vA', -1)
                        if reg >= 0:
                            self.taint_map[reg] = source_cat
                            results['tainted_registers'].add(reg)
                        results['sources'].append({
                            'address': inst.address,
                            'register': reg,
                            'category': source_cat,
                            'method': method_name_str,
                        })

            # 检查污点汇点
            for sink_cat, patterns in self.TAINT_SINKS.items():
                for pat in patterns:
                    if pat.lower() in method_name_str.lower():
                        regs = inst.operands.get('registers', [])
                        tainted_regs = [r for r in regs if r in self.taint_map]
                        results['sinks'].append({
                            'address': inst.address,
                            'registers': regs,
                            'tainted_registers': tainted_regs,
                            'category': sink_cat,
                            'method': method_name_str,
                            'severity': 'critical' if tainted_regs else 'info',
                        })

        # 追踪 move 指令中的传播
        for inst in instructions:
            if inst.opcode in {0x01, 0x02, 0x03, 0x07, 0x08, 0x09}:  # move/move-object
                vA = inst.operands.get('vA', -1)
                vB = inst.operands.get('vB', -1)
                if vB in self.taint_map:
                    self.taint_map[vA] = self.taint_map[vB]
                    results['propagations'].append({
                        'address': inst.address,
                        'from_reg': vB,
                        'to_reg': vA,
                        'taint': self.taint_map[vB],
                    })
                    results['tainted_registers'].add(vA)

        results['tainted_registers'] = sorted(results['tainted_registers'])
        return results


class DexDataFlowAnalyzer:
    """DEX 方法级数据流分析器"""

    def __init__(self, dex_parser=None):
        self.dp = dex_parser
        self.taint = TaintTracker()

    def analyze_method_dataflow(self, class_name, method_name=None):
        """分析指定类/方法的数据流"""
        if not self.dp:
            return {'error': '未提供 DEX 解析器'}

        self.dp._ensure_parsed()
        cls = self.dp.get_class_by_name(class_name)
        if not cls:
            return {'error': f'类未找到: {class_name}'}

        results = {
            'class': class_name,
            'methods': [],
        }

        methods = []
        if method_name:
            methods = [m for m in cls.get('direct_methods', []) + cls.get('virtual_methods', [])
                       if m.get('name') == method_name]
        else:
            methods = cls.get('direct_methods', []) + cls.get('virtual_methods', [])

        for m in methods:
            code = m.get('code')
            if not code:
                continue

            instructions = self._decode_instructions(code)
            if not instructions:
                continue

            taint_result = self.taint.analyze_method(
                instructions, m.get('name', ''),
                strings=self.dp.get_strings(),
                methods=self.dp.get_methods()
            )

            cfg = CFGBuilder.analyze_method(instructions)

            results['methods'].append({
                'method': m.get('name'),
                'access_flags': m.get('access_flags'),
                'registers': code.get('registers_size', 0),
                'instruction_count': len(instructions),
                'taint': taint_result,
                'cfg': {
                    'blocks': cfg.get('total_blocks', 0),
                    'edges': cfg.get('total_edges', 0),
                    'edge_types': cfg.get('edge_types', {}),
                },
            })

        return results

    def _decode_instructions(self, code_item):
        """从 code_item 解码指令"""
        from ...core.dex.instruction_decoder import InstructionDecoder
        insns_start = code_item.get('insns_start', 0)
        insns_size = code_item.get('insns_size', 0)
        if insns_start == 0 or insns_size == 0:
            return []

        data = self.dp.data
        insns_end = insns_start + insns_size * 2
        if insns_end > len(data):
            insns_end = len(data)

        instructions = []
        pos = insns_start
        while pos < insns_end:
            inst = InstructionDecoder.decode(data, pos)
            instructions.append(inst)
            pos += inst.size * 2

        return instructions

    def trace_register(self, class_name, method_name, target_reg):
        """追踪指定寄存器的所有读写位置"""
        if not self.dp:
            return {'error': '未提供 DEX 解析器'}

        self.dp._ensure_parsed()
        cls = self.dp.get_class_by_name(class_name)
        if not cls:
            return {'error': f'类未找到: {class_name}'}

        for m in cls.get('direct_methods', []) + cls.get('virtual_methods', []):
            if m.get('name') != method_name:
                continue
            code = m.get('code')
            if not code:
                continue

            instructions = self._decode_instructions(code)
            reads, writes = [], []

            for inst in instructions:
                ops = inst.operands
                # Check writes (vA is typically the destination)
                if ops.get('vA') == target_reg:
                    writes.append({
                        'address': inst.address,
                        'instruction': inst.name,
                        'operands': dict(ops),
                    })
                # Check reads
                for key in ['vB', 'vC']:
                    if ops.get(key) == target_reg:
                        reads.append({
                            'address': inst.address,
                            'instruction': inst.name,
                            'operands': dict(ops),
                        })
                # Check register lists
                regs = ops.get('registers', [])
                if target_reg in regs:
                    reads.append({
                        'address': inst.address,
                        'instruction': inst.name,
                        'operands': dict(ops),
                    })

            return {
                'register': target_reg,
                'reads': reads[:50],
                'writes': writes[:50],
                'read_count': len(reads),
                'write_count': len(writes),
            }

        return {'error': f'方法未找到: {method_name}'}

    def propagate_constants(self, class_name, method_name):
        """常量传播分析 - 追踪方法内所有常量值的流动"""
        if not self.dp:
            return {'error': '未提供 DEX 解析器'}

        self.dp._ensure_parsed()
        cls = self.dp.get_class_by_name(class_name)
        if not cls:
            return {'error': f'类未找到: {class_name}'}

        for m in cls.get('direct_methods', []) + cls.get('virtual_methods', []):
            if m.get('name') != method_name:
                continue
            code = m.get('code')
            if not code:
                continue

            instructions = self._decode_instructions(code)
            const_map = {}  # register -> constant value
            moves = []  # propagation chain

            for inst in instructions:
                ops = inst.operands
                # const instructions
                if inst.opcode == 0x12:  # const/4
                    reg = ops.get('vA', -1)
                    val = ops.get('litB', 0)
                    const_map[reg] = val
                    moves.append({'addr': inst.address, 'op': 'const/4', 'reg': reg, 'value': val})
                elif inst.opcode == 0x13:  # const/16
                    reg = ops.get('vA', -1)
                    val = ops.get('litB', 0)
                    const_map[reg] = val
                    moves.append({'addr': inst.address, 'op': 'const/16', 'reg': reg, 'value': val})
                elif inst.opcode == 0x14:  # const
                    reg = ops.get('vA', -1)
                    val = ops.get('litB', 0)
                    const_map[reg] = val
                    moves.append({'addr': inst.address, 'op': 'const', 'reg': reg, 'value': val})
                elif inst.opcode == 0x1a:  # const-string
                    reg = ops.get('vA', -1)
                    ref = ops.get('ref', -1)
                    strings = self.dp.get_strings()
                    val = strings[ref] if strings and 0 <= ref < len(strings) else f'string@{ref}'
                    const_map[reg] = val
                    moves.append({'addr': inst.address, 'op': 'const-string', 'reg': reg, 'value': val})
                # move instructions propagate constants
                elif inst.opcode in {0x01, 0x02, 0x03, 0x07, 0x08, 0x09}:
                    vA = ops.get('vA', -1)
                    vB = ops.get('vB', -1)
                    if vB in const_map:
                        const_map[vA] = const_map[vB]
                        moves.append({'addr': inst.address, 'op': 'move', 'from': vB, 'to': vA,
                                      'value': const_map[vB]})

            return {
                'constants': {str(k): v for k, v in const_map.items()},
                'propagation_chain': moves[:100],
                'total_constants': len(const_map),
            }

        return {'error': f'方法未找到: {method_name}'}
