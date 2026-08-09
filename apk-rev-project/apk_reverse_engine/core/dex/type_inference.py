"""DEX 类型推断引擎

为 DEX 方法级提供基于数据流的类型推断：
- 寄存器类型推断：根据 const/new-instance/iget 等指令推断寄存器类型
- 类型传播：move 指令传播类型，invoke 传播返回类型
- 类型一致性检查：检测类型不匹配的指令
- 精确类型 vs 宽松类型推断
"""
from collections import defaultdict


# Dalvik 类型分类
TYPE_UNKNOWN = 'unknown'
TYPE_NULL = 'null'
TYPE_INT = 'int'
TYPE_FLOAT = 'float'
TYPE_LONG = 'long'
TYPE_DOUBLE = 'double'
TYPE_OBJECT = 'object'
TYPE_ARRAY = 'array'
TYPE_STRING = 'java/lang/String'
TYPE_BOOLEAN = 'boolean'
TYPE_BYTE = 'byte'
TYPE_CHAR = 'char'
TYPE_SHORT = 'short'

# const 指令到类型的映射
CONST_TYPE_MAP = {
    0x12: TYPE_INT,      # const/4
    0x13: TYPE_INT,      # const/16
    0x14: TYPE_INT,      # const
    0x15: TYPE_INT,      # const/high16
    0x16: TYPE_INT,      # const-wide/16
    0x17: TYPE_INT,      # const-wide/16 (actually long)
    0x18: TYPE_LONG,     # const-wide
    0x19: TYPE_LONG,     # const-wide/high16
    0x1a: TYPE_STRING,   # const-string
    0x1b: TYPE_STRING,   # const-string/jumbo
    0x1c: TYPE_INT,      # const-class -> Class object
}

# 宽类型：long/double 占两个寄存器
WIDE_TYPES = {TYPE_LONG, TYPE_DOUBLE}

# iget 指令推断的类型前缀映射
IGET_TYPE_MAP = {
    0x52: (TYPE_OBJECT, 'Ljava/'),   # iget-object
    0x53: (TYPE_BOOLEAN, 'Z'),        # iget-boolean
    0x54: (TYPE_BYTE, 'B'),           # iget-byte
    0x55: (TYPE_CHAR, 'C'),           # iget-char
    0x56: (TYPE_SHORT, 'S'),          # iget-short
    0x57: (TYPE_INT, 'I'),            # iget
    0x58: (TYPE_INT, 'I'),            # iget-wide (long/double)
}

# aget 指令推断的类型映射
AGET_TYPE_MAP = {
    0x44: TYPE_INT,      # aget
    0x45: TYPE_LONG,     # aget-wide
    0x46: TYPE_OBJECT,   # aget-object
    0x47: TYPE_BOOLEAN,  # aget-boolean
    0x48: (TYPE_BYTE, 'B'),           # iget-byte
    0x49: TYPE_CHAR,     # aget-char
    0x4a: TYPE_SHORT,    # aget-short
}

# unary 运算类型映射
UNARY_TYPE_MAP = {
    0x7b: TYPE_INT,      # neg-int
    0x7c: TYPE_INT,      # not-int
    0x7d: TYPE_LONG,     # neg-long
    0x7e: TYPE_LONG,     # not-long
    0x7f: TYPE_FLOAT,    # neg-float
    0x80: TYPE_DOUBLE,   # neg-double
    0x81: TYPE_INT,      # int-to-byte
    0x82: TYPE_INT,      # int-to-char
    0x83: TYPE_INT,      # int-to-short
    0x84: TYPE_INT,      # long-to-int
    0x85: TYPE_FLOAT,    # long-to-float
    0x86: TYPE_DOUBLE,   # long-to-double
    0x87: TYPE_INT,      # float-to-int
    0x88: TYPE_LONG,     # float-to-long
    0x89: TYPE_DOUBLE,   # float-to-double
    0x8a: TYPE_INT,      # double-to-int
    0x8b: TYPE_LONG,     # double-to-long
    0x8c: TYPE_FLOAT,    # double-to-float
    0x8d: TYPE_INT,      # int-to-float
    0x8e: TYPE_INT,      # int-to-long (actually long)
    0x8f: TYPE_FLOAT,    # int-to-double (actually double)
}


class TypeInference:
    """寄存器类型推断引擎

    使用前向数据流分析推断每个程序点寄存器的类型。
    支持精确类型（如 java/lang/String）和类别类型（如 object/int/float）。
    """

    @staticmethod
    def infer_method(instructions, cfg=None, strings=None, types=None, fields=None, methods=None):
        """推断方法内所有寄存器在每个程序点的类型。

        Args:
            instructions: Instruction 列表
            cfg: 预构建 CFG（可选）
            strings: DEX 字符串池
            types: DEX 类型描述符列表
            fields: DEX 字段列表
            methods: DEX 方法列表

        Returns:
            dict: {
                'register_types': {inst_addr: {reg: type_str}},
                'type_changes': [{addr, reg, old_type, new_type, instruction}],
                'inconsistencies': [{addr, reg, expected, actual, instruction}],
                'parameter_types': {reg: type_str},
                'wide_registers': set of reg,  # long/double 占用的寄存器对
            }
        """
        if not instructions:
            return {
                'register_types': {}, 'type_changes': [],
                'inconsistencies': [], 'parameter_types': {},
                'wide_registers': set(),
            }

        if cfg is None:
            from .disassembler import Disassembler
            cfg = Disassembler.build_cfg(instructions)

        # 类型环境：每个基本块入口的寄存器类型映射
        # reg -> type_str
        block_in = {blk['start']: {} for blk in cfg['blocks']}
        block_out = {blk['start']: {} for blk in cfg['blocks']}

        # 迭代直到不动点
        changed = True
        iteration = 0
        max_iter = 100

        while changed and iteration < max_iter:
            changed = False
            iteration += 1

            for blk in cfg['blocks']:
                bs = blk['start']

                # 合并前驱的 OUT
                new_in = {}
                preds = blk['predecessors']
                if not preds and bs == cfg.get('entry'):
                    new_in = {}  # 入口块
                else:
                    for p in preds:
                        p_out = block_out.get(p, {})
                        for reg, t in p_out.items():
                            if reg in new_in:
                                # 类型交汇：如果不同则降级为 unknown
                                if new_in[reg] != t:
                                    new_in[reg] = TYPE_UNKNOWN
                            else:
                                new_in[reg] = t

                if new_in != block_in[bs]:
                    block_in[bs] = new_in
                    changed = True

                # 在块内顺序执行类型推断
                env = dict(new_in)
                for inst in blk['instructions']:
                    TypeInference._infer_instruction(inst, env, strings, types, fields, methods)

                block_out[bs] = dict(env)

        # 收集每个程序点的类型快照
        register_types = {}
        type_changes = []
        wide_registers = set()

        for blk in cfg['blocks']:
            env = dict(block_in[blk['start']])
            for inst in blk['instructions']:
                old_env = dict(env)
                TypeInference._infer_instruction(inst, env, strings, types, fields, methods)
                # 记录类型变化
                for reg in set(old_env.keys()) | set(env.keys()):
                    old_t = old_env.get(reg, TYPE_UNKNOWN)
                    new_t = env.get(reg, TYPE_UNKNOWN)
                    if old_t != new_t:
                        type_changes.append({
                            'addr': inst.address,
                            'reg': reg,
                            'old_type': old_t,
                            'new_type': new_t,
                            'instruction': inst.name,
                        })
                register_types[inst.address] = dict(env)
                # 检测 wide 寄存器
                for reg, t in env.items():
                    if t in WIDE_TYPES:
                        wide_registers.add(reg)
                        wide_registers.add(reg + 1)

        # 类型一致性检查
        inconsistencies = TypeInference._check_consistency(instructions, register_types, strings, types, fields, methods)

        return {
            'register_types': register_types,
            'type_changes': type_changes,
            'inconsistencies': inconsistencies,
            'parameter_types': block_in.get(cfg.get('entry', -1), {}),
            'wide_registers': sorted(wide_registers),
        }

    @staticmethod
    def _infer_instruction(inst, env, strings=None, types=None, fields=None, methods=None):
        """根据单条指令更新类型环境"""
        op = inst.opcode
        ops = inst.operands

        # const 类指令
        if op in CONST_TYPE_MAP:
            reg = ops.get('vA', -1)
            if reg >= 0:
                t = CONST_TYPE_MAP[op]
                if op == 0x1c:
                    t = 'java/lang/Class'
                if op in (0x16, 0x17, 0x18, 0x19):
                    t = TYPE_LONG  # const-wide 都是 long/double
                env[reg] = t
                if t in WIDE_TYPES:
                    env[reg + 1] = t
            return

        # move 类指令：传播类型
        if op in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09):
            vA = ops.get('vA', -1)
            vB = ops.get('vB', -1)
            if vA >= 0 and vB >= 0:
                src_type = env.get(vB, TYPE_UNKNOWN)
                env[vA] = src_type
                if src_type in WIDE_TYPES:
                    env[vA + 1] = src_type
            return

        # move-result：从 invoke 的返回类型推断
        if op in (0x0a, 0x0b, 0x0c):
            vA = ops.get('vA', -1)
            if vA >= 0:
                # move-result 类型取决于前一条 invoke 的返回值
                # 标记为 unknown，需要结合上下文
                if op == 0x0b:
                    env[vA] = TYPE_LONG
                    env[vA + 1] = TYPE_LONG
                elif op == 0x0c:
                    env[vA] = TYPE_OBJECT
                else:
                    env[vA] = TYPE_UNKNOWN
            return

        # move-exception
        if op == 0x0d:
            vA = ops.get('vA', -1)
            if vA >= 0:
                env[vA] = TYPE_OBJECT  # Throwable
            return

        # iget 系列
        if op in (0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58):
            vA = ops.get('vA', -1)
            if vA >= 0:
                field_idx = ops.get('field_idx', ops.get('ref', -1))
                if fields and 0 <= field_idx < len(fields):
                    field_info = fields[field_idx]
                    desc = field_info.get('type_desc', field_info.get('type', ''))
                    t = TypeInference._desc_to_type(desc)
                    env[vA] = t
                    if t in WIDE_TYPES:
                        env[vA + 1] = t
                else:
                    type_info = IGET_TYPE_MAP.get(op, (TYPE_UNKNOWN, ''))
                    env[vA] = type_info[0] if isinstance(type_info, tuple) else type_info
            return

        # aget 系列
        if op in (0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a):
            vA = ops.get('vA', -1)
            if vA >= 0:
                t = AGET_TYPE_MAP.get(op, TYPE_UNKNOWN)
                env[vA] = t
                if t in WIDE_TYPES:
                    env[vA + 1] = t
            return

        # sget 系列
        if op in (0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66):
            vA = ops.get('vA', -1)
            if vA >= 0:
                field_idx = ops.get('field_idx', ops.get('ref', -1))
                if fields and 0 <= field_idx < len(fields):
                    field_info = fields[field_idx]
                    desc = field_info.get('type_desc', field_info.get('type', ''))
                    t = TypeInference._desc_to_type(desc)
                    env[vA] = t
                    if t in WIDE_TYPES:
                        env[vA + 1] = t
                else:
                    env[vA] = TYPE_OBJECT if op == 0x62 else TYPE_INT
            return

        # new-instance
        if op == 0x22:
            vA = ops.get('vA', -1)
            type_idx = ops.get('type_idx', ops.get('ref', -1))
            if vA >= 0:
                if types and 0 <= type_idx < len(types):
                    env[vA] = types[type_idx]
                else:
                    env[vA] = TYPE_OBJECT
            return

        # new-array
        if op == 0x23:
            vA = ops.get('vA', -1)
            type_idx = ops.get('type_idx', ops.get('ref', -1))
            if vA >= 0:
                if types and 0 <= type_idx < len(types):
                    env[vA] = types[type_idx]  # 数组类型描述符如 [I
                else:
                    env[vA] = TYPE_ARRAY
            return

        # check-cast
        if op == 0x1f:
            vA = ops.get('vA', -1)
            type_idx = ops.get('type_idx', ops.get('ref', -1))
            if vA >= 0:
                if types and 0 <= type_idx < len(types):
                    env[vA] = types[type_idx]
            return

        # instance-of
        if op == 0x20:
            vA = ops.get('vA', -1)
            if vA >= 0:
                env[vA] = TYPE_BOOLEAN
            return

        # array-length
        if op == 0x21:
            vA = ops.get('vA', -1)
            if vA >= 0:
                env[vA] = TYPE_INT
            return

        # unary 运算
        if op in UNARY_TYPE_MAP:
            vA = ops.get('vA', -1)
            if vA >= 0:
                t = UNARY_TYPE_MAP[op]
                env[vA] = t
                if t in WIDE_TYPES:
                    env[vA + 1] = t
            return

        # 二元运算：结果类型取决于操作数
        if op in range(0x90, 0xb0) or op in range(0xb0, 0xd0) or op in range(0xd0, 0xe3):
            vA = ops.get('vA', -1)
            if vA >= 0:
                # int 运算默认 int，long 运算默认 long
                if op in range(0x97, 0x9d) or op in range(0xb7, 0xbd) or op in range(0xd7, 0xdd):
                    env[vA] = TYPE_LONG
                    env[vA + 1] = TYPE_LONG
                elif op in range(0xa7, 0xab) or op in range(0xab, 0xaf) or op in range(0xd7, 0xdb):
                    env[vA] = TYPE_FLOAT
                elif op in range(0xab, 0xaf) or op in range(0xbb, 0xbf):
                    env[vA] = TYPE_DOUBLE
                    env[vA + 1] = TYPE_DOUBLE
                else:
                    env[vA] = TYPE_INT
            return

        # cmp
        if op in (0x2d, 0x2e, 0x2f, 0x30, 0x31):
            vA = ops.get('vA', -1)
            if vA >= 0:
                env[vA] = TYPE_INT
            return

        # filled-new-array
        if op in (0x24, 0x25):
            type_idx = ops.get('type_idx', ops.get('ref', -1))
            if types and 0 <= type_idx < len(types):
                # 结果在 result 寄存器（move-result-object 获取）
                pass
            return

        # const-class
        if op == 0x1c:
            vA = ops.get('vA', -1)
            if vA >= 0:
                env[vA] = 'java/lang/Class'
            return

        # const 操作 null
        if op == 0x0e:  # const/4 vA, #0 -> 可能是 null
            vA = ops.get('vA', -1)
            lit = ops.get('litB', ops.get('lit', 0))
            if vA >= 0 and lit == 0:
                # const/4 v0, #0 常用于设置 null
                # 不确定是 int 0 还是 null，保持 unknown
                env[vA] = TYPE_UNKNOWN
            return

    @staticmethod
    def _desc_to_type(desc):
        """将类型描述符转换为推断类型"""
        if not desc:
            return TYPE_UNKNOWN
        if desc == 'I':
            return TYPE_INT
        elif desc == 'F':
            return TYPE_FLOAT
        elif desc == 'J':
            return TYPE_LONG
        elif desc == 'D':
            return TYPE_DOUBLE
        elif desc == 'Z':
            return TYPE_BOOLEAN
        elif desc == 'B':
            return TYPE_BYTE
        elif desc == 'C':
            return TYPE_CHAR
        elif desc == 'S':
            return TYPE_SHORT
        elif desc == 'V':
            return 'void'
        elif desc.startswith('['):
            return TYPE_ARRAY
        elif desc.startswith('Ljava/lang/String'):
            return TYPE_STRING
        elif desc.startswith('L'):
            return desc[1:-1]  # 去掉 L 和 ;
        return TYPE_OBJECT

    @staticmethod
    def _check_consistency(instructions, register_types, strings=None, types=None, fields=None, methods=None):
        """检查类型不一致问题"""
        inconsistencies = []

        for inst in instructions:
            op = inst.opcode
            ops = inst.operands
            addr = inst.address
            env = register_types.get(addr, {})

            # move-wide: 源应该是 wide 类型
            if op in (0x04, 0x05, 0x06):  # move-wide/from16, move-wide/16
                vB = ops.get('vB', -1)
                if vB >= 0:
                    src_type = env.get(vB, TYPE_UNKNOWN)
                    if src_type not in WIDE_TYPES and src_type != TYPE_UNKNOWN:
                        inconsistencies.append({
                            'addr': addr, 'reg': vB,
                            'expected': 'wide (long/double)',
                            'actual': src_type,
                            'instruction': inst.name,
                        })

            # iget-boolean: 结果应该是 boolean
            if op == 0x53:
                vA = ops.get('vA', -1)
                if vA >= 0:
                    t = env.get(vA, TYPE_UNKNOWN)
                    if t not in (TYPE_BOOLEAN, TYPE_UNKNOWN):
                        inconsistencies.append({
                            'addr': addr, 'reg': vA,
                            'expected': TYPE_BOOLEAN,
                            'actual': t,
                            'instruction': inst.name,
                        })

            # invoke 传递的参数类型检查
            if op in (0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
                method_idx = ops.get('method_idx', ops.get('ref', -1))
                if methods and 0 <= method_idx < len(methods):
                    method_info = methods[method_idx]
                    proto = method_info.get('proto', '')
                    # 解析参数类型
                    if proto and '(' in proto:
                        params_str = proto[proto.index('(') + 1:proto.rindex(')')]
                        param_types = TypeInference._parse_param_types(params_str)
                        regs = ops.get('registers', [])
                        if 'start_reg' in ops:
                            start = ops['start_reg']
                            count = ops.get('reg_count', 0)
                            regs = [start + i for i in range(count)]
                        # 第一个寄存器是 this（如果非 static）
                        invoke_is_static = op in (0x71, 0x72, 0x77, 0x78)
                        reg_offset = 0 if invoke_is_static else 1
                        for i, ptype in enumerate(param_types):
                            reg_idx = reg_offset + i
                            if reg_idx < len(regs):
                                reg = regs[reg_idx]
                                expected = TypeInference._desc_to_type(ptype)
                                actual = env.get(reg, TYPE_UNKNOWN)
                                if actual != TYPE_UNKNOWN and expected != TYPE_UNKNOWN:
                                    if not TypeInference._types_compatible(expected, actual):
                                        inconsistencies.append({
                                            'addr': addr, 'reg': reg,
                                            'expected': expected,
                                            'actual': actual,
                                            'instruction': inst.name,
                                        })

        return inconsistencies

    @staticmethod
    def _parse_param_types(param_str):
        """解析方法参数类型描述符字符串"""
        params = []
        i = 0
        while i < len(param_str):
            c = param_str[i]
            if c in 'ZBCSIJFD':
                params.append(c)
                i += 1
            elif c == 'L':
                end = param_str.index(';', i)
                params.append(param_str[i:end + 1])
                i = end + 1
            elif c == '[':
                # 数组类型
                arr = '['
                i += 1
                while i < len(param_str) and param_str[i] == '[':
                    arr += '['
                    i += 1
                if i < len(param_str):
                    if param_str[i] == 'L':
                        end = param_str.index(';', i)
                        arr += param_str[i:end + 1]
                        i = end + 1
                    else:
                        arr += param_str[i]
                        i += 1
                params.append(arr)
            else:
                i += 1
        return params

    @staticmethod
    def _types_compatible(t1, t2):
        """检查两个类型是否兼容"""
        if t1 == t2:
            return True
        if TYPE_UNKNOWN in (t1, t2):
            return True
        if TYPE_NULL in (t1, t2):
            return True  # null 兼容所有引用类型
        # int 子类型兼容
        int_types = {TYPE_INT, TYPE_BOOLEAN, TYPE_BYTE, TYPE_CHAR, TYPE_SHORT}
        if t1 in int_types and t2 in int_types:
            return True
        # object 和具体类兼容
        if t1 == TYPE_OBJECT and t2 not in (TYPE_INT, TYPE_FLOAT, TYPE_LONG, TYPE_DOUBLE, TYPE_BOOLEAN, TYPE_BYTE, TYPE_CHAR, TYPE_SHORT):
            return True
        if t2 == TYPE_OBJECT and t1 not in (TYPE_INT, TYPE_FLOAT, TYPE_LONG, TYPE_DOUBLE, TYPE_BOOLEAN, TYPE_BYTE, TYPE_CHAR, TYPE_SHORT):
            return True
        return False
