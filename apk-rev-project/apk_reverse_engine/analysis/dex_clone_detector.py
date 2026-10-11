"""DEX 方法克隆检测器 - 基于指令指纹检测重复/相似方法"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)

import struct, hashlib
from collections import defaultdict


class DexCloneDetector:
    """检测 DEX 中的重复方法（代码克隆）"""

    @staticmethod
    def detect(dex_parser):
        """检测 DEX 中的重复方法
        Args:
            dex_parser: DexParser 实例
        Returns:
            dict: {total_methods, clone_groups, clone_count, similarity_matrix}
        """
        dex_parser._ensure_parsed()

        methods_info = []
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()

        for cd_idx, cd in enumerate(class_defs):
            class_name = dex_parser._get_type_string(cd)
            if class_name.startswith('['):
                continue

            methods = cd.get('methods', [])
            for m_idx, method in enumerate(methods):
                method_idx = method.get('method_idx', 0)
                code_off = method.get('code_off', 0)

                if code_off == 0:
                    continue

                # 解析 code item
                code_item = dex_parser._parse_code_item(code_off)
                if not code_item or not code_item.get('insns'):
                    continue

                insns = code_item['insns']
                registers_size = code_item.get('registers_size', 0)

                # 生成指令指纹（忽略寄存器编号，只看操作码序列）
                opcode_sequence = DexCloneDetector._extract_opcode_sequence(insns)
                exact_hash = DexCloneDetector._hash_instructions(insns)
                opcode_hash = hashlib.md5(opcode_sequence.encode()).hexdigest()

                # 方法名和签名
                method_name, method_sig = dex_parser.get_method_signature(method)

                methods_info.append({
                    'class': class_name,
                    'method': method_name,
                    'signature': method_sig,
                    'registers': registers_size,
                    'code_size': len(insns) * 2,  # bytes
                    'instruction_count': len(insns),
                    'exact_hash': exact_hash,
                    'opcode_hash': opcode_hash,
                    'opcode_sequence': opcode_sequence,
                    'code_off': code_off,
                    'class_idx': cd_idx,
                    'method_idx': m_idx,
                })

        # 按精确哈希分组
        exact_groups = defaultdict(list)
        for m in methods_info:
            exact_groups[m['exact_hash']].append(m)

        exact_clones = {k: v for k, v in exact_groups.items() if len(v) > 1}

        # 按操作码哈希分组（相似方法）
        opcode_groups = defaultdict(list)
        for m in methods_info:
            if len(m['opcode_sequence']) >= 10:  # 忽略太短的方法
                opcode_groups[m['opcode_hash']].append(m)

        opcode_clones = {k: v for k, v in opcode_groups.items() if len(v) > 1}

        # 构建克隆组
        clone_groups = []

        # 精确重复
        for h, group in exact_clones.items():
            clone_groups.append({
                'type': 'exact',
                'hash': h,
                'count': len(group),
                'methods': [{
                    'class': m['class'],
                    'method': m['method'],
                    'signature': m['signature'],
                    'code_size': m['code_size'],
                    'instruction_count': m['instruction_count'],
                } for m in group],
                'total_redundant_bytes': (len(group) - 1) * group[0]['code_size'],
            })

        # 相似（操作码序列相同但指令不完全相同）
        for h, group in opcode_clones.items():
            # 排除已经在精确重复中的
            exact_hashes = {m['exact_hash'] for m in group}
            if len(exact_hashes) == 1:
                continue  # 全是精确重复，跳过

            clone_groups.append({
                'type': 'similar',
                'hash': h,
                'count': len(group),
                'methods': [{
                    'class': m['class'],
                    'method': m['method'],
                    'signature': m['signature'],
                    'code_size': m['code_size'],
                    'instruction_count': m['instruction_count'],
                    'exact_hash': m['exact_hash'],
                } for m in group],
                'variant_count': len(exact_hashes),
            })

        # 按冗余字节数排序
        clone_groups.sort(key=lambda g: g.get('total_redundant_bytes', 0), reverse=True)

        total_exact = sum(g['count'] for g in clone_groups if g['type'] == 'exact')
        total_similar = sum(g['count'] for g in clone_groups if g['type'] == 'similar')
        total_redundant = sum(g.get('total_redundant_bytes', 0) for g in clone_groups if g['type'] == 'exact')

        return {
            'total_methods': len(methods_info),
            'clone_groups': clone_groups,
            'clone_count': len(clone_groups),
            'exact_clone_groups': sum(1 for g in clone_groups if g['type'] == 'exact'),
            'similar_clone_groups': sum(1 for g in clone_groups if g['type'] == 'similar'),
            'total_cloned_methods': total_exact + total_similar,
            'total_redundant_bytes': total_redundant,
            'clone_ratio': (total_exact + total_similar) / max(len(methods_info), 1) * 100,
        }

    @staticmethod
    def _extract_opcode_sequence(insns):
        """提取操作码序列（忽略寄存器和操作数，只保留操作码）"""
        opcodes = []
        for inst in insns:
            op = inst.get('opcode', '')
            if op:
                # 提取操作码基础部分（去掉操作数）
                op_base = op.split()[0] if ' ' in op else op
                opcodes.append(op_base)
        return '|'.join(opcodes)

    @staticmethod
    def _hash_instructions(insns):
        """生成指令序列的精确哈希"""
        parts = []
        for inst in insns:
            op = inst.get('opcode', '')
            operands = inst.get('operands', [])
            parts.append(f"{op}:{','.join(str(o) for o in operands)}")
        return hashlib.md5('|'.join(parts).encode()).hexdigest()

    @staticmethod
    def get_summary(detection_result):
        """生成简洁摘要"""
        total = detection_result['total_methods']
        cloned = detection_result['total_cloned_methods']
        ratio = detection_result['clone_ratio']
        redundant = detection_result['total_redundant_bytes']
        groups = detection_result['clone_count']

        return {
            'total_methods': total,
            'cloned_methods': cloned,
            'clone_ratio_percent': round(ratio, 2),
            'clone_groups': groups,
            'redundant_code_bytes': redundant,
            'redundant_code_kb': round(redundant / 1024, 1),
            'top_5_groups': [
                {
                    'type': g['type'],
                    'count': g['count'],
                    'first_method': f"{g['methods'][0]['class']}->{g['methods'][0]['method']}",
                    'code_size': g['methods'][0]['code_size'],
                }
                for g in detection_result['clone_groups'][:5]
            ],
        }
