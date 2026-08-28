"""DEX 继承图分析 — 类继承关系树/接口实现/抽象类检测"""
from apk_reverse_engine.utils.logutil import get_logger
logger = get_logger(__name__)
from collections import defaultdict

class DexInheritanceAnalyzer:
    """DEX 类继承关系分析"""

    @staticmethod
    def analyze(dex_parser):
        """分析 DEX 中所有类的继承关系"""
        dex_parser._ensure_parsed()
        class_defs = dex_parser.get_class_defs()
        strings = dex_parser.get_strings()
        types = dex_parser.get_types()

        classes_info = []
        inheritance_map = {}  # class -> superclass
        interface_map = defaultdict(list)  # class -> [interfaces]
        children_map = defaultdict(list)   # superclass -> [subclasses]
        interface_impls = defaultdict(list) # interface -> [implementers]

        for cd_idx, cd in enumerate(class_defs):
            class_name = dex_parser._get_type_string(cd) if hasattr(dex_parser, '_get_type_string') else f'class_{cd_idx}'
            if class_name.startswith('['):
                continue

            superclass_idx = cd.get('superclass_idx', 0)
            superclass = dex_parser.get_string(superclass_idx) if superclass_idx else None
            if not superclass and superclass_idx:
                try:
                    superclass = types[superclass_idx] if superclass_idx < len(types) else None
                except:
                    pass

            interfaces_off = cd.get('interfaces_off', 0)
            interfaces = []
            if interfaces_off:
                interfaces = DexInheritanceAnalyzer._parse_interfaces(dex_parser, interfaces_off, types, strings)

            access_flags = cd.get('access_flags', 0)
            is_interface = bool(access_flags & 0x0200)
            is_abstract = bool(access_flags & 0x0400)
            is_final = bool(access_flags & 0x0010)
            is_public = bool(access_flags & 0x0001)

            inheritance_map[class_name] = superclass
            if superclass:
                children_map[superclass].append(class_name)
            if interfaces:
                interface_map[class_name] = interfaces
                for iface in interfaces:
                    interface_impls[iface].append(class_name)

            classes_info.append({
                'class': class_name,
                'superclass': superclass,
                'interfaces': interfaces,
                'is_interface': is_interface,
                'is_abstract': is_abstract,
                'is_final': is_final,
                'is_public': is_public,
                'access_flags': access_flags,
            })

        # 找出继承深度
        depth_map = {}
        for cls in inheritance_map:
            depth_map[cls] = DexInheritanceAnalyzer._get_depth(cls, inheritance_map)

        # 找出根类（无父类或父类为 java.lang.Object）
        root_classes = [c for c, p in inheritance_map.items() if not p or p == 'Ljava/lang/Object;']

        # 统计
        total_classes = len(classes_info)
        interface_count = sum(1 for c in classes_info if c['is_interface'])
        abstract_count = sum(1 for c in classes_info if c['is_abstract'])
        final_count = sum(1 for c in classes_info if c['is_final'])

        # 最深继承链
        if depth_map:
            deepest = sorted(depth_map.items(), key=lambda x: x[1], reverse=True)[:10]
        else:
            deepest = []

        # 最多子类的类
        most_children = sorted(children_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]

        return {
            'total_classes': total_classes,
            'interface_count': interface_count,
            'abstract_count': abstract_count,
            'final_count': final_count,
            'root_classes': root_classes[:50],
            'inheritance_map': dict(list(inheritance_map.items())[:500]),
            'children_map': {k: v[:20] for k, v in list(children_map.items())[:100]},
            'interface_implementers': {k: v[:20] for k, v in list(interface_impls.items())[:100]},
            'deepest_inheritance': [(c, d) for c, d in deepest],
            'most_subclassed': [(k, len(v)) for k, v in most_children],
            'all_classes': classes_info if total_classes <= 500 else classes_info[:500],
        }

    @staticmethod
    def _parse_interfaces(dex_parser, interfaces_off, types, strings):
        """解析接口列表"""
        import struct
        interfaces = []
        try:
            count = struct.unpack_from('<H', dex_parser.data, interfaces_off)[0]
            for i in range(count):
                type_idx = struct.unpack_from('<H', dex_parser.data, interfaces_off + 2 + i * 2)[0]
                if type_idx < len(types):
                    interfaces.append(types[type_idx])
                elif type_idx < len(strings):
                    interfaces.append(strings[type_idx])
        except Exception as e:
            logger.debug(f"解析接口失败: {e}")
        return interfaces

    @staticmethod
    def _get_depth(class_name, inheritance_map, visited=None):
        """计算继承深度"""
        if visited is None:
            visited = set()
        if class_name in visited:
            return 0
        visited.add(class_name)
        parent = inheritance_map.get(class_name)
        if not parent or parent == 'Ljava/lang/Object;':
            return 0
        return 1 + DexInheritanceAnalyzer._get_depth(parent, inheritance_map, visited)

    @staticmethod
    def get_summary(result):
        """生成摘要"""
        return {
            'total_classes': result['total_classes'],
            'interfaces': result['interface_count'],
            'abstract_classes': result['abstract_count'],
            'final_classes': result['final_count'],
            'root_classes_count': len(result['root_classes']),
            'top5_deepest': result['deepest_inheritance'][:5],
            'top5_most_subclassed': result['most_subclassed'][:5],
        }