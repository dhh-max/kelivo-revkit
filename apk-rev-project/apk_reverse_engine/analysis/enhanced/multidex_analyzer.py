"""多 DEX 关联分析 - 跨 DEX 引用追踪、类分布、重复检测

功能：
1. 多 DEX 类分布统计
2. 跨 DEX 引用追踪（DEX A 引用 DEX B 中的类）
3. 重复类检测（同包名类名出现在多个 DEX）
4. DEX 依赖关系图
5. 主 DEX 识别（启动类优先）
"""
from collections import defaultdict


class MultiDexAnalyzer:
    """多 DEX 关联分析器"""

    @staticmethod
    def analyze_dex_distribution(dex_parsers):
        """分析多 DEX 文件的类分布

        Args:
            dex_parsers: dict {dex_name: DexParser}

        Returns:
            dict: {dex_stats, class_to_dex, duplicate_classes, summary}
        """
        dex_stats = {}
        class_to_dex = defaultdict(list)  # class_name -> [dex_names]

        for dex_name, dp in dex_parsers.items():
            dp._ensure_parsed()
            class_count = 0
            method_count = 0
            field_count = 0
            string_count = len(dp.get_strings())

            for cls in dp.get_class_defs():
                cls_name = cls.get('class_name', '')
                class_count += 1
                class_to_dex[cls_name].append(dex_name)

                all_methods = cls.get('direct_methods', []) + cls.get('virtual_methods', [])
                method_count += len(all_methods)
                for m in all_methods:
                    code = m.get('code')
                    if code:
                        field_count += 0  # fields counted separately

            # Count fields
            field_count = len(dp.get_field_ids())

            dex_stats[dex_name] = {
                'classes': class_count,
                'methods': method_count,
                'fields': field_count,
                'strings': string_count,
                'method_ids': len(dp.get_methods()),
            }

        # 找重复类
        duplicate_classes = {
            cls: dexes for cls, dexes in class_to_dex.items()
            if len(dexes) > 1
        }

        # 汇总
        total_classes = sum(s['classes'] for s in dex_stats.values())
        total_methods = sum(s['methods'] for s in dex_stats.values())
        total_fields = sum(s['fields'] for s in dex_stats.values())
        total_strings = sum(s['strings'] for s in dex_stats.values())

        return {
            'dex_stats': dex_stats,
            'class_to_dex': dict(class_to_dex),
            'duplicate_classes': duplicate_classes,
            'summary': {
                'dex_count': len(dex_parsers),
                'total_classes': total_classes,
                'total_methods': total_methods,
                'total_fields': total_fields,
                'total_strings': total_strings,
                'duplicate_class_count': len(duplicate_classes),
            },
        }

    @staticmethod
    def analyze_cross_references(dex_parsers):
        """分析跨 DEX 引用

        Args:
            dex_parsers: dict {dex_name: DexParser}

        Returns:
            dict: {cross_refs, dependency_graph, summary}
        """
        # 先建立类 -> DEX 映射
        class_to_dex = {}
        dex_class_sets = {}

        for dex_name, dp in dex_parsers.items():
            dp._ensure_parsed()
            class_set = set()
            for cls in dp.get_class_defs():
                cls_name = cls.get('class_name', '')
                class_to_dex[cls_name] = dex_name
                class_set.add(cls_name)
            dex_class_sets[dex_name] = class_set

        # 分析每个 DEX 的字符串中引用的外部类
        cross_refs = defaultdict(lambda: defaultdict(int))  # source_dex -> target_dex -> count
        cross_ref_details = defaultdict(lambda: defaultdict(list))

        for dex_name, dp in dex_parsers.items():
            dp._ensure_parsed()
            strings = dp.get_strings()
            local_classes = dex_class_sets[dex_name]

            for s in strings:
                if not isinstance(s, str):
                    continue
                # 匹配类描述符 L...;
                if not (s.startswith('L') and s.endswith(';') and '/' in s):
                    continue
                # 检查引用的类是否在其他 DEX 中
                if s in local_classes:
                    continue  # 本地类
                if s in class_to_dex:
                    target_dex = class_to_dex[s]
                    if target_dex != dex_name:
                        cross_refs[dex_name][target_dex] += 1
                        if len(cross_ref_details[dex_name][target_dex]) < 50:
                            cross_ref_details[dex_name][target_dex].append(s)

        # 构建依赖图
        dependency_graph = {}
        for src, targets in cross_refs.items():
            dependency_graph[src] = {
                tgt: count for tgt, count in targets.items()
            }

        # 识别主 DEX（被依赖最多的）
        dependents_count = defaultdict(int)
        for src, targets in cross_refs.items():
            for tgt in targets:
                dependents_count[tgt] += 1

        main_dex = max(dependents_count, key=dependents_count.get) if dependents_count else None

        return {
            'cross_refs': {k: dict(v) for k, v in cross_refs.items()},
            'cross_ref_details': {k: dict(v) for k, v in cross_ref_details.items()},
            'dependency_graph': dependency_graph,
            'main_dex': main_dex,
            'summary': {
                'total_cross_refs': sum(sum(v.values()) for v in cross_refs.values()),
                'dex_dependencies': len(dependency_graph),
                'main_dex': main_dex,
            },
        }

    @staticmethod
    def detect_duplicate_classes(dex_parsers):
        """检测重复类

        Returns:
            dict: {duplicates, summary}
        """
        class_locations = defaultdict(list)

        for dex_name, dp in dex_parsers.items():
            dp._ensure_parsed()
            for cls in dp.get_class_defs():
                cls_name = cls.get('class_name', '')
                class_locations[cls_name].append(dex_name)

        duplicates = {
            cls: dexes for cls, dexes in class_locations.items()
            if len(dexes) > 1
        }

        return {
            'duplicates': duplicates,
            'total_unique_classes': len(class_locations),
            'total_class_entries': sum(len(v) for v in class_locations.values()),
            'duplicate_count': len(duplicates),
        }

    @staticmethod
    def analyze(dex_parsers):
        """综合多 DEX 分析

        Args:
            dex_parsers: dict {dex_name: DexParser}

        Returns:
            dict: 所有分析结果
        """
        return {
            'distribution': MultiDexAnalyzer.analyze_dex_distribution(dex_parsers),
            'cross_references': MultiDexAnalyzer.analyze_cross_references(dex_parsers),
            'duplicates': MultiDexAnalyzer.detect_duplicate_classes(dex_parsers),
        }