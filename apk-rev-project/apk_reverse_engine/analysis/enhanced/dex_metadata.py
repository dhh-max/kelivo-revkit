"""DEX 元数据深度分析 - Annotation/Debug/Hidden API 检测

功能：
1. Annotation 解析（类/字段/方法/参数注解）
2. Debug 信息提取（行号映射、局部变量名、源文件）
3. Hidden API 检测（@SystemApi, @hide, 灰名单 API）
4. 注解处理器检测（ButterKnife, Dagger, Room 等）
5. 序列化标记检测（@Serializable, Parcelable, Gson）
"""
import re
from collections import defaultdict


class DexMetadataAnalyzer:
    """DEX 元数据深度分析器"""

    # 常见注解处理器框架
    ANNOTATION_PROCESSORS = {
        'butterknife': ['Lbutterknife/', 'Landroid/support/v4/butterknife/'],
        'dagger': ['Ldagger/', 'Ldagger2/'],
        'room': ['Landroidx/room/', 'Landroid/arch/persistence/room/'],
        'realm': ['Lio/realm/'],
        'greenrobot': ['Lorg/greenrobot/greendao/'],
        'ormlite': ['Lcom/j256/ormlite/'],
        'eventbus': ['Lorg/greenrobot/eventbus/', 'Lde/greenrobot/event/'],
        'otto': ['Lcom/squareup/otto/'],
        'moxy': ['Lcom/arellomobile/'],
        'moxy_x': ['Lmoxy/'],
    }

    # 序列化相关标记
    SERIALIZATION_MARKERS = {
        'parcelable': ['Landroid/os/Parcelable;', 'Landroid/os/Parcelable$Creator;'],
        'serializable': ['Ljava/io/Serializable;'],
        'gson': ['Lcom/google/gson/'],
        'moshi': ['Lcom/squareup/moshi/'],
        'jackson': ['Lcom/fasterxml/jackson/'],
        'fastjson': ['Lcom/alibaba/fastjson/', 'Ljava/lang/reflect/Type;'],
        'kotlinx_serialization': ['Lkotlinx/serialization/'],
    }

    # Hidden API 标记
    HIDDEN_API_PATTERNS = [
        (r'Landroid/internal/', 'internal_api', 'high', '访问 Android 内部 API'),
        (r'Lcom/android/internal/', 'internal_api', 'high', '访问 Android 内部 API'),
        (r'Ldalvik/system/', 'dalvik_system', 'medium', '访问 Dalvik 系统层 API'),
        (r'Lsun/misc/', 'sun_misc', 'medium', '访问 sun.misc 内部 API'),
        (r'Llibcore/io/', 'libcore', 'medium', '访问 libcore 内部 API'),
        (r'Landroid/reflect/', 'android_reflect', 'high', '访问 Android 反射 API'),
        (r'Landroid/util/Log;->println', 'native_log', 'low', '使用原生日志方法'),
        (r'getCurrentUser|setUserRestriction', 'multi_user', 'high', '多用户管理 API'),
        (r'killBackgroundProcesses|forceStopPackage', 'force_stop', 'high', '强制停止应用 API'),
        (r'installPackage|deletePackage', 'pm_install', 'critical', '静默安装/卸载 API'),
        (r'setComponentEnabledSetting.*PackageManager', 'component_toggle', 'medium', '动态组件开关'),
    ]

    # 反射模式
    REFLECTION_PATTERNS = [
        (r'Class\.forName', 'class_forname', '反射加载类'),
        (r'getDeclaredMethod', 'get_declared_method', '反射获取方法'),
        (r'getDeclaredField', 'get_declared_field', '反射获取字段'),
        (r'setAccessible\(true\)', 'set_accessible', '反射突破访问控制'),
        (r'getMethod\(', 'get_method', '反射获取公共方法'),
        (r'getField\(', 'get_field', '反射获取公共字段'),
        (r'newInstance\(', 'new_instance', '反射创建实例'),
        (r'invoke\(', 'method_invoke', '反射调用方法'),
        (r'Ldalvik/system/DexClassLoader;', 'dex_classloader', '动态 DEX 加载'),
        (r'Ldalvik/system/PathClassLoader;', 'path_classloader', '路径类加载器'),
    ]

    @staticmethod
    def analyze_annotations(dex_parser):
        """解析 DEX 中的注解信息

        Returns:
            dict: {
                class_annotations, field_annotations, method_annotations,
                parameter_annotations, annotation_set_items, summary
            }
        """
        dp = dex_parser
        dp._ensure_parsed()

        results = {
            'class_annotations': [],
            'field_annotations': [],
            'method_annotations': [],
            'parameter_annotations': [],
            'summary': defaultdict(int),
        }

        strings = dp.get_strings()
        type_ids = dp.get_type_ids()

        # 解析 annotation_directory_item
        for cls in dp.get_class_defs():
            cls_name = cls.get('class_name', '')
            annotations_off = cls.get('annotations_off', 0)

            if annotations_off == 0:
                continue

            try:
                import struct
                data = dp.data

                # 读取 annotation_directory_item
                offset = annotations_off
                class_annotations_off, fields_size, methods_size, params_size = \
                    struct.unpack_from('<IIII', data, offset)
                offset += 16

                # 类注解
                if class_annotations_off != 0:
                    results['class_annotations'].append({
                        'class': cls_name,
                        'annotations_off': class_annotations_off,
                    })
                    results['summary']['class_annotations'] += 1

                # 字段注解
                for _ in range(fields_size):
                    field_idx, annotations_off_field = struct.unpack_from('<II', data, offset)
                    offset += 8
                    field_name = ''
                    if field_idx < len(dp.get_field_ids()):
                        field_name = dp.get_field_ids()[field_idx].get('name', '')
                    results['field_annotations'].append({
                        'class': cls_name,
                        'field': field_name,
                        'annotations_off': annotations_off_field,
                    })
                    results['summary']['field_annotations'] += 1

                # 方法注解
                for _ in range(methods_size):
                    method_idx, annotations_off_method = struct.unpack_from('<II', data, offset)
                    offset += 8
                    method_name = ''
                    if method_idx < len(dp.get_methods()):
                        method_name = dp.get_methods()[method_idx].get('name', '')
                    results['method_annotations'].append({
                        'class': cls_name,
                        'method': method_name,
                        'annotations_off': annotations_off_method,
                    })
                    results['summary']['method_annotations'] += 1

                # 参数注解
                for _ in range(params_size):
                    method_idx, annotations_off_param = struct.unpack_from('<II', data, offset)
                    offset += 8
                    method_name = ''
                    if method_idx < len(dp.get_methods()):
                        method_name = dp.get_methods()[method_idx].get('name', '')
                    results['parameter_annotations'].append({
                        'class': cls_name,
                        'method': method_name,
                        'annotations_off': annotations_off_param,
                    })
                    results['summary']['parameter_annotations'] += 1

            except Exception:
                continue

        results['summary'] = dict(results['summary'])
        return results

    @staticmethod
    def analyze_debug_info(dex_parser, max_classes=200):
        """提取 Debug 调试信息

        Returns:
            dict: {
                source_files, line_maps, local_variables,
                total_methods, methods_with_debug, summary
            }
        """
        dp = dex_parser
        dp._ensure_parsed()

        from ..core.dex.disassembler import DebugInfoParser

        results = {
            'source_files': [],
            'line_maps': [],
            'local_variables': [],
            'total_methods': 0,
            'methods_with_debug': 0,
            'summary': {},
        }

        strings = dp.get_strings()
        class_count = 0

        for cls in dp.get_class_defs():
            if class_count >= max_classes:
                break
            class_count += 1

            cls_name = cls.get('class_name', '')
            source_file_idx = cls.get('source_file_idx', -1)
            if source_file_idx >= 0 and source_file_idx < len(strings):
                results['source_files'].append({
                    'class': cls_name,
                    'source_file': strings[source_file_idx],
                })

            all_methods = cls.get('direct_methods', []) + cls.get('virtual_methods', [])
            for m in all_methods:
                results['total_methods'] += 1
                m_name = m.get('name', '')
                code = m.get('code')
                if not code:
                    continue

                debug_info_off = code.get('debug_info_off', 0)
                if debug_info_off == 0:
                    continue

                results['methods_with_debug'] += 1

                try:
                    debug_info = DebugInfoParser.parse(dp.data, debug_info_off, strings)
                    if debug_info:
                        line_map = DebugInfoParser.build_line_map(debug_info)
                        if line_map:
                            results['line_maps'].append({
                                'class': cls_name,
                                'method': m_name,
                                'line_count': len(line_map),
                                'first_line': line_map[0][1] if line_map else 0,
                            })

                        local_vars = debug_info.get('local_variables', [])
                        if local_vars:
                            results['local_variables'].append({
                                'class': cls_name,
                                'method': m_name,
                                'variables': local_vars[:20],
                            })
                except Exception:
                    continue

        results['summary'] = {
            'total_source_files': len(results['source_files']),
            'total_line_maps': len(results['line_maps']),
            'total_local_variables': len(results['local_variables']),
            'total_methods': results['total_methods'],
            'methods_with_debug': results['methods_with_debug'],
            'debug_coverage': f"{results['methods_with_debug']}/{results['total_methods']}" if results['total_methods'] else '0/0',
        }
        return results

    @staticmethod
    def detect_hidden_api(dex_parser):
        """检测 Hidden API 使用

        Returns:
            dict: {findings, summary}
        """
        dp = dex_parser
        dp._ensure_parsed()

        strings = dp.get_strings()
        findings = []

        for idx, s in enumerate(strings):
            if not isinstance(s, str) or len(s) < 5:
                continue
            for pattern, api_type, severity, desc in DexMetadataAnalyzer.HIDDEN_API_PATTERNS:
                if re.search(pattern, s):
                    findings.append({
                        'type': api_type,
                        'severity': severity,
                        'description': desc,
                        'match': s[:200],
                        'string_index': idx,
                    })

        summary = defaultdict(int)
        for f in findings:
            summary[f['severity']] += 1
            summary[f['type']] += 1

        return {
            'findings': findings,
            'total': len(findings),
            'summary': dict(summary),
        }

    @staticmethod
    def detect_annotation_processors(dex_parser):
        """检测注解处理器框架

        Returns:
            dict: {detected: {framework: [classes]}, summary}
        """
        dp = dex_parser
        dp._ensure_parsed()

        strings = dp.get_strings()
        detected = defaultdict(list)

        for s in strings:
            if not isinstance(s, str):
                continue
            for framework, patterns in DexMetadataAnalyzer.ANNOTATION_PROCESSORS.items():
                for pat in patterns:
                    if pat in s:
                        detected[framework].append(s[:200])
                        break

        return {
            'detected': dict(detected),
            'summary': {k: len(v) for k, v in detected.items()},
        }

    @staticmethod
    def detect_serialization(dex_parser):
        """检测序列化框架使用

        Returns:
            dict: {detected: {framework: [matches]}, summary}
        """
        dp = dex_parser
        dp._ensure_parsed()

        strings = dp.get_strings()
        detected = defaultdict(list)

        for s in strings:
            if not isinstance(s, str):
                continue
            for framework, patterns in DexMetadataAnalyzer.SERIALIZATION_MARKERS.items():
                for pat in patterns:
                    if pat in s:
                        detected[framework].append(s[:200])
                        break

        return {
            'detected': dict(detected),
            'summary': {k: len(v) for k, v in detected.items()},
        }

    @staticmethod
    def analyze(dex_parser, max_classes=200):
        """综合元数据分析

        Returns:
            dict: 所有分析结果合并
        """
        return {
            'annotations': DexMetadataAnalyzer.analyze_annotations(dex_parser),
            'debug_info': DexMetadataAnalyzer.analyze_debug_info(dex_parser, max_classes),
            'hidden_api': DexMetadataAnalyzer.detect_hidden_api(dex_parser),
            'annotation_processors': DexMetadataAnalyzer.detect_annotation_processors(dex_parser),
            'serialization': DexMetadataAnalyzer.detect_serialization(dex_parser),
        }
