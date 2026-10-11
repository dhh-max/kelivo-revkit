"""Native-Java 交叉引用分析 - SO 与 DEX 之间的调用关系追踪

功能：
1. JNI 函数注册检测（RegisterNatives / JNI_OnLoad）
2. Java→Native 调用映射（native 方法声明 → SO 符号）
3. Native→Java 回调检测（JNIEnv 调用 FindClass/GetMethodID 等）
4. 导出函数与导入函数关联
5. 安全风险评估（危险 JNI 调用模式）
"""
import re
from collections import defaultdict


class NativeCrossRefAnalyzer:
    """Native-Java 交叉引用分析器"""

    # JNI 关键函数模式
    JNI_IMPORT_PATTERNS = [
        (r'FindClass', 'find_class', 'Native 查找 Java 类'),
        (r'GetMethodID', 'get_method_id', 'Native 获取 Java 方法 ID'),
        (r'GetFieldID', 'get_field_id', 'Native 获取 Java 字段 ID'),
        (r'GetStaticMethodID', 'get_static_method_id', 'Native 获取静态方法 ID'),
        (r'GetStaticFieldID', 'get_static_field_id', 'Native 获取静态字段 ID'),
        (r'NewStringUTF', 'new_string_utf', 'Native 创建 Java 字符串'),
        (r'GetStringUTFChars', 'get_string_utf', 'Native 读取 Java 字符串'),
        (r'CallVoidMethod', 'call_void', 'Native 调用 Java void 方法'),
        (r'CallObjectMethod', 'call_object', 'Native 调用 Java 对象方法'),
        (r'CallIntMethod', 'call_int', 'Native 调用 Java int 方法'),
        (r'CallBooleanMethod', 'call_bool', 'Native 调用 Java boolean 方法'),
        (r'CallStaticVoidMethod', 'call_static_void', 'Native 调用静态 void 方法'),
        (r'CallStaticObjectMethod', 'call_static_object', 'Native 调用静态对象方法'),
        (r'RegisterNatives', 'register_natives', '动态注册 JNI 方法'),
        (r'JNI_OnLoad', 'jni_onload', 'JNI 加载入口'),
        (r'GetEnv', 'get_env', '获取 JNI 环境'),
        (r'AttachCurrentThread', 'attach_thread', '附加当前线程到 JVM'),
        (r'DetachCurrentThread', 'detach_thread', '分离当前线程'),
        (r'NewGlobalRef', 'new_global_ref', '创建全局引用'),
        (r'DeleteLocalRef', 'delete_local_ref', '删除局部引用'),
        (r'GetJavaVM', 'get_java_vm', '获取 JavaVM 指针'),
        (r'GetObjectClass', 'get_object_class', '获取对象类'),
        (r'IsInstanceOf', 'is_instance_of', '类型检查'),
        (r'ThrowNew', 'throw_new', 'Native 抛出 Java 异常'),
    ]

    # 危险 JNI 调用模式
    DANGEROUS_JNI_PATTERNS = [
        (r'exec\(|Runtime', 'runtime_exec', 'critical', 'Native 中执行命令'),
        (r'system\(|popen', 'system_call', 'critical', 'Native 中调用系统命令'),
        (r'chmod|chown', 'file_perm', 'high', 'Native 中修改文件权限'),
        (r'ptrace', 'ptrace', 'high', 'Native 中使用 ptrace（反调试）'),
        (r'/proc/self/status|/proc/self/maps', 'proc_check', 'high', 'Native 中读取 /proc（反调试/环境检测）'),
        (r'__system_property_get', 'system_property', 'medium', '读取系统属性'),
        (r'dlopen|dlsym', 'dynamic_load', 'medium', '动态加载 SO 库'),
        (r'mmap|mprotect', 'memory_op', 'medium', '内存操作（可能用于代码注入）'),
        (r'fork\(|vfork', 'fork', 'high', 'Native 中 fork 进程'),
        (r'kill\(|signal\(', 'signal_op', 'medium', 'Native 中发送信号'),
    ]

    # 常见 JNI 方法名前缀
    JNI_NAME_PREFIXES = ['Java_', 'Java_com_', 'Java_org_', 'Java_android_']

    @staticmethod
    def analyze_native_methods(dex_parser):
        """从 DEX 中提取 native 方法声明

        Returns:
            dict: {native_methods, class_mapping, summary}
        """
        dp = dex_parser
        dp._ensure_parsed()

        native_methods = []
        class_mapping = defaultdict(list)

        for cls in dp.get_class_defs():
            cls_name = cls.get('class_name', '')
            all_methods = cls.get('direct_methods', []) + cls.get('virtual_methods', [])
            for m in all_methods:
                access_flags = m.get('access_flags', 0)
                # ACC_NATIVE = 0x0100
                if not (access_flags & 0x0100):
                    continue

                method_name = m.get('name', '')
                descriptor = m.get('descriptor', '')

                # 推测 JNI 函数名
                # Java_com_example_Class_method
                jni_name = ''
                if cls_name.startswith('L') and cls_name.endswith(';'):
                    cleaned = cls_name[1:-1].replace('/', '_')
                    jni_name = f'Java_{cleaned}_{method_name}'

                native_methods.append({
                    'class': cls_name,
                    'method': method_name,
                    'descriptor': descriptor,
                    'jni_name': jni_name,
                })
                class_mapping[cls_name].append(method_name)

        return {
            'native_methods': native_methods,
            'class_mapping': dict(class_mapping),
            'summary': {
                'total_native_methods': len(native_methods),
                'classes_with_native': len(class_mapping),
            },
        }

    @staticmethod
    def analyze_so_exports(so_data_or_symbols, so_name=''):
        """分析 SO 文件的导出符号

        Args:
            so_data_or_symbols: 符号名列表 或 ELF 数据
            so_name: SO 文件名

        Returns:
            dict: {jni_functions, other_exports, dangerous_patterns, summary}
        """
        # 如果传入的是符号列表
        if isinstance(so_data_or_symbols, (list, tuple)):
            symbols = list(so_data_or_symbols)
        else:
            # 尝试从字符串中提取符号名
            symbols = []
            if isinstance(so_data_or_symbols, bytes):
                try:
                    text = so_data_or_symbols.decode('utf-8', errors='ignore')
                except Exception:
                    text = str(so_data_or_symbols)
            else:
                text = str(so_data_or_symbols)

            # 简单提取以 Java_ 开头的符号
            for match in re.finditer(r'(Java_[A-Za-z0-9_]+)', text):
                symbols.append(match.group(1))

        jni_functions = []
        other_exports = []
        dangerous_patterns = []

        for sym in symbols:
            if not isinstance(sym, str):
                continue
            is_jni = False
            for prefix in NativeCrossRefAnalyzer.JNI_NAME_PREFIXES:
                if sym.startswith(prefix):
                    jni_functions.append(sym)
                    is_jni = True
                    break
            if not is_jni:
                # 检查是否是 JNI 相关函数
                if sym in ('JNI_OnLoad', 'JNI_OnUnload', 'JNI_OnUnload'):
                    jni_functions.append(sym)
                    is_jni = True
                else:
                    other_exports.append(sym)

            # 检查危险模式
            for pattern, name, severity, desc in NativeCrossRefAnalyzer.DANGEROUS_JNI_PATTERNS:
                if re.search(pattern, sym):
                    dangerous_patterns.append({
                        'symbol': sym,
                        'type': name,
                        'severity': severity,
                        'description': desc,
                    })

        # 去重
        jni_functions = list(dict.fromkeys(jni_functions))
        other_exports = list(dict.fromkeys(other_exports))

        return {
            'so_name': so_name,
            'jni_functions': jni_functions,
            'other_exports': other_exports[:500],  # 限制数量
            'dangerous_patterns': dangerous_patterns,
            'summary': {
                'jni_function_count': len(jni_functions),
                'other_export_count': len(other_exports),
                'dangerous_count': len(dangerous_patterns),
            },
        }

    @staticmethod
    def analyze_jni_callbacks(so_data, max_strings=50000):
        """分析 SO 中 JNI 回调 Java 的模式

        Args:
            so_data: SO 文件二进制数据
            max_strings: 最大字符串数量

        Returns:
            dict: {callbacks, dangerous_callbacks, summary}
        """
        try:
            if isinstance(so_data, bytes):
                text = so_data.decode('utf-8', errors='ignore')
            else:
                text = str(so_data)
        except Exception:
            text = ''

        callbacks = []
        dangerous = []

        # 在字符串中查找 JNI 函数引用
        for pattern, name, desc in NativeCrossRefAnalyzer.JNI_IMPORT_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                callbacks.append({
                    'function': name,
                    'pattern': pattern,
                    'count': len(matches),
                    'description': desc,
                })

        # 检查危险模式
        for pattern, name, severity, desc in NativeCrossRefAnalyzer.DANGEROUS_JNI_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                dangerous.append({
                    'type': name,
                    'severity': severity,
                    'count': len(matches),
                    'description': desc,
                })

        return {
            'callbacks': callbacks,
            'dangerous_callbacks': dangerous,
            'summary': {
                'total_jni_callbacks': len(callbacks),
                'total_dangerous': len(dangerous),
            },
        }

    @staticmethod
    def cross_reference(dex_parser, so_symbols_map):
        """交叉引用分析 - DEX native 方法与 SO 导出符号匹配

        Args:
            dex_parser: DexParser 实例
            so_symbols_map: dict {so_name: [symbol_names]}

        Returns:
            dict: {matched, unmatched_native, unmatched_so, summary}
        """
        native_info = NativeCrossRefAnalyzer.analyze_native_methods(dex_parser)
        native_methods = native_info['native_methods']

        # 收集所有 SO 的导出符号
        all_so_symbols = {}
        so_symbol_to_so = {}
        for so_name, symbols in so_symbols_map.items():
            all_so_symbols[so_name] = set(symbols) if isinstance(symbols, (list, set, tuple)) else set()
            for sym in all_so_symbols[so_name]:
                so_symbol_to_so[sym] = so_name

        matched = []
        unmatched_native = []

        for nm in native_methods:
            jni_name = nm['jni_name']
            found = False
            if jni_name:
                for so_name, sym_set in all_so_symbols.items():
                    if jni_name in sym_set:
                        matched.append({
                            'class': nm['class'],
                            'method': nm['method'],
                            'jni_name': jni_name,
                            'so_file': so_name,
                        })
                        found = True
                        break
            if not found:
                # 检查 JNI_OnLoad 动态注册
                for so_name, sym_set in all_so_symbols.items():
                    if 'JNI_OnLoad' in sym_set:
                        nm['likely_dynamic_registration'] = so_name
                        break
                unmatched_native.append(nm)

        # SO 中未被 DEX 引用的 JNI 函数
        matched_jni_names = {m['jni_name'] for m in matched}
        unmatched_so = {}
        for so_name, sym_set in all_so_symbols.items():
            for sym in sym_set:
                if sym.startswith('Java_') and sym not in matched_jni_names:
                    unmatched_so.setdefault(so_name, []).append(sym)

        return {
            'matched': matched,
            'unmatched_native': unmatched_native,
            'unmatched_so': {k: list(v) for k, v in unmatched_so.items()},
            'summary': {
                'total_native_methods': len(native_methods),
                'matched_count': len(matched),
                'unmatched_native_count': len(unmatched_native),
                'unmatched_so_count': sum(len(v) for v in unmatched_so.values()),
            },
        }

    @staticmethod
    def analyze(dex_parser=None, so_symbols_map=None, so_data=None):
        """综合 Native-Java 交叉引用分析

        Args:
            dex_parser: DexParser 实例（可选）
            so_symbols_map: dict {so_name: [symbols]}（可选）
            so_data: SO 文件二进制数据（可选，用于 JNI 回调分析）

        Returns:
            dict: 所有分析结果
        """
        results = {}

        if dex_parser:
            results['native_methods'] = NativeCrossRefAnalyzer.analyze_native_methods(dex_parser)

        if so_symbols_map:
            results['so_exports'] = {}
            for so_name, symbols in so_symbols_map.items():
                results['so_exports'][so_name] = NativeCrossRefAnalyzer.analyze_so_exports(symbols, so_name)

        if so_data:
            results['jni_callbacks'] = NativeCrossRefAnalyzer.analyze_jni_callbacks(so_data)

        if dex_parser and so_symbols_map:
            results['cross_reference'] = NativeCrossRefAnalyzer.cross_reference(dex_parser, so_symbols_map)

        return results
