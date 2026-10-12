/// MCP 出口的参数预校验：把「类型不符 → 未捕获 Dart 异常」收敛为结构化错误。
///
/// 2026-09-19 全量复测实测（缺陷 DEF-02）：9 个工具 16 例把数值/布尔参数传成
/// 字符串时，各 handler 的 `(args['x'] as num?)` 直接抛
/// `type 'String' is not a subtype of type 'num?' in type cast`，出口兜成
/// `TOOL_EXCEPTION` 且 `recoverable=true` —— 调用方既看不出哪个参数错，又被
/// 诱导原样重试。
///
/// 这里按 **tools/list 已发布的 inputSchema** 做一次预校验，规则刻意保守：
/// - 可无损解析的字符串（"20" / "true"）**就地强制转换**，保持原有宽松；
/// - 不能解析的才报结构化错误，并指出参数名、期望类型与实际类型；
/// - 枚举越界给 `allowedValues`（DEF-06/16/17 的同一类缺口）；
/// - schema 里没有的键一律放过（未知参数策略＝忽略，不判缺陷）；
/// - 不校验 `null`（缺省语义交给 handler）。
library;

/// 校验结果：通过时返回 null，否则返回要回给客户端的错误体。
class ToolArgumentFault {
  const ToolArgumentFault({
    required this.code,
    required this.message,
    required this.parameter,
    this.expected,
    this.actual,
    this.allowedValues,
    this.suggestion,
  });

  final String code;
  final String message;
  final String parameter;
  final String? expected;
  final String? actual;
  final List<Object?>? allowedValues;
  final String? suggestion;

  Map<String, dynamic> toError() => <String, dynamic>{
    'code': code,
    'message': message,
    'parameter': parameter,
    if (expected != null) 'expected': expected,
    if (actual != null) 'actual': actual,
    if (allowedValues != null) 'allowedValues': allowedValues,
    'recoverable': true,
    'retrySameArguments': false,
  };
}

abstract final class ToolArgumentGuard {
  const ToolArgumentGuard._();

  /// 路径参数别名对（契约公布方 `WorkspacePolicyContract` 必须与这里一致——
  /// C5 防漂移单测直接断言两者相等）。
  static const List<List<String>> pathAliasPairs = <List<String>>[
    <String>['apkPath', 'path'],
    <String>['sourcePath', 'path'],
  ];

  /// 就地规范化 [args]（可无损转换的类型就地改写），返回首个致命缺陷。
  ///
  /// [schema] 为 tools/list 发布的 inputSchema（含 properties/required）。
  static ToolArgumentFault? check(
    Map<String, dynamic> schema,
    Map<String, dynamic> args,
  ) {
    final props = schema['properties'];
    if (props is! Map) return null;

    // 参数别名必须先于必填校验处理（契约统一，2026-09-19）：写工具用 apkPath、
    // dex/SO 工具用 path，调用方极易混用。schema 只声明其中一个时把另一个同义键
    // 搬过来——否则「名字记错」会被判成 missing_argument，把可救的调用直接打死。
    _applyPathAliases(schema, args);

    // 必填缺失：发布契约里标了 required 就必须给（DEF-18 实测：dex_search
    // 的 path、route_task 的 goal 标了 required 却能省略，契约与实现两套口径）。
    final required = schema['required'];
    if (required is List) {
      for (final raw in required) {
        final key = raw.toString();
        final value = args[key];
        final missing = value == null || (value is String && value.trim().isEmpty);
        if (missing) {
          return ToolArgumentFault(
            code: 'missing_argument',
            message: '缺少必填参数 $key。',
            parameter: key,
            expected: (props[key] is Map)
                ? ((props[key] as Map)['type']?.toString() ?? 'value')
                : 'value',
            suggestion: '补上 $key 后重试；参数含义见 get_solab_tool_map(tool=...) 全量声明。',
          );
        }
      }
    }

    for (final key in args.keys.toList()) {
      final spec = props[key];
      if (spec is! Map) continue;
      final type = spec['type']?.toString();
      final value = args[key];
      if (value == null) continue;

      // v8-D2（2026-10-04）：schema 可以声明多形态（`'type': ['object','array']`）
      // ——replacements 这类「对象或列表均可」的参数过去只声明 object，守卫
      // 把合法的列表形态直接拒掉，与工具描述自相矛盾。
      final acceptedTypes = spec['acceptsTypes'];
      if (acceptedTypes is List && acceptedTypes.isNotEmpty) {
        final typeName = switch (value) {
          Map() => 'object',
          List() => 'array',
          String() => 'string',
          bool() => 'boolean',
          int() => 'integer',
          num() => 'number',
          _ => 'value',
        };
        if (acceptedTypes.contains(typeName)) continue;
        if (!acceptedTypes.contains(type) ||
            (typeName != 'string' && typeName != 'number')) {
          return _typeFault(key, acceptedTypes.join(' 或 '), value);
        }
      }

      switch (type) {
        case 'integer':
          final asInt = _asInt(value);
          if (asInt == null) {
            return _typeFault(key, 'integer', value);
          }
          args[key] = asInt;
        case 'number':
          final asNum = _asNum(value);
          if (asNum == null) {
            return _typeFault(key, 'number', value);
          }
          args[key] = asNum;
        case 'boolean':
          final asBool = _asBool(value);
          if (asBool == null) {
            return _typeFault(key, 'boolean', value);
          }
          args[key] = asBool;
        case 'array':
          if (value is! List) return _typeFault(key, 'array', value);
        case 'object':
          if (value is! Map) return _typeFault(key, 'object', value);
        case 'string':
          if (value is String) break;
          // 宽松保留：数字/布尔当字符串用是既有行为（如 calculate("5")）。
          if (value is num || value is bool) {
            args[key] = value.toString();
            break;
          }
          return _typeFault(key, 'string', value);
        default:
          break;
      }

      // 枚举：仅当 schema 声明了 enum 才校验（so_analyze.action 等未声明 enum，
      // 由 handler 自己给 allowedValues，不受此处影响）。
      final allowed = spec['enum'];
      if (allowed is List && allowed.isNotEmpty && !allowed.contains(args[key])) {
        return ToolArgumentFault(
          code: 'invalid_argument_value',
          message:
              '参数 $key 取值不在允许集合内：${_describe(args[key])}。'
              '允许值：${allowed.join(' / ')}',
          parameter: key,
          expected: allowed.map((e) => e.toString()).join(' / '),
          actual: _describe(args[key]),
          allowedValues: List<Object?>.from(allowed),
          suggestion: '改用允许值之一后重试；不要原样重发。',
        );
      }
    }
    return null;
  }

  static ToolArgumentFault _typeFault(
    String key,
    String expected,
    Object value,
  ) =>
      ToolArgumentFault(
        code: 'invalid_argument_type',
        message: '参数 $key 类型不符：期望 $expected，实际 ${_describe(value)}。',
        parameter: key,
        expected: expected,
        actual: value.runtimeType.toString(),
        suggestion: expected == 'integer' || expected == 'number'
            ? '传数字（如 20），不要传 "20" 之外的非数字字符串。'
            : '按参数类型传值后重试。',
      );

  static int? _asInt(Object value) {
    if (value is int) return value;
    if (value is double) return value == value.roundToDouble() ? value.toInt() : null;
    if (value is String) return int.tryParse(value.trim());
    if (value is bool) return value ? 1 : 0;
    return null;
  }

  static num? _asNum(Object value) {
    if (value is num) return value;
    if (value is String) return num.tryParse(value.trim());
    if (value is bool) return value ? 1 : 0;
    return null;
  }

  static bool? _asBool(Object value) {
    if (value is bool) return value;
    if (value is num) return value != 0;
    if (value is String) {
      switch (value.trim().toLowerCase()) {
        case 'true':
        case '1':
        case 'yes':
          return true;
        case 'false':
        case '0':
        case 'no':
          return false;
      }
    }
    return null;
  }

  static void _applyPathAliases(
    Map<String, dynamic> schema,
    Map<String, dynamic> args,
  ) {
    final props = schema['properties'];
    if (props is! Map) return;
    const pairs = pathAliasPairs;
    for (final pair in pairs) {
      final declared = pair.where(props.containsKey).toList();
      if (declared.length != 1) continue;
      final canonical = declared.single;
      final alias = pair.firstWhere((name) => name != canonical);
      if (args[canonical] == null && args[alias] != null) {
        args[canonical] = args[alias];
      }
    }
  }

  static String _describe(Object? value) {
    if (value is String) return '"$value"（字符串）';
    if (value is num || value is bool) return '$value';
    if (value is List) return '数组(${value.length} 项)';
    if (value is Map) return '对象(${value.length} 键)';
    return value.runtimeType.toString();
  }
}
