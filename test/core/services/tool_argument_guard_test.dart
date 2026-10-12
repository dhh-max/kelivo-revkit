import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/mcp_server/tool_argument_guard.dart';

/// 参数预校验回归（2026-09-19 全量复测 DEF-02/06/18）：
/// 9 个工具把数值/布尔参数传成字符串时，handler 里的 `as num?` 直接抛
/// `type 'String' is not a subtype of type 'num?' in type cast`，出口只剩
/// TOOL_EXCEPTION；枚举越界与必填缺失也缺少 allowedValues / 参数名。
void main() {
  Map<String, dynamic> schema({
    Map<String, dynamic>? properties,
    List<String>? required,
  }) =>
      <String, dynamic>{
        'type': 'object',
        'properties': properties ?? const <String, dynamic>{},
        if (required != null) 'required': required,
      };

  test('数值参数传非数字字符串 → 结构化错误，指出参数与期望类型', () {
    final args = <String, dynamic>{'limit': 'not_a_number'};
    final fault = ToolArgumentGuard.check(
      schema(properties: {
        'limit': {'type': 'integer'},
      }),
      args,
    );
    expect(fault, isNotNull);
    expect(fault!.code, 'invalid_argument_type');
    expect(fault.parameter, 'limit');
    expect(fault.expected, 'integer');
    expect(fault.toError()['recoverable'], true);
    expect(fault.toError()['retrySameArguments'], false);
  });

  test('可无损解析的数字字符串就地转换（保持既有宽松语义）', () {
    final args = <String, dynamic>{'limit': '20', 'dryRun': 'true'};
    final fault = ToolArgumentGuard.check(
      schema(properties: {
        'limit': {'type': 'integer'},
        'dryRun': {'type': 'boolean'},
      }),
      args,
    );
    expect(fault, isNull);
    expect(args['limit'], 20);
    expect(args['dryRun'], true);
  });

  test('布尔参数传非布尔字符串 → 结构化错误', () {
    final fault = ToolArgumentGuard.check(
      schema(properties: {
        'recursive': {'type': 'boolean'},
      }),
      <String, dynamic>{'recursive': 'not_a_bool'},
    );
    expect(fault, isNotNull);
    expect(fault!.parameter, 'recursive');
    expect(fault.expected, 'boolean');
  });

  test('枚举越界 → 错误里带 allowedValues（全量）', () {
    final fault = ToolArgumentGuard.check(
      schema(properties: {
        'action': {
          'type': 'string',
          'enum': ['list', 'read', 'write'],
        },
      }),
      <String, dynamic>{'action': '__bogus__'},
    );
    expect(fault, isNotNull);
    expect(fault!.code, 'invalid_argument_value');
    expect(fault.allowedValues, ['list', 'read', 'write']);
    expect(fault.message, contains('list'));
  });

  test('必填缺失 → 指出缺哪个参数', () {
    final fault = ToolArgumentGuard.check(
      schema(
        properties: {
          'path': {'type': 'string'},
        },
        required: ['path'],
      ),
      <String, dynamic>{},
    );
    expect(fault, isNotNull);
    expect(fault!.code, 'missing_argument');
    expect(fault.parameter, 'path');
  });

  test('未知参数与 null 一律放过（未知参数策略＝忽略）', () {
    final args = <String, dynamic>{'__unknown_key__': 1, 'limit': null};
    expect(
      ToolArgumentGuard.check(
        schema(properties: {
          'limit': {'type': 'integer'},
        }),
        args,
      ),
      isNull,
    );
  });

  test('字符串参数收到数字/布尔仍按既有行为转换，不报错', () {
    final args = <String, dynamic>{'expression': 5};
    expect(
      ToolArgumentGuard.check(
        schema(properties: {
          'expression': {'type': 'string'},
        }),
        args,
      ),
      isNull,
    );
    expect(args['expression'], '5');
  });

  test('数组/对象传成标量 → 结构化错误', () {
    expect(
      ToolArgumentGuard.check(
        schema(properties: {
          'calls': {'type': 'array'},
        }),
        <String, dynamic>{'calls': 'x'},
      )!.parameter,
      'calls',
    );
    expect(
      ToolArgumentGuard.check(
        schema(properties: {
          'replacements': {'type': 'object'},
        }),
        <String, dynamic>{'replacements': 1},
      )!.parameter,
      'replacements',
    );
  });

  test('参数别名：schema 声明 apkPath 时，传 path 也能命中', () {
    final args = <String, dynamic>{'path': '/storage/emulated/0/Ai/x.apk'};
    final fault = ToolArgumentGuard.check(
      schema(properties: {
        'apkPath': {'type': 'string'},
      }),
      args,
    );
    expect(fault, isNull);
    expect(args['apkPath'], '/storage/emulated/0/Ai/x.apk');
  });

  test('参数别名：schema 声明 path 时，传 apkPath 也能命中', () {
    final args = <String, dynamic>{'apkPath': '/a/b.apk'};
    expect(
      ToolArgumentGuard.check(
        schema(properties: {
          'path': {'type': 'string'},
        }),
        args,
      ),
      isNull,
    );
    expect(args['path'], '/a/b.apk');
  });

  test('别名不覆盖已显式给出的规范参数', () {
    final args = <String, dynamic>{'apkPath': '/canonical.apk', 'path': '/alias.apk'};
    ToolArgumentGuard.check(
      schema(properties: {
        'apkPath': {'type': 'string'},
      }),
      args,
    );
    expect(args['apkPath'], '/canonical.apk');
  });
}
