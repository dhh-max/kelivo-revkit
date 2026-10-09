import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/local_tools/tool_error_policy.dart';

/// 报告 2-21 守护：错误码形态必须**在两条出口上一致**（端内 Agent 面与 MCP 面）。
///
/// 历史上生产端有三种拼法：Kotlin `err()` 的 `UPPER_SNAKE`、Dart handler 的
/// `lower_snake`、以及自由文本当码。D7 已经做了小写归一，但真机复测仍能看到
/// UPPER 漏到端内——因为 `enrich` 只认 `error` 键，`{ok:false, code:...}` 这条
/// 形态整个绕过归一。
void main() {
  Map<String, dynamic> decode(String raw) =>
      jsonDecode(raw) as Map<String, dynamic>;

  group('扁平形态 {error: ...}', () {
    test('error 是 UPPER_SNAKE 字符串 → 归一为小写并保留 rawCode', () {
      final out = decode(
        ToolErrorPolicy.enrich(
          jsonEncode(<String, dynamic>{'error': 'INVALID_ARGUMENT'}),
        ),
      );
      final error = out['error'] as Map<String, dynamic>;
      expect(error['code'], 'invalid_argument');
      expect(error['rawCode'], 'INVALID_ARGUMENT');
      // recoverable 与原生 err() 信封对齐，放在 error 内（顶层再放一份会让客户端漏读）。
      expect(error['recoverable'], isTrue);
    });

    test('error 是对象（UPPER code）→ 同样归一', () {
      final out = decode(
        ToolErrorPolicy.enrich(
          jsonEncode(<String, dynamic>{
            'error': <String, dynamic>{'code': 'FILE_NOT_FOUND'},
          }),
        ),
      );
      final error = out['error'] as Map<String, dynamic>;
      expect(error['code'], 'file_not_found');
      expect(error['rawCode'], 'FILE_NOT_FOUND');
    });
  });

  group('顶层 code 形态 {ok:false, code: ...}', () {
    test('failure：归一 code + 补 recoverable（过去整条绕过）', () {
      final out = decode(
        ToolErrorPolicy.enrich(
          jsonEncode(<String, dynamic>{
            'ok': false,
            'code': 'INVALID_ARGUMENT',
          }),
        ),
      );
      expect(out['code'], 'invalid_argument', reason: '端内不该再看到 UPPER_SNAKE');
      expect(out['rawCode'], 'INVALID_ARGUMENT');
      expect(out['recoverable'], isTrue);
    });

    test('环境类失败：recoverable=false（原样重试必然再失败）', () {
      final out = decode(
        ToolErrorPolicy.enrich(
          jsonEncode(<String, dynamic>{
            'ok': false,
            'code': 'CHAT_SERVICE_UNAVAILABLE',
          }),
        ),
      );
      expect(out['code'], 'chat_service_unavailable');
      expect(out['recoverable'], isFalse);
    });

    test('成功结果带 code（如状态枚举）不动它', () {
      final raw = jsonEncode(<String, dynamic>{
        'ok': true,
        'code': 'OK',
        'message': 'done',
      });
      expect(ToolErrorPolicy.enrich(raw), raw);
    });
  });

  group('不改写的情形', () {
    test('无 error 且无 ok/code：原样返回', () {
      final raw = jsonEncode(<String, dynamic>{'result': 42});
      expect(ToolErrorPolicy.enrich(raw), raw);
    });

    test('已有显式 recoverable：保留判定，形状仍归一（F-39）', () {
      final map = decode(ToolErrorPolicy.enrich(
        jsonEncode(<String, dynamic>{
          'error': 'weird_free_text',
          'recoverable': false,
        }),
      ));
      expect(map['recoverable'], isFalse);
      expect((map['error'] as Map<String, dynamic>)['recoverable'], isFalse);
    });

    test('非 JSON（人类可读文本）：不干预', () {
      const raw = 'not json at all: error happened';
      expect(ToolErrorPolicy.enrich(raw), raw);
    });
  });

  group('信封形态 {ok, data, error:{...}}', () {
    test('enrichEnvelope 归一 code；recoverable 双层同值（F-39 统一形状）', () {
      final out = ToolErrorPolicy.enrichEnvelope(<String, dynamic>{
        'ok': false,
        'data': null,
        'error': <String, dynamic>{'code': 'ADVANCE_REJECTED'},
      });
      final error = out['error'] as Map<String, dynamic>;
      expect(error['code'], 'advance_rejected');
      expect(error['rawCode'], 'ADVANCE_REJECTED');
      expect(error['recoverable'], isTrue);
      // F-39（2026-10-05）：顶层镜像与 error 内同值——过去只在 error 内，
      // 与另外两个工具的信封形状不一致。
      expect(out['recoverable'], isTrue);
      expect(out['code'], 'advance_rejected');
      expect(out['rawCode'], 'ADVANCE_REJECTED');
    });

    test('成功信封原样返回', () {
      final envelope = <String, dynamic>{'ok': true, 'data': 1, 'error': null};
      expect(ToolErrorPolicy.enrichEnvelope(envelope), same(envelope));
    });
  });

  test('两个出口对同一错误码给出同一形态（跨面一致性）', () {
    final flat = decode(
      ToolErrorPolicy.enrich(jsonEncode(<String, dynamic>{'error': 'BAD_ARGS'})),
    );
    final envelope = ToolErrorPolicy.enrichEnvelope(<String, dynamic>{
      'ok': false,
      'error': <String, dynamic>{'code': 'BAD_ARGS'},
    });
    expect(
      (flat['error'] as Map)['code'],
      (envelope['error'] as Map)['code'],
    );
    expect((flat['error'] as Map)['code'], 'bad_args');
  });

  _missingCode();
}

/// R5 兜底：`ok:false` 却没有任何机器可读错误码的回执，必须被合成一个，
/// 而不是让调用方对着 message 猜。
void _missingCode() {
  Map<String, dynamic> decodeIn(String raw) =>
      jsonDecode(raw) as Map<String, dynamic>;

  group('无码失败的 R5 兜底', () {
    test('errors[] 里有 code 就不算「无码」（报告 F-15：顶层曾被误合成）', () {
      final out = decodeIn(
        ToolErrorPolicy.enrich(
          jsonEncode(<String, dynamic>{
            'ok': false,
            'errors': <Map<String, dynamic>>[
              <String, dynamic>{'code': 'NO_TASK', 'message': '当前对话还没有任务。'},
            ],
          }),
        ),
      );
      expect(
        ToolErrorPolicy.needsSynthesizedCode(out),
        isFalse,
        reason: '内层 errors[0].code=NO_TASK 时顶层不许再合成 missing_error_code',
      );
    });

    test('ok=false 且无 error/code → 合成 missing_error_code（不可重试）', () {
      final out = decodeIn(
        ToolErrorPolicy.enrich(
          jsonEncode(<String, dynamic>{'ok': false, 'message': 'something broke'}),
        ),
      );
      final error = out['error'] as Map<String, dynamic>;
      expect(error['code'], 'missing_error_code');
      expect(error['recoverable'], isFalse);
      expect(error['retrySameArguments'], isFalse);
      expect(error['message'], contains('工具实现缺口'));
      expect(out['message'], 'something broke', reason: '原有信息不覆盖');
    });

    test('ok=false 但有 code → 不合成（走既有归一）', () {
      expect(
        ToolErrorPolicy.needsSynthesizedCode(<String, dynamic>{
          'ok': false,
          'code': 'INVALID_ARGUMENT',
        }),
        isFalse,
      );
    });

    test('ok=false 且有 error 码 → 不合成', () {
      expect(
        ToolErrorPolicy.needsSynthesizedCode(<String, dynamic>{
          'ok': false,
          'error': <String, dynamic>{'code': 'FILE_NOT_FOUND'},
        }),
        isFalse,
      );
    });

    test('成功结果不受影响', () {
      expect(
        ToolErrorPolicy.needsSynthesizedCode(<String, dynamic>{'ok': true}),
        isFalse,
      );
    });

    test('合成带 tool 名便于定位（两个出口共用同一判定）', () {
      final synthesized = ToolErrorPolicy.synthesizeMissingCode(
        <String, dynamic>{'ok': false},
        tool: 'apk_sign',
      );
      expect((synthesized['error'] as Map)['message'], contains('apk_sign'));
    });
  });
}
