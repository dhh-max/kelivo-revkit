import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:Kelivo/core/services/local_tools/tool_error_policy.dart';

void main() {
  group('normalizeCode 错误码风格统一（D7）', () {
    test('全大写下划线 → 全小写下划线', () {
      expect(ToolErrorPolicy.normalizeCode('APK_NOT_FOUND'), 'apk_not_found');
      expect(ToolErrorPolicy.normalizeCode('VA_NOT_MAPPED'), 'va_not_mapped');
      expect(
        ToolErrorPolicy.normalizeCode('UNSAFE_DART_AOT_RAW_CONSTANT'),
        'unsafe_dart_aot_raw_constant',
      );
      expect(ToolErrorPolicy.normalizeCode('INPUT_TOO_LARGE'), 'input_too_large');
    });

    test('驼峰与自由文本也收敛到同一种形态', () {
      expect(ToolErrorPolicy.normalizeCode('noMatch'), 'no_match');
      expect(ToolErrorPolicy.normalizeCode('Search failed: boom'), 'search_failed:_boom');
      expect(ToolErrorPolicy.normalizeCode('  spaced-code  '), 'spaced_code');
    });

    test('已是规范形态的原样返回，空码落 tool_failed', () {
      expect(ToolErrorPolicy.normalizeCode('loop_detected'), 'loop_detected');
      expect(ToolErrorPolicy.normalizeCode(''), 'tool_failed');
      expect(ToolErrorPolicy.normalizeCode(null), 'tool_failed');
    });

    test('enrichEnvelope 归一错误码并保留原始写法（rawCode）', () {
      final out = ToolErrorPolicy.enrichEnvelope(<String, dynamic>{
        'ok': false,
        'data': null,
        'error': <String, dynamic>{
          'code': 'REPORT_NOT_READY',
          'message': 'x',
          'recoverable': true,
        },
        'nextActions': const <dynamic>[],
      });
      final err = out['error'] as Map<String, dynamic>;
      expect(err['code'], 'report_not_ready');
      expect(err['rawCode'], 'REPORT_NOT_READY');
      expect(err['recoverable'], isTrue);
    });

    test('enrich 的字符串错误码同样归一', () {
      final out = jsonDecode(
        ToolErrorPolicy.enrich(jsonEncode(<String, dynamic>{
          'ok': false,
          'error': 'PATH_OUTSIDE_WORKSPACE',
        })),
      ) as Map<String, dynamic>;
      final err = out['error'] as Map<String, dynamic>;
      expect(err['code'], 'path_outside_workspace');
      expect(err['rawCode'], 'PATH_OUTSIDE_WORKSPACE');
      expect(err['recoverable'], isTrue);
    });
  });

  group('recoverableFor 可恢复性判定', () {
    test('参数无效 / 缺失 / 目标不存在类错误可恢复', () {
      for (final code in <String>[
        'invalid_args',
        'invalid_apk_path',
        'invalid_path',
        'invalid_topics',
        'output_dir_required',
        'work_dir_required',
        'so_path_required',
        'workspace_not_set',
        'work_dir_not_set',
        'apk_not_found',
        'patch_artifact_not_found',
        'no_apk_selected',
        'confirmation_required',
        'preview_required',
        'project_not_ready',
        // 预览类工具确认目标失配（patch_apk_dex_strings 0 命中）：修正
        // replacements 后可重试，故可恢复；原样重试必再失败，与
        // retrySameArguments=false 配套。
        'no_match',
      ]) {
        expect(ToolErrorPolicy.recoverableFor(code), isTrue, reason: code);
      }
    });

    test('平台 / 能力 / 环境不可用与安全拒绝不可恢复', () {
      for (final code in <String>[
        'unsupported_platform',
        'tool_not_available',
        'chat_service_unavailable',
        'UNSAFE_DART_AOT_RAW_CONSTANT',
      ]) {
        expect(ToolErrorPolicy.recoverableFor(code), isFalse, reason: code);
      }
    });

    test('大小写与空白不敏感', () {
      expect(ToolErrorPolicy.recoverableFor('UNSUPPORTED_PLATFORM'), isFalse);
      expect(ToolErrorPolicy.recoverableFor('  invalid_args '), isTrue);
    });

    test('空值与未知码默认可恢复，保留重试机会', () {
      expect(ToolErrorPolicy.recoverableFor(null), isTrue);
      expect(ToolErrorPolicy.recoverableFor(''), isTrue);
      // 未知码不因未登记就判死：与改造前 MCP 侧行为一致，不引入能力回退。
      expect(ToolErrorPolicy.recoverableFor('something_new'), isTrue);
    });
  });

  group('enrich 补齐 recoverable', () {
    test('String error 结构化为对象并补 recoverable=true（C8）', () {
      final out = ToolErrorPolicy.enrich(
        jsonEncode(<String, dynamic>{
          'error': 'invalid_args',
          'message': '缺少 fileName',
        }),
      );
      final map = jsonDecode(out) as Map<String, dynamic>;
      // C8：error 由字符串结构化为 {code, message, recoverable}，与原生信封对齐。
      final err = map['error'] as Map<String, dynamic>;
      expect(err['code'], 'invalid_args');
      expect(err['message'], '缺少 fileName');
      expect(err['recoverable'], isTrue);
      expect(map['message'], '缺少 fileName'); // 顶层 message 保留
    });

    test('不可恢复错误结构化为对象且 recoverable=false', () {
      final map = jsonDecode(ToolErrorPolicy.enrich(
        jsonEncode(<String, dynamic>{'error': 'unsupported_platform'}),
      )) as Map<String, dynamic>;
      final err = map['error'] as Map<String, dynamic>;
      expect(err['code'], 'unsupported_platform');
      expect(err['recoverable'], isFalse);
    });

    test('已有显式 recoverable 时保留判定，但形状仍归一（F-39）', () {
      final map = jsonDecode(ToolErrorPolicy.enrich(
        '{"error":"x","recoverable":false}',
      )) as Map<String, dynamic>;
      // 显式判定不被覆盖。
      expect(map['recoverable'], isFalse);
      expect((map['error'] as Map<String, dynamic>)['recoverable'], isFalse);
      // F-39：形状统一为规范失败形（error 对象化 + 顶层镜像），不再是原样透传。
      final err = map['error'] as Map<String, dynamic>;
      expect(err['code'], isA<String>());
      expect(err['message'], isNotEmpty);
      expect(err['severity'], 'error');
      expect(err['retrySameArguments'], isFalse);
      expect(map['code'], err['code']);
      expect(map['message'], isNotEmpty);
      expect(map['nextActions'], isA<List<dynamic>>());
    });

    test('error 为 null 的成功结果不被改写', () {
      const raw = '{"ok":true,"error":null,"data":{}}';
      expect(ToolErrorPolicy.enrich(raw), raw);
    });

    test('非 JSON 文本原样返回', () {
      const text = 'not json at all';
      expect(ToolErrorPolicy.enrich(text), text);
    });

    test('含 error 字样的成功结果不被改写', () {
      // 前置判断按带引号的键名匹配，避免把含 "error" 文本的大结果拖进解析。
      const raw = '{"errorCount":0,"items":[]}';
      expect(ToolErrorPolicy.enrich(raw), raw);
    });

    test('error 为对象时按其中 code 判定', () {
      final map = jsonDecode(ToolErrorPolicy.enrich(
        jsonEncode(<String, dynamic>{
          'error': <String, dynamic>{'code': 'tool_not_available'},
        }),
      )) as Map<String, dynamic>;
      expect(map['recoverable'], isFalse);
    });
  });

  group('enrichEnvelope 标准信封', () {
    test('recoverable 既在 error 内也在顶层镜像（F-39 统一形状）', () {
      final out = ToolErrorPolicy.enrichEnvelope(<String, dynamic>{
        'ok': false,
        'data': <String, dynamic>{},
        'error': <String, dynamic>{
          'code': 'invalid_apk_path',
          'message': 'bad path',
        },
        'nextActions': <dynamic>[],
      });
      // F-39（2026-10-05）：三个工具曾各缺不同顶层字段（file 缺 message/
      // recoverable、so_analyze 缺 code/nextActions）——现在统一镜像，
      // 顶层与 error 内同值，调用方读哪层都行。
      expect(out['recoverable'], isTrue);
      final err = out['error'] as Map<String, dynamic>;
      expect(err['code'], 'invalid_apk_path');
      expect(err['recoverable'], isTrue);
      expect(out['code'], 'invalid_apk_path');
      expect(out['message'], 'bad path');
      expect(out['nextActions'], isA<List<dynamic>>());
      expect(out['data'], <String, dynamic>{});
    });

    test('error 为 null 时原样返回同一对象', () {
      final envelope = <String, dynamic>{
        'ok': true,
        'data': <String, dynamic>{'a': 1},
        'error': null,
        'nextActions': <dynamic>[],
      };
      expect(ToolErrorPolicy.enrichEnvelope(envelope), same(envelope));
    });

    test('已有 recoverable 时不覆盖', () {
      final out = ToolErrorPolicy.enrichEnvelope(<String, dynamic>{
        'ok': false,
        'data': <String, dynamic>{},
        'error': <String, dynamic>{
          'code': 'x',
          'recoverable': false,
        },
        'nextActions': <dynamic>[],
      });
      expect((out['error'] as Map<String, dynamic>)['recoverable'], isFalse);
    });

    test('String error 结构化为对象并补 recoverable（C8）', () {
      final out = ToolErrorPolicy.enrichEnvelope(<String, dynamic>{
        'ok': false,
        'data': <String, dynamic>{},
        'error': 'invalid_args',
        'message': '缺少参数',
        'nextActions': <dynamic>[],
      });
      expect(out['error'], isNot('invalid_args'));
      final err = out['error'] as Map<String, dynamic>;
      expect(err['code'], 'invalid_args');
      expect(err['message'], '缺少参数');
      expect(err['recoverable'], isTrue);
    });

    // 回归锁（2026-09-15 真机）：patch_apk_dex_strings dryRun 0 命中时，此前
    // 信封无 ok:false 也无 error，落到 MCP 侧 _normalizeToolOutput 的兜底分支
    // 被算成 ok:true —— 调用方看到"预览成功"，接着拿 applyArguments 去 apply
    // 必然撞墙。修法是失配路径显式给出 no_match 错误码，这里锁死该码经过
    // 出口规范化后仍判为失败、且 recoverable=true / retrySameArguments=false。
    test('no_match 失配信封规范化后仍为失败（0 命中预览回归锁）', () {
      final out = ToolErrorPolicy.enrichEnvelope(<String, dynamic>{
        'ok': false,
        'data': <String, dynamic>{
          'preview': true,
          'totalMatched': 0,
          'previewUsable': false,
        },
        'error': <String, dynamic>{
          'code': 'no_match',
          'message': '本次预览 0 命中',
          'recoverable': true,
          'retrySameArguments': false,
        },
        'nextActions': <dynamic>[],
      });
      expect(out['ok'], isFalse);
      final err = out['error'] as Map<String, dynamic>;
      expect(err['code'], 'no_match');
      expect(err['recoverable'], isTrue);
      expect(err['retrySameArguments'], isFalse);
      // 诊断数据必须原样保留：调用方靠 totalMatched/previewUsable 判别失配，
      // 不能因为标了失败就把 data 清空。
      final data = out['data'] as Map<String, dynamic>;
      expect(data['totalMatched'], 0);
      expect(data['previewUsable'], isFalse);
    });
  });

  group('F-39 失败信封统一（2026-10-05 v11 复测）', () {
    test('file / so_analyze / patch_apk_dex_strings 三种形状 → 一致键集', () {
      final shapes = <String, Map<String, dynamic>>{
        // v11 实测形状 1：只有 error 对象（无顶层 message/recoverable/code）。
        'file': <String, dynamic>{
          'ok': false,
          'error': <String, dynamic>{
            'code': 'INVALID_PATH',
            'message': 'path 不是合法绝对路径',
            'severity': 'error',
            'recoverable': true,
            'retrySameArguments': false,
            'argument': 'path',
            'badValue': '/x',
            'diagnostics': <String, dynamic>{},
          },
        },
        // 形状 2：error + 顶层 message/recoverable，缺 code/nextActions。
        'so_analyze': <String, dynamic>{
          'ok': false,
          'error': <String, dynamic>{
            'code': 'RZ_ANALYZE_FAILED',
            'message': '分析失败',
          },
          'message': '分析失败',
          'recoverable': true,
        },
        // 形状 3：最全（顶层 code + error + message + recoverable + nextActions）。
        'patch_apk_dex_strings': <String, dynamic>{
          'ok': false,
          'code': 'NO_MATCH',
          'error': <String, dynamic>{
            'code': 'NO_MATCH',
            'message': '本次预览 0 命中',
            'severity': 'error',
            'recoverable': true,
            'retrySameArguments': false,
            'argument': 'replacements',
          },
          'message': '本次预览 0 命中',
          'recoverable': true,
          'nextActions': <dynamic>[],
        },
      };
      for (final entry in shapes.entries) {
        final map = ToolErrorPolicy.unifyFailure(entry.value);
        final err = map['error'] as Map<String, dynamic>;
        for (final key in <String>[
          'code',
          'message',
          'severity',
          'recoverable',
          'retrySameArguments',
          'diagnostics',
        ]) {
          expect(err.containsKey(key), isTrue, reason: '${entry.key} 缺 error.$key');
        }
        for (final key in <String>['code', 'message', 'recoverable', 'nextActions']) {
          expect(map.containsKey(key), isTrue, reason: '${entry.key} 缺顶层 $key');
        }
        expect(map['code'], err['code'], reason: '${entry.key} 顶层 code 与 error 同值');
        expect(map['recoverable'], err['recoverable'], reason: entry.key);
        expect(map['message'], isNotEmpty, reason: entry.key);
      }
      // 码归一（UPPER → lower）+ rawCode 双层保留。
      final file = ToolErrorPolicy.unifyFailure(shapes['file']!);
      final fileErr = file['error'] as Map<String, dynamic>;
      expect(fileErr['code'], 'invalid_path');
      expect(fileErr['rawCode'], 'INVALID_PATH');
      expect(file['rawCode'], 'INVALID_PATH');
    });
  });
}
