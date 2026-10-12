import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/local_tools/dart_tool_stats.dart';

/// Dart 面工具耗时记账（C 批 / §14.15.6）单测。
///
/// 这些断言钉的是**读数的可信度**：窗口内 p95、有界内存、失败样本带错误码。
/// 数字本身没有对错，但"记错样本/样本无界/失败不记账"会让 C 批后续的对比
/// 全部失去意义。
void main() {
  setUp(DartToolStats.reset);
  tearDown(DartToolStats.reset);

  test('聚合字段与 Kotlin 侧同形（含 p50/p95/max/lastError）', () {
    DartToolStats.record('string_scan', true, 5700 * 1000);
    DartToolStats.record('string_scan', true, 300 * 1000);
    DartToolStats.record(
      'string_scan',
      false,
      1200 * 1000,
      error: 'path_out_of_scope',
    );

    final snap = DartToolStats.snapshot();
    expect(snap['totalCalls'], 3);
    expect(snap['totalOk'], 2);
    expect(snap['totalFailed'], 1);
    expect(snap['distinctTools'], 1);

    final row = (snap['tools'] as List).single as Map<String, Object?>;
    expect(row['tool'], 'string_scan');
    expect(row['calls'], 3);
    expect(row['ok'], 2);
    expect(row['failed'], 1);
    // 5700+300+1200 ms / 3 = 2400ms（整数除法，与 Kotlin 一致）
    expect(row['avgMs'], 2400);
    expect(row['maxMs'], 5700);
    expect(row['sampleCount'], 3);
    expect(row['lastError'], 'path_out_of_scope');
    expect(row['lastAt'], greaterThan(0));
    // 样本升序 [300,1200,5700]：p50 → 1200ms（ceil(0.5*3)-1 = 1），p95 → 5700ms
    expect(row['p50Ms'], 1200);
    expect(row['p95Ms'], 5700);
  });

  test('样本只保留最近 64 个（p95 是窗口口径，不是全历史）', () {
    // 第 i 次记 (i+1) 毫秒 → micros = (i+1)*1000。
    for (var i = 0; i < 70; i++) {
      DartToolStats.record('dex_search', true, (i + 1) * 1000);
    }
    final row = (DartToolStats.snapshot()['tools'] as List).single
        as Map<String, Object?>;
    expect(row['calls'], 70);
    expect(row['sampleCount'], DartToolStats.recentSampleLimit);
    // max 按全历史算（与 Kotlin 一致）：第 70 次 = 70ms。
    expect(row['maxMs'], 70);
    // p95 只吃窗口内的 64 个样本（第 7..70 次 = 7..70ms）：
    // index = ceil(0.95*64)-1 = 60 → 升序第 61 个 = 67ms。
    expect(row['p95Ms'], 67);
    expect(row['p50Ms'], 38);
  });

  test('工具种类有上限，超限淘汰最久未更新的一项', () async {
    DartToolStats.record('apk_archive', true, 1000);
    await Future<void>.delayed(const Duration(milliseconds: 5));
    DartToolStats.record('dex_xref', true, 1000);
    await Future<void>.delayed(const Duration(milliseconds: 5));
    DartToolStats.record('string_scan', true, 1000);
    expect(DartToolStats.trackedToolCount, 3);

    DartToolStats.debugTrimTo(2);
    expect(DartToolStats.trackedToolCount, 2);
    final tools = (DartToolStats.snapshot()['tools'] as List)
        .map((e) => (e as Map)['tool'])
        .toList();
    expect(tools, isNot(contains('apk_archive')), reason: '最旧的应被淘汰');
    expect(tools, containsAll(<String>['dex_xref', 'string_scan']));
  });

  test('reset 清空（真机复测的"从零起算"口径）', () {
    DartToolStats.record('apk_sign', true, 500000);
    DartToolStats.reset();
    final snap = DartToolStats.snapshot();
    expect(snap['totalCalls'], 0);
    expect(snap['tools'], isEmpty);
    expect(DartToolStats.trackedToolCount, 0);
  });

  group('errorHint：只取码样值，取不到不猜', () {
    test('结构化形态（code 对象）', () {
      const output =
          '{"ok":false,"error":{"code":"path_out_of_scope","message":"…"}}';
      expect(DartToolStats.errorHint(output), 'path_out_of_scope');
    });

    test('咽喉处的字符串形态（handler 原样，code 对象是归一后才有的）', () {
      expect(
        DartToolStats.errorHint('{"ok":false,"error":"STEP_FAILED","message":"…"}'),
        'STEP_FAILED',
      );
    });

    test('人话消息不算码（含空格/过长一律不收）', () {
      expect(
        DartToolStats.errorHint(
          '{"ok":false,"error":"APK 目标不存在: /storage/emu/x.apk","message":"…"}',
        ),
        '',
      );
      expect(
        DartToolStats.errorHint('{"ok":false,"error":"${'A' * 41}"}'),
        '',
      );
    });

    test('无 code 字段回空串', () {
      expect(DartToolStats.errorHint('{"ok":false}'), '');
    });

    test('超大输出不扫（成功/长尾路径零额外解析的边界）', () {
      final huge = '{"ok":false,"error":{"code":"x"},"data":"${'a' * (64 * 1024)}"}';
      expect(DartToolStats.errorHint(huge), '');
    });
  });

  test('slowestTools 按 p95 降序（真机体检直接读头部）', () {
    DartToolStats.record('fast', true, 1000);
    DartToolStats.record('slow', true, 900000);
    final slowest = DartToolStats.snapshot()['slowestTools'] as List;
    expect((slowest.first as Map)['tool'], 'slow');
  });

  /// 报告 2-7：统计键由调用方拼装，畸形参数会在账本里造出伪工具
  /// （真机实测出现过 `so_analyze:blutter<tool_sep:…"rz_command":…`）。
  group('统计键清洗（报告 2-7）', () {
    test('畸形参数不再污染键', () {
      final cleaned = DartToolStats.sanitizeToolKey(
        'so_analyze:blutter<tool_sep:{"rz_command":"pd 40 @ 0x91f6e0"}',
      );
      expect(cleaned.startsWith('so_analyze:blutter'), isTrue);
      for (final bad in const ['<', '"', '{', '}', ' ']) {
        expect(cleaned.contains(bad), isFalse, reason: '不应含 $bad');
      }
      expect(cleaned.length, lessThanOrEqualTo(64));
    });

    test('正常键保持不变', () {
      for (final key in const [
        'so_analyze:disasm',
        'file',
        'todo_write',
        'apk_rebuild',
        'so_analyze:blutter.locate-1',
      ]) {
        expect(DartToolStats.sanitizeToolKey(key), key);
      }
    });

    test('清洗后为空记 unknown；超长截断到 64', () {
      expect(DartToolStats.sanitizeToolKey('   '), 'unknown');
      expect(DartToolStats.sanitizeToolKey(''), 'unknown');
      expect(DartToolStats.sanitizeToolKey('a' * 200).length, 64);
    });

    test('record 走清洗：账本里不会再出现含畸形字符的键', () {
      DartToolStats.record('so_analyze:x<bad:"1"', true, 1000);
      DartToolStats.record('so_analyze:x<bad:"2"', true, 1000);
      final tools = DartToolStats.snapshot()['tools'] as List;
      expect(tools.length, 2, reason: '参数不同 = 不同调用，不该被并成一条');
      for (final entry in tools) {
        final key = (entry as Map)['tool'].toString();
        for (final bad in const ['<', '"', ' ']) {
          expect(key.contains(bad), isFalse, reason: '账本键不应含 $bad：$key');
        }
      }
      // 同一畸形串重复调用才会聚合（证明键是确定性的）。
      DartToolStats.reset();
      DartToolStats.record('so_analyze:x<bad:"1"', true, 1000);
      DartToolStats.record('so_analyze:x<bad:"1"', true, 1000);
      expect((DartToolStats.snapshot()['tools'] as List).length, 1);
    });
  });
}
