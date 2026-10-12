import 'package:flutter_test/flutter_test.dart';
import 'package:Kelivo/core/services/local_tools/loop_reminder.dart';
import 'package:Kelivo/core/services/local_tools/tool_call_loop_guard.dart';

void main() {
  test('short cycle: first repeat is reminded, second repeat is blocked', () {
    final guard = ToolCallLoopGuard();

    expect(guard.check('xref', {'offset': 1}).allowed, isTrue);
    expect(guard.check('blutter', {'va': '0xe0f34c'}).allowed, isTrue);
    expect(guard.check('disasm', {'va': '0xe0f34c'}).allowed, isTrue);

    // 2026-10-02 分级：首次重复只提醒（不打断「复核」闭环），再重复才拦。
    final firstRepeat = guard.check('xref', {'offset': 1});
    expect(firstRepeat.allowed, isTrue);
    expect(firstRepeat.reminder, contains('LOOP_REMINDER'));
    expect(guard.check('xref', {'offset': 1}).allowed, isFalse);
  });

  test('canonicalizes nested map key order', () {
    final guard = ToolCallLoopGuard();

    expect(
      guard.check('search', {
        'filters': {'kind': 'string', 'limit': 10},
      }).allowed,
      isTrue,
    );
    final repeat = guard.check('search', {
      'filters': {'limit': 10, 'kind': 'string'},
    });
    expect(repeat.allowed, isTrue, reason: '同参首次重复只提醒');
    expect(repeat.reminder, isNotEmpty);
    expect(
      guard
          .check('search', {
            'filters': {'limit': 10, 'kind': 'string'},
          })
          .allowed,
      isFalse,
      reason: '同参第二次重复才拦',
    );
  });

  test('does not track polling calls', () {
    final guard = ToolCallLoopGuard();

    expect(guard.check('status', const {}, polling: true).allowed, isTrue);
    expect(guard.check('status', const {}, polling: true).allowed, isTrue);
  });

  test('forgets fingerprints outside the window', () {
    final guard = ToolCallLoopGuard(windowSize: 2);

    expect(guard.check('a', const {}).allowed, isTrue);
    expect(guard.check('b', const {}).allowed, isTrue);
    expect(guard.check('c', const {}).allowed, isTrue);
    expect(guard.check('a', const {}).allowed, isTrue);
  });

  test('forget allows retrying a failed (timeout/network) call', () {
    final guard = ToolCallLoopGuard();

    expect(
      guard.check('file', {'action': 'read', 'path': 'a.txt'}).allowed,
      isTrue,
    );
    guard.forget('file', {'action': 'read', 'path': 'a.txt'});
    expect(
      guard.check('file', {'action': 'read', 'path': 'a.txt'}).allowed,
      isTrue,
    );
  });

  test('state change invalidates stale reads but keeps duplicate write blocked', () {
    final guard = ToolCallLoopGuard();

    expect(guard.check('get_current_apk_report', const {}).allowed, isTrue);
    expect(guard.check('analyze_apk_workspace', const {}).allowed, isTrue);
    guard.advanceState('analyze_apk_workspace', const {});

    expect(guard.check('get_current_apk_report', const {}).allowed, isTrue);
    // 写后同参重复：首次提醒，再重复才拦。
    expect(
      guard.check('analyze_apk_workspace', const {}).allowed,
      isTrue,
      reason: '首次重复放行并提醒',
    );
    expect(guard.check('analyze_apk_workspace', const {}).allowed, isFalse);
  });

  test('classifies Blutter reads and writes separately', () {
    expect(
      ToolCallLoopGuard.changesState('so_analyze', const {
        'action': 'disasm',
      }),
      isFalse,
    );
    expect(
      ToolCallLoopGuard.changesState('so_analyze', const {
        'action': 'blutter',
        'blutterAction': 'locate',
      }),
      isTrue,
    );
  });

  test('does not advance state after failed tool output', () {
    expect(ToolCallLoopGuard.succeeded('{"ok":false}'), isFalse);
    expect(ToolCallLoopGuard.succeeded('{"success":false}'), isFalse);
    expect(ToolCallLoopGuard.succeeded('{"status":"failed"}'), isFalse);
    expect(ToolCallLoopGuard.succeeded('{"ok":true}'), isTrue);
  });

  test('succeeded fast path keeps exact decode semantics', () {
    // 快路径（2026-09-15）：大结果跳过全量 jsonDecode，但语义必须与原实现一致。
    expect(ToolCallLoopGuard.succeeded('{"ok":true,"error":""}'), isTrue);
    expect(ToolCallLoopGuard.succeeded('{"ok":true,"error":null}'), isTrue);
    expect(
      ToolCallLoopGuard.succeeded('{"error":{"code":"invalid_args"}}'),
      isFalse,
    );
    expect(ToolCallLoopGuard.succeeded('{"error":"invalid_args"}'), isFalse);
    expect(ToolCallLoopGuard.succeeded('{ "ok": false }'), isFalse);
    expect(ToolCallLoopGuard.succeeded('{"status":"Error"}'), isFalse);
    expect(ToolCallLoopGuard.succeeded('{"status":"ok"}'), isTrue);
    expect(
      ToolCallLoopGuard.succeeded('{"ok":true,"data":{"ok":false}}'),
      isTrue,
    );
    expect(ToolCallLoopGuard.succeeded('plain text output'), isFalse);
    expect(ToolCallLoopGuard.succeeded('[1,2,3]'), isFalse);
    final big = '{"ok":true,"data":"${'x' * 600000}"}';
    expect(ToolCallLoopGuard.succeeded(big), isTrue);
  });

  /// 用户报告 #1：只读动作的同参复核也被拦——读是**新观测**，不是重复证据。
  group('只读同参复核必须放行（#1）', () {
    test('窗口成员 = 改状态的调用（clipboard read / calculate 都不在内）', () {
      for (final probe in const [
        ('clipboard_tool', {'action': 'read'}),
        ('calculate', {'expression': '1+1'}),
        ('get_time_info', <String, dynamic>{}),
        ('file', {'action': 'info', 'path': '/x'}),
        ('so_analyze', {'action': 'handles'}),
      ]) {
        expect(
          ToolCallLoopGuard.changesState(probe.$1, probe.$2),
          isFalse,
          reason: '${probe.$1} 不改状态 → 应可重复（不进环路窗口）',
        );
      }
      for (final probe in const [
        ('clipboard_tool', {'action': 'write', 'text': 'x'}),
        ('file', {'action': 'delete', 'path': '/x'}),
        ('apk_rebuild', <String, dynamic>{}),
      ]) {
        expect(
          ToolCallLoopGuard.changesState(probe.$1, probe.$2),
          isTrue,
          reason: '${probe.$1} 改状态 → 必须留在窗口里',
        );
      }
    });

    test('连续同参只读：readOnly=true 时不拦', () {
      final guard = ToolCallLoopGuard();
      const readArgs = {'action': 'read'};
      for (var i = 0; i < 5; i++) {
        expect(
          guard.check('clipboard_tool', readArgs, readOnly: true).allowed,
          isTrue,
          reason: '第 ${i + 1} 次同参只读都应放行（#1 的原症状）',
        );
      }
    });

    test('只读不写进窗口：随后的写重复仍会被拦', () {
      final guard = ToolCallLoopGuard();
      const readArgs = {'action': 'read'};
      const writeArgs = {'action': 'write', 'text': 'x'};
      for (var i = 0; i < 5; i++) {
        guard.check('clipboard_tool', readArgs, readOnly: true);
      }
      expect(
        guard.check('clipboard_tool', writeArgs).allowed,
        isTrue,
        reason: '首次写',
      );
      final repeat = guard.check('clipboard_tool', writeArgs);
      expect(repeat.allowed, isTrue, reason: '同参重复写首次只提醒');
      expect(repeat.reminder, isNotEmpty);
      expect(
        guard.check('clipboard_tool', writeArgs).allowed,
        isFalse,
        reason: '同参重复写仍会拦（第三次）——环路闸门本来的职责',
      );
    });

    test('写后读回（#7 场景）在 readOnly 语义下依然通', () {
      final guard = ToolCallLoopGuard();
      const readArgs = {'action': 'read'};
      const writeArgs = {'action': 'write', 'text': 'hello'};
      guard.check('clipboard_tool', readArgs, readOnly: true);
      guard.advanceState('clipboard_tool', writeArgs);
      expect(
        guard.check('clipboard_tool', readArgs, readOnly: true).allowed,
        isTrue,
      );
    });
  });

  /// 用户报告 #7：`读 → 写 → 读(同参)` 的第二次读被拦住，写后读回闭环做不了。
  group('写后读回不被环路闸门拦（#7）', () {
    test('剪贴板：write 改状态、read 不改（按 action 细分）', () {
      expect(
        ToolCallLoopGuard.changesState('clipboard_tool', {
          'action': 'write',
          'text': 'x',
        }),
        isTrue,
      );
      expect(
        ToolCallLoopGuard.changesState('clipboard_tool', {'action': 'read'}),
        isFalse,
        reason: '读不该被当成写，否则它自己会把窗口清掉',
      );
    });

    test('日历/提醒/记忆的写入也改状态（原先全漏）', () {
      for (final name in const [
        'calendar_create',
        'reminders_create',
        'reminders_complete',
        'memory_update',
        'memory_edit',
        'memory_delete',
      ]) {
        expect(
          ToolCallLoopGuard.changesState(name, const {}),
          isTrue,
          reason: name,
        );
      }
    });

    test('端到端：读 → 写 → 读(同参) 第二次必须放行', () {
      final guard = ToolCallLoopGuard();
      const readArgs = {'action': 'read'};
      const writeArgs = {'action': 'write', 'text': 'hello'};

      expect(guard.check('clipboard_tool', readArgs).allowed, isTrue);
      // 不带 readOnly 时同参读会进窗口：分级后首次重复只提醒（彻底豁免见上一组）。
      expect(guard.check('clipboard_tool', readArgs).allowed, isTrue);

      expect(
        ToolCallLoopGuard.changesState('clipboard_tool', writeArgs),
        isTrue,
      );
      guard.advanceState('clipboard_tool', writeArgs);

      expect(
        guard.check('clipboard_tool', readArgs).allowed,
        isTrue,
        reason: '写后读回必须放行——否则无法校验写入结果（#7 的原症状）',
      );
    });
  });

  group('分级与提醒注入（2026-10-02）', () {
    test('blockAfterRepeats 可配：2 表示第 2 次相同调用就拦', () {
      final guard = ToolCallLoopGuard(blockAfterRepeats: 2);
      expect(guard.check('a', const {}).allowed, isTrue, reason: '原始调用');
      expect(
        guard.check('a', const {}).allowed,
        isFalse,
        reason: '阈值 2：第 2 次相同调用即拦',
      );
    });

    test('提醒里带重复次数与剩余次数', () {
      final guard = ToolCallLoopGuard();
      guard.check('a', const {});
      final first = guard.check('a', const {});
      expect(first.reminder, contains('重复 2 次'));
      expect(first.reminder, contains('再重复 1 次'));
      final second = guard.check('a', const {});
      expect(second.allowed, isFalse, reason: '第 3 次相同调用被拦');
      expect(second.message, contains('第 3 次'));
    });

    test('写操作清窗后计数一起归零（不会因旧计数提前拦）', () {
      final guard = ToolCallLoopGuard();
      guard.check('a', const {});
      guard.check('a', const {}); // 计数 2
      guard.advanceState('a', const {});
      expect(
        guard.check('a', const {}).allowed,
        isTrue,
        reason: '清窗后从 1 起算，这一次是第 2 次',
      );
      expect(
        guard.check('a', const {}).allowed,
        isFalse,
        reason: '第 3 次相同调用被拦（旧计数没有残留，否则会更早拦）',
      );
    });

    test('窗口淘汰后计数被清理（远距离同参不累计）', () {
      final guard = ToolCallLoopGuard(windowSize: 1);
      guard.check('a', const {});
      guard.check('a', const {}); // 计数 2，提醒
      guard.check('b', const {}); // a 被淘汰
      expect(guard.check('a', const {}).allowed, isTrue, reason: '淘汰后从头计');
    });

    test('appendLoopReminder：JSON 结果加字段，纯文本追加一行', () {
      expect(
        appendLoopReminder('{"ok":true}', 'REM'),
        '{"ok":true,"loopReminder":"REM"}',
      );
      expect(appendLoopReminder('plain', 'REM'), 'plain\n\nREM');
      expect(appendLoopReminder('{"ok":true}', ''), '{"ok":true}');
      expect(appendLoopReminder(null, 'REM'), isNull);
      expect(appendLoopReminder(null, ''), isNull);
    });

    test('appendLoopReminder：嵌套 JSON 保留原字段', () {
      final out = appendLoopReminder('{"ok":true,"data":{"n":1}}', 'REM');
      expect(out, contains('"data":{"n":1}'));
      expect(out, contains('"loopReminder":"REM"'));
    });
  });
}
