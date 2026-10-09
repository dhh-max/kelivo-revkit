import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/local_tools/local_tool_names.dart';
import 'package:Kelivo/core/services/local_tools/local_tool_registry.dart';
import 'package:Kelivo/core/services/local_tools/tool_lane_policy.dart';

/// 用户报告 #3 的回归锁：**重内存判定按 action，不按工具名**。
///
/// 病根：`so_analyze` 整个被当成重内存 → 它的纯读动作（hexdump/strings/workspaces/
/// pool/handles）既落写 lane、又排全局堆互斥，于是一个 `apk_rebuild` 跑着，这些
/// 读动作实测排队 27s+。
///
/// 这里同时锁住**两个维度正交**：lane（抢文件写锁）与 heavy（顶堆峰值）不是一回事——
/// blutter `analyze` 归读 lane（避免超时连坐写链路，N2 的历史结论）但**是**重内存
/// （真会起 runner + 建索引）。混为一谈会在某个方向上出错。
void main() {
  final readOnlyToolIds = LocalToolRegistry.readOnlyToolIds();

  bool ro(String name, [Map<String, dynamic> args = const {}]) =>
      ToolLanePolicy.isReadOnlyCall(name, args, readOnlyToolIds: readOnlyToolIds);
  bool heavy(String name, [Map<String, dynamic> args = const {}]) =>
      ToolLanePolicy.isHeavyCall(name, args);

  group('so_analyze 轻读动作：既不占写 lane，也不进堆互斥', () {
    test('裸读动作（报告点名的 hexdump/strings/workspaces/handles）', () {
      for (final action in const [
        'hexdump',
        'strings',
        'workspaces',
        'handles',
        'read_elf',
        'list',
        'overview',
        'status',
      ]) {
        expect(ro(LocalToolNames.soAnalyze, {'action': action}), isTrue,
            reason: '$action 应走读 lane');
        expect(heavy(LocalToolNames.soAnalyze, {'action': action}), isFalse,
            reason: '$action 不该进全局堆互斥（#3 的核心）');
      }
    });

    test('blutter 读类子动作（pool/xref/disasm/locate…）', () {
      for (final sub in const [
        'pool',
        'status',
        'result',
        'report',
        'packages',
        'xref',
        'callers',
        'disasm',
        'raw_strings',
        'inspect',
        'locate',
      ]) {
        final args = {'action': 'blutter', 'blutterAction': sub};
        expect(ro(LocalToolNames.soAnalyze, args), isTrue, reason: 'blutter $sub 走读 lane');
        expect(heavy(LocalToolNames.soAnalyze, args), isFalse,
            reason: 'blutter $sub 不产生堆峰值');
      }
    });
  });

  group('两个维度正交：该重的仍然重', () {
    test('blutter analyze 归读 lane，但仍是重内存', () {
      const args = {'action': 'blutter', 'blutterAction': 'analyze'};
      expect(ro(LocalToolNames.soAnalyze, args), isTrue,
          reason: 'N2 历史结论：analyze 归读 lane，避免超时连坐写链路');
      expect(heavy(LocalToolNames.soAnalyze, args), isTrue,
          reason: '它真的会起 runner + 建索引，必须留在堆互斥里');
    });

    test('blutter search/values/trace 可能建语义索引 → 仍是重内存', () {
      for (final sub in const ['search', 'values', 'trace']) {
        expect(heavy(LocalToolNames.soAnalyze, {'action': 'blutter', 'blutterAction': sub}),
            isTrue, reason: 'blutter $sub 可能触发语义索引构建');
      }
    });

    test('search 按 scope 分：pp 轻、asm 重', () {
      expect(heavy(LocalToolNames.soAnalyze, {'action': 'search', 'scope': 'pp'}), isFalse);
      expect(heavy(LocalToolNames.soAnalyze, {'action': 'search'}), isFalse,
          reason: '默认 scope 就是 pp');
      expect(heavy(LocalToolNames.soAnalyze, {'action': 'search', 'scope': 'asm'}), isTrue);
    });

    test('so_analyze 的写类动作不占读 lane 且是重内存', () {
      for (final action in const ['edit_hex', 'edit_asm', 'build', 'analyze_apk']) {
        expect(ro(LocalToolNames.soAnalyze, {'action': action}), isFalse,
            reason: '$action 是写类');
        expect(heavy(LocalToolNames.soAnalyze, {'action': action}), isTrue);
      }
    });
  });

  group('其它工具不受影响（改动不越界）', () {
    test('重内存工具名仍然重', () {
      for (final name in const ['apk_rebuild', 'apk_sign', 'jadx_decompile', 'rz_functions']) {
        expect(heavy(name), isTrue, reason: name);
      }
    });

    test('file 的读/写动作分得清', () {
      for (final a in const ['read', 'list', 'info', 'grep', 'strings', 'inventory']) {
        expect(ro(LocalToolNames.file, {'action': a}), isTrue, reason: 'file $a');
      }
      for (final a in const ['write', 'delete', 'mkdir', 'replace', 'move']) {
        expect(ro(LocalToolNames.file, {'action': a}), isFalse, reason: 'file $a 是写类');
      }
      expect(heavy(LocalToolNames.file, {'action': 'read'}), isFalse,
          reason: 'file 不是重内存工具');
    });

    test('未声明的工具默认既不只读也不重（保守）', () {
      expect(ro('some_unknown_tool'), isFalse);
      expect(heavy('some_unknown_tool'), isFalse);
    });
  });
}
