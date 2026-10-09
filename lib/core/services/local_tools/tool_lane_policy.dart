/// 工具调用的**车道/重内存**判定策略（纯函数，可单测）。
///
/// 为什么单独抽出来（2026-09-21 用户报告 #3）：
/// 判定原先写在 MCP server 里、且**按工具名**分组——`so_analyze` 整个被当成重内存，
/// 于是它的纯读动作（hexdump/strings/workspaces/pool/handles）既落在**写 lane**、
/// 又要排队等全局重内存互斥：一个 `apk_rebuild` 跑着，这些读动作实测排队 **27s+**。
/// 抽成纯策略后：① 判定可单测、改错会被测试挡住；② 两个维度分开表达——
///   - **lane**（read/write）：谁和谁抢文件写锁；
///   - **heavy**（要不要进全局堆互斥）：谁会顶出堆峰值。
/// 这两个维度**不等价**：blutter `analyze` 归读 lane（避免超时连坐写链路）但**是**重内存
/// （它真的会起 runner + 建索引）。混为一谈就会在某个方向上出错。
library;

import 'local_tool_names.dart';

/// 工具调用在 lane / 重内存两个维度上的判定。
abstract final class ToolLanePolicy {
  ToolLanePolicy._();

  /// 重内存工具名（**按工具名**成立的那些）。`so_analyze` 的轻读动作见
  /// [lightSoAnalyzeActions]——它们不产生堆峰值，不进全局堆互斥。
  static const Set<String> heavyMemoryTools = <String>{
    'patch_apk_dex_strings',
    'patch_apk_dex_methods',
    'patch_apk_manifest',
    'apk_rebuild',
    'apk_sign',
    'so_patch_into_apk',
    'signature_bypass',
    'so_analyze',
    'dex_search',
    'dex_xref',
    'dex_class_outline',
    'smali_read',
    'apk_archive',
    'jadx_decompile',
    'rz_functions',
  };

  /// `file` 的只读动作。
  static const Set<String> readOnlyFileActions = <String>{
    'inventory',
    'read',
    'list',
    'info',
    'grep',
    'strings',
  };

  /// `so_analyze` 里**确定不产生堆峰值、也不写文件**的动作。
  ///
  /// 判定方向刻意选"只读白名单"而不是"写黑名单"：漏标一个重动作会让两个重任务
  /// 并发（OOM 风险），漏标一个轻动作只是少省一点排队——前者危险，后者只是慢。
  static const Set<String> lightSoAnalyzeActions = <String>{
    // 读 ELF / 原始数据
    'read_elf', 'read_stats', 'hexdump', 'strings', 'list', 'overview',
    'analysis_report', 'crypto_scan', 'jni_bridge',
    // 会话与清单（读）
    'workspaces', 'list_sources', 'list_builds', 'list_audits',
    'asset_status', 'suggest', 'capabilities', 'handles',
    'diff', 'rz_diff', 'audit', 'audit_load', 'status',
  };

  /// `so_analyze(action=blutter)` 里**确定不产生堆峰值**的子动作。
  ///
  /// 刻意**不含** `analyze`（起 runner + 建索引）、`search`/`values`/`trace`
  /// （可能触发语义索引构建）——那几个仍是重内存，别为了省排队把堆保护拆了。
  static const Set<String> lightBlutterActions = <String>{
    'pool', 'status', 'result', 'report', 'packages',
    'xref', 'callers', 'disasm', 'raw_strings', 'inspect', 'locate',
  };

  /// blutter 子动作里归**读 lane** 的集合（lane 维度，与 heavy 维度分开）。
  ///
  /// 这是 N2 的历史结论：`analyze` 时长可达分钟级，放写 lane 一旦超时会连坐**所有**
  /// 写工具（全局可用性故障），所以它归读 lane；但它**仍是重内存**（见
  /// [lightBlutterActions] 的注释）。两个维度不能合并成一套集合——这正是本文件
  /// 存在的理由，测试 `tool_lane_policy_test.dart` 锁着这条正交性。
  static const Set<String> readLaneBlutterActions = <String>{
    // N2 原集合（analyze/search/values/prune 也在这里）
    'analyze', 'status', 'search', 'values', 'report', 'packages', 'prune',
    'locate', 'disasm', 'result',
    // 本批补入的轻读子动作（此前不在名单里 → 落写 lane 被重任务饿死）
    'pool', 'xref', 'callers', 'raw_strings', 'inspect', 'diff',
  };

  /// 是否只读调用（决定走读 lane 还是写 lane）。
  static bool isReadOnlyCall(
    String name,
    Map<String, dynamic> args, {
    required Set<String> readOnlyToolIds,
  }) {
    if (readOnlyToolIds.contains(name)) return true;
    if (name == LocalToolNames.file) {
      return readOnlyFileActions.contains(args['action']?.toString());
    }
    if (name == LocalToolNames.soAnalyze) {
      final action = args['action']?.toString() ?? '';
      if (action == 'blutter') {
        // N2 的既有结论保留：blutter 读类子动作归读 lane——放写 lane 一旦超时会
        // 连坐所有写工具（历史全局可用性故障）。注意 `analyze` 也在这里（它重，
        // 但归读 lane），"重"由 isHeavyCall 单独表达。
        return readLaneBlutterActions.contains(args['blutterAction']?.toString());
      }
      return lightSoAnalyzeActions.contains(action);
    }
    return false;
  }

  /// 是否重内存调用（决定要不要进全局堆互斥）。
  ///
  /// **按 action 细分**：`so_analyze` 的轻读动作不产生堆峰值，不该排在重任务后面
  /// （用户报告 #3：apk_rebuild 跑着时这些读动作排队 27s+）。
  static bool isHeavyCall(String name, Map<String, dynamic> args) {
    if (!heavyMemoryTools.contains(name)) return false;
    if (name == LocalToolNames.soAnalyze) {
      final action = args['action']?.toString() ?? '';
      if (action == 'blutter') {
        return !lightBlutterActions.contains(args['blutterAction']?.toString());
      }
      // search 的 pp 维度只读底账（亚秒级）；asm 维度会建语义索引 → 仍是重内存。
      if (action == 'search') {
        final scope = (args['scope']?.toString() ?? 'pp').toLowerCase();
        return scope != 'pp';
      }
      return !lightSoAnalyzeActions.contains(action);
    }
    return true;
  }
}
