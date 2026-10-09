import 'dart:collection';
import 'dart:convert';

import 'local_tool_names.dart';

class ToolCallLoopDecision {
  const ToolCallLoopDecision._({
    required this.allowed,
    this.message = '',
    this.reminder = '',
  });

  const ToolCallLoopDecision.allowed({String reminder = ''})
    : this._(allowed: true, reminder: reminder);

  const ToolCallLoopDecision.blocked(String message)
    : this._(allowed: false, message: message);

  final bool allowed;
  final String message;

  /// 放行但附带提醒（首次/二次重复）：调用方应把提醒注入结果带给模型。
  final String reminder;
}

/// Detects repeated tool calls inside a short sliding window.
///
/// A window catches both consecutive repeats and short cycles such as A-B-C-A.
/// Polling calls are ignored because their result can legitimately change.
class ToolCallLoopGuard {
  ToolCallLoopGuard({this.windowSize = 12, this.blockAfterRepeats = 3})
    : assert(windowSize > 0),
      assert(blockAfterRepeats >= 2);

  final int windowSize;

  /// 同一指纹在窗口内第几次出现才拦下（1=首次就拦，现状改为 3：
  /// 原始 1 次 + 两次重复都放行并提醒，第三次重复才拦）。
  ///
  /// 依据：拦错会破坏「写后读回自证」的验证闭环，而重复一次只是浪费一次调用
  /// ——两者代价不对称（见下方只读豁免的同一段推理）。
  final int blockAfterRepeats;

  final Queue<String> _recent = Queue<String>();
  final Map<String, int> _repeats = <String, int>{};

  ToolCallLoopDecision check(
    String name,
    Map<String, dynamic> arguments, {
    bool polling = false,
    bool readOnly = false,
  }) {
    if (polling) return const ToolCallLoopDecision.allowed();
    // 只读调用**不进环路窗口**（用户报告 #1，第三轮实测推翻上一轮的判断）：
    // 读是**新观测**，不是重复证据——剪贴板、计数器、状态查询这类返回值本来就会
    // 随外部变化，`read → read(同参)` 的第二次读是合法复核。旧行为把它当重复拦掉，
    // 于是"改完一个状态用工具自证"这个闭环根本做不了。
    //
    // 代价：agent 可能把同一个只读调用打很多次。这是**浪费一次调用**，而拦错会
    // **破坏验证闭环**——两者不对称，所以选择放行（浪费由调用方自己的预算约束管）。
    if (readOnly) return const ToolCallLoopDecision.allowed();

    final fingerprint = _fingerprint(name, arguments);
    if (_recent.contains(fingerprint)) {
      final repeats = (_repeats[fingerprint] ?? 1) + 1;
      _repeats[fingerprint] = repeats;
      if (repeats < blockAfterRepeats) {
        return ToolCallLoopDecision.allowed(
          reminder:
              'LOOP_REMINDER: $name 已用相同参数重复 $repeats 次（滑窗内）。'
              '若这是有意复核，请说明依据；否则换参数、地址、分页游标或分析路径。'
              '再重复 ${blockAfterRepeats - repeats} 次将被拦下。',
        );
      }
      return ToolCallLoopDecision.blocked(
        'LOOP_DETECTED: $name 在滑窗内第 $repeats 次用相同参数调用，已拦下。'
        '请使用已有结果，或更换参数、地址、分页游标或分析路径；不要重复验证同一证据。',
      );
    }

    _recent.addLast(fingerprint);
    _repeats[fingerprint] = 1;
    while (_recent.length > windowSize) {
      final evicted = _recent.removeFirst();
      final left = (_repeats[evicted] ?? 0) - 1;
      if (left <= 0) {
        _repeats.remove(evicted);
      } else {
        _repeats[evicted] = left;
      }
    }
    return const ToolCallLoopDecision.allowed();
  }

  void reset() {
    _recent.clear();
    _repeats.clear();
  }

  /// 移除一次调用的指纹（超时/异常/网络中断后调用）：
  /// 失败的调用没有可信结果，客户端网络恢复后的相同参数重试是合理恢复
  /// 路径，不应被 LOOP_DETECTED 拦截。
  void forget(String name, Map<String, dynamic> arguments) {
    final fingerprint = _fingerprint(name, arguments);
    _recent.remove(fingerprint);
    _repeats.remove(fingerprint);
  }

  /// A successful write makes earlier read fingerprints stale. Keep the write
  /// itself so an immediate duplicate mutation is still blocked.
  void advanceState(String name, Map<String, dynamic> arguments) {
    final fingerprint = _fingerprint(name, arguments);
    _recent
      ..clear()
      ..addLast(fingerprint);
    _repeats
      ..clear()
      ..[fingerprint] = 1;
  }

  static bool changesState(String name, Map<String, dynamic> arguments) {
    if (const <String>{
      'analyze_apk_workspace',
      'patch_apk_dex_methods',
      'patch_apk_dex_strings',
      'signature_bypass',
      'patch_apk_manifest',
      'apk_rebuild',
      'apk_sign',
      'so_patch_into_apk',
      'cleanup_apk_builds',
      'apk_note_write',
      'save_apk_patch_memory',
      'record_apk_patch_verification',
      'ask_user_input_v0',
      // 用户报告 #7：写后读回被 LOOP_DETECTED 拦住。这些"写"能让随后的"读"结果
      // 变化，漏在名单外时窗口不清 → `读 → 写 → 读(同参)` 的第二次读被当成重复，
      // 于是「写后读回校验」这个闭环做不了。
      LocalToolNames.clipboard,
      LocalToolNames.calendarCreate,
      LocalToolNames.remindersCreate,
      LocalToolNames.remindersComplete,
      LocalToolNames.memoryUpdate,
      LocalToolNames.memoryEdit,
      LocalToolNames.memoryDelete,
    }.contains(name)) {
      // clipboard_tool 只有 write 改状态，read 不改——按 action 细分，别把读也当写。
      if (name == LocalToolNames.clipboard) {
        return arguments['action']?.toString() == 'write';
      }
      return true;
    }
    if (name == 'file') {
      return const <String>{
        'write',
        'copy',
        'move',
        'rename',
        'delete',
        'mkdir',
      }.contains(arguments['action']?.toString());
    }
    if (name != 'so_analyze') return false;
    final action = arguments['action']?.toString();
    if (action == 'blutter') {
      return const <String>{
        'analyze',
        'cancel',
        'locate',
        'prune',
      }.contains(arguments['blutterAction']?.toString());
    }
    return const <String>{
      'set_work_dir',
      'open',
      'open_url',
      'close',
      'analyze_apk',
      'edit_open',
      'edit_snapshot',
      'edit_rollback',
      'edit_undo',
      'edit_redo',
      'edit_reset',
      'edit_hex',
      'edit_asm',
      'edit_symbol',
      'fix_sections',
      'build',
      'build_many',
      'lief_patch_address',
      'lief_add_export',
      'lief_remove_symbol',
    }.contains(action);
  }

  /// 判定工具输出是否成功。
  ///
  /// 快路径（2026-09-15 逐工具性能复查）：输出可达 512KB，旧实现对每个
  /// 本地结果做一次全量 jsonDecode 仅为判 ok——分配整棵对象树代价过高。
  /// 先用零分配子串扫描排除失败标记；只有命中可疑标记或非预期形态时才
  /// 退回全量 decode 做精确判定。jsonEncode 恒输出紧凑形态（`"ok":false`
  /// 无空格），子串匹配安全；凡带可疑空格的形态一律走慢路径兜底。
  static bool succeeded(String output) {
    final trimmed = output.trimLeft();
    // 非 JSON 对象（纯文本 / 数组 / 标量）：与原 decode 语义一致，视为未成功。
    if (!trimmed.startsWith('{')) return false;
    // 可疑失败标记（含带空格变体）→ 慢路径精确判定。
    final suspicious = RegExp(
      r'"(?:ok|success)"\s*:\s*false|"error"\s*:\s*[\{"]|"status"\s*:\s*"',
    ).hasMatch(trimmed);
    if (!suspicious) {
      // 无失败标记且顶层是对象：成功。"error":null/false/"" 均不算失败，
      // 与慢路径语义一致。
      return true;
    }
    try {
      final decoded = jsonDecode(output);
      if (decoded is! Map) return false;
      if (decoded['ok'] == false) return false;
      if (decoded['success'] == false) return false;
      final error = decoded['error'];
      if (error != null && error != false && error != '') return false;
      final status = decoded['status']?.toString().toLowerCase();
      return !const {'error', 'failed', 'failure', 'invalid'}.contains(status);
    } catch (_) {
      return false;
    }
  }

  String _fingerprint(String name, Map<String, dynamic> arguments) =>
      fingerprintOf(name, arguments);

  /// 与滑窗内部完全同源的调用指纹（会话无关，键序已规范化）。
  ///
  /// MCP 面用它给"被闸门拦下的只读重复调用"命中回放缓存——判定与缓存必须是
  /// 同一把尺子，否则会出现"拦了却回放不到"的死角。
  static String fingerprintOf(String name, Map<String, dynamic> arguments) =>
      '$name|${jsonEncode(_canonicalize(arguments))}';

  static dynamic _canonicalize(dynamic value) {
    if (value is Map) {
      final entries =
          value.entries
              .map((entry) => MapEntry(entry.key.toString(), entry.value))
              .toList()
            ..sort((a, b) => a.key.compareTo(b.key));
      return <String, dynamic>{
        for (final entry in entries) entry.key: _canonicalize(entry.value),
      };
    }
    if (value is List) return value.map(_canonicalize).toList();
    return value;
  }
}
