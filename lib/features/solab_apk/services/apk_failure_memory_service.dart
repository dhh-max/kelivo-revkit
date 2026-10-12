import '../../../core/models/memory_entry.dart';
import '../../../core/services/memory/memory_repository.dart';

/// A2（自研能力提升方案 §6.1）：失败记忆落库。
///
/// Task Command 固定链返回结构化 failureReason（NO_WRITER / NO_REFS /
/// MULTIPLE_WRITERS / BUDGET_EXHAUSTED / DEX_SEARCH_FAILED / ARTIFACT_MISSING
/// 等）时，按「APK + 链 + 失败原因 + 目标」为键去重落库——同键重复失败只
/// 递增 count 并刷新时间，不产生重复条目。读取面给链响应附最近失败摘要，
/// LLM 据此避免重复踩坑（§6.1「失败是经验」）。
abstract final class ApkFailureMemoryService {
  static const _assistantId = 'builtin-apk-mod';

  /// 每个 APP（[apkKey] = 包文件名）**最多保留**几条失败记忆。
  ///
  /// 用户 2026-10-04：「APP 更新之后，旧的只能用来存着、不一定使用……旧的完全
  /// 失效了，也不需要记忆，只需要保留几条即可」。失败记忆是自动落库的诊断
  /// 计数器（按 命令+失败原因+目标 去重、count 自增），只增不减会无限累积；
  /// 读取面 `load()` 默认也只取最近 5 条，所以存储侧同样保留最近 5 条。
  static const int keepPerApp = 5;

  /// 单条失败记录（content 是一句话可读摘要，结构化指纹在 extraJson）。
  ///
  /// 写入与「每 APP 只留 [keepPerApp] 条」的清理在同一个独占事务里完成，
  /// 不会出现「写进去了但没清」的中间态。
  static Future<void> recordFailure(
    MemoryRepository repo, {
    required String command,
    required String apkPath,
    required String failureReason,
    String target = '',
    String detail = '',
    DateTime? now,
  }) async {
    if (failureReason.trim().isEmpty) return;
    final ts = (now ?? DateTime.now()).toUtc();
    final apkKey = _apkKeyOf(apkPath);
    final dedupKey = _dedupKey(
      apkKey: apkKey,
      command: command,
      failureReason: failureReason,
      target: target,
    );
    await repo.runExclusive(() async {
      final all = await repo.readAll();
      MemoryEntry? hit;
      for (final e in all) {
        if (e.type == MemoryType.apkFailure &&
            (e.extraJson?['dedupKey'] ?? '') == dedupKey) {
          hit = e;
          break;
        }
      }
      final MemoryEntry next;
      if (hit != null) {
        final count = ((hit.extraJson?['count'] as num?)?.toInt() ?? 1) + 1;
        final lastDetail = (hit.extraJson?['detail'] ?? '').toString();
        next = hit.copyWith(
          updatedAt: ts,
          extraJson: {
            ...?hit.extraJson,
            'count': count,
            'lastSeenAt': ts.microsecondsSinceEpoch,
            if (detail.isNotEmpty && detail != lastDetail) 'detail': detail,
          },
        );
      } else {
        final content = _contentOf(
          command: command,
          failureReason: failureReason,
          target: target,
          detail: detail,
          apkPath: apkPath,
        );
        next = MemoryEntry(
          id: MemoryEntry.newId(),
          scope: MemoryScope.assistant,
          assistantId: _assistantId,
          type: MemoryType.apkFailure,
          content: content,
          source: MemorySource.tool,
          extraJson: {
            'dedupKey': dedupKey,
            'apkKey': apkKey,
            'apkPath': apkPath,
            'command': command,
            'failureReason': failureReason,
            if (target.isNotEmpty) 'target': target,
            if (detail.isNotEmpty) 'detail': detail,
            'count': 1,
            'timestamp': ts.microsecondsSinceEpoch,
          },
          createdAt: ts,
          updatedAt: ts,
        );
      }
      final kept = <MemoryEntry>[
        for (final e in all)
          if (e.id != next.id) e,
        next,
      ];
      await repo.writeAll(pruned(kept));
    });
  }

  /// 每 APP 只保留最近 [keepPerApp] 条失败记忆；其它类型原样返回。
  ///
  /// 纯函数（不改仓库），供写入路径与「清理」入口共用。
  static List<MemoryEntry> pruned(
    List<MemoryEntry> all, {
    int keepPerApp = ApkFailureMemoryService.keepPerApp,
  }) {
    final byApp = <String, List<MemoryEntry>>{};
    final kept = <MemoryEntry>[];
    for (final e in all) {
      if (e.type != MemoryType.apkFailure) {
        kept.add(e);
        continue;
      }
      final key = (e.extraJson?['apkKey'] ?? '').toString();
      byApp.putIfAbsent(key, () => <MemoryEntry>[]).add(e);
    }
    for (final list in byApp.values) {
      list.sort((a, b) => b.updatedAt.compareTo(a.updatedAt));
      kept.addAll(list.take(keepPerApp));
    }
    return kept;
  }

  /// 手动清理（管理页/维护用）：返回被清理掉的条数。
  static Future<int> pruneNow(
    MemoryRepository repo, {
    int keepPerApp = ApkFailureMemoryService.keepPerApp,
  }) {
    return repo.runExclusive(() async {
      final all = await repo.readAll();
      final kept = pruned(all, keepPerApp: keepPerApp);
      if (kept.length == all.length) return 0;
      await repo.writeAll(kept);
      return all.length - kept.length;
    });
  }

  /// 最近失败记录（时间倒序，最多 [limit] 条）。
  static Future<List<MemoryEntry>> load(
    MemoryRepository repo, {
    String? apkPath,
    int limit = 5,
  }) async {
    final all = await repo.readByType(MemoryType.apkFailure);
    final apkKey = apkPath == null ? null : _apkKeyOf(apkPath);
    final filtered = all.where((e) {
      if (apkKey == null) return true;
      return (e.extraJson?['apkKey'] ?? '') == apkKey;
    }).toList()
      ..sort((a, b) => b.updatedAt.compareTo(a.updatedAt));
    return filtered.take(limit).toList(growable: false);
  }

  /// 给链响应附的最近失败摘要（机器可读 + 一句话），空列表时不注入。
  static Future<List<Map<String, dynamic>>> summaryForPrompt(
    MemoryRepository repo, {
    String? apkPath,
    int limit = 3,
  }) async {
    final entries = await load(repo, apkPath: apkPath, limit: limit);
    return [
      for (final e in entries)
        {
          'failureReason': e.extraJson?['failureReason'] ?? '',
          'command': e.extraJson?['command'] ?? '',
          if ((e.extraJson?['target'] ?? '').toString().isNotEmpty)
            'target': e.extraJson?['target'],
          'count': e.extraJson?['count'] ?? 1,
          'lastSeenAt': e.updatedAt.toIso8601String(),
          'summary': e.content,
        },
    ];
  }

  static String _contentOf({
    required String command,
    required String failureReason,
    required String target,
    required String detail,
    required String apkPath,
  }) {
    final buf = StringBuffer('$command 在 $failureReason 处收束');
    if (target.isNotEmpty) buf.write('（目标: $target）');
    if (apkPath.isNotEmpty) buf.write(' · ${_apkKeyOf(apkPath)}');
    buf.write('；已重复出现请勿重试同一探针');
    if (detail.isNotEmpty) buf.write(' · $detail');
    return buf.toString();
  }

  /// APK 路径指纹：取文件名 + 大小尾缀（路径跨设备/搬移仍能对上同一包）。
  static String _apkKeyOf(String apkPath) {
    if (apkPath.isEmpty) return 'unknown';
    final name = apkPath.split(RegExp(r'[\\/]')).last;
    return name;
  }

  static String _dedupKey({
    required String apkKey,
    required String command,
    required String failureReason,
    required String target,
  }) =>
      [apkKey, command, failureReason, target].join('\u001f');
}
