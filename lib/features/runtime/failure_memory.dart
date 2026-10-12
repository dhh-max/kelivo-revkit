/// 失败记忆（§17.2 / §17.4）。
///
/// 与已有的 PatchMemory（改包经验）不同：这里记的是**工具/路线层面的失败模式**，
/// 目的是「避免同一个坑反复踩」，并且必须带作用域和失效时间，
/// 不能永久污染新任务（§17.4）。
library;

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import 'task_store.dart';

/// 失败作用域：决定了这条经验能被哪些任务参考。
class FailureScope {
  FailureScope._();

  /// 只对当前任务有效。
  static const task = 'task';

  /// 对同一个 APK（按指纹）有效。
  static const apk = 'apk';

  /// 全局工具经验，如「字段声明查询不含字段消费点」。
  static const tool = 'tool';
}

/// 失败处理结果。
class FailureOutcome {
  FailureOutcome._();

  static const recovered = 'recovered';
  static const blocked = 'blocked';
  static const pending = 'pending';
}

/// 一条失败记录（§17.2）。
class FailureRecord {
  final String id;
  final String taskId;
  final String phase;

  /// 失败的操作（工具名）。
  final String operation;

  /// 失败模式（稳定的分类标签），用于同类匹配。
  final String pattern;

  /// 失败时的现场证据（工具返回的关键字段）。
  final Map<String, Object?> evidence;

  /// 采取的恢复动作。
  final String action;

  final String outcome;

  /// 教训：一句话说明下次该怎么做。
  final String lesson;

  final String scope;

  /// 过期时间（毫秒）；0 表示不过期。
  final int expiresAt;

  final int createdAt;

  const FailureRecord({
    required this.id,
    required this.taskId,
    required this.pattern,
    this.phase = '',
    this.operation = '',
    this.evidence = const {},
    this.action = '',
    this.outcome = FailureOutcome.pending,
    this.lesson = '',
    this.scope = FailureScope.tool,
    this.expiresAt = 0,
    this.createdAt = 0,
  });

  bool isExpired(int now) => expiresAt > 0 && now > expiresAt;

  Map<String, Object?> toJson() => {
        'id': id,
        'taskId': taskId,
        'phase': phase,
        'operation': operation,
        'pattern': pattern,
        if (evidence.isNotEmpty) 'evidence': evidence,
        'action': action,
        'outcome': outcome,
        'lesson': lesson,
        'scope': scope,
        'expiresAt': expiresAt,
        'createdAt': createdAt,
      };

  static FailureRecord fromJson(Object? raw) {
    if (raw is! Map) throw const FormatException('failure 不是对象');
    final id = raw['id']?.toString() ?? '';
    if (id.isEmpty) throw const FormatException('failure 缺少 id');
    return FailureRecord(
      id: id,
      taskId: raw['taskId']?.toString() ?? '',
      phase: raw['phase']?.toString() ?? '',
      operation: raw['operation']?.toString() ?? '',
      pattern: raw['pattern']?.toString() ?? '',
      evidence: raw['evidence'] is Map
          ? Map<String, Object?>.from(raw['evidence'] as Map)
          : const {},
      action: raw['action']?.toString() ?? '',
      outcome: raw['outcome']?.toString() ?? FailureOutcome.pending,
      lesson: raw['lesson']?.toString() ?? '',
      scope: raw['scope']?.toString() ?? FailureScope.tool,
      expiresAt: (raw['expiresAt'] as num?)?.toInt() ?? 0,
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
    );
  }
}

/// 失败记忆库。全局一份，按作用域过滤。
class FailureMemoryStore {
  FailureMemoryStore(this._tasks);

  final TaskStore _tasks;

  /// 工具级经验保留 30 天；过期的记录读的时候直接忽略。
  static const toolScopeTtlMs = 30 * 24 * 60 * 60 * 1000;

  /// 上限，防止无限增长。
  static const maxEntries = 200;

  Future<File> _file() async =>
      File(p.join((await _tasks.root()).path, 'failures.json'));

  Future<List<FailureRecord>> loadAll() async {
    final file = await _file();
    if (!await file.exists()) return const [];
    try {
      final raw = jsonDecode(await file.readAsString());
      if (raw is! List) return const [];
      final out = <FailureRecord>[];
      for (final e in raw) {
        try {
          out.add(FailureRecord.fromJson(e));
        } catch (_) {
          // 跳过坏记录
        }
      }
      return out;
    } catch (_) {
      return const [];
    }
  }

  Future<void> _save(List<FailureRecord> list) async {
    final file = await _file();
    await file.parent.create(recursive: true);
    await file.writeAsString(
      jsonEncode([for (final r in list) r.toJson()]),
      flush: true,
    );
  }

  Future<void> record(FailureRecord record) async {
    final list = List<FailureRecord>.from(await loadAll())..add(record);
    if (list.length > maxEntries) {
      list.sort((a, b) => a.createdAt.compareTo(b.createdAt));
      list.removeRange(0, list.length - maxEntries);
    }
    await _save(list);
  }

  /// 记一次失败（自动填作用域与过期时间）。
  Future<FailureRecord> recordFailure({
    required String id,
    required String taskId,
    required String pattern,
    required int now,
    String phase = '',
    String operation = '',
    Map<String, Object?> evidence = const {},
    String action = '',
    String outcome = FailureOutcome.pending,
    String lesson = '',
    String scope = FailureScope.tool,
    int? expiresAt,
  }) async {
    final r = FailureRecord(
      id: id,
      taskId: taskId,
      phase: phase,
      operation: operation,
      pattern: pattern,
      evidence: evidence,
      action: action,
      outcome: outcome,
      lesson: lesson,
      scope: scope,
      expiresAt: expiresAt ??
          (scope == FailureScope.tool ? now + toolScopeTtlMs : 0),
      createdAt: now,
    );
    await record(r);
    return r;
  }

  /// 查与当前任务相关的经验（§17.4：让 Agent 下一次真正参考）。
  ///
  /// 过滤规则：
  /// - 过期记录不要；
  /// - scope=task 只认同一任务；
  /// - scope=tool 全局可用（最有用的一类）；
  /// - scope=apk 需要调用方传 [apkFingerprint]，这里用任务 id 兜底。
  Future<List<FailureRecord>> lookup({
    required String taskId,
    required int now,
    String? apkFingerprint,
    String? pattern,
  }) async {
    final all = await loadAll();
    final out = <FailureRecord>[];
    for (final r in all) {
      if (r.isExpired(now)) continue;
      if (pattern != null && pattern.isNotEmpty && r.pattern != pattern) {
        continue;
      }
      switch (r.scope) {
        case FailureScope.task:
          if (r.taskId != taskId) continue;
          break;
        case FailureScope.apk:
          if (apkFingerprint == null || apkFingerprint.isEmpty) continue;
          if (r.evidence['apkFingerprint'] != apkFingerprint) continue;
          break;
        default:
          break; // tool 级：全局
      }
      out.add(r);
    }
    out.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    return out;
  }

  /// 用户清空（§17.4 userCanClear）。
  ///
  /// 语义（2026-09-14 真机反馈「点了清空没反应」）：诊断页列表展示的是
  /// [lookup] 的结果——scope=tool 的记录是**全局可见**的，来自所有任务；
  /// 而按 taskId 清空只删「本任务自己记的」那几条，别的任务留下的照样显示。
  /// 所以页面按「所见即所清」调用 [clearAll]，[clear] 保留给按任务清理的调用方。
  Future<void> clear({String? taskId}) async {
    if (taskId == null) {
      await _save(const []);
      return;
    }
    final list = (await loadAll()).where((r) => r.taskId != taskId).toList();
    await _save(list);
  }

  /// 清空全部失败记忆（诊断页「清空」按钮：所见即所清）。
  Future<void> clearAll() => _save(const []);
}
