/// 证据库（§11 Evidence Store）。
///
/// 落盘：`runtime/tasks/<taskId>/evidence.json`（数组，整体重写，量级小）。
/// 职责：
/// - 写入证据并标记等级；
/// - 按目标/等级查询；
/// - 记录冲突并把两侧标记为未决（§11.4）。
library;

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import 'models/evidence.dart';
import 'models/task_event.dart';
import 'task_store.dart';

class EvidenceStore {
  EvidenceStore(this._tasks);

  final TaskStore _tasks;

  Future<File> _file(String taskId) async => File(
        p.join((await _tasks.taskDir(taskId)).path, 'evidence.json'),
      );

  Future<File> _conflictFile(String taskId) async => File(
        p.join((await _tasks.taskDir(taskId)).path, 'conflicts.json'),
      );

  Future<List<Evidence>> load(String taskId) async {
    final file = await _file(taskId);
    if (!await file.exists()) return const [];
    try {
      final raw = jsonDecode(await file.readAsString());
      if (raw is! List) return const [];
      final out = <Evidence>[];
      for (final e in raw) {
        try {
          out.add(Evidence.fromJson(e));
        } catch (_) {
          // 跳过坏记录，不因为一条坏数据丢掉整个证据库
        }
      }
      return out;
    } catch (_) {
      return const [];
    }
  }

  Future<void> _save(String taskId, List<Evidence> list) async {
    final file = await _file(taskId);
    await file.parent.create(recursive: true);
    await file.writeAsString(
      jsonEncode([for (final e in list) e.toJson()]),
      flush: true,
    );
  }

  /// 写入一条证据。
  Future<Evidence> add(Evidence evidence) async {
    final list = List<Evidence>.from(await load(evidence.taskId));
    list.add(evidence);
    await _save(evidence.taskId, list);
    await _tasks.appendEvent(TaskEvent(
      id: 'evt_${evidence.id}',
      taskId: evidence.taskId,
      type: TaskEventType.evidenceRecorded,
      payload: {
        'evidenceId': evidence.id,
        'level': evidence.level.label,
        'type': evidence.type,
      },
      createdAt: evidence.createdAt,
    ));
    return evidence;
  }

  Future<Evidence?> byId(String taskId, String evidenceId) async {
    final list = await load(taskId);
    for (final e in list) {
      if (e.id == evidenceId) return e;
    }
    return null;
  }

  /// 升级证据等级（如把 Candidate 提升为 Observed）。
  Future<bool> upgrade(
    String taskId,
    String evidenceId,
    EvidenceLevel level,
  ) async {
    final list = List<Evidence>.from(await load(taskId));
    final i = list.indexWhere((e) => e.id == evidenceId);
    if (i < 0) return false;
    if (level.rank <= list[i].level.rank) return false;
    list[i] = list[i].copyWith(level: level);
    await _save(taskId, list);
    return true;
  }

  /// 当前最高证据等级（无证据返回 null）。
  Future<EvidenceLevel?> highestLevel(String taskId) async {
    final list = await load(taskId);
    if (list.isEmpty) return null;
    var best = list.first.level;
    for (final e in list) {
      if (e.level.rank > best.rank) best = e.level;
    }
    return best;
  }

  /// 是否有未决证据（冲突未解决）——用于阻止进入修改阶段。
  Future<bool> hasUnresolved(String taskId) async {
    final list = await load(taskId);
    return list.any((e) => !e.resolved);
  }

  // ---------------------------------------------------------------- 冲突

  Future<List<EvidenceConflict>> loadConflicts(String taskId) async {
    final file = await _conflictFile(taskId);
    if (!await file.exists()) return const [];
    try {
      final raw = jsonDecode(await file.readAsString());
      if (raw is! List) return const [];
      final out = <EvidenceConflict>[];
      for (final c in raw) {
        try {
          out.add(EvidenceConflict.fromJson(c));
        } catch (_) {
          // 跳过坏记录
        }
      }
      return out;
    } catch (_) {
      return const [];
    }
  }

  /// 记录一次证据冲突（§11.4 第 1、2 步：记录冲突 + 标记未决）。
  ///
  /// 不做裁决。调用方随后应选择第三个独立证据源。
  Future<EvidenceConflict> recordConflict({
    required String taskId,
    required String claim,
    required List<String> evidenceIds,
    required String conflictId,
    required int now,
  }) async {
    final list = List<Evidence>.from(await load(taskId));
    for (var i = 0; i < list.length; i++) {
      if (evidenceIds.contains(list[i].id)) {
        list[i] = list[i].copyWith(resolved: false);
      }
    }
    await _save(taskId, list);

    final conflict = EvidenceConflict(
      id: conflictId,
      taskId: taskId,
      claim: claim,
      evidenceIds: evidenceIds,
      createdAt: now,
    );
    final all = List<EvidenceConflict>.from(await loadConflicts(taskId))
      ..add(conflict);
    final file = await _conflictFile(taskId);
    await file.parent.create(recursive: true);
    await file.writeAsString(
      jsonEncode([for (final c in all) c.toJson()]),
      flush: true,
    );
    await _tasks.appendEvent(TaskEvent(
      id: 'evt_$conflictId',
      taskId: taskId,
      type: TaskEventType.evidenceConflict,
      payload: {'claim': claim, 'evidenceIds': evidenceIds},
      createdAt: now,
    ));
    return conflict;
  }

  /// 用第三个独立证据解决冲突，把两侧证据恢复为已决。
  Future<bool> resolveConflict(
    String taskId,
    String conflictId,
    String byEvidenceId,
  ) async {
    final conflicts = List<EvidenceConflict>.from(await loadConflicts(taskId));
    final i = conflicts.indexWhere((c) => c.id == conflictId);
    if (i < 0) return false;
    final c = conflicts[i];
    conflicts[i] = EvidenceConflict(
      id: c.id,
      taskId: c.taskId,
      claim: c.claim,
      evidenceIds: c.evidenceIds,
      resolvedBy: byEvidenceId,
      createdAt: c.createdAt,
    );
    final file = await _conflictFile(taskId);
    await file.writeAsString(
      jsonEncode([for (final x in conflicts) x.toJson()]),
      flush: true,
    );

    final list = List<Evidence>.from(await load(taskId));
    for (var k = 0; k < list.length; k++) {
      if (c.evidenceIds.contains(list[k].id)) {
        list[k] = list[k].copyWith(resolved: true);
      }
    }
    await _save(taskId, list);
    return true;
  }
}
