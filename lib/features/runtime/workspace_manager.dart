/// 工作区管理（§16）。
///
/// 目录布局：
/// ```
/// runtime/workspaces/task_xxx/
///   input/     原始 APK（只读）
///   work/      工作副本（所有修改发生在这里）
///   cache/     任务级缓存
///   analysis/  分析产物
///   evidence/  证据快照
///   logs/      日志
///   patches/   补丁与预览
///   build/     构建中间产物
///   output/    最终交付物
///   manifest.json
/// ```
library;

import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import 'task_store.dart';

/// 清理策略（§16.4）。
class CleanupPolicy {
  /// 必须保留：原始 APK、最终交付 APK、任务 manifest、关键证据、Patch Plan。
  static const keep = ['input', 'output', 'manifest.json'];

  /// 默认可清理：临时解包、中间构建、临时日志、一次性缓存。
  static const purge = ['work', 'cache', 'build', 'logs'];

  /// 可选保留：分析产物、证据快照、补丁。
  static const keepOptional = ['analysis', 'evidence', 'patches'];
}

/// 一次清理的结果记录（§16.5）。
class CleanupRecord {
  final int at;
  final List<String> purged;
  final List<String> kept;
  final List<String> failed;

  const CleanupRecord({
    required this.at,
    this.purged = const [],
    this.kept = const [],
    this.failed = const [],
  });

  Map<String, Object?> toJson() => {
        'at': at,
        'purged': purged,
        'kept': kept,
        'failed': failed,
      };
}

class WorkspaceManager {
  WorkspaceManager(this._tasks);

  final TaskStore _tasks;

  static const _subdirs = [
    'input',
    'work',
    'cache',
    'analysis',
    'evidence',
    'logs',
    'patches',
    'build',
    'output',
  ];

  Future<Directory> workspaceDir(String taskId) async => Directory(
        p.join((await _tasks.root()).path, 'workspaces', taskId),
      );

  Future<Directory> subdir(String taskId, String name) async =>
      Directory(p.join((await workspaceDir(taskId)).path, name));

  /// 建立工作区目录骨架并写 manifest。
  Future<Directory> prepare({
    required String taskId,
    required String sourceApkPath,
    required int now,
  }) async {
    final root = await workspaceDir(taskId);
    for (final name in _subdirs) {
      await Directory(p.join(root.path, name)).create(recursive: true);
    }

    // 原始 APK 只读副本：复制到 input/，源文件本身永不被改（§16.2）。
    final src = File(sourceApkPath);
    final destName = p.basename(sourceApkPath);
    final dest = File(p.join(root.path, 'input', destName));
    if (await src.exists() && src.absolute.path != dest.absolute.path) {
      await src.copy(dest.path);
    }

    await _writeManifest(taskId, {
      'taskId': taskId,
      'sourceApk': destName,
      'sourceApkOriginalPath': sourceApkPath,
      'createdAt': now,
      'keep': CleanupPolicy.keep,
    });
    return root;
  }

  Future<Map<String, Object?>> readManifest(String taskId) async {
    final file = File(
      p.join((await workspaceDir(taskId)).path, 'manifest.json'),
    );
    if (!await file.exists()) return const {};
    try {
      final raw = jsonDecode(await file.readAsString());
      return raw is Map ? Map<String, Object?>.from(raw) : const {};
    } catch (_) {
      return const {};
    }
  }

  Future<void> _writeManifest(
    String taskId,
    Map<String, Object?> manifest,
  ) async {
    final file = File(
      p.join((await workspaceDir(taskId)).path, 'manifest.json'),
    );
    await file.writeAsString(jsonEncode(manifest), flush: true);
  }

  /// 执行清理（§16.4 / §16.5）。
  ///
  /// [keepAnalysis] 为 true 时保留分析产物、证据与补丁（失败任务诊断用）。
  /// 只删白名单里的目录，绝不动 input/ 与 output/。
  Future<CleanupRecord> cleanup(
    String taskId, {
    required int now,
    bool keepAnalysis = false,
  }) async {
    final root = await workspaceDir(taskId);
    final purged = <String>[];
    final kept = <String>[];
    final failed = <String>[];

    final targets = <String>[
      ...CleanupPolicy.purge,
      if (!keepAnalysis) ...CleanupPolicy.keepOptional,
    ];

    for (final name in targets) {
      final dir = Directory(p.join(root.path, name));
      if (!await dir.exists()) continue;
      try {
        await dir.delete(recursive: true);
        purged.add(name);
      } catch (_) {
        failed.add(name);
      }
    }
    for (final name in CleanupPolicy.keep) {
      final target = FileSystemEntity.typeSync(p.join(root.path, name));
      if (target != FileSystemEntityType.notFound) kept.add(name);
    }
    if (keepAnalysis) kept.addAll(CleanupPolicy.keepOptional);

    final record = CleanupRecord(
      at: now,
      purged: purged,
      kept: kept,
      failed: failed,
    );
    final logDir = Directory(p.join(root.path, 'cleanup'));
    await logDir.create(recursive: true);
    await File(p.join(logDir.path, 'last.json'))
        .writeAsString(jsonEncode(record.toJson()), flush: true);
    return record;
  }

  /// 回收历史工作区（2026-09-14 体积治理）。
  ///
  /// [prepare] 会把整包 APK 复制进 `input/`（§16.2 只读副本），而 cleanup 只有
  /// 手动入口、且 keep 含 input——每次换包 / 新会话都留下**一份全量 APK 副本**，
  /// 且每个历史会话的作用域绑定永久驻留 SP（"绑定"≠活跃），实测 app_flutter
  /// 因此涨到 6.75GB（775 文件）。工作区文件写进去后几乎无读者（仅诊断页读
  /// manifest、手动清理工具），因此回收边界可以按"新鲜度"定：
  /// - 绑定且 [boundMaxAge] 内动过的 → 保留（当前正在用的任务永远命中）；
  /// - 绑定但长期未动（历史会话）→ 回收；
  /// - 未绑定：仅保留最新 [keepNewestUnbound] 个且 [maxAge] 内（诊断可选）。
  /// 任务记录（tasks/）一律保留可查。
  ///
  /// 年龄规则之外还有**硬上限** [maxTotalBytes]：绑定 churn（历史会话绑定
  /// 永久驻留 SP）可能让全部工作区都是"3 天内新建的绑定"，年龄规则会放行。
  /// 超限时按最旧优先回收，但永远保护「最新的绑定工作区」（活跃任务）与
  /// 「最新未绑定样例」——保证总量有界，而不是换个名字继续涨。
  Future<WorkspacePruneReport> pruneOrphanWorkspaces({
    required Set<String> boundTaskIds,
    required int now,
    Duration maxAge = const Duration(hours: 24),
    Duration boundMaxAge = const Duration(days: 3),
    int keepNewestUnbound = 1,
    int maxTotalBytes = 1024 * 1024 * 1024,
  }) async {
    final root = Directory(p.join((await _tasks.root()).path, 'workspaces'));
    if (!await root.exists()) {
      return const WorkspacePruneReport(deleted: [], kept: [], freedBytes: 0);
    }
    final entries = <({String id, bool bound, DateTime modified, int bytes})>[];
    await for (final entity in root.list(followLinks: false)) {
      if (entity is! Directory) continue;
      final id = p.basename(entity.path);
      try {
        final stat = await entity.stat();
        var bytes = 0;
        await for (final child in entity.list(
          recursive: true,
          followLinks: false,
        )) {
          if (child is File) {
            try {
              bytes += await child.length();
            } catch (_) {}
          }
        }
        entries.add((
          id: id,
          bound: boundTaskIds.contains(id),
          modified: stat.modified,
          bytes: bytes,
        ));
      } catch (_) {}
    }
    entries.sort((a, b) => b.modified.compareTo(a.modified));
    // 未绑定的"最新一个且未超龄"作为诊断样例保留。
    String? newestUnboundKept;
    if (keepNewestUnbound > 0) {
      for (final e in entries) {
        if (e.bound) continue;
        if (now - e.modified.millisecondsSinceEpoch <
            maxAge.inMilliseconds) {
          newestUnboundKept = e.id;
        }
        break; // entries 已按时间倒序，只看最新的那个未绑定
      }
    }
    final deleted = <String>[];
    final kept = <String>[];
    var freed = 0;
    final retained = <({String id, bool bound, DateTime modified, int bytes})>[];
    for (final e in entries) {
      final age = now - e.modified.millisecondsSinceEpoch;
      final retain = e.bound
          ? age < boundMaxAge.inMilliseconds
          : (e.id == newestUnboundKept);
      if (retain) {
        retained.add(e);
      } else {
        try {
          await Directory(p.join(root.path, e.id)).delete(recursive: true);
          deleted.add(e.id);
          freed += e.bytes;
        } catch (_) {
          kept.add(e.id);
          retained.add(e);
        }
      }
    }
    // 硬上限：保护最新绑定（活跃任务）与最新未绑定样例，其余最旧优先回收。
    final protected = <String>{
      if (retained.isNotEmpty) retained.first.id,
      if (newestUnboundKept != null) newestUnboundKept,
    };
    var retainedBytes = retained.fold<int>(0, (sum, e) => sum + e.bytes);
    for (var i = retained.length - 1; i >= 0 && retainedBytes > maxTotalBytes; i--) {
      final e = retained[i];
      if (protected.contains(e.id)) continue;
      try {
        await Directory(p.join(root.path, e.id)).delete(recursive: true);
        deleted.add(e.id);
        freed += e.bytes;
        retainedBytes -= e.bytes;
      } catch (_) {
        kept.add(e.id);
      }
    }
    for (final e in retained) {
      if (!deleted.contains(e.id) && !kept.contains(e.id)) kept.add(e.id);
    }
    return WorkspacePruneReport(
      deleted: deleted,
      kept: kept,
      freedBytes: freed,
    );
  }
}

/// 一次无主工作区回收的结果。
class WorkspacePruneReport {
  const WorkspacePruneReport({
    required this.deleted,
    required this.kept,
    required this.freedBytes,
  });

  final List<String> deleted;
  final List<String> kept;
  final int freedBytes;
}
