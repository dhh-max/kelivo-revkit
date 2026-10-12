/// 产物登记（§23.3 Artifact、§16.2 产物必须登记）。
///
/// 每次改包/签名/构建都会产出新的 APK，如果不登记，「这份成品是哪一步出来的、
/// 源包是哪个、哈希对不对」就只能靠记忆。这里把它们记成有血缘关系的条目。
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;

import '../../core/services/local_tools/local_tool_names.dart';
import 'task_store.dart';

/// 产物类型。
class ArtifactKind {
  ArtifactKind._();

  static const inputApk = 'input_apk';
  static const patchedApk = 'patched_apk';
  static const signedApk = 'signed_apk';
  static const builtApk = 'built_apk';
  static const report = 'report';
  static const other = 'other';
}

/// 一份产物（§23.3）。
class Artifact {
  final String id;
  final String taskId;
  final String kind;
  final String path;
  final String sha256;
  final int size;

  /// 由哪份产物派生而来（血缘）。源包为空。
  final String sourceArtifactId;
  final int createdAt;

  /// 用户明确要求保留的产物，清理时不动它（§16.4）。
  final bool retained;

  /// 该产物在**设备路径空间**的来源（F-13/F-16，2026-10-05 v11 复测）。
  ///
  /// 工作区内的 input 是设备原包的**只读副本**；台账登记的是副本路径
  /// （runtime 空间），交付报告若直接引用它，审计会看到「设备根 / runtime 根
  /// 两套路径并存」。这里在登记时记下设备原件路径，交付源头优先取它。
  final String originPath;

  const Artifact({
    required this.id,
    required this.taskId,
    required this.kind,
    required this.path,
    this.sha256 = '',
    this.size = 0,
    this.sourceArtifactId = '',
    this.createdAt = 0,
    this.retained = false,
    this.originPath = '',
  });

  Artifact copyWith({bool? retained}) => Artifact(
        id: id,
        taskId: taskId,
        kind: kind,
        path: path,
        sha256: sha256,
        size: size,
        sourceArtifactId: sourceArtifactId,
        createdAt: createdAt,
        retained: retained ?? this.retained,
        originPath: originPath,
      );

  Map<String, Object?> toJson() => {
        'id': id,
        'taskId': taskId,
        'kind': kind,
        'path': path,
        'sha256': sha256,
        'size': size,
        if (sourceArtifactId.isNotEmpty) 'sourceArtifactId': sourceArtifactId,
        'createdAt': createdAt,
        'retained': retained,
        if (originPath.isNotEmpty) 'originPath': originPath,
      };

  static Artifact fromJson(Object? raw) {
    if (raw is! Map) throw const FormatException('artifact 不是对象');
    final id = raw['id']?.toString() ?? '';
    if (id.isEmpty) throw const FormatException('artifact 缺少 id');
    return Artifact(
      id: id,
      taskId: raw['taskId']?.toString() ?? '',
      kind: raw['kind']?.toString() ?? ArtifactKind.other,
      path: raw['path']?.toString() ?? '',
      sha256: raw['sha256']?.toString() ?? '',
      size: (raw['size'] as num?)?.toInt() ?? 0,
      sourceArtifactId: raw['sourceArtifactId']?.toString() ?? '',
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
      retained: raw['retained'] == true,
      originPath: raw['originPath']?.toString() ?? '',
    );
  }
}

/// 产物登记表：一个任务一份，JSON 落盘。
class ArtifactStore {
  ArtifactStore(this._tasks);

  final TaskStore _tasks;

  Future<File> _file(String taskId) async =>
      File(p.join((await _tasks.taskDir(taskId)).path, 'artifacts.json'));

  Future<List<Artifact>> list(String taskId) async {
    final f = await _file(taskId);
    if (!await f.exists()) return const [];
    try {
      final raw = jsonDecode(await f.readAsString());
      if (raw is! List) return const [];
      final out = <Artifact>[];
      for (final e in raw) {
        try {
          out.add(Artifact.fromJson(e));
        } catch (_) {
          // 跳过坏记录
        }
      }
      return out;
    } catch (_) {
      return const [];
    }
  }

  Future<void> _save(String taskId, List<Artifact> list) async {
    final f = await _file(taskId);
    await f.parent.create(recursive: true);
    await f.writeAsString(
      jsonEncode([for (final a in list) a.toJson()]),
      flush: true,
    );
  }

  Future<Artifact?> byId(String taskId, String id) async {
    for (final a in await list(taskId)) {
      if (a.id == id) return a;
    }
    return null;
  }

  /// 最近一份产物（按登记时间）。血缘默认指向它。
  Future<Artifact?> latest(String taskId) async {
    final all = await list(taskId);
    if (all.isEmpty) return null;
    all.sort((a, b) => a.createdAt.compareTo(b.createdAt));
    return all.last;
  }

  /// 登记一份产物。
  ///
  /// 同一个路径不会重复登记（改包多次会产出不同文件名，不会被误合并）。
  /// 文件不存在、读不到哈希时不登记——宁可没有登记，也不要一条假记录。
  Future<Artifact?> register({
    required String taskId,
    required String kind,
    required String path,
    String sourceArtifactId = '',
    int now = 0,
    String? idFactory,
    /// 设备路径空间的来源（工作区副本登记时传原包路径，见 [Artifact.originPath]）。
    String originPath = '',
  }) async {
    final s = path.trim();
    if (s.isEmpty) return null;
    final file = File(s);
    if (!await file.exists()) return null;

    final all = List<Artifact>.from(await list(taskId));
    for (final a in all) {
      if (p.equals(a.path, file.path)) return a; // 已登记
    }

    final bytes = await file.readAsBytes();
    var source = sourceArtifactId;
    if (source.isEmpty) {
      // 血缘：默认挂到最近一份产物上
      final latest = all.isEmpty ? null : (all.toList()
        ..sort((a, b) => a.createdAt.compareTo(b.createdAt))).last;
      source = latest?.id ?? '';
    }
    final artifact = Artifact(
      id: idFactory ??
          'art_${(now == 0 ? DateTime.now().millisecondsSinceEpoch : now)}'
              '_${all.length}',
      taskId: taskId,
      kind: kind,
      path: file.path,
      sha256: sha256.convert(bytes).toString(),
      size: bytes.length,
      sourceArtifactId: source,
      createdAt: now == 0 ? DateTime.now().millisecondsSinceEpoch : now,
      originPath: originPath.trim(),
    );
    all.add(artifact);
    await _save(taskId, all);
    return artifact;
  }

  /// 标记为保留（清理时跳过）。
  Future<bool> markRetained(String taskId, String id, bool retained) async {
    final all = List<Artifact>.from(await list(taskId));
    final i = all.indexWhere((a) => a.id == id);
    if (i < 0) return false;
    all[i] = all[i].copyWith(retained: retained);
    await _save(taskId, all);
    return true;
  }

  /// 工具名 → 产物类型。
  static String kindForTool(String tool) {
    switch (tool) {
      case LocalToolNames.apkSign:
        return ArtifactKind.signedApk;
      case 'apk_rebuild':
        return ArtifactKind.builtApk;
      case 'patch_apk_dex_methods':
      case 'patch_apk_dex_strings':
      case 'patch_apk_manifest':
      case 'signature_bypass':
      case 'so_patch_into_apk':
        return ArtifactKind.patchedApk;
      default:
        return ArtifactKind.other;
    }
  }

  /// 可能产出 APK 的工具。
  static const producingTools = <String>{
    LocalToolNames.apkSign,
    'apk_rebuild',
    'patch_apk_dex_methods',
    'patch_apk_dex_strings',
    'patch_apk_manifest',
    'signature_bypass',
    'so_patch_into_apk',
  };

  /// 从工具返回里挑出「看起来是产出的 APK 路径」。
  ///
  /// 各工具的输出字段名不统一（output / outputPath / outputApk / kept…），
  /// 这里按值判断：**以 .apk 结尾的字符串**才算，避免把参数路径当产物。
  static List<String> extractApkPaths(Map<String, Object?> data) {
    final out = <String>{};
    void scan(Object? v) {
      if (v is String) {
        final s = v.trim();
        // 必须像路径（两种分隔符都认），避免把 "app.apk" 这种文件名当产物
        final looksLikePath = s.contains('/') || s.contains(r'\');
        if (s.toLowerCase().endsWith('.apk') && looksLikePath) out.add(s);
      } else if (v is List) {
        for (final x in v) {
          scan(x);
        }
      } else if (v is Map) {
        for (final x in v.values) {
          scan(x);
        }
      }
    }

    for (final k in const [
      'output',
      'outputPath',
      'outputApk',
      'outputs',
      'kept',
      'result',
      'data',
    ]) {
      scan(data[k]);
    }
    return out.toList();
  }
}
