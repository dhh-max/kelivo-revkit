import 'dart:convert';
import 'dart:io';

import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/models/memory_entry.dart';
import '../../../core/services/memory/memory_repository.dart';

/// 精简的 APK 修改经验记忆：按「类型指纹」匹配，不依赖包名/SHA/应用名，
/// App 改名、换包名、换运营都不影响命中（同类型 90% 代码相似）。
///
/// 存储已并入记忆系统 V1（MemoryType.apkPatch）：content 存一句话方案，
/// 结构化字段（title/fingerprint/outcome/operation/timestamp）存 extraJson。
/// 指纹维度：广告厂商集合 + 加固壳类型 + 引擎类型。
class ApkPatchMemory {
  const ApkPatchMemory({
    required this.id,
    required this.fingerprint,
    required this.title,
    required this.solution,
    required this.timestamp,
    this.outcome = 'unverified_legacy',
    this.operation = '',
    this.pitfall = '',
    this.targets = const <String>[],
    this.artifacts = const <Map<String, dynamic>>[],
    this.status = MemoryStatus.active,
  });

  final String id;

  /// 类型指纹：{vendors:[...], shell:[...], engine:str}
  final Map<String, dynamic> fingerprint;
  final String title;
  final String solution;
  final int timestamp;
  final String outcome;
  final String operation;

  /// 易错点警示（怎么改才对）：如「恒返回常量用 force_return_constant，
  /// 勿裸 hex 改栈帧」。复用记忆时与方案一起展示，防踩同坑。
  final String pitfall;

  /// 具体改点定位符（qualifiedId / so 符号 / 条目路径），复用时可直接
  /// 按图索骥，不再只有一句抽象方案。同指纹合并时取并集去重。
  final List<String> targets;

  /// 验证过的产物文件档案（跨会话按内容指纹识别成品/基线）：
  /// [{sha256, path, size, fileName, kind, recordedAt}]。同指纹合并时按
  /// sha256 去重取并集——agent 拿到一个来历不明的 APK 时可反查
  /// 「这是不是某个已验证项目的成品/源包」。
  final List<Map<String, dynamic>> artifacts;

  /// 记忆状态（active/archived）：新版本验证成功后旧版本条目自动置
  /// archived 供复查；默认查询只回 active。
  final MemoryStatus status;

  ApkPatchMemory copyWith({
    String? id,
    Map<String, dynamic>? fingerprint,
    String? title,
    String? solution,
    int? timestamp,
    String? outcome,
    String? operation,
    String? pitfall,
    List<String>? targets,
    List<Map<String, dynamic>>? artifacts,
    MemoryStatus? status,
  }) => ApkPatchMemory(
    id: id ?? this.id,
    fingerprint: fingerprint ?? this.fingerprint,
    title: title ?? this.title,
    solution: solution ?? this.solution,
    timestamp: timestamp ?? this.timestamp,
    outcome: outcome ?? this.outcome,
    operation: operation ?? this.operation,
    pitfall: pitfall ?? this.pitfall,
    targets: targets ?? this.targets,
    artifacts: artifacts ?? this.artifacts,
    status: status ?? this.status,
  );
}

class ApkPatchMemoryService {
  const ApkPatchMemoryService._();

  /// SoLab APK 助手作用域：经验只归内置 SoLab APK 助手，不污染其它助手记忆。
  static const _assistantId = 'builtin-apk-mod';

  static const _legacyKey = 'apk_mod_patch_memory_v1';

  /// 从报告提取类型指纹（不依赖包名/SHA）。
  static Map<String, dynamic> fingerprintFromReport(
    Map<String, dynamic> report, {
    required Set<String> vendors,
  }) {
    final shellPacking = report['shellPacking'];
    final shells = shellPacking is Map
        ? ((shellPacking['shells'] as List?)
                  ?.map((e) => e.toString())
                  .toList() ??
              const <String>[])
        : const <String>[];
    final flutterApp = report['flutterApp'];
    // 多信号兜底：旧格式报告（恢复的历史工作区）可能没有 flutterApp key，
    // 用 nativeLibraries/runtimeEngines 兜底判定，否则 Flutter 维度整体失效。
    final flutterDetected =
        (flutterApp is Map && flutterApp['detected'] == true) ||
        reportLooksFlutter(report);
    return {
      if ((report['packageName'] ?? '').toString().trim().isNotEmpty)
        'appId': report['packageName'].toString().trim().toLowerCase(),
      'vendors': (vendors.toList()..sort()),
      'shell': (shells.toList()..sort()),
      'engine': flutterDetected ? 'flutter' : 'native',
      // Flutter 细维度：纯 Flutter 会员包的 vendors 常为小众广告 SDK 或空，
      // 仅靠 vendors Jaccard 永远到不了 0.6 阈值。mode+abi 表征工具链
      // （blutter→pp.txt→xref→edit_asm 全程一致），vipCandidateBucket 表征
      // 任务形态（会员候选规模），二者可独立支撑同类判定。
      if (flutterDetected) 'flutterProfile': _flutterProfile(report),
    };
  }

  /// Flutter 检出兜底：flutterApp.detected 之外，nativeLibraries 含
  /// libapp.so 或 runtimeEngines 含 flutter 也算检出（兼容旧报告）。
  static bool reportLooksFlutter(Map<String, dynamic> report) {
    final fa = report['flutterApp'];
    if (fa is Map && fa['detected'] == true) return true;
    final libs = report['nativeLibraries'];
    if (libs is List && libs.any((e) => e.toString().contains('libapp.so'))) {
      return true;
    }
    final engines = report['runtimeEngines'];
    if (engines is List) {
      for (final e in engines) {
        if (e is Map && '${e['engine']}'.toLowerCase().contains('flutter')) {
          return true;
        }
      }
    }
    return false;
  }

  static Map<String, dynamic> _flutterProfile(Map<String, dynamic> report) {
    final flutterApp = report['flutterApp'];
    final fa = flutterApp is Map ? flutterApp : const <String, dynamic>{};
    final rawEngine = (fa['engine'] ?? '').toString();
    // 旧报告无 flutterApp 时（兜底检出）默认 aot + 取整体 abis 首位。
    final mode = (rawEngine.isNotEmpty && rawEngine != 'unknown')
        ? rawEngine
        : 'aot';
    var abi = '';
    final faAbis = fa['abis'];
    if (faAbis is List && faAbis.isNotEmpty) {
      abi = faAbis.first.toString();
    } else {
      final reportAbis = report['abis'];
      if (reportAbis is List && reportAbis.isNotEmpty) {
        abi = reportAbis.first.toString();
      }
    }
    final vipCount =
        ((report['vipMethodCandidates'] as List?) ?? const []).length;
    final bucket = vipCount == 0
        ? 'none'
        : vipCount <= 3
        ? 'few'
        : vipCount <= 10
        ? 'some'
        : 'many';
    return {'mode': mode, 'abi': abi, 'vipBucket': bucket};
  }

  /// 匹配度：加权平均 = 厂商 Jaccard×1.0 + 壳 Jaccard×0.5 + 引擎一致×0.3，
  /// 除以参与项权重和。返回 0~1；>= 0.6 视为同类。
  ///
  /// 注意引擎项按权重计分（匹配贡献 0.3 而非 1.0）：引擎区分度低
  /// （native 占大头），若满额计分会把厂商差异稀释到阈值失效
  /// （历史 bug：厂商 Jaccard 0.2 + 引擎相同 = 0.92 误命中）。
  static double matchScore(Map<String, dynamic> a, Map<String, dynamic> b) {
    if (_sameApp(a, b)) return 1;
    final av = ((a['vendors'] as List?) ?? const [])
        .map((e) => e.toString())
        .toSet();
    final bv = ((b['vendors'] as List?) ?? const [])
        .map((e) => e.toString())
        .toSet();
    final ash = ((a['shell'] as List?) ?? const [])
        .map((e) => e.toString())
        .toSet();
    final bsh = ((b['shell'] as List?) ?? const [])
        .map((e) => e.toString())
        .toSet();
    final ae = (a['engine'] ?? '').toString();
    final be = (b['engine'] ?? '').toString();
    final afp = a['flutterProfile'];
    final bfp = b['flutterProfile'];

    double score = 0;
    double weight = 0;
    // 厂商重合（权重最高：同类 App 广告 SDK 相似）
    if (av.isNotEmpty || bv.isNotEmpty) {
      final union = av.union(bv).length;
      final inter = av.intersection(bv).length;
      score += (union == 0 ? 0 : (inter / union)) * 1.0;
      weight += 1.0;
    }
    // 壳重合
    if (ash.isNotEmpty || bsh.isNotEmpty) {
      final union = ash.union(bsh).length;
      final inter = ash.intersection(bsh).length;
      score += (union == 0 ? 0 : (inter / union)) * 0.5;
      weight += 0.5;
    }
    // 引擎一致（低权重：区分度有限）。防误命中：双旧格式（都无
    // flutterProfile）且 vendors/shell 全空时，仅 engine 一项不能给分——
    // 否则任意两个无关 Flutter 包都得满分（0.3/0.3=1.0）。
    final onlyEngineLeft =
        (afp is! Map || bfp is! Map) &&
        av.isEmpty &&
        bv.isEmpty &&
        ash.isEmpty &&
        bsh.isEmpty;
    if (ae.isNotEmpty && be.isNotEmpty && ae == be && !onlyEngineLeft) {
      score += 0.3;
      weight += 0.3;
    }
    // Flutter 细维度：同为 Flutter AOT 同 ABI 的会员任务，工具链与打法
    // 高度可迁移（blutter→pp.txt→xref→edit_asm），独立支撑同类判定。
    // 纯 Flutter 包 vendors 为空/小众时，仅此维度即可过 0.6 阈值。
    if (afp is Map && bfp is Map) {
      final modeMatch =
          afp['mode'] == bfp['mode'] && afp['mode'].toString().isNotEmpty;
      final abiMatch =
          afp['abi'] == bfp['abi'] && afp['abi'].toString().isNotEmpty;
      if (modeMatch && abiMatch) {
        score += 0.55;
        weight += 0.55;
        score += (afp['vipBucket'] == bfp['vipBucket'] ? 1 : 0) * 0.15;
        weight += 0.15;
      }
    } else if ((afp is Map || bfp is Map) &&
        ae == 'flutter' &&
        be == 'flutter') {
      // 旧记忆兼容：flutterProfile 维度上线前保存的指纹没有该字段。
      // 双侧引擎同为 flutter 时给部分分（0.3/0.55），同包旧记忆可命中
      // （叠加 vendors 重合过阈值），跨包不相关记忆仍到不了 0.6。
      score += 0.3;
      weight += 0.55;
    }
    return weight == 0 ? 0 : (score / weight).clamp(0.0, 1.0);
  }

  /// 指纹归一化 key：厂商（排序）+ 壳（排序）+ 引擎 + Flutter 细维度。
  /// 空指纹返回空串（不去重）。
  static String fingerprintKey(Map<String, dynamic> fingerprint) {
    final appId = (fingerprint['appId'] ?? '').toString().trim().toLowerCase();
    final vendors =
        ((fingerprint['vendors'] as List?) ?? const [])
            .map((e) => e.toString().trim())
            .where((e) => e.isNotEmpty)
            .toList()
          ..sort();
    final shells =
        ((fingerprint['shell'] as List?) ?? const [])
            .map((e) => e.toString().trim())
            .where((e) => e.isNotEmpty)
            .toList()
          ..sort();
    final engine = (fingerprint['engine'] ?? '').toString().trim();
    final fp = fingerprint['flutterProfile'];
    final flutterPart = fp is Map
        ? '${fp['mode']}@${fp['abi']}#${fp['vipBucket']}'
        : '';
    if (appId.isEmpty &&
        vendors.isEmpty &&
        shells.isEmpty &&
        engine.isEmpty &&
        flutterPart.isEmpty) {
      return '';
    }
    final typeKey =
        '${vendors.join(',')}|${shells.join(',')}|$engine|$flutterPart';
    return appId.isEmpty ? typeKey : '$appId|$typeKey';
  }

  /// 同一个安装包项目的稳定标识。优先使用包名；旧记忆没有包名时为空。
  static String appKey(Map<String, dynamic> fingerprint) =>
      (fingerprint['appId'] ?? '').toString().trim().toLowerCase();

  static bool _sameApp(Map<String, dynamic> a, Map<String, dynamic> b) {
    final ak = appKey(a);
    return ak.isNotEmpty && ak == appKey(b);
  }

  /// 退化指纹：无厂商且无壳（只剩引擎）。引擎区分度太低（native 占大头），
  /// 不能单独作为同类判定信号——匹配时双侧都拒绝，防止无关经验误命中。
  /// 例外：带 flutterProfile 的指纹有独立区分维度（mode+abi+任务形态），
  /// 不算退化（纯 Flutter 会员包 vendors 常为空，此前被误杀导致永不命中）。
  static bool isDegenerateFingerprint(Map<String, dynamic> fingerprint) {
    bool isEmptyList(Object? v) => ((v as List?) ?? const [])
        .where((e) => e.toString().trim().isNotEmpty)
        .isEmpty;
    final hasFlutterProfile = fingerprint['flutterProfile'] is Map;
    return appKey(fingerprint).isEmpty &&
        !hasFlutterProfile &&
        isEmptyList(fingerprint['vendors']) &&
        isEmptyList(fingerprint['shell']);
  }

  /// 记忆侧退化判定（比查询侧宽）：engine=flutter 的旧格式记忆
  /// （flutterProfile 上线前保存）放行——否则历史记忆永远命中不了。
  /// 误命中由 matchScore 的双旧格式零分规则兜底（纯 engine 不给分）。
  static bool _isDegenerateMemory(Map<String, dynamic> fingerprint) {
    if (!isDegenerateFingerprint(fingerprint)) return false;
    return (fingerprint['engine'] ?? '').toString() != 'flutter';
  }

  static String _solutionKey(String solution) =>
      solution.trim().replaceAll(RegExp(r'\s+'), ' ').toLowerCase();

  static int _outcomeRank(String outcome) => switch (outcome) {
    'verified_success' => 0,
    'unverified' || 'unverified_legacy' => 1,
    _ => 2,
  };

  // ---- MemoryEntry ↔ ApkPatchMemory 映射 ----

  /// 从 entry 提取指纹（蒸馏/展示用）。
  static Map<String, dynamic> entryFingerprint(MemoryEntry e) {
    final extra = e.extraJson ?? const <String, dynamic>{};
    return extra['fingerprint'] is Map
        ? Map<String, dynamic>.from(extra['fingerprint'] as Map)
        : const <String, dynamic>{};
  }

  /// entry → ApkPatchMemory（蒸馏/展示用）。
  static ApkPatchMemory entryToMemory(MemoryEntry e) => _fromEntry(e);

  /// ApkPatchMemory → entry（蒸馏写回用）。
  static MemoryEntry memoryToEntry(ApkPatchMemory m) => _toEntry(m);

  static ApkPatchMemory _fromEntry(MemoryEntry e) {
    final extra = e.extraJson ?? const <String, dynamic>{};
    return ApkPatchMemory(
      id: e.id,
      fingerprint: extra['fingerprint'] is Map
          ? Map<String, dynamic>.from(extra['fingerprint'] as Map)
          : const <String, dynamic>{},
      title: (extra['title'] ?? '').toString(),
      solution: e.content,
      timestamp:
          (extra['timestamp'] as num?)?.toInt() ??
          e.createdAt.millisecondsSinceEpoch,
      outcome: (extra['outcome'] ?? 'unverified').toString(),
      operation: (extra['operation'] ?? '').toString(),
      pitfall: (extra['pitfall'] ?? '').toString(),
      targets: [
        for (final t in (extra['targets'] as List? ?? const []))
          if (t.toString().trim().isNotEmpty) t.toString().trim(),
      ],
      artifacts: [
        for (final a in (extra['artifacts'] as List? ?? const []))
          if (a is Map) Map<String, dynamic>.from(a),
      ],
      status: e.status,
    );
  }

  static MemoryEntry _toEntry(ApkPatchMemory m, {DateTime? now}) {
    final ts = now ?? DateTime.now().toUtc();
    return MemoryEntry(
      id: m.id,
      scope: MemoryScope.assistant,
      assistantId: _assistantId,
      type: MemoryType.apkPatch,
      content: m.solution,
      source: MemorySource.tool,
      // status 必须随行：漏带会把 archived 条目写成 active（roundtrip
      // 丢状态，add(archived) 路径实测触发；默认 active 不受影响）。
      status: m.status,
      extraJson: {
        'title': m.title,
        'fingerprint': m.fingerprint,
        'fingerprintKey': fingerprintKey(m.fingerprint),
        'outcome': m.outcome,
        'operation': m.operation,
        if (m.pitfall.isNotEmpty) 'pitfall': m.pitfall,
        if (m.targets.isNotEmpty) 'targets': m.targets,
        if (m.artifacts.isNotEmpty) 'artifacts': m.artifacts,
        'timestamp': m.timestamp,
      },
      createdAt: ts,
      updatedAt: ts,
    );
  }

  static String _fingerprintKeyOfEntry(MemoryEntry entry) {
    final extra = entry.extraJson ?? const <String, dynamic>{};
    final stored = extra['fingerprintKey']?.toString() ?? '';
    if (stored.isNotEmpty) return stored;
    final fingerprint = extra['fingerprint'];
    return fingerprint is Map
        ? fingerprintKey(Map<String, dynamic>.from(fingerprint))
        : '';
  }

  /// 读取全部 APK 经验（按时间倒序）。
  static Future<List<ApkPatchMemory>> load(
    MemoryRepository repo, {
    bool includeArchived = false,
  }) async {
    final all = await repo.readByType(MemoryType.apkPatch);
    final result = <ApkPatchMemory>[
      for (final e in all)
        if (e.type == MemoryType.apkPatch &&
            (includeArchived || e.status != MemoryStatus.archived))
          _fromEntry(e),
    ];
    result.sort((a, b) => b.timestamp.compareTo(a.timestamp));
    return result;
  }

  /// 方案合并：归一化相同→刷新措辞；一方涵盖另一方→保留涵盖者；
  /// 不同修改点→按行追加（一条记忆共存多个方案点）。
  static String mergeSolution(String oldS, String newS) {
    final oldKey = _solutionKey(oldS);
    final newKey = _solutionKey(newS);
    if (oldKey == newKey) return newS;
    if (oldKey.contains(newKey)) return oldS;
    if (newKey.contains(oldKey)) return newS;
    // 行级去重合并（旧条目可能已有多行）
    final lines = <String>[
      for (final l in oldS.split('\n'))
        if (l.trim().isNotEmpty) l.trim(),
    ];
    for (final l in newS.split('\n')) {
      if (l.trim().isNotEmpty &&
          !lines.any((e) => _solutionKey(e) == _solutionKey(l))) {
        lines.add(l.trim());
      }
    }
    return lines.join('\n');
  }

  /// 易错点合并：非空叠加去重（旧含新则保留旧）。
  static String mergePitfall(String oldP, String newP) {
    if (newP.isEmpty) return oldP;
    if (oldP.isEmpty) return newP;
    if (oldP.contains(newP)) return oldP;
    return '$oldP；$newP';
  }

  /// 新增经验：id 相同覆盖；同指纹收敛为同一条（保留原 id，
  /// solution/pitfall/targets 合并去重，outcome 取更优）。
  ///
  /// 同一类型 APK 反复保存措辞各异的方案时不再堆积多条——统一在
  /// 该指纹的唯一条目上增删。退化指纹（无厂商无壳）无同类判定信号，
  /// 不做指纹收敛（保持按 id 覆盖）。
  /// 通过 [repo] 的串行队列保证读-改-写原子性。
  static Future<void> add(MemoryRepository repo, ApkPatchMemory memory) {
    return repo.runExclusive(() async {
      final apk = await repo.readByType(MemoryType.apkPatch);

      apk.removeWhere((e) => e.id == memory.id);
      final fpKey = fingerprintKey(memory.fingerprint);
      if (fpKey.isNotEmpty) {
        final matches = apk.where((e) {
          final old = _fromEntry(e);
          return _sameApp(old.fingerprint, memory.fingerprint) ||
              _fingerprintKeyOfEntry(e) == fpKey;
        }).toList();
        if (matches.isNotEmpty) {
          matches.sort((a, b) => a.createdAt.compareTo(b.createdAt));
          final stable = _fromEntry(matches.first);
          var merged = stable;
          for (final entry in matches.skip(1)) {
            final old = _fromEntry(entry);
            merged = merged.copyWith(
              solution: mergeSolution(merged.solution, old.solution),
              pitfall: mergePitfall(merged.pitfall, old.pitfall),
              targets: {...merged.targets, ...old.targets}.toList(),
              outcome: _outcomeRank(merged.outcome) <= _outcomeRank(old.outcome)
                  ? merged.outcome
                  : old.outcome,
            );
          }
          memory = memory.copyWith(
            id: stable.id,
            title: stable.title.isNotEmpty ? stable.title : memory.title,
            solution: mergeSolution(merged.solution, memory.solution),
            pitfall: mergePitfall(merged.pitfall, memory.pitfall),
            targets: [
              ...merged.targets,
              ...memory.targets,
            ].map((e) => e.trim()).where((e) => e.isNotEmpty).toSet().toList(),
            // 已有验证结论不被未验证回写降级
            outcome:
                _outcomeRank(merged.outcome) <= _outcomeRank(memory.outcome)
                ? merged.outcome
                : memory.outcome,
          );
          for (final duplicate in matches.skip(1)) {
            await repo.deleteOne(duplicate.id);
          }
        }
      }

      final entry = _toEntry(memory);
      await repo.upsertOne(entry);
    });
  }

  /// 收敛写入验证结果：同指纹收敛为同一条（优先命中已验证条目，
  /// 其次任意同指纹条目——save 已收敛单条后两者通常同一条），
  /// 没有才新建。方案/易错点/改点合并且保留，验证结论以最新反馈为准。
  /// [artifacts] 为本次验证产物的文件档案（sha256 跨会话反查成品用）。
  /// [versionName] 为本次验证时 APP 的版本：同 APP 出现**新版本**的验证
  /// 成功时，旧版本条目自动置 archived（保留原方案供复查），新版本条目
  /// active——一个 APP 同时只有一条 active 经验。
  static Future<void> upsertVerification({
    required MemoryRepository repo,
    required Map<String, dynamic> fingerprint,
    required String outcome,
    required String title,
    required String solution,
    required String operation,
    String pitfall = '',
    List<String> targets = const <String>[],
    List<Map<String, dynamic>> artifacts = const <Map<String, dynamic>>[],
    String versionName = '',
  }) {
    return repo.runExclusive(() async {
      final apk = await repo.readByType(MemoryType.apkPatch);
      final fpKey = fingerprintKey(fingerprint);
      final now = DateTime.now().millisecondsSinceEpoch;

      if (fpKey.isNotEmpty) {
        final entries = apk.map(_fromEntry).toList();
        // 优先已验证条目（历史行为），否则任意同指纹条目
        int findWhere(bool Function(ApkPatchMemory m) test) {
          for (var i = 0; i < entries.length; i++) {
            if ((_sameApp(entries[i].fingerprint, fingerprint) ||
                    _fingerprintKeyOfEntry(apk[i]) == fpKey) &&
                test(entries[i])) {
              return i;
            }
          }
          return -1;
        }

        var idx = findWhere(
          (m) =>
              m.outcome == 'verified_success' ||
              m.outcome == 'verified_failure',
        );
        if (idx == -1) idx = findWhere((m) => true);
        if (idx != -1) {
          var old = entries[idx];
          final duplicateIndexes = <int>[];
          var mergedArtifacts = List<Map<String, dynamic>>.of(old.artifacts);
          for (var i = 0; i < entries.length; i++) {
            if (i == idx) continue;
            if (_sameApp(entries[i].fingerprint, fingerprint) ||
                _fingerprintKeyOfEntry(apk[i]) == fpKey) {
              duplicateIndexes.add(i);
              old = old.copyWith(
                solution: mergeSolution(old.solution, entries[i].solution),
                pitfall: mergePitfall(old.pitfall, entries[i].pitfall),
                targets: {...old.targets, ...entries[i].targets}.toList(),
              );
              mergedArtifacts = mergeArtifacts(mergedArtifacts, entries[i].artifacts);
            }
          }
          // 版本代际：同 APP 已有 active 验证条目且版本不同 → 旧条目归档，
          // 本次写入成为新的 active 经验（旧方案保留在 archived 里供复查）。
          final oldVersion =
              (old.fingerprint['versionName'] ?? '').toString().trim();
          final newVersion = versionName.trim();
          final isNewVersionForVerifiedApp =
              old.outcome.startsWith('verified_') &&
              oldVersion.isNotEmpty &&
              newVersion.isNotEmpty &&
              oldVersion != newVersion;
          if (isNewVersionForVerifiedApp) {
            final archivedOld = _toEntry(
              old.copyWith(outcome: 'archived_${old.outcome}'),
              now: apk[idx].createdAt,
            ).copyWith(status: MemoryStatus.archived);
            await repo.upsertOne(archivedOld);
            // 旧条目归档后不再参与本轮合并：新开条目
            final entry = _toEntry(
              ApkPatchMemory(
                id: MemoryEntry.newId(),
                fingerprint: fingerprint,
                title: title,
                solution: solution,
                timestamp: now,
                outcome: outcome,
                operation: operation,
                pitfall: pitfall,
                targets: targets,
                artifacts: artifacts,
              ),
            ).copyWith(
              extraJson: {
                ...?_toEntry(
                  ApkPatchMemory(
                    id: MemoryEntry.newId(),
                    fingerprint: fingerprint,
                    title: title,
                    solution: solution,
                    timestamp: now,
                    outcome: outcome,
                    operation: operation,
                    pitfall: pitfall,
                    targets: targets,
                    artifacts: artifacts,
                  ),
                ).extraJson,
                'versionName': newVersion,
              },
            );
            await repo.upsertOne(entry);
            for (final duplicateIndex in duplicateIndexes) {
              await repo.deleteOne(apk[duplicateIndex].id);
            }
            return;
          }
          // 标题：验证结果落地后必须反映**当前**结论。旧实现是
          // `old.title.isNotEmpty ? old.title : title` —— 合并时永远沿用旧标题，
          // 于是「待验证 APK 修改」这条草稿标题会一直挂着，而 outcome 已经变成
          // verified_success（复验方看到的就是这个自相矛盾）。仅当旧标题更具体
          // （不是待验证草稿）且新标题是默认值时，才保留旧标题。
          final oldTitleLooksPending = old.title.startsWith('待验证');
          final merged = ApkPatchMemory(
            id: old.id,
            fingerprint: {
              ...fingerprint,
              if (newVersion.isNotEmpty) 'versionName': newVersion,
            },
            title: oldTitleLooksPending || old.title.isEmpty ? title : old.title,
            solution: mergeSolution(old.solution, solution),
            timestamp: now,
            outcome: outcome,
            operation: operation,
            pitfall: mergePitfall(old.pitfall, pitfall),
            targets: [
              ...old.targets,
              ...targets,
            ].map((e) => e.trim()).where((e) => e.isNotEmpty).toSet().toList(),
            artifacts: mergeArtifacts(mergedArtifacts, artifacts),
          );
          final updated = _toEntry(merged, now: apk[idx].createdAt);
          if (newVersion.isNotEmpty) {
            await repo.upsertOne(
              updated.copyWith(
                extraJson: {
                  ...?updated.extraJson,
                  'versionName': newVersion,
                },
              ),
            );
          } else {
            await repo.upsertOne(updated);
          }
          for (final duplicateIndex in duplicateIndexes) {
            await repo.deleteOne(apk[duplicateIndex].id);
          }
          return;
        }
      }
      final entry = _toEntry(
        ApkPatchMemory(
          id: MemoryEntry.newId(),
          fingerprint: {
            ...fingerprint,
            if (versionName.trim().isNotEmpty)
              'versionName': versionName.trim(),
          },
          title: title,
          solution: solution,
          timestamp: now,
          outcome: outcome,
          operation: operation,
          pitfall: pitfall,
          targets: targets,
          artifacts: artifacts,
        ),
      );
      await repo.upsertOne(entry);
    });
  }

  /// 产物档案合并：按 sha256 去重取并集，新记录的字段刷新旧路径。
  static List<Map<String, dynamic>> mergeArtifacts(
    Iterable<Map<String, dynamic>> existing,
    Iterable<Map<String, dynamic>> incoming,
  ) {
    final bySha = <String, Map<String, dynamic>>{
      for (final a in existing)
        if ((a['sha256'] ?? '').toString().trim().isNotEmpty)
          a['sha256'].toString().trim(): a,
    };
    for (final a in incoming) {
      final sha = (a['sha256'] ?? '').toString().trim();
      if (sha.isEmpty) continue;
      final old = bySha[sha];
      bySha[sha] = old == null ? Map<String, dynamic>.from(a) : {...old, ...a};
    }
    return bySha.values.toList();
  }

  /// 按产物文件内容指纹反查经验记录：agent 拿到一个来历不明的 APK 时，
  /// 用它的 sha256 判断「这是不是某个已验证项目的成品/源包」。
  static Future<List<ApkPatchMemory>> findByArtifactSha256(
    MemoryRepository repo,
    String sha256,
  ) async {
    final normalized = sha256.trim().toLowerCase();
    if (normalized.isEmpty) return const <ApkPatchMemory>[];
    final all = await load(repo);
    return [
      for (final m in all)
        if (m.artifacts.any(
          (a) => (a['sha256'] ?? '').toString().trim().toLowerCase() == normalized,
        ))
          m,
    ];
  }

  static Future<void> remove(MemoryRepository repo, String id) {
    return repo.runExclusive(() => repo.deleteOne(id));
  }

  /// 匹配当前指纹的历史经验（按匹配度降序，同分按 outcome 优先级，>=0.6 同类）。
  ///
  /// 退化指纹防护（两侧都检查）：无厂商+无壳、只剩引擎的指纹与任何同引擎
  /// APK 都会算出高分（引擎项 1.0），会把无关经验误当同类——这类记忆不参与
  /// 匹配，查询指纹本身退化时直接返回空集（信号不足，宁缺勿滥）。
  static Future<List<Map<String, dynamic>>> match(
    MemoryRepository repo,
    Map<String, dynamic> fingerprint, {
    double threshold = 0.6,
    bool exactAppOnly = false,
  }) async {
    if (isDegenerateFingerprint(fingerprint)) {
      return const <Map<String, dynamic>>[];
    }
    final memories = await load(repo);
    final scored = <(ApkPatchMemory, double)>[];
    final queryApp = appKey(fingerprint);
    for (final memory in memories) {
      if (exactAppOnly &&
          (queryApp.isEmpty || appKey(memory.fingerprint) != queryApp)) {
        continue;
      }
      // 记忆侧用宽判定：flutter 旧格式记忆放行（matchScore 兜底防误命中）
      if (_isDegenerateMemory(memory.fingerprint)) continue;
      final s = matchScore(memory.fingerprint, fingerprint);
      if (s >= threshold) scored.add((memory, s));
    }
    scored.sort((a, b) {
      final byScore = b.$2.compareTo(a.$2);
      if (byScore != 0) return byScore;
      return _outcomeRank(a.$1.outcome).compareTo(_outcomeRank(b.$1.outcome));
    });
    return [
      for (final (memory, score) in scored)
        {
          'id': memory.id,
          'title': memory.title,
          'solution': memory.solution,
          'outcome': memory.outcome,
          'operation': memory.operation,
          if (memory.pitfall.isNotEmpty) 'pitfall': memory.pitfall,
          if (memory.targets.isNotEmpty) 'targets': memory.targets,
          'score': score,
          ...artifactPresenceOf(memory),
        },
    ];
  }

  /// 产物在场性（用户报告 #4）：记忆说"验证通过"，但它记的成品文件可能**已经不在
  /// 工作目录里**（被清理/换机/换目录）。旧行为只回 `verified_success`，调用方会以为
  /// 自己有一条可用基线——出现"已验证记录在场、已验证产物不在场"的不一致态。
  ///
  /// 这里按 `artifacts[].path` 逐个 stat，如实回报：
  ///   - 全部在场 → `artifactPresence: {present: n, missing: 0}`
  ///   - 有缺失 → 额外给 `artifactMissing: true` + `artifactMissingPaths` + 处置指引
  /// 只读 stat，不改记忆（记忆里该不该标 missing 是另一件事：文件可能只是被移走，
  /// 标脏会污染后续反查）。
  static Map<String, dynamic> artifactPresenceOf(ApkPatchMemory memory) {
    final recorded = memory.artifacts
        .map((a) => (a['path'] ?? '').toString().trim())
        .where((p) => p.isNotEmpty)
        .toList();
    if (recorded.isEmpty) {
      return const <String, dynamic>{'artifactPresence': 'not_recorded'};
    }
    final present = <String>[];
    final missing = <String>[];
    for (final path in recorded) {
      // File.existsSync 是同步 stat：一次工具调用最多几条记忆、每条几个产物，
      // 开销可忽略，不值得为它引入异步。
      if (File(path).existsSync()) {
        present.add(path);
      } else {
        missing.add(path);
      }
    }
    return <String, dynamic>{
      'artifactPresence': missing.isEmpty ? 'present' : 'missing',
      'artifactPresentCount': present.length,
      'artifactMissingCount': missing.length,
      if (missing.isNotEmpty) 'artifactMissingPaths': missing,
      if (missing.isNotEmpty)
        'artifactMissingNote':
            '这条经验记的成品文件已不在工作目录（$missing）。**不要把它当成可用基线**：'
            '当前工作区里没有对应产物，引用它之前先确认目标文件是否存在，'
            '需要重放时按同 APP 的 rootSource 重新走一遍补丁流程（记忆里的方案与改点仍然有效）。',
    };
  }

  /// 供 AI 读取：当前报告指纹匹配的经验，JSON 编码。
  ///
  /// 匹配优先（用户要求）：默认只返回与当前 APP 匹配的 active 经验；
  /// 匹配为空时降级返回同 APP 的 archived 旧版本经验（标注供复查）；
  /// [listAll]=true 时返回全部 active 经验的简表（id/title/版本/结论），
  /// 供 agent 主动浏览全部记忆而不只看匹配项。
  static Future<String> readForAi(
    MemoryRepository repo,
    Map<String, dynamic> fingerprint, {
    bool listAll = false,
  }) async {
    if (listAll) {
      final all = await load(repo);
      return jsonEncode({
        'listAll': true,
        'count': all.length,
        'memories': [
          for (final m in all)
            {
              'id': m.id,
              'title': m.title,
              'appId': appKey(m.fingerprint),
              'versionName':
                  (m.fingerprint['versionName'] ?? '').toString(),
              'outcome': m.outcome,
            },
        ],
        // D10（2026-09-21 复验）：这两条语义必须说清楚，否则读起来是"自相矛盾"——
        // ① `versionName` 是**验证当时分析报告（源包）**的版本，不是成品自身读出的
        //    版本，报告过期/换包时会与成品不符，字段为空表示当时报告没给；
        // ② `title` 是**首次登记时**写的草稿标题，后续验证只更新 `outcome`——
        //    两者不一致时以 `outcome` 为准（标题保持历史原文，便于与当时对话对上）。
        'fieldSemantics': <String, String>{
          'versionName':
              '验证当时分析报告（源包）的版本，非成品自读版本；空 = 当时报告未提供。',
          'title': '首次登记时的草稿标题；验证结论看 outcome，不看标题措辞。',
          'outcome': '本条经验的当前结论（verified_success / verified_failure 等）。',
        },
        'hint':
            '全部经验的简表。要看某条的完整方案/改点，按对应 APP 分析后用默认匹配模式读取；'
            '不要盲目展开全部全文。',
      });
    }
    if (isDegenerateFingerprint(fingerprint)) {
      return jsonEncode({
        'fingerprint': fingerprint,
        'matchedMemories': const <Map<String, dynamic>>[],
        'hint':
            '当前报告缺少类型信号（未检出广告厂商与壳）：无法判定同类，'
            '不返回历史经验以免误导。此类 APK 的经验复用价值低，'
            '安装验证后也只记录带明确指纹（厂商/壳命中）的经验。',
      });
    }
    final matched = await match(repo, fingerprint, exactAppOnly: true);
    if (matched.isNotEmpty) {
      return jsonEncode({
        'fingerprint': fingerprint,
        'matchedMemories': matched,
        'hint': '这里只返回当前 APP 已确认的单条经验；其他 APP 或其他会话的待验证产物笔记不会返回。优先参考 outcome=verified_success；verified_failure 仅用于避坑，unverified_legacy 不能直接采信。'
                '条目含 pitfall 字段时为易错点警示（怎么改才对），向用户展示时须与 solution 并列单独成行醒目呈现，不要淹没在方案长文本里。',
      });
    }
    // 匹配为空 → 降级：同 APP 的 archived 旧版本经验（供新版本复查）
    final app = appKey(fingerprint);
    if (app.isNotEmpty) {
      final archived = (await load(repo, includeArchived: true))
          .where(
            (m) =>
                m.status == MemoryStatus.archived && appKey(m.fingerprint) == app,
          )
          .toList();
      if (archived.isNotEmpty) {
        return jsonEncode({
          'fingerprint': fingerprint,
          'matchedMemories': [
            for (final m in archived)
              {
                'id': m.id,
                'title': m.title,
                'solution': m.solution,
                'outcome': m.outcome,
                'operation': m.operation,
                if (m.pitfall.isNotEmpty) 'pitfall': m.pitfall,
                if (m.targets.isNotEmpty) 'targets': m.targets,
                'legacyForReference': true,
                'versionName': (m.fingerprint['versionName'] ?? '').toString(),
              },
          ],
          'hint':
              '当前 APP 无 active 经验，以上为旧版本已归档经验（legacyForReference=true）：'
              '作为假设起点先验证旧逻辑是否延续，确认后用 record_apk_patch_verification 更新为新版本方案。',
        });
      }
    }
    // 跨 APP 方法论降级命中（2026-09-21 真机复盘 P1）：
    // 本机早有一条「Flutter AOT 会员解锁」的 verified_success 经验，指纹同为
    // engine=flutter / 无壳 / vipBucket=some，只因 appId 不同就被丢弃，
    // matchedMemories 回空 → agent 从零重推，约多走 20 次工具调用。
    //
    // 为什么不是放宽 matchedMemories：appId 是用户定案硬边界（distill 里写明
    // 「一个软件一条经验，跨 APP 永不合并」），且 solution 全文跨包复用本来就
    // 不是证据。所以单开一个字段：只给"方法级"摘要（标题/操作/结论），
    // 明确标注非本包证据。
    final methodology = await matchMethodology(repo, fingerprint);
    if (methodology.isNotEmpty) {
      return jsonEncode({
        'fingerprint': fingerprint,
        'matchedMemories': const <Map<String, dynamic>>[],
        'crossAppMethodology': methodology,
        'hint': '当前 APP 无已验证经验。crossAppMethodology 是**其他 APP** 的同类（同引擎/同会员形态）'
                '经验摘要——它只说明"这类包通常怎么做"，**不是本包证据**，具体 VA/字段/偏移一律不可复用，'
                '必须在本包重新定位。用它的标题当检索线索（例如里面的类名/函数名形态）去 search/pool，'
                '不要照搬补丁。',
      });
    }
    return jsonEncode({
      'fingerprint': fingerprint,
      'matchedMemories': const <Map<String, dynamic>>[],
      'hint': '当前 APP 无已验证经验。安装验证后用 record_apk_patch_verification 记录结果。',
    });
  }

  /// 跨 APP 方法论摘要：同 engine + 同 flutterProfile(mode/abi/vipBucket) 的其他
  /// APP 经验，按结论优先、分数次之排序，最多 3 条。
  ///
  /// 与 [peekSimilarExperiences] 同样只给"谁有经验"级别的摘要（标题/操作/结论），
  /// 不给 solution 全文——跨包方案全文既不是证据也容易误导照搬。区别是它还要
  /// 求"同任务形态"（vipBucket 一致），避免把纯广告包的经验当成会员包的方法论。
  static Future<List<Map<String, dynamic>>> matchMethodology(
    MemoryRepository repo,
    Map<String, dynamic> fingerprint,
  ) async {
    if (isDegenerateFingerprint(fingerprint)) {
      return const <Map<String, dynamic>>[];
    }
    final queryApp = appKey(fingerprint);
    final engine = (fingerprint['engine'] ?? '').toString();
    final queryProfile = fingerprint['flutterProfile'];
    // 只在有明确任务形态时降级命中：engine 必须有，且 Flutter 包必须有
    // flutterProfile（mode/abi/vipBucket）。缺形态的指纹命中等于凭"都是 Flutter"
    // 乱猜，正是旧版把两个包并成一坨的原因。
    if (engine.isEmpty) return const <Map<String, dynamic>>[];
    if (engine == 'flutter' && queryProfile is! Map) {
      return const <Map<String, dynamic>>[];
    }
    final queryBucket =
        queryProfile is Map ? (queryProfile['vipBucket'] ?? '').toString() : '';
    final queryMode =
        queryProfile is Map ? (queryProfile['mode'] ?? '').toString() : '';
    final bestByApp = <String, (ApkPatchMemory, double)>{};
    for (final memory in await load(repo)) {
      if (_isDegenerateMemory(memory.fingerprint)) continue;
      final appId = appKey(memory.fingerprint);
      if (appId.isEmpty || appId == queryApp) continue;
      if ((memory.fingerprint['engine'] ?? '').toString() != engine) continue;
      final profile = memory.fingerprint['flutterProfile'];
      if (engine == 'flutter') {
        if (profile is! Map) continue;
        if ((profile['vipBucket'] ?? '').toString() != queryBucket) continue;
        if (queryMode.isNotEmpty &&
            (profile['mode'] ?? '').toString() != queryMode) {
          continue;
        }
      }
      final score = matchScore(memory.fingerprint, fingerprint);
      final current = bestByApp[appId];
      if (current == null ||
          _outcomeRank(memory.outcome) < _outcomeRank(current.$1.outcome) ||
          (memory.outcome == current.$1.outcome && score > current.$2)) {
        bestByApp[appId] = (memory, score);
      }
    }
    final ranked = bestByApp.values.toList()
      ..sort((a, b) {
        final byOutcome =
            _outcomeRank(a.$1.outcome).compareTo(_outcomeRank(b.$1.outcome));
        if (byOutcome != 0) return byOutcome;
        return b.$2.compareTo(a.$2);
      });
    return [
      for (final (memory, score) in ranked.take(3))
        {
          'appId': appKey(memory.fingerprint),
          'title': memory.title,
          'operation': memory.operation,
          'outcome': memory.outcome,
          'matchScore': score,
          'evidenceScope': 'other_app_methodology_only',
        },
    ];
  }

  /// resume-state 自动浮现（2026-09-05）：只回答「有没有、是什么」，不携带
  /// 方案全文——全文仍须经 get_apk_patch_memory 按需读取。
  ///
  /// 背景：apk_patch/apk_note/apk_failure 三类不在通用记忆注入白名单
  /// （memory_block_builder 只注 identity/workflow/voice/instruction），
  /// 库里有经验时 Agent 上下文零信号，提示词精简后更无引导——
  /// 「明明有经验，AI 不看，看的是别的记忆」实测事故。本方法由
  /// main() 装进 ApkWorkspaceBindingService.verifiedExperiencePeek，
  /// taskResumeState 命中时注入 verifiedExperience 键：程序负责让它被
  /// 看见，LLM 只负责判断要不要用。无命中回 null（零成本不加键）。
  static Future<Map<String, dynamic>?> peekVerifiedExperience(
    MemoryRepository repo,
    Map<String, dynamic> fingerprint,
  ) async {
    if (isDegenerateFingerprint(fingerprint)) return null;
    final matched = await match(repo, fingerprint, exactAppOnly: true);
    if (matched.isNotEmpty) {
      final best = matched.first;
      return <String, dynamic>{
        'availability': 'active',
        'title': best['title'] ?? '',
        'appId': appKey(fingerprint),
        'outcome': best['outcome'] ?? '',
        'matchScore': best['score'],
        'targetsCount': (best['targets'] as List?)?.length ?? 0,
        'hint': '当前 APP 存在已验证经验：完整方案/易错点/改点清单用 '
            'get_apk_patch_memory 读取后再动手，不要凭标题复写。',
      };
    }
    final app = appKey(fingerprint);
    if (app.isEmpty) return null;
    final archived = (await load(repo, includeArchived: true))
        .where(
          (m) =>
              m.status == MemoryStatus.archived && appKey(m.fingerprint) == app,
        )
        .toList();
    if (archived.isNotEmpty) {
      return <String, dynamic>{
        'availability': 'archived',
        'title': archived.first.title,
        'appId': app,
        'versionName':
            (archived.first.fingerprint['versionName'] ?? '').toString(),
        'outcome': archived.first.outcome,
        'hint': '无 active 经验，但存在旧版本归档经验：先核实旧逻辑是否延续，'
            '确认后用 get_apk_patch_memory 读取详情并更新。',
      };
    }
    // 精确/归档皆无 → 跨 APP 同类经验浮现（C1）
    final similar = await peekSimilarExperiences(repo, fingerprint);
    if (similar.isEmpty) return null;
    return <String, dynamic>{
      'availability': 'similar',
      'appId': app,
      'similar': similar,
      'hint': '本 APP 无已验证经验，但存在 ${similar.length} 条同类经验'
          '（类型指纹命中，思路大概率可迁移）：用 get_apk_patch_memory'
          '(listAll:true) 浏览后按 appId 读取对应详情，方案须先验证再采信。',
    };
  }

  // ---- peek 结果记忆化（P1/P2，2026-09-05）----
  // taskResumeState 每条消息被调用 2~3 次，每次都完整走
  // 规则匹配 → 指纹 → peek（多次 SQLite 读）。peek 结果只取决于
  // （指纹, 经验集合），故按 fingerprintKey|count|maxTimestamp 记忆化：
  // 经验增删/验证（timestamp 前进）自动失效，无变化直接复用。
  static ({String key, Map<String, dynamic>? result})? _peekCache;

  /// 测试专用：清空 peek 缓存（静态状态跨测试泄漏防护）。
  static void resetPeekCacheForTest() => _peekCache = null;

  static Future<List<ApkPatchMemory>> _loadAllForRev(
    MemoryRepository repo,
  ) => load(repo, includeArchived: true);

  /// main() 钩子的实际入口：报告已在钩子层读好，指纹在此计算并复用缓存。
  static Future<Map<String, dynamic>?> peekVerifiedExperienceCached(
    MemoryRepository repo, {
    required Map<String, dynamic> report,
    required Set<String> vendors,
  }) async {
    final fingerprint = fingerprintFromReport(report, vendors: vendors);
    if (isDegenerateFingerprint(fingerprint)) return null;
    final memories = await _loadAllForRev(repo);
    var maxTs = 0;
    for (final m in memories) {
      if (m.timestamp > maxTs) maxTs = m.timestamp;
    }
    final key =
        '${fingerprintKey(fingerprint)}|${memories.length}|$maxTs';
    final cached = _peekCache;
    if (cached != null && cached.key == key) return cached.result;
    final result = await peekVerifiedExperience(repo, fingerprint);
    _peekCache = (key: key, result: result);
    return result;
  }

  /// 本 APP 无精确/归档经验时，浮现**跨 APP 同类**经验（C1，2026-09-05）：
  /// 类型指纹体系的核心红利——「同类 90% 代码相似」，vendors/shell/engine
  /// 任一维度命中 ≥0.6 的其他 APP 经验对新 APP 首任务同样有参考价值。
  /// 按 appId 去重（同 APP 多条取最高分）、verified_success 优先、≤3 条，
  /// 只给「谁有经验」不给方案全文。
  static Future<List<Map<String, dynamic>>> peekSimilarExperiences(
    MemoryRepository repo,
    Map<String, dynamic> fingerprint,
  ) async {
    if (isDegenerateFingerprint(fingerprint)) {
      return const <Map<String, dynamic>>[];
    }
    final queryApp = appKey(fingerprint);
    final bestByApp = <String, (ApkPatchMemory, double)>{};
    for (final memory in await load(repo)) {
      if (_isDegenerateMemory(memory.fingerprint)) continue;
      final appId = appKey(memory.fingerprint);
      if (appId.isEmpty || appId == queryApp) continue;
      final score = matchScore(memory.fingerprint, fingerprint);
      if (score < 0.6) continue;
      final current = bestByApp[appId];
      if (current == null ||
          _outcomeRank(memory.outcome) < _outcomeRank(current.$1.outcome) ||
          (memory.outcome == current.$1.outcome && score > current.$2)) {
        bestByApp[appId] = (memory, score);
      }
    }
    final ranked = bestByApp.values.toList()
      ..sort((a, b) {
        final byOutcome =
            _outcomeRank(a.$1.outcome).compareTo(_outcomeRank(b.$1.outcome));
        if (byOutcome != 0) return byOutcome;
        return b.$2.compareTo(a.$2);
      });
    return [
      for (final (memory, score) in ranked.take(3))
        {
          'appId': appKey(memory.fingerprint),
          'title': memory.title,
          'outcome': memory.outcome,
          'matchScore': score,
        },
    ];
  }

  /// 旧版 SharedPreferences 迁移：把 [raw]（旧 blob JSON）转成 MemoryEntry 草案。
  /// migrationId 幂等防重复。仅由迁移器调用。
  static List<MemoryCreateDraft> draftsFromLegacyJson(String raw) {
    try {
      final decoded = jsonDecode(raw) as List<dynamic>;
      return [
        for (final e in decoded)
          if (e is Map)
            MemoryCreateDraft(
              scope: MemoryScope.assistant,
              assistantId: _assistantId,
              type: MemoryType.apkPatch,
              content: (e['solution'] ?? '').toString(),
              source: MemorySource.tool,
              migrationId: 'apk_patch_${e['id']}',
              extraJson: {
                'title': (e['title'] ?? '').toString(),
                'fingerprint': e['fingerprint'] is Map
                    ? e['fingerprint']
                    : const <String, dynamic>{},
                'outcome': (e['outcome'] ?? 'unverified').toString(),
                'operation': (e['operation'] ?? '').toString(),
                'timestamp': (e['timestamp'] as num?)?.toInt() ?? 0,
              },
            ),
      ];
    } catch (_) {
      return const <MemoryCreateDraft>[];
    }
  }

  /// 旧版 SharedPreferences key（迁移后删除）。
  static const String legacyKey = _legacyKey;

  static Future<void> removeLegacyKey() async {
    final prefs = await SharedPreferences.getInstance();
    if (prefs.containsKey(_legacyKey)) {
      await prefs.remove(_legacyKey);
    }
  }
}
