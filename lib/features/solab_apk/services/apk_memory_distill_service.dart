import 'dart:convert';

import '../../../core/models/memory_entry.dart';
import '../../../core/services/memory/memory_repository.dart';
import 'apk_patch_memory_service.dart';

/// [ApkMemoryDistillService.scan] 的结果：分组 + 「为什么没分组」的诊断。
///
/// 用户 2026-10-04：点「整理蒸馏经验」只看到「无需整理」是黑盒——不知道是数据
/// 本来就只有一条，还是老记忆缺包名聚不起来。这里把口径摊开给 UI。
class ApkDistillScan {
  const ApkDistillScan({
    required this.groups,
    required this.activePatchCount,
    required this.candidateCount,
    required this.appsWithSingle,
    required this.withoutAppId,
    required this.degenerate,
  });

  final List<List<MemoryEntry>> groups;

  /// active 的 APK 经验总数。
  final int activePatchCount;

  /// 进入分组判定的条数（有包名、指纹不退化）。
  final int candidateCount;

  /// 只有一条经验的 APP 数（本来就没得合并）。
  final int appsWithSingle;

  /// 缺包名、无法判定是否同一 APP 的条数（保守不合并——跨 APP 合并是历史事故）。
  final int withoutAppId;

  /// 指纹退化（无厂商无壳）或无指纹键的条数。
  final int degenerate;

  bool get hasWork => groups.isNotEmpty;
}

/// APK 经验蒸馏：把同一指纹下的多条零散经验合并为一条精简条目。
///
/// 复用记忆模型（设置→记忆的模型选择）；LLM 不可用时降级为确定性合并
///（保留最新 verified 条目 + 其余归档）。结果由调用方预览确认后写回。
class ApkMemoryDistillService {
  const ApkMemoryDistillService._();

  /// 蒸馏后的方案上限：行数 / 字符数。
  ///
  /// 蒸馏的意义是「精简」，不是把 N 条拼成一大段（用户 2026-10-04「格式不固定、
  /// 不好管理」）。超出部分**不丢**：写回是归档而不是删除，完整原文仍在归档条目里。
  static const int maxSolutionLines = 20;
  static const int maxSolutionChars = 2000;
  static const int maxPitfallLines = 6;
  static const int maxPitfallChars = 800;

  /// 一个待蒸馏分组：同类的多条经验。
  ///
  /// 分组边界：**同 appId**（一个软件一条经验，跨 APP 永不合并）。
  /// 缺包名的条目无法判定归属，宁可不动——[scan] 会把条数报给 UI。
  /// （历史注释曾说按 matchScore >= threshold 聚类，实际早已改为 appId 硬边界，
  /// 这里同步更正；[threshold] 参数保留只为兼容旧调用点。）
  static Future<ApkDistillScan> scan(
    MemoryRepository repo, {
    double threshold = 0.6,
  }) async {
    final all = await repo.readAll();
    // 只扫 active：写回是「归档旧条目 + 新增合并条目」，归档件不该再次进入
    // 分组，否则每点一次蒸馏都会把同一批再合一遍。
    final patch = all
        .where(
          (e) =>
              e.type == MemoryType.apkPatch &&
              e.status == MemoryStatus.active,
        )
        .toList();
    final candidates = <MemoryEntry>[];
    final fingerprints = <Map<String, dynamic>>[];
    var withoutAppId = 0;
    var degenerate = 0;
    for (final e in patch) {
      final fp = ApkPatchMemoryService.entryFingerprint(e);
      if (ApkPatchMemoryService.fingerprintKey(fp).isEmpty) {
        degenerate++;
        continue;
      }
      // 缺包名 = 无法确认是不是同一个 APP（跨 APP 合并是历史事故：
      // 所有 Flutter arm64 包被并成一坨），只报数、不合并。
      if (ApkPatchMemoryService.appKey(fp).isEmpty) {
        withoutAppId++;
        continue;
      }
      if (ApkPatchMemoryService.isDegenerateFingerprint(fp)) {
        degenerate++;
        continue;
      }
      candidates.add(e);
      fingerprints.add(fp);
    }
    // 并查集：同一 appId 即同组
    final parent = List<int>.generate(candidates.length, (i) => i);
    int find(int x) => parent[x] == x ? x : (parent[x] = find(parent[x]));
    void union(int a, int b) {
      final ra = find(a);
      final rb = find(b);
      if (ra != rb) parent[ra] = rb;
    }

    for (var i = 0; i < candidates.length; i++) {
      for (var j = i + 1; j < candidates.length; j++) {
        final sameApp =
            ApkPatchMemoryService.appKey(fingerprints[i]).isNotEmpty &&
            ApkPatchMemoryService.appKey(fingerprints[i]) ==
                ApkPatchMemoryService.appKey(fingerprints[j]);
        if (sameApp) {
          union(i, j);
        }
      }
    }
    final byRoot = <int, List<MemoryEntry>>{};
    for (var i = 0; i < candidates.length; i++) {
      byRoot.putIfAbsent(find(i), () => <MemoryEntry>[]).add(candidates[i]);
    }
    final groups = <List<MemoryEntry>>[];
    var appsWithSingle = 0;
    for (final g in byRoot.values) {
      if (g.length > 1) {
        // 组内按时间升序（oldest first），蒸馏 prompt 的"第一条"最稳定
        g.sort(
          (a, b) => ((a.extraJson ?? const {})['timestamp'] as num? ?? 0)
              .compareTo((b.extraJson ?? const {})['timestamp'] as num? ?? 0),
        );
        groups.add(g);
      } else {
        appsWithSingle++;
      }
    }
    return ApkDistillScan(
      groups: groups,
      activePatchCount: patch.length,
      candidateCount: candidates.length,
      appsWithSingle: appsWithSingle,
      withoutAppId: withoutAppId,
      degenerate: degenerate,
    );
  }

  /// 兼容旧调用点：只要分组。
  static Future<List<List<MemoryEntry>>> groupsForDistill(
    MemoryRepository repo, {
    double threshold = 0.6,
  }) async => (await scan(repo, threshold: threshold)).groups;

  /// 用 LLM 把一组经验合并为一条 [ApkPatchMemory]（未写回）。
  /// [llmCall] 失败抛错，由调用方降级。
  static Future<ApkPatchMemory> distillGroupWithLlm({
    required List<MemoryEntry> group,
    required Future<String> Function(String prompt) llmCall,
  }) async {
    final prompt = _buildPrompt(group);
    final raw = await llmCall(prompt);
    final parsed = _parseLlmResult(raw);
    final fallback = distillGroupDeterministic(group);
    final parsedTitle = (parsed['title'] ?? '').toString().trim();
    final parsedSolution = (parsed['solution'] ?? '').toString().trim();
    final parsedOperation = (parsed['operation'] ?? '').toString().trim();
    final parsedPitfall = (parsed['pitfall'] ?? '').toString().trim();
    final parsedTargets = parsed['targets'] is List
        ? (parsed['targets'] as List)
              .map((e) => e.toString().trim())
              .where((e) => e.isNotEmpty)
              .toList()
        : const <String>[];
    final parsedFingerprint = parsed['fingerprint'] is Map
        ? Map<String, dynamic>.from(parsed['fingerprint'] as Map)
        : const <String, dynamic>{};
    final keepParsedFingerprint =
        ApkPatchMemoryService.appKey(fallback.fingerprint).isEmpty ||
        ApkPatchMemoryService.appKey(parsedFingerprint) ==
            ApkPatchMemoryService.appKey(fallback.fingerprint);
    // 半成品（有 solution 没 title、超长拼接）比降级更糟：缺字段一律回落
    // 确定性合并结果，长度收敛到 [maxSolutionChars] / [maxSolutionLines]。
    return fallback.copyWith(
      fingerprint: keepParsedFingerprint && parsedFingerprint.isNotEmpty
          ? parsedFingerprint
          : fallback.fingerprint,
      title: parsedTitle.isEmpty ? fallback.title : parsedTitle,
      solution: parsedSolution.isEmpty
          ? fallback.solution
          : clampSolution(parsedSolution),
      timestamp: DateTime.now().millisecondsSinceEpoch,
      operation: parsedOperation.isEmpty ? fallback.operation : parsedOperation,
      pitfall: clampPitfall(
        ApkPatchMemoryService.mergePitfall(fallback.pitfall, parsedPitfall),
      ),
      targets: {...fallback.targets, ...parsedTargets}.toList(),
    );
  }

  /// 确定性降级合并：所有方案、易错点和定位符都并入同一条。
  static ApkPatchMemory distillGroupDeterministic(List<MemoryEntry> group) {
    final memories = group.map(ApkPatchMemoryService.entryToMemory).toList()
      ..sort((a, b) => a.timestamp.compareTo(b.timestamp));
    final base = memories.last;
    final verifiedSuccess =
        group
            .map(ApkPatchMemoryService.entryToMemory)
            .where((m) => m.outcome == 'verified_success')
            .toList()
          ..sort((a, b) => b.timestamp.compareTo(a.timestamp));
    final seed = verifiedSuccess.isNotEmpty ? verifiedSuccess.first : base;
    var solution = '';
    var pitfall = '';
    final targets = <String>{};
    for (final memory in memories) {
      solution = solution.isEmpty
          ? memory.solution
          : ApkPatchMemoryService.mergeSolution(solution, memory.solution);
      pitfall = ApkPatchMemoryService.mergePitfall(pitfall, memory.pitfall);
      targets.addAll(memory.targets);
    }
    return seed.copyWith(
      id: memories.first.id,
      fingerprint: base.fingerprint,
      solution: clampSolution(solution),
      timestamp: DateTime.now().millisecondsSinceEpoch,
      outcome: _bestOutcome(group),
      pitfall: clampPitfall(pitfall),
      targets: targets.toList(),
    );
  }

  /// 蒸馏后的方案收敛到可管理规模（超出部分标注省略量）。
  static String clampSolution(String solution) =>
      _clampText(solution, maxLines: maxSolutionLines, maxChars: maxSolutionChars);

  /// 易错点同样收敛（多条拼接很容易越滚越长）。
  static String clampPitfall(String pitfall) =>
      _clampText(pitfall, maxLines: maxPitfallLines, maxChars: maxPitfallChars);

  static String _clampText(
    String text, {
    required int maxLines,
    required int maxChars,
  }) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return trimmed;
    final lines = <String>[
      for (final line in trimmed.split('\n'))
        if (line.trim().isNotEmpty) line.trim(),
    ];
    var kept = lines;
    var droppedLines = 0;
    if (lines.length > maxLines) {
      kept = lines.sublist(0, maxLines);
      droppedLines = lines.length - maxLines;
    }
    var out = kept.join('\n');
    var droppedChars = 0;
    if (out.length > maxChars) {
      out = out.substring(0, maxChars).trimRight();
      droppedChars = trimmed.length - out.length;
    }
    if (droppedLines == 0 && droppedChars == 0) return out;
    final notes = <String>[
      if (droppedLines > 0) '另有 $droppedLines 行',
      if (droppedChars > 0) '约 $droppedChars 字',
    ];
    // 完整原文留在归档条目里（applyDistill 是归档而不是删除）。
    return '$out\n…（${notes.join('、')}已省略，完整内容见归档条目）';
  }

  /// 写回：新增一条合并结果，**归档**（而不是删除）被合并的旧条目。
  ///
  /// 用户 2026-10-04：硬删除不可撤销，且预览面板的注释写「归档旧条目」与实现
  /// 不符。归档后：工具链默认只读 active（`ApkPatchMemoryService.load`），
  /// 行为不变；用户仍能在「已归档」区复查原文，蒸馏可撤销。
  static Future<void> applyDistill({
    required MemoryRepository repo,
    required List<MemoryEntry> group,
    required ApkPatchMemory merged,
  }) {
    return repo.runExclusive(() async {
      final all = await repo.readAll();
      final mergedIds = group.map((e) => e.id).toSet();
      final now = DateTime.now().toUtc();
      final next = <MemoryEntry>[
        for (final e in all)
          if (mergedIds.contains(e.id))
            e.copyWith(status: MemoryStatus.archived, updatedAt: now)
          else
            e,
      ];
      // 合并条目必须拿新 id：旧 id 还挂在归档条目上（沿用会撞 id）。
      next.add(
        ApkPatchMemoryService.memoryToEntry(
          merged.copyWith(id: MemoryEntry.newId()),
        ),
      );
      await repo.writeAll(next);
    });
  }

  static String _bestOutcome(List<MemoryEntry> group) {
    final outcomes = group
        .map((e) => ((e.extraJson ?? const {})['outcome'] ?? '').toString())
        .toSet();
    if (outcomes.contains('verified_success')) return 'verified_success';
    if (outcomes.contains('verified_failure')) return 'verified_failure';
    return 'unverified';
  }

  static String _buildPrompt(List<MemoryEntry> group) {
    final lines = <String>[];
    for (final e in group) {
      final extra = e.extraJson ?? const <String, dynamic>{};
      lines.add(
        '- [${(extra['outcome'] ?? 'unverified')}] '
        '${(extra['title'] ?? '')}: ${e.content}',
      );
    }
    return '''
你是 APK 修改经验整理助手。下面是同一个 APP 或同类 APK 的多条修改经验。必须合并为一条完整、精简、可继续更新的长期记忆。

要求：
1. 只输出 JSON（不要任何解释或 Markdown 代码块）。
2. JSON 字段：title、solution、operation、fingerprint、pitfall、targets。fingerprint 必须原样保留；targets 是去重后的字符串数组。
3. 不得丢失任何已验证改点、真实字节依据、易错点和定位符。相同内容去重；verified_success 作为结论，verified_failure 只并入 pitfall。
4. solution **固定四节**（每节以标记开头，顺序固定，最多 $maxSolutionLines 行 / $maxSolutionChars 字）：
   [结论] 一句话说清最终做法
   [改点] 每条一行：定位符 + 操作（多个改点各占一行）
   [坑] 怎么改会错（verified_failure 与易错点并入这里）
   [证据] 关键字节依据 / 产物指纹，一行一条
   没有内容的节可以省略；**不要**写排查流水、不要复述原文。
5. title ≤ 40 字；pitfall ≤ $maxPitfallChars 字且不换行。

指纹参考（原样保留）：${jsonEncode(ApkPatchMemoryService.entryFingerprint(group.first))}

经验列表：
${lines.join('\n')}
''';
  }

  static Map<String, dynamic> _parseLlmResult(String raw) {
    try {
      final cleaned = raw
          .trim()
          .replaceFirst(RegExp(r'^```(?:json)?\s*'), '')
          .replaceFirst(RegExp(r'\s*```$'), '');
      final decoded = jsonDecode(cleaned);
      if (decoded is Map) {
        return Map<String, dynamic>.from(decoded);
      }
      return const <String, dynamic>{};
    } catch (_) {
      return const <String, dynamic>{};
    }
  }
}
