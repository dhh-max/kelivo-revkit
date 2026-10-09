import 'dart:async';
import 'dart:collection';

import '../services/apk_analysis_service.dart';
import '../services/apk_toolchain_service.dart';
import '../services/apk_workspace_binding_service.dart';
import '../services/apk_workspace_service.dart';
import 'analyzer_api.dart';
import 'analyzer_index.dart';// ============================================================================
// AnalyzerGateway 实现（Phase 0）
//
// Agent 通过 4 个高阶 API 访问分析引擎；底层工具对内执行。
// ============================================================================

class AnalyzerGatewayRegistry {
  AnalyzerGatewayRegistry._();

  static const _maxContexts = 8;
  static final LinkedHashMap<String, DefaultAnalyzerGateway> _byContext =
      LinkedHashMap<String, DefaultAnalyzerGateway>();

  static AnalyzerGateway forKey(String contextKey) {
    final key = contextKey.trim().isEmpty ? 'app' : contextKey.trim();
    final existing = _byContext.remove(key);
    if (existing != null) {
      _byContext[key] = existing;
      return existing;
    }
    final created = DefaultAnalyzerGateway();
    _byContext[key] = created;
    while (_byContext.length > _maxContexts) {
      _byContext.remove(_byContext.keys.first);
    }
    return created;
  }

  static void resetForTest() => _byContext.clear();
}

class DefaultAnalyzerGateway implements AnalyzerGateway {
  DefaultAnalyzerGateway({AnalyzerIndex? index})
    : index = index ?? AnalyzerIndex(apkId: 'unbound');

  AnalyzerIndex index;

  /// 最近 open 的 APK 路径（按需分析时用作兜底路径）。
  String _lastOpenedApkPath = '';

  /// 字段级 LRU 缓存：fieldLocator → 扫描结果。访问什么缓存什么，
  /// 不预建全量索引。命中直接返回，避免重复扫 dex。
  final Map<String, List<FieldRef>> _fieldRefCache = <String, List<FieldRef>>{};
  static const int _fieldRefCacheMax = 512;
  final Map<String, AnalyzerResult> _businessStateCache =
      <String, AnalyzerResult>{};
  static const int _businessStateCacheMax = 128;

  void _cacheFieldRefs(String cacheKey, List<FieldRef> refs) {
    if (refs.isEmpty) return;
    _fieldRefCache[cacheKey] = refs;
    // 简单 LRU 淘汰：超出上限删最旧（LinkedHashMap 按插入序）。
    while (_fieldRefCache.length > _fieldRefCacheMax) {
      _fieldRefCache.remove(_fieldRefCache.keys.first);
    }
  }

  void _cacheBusinessState(String key, AnalyzerResult result) {
    _businessStateCache[key] = result;
    while (_businessStateCache.length > _businessStateCacheMax) {
      _businessStateCache.remove(_businessStateCache.keys.first);
    }
  }

  static DefaultAnalyzerGateway get instance =>
      AnalyzerGatewayRegistry.forKey('app') as DefaultAnalyzerGateway;

  /// 当前分析目标的缓存键哈希（apkId 的 sha256 摘要，长度 >=16）。
  /// apkId 形如 `sha256:<64hex>`；直接取 hash 段即可稳定跨调用复用。
  String get _analysisCacheKeyHash {
    final id = index.apkId;
    if (id.startsWith('sha256:')) {
      final hex = id.substring('sha256:'.length);
      if (hex.length >= 16) return hex;
    }
    // 非 sha256 身份（如 apk:<path>）：用对象 hash 兜底，
    // 至少保证同一会话同一目标命中同一缓存槽。
    return id.hashCode.toRadixString(16).padLeft(16, '0');
  }

  /// 最近一次主数据源（analyzeModule fields）的诊断标签。
  /// 仅用于在回退信封里如实交代"为什么走到了内存索引"。
  String _lastPrimarySourceNote = 'not_attempted';

  /// 主数据源返回的候选名样本（最多 20 个）。
  /// 用于向调用方如实交代"模块扫到了哪些字段"，判断无匹配是词表问题
  /// 还是关键词真不存在（R8 混淆后字段名常为 a/b/c）。
  List<String> _lastPrimaryCandidateNames = const <String>[];

  /// analyzer 是否尚未绑定任何 APK（空结果可能因未绑定，需在响应里提示，
  /// 避免模型把 unbound 的空结果当"目标不存在"）。
  bool get _unbound => index.apkId == 'unbound';

  AnalyzerResult? _contextMismatch(String query, String? requestedApkId) {
    final requested = requestedApkId?.trim();
    if (requested == null || requested.isEmpty || index.apkId == 'unbound') {
      return null;
    }
    if (_sameApkId(requested, index.apkId)) return null;
    // apkId 是 sha256 形态时**无法从路径反推摘要**：再拿"当前已打开的目标路径"
    // 比一次，让 path / 裸文件名两种写法同样可用（真机实测：只比 apkId 时
    // 这两种写法会被判 mismatch，而它们的意图明确就是"当前这个包"）。
    // 比较仍是全路径/basename 严格判等——指向别的包照样拒绝。
    if (_lastOpenedApkPath.isNotEmpty &&
        _sameApkId(requested, _lastOpenedApkPath)) {
      return null;
    }
    return AnalyzerResult(
      query: query,
      summary:
          'APK_CONTEXT_MISMATCH: 当前入口打开的是 ${index.apkId}，请求绑定 $requested。请重新 open，或不传 apkId 使用当前目标。',
      score: 0,
      confidence: ConfidenceLevel.high,
      evidenceLevel: EvidenceLevel.l0,
      sufficiency: Sufficiency.insufficient,
      stopReason: 'apk_context_mismatch',
      recommendedAction: 'OPEN_WORKSPACE',
      detail: <String, dynamic>{
        'code': 'APK_CONTEXT_MISMATCH',
        'currentApkId': index.apkId,
        'requestedApkId': requested,
      },
    );
  }

  /// 同一目标的不同写法必须判为同一个 apkId。
  ///
  /// `analyzer_open` 回显的 apkId 有两种形态：有报告指纹时 `sha256:<64hex>`，
  /// 否则 `apk:<path>`；调用方则常把「回显值原样回传」「带前缀的路径」「裸文件名」
  /// 混着用（实测：open 回显 `apk:日记_1.0.0.apk`，照着回传即被判 mismatch，
  /// 看起来像"这个工具要另一种 id"——同一 id 出现三种行为）。
  ///
  /// 这里先剥 `sha256:`/`apk:` 前缀与路径分隔符再比；只有当一方是裸文件名
  /// （不含 `/`）且另一方的 basename 相同时才退化到按名字判等——两个不同目录的
  /// 同名包仍会被全路径比较挡住，不会把 A 的证据算到 B 上。
  static bool _sameApkId(String a, String b) {
    if (a == b) return true;
    String norm(String raw) {
      var s = raw.trim().replaceAll('\\', '/');
      if (s.startsWith('sha256:')) s = s.substring('sha256:'.length);
      if (s.startsWith('apk:')) s = s.substring('apk:'.length);
      return s;
    }

    final na = norm(a);
    final nb = norm(b);
    if (na == nb) return true;
    final ba = na.contains('/') ? na.substring(na.lastIndexOf('/') + 1) : na;
    final bb = nb.contains('/') ? nb.substring(nb.lastIndexOf('/') + 1) : nb;
    return ba == bb && (!na.contains('/') || !nb.contains('/'));
  }

  /// 供契约测试直接验证"同一目标的不同写法"矩阵（与 [classifySignatureSmaliForTest] 同款缝）。
  static bool sameApkIdForTest(String a, String b) => _sameApkId(a, b);

  Future<String?> _analysisPath() async {
    if (_lastOpenedApkPath.isNotEmpty) return _lastOpenedApkPath;
    try {
      return await ApkWorkspaceBindingService.activeApkPath();
    } catch (_) {
      return null;
    }
  }

  @override
  Future<AnalyzerResult> openWorkspace({
    required String apkPath,
    String? apkIdOverride,
  }) async {
    // 幂等：同一路径已打开过时直接复用，避免每次再读完整报告。
    if (_lastOpenedApkPath == apkPath && index.apkId != 'unbound') {
      return AnalyzerResult(
        query: 'workspace.open($apkPath)',
        summary: '已打开（${index.apkId}），按需分析就绪。',
        score: 1,
        confidence: ConfidenceLevel.high,
        evidenceLevel: EvidenceLevel.l0,
        sufficiency: Sufficiency.complete,
        stopReason: 'workspace_reused',
        detail: <String, dynamic>{
          'apk_id': index.apkId,
          'apkId': index.apkId,
          'apk_path': apkPath,
        },
      );
    }

    // 首次打开时从报告取 APK 身份，后续调用走上面的内存复用路径。
    final report = await ApkWorkspaceService.readReport();
    final normalizedPath = apkPath.replaceAll('\\', '/');
    final fileName = normalizedPath.substring(
      normalizedPath.lastIndexOf('/') + 1,
    );
    final sourceApk = report?['sourceApk'];
    final reportPath = sourceApk is Map
        ? sourceApk['path']?.toString().replaceAll('\\', '/')
        : null;
    final reportFileName = report?['fileName']?.toString();
    final reportMatchesPath =
        reportPath == normalizedPath ||
        (reportPath == null && reportFileName == fileName);
    final sha = reportMatchesPath ? (report?['sha256'])?.toString() : null;
    final apkId =
        apkIdOverride ??
        (sha != null && sha.isNotEmpty ? 'sha256:$sha' : 'apk:$apkPath');
    index = AnalyzerIndex(apkId: apkId);
    _lastOpenedApkPath = apkPath;
    _fieldRefCache.clear();
    _businessStateCache.clear();

    // 按需分析模式：不预建任何索引。dex 总数从报告读（仅用于覆盖率展示）。
    final dexDetails = reportMatchesPath && report != null
        ? report['dexDetails']
        : null;
    if (dexDetails is List) {
      index.dexTotal = dexDetails.length;
      index.dexParsed = dexDetails.length;
    }

    return AnalyzerResult(
      query: 'workspace.open($apkPath)',
      summary: '已打开 APK（$apkId）。按需分析模式：无需预建索引，直接用 locate/trace 定位。',
      score: 1,
      confidence: ConfidenceLevel.high,
      evidenceLevel: EvidenceLevel.l0,
      sufficiency: Sufficiency.complete,
      stopReason: 'workspace_ready',
      detail: <String, dynamic>{
        'apk_id': apkId,
        'apkId': apkId,
        'apk_path': apkPath,
        'mode': 'on_demand',
      },
    );
  }

  @override
  Future<AnalyzerResult> globalSearch({
    required String query,
    int topK = 20,
    String? apkId,
  }) async {
    final mismatch = _contextMismatch('global_search($query)', apkId);
    if (mismatch != null) return mismatch;
    // 按需扫 dex：走底层 dex_search（class_by_string），真实跨 36 dex 搜。
    final viaNative = await _globalSearchNative(query, topK);
    if (viaNative != null) return viaNative;

    // 回退：内存索引（无工作区/通道不可用时）。
    final lower = query.toLowerCase();
    final hits = <IndexEntry>[];
    for (final e in index.classByName.values) {
      if (e.name.toLowerCase().contains(lower)) hits.add(e);
      if (hits.length >= topK) break;
    }
    if (hits.length < topK) {
      for (final e in index.methodBySignature.values) {
        if (e.name.toLowerCase().contains(lower)) {
          hits.add(e);
          if (hits.length >= topK) break;
        }
      }
    }
    if (hits.length < topK) {
      for (final e in index.fieldBySignature.values) {
        if (e.name.toLowerCase().contains(lower)) {
          hits.add(e);
          if (hits.length >= topK) break;
        }
      }
    }
    return IndexQueryResult.fromSearch(
      index: index,
      query: 'global_search($query)',
      hits: hits,
      summary: '内存索引命中 ${hits.length} 项',
    );
  }

  /// 走底层 dex_search 按需扫；通道不可用返回 null。
  ///
  /// 单次 `action=auto` 调用取代旧的 5 步串行阶梯（auto → method_by_name →
  /// class_by_name → method_by_string → class_by_string）。旧实现每一步都是
  /// 一次独立 MethodChannel 往返，最坏 5 次；而 2026-09-15 的 DexKit 修复已让
  /// auto 自身覆盖全部五个维度（method 侧 class_name/method_name/used_strings/
  /// used_fields/invoked_methods/used_numbers/opcode_sequence + class 侧
  /// class_name/super_class/interface/annotation/used_strings），阶梯里的四个
  /// 兜底 action 全是 auto 的子集——保留它们只会在 auto 空命中时白跑 4 次
  /// 通道往返，且每次都重开 DexKit、重扫相同 dex。
  Future<AnalyzerResult?> _globalSearchNative(String query, int topK) async {
    final path = await _analysisPath();
    if (path == null || path.isEmpty) return null;
    try {
      final attempt = await ApkToolchainService.dexSearch(
        path: path,
        keyword: query,
        action: 'auto',
        matchType: 'Contains',
        ignoreCase: true,
        limit: topK,
      );
      if (!attempt.ok || attempt.data == null) return null;
      final data = attempt.data!;
      // auto 把类命中放在独立的 classes 通道，method 命中在 results；
      // 两条都要收，否则纯类名查询会被误判为 0 命中。
      final methodResults = data['results'];
      final classResults = data['classes'];
      final results = <dynamic>[
        if (methodResults is List) ...methodResults,
        if (classResults is List) ...classResults,
      ];
      final action = 'auto';
      if (results.isEmpty) {
        return AnalyzerResult(
          query: 'global_search($query)',
          summary: _unbound
              ? 'DEX 类名、方法名与字符串均未命中。⚠️ 当前 analyzer 未绑定任何 '
                  'APK（unbound）——空结果可能因未绑定而非目标不存在。先 '
                  'analyzer_open(apkPath=...) 或 analyze_apk_workspace 再查。'
              : 'DEX 类名、方法名与字符串均未命中',
          score: 0,
          confidence: ConfidenceLevel.high,
          evidenceLevel: EvidenceLevel.l0,
          sufficiency: Sufficiency.complete,
          stopReason: _unbound ? 'no_hit_unbound' : 'no_hit',
          recommendedAction: _unbound ? 'OPEN_WORKSPACE' : 'FIND_CLASS',
        );
      }
      final candidates = <AnalyzerCandidate>[];
      final evidence = <Map<String, dynamic>>[];
      for (final raw in results) {
        if (raw is! Map) continue;
        final cls = raw['class']?.toString() ?? '';
        if (cls.isEmpty) continue;
        final method = raw['method']?.toString() ?? '';
        final locator = method.isNotEmpty
            ? 'dex_method:$cls->$method'
            : 'dex_class:$cls';
        candidates.add(
          AnalyzerCandidate(
            locator: locator,
            score: 0.6,
            reason: '$action 命中 "$query"',
          ),
        );
        evidence.add(<String, dynamic>{
          'type': method.isNotEmpty ? 'method_match' : 'class_match',
          'locator': locator,
          'simple_name': raw['simpleName']?.toString() ?? '',
        });
      }
      final total = (data['total'] as num?)?.toInt() ??
          (methodResults is List ? methodResults.length : results.length);
      final classTotal = (data['classTotal'] as num?)?.toInt() ?? 0;
      return AnalyzerResult(
        query: 'global_search($query)',
        summary: 'dex_search(auto) 命中 $total 个方法 / $classTotal 个类',
        score: candidates.isEmpty ? 0 : 0.6,
        confidence: ConfidenceLevel.high,
        evidenceLevel: EvidenceLevel.l0,
        sufficiency: Sufficiency.complete,
        stopReason: candidates.isEmpty ? 'no_hit' : 'hits',
        primaryCandidates: candidates.take(topK).toList(),
        evidenceGraph: <String, dynamic>{
          'matches': evidence,
          'source': 'dex_search',
        },
        nextBestActions: <String>[
          for (final c in candidates.take(3)) 'class_outline("${c.locator}")',
        ],
        recommendedAction: candidates.isEmpty ? 'FIND_CLASS' : 'CLASS_OUTLINE',
        detail: <String, dynamic>{
          'total': total,
          'classTotal': classTotal,
          'results': results,
        },
      );
    } catch (_) {
      return null;
    }
  }

  @override
  Future<AnalyzerResult> findFieldUsage({
    required String fieldLocator,
    String? apkId,
  }) async {
    final mismatch = _contextMismatch('find_field_usage($fieldLocator)', apkId);
    if (mismatch != null) return mismatch;
    // 字段 → 读写方法：按需扫（LRU 缓存，二次命中秒回）。
    final refs = await _fieldRefsFor(fieldLocator);
    final reads = refs.where((r) => r.relation == 'READ_FIELD').length;
    final writes = refs.where((r) => r.relation == 'WRITE_FIELD').length;

    // 证据链：每条引用是「可复验证据」——locator + opcode + 指令 index，
    // Agent 可直接使用返回的定位信息复核，不盲信结论。
    final evidence = <Map<String, dynamic>>[
      for (final r in refs)
        <String, dynamic>{
          'type': r.relation == 'WRITE_FIELD' ? 'field_write' : 'field_read',
          'method': r.methodLocator,
          'opcode': r.opcode,
          'instruction_index': r.instructionIndex,
          'access_kind': r.accessKind,
        },
    ];

    // 排序（不造假概率）：写入方优先（权威），其次按指令序。
    final ranked = <Map<String, dynamic>>[
      for (final r in _rankFieldRefs(refs))
        <String, dynamic>{
          'locator': r.methodLocator,
          'rank_reason': _rankReasons(r),
          'is_writer': r.relation == 'WRITE_FIELD',
        },
    ];

    final writerRefs = refs.where((r) => r.relation == 'WRITE_FIELD').toList();
    final writer = writerRefs.isEmpty ? null : writerRefs.first;
    final conclusion = refs.isEmpty
        ? _fieldRefSource == 'native_xref'
              ? _unbound
                    ? '字段 $fieldLocator 未发现读写引用。⚠️ 当前 analyzer 未绑定'
                        ' APK（unbound）——空结果可能因未绑定，先 analyzer_open 或 '
                        'analyze_apk_workspace 再确认'
                    : '字段 $fieldLocator 的实时扫描未发现读写引用'
              : '字段 $fieldLocator 暂无可验证读写引用（扫描不可用）'
        : writer != null
        ? '$fieldLocator 的权威写入方是 ${writer.methodLocator}'
        : '$fieldLocator 只有读取、无写入方';

    return AnalyzerResult(
      query: 'find_field_usage($fieldLocator)',
      summary: '$conclusion；$reads 读 $writes 写',
      score: refs.isEmpty ? 0 : 0.7,
      confidence: refs.isEmpty ? ConfidenceLevel.medium : ConfidenceLevel.high,
      evidenceLevel: refs.isEmpty
          ? EvidenceLevel.l1
          : (writes > 0 ? EvidenceLevel.l3 : EvidenceLevel.l2),
      // R5 修复：空结果一律 INSUFFICIENT——此前 native_xref 通道扫出 0 引用时
      // 仍标记 COMPLETE，配合 score=0.0 会让下游 agent 把"没找到"读成"已查清"。
      // native_xref 只保证"扫描通道可用"，不保证"找到了东西"。
      sufficiency: refs.isEmpty
          ? Sufficiency.insufficient
          : Sufficiency.complete,
      stopReason: refs.isEmpty
          ? (_unbound ? 'no_refs_unbound' : 'no_refs')
          : (writes > 0 ? 'writer_confirmed' : 'read_only'),
      primaryCandidates: [
        for (final r in ranked.take(20))
          AnalyzerCandidate(
            locator: r['locator'] as String,
            score: (r['is_writer'] == true) ? 0.95 : 0.5,
            reason: (r['rank_reason'] as List).join(', '),
          ),
      ],
      evidenceGraph: <String, dynamic>{
        'field': fieldLocator,
        'evidence': evidence,
        'ranking': ranked,
        'source': _fieldRefSource,
      },
      uncertainties: writes > 1
          ? <dynamic>[
              <String, dynamic>{
                'reason': '字段有 $writes 个写入方，需 trace_backward 确认权威路径',
                'impact': '写入方候选不止一个',
              },
            ]
          : const <dynamic>[],
      nextBestActions: <String>[
        for (final r in ranked.take(3))
          'smali_read("${(r['locator'] as String).replaceFirst('dex_method:', '')}")',
        if (writer != null)
          'dex_xref("${writer.methodLocator.replaceFirst('dex_method:', '')}")',
      ],
      nextActions: <AnalyzerNextAction>[
        // 精确下一步：读消费点方法体（smali_read 底层，Agent 直接复制）。
        for (final r in ranked.take(3))
          AnalyzerNextAction(
            tool: 'smali_read',
            purpose: 'inspect',
            arguments: <String, dynamic>{
              'qualifiedId': (r['locator'] as String).replaceFirst(
                'dex_method:',
                '',
              ),
            },
            description: '读该消费点的 smali 字节码，确认逻辑后再改',
          ),
        if (writer != null)
          AnalyzerNextAction(
            tool: 'dex_xref',
            purpose: 'trace_callers',
            arguments: <String, dynamic>{
              'target': writer.methodLocator.replaceFirst('dex_method:', ''),
              'direction': 'to',
            },
            description: '按需查看权威写入方的上游调用者，避免修改无关下游判断',
          ),
      ],
      recommendedAction: refs.isEmpty
          ? 'FIND_CLASS'
          : (writer != null ? 'INSPECT_ENTITIES' : 'TRACE_BACKWARD'),
      detail: <String, dynamic>{
        'refs': [for (final r in refs) r.toJson()],
        'reads': reads,
        'writes': writes,
        'source': _fieldRefSource,
      },
    );
  }

  /// 排序：写入方优先，其余按指令序。
  List<FieldRef> _rankFieldRefs(List<FieldRef> refs) {
    final sorted = List<FieldRef>.from(refs);
    sorted.sort((a, b) {
      final aw = a.relation == 'WRITE_FIELD' ? 0 : 1;
      final bw = b.relation == 'WRITE_FIELD' ? 0 : 1;
      if (aw != bw) return aw.compareTo(bw);
      return a.instructionIndex.compareTo(b.instructionIndex);
    });
    return sorted;
  }

  List<String> _rankReasons(FieldRef r) {
    final reasons = <String>[];
    if (r.relation == 'WRITE_FIELD') reasons.add('writer');
    reasons.add(r.relation == 'WRITE_FIELD' ? 'WRITE_FIELD' : 'READ_FIELD');
    reasons.add('opcode=${r.opcode}');
    reasons.add('instruction#${r.instructionIndex}');
    return reasons;
  }

  /// Field XREF 数据源标识（测试/日志断言用）：
  /// sqlite_index=Kotlin Workspace 索引（纯 SELECT）；native_xref=按需扫 dex；memory=内存索引。
  String _fieldRefSource = 'memory';

  /// 公开只读：Field XREF 数据源（测试断言用）。
  String get fieldRefSource => _fieldRefSource;

  /// 按需查字段引用（LRU 缓存 → fieldXref 按需扫 → 内存索引兜底）。
  /// 不预建全量索引：首次扫，扫过即缓存，二次命中秒回。
  Future<List<FieldRef>> _fieldRefsFor(String fieldLocator) async {
    final path = await _analysisPath();
    // 归一化 fieldTarget：dex_field:Lcom/x/A;->f:I → Lcom/x/A;->f:I
    var fieldTarget = fieldLocator;
    if (fieldTarget.startsWith('dex_field:')) {
      fieldTarget = fieldTarget.substring('dex_field:'.length);
    }
    final cacheKey =
        // B-1 修复：缓存键并入索引模式镜像（ApkToolchainService 静态，
        // 切 A/B 方案时同步），旧模式缓存自动不命中，测量不失真。
        '${ApkToolchainService.fieldRefsModeKey}|'
        '${path ?? _lastOpenedApkPath}|$fieldTarget';
    final cached = _fieldRefCache[cacheKey];
    if (cached != null) {
      _fieldRefSource = 'lru_cache';
      return cached;
    }
    if (path != null && path.isNotEmpty) {
      // fieldXref 通道（按需扫 dex）：一次扫出该字段的全部 READ/WRITE。
      try {
        final result = await ApkToolchainService.fieldXref(
          path: path,
          fieldTarget: fieldTarget,
        );
        if (result.ok && result.data != null) {
          final rawRefs = result.data!['fieldRefs'];
          if (rawRefs is List) {
            _fieldRefSource = 'native_xref';
            final refs = rawRefs.isEmpty
                ? const <FieldRef>[]
                : _parseFieldRefs(rawRefs);
            _cacheFieldRefs(cacheKey, refs);
            return refs;
          }
        }
      } catch (_) {
        // 通道失败回退。
      }
    }
    _fieldRefSource = 'memory';
    final memoryRefs = index.fieldRefs(fieldLocator);
    _cacheFieldRefs(cacheKey, memoryRefs);
    return memoryRefs;
  }

  List<FieldRef> _parseFieldRefs(List<dynamic> rawRefs) {
    final out = <FieldRef>[];
    for (final raw in rawRefs) {
      if (raw is! Map) continue;
      final field = raw['field']?.toString() ?? '';
      final method = raw['method']?.toString() ?? '';
      if (field.isEmpty || method.isEmpty) continue;
      out.add(
        FieldRef(
          fieldLocator: 'dex_field:$field',
          methodLocator: 'dex_method:$method',
          relation: raw['relation']?.toString() ?? 'READ_FIELD',
          accessKind: raw['accessKind']?.toString() ?? 'READ_INSTANCE',
          opcode: raw['opcode']?.toString() ?? 'iget',
          instructionIndex: (raw['instructionIndex'] as num?)?.toInt() ?? 0,
          dexId: (raw['dexId'] as num?)?.toInt() ?? 0,
        ),
      );
    }
    return out;
  }

  @override
  Future<AnalyzerResult> analyzeBusinessState({
    required String targetKeyword,
    String domain = 'vip',
    String fieldName = '',
    String? apkId,
  }) async {
    final mismatch = _contextMismatch(
      'analyze_business_state($targetKeyword, $domain)',
      apkId,
    );
    if (mismatch != null) return mismatch;
    final cacheKey = '${index.apkId}|$targetKeyword|$domain|$fieldName';
    final cached = _businessStateCache[cacheKey];
    if (cached != null) return cached;
    final path = await _analysisPath();

    // 主数据源：analyzeModule(fields) 一步返回敏感字段 + 消费点 + patch 目标，
    // 底层内置通用领域词表（isVip/vipExpire/userType 等），跨 dex 聚合，
    // 不硬编码任何 APK 特定类名。
    if (path != null && path.isNotEmpty) {
      // cacheKeySha256 必传：ApkAnalysisService.analyzeModule 在
      // cacheKeySha256 为空时**完全不走缓存**（cacheKey=null），
      // 意味每次 analyze_business_state 都重跑一遍两阶段全 dex 扫描
      // ——240MB 包的 fields 模块是秒级到十秒级的开销。
      // 用当前分析目标的 apkId 摘要作为缓存键，跨调用复用同一份 fields 结果。
      final result = await ApkAnalysisService.analyzeModule(
        path: path,
        module: 'fields',
        cacheKeySha256: _analysisCacheKeyHash,
        useCache: true,
      );
      // 诊断：主数据源为何未产出命中。此前该分支静默落到内存索引回退，
      // 调用方只看到 index_unavailable，无法区分"模块分析失败"与"确实无匹配"。
      _lastPrimarySourceNote = result['ok'] == true
          ? 'analyze_module_fields_ok'
          : 'analyze_module_fields_failed:${result['error'] ?? result['message'] ?? 'unknown'}';
      if (result['ok'] == true) {
        final readCandidates = result['fieldReadCandidates'];
        final fieldCandidates = result['fieldCandidates'];
        final filter = (fieldName.isNotEmpty ? fieldName : targetKeyword)
            .toLowerCase();

        // 匹配源：优先 fieldReadCandidates（带消费点），补 fieldCandidates
        // （全字段，含消费点少被截断的字段）。用 field 字段名过滤，不 fallback。
        final allCandidates = <Map<String, dynamic>>[
          if (readCandidates is List)
            for (final r in readCandidates)
              if (r is Map) Map<String, dynamic>.from(r),
          if (fieldCandidates is List)
            for (final r in fieldCandidates)
              if (r is Map) Map<String, dynamic>.from(r),
        ];

        // 过滤：字段名与 keyword 做**分段匹配**，不做裸 substring。
        // 缺陷修复（isProxy 假阳性）：原 `name.contains(filter)` 让 `isProxy`、
        // `isProtected`、`isProduct`、`isPromise` 全部命中关键词 `ispro`——
        // 短词表的裸子串匹配会把网络层字段抬成业务状态字段（真机实测
        // Lanet/channel/statist/SessionStatistic;->isProxy:I 被以 0.95 +
        // authoritative_writer_confirmed 呈现）。
        // 改为：先把字段名按分隔符拆段（`_`/`$`/数字/驼峰边界），
        // 只有当 filter 恰好等于某一段、或等于整名、或是多段拼接时才判命中。
        final matched = <Map<String, dynamic>>[];
        // 记录每个候选的匹配强度：exact=整名/整段全等；partial=仅部分包含；
        // 空串 filter 视为 wildcard。
        // 键用 **去重签名**（field 优先，退化为 name），与 seenFields 一致，
        // 避免同名不同签名的候选互相覆盖强度。
        final matchStrength = <String, String>{};
        // 去重（fieldReadCandidates + fieldCandidates 可能重复）：
        // candidates 可达数千条，必须用 Set 判重（原 any() 线性扫是 O(n²)）。
        final seenFields = <String>{};
        for (final raw in allCandidates) {
          final field = raw['field']?.toString() ?? '';
          final name =
              raw['name']?.toString() ??
              (field.contains('->') ? field.split('->').last : field);
          String strength;
          if (filter.isEmpty) {
            strength = 'wildcard';
          } else {
            final s = _businessKeywordMatchStrength(name, filter);
            if (s == null) continue;
            strength = s;
          }
          final sig = field.isNotEmpty ? field : (raw['name']?.toString() ?? '');
          if (!seenFields.add(sig)) continue;
          matchStrength[sig] = strength;
          matched.add(raw);
        }

        // 关键修复：matched 为空 = 该关键词真无匹配字段，不 fallback 到全部，
        // 否则会命中无关字段（如 joiningDeadlineMs）。
        // 同时记录诊断：主数据源可用但候选数/命中数各是多少，
        // 便于调用方区分"字段模块没数据"与"关键词不在候选里"。
        _lastPrimarySourceNote = matched.isEmpty
            ? 'analyze_module_fields_ok:candidates=${allCandidates.length},'
                  'readCandidates=${readCandidates is List ? readCandidates.length : 0},'
                  'fieldCandidates=${fieldCandidates is List ? fieldCandidates.length : 0},'
                  'matched=0'
            : 'analyze_module_fields_ok:candidates=${allCandidates.length},matched=${matched.length}';
        // 词表召回诊断：模块若只返回极少候选，说明 APK 字段名与词表对不上
        // （R8 混淆后字段名会变成 a/b/c），此时"无匹配"是词表问题而非工具缺陷。
        _lastPrimaryCandidateNames = <String>[
          for (final c in allCandidates.take(20))
            c['name']?.toString() ?? c['field']?.toString() ?? '?',
        ];
        if (matched.isNotEmpty) {
          // 匹配强度优先级：exact > partial > wildcard。强度是硬约束——
          // 只要存在 exact 候选，partial 候选就不再参与排序与选优，
          // 避免"名字沾边"的网络字段压过真正的业务字段。
          int strengthRank(String s) => switch (s) {
            'exact' => 0,
            'partial' => 1,
            _ => 2,
          };
          matched.sort((a, b) {
            final ar = strengthRank(_candidateStrength(a, matchStrength));
            final br = strengthRank(_candidateStrength(b, matchStrength));
            if (ar != br) return ar.compareTo(br);
            // VIP 状态优先布尔/整数用户字段；同类候选再按消费点数量排序。
            return _businessFieldScore(
              b,
              domain: domain,
            ).compareTo(_businessFieldScore(a, domain: domain));
          });
          final topStrength = strengthRank(
            _candidateStrength(matched.first, matchStrength),
          );
          // 只有 partial/wildcard 命中时降置信：工具无法证明这就是业务字段。
          final fuzzyOnly = topStrength > 0;

          // 取第一个字段，解析其消费点。
          final top = matched.first;
          final field = top['field']?.toString() ?? '';
          final refs = await _fieldRefsFor('dex_field:$field');
          final writers = refs
              .where((r) => r.relation == 'WRITE_FIELD')
              .toList();
          final readers = refs
              .where((r) => r.relation == 'READ_FIELD')
              .toList();
          final writer = writers.isEmpty ? null : writers.first;

          final evidence = <Map<String, dynamic>>[
            for (final r in refs)
              <String, dynamic>{
                'type': r.relation == 'WRITE_FIELD'
                    ? 'field_write'
                    : 'field_read',
                'method': r.methodLocator,
                'opcode': r.opcode,
              },
          ];

          final patchTargets = refs
              .map((ref) => ref.methodLocator.replaceFirst('dex_method:', ''))
              .toSet()
              .toList();

          final answer = AnalyzerResult(
            query: 'analyze_business_state($targetKeyword, $domain)',
            summary: writer != null
                ? '$domain 状态字段 dex_field:$field：${writers.length} 写 ${readers.length} 读，'
                      '权威写入方 ${writer.methodLocator}'
                : '$domain 状态字段 dex_field:$field：${readers.length} 读 0 写'
                      '（字段由反射/反序列化填充，无 iput 写入点，需逐读取点修改）',
            // 缺陷修复：fuzzyOnly（无 exact 命中）时降分降置信——
            // 名字沾边不等于业务字段，0.9 + HIGH 会诱导下游直接把网络层
            // 字段当会员状态去 patch。
            score: refs.isEmpty
                ? (fuzzyOnly ? 0.1 : 0.3)
                : (fuzzyOnly ? 0.45 : 0.9),
            confidence: fuzzyOnly && refs.isNotEmpty
                ? ConfidenceLevel.medium
                : ConfidenceLevel.high,
            evidenceLevel: refs.length >= 2
                ? EvidenceLevel.l4
                : (refs.isNotEmpty ? EvidenceLevel.l3 : EvidenceLevel.l1),
            sufficiency: refs.isEmpty
                ? Sufficiency.insufficient
                : Sufficiency.complete,
            stopReason: refs.isEmpty
                ? 'no_consumers'
                : (writer != null ? 'writer_confirmed' : 'read_only_field'),
            primaryCandidates: [
              if (writer != null)
                AnalyzerCandidate(
                  locator: writer.methodLocator,
                  // 权威写入方只有在 exact 命中时才配 0.95。
                  score: fuzzyOnly ? 0.45 : 0.95,
                  reason: fuzzyOnly
                      ? 'authoritative writer (WRITE_FIELD) — 字段名与目标关键词仅弱匹配，需人工确认是否业务字段'
                      : 'authoritative writer (WRITE_FIELD)',
                ),
              for (final r in readers.take(5))
                AnalyzerCandidate(
                  locator: r.methodLocator,
                  score: fuzzyOnly ? 0.2 : 0.5,
                  reason: 'READ_FIELD @${r.opcode}',
                ),
            ],
            evidenceGraph: <String, dynamic>{
              'field': 'dex_field:$field',
              'evidence': evidence,
              'patch_targets': patchTargets,
              'source': 'analyze_module_fields',
              'match_strength': fuzzyOnly ? 'partial' : 'exact',
              'matched_name': top['name']?.toString() ?? field,
            },
            uncertainties: <dynamic>[
              if (fuzzyOnly)
                <String, dynamic>{
                  'reason':
                      '字段名 "${top['name'] ?? field}" 与目标关键词 "$targetKeyword" '
                      '仅弱匹配（无精确分段命中）',
                  'impact':
                      '该字段可能是同名无关字段（如网络层 isProxy 之于关键词 isPro），'
                      'patch 前必须 smali_read 确认它确为业务状态字段',
                },
              if (writers.length > 1)
                <String, dynamic>{
                  'reason': '字段有 ${writers.length} 个写入方',
                  'impact': '需 trace_backward 确认权威路径',
                },
            ],
            nextBestActions: patchTargets.take(3).toList(),
            nextActions: <AnalyzerNextAction>[
              for (final m in patchTargets.take(5))
                AnalyzerNextAction(
                  tool: 'smali_read',
                  purpose: 'inspect',
                  arguments: <String, dynamic>{'qualifiedId': m},
                  description: '读消费点 smali，确认逻辑后定位 patch 目标',
                ),
            ],
            recommendedAction: 'INSPECT_ENTITIES',
            detail: <String, dynamic>{
              'field': 'dex_field:$field',
              'writers': [for (final w in writers) w.toJson()],
              'readers': readers.length,
              'patch_targets': patchTargets,
              'candidate_count': matched.length,
              'match_strength': fuzzyOnly ? 'partial' : 'exact',
              'matched_name': top['name']?.toString() ?? field,
            },
          );
          _cacheBusinessState(cacheKey, answer);
          return answer;
        }
      }
    }

    // 回退：内存索引（无工作区/单元测试）。
    // 醒目约束：这条路径**不是**权威来源——内存索引可能未构建/不完整。
    // 因此不得再输出 `authoritative_writer_confirmed` + 0.95（旧实现在
    // 真机 vipLevel 查询上就落到这里，返回 INSUFFICIENT/writer_not_found，
    // 让调用方无法区分"APK 里真没有"与"索引没建起来"）。
    final memoryIndexReady = index.fieldBySignature.isNotEmpty;
    final filter = (fieldName.isNotEmpty ? fieldName : targetKeyword)
        .toLowerCase();
    final hits = <IndexEntry>[];
    for (final e in index.fieldBySignature.values) {
      if (_businessKeywordMatchStrength(e.name, filter) != null) {
        hits.add(e);
      }
    }
    if (hits.isEmpty) {
      for (final e in index.methodBySignature.values) {
        if (_businessKeywordMatchStrength(e.name, filter) != null) {
          hits.add(e);
          if (hits.length >= 10) break;
        }
      }
    }
    final field = hits.isEmpty ? null : hits.first;
    final refs = field == null
        ? const <FieldRef>[]
        : await _fieldRefsFor(field.canonicalLocator);
    final writers = refs.where((r) => r.relation == 'WRITE_FIELD').toList();
    final writer = writers.isEmpty ? null : writers.first;
    final readers = refs.where((r) => r.relation == 'READ_FIELD').toList();

    // D5（2026-09-19 真机 QA）：主数据源失败/索引为空时，响应不能读成
    // "APK 里不存在该字段"。过去 summary 只写"未定位 $domain 字段 X（数据源：
    // 内存索引）"，配 stop_reason=index_unavailable，模型很容易据此下"没有 VIP
    // 逻辑"的结论——那是一次**未评估**，不是一次否证。
    final primaryFailed = _lastPrimarySourceNote.startsWith('analyze_module_fields_failed');
    final notEvaluated = writer == null && (primaryFailed || !memoryIndexReady);
    // R8 混淆判据：候选名样本里全是 1~2 字符的短名 → 按词表/关键词匹配天然
    // 召回不到（真机 QA：pc1/a/b/c 这种包，fieldName 词表匹配恒空）。
    final obfuscatedCandidates = _lastPrimaryCandidateNames.isNotEmpty &&
        _lastPrimaryCandidateNames.every((n) {
          final leaf = n.contains('->') ? n.split('->').last : n;
          final name = leaf.split(':').first;
          return name.length <= 2;
        });

    return AnalyzerResult(
      query: 'analyze_business_state($targetKeyword, $domain)',
      summary: writer == null
          ? (notEvaluated
                ? '$domain 状态字段 $targetKeyword：**未评估**'
                      '（主数据源 ${primaryFailed ? _lastPrimarySourceNote : "不可用"}'
                      '${memoryIndexReady ? "" : "，内存索引为空"}）。'
                      '这不是"字段不存在"的证据——请按 nextActions 换手段定位'
                      '（qid 直查 / 字符串交叉确认）。'
                      '${obfuscatedCandidates ? " 候选名疑似 R8 混淆（如 ${_lastPrimaryCandidateNames.take(3).join("、")}），按名匹配天然无效。" : ""}'
                : '未定位 $domain 字段 $targetKeyword'
                      '（数据源：内存索引${memoryIndexReady ? '' : '，索引为空'}）')
          : '$domain 状态字段 ${field?.canonicalLocator}：写入方 ${writer.methodLocator}'
                '（数据源：内存索引，未经工作区扫描确认）',
      // 内存索引命中不是权威证据：0.75 上限，且明确降置信。
      score: writer == null ? 0 : 0.75,
      confidence: ConfidenceLevel.medium,
      evidenceLevel: writer == null
          ? EvidenceLevel.l1
          : (refs.length >= 2 ? EvidenceLevel.l3 : EvidenceLevel.l2),
      sufficiency: writer == null
          ? Sufficiency.insufficient
          : Sufficiency.complete,
      stopReason: writer == null
          ? (memoryIndexReady ? 'writer_not_found' : 'index_unavailable')
          : 'writer_candidate_unverified',
      primaryCandidates: [
        if (writer != null)
          AnalyzerCandidate(
            locator: writer.methodLocator,
            score: 0.75,
            reason: 'writer candidate (WRITE_FIELD) — 来自内存索引，'
                '未经工作区扫描确认，需 smali_read 复核',
          ),
      ],
      evidenceGraph: <String, dynamic>{
        'field': field?.canonicalLocator,
        'source': 'memory_index',
        'authoritative': false,
        // D5：机器可读的"未评估"标记与原因，避免调用方只看 stopReason 就下结论。
        'notEvaluated': notEvaluated,
        if (notEvaluated) 'unavailableReason': _lastPrimarySourceNote,
        if (obfuscatedCandidates) 'candidateNamesLookObfuscated': true,
      },
      uncertainties: <dynamic>[
        if (writer == null && !memoryIndexReady)
          <String, dynamic>{
            'reason': _unbound
                ? 'analyzer 未绑定任何 APK，且字段模块未产出可用候选'
                : '按需分析模式下不预建字段索引，且字段模块未产出可匹配候选',
            'impact': '本次空结果**不能**推断 APK 中不存在该字段；'
                '先按 primary_source 判断是模块失败还是词表未召回，'
                '再决定改用 dex_search / string_scan 交叉确认',
          },
        if (notEvaluated && memoryIndexReady)
          <String, dynamic>{
            'reason': '主数据源失败（$_lastPrimarySourceNote），本次属**未评估**'
                '${obfuscatedCandidates ? "；且候选名疑似 R8 混淆，按名匹配天然无效" : ""}',
            'impact': '不得据此判断字段/业务逻辑不存在。'
                '改用 run_task_command(FIELD_STATE_LOCATE, className+field 或全量 qid)'
                ' 或 string_scan 交叉确认',
          },
        if (writer != null)
          <String, dynamic>{
            'reason': '写入方来自内存索引，非工作区实时扫描',
            'impact': '权威性未确认，patch 前须 smali_read 复核',
          },
      ],
      nextBestActions: <String>[
        if (writer != null) 'smali_read("${writer.methodLocator}")',
        if (writer == null) 'dex_search(keyword="$targetKeyword", action="auto")',
        if (writer == null) 'string_scan(query="$targetKeyword")',
        if (notEvaluated)
          'run_task_command(command="FIELD_STATE_LOCATE", className="<类名>", field="<字段名>")'
              ' — 按 qid 直查，不依赖字段名词表',
      ],
      nextActions: <AnalyzerNextAction>[
        if (writer != null)
          AnalyzerNextAction(
            tool: 'smali_read',
            purpose: 'inspect',
            arguments: <String, dynamic>{
              'qualifiedId': writer.methodLocator.replaceFirst(
                'dex_method:',
                '',
              ),
            },
            description: '读候选写入方 smali',
          ),
        if (writer == null)
          AnalyzerNextAction(
            tool: 'dex_search',
            purpose: 'cross_check',
            arguments: <String, dynamic>{
              'keyword': targetKeyword,
              'action': 'auto',
              'matchType': 'Contains',
              'ignoreCase': true,
            },
            description: '字段模块未召回该关键词时，改用 dex_search 交叉确认'
                '（R8 混淆后字段名可能已被重命名，字段模块词表匹配不到）',
          ),
        if (writer == null)
          AnalyzerNextAction(
            tool: 'string_scan',
            purpose: 'cross_check',
            arguments: <String, dynamic>{'query': targetKeyword},
            description: '确认该关键词是否以字符串形式存在于 APK 条目中',
          ),
      ],
      recommendedAction: writer == null ? 'LOCATE_SYMBOL' : 'INSPECT_ENTITIES',
      detail: <String, dynamic>{
        'field': field?.canonicalLocator,
        'writers': [for (final w in writers) w.toJson()],
        'readers': readers.length,
        'source': 'memory_index',
        'authoritative': false,
        'memory_index_ready': memoryIndexReady,
        'primary_source': _lastPrimarySourceNote,
        'primary_candidate_names': _lastPrimaryCandidateNames,
        'fallback_reason': _lastPrimarySourceNote.startsWith(
          'analyze_module_fields_failed',
        )
            ? '主数据源 analyzeModule(fields) 失败或无数据，已回退内存索引'
            : '主数据源未命中该关键词，已回退内存索引',
      },
    );
  }

  /// 从候选 map 反查其匹配强度（键与去重签名一致：field 优先，退化 name）。
  static String _candidateStrength(
    Map<String, dynamic> candidate,
    Map<String, String> matchStrength,
  ) {
    final field = candidate['field']?.toString() ?? '';
    if (field.isNotEmpty) {
      final byField = matchStrength[field];
      if (byField != null) return byField;
    }
    final byName = matchStrength[candidate['name']?.toString() ?? ''];
    return byName ?? 'wildcard';
  }

  /// 业务字段名 vs 关键词的**分段匹配**强度。
  ///
  /// 返回 `null` = 不命中；`'exact'` = 整名相等或分隔后的某一段全等
  /// （如 filter `vip` 命中 `isVip` / `vipLevel` 的 `vip` 段）；
  /// `'partial'` = 存在段级部分包含但无段全等。
  ///
  /// 关键约束：**禁止裸 substring**。`ispro` 是 `isproxy` / `isprotected` /
  /// `isproduct` / `isPromise` 的子串，裸匹配会把网络层/无关字段抬进候选。
  ///
  /// 测试用只读入口。
  static String? debugBusinessKeywordMatchStrength(String name, String filter) =>
      _businessKeywordMatchStrength(name, filter);

  static String? _businessKeywordMatchStrength(String name, String filter) {
    final f = filter.toLowerCase();
    if (f.isEmpty) return 'wildcard';
    final segments = _businessNameSegments(name);
    if (segments.isEmpty) return null;
    // 整名全等（忽略大小写）。
    if (segments.join() == f) return 'exact';
    // 单段全等：`isVip` → ['is','vip']，filter `vip` 命中。
    if (segments.contains(f)) return 'exact';
    // 连续多段拼接全等：`vipLevel` → ['vip','level'] 拼成 `viplevel`。
    for (var start = 0; start < segments.length; start++) {
      final sb = StringBuffer();
      for (var end = start; end < segments.length; end++) {
        sb.write(segments[end]);
        final joined = sb.toString();
        if (joined == f) return 'exact';
        if (joined.length >= f.length) break;
        if (!f.startsWith(joined)) break;
      }
    }
    // 段级部分包含（`level` in `levels`）——弱命中，单独归类。
    if (segments.any((s) => s.contains(f) || f.contains(s))) return 'partial';
    // 拼接后包含但无段边界对齐（`ispro` in `isproxy`）——同样归 partial，
    // 由调用方按强度降置信，而不是当精确命中用。
    if (segments.join().contains(f)) return 'partial';
    return null;
  }

  /// 驼峰/下划线/美元符/数字边界拆段（全部小写输出）。
  ///
  /// `isProxy` → ['is','proxy']；`vipLevel` → ['vip','level']；
  /// `user_info` → ['user','info']；`isVip2` → ['is','vip','2']。
  ///
  /// 注意：必须在**转小写之前**识别驼峰边界，否则大小写信息丢失、
  /// 整名退化成单段（这是上一版实现把 `isVip` 判成 partial 的原因）。
  static List<String> _businessNameSegments(String name) {
    final out = <String>[];
    final sb = StringBuffer();
    // 跟踪当前段末字符类别，避免反复 StringBuffer.toString()（O(n²)）。
    var lastWasLower = false;
    var lastWasDigit = false;
    void flush() {
      if (sb.isNotEmpty) {
        out.add(sb.toString());
        sb.clear();
      }
      lastWasLower = false;
      lastWasDigit = false;
    }

    for (var i = 0; i < name.length; i++) {
      final ch = name[i];
      final code = ch.codeUnitAt(0);
      final isLower = code >= 0x61 && code <= 0x7a; // a-z
      final isUpper = code >= 0x41 && code <= 0x5a; // A-Z
      final isDigit = code >= 0x30 && code <= 0x39; // 0-9
      if (!isLower && !isUpper && !isDigit) {
        flush();
        continue;
      }
      // 驼峰边界：小写后接大写 → 新段（isProxy → is|Proxy）。
      if (isUpper && lastWasLower) flush();
      // 数字起始新段（vip2 → vip|2）。
      if (isDigit && sb.isNotEmpty && !lastWasDigit) flush();
      sb.write(isUpper ? ch.toLowerCase() : ch);
      lastWasLower = isLower;
      lastWasDigit = isDigit;
    }
    flush();
    return out;
  }

  int _businessFieldScore(
    Map<String, dynamic> candidate, {
    required String domain,
  }) {
    final field = candidate['field']?.toString() ?? '';
    final lower = field.toLowerCase();
    var score = (candidate['consumerCount'] as num?)?.toInt() ?? 0;
    if (domain.toLowerCase() != 'vip') return score;
    if (field.endsWith(':Z') || field.endsWith(':I')) score += 1000;
    if (lower.contains('user') ||
        lower.contains('account') ||
        lower.contains('member') ||
        lower.contains('profile') ||
        lower.contains('userinfo')) {
      score += 100;
    }
    return score;
  }
}
