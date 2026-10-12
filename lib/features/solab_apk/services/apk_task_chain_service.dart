import 'dart:convert';
import 'dart:io';

import '../analyzer/analyzer_api.dart';
import '../analyzer/analyzer_gateway_impl.dart';
import 'apk_probe_planner.dart';
import 'apk_structural_service.dart';
import 'apk_toolchain_service.dart';
import 'apk_workspace_binding_service.dart';
import 'apk_workspace_service.dart';
import '../../../core/services/local_tools/tool_arg_echo.dart';
import 'apk_task_chain_verdict.dart';

/// B 类固定链执行器（蓝图 v2.1 §5.2 Direct Command 2.0）。
///
/// 「程序负责怎么查，LLM 负责判断」：一次工具调用内按**固定探针序**程序化
/// 跑完整条链，返回证据汇总；LLM 只消费汇总做支持/反驳/待验证判断，不再
/// 自拟查询链。每条链自带探针预算（步数硬上界），每次探针的 tool/args/
/// 耗时都记录在 probes[] 里，供 Benchmark 统计与后续薄版 Probe Planner
/// （蓝图 §5.3）接入。
///
/// 纪律：链只读、无 dryRun/confirm 面；探针失败即收束并给出结构化
/// failureReason（机器可读，为 §6.1 Failure Memory 预留），不猜测。
class ApkTaskChainService {
  ApkTaskChainService._();

  // A3：方法体进程级 LRU（key=apkPath|qualifiedId → smali）。同 APK 跨
  // 字段链复用方法体，避免重复 dex 解析；max 128 条防内存膨胀。
  static final Map<String, String> _methodBodyCache =
      <String, String>{};
  static const int _methodBodyCacheMax = 128;

  /// FIELD_STATE_LOCATE：状态/字段候选 → FIELD_USAGE → WRITE_FIELD 优先 →
  /// enclosing method（METHOD_BODY）→ caller 摘要 → 证据汇总。
  static const String fieldStateLocate = 'FIELD_STATE_LOCATE';

  /// VERIFY_ARTIFACT：产物存在 → 血缘正确（产物索引/活动链）→ 签名有效
  /// （内置 ApkVerifier，R7）。真机安装检查不在本链（R9 后续增强）。
  static const String verifyArtifact = 'VERIFY_ARTIFACT';

  /// FIELD_CANDIDATE_MINE（B1）：语义关键词 → DexKit 字段名/字符串双探针 →
  /// 候选类聚合 → class_outline 枚举字段 → 可改性打分，产出 fieldCandidates[]
  /// 供 LLM 择一后再走 FIELD_STATE_LOCATE。
  static const String fieldCandidateMine = 'FIELD_CANDIDATE_MINE';

  /// AD_SDK_LOCATE：广告 SDK 定位——报告 adSdkMatches 确认主导厂商 →
  /// dex_search 反查 init/注册入口 → smali 确认宿主调用点，产出 patch 候选。
  static const String adSdkLocate = 'AD_SDK_LOCATE';

  /// SIGNATURE_CHECK_LOCATE：签名校验定位——scanSignatureCheck 全 dex 词扫描
  /// → dex_search 反查命中方法 → smali 确认读自身签名并参与放行/退出分支 →
  /// 产出「是否需要去签」结论（方法级证据才可判定）。
  static const String signatureCheckLocate = 'SIGNATURE_CHECK_LOCATE';

  /// B1 SDK 类黑名单前缀：命中即视为依赖库/框架类，字段候选不取自此类
  /// （业务字段在宿主包，gson/rxjava 的 members/subscribers 是典型假阳性）。
  static const List<String> _sdkPackagePrefixes = <String>[
    'android/',
    'androidx/',
    'java/',
    'javax/',
    'kotlin/',
    'kotlinx/',
    'com/google/',
    'com/google/android/',
    'com/squareup/',
    'com/bumptech/',
    'com/facebook/',
    'com/tencent/',
    'com/umeng/',
    'com/alibaba/',
    'com/aliyun/',
    'io/reactivex/',
    'rx/',
    'okhttp',
    'okio/',
    'retrofit2/',
    'org/json/',
    'org/apache/',
    'org/chromium/',
    'org/intellij/',
    'org/jetbrains/',
    'org/w3c/',
    'org/xml/',
    'org/slf4j/',
    'dalvik/',
    'libcore/',
    'junit/',
    'org/checkerframework/',
    'org/objectweb/',
    'org/bouncycastle/',
    'gnu/',
  ];

  /// 链注册表（蓝图「不要一次设计几十个 Task Command」）。
  static const List<String> chains = <String>[
    fieldStateLocate,
    verifyArtifact,
    fieldCandidateMine,
    adSdkLocate,
    signatureCheckLocate,
  ];

  /// 统一入口。返回信封遵循 R5：{ok:true, ...} / {ok:false, error:{...}}。
  ///
  /// 全链异常保护：任何未预期异常（如通道数据形状漂移）都转为结构化
  /// CHAIN_CRASH 错误——MCP/端内调用方永远拿到机器可读错误与堆栈上下文，
  /// 不再裸异常（真机 'String' is not a subtype of List 教训）。
  static Future<Map<String, dynamic>> run({
    required String command,
    required Map<String, dynamic> args,
    String analyzerContextKey = 'app',
  }) async {
    try {
      // D9（2026-09-19 真机 QA）：apkPath 是相对名时先按统一工作目录解析成绝对
      // 路径——其他工具都支持工作目录相对名，只有这里把相对名原样传给原生，回的是
      // `NoSuchFileException: 日记_1.0.0.apk`，调用方分不清"该用绝对路径"还是
      // "文件没放对"。解析后仍不存在则给结构化错误 + 工作目录候选清单。
      final resolved = await _resolveApkPathArg(args);
      if (resolved['ok'] == false && resolved['error'] != null) {
        return resolved;
      }
      return await _dispatch(
        command: command,
        args: resolved,
        analyzerContextKey: analyzerContextKey,
      );
    } catch (e, st) {
      return <String, dynamic>{
        'ok': false,
        'error': <String, dynamic>{
          'code': 'CHAIN_CRASH',
          'message': '链执行未预期异常（$command）：$e',
          'stackHead': st.toString().split('\n').take(6).join('\n'),
          'recoverable': true,
        },
      };
    }
  }

  /// 相对 `apkPath` → 工作目录绝对路径；文件确实不存在时返回错误信封
  /// （含 `resolvedApkPath` 与工作目录内的 APK 候选）。
  ///
  /// 查不到工作目录（未绑定 / 通道不可用 / 单测环境）时**原样放行**——这只是
  /// 路径归一化的便利，不能因为它自己失败就把整条链打成 CHAIN_CRASH。
  static Future<Map<String, dynamic>> _resolveApkPathArg(
    Map<String, dynamic> args,
  ) async {
    final raw = (args['apkPath'] ?? '').toString().trim();
    if (raw.isEmpty) return args;
    var abs = raw;
    try {
      final resolved = await ApkWorkspaceBindingService.absoluteArtifactPath(raw);
      if (resolved.isNotEmpty) abs = resolved;
    } catch (_) {
      // 工作目录不可用时保持原样继续（下面照样做存在性检查）。
    }
    if (File(abs).existsSync()) {
      if (abs == raw) return args;
      return <String, dynamic>{...args, 'apkPath': abs, 'apkPathResolvedFrom': raw};
    }
    final candidates = <String>[];
    try {
      final dir = await ApkWorkspaceBindingService.workDir();
      if (dir != null && dir.isNotEmpty) {
        for (final entity in Directory(dir).listSync()) {
          if (entity is File && entity.path.toLowerCase().endsWith('.apk')) {
            candidates.add(entity.path);
            if (candidates.length >= 10) break;
          }
        }
      }
    } catch (_) {
      // 目录不可读不阻断：错误里少一份候选而已。
    }
    return <String, dynamic>{
      'ok': false,
      'error': <String, dynamic>{
        'code': 'APK_NOT_FOUND',
        'message':
            'apkPath 指向的文件不存在：$raw（按工作目录解析为 $abs）。'
            '工作目录内的 APK：${candidates.isEmpty ? "（未发现 .apk 文件）" : candidates.join("、")}',
        'recoverable': true,
      },
      'apkPath': raw,
      'resolvedApkPath': abs,
      'candidates': candidates,
    };
  }

  static Future<Map<String, dynamic>> _dispatch({
    required String command,
    required Map<String, dynamic> args,
    required String analyzerContextKey,
  }) async {
    // 报告 2-22：所有链的**唯一出口**都补 outcome（成功/不完整/不适用/失败），
    // 调用方不再自己拼「ok 且 failureReason 为空」这种启发式。
    return _withOutcome(
      await _dispatchRaw(
        command: command,
        args: args,
        analyzerContextKey: analyzerContextKey,
      ),
    );
  }

  /// 给链结果补 `outcome`（判定逻辑在 [TaskChainVerdicts.outcomeFor]，纯函数可单测）。
  static Map<String, dynamic> _withOutcome(Map<String, dynamic> result) {
    final verdict = result['verdict']?.toString();
    final outcome = TaskChainVerdicts.outcomeFor(
      ok: result['ok'] != false,
      failureReason: result['failureReason']?.toString(),
      verdict: verdict,
    );
    return <String, dynamic>{
      ...result,
      'outcome': outcome,
      'succeeded': outcome == 'succeeded',
    };
  }

  static Future<Map<String, dynamic>> _dispatchRaw({
    required String command,
    required Map<String, dynamic> args,
    required String analyzerContextKey,
  }) async {
    switch (command) {
      case fieldStateLocate:
        return _runFieldStateLocate(args, analyzerContextKey);
      case verifyArtifact:
        return _runVerifyArtifact(args);
      case fieldCandidateMine:
        return _runFieldCandidateMine(args, analyzerContextKey);
      case adSdkLocate:
        return _runAdSdkLocate(args, analyzerContextKey);
      case signatureCheckLocate:
        return _runSignatureCheckLocate(args, analyzerContextKey);
      default:
        return <String, dynamic>{
          'ok': false,
          'error': <String, dynamic>{
            'code': 'UNKNOWN_COMMAND',
            'message': '未注册的 Task Command: $command（已注册: ${chains.join(", ")}）',
            'recoverable': true,
          },
        };
    }
  }

  // -------------------------------------------------------------------------
  // FIELD_STATE_LOCATE
  // -------------------------------------------------------------------------

  static Future<Map<String, dynamic>> _runFieldStateLocate(
    Map<String, dynamic> args,
    String analyzerContextKey,
  ) async {
    final target = FieldTarget.parse(
      field: (args['field'] ?? '').toString().trim(),
      className: (args['className'] ?? '').toString().trim(),
      raw: (args['fieldLocator'] ?? '').toString().trim(),
    );
    if (target == null) {
      return <String, dynamic>{
        'ok': false,
        'error': <String, dynamic>{
          'code': 'INVALID_ARGUMENT',
          'message':
              'field 无法解析。支持 Lpkg/Class;->name:type 全量 qid，或 '
              'className + field 组合（如 className=UserInfoBean, field=isVip）。',
          'recoverable': true,
          'argument': 'field',
        },
      };
    }
    final apkPath = (args['apkPath'] ?? '').toString().trim();
    final probes = <Map<String, dynamic>>[];
    final plannerDecisions = <Map<String, dynamic>>[];
    final gateway = AnalyzerGatewayRegistry.forKey(analyzerContextKey);

    // B-2 修复：冷启动/新会话下网关未绑定会静默返回 0 引用（违反 R5）。
    // 链内先显式绑定 APK 上下文（幂等），保证 find_field_usage 有界可查。
    if (apkPath.isNotEmpty) {
      try {
        await gateway.openWorkspace(apkPath: apkPath);
      } catch (_) {
        // 绑定失败不阻断：按需模式可能已有别的绑定路径。
      }
    }

    // 薄版 Probe Planner（蓝图 §5.3）主循环：程序按固定规则决定 next probe，
    // 每步决策（规则标签/代价/剩余预算/patch 门禁）全量记录 plannerDecisions[]，
    // 日志可观察。链体不再硬编码探针顺序。
    var state = const ProbeEvidenceState();
    var seq = 0;
    AnalyzerResult? usage;
    var writes = 0;
    var reads = 0;
    var stopReason = '';
    String? topWriter;
    var failureReason = '';
    var methods = <Map<String, dynamic>>[];
    var callerSummary = <String>[];
    var methodBodyFailed = false;

    while (true) {
      seq++;
      final d = ApkProbePlanner.decide(state, seq: seq);
      plannerDecisions.add(d.toLog());
      if (d.action == 'stop') {
        // R2/R5 收束：缺口映射到机器可读 failureReason。
        // no_refs_unbound：扫描通道可用但 analyzer 未绑定 APK——
        // 与"扫过了真没引用"（NO_REFS）区分，否则会误导上游直接放弃。
        failureReason = switch (d.gap) {
          'NO_WRITER' => switch (stopReason) {
            'no_refs' => 'NO_REFS',
            'no_refs_unbound' => 'ANALYZER_UNBOUND',
            _ => 'NO_WRITER',
          },
          'BUDGET_EXHAUSTED' => 'BUDGET_EXHAUSTED',
          _ => '',
        };
        break;
      }
      final cost = d.nextProbeCost;
      switch (d.nextProbe) {
        case ApkProbeKind.fieldUsage:
          // Probe — FIELD_USAGE：字段 READ/WRITE 消费点（写入方优先，LRU）。
          usage = await _probe(probes, 'analyzer.find_field_usage', () {
            return gateway.findFieldUsage(fieldLocator: target.locator);
          });
          final graph = usage.evidenceGraph;
          final evidence = (graph['evidence'] as List?) ?? const <dynamic>[];
          // whereType<Map>()：evidence 的元素类型不受本文件控制，
          // 元素若是 null/标量，硬 cast 会直接抛异常而不是「这一条不算」。
          writes = evidence
              .whereType<Map>()
              .where((e) => e['type'] == 'field_write')
              .length;
          reads = evidence
              .whereType<Map>()
              .where((e) => e['type'] == 'field_read')
              .length;
          stopReason = usage.stopReason ?? '';
          for (final r in ((graph['ranking'] as List?) ?? const <dynamic>[])
              .whereType<Map>()) {
            if (r['is_writer'] == true) {
              topWriter = (r['locator'] ?? '').toString();
              break;
            }
          }
          state = state.copyWith(
            hasFieldUsage: true,
            writes: writes,
            reads: reads,
            costSpent: state.costSpent + cost,
          );
        case ApkProbeKind.methodBody:
          // Probe — METHOD_BODY：权威写入方方法体（规则 3 判别 / 规则 6 升级）。
          if (topWriter == null || topWriter.isEmpty) {
            state = state.copyWith(costSpent: state.costSpent + cost);
            break;
          }
          final qid = topWriter.replaceFirst('dex_method:', '');
          final body = await _readMethodBody(qid, apkPath, probes);
          methods = <Map<String, dynamic>>[
            <String, dynamic>{
              'qualifiedId': qid,
              'isWriter': true,
              if (body != null) 'smali': body,
              if (body == null) 'error': 'smali_read_failed',
            },
          ];
          // 方法体读取失败 = 同探针无信息增益（蓝图规则 5）：不重试同探针，
          // 立即收束，避免预算被重复失败烧光。
          if (body == null || body.isEmpty) {
            failureReason = 'METHOD_BODY_UNAVAILABLE';
            methodBodyFailed = true;
            break;
          }
          state = state.copyWith(hasMethodBody: true, costSpent: state.costSpent + cost);
        case ApkProbeKind.xref:
          // Probe — XREF_CALLERS：权威写入方上游调用者摘要（只取 locator）。
          callerSummary = await _callerSummary(
            (topWriter ?? '').replaceFirst('dex_method:', ''),
            apkPath,
            probes,
          );
          state = state.copyWith(hasCallers: true, costSpent: state.costSpent + cost);
      }
      // 方法体读取失败：同探针重试无信息增益 → 收束（蓝图规则 5）。
      if (methodBodyFailed) {
        plannerDecisions.add(<String, dynamic>{
          'seq': ++seq,
          'action': 'stop',
          'rule': 'R5_NO_GAIN_ON_FAILED_PROBE',
          'reason': 'METHOD_BODY 探针失败且无信息增益 → 收束并报告缺口（蓝图规则 5）',
          'costSpent': state.costSpent,
          'costRemaining': state.costRemaining,
          'patchAllowed': false,
          'gap': 'METHOD_BODY_UNAVAILABLE',
        });
        break;
      }
    }

    final methodsFetched = methods
        .where((m) => m['smali'] is String && (m['smali'] as String).isNotEmpty)
        .length;
    final hasMethodBody = methodsFetched > 0;
    final actionable = hasMethodBody;
    if (writes > 1 && failureReason.isEmpty) failureReason = 'MULTIPLE_WRITERS';
    final lastDecision = plannerDecisions.isNotEmpty
        ? plannerDecisions.last
        : const <String, dynamic>{};
    final patchAllowed = lastDecision['patchAllowed'] == true;

    return <String, dynamic>{
      'ok': true,
      'chain': fieldStateLocate,
      'command': fieldStateLocate,
      'target': <String, dynamic>{
        'field': target.field,
        'className': target.className,
        'locator': target.locator,
      },
      'evidence': <String, dynamic>{
        'writes': writes,
        'reads': reads,
        'primaryLocator': actionable
            ? methods.first['qualifiedId']
            : ((usage?.primaryCandidates.isNotEmpty ?? false)
                  ? usage!.primaryCandidates.first.locator
                  : ''),
        'evidenceLevel': usage?.evidenceLevel.label ?? 'L0',
        'confidence': usage?.confidence.label ?? 'LOW',
        'stopReason': stopReason,
        if (failureReason.isNotEmpty) 'failureReason': failureReason,
        'uncertainties': usage?.uncertainties ?? const <dynamic>[],
      },
      'planner': <String, dynamic>{
        'costBudget': state.costBudget,
        'costSpent': state.costSpent,
        'costRemaining': state.costRemaining,
        'patchAllowed': patchAllowed,
        'patchGate': patchAllowed
            ? '方法体直接证据 + 写入方已确认：允许进入 patch（dryRun 纪律照旧）'
            : 'R2 门禁：当前证据不允许进入 patch（蓝图规则 2）',
        'stopRule': lastDecision['rule'],
      },
      'plannerDecisions': plannerDecisions,
      'probes': probes,
      'probeCount': probes.length,
      'methods': methods,
      'callerSummary': callerSummary,
      'nextActions': [
        for (final a in (usage?.nextActions ?? const <AnalyzerNextAction>[]))
          a.toJson(),
      ],
      'summary': usage?.summary ?? '探针未产出可用结果',
      'llmJudgment': '程序已按 Probe Planner 固定规则完成探针（决策见 '
          'plannerDecisions，执行见 probes）。请只做判断，不要补跑同类探针：'
          '给出 支持/反驳/待验证 + primary locator；patchAllowed=false 时'
          '禁止建议直接修改；failureReason 非空时如实报告缺口与 nextActions。',
    };
  }

  // -------------------------------------------------------------------------
  // FIELD_CANDIDATE_MINE（B1：字段候选自动挖掘）
  // -------------------------------------------------------------------------

  static Future<Map<String, dynamic>> _runFieldCandidateMine(
    Map<String, dynamic> args,
    String analyzerContextKey,
  ) async {
    final semantic = (args['semantic'] ?? '').toString().trim();
    final apkPath = (args['apkPath'] ?? '').toString().trim();
    if (semantic.isEmpty) {
      return <String, dynamic>{
        'ok': false,
        'error': <String, dynamic>{
          'code': 'INVALID_ARGUMENT',
          'message': 'semantic 必填：给出要定位的语义描述（如「会员解锁」「去广告」）。',
          'recoverable': true,
          'argument': 'semantic',
        },
      };
    }
    // 报告 2-23 同族：limit/maxClasses 都被钳过却只字不提。
    final limitRequested = (args['limit'] as num?)?.toInt();
    final limit = (limitRequested ?? 20).clamp(1, 50).toInt();
    final maxClassesRequested = (args['maxClasses'] as num?)?.toInt();
    final maxClasses = (maxClassesRequested ?? 5).clamp(1, 8).toInt();
    final packagePrefix = (args['packagePrefix'] ?? '').toString().trim();
    final extraKeywords = ((args['keywords'] as List?) ?? const <dynamic>[])
        .whereType<String>()
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();

    final probes = <Map<String, dynamic>>[];
    final keywords = expandSemanticKeywords(semantic, extra: extraKeywords);

    // B-2 同款：网关绑定（幂等），DexKit 走 toolchain 但候选类 outline 需要
    // 工作区上下文一致。
    if (apkPath.isNotEmpty) {
      try {
        await AnalyzerGatewayRegistry.forKey(analyzerContextKey)
            .openWorkspace(apkPath: apkPath);
      } catch (_) {}
    }

    // Probe 1 — DexKit fieldNames 维度：**逐词**查（DexKit usingField 多关键词
    // 是 OR，vip+member 会把 gson 的 members 带进来）。每个关键词独立一次，
    // 单关键词命中即方法用该名子段——高信号；逐词聚合后业务类因多命中靠前。
    // 预算：最多 4 个高信号词（短词更具体，优先），避免把预算烧在噪音词上。
    final p1Rows = <Map<String, dynamic>>[];
    final sortedKw = keywords.toList()
      ..sort((a, b) => a.length.compareTo(b.length));
    final fieldKw = sortedKw.take(4).toList();
    for (final kw in fieldKw) {
      final p = await _structuralProbe(probes, 'dex_search.fieldNames', () {
        return ApkToolchainService.dexSearch(
          path: apkPath,
          fieldNames: <String>[kw],
          action: 'auto',
          ignoreCase: true,
          packagePrefix: packagePrefix.isNotEmpty ? packagePrefix : null,
          limit: 20,
        );
      });
      if (p != null) p1Rows.addAll(_probeRows(p));
    }
    // Probe 2 — 字符串维度：语义原文（中文 UI 文案/英文标识符均常见指示）。
    final p2 = await _structuralProbe(probes, 'dex_search.strings', () {
      return ApkToolchainService.dexSearch(
        path: apkPath,
        keyword: semantic,
        action: 'auto',
        ignoreCase: true,
        packagePrefix: packagePrefix.isNotEmpty ? packagePrefix : null,
        limit: 50,
      );
    });
    if (p1Rows.isEmpty && p2 == null) {
      return <String, dynamic>{
        'ok': true,
        'chain': fieldCandidateMine,
        'command': fieldCandidateMine,
        'semantic': semantic,
        'keywords': keywords,
        'fieldCandidates': const <dynamic>[],
        'candidateClasses': const <dynamic>[],
        'failureReason': 'DEX_SEARCH_FAILED',
        // 报告 2-20：证据根本拿不到时要有**可判定**的「不适用」，而不是让模型
        // 在「无候选」和「探针坏了」之间猜。verdict 是机器可读判定，
        // applicable=false 表示本轮不能凭这条链下结论。
        'verdict': TaskChainVerdict.probeUnavailable.wire,
        'applicable': TaskChainVerdict.probeUnavailable.applicable,
        'verdictReason': TaskChainVerdicts.reasonProbeUnavailable,
        'verdictMessage': TaskChainVerdicts.messageFor(
          TaskChainVerdict.probeUnavailable,
        ),
        'nextActions': TaskChainVerdicts.nextActionsFor(
          TaskChainVerdict.probeUnavailable,
        ),
        'probes': probes,
        'probeCount': probes.length,
        'llmJudgment':
            '探针不可用（verdict=not_applicable/PROBE_UNAVAILABLE）：本轮不能判断该语义，'
            '如实报告环境缺口与 nextActions，不要猜测字段，也不要下「不存在」的结论。',
      };
    }

    // 候选类聚合（纯函数）：fieldNames（p1，字段名证据强）与字符串（p2）分开
    // 聚合，source 标签如实标注；再按命中数合并截断。SDK 类已在聚合内剔除。
    final p2Rows = p2 == null ? const <Map<String, dynamic>>[] : _probeRows(p2);
    final merged = <String, Map<String, dynamic>>{};
    for (final c in aggregateCandidateClasses(
      p1Rows,
      maxClasses: maxClasses,
      sourceLabel: 'fieldNames',
    )) {
      merged[c['className']!] = c;
    }
    for (final c in aggregateCandidateClasses(
      p2Rows,
      maxClasses: maxClasses,
      sourceLabel: 'strings',
    )) {
      final exist = merged[c['className']!];
      if (exist != null) {
        exist['hits'] = ((int.tryParse(exist['hits']!) ?? 0) +
                (int.tryParse(c['hits']!) ?? 0))
            .toString();
        exist['source'] = '${exist['source']}+${c['source']}';
      } else {
        merged[c['className']!] = c;
      }
    }
    final candidateClasses = merged.values.toList()
      ..sort((a, b) => (int.tryParse(b['hits']!) ?? 0)
          .compareTo(int.tryParse(a['hits']!) ?? 0));
    final candidateClassesAll = candidateClasses.take(maxClasses).toList();

    // Probe 3..N — class_outline 枚举候选类字段（预算 = maxClasses）。
    final fieldsByClass = <String, List<Map<String, dynamic>>>{};
    for (final cls in candidateClassesAll) {
      final name = cls['className']!;
      final r = await _structuralProbe(probes, 'class_outline', () {
        return ApkToolchainService.classOutline(
          path: apkPath,
          className: name,
        );
      });
      if (r == null) continue;
      final fields = ((r.data ?? const {})['fields'] as List?) ?? const [];
      fieldsByClass[name] = fields
          .whereType<Map>()
          .map((m) => Map<String, dynamic>.from(m))
          .toList();
    }

    final evidenceClasses = candidateClassesAll
        .where((c) => ((c['source'] ?? '') as String).contains('fieldNames'))
        .map<String>((c) => (c['className'] ?? '') as String)
        .where((s) => s.isNotEmpty)
        .toSet();
    final candidates = scoreFieldCandidates(
      fieldsByClass: fieldsByClass,
      keywords: keywords,
      semantic: semantic,
      fieldProbeClasses: evidenceClasses,
      limit: limit,
    );

    final failed = candidateClassesAll.isNotEmpty && fieldsByClass.isEmpty;
    // 报告 2-20：三档判定，机器可读，模型不必在「没候选」和「判不了」之间猜。
    //  - candidates_found：有候选，可以往下走 FIELD_STATE_LOCATE
    //  - inconclusive   ：有候选类但拿不到字段体（证据不全，值得再补一次）
    //  - not_applicable ：探针跑完且零线索——本包内没有该语义的可定位痕迹，
    //                     这时**不该**硬给结论，也不该编字段。
    final classified = TaskChainVerdicts.classifyFieldCandidates(
      hasCandidates: candidates.isNotEmpty,
      outlineFailed: failed,
    );
    final verdict = classified.verdict;
    final verdictReason = classified.reason;
    return <String, dynamic>{
      'ok': true,
      'chain': fieldCandidateMine,
      'command': fieldCandidateMine,
      'semantic': semantic,
      'keywords': keywords,
      'verdict': verdict.wire,
      'applicable': verdict.applicable,
      // 生效值回显（同族缺陷扫查）：钳过就说清楚。
      ...ToolArgEcho.effectiveAll(
        <({String name, num? requested, num effective})>[
          (name: 'limit', requested: limitRequested, effective: limit),
          (
            name: 'maxClasses',
            requested: maxClassesRequested,
            effective: maxClasses,
          ),
        ],
      ),
      'verdictReason': verdictReason,
      'verdictMessage': TaskChainVerdicts.messageFor(verdict),
      if (verdict != TaskChainVerdict.candidatesFound)
        'nextActions': TaskChainVerdicts.nextActionsFor(verdict),
      'candidateClasses': [
        for (final c in candidateClassesAll)
          {'className': c['className'], 'hits': c['hits'], 'source': c['source']},
      ],
      'fieldCandidates': candidates,
      if (candidates.isEmpty && !failed)
        'failureReason': 'NO_CANDIDATES'
      else if (failed) 'failureReason': 'OUTLINE_UNAVAILABLE',
      'probes': probes,
      'probeCount': probes.length,
      'llmJudgment': candidates.isEmpty
          ? '程序已按固定链挖掘但无候选（verdict=${verdict.wire} / $verdictReason）。'
              '${verdict == TaskChainVerdict.notApplicable ? '本轮判定为不适用：如实报告理由与 nextActions，'
                  '不要下「功能不存在」的结论，不要编造字段。' : '证据不全：如实报告缺口，'
                  '按 nextActions 补证据，不要据此下结论。'}'
          : '程序已按固定链产出 fieldCandidates[]（verdict=candidates_found，打分=名称命中+'
              '类型可改性+证据维度）。请从中择一目标后改用 FIELD_STATE_LOCATE（传 className+'
              'field 或 fieldLocator），不要在本轮直接修改字段；布尔/数值形态'
              '通常是开关型标志，字符串多为展示文案。',
    };
  }

  // -------------------------------------------------------------------------
  // AD_SDK_LOCATE
  // -------------------------------------------------------------------------

  /// AD_SDK_LOCATE：定位广告 SDK 初始化/触发调用点，产出 patch 候选。
  /// 固定探针序：报告 adSdkMatches（前置）→ 每厂商 dex_search 反查 init →
  /// smali 确认初始化体 → caller 摘要找宿主触发点。只读，不做任何修改。
  static Future<Map<String, dynamic>> _runAdSdkLocate(
    Map<String, dynamic> args,
    String analyzerContextKey,
  ) async {
    final apkPath = (args['apkPath'] ?? '').toString().trim();
    final probes = <Map<String, dynamic>>[];
    final plannerDecisions = <Map<String, dynamic>>[];
    final vendorHint = (args['vendor'] ?? '').toString().trim();

    // 链内预算：每次探针 +1，硬上界 8（防失控；FieldStateLocate 同级纪律）。
    const budget = 8;
    var spent = 0;
    void spend() => spent++;

    if (apkPath.isEmpty) {
      return <String, dynamic>{
        'ok': false,
        'error': <String, dynamic>{
          'code': 'APK_PATH_REQUIRED',
          'message': 'apkPath 必填：先在工作台选定 APK 或传 apkPath。',
          'recoverable': true,
        },
      };
    }

    // 1. 报告 adSdkMatches（前置：广告 SDK 由分析报告的 DEX/组件证据确认）。
    final report = await ApkWorkspaceService.readReport();
    final reportSdks = <String>[
      for (final e in listField(report, 'adSdkMatches'))
        if (e != null && e.toString().trim().isNotEmpty) e.toString().trim(),
    ];
    // B7：空列表是合法形状（"无广告 SDK 命中"），走 NO_AD_SDK_HITS 分支；
    // 只有字段存在但不是 List 才是真形状漂移。
    final rawAdSdkMatches = report?['adSdkMatches'];
    if (report != null && rawAdSdkMatches != null && rawAdSdkMatches is! List) {
      probes.add(<String, dynamic>{
        'tool': 'report.adSdkMatches',
        'ok': false,
        'error': 'adSdkMatches 形状漂移: ${actualTypeOf(report, 'adSdkMatches')}',
      });
    }
    // 厂商提示优先；否则取报告命中前 3（多 SDK 不一次全查，预算保护）。
    var sdkTargets = <String>[
      if (vendorHint.isNotEmpty) vendorHint,
      ...reportSdks,
    ];
    sdkTargets = sdkTargets.toSet().take(3).toList();

    if (sdkTargets.isEmpty) {
      return <String, dynamic>{
        'ok': true,
        'chain': adSdkLocate,
        'command': adSdkLocate,
        'failureReason': 'NO_AD_SDK_HITS',
        'adSdkMatches': const <String>[],
        'plannerDecisions': plannerDecisions,
        'probes': probes,
        'probeCount': probes.length,
        'llmJudgment': '报告无 adSdkMatches 且未给 vendor。先 analyze 产出报告'
            '（或直接传 vendor 包名）再定位；不要猜测 SDK。',
      };
    }

    // 2. 对每个 SDK 包反查初始化入口。DexKit usingString/methodName 双维度。
    final patchCandidates = <Map<String, dynamic>>[];
    final evidence = <Map<String, dynamic>>[];
    for (final sdkPkg in sdkTargets) {
      if (spent >= budget) break;
      final initProbe = await _structuralProbe(probes, 'dex_search.init', () {
        return ApkToolchainService.dexSearch(
          path: apkPath,
          methodName: 'init',
          packagePrefix: sdkPkg,
          limit: 15,
        );
      });
      if (initProbe != null) {
        final rows = _probeRows(initProbe);
        for (final row in rows.take(3)) {
          if (spent >= budget) break;
          final qid = (row['qualifiedId'] ?? row['qid'] ?? '').toString();
          if (qid.isEmpty) continue;
          spend();
          final smali = await _readMethodBody(qid, apkPath, probes);
          if (smali == null) continue;
          final callers = await _callerSummary(qid, apkPath, probes);
          final confirmed = smali.contains('invoke-') ||
              smali.contains(';-><init>') ||
              smali.contains('register');
          evidence.add(<String, dynamic>{
            'qualifiedId': qid,
            'sdkPackage': sdkPkg,
            'role': 'init',
            'smaliConfirmed': confirmed,
            'callers': callers.take(5).toList(),
          });
          patchCandidates.add(<String, dynamic>{
            'qualifiedId': qid,
            'sdkPackage': sdkPkg,
            'role': 'init',
            'smaliConfirmed': confirmed,
            'reason': 'SDK $sdkPkg 初始化入口，方法体含调用逻辑',
          });
        }
      }
      plannerDecisions.add(<String, dynamic>{
        'seq': plannerDecisions.length + 1,
        'action': 'probe',
        'rule': 'AD_INIT_LOOKUP',
        'sdkPackage': sdkPkg,
        'reason': '反查初始化入口',
        'costSpent': spent,
        'costRemaining': budget - spent,
        'patchAllowed': false,
      });
      if (spent >= budget) break;
    }

    // 3. 收束信封。patchAllowed 恒 false：本链只定位，不修改。
    final found = patchCandidates.isNotEmpty;
    plannerDecisions.add(<String, dynamic>{
      'seq': plannerDecisions.length + 1,
      'action': found ? 'stop' : 'stop',
      'rule': found ? 'R4_DIRECT_EVIDENCE' : 'R5_BUDGET_EXHAUSTED',
      'gap': found ? null : 'BUDGET_EXHAUSTED',
      'reason': found ? '已产出 init 候选' : '预算内未找到可确认的 init 候选',
      'costSpent': spent,
      'costRemaining': budget - spent,
      'patchAllowed': false,
    });

    return <String, dynamic>{
      'ok': true,
      'chain': adSdkLocate,
      'command': adSdkLocate,
      'adSdkMatches': reportSdks,
      'sdkTargets': sdkTargets,
      'patchCandidates': patchCandidates,
      'evidence': evidence,
      if (!found) 'failureReason': 'NO_INIT_CANDIDATES',
      'plannerDecisions': plannerDecisions,
      'probes': probes,
      'probeCount': probes.length,
      'llmJudgment': found
          ? '已定位 SDK 初始化/触发候选（patchCandidates[]）。下一步：对确认的'
              '方法用 patch_apk_dex_methods 的 voidMethods/sdkPackages 先 dryRun，'
              '或走 patch_apk_manifest 删组件；本轮禁止链内直接修改。'
          : '固定链未找到可确认的 init 候选。如实报告；可用 vendor 参数指定'
              'SDK 包名后重试，或转 route_task 自由探索。',
    };
  }

  // -------------------------------------------------------------------------
  // SIGNATURE_CHECK_LOCATE
  // -------------------------------------------------------------------------

  /// SIGNATURE_CHECK_LOCATE：定位签名校验参与代码，产出「是否需要去签」。
  /// 固定探针序：scanSignatureCheck 全 dex 词扫描 → dex_search 反查命中词 →
  /// smali 逐方法确认读自身签名 + 参与放行/退出分支 → caller 摘要。只读。
  static Future<Map<String, dynamic>> _runSignatureCheckLocate(
    Map<String, dynamic> args,
    String analyzerContextKey,
  ) async {
    final apkPath = (args['apkPath'] ?? '').toString().trim();
    final probes = <Map<String, dynamic>>[];
    final plannerDecisions = <Map<String, dynamic>>[];
    const budget = 8;
    var spent = 0;
    void spend() => spent++;

    if (apkPath.isEmpty) {
      return <String, dynamic>{
        'ok': false,
        'error': <String, dynamic>{
          'code': 'APK_PATH_REQUIRED',
          'message': 'apkPath 必填：先在工作台选定 APK 或传 apkPath。',
          'recoverable': true,
        },
      };
    }

    // 1. 原生全 dex 词扫描（不依赖报告，兼容报告缺失/陈旧）。
    final scan = await _structuralProbe(probes, 'scan_signature_check', () {
      return ApkToolchainService.scanSignatureCheck(path: apkPath);
    });
    if (scan == null) {
      return <String, dynamic>{
        'ok': true,
        'chain': signatureCheckLocate,
        'command': signatureCheckLocate,
        'failureReason': 'SCAN_FAILED',
        'plannerDecisions': plannerDecisions,
        'probes': probes,
        'probeCount': probes.length,
        'llmJudgment': 'scanSignatureCheck 探针失败，见 probes[].error。'
            '不要在没有扫描结果时下"无签名校验"结论。',
      };
    }
    final scanHits = <String>[
      for (final e in listField(scan.data, 'hits'))
        if (e != null && e.toString().trim().isNotEmpty) e.toString().trim(),
    ];
    if (scan.data?['hits'] != null && scanHits.isEmpty) {
      // 带实际值（截断）诊断：形状漂移根因曾定位到传输层，值本身能区分
      // "空命中序列化异常" 与 "真实命中被压成字符串"（后者可抢救）。
      final rawHits = scan.data?['hits']?.toString() ?? '';
      probes.add(<String, dynamic>{
        'tool': 'scan_signature_check',
        'ok': false,
        'error': 'hits 形状漂移: ${actualTypeOf(scan.data, 'hits')}，'
            'value=${rawHits.length > 80 ? rawHits.substring(0, 80) : rawHits}',
      });
    }

    // 2. 无命中 → 收束：不需要去签（注意壳/Flutter 的 dex 盲区，llmJudgment 提示）。
    if (scanHits.isEmpty) {
      return <String, dynamic>{
        'ok': true,
        'chain': signatureCheckLocate,
        'command': signatureCheckLocate,
        'signatureCheck': <String, dynamic>{
          'scanHits': const <String>[],
          'verdict': 'NO_SIGNATURE_CHECK_DETECTED',
          'methodLevelConfirmed': false,
          'evidenceMethods': const <dynamic>[],
          'needsSignatureBypass': false,
        },
        'plannerDecisions': plannerDecisions,
        'probes': probes,
        'probeCount': probes.length,
        'llmJudgment': 'DEX 层未扫到签名校验词。若 APK 有壳或业务在 Flutter '
            'libapp.so，自校验可能在 so 层，需走 so_analyze；不要仅凭 dex 扫描'
            '为空就断言绝对无校验。',
      };
    }

    // 3. 高信号词优先（读取自身签名 API 比通用 verify/equals 更可靠）。
    const strongNeedles = <String>[
      'getPackageInfo',
      'GET_SIGNATURES',
      'get-signatures',
      'signatures[0]',
      'toByteArray',
      'checkSignature',
      'PackageManager',
    ];
    final sorted = List<String>.of(scanHits)
      ..sort((a, b) {
        final ai = strongNeedles.indexWhere((n) => a.contains(n));
        final bi = strongNeedles.indexWhere((n) => b.contains(n));
        final ascore = ai == -1 ? 99 : ai;
        final bscore = bi == -1 ? 99 : bi;
        return ascore.compareTo(bscore);
      });
    final evidenceMethods = <Map<String, dynamic>>[];

    for (final hit in sorted.take(3)) {
      if (spent >= budget) break;
      final search = await _structuralProbe(probes, 'dex_search.signature', () {
        return ApkToolchainService.dexSearch(
          path: apkPath,
          keyword: hit,
          action: 'auto',
          ignoreCase: true,
          limit: 15,
        );
      });
      if (search == null) continue;
      for (final row in _probeRows(search).take(2)) {
        if (spent >= budget) break;
        final qid = (row['qualifiedId'] ?? row['qid'] ?? '').toString();
        if (qid.isEmpty) continue;
        spend();
        final smali = await _readMethodBody(qid, apkPath, probes);
        if (smali == null) continue;
        final features = _classifySignatureSmali(smali);
        if (features.isEmpty) continue;
        final callers = await _callerSummary(qid, apkPath, probes);
        evidenceMethods.add(<String, dynamic>{
          'qualifiedId': qid,
          'hitKeyword': hit,
          'features': features,
          'smaliConfirmed': features.isNotEmpty,
          // B8：微信/支付宝等开放平台的 SDK 自带"校验应用签名"逻辑（用于
          // 平台登录/支付），特征与应用级反篡改完全同形，单独命中会误报
          // CONFIRMED 引导无谓去签。标记后由聚合判定降级。
          'thirdPartySdk': _isThirdPartySignatureSdkMethod(qid),
          'callers': callers.take(5).toList(),
        });
      }
      plannerDecisions.add(<String, dynamic>{
        'seq': plannerDecisions.length + 1,
        'action': 'probe',
        'rule': 'SIG_METHOD_LOOKUP',
        'keyword': hit,
        'reason': '反查签名词命中方法',
        'costSpent': spent,
        'costRemaining': budget - spent,
        'patchAllowed': false,
      });
      if (spent >= budget) break;
    }

    // 4. 纯函数聚合判定。
    final verdict = _summarizeSignatureVerdict(evidenceMethods);
    plannerDecisions.add(<String, dynamic>{
      'seq': plannerDecisions.length + 1,
      'action': 'stop',
      'rule': 'R4_DIRECT_EVIDENCE',
      'reason': '产出判定: ${verdict['verdict']}',
      'costSpent': spent,
      'costRemaining': budget - spent,
      'patchAllowed': false,
    });

    return <String, dynamic>{
      'ok': true,
      'chain': signatureCheckLocate,
      'command': signatureCheckLocate,
      'signatureCheck': <String, dynamic>{
        'scanHits': scanHits,
        'verdict': verdict['verdict'],
        'methodLevelConfirmed': verdict['methodLevelConfirmed'],
        'evidenceMethods': evidenceMethods,
        'needsSignatureBypass': verdict['needsSignatureBypass'],
        if (verdict['reason'] != null) 'reason': verdict['reason'],
      },
      'plannerDecisions': plannerDecisions,
      'probes': probes,
      'probeCount': probes.length,
      'llmJudgment': verdict['needsSignatureBypass'] == true
          ? '已确认方法级签名校验证据（读自身签名 + 参与分支）。可走 '
              'apk_signature_bypass（mode 选择见工作台默认），但仍应先 dryRun。'
          : 'DEX 层仅有字符串级签名提示或方法弱证据，未到方法级确认。'
              '如需去签可走 signature_bypass 的 dryRun 预览再决定；'
              '壳/Flutter 自校验需另走 so 分析。',
    };
  }

  /// 纯函数：smali 方法体 → 签名校验特征标签。方法级证据的门槛是「读取
  /// 自身签名」——仅含 equals/if 不升级为 gate_logic（防第三方 SDK 字符串
  /// 误判，Kotlin signatureCheck note 同款约束）。
  /// B8：已知三方开放平台 SDK 命名空间（这些平台的 SDK 会读取应用自身签名
  /// 用于平台登录/支付校验，与应用级反篡改同形）。qualifiedId 兼容
  /// Lcom/tencent/mm/... 与 com.tencent.mm... 两种分隔形态。
  static const List<String> _thirdPartySignatureSdkTokens = <String>[
    'com/tencent/mm', 'com.tencent.mm', // 微信开放平台
    'com/tencent/open', 'com.tencent.open', // 腾讯开放 SDK
    'com/alipay', 'com.alipay', // 支付宝
    'com/umeng', 'com.umeng', // 友盟
    'com/sinaweibo', 'com.sinaweibo', // 微博
    'com/unionpay', 'com.unionpay', // 银联
  ];

  static bool _isThirdPartySignatureSdkMethod(String qualifiedId) {
    final q = qualifiedId.toLowerCase();
    return _thirdPartySignatureSdkTokens.any(q.contains);
  }

  static List<String> _classifySignatureSmali(String smali) {
    final lower = smali.toLowerCase();
    final features = <String>[];
    final readsOwnSignature =
        lower.contains('getpackageinfo') ||
        lower.contains('get_signatures') ||
        lower.contains('signatures[') ||
        lower.contains('packagemanager') ||
        lower.contains('getsigninginfo') ||
        lower.contains('tobytearray');
    if (readsOwnSignature) features.add('reads_signature');
    // 参与放行/退出分支：必须在读取签名的基础上才有意义。
    if (readsOwnSignature &&
        (lower.contains('check') ||
            lower.contains('verify') ||
            lower.contains('equals') ||
            lower.contains('if-eqz') ||
            lower.contains('if-nez') ||
            lower.contains('const/4'))) {
      features.add('gate_logic');
    }
    return features;
  }

  /// 纯函数：evidenceMethods → 签名校验判定（verdict + needsSignatureBypass）。
  static Map<String, dynamic> _summarizeSignatureVerdict(
    List<Map<String, dynamic>> evidenceMethods,
  ) {
    if (evidenceMethods.isEmpty) {
      return <String, dynamic>{
        'verdict': 'STRING_HINT_ONLY',
        'methodLevelConfirmed': false,
        'needsSignatureBypass': false,
        'reason': '仅有字符串命中，无方法级证据',
      };
    }
    // B8：三方平台 SDK 的签名读取不参与 CONFIRMED 判定（防微信/支付宝
    // 登录 SDK 的自身签名校验被误判为应用级反篡改）。
    bool isAppGate(Map<String, dynamic> m) =>
        (listField(m, 'features')).contains('gate_logic') &&
        m['thirdPartySdk'] != true;
    bool isAppRead(Map<String, dynamic> m) =>
        (listField(m, 'features')).contains('reads_signature') &&
        m['thirdPartySdk'] != true;
    final gate = evidenceMethods.any(isAppGate);
    if (gate) {
      return <String, dynamic>{
        'verdict': 'SIGNATURE_CHECK_CONFIRMED',
        'methodLevelConfirmed': true,
        'needsSignatureBypass': true,
        'reason': '≥1 应用级方法读取自身签名并参与放行/退出分支',
      };
    }
    final reads = evidenceMethods.any(isAppRead);
    if (reads) {
      return <String, dynamic>{
        'verdict': 'SIGNATURE_READ_ONLY',
        'methodLevelConfirmed': true,
        'needsSignatureBypass': false,
        'reason': '方法读取自身签名但未见放行分支',
      };
    }
    final onlyThirdParty = evidenceMethods.any(
      (m) => (listField(m, 'features')).isNotEmpty && m['thirdPartySdk'] == true,
    );
    if (onlyThirdParty) {
      return <String, dynamic>{
        'verdict': 'SIGNATURE_READ_ONLY',
        'methodLevelConfirmed': false,
        'needsSignatureBypass': false,
        'reason': '签名读取特征仅来自已知三方平台 SDK（微信/支付宝等开放平台'
            '自身签名校验），未见应用级反篡改证据；不要据此去签',
      };
    }
    return <String, dynamic>{
      'verdict': 'STRING_HINT_ONLY',
      'methodLevelConfirmed': false,
      'needsSignatureBypass': false,
      'reason': '方法无签名读取特征',
    };
  }

  /// 测试入口：签名 smali 特征分类（转发 [_classifySignatureSmali]）。
  static List<String> classifySignatureSmaliForTest(String smali) =>
      _classifySignatureSmali(smali);

  /// 测试入口：签名判定聚合（转发 [_summarizeSignatureVerdict]）。
  static Map<String, dynamic> summarizeSignatureVerdictForTest(
    List<Map<String, dynamic>> evidenceMethods,
  ) =>
      _summarizeSignatureVerdict(evidenceMethods);

  /// 结构化探针包装（toolchain 域）：带计时/错误捕获，失败返回 null 不中断。
  static Future<ApkStructuralResult?> _structuralProbe(
    List<Map<String, dynamic>> probes,
    String name,
    Future<ApkStructuralResult> Function() action,
  ) async {
    final sw = Stopwatch()..start();
    ApkStructuralResult r;
    try {
      r = await action();
    } catch (e) {
      probes.add(<String, dynamic>{
        'tool': name,
        'ok': false,
        'error': '${e.runtimeType}: $e',
        'durationMs': sw.elapsedMilliseconds,
      });
      return null;
    }
    sw.stop();
    probes.add(<String, dynamic>{
      'tool': name,
      'ok': r.ok,
      'summary': r.message,
      'durationMs': sw.elapsedMilliseconds,
      if (!r.ok) 'error': r.error ?? r.message,
    });
    return r.ok ? r : null;
  }

  static List<Map<String, dynamic>> _probeRows(ApkStructuralResult r) {
    final rows = listField(r.data, 'results');
    return rows.whereType<Map>().map((m) => Map<String, dynamic>.from(m)).toList();
  }

  /// 防御式 List 字段提取（真机 'String' is not a subtype of List 教训）：
  /// 通道/报告字段的实际形状可能与预期漂移，硬 cast `as List?` 会把链炸成
  /// 裸异常。两种可抢救形态自动还原：JSON 数组字符串 `["a","b"]`，以及
  /// Kotlin List.toString() 产物 `[a, b, c]`（Android org.json 对裸
  /// Collection 走 toString 的历史产物）；其余返回空列表。
  static List<dynamic> listField(Map<Object?, Object?>? data, String key) {
    final v = data?[key];
    if (v is List) return v;
    if (v is String) {
      final t = v.trim();
      if (t.startsWith('[') && t.endsWith(']')) {
        final inner = t.substring(1, t.length - 1).trim();
        if (inner.isEmpty) return const <dynamic>[];
        // 先试标准 JSON（元素带引号的合法数组）。
        try {
          final decoded = jsonDecode(t);
          if (decoded is List) return decoded;
        } catch (_) {}
        // 再试 Kotlin List.toString() 格式（无引号、逗号分隔）。
        return inner
            .split(',')
            .map((s) => s.trim())
            .where((s) => s.isNotEmpty)
            .toList();
      }
    }
    return const <dynamic>[];
  }

  /// 诊断用：字段实际运行时类型（形状漂移时写进 probes 自解释）。
  static String actualTypeOf(Map<Object?, Object?>? data, String key) {
    final v = data?[key];
    return v == null ? 'null' : v.runtimeType.toString();
  }

  // B1 纯函数：语义 → 关键词集。语义原文 + 英文 token + 内置同义词表展开，
  // 全小写去重，上限 12（DexKit 特征维度有实测性价比上限）。
  static List<String> expandSemanticKeywords(
    String semantic, {
    List<String> extra = const <String>[],
  }) {
    const synonyms = <String, List<String>>{
      // 付费墙/会员语义全覆盖：国内 vip 系 + 海外 pro 系 + 本地化（正式版）。
      '会员': ['vip', 'premium', 'pro', 'isvip', 'ispro', 'member'],
      'vip': ['vip', 'premium', 'member', 'isvip', 'pro', 'ispro'],
      'pro': ['pro', 'ispro', 'premium'],
      '正式': ['pro', 'full', 'ispro', 'paid'],
      '完整': ['full', 'pro', 'paid'],
      '广告': ['advert', 'ad', 'banner', 'splash', 'interstitial', 'reward'],
      '解锁': ['unlock', 'lock', 'limit', 'license', 'restrict'],
      '付费': ['pay', 'purchase', 'buy', 'ispay', 'payment'],
      '购买': ['purchase', 'buy', 'pay'],
      '支付': ['pay', 'payment', 'purchase'],
      '登录': ['login', 'token', 'auth', 'session'],
      '积分': ['point', 'credit', 'coin'],
      '金币': ['coin', 'gold', 'diamond'],
      '签到': ['sign', 'checkin', 'attend'],
    };
    final lower = semantic.toLowerCase();
    final out = <String>{};
    void add(String w) {
      final t = w.trim().toLowerCase();
      if (t.length >= 2 && t.length <= 32) out.add(t);
    }

    for (final token in RegExp(r'[A-Za-z_][A-Za-z0-9_]{1,}').allMatches(semantic)) {
      add(token.group(0)!);
    }
    synonyms.forEach((key, vals) {
      if (lower.contains(key)) vals.forEach(add);
    });
    extra.forEach(add);
    final list = out.toList()..sort();
    return list.take(16).toList(growable: false);
  }

  /// B1 纯函数：类名归一化为斜杠格式（dex_search 返回点分 `androidx.activity.X`，
  /// outline/key 用斜杠 `com/fewwind/X`；黑名单前缀统一斜杠比对）。
  static String slashClassName(String cls) =>
      cls.contains('/') ? cls : cls.replaceAll('.', '/');

  /// B1 纯函数：探针方法行 → 候选类聚合计数（含证据来源标签）。
  /// SDK/框架类直接剔除（不占 outline 探针预算）。类名点分/斜杠均兼容。
  static List<Map<String, String>> aggregateCandidateClasses(
    List<Map<String, dynamic>> rows, {
    required int maxClasses,
    String sourceLabel = 'methodProbe',
  }) {
    final hits = <String, int>{};
    final sources = <String, Set<String>>{};
    for (final row in rows) {
      final raw = (row['class'] ?? '').toString();
      final cls = slashClassName(raw);
      if (cls.isEmpty || _sdkPackagePrefixes.any(cls.startsWith)) continue;
      hits[cls] = (hits[cls] ?? 0) + 1;
      (sources[cls] ??= <String>{}).add(sourceLabel);
    }
    final ordered = hits.keys.toList()
      ..sort((a, b) => hits[b]!.compareTo(hits[a]!));
    return ordered.take(maxClasses).map((c) {
      return <String, String>{
        'className': c,
        'hits': hits[c].toString(),
        'source': sources[c]!.join('+'),
      };
    }).toList(growable: false);
  }

  /// B1 纯函数：候选类字段 → 打分排序的 fieldCandidates[]。
  ///
  /// 降噪（真机教训）：SDK/框架类直接过滤；字段名 camelCase 拆词后 exact 匹配
  /// 关键词（isVip → [is,vip] 命中 vip；gson 的 members 拆出 [members] 不匹配
  /// member，过滤掉）。
  /// 分数构成：名称命中关键词 +60；布尔/数值形态（开关类特征）+30/+15；
  /// 字段名探针证据类 +10；类短名含语义 token +20。分数相同按 qid 字典序稳定。
  /// B1 纯函数：字段名 camelCase/snake 拆词（isVip→[is,vip]、vipText→[vip,text]、
  /// members→[members]、SUBSCRIBERS→[subscribers]）。exact 词匹配关键词，
  /// 消除 members/subscribers 这类 contains 假阳性。
  static List<String> fieldNameTokens(String name) {
    // 基于原串（保留大小写）拆：大写字母 / 下划线 / 数字 / 非字母数字为边界。
    final words = RegExp(
      r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\d|_|$)|[0-9]+',
    ).allMatches(name).map((m) => m.group(0)!.toLowerCase()).toList();
    // 兜底：camelCase 漏网的（如纯小写 snake）按 _ / 非字母拆。
    if (words.isEmpty && name.isNotEmpty) {
      return name
          .split(RegExp(r'[^a-zA-Z0-9]+'))
          .where((s) => s.isNotEmpty)
          .map((s) => s.toLowerCase())
          .toList();
    }
    return words;
  }

  /// B1 纯函数：候选类字段 → 打分排序的 fieldCandidates[]。
  ///
  /// 降噪（真机教训）：SDK/框架类直接过滤；字段名 camelCase 拆词后 exact 匹配
  /// 关键词（isVip → [is,vip] 命中 vip；gson 的 members 拆出 [members] 不匹配
  /// member，过滤掉）。
  /// 分数构成：名称命中关键词 +60；布尔/数值形态（开关类特征）+30/+15；
  /// 字段名探针证据类 +10；类短名含语义 token +20。分数相同按 qid 字典序稳定。
  static List<Map<String, dynamic>> scoreFieldCandidates({
    required Map<String, List<Map<String, dynamic>>> fieldsByClass,
    required List<String> keywords,
    required String semantic,
    required Set<String> fieldProbeClasses,
    required int limit,
  }) {
    final kwLower = keywords.map((k) => k.toLowerCase()).toList();
    final semanticTokens = RegExp(r'[A-Za-z_][A-Za-z0-9_]{1,}')
        .allMatches(semantic)
        .map((m) => m.group(0)!.toLowerCase())
        .toSet();
    String formOf(String type) {
      if (type == 'Z') return 'boolean';
      if (const {'I', 'J', 'S', 'B', 'D', 'F'}.contains(type)) return 'numeric';
      if (type == 'Ljava/lang/String;') return 'string';
      if (type.startsWith('Ljava/util/List') || type.contains('[]')) {
        return 'list';
      }
      return 'object';
    }

    final byQid = <String, Map<String, dynamic>>{};
    fieldsByClass.forEach((cls, fields) {
      // SDK/框架类过滤（依赖库字段是假阳性主力）。
      if (_sdkPackagePrefixes.any(cls.startsWith)) return;
      final shortName = cls.split('/').last.toLowerCase();
      for (final f in fields) {
        final name = (f['name'] ?? '').toString();
        final type = (f['type'] ?? '').toString();
        if (name.isEmpty || type.isEmpty) continue;
        // camelCase 拆词后 exact 匹配：isVip → [is,vip] 命中 vip；
        // members → [members] 不匹配 member（contains 假阳性消除）。
        final nameTokens = fieldNameTokens(name);
        final kwHit = kwLower.any(
          (k) => nameTokens.any((t) => t == k),
        );
        if (!kwHit) continue;
        final form = formOf(type);
        var score = 60;
        if (form == 'boolean') {
          score += 30;
        } else if (form == 'numeric') {
          score += 15;
        } else if (form == 'string') {
          score += 5;
        }
        if (fieldProbeClasses.contains(cls)) score += 10;
        if (semanticTokens.any(shortName.contains)) score += 20;
        final qid = 'L$cls;->$name:$type';
        // 多 dex 同名类重复：按 qid 去重（后写覆盖，score 相同或更高）。
        byQid[qid] = <String, dynamic>{
          'fieldLocator': qid,
          'className': cls,
          'name': name,
          'type': type,
          'form': form,
          'score': score,
          'source': [
            'outline',
            if (fieldProbeClasses.contains(cls)) 'fieldNames',
          ],
        };
      }
    });
    final out = byQid.values.toList();
    out.sort((a, b) {
      final byScore = (b['score'] as int).compareTo(a['score'] as int);
      return byScore != 0
          ? byScore
          : (a['fieldLocator'] as String).compareTo(b['fieldLocator'] as String);
    });
    return out.take(limit).toList(growable: false);
  }

  // -------------------------------------------------------------------------
  // VERIFY_ARTIFACT
  // -------------------------------------------------------------------------

  static Future<Map<String, dynamic>> _runVerifyArtifact(
    Map<String, dynamic> args,
  ) async {
    final probes = <Map<String, dynamic>>[];
    var apkPath = (args['apkPath'] ?? '').toString().trim();

    // 目标解析：显式 apkPath → 活动链目标 → 最近签名成品（索引内存在者）。
    List<Map<String, dynamic>> builds = const <Map<String, dynamic>>[];
    if (apkPath.isEmpty) {
      apkPath = await ApkWorkspaceBindingService.activeApkPath() ?? '';
    }
    if (apkPath.isEmpty) {
      builds = await ApkWorkspaceBindingService.readBuilds();
      for (final build in builds) {
        final out = (build['output'] ?? '').toString();
        if ((build['signed'] == true) &&
            (build['exists'] == true) &&
            out.isNotEmpty) {
          apkPath = out;
          break;
        }
      }
    }

    // Probe 1 — 产物存在。
    var exists = false;
    int? sizeBytes;
    if (apkPath.isNotEmpty) {
      final sw = Stopwatch()..start();
      final f = File(apkPath);
      exists = await f.exists();
      if (exists) sizeBytes = await f.length();
      sw.stop();
      probes.add(<String, dynamic>{
        'tool': 'workspace.stat',
        'ok': exists,
        'target': apkPath,
        'sizeBytes': sizeBytes,
        'durationMs': sw.elapsedMilliseconds,
      });
    }

    // Probe 2 — 血缘正确：产物索引条目 + 活动链一致性（R3）。
    if (builds.isEmpty) builds = await ApkWorkspaceBindingService.readBuilds();
    final sw2 = Stopwatch()..start();
    Map<String, dynamic>? entry;
    for (final build in builds) {
      if ((build['output'] ?? '').toString() == apkPath) {
        entry = build;
        break;
      }
    }
    final activeApk = await ApkWorkspaceBindingService.activeApkPath() ?? '';
    final activeChainMatch =
        apkPath.isNotEmpty &&
        (apkPath == activeApk ||
            (entry?['source'] ?? '').toString() == activeApk ||
            (entry?['rootSource'] ?? '').toString() == activeApk);
    sw2.stop();
    probes.add(<String, dynamic>{
      'tool': 'workspace.builds',
      'ok': true,
      'tracked': entry != null,
      'activeChainMatch': activeChainMatch,
      'durationMs': sw2.elapsedMilliseconds,
    });

    // Probe 3 — 签名有效：内置 ApkVerifier（R7：签名一致性以此为准）。
    Map<String, dynamic>? signature;
    String? signError;
    if (exists) {
      final sw3 = Stopwatch()..start();
      try {
        final r = await ApkToolchainService.apkArchive(
          path: apkPath,
          action: 'certificates',
        );
        sw3.stop();
        if (r.ok) {
          signature = Map<String, dynamic>.from(r.data ?? const {});
        } else {
          signError = r.error ?? r.message;
        }
      } catch (e) {
        signError = '${e.runtimeType}: $e';
      }
      probes.add(<String, dynamic>{
        'tool': 'apk_archive.certificates',
        'ok': signature != null,
        'durationMs': sw3.elapsedMilliseconds,
        if (signError != null) 'error': signError,
      });
    }

    var verdict = summarizeVerify(
      target: apkPath,
      exists: exists,
      sizeBytes: sizeBytes,
      lineageTracked: entry != null,
      lineageSigned: entry?['signed'] == true,
      activeChainMatch: activeChainMatch,
      signature: signature,
      signError: signError,
    );

    // Probe 4 — 设备侧安装（R9）：仅三项检查 PASS 且显式请求 install 时
    // 执行；PackageInstaller 会话 + 系统验签，屏幕确认页由用户人工同意。
    if (args['install'] == true && verdict['verdict'] == 'PASS') {
      final sw4 = Stopwatch()..start();
      Map<String, dynamic> installResult;
      try {
        final r = await ApkToolchainService.installApk(path: apkPath);
        sw4.stop();
        installResult = Map<String, dynamic>.from(
          r.data ?? const <Object?, Object?>{},
        );
        if (!r.ok && installResult.isEmpty) {
          installResult = <String, dynamic>{
            'installStatus': 'ERROR',
            'message': r.error ?? r.message ?? '安装调用失败',
          };
        }
      } catch (e) {
        installResult = <String, dynamic>{
          'installStatus': 'ERROR',
          'error': '${e.runtimeType}: $e',
        };
      }
      probes.add(<String, dynamic>{
        'tool': 'package_installer',
        'ok': installResult['installStatus'] == 'SUCCESS',
        'installStatus': installResult['installStatus'],
        if (installResult['failureReason'] != null)
          'failureReason': installResult['failureReason'],
        'durationMs': sw4.elapsedMilliseconds,
      });
      verdict = summarizeVerify(
        target: apkPath,
        exists: exists,
        sizeBytes: sizeBytes,
        lineageTracked: entry != null,
        lineageSigned: entry?['signed'] == true,
        activeChainMatch: activeChainMatch,
        signature: signature,
        signError: signError,
        installResult: installResult,
      );
    }

    return <String, dynamic>{
      'ok': true,
      'chain': verifyArtifact,
      'command': verifyArtifact,
      ...verdict,
      'probes': probes,
      'probeCount': probes.length,
      'llmJudgment': '程序已按固定链完成三项检查（见 checks/probes）。请只做判断与'
          '转述，不要补跑同类检查；状态口径见 statusNote。',
    };
  }

  /// VERIFY_ARTIFACT 判定聚合（纯函数，可单测）。
  ///
  /// 检查项：产物存在 / 血缘正确（索引+活动链）/ 签名有效（ApkVerifier）。
  /// [installResult] 传入时追加 deviceInstall 检查块；install SUCCESS =
  /// Verified 的设备侧证据（claimableStatus 升级），失败则保持 Signed 语义
  /// 并带结构化 failureReason。未请求安装时状态口径不变：最高只到 Signed。
  static Map<String, dynamic> summarizeVerify({
    required String target,
    required bool exists,
    required int? sizeBytes,
    required bool lineageTracked,
    required bool lineageSigned,
    required bool activeChainMatch,
    required Map<String, dynamic>? signature,
    String? signError,
    Map<String, dynamic>? installResult,
  }) {
    final checks = <String, dynamic>{
      'exist': <String, dynamic>{
        'pass': exists,
        'detail': exists
            ? {'path': target, 'sizeBytes': sizeBytes}
            : {'path': target, 'message': '产物文件不存在'},
      },
      'lineage': <String, dynamic>{
        'pass': exists && lineageTracked && (activeChainMatch || lineageSigned),
        'detail': <String, dynamic>{
          'tracked': lineageTracked,
          'signed': lineageSigned,
          'activeChainMatch': activeChainMatch,
        },
      },
      'signature': <String, dynamic>{
        'pass': exists && signature?['verified'] == true,
        'detail': signature == null
            ? <String, dynamic>{
                if (signError != null) 'error': signError,
                if (signError == null) 'message': '未执行（产物不存在）',
              }
            : <String, dynamic>{
                'verified': signature['verified'],
                'v1': signature['verifiedUsingV1'],
                'v2': signature['verifiedUsingV2'],
                'v3': signature['verifiedUsingV3'],
                'certSha256': ((signature['certificates'] as List?) ?? const [])
                    .whereType<Map>()
                    .map((c) => (c['sha256'] ?? '').toString())
                    .where((s) => s.isNotEmpty)
                    .toList(),
              },
      },
    };

    String overall;
    var failureReason = '';
    if (!exists) {
      overall = 'FAIL';
      failureReason = 'ARTIFACT_MISSING';
    } else if (signature?['verified'] != true) {
      overall = 'FAIL';
      failureReason = 'SIGNATURE_INVALID';
    } else if (!(lineageTracked && (activeChainMatch || lineageSigned))) {
      overall = 'WARN';
      failureReason = 'LINEAGE_UNTRACKED';
    } else {
      overall = 'PASS';
    }

    var claimable = overall == 'FAIL'
        ? '不可声称 Signed：签名校验未通过或产物缺失'
        : overall == 'WARN'
        ? 'Signed（签名校验通过），但产物不在索引/活动链内，来源需人工确认'
        : lineageSigned
        ? 'Signed 且签名校验通过'
        : '签名校验通过';

    if (installResult != null) {
      final installStatus =
          (installResult['installStatus'] ?? 'UNKNOWN').toString();
      final installSuccess = installStatus == 'SUCCESS' && overall == 'PASS';
      checks['deviceInstall'] = <String, dynamic>{
        'pass': installSuccess,
        'installStatus': installStatus,
        if (installResult['failureReason'] != null)
          'failureReason': installResult['failureReason'],
        if (installResult['message'] != null)
          'message': installResult['message'],
        if (overall != 'PASS') 'skipped': true,
      };
      if (installSuccess) {
        claimable = 'Verified（真机安装成功，系统验签通过）';
      } else if (overall == 'PASS') {
        claimable = '$claimable（安装未完成：$installStatus，待真机验证）';
      }
    }

    return <String, dynamic>{
      'target': <String, dynamic>{'path': target, 'sizeBytes': sizeBytes},
      'checks': checks,
      'verdict': overall,
      if (failureReason.isNotEmpty) 'failureReason': failureReason,
      'claimableStatus': claimable,
      'statusNote': '状态口径（蓝图 §10.5）：Signed = 签名校验通过；Verified = '
          '真机安装 + 系统验签通过（本链 deviceInstall SUCCESS 才可声称），'
          '其余情况一律报告「待真机验证」。',
    };
  }

  // -------------------------------------------------------------------------
  // 探针原语（全部带计时与预算上界）
  // -------------------------------------------------------------------------

  static Future<AnalyzerResult> _probe(
    List<Map<String, dynamic>> probes,
    String name,
    Future<AnalyzerResult> Function() action,
  ) async {
    final sw = Stopwatch()..start();
    AnalyzerResult result;
    try {
      result = await action();
    } catch (e) {
      probes.add(<String, dynamic>{
        'tool': name,
        'ok': false,
        'error': '${e.runtimeType}: $e',
        'durationMs': sw.elapsedMilliseconds,
      });
      rethrow;
    }
    sw.stop();
    probes.add(<String, dynamic>{
      'tool': name,
      'ok': true,
      'summary': result.summary,
      'stopReason': result.stopReason,
      'durationMs': sw.elapsedMilliseconds,
    });
    return result;
  }

  static Future<String?> _readMethodBody(
    String qualifiedId,
    String apkPath,
    List<Map<String, dynamic>> probes,
  ) async {
    if (qualifiedId.isEmpty) return null;
    // A3：方法体进程级 LRU——同一 APK 的同一方法 smali 跨字段链复用，
    // 避免每轮链重复读同一方法体（dex 重解析昂贵）。
    final cacheKey = '$apkPath|$qualifiedId';
    final cachedSmali = _methodBodyCache.remove(cacheKey);
    if (cachedSmali != null) {
      _methodBodyCache[cacheKey] = cachedSmali;
      probes.add(<String, dynamic>{
        'tool': 'smali_read',
        'ok': true,
        'target': qualifiedId,
        'durationMs': 0,
        'cache': 'hit',
      });
      return cachedSmali;
    }
    final sw = Stopwatch()..start();
    try {
      final r = await ApkToolchainService.smaliRead(
        path: apkPath,
        qualifiedId: qualifiedId,
      );
      sw.stop();
      final data = r.data ?? const <Object?, Object?>{};
      // smali_read 载荷形状：data.matches[].smali（多 dex 时多个匹配）。
      final matches = (data['matches'] as List?) ?? const <dynamic>[];
      var smali = '';
      for (final m in matches) {
        final s = ((m as Map)['smali'] ?? '').toString();
        if (s.isNotEmpty) {
          smali = s;
          break;
        }
      }
      if (r.ok && smali.isNotEmpty) {
        _methodBodyCache[cacheKey] = smali;
        while (_methodBodyCache.length > _methodBodyCacheMax) {
          _methodBodyCache.remove(_methodBodyCache.keys.first);
        }
      }
      probes.add(<String, dynamic>{
        'tool': 'smali_read',
        'ok': r.ok && smali.isNotEmpty,
        'target': qualifiedId,
        'durationMs': sw.elapsedMilliseconds,
        if (!r.ok) 'error': r.error ?? r.message,
      });
      return r.ok ? smali : null;
    } catch (e) {
      probes.add(<String, dynamic>{
        'tool': 'smali_read',
        'ok': false,
        'target': qualifiedId,
        'error': '${e.runtimeType}: $e',
        'durationMs': sw.elapsedMilliseconds,
      });
      return null;
    }
  }

  static Future<List<String>> _callerSummary(
    String target,
    String apkPath,
    List<Map<String, dynamic>> probes,
  ) async {
    final sw = Stopwatch()..start();
    try {
      final r = await ApkToolchainService.dexXref(
        path: apkPath,
        target: target,
        direction: 'to',
        limit: 10,
      );
      sw.stop();
      final data = r.data ?? const <Object?, Object?>{};
      final callers = <String>[];
      // 防御式提取（硬 cast 曾把形状漂移炸成裸异常）。
      final raw = listField(data, 'callers').isNotEmpty
          ? listField(data, 'callers')
          : listField(data, 'xref');
      for (final item in raw) {
        final locator = item is Map
            ? (item['caller'] ?? item['method'] ?? item['locator'] ?? '')
                  .toString()
            : item.toString();
        if (locator.isNotEmpty) callers.add(locator);
      }
      probes.add(<String, dynamic>{
        'tool': 'dex_xref',
        'ok': r.ok,
        'target': target,
        'callers': callers.length,
        'durationMs': sw.elapsedMilliseconds,
        if (!r.ok) 'error': r.error ?? r.message,
      });
      return callers.take(10).toList();
    } catch (e) {
      probes.add(<String, dynamic>{
        'tool': 'dex_xref',
        'ok': false,
        'target': target,
        'error': '${e.runtimeType}: $e',
        'durationMs': sw.elapsedMilliseconds,
      });
      return const <String>[];
    }
  }
}

/// FIELD_STATE_LOCATE 目标解析（纯函数，可单测）。
class FieldTarget {
  const FieldTarget({required this.className, required this.field})
    : locator = 'L$className;->$field';

  const FieldTarget.raw(this.locator)
    : className = '',
      field = '';

  /// smali 字段 qid：Lcom/x/UserInfoBean;->isVip:Z
  final String locator;
  final String className;
  final String field;

  /// 解析优先级：raw（L…;->… 形态全量 qid）→ className+field 组合。
  /// className 允许带 L 前缀与 ; 后缀（宽容输入）；field 允许带 -> 前缀。
  /// field 参数与 schema 承诺一致：裸字段名或全量 qid（Lpkg/Class;->name:type）
  /// 均可——全量 qid 形态自动提升到 raw 解析通道，避免「schema 收 qid、
  /// 实现只收裸名」的参数断裂。
  static FieldTarget? parse({
    String field = '',
    String className = '',
    String raw = '',
  }) {
    final r = raw.trim();
    var f0 = field.trim();
    // field 参数本身是完整 qid（如 Lcom/x/UserInfoBean;->isVip:Z 或带
    // dex_field: 前缀）时，按 raw 处理；否则按裸字段名参与组合解析。
    final f0NoPrefix = f0.startsWith('dex_field:') ? f0.substring(10) : f0;
    final effectiveRaw = r.isNotEmpty
        ? r
        : RegExp(r'^L[\w/$-]+;->').hasMatch(f0NoPrefix)
        ? f0NoPrefix
        : '';
    if (effectiveRaw.isNotEmpty) {
      final normalized = effectiveRaw.startsWith('dex_field:')
          ? effectiveRaw.substring(10)
          : effectiveRaw;
      if (RegExp(r'^L[\w/$-]+;->[\w$<>]+(:[\w/$;\[]+)?$').hasMatch(normalized)) {
        return FieldTarget.raw(normalized);
      }
    }
    var f = f0;
    var c = className.trim();
    if (f.startsWith('->')) f = f.substring(2);
    if (f.contains(':')) f = f.split(':').first;
    if (c.startsWith('L') && c.endsWith(';')) {
      c = c.substring(1, c.length - 1);
    }
    // 兼容 Java FQN 写法：dex 类名用 `/` 分隔，用户常按 `com.example.Foo` 输入
    // （点号在 dex 类名里非法，转换无歧义）。
    if (c.contains('.')) c = c.replaceAll('.', '/');
    // 字段名可大写开头：混淆名（OooOOOO/OooOO0o）首字符大写合法，拒之
    // 会让 FIELD_STATE_LOCATE 对真实混淆字段全挂（冒烟实测 OooOOOO）。
    final fieldRe = RegExp(r'^[a-zA-Z_\$][A-Za-z0-9_\$]*$');
    // 类名同理**不能要求首字母大写**：R8 把类压成 pc1 / a / ooo 这类小写名是常态。
    // 旧正则（`[A-Z][\w$]*`）会让 className=pc1 直接解析失败，报"field 无法解析"，
    // 而同一句错误提示又声称支持 className+field（实测：全量 qid 能用、组合不能用）。
    // 这里只拦含非法字符的输入，真实存在性交给下游查表报 NOT_FOUND。
    final classRe = RegExp(r'^(?:[a-zA-Z_\$][\w\$]*/)*[a-zA-Z_\$][\w\$]*$');
    if (!fieldRe.hasMatch(f) || !classRe.hasMatch(c)) return null;
    return FieldTarget(className: c, field: f);
  }
}
