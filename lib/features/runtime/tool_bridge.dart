/// 工具桥：把现有工具层接进 Runtime（§7.2 / §8 / §18）。
///
/// 做四件事，全部是模型不能代劳的确定性工作：
/// 1. 权限门控——高风险工具在调用**前**被拦（§18.2 Prompt 不能授予权限）；
/// 2. 预算门控——超预算直接拒绝（§12.3）；
/// 3. 结果归一——把各工具五花八门的 JSON 收敛成统一信封（§8.1）；
/// 4. 记账与证据——每次调用留痕，命中定位类工具时登记证据（§11.6）。
///
/// 为什么用「包一层」而不是重写 31 个工具：工具内部实现是对的，
/// 需要改的是**对外协议**。包一层能一次收敛，且不碰工具内部逻辑。
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import 'capability_manifest.dart';
import 'artifact_store.dart';
import 'failure_memory.dart';
import 'models/evidence.dart';
import 'models/task.dart';
import 'models/tool_result.dart';
import 'multi_dex.dart';
import 'recovery.dart';
import 'task_runtime.dart';

class ToolBridge {
  ToolBridge(this.runtime, {this.onRuntimeWrite});

  final TaskRuntime runtime;

  /// 运行期写入（登记证据/改动计划/失败）后的通知钩子：界面靠它把「工具跑到
  /// 一半时产生的证据」实时显示出来，而不是等整个工具收尾（2026-09-15 用户
  /// 点名「刷新及时一点」）。回调必须是轻量的：只做通知，不做 IO。
  final void Function()? onRuntimeWrite;

  /// 一次工具调用：门控 → 执行 → 归一 → 记账 → 登记证据。
  ///
  /// 返回信封（调用方决定是转成文本喂模型还是自己消费）。
  Future<ToolEnvelope> invoke({
    required String taskId,
    required String tool,
    Map<String, dynamic> args = const {},
    required Future<String> Function() run,
    /// 本次调用来自 MCP 面：恢复动作要翻译成 MCP 可调用的工具名。
    bool mcpFace = false,
  }) async {
    final task = await runtime.get(taskId);
    if (task == null) {
      return ToolEnvelope.failure(
        tool: tool,
        code: 'NO_TASK',
        message: '任务不存在，无法执行工具',
      );
    }

    // 1) 权限（§18.3）
    // 装机授权挂在参数上（run_task_command install=true / apk_sign install=true），
    // 所以必须把本次调用的 args 一起传进去，否则 allowInstall 永不命中。
    final denial = CapabilityManifest.denialReason(
      tool,
      task.contract.constraints,
      args: args,
    );
    if (denial != null) {
      await runtime.recordToolCall(
        taskId: taskId,
        tool: tool,
        arguments: args,
        cost: 0,
        ok: false,
        errorCode: 'PERMISSION_DENIED',
      );
      await _audit(
        task: task,
        tool: tool,
        args: args,
        allowed: false,
        result: 'denied',
        failureReason: denial,
        authorization: CapabilityManifest.highRisk[tool] ?? 'none',
      );
      // 拒绝是用户/策略的授权决策，不是工具故障：不写失败记忆、不挂
      // 恢复方案（2026-09-15 用户点名「被拒绝的时候也会被归类为错误」）。
      // 指引里的工具名必须是该面真实可调用的（第 62 项）：agent 面是
      // ask_user_input_v0；MCP 面没有询问工具，就不点名工具、只说明要用户确认。
      final confirmTool = RecoveryEngine.faceName(
        'request_confirmation',
        mcp: mcpFace,
      );
      return ToolEnvelope.failure(
        tool: tool,
        code: 'PERMISSION_DENIED',
        message: confirmTool == null
            ? '$denial\n（这是授权决策，不是工具执行故障；请让用户确认后再试，勿直接重试）'
            : '$denial\n（这是授权决策，不是工具执行故障；'
                  '如需继续请走 $confirmTool，勿直接重试）',
        suggestedActions: confirmTool == null
            ? const <String>[]
            : <String>[confirmTool],
      );
    }

    // 2) 预算（§12.3）
    if (task.budget.exhausted) {
      final env = ToolEnvelope.failure(
        tool: tool,
        code: 'BUDGET_EXHAUSTED',
        message: '任务预算已用尽（工具 ${task.budget.usedToolCalls}/'
            '${task.budget.maxToolCalls}，成本 ${task.budget.usedCost}/'
            '${task.budget.maxCost}）',
      );
      return _attachRecovery(env, task: task, tool: tool, args: args, mcpFace: mcpFace);
    }

    // 3) 执行 + 计时
    final sw = Stopwatch()..start();
    String raw;
    try {
      raw = await run();
    } on TimeoutException {
      // 超时 ≠ 工具失败：MethodChannel 的等待里混着重型任务排队时间，
      // 原生任务大概率仍在跑（2026-09-15 用户点名「排队中被归类为错误」）。
      // 不进失败记忆、不给恢复方案，只提示稍后重试。
      sw.stop();
      await runtime.recordToolCall(
        taskId: taskId,
        tool: tool,
        arguments: args,
        cost: 0,
        ok: false,
        errorCode: 'TOOL_BUSY_TIMEOUT',
        // 超时本身就是"耗时长"的证据，必须入账（2026-09-16）：少了它，
        // 慢工具在耗时统计里反而看不到——最该被抓出来的那类恰好被漏掉。
        extra: {'durationMs': sw.elapsedMilliseconds},
      );
      return ToolEnvelope.failure(
        tool: tool,
        code: 'TOOL_BUSY_TIMEOUT',
        message: '工具未在时限内完成：可能在重型任务队列中排队等待，'
            '也可能执行耗时较长。这不是执行故障，原生任务仍在继续；'
            '稍候片刻后可用相同参数重试。',
        retryable: true,
        meta: ToolMeta(durationMs: sw.elapsedMilliseconds),
      );
    } catch (e) {
      sw.stop();
      await runtime.recordToolCall(
        taskId: taskId,
        tool: tool,
        arguments: args,
        cost: 0,
        ok: false,
        errorCode: 'TOOL_EXCEPTION',
        extra: {'durationMs': sw.elapsedMilliseconds},
      );
      final failure = ToolEnvelope.failure(
        tool: tool,
        code: 'TOOL_EXCEPTION',
        message: '$e',
        retryable: true,
        meta: ToolMeta(durationMs: sw.elapsedMilliseconds),
      );
      return _attachRecovery(failure, task: task, tool: tool, args: args, mcpFace: mcpFace);
    }
    sw.stop();

    // 4) 归一（§8.1）
    final cost = CapabilityManifest.costOf(tool);
    var env = normalize(raw, tool: tool).copyWithMeta(
          ToolMeta(
            durationMs: sw.elapsedMilliseconds,
            cost: cost,
          ),
        );

    // 多 DEX 范围契约（§7.7）：补上「搜了几个 / 总共几个」。
    // 空结果且范围不完整时会被降级为 partial，避免把「没搜完」当「没有」。
    final knownTotal = await runtime.knownDexCount(taskId);
    env = MultiDexGuard.apply(env, tool: tool, knownTotalDex: knownTotal);
    final searchedDex = MultiDexGuard.searchedOf(env.data);
    if (searchedDex != null) await runtime.noteDexCount(taskId, searchedDex);

    // 记账（§25 指标要能算出来，所以范围与截断标记一并落进事件）。
    // 耗时同样入账（2026-09-16 审核）：`sw` 一直在计时并塞进 ToolMeta，但从不落
    // 事件流——于是「哪个工具慢、慢在哪一步」在数据里查不到，只能靠体感猜。
    // 这是纯增量字段，旧记录读回时缺键即为 0，不破坏既有格式。
    final invocationId = await runtime.recordToolCall(
      taskId: taskId,
      tool: tool,
      arguments: args,
      cost: cost,
      ok: true,
      extra: {
        if (env.meta.queryScope.isNotEmpty) 'queryScope': env.meta.queryScope,
        'truncated': env.truncated,
        'durationMs': sw.elapsedMilliseconds,
      },
    );
    env = _withInvocation(env, invocationId);

    // 5) 证据（§11.6）：命中定位类工具时登记
    if (env.ok) {
      if (AuditLog.needsAudit(tool)) {
        await _audit(
          task: task,
          tool: tool,
          args: args,
          allowed: true,
          result: env.summary.isEmpty ? 'ok' : env.summary,
          authorization: CapabilityManifest.highRisk[tool] ?? 'mcp_enabled',
        );
      }
      // 产物登记（§16.2）：改包/签名/构建产出的 APK 自动入册并记血缘。
      if (ArtifactStore.producingTools.contains(tool)) {
        await _registerArtifacts(taskId: task.id, tool: tool, env: env);
      }
      final ev = await _maybeRecordEvidence(
        taskId: taskId,
        tool: tool,
        args: args,
        env: env,
        invocationId: invocationId,
      );
      if (ev != null) {
        env = _withEvidence(env, ev.id);
      }
    } else {
      env = await _attachRecovery(env, task: task, tool: tool, args: args, mcpFace: mcpFace);
    }
    return env;
  }

  /// 失败时：分类 → 给恢复方案 → 写失败记忆（§17.1 六步里的第 1、4、5、6 步）。
  ///
  /// 只收真正的执行故障（工具抛异常、结果异常等）。权限拒绝与排队超时
  /// 是决策/等待，不是故障，不走这里（2026-09-15 用户点名「排队中或被
  /// 拒绝时也被归类为错误」）。
  Future<ToolEnvelope> _attachRecovery(
    ToolEnvelope env, {
    required Task task,
    required String tool,
    Map<String, dynamic> args = const {},
    bool mcpFace = false,
  }) async {
    final plan = RecoveryEngine.fromEnvelope(
      env,
      task: task,
      tool: tool,
      args: args,
    );
    final actions = RecoveryEngine.actionsForFace(
      RecoveryEngine.filterByPhase(plan.nextActions, task.phase),
      mcp: mcpFace,
    );
    await _rememberFailure(
      task: task,
      tool: tool,
      pattern: plan.pattern,
      lesson: plan.lesson,
      // 错误正文一起落库（2026-09-14 真机反馈「错误是什么，我看不见」）：
      // 此前只记分类标签与教训，诊断页看不到到底报了什么错。
      errorCode: env.errors.isEmpty ? '' : env.errors.first.code,
      errorMessage:
          env.errors.isEmpty ? env.summary : env.errors.first.message,
      retryable: env.errors.isNotEmpty && env.errors.first.retryable,
    );
    // request_confirmation 在 agent 面要写真实工具名（ask_user_input_v0），
    // MCP 面没有等价的询问工具 → faceName 返回 null，这里就不追加（第 62 项）。
    final confirmTool = RecoveryEngine.faceName(
      'request_confirmation',
      mcp: mcpFace,
    );
    return env.withNextActions([
      for (final a in actions)
        ToolNextAction(
          action: a,
          reason: plan.strategy,
          arguments: plan.arguments[a],
        ),
      if (plan.requiresUser && confirmTool != null && !actions.contains(confirmTool))
        ToolNextAction(
          action: confirmTool,
          reason: '需要用户介入：${plan.strategy}',
        ),
    ]);
  }

  /// 写失败记忆，带 10 分钟去重（同一任务 + 同一工具 + 同一模式不重复记）。
  Future<void> _rememberFailure({
    required Task task,
    required String tool,
    required String pattern,
    required String lesson,
    String errorCode = '',
    String errorMessage = '',
    bool retryable = false,
  }) async {
    const dedupeWindowMs = 10 * 60 * 1000;
    final now = DateTime.now().millisecondsSinceEpoch;
    try {
      final existing = await runtime.failures.lookup(
        taskId: task.id,
        now: now,
        pattern: pattern,
      );
      final duplicate = existing.any((r) =>
          r.operation == tool && now - r.createdAt < dedupeWindowMs);
      if (duplicate) return;
      await runtime.failures.recordFailure(
        id: 'fail_${now}_${tool.hashCode.abs()}',
        taskId: task.id,
        pattern: pattern,
        now: now,
        phase: task.phase.id,
        operation: tool,
        lesson: lesson,
        scope: FailureScope.tool,
        evidence: {
          'apk': p.basename(task.contract.inputApk),
          if (errorCode.isNotEmpty) 'errorCode': errorCode,
          if (errorMessage.isNotEmpty) 'error': _clipError(errorMessage, 600),
          'retryable': retryable,
        },
      );
      // 失败一落库也通知：诊断分区/状态条能立刻看到（不必等工具收尾）。
      onRuntimeWrite?.call();
    } catch (_) {
      // 失败记忆写不进去不能影响工具结果本身
    }
  }

  static String _clipError(String text, int max) =>
      text.length <= max ? text : '${text.substring(0, max)}…';

  /// 写审计（§18.4）。高风险操作必须留痕，且失败也要记。
  /// 把工具产出的 APK 登记为产物（路径不存在则跳过，不造假记录）。
  Future<void> _registerArtifacts({
    required String taskId,
    required String tool,
    required ToolEnvelope env,
  }) async {
    try {
      final paths = ArtifactStore.extractApkPaths(env.data);
      for (final path in paths) {
        await runtime.artifacts.register(
          taskId: taskId,
          kind: ArtifactStore.kindForTool(tool),
          path: path,
        );
      }
    } catch (_) {
      // 登记失败不影响工具结果本身
    }
  }

  Future<void> _audit({
    required Task task,
    required String tool,
    required Map<String, dynamic> args,
    required bool allowed,
    required String result,
    required String authorization,
    String failureReason = '',
  }) async {
    try {
      final root = await runtime.store.root();
      final log = AuditLog(File(p.join(root.path, 'audit', 'audit.jsonl')));
      final now = DateTime.now().millisecondsSinceEpoch;
      await log.append(AuditRecord(
        id: 'aud_${now}_${tool.hashCode.abs()}',
        taskId: task.id,
        operation: tool,
        target: (args['path'] ?? args['target'] ?? '').toString(),
        authorization: authorization,
        allowed: allowed,
        result: result,
        failureReason: failureReason,
        createdAt: now,
      ));
    } catch (_) {
      // 审计失败不影响主流程
    }
  }

  // ------------------------------------------------------------ 结果归一

  /// 把工具返回的原始文本归一成信封。
  ///
  /// 兼容三类现状：
  /// - 标准对象 `{ok, message, ...}`（自研工具多数如此）；
  /// - 带 `error` 字段的失败对象（旧格式，error 可能是字符串或对象）；
  /// - 纯文本（如 web_search 返回的可读文本）。
  static ToolEnvelope normalize(String raw, {required String tool}) {
    final text = raw.trim();
    if (text.isEmpty) {
      return ToolEnvelope.success(tool: tool, summary: '（空结果）');
    }

    Object? decoded;
    try {
      decoded = jsonDecode(text);
    } catch (_) {
      // 不是 JSON：当成可读文本
      return ToolEnvelope.success(
        tool: tool,
        summary: _clip(text, 200),
        data: {'text': text},
      );
    }
    if (decoded is! Map) {
      return ToolEnvelope.success(
        tool: tool,
        summary: _clip(text, 200),
        data: {'value': decoded},
      );
    }

    final map = Map<String, Object?>.from(decoded);
    final rawError = map['error'];
    final ok = map['ok'] == true || (map['ok'] == null && rawError == null);

    // 失败：抽结构化错误
    if (!ok) {
      final err = _parseError(rawError, map['message']);
      return ToolEnvelope(
        ok: false,
        status: ToolStatus.error,
        tool: tool,
        summary: err.message,
        warnings: _stringList(map['warnings']),
        errors: [err],
      );
    }

    // 成功：summary 优先取 message，data 放其余字段。
    //
    // 注意：只有**字符串** summary 才是「标题」；`field_xref` 这类工具的
    // summary 是一个含统计信息的对象（dexCount/totalRefs…），必须留在 data 里，
    // 否则多 DEX 覆盖范围判断就瞎了。
    final rawSummary = map['summary'];
    final summary = (map['message'] ??
            (rawSummary is String ? rawSummary : null))
        ?.toString() ??
        '';
    final data = <String, Object?>{};
    for (final e in map.entries) {
      const meta = {'ok', 'message', 'error', 'warnings'};
      if (meta.contains(e.key)) continue;
      if (e.key == 'summary' && e.value is String) continue;
      data[e.key] = e.value;
    }

    final truncated = map['truncated'] == true ||
        map['hasMore'] == true ||
        map['more'] == true;
    final continuation = ToolContinuation.fromJson(map['continuation']) ??
        _continuationFromCursor(map);

    return ToolEnvelope(
      ok: true,
      status: truncated ? ToolStatus.partial : ToolStatus.success,
      tool: tool,
      summary: summary.isNotEmpty ? summary : _summarize(data),
      data: data,
      warnings: _stringList(map['warnings']),
      truncated: truncated,
      continuation: continuation,
      meta: ToolMeta(queryScope: _queryScope(map)),
    );
  }

  static ToolError _parseError(Object? rawError, Object? message) {
    if (rawError is Map) {
      return ToolError.fromJson(rawError);
    }
    final code = rawError?.toString() ?? 'tool_error';
    final msg = (message ?? rawError)?.toString() ?? '工具执行失败';
    return ToolError(code: code, message: msg, retryable: false);
  }

  /// 旧工具的 cursor/nextCursor 字段兜底成续读信息。
  static ToolContinuation? _continuationFromCursor(Map<String, Object?> map) {
    for (final key in const ['nextCursor', 'cursor', 'pageToken']) {
      final v = map[key]?.toString();
      if (v != null && v.isNotEmpty) {
        return ToolContinuation(type: 'cursor', token: v);
      }
    }
    return null;
  }

  /// 多 DEX 查询范围（§7.7）——避免「没找到」其实是没搜完。
  static Map<String, Object?> _queryScope(Map<String, Object?> map) {
    for (final key in const ['queryScope', 'searchScope', 'scope']) {
      final v = map[key];
      if (v is Map) return Map<String, Object?>.from(v);
      if (v is String && v.isNotEmpty) return {'queryScope': v};
    }
    return const {};
  }

  static List<String> _stringList(Object? raw) => [
        for (final x in (raw as List? ?? const [])) x.toString(),
      ];

  /// 没给 message 时，用 data 的规模凑一句摘要。
  static String _summarize(Map<String, Object?> data) {
    for (final key in const ['count', 'total', 'hitCount', 'size']) {
      final v = data[key];
      if (v is num) return '$key=$v';
    }
    if (data.isEmpty) return '（无数据）';
    return data.keys.take(4).join(', ');
  }

  static String _clip(String s, int max) =>
      s.length <= max ? s : '${s.substring(0, max)}…';

  // ------------------------------------------------------------ 证据登记

  /// 工具 → 证据类型/等级的映射（§11.3）。
  ///
  /// 只给**确定能产生事实**的工具登记，避免造出一堆噪声证据。
  /// - 搜索/结构类：Candidate（字符串命中、命名相关，不能算定位）
  /// - 交叉引用/方法体/SO 类：Observed（真实的读写点、调用关系、分支）
  ///
  /// analyzer.* 四个高阶入口不在这张表里：它们的载荷结构与原子工具不同
  /// （stop_reason 语义闸门 + primary_candidates），走 [_analyzerEvidenceFor]。
  static const Map<String, (String, EvidenceLevel)> _evidenceMap = {
    'dex_search': (EvidenceKindString.search, EvidenceLevel.candidate),
    'string_scan': (EvidenceKindString.search, EvidenceLevel.candidate),
    'class_outline': (EvidenceKindString.structure, EvidenceLevel.candidate),
    'jadx_decompile': (EvidenceKindString.methodBody, EvidenceLevel.observed),
    'smali_read': (EvidenceKindString.methodBody, EvidenceLevel.observed),
    'dex_xref': (EvidenceKindString.xref, EvidenceLevel.observed),
    'field_xref': (EvidenceKindString.fieldUsage, EvidenceLevel.observed),
    'so_analyze': (EvidenceKindString.observed, EvidenceLevel.observed),
  };

  /// analyzer.* 高阶入口的证据映射（2026-09-15 复核补）。
  ///
  /// 这是**主力定位路径**：模型走 analyzer_global_search /
  /// analyzer_find_field_usage 拿到的 locator 才是后面 patch 的依据，但此前
  /// 证据登记只认 dex_*/so_* 等原子工具名 → 状态条「证据」档与弹层证据分区
  /// 恒空（用户真机反馈「弹窗里没有数据」）。两种拼写都要认：运行时看到的是
  /// 内部名（点号），声明层/提示词里是发布名（下划线）。
  ///
  /// 空手而归的结果**不登记**：stop_reason 是结果自带的语义闸门（no_hit /
  /// no_refs / unbound），登记了就是在台账里造假证据。
  static (String, EvidenceLevel)? _analyzerEvidenceFor(
    String tool,
    Map<String, Object?> data,
  ) {
    final stop = (data['stop_reason'] ?? data['stopReason'] ?? '').toString();
    switch (tool) {
      case 'analyzer.global_search':
      case 'analyzer_global_search':
        // 搜索命中只是候选（字符串/命名相关），不是定位。
        if (stop != 'hits') return null;
        return (EvidenceKindString.search, EvidenceLevel.candidate);
      case 'analyzer.find_field_usage':
      case 'analyzer_find_field_usage':
      case 'analyzer.analyze_business_state':
      case 'analyzer_analyze_business_state':
        // 字段 READ/WRITE 消费点是真实关系（与 field_xref 同档）。
        if (stop == 'writer_confirmed' ||
            stop == 'read_only' ||
            stop == 'read_only_field') {
          return (EvidenceKindString.fieldUsage, EvidenceLevel.observed);
        }
        return null;
      default:
        return null;
    }
  }

  Future<Evidence?> _maybeRecordEvidence({
    required String taskId,
    required String tool,
    required Map<String, dynamic> args,
    required ToolEnvelope env,
    required String invocationId,
  }) async {
    final analyzer = _analyzerEvidenceFor(tool, env.data);
    final mapped = _evidenceMap[tool] ?? analyzer;
    if (mapped == null) return null;

    // 空结果的搜索类工具不能登记证据：claim 会写成「命中 X」，
    // 但实际一条都没找到。宁可没有证据，也不要造一条假证据。
    if (MultiDexGuard.dexTools.contains(tool) &&
        MultiDexGuard.hitsOf(env.data) == 0) {
      return null;
    }

    final target = _targetOf(args);
    final where = _whereOf(args);
    final claim = analyzer != null
        ? _analyzerClaim(env)
        : _claimOf(tool, args, env.data, target, where);

    final evidence = await runtime.addEvidence(
      taskId: taskId,
      claim: claim,
      type: mapped.$1,
      level: mapped.$2,
      source: EvidenceSource(
        artifact: _artifactOf(args),
        className: args['className']?.toString(),
        method: args['method']?.toString(),
        location:
            (args['qualifiedId'] ?? args['fieldLocator'])?.toString(),
      ),
      rawRef: {
        'kind': 'tool',
        'tool': tool,
        'args': args,
      },
      relations: [
        if (target.isNotEmpty)
          {'type': 'about', 'target': target},
      ],
      toolCallId: invocationId,
    );
    // 证据一落库就通知界面：这是「工具还在跑、状态条已经能看到新证据」的关键
    // 一环（此前只在工具收尾 bump 一次，长工具期间看不到任何进展）。
    onRuntimeWrite?.call();
    return evidence;
  }

  /// analyzer.* 的 claim：结果自带的 summary 本就是事实句（「命中 N 个方法」/
  /// 「字段 X 的权威写入方是 Y」），再附前两条候选 locator——「命中了什么、
  /// 在哪」比「调用了什么」有用（与 [_claimOf] 同一口径）。
  static String _analyzerClaim(ToolEnvelope env) {
    final base = env.summary.trim();
    final samples = _analyzerLocators(env.data);
    if (samples.isEmpty) {
      return base.isEmpty ? 'analyzer 返回了可核对的事实' : _clip(base, 180);
    }
    final body = samples.join('、');
    return _clip(base.isEmpty ? body : '$base（$body）', 180);
  }

  /// 从 analyzer 载荷里取前两条候选定位（primary_candidates，其次
  /// evidence_graph 的 matches/evidence）。
  static List<String> _analyzerLocators(Map<String, Object?> data) {
    final out = <String>[];
    void harvest(Object? raw) {
      if (raw is! List) return;
      for (final item in raw) {
        if (out.length >= 2) return;
        if (item is String) {
          final s = item.trim();
          if (s.isNotEmpty) out.add(s);
          continue;
        }
        if (item is Map) {
          for (final k in const ['locator', 'methodLocator', 'method']) {
            final v = item[k]?.toString().trim();
            if (v != null && v.isNotEmpty) {
              out.add(v);
              break;
            }
          }
        }
      }
    }

    harvest(data['primary_candidates']);
    if (out.isEmpty) {
      final graph = data['evidence_graph'];
      if (graph is Map) {
        final m = Map<String, Object?>.from(graph);
        harvest(m['matches']);
        harvest(m['evidence']);
      }
    }
    return [for (final s in out) _clip(s, 80)];
  }

  /// 位置短语：`类.方法（产物）`，让证据一眼看出"在哪"。
  static String _whereOf(Map<String, dynamic> args) {
    final cls = args['className']?.toString() ?? '';
    final m = args['method']?.toString() ?? '';
    final loc = args['qualifiedId']?.toString() ?? '';
    final member = [
      if (m.isNotEmpty) m else if (loc.isNotEmpty) loc,
    ].join();
    final where = [
      if (cls.isNotEmpty) '$cls${member.isNotEmpty ? '.$member' : ''}'
      else if (member.isNotEmpty) member,
    ].join();
    final artifact = _artifactOf(args);
    if (where.isEmpty && artifact.isEmpty) return '';
    if (where.isEmpty) return artifact;
    return artifact.isEmpty ? where : '$where@$artifact';
  }

  /// claim 要写**事实结论**，不是「调用了什么」（2026-09-15 用户点名：
  /// 证据列表不能全是"xx_search 命中 xx"这种流水账）。优先从返回数据里
  /// 取命中内容样本（具体字符串/方法/调用关系），写成可直接读的一句话。
  static String _claimOf(
    String tool,
    Map<String, dynamic> args,
    Map<String, Object?> data,
    String target,
    String where,
  ) {
    final samples = _hitSamples(data);
    // hitsOf 是通用计数（count/total/matches/… 再退到列表长度），不按 dexTools
    // 分叉：分叉让非 dex 的 so_analyze 恒得 0，于是把样本条数当成命中总数写进
    // 证据台账（「A、B 共 2 处」而实际几十处）。计数不比样本多时不写这个子句
    // ——数字要么是事实，要么就别写。
    final count = MultiDexGuard.hitsOf(data);
    final tail = where.isEmpty ? '' : '（$where）';
    if (samples.isNotEmpty) {
      final more = count > samples.length;
      final body = more ? '${samples.join('、')} 等' : samples.join('、');
      final total = more ? ' 共 $count 处' : '';
      return _clip('$body$total$tail', 180);
    }
    if (target.isNotEmpty) return _clip('命中「$target」$tail', 180);
    return '$tool 返回了可核对的事实';
  }

  /// 从返回数据取前 2 个命中样本。不同工具的列表字段名不一致，按常见
  /// 命名猜一轮；嵌套在 summary 里的再下钻一层。
  static List<String> _hitSamples(Map<String, Object?> data) {
    for (final key in const [
      'matches',
      'hits',
      'results',
      'refs',
      'xrefs',
      'candidates',
      'items',
      'classes',
      'methods',
    ]) {
      final v = data[key];
      if (v is List && v.isNotEmpty) {
        return v
            .take(2)
            .map(_hitSummary)
            .where((s) => s.isNotEmpty)
            .toList();
      }
    }
    final nested = data['summary'];
    if (nested is Map) {
      return _hitSamples(Map<String, Object?>.from(nested));
    }
    return const [];
  }

  static String _hitSummary(Object? item) {
    if (item is String) return _clip(item, 60);
    if (item is Map) {
      final m = Map<String, Object?>.from(item);
      for (final key in const [
        'value',
        'string',
        'text',
        'method',
        'to',
        'from',
        'target',
        'name',
        'className',
        'class',
      ]) {
        final v = m[key]?.toString();
        if (v != null && v.isNotEmpty) return _clip(v, 60);
      }
    }
    return '';
  }

  static String _targetOf(Map<String, dynamic> args) {
    for (final key in const [
      'target',
      'keyword',
      'className',
      'qualifiedId',
      'fieldTarget',
      // analyzer 入口的参数名（2026-09-15 复核）：字段定位/业务关键词，
      // 缺了它们 analyzer 证据的 relations 里就没有「关于什么」。
      'fieldLocator',
      'targetKeyword',
      'locator',
      'query',
    ]) {
      final v = args[key]?.toString().trim();
      if (v != null && v.isNotEmpty) return v;
    }
    return '';
  }

  static String _artifactOf(Map<String, dynamic> args) {
    // analyzer 入口不传 path（它绑的是已打开的 APK），补给证据来源一个
    // 可读的产物名——否则证据行的「在哪」少一半。
    final raw = (args['path'] ?? args['apkPath'])?.toString().trim() ?? '';
    return raw.isEmpty ? '' : p.basename(raw);
  }

  static ToolEnvelope _withInvocation(ToolEnvelope e, String invocationId) =>
      ToolEnvelope(
        ok: e.ok,
        status: e.status,
        tool: e.tool,
        invocationId: invocationId,
        requestId: e.requestId,
        summary: e.summary,
        data: e.data,
        evidenceIds: e.evidenceIds,
        artifacts: e.artifacts,
        warnings: e.warnings,
        errors: e.errors,
        truncated: e.truncated,
        continuation: e.continuation,
        nextActions: e.nextActions,
        meta: e.meta,
      );

  static ToolEnvelope _withEvidence(ToolEnvelope e, String evidenceId) =>
      ToolEnvelope(
        ok: e.ok,
        status: e.status,
        tool: e.tool,
        invocationId: e.invocationId,
        requestId: e.requestId,
        summary: e.summary,
        data: e.data,
        evidenceIds: [...e.evidenceIds, evidenceId],
        artifacts: e.artifacts,
        warnings: e.warnings,
        errors: e.errors,
        truncated: e.truncated,
        continuation: e.continuation,
        nextActions: e.nextActions,
        meta: e.meta,
      );
}

/// 证据类型常量（避免和 [EvidenceKind] 的枚举标签混淆）。
class EvidenceKindString {
  EvidenceKindString._();

  static const search = 'STRING';
  static const structure = 'STRUCTURE';
  static const methodBody = 'METHOD_BODY';
  static const xref = 'XREF';
  static const fieldUsage = 'FIELD_USAGE';
  static const observed = 'OBSERVED';
}
