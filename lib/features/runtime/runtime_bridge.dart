import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../chat/runtime_tools.dart';
import '../solab_apk/services/apk_workspace_binding_service.dart';
import 'model_gateway.dart';
import 'models/task.dart';
import 'models/tool_result.dart';
import 'task_runtime.dart';
import 'task_session.dart';
import 'tool_bridge.dart';

/// 把 SoLab 运行时层接到工作台的工具执行链上。
///
/// 接入点只有一个：工具执行的外层。包一层之后，每次工具调用都会留下
/// 统一信封、证据登记、预算记账和审计记录，业务实现一行不用改。
///
/// 两条纪律：
/// - **首任务纪律（§5.5）**：没选定 APK 时不建任务，保持工作台原行为。
/// - **零影响纪律**：运行时层不可用或自身出错时（存储未初始化、插件缺失、
///   状态机拒绝），一律退化为裸执行，绝不改变工具本身的结果，也绝不
///   重复执行工具。
class RuntimeBridge {
  /// [runtimeOverride] 供测试注入隔离的 TaskStore（默认走 AppData 持久化）。
  RuntimeBridge({TaskRuntime? runtimeOverride})
    : runtime = runtimeOverride ?? TaskRuntime();

  static final RuntimeBridge instance = RuntimeBridge();

  final TaskRuntime runtime;
  late final TaskSession session = TaskSession(runtime);
  late final ToolBridge bridge = ToolBridge(runtime, onRuntimeWrite: bumpRevision);

  /// 当前正在执行的工具名（null = 空闲）。
  ///
  /// 状态条靠它把「工具已开始」立刻反映出来：此前只有工具收尾才 bumpRevision，
  /// 长工具（blutter analyze、全量扫描）跑着的几分钟里状态条一动不动，看起来
  /// 像卡死（2026-09-15 用户点名「刷新及时一点」）。
  final ValueNotifier<String?> activeTool = ValueNotifier<String?>(null);

  /// 本次工具执行期间乐观点亮的档位（0 分析/1 证据/2 修改/3 预览/4 成品；
  /// -1 = 不抢灯）。
  ///
  /// 为什么在桥里算而不是界面里：判定要看**这次调用的参数**（write 工具带
  /// dryRun=true 的纯预演不落地、不抢灯），而工具名与参数只在 [wrapOrRun]
  /// 这一处同时可见（2026-09-15 用户点名「修改的时候没有跳到相应档位」）。
  final ValueNotifier<int> executingStage = ValueNotifier<int>(-1);

  /// 最近一次工具调用后的任务快照。系统提示是同步组装的，缓存一份供它取用。
  Map<String, Object?>? _lastSnapshot;

  /// 运行时数据版本号：每次工具调用收尾 +1。
  ///
  /// 对话页的状态条、运行时弹层、设置里的五个页面都监听它自动刷新——
  /// 之前页面只在 initState 读一次，工具跑完了页面还是旧数据（真机反馈）。
  final ValueNotifier<int> revision = ValueNotifier<int>(0);

  /// 主动通知界面刷新（任务被删除、预算被改这类不在工具调用里的变化）。
  void bumpRevision() {
    revision.value++;
  }

  /// 当前作用域的任务（选定 APK 后建立，跨会话复用）。
  ///
  /// 绑定优先级：**本次工具调用指定的 APK** > 工作台记录的当前 APK。
  ///
  /// 为什么以工具参数为准：工作台里记的 activeApkPath 可能是早就被移走/删除
  /// 的旧包（实测：界面因此一直显示一个不存在的包，跟当前正在分析的 APK 对
  /// 不上）。工具实际处理哪个包，任务就该记哪个包。
  Future<Task?> ensureTaskForActiveApk({
    String? scopeKey,
    String? goal,
    String? apkPath,
    bool allowExternalMcp = false,
  }) async {
    var target = (apkPath ?? '').trim();
    // 任务目标必须是 APK（2026-09-14 审核修复）：file/so_analyze 等工具的
    // path 参数是任意工作文件（.md/.so/.json，so_analyze 还有 apk: 内部格式），
    // 拿它当任务目标时 _sameApk/sameLifecycle 都判否 → 每次非 APK 工具调用
    // 都「换目标」→ 解绑重建任务反复横跳，血缘归并被绕过。非 .apk 路径
    // 不作为任务目标，回退工作台记录的当前 APK。
    if (!_isApkTarget(target)) target = '';
    if (target.isEmpty || !_exists(target)) {
      final bound = await ApkWorkspaceBindingService.activeApkPath();
      final boundApk = (bound ?? '').trim();
      target = _isApkTarget(boundApk) ? boundApk : '';
    }
    if (target.isEmpty) return null;
    // 绑定目标必须真实存在：不存在的包不建任务，避免页面拿幻影数据当真。
    if (!_exists(target)) return null;
    final workDir = await ApkWorkspaceBindingService.workDir();
    return session.ensureTask(
      scopeKey: scopeKey ?? 'workbench',
      goal: goal ?? '分析并按要求处理当前 APK',
      apkPath: target,
      workDir: workDir,
      // 血缘归并（2026-09-14「一个 APP 几十份报告」）：同一产物链上的
      // 派生包（去签/中间/成品/签名）不算换目标，复用同一条任务。
      sameLifecycle: ApkWorkspaceBindingService.sameLifecycle,
      constraints: TaskConstraints(
        preserveOriginal: true,
        allowModification: true,
        allowSigning: true,
        allowInstall: false,
        allowFrida: false,
        allowMemoryDump: false,
        allowRuntimeDexDump: false,
        allowDeviceDebug: false,
        allowExternalMcp: allowExternalMcp,
      ),
    );
  }

  /// 预算是「段」不是「墙」（2026-09-13 互斥双模复查；2026-09-14 体积治理修正）。
  ///
  /// TaskBudget 按（作用域，APK）复用并持久化：agent 侧随新会话自然轮换，
  /// 但 MCP host 固定 `mcp-host` 单作用域——同一 APK 上累计 200 次调用即
  /// 永久 BUDGET_EXHAUSTED。这里**在原任务上重置预算段**继续执行。
  ///
  /// 初版实现是「解绑重建新任务」，2026-09-14 实测发现代价巨大：
  /// createTask 会调 workspace.prepare() 复制一份全量 APK 到新工作区，
  /// 预算每耗尽一次就多一份 G 级副本（app_flutter 6.75GB 事故的放大器）。
  /// 重置同任务预算即达成「继续执行」目标，零字节开销。
  /// 失控仍有 ToolCallLoopGuard（主链路/子代理/MCP 三面各持自己的窗口）与
  /// ApkAnalysisGuard（agent 侧；子代理与主对话共享同一份会话预算，2026-09-28
  /// 审核 P2-5 修好了子代理直进咽喉绕过两道闸门的问题）兜底。
  Future<Task> _rotateExhaustedTask(
    Task task, {
    required String? scopeKey,
    String? goal,
    String? apkPath,
    bool allowExternalMcp = false,
  }) async {
    try {
      final reset = task.copyWith(
        budget: TaskBudget(
          maxToolCalls: task.budget.maxToolCalls,
          maxCost: task.budget.maxCost,
        ),
        updatedAt: DateTime.now().millisecondsSinceEpoch,
      );
      await runtime.store.save(reset);
      return reset;
    } catch (_) {
      return task;
    }
  }

  /// 启动期回收无主工作区（2026-09-14 体积治理）：任务记录保留，仅清
  /// 无人绑定的工作区目录（含全量 input APK 副本）。失败静默。
  Future<int> pruneOrphanWorkspaces() async {
    try {
      final bound = await session.boundTaskIds();
      final report = await runtime.workspace.pruneOrphanWorkspaces(
        boundTaskIds: bound,
        now: DateTime.now().millisecondsSinceEpoch,
      );
      return report.freedBytes;
    } catch (_) {
      return 0;
    }
  }

  /// 启动期回收超量的**历史任务记录**（2026-09-14「一个 APP 几十份报告」）。
  ///
  /// 未绑定且超出保留量的旧任务（含 task.json、事件流、交付报告镜像、工作区）
  /// 一起删除。与工作区回收共用 [TaskSession.pruneGarbageOnce] 的串行闸门，
  /// 避免两个清理同时扫同一批目录。
  Future<int> pruneRuntimeGarbage() async {
    try {
      return await session.pruneGarbageOnce();
    } catch (_) {
      return 0;
    }
  }

  /// 同步判存，且**绝不用异步文件 API**。
  ///
  /// 为什么必须同步：这个判存落在工具执行的最外层，每一次工具调用都会走到。
  /// 用 `await File(path).exists()` 的话，在 `testWidgets` 的 fake-async 区里
  /// 这个真实 I/O 的 future 永远不会完成——测试会一路挂到 10 分钟超时
  /// （实测：`tool_handler_service_test` 的 write-back 用例，合并前 1 秒通过，
  /// 合并后挂死）。同步 `existsSync` 在同一个区里照常返回。
  ///
  /// 代价只是每次工具调用一次 stat，可忽略；相比"整个工具调用挂住"这是净赚。
  static bool _exists(String path) {
    if (path.isEmpty) return false;
    try {
      return File(path).existsSync();
    } catch (_) {
      return false;
    }
  }

  /// 任务目标必须是 APK 文件（file/so_analyze 的 path 是任意工作文件）。
  static bool _isApkTarget(String path) {
    final v = path.trim();
    return v.isNotEmpty && v.toLowerCase().endsWith('.apk');
  }

  /// 记一次模型调用用量（token）。
  ///
  /// 运行时账本此前从没被写入过——LLM 调用发生在对话层，运行时只管工具，
  /// 所以「模型用量」恒为 0。这里由对话收尾时回调，把真实 token 计进当前
  /// 任务；没有任务时静默跳过，绝不影响对话本身。
  Future<void> noteLlmUsage({
    required String conversationId,
    required int promptTokens,
    required int completionTokens,
    int cachedTokens = 0,
    String model = '',
    ModelTier? tier,
  }) async {
    if (promptTokens <= 0 && completionTokens <= 0) return;
    try {
      final task = await session.taskFor(conversationId);
      if (task == null) return;
      await runtime.usage.record(
        taskId: task.id,
        model: model,
        promptTokens: promptTokens,
        completionTokens: completionTokens,
        cachedTokens: cachedTokens,
        tier: tier ?? ModelRouting.tierForPhase(task.phase),
      );
    } catch (_) {
      // 记账失败不影响对话。
    }
  }

  /// 执行一次工具调用，并把它接进运行时。
  ///
  /// **保证 [run] 恰好执行一次**：运行时可用时由 [ToolBridge] 包着跑，
  /// 不可用时裸跑。返回工具结果的 JSON 文本，形态与工作台原有契约一致
  /// （扁平 payload），运行时信息作为附加键并入，不改变既有字段语义。
  Future<String?> wrapOrRun({
    required String tool,
    required Map<String, dynamic> args,
    required Future<String?> Function() run,
    String? scopeKey,
    String? goal,
    String? apkPath,
    bool allowExternalMcp = false,
  }) async {
    // 立刻对外声明「正在执行哪个工具」：长工具期间状态条至少能显示在跑什么，
    // 而不是几分钟一动不动（2026-09-15 用户点名「刷新及时一点」）。
    activeTool.value = tool;
    // 同一步把乐观档位算好（判定要看这次调用的参数，只有这里同时可见）。
    executingStage.value = TaskSession.executingStageFor(tool, args);
    try {
      return await _wrapOrRunInner(
        tool: tool,
        args: args,
        run: run,
        scopeKey: scopeKey,
        goal: goal,
        apkPath: apkPath,
        allowExternalMcp: allowExternalMcp,
      );
    } finally {
      // 只在「还是本次调用占着位」时才清：另一个工具已经接手的话，清掉会
      // 把它的执行中状态与乐观档位一起抹掉（MCP 面可能并发调工具）。
      if (activeTool.value == tool) {
        activeTool.value = null;
        executingStage.value = -1;
      }
    }
  }

  Future<String?> _wrapOrRunInner({
    required String tool,
    required Map<String, dynamic> args,
    required Future<String?> Function() run,
    String? scopeKey,
    String? goal,
    String? apkPath,
    bool allowExternalMcp = false,
  }) async {
    Task? task;
    try {
      task = await ensureTaskForActiveApk(
        scopeKey: scopeKey,
        goal: goal,
        apkPath: apkPath,
        allowExternalMcp: allowExternalMcp,
      );
      if (task != null && task.budget.exhausted) {
        task = await _rotateExhaustedTask(
          task,
          scopeKey: scopeKey,
          goal: goal,
          apkPath: apkPath,
          allowExternalMcp: allowExternalMcp,
        );
      }
    } catch (_) {
      // 偏好存储/插件不可用（如无插件的宿主）→ 不包装。
      task = null;
    }
    if (task == null) {
      try {
        return await run();
      } finally {
        bumpRevision();
      }
    }

    var ran = false;
    String? produced;
    try {
      final envelope = await bridge.invoke(
        taskId: task.id,
        tool: tool,
        args: args,
        mcpFace: allowExternalMcp,
        run: () async {
          ran = true;
          produced = await run();
          return produced ?? '';
        },
      );
      final latest = await runtime.get(task.id) ?? task;
      await _advanceAfter(
        latest,
        tool,
        envelope.ok,
        args: args,
        envelope: envelope,
        ran: ran,
      );
      _lastSnapshot = {
        'taskId': latest.id,
        'status': latest.status.label,
        'phase': latest.phase.label,
        'usedToolCalls': latest.budget.usedToolCalls,
        'remainingCalls': latest.budget.remainingCalls,
      };
      final text = produced;
      if (text == null) {
        // handler 抛异常（或本就没返回内容）：失败时把错误如实交回，
        // 不能因为「没有文本」就把失败吞成「工具未处理」。
        if (!envelope.ok) return _failurePayload(envelope);
        return null;
      }
      if (!envelope.ok) {
        // 失败：保留 handler 自己的 payload（含 error/message），只并入
        // 恢复建议，让模型看得见「下一步该做什么」。
        return _mergeNextActions(text, envelope);
      }
      return _flattenPayload(envelope, text);
    } catch (_) {
      // handler 已跑过就返回它的结果，绝不再跑第二次；没跑过才裸跑一次。
      if (ran) return produced;
      return run();
    } finally {
      bumpRevision();
    }
  }

  /// 系统提示用的运行时上下文（§6.5）：当前阶段 + 预算。
  /// 还没跑过工具（无任务）时返回 null，不注入任何东西。
  String? promptBlock() {
    final s = _lastSnapshot;
    if (s == null) return null;
    return '# Task runtime\n'
        '- current stage: ${s['status']} (${s['phase']})\n'
        '- tool calls used: ${s['usedToolCalls']}, remaining: ${s['remainingCalls']}\n'
        '- Tool results keep their original fields; the runtime only adds '
        '`truncated` (continue with `continuation` before concluding), '
        '`nextActions` (suggested next steps) and `evidenceIds` when present. '
        'Do not report build success as task success; report 未验证项 explicitly.';
  }

  /// 系统提示用的运行时上下文（§6.5）：当前阶段 + 预算。
  ///
  /// 状态机只允许逐格推进，所以这里按需补齐中间事件（改包类先补记
  /// 计划与预览通过事件），再一格一格走。守卫不通过不算错误——只说明
  /// 还没到那一步。工具名归一统一走 [TaskSession.advanceTargetFor]，
  /// 避免两套映射各自漂移。
  Future<void> _advanceAfter(
    Task task,
    String tool,
    bool ok, {
    required Map<String, dynamic> args,
    ToolEnvelope? envelope,
    bool ran = true,
  }) async {
    if (!ok || !ran) return;
    try {
      final data = envelope?.data ?? const <String, Object?>{};

      // 1) 已落地修改登记（修改预览页的数据源，也是状态机走到
      //    Planned/DryRunVerified 的依据）。覆盖全部真实写面，不再受
      //    「状态未过 DryRunVerified」封顶——幂等由（工具+目标+参数签名）
      //    去重保证（2026-09-14 真机反馈：此前只有第一次修改会登记）。
      if (TaskSession.isLandedWrite(tool, args, data: data)) {
        final cur = await runtime.get(task.id) ?? task;
        await RuntimeTools.recordLandedPatch(
          task: cur,
          runtime: runtime,
          tool: tool,
          args: args,
          data: data,
        );
      }

      // 2) 状态推进（只认能一次证明的推进；守卫不通过不是错误）。
      final target = TaskSession.advanceTargetFor(tool);
      if (target != null) await _advanceToward(task.id, target);

      // 3) 交付报告：签名成功即汇总（交付页的数据源）。除了 apk_sign，
      //    链式签名（如 so_patch_into_apk sign=true 产出 signedPath）同样
      //    产生成品，也算一次交付——此前只有 apk_sign 一条路，走链式签名
      //    的成品在交付页永远看不到（2026-09-14 真机反馈）。
      final signedPath = (data['signedPath'] ?? '').toString().trim();
      if (tool == 'apk_sign' || signedPath.isNotEmpty) {
        final cur = await runtime.get(task.id);
        if (cur != null) {
          await RuntimeTools.writeDeliveryReport(cur, runtime);
        }
      }
    } catch (_) {
      // 状态推进/报告生成失败不能影响工具结果本身。
    }
  }

  /// 逐格推进到 [target]：状态机禁止跳跃，中间格被守卫拒绝就停下。
  Future<void> _advanceToward(String taskId, TaskStatus target) async {
    final targetIndex = TaskStatus.linear.indexOf(target);
    if (targetIndex < 0) return;
    var cur = await runtime.get(taskId);
    while (cur != null) {
      final idx = cur.status.linearIndex;
      if (idx < 0 || idx >= targetIndex) return;
      if (idx + 1 >= TaskStatus.linear.length) return;
      final next = TaskStatus.linear[idx + 1];
      try {
        cur = await runtime.advance(taskId, next, reason: '工具执行成功，状态推进');
      } on AdvanceRejection {
        return; // 进入条件未满足：不是错误，只是还没到那一步
      }
    }
  }

  /// 成功结果：把运行时载荷摊平回调用方原有的扁平形态。
  ///
  /// `normalize` 已把业务字段收进 [ToolEnvelope.data]，这里以它为底、
  /// 只补齐缺失的运行时附加键，绝不覆盖业务已有字段。
  static String _flattenPayload(ToolEnvelope env, String raw) {
    // 非 JSON 对象（纯文本结果，如 web_search）保持原样，不加信封。
    if (!_isJsonObject(raw)) return raw;
    final base = <String, Object?>{...env.data};
    // normalize 把 payload 里的**字符串** summary 收进信封当"标题"（见
    // ToolEnvelope 的构造），但这里是回给调用方的出口——不收回来，调用方就
    // 永远看不到那句话。真机实测：analyzer_analyze_business_state 的结论句
    // （"未评估…，这不是字段不存在的证据"）就是这样消失的，模型只拿到
    // stop_reason/uncertainties，容易漏读语义。
    // 只在原 payload 本当有 summary 时补回，**不新增字段**（否则等于给所有
    // 工具凭空加一个字段，破坏既有响应形状）。
    if (!base.containsKey('summary')) {
      final restored = _payloadStringSummary(raw);
      if (restored != null) base['summary'] = restored;
    }
    base.putIfAbsent('ok', () => true);
    if (env.truncated) base.putIfAbsent('truncated', () => true);
    final cont = env.continuation;
    if (cont != null) base.putIfAbsent('continuation', () => cont.toJson());
    if (env.nextActions.isNotEmpty) {
      base.putIfAbsent(
        'nextActions',
        () => [for (final a in env.nextActions) a.toJson()],
      );
    }
    if (env.evidenceIds.isNotEmpty) {
      base.putIfAbsent('evidenceIds', () => env.evidenceIds);
    }
    if (env.invocationId.isNotEmpty) {
      base.putIfAbsent('runtimeInvocationId', () => env.invocationId);
    }
    return jsonEncode(base);
  }

  /// 失败结果：保留原 payload，只在缺少时补上恢复建议。
  static String _mergeNextActions(String raw, ToolEnvelope env) {
    if (!_isJsonObject(raw) || env.nextActions.isEmpty) return raw;
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return raw;
      final map = <String, Object?>{
        for (final e in decoded.entries) e.key.toString(): e.value,
      };
      map.putIfAbsent(
        'nextActions',
        () => [for (final a in env.nextActions) a.toJson()],
      );
      return jsonEncode(map);
    } catch (_) {
      return raw;
    }
  }

  /// handler 没有产出文本时的失败兜底：把信封里的错误变成结构化 payload。
  static String _failurePayload(ToolEnvelope env) {
    final err = env.errors.isNotEmpty ? env.errors.first : null;
    return jsonEncode(<String, Object?>{
      'error': err?.code ?? 'tool_error',
      'message': (err?.message.isNotEmpty ?? false)
          ? err!.message
          : (env.summary.isNotEmpty ? env.summary : '工具执行失败'),
      'recoverable': err?.retryable ?? true,
      if (env.nextActions.isNotEmpty)
        'nextActions': [for (final a in env.nextActions) a.toJson()],
    });
  }

  static bool _isJsonObject(String? s) {
    if (s == null) return false;
    final t = s.trim();
    if (!t.startsWith('{') || !t.endsWith('}')) return false;
    try {
      return jsonDecode(t) is Map;
    } catch (_) {
      return false;
    }
  }

  /// 原始 payload 里**字符串**形态的 summary（对象形态的 summary 本来就留在
  /// data 里，见 ToolEnvelope.normalize 的注释）；没有则 null。
  static String? _payloadStringSummary(String raw) {
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return null;
      final value = decoded['summary'];
      return value is String && value.trim().isNotEmpty ? value : null;
    } catch (_) {
      return null;
    }
  }

  /// 供契约测试直接验证出口形态（与 `classifySignatureSmaliForTest` 同款缝）。
  static String flattenPayloadForTest(ToolEnvelope env, String raw) =>
      _flattenPayload(env, raw);

  /// 当前任务（界面展示阶段/预算用）。
  Future<Task?> currentTask({String? scopeKey}) =>
      session.taskFor(scopeKey ?? 'workbench');

  /// 任务快照（阶段、预算、授权），给 UI 或 prompt 组装用。
  Future<Map<String, Object?>?> taskSnapshot({String? scopeKey}) async {
    final task = await currentTask(scopeKey: scopeKey);
    if (task == null) return null;
    return {
      'taskId': task.id,
      'goal': task.contract.goal,
      'status': task.status.label,
      'phase': task.phase.id,
      'usedToolCalls': task.budget.usedToolCalls,
      'maxToolCalls': task.budget.maxToolCalls,
    };
  }
}
