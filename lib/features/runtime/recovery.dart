/// 失败恢复引擎（§17.3 / §17.5）。
///
/// 失败不是「重试一次」，而是六步（§17.1）：
/// 分类 → 保存证据 → 判断可恢复 → 选恢复策略 → 更新任务认知 → 避免重复无效操作。
///
/// 这里落地的是「分类 + 选策略」两步：把 §17.3 的表格变成可执行的数据，
/// 让 Runtime 在工具失败时给出**具体**的下一步，而不是让模型自己猜。
library;

import 'dart:convert';
import 'dart:io';

import 'capability_manifest.dart';
import 'models/task.dart';
import 'models/tool_result.dart';

/// 失败模式（§17.2 pattern）。稳定的分类标签，写入 Failure Memory 供后续匹配。
class FailurePattern {
  FailurePattern._();

  static const paramError = 'param_error';
  static const outputTruncated = 'output_truncated';
  static const unsupportedArtifact = 'unsupported_artifact';
  static const noEvidenceOnRoute = 'no_evidence_on_route';
  static const indexFailure = 'index_failure';
  static const previewMismatch = 'preview_mismatch';
  static const buildFailure = 'build_failure';
  static const signFailure = 'sign_failure';
  static const verifyFailure = 'verify_failure';
  static const highRiskDenied = 'high_risk_denied';
  static const dryRunFailed = 'dry_run_failed';
  static const multiDexIncomplete = 'multi_dex_incomplete';
  static const evidenceConflict = 'evidence_conflict';
  static const budgetExhausted = 'budget_exhausted';
  static const memoryPressure = 'memory_pressure';
  static const inputTooLarge = 'input_too_large';
  static const toolException = 'tool_exception';

  /// 目标标识不存在（TARGET/METHOD/CLASS/ENTRY/FILE/JOB *_NOT_FOUND、no_match）。
  static const targetMissing = 'target_missing';

  /// 前置状态缺失或已失效（未 open/edit_open/analyze、报告 stale、去签未开）。
  static const stateNotReady = 'state_not_ready';

  /// 同参在滑环窗内重复（MCP 环路闸门）。
  static const repeatedCall = 'repeated_call';

  /// 状态机拒绝推进（ADVANCE_REJECTED）：当前阶段不允许该目标。
  ///
  /// v12 复测（v10-N2）：它过去被归到 previewMismatch，顶层的恢复计划因此
  /// 给的是「重新确认目标位置」这类文不对题的模板，而信封里其实已经带着
  /// currentStatus / allowedNext 的确切允许集。
  static const stateMachineRejection = 'state_machine_rejection';

  /// 工具在当前调用面不可用（Agent 独有工具被 MCP 调用等）。
  static const toolUnavailable = 'tool_unavailable';
  static const unknown = 'unknown';
}

/// 一条恢复方案（§17.3 一行的可执行形式）。
class RecoveryPlan {
  final String pattern;

  /// 建议的恢复动作（自然语言，给模型看）。
  final String strategy;

  /// 建议调用的工具（可空）。
  final List<String> nextActions;

  /// 是否还应该在**同一条路线**上继续。false 表示该换路线或改方案。
  final bool stayOnRoute;

  /// 是否必须用户介入。
  final bool requiresUser;

  /// 是否必须阻止流程继续（例如 Dry Run 没过就不能改）。
  final bool blockProgress;

  /// 一句话教训，写进 Failure Memory（§17.2 lesson）。
  final String lesson;

  /// 每个动作可带的可执行参数（键＝动作名）。
  ///
  /// 2026-09-19 全量复测对照 MT：它的 nextActions 直接给
  /// `{tool, arguments}`，调用方可以照抄参数重发；我们过去只给动作名 +
  /// 一句「原因不明」，等于把「下一步怎么走」重新丢回给调用方。
  final Map<String, Map<String, dynamic>> arguments;

  const RecoveryPlan({
    required this.pattern,
    required this.strategy,
    this.nextActions = const [],
    this.arguments = const {},
    this.stayOnRoute = true,
    this.requiresUser = false,
    this.blockProgress = false,
    this.lesson = '',
  });

  Map<String, Object?> toJson() => {
    'pattern': pattern,
    'strategy': strategy,
    if (nextActions.isNotEmpty) 'nextActions': nextActions,
    'stayOnRoute': stayOnRoute,
    'requiresUser': requiresUser,
    'blockProgress': blockProgress,
    if (lesson.isNotEmpty) 'lesson': lesson,
  };
}

/// 恢复引擎（§17.5）。
class RecoveryEngine {
  RecoveryEngine._();

  /// 把失败信封分类成失败模式。
  ///
  /// 判定顺序有意义：先看结构化错误码，再看文本关键词，最后看截断标记。
  static String classify(ToolEnvelope env) {
    if (env.truncated && env.ok) return FailurePattern.outputTruncated;
    if (env.ok) return FailurePattern.unknown;

    final code = env.errors.isEmpty ? '' : env.errors.first.code.toUpperCase();
    final msg = env.errors.isEmpty ? env.summary : env.errors.first.message;
    final lower = msg.toLowerCase();

    switch (code) {
      case 'PERMISSION_DENIED':
        return FailurePattern.highRiskDenied;
      case 'BUDGET_EXHAUSTED':
        return FailurePattern.budgetExhausted;
      case 'BAD_ARGS':
      case 'MISSING_ARG':
        return FailurePattern.paramError;
      case 'UNSUPPORTED_ARTIFACT':
        return FailurePattern.unsupportedArtifact;
      case 'TOOL_EXCEPTION':
        return FailurePattern.toolException;
      case 'ADVANCE_REJECTED':
        return FailurePattern.stateMachineRejection;
      case 'NO_ARTIFACT':
      case 'NOT_FOUND':
      case 'PATH_ESCAPE':
        return FailurePattern.paramError;
      // 内存类拒绝：过去落到 unknown，于是 nextActions 只说「原因不明：先查任务
      // 状态与最近的证据」——执行端拿不到任何能自救的动作（2026-09-15 真机）。
      case 'NATIVE_PRESSURED':
      case 'MEM_PRESSURED':
        return FailurePattern.memoryPressure;
      case 'INPUT_TOO_LARGE':
        return FailurePattern.inputTooLarge;
    }

    // ---- handler 侧真实错误码词表（2026-09-19 全量复测实测）----
    // 改造前这些码全部落到末尾 unknown → nextActions 只说「原因不明：先查
    // 任务状态与最近的证据」，而其中绝大多数错误的原因其实一清二楚
    // （目标不存在 / 前置没就绪 / 参数非法 / 同参重复）。
    // 顺序有意义：先判「前置状态」，再判「目标不存在」，最后判参数类。
    if (code == 'EDIT_SESSION_NOT_FOUND' ||
        code == 'EMULATOR_SESSION_NOT_FOUND' ||
        code == 'JOB_NOT_FOUND' ||
        code == 'WORKSPACE_REQUIRED' ||
        code == 'WORKSPACE_NOT_SET' ||
        code == 'TASK_NOT_FOUND' ||
        code == 'STALE_REPORT' ||
        code == 'STALE_REPORT_DISCARDED' ||
        code == 'REPORT_NOT_READY' ||
        code == 'PROJECT_NOT_READY' ||
        code == 'SIGNATURE_BYPASS_DISABLED' ||
        code == 'NO_APK_SELECTED' ||
        code == 'PATCH_ARTIFACT_NOT_FOUND') {
      return FailurePattern.stateNotReady;
    }
    if (code == 'LOOP_DETECTED') return FailurePattern.repeatedCall;
    if (code == 'TOOL_NOT_FOUND' ||
        code == 'TOOL_NOT_AVAILABLE' ||
        code == 'UNSUPPORTED_PLATFORM') {
      return FailurePattern.toolUnavailable;
    }
    if (code.endsWith('_NOT_FOUND') ||
        code == 'NOT_FOUND' ||
        code == 'NO_MATCH' ||
        code == 'ABSENT') {
      return FailurePattern.targetMissing;
    }
    if (code.startsWith('INVALID_') ||
        code == 'UNKNOWN_ACTION' ||
        code == 'UNKNOWN_COMMAND' ||
        code.startsWith('MISSING_') ||
        code.startsWith('EMPTY_') ||
        code.endsWith('_REQUIRED') ||
        code.endsWith('_OUT_OF_SCOPE') ||
        code == 'PATH_OUTSIDE_WORKSPACE' ||
        code == 'PARSE_ERROR' ||
        code == 'MATH_ERROR' ||
        code == 'NAME_TOO_SHORT' ||
        code == 'STEP_FAILED' ||
        code == 'INVALID_STEP_REF' ||
        code == 'BAD_ARGS' ||
        code == 'MISSING_ARG') {
      return FailurePattern.paramError;
    }
    if (code == 'TARGET_EXISTS' || code == 'DECODE_DIR_EXISTS') {
      return FailurePattern.buildFailure;
    }
    if (code == 'STRUCTURAL_FAILED' ||
        code == 'TOOL_FAILED' ||
        code == 'PATCH_FAILED' ||
        code.startsWith('LIEF_') ||
        code == 'APKEDITOR_FAILED' ||
        code == 'EMULATION_ERROR') {
      return FailurePattern.toolException;
    }

    if (lower.contains('内存水位') ||
        lower.contains('native 堆') ||
        lower.contains('堆压力')) {
      return FailurePattern.memoryPressure;
    }
    if (lower.contains('不支持') || lower.contains('unsupported')) {
      return FailurePattern.unsupportedArtifact;
    }
    if (lower.contains('签名') || lower.contains('sign')) {
      return FailurePattern.signFailure;
    }
    if (lower.contains('构建') ||
        lower.contains('build') ||
        lower.contains('回编')) {
      return FailurePattern.buildFailure;
    }
    if (lower.contains('没找到') ||
        lower.contains('not found') ||
        lower.contains('无结果')) {
      return FailurePattern.noEvidenceOnRoute;
    }
    if (lower.contains('失效') ||
        lower.contains('未开启') ||
        lower.contains('未设置') ||
        lower.contains('请先')) {
      return FailurePattern.stateNotReady;
    }
    if (lower.contains('不存在') || lower.contains('无效的')) {
      return FailurePattern.targetMissing;
    }
    if (lower.contains('越界') || lower.contains('非法')) {
      return FailurePattern.paramError;
    }
    if (lower.contains('索引') || lower.contains('index')) {
      return FailurePattern.indexFailure;
    }
    return FailurePattern.unknown;
  }

  /// 按失败模式给出恢复方案（§17.3 表格）。
  static RecoveryPlan plan(
    String pattern, {
    Task? task,
    String tool = '',
    Map<String, dynamic> args = const {},
    ToolEnvelope? envelope,
  }) {
    switch (pattern) {
      // v10-N2（v12 复测）：状态机拒绝的顶层恢复计划必须用**信封里的允许集**，
      // 不能落「未分类失败」的通用模板——那时调用方只能再读一遍 error.message。
      case FailurePattern.stateMachineRejection:
        final data = envelope?.data ?? const <String, Object?>{};
        final current = (data['currentStatus'] ?? '').toString();
        final allowed = <String>[
          for (final entry in (data['allowedNext'] as List? ?? const <Object?>[]))
            entry.toString(),
        ];
        return RecoveryPlan(
          pattern: pattern,
          strategy: allowed.isEmpty
              ? '状态机拒绝推进${current.isEmpty ? '' : '（当前 $current）'}：'
                    '该目标在当前阶段不可达——先按错误正文补齐前置动作，再用 task_status 复核；'
                    '不要原样重发被拒的目标'
              : '状态机拒绝推进（当前 $current）：允许推进到 ${allowed.join(' / ')}——'
                    '从允许集里重挑目标；不要原样重发被拒的值',
          nextActions: const <String>['task_status'],
          stayOnRoute: false,
          lesson: '状态推进要按当前阶段的允许集选目标（允许集见信封 allowedNext）',
        );

      case FailurePattern.paramError:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '修正参数后重试同一个工具，不要急着换路线',
          nextActions: [tool.isEmpty ? 'task_status' : tool],
          lesson: '参数错误先改参数，换路线只是掩盖问题',
        );

      case FailurePattern.outputTruncated:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '用 continuation 续读，或改用更精准的区间读取',
          nextActions: [tool.isEmpty ? 'artifact_read' : tool],
          lesson: '截断的结果不算完整结果，必须续读完再用',
        );

      case FailurePattern.unsupportedArtifact:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '换一个支持该产物的能力；DEX 走 DEX 工具，SO 走原生工具',
          nextActions: const ['list_lib_entries', 'so_analyze'],
          stayOnRoute: false,
          lesson: '分析器与产物类型要匹配，硬套会一直失败',
        );

      case FailurePattern.noEvidenceOnRoute:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '当前路线没有新证据，先重新路由再看别的入口',
          nextActions: const ['route_task', 'plan_probes'],
          stayOnRoute: false,
          lesson: '一条路线搜不到就换路线，别在同一条路上反复搜',
        );

      case FailurePattern.indexFailure:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '回退到局部解析，索引只是加速器不是前置依赖',
          nextActions: const ['dex_search', 'class_outline'],
          lesson: '索引失败不影响分析本身，退回局部解析即可',
        );

      case FailurePattern.previewMismatch:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '阻止执行，重新确认目标位置后再评估',
          blockProgress: true,
          lesson: '预览与实际不一致时必须停下，不能带着疑问改包',
        );

      case FailurePattern.dryRunFailed:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '禁止修改，重新评估 Patch Plan（目标是否唯一、片段是否匹配）',
          nextActions: const ['patch_plan', 'smali_read'],
          blockProgress: true,
          lesson: 'Dry Run 不通过就绝不能改，改完的包没有可信度',
        );

      case FailurePattern.buildFailure:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '读结构化错误定位到具体产物，再决定回退还是修正',
          nextActions: const ['apk_rebuild', 'get_current_apk_report'],
          lesson: '构建失败要看错误内容，不要盲目重试同一条命令',
        );

      case FailurePattern.signFailure:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '检查输入包是否完整、签名工具是否可用，再重试',
          nextActions: const ['scan_signature_check', 'apk_sign'],
          lesson: '签名失败多半是输入包或密钥问题，先查再重试',
        );

      case FailurePattern.verifyFailure:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '标记为未完成，不得虚报成功',
          blockProgress: true,
          lesson: '验证没过就只能如实报告未完成',
        );

      case FailurePattern.highRiskDenied:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '用 request_confirmation 向用户要授权；用户拒绝了就换方案',
          nextActions: const ['request_confirmation'],
          requiresUser: true,
          lesson: '高风险操作被拒不是错误，是要用户点头',
        );

      case FailurePattern.multiDexIncomplete:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '继续搜剩下的 DEX 或扩大查询范围，不要当成「没找到」',
          nextActions: [tool.isEmpty ? 'dex_search' : tool],
          lesson: '多 DEX 没搜完时，「没找到」是不可信的结论',
        );

      case FailurePattern.evidenceConflict:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '记录冲突并标记未决，用第三个独立来源裁决',
          nextActions: const ['plan_probes'],
          requiresUser: true,
          lesson: '证据打架时不能挑一个顺眼的，要第三个来源',
        );

      case FailurePattern.budgetExhausted:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '预算用尽：先汇报已有结论与未完成部分，别再试探针',
          nextActions: const ['task_status', 'collect_delivery'],
          requiresUser: true,
          blockProgress: true,
          lesson: '预算耗尽要如实收口，而不是继续烧',
        );

      case FailurePattern.toolException:
        return RecoveryPlan(
          pattern: pattern,
          strategy: '工具内部异常：可重试一次；再失败就换同类工具',
          nextActions: const ['task_status'],
          lesson: '工具崩了先重试一次，连续失败就换实现方式',
        );

      case FailurePattern.memoryPressure:
        return RecoveryPlan(
          pattern: pattern,
          strategy:
              '服务进程内存水位越线：清理与 GC 有释放延迟，先等一会再原样重试一次；'
              '仍被拒就改用更小粒度的入口（逐 dex / 单条目流式改写）或重启 App 清空进程',
          nextActions: const ['task_status'],
          lesson: '水位越线是进程级状态：重试要么等清理生效，要么降粒度，不要连续硬撞',
        );

      case FailurePattern.inputTooLarge:
        return RecoveryPlan(
          pattern: pattern,
          strategy:
              '本次进堆数据超预算：降粒度——jadx 传 dexName 逐 dex、'
              'dex_search 替代整包扫描、SO 回填走 so_patch_into_apk；'
              '确需整包执行再显式带 allowOversize 一次性放行',
          lesson: '超预算先降粒度，原样重试不会改变预算',
        );

      case FailurePattern.targetMissing:
        return RecoveryPlan(
          pattern: pattern,
          strategy:
              '错误里点名的目标标识不存在：先用反查拿到真实 qualifiedId / locator / '
              '条目名（dex_search / class_outline / analyzer_global_search / apk_archive），'
              '再对同工具重试；不要换路线，也不要原样重发',
          nextActions: [tool.isEmpty ? 'dex_search' : tool, 'dex_search'],
          arguments: _targetLookupArguments(args),
          lesson: '「没找到」先怀疑标识写法，不是方案不对',
        );

      case FailurePattern.stateNotReady:
        return RecoveryPlan(
          pattern: pattern,
          strategy:
              '前置状态缺失或已失效：按错误正文补齐前置步骤（open / edit_open / '
              'analyze / 重新 dryRun 拿新 previewToken），再执行原操作',
          nextActions: [tool.isEmpty ? 'task_status' : tool],
          lesson: '前置没就绪时重试必然再败，先把状态补上',
        );

      case FailurePattern.repeatedCall:
        return RecoveryPlan(
          pattern: pattern,
          strategy:
              '同参在滑窗内已执行过：直接使用已有结果，或换参数/地址/分页游标/'
              '分析路径——换证据维度，而不是重复同一份证据',
          nextActions: const [],
          lesson: '重复同一调用不产生新证据',
        );

      case FailurePattern.toolUnavailable:
        return RecoveryPlan(
          pattern: pattern,
          strategy:
              '该工具在当前调用面不可用：先取可用工具名单与全量参数声明，'
              '再改用已声明的同类入口；不要编造工具名或参数',
          nextActions: const ['get_solab_tool_map'],
          stayOnRoute: false,
          lesson: '工具缺席是环境约束，换已声明入口即可',
        );

      default:
        return const RecoveryPlan(
          pattern: FailurePattern.unknown,
          strategy:
              '未分类失败：先读 error.message 里的具体原因，再决定是改参数、'
              '补前置还是换路线；不要原样重发',
          nextActions: ['task_status'],
        );
    }
  }

  /// 分类并给方案，一步到位。
  static RecoveryPlan fromEnvelope(
    ToolEnvelope env, {
    Task? task,
    String tool = '',
    Map<String, dynamic> args = const {},
  }) => plan(
    classify(env),
    task: task,
    tool: tool,
    args: args,
    envelope: env,
  );

  /// 动作名跨面翻译：运行时动作 → 该面上**真实可调用**的工具名。
  ///
  /// 沿革：第 62 项时运行时控制面只有实现、没有发布（`RuntimeTools.defs` /
  /// `.handle` 在生产链路零调用者），发给模型的 `nextActions` 必须翻译成真名，
  /// 否则模型会去调一个不存在的工具、白烧一轮甚至编造工具名。第 72 项已把 11 个
  /// 控制工具接到 Agent 面（schema 由 `RuntimeTools.defs` 单一来源生成，
  /// `_toolHandlers` 分派到 `RuntimeTools.handle`），所以 **Agent 面这些动作名
  /// 就是真名，原样透传**；MCP 面仍不发布它们（那张面另有 `mcp_task_status` 状态口，
  /// 两套口径会打架），有等价物的翻成 MCP 真名，没有等价物的丢弃。
  ///
  /// MCP 客户端只认 tools/list 里的名字（2026-09-19 复测实测：MCP 错误建议里
  /// 出现过 `task_status`），MCP 面翻成 MCP 的等价工具。
  static const Map<String, String> _mcpActionAliases = <String, String>{
    'task_status': 'mcp_task_status',
    'artifact_read': 'file',
    'list_lib_entries': 'apk_archive',
    'scan_signature_check': 'run_task_command',
    'sign_apk': 'apk_sign',
    'collect_delivery': 'export_apk_report',
    'plan_probes': 'route_task',
    'dex_outline': 'class_outline',
  };

  /// Agent 面的等价工具（发布名，均可在 agent 面工具清单里查到）。
  ///
  /// 运行时控制面动作（task_status / artifact_read / plan_probes /
  /// request_confirmation / collect_delivery …）自第 72 项起已是 Agent 面真名，
  /// **不列在这里**（列了反而会把真名翻译成替身）。剩下的都是「动作名与工具名
  /// 不同」的别名。
  static const Map<String, String> _agentActionAliases = <String, String>{
    'list_lib_entries': 'apk_archive',
    'scan_signature_check': 'run_task_command',
    'sign_apk': 'apk_sign',
    'dex_outline': 'class_outline',
  };

  /// 只在 Agent 面发布的动作（MCP 面没有对应工具，直接丢弃）。
  ///
  /// 运行时控制面第 72 项只挂 Agent 面；其中 `task_status` / `plan_probes` /
  /// `collect_delivery` / `artifact_read` 在 MCP 面有等价工具，走
  /// `_mcpActionAliases` 翻译，不在这里。
  static const Set<String> _agentOnlyActions = <String>{
    'request_confirmation',
    'task_update',
    'patch_plan',
    'dry_run_patch',
    'evidence_query',
    'verify_apk',
    'workspace_cleanup',
  };

  /// 单个动作在该面上的真名；该面没有等价物（会被丢弃）时返回 null。
  static String? faceName(String action, {required bool mcp}) {
    if (mcp && _agentOnlyActions.contains(action)) return null;
    return (mcp ? _mcpActionAliases : _agentActionAliases)[action] ?? action;
  }

  /// 把恢复动作翻译成该面上真实可调用的工具名（去重、保持顺序）。
  static List<String> actionsForFace(
    List<String> actions, {
    required bool mcp,
  }) {
    final out = <String>[];
    for (final action in actions) {
      final mapped = faceName(action, mcp: mcp);
      if (mapped == null || out.contains(mapped)) continue;
      out.add(mapped);
    }
    return List<String>.unmodifiable(out);
  }

  /// 从原始调用参数里提取「反查目标」的检索词，供 targetMissing 方案带上
  /// 可执行参数（调用方照抄即可重发）。
  static Map<String, Map<String, dynamic>> _targetLookupArguments(
    Map<String, dynamic> args,
  ) {
    var hint =
        (args['target'] ??
                args['qualifiedId'] ??
                args['className'] ??
                args['entry'] ??
                args['entryName'] ??
                args['locator'] ??
                '')
            .toString()
            .trim();
    if (hint.isEmpty) return const {};
    // 类名去掉 smali 包装：Lpkg/Class; → pkg/Class
    if (hint.startsWith('L') && hint.endsWith(';') && !hint.contains('->')) {
      hint = hint.substring(1, hint.length - 1);
    }
    if (hint.length > 120) hint = hint.substring(0, 120);
    // 第 64 项（2026-09-29）：dex_search 的 `path` 是发布契约里的必填项
    // （`local_tool_schemas.dart` 的 `'required': ['path']`），参数守卫会在
    // **两面共用咽喉**的分发前判 `missing_argument`（`local_tools_service.dart:549`）。
    // 原调用能走到恢复层，说明它自己已过守卫、必然带 path/apkPath —— 把同一个
    // 路径带上，建议才真的「照抄可重发」；拿不到路径时**宁可不发参数**，
    // 也不给一份必然被守卫打死的半成品（旧实现实测 100% 回落成
    // missing_argument，白烧一轮预算）。
    final path = (args['path'] ?? args['apkPath'] ?? args['sourcePath'] ?? '')
        .toString()
        .trim();
    if (path.isEmpty) return const {};
    return <String, Map<String, dynamic>>{
      'dex_search': <String, dynamic>{
        'path': path,
        'keywords': <String>[hint],
        'limit': 10,
      },
    };
  }

  /// 检查某个建议的工具在当前阶段是否真的可用；不可用就换成同类替代。
  static List<String> filterByPhase(List<String> tools, TaskPhase phase) {
    final allowed = {
      ...CapabilityManifest.forPhase(phase),
      ...CapabilityManifest.control,
    };
    final usable = tools.where(allowed.contains).toList();
    if (usable.isNotEmpty) return usable;
    // 全部不可用：给一个该阶段一定有的兜底工具
    return allowed.contains('task_status') ? const ['task_status'] : const [];
  }
}

/// 审计记录（§18.4）。
///
/// 所有高风险操作必须留痕：操作类型 / 时间 / 目标 / 授权来源 / 结果 / 失败原因。
class AuditRecord {
  final String id;
  final String taskId;
  final String operation;
  final String target;

  /// 授权来源：任务约束里的哪个开关、或用户确认。
  final String authorization;
  final bool allowed;
  final String result;
  final String failureReason;
  final int createdAt;

  const AuditRecord({
    required this.id,
    required this.taskId,
    required this.operation,
    this.target = '',
    this.authorization = '',
    this.allowed = false,
    this.result = '',
    this.failureReason = '',
    this.createdAt = 0,
  });

  Map<String, Object?> toJson() => {
    'id': id,
    'taskId': taskId,
    'operation': operation,
    'target': target,
    'authorization': authorization,
    'allowed': allowed,
    'result': result,
    if (failureReason.isNotEmpty) 'failureReason': failureReason,
    'createdAt': createdAt,
  };

  static AuditRecord fromJson(Object? raw) {
    if (raw is! Map) throw const FormatException('audit 不是对象');
    return AuditRecord(
      id: raw['id']?.toString() ?? '',
      taskId: raw['taskId']?.toString() ?? '',
      operation: raw['operation']?.toString() ?? '',
      target: raw['target']?.toString() ?? '',
      authorization: raw['authorization']?.toString() ?? '',
      allowed: raw['allowed'] == true,
      result: raw['result']?.toString() ?? '',
      failureReason: raw['failureReason']?.toString() ?? '',
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
    );
  }
}

/// 审计日志：JSONL 追加写，一行一条。
class AuditLog {
  AuditLog(this.logFile);

  final File logFile;

  /// 只有高风险操作才需要审计（§18.3 清单），普通读操作不写。
  static bool needsAudit(String tool) =>
      CapabilityManifest.highRisk.containsKey(tool) || tool.startsWith('mcp__');

  Future<void> append(AuditRecord record) async {
    await logFile.parent.create(recursive: true);
    await logFile.writeAsString(
      '${jsonEncode(record.toJson())}\n',
      mode: FileMode.append,
      flush: true,
    );
  }

  Future<List<AuditRecord>> read() async {
    if (!await logFile.exists()) return const [];
    final out = <AuditRecord>[];
    for (final line in await logFile.readAsLines()) {
      final t = line.trim();
      if (t.isEmpty) continue;
      try {
        out.add(AuditRecord.fromJson(jsonDecode(t)));
      } catch (_) {
        // 跳过坏行
      }
    }
    return out;
  }
}
