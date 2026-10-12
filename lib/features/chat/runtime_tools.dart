/// 运行时控制类工具（§7.4 核心控制）。
///
/// 这些工具不改 APK，只改**任务状态**：查状态、推进阶段、记路线、查证据、
/// 读产物、提计划、跑 Dry Run、清理工作区、收交付。
///
/// 关键约束：模型调用它们**不等于**状态会变。状态推进一律走
/// [TaskRuntime.advance] 的进入条件校验（§13.4「模型不能直接修改任务状态」）。
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;

import '../runtime/models/evidence.dart';
import '../runtime/capability_manifest.dart';
import '../runtime/models/task.dart';
import '../runtime/models/task_event.dart';
import '../../features/solab_apk/services/apk_workspace_binding_service.dart';
import '../../core/services/local_tools/tool_arg_echo.dart';
import '../../core/services/local_tools/tool_paging.dart';
import '../runtime/models/tool_result.dart';
import '../runtime/artifact_store.dart';
import '../runtime/model_gateway.dart';
import '../runtime/probe_planner.dart';
import '../runtime/task_runtime.dart';
import '../runtime/task_session.dart';
import '../runtime/verification.dart';
import 'chat_models.dart';

class RuntimeTools {
  RuntimeTools._();

  /// 验证器。测试可以替换（注入假的 ApkProbe）。
  static Verifier verifier = Verifier();

  /// 探针规划器。测试可以替换（注入自定义成本表）。
  static ProbePlanner planner = ProbePlanner();

  /// 控制类工具名集合（判断该走运行时还是走 APK 工具层）。
  static final Set<String> names = {for (final d in defs) d.name};

  /// 发给模型的 schema。
  static List<ToolDef> get defs => const [
    ToolDef(
      name: 'task_status',
      description: '查看当前任务状态：阶段、预算余量、证据数量、未决冲突。开始和不确定时都该先看它。',
      parameters: {'type': 'object', 'properties': {}},
    ),
    ToolDef(
      name: 'task_update',
      description:
          '请求推进任务状态（如分析完成后推进到 analyzed）。'
          '是否真的推进由系统按进入条件判定，不满足会说明原因。',
      parameters: {
        'type': 'object',
        'properties': {
          'next': {
            'type': 'string',
            'description':
                '目标状态：prepared/analyzed/located/planned/'
                'dryRunVerified/modified/built/signed/verified/delivered',
          },
          'reason': {'type': 'string', 'description': '推进依据'},
        },
        'required': ['next', 'reason'],
      },
    ),
    ToolDef(
      name: 'route_task',
      description:
          '记录本次分析路线选择（dex/native/flutter）与理由。路线是当前假设，'
          '不是永久结论；换了路线要重新调用。',
      parameters: {
        'type': 'object',
        'properties': {
          'routes': {
            'type': 'array',
            'description': '按优先级排列的路线，元素为 {name, reason}',
            'items': {'type': 'object'},
          },
          'nextAction': {'type': 'string', 'description': '下一步动作'},
        },
        'required': ['routes'],
      },
    ),
    ToolDef(
      name: 'evidence_query',
      description: '查询已登记的证据（含等级与来源）。下结论前用它确认证据够不够。',
      parameters: {
        'type': 'object',
        'properties': {
          'level': {
            'type': 'string',
            'description':
                '只看不低于该等级的证据：candidate/observed/'
                'correlated/verified',
          },
          'limit': {'type': 'integer'},
        },
      },
    ),
    ToolDef(
      name: 'artifact_read',
      description:
          '读取任务工作区里的产物文件（工作目录内相对路径）。'
          '大文件会截断并给出续读令牌，必须续读完再下结论。',
      parameters: {
        'type': 'object',
        'properties': {
          'path': {'type': 'string', 'description': '相对工作区的路径'},
          'offset': {'type': 'integer', 'description': '起始字节偏移，默认 0'},
          'limit': {'type': 'integer', 'description': '最多读多少字节，默认 8000'},
          'continuation': {'type': 'string', 'description': '上次返回的续读令牌'},
        },
        'required': ['path'],
      },
    ),
    ToolDef(
      name: 'patch_plan',
      description:
          '登记结构化修改计划（目标、操作、依据、预览、风险、回滚方式）。'
          '没有计划就不能进入修改阶段。',
      parameters: {
        'type': 'object',
        'properties': {
          'targetArtifact': {'type': 'string', 'description': '如 classes.dex'},
          'targetMethod': {
            'type': 'string',
            'description': '如 Lcom/x/A;->isVip()Z',
          },
          'operation': {
            'type': 'string',
            'description':
                'branch_change / string_replace / method_void / '
                'manifest_edit / so_patch',
          },
          'reason': {'type': 'string', 'description': '修改依据（引用证据 id 更好）'},
          'preconditions': {
            'type': 'array',
            'items': {'type': 'string'},
            'description': '如 method_signature_matches',
          },
          'before': {'type': 'string', 'description': '修改前片段'},
          'after': {'type': 'string', 'description': '修改后片段'},
          'risk': {
            'type': 'string',
            'description': 'low / medium / high / critical',
          },
          'evidenceIds': {
            'type': 'array',
            'items': {'type': 'string'},
          },
        },
        'required': ['targetArtifact', 'operation', 'reason'],
      },
    ),
    ToolDef(
      name: 'dry_run_patch',
      description:
          '对已登记的计划做修改前检查（目标存在且唯一、片段匹配、可回滚）。'
          '不通过则禁止真正修改。',
      parameters: {
        'type': 'object',
        'properties': {
          'patchId': {'type': 'string'},
          'checks': {
            'type': 'array',
            'items': {'type': 'object'},
            'description': '每项 {name, passed, detail}',
          },
          'passed': {'type': 'boolean', 'description': '全部检查是否通过（与 checks 一致）'},
        },
        'required': ['patchId', 'passed'],
      },
    ),
    // 2026-09-29（第 72 项）：原 explore_routes 只有 def、没有 handle 分支，
    // 发布出去就是「模型看得见、永远 UNKNOWN_TOOL」的坏工具（§五判据 19
    // 「发给模型的下一步必须真存在」）。按「要么真实现、要么不发布」处理：
    // 本轮从 defs 里删除，勘察需求由 plan_probes + 各分析工具承担。
    ToolDef(
      name: 'plan_probes',
      description:
          '让系统按「当前最缺哪条证据」排出下一步探针建议（含成本与价值）。'
          '不知道下一步该查什么、或证据卡住时用它。建议仅供参考。',
      parameters: {
        'type': 'object',
        'properties': {
          'limit': {'type': 'integer', 'description': '最多给几条，默认 3'},
        },
      },
    ),
    ToolDef(
      name: 'verify_apk',
      description:
          '对产物做工程验证（能否解析、SHA-256、签名、可安装性）'
          '并可选合并行为验证观察。工程验证与行为验证分开报告，'
          '做不到的项会如实标 NOT VERIFIED。',
      parameters: {
        'type': 'object',
        'properties': {
          'path': {
            'type': 'string',
            'description': '产物 APK 路径（绝对路径或工作区内相对路径）；省略则取 output/ 里最新的 APK',
          },
          'expectSha256': {'type': 'string', 'description': '预期哈希，用于比对'},
          'behavior': {
            'type': 'array',
            'items': {'type': 'object'},
            'description':
                '行为验证观察，每项 {name, passed, detail}；'
                '没实际观察就别传',
          },
        },
      },
    ),
    ToolDef(
      name: 'collect_delivery',
      description: '整理交付物：列出成品、计算 SHA-256、汇总未验证项。任务收尾用。',
      parameters: {
        'type': 'object',
        'properties': {
          'note': {'type': 'string', 'description': '交付说明'},
        },
      },
    ),
    ToolDef(
      name: 'workspace_cleanup',
      description: '清理任务工作区的中间产物（保留原始 APK 与成品）。',
      parameters: {
        'type': 'object',
        'properties': {
          'keepAnalysis': {'type': 'boolean', 'description': '失败诊断时保留分析与证据目录'},
        },
      },
    ),
    ToolDef(
      name: 'request_confirmation',
      description:
          '需要用户明确授权才能继续时调用（高风险操作、目标不明确、'
          '证据冲突）。调用后任务进入等待确认状态。',
      parameters: {
        'type': 'object',
        'properties': {
          'reason': {'type': 'string', 'description': '为什么需要用户决定'},
        },
        'required': ['reason'],
      },
    ),
  ];

  /// 执行控制类工具。返回统一信封的 JSON 文本。
  static Future<String> handle(
    String name,
    Map<String, dynamic> args, {
    required TaskSession session,
    required String scopeKey,
  }) async {
    final runtime = session.runtime;
    final task = await session.taskFor(scopeKey);
    if (task == null) {
      return _fail(name, 'NO_TASK', '当前对话还没有任务。先设置工作目录并选定 APK。').toToolText();
    }

    try {
      switch (name) {
        case 'task_status':
          return (await _taskStatus(task, runtime, scopeKey: scopeKey))
              .toToolText();
        case 'task_update':
          return (await _taskUpdate(task, args, runtime)).toToolText();
        case 'route_task':
          return (await _routeTask(task, args, runtime)).toToolText();
        case 'evidence_query':
          return (await _evidenceQuery(task, args, runtime)).toToolText();
        case 'artifact_read':
          return (await _artifactRead(task, args, runtime)).toToolText();
        case 'patch_plan':
          return (await _patchPlan(task, args, runtime)).toToolText();
        case 'dry_run_patch':
          return (await _dryRunPatch(task, args, runtime)).toToolText();
        case 'verify_apk':
          return (await _verifyApk(task, args, runtime)).toToolText();
        case 'plan_probes':
          return (await _planProbes(task, args, runtime)).toToolText();
        case 'collect_delivery':
          return (await _collectDelivery(task, args, runtime)).toToolText();
        case 'workspace_cleanup':
          return (await _workspaceCleanup(task, args, runtime)).toToolText();
        case 'request_confirmation':
          return (await _requestConfirmation(task, args, runtime)).toToolText();
        default:
          return _fail(name, 'UNKNOWN_TOOL', '未知的控制工具：$name').toToolText();
      }
    } catch (e) {
      return _fail(name, 'RUNTIME_ERROR', '$e').toToolText();
    }
  }

  // ---------------------------------------------------------------- 实现

  static Future<ToolEnvelope> _taskStatus(
    Task task,
    TaskRuntime runtime, {
    String scopeKey = '',
  }) async {
    final evidence = await runtime.evidence.load(task.id);
    final conflicts = await runtime.evidence.loadConflicts(task.id);
    final usage = await runtime.usage.summary(task.id);
    final metrics = await runtime.metrics.collect(task.id);
    final unresolved = conflicts.where((c) => c.resolvedBy.isEmpty).length;
    // v9-N2（v12 复测）：同一作用域先后出现两个 taskId 时，这里给出因果——
    // 换目标包重建的任务在 created 事件里记着被顶替的旧任务（replacesTaskId）。
    String replacesTaskId = '';
    String replaceReason = '';
    try {
      for (final event in await runtime.store.loadEvents(task.id)) {
        if (event.type != TaskEventType.created) continue;
        replacesTaskId = (event.payload['replacesTaskId'] ?? '').toString();
        replaceReason = (event.payload['replaceReason'] ?? '').toString();
        break;
      }
    } catch (_) {
      // 事件流读不到不影响状态本身。
    }
    return ToolEnvelope.success(
      tool: 'task_status',
      summary: '${task.status.label} / 阶段 ${task.phase.label}',
      data: {
        'taskId': task.id,
        // 作用域键：本 id 是「这个作用域当前绑定的任务」；同一作用域再次
        // 换目标任务会被重建并改绑，见 replacesTaskId。
        if (scopeKey.isNotEmpty) 'scopeKey': scopeKey,
        if (replacesTaskId.isNotEmpty) 'replacesTaskId': replacesTaskId,
        if (replaceReason.isNotEmpty) 'replaceReason': replaceReason,
        'goal': task.contract.goal,
        'status': task.status.label,
        'statusText': task.status.description,
        'phase': task.phase.id,
        'workspacePath': task.workspacePath,
        'inputApk': task.contract.inputApk,
        'constraints': task.contract.constraints.toJson(),
        'budget': {
          'usedToolCalls': task.budget.usedToolCalls,
          'maxToolCalls': task.budget.maxToolCalls,
          'usedCost': task.budget.usedCost,
          'maxCost': task.budget.maxCost,
        },
        'evidenceCount': evidence.length,
        'unresolvedConflicts': unresolved,
        'usage': usage.toJson(),
        'recommendedTier': ModelRouting.tierForPhase(task.phase).id,
        // 指标只给关键的几个，避免把状态查询变成报表（§25.1 核心指标）
        'timeToFirstUsefulEvidenceMs': metrics.timeToFirstUsefulEvidenceMs,
        'invalidCallRate': metrics.invalidCallRate,
        'falseCompletionRisk': metrics.falseCompletionRisk,
        // 耗时账：慢工具在数据里可见（性能定位用，不参与任何状态判定）
        if (metrics.slowestTool != null)
          'slowestTool': {
            'tool': metrics.slowestTool,
            'durationMs': metrics.slowestToolMs,
          },
        if (metrics.slowToolCalls > 0) 'slowToolCalls': metrics.slowToolCalls,
      },
    );
  }

  static Future<ToolEnvelope> _taskUpdate(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final nextLabel = (args['next'] ?? '').toString();
    final next = _statusFromInput(nextLabel);
    if (next == null) {
      return _fail('task_update', 'BAD_STATE', '无法识别的目标状态：$nextLabel');
    }
    final reason = (args['reason'] ?? '').toString();
    try {
      final updated = await runtime.advance(task.id, next, reason: reason);
      return ToolEnvelope.success(
        tool: 'task_update',
        summary: '已推进到 ${updated.status.label}',
        data: {'status': updated.status.label, 'phase': updated.phase.id},
      );
    } on AdvanceRejection catch (e) {
      // v8-D13（2026-10-04 真机）：拒绝必须可行动——过去只有一句「状态机不允许
      // 这一步」，不给当前阶段也不给允许值（nextActions 还是通用模板）。
      final allowed = <String>[
        for (final s in TaskStatus.values)
          if (e.from.canAdvanceTo(s)) s.label,
      ];
      return ToolEnvelope.failure(
        tool: 'task_update',
        code: 'ADVANCE_REJECTED',
        message: '${e.reason}。当前状态：${e.from.label}；'
            '允许推进到：${allowed.isEmpty ? '（无——先完成前置动作，用 task_status 看下一步）' : allowed.join(' / ')}。'
            '本次请求的目标：${e.to.label}。',
        data: {
          'currentStatus': e.from.label,
          'requestedNext': e.to.label,
          'allowedNext': allowed,
        },
        // v10-N2（2026-10-04 复测）：suggestedActions 过去是「请看 allowedNext」
        // 的通用模板，等于把可行动值又藏回 data 里。这里直接把允许值写进话术；
        // 无允许值时给出唯一的真实出路（先补齐前置动作）。
        suggestedActions: <String>[
          if (allowed.isNotEmpty)
            '可推进到：${allowed.join(' / ')}——从中挑一个重发'
          else
            '当前没有可推进目标：先按 message 补齐前置动作，再用 task_status 复核',
          '不要原样重发被拒的目标：${e.to.label}',
        ],
      );
    }
  }

  static Future<ToolEnvelope> _routeTask(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final routes = (args['routes'] as List? ?? const [])
        .whereType<Map>()
        .map((m) => Map<String, Object?>.from(m))
        .toList();
    if (routes.isEmpty) {
      return _fail('route_task', 'BAD_ARGS', 'routes 不能为空');
    }
    await runtime.store.appendEvent(
      TaskEventFactory.route(
        taskId: task.id,
        phase: task.phase.id,
        routes: routes,
        nextAction: args['nextAction']?.toString() ?? '',
      ),
    );
    return ToolEnvelope.success(
      tool: 'route_task',
      summary: '已记录 ${routes.length} 条路线',
      data: {'routes': routes},
    );
  }

  static Future<ToolEnvelope> _evidenceQuery(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final all = await runtime.evidence.load(task.id);
    final minLabel = (args['level'] ?? '').toString().toLowerCase();
    EvidenceLevel? min;
    if (minLabel.isNotEmpty) {
      for (final l in EvidenceLevel.values) {
        if (l.label.toLowerCase() == minLabel) {
          min = l;
          break;
        }
      }
    }
    final limit = (args['limit'] as num?)?.toInt() ?? 20;
    final minLevel = min;
    final filtered = minLevel == null
        ? all
        : all.where((e) => e.level.rank >= minLevel.rank).toList();
    final shown = filtered.take(limit).toList();
    return ToolEnvelope.success(
      tool: 'evidence_query',
      summary:
          '共 ${filtered.length} 条${minLevel == null ? '' : '（≥${minLevel.label}）'}',
      data: {
        'total': filtered.length,
        'returned': shown.length,
        'items': [
          for (final e in shown)
            {
              'id': e.id,
              'level': e.level.label,
              'type': e.type,
              'claim': e.claim,
              'source': e.source.toJson(),
              'resolved': e.resolved,
            },
        ],
      },
      truncated: filtered.length > shown.length,
      continuation: filtered.length > shown.length
          ? ToolContinuation(type: 'page', token: '${shown.length}')
          : null,
    );
  }

  /// 读工作区产物。大文件截断 + 续读令牌（§8.2 的完整示例）。
  static Future<ToolEnvelope> _artifactRead(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final rel = (args['path'] ?? '').toString().trim();
    if (rel.isEmpty) return _fail('artifact_read', 'BAD_ARGS', '缺 path');

    // 报告 2-10：过去这里只认 `task.workspacePath`（任务运行时工作区，形如
    // …/runtime/workspaces/task_*/），于是调用方按工具描述去读**工作目录**里的
    // 产物（相对路径）一律 NOT_FOUND——两种「工作区」同名不同物。
    // 现在按「绑定的工作目录 → 任务运行时工作区」顺序找，并把搜索过的根如实回报。
    final searchRoots = <({String kind, String root})>[];
    final boundWorkDir = await ApkWorkspaceBindingService.workDir();
    if (boundWorkDir != null && boundWorkDir.trim().isNotEmpty) {
      searchRoots.add((kind: 'workDir', root: boundWorkDir.trim()));
    }
    if (task.workspacePath.isNotEmpty) {
      searchRoots.add((kind: 'taskWorkspace', root: task.workspacePath));
    }
    if (searchRoots.isEmpty) {
      return _fail('artifact_read', 'NO_WORKSPACE', '工作目录与任务工作区都未建立');
    }

    final normalized = p.normalize(rel).replaceAll('\\', '/');
    final isAbsolute = p.isAbsolute(normalized);
    if (!isAbsolute && normalized.startsWith('..')) {
      return _fail('artifact_read', 'PATH_ESCAPE', '相对路径不能含 ..');
    }

    // v16-N1：绝对路径先过**沙盒别名表**（与 file/so_analyze 同一张
    // ApkWorkspaceBindingService.resolveZoneAlias）——策略文档里 /workspace 是
    // 合法可写区，读类工具不该与写类工具两套路径词汇表。别名解析不到（未绑定
    // 工作区）时保持原样，走下面的越界判定。
    final aliased = isAbsolute
        ? ApkWorkspaceBindingService.resolveZoneAlias(normalized)
        : null;
    final resolvedTarget = aliased ?? normalized;

    File? file;
    String? rootKind;
    if (isAbsolute) {
      // 绝对路径必须落在某个已知根内（否则等于任意读盘）。
      for (final candidate in searchRoots) {
        if (p.isWithin(candidate.root, resolvedTarget)) {
          file = File(resolvedTarget);
          rootKind = candidate.kind;
          break;
        }
      }
      if (file == null) {
        return ToolEnvelope.failure(
          tool: 'artifact_read',
          code: 'PATH_ESCAPE',
          message: '绝对路径不在任何已知根内：$normalized',
          suggestedActions: <String>[
            '同一文件的等价写法：/workspace/<相对路径> 或直接给 <相对路径>'
                '（二者都相对绑定的工作目录）',
            '先 list_workspace_apks / get_apk_project_info 确认产物真实路径',
          ],
          data: <String, Object?>{
            'searchedRoots': [
              for (final candidate in searchRoots) candidate.root,
            ],
          },
        );
      }
    } else {
      for (final candidate in searchRoots) {
        final probe = File(p.join(candidate.root, normalized));
        if (await probe.exists()) {
          file = probe;
          rootKind = candidate.kind;
          break;
        }
      }
      if (file == null) {
        return ToolEnvelope.failure(
          tool: 'artifact_read',
          code: 'NOT_FOUND',
          message:
              '文件不存在：$normalized（已在 ${searchRoots.length} 个根下查找：'
              '${searchRoots.map((c) => c.root).join(' 、 ')}）',
          suggestedActions: <String>[
            '确认文件名与相对路径；产物可能躺在任务运行时工作区（input/…）而不是工作目录',
            '用 list_workspace_apks 或 get_workspace_policy 看真实产物路径',
          ],
          data: <String, Object?>{
            'path': normalized,
            'searchedRoots': [
              for (final candidate in searchRoots) candidate.root,
            ],
          },
        );
      }
    }

    var offset = (args['offset'] as num?)?.toInt() ?? 0;
    // 续读令牌优先（§8.2）：令牌里带了正确的 offset，避免模型自己算错
    final token = (args['continuation'] ?? '').toString();
    if (token.isNotEmpty) {
      final decoded = _decodeToken(token);
      if (decoded != null) offset = decoded;
    }
    final limitRequested = (args['limit'] as num?)?.toInt();
    final limit = (limitRequested ?? 8000).clamp(1, 200000);

    final len = await file.length();
    if (offset >= len) {
      return ToolEnvelope.success(
        tool: 'artifact_read',
        summary: '已到文件末尾',
        data: {
          'path': normalized,
          'resolvedPath': file.path,
          'rootKind': rootKind,
          'totalBytes': len,
          'offset': offset,
        },
      );
    }
    final raf = await file.open();
    try {
      await raf.setPosition(offset);
      final bytes = await raf.read(limit);
      final end = offset + bytes.length;
      final truncated = end < len;
      return ToolEnvelope.success(
        tool: 'artifact_read',
        summary: '读取 $offset..$end / $len 字节',
        data: {
          'path': normalized,
          // 命中的是哪个根：两处「工作区」同名不同物，必须让调用方看得见。
          'resolvedPath': file.path,
          'rootKind': rootKind,
          'offset': offset,
          'end': end,
          'totalBytes': len,
          // 报告 2-23：单位是**字节**，显式声明 + 统一 page 块；limit 生效值也回显
          // （过去 clamp(1,200000) 之后不回显，调用方不知道自己传的 999999 被压过）。
          ...ToolArgEcho.effective('limit', limitRequested, limit),
          'page': ToolPaging.block(
            unit: ToolPaging.unitBytes,
            offset: offset,
            limit: limit,
            returned: bytes.length,
            total: len,
          ),
          'text': utf8.decode(bytes, allowMalformed: true),
        },
        truncated: truncated,
        continuation: truncated
            ? ToolContinuation(
                type: 'range',
                token: _encodeToken(end),
                nextCursor: 'offset=$end',
              )
            : null,
      );
    } finally {
      await raf.close();
    }
  }

  static Future<ToolEnvelope> _patchPlan(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final artifact = (args['targetArtifact'] ?? '').toString();
    final operation = (args['operation'] ?? '').toString();
    final reason = (args['reason'] ?? '').toString();
    if (artifact.isEmpty || operation.isEmpty || reason.isEmpty) {
      return _fail(
        'patch_plan',
        'BAD_ARGS',
        'targetArtifact / operation / reason 都必填',
      );
    }
    final patchId = 'patch_${DateTime.now().millisecondsSinceEpoch}';
    await runtime.store.appendEvent(
      TaskEventFactory.patchPlan(
        taskId: task.id,
        phase: task.phase.id,
        patchId: patchId,
        payload: {
          'targetArtifact': artifact,
          'targetMethod': args['targetMethod']?.toString() ?? '',
          'operation': operation,
          'reason': reason,
          'preconditions': args['preconditions'] ?? const [],
          'preview': {
            'before': args['before']?.toString() ?? '',
            'after': args['after']?.toString() ?? '',
          },
          'risk': args['risk']?.toString() ?? 'medium',
          'evidenceIds': args['evidenceIds'] ?? const [],
          'requiresConfirmation': true,
          'rollback': 'restore_backup_artifact',
        },
      ),
    );

    try {
      final updated = await runtime.advance(
        task.id,
        TaskStatus.planned,
        reason: '已登记修改计划 $patchId',
      );
      return ToolEnvelope.success(
        tool: 'patch_plan',
        summary: '计划已登记，状态推进到 ${updated.status.label}',
        data: {'patchId': patchId, 'status': updated.status.label},
      );
    } on AdvanceRejection catch (e) {
      // 报告 2-9 / v6 D2 裁决（2026-10-03）：计划**已经落库**，登记本身成功。
      // patch_plan 的职责是登记（阶段推进只做 best-effort）——登记成功就回
      // ok=true，把推进被拒作为标注回传；否则调用方会把「登记成功」当失败，
      // 整条「登记→预览→推进」流程卡死。
      return ToolEnvelope.success(
        tool: 'patch_plan',
        summary: '计划已登记（patchId=$patchId）；状态推进被跳过：${e.reason}',
        data: <String, Object?>{
          'patchId': patchId,
          'registered': true,
          'advanceRejected': true,
          'advanceRejectedReason': e.reason,
          'status': task.status.label,
          'note': '登记已生效，可直接 dry_run_patch(patchId=…) 完成预览闭环；'
              '状态推进被拒说明阶段前置条件未满足，完成前置后再 task_update。',
        },
      );
    }
  }

  static Future<ToolEnvelope> _dryRunPatch(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final patchId = (args['patchId'] ?? '').toString();
    if (patchId.isEmpty) return _fail('dry_run_patch', 'BAD_ARGS', '缺 patchId');
    final passed = args['passed'] == true;
    final checks = (args['checks'] as List? ?? const [])
        .whereType<Map>()
        .map((m) => Map<String, Object?>.from(m))
        .toList();

    await runtime.store.appendEvent(
      TaskEventFactory.patchDryRun(
        taskId: task.id,
        phase: task.phase.id,
        patchId: patchId,
        passed: passed,
        checks: checks,
      ),
    );
    if (!passed) {
      return ToolEnvelope.success(
        tool: 'dry_run_patch',
        summary: 'Dry Run 未通过，禁止修改',
        data: {'patchId': patchId, 'passed': false, 'checks': checks},
      );
    }
    try {
      final updated = await runtime.advance(
        task.id,
        TaskStatus.dryRunVerified,
        reason: 'Dry Run 通过',
      );
      return ToolEnvelope.success(
        tool: 'dry_run_patch',
        summary: 'Dry Run 通过，可以执行修改',
        data: {
          'patchId': patchId,
          'passed': true,
          'status': updated.status.label,
        },
      );
    } on AdvanceRejection catch (e) {
      // v6 D2 裁决（2026-10-03）：Dry Run 事件已落库＝预览闭环有效；阶段推进
      // 只做 best-effort。回 ok=true + 标注，别再让「登记→预览→推进」卡死。
      return ToolEnvelope.success(
        tool: 'dry_run_patch',
        summary: 'Dry Run 已记录（通过）；状态推进被跳过：${e.reason}',
        data: <String, Object?>{
          'patchId': patchId,
          'passed': true,
          'advanceRejected': true,
          'advanceRejectedReason': e.reason,
          'note': '预览闭环已生效；推进被拒＝阶段前置未满足，完成后再 task_update。',
        },
      );
    }
  }

  /// 工程验证 + 可选行为观察（§15.1 / §15.2）。
  /// 探针规划（§12）：回答「当前最缺哪条证据」。
  static Future<ToolEnvelope> _planProbes(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final evidence = await runtime.evidence.load(task.id);
    final conflicts = await runtime.evidence.loadConflicts(task.id);
    final failures = await runtime.relevantFailures(task.id);
    final allowed = CapabilityManifest.forPhase(task.phase);
    final limit = (args['limit'] as num?)?.toInt() ?? 3;
    final probes = planner.suggest(
      task: task,
      evidence: evidence,
      conflicts: conflicts,
      failures: failures,
      allowedTools: allowed,
      limit: limit,
    );
    return ToolEnvelope.success(
      tool: 'plan_probes',
      summary: probes.isEmpty
          ? (task.budget.remainingCost <= 1 ? '预算不足以执行有价值的探针' : '当前阶段没有更合适的探针')
          : '建议先做 ${probes.first.probe}',
      data: {
        'evidenceLevel': evidence.isEmpty
            ? null
            : _levelLabel(
                evidence
                    .map((e) => e.level)
                    .reduce((a, b) => a.rank >= b.rank ? a : b),
              ),
        'unresolvedConflicts': conflicts
            .where((c) => c.resolvedBy.isEmpty)
            .length,
        'probes': [for (final p in probes) p.toJson()],
      },
      nextActions: [
        for (final p in probes)
          ToolNextAction(action: p.probe, reason: p.purpose),
      ],
    );
  }

  static String _levelLabel(EvidenceLevel l) => l.label;

  /// 工程验证 + 可选行为观察（§15.1 / §15.2）。
  ///
  /// 只有工程验证**全部通过**才把状态推进到 Verified；有一项未判定就停在
  /// 原状态并如实报告（§15.4 不得虚报）。
  static Future<ToolEnvelope> _verifyApk(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final path = await _resolveApk(task, (args['path'] ?? '').toString());
    if (path == null) {
      return _fail(
        'verify_apk',
        'NO_ARTIFACT',
        '没有可验证的 APK：output/ 与 build/ 下都没有找到',
      );
    }
    // F-50（2026-10-04）：verify 实际要读 18MB 包并验签，过去 meta 落默认值
    // durationMs:0/cost:0——0 与"真实为 0"不可区分，性能排查被误导。
    final sw = Stopwatch()..start();
    final now = DateTime.now().millisecondsSinceEpoch;
    final engineering = await verifier.verifyEngineering(
      taskId: task.id,
      apkPath: path,
      expectSha256: args['expectSha256']?.toString(),
      now: now,
    );
    final observed = <VerificationCheck>[];
    for (final raw in (args['behavior'] as List? ?? const [])) {
      if (raw is! Map) continue;
      observed.add(
        VerificationCheck(
          name: raw['name']?.toString() ?? 'behavior_check',
          category: CheckCategory.behavior,
          status: raw['passed'] == true
              ? CheckStatus.passed
              : (raw['passed'] == false
                    ? CheckStatus.failed
                    : CheckStatus.notVerified),
          detail: raw['detail']?.toString() ?? '',
        ),
      );
    }
    final behavior = verifier.behavior(
      taskId: task.id,
      artifactPath: path,
      observed: observed,
      now: now,
    );
    final merged = Verifier.merge(task.id, path, [
      engineering,
      behavior,
    ], now: now);

    await _saveVerification(task, merged);
    await runtime.store.appendEvent(
      TaskEventFactory.verified(
        taskId: task.id,
        phase: task.phase.id,
        artifactPath: path,
        engineering: merged.engineeringStatus.id,
        behavior: merged.behaviorStatus.id,
        notVerified: merged.notVerified,
      ),
    );

    var advancedTo = '';
    if (merged.engineeringStatus == CheckStatus.passed &&
        task.status == TaskStatus.signed) {
      try {
        final t = await runtime.advance(
          task.id,
          TaskStatus.verified,
          reason: '工程验证全部通过',
        );
        advancedTo = t.status.label;
      } on AdvanceRejection {
        // 状态没到位就不推进，报告里如实体现
      }
    }

    return ToolEnvelope.success(
      tool: 'verify_apk',
      summary: merged.summaryLine.replaceAll('\n', ' / '),
      meta: ToolMeta(durationMs: sw.elapsedMilliseconds),
      data: {
        'artifactPath': path,
        'checks': [for (final c in merged.checks) c.toJson()],
        'engineering': merged.engineeringStatus.id,
        'behavior': merged.behaviorStatus.id,
        'notVerified': merged.notVerified,
        if (advancedTo.isNotEmpty) 'status': advancedTo,
      },
      warnings: merged.notVerified.isEmpty
          ? const []
          : ['有未验证项：${merged.notVerified.join('、')}'],
    );
  }

  /// 交付清单 + 交付报告（§15.5 / §15.6）。
  static Future<ToolEnvelope> _collectDelivery(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    const reportName = 'delivery-report.json';
    final outDir = Directory(p.join(task.workspacePath, 'output'));
    final items = <Map<String, Object?>>[];
    if (await outDir.exists()) {
      await for (final f in outDir.list(followLinks: false)) {
        if (f is! File) continue;
        if (p.basename(f.path) == reportName) continue; // 报告自己不算交付物
        final bytes = await f.readAsBytes();
        items.add({
          'name': p.basename(f.path),
          'path': f.path,
          'size': bytes.length,
          'sha256': sha256.convert(bytes).toString(),
        });
      }
    }

    // 工程验证（有产物才跑；没产物就留空，不编造结论）
    VerificationResult verification = VerificationResult(taskId: task.id);
    if (items.isNotEmpty) {
      final newest = await _newestApk(task);
      if (newest != null) {
        verification = await verifier.verifyEngineering(
          taskId: task.id,
          apkPath: newest,
          now: DateTime.now().millisecondsSinceEpoch,
        );
      }
    }

    final evidence = await runtime.evidence.load(task.id);
    final conflicts = (await runtime.evidence.loadConflicts(
      task.id,
    )).where((c) => c.resolvedBy.isEmpty).toList();
    final patches = await _patchPlans(runtime, task.id);

    final registered = await runtime.artifacts.list(task.id);
    // v8-D18（2026-10-04 真机）：原始源包——contract.inputApk 会随 makeActive
    // 链式前移（审计看到它漂到去签后的中间件）。台账里 kind=input_apk 的登记
    // 条目才是起源根，优先采用；两值都给出并标注口径。
    var sourceApk = task.contract.inputApk;
    var sourceApkBasis = 'contract_input_chain_head';
    final inputArtifacts = registered
        .where((a) => a.kind == ArtifactKind.inputApk)
        .toList(growable: false);
    if (inputArtifacts.isNotEmpty) {
      sourceApk = inputArtifacts.first.path;
      sourceApkBasis = 'artifact_ledger_input';
      // F-13/F-16（v11 复测）：台账登记的是工作区**副本**路径，交付源头要取
      // 登记时记下的设备原件（originPath）——台账里的设备路径优先于 runtime 副本。
      final origin = inputArtifacts.first.originPath.trim();
      if (origin.isNotEmpty && !origin.contains('/runtime/workspaces/')) {
        sourceApk = origin;
        sourceApkBasis = 'artifact_origin_device_path';
      }
    }
    // F-13/F-16（v9 复测）：runtime 工作区的 input 是**副本**（/data/user/0/
    // .../runtime/workspaces/task_*/input/）——交付源头应是设备上的原包。
    // 台账没有 originPath 的旧任务（或 originPath 自身也在 runtime 空间）时，
    // 退回 builds 台账的 rootSource；再不行保持副本路径并显式标注口径。
    if (sourceApk.contains('/runtime/workspaces/')) {
      final builds = await ApkWorkspaceBindingService.readBuilds();
      for (final build in builds) {
        final root = build['rootSource']?.toString().trim() ?? '';
        if (root.isNotEmpty &&
            !root.contains('/runtime/workspaces/') &&
            await File(root).exists()) {
          sourceApk = root;
          sourceApkBasis = 'builds_ledger_root_source';
          break;
        }
      }
    }
    final sourceApkIsWorkspaceCopy = sourceApk.contains('/runtime/workspaces/');
    final sourceSha = await _sha256Of(sourceApk);
    // v8-D17：patch 视图按操作类型分口径——manifest/permission 类操作把
    // 「元素名」从 DEX 语义的 targetMethod 挪到 targetElement（并给 targetKind），
    // reason 与元素名重复时不再重复入账。
    final patchViews = <Map<String, Object?>>[
      for (final plan in patches)
        () {
          final json = Map<String, Object?>.from(plan);
          final op = (plan['operation'] ?? '').toString().toLowerCase();
          final manifestOp = op.contains('manifest') || op.contains('permission');
          if (manifestOp) {
            final element = (json['targetMethod'] ?? '').toString();
            json['targetKind'] = 'manifest_element';
            json['targetElement'] = element;
            json['targetMethod'] = '';
            if (json['reason'] == element) json['reason'] = '';
          } else {
            json['targetKind'] = 'dex_method';
          }
          return json;
        }(),
    ];
    final report = DeliveryReport(
      taskId: task.id,
      goal: task.contract.goal,
      sourceApk: sourceApk,
      sourceSha256: sourceSha,
      patches: patches,
      evidenceRefs: [for (final e in evidence) e.id],
      verification: verification,
      artifacts: items,
      unverified: [
        ...verification.notVerified,
        if (conflicts.isNotEmpty) '未决证据冲突 ${conflicts.length} 处',
      ],
      risks: [
        if (conflicts.isNotEmpty) '存在未决证据冲突，结论可能不稳',
        if (verification.behaviorStatus != CheckStatus.passed) '目标行为未做运行时验证',
      ],
      cleanup: await runtime.workspace.readManifest(task.id),
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );

    // 报告落盘到交付目录，方便用户直接拿走
    final reportFile = File(p.join(outDir.path, reportName));
    await outDir.create(recursive: true);
    await reportFile.writeAsString(report.toPrettyJson(), flush: true);
    // 镜像到任务目录（2026-09-14 体积治理配套）：工作区会被回收策略清理
    // （无主/超龄/超硬上限），而任务记录保留可查——交付报告跟着记录走，
    // 否则交付页会在工作区回收后显示「还没有交付报告」。失败不影响主流程。
    try {
      final mirror = File(
        p.join((await runtime.store.taskDir(task.id)).path, reportName),
      );
      await mirror.writeAsString(report.toPrettyJson(), flush: true);
    } catch (_) {}

    // 交付收口（§13.2：Delivered = 成品和报告已交付）。报告落盘即视为交付完成，
    // 但状态只能由 Runtime 推进（§13.4），所以这里显式走 advance，模型调这个
    // 工具本身不代表状态会变。
    //
    // 只在「已有产物 + 状态正好停在 Verified」时推进：状态机主链一次只走一格，
    // Signed 及更早（签名成功后 RuntimeBridge 自动写报告时就是这种情况）一律
    // 不跳级，等 verify_apk 把状态推到 Verified 后再交付一次即可收口。
    var deliveredLabel = '';
    String? advanceNote;
    if (task.status == TaskStatus.verified && items.isNotEmpty) {
      try {
        final advanced = await runtime.advance(
          task.id,
          TaskStatus.delivered,
          reason: '交付报告已生成，确认交付收口',
        );
        deliveredLabel = advanced.status.label;
      } on AdvanceRejection catch (e) {
        // 不静默：推进被拒就把原因如实放进信封 warnings
        advanceNote = '交付状态推进被拒：${e.reason}';
      }
    }
    final statusLabel = deliveredLabel.isEmpty
        ? task.status.label
        : deliveredLabel;

    return ToolEnvelope.success(
      tool: 'collect_delivery',
      // v8-D16（2026-10-04 真机）：summary 不能只说目录——台账有登记产物而
      // output/ 为空时，旧文案「交付目录还没有产物」与 registeredArtifacts
      // 自相矛盾（审计正是在这种状态下抓到）。
      summary: items.isEmpty
          ? (registered.isEmpty
                ? '交付目录还没有产物'
                : '交付目录为空，但台账有 ${registered.length} 个登记产物（见 registeredArtifacts）')
          : '${items.length} 个交付物',
      data: {
        'note': args['note']?.toString() ?? '',
        'sourceApk': sourceApk,
        'sourceSha256': sourceSha,
        'sourceApkBasis': sourceApkBasis,
        // F-13/F-16（v11 复测）：口径显式化——即便是副本路径也标出来，
        // 审计不必再自己分辨「设备根 / runtime 根」两套路径。
        'sourceApkIsWorkspaceCopy': sourceApkIsWorkspaceCopy,
        if (sourceApkIsWorkspaceCopy)
          'sourceApkNote':
              'sourceApk 指向任务工作区的只读副本（runtime 空间）：该任务创建于'
              '「登记设备原件路径（originPath）」之前，且 builds 台账里没有可用的'
              'rootSource。要引用设备原件请改用同一任务的设备侧路径复核。',
        'status': statusLabel,
        'artifacts': items,
        // 登记过的产物（含类型与血缘）——成品是哪一步出来的，这里说得清。
        // F-13/F-16（v13 复测）：台账条目的主 path 过去一律是 runtime 工作区
        // 副本（设备根命名空间里不可达）。有设备原件映射（originPath）的条目把
        // 主 path 换成设备路径、副本降为 workspaceCopyPath 附加字段——交付台账
        // 在设备根内整体可达，路径分裂消除。
        'registeredArtifacts': <Map<String, Object?>>[
          for (final a in registered)
            if (a.originPath.trim().isNotEmpty &&
                !a.originPath.contains('/runtime/workspaces/'))
              <String, Object?>{
                ...a.toJson(),
                'path': a.originPath,
                'workspaceCopyPath': a.path,
                'pathBasis': 'origin_device_path',
              }
            else
              <String, Object?>{...a.toJson(), 'pathBasis': 'workspace_path'},
        ],
        'patches': patchViews,
        'evidenceCount': evidence.length,
        'unresolvedConflicts': conflicts.length,
        'engineering': verification.engineeringStatus.id,
        'behavior': verification.behaviorStatus.id,
        // D16：目录无产物=工程验证根本没跑（过去 unverified 为空与
        // engineering:not_verified 并排，读起来像"验证过且没问题"）。
        'verificationSkipped': items.isEmpty,
        'unverified': [
          if (items.isEmpty) '交付目录无产物，本目录未跑工程验证（台账产物见 registeredArtifacts）',
          ...report.unverified,
        ],
        'reportPath': reportFile.path,
        'summary': report.summaryLine,
      },
      warnings: [
        if (items.isEmpty)
          registered.isEmpty
              ? '交付目录为空'
              : '交付目录为空，但台账已登记 ${registered.length} 个产物（可能不在本目录）',
        if (sourceApkIsWorkspaceCopy)
          'sourceApk 是工作区只读副本（runtime 路径），未解析到设备原件（旧任务缺 originPath）',
        if (advanceNote != null) advanceNote,
      ],
    );
  }

  // ------------------------------------------------- 运行时桥用的内部入口

  /// 交付报告落盘（供 [RuntimeBridge] 在签名成功后自动调用）。
  ///
  /// 与 `collect_delivery` 工具共用同一实现，避免两处汇总逻辑漂移。
  static Future<void> writeDeliveryReport(
    Task task,
    TaskRuntime runtime,
  ) async {
    await _collectDelivery(task, const <String, dynamic>{}, runtime);
  }

  /// 登记一条「已落地的修改」事件（计划 + 预览契约通过），供运行时桥在
  /// 写类工具成功后自动调用。这些事件是修改预览页的数据源，也是状态机
  /// 走到 Modified 的依据；模型不直接调用它，所以不走权限门控。
  ///
  /// 幂等键 = 工具 + 目标产物 + 参数签名（2026-09-14 真机反馈）：
  /// 旧实现只按「工具 + 目标」去重，且只在状态未过 DryRunVerified 时登记，
  /// 结果是**一条任务里只有第一次修改会出现在预览页**。现在按参数签名去重，
  /// 每次实质不同的修改都会登记一条，重复调用同一参数仍然只有一条。
  static Future<void> recordLandedPatch({
    required Task task,
    required TaskRuntime runtime,
    required String tool,
    required Map<String, dynamic> args,
    required Map<String, Object?> data,
  }) async {
    final patchId = 'patch_${DateTime.now().microsecondsSinceEpoch}';
    final output =
        (data['outputPath'] ??
                data['outputApk'] ??
                // file 工具的产物字段（zip/unzip 用 output，copy/rename 用 target）：
                // 此前不认这两个键 → 台账把任务输入 APK 或源目录当成目标
                // （2026-10-03 报告 F-17：targetMethod 被填成 't_probe' 之类）。
                data['output'] ??
                data['target'] ??
                data['signedPath'] ??
                data['path'] ??
                '')
            .toString();
    final targetArtifact = output.isEmpty
        ? p.basename(task.contract.inputApk)
        : p.basename(output);
    // 幂等：同一工具 + 同一目标 + 同一参数只登记一次，避免同一调用重复登记
    // 把预览页刷成一片重复；参数变了（换方法/换字段/换文件）就是新的一条。
    final signature = patchArgsSignature(args);
    final events = await runtime.store.loadEvents(task.id);
    final already = events.any(
      (e) =>
          e.type == 'patch.planned' &&
          e.payload['operation']?.toString() == tool &&
          e.payload['targetArtifact']?.toString() == targetArtifact &&
          (e.payload['argsSignature']?.toString() ?? '') == signature,
    );
    if (already) return;
    await runtime.store.appendEvent(
      TaskEventFactory.patchPlan(
        taskId: task.id,
        phase: task.phase.id,
        patchId: patchId,
        payload: {
          'targetArtifact': targetArtifact,
          // 目标方法与 reason 共用同一份参数解析：数组形态的改动目标
          // （classMethods/replacements…）此前两条都取不到，预览条目只剩
          // 工具名（2026-09-15 复核）。
          // file 工具的写操作没有「方法」概念：留空，别把文件/目录名填进
          // targetMethod 污染补丁审计（2026-10-03 报告 F-17）。
          'targetMethod': tool == 'file' ? '' : patchTargetOf(args),
          'operation': tool,
          'action': (args['action'] ?? '').toString(),
          'reason': patchReason(args),
          'risk': patchRisk(tool, args),
          'evidenceIds': const <String>[],
          'requiresConfirmation': true,
          'rollback': 'restore_backup_artifact',
          'argsSignature': signature,
        },
      ),
    );
    // 能落地就说明工具自带的预览/确认门已通过（写类工具的统一契约）。
    await runtime.store.appendEvent(
      TaskEventFactory.patchDryRun(
        taskId: task.id,
        phase: task.phase.id,
        patchId: patchId,
        passed: true,
        checks: const <Map<String, Object?>>[
          {
            'name': 'tool_preview_contract',
            'passed': true,
            'detail': '工具自带预览/确认门控，落地即通过',
          },
        ],
      ),
    );
  }

  /// 参数签名：去掉只影响执行方式、不影响「改了什么」的易变键后做稳定序列化。
  static String patchArgsSignature(Map<String, dynamic> args) {
    const volatile = <String>{
      'dryRun',
      'applyAfterPreview',
      'previewToken',
      'sign',
      'async',
      'wait',
      'note',
      'timeoutMs',
      'sessionId',
      'apkPath', // 输入路径：真正的目标由 targetArtifact 表达
    };
    final keys = args.keys.where((k) => !volatile.contains(k)).toList()..sort();
    final buf = StringBuffer();
    for (final k in keys) {
      final v = args[k];
      if (v == null) continue;
      buf.write(k);
      buf.write('=');
      buf.write(v is Map || v is List ? jsonEncode(v) : v.toString());
      buf.write(';');
    }
    return buf.toString();
  }

  /// 给预览卡片的一句「依据」：把这次调用动了什么说清楚。
  ///
  /// 真实写工具的改动目标是**数组参数**（patch_apk_dex_methods 的
  /// classMethods/voidMethods/trueMethods、patch_apk_dex_strings 的
  /// replacements、patch_apk_manifest 的 removeComponents…），此前只认
  /// qualifiedId/method/target 这类字符串键 → 数组形态的调用一律退回
  /// 「工具执行成功」，预览页只剩条目没有内容（2026-09-15 用户点名
  /// 弹层「没有数据、不详细」）。
  static String patchReason(Map<String, dynamic> args) {
    final action = (args['action'] ?? '').toString();
    final target = patchTargetOf(args);
    final parts = <String>[
      if (action.isNotEmpty) action,
      if (target.isNotEmpty) target,
      if (args['edits'] is List) '${(args['edits'] as List).length} 处改动',
    ];
    return parts.isEmpty ? '工具执行成功' : parts.join(' · ');
  }

  /// 从一次写调用的参数里取出「改的是哪」的人话描述。
  ///
  /// 优先级：显式目标键 → 数组参数的条目（最多两条 + 共 N 处）→ 文件路径。
  /// 只做展示，不影响任何执行逻辑。
  static String patchTargetOf(Map<String, dynamic> args) {
    for (final key in const [
      'qualifiedId',
      'qualifiedIds',
      'method',
      'methods',
      'fieldLocator',
      'target',
      'va',
      'locator',
      'entryName',
    ]) {
      final v = args[key];
      if (v is String && v.trim().isNotEmpty) return v.trim();
      if (v is List && v.isNotEmpty) {
        return _joinedTargets(v);
      }
    }
    // 数组形态的改动目标：把第一个列表参数的条目当目标说清楚。
    for (final key in const [
      'classMethods',
      'voidMethods',
      'trueMethods',
      'falseMethods',
      'removeComponents',
      'removePermissions',
      'removeMetaData',
      'patchEntries',
    ]) {
      final v = args[key];
      if (v is List && v.isNotEmpty) return _joinedTargets(v);
    }
    // replacements 是 {old: new} 映射：说清替换了什么，几组时带总数。
    final repl = args['replacements'];
    if (repl is Map && repl.isNotEmpty) {
      final first = repl.entries.first;
      final more = repl.length > 1 ? ' 等 ${repl.length} 组' : '';
      return '${first.key} → ${first.value}$more';
    }
    if (repl is List && repl.isNotEmpty) {
      final first = repl.first;
      if (first is Map) {
        return '${first['from'] ?? ''} → ${first['to'] ?? ''}'
            '${repl.length > 1 ? ' 等 ${repl.length} 组' : ''}';
      }
    }
    for (final key in const ['path', 'sourcePath', 'soPath', 'apkPath']) {
      final v = args[key]?.toString().trim();
      if (v != null && v.isNotEmpty) return p.basename(v);
    }
    return '';
  }

  /// 列表目标：取前两条，多出来的写成「等 N 处」。
  static String _joinedTargets(List<dynamic> items) {
    final head = [for (final x in items.take(2)) x.toString()];
    return head.length == items.length
        ? head.join('、')
        : '${head.join('、')} 等 ${items.length} 处';
  }

  /// 风险等级：绕过签名校验 / 高危动作为 high，其余 medium。
  static String patchRisk(String tool, Map<String, dynamic> args) {
    if (tool == 'signature_bypass') return 'high';
    final action = (args['action'] ?? '').toString();
    if (const {'edit_symbol', 'build'}.contains(action)) return 'high';
    return 'medium';
  }

  // ---------------------------------------------------------------- 辅助

  /// 解析产物路径：给了就用；没给就取 output/ → build/ 里最新的 APK。
  static Future<String?> _resolveApk(Task task, String raw) async {
    final s = raw.trim();
    if (s.isEmpty) return _newestApk(task);
    if (p.isAbsolute(s)) return s;
    // v6 D4 / F-32：裸文件名先按**统一工作目录**解析（用户把文件放那里），
    // 找不到再退任务运行时工作区——此前只认任务工作区，工作目录里的文件
    // 必然 misresolve 成「产物不存在」。
    final workDir = await ApkWorkspaceBindingService.workDir();
    if (workDir != null && workDir.trim().isNotEmpty) {
      final candidate = p.join(workDir, p.normalize(s));
      if (await File(candidate).exists()) return candidate;
    }
    final inTask = p.join(task.workspacePath, p.normalize(s));
    if (await File(inTask).exists()) return inTask;
    return inTask;
  }

  static Future<String?> _newestApk(Task task) async {
    for (final sub in const ['output', 'build']) {
      final dir = Directory(p.join(task.workspacePath, sub));
      if (!await dir.exists()) continue;
      File? best;
      DateTime? bestTime;
      await for (final f in dir.list(followLinks: false)) {
        if (f is! File) continue;
        if (!f.path.toLowerCase().endsWith('.apk')) continue;
        final st = await f.stat();
        if (bestTime == null || st.modified.isAfter(bestTime)) {
          best = f;
          bestTime = st.modified;
        }
      }
      if (best != null) return best.path;
    }
    return null;
  }

  static Future<String> _sha256Of(String path) async {
    try {
      final f = File(path);
      if (!await f.exists()) return '';
      return sha256.convert(await f.readAsBytes()).toString();
    } catch (_) {
      return '';
    }
  }

  /// 从事件流里取出已登记的 Patch Plan（交付报告要写清「改了什么」）。
  static Future<List<Map<String, Object?>>> _patchPlans(
    TaskRuntime runtime,
    String taskId,
  ) async {
    final events = await runtime.store.loadEvents(taskId);
    return [
      for (final e in events)
        if (e.type == 'patch.planned')
          {
            'patchId': e.payload['patchId'],
            'targetArtifact': e.payload['targetArtifact'],
            'targetMethod': e.payload['targetMethod'],
            'operation': e.payload['operation'],
            'reason': e.payload['reason'],
            'risk': e.payload['risk'],
          },
    ];
  }

  static Future<void> _saveVerification(
    Task task,
    VerificationResult result,
  ) async {
    final dir = Directory(p.join(task.workspacePath, 'evidence'));
    await dir.create(recursive: true);
    await File(
      p.join(dir.path, 'verification.json'),
    ).writeAsString(jsonEncode(result.toJson()), flush: true);
  }

  static Future<ToolEnvelope> _workspaceCleanup(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final keepAnalysis = args['keepAnalysis'] == true;
    final rec = await runtime.workspace.cleanup(
      task.id,
      now: DateTime.now().millisecondsSinceEpoch,
      keepAnalysis: keepAnalysis,
    );
    await runtime.store.appendEvent(
      TaskEventFactory.cleanup(
        taskId: task.id,
        phase: task.phase.id,
        purged: rec.purged,
        kept: rec.kept,
        failed: rec.failed,
      ),
    );
    return ToolEnvelope.success(
      tool: 'workspace_cleanup',
      summary: '清理完成：删除 ${rec.purged.length} 项，保留 ${rec.kept.length} 项',
      data: {'purged': rec.purged, 'kept': rec.kept, 'failed': rec.failed},
      warnings: rec.failed.isEmpty ? const [] : ['部分目录删除失败'],
    );
  }

  static Future<ToolEnvelope> _requestConfirmation(
    Task task,
    Map<String, dynamic> args,
    TaskRuntime runtime,
  ) async {
    final reason = (args['reason'] ?? '').toString();
    if (reason.isEmpty) {
      return _fail('request_confirmation', 'BAD_ARGS', '缺 reason');
    }
    await runtime.awaitConfirmation(task.id, reason: reason);
    return ToolEnvelope.success(
      tool: 'request_confirmation',
      summary: '已转入等待用户确认',
      data: {'reason': reason},
    );
  }

  // ---------------------------------------------------------------- 工具函数

  /// 接受 label / id 两种写法。
  static TaskStatus? _statusFromInput(String raw) {
    if (raw.isEmpty) return null;
    final lower = raw.toLowerCase();
    for (final s in TaskStatus.values) {
      if (s.label.toLowerCase() == lower) return s;
    }
    return null;
  }

  static String _encodeToken(int offset) =>
      base64Url.encode(utf8.encode('o:$offset'));

  static int? _decodeToken(String token) {
    try {
      final raw = utf8.decode(base64Url.decode(token));
      if (!raw.startsWith('o:')) return null;
      return int.tryParse(raw.substring(2));
    } catch (_) {
      return null;
    }
  }

  static ToolEnvelope _fail(String tool, String code, String message) =>
      ToolEnvelope.failure(tool: tool, code: code, message: message);
}

/// 事件构造（把 payload 拼装集中在一处，避免各调用点各写一套）。
class TaskEventFactory {
  TaskEventFactory._();

  static TaskEvent _base(
    String taskId,
    String type,
    String phase,
    Map<String, Object?> payload,
  ) => TaskEvent(
    id: 'evt_${DateTime.now().microsecondsSinceEpoch}',
    taskId: taskId,
    type: type,
    phase: phase,
    payload: payload,
    createdAt: DateTime.now().millisecondsSinceEpoch,
  );

  static TaskEvent route({
    required String taskId,
    required String phase,
    required List<Map<String, Object?>> routes,
    required String nextAction,
  }) => _base(taskId, 'task.routed', phase, {
    'routes': routes,
    'nextAction': nextAction,
  });

  static TaskEvent patchPlan({
    required String taskId,
    required String phase,
    required String patchId,
    required Map<String, Object?> payload,
  }) => _base(taskId, 'patch.planned', phase, {'patchId': patchId, ...payload});

  static TaskEvent patchDryRun({
    required String taskId,
    required String phase,
    required String patchId,
    required bool passed,
    required List<Map<String, Object?>> checks,
  }) => _base(taskId, 'patch.dry_run', phase, {
    'patchId': patchId,
    'passed': passed,
    'checks': checks,
  });

  static TaskEvent cleanup({
    required String taskId,
    required String phase,
    required List<String> purged,
    required List<String> kept,
    required List<String> failed,
  }) => _base(taskId, 'workspace.cleanup', phase, {
    'purged': purged,
    'kept': kept,
    'failed': failed,
  });

  static TaskEvent verified({
    required String taskId,
    required String phase,
    required String artifactPath,
    required String engineering,
    required String behavior,
    required List<String> notVerified,
  }) => _base(taskId, 'verify.completed', phase, {
    'artifactPath': artifactPath,
    'engineering': engineering,
    'behavior': behavior,
    'notVerified': notVerified,
  });
}
