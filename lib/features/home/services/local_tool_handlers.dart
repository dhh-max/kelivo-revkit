part of 'local_tools_service.dart';

Future<String> _handleApkProjectInfo(ToolContext context) async {
  final repository = context.chatService?.chatRepositoryOrNull;
  if (repository == null) {
    return jsonEncode({
      'error': 'chat_service_unavailable',
      'message': '聊天服务尚未就绪，请稍后再试。',
    });
  }
  final service = ApkProjectService(repository);
  final report = await _readPatchMemoryReport();
  final activeTarget = await ApkWorkspaceBindingService.activeApkPath();
  final resumeState = await ApkWorkspaceBindingService.taskResumeState();
  if (report == null) {
    if (activeTarget != null && activeTarget.isNotEmpty) {
      return jsonEncode({
        'boundApk': activeTarget,
        'source': 'last_modified',
        'report': null,
        'workflow': _projectWorkflowState(null, resumeState),
        'message':
            '工作台暂无本地分析报告，但存在最近修改的目标（见 boundApk）。可先 analyze_apk_workspace 重建报告，或用 dex_search / dex_xref 获取细节。',
      });
    }
    return jsonEncode({
      'error': 'no_apk_selected',
      'workflow': _projectWorkflowState(null, resumeState),
      'message': '当前没有 APK 项目，请先在 APK 工作台选择 APK 并完成分析。',
    });
  }
  final project = await service.findBySha256(
    (report['sha256'] ?? '').toString(),
  );
  if (project == null) {
    return jsonEncode({
      'error': 'project_not_found',
      'message': '当前报告没有对应的项目记录，请重新在 APK 工作台分析。',
      'sha256': report['sha256'],
    });
  }
  final info = service.projectInfoForAi(project);
  final sourceApk = report['sourceApk'];
  final freshness = await _freshnessWithBoundApk(report, activeTarget);
  // 已处理产物身份检测：绑定目标（或报告源）是本工具链成品时显式标注，
  // 防止把成品当原包重做（用户实测缺陷）。
  final identityTarget = (activeTarget != null && activeTarget.isNotEmpty)
      ? activeTarget
      : (sourceApk is Map ? sourceApk['path']?.toString() : null);
  final artifactIdentity = (identityTarget != null && identityTarget.isNotEmpty)
      ? await ApkArtifactIdentityService.identify(
          identityTarget,
          memoryRepository: context.memoryRepository,
        )
      : null;
  return jsonEncode({
    ...info,
    'analysisVersion':
        (report['analysisVersion'] as num?)?.toInt() ?? info['analysisVersion'],
    if (sourceApk is Map) 'reportSourceApk': sourceApk,
    if (activeTarget != null && activeTarget.isNotEmpty)
      'boundApk': activeTarget,
    'reportFreshness': freshness,
    if (artifactIdentity != null) 'artifactIdentity': artifactIdentity.toJson(),
    if (artifactIdentity != null) 'identityGuidance': artifactIdentity.guidance,
    'workflow': _projectWorkflowState(freshness, resumeState),
    ...(await _incrementalBuildContext(activeTarget, sourceApk)),
    'source': 'explicit',
    'consistencyHint':
        '对比 reportSourceApk（报告对应 APK）与 boundApk（当前连续修改目标）：'
        '文件名不一致或报告 sourceApk 缺失时，报告可能对应旧 APK 或当前目标是'
        '另一个 APK，必须先用 analyze_apk_workspace 重新分析当前目标再执行修改。'
        'artifactIdentity.isProcessedArtifact=true 时当前目标是本工具链成品，'
        '只能叠加修改，禁止当原包重做。',
  });
}

Map<String, dynamic> _projectWorkflowState(
  Map<String, dynamic>? freshness,
  Map<String, dynamic> resumeState,
) {
  final stale = freshness?['status'] == 'stale';
  final activeArtifact = resumeState['activeArtifact'];
  final waitingVerification =
      activeArtifact is Map &&
      activeArtifact['pendingMemoryStatus'] == 'awaiting_user_verification';
  final stage = freshness == null
      ? 'analysis_required'
      : stale
      ? 'analysis_stale'
      : waitingVerification
      ? 'verification_required'
      : 'analysis_ready';
  return {
    'stage': stage,
    'nextTool': switch (stage) {
      'analysis_required' ||
      'analysis_stale' => LocalToolNames.apkAnalyzeWorkspace,
      'verification_required' => LocalToolNames.askUser,
      _ => LocalToolNames.apkReport,
    },
    'activeApk': resumeState['activeApk'],
    'activeApkExists': resumeState['activeApkExists'] == true,
    'recentCheckpoints': resumeState['recentToolCheckpoints'] ?? const [],
    if (activeArtifact is Map) 'activeArtifact': activeArtifact,
  };
}

/// 路由结果里既没有轨道也没有推荐工具 → 视为"空路由"（通用问答/闲聊）。
bool _routeHasNoTools(Map<String, dynamic> route) {
  final tools = route['recommendedTools'];
  final tracks = route['tracks'];
  final noTools = tools is! List || tools.isEmpty;
  final noTracks = tracks is! List || tracks.isEmpty;
  return noTools && noTracks;
}

/// 当前工作台绑定且真实存在的 APK（工作区感知路由用；任何异常都当作"没有"）。
Future<String> _routeActiveApkPath() async {
  try {
    final active = await ApkWorkspaceBindingService.activeApkPath();
    final path = (active ?? '').trim();
    if (path.isEmpty) return '';
    return await File(path).exists() ? path : '';
  } catch (_) {
    return '';
  }
}

/// 轨道条目里出现过的工具名全集（用于区分"工具名"与描述性自由文本）。
final Set<String> _routeKnownToolNames = <String>{
  ...LocalToolNames.all,
  ...AnalyzerToolNames.all,
  ...AnalyzerToolNames.all.map(AnalyzerToolNames.publishedName),
};

/// 第 60 项：判断轨道里的一个工具条目在当前助手面是否真的可调用。
/// 条目可能是裸名（`dex_xref`）或描述式写法（`so_analyze(search/xref)`）——
/// 后者按括号前的基础名判定；非工具名的自由文本一律保留，只有"确定是工具、
/// 但当前面调不动"才丢弃。
bool _routeToolCallable(String entry, Set<String> availableTools) {
  final base = entry.split('(').first.trim();
  if (base.isEmpty) return false;
  if (!_routeKnownToolNames.contains(base)) return true;
  if (availableTools.contains(base)) return true;
  // localToolIds 存 analyzer 内部名（analyzer.find_field_usage），MCP 面与轨道
  // 写发布名（analyzer_find_field_usage）：必须互查，否则会把 SoLab 助手本来
  // 能调的 analyzer 工具误删。
  final internal = AnalyzerToolNames.internalName(base);
  return internal != base && availableTools.contains(internal);
}

Future<String> _handleRouteTask(
  Map<String, dynamic> args,
  ToolContext context,
) async {
  final goal = (args['goal'] ?? '').toString();
  var route = TaskRouter.route(goal);
  // 工作区感知重路由（2026-09-15 真机 P1）：goal 里没写 APK 关键词时会被判成
  // 通用问答、recommendedTools 为空——哪怕工作目录里就有 APK、上一轮还在改它，
  // Agent 因此拿到一条"什么工具都没有"的轨道。有在分析的 APK 时用「目标 +
  // 工作区上下文」重路由一次，来源如实标注。
  if (_routeHasNoTools(route)) {
    final activeApk = await _routeActiveApkPath();
    if (activeApk.isNotEmpty) {
      final contextual = TaskRouter.route('$goal · 已选 APK：$activeApk');
      if (!_routeHasNoTools(contextual)) {
        route = contextual;
        route['contextBias'] = 'workspace_apk_present';
        route['contextNote'] =
            'goal 未含 APK 关键词，但工作区已有在分析的 APK（$activeApk），已按 APK 任务路由。';
      } else {
        route['contextNote'] =
            '工作区已有 APK（$activeApk），但目标没指向 APK 任务；要处理它请在 goal 里写明动作。';
      }
    }
  }
  final availableTools = context.assistant.localToolIds.toSet();
  final agentContextTools = <String, bool>{
    LocalToolNames.agentRuntimeGuide: availableTools.contains(
      LocalToolNames.agentRuntimeGuide,
    ),
    LocalToolNames.apkKnowledge: availableTools.contains(
      LocalToolNames.apkKnowledge,
    ),
    LocalToolNames.installedSkills: availableTools.contains(
      LocalToolNames.installedSkills,
    ),
    LocalToolNames.apkSkill: availableTools.contains(LocalToolNames.apkSkill),
  };
  final recommended = route['recommendedTools'];
  if (recommended is List) {
    route['recommendedTools'] = recommended
        .map((tool) => tool.toString())
        .where(availableTools.contains)
        .toList(growable: false);
  }
  // 第 60 项：同一把尺子必须也用到 evidenceRoutes[].tools。此前只有
  // recommendedTools 按当前面过滤，evidenceRoutes 是原样照抄的轨道声明——开发助手
  // （toolIds 只有 route_task/workspace_policy/file/todo_*/subagent/agent_runtime_guide）
  // 调 route_task 时 recommendedTools 被诚实清空，同一 payload 却仍列出 dex_search /
  // string_scan / class_outline / dex_xref / smali_read / get_current_apk_report 等它
  // 调不动的工具（实测 8 条），与下面 modeCapabilities.note「只推荐当前模式真实可
  // 调用的工具」自相矛盾，模型会去点不存在的工具。轨道里的 actionPlan 没有被
  // TaskRouter 带进本 payload，故只需处理这里。
  final evidenceRoutes = route['evidenceRoutes'];
  if (evidenceRoutes is List) {
    route['evidenceRoutes'] = <dynamic>[
      for (final evidence in evidenceRoutes)
        evidence is Map
            ? <String, dynamic>{
                ...Map<String, dynamic>.from(evidence),
                if (evidence['tools'] is List)
                  'tools': <String>[
                    for (final tool in evidence['tools'] as List)
                      if (_routeToolCallable(tool.toString(), availableTools))
                        tool.toString(),
                  ],
              }
            : evidence,
    ];
  }
  final requiredSkills = route['requiredSkills'];
  if (requiredSkills is List &&
      agentContextTools[LocalToolNames.apkSkill] != true) {
    route['requiredSkills'] = const <String>[];
  }
  route['modeCapabilities'] = {
    'mode': agentContextTools.values.any((available) => available)
        ? 'agent'
        : 'mcp',
    'agentContextTools': agentContextTools,
    'unavailableAgentExtensions': [
      for (final entry in agentContextTools.entries)
        if (!entry.value) entry.key,
    ],
    'note': '只推荐当前模式真实可调用的工具；MCP 可复用共同分析核心，Agent 额外拥有按需知识、Skill、记忆和交互能力。',
  };
  final membershipTask = RegExp(
    r'会员|权益|vip|svip|premium|member|membership|pro|订阅|subscription|到期|过期|expiry|lifetime',
    caseSensitive: false,
  ).hasMatch(goal);
  if (membershipTask) {
    try {
      final report = await ApkWorkspaceService.readReport();
      final flutter = report?['flutterApp'];
      final detected = flutter is Map ? flutter['detected'] : null;
      if (detected is bool) {
        route['toolTrack'] = detected ? 'flutter_vip' : 'dex_native';
        route['toolTracks'] = detected
            ? ['flutter_vip', 'dex_native']
            : ['dex_native'];
        route['layerHints'] = {
          'primaryLayer': detected ? 'dart' : 'native_dex',
          'availableLayers': detected
              ? ['dart', 'native_dex', 'native_so', 'resources']
              : ['native_dex', 'native_so', 'resources'],
          'evidence': ['report.flutterApp.detected=$detected（当前工作台 APK 实证）'],
          'note': 'primaryLayer 只是优先假设,不排除其他层；可按现有 locator 自由切换或组合。',
        };
        if (detected && agentContextTools[LocalToolNames.apkSkill] == true) {
          final skills = <String>{
            for (final skill
                in (route['requiredSkills'] as List? ?? const <dynamic>[]))
              skill.toString(),
            'apk_flutter_locate',
            'flutter_vip_unlock',
          };
          route['requiredSkills'] = skills.toList(growable: false);
        }
      }
    } catch (_) {}
  }
  if (agentContextTools[LocalToolNames.apkSkill] == true) {
    final activations = <Map<String, dynamic>>[
      for (final skill
          in (route['requiredSkills'] as List? ?? const <dynamic>[]))
        if (SolabBuiltinSkills.activation(skill.toString()) case final activation?)
          activation,
    ];
    if (activations.isNotEmpty) {
      route['activeBuiltInSkills'] = activations;
      route['skillInstruction'] =
          'activeBuiltInSkills 已在本轮生效，直接遵守 rules；只有完整技能正文会改变下一步时才调用 fullSkillTool，禁止重复读取。';
    }
  }
  final topics = (route['knowledgeTopics'] as List? ?? const <dynamic>[])
      .map((topic) => topic.toString())
      .toList(growable: false);
  final installedSkillProvider = context.agentSkillProvider;
  if (installedSkillProvider != null && topics.isNotEmpty) {
    try {
      await installedSkillProvider.initialize();
      final installed = installedSkillProvider.retrieve(
        topics: topics,
        limit: 3,
      );
      if (installed.isNotEmpty) {
        String cap(String text, int max) =>
            text.length <= max ? text : '${text.substring(0, max)}…';
        route['activeInstalledSkills'] = [
          for (final skill in installed)
            {
              'id': skill.id,
              'name': skill.name,
              'topics': skill.topics,
              'content': cap(skill.content, 800),
              'contentTruncated': skill.content.length > 800,
            },
        ];
        route['installedSkillInstruction'] =
            '这些启用且相关的用户 Skill 已在本轮生效；只执行适用部分，事实与权限边界仍以当前工具结果为准。';
      }
    } catch (_) {}
  }
  final worldBookProvider = context.worldBookProvider;
  if (worldBookProvider != null) {
    if (topics.isNotEmpty) {
      try {
        await worldBookProvider.initialize();
        final entries = worldBookProvider.retrieveActiveEntries(
          assistantId: context.assistant.id,
          topics: topics,
          limit: 3,
        );
        if (entries.isNotEmpty) {
          String cap(String text, int max) =>
              text.length <= max ? text : '${text.substring(0, max)}…';
          route['prefetchedKnowledge'] = {
            'top': {
              'entryName': entries.first['entryName'],
              'content': cap(entries.first['content'].toString(), 800),
            },
            'moreEntries': [
              for (final entry in entries.skip(1)) entry['entryName'],
            ],
            'note':
                '最高分条目已直接附上；moreEntries 里的条目按需用 get_apk_knowledge(topics) 读取。',
          };
          ToolSessionState.recordPrefetchedKnowledge(
            _toolSessionKey(context.assistant, context.conversationId),
            entries.first['entryName'].toString(),
          );
        }
      } catch (_) {}
    }
  }
  // 路由语义显式化：route_task 只做轨道/技能/知识推荐，不执行任何工具、
  // 不产生产物。此前返回经 MCP normalize 后统一盖 ok:true，与真实执行
  // 工具在 envelope 上不可区分（实测被误读为"路由动作已执行"）。
  route['routingOnly'] = true;
  // 报告 2-8：recommendedTools 被"当前面可调用"过滤后为空时，过去只给一个空数组，
  // 调用方读成「没有下一步」。现在明确区分两种情况：**轨道本身没推荐** vs
  // **有轨道但本会话没开这些工具**，后者给可执行的替代路径。
  final recommendedFinal = route['recommendedTools'];
  if (recommendedFinal is List && recommendedFinal.isEmpty) {
    final hasReverseFace = <String>[
      LocalToolNames.soAnalyze,
      LocalToolNames.smaliRead,
      LocalToolNames.dexSearch,
    ].any(availableTools.contains);
    route['recommendationEmptyReason'] = <String, dynamic>{
      'reason': 'no_recommendation_callable_in_this_face',
      'message':
          '这条轨道需要的工具在当前助手工具面里不可调用，所以 recommendedTools 为空——'
          '不是「没有路线」，而是「路线在你这边调不动」。',
      'availableToolCount': availableTools.length,
      'nextActions': <String>[
        '要 APK 逆向能力：切到「逆向助手」（工具面含 apk_reverse 域）再调 route_task',
        '只用现有工具推进：file 采集证据 / shell 跑命令 / get_workspace_policy 看边界，再复核结论',
        if (hasReverseFace)
          '当前面已含逆向域：把 goal 写成具体动作（如「定位会员校验并给出 patch 方案」）'
        else
          '把 goal 写成具体动作（定位/验证/产出），路由才会命中该面可执行的轨道',
      ],
    };
  }
  return jsonEncode(route);
}

Future<String> _handleAgentRuntimeGuide(
  Map<String, dynamic> args,
  Assistant assistant,
  MemoryRepository? memoryRepository,
  WorldBookProvider? worldBookProvider,
  AgentSkillProvider? agentSkillProvider,
  InstructionInjectionProvider? instructionInjectionProvider,
) async {
  final runtimeToolNames = _runtimeToolNames(args, assistant);
  Future<bool> initialize(Future<void> Function()? action) async {
    if (action == null) return false;
    try {
      await action();
      return true;
    } catch (_) {
      return false;
    }
  }

  final readiness = await Future.wait<bool>([
    initialize(worldBookProvider?.initialize),
    initialize(agentSkillProvider?.initialize),
    initialize(instructionInjectionProvider?.initialize),
  ]);
  final activeBookIds =
      worldBookProvider?.activeBookIdsFor(assistant.id).toSet() ??
      const <String>{};
  final activeBooks =
      worldBookProvider?.books
          .where((book) => book.enabled && activeBookIds.contains(book.id))
          .map((book) => book.name)
          .toList(growable: false) ??
      const <String>[];
  final injections =
      instructionInjectionProvider
          ?.activesFor(assistant.id)
          .map(
            (injection) => {
              'title': injection.title,
              if (injection.group.isNotEmpty) 'group': injection.group,
            },
          )
          .toList(growable: false) ??
      const <Map<String, String>>[];
  final installedSkillCount =
      agentSkillProvider?.skills.where((skill) => skill.enabled).length ?? 0;
  final activeBookEntries =
      worldBookProvider?.books
          .where((book) => book.enabled && activeBookIds.contains(book.id))
          .expand((book) => book.entries)
          .where((entry) => entry.enabled && entry.content.trim().isNotEmpty)
          .length ??
      0;
  final injectionPromptChars =
      instructionInjectionProvider
          ?.activesFor(assistant.id)
          .fold<int>(0, (sum, item) => sum + item.prompt.trim().length) ??
      0;

  return jsonEncode(
    {
      'automatic': {
        'instructionInjections': {
          'active': injections,
          'when': '应用在每次请求的 system 提示末尾自动追加；不要再次索取完整文本。',
        },
        'memory': {
          'enabled': assistant.enableMemory,
          'autoOrganize': assistant.autoOrganizeMemory,
          'repositoryAvailable': memoryRepository != null,
          'promptMode': 'system_rules_plus_on_demand_index',
          'memoryContentAutoInjected': false,
          'tools': [
            'memory_read',
            'memory_update',
            'memory_search_profile',
            'memory_edit',
            'memory_delete',
            'update_user_profile',
          ],
          'when': '按任务相关性读取；只保存用户确认的稳定偏好和工作流。',
        },
        'pastConversationRecall': {
          'enabled': assistant.allowPastConversationRecall,
          'tool': 'chat_search',
          'when': '需要历史对话证据时按需检索，不把历史摘要当成当前 APK 事实。',
        },
        'customFeatures': {'when': '规则仅在当前报告出现对应命中、或下一步确实依赖规则时读取；不要为每个任务重复读取。'},
        'patchNotes': {
          'when': '写操作成功后自动记录当前 APK 的修改笔记；任务开始时用 apk_note_read 防止重复修改。',
        },
      },
      'onDemand': {
        'worldBooks': {
          'active': activeBooks,
          'tool': '仅在知识书会改变下一步时，按 route 的 topics 读取少量条目。',
        },
        'installedSkills': {
          'enabledCount': installedSkillCount,
          'tool': '仅在启用的用户 Skill 与当前任务相关时读取。',
        },
        'builtInSkills': {'仅在当前任务需要额外操作步骤时读取指定 Skill。'},
        'patchExperience': {'同类补丁已有验证经验时才读取；安装验证后再记录结果。'},
        'toolSelection': {'tool': '不确定下一步时才重新读取 route_task。'},
      },
      'contextReadiness': {
        'worldBooks': {
          'providerAvailable': worldBookProvider != null,
          'loaded': readiness[0],
          'activeBookCount': activeBooks.length,
          'activeEntryCount': activeBookEntries,
        },
        'installedSkills': {
          'providerAvailable': agentSkillProvider != null,
          'loaded': readiness[1],
          'enabledCount': installedSkillCount,
        },
        'instructionInjections': {
          'providerAvailable': instructionInjectionProvider != null,
          'loaded': readiness[2],
          'activeCount': injections.length,
          'promptChars': injectionPromptChars,
        },
        'memory': {
          'repositoryAvailable': memoryRepository != null,
          'enabled': assistant.enableMemory,
        },
      },
      'requiredOrder': [
        '先读取当前报告；缺失、过期或显式切换 APK 时才分析。',
        '只调用能直接减少当前不确定性的定位工具；相同参数失败后不重试。',
        '优先续接当前会话快照；精确目标已授权时用 dryRun=true+applyAfterPreview=true 一次完成，纯预览则原样调用 applyArguments。',
        '直接 DEX 补丁完成后用 apk_sign；只有已编辑解码目录时用 apk_rebuild。',
      ],
      // 工具清单不在运行时指南里重复罗列：本轮 tools/list 已声明全部
      // 工具，再回传 localToolIds 纯属冗余（此前 31 个 id 白占上下文）。
      'availableLocalToolCount': runtimeToolNames.length,
      'availableLocalTools': runtimeToolNames.toList()..sort(),
      'externalMcpTools': {
        'naming': 'mcp__<server>__<tool>',
        'note': '用户外接的 MCP 工具（如 MT）已按此命名合并进本轮工具列表，每轮动态刷新；直接按名称调用即可，无需询问工具是否存在。',
      },
    },
    toEncodable: (value) =>
        value is Set ? value.toList(growable: false) : value.toString(),
  );
}

Future<String> _handleApkKnowledge(
  Map<String, dynamic> args,
  Assistant assistant,
  WorldBookProvider? worldBookProvider, {
  String? conversationId,
}) async {
  if (worldBookProvider == null) {
    return jsonEncode({
      'error': 'world_book_unavailable',
      'message': '知识书尚未就绪，请稍后重试。',
    });
  }
  final rawTopics = args['topics'];
  if (rawTopics is! List) {
    return jsonEncode({
      'error': 'invalid_topics',
      'message': 'topics 必须是 route_task 返回的 knowledgeTopics 数组。',
    });
  }
  final topics = rawTopics
      .map((topic) => topic.toString().trim())
      .where((topic) => topic.isNotEmpty)
      .toList(growable: false);
  if (topics.isEmpty) {
    return jsonEncode({'error': 'invalid_topics', 'message': 'topics 不能为空。'});
  }
  final rawLimit = args['maxEntries'];
  final parsedLimit = rawLimit is num
      ? rawLimit.toInt()
      : int.tryParse(rawLimit?.toString() ?? '');
  final limit = (parsedLimit ?? 3).clamp(1, 5).toInt();
  await worldBookProvider.initialize();
  final prefetched = ToolSessionState.prefetchedKnowledge(
    _toolSessionKey(assistant, conversationId),
  );
  final entries = worldBookProvider
      .retrieveActiveEntries(
        assistantId: assistant.id,
        topics: topics,
        limit: limit + prefetched.length,
      )
      .where((entry) => !prefetched.contains(entry['entryName']))
      .take(limit)
      .toList(growable: false);
  // F-48（2026-10-04）：空命中必须能区分「世界书没配」与「主题没对上」——
  // 两种状态的后续动作完全不同（去配置 vs 换词重查）。启用条目数与已知
  // 主题样本从 provider 现算（与 agent_runtime_guide 同一数据源）。
  String emptyInstruction;
  var activeEntryCount = 0;
  final knownTopicSample = <String>{};
  for (final bookId in worldBookProvider.activeBookIdsFor(assistant.id)) {
    final book = worldBookProvider.getById(bookId);
    if (book == null) continue;
    for (final entry in book.entries) {
      if (!entry.enabled) continue;
      activeEntryCount++;
      knownTopicSample.addAll(entry.keywords.take(4));
    }
  }
  if (entries.isEmpty) {
    emptyInstruction = activeEntryCount == 0
        ? '该助手没有启用任何知识条目（世界书未配置或条目全部停用，属配置状态非故障）。'
              '如需方法论知识，引导用户在 设置→世界书 启用对应条目；本次基于报告与工具链流程继续。'
        : '知识库有 $activeEntryCount 条启用条目，但本次 topics 没有命中'
              '（匹配按条目名/关键词/正文的子串打分，不接受近义词）。'
              '已知主题样本：${knownTopicSample.take(12).join('、')}。'
              '换用这些词重查，或基于报告与工具链流程继续。';
  } else {
    emptyInstruction =
        '这些条目是当前任务的说明书。把每条内容转成检查项并在报告或工具结果中验证；不要假定未返回的条目已生效。';
  }
  return jsonEncode({
    'topics': topics,
    'returned': entries.length,
    'activeEntryCount': activeEntryCount,
    'entries': entries,
    'instruction': emptyInstruction,
  });
}

String _toolSessionKey(Assistant assistant, String? conversationId) =>
    conversationId == null || conversationId.isEmpty
    ? 'assistant:${assistant.id}'
    : 'conversation:$conversationId';

Future<String> _handleInstalledSkills(
  Map<String, dynamic> args,
  AgentSkillProvider? provider,
) async {
  if (provider == null) {
    return jsonEncode({'error': 'skill_store_unavailable'});
  }
  final rawTopics = args['topics'];
  if (rawTopics is! List) {
    return jsonEncode({'error': 'invalid_topics'});
  }
  final topics = rawTopics
      .map((topic) => topic.toString().trim())
      .where((topic) => topic.isNotEmpty)
      .toList(growable: false);
  final rawLimit = args['maxEntries'];
  final parsedLimit = rawLimit is num
      ? rawLimit.toInt()
      : int.tryParse(rawLimit?.toString() ?? '');
  await provider.initialize();
  final skills = provider.retrieve(
    topics: topics,
    limit: (parsedLimit ?? 3).clamp(1, 5).toInt(),
  );
  return jsonEncode({
    'topics': topics,
    'returned': skills.length,
    'skills': skills
        .map(
          (skill) => {
            'id': skill.id,
            'name': skill.name,
            'description': skill.description,
            'version': skill.version,
            'sourceUrl': skill.sourceUrl,
            'topics': skill.topics,
            'content': skill.content,
          },
        )
        .toList(growable: false),
    'instruction': 'Skill 是当前任务的补充步骤。逐条执行适用部分，并以报告、工具结果、预览和用户确认作为最终边界。',
    if (skills.isEmpty)
      'emptyHint':
          '技能库当前没有匹配条目（用户未安装技能或主题不匹配）。这不是工具故障：'
          '改用 get_apk_knowledge 的世界知识、route_task 的轨道知识或直接按工具链流程推进即可。',
  });
}

/// F5：签名包续改检测——当前连续修改目标（boundApk=activeApkPath）是签名包
/// （源自报告源 APK 的构建链）时标记 incrementalFromSource。目标缺失时改用
/// build 索引里最新签名包（rootSource 匹配报告源）判定。
Future<Map<String, dynamic>> _incrementalBuildContext(
  String? boundApk,
  Object? sourceApk,
) async {
  final reportFile =
      (sourceApk is Map ? sourceApk['fileName']?.toString() : '') ?? '';
  if (reportFile.isEmpty) return const {};
  final builds = await ApkWorkspaceBindingService.readBuilds();
  final noTarget = boundApk == null || boundApk.isEmpty;
  // 定位当前签名包：优先 boundApk 路径匹配，无目标时取最新签名包（kind=build）
  Map<String, dynamic>? current;
  if (!noTarget) {
    for (final b in builds) {
      if (b['output'] == boundApk) {
        current = b;
        break;
      }
    }
  } else {
    for (final b in builds) {
      if (b['kind'] == 'build' || b['signed'] == true) {
        current = b;
        break; // 索引按时间倒序，第一个签名包即最新
      }
    }
  }
  if (current == null) {
    // 无签名包可核对：无当前目标时一致性无法核对（P3 盲区显式化）
    if (noTarget) {
      return {
        'boundApkUnresolved': true,
        'incrementalHint':
            '当前没有连续修改目标（boundApk 缺失），一致性无法按路径核对：'
            '请用 analyze_apk_workspace 重新分析目标 APK 后再执行修改；'
            'build 索引中也无匹配的签名包记录。',
      };
    }
    return const {};
  }
  final source =
      (current['rootSource'] ?? current['source'] ?? current['input'])
          ?.toString() ??
      '';
  final isIncremental = source.isNotEmpty && source.contains(reportFile);
  if (!isIncremental) return const {};
  final targetOutput = current['output']?.toString() ?? boundApk ?? '';
  return {
    'currentTargetIsBuild': true,
    'incrementalFromSource': true,
    if (noTarget) 'boundApkUnresolved': true,
    'incrementalHint':
        '当前目标（$targetOutput）是签名包产物（源自报告源 APK $reportFile 的构建链），SHA 与报告不同属正常。'
        'DEX/方法/字段定位（dex_search、class_outline、dex_xref）直接基于当前包执行；'
        '报告决策证据（规则命中/组件）仍基于源 APK，修改结果以安装验证为准。',
  };
}

/// F5：freshness 绑定当前目标文件指纹。连续修改目标（boundApk=activeApkPath）
/// 与报告源 APK 文件名不一致（如签名包续改、换包）→ 强制 stale，触发重建
/// 报告流程；无当前目标 → 无法核对，降为 unknown。
Future<Map<String, dynamic>> _freshnessWithBoundApk(
  Map<String, dynamic> report,
  String? boundApk,
) async {
  final base = await ApkWorkspaceService.reportFreshnessOf(report);
  final target = boundApk ?? '';
  final sourceApk = report['sourceApk'];
  final reportFile =
      (sourceApk is Map ? sourceApk['fileName']?.toString() : '') ?? '';
  if (target.isEmpty) {
    return {
      ...base,
      if (base['status'] == 'fresh') 'status': 'unknown',
      'boundApkCheck':
          '当前没有连续修改目标（boundApk 缺失），文件指纹无法核对（P3 盲区）；请用 analyze_apk_workspace 重新分析目标 APK 后重查',
    };
  }
  if (reportFile.isEmpty) return base;
  final boundName = target.split('/').last;
  if (boundName != reportFile) {
    return {
      ...base,
      'status': 'stale',
      'action':
          '当前目标是 $boundName，报告对应 $reportFile（源 APK）——两者不一致：'
          '报告决策证据基于源 APK，当前目标是签名包或其他包，必须先 analyze_apk_workspace '
          '重新分析当前实际目标后再执行任何修改。',
    };
  }
  return base;
}

/// 工具能力总表：列出全部本地 APK 工具的触发信号与流程，供 AI 选工具时查阅。
final Map<String, String> _apkToolMapCache = <String, String>{};

/// 工具描述摘要：首句 + 80 字符上限（目录模式用，见 [_handleApkToolMap]）。
String _summarizeToolDescription(Object? raw) {
  final text = raw?.toString().trim() ?? '';
  if (text.isEmpty) return '';
  final firstSentence = text.split(RegExp(r'(?<=[.。;；])\s*')).first.trim();
  final base = firstSentence.isEmpty ? text : firstSentence;
  return base.length <= 80 ? base : '${base.substring(0, 80)}…';
}

String _handleApkToolMap(Assistant assistant, Map<String, dynamic> args) {
  final requestedRaw = args['tool']?.toString().trim();
  // 第 61 项：模型函数面声明的是发布名（analyzer_open），而 assistant.localToolIds
  // 存的是内部名（analyzer.open）。总表过去只按内部名判「是否启用」，于是
  // get_solab_tool_map(tool=analyzer_find_field_usage)——恰好是函数面看得见、
  // ToolArgumentGuard 又建议来查参数的那个名字——直接回 tool_not_available，
  // 把「缺参数就查总表」这条恢复路径堵死。这里统一归一化成内部名再判。
  final requestedTool = requestedRaw == null || requestedRaw.isEmpty
      ? requestedRaw
      : AnalyzerToolNames.internalName(requestedRaw);
  // 目录过滤（2026-09-15 真机 P3）：全量目录噪音大，Agent 为拿三个写入
  // 工具的 schema 多花 3 次单读。filter 支持 declaredNow（本轮已声明）/
  // missing（启用但本轮未声明）/ write（写操作工具）。
  final filter = args['filter']?.toString().trim();
  final supportsFilter = requestedTool == null || requestedTool.isEmpty;
  bool filterMatches(String toolName, {required bool declared}) {
    if (!supportsFilter || filter == null || filter.isEmpty) return true;
    switch (filter) {
      case 'declaredNow':
        return declared;
      case 'missing':
        return !declared;
      case 'write':
        return ApkAgentPolicy.mutationToolNames.contains(toolName);
      default:
        return true;
    }
  }

  // 目录语义 = 能力总表：assistant 启用的全部工具（含 analyzer.*），
  // 不是本轮实际下发的函数子集。此前用 __runtimeToolNames 当目录全集，
  // Tier0 轻量路由下只剩编排/记忆类，Agent 误判「写工具缺失」而中断
  // （实测执行层一切正常，纯粹是目录层与启用集脱节）。
  final enabledToolIds = assistant.localToolIds.toSet();
  final sortedEnabled = enabledToolIds.toList()..sort();
  final runtimeNames = _runtimeToolNames(args, assistant);
  final declaredThisTurn = runtimeNames.intersection(enabledToolIds).toList()
    ..sort();
  // 缓存键必须含 **filter**（2026-09-21 复测 D6）：过去只有启用集 + 本轮声明 +
  // requestedTool，于是「先不带 filter 查一次全量」会把结果缓存住，之后任何
  // filter=write/missing 都命中那份未过滤的响应 —— 表现为 filter 静默失效
  // （真机复现：三次调用全回 44/44 且 filterApplied=false，而非法枚举又会被
  // 守卫拒，说明参数确实到过校验层，是这一层吃掉了差异）。
  final cacheKey =
      '${sortedEnabled.join('\u0001')}\u0000${declaredThisTurn.join('\u0001')}'
      '\u0000${requestedTool ?? ''}'
      '\u0000${supportsFilter ? (filter ?? '') : '<tool-mode>'}';
  final cached = _apkToolMapCache[cacheKey];
  if (cached != null) return cached;
  final definitionsByName = <String, Map>{};
  for (final definition in <Map<String, dynamic>>[
    ...LocalToolsService.buildToolDefinitions(
      assistant: assistant,
      supportsTools: true,
    ),
    ...AnalyzerGatewayTools.buildDefinitions(assistant.localToolIds.toSet()),
  ]) {
    if (definition['function'] case final Map function) {
      final declaredName = function['name'].toString();
      definitionsByName[declaredName] = function;
      // 声明用发布名（analyzer_open），总表却按 assistant.localToolIds 枚举
      // （内部名 analyzer.open）。只按声明名做键，这四项在总表里既没有
      // description 也没有 parameters，单读还会回一句「仅可按 parameters
      // 调用」却没有 parameters（第 61 项）。补一条内部名别名索引即可对齐。
      definitionsByName.putIfAbsent(
        AnalyzerToolNames.internalName(declaredName),
        () => function,
      );
    }
  }
  final requestedEnabled = requestedTool != null && requestedTool.isNotEmpty;
  // DEF-05（2026-09-19 复测）：tool_batch / mcp_task_status 由 MCP 面注册
  // （不进 assistant.localToolIds），过去在工具总表里查不到——而 MCP 指令恰恰
  // 让 agent 用本工具补全参数，这条路是断的。这里放行面级系统工具。
  final systemLevelToolIds = <String>{
    LocalToolNames.toolBatch,
    'mcp_task_status',
  };
  if (requestedEnabled &&
      !enabledToolIds.contains(requestedTool) &&
      !systemLevelToolIds.contains(requestedTool)) {
    final related = sortedEnabled
        .where(
          (name) =>
              name.contains(requestedTool) ||
              AnalyzerToolNames.publishedName(
                name,
              ).contains(requestedRaw ?? requestedTool),
        )
        .take(5)
        .toList(growable: false);
    return jsonEncode({
      'error': 'tool_not_available',
      'message':
          '工具 ${requestedRaw ?? requestedTool} 未在当前助手启用（可用名单见 callableToolNames）。',
      if (related.isNotEmpty) 'similarNames': related,
    });
  }
  final selectedNames = requestedEnabled
      ? <String>[requestedTool]
      : sortedEnabled
            .where(
              (name) => filterMatches(
                name,
                declared: declaredThisTurn.contains(name),
              ),
            )
            .toList();
  final tools = <Map<String, dynamic>>[
    for (final name in selectedNames)
      {
        'name': name,
        'declaredNow': declaredThisTurn.contains(name),
        // 第 61 项：目录按 localToolIds 枚举，analyzer 四项因此在总表里显示点号
        // 内部名，而函数面声明的可调用名是下划线发布名。显式给出后者，避免模型
        // 照着目录去点一个自己函数表里不存在的名字。
        if (AnalyzerToolNames.publishedName(name) != name)
          'publishedName': AnalyzerToolNames.publishedName(name),
        if (definitionsByName[name]?['description'] != null)
          // 目录模式（不带 tool=）只给一句话摘要：整份目录原来 19KB 超结果
          // 上限被截断，so_*/signature_bypass 这类靠后的工具直接看不见，
          // Agent 因此误判「没有签名工具」（2026-09-15 真机）。完整描述与
          // 参数用 tool=<name> 单读，不受截断影响。
          'description': requestedEnabled
              ? definitionsByName[name]!['description']
              : _summarizeToolDescription(
                  definitionsByName[name]!['description'],
                ),
        if (requestedEnabled && systemLevelToolIds.contains(name))
          'description': name == LocalToolNames.toolBatch
              ? 'Batch runner: run up to 8 tool calls in one round trip; each entry '
                    'is {tool, args}. Inner calls reuse full per-call semantics '
                    '(lane queueing, timeout, loop guard, async queueing); a failed '
                    'inner call stays as an isError entry without aborting the batch; '
                    'total budget 120s. Cannot nest itself.'
              : 'Poll an asynchronous MCP task by taskId; returns status/phase/'
                    'elapsedMs and the final result payload.',
        if (requestedEnabled &&
            !systemLevelToolIds.contains(name) &&
            definitionsByName[name]?['parameters'] is Map)
          'parameters': name == LocalToolNames.soAnalyze
              ? _fullSoAnalyzeParameters(
                  definitionsByName[name]!['parameters'] as Map,
                )
              : definitionsByName[name]!['parameters'],
      },
  ];
  final result = jsonEncode({
    'tools': tools,
    // 工作区/沙盒能力目录（2026-10-02 用户反馈：模型不知道沙盒里能干什么，
    // 一直用 file 工具整篇读写，也没意识到可以装依赖）。
    'workspace': workspaceCapabilitySection(),
    'callableToolNames': [for (final tool in tools) tool['name']],
    'declaredThisTurn': declaredThisTurn,
    'compact': !requestedEnabled,
    // 过滤自证（2026-09-19 复测：三档 filter 当时返回同一份内容，调用方无法
    // 判断过滤到底有没有生效）。这里显式回执 filter / returned / total。
    'filterApplied': supportsFilter && filter != null && filter.isNotEmpty,
    'returned': tools.length,
    'totalEnabled': sortedEnabled.length,
    if (supportsFilter && filter != null && filter.isNotEmpty) 'filter': filter,
    'contract': requestedEnabled
        ? (declaredThisTurn.contains(requestedTool)
              ? '仅可按 parameters 调用该工具。'
              : '该工具已启用：直接调用即可（执行层已启用即放行）；'
                    '未出现在本轮函数列表只影响声明成本，不影响执行。不要因此判定能力缺失。')
        : '这是能力总表（assistant 启用的全部工具，description 只给一句话摘要）。'
              'filter=write 只看写操作工具；declaredNow/missing 按本轮声明过滤。'
              '需要完整描述与参数时用 get_solab_tool_map(tool=<name>) 单读该工具（不受结果截断影响）。'
              '目录里没有的工具才是真的没启用；不要用本轮 declaredThisTurn 判断能力存缺。',
  });
  if (_apkToolMapCache.length >= 16) {
    _apkToolMapCache.remove(_apkToolMapCache.keys.first);
  }
  _apkToolMapCache[cacheKey] = result;
  return result;
}

/// 工作区/沙盒能力目录：让模型知道「有 shell/edit_file/grep/glob」以及
/// 「缺依赖可以去装」，并且**给出择优用法**（改已有文件用 edit_file，别整篇重写）。
///
/// 沙盒是否就绪、装了哪些依赖是运行时状态，这里只给静态目录 + 自检方法：
/// 让模型用 shell `command -v` 自己验，而不是猜或假装有。
Map<String, dynamic> workspaceCapabilitySection() {
  final tools = <Map<String, String>>[
    for (final definition in WorkspaceToolsService.definitions())
      if (definition['function'] case final Map function)
        if (function['name'] != null)
          {
            'name': function['name'].toString(),
            'description': _summarizeToolDescription(
              function['description']?.toString() ?? '',
            ),
          },
  ];
  return <String, dynamic>{
    'tools': tools,
    'prefer': <String, String>{
      'modifyExistingFile':
          'edit_file（精确替换：只改要改的那几行；不要用 write_file 整篇重写，既费 token 又容易覆盖别人/自己的改动）',
      'createOrRewriteFile': 'write_file',
      'findByContent': 'grep',
      'findByPath': 'glob',
      'runCommand': 'shell（在 Linux 沙盒里执行命令；沙盒未就绪会回 environment_not_ready）',
      'readLargeFile': 'read_file + offset/limit 分段读，别一次整篇读进来',
      'lookAtImage': 'view_image',
    },
    'presets': <Map<String, String>>[
      for (final dependency in EnvironmentDependency.values)
        <String, String>{
          'id': dependency.name,
          'packages': dependency.packages(alpine: false),
        },
    ],
    'checkInstalled': 'command -v rg jq gcc g++ make java javac readelf objdump',
    'installHint':
        '沙盒里缺依赖时不要绕路、也不要假装有：告诉用户在「设置 → 工作区 → 环境预设」点安装'
        '（按组安装，装完对所有工作区生效）。',
    'note':
        '沙盒未就绪时 shell 返回 environment_not_ready；请用户先在设置里启用工作区环境。',
  };
}

Set<String> _runtimeToolNames(Map<String, dynamic> args, Assistant assistant) {
  final runtime = args['__runtimeToolNames'];
  if (runtime is List) {
    return runtime.map((name) => name.toString()).toSet();
  }
  return assistant.localToolIds.toSet();
}

Map<String, dynamic> _fullSoAnalyzeParameters(Map parameters) {
  final properties = Map<String, dynamic>.from(parameters['properties'] as Map);
  final action = Map<String, dynamic>.from(properties['action'] as Map);
  action['description'] = kSoAnalyzeActionCatalog.join(' | ');
  properties['action'] = action;
  return <String, dynamic>{...parameters, 'properties': properties};
}

Future<String> _handleApkRecordPatchVerification(
  Map<String, dynamic> args,
  ChatService? chatService,
  MemoryRepository? memoryRepository,
) async {
  final repository = chatService?.chatRepositoryOrNull;
  // F-36 同族：验证回写同样依赖 memoryRepository，端内 Agent 面过去 100% 必挂。
  if (memoryRepository == null) {
    return _apkMemoryToolError(
      'memory_store_unavailable',
      '补丁记忆库在当前工具面不可用：进程级注入缺失（正常装机不会出现），重启 App 可恢复。',
      recoverable: true,
    );
  }
  if (repository == null) {
    return _apkMemoryToolError(
      'chat_service_unavailable',
      '聊天服务尚未就绪，请稍后再试。',
      recoverable: false,
    );
  }
  final outcome = (args['outcome'] ?? '').toString();
  final summary = (args['summary'] ?? '').toString().trim();
  if ((outcome != 'success' && outcome != 'failure') || summary.isEmpty) {
    return jsonEncode({
      'error': 'invalid_args',
      'message': 'outcome 只能是 success 或 failure，summary 必填。',
    });
  }
  final report = await _readPatchMemoryReport();
  final activePath = await ApkWorkspaceBindingService.activeApkPath();
  final builds = await ApkWorkspaceBindingService.readBuilds();
  Map<String, dynamic>? artifact;
  for (final build in builds) {
    if (build['output'] == activePath) {
      artifact = build;
      break;
    }
  }
  // 产物档案是否齐全（build 台账 + 已签名 + 预存待验证草稿）。
  // agent 用 apk_archive/signature_bypass 等流式工具直改直签时没有走
  // 台账流程——此前直接拒绝（patch_artifact_not_found / signed_artifact_
  // required），用户实机验证通过的结论记不进记忆（2026-09-15 用户点名
  // 「修改有效了为什么还没更新」）。现在降级：验证结论照样写长期记忆，
  // 只是产物指纹、台账回填与自动清理不可用——记账不该被簿记缺失挡住。
  final artifactReady =
      artifact != null &&
      artifact['kind'] == 'build' &&
      artifact['signed'] == true &&
      artifact['pendingMemoryStatus'] == 'awaiting_user_verification';
  // 成品文件档案：验证通过时把产物的内容指纹（sha256）连同验证结论一起
  // 沉淀到 patch memory——后续会话拿到这个文件时按指纹反查即可识别
  // 「这是已验证的成品/基线」，不必从原始包重做。
  //
  // 锚点解析顺序（2026-09-15 审核修复）：显式 artifactPath > build 台账的
  // output > activeApkPath。注意 activeApkPath 只是「最后一个被任何工具
  // 碰过的 APK」——analyze_apk_workspace 与任何显式传 path 的工具都会改写
  // 它，常常是原始包；拿它当成品指纹会把源包的 sha 记成「用户已验证的
  // 成品」，后续会话按 sha 反查原始包时被误导成「这是成品/基线，不要从
  // 原始包重做」。所以只有台账成品或显式点名的文件才算可信锚点。
  final explicitArtifactRaw = (args['artifactPath'] ?? '').toString().trim();
  // 越权面收敛：artifactPath 此前只做 exists 检查，可用来探测（并回填哈希）
  // 工作目录外的任意文件。与 file_* 同一套门禁。
  final artifactWorkDir = await ApkWorkspaceBindingService.workDir();
  final explicitArtifact = explicitArtifactRaw.isEmpty
      ? ''
      : (_guardInsideWorkDir(artifactWorkDir ?? '', explicitArtifactRaw) ?? '');
  if (explicitArtifactRaw.isNotEmpty && explicitArtifact.isEmpty) {
    return jsonEncode(_pathOutsideWorkspace(explicitArtifactRaw, artifactWorkDir ?? ''));
  }
  if (explicitArtifact.isNotEmpty && !File(explicitArtifact).existsSync()) {
    return jsonEncode({
      'error': 'artifact_not_found',
      'message': 'artifactPath 指向的文件不存在: $explicitArtifact',
    });
  }
  final artifactOutput = (artifact?['output'] ?? '').toString().trim();
  final outputPath = explicitArtifact.isNotEmpty
      ? explicitArtifact
      : artifactOutput.isNotEmpty
      ? artifactOutput
      : (activePath ?? '').trim();
  // 可信锚点 = 台账里的签名成品，或调用方显式点名的文件；否则 outputPath
  // 只是「最近碰过的包」，可以登记实机验证（按 path/sha 反查，不会误命中
  // 别的产物），但绝不写进记忆的产物档案。
  final anchorTrusted = explicitArtifact.isNotEmpty || artifactReady;
  String outputSha256 = '';
  int outputSize = 0;
  if (outputPath.isNotEmpty && File(outputPath).existsSync()) {
    outputSha256 = await _sha256OfFile(outputPath);
    outputSize = File(outputPath).lengthSync();
  }
  final vendors = await ApkRuleService(
    repository,
  ).vendorsForReport(report ?? const <String, dynamic>{});
  final fingerprint = ApkPatchMemoryService.fingerprintFromReport(
    report ?? const <String, dynamic>{},
    vendors: vendors,
  );
  final operation = (artifact?['operation'] ?? '').toString();
  // MT 签名产物没有 operation 字段，用统一标识避免标题空操作。
  final effectiveOperation = operation.isNotEmpty ? operation : 'apk_build';
  final now = DateTime.now().millisecondsSinceEpoch;
  // 改点来自本次 APK 的修改笔记（apk_note_write 沉淀）：验证经验带上
  // 具体 locator（qualifiedId/so 符号/条目路径），复用时按图索骥，
  // 而不是只有一句抽象方案 + 工具名。
  final pendingDraft = artifact?['pendingMemoryDraft'] is Map
      ? Map<String, dynamic>.from(artifact!['pendingMemoryDraft'] as Map)
      : const <String, dynamic>{};
  final pendingChanges = <Map<String, dynamic>>[
    for (final change in (artifact?['pendingChanges'] as List? ?? const []))
      if (change is Map) Map<String, dynamic>.from(change),
  ];
  final targets = {
    for (final target in _stringList(pendingDraft['targets']))
      if (target.toString().trim().isNotEmpty) target.toString().trim(),
    for (final change in pendingChanges) ...{
      if ((change['locator'] ?? '').toString().trim().isNotEmpty)
        (change['locator'] ?? '').toString().trim(),
      for (final locator in _stringList(change['locators']))
        if (locator.toString().trim().isNotEmpty) locator.toString().trim(),
    },
  }.toList();
  // 标题带改点摘要（locator 取短名，最多 3 个）：纯工具名（如
  // patch_apk_dex_methods）零信息量，看不出改了什么。
  String shortLocator(String loc) =>
      loc.length > 40 ? '${loc.substring(0, 40)}…' : loc;
  final draftTitle = (pendingDraft['title'] ?? '').toString().trim();
  final title = draftTitle.isNotEmpty
      ? draftTitle
      : targets.isEmpty
      ? (outcome == 'success'
            ? '已验证有效: $effectiveOperation'
            : '已验证无效: $effectiveOperation')
      : (outcome == 'success'
            ? '已验证有效·${targets.length}处: ${targets.take(3).map(shortLocator).join('; ')}'
            : '已验证无效·${targets.length}处: ${targets.take(3).map(shortLocator).join('; ')}');
  // 收敛写入：同指纹收敛为同一条（方案/易错点/改点合并且保留）。
  // pitfall 可选：本次验证发现/规避的易错点，随经验一起沉淀。
  final draftSolution = (pendingDraft['solution'] ?? '').toString().trim();
  final verifiedSolution = draftSolution.isEmpty
      ? summary
      : '$draftSolution\n安装验证: $summary';
  // 退化指纹不写长期记忆（2026-09-15 审核修复）：报告缺失（直改直签、没有
  // 分析）时指纹只剩 engine=native，isDegenerateFingerprint 为 true——这种
  // 指纹的 key 是常量 '||native|'，写入会与别的 App 的同类写入并进同一条
  // （方案/改点被求并集），而所有读路径都拒绝退化指纹，条目既脏又召回不了。
  final fingerprintDegenerate = ApkPatchMemoryService.isDegenerateFingerprint(
    fingerprint,
  );
  if (!fingerprintDegenerate) {
    await ApkPatchMemoryService.upsertVerification(
      repo: memoryRepository,
      fingerprint: fingerprint,
      outcome: 'verified_$outcome',
      title: title,
      solution: verifiedSolution,
      operation: effectiveOperation,
      pitfall: ApkPatchMemoryService.mergePitfall(
        (pendingDraft['pitfall'] ?? '').toString().trim(),
        (args['pitfall'] ?? '').toString().trim(),
      ),
      targets: targets,
      // D10（2026-09-21 复验）：这里的版本号是**分析报告**（源包）的版本，不是
      // 成品自身读出来的——报告过期/换包时它会错（复验方实测 0.132.0 记成了
      // 0.134.0 的那条），报告缺字段时又是空串，两种都误导。语义澄清放在回执里
      // （记忆 schema 不加列：上游容器优先，见 docs/上游对接进度.md §二）。
      versionName: (report?['versionName'] ?? '').toString().trim(),
      artifacts: [
        // 产物档案只在锚点可信（台账成品 / 显式 artifactPath）时写入：
        // 否则会把「最近碰过的包」的 sha 存成已验证成品，污染
        // findByArtifactSha256 的反查结论。
        if (anchorTrusted && outputSha256.isNotEmpty)
          {
            'sha256': outputSha256,
            'path': outputPath,
            'size': outputSize,
            'fileName': outputPath.split('/').last.split('\\').last,
            'kind': 'patched_output',
            'recordedAt': now,
          },
      ],
    );
  }
  // 用户实机验证登记（独立台账）：交付报告是交付时快照不会自己更新，
  // 运行时弹层交付区靠这份登记按成品指纹反查「通过 · 用户实机」——
  // 完整/降级链路都登记（2026-09-15 用户点名「修改有效了为什么还没更新」）。
  // 只登记真实存在的文件：路径不落地就写，只会给交付区塞一条永不命中的记录。
  if (outputPath.isNotEmpty && File(outputPath).existsSync()) {
    await ApkWorkspaceBindingService.recordUserVerification(
      output: outputPath,
      sha256: outputSha256,
      outcome: outcome,
      summary: summary,
      verifiedAt: now,
    );
  }
  Map<String, dynamic>? cleanup;
  if (artifact != null && artifactReady) {
    artifact['verification'] = outcome;
    // 证据等级：本链路的结论来自用户口述转述（agent 读 args.outcome 写入），
    // 无机器级安装/启动校验——必须显式标 user_reported，防止未来被当作
    // machine_verified 级可信基线复用。
    artifact['verificationSource'] = 'user_reported';
    artifact['verificationSummary'] = summary;
    artifact['verifiedAt'] = now;
    if (outputSha256.isNotEmpty) {
      artifact['outputSha256'] = outputSha256;
      artifact['outputSize'] = outputSize;
    }
    artifact['pendingMemoryStatus'] = 'committed_after_user_verification';
    await ApkWorkspaceBindingService.replaceBuilds(builds);
    if (outcome == 'success') {
      cleanup = await ApkWorkspaceBindingService.cleanupAfterVerifiedSuccess();
      ToolSessionState.lastBuiltSoPath = null;
      ToolSessionState.lastBuiltSoApkPath = null;
      ToolSessionState.lastBuiltSoEntry = null;
    }
  }
  // 降级/降级子情形的如实回报（2026-09-15 审核修复）：此前正文写死「已写入
  // 长期记忆、但没有产物指纹」，而代码实际可能写了指纹、也可能因指纹退化
  // 根本没写记忆——正文与行为矛盾。现在按实际发生的组合逐项说明。
  final degradedNotes = <String>[
    if (!artifactReady) '本次修改未走台账流程（缺少 build 记录或预存草稿）',
    if (!anchorTrusted && outputPath.isNotEmpty)
      '产物指纹锚点不可信（未传 artifactPath，回退到最近碰过的 APK），未登记产物档案',
    if (fingerprintDegenerate) '缺少分析报告导致 App 指纹退化，本次未写长期记忆',
    if (outputPath.isEmpty || !File(outputPath).existsSync())
      '没有可登记的成品文件（artifactPath 未传且无台账产物），未登记实机验证',
    if (!artifactReady) '下次改包建议走 apk_sign + 预存草稿的完整链路以获得合并与自动清理',
  ];
  final memoryNote = fingerprintDegenerate
      ? '指纹退化，未写长期记忆'
      : anchorTrusted
      ? '验证结论已写入长期记忆'
      : '验证结论已写入长期记忆（无产物指纹）';
  return jsonEncode({
    'ok': true,
    'outcome': outcome,
    'operation': effectiveOperation,
    'verificationSource': 'user_reported',
    'memoryWritten': !fingerprintDegenerate,
    'artifactRecorded': anchorTrusted && outputSha256.isNotEmpty,
    if (!artifactReady) ...{
      'degraded': true,
      if (degradedNotes.isNotEmpty) 'warning': '${degradedNotes.join('；')}。',
    },
    // 消息与 cleanup 结果一致：清理失败就不说“已自动清理”（Agent 曾因
    // 正文与字段矛盾多花一轮手动删除）。
    'message': !artifactReady
        ? '用户安装验证结论已记录（降级：未走台账流程，无台账回填与自动清理；$memoryNote）。'
        : outcome == 'success'
        ? (cleanup == null || cleanup['ok'] == true
              ? '用户安装验证结论已写入长期记忆；工作目录已自动清理，仅保留原包和最终成品。'
              : '用户安装验证结论已写入长期记忆；工作目录清理未完成（见 cleanup 字段），请检查遗留中间产物。')
        : '用户安装验证结论已写入长期记忆；未清理工作目录，保留现场继续修复。',
    if (cleanup != null) 'cleanup': cleanup,
  });
}

/// Analyzer Gateway：4 个高阶 API 分派。
Future<String> _handleAnalyzerTool(
  String name,
  Map<String, dynamic> args,
  String contextKey,
) async {
  // D16（2026-09-21 自检）：词表/字段名匹配型能力对 Dart AOT 包结构性不适用
  // （业务不在 DEX 里，字段名还被 AOT 混淆成 field_7/a/b），入口直接回
  // not_applicable：不进入探测流程、不产生耗时、也不写失败记忆。
  // 不拦 analyzer.open——那只是建会话，与目标层无关。
  final gate = await _dartAotNotApplicable(
    capability: name,
    instead:
        'Dart 层路径：so_analyze(action=blutter, blutterAction=search, scope=pp, query=<业务词>) '
        '找对象池偏移 → blutterAction=pool 读对象原文与引用 VA → '
        'so_analyze(action=disasm, addr=<引用VA>) 读原始反汇编判读写方向。',
  );
  if (gate != null) return jsonEncode(gate);
  return AnalyzerGatewayTools(contextKey: contextKey).handle(name, args);
}

/// D16 入口前置层：目标包是 Dart AOT 时，词表/字段名匹配型能力返回
/// `not_applicable: dart_aot` 而不是"未评估/INSUFFICIENT"。
///
/// 为什么必须放在**入口**：这类能力进到探测流程后只有两种结局——耗时后 0 命中，
/// 或者被记成一次失败（同一失败还会被重复记账）。两者都在误导调用方：
/// 前者让模型以为"再换关键词就行"，后者污染失败记忆的统计口径。
///
/// 返回 null 表示适用（可以继续）；返回 Map 表示不适用，直接回给调用方。
/// 关键副作用约定：本函数只读报告，**不写任何记忆**。
Future<Map<String, dynamic>?> _dartAotNotApplicable({
  required String capability,
  required String instead,
}) async {
  Map<String, dynamic>? report;
  try {
    report = await _readPatchMemoryReport();
  } catch (_) {
    // 报告不可读时不拦（"不知道"不等于"不适用"）。
    return null;
  }
  if (report == null) return null;
  final flutterApp = report['flutterApp'];
  if (flutterApp is! Map) return null;
  if (flutterApp['detected'] != true) return null;
  final mode = (flutterApp['mode'] ?? '').toString().trim().toLowerCase();
  // JIT 包（debug/未 AOT）里 Dart 符号还在，词表匹配仍可能命中，故不拦。
  if (mode == 'jit') return null;
  return <String, dynamic>{
    'ok': false,
    'error': 'not_applicable',
    'applicability': 'not_applicable',
    'reason': 'dart_aot',
    'capability': capability,
    'targetLayer': 'dart_aot',
    'failureMemoryRecorded': false,
    'message':
        '$capability 是 DEX 层词表/字段名匹配能力，对本包（flutterApp.detected=true'
        '${mode.isEmpty ? '' : ', mode=$mode'}）结构性不适用：业务逻辑与字段都在 Dart AOT 里，'
        'DEX 层看不到目标。本次未执行探测、未写失败记忆。',
    'instead': instead,
    'nextActions': <Map<String, dynamic>>[
      {
        'action': 'switch_layer',
        'tool': LocalToolNames.soAnalyze,
        'to': 'blutter pool + raw disasm',
        'reason': 'Dart AOT 的真实定位路径；不依赖 DEX 词表匹配。',
      },
    ],
  };
}

/// 统一解析本地 APK 绝对路径。
/// 返回 (path, error)：path 非空=成功；error 非空=需报错；两者都空=无路径可用。
/// apkPath/path 契约（两者同语义：补丁类工具 schema 用 apkPath，
/// M1-M6 工具链 schema 用 path）：
///   - 绝对路径（/ 开头或含盘符）→ 原样使用
///   - 未传 → 优先沿用当前连续修改的产物；没有才回退当前项目源包。
///   - 相对路径/文件名 → join(工作目录, 输入)。工作目录是用户在 APK 工作台
///     选定的统一工作目录（APK/SO/文件工具共用）。
///   - 工作目录未设置且给了相对路径 → 明确拒绝（不一致时拒绝执行）。
/// 解析本地 APK 路径。
///
/// [bindActive]（F-40，2026-10-04）：是否把解析结果**写回** activeApk 绑定。
/// 写类工具（patch/sign/rebuild）保持 true——「当前产物 = 默认续接」的链语义
/// 依赖它；读类工具（jadx/dex_search/string_scan/apk_archive/class_outline/
/// smali_read）必须传 false：只解析不落任何绑定写（含链头自愈的改绑与
/// clearActiveApkPath），否则一次只读调用就能静默改写「下一个补丁打到哪个包」
/// （真机 v8 D3：读一次报告后 activeApk 从 null 变成报告源包路径）。
Future<(String?, String?)> _resolveLocalApkPath(
  Map<String, dynamic> args,
  ChatService? chatService, {
  bool bindActive = true,
}) async {
  var explicit = (args['apkPath'] ?? args['path'] ?? '').toString().trim();
  if (explicit.isNotEmpty) {
    // zone 别名（/workspace、/chat、/tmp）先归一（v6 D5 / F-33）。
    explicit = ApkWorkspaceBindingService.resolveZoneAlias(explicit) ?? explicit;
    final isAbsolute = explicit.startsWith('/') || explicit.contains(':');
    if (isAbsolute) {
      // P0-A 铁律：绝对路径必须位于**某个**已声明根内（工作台全局目录或
      // 当前 zone 根）。v6 D3 / F-31：只认一个根时，设备工作目录里的 APK
      // 会报路径越界，而 workbench 报告读的正是那处——多根命中即接受。
      final roots = await ApkWorkspaceBindingService.resolutionRoots();
      if (roots.isEmpty) {
        return (
          null,
          '工作目录未设置：请先在 APK 工作台设置统一工作目录（所有工具读写'
              '限制在工作目录内），或直接传工作目录内路径。',
        );
      }
      String? guarded;
      for (final root in roots) {
        guarded = _guardInsideWorkDir(root, explicit);
        if (guarded != null) break;
      }
      if (guarded == null) {
        return (
          null,
          '路径越界（$explicit）：所有工具读写必须限制在已声明的工作目录内'
              '（${roots.join(' 或 ')}）。外部 APK 请先用 file(action=copy) '
              '复制进工作目录，再使用工作目录内路径。',
        );
      }
      if (!await File(guarded).exists()) {
        final regenerated = await _tryRegenerateSignatureArtifact(guarded);
        if (regenerated != null) return (regenerated, null);
        return (null, await _missingLocalApkMessage(guarded));
      }
      // 上面分支已确认存在（或已返回），此处不再重复 stat——
      // 这是每个 APK 工具调用的公共路径，省一次文件系统往返。
      if (bindActive && guarded.toLowerCase().endsWith('.apk')) {
        await ApkWorkspaceBindingService.setActiveApkPath(guarded);
      }
      return (guarded, null);
    }
    // 相对路径/文件名 → 用统一工作目录拼接
    final dir = await ApkWorkspaceBindingService.workDir();
    if (dir == null || dir.isEmpty) {
      return (
        null,
        'apkPath 是相对路径/文件名「$explicit」，需要先在 APK 工作台设置「工作目录」'
            '（统一工作目录：APK/SO/文件工具共用），才能解析为绝对路径。请先在工作台选择工作'
            '目录，或直接传绝对路径。',
      );
    }
    final direct = _joinInsideWorkDir(dir, explicit);
    if (direct == null) {
      return (
        null,
        '路径越界（$explicit）：所有工具读写必须限制在统一工作目录内（$dir）。'
            '外部 APK 请先用 file(action=copy) 复制进工作目录，再使用工作目录内路径。',
      );
    }
    if (await File(direct).exists()) {
      if (bindActive && direct.toLowerCase().endsWith('.apk')) {
        await ApkWorkspaceBindingService.setActiveApkPath(direct);
      }
      return (direct, null);
    }
    final matches = await _workspaceApkMatches(explicit);
    if (matches.length == 1) {
      final matched = matches.single['path']?.toString() ?? '';
      if (matched.isNotEmpty) {
        if (bindActive) {
          await ApkWorkspaceBindingService.setActiveApkPath(matched);
        }
        return (matched, null);
      }
    }
    final candidates = matches
        .map((entry) => entry['name']?.toString() ?? '')
        .where((name) => name.isNotEmpty)
        .join('、');
    if (candidates.isEmpty) {
      final regenerated = await _tryRegenerateSignatureArtifact(direct);
      if (regenerated != null) return (regenerated, null);
      return (null, await _missingLocalApkMessage(direct));
    }
    return (
      null,
      '「$explicit」匹配多个 APK：$candidates。先调用 list_workspace_apks 后选择准确文件名。',
    );
  }
  final active = await ApkWorkspaceBindingService.activeApkPath();
  if (active != null) {
    if (await File(active).exists()) return (active, null);
    // 链头自愈：active 指向的产物已被清理/删除（自动清中间包、手动删除、
    // 清理工具回收）时，回退到产物索引中仍存在的最新产物并同步修正链头，
    // 防止整条工具链因产物缺失硬中断。
    final builds = await ApkWorkspaceBindingService.readBuilds();
    for (final build in builds) {
      final candidate = build['output']?.toString();
      if (candidate == null || candidate.isEmpty || candidate == active) {
        continue;
      }
      if (build['exists'] == true) {
        // 读类工具（bindActive=false）只借用存活产物解析路径，不抢链头——
        // 自愈改绑会把「下一个补丁打到哪个包」静默换掉。
        if (bindActive) {
          await ApkWorkspaceBindingService.setActiveApkPath(candidate);
        }
        return (candidate, null);
      }
    }
    final regenerated = await _tryRegenerateSignatureArtifact(active);
    if (regenerated != null) return (regenerated, null);
    if (bindActive) {
      await ApkWorkspaceBindingService.clearActiveApkPath();
    }
    return (null, await _missingLocalApkMessage(active));
  }
  final report = await ApkWorkspaceService.readReport();
  final repository = chatService?.chatRepositoryOrNull;
  if (report != null && repository != null) {
    final project = await ApkProjectService(
      repository,
    ).findBySha256((report['sha256'] ?? '').toString());
    final sourcePath = project?.sourcePath;
    if (sourcePath != null && sourcePath.isNotEmpty) {
      if (await File(sourcePath).exists()) return (sourcePath, null);
      return (null, await _missingLocalApkMessage(sourcePath));
    }
  }
  var workspaceApks = await ApkWorkspaceBindingService.listApks();
  // 附件镜像会让同一包在根与 inbox/ 各存一份：按 (名, 大小) 去重再判唯一，
  // 否则"工作目录只有一个包"的场景会被误报成多个候选。
  final seenApkKeys = <String>{};
  workspaceApks = [
    for (final e in workspaceApks)
      if (seenApkKeys.add('${e['name']}|${e['size']}')) e,
  ];
  if (workspaceApks.length == 1) {
    final path = workspaceApks.single['path']?.toString() ?? '';
    if (path.isNotEmpty) {
      if (bindActive) {
        await ApkWorkspaceBindingService.setActiveApkPath(path);
      }
      return (path, null);
    }
  }
  if (workspaceApks.length > 1) {
    final candidates = workspaceApks
        .map((entry) => entry['name']?.toString() ?? '')
        .where((name) => name.isNotEmpty)
        .join('、');
    return (
      null,
      '当前没有可用 APK 路径。工作目录有多个 APK：$candidates。先调用 list_workspace_apks，再选择 fileName 或 apkPath。',
    );
  }
  return (null, null);
}

Future<List<Map<String, dynamic>>> _workspaceApkMatches(
  String requested,
) async {
  final name = p.basename(requested).toLowerCase();
  final stem = p.basenameWithoutExtension(name);
  return (await ApkWorkspaceBindingService.listApks())
      .where((entry) {
        final candidate = (entry['name'] ?? '').toString().toLowerCase();
        return candidate == name ||
            p.basenameWithoutExtension(candidate) == stem;
      })
      .toList(growable: false);
}

Future<String> _missingLocalApkMessage(String missingPath) async {
  final dir = await ApkWorkspaceBindingService.workDir();
  final apks = await ApkWorkspaceBindingService.listApks();
  final builds = await ApkWorkspaceBindingService.readBuilds();
  Map<String, dynamic>? missingArtifact;
  for (final build in builds) {
    if (build['output'] == missingPath) {
      missingArtifact = build;
      break;
    }
  }
  final available = apks
      .map((entry) => entry['path']?.toString() ?? '')
      .where((path) => path.isNotEmpty)
      .toList(growable: false);
  final signatureChainBroken =
      missingArtifact?['signatureCompatibility'] != null ||
      (missingArtifact?['operation']?.toString() ?? '').startsWith(
        'signature_compatibility_',
      );
  final recovery = signatureChainBroken
      ? '该文件属于签名兼容修改链且已丢失。下一次需要它时会从原始 APK 自动补生，不重做分析报告。'
      : '请从现存 APK 中明确选择 apkPath；若缺失的是签名兼容产物，先调用 analyze_apk_workspace 重新生成。';
  return 'APK 目标不存在: $missingPath。工作目录: ${dir ?? '未设置'}。'
      '现存 APK: ${available.isEmpty ? '无' : available.join('、')}。$recovery';
}

Future<String?> _tryRegenerateSignatureArtifact(String missingPath) async {
  for (final build in await ApkWorkspaceBindingService.readBuilds()) {
    if (build['output'] == missingPath) {
      return _regenerateSignatureArtifact(build, missingPath: missingPath);
    }
  }
  return null;
}

Future<String?> _regenerateSignatureArtifact(
  Map<String, dynamic> artifact, {
  required String missingPath,
}) async {
  final operation = artifact['operation']?.toString() ?? '';
  if (!operation.startsWith('signature_compatibility_')) return null;
  final sourcePath =
      (artifact['rootSource'] ?? artifact['source'] ?? artifact['input'])
          ?.toString() ??
      '';
  if (sourcePath.isEmpty || !await File(sourcePath).exists()) return null;
  final outputDir = await ApkWorkspaceBindingService.managedOutputDir();
  if (outputDir == null || outputDir.isEmpty) return null;
  final mode = operation.substring('signature_compatibility_'.length);
  final result = await ApkStructuralService.patchDexMethods(
    path: sourcePath,
    signatureBypass: true,
    signatureBypassMode: mode,
    originalApkPath: mode == 'original_apk' || mode == 'dpatch'
        ? sourcePath
        : null,
    outputDir: outputDir,
  );
  if (!result.ok) return null;
  final output = result.data?['outputPath']?.toString() ?? '';
  if (output.isEmpty || !await File(output).exists()) return null;
  await ApkWorkspaceBindingService.recordPatchArtifact(
    source: sourcePath,
    output: output,
    operation: operation,
  );
  await ApkWorkspaceService.refreshSourceFingerprint(
    output,
    replacesPath: missingPath,
  );
  return output;
}

Future<String?> _validateMutationPreview(
  Map<String, dynamic> args, {
  required String operation,
  required String path,
}) async {
  final token = (args['previewToken'] ?? '').toString();
  if (token.isEmpty) {
    return '缺少预览凭证。请先用 dryRun=true 预览当前修改，再带 previewToken 执行。';
  }
  final result = await ApkMutationPreviewService.validateResult(
    token: token,
    operation: operation,
    path: path,
    args: args,
  );
  if (result['ok'] == true) return null;
  if (result['reason'] == 'mismatch') {
    return '${result['message']} expectedPath=${result['expectedPath']}; '
        'expectedArguments=${jsonEncode(result['expectedArguments'])}。'
        '使用原 token 和上述参数直接重试，不要重新 dryRun。';
  }
  // P1-4：附过期时间与重取方式，让失败原因可执行
  return '${result['message']}请重新 dryRun=true 预览获取新 previewToken 后执行。';
}

Map<String, dynamic> _previewApplyArguments(
  Map<String, dynamic> args, {
  required String path,
  required String previewToken,
  Map<String, dynamic> resolved = const <String, dynamic>{},
}) => <String, dynamic>{
  ...args,
  ...resolved,
  'apkPath': path,
  'dryRun': false,
  'confirm': true,
  'previewToken': previewToken,
}..remove('applyAfterPreview');

/// 「本次调用请求落地写回」的统一判定。
///
/// D9：写工具契约文案一直是"applyAfterPreview=true（或 confirm=true）"，
/// 但单发路径只认 applyAfterPreview —— 传 confirm=true + dryRun=true 的调用方
/// 拿到的是预览，却以为已经写回（静默忽略）。这里把两者真正对齐，与
/// `confirmation_required` 门控、`_previewApplyArguments` 的语义一致。
bool _applyRequested(Map<String, dynamic> args) =>
    args['applyAfterPreview'] == true || args['confirm'] == true;

bool _previewCanApply(ApkStructuralResult result) {
  if (!result.ok) return false;
  final data = result.data ?? const <String, Object?>{};
  final warning = data['warning'];
  if (warning is Map && warning['type'] != null) return false;
  // B2：写入类工具的预览响应按契约恒为 changed:false（预览不产 APK），
  // 不能拿它判"预览不合格"。有命中计数以计数为准（0 命中不可自动执行）；
  // 无计数键（如 manifest/methods 预览）才回退 changed 检查。
  final total = data['totalMatched'];
  if (total is num) return total > 0;
  if (data['changed'] == false) return false;
  return true;
}

Future<String> _handleApkPatchDex(
  Map<String, dynamic> args,
  ChatService? chatService,
) async {
  final (path, pathError) = await _resolveLocalApkPath(args, chatService);
  if (pathError != null) {
    return jsonEncode({'error': 'invalid_apk_path', 'message': pathError});
  }
  if (path == null || path.isEmpty) {
    return jsonEncode({
      'error': 'project_not_ready',
      'message':
          '需要本地 APK 路径才能修改。请先在工作台选择并分析 APK，'
          '或传入 apkPath 参数指定本地 APK 绝对路径。',
    });
  }
  final dryRun = args['dryRun'] == true;
  if (!dryRun && args['confirm'] != true && args['applyAfterPreview'] != true) {
    return jsonEncode({
      'error': 'confirmation_required',
      ..._gateEcho(args),
      'message':
          '契约：先用 dryRun=true 预览，再以相同参数 + applyAfterPreview=true（或 confirm=true）执行。',
    });
  }
  final outputDir = await ApkWorkspaceBindingService.managedOutputDir();
  if (outputDir == null || outputDir.isEmpty) {
    return jsonEncode({
      'error': 'output_dir_required',
      'message': '请先在 APK 工作台设置「工作目录」（统一工作目录：APK/SO/文件工具共用），产物才能落外部可访问位置。',
    });
  }
  final previewArgs = <String, dynamic>{...args, 'outputDir': outputDir};
  if (!dryRun) {
    final previewError = await _validateMutationPreview(
      previewArgs,
      operation: LocalToolNames.apkPatchDex,
      path: path,
    );
    if (previewError != null) {
      return jsonEncode({'error': 'preview_required', 'message': previewError});
    }
  }
  final signatureBypass = args['signatureBypass'] == true;
  final requestedSignatureMode =
      args['signatureBypassMode']?.toString().trim() ?? '';
  final signatureBypassMode = signatureBypass
      ? (requestedSignatureMode.isEmpty
            ? await ApkWorkspaceBindingService.signatureBypassDefaultMode()
            : requestedSignatureMode)
      : 'normal';
  // 工作台默认未开启去签（'off'）时，调用方仍显式要 bypass 又没点名方案：
  // 不能静默按"普通去签"处理（那等于绕过工作台设置），也不能悄悄不去签
  // （那等于无视调用方的显式要求）。给可执行的结构化拒绝：显式传
  // signatureBypassMode 即可本次执行，无需改设置。
  if (signatureBypass && signatureBypassMode == 'off') {
    return jsonEncode({
      'error': 'signature_bypass_disabled',
      'message':
          '工作台「默认去签名」未开启（当前为不开启），本次调用要求 signatureBypass=true '
          '但未指定 signatureBypassMode。请显式传 normal / original_apk / dpatch，'
          '或先在 APK 工作台选择默认去签方案。',
      'recoverable': true,
      'retrySameArguments': false,
      'nextActions': [
        {
          'action': 'retry_with_param',
          'tool': 'patch_apk_dex_methods',
          'param': 'signatureBypassMode',
          'values': ['normal', 'original_apk', 'dpatch'],
          'reason': '显式点名去签方案即可本次执行，不必修改工作台设置。',
        },
      ],
    });
  }
  // 越权面收敛：originalApkPath 会被去签注入器读取并原样嵌进产物
  // （assets/solab/original.apk，随后用 apk_archive 就能取回），此前完全没有
  // 校验——等于任意宿主文件读取。与 file_* 走同一套工作目录门禁。
  final originalApkRaw = (args['originalApkPath'] ?? '').toString().trim();
  String? originalApkPath;
  if (originalApkRaw.isNotEmpty) {
    final (resolvedOriginal, originalError) = await _resolveFileOpsPath(
      <String, dynamic>{'path': originalApkRaw},
    );
    if (resolvedOriginal == null) {
      return jsonEncode(originalError ?? _pathOutsideWorkspace(originalApkRaw, ''));
    }
    originalApkPath = resolvedOriginal;
  }
  Future<ApkStructuralResult> runPatch(bool preview) =>
      ApkStructuralService.patchDexMethods(
        path: path,
        voidMethods: _stringList(args['voidMethods']),
        trueMethods: _stringList(args['trueMethods']),
        falseMethods: _stringList(args['falseMethods']),
        classMethods: _stringList(args['classMethods']),
        sdkPackages: _stringList(args['sdkPackages']),
        removeVpnDetection: args['removeVpnDetection'] == true,
        removeEmulatorDetection: args['removeEmulatorDetection'] == true,
        removeRootDetection: args['removeRootDetection'] == true,
        removeDebugDetection: args['removeDebugDetection'] == true,
        // N1：此前这两个 flag 没透传到 channel，单传时 Kotlin 侧全空 →
        // invalid_args（错误信息里却列着它们）；凑其它 flag 才能生效
        removeScreenCaptureDetection:
            args['removeScreenCaptureDetection'] == true,
        removeFlagSecure: args['removeFlagSecure'] == true,
        timeMethods: _stringList(args['timeMethods']),
        nullMethods: _stringList(args['nullMethods']),
        shortenSplashCountdown: args['shortenSplashCountdown'] == true,
        signatureBypass: signatureBypass,
        signatureBypassMode: signatureBypassMode,
        originalApkPath: originalApkPath,
        stripDebugInfo: args['stripDebugInfo'] == true,
        outputDir: outputDir,
        // INPUT_TOO_LARGE 的显式放行位（native checkInputBudget 消费）：
        // 不透传的话，错误文案里承诺的「携带 allowOversize:true 重试」是死路。
        allowOversize: args['allowOversize'] == true,
        dryRun: preview,
      );

  var result = await runPatch(dryRun);
  var effectiveDryRun = dryRun;
  Map<String, Object?>? previewData;
  String? previewToken = dryRun && result.ok
      ? await ApkMutationPreviewService.issue(
          operation: LocalToolNames.apkPatchDex,
          path: path,
          args: previewArgs,
        )
      : (args['previewToken']?.toString());
  Map<String, dynamic>? applyArguments;
  if (dryRun && previewToken != null) {
    applyArguments = _previewApplyArguments(
      args,
      path: path,
      previewToken: previewToken,
    );
    if (_applyRequested(args) && _previewCanApply(result)) {
      previewData = result.data?.map(
        (key, value) => MapEntry(key.toString(), value),
      );
      result = await runPatch(false);
      effectiveDryRun = false;
    }
  }
  final modifiedLocators = _patchDexLocators(args);
  var encoded = await _encodeApkMutationResult(
    result,
    sourcePath: path,
    operation: LocalToolNames.apkPatchDex,
    dryRun: effectiveDryRun,
    previewToken: previewToken,
    modifiedLocators: modifiedLocators,
  );
  // 防重复修改闭环：dryRun 预览附带"本次目标与历史修改笔记的重叠"。
  // 此前笔记只写不回读——模型不主动调 apk_note_read 时，同一方法被
  // 重复补丁无任何提示。有意重做（从原包重开链）仍可 confirm，不阻断。
  if (dryRun) {
    try {
      final requested = modifiedLocators.toSet();
      if (requested.isNotEmpty) {
        final active = await ApkWorkspaceBindingService.activeApkPath();
        final builds = await ApkWorkspaceBindingService.readBuilds();
        final patched = <String>{
          for (final build in builds)
            if (build['output'] == active)
              for (final change
                  in (build['pendingChanges'] as List? ?? const []))
                if (change is Map) ...{
                  if ((change['locator'] ?? '').toString().trim().isNotEmpty)
                    (change['locator'] ?? '').toString().trim(),
                  for (final locator in _stringList(change['locators']))
                    if (locator.toString().trim().isNotEmpty)
                      locator.toString().trim(),
                },
        };
        final overlap = requested
            .where(patched.contains)
            .toList(growable: false);
        if (overlap.isNotEmpty) {
          final map = jsonDecode(encoded) as Map<String, dynamic>;
          map['alreadyPatchedOverlap'] = overlap;
          // 基线判定：当前目标与登记链的源头是否同一文件（内容 sha256）。
          // 同包重补 → 提示移除重叠项；换基线重做（用户指示在旧成品上
          // 叠加）→ 提示是预期场景，确认后继续。
          map['alreadyPatchedBaseline'] = await _alreadyPatchedBaselineLabel(
            builds,
            targetPath: path,
          );
          map['alreadyPatchedHint'] = map['alreadyPatchedBaseline'] == 'same'
              ? '以上 locator 已在当前对话的修改链中登记，且本次目标与登记基线是同一文件（同包重补）。'
                    '若是有意重做可继续 confirm；否则移除重叠项，避免对同一方法重复补丁。'
              : '以上 locator 已在历史修改链中登记，但本次目标与登记基线不是同一文件（换基线/在旧成品上叠加重做）。'
                    '属预期场景时确认即可；确认前核对 apkPath 确实是用户指定的目标。';
          encoded = jsonEncode(map);
        }
      }
    } catch (_) {
      // 笔记不可用时预览照常返回。
    }
  }

  return _withPreviewFlow(
    encoded,
    applyArguments: applyArguments,
    previewData: previewData,
    appliedAfterPreview: previewData != null && result.ok,
    autoApplyBlocked: dryRun && _applyRequested(args) && previewData == null,
  );
}

/// C6：dex 字符串池替换工具。替换 const-string 引用的精确字符串（URL/文案/
/// 水印等），秒级完成。契约同 patchDex：先 dryRun 预览命中 → 同参 +
/// applyAfterPreview=true 执行。replacements 支持 {from: to} 对象或
/// [{'from':..,'to':..}] 列表两种形态。
Future<String> _handleApkPatchDexStrings(
  Map<String, dynamic> args,
  ChatService? chatService,
) async {
  final (path, pathError) = await _resolveLocalApkPath(args, chatService);
  if (pathError != null) {
    return jsonEncode({'error': 'invalid_apk_path', 'message': pathError});
  }
  if (path == null || path.isEmpty) {
    return jsonEncode({
      'error': 'project_not_ready',
      'message': '需要本地 APK 路径。请先在工作台选择并分析 APK，或传 apkPath 绝对路径。',
    });
  }
  final replacements = _stringReplacements(args['replacements']);
  final samePairs = _sameFromToPairs(args['replacements']);
  if (replacements.isEmpty) {
    // v9-N3（2026-10-05 真机）：失败体对齐 class_outline 标准形——过去
    // error 是字符串、无 ok/code，只读 ok 或只读 code 的失败判定拿不到信号。
    return jsonEncode({
      'ok': false,
      'code': 'invalid_arguments',
      'error': {
        'code': 'invalid_arguments',
        'message':
            'replacements 必填：{旧串: 新串} 对象或 [{"from":..., "to":...}] 列表，'
            '且 from 与 to 不能相同、from 不能为空。'
            '${samePairs.isEmpty ? '' : '其中 from==to 的条目（${samePairs.take(3).join('、')}'
                '${samePairs.length > 3 ? ' 等' : ''}）是空操作，已被忽略。'}',
        'severity': 'error',
        'recoverable': true,
        'retrySameArguments': false,
        'argument': 'replacements',
      },
      'message':
          'replacements 必填：{旧串: 新串} 对象或 [{"from":..., "to":...}] 列表，'
          '且 from 与 to 不能相同、from 不能为空。',
      if (samePairs.isNotEmpty) 'ignoredSamePairs': samePairs,
      'recoverable': true,
      'nextActions': <String>[
        '按 message 修正 replacements（对象或列表两形态均可）后重试',
      ],
    });
  }
  final dryRun = args['dryRun'] == true;
  if (!dryRun && args['confirm'] != true && args['applyAfterPreview'] != true) {
    return jsonEncode({
      'error': 'confirmation_required',
      ..._gateEcho(args),
      'message':
          '契约：先用 dryRun=true 预览命中，再以相同参数 + applyAfterPreview=true（或 confirm=true）执行。',
    });
  }
  final outputDir = await ApkWorkspaceBindingService.managedOutputDir();
  if (outputDir == null || outputDir.isEmpty) {
    return jsonEncode({
      'error': 'output_dir_required',
      'message': '请先在 APK 工作台设置「工作目录」，产物才能落外部可访问位置。',
    });
  }
  if (!dryRun) {
    final previewError = await _validateMutationPreview(
      {...args, 'outputDir': outputDir},
      operation: LocalToolNames.apkPatchDexStrings,
      path: path,
    );
    if (previewError != null) {
      return jsonEncode({'error': 'preview_required', 'message': previewError});
    }
  }
  Future<ApkStructuralResult> runPatch(bool preview) =>
      ApkStructuralService.patchDexStrings(
        path: path,
        replacements: replacements,
        outputDir: outputDir,
        // INPUT_TOO_LARGE 的显式放行位（native checkInputBudget 消费）。
        allowOversize: args['allowOversize'] == true,
        dryRun: preview,
      );

  var result = await runPatch(dryRun);
  // 0 命中预览不是"成功预览"，是"目标失配"。真机实测（2026-09-15）暴露两个
  // 连带缺陷，都在这里收口：
  //   1) 此前无条件签发 previewToken —— token 是 apply 的通行证，为一个必然
  //      0 命中的预览发证，等于诱导调用方拿着它去 apply 然后撞
  //      preview_required/无产物的墙；
  //   2) 此前无条件回 applyArguments —— 直接把"准备好了、发我就能改"的
  //      配方递到调用方手里，而这次改动注定不产生任何变更。
  // 口径统一为：只有真命中（totalMatched > 0）才发证、才给 apply 配方。
  // 失配时不发证，但 preview 字段与 diagnostics 照常回，调用方仍能拿到
  // 完整归因（ABSENT vs PRESENT_NO_CONST_REF）。
  final previewHits = (result.data?['totalMatched'] as num?)?.toInt() ?? 0;
  final previewUsable = result.ok && previewHits > 0;
  Map<String, Object?>? previewData;
  String? previewToken = args['previewToken']?.toString();
  if (dryRun) {
    if (previewUsable) {
      previewToken ??= await ApkMutationPreviewService.issue(
        operation: LocalToolNames.apkPatchDexStrings,
        path: path,
        args: args,
      );
    }
  }
  Map<String, dynamic>? applyArguments;
  if (dryRun && previewToken != null && previewUsable) {
    applyArguments = _previewApplyArguments(
      args,
      path: path,
      previewToken: previewToken,
    );
    if (_applyRequested(args) && _previewCanApply(result)) {
      previewData = result.data?.map(
        (key, value) => MapEntry(key.toString(), value),
      );
      result = await runPatch(false);
    }
  }
  if (!result.ok) {
    return jsonEncode({
      'error': result.error ?? 'patch_failed',
      'message': result.message,
      'recoverable': true,
    });
  }
  final data = result.data ?? const <String, dynamic>{};
  final applied = !dryRun || previewData != null;
  final encoded = jsonEncode(<String, dynamic>{
    if (!applied) ...{
      'preview': true,
      'matchedStrings': data['matchedStrings'],
      'totalMatched': data['totalMatched'],
      // warning/diagnostics 必须透传：_withPreviewFlow 的 autoApplyBlocked
      // 分支靠它们区分"含 warning"与"0 命中"，丢掉就只剩无信息量兜底文案。
      if (data['warning'] != null) 'warning': data['warning'],
      if (data['diagnostics'] != null) 'diagnostics': data['diagnostics'],
      'message': data['message'],
      // 明确区分"预览成功且有命中"与"预览成功但目标失配"：后者不是可供
      // apply 的预览，顶层把它标出来，调用方不必翻 matchedStrings 才知道。
      if (!previewUsable) 'previewUsable': false,
      if (!previewUsable)
        'previewBlockReason':
            '本次预览 0 命中（逐 key 计数见 matchedStrings，归因见 diagnostics），'
            '未签发 previewToken、未生成 applyArguments —— 目标失配，'
            '按 diagnostics 修正 replacements 后重新 dryRun。',
    },
    if (applied) ...{
      'preview': false,
      'changed': data['changed'] == true,
      if (data['changed'] == true) ...{
        'outputPath': data['outputPath'],
        'matchedStrings': data['matchedStrings'],
        'totalMatched': data['totalMatched'],
        'modifiedDexFiles': data['modifiedDexFiles'],
      },
      'message': data['message'],
    },
    if (previewToken != null) 'previewToken': previewToken,
    if (applyArguments != null) 'applyArguments': applyArguments,
  });
  // v8-D11（2026-10-04 真机）：写入产物登记进台账——过去 dex 字符串补丁的
  // 产物没有独立条目（只作为下一环的 input/rootSource 出现），跨会话没法按
  // 产物身份核验该步（而同链其它步骤都有记录）。
  final producedPath = (data['outputPath'] ?? '').toString();
  if (applied && data['changed'] == true && producedPath.isNotEmpty) {
    await ApkWorkspaceBindingService.recordPatchArtifact(
      source: path,
      output: producedPath,
      operation: 'patch_apk_dex_strings',
    );
  }
  return _withPreviewFlow(
    encoded,
    applyArguments: applyArguments,
    previewData: previewData,
    appliedAfterPreview: previewData != null && result.ok,
    // B2：已成功自动写入（previewData 非空）时不再标 blocked，
    // 与 patchDex/patchManifest 的判定保持一致。
    autoApplyBlocked: dryRun && _applyRequested(args) && previewData == null,
    // 0 命中预览是"目标失配"，不是"预览被 warning 拦住"。两者在
    // _withPreviewFlow 里分叉出不同的 nextStep 文案，靠这个位区分。
    previewMissedTarget: dryRun && !applied && !previewUsable,
  );
}

/// 解析 replacements 参数为 {旧串: 新串}（两形态均收，去重、去空、去恒等）。
/// from == to 的「空操作」条目（F-30：此前被静默丢弃，调用方以为已按原样
/// 执行）。单独收集用于在拒绝/回执里显式点名。
List<String> _sameFromToPairs(Object? value) {
  final out = <String>[];
  void consider(Object? from, Object? to) {
    if (from == null || to == null) return;
    final f = from.toString().trim();
    if (f.isNotEmpty && f == to.toString()) out.add(f);
  }

  if (value is Map) {
    for (final e in value.entries) {
      consider(e.key, e.value);
    }
  } else if (value is List) {
    for (final item in value) {
      if (item is Map) consider(item['from'], item['to']);
    }
  }
  return out;
}

Map<String, String> _stringReplacements(Object? value) {
  if (value is Map) {
    final out = <String, String>{};
    for (final e in value.entries) {
      // v8-D1（2026-10-04 真机）：from **不做 trim**——池里的串常带前导/尾随
      // 空格（" preference="、"app icon "），trim 后永远匹配不上，dryRun 只会
      // 报目标失配且无绕行。只用 trim 判空，匹配用原样。
      final from = e.key.toString();
      final to = e.value.toString();
      if (from.trim().isNotEmpty && from != to) out[from] = to;
    }
    return out;
  }
  if (value is List) {
    final out = <String, String>{};
    for (final item in value) {
      if (item is Map && item['from'] != null && item['to'] != null) {
        final from = item['from'].toString();
        final to = item['to'].toString();
        if (from.trim().isNotEmpty && from != to) out[from] = to;
      }
    }
    return out;
  }
  return const {};
}

/// 重叠场景的基线判定：本次目标与登记链源头是否同一文件（内容 sha256）。
/// 返回 same / different / unknown（无登记源或哈希失败）。
Future<String> _alreadyPatchedBaselineLabel(
  List<Map<String, dynamic>> builds, {
  required String targetPath,
}) async {
  String? targetSha;
  try {
    if (File(targetPath).existsSync()) {
      targetSha = await _sha256OfFile(targetPath);
    } else {
      return 'unknown';
    }
  } catch (_) {
    return 'unknown';
  }
  final candidatePaths = <String>{
    for (final build in builds)
      for (final key in const ['rootSource', 'source', 'input'])
        if ((build[key] ?? '').toString().trim().isNotEmpty)
          build[key].toString().trim(),
  };
  for (final candidate in candidatePaths) {
    try {
      if (File(candidate).existsSync() &&
          await _sha256OfFile(candidate) == targetSha) {
        return 'same';
      }
    } catch (_) {
      // 单个候选不可读不影响其余候选。
    }
  }
  return 'different';
}

/// 扫描 APK 的签名校验命中关键词（DPatch 去签的风险判定）。
/// 走 Kotlin channel 的 scanSignatureCheck（AC 自动机全 dex 扫描）。
Future<List<String>> _scanSignatureCheckHits(String path) async {
  try {
    final r = await ApkToolchainService.scanSignatureCheck(path: path);
    if (!r.ok) return const <String>[];
    final hits = r.data?['hits'];
    if (hits is List) {
      return [for (final h in hits) h.toString()];
    }
    return const <String>[];
  } catch (_) {
    return const <String>[];
  }
}

/// 独立去签工具：只做签名兼容注入，不分析、不改业务、不签名。
///
/// 铁律：只作用于「未改原包」。因此 [args] 必须显式传 apkPath（原始 APK），
/// 不沿用「最新 patch 输出」这类隐式回退——否则会把注入打到已修改包上。
Future<String> _handleApkSignatureBypass(
  Map<String, dynamic> args,
  ChatService? chatService,
  MemoryRepository? memoryRepository,
) async {
  final explicit = (args['apkPath'] ?? '').toString().trim();
  if (explicit.isEmpty) {
    return jsonEncode({
      'error': 'apk_path_required',
      'message':
          '去签必须显式传 apkPath（未改原包）。请先用 list_workspace_apks 或 file(action=list) 确认原包路径，再传 apkPath 调用本工具；不要省略。',
    });
  }
  final (path, pathError) = await _resolveLocalApkPath(args, chatService);
  if (pathError != null) {
    return jsonEncode({'error': 'invalid_apk_path', 'message': pathError});
  }
  if (path == null || path.isEmpty) {
    return jsonEncode({
      'error': 'apk_not_found',
      'message': 'apkPath 无法解析到本地 APK。',
    });
  }
  final requestedMode = args['mode']?.toString().trim() ?? '';
  final mode = requestedMode.isEmpty
      ? await ApkWorkspaceBindingService.signatureBypassDefaultMode()
      : requestedMode;
  if (mode == 'off') {
    return jsonEncode({
      'error': 'signature_bypass_disabled',
      'message': 'APK 工作台当前未开启去签。请在工作台选择普通、原包或 DPatch，或本次调用显式传 mode。',
      // 原因明确时直接给出解法（2026-09-15 真机 P1：通用错误包装曾给
      // task_status/evidence_query 的「原因不明」探查建议，白白多花一轮
      // 调用 + 一次用户确认）。
      'nextActions': [
        {
          'action': 'retry_with_param',
          'tool': 'signature_bypass',
          'param': 'mode',
          'values': ['normal', 'original_apk', 'dpatch'],
          'reason': '工作台默认 mode=off；显式传 mode 即可本次执行，无需改工作台设置。',
        },
        {
          'action': 'ask_user_input_v0',
          'reason': '若不确定用哪种去签方案（普通/原包/DPatch），先问用户。',
        },
      ],
    });
  }
  if (mode != 'normal' && mode != 'original_apk' && mode != 'dpatch') {
    return jsonEncode({
      'error': 'invalid_mode',
      'message': 'mode 仅支持 normal、original_apk 或 dpatch。',
    });
  }
  final outputDir = await ApkWorkspaceBindingService.managedOutputDir();
  if (outputDir == null || outputDir.isEmpty) {
    return jsonEncode({
      'error': 'output_dir_required',
      'message': '请先在 APK 工作台设置工作目录。',
    });
  }
  // 越权面收敛：同 patch_apk_dex_methods，originalApkPath 必须留在工作目录内。
  final originalApkRaw = (args['originalApkPath'] ?? '').toString().trim();
  String? originalApkPath;
  if (originalApkRaw.isNotEmpty) {
    final (resolvedOriginal, originalError) = await _resolveFileOpsPath(
      <String, dynamic>{'path': originalApkRaw},
    );
    if (resolvedOriginal == null) {
      return jsonEncode(originalError ?? _pathOutsideWorkspace(originalApkRaw, ''));
    }
    originalApkPath = resolvedOriginal;
  }
  final r = await ApkStructuralService.patchDexMethods(
    path: path,
    signatureBypass: true,
    signatureBypassMode: mode,
    originalApkPath: mode == 'original_apk' || mode == 'dpatch'
        ? (originalApkPath ?? path)
        : null,
    outputDir: outputDir,
  );
  // D8（2026-09-21 自检）：去签**默认不改变 activeArtifact**。
  // 旧行为里路径解析/登记会顺手把活动产物指针推到刚生成的中转包上，于是
  // "当前修改目标"漂移——后续工具（打点、补丁）落在错误的包上。
  // 需要切换时由调用方显式传 makeActive=true。
  final activeBefore = await ApkWorkspaceBindingService.activeApkPath();
  final wantsActive = args['makeActive'] == true;
  if (!r.ok) {
    // 已处理产物诊断（用户实测缺陷：verify 失败无分类指引）。先做身份
    // 判定，命中处理痕迹时把错误改判为分类诊断 + 恢复路径，并附文件身份。
    final identity = await ApkArtifactIdentityService.identify(
      path,
      memoryRepository: memoryRepository,
    );
    final rawError = r.error ?? 'signature_bypass_failed';
    return jsonEncode({
      'error': identity.isProcessedArtifact
          ? 'signature_bypass_processed_artifact'
          : rawError,
      'message': identity.isProcessedArtifact
          ? '去签失败（${r.displayMessage}），且身份检测确认该文件是本工具链'
                '处理过的产物。恢复路径：① 已注入签名兼容的包不需要再去签'
                '（normal 模式重复注入才会报 old signature entries remain）——'
                '直接在其上叠改；② 确需全新去签，请换回真正的原始包；③ 或改走 '
                'dpatch 模式（原包直补签名）。'
          : '去签失败：${r.displayMessage}',
      'artifactIdentity': identity.toJson(),
      'identityGuidance': identity.guidance,
      if (identity.sha256 != null)
        'fileSha256': identity.sha256!.substring(
          0,
          identity.sha256!.length > 12 ? 12 : identity.sha256!.length,
        ),
      'recoverable': true,
    });
  }
  final output = r.data?['outputPath']?.toString() ?? '';
  if (output.isEmpty ||
      p.normalize(p.absolute(output)) == p.normalize(p.absolute(path))) {
    return jsonEncode({
      'error': 'signature_bypass_output_missing',
      'message': '去签没有生成独立产物，已阻止继续修改原包。请重新执行 signature_bypass。',
    });
  }
  if (output.isNotEmpty) {
    await ApkWorkspaceBindingService.recordPatchArtifact(
      source: path,
      output: output,
      operation: 'signature_compatibility_$mode',
    );
  }
  // D8（2026-09-21 自检）：去签产物路径**复用旧中间包名**（实测出现过
  // 极简记物_3.3.1_v1.apk，那是上一轮已被自动清理的历史中间包路径，两个不同
  // 内容先后占同一个名字，按文件名识别产物必然歧义）。命名规则在原生侧
  // （命名带 mode 后缀需要 outputName 贯通），这里先把"复用旧名"这件事变成
  // 可见信号：产物名已存在于清理过的历史记录里就显式警告。
  final reusableHistory = await ApkWorkspaceBindingService.historicalRecordsFor(
    output,
  );
  // D8：默认把活动产物指针还原回调用前的值（去签只是生成一个中转包，不该
  // 改变"当前修改目标"）。显式 makeActive=true 时才让它前移。
  final activeAfter = await ApkWorkspaceBindingService.activeApkPath();
  var activeRestored = false;
  if (!wantsActive &&
      activeBefore != null &&
      activeBefore.isNotEmpty &&
      activeAfter != null &&
      activeAfter != activeBefore) {
    await ApkWorkspaceBindingService.setActiveApkPath(activeBefore);
    activeRestored = true;
  }
  final driftedActive = await ApkWorkspaceBindingService.activeApkPath();
  return jsonEncode({
    'ok': true,
    'mode': mode,
    'outputPath': output,
    if (mode == 'dpatch')
      'signatureCheckHits': await _scanSignatureCheckHits(path),
    if (r.data?['signatureBypass'] != null)
      'signatureBypass': r.data?['signatureBypass'],
    if (r.data?['signatureBypassVerification'] != null)
      'signatureBypassVerification': r.data?['signatureBypassVerification'],
    if (reusableHistory.isNotEmpty) 'outputNameReusedFromHistory': true,
    if (reusableHistory.isNotEmpty)
      'outputNameReuseNote':
          '输出路径 $output 与 ${reusableHistory.length} 条历史记录重名（这些历史条目指向的内容已被自动清理/替换）。'
          '按文件名识别产物在重名后必然歧义：请以 outputPath 的 sha256 为准，必要时先改名再继续。',
    'activeArtifactAfter': driftedActive,
    if (activeRestored) 'activeArtifactRestored': true,
    if (activeRestored)
      'activeArtifactNote':
          '去签产物已生成，但**活动产物指针已还原**（去签只产生中转包，不改变当前修改目标）。'
          '确实要把它设为后续修改目标时，显式重发本调用并传 makeActive=true。',
    'next':
        '后续所有修改都传这个 outputPath 作为 apkPath，并显式 signatureBypass=false；最终对输出调用 apk_sign 签名。不要在原包或已修改包上重复去签。',
  });
}

/// B6/B7：Manifest 组件/权限清理（dryRun 预览 → confirm 执行）。
Future<String> _handleApkPatchManifest(
  Map<String, dynamic> args,
  ChatService? chatService,
  MemoryRepository? memoryRepository,
) async {
  final (path, pathError) = await _resolveLocalApkPath(args, chatService);
  if (pathError != null) {
    return jsonEncode({'error': 'invalid_apk_path', 'message': pathError});
  }
  if (path == null || path.isEmpty) {
    return jsonEncode({
      'error': 'project_not_ready',
      'message': '请先在 APK 工作台完成分析，或传入 apkPath 绝对路径。',
    });
  }
  final dryRun = args['dryRun'] == true;
  if (!dryRun && args['confirm'] != true && args['applyAfterPreview'] != true) {
    return jsonEncode({
      'error': 'confirmation_required',
      ..._gateEcho(args),
      'message':
          '契约：先用 dryRun=true 预览命中清单，再以相同参数 + applyAfterPreview=true（或 confirm=true）执行。',
    });
  }
  if (!dryRun) {
    final previewError = await _validateMutationPreview(
      args,
      operation: LocalToolNames.apkPatchManifest,
      path: path,
    );
    if (previewError != null) {
      return jsonEncode({'error': 'preview_required', 'message': previewError});
    }
  }
  final outputDir = await ApkWorkspaceBindingService.managedOutputDir();
  if (outputDir == null || outputDir.isEmpty) {
    return jsonEncode({
      'error': 'output_dir_required',
      'message': '还没设置工作目录：去「设置 → 工作台 → 工作区」点「默认工作区」，给它选一个可见目录（APK/SO/文件工具共用同一个根）。',
    });
  }
  Future<ApkStructuralResult> runPatch(bool preview) =>
      ApkStructuralService.patchManifest(
        path: path,
        removeComponents: _stringList(args['removeComponents']),
        removePermissions: _stringList(args['removePermissions']),
        removeMetaData: _stringList(args['removeMetaData']),
        applicationFlags: _applicationFlags(args['applicationFlags']),
        auto: args['auto'] == true,
        outputDir: outputDir,
        dryRun: preview,
      );
  var result = await runPatch(dryRun);
  var effectiveDryRun = dryRun;
  Map<String, Object?>? previewData;
  String? previewToken = dryRun && result.ok
      ? await ApkMutationPreviewService.issue(
          operation: LocalToolNames.apkPatchManifest,
          path: path,
          args: args,
        )
      : (args['previewToken']?.toString());
  Map<String, dynamic>? applyArguments;
  if (dryRun && previewToken != null) {
    applyArguments = _previewApplyArguments(
      args,
      path: path,
      previewToken: previewToken,
    );
    if (_applyRequested(args) && _previewCanApply(result)) {
      previewData = result.data?.map(
        (key, value) => MapEntry(key.toString(), value),
      );
      result = await runPatch(false);
      effectiveDryRun = false;
    }
  }
  final encoded = await _encodeApkMutationResult(
    result,
    sourcePath: path,
    operation: LocalToolNames.apkPatchManifest,
    dryRun: effectiveDryRun,
    previewToken: previewToken,
  );
  return _withPreviewFlow(
    encoded,
    applyArguments: applyArguments,
    previewData: previewData,
    appliedAfterPreview: previewData != null && result.ok,
    autoApplyBlocked: dryRun && _applyRequested(args) && previewData == null,
  );
}

/// F-36（2026-10-04）：记忆族工具失败信封的统一构造。
/// 过去「缺 memoryRepository」被吞成 chat_service_unavailable 且 recoverable:false
/// ——端内 Agent 面从不传 memoryRepository，经验检索/验证回写两条 100% 必挂且
/// 不可重试（v8 真机 D1 实测）。现在两依赖各自给码：memory_store_unavailable
/// （可恢复；进程级 resolver 已在 main.dart 注入，正常装机不会再走到）与
/// chat_service_unavailable；并统一带 ok/code/recoverable 三件套（F-39 的 D 形）。
String _apkMemoryToolError(
  String code,
  String message, {
  required bool recoverable,
}) => jsonEncode({
  'ok': false,
  'error': {'code': code, 'message': message, 'recoverable': recoverable},
  'message': message,
});

/// B8：广告 assets 清理（dryRun 预览 → confirm 执行；被引用不删）。
Future<String> _handleApkPatchMemory(
  Map<String, dynamic> args,
  ChatService? chatService,
  MemoryRepository? memoryRepository,
) async {
  final repository = chatService?.chatRepositoryOrNull;
  if (memoryRepository == null) {
    return _apkMemoryToolError(
      'memory_store_unavailable',
      '补丁记忆库在当前工具面不可用：进程级注入缺失（正常装机不会出现），重启 App 可恢复。',
      recoverable: true,
    );
  }
  if (repository == null) {
    return _apkMemoryToolError(
      'chat_service_unavailable',
      '聊天服务尚未就绪，请稍后再试。',
      recoverable: false,
    );
  }
  // 产物识别模式：给定任意 APK 路径，按内容 sha256 反查——
  // 1) 是否某个已验证补丁记录的成品/基线（跨会话 patch memory 档案）；
  // 2) 是否某个已分析项目的源包（项目注册表）。
  // 修复场景：记忆/笔记里没有基线包记录，Agent 无法识别 _signed.apk
  // 已是改好的成品，从原包重做了一遍。
  final lookupPath = (args['lookupArtifactPath'] ?? '').toString().trim();
  if (lookupPath.isNotEmpty) {
    // 越权面收敛：lookupArtifactPath 此前只查存在性 + 回 sha256，等于给了
    // 「任意宿主文件的探测与指纹比对」能力。限制在工作目录内。
    final lookupWorkDir = await ApkWorkspaceBindingService.workDir();
    final guardedLookup = _guardInsideWorkDir(lookupWorkDir ?? '', lookupPath);
    if (guardedLookup == null) {
      return jsonEncode(_pathOutsideWorkspace(lookupPath, lookupWorkDir ?? ''));
    }
    final f = File(guardedLookup);
    if (!f.existsSync()) {
      return jsonEncode({
        'ok': false,
        'error': 'file_not_found',
        'message': '文件不存在: $lookupPath',
      });
    }
    final sha = await _sha256OfFile(guardedLookup);
    final matches = await ApkPatchMemoryService.findByArtifactSha256(
      memoryRepository,
      sha,
    );
    final project = await ApkProjectService(repository).findBySha256(sha);
    // D21（2026-09-21 复验）：这条路径过去只查两处——已验证补丁记录与项目源包，
    // **完全不查产物台账**，于是"本工具链刚产出、尚未经过安装验证"的包会被判成
    // "未经本助手处理"（复验方实测：同文件 VERIFY_ARTIFACT 报 lineage.tracked=true，
    // 这里却回 not-processed，两套判定互相矛盾）。第三来源：按路径+内容指纹
    // 在台账里找（台账条目带 outputSha256，路径可能已移动，故指纹优先）。
    final builds = await ApkWorkspaceBindingService.readBuilds();
    final lineageEntries = <Map<String, dynamic>>[];
    for (final build in builds) {
      final out = (build['output'] ?? '').toString();
      if (out.isEmpty) continue;
      final recordedSha = (build['outputSha256'] ?? '').toString().trim();
      if (recordedSha.isNotEmpty && recordedSha == sha) {
        lineageEntries.add(build);
        continue;
      }
      // 指纹缺失（旧条目）时退化为路径比对；不拿别人的条目顶替。
      if (out == lookupPath) lineageEntries.add(build);
    }
    return jsonEncode({
      'ok': true,
      'lookupArtifactPath': lookupPath,
      'sha256': sha,
      if (project != null)
        'sourceProject': ApkProjectService(
          repository,
        ).projectInfoForAi(project),
      'verifiedArtifacts': [
        for (final m in matches)
          {
            'id': m.id,
            'title': m.title,
            'outcome': m.outcome,
            'operation': m.operation,
            if (m.pitfall.isNotEmpty) 'pitfall': m.pitfall,
            if (m.targets.isNotEmpty) 'targets': m.targets,
            'solution': m.solution,
            'artifacts': m.artifacts,
          },
      ],
      if (lineageEntries.isNotEmpty)
        'lineageArtifacts': [
          for (final build in lineageEntries)
            {
              'output': build['output'],
              'input': build['input'] ?? build['source'],
              'signed': build['signed'] == true,
              'pendingMemoryStatus': build['pendingMemoryStatus'],
              'pendingChangeCount':
                  (build['pendingChanges'] as List?)?.length ?? 0,
              'timestamp': build['timestamp'],
            },
        ],
      'lineageTracked': lineageEntries.isNotEmpty,
      'hint': matches.isNotEmpty
          ? '该文件是已验证补丁记录的产物（成品或基线）：直接在其上继续叠加修改即可，'
                '不要从原始包重做；沿用记录中的方案（solution）与改点（targets）。'
                '路径可能已移动，以指纹为准。'
          : lineageEntries.isNotEmpty
          ? '该文件是**本工具链产出的中间/成品**（台账有记录，lineageTracked=true），'
                '但尚未经过安装验证，所以没有已验证经验可复用。可继续在其上叠加修改；'
                '若这是最终成品，请在用户确认可安装后走 record_apk_patch_verification 落经验。'
          : project != null
          ? '该文件是已分析项目的源包，可直接继续分析或修改。'
          : '无任何匹配记录：这是未经本助手处理的包（原始包或外部产物），按新任务流程处理。',
    });
  }
  final report = await _readPatchMemoryReport();
  if (report == null) {
    return jsonEncode({
      'error': 'no_apk_selected',
      'message':
          '当前没有 APK 报告，请先在工作台选择并分析；'
          '识别来历不明的包可用 lookupArtifactPath 按文件指纹反查。',
    });
  }
  final vendors = await ApkRuleService(repository).vendorsForReport(report);
  final fingerprint = ApkPatchMemoryService.fingerprintFromReport(
    report,
    vendors: vendors,
  );
  return ApkPatchMemoryService.readForAi(
    memoryRepository,
    fingerprint,
    listAll: args['listAll'] == true,
  );
}

class _DigestCapture implements Sink<Digest> {
  Digest? value;

  @override
  void add(Digest data) => value = data;

  @override
  void close() {}
}

/// 大文件 sha256：流式分块，不整读进内存（APK 可达数百 MB）。
Future<String> _sha256OfFile(String path) async {
  final sink = _DigestCapture();
  final input = sha256.startChunkedConversion(sink);
  await for (final chunk in File(path).openRead()) {
    input.add(chunk);
  }
  input.close();
  return sink.value!.toString();
}

/// 指纹是锦上添花：产物缺失（通道报 ok 但文件没落地等异常态）时返回空串
/// 降级，绝不让 PathNotFound 把已成功的工具结果整个炸成 TOOL_EXCEPTION。
Future<String> _sha256OfFileOrEmpty(String path) async {
  try {
    if (!await File(path).exists()) return '';
    return await _sha256OfFile(path);
  } catch (_) {
    return '';
  }
}

Future<String> _handleApkSavePatchMemory(
  Map<String, dynamic> args,
  ChatService? chatService,
  MemoryRepository? memoryRepository,
) async {
  final title = (args['title'] ?? '').toString().trim();
  final solution = (args['solution'] ?? '').toString().trim();
  if (title.isEmpty || solution.isEmpty) {
    return jsonEncode({
      'error': 'invalid_args',
      'message': 'title 和 solution 都必填。',
    });
  }
  final titleIssue = MemoryQuality.validate(title);
  final solutionIssue = MemoryQuality.validate(solution);
  if (titleIssue != null || solutionIssue != null) {
    return jsonEncode({
      'error': 'quality_rejected',
      'message': titleIssue ?? solutionIssue,
    });
  }
  // 安全审计：补丁记忆也会注入回上下文，注入话术/凭据一律不落盘。
  for (final field in <String, String>{
    'title': title,
    'solution': solution,
  }.entries) {
    final audit = MemoryAudit.inspect(field.value);
    if (audit.blocked) {
      return jsonEncode({
        'error': 'memory_audit_blocked',
        'field': field.key,
        'message': audit.refusalMessage,
        'findings': [for (final finding in audit.findings) finding.toJson()],
      });
    }
  }
  final report = await _readPatchMemoryReport();
  final staged = await ApkWorkspaceBindingService.stagePendingMemoryDraft(
    {
      'title': title,
      'solution': solution,
      'pitfall': (args['pitfall'] ?? args['pitfalls'] ?? '').toString().trim(),
      'targets': _stringList(args['targets']),
      if (report?['packageName'] != null) 'packageName': report!['packageName'],
      if (report?['sha256'] != null) 'reportSha256': report!['sha256'],
      'createdAt': DateTime.now().millisecondsSinceEpoch,
    },
    // D6/D7：按调用方给的 apkPath 绑定；同一方案已 committed 时继承结论，
    // 不把已验证的方案打回待验证。
    targetPath:
        (args['apkPath'] ?? args['path'] ?? '').toString().trim().isEmpty
        ? null
        : (args['apkPath'] ?? args['path']).toString().trim(),
  );
  if (staged == null) {
    return jsonEncode({
      'error': 'signed_artifact_required',
      'message': '请先生成签名成品，再预存待验证修改记录。',
    });
  }
  if (staged['inherited'] == true) {
    return jsonEncode({
      'ok': true,
      'staged': true,
      'memoryStatus': staged['status'],
      'verificationInherited': true,
      'inheritedFrom': staged['inheritedFrom'],
      'persistedToLongTermMemory': true,
      'message':
          '同一方案此前已通过用户验证，本次仅重新签名/打包，记忆状态按单向迁移保持已提交'
          '（不回退为待验证），无需再次向用户复验同一方案。',
    });
  }
  return jsonEncode({
    'ok': true,
    'staged': true,
    'memoryStatus': staged['status'],
    'persistedToLongTermMemory': false,
    'message': '修改记录已预存，尚未写入长期记忆。',
    'nextRequiredTool': LocalToolNames.askUser,
    'mcpFallback': 'MCP 调用方没有提问工具时，可以用文字询问并等待用户明确回复。',
    'questionArguments': _apkVerificationQuestionArguments,
  });
}

const _apkVerificationQuestionArguments = <String, dynamic>{
  'questions': [
    {
      'id': 'apk_install_result',
      'question': '请安装并运行成品，修改是否有效？',
      'type': 'single',
      'options': ['有效', '无效'],
    },
  ],
};

void _markApkAwaitingVerification(Map<String, dynamic> data) {
  data['memoryState'] = 'staged_until_user_verification';
  data['persistedToLongTermMemory'] = false;
  data['verificationRequired'] = true;
  data['completionBlockedUntilUserAnswer'] = true;
  data['nextRequiredTool'] = LocalToolNames.askUser;
  data['questionArguments'] = _apkVerificationQuestionArguments;
  data['mcpFallback'] = 'MCP 调用方没有提问工具时，用文字询问并等待用户明确回复。';
}

Future<Map<String, dynamic>?> _readPatchMemoryReport() async {
  final current = await ApkWorkspaceService.readReport();
  if (current != null) return current;
  final active = await ApkWorkspaceBindingService.activeApkPath();
  final builds = await ApkWorkspaceBindingService.readBuilds();
  final candidates = <String>{};
  if (active != null && active.isNotEmpty) candidates.add(active);
  for (final build in builds) {
    if (active != null && build['output'] != active) continue;
    for (final key in const ['rootSource', 'source', 'input']) {
      final path = (build[key] ?? '').toString();
      if (path.isNotEmpty) candidates.add(path);
    }
  }
  for (final path in candidates) {
    if (!await File(path).exists()) continue;
    final report = await ApkWorkspaceService.findFreshReportForPath(path);
    if (report != null) return report;
  }
  return null;
}

/// REQ-02：列出 MT build 产物索引。
Future<String> _handleApkListBuilds() async {
  final builds = await ApkWorkspaceBindingService.readBuilds();
  // 在场语义显式化（2026-09-15 真机）：条目自带的 exists/state 说的是
  // **该条目的 output** 还在不在磁盘上，而顶层没有汇总，Agent 单看一条
  // 「成品 exists:false」无法判断成品到底还在不在场，还得再去调一次
  // list_workspace_apks。这里补齐：每条 outputPresent/sourcePresent +
  // 顶层在场计数 + 最新在场签名成品。
  final annotated = <Map<String, dynamic>>[];
  var presentOutputs = 0;
  var signedPresent = 0;
  String newestSignedOutputInPlace = '';
  for (final build in builds) {
    final item = Map<String, dynamic>.from(build);
    final output = (item['output'] ?? '').toString();
    final source = (item['source'] ?? item['rootSource'] ?? item['input'] ?? '')
        .toString();
    final outputPresent = output.isNotEmpty && await File(output).exists();
    final sourcePresent = source.isNotEmpty && await File(source).exists();
    item['outputPresent'] = outputPresent;
    item['sourcePresent'] = sourcePresent;
    if (outputPresent) {
      // 包元信息（2026-09-19 复测对照 MT `mt_apk_list_available_apks`：它的
      // 清单每条都带 packageName/versionName，我们只有路径）。体量走 stat，
      // 包信息走**已缓存的新鲜报告**——不为一条清单去重新解析整包。
      try {
        final stat = await File(output).stat();
        item['sizeBytes'] = stat.size;
      } catch (_) {}
      final sha = (item['outputSha256'] ?? '').toString();
      if (sha.length >= 12) item['sha256Short'] = sha.substring(0, 12);
      try {
        final report = await ApkWorkspaceService.findFreshReportForPath(output);
        if (report != null) {
          item['packageName'] = report['packageName'];
          item['versionName'] = report['versionName'];
          item['minSdk'] = report['minSdk'];
          item['targetSdk'] = report['targetSdk'];
        }
      } catch (_) {}
      presentOutputs++;
      if (item['signed'] == true) {
        signedPresent++;
        if (newestSignedOutputInPlace.isEmpty) {
          newestSignedOutputInPlace = output;
        }
      }
    }
    annotated.add(item);
  }
  return jsonEncode({
    'builds': annotated,
    'count': annotated.length,
    'presentOutputs': presentOutputs,
    'missingOutputs': annotated.length - presentOutputs,
    'signedOutputsInPlace': signedPresent,
    if (newestSignedOutputInPlace.isNotEmpty)
      'newestSignedOutputInPlace': newestSignedOutputInPlace,
    'fieldSemantics':
        '条目里的 exists/state 指该条目 output 文件是否还在磁盘上（产物在场）；'
        'outputPresent 同义显式化，sourcePresent 指它的输入包是否在场；'
        '顶层 presentOutputs/missingOutputs/signedOutputsInPlace 是全量汇总，'
        '不需要再调 list_workspace_apks 判断成品在不在场；'
        'sizeBytes 为该产物磁盘体积，packageName/versionName/minSdk 来自'
        '「与产物路径匹配且新鲜」的缓存报告（未分析过的产物只有体积与 sha256Short，'
        '需要包信息时先 analyze_apk_workspace）。',
  });
}

/// 连续修改链的中间包后缀：出现在工作目录根部且不在产物索引里的
/// 即为「无主中间包」（索引 50 条截断 / AI 改名复制的失联产物）。
const _intermediateApkSuffixes = <String>[
  '_dexpatch.apk',
  '_manifest.apk',
  '_structural.apk',
  '_assets.apk',
  '_abi.apk',
  '_rebuilt.apk',
  '_merged.apk',
  '_refactored.apk',
  '_patched.apk',
];

final _intermediateApkVersionPattern = RegExp(
  r'_v\d+\.apk$',
  caseSensitive: false,
);

Future<int> _dirSize(Directory dir) {
  var total = 0;
  return dir
      .list(recursive: true, followLinks: false)
      .handleError((_) {})
      .asyncMap((entry) async {
        if (entry is File) {
          try {
            return await entry.length();
          } catch (_) {
            return 0;
          }
        }
        return 0;
      })
      .forEach((size) => total += size)
      .then((_) => total);
}

/// P3-1 产物清理（流程图②收尾清理的落地版）：
/// - 默认级：SoLab 缓存目录（dexio/jadx/locator，可再生）+ 过期 so 构建
///   产物（patched*.so / *.patch-report.json，保留最近一次 build 的
///   [ToolSessionState.lastBuiltSoPath]）+ 未索引中间包（见 [_intermediateApkSuffixes]）。
/// - aggressive：额外恢复干净基线（保留签名成品、索引内源 APK、当前
///   连续修改目标，其余全清——Blutter 结果/jadx 导出按需重建）。
/// 统一 dryRun → previewToken → confirm 三件套；源 APK 永不删除。
/// 解析 keep/release 参数：接受字符串数组，也接受单个字符串（模型常只给一个）。
List<String> _cleanupPathList(Object? raw) {
  final out = <String>[];
  void add(Object? item) {
    final text = item?.toString().trim() ?? '';
    if (text.isNotEmpty) out.add(text);
  }

  if (raw is String) {
    add(raw);
  } else if (raw is List) {
    for (final item in raw) {
      add(item);
    }
  }
  return List<String>.unmodifiable(out);
}

/// keep/release 的匹配口径：完整路径（规范化后）相等，或 basename 相等
/// （忽略大小写）——与 ApkWorkspaceBindingService.setBuildKeep 保持一致。
bool _cleanupNameMatches(String name, String output) {
  final target = name.trim();
  if (target.isEmpty) return false;
  return p.normalize(p.absolute(target)) == p.normalize(p.absolute(output)) ||
      p.basename(target).toLowerCase() == p.basename(output).toLowerCase();
}

Future<String> _handleApkCleanupBuilds(Map<String, dynamic> args) async {
  final dryRun = args['dryRun'] == true;
  // confirm 与 applyAfterPreview 等价；文案统一走新契约，不再引用 previewToken。
  final confirm = args['applyAfterPreview'] == true || args['confirm'] == true;
  final aggressive = args['aggressive'] == true;
  if (!dryRun && !confirm) {
    return jsonEncode({
      'error': 'confirmation_required',
      ..._gateEcho(args),
      'message':
          '这是删除操作。契约：先 dryRun=true 预览路径与体积，再以相同参数 + applyAfterPreview=true（或 confirm=true）执行。',
    });
  }
  final workDir = await ApkWorkspaceBindingService.workDir();
  if (workDir == null || workDir.isEmpty) {
    return jsonEncode({
      'error': 'output_dir_required',
      'message': '请先在 APK 工作台设置「工作目录」再清理。',
    });
  }
  final previewArgs = <String, dynamic>{...args, 'apkPath': workDir};
  if (!dryRun) {
    final token = args['previewToken']?.toString() ?? '';
    if (token.isEmpty) {
      return jsonEncode({
        'error': 'preview_token_required',
        'message': '缺少 previewToken：先 dryRun=true 获取预览凭证。',
      });
    }
    final check = await ApkMutationPreviewService.validateResult(
      token: token,
      operation: LocalToolNames.apkCleanupBuilds,
      path: workDir,
      args: previewArgs,
    );
    if (check['ok'] != true) return jsonEncode(check);
  }

  final builds = await ApkWorkspaceBindingService.readBuilds();
  // 用户点名「保留」的产物写进台账 keep 标记（docs/Solab.md 明文
  // 「用户明确要求保留的文件不能被自动清理」）。dryRun 是只读契约：参数只用于
  // 如实预览「本次不会删它们」，落盘只发生在真正执行（!dryRun）时。
  final keepArgs = _cleanupPathList(args['keep']);
  final releaseArgs = _cleanupPathList(args['release']);
  final keepMatched = <String>{};
  final releaseMatched = <String>{};
  for (final build in builds) {
    final out = (build['output'] ?? '').toString().trim();
    if (out.isEmpty) continue;
    for (final name in keepArgs) {
      if (_cleanupNameMatches(name, out)) {
        build['keep'] = true;
        keepMatched.add(name);
      }
    }
    for (final name in releaseArgs) {
      if (keepArgs.contains(name)) continue; // 同名同时给出时以 keep 为准
      if (_cleanupNameMatches(name, out)) {
        build.remove('keep');
        releaseMatched.add(name);
      }
    }
  }
  if (!dryRun) {
    for (final name in keepMatched) {
      await ApkWorkspaceBindingService.setBuildKeep(name, true);
    }
    for (final name in releaseMatched) {
      await ApkWorkspaceBindingService.setBuildKeep(name, false);
    }
  }
  // 命中口径分两类：台账里有记录（执行时写 keep 标记，之后所有剪枝与回收
  // 都会跳过它），以及磁盘上有文件但台账没记录（本次靠 kept 名单保护，
  // 无法持久化成标记——索引 50 条截断后改名复制的产物就属于这类）。
  final keepUnindexed = <String>[];
  final resolvedKeep = <String>{...keepMatched};
  for (final name in keepArgs) {
    if (keepMatched.contains(name)) continue;
    final inWorkDir = File(p.join(workDir, p.basename(name)));
    if (File(name).existsSync() || inWorkDir.existsSync()) {
      keepUnindexed.add(name);
      resolvedKeep.add(name);
    }
  }
  final keepUnmatched = <String>[
    ...keepArgs.where((name) => !resolvedKeep.contains(name)),
  ];
  final releaseUnmatched = <String>[
    ...releaseArgs.where(
      (name) => !releaseMatched.contains(name) && !keepArgs.contains(name),
    ),
  ];
  // keep 参数一律解析成绝对路径再进 kept：模型常只给文件名，直接塞原始
  // 字符串会让「不在台账里」的文件照样被删（第 12 轮实测踩到）。
  final kept = <String>{};
  for (final name in keepArgs) {
    final inWorkDir = p.join(workDir, p.basename(name));
    if (File(name).existsSync() || Directory(name).existsSync()) {
      kept.add(p.normalize(p.absolute(name)));
    } else if (File(inWorkDir).existsSync() ||
        Directory(inWorkDir).existsSync()) {
      kept.add(p.normalize(p.absolute(inWorkDir)));
    } else {
      // 找不到就原样留名：执行后进 missingKept，如实报告「计划保留但不在场」。
      kept.add(name);
    }
  }
  final active = await ApkWorkspaceBindingService.activeApkPath();
  if (active != null && active.isNotEmpty) kept.add(active);
  // v9-N4（2026-10-05 真机）：台账产物只在**磁盘上真实存在**时才进 kept——
  // 过去照单全收，被清理/删掉的中间包以幽灵形态留在 keptPaths 里（读的人
  // 以为还在受保护）。
  for (final build in builds) {
    final out = (build['output'] ?? '').toString();
    if (out.isNotEmpty &&
        (build['kind'] == 'build' || build['keep'] == true) &&
        File(out).existsSync()) {
      kept.add(out);
    }
    for (final key in const ['source', 'rootSource', 'input']) {
      final src = (build[key] ?? '').toString();
      if (src.isNotEmpty && p.isWithin(workDir, src) && File(src).existsSync()) {
        kept.add(src);
      }
    }
  }
  var lastBuiltSo = ToolSessionState.lastBuiltSoPath;
  if (lastBuiltSo != null && !await File(lastBuiltSo).exists()) {
    ToolSessionState.lastBuiltSoPath = null;
    ToolSessionState.lastBuiltSoApkPath = null;
    ToolSessionState.lastBuiltSoEntry = null;
    lastBuiltSo = null;
  }

  final candidates = <Map<String, dynamic>>[];
  Future<void> addCandidate(FileSystemEntity entity, String reason) async {
    final path = entity.path;
    if (kept.contains(path)) return;
    // 兜底：basename 命中也算保留（与 setBuildKeep 的匹配口径一致）。
    if (keepArgs.any((name) => _cleanupNameMatches(name, path))) return;
    if (path == lastBuiltSo) return;
    var size = 0;
    if (entity is File) {
      try {
        size = await entity.length();
      } catch (_) {
        return;
      }
    } else if (entity is Directory) {
      size = await _dirSize(entity);
    }
    candidates.add({
      'path': path,
      'type': entity is Directory ? 'dir' : 'file',
      'size': size,
      'reason': reason,
    });
  }

  // —— 默认级收集 ——
  final soLab = Directory(p.join(workDir, 'SoLab'));
  final root = Directory(workDir);
  // 待验证草稿守卫（2026-09-15 真机 P0）：build 台账存在
  // awaiting_user_verification 草稿时，patch-report 是 record_
  // apk_patch_verification 提交时产物指纹的唯一来源——删了它，
  // 用户实机验证通过的结论只能 degraded 记账（无 artifact 指纹）。
  // pending 期间 SO 产物全部保留，dryRun 里如实说明原因。
  //
  // 2026-10-03 报告 F-27：台账是跨会话共享的，**上一轮会话遗留的草稿**
  // 会挡住本轮清理（用户点名）。守卫收窄到「草稿的产物链与当前任务相关」
  // ——即草稿条目的 output/input/source/rootSource 命中当前活动 APK，
  // 或草稿本身没有链条信息时保守保留（宁保守不误删）。
  final activeForDraft = (await ApkWorkspaceBindingService.activeApkPath())
      ?.trim()
      .toLowerCase();
  bool draftBelongsToCurrentChain(Map<String, dynamic> build) {
    final fields = [
      build['output'],
      build['input'],
      build['source'],
      build['rootSource'],
    ].map((v) => (v ?? '').toString().trim().toLowerCase()).where((v) => v.isNotEmpty);
    if (activeForDraft == null || activeForDraft.isEmpty) {
      // 没有活动 APK：无法判定归属，维持保守（任何草稿都算数）。
      return true;
    }
    final list = fields.toList();
    if (list.isEmpty) return true;
    return list.any(
      (v) => v == activeForDraft || v.endsWith(p.basename(activeForDraft)),
    );
  }

  final hasPendingDraft = builds.any(
    (build) =>
        build['pendingMemoryStatus'] == 'awaiting_user_verification' &&
        draftBelongsToCurrentChain(build),
  );
  // v9-N4：草稿的实际操作类型（给 pendingDraftGuard 的 note 用，不再硬编码
  // "SO 补丁"）。
  final draftOperations = <String>{
    for (final build in builds)
      if (build['pendingMemoryStatus'] == 'awaiting_user_verification' &&
          draftBelongsToCurrentChain(build))
        for (final change
            in (build['pendingChanges'] as List? ?? const []))
          if (change is Map &&
              (change['operation'] ?? '').toString().isNotEmpty)
            (change['operation'] ?? '').toString(),
  };
  // 顶层未索引中间包（索引 50 条截断 / AI 改名复制的失联产物）。
  Future<void> collectIntermediateApks() async {
    final indexed = <String>{
      for (final build in builds) (build['output'] ?? '').toString(),
    };
    if (await root.exists()) {
      await for (final entry in root.list().handleError((_) {})) {
        if (entry is! File) continue;
        final name = entry.path.toLowerCase();
        if (!_intermediateApkSuffixes.any(name.endsWith) &&
            !_intermediateApkVersionPattern.hasMatch(name)) {
          continue;
        }
        if (indexed.contains(entry.path)) continue;
        await addCandidate(entry, '未索引中间包');
      }
    }
  }

  if (aggressive) {
    // aggressive 基线：整个 SoLab/ 目录删除（jadx/apkeditor/blutter 产物
    // 均可再生）。顶层只清已识别的中间包后缀——用户放置的原始 APK 和
    // 其他文件即使不在索引里也不动（索引截断可能丢失源 APK 记录）。
    if (await soLab.exists()) {
      await addCandidate(soLab, 'aggressive: SoLab 全部产物（按需重建）');
    }
    await collectIntermediateApks();
  } else {
    // 1) 可再生缓存目录。
    for (final rel in const ['cache/dexio', 'cache/jadx', 'cache/locator']) {
      final dir = Directory(p.join(soLab.path, rel));
      if (await dir.exists()) await addCandidate(dir, 'SoLab 缓存（可再生）');
    }
    // 2) so 构建产物目录：patched*.so 与补丁报告；当前 build 产物保留。
    final soOut = Directory(p.join(soLab.path, 'output/so'));
    if (await soOut.exists()) {
      await for (final entry in soOut.list().handleError((_) {})) {
        if (entry is! File) continue;
        final name = p.basename(entry.path);
        final isSoBuild =
            (name.endsWith('.so') && name.contains('patched')) ||
            name.endsWith('.patch-report.json');
        if (isSoBuild) {
          if (hasPendingDraft) continue; // 守卫：pending 草稿指纹来源
          await addCandidate(entry, '过期 SO 构建产物');
        }
      }
    }
    await collectIntermediateApks();
  }

  if (dryRun) {
    final staleRecords =
        await ApkWorkspaceBindingService.countMissingArtifacts();
    final totalBytes = candidates.fold<int>(
      0,
      (sum, c) => sum + (c['size'] as int),
    );
    final token = await ApkMutationPreviewService.issue(
      operation: LocalToolNames.apkCleanupBuilds,
      path: workDir,
      args: previewArgs,
    );
    // aggressive 专项预警：统计本次将删除的签名成品数。判定口径与现有
    // 代码一致——产物名 _signed.apk / _成品.apk（见 _handleApkSign、
    // already_signed 防呆）或索引登记 kind=build/keep=true 的签名链产物；
    // 落在候选删除路径（如 SoLab/ 目录整体删除）内即视为 at risk。
    var signedArtifactsAtRisk = 0;
    if (aggressive) {
      bool signedName(String fileName) {
        final n = fileName.toLowerCase();
        return n.endsWith('_signed.apk') || n.endsWith('_成品.apk');
      }

      final atRisk = <String>{};
      for (final c in candidates) {
        final path = c['path'] as String;
        if (c['type'] == 'file') {
          if (signedName(p.basename(path))) atRisk.add(path);
          continue;
        }
        // 目录候选（SoLab/ 整体删除）：索引登记的签名成品在其内也会被删
        for (final build in builds) {
          final out = (build['output'] ?? '').toString();
          final registered = build['kind'] == 'build' || build['keep'] == true;
          if (registered && out != path && p.isWithin(path, out)) {
            atRisk.add(out);
          }
        }
        try {
          await for (final f in Directory(
            path,
          ).list(recursive: true).handleError((_) {})) {
            if (f is File && signedName(p.basename(f.path))) {
              atRisk.add(f.path);
            }
          }
        } catch (_) {}
      }
      signedArtifactsAtRisk = atRisk.length;
    }
    return jsonEncode({
      'ok': true,
      'dryRun': true,
      'aggressive': aggressive,
      'itemCount': candidates.length,
      'totalBytes': totalBytes,
      'candidates': candidates,
      'staleRecords': staleRecords,
      if (aggressive) 'signedArtifactsAtRisk': signedArtifactsAtRisk,
      'previewToken': token,
      'keepApplied': keepMatched.toList(growable: false),
      if (releaseMatched.isNotEmpty)
        'releaseApplied': releaseMatched.toList(growable: false),
      if (keepUnmatched.isNotEmpty) 'keepUnmatched': keepUnmatched,
      if (keepUnindexed.isNotEmpty) 'keepUnindexed': keepUnindexed,
      if (releaseUnmatched.isNotEmpty) 'releaseUnmatched': releaseUnmatched,
      if (keepArgs.isNotEmpty || releaseArgs.isNotEmpty)
        'keepNote': 'keep 命中的产物不会出现在候选里；dryRun 不改台账，'
            'dryRun=false + confirm=true 执行时才会写入 keep 标记，'
            '之后所有回收与剪枝都会跳过它们。'
            'keepUnindexed 里的名字磁盘上有文件但台账没记录，'
            '本次受保护、无法写成持久标记，建议用 list_apk_builds 的 output 路径重试。',
      'keptPaths': kept.toList(growable: false),
      if (hasPendingDraft && !aggressive) 'pendingDraftGuard': true,
      'note': aggressive
          ? '⚠️ aggressive 将同时删除 $signedArtifactsAtRisk 个已签名成品。'
                '确认无误后传 previewToken + confirm=true + dryRun=false 执行'
                '（dryRun 保持 true 只会再出一份预览，不会落刀）。'
                '源 APK、当前修改目标不清理。'
          : hasPendingDraft
          ? '确认无误后传 previewToken + confirm=true + dryRun=false 执行。签名成品、源 APK、当前修改目标不清理。'
                // v9-N4：草稿说明按实际操作类型生成（过去硬编码"SO 补丁报告与
                // patched SO"，本链路是 manifest 草稿时文不对题）。
                '存在待验证记忆草稿（${draftOperations.isEmpty ? '未分类' : draftOperations.take(3).join('、')}），'
                '相关产物已保留（pendingDraftGuard），等 record_apk_patch_verification 提交后自动解除。'
          : '确认无误后传 previewToken + confirm=true + dryRun=false 执行。签名成品、源 APK、当前修改目标不清理。',
    });
  }

  // —— 执行 ——
  final deleted = <String>[];
  final failed = <String>[];
  var freedBytes = 0;
  for (final candidate in candidates) {
    final path = candidate['path'] as String;
    try {
      if (candidate['type'] == 'dir') {
        await Directory(path).delete(recursive: true);
      } else {
        await File(path).delete();
      }
      deleted.add(path);
      freedBytes += candidate['size'] as int;
    } catch (_) {
      failed.add(path);
    }
  }
  if (lastBuiltSo != null && deleted.contains(lastBuiltSo)) {
    ToolSessionState.lastBuiltSoPath = null;
    ToolSessionState.lastBuiltSoApkPath = null;
    ToolSessionState.lastBuiltSoEntry = null;
  }
  final prunedRecords =
      await ApkWorkspaceBindingService.pruneMissingArtifacts();
  final token = args['previewToken']?.toString();
  if (token != null && token.isNotEmpty) {
    await ApkMutationPreviewService.consume(
      token: token,
      operation: LocalToolNames.apkCleanupBuilds,
      path: workDir,
      args: previewArgs,
    );
  }
  // D11（2026-09-21 复验第二轮）：dryRun 回执里的 keptPaths 是"计划保留"的路径，
  // 执行后必须按**磁盘实况**重算——复验方实测 keptPaths 里列着已删除的 `_v1.apk`。
  // 语义：keptPaths = 清理结束后仍然存在的保留项；被删的单独进 removedKeptPaths
  // （它们属于"计划保留但实际不在场"，最常见的是台账里有记录、文件早已移动/删除）。
  final survivingKept = <String>[];
  final missingKept = <String>[];
  for (final path in kept) {
    if (await File(path).exists() || await Directory(path).exists()) {
      survivingKept.add(path);
    } else {
      missingKept.add(path);
    }
  }
  return jsonEncode({
    'ok': failed.isEmpty,
    'deletedCount': deleted.length,
    'freedBytes': freedBytes,
    'deleted': deleted,
    'prunedRecords': prunedRecords,
    if (failed.isNotEmpty) 'failed': failed,
    'keptPaths': survivingKept,
    if (keepMatched.isNotEmpty || releaseMatched.isNotEmpty)
      'keepUpdated': <String, dynamic>{
        'kept': keepMatched.toList(growable: false),
        if (releaseMatched.isNotEmpty)
          'released': releaseMatched.toList(growable: false),
      },
    if (keepUnindexed.isNotEmpty) 'keepUnindexed': keepUnindexed,
    if (keepUnmatched.isNotEmpty || releaseUnmatched.isNotEmpty)
      'keepUnmatched': <String, dynamic>{
        if (keepUnmatched.isNotEmpty) 'keep': keepUnmatched,
        if (releaseUnmatched.isNotEmpty) 'release': releaseUnmatched,
        'note':
            '这些名字在台账里没有对应产物记录：本次仍按 kept 集合保护，但无法被长期记住'
            '（下次清理不再自动保留）。请改用 list_apk_builds 给出的 output 路径重试。',
      },
    if (missingKept.isNotEmpty) 'keptPathsMissing': missingKept,
    'keptPathsRechecked': true,
    if (missingKept.isNotEmpty)
      'keptPathsMissingNote':
          '这些路径在台账里被标记为保留，但清理结束时磁盘上不存在'
          '（文件被移动/删除，或登记的就是计划路径）——不是本次清理误删。',
  });
}

/// REQ-02：回收 MT build 产物（保留最新 + keep 标记项）。
Future<List<String>> _apkLineageIds() async {
  final ids = <String>{};
  final report = await _readPatchMemoryReport();
  final packageName = report?['packageName']?.toString().trim() ?? '';
  if (packageName.isNotEmpty) ids.add('app:${packageName.toLowerCase()}');
  final sha = report?['sha256']?.toString() ?? '';
  if (sha.isNotEmpty) ids.add(sha);
  final active = await ApkWorkspaceBindingService.activeApkPath();
  if (active != null && active.isNotEmpty) ids.add('apk_$active');
  final builds = await ApkWorkspaceBindingService.readBuilds();
  for (final build in builds) {
    if (active != null && build['output'] != active) continue;
    for (final key in const ['rootSource', 'source', 'input', 'output']) {
      final path = (build[key] ?? '').toString();
      if (path.isNotEmpty) ids.add('apk_$path');
    }
  }
  if (ids.isEmpty) ids.add('unknown');
  return ids.toList(growable: false);
}

Future<String> _handleApkNoteRead() async {
  final apkIds = await _apkLineageIds();
  final merged = <String, Map<String, dynamic>>{};
  final active = await ApkWorkspaceBindingService.activeApkPath();
  final builds = await ApkWorkspaceBindingService.readBuilds();
  // 血缘内读取（2026-09-15 真机）：此前只认 output == 当前 activeApkPath 的
  // 那一条台账，换了对话/换了产物（新链、源包被重新 analyze）后，旧链的
  // patched locator 就查不到了——它们只在 list_apk_builds.pendingChanges 里
  // 可见，Agent 无法据此避免重复打补丁。现在按血缘根取整条链的记录，
  // 并给每条标注它来自哪个产物。
  final activePath = (active ?? '').trim();
  final activeRoot = activePath.isEmpty
      ? ''
      : await ApkWorkspaceBindingService.lineageRootOf(activePath);
  var scannedBuilds = 0;
  for (final build in builds) {
    final output = (build['output'] ?? '').toString();
    if (output.isEmpty) continue;
    if (activePath.isNotEmpty && output != activePath) {
      final root = await ApkWorkspaceBindingService.lineageRootOf(output);
      final sameLineage = activeRoot.isEmpty
          ? root == output || root.isEmpty
          : root == activeRoot;
      if (!sameLineage) continue;
    }
    scannedBuilds++;
    // 状态单一事实源：build 级 pendingMemoryStatus。验证回填
    // （record_apk_patch_verification）只更新 build 级字段，这里必须联动
    // 读取——否则安装验证成功后 note 仍显示 pending_verification，与
    // 台账的 committed_after_user_verification 自相矛盾（实测复现）。
    final committed =
        build['pendingMemoryStatus'] == 'committed_after_user_verification';
    // F-53（2026-10-04）：产物在场核验。台账路径绑会话工作区，跨会话/清理后
    // pendingChanges 会报出「幽灵待验证项」（真机 v8 D20：血缘指向另一会话、
    // 文件全不在场仍标 pending_verification）。这里对每条产物做 exists 检查，
    // 不在场即显式标注并把状态降级为历史记录——别让人误以为有待验证的改动。
    final artifactPresent = await File(output).exists();
    for (final change in (build['pendingChanges'] as List? ?? const [])) {
      if (change is! Map) continue;
      final locators = <String>{
        if ((change['locator'] ?? '').toString().isNotEmpty)
          (change['locator'] ?? '').toString(),
        for (final locator in _stringList(change['locators']))
          if (locator.toString().isNotEmpty) locator.toString(),
      };
      if (locators.isEmpty) locators.add('auto:${change['operation']}');
      for (final locator in locators) {
        final previous = merged[locator];
        final entry = <String, dynamic>{
          'locator': locator,
          'status': committed ? 'verified' : 'pending_verification',
          'summary': (change['summary'] ?? change['operation'] ?? '')
              .toString(),
          'timestamp': (change['timestamp'] as num?)?.toInt() ?? 0,
          'persistedToLongTermMemory': committed,
          'artifact': output,
          'artifactPresent': artifactPresent,
          if (!artifactPresent)
            'artifactMissingNote':
                '该条目的产物文件已不在盘上（属其他会话或已被清理）：'
                    '本条是历史记录，不是当前包上待验证的改动。',
          if (committed) 'verification': build['verification'],
        };
        // 同一 locator 出现在多个产物上：保留时间较新的那条，并记录它被
        // 打过几次（跨会话判重看的就是这个）。
        final prevAt = (previous?['timestamp'] as num?)?.toInt() ?? -1;
        final curAt = (entry['timestamp'] as num?)?.toInt() ?? 0;
        if (previous == null || curAt >= prevAt) {
          entry['seenOnArtifacts'] =
              ((previous?['seenOnArtifacts'] as num?)?.toInt() ?? 0) + 1;
          merged[locator] = entry;
        } else {
          previous['seenOnArtifacts'] =
              ((previous['seenOnArtifacts'] as num?)?.toInt() ?? 0) + 1;
        }
      }
    }
  }
  final notes = merged.values.toList()
    ..sort(
      (a, b) => ((b['timestamp'] as num?)?.toInt() ?? 0).compareTo(
        (a['timestamp'] as num?)?.toInt() ?? 0,
      ),
    );
  final pathBasedLineage = apkIds.any((id) => id.startsWith('apk_'));
  return jsonEncode({
    'apkId': apkIds.first,
    'lineageIds': apkIds,
    // F-53（2026-10-04）：血缘口径标注。主键 = 包身份（app:<pkg> + sha256），
    // 路径型条目（apk_<path>）只是附注——路径绑会话工作区，跨会话/清理后会
    // 漂移（真机 v8 D20 的幽灵待验证项根因）。仅有路径型血缘时显式降级。
    'lineageBasis': apkIds.first.startsWith('app:') || apkIds.first.length == 64
        ? 'package_identity'
        : 'path_only',
    if (!pathBasedLineage)
      'lineageScopeNote': '当前血缘只有包身份（无路径条目）：本会话尚未绑定产物链，'
          'modified 仅含全局台账记录。',
    'modified': notes,
    'buildsScanned': scannedBuilds,
    'hint': notes.isEmpty
        ? (builds.isEmpty
              ? '当前对话暂无已修改标记，台账里也没有产物记录：先完成一次分析/修改。'
              : '当前对话与血缘内暂无已修改标记（已扫 $scannedBuilds 条台账）。')
        : '含当前血缘（同一 App 的产物链）内的全部已修改标记，每条带 artifact 与 '
              'seenOnArtifacts（重复打点次数）；据此可避免对同一 locator 重复打补丁。'
              '安装验证后才合并到该 APP 的单条长期记忆。',
  });
}

/// REQ-08：写已修改标记。
Future<String> _handleApkNoteWrite(Map<String, dynamic> args) async {
  final locator = (args['locator'] ?? '').toString().trim();
  if (locator.isEmpty) {
    return jsonEncode({'error': 'invalid_args', 'message': 'locator 必填。'});
  }
  final status = (args['status'] ?? 'patched').toString();
  final summary = (args['summary'] ?? '').toString();
  // D7（2026-09-21 自检）：打点按调用方给的 apkPath 钉死绑定。此前只按"写入
  // 时刻的 activeArtifact"落地——对成品打点后紧接着执行 signature_bypass，
  // 打点就挂到了签名兼容基包上（成品那条丢失）。调用方没传 apkPath 时保持
  // 原语义（沿用活动产物）。
  final targetApkPath = (args['apkPath'] ?? args['path'] ?? '')
      .toString()
      .trim();
  final staged = await ApkWorkspaceBindingService.stagePendingChange({
    'locator': locator,
    'status': status,
    'summary': summary,
    'timestamp': DateTime.now().millisecondsSinceEpoch,
  }, targetPath: targetApkPath.isEmpty ? null : targetApkPath);
  if (!staged) {
    return jsonEncode({
      'error': 'patch_artifact_not_found',
      'message': targetApkPath.isEmpty
          ? '当前没有可暂存修改记录的产物。'
          : 'apkPath=$targetApkPath 不是本工作目录里的产物（构建台账里没有这条输出）：'
                '打点必须落在已登记产物上。传工作目录内的成品路径，或省略 apkPath 沿用当前活动产物。',
    });
  }
  return jsonEncode({
    'ok': true,
    'locator': locator,
    'status': status,
    'staged': true,
    'boundTo': targetApkPath.isEmpty ? 'active_artifact' : targetApkPath,
    'persistedToLongTermMemory': false,
  });
}

/// 需求1：列出工作目录里的 APK 文件。
/// 工作区策略自省（自研，只读）。
///
/// 对标 MT MCP 的 `mt_file_access_policy`（2026-09-19 外部 MCP 对比结论）：
/// 外部 agent 先用一次调用问清「我能碰哪些路径、哪些操作要先得到用户同意、
/// 结果有多长」，而不是撞墙之后才从报错里反推规则。
///
/// 内容全部取自代码里的事实源（绑定服务 + [ApkAgentPolicy]），不写死、不猜测；
/// 未绑定工作目录时如实返回 bound=false，不拿默认值糊弄。
Future<String> _handleWorkspacePolicy([
  Map<String, dynamic> args = const {},
]) async {
  final dir = await ApkWorkspaceBindingService.workDir();
  final bound = dir != null && dir.trim().isNotEmpty;
  final activeApk = bound
      ? await ApkWorkspaceBindingService.activeApkPath()
      : null;
  final apks = bound
      ? await ApkWorkspaceBindingService.listApks()
      : const <String>[];
  // F-37（2026-10-04）：新鲜度/指纹在**这里现算**（readReport 有
  // path|size|mtime 进程缓存，源包只做一次 stat）——policy 自己成为事实源，
  // 不再依赖 analysisGuard 状态机的回显（其种子值 missing/'' 曾与
  // get_current_apk_report 的 fresh 给出方向相反的答案，v8 D2）。
  final policyReport = await ApkWorkspaceService.readReport();
  final policyFreshness = policyReport == null
      ? null
      : await ApkWorkspaceService.reportFreshnessOf(policyReport);
  return jsonEncode({
    'ok': true,
    'bound': bound,
    'workDirectory': bound ? dir : null,
    'activeApk': activeApk,
    'knownApkCount': apks.length,
    'reportFreshness': policyFreshness?['status']?.toString() ?? 'missing',
    'apkFingerprint': (policyReport?['sha256'] ?? '').toString(),
    'originalApkReadOnly': true,
    // 分区边界如实公布（用户实测报告第 1 组）：文件工具与 shell 两条通道过去边界
    // 不一致——write_file 对 /skills 报 skills_readonly，而沙盒里的 shell(root) 能
    // 直接写。现在挂载层把 /skills 标只读，由 MountWriteGuards 按前缀拦截常见命令；
    // 但那是**按命令包装的 best-effort**，不是内核级沙盒，必须让调用方知道。
    'zoneBoundaries': <String, Object?>{
      'writable': <String>['/workspace', '/chat', '/tmp', '/mounts/<external>'],
      'readOnly': <String>['/skills'],
      'readOnlyEnforcementOnFileTools':
          'structural: write_file/edit_file return skills_readonly',
      'readOnlyEnforcementOnShell':
          'best-effort: sandbox installs prefix guards for touch/tee/cp/mv/mkdir/'
          'rm/rmdir/ln/dd under read-only mount prefixes. Not a kernel sandbox — a '
          'custom program writing directly can still bypass it, so never treat a '
          'successful shell write to /skills as a supported operation.',
      'outsideSandbox':
          'the guest rootfs has no /system, /vendor, /data, /sdcard; /proc/mounts '
          'still lists device mounts but they are unreachable',
    },
    'pathRule':
        'Only paths inside the bound work directory are reachable '
        '(work-dir file names resolve against it); anything else is refused with '
        'a structured path_out_of_scope / output_path_out_of_scope error.',
    'alwaysBlocked': <String>[
      'the original APK is never modified',
      'signing keystores and private keys never enter the work directory or the model context',
    ],
    'mutationsNeedExplicitUserRequest':
        (ApkAgentPolicy.mutationToolNames.toList()..sort()),
    'previewContract':
        'Preview-capable write tools run dryRun first; when the user authorised '
        'the exact change, pass dryRun=true with applyAfterPreview=true once and '
        'carry the returned nextInputPath previewToken forward verbatim.',
    'resultCaps': <String, Object?>{
      'inlineChars': ApkAgentPolicy.maxVisibleToolResultChars,
      'mcpInlineChars': WorkspacePolicyContract.mcpInlineChars,
      'continuationTool': LocalToolNames.getToolResult,
      'continuationScope': 'agent-face-only',
      'note':
          'A truncated result is continued once via get_tool_result on the agent '
          'face. MCP clients cannot call that tool: a truncated result carries a '
          'narrow_scope nextAction — re-run the source tool with a narrower query '
          '(limit/offset/cursor/keyword) instead of paging repeatedly.',
    },
    // 契约块来自单一事实源（C5 防漂移）：单测断言它与守卫的别名对、
    // MCP 的结果上限一致，任一侧漂移立刻红。
    ...WorkspacePolicyContract.asMap(),
    // C 批/D4 读数出口：includeToolStats=true 时把两侧工具耗时快照一并带回。
    //   - 顶层是 Kotlin 原生工具（so_analyze/blutter）的快照，形状不变；
    //   - `dart` 段是 Dart 面五域（dex/归档/构建/编排/系统）的同一套字段，
    //     由 DartToolStats 记账（§14.15.6 落地）。
    // 两者工具名不重叠（一个 so_analyze:/blutter.*，一个 Dex 面工具名），
    // 需要合并读时按 `tools` 数组并集即可，不必两套读法。
    if (args['includeToolStats'] == true)
      'toolStats': _filterToolStatsPayload(args, <String, Object?>{
        // 2026-10-03 报告 F-11：两侧快照都是**进程级聚合**（跨会话），并非本次
        // 对话的历史——不标注会被新会话误认领（甚至拿别的 App 的失败原文当自己
        // 的教训）。scope 字段把口径钉死。
        'scope': 'process_aggregate',
        'scopeNote': '统计为进程级聚合（跨会话）；它不代表本次对话的历史，'
            '也不要把它当成本会话的失败证据。',
        ...await ApkToolchainService.toolStats(),
        'dart': DartToolStats.snapshot(),
      }),
    'originalInputs':
        'Tools accept path/apkPath; relative names resolve inside the work directory, '
        'and the current artifact (nextInputPath) is the default continuation.',
  });
}

/// F-52（2026-10-04）：toolStats 载荷过滤（get_workspace_policy）。
/// includeToolStats=true 过去一次带回 ~50 个工具的全量统计（tools +
/// slowestTools 双份副本），想看「谁在失败」也得吃全量。toolStatsFilter：
/// `none`=不带明细 / `failures_only`=只留 failed>0 的行 / `top`=按 p95 取
/// 前 10；缺省保持全量（向后兼容）。Kotlin 顶层快照与 `dart` 嵌套段同一过滤。
Map<String, Object?> _filterToolStatsPayload(
  Map<String, dynamic> args,
  Map<String, Object?> payload,
) {
  final filter = (args['toolStatsFilter'] ?? '').toString().trim();
  if (filter.isEmpty) return payload;

  double p95Of(Map<String, dynamic> row) {
    for (final key in const ['p95Ms', 'p95', 'avgMs', 'avg']) {
      final value = row[key];
      if (value is num) return value.toDouble();
    }
    return 0;
  }

  Map<String, Object?> filterSnapshot(Map<String, Object?> snap) {
    if (filter == 'none') {
      return <String, Object?>{
        'filter': 'none',
        'note': 'toolStatsFilter=none：本次不带统计明细；去掉该参数可取全量。',
      };
    }
    final rows = <Map<String, dynamic>>[
      for (final raw in (snap['tools'] as List? ?? const []))
        if (raw is Map)
          {for (final e in raw.entries) e.key.toString(): e.value},
    ];
    List<Map<String, dynamic>> kept;
    switch (filter) {
      case 'failures_only':
        kept = rows
            .where((row) => ((row['failed'] as num?)?.toInt() ?? 0) > 0)
            .toList();
        break;
      case 'top':
        final scored = [...rows]
          ..sort((a, b) => p95Of(b).compareTo(p95Of(a)));
        kept = scored.take(10).toList();
        break;
      default:
        return snap;
    }
    return <String, Object?>{
      ...snap,
      'tools': kept,
      'slowestTools': const <Object?>[],
      'toolCountTotal': rows.length,
      'filterApplied': filter,
    };
  }

  final out = filterSnapshot(payload);
  final dart = out['dart'];
  if (dart is Map) {
    out['dart'] = filterSnapshot(<String, Object?>{
      for (final e in dart.entries) e.key.toString(): e.value,
    });
  }
  return out;
}

Future<String> _handleApkListWorkspace() async {
  final dir = await ApkWorkspaceBindingService.workDir();
  if (dir == null || dir.isEmpty) {
    return jsonEncode({
      'error': 'work_dir_not_set',
      'message': '还没设置工作目录：去「设置 → 工作台 → 工作区」点「默认工作区」，给它选一个可见目录（APK/SO/文件工具共用同一个根）。',
    });
  }
  final dirFile = Directory(dir);
  if (!await dirFile.exists()) {
    return jsonEncode({
      'error': 'work_dir_not_found',
      'message': '工作目录不存在: $dir',
    });
  }
  final apks = await ApkWorkspaceBindingService.listApks();
  final activeApk = await ApkWorkspaceBindingService.activeApkPath();
  final builds = await ApkWorkspaceBindingService.readBuilds();
  final missingArtifacts = builds
      .where((build) => build['exists'] == false)
      .toList(growable: false);
  final activeExists =
      activeApk != null &&
      activeApk.isNotEmpty &&
      await File(activeApk).exists();
  if (apks.isEmpty) {
    // 自诊断：区分「目录为空」与「权限被拒」，给可操作的提示。
    final readable = await ApkWorkspaceBindingService.dirReadable(dir);
    if (!readable) {
      // 主动申请：直接在手机上拉起「所有文件访问」授权页。
      var requested = false;
      try {
        requested = await ApkStructuralService.requestStoragePermission();
      } catch (_) {}
      return jsonEncode({
        'workDir': dir,
        'apks': apks,
        'count': 0,
        'permissionRequested': requested,
        'hint': requested
            ? '目录无法读取，已在手机上拉起「所有文件访问」授权页：请用户完成授权后重试本工具。'
            : '目录无法读取（$dir）：请授予「所有文件访问」权限（系统设置 → 应用 → SoLab）。',
      });
    }
    return jsonEncode({
      'workDir': dir,
      'apks': apks,
      'count': apks.length,
      'activeApkPath': activeApk,
      'activeApkExists': activeExists,
      'missingIndexedArtifacts': missingArtifacts,
    });
  }
  return jsonEncode({
    'workDir': dir,
    'apks': apks,
    'count': apks.length,
    'activeApkPath': activeApk,
    'activeApkExists': activeExists,
    'missingIndexedArtifacts': missingArtifacts,
    if (!activeExists && activeApk != null)
      'recovery': await _missingLocalApkMessage(activeApk),
  });
}

/// 需求1：分析工作目录里指定的 APK 并保存为当前报告。
int _lengthOf(Object? value) => value is List ? value.length : 0;

/// 能力位三态（D22）：报告里**没有这个维度**时回 null（未知），不要回 false。
bool? _capabilityFromReport(Map<Object?, Object?> report, String key) {
  final value = report[key];
  if (value is! List) return null;
  return value.isNotEmpty;
}

Future<String> _handleApkAnalyzeWorkspace(
  Map<String, dynamic> args,
  ChatService? chatService,
  String? conversationId,
) async {
  var fileName = (args['fileName'] ?? '').toString().trim();
  final dir = await ApkWorkspaceBindingService.workDir();
  if (dir == null || dir.isEmpty) {
    return jsonEncode({
      'error': 'work_dir_not_set',
      'message': '请先在 APK 工作台设置「工作目录」。',
    });
  }
  final apks = await ApkWorkspaceBindingService.listApks();
  if (fileName.isEmpty) {
    if (apks.isEmpty) {
      final readable = await ApkWorkspaceBindingService.dirReadable(dir);
      if (!readable) {
        // 主动申请：直接在手机上拉起「所有文件访问」授权页。
        var requested = false;
        try {
          requested = await ApkStructuralService.requestStoragePermission();
        } catch (_) {}
        return jsonEncode({
          'error': 'apk_not_found',
          'workDir': dir,
          'permissionRequested': requested,
          'message': requested
              ? '工作目录无法读取，已在手机上拉起「所有文件访问」授权页：请用户完成授权后重试。'
              : '工作目录无法读取（$dir）：请授予「所有文件访问」权限。',
        });
      }
      return jsonEncode({
        'error': 'apk_not_found',
        'workDir': dir,
        'message': '工作目录中没有 APK 文件。',
      });
    }
    if (apks.length > 1) {
      final active = await ApkWorkspaceBindingService.activeApkPath();
      final knownPaths = apks.map((apk) => apk['path']?.toString()).toSet();
      String? resumable = active != null && knownPaths.contains(active)
          ? active
          : null;
      if (resumable == null) {
        final builds = await ApkWorkspaceBindingService.readBuilds();
        for (final build in builds) {
          final output = build['output']?.toString() ?? '';
          if (build['signed'] == true && knownPaths.contains(output)) {
            resumable = output;
            break;
          }
        }
      }
      if (resumable == null) {
        return jsonEncode({
          'error': 'apk_selection_required',
          'workDir': dir,
          'apks': apks,
          'message': '目录中有多个 APK，当前对话没有可续接产物，请让用户选择其中一个 fileName。',
        });
      }
      fileName = p.basename(resumable);
    } else {
      fileName = apks.single['name']?.toString() ?? '';
    }
  }
  // 防路径穿越：只取文件名。
  final safeName = fileName.split('/').last.split('\\').last;
  final path = p.join(dir, safeName);
  final file = File(path);
  if (!await file.exists()) {
    return jsonEncode({
      'error': 'apk_not_found',
      'message': '工作目录里没有找到 $safeName，可用 file(action=list) 查看实际文件名。',
    });
  }
  final requestedSignatureMode = args['signatureMode']?.toString().trim() ?? '';
  final signatureMode = requestedSignatureMode.isEmpty
      ? await ApkWorkspaceBindingService.signatureBypassDefaultMode()
      : requestedSignatureMode;
  var effectiveSignatureMode = signatureMode == 'off' ? 'skip' : signatureMode;
  // A-1 修复：签名准备失败时自动降级 skip 继续分析（蓝图 §5.1「开工不被
  // 前置条件阻塞」）。目标非干净原包（如已带去签标记的历史包）时签名准备
  // 必撞 SIGNATURE_BYPASS_MODE_SWITCH_REQUIRES_ORIGINAL——签名兼容留给
  // signature_bypass 工具单独处理（它有原包校验），分析本身不该被阻塞。
  var autoSkippedSignaturePrepare = false;
  if (effectiveSignatureMode != 'normal' &&
      effectiveSignatureMode != 'original_apk' &&
      effectiveSignatureMode != 'skip') {
    return jsonEncode({
      'error': 'invalid_signature_mode',
      'message': 'signatureMode 支持 normal、original_apk、skip 或 dpatch。',
    });
  }
  final builds = await ApkWorkspaceBindingService.readBuilds();
  Map<String, dynamic>? selectedArtifact;
  for (final build in builds) {
    if (build['output'] == path) {
      selectedArtifact = build;
      break;
    }
  }
  final reusePreparedArtifact =
      selectedArtifact?['modificationInputReady'] == true ||
      (selectedArtifact?['signatureCompatibility'] ?? '').toString().isNotEmpty;
  var preparedPath = '';
  if (effectiveSignatureMode != 'skip' && !reusePreparedArtifact) {
    final outputDir = await ApkWorkspaceBindingService.managedOutputDir();
    final signaturePrepared = await ApkStructuralService.patchDexMethods(
      path: path,
      signatureBypass: true,
      signatureBypassMode: effectiveSignatureMode,
      originalApkPath:
          effectiveSignatureMode == 'original_apk' ||
              effectiveSignatureMode == 'dpatch'
          ? path
          : null,
      outputDir: outputDir,
    );
    if (!signaturePrepared.ok) {
      // A-1：签名准备失败 → 自动降级 skip，不让签名前置阻塞分析。
      effectiveSignatureMode = 'skip';
      autoSkippedSignaturePrepare = true;
      preparedPath = '';
    } else {
      preparedPath = signaturePrepared.data?['outputPath']?.toString() ?? '';
      if (preparedPath.isEmpty ||
          p.normalize(p.absolute(preparedPath)) ==
              p.normalize(p.absolute(path))) {
        effectiveSignatureMode = 'skip';
        autoSkippedSignaturePrepare = true;
        preparedPath = '';
      }
    }
  }
  final reportPath = preparedPath.isEmpty ? path : preparedPath;
  if (preparedPath.isNotEmpty) {
    await ApkWorkspaceBindingService.recordPatchArtifact(
      source: path,
      output: preparedPath,
      operation: 'signature_compatibility_$effectiveSignatureMode',
    );
  } else {
    await ApkWorkspaceBindingService.setActiveApkPath(path);
  }
  Map<Object?, Object?>? currentReport;
  final savedReport = await ApkWorkspaceService.readReport();
  if (savedReport != null) {
    final source = savedReport['sourceApk'];
    final sourcePath = source is Map ? source['path']?.toString() : null;
    final freshness = await ApkWorkspaceService.reportFreshnessOf(savedReport);
    if (sourcePath == reportPath && freshness['status'] == 'fresh') {
      currentReport = Map<Object?, Object?>.from(savedReport);
    }
  }
  currentReport ??= await ApkWorkspaceService.findFreshReportForPath(
    reportPath,
  );
  currentReport ??= await ApkAnalysisService.analyzeFull(reportPath);
  if (currentReport == null) {
    return jsonEncode({'error': 'analyze_failed', 'message': '分析失败'});
  }
  if (currentReport.containsKey('error')) {
    return jsonEncode(currentReport);
  }
  await ApkWorkspaceService.saveReport(
    currentReport,
    conversationId: conversationId,
  );
  // 落库为项目记录（按 sha256 去重）。
  String? projectId;
  final repository = chatService?.chatRepositoryOrNull;
  if (repository != null) {
    try {
      final project = await ApkProjectService(repository).saveProjectFromReport(
        currentReport.map((key, value) => MapEntry(key.toString(), value)),
        sourcePath: reportPath,
      );
      projectId = project.id;
    } catch (_) {}
  }
  return jsonEncode({
    'ok': true,
    'analyzed': p.basename(reportPath),
    'packageName': currentReport['packageName'],
    'versionName': currentReport['versionName'],
    'shellDetected':
        currentReport['shellPacking'] is Map &&
        (currentReport['shellPacking'] as Map)['detected'] == true,
    'flutterDetected':
        currentReport['flutterApp'] is Map &&
        (currentReport['flutterApp'] as Map)['detected'] == true,
    // 只回样本+总数（全量在 get_current_apk_report 按需分段读取），
    // 避免 analyze 返回体被几百条 pattern 明细撑爆。
    'adSdkMatchSample': ((currentReport['adSdkMatches'] as List?) ?? const [])
        .take(12)
        .toList(),
    'adSdkMatchTotal':
        ((currentReport['adSdkMatches'] as List?) ?? const []).length,
    // 打开即全貌（2026-09-19 全量复测对照 MT `mt_apk_open`）：过去 analyze
    // 只回分析结论，规模与后端能力要再花几轮去试。这里补 counts + capabilities，
    // 让调用方一趟就知道「包里有什么、哪些能力可用、哪些不能用」。
    'counts': <String, dynamic>{
      'totalFiles': currentReport['totalFiles'],
      'dexFiles': currentReport['dexFiles'],
      'resourceFiles': currentReport['resourceFiles'],
      'assetFiles': currentReport['assetFiles'],
      'nativeLibraries': currentReport['nativeLibraries'],
      'abis': currentReport['abis'],
      'activities': _lengthOf(currentReport['activities']),
      'services': _lengthOf(currentReport['services']),
      'receivers': _lengthOf(currentReport['receivers']),
      'providers': _lengthOf(currentReport['providers']),
      'exportedComponents': _lengthOf(currentReport['exportedComponents']),
      'permissions': _lengthOf(currentReport['permissions']),
      'analysisVersion': currentReport['analysisVersion'],
    },
    'capabilities': <String, dynamic>{
      // 能力位的语义是"这套工具/这个目标能不能做这件事"。过去这三个位直接由
      // **报告里有没有列出对应文件**推导（`_lengthOf(report['dexFiles']) > 0`），
      // 于是报告过期/精简/换维度时它们变 false，而 dex_search / so_analyze /
      // 补丁工具其实完全可用——调用方据此以为"能力缺失"而中断（复验 D22）。
      // 现在区分三态：true / false（报告明确给出该维度且为空）/ **null＝报告未
      // 提供这一维度，未知**。未知不等价于没有，验证请直接调对应工具。
      'canReadAxml': true,
      'canSearchDexNames': _capabilityFromReport(currentReport, 'dexFiles'),
      'canPatchDex': _capabilityFromReport(currentReport, 'dexFiles'),
      'canPatchManifest': true,
      'canReadNative': _capabilityFromReport(currentReport, 'nativeLibraries'),
      'capabilitiesNote':
          'canSearchDexNames/canPatchDex/canReadNative 由报告列出的文件推导：null 表示'
          '「本报告未提供该维度」，不是「没有」——直接调 dex_search / so_analyze 等工具即可验证。',
      'canBlutter':
          currentReport['flutterApp'] is Map &&
          (currentReport['flutterApp'] as Map)['detected'] == true,
      // 资源表读取已实装（apk_archive(action=resources)）：按名字/类型/值子串
      // 或 id=0xPPTTEEEE 精读；xref（跨 dex/axml 引用反查）仍缺，另有
      // canReadResourceXref 单独声明，避免调用方把两者混为一谈。
      'canReadResourceTable': true,
      'canReadResourceXref': false,
      'resourceLimits': '默认每资源给首个配置值；按 query 精读时同一 id 可能返回'
          '**多条**（不同语言/密度配置都会列出，如 app_name 同时有中文与英文值）；'
          '复杂值只报类型不展开。',
      'shellPacking':
          currentReport['shellPacking'] is Map &&
          (currentReport['shellPacking'] as Map)['detected'] == true,
      'signingScheme': normalizeSigningSchemeView(currentReport['signingScheme']),
    },
    if (projectId != null) 'projectId': projectId,
    'signatureCompatibility': effectiveSignatureMode == 'skip'
        ? (requestedSignatureMode.isEmpty && signatureMode == 'off'
              ? 'skipped_by_default'
              : 'skipped_by_request')
        : reusePreparedArtifact
        ? 'reused_existing'
        : preparedPath.isEmpty
        ? 'already_prepared'
        : '${effectiveSignatureMode}_prepared',
    if (autoSkippedSignaturePrepare) 'signaturePrepareAutoSkipped': true,
    'signatureDefaultMode': requestedSignatureMode.isEmpty
        ? signatureMode
        : null,
    if (reusePreparedArtifact) 'reusedPreparedArtifact': true,
    'message':
        '分析完成，报告已保存为当前项目，可直接用 get_current_apk_report 读取（命中明细按 section=ads/decision 读取）。',
  });
}

/// 规则库查询：分类统计 + 厂商映射 + 当前报告命中建议。
Future<String> _handleListApkRules(
  Map<String, dynamic> args,
  ChatService? chatService,
) async {
  final repository = chatService?.chatRepositoryOrNull;
  if (repository == null) {
    return jsonEncode({
      'error': 'chat_service_unavailable',
      'message': '聊天服务尚未就绪，请稍后再试。',
    });
  }
  final service = ApkRuleService(repository);
  // 关键：先触发 seed（否则新规则类别 detection_*/time_methods/shell 一直是 0）。
  await service.ensureSeedIfNeeded();
  final vendor = (args['vendor'] ?? '').toString().trim();
  if (vendor.isNotEmpty) {
    final rules = await service.rulesForVendor(vendor);
    // 分页读取：自定义特征可达数千条，默认只给 50 条样本（按需翻页，
    // 不要一次性喂全量），offset/limit 翻页读全量（limit 上限 1000）。
    final offset = (args['offset'] as num?)?.toInt() ?? 0;
    final limit = ((args['limit'] as num?)?.toInt() ?? 50).clamp(1, 1000);
    final window = rules.skip(offset).take(limit).toList();
    final hasMore = offset + window.length < rules.length;
    return jsonEncode({
      'vendor': vendor,
      'label': ApkRuleService.vendorLabels[vendor] ?? vendor,
      'ruleCount': rules.length,
      'offset': offset,
      'limit': limit,
      'hasMore': hasMore,
      if (hasMore) 'nextOffset': offset + window.length,
      // 报告 2-23：单位是**条**（不是字节/字符），显式声明。
      'page': ToolPaging.block(
        unit: ToolPaging.unitItems,
        offset: offset,
        limit: limit,
        returned: window.length,
        total: rules.length,
      ),
      'rules': [
        for (final rule in window)
          {
            'name': rule.name,
            'category': rule.category,
            'enabled': rule.enabled,
            'risk': rule.risk,
          },
      ],
      if (hasMore)
        'pagingHint':
            '共 ${rules.length} 条，仅返回 $offset-${offset + window.length}；传 offset=${offset + window.length} 继续读取。',
    });
  }
  final counts = await service.countsByCategory();
  final report = await ApkWorkspaceService.readReport();
  final matchedVendors = report == null
      ? const <String>[]
      : await service.vendorsForReport(report);
  // 多信号厂商聚合：DEX/Manifest/assets 三信号，按信号数排序
  var vendorSignals = report == null
      ? const <Map<String, dynamic>>[]
      : service.vendorSignalsForReport(report);
  // F-38（2026-10-04）：limit 过去只在 vendor 分支生效，汇总分支整个被吞
  // （真机实测 limit=3 仍回 4 条）。这里对 vendorSignals 生效（0/缺省=不限）。
  final signalLimit = (args['limit'] as num?)?.toInt() ?? 0;
  if (signalLimit > 0 && vendorSignals.length > signalLimit) {
    vendorSignals = vendorSignals.take(signalLimit).toList();
  }
  return jsonEncode({
    'counts': counts,
    // F-18（v9 复测仍现 143 vs 144）：counts = 规则库**当前**行数；
    // 报告 ruleStats = 分析时刻的快照（analysisVersion 锁定）。分析后 seed
    // 新增规则（detection_*/time_methods/shell 首次触发）会做出差值——
    // 两个数各说各的时刻，不是数据损坏；要对比请以重跑 analyze 后的报告为准。
    'countsBasis':
        '规则库当前行数（含未启用）；报告 ruleStats.sdkPackages 是**分析时刻**快照。'
            '分析后新增 seed 规则会产生 ±N 差值，属时序差而非不一致。'
            '需要一致时重跑 analyze_apk_workspace 刷新报告快照。',
    'reportPresent': report != null,
    'matchedVendors': [
      for (final id in matchedVendors)
        {'id': id, 'label': ApkRuleService.vendorLabels[id] ?? id},
    ],
    'vendorSignals': vendorSignals,
    'fieldSemantics': {
      'matchedVendors':
          '确认口径：报告 adSdkMatches 与厂商 sdk 包前缀精确匹配，据此预勾选厂商规则。',
      'vendorSignals':
          '信号口径：DEX 前缀/Manifest 组件/assets 文件名的子串信号（证据词已按特异性收敛），'
              '只用于定位线索，不构成「存在广告 SDK」的证据。',
    },
    if (report == null)
      'reportScopeNote':
          '当前会话作用域没有已保存的分析报告：matchedVendors/vendorSignals 都基于报告计算，'
              '本次为空不是「没有广告 SDK」的结论。先 analyze_apk_workspace 生成当前作用域报告再查。',
    if (matchedVendors.isEmpty && vendorSignals.isNotEmpty)
      'signalOnlyNote':
          'vendorSignals 全部为子串信号、adSdkMatches 精确匹配为空：两字段口径不同（见 fieldSemantics），'
              '不要据此断定有广告 SDK；逐条取证确认后再动手。',
    'hint':
        "matchedVendors=确认命中（可当依据）；vendorSignals=仅定位信号（按证据数降序，不可当证据）。"
        "Use vendor=<id> to list a vendor's rules.",
  });
}

/// 结构操作：先 dryRun 预览，再带 previewToken 和 confirm=true 执行。

/// 写操作确认门的标准诊断载荷：让调用方能自证"服务端实际收到了什么"，
/// 而不是对着固定文案盲试参数拼写。
Map<String, dynamic> _gateEcho(Map<String, dynamic> args) {
  return <String, dynamic>{
    'receivedArgumentCount': args.length,
    'receivedArguments': <String, dynamic>{
      for (final k in args.keys) k: args[k],
    },
    'previewIssued': false,
  };
}

Future<String> _handleSoPatchIntoApk(
  Map<String, dynamic> args,
  ChatService? chatService,
  MemoryRepository? memoryRepository,
) async {
  final dryRun = args['dryRun'] == true;
  // confirm 与 applyAfterPreview 等价接受；两步执行仍由 previewToken
  // 绑定预览参数，已获用户授权时可用 applyAfterPreview 单次预览并写入。
  final confirm = args['confirm'] == true || args['applyAfterPreview'] == true;
  if (!dryRun && !confirm) {
    return jsonEncode({
      'error': 'confirmation_required',
      ..._gateEcho(args),
      'message':
          '这是写操作。先用 dryRun=true 预览，再原样发送返回的 applyArguments；用户已授权精确写回时可直接 dryRun=true + applyAfterPreview=true。可传 sign=true 一步出签名包。本响应附 receivedArguments，可用于核对参数是否送达。',
      'nextAction': '若 receivedArguments 为空或不完整，说明调用层丢参，请整段重发工具调用。',
    });
  }

  // SO 补丁产物：显式 soPath > 最近 so_analyze build 产物
  final soPathRaw = (args['soPath'] ?? '').toString().trim();
  String? soPath;
  if (soPathRaw.isNotEmpty) {
    final (resolved, soErr) = await _resolveFileOpsPath(<String, dynamic>{
      'path': soPathRaw,
    });
    if (resolved == null) {
      return jsonEncode(soErr);
    }
    soPath = resolved;
    if (!await File(soPath).exists()) {
      return jsonEncode({
        'error': 'so_path_not_found',
        'message':
            'SO 补丁文件不存在: $soPath。请重新 so_analyze(action=build)，或传入 list_sources/list_builds 返回的现存路径。',
      });
    }
  } else {
    soPath = ToolSessionState.lastBuiltSoPath;
    if (soPath == null || soPath.isEmpty || !await File(soPath).exists()) {
      final artifacts = await ApkWorkspaceBindingService.readFileArtifacts();
      Map<String, dynamic>? recovered;
      for (final artifact in artifacts) {
        if (artifact['operation'] == 'so_build' && artifact['exists'] == true) {
          recovered = artifact;
          break;
        }
      }
      if (recovered != null) {
        soPath = recovered['path']?.toString();
        ToolSessionState.lastBuiltSoPath = soPath;
        ToolSessionState.lastBuiltSoApkPath = recovered['source']?.toString();
        final metadata = recovered['metadata'];
        if (metadata is Map) {
          ToolSessionState.lastBuiltSoEntry = metadata['sourceEntry']
              ?.toString();
        }
      }
    }
    if (soPath == null || soPath.isEmpty) {
      return jsonEncode({
        'error': 'so_path_required',
        'message':
            '缺少 SO 补丁产物：传 soPath，或先 so_analyze(action=build) 构建（成功后自动记忆，之后可缺省）。',
      });
    }
    // 归属校验：记忆产物属于构建时的连续修改目标；切换 APK 后禁止
    // 隐式复用旧产物注入新包（显式传 soPath 表示 Agent 已确认归属）。
    final rememberedApk = ToolSessionState.lastBuiltSoApkPath;
    final activeTarget = await ApkWorkspaceBindingService.activeApkPath();
    if (rememberedApk != null &&
        rememberedApk.isNotEmpty &&
        activeTarget != null &&
        activeTarget != rememberedApk) {
      return jsonEncode({
        'error': 'so_path_mismatch',
        'message':
            '记忆中的 SO 产物属于 $rememberedApk，与当前连续修改目标 $activeTarget 不一致。'
            '切换 APK 后不能缺省复用：请显式传 soPath（确认归属），或对新 APK 重新 so_analyze(action=build)。',
      });
    }
    if (!await File(soPath).exists()) {
      return jsonEncode({
        'error': 'so_path_required',
        'message':
            '上次 so_analyze(build) 的产物已不存在（可能被签名收口自动清理）：请传 soPath，或重新 build。',
      });
    }
  }

  // 目标 APK：显式 apkPath > 当前连续修改目标
  final (path, pathError) = await _resolveLocalApkPath(args, chatService);
  if (pathError != null) {
    return jsonEncode({'error': 'invalid_apk_path', 'message': pathError});
  }
  if (path == null || path.isEmpty) {
    return jsonEncode({
      'error': 'project_not_ready',
      'message': '需要本地 APK 路径。请先分析 APK，或传入 apkPath 指定当前待修改 APK。',
    });
  }
  // 目标条目：entryName 显式 > 按 so 名自动推断。
  // 剥离策略（逐级放宽，命中即停）：
  // 1) 明确的补丁后缀 -patched/-patch[-N]；
  // 2) 任意最后一个 -/_ 短词缀（≤12 位字母数字，如 -patped/-mod/-v2），
  //    覆盖 AI 自起名与项目硬编码后缀（_dexpatch/_manifest 等）。
  final soStems = <String>[];
  var entryName = (args['entryName'] ?? '').toString().trim();
  var autoResolved = false;
  if (entryName.isEmpty) {
    final libResult = await ApkToolchainService.listLibEntries(path: path);
    if (!libResult.ok) {
      return jsonEncode({
        'error': libResult.error ?? 'list_libs_failed',
        'message': libResult.message ?? '读取 APK lib 条目失败',
      });
    }
    final libEntries = (libResult.data?['entries'] as List? ?? const [])
        .whereType<Map>()
        .toList();
    final abi = (args['abi'] ?? '').toString().trim().toLowerCase();
    final baseStem = p.basenameWithoutExtension(soPath);
    final knownStems =
        libEntries
            .map(
              (entry) => p.basenameWithoutExtension(
                (entry['soName'] ?? entry['name'] ?? '').toString(),
              ),
            )
            .where(
              (known) =>
                  known.isNotEmpty &&
                  (baseStem == known ||
                      baseStem.startsWith('$known-') ||
                      baseStem.startsWith('${known}_') ||
                      baseStem.endsWith('-$known') ||
                      baseStem.endsWith('_$known')),
            )
            .toSet()
            .toList()
          ..sort((a, b) => b.length.compareTo(a.length));
    soStems.addAll(knownStems);
    var stem = baseStem.replaceAll(
      RegExp(r'[-_](patched|patch)([-_]\d+)?$'),
      '',
    );
    if (stem != baseStem) soStems.add(stem);
    final generic = baseStem.replaceFirst(
      RegExp(r'[-_][A-Za-z0-9]{1,12}$'),
      '',
    );
    if (generic != baseStem && generic.isNotEmpty) soStems.add(generic);
    if (!soStems.contains(baseStem)) soStems.add(baseStem);
    final candidates = <String>[];
    for (final s in soStems) {
      candidates.addAll(
        libEntries
            .where((e) => (e['soName'] ?? '').toString() == '$s.so')
            .map((e) => e['name'].toString()),
      );
      if (candidates.isNotEmpty) break;
    }
    if (candidates.isEmpty) {
      final rememberedEntry = ToolSessionState.lastBuiltSoEntry;
      final rememberedCandidates = rememberedEntry == null
          ? const <String>[]
          : libEntries
                .where((e) => e['name'].toString() == rememberedEntry)
                .map((e) => e['name'].toString())
                .toList();
      final libappCandidates = libEntries
          .where((e) => (e['soName'] ?? '').toString() == 'libapp.so')
          .map((e) => e['name'].toString())
          .where((name) => abi.isEmpty || name.startsWith('lib/$abi/'))
          .toList();
      if (rememberedCandidates.length == 1) {
        candidates.add(rememberedCandidates.single);
      } else if (baseStem.toLowerCase().startsWith('patched') &&
          libappCandidates.length == 1) {
        candidates.add(libappCandidates.single);
      }
    }
    if (candidates.isEmpty) {
      // 近似建议：按最长公共前缀/包含关系挑最接近的 lib 条目，
      // 让 AI 一次看清该传什么 entryName，省一轮试错。
      final soNames = libEntries
          .map((e) => (e['soName'] ?? e['name'] ?? '').toString())
          .where((n) => n.isNotEmpty)
          .toList();
      int lcp(String a, String b) {
        var i = 0;
        while (i < a.length && i < b.length && a[i] == b[i]) {
          i++;
        }
        return i;
      }

      final near = soNames.toList()
        ..sort((x, y) {
          final lx = lcp(baseStem, x);
          final ly = lcp(baseStem, y);
          if (lx != ly) return ly - lx;
          return (x.length - y.length);
        });
      final suggestion = near.take(3).isNotEmpty
          ? '最接近的条目: ${near.take(3).map((n) => n).join(', ')}。'
          : '';
      return jsonEncode({
        'error': 'entry_not_found',
        'message':
            'APK 的 lib/ 下没有 ${soStems.first}.so（已尝试剥离补丁后缀: ${soStems.take(2).join(' → ')}）。$suggestion 全部条目: ${libEntries.map((e) => e['name']).take(20).join(', ')}${libEntries.length > 20 ? ' …' : ''}。目标名不同请传 entryName（如 lib/arm64-v8a/xxx.so）。',
      });
    }
    if (abi.isNotEmpty) {
      final hit = candidates.where((c) => c.startsWith('lib/$abi/')).toList();
      if (hit.isEmpty) {
        return jsonEncode({
          'error': 'abi_not_found',
          'message':
              'APK 无 $abi 的 ${soStems.first}.so。候选: ${candidates.join(', ')}。',
        });
      }
      entryName = hit.first;
    } else if (candidates.length == 1) {
      entryName = candidates.first;
    } else {
      return jsonEncode({
        'error': 'ambiguous_abi',
        'message':
            '${soStems.first}.so 命中多个 ABI: ${candidates.join(', ')}。请传 abi 或 entryName 指定目标。',
      });
    }
    autoResolved = true;
  }

  // A4：SO 回填工具只允许写 lib/<abi>/*.so——此前接受任意 entryName，
  // 等于一个通用 zip 覆盖器，是误改 classes.dex/assets 的入口
  // （2026-09-14 缺陷汇报 A4）。
  if (!RegExp(r'^lib/[^/]+/.+\.so$').hasMatch(entryName)) {
    return jsonEncode({
      'error': 'entry_not_patchable',
      'message':
          'so_patch_into_apk 只能回填 lib/<abi>/*.so 条目，收到: $entryName。'
          '其他条目没有通用的流式写入工具（apk_archive 是只读的）：'
          'dex 用 patch_apk_dex_methods / patch_apk_dex_strings，'
          'Manifest 用 patch_apk_manifest，资源/其它条目目前没有入口。',
    });
  }

  final resolvedArgs = <String, dynamic>{
    ...args,
    'apkPath': path,
    'soPath': soPath,
    'entryName': entryName,
  };
  if (!dryRun) {
    final previewError = await _validateMutationPreview(
      resolvedArgs,
      operation: LocalToolNames.soPatchIntoApk,
      path: path,
    );
    if (previewError != null) {
      return jsonEncode({'error': 'preview_required', 'message': previewError});
    }
  }

  final outputDir = await ApkWorkspaceBindingService.managedOutputDir();
  if (outputDir == null || outputDir.isEmpty) {
    return jsonEncode({
      'error': 'output_dir_required',
      'message': '请先在 APK 工作台设置「工作目录」（统一工作目录：APK/SO/文件工具共用），产物才能落外部可访问位置。',
    });
  }
  Future<ApkStructuralResult> runPatch(bool preview) =>
      ApkStructuralService.writeZipEntry(
        path: path,
        entries: [
          {
            'locator': 'zip_entry:$entryName',
            'action': 'overwrite',
            'content': {'path': soPath},
            // 缩水守卫（native shrink_ratio_guard）按 entry 逐条读这个开关：
            // 不在这里透传，schema 承诺的「传 allowShrink:true 重新执行」就是
            // 死路——重试永远撞同一条错误。
            if (args['allowShrink'] == true) 'allowShrink': true,
          },
        ],
        outputDir: outputDir,
        dryRun: preview,
      );
  var result = await runPatch(dryRun);
  if (!result.ok && dryRun) {
    return jsonEncode({
      'error': result.error ?? 'patch_failed',
      'message': result.message ?? 'SO 回填失败',
    });
  }
  var effectiveDryRun = dryRun;
  Map<String, Object?>? previewData;
  final previewToken = dryRun
      ? await ApkMutationPreviewService.issue(
          operation: LocalToolNames.soPatchIntoApk,
          path: path,
          args: resolvedArgs,
        )
      : args['previewToken']?.toString();
  final applyArguments = previewToken == null
      ? null
      : _previewApplyArguments(
          resolvedArgs,
          path: path,
          previewToken: previewToken,
        );
  if (dryRun && _applyRequested(args) && _previewCanApply(result)) {
    previewData = result.data?.map(
      (key, value) => MapEntry(key.toString(), value),
    );
    result = await runPatch(false);
    effectiveDryRun = false;
  }
  var encoded = await _encodeApkMutationResult(
    result,
    sourcePath: path,
    operation: LocalToolNames.soPatchIntoApk,
    dryRun: effectiveDryRun,
    nextStep: effectiveDryRun
        ? '以上为预览。确认后以 confirm=true 执行（可传 sign=true 一步出签名包）。'
        : null,
    previewToken: previewToken,
  );
  encoded = _withPreviewFlow(
    encoded,
    applyArguments: applyArguments,
    previewData: previewData,
    appliedAfterPreview: previewData != null && result.ok,
    autoApplyBlocked: dryRun && _applyRequested(args) && previewData == null,
  );
  // sign=true 链式签名：中间包签名 → 登记签名成品（自动清理同源中间包）。
  // 输出名去套娃：剥掉累积的 _signed/_structural 等中间尾缀后统一加
  // _signed，最终名稳定为「源名_signed」（覆盖旧成品，不产生
  // _signed_structural_signed 链）。
  if (!effectiveDryRun && args['sign'] == true && result.ok) {
    final output = result.data?['outputPath']?.toString() ?? '';
    if (output.isNotEmpty) {
      final signedDir = File(output).parent.path;
      final stem = _artifactBaseStem(output);
      final signedPath = p.join(
        signedDir,
        '${stem.isEmpty ? 'app' : stem}_成品.apk',
      );
      final signed = await ApkToolchainService.apkSign(
        inputApk: output,
        outputApk: signedPath,
      );
      if (signed.ok) {
        final cleaned = await ApkWorkspaceBindingService.recordSignedBuild(
          source: output,
          output: signedPath,
          // 签名成品内容指纹：freshness 校验活动产物、验证对账依赖。
          outputSha256: await _sha256OfFile(signedPath),
        );
        final map = jsonDecode(encoded) as Map<String, dynamic>;
        map['signedPath'] = signedPath;
        _markApkAwaitingVerification(map);
        // 目录净化：补丁 so 已写入签名 APK，使命完成即删，
        // 工作目录只留源包与签名成品（patch-report 含 SHA 可追溯）。
        final soFile = File(soPath);
        if (await soFile.exists()) {
          await soFile.delete();
          map['autoCleanedPaths'] = [
            ...((map['autoCleanedPaths'] as List?) ?? const <String>[]),
            soPath,
          ];
        }
        if (cleaned.isNotEmpty) {
          map['autoCleanedPaths'] = [
            ...((map['autoCleanedPaths'] as List?) ?? const <String>[]),
            ...cleaned,
          ];
        }
        encoded = jsonEncode(map);
      } else {
        final map = jsonDecode(encoded) as Map<String, dynamic>;
        map['signError'] = signed.message ?? signed.error ?? 'sign_failed';
        encoded = jsonEncode(map);
      }
    }
  }
  if (autoResolved) {
    final map = jsonDecode(encoded) as Map<String, dynamic>;
    map['autoResolvedEntry'] = entryName;
    encoded = jsonEncode(map);
  }
  return encoded;
}

String _withPreviewFlow(
  String encoded, {
  Map<String, dynamic>? applyArguments,
  Map<String, Object?>? previewData,
  bool appliedAfterPreview = false,
  bool autoApplyBlocked = false,
  bool previewMissedTarget = false,
}) {
  final decoded = jsonDecode(encoded);
  if (decoded is! Map) return encoded;
  final payload = decoded.map((key, value) => MapEntry(key.toString(), value));
  // 工具执行层真错误（ok:false）：预览归因模板（"预览无变更/warning"）与
  // 实际原因无关——实测 INPUT_TOO_LARGE 被配上"预览无变更"的误导 nextStep。
  // error 两种形态都要接住：Map（{code,message}）与 String（ApkStructuralResult
  // 经 _encodeApkMutationResult 透传的通道错误码，如 INPUT_TOO_LARGE/MEM_PRESSURED）。
  // 按 code 分支生成归因，且不再标 autoApplyBlocked（调用根本没到预览）。
  if (payload['ok'] != true && payload['error'] != null) {
    final rawError = payload['error'];
    final errorCode = rawError is Map
        ? (rawError['code'] ?? 'tool_failed').toString()
        : rawError.toString();
    payload.remove('autoApplyBlocked');
    payload['nextStep'] = switch (errorCode) {
      'INPUT_TOO_LARGE' =>
        '输入体积超过执行预算（见 message），任务未执行。稍候重试'
            '（等待其他任务释放内存后预算自动放宽），或改用更小的动作粒度'
            '（如 jadx 指定 dexName 逐 dex、dex_search 替代整包扫描）。',
      'MEM_PRESSURED' || 'NATIVE_PRESSURED' || 'JVM_OOM' =>
        '服务进程内存压力（$errorCode，见 message），任务未执行。稍候重试'
            '（等待其他任务释放内存），或重启 App 清空堆后再试。',
      _ =>
        '工具执行失败（$errorCode，见 message），未进入预览/写入流程。'
            '按错误信息归因处理后重试。',
    };
    // 单发契约（dryRun+applyAfterPreview）的执行层失败仍要附 applyArguments：
    // 瞬态失败（temporary_write_failure 等）靠它原样重试，预览令牌可复用
    // 语义依赖这个配方（回归锁：failed DEX write keeps preview token
    // reusable）。归因修正不等于丢弃重试入口。
    if (applyArguments != null) payload['applyArguments'] = applyArguments;
    return jsonEncode(payload);
  }
  if (applyArguments != null &&
      (!appliedAfterPreview || payload['ok'] != true)) {
    payload['applyArguments'] = applyArguments;
  }
  if (previewData != null) payload['preview'] = previewData;
  if (appliedAfterPreview) payload['appliedAfterPreview'] = true;
  // 0 命中预览：这不是"工具执行成功"，是"参数指的目标不存在"。整条链路上
  // 最下游的 MCP 信封只认 ok/error 两个字段判成败，而此前这条路径的
  // payload 既无 ok:false 也无 error，落到 _normalizeToolOutput 的兜底分支
  // 就被算成 ok:true（真机实测：调用方看到 success，接着去 apply 必然撞墙）。
  // 这里显式补上失败标记：ok:false + 稳定错误码 no_match，让每个消费层
  // （agent 工具循环 / MCP 客户端 / tool_batch 的 succeeded 计数）都用同一
  // 口径判定。诊断与逐 key 计数照常保留在 data 侧，信息不丢。
  if (previewMissedTarget) {
    payload['ok'] = false;
    payload['error'] = <String, dynamic>{
      'code': 'no_match',
      'message':
          (payload['previewBlockReason'] ?? payload['message'] ?? '预览 0 命中')
              .toString(),
      // 换参数重试有意义（同参数必然再次 0 命中），故 recoverable=true 而
      // retrySameArguments=false —— 与 ToolErrorPolicy 对 no_match 的判定一致。
      'recoverable': true,
      'retrySameArguments': false,
    };
    payload['previewUsable'] = false;
    return jsonEncode(payload);
  }
  if (autoApplyBlocked) {
    // 失配路径（0 命中）不再标 autoApplyBlocked：apply 没执行的原因由
    // diagnostics/nextStep 归因说清（实测该字段在归因正确时是冗余噪音，
    // 调用方误以为"被拦截"而非"目标失配"）。真 warning 拦截仍保留标记。
    final noMatch = payload['totalMatched'] == 0 && payload['warning'] == null;
    if (!noMatch) payload['autoApplyBlocked'] = true;
    // B2：autoApplyBlocked 时把 warning 正文显式提取出来——此前只给固定
    // nextStep 文案，warning 对象内容从未以可读文本出现。
    final warning = payload['warning'];
    String warningText = '';
    if (warning is Map) {
      final msg = warning['message']?.toString() ?? '';
      final type = warning['type']?.toString() ?? '';
      warningText = [
        if (type.isNotEmpty) 'type=$type',
        if (msg.isNotEmpty) msg,
      ].join(' | ');
    } else if (warning is String) {
      warningText = warning;
    }
    if (warningText.isNotEmpty) {
      payload['warningSummary'] = warningText;
      payload['nextStep'] =
          '预览包含 warning（$warningText），未自动写入。针对 warning 修正目标后重试，不要重复相同 dryRun。';
    } else {
      // 失配路径（totalMatched=0，无 warning）：Kotlin 侧已给出 diagnostics
      // 三态归因，摘进 nextStep——必须能区分"串不存在"和"存在但无 const 引用"。
      final diagnostics = payload['diagnostics'];
      String diagnosticHint = '';
      if (diagnostics is Map && diagnostics.isNotEmpty) {
        var absent = 0;
        var noRef = 0;
        diagnostics.forEach((_, value) {
          final status = value is Map ? value['status']?.toString() : null;
          if (status == 'ABSENT') {
            absent++;
          } else if (status == 'PRESENT_NO_CONST_REF') {
            noRef++;
          }
        });
        final parts = <String>[
          if (absent > 0) '$absent 个目标串在所有 DEX 中不存在（多为长文案的子串，精确匹配需完整字面量）',
          if (noRef > 0) '$noRef 个目标串存在但无 const-string 指令引用',
        ];
        diagnosticHint = parts.join('；');
      }
      payload['nextStep'] = diagnosticHint.isEmpty
          ? '预览无变更或含无正文 warning，未自动写入。核对预览数据后修正目标，不要重复相同 dryRun。'
          : '预览 0 命中：$diagnosticHint。按归因修正目标后重试，不要重复相同 dryRun。';
    }
  }
  return jsonEncode(payload);
}

Future<String> _encodeApkMutationResult(
  ApkStructuralResult result, {
  required String sourcePath,
  required String operation,
  required bool dryRun,
  String? nextStep,
  String? previewToken,
  List<String> modifiedLocators = const <String>[],
}) async {
  final data = <String, dynamic>{
    for (final entry in (result.data ?? const <Object?, Object?>{}).entries)
      entry.key.toString(): entry.value,
  };
  final output = data['outputPath']?.toString();
  final autoCleaned =
      !dryRun && result.ok && output != null && output.isNotEmpty
      ? await ApkWorkspaceBindingService.recordPatchArtifact(
          source: sourcePath,
          output: output,
          operation: operation,
          locators: modifiedLocators,
          evidence: _patchNoteEvidence(data),
        )
      : const <String>[];
  // 写操作成功后，基于旧 APK 的全部预览失效，避免不同操作从旧产物分叉。
  final invalidatedTokens = !dryRun && result.ok
      ? await ApkMutationPreviewService.invalidateArtifact(sourcePath)
      : const <String>[];
  // 产物内容指纹（用户实测：输出需可追溯到具体文件，杜绝同名异物）。
  // 流式计算，成功产出时一次 ~1-2s；dryRun 无产物不算。
  String? outputSha;
  if (!dryRun && result.ok && output != null && output.isNotEmpty) {
    try {
      if (File(output).existsSync()) outputSha = await _sha256OfFile(output);
    } catch (_) {}
    // 同步挂进台账：reportFreshness 靠它校验 activeArtifactPath 的内容
    // ——此前指纹只在验证回填时才落台账，验证前的成品被改内容不会判 stale。
    if (outputSha != null) {
      await ApkWorkspaceBindingService.attachBuildOutputSha(output, outputSha);
    }
  }
  return jsonEncode({
    'ok': result.ok,
    'dryRun': dryRun,
    // 目标透明化：明确本次基于哪个 APK 输出，防止连续修改链中
    // 默认目标漂移（如已切到签名包）被误当作「没生效」。
    'basedOnApk': sourcePath,
    if (!result.ok) 'error': result.error,
    'message': result.message,
    'data': data,
    if (output != null && output.isNotEmpty) 'nextInputPath': output,
    if (outputSha != null) ...{
      'outputSha256': outputSha,
      'outputSha256Short': outputSha.substring(0, 12),
      'identityNote':
          '产物内容指纹。后续对产物验身份（是否本工具链产物）用它，'
          '不要只看路径/文件名。',
    },
    if (autoCleaned.isNotEmpty) 'autoCleanedPaths': autoCleaned,
    if (!dryRun && result.ok) 'memoryState': 'staged_until_user_verification',
    if (previewToken != null && (dryRun || !result.ok))
      'previewToken': previewToken,
    if (previewToken != null && !dryRun && !result.ok)
      'previewTokenReusable': true,
    if (invalidatedTokens.isNotEmpty) ...{
      'invalidatedTokens': invalidatedTokens,
      'invalidatedTokenNote':
          '本次写操作已执行，上述未消费的 previewToken 全部失效，'
          '继续修改必须以 nextInputPath 为输入，不得回到旧 APK 或复用旧 token',
    },
    if (nextStep != null) 'nextStep': nextStep,
  });
}

List<String> _patchDexLocators(Map<String, dynamic> args) {
  final locators = <String>{};
  for (final key in [
    'voidMethods',
    'trueMethods',
    'falseMethods',
    'classMethods',
  ]) {
    for (final value in _stringList(args[key])) {
      if (value.startsWith('L') && value.contains('->')) locators.add(value);
    }
  }
  return locators.toList(growable: false);
}

Map<String, dynamic> _patchNoteEvidence(Map<String, dynamic> data) {
  final evidence = <String, dynamic>{};
  void take(String key) {
    final value = data[key];
    if (value is num && value > 0) evidence[key] = value;
    if (value is List && value.isNotEmpty) evidence[key] = value.length;
  }

  for (final key in [
    'voidMethods',
    'trueMethods',
    'falseMethods',
    'nopLoadLibrary',
    'timeMethods',
    'classMethods',
    'modifiedDexFiles',
    'removedPermissions',
    'removedComponents',
    'deletedCount',
    'resSuspectedCount',
  ]) {
    take(key);
  }
  final signatureBypass = data['signatureBypass'];
  if (signatureBypass is Map && signatureBypass.isNotEmpty) {
    evidence['signatureBypass'] = {
      'mode': signatureBypass['mode'],
      'alreadyInjected': signatureBypass['alreadyInjected'],
      'usesEmbeddedOriginalApk': signatureBypass['usesEmbeddedOriginalApk'],
    };
  }
  // zip 条目级改写（so_patch_into_apk 等）的哈希链证据：此前 pendingChanges
  // 只记 operation 名，SO 换掉哪些条目、前后内容指纹全靠调用方自证（实测
  // 回溯断链）。before/after sha256 让成品内的 SO 条目可与补丁前 SO 对账。
  final zipResults = data['results'];
  if (zipResults is List && zipResults.isNotEmpty) {
    evidence['zipEntryResults'] = [
      for (final r in zipResults)
        if (r is Map && ((r['locator'] ?? '').toString().isNotEmpty))
          {
            'locator': r['locator'],
            'action': r['action'],
            if (r['beforeSha256'] != null) 'beforeSha256': r['beforeSha256'],
            if (r['afterSha256'] != null) 'afterSha256': r['afterSha256'],
            if (r['beforeSize'] != null) 'beforeSize': r['beforeSize'],
            if (r['afterSize'] != null) 'afterSize': r['afterSize'],
          },
    ];
  }
  return evidence;
}

List<String> _stringList(Object? value) => switch (value) {
  final List list => list.map((item) => item.toString()).toList(),
  final String text when text.trim().isNotEmpty => <String>[text.trim()],
  _ => const [],
};

/// 解析 applicationFlags（{attrName: bool}）。非 bool 值忽略——防止脏参数
/// 被静默当 true 写进 Manifest。
Map<String, bool> _applicationFlags(Object? value) {
  if (value is! Map) return const {};
  final out = <String, bool>{};
  for (final entry in value.entries) {
    final name = entry.key.toString().trim();
    final v = entry.value;
    if (name.isEmpty) continue;
    if (v is bool) {
      out[name] = v;
    } else if (v is num) {
      out[name] = v != 0;
    } else if (v is String) {
      final t = v.trim().toLowerCase();
      if (t == 'true' || t == '1') {
        out[name] = true;
      } else if (t == 'false' || t == '0') {
        out[name] = false;
      }
    }
  }
  return out;
}

Future<String> _handleClipboardTool(Map<String, dynamic> args) async {
  final action = (args['action'] ?? '').toString();
  switch (action) {
    case 'read':
      final text = await const MethodChannel(
        'solab/device_clipboard',
      ).invokeMethod<String>('readText');
      return jsonEncode({'text': text ?? ''});
    case 'write':
      final text = args['text']?.toString();
      if (text == null) {
        throw ArgumentError('text is required for clipboard write');
      }
      await const MethodChannel(
        'solab/device_clipboard',
      ).invokeMethod<bool>('writeText', {'text': text});
      return jsonEncode({'success': true, 'text': text});
    default:
      throw ArgumentError('unknown clipboard action: $action');
  }
}

Future<String> _handleTextToSpeechTool(
  Map<String, dynamic> args,
  TextToSpeechStarter? onSpeakText,
) async {
  final text = args['text']?.toString().trim();
  if (text == null || text.isEmpty) {
    throw ArgumentError('text is required for text_to_speech');
  }
  if (onSpeakText == null) {
    throw StateError('text-to-speech executor is unavailable');
  }
  await onSpeakText(text);
  return jsonEncode({'success': true});
}

Map<String, dynamic> _buildTimeInfoPayload(DateTime now) {
  final offset = now.timeZoneOffset;
  final offsetSign = offset.isNegative ? '-' : '+';
  final offsetAbs = offset.abs();
  final offsetHours = offsetAbs.inHours.toString().padLeft(2, '0');
  final offsetMinutes = (offsetAbs.inMinutes % 60).toString().padLeft(2, '0');

  final year = now.year.toString().padLeft(4, '0');
  final month = now.month.toString().padLeft(2, '0');
  final day = now.day.toString().padLeft(2, '0');
  final hour = now.hour.toString().padLeft(2, '0');
  final minute = now.minute.toString().padLeft(2, '0');
  final second = now.second.toString().padLeft(2, '0');
  final weekdayEn = _englishWeekdayName(now.weekday);

  return <String, dynamic>{
    'year': now.year,
    'month': now.month,
    'day': now.day,
    'weekday': weekdayEn,
    'weekday_en': weekdayEn,
    'weekday_index': now.weekday,
    'date': '$year-$month-$day',
    'time': '$hour:$minute:$second',
    'datetime': now.toIso8601String(),
    'timezone': now.timeZoneName,
    'utc_offset': '$offsetSign$offsetHours:$offsetMinutes',
    'timestamp_ms': now.millisecondsSinceEpoch,
  };
}

String _englishWeekdayName(int weekday) {
  return switch (weekday) {
    DateTime.monday => 'Monday',
    DateTime.tuesday => 'Tuesday',
    DateTime.wednesday => 'Wednesday',
    DateTime.thursday => 'Thursday',
    DateTime.friday => 'Friday',
    DateTime.saturday => 'Saturday',
    DateTime.sunday => 'Sunday',
    _ => 'Unknown',
  };
}

const MethodChannel _deviceToolsChannel = DeviceLocalTools._channel;

String _deviceTimezoneHint() {
  final now = DateTime.now();
  final offset = now.timeZoneOffset;
  final sign = offset.isNegative ? '-' : '+';
  final abs = offset.abs();
  final hh = abs.inHours.toString().padLeft(2, '0');
  final mm = (abs.inMinutes % 60).toString().padLeft(2, '0');
  return "The device timezone is '${now.timeZoneName}' (UTC offset $sign$hh:$mm); "
      'times without an explicit offset are interpreted in this timezone.';
}

/// deviceGated 工具在当前环境不支持时的统一应答。
///
/// R5：禁止静默返回 null（MCP 面会落成 TOOL_NOT_HANDLED、agent 面落成
/// unknown_function，都不是结构化错误码）。`tool_not_available` 经
/// ToolErrorPolicy 判定 recoverable=false——环境能力缺失，重试无用。
Future<String> _deviceToolNotAvailable(String toolName, String reason) {
  return Future<String>.value(
    jsonEncode({
      'ok': false,
      'error': 'tool_not_available',
      'message': '$toolName is not available in this environment: $reason.',
      'recoverable': false,
    }),
  );
}

/// Invokes a native device tool over the MethodChannel. The native side
/// returns a JSON string payload (including structured error payloads that
/// the model can act on, e.g. missing permissions).
Future<String> _invokeDeviceTool(
  String method,
  Map<String, dynamic> args,
) async {
  try {
    final result = await _deviceToolsChannel.invokeMethod<String>(
      method,
      jsonEncode(args),
    );
    if (result == null || result.isEmpty) {
      return jsonEncode({
        'error': 'no_result',
        'message': 'The device tool returned no result.',
      });
    }
    return result;
  } on MissingPluginException {
    return jsonEncode({
      'error': 'unsupported_platform',
      'message': 'This tool is not available on the current platform.',
    });
  } on PlatformException catch (e) {
    return jsonEncode({
      'error': e.code,
      'message': e.message ?? 'The device tool failed.',
    });
  }
}

/// 进制字面量归一：`0x1F` / `0b1010` / `0o17` → 十进制，并记录替换过程。
///
/// 报告 2-15：`calculate("0x10 + 1")` 过去直接 `parse_error`。逆向场景里偏移、
/// 掩码、长度几乎都是十六进制，最常用的「算一下」反而用不了。归一后把替换过的
/// 字面量一并回报，调用方看得见系统按什么值算的（不静默改写算式）。
({String expression, List<Map<String, String>> literals})
_normalizeCalcRadixLiterals(String raw) {
  final literals = <Map<String, String>>[];
  final pattern = RegExp(r'\b0([xXbBoO])([0-9a-fA-F]+)\b');
  final expression = raw.replaceAllMapped(pattern, (match) {
    final prefix = match.group(1)!.toLowerCase();
    final digits = match.group(2)!;
    final radix = prefix == 'x'
        ? 16
        : prefix == 'b'
        ? 2
        : 8;
    final value = int.tryParse(digits, radix: radix);
    if (value == null) return match.group(0)!; // 非法字面量留给解析器报错
    literals.add(<String, String>{
      'literal': match.group(0)!,
      'decimal': value.toString(),
    });
    return value.toString();
  });
  return (expression: expression, literals: literals);
}

/// 位运算不是数学表达式的表达能力（math_expressions 不支持 & | << >> ~）。
///
/// 与其回一个含糊的 parse_error，直接指向本仓自研的 `value_calc(action=bitwise)`。
String? _unsupportedBitwiseOperator(String expression) {
  for (final operator in const <String>['<<', '>>', '&', '|', '~']) {
    if (expression.contains(operator)) return operator;
  }
  return null;
}

String _handleCalculateTool(Map<String, dynamic> args) {
  final raw = (args['expression'] ?? '').toString().trim();
  if (raw.isEmpty) {
    return jsonEncode({
      'error': 'empty_expression',
      'message':
          'Expression is empty. Please provide a mathematical expression in standard notation, e.g. "(15 + 3) * 2".',
    });
  }

  final normalized = _normalizeCalcRadixLiterals(raw);
  final expression = normalized.expression;

  final bitwise = _unsupportedBitwiseOperator(expression);
  if (bitwise != null) {
    return jsonEncode({
      'error': 'unsupported_operator',
      'message':
          'calculate 只算数学表达式，不支持位运算「$bitwise」。位掩码/移位/异或/取反请用 '
          'value_calc(action=bitwise, op=and|xor|or|shl|shr|not, a=…, b=…, bitWidth=32, from=hex)。',
      'operator': bitwise,
      'suggestedTool': 'value_calc',
      'example': <String, Object?>{
        'action': 'bitwise',
        'op': 'and',
        'a': '0x1F',
        'b': '0x0F',
        'bitWidth': 32,
        'from': 'hex',
      },
      'originalExpression': raw,
      'normalizedExpression': expression,
    });
  }

  try {
    final parsed = GrammarParser().parse(expression);
    final result = parsed.evaluate(EvaluationType.REAL, ContextModel());
    if (!result.isFinite) {
      return jsonEncode({
        'error': 'math_error',
        'message':
            'The result is not a finite number. Please check your expression (e.g. division by zero).',
      });
    }
    return jsonEncode({
      'expression': expression,
      if (normalized.literals.isNotEmpty) 'originalExpression': raw,
      if (normalized.literals.isNotEmpty)
        'radixLiterals': normalized.literals,
      // 整数值不要写成 "17.0"：偏移/长度/掩码几乎都是整数，`.0` 只会让人多想。
      'result': result == result.roundToDouble()
          ? result.toInt().toString()
          : result.toString(),
    });
  } catch (e) {
    // 报告 F-23（v7 D10）：`log(8)` 只报 `Invalid argument: "log"`，没说清
    // 该函数要几个参数。按函数名给可行动的提示。
    final helper = _calculateArityHint(expression);
    return jsonEncode({
      'error': 'parse_error',
      'message':
          'Could not parse the expression. Use standard notation, e.g. "(15 + 3) * 2". '
          'Hexadecimal/binary literals (0x1F, 0b1010) are accepted; bitwise operators are not '
          '(use value_calc).'
          '${helper == null ? '' : ' $helper'}',
      'detail': e.toString(),
      if (helper != null) 'hint': helper,
      if (normalized.literals.isNotEmpty)
        'radixLiterals': normalized.literals,
      'normalizedExpression': expression,
    });
  }
}

/// 已知函数的参数个数提示（报告 F-23）：math_expressions 的报错只给
/// `Invalid argument: "foo"`，缺参/多参都没说清。覆盖仓里会用到的函数。
String? _calculateArityHint(String expression) {
  const arity = <String, String>{
    'log': 'log 需要两个参数：log(base, value)（如 log(2, 8) = 3）；自然对数用 ln(x)。',
    'ln': 'ln 需要一个参数：ln(x)。',
    'sqrt': 'sqrt 需要一个参数：sqrt(x)。',
    'root': 'root 需要两个参数：root(degree, x)。',
    'pow': 'pow 需要两个参数：pow(base, exponent)。',
    'min': 'min 需要至少两个参数：min(a, b, …)。',
    'max': 'max 需要至少两个参数：max(a, b, …)。',
    'abs': 'abs 需要一个参数：abs(x)。',
  };
  for (final entry in arity.entries) {
    // 非裸字符串里 `\s` 会被 Dart 吃成字面 s（上一轮评审 P2）：函数名与
    // 左括号之间允许空白，必须写成 `\\s`。
    if (RegExp('(^|[^A-Za-z0-9_])${RegExp.escape(entry.key)}\\s*\\(')
        .hasMatch(expression)) {
      return entry.value;
    }
  }
  return null;
}

/// 数值/字节级计算（自研 `value_calc`，read-only）。
///
/// 逻辑全在 [ValueCalcService]：这里只做入参传递与 JSON 编码，保持
/// 「补丁值不靠心算」这条契约可被单测直接覆盖（见 value_calc_service_test）。
String _handleValueCalc(Map<String, dynamic> args) {
  return jsonEncode(ValueCalcService.execute(args));
}

// ===== M1: 玄星逆核工具链处理 =====
/// 新工具路径解析：优先显式参数（path/apkPath），绝对路径原样、相对路径
/// join 工作目录；未传回退 activeApkPath（连续修改产物）。
///
/// [bindActive]（F-40）：读类工具传 false——纯解析，不写 activeApk 绑定。
Future<(String?, String?)> _resolveToolchainPath(
  Map<String, dynamic> args, {
  bool bindActive = true,
}) async {
  // 统一路径解析：与 _resolveLocalApkPath 同一实现（apkPath/path 参数语义一致）
  return _resolveLocalApkPath(args, null, bindActive: bindActive);
}

String _encodeToolResult(ApkStructuralResult r) => jsonEncode(
  r.data ??
      {
        'ok': r.ok,
        if (r.error != null) 'error': r.error,
        'message': r.message ?? (r.ok ? 'ok' : '调用失败'),
      },
);

/// 批量模式逐项结果：直接复用 r.data，与 [_encodeToolResult] 解码后形态一致，
/// 省掉每项一次「jsonEncode 再 jsonDecode」的往返（dex_search/smali_read
/// 批量 cap 8，旧实现把编解码放大 8 倍——2026-09-15 性能复查）。
Map<dynamic, dynamic> _toolResultMap(ApkStructuralResult r) =>
    r.data ??
    <String, dynamic>{
      'ok': r.ok,
      if (r.error != null) 'error': r.error,
      'message': r.message ?? (r.ok ? 'ok' : '调用失败'),
    };

Future<String> _handleJadxDecompile(Map<String, dynamic> args) async {
  final (path, err) = await _resolveToolchainPath(args, bindActive: false);
  if (path == null) {
    return jsonEncode({'ok': false, 'error': 'invalid_args', 'message': err});
  }
  final workDir = await ApkWorkspaceBindingService.workDir();
  if (workDir == null || workDir.trim().isEmpty) {
    return jsonEncode({
      'ok': false,
      'error': 'work_dir_required',
      'message': '请先设置工作目录，反编译产物只会写入工作目录。',
    });
  }
  final r = await ApkToolchainService.jadxDecompile(
    path: path,
    action: (args['action'] ?? 'save').toString(),
    className: (args['className'] ?? '').toString(),
    dexName: (args['dexName'] ?? '').toString(),
    limit: (args['limit'] as num?)?.toInt(),
    offset: (args['offset'] as num?)?.toInt(),
    workDir: workDir,
    // INPUT_TOO_LARGE 的显式放行位（native checkInputBudget 消费）。
    allowOversize: args['allowOversize'] == true,
  );
  return _encodeToolResult(r);
}

String _artifactBaseStem(String path) {
  final source = File(path);
  final stem = p.basenameWithoutExtension(path);
  final match = RegExp(r'^(.*)_v\d+$', caseSensitive: false).firstMatch(stem);
  final previous = match?.group(1) ?? '';
  return previous.isNotEmpty &&
          File(p.join(source.parent.path, '$previous.apk')).existsSync()
      ? previous
      : stem;
}

Future<String> _handleApkSign(Map<String, dynamic> args) async {
  // 防呆（真机实测教训）：无 apkPath 的 apk_sign 会落到「当前活动产物」——
  // 若那已是签名成品（*_成品.apk），探测性调用会重复签名出垃圾产物。
  // 隐式目标且看起来已签名时，要求显式 apkPath 或 confirm=true；
  // 正常链路（patch 产物 _dexpatch.apk 等）不受影响。
  final explicitPath = (args['apkPath'] ?? args['path'] ?? '')
      .toString()
      .trim()
      .isNotEmpty;
  if (!explicitPath && (args['confirm'] != true)) {
    final (probed, _) = await _resolveToolchainPath(const {});
    if (probed != null &&
        (p.basename(probed).endsWith('_成品.apk') ||
            p.basename(probed).toLowerCase().endsWith('_signed.apk'))) {
      return jsonEncode({
        'ok': false,
        'error': 'already_signed_confirm_required',
        'message':
            '未传 apkPath 时解析到的目标已是签名成品：$probed。重复签名只会产生冗余产物。'
            '如确需重签：显式传 apkPath；或对本目标传 confirm=true。',
        'recoverable': true,
        'resolvedTarget': probed,
      });
    }
  }
  final (path, err) = await _resolveToolchainPath(args);
  if (path == null) {
    return jsonEncode({'ok': false, 'error': 'invalid_args', 'message': err});
  }
  final workDir = await ApkWorkspaceBindingService.workDir();
  if (workDir == null || workDir.trim().isEmpty) {
    return jsonEncode({
      'ok': false,
      'error': 'work_dir_required',
      'message': '请先设置工作目录，签名产物只会写入工作目录。',
    });
  }
  final requestedOutput = (args['outputApk'] ?? '').toString().trim();
  String outputApk;
  if (requestedOutput.isEmpty) {
    // 成品直接落**工作目录根**（用户 2026-10-03：「本来也是在工作目录下的，为什么
    // 现在要搞那么多子目录」）。与中间包同级，list/验签一眼能看到全部产物；
    // 中间产物仍在各工具的临时区，不会混进这里。
    outputApk = p.join(workDir, '${_artifactBaseStem(path)}_成品.apk');
  } else {
    // T1.1：签名输出路径必须落在统一工作目录内（与输入侧 P0-A 铁律对称）。
    // 绝对路径 guard；相对路径/文件名 join 工作目录。越界一律结构化拒绝，
    // 防远程调用者（MCP）指定任意路径覆盖写。
    final isAbsolute =
        requestedOutput.startsWith('/') || requestedOutput.contains(':');
    if (isAbsolute) {
      final guarded = _guardInsideWorkDir(workDir, requestedOutput);
      if (guarded == null) {
        return jsonEncode({
          'ok': false,
          'error': 'output_path_out_of_scope',
          'message':
              '输出路径越界（$requestedOutput）：签名产物必须写入统一工作目录内（$workDir）。'
              '请改用工作目录内路径或文件名。',
          'recoverable': true,
        });
      }
      outputApk = guarded;
    } else {
      final joined = _joinInsideWorkDir(workDir, requestedOutput);
      if (joined == null) {
        return jsonEncode({
          'ok': false,
          'error': 'output_path_out_of_scope',
          'message':
              '输出路径越界（$requestedOutput）：签名产物必须写入统一工作目录内（$workDir）。'
              '请改用工作目录内路径或文件名。',
          'recoverable': true,
        });
      }
      outputApk = joined;
    }
  }
  await Directory(p.dirname(outputApk)).create(recursive: true);
  // D11（2026-09-21 自检）：覆盖对比必须在**写入前**取旧指纹。旧实现把这次读取
  // 放在 apk_sign 之后，读到的就是刚写好的新文件，于是 overwrittenSha256 与
  // outputSha256 恒等——"被覆盖的旧内容"和"本次产物"同一个哈希，逻辑上不可能，
  // 调用方据此无法判断到底覆盖了什么。
  final existingShaBeforeWrite = await _sha256OfFileOrEmpty(outputApk);
  final r = await ApkToolchainService.apkSign(
    inputApk: path,
    outputApk: outputApk,
    minSdk: (args['minSdk'] as num?)?.toInt(),
  );
  if (!r.ok) return _encodeToolResult(r);
  // P1-8 成品即净：登记签名产物并自动清理同源未签名中间包，
  // 使产物列表与验证记录能读取内置签名产物。
  final data = <String, dynamic>{
    for (final entry in (r.data ?? const <Object?, Object?>{}).entries)
      entry.key.toString(): entry.value,
  };
  final output = data['outputApk']?.toString() ?? '';
  if (output.isNotEmpty) {
    // D19/D20（2026-09-21 独立复验）：这条路径会**静默覆盖**同名成品——复验方
    // 实测 out/成品.apk 被第二次 apk_sign 覆盖、sha256 变化且无任何提示，挂在
    // 旧路径上的修改打点随之查不到（数据丢失）。记录侧已改为"合并打点 + 留档"，
    // 这里再把**磁盘覆盖这件事本身**显式回报：覆盖前的指纹与改名建议。
    final currentSha = await _sha256OfFileOrEmpty(output);
    final overwriteNote = <String, dynamic>{};
    if (existingShaBeforeWrite.isNotEmpty &&
        existingShaBeforeWrite != currentSha) {
      overwriteNote['overwroteExistingOutput'] = true;
      overwriteNote['overwrittenSha256'] = existingShaBeforeWrite;
      overwriteNote['overwriteHint'] =
          '同名产物已被本次签名覆盖（旧内容 sha256 见 overwrittenSha256，'
          '其修改打点已合并进本产物的 pendingChanges）。需要同时保留多版成品时，'
          '签名前把上一版改名或换 outputApk 路径——按文件名识别产物在覆盖后必然歧义。';
    }
    final cleaned = await ApkWorkspaceBindingService.recordSignedBuild(
      source: path,
      output: output,
      // 签名成品内容指纹：freshness 校验活动产物、验证对账依赖。
      outputSha256: currentSha,
    );
    // 一级自动清理（改完即清，免确认）：成品落地后删除工作区内全部
    // 生成型中间包（_dexpatch/_structural/_manifest/_assets/_abi/_signed
    // 旧成品等），保留原包、当前成品、分析目录。修改无效时上一版成品
    // 即下一轮基底——这里绝不动基底与当前成品。
    final intermediateCleaned =
        await ApkWorkspaceBindingService.cleanupIntermediateArtifacts(
          outputPath: output,
        );
    final allCleaned = {...cleaned, ...intermediateCleaned}.toList();
    // DEF-01（2026-09-19 全量复测）：判定必须看 allCleaned——过去只看
    // recordSignedBuild 的返回值，于是「清掉了中间包但 cleaned 为空」时删除
    // 发生却不上报，调用方以为产物还在（复测中因此两次回读踩空）。
    if (allCleaned.isNotEmpty) {
      data['autoCleanedPaths'] = allCleaned;
      data['autoCleanNote'] = '中间包与同源未签名产物已自动清理（成品即净）';
      data['autoCleanCount'] = allCleaned.length;
    }
    data.addAll(overwriteNote);
    // F-19（v6 D18）口径对齐：签名方案以回执为准。
    // 普通路径 = v1+v2+v3；数据复用（multiplexed）路径 =
    // v1 落盘后补 V2/V3（不经 setV2/3SigningEnabled）。回执直接说清，
    // 不再让描述层的“v1/v2/v3”与重新分析的探测口径打架。
    final multiplexed = data['dataMultiplexing'] == true;
    data['signingSchemes'] = <String>['v1', 'v2', 'v3'];
    data['signingSchemeNote'] = multiplexed
        ? '数据复用包：v1 签名后由 V2V3SchemeSigner 补齐 v2/v3（实现路径与普通包不同，'
            '最终产物均含 v1+v2+v3）；重新分析时 signingScheme 在本地不可靠时会标 unknown，'
            '以 MT 等第三方验签为准。'
        : '产物为 v1+v2+v3 全开签名；重新分析时 v2/v3 由 APK Signing Block 解析、'
            'v1 由 META-INF 枚举，两边描述维度不同不等于不一致。';
    // 签名与安装验证解耦：默认 apk_sign 只回纯签名语义（产物+签名状态），
    // 不再默认携带 ask_user 安装等待点字段（completionBlockedUntilUserAnswer 等）。
    // 仅当调用方显式传安装验证相关参数（install / requestInstallVerification /
    // askVerification 任一为 true）才标记等待点；字段名不变，只是不再默认出现。
    final installVerificationRequested =
        args['install'] == true ||
        args['requestInstallVerification'] == true ||
        args['askVerification'] == true;
    if (installVerificationRequested) {
      _markApkAwaitingVerification(data);
    }
  }
  return jsonEncode(data);
}

Future<String> _handleApkRebuild(Map<String, dynamic> args) async {
  final workDir = await ApkWorkspaceBindingService.workDir();
  if (workDir == null || workDir.trim().isEmpty) {
    return jsonEncode({
      'ok': false,
      'error': 'work_dir_required',
      'message': '请先设置工作目录，重建产物只会写入工作目录。',
    });
  }
  final action = (args['action'] ?? 'decode').toString();
  final (path, err) = action == 'build'
      ? await _resolveDecodedApkDirectory(args, workDir)
      : await _resolveToolchainPath(args);
  if (path == null) {
    return jsonEncode({'ok': false, 'error': 'invalid_args', 'message': err});
  }
  final r = await ApkToolchainService.apkRebuild(
    path: path,
    action: action,
    output: (args['output'] ?? '').toString(),
    type: (args['type'] ?? '').toString(),
    dex: args['dex'] as bool?,
    force: args['force'] as bool?,
    cleanMeta: args['cleanMeta'] as bool?,
    fixTypeNames: args['fixTypeNames'] as bool?,
    allowOversize: args['allowOversize'] as bool?,
    workDir: workDir,
  );
  return _encodeToolResult(r);
}

Future<(String?, String?)> _resolveDecodedApkDirectory(
  Map<String, dynamic> args,
  String workDir,
) async {
  var raw = (args['path'] ?? '').toString().trim();
  // zone 别名归一（F-33）：/workspace、/chat、/tmp 与沙盒工具族同一套词表。
  raw = ApkWorkspaceBindingService.resolveZoneAlias(raw) ?? raw;
  if (raw.isEmpty) {
    return (null, 'build 的 path 必须是工作目录内的解码目录。');
  }
  final candidate = raw.startsWith('/') || raw.contains(':')
      ? _guardInsideWorkDir(workDir, raw)
      : _guardInsideWorkDir(workDir, p.join(workDir, raw));
  if (candidate == null) {
    return (null, '路径越界：build 的解码目录必须位于工作目录内。');
  }
  if (!await Directory(candidate).exists()) {
    return (null, '解码目录不存在: $candidate。先调用 apk_rebuild(action=decode)。');
  }
  return (candidate, null);
}

Future<String> _handleDexSearch(Map<String, dynamic> args) async {
  final (path, err) = await _resolveToolchainPath(args, bindActive: false);
  if (path == null) {
    return jsonEncode({'ok': false, 'error': 'invalid_args', 'message': err});
  }
  List<String>? stringTerms(String key) {
    final value = args[key];
    if (value is! List) return null;
    final terms = value
        .map((item) => item.toString().trim())
        .where((item) => item.isNotEmpty)
        .toList(growable: false);
    return terms.isEmpty ? null : terms;
  }

  final keyword = (args['keyword'] ?? '').toString().trim();
  // 批量模式：keywords 数组一次搜多词（cap 8），逐词独立执行、独立截断，
  // 单词零命中不炸批——多词探查场景几十次连调压成一次往返
  final rawKeywords = args['keywords'];
  if (rawKeywords is List && rawKeywords.isNotEmpty) {
    final selected = rawKeywords
        .map((k) => k.toString().trim())
        .where((k) => k.isNotEmpty)
        .take(8)
        .toList();
    final results = <Map<String, dynamic>>[];
    var succeeded = 0;
    for (final k in selected) {
      final r = await ApkToolchainService.dexSearch(
        path: path,
        keyword: k,
        className: (args['className'] ?? '').toString().trim(),
        action: (args['action'] ?? 'auto').toString(),
        matchType: (args['matchType'] ?? 'Contains').toString(),
        ignoreCase: args['ignoreCase'] as bool? ?? false,
        packagePrefix: (args['packagePrefix'] ?? '').toString(),
        limit: (args['limit'] as num?)?.toInt(),
      );
      final decoded = _toolResultMap(r);
      final ok = decoded['ok'] == true;
      if (ok) succeeded++;
      results.add(<String, dynamic>{'keyword': k, 'result': decoded});
    }
    return jsonEncode(<String, dynamic>{
      'ok': succeeded > 0,
      'batch': true,
      'requested': rawKeywords.length,
      'executed': selected.length,
      'succeeded': succeeded,
      'results': results,
      if (rawKeywords.length > 8) 'note': '超出上限 8 的词已截断，请分批重试其余词',
    });
  }
  final numbers = (args['numbers'] as List?)?.whereType<num>().toList(
    growable: false,
  );
  final className = (args['className'] ?? '').toString().trim();
  final methodName = (args['methodName'] ?? '').toString().trim();
  final fieldNames = stringTerms('fieldNames');
  final invokedMethodNames = stringTerms('invokedMethodNames');
  final opNames = stringTerms('opNames');
  if (keyword.isEmpty &&
      (numbers == null || numbers.isEmpty) &&
      className.isEmpty &&
      methodName.isEmpty &&
      fieldNames == null &&
      invokedMethodNames == null &&
      opNames == null) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_args',
      'message': '至少提供一种类、方法、字段、字符串、数字或指令线索',
    });
  }
  final r = await ApkToolchainService.dexSearch(
    path: path,
    keyword: keyword,
    numbers: numbers,
    className: className,
    methodName: methodName,
    fieldNames: fieldNames,
    invokedMethodNames: invokedMethodNames,
    opNames: opNames,
    action: (args['action'] ?? 'auto').toString(),
    matchType: (args['matchType'] ?? 'Contains').toString(),
    ignoreCase: args['ignoreCase'] as bool? ?? false,
    packagePrefix: (args['packagePrefix'] ?? '').toString(),
    limit: (args['limit'] as num?)?.toInt(),
  );
  return _encodeToolResult(r);
}

/// string_scan 高信号词（命中风险分级用）：命中值含任一词（大小写不敏感
/// 子串）即 risk=high，排前；其余 risk=normal。
const _stringScanHighSignalWords = <String>[
  'vip',
  'paid',
  'premium',
  'sign',
  'check',
  'license',
  'root',
  'emulator',
  'verify',
  'pro',
];

bool _isHighSignalStringHit(String value) {
  final lower = value.toLowerCase();
  return _stringScanHighSignalWords.any(lower.contains);
}

/// 轻量分级排序：各 category 数组把高信号条目排前（组内保持原序），
/// locations 条目加 risk 字段并同序重排；不改 totalHits 与截断逻辑。
void _rankStringScanRisk(Map<Object?, Object?> data) {
  final categories = data['categories'];
  if (categories is! Map) return;
  var highTotal = 0;
  var valueTotal = 0;
  final highByCategory = <String, int>{};
  categories.forEach((key, values) {
    if (values is! List) return;
    final highs = <String>[];
    final normals = <String>[];
    for (final v in values) {
      valueTotal++;
      final s = v.toString();
      if (_isHighSignalStringHit(s)) {
        highs.add(s);
      } else {
        normals.add(s);
      }
    }
    highByCategory[key.toString()] = highs.length;
    highTotal += highs.length;
    categories[key] = [...highs, ...normals];
  });
  final locations = data['locations'];
  if (locations is Map) {
    locations.forEach((key, entries) {
      if (entries is! List) return;
      final highs = <Map<String, dynamic>>[];
      final normals = <Map<String, dynamic>>[];
      for (final e in entries) {
        if (e is! Map) continue;
        final item = Map<String, dynamic>.from(e);
        final isHigh = _isHighSignalStringHit((item['value'] ?? '').toString());
        item['risk'] = isHigh ? 'high' : 'normal';
        (isHigh ? highs : normals).add(item);
      }
      locations[key] = [...highs, ...normals];
    });
  }
  data['risk'] = {
    'high': highTotal,
    'normal': valueTotal - highTotal,
    'highByCategory': highByCategory,
    'words': _stringScanHighSignalWords,
    'note':
        'risk=high 表示命中值含高信号词（大小写不敏感子串）；各 category 与 locations 已把 high 条目排前，条目总数与截断不变',
  };
}

Future<String> _handleStringScan(Map<String, dynamic> args) async {
  final (path, err) = await _resolveToolchainPath(args, bindActive: false);
  if (path == null) {
    return jsonEncode({'ok': false, 'error': 'invalid_args', 'message': err});
  }
  final r = await ApkToolchainService.stringScan(
    path: path,
    category: (args['category'] ?? 'all').toString(),
    minLen: (args['minLen'] as num?)?.toInt(),
    limit: (args['limit'] as num?)?.toInt(),
    includePrivate: args['includePrivate'] as bool?,
  );
  if (r.ok && r.data != null) {
    _rankStringScanRisk(r.data!);
  }
  return _encodeToolResult(r);
}

Future<String> _handleApkArchive(
  Map<String, dynamic> args, [
  ToolContext? context,
]) async {
  final (path, err) = await _resolveToolchainPath(args, bindActive: false);
  if (path == null) {
    return jsonEncode({'ok': false, 'error': 'invalid_args', 'message': err});
  }
  // 批量读回（2026-09-15 真机 P1）：验收 N 个改点从 N 次工具调用压成 1 次，
  // 每项支持 va（ELF64 PT_LOAD 自动换算，模型不再做地址算术——实测手工
  // 换算 6 次里错 2 次）或裸 offset。
  //
  // D9（2026-09-21 自检）：读取形状必须唯一可预期。此前只有"reads 是 List
  // 且非空"这一条路，调用方补上 action:'read'（文档写着"action is implied
  // read"）就被 schema 判缺 entry，而裸 {path, reads} 却放行；action:'reads'
  // 更会被 enum 拒成"取值不在允许集合内"——同一意图三种形状两种结局。
  // 现在：reads 存在即批量（action 省略/read/reads 均可），显式给了别的
  // 真实 action 就报冲突而不是静默改语义，action:'reads' 给一条明确指路。
  final readsArg = args['reads'];
  final actionArg = (args['action'] ?? '').toString().trim().toLowerCase();
  // 生效动作（D12 出口要按它决定是否统一 processedArtifact 判定）。
  final actionName = actionArg.isEmpty ? 'list' : actionArg;
  if (readsArg is List && readsArg.isNotEmpty) {
    if (actionArg.isNotEmpty && actionArg != 'read' && actionArg != 'reads') {
      return jsonEncode({
        'ok': false,
        'error': 'conflicting_action',
        'message':
            'reads 是批量读（等价于 action=read 的多次合并），与 action=$actionArg 冲突。'
            '二选一：要么去掉 action 只传 reads，要么去掉 reads 用 action=$actionArg。',
        'action': actionArg,
        'reads': readsArg.length,
      });
    }
    return _handleApkArchiveReads(path, readsArg);
  }
  // 注：`action=reads` 走不到这里——`action` 是带 enum 的参数，参数预校验层
  // （ToolArgumentGuard）会在进 handler 之前就按 allowedValues 拒掉它。
  // 故此处不再放"action=reads 不是动作"的分支（曾经是死代码）；改为在 schema
  // 的 action 描述里明确写出"reads 是数组参数、不是 action 取值"，把错误
  // 挡在调用方生成参数之前。
  final entry = (args['entry'] ?? '').toString();
  final va = _parseElfVa(args['va']);
  var offset = (args['offset'] as num?)?.toInt();
  String? vaEcho;
  if (va != null) {
    final mapped = await _elfVaToEntryOffset(path: path, entry: entry, va: va);
    if (mapped == null) {
      return jsonEncode({
        'ok': false,
        'error': 'VA_NOT_MAPPED',
        'message':
            'va=0x${va.toRadixString(16)} 未落在 entry 的任何 PT_LOAD 段内'
            '（或 entry 不是 ELF64）。确认 VA 与 entry 对应同一个 SO。',
        'entry': entry,
      });
    }
    offset = mapped + (offset ?? 0);
    vaEcho = '0x${va.toRadixString(16)}';
  }
  final r = await ApkToolchainService.apkArchive(
    path: path,
    action: (args['action'] ?? 'list').toString(),
    query: (args['query'] ?? '').toString(),
    entry: entry,
    // entryPrefix 同样要逐键带上（2026-09-21 复测 D1：schema 声明了它、
    // 原生 FileOpsTool 也读它，但这里漏传 → list 恒回全量条目，
    // 调用方看到的是"META-INF 也在里面"，误判过滤生效）。
    entryPrefix: (args['entryPrefix'] ?? '').toString(),
    offset: offset,
    limit: (args['limit'] as num?)?.toInt(),
    minLen: (args['minLen'] as num?)?.toInt(),
    // id / withReferences 必须逐键带上：原生侧读不到就回默认值，表现为"参数被忽略"。
    id: (args['id'] ?? '').toString(),
    withReferences: args['withReferences'] as bool?,
  );
  final payload = Map<String, dynamic>.from(
    _toolResultMap(r).cast<String, dynamic>(),
  );
  if (vaEcho != null) payload['va'] = vaEcho;
  // D12（2026-09-21 自检）：processedArtifact 与 get_apk_project_info 的
  // isProcessedArtifact 必须同源。原生侧只按"内置签名 / 签名代理"两条算，
  // 漏了第三条证据——已验证产物台账里的 sha256 命中（用户自有密钥重签后的
  // 成品就是这么漏掉的）。这里统一改由 ApkArtifactIdentityService 出结论，
  // 原生两个原始证据字段保留用于对账。
  if (actionName == 'certificates' &&
      payload.containsKey('processedArtifact')) {
    final nativeVerdict = payload['processedArtifact'] == true;
    try {
      final identity = await ApkArtifactIdentityService.identify(
        path,
        memoryRepository: context?.memoryRepository,
      );
      if (identity.checkFailed == null) {
        payload['processedArtifact'] = identity.isProcessedArtifact;
        payload['processedArtifactSource'] = 'artifact_identity_service';
        payload['processedArtifactEvidence'] = <String, dynamic>{
          'selfSignedByToolchain': identity.selfSignedByToolchain,
          'signatureProxyInjected': identity.signatureProxyInjected,
          'verifiedArtifactCount': identity.verifiedArtifactMatches.length,
          'nativeVerdict': nativeVerdict,
        };
        if (nativeVerdict != identity.isProcessedArtifact) {
          payload['processedArtifactNote'] =
              '原生证书扫描与产物身份判定不一致（native=$nativeVerdict，'
              'identity=${identity.isProcessedArtifact}）：产物台账（sha256 命中的已验证记录）'
              '是第三类证据，已以身份判定为准。';
        }
      } else {
        // 身份检测跑完但自身失败（如 APK 不可读）：不改判定，但**必须标来源**——
        // 否则调用方分不清这个 false 是"判定为原包"还是"没检测成"。
        payload['processedArtifactSource'] = 'native_certificate_scan';
        payload['processedArtifactNote'] =
            '产物身份检测未完成（${identity.checkFailed}），本次结论来自原生证书扫描，'
            '只覆盖"内置签名 / 签名代理"两类证据，可能漏判（例如用户自有密钥重签的成品）。';
      }
    } catch (_) {
      // 身份检测不可用时不改判定，保持原生结论（并如实标注来源）。
      payload['processedArtifactSource'] = 'native_certificate_scan';
    }
  }
  return jsonEncode(payload);
}

/// va 参数解析：0x 前缀 16 进制，纯数字先 10 进制再兜底 16 进制。
int? _parseElfVa(Object? raw) {
  if (raw == null) return null;
  if (raw is num) return raw.toInt();
  final text = raw.toString().trim();
  if (text.isEmpty) return null;
  final lower = text.toLowerCase();
  if (lower.startsWith('0x')) {
    return int.tryParse(text.substring(2), radix: 16);
  }
  return int.tryParse(text) ?? int.tryParse(text, radix: 16);
}

/// ELF64 VA → APK entry 内文件偏移：读 entry 头部 4KB 解析 program
/// headers，命中 PT_LOAD（vaddr ≤ va < vaddr+filesz）返回 p_offset +
/// (va-vaddr)。非 ELF64 / 解析失败 / 未命中返回 null。zip 存储不影响
/// （映射发生在 entry 内部，与 zip 对齐无关）。
Future<int?> _elfVaToEntryOffset({
  required String path,
  required String entry,
  required int va,
}) async {
  final r = await ApkToolchainService.apkArchive(
    path: path,
    action: 'read',
    entry: entry,
    offset: 0,
    limit: 4096,
  );
  final data = r.data;
  if (!r.ok || data == null) return null;
  final hex = data['hexPreview']?.toString() ?? '';
  if (hex.isEmpty) return null;
  final parts = hex.split(' ');
  final bytes = <int>[];
  for (final part in parts) {
    final v = part.isEmpty ? null : int.tryParse(part, radix: 16);
    if (v == null) return null;
    bytes.add(v);
  }
  if (bytes.length < 64 ||
      bytes[0] != 0x7F ||
      bytes[1] != 0x45 ||
      bytes[2] != 0x4C ||
      bytes[3] != 0x46) {
    return null;
  }
  if (bytes[4] != 2) return null; // 仅 ELF64（arm64 场景）
  int u16(int o) => bytes[o] | (bytes[o + 1] << 8);
  int u32(int o) =>
      bytes[o] |
      (bytes[o + 1] << 8) |
      (bytes[o + 2] << 16) |
      (bytes[o + 3] << 24);
  int u64(int o) => u32(o) | (u32(o + 4) << 32);
  final phoff = u64(0x20);
  final phentsize = u16(0x36);
  final phnum = u16(0x38);
  if (phentsize < 56 || phnum == 0 || phnum > 128) return null;
  for (var i = 0; i < phnum; i++) {
    final base = phoff + i * phentsize;
    if (base < 0 || base + 56 > bytes.length) break;
    if (u32(base) != 1) continue; // PT_LOAD
    final pOffset = u64(base + 8);
    final pVaddr = u64(base + 16);
    final pFilesz = u64(base + 32);
    if (va >= pVaddr && va < pVaddr + pFilesz) {
      return pOffset + (va - pVaddr);
    }
  }
  return null;
}

/// apk_archive 批量读回：reads=[{entry, va|offset, limit}]（≤8，顺序执行）。
/// 无 limit 时默认 64 字节验收窗口，防止 8 × 大窗口撑爆结果上限。
Future<String> _handleApkArchiveReads(String path, List readsArg) async {
  if (readsArg.length > 8) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_args',
      'message': 'reads 批量上限 8 条。',
    });
  }
  final results = <Map<String, dynamic>>[];
  var failed = 0;
  for (var i = 0; i < readsArg.length; i++) {
    final item = readsArg[i];
    if (item is! Map) {
      results.add({
        'index': i,
        'ok': false,
        'error': 'invalid_args',
        'message': 'reads[$i] 必须是 {entry, va|offset, limit} 对象。',
      });
      failed++;
      continue;
    }
    final entry = (item['entry'] ?? '').toString();
    final va = _parseElfVa(item['va']);
    var offset = (item['offset'] as num?)?.toInt();
    if (va != null) {
      final mapped = await _elfVaToEntryOffset(
        path: path,
        entry: entry,
        va: va,
      );
      if (mapped == null) {
        results.add({
          'index': i,
          'ok': false,
          'error': 'VA_NOT_MAPPED',
          'entry': entry,
          'va': '0x${va.toRadixString(16)}',
          'message': 'va 未落在 entry 的任何 PT_LOAD 段内（或非 ELF64）。',
        });
        failed++;
        continue;
      }
      offset = mapped + (offset ?? 0);
    }
    final r = await ApkToolchainService.apkArchive(
      path: path,
      action: 'read',
      entry: entry,
      offset: offset,
      limit: (item['limit'] as num?)?.toInt() ?? 64,
    );
    final payload = Map<String, dynamic>.from(
      _toolResultMap(r).cast<String, dynamic>(),
    );
    if (va != null) payload['va'] = '0x${va.toRadixString(16)}';
    results.add({'index': i, ...payload});
    if (!r.ok) failed++;
  }
  return jsonEncode({
    'ok': failed == 0,
    'tool': 'apk_archive',
    'action': 'read',
    'batch': true,
    'reads': results,
    'succeeded': results.length - failed,
    'failed': failed,
  });
}

Future<String> _handleApkExportReport(
  Map<String, dynamic> args,
  ToolContext context,
) async {
  final report = await ApkWorkspaceService.readReport(
    conversationId: context.conversationId,
  );
  if (report == null) {
    return jsonEncode({
      'ok': false,
      'error': 'report_not_ready',
      'message': '当前没有可导出的 APK 分析报告，请先完成分析。',
    });
  }
  final freshness = await ApkWorkspaceService.reportFreshnessOf(report);
  if (freshness['status'] == 'stale') {
    return jsonEncode({
      'ok': false,
      'error': 'stale_report',
      'message': '当前报告已失效，请重新分析后再导出。',
    });
  }
  final workDir = await ApkWorkspaceBindingService.workDir();
  if (workDir == null || workDir.isEmpty) {
    return jsonEncode({
      'ok': false,
      'error': 'work_dir_required',
      'message': '请先设置工作目录，报告会保存到该目录。',
    });
  }
  final requested = (args['fileName'] ?? '').toString().trim();
  if (requested.isNotEmpty &&
      (p.basename(requested) != requested || !requested.endsWith('.json'))) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_file_name',
      'message': 'fileName 只能是工作目录中的 .json 文件名。',
    });
  }
  final stem = p.basenameWithoutExtension(
    (report['fileName'] ?? 'apk').toString(),
  );
  final name = requested.isEmpty
      ? '${stem}_analysis_${DateTime.now().millisecondsSinceEpoch}.json'
      : requested;
  final output = File(p.join(workDir, name));
  await output.writeAsString(jsonEncode(report));
  await ApkWorkspaceBindingService.recordFileArtifact(
    path: output.path,
    operation: 'apk_report_export',
    source: (report['sourceApk'] as Map?)?['path']?.toString(),
    metadata: {'analysisVersion': report['analysisVersion']},
  );
  return jsonEncode({
    'ok': true,
    'outputPath': output.path,
    'bytes': await output.length(),
    'message': '当前 APK 分析报告已导出（自动命名 {APK名}_analysis_{时间戳}，无需手工管理）。',
    'cleanupHint':
        '导出物是临时交付物：已登记为 file 产物（apk_report_export），'
        '确认使用完毕后可用 file(action=delete) 清理，避免测试 JSON 堆积工作目录。',
  });
}

Future<String> _handleDexXref(
  Map<String, dynamic> args,
  ChatService? chatService,
) async {
  final (path, pathError) = await _resolveLocalApkPath(args, chatService);
  if (pathError != null) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_apk_path',
      'message': pathError,
    });
  }
  if (path == null || path.isEmpty) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_args',
      'message':
          '需要本地 APK 才能查调用图。请先 analyze_apk_workspace 分析目标，或传 path 指定 APK。',
    });
  }
  var target = (args['target'] ?? args['locator'] ?? '').toString().trim();
  // 兼容旧 dex_method: 前缀定位符——引擎直接消费 qualifiedId（R4 同源格式）
  final prefixIdx = target.indexOf('dex_method:');
  if (prefixIdx != -1) {
    target = target.substring(prefixIdx + 'dex_method:'.length).trim();
  }
  if (target.isEmpty) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_args',
      'message': '缺少 target(qualifiedId)',
    });
  }
  if (target.startsWith('dex_field:')) {
    target = target.substring('dex_field:'.length).trim();
    final fieldResult = await ApkToolchainService.fieldXref(
      path: path,
      fieldTarget: target,
      offset: (args['offset'] as num?)?.toInt(),
      limit: (args['limit'] as num?)?.toInt(),
    );
    if (!fieldResult.ok) {
      return jsonEncode({
        'ok': false,
        'error': fieldResult.error ?? 'field_xref_failed',
        'message': fieldResult.message ?? '字段引用查询失败',
        'recoverable': true,
      });
    }
    final data = <String, dynamic>{
      for (final entry
          in (fieldResult.data ?? const <Object?, Object?>{}).entries)
        entry.key.toString(): entry.value,
      'sourceApk': path,
      'note': '字段引用覆盖 iget/iput/sget/sput；每项 method 可直接传给 smali_read。',
    };
    return jsonEncode(data);
  }
  final classPrefix = (args['classPrefix'] ?? args['callerPrefix'] ?? '')
      .toString()
      .trim();
  final r = await ApkToolchainService.dexXref(
    path: path,
    target: target,
    direction: (args['direction'] ?? 'to').toString(),
    classPrefix: classPrefix,
    offset: (args['offset'] as num?)?.toInt() ?? 0,
    limit: (args['limit'] as num?)?.toInt(),
    callSiteOffset: (args['callSiteOffset'] as num?)?.toInt() ?? 0,
    callSiteLimit: (args['callSiteLimit'] as num?)?.toInt(),
  );
  if (!r.ok) {
    return jsonEncode({
      'ok': false,
      'error': r.error ?? 'xref_failed',
      'message': r.message ?? '调用图查询失败',
      'recoverable': true,
    });
  }
  final data = <String, dynamic>{
    for (final entry in (r.data ?? const <Object?, Object?>{}).entries)
      entry.key.toString(): entry.value,
  };
  data['sourceApk'] = path;
  data['note'] =
      '跨全部 dex 聚合；每项 qualifiedId 可直接传给 smali_read。'
      'directCallers=精确调用点；dispatchCandidates=invoke-virtual 分派候选'
      '（实际执行可能经子类分派，需 class_outline 确认）';
  return jsonEncode(data);
}

Future<String> _handleClassOutline(Map<String, dynamic> args) async {
  final runtime = (args['runtime'] ?? 'dex').toString().toLowerCase();
  final className = (args['className'] ?? '').toString().trim();
  if (className.isEmpty) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_args',
      'message': '缺少 className',
    });
  }
  if (runtime == 'dart') {
    final jobId = (args['jobId'] ?? '').toString().trim();
    if (jobId.isEmpty) {
      return jsonEncode({
        'ok': false,
        'error': 'blutter_job_required',
        'message': 'Dart 类查询需要当前 APK 的 Blutter jobId。先 analyze，再传其 jobId。',
      });
    }
    final r = await ApkToolchainService.soAnalyze({
      'action': 'blutter',
      'blutterAction': 'search',
      'jobId': jobId,
      'query': className,
      'scope': 'asm',
      'includePath': className,
      'limit': (args['limit'] as num?)?.toInt() ?? 50,
    });
    return _encodeToolResult(r);
  }
  if (runtime != 'dex') {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_runtime',
      'message': 'runtime 只支持 dex 或 dart。',
    });
  }
  if (!className.contains(RegExp(r'[./;$]')) && className.length <= 2) {
    return jsonEncode({
      'ok': false,
      'error': 'ambiguous_short_class',
      'message':
          '两字符短类名无法区分 DEX 混淆类与 Dart 类，拒绝全 DEX 扫描以避免返回系统类噪音。Dart 请传 runtime:"dart" 和当前 Blutter jobId；DEX 请传完整类名。',
    });
  }
  final (path, err) = await _resolveToolchainPath(args, bindActive: false);
  if (path == null) {
    return jsonEncode({'ok': false, 'error': 'invalid_args', 'message': err});
  }
  final r = await ApkToolchainService.classOutline(
    path: path,
    className: className,
    offset: (args['offset'] as num?)?.toInt() ?? 0,
    limit: (args['limit'] as num?)?.toInt(),
    // 字段独立游标：逐键转发漏了它，字段尾部就永远读不到（2026-09-21 复验）。
    fieldsOffset: (args['fieldsOffset'] as num?)?.toInt(),
  );
  return _encodeToolResult(r);
}

// ===== M3/M5: SO 引擎 + root 工具处理 =====

Future<String> _handleSoAnalyze(Map<String, dynamic> args) async {
  // B4：blutterAction 是 blutter 专属参数；外部 agent 按压缩 schema 自行
  // 填参时常漏传 action，双端静默默认 'open' 会把调用顶替成工作区打开
  // （有 path 返回 open 载荷，无 path 报 Missing SO path）。此处显式归位。
  var requestedAction = (args['action'] ?? '').toString().trim();
  if (requestedAction.isEmpty) {
    requestedAction = (args['blutterAction'] ?? '').toString().trim().isNotEmpty
        ? 'blutter'
        : 'open';
    args['action'] = requestedAction;
  }
  const actionAliases = <String, String>{
    'xrefs': 'rz_xrefs',
    'functions': 'rz_functions',
    'decompile': 'rz_decompile',
  };
  final action = actionAliases[requestedAction] ?? requestedAction;
  if (action != requestedAction) args['action'] = action;
  // D18/D19（2026-09-21 自检）：退役动作与"域"在**执行前**就拦下并给出唯一
  // 替代路径。此前它们要么进 catalog 被反复尝试直到失败（capabilities 8/8、
  // emulate 7/7、lief_* 4/4、open_url 6/6），要么只回一句笼统的
  // Unknown action（read/edit/workspace/xref 这些域或旧别名）。
  final retired = kSoAnalyzeRetiredActions[action];
  // 2026-10-04 复查「新发现」：过去 allowDeprecatedAction=true 会**放行**这里，
  // 与 schema 的「cannot bypass」自相矛盾；且 Kotlin 分发层现在无条件早退
  // （F-43），放行也只会在下层再撞一次。这里改为**无条件拒绝**，措辞与行为
  // 统一：退役动作在任何入口都不可执行，唯一出路是 instead 的替代路径。
  if (retired != null) {
    return jsonEncode({
      'ok': false,
      'error': 'known_broken_action',
      // F-39（2026-10-04）：与 class_outline（D 形）对齐——顶层补 code 与
      // recoverable，读过任一字段名的消费方都能拿到机器可读信号。
      'code': 'known_broken_action',
      'recoverable': false,
      'retrySameArguments': false,
      'action': action,
      'status': 'retired',
      'message':
          'so_analyze action=$action 已知不可用，且不会因为重试而变好：${retired['reason']}',
      'instead': retired['instead'],
      'suggestion':
          '直接改用 instead 里的动作，不要原样重发、不要换参数重试。'
          '退役动作已在接受面移除（Dart 与原生分发层双层拒绝），没有放行开关。',
    });
  }
  final domain = kSoAnalyzeDomains[action];
  if (domain != null) {
    return jsonEncode({
      'ok': false,
      'error': 'domain_not_action',
      'code': 'domain_not_action',
      'recoverable': false,
      'retrySameArguments': false,
      'action': action,
      'status': 'domain',
      'message':
          'so_analyze action=$action 是"域"（一组子动作的命名空间），不是可直接调用的动作：${domain['note'] ?? '请从 subActions 里选一个具体动作。'}',
      'subActions': domain['subActions'],
      'suggestion': '从 subActions 选一个具体动作后重发，不要原样重发。',
    });
  }
  final renamed = kSoAnalyzeActionRenames[action];
  if (renamed != null && renamed != action) {
    return jsonEncode({
      'ok': false,
      'error': 'renamed_action',
      'code': 'renamed_action',
      'recoverable': false,
      'retrySameArguments': false,
      'action': action,
      'status': 'renamed',
      'message': 'so_analyze action=$action 是历史别名，当前等价写法是：$renamed',
      'instead': renamed,
      'suggestion': '改用 instead 的写法后重发。',
    });
  }
  final detachedBlutterAnalyzeWait =
      action == 'blutter' &&
      args['blutterAction'] == 'analyze' &&
      args['wait'] == true;
  if (detachedBlutterAnalyzeWait) args['wait'] = false;
  // 路径路由修复：open/analyze_apk/blutter 的 path 支持相对路径（相对工作
  // 目录）与文件名（工作区文件），与 APK 工具链的路径语义对齐；
  // P0-A 铁律：绝对路径必须位于统一工作目录内（apk:xxx 内部格式除外）。
  const autoOpenFromPathActions = {
    'read_elf',
    'read_stats',
    'disasm',
    'hexdump',
    'strings',
    'search',
    'list',
    'overview',
    'analysis_report',
    'rz_analyze',
    'rz_functions',
    'rz_xrefs',
    'rz_decompile',
    'rz_crypto',
    'rz_cfg',
    'rz_esil',
    'rz_search_bytes',
    'rz_command',
  };
  final pathRoutedActions = {
    'open',
    'analyze_apk',
    'blutter',
    ...autoOpenFromPathActions,
  };
  if (pathRoutedActions.contains(action) && args['path'] != null) {
    final raw = args['path'].toString().trim();
    if (raw.isNotEmpty && !raw.startsWith('apk:')) {
      final dir = await ApkWorkspaceBindingService.workDir();
      if (dir == null || dir.isEmpty) {
        return jsonEncode(const {
          'ok': false,
          'error': 'workspace_not_set',
          'message': '工作目录未设置：请先在 APK 工作台设置统一工作目录',
        });
      }
      if (raw.startsWith('/') || raw.contains(':')) {
        final guarded = _guardInsideWorkDir(dir, raw);
        if (guarded == null) {
          return jsonEncode(_pathOutsideWorkspace(raw, dir));
        }
        args['path'] = guarded;
      } else {
        final joined = _joinInsideWorkDir(dir, raw);
        if (joined == null) {
          return jsonEncode(_pathOutsideWorkspace(raw, dir));
        }
        args['path'] = joined;
      }
    }
  }
  // 引擎写根永远等于绑定工作目录：模型不能把 build/audit/open_url 的落地
  // 目录改到工作目录之外（旧实现只拦绝对路径，且改完不会被自动同步拉回）。
  if (action == 'set_work_dir') {
    final bound = await ApkWorkspaceBindingService.workDir();
    if (bound == null || bound.isEmpty) {
      return jsonEncode(const {
        'ok': false,
        'error': 'workspace_not_set',
        'message': '工作目录未设置：请先在 APK 工作台设置统一工作目录',
      });
    }
    args['path'] = bound;
  }
  // 统一工作路径：每个 action 前把 APK 工作目录同步给 SO 引擎，
  // 保证工作目录内的 .so/.apk 可被 so_analyze 识别（免 SAF，path 模式）。
  // native setWorkDirectoryPath 同路径幂等短路，无额外开销；
  // 不只 open/analyze_apk — list_sources/suggest 等也依赖工作目录。
  {
    final dir = await ApkWorkspaceBindingService.workDir();
    if (dir != null &&
        dir.isNotEmpty &&
        LocalToolsService._lastSyncedSoWorkDir != dir) {
      try {
        final sync = await ApkToolchainService.soAnalyze(<String, Object?>{
          'action': 'set_work_dir',
          'path': dir,
        });
        if (sync.ok) LocalToolsService._lastSyncedSoWorkDir = dir;
      } catch (_) {
        // 同步失败不阻塞主调用（引擎可能未就绪）
      }
    }
  }
  if (autoOpenFromPathActions.contains(action) &&
      (args['workspaceId']?.toString().trim().isEmpty ?? true) &&
      (args['path']?.toString().trim().isNotEmpty ?? false)) {
    final opened = await ApkToolchainService.soAnalyze(<String, Object?>{
      'action': 'open',
      'path': args['path']?.toString(),
      'temporary': true,
    });
    final workspaceId = opened.data?['workspaceId']?.toString() ?? '';
    if (!opened.ok || workspaceId.isEmpty) {
      final data = opened.data ?? <String, Object?>{};
      return jsonEncode({
        ...data,
        'ok': false,
        'error': data['error'] ?? 'workspace_open_failed',
        'message': data['message'] ?? '无法从 path 打开分析工作区',
      });
    }
    args['workspaceId'] = workspaceId;
  }
  const editActions = {'edit_hex', 'edit_asm', 'edit_symbol'};
  final previewRequested = args['dryRun'] == true;
  final applyAfterPreview = _applyRequested(args);
  final aotRawConstantRisk =
      editActions.contains(action) &&
      args['overrideAotObjectSafety'] != true &&
      await _hasUnsafeDartAotRawConstant(args, action);
  if (aotRawConstantRisk && !previewRequested) {
    return jsonEncode({
      'ok': false,
      'error': 'UNSAFE_DART_AOT_RAW_CONSTANT',
      'message':
          '检测到 Flutter/Dart AOT 中手写 MOV 立即数。对象字段不能按普通整数直接写入；请改用 force_return_constant、已证明方向的分支修改，或先补齐真实字段读取与对象编码证据。',
    });
  }
  var r = await ApkToolchainService.soAnalyze(Map<String, Object?>.from(args));
  if (editActions.contains(action) && previewRequested && r.ok) {
    final preview = <String, Object?>{
      for (final entry in (r.data ?? const <String, Object?>{}).entries)
        entry.key.toString(): entry.value,
    };
    final targetVersion = preview['targetVersion']?.toString() ?? '';
    final previewCount = (preview['previewCount'] as num?)?.toInt() ?? 0;
    final applyArgs = <String, Object?>{
      ...Map<String, Object?>.from(args),
      'dryRun': false,
      'targetVersion': targetVersion,
    }..remove('applyAfterPreview');
    if (!aotRawConstantRisk &&
        applyAfterPreview &&
        targetVersion.isNotEmpty &&
        previewCount > 0) {
      final applied = await ApkToolchainService.soAnalyze(applyArgs);
      final appliedData = <String, Object?>{
        for (final entry in (applied.data ?? const <String, Object?>{}).entries)
          entry.key.toString(): entry.value,
        'ok': applied.ok,
        'preview': preview,
        'appliedAfterPreview': applied.ok,
        if (!applied.ok) 'applyArguments': applyArgs,
        if (!applied.ok && applied.error != null) 'error': applied.error,
        if (!applied.ok && applied.message != null) 'message': applied.message,
      };
      return jsonEncode(appliedData);
    }
    if (!aotRawConstantRisk) preview['applyArguments'] = applyArgs;
    if (aotRawConstantRisk) {
      preview['warning'] = {
        'type': 'unsafe_dart_aot_raw_constant',
        'message': '该预览把 Dart AOT 对象字段当原生立即数写入，可能导致登录或对象读取崩溃。',
      };
      preview['autoApplyBlocked'] = true;
      preview['nextStep'] =
          '回到字段读取者或业务条件分支验证。常量返回使用 force_return_constant；对象构造/JSON 解析函数只作字段来源证据，不作补丁目标。';
    } else if (applyAfterPreview) {
      preview['autoApplyBlocked'] = true;
      preview['nextStep'] =
          '预览没有可写入字节或缺少 targetVersion，未执行。修正定位或编辑参数，不要重复同一 dryRun。';
    }
    r = ApkStructuralResult(ok: r.ok, data: preview);
  }
  // Blutter wait=true 在终态、阶段变化或新心跳时立即返回，避免一次工具调用
  // 阻塞 90 秒而用户看不到任何反馈。Agent 可把本次进度告诉用户后继续续等。
  if (action == 'blutter' && args['wait'] == true) {
    r = await _waitBlutterJob(args, r);
  }
  final data = r.data ?? {'ok': r.ok, 'error': r.error, 'message': r.message};
  if (detachedBlutterAnalyzeWait &&
      r.ok &&
      data['status']?.toString() == 'running') {
    data['waitDetached'] = true;
    data['hint'] =
        '分析已在后台运行。立即向用户报告 jobId 和当前阶段,\n'
        '然后用同一 jobId 调用 status(wait=true),不要在单次 analyze 里静默等待。';
  }
  // T1: 记录最近一次 build 成功产物路径，so_patch_into_apk 缺省自动感知。
  if (data['ok'] == true) {
    if (action == 'build') {
      final out = data['outputPath']?.toString() ?? '';
      if (out.isNotEmpty) {
        final activeApk = await ApkWorkspaceBindingService.activeApkPath();
        ToolSessionState.lastBuiltSoPath = out;
        ToolSessionState.lastBuiltSoApkPath = activeApk;
        ToolSessionState.lastBuiltSoEntry = data['sourceEntry']?.toString();
        await ApkWorkspaceBindingService.recordFileArtifact(
          path: out,
          operation: 'so_build',
          source: activeApk,
          metadata: {
            if (data['sourceEntry'] != null) 'sourceEntry': data['sourceEntry'],
          },
        );
      }
    } else if (action == 'build_many') {
      final outputs = data['outputs'];
      if (outputs is List && outputs.isNotEmpty) {
        final last = outputs.last;
        if (last is Map) {
          final out = last['outputPath']?.toString() ?? '';
          if (out.isNotEmpty) {
            final activeApk = await ApkWorkspaceBindingService.activeApkPath();
            ToolSessionState.lastBuiltSoPath = out;
            ToolSessionState.lastBuiltSoApkPath = activeApk;
            ToolSessionState.lastBuiltSoEntry = last['sourceEntry']?.toString();
            await ApkWorkspaceBindingService.recordFileArtifact(
              path: out,
              operation: 'so_build',
              source: activeApk,
              metadata: {
                if (last['sourceEntry'] != null)
                  'sourceEntry': last['sourceEntry'],
              },
            );
          }
        }
      }
    }
  }
  // 成功打开的 SO 工作区无需审批；修改类 action 走 dryRun/confirm 链由提示词约束
  return jsonEncode(data);
}

Future<bool> _hasUnsafeDartAotRawConstant(
  Map<String, dynamic> args,
  String action,
) async {
  if (action != 'edit_hex' && action != 'edit_asm') return false;
  final report = await _readPatchMemoryReport();
  final path = (args['path'] ?? '').toString().replaceAll('\\', '/');
  final isAot =
      (report != null && ApkPatchMemoryService.reportLooksFlutter(report)) ||
      p.basename(path).toLowerCase() == 'libapp.so';
  if (!isAot) return false;

  final edits = <Map<String, dynamic>>[];
  final rawEdits = args['edits'];
  if (rawEdits is List) {
    for (final edit in rawEdits) {
      if (edit is Map) edits.add(Map<String, dynamic>.from(edit));
    }
  }
  if (edits.isEmpty) edits.add(args);
  if (action == 'edit_asm') {
    final rawMov = RegExp(
      r'\bmov[zk]?\s+[wx][0-9]+\s*,\s*#',
      caseSensitive: false,
    );
    return edits.any((edit) {
      final mode = (edit['mode'] ?? '').toString();
      if (const {
        'force_return_constant',
        'return_constant',
        'constant_return',
      }.contains(mode)) {
        return false;
      }
      final asm =
          (edit['writeAsm'] ??
                  edit['newAsm'] ??
                  edit['asm'] ??
                  edit['assembly'] ??
                  '')
              .toString();
      return rawMov.hasMatch(asm);
    });
  }
  return edits.any((edit) {
    final raw =
        (edit['newHex'] ??
                edit['hex'] ??
                edit['bytes'] ??
                edit['data'] ??
                edit['rawHex'] ??
                args['patchHex'] ??
                '')
            .toString();
    final cleaned = raw.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    if (cleaned.isEmpty || cleaned.length.isOdd) return false;
    final bytes = <int>[
      for (var i = 0; i < cleaned.length; i += 2)
        int.parse(cleaned.substring(i, i + 2), radix: 16),
    ];
    for (var i = 0; i + 3 < bytes.length; i += 4) {
      final word =
          bytes[i] |
          (bytes[i + 1] << 8) |
          (bytes[i + 2] << 16) |
          (bytes[i + 3] << 24);
      if ((word & 0x7f800000) == 0x52800000) return true;
    }
    return false;
  });
}

/// Blutter job 等待。每 2s 轮询；终态、阶段变化或新心跳任一发生就返回，
/// 让调用方能持续展示真实阶段和产物增长，不在单次 MCP 调用里静默等待。
Future<ApkStructuralResult> _waitBlutterJob(
  Map<String, dynamic> args,
  ApkStructuralResult initial,
) async {
  const terminal = {'succeeded', 'failed', 'cancelled', 'interrupted'};
  final timeoutMsRequested = (args['timeoutMs'] as num?)?.toInt();
  final timeoutMs = (timeoutMsRequested ?? 90000).clamp(5000, 90000);
  // 报告 2-23 同族：等待上限被钳到 [5000,90000] 却不回显。
  final timeoutEcho = ToolArgEcho.effective(
    'timeoutMs',
    timeoutMsRequested,
    timeoutMs,
  );
  final deadline = DateTime.now().add(Duration(milliseconds: timeoutMs));

  Map<String, Object?> dataOf(ApkStructuralResult r) =>
      r.data?.map((k, v) => MapEntry(k.toString(), v)) ?? const {};

  var data = dataOf(initial);
  var jobId = data['jobId']?.toString() ?? '';
  var current = initial;
  var fingerprint =
      '${data['updatedAt']}|${data['stage']}|${data['outputBytes']}|${data['outputFiles']}';
  while (jobId.isNotEmpty &&
      !terminal.contains(data['status']?.toString() ?? '') &&
      DateTime.now().isBefore(deadline)) {
    await Future.delayed(const Duration(seconds: 2));
    current = await ApkToolchainService.soAnalyze(<String, Object?>{
      'action': 'blutter',
      'blutterAction': 'status',
      'jobId': jobId,
    });
    data = dataOf(current);
    final nextFingerprint =
        '${data['updatedAt']}|${data['stage']}|${data['outputBytes']}|${data['outputFiles']}';
    if (!terminal.contains(data['status']?.toString() ?? '') &&
        nextFingerprint != fingerprint) {
      data['inProgress'] = true;
      data['hint'] =
          'Blutter 正在运行: ${data['stageLabel'] ?? data['stage']}, '
          '已耗时 ${data['elapsedMillis'] ?? 0}ms, '
          '已产生 ${data['outputFiles'] ?? 0} 个文件。可向用户报告后用同一 jobId 续等。';
      return ApkStructuralResult(ok: current.ok, data: data);
    }
    fingerprint = nextFingerprint;
  }
  if (jobId.isNotEmpty &&
      !terminal.contains(data['status']?.toString() ?? '')) {
    final stage = data['stage']?.toString() ?? data['status']?.toString() ?? '';
    data['waitTimeout'] = true;
    // 报告 2-23 同族：等待上限被钳过就如实说。
    data.addAll(timeoutEcho);
    data['hint'] =
        'Blutter 仍在运行（stage=$stage），再次调用 so_analyze(action=blutter, '
        'blutterAction=status, jobId=$jobId, wait=true) 续等'
        '${data['timeoutMsClamped'] == true ? '（本次等待上限已被钳到 ${data['timeoutMs']}ms）' : ''}';
    current = ApkStructuralResult(ok: current.ok, data: data);
  }
  return current;
}

String? _guardInsideWorkDir(String workDir, String path) {
  String norm(String s) =>
      s.startsWith('/sdcard/') ? '/storage/emulated/0/${s.substring(8)}' : s;
  final d = norm(workDir);
  final v = norm(path);
  if (v == d || p.isWithin(d, v)) return v;
  return null;
}

/// join(workDir, raw) 之后套用与绝对路径同一套越界判定。
///
/// 旧实现对相对路径直接 `p.join(dir, raw)`，`../` 段不会被拦——`../../../
/// sdcard/Download/x.apk` 因而能落到工作目录之外（读、写、签名产物都受过影响）。
/// 越界返回 null。
String? _joinInsideWorkDir(String workDir, String raw) {
  if (raw.isEmpty) return null;
  final joined = p.normalize(p.join(workDir, raw));
  return _guardInsideWorkDir(workDir, joined);
}

/// 越界/未设置错误信封（file_* 与 apk/so 工具链共用同一套错误码）。
Map<String, dynamic> _pathOutsideWorkspace(String path, String workDir) => {
  'ok': false,
  'error': 'PATH_OUTSIDE_WORKSPACE',
  'message':
      '路径越界（$path）：所有读写必须限制在统一工作目录内（$workDir）。'
      '外部文件请先用 file(action=copy) 复制进工作目录，再使用工作目录内路径。',
};

/// 统一路径：相对路径/文件名 join 工作目录；绝对路径仅允许工作目录内
/// 子路径（P0-A 铁律）。返回 (path, error)，二者互斥。
/// 同路径判定（大小写/分隔符不敏感）：闸门不能因为 `/a/b.apk` 与 `\\a\\b.apk`
/// 的写法差异而漏判。
bool _sameFilePath(String a, String b) {
  String norm(String v) => v.replaceAll('\\', '/').replaceAll(RegExp(r'/+'), '/').trim().toLowerCase();
  return norm(a) == norm(b);
}

/// 原始 APK 只读闸门（用户实测报告 2-6）。
///
/// 工作目录策略声明「原始 APK 永不被修改」，但文件读写通道过去**没有任何对应闸门**
/// （报告只做到 dryRun 预览探测，没敢真写）。这里在真正落盘的三个动作
/// （write / replace / delete）前统一拦一次：目标等于**当前绑定 APK**或**报告
/// 对应的源 APK**时，返回结构化拒绝并给出可行替代路径。
Future<Map<String, dynamic>?> _originalApkWriteGuard(
  String action,
  String path,
) async {
  try {
    final candidates = <String>[];
    final bound = await ApkWorkspaceBindingService.activeApkPath();
    if (bound != null && bound.trim().isNotEmpty) candidates.add(bound);
    final report = await ApkWorkspaceService.readReport();
    final source = report?['sourceApk'];
    final sourcePath = source is Map ? source['path']?.toString() : null;
    if (sourcePath != null && sourcePath.trim().isNotEmpty) {
      candidates.add(sourcePath);
    }
    // v9 复测（F-02）：activeApk 会随 makeActive 链式前移——原包不在
    // active/报告候选里时，写原包照样放行。补上台账全部 rootSource（血缘
    // 首条就是用户导入的原包），原包在任何链位上都受保护。
    final builds = await ApkWorkspaceBindingService.readBuilds();
    for (final build in builds) {
      final root = build['rootSource']?.toString().trim() ?? '';
      if (root.isNotEmpty) candidates.add(root);
    }
    for (final candidate in candidates) {
      if (!_sameFilePath(candidate, path)) continue;
      return _originalApkReadOnlyEnvelope(action, path, candidates.first);
    }
    // v10 复测（F-02 仍未命中）：候选三条路径都可能落空——activeApk 漂到
    // 成品、报告源被跨会话复制成 runtime 路径、台账 rootSource 指向已清理的
    // 中间件。而「原始 APK 永不被修改」的本质是**内容身份**，不是路径身份：
    // 内容 sha256 等于被分析源包指纹的任何 .apk（含改名副本）都是基线，写入
    // 即破坏唯一可回退点。这里按内容指纹兜底匹配（仅在扩展名为 .apk 且候选
    // 未命中时执行，一次 sha256 读）。
    final reportSha = (report?['sha256'] ?? '').toString().trim();
    if (reportSha.isNotEmpty && path.toLowerCase().endsWith('.apk')) {
      final file = File(path);
      if (await file.exists() && await file.length() > 0) {
        try {
          final digest = await _sha256OfFile(path);
          if (digest.toLowerCase() == reportSha.toLowerCase()) {
            return _originalApkReadOnlyEnvelope(action, path, 'sha256:$reportSha');
          }
        } catch (_) {
          // 指纹算不出（文件锁/权限）不阻断闸门其余逻辑，但保守拒绝：
          // 对 .apk 的写入本身是危险操作，fail-closed。
          return _originalApkReadOnlyEnvelope(action, path, 'sha256:unreadable');
        }
      }
    }
  } catch (_) {
    // 闸门自身异常不能把工具调用炸掉：退化为「不拦」，由下层原有校验继续兜。
  }
  return null;
}

/// F-02 拒绝信封（路径命中与内容指纹命中共用同一文案）。
Map<String, dynamic> _originalApkReadOnlyEnvelope(
  String action,
  String path,
  String identity,
) => <String, dynamic>{
  'ok': false,
  'error': 'original_apk_readonly',
  'action': action,
  'path': path,
  'boundApk': identity,
  'message':
      '拒绝改写原始 APK（$path）：它是本次分析的**源**，改掉就再也回不到基线。'
      '需要在它基础上改的话，先 copy 一份到工作目录另起一个产物，再对副本操作。',
  'nextActions': <String>[
    '先 file copy 到工作目录内的新路径（例如 <app>-patched.apk），再对副本 write/replace',
    '要产出可安装包请走 patch_apk_* / buildApk / apk_sign 这条带校验链的通道',
  ],
};

Future<(String?, Map<String, dynamic>?)> _resolveFileOpsPath(
  Map<String, dynamic> args,
) async {
  final raw = (args['path'] ?? '').toString().trim();
  if (raw.isEmpty) {
    // 报告 2-5：策略契约（workspace_policy_contract.argumentErrorCodes）声明参数类
    // 错误用 missing_argument，这里过去回 invalid_path——按文档写分支逻辑会落空。
    // 现在按契约给码，并补齐 parameter/expected/actual 与自纠指引。
    return (
      null,
      const {
        'ok': false,
        'error': 'missing_argument',
        'parameter': 'path',
        'expected': '工作目录内的绝对路径或相对路径（非空字符串）',
        'actual': '',
        'message': 'path 缺失或为空。若刚发起写操作（write/build 等），其产物路径尚未返回，'
            '请等该操作完成拿到 outputPath 后再复制/重命名。',
        'nextActions': <String>[
          '补上 path 后重试',
          '不确定路径时先用 action=list 看清工作目录内容',
        ],
      },
    );
  }
  final dir = await ApkWorkspaceBindingService.workDir();
  if (dir == null || dir.isEmpty) {
    return (
      null,
      const {
        'ok': false,
        'error': 'workspace_not_set',
        'message': '工作目录未设置：请先在 APK 工作台设置统一工作目录',
      },
    );
  }
  // F-24/F-33/F-31（2026-10-04 复查复现）：file 族与 SoLab/读文件族共用同一
  // 路径词汇表——`/workspace`、`/chat`、`/tmp` 别名先归一（过去只有 SoLab
  // APK 路径解析器接了 resolveZoneAlias，file 对 /workspace 报
  // path_outside_workspace，而 list_dir/read_file 对同一路径正常）。
  // v9-N1（2026-10-05）：/chat、/tmp 的真实宿主根只有 workspace 工具知道，
  // file 族**不再静默改写**——/chat、/tmp 前缀给出指路型错误，/workspace 照常映射。
  final aliased = ApkWorkspaceBindingService.resolveZoneAlias(raw) ?? raw;
  if (aliased.startsWith('/') || aliased.contains(':')) {
    // 多根命中（F-31/F-35）：工作台全局目录与 zone 根都接受。
    final roots = await ApkWorkspaceBindingService.resolutionRoots();
    for (final root in (roots.isEmpty ? <String>[dir] : roots)) {
      final guarded = _guardInsideWorkDir(root, aliased);
      if (guarded != null) return (guarded, null);
    }
    if (raw == '/chat' || raw.startsWith('/chat/') || raw == '/tmp' || raw.startsWith('/tmp/')) {
      return (
        null,
        {
          'ok': false,
          'error': 'zone_not_resolvable_here',
          'path': raw,
          'message': '$raw 属于沙盒的 /chat、/tmp zone，file 工具没有它们的宿主映射'
              '（静默改写到工作目录会读写到错误文件）。请改用 workspace 工具'
              '（read_file / list_dir / write_file / shell），它们对这两个 zone 有真实映射。',
          'recoverable': true,
          'nextActions': <String>[
            '改用 read_file/list_dir/write_file（对 /chat、/tmp 有真实映射）',
            '若目标是工作目录内的文件，直接用设备绝对路径或工作目录相对路径',
          ],
        },
      );
    }
    return (null, _pathOutsideWorkspace(aliased, dir));
  }
  if (aliased.split('/').contains('..') || aliased.split(r'\').contains('..')) {
    return (
      null,
      const {'ok': false, 'error': 'invalid_path', 'message': 'path 含 .. 已拒绝'},
    );
  }
  // 归一化（2026-10-03 报告 F-13：`path="."` 曾回带 `…/files/./x` 的路径）。
  return (p.normalize(p.join(dir, aliased)), null);
}

/// B5：copy/rename/diff 兼容 path→sourcePath 别名。schema 主参数是
/// sourcePath/targetPath，但模型常传 path/targetPath，旧 handler 会报
/// "path 缺失或为空"。sourcePath 已传时不覆盖。
Map<String, dynamic> _aliasSourcePath(Map<String, dynamic> args) {
  final src = (args['sourcePath'] ?? '').toString().trim();
  final path = (args['path'] ?? '').toString().trim();
  if (src.isEmpty && path.isNotEmpty) {
    return <String, dynamic>{...args, 'sourcePath': args['path']};
  }
  return args;
}

/// 统一文件操作入口：action ∈ {inventory,read,write,list,info,delete,copy,rename,zip,unzip,grep,replace,strings}。
/// 复用既有 9 个原子 handler，Agent 只记一个 file 工具。
/// 文件 stale 守卫实例：读时登记、写前校验、写后刷新。
final FsObservationGuard _fsObservationGuard = FsObservationGuard();

/// 写类操作的前置校验：只有「读过且此后变了」才拒绝（结构化错误 + 补救话术）。
String? _fsGuardBlock(Map<String, dynamic> args, String path) {
  if (args['dryRun'] == true) return null;
  final status = _fsObservationGuard.check(path);
  if (status != FsObservationStatus.changed) return null;
  return jsonEncode(<String, dynamic>{
    'ok': false,
    'error': 'FS_STALE_VERSION',
    'recoverable': true,
    'path': path,
    'message': FsObservationGuard.staleMessage(path),
  });
}

Future<String> _handleFileUnified(Map<String, dynamic> args) async {
  final action = (args['action'] ?? '').toString().trim();
  switch (action) {
    case 'inventory':
      return _handleFileInventory();
    case 'read':
      return _handleFileRead(args);
    case 'write':
      return _handleFileWrite(args);
    case 'list':
      return _handleFileList(args);
    case 'info':
      return _handleFileInfo(args);
    case 'delete':
      return _handleFileDelete(args);
    case 'copy':
      return _handleFileCopy(_aliasSourcePath(args));
    case 'diff':
      return _handleFileDiff(_aliasSourcePath(args));
    case 'mkdir':
      return _handleFileMkdir(args);
    case 'rename':
    case 'move':
      // D13（2026-09-21 自检）：move 与 rename 是同一实现（跨目录重定位由底层
      // File.renameTo 完成），但响应过去一律回 action=rename，调用方看不出
      // 自己写的 move 被归一了。现在按调用方原词回显，并在不同名时显式给出
      // normalizedTo，归一不再是静默的。
      return _handleFileRename(_aliasSourcePath(args), requestedAction: action);
    case 'zip':
    case 'unzip':
      return _handleFileZip(<String, dynamic>{...args, 'action': action});
    case 'grep':
    case 'replace':
      return _handleFileGrep(<String, dynamic>{
        ...args,
        'mode': action == 'replace' ? 'replace' : 'grep',
      });
    case 'strings':
      return _handleFileStrings(args);
    default:
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'invalid_action',
        'message':
            'file action 非法：$action。支持 inventory/read/write/list/info/delete/copy/diff/mkdir/rename/zip/unzip/grep/replace/strings',
      });
  }
}

Future<Map<String, dynamic>> _workspaceInventory() async {
  final workDir = await ApkWorkspaceBindingService.workDir();
  final active = await ApkWorkspaceBindingService.activeApkPath();
  final report = await ApkWorkspaceService.readReport();
  final source = report?['sourceApk'];
  final reportPath = source is Map ? source['path']?.toString() : null;
  var lastSo = ToolSessionState.lastBuiltSoPath;
  if (lastSo == null || !await File(lastSo).exists()) {
    for (final artifact
        in await ApkWorkspaceBindingService.readFileArtifacts()) {
      if (artifact['operation'] == 'so_build' && artifact['exists'] == true) {
        lastSo = artifact['path']?.toString();
        ToolSessionState.lastBuiltSoPath = lastSo;
        ToolSessionState.lastBuiltSoApkPath = artifact['source']?.toString();
        final metadata = artifact['metadata'];
        if (metadata is Map) {
          ToolSessionState.lastBuiltSoEntry = metadata['sourceEntry']
              ?.toString();
        }
        break;
      }
    }
  }

  /// 工作目录根的真实文件清单：用户手动放进来的 .md/日志等非绑定产物
  /// 也必须可见，否则模型"看不见"目录里的普通文件。
  final workDirRoot = <Map<String, dynamic>>[];
  var workDirRootTruncated = false;
  if (workDir != null && workDir.isNotEmpty) {
    try {
      final entities = await Directory(
        workDir,
      ).list(followLinks: false).toList();
      entities.sort((a, b) {
        final aDir = a is Directory;
        final bDir = b is Directory;
        if (aDir != bDir) return aDir ? -1 : 1;
        final an = p.basename(a.path).toLowerCase();
        final bn = p.basename(b.path).toLowerCase();
        return an.compareTo(bn);
      });
      const cap = 100;
      for (final entity in entities.take(cap)) {
        try {
          final stat = await entity.stat();
          workDirRoot.add(<String, dynamic>{
            'name': p.basename(entity.path),
            'path': entity.path,
            'isDirectory': entity is Directory,
            'size': entity is File ? stat.size : 0,
            'modified': stat.modified.millisecondsSinceEpoch,
          });
        } catch (_) {}
      }
      workDirRootTruncated = entities.length > cap;
    } catch (_) {}
  }
  return <String, dynamic>{
    'ok': true,
    'scope': ApkWorkspaceBindingService.currentScopeId ?? 'global',
    'workDir': workDir,
    'workDirRoot': workDirRoot,
    if (workDirRootTruncated) 'workDirRootTruncated': true,
    'activeApk': active,
    'activeApkExists': active != null && await File(active).exists(),
    'reportSourceApk': reportPath,
    'reportSourceExists': reportPath != null && await File(reportPath).exists(),
    'lastBuiltSo': lastSo,
    'lastBuiltSoExists': lastSo != null && await File(lastSo).exists(),
    'apkFiles': await ApkWorkspaceBindingService.listApks(),
    'buildArtifacts': await ApkWorkspaceBindingService.readBuilds(),
    'fileArtifacts': await ApkWorkspaceBindingService.readFileArtifacts(),
    // 2026-10-03 报告 F-12：工作区跨会话共享（互斥双模设计），新会话读到
    // 上一轮的产物/草稿时必须知道它们不属于本次对话。
    'ownershipNote': '工作区（含产物台账/文件产物/待验证草稿）**跨会话共享**：'
        '以上条目可能来自其它对话，不代表属于本次会话；'
        '确认草稿（awaiting_user_verification）前先与用户核对是不是他刚改的。',
  };
}

Future<String> _handleFileInventory() async =>
    jsonEncode(await _workspaceInventory());

Future<String> _encodeFileMutation(
  ApkStructuralResult result, {
  required bool dryRun,
  required String operation,
  String? path,
  String? source,
  Future<void> Function()? reconcile,
}) async {
  if (result.ok && !dryRun) {
    if (reconcile != null) await reconcile();
    if (path != null && path.isNotEmpty) {
      await ApkWorkspaceBindingService.recordFileArtifact(
        path: path,
        operation: operation,
        source: source,
      );
    }
  }
  final decoded = jsonDecode(_encodeToolResult(result));
  if (decoded is! Map) return _encodeToolResult(result);
  final payload = Map<String, dynamic>.from(decoded);
  if (result.ok && !dryRun) {
    // 变更类工具回带轻量同步摘要；完整清单由 action=inventory 显式获取。
    // 这里走轻量摘要专用路径：rootEntryCount 只需目录列举，不需要
    // inventory 的逐条 stat（每次写操作省 N 次文件系统往返）。
    final inv = await _lightWorkspaceSummary();
    payload['workspaceSync'] = inv;
  }
  return jsonEncode(payload);
}

/// 写操作回执用的轻量同步摘要：只列根目录计数（不 stat）+ 缓存索引计数。
/// 完整 inventory（含逐条 size/modified）只在 file(action=inventory) 显式取。
Future<Map<String, dynamic>> _lightWorkspaceSummary() async {
  final workDir = await ApkWorkspaceBindingService.workDir();
  var rootEntryCount = 0;
  var truncated = false;
  if (workDir != null && workDir.isNotEmpty) {
    try {
      final entities = await Directory(
        workDir,
      ).list(followLinks: false).toList();
      truncated = entities.length > 100;
      rootEntryCount = truncated ? 100 : entities.length;
    } catch (_) {}
  }
  final builds = await ApkWorkspaceBindingService.readBuilds();
  final fileArtifacts = await ApkWorkspaceBindingService.readFileArtifacts();
  return <String, dynamic>{
    'scope': ApkWorkspaceBindingService.currentScopeId ?? 'global',
    'workDir': workDir,
    'activeApk': await ApkWorkspaceBindingService.activeApkPath(),
    'rootEntryCount': rootEntryCount,
    if (truncated) 'workDirRootTruncated': true,
    'apkCount': (await ApkWorkspaceBindingService.listApks()).length,
    'buildCount': builds.length,
    'fileArtifactCount': fileArtifacts.length,
    'lastBuiltSo': ToolSessionState.lastBuiltSoPath,
    'hint': '完整清单请调用 action=inventory。',
  };
}

Future<String> _handleFileRead(Map<String, dynamic> args) async {
  // 批量模式：paths 数组一次读多文件（cap 8），逐项复用单路径逻辑，
  // 单文件失败不影响其余——把几十次亚秒连调压成一次往返
  final rawPaths = args['paths'];
  if (rawPaths is List && rawPaths.isNotEmpty) {
    final selected = rawPaths.take(8).map((p) => p.toString()).toList();
    final results = <Map<String, dynamic>>[];
    var succeeded = 0;
    for (final p in selected) {
      final one = Map<String, dynamic>.from(args)
        ..remove('paths')
        ..remove('path')
        ..['path'] = p;
      final decoded = jsonDecode(await _handleFileRead(one));
      final ok = decoded is Map<String, dynamic> && decoded['ok'] == true;
      if (ok) succeeded++;
      results.add(<String, dynamic>{'path': p, 'result': decoded});
    }
    return jsonEncode(<String, dynamic>{
      'ok': succeeded > 0,
      'batch': true,
      'requested': rawPaths.length,
      'executed': selected.length,
      'succeeded': succeeded,
      'results': results,
      if (rawPaths.length > 8) 'note': '超出上限 8 的路径已截断，请分批重试其余路径',
    });
  }
  final (path, pathErr) = await _resolveFileOpsPath(args);
  if (path == null) return jsonEncode(pathErr);
  // 读过即登记观测：后续写/删前据此判断内容是否已过期。
  _fsObservationGuard.observe(path);
  final normalized = path.replaceAll('\\', '/').toLowerCase();
  final isBlutterReference =
      normalized.contains('/blutter/v1/results/') &&
      (normalized.endsWith('/pp.txt') ||
          normalized.endsWith('/objs.txt') ||
          normalized.endsWith('.jsonl') ||
          (normalized.contains('/asm/') && normalized.endsWith('.dart')));
  final requestedOffset = (args['offset'] as num?)?.toInt() ?? 0;
  if (isBlutterReference && requestedOffset > 0) {
    return jsonEncode(<String, dynamic>{
      'ok': false,
      'error': 'reference_paging_blocked',
      'referenceOnly': true,
      'message':
          '这是 Blutter 参考产物，禁止按 offset 连续翻页。请用 grep 精确匹配，或用 so_analyze 的 locate/search/xref/disasm 按证据读取。当前页没有帮助就停止。',
    });
  }
  final req = <String, Object?>{'action': 'read', 'path': path};
  final offset = args['offset'];
  final limit = args['limit'];
  if (offset is num) req['offset'] = offset.toInt();
  if (limit is num) {
    req['limit'] = isBlutterReference
        ? limit.toInt().clamp(1, 80).toInt()
        : limit.toInt();
  } else if (isBlutterReference) {
    req['limit'] = 80;
  }
  final r = await ApkToolchainService.fileOps(req);
  final encoded = _encodeToolResult(r);
  if (!isBlutterReference) return encoded;
  final decoded = jsonDecode(encoded);
  if (decoded is Map<String, dynamic>) {
    decoded['referenceOnly'] = true;
    decoded['pagingBlocked'] = true;
    decoded['nextStep'] =
        '不要继续 read 下一页；改用 grep 或 so_analyze locate/search/xref/disasm。';
    return jsonEncode(decoded);
  }
  return encoded;
}

Future<String> _handleFileWrite(Map<String, dynamic> args) async {
  final (path, pathErr) = await _resolveFileOpsPath(args);
  if (path == null) return jsonEncode(pathErr);
  final staleBlock = _fsGuardBlock(args, path);
  if (staleBlock != null) return staleBlock;
  final content = (args['content'] ?? '').toString();
  final dryRun = (args['dryRun'] as bool?) ?? true;
  // v9 复测（F-02）：原包闸门在 **dryRun 预览阶段就拦**——过去只拦实际写入，
  // 预览回执 only wouldOverwrite:true 会误导调用方"下一步就能写"。
  final apkBlock = await _originalApkWriteGuard('write', path);
  if (apkBlock != null) return jsonEncode(apkBlock);
  // C12：透传 contentEncoding（utf8 缺省/base64/hex）——Kotlin 端支持二进制
  // 写入，此前 Dart 包装层丢参数导致二进制写退化成文本写。
  final encoding = (args['contentEncoding'] ?? '').toString().trim();
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'write',
    'path': path,
    'content': content,
    'dryRun': dryRun,
    if (encoding.isNotEmpty) 'contentEncoding': encoding,
  });
  final encoded = _encodeFileMutation(
    r,
    dryRun: dryRun,
    operation: 'write',
    path: path,
  );
  if (!dryRun) _fsObservationGuard.observe(path);
  return encoded;
}

Future<String> _handleFileList(Map<String, dynamic> args) async {
  // path 缺省 = 列统一工作目录本身（与 build/so 工具链产物落点一致）
  final raw = (args['path'] ?? '').toString().trim();
  final String? path;
  if (raw.isEmpty) {
    final dir = await ApkWorkspaceBindingService.workDir();
    path = (dir == null || dir.isEmpty) ? null : dir;
    if (path == null) {
      return jsonEncode(const {
        'ok': false,
        'error': 'workspace_not_set',
        'message': '工作目录未设置：请先在 APK 工作台设置统一工作目录，或显式传 path',
      });
    }
  } else {
    final (resolved, pathErr) = await _resolveFileOpsPath(args);
    if (resolved == null) return jsonEncode(pathErr);
    path = resolved;
  }
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'list',
    'path': path,
    'limit': (args['limit'] as num?)?.toInt() ?? 200,
    // APK/ZIP 条目列表（Kotlin 端识别包文件后走包内清单分支）
    if (args['offset'] is num) 'offset': (args['offset'] as num).toInt(),
    if ((args['entryPrefix'] ?? '').toString().trim().isNotEmpty)
      'entryPrefix': args['entryPrefix'].toString().trim(),
  });
  return _encodeToolResult(r);
}

Future<String> _handleFileInfo(Map<String, dynamic> args) async {
  final (path, pathErr) = await _resolveFileOpsPath(args);
  if (path == null) return jsonEncode(pathErr);
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'info',
    'path': path,
  });
  return _encodeToolResult(r);
}

Future<String> _handleFileDelete(Map<String, dynamic> args) async {
  final (path, pathErr) = await _resolveFileOpsPath(args);
  if (path == null) return jsonEncode(pathErr);
  final dryRun = (args['dryRun'] as bool?) ?? true;
  if (!dryRun) {
    // 原始 APK 只读闸门（报告 2-6）：删除同样不可逆，与 write/replace 同口径。
    final apkBlock = await _originalApkWriteGuard('delete', path);
    if (apkBlock != null) return jsonEncode(apkBlock);
  }
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'delete',
    'path': path,
    'recursive': args['recursive'] == true,
    'dryRun': dryRun,
  });
  return _encodeFileMutation(
    r,
    dryRun: dryRun,
    operation: 'delete',
    path: path,
    // 删除成功即冲销产物索引簿记：移除指向该路径的 build 记录与
    // 「待验证修改」草稿，避免 exists:false 陈账误导后续会话（复测实测）。
    reconcile: () => ApkWorkspaceBindingService.forgetArtifact(path),
  );
}

Future<String> _handleFileZip(Map<String, dynamic> args) async {
  final (path, pathErr) = await _resolveFileOpsPath(args);
  if (path == null) return jsonEncode(pathErr);
  final action = (args['action'] ?? 'zip').toString();
  final output = (args['output'] ?? '').toString().trim();
  final outputDir = (args['outputDir'] ?? '').toString().trim();
  final (resolvedOutput, outputErr) = output.isEmpty
      ? (null, null)
      : await _resolveFileOpsPath(<String, dynamic>{'path': output});
  final (resolvedOutputDir, outputDirErr) = outputDir.isEmpty
      ? (null, null)
      : await _resolveFileOpsPath(<String, dynamic>{'path': outputDir});
  if (outputErr != null) return jsonEncode(outputErr);
  if (outputDirErr != null) return jsonEncode(outputDirErr);
  // 原包只读闸门（F-02）：zip 产物不许写到原包头上。
  final zipOutput = resolvedOutput ?? '';
  if (zipOutput.isNotEmpty) {
    final zipBlock = await _originalApkWriteGuard('zip', zipOutput);
    if (zipBlock != null) return jsonEncode(zipBlock);
  }
  final dryRun = (args['dryRun'] as bool?) ?? true;
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': action,
    'path': path,
    if (resolvedOutput != null) 'output': resolvedOutput,
    if (resolvedOutputDir != null) 'outputDir': resolvedOutputDir,
    'dryRun': dryRun,
  });
  return _encodeFileMutation(
    r,
    dryRun: dryRun,
    operation: action,
    path:
        (action == 'zip' ? resolvedOutput : resolvedOutputDir) ??
        r.data?['outputPath']?.toString() ??
        r.data?['outputDir']?.toString(),
    source: path,
  );
}

Future<String> _handleFileDiff(Map<String, dynamic> args) async {
  final (source, sourceErr) = await _resolveFileOpsPath(<String, dynamic>{
    'path': args['sourcePath'],
  });
  if (source == null) return jsonEncode(sourceErr);
  final (target, targetErr) = await _resolveFileOpsPath(<String, dynamic>{
    'path': args['targetPath'],
  });
  if (target == null) return jsonEncode(targetErr);
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'diff',
    'path': source,
    'target': target,
    if (args['context'] is num) 'context': (args['context'] as num).toInt(),
  });
  return _encodeToolResult(r);
}

Future<String> _handleFileMkdir(Map<String, dynamic> args) async {
  final (path, pathErr) = await _resolveFileOpsPath(args);
  if (path == null) return jsonEncode(pathErr);
  // D10（2026-09-21 自检）：此前 mkdir 恒定 dryRun:false 直接落盘，调用方传
  // dryRun=true 也只得到"已创建"——工具自己声明的预览契约说一套做一套。改为
  // 与其他写类动作（write/delete/copy/rename/zip/replace）同款：缺省 true，
  // 只有显式 dryRun:false 才真正创建。
  final dryRun = (args['dryRun'] as bool?) ?? true;
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'mkdir',
    'path': path,
    'dryRun': dryRun,
  });
  return _encodeFileMutation(r, dryRun: dryRun, operation: 'mkdir', path: path);
}

Future<String> _handleFileCopy(Map<String, dynamic> args) async {
  final (source, sourceErr) = await _resolveFileOpsPath(<String, dynamic>{
    'path': args['sourcePath'],
  });
  if (source == null) return jsonEncode(sourceErr);
  final (target, targetErr) = await _resolveFileOpsPath(<String, dynamic>{
    'path': args['targetPath'],
  });
  if (target == null) return jsonEncode(targetErr);
  // 原包只读闸门补到 copy 的**目标**（2026-10-03 报告 F-02：此前只拦
  // write/delete/replace，copy/rename/zip 的输出路径能覆盖原包）。
  final copyBlock = await _originalApkWriteGuard('copy', target);
  if (copyBlock != null) return jsonEncode(copyBlock);
  final dryRun = (args['dryRun'] as bool?) ?? true;
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'copy',
    'path': source,
    'target': target,
    'overwrite': args['overwrite'] == true,
    'dryRun': dryRun,
  });
  return _encodeFileMutation(
    r,
    dryRun: dryRun,
    operation: 'copy',
    path: target,
    source: source,
    reconcile: () => ApkWorkspaceBindingService.reconcileMovedPath(
      source,
      target,
      copy: true,
    ),
  );
}

Future<String> _handleFileRename(
  Map<String, dynamic> args, {
  String requestedAction = 'rename',
}) async {
  final (source, sourceErr) = await _resolveFileOpsPath(<String, dynamic>{
    'path': args['sourcePath'],
  });
  if (source == null) return jsonEncode(sourceErr);
  final (target, targetErr) = await _resolveFileOpsPath(<String, dynamic>{
    'path': args['targetPath'],
  });
  if (target == null) return jsonEncode(targetErr);
  // 原包只读闸门（F-02）：rename 的落点同样不许覆盖原包。
  final renameBlock = await _originalApkWriteGuard('rename', target);
  if (renameBlock != null) return jsonEncode(renameBlock);
  final dryRun = (args['dryRun'] as bool?) ?? true;
  final r = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'rename',
    'path': source,
    'target': target,
    'overwrite': args['overwrite'] == true,
    'dryRun': dryRun,
  });
  final encoded = await _encodeFileMutation(
    r,
    dryRun: dryRun,
    operation: 'rename',
    path: target,
    source: source,
    reconcile: () async {
      await ApkWorkspaceBindingService.reconcileMovedPath(source, target);
      await ApkWorkspaceService.refreshSourceFingerprint(
        target,
        replacesPath: source,
      );
    },
  );
  // 归一可见化：move 与 rename 同实现，但调用方写的 move 必须被回显，
  // 否则"我写的动作到底执行了没有"无从判断（自检 D13）。
  if (requestedAction == 'rename') return encoded;
  final decoded = jsonDecode(encoded);
  if (decoded is! Map) return encoded;
  final payload = Map<String, dynamic>.from(decoded);
  payload['action'] = requestedAction;
  payload['normalizedTo'] = 'rename';
  payload['normalizationNote'] =
      'move 与 rename 是同一实现（跨目录重定位由底层文件重命名完成），'
      '本次按 rename 执行；返回体保留你写的 action=move 以便对账。';
  return jsonEncode(payload);
}

Future<String> _handleFileGrep(Map<String, dynamic> args) async {
  final (path, pathErr) = await _resolveFileOpsPath(args);
  if (path == null) return jsonEncode(pathErr);
  final mode = (args['mode'] ?? 'grep').toString();
  // 报告 2-1（用户实测，风险最高的一条）：replace 过去缺省 dryRun=false，也就是
  // 「不传参数就真改文件」，与工作目录策略「写类动作默认预览」相反。现在与
  // write/copy/mkdir/zip/unzip/delete 对齐：**缺省即预览**，要落地必须显式传
  // dryRun=false。
  final dryRun = (args['dryRun'] as bool?) ?? (mode == 'replace');
  final req = <String, Object?>{
    'action': mode == 'replace' ? 'replace' : 'grep',
    'path': path,
    if (mode == 'replace') ...{
      'find': (args['find'] ?? '').toString(),
      'replacement': (args['replacement'] ?? '').toString(),
      'dryRun': dryRun,
    } else ...{
      'pattern': (args['pattern'] ?? args['query'] ?? '').toString(),
      if (args['limit'] is num) 'limit': (args['limit'] as num).toInt(),
      // schema 已声明这两个 grep 旋钮（local_tool_schemas.dart:2629/:2634），
      // 且原生侧 FileOpsTool.grep 会读它们（:875-876），恢复指引也明确让调用方
      // 「提高 maxFileBytes / 加 forceText=true 重试」——此前 Dart 侧不转发，
      // 于是模型照做也没用（声明与行为不一致）。
      if (args['maxFileBytes'] is num)
        'maxFileBytes': (args['maxFileBytes'] as num).toInt(),
      if (args['forceText'] is bool) 'forceText': args['forceText'],
    },
    if (args['include'] != null) 'include': args['include'].toString(),
  };
  if (mode == 'replace' && !dryRun) {
    final apkBlock = await _originalApkWriteGuard('replace', path);
    if (apkBlock != null) return jsonEncode(apkBlock);
  }
  final r = await ApkToolchainService.fileOps(req);
  if (mode != 'replace') return _encodeToolResult(r);
  return _encodeFileMutation(
    r,
    dryRun: dryRun,
    operation: 'replace',
    path: path,
  );
}

Future<String> _handleFileStrings(Map<String, dynamic> args) async {
  final (path, pathErr) = await _resolveFileOpsPath(args);
  if (path == null) return jsonEncode(pathErr);
  final result = await ApkToolchainService.fileOps(<String, Object?>{
    'action': 'strings',
    'path': path,
    'encoding': (args['encoding'] ?? 'auto').toString(),
    'query': (args['query'] ?? '').toString(),
    if (args['limit'] is num) 'limit': (args['limit'] as num).toInt(),
    if (args['minLength'] is num)
      'minLength': (args['minLength'] as num).toInt(),
  });
  return _encodeToolResult(result);
}

Future<String> _handleSmaliRead(Map<String, dynamic> args) async {
  final (path, err) = await _resolveToolchainPath(args, bindActive: false);
  if (path == null) {
    return jsonEncode({'ok': false, 'error': 'invalid_args', 'message': err});
  }
  final qid = (args['qualifiedId'] ?? '').toString();
  // 批量模式：qualifiedIds 数组一次读多类/方法（cap 8），逐项独立，
  // 单项失败填错误对象不炸批——数组遍历场景几十次连调压成一次往返
  final rawQids = args['qualifiedIds'];
  if (rawQids is List && rawQids.isNotEmpty) {
    final selected = rawQids.take(8).map((q) => q.toString()).toList();
    final results = <Map<String, dynamic>>[];
    var succeeded = 0;
    for (final q in selected) {
      final r = await ApkToolchainService.smaliRead(path: path, qualifiedId: q);
      final decoded = _toolResultMap(r);
      final ok = decoded['ok'] == true;
      if (ok) succeeded++;
      results.add(<String, dynamic>{'qualifiedId': q, 'result': decoded});
    }
    return jsonEncode(<String, dynamic>{
      'ok': succeeded > 0,
      'batch': true,
      'requested': rawQids.length,
      'executed': selected.length,
      'succeeded': succeeded,
      'results': results,
      if (rawQids.length > 8) 'note': '超出上限 8 的项已截断，请分批重试其余项',
    });
  }
  if (qid.isEmpty) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_args',
      'message': '缺少 qualifiedId（或传 qualifiedIds 数组批量读取）',
    });
  }
  final r = await ApkToolchainService.smaliRead(path: path, qualifiedId: qid);
  return _encodeToolResult(r);
}

/// Direct Command 2.0（蓝图 §5.2）：B 类固定链执行器。
/// 链体在 [ApkTaskChainService] 内程序化探针，LLM 只消费证据汇总做判断。
Future<String> _handleRunTaskCommand(
  Map<String, dynamic> args,
  String analyzerContextKey,
  MemoryRepository? memoryRepository,
) async {
  final apkPath = (args['apkPath'] ?? '').toString().trim();
  final command = (args['command'] ?? '').toString().trim();
  // 越权面收敛：apkPath 此前原样交给任务链，相对路径里的 `..` 能指到工作目录
  // 之外（链内的扫描/读取/安装全都会接受它）。统一走 APK 路径解析（含工作目录
  // 门禁与产物沿用逻辑）。
  if (apkPath.isNotEmpty) {
    final (resolvedApkPath, resolveError) = await _resolveLocalApkPath(
      <String, dynamic>{'apkPath': apkPath},
      null,
    );
    if (resolvedApkPath == null) {
      return jsonEncode({
        'ok': false,
        'error': 'PATH_OUTSIDE_WORKSPACE',
        'message': resolveError ?? 'apkPath 无法解析到工作目录内',
      });
    }
    args['apkPath'] = resolvedApkPath;
  }
  // D16（2026-09-21 自检）：FIELD_STATE_LOCATE 是 DEX 层字段状态链
  // （FIELD_USAGE → WRITE_FIELD → METHOD_BODY），对 Dart AOT 包结构性不可能命中。
  // 在进入链之前拦下——链一旦跑起来就会产出结构化 failureReason，被下面的
  // 失败记忆记账收走（实测同一失败还记了两次）。
  if (command == ApkTaskChainService.fieldStateLocate) {
    final gate = await _dartAotNotApplicable(
      capability: 'run_task_command($command)',
      instead:
          '改用 FIELD_STATE_LOCATE 之外的两条路：① Dart 层定位 —— '
          'so_analyze(action=blutter, blutterAction=search, scope=pp, query=<业务词>) → '
          'blutterAction=pool → so_analyze(action=disasm) 判读写方向；'
          '② 需要 DEX 层结构时先确认目标确实在 DEX（非 Flutter 业务）。',
    );
    if (gate != null) return jsonEncode(gate);
  }
  final result = await ApkTaskChainService.run(
    command: command,
    args: <String, dynamic>{
      ...args,
      if (apkPath.isEmpty)
        'apkPath': await ApkWorkspaceBindingService.activeApkPath() ?? '',
    },
    analyzerContextKey: analyzerContextKey,
  );
  // A2（§6.1 失败记忆）：链返回结构化 failureReason 时落库（去重计数），
  // 并给响应附最近失败摘要——LLM 据此避免重复踩坑。
  if (memoryRepository != null) {
    try {
      final command = (args['command'] ?? '').toString().trim();
      var failureReason = (result['failureReason'] ?? '').toString();
      if (failureReason.isEmpty && result['evidence'] is Map) {
        failureReason = ((result['evidence'] as Map)['failureReason'] ?? '')
            .toString();
      }
      final target = result['target'] is Map
          ? ((result['target'] as Map)['locator'] ?? '').toString()
          : '';
      if (failureReason.isNotEmpty) {
        await ApkFailureMemoryService.recordFailure(
          memoryRepository,
          command: command,
          apkPath: apkPath,
          failureReason: failureReason,
          target: target,
          detail: (result['summary'] ?? '').toString(),
        );
      }
      final recent = await ApkFailureMemoryService.summaryForPrompt(
        memoryRepository,
        apkPath: apkPath,
      );
      if (recent.isNotEmpty) {
        result['recentFailures'] = recent;
        result['recentFailuresNote'] =
            '最近 ${recent.length} 条同包失败记忆（machine-readable）：'
            '相同 failureReason+目标不要用同样方式重试。';
      }
    } catch (_) {
      // 失败记忆是增强面：任何异常不阻断链结果本身。
    }
  }
  return jsonEncode(result);
}
