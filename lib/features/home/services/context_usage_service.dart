import 'dart:async';
import 'dart:convert';
import 'dart:isolate';

import 'package:flutter/foundation.dart';

import '../../../core/database/chat_database_repository.dart';
import '../../../core/models/assistant.dart';
import '../../../core/models/chat_message.dart';
import '../../../core/models/conversation.dart';
import '../../../core/models/conversation_prompt_settings.dart';
import '../../../core/models/model_spec.dart';
import '../../../core/models/token_usage.dart';
import '../../../core/providers/assistant_provider.dart';
import '../../../core/providers/instruction_injection_provider.dart';
import '../../../core/providers/memory_provider_v2.dart';
import '../../../core/providers/settings_provider.dart';
import '../../../core/providers/world_book_provider.dart';
import '../../../core/services/chat/chat_service.dart';
import '../../../core/services/memory/memory_snapshot.dart';
import '../../../core/services/model_catalog/model_catalog_service.dart';
import '../../../core/services/model_spec/model_spec_resolver.dart';
import '../../../core/services/workspace/project_scope.dart';
import '../utils/model_display_helper.dart';
import 'context_assembly.dart';
import 'draft_token_counter.dart';

enum ContextUsageState { none, computing, exact, estimated, stale }

typedef ContextUsageConfiguration = ({
  Object settings,
  String? memorySnapshotHash,
});

Future<String?> readContextMemorySnapshotHash({
  required ChatDatabaseRepository? repository,
  required SettingsProvider settings,
  required Assistant? assistant,
  /// 显式项目（工作区）id：null 表示「这条会话没有项目」。
  String? projectId,
  /// 是否在 [projectId] 为空时回落到进程级活动项目。用量锚定传 false：
  /// 请求期与事后重算必须用同一个项目，否则 hash 漂移会作废锚定。
  bool useAmbientProject = true,
}) async {
  if (repository == null ||
      settings.legacyMemoryMode ||
      assistant?.enableMemory != true) {
    return null;
  }
  final snapshot = await readMemorySnapshot(
    repository: repository,
    assistantId: assistant!.id,
    lang: settings.resolvedMemoryPromptLang,
    maxItems: settings.memoryInjectionMaxItems,
    projectId: projectId,
    useAmbientProject: useAmbientProject,
  );
  return snapshot.isEmpty ? null : snapshot.hash;
}

/// Capture before assembling a request. Only matching request-time settings
/// can anchor the current context to that response's usage.
ContextUsageConfiguration contextUsageConfiguration({
  required SettingsProvider settings,
  required ProviderConfig config,
  required String providerKey,
  required String modelId,
  required Assistant? assistant,
  required InstructionInjectionProvider? instructions,
  required WorldBookProvider? worldBooks,
  Conversation? conversation,
  String? assistantId,
  String? memorySnapshotHash,
}) => (
  memorySnapshotHash: memorySnapshotHash,
  settings: (
    providerKey,
    modelId,
    assistant?.id ?? assistantId,
    ProviderConfig.classify(providerKey, explicitType: config.providerType),
    ModelSpecResolver.instance.spec(config, modelId),
    jsonEncode(assistant?.toJson()),
    settings.legacyMemoryMode,
    settings.memoryInjectionMaxItems,
    settings.resolvedMemoryPromptLang,
    settings.memoryRulesPromptEn,
    settings.memoryRulesPromptZh,
    settings.legacyMemoryPromptEn,
    settings.legacyMemoryPromptZh,
    instructions?.promptFor(
          assistant?.id ?? assistantId,
          instructionIds: assistant?.allowConversationPromptInjection == true
              ? ConversationPromptSettings.fromExtras(
                  conversation?.extras ?? const {},
                ).instructionIds
              : null,
        ) ??
        '',
    jsonEncode(
      worldBooks
              ?.activeBooksFor(
                assistant?.id ?? assistantId,
                bookIds: assistant?.allowConversationPromptInjection == true
                    ? ConversationPromptSettings.fromExtras(
                        conversation?.extras ?? const {},
                      ).worldBookIds
                    : null,
              )
              .map((book) => book.toJson())
              .toList() ??
          const [],
    ),
  ),
);

class ContextUsageBuckets {
  const ContextUsageBuckets({
    this.system = 0,
    this.injections = 0,
    this.history = 0,
    this.tools = 0,
    this.attachments = 0,
    this.draft = 0,
    this.memory = 0,
    this.worldBook = 0,
    this.skills = 0,
    this.workspace = 0,
    this.search = 0,
    this.mcpTools = 0,
  });

  final int system;
  final int injections;
  final int history;
  final int tools;
  final int attachments;
  final int draft;
  final int memory;
  final int worldBook;
  final int skills;
  final int workspace;
  final int search;
  final int mcpTools;

  int get nonDraftTotal =>
      system +
      injections +
      history +
      tools +
      attachments +
      memory +
      worldBook +
      skills +
      workspace +
      search +
      mcpTools;

  int get total => nonDraftTotal + draft;

  ContextUsageBuckets copyWith({
    int? system,
    int? injections,
    int? history,
    int? tools,
    int? attachments,
    int? draft,
    int? memory,
    int? worldBook,
    int? skills,
    int? workspace,
    int? search,
    int? mcpTools,
  }) {
    return ContextUsageBuckets(
      system: system ?? this.system,
      injections: injections ?? this.injections,
      history: history ?? this.history,
      tools: tools ?? this.tools,
      attachments: attachments ?? this.attachments,
      draft: draft ?? this.draft,
      memory: memory ?? this.memory,
      worldBook: worldBook ?? this.worldBook,
      skills: skills ?? this.skills,
      workspace: workspace ?? this.workspace,
      search: search ?? this.search,
      mcpTools: mcpTools ?? this.mcpTools,
    );
  }
}

/// Scales non-draft buckets so they sum to [anchorTotal], keeping proportions.
/// Returns null when there is nothing to scale (single "used" presentation).
ContextUsageBuckets? calibrateContextUsageBuckets({
  required ContextUsageBuckets estimated,
  required int anchorTotal,
}) {
  final values = <int>[
    estimated.system,
    estimated.injections,
    estimated.history,
    estimated.tools,
    estimated.attachments,
    estimated.memory,
    estimated.worldBook,
    estimated.skills,
    estimated.workspace,
    estimated.search,
    estimated.mcpTools,
  ];
  final estimatedNonDraft = values.fold<int>(0, (sum, value) => sum + value);
  if (estimatedNonDraft <= 0) return null;
  final scaled = [
    for (final value in values)
      (value * anchorTotal / estimatedNonDraft).round(),
  ];
  var residual = anchorTotal - scaled.fold<int>(0, (sum, value) => sum + value);
  while (residual != 0) {
    var largest = 0;
    for (var i = 1; i < scaled.length; i++) {
      if (scaled[i] > scaled[largest]) largest = i;
    }
    // With many small categories, rounding can exceed the anchor by more than
    // a single bucket. Distribute that correction without negative counts.
    final correction = residual < -scaled[largest]
        ? -scaled[largest]
        : residual;
    scaled[largest] += correction;
    residual -= correction;
  }
  return ContextUsageBuckets(
    system: scaled[0],
    injections: scaled[1],
    history: scaled[2],
    tools: scaled[3],
    attachments: scaled[4],
    draft: estimated.draft,
    memory: scaled[5],
    worldBook: scaled[6],
    skills: scaled[7],
    workspace: scaled[8],
    search: scaled[9],
    mcpTools: scaled[10],
  );
}

class ContextUsageSnapshot {
  const ContextUsageSnapshot({
    required this.state,
    required this.buckets,
    required this.usedTokens,
    required this.contextWindow,
    required this.conversationId,
    required this.revision,
    required this.providerKey,
    required this.modelId,
    required this.assistantId,
    required this.computedAt,
    this.calibrated = false,
  });

  final ContextUsageState state;
  final ContextUsageBuckets buckets;
  final int usedTokens;
  final int? contextWindow;
  final String conversationId;
  final int revision;
  final String providerKey;
  final String modelId;
  final String? assistantId;
  final DateTime computedAt;
  final bool calibrated;

  double? get ratio {
    final window = contextWindow;
    if (window == null || window <= 0) return null;
    return usedTokens / window;
  }

  ContextUsageSnapshot copyWith({
    ContextUsageState? state,
    ContextUsageBuckets? buckets,
    int? usedTokens,
    int? contextWindow,
    String? conversationId,
    int? revision,
    String? providerKey,
    String? modelId,
    String? assistantId,
    DateTime? computedAt,
    bool? calibrated,
  }) {
    return ContextUsageSnapshot(
      state: state ?? this.state,
      buckets: buckets ?? this.buckets,
      usedTokens: usedTokens ?? this.usedTokens,
      contextWindow: contextWindow ?? this.contextWindow,
      conversationId: conversationId ?? this.conversationId,
      revision: revision ?? this.revision,
      providerKey: providerKey ?? this.providerKey,
      modelId: modelId ?? this.modelId,
      assistantId: assistantId ?? this.assistantId,
      computedAt: computedAt ?? this.computedAt,
      calibrated: calibrated ?? this.calibrated,
    );
  }
}

class ContextUsageService extends ChangeNotifier {
  ContextUsageService({
    required this._chatService,
    required this._settings,
    required this._assistants,
    required this._instructions,
    required this._worldBooks,
    this._memories,
    this._assemble,
    this._resolveConversationProject,
    this._staleRefreshDelay = const Duration(milliseconds: 800),
    Future<T> Function<T>(T Function() computation)? runEstimate,
  }) : _runEstimate = runEstimate ?? Isolate.run {
    _settings.addListener(_onSettingsOrAssistantChanged);
    _assistants.addListener(_onSettingsOrAssistantChanged);
    _instructions.addListener(_onSettingsOrAssistantChanged);
    _worldBooks.addListener(_onSettingsOrAssistantChanged);
    _memories?.addListener(_onMemoryChanged);
    ModelCatalogService.instance.addListener(_onSettingsOrAssistantChanged);
  }

  final ChatService _chatService;
  final SettingsProvider _settings;
  final AssistantProvider _assistants;
  final InstructionInjectionProvider _instructions;
  final WorldBookProvider _worldBooks;
  final MemoryProviderV2? _memories;
  ContextAssemblyPreviewFn? _assemble;
  final ConversationProjectResolver? _resolveConversationProject;
  final Duration _staleRefreshDelay;
  final Future<T> Function<T>(T Function() computation) _runEstimate;

  final Map<String, ContextUsageSnapshot> _snapshots =
      <String, ContextUsageSnapshot>{};
  final Map<String, int> _inFlight = <String, int>{};
  final Map<String, int> _memoryChecks = <String, int>{};
  final Map<String, Timer> _debounce = <String, Timer>{};
  final Map<String, _ExactAnchor> _anchors = <String, _ExactAnchor>{};
  final Map<String, Object?> _snapshotConfigurations = <String, Object?>{};
  final Map<String, String?> _memorySnapshotHashes = {};
  final Map<String, DraftTokenCounter> _draftCounters = {};

  String? _activeConversationId;
  VoidCallback? _revisionListener;
  ValueListenable<int>? _revisionListenable;
  bool _disposed = false;

  String? get activeConversationId => _activeConversationId;

  ContextUsageSnapshot? get current {
    final id = _activeConversationId;
    if (id == null) return null;
    return _snapshots[id];
  }

  ContextUsageSnapshot? snapshot(String conversationId) =>
      _snapshots[conversationId];

  void bindAssembler(ContextAssemblyPreviewFn assemble) {
    _assemble = assemble;
  }

  /// Queues only the composer contribution; counting runs off the UI thread.
  void updateDraft(String conversationId, String text) {
    if (_disposed) return;
    _draftCounters
        .putIfAbsent(
          conversationId,
          () => DraftTokenCounter(
            onCountChanged: (_) {
              final snapshot = _snapshots[conversationId];
              if (snapshot != null) _foldDraft(conversationId, snapshot);
            },
          ),
        )
        .update(text);
  }

  void setActiveConversation(String? conversationId) {
    if (_activeConversationId == conversationId) {
      _syncResolvedIdentity();
      notifyListeners();
      return;
    }
    _unlistenRevision();
    _activeConversationId = conversationId;
    if (conversationId != null) {
      _listenRevision(conversationId);
      final snap = _snapshots[conversationId];
      final revision = _chatService.contextRevision(conversationId);
      if (snap != null &&
          snap.revision != revision &&
          snap.state != ContextUsageState.none) {
        _clearExactAnchor(conversationId);
        _snapshots[conversationId] = snap.copyWith(
          state: ContextUsageState.stale,
        );
        _scheduleRefresh(conversationId);
      } else if (snap == null || snap.state == ContextUsageState.none) {
        // 重启 / 首次进入该会话：快照根本不存在——此处不调度就**没有任何
        // 人**触发首次估算（recordUsage 只在回复后跑），圆环/图谱/弹窗
        // 一直空白（2026-10-03 真机点名）。进会话即估一次（debounce）。
        _scheduleRefresh(conversationId);
      }
      _syncResolvedIdentity();
    }
    notifyListeners();
  }

  /// Callers do not await this, so a failure falls back to an estimate
  /// instead of escaping as an uncaught error.
  Future<void> recordUsage({
    required String conversationId,
    required String providerKey,
    required String modelId,
    required String? assistantId,
    required TokenUsage usage,
    required ChatMessage assistantMessage,
    Object? requestConfiguration,
    int? requestRevision,
    /// 调用方是否在本次请求后**自己也写了一条带正文的消息**（正常回合的最终回答）。
    /// 那种写入会让 context revision +1；只有这种情况才允许 +1 漂移
    /// （用户改世界书/编辑历史同样只 +1，不能用容差混过去）。
    bool ownMessagePersisted = false,
  }) async {
    try {
      await _recordUsage(
        conversationId: conversationId,
        providerKey: providerKey,
        modelId: modelId,
        usage: usage,
        assistantMessage: assistantMessage,
        requestConfiguration: requestConfiguration,
        requestRevision: requestRevision,
        ownMessagePersisted: ownMessagePersisted,
      );
    } catch (_) {
      if (!_disposed) {
        _clearExactAnchor(conversationId);
        unawaited(refresh(conversationId, force: true));
      }
    }
  }

  Future<void> _recordUsage({
    required String conversationId,
    required String providerKey,
    required String modelId,
    required TokenUsage usage,
    required ChatMessage assistantMessage,
    required Object? requestConfiguration,
    required int? requestRevision,
    required bool ownMessagePersisted,
  }) async {
    if (_disposed || usage.promptTokens <= 0) return;
    // Pin the revision before the memory read so a change made meanwhile
    // invalidates the anchor instead of adopting it.
    final revision = _chatService.contextRevision(conversationId);
    final before = _resolvedIdentity(conversationId);
    if (before == null) return;
    final memoryHash = await _readMemoryHash(before, conversationId);
    if (_disposed) return;
    _memorySnapshotHashes[conversationId] = memoryHash;
    final resolved = _resolvedIdentity(conversationId);
    // 锚定漂移判定（2026-10-03 修正）：生成链路从 begin 的消息对 publish 到
    // checkpoint / finalize 全部是**静默写入、不 bump revision**——正常回合
    // driftFromRequest == 0。ownMessagePersisted 保留 1 格容差给「我们自己的
    // 落库确实 bump 一格」的路径；两个条件都必须落在 [0, allowedDrift] 内，
    // 溢出说明请求期间上下文被外部改动（用户编辑/新消息），作废回估算。
    // 2026-10-02 版要求 drift **恰好等于** 1，而静默写入的现实是 0——锚定
    // 每次都被自己拒绝，图谱永远停在「估算」（假数据根因）。
    final currentRevision = _chatService.contextRevision(conversationId);
    // 只有调用方**明确声明**本次请求属于正常回答落库时才容忍 1 格漂移；
    // 其余调用 strict 0——外部写入（改世界书/编辑历史）不能被误锚定。
    final allowedDrift = ownMessagePersisted ? 1 : 0;
    final driftFromRequest = currentRevision - (requestRevision ?? currentRevision);
    // pin 在本函数开头（finalize 之后）：期间任何 bump 都来自外部改动。
    final driftFromPin = currentRevision - revision;
    if (requestRevision == null ||
        driftFromRequest < 0 ||
        driftFromRequest > allowedDrift ||
        driftFromPin != 0 ||
        requestConfiguration == null ||
        resolved == null ||
        resolved.providerKey != providerKey ||
        resolved.modelId != modelId ||
        resolved.configuration != requestConfiguration) {
      _clearExactAnchor(conversationId);
      unawaited(refresh(conversationId, force: true));
      return;
    }
    final spec = resolved.spec;
    final used = contextTokensAfterTurn(
      usage: usage,
      assistantMessage: assistantMessage,
      replay: spec.reasoning.replay,
      toolEvents: _chatService.getToolEvents(assistantMessage.id),
    );
    final window = spec.contextWindow;
    final previous = _snapshots[conversationId];
    final draft = _draftCounters[conversationId]?.tokens ?? 0;
    final computedAt = DateTime.now();
    final storedAssistantId = resolved.assistantId;
    final configuration = requestConfiguration;
    _snapshotConfigurations[conversationId] = configuration;
    _anchors[conversationId] = _ExactAnchor(
      total: used,
      // 挂在**当前** revision 上：此后 context 若再变（用户改/新消息）刷新才发现
      // 失配并作废；挂请求期 revision 会被我们自己那条消息立刻顶掉。
      revision: currentRevision,
      computedAt: computedAt,
      providerKey: providerKey,
      modelId: modelId,
      assistantId: storedAssistantId,
      configuration: configuration,
    );
    _snapshots[conversationId] = ContextUsageSnapshot(
      state: ContextUsageState.exact,
      buckets: (previous?.buckets ?? const ContextUsageBuckets()).copyWith(
        draft: draft,
      ),
      usedTokens: used + draft,
      contextWindow: window,
      conversationId: conversationId,
      revision: revision,
      providerKey: providerKey,
      modelId: modelId,
      assistantId: storedAssistantId,
      computedAt: computedAt,
    );
    notifyListeners();
    unawaited(refresh(conversationId, force: true));
  }

  /// Omitted [draftText] preserves the latest input; an explicit empty string
  /// clears it. Background refreshes never own the input field's state.
  Future<void> refresh(
    String conversationId, {
    String? draftText,
    bool force = false,
  }) async {
    if (_disposed) return;
    // Capture edits before any await so overlapping background work sees them.
    if (draftText != null) {
      updateDraft(conversationId, draftText);
    }
    final initial = _resolvedIdentity(conversationId);
    if (initial == null) return;
    final revision = _chatService.contextRevision(conversationId);
    final check = (_memoryChecks[conversationId] ?? 0) + 1;
    _memoryChecks[conversationId] = check;
    int? generation;
    try {
      await _draftCounters[conversationId]?.flush();
      if (_disposed || _memoryChecks[conversationId] != check) return;
      final memoryHash = await _readMemoryHash(initial, conversationId);
      if (_disposed || _memoryChecks[conversationId] != check) return;
      if (_chatService.contextRevision(conversationId) != revision ||
          _resolvedIdentity(conversationId)?.configuration !=
              initial.configuration) {
        _scheduleRefresh(conversationId);
        return;
      }
      _memorySnapshotHashes[conversationId] = memoryHash;
      final resolved = _resolvedIdentity(conversationId)!;
      final existing = _snapshots[conversationId];
      if (!force &&
          existing != null &&
          _isFresh(existing, conversationId, resolved)) {
        _foldDraft(conversationId, existing);
        return;
      }

      // A cache hit must not cancel an already-running forced recalibration.
      generation = (_inFlight[conversationId] ?? 0) + 1;
      _inFlight[conversationId] = generation;
      final keepExact = _anchorMatches(conversationId, revision, resolved);
      _snapshotConfigurations[conversationId] = resolved.configuration;
      if (!keepExact) {
        _snapshots[conversationId] = ContextUsageSnapshot(
          state: ContextUsageState.computing,
          buckets: existing?.buckets ?? const ContextUsageBuckets(),
          usedTokens: existing?.usedTokens ?? 0,
          contextWindow: resolved.contextWindow,
          conversationId: conversationId,
          revision: revision,
          providerKey: resolved.providerKey,
          modelId: resolved.modelId,
          assistantId: resolved.assistantId,
          computedAt: existing?.computedAt ?? DateTime.now(),
        );
        notifyListeners();
      }

      final assemble = _assemble;
      final preview = assemble == null
          ? const ContextAssemblyPreview(
              systemText: '',
              injectionsText: '',
              historyText: '',
              tools: [],
              images: [],
            )
          : await assemble(
              conversationId: conversationId,
              providerKey: resolved.providerKey,
              modelId: resolved.modelId,
              assistantId: resolved.assistantId,
            );
      if (_disposed || _inFlight[conversationId] != generation) return;
      final job = ContextEstimateJob(preview: preview, kind: resolved.kind);
      final estimated = await _runEstimate(() => estimateContextBuckets(job));
      if (_disposed || _inFlight[conversationId] != generation) return;
      final latestMemoryHash = await _readMemoryHash(
        resolved,
        conversationId,
      );
      if (_disposed || _inFlight[conversationId] != generation) return;
      if (_chatService.contextRevision(conversationId) != revision) return;
      if (_resolvedIdentity(conversationId)?.configuration !=
          resolved.configuration) {
        return;
      }
      if (latestMemoryHash != memoryHash) {
        _memorySnapshotHashes[conversationId] = latestMemoryHash;
        _clearExactAnchor(conversationId);
        final snapshot = _snapshots[conversationId];
        if (snapshot != null) {
          _snapshots[conversationId] = snapshot.copyWith(
            state: ContextUsageState.stale,
          );
          notifyListeners();
        }
        _scheduleRefresh(conversationId);
        return;
      }
      final buckets = ContextUsageBuckets(
        system: estimated.system,
        injections: estimated.injections,
        history: estimated.history,
        tools: estimated.tools,
        attachments: estimated.attachments,
        draft: _draftCounters[conversationId]?.tokens ?? 0,
        memory: estimated.memory,
        worldBook: estimated.worldBook,
        skills: estimated.skills,
        workspace: estimated.workspace,
        search: estimated.search,
        mcpTools: estimated.mcpTools,
      );
      _snapshots[conversationId] = _snapshotFromEstimate(
        conversationId: conversationId,
        revision: revision,
        resolved: resolved,
        buckets: buckets,
      );
      notifyListeners();
    } catch (_) {
      if (_disposed ||
          (generation == null
              ? _memoryChecks[conversationId] != check
              : _inFlight[conversationId] != generation)) {
        return;
      }
      final fallback = _snapshots[conversationId];
      _clearExactAnchor(conversationId);
      if (fallback != null && fallback.state != ContextUsageState.none) {
        _snapshots[conversationId] = fallback.copyWith(
          state: ContextUsageState.stale,
        );
        notifyListeners();
      }
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _settings.removeListener(_onSettingsOrAssistantChanged);
    _assistants.removeListener(_onSettingsOrAssistantChanged);
    _instructions.removeListener(_onSettingsOrAssistantChanged);
    _worldBooks.removeListener(_onSettingsOrAssistantChanged);
    _memories?.removeListener(_onMemoryChanged);
    ModelCatalogService.instance.removeListener(_onSettingsOrAssistantChanged);
    _unlistenRevision();
    for (final timer in _debounce.values) {
      timer.cancel();
    }
    _debounce.clear();
    for (final counter in _draftCounters.values) {
      counter.dispose();
    }
    _draftCounters.clear();
    super.dispose();
  }

  ContextUsageSnapshot _snapshotFromEstimate({
    required String conversationId,
    required int revision,
    required _ResolvedIdentity resolved,
    required ContextUsageBuckets buckets,
  }) {
    final anchor = _anchors[conversationId];
    if (anchor != null && _anchorMatches(conversationId, revision, resolved)) {
      // 注意（2026-10-02 回退）：这里曾改成「锚定时存估算 + 之后按增量归因」，
      // 与既有语义冲突——锚定期间总量必须保持实测值（world book 用例明确要求
      // 内容变化后仍显示锚定总量直到下一次真实请求）。增量归因要另立设计并配
      // 全套用例，不能顺手替换。
      final calibrated = calibrateContextUsageBuckets(
        estimated: buckets,
        anchorTotal: anchor.total,
      );
      if (calibrated != null) {
        return ContextUsageSnapshot(
          state: ContextUsageState.exact,
          buckets: calibrated,
          usedTokens: anchor.total + calibrated.draft,
          contextWindow: resolved.contextWindow,
          conversationId: conversationId,
          revision: revision,
          providerKey: resolved.providerKey,
          modelId: resolved.modelId,
          assistantId: resolved.assistantId,
          computedAt: anchor.computedAt,
          calibrated: true,
        );
      }
      return ContextUsageSnapshot(
        state: ContextUsageState.exact,
        buckets: ContextUsageBuckets(draft: buckets.draft),
        usedTokens: anchor.total + buckets.draft,
        contextWindow: resolved.contextWindow,
        conversationId: conversationId,
        revision: revision,
        providerKey: resolved.providerKey,
        modelId: resolved.modelId,
        assistantId: resolved.assistantId,
        computedAt: anchor.computedAt,
      );
    }
    _clearExactAnchor(conversationId);
    return ContextUsageSnapshot(
      state: ContextUsageState.estimated,
      buckets: buckets,
      usedTokens: buckets.total,
      contextWindow: resolved.contextWindow,
      conversationId: conversationId,
      revision: revision,
      providerKey: resolved.providerKey,
      modelId: resolved.modelId,
      assistantId: resolved.assistantId,
      computedAt: DateTime.now(),
    );
  }

  bool _anchorMatches(
    String conversationId,
    int revision,
    _ResolvedIdentity resolved,
  ) {
    final anchor = _anchors[conversationId];
    return anchor != null &&
        anchor.revision == revision &&
        anchor.providerKey == resolved.providerKey &&
        anchor.modelId == resolved.modelId &&
        anchor.assistantId == resolved.assistantId &&
        anchor.configuration == resolved.configuration;
  }

  void _clearExactAnchor(String conversationId) {
    _anchors.remove(conversationId);
  }

  void _foldDraft(String conversationId, ContextUsageSnapshot existing) {
    final draftTokens = _draftCounters[conversationId]?.tokens ?? 0;
    if (existing.buckets.draft == draftTokens) return;
    final usedWithoutDraft = existing.usedTokens - existing.buckets.draft;
    _snapshots[conversationId] = existing.copyWith(
      buckets: existing.buckets.copyWith(draft: draftTokens),
      usedTokens: usedWithoutDraft + draftTokens,
    );
    notifyListeners();
  }

  bool _isFresh(
    ContextUsageSnapshot snapshot,
    String conversationId,
    _ResolvedIdentity resolved,
  ) {
    if (snapshot.state != ContextUsageState.exact &&
        snapshot.state != ContextUsageState.estimated) {
      return false;
    }
    return snapshot.revision == _chatService.contextRevision(conversationId) &&
        snapshot.providerKey == resolved.providerKey &&
        snapshot.modelId == resolved.modelId &&
        snapshot.assistantId == resolved.assistantId &&
        _snapshotConfigurations[conversationId] == resolved.configuration;
  }

  void _listenRevision(String conversationId) {
    final listenable = _chatService.contextRevisionListenable(conversationId);
    void listener() => _onActiveRevisionChanged(conversationId);
    listenable.addListener(listener);
    _revisionListenable = listenable;
    _revisionListener = listener;
  }

  void _unlistenRevision() {
    final listenable = _revisionListenable;
    final listener = _revisionListener;
    if (listenable != null && listener != null) {
      listenable.removeListener(listener);
    }
    _revisionListenable = null;
    _revisionListener = null;
  }

  void _onActiveRevisionChanged(String conversationId) {
    if (_activeConversationId != conversationId) return;
    final snap = _snapshots[conversationId];
    final revision = _chatService.contextRevision(conversationId);
    if (snap != null &&
        snap.revision != revision &&
        snap.state != ContextUsageState.none) {
      _clearExactAnchor(conversationId);
      _snapshots[conversationId] = snap.copyWith(
        state: ContextUsageState.stale,
      );
      notifyListeners();
    }
    _scheduleRefresh(conversationId);
  }

  void _onSettingsOrAssistantChanged() {
    final id = _activeConversationId;
    if (id == null) return;
    _syncResolvedIdentity();
  }

  void _onMemoryChanged() {
    final id = _activeConversationId;
    if (id != null) unawaited(refresh(id));
  }

  /// 记忆快照 hash，按**这条会话**所属项目计算。
  ///
  /// 项目身份以会话绑定为准（[_resolveConversationProject]）；未接线时回落到
  /// 进程级活动项目，保持旧行为（测试与老构造点零影响）。
  Future<String?> _readMemoryHash(
    _ResolvedIdentity identity,
    String conversationId,
  ) async {
    final resolver = _resolveConversationProject;
    if (resolver == null) {
      return readContextMemorySnapshotHash(
        repository: _chatService.chatRepositoryOrNull,
        settings: _settings,
        assistant: identity.assistant,
      );
    }
    String? projectId;
    try {
      projectId = (await resolver(conversationId)).id;
    } catch (e) {
      debugPrint('ContextUsage memory project resolve failed: $e');
    }
    return readContextMemorySnapshotHash(
      repository: _chatService.chatRepositoryOrNull,
      settings: _settings,
      assistant: identity.assistant,
      projectId: projectId,
      useAmbientProject: false,
    );
  }

  void _syncResolvedIdentity() {
    final id = _activeConversationId;
    if (id == null) return;
    final resolved = _resolvedIdentity(id);
    final snap = _snapshots[id];
    if (resolved == null || snap == null) return;
    if (snap.providerKey == resolved.providerKey &&
        snap.modelId == resolved.modelId &&
        snap.assistantId == resolved.assistantId &&
        _snapshotConfigurations[id] == resolved.configuration) {
      return;
    }
    _clearExactAnchor(id);
    _inFlight[id] = (_inFlight[id] ?? 0) + 1;
    _snapshots[id] = snap.copyWith(state: ContextUsageState.stale);
    notifyListeners();
    _scheduleRefresh(id);
  }

  void _scheduleRefresh(String conversationId) {
    if (_activeConversationId != conversationId) return;
    _debounce[conversationId]?.cancel();
    _debounce[conversationId] = Timer(_staleRefreshDelay, () {
      _debounce.remove(conversationId);
      if (_activeConversationId != conversationId) return;
      unawaited(refresh(conversationId));
    });
  }

  _ResolvedIdentity? _resolvedIdentity(String conversationId) {
    final conversation = _chatService.getConversation(conversationId);
    if (conversation == null) return null;
    final assistantId = conversation.assistantId;
    final assistant = assistantId == null
        ? _assistants.currentAssistant
        : _assistants.getById(assistantId);
    final model = resolveChatModel(
      _settings,
      conversation: conversation,
      assistant: assistant,
    );
    final providerKey = model.providerKey;
    final modelId = model.modelId;
    if (providerKey == null || modelId == null) return null;
    final cfg = _settings.getProviderConfig(providerKey);
    final spec = ModelSpecResolver.instance.spec(cfg, modelId);
    return _ResolvedIdentity(
      providerKey: providerKey,
      modelId: modelId,
      assistantId: assistant?.id ?? assistantId,
      kind: ProviderConfig.classify(
        providerKey,
        explicitType: cfg.providerType,
      ),
      spec: spec,
      assistant: assistant,
      configuration: contextUsageConfiguration(
        settings: _settings,
        config: cfg,
        providerKey: providerKey,
        modelId: modelId,
        assistant: assistant,
        assistantId: assistantId,
        instructions: _instructions,
        worldBooks: _worldBooks,
        conversation: conversation,
        memorySnapshotHash: _memorySnapshotHashes[conversationId],
      ),
    );
  }
}

class _ExactAnchor {
  const _ExactAnchor({
    required this.total,
    required this.revision,
    required this.computedAt,
    required this.providerKey,
    required this.modelId,
    required this.assistantId,
    required this.configuration,
  });

  final int total;
  final int revision;
  final DateTime computedAt;
  final String providerKey;
  final String modelId;
  final String? assistantId;
  final Object? configuration;
}

class _ResolvedIdentity {
  const _ResolvedIdentity({
    required this.providerKey,
    required this.modelId,
    required this.assistantId,
    required this.kind,
    required this.spec,
    required this.assistant,
    required this.configuration,
  });

  final String providerKey;
  final String modelId;
  final String? assistantId;
  final ProviderKind kind;
  final ModelSpec spec;
  final Assistant? assistant;
  final Object configuration;

  int? get contextWindow => spec.contextWindow;
}
