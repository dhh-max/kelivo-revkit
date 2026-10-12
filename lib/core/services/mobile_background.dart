import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import '../../l10n/app_localizations.dart';
import '../models/mobile_background_settings.dart';
import '../providers/settings_provider.dart';
import 'android_background.dart';
import 'mcp_server/mcp_http_server.dart';
import 'notification_service.dart';

enum BackgroundTaskPhase { requesting, generating, thinking, tool, retrying }

enum BackgroundTaskOutcome { completed, failed, cancelled, interrupted }

class MobileBackgroundStatus {
  const MobileBackgroundStatus([this.values = const {}]);

  final Map<String, dynamic> values;
  bool flag(String key) => values[key] == true;
  String text(String key) => values[key]?.toString() ?? '';
}

class _BackgroundTask {
  _BackgroundTask({
    required this.id,
    required this.conversationId,
    required this.title,
    required this.cancel,
    required this.startedAt,
    required this.scheduled,
    this.scheduledNotify = true,
    this.scheduledPreview = true,
  });

  final String id;
  final String conversationId;
  final String title;
  final Future<void> Function() cancel;
  final DateTime startedAt;
  final bool scheduled;
  final bool scheduledNotify, scheduledPreview;
  BackgroundTaskPhase phase = BackgroundTaskPhase.requesting;
  String toolName = '';
  int tokens = 0;
  bool interrupted = false;
}

/// Owns task identities for both platforms. Native code receives whole snapshots
/// on one serial channel; a late update/finish cannot resurrect a removed run.
class MobileBackgroundCoordinator extends ChangeNotifier
    with WidgetsBindingObserver {
  MobileBackgroundCoordinator({
    TargetPlatform? platform,
    MethodChannel? channel,
    ChatCompletionNotificationSender? notificationSender,
  }) : platform = platform ?? defaultTargetPlatform,
       _channel = channel ?? const MethodChannel('app.mobile_background'),
       _notificationSender =
           notificationSender ?? NotificationService.showChatCompleted;

  static final instance = MobileBackgroundCoordinator();
  final TargetPlatform platform;

  /// 通知标题里的运行时模式标签。
  ///
  /// 互斥双模（2026-09-13 定案）：进程内 MCP 服务器在跑 = MCP 模式（此时本地
  /// Agent 工具暂停），否则是本地 Agent 模式。做成可注入是因为测试不该依赖
  /// 真实服务器状态，也方便以后加第三种模式。
  static String Function() notificationModeLabel = _defaultModeLabel;

  static String _defaultModeLabel() =>
      McpHttpServer.instance.isRunning ? 'MCP 模式' : 'Agent 模式';
  final MethodChannel _channel;
  final ChatCompletionNotificationSender _notificationSender;
  final Map<String, _BackgroundTask> _tasks = {};
  MobileBackgroundSettings _settings = const MobileBackgroundSettings();
  MobileBackgroundSettings get settings => _settings;
  MobileBackgroundStatus status = const MobileBackgroundStatus();
  String? lastError;
  AppLocalizations? _l10n;
  bool _initialized = false;
  bool _foreground = true;
  bool get isForeground => _foreground;
  bool get supported =>
      !kIsWeb &&
      (platform == TargetPlatform.android || platform == TargetPlatform.iOS);
  String? Function()? visibleConversation;
  Future<void> Function()? pauseSpeech;
  Future<void>? _tail;
  Timer? _updateTimer;
  int _revision = 0;

  @visibleForTesting
  Set<String> get activeTaskIds => Set.unmodifiable(_tasks.keys);

  bool wasInterrupted(String id) => _tasks[id]?.interrupted == true;

  Future<void> initialize() async {
    if (!supported || _initialized) return;
    _initialized = true;
    _foreground =
        WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed;
    WidgetsBinding.instance.addObserver(this);
    _channel.setMethodCallHandler(_handleNativeCall);
    await _enqueue(() async {
      final pending = await _channel.invokeMethod<String>(
        'takePendingConversation',
      );
      if (pending != null) NotificationService.openConversation(pending);
    });
  }

  /// Settings can finish loading after the last frame before going background.
  /// Read them after loading, without requiring another widget rebuild.
  Future<void> configureFromSettings(
    SettingsProvider settings,
    AppLocalizations l10n,
  ) async {
    await settings.loaded;
    await configure(settings.mobileBackground, l10n);
  }

  Future<void> configure(
    MobileBackgroundSettings settings,
    AppLocalizations l10n,
  ) async {
    final changed =
        jsonEncode(_settings.toJson()) != jsonEncode(settings.toJson()) ||
        _l10n?.localeName != l10n.localeName;
    _settings = settings;
    _l10n = l10n;
    await initialize();
    if (changed) {
      if (platform == TargetPlatform.iOS &&
          !_foreground &&
          !settings.backgroundSpeechEnabled) {
        await pauseSpeech?.call();
      }
      await _sync();
    }
  }

  Future<void> start({
    required String id,
    required String conversationId,
    required String title,
    required Future<void> Function() cancel,
    bool scheduled = false,
    bool scheduledNotify = true,
    bool scheduledPreview = true,
  }) async {
    if (!supported || _tasks.containsKey(id)) return;
    _tasks[id] = _BackgroundTask(
      id: id,
      conversationId: conversationId,
      title: title,
      cancel: cancel,
      startedAt: DateTime.now(),
      scheduled: scheduled,
      scheduledNotify: scheduledNotify,
      scheduledPreview: scheduledPreview,
    );
    await initialize();
    await _sync();
  }

  void update(
    String id, {
    required BackgroundTaskPhase phase,
    int? tokens,
    String toolName = '',
  }) {
    final task = _tasks[id];
    if (task == null) return;
    task.phase = phase;
    task.toolName = toolName;
    if (tokens != null) task.tokens = tokens;
    _updateTimer ??= Timer(const Duration(milliseconds: 500), () {
      _updateTimer = null;
      unawaited(_sync());
    });
  }

  Future<void> finish(
    String id,
    BackgroundTaskOutcome outcome, {
    bool resultPersisted = true,
    String? replyPreview,
  }) async {
    final task = _tasks.remove(id);
    if (task == null) return;
    if (task.interrupted) outcome = BackgroundTaskOutcome.interrupted;
    _cancelUpdateTimer();
    final snapshot = _snapshot(
      terminal: {
        ..._taskMap(task),
        'outcome': outcome.name,
        'detail': _outcomeText(outcome),
        'finishedAt': DateTime.now().millisecondsSinceEpoch,
      },
    );
    await _enqueue(() async {
      final l10n = _l10n;
      if (resultPersisted &&
          outcome != BackgroundTaskOutcome.cancelled &&
          NotificationService.shouldShowChatCompleted(
            notifyModeEnabled: task.scheduled
                ? task.scheduledNotify
                : _settings.notificationsEnabled,
            appInForeground: _foreground,
            // 协调器只跟踪前后台；路由可见性尚未接入，见谓词文档。
            homeRouteVisible: true,
            isCurrentConversation:
                visibleConversation?.call() == task.conversationId,
          )) {
        try {
          final baseTitle = _settings.privacyMode || task.title.trim().isEmpty
              ? (l10n?.backgroundTaskTitle ?? 'SoLab')
              : task.title;
          await _notificationSender(
            conversationId: task.conversationId,
            // 通知内容区分运行时模式（互斥双模）：MCP 模式下本地 Agent 工具暂停，
            // 两类任务的通知混在一起时看不出这条是谁跑完的。模式标签只加在标题
            // 后缀，正文仍留给回复预览/结果文案。
            title: '$baseTitle · ${notificationModeLabel()}',
            body:
                task.scheduled &&
                    task.scheduledPreview &&
                    !_settings.privacyMode &&
                    outcome == BackgroundTaskOutcome.completed &&
                    replyPreview?.trim().isNotEmpty == true
                ? replyPreview!.trim().characters.take(200).toString()
                : _outcomeText(outcome),
          );
        } catch (error) {
          _recordError(error);
        }
      }
      // Earlier queued updates retain their active-task snapshot, so they
      // cannot release the iOS assertion before this notification is posted.
      await _sendSnapshot(snapshot);
    });
  }

  String _outcomeText(BackgroundTaskOutcome outcome) => switch (outcome) {
    BackgroundTaskOutcome.completed =>
      _l10n?.backgroundCompleted ?? 'Generation complete',
    BackgroundTaskOutcome.failed =>
      _l10n?.backgroundFailed ?? 'Generation failed',
    BackgroundTaskOutcome.cancelled =>
      _l10n?.backgroundCancelled ?? 'Generation cancelled',
    BackgroundTaskOutcome.interrupted =>
      _l10n?.backgroundInterrupted ?? 'Background generation interrupted',
  };

  Map<String, Object?> _taskMap(_BackgroundTask task) {
    final detail = switch (task.phase) {
      BackgroundTaskPhase.requesting => _l10n?.backgroundRequesting,
      BackgroundTaskPhase.generating => _l10n?.backgroundGenerating,
      BackgroundTaskPhase.thinking => _l10n?.backgroundThinking,
      BackgroundTaskPhase.tool => _l10n?.backgroundToolRunning,
      BackgroundTaskPhase.retrying => _l10n?.backgroundRetrying,
    };
    return {
      'id': task.id,
      'conversationId': task.conversationId,
      'title': _settings.privacyMode
          ? (_l10n?.backgroundTaskTitle ?? 'SoLab')
          : task.title,
      'detail': _settings.privacyMode
          ? (_l10n?.backgroundWorking ?? 'Working')
          : '${detail ?? task.phase.name}${task.phase == BackgroundTaskPhase.tool && task.toolName.isNotEmpty ? ': ${task.toolName}' : ''}',
      'tokens': _settings.privacyMode ? 0 : task.tokens,
      'startedAt': task.startedAt.millisecondsSinceEpoch,
    };
  }

  Future<void> _sync() {
    _cancelUpdateTimer();
    final snapshot = _snapshot();
    return _enqueue(() => _sendSnapshot(snapshot));
  }

  /// MCP 常驻：无生成任务时也要求上游 BackgroundRuntime 持有前台服务
  /// （与自研保活互斥，由 main 决定谁接管）。
  bool _mcpResident = false;

  Future<void> setMcpResident(bool value) async {
    if (_mcpResident == value) return;
    _mcpResident = value;
    await initialize();
    await _sync();
  }

  Map<String, dynamic> _snapshot({Map<String, Object?>? terminal}) => {
    'revision': ++_revision,
    'settings': {
      ..._settings.toJson(),
      'completionSeconds': _settings.completionVisibility.seconds,
      'mcpResident': _mcpResident,
    },
    'tasks': _tasks.values.map(_taskMap).toList(),
    'terminal': terminal,
    'labels': {
      'app': 'SoLab',
      'working': _l10n?.backgroundWorking ?? 'Working',
      'tasks': _l10n?.backgroundTasks ?? 'Tasks',
      'stop': _l10n?.backgroundStopTasks ?? 'Stop tasks',
      'open': _l10n?.backgroundOpenChat ?? 'Open chat',
      'close': _l10n?.commonClose ?? 'Close',
      'completed': _l10n?.backgroundCompleted ?? 'Generation complete',
      'stale': _l10n?.backgroundStale ?? 'Open SoLab to check the task.',
      // 常驻保护胶囊文案（原生浮层用；fork 字面量，跟随上游浮层开关与外观）。
      'resident': '常驻中',
    },
  };

  Future<void> _sendSnapshot(Map<String, dynamic> snapshot) async {
    // Redact queued payloads as well when privacy was enabled while a previous
    // native call was still in flight.
    if (_settings.privacyMode) {
      snapshot['settings'] = {
        ...snapshot['settings'] as Map<String, dynamic>,
        'privacyMode': true,
      };
      void redact(Map<String, Object?> task, {bool terminal = false}) {
        task['title'] = _l10n?.backgroundTaskTitle ?? 'SoLab';
        if (!terminal) task['detail'] = _l10n?.backgroundWorking ?? 'Working';
        task['tokens'] = 0;
      }

      for (final task in snapshot['tasks'] as List<Map<String, Object?>>) {
        redact(task);
      }
      final terminal = snapshot['terminal'] as Map<String, Object?>?;
      if (terminal != null) redact(terminal, terminal: true);
    }
    final result = await _channel.invokeMapMethod<String, dynamic>(
      'sync',
      snapshot,
    );
    if (result != null) {
      status = MobileBackgroundStatus(result);
      notifyListeners();
    }
  }

  Future<void> refreshStatus() => _enqueue(() async {
    final result = await _channel.invokeMapMethod<String, dynamic>('getStatus');
    if (result != null) status = MobileBackgroundStatus(result);
    notifyListeners();
  });

  /// Called only by explicit settings actions. Neither sync nor status requests
  /// permissions, including when the app is reopened with enabled settings.
  Future<void> requestPermission(String permission) =>
      _settingsAction('requestPermission', permission);

  Future<void> openSettings(String destination) =>
      _settingsAction('openSettings', destination);

  Future<void> _settingsAction(String method, String argument) async {
    if (!supported) return;
    try {
      await _channel.invokeMethod<void>(method, argument);
    } catch (error) {
      _recordError(error);
    }
  }

  /// Await before a real audio source takes ownership; release in all terminal
  /// paths. Native silent audio must never reconfigure an active recording.
  final Set<String> _captureOwners = {};
  bool get hasCaptureAudio => _captureOwners.isNotEmpty;

  Future<void> setAudioOwner(String owner, bool active) async {
    if (platform != TargetPlatform.iOS) return;
    if (owner.startsWith('capture:')) {
      if (active) {
        _captureOwners.add(owner);
        try {
          await pauseSpeech?.call();
        } catch (error) {
          _recordError(error);
        }
      } else {
        _captureOwners.remove(owner);
      }
    }
    await _enqueue(() async {
      await _channel.invokeMethod<void>('audioOwner', {
        'owner': owner,
        'active': active,
      });
    });
  }

  Future<void> _handleNativeCall(MethodCall call) async {
    if (call.method == 'openConversation') {
      final id = call.arguments as String?;
      if (id != null) NotificationService.openConversation(id);
    } else if (call.method == 'cancelTasks' || call.method == 'interrupted') {
      final args = Map<String, dynamic>.from(call.arguments as Map? ?? {});
      final ids = (args['ids'] as List? ?? []).cast<String>().toSet();
      final tasks = _tasks.values.where((t) => ids.contains(t.id)).toList();
      if (call.method == 'interrupted') {
        _recordError(args['reason'] ?? 'background_interrupted');
        for (final task in tasks) {
          task.interrupted = true;
        }
      }
      // A channel callback must not wait for cancellation to call back into the
      // same native sync queue (notably while an iOS assertion is expiring).
      for (final task in tasks) {
        unawaited(task.cancel().catchError(_recordError));
      }
    } else if (call.method == 'pauseSpeech') {
      final pause = pauseSpeech;
      if (pause != null) unawaited(pause().catchError(_recordError));
    } else if (call.method == 'statusChanged') {
      unawaited(refreshStatus());
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _foreground = true;
      unawaited(_sync());
    } else if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached ||
        state == AppLifecycleState.hidden) {
      _foreground = false;
      // 退到后台时重发一次常驻通知（2026-09-21 用户实测）：Android 13+ 在
      // POST_NOTIFICATIONS 授予之前发起的 FGS，其通知会被系统隐藏；授予后
      // 必须再 startForeground 一次才可见，否则要杀后台重开才出现。这里是
      // 用户"离开前台"的唯一可靠时点——补这一次重发，通知不再看运气。
      // 服务未运行时 refreshNotification 自身是 no-op。
      unawaited(AndroidBackgroundManager.refreshNotification());
      if (platform == TargetPlatform.iOS &&
          !_settings.backgroundSpeechEnabled) {
        final pause = pauseSpeech;
        if (pause != null) unawaited(pause().catchError(_recordError));
      }
    }
  }

  Future<void> _enqueue(Future<void> Function() operation) {
    if (!supported) return Future<void>.value();
    final previous = _tail;
    final next = previous == null
        ? Future<void>.sync(operation)
        : previous.then((_) => operation());
    return _tail = next.catchError(_recordError);
  }

  void _recordError(Object error) {
    lastError = error.toString();
    debugPrint('[MobileBackground] $error');
    notifyListeners();
  }

  void _cancelUpdateTimer() {
    _updateTimer?.cancel();
    _updateTimer = null;
  }

  @visibleForTesting
  Future<void> flush() async {
    if (_updateTimer != null) await _sync();
    await _tail;
  }

  @override
  void dispose() {
    _cancelUpdateTimer();
    if (_initialized) {
      WidgetsBinding.instance.removeObserver(this);
      _channel.setMethodCallHandler(null);
    }
    super.dispose();
  }
}
