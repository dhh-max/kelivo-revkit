import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

typedef ChatCompletionNotificationSender =
    Future<void> Function({
      required String conversationId,
      String? title,
      String? body,
    });

class NotificationService {
  static final FlutterLocalNotificationsPlugin _plugin =
      FlutterLocalNotificationsPlugin();
  static final StreamController<String> _conversationTapController =
      StreamController<String>.broadcast();
  static final StreamController<String> _scheduledRunTapController =
      StreamController<String>.broadcast();
  static String? _pendingScheduledRunId;
  static Stream<String> get scheduledRunTaps =>
      _scheduledRunTapController.stream;
  static String? takePendingScheduledRunId() {
    final id = _pendingScheduledRunId;
    _pendingScheduledRunId = null;
    return id;
  }

  static bool _inited = false;
  static Future<void>? _initialization;
  static String? _pendingConversationId;
  static final Map<String, String> _pendingMessageIds = {};
  static String? takePendingMessageId(String conversationId) =>
      _pendingMessageIds.remove(conversationId);
  static const String _chatCompletionPayloadPrefix = 'chat-complete:';
  static const AndroidNotificationChannel _channel = AndroidNotificationChannel(
    // 渠道 id 保持不变（改 id 会新建一个渠道、用户原来的开关设置会丢）；
    // 名称/描述是用户在系统通知设置里看到的那行字，跟着品牌走。
    'kelivo_bg_chat_v2',
    'SoLab 后台生成',
    description: 'SoLab 在后台完成对话生成时提醒你',
    importance: Importance.high,
    playSound: true,
  );

  static Stream<String> get conversationTaps =>
      _conversationTapController.stream;

  /// Returns a notification target received before the home page subscribed.
  static String? takePendingConversationId() {
    final conversationId = _pendingConversationId;
    _pendingConversationId = null;
    return conversationId;
  }

  static Future<void> ensureInitialized() async {
    if (!Platform.isAndroid) return;
    if (_inited) return;
    final existing = _initialization;
    if (existing != null) {
      await existing;
      return;
    }

    final initialization = _initializeAndroid();
    _initialization = initialization;
    try {
      await initialization;
    } finally {
      if (identical(_initialization, initialization)) {
        _initialization = null;
      }
    }
  }

  static Future<void> _initializeAndroid() async {
    // Android initialization
    // 默认小图标也用品牌单色剪影（这里只是"没显式给 icon 时"的兜底）。
    const AndroidInitializationSettings androidInit =
        AndroidInitializationSettings('@drawable/ic_stat_solab');
    const InitializationSettings init = InitializationSettings(
      android: androidInit,
    );
    await _plugin.initialize(
      init,
      onDidReceiveNotificationResponse: _handleNotificationResponse,
    );

    // Create channel
    final android = _plugin
        .resolvePlatformSpecificImplementation<
          AndroidFlutterLocalNotificationsPlugin
        >();
    if (android != null) {
      await android.createNotificationChannel(_channel);
      // Runtime notification permission (Android 13+) should be requested by app UI if needed
    }
    _inited = true;

    // The response callback covers warm starts. Cold starts must be queried
    // explicitly after plugin initialization.
    try {
      final launchDetails = await _plugin.getNotificationAppLaunchDetails();
      if (launchDetails?.didNotificationLaunchApp == true) {
        final response = launchDetails?.notificationResponse;
        if (response != null) _handleNotificationResponse(response);
      }
    } catch (_) {}
  }

  /// Ensure Android 13+ notifications permission is granted (no-op on lower versions/other platforms).
  static Future<bool> ensureAndroidNotificationsPermission() async {
    if (!Platform.isAndroid) return true;
    final android = _plugin
        .resolvePlatformSpecificImplementation<
          AndroidFlutterLocalNotificationsPlugin
        >();
    if (android == null) return true;
    try {
      final enabled = await android.areNotificationsEnabled();
      if (enabled == true) return true;
    } catch (_) {}
    try {
      final ok = await android.requestNotificationsPermission();
      return ok ?? false;
    } catch (_) {
      return false;
    }
  }

  static Future<void> showChatCompleted({
    required String conversationId,
    String? title,
    String? body,
  }) async {
    if (!Platform.isAndroid) return;
    if (conversationId.trim().isEmpty) return;
    await ensureInitialized();
    await _plugin.show(
      notificationIdForConversation(conversationId),
      title ?? 'Generation complete',
      body ?? 'Assistant reply has been generated',
      NotificationDetails(
        android: AndroidNotificationDetails(
          _channel.id,
          _channel.name,
          channelDescription: _channel.description,
          importance: Importance.max,
          priority: Priority.max,
          playSound: true,
          enableVibration: true,
          category: AndroidNotificationCategory.message,
          visibility: NotificationVisibility.public,
          ticker: 'SoLab',
          styleInformation: BigTextStyleInformation(
            body ?? 'Assistant reply has been generated',
          ),
        ),
      ),
      payload: '$_chatCompletionPayloadPrefix$conversationId',
    );
  }

  static void _handleNotificationResponse(NotificationResponse response) {
    final runId = scheduledRunIdFromPayload(response.payload);
    if (runId != null) {
      if (_scheduledRunTapController.hasListener) {
        _scheduledRunTapController.add(runId);
      } else {
        _pendingScheduledRunId = runId;
      }
      return;
    }
    final conversationId = conversationIdFromPayload(response.payload);
    if (conversationId == null) return;
    openConversation(conversationId);
  }

  /// 打开某个会话（上游 1.2.6 抽成公开方法）。
  ///
  /// 除通知点击外，原生前台通知、悬浮窗、ActivityKit 也走这里；首页尚未订阅
  /// 时先把目标暂存（由 `takePendingConversationId` 取走），避免点击丢失。
  /// [messageId] 由上游 1.3.0 加入：带消息落点的通知点击可直达那条消息。
  static void openConversation(String conversationId, {String? messageId}) {
    if (messageId != null) _pendingMessageIds[conversationId] = messageId;
    if (conversationId.trim().isEmpty) return;
    if (_conversationTapController.hasListener) {
      _conversationTapController.add(conversationId);
    } else {
      _pendingConversationId = conversationId;
    }
  }

  @visibleForTesting
  static String? conversationIdFromPayload(String? payload) {
    if (payload == null || !payload.startsWith(_chatCompletionPayloadPrefix)) {
      return null;
    }
    final conversationId = payload
        .substring(_chatCompletionPayloadPrefix.length)
        .trim();
    return conversationId.isEmpty ? null : conversationId;
  }

  /// 定时任务通知的点击载荷（上游 1.3.0）：`scheduled-task:<runId>`。
  @visibleForTesting
  static String? scheduledRunIdFromPayload(String? payload) {
    const prefix = 'scheduled-task:';
    if (payload == null || !payload.startsWith(prefix)) return null;
    final id = payload.substring(prefix.length).trim();
    return id.isEmpty ? null : id;
  }

  /// Stable per-conversation IDs let notifications from different chats
  /// coexist while a later completion in the same chat replaces the old one.
  @visibleForTesting
  static int notificationIdForConversation(String conversationId) {
    var hash = 0x811c9dc5;
    for (final byte in utf8.encode(conversationId)) {
      hash = ((hash ^ byte) * 0x01000193) & 0x7fffffff;
    }
    const firstChatNotificationId = 10000;
    return firstChatNotificationId +
        (hash % (0x7fffffff - firstChatNotificationId));
  }

  /// 收尾通知的唯一策略源：[MobileBackgroundCoordinator.finish] 的实际门曾经是
  /// 一段内联条件，与这里容易漂移。平台维度不在这里判断——[showChatCompleted]
  /// 自身在非 Android 上直接 return；在这里再判一次只会让「注入假 sender」的
  /// 测试失去意义，也会把平台差异藏进两处。
  ///
  /// [homeRouteVisible] 表达「首页/会话页是否真的在可见路由上」。协调器只跟踪
  /// 前后台状态，因此传 true；保留该维度是为了将来接入路由可见性时不必再改签名。
  static bool shouldShowChatCompleted({
    required bool notifyModeEnabled,
    required bool appInForeground,
    required bool homeRouteVisible,
    required bool isCurrentConversation,
  }) {
    if (!notifyModeEnabled) return false;
    return !(appInForeground && homeRouteVisible && isCurrentConversation);
  }
}
