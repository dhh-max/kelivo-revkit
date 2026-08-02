import 'dart:io' show Platform;
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:flutter/services.dart';

/// Chat generation status for real-time notifications.
enum ChatNotificationStatus { inProgress, completed, failed, interrupted }

class NotificationService {
  static final FlutterLocalNotificationsPlugin _plugin =
      FlutterLocalNotificationsPlugin();
  static bool _inited = false;
  static const AndroidNotificationChannel _channel = AndroidNotificationChannel(
    'kelivo_bg_chat_v2',
    'Chat Background',
    description: 'Notifications for chat generation status',
    importance: Importance.high,
    playSound: true,
  );

  static Future<void> ensureInitialized() async {
    if (!Platform.isAndroid) return;
    if (_inited) return;

    // Android initialization
    const AndroidInitializationSettings androidInit =
        AndroidInitializationSettings('@mipmap/ic_launcher');
    const InitializationSettings init = InitializationSettings(
      android: androidInit,
    );
    await _plugin.initialize(init);

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

  static Future<void> showChatCompleted({String? title, String? body}) async {
    if (!Platform.isAndroid) return;
    await ensureInitialized();
    await _plugin.show(
      2001, // id
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
          ticker: 'Kelivo',
          styleInformation: const DefaultStyleInformation(true, true),
        ),
      ),
    );
  }

  /// Show a real-time chat notification with status distinction.
  ///
  /// - [inProgress]: ongoing generation (low priority, silent)
  /// - [completed]: successful completion (vibrate + sound)
  /// - [failed]: generation failed (vibrate + sound)
  /// - [interrupted]: user interrupted (silent notification)
  static Future<void> showChatStatus({
    required ChatNotificationStatus status,
    String? title,
    String? body,
    String? preview,
  }) async {
    if (!Platform.isAndroid) return;
    await ensureInitialized();

    String notifTitle;
    String notifBody;
    bool playSound;
    bool vibrate;
    Importance importance;
    bool ongoing;

    switch (status) {
      case ChatNotificationStatus.inProgress:
        notifTitle = title ?? 'Generating...';
        notifBody = body ?? (preview != null ? 'Latest: $preview' : 'AI is generating a response');
        playSound = false;
        vibrate = false;
        importance = Importance.low;
        ongoing = true;
        break;
      case ChatNotificationStatus.completed:
        notifTitle = title ?? 'Generation complete';
        notifBody = body ?? (preview ?? 'Assistant reply has been generated');
        playSound = true;
        vibrate = true;
        importance = Importance.high;
        ongoing = false;
        break;
      case ChatNotificationStatus.failed:
        notifTitle = title ?? 'Generation failed';
        notifBody = body ?? 'An error occurred during generation';
        playSound = true;
        vibrate = true;
        importance = Importance.high;
        ongoing = false;
        break;
      case ChatNotificationStatus.interrupted:
        notifTitle = title ?? 'Generation interrupted';
        notifBody = body ?? 'Response generation was cancelled';
        playSound = false;
        vibrate = false;
        importance = Importance.defaultImportance;
        ongoing = false;
        break;
    }

    await _plugin.show(
      2002, // Use a different ID so it updates in place
      notifTitle,
      notifBody,
      NotificationDetails(
        android: AndroidNotificationDetails(
          _channel.id,
          _channel.name,
          channelDescription: _channel.description,
          importance: importance,
          priority: importance == Importance.high ? Priority.high : Priority.low,
          playSound: playSound,
          enableVibration: vibrate,
          ongoing: ongoing,
          autoCancel: !ongoing,
          category: AndroidNotificationCategory.message,
          visibility: NotificationVisibility.public,
          ticker: 'Kelivo',
          styleInformation: BigTextStyleInformation(
            notifBody,
            contentTitle: notifTitle,
          ),
        ),
      ),
    );

    // Vibrate on completion/failure for lock-screen awareness
    if (vibrate) {
      await vibrateDevice();
    }
  }

  /// Cancel ongoing chat notification.
  static Future<void> cancelChatStatus() async {
    if (!Platform.isAndroid) return;
    await ensureInitialized();
    await _plugin.cancel(2002);
  }

  /// Trigger device vibration (for lock-screen task completion).
  static Future<void> vibrateDevice({int durationMs = 300}) async {
    try {
      await HapticFeedback.vibrate();
    } catch (_) {}
  }
}
