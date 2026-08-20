import 'dart:io' show Platform;
import 'package:flutter_background/flutter_background.dart';
import 'notification_service.dart';

/// Callback signature for background task completion.
typedef BackgroundTaskCallback = void Function(BackgroundTaskResult result);

/// Result of a background task execution.
enum BackgroundTaskResult { completed, failed, interrupted }

/// Manager for enabling/disabling background execution on Android.
///
/// Enhanced with:
/// - Task lifecycle management (start/end with notification)
/// - Vibration on completion when screen is off
/// - Automatic background disable after task ends
class AndroidBackgroundManager {
  static bool _initialized = false;
  static bool _taskActive = false;
  static BackgroundTaskCallback? _onTaskComplete;

  /// Initialize the plugin once and request needed permissions.
  static Future<bool> ensureInitialized({
    String? notificationTitle,
    String? notificationText,
  }) async {
    if (!Platform.isAndroid) return false;
    if (_initialized) return true;
    try {
      final androidConfig = FlutterBackgroundAndroidConfig(
        notificationTitle: notificationTitle ?? 'Kelivo is running',
        notificationText:
            notificationText ?? 'Keeping chat generation alive in background',
        notificationImportance: AndroidNotificationImportance.normal,
        // Explicitly use app launcher icon from mipmap to avoid resource resolution issues
        notificationIcon: const AndroidResource(
          name: 'ic_launcher',
          defType: 'mipmap',
        ),
      );
      final ok = await FlutterBackground.initialize(
        androidConfig: androidConfig,
      );
      _initialized = ok;
      return ok;
    } catch (_) {
      return false;
    }
  }

  /// Enable/disable background execution. Requires [ensureInitialized] to have run.
  static Future<void> setEnabled(bool enable) async {
    if (!Platform.isAndroid) return;
    try {
      // Short-circuit if state already matches
      try {
        final current = FlutterBackground.isBackgroundExecutionEnabled;
        if (current == enable) return;
      } catch (_) {}

      if (enable) {
        if (!_initialized) {
          // Initialize only when enabling, since this may trigger permission dialogs
          await ensureInitialized();
        }
        await FlutterBackground.enableBackgroundExecution();
      } else {
        // Try to disable without forcing initialization to avoid permission prompts
        try {
          await FlutterBackground.disableBackgroundExecution();
        } catch (_) {}
      }
    } catch (_) {
      // ignore runtime errors; best effort only
    }
  }

  /// Convenience to query whether background execution is currently enabled.
  static Future<bool> isEnabled() async {
    if (!Platform.isAndroid) return false;
    try {
      return FlutterBackground.isBackgroundExecutionEnabled;
    } catch (_) {
      return false;
    }
  }

  /// Whether a background task is currently active.
  static bool get isTaskActive => _taskActive;

  /// Start a background task with lock-screen persistence.
  ///
  /// Enables background execution and shows an ongoing notification.
  /// Call [endTask] when the operation completes.
  static Future<void> startTask({
    String? title,
    BackgroundTaskCallback? onComplete,
  }) async {
    if (!Platform.isAndroid) return;
    _onTaskComplete = onComplete;
    _taskActive = true;

    await setEnabled(true);

    // Show ongoing notification
    await NotificationService.showChatStatus(
      status: ChatNotificationStatus.inProgress,
      title: title ?? 'Processing in background',
    );
  }

  /// End the current background task.
  ///
  /// Vibrates the device, shows a result notification,
  /// and disables background execution.
  static Future<void> endTask({
    BackgroundTaskResult result = BackgroundTaskResult.completed,
    String? title,
    String? body,
  }) async {
    if (!Platform.isAndroid) return;
    if (!_taskActive) return;
    _taskActive = false;

    // Map result to notification status
    ChatNotificationStatus notifStatus;
    switch (result) {
      case BackgroundTaskResult.completed:
        notifStatus = ChatNotificationStatus.completed;
        break;
      case BackgroundTaskResult.failed:
        notifStatus = ChatNotificationStatus.failed;
        break;
      case BackgroundTaskResult.interrupted:
        notifStatus = ChatNotificationStatus.interrupted;
        break;
    }

    // Show result notification (also vibrates for completed/failed)
    await NotificationService.showChatStatus(
      status: notifStatus,
      title: title,
      body: body,
    );

    // Invoke callback
    _onTaskComplete?.call(result);
    _onTaskComplete = null;

    // Disable background execution after a short delay
    // to allow notification to be fully delivered.
    Future.delayed(const Duration(seconds: 2), () {
      setEnabled(false);
    });
  }
}
