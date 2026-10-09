part of 'local_tools_service.dart';

class PhoneControlStatus {
  const PhoneControlStatus({required this.enabled, required this.connected});

  final bool enabled;
  final bool connected;
}

class DeviceLocalTools {
  const DeviceLocalTools._();

  static const MethodChannel _channel = MethodChannel('app.device_tools');

  static bool get screenTimeSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  static bool get calendarSupported =>
      !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.android ||
          defaultTargetPlatform == TargetPlatform.iOS);

  static bool get iosDeviceToolsSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.iOS;

  static bool get locationSupported =>
      !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.android ||
          defaultTargetPlatform == TargetPlatform.iOS);

  /// WeatherKit is iOS 16+. Defaults false until [prefetchIosCapabilities].
  static bool? _weatherKitAvailable;

  /// HealthKit may be absent on older iPads. Defaults false until prefetch.
  static bool? _healthDataAvailable;
  static List<String>? _availableHealthTypeIds;
  static Future<bool>? _prefetchFuture;
  static int _capabilityEpoch = 0;

  static bool get weatherSupported =>
      iosDeviceToolsSupported && (_weatherKitAvailable ?? false);

  static bool get healthSupported =>
      iosDeviceToolsSupported && (_healthDataAvailable ?? false);

  /// HealthKit type IDs the current OS can query. Until prefetch finishes,
  /// version-gated types (daylight) are omitted.
  static List<String> get availableHealthTypeIds {
    if (!iosDeviceToolsSupported) return const [];
    return List<String>.unmodifiable(
      _availableHealthTypeIds ?? HealthDataTypeIds.withoutOsVersionGate,
    );
  }

  static bool get remindersSupported => iosDeviceToolsSupported;

  /// 无障碍「手机控制」（上游 1.3.0）：仅 Android，且需系统无障碍服务已启用。
  static bool get phoneControlSupported =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  /// 服务是否已启用、是否已连接（未启用或未连通都返回 null）。
  static Future<PhoneControlStatus?> phoneControlStatus() async {
    if (!phoneControlSupported) return null;
    try {
      final result = await _channel.invokeMapMethod<String, dynamic>(
        'phoneControlStatus',
      );
      if (result == null) return null;
      return PhoneControlStatus(
        enabled: result['enabled'] == true,
        connected: result['enabled'] == true && result['connected'] == true,
      );
    } on MissingPluginException {
      return null;
    } on PlatformException {
      return null;
    }
  }

  /// 跳到系统无障碍设置页，让用户自己启用本服务。
  static Future<bool> openAccessibilitySettings() async {
    if (!phoneControlSupported) return false;
    try {
      await _channel.invokeMethod<void>('openAccessibilitySettings');
      return true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  /// Whether Android Usage Access (PACKAGE_USAGE_STATS) is granted.
  static Future<bool> hasUsageStatsPermission() async {
    if (!screenTimeSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>(
        'hasUsageStatsPermission',
      );
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  /// Opens the system Usage Access settings page (Android).
  static Future<void> openUsageAccessSettings() async {
    if (!screenTimeSupported) return;
    try {
      await _channel.invokeMethod<void>('openUsageAccessSettings');
    } on MissingPluginException {
      // Unsupported host.
    } on PlatformException {
      // Settings unavailable.
    }
  }

  /// Returns true when calendar full access is already granted.
  /// Uses the native EventKit / Android calendar permission path (not
  /// permission_handler), so it works without iOS PERMISSION_EVENTS macros.
  static Future<bool> hasCalendarPermission() async {
    if (!calendarSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>('hasCalendarPermission');
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  /// Requests calendar full access via the native channel.
  /// Returns true only when granted. On iOS, permanently denied / restricted
  /// states open the app Settings page.
  static Future<bool> requestCalendarPermission() async {
    if (!calendarSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>(
        'requestCalendarPermission',
      );
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  static Future<bool> hasLocationPermission() async {
    if (!locationSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>('hasLocationPermission');
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  static const locationPermissionPermanentlyDenied =
      'LOCATION_PERMISSION_PERMANENTLY_DENIED';

  /// Throws [PlatformException] with [locationPermissionPermanentlyDenied] on
  /// Android so settings UI can offer a way to restore permission.
  static Future<bool> requestLocationPermission() async {
    if (!locationSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>(
        'requestLocationPermission',
      );
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException catch (error) {
      if (error.code == locationPermissionPermanentlyDenied) rethrow;
      return false;
    }
  }

  static Future<bool> hasRemindersPermission() async {
    if (!remindersSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>(
        'hasRemindersPermission',
      );
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  static Future<bool> requestRemindersPermission() async {
    if (!remindersSupported) return false;
    try {
      final result = await _channel.invokeMethod<bool>(
        'requestRemindersPermission',
      );
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  /// Warms WeatherKit and HealthKit availability caches used by the sync
  /// [weatherSupported] / [healthSupported] getters.
  static Future<bool> prefetchIosCapabilities() {
    final existing = _prefetchFuture;
    if (existing != null) return existing;
    final epoch = _capabilityEpoch;
    final future = _queryIosCapabilities(epoch);
    _prefetchFuture = future;
    return future;
  }

  static Future<bool> _queryIosCapabilities(int epoch) async {
    if (!iosDeviceToolsSupported) {
      if (epoch == _capabilityEpoch) {
        _weatherKitAvailable = false;
        _healthDataAvailable = false;
        _availableHealthTypeIds = const [];
      }
      return false;
    }
    final results = await Future.wait([
      _invokeCapabilityFlag('isWeatherKitAvailable'),
      _invokeCapabilityFlag('isHealthDataAvailable'),
    ]);
    final weatherAvailable = results[0];
    final healthAvailable = results[1];
    final typeIds = healthAvailable
        ? await _invokeHealthTypeIds()
        : const <String>[];
    if (epoch == _capabilityEpoch) {
      _weatherKitAvailable = weatherAvailable;
      _healthDataAvailable = healthAvailable;
      _availableHealthTypeIds = typeIds;
    }
    return _weatherKitAvailable ?? weatherAvailable;
  }

  static Future<bool> _invokeCapabilityFlag(String method) async {
    try {
      final result = await _channel.invokeMethod<bool>(method);
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  static Future<List<String>> _invokeHealthTypeIds() async {
    try {
      final result = await _channel.invokeMethod<List<dynamic>>(
        'availableHealthTypes',
      );
      if (result == null) {
        return List<String>.from(HealthDataTypeIds.withoutOsVersionGate);
      }
      return HealthDataTypeIds.knownOnly(result.whereType<String>());
    } on MissingPluginException {
      return List<String>.from(HealthDataTypeIds.withoutOsVersionGate);
    } on PlatformException {
      return List<String>.from(HealthDataTypeIds.withoutOsVersionGate);
    }
  }

  @visibleForTesting
  static void debugResetIosCapabilities() {
    _capabilityEpoch++;
    _weatherKitAvailable = null;
    _healthDataAvailable = null;
    _availableHealthTypeIds = null;
    _prefetchFuture = null;
  }

  @visibleForTesting
  static void debugSetWeatherKitAvailable(bool? value) {
    _capabilityEpoch++;
    _weatherKitAvailable = value;
    _prefetchFuture = value == null ? null : Future<bool>.value(value);
  }

  @visibleForTesting
  static void debugSetHealthDataAvailable(bool? value) {
    _capabilityEpoch++;
    _healthDataAvailable = value;
    _availableHealthTypeIds = value == true
        ? List<String>.from(HealthDataTypeIds.all)
        : (value == false ? const <String>[] : null);
    _prefetchFuture = value == null
        ? null
        : Future<bool>.value(_weatherKitAvailable ?? false);
  }

  @visibleForTesting
  static void debugSetAvailableHealthTypeIds(List<String>? ids) {
    _availableHealthTypeIds = ids == null
        ? null
        : HealthDataTypeIds.knownOnly(ids);
  }

  /// Presents the HealthKit read sheet for [types] only. The returned flag is
  /// only that the request completed; iOS does not reveal per-type read grants.
  static Future<bool> requestHealthPermission({
    List<String> types = const [],
  }) async {
    if (!healthSupported) return false;
    final filtered = HealthDataTypeIds.intersectAvailable(
      types,
      availableHealthTypeIds,
    );
    if (filtered.isEmpty) return true;
    try {
      final result = await _channel.invokeMethod<bool>(
        'requestHealthPermission',
        jsonEncode({'types': filtered}),
      );
      return result == true;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  /// Opens this app's system settings page on Android or iOS.
  static Future<void> openAppSettings() async {
    if (!locationSupported) return;
    try {
      await _channel.invokeMethod<void>('openAppSettings');
    } on MissingPluginException {
      // Unsupported host.
    } on PlatformException {
      // Settings unavailable.
    }
  }
}
