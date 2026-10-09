/// User intent, separate from the permissions and resources reported by the OS.
class MobileBackgroundSettings {
  const MobileBackgroundSettings({
    this.androidEnabled = false,
    this.iosEnabled = false,
    this.notificationsEnabled = false,
    this.privacyMode = false,
    this.overlayEnabled = false,
    this.liveUpdatesEnabled = false,
    this.liveActivitiesEnabled = false,
    this.locationEnabled = false,
    this.silentAudioEnabled = false,
    this.backgroundSpeechEnabled = false,
    this.completionVisibility = BackgroundCompletionVisibility.oneMinute,
    // 用户 2026-10-04：默认用「大肥鱼」圆形图标（不带其他装饰）——过去默认
    // 'app'（应用图标）。显式选过 image/emoji 的用户不受影响（持久化会覆盖）。
    this.overlayIconKind = 'fish',
    this.overlayIconValue = '',
    this.overlayAppearance = const BackgroundOverlayAppearance(),
  });

  final bool androidEnabled;
  final bool iosEnabled;
  final bool notificationsEnabled;
  final bool privacyMode;
  final bool overlayEnabled;
  final bool liveUpdatesEnabled;
  final bool liveActivitiesEnabled;
  final bool locationEnabled;
  final bool silentAudioEnabled;
  final bool backgroundSpeechEnabled;
  final BackgroundCompletionVisibility completionVisibility;
  final String overlayIconKind;
  final String overlayIconValue;
  final BackgroundOverlayAppearance overlayAppearance;

  factory MobileBackgroundSettings.fromJson(Map<String, dynamic> json) {
    final visibility = BackgroundCompletionVisibility.values.firstWhere(
      (value) => value.name == json['completionVisibility'],
      orElse: () => BackgroundCompletionVisibility.oneMinute,
    );
    final kind = json['overlayIconKind'];
    return MobileBackgroundSettings(
      androidEnabled: json['androidEnabled'] == true,
      iosEnabled: json['iosEnabled'] == true,
      notificationsEnabled: json['notificationsEnabled'] == true,
      privacyMode: json['privacyMode'] == true,
      overlayEnabled: json['overlayEnabled'] == true,
      liveUpdatesEnabled: json['liveUpdatesEnabled'] == true,
      liveActivitiesEnabled: json['liveActivitiesEnabled'] == true,
      locationEnabled: json['locationEnabled'] == true,
      silentAudioEnabled: json['silentAudioEnabled'] == true,
      backgroundSpeechEnabled: json['backgroundSpeechEnabled'] == true,
      completionVisibility: visibility,
      // 缺键/脏值 → 新默认 'fish'（大肥鱼圆形）；显式存过的 'app'/'image'/
      // 'emoji' 原样保留（老用户的选择不被默认值改写）。
      overlayIconKind:
          kind == 'image' || kind == 'emoji' || kind == 'fish' || kind == 'app'
          ? kind!
          : 'fish',
      overlayIconValue: json['overlayIconValue'] as String? ?? '',
      overlayAppearance: BackgroundOverlayAppearance.fromJson(
        (json['overlayAppearance'] as Map?)?.cast<String, dynamic>() ??
            const {},
      ),
    );
  }

  Map<String, dynamic> toJson() => {
    'androidEnabled': androidEnabled,
    'iosEnabled': iosEnabled,
    'notificationsEnabled': notificationsEnabled,
    'privacyMode': privacyMode,
    'overlayEnabled': overlayEnabled,
    'liveUpdatesEnabled': liveUpdatesEnabled,
    'liveActivitiesEnabled': liveActivitiesEnabled,
    'locationEnabled': locationEnabled,
    'silentAudioEnabled': silentAudioEnabled,
    'backgroundSpeechEnabled': backgroundSpeechEnabled,
    'completionVisibility': completionVisibility.name,
    'overlayIconKind': overlayIconKind,
    'overlayIconValue': overlayIconValue,
    'overlayAppearance': overlayAppearance.toJson(),
  };

  MobileBackgroundSettings copyWith({
    bool? androidEnabled,
    bool? iosEnabled,
    bool? notificationsEnabled,
    bool? privacyMode,
    bool? overlayEnabled,
    bool? liveUpdatesEnabled,
    bool? liveActivitiesEnabled,
    bool? locationEnabled,
    bool? silentAudioEnabled,
    bool? backgroundSpeechEnabled,
    BackgroundCompletionVisibility? completionVisibility,
    String? overlayIconKind,
    String? overlayIconValue,
    BackgroundOverlayAppearance? overlayAppearance,
  }) => MobileBackgroundSettings(
    androidEnabled: androidEnabled ?? this.androidEnabled,
    iosEnabled: iosEnabled ?? this.iosEnabled,
    notificationsEnabled: notificationsEnabled ?? this.notificationsEnabled,
    privacyMode: privacyMode ?? this.privacyMode,
    overlayEnabled: overlayEnabled ?? this.overlayEnabled,
    liveUpdatesEnabled: liveUpdatesEnabled ?? this.liveUpdatesEnabled,
    liveActivitiesEnabled: liveActivitiesEnabled ?? this.liveActivitiesEnabled,
    locationEnabled: locationEnabled ?? this.locationEnabled,
    silentAudioEnabled: silentAudioEnabled ?? this.silentAudioEnabled,
    backgroundSpeechEnabled:
        backgroundSpeechEnabled ?? this.backgroundSpeechEnabled,
    completionVisibility: completionVisibility ?? this.completionVisibility,
    overlayIconKind: overlayIconKind ?? this.overlayIconKind,
    overlayIconValue: overlayIconValue ?? this.overlayIconValue,
    overlayAppearance: overlayAppearance ?? this.overlayAppearance,
  );
}

/// Sizes are logical pixels (Android dp). Display options never enable the
/// overlay or request permissions. Native rendering enforces the same bounds.
class BackgroundOverlayAppearance {
  const BackgroundOverlayAppearance({
    this.width = 290,
    this.height = 84,
    this.cornerRadius = 24,
    this.iconSize = 34,
    this.progressSize = 42,
    this.progressStrokeWidth = 2,
    this.showProgress = true,
    this.showTitle = true,
    this.showSubtitle = true,
    this.showTime = true,
    this.showClose = true,
    this.showBackground = true,
    this.showBorder = false,
    this.snapToEdge = true,
    this.showInApp = false,
  });

  static const circle = BackgroundOverlayAppearance(
    width: 64,
    height: 64,
    cornerRadius: 32,
    iconSize: 48,
    progressSize: 60,
    showTitle: false,
    showSubtitle: false,
    showTime: false,
    showClose: false,
    showBackground: false,
  );

  final double width;
  final double height;
  final double cornerRadius;
  final double iconSize;
  final double progressSize;
  final double progressStrokeWidth;
  final bool showProgress;
  final bool showTitle;
  final bool showSubtitle;
  final bool showTime;
  final bool showClose;
  final bool showBackground;
  final bool showBorder;

  /// 空闲三秒后自动贴到最近的屏幕左/右边（桌宠行为）。原生侧默认开启，
  /// 只有显式写成 false 才关闭，避免旧配置升级后行为不一致。
  final bool snapToEdge;

  /// 应用内也显示自研保活小标记：默认只在退到后台时出现。
  final bool showInApp;

  bool get hasText => showTitle || showSubtitle || showTime;
  bool get isIconOnly => !hasText && !showClose;
  double get badgeSize =>
      showProgress && progressSize > iconSize ? progressSize : iconSize;

  factory BackgroundOverlayAppearance.fromJson(Map<String, dynamic> json) {
    double size(String key, double fallback, double min, double max) {
      final value = json[key];
      return value is num && value.isFinite
          ? value.toDouble().clamp(min, max)
          : fallback;
    }

    return BackgroundOverlayAppearance(
      width: size('width', 290, 48, 400),
      height: size('height', 84, 48, 180),
      cornerRadius: size('cornerRadius', 24, 0, 90),
      iconSize: size('iconSize', 34, 16, 120),
      progressSize: size('progressSize', 42, 20, 140),
      progressStrokeWidth: size('progressStrokeWidth', 2, 1, 12),
      showProgress: json['showProgress'] != false,
      showTitle: json['showTitle'] != false,
      showSubtitle: json['showSubtitle'] != false,
      showTime: json['showTime'] != false,
      showClose: json['showClose'] != false,
      showBackground: json['showBackground'] != false,
      showBorder: json['showBorder'] == true,
      snapToEdge: json['snapToEdge'] != false,
      showInApp: json['showInApp'] == true,
    );
  }

  Map<String, dynamic> toJson() => {
    'width': width,
    'height': height,
    'cornerRadius': cornerRadius,
    'iconSize': iconSize,
    'progressSize': progressSize,
    'progressStrokeWidth': progressStrokeWidth,
    'showProgress': showProgress,
    'showTitle': showTitle,
    'showSubtitle': showSubtitle,
    'showTime': showTime,
    'showClose': showClose,
    'showBackground': showBackground,
    'showBorder': showBorder,
    'snapToEdge': snapToEdge,
    'showInApp': showInApp,
  };

  BackgroundOverlayAppearance copyWith({
    double? width,
    double? height,
    double? cornerRadius,
    double? iconSize,
    double? progressSize,
    double? progressStrokeWidth,
    bool? showProgress,
    bool? showTitle,
    bool? showSubtitle,
    bool? showTime,
    bool? showClose,
    bool? showBackground,
    bool? showBorder,
    bool? snapToEdge,
    bool? showInApp,
  }) => BackgroundOverlayAppearance.fromJson({
    ...toJson(),
    'width': width ?? this.width,
    'height': height ?? this.height,
    'cornerRadius': cornerRadius ?? this.cornerRadius,
    'iconSize': iconSize ?? this.iconSize,
    'progressSize': progressSize ?? this.progressSize,
    'progressStrokeWidth': progressStrokeWidth ?? this.progressStrokeWidth,
    'showProgress': showProgress ?? this.showProgress,
    'showTitle': showTitle ?? this.showTitle,
    'showSubtitle': showSubtitle ?? this.showSubtitle,
    'showTime': showTime ?? this.showTime,
    'showClose': showClose ?? this.showClose,
    'showBackground': showBackground ?? this.showBackground,
    'showBorder': showBorder ?? this.showBorder,
    'snapToEdge': snapToEdge ?? this.snapToEdge,
    'showInApp': showInApp ?? this.showInApp,
  });
}

/// 大肥鱼动画素材（源：QCYTSN/dsh-dafeiyu，MIT）的取值口径。
///
/// 帧文件与 manifest.json 是原生播放器（Kotlin PetAssets）与设置页预览
/// 共用的跨语言契约：清单里的 frames 是相对 assets/pet/ 的路径，改名要
/// 两边同步。这里只列悬浮窗真正会用到的动作。
class OverlayPetClips {
  const OverlayPetClips._();

  static const String manifest = 'assets/pet/manifest.json';

  /// 基础状态：待机 / 思考 / 成功 / 失败，按任务状态自动切。
  static const List<String> states = [
    'idle',
    'thinking',
    'success',
    'error',
  ];

  /// 一次性反应：拖动中 / 松手 / 被戳 / 待机偷吃。
  static const List<String> reactions = [
    'dragging',
    'dragging_release',
    'poke',
    'eat_token',
  ];

  static const String idle = 'idle';
}

enum BackgroundCompletionVisibility {
  immediate,
  oneMinute,
  fiveMinutes,
  untilForeground;

  int get seconds => switch (this) {
    immediate => 0,
    oneMinute => 60,
    fiveMinutes => 300,
    untilForeground => 900,
  };
}
