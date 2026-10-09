import 'local_tool_names.dart';
import 'local_tool_registry.dart';

/// 本地工具的能力域。
///
/// 域是**给助手配工具用的推荐集合**，不是权限闸门：某个助手到底能调什么，
/// 仍由它的 `localToolIds` 决定（可在「助手设置 → 本地工具」里逐项开关）。
///
/// 分域解决两个实际问题：
/// - **通用层**：文件、待办、子代理、编排、自省、计算这些与业务域无关的原语，
///   任何助手（包括用户自建助手）都值得开；
/// - **领域层**：APK 逆向/改包工具只在逆向助手有意义，设备类工具在需要时才开，
///   避免每个助手都被塞进几十个用不上的工具（既占上下文又增加误调）。
enum LocalToolDomain {
  /// 通用原语：与具体业务无关。
  general,

  /// 设备/个人数据：日历、提醒、健康、天气、位置、剪贴板、TTS、手机控制。
  device,

  /// APK 逆向与改包：侦察、定位、修改、签名、验证与产物链。
  apkReverse,
}

abstract final class LocalToolDomains {
  /// 逆向域（显式列举：这些工具离开 APK 任务没有意义）。
  static const Set<String> apkReverseTools = <String>{
    LocalToolNames.apkReport,
    LocalToolNames.apkKnowledge,
    LocalToolNames.apkProjectInfo,
    LocalToolNames.apkRules,
    LocalToolNames.apkPatchDex,
    LocalToolNames.apkPatchDexStrings,
    LocalToolNames.apkSignatureBypass,
    LocalToolNames.apkPatchManifest,
    LocalToolNames.apkPatchMemory,
    LocalToolNames.apkSavePatchMemory,
    LocalToolNames.apkRecordPatchVerification,
    LocalToolNames.apkListBuilds,
    LocalToolNames.apkCleanupBuilds,
    LocalToolNames.apkNoteRead,
    LocalToolNames.apkNoteWrite,
    LocalToolNames.apkListWorkspace,
    LocalToolNames.apkAnalyzeWorkspace,
    LocalToolNames.apkArchive,
    LocalToolNames.apkExportReport,
    LocalToolNames.apkSign,
    LocalToolNames.apkRebuild,
    LocalToolNames.runTaskCommand,
    LocalToolNames.jadxDecompile,
    LocalToolNames.dexSearch,
    LocalToolNames.stringScan,
    LocalToolNames.dexXref,
    LocalToolNames.classOutline,
    LocalToolNames.smaliRead,
    LocalToolNames.soAnalyze,
    LocalToolNames.soPatchIntoApk,
    LocalToolNames.frida,
  };

  /// 走设备 schema 模块（`DeviceLocalToolSchemas`）解析的设备工具：
  /// 这些名字必须能被模块认识，否则就是挂不上的假工具（有用例守着）。
  static const Set<String> deviceSchemaTools = <String>{
    LocalToolNames.calendarQuery,
    LocalToolNames.calendarCreate,
    LocalToolNames.remindersQuery,
    LocalToolNames.remindersCreate,
    LocalToolNames.remindersComplete,
    LocalToolNames.healthSummary,
    LocalToolNames.weather,
    LocalToolNames.currentLocation,
    LocalToolNames.screenTime,
    LocalToolNames.phoneControl,
  };

  /// 设备/个人数据域：设备 schema 工具 + 由其它通道解析的设备原语
  /// （剪贴板、TTS 走平台通道，不经过设备 schema 模块）。
  static const Set<String> deviceTools = <String>{
    ...deviceSchemaTools,
    LocalToolNames.clipboard,
    LocalToolNames.textToSpeech,
  };

  /// 全部本地工具 = 注册表里的工具 + 设备域显式列出的设备工具。
  ///
  /// 设备工具由 features 层的 `DeviceLocalToolSchemas` 按名解析（那是 part 文件，
  /// core 不能反向依赖），所以这里显式并入 [deviceTools]；这些名字是否真实存在
  /// 由 `local_tool_domains_test.dart` 用 features 层 API 校验。
  static List<String> get all {
    final names = <String>{
      ...LocalToolRegistry.specs.map((spec) => spec.name),
      ...deviceTools,
    };
    return names.toList(growable: false);
  }

  static List<String> toolsOf(LocalToolDomain domain) => switch (domain) {
    LocalToolDomain.apkReverse => all
        .where(apkReverseTools.contains)
        .toList(growable: false),
    LocalToolDomain.device => all
        .where(deviceTools.contains)
        .toList(growable: false),
    LocalToolDomain.general => all
        .where(
          (name) =>
              !apkReverseTools.contains(name) && !deviceTools.contains(name),
        )
        .toList(growable: false),
  };

  static LocalToolDomain of(String toolId) {
    if (apkReverseTools.contains(toolId)) return LocalToolDomain.apkReverse;
    if (deviceTools.contains(toolId)) return LocalToolDomain.device;
    return LocalToolDomain.general;
  }

  /// 某个助手默认值得开的一揽子工具：
  /// 通用层 +（逆向助手才加）逆向域 +（需要时）设备域。
  static List<String> recommendedFor({
    required bool includeApkReverse,
    bool includeDevice = false,
  }) => <String>[
    ...toolsOf(LocalToolDomain.general),
    if (includeApkReverse) ...toolsOf(LocalToolDomain.apkReverse),
    if (includeDevice) ...toolsOf(LocalToolDomain.device),
  ];
}
