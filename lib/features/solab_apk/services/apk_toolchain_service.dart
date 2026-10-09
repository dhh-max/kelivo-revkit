import 'package:flutter/services.dart';
import '../../../core/services/apk_channel_invoke.dart';
import '../../../core/services/logging/flutter_logger.dart';
import 'apk_structural_service.dart';

/// 静态分析/SO 引擎工具链的 MethodChannel 封装。
///
/// 对应 Kotlin 侧 SolabChannel 的当前工具入口。
///
/// 信封契约：{ok:true,...} / {ok:false, error:{code,message}, message}；
/// 错误解析复用 [ApkStructuralResult]（含结构化 error 解析）。
class ApkToolchainService {
  const ApkToolchainService._();

  static const _channel = MethodChannel('solab/workspace');

  static Future<ApkStructuralResult> _invoke(
    String method,
    Map<String, Object?> arguments,
  ) {
    return invokeApkChannel(_channel, method, arguments);
  }

  /// 签名校验点扫描（DPatch 去签前的风险判定）。
  static Future<ApkStructuralResult> scanSignatureCheck({
    required String path,
  }) {
    return _invoke('scanSignatureCheck', {'path': path});
  }

  /// FieldRefs 模式（自适应三态，2026-09-02）：
  /// auto（默认）= 自适应：冷启动扫描开工，同一 APK 字段查询重复 ≥2 次后台
  ///   自动建索引，建好后自动切索引查询——无需用户手动区分；
  /// on = 始终预建索引（原方案 A）；off = 始终扫描（原方案 B）。
  /// [mode] 缺省 = 查询当前模式；传值 = 切换并持久化（native SP）。
  /// 返回 data['mode'] 为切换/查询后的生效模式。
  /// 同步 [fieldRefsModeKey]（Dart 侧模式镜像，供 analyzer 缓存键分模）。
  static Future<ApkStructuralResult> fieldRefsIndexMode({String? mode}) {
    return _invoke('fieldRefsIndexMode', {
      if (mode != null) 'mode': mode,
    }).then((r) {
      final data = r.data;
      if (r.ok && data != null && data['mode'] is String) {
        _lastKnownFieldRefsMode = data['mode'] as String;
      }
      return r;
    });
  }

  /// FieldRefs 模式 Dart 侧镜像（B-1 修复）：切模式后 analyzer 网关缓存键
  /// 随之变化，避免命中旧模式缓存导致测量失真。
  static String? _lastKnownFieldRefsMode;

  /// 语义索引是否跳过数据性/生成代码子树（B2-3，默认关闭）。
  ///
  /// 打开后 blutter 语义索引不再为 `/l10n/`、`highlighter/languages/`、`/intl/messages`、
  /// `/generated/` 命中的 asm 文件建行（体积与构建耗时的大头），代价是这些子树在语义
  /// 检索里搜不到——需要时用 `search scope=asm fullScan=true` 扫原文；搜索响应会带
  /// `skipNoisyPaths`/`skippedNoisyFiles` 自报。
  /// [enabled] 缺省 = 查询当前值；传值 = 切换并持久化（native SP），并让旧索引判定为
  /// 未就绪、按新口径重建。返回 data['enabled'] 为切换/查询后的生效值。
  static Future<ApkStructuralResult> semanticIndexSkipNoisyPaths({bool? enabled}) {
    return _invoke('semanticIndexSkipNoisyPaths', {
      if (enabled != null) 'enabled': enabled,
    });
  }

  /// 缓存键前缀：on→idx、off→scan、auto→auto（auto 下扫描/索引结果等价，
  /// 共享缓存无害；切显式模式时前缀变化自动隔离旧缓存）。
  static String get fieldRefsModeKey => switch (_lastKnownFieldRefsMode) {
    'on' => 'idx',
    'off' => 'scan',
    _ => 'auto',
  };

  /// R9 自动验收（蓝图 Week 3~4）：PackageInstaller 会话安装。
  /// PENDING_USER_ACTION 拉起系统确认页（用户人工确认）；终端状态或 5 分钟
  /// 超时才返回。data['installStatus'] ∈ SUCCESS / BLOCKED / CONFLICT /
  /// INVALID / STORAGE / INCOMPATIBLE / ABORTED / TIMEOUT / SESSION_ERROR /
  /// APK_NOT_FOUND；失败带 data['failureReason']（机器可读，蓝图 §5.4）。
  /// install SUCCESS = 系统验签通过 = Verified 的设备侧证据。
  static Future<ApkStructuralResult> installApk({required String path}) {
    return _invoke('installApk', {'path': path});
  }

  /// A1: jadx DEX→Java 反编译。action ∈ {save, class, list}。
  static Future<ApkStructuralResult> jadxDecompile({
    required String path,
    String action = 'save',
    String? className,
    String? dexName,
    int? limit,
    int? offset,
    String? workDir,
    bool allowOversize = false,
  }) {
    return _invoke('jadxDecompile', {
      'path': path,
      'action': action,
      if (className != null && className.isNotEmpty) 'className': className,
      if (dexName != null && dexName.isNotEmpty) 'dexName': dexName,
      if (limit != null) 'limit': limit,
      if (offset != null) 'offset': offset,
      if (workDir != null && workDir.isNotEmpty) 'workDir': workDir,
      // INPUT_TOO_LARGE 后的显式放行位（Kotlin checkInputBudget 消费）。
      if (allowOversize) 'allowOversize': true,
    });
  }

  /// Frida gadget（宿主侧）：status / install_gadget / inject。
  ///
  /// 越权面：只传统一工作目录 + 纯文件名（Kotlin 侧拒绝含 `..`/分隔符的名字）。
  /// 运行期动作（open/hook/call/read/backtrace/close）走沙盒，未装环境时报不可用。
  static Future<ApkStructuralResult> frida({
    required String action,
    String? workDir,
    String? apkName,
    /// install_gadget 的候选下载源（按序尝试；sha256 仍在 Kotlin 侧校验）。
    List<String>? sources,
    /// install_gadget 的本地文件兜底（GitHub 不可达时用户手动放好的 .xz）。
    String? localPath,
  }) {
    return _invoke('fridaGadget', {
      'action': action,
      if (workDir != null && workDir.isNotEmpty) 'workDir': workDir,
      if (apkName != null && apkName.isNotEmpty) 'apkName': apkName,
      if (sources != null && sources.isNotEmpty) 'sources': sources,
      if (localPath != null && localPath.isNotEmpty) 'localPath': localPath,
    });
  }

  /// A4: APK v1/v2/v3 签名（内置自签名密钥，首次自动生成）。
  static Future<ApkStructuralResult> apkSign({
    required String inputApk,
    String? outputApk,
    int? minSdk,
  }) {
    return _invoke('apkSign', {
      'inputApk': inputApk,
      if (outputApk != null && outputApk.isNotEmpty) 'outputApk': outputApk,
      if (minSdk != null) 'minSdk': minSdk,
    });
  }

  /// T1: 列出 APK 内 `lib/<abi>/*.so` 条目（so_patch_into_apk 自动定位回填目标）。
  static Future<ApkStructuralResult> listLibEntries({required String path}) {
    return _invoke('listLibEntries', {'path': path});
  }

  /// A6: APKEditor 完整回编/合并/去混淆。action ∈ {decode, build, merge, refactor}。
  static Future<ApkStructuralResult> apkRebuild({
    required String path,
    String action = 'decode',
    String? output,
    String? type,
    bool? dex,
    bool? force,
    bool? cleanMeta,
    bool? fixTypeNames,
    bool? allowOversize,
    String? workDir,
  }) {
    return _invoke('apkRebuild', {
      'path': path,
      'action': action,
      if (output != null && output.isNotEmpty) 'output': output,
      if (type != null && type.isNotEmpty) 'type': type,
      if (dex != null) 'dex': dex,
      if (force != null) 'force': force,
      if (cleanMeta != null) 'cleanMeta': cleanMeta,
      if (fixTypeNames != null) 'fixTypeNames': fixTypeNames,
      // INPUT_TOO_LARGE 后的显式放行位（2026-09-15 用户基线 L5）：
      // OOM 风险自担的一次性覆盖，Kotlin 侧 checkInputBudget 消费。
      if (allowOversize != null) 'allowOversize': allowOversize,
      if (workDir != null && workDir.isNotEmpty) 'workDir': workDir,
    });
  }

  /// A8: DexKit 反混淆查找。默认自动组合证据并在零命中时换路。
  static Future<ApkStructuralResult> dexSearch({
    required String path,
    String keyword = '',
    List<num>? numbers,
    String? className,
    String? methodName,
    List<String>? fieldNames,
    List<String>? invokedMethodNames,
    List<String>? opNames,
    String action = 'auto',
    String matchType = 'Contains',
    bool ignoreCase = false,
    String? packagePrefix,
    int? limit,
  }) {
    return _invoke('dexSearch', {
      'path': path,
      'keyword': keyword,
      if (numbers != null && numbers.isNotEmpty) 'numbers': numbers,
      if (className != null && className.isNotEmpty) 'className': className,
      if (methodName != null && methodName.isNotEmpty) 'methodName': methodName,
      if (fieldNames != null && fieldNames.isNotEmpty) 'fieldNames': fieldNames,
      if (invokedMethodNames != null && invokedMethodNames.isNotEmpty)
        'invokedMethodNames': invokedMethodNames,
      if (opNames != null && opNames.isNotEmpty) 'opNames': opNames,
      'action': action,
      'matchType': matchType,
      'ignoreCase': ignoreCase,
      if (packagePrefix != null && packagePrefix.isNotEmpty)
        'packagePrefix': packagePrefix,
      if (limit != null) 'limit': limit,
    });
  }

  /// A9: 敏感字符串扫描。category ∈ {all, url, ip, email, jwt, private_key,
  /// aws_ak, google_api, aliyun_ak, secret_field}；ip 默认排除本地/保留/私网地址。
  static Future<ApkStructuralResult> stringScan({
    required String path,
    String category = 'all',
    int? minLen,
    int? limit,
    bool? includePrivate,
  }) {
    return _invoke('stringScan', {
      'path': path,
      'category': category,
      if (minLen != null) 'minLen': minLen,
      if (limit != null) 'limit': limit,
      if (includePrivate != null) 'includePrivate': includePrivate,
    });
  }

  /// apk_archive 统一入口。
  ///
  /// 注意：这里逐键转发到原生，**schema 里声明过的参数必须在这里也列一份**——
  /// 漏一个键，模型传的值就到不了原生（`id` / `withReferences` 曾因此被静默吞掉：
  /// 响应里回显默认值，看起来像"参数被忽略"）。
  static Future<ApkStructuralResult> apkArchive({
    required String path,
    String action = 'list',
    String? query,
    String? entry,
    /// list 的前缀过滤（原生 FileOpsTool 支持；漏传会被静默忽略 → 返回全量条目）。
    String? entryPrefix,
    int? offset,
    int? limit,
    int? minLen,
    String? id,
    bool? withReferences,
  }) {
    return _invoke('apkArchive', {
      'path': path,
      'action': action,
      if (query != null && query.isNotEmpty) 'query': query,
      if (entry != null && entry.isNotEmpty) 'entry': entry,
      if (entryPrefix != null && entryPrefix.isNotEmpty)
        'entryPrefix': entryPrefix,
      if (offset != null) 'offset': offset,
      if (limit != null) 'limit': limit,
      if (minLen != null) 'minLen': minLen,
      if (id != null && id.isNotEmpty) 'id': id,
      if (withReferences != null) 'withReferences': withReferences,
    });
  }

  /// M2: DEX 调用处、流程图与重写实现。
  static Future<ApkStructuralResult> dexXref({
    required String path,
    required String target,
    String direction = 'to',
    String? classPrefix,
    int offset = 0,
    int? limit,
    bool includeGraph = false,
    int callSiteOffset = 0,
    int? callSiteLimit,
  }) {
    return _invoke('dexXref', {
      'path': path,
      'target': target,
      'direction': direction,
      if (classPrefix != null && classPrefix.isNotEmpty)
        'classPrefix': classPrefix,
      'offset': offset,
      'includeGraph': includeGraph,
      if (limit != null) 'limit': limit,
      'callSiteOffset': callSiteOffset,
      if (callSiteLimit != null) 'callSiteLimit': callSiteLimit,
    });
  }

  /// M2: Field XREF（字段 → 读写它的方法，跨 dex 聚合，带指令 index）。
  /// offset/limit 均缺省时一次返回全部（写入方优先）；分页场景显式传参。
  static Future<ApkStructuralResult> fieldXref({
    required String path,
    required String fieldTarget,
    int? offset,
    int? limit,
  }) {
    return _invoke('fieldXref', {
      'path': path,
      'fieldTarget': fieldTarget,
      if (offset != null) 'offset': offset,
      if (limit != null) 'limit': limit,
    });
  }

  /// M2: 类大纲（替代 outline_class）。className 支持全限定或短名子串。
  static Future<ApkStructuralResult> classOutline({
    required String path,
    required String className,
    int offset = 0,
    int? limit,
    /// 字段独立游标（2026-09-21）：过去字段恒从头取 limit 条，尾部字段读不到。
    int? fieldsOffset,
  }) {
    return _invoke('classOutline', {
      'path': path,
      'className': className,
      'offset': offset,
      if (limit != null) 'limit': limit,
      if (fieldsOffset != null) 'fieldsOffset': fieldsOffset,
    });
  }

  /// M2: smaliRead（替代 mt_apk_read_text）。按 qualifiedId 输出方法 smali。
  static Future<ApkStructuralResult> smaliRead({
    required String path,
    required String qualifiedId,
  }) {
    return _invoke('smaliRead', {'path': path, 'qualifiedId': qualifiedId});
  }

  /// M3: SO 引擎统一入口。action 覆盖 workspace/read/edit/emulate/backend/blutter 全部分域。
  static Future<ApkStructuralResult> soAnalyze(Map<String, Object?> args) {
    return _invoke('soAnalyze', args);
  }

  /// 按需下载可选引擎资源。
  /// [url] 必须 http/https 且非私有地址（引擎侧校验）；[sha256] 可选校验。
  static Future<ApkStructuralResult> assetDownload({
    required String url,
    required String name,
    String? sha256,
  }) {
    return _invoke('soAnalyze', {
      'action': 'asset_download',
      'url': url,
      'name': name,
      if (sha256 != null && sha256.isNotEmpty) 'sha256': sha256,
    });
  }

  static Future<ApkStructuralResult> assetStatus({List<String>? names}) {
    return _invoke('soAnalyze', {
      'action': 'asset_status',
      if (names != null && names.isNotEmpty) 'names': names,
    });
  }

  /// 文件管理：读写工作目录任意格式文件 / 增删改查 / 压缩解压。
  /// action ∈ {read, write, list, delete, info, zip, unzip, copy, rename, grep, replace, strings}；
  /// write/delete/zip/unzip 写操作需 dryRun→confirm（previewToken 由调用方管理）。
  static Future<ApkStructuralResult> fileOps(Map<String, Object?> args) {
    return _invoke('fileOps', args);
  }

  /// 工具耗时统计快照（C 批逐域体检与 D4 三指标读数出口）。
  ///
  /// 只读、无副作用。引擎故障与"没有统计"必须可区分（R5）：此前异常被吞成
  /// 空表，读数出口会把"引擎坏了"读成"工具都不慢"。失败一律回
  /// `available:false`，并尽量带上引擎的结构化错误码/文案；统计字段保持缺失。
  ///
  /// 原生回的是 `{ok, stats:{tools,slowestTools,totalCalls…}}` 信封，这里**剥掉外层**
  /// 只把 `stats` 交给调用方——近一层信封会让 `toolStats.tools` 这类读法全落空。
  static Future<Map<String, Object?>> toolStats() async {
    try {
      final raw = await _channel.invokeMethod<Object?>(
        'toolStats',
        <String, Object?>{},
      );
      if (raw is Map) {
        final map = raw.cast<Object?, Object?>();
        final stats = map['stats'];
        if (stats is Map) return stats.cast<String, Object?>();
        if (map['ok'] != true) return _statsUnavailable(map['error']);
        return map.cast<String, Object?>();
      }
      return _statsUnavailable(null);
    } catch (e, st) {
      FlutterLogger.log(
        '[ApkToolchain] toolStats failed: $e\n$st',
        tag: 'ApkToolchain',
      );
      return _statsUnavailable(null);
    }
  }

  /// 引擎故障/未就绪时的统计出口：显式标记不可用，绝不与空统计混淆。
  static Map<String, Object?> _statsUnavailable(Object? error) {
    final code = error is Map ? error['code'] : null;
    final message = error is Map ? error['message'] : null;
    final codeText = code == null ? '' : '$code'.trim();
    final messageText = message == null ? '' : '$message'.trim();
    return <String, Object?>{
      'available': false,
      if (codeText.isNotEmpty) 'error': codeText,
      if (messageText.isNotEmpty) 'message': messageText,
    };
  }

  /// 打断：取消当前执行中的长任务（DEX 分析 / SO 分析 / jadx 等），
  /// 引擎返回 TASK_CANCELLED 结构化错误。
  static Future<bool> cancelTask() async {
    try {
      final raw = await _channel.invokeMethod<Object?>(
        'cancelTask',
        <String, Object?>{},
      );
      return raw is Map && raw['cancelled'] == true;
    } catch (_) {
      return false;
    }
  }
}
