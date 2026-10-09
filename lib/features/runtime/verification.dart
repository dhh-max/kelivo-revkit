/// 验证器（§15）：工程验证与行为验证必须分开报告。
///
/// 核心约束（§15.4）：
/// ```
/// Build passed ≠ Task goal verified
/// ```
/// 所以这里把检查分成两类，**不允许**用工程检查去支撑「用户目标已达成」：
/// - 工程验证：由系统确定性完成（文件在不在、包能不能解析、签名对不对、能不能装）；
/// - 行为验证：目标行为是否真的变了——做不到就如实写 NOT VERIFIED。
library;

import 'dart:convert';
import 'dart:io';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';

import '../solab_apk/services/apk_toolchain_service.dart';

/// 检查分类（§15.1 / §15.2）。
enum CheckCategory {
  engineering('engineering', '工程验证'),
  behavior('behavior', '行为验证');

  const CheckCategory(this.id, this.label);
  final String id;
  final String label;
}

/// 单项检查结果。
enum CheckStatus {
  passed('pass', '通过'),
  failed('fail', '失败'),
  notVerified('not_verified', 'NOT VERIFIED');

  const CheckStatus(this.id, this.label);
  final String id;
  final String label;
}

class VerificationCheck {
  final String name;
  final CheckCategory category;
  final CheckStatus status;
  final String detail;

  const VerificationCheck({
    required this.name,
    required this.category,
    required this.status,
    this.detail = '',
  });

  Map<String, Object?> toJson() => {
        'name': name,
        'category': category.id,
        'status': status.id,
        'detail': detail,
      };

  static VerificationCheck fromJson(Object? raw) {
    if (raw is! Map) {
      return const VerificationCheck(
        name: '',
        category: CheckCategory.engineering,
        status: CheckStatus.notVerified,
      );
    }
    return VerificationCheck(
      name: raw['name']?.toString() ?? '',
      category: CheckCategory.values.firstWhere(
        (c) => c.id == raw['category']?.toString(),
        orElse: () => CheckCategory.engineering,
      ),
      status: CheckStatus.values.firstWhere(
        (c) => c.id == raw['status']?.toString(),
        orElse: () => CheckStatus.notVerified,
      ),
      detail: raw['detail']?.toString() ?? '',
    );
  }
}

/// 一次验证的结果（§15.3）。
class VerificationResult {
  final String taskId;
  final List<VerificationCheck> checks;
  final int createdAt;

  /// 被验证的产物路径。
  final String artifactPath;

  const VerificationResult({
    required this.taskId,
    this.checks = const [],
    this.createdAt = 0,
    this.artifactPath = '',
  });

  List<VerificationCheck> get engineering =>
      checks.where((c) => c.category == CheckCategory.engineering).toList();

  List<VerificationCheck> get behavior =>
      checks.where((c) => c.category == CheckCategory.behavior).toList();

  List<String> get notVerified =>
      [for (final c in checks) if (c.status == CheckStatus.notVerified) c.name];

  /// 某一类的总体结论：有失败即 FAIL，有未验证即 NOT VERIFIED，否则 PASS。
  static CheckStatus overallOf(Iterable<VerificationCheck> items) {
    final list = items.toList();
    if (list.isEmpty) return CheckStatus.notVerified;
    if (list.any((c) => c.status == CheckStatus.failed)) return CheckStatus.failed;
    if (list.any((c) => c.status == CheckStatus.notVerified)) {
      return CheckStatus.notVerified;
    }
    return CheckStatus.passed;
  }

  CheckStatus get engineeringStatus => overallOf(engineering);
  CheckStatus get behaviorStatus => overallOf(behavior);

  /// 人类可读的两行结论（§15.4 报告格式）。
  String get summaryLine =>
      'Engineering: ${engineeringStatus.label}\n'
      'Behavior: ${behaviorStatus.label}';

  Map<String, Object?> toJson() => {
        'taskId': taskId,
        'artifactPath': artifactPath,
        'checks': [for (final c in checks) c.toJson()],
        'engineering': engineeringStatus.id,
        'behavior': behaviorStatus.id,
        'notVerified': notVerified,
        'createdAt': createdAt,
      };

  static VerificationResult fromJson(Object? raw) {
    if (raw is! Map) {
      return const VerificationResult(taskId: '');
    }
    return VerificationResult(
      taskId: raw['taskId']?.toString() ?? '',
      artifactPath: raw['artifactPath']?.toString() ?? '',
      checks: [
        for (final c in (raw['checks'] as List? ?? const []))
          VerificationCheck.fromJson(c)
      ],
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
    );
  }
}

/// 验证器依赖的外部探测能力。
///
/// 抽成接口的原因：工程验证里的「签名是否有效 / 能不能装」必须调用原生工具链，
/// 在单元测试里跑不了。运行期用 [PlatformApkProbe]，测试注入假实现。
abstract class ApkProbe {
  /// 签名是否有效。返回 null 表示**无法判定**（不是失败）。
  Future<bool?> signatureValid(String apkPath);

  /// 是否可安装。返回 null 表示无法判定。
  Future<bool?> installable(String apkPath);
}

/// 运行期实现：签名交给平台 apksig（`apk_archive(action=certificates)`，
/// 与内置 apk_sign、分析报告用的是同一条验签链路），装机只做静态判定。
///
/// 刻意不在这里做真实安装：安装是高风险操作，需要用户确认（§18.3）。
/// 平台不可用时（桌面端、单元测试）一律返回 null，由上层如实记
/// NOT VERIFIED——绝不用「构建成功」或「没报错」冒充验证通过。
class PlatformApkProbe implements ApkProbe {
  const PlatformApkProbe();

  @override
  Future<bool?> signatureValid(String apkPath) async {
    final data = await _certificates(apkPath);
    final verified = data?['verified'];
    return verified is bool ? verified : null;
  }

  @override
  Future<bool?> installable(String apkPath) async {
    // 静态判定（不做真实安装）：Android 拒绝安装包结构不可解析或签名无效的
    // APK；平台验签返回 verified 意味着 apksig 已解析 ZIP 中央目录与 v1/v2/v3
    // 签名块并全部通过，即「可解析 + 签名有效」两项安装前置条件同时成立。
    // 真机安装结果仍以用户确认（record_apk_patch_verification）为准。
    final data = await _certificates(apkPath);
    if (data == null) return null;
    final verified = data['verified'];
    return verified is bool ? verified : null;
  }

  /// 平台验签原始结果；平台不可用或文件不可读时返回 null（= 无法判定）。
  Future<Map<Object?, Object?>?> _certificates(String apkPath) async {
    if (apkPath.isEmpty) return null;
    try {
      final result = await ApkToolchainService.apkArchive(
        path: apkPath,
        action: 'certificates',
      );
      if (!result.ok) return null;
      return result.data;
    } catch (_) {
      // invokeApkChannel 已把 PlatformException 归一为 ok=false；这里兜住
      // MissingPluginException（测试/桌面）等通道缺失，按「无法判定」处理。
      return null;
    }
  }
}

/// 验证器。
class Verifier {
  Verifier({ApkProbe? probe}) : probe = probe ?? const PlatformApkProbe();

  final ApkProbe probe;

  /// 工程验证（§15.1）：全部是确定性检查，不调模型。
  ///
  /// [expectSha256] 非空时校验产物哈希与预期一致。
  Future<VerificationResult> verifyEngineering({
    required String taskId,
    required String apkPath,
    String? expectSha256,
    int now = 0,
  }) async {
    final checks = <VerificationCheck>[];
    final file = File(apkPath);

    // 1) 产物存在
    final exists = await file.exists();
    checks.add(VerificationCheck(
      name: 'artifact_exists',
      category: CheckCategory.engineering,
      status: exists ? CheckStatus.passed : CheckStatus.failed,
      detail: exists ? apkPath : '文件不存在：$apkPath',
    ));
    if (!exists) {
      return VerificationResult(
        taskId: taskId,
        checks: checks,
        createdAt: now,
        artifactPath: apkPath,
      );
    }

    final bytes = await file.readAsBytes();

    // 2) 是合法 ZIP 且含 AndroidManifest.xml（APK 能否解析）
    var manifestOk = false;
    var dexCount = 0;
    String parseDetail = '';
    try {
      final archive = ZipDecoder().decodeBytes(bytes, verify: false);
      manifestOk = archive.files
          .any((f) => f.isFile && f.name == 'AndroidManifest.xml');
      dexCount = archive.files
          .where((f) => f.isFile && RegExp(r'^classes\d*\.dex$').hasMatch(f.name))
          .length;
      parseDetail = manifestOk
          ? '解析正常，含 $dexCount 个 dex'
          : '压缩包可读，但缺少 AndroidManifest.xml';
    } catch (e) {
      parseDetail = '无法作为 APK 解析：$e';
    }
    checks.add(VerificationCheck(
      name: 'apk_parseable',
      category: CheckCategory.engineering,
      status: manifestOk ? CheckStatus.passed : CheckStatus.failed,
      detail: parseDetail,
    ));

    // 3) SHA-256（总是算出来放进报告，便于交付核对，§15.5）
    final sha = sha256.convert(bytes).toString();
    if (expectSha256 != null && expectSha256.isNotEmpty) {
      checks.add(VerificationCheck(
        name: 'sha256_matches',
        category: CheckCategory.engineering,
        status:
            sha == expectSha256 ? CheckStatus.passed : CheckStatus.failed,
        detail: '实际 $sha / 预期 $expectSha256',
      ));
    }

    // 4) 签名（原生探测；判定不了就如实 NOT VERIFIED）
    final sig = await probe.signatureValid(apkPath);
    checks.add(VerificationCheck(
      name: 'signature_valid',
      category: CheckCategory.engineering,
      status: sig == null
          ? CheckStatus.notVerified
          : (sig ? CheckStatus.passed : CheckStatus.failed),
      detail: sig == null ? '未接入签名校验，无法判定' : (sig ? '签名有效' : '签名无效'),
    ));

    // 5) 可安装性（静态判定 + 原生探测）
    final install = await probe.installable(apkPath);
    checks.add(VerificationCheck(
      name: 'installable',
      category: CheckCategory.engineering,
      status: install == null
          ? CheckStatus.notVerified
          : (install ? CheckStatus.passed : CheckStatus.failed),
      detail: install == null ? '未做真实安装，无法判定' : (install ? '可安装' : '不可安装'),
    ));

    return VerificationResult(
      taskId: taskId,
      checks: checks,
      createdAt: now,
      artifactPath: apkPath,
    );
  }

  /// 行为验证（§15.2）。
  ///
  /// 系统**无法**自行证明用户目标达成——这需要运行 App 看行为。所以这里
  /// 只接收调用方提供的观察结果；没提供就一律 NOT VERIFIED，绝不用
  /// 「构建成功」顶替（§15.4）。
  VerificationResult behavior({
    required String taskId,
    required String artifactPath,
    List<VerificationCheck> observed = const [],
    int now = 0,
  }) {
    final checks = observed.isEmpty
        ? [
            const VerificationCheck(
              name: 'target_behavior_rechecked',
              category: CheckCategory.behavior,
              status: CheckStatus.notVerified,
              detail: '未做运行时行为验证（需装上设备实际观察）',
            ),
          ]
        : observed
            .map((c) => VerificationCheck(
                  name: c.name,
                  category: CheckCategory.behavior,
                  status: c.status,
                  detail: c.detail,
                ))
            .toList();
    return VerificationResult(
      taskId: taskId,
      checks: checks,
      createdAt: now,
      artifactPath: artifactPath,
    );
  }

  /// 合并工程验证与行为验证成一份报告（§15.3 result 的展开形式）。
  static VerificationResult merge(
    String taskId,
    String artifactPath,
    Iterable<VerificationResult> parts, {
    int now = 0,
  }) {
    final checks = <VerificationCheck>[];
    for (final p in parts) {
      checks.addAll(p.checks);
    }
    return VerificationResult(
      taskId: taskId,
      checks: checks,
      createdAt: now,
      artifactPath: artifactPath,
    );
  }
}

/// 交付报告（§15.5 / §15.6）。
class DeliveryReport {
  final String taskId;
  final String goal;
  final String sourceApk;
  final String sourceSha256;

  /// 改了什么（从 Patch Plan 事件抽取）。
  final List<Map<String, Object?>> patches;

  /// 关键证据引用。
  final List<String> evidenceRefs;

  final VerificationResult verification;

  /// 交付物（名称/路径/大小/哈希）。
  final List<Map<String, Object?>> artifacts;

  /// 未验证项（同时来自验证结果与调用方补充）。
  final List<String> unverified;

  /// 风险提示。
  final List<String> risks;

  /// 清理摘要。
  final Map<String, Object?> cleanup;

  final int createdAt;

  const DeliveryReport({
    required this.taskId,
    required this.goal,
    required this.sourceApk,
    this.sourceSha256 = '',
    this.patches = const [],
    this.evidenceRefs = const [],
    required this.verification,
    this.artifacts = const [],
    this.unverified = const [],
    this.risks = const [],
    this.cleanup = const {},
    this.createdAt = 0,
  });

  Map<String, Object?> toJson() => {
        'taskId': taskId,
        'goal': goal,
        'sourceApk': sourceApk,
        'sourceSha256': sourceSha256,
        'patches': patches,
        'evidenceRefs': evidenceRefs,
        'engineering': verification.engineeringStatus.id,
        'behavior': verification.behaviorStatus.id,
        'checks': [for (final c in verification.checks) c.toJson()],
        'artifacts': artifacts,
        'unverified': unverified,
        'risks': risks,
        'cleanup': cleanup,
        'createdAt': createdAt,
      };

  /// 给用户看的两行结论。
  String get summaryLine => verification.summaryLine;

  static DeliveryReport fromJson(Object? raw) {
    if (raw is! Map) {
      return const DeliveryReport(
        taskId: '',
        goal: '',
        sourceApk: '',
        verification: VerificationResult(taskId: ''),
      );
    }
    return DeliveryReport(
      taskId: raw['taskId']?.toString() ?? '',
      goal: raw['goal']?.toString() ?? '',
      sourceApk: raw['sourceApk']?.toString() ?? '',
      sourceSha256: raw['sourceSha256']?.toString() ?? '',
      patches: [
        for (final p in (raw['patches'] as List? ?? const []))
          if (p is Map) Map<String, Object?>.from(p)
      ],
      evidenceRefs: [
        for (final e in (raw['evidenceRefs'] as List? ?? const [])) e.toString()
      ],
      verification: VerificationResult.fromJson(raw),
      artifacts: [
        for (final a in (raw['artifacts'] as List? ?? const []))
          if (a is Map) Map<String, Object?>.from(a)
      ],
      unverified: [
        for (final u in (raw['unverified'] as List? ?? const [])) u.toString()
      ],
      risks: [
        for (final r in (raw['risks'] as List? ?? const [])) r.toString()
      ],
      cleanup: raw['cleanup'] is Map
          ? Map<String, Object?>.from(raw['cleanup'] as Map)
          : const {},
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
    );
  }

  String toPrettyJson() => const JsonEncoder.withIndent('  ').convert(toJson());
}
