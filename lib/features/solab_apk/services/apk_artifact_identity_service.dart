import 'dart:async';
import 'dart:io';

import '../../../core/services/memory/memory_repository.dart';
import 'apk_patch_memory_service.dart';
import 'apk_toolchain_service.dart';
import 'apk_workspace_service.dart';

/// 一次 APK 身份判定结果（C 修复轮：已处理状态检测）。
///
/// 用户实测缺陷：工具链无法识别「该 APK 已是本工具链处理过的产物」，
/// 导致分析/签名/补丁在错误基线上工作而未告警。本类给出单一事实判定，
/// 供 signature_bypass 诊断、报告标注与 freshness 校验复用。
class ApkArtifactIdentity {
  const ApkArtifactIdentity({
    required this.apkPath,
    this.sha256,
    this.selfSignedByToolchain = false,
    this.signatureProxyInjected = false,
    this.verifiedArtifactMatches = const <Map<String, dynamic>>[],
    this.checkFailed,
  });

  final String apkPath;

  /// 流式计算的文件内容指纹（大包 1~2s，调用方按需缓存）。
  final String? sha256;

  /// 任一签名证书 = 本工具链内置证书（apk_sign 产物，不是第三方原包）。
  final bool selfSignedByToolchain;

  /// manifest 含 SignatureProxyApplication（做过 signature_bypass 注入）。
  final bool signatureProxyInjected;

  /// sha256 命中的已验证补丁记录（成品或基线，含方案与改点）。
  final List<Map<String, dynamic>> verifiedArtifactMatches;

  /// 身份检测本身失败（如 apk_archive 不可用）——不阻断调用方，但如实带出。
  final String? checkFailed;

  /// 任一证据命中 → 该文件是本工具链处理过的产物。
  bool get isProcessedArtifact =>
      selfSignedByToolchain ||
      signatureProxyInjected ||
      verifiedArtifactMatches.isNotEmpty;

  /// 机器可读身份标签：processed / original / unknown。
  String get kind {
    if (isProcessedArtifact) return 'processed';
    if (checkFailed != null) return 'unknown';
    return 'original';
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'kind': kind,
        'isProcessedArtifact': isProcessedArtifact,
        if (sha256 != null) 'sha256': sha256,
        'selfSignedByToolchain': selfSignedByToolchain,
        'signatureProxyInjected': signatureProxyInjected,
        'verifiedArtifactCount': verifiedArtifactMatches.length,
        if (verifiedArtifactMatches.isNotEmpty)
          'verifiedArtifacts': verifiedArtifactMatches
              .map((m) => <String, dynamic>{
                    'title': m['title'],
                    'operation': m['operation'],
                    if (m['solution'] != null) 'solution': m['solution'],
                  })
              .toList(),
        if (checkFailed != null) 'checkFailed': checkFailed,
      };

  /// 面向 LLM 的一句话处置指引（复用 patch memory 的既有语义：成品上叠改合法，
  /// 禁止当原包重做）。
  String get guidance {
    if (!isProcessedArtifact) {
      return '未检出本工具链处理痕迹，可按原包基线正常分析/修改。';
    }
    return '⚠️ 该文件是本工具链处理过的产物（'
        '${[
          if (selfSignedByToolchain) '内置签名',
          if (signatureProxyInjected) '签名代理注入',
          if (verifiedArtifactMatches.isNotEmpty) '已验证成品指纹',
        ].join(' + ')}）。'
        '不要把它当第三方原包做「从原包重做」类操作；正确基线：'
        '在其上叠加修改（它就是新基底），或换回真正的原始包。';
  }
}

/// APK 身份判定服务：签名指纹 + 注入痕迹 + 成品指纹三证据合一。
///
/// 证据全部来自既有设施（apk_archive certificates 的身份字段 / patch memory
/// 指纹反查 / 流式 sha256），失败降级不阻断。结果按 path+mtime+size 缓存
/// （project_info 等高频入口复用；文件被替换后缓存自动失效）。
class ApkArtifactIdentityService {
  const ApkArtifactIdentityService._();

  static final Map<String, ApkArtifactIdentity> _cache =
      <String, ApkArtifactIdentity>{};

  /// 判定 [apkPath] 的身份。`memoryRepository` 为空时跳过成品指纹反查。
  static Future<ApkArtifactIdentity> identify(
    String apkPath, {
    MemoryRepository? memoryRepository,
  }) async {
    final file = File(apkPath);
    if (!file.existsSync()) {
      return ApkArtifactIdentity(
        apkPath: apkPath,
        checkFailed: 'file_not_found',
      );
    }
    final stat = file.statSync();
    final cacheKey =
        '${file.path}|${stat.modified.millisecondsSinceEpoch}|${stat.size}';
    final cached = _cache[cacheKey];
    if (cached != null) return cached;
    final identity = await _identifyUncached(
      apkPath,
      memoryRepository: memoryRepository,
    );
    while (_cache.length >= 4) {
      _cache.remove(_cache.keys.first);
    }
    _cache[cacheKey] = identity;
    return identity;
  }

  static Future<ApkArtifactIdentity> _identifyUncached(
    String apkPath, {
    MemoryRepository? memoryRepository,
  }) async {
    final file = File(apkPath);

    // 1. 内容指纹（流式，防大包整读）。
    //
    // C2（2026-09-20 真机）：这里过去是**本服务私有的无缓存实现**，与
    // `ApkWorkspaceService.contentSha256` 各算各的——同一个大包在一次调用里
    // 被完整读两遍（freshness 校验一遍、身份检测一遍），冷进程实测这两处合计
    // 2~3.6s。改走共享实现：同一 (路径|mtime|size) 只算一次，失败语义不变
    // （算不出返回 null，与原来的 catch 置空一致）。
    final sha = await ApkWorkspaceService.contentSha256(file);

    // 2. 签名/注入痕迹（apk_archive certificates 一次拿两证据）。
    var selfSigned = false;
    var proxyInjected = false;
    String? checkFailed;
    try {
      final r = await ApkToolchainService.apkArchive(
        path: apkPath,
        action: 'certificates',
      );
      if (r.ok) {
        selfSigned = r.data?['selfSignedByToolchain'] == true;
        proxyInjected = r.data?['signatureProxyInjected'] == true;
      } else {
        checkFailed = r.error ?? r.message;
      }
    } catch (e) {
      checkFailed = '$e';
    }

    // 3. 已验证成品指纹反查（patch memory）。
    var matches = const <Map<String, dynamic>>[];
    if (memoryRepository != null && sha != null && sha.isNotEmpty) {
      try {
        final found = await ApkPatchMemoryService.findByArtifactSha256(
          memoryRepository,
          sha,
        );
        matches = [
          for (final m in found)
            <String, dynamic>{
              'title': m.title,
              'operation': m.operation,
              'solution': m.solution,
              'artifacts': m.artifacts,
            },
        ];
      } catch (e) {
        // 反查失败不能让「已验证成品指纹」这一类证据静默消失：否则
        // isProcessedArtifact 会以 false 定格，调用方（certificates 的
        // processedArtifact 判定）会把「检测没跑成」误读成「判定为原包」，
        // 恰好漏掉这条证据本来要覆盖的场景。如实带出，走 checkFailed 降级。
        checkFailed ??= 'patch_memory_lookup_failed: $e';
      }
    }

    return ApkArtifactIdentity(
      apkPath: apkPath,
      sha256: sha,
      selfSignedByToolchain: selfSigned,
      signatureProxyInjected: proxyInjected,
      verifiedArtifactMatches: matches,
      checkFailed: checkFailed,
    );
  }
}
