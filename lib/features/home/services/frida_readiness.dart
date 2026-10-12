import 'frida_gadget_sources.dart';

/// Frida 两侧就绪度的**组合诊断**（报告 ⑤-c）。
///
/// 真机实测的坑：测试者按提示在 rootfs 里 `pip install --break-system-packages
/// frida` 装上了 17.20.0 客户端，然后发现链路还是不通——因为**这是两条独立的链路**：
///
///  - **设备侧 gadget**（宿主）：`frida(action=install_gadget)` 下载并校验的那段
///    `.so`，注入目标 APK 后，目标进程才会监听 127.0.0.1:27042。没有它，运行期
///    动作无从连起。
///  - **沙盒侧 python 客户端**（rootfs）：`open/hook/call/read/backtrace/close`
///    的执行器，连的是上面那个监听端口。
///
/// 装客户端不会得到 gadget，反之亦然。过去 `status` 只分别回报两侧状态，没有一句
/// 话把「缺哪一侧、下一步做什么」讲清楚，于是出现「按指引装完还是不能用」。
abstract final class FridaReadiness {
  FridaReadiness._();

  /// 就绪度判定（`verdict`）。
  static const String verdictReady = 'ready';
  static const String verdictNeedGadget = 'need_gadget';
  static const String verdictNeedSandbox = 'need_sandbox';
  static const String verdictNeedBoth = 'need_both';

  /// 组合诊断。纯函数（不碰通道/文件系统），便于单测。
  ///
  /// [clientVersion] 来自沙盒驱动的 `clientStatus()`（拿不到传 null）。
  /// [archivePresent]（F-46，2026-10-04）：安装归档（.xz）已在本地——此时
  /// 「去下载」是错的指引，应直接 install_gadget(localPath=归档)。
  /// [pinnedVersion]：与 [clientVersion] 做 major.minor 比对，错配给 versionSkew。
  static Map<String, Object?> diagnose({
    required bool gadgetPresent,
    required bool sandboxDriverAvailable,
    String? clientVersion,
    String? gadgetSha256,
    bool archivePresent = false,
    String? pinnedVersion,
  }) {
    final verdict = switch ((gadgetPresent, sandboxDriverAvailable)) {
      (true, true) => verdictReady,
      (false, true) => verdictNeedGadget,
      (true, false) => verdictNeedSandbox,
      (false, false) => verdictNeedBoth,
    };
    // F-46：版本错配警告（pinned gadget vs 沙盒客户端），major.minor 不同即提示。
    String _mm(String v) => v.split(RegExp(r'[.\-+]')).take(2).join('.');
    final pinned = (pinnedVersion ?? '').trim();
    final client = (clientVersion ?? '').trim();
    final versionSkew = (pinned.isNotEmpty &&
            client.isNotEmpty &&
            _mm(pinned) != _mm(client))
        ? '版本错配：pinned gadget $pinned vs 沙盒 python 客户端 $client'
              '（major.minor 不同）——frida 协议可能不兼容，优先把两侧对齐到同一版本，'
              '不要假设能配对工作。'
        : null;
    return <String, Object?>{
      'verdict': verdict,
      'gadgetPresent': gadgetPresent,
      'sandboxDriverAvailable': sandboxDriverAvailable,
      if (pinned.isNotEmpty) 'pinnedVersion': pinned,
      if (client.isNotEmpty) 'sandboxClientVersion': client,
      if (gadgetSha256 != null && gadgetSha256.isNotEmpty)
        'gadgetSha256': gadgetSha256,
      if (versionSkew != null) 'versionSkew': versionSkew,
      'archivePresent': archivePresent,
      'sides': const <String, Object?>{
        'deviceGadget':
            '设备侧：注入进目标 APK 的 libfrida-gadget.so，由 install_gadget + inject 提供',
        'sandboxClient':
            '沙盒侧：rootfs 里的 python frida 客户端，负责 open/hook/call/read/backtrace/close',
        'note': '两侧互相独立：装客户端不会得到 gadget，装 gadget 也不会装客户端。',
      },
      'summary': _summaryFor(
        verdict,
        clientVersion: clientVersion,
        archivePresent: archivePresent,
      ),
      if (verdict != verdictReady)
        'nextActions': _actionsFor(verdict, archivePresent: archivePresent),
    };
  }

  static String _summaryFor(
    String verdict, {
    String? clientVersion,
    bool archivePresent = false,
  }) {
    final client = (clientVersion ?? '').isNotEmpty
        ? '沙盒侧 python 客户端已是 $clientVersion'
        : '沙盒侧 python 客户端版本未知';
    return switch (verdict) {
      verdictReady => '两侧都就绪：gadget 已在宿主，$client；可走 inject → apk_sign → 安装。',
      verdictNeedGadget =>
        archivePresent
            ? '缺**设备侧 gadget**，但安装归档已在本地：直接 install_gadget(localPath=<归档路径>) '
                  '解压即可，不要再走网络下载。注意：$client，与 gadget 是独立两条链路。'
            : '缺**设备侧 gadget**（宿主未安装）。注意：rootfs 里那套 python frida 客户端'
                  '（$client）不能替代它——两者是独立的两条链路。',
      verdictNeedSandbox =>
        'gadget 已就绪，但**沙盒未就绪**：open/hook/call 等运行期动作需要 Linux '
            '环境；宿主侧的 inject / apk_sign 不受影响，可现在就用。',
      _ =>
        '两侧都缺：先装设备侧 gadget，再装 Linux 沙盒（顺序无关，但两者都要）。',
    };
  }

  static List<String> _actionsFor(
    String verdict, {
    bool archivePresent = false,
  }) => switch (verdict) {
    verdictNeedGadget => archivePresent
        ? <String>[
            '归档已在本地：frida(action=install_gadget, localPath=<回执 archive.path>) 直接解压',
            '解压后：frida(action=inject, apkPath=…) → apk_sign → 安装到设备',
          ]
        : <String>[
            'frida(action=install_gadget)：自动按镜像候选下载并校验 sha256',
            '若 GitHub 与镜像都不可达：手动下载 ${FridaGadgetSources.canonicalUrl.split('/').last} '
                '后 frida(action=install_gadget, localPath=<本地 .xz>)',
            '拿到 gadget 后：frida(action=inject, apkPath=…) → apk_sign → 安装到设备',
          ],
    verdictNeedSandbox => <String>[
      '在「设置 → 工作区」安装 Linux 环境（rootfs）后重试运行期动作',
      '只需静态结论时不必等沙盒：inject + apk_sign 已经能产出可安装的注入版',
    ],
    _ => <String>[
      '先 frida(action=install_gadget)（可用 source=镜像 或 localPath 兜底）',
      '再装 Linux 沙盒环境以启用运行期动作',
      '两侧都就绪后：inject → apk_sign → 安装 → 运行期 open/hook',
    ],
  };
}
