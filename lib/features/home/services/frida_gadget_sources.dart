/// Frida gadget 的**下载源候选**（用户实测报告 ⑤：GitHub 不可达时 gadget 装不上）。
///
/// 背景：`FridaGadgetTool.DOWNLOAD_URL` 是钉死的 GitHub release 地址。在 GitHub 被
/// 墙/不可达的环境里，`install_gadget` 直接失败，而业务侧没有任何替代路径，整个
/// 无 root 插桩链路就断了。
///
/// 这里只做**顺序**决策，不改钉死的版本与 sha256：所有候选源下载下来的文件都必须
/// 通过同一个 sha256 校验（校验在 AssetDownloader.download 里，Kotlin 侧执行），
/// 因此镜像被投毒也换不掉二进制。
abstract final class FridaGadgetSources {
  FridaGadgetSources._();

  /// 钉死的官方地址（与 FridaGadgetTool.DOWNLOAD_URL 一致；仅用于拼镜子）。
  static const String canonicalUrl =
      'https://github.com/frida/frida/releases/download/'
      '17.19.0/frida-gadget-17.19.0-android-arm64.so.xz';

  /// 常见 GitHub 加速前缀（按经验顺序：先通用代理，再专用加速站）。
  ///
  /// 只影响**从哪下**，不影响下到什么：sha256 仍由 Kotlin 侧校验。
  static const List<String> mirrorPrefixes = <String>[
    'https://ghfast.top/',
    'https://gh-proxy.com/',
    'https://mirror.ghproxy.com/',
    'https://ghproxy.net/',
  ];

  /// 候选顺序：显式 `source`（用户/调用方指定，最高优先）→ 镜像前缀套官方地址 →
  /// 官方地址本身（放最后：能直连时它最可信，不能直连时前面已经试过）。
  ///
  /// [source] 可以是完整 URL，也可以是「镜像前缀」（以 `/` 结尾时按前缀处理）。
  static List<String> resolve({
    String? source,
    String? canonical,
    List<String> mirrors = mirrorPrefixes,
  }) {
    final pinned = (canonical ?? canonicalUrl).trim();
    final out = <String>[];
    void add(String url) {
      final value = url.trim();
      if (value.isEmpty || out.contains(value)) return;
      out.add(value);
    }

    final explicit = (source ?? '').trim();
    if (explicit.isNotEmpty) {
      if (explicit.endsWith('/')) {
        add('$explicit$pinned');
      } else {
        add(explicit);
      }
    }
    for (final prefix in mirrors) {
      add('${prefix.trim()}$pinned');
    }
    add(pinned);
    return List<String>.unmodifiable(out);
  }
}
