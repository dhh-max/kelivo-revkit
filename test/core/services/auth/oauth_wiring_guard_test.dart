import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// 接线守卫：`ProviderOAuthService.authenticatedClient` 必须被**生产代码**调用。
///
/// 背景（2026-09-20 定位的同步静默丢件）：上游在 `chat_api_service` 与
/// `model_provider` 的 client 工厂里各包一层 `authenticatedClient(...)`，我们同步时
/// 把这两处丢了 —— OAuth 提供商（Claude / ChatGPT / Grok / Kimi…）的请求拿不到
/// OAuth 头、登录成功也会 401；而该 API 从此只剩测试在调，连它内部的缺陷都只在
/// 测试里暴露（就是 claude_oauth 那 10 条红）。
///
/// 这类"公共 API 没有生产调用者"的丢失，功能测试抓不到（测试自己会调 API），
/// 所以用静态守卫钉住：生产目录里必须出现调用点。
void main() {
  test('authenticatedClient 在生产代码里有调用点（OAuth 包装没被丢件）', () {
    final roots = <Directory>[
      Directory('lib/core/services/api'),
      Directory('lib/core/providers'),
    ];
    final produced = <String>[];
    for (final root in roots) {
      for (final entity in root.listSync(recursive: true)) {
        if (entity is! File || !entity.path.endsWith('.dart')) continue;
        final source = entity.readAsStringSync();
        for (final line in source.split('\n')) {
          if (line.trimLeft().startsWith('//') || line.trimLeft().startsWith('///')) {
            continue;
          }
          if (line.contains('authenticatedClient(')) {
            produced.add('${entity.path}: ${line.trim()}');
          }
        }
      }
    }
    expect(
      produced,
      isNotEmpty,
      reason: 'authenticatedClient 在生产代码里没有任何调用点 —— OAuth 包装丢了，'
          'OAuth 提供商请求会 401（见 docs/上游对接进度.md §8/§10）',
    );
    // 两条已知接线（client 工厂）必须都在
    expect(
      produced.where((line) => line.contains('chat_api_service.dart')).length,
      1,
      reason: 'chat_api_service 的 client 工厂必须包 OAuth',
    );
    expect(
      produced.where((line) => line.contains('model_provider.dart')).length,
      1,
      reason: 'model_provider 的 client 工厂必须包 OAuth',
    );
  });
}
