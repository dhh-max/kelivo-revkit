import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:Kelivo/core/providers/settings_provider.dart';
import 'package:Kelivo/core/services/api/api_session_scope.dart';
import 'package:Kelivo/core/services/api/chat_api_helpers.dart';

ProviderConfig _config() => ProviderConfig(
  id: 'session-test',
  enabled: true,
  name: 'session-test',
  apiKey: 'k',
  baseUrl: 'https://api.example.com/v1',
  providerType: ProviderKind.openai,
);

void main() {
  tearDown(() {
    ApiSessionScope.resetForTest();
  });

  test('customHeaders 在会话作用域内注入 x-opencode-session', () {
    final headers = ApiSessionScope.run(
      () => customHeaders(_config(), 'model-x'),
      'conv-123',
    );
    expect(headers[ApiSessionScope.headerName], 'conv-123');
  });

  test('无作用域且未预载：不注入（避免瞎编会话）', () {
    final headers = customHeaders(_config(), 'model-x');
    expect(headers.containsKey(ApiSessionScope.headerName), isFalse);
  });

  test('无作用域但已预载：回退安装级稳定 ID 且跨次不变', () async {
    SharedPreferences.setMockInitialValues({});
    await ApiSessionScope.preload();
    final first = customHeaders(_config(), 'model-x');
    expect(first[ApiSessionScope.headerName], isNotEmpty);
    await ApiSessionScope.preload();
    final second = customHeaders(_config(), 'model-x');
    expect(
      second[ApiSessionScope.headerName],
      first[ApiSessionScope.headerName],
      reason: '安装级 ID 必须稳定',
    );
  });

  test('Zone 作用域沿 await 链传播（并发流互不串话）', () async {
    String? seenA;
    String? seenB;
    await Future.wait([
      ApiSessionScope.run(() async {
        await Future<void>.delayed(const Duration(milliseconds: 5));
        await Future<void>.delayed(const Duration(milliseconds: 5));
        seenA = ApiSessionScope.current;
      }, 'conv-A'),
      ApiSessionScope.run(() async {
        await Future<void>.delayed(const Duration(milliseconds: 7));
        seenB = ApiSessionScope.current;
      }, 'conv-B'),
    ]);
    expect(seenA, 'conv-A');
    expect(seenB, 'conv-B');
  });

  test('空会话 ID 等同无作用域', () {
    final headers = ApiSessionScope.run(
      () => customHeaders(_config(), 'model-x'),
      '   ',
    );
    expect(headers.containsKey(ApiSessionScope.headerName), isFalse);
  });

  test('用户自定义同名头可覆盖自动注入（merge 优先级不变）', () {
    final cfg = ProviderConfig(
      id: 'session-override',
      enabled: true,
      name: 'session-override',
      apiKey: 'k',
      baseUrl: 'https://api.example.com/v1',
      providerType: ProviderKind.openai,
      customHeaders: [
        {'name': 'x-opencode-session', 'value': 'custom-value'},
      ],
    );
    final headers = ApiSessionScope.run(
      () => customHeaders(cfg, 'model-x'),
      'conv-123',
    );
    expect(headers[ApiSessionScope.headerName], 'custom-value');
  });
}
