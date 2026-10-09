import 'dart:convert';
import 'dart:io';

import 'package:Kelivo/core/providers/settings_provider.dart';
import 'package:Kelivo/core/services/api/chat_api_service.dart';
import 'package:Kelivo/core/services/api/provider_request_headers.dart';
import 'package:flutter_test/flutter_test.dart';

class _ProxyHttpOverrides extends HttpOverrides {
  _ProxyHttpOverrides(this.port);
  final int port;

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    final client = super.createHttpClient(context);
    client.findProxy = (_) => 'PROXY 127.0.0.1:$port';
    return client;
  }
}

ProviderConfig _config({
  String host = 'opencode.ai',
  ProviderKind kind = ProviderKind.openai,
  bool responses = false,
}) => ProviderConfig(
  id: 'Custom',
  name: 'Custom',
  enabled: true,
  apiKey: 'test-key',
  baseUrl: 'http://$host/zen/go/v1',
  providerType: kind,
  useResponseApi: responses,
);

const _reply = {
  'choices': [
    {
      'message': {'role': 'assistant', 'content': 'ok'},
      'finish_reason': 'stop',
    },
  ],
  'content': [
    {'type': 'text', 'text': 'ok'},
  ],
  'output': [
    {
      'type': 'message',
      'role': 'assistant',
      'content': [
        {'type': 'output_text', 'text': 'ok'},
      ],
    },
  ],
};

void main() {
  test('automatic session header is limited to the official host', () {
    for (final host in [
      'example.com',
      'opencode.ai.example.com',
      'fakeopencode.ai',
    ]) {
      expect(
        providerSessionHeaders(_config(host: host), conversationId: 'chat'),
        isNull,
      );
    }
    expect(
      providerSessionHeaders(
        _config(host: 'OPENCODE.AI'),
        conversationId: 'chat',
      ),
      {'x-opencode-session': 'chat'},
    );
  });

  for (final route in [
    (kind: ProviderKind.openai, responses: false, path: 'chat/completions'),
    (kind: ProviderKind.openai, responses: true, path: 'responses'),
    (kind: ProviderKind.claude, responses: false, path: 'messages'),
  ]) {
    test(
      '${route.path} uses stable conversation IDs and separate task IDs',
      () async {
        final headers = <String?>[];
        final paths = <String>[];
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((request) async {
          headers.add(request.headers.value('x-opencode-session'));
          paths.add(request.uri.path);
          await request.drain<void>();
          request.response.headers.contentType = ContentType.json;
          request.response.write(jsonEncode(_reply));
          await request.response.close();
        });
        final config = _config(kind: route.kind, responses: route.responses);
        await HttpOverrides.runZoned(() async {
          for (final id in ['chat-a', 'chat-a', 'chat-b', null, null]) {
            final result = await ChatApiService.generateText(
              config: config,
              modelId: 'test-model',
              prompt: 'hello',
              conversationId: id,
            );
            expect(result, 'ok');
          }
          await ChatApiService.generateText(
            config: config.copyWith(
              customHeaders: const [
                {'name': 'X-OPENCODE-SESSION', 'value': 'manual'},
              ],
            ),
            modelId: 'test-model',
            prompt: 'hello',
            conversationId: 'chat-a',
          );
        }, createHttpClient: _ProxyHttpOverrides(server.port).createHttpClient);
        expect(headers.take(3), ['chat-a', 'chat-a', 'chat-b']);
        // 无会话 id 且不在作用域内：本 fork 不注入该头（宁缺勿瞎编一个假会话
        // id，见 api_session_scope_test）。上游在这里每次现编一个 UUID。
        expect(headers[3], isNull);
        expect(headers[4], isNull);
        expect(headers.last, 'manual');
        expect(paths, everyElement('/zen/go/v1/${route.path}'));
      },
    );
  }
  // 上游还有一组「流式工具轮 + 429 重试复用会话作用域」的用例，依赖自动重试
  // 环（retryingStream）。本 fork 未接线上游的自动重试（见 display_settings_page
  // 与 chat_actions 的说明），该用例在无重试下会一直等一个不会关闭的 429 响应，
  // 故整组移除；重试接线后应连同上游用例一起取回。
}
