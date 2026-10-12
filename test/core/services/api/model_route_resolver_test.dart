import 'package:flutter_test/flutter_test.dart';
import 'package:Kelivo/core/providers/settings_provider.dart';
import 'package:Kelivo/core/services/api/model_route_resolver.dart';

ProviderConfig _gateway({
  required String id,
  required String baseUrl,
  Map<String, dynamic> modelOverrides = const <String, dynamic>{},
}) => ProviderConfig(
  id: id,
  enabled: true,
  name: id,
  apiKey: 'k',
  baseUrl: baseUrl,
  providerType: ProviderKind.openai,
  models: const <String>[],
  modelOverrides: modelOverrides,
);

void main() {
  test('OpenCode Zen：按官方端点表分三路', () {
    final zen = _gateway(id: 'OpenCode', baseUrl: 'https://opencode.ai/zen/v1');
    expect(ModelRouteResolver.endpointFor(zen, 'glm-5.3-flash'),
        ModelRouteResolver.chatCompletions);
    expect(ModelRouteResolver.endpointFor(zen, 'deepseek-v4-flash'),
        ModelRouteResolver.chatCompletions);
    expect(ModelRouteResolver.endpointFor(zen, 'gpt-6-astra'),
        ModelRouteResolver.responses);
    expect(ModelRouteResolver.endpointFor(zen, 'grok-4.6'),
        ModelRouteResolver.responses);
    expect(ModelRouteResolver.endpointFor(zen, 'muse-spark-1.3'),
        ModelRouteResolver.responses);
    expect(ModelRouteResolver.endpointFor(zen, 'claude-opus-5'),
        ModelRouteResolver.messages);
    expect(ModelRouteResolver.endpointFor(zen, 'qwen3.7-max'),
        ModelRouteResolver.messages);
    expect(ModelRouteResolver.requiresAnthropicPath(zen, 'claude-opus-5'),
        isTrue);
    expect(
      ModelRouteResolver.effectiveConfig(zen, 'gpt-6-astra').useResponseApi,
      isTrue,
    );
    expect(
      ModelRouteResolver.effectiveConfig(zen, 'glm-5.3-flash').useResponseApi,
      isFalse,
    );
  });

  test('Command Code：模型自报 supported_endpoints 优先于模型名规则', () {
    final cc = _gateway(
      id: 'CommandCode',
      baseUrl: 'https://api.commandcode.ai/provider/v1',
      modelOverrides: <String, dynamic>{
        'deepseek/deepseek-v4-flash': <String, dynamic>{
          ModelRouteResolver.supportedEndpointsKey: <String>[
            '/chat/completions',
            '/responses',
          ],
        },
        'claude-sonnet-5': <String, dynamic>{
          ModelRouteResolver.supportedEndpointsKey: <String>['/messages'],
        },
      },
    );
    // 自报含 chat/completions → 走 chat（列表顺序决定优先级，chat 在前）
    expect(ModelRouteResolver.endpointFor(cc, 'deepseek/deepseek-v4-flash'),
        ModelRouteResolver.chatCompletions);
    expect(ModelRouteResolver.endpointFor(cc, 'claude-sonnet-5'),
        ModelRouteResolver.messages);
    // 手填 endpoint 覆盖一切
    final pinned = _gateway(
      id: 'CommandCode',
      baseUrl: 'https://api.commandcode.ai/provider/v1',
      modelOverrides: <String, dynamic>{
        'z-ai/glm-5.3-flash': <String, dynamic>{'endpoint': '/responses'},
      },
    );
    expect(ModelRouteResolver.endpointFor(pinned, 'z-ai/glm-5.3-flash'),
        ModelRouteResolver.responses);
    expect(
      ModelRouteResolver.effectiveConfig(pinned, 'z-ai/glm-5.3-flash')
          .useResponseApi,
      isTrue,
    );
  });

  test('非网关厂家：行为与改造前一致（供应商默认）', () {
    final plain = _gateway(id: 'SomeRelay', baseUrl: 'https://relay.example/v1');
    expect(ModelRouteResolver.endpointFor(plain, 'glm-5.3-flash'),
        ModelRouteResolver.chatCompletions);
    expect(ModelRouteResolver.requiresAnthropicPath(plain, 'claude-opus-5'),
        isFalse, reason: '别把普通中转的 claude 模型也改道');
    final responses = plain.copyWith(useResponseApi: true);
    expect(ModelRouteResolver.endpointFor(responses, 'gpt-5.6-sol'),
        ModelRouteResolver.responses);
  });
}
