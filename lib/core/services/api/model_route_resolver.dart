import '../../providers/settings_provider.dart';

/// 每模型协议路由。
///
/// 同一个网关的不同模型服务在**不同端点**上，这不是特例而是常态：
/// - OpenCode Zen（官方端点表）：gpt/grok/muse-spark → `/responses`，
///   claude/qwen → `/messages`，glm/deepseek/kimi/minimax 等 → `/chat/completions`；
/// - Command Code（官方 Provider API）：`/chat/completions`、`/responses`、
///   `/messages` 三路，每个模型在 `/models` 的 `supported_endpoints` 里自报能走哪路。
///
/// 所以"这家供应商用哪个协议"要降到**每个模型**上：供应商配置仍是默认值，
/// 模型级覆盖有三档来源，优先级从高到低：
///   1. `modelOverrides[modelId]['endpoint']`（用户手填，或模型目录刷新时写入）；
///   2. 已知网关的模型名规则（Zen 这类不返回 supported_endpoints 的目录）；
///   3. 供应商默认（`useResponseApi` / `chatPath`，即改造前的行为）。
abstract final class ModelRouteResolver {
  const ModelRouteResolver._();

  /// 模型级端点覆盖键（存在 modelOverrides 里，不新增容器）。
  static const String endpointKey = 'endpoint';

  /// 模型目录刷新写入的"这家自报能走哪些路"（Command Code 的
  /// supported_endpoints 原样存下，供诊断与后续判断）。
  static const String supportedEndpointsKey = 'supportedEndpoints';

  static const String chatCompletions = '/chat/completions';
  static const String responses = '/responses';
  static const String messages = '/messages';

  /// 网关身份：这些厂家的模型可能各走各的协议。
  static bool isMultiProtocolGateway(ProviderConfig config) {
    final host = Uri.tryParse(config.baseUrl)?.host.toLowerCase() ?? '';
    final id = config.id.toLowerCase();
    return id.contains('opencode') ||
        id.contains('commandcode') ||
        id.contains('command code') ||
        host.contains('opencode.ai') ||
        host.contains('commandcode.ai');
  }

  /// 该模型在这家供应商上应该走哪个端点。
  static String endpointFor(ProviderConfig config, String modelId) {
    final override = config.modelOverrides[modelId];
    if (override is Map) {
      final raw = (override[endpointKey] ?? override['apiEndpoint'])
          ?.toString()
          .trim();
      if (raw != null && raw.isNotEmpty) {
        return raw.startsWith('/') ? raw : '/$raw';
      }
      // 供应商自报的端点列表：取第一个我们支持的。
      final declared = override[supportedEndpointsKey];
      if (declared is List) {
        final paths = <String>[
          for (final item in declared)
            if (item.toString().trim().isNotEmpty)
              item.toString().trim().startsWith('/')
                  ? item.toString().trim()
                  : '/${item.toString().trim()}',
        ];
        for (final candidate in const <String>[
          chatCompletions,
          responses,
          messages,
        ]) {
          if (paths.contains(candidate)) return candidate;
        }
      }
    }
    if (isMultiProtocolGateway(config)) return _gatewayDefaultEndpoint(modelId);
    if (config.useResponseApi == true) return responses;
    return config.chatPath?.trim().isNotEmpty == true
        ? config.chatPath!.trim()
        : chatCompletions;
  }

  /// 网关的模型名规则（官方端点表的等价物）：Claude 系只走 Messages，
  /// GPT/Grok/Muse 系走 Responses，其余走 Chat Completions。
  static String _gatewayDefaultEndpoint(String modelId) {
    final id = modelId.toLowerCase();
    final bare = id.contains('/') ? id.split('/').last : id;
    if (id.contains('claude')) return messages;
    if (id.startsWith('qwen') || bare.startsWith('qwen')) return messages;
    if (RegExp(
      r'^(gpt-|grok-|muse-spark|o[0-9](-|$))',
    ).hasMatch(bare)) {
      return responses;
    }
    return chatCompletions;
  }

  /// 把供应商配置折算成"这个模型该用的那份配置"。
  ///
  /// 只动协议相关的两个字段（`useResponseApi` / `chatPath`），其余原样；
  /// `/messages` 不在 OpenAI 兼容路径的服务范围内，这里**不改配置**并返回
  /// 原样，由调用方决定（见 [requiresAnthropicPath]）。
  static ProviderConfig effectiveConfig(ProviderConfig config, String modelId) {
    final endpoint = endpointFor(config, modelId);
    switch (endpoint) {
      case responses:
        return config.copyWith(useResponseApi: true);
      case chatCompletions:
        return config.copyWith(
          useResponseApi: false,
          chatPath: chatCompletions,
        );
      case messages:
        return config;
      default:
        return config.copyWith(useResponseApi: false, chatPath: endpoint);
    }
  }

  /// 该模型是否只能用 Anthropic Messages 协议（OpenAI 兼容路径服务不了）。
  static bool requiresAnthropicPath(ProviderConfig config, String modelId) =>
      endpointFor(config, modelId) == messages;
}
