import '../../models/provider_oauth.dart';
import 'package:uuid/uuid.dart';

import '../../providers/settings_provider.dart';
import 'api_session_scope.dart';

const String _openRouterAppReferer = 'https://github.com/Chevey339/kelivo';
const String _openRouterAppTitle = 'SoLab';
const String _openRouterAppCategories = 'general-chat';

/// OpenCode Go gateway session headers, resolved once per generation.
///
/// Upstream gates on the official host. This fork's chat layer injects the
/// same header for every provider (the gateway may sit behind a custom host;
/// see [ApiSessionScope] and its test), so this helper is the narrow,
/// upstream-shaped view of the same scope.
Map<String, String>? providerSessionHeaders(
  ProviderConfig config, {
  String? conversationId,
  Map<String, String>? extraHeaders,
}) {
  final host = Uri.tryParse(config.baseUrl)?.host.toLowerCase();
  if (config.isOAuth) {
    final id = conversationId?.trim() ?? '';
    final session = id.isEmpty ? const Uuid().v4() : id;
    return {
      if (config.oauthProvider == OAuthProvider.chatgpt) ...{
        'session_id': session,
        'conversation_id': session,
        'x-client-request-id': session,
      },
      if (config.oauthProvider == OAuthProvider.grok) 'x-grok-conv-id': session,
      if (config.oauthProvider == OAuthProvider.claude)
        'X-Claude-Code-Session-Id': session,
      ...?extraHeaders,
    };
  }
  if (host != 'opencode.ai') return extraHeaders;
  final id = conversationId?.trim() ?? '';
  if (id.isNotEmpty) {
    return {ApiSessionScope.headerName: id, ...?extraHeaders};
  }
  final scoped = ApiSessionScope.resolveHeaderValue();
  return {
    ApiSessionScope.headerName: scoped ?? const Uuid().v4(),
    ...?extraHeaders,
  };
}

bool isOpenRouterProvider(ProviderConfig config) {
  final host = Uri.tryParse(config.baseUrl)?.host.toLowerCase() ?? '';
  return host.contains('openrouter.ai');
}

Map<String, String> providerDefaultHeaders(ProviderConfig config) {
  if (!isOpenRouterProvider(config)) return const <String, String>{};
  return const <String, String>{
    'HTTP-Referer': _openRouterAppReferer,
    'X-OpenRouter-Title': _openRouterAppTitle,
    'X-OpenRouter-Categories': _openRouterAppCategories,
  };
}
