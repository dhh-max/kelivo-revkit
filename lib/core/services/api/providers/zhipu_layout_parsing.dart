/// Zhipu GLM-OCR Layout Parsing
///
/// Official GLM-OCR uses `/layout_parsing` with `{model, file}`, not Chat Completions.
/// This module provides the standalone request/response handling for that endpoint.
///
/// When integrated as part of chat_api_service.dart, it can access _apiModelId,
/// _apiKeyForRequest, _customHeaders etc. directly.
/// For now, it accepts ProviderConfig and modelId from the caller.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import '../../../models/token_usage.dart';
import '../../model_override_payload_parser.dart';
import '../../../providers/settings_provider.dart';

const String officialGlmOcrModelId = 'glm-ocr';

/// Check if this provider/config combination should use Zhipu layout parsing.
bool shouldUseZhipuLayoutParsing(ProviderConfig config, String modelId) {
  return isOfficialZhipuHost(config) &&
      isOfficialGlmOcrModel(_apiModelIdSafe(config, modelId));
}

bool isOfficialZhipuHost(ProviderConfig config) {
  final host = Uri.tryParse(config.baseUrl.trim())?.host.toLowerCase() ?? '';
  return host == 'open.bigmodel.cn';
}

bool isOfficialGlmOcrModel(String modelId) {
  return modelId.trim().toLowerCase() == officialGlmOcrModelId;
}

String _apiModelIdSafe(ProviderConfig config, String modelId) {
  final ov = config.modelOverrides[modelId];
  if (ov != null && ov.apiModelId != null && ov.apiModelId!.isNotEmpty) {
    return ov.apiModelId!;
  }
  return modelId;
}

String _apiKeyForRequestSafe(ProviderConfig config, String modelId) {
  final ov = config.modelOverrides[modelId];
  if (ov != null && ov.apiKey != null && ov.apiKey!.isNotEmpty) {
    return ov.apiKey!;
  }
  final apiKey = config.apiKey;
  return apiKey.isNotEmpty ? apiKey : 'sk-no-key';
}

Map<String, String> _customHeadersSafe(
  ProviderConfig config,
  String modelId, {
  Map<String, String>? baseHeaders,
  Map<String, String>? assistantHeaders,
}) {
  final headers = <String, String>{...?baseHeaders};
  final ov = config.modelOverrides[modelId];
  if (ov != null) {
    final customHeaders = ModelOverridePayloadParser.customHeaders(ov);
    headers.addAll(customHeaders);
  }
  if (assistantHeaders != null) {
    headers.addAll(assistantHeaders);
  }
  return headers;
}

/// Send a Zhipu layout parsing request and return the result as a stream.
Stream<({String text, TokenUsage? usage})> sendZhipuLayoutParsingStream(
  http.Client client,
  ProviderConfig config,
  String modelId,
  List<Map<String, dynamic>> messages, {
  List<String>? userImagePaths,
  Map<String, String>? extraHeaders,
}) async* {
  final file = await _resolveLayoutParsingFile(
    messages: messages,
    userImagePaths: userImagePaths,
  );
  final body = <String, dynamic>{'model': officialGlmOcrModelId, 'file': file};
  final response = await client.post(
    _layoutParsingUrl(config),
    headers: _customHeadersSafe(
      config,
      modelId,
      baseHeaders: <String, String>{
        'Authorization': 'Bearer ${_apiKeyForRequestSafe(config, modelId)}',
        'Content-Type': 'application/json',
      },
      assistantHeaders: extraHeaders,
    ),
    body: jsonEncode(body),
  );
  final decoded = _decodeLayoutParsingResponse(response);
  final text = _mdResultsFromResponse(decoded);
  final usage = _usageFromResponse(decoded);
  yield (text: text, usage: usage);
}

Uri _layoutParsingUrl(ProviderConfig config) {
  final rawBase = config.baseUrl.endsWith('/')
      ? config.baseUrl.substring(0, config.baseUrl.length - 1)
      : config.baseUrl;
  return Uri.parse('$rawBase/layout_parsing');
}

Future<String> _resolveLayoutParsingFile({
  required List<Map<String, dynamic>> messages,
  List<String>? userImagePaths,
}) async {
  for (final path in userImagePaths ?? const <String>[]) {
    final encoded = await _encodeLayoutParsingFile(path);
    if (encoded != null) return encoded;
  }
  for (var i = messages.length - 1; i >= 0; i--) {
    if ((messages[i]['role'] ?? '').toString() != 'user') continue;
    final encoded = await _encodeLayoutParsingFileFromContent(
      messages[i]['content'],
    );
    if (encoded != null) return encoded;
  }
  throw const HttpException('GLM-OCR requires an image or PDF file.');
}

Future<String?> _encodeLayoutParsingFileFromContent(dynamic content) async {
  if (content is List) {
    for (final part in content) {
      if (part is! Map) continue;
      final type = (part['type'] ?? '').toString();
      if (type != 'image_url' && type != 'input_image' && type != 'image') {
        continue;
      }
      final image = part['image_url'] ?? part['input_image'];
      final source = image is Map
          ? (image['url'] ?? image['image_url'] ?? '').toString()
          : image?.toString() ?? '';
      final encoded = await _encodeLayoutParsingFile(source);
      if (encoded != null) return encoded;
    }
    return null;
  }
  final raw = (content ?? '').toString().trim();
  if (raw.startsWith('http://') ||
      raw.startsWith('https://') ||
      raw.startsWith('data:')) {
    return raw;
  }
  return null;
}

Future<String?> _encodeLayoutParsingFile(String source) async {
  final trimmed = source.trim();
  if (trimmed.isEmpty) return null;
  if (trimmed.startsWith('http://') ||
      trimmed.startsWith('https://') ||
      trimmed.startsWith('data:')) {
    return trimmed;
  }
  // Try to encode as base64 data URL
  try {
    final file = File(trimmed);
    if (await file.exists()) {
      final bytes = await file.readAsBytes();
      final base64Str = base64Encode(bytes);
      final ext = trimmed.split('.').last.toLowerCase();
      final mime = switch (ext) {
        'jpg' || 'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'webp' => 'image/webp',
        'pdf' => 'application/pdf',
        _ => 'application/octet-stream',
      };
      return 'data:$mime;base64,$base64Str';
    }
  } catch (_) {}
  return null;
}

Map<String, dynamic> _decodeLayoutParsingResponse(http.Response response) {
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw HttpException('HTTP ${response.statusCode}: ${response.body}');
  }
  final decoded = jsonDecode(response.body);
  if (decoded is! Map) {
    throw const FormatException('GLM-OCR returned a non-object body.');
  }
  return decoded.cast<String, dynamic>();
}

String _mdResultsFromResponse(Map<String, dynamic> response) {
  final raw = response['md_results'];
  if (raw is String) return raw.trim();
  if (raw is List) {
    return [
      for (final item in raw)
        if (item != null && item.toString().trim().isNotEmpty)
          item.toString().trim(),
    ].join('\n\n');
  }
  return '';
}

TokenUsage? _usageFromResponse(Map<String, dynamic> response) {
  final usage = response['usage'];
  if (usage is! Map) return null;
  final prompt = _asInt(usage['prompt_tokens']);
  final completion = _asInt(usage['completion_tokens']);
  final total = _asInt(usage['total_tokens']);
  if (prompt == 0 && completion == 0 && total == 0) return null;
  return TokenUsage(
    promptTokens: prompt,
    completionTokens: completion,
    totalTokens: total > 0 ? total : prompt + completion,
  );
}

int _asInt(dynamic value) {
  if (value is int) return value;
  if (value is num) return value.toInt();
  return int.tryParse(value?.toString() ?? '') ?? 0;
}
