import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:Kelivo/relaygo/config/constants.dart';
import 'package:Kelivo/relaygo/models/api_key.dart';
import 'package:Kelivo/relaygo/models/user_settings.dart';
import 'package:Kelivo/relaygo/services/key_manager.dart';
import 'package:Kelivo/relaygo/services/model_call_tracker.dart';
import 'package:Kelivo/relaygo/services/providers/base_provider.dart';
import 'package:Kelivo/relaygo/services/providers/provider_factory.dart';

/// 图像生成代理（融合自 SenseNova Key Rotator 的 /v1/images/generations）
///
/// 把图像生成请求转发到上游提供商，支持按模型计数限额与 key 自动切换。
class ImageGenProxy {
  final KeyManager keyManager;
  final ModelCallTracker tracker;
  final UserSettings settings;

  ImageGenProxy({
    required this.keyManager,
    required this.tracker,
    required this.settings,
  });

  /// 处理 /v1/images/generations 请求
  Future<void> handle(HttpRequest request) async {
    if (request.method != 'POST') {
      request.response.statusCode = 405;
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({'error': '该接口仅支持 POST'}));
      await request.response.close();
      return;
    }

    // 读取请求体
    final body = <int>[];
    await for (final chunk in request) {
      body.addAll(chunk);
      if (body.length > Constants.maxRequestBodyBytes) {
        request.response.statusCode = 413;
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode({'error': '请求体过大'}));
        await request.response.close();
        return;
      }
    }

    Map<String, dynamic> payload;
    try {
      payload = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    } catch (_) {
      request.response.statusCode = 400;
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({'error': '无效的 JSON 请求体'}));
      await request.response.close();
      return;
    }

    final model = payload['model'] as String? ?? 'dall-e-3';
    final providerName = _detectProvider(model);
    final provider = providerForName(providerName);
    if (provider == null) {
      request.response.statusCode = 400;
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({'error': '无法识别模型 $model 的提供商'}));
      await request.response.close();
      return;
    }

    // 候选 key 池
    var keys = keyManager.getUsableByProvider(providerName);
    if (keys.isEmpty) {
      keys = keyManager.getUsableByProvider('openai');
    }
    if (keys.isEmpty) {
      request.response.statusCode = 503;
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({'error': '没有可用的 key 来处理图像生成请求'}));
      await request.response.close();
      return;
    }

    // 按限额过滤
    keys = keys.where((k) => tracker.canCall(k, model)).toList();
    if (keys.isEmpty) {
      request.response.statusCode = 429;
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode({
        'error': '模型 $model 的调用限额已用完，请等待窗口刷新后重试',
      }));
      await request.response.close();
      return;
    }

    // 尝试每个 key
    String? lastError;
    for (final key in keys) {
      if (!tracker.canCall(key, model)) continue;
      tracker.recordCall(key, model);

      try {
        final result = await provider.forward(
          ProxyRequest(
            method: 'POST',
            path: Constants.imagesPath,
            query: '',
            headers: const {},
            body: body,
            model: model,
            stream: false,
            clientIp: request.connectionInfo?.remoteAddress.address ?? '',
          ),
          key,
          timeout: Duration(seconds: settings.upstreamTimeoutSeconds),
        );

        if (result.statusCode >= 200 && result.statusCode < 300) {
          tracker.recordSuccess(key, model);
          request.response.statusCode = result.statusCode;
          result.headers.forEach((name, value) {
            final lower = name.toLowerCase();
            if (BaseHttpProvider.skipResponseHeader(lower)) return;
            request.response.headers.set(name, value);
          });
          await request.response.addStream(result.body);
          await request.response.close();
          return;
        }

        // 捕获错误
        final errBytes = <int>[];
        await for (final chunk in result.body.timeout(
            const Duration(seconds: 5))) {
          errBytes.addAll(chunk);
          if (errBytes.length >= 500) break;
        }
        lastError = utf8.decode(errBytes, allowMalformed: true);

        // 额度耗尽则标记并继续下一个 key
        if (result.statusCode == 429 || result.statusCode == 402) {
          tracker.markExhausted(key, model, 'image_quota');
          continue;
        }
        // 其他错误也透传
        request.response.statusCode = result.statusCode;
        request.response.headers.contentType = ContentType.json;
        request.response.write(lastError);
        await request.response.close();
        return;
      } catch (e) {
        lastError = e.toString();
        continue;
      }
    }

    request.response.statusCode = 503;
    request.response.headers.contentType = ContentType.json;
    request.response.write(jsonEncode({
      'error': '图像生成失败，已尝试所有可用 key',
      'detail': lastError,
    }));
    await request.response.close();
  }

  String _detectProvider(String model) {
    final m = model.toLowerCase();
    if (m.contains('dall-e') || m.contains('gpt-image')) return 'openai';
    if (m.contains('sensenova') || m.contains('nova')) return 'sensenova';
    if (m.contains('stable') || m.contains('sd')) return 'stability';
    return 'openai';
  }
}
