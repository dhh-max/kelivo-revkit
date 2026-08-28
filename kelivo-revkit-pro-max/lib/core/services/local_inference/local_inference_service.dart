import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:llama_flutter_android/llama_flutter_android.dart';

/// 本地 GGUF 推理引擎
/// llama.cpp 引擎已随 APK 内置（llama_flutter_android 插件构建时编译进 APK）。
/// 通过本地 HTTP 代理暴露 OpenAI 兼容 API，供现有对话链路使用。
class LocalInferenceService {
  static final LocalInferenceService _instance = LocalInferenceService._();
  factory LocalInferenceService() => _instance;
  LocalInferenceService._();

  LlamaController? _controller;
  HttpServer? _server;
  bool _loading = false;
  bool _generating = false;
  String? _currentModelName;
  int _port = 0;

  bool get isRunning => _controller != null && !_loading;
  int get port => _port;

  /// 加载 GGUF 模型并启动本地 HTTP 代理（OpenAI 兼容 API）
  Future<int> start({
    required String modelPath,
    required String modelName,
    int? port,
    int? nGpuLayers,
    int? nCtx,
  }) async {
    if (_controller != null) await stop();

    _currentModelName = modelName;
    _loading = true;

    try {
      debugPrint('[LocalInference] Loading model: $modelPath');
      _controller = LlamaController();

      // 检测 GPU 支持
      GpuInfo gpu;
      try {
        gpu = await _controller!.detectGpu();
        debugPrint('[LocalInference] GPU: ${gpu.gpuName}, vulkan=${gpu.vulkanSupported}');
      } catch (_) {
        gpu = GpuInfo(
          vulkanSupported: false,
          gpuName: 'CPU',
          vulkanApiVersion: -1,
          deviceLocalMemoryBytes: -1,
          freeRamBytes: -1,
          recommendedGpuLayers: 0,
        );
      }

      // 加载模型
      await _controller!.loadModel(
        modelPath: modelPath,
        threads: 4,
        contextSize: nCtx ?? 2048,
        gpuLayers: nGpuLayers ?? (gpu.vulkanSupported ? gpu.recommendedGpuLayers : 0),
      );

      debugPrint('[LocalInference] Model loaded: $modelName');

      // 启动 HTTP 代理
      _server = await HttpServer.bind(InternetAddress.loopbackIPv4, port ?? 0);
      _port = _server!.port;
      _server!.listen(_handleRequest);
      _loading = false;

      debugPrint('[LocalInference] HTTP proxy on port $_port');
      return _port;
    } catch (e) {
      await _cleanup();
      _loading = false;
      throw Exception('加载模型失败: $e');
    }
  }

  Future<void> _handleRequest(HttpRequest request) async {
    try {
      final path = request.uri.path;

      if (request.method == 'POST' && path == '/v1/chat/completions') {
        await _handleChat(request);
      } else if (request.method == 'GET' && path == '/v1/models') {
        _writeJson(request, {
          'object': 'list',
          'data': [
            {
              'id': _currentModelName ?? 'local-model',
              'object': 'model',
              'created': DateTime.now().millisecondsSinceEpoch ~/ 1000,
              'owned_by': 'local',
            }
          ],
        });
      } else if (path == '/health') {
        _writeJson(request, {'status': 'ok', 'model': _currentModelName});
      } else {
        request.response.statusCode = 404;
        request.response.close();
      }
    } catch (e) {
      try {
        _writeJson(request, {'error': e.toString()}, 500);
      } catch (_) {}
    }
  }

  Future<void> _handleChat(HttpRequest request) async {
    final controller = _controller;
    if (controller == null) {
      _writeJson(request, {'error': '推理引擎未就绪'}, 503);
      return;
    }

    final body = await utf8.decoder.bind(request).join();
    final data = jsonDecode(body) as Map<String, dynamic>;
    final messages = data['messages'] as List<dynamic>;
    final stream = data['stream'] == true;

    if (_generating) {
      request.response
        ..statusCode = 429
        ..write(jsonEncode({'error': '正在生成中，请稍候'}))
        ..close();
      return;
    }

    if (stream) {
      request.response
        ..statusCode = 200
        ..headers.contentType = ContentType.parse('text/event-stream')
        ..headers.set('Cache-Control', 'no-cache');
      await _streamChat(controller, messages, request.response);
    } else {
      final result = await _fullChat(controller, messages);
      _writeJson(request, result);
    }
  }

  ChatMessage _toChatMessage(dynamic m) {
    final map = m as Map<String, dynamic>;
    return ChatMessage(
      role: map['role'] as String? ?? 'user',
      content: map['content'] as String? ?? '',
    );
  }

  String? _inferTemplate() {
    final name = _currentModelName?.toLowerCase() ?? '';
    if (name.contains('qwen')) return 'chatml';
    if (name.contains('llama')) return 'llama2';
    if (name.contains('phi')) return 'phi';
    if (name.contains('gemma')) return 'gemma';
    if (name.contains('mistral')) return 'mistral';
    if (name.contains('zephyr')) return 'zephyr';
    if (name.contains('vicuna')) return 'vicuna';
    if (name.contains('alpaca')) return 'alpaca';
    return null;
  }

  Future<Map<String, dynamic>> _fullChat(
    LlamaController controller,
    List<dynamic> messages,
  ) async {
    final texts = <String>[];
    _generating = true;
    try {
      final chatMessages = messages.map(_toChatMessage).toList();
      final template = _inferTemplate();
      debugPrint('[LocalInference] Template: $template, msgs: ${messages.length}');

      await for (final token in controller.generateChat(
        messages: chatMessages,
        template: template,
        maxTokens: 512,
        temperature: 0.7,
      )) {
        texts.add(token);
      }
    } finally {
      _generating = false;
    }

    return {
      'id': 'chatcmpl-${DateTime.now().millisecondsSinceEpoch}',
      'object': 'chat.completion',
      'created': DateTime.now().millisecondsSinceEpoch ~/ 1000,
      'model': _currentModelName,
      'choices': [
        {
          'index': 0,
          'message': {'role': 'assistant', 'content': texts.join()},
          'finish_reason': 'stop',
        }
      ],
      'usage': {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0},
    };
  }

  Future<void> _streamChat(
    LlamaController controller,
    List<dynamic> messages,
    HttpResponse response,
  ) async {
    _generating = true;
    final id = 'chatcmpl-${DateTime.now().millisecondsSinceEpoch}';
    try {
      final chatMessages = messages.map(_toChatMessage).toList();
      final template = _inferTemplate();
      int idx = 0;

      await for (final token in controller.generateChat(
        messages: chatMessages,
        template: template,
        maxTokens: 512,
        temperature: 0.7,
      )) {
        final chunk = {
          'id': id,
          'object': 'chat.completion.chunk',
          'created': DateTime.now().millisecondsSinceEpoch ~/ 1000,
          'model': _currentModelName,
          'choices': [
            {
              'index': idx++,
              'delta': {'content': token},
              'finish_reason': null,
            }
          ],
        };
        response.write('data: ${jsonEncode(chunk)}\n\n');
        await response.flush();
      }

      response.write('data: ${jsonEncode({
        'id': id,
        'object': 'chat.completion.chunk',
        'created': DateTime.now().millisecondsSinceEpoch ~/ 1000,
        'model': _currentModelName,
        'choices': [
          {'index': idx, 'delta': {}, 'finish_reason': 'stop'}
        ],
      })}\n\n');
      response.write('data: [DONE]\n\n');
    } finally {
      _generating = false;
      await response.close();
    }
  }

  void _writeJson(HttpRequest req, Map<String, dynamic> data, [int code = 200]) {
    req.response
      ..statusCode = code
      ..headers.contentType = ContentType.json
      ..write(jsonEncode(data))
      ..close();
  }

  Future<void> _cleanup() async {
    try {
      await _controller?.dispose();
    } catch (_) {}
    _controller = null;
    try {
      await _server?.close(force: true);
    } catch (_) {}
    _server = null;
    _generating = false;
  }

  /// 停止并释放
  Future<void> stop() async {
    await _cleanup();
    _loading = false;
    debugPrint('[LocalInference] Stopped');
  }
}