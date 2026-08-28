import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:Kelivo/relaygo/config/environment.dart';
import 'package:Kelivo/relaygo/models/api_key.dart';
import 'package:Kelivo/relaygo/utils/encryption.dart';

/// 网关健康自检：探测各 Key 上游连通性。
///
/// 对一组 ApiKey 做轻量上游连通性探测（GET {base}/models），
/// 供 /relay/health 接口与控制台状态展示。
class HealthProbe {
  static const Duration probeTimeout = Duration(seconds: 5);
  static const int maxKeysPerProbe = 30;

  final HttpClient? _client;
  HttpClient get _http => _client ?? HttpClient();

  HealthProbe({HttpClient? client}) : _client = client;

  Future<void> aclose() async {
    _client?.close();
  }

  /// 探测单个 Key：GET {base}/models 是否可达。
  Future<Map<String, dynamic>> probeKey(ApiKey key) async {
    final result = <String, dynamic>{
      'key_id': key.id,
      'name': key.name,
      'provider': key.provider,
      'ok': false,
      'latency_ms': 0,
      'error': '',
    };

    final base = Environment.providerBaseUrls[key.provider] ?? '';
    final keyBase = key.baseUrl ?? '';
    final resolvedBase = keyBase.isNotEmpty ? keyBase : base;
    if (resolvedBase.isEmpty) {
      result['error'] = 'base_url 无法解析';
      return result;
    }

    String plainKey;
    try {
      plainKey = Encryption.decrypt(key.encryptedKey);
    } catch (e) {
      result['error'] = '密钥解密失败: $e';
      return result;
    }
    if (plainKey.isEmpty) {
      result['error'] = '密钥为空';
      return result;
    }

    String url;
    Map<String, String> headers;
    if (key.provider == 'google') {
      url = '$resolvedBase/v1beta/models?key=$plainKey';
      headers = {};
    } else {
      url = '$resolvedBase/models';
      headers = {'Authorization': 'Bearer $plainKey'};
    }

    final stopwatch = Stopwatch()..start();
    try {
      final req = await _http.getUrl(Uri.parse(url)).timeout(probeTimeout);
      headers.forEach((k, v) => req.headers.set(k, v));
      final resp = await req.close().timeout(probeTimeout);
      stopwatch.stop();
      result['latency_ms'] = stopwatch.elapsedMilliseconds;
      if (resp.statusCode < 400) {
        result['ok'] = true;
      } else {
        result['error'] = 'HTTP ${resp.statusCode}';
      }
    } on TimeoutException {
      result['error'] = '连接超时';
    } catch (e) {
      result['error'] = '连接失败: $e';
    }
    return result;
  }

  /// 并发探测全部 Key（最多 maxKeysPerProbe 个）
  Future<List<Map<String, dynamic>>> probeAll(List<ApiKey> keys) async {
    final subset = keys.take(maxKeysPerProbe).toList();
    final results = await Future.wait(
      subset.map((k) => probeKey(k)),
    );
    return results;
  }

  /// 汇总
  static Map<String, dynamic> summary(List<Map<String, dynamic>> results) {
    final total = results.length;
    final ok = results.where((r) => r['ok'] == true).length;
    final latencies = results
        .where((r) => r['ok'] == true)
        .map((r) => r['latency_ms'] as int)
        .toList();
    final avg = latencies.isNotEmpty
        ? (latencies.reduce((a, b) => a + b) / latencies.length).round()
        : 0;
    return {
      'total': total,
      'ok': ok,
      'failed': total - ok,
      'up_rate': total > 0 ? (ok / total).toStringAsFixed(3) : '0.0',
      'avg_latency_ms': avg,
    };
  }
}