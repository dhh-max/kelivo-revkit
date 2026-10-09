import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;

/// 发送层失败重连：对瞬态故障（连接被拒/中断/超时、HTTP 408/429/5xx）
/// 做有限次指数退避重试；业务性 4xx（如 schema 被拒的 400）不重试——
/// 重放同样的请求不会成功。仅在响应头到达、流未消费前判定，不对
/// 已建立的 SSE 流做中途续传。
abstract final class HttpSendRetry {
  static const Set<int> retryableStatusCodes = {408, 429, 500, 502, 503, 504};

  /// buildRequest 每次重新构造（http.Request 携带 body 字节后不可复用）。
  static Future<http.StreamedResponse> send(
    http.Client client,
    http.Request Function() buildRequest, {
    int maxAttempts = 3,
    Duration initialDelay = const Duration(milliseconds: 500),
  }) async {
    assert(maxAttempts >= 1);
    var delay = initialDelay;
    for (var attempt = 1; ; attempt++) {
      http.StreamedResponse response;
      try {
        response = await client.send(buildRequest());
      } on Exception catch (e) {
        if (!_isTransient(e) || attempt >= maxAttempts) rethrow;
        await Future<void>.delayed(delay);
        delay *= 2;
        continue;
      }
      if (!retryableStatusCodes.contains(response.statusCode) ||
          attempt >= maxAttempts) {
        return response;
      }
      // 429 可能是永久配额（GoUsage/monthly usage limit，重置需数天）——
      // 重试必然再 429，还浪费配额探测调用。读 body 判定，命中直接返回
      // 让上层报「配额耗尽」，不空等重试。
      if (response.statusCode == 429) {
        final body = await _readBodySafely(response);
        if (_isPermanentQuota(body)) return response;
      } else {
        // 瞬态状态码：先排空旧响应再退避重试，避免连接占用。
        await response.stream.drain<void>().catchError((_) {});
      }
      await Future<void>.delayed(delay);
      delay *= 2;
    }
  }

  /// 尽量读响应体（上限 64KB），失败返回空串（响应流已被 drain 则无法重试）。
  static Future<String> _readBodySafely(http.StreamedResponse response) async {
    try {
      final bytes = await response.stream
          .take(64 * 1024 + 1)
          .fold<List<int>>(<int>[], (acc, chunk) {
            if (acc.length > 64 * 1024) return acc;
            acc.addAll(chunk);
            return acc;
          });
      return String.fromCharCodes(bytes.take(64 * 1024));
    } catch (_) {
      return '';
    }
  }

  /// 永久配额/用量耗尽判定：GoUsage、usage limit、monthly、quota 等标记。
  /// 命中表示重试无意义（重置以天计），非瞬态限流（后者通常是秒级）。
  static bool _isPermanentQuota(String body) {
    final lower = body.toLowerCase();
    return lower.contains('usage limit') ||
        lower.contains('usage_limit') ||
        lower.contains('gousage') ||
        lower.contains('quota') ||
        lower.contains('monthly') ||
        lower.contains('insufficient_quota');
  }

  static bool _isTransient(Exception e) =>
      e is SocketException || e is TimeoutException || e is http.ClientException;
}
