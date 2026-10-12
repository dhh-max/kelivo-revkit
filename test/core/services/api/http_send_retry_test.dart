import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'package:Kelivo/core/services/api/http_send_retry.dart';

void main() {
  test('permanent quota 429 (GoUsage monthly) is not retried', () async {
    var calls = 0;
    final client = MockClient((request) async {
      calls++;
      return http.Response(
        jsonEncode({
          'error': {
            'type': 'GoUsageLimitError',
            'message': 'Monthly usage limit reached. Resets in 8 days.',
          },
        }),
        429,
        headers: {'content-type': 'application/json'},
      );
    });
    final response = await HttpSendRetry.send(
      client,
      () => http.Request('POST', Uri.parse('http://example.com/chat')),
      maxAttempts: 3,
    );
    expect(calls, 1, reason: '永久配额 429 不应退避重试');
    expect(response.statusCode, 429);
  });

  test('transient 429 without quota marker is retried then returned', () async {
    var calls = 0;
    final client = MockClient((request) async {
      calls++;
      if (calls < 3) {
        return http.Response('{"error":"overloaded"}', 429,
            headers: {'content-type': 'application/json'});
      }
      return http.Response('ok', 200);
    });
    final response = await HttpSendRetry.send(
      client,
      () => http.Request('POST', Uri.parse('http://example.com/chat')),
      maxAttempts: 3,
    );
    expect(calls, 3, reason: '非配额 429 应退避重试到成功或达上限');
    expect(response.statusCode, 200);
  });

  test('permanent quota detection matches common markers', () async {
    for (final body in [
      'Monthly usage limit reached.',
      '{"type":"GoUsageLimitError","message":"usage limit"}',
      'insufficient_quota',
      'quota exceeded for the workspace',
    ]) {
      final client = MockClient((request) async {
        return http.Response(body, 429);
      });
      final response = await HttpSendRetry.send(
        client,
        () => http.Request('POST', Uri.parse('http://example.com/chat')),
        maxAttempts: 3,
      );
      expect(response.statusCode, 429);
    }
  });
}
