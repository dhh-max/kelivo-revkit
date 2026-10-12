import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/api/retry_policy.dart';

/// 断线自动重发的传输判据（2026-10-03：切网络后必须自动再次发起请求）。
void main() {
  test('传输类断线：SocketException / Timeout / dio 连接错误 都判真', () {
    expect(isTransportRetryableError(const SocketException('down')), isTrue);
    expect(isTransportRetryableError(TimeoutException('slow')), isTrue);
    expect(
      isTransportRetryableError(
        DioException(
          requestOptions: RequestOptions(path: '/x'),
          type: DioExceptionType.connectionError,
        ),
      ),
      isTrue,
    );
    expect(
      isTransportRetryableError(
        DioException(
          requestOptions: RequestOptions(path: '/x'),
          type: DioExceptionType.receiveTimeout,
        ),
      ),
      isTrue,
    );
  });

  test('非传输类：HTTP 4xx/5xx、取消、业务错误都不触发自动重发', () {
    expect(
      isTransportRetryableError(
        DioException(
          requestOptions: RequestOptions(path: '/x'),
          type: DioExceptionType.badResponse,
          response: Response(
            requestOptions: RequestOptions(path: '/x'),
            statusCode: 500,
          ),
        ),
      ),
      isFalse,
    );
    expect(
      isTransportRetryableError(
        DioException(
          requestOptions: RequestOptions(path: '/x'),
          type: DioExceptionType.cancel,
        ),
      ),
      isFalse,
      reason: '用户停止不能被当成断线重发',
    );
    expect(isTransportRetryableError(StateError('boom')), isFalse);
  });
}
