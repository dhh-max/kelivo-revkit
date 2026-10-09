import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/search/search_service.dart';

/// D21（2026-09-21 自检）回归锁：外部搜索不可达时必须回**结构化降级状态**，
/// 而不是抛裸异常把整条调用链打断，也不能让"没搜到"和"网上没有"混为一谈。
void main() {
  group('SearchDegradation 分类', () {
    test('超时 → network_timeout 且可重试，文案说明"已跳过不是故障"', () {
      final d = SearchDegradation.fromError(
        TimeoutException('timed out'),
        provider: 'Bing (Local)',
        timeout: const Duration(milliseconds: 5000),
      );
      expect(d.code, 'network_timeout');
      expect(d.retryable, isTrue);
      expect(d.provider, 'Bing (Local)');
      expect(d.message, contains('5000ms'));
      expect(d.message, contains('已跳过'));
      expect(d.toJson()['skippedExternalSearch'], isTrue);
    });

    test('连接不可达 → network_unreachable', () {
      final d = SearchDegradation.fromError(
        const SocketException('Failed host lookup'),
        provider: 'Bing (Local)',
      );
      expect(d.code, 'network_unreachable');
      expect(d.retryable, isTrue);
    });

    test('上游非 200 → http_status 且不可重试（不是网络问题）', () {
      final d = SearchDegradation.fromError(
        Exception('Failed to fetch results: 429'),
        provider: 'Bing (Local)',
      );
      expect(d.code, 'http_status');
      expect(d.retryable, isFalse);
      expect(d.message, contains('429'));
    });

    test('未知异常也归类，不吞掉原文', () {
      final d = SearchDegradation.fromError(
        StateError('boom'),
        provider: 'X',
      );
      expect(d.code, 'unknown');
      expect(d.message, contains('boom'));
    });
  });

  group('SearchResult 携带降级状态', () {
    test('降级结果序列化后带 degradation，且 items 为空', () {
      final result = SearchResult(
        items: const [],
        degradation: const SearchDegradation(
          code: 'parse_failed',
          message: '页面结构变化',
          provider: 'Bing (Local)',
          retryable: false,
        ),
      );
      expect(result.isDegraded, isTrue);
      final json = jsonDecode(jsonEncode(result.toJson())) as Map<String, dynamic>;
      expect(json['items'], isEmpty);
      expect((json['degradation'] as Map)['code'], 'parse_failed');
      expect((json['degradation'] as Map)['retryable'], isFalse);
    });

    test('正常结果不带 degradation（不要把成功也标成降级）', () {
      final result = SearchResult(
        items: [
          SearchResultItem(title: 't', url: 'https://e.com', text: 'x'),
        ],
      );
      expect(result.isDegraded, isFalse);
      final json = jsonDecode(jsonEncode(result.toJson())) as Map<String, dynamic>;
      expect(json.containsKey('degradation'), isFalse);
    });

    test('往返：fromJson 能还原降级状态', () {
      final original = SearchResult(
        items: const [],
        degradation: const SearchDegradation(
          code: 'network_timeout',
          message: 'm',
          provider: 'p',
        ),
      );
      final restored = SearchResult.fromJson(
        jsonDecode(jsonEncode(original.toJson())) as Map<String, dynamic>,
      );
      expect(restored.isDegraded, isTrue);
      expect(restored.degradation!.code, 'network_timeout');
      expect(restored.degradation!.provider, 'p');
    });
  });
}
