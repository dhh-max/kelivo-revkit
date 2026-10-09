import 'dart:async';
import 'dart:convert';
import 'dart:io' show SocketException;

import 'package:flutter/material.dart';
import 'package:html/parser.dart' as parser;
import '../../../../l10n/app_localizations.dart';
import '../search_service.dart';

class BingSearchService extends SearchService<BingLocalOptions> {
  @override
  String get name => 'Bing (Local)';

  @override
  Widget description(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return Text(
      l10n.searchProviderBingLocalDescription,
      style: const TextStyle(fontSize: 12),
    );
  }

  @override
  Future<SearchResult> search({
    required String query,
    required SearchCommonOptions commonOptions,
    required BingLocalOptions serviceOptions,
  }) async {
    final timeout = Duration(milliseconds: commonOptions.timeout);
    try {
      final encodedQuery = Uri.encodeComponent(query);
      final url = 'https://www.bing.com/search?q=$encodedQuery';

      final response = await withHttpClient(
        (client) => client
            .get(
              Uri.parse(url),
              headers: {
                'User-Agent':
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept-Language': serviceOptions.acceptLanguage,
              },
            )
            .timeout(timeout),
      );

      if (response.statusCode != 200) {
        // D21：上游拒绝/限流是**可分类**的状态，不是"搜索失败"一句了事。
        return SearchResult(
          items: const [],
          degradation: SearchDegradation.fromError(
            Exception('Failed to fetch results: ${response.statusCode}'),
            provider: name,
          ),
        );
      }

      final document = parser.parse(response.body);
      final results = <SearchResultItem>[];

      final elements = document.querySelectorAll('li.b_algo');
      for (final element in elements.take(commonOptions.resultSize)) {
        final titleElement = element.querySelector('h2');
        final linkElement = element.querySelector('h2 > a');
        final snippetElement = element.querySelector(
          '.b_caption p, .b_algoSlug',
        );

        if (titleElement != null && linkElement != null) {
          results.add(
            SearchResultItem(
              title: titleElement.text.trim(),
              url: _unwrapBingRedirect(linkElement.attributes['href'] ?? ''),
              text: snippetElement?.text.trim() ?? '',
            ),
          );
        }
      }

      // 200 但一条都解析不出来：页面结构变了或被反爬挡了。这是**降级**而不是
      // 空结果——两者对调用方的含义完全不同（"没人讨论"vs"我没搜到"）。
      if (results.isEmpty) {
        return SearchResult(
          items: const [],
          degradation: SearchDegradation(
            code: 'parse_failed',
            message:
                'Bing 返回 200 但未解析出任何结果（页面结构变化或被反爬拦截）：本次外部搜索按失败处理，'
                '不要据此判断"网上没有相关信息"。',
            provider: name,
            retryable: false,
          ),
        );
      }

      return SearchResult(items: results);
    } on TimeoutException catch (e) {
      return SearchResult(
        items: const [],
        degradation: SearchDegradation.fromError(
          e,
          provider: name,
          timeout: timeout,
        ),
      );
    } on SocketException catch (e) {
      return SearchResult(
        items: const [],
        degradation: SearchDegradation.fromError(e, provider: name),
      );
    } catch (e) {
      // D21：不再抛裸异常——链路不能因为一次外部搜索不可达而中断。
      return SearchResult(
        items: const [],
        degradation: SearchDegradation.fromError(e, provider: name),
      );
    }
  }
}

/// 解开 Bing 的点击跟踪跳转（`bing.com/ck/a?...&u=a1<base64url>&...` → 目标直链）。
/// 2026-10-03 报告 F-20：降级路径返回的 `ck/a` 包装链接带 fclid/ptn 等易过期参数，
/// 喂给 fetch 拿到的是跳转页而不是目标站。解不开就原样返回。
String _unwrapBingRedirect(String href) {
  if (href.isEmpty) return href;
  final uri = Uri.tryParse(href);
  if (uri == null) return href;
  if (!uri.host.contains('bing.com') || !uri.path.contains('/ck/a')) return href;
  final u = uri.queryParameters['u'];
  if (u == null || u.isEmpty) return href;
  // Bing 用 `a1` + base64url(目标) 的包装。
  var payload = u;
  if (payload.startsWith('a1')) payload = payload.substring(2);
  try {
    final normalized = base64Url.normalize(payload);
    final decoded = utf8.decode(base64Url.decode(normalized), allowMalformed: true);
    if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
      return decoded;
    }
  } catch (_) {}
  return href;
}
