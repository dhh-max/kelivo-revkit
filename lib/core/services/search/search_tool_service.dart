import 'dart:convert';
import 'package:uuid/uuid.dart';
import 'search_service.dart';
import '../../providers/settings_provider.dart';

class SearchToolService {
  static const String toolName = 'search_web';
  static const String toolDescription = '''
Search the web for current information, news, and real-time data.

Use this when:
- The user asks about recent events, current prices, or live data
- You need to verify facts you are uncertain about or that may have changed
- The user references something you don't have context on (products, people, docs, APIs)

Don't use for:
- Math, code reasoning, or things you can answer from your training
- Well-known facts unlikely to have changed

Write focused keyword queries, not full sentences. You may call this multiple times to broaden coverage:
- If the topic likely has more authoritative sources in another language (English for tech/scientific topics, the local language for regional news), repeat the search with the query translated into that language.
- If the first results miss an angle, refine with synonyms or sub-aspects.

Response format:
- items[]: search results, each with index (result number), id (short unique id), title, url, text
- answer: an optional pre-synthesized answer (may be absent)

Cite: append [cite:id] immediately after each statement a result supports, using that result's exact `id` field.''';

  static final RegExp _schemeRe = RegExp(r'^[a-zA-Z][a-zA-Z0-9+.-]*:');

  /// 查询里的停用词（只去冠词/介词这类纯语法词；how/what/tutorial 属内容词，
  /// 保留参与丢词核对——它们恰恰是技术查询里最容易被实体改写吞掉的词）。
  static const Set<String> _stopWords = <String>{
    'the', 'a', 'an', 'of', 'to', 'in', 'on', 'for', 'and', 'or',
    'with', 'at', 'by', 'from', 'is', 'are', 'be',
  };

  /// 逐词核对：返回在结果集里 **0 命中** 的有意义查询词。
  ///
  /// 这是 F-04 的硬判据（v11 复测：旧启发只看条数/跳转包装，10 条实体域结果
  /// 整条漏检）。搜索服务按首词实体改写查询时，被吞掉的词在全部结果的
  /// title/url/text 里一次都不会出现——所以「0 命中」就是丢词特征本身。
  static List<String> droppedQueryTerms(
    String query,
    List<SearchResultItem> items,
  ) {
    if (items.isEmpty) return const <String>[];
    final terms = _meaningfulTerms(query);
    if (terms.length < 2) return const <String>[];
    final haystack = <String>[
      for (final item in items)
        '${item.title}\n${item.url}\n${item.text}'.toLowerCase(),
    ];
    return <String>[
      for (final term in terms)
        if (!haystack.any((text) => text.contains(term))) term,
    ];
  }

  /// 查询 → 有意义的词（小写；长度 ≥2；去停用词；去重）。
  static List<String> _meaningfulTerms(String query) {
    final tokens = query.toLowerCase().split(
      RegExp(r'[^\p{L}\p{N}_+#.]+', unicode: true),
    );
    final terms = <String>[];
    for (final token in tokens) {
      final term = token.replaceAll(RegExp(r'^[._+#]+|[._+#]+$'), '');
      if (term.length < 2) continue;
      if (_stopWords.contains(term)) continue;
      if (!terms.contains(term)) terms.add(term);
    }
    return terms;
  }

  /// 丢词场景的候选改写②：去掉**首词**（实体改写通常由首词触发），其余原样保留。
  ///
  /// "Amazon AWS Lambda tutorial" → "AWS Lambda tutorial"——v14 复测：只把被吞
  /// 词提前（候选①）仍会被服务吞掉 lambda/tutorial，去首词才可能全保住。
  static String rewriteQueryDropLeading(String query, List<String> droppedTerms) {
    if (droppedTerms.isEmpty) return '';
    final tokens = query
        .split(RegExp(r'\s+'))
        .where((t) => t.trim().isNotEmpty)
        .toList(growable: false);
    if (tokens.length < 2) return '';
    return tokens.sublist(1).join(' ').trim();
  }

  /// 丢词场景的候选改写③：把被吞词**逐个加引号**（精确匹配），其余按原序跟上。
  ///
  /// "Amazon AWS Lambda tutorial" → `"aws" "lambda" tutorial Amazon`。
  /// v16：候选①（提前）与②（去首词）都被服务吞词时，引号短语是最后一道硬约束。
  static String rewriteQueryWithQuotedDropped(
    String query,
    List<String> droppedTerms,
  ) {
    if (droppedTerms.isEmpty) return '';
    final kept = <String>[
      for (final token in query.split(RegExp(r'\s+')))
        if (token.trim().isNotEmpty &&
            !droppedTerms.contains(token.toLowerCase()))
          token.trim(),
    ];
    return <String>[
      for (final term in droppedTerms) '"$term"',
      ...kept,
    ].join(' ').trim();
  }

  /// 丢词场景的重写查询：把被吞掉的词**提到最前**，其余按原序跟上。
  ///
  /// 搜索服务按「首词实体」改写时，把关键术语放首位能改变实体判定
  /// （"Amazon AWS Lambda tutorial" → "AWS Lambda tutorial Amazon"）。
  static String rewriteQueryForRetry(String query, List<String> droppedTerms) {
    if (droppedTerms.isEmpty) return '';
    final kept = <String>[
      for (final token in query.split(RegExp(r'\s+')))
        if (token.trim().isNotEmpty && !droppedTerms.contains(token.toLowerCase()))
          token.trim(),
    ];
    return <String>[
      ...droppedTerms,
      ...kept,
    ].join(' ').trim();
  }

  static String _normalizeUrl(String raw) {
    var u = raw.trim();
    if (u.isEmpty) return u;

    // Strip surrounding quotes if the backend returns a JSON-ish value.
    if ((u.startsWith('"') && u.endsWith('"')) ||
        (u.startsWith("'") && u.endsWith("'"))) {
      u = u.substring(1, u.length - 1).trim();
    }
    if (u.isEmpty) return u;

    // Protocol-relative URL (e.g. //example.com/path)
    if (u.startsWith('//')) return 'https:$u';

    // No scheme => default to https.
    if (!_schemeRe.hasMatch(u)) return 'https://$u';
    return u;
  }

  static Map<String, dynamic> getToolDefinition() {
    return {
      'type': 'function',
      'function': {
        'name': toolName,
        'description': toolDescription,
        'parameters': {
          'type': 'object',
          'properties': {
            'query': {
              'type': 'string',
              'description': 'The search query to look up online',
            },
          },
          'required': ['query'],
        },
      },
    };
  }

  static Future<String> executeSearch(
    String query,
    SettingsProvider settings,
  ) async {
    try {
      // Get selected search service
      final services = settings.searchServices;
      if (services.isEmpty) {
        return jsonEncode({'error': 'No search services configured'});
      }

      final selectedIndex = settings.searchServiceSelected.clamp(
        0,
        services.length - 1,
      );
      final service = SearchService.getService(services[selectedIndex]);

      // 执行搜索
      var result = await service.search(
        query: query,
        commonOptions: settings.searchCommonOptions,
        serviceOptions: services[selectedIndex],
      );

      // v13 复测（F-04）：光提示丢词不够——结果本身没用。检测到「被首词实体
      // 改写」的特征时自动重试；v14 复测：只把被吞词提前仍会丢词
      // （droppedAfter 还有 lambda/tutorial），所以跑**两条候选**取最优：
      // ①被吞词提前；②去掉首词。逐条试、丢词最少者胜、清零即收手。
      var queryUsed = query;
      Map<String, Object?>? rewriteRetry;
      final droppedFirst = droppedQueryTerms(query, result.items);
      if (droppedFirst.isNotEmpty &&
          result.items.isNotEmpty &&
          result.degradation == null) {
        final attempts = <Map<String, Object?>>[];
        final candidates = <String>{
          rewriteQueryForRetry(query, droppedFirst),
          rewriteQueryDropLeading(query, droppedFirst),
          // v16 复测：往前移/去首词都试过仍被吞时，用**加引号的精确匹配**再试
          // 一次（多数服务端对引号短语不做实体改写）。
          rewriteQueryWithQuotedDropped(query, droppedFirst),
        };
        for (final candidate in candidates) {
          if (candidate.isEmpty || candidate == query) continue;
          try {
            final retry = await service.search(
              query: candidate,
              commonOptions: settings.searchCommonOptions,
              serviceOptions: services[selectedIndex],
            );
            if (retry.items.isEmpty || retry.degradation != null) continue;
            final droppedRetry = droppedQueryTerms(candidate, retry.items);
            attempts.add(<String, Object?>{
              'query': candidate,
              'droppedAfter': droppedRetry,
            });
            if (droppedRetry.length <
                droppedQueryTerms(queryUsed, result.items).length) {
              queryUsed = candidate;
              result = retry;
            }
            if (droppedRetry.isEmpty) break; // 词全保住，不再试下一条
          } catch (_) {
            // 单条候选失败不影响其余候选与原结果。
          }
        }
        if (attempts.isNotEmpty && queryUsed != query) {
          rewriteRetry = <String, Object?>{
            'from': query,
            'to': queryUsed,
            'droppedBefore': droppedFirst,
            'droppedAfter': droppedQueryTerms(queryUsed, result.items),
            'attempts': attempts,
          };
        }
      }

      // Add unique IDs to each result item
      final itemsWithIds = result.items.asMap().entries.map((entry) {
        final item = entry.value;
        return SearchResultItem(
          title: item.title,
          url: _normalizeUrl(item.url),
          text: item.text,
          id: const Uuid().v4().substring(0, 6),
          index: entry.key + 1,
        );
      }).toList();

      // 导航型结果集提示（2026-10-03 报告 F-04）：搜索服务可能按首词实体改写
      // 查询（技术查询会静默返回品牌/导航结果域）。识别特征：命中过跳转包装
      // 或结果数很少——如实标注，别让模型把这些当权威结果。
      final unwrappedCount = result.items.where((item) {
        final uri = Uri.tryParse(item.url);
        return uri != null && uri.host.contains('bing.com') && uri.path.contains('/ck/a');
      }).length;
      final looksNavigational = result.items.isNotEmpty &&
          (result.items.length <= 4 || unwrappedCount > result.items.length ~/ 2);

      // v11/v13 复测（F-04）：上面这条只看「条数/跳转包装」，10 条实体域结果
      // 时整条漏检——"Amazon AWS Lambda tutorial" 返回 10 条 amazon.* 零售页，
      // 既没有 hint 也没有丢词说明。逐词核对才是硬判据：查询里每个有意义的词
      // 至少在一条结果的 title/url/text 里出现过。
      final droppedTerms = droppedQueryTerms(queryUsed, result.items);

      // Return formatted result
      return jsonEncode({
        if (result.answer != null) 'answer': result.answer,
        'query': query,
        if (queryUsed != query) 'queryUsed': queryUsed,
        if (rewriteRetry != null) 'rewriteRetry': rewriteRetry,
        'items': itemsWithIds.map((item) => item.toJson()).toList(),
        if (droppedTerms.isNotEmpty) 'droppedQueryTerms': droppedTerms,
        if (droppedTerms.isNotEmpty)
          'queryRewriteHint': droppedTerms.length == _meaningfulTerms(queryUsed).length
              ? '结果与查询词（${droppedTerms.join('、')}）**全部不匹配**：搜索服务疑似整体'
                    '改写/降级，当前结果不可信——换一个搜索服务，或换查询词重试。'
              : '疑似按首词实体改写（实测：品牌词放首位的技术查询会丢词）：结果中 0 条包含'
                    '「${droppedTerms.join('、')}」。换词序（把最关键的词放前面）、加限定词或'
                    '用 site: 运算符重试；不要把当前结果当作该主题的权威来源。'
        else if (looksNavigational)
          'queryRewriteHint':
              '结果集看起来是首词的导航型命中（条数少/大量跳转链接）——搜索服务可能'
              '把查询按实体改写了（实测：品牌词放首位的技术查询会丢词）。'
              '换词序、加限定词或用 site: 运算符重试，别把这些结果当权威。',
        // D21（2026-09-21 自检）：降级状态原样透出。此前服务层抛裸异常，这里只能
        // 回一句 'Search failed: ...'，调用方既分不清"网络不可达"与"上游拒绝"，
        // 也无法判断该不该重试——整条链路被打断。
        if (result.degradation != null)
          'degradation': result.degradation!.toJson(),
        if (result.degradation != null)
          'note':
              '本次外部搜索未成功（${result.degradation!.code}），已跳过而不是中断。'
                  'items 为空**不代表网上没有相关信息**；用已有证据继续，或换一个可达的搜索服务后重试。',
      });
    } catch (e) {
      // 兜底：连服务层都没起来（配置错误等）。仍然给结构化降级状态，不裸抛。
      return jsonEncode({
        'error': 'Search failed: $e',
        'degradation': SearchDegradation.fromError(
          e,
          provider: 'unknown',
        ).toJson(),
      });
    }
  }

  static String getSystemPrompt() {
    return '''
<citations>
When a statement in your answer is based on a search_web result, append a citation marker immediately after that statement: [cite:id], where id is the exact `id` field of the supporting result item.
- Example: "The event took place yesterday afternoon. [cite:a1b2c3]"
- Chain markers when several results support one statement: [cite:a1b2c3][cite:d4e5f6]
- Copy ids exactly as returned by the tool. Never invent, renumber, or reuse ids from other results.
- Place markers inline right after the supported statement (after its punctuation). Do not collect them at the end of the response, and do not add a "References" or "Sources" section — the app renders citations from the inline markers.
- Statements from your own knowledge take no marker.
</citations>
''';
  }
}
