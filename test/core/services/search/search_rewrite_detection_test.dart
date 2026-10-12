import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/search/search_service.dart';
import 'package:Kelivo/core/services/search/search_tool_service.dart';

/// F-04 守护（2026-10-05 v11 复测）：搜索服务按首词实体改写查询时，
/// 被吞掉的查询词在全部结果里 0 命中——这就是「丢词」的硬判据。
void main() {
  SearchResultItem item(String title, String url, String text) =>
      SearchResultItem(title: title, url: url, text: text);

  _rewriteRetry();

  group('F-04 查询词保留度检测', () {
    test('品牌词吞词：AWS/Lambda 在 10 条 amazon 零售结果里 0 命中', () {
      final items = <SearchResultItem>[
        for (var i = 0; i < 10; i++)
          item(
            'Amazon.com: 商品 $i',
            'https://www.amazon.com/dp/$i',
            'amazon 零售与卖家页',
          ),
      ];
      final dropped = SearchToolService.droppedQueryTerms(
        'Amazon AWS Lambda tutorial',
        items,
      );
      expect(dropped, containsAll(<String>['aws', 'lambda']));
      expect(dropped, isNot(contains('amazon')));
      expect(dropped.length, lessThan(4), reason: '不是全丢场景');
    });

    test('正常结果：所有查询词都有命中 → 不报丢词', () {
      final items = <SearchResultItem>[
        item(
          'AWS Lambda tutorial',
          'https://docs.aws.amazon.com/lambda',
          'Amazon AWS Lambda 入门教程',
        ),
      ];
      expect(
        SearchToolService.droppedQueryTerms(
          'Amazon AWS Lambda tutorial',
          items,
        ),
        isEmpty,
      );
    });

    test('单关键词查询不判（信息不足，避免误报）', () {
      final items = <SearchResultItem>[
        item('Amazon', 'https://amazon.com', ''),
      ];
      expect(SearchToolService.droppedQueryTerms('Amazon', items), isEmpty);
    });

    test('停用词不参与核对（the/of 不算丢词）', () {
      final items = <SearchResultItem>[
        item('AWS Lambda guide', 'https://example.com', 'lambda 教程'),
      ];
      expect(
        SearchToolService.droppedQueryTerms(
          'the AWS Lambda of guide',
          items,
        ),
        isEmpty,
      );
    });

    test('中文查询按词核对', () {
      final items = <SearchResultItem>[
        item('国产手机推荐', 'https://example.com', '手机选购指南'),
      ];
      expect(
        SearchToolService.droppedQueryTerms('国产 手机 评测', items),
        <String>['评测'],
      );
    });

    test('结果与全部查询词都不匹配 → 全丢（疑似整体降级）', () {
      final items = <SearchResultItem>[
        item('无关内容', 'https://x.com', 'nothing relevant'),
      ];
      expect(
        SearchToolService.droppedQueryTerms('AWS Lambda', items),
        hasLength(2),
      );
    });

    test('空结果集不判（降级路径另有 degradation 字段）', () {
      expect(
        SearchToolService.droppedQueryTerms('AWS Lambda', <SearchResultItem>[]),
        isEmpty,
      );
    });
  });
}

/// F-04 自动重试的查询重写（v13：光提示不够，检索本身要能自救）。
void _rewriteRetry() {
  group('F-04 重写查询', () {
    test('被吞的词提到最前，其余按原序跟上', () {
      expect(
        SearchToolService.rewriteQueryForRetry(
          'Amazon AWS Lambda tutorial',
          <String>['aws', 'lambda'],
        ),
        'aws lambda Amazon tutorial',
      );
    });

    test('没有丢词时返回空（不重试）', () {
      expect(
        SearchToolService.rewriteQueryForRetry('AWS Lambda', const <String>[]),
        isEmpty,
      );
    });

    test('候选②去首词：实体改写的元凶是首词时，其余词全保住', () {
      // v14：只提前被吞词（候选①）仍会被吞 lambda/tutorial，去首词才可能全保住。
      expect(
        SearchToolService.rewriteQueryDropLeading(
          'Amazon AWS Lambda tutorial',
          <String>['aws', 'lambda', 'tutorial'],
        ),
        'AWS Lambda tutorial',
      );
      expect(
        SearchToolService.rewriteQueryDropLeading('AWS Lambda', const <String>[]),
        isEmpty,
        reason: '没有丢词就不该产生候选',
      );
      expect(
        SearchToolService.rewriteQueryDropLeading('Lambda', <String>['lambda']),
        isEmpty,
        reason: '单关键词没有「去掉首词」的余地',
      );
    });

    test('重写后的查询再核对：丢词变少（模拟服务端实体改写被打破）', () {
      final rewritten = SearchToolService.rewriteQueryForRetry(
        'Amazon AWS Lambda tutorial',
        <String>['aws', 'lambda', 'tutorial'],
      );
      expect(rewritten.startsWith('aws lambda tutorial'), isTrue);
    });
  });
}
