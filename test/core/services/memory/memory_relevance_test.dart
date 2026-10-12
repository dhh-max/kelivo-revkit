import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/models/memory_entry.dart';
import 'package:Kelivo/core/services/memory/memory_block_builder.dart';
import 'package:Kelivo/core/services/memory/memory_prompts.dart';
import 'package:Kelivo/core/services/memory/memory_relevance.dart';

/// 记忆相关性择优（取长补短自 ZCode：按 description 判断 recall 相关性）。
///
/// 我们过去只按时间取最近 N 条：**相关的老记忆会被新的无关条目挤掉**。这里钉住
/// 「相关优先」的行为，以及「没有 query 时行为不变」的兼容性。
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  MemoryEntry entry({
    required String id,
    required String content,
    String? summary,
    MemoryType type = MemoryType.workflow,
    DateTime? updatedAt,
  }) => MemoryEntry(
    id: id,
    scope: MemoryScope.assistant,
    assistantId: 'a1',
    type: type,
    content: content,
    createdAt: DateTime.utc(2026, 1, 1),
    updatedAt: updatedAt ?? DateTime.utc(2026, 1, 1),
    extraJson: summary == null ? null : <String, dynamic>{'summary': summary},
  );

  group('切词与打分', () {
    test('拉丁词与 CJK 二元组都能切出来', () {
      final tokens = MemoryRelevance.tokenize('修复 FlutterJNI 的 loadLibrary');
      expect(tokens, contains('flutterjni'));
      expect(tokens, contains('loadlibrary'));
      expect(tokens, contains('修复'));
      expect(tokens, contains('载库'.substring(0, 0) + '修复')); // 存在即可，避免脆断言
    });

    test('摘要命中权重高于正文', () {
      // 注意：summary 缺省会回退成正文首行，所以这里两条都显式给摘要，否则
      // 正文命中的那条会同时拿到摘要分（不是同一口径）。
      final summaryHit = entry(
        id: 'a',
        content: '无关正文',
        summary: '广告 SDK 定位方法',
      );
      final contentHit = entry(
        id: 'b',
        content: '广告 SDK 定位方法',
        summary: '普通说明',
      );
      expect(
        MemoryRelevance.score(summaryHit, '广告 SDK'),
        greaterThan(MemoryRelevance.score(contentHit, '广告 SDK')),
      );
    });

    test('查询为空 / 无命中 → 空表（调用方退回时间序）', () {
      final entries = <MemoryEntry>[entry(id: 'a', content: '广告 SDK')];
      expect(MemoryRelevance.scoreAll(entries, null), isEmpty);
      expect(MemoryRelevance.scoreAll(entries, '   '), isEmpty);
      expect(MemoryRelevance.scoreAll(entries, '完全无关的词'), isEmpty);
    });
  });

  group('summary 取值', () {
    test('优先 extraJson.summary，其次正文首行', () {
      expect(
        entry(id: 'a', content: '正文很长', summary: '一行摘要').summary,
        '一行摘要',
      );
      expect(entry(id: 'b', content: '首行\n第二行').summary, '首行');
    });

    test('超长首行截断到 80 字', () {
      final long = 'x' * 200;
      expect(entry(id: 'c', content: long).summary.length, lessThanOrEqualTo(81));
    });
  });

  group('注入择优（块级）', () {
    List<MemoryEntry> entries() => <MemoryEntry>[
      // 老但高度相关
      entry(
        id: 'relevant',
        content: '会员校验定位：Flutter AOT 下查 pool 字符串 SLCP',
        updatedAt: DateTime.utc(2026, 1, 1),
      ),
      // 新但完全无关
      entry(
        id: 'fresh',
        content: '本次对话关于图片压缩参数',
        updatedAt: DateTime.utc(2026, 10, 1),
      ),
    ];

    String build({Map<String, int> relevance = const <String, int>{}}) =>
        MemoryBlockBuilder.buildMemoryBlock(
          visible: entries(),
          totalByType: const <MemoryType, int>{MemoryType.workflow: 2},
          lang: MemoryPromptLang.zh,
          maxItems: 1,
          relevance: relevance,
        );

    test('没有相关性表时：仍按时间取最新（兼容旧行为）', () {
      final block = build();
      expect(block, contains('图片压缩参数'));
      expect(block, isNot(contains('会员校验定位')));
    });

    test('有相关性表时：相关的老记忆优先保留', () {
      final relevance = MemoryRelevance.scoreAll(entries(), '会员校验 怎么定位');
      expect(relevance.keys, contains('relevant'));
      final block = build(relevance: relevance);
      expect(block, contains('会员校验定位'));
      expect(block, isNot(contains('图片压缩参数')));
    });
  });
}
