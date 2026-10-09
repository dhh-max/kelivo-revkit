import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/providers/world_book_provider.dart';

import '../../support/business_test_harness.dart';

/// 世界书种子：两个内置助手各一本随包知识书，各自绑定、互不串。
void main() {
  const apkAssistant = 'builtin-apk-mod';
  // 内置开发助手的真实助手 id（历史上这里写成 builtin-dev-assistant，
  // 导致种子知识书绑了个不存在的助手；2026-10-03 修）。
  const devAssistant = 'builtin-dev-agent';
  const wrongDevAssistant = 'builtin-dev-assistant';
  const apkBookId = 'apk_mod_knowledge_book';
  const devBookId = 'dev_knowledge_book';
  const apkVersionKey = 'apk_mod_knowledge_seed_version_world_book';
  const devVersionKey = 'dev_knowledge_seed_version_world_book';

  Future<WorldBookProvider> fresh() async {
    final preferences = createBusinessTestPreferences();
    final provider = WorldBookProvider(preferences: preferences);
    await provider.initialize();
    return provider;
  }

  test('初始化后两本知识书都在，且名称与助手对齐', () async {
    final provider = await fresh();

    final apkBook = provider.getById(apkBookId);
    final devBook = provider.getById(devBookId);
    expect(apkBook, isNotNull, reason: '逆向助手的知识书必须存在');
    expect(devBook, isNotNull, reason: '开发助手的知识书必须存在（此前只有逆向那本）');
    expect(apkBook!.name, '逆向助手 · 知识书');
    expect(devBook!.name, '开发助手 · 知识书');
    expect(devBook.entries.length, greaterThanOrEqualTo(5));
    expect(
      devBook.entries.every((entry) => entry.keywords.isNotEmpty),
      isTrue,
      reason: '每条都要有关键词，否则不会被激活',
    );
  });

  test('两本书各自绑定到对应助手，互不串', () async {
    final provider = await fresh();

    final apkActive = provider.activeBookIdsFor(apkAssistant);
    final devActive = provider.activeBookIdsFor(devAssistant);
    expect(apkActive, contains(apkBookId));
    expect(devActive, contains(devBookId));
    expect(apkActive, isNot(contains(devBookId)));
    expect(devActive, isNot(contains(apkBookId)));
    expect(
      provider.activeBookIdsFor(wrongDevAssistant),
      isEmpty,
      reason: '不存在的旧 id 不该有绑定（历史 bug 的回归锁）',
    );
  });

  test('重复初始化幂等：书不重复、绑定不重复', () async {
    final preferences = createBusinessTestPreferences();
    final provider = WorldBookProvider(preferences: preferences);
    await provider.initialize();
    final firstCount = provider.books.length;
    final firstDevActive = provider.activeBookIdsFor(devAssistant);

    // 再建一个 provider（同一份 preferences）模拟重启
    final again = WorldBookProvider(preferences: preferences);
    await again.initialize();
    expect(again.books.length, firstCount, reason: '重启不应重复播种');
    expect(again.books.where((b) => b.id == devBookId).length, 1);
    expect(again.activeBookIdsFor(devAssistant).toSet(), firstDevActive.toSet());
  });

  test('旧书名迁移：SoLab 知识书 → 逆向助手 · 知识书', () async {
    final preferences = createBusinessTestPreferences();
    // 预置旧状态：只有旧名的书 + 旧版本号
    final seed = WorldBookProvider(preferences: preferences);
    await seed.initialize();
    final oldBook = seed.getById(apkBookId)!;
    await seed.updateBook(oldBook.copyWith(name: 'SoLab 知识书'));
    await preferences.setInt(apkVersionKey, 29);

    final provider = WorldBookProvider(preferences: preferences);
    await provider.initialize();
    expect(provider.getById(apkBookId)!.name, '逆向助手 · 知识书');
  });

  test('v1 旧正文会被 v2 升级覆盖，但用户关掉的条目开关保留', () async {
    final preferences = createBusinessTestPreferences();
    final seed = WorldBookProvider(preferences: preferences);
    await seed.initialize();
    final book = seed.getById(devBookId)!;
    await seed.updateBook(
      book.copyWith(
        entries: [
          for (final entry in book.entries)
            if (entry.id == 'dev_entry_android_build')
              entry.copyWith(content: '旧的中文空话', enabled: false)
            else
              entry,
        ],
      ),
    );
    await preferences.setInt(devVersionKey, 1);

    final provider = WorldBookProvider(preferences: preferences);
    await provider.initialize();
    final upgraded = provider
        .getById(devBookId)!
        .entries
        .firstWhere((entry) => entry.id == 'dev_entry_android_build');
    expect(upgraded.content, isNot('旧的中文空话'));
    expect(upgraded.content, contains('exported'));
    expect(upgraded.enabled, isFalse, reason: '用户关掉的条目不能被内容升级重新打开');
  });

  test('用户改过的书名不被迁移覆盖', () async {    final preferences = createBusinessTestPreferences();
    final seed = WorldBookProvider(preferences: preferences);
    await seed.initialize();
    final oldBook = seed.getById(apkBookId)!;
    await seed.updateBook(oldBook.copyWith(name: '我自己改的名字'));
    await preferences.setInt(apkVersionKey, 29);

    final provider = WorldBookProvider(preferences: preferences);
    await provider.initialize();
    expect(provider.getById(apkBookId)!.name, '我自己改的名字');
  });
}
