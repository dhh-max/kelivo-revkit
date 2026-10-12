import 'dart:convert';

import 'package:solab/core/database/app_database.dart';
import 'package:solab/core/database/business_preferences.dart';
import 'package:solab/core/database/business_repository.dart';
import 'package:solab/core/models/memory_entry.dart';
import 'package:solab/core/services/memory/memory_block_builder.dart';
import 'package:solab/core/services/memory/memory_repository.dart';
import 'package:solab/features/solab_apk/services/apk_patch_memory_service.dart';
import 'package:solab/features/solab_apk/services/apk_patch_note_service.dart';
import 'package:solab/features/solab_apk/services/apk_memory_distill_service.dart';
import 'package:drift/drift.dart' show driftRuntimeOptions;
import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  driftRuntimeOptions.dontWarnAboutMultipleDatabases = true;

  Map<String, dynamic> fp(String vendor) => {
    'vendors': [vendor],
    'shell': const <String>[],
    'engine': 'native',
  };

  late AppDatabase database;
  late BusinessPreferences preferences;
  late MemoryRepository repo;

  setUp(() async {
    database = AppDatabase(NativeDatabase.memory());
    preferences = BusinessPreferences(BusinessRepository(database));
    repo = MemoryRepository(preferences);
    await preferences.load();
    TestWidgetsFlutterBinding.ensureInitialized();
  });

  tearDown(() => database.close());

  group('MemoryType / MemoryEntry 扩展', () {
    test('typeFromString 认识 apk_patch / apk_note 并往返', () {
      expect(MemoryEntry.typeFromString('apk_patch'), MemoryType.apkPatch);
      expect(MemoryEntry.typeFromString('apk_note'), MemoryType.apkNote);
      expect(MemoryEntry.typeToString(MemoryType.apkPatch), 'apk_patch');
      expect(MemoryEntry.typeToString(MemoryType.apkNote), 'apk_note');
    });

    test('extraJson 经 toPayload/fromPayload 往返', () {
      final entry = MemoryEntry(
        id: 'mem_1',
        scope: MemoryScope.assistant,
        assistantId: 'builtin-apk-mod',
        type: MemoryType.apkPatch,
        content: '一句话方案',
        source: MemorySource.tool,
        extraJson: {
          'title': '标题',
          'fingerprint': {
            'vendors': ['a'],
            'shell': ['b'],
            'engine': 'native',
          },
          'outcome': 'verified_success',
        },
        createdAt: DateTime.now().toUtc(),
        updatedAt: DateTime.now().toUtc(),
      );
      final decoded = MemoryEntry.fromPayload(entry.toPayload());
      expect(decoded.extraJson?['title'], '标题');
      expect((decoded.extraJson?['fingerprint'] as Map)['engine'], 'native');
      expect(decoded.type, MemoryType.apkPatch);
    });

    test('APK 记忆类型不在注入范围', () {
      expect(MemoryBlockBuilder.isInjectableType(MemoryType.apkPatch), isFalse);
      expect(MemoryBlockBuilder.isInjectableType(MemoryType.apkNote), isFalse);
      expect(MemoryBlockBuilder.isInjectableType(MemoryType.workflow), isTrue);
    });
  });

  group('ApkPatchMemoryService 后端（MemoryRepository）', () {
    Map<String, dynamic> fp(String vendor) => {
      'vendors': [vendor],
      'shell': const <String>[],
      'engine': 'native',
    };

    test('空库 add 不崩（unmodifiable list 修复）并写回', () async {
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'm1',
          fingerprint: fp('com.a'),
          title: 't',
          solution: 's1',
          timestamp: 1,
        ),
      );
      final loaded = await ApkPatchMemoryService.load(repo);
      expect(loaded, hasLength(1));
      expect(loaded.first.solution, 's1');
    });

    test('APK 经验单行写入和删除不重写其他记忆类型', () async {
      await repo.create(
        scope: MemoryScope.global,
        type: MemoryType.workflow,
        content: '保留的工作流记忆',
        source: MemorySource.manual,
      );
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'patch-direct',
          fingerprint: fp('com.direct'),
          title: '单行写入',
          solution: 'solution',
          timestamp: 1,
        ),
      );

      expect(await repo.readByType(MemoryType.workflow), hasLength(1));
      expect(await repo.readByType(MemoryType.apkPatch), hasLength(1));

      await ApkPatchMemoryService.remove(repo, 'patch-direct');
      expect(await repo.readByType(MemoryType.apkPatch), isEmpty);
      expect(await repo.readByType(MemoryType.workflow), hasLength(1));
    });

    test('同指纹同方案去重覆盖（不堆积）', () async {
      final fpA = fp('com.a');
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'm1',
          fingerprint: fpA,
          title: 't',
          solution: 'same solution',
          timestamp: 1,
        ),
      );
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'm2',
          fingerprint: fpA,
          title: 't2',
          solution: 'same solution',
          timestamp: 2,
        ),
      );
      final loaded = await ApkPatchMemoryService.load(repo);
      expect(loaded, hasLength(1));
      // 覆盖保留原 id。
      expect(loaded.first.id, 'm1');
    });

    test('同指纹不同方案收敛单条（方案行级共存 + targets 累积去重）', () async {
      final fpA = fp('com.a');
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'm1',
          fingerprint: fpA,
          title: '去广告',
          solution: 'NOP TTAdSdk.init',
          timestamp: 1,
          pitfall: '勿裸 hex 改栈帧',
          targets: const ['Lcom/x;->initAd()V', 'libapp.so:symbolA'],
        ),
      );
      // 措辞不同的新方案 + 部分重叠 targets：同指纹收敛为一条
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'm2',
          fingerprint: fpA,
          title: '去广告2',
          solution: '恒返回常量置空 isVip',
          timestamp: 2,
          pitfall: '用 force_return_constant',
          targets: const ['Lcom/x;->initAd()V', 'Lcom/y;->isVip()Z'],
        ),
      );
      final loaded = await ApkPatchMemoryService.load(repo);
      expect(loaded, hasLength(1));
      expect(loaded.first.id, 'm1');
      // 两个方案点行级共存，不互相覆盖
      expect(loaded.first.solution, contains('NOP TTAdSdk.init'));
      expect(loaded.first.solution, contains('恒返回常量置空 isVip'));
      // pitfall 合并
      expect(loaded.first.pitfall, contains('勿裸 hex 改栈帧'));
      expect(loaded.first.pitfall, contains('force_return_constant'));
      // targets 并集去重（3 个唯一值）
      expect(loaded.first.targets, hasLength(3));
      expect(
        loaded.first.targets,
        containsAll(const ['libapp.so:symbolA', 'Lcom/y;->isVip()Z']),
      );
    });

    test('同一 APP 指纹随版本变化仍只保留一条记忆', () async {
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'app-v1',
          fingerprint: const {
            'appId': 'com.example.diary',
            'vendors': ['pangle'],
            'shell': <String>[],
            'engine': 'flutter',
          },
          title: 'v1',
          solution: '补丁一',
          timestamp: 1,
        ),
      );
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'app-v2',
          fingerprint: const {
            'appId': 'com.example.diary',
            'vendors': ['gdt'],
            'shell': ['new-shell'],
            'engine': 'flutter',
          },
          title: 'v2',
          solution: '补丁二',
          timestamp: 2,
        ),
      );

      final loaded = await ApkPatchMemoryService.load(repo);
      expect(loaded, hasLength(1));
      expect(loaded.single.id, 'app-v1');
      expect(loaded.single.solution, contains('补丁一'));
      expect(loaded.single.solution, contains('补丁二'));
    });

    test('upsertVerification 同指纹收敛更新（不堆积）', () async {
      final fpA = fp('com.a');
      await ApkPatchMemoryService.upsertVerification(
        repo: repo,
        fingerprint: fpA,
        outcome: 'verified_success',
        title: 't',
        solution: 'v1',
        operation: 'op',
      );
      await ApkPatchMemoryService.upsertVerification(
        repo: repo,
        fingerprint: fpA,
        outcome: 'verified_failure',
        title: 't2',
        solution: 'v2',
        operation: 'op',
      );
      final loaded = await ApkPatchMemoryService.load(repo);
      expect(loaded, hasLength(1));
      expect(loaded.first.outcome, 'verified_failure');
    });

    test('空指纹防护：退化指纹（无厂商无壳）不参与匹配', () async {
      // 场景：历史里存过一条"无厂商+无壳+native"的退化指纹经验，
      // 任何同引擎 APK 都会算出满分——必须被拦住（宁缺勿滥）。
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'degenerate',
          fingerprint: const {
            'vendors': <String>[],
            'shell': <String>[],
            'engine': 'native',
          },
          title: '退化指纹经验',
          solution: '把 initAd 置空',
          timestamp: 1,
        ),
      );

      // 查询侧也是退化指纹 → 直接空集（信号不足）
      final emptyQuery = await ApkPatchMemoryService.match(repo, const {
        'vendors': <String>[],
        'shell': <String>[],
        'engine': 'native',
      });
      expect(emptyQuery, isEmpty);

      // 查询侧有真实指纹 → 记忆侧退化指纹被跳过，不误命中
      final realQuery = await ApkPatchMemoryService.match(repo, fp('com.a'));
      expect(realQuery, isEmpty);
    });

    test('不同包名/名称的同类型 APK 靠指纹命中（版本演进 SDK 增多降分）', () async {
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'same-type',
          fingerprint: fp('pangle'),
          title: '穿山甲去广告',
          solution: 'NOP TTAdSdk init',
          timestamp: 1,
        ),
      );

      // 同厂商组合（包名/名称不同）→ 命中
      final sameVendors = await ApkPatchMemoryService.match(repo, fp('pangle'));
      expect(sameVendors, hasLength(1));
      expect(sameVendors.first['score'], greaterThanOrEqualTo(0.6));

      // 新版本多检出 SDK（超集）→ Jaccard 降分，1/2 时仍过阈值
      final superset = await ApkPatchMemoryService.match(repo, {
        'vendors': const ['pangle', 'gdt'],
        'shell': const <String>[],
        'engine': 'native',
      });
      expect(
        superset.first['score'] as double,
        allOf(greaterThan(0.5), lessThan(1.0)),
      );

      // 完全不同厂商 → 不命中
      final different = await ApkPatchMemoryService.match(
        repo,
        fp('ironsource'),
      );
      expect(different, isEmpty);

      // 引擎权重修复回归：厂商几乎不同（1/5 重合）+ 同为 native 引擎
      // → 不得因引擎满额计分而误命中（历史 bug：0.2 厂商 + 引擎 = 0.92）。
      final lowOverlap = await ApkPatchMemoryService.match(repo, {
        'vendors': const ['pangle', 'gdt', 'kuaishou', 'baidu', 'sigmob'],
        'shell': const <String>[],
        'engine': 'native',
      });
      if (lowOverlap.isNotEmpty) {
        expect(lowOverlap.first['score'] as double, lessThan(0.6));
      }
    });

    test('match 按 outcome 优先级排序（verified_success 优先）', () async {
      final fpA = fp('com.a');
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'un',
          fingerprint: fpA,
          title: 'un',
          solution: 'unverified solution',
          timestamp: 1,
          outcome: 'unverified',
        ),
      );
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'ok',
          fingerprint: fpA,
          title: 'ok',
          solution: 'verified solution',
          timestamp: 2,
          outcome: 'verified_success',
        ),
      );
      final matched = await ApkPatchMemoryService.match(repo, fpA);
      expect(matched.first['outcome'], 'verified_success');
    });

    test('AI 只读取当前 APP 的已验证记忆', () async {
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'other-app',
          fingerprint: const {
            'appId': 'com.example.other',
            'vendors': ['pangle'],
            'shell': <String>[],
            'engine': 'native',
          },
          title: '其他 APP',
          solution: '其他 APP 的修改方案',
          timestamp: 1,
          outcome: 'verified_success',
        ),
      );
      const currentFingerprint = {
        'appId': 'com.example.current',
        'vendors': ['pangle'],
        'shell': <String>[],
        'engine': 'native',
      };

      var decoded =
          jsonDecode(
                await ApkPatchMemoryService.readForAi(repo, currentFingerprint),
              )
              as Map<String, dynamic>;
      expect(decoded['matchedMemories'], isEmpty);

      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'current-app',
          fingerprint: currentFingerprint,
          title: '当前 APP',
          solution: '当前 APP 的修改方案',
          timestamp: 2,
          outcome: 'verified_success',
        ),
      );
      decoded =
          jsonDecode(
                await ApkPatchMemoryService.readForAi(repo, currentFingerprint),
              )
              as Map<String, dynamic>;
      final matched = decoded['matchedMemories'] as List;
      expect(matched, hasLength(1));
      expect((matched.single as Map)['id'], 'current-app');
    });
  });

  group('ApkPatchNoteService 后端（MemoryRepository）', () {
    test('write/read/remove 按 apkId 隔离', () async {
      await ApkPatchNoteService.write(
        repo,
        'apk-a',
        'loc1',
        summary: '改了一处',
        details: const {
          'operation': 'patch_apk_dex_methods',
          'locatorQuality': 'exact',
          'result': {'trueMethods': 1},
        },
      );
      await ApkPatchNoteService.write(repo, 'apk-b', 'loc2', summary: '另一个包');
      final a = await ApkPatchNoteService.read(repo, 'apk-a');
      final b = await ApkPatchNoteService.read(repo, 'apk-b');
      expect(a, hasLength(1));
      expect(a.first['locator'], 'loc1');
      expect((a.first['details'] as Map)['locatorQuality'], 'exact');
      expect(b, hasLength(1));
      expect(b.first['locator'], 'loc2');
      expect(await repo.readByType(MemoryType.apkNote), hasLength(2));

      await ApkPatchNoteService.write(repo, 'apk-a', 'loc3', summary: '再改一处');
      expect(await ApkPatchNoteService.read(repo, 'apk-a'), hasLength(2));
      expect(await repo.readByType(MemoryType.apkNote), hasLength(2));

      await ApkPatchNoteService.remove(repo, 'apk-a', 'loc1');
      expect(await ApkPatchNoteService.read(repo, 'apk-a'), hasLength(1));
      await ApkPatchNoteService.remove(repo, 'apk-a', 'loc3');
      expect(await ApkPatchNoteService.read(repo, 'apk-a'), isEmpty);
      expect(await ApkPatchNoteService.read(repo, 'apk-b'), hasLength(1));
    });

    test('操作级旧笔记要求重新定位，精确笔记保留续做信息', () async {
      await ApkPatchNoteService.write(
        repo,
        'apk-a',
        'auto:patch_apk_dex_methods',
        summary: '旧汇总',
      );
      await ApkPatchNoteService.write(
        repo,
        'apk-a',
        'Lx/A;->isVip()Z',
        summary: '已修改会员判断',
        details: const {
          'basedOnApk': '/work/base.apk',
          'outputApk': '/work/base_dexpatch.apk',
          'locatorQuality': 'exact',
          'resumeAction': '先核对方法体。',
        },
      );

      final decoded =
          jsonDecode(await ApkPatchNoteService.readForAi(repo, 'apk-a'))
              as Map<String, dynamic>;
      expect(decoded['needsRelocation'], isTrue);
      expect(decoded['hint'], contains('不能直接复用'));
      final notes = decoded['modified'] as List;
      final exact = notes.cast<Map>().firstWhere(
        (note) => note['locator'] == 'Lx/A;->isVip()Z',
      );
      expect((exact['details'] as Map)['outputApk'], '/work/base_dexpatch.apk');
    });
  });

  group('迁移器', () {
    test('draftsFromLegacyJson 转换旧经验 JSON', () {
      const legacy = '''
        [{"id":"m1","title":"t","solution":"s","outcome":"verified_success",
          "operation":"op","timestamp":1,
          "fingerprint":{"vendors":["a"],"shell":[],"engine":"native"}}]
      ''';
      final drafts = ApkPatchMemoryService.draftsFromLegacyJson(legacy);
      expect(drafts, hasLength(1));
      expect(drafts.first.type, MemoryType.apkPatch);
      expect(drafts.first.content, 's');
      expect(drafts.first.migrationId, 'apk_patch_m1');
      expect((drafts.first.extraJson?['title']), 't');
    });

    test('笔记旧 JSON 转换', () {
      const legacy =
          '{"apk-a":[{"locator":"l1","status":"patched","summary":"s","timestamp":1}]}';
      final drafts = ApkPatchNoteService.draftsFromLegacyJson(legacy);
      expect(drafts, hasLength(1));
      expect(drafts.first.type, MemoryType.apkNote);
      expect(drafts.first.content, 's');
      expect((drafts.first.extraJson?['locator']), 'l1');
    });
  });

  group('蒸馏服务', () {
    test('分组按相似度聚类：指纹微变（厂商列表增项）也聚同组', () async {
      // 同类型 APK 版本迭代：厂商列表多检出一项 → 指纹 key 不同
      // 但 matchScore >= 0.6，应聚到一组蒸馏（此前精确 key 相等聚不到）。
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'v1',
          fingerprint: fp('pangle'),
          title: 't1',
          solution: 's1',
          timestamp: 1,
        ),
      );
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'v2',
          fingerprint: const {
            'vendors': ['pangle', 'gdt'],
            'shell': <String>[],
            'engine': 'native',
          },
          title: 't2',
          solution: 's2',
          timestamp: 2,
        ),
      );
      // 无关指纹（不同厂商）不混入
      await ApkPatchMemoryService.add(
        repo,
        ApkPatchMemory(
          id: 'other',
          fingerprint: fp('ironsource'),
          title: 't3',
          solution: 's3',
          timestamp: 3,
        ),
      );
      final groups = await ApkMemoryDistillService.groupsForDistill(repo);
      expect(groups, hasLength(1));
      expect(groups.first, hasLength(2));
      expect(groups.first.map((e) => e.id), containsAll(const ['v1', 'v2']));
    });

    test('distillGroupDeterministic 保留 verified_success 优先', () async {
      final now = DateTime.now().toUtc();
      final group = [
        MemoryEntry(
          id: 'a',
          scope: MemoryScope.assistant,
          assistantId: 'builtin-apk-mod',
          type: MemoryType.apkPatch,
          content: 'old',
          source: MemorySource.tool,
          extraJson: {
            'title': 'old',
            'fingerprint': {
              'vendors': ['x'],
              'shell': <String>[],
              'engine': 'native',
            },
            'outcome': 'unverified',
          },
          createdAt: now,
          updatedAt: now,
        ),
        MemoryEntry(
          id: 'b',
          scope: MemoryScope.assistant,
          assistantId: 'builtin-apk-mod',
          type: MemoryType.apkPatch,
          content: 'verified one',
          source: MemorySource.tool,
          extraJson: {
            'title': 'ok',
            'fingerprint': {
              'vendors': ['x'],
              'shell': <String>[],
              'engine': 'native',
            },
            'outcome': 'verified_success',
          },
          createdAt: now,
          updatedAt: now,
        ),
      ];
      final merged = ApkMemoryDistillService.distillGroupDeterministic(group);
      expect(merged.solution, contains('old'));
      expect(merged.solution, contains('verified one'));
      expect(merged.outcome, 'verified_success');
    });
  });
}
