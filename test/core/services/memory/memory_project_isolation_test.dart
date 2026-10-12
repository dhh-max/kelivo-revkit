import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/models/memory_entry.dart';
import 'package:Kelivo/core/services/memory/memory_repository.dart';
import 'package:Kelivo/core/services/workspace/project_scope.dart';

/// 记忆的工作区隔离（用户 2026-10-03 口径）：
/// **一般记忆按工作区隔离**（不用某个工作区就不要它的记忆）；
/// **逆向经验（apkPatch/apkNote/apkFailure）跨工作区保留**（经验不该随工作区消失）；
/// 老数据/未标记一律按全局可见，不丢历史记忆。
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  MemoryEntry entry({
    required MemoryType type,
    String? projectId,
    String content = 'x',
  }) => MemoryEntry(
    id: 'm-$type-$projectId-$content',
    scope: MemoryScope.assistant,
    assistantId: 'a1',
    type: type,
    content: content,
    createdAt: DateTime.utc(2026),
    updatedAt: DateTime.utc(2026),
    extraJson: projectId == null
        ? null
        : <String, dynamic>{'projectId': projectId},
  );

  tearDown(ProjectScope.clearActive);

  group('条目可见性', () {
    test('未标记（全局/老数据）：任何项目都可见', () {
      final global = entry(type: MemoryType.identity);
      expect(global.projectId, isNull);
      expect(global.visibleInProject(null), isTrue);
      expect(global.visibleInProject('p-a'), isTrue);
    });

    test('一般记忆（按工作区隔离）：只在本工作区可见', () {
      for (final type in const <MemoryType>[
        MemoryType.identity,
        MemoryType.workflow,
        MemoryType.voice,
        MemoryType.instruction,
      ]) {
        final tagged = entry(type: type, projectId: 'p-a');
        expect(tagged.projectId, 'p-a');
        expect(tagged.visibleInProject('p-a'), isTrue, reason: '$type 同项目可见');
        expect(
          tagged.visibleInProject('p-b'),
          isFalse,
          reason: '$type 不能串到别的工作区',
        );
        expect(
          tagged.visibleInProject(null),
          isFalse,
          reason: '没有工作区上下文时不放行',
        );
      }
    });

    test('逆向经验（apkPatch/apkNote/apkFailure）：跨工作区保留，任何项目都可见', () {
      for (final type in const <MemoryType>[
        MemoryType.apkPatch,
        MemoryType.apkNote,
        MemoryType.apkFailure,
      ]) {
        // 经验类不参与项目隔离；即使历史数据上被打了标也照旧可见
        // （当天早些时候的旧口径给它们打过标，不能让经验因此消失）。
        final tagged = entry(type: type, projectId: 'p-a');
        expect(tagged.visibleInProject('p-a'), isTrue, reason: '$type 任何时候可见');
        expect(tagged.visibleInProject('p-b'), isTrue, reason: '$type 换工作区保留');
        expect(tagged.visibleInProject(null), isTrue, reason: '$type 无工作区也可见');
      }
    });

    test('空字符串标记按未标记处理（脏数据不误伤）', () {
      final dirty = MemoryEntry(
        id: 'm-dirty',
        scope: MemoryScope.assistant,
        type: MemoryType.apkNote,
        content: 'x',
        createdAt: DateTime.utc(2026),
        updatedAt: DateTime.utc(2026),
        extraJson: const <String, dynamic>{'projectId': '   '},
      );
      expect(dirty.projectId, isNull);
      expect(dirty.visibleInProject('p-b'), isTrue);
    });
  });

  group('写入打标：一般记忆打，逆向经验不打', () {
    test('一般四型在项目内打标', () {
      ProjectScope.activeId = 'p-a';
      for (final type in const <MemoryType>[
        MemoryType.identity,
        MemoryType.workflow,
        MemoryType.voice,
        MemoryType.instruction,
      ]) {
        final tagged = MemoryRepository.withProjectTag(
          type: type,
          extraJson: null,
        );
        expect(tagged?['projectId'], 'p-a', reason: '$type 应打标');
      }
    });

    test('逆向经验不打标（跨工作区保留）', () {
      ProjectScope.activeId = 'p-a';
      for (final type in const <MemoryType>[
        MemoryType.apkPatch,
        MemoryType.apkNote,
        MemoryType.apkFailure,
      ]) {
        expect(
          MemoryRepository.withProjectTag(type: type, extraJson: null),
          isNull,
          reason: '$type 是经验，不该被关进工作区',
        );
      }
    });

    test('已有标记不被覆盖；无活动项目时不打标', () {
      ProjectScope.activeId = 'p-b';
      final kept = MemoryRepository.withProjectTag(
        type: MemoryType.workflow,
        extraJson: const <String, dynamic>{'projectId': 'p-a', 'k': 'x'},
      );
      expect(kept?['projectId'], 'p-a');
      expect(kept?['k'], 'x');

      ProjectScope.clearActive();
      expect(
        MemoryRepository.withProjectTag(
          type: MemoryType.workflow,
          extraJson: null,
        ),
        isNull,
        reason: '没有工作区上下文就按全局写，不猜',
      );
    });
  });

  group('读取过滤', () {
    test('全局 + 本项目留下，别的项目剔除；经验全留', () {
      final entries = <MemoryEntry>[
        entry(type: MemoryType.identity, content: 'global'),
        entry(type: MemoryType.workflow, projectId: 'p-a', content: 'a'),
        entry(type: MemoryType.voice, projectId: 'p-b', content: 'b'),
        entry(type: MemoryType.apkPatch, projectId: 'p-a', content: 'exp'),
      ];
      final visibleA = MemoryRepository.visibleInProject(entries, 'p-a');
      expect(visibleA.map((e) => e.content), <String>['global', 'a', 'exp']);
      final visibleB = MemoryRepository.visibleInProject(entries, 'p-b');
      expect(visibleB.map((e) => e.content), <String>['global', 'b', 'exp']);
      expect(
        MemoryRepository.visibleInProject(entries, null).map((e) => e.content),
        <String>['global', 'exp'],
      );
    });
  });

  group('ProjectScope 取值优先级', () {
    test('zone 优先于活动项目；退出 zone 回到活动项目', () async {
      ProjectScope.activeId = 'active-project';
      final inside = ProjectScope.run<String?>(
        'zone-project',
        '/ws/zone',
        () => ProjectScope.currentId,
      );
      expect(inside, 'zone-project');

      // 跨 await 也在同一 zone 上（工具调用是异步链）。
      final acrossAwait = await ProjectScope.run<Future<String?>>(
        'zone-project',
        '/ws/zone',
        () async {
          await Future<void>.delayed(Duration.zero);
          return ProjectScope.currentId;
        },
      );
      expect(acrossAwait, 'zone-project');
      expect(ProjectScope.currentId, 'active-project');
      expect(ProjectScope.currentRoot, isNull, reason: 'zone 外无根目录');
    });

    test('只给根目录（无 id）时也能拿到 root，但不产生伪项目 id', () {
      final root = ProjectScope.run<String?>(
        null,
        '/ws/only-root',
        () => ProjectScope.currentRoot,
      );
      expect(root, '/ws/only-root');
      expect(ProjectScope.currentId, isNull);
    });
  });
}
