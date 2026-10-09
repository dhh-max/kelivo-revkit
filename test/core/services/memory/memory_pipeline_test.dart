import 'dart:convert';
import 'dart:io';

import 'package:Kelivo/core/database/app_database.dart';
import 'package:Kelivo/core/database/business_data.dart';
import 'package:Kelivo/core/database/business_preferences.dart';
import 'package:Kelivo/core/database/business_repository.dart';
import 'package:Kelivo/core/database/chat_database_repository.dart';
import 'package:Kelivo/core/models/assistant.dart';
import 'package:Kelivo/core/models/reasoning_request.dart';
import 'package:Kelivo/core/models/chat_message.dart';
import 'package:Kelivo/core/models/message_part.dart';
import 'package:Kelivo/core/models/memory_entry.dart';
import 'package:Kelivo/core/providers/assistant_provider.dart';
import 'package:Kelivo/core/providers/memory_provider_v2.dart';
import 'package:Kelivo/core/providers/settings_provider.dart';
import 'package:Kelivo/core/services/chat/chat_service.dart';
import 'package:Kelivo/core/services/memory/memory_gatekeeper.dart';
import 'package:Kelivo/core/services/memory/memory_pipeline.dart';
import 'package:Kelivo/core/services/memory/memory_prompts.dart';
import 'package:Kelivo/core/services/memory/memory_repository.dart';
import 'package:Kelivo/core/services/workspace/project_scope.dart';
import 'package:Kelivo/features/home/services/context_usage_service.dart';
import 'package:drift/drift.dart' show driftRuntimeOptions;
import 'package:drift/native.dart';
import 'package:flutter_test/flutter_test.dart';
// ignore: depend_on_referenced_packages
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _FakePathProviderPlatform extends PathProviderPlatform {
  _FakePathProviderPlatform(this.path);

  final String path;

  @override
  Future<String?> getApplicationDocumentsPath() async => path;

  @override
  Future<String?> getApplicationSupportPath() async => path;

  @override
  Future<String?> getApplicationCachePath() async => '$path/cache';

  @override
  Future<String?> getTemporaryPath() async => '$path/tmp';
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  driftRuntimeOptions.dontWarnAboutMultipleDatabases = true;

  late AppDatabase database;
  late BusinessPreferences preferences;
  late ChatDatabaseRepository chatRepository;
  late MemoryRepository memoryRepository;
  late ChatService chatService;
  late SettingsProvider settings;
  late AssistantProvider assistants;
  late MemoryProviderV2 memoryV2;
  late MemoryPipelineService pipeline;
  late Directory tempDir;
  late PathProviderPlatform previousPathProvider;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    tempDir = await Directory.systemTemp.createTemp('kelivo_memory_pipeline_');
    previousPathProvider = PathProviderPlatform.instance;
    PathProviderPlatform.instance = _FakePathProviderPlatform(tempDir.path);

    database = AppDatabase(
      NativeDatabase.memory(
        setup: (raw) => raw.execute('PRAGMA foreign_keys = ON;'),
      ),
    );
    final businessRepository = BusinessRepository(database);
    preferences = BusinessPreferences(businessRepository);
    chatRepository = ChatDatabaseRepository(database);
    memoryRepository = MemoryRepository(preferences);
    await chatRepository.ensureReady();
    await preferences.load();

    chatService = ChatService(existingRepository: chatRepository);
    await chatService.init();

    settings = SettingsProvider(preferences);
    await settings.loaded;
    await settings.setMemoryModel('openai', 'gpt-test');
    await settings.setMemoryPromptLang('zh');

    // Seed a listed model so existence check passes.
    final cfg = settings.getProviderConfig('openai');
    await settings.setProviderConfig(
      'openai',
      cfg.copyWith(models: ['gpt-test']),
    );

    assistants = AssistantProvider(
      preferences: preferences,
      chatService: chatService,
    );
    await assistants.loaded;

    memoryV2 = MemoryProviderV2(
      repository: memoryRepository,
      chatRepository: chatRepository,
    );

    pipeline = MemoryPipelineService(
      chatService: chatService,
      repository: memoryRepository,
      chatRepository: chatRepository,
      settings: () => settings,
      assistants: () => assistants,
      memoryV2: () => memoryV2,
      generateText:
          ({
            required ProviderConfig config,
            required String modelId,
            required String prompt,
            String? conversationId,
            ReasoningRequest reasoning = ReasoningRequest.auto,
          }) async =>
              throw StateError('use processWindow llmCall in these tests'),
    );
  });

  tearDown(() async {
    PathProviderPlatform.instance = previousPathProvider;
    await chatService.close();
    await database.close();
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });

  Future<void> seedAssistant(String id) async {
    final raw = preferences.getString(BusinessEntityKind.assistant.sourceKey);
    final list = <Map<String, dynamic>>[
      if (raw != null && raw.isNotEmpty)
        for (final item in jsonDecode(raw) as List)
          (item as Map).cast<String, dynamic>(),
    ];
    if (!list.any((item) => item['id'] == id)) {
      list.add({
        'id': id,
        'name': id,
        'enableMemory': true,
        'autoOrganizeMemory': true,
      });
    }
    await preferences.setString(
      BusinessEntityKind.assistant.sourceKey,
      jsonEncode(list),
    );
  }

  Assistant assistant({
    MemorySmartAddMode mode = MemorySmartAddMode.batched,
    MemoryWriteScope scope = MemoryWriteScope.alwaysGlobal,
  }) {
    return Assistant(
      id: 'a1',
      name: 'A1',
      enableMemory: true,
      autoOrganizeMemory: true,
      memorySmartAddMode: mode,
      memoryWriteScope: scope,
    );
  }

  List<({ChatMessage message, int order})> sampleWindow({
    required String conversationId,
    int endOrder = 3,
  }) {
    return [
      (
        message: ChatMessage(
          role: 'user',
          content: '我是大学生，学软件工程。',
          conversationId: conversationId,
        ),
        order: endOrder - 1,
      ),
      (
        message: ChatMessage(
          role: 'assistant',
          content: '了解了。',
          conversationId: conversationId,
        ),
        order: endOrder,
      ),
    ];
  }

  group('§12.10 conversation summary double gate', () {
    test('requires both switches', () {
      expect(
        MemoryPipelineService.shouldGenerateConversationSummary(
          allowPastConversationRecall: true,
          generateConversationSummary: true,
        ),
        isTrue,
      );
      expect(
        MemoryPipelineService.shouldGenerateConversationSummary(
          allowPastConversationRecall: true,
          generateConversationSummary: false,
        ),
        isFalse,
      );
      expect(
        MemoryPipelineService.shouldGenerateConversationSummary(
          allowPastConversationRecall: false,
          generateConversationSummary: true,
        ),
        isFalse,
      );
    });
  });

  group('buildConversationText', () {
    test('uses zh/en prefixes and TextPart text only', () {
      final msgs = [
        ChatMessage(
          role: 'user',
          conversationId: 'c',
          parts: const [
            TextPart('hello  world'),
            ImagePart(uri: '/tmp/a.png'),
          ],
        ),
        ChatMessage(role: 'assistant', content: 'hi', conversationId: 'c'),
        ChatMessage(role: 'tool', content: 'ignored', conversationId: 'c'),
      ];
      final zh = MemoryPipelineService.buildConversationText(
        msgs,
        MemoryPromptLang.zh,
      );
      expect(zh, contains('用户：'));
      expect(zh, contains('助手：'));
      expect(zh, contains('hello  world'));
      expect(zh, isNot(contains('/tmp/a.png')));
      expect(zh, isNot(contains('[image:')));
      expect(zh, isNot(contains('ignored')));

      final en = MemoryPipelineService.buildConversationText(
        msgs,
        MemoryPromptLang.en,
      );
      expect(en, contains('User: '));
      expect(en, contains('Assistant: '));
    });
  });

  group('temporary conversations', () {
    test('are never organized into long-term memory', () async {
      // A temporary chat is discarded when the user leaves it, so distilling
      // it would outlive the conversation they asked to be throwaway.
      await seedAssistant('a1');
      final temp = await chatService.createDraftConversation(
        title: 'temp',
        assistantId: 'a1',
        temporary: true,
      );
      expect(chatService.isTemporaryConversation(temp.id), isTrue);

      final result = await pipeline.runNow(
        conversationId: temp.id,
        assistantId: 'a1',
      );
      expect(result.advanced, isFalse);
      expect(result.error, 'temporary_conversation');

      // The auto path must be just as silent.
      pipeline.scheduleIfNeeded(conversationId: temp.id, assistantId: 'a1');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(
        await chatRepository.queryVisibleMemories(assistantId: 'a1'),
        isEmpty,
      );
    });
  });

  group('background refresh does not narrow the UI', () {
    test('reloadCurrentScope keeps a global listing intact', () async {
      // The global memory page loads every assistant. A background run knows
      // only the assistant it ran for, and passing that id would drop every
      // other assistant's entries from the open list.
      final memoryV2 = MemoryProviderV2(
        repository: memoryRepository,
        chatRepository: chatRepository,
      );
      await memoryRepository.create(
        scope: MemoryScope.assistant,
        assistantId: 'a1',
        type: MemoryType.identity,
        content: 'Belongs to a1.',
        source: MemorySource.manual,
      );
      await memoryRepository.create(
        scope: MemoryScope.assistant,
        assistantId: 'a2',
        type: MemoryType.identity,
        content: 'Belongs to a2.',
        source: MemorySource.manual,
      );

      await memoryV2.refreshAll();
      expect(memoryV2.entries, hasLength(2));

      await memoryV2.reloadCurrentScope();
      expect(
        memoryV2.entries,
        hasLength(2),
        reason: 'a background reload must not change the visible scope',
      );

      // Same contract as ToolHandlerService.onMutated: a write for one
      // assistant must not collapse an open global listing.
      await memoryRepository.create(
        scope: MemoryScope.assistant,
        assistantId: 'a1',
        type: MemoryType.identity,
        content: 'Another a1 fact.',
        source: MemorySource.tool,
      );
      await memoryV2.reloadCurrentScope();
      expect(memoryV2.entries, hasLength(3));
      expect(
        memoryV2.entries.any((e) => e.assistantId == 'a2'),
        isTrue,
        reason: 'a1 tool writes must leave a2 entries visible',
      );
    });
  });

  group('processWindow watermark + short-circuit', () {
    test('Gatekeeper false advances watermark and skips Extract', () async {
      await seedAssistant('a1');
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );
      expect(convo.lastMemoryExtractedOrder, -1);

      var calls = 0;
      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(conversationId: convo.id, endOrder: 5),
        llmCall: (prompt) async {
          calls++;
          expect(prompt, contains('分析以下对话'));
          return '<gate><user_memory>false</user_memory></gate>';
        },
      );
      expect(result.advanced, isTrue);
      expect(result.gate, MemoryGateParseResult.skip);
      expect(calls, 1); // no Extract
      expect(convo.lastMemoryExtractedOrder, 5);
    });

    test('Gatekeeper malformed does not advance', () async {
      await seedAssistant('a1');
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );
      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(conversationId: convo.id, endOrder: 2),
        llmCall: (_) async => '???',
      );
      expect(result.advanced, isFalse);
      expect(result.gate, MemoryGateParseResult.malformed);
      expect(convo.lastMemoryExtractedOrder, -1);
    });

    test('Extract malformed does not advance', () async {
      await seedAssistant('a1');
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );
      var step = 0;
      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(conversationId: convo.id, endOrder: 4),
        llmCall: (_) async {
          step++;
          if (step == 1) {
            return '<gate><user_memory>true</user_memory></gate>';
          }
          return 'no extracted tag';
        },
      );
      expect(result.advanced, isFalse);
      expect(result.error, 'extract_parse_failed');
      expect(convo.lastMemoryExtractedOrder, -1);
    });

    test('successful extract + smart add advances watermark', () async {
      await seedAssistant('a1');
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );
      var step = 0;
      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(mode: MemorySmartAddMode.perItem),
        settings: settings,
        watermark: -1,
        window: sampleWindow(conversationId: convo.id, endOrder: 7),
        llmCall: (prompt) async {
          step++;
          if (step == 1) {
            return '<gate><user_memory>true</user_memory></gate>';
          }
          if (step == 2) {
            return '''
<extracted>
<item type="workflow">处理混淆崩溃先确认 keep 规则覆盖反射入口。</item>
</extracted>
''';
          }
          // Smart Add per-item
          return jsonEncode({
            'action': 'NEW',
            'targetId': null,
            'mergedContent': null,
            'relatedIds': <String>[],
          });
        },
      );
      expect(result.advanced, isTrue);
      expect(result.extractedCount, 1);
      expect(convo.lastMemoryExtractedOrder, 7);
      final entries = await chatRepository.queryVisibleMemories(
        assistantId: 'a1',
        type: MemoryType.workflow,
      );
      expect(entries, isNotEmpty);
      expect(entries.first.source, MemorySource.extracted);
    });

    test('identity / voice items never reach Smart Add', () async {
      await seedAssistant('a1');
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );
      var calls = 0;
      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(mode: MemorySmartAddMode.perItem),
        settings: settings,
        watermark: -1,
        window: sampleWindow(conversationId: convo.id, endOrder: 6),
        llmCall: (prompt) async {
          calls++;
          if (calls == 1) {
            return '<gate><user_memory>true</user_memory></gate>';
          }
          return '''
<extracted>
<item type="identity">用户是大学生。</item>
<item type="voice">语气要简短。</item>
</extracted>
''';
        },
      );
      expect(result.advanced, isTrue);
      expect(result.extractedCount, 2);
      // 白名单把两类条目全部挡在 Smart Add 之前：只有 Gate + Extract 两次调用。
      expect(calls, 2);
      final entries = await chatRepository.queryVisibleMemories(
        assistantId: 'a1',
      );
      expect(entries, isEmpty);
      expect(convo.lastMemoryExtractedOrder, 6);
    });

    test('user prompt override is used for Gatekeeper', () async {
      await seedAssistant('a1');
      await settings.setMemoryGatePromptZh('OVERRIDE-GATE {{conversation}}');
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );
      String? seen;
      await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(conversationId: convo.id),
        llmCall: (prompt) async {
          seen = prompt;
          return '<gate><user_memory>false</user_memory></gate>';
        },
      );
      expect(seen, startsWith('OVERRIDE-GATE '));
      expect(seen, isNot(contains(MemoryPrompts.gateZh.substring(0, 8))));
    });
  });

  group('Distiller parse malformed fails cleanly', () {
    test('bad distiller JSON does not throw and still advances', () async {
      await seedAssistant('a1');
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );
      var step = 0;
      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(mode: MemorySmartAddMode.perItem),
        settings: settings,
        watermark: -1,
        window: sampleWindow(conversationId: convo.id, endOrder: 9),
        llmCall: (_) async {
          step++;
          if (step == 1) {
            return '<gate><user_memory>true</user_memory></gate>';
          }
          if (step == 2) {
            return '<extracted><item type="identity">用户希望被称为小明。</item></extracted>';
          }
          if (step == 3) {
            return jsonEncode({'action': 'NEW', 'relatedIds': <String>[]});
          }
          // Distiller
          return 'not-json';
        },
      );
      expect(result.advanced, isTrue);
      expect(convo.lastMemoryExtractedOrder, 9);
    });
  });

  group('background run project scope (工作区隔离)', () {
    tearDown(ProjectScope.clearActive);

    /// 全流程 stub：Gate → Extract（一条 workflow）→（无候选，本地 NEW）。
    Future<String> Function(String) scriptedLlm({
      required void Function() onGate,
    }) {
      var step = 0;
      return (prompt) async {
        step++;
        if (step == 1) {
          onGate();
          return '<gate><user_memory>true</user_memory></gate>';
        }
        if (step == 2) {
          return '<extracted><item type="workflow">改包前先确认 keep 规则覆盖反射入口。</item></extracted>';
        }
        return jsonEncode({
          'action': 'NEW',
          'targetId': null,
          'mergedContent': null,
          'relatedIds': <String>[],
        });
      };
    }

    MemoryPipelineService pipelineWith({
      ConversationProjectResolver? resolver,
      required Future<String> Function(String prompt) llm,
    }) {
      return MemoryPipelineService(
        chatService: chatService,
        repository: memoryRepository,
        chatRepository: chatRepository,
        settings: () => settings,
        assistants: () => assistants,
        memoryV2: () => memoryV2,
        resolveConversationProject: resolver,
        generateText:
            ({
              required ProviderConfig config,
              required String modelId,
              required String prompt,
              String? conversationId,
              ReasoningRequest reasoning = ReasoningRequest.auto,
            }) => llm(prompt),
      );
    }

    Future<List<MemoryEntry>> workflowEntries() async => (await memoryRepository
            .readAll())
        .where((entry) => entry.type == MemoryType.workflow)
        .toList(growable: false);

    /// 通过 provider 建助手：runNow/scheduleIfNeeded 会去 provider 里查助手
    /// （直接写 preferences 的 [seedAssistant] 只对显式传 assistant 的
    /// processWindow 路径有效）。
    Future<Assistant> addMemoryAssistant() async {
      final id = await assistants.addAssistant(name: 'A1');
      final created = assistants.getById(id)!;
      final updated = created.copyWith(
        enableMemory: true,
        autoOrganizeMemory: true,
        memorySmartAddMode: MemorySmartAddMode.perItem,
        memoryWriteScope: MemoryWriteScope.alwaysGlobal,
      );
      await assistants.updateAssistant(updated);
      return updated;
    }

    /// runNow 走真实落库的消息（processWindow 的合成 window 不适用）。
    Future<void> seedTurns(String conversationId) async {
      await chatService.addMessage(
        conversationId: conversationId,
        role: 'user',
        content: '我是大学生，学软件工程。',
      );
      await chatService.addMessage(
        conversationId: conversationId,
        role: 'assistant',
        content: '了解了。',
      );
    }

    test('入队后切工作区，落库仍打「入队时那条会话的工作区」', () async {
      // 回归：打标过去读的是进程级活动项目（最后一次生成），后台任务排队/等模型
      // 期间用户切工作区，就会把 A 会话的经验写进 B 工作区。
      final ai = await addMemoryAssistant();
      final convo = await chatService.createConversation(
        title: 'A 工作区会话',
        assistantId: ai.id,
      );
      ProjectScope.activeId = 'p-a';
      await seedTurns(convo.id);
      final scoped = pipelineWith(
        llm: scriptedLlm(onGate: () => ProjectScope.activeId = 'p-b'),
      );

      final result = await scoped.runNow(
        conversationId: convo.id,
        assistantId: ai.id,
      );

      expect(result.advanced, isTrue, reason: '${result.error}');
      final entries = await workflowEntries();
      expect(entries, hasLength(1));
      expect(
        entries.single.projectId,
        'p-a',
        reason: '打标必须跟着任务所属工作区，不跟进程级活动项目',
      );
    });

    test('注入的会话解析器优先于环境态活动项目', () async {
      final ai = await addMemoryAssistant();
      final convo = await chatService.createConversation(
        title: 'C 工作区会话',
        assistantId: ai.id,
      );
      ProjectScope.activeId = 'p-b';
      await seedTurns(convo.id);
      final scoped = pipelineWith(
        resolver: (conversationId) async => (id: 'p-c', root: null),
        llm: scriptedLlm(onGate: () {}),
      );

      final result = await scoped.runNow(
        conversationId: convo.id,
        assistantId: ai.id,
      );

      expect(result.advanced, isTrue, reason: '${result.error}');
      expect((await workflowEntries()).single.projectId, 'p-c');
    });

    test('解析器说「这条会话没绑工作区」时不回落到过期的活动项目', () async {
      // 否则「切到无工作区会话再发一轮」会把 A 的经验标成 A 之外/全局。
      final ai = await addMemoryAssistant();
      final convo = await chatService.createConversation(
        title: '无工作区会话',
        assistantId: ai.id,
      );
      ProjectScope.activeId = 'p-b';
      await seedTurns(convo.id);
      final scoped = pipelineWith(
        resolver: (conversationId) async => (id: null, root: null),
        llm: scriptedLlm(onGate: () {}),
      );

      final result = await scoped.runNow(
        conversationId: convo.id,
        assistantId: ai.id,
      );

      expect(result.advanced, isTrue, reason: '${result.error}');
      expect(
        (await workflowEntries()).single.projectId,
        isNull,
        reason: '未绑定工作区 = 全局，不能猜成别的项目',
      );
    });

    test('解析器抛错时回落到入队时捕获的活动项目', () async {
      final ai = await addMemoryAssistant();
      final convo = await chatService.createConversation(
        title: '解析失败的会话',
        assistantId: ai.id,
      );
      ProjectScope.activeId = 'p-a';
      await seedTurns(convo.id);
      final scoped = pipelineWith(
        resolver: (conversationId) async => throw StateError('resolver boom'),
        llm: scriptedLlm(onGate: () {}),
      );

      final result = await scoped.runNow(
        conversationId: convo.id,
        assistantId: ai.id,
      );

      expect(result.advanced, isTrue, reason: '${result.error}');
      expect((await workflowEntries()).single.projectId, 'p-a');
    });

    test('用量 hash 用显式项目钉住：环境态变了也不漂', () async {
      // 回归：切工作区后重算的 hash 若取环境态，会与请求期不同 → 精确锚定作废。
      await seedAssistant('a1');
      ProjectScope.activeId = 'p-a';
      await memoryRepository.create(
        scope: MemoryScope.global,
        type: MemoryType.workflow,
        content: 'A 工作区的结论',
        source: MemorySource.tool,
      );
      final assistantForHash = assistant();

      final pinnedA = await readContextMemorySnapshotHash(
        repository: chatRepository,
        settings: settings,
        assistant: assistantForHash,
        projectId: 'p-a',
        useAmbientProject: false,
      );
      final pinnedNone = await readContextMemorySnapshotHash(
        repository: chatRepository,
        settings: settings,
        assistant: assistantForHash,
        projectId: null,
        useAmbientProject: false,
      );
      // 环境态切到别的工作区：显式项目的结果不变。
      ProjectScope.activeId = 'p-b';
      final pinnedAAgain = await readContextMemorySnapshotHash(
        repository: chatRepository,
        settings: settings,
        assistant: assistantForHash,
        projectId: 'p-a',
        useAmbientProject: false,
      );

      expect(pinnedA, isNotNull);
      expect(pinnedAAgain, pinnedA, reason: '显式项目与环境态无关');
      expect(
        pinnedNone,
        isNot(pinnedA),
        reason: '无项目的会话看不到 A 工作区的结论',
      );
    });
  });

  group('quota cooldown tiering (user-facing repeated-toast fix)', () {
    test('monthly usage limit parses Resets-in-days into day-scale cooldown', () {
      final err =
          'gate_request_failed:HttpException: HTTP 429: {"error":{"type":'
          '"GoUsageLimitError","message":"Monthly usage limit reached. '
          'Resets in 6 days. To continue using this model now, enable usage '
          'from your available balance."}}';
      expect(MemoryPipelineService.isPermanentQuotaError(err), isTrue);
      final cooldown = MemoryPipelineService.quotaCooldownFor(err);
      // 6 天 + 2h 余量，封顶 7 天。
      expect(cooldown.inHours, 6 * 24 + 2);
    });

    test('monthly without reset days falls back to 24h; unknown stays 6h', () {
      expect(
        MemoryPipelineService.quotaCooldownFor(
          'HTTP 429: Monthly usage limit reached.',
        ).inHours,
        24,
      );
      expect(
        MemoryPipelineService.quotaCooldownFor(
          'HTTP 429: hourly rate limit exceeded',
        ).inHours,
        MemoryPipelineService.quotaCooldownDuration.inHours,
      );
    });

    test('quota_cooldown skip is not a task failure (no repeated toast)', () {
      // 回归：冷却内每条消息曾被当任务失败冒泡弹「记忆失败：quota_cooldown」。
      expect(
        MemoryPipelineService.skipReasonCodes.contains('quota_cooldown'),
        isTrue,
      );
    });
  });
}

