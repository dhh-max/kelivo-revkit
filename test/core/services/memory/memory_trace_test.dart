import 'dart:convert';
import 'dart:io';

import 'package:Kelivo/core/database/app_database.dart';
import 'package:Kelivo/core/database/business_preferences.dart';
import 'package:Kelivo/core/database/business_repository.dart';
import 'package:Kelivo/core/database/chat_database_repository.dart';
import 'package:Kelivo/core/models/assistant.dart';
import 'package:Kelivo/core/models/reasoning_request.dart';
import 'package:Kelivo/core/models/chat_message.dart';
import 'package:Kelivo/core/models/memory_entry.dart';
import 'package:Kelivo/core/providers/assistant_provider.dart';
import 'package:Kelivo/core/providers/memory_provider_v2.dart';
import 'package:Kelivo/core/providers/settings_provider.dart';
import 'package:Kelivo/core/services/chat/chat_service.dart';
import 'package:Kelivo/core/services/memory/memory_pipeline.dart';
import 'package:Kelivo/core/services/memory/memory_profile_distiller.dart';
import 'package:Kelivo/core/services/memory/memory_prompts.dart';
import 'package:Kelivo/core/services/memory/memory_repository.dart';
import 'package:Kelivo/core/services/memory/memory_trace.dart';
import 'package:Kelivo/core/services/workspace/project_scope.dart';
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

/// Recorder whose every hook throws, to prove the pipeline is unaffected.
class _ThrowingRecorder extends MemoryTraceRecorder {
  int beginCalls = 0;

  @override
  MemoryTraceHandle? begin({
    required MemoryTraceTrigger trigger,
    required MemoryTraceScope scope,
    String? conversationId,
    String? conversationTitle,
    String? assistantId,
    String? assistantName,
  }) {
    beginCalls++;
    throw StateError('recorder exploded');
  }

  @override
  void publish(MemoryTrace trace) => throw StateError('publish exploded');
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
  late Directory tempDir;
  late PathProviderPlatform previousPathProvider;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    tempDir = await Directory.systemTemp.createTemp('kelivo_memory_trace_');
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

    assistants = AssistantProvider(
      preferences: preferences,
      chatService: chatService,
    );
    await assistants.loaded;

    memoryV2 = MemoryProviderV2(
      repository: memoryRepository,
      chatRepository: chatRepository,
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

  MemoryPipelineService buildPipeline(MemoryTraceRecorder recorder) {
    return MemoryPipelineService(
      chatService: chatService,
      repository: memoryRepository,
      chatRepository: chatRepository,
      settings: () => settings,
      assistants: () => assistants,
      memoryV2: () => memoryV2,
      traceRecorder: recorder,
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
  }

  Assistant assistant({
    MemorySmartAddMode mode = MemorySmartAddMode.perItem,
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

  List<({ChatMessage message, int order})> sampleWindow(String conversationId) {
    return [
      (
        message: ChatMessage(
          role: 'user',
          content: '我是大学生，学软件工程。',
          conversationId: conversationId,
        ),
        order: 4,
      ),
      (
        message: ChatMessage(
          role: 'assistant',
          content: '了解了。',
          conversationId: conversationId,
        ),
        order: 5,
      ),
    ];
  }

  /// Gate true → one workflow item → Smart Add NEW.
  ///
  /// 自动写入白名单只放行 `workflow`（SoLab-全景文档 §B）：identity 条目在
  /// Smart Add 之前就被丢掉，因而 Distiller 不会被触发。
  Future<String> Function(String prompt) fullRunLlm() {
    var step = 0;
    return (prompt) async {
      step++;
      if (step == 1) return '<gate><user_memory>true</user_memory></gate>';
      if (step == 2) {
        return '<extracted><item type="workflow">'
            '处理混淆崩溃先确认 keep 规则覆盖反射入口。</item></extracted>';
      }
      return jsonEncode({'action': 'NEW', 'relatedIds': <String>[]});
    };
  }

  group('trace recording', () {
    test('captures executed stages with prompt, response and mutations', () async {
      final recorder = MemoryTraceRecorder();
      final pipeline = buildPipeline(recorder);
      final convo = await chatService.createConversation(
        title: '记忆测试',
        assistantId: 'a1',
      );

      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(convo.id),
        llmCall: fullRunLlm(),
      );
      expect(result.advanced, isTrue);

      expect(recorder.traces, hasLength(1));
      final trace = recorder.traces.first;
      expect(trace.conversationId, convo.id);
      expect(trace.conversationTitle, '记忆测试');
      expect(trace.assistantId, 'a1');
      expect(trace.assistantName, 'A1');
      expect(trace.scope, MemoryTraceScope.global);
      expect(trace.windowSize, 2);
      expect(trace.windowStartOrder, 4);
      expect(trace.windowEndOrder, 5);
      expect(trace.watermark, -1);
      expect(trace.advanced, isTrue);
      expect(trace.forcedAdvance, isFalse);
      expect(trace.error, isNull);

      expect(trace.steps.map((s) => s.kind).toList(), [
        MemoryTraceStepKind.gatekeeper,
        MemoryTraceStepKind.extract,
        MemoryTraceStepKind.smartAdd,
        MemoryTraceStepKind.profileDistiller,
      ]);
      for (final step in trace.steps.take(3)) {
        expect(step.status, MemoryTraceStepStatus.success);
        expect(step.prompt, isNotEmpty);
        expect(step.rawResponse, isNotEmpty);
        expect(step.duration, isNotNull);
      }
      // Distiller 只在 identity 真正落库时运行；白名单挡下身份类条目后这
      // 一轮必然跳过，但仍要出现在链里（查看器按四段展示）。
      expect(trace.steps[3].status, MemoryTraceStepStatus.skipped);
      expect(trace.steps[3].mutations, isEmpty);

      final gate = trace.steps[0];
      expect(gate.prompt, contains('用户：我是大学生'));
      expect(gate.rawResponse, contains('<user_memory>true'));
      expect(gate.parsedResult, 'worthRemembering');

      final extract = trace.steps[1];
      expect(extract.parsedResult, contains('混淆'));

      final smartAdd = trace.steps[2];
      expect(smartAdd.parsedResult, contains('NEW'));
      expect(smartAdd.mutations, hasLength(1));
      expect(
        smartAdd.mutations.first.kind,
        MemoryTraceMutationKind.memoryCreated,
      );
      expect(
        smartAdd.mutations.first.after,
        '处理混淆崩溃先确认 keep 规则覆盖反射入口。',
      );
      expect(smartAdd.mutations.first.targetId, isNotNull);
    });

    test('short-circuited stages are recorded as skipped', () async {
      final recorder = MemoryTraceRecorder();
      final pipeline = buildPipeline(recorder);
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );

      await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(convo.id),
        llmCall: (_) async => '<gate><user_memory>false</user_memory></gate>',
      );

      final trace = recorder.traces.single;
      expect(trace.steps.first.status, MemoryTraceStepStatus.success);
      expect(
        trace.steps.skip(1).map((s) => s.status).toList(),
        everyElement(MemoryTraceStepStatus.skipped),
      );
      expect(trace.advanced, isTrue);
    });

    test('a failed stage records the error and holds the watermark', () async {
      final recorder = MemoryTraceRecorder();
      final pipeline = buildPipeline(recorder);
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );

      await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(convo.id),
        llmCall: (_) async => 'unparseable',
      );

      final trace = recorder.traces.single;
      expect(trace.steps.first.status, MemoryTraceStepStatus.failed);
      expect(trace.steps.first.error, 'gate_parse_failed');
      expect(trace.error, 'gate_parse_failed');
      expect(trace.advanced, isFalse);
    });
  });

  group('toggle', () {
    test('disabled recorder records nothing', () async {
      final recorder = MemoryTraceRecorder(false);
      final pipeline = buildPipeline(recorder);
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );

      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(convo.id),
        llmCall: fullRunLlm(),
      );

      expect(result.advanced, isTrue);
      expect(recorder.traces, isEmpty);
    });

    test('turning the toggle off releases retained traces', () async {
      final recorder = MemoryTraceRecorder();
      final pipeline = buildPipeline(recorder);
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );
      await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(convo.id),
        llmCall: fullRunLlm(),
      );
      expect(recorder.traces, isNotEmpty);

      recorder.setEnabled(false);
      expect(recorder.traces, isEmpty);
    });

    test('the preference drives the shared recorder', () async {
      expect(settings.memoryTraceEnabled, isTrue);
      expect(MemoryTraceRecorder.instance.enabled, isTrue);

      await settings.setMemoryTraceEnabled(false);
      expect(settings.memoryTraceEnabled, isFalse);
      expect(MemoryTraceRecorder.instance.enabled, isFalse);

      await settings.setMemoryTraceEnabled(true);
      expect(MemoryTraceRecorder.instance.enabled, isTrue);
    });
  });

  group('ring buffer', () {
    test('keeps at most maxTraces, newest first', () {
      final recorder = MemoryTraceRecorder();
      for (var i = 0; i < MemoryTraceRecorder.maxTraces + 7; i++) {
        final handle = recorder.begin(
          trigger: MemoryTraceTrigger.manual,
          scope: MemoryTraceScope.global,
          conversationId: 'c$i',
        )!;
        handle.beginStep(MemoryTraceStepKind.gatekeeper);
        handle.commit(advanced: true);
      }

      expect(recorder.length, MemoryTraceRecorder.maxTraces);
      final traces = recorder.traces;
      expect(
        traces.first.conversationId,
        'c${MemoryTraceRecorder.maxTraces + 6}',
      );
      expect(traces.last.conversationId, 'c7');
    });

    test('repeated no-op triggers coalesce instead of evicting runs', () {
      final recorder = MemoryTraceRecorder();
      for (var i = 0; i < 5; i++) {
        recorder
            .begin(
              trigger: MemoryTraceTrigger.autoTurns,
              scope: MemoryTraceScope.global,
              conversationId: 'c1',
            )!
            .commit(error: 'below_threshold');
      }

      expect(recorder.length, 1);
      expect(recorder.traces.single.repeatCount, 5);
    });
  });

  group('failure isolation', () {
    test('a throwing recorder does not break the pipeline', () async {
      final recorder = _ThrowingRecorder();
      final pipeline = buildPipeline(recorder);
      final convo = await chatService.createConversation(
        title: 't',
        assistantId: 'a1',
      );

      final result = await pipeline.processWindow(
        conversationId: convo.id,
        assistant: assistant(),
        settings: settings,
        watermark: -1,
        window: sampleWindow(convo.id),
        llmCall: fullRunLlm(),
      );

      expect(recorder.beginCalls, greaterThan(0));
      expect(result.advanced, isTrue);
      expect(result.extractedCount, 1);
      final fresh = chatService.getConversation(convo.id);
      expect(fresh?.lastMemoryExtractedOrder, 5);
    });
  });

  // 自动写入白名单只放行 workflow，identity 条目进不了 Smart Add，因此
  // `identityChanged` 恒为 false、管线里的 Distiller 分支已不可达。蒸馏逻辑
  // 本身仍是「身份记忆 → 画像字段」的唯一实现，这里直接覆盖它。
  group('profile distiller', () {
    MemoryProfileDistiller buildDistiller() =>
        MemoryProfileDistiller(
          repository: memoryRepository,
          chatRepository: chatRepository,
        );

    test('records profileFieldWritten mutations on an open trace', () async {
      await memoryRepository.create(
        scope: MemoryScope.global,
        type: MemoryType.identity,
        content: '用户希望被称为小明。',
        source: MemorySource.tool,
      );

      final recorder = MemoryTraceRecorder();
      final handle = recorder.begin(
        trigger: MemoryTraceTrigger.manual,
        scope: MemoryTraceScope.global,
        assistantId: 'a1',
      )!;
      final step = handle.beginStep(MemoryTraceStepKind.profileDistiller);

      final ok = await buildDistiller().run(
        lang: MemoryPromptLang.zh,
        assistantId: 'a1',
        llmCall: (_) async => jsonEncode({
          'fields': [
            {'key': 'preferred_name', 'value': '小明'},
          ],
        }),
        traceStep: step,
      );
      handle.commit(advanced: true);

      expect(ok, isTrue);
      final mutation = step!.mutations.single;
      expect(mutation.kind, MemoryTraceMutationKind.profileFieldWritten);
      expect(mutation.targetId, 'preferred_name');
      expect(mutation.before, isNull);
      expect(mutation.after, '小明');
      expect(step.prompt, contains('用户希望被称为小明。'));

      final fields = await chatRepository.readProfileFields();
      expect(fields.single.key, 'preferred_name');
      expect(fields.single.value, '小明');
    });

    test('skips without identity entries and reports malformed JSON', () async {
      final recorder = MemoryTraceRecorder();
      final handle = recorder.begin(
        trigger: MemoryTraceTrigger.manual,
        scope: MemoryTraceScope.global,
        assistantId: 'a1',
      )!;
      final step = handle.beginStep(MemoryTraceStepKind.profileDistiller);

      final skipped = await buildDistiller().run(
        lang: MemoryPromptLang.zh,
        assistantId: 'a1',
        llmCall: (_) async => fail('must not call the model'),
        traceStep: step,
      );
      expect(skipped, isTrue);
      expect(step!.parsedResult, 'no_identity_entries');

      await memoryRepository.create(
        scope: MemoryScope.global,
        type: MemoryType.identity,
        content: '用户是大学生。',
        source: MemorySource.tool,
      );
      final malformed = await buildDistiller().run(
        lang: MemoryPromptLang.zh,
        assistantId: 'a1',
        llmCall: (_) async => 'not json at all',
      );
      expect(malformed, isFalse);
    });

    test('项目内的身份记忆不进全局画像（跨工作区泄漏闸门）', () async {
      // 画像字段是全局注入的；用带工作区标记的身份记忆蒸馏，等于把某个项目的
      // 身份写成所有工作区都看得到的画像。闸门：只吃未打标的全局身份记忆。
      ProjectScope.activeId = 'p-a';
      addTearDown(ProjectScope.clearActive);
      await memoryRepository.create(
        scope: MemoryScope.global,
        type: MemoryType.identity,
        content: '用户希望被称为小明。',
        source: MemorySource.tool,
      );
      // 条目现在带 p-a 标记；在同一个项目里跑蒸馏，它对 queryVisibleMemories
      // 是**可见**的——所以这条用例证明的是蒸馏器自己的闸门，而不是查询过滤。
      final visible = await chatRepository.queryVisibleMemories(
        assistantId: 'a1',
        type: MemoryType.identity,
      );
      expect(visible.single.projectId, 'p-a');

      final recorder = MemoryTraceRecorder();
      final handle = recorder.begin(
        trigger: MemoryTraceTrigger.manual,
        scope: MemoryTraceScope.global,
        assistantId: 'a1',
      )!;
      final step = handle.beginStep(MemoryTraceStepKind.profileDistiller);
      final ok = await buildDistiller().run(
        lang: MemoryPromptLang.zh,
        assistantId: 'a1',
        llmCall: (_) async => fail('must not call the model'),
        traceStep: step,
      );

      expect(ok, isTrue);
      expect(step!.parsedResult, 'no_identity_entries');
      expect(await chatRepository.readProfileFields(), isEmpty);
    });

    test('未打标的全局身份记忆照旧蒸馏', () async {
      // 与上一条互补：闸门只挡「项目身份」，不能把全局画像蒸馏一起关掉。
      ProjectScope.clearActive();
      await memoryRepository.create(
        scope: MemoryScope.global,
        type: MemoryType.identity,
        content: '用户希望被称为小明。',
        source: MemorySource.tool,
      );
      final recorder = MemoryTraceRecorder();
      final handle = recorder.begin(
        trigger: MemoryTraceTrigger.manual,
        scope: MemoryTraceScope.global,
        assistantId: 'a1',
      )!;
      final step = handle.beginStep(MemoryTraceStepKind.profileDistiller);
      final ok = await buildDistiller().run(
        lang: MemoryPromptLang.zh,
        assistantId: 'a1',
        llmCall: (_) async => jsonEncode({
          'fields': [
            {'key': 'preferred_name', 'value': '小明'},
          ],
        }),
        traceStep: step,
      );

      expect(ok, isTrue);
      final fields = await chatRepository.readProfileFields();
      expect(fields.single.value, '小明');
    });
  });
}
