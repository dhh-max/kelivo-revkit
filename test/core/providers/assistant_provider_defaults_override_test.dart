import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/providers/assistant_provider.dart';

import '../../support/business_preferences_test_harness.dart';
import 'package:Kelivo/core/models/model_spec.dart';
import 'package:Kelivo/core/models/reasoning_request.dart';

/// 内置 APK Mod 助手升级覆盖策略：
/// 用户编辑过（apk_mod_assistant_user_edited_v1=true）→ 升级不覆盖；
/// 未编辑 → 版本 key 低于当前时覆盖为最新模板。
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late BusinessPreferencesTestHarness harness;
  late BusinessPreferencesTestSession session;

  setUp(() async {
    harness = await BusinessPreferencesTestHarness.create();
    session = await harness.open();
  });

  tearDown(() => harness.dispose());

  Future<AssistantProvider> loadedProvider(
    List<Map<String, Object?>> assistants,
  ) async {
    await session.preferences.setString(
      'assistants_v1',
      jsonEncode(assistants),
    );
    final provider = AssistantProvider(preferences: session.preferences);
    for (
      var i = 0;
      i < 25 && provider.assistants.length != assistants.length;
      i++
    ) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
    return provider;
  }

  test('用户编辑过内置助手时：系统提示词升级为模板（v70 强制同步），其余配置保留', () async {
    const customPrompt = '用户自定义提示词，v69 及以前不被覆盖';
    final provider = await loadedProvider([
      {
        'id': AssistantProvider.apkModAssistantId,
        'name': 'APK Mod',
        'systemPrompt': customPrompt,
        'localToolIds': <String>['get_time_info'],
        'mcpServerIds': <String>['external-mt'],
      },
    ]);
    await session.preferences.setBool(
      'builtin_apk_mod_assistant_user_edited_v1',
      true,
    );
    await session.preferences.setInt('builtin_apk_mod_assistant_version', 30);

    await provider.ensureDefaults(null);

    final apkMod = provider.assistants.firstWhere(
      (a) => a.id == AssistantProvider.apkModAssistantId,
    );
    // v70 起：系统提示词被强制替换为最新模板（用户明确指定）。
    expect(apkMod.systemPrompt, isNot(customPrompt));
    expect(
      apkMod.systemPrompt,
      contains('You are 逆向助手 (SoLab)'),
    );
    // v102 起：助手名随版本强刷为「逆向助手」（内置助手身份由模板唯一决定）。
    expect(apkMod.name, '逆向助手');
    // 内置助手只保留当前模板工具，避免旧入口继续残留。
    expect(
      apkMod.localToolIds,
      containsAll(const [
        'route_task',
        'get_current_apk_report',
        'analyze_apk_workspace',
        'so_patch_into_apk',
        'analyzer.global_search',
        'analyzer.find_field_usage',
        'analyzer.analyze_business_state',
        'ask_user_input_v0',
        'get_agent_runtime_guide',
        'get_solab_tool_map',
        'list_workspace_apks',
        'get_apk_project_info',
        'list_apk_builds',
      ]),
    );
    // 迁移后工具集必须与当前模板一致，旧条目不得残留。
    // （历史断言用 get_time_info 探测，但模板后来把它并入
    //  BuiltinApkMod.toolIds 以对齐 MCP 暴露面，该探测已失效。）
    expect(apkMod.localToolIds, AssistantProvider.apkModToolIds);
    expect(apkMod.mcpServerIds, containsAll(['external-mt', 'solab_fetch']));
    expect(apkMod.reasoning?.level, ReasoningLevel.auto);
  });

  test('用户未编辑过内置助手时，升级覆盖为最新模板', () async {
    final provider = await loadedProvider([
      {
        'id': AssistantProvider.apkModAssistantId,
        'name': 'APK Mod',
        'systemPrompt': '旧提示词',
        'localToolIds': <String>['get_time_info'],
      },
    ]);
    await session.preferences.setInt('builtin_apk_mod_assistant_version', 30);

    await provider.ensureDefaults(null);

    final apkMod = provider.assistants.firstWhere(
      (a) => a.id == AssistantProvider.apkModAssistantId,
    );
    expect(apkMod.systemPrompt, isNot('旧提示词'));
    // 用户 2026-10-04 改口径：内置助手默认**不**限上下文条数（有自动压缩，
    // 限条数会让窗口永远不满、超出直接丢 = 静默失忆）。模板早已是 false，
    // 这里原先断言 true 属存量过期期望（2026-10-06 复核：stash 后同样失败）。
    expect(apkMod.limitContextMessages, isFalse);
    expect(apkMod.generateConversationSummary, isTrue);
    expect(apkMod.reasoning?.level, ReasoningLevel.auto);
    // v105：作业约定开关必须随模板刷到已装助手（漏搬字段 = 老装用户看不到开关）。
    expect(apkMod.operatorConventionsEnabled, isTrue);
    // Phase 0：内置助手收敛为 analyzer.* 高阶 API（58 工具不再直接挂载）。
    expect(
      apkMod.localToolIds,
      containsAll(const [
        'analyzer.global_search',
        'analyzer.find_field_usage',
        'analyzer.analyze_business_state',
      ]),
    );
  });

  test('用户明确关闭思考时升级不覆盖', () async {
    final provider = await loadedProvider([
      {
        'id': AssistantProvider.apkModAssistantId,
        'name': 'APK Mod',
        'reasoning': {'level': 'auto'},
      },
    ]);
    await session.preferences.setInt('builtin_apk_mod_assistant_version', 88);

    await provider.ensureDefaults(null);

    final apkMod = provider.assistants.firstWhere(
      (a) => a.id == AssistantProvider.apkModAssistantId,
    );
    expect(apkMod.reasoning?.level, ReasoningLevel.auto);
  });
}
