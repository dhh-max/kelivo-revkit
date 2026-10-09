import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:Kelivo/core/models/chat_input_data.dart';
import 'package:Kelivo/core/providers/assistant_provider.dart';
import 'package:Kelivo/core/providers/settings_provider.dart';
import 'package:Kelivo/core/providers/tts_provider.dart';
import 'package:Kelivo/core/providers/user_provider.dart';
import 'package:Kelivo/features/home/services/ask_user_interaction_service.dart';
import 'package:Kelivo/features/home/services/session_mode.dart';
import 'package:Kelivo/features/home/services/tool_approval_service.dart';
import 'package:Kelivo/features/home/widgets/chat_input_bar.dart';
import 'package:Kelivo/icons/lucide_adapter.dart';
import 'package:Kelivo/l10n/app_localizations.dart';

import '../test/support/business_test_harness.dart';

/// 第 66 项的真机验证：用户报的「选了模式胶囊，后面打字发送就被清空」。
/// 端上 adb 注入字符进不了 Flutter 输入框，所以用 integration_test 在真机
/// 上跑真实 widget 树 + 真实引擎（tester.enterText 走同一套输入通道）。
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  Future<TextEditingController> pumpBar(
    WidgetTester tester,
    List<String> sent, {
    String conversationId = 'conv-device',
  }) async {
    final harness = await createBusinessTestHarness();
    SharedPreferences.setMockInitialValues(<String, Object>{});
    final settings = SettingsProvider(harness.preferences);
    await settings.loaded;
    final controller = TextEditingController();
    final assistantProvider = AssistantProvider(
      preferences: createBusinessTestPreferences(),
    );
    await assistantProvider.loaded;
    final assistantId = await assistantProvider.addAssistant(name: 'Test');
    await assistantProvider.setCurrentAssistant(assistantId);
    await tester.pumpWidget(
      MultiProvider(
        providers: [
          ChangeNotifierProvider<SettingsProvider>.value(value: settings),
          ChangeNotifierProvider<AssistantProvider>.value(value: assistantProvider),
          ChangeNotifierProvider(
            create: (_) => TtsProvider(preferences: createBusinessTestPreferences()),
          ),
          ChangeNotifierProvider(create: (_) => ToolApprovalService()),
          ChangeNotifierProvider(create: (_) => AskUserInteractionService()),
          ChangeNotifierProvider(
            create: (_) =>
                UserProvider(preferences: createBusinessTestPreferences()),
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(
            body: ChatInputBar(
              controller: controller,
              conversationId: conversationId,
              onSend: (data) async {
                sent.add(data.text);
                return ChatInputSubmissionResult.sent;
              },
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    return controller;
  }

  testWidgets('真机：/plan + 尾随文字 = 切模式并把文字作为消息发出', (tester) async {
    SessionModeRuntime.reset();
    final sent = <String>[];
    final controller = await pumpBar(tester, sent);
    await tester.enterText(find.byType(TextField), '/plan 你好');
    await tester.pumpAndSettle();
    await tester.tap(find.byIcon(Lucide.ArrowUp));
    await tester.pumpAndSettle();
    expect(SessionModeRuntime.modeFor('conv-device'), SessionMode.plan);
    expect(sent, <String>['你好'], reason: '尾随文字必须发出去，不能被静默丢掉');
    expect(controller.text, isEmpty);
    controller.dispose();
  });

  testWidgets('真机：面板选中 /plan 之后输入框带分隔空格（继续打字仍是合法命令）', (tester) async {
    SessionModeRuntime.reset();
    final sent = <String>[];
    final controller = await pumpBar(tester, sent);
    await tester.enterText(find.byType(TextField), '/pl');
    await tester.pumpAndSettle();
    await tester.tap(find.textContaining('/plan').first);
    await tester.pumpAndSettle();
    expect(controller.text, '/plan ');
    await tester.enterText(find.byType(TextField), '/plan 你好');
    await tester.pumpAndSettle();
    await tester.tap(find.byIcon(Lucide.ArrowUp));
    await tester.pumpAndSettle();
    expect(SessionModeRuntime.modeFor('conv-device'), SessionMode.plan);
    expect(sent, <String>['你好']);
    controller.dispose();
  });
}
