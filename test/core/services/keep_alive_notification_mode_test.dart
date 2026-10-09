import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/android_background.dart';
import 'package:Kelivo/core/services/mcp_server/mcp_http_server.dart';

/// 保活（FGS）常驻通知的**模式区分**回归（2026-09-19 用户要求；
/// 2026-09-21 增补 MCP 端口段与"关闭"动作的回调契约）。
///
/// 此前两种模式都只显示同一句「后台任务保活中」：MCP 模式（局域网 MCP 服务
/// 在跑、本地 Agent 工具暂停）与本地 Agent 模式在通知栏完全分不出来。
/// 现在正文统一带模式前缀，MCP 模式再带端口——这里把「两种模式文案必须不同」
/// 「携带端口」「反复刷新不会越加越长」钉住（走 composeNotificationText 缝，
/// 不依赖平台通道）。
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final port = McpHttpServer.instance.port;

  tearDown(() {
    AndroidBackgroundManager.isMcpMode = () => false;
  });

  test('Agent 模式：前缀是 Agent 模式，且不再是裸的保活文案', () {
    AndroidBackgroundManager.isMcpMode = () => false;
    final text = AndroidBackgroundManager.composeNotificationText(null);
    expect(text, 'Agent 模式 · 后台任务保活中');
    expect(
      text,
      isNot(contains('端口')),
      reason: 'Agent 模式没有服务端口，写端口就是假信息',
    );
  });

  test('MCP 模式：前缀带端口（用户要能一眼看出服务在哪个端口）', () {
    AndroidBackgroundManager.isMcpMode = () => false;
    final agent = AndroidBackgroundManager.composeNotificationText(null);
    AndroidBackgroundManager.isMcpMode = () => true;
    final mcp = AndroidBackgroundManager.composeNotificationText(null);
    expect(mcp, startsWith('MCP 模式 · 端口 '));
    expect(mcp, contains('$port'));
    expect(mcp, isNot(agent));
  });

  test('调用方给的正文被保留，只加前缀', () {
    AndroidBackgroundManager.isMcpMode = () => true;
    expect(
      AndroidBackgroundManager.composeNotificationText('后台保持聊天生成'),
      'MCP 模式 · 端口 $port · 后台保持聊天生成',
    );
  });

  test('反复组合不会把模式前缀/端口越加越多', () {
    AndroidBackgroundManager.isMcpMode = () => true;
    var text = AndroidBackgroundManager.composeNotificationText('后台任务保活中');
    for (var i = 0; i < 3; i++) {
      text = AndroidBackgroundManager.composeNotificationText(text);
    }
    expect('MCP 模式'.allMatches(text).length, 1, reason: '前缀只允许出现一次');
    expect('端口'.allMatches(text).length, 1, reason: '端口段只允许出现一次');
    expect(text, 'MCP 模式 · 端口 $port · 后台任务保活中');
  });

  test('模式切换后正文随之改变（MCP → Agent：端口段随之消失）', () {
    AndroidBackgroundManager.isMcpMode = () => true;
    final mcp = AndroidBackgroundManager.composeNotificationText('后台任务保活中');
    AndroidBackgroundManager.isMcpMode = () => false;
    final agent = AndroidBackgroundManager.composeNotificationText(mcp);
    expect(mcp, 'MCP 模式 · 端口 $port · 后台任务保活中');
    expect(
      agent,
      'Agent 模式 · 后台任务保活中',
      reason: '切回 Agent 时端口段必须被剥掉，否则会留一个不存在的端口',
    );
  });

  test('空正文不会把前缀剥成空串', () {
    expect(
      AndroidBackgroundManager.stripNotificationPrefix('MCP 模式 · 端口 $port'),
      '后台任务保活中',
    );
    expect(AndroidBackgroundManager.stripNotificationPrefix('  '), '后台任务保活中');
  });

  test('通知上的「关闭」：原生回传后触发回调并清空本地运行态', () async {
    var called = 0;
    AndroidBackgroundManager.onUserStoppedFromNotification = () async {
      called++;
    };
    addTearDown(() {
      AndroidBackgroundManager.onUserStoppedFromNotification = null;
    });
    AndroidBackgroundManager.debugAttachHandlers();

    await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .handlePlatformMessage(
          'app.background',
          const StandardMethodCodec().encodeMethodCall(
            const MethodCall('keepAliveStoppedByUser'),
          ),
          (_) {},
        );

    expect(called, 1, reason: '原生点「关闭」后 Dart 必须退出 MCP 模式');
  });
}
