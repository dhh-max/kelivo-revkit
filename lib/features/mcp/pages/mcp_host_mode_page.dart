import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../core/providers/settings_provider.dart';
import '../../../core/services/android_background.dart';
import '../../../core/services/mcp_server/mcp_http_server.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/form_sheet.dart';
import '../../../shared/widgets/snackbar.dart';
import '../../../shared/widgets/ios_settings_rows.dart';
import '../../../shared/widgets/ios_tile_button.dart';
import '../../../shared/widgets/section_card.dart';
import '../../../theme/app_font_weights.dart';
import 'package:Kelivo/theme/app_semantic_colors.dart';

class McpHostModeGate extends StatelessWidget {
  const McpHostModeGate({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    if (!context.watch<SettingsProvider>().mcpServerEnabled) return child;
    final isDark = Theme.of(context).brightness == Brightness.dark;
    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
        statusBarBrightness: isDark ? Brightness.dark : Brightness.light,
      ),
      // 本页挂在 MaterialApp.builder 层（Navigator 之上），从这里的 context
      // 弹出 bottom sheet / snackbar 会落在页面**下面**（看不见 → 表现为"点了没反应"）。
      // 给它自己的 Navigator + ScaffoldMessenger：弹层与提示都渲染在本页之上。
      child: ScaffoldMessenger(
        child: Navigator(
          onGenerateRoute: (_) => MaterialPageRoute<void>(
            settings: const RouteSettings(name: 'mcp-host-mode'),
            builder: (_) => const McpHostModePage(),
          ),
        ),
      ),
    );
  }
}

/// 「三步完成连接」文案（原页面内联的长指引，收敛进「连接指引」弹层）。
const List<String> _guideSteps = [
  '电脑与本机连同一局域网（手机热点也可以）',
  '在 Claude Code / Cursor 等客户端添加 MCP 服务器，地址填下方连接信息里的任意一个',
  '开启访问保护时，把「安全」里的访问令牌一并填上',
];

void _copyText(BuildContext context, String value, String message) {
  Clipboard.setData(ClipboardData(text: value));
  // 反馈统一走项目标准的 showAppSnackBar（图标 + 类型配色），不用裸 SnackBar。
  showAppSnackBar(context, message: message);
}

/// 重新生成 MCP 访问令牌：确认后旧令牌**立即失效**，所有客户端需重填。
///
/// 为什么必须显式轮换：`setMcpServerAuthEnabled` 只负责开关，重新打开时会
/// **复用**已存在的令牌（`_mcpServerToken.isEmpty ? 生成 : 旧值`），所以关闭再
/// 打开拿到的还是同一个令牌——一旦令牌被截图/日志泄漏，用户没有任何补救路径。
/// 服务端在每次请求时实时读 `_token`，但持有者是单例，轮换后必须再 configure
/// 一次，否则正在跑的服务仍在用旧值。
///
/// 抽成顶层函数（而不是页面的私有方法）是为了让 widget 测试能直接驱动。
Future<bool> rotateMcpServerToken(BuildContext context) async {
  final settings = context.read<SettingsProvider>();
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: const Text('重新生成访问令牌？'),
      content: const Text(
        '旧令牌会立即失效，已连接或已配置的客户端都要重新填写新令牌。',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(false),
          child: const Text('取消'),
        ),
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(true),
          child: const Text('重新生成'),
        ),
      ],
    ),
  );
  if (confirmed != true) return false;
  await settings.regenerateMcpServerToken();
  McpHttpServer.instance.configure(token: settings.mcpServerToken);
  if (context.mounted) {
    showAppSnackBar(context, message: '已生成新访问令牌，旧令牌立即失效');
  }
  return true;
}

/// 客户端活动时间（HH:mm:ss）。只用于"最近一次请求"这类自证信息，
/// 不做日期推断——跨天的会话本来就该在页面刷新时重看。
String _formatClock(DateTime time) =>
    '${time.hour.toString().padLeft(2, '0')}:'
    '${time.minute.toString().padLeft(2, '0')}:'
    '${time.second.toString().padLeft(2, '0')}';

/// 连接指引弹层：三步完成连接 / 连接地址 / JSON 配置（等宽字体 + 复制）/ 使用说明。
/// MCP 页与 MCP 全屏模式页共用同一条一行入口，长指引不再铺在页面上。
Future<void> showMcpConnectionGuideSheet(BuildContext context) async {
  final l10n = AppLocalizations.of(context)!;
  final settings = context.read<SettingsProvider>();
  final server = McpHttpServer.instance;
  final running = server.isRunning;
  final urls = running ? server.lanUrls : const <String>[];
  final token = settings.mcpServerToken;
  final address = urls.isEmpty ? '' : (urls.length > 1 ? urls[1] : urls.first);
  final headers = token.isEmpty
      ? ''
      : ',\n      "headers": {"Authorization": "Bearer $token"}';
  final json =
      '{\n'
      '  "mcpServers": {\n'
      '    "solab": {\n'
      '      "type": "http",\n'
      '      "url": "$address"$headers\n'
      '    }\n'
      '  }\n'
      '}';
  await showFormSheet<void>(
    context,
    builder: (ctx) {
      final cs = Theme.of(ctx).colorScheme;
      final textTheme = Theme.of(ctx).textTheme;
      return FormSheet(
        title: '连接指引',
        children: [
          SizedBox(
            width: double.infinity,
            child: IosSectionHeader(text: '三步完成连接', first: true),
          ),
          SectionCard(
            padding: EdgeInsets.zero,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              for (var i = 0; i < _guideSteps.length; i++) ...[
                if (i > 0) const IosRowDivider(indent: 44),
                _GuideStepRow(index: i + 1, text: _guideSteps[i]),
              ],
            ],
          ),
          SizedBox(
            width: double.infinity,
            child: IosSectionHeader(text: l10n.mcpServerUrlsLabel),
          ),
          SectionCard(
            padding: EdgeInsets.zero,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: running
                ? [
                    for (var i = 0; i < urls.length; i++) ...[
                      if (i > 0) const IosRowDivider(),
                      _HostAddressRow(
                        icon: i == 0 ? Lucide.Smartphone : Lucide.Globe,
                        label: i == 0 ? '本机' : '局域网',
                        value: urls[i],
                        onCopy: () => _copyText(ctx, urls[i], '已复制连接地址'),
                      ),
                    ],
                  ]
                : const [
                    _HostNoticeRow(
                      icon: Lucide.TriangleAlert,
                      text: '服务未运行，暂无可用地址',
                      destructive: true,
                    ),
                  ],
          ),
          SizedBox(
            width: double.infinity,
            child: IosSectionHeader(text: 'JSON 配置'),
          ),
          SectionCard(
            padding: EdgeInsets.zero,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: running
                ? [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(12, 12, 12, 12),
                      child: Text(
                        json,
                        style: textTheme.bodySmall?.copyWith(
                          fontFamily: 'monospace',
                          height: 1.5,
                        ),
                      ),
                    ),
                    const IosRowDivider(indent: 12),
                    Padding(
                      padding: const EdgeInsets.fromLTRB(12, 8, 12, 10),
                      child: IosTileButton(
                        icon: Lucide.Copy,
                        label: l10n.mcpServerCopyToken,
                        backgroundColor: cs.primary,
                        onTap: () => _copyText(ctx, json, l10n.mcpServerCopied),
                      ),
                    ),
                  ]
                : const [
                    _HostNoticeRow(
                      icon: Lucide.TriangleAlert,
                      text: '服务未运行，暂无可用地址',
                      destructive: true,
                    ),
                  ],
          ),
          SizedBox(
            width: double.infinity,
            child: IosSectionHeader(text: '使用说明'),
          ),
          SectionCard(
            padding: EdgeInsets.zero,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Padding(
                padding: const EdgeInsets.all(12),
                child: Text(
                  l10n.mcpServerSheetDesc,
                  style: textTheme.bodySmall?.copyWith(
                    color: cs.onSurface.withValues(alpha: 0.8),
                    height: 1.5,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
        ],
      );
    },
  );
}

/// MCP 全屏模式页：顶部状态卡（状态 / 连接信息 / 连接指引一行入口），
/// 中部连接地址与访问令牌，底部常驻「退出 MCP 模式」（主操作不随长页面滚动）。
class McpHostModePage extends StatelessWidget {
  const McpHostModePage({super.key});

  Future<void> _exit(BuildContext context) async {
    final settings = context.read<SettingsProvider>();
    await McpHttpServer.instance.stop();
    await settings.setMcpServerEnabled(false);
    if (Platform.isAndroid &&
        settings.androidBackgroundChatMode == AndroidBackgroundChatMode.off &&
        !AndroidBackgroundManager.hasActiveGenerationHold) {
      try {
        await AndroidBackgroundManager.setEnabled(false);
      } catch (_) {}
    } else if (Platform.isAndroid) {
      await AndroidBackgroundManager.setEnabled(
        true,
        networkRequired: AndroidBackgroundManager.hasActiveGenerationHold,
      );
    }
    if (Platform.isAndroid) {
      // 保活通知的文案带运行时模式前缀；退出 MCP 模式后 FGS 仍在跑时必须
      // 刷新一次，否则常驻通知还写着「MCP 模式」。
      await AndroidBackgroundManager.refreshNotification();
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    final settings = context.watch<SettingsProvider>();
    final server = McpHttpServer.instance;
    return ListenableBuilder(
      listenable: server,
      builder: (context, _) {
        final running = server.isRunning;
        final urls = server.lanUrls;
        final authOn = server.authRequired;
        // 2026-09-21 修：过去用 sseSessionCount，只数 legacy GET /sse 会话；
        // 现代客户端走 Streamable HTTP（POST /mcp，无状态）不计入 → 页面永远
        // 显示 0 个客户端，用户据此判断"没连上"。
        final sessions = server.activeClientCount;
        final lastActivity = server.lastClientActivityAt;
        final statusColor = running ? context.appColors.success : cs.error;
        return Scaffold(
          backgroundColor: cs.surface,
          body: SafeArea(
            bottom: false,
            child: ListView(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
              children: [
                // 状态卡：状态 / 连接信息 / 连接指引（一行入口 → 弹层）
                SectionCard(
                  variant: SectionCardVariant.emphasized,
                  padding: EdgeInsets.zero,
                  children: [
                    IosNavRow(
                      icon: running ? Lucide.Network : Lucide.TriangleAlert,
                      iconColor: statusColor,
                      label: l10n.mcpServerTitle,
                      labelWeight: AppFontWeights.medium,
                      subtitle: running ? '工具端运行中' : '服务已停止',
                    ),
                    const IosRowDivider(),
                    IosNavRow(
                      icon: Lucide.Activity,
                      label: '连接信息',
                      detailText: running
                          ? '$sessions 个客户端 · 端口 ${server.port}'
                          : '端口 ${server.port}',
                    ),
                    const IosRowDivider(),
                    IosNavRow(
                      icon: Lucide.BookOpen,
                      iconColor: cs.primary,
                      label: '连接指引',
                      labelWeight: AppFontWeights.medium,
                      subtitle: '电脑端',
                      onTap: () =>
                          unawaited(showMcpConnectionGuideSheet(context)),
                    ),
                  ],
                ),
                IosSectionFooter(
                  text: !running
                      ? '请退出后检查端口并重新开启'
                      : sessions > 0
                      ? '$sessions 个外部客户端已连接 · App 内 Agent 工具已暂停'
                      // 没连上时给出可自证的信息：最近一次请求时间。用户让电脑端
                      // 发一次调用就能看到它跳字——比"等待连接"这句静止的文案有
                      // 用得多（2026-09-21 用户反馈"是否已连接没有任何效果"）。
                      : lastActivity == null
                      ? '等待外部 AI 客户端连接 · App 内 Agent 工具已暂停'
                      : '暂无在线客户端（最近一次请求 ${_formatClock(lastActivity)}）'
                            ' · App 内 Agent 工具已暂停',
                ),
                const SizedBox(height: 18),
                // 连接地址
                IosSectionHeader(
                  text: running
                      ? '${urls.length} 个可用地址'
                      : l10n.mcpServerUrlsLabel,
                ),
                SectionCard(
                  padding: EdgeInsets.zero,
                  children: running
                      ? [
                          for (var i = 0; i < urls.length; i++) ...[
                            if (i > 0) const IosRowDivider(),
                            _HostAddressRow(
                              icon: i == 0 ? Lucide.Smartphone : Lucide.Globe,
                              label: i == 0 ? '本机' : '局域网',
                              value: urls[i],
                              onCopy: () =>
                                  _copyText(context, urls[i], '已复制连接地址'),
                            ),
                          ],
                        ]
                      : const [
                          _HostNoticeRow(
                            icon: Lucide.TriangleAlert,
                            text: '服务未运行，暂无可用地址',
                            destructive: true,
                          ),
                        ],
                ),
                IosSectionHeader(text: '安全'),
                // 访问保护 / 访问令牌
                SectionCard(
                  padding: EdgeInsets.zero,
                  children: [
                    IosNavRow(
                      icon: authOn ? Lucide.ShieldCheck : Lucide.Shield,
                      iconColor: authOn ? context.appColors.success : null,
                      label: authOn ? '访问保护已开启' : '访问保护未开启',
                      labelWeight: AppFontWeights.medium,
                      subtitle: authOn ? null : '局域网内客户端可直接连接',
                    ),
                    if (authOn) ...[
                      const IosRowDivider(),
                      IosNavRow(
                        icon: Lucide.KeyRound,
                        label: l10n.mcpServerTokenLabel,
                        // 令牌不减位数（安全不动），显示用一行掩码：
                        // 完整值点按即复制，JSON 配置弹层里也有全文。
                        subtitle: _maskToken(settings.mcpServerToken),
                        subtitleMaxLines: 1,
                        trailing: Icon(
                          Lucide.Copy,
                          size: 17,
                          color: cs.onSurfaceVariant,
                        ),
                        onTap: () => _copyText(
                          context,
                          settings.mcpServerToken,
                          '已复制访问令牌',
                        ),
                      ),
                      const IosRowDivider(),
                      // 泄漏补救路径：令牌一旦生成就再也不会变，必须给用户一个
                      // 「换掉它」的入口（旧令牌立即失效）。
                      IosNavRow(
                        icon: Lucide.RefreshCw,
                        label: '重新生成令牌',
                        subtitle: '旧令牌立即失效，客户端需重新填写',
                        onTap: () => unawaited(rotateMcpServerToken(context)),
                      ),
                    ],
                  ],
                ),
                IosSectionHeader(text: '工具权限'),
                // 用户 2026-10-06：MCP 可能是别的工具在调，而子代理/AI 工作流
                // 花的是本机 App 里的模型额度——默认不允许，要显式打开。
                SectionCard(
                  padding: EdgeInsets.zero,
                  children: [
                    FormSheetSwitchRow(
                      key: const ValueKey('mcp-allow-quota-tools'),
                      label: '允许子代理',
                      value: settings.mcpServerAllowQuotaTools,
                      onChanged: (v) => unawaited(
                        context
                            .read<SettingsProvider>()
                            .setMcpServerAllowQuotaTools(v),
                      ),
                    ),
                    const IosRowDivider(),
                    // 用户 2026-10-06：与端内逆向助手同一份「作业约定」，
                    // 打开后随 initialize 的 instructions 下发给 MCP 客户端。
                    FormSheetSwitchRow(
                      key: const ValueKey('mcp-operator-conventions'),
                      label: '作业约定',
                      value: settings.mcpServerOperatorConventions,
                      onChanged: (v) => unawaited(
                        context
                            .read<SettingsProvider>()
                            .setMcpServerOperatorConventions(v),
                      ),
                    ),
                  ],
                ),
                IosSectionFooter(
                  text: '「允许子代理」打开后，MCP 客户端可调用 subagent 与 '
                      'run_workflow —— 它们消耗本机配置的模型额度（你 App 里的 '
                      'token）。「作业约定」打开后，连接时下发的指令会追加一份'
                      '工作台约定：授权范围内直接执行、越界只说一次并给替代、'
                      '交付带产物路径与回执证据。关闭时这两项都保持原状。',
                ),
              ],
            ),
          ),
          // 主操作常驻底部：退出无需在长页面里滚动。
          bottomNavigationBar: SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  FilledButton.icon(
                    icon: const Icon(Lucide.CircleStop, size: 18),
                    label: const Text('退出 MCP 模式'),
                    style: FilledButton.styleFrom(
                      minimumSize: const Size.fromHeight(48),
                    ),
                    onPressed: () async {
                      final ok = await showDialog<bool>(
                        context: context,
                        builder: (dctx) => AlertDialog(
                          title: const Text('退出 MCP 模式'),
                          content: const Text(
                            '退出后本机工具面立即关闭，已连接的外部 AI 会断开。确定退出？',
                          ),
                          actions: [
                            TextButton(
                              onPressed: () => Navigator.of(dctx).pop(false),
                              child: const Text('取消'),
                            ),
                            FilledButton(
                              onPressed: () => Navigator.of(dctx).pop(true),
                              child: const Text('退出'),
                            ),
                          ],
                        ),
                      );
                      if (ok != true || !context.mounted) return;
                      await _exit(context);
                    },
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '退出后恢复 App 使用，外部 AI 将断开连接',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: cs.onSurface.withValues(alpha: 0.55),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

/// 指引步骤：圆形序号 + 可换行的说明（分享行的 label 只支持单行，长句会被截断）。
class _GuideStepRow extends StatelessWidget {
  const _GuideStepRow({required this.index, required this.text});

  final int index;
  final String text;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 22,
            height: 22,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: cs.primary.withValues(alpha: 0.12),
              shape: BoxShape.circle,
            ),
            child: Text(
              '$index',
              style: theme.textTheme.labelSmall?.copyWith(
                color: cs.primary,
                fontWeight: AppFontWeights.semibold,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              text,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: cs.onSurface.withValues(alpha: 0.9),
                height: 1.4,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// 一条连接地址：名称 + 可换行的地址值 + 复制。
class _HostAddressRow extends StatelessWidget {
  const _HostAddressRow({
    required this.icon,
    required this.label,
    required this.value,
    required this.onCopy,
  });

  final IconData icon;
  final String label;
  final String value;
  final VoidCallback onCopy;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return IosNavRow(
      icon: icon,
      label: label,
      subtitle: value,
      subtitleMaxLines: null,
      trailing: Icon(Lucide.Copy, size: 17, color: cs.onSurfaceVariant),
      onTap: onCopy,
    );
  }
}

/// 状态提示行（无操作）。
class _HostNoticeRow extends StatelessWidget {
  const _HostNoticeRow({
    required this.icon,
    required this.text,
    this.destructive = false,
  });

  final IconData icon;
  final String text;
  final bool destructive;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return IosNavRow(
      icon: icon,
      iconColor: destructive ? cs.error : null,
      label: text,
    );
  }
}

/// 令牌显示掩码：前 10 + … + 后 6（一行放得下），完整值靠复制/JSON 配置。
String _maskToken(String token) {
  final trimmed = token.trim();
  if (trimmed.isEmpty) return trimmed;
  if (trimmed.length <= 8) {
    return List<String>.filled(trimmed.length, '•').join();
  }
  final short = trimmed.length <= 18;
  final head = short ? 4 : 10;
  final tail = short ? 4 : 6;
  return '${trimmed.substring(0, head)}…${trimmed.substring(trimmed.length - tail)}';
}
