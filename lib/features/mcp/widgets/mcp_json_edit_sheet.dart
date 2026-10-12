import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../icons/lucide_adapter.dart';
import '../../../core/providers/mcp_provider.dart';
import '../../../shared/widgets/snackbar.dart';
import '../../../l10n/app_localizations.dart';
import '../../../core/providers/settings_provider.dart';
import '../../../theme/app_font_weights.dart';
import 'package:Kelivo/theme/app_semantic_colors.dart';
import 'json_error_text.dart';

Future<void> showMcpJsonEditSheet(BuildContext context) async {
  final cs = Theme.of(context).colorScheme;
  await showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    backgroundColor: cs.surface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
    ),
    builder: (ctx) => _McpJsonEditSheet(),
  );
}

class _McpJsonEditSheet extends StatefulWidget {
  @override
  State<_McpJsonEditSheet> createState() => _McpJsonEditSheetState();
}

class _McpJsonEditSheetState extends State<_McpJsonEditSheet> {
  final _controller = TextEditingController();
  String? _error;

  /// 打开时的原文：用来判断"有未保存改动"，避免点 X 无声丢掉编辑。
  late final String _originalText;

  @override
  void initState() {
    super.initState();
    final mcp = context.read<McpProvider>();
    _controller.text = mcp.exportServersAsUiJson();
    _originalText = _controller.text;
  }

  /// 破坏性操作前的一次确认（整份覆盖 / 丢弃未保存内容）。
  Future<bool> _confirm(String title, String content, String okLabel) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: Text(content, style: const TextStyle(fontSize: 13, height: 1.6)),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: Text(okLabel),
          ),
        ],
      ),
    );
    return ok == true;
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final l10n = AppLocalizations.of(context)!;
    try {
      // Quick JSON check before provider import for immediate feedback
      jsonDecode(_controller.text);
    } catch (e) {
      setState(() => _error = describeJsonError(e));
      showAppSnackBar(
        context,
        message: l10n.mcpJsonEditParseFailed,
        type: NotificationType.warning,
      );
      return;
    }
    // 保存是"整份覆盖"现有服务器配置：改错了会一次性丢掉所有条目，先确认。
    if (!await _confirm(
      '保存整份配置？',
      '将用当前 JSON 整份替换本机 MCP 服务器配置。',
      '保存',
    )) {
      return;
    }
    if (!mounted) return;
    try {
      await context.read<McpProvider>().replaceAllFromJson(_controller.text);
      if (!mounted) return;
      Navigator.of(context).maybePop();
      showAppSnackBar(context, message: l10n.mcpJsonEditSavedApplied);
    } catch (e) {
      final friendly = describeJsonError(e);
      setState(() => _error = friendly);
      if (!mounted) return;
      showAppSnackBar(
        context,
        message: friendly,
        type: NotificationType.warning,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    // Resolve user-preferred code font family (local/system)
    final settings = context.watch<SettingsProvider>();
    String resolveCodeFont() {
      final fam = settings.codeFontFamily;
      if (fam == null || fam.isEmpty) return 'monospace';
      return fam;
    }

    final codeFontFamily = resolveCodeFont();
    final media = MediaQuery.of(context);
    final height = media.size.height * 0.9;

    return SafeArea(
      child: SizedBox(
        height: height,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Drag handle
            const SizedBox(height: 8),
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: cs.onSurface.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            // const SizedBox(height: 6),
            // Header bar
            Padding(
              padding: const EdgeInsets.fromLTRB(8, 2, 8, 6),
              child: Row(
                children: [
                  IconButton(
                    onPressed: () async {
                      if (_controller.text != _originalText) {
                        final discard = await _confirm(
                          '放弃未保存的修改？',
                          '当前编辑内容尚未保存，关闭后会丢失。',
                          '放弃',
                        );
                        if (!discard || !context.mounted) return;
                      }
                      if (!context.mounted) return;
                      Navigator.of(context).maybePop();
                    },
                    icon: Icon(Lucide.X, size: 20, color: cs.onSurface),
                    tooltip: MaterialLocalizations.of(
                      context,
                    ).closeButtonTooltip,
                  ),
                  const Spacer(),
                  Text(
                    AppLocalizations.of(context)!.mcpJsonEditTitle,
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: AppFontWeights.emphasis,
                    ),
                  ),
                  const Spacer(),
                  IconButton(
                    onPressed: _save,
                    icon: Icon(Lucide.Check, size: 20, color: cs.primary),
                    tooltip: AppLocalizations.of(
                      context,
                    )!.mcpServerEditSheetSave,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 4),
            Expanded(
              child: Padding(
                padding: EdgeInsets.only(
                  left: 12,
                  right: 12,
                  bottom: media.viewInsets.bottom + 12,
                ),
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    color: context.appColors.surfaceCard,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: cs.outlineVariant.withValues(alpha: 0.3),
                    ),
                  ),
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: TextField(
                      controller: _controller,
                      autocorrect: false,
                      enableSuggestions: false,
                      smartDashesType: SmartDashesType.disabled,
                      smartQuotesType: SmartQuotesType.disabled,
                      keyboardType: TextInputType.multiline,
                      maxLines: null,
                      style: TextStyle(
                        fontFamily: codeFontFamily,
                        fontSize: 13.5,
                        height: 1.4,
                      ),
                      decoration: const InputDecoration(
                        isCollapsed: true,
                        border: InputBorder.none,
                      ),
                    ),
                  ),
                ),
              ),
            ),
            if (_error != null) ...[
              Padding(
                padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
                child: Text(
                  _error!,
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.error,
                    fontSize: 12,
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
