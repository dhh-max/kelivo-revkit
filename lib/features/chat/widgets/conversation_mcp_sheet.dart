import 'dart:async';

import 'package:Kelivo/core/models/assistant.dart';
import 'package:Kelivo/core/providers/assistant_provider.dart';
import 'package:Kelivo/core/providers/mcp_provider.dart';
import 'package:Kelivo/core/services/chat/chat_service.dart';
import 'package:Kelivo/core/services/mcp/mcp_tool_service.dart';
import 'package:Kelivo/l10n/app_localizations.dart';
import 'package:Kelivo/shared/widgets/form_sheet.dart';
import 'package:Kelivo/shared/widgets/ios_settings_rows.dart';
import 'package:Kelivo/shared/widgets/section_card.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

/// 会话级 MCP 服务器白名单弹层。
///
/// 语义：会话白名单非空时**收窄**助手可见的 MCP（求交）；清空即「跟随助手
/// 设置」。只写 Conversation.mcpServerIds，不修改助手配置。
Future<void> showConversationMcpSheet(
  BuildContext context, {
  required String conversationId,
  required String assistantId,
}) {
  final l10n = AppLocalizations.of(context)!;
  return showFormSheet<void>(
    context,
    builder: (ctx) => FormSheet(
      title: l10n.mcpSessionTitle,
      children: [
        ConversationMcpPanel(
          conversationId: conversationId,
          assistantId: assistantId,
        ),
      ],
    ),
  );
}

class ConversationMcpPanel extends StatelessWidget {
  const ConversationMcpPanel({
    super.key,
    required this.conversationId,
    required this.assistantId,
  });

  final String conversationId;
  final String assistantId;

  Assistant? _assistant(AssistantProvider provider) => assistantId.isEmpty
      ? provider.currentAssistant
      : provider.getById(assistantId);

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final mcp = context.watch<McpProvider>();
    final chat = context.watch<ChatService>();
    final assistant = _assistant(context.watch<AssistantProvider>());
    final service = context.read<McpToolService>();
    final conversationIds = chat.getConversationMcpServers(conversationId);
    final explicit = conversationIds.isNotEmpty;
    final selected = service.effectiveServersForAssistant(
      mcp,
      assistant,
      conversationServerIds: explicit ? conversationIds.toSet() : null,
    );
    final servers = mcp.servers
        .where((server) => mcp.statusFor(server.id) == McpStatus.connected)
        .toList();

    Future<void> write(Iterable<String> ids) =>
        chat.setConversationMcpServers(conversationId, ids.toList());

    Future<void> toggle(String serverId, bool value) async {
      final next = selected.toSet();
      if (value) {
        next.add(serverId);
      } else {
        next.remove(serverId);
      }
      await write(next);
    }

    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
          child: Text(
            l10n.mcpSessionHint,
            style: TextStyle(
              fontSize: 12,
              color: cs.onSurface.withValues(alpha: 0.6),
            ),
          ),
        ),
        SectionCard(
          children: [
            IosSwitchRow(
              key: const ValueKey<String>('conversation-mcp-follow-assistant'),
              label: l10n.mcpSessionFollowAssistant,
              value: !explicit,
              onChanged: (value) async {
                await write(value ? const <String>[] : selected);
              },
            ),
            if (servers.isEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 12),
                child: Text(
                  l10n.mcpSessionEmpty,
                  style: TextStyle(fontSize: 13, color: cs.onSurface),
                ),
              )
            else
              for (final server in servers)
                IosSwitchRow(
                  key: ValueKey<String>(
                    'conversation-mcp-server-${server.id}',
                  ),
                  label: server.name,
                  value: selected.contains(server.id),
                  onChanged: (value) => unawaited(toggle(server.id, value)),
                ),
          ],
        ),
      ],
    );
  }
}
