import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/models/chat_message.dart';
import '../../../core/models/message_part.dart';
import '../../../core/providers/settings_provider.dart';
import '../../../core/providers/tts_provider.dart';
import '../../../core/services/tts/tts_text_selection.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/custom_bottom_sheet.dart';
import '../../../theme/app_font_weights.dart';
import '../../chat/widgets/chat_message_widget.dart';
import '../../home/services/subagent_run_monitor.dart';

/// 子代理队列与对话历史弹窗（2026-10-01）。
///
/// 用户原话：专家团「哪一个出他就亮哪一个，然后点击的话可以展开，包括他们
/// 的队列」；单发子代理「也是可以弹窗一样的展开，我要看到它的思考内容、
/// 它的对话历史之类的，现在的都是静默的」。
///
/// 两个入口：状态条上的成员灯（点单个灯 = 直接看它的历史）、点状态条
/// （看整支队列：进行中 + 最近）。数据源是 [SubAgentRunMonitor]——在跑的
/// 实时更新，跑完的进 recent 存档（含完整对话历史）不丢。

/// 队列弹窗：进行中 + 最近跑过的实例（只看当前会话——会话隔离，
/// 2026-10-01 用户点名）。
void showSubAgentQueueSheet(BuildContext context, {String? conversationId}) {
  showCustomBottomSheet<void>(
    context: context,
    title: AppLocalizations.of(context)!.subagentQueueTitle,
    builder: (sheetContext, scrollController) {
      final l10n = AppLocalizations.of(sheetContext)!;
      return ListenableBuilder(
        listenable: SubAgentRunMonitor.instance,
        builder: (context, _) {
          final monitor = SubAgentRunMonitor.instance;
          final running = monitor.activeFor(conversationId);
          final recent = monitor.recentFor(conversationId);
          if (running.isEmpty && recent.isEmpty) {
            return Padding(
              padding: const EdgeInsets.all(24),
              child: Center(
                child: Text(
                  l10n.subagentQueueEmpty,
                  style: TextStyle(
                    fontSize: 13,
                    color: Theme.of(sheetContext).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            );
          }
          return ListView(
            controller: scrollController,
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            children: [
              if (running.isNotEmpty) ...[
                _sectionLabel(sheetContext, l10n.subagentSectionRunning),
                for (final run in running)
                  _RunTile(run: run, live: true),
                const SizedBox(height: 10),
              ],
              if (recent.isNotEmpty) ...[
                _sectionLabel(sheetContext, l10n.subagentSectionRecent),
                for (final run in recent) _RunTile(run: run, live: false),
              ],
            ],
          );
        },
      );
    },
  );
}

/// 单个实例的对话历史（思考内容 / 每步输出 / 工具调用与结果）。
void showSubAgentHistorySheet(BuildContext context, SubAgentRun run) {
  showCustomBottomSheet<void>(
    context: context,
    title: run.label.isEmpty ? run.agent : '${run.agent} · ${run.label}',
    builder: (sheetContext, scrollController) {
      return _HistoryBody(run: run, scrollController: scrollController);
    },
  );
}

Widget _sectionLabel(BuildContext context, String text) {
  final cs = Theme.of(context).colorScheme;
  return Padding(
    padding: const EdgeInsets.fromLTRB(0, 10, 0, 6),
    child: Text(
      text,
      style: TextStyle(
        fontSize: 12,
        fontWeight: AppFontWeights.semibold,
        color: cs.onSurfaceVariant,
      ),
    ),
  );
}

/// 队列里的一行：状态图标 + 名字 + 阶段/结局 + 秒数；点击展开对话历史。
class _RunTile extends StatelessWidget {
  const _RunTile({required this.run, required this.live});

  final SubAgentRun run;
  final bool live;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    final statusText = live
        ? (run.cancelRequested
            ? l10n.subagentRunCancelling
            : run.stage)
        : _doneLabel(run, l10n);
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Card(
        elevation: 0,
        color: cs.onSurface.withValues(alpha: 0.04),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: ListTile(
          dense: true,
          onTap: () => showSubAgentHistorySheet(context, run),
          leading: live
              ? SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    valueColor: AlwaysStoppedAnimation<Color>(cs.primary),
                  ),
                )
              : Icon(_doneIcon(run), size: 18, color: _doneColor(run, cs)),
          title: Text(
            run.label.isEmpty ? run.agent : '${run.agent} · ${run.label}',
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 13,
              fontWeight: AppFontWeights.emphasis,
            ),
          ),
          subtitle: run.task.trim().isEmpty
              ? null
              : Text(
                  run.task.trim(),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 11,
                    color: cs.onSurfaceVariant,
                  ),
                ),
          trailing: Text(
            statusText,
            style: TextStyle(
              fontSize: 11,
              color: cs.onSurfaceVariant,
            ),
          ),
        ),
      ),
    );
  }

  bool get _failed {
    final status = run.outcomeStatus;
    if (status == null) return false;
    return status != 'ok' && status != 'cancelled';
  }

  IconData _doneIcon(SubAgentRun run) =>
      _failed ? Lucide.TriangleAlert : Lucide.CheckCircle;

  Color _doneColor(SubAgentRun run, ColorScheme cs) =>
      _failed ? cs.error : cs.primary;
}

String _doneLabel(SubAgentRun run, AppLocalizations l10n) {
  final status = run.outcomeStatus;
  return switch (status) {
    'ok' => l10n.subagentCardStatusOk,
    'timeout' => l10n.subagentCardStatusTimeout,
    'cancelled' => l10n.subagentCardStatusCancelled,
    null => l10n.subagentCardStatusFailed,
    _ => l10n.subagentCardStatusFailed,
  };
}

/// 子代理对话历史 → 主对话同款消息（复用 ChatMessageWidget 渲染机制）。
///
/// 用户 2026-10-01：「我们主页面是什么渲染机制？就你在这也是对话一样的，
/// 尽量复用组件」——所以这里把 transcript 映射成 ChatMessage + ToolUIPart，
/// 气泡、思考折叠、工具卡片、Markdown 全部走与主对话同一条渲染链，
/// 只把头像/名称/统计/操作按钮关掉（弹窗里不需要）。
class SubAgentChatItem {
  SubAgentChatItem({
    required this.message,
    required this.toolParts,
    this.reasoningText,
  });

  final ChatMessage message;
  final List<ToolUIPart> toolParts;
  final String? reasoningText;
}

List<SubAgentChatItem> buildSubAgentChatItems(SubAgentRun run) {
  final items = <SubAgentChatItem>[];
  final conversationId = run.conversationId ?? 'subagent';
  final task = run.task.trim();
  if (task.isNotEmpty) {
    items.add(
      SubAgentChatItem(
        message: ChatMessage(
          role: 'user',
          content: task,
          conversationId: conversationId,
        ),
        toolParts: const <ToolUIPart>[],
      ),
    );
  }
  // 工具结果按顺序回填到最近一条 assistant 步的 toolParts（循环里每个
  // call 执行后立即记一条 tool，顺序与 toolCalls 一一对应）。
  SubAgentChatItem? pending;
  for (final entry in run.transcript) {
    if (entry.role == 'assistant') {
      final reasoning = entry.reasoning.trim();
      final text = entry.text.trim();
      final parts = <MessagePart>[
        if (reasoning.isNotEmpty) ReasoningPart(reasoning),
        if (text.isNotEmpty) TextPart(text),
        for (final call in entry.toolCalls)
          ToolCallPart(
            jsonEncode(<String, dynamic>{
              'id': call.id,
              'name': call.name,
              'arguments': call.arguments,
            }),
          ),
      ];
      final item = SubAgentChatItem(
        message: ChatMessage(
          role: 'assistant',
          content: text.isEmpty ? null : text,
          parts: parts.isEmpty ? null : parts,
          conversationId: conversationId,
        ),
        toolParts: <ToolUIPart>[
          for (final call in entry.toolCalls)
            ToolUIPart(
              id: call.id,
              toolName: call.name,
              arguments: call.arguments,
              // 结果还没回来：先标 loading，后续 tool 条目按序回填并置 false
              // （ToolUIPart.loading 默认 false，不标会让回填匹配不到）。
              loading: true,
            ),
        ],
        reasoningText: reasoning.isEmpty ? null : reasoning,
      );
      items.add(item);
      pending = item.toolParts.isEmpty ? null : item;
    } else if (entry.role == 'tool') {
      final item = pending;
      if (item == null) continue;
      for (var i = 0; i < item.toolParts.length; i++) {
        final part = item.toolParts[i];
        if (!part.loading) continue;
        item.toolParts[i] = ToolUIPart(
          id: part.id,
          toolName: part.toolName,
          arguments: part.arguments,
          content: entry.result,
        );
        break;
      }
    }
  }
  return items;
}

/// 单条消息：主对话同款渲染，关掉弹窗里不需要的装饰。
///
/// 动作按钮口径（用户 2026-10-03：「子代理里刷新/朗读/更多点了没反应，只有复制
/// 能用」）：**能自成闭环的才补全，其余不渲染**。消息组件的约定是「回调为 null
/// 就不画按钮」，所以这里只给得出真结果的那一个：
/// - 复制：组件自带兜底 ✓
/// - 朗读：接 TTS，自身闭环 ✓（TTS 不可用时传 null → 按钮不出现）
/// - 刷新/重发：执行记录只读，重跑的是子代理任务而不是某条消息 ✗
/// - 翻译：翻译落点绑定会话消息（TranslationService 会 updateMessage），
///   子代理记录没有落点 ✗
/// - 更多菜单：编辑/删除/分叉/分享/选择消息全部依赖会话消息 ✗
class SubAgentChatMessageRow extends StatelessWidget {
  const SubAgentChatMessageRow({super.key, required this.item});

  final SubAgentChatItem item;

  @override
  Widget build(BuildContext context) {
    return Consumer<TtsProvider>(
      builder: (context, tts, _) => ChatMessageWidget(
        message: item.message,
        toolParts: item.toolParts.isEmpty ? null : item.toolParts,
        reasoningText: item.reasoningText,
        showThinkingCards: true,
        showToolCards: true,
        showModelIcon: false,
        useAssistantAvatar: false,
        useAssistantName: false,
        showUserAvatar: false,
        showTokenStats: false,
        collapseLongUserText: false,
        onSpeak: tts.isAvailable ? () => _speak(context, tts) : null,
      ),
    );
  }

  /// 朗读这一段（与主对话同一条取文规则：TTS 文本选择模式）。
  Future<void> _speak(BuildContext context, TtsProvider tts) async {
    if (tts.playbackState.isActive) {
      await tts.stop();
      return;
    }
    final settings = context.read<SettingsProvider>();
    final text = TtsTextSelection.apply(
      item.message.content,
      mode: settings.ttsTextSelectionMode,
    );
    if (text.trim().isEmpty) return;
    await tts.speak(text, waitForCompletion: false);
  }
}

/// 对话历史正文：中止行 + 任务与逐步消息（主对话同款渲染）。
class _HistoryBody extends StatelessWidget {
  const _HistoryBody({required this.run, required this.scrollController});

  final SubAgentRun run;
  final ScrollController scrollController;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return ListenableBuilder(
      listenable: SubAgentRunMonitor.instance,
      builder: (context, _) {
        // 实时：transcript 逐步写入，弹窗开着就能看到消息一条条出现。
        final items = buildSubAgentChatItems(run);
        final live =
            SubAgentRunMonitor.instance.active.any((item) => item.id == run.id);
        return ListView(
          controller: scrollController,
          padding: const EdgeInsets.fromLTRB(0, 4, 0, 24),
          children: [
            // 中止入口并入历史弹窗（原输入框内的监看行已撤）。
            if (live)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 4),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        run.cancelRequested
                            ? l10n.subagentRunCancelling
                            : '${run.stage} · '
                                '${(run.elapsed.inMilliseconds / 1000).toStringAsFixed(0)}s',
                        style:
                            TextStyle(fontSize: 12, color: cs.onSurfaceVariant),
                      ),
                    ),
                    if (!run.cancelRequested)
                      TextButton.icon(
                        onPressed: () =>
                            SubAgentRunMonitor.instance.requestCancel(run.id),
                        icon: Icon(Lucide.X, size: 14, color: cs.error),
                        label: Text(
                          l10n.subagentRunCancel,
                          style: TextStyle(fontSize: 12, color: cs.error),
                        ),
                      ),
                  ],
                ),
              ),
            if (items.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 24),
                child: Center(
                  child: Text(
                    l10n.subagentQueueEmpty,
                    style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant),
                  ),
                ),
              )
            else
              for (final item in items) SubAgentChatMessageRow(item: item),
          ],
        );
      },
    );
  }
}

