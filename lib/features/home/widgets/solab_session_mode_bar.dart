import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/models/assistant.dart';
import '../../../core/providers/assistant_provider.dart';
import '../../../icons/lucide_adapter.dart';
import '../services/composer_notices.dart';
import '../services/local_tools_service.dart';
import '../services/session_mode.dart';
import '../services/slash_commands.dart';
import 'slash_command_palette.dart';

/// SoLab 会话模式（`/plan` `/goal`）与斜杠命令的**输入框侧集成**。
///
/// 为什么单独成文件：上游的 `chat_input_bar.dart` 是逐版本重写的热点文件，
/// 我方增量塞进去会让每次同步都要重新适配。这里把**逻辑与 UI 全部收在本文件**，
/// 上游 composer 只保留 5 个极小钩子（字段/initState/send/build/dispose），
/// 同步时按 `docs/上游对接进度.md` 的「重贴清单」补回去即可。
class SolabComposerSessionMode {
  SolabComposerSessionMode({required this.conversationId});

  /// 可变：composer 是跨会话复用的稳定实例，而冷启动时输入框往往**先于**
  /// 会话恢复构建（此时 id 是 null）。id 不跟进的话 setMode 全部写到空/旧
  /// 会话上——`/plan` `/goal` 看起来「发不出去」，只有 trailing 文字被发出
  /// （2026-10-03 真机根因）。会话切换时必须经 [updateConversation] 跟进。
  String? conversationId;

  final SessionModeStore _store = SessionModeStore();
  SessionMode _mode = SessionMode.build;
  String _goal = '';

  _SolabCommandStatus? _status;
  Timer? _statusTimer;

  String get _id => conversationId?.trim() ?? '';
  bool get isActive => _mode != SessionMode.build;
  SessionMode get mode => _mode;
  String get goal => _goal;

  void dispose() {
    _statusTimer?.cancel();
    detachRuntimeListener();
  }

  /// 会话切换（或首帧后恢复出会话）时跟进 id 并重载该会话的模式状态。
  Future<void> updateConversation(String? id, VoidCallback onChanged) async {
    final next = id?.trim();
    if (next == (conversationId?.trim() ?? '')) return;
    conversationId = id;
    // 评审批 P2（2026-10-04）：跨会话不留旧状态行——busy 态（如「正在原地
    // 压缩…」）没有自动清除定时器，切走后会一直挂在**新**会话输入框上方。
    clearStatus(onChanged);
    await ensureLoaded(onChanged);
  }

  void _showStatus(String text, {bool isError = false, bool busy = false, required VoidCallback onChanged}) {
    _statusTimer?.cancel();
    _status = _SolabCommandStatus(text: text, isError: isError, busy: busy);
    onChanged();
    if (busy) return;
    _statusTimer = Timer(Duration(seconds: isError ? 12 : 6), () {
      _status = null;
      onChanged();
    });
  }

  void clearStatus(VoidCallback onChanged) {
    _statusTimer?.cancel();
    _status = null;
    onChanged();
  }

  /// 运行时模式变更监听（模型自启用目标模式/自动推进切模式时绑上）。
  VoidCallback? _runtimeListenerOnChanged;

  /// 目标循环提示监听（完成/受阻/暂停/触顶）：显示在输入框上方的内联状态行。
  VoidCallback? _goalNoticeOnChanged;

  void attachRuntimeListener(VoidCallback onChanged) {
    _runtimeListenerOnChanged = onChanged;
    _goalNoticeOnChanged = onChanged;
    SessionModeRuntime.revision.addListener(_onRuntimeRevision);
    ComposerNotices.latest.addListener(_onGoalNotice);
  }

  void _onGoalNotice() {
    final onChanged = _goalNoticeOnChanged;
    if (onChanged == null) return;
    final notice = ComposerNotices.latest.value;
    if (notice == null) return;
    if (notice.conversationId != _id) return;
    _showStatus(
      notice.text,
      isError: notice.isError,
      busy: notice.busy,
      onChanged: onChanged,
    );
  }

  void _onRuntimeRevision() {
    final onChanged = _runtimeListenerOnChanged;
    if (onChanged == null) return;
    unawaited(_reloadIfChanged(onChanged));
  }

  Future<void> _reloadIfChanged(VoidCallback onChanged) async {
    final mode = await _store.modeOf(_id);
    final goal = mode == SessionMode.goal ? await _store.goalOf(_id) : '';
    if (mode == _mode && goal == _goal) return;
    _mode = mode;
    _goal = goal;
    onChanged();
  }

  void detachRuntimeListener() {
    SessionModeRuntime.revision.removeListener(_onRuntimeRevision);
    ComposerNotices.latest.removeListener(_onGoalNotice);
    _runtimeListenerOnChanged = null;
    _goalNoticeOnChanged = null;
  }

  /// 进页面时装载一次，并把策略写进 `SessionModeRuntime`（执行期拦截依赖它）。
  Future<void> ensureLoaded(VoidCallback onChanged) async {
    final mode = await _store.modeOf(_id);
    final goal = mode == SessionMode.goal ? await _store.goalOf(_id) : '';
    SessionModeRuntime.apply(_id, SessionModePolicy(mode: mode, goal: goal));
    _mode = mode;
    _goal = goal;
    onChanged();
  }

  /// 指示条上的 X：退出当前模式回 build（goal 的目标保留——彻底清掉用 `/goal clear`）。
  Future<void> exitMode(VoidCallback onChanged) async {
    await _store.setMode(_id, SessionMode.build);
    await ensureLoaded(onChanged);
  }

  /// 面板内容：只列模式命令（`/plan`、`/goal`；已在模式内时补 `/build` 作为出口）。
  List<SlashPaletteEntry> entriesFor(String text) {
    final isCommandDraft = text.startsWith('/') && !text.contains('\n');
    if (!isCommandDraft) return const <SlashPaletteEntry>[];
    // 已经是完整命令（例如选完写回的 `/plan `）→ 收起面板。
    if (SlashCommands.parse(text) != null) return const <SlashPaletteEntry>[];
    final paletteModes = <SessionMode>{
      SessionMode.plan,
      SessionMode.goal,
      if (_mode != SessionMode.build) SessionMode.build,
    };
    return buildSlashPalette(query: text.substring(1))
        .where(
          (entry) =>
              paletteModes.any((m) => m.wireName == entry.commandName),
        )
        .toList(growable: false);
  }

  /// 选中一行：把模式写进输入框（不直接执行），发送时判定并生效。
  void pick(
    SlashPaletteEntry entry,
    TextEditingController controller,
    VoidCallback onChanged,
  ) {
    final insert = entry.insertText;
    controller.value = TextEditingValue(
      text: insert,
      selection: TextSelection.collapsed(offset: insert.length),
    );
    onChanged();
  }

  /// 执行一条命令；返回 true 表示已消化，不要把原文当普通消息发出。
  Future<bool> runFromText(
    String raw, {
    required BuildContext context,
    required TextEditingController controller,
    required VoidCallback onChanged,
    Future<void> Function(String message)? onSend,
    VoidCallback? onOpenSkills,
    VoidCallback? onClearContext,
  }) async {
    final parsed = SlashCommands.parse(raw);
    if (parsed == null) return false;
    final command = parsed.command;
    Assistant? assistant;
    try {
      assistant = context.read<AssistantProvider>().currentAssistant;
    } catch (_) {
      // 没有助手上下文时按通用域派发，不阻断命令。
    }
    final commandContext = SlashCommandContext(
      conversationId: _id,
      modeStore: _store,
      sendMessage: (message) async => onSend?.call(message),
      openSkills: onOpenSkills,
      clearContext: () async => onClearContext?.call(),
      dispatchSubAgent: (agent, task) =>
          LocalToolsService.subAgentHandler.handle(
            <String, dynamic>{'task': task, 'agent': agent},
            conversationId: conversationId,
            assistant: assistant,
          ),
    );
    if (command.longRunning) {
      _showStatus('正在执行 /${command.name} …', busy: true, onChanged: onChanged);
    }
    final SlashCommandResult result;
    try {
      result = await command.run(commandContext, parsed.args);
    } catch (error) {
      // 命令异常必须收成用户看得见的一行：否则就是「点了发送什么都没发生」。
      _showStatus('/${command.name} 执行失败：$error', isError: true, onChanged: onChanged);
      return true;
    }
    final notice = result.notice?.trim() ?? '';
    // 模式命令不重复展示提示：输入框上方常驻横幅就是反馈（用户不要 toast）。
    final showNotice = notice.isNotEmpty &&
        (!command.changesSession || result.isError || result.draft != null);
    if (showNotice) {
      _showStatus(notice, isError: result.isError, onChanged: onChanged);
    } else if (command.longRunning) {
      clearStatus(onChanged);
    }
    if (result.handled) {
      controller.clear();
      await ensureLoaded(onChanged);
      final draft = result.draft;
      if (draft != null) {
        controller.value = TextEditingValue(
          text: draft,
          selection: TextSelection.collapsed(offset: draft.length),
        );
      }
    }
    return result.handled;
  }

  /// 输入框上方的三块叠加层：命令反馈行 → 会话模式指示条 → 斜杠面板。
  /// 不做任何事时返回空列表，保证「输入行一个像素不动」。
  List<Widget> buildOverlay({
    required BuildContext context,
    required String draftText,
    required TextEditingController controller,
    required VoidCallback onChanged,
    Color? fillColor,
    Color? borderColor,
  }) {
    final theme = Theme.of(context);
    final entries = entriesFor(draftText);
    return <Widget>[
      if (_status != null)
        Padding(
          padding: const EdgeInsets.only(bottom: 6),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              if (_status!.busy)
                SizedBox(
                  width: 13,
                  height: 13,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: theme.colorScheme.primary,
                  ),
                )
              else
                Icon(
                  _status!.isError
                      ? Lucide.TriangleAlert
                      : Lucide.CheckCircle,
                  size: 13,
                  color: _status!.isError
                      ? theme.colorScheme.error
                      : theme.colorScheme.primary,
                ),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  _status!.text,
                  maxLines: 4,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: _status!.isError
                        ? theme.colorScheme.error
                        : theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
              Tooltip(
                message: '收起这条提示',
                child: InkWell(
                  onTap: () => clearStatus(onChanged),
                  borderRadius: BorderRadius.circular(10),
                  child: const Padding(
                    padding: EdgeInsets.all(4),
                    child: Icon(Lucide.X, size: 14),
                  ),
                ),
              ),
            ],
          ),
        ),
      // 会话模式常驻指示条：模式不能是隐形状态——一闪就没的话，goal 的目标
      // 从此不可见，用户回头不知道 AI 在围绕什么自主干活。
      if (isActive)
        Padding(
          padding: const EdgeInsets.only(bottom: 6),
          child: Row(
            children: <Widget>[
              Icon(
                _mode == SessionMode.plan ? Lucide.ListTodo : Lucide.Crosshair,
                size: 13,
                color: theme.colorScheme.primary,
              ),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  _mode == SessionMode.plan
                      ? '计划模式 · 只调研、出分步计划'
                      : (_goal.isEmpty ? '目标模式' : '目标模式 · $_goal'),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
              Tooltip(
                message: '退出模式（回普通）',
                child: InkWell(
                  onTap: () => exitMode(onChanged),
                  borderRadius: BorderRadius.circular(10),
                  child: Padding(
                    padding: const EdgeInsets.all(4),
                    child: Icon(
                      Lucide.X,
                      size: 14,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      if (entries.isNotEmpty)
        SlashCommandPalette(
          entries: entries,
          onSelect: (entry) => pick(entry, controller, onChanged),
          selectedIndex: entries.indexWhere(
            (entry) => entry.commandName == _mode.wireName,
          ),
          fillColor: fillColor ?? theme.colorScheme.surface,
          borderColor: borderColor ??
              theme.colorScheme.outline.withValues(alpha: 0.20),
        ),
    ];
  }
}

class _SolabCommandStatus {
  const _SolabCommandStatus({
    required this.text,
    required this.isError,
    required this.busy,
  });

  final String text;
  final bool isError;
  final bool busy;
}
