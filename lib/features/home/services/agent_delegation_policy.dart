/// 子代理/专家团的**模型可见**派发策略段（2026-09-29）。
///
/// 参照 deepseek-harness 的做法：能力由部署/开关决定，而「什么时候该派」靠一段
/// 固定策略文本——`packages/subagent/tool-subagent/src/index.ts` 的
/// `tool:<toolName>` 段（order = TOOL_SUBAGENT）与
/// `packages/experimental/tool-agent-team/src/index.ts` 的 `team:policy` 段
/// （order = TEAM_POLICY）。参照实现里工具缺席时段文本为空，这里同样只在
/// `subagent` 真挂在这个助手上时才注入——与本仓「点名的调用必须真存在」
/// 的判据一致（第 63/65 条）。
///
/// 名单面（2026-09-29「各司其职」）：策略段只点名当前助手域内可见的预置团
/// （开发域提 dev-team，逆向域提 apk-team，any 域两个都提）——schema 与
/// SubAgentToolHandler 的可见名单同源。
library;

import 'subagent_registry.dart';

abstract final class AgentDelegationPolicy {
  /// 单发派发纪律。文本里点名 `subagent`，与工具发布名一一对应。
  static const String _subagent = '''## Delegation

`subagent` dispatches self-contained work to a fresh instance with its own tool loop and reports the result back. Start independent delegations together in one assistant message and keep working while they run. Delegate when the job is genuinely separable — a focused investigation, an independent review of what you just changed, or a wide read you would otherwise hoist into this chat; finish one-step work yourself instead.

Everything the subagent needs must be in `task` (plus optional `context`): it does not see this conversation. It can only use tools this assistant also has, a read-only instance cannot write, and a writing instance needs /goal mode. Wait for the reports and fold them into your answer — never present delegated work you have not received back.''';

  /// 专家团纪律。只在开关打开时追加；预置团名按助手域注入。
  static String _teams(SubAgentDomain domain) {
    final teamNames = switch (domain) {
      SubAgentDomain.dev => '`team: dev-team`',
      SubAgentDomain.apk => '`team: apk-team`',
      SubAgentDomain.any => '`team: dev-team` / `team: apk-team`',
    };
    return 'For work that splits into research -> implement -> review '
        '(analyse -> patch -> verify for APK work) use the expert-team shape: '
        '$teamNames, or your own `members[]` chained with `blockedBy`. '
        'Create a team only when the user asks for one or the change genuinely '
        'needs an independent verification pass; keep it as small as the job '
        'allows (max 4 members), give each member its own write scope, and '
        'expect their reports before claiming the result.';
  }

  /// 关闭专家团时给出的替代句（工具还在，只是没有团形态）。
  static const String _teamsOff =
      'Expert teams are turned off for this assistant: dispatch single jobs only (`agent` + `task`).';

  /// 当前助手该看到的派发策略；`subagent` 没挂上就返回空串（不注入任何段落）。
  static String hintFor({
    required bool subagentEnabled,
    required bool teamsEnabled,
    SubAgentDomain domain = SubAgentDomain.any,
  }) {
    if (!subagentEnabled) return '';
    final buffer = StringBuffer(_subagent);
    buffer.write('\n\n');
    buffer.write(teamsEnabled ? _teams(domain) : _teamsOff);
    return buffer.toString();
  }
}
