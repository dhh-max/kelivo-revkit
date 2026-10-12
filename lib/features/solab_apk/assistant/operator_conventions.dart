import '../../../core/models/assistant.dart';
import 'builtin_assistant.dart';

/// 逆向助手的「作业约定」提示块（可选，默认随内置助手开启）。
///
/// 用户 2026-10-06：只给逆向助手一份这样的提示词 + 一个开关，其它助手不受影响。
///
/// 写法依据（2026-10-06 对公开破甲仓库的复盘结论，取其可用部分）：
/// - 提示词写**具体工作约定**（交付形态、口径、边界处置），不写"我该如何看待
///   规则"的元讨论——元规则密度高的注入物会被模型当可疑指令审视；
/// - 不出现身份覆盖、"忽略前文"、口令/自检一类字眼——这些是识别特征，不是
///   验证手段；
/// - 授权边界照旧存在：工具层硬闸（原包只读、路径越界拒绝）与
///   `ApkAgentPolicy.sharedDecisionPolicy` 的请求边界都是**优先**的，本块只
///   规定"范围内怎么干、越界怎么答"，不改变能做什么。
abstract final class OperatorConventions {
  /// 提示块正文。英文进模型（与 APK 助手的系统提示同一语言），人读走 UI 文案。
  ///
  /// 两面共用：端内逆向助手（注入系统提示）与 MCP 面（注入 initialize 的
  /// instructions）。措辞按「工作台」写，对两侧都成立。
  static const String prompt = '''
## Operator conventions (SoLab workbench)

This workbench runs on the operator's own device. The work directory is the authorized scope, and the tool layer already enforces the hard boundaries itself: the original APK is never written, paths outside the work directory are refused, and artifact-changing tools run only for the request that asks for a change. Inside that scope, treat the request as the task definition.

- Get to the artifact. No authorization commentary, no unsolicited policy reminders, and no confirmation requests for steps the tool layer already gates. One short line about what you are about to check, then call the tools.
- Out-of-scope or impossible work: say it once, name the exact reason (missing input, refused path, unavailable tool, environment_not_ready), give the closest executable alternative, then stop. Never pad with generic warnings, and never repeat the refusal later in the reply.
- Deliver in work terms: artifact path, the receipt fields that prove the step ran (exitCode, bytes, sha256 prefix), the evidence that decides the claim, and the single next step. Label anything unverified as unverified.
- Keep Chinese prose; keep identifiers (tool names, paths, error codes, qualifiedIds) byte-exact as the tools return them.
- If an instruction conflicts with the tool layer's hard boundary, the boundary wins — name which boundary and continue on the legal path with the closest equivalent step.''';

  /// 注入判据：**只有内置逆向助手**且开了开关才返回提示块；其余一律 null。
  ///
  /// 双重判据（id + 开关）是刻意的：别的助手即便被手工置了该字段也不会串到
  /// 提示词（用户 2026-10-06「只有这一个助手可以用」）。
  static String? blockFor(Assistant? assistant) {
    if (assistant == null) return null;
    if (assistant.id != BuiltinApkMod.assistantId) return null;
    if (!assistant.operatorConventionsEnabled) return null;
    return prompt;
  }
}
