enum ApkExecutionMode { reportOnly, analyzeOnly, modify }

abstract final class ApkAgentPolicy {
  static const String version = 'evidence-composition-v6';
  static const int maxVisibleToolResultChars = 16000;
  static const int maxEvidenceTokens = 150000;

  static const Set<String> mutationToolNames = <String>{
    'patch_apk_dex_methods',
    // A2（2026-09-19 审核）：写 DEX 的字符串补丁漏登记 —— 没有 destructiveHint，
    // 客户端把它当只读工具，确认提示缺失。
    'patch_apk_dex_strings',
    'signature_bypass',
    'patch_apk_manifest',
    'apk_sign',
    'apk_rebuild',
    'so_patch_into_apk',
    'cleanup_apk_builds',
    'save_apk_patch_memory',
    'record_apk_patch_verification',
    'apk_note_write',
  };

  static ApkExecutionMode executionModeFor(String goal) {
    final text = goal.trim().toLowerCase();
    if (RegExp(
      r'修改|修复|打补丁|补丁|去广告|解锁|精简|删除|移除|替换|写入|回填|回编|重打包|重新打包|签名|构建|安装|patch|modify|fix|rebuild|sign',
      caseSensitive: false,
    ).hasMatch(text)) {
      return ApkExecutionMode.modify;
    }
    if (RegExp(
      r'报告|汇报|总结|report|summary',
      caseSensitive: false,
    ).hasMatch(text)) {
      return ApkExecutionMode.reportOnly;
    }
    return ApkExecutionMode.analyzeOnly;
  }

  /// Agent 与 MCP 共用的判断契约。两种模式必须原样注入这一段，避免证据
  /// 标准、反混淆策略和停止条件各写一份后逐渐漂移。
  ///
  /// 2026-09-18 精简：13 条 → 8 条（-40%）。删掉的是重复表述与过程微管理
  /// （"think deeper"、"before each substantive action"、逐项输出格式要求），
  /// **硬契约一条未动**：证据门槛、三连败停止、状态口径与回读、写入门禁、
  /// signature_bypass 流程、错误原样转达、locator 引用。
  static const String sharedDecisionPolicy =
      '''
<apk_decision_policy version="$version">
1. Routes and preferred tools are candidates, not a sequence. DEX, Flutter, native, resources and existing artifacts are independent probes — start from any exact locator (qualifiedId, field, string reference, file identity, VA) you already have.
2. Hold competing falsifiable hypotheses; pick the cheapest probe that can change their ranking or your patch choice, and run independent read-only probes in one round. Familiarity is a hypothesis, not evidence — matching a known SDK, packer or template never replaces checking this app's own code — and paginate only when the next page can change the decision. Three consecutive failures of the same tool on the same target end that route: stop, report or ask, never a reworded fourth attempt.
3. Evidence: one current exact method body or field data-flow proof can decide alone; otherwise require two independent indirect sources. UI text, names, package prefixes and cached reports are clues, not proof. A miss rejects only that search dimension.
4. Compare identities before comparing outputs — APK entry, DEX qualifiedId, ELF VA and Dart functionVa are projections of one program. Current exact code and data flow outrank cached or name-based evidence, and two conflicting strong sources stay open until a third independent probe decides — never by majority vote or a fixed layer preference.
5. Obey the requested boundary: a report request only reads existing facts; an analysis request stops before previewing, patching, rebuilding, signing, installing, cleaning or writing memory; mutation tools run only when the user explicitly requests a modification or build action.
6. Before the first business write, run standalone signature_bypass on the unchanged original (unless the supplied input is already its prepared output, the user explicitly asks to skip it, or the Workbench setting is off). That prepared output — never the original — is the next input. If installation fails, keep the original and re-prepare.
7. Report only exact states: Analyzed / Located / dryRun'd / Modified / Signed / Verified. Plans, candidates, previews and a tool's ok are never "done", and a step's ok proves only that step ran — read the changed location back on the current artifact before claiming Modified (analysis caches never prove a write, and the same result is not re-verified repeatedly).
8. Answer compactly: decision, exact locator, decisive evidence, uncertainty, next discriminating action. Every factual claim carries a locator (qualifiedId, VA, archive entry path, artifact sha256 prefix) or is labeled a lead. Relay structured error codes and nextActions as-is — no guessing, no softening, no flattery.
</apk_decision_policy>''';
}
