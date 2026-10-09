/// 记忆**安全审计**（确定性规则，不依赖 LLM）。
///
/// 与 [MemoryQuality] 分工：质量闸门管「值不值得记」（长度/噪音/垃圾），
/// 这里管「**能不能安全地记**」——记忆会被注入回模型上下文，所以它是一条
/// 指令注入通道，也是凭据泄漏的常见落点。三类必须拦：
///
/// - `memory_prompt_injection`：指令覆盖/越权措辞（"忽略以上指令"…）；
/// - `memory_credential`：API key、口令、私钥等凭据（记忆永不存凭据）；
/// - `memory_invisible_control`：零宽/双向控制字符（隐藏指令的经典载体）。
///
/// 全是可解释规则 + 证据片段（凭据只回前 3 位），方便用户复核，不做静默丢弃。
library;

enum MemoryAuditSeverity { ok, notice, warn, block }

class MemoryAuditFinding {
  const MemoryAuditFinding({
    required this.code,
    required this.severity,
    required this.message,
    this.evidence = '',
  });

  final String code;
  final MemoryAuditSeverity severity;
  final String message;
  final String evidence;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'code': code,
    'severity': severity.name,
    'message': message,
    if (evidence.isNotEmpty) 'evidence': evidence,
  };
}

class MemoryAuditReport {
  const MemoryAuditReport(this.findings);

  static const MemoryAuditReport clean = MemoryAuditReport(
    <MemoryAuditFinding>[],
  );

  final List<MemoryAuditFinding> findings;

  bool get hasFindings => findings.isNotEmpty;

  MemoryAuditSeverity get severity {
    var worst = MemoryAuditSeverity.ok;
    for (final finding in findings) {
      if (finding.severity.index > worst.index) worst = finding.severity;
    }
    return worst;
  }

  bool get blocked => severity == MemoryAuditSeverity.block;

  List<String> get codes =>
      findings.map((finding) => finding.code).toList(growable: false);

  /// 面向模型的统一拒绝话术（blocked 时用）。
  ///
  /// 用户实测报告 2-12：过去只回「像提示注入/指令覆盖」，调用方不知道是哪个词触发的，
  /// 只能反复改写试错。现在把**命中的原文片段**（凭据类已脱敏）一并带出。
  String get refusalMessage {
    final blockedFindings = findings
        .where((finding) => finding.severity == MemoryAuditSeverity.block)
        .toList(growable: false);
    if (blockedFindings.isEmpty) return '';
    final detail = blockedFindings
        .map((finding) {
          final evidence = finding.evidence.trim();
          return evidence.isEmpty
              ? finding.message
              : '${finding.message}（命中原文：「$evidence」）';
        })
        .join('；');
    return '记忆安全审计拒绝写入：$detail'
        '。记忆只存事实与偏好，不存指令、不存凭据；'
        '若是正常技术结论，请去掉指令口吻/凭据片段后重写。';
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
    'severity': severity.name,
    'blocked': blocked,
    'findings': [for (final finding in findings) finding.toJson()],
  };
}

abstract final class MemoryAudit {
  MemoryAudit._();

  /// 句子边界（行首/句首/分号后）：**只**给最弱的几条用——真正的指令注入通常
  /// 起头就说，而技术散文里引用这些词多在中段（报告 2-12 的误伤来源）。
  static const String _sentenceStart = r'(?:^|[\n。！？!?；;]\s*)';

  static RegExp _atSentenceStart(String source) =>
      RegExp('$_sentenceStart(?:$source)', caseSensitive: false);

  /// 指令覆盖/越权措辞：命中即拦。
  ///
  /// 刻意要求「动词 + 目标词」同时出现（如 ignore + instructions），
  /// 避免把正常描述（"忽略大小写" / "case-insensitive"）误判。
  ///
  /// 2026-10-03（报告 2-12）：`(覆盖|替换|重写)(系统)?(提示词|提示|指令)` 过去会把
  /// 「重写指令解析器」这类正常技术结论判成注入。现在只认**元层目标**
  /// （系统提示词 / system prompt），不再认裸的「指令」「提示」。
  static final List<RegExp> injectionPatterns = <RegExp>[
    RegExp(
      r'忽略(之前|以上|上述|前面)?(的)?(所有)?(指令|提示|规则|约束)',
      caseSensitive: false,
    ),
    RegExp(
      r'无视(之前|前面|以上|上述|所有)?(的)?(指令|规则|限制|约束)',
      caseSensitive: false,
    ),
    RegExp(
      r'ignore\s+(all\s+)?(the\s+)?(previous|above|prior)\s+'
      r'(instructions?|prompts?|rules?|constraints?)',
      caseSensitive: false,
    ),
    RegExp(
      r'disregard\s+(the\s+)?(previous|above|prior)\s+'
      r'(instructions?|prompts?|rules?)',
      caseSensitive: false,
    ),
    RegExp(
      r'(覆盖|替换|重写)\s*(你的|系统|system)?\s*(系统提示词|系统提示|safety\s*rules?|system\s*prompt)',
      caseSensitive: false,
    ),
    RegExp(
      r'(override|replace)\s+(the\s+)?system\s+(prompt|message|instructions?)',
      caseSensitive: false,
    ),
    RegExp(r'不要(告诉|通知|提醒)(用户|主人|使用者)', caseSensitive: false),
    RegExp(r"don'?t\s+(tell|notify|inform)\s+the\s+user", caseSensitive: false),
    // 最弱的两条：必须出现在句首，否则可能只是描述（「无条件执行」在说明文档里
    // 是正常措辞）。
    _atSentenceStart(r'无条件(执行|服从|接受)'),
    _atSentenceStart(r'(永远|一律)不要(询问|确认|问用户)'),
    _atSentenceStart(r'从现在起(你)?(必须|要|只能)'),
  ];

  /// 凭据模式：命中即拦（记忆永不存凭据）。
  static final List<RegExp> credentialPatterns = <RegExp>[
    RegExp(r'sk-[A-Za-z0-9_\-]{16,}'),
    RegExp(r'ghp_[A-Za-z0-9]{16,}'),
    RegExp(r'github_pat_[A-Za-z0-9_]{16,}'),
    RegExp(r'AKIA[0-9A-Z]{12,}'),
    RegExp(r'xox[baprs]-[A-Za-z0-9\-]{10,}'),
    RegExp(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    RegExp(r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
    RegExp(
      r'(password|passwd|pwd|api[_-]?key|apikey|secret|access[_-]?token)'
      r'\s*[:=]\s*\S{8,}',
      caseSensitive: false,
    ),
    RegExp(r'Bearer\s+[A-Za-z0-9_\-\.]{20,}', caseSensitive: false),
  ];

  /// 不可见/双向控制字符：零宽字符与 bidi 覆写。
  static final RegExp invisibleControlPattern = RegExp(
    '[\\u200B-\\u200F\\u2060-\\u2064\\u206A-\\u206F\\uFEFF'
    '\\u202A-\\u202E\\u2066-\\u2069]',
  );

  /// 「长正文 + 祈使句式」的软信号：不拦，只提醒（可能是被塞进记忆的流程说明）。
  static final RegExp longImperativePattern = RegExp(
    r'(必须|务必|一定要|每次都要|始终|永远)\s*(执行|遵守|调用|使用|按|照)',
  );

  static const int longContentThreshold = 800;

  /// 审计一段将要写入记忆的正文。
  static MemoryAuditReport inspect(String content) {
    final text = content.trim();
    if (text.isEmpty) return MemoryAuditReport.clean;

    final findings = <MemoryAuditFinding>[];

    for (final pattern in injectionPatterns) {
      final match = pattern.firstMatch(text);
      if (match == null) continue;
      findings.add(
        MemoryAuditFinding(
          code: 'memory_prompt_injection',
          severity: MemoryAuditSeverity.block,
          message: '像提示注入/指令覆盖（命中「${match.group(0)}」）',
          evidence: match.group(0) ?? '',
        ),
      );
      break;
    }

    for (final pattern in credentialPatterns) {
      final match = pattern.firstMatch(text);
      if (match == null) continue;
      findings.add(
        MemoryAuditFinding(
          code: 'memory_credential',
          severity: MemoryAuditSeverity.block,
          message: '含凭据（API key/口令/私钥），记忆不存凭据',
          evidence: _redact(match.group(0) ?? ''),
        ),
      );
      break;
    }

    final control = invisibleControlPattern.firstMatch(text);
    if (control != null) {
      findings.add(
        MemoryAuditFinding(
          code: 'memory_invisible_control',
          severity: MemoryAuditSeverity.block,
          message: '含不可见/双向控制字符（隐藏指令的常见载体）',
          evidence: 'U+${control.group(0)!.runes.first.toRadixString(16).toUpperCase()}',
        ),
      );
    }

    if (text.length >= longContentThreshold &&
        longImperativePattern.hasMatch(text)) {
      findings.add(
        const MemoryAuditFinding(
          code: 'memory_long_imperative',
          severity: MemoryAuditSeverity.notice,
          message: '正文较长且是祈使句式：确认这是「事实/偏好」而不是「给未来自己的指令」',
        ),
      );
    }

    if (findings.isEmpty) return MemoryAuditReport.clean;
    return MemoryAuditReport(findings);
  }

  /// 凭据只回前 3 位，避免审计日志本身泄漏。
  static String _redact(String value) {
    final trimmed = value.trim();
    if (trimmed.length <= 3) return '***';
    return '${trimmed.substring(0, 3)}***';
  }
}
