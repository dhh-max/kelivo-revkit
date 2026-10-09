import 'dart:convert';

/// 记忆质量硬校验（非 LLM 依赖）：所有写入路径的统一闸门。
///
/// 解决"无用信息记录"问题：仅靠 Gatekeeper/SmartAdd 的 prompt 软约束
/// 拦不住噪音，这里用确定性规则拒绝：
///  - 长度越界（过短无信息量、过长 token 炸弹）
///  - 工具调用/中间状态噪音（workspaceId/dryRun/预览令牌等）
///  - 一次性操作指令模式（时间点/单次任务措辞）
///  - 非文本垃圾（控制字符、纯标点）
///
/// 2026-10-03（用户实测报告 2-11）：噪音判定**过去按词面**——正常项目结论只要
/// 提到 `dryRun` / `nextCursor` 这类参数名就被拒，写两次才落库。现在改成按
/// **痕迹形态**判定（键值片段、工具信封、字段名多次共现 + 结构化标点），并在错误
/// 里回报命中的原文片段，调用方知道该改哪里。
class MemoryQuality {
  MemoryQuality._();

  static const int minLength = 4;
  static const int maxLength = 2000;

  /// 痕迹字段名（单独出现**不算**噪音）。
  static final RegExp _traceTokens = RegExp(
    r'workspaceId|editSessionId|previewToken|targetVersion|dryRun|nextCursor|hasMore|confirm',
    caseSensitive: false,
  );

  /// 键/赋值形态：`"dryRun": true`、`nextCursor=xxx`、`hasMore:false`…
  /// 这是工具调用痕迹的真正长相；散文里提到参数名不会命中。
  static final RegExp _traceValuePattern = RegExp(
    r'["\u2018\u2019\u201c\u201d]?(workspaceId|editSessionId|previewToken|targetVersion|dryRun|nextCursor|hasMore)["\u2018\u2019\u201c\u201d]?\s*[:=]\s*\S',
    caseSensitive: false,
  );

  /// 工具信封外壳：JSON 键 + 典型值（`"ok": true` 这类）。
  static final RegExp _traceEnvelopePattern = RegExp(
    r'["\u201c]?(ok|error|nextActions|resultCaps|truncated|searchPerformed)["\u201d]?\s*:\s*["\[{tTfF0-9\-]',
    caseSensitive: false,
  );

  /// 中文痕迹口吻（本身就是痕迹口吻，保留硬拦）。
  static final RegExp _tracePhrasePattern = RegExp(r'调用工具|工具执行|工具结果');

  /// 时间戳前缀。
  static final RegExp _timestampPrefixPattern = RegExp(
    r'^\[?\d{4}-\d{2}-\d{2}[ T]?\d{2}:\d{2}',
  );

  /// 痕迹字段名共现阈值：单次提到是描述，多次 + 结构化标点才是痕迹。
  static const int _traceTokenMinHits = 3;

  /// 对外暴露的模式清单（保持向后兼容的命名）。
  static List<RegExp> get noisePatterns => <RegExp>[
    _traceValuePattern,
    _traceEnvelopePattern,
    _tracePhrasePattern,
    _timestampPrefixPattern,
  ];

  /// 返回 null 表示通过；否则为拒绝原因（面向用户/日志的文案）。
  static String? validate(String content) {
    final text = content.trim();
    if (text.isEmpty) return '记忆内容不能为空';
    if (text.length < minLength) return '记忆内容过短（< $minLength 字符），无信息量';
    if (text.length > maxLength) return '记忆内容过长（> $maxLength 字符），请拆分或精简';
    // 控制字符 / 纯标点垃圾
    final printable = text.runes.where((r) => r >= 0x20 && r != 0x7f).length;
    if (printable < text.runes.length * 3 ~/ 4) return '记忆内容包含大量控制字符，疑似垃圾';
    if (!RegExp(r'[\p{L}\p{N}]', unicode: true).hasMatch(text)) {
      return '记忆内容无可读文字（纯符号/标点）';
    }

    // ① 强形态：文本带 JSON 花括号（工具信封长相）时，键/赋值或信封字段一律判噪音。
    //    为什么必须带上这一层：报告 2-11 的误伤就是「散文里写 dryRun=true 预览」——
    //    单个键值片段在技术结论里很常见，只有整段是结构化痕迹才该拒。
    final looksJsonish = text.contains('{') && text.contains('}');
    final hits = _traceTokens.allMatches(text).length;
    final equalsCount = '='.allMatches(text).length;
    if (looksJsonish) {
      for (final pattern in <RegExp>[_traceValuePattern, _traceEnvelopePattern]) {
        final hit = pattern.firstMatch(text);
        if (hit != null) {
          return '命中噪音形态「${_clip(hit.group(0))}」：这是工具调用痕迹/中间状态，'
              '不写入记忆。想留下结论请改写成完整句子（不要贴参数键值片段）。';
        }
      }
    }

    // ② 弱形态：痕迹字段名多次共现 + 结构化标点（≥3 次命中且至少 3 个等号），
    //    散装参数串也拦得住。
    if (hits >= _traceTokenMinHits && equalsCount >= 3) {
      return '命中噪音形态（痕迹字段名出现 $hits 次且含 $equalsCount 个赋值片段）：'
          '疑似工具调用痕迹，不写入记忆。';
    }

    // ③ 痕迹口吻与时间戳前缀。
    final phrase = _tracePhrasePattern.firstMatch(text);
    if (phrase != null) {
      return '命中噪音形态「${_clip(phrase.group(0))}」（工具调用痕迹不写入记忆）';
    }
    final stamp = _timestampPrefixPattern.firstMatch(text);
    if (stamp != null) {
      return '命中噪音形态「${_clip(stamp.group(0))}」（时间戳前缀属一次性中间状态）';
    }
    return null;
  }

  /// 尝试解码 JSON 内容（payload 序列化场景），失败返回原文。
  static String fromJsonPayload(String payload) {
    try {
      final decoded = jsonDecode(payload);
      if (decoded is Map && decoded['content'] is String) {
        return decoded['content'] as String;
      }
      return payload;
    } catch (_) {
      return payload;
    }
  }

  /// 命中原文只回报一小段，避免错误体本身变成大文本。
  static String _clip(String? value) {
    final oneLine = (value ?? '').replaceAll(RegExp(r'\s+'), ' ').trim();
    return oneLine.length <= 40 ? oneLine : '${oneLine.substring(0, 40)}…';
  }
}
