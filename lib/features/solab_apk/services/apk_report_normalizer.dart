/// 存量 APK 报告的读取侧自洽化。
///
/// 报告 JSON 是**分析时刻**那版代码写的；按指纹/analysisVersion 判定「新鲜」
/// 后不会重算。分析器口径修了（例如签名 note 与布尔真值自相矛盾），老报告
/// 仍带着旧文案被读出来——v10 复测（2026-10-04）里 agent 就据此报「报告自己
/// 跟自己打架」。这里在读取侧按报告里**已有的数据**重述派生文案：不猜测、
/// 不改数值。布尔值 = apksig 验签真值；只有 v2/v3 确为 'unknown' 时才保留
/// unknown 文案；v1=false 但 META-INF 有 v1 文件时补 v1Conflict 说明两口径
/// 为何不同。
Map<String, Object?>? normalizeSigningSchemeView(Object? raw) {
  if (raw is! Map) return null;
  final map = Map<String, Object?>.from(raw);
  final v1 = map['v1'];
  final v2 = map['v2'];
  final v3 = map['v3'];
  final filesRaw = map['v1SignatureFiles'];
  final files = filesRaw is List
      ? <String>[
          for (final entry in filesRaw)
            if (entry.toString().trim().isNotEmpty) entry.toString().trim(),
        ]
      : const <String>[];
  final unknown = v2 == 'unknown' || v3 == 'unknown';
  if (!unknown && (v2 is bool || v3 is bool)) {
    map['note'] =
        '以 apksig 验签为准：v1/v2/v3 均为验签真值（v1=$v1, v2=$v2, v3=$v3）；'
        'v1SignatureFiles 只是 META-INF 枚举结果，文件在场不等于该方案验签通过。';
    if (v1 == false && files.isNotEmpty && map['v1Conflict'] == null) {
      map['v1Conflict'] =
          'META-INF 存在 v1 签名文件（${files.join('、')}）但 apksig 判定 v1 未通过'
          '（常见于 v1 摘要未覆盖全部条目/后续增改文件）。以 apksig 的 v1=false 为准；'
          '需要第三方交叉验证时用 MT 验签。';
    }
  } else if (unknown) {
    map['note'] = '本地无法可靠判断 v2/v3，已输出 unknown；以 MT 验签为准';
  }
  return map;
}
