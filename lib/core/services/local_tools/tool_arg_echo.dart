/// 参数「生效值」回显（同类缺陷扫查的收敛点）。
///
/// 用户实测报告第 2 组的共性：工具对入参做 `clamp` / 默认值替换后**不回显生效值**，
/// 调用方以为自己传的就是被用的（`cwd` 静默回落、`timeout_seconds=0` 静默抬到 1s、
/// `limit` 被压到上限……）。修 shell 时只修了那一处；这里给一个统一助手，
/// 让「钳过/改过就如实说」可以一行接入，避免再逐个漏。
abstract final class ToolArgEcho {
  ToolArgEcho._();

  /// 构造回显字段：始终给生效值 [effective]；与调用方请求不同时额外给
  /// `<name>Requested` 与 `<name>Clamped`，让调用方一眼看出被改写过。
  ///
  /// [requested] 为 null 表示调用方没传（用了默认值）——这时只回生效值，
  /// 不标 clamped（默认值不是「改写」）。
  static Map<String, Object?> effective(
    String name,
    num? requested,
    num effective,
  ) {
    final clamped = requested != null && requested != effective;
    return <String, Object?>{
      name: effective,
      if (clamped) '${name}Requested': requested,
      if (clamped) '${name}Clamped': true,
    };
  }

  /// 多参数版本：把若干 `(name, requested, effective)` 合成一个回显块。
  static Map<String, Object?> effectiveAll(
    List<({String name, num? requested, num effective})> entries,
  ) => <String, Object?>{
    for (final entry in entries)
      ...effective(entry.name, entry.requested, entry.effective),
  };
}
