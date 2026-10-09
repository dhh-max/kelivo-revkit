/// 分页的统一契约（报告 2-23）。
///
/// 真机复测发现三处混用：
///  - **命名**：`memory_read` 回 `has_more` / `next_offset`（snake_case），
///    `apk_rules` 回 `hasMore` / `nextOffset`（camelCase）；
///  - **单位不明**：`artifact_read` 的 offset/limit 是**字节**，
///    `memory_read` / `apk_rules` 是**条数**，`get_tool_result` 是**字符**，
///    结果体里都没写单位 —— 调用方只能靠字段名猜，猜错就少读/多读一段；
///  - **续读入口**：有的给 `nextOffset`、有的给 `continuation` token。
///
/// 这里给一个**统一分页块** `page`：显式声明单位 + 偏移 + 总数 + 是否还有，
/// 并同时给出 `nextOffset`。各工具原有的字段一律保留（向后兼容），
/// 新增的 `page` 是机器可读的单一事实源。
abstract final class ToolPaging {
  ToolPaging._();

  /// 单位取值（`page.unit`）。
  static const String unitItems = 'items';
  static const String unitBytes = 'bytes';
  static const String unitChars = 'chars';

  /// 构造统一分页块。
  ///
  /// [total] 未知时传负数，此时 `hasMore` 按「本页是否取满」保守判断。
  static Map<String, Object?> block({
    required String unit,
    required int offset,
    required int limit,
    required int returned,
    int total = -1,
  }) {
    final knownTotal = total >= 0;
    final consumed = offset + returned;
    final hasMore = knownTotal ? consumed < total : returned >= limit;
    return <String, Object?>{
      'unit': unit,
      'offset': offset,
      'limit': limit,
      'returned': returned,
      if (knownTotal) 'total': total,
      'hasMore': hasMore,
      if (hasMore) 'nextOffset': consumed,
      'note':
          'offset/limit/returned/total 的单位都是 page.unit（$unit）；'
          '续读用 nextOffset 原样回填 offset。',
    };
  }
}
