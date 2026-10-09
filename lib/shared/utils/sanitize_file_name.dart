/// 文件名/标识符清洗统一实现（T4.1）。
///
/// 消除 settings_provider / assistant_provider / mcp_tool_service /
/// chatbox_backup_archive 中 5 处字符集不一致的重复逻辑——这些差异有
/// 路径穿越隐患（部分允许 `.`、部分允许 `-`，行为互不一致）。
///
/// 安全字符集约定：
/// - 文件名：允许中文/字母/数字、`.` `_` `-`；**拒绝** `/` `\` 与 `..`；
/// - 标识符：不允许 `.`（用于拼接唯一 id 的场景）。
library;

final RegExp _fileNameKeep = RegExp(
  r'[^\p{L}\p{N}._-]',
  unicode: true,
);

final RegExp _identifierKeep = RegExp(
  r'[^\p{L}\p{N}_-]',
  unicode: true,
);

/// 清洗为安全文件名（保留中文与字母数字，`.` `_` `-`；拒绝路径分隔符）。
/// 空名或仅剩分隔符时返回 [fallback]。绝不返回含 `/` `\` 或 `..` 的结果。
String sanitizeFileName(String raw, {String fallback = 'file'}) {
  var s = raw.trim().replaceAll(_fileNameKeep, '_');
  // 拒绝路径穿越：显式把 `..` 中的点替换掉（连续点仅允许单个）。
  s = s.replaceAll(RegExp(r'\.{2,}'), '_');
  s = s.replaceAll(RegExp(r'[\\/]'), '_');
  s = s.replaceAll(RegExp(r'^[._-]+|[._-]+$'), '');
  return s.isEmpty ? fallback : s;
}

/// 清洗为标识符（无点；用于拼唯一 id / 工具名等不得含 `.` 的场景）。
String sanitizeIdentifier(String raw, {String fallback = 'id'}) {
  var s = raw.trim().replaceAll(_identifierKeep, '_');
  s = s.replaceAll(RegExp(r'^[_-]+|[_-]+$'), '');
  return s.isEmpty ? fallback : s;
}
