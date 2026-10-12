import 'dart:convert';

import 'package:yaml/yaml.dart';

/// 技能的来源。
enum SkillSource {
  /// 随 App 打包（`assets/skills/<id>/SKILL.md`），只读。
  builtin,

  /// 用户导入（zip / .md / 目录），存于应用数据目录，可删除。
  imported,
}

/// 一个技能。
///
/// 格式与网络通用的 agent skill 约定一致（`SKILL.md` + YAML frontmatter）：
/// ```
/// ---
/// name: 技能名
/// description: 一句话说明
/// ---
/// 正文（注入模型的指令）
/// ```
class SkillDef {
  /// 唯一标识（slug，来自目录名或由名称生成）。
  final String id;
  final String name;
  final String description;

  /// 注入对话的正文（frontmatter 之后的全部内容）。
  final String systemPrompt;

  final SkillSource source;

  /// 来源路径：builtin 为 asset key；imported 为磁盘目录/文件路径。
  final String? path;

  /// 随技能包附带的额外文件数量（仅统计，供 UI 展示）。
  final int resourceCount;

  /// SKILL.md frontmatter 的完整元数据。
  ///
  /// 除 name/description 外的字段（version / category / permissions /
  /// supportedArtifacts / requires 等）由 SkillRegistry 读作「能力契约」，
  /// 决定这个技能什么时候该被选中（§19.2 / §19.4）。
  final Map<String, dynamic> meta;

  const SkillDef({
    required this.id,
    required this.name,
    required this.description,
    required this.systemPrompt,
    required this.source,
    this.path,
    this.resourceCount = 0,
    this.meta = const {},
  });

  bool get isBuiltin => source == SkillSource.builtin;

  /// 挂载预览用：正文首行摘要。
  String get preview {
    final first = systemPrompt
        .split('\n')
        .map((l) => l.trim())
        .firstWhere((l) => l.isNotEmpty && !l.startsWith('#'), orElse: () => '');
    return first;
  }

  SkillDef copyWith({String? name, String? description, String? systemPrompt}) =>
      SkillDef(
        id: id,
        name: name ?? this.name,
        description: description ?? this.description,
        systemPrompt: systemPrompt ?? this.systemPrompt,
        source: source,
        path: path,
        resourceCount: resourceCount,
        meta: meta,
      );
}

/// `SKILL.md` 解析结果。
class SkillParseResult {
  final String? name;
  final String? description;
  final String body;
  final Map<String, dynamic> meta;

  const SkillParseResult({
    required this.name,
    required this.description,
    required this.body,
    required this.meta,
  });
}

/// SKILL.md 解析器：YAML frontmatter + 正文。
///
/// 兼容多种真实写法：带/不带 frontmatter、frontmatter 用 `---` 或 `+++`、
/// name/description 缺失时回退（description 取正文首段、name 由调用方给）。
class SkillParser {
  SkillParser._();

  /// 由名称生成 slug（保留中文，去掉空白与路径不安全字符）。
  static String slugify(String raw) {
    final s = raw
        .trim()
        .toLowerCase()
        .replaceAll(RegExp(r'[\s/\\:*?"<>|]+'), '-')
        .replaceAll(RegExp(r'-{2,}'), '-')
        .replaceAll(RegExp(r'^-|-$'), '');
    return s.isEmpty ? 'skill-${DateTime.now().millisecondsSinceEpoch}' : s;
  }

  /// 解析 SKILL.md 文本。
  static SkillParseResult parse(String source) {
    var text = source.replaceAll('\r\n', '\n');
    // 去掉 BOM
    if (text.isNotEmpty && text.codeUnitAt(0) == 0xFEFF) {
      text = text.substring(1);
    }
    final trimmed = text.trimLeft();
    for (final fence in const ['---', '+++']) {
      if (!trimmed.startsWith(fence)) continue;
      final afterOpen = trimmed.indexOf('\n');
      if (afterOpen < 0) break;
      final closeIdx = trimmed.indexOf('\n$fence', afterOpen);
      if (closeIdx < 0) break;
      final rawMeta = trimmed.substring(afterOpen + 1, closeIdx);
      final body = trimmed.substring(closeIdx + 1 + fence.length);
      Map<String, dynamic> meta = const {};
      try {
        final yaml = loadYaml(rawMeta);
        if (yaml is Map) {
          meta = yaml.map((k, v) => MapEntry(k.toString(), v));
        }
      } catch (_) {
        // frontmatter 不是合法 YAML：忽略元数据，正文仍然可用。
      }
      return SkillParseResult(
        name: _str(meta['name']) ?? _str(meta['title']),
        description: _str(meta['description']) ?? _str(meta['summary']),
        body: body.trim(),
        meta: meta,
      );
    }
    // 无 frontmatter：整个文件就是正文。
    return SkillParseResult(
      name: null,
      description: null,
      body: text.trim(),
      meta: const {},
    );
  }

  /// 正文首段作为 description 的回退值。
  static String fallbackDescription(String body) {
    for (final line in body.split('\n')) {
      final t = line.trim();
      if (t.isEmpty || t.startsWith('#')) continue;
      return t.length > 120 ? '${t.substring(0, 120)}…' : t;
    }
    return '（无说明）';
  }

  static String? _str(Object? v) {
    if (v == null) return null;
    final s = v.toString().trim();
    return s.isEmpty ? null : s;
  }

  /// 生成导出用的 SKILL.md 文本。
  static String compose({
    required String name,
    required String description,
    required String body,
  }) {
    final safeName = name.replaceAll('\n', ' ').trim();
    final safeDesc = description.replaceAll('\n', ' ').trim();
    return '---\n'
        'name: ${_quote(safeName)}\n'
        'description: ${_quote(safeDesc)}\n'
        '---\n\n'
        '$body\n';
  }

  /// YAML 值安全转义（含中文/特殊字符时加引号）。
  static String _quote(String v) {
    if (v.isEmpty) return '""';
    final needsQuote = RegExp(r'''[:#\[\]{}&*!|>'"%@`]''').hasMatch(v) ||
        v.startsWith('-') ||
        v.startsWith(' ');
    if (!needsQuote) return v;
    return '"${v.replaceAll(r'\', r'\\').replaceAll('"', r'\"')}"';
  }
}

/// 技能索引（导入技能的持久化元信息），避免每次启动解析所有文件。
class SkillIndexEntry {
  final String id;
  final String name;
  final String description;
  final String relPath;

  const SkillIndexEntry({
    required this.id,
    required this.name,
    required this.description,
    required this.relPath,
  });

  Map<String, Object?> toJson() => {
        'id': id,
        'name': name,
        'description': description,
        'relPath': relPath,
      };

  static SkillIndexEntry? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id']?.toString();
    final rel = raw['relPath']?.toString();
    if (id == null || id.isEmpty || rel == null || rel.isEmpty) return null;
    return SkillIndexEntry(
      id: id,
      name: raw['name']?.toString() ?? id,
      description: raw['description']?.toString() ?? '',
      relPath: rel,
    );
  }
}

/// 技能导出为 SKILL.md 的便捷封装。
String encodeSkillMarkdown(SkillDef def) => SkillParser.compose(
      name: def.name,
      description: def.description,
      body: def.systemPrompt,
    );

/// 供调试/日志使用的 JSON 快照。
String skillDebugJson(SkillDef def) => jsonEncode({
      'id': def.id,
      'name': def.name,
      'source': def.source.name,
      'resourceCount': def.resourceCount,
    });
