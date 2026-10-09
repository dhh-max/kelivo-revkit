import 'dart:math';

enum MemoryScope { global, assistant }

enum MemoryType { identity, workflow, voice, instruction, apkPatch, apkNote, apkFailure }

enum MemoryStatus { active, archived }

enum MemorySource { manual, tool, extracted, distilled }

class MemoryEntry {
  final String id;
  final MemoryScope scope;
  final String? assistantId;
  final MemoryType type;
  final MemoryStatus status;
  final String content;
  final MemorySource source;
  final List<String> relatedIds;
  final List<String> migrationIds;
  final DateTime createdAt;
  final DateTime updatedAt;

  /// 结构化扩展数据（APK 经验指纹 / 笔记 locator 等）。经 toPayload 序列化进
  /// payload JSON，由 drift 镜像表的 payload 列原样承载，无需独立列。
  final Map<String, dynamic>? extraJson;

  /// APK 三类（经验/笔记/失败）：都是**工具管理**的结构化记忆。
  ///
  /// 用户 2026-10-04「APK 三种类型会不会过多」：类型本身没错（生命周期不同：
  /// 经验=验证后的长期资产、笔记=按 locator 的改动台账、失败=自动落库的诊断
  /// 计数器），但它们在管理面应当归成一组，且不能走通用记忆编辑器
  /// （通用编辑器只改 content，会让 extraJson 与正文脱节）。
  static const Set<MemoryType> apkTypes = <MemoryType>{
    MemoryType.apkPatch,
    MemoryType.apkNote,
    MemoryType.apkFailure,
  };

  /// 参与**项目（工作区）隔离**的记忆类型（用户 2026-10-03 口径）。
  ///
  /// 「一般的话可以按照工作区来搞记忆；不用某个工作区就不要相应的记忆」——
  /// 身份/工作流/语气/指令这类一般记忆在写入时按当前工作区打标，只在同一工作区
  /// 可见；未绑定工作区时写入的不打标，照旧全局共享（老数据同理）。
  ///
  /// APK 三种（apkPatch/apkNote/apkFailure）是**软件逆向经验**，用户明确要求
  /// 「这个是经验，所以需要保留」——不参与项目隔离，任何工作区都可见可读。
  static const Set<MemoryType> projectScopedTypes = <MemoryType>{
    MemoryType.identity,
    MemoryType.workflow,
    MemoryType.voice,
    MemoryType.instruction,
  };

  /// 记忆所属**项目**（工作区）id；null = 全局（跨项目可见）。
  ///
  /// null 也代表「老数据/未标记」：一律按全局可见处理，不丢历史记忆。
  String? get projectId {
    final raw = extraJson?['projectId'];
    final value = raw?.toString().trim() ?? '';
    return value.isEmpty ? null : value;
  }

  /// 这条记忆在 [currentProjectId] 的项目里是否可见。
  ///
  /// - 非项目隔离类型（逆向经验等）：任何项目都可见（经验跨工作区保留）；
  /// - 项目隔离类型：无标记（全局）可见；有标记则只在同一项目里可见，
  ///   无项目上下文时不可见（不能串到别的项目）。
  bool visibleInProject(String? currentProjectId) {
    if (!projectScopedTypes.contains(type)) return true;
    final owner = projectId;
    if (owner == null) return true;
    final current = currentProjectId?.trim() ?? '';
    return current.isNotEmpty && current == owner;
  }

  /// 一行式摘要（取长补短自 ZCode 的 `description`）：写入时的 `extraJson['summary']`
  /// 优先，其次正文首个非空行。用于**相关性打分**与列表展示——注入时据此选条目，
  /// 不必把每条正文都塞进上下文。
  String get summary {
    final explicit = extraJson?['summary']?.toString().trim() ?? '';
    if (explicit.isNotEmpty) return explicit;
    for (final line in content.split('\n')) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;
      return trimmed.length <= 80 ? trimmed : '${trimmed.substring(0, 80)}…';
    }
    return content.length <= 80 ? content : '${content.substring(0, 80)}…';
  }

  const MemoryEntry({
    required this.id,
    required this.scope,
    this.assistantId,
    required this.type,
    this.status = MemoryStatus.active,
    required this.content,
    this.source = MemorySource.manual,
    this.relatedIds = const <String>[],
    this.migrationIds = const <String>[],
    required this.createdAt,
    required this.updatedAt,
    this.extraJson,
  });

  MemoryEntry copyWith({
    String? id,
    MemoryScope? scope,
    String? assistantId,
    MemoryType? type,
    MemoryStatus? status,
    String? content,
    MemorySource? source,
    List<String>? relatedIds,
    List<String>? migrationIds,
    DateTime? createdAt,
    DateTime? updatedAt,
    Map<String, dynamic>? extraJson,
    bool clearExtraJson = false,
    bool clearAssistantId = false,
  }) => MemoryEntry(
    id: id ?? this.id,
    scope: scope ?? this.scope,
    assistantId: clearAssistantId ? null : (assistantId ?? this.assistantId),
    type: type ?? this.type,
    status: status ?? this.status,
    content: content ?? this.content,
    source: source ?? this.source,
    relatedIds: relatedIds ?? this.relatedIds,
    migrationIds: migrationIds ?? this.migrationIds,
    createdAt: createdAt ?? this.createdAt,
    updatedAt: updatedAt ?? this.updatedAt,
    extraJson: clearExtraJson ? null : (extraJson ?? this.extraJson),
  );

  Map<String, dynamic> toPayload() => {
    'id': id,
    'scope': scopeToString(scope),
    'assistantId': assistantId,
    'type': typeToString(type),
    'status': statusToString(status),
    'content': content,
    'source': sourceToString(source),
    'relatedIds': relatedIds,
    if (migrationIds.isNotEmpty) 'migrationIds': migrationIds,
    if (extraJson != null) 'extraJson': extraJson,
    'createdAt': createdAt.microsecondsSinceEpoch,
    'updatedAt': updatedAt.microsecondsSinceEpoch,
  };

  static MemoryEntry fromPayload(Map<String, dynamic> json) {
    final scope = scopeFromString(json['scope'] as String);
    return MemoryEntry(
      id: json['id'] as String,
      scope: scope,
      assistantId: json['assistantId'] as String?,
      type: typeFromString(json['type'] as String),
      status: statusFromString((json['status'] as String?) ?? 'active'),
      content: json['content'] as String,
      source: sourceFromString((json['source'] as String?) ?? 'manual'),
      relatedIds:
          (json['relatedIds'] as List?)?.cast<String>() ?? const <String>[],
      migrationIds:
          (json['migrationIds'] as List?)?.cast<String>() ?? const <String>[],
      createdAt: DateTime.fromMicrosecondsSinceEpoch(
        (json['createdAt'] as num).toInt(),
      ),
      updatedAt: DateTime.fromMicrosecondsSinceEpoch(
        (json['updatedAt'] as num).toInt(),
      ),
      extraJson: json['extraJson'] is Map
          ? Map<String, dynamic>.from(json['extraJson'] as Map)
          : null,
    );
  }

  /// Trim, collapse every whitespace run to a single space, then lowercase.
  static String normalizeContent(String content) {
    return content.trim().replaceAll(RegExp(r'\s+'), ' ').toLowerCase();
  }

  /// Alphabet: `0123456789abcdef` (8 hex chars after `mem_`).
  static String newId([Random? random]) {
    final rng = random ?? Random.secure();
    const alphabet = '0123456789abcdef';
    final buf = StringBuffer('mem_');
    for (var i = 0; i < 8; i++) {
      buf.write(alphabet[rng.nextInt(alphabet.length)]);
    }
    return buf.toString();
  }

  static String scopeToString(MemoryScope scope) {
    switch (scope) {
      case MemoryScope.global:
        return 'global';
      case MemoryScope.assistant:
        return 'assistant';
    }
  }

  static MemoryScope scopeFromString(String value) {
    switch (value) {
      case 'global':
        return MemoryScope.global;
      case 'assistant':
        return MemoryScope.assistant;
      default:
        throw FormatException('Unknown MemoryScope: $value');
    }
  }

  static String typeToString(MemoryType type) {
    switch (type) {
      case MemoryType.identity:
        return 'identity';
      case MemoryType.workflow:
        return 'workflow';
      case MemoryType.voice:
        return 'voice';
      case MemoryType.instruction:
        return 'instruction';
      case MemoryType.apkPatch:
        return 'apk_patch';
      case MemoryType.apkNote:
        return 'apk_note';
      case MemoryType.apkFailure:
        return 'apk_failure';
    }
  }

  static MemoryType typeFromString(String value) {
    switch (value) {
      case 'identity':
        return MemoryType.identity;
      case 'workflow':
        return MemoryType.workflow;
      case 'voice':
        return MemoryType.voice;
      case 'instruction':
        return MemoryType.instruction;
      case 'apk_patch':
        return MemoryType.apkPatch;
      case 'apk_note':
        return MemoryType.apkNote;
      case 'apk_failure':
        return MemoryType.apkFailure;
      default:
        throw FormatException('Unknown MemoryType: $value');
    }
  }

  static String statusToString(MemoryStatus status) {
    switch (status) {
      case MemoryStatus.active:
        return 'active';
      case MemoryStatus.archived:
        return 'archived';
    }
  }

  static MemoryStatus statusFromString(String value) {
    switch (value) {
      case 'active':
        return MemoryStatus.active;
      case 'archived':
        return MemoryStatus.archived;
      default:
        throw FormatException('Unknown MemoryStatus: $value');
    }
  }

  static String sourceToString(MemorySource source) {
    switch (source) {
      case MemorySource.manual:
        return 'manual';
      case MemorySource.tool:
        return 'tool';
      case MemorySource.extracted:
        return 'extracted';
      case MemorySource.distilled:
        return 'distilled';
    }
  }

  static MemorySource sourceFromString(String value) {
    switch (value) {
      case 'manual':
        return MemorySource.manual;
      case 'tool':
        return MemorySource.tool;
      case 'extracted':
        return MemorySource.extracted;
      case 'distilled':
        return MemorySource.distilled;
      default:
        throw FormatException('Unknown MemorySource: $value');
    }
  }
}

/// 记忆对指定助手的可见性（global 对所有助手可见；assistant 域仅属主可见）。
/// 复用：memory_tools 与 memory_provider_v2 曾各自实现一份 _isVisible。
extension MemoryVisibility on MemoryEntry {
  bool isVisibleFor(String? assistantId) {
    if (scope == MemoryScope.global) return true;
    return assistantId != null && assistantId == this.assistantId;
  }
}
