/// 证据模型与证据等级（§11 Evidence Store）。
///
/// 三个硬约束：
/// - 候选不等于定位（§11.3）：只有 Candidate 等级时必须继续升级；
/// - 数字置信度只能用于排序，不能替代等级（§11.5）；
/// - 两个低成本探针冲突时不能拍脑袋选一个，要引入第三个独立探针（§11.4）。
library;

/// 证据等级（§11.3）。
enum EvidenceLevel {
  candidate('Candidate', '候选：字符串命中、命名相关、模糊匹配'),
  observed('Observed', '已观察：真实字段读写点、真实调用关系、实际分支'),
  correlated('Correlated', '已关联：多个证据互相支持，指向同一行为'),
  verified('Verified', '已验证：运行时验证、修改前后对比、安装测试');

  const EvidenceLevel(this.label, this.description);

  /// 英文名，落库与日志用。**不要直接显示给用户**。
  final String label;

  /// 中文说明，UI 用。
  final String description;

  /// 界面显示用的中文等级名（与 [label] 分开，label 是持久化契约）。
  String get displayName => switch (this) {
        EvidenceLevel.candidate => '候选',
        EvidenceLevel.observed => '已观察',
        EvidenceLevel.correlated => '已关联',
        EvidenceLevel.verified => '已验证',
      };

  /// 等级强弱，用于排序与「是否够用」判断。
  int get rank => index;

  bool operator >=(EvidenceLevel other) => rank >= other.rank;
  bool operator <(EvidenceLevel other) => rank < other.rank;

  static EvidenceLevel fromLabel(String label) =>
      EvidenceLevel.values.firstWhere(
        (l) => l.label.toLowerCase() == label.toLowerCase(),
        orElse: () => EvidenceLevel.candidate,
      );
}

/// 证据升级链（§11.4）。
///
/// 不要求每次走完整条链，但证据不足时必须继续升级。
enum EvidenceKind {
  string('STRING', 1),
  fieldUsage('FIELD_USAGE', 2),
  xref('XREF', 3),
  methodBody('METHOD_BODY', 5),
  behaviorVerify('BEHAVIOR_VERIFY', 8);

  const EvidenceKind(this.label, this.cost);

  final String label;

  /// 探针建议成本（§12.3），用于预算比较而非绝对耗时。
  final int cost;

  /// 链上的下一级；已在末端返回 null。
  EvidenceKind? get next {
    final i = index + 1;
    return i < EvidenceKind.values.length ? EvidenceKind.values[i] : null;
  }

  static EvidenceKind? fromLabel(String label) {
    final up = label.toUpperCase();
    for (final k in EvidenceKind.values) {
      if (k.label == up) return k;
    }
    return null;
  }
}

/// 证据来源（§11.2 source）。
class EvidenceSource {
  /// 所在产物，如 classes3.dex / lib/arm64-v8a/libx.so。
  final String artifact;
  final String? className;
  final String? method;

  /// 位置描述（偏移、行号、smali 索引等）。
  final String? location;

  const EvidenceSource({
    required this.artifact,
    this.className,
    this.method,
    this.location,
  });

  Map<String, Object?> toJson() => {
        'artifact': artifact,
        if (className != null) 'class': className,
        if (method != null) 'method': method,
        if (location != null) 'location': location,
      };

  static EvidenceSource fromJson(Object? raw) {
    if (raw is! Map) return const EvidenceSource(artifact: '');
    return EvidenceSource(
      artifact: raw['artifact']?.toString() ?? '',
      className: raw['class']?.toString(),
      method: raw['method']?.toString(),
      location: raw['location']?.toString(),
    );
  }
}

/// 一条证据（§11.2 / §23.4）。
class Evidence {
  final String id;
  final String taskId;

  /// 证据类型，取 [EvidenceKind.label] 或自定义串。
  final String type;

  final EvidenceLevel level;

  /// 这条证据支持的结论（一句话）。
  final String claim;

  final EvidenceSource source;

  /// 原始引用：kind 为 smali / elf / hex 等，path + range 定位。
  final Map<String, Object?> rawRef;

  /// 关系列表，如 {type: reads_field, target: UserInfo.isVip}。
  final List<Map<String, Object?>> relations;

  /// 产生这条证据的工具调用 id（§11.6 必须关联 ToolCall）。
  final String toolCallId;

  /// 已解决/未决标记：证据冲突时置为 false（§11.4 标记当前结论为未决）。
  final bool resolved;

  final int createdAt;

  const Evidence({
    required this.id,
    required this.taskId,
    required this.type,
    required this.level,
    required this.claim,
    required this.source,
    this.rawRef = const {},
    this.relations = const [],
    this.toolCallId = '',
    this.resolved = true,
    this.createdAt = 0,
  });

  Evidence copyWith({
    EvidenceLevel? level,
    String? claim,
    bool? resolved,
  }) =>
      Evidence(
        id: id,
        taskId: taskId,
        type: type,
        level: level ?? this.level,
        claim: claim ?? this.claim,
        source: source,
        rawRef: rawRef,
        relations: relations,
        toolCallId: toolCallId,
        resolved: resolved ?? this.resolved,
        createdAt: createdAt,
      );

  Map<String, Object?> toJson() => {
        'id': id,
        'taskId': taskId,
        'type': type,
        'level': level.label,
        'claim': claim,
        'source': source.toJson(),
        if (rawRef.isNotEmpty) 'rawRef': rawRef,
        if (relations.isNotEmpty) 'relations': relations,
        if (toolCallId.isNotEmpty) 'toolCallId': toolCallId,
        'resolved': resolved,
        'createdAt': createdAt,
      };

  static Evidence fromJson(Object? raw) {
    if (raw is! Map) throw const FormatException('evidence 不是对象');
    final id = raw['id']?.toString() ?? '';
    if (id.isEmpty) throw const FormatException('evidence 缺少 id');
    return Evidence(
      id: id,
      taskId: raw['taskId']?.toString() ?? '',
      type: raw['type']?.toString() ?? '',
      level: EvidenceLevel.fromLabel(raw['level']?.toString() ?? 'Candidate'),
      claim: raw['claim']?.toString() ?? '',
      source: EvidenceSource.fromJson(raw['source']),
      rawRef: raw['rawRef'] is Map
          ? Map<String, Object?>.from(raw['rawRef'] as Map)
          : const {},
      relations: [
        for (final r in (raw['relations'] as List? ?? const []))
          if (r is Map) Map<String, Object?>.from(r)
      ],
      toolCallId: raw['toolCallId']?.toString() ?? '',
      resolved: raw['resolved'] is bool ? raw['resolved'] as bool : true,
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
    );
  }
}

/// 证据冲突（§11.4）。
///
/// 冲突不自动裁决：只记录，并把两侧标记为未决，交给第三个独立探针。
class EvidenceConflict {
  final String id;
  final String taskId;
  final String claim;
  final List<String> evidenceIds;
  final String resolvedBy;
  final int createdAt;

  const EvidenceConflict({
    required this.id,
    required this.taskId,
    required this.claim,
    this.evidenceIds = const [],
    this.resolvedBy = '',
    this.createdAt = 0,
  });

  Map<String, Object?> toJson() => {
        'id': id,
        'taskId': taskId,
        'claim': claim,
        'evidenceIds': evidenceIds,
        'resolvedBy': resolvedBy,
        'createdAt': createdAt,
      };

  static EvidenceConflict fromJson(Object? raw) {
    if (raw is! Map) throw const FormatException('conflict 不是对象');
    return EvidenceConflict(
      id: raw['id']?.toString() ?? '',
      taskId: raw['taskId']?.toString() ?? '',
      claim: raw['claim']?.toString() ?? '',
      evidenceIds: [
        for (final e in (raw['evidenceIds'] as List? ?? const [])) e.toString()
      ],
      resolvedBy: raw['resolvedBy']?.toString() ?? '',
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
    );
  }
}
