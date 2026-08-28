/// A recorded tool call with input, output, and timing.
class ToolCallRecord {
  final String id;
  final String toolName;
  final String serverId;
  final Map<String, dynamic> arguments;
  final String? result;
  final String? error;
  final DateTime startedAt;
  final DateTime? completedAt;
  final bool approved;
  final String conversationId;
  final String messageId;

  const ToolCallRecord({
    required this.id,
    required this.toolName,
    required this.serverId,
    required this.arguments,
    this.result,
    this.error,
    required this.startedAt,
    this.completedAt,
    this.approved = true,
    required this.conversationId,
    required this.messageId,
  });

  Duration? get duration => completedAt != null
      ? completedAt!.difference(startedAt)
      : null;

  bool get isSuccess => error == null && result != null;
  bool get isError => error != null;
  bool get isPending => completedAt == null;

  ToolCallRecord copyWith({
    String? result,
    String? error,
    DateTime? completedAt,
    bool? approved,
  }) {
    return ToolCallRecord(
      id: id,
      toolName: toolName,
      serverId: serverId,
      arguments: arguments,
      result: result ?? this.result,
      error: error ?? this.error,
      startedAt: startedAt,
      completedAt: completedAt ?? this.completedAt,
      approved: approved ?? this.approved,
      conversationId: conversationId,
      messageId: messageId,
    );
  }
}

/// Auto-approval rule for MCP tool calls.
class ToolAutoApprovalRule {
  final String id;
  final String? serverIdPattern;
  final String? toolNamePattern;
  final bool approve;
  final DateTime createdAt;
  final bool enabled;

  const ToolAutoApprovalRule({
    required this.id,
    this.serverIdPattern,
    this.toolNamePattern,
    this.approve = true,
    required this.createdAt,
    this.enabled = true,
  });

  bool matches(String serverId, String toolName) {
    if (!enabled) return false;
    final serverOk = serverIdPattern == null ||
        serverIdPattern!.isEmpty ||
        serverId.contains(serverIdPattern!) ||
        RegExp(serverIdPattern!).hasMatch(serverId);
    final toolOk = toolNamePattern == null ||
        toolNamePattern!.isEmpty ||
        toolName.contains(toolNamePattern!) ||
        RegExp(toolNamePattern!).hasMatch(toolName);
    return serverOk && toolOk;
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'serverIdPattern': serverIdPattern,
    'toolNamePattern': toolNamePattern,
    'approve': approve,
    'createdAt': createdAt.toIso8601String(),
    'enabled': enabled,
  };

  static ToolAutoApprovalRule fromJson(Map<String, dynamic> json) =>
      ToolAutoApprovalRule(
        id: json['id'] as String? ?? '',
        serverIdPattern: json['serverIdPattern'] as String?,
        toolNamePattern: json['toolNamePattern'] as String?,
        approve: json['approve'] as bool? ?? true,
        createdAt: json['createdAt'] != null
            ? DateTime.tryParse(json['createdAt'] as String) ?? DateTime.now()
            : DateTime.now(),
        enabled: json['enabled'] as bool? ?? true,
      );
}