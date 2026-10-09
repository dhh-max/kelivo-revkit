import 'package:flutter/foundation.dart';

enum WorkspaceKind { managed, linked }

/// 工作区的运行环境（用户 2026-10-04 批准「工作区即项目」P1）。
///
/// - [direct]：**直连 Android 文件系统**——文件读写/命令直接在宿主目录里发生，
///   产物用户自己就能取出（无需 root）。就是用户说的「工作台目录」那套。
/// - [sandbox]：挂 **Linux（PRoot）环境**，工作区根挂成沙盒 `/workspace`。
///
/// 以前这是两套并行系统（APK 工作台 = direct、工作区 = sandbox）；现在它是工作区的
/// 一个属性：同一个容器，两种环境。
enum WorkspaceEnvMode { direct, sandbox }

class Workspace {
  final String id;
  final String name;
  final WorkspaceKind kind;
  final String? hostPath;

  /// 环境模式：默认 [WorkspaceEnvMode.sandbox]（保持历史行为不变）。
  final WorkspaceEnvMode envMode;
  final bool shellNeedsApproval;
  final String defaultCwd;
  final Set<String> disabledTools;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime? lastUsedAt;

  const Workspace({
    required this.id,
    required this.name,
    required this.kind,
    this.hostPath,
    this.envMode = WorkspaceEnvMode.sandbox,
    this.shellNeedsApproval = false,
    this.defaultCwd = '',
    this.disabledTools = const {},
    required this.createdAt,
    required this.updatedAt,
    this.lastUsedAt,
  });

  /// 「默认工作区」的固定 id（未绑定会话自动落这里，见 WorkspaceProvider）。
  static const String defaultId = 'default';

  /// 是不是那个自动创建/复用的「默认工作区」。
  ///
  /// 它特殊在**记忆口径**：默认工作区里的记忆仍按「全局」处理（不打项目标记），
  /// 否则未绑定会话的记忆会突然只在一个项目里可见、也不再进全局画像蒸馏。
  bool get isDefault => id == defaultId;

  /// 默认工作区**还没设置根目录**。
  ///
  /// 用户 2026-10-04：「没有就让设置啊，别默认」——没设过目录时不要替用户挑一个
  /// （更不要把文件悄悄写进应用私有目录），而是提示去设置；工具在设置之前报
  /// `work_dir_not_set`。
  bool get needsRoot => isDefault && (hostPath ?? '').trim().isEmpty;

  bool isToolEnabled(String name) => !disabledTools.contains(name);

  Workspace copyWith({
    String? id,
    String? name,
    WorkspaceKind? kind,
    String? hostPath,
    WorkspaceEnvMode? envMode,
    bool? shellNeedsApproval,
    String? defaultCwd,
    Set<String>? disabledTools,
    DateTime? createdAt,
    DateTime? updatedAt,
    DateTime? lastUsedAt,
    bool clearHostPath = false,
    bool clearLastUsedAt = false,
  }) {
    return Workspace(
      id: id ?? this.id,
      name: name ?? this.name,
      kind: kind ?? this.kind,
      hostPath: clearHostPath ? null : (hostPath ?? this.hostPath),
      envMode: envMode ?? this.envMode,
      shellNeedsApproval: shellNeedsApproval ?? this.shellNeedsApproval,
      defaultCwd: defaultCwd ?? this.defaultCwd,
      disabledTools: disabledTools == null
          ? this.disabledTools
          : Set.unmodifiable(disabledTools),
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      lastUsedAt: clearLastUsedAt ? null : (lastUsedAt ?? this.lastUsedAt),
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'kind': kind.name,
    'hostPath': hostPath,
    'envMode': envMode.name,
    'shellNeedsApproval': shellNeedsApproval,
    'defaultCwd': defaultCwd,
    'disabledTools': disabledTools.toList()..sort(),
    'createdAt': createdAt.toIso8601String(),
    'updatedAt': updatedAt.toIso8601String(),
    'lastUsedAt': lastUsedAt?.toIso8601String(),
  };

  factory Workspace.fromJson(Map<String, dynamic> json) {
    return Workspace(
      id: json['id'] as String,
      name: (json['name'] as String?) ?? '',
      kind: workspaceKindFromString(json['kind'] as String?),
      hostPath: json['hostPath'] as String?,
      envMode: workspaceEnvModeFromString(json['envMode'] as String?),
      shellNeedsApproval: json['shellNeedsApproval'] as bool? ?? false,
      defaultCwd: (json['defaultCwd'] as String?) ?? '',
      disabledTools: Set.unmodifiable(
        (json['disabledTools'] as List? ?? const []).cast<String>(),
      ),
      createdAt: DateTime.parse(json['createdAt'] as String),
      updatedAt: DateTime.parse(json['updatedAt'] as String),
      lastUsedAt: json['lastUsedAt'] == null
          ? null
          : DateTime.parse(json['lastUsedAt'] as String),
    );
  }

  static WorkspaceKind workspaceKindFromString(String? value) {
    switch (value) {
      case 'linked':
        return WorkspaceKind.linked;
      case 'managed':
      default:
        return WorkspaceKind.managed;
    }
  }

  /// 缺省/未知一律 [WorkspaceEnvMode.sandbox]：老数据没有这个字段，必须保持
  /// 历史行为（移动端一直走沙盒），不能因为升级把已有工作区悄悄切到 direct。
  static WorkspaceEnvMode workspaceEnvModeFromString(String? value) {
    switch (value) {
      case 'direct':
        return WorkspaceEnvMode.direct;
      case 'sandbox':
      default:
        return WorkspaceEnvMode.sandbox;
    }
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        other is Workspace &&
            other.id == id &&
            other.name == name &&
            other.kind == kind &&
            other.hostPath == hostPath &&
            other.envMode == envMode &&
            other.shellNeedsApproval == shellNeedsApproval &&
            other.defaultCwd == defaultCwd &&
            setEquals(other.disabledTools, disabledTools) &&
            other.createdAt == createdAt &&
            other.updatedAt == updatedAt &&
            other.lastUsedAt == lastUsedAt;
  }

  @override
  int get hashCode => Object.hash(
    id,
    name,
    kind,
    hostPath,
    envMode,
    shellNeedsApproval,
    defaultCwd,
    Object.hashAllUnordered(disabledTools),
    createdAt,
    updatedAt,
    lastUsedAt,
  );
}
