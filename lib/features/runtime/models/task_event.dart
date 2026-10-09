/// 任务事件（§23.2 TaskEvent）。
///
/// 事件是任务状态的唯一依据：状态推进、证据写入、失败恢复都从这里回溯
/// （§13.4「状态推进必须有事件依据」「每次状态变化必须写入事件日志」）。
library;

/// 事件类型。用常量而非 enum，便于后续扩展而不破坏已落盘的旧记录。
class TaskEventType {
  TaskEventType._();

  static const created = 'task.created';
  static const statusChanged = 'task.status_changed';
  static const phaseChanged = 'task.phase_changed';
  static const workspacePrepared = 'workspace.prepared';

  static const toolCalled = 'tool.called';
  static const toolFailed = 'tool.failed';

  static const evidenceRecorded = 'evidence.recorded';
  static const evidenceConflict = 'evidence.conflict';

  static const patchPlanned = 'patch.planned';
  static const patchDryRun = 'patch.dry_run';
  static const patchApplied = 'patch.applied';

  static const verified = 'verify.completed';
  static const failureRecorded = 'failure.recorded';
  static const cleanupPerformed = 'workspace.cleanup';
}

/// 一条任务事件。
class TaskEvent {
  final String id;
  final String taskId;
  final String type;
  final String phase;
  final Map<String, Object?> payload;
  final int createdAt;

  const TaskEvent({
    required this.id,
    required this.taskId,
    required this.type,
    this.phase = '',
    this.payload = const {},
    this.createdAt = 0,
  });

  Map<String, Object?> toJson() => {
        'id': id,
        'taskId': taskId,
        'type': type,
        if (phase.isNotEmpty) 'phase': phase,
        if (payload.isNotEmpty) 'payload': payload,
        'createdAt': createdAt,
      };

  static TaskEvent fromJson(Object? raw) {
    if (raw is! Map) throw const FormatException('task event 不是对象');
    final id = raw['id']?.toString() ?? '';
    if (id.isEmpty) throw const FormatException('task event 缺少 id');
    return TaskEvent(
      id: id,
      taskId: raw['taskId']?.toString() ?? '',
      type: raw['type']?.toString() ?? '',
      phase: raw['phase']?.toString() ?? '',
      payload: raw['payload'] is Map
          ? Map<String, Object?>.from(raw['payload'] as Map)
          : const {},
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
    );
  }
}
