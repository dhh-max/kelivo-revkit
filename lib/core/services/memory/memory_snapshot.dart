import '../../database/chat_database_repository.dart';
import '../../models/memory_entry.dart';
import '../workspace/project_scope.dart';
import 'memory_block_builder.dart';
import 'memory_prompts.dart';
import 'memory_relevance.dart';
import 'memory_repository.dart';

typedef MemorySnapshotState = ({String prefix, String hash, bool isEmpty});

/// The same effective profile and memory blocks for requests and usage caches.
Future<MemorySnapshotState> readMemorySnapshot({
  required ChatDatabaseRepository repository,
  required String assistantId,
  required MemoryPromptLang lang,
  required int maxItems,
  /// 当前项目（工作区）id：项目结论只在同项目可见。null = 不按项目过滤
  /// （未绑定工作区的旧路径保持原行为）。
  String? projectId,
  /// [projectId] 为空时是否回落到进程级活动项目（[ProjectScope.currentId]）。
  ///
  /// 请求期注入/用量 hash 必须显式传 `false`：项目身份由调用方按**这条会话**
  /// 解析好，不能取环境态——否则用户切工作区后重算的 hash 与请求期不同，
  /// 精确锚定会失效。
  bool useAmbientProject = true,
  /// 当前用户消息：用来按相关性选记忆（空 = 纯时间序，保持旧行为）。
  String? query,
}) async {
  final data = await repository.readMemorySnapshotData(
    assistantId: assistantId,
    // 项目过滤在下面按**显式/环境态**的项目统一做：先在这里按环境态筛一遍会把
    // 别的项目的条目永久丢掉，显式项目再也拿不回来。
    applyProjectScope: false,
  );
  final fields = data.profile;
  // 项目隔离（用户 2026-10-03）：只注入「全局/用户级 + 当前项目结论」。
  // 项目 A 的补丁/失败经验在项目 B 里不可见；偏好类记忆不打标，照旧全局共享。
  final effectiveProject = useAmbientProject
      ? (projectId ?? ProjectScope.currentId)
      : projectId;
  final visible = MemoryRepository.visibleInProject(
    data.memories,
    effectiveProject,
  );
  final totals = <MemoryType, int>{};
  for (final entry in visible) {
    totals.update(entry.type, (count) => count + 1, ifAbsent: () => 1);
  }
  final profileBlock = MemoryBlockBuilder.buildProfileBlock(
    fields: fields,
    lang: lang,
  );
  final memoryBlock = MemoryBlockBuilder.buildMemoryBlock(
    visible: visible,
    totalByType: totals,
    lang: lang,
    maxItems: maxItems,
    relevance: MemoryRelevance.scoreAll(visible, query),
  );
  return (
    prefix: MemoryBlockBuilder.buildFullSnapshotPrefix(
      profileBlock,
      memoryBlock,
      lang,
    ),
    hash: MemoryBlockBuilder.hashBlocks(profileBlock, memoryBlock),
    isEmpty:
        visible.isEmpty && fields.every((field) => field.value.trim().isEmpty),
  );
}
