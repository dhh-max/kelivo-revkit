import 'dart:async';

/// 会话 → 项目（工作区）解析器。
///
/// `main.dart` 注入 `WorkspaceToolsService.resolveConversationProject`；测试注入
/// 替身。后台任务（记忆整理）与事后重算（用量锚定）都用它拿「这条会话属于哪个
/// 工作区」，而不是进程级活动项目——后者只反映「最后一次生成」，切会话/切工作区
/// 后就过期了。
typedef ConversationProjectResolver =
    Future<({String? id, String? root})> Function(String conversationId);

/// 当前工具调用所属**项目（工作区）**的作用域。
///
/// 用户 2026-10-03：「不同项目的绝对不能互通，同一个项目可以；记忆什么的都可以同，
/// 但不同项目的绝对不行」。需要项目维度的有两处：
///  - 文件族的工作根目录（`ApkWorkspaceBindingService.workDir()`）；
///  - 记忆的「项目结论」（只在本项目可见，用户级偏好仍全局）。
///
/// 放在 core 而不是功能层：记忆层要用它，但记忆不该反向依赖 APK 工作台。
/// 工具分发点（`tool_handler_service`）进入本地工具前压入一次，之后同 zone 内
/// 任何读取者拿到的都是同一个项目——不会出现「文件按 A 项目、记忆按 B 项目」。
class ProjectScope {
  ProjectScope._();

  static const Object _key = Object();

  /// 进程级「当前活动项目」兜底。
  ///
  /// 为什么需要兜底：注入记忆发生在**生成准备期**、记忆工具发生在**执行期**，
  /// 两者都不一定在工具分发的 zone 里。生成期解析出本会话绑定的工作区后同步写入
  /// 这里（不需要 await 链传播），于是「注入看到哪个项目」与「工具写到哪个项目」
  /// 是同一个。zone 里的值优先级更高（同 zone 内绝不被外层活动项目覆盖）。
  static String? activeId;

  static _ProjectBinding? get _binding {
    final value = Zone.current[_key];
    return value is _ProjectBinding ? value : null;
  }

  /// 当前项目 id：zone 优先，其次进程级活动项目（未绑定返回 null）。
  ///
  /// zone 里**存在绑定**时一律以绑定为准（空 id = 明确「这条会话没有项目」），
  /// 不再回落到进程级活动项目——否则「未绑定工作区的会话」会串到上一个项目。
  static String? get currentId {
    final binding = _binding;
    if (binding != null) {
      final scoped = binding.id.trim();
      return scoped.isEmpty ? null : scoped;
    }
    final active = activeId?.trim() ?? '';
    return active.isEmpty ? null : active;
  }

  /// 当前项目的工作根目录（未绑定返回 null）。
  static String? get currentRoot {
    final scoped = _binding?.root.trim() ?? '';
    return scoped.isEmpty ? null : scoped;
  }

  /// 清空进程级活动项目（切到无工作区的会话时调用）。
  static void clearActive() => activeId = null;

  /// 在某个项目作用域内执行 [action]。
  ///
  /// [force] 为 false（默认）时，id 与 root 都为空就原样执行（旧调用点行为不变）；
  /// 为 true 时即使两者都为空也进入「明确无项目」的 zone，屏蔽进程级活动项目。
  /// 后台记忆整理与工具分发在按会话解析出「没绑工作区」时必须用 [force]，
  /// 否则会拿到上一个会话的项目。
  static T run<T>(
    String? id,
    String? root,
    T Function() action, {
    bool force = false,
  }) {
    final normalizedId = id?.trim() ?? '';
    final normalizedRoot = root?.trim() ?? '';
    if (!force && normalizedId.isEmpty && normalizedRoot.isEmpty) {
      return action();
    }
    return runZoned(
      action,
      zoneValues: {
        _key: _ProjectBinding(id: normalizedId, root: normalizedRoot),
      },
    );
  }
}

class _ProjectBinding {
  const _ProjectBinding({required this.id, required this.root});

  final String id;
  final String root;
}
