/// 会话/工作区作用域：把「当前工作区根路径」和「一次工具调用的执行范围」串起来。
///
/// 台账/检查点/产物索引/待验证草稿等所有跨会话资源都通过 [run] 在正确的
/// scope 里执行读写，避免会话之间串数据。
class ProjectScope {
  ProjectScope._();

  static String? _currentRoot;
  static String? _currentId;

  static String? get currentRoot => _currentRoot;
  static String? get currentId => _currentId;

  /// 在给定 [root] 下执行 [action]。[force] 为 true 时无条件切作用域。
  ///
  /// [action] 支持同步或异步两种形式（通过 [runAsync] 显式区分以避免泛型推断歧义）。
  static T run<T>(
    String? id,
    String? root,
    T Function() action, {
    bool force = false,
  }) {
    final previousRoot = _currentRoot;
    final previousId = _currentId;
    final normalizedRoot = root?.trim();
    final effectiveRoot =
        (normalizedRoot == null || normalizedRoot.isEmpty) ? null : normalizedRoot;
    if (force || effectiveRoot != previousRoot) {
      _currentRoot = effectiveRoot;
      _currentId = id;
    }
    try {
      return action();
    } finally {
      _currentRoot = previousRoot;
      _currentId = previousId;
    }
  }

  /// 异步版本：[action] 返回 Future 时使用。
  static Future<T> runAsync<T>(
    String? id,
    String? root,
    Future<T> Function() action, {
    bool force = false,
  }) async {
    final previousRoot = _currentRoot;
    final previousId = _currentId;
    final normalizedRoot = root?.trim();
    final effectiveRoot =
        (normalizedRoot == null || normalizedRoot.isEmpty) ? null : normalizedRoot;
    if (force || effectiveRoot != previousRoot) {
      _currentRoot = effectiveRoot;
      _currentId = id;
    }
    try {
      return await action();
    } finally {
      _currentRoot = previousRoot;
      _currentId = previousId;
    }
  }
}
