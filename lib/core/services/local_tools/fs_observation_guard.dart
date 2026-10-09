import 'dart:io';

/// 文件观测状态：调用方据此决定「直接写」「照旧写」还是「拒绝并让模型重读」。
enum FsObservationStatus {
  /// 没观测过这个路径——不拦（避免把从未读过的写入一律挡死）。
  unknown,

  /// 观测后没变——放行。
  unchanged,

  /// 观测后被外部改动（mtime 严格前进或 size 变化）——拒绝并要求重读。
  changed,
}

/// 文件 stale 守卫（对齐 deepseek-harness 的 `FS_STALE_VERSION` 语义）。
///
/// 只做**保守拦截**：只有「本进程确实读过该文件、且此后它变了」才拒绝，
/// 没读过的一律放行。这样既挡住「模型基于过期内容覆盖用户/其他 agent 的改动」，
/// 又不会把既有写路径（新文件、未读文件、包内路径）误伤。
///
/// 会话恢复**不携带**观测状态（进程内表，重启即空）——与 DSH 一致：
/// 恢复后必须重新读文件。
class FsObservationGuard {
  FsObservationGuard({this.maxEntries = 4096});

  final int maxEntries;
  final Map<String, FsObservation> _observed = <String, FsObservation>{};

  /// 记录一次观测（通常在一次成功读取之后）。路径不可 stat（包内条目、远端）
  /// 时静默跳过——守卫只治理真实文件。
  bool observe(String path) {
    final stat = _stat(path);
    if (stat == null) return false;
    _observed[_key(path)] = stat;
    if (_observed.length > maxEntries) {
      _observed.remove(_observed.keys.first);
    }
    return true;
  }

  FsObservationStatus check(String path) {
    final previous = _observed[_key(path)];
    if (previous == null) return FsObservationStatus.unknown;
    final current = _stat(path);
    if (current == null) {
      // 文件在我们观测后消失：也按「变了」处理，让模型重新确认目标。
      return FsObservationStatus.changed;
    }
    if (current.size != previous.size) return FsObservationStatus.changed;
    if (current.mtimeMs > previous.mtimeMs) return FsObservationStatus.changed;
    return FsObservationStatus.unchanged;
  }

  void forget(String path) => _observed.remove(_key(path));

  void clear() => _observed.clear();

  int get observedCount => _observed.length;

  /// 模型可见的补救话术：固定以「重新读取后重试」结尾（照抄 DSH 的说法）。
  static String staleMessage(String path) =>
      'cannot modify "$path": file changed since it was read '
      '— re-read the file, then retry';

  static String notObservedMessage(String path) =>
      'cannot modify "$path": file has not been read '
      '— read the file, then retry';

  static String _key(String path) =>
      path.replaceAll('\\', '/').trim().toLowerCase();

  static FsObservation? _stat(String path) {
    final trimmed = path.trim();
    if (trimmed.isEmpty) return null;
    try {
      final file = File(trimmed);
      if (!file.existsSync()) return null;
      final stat = file.statSync();
      return FsObservation(
        mtimeMs: stat.modified.millisecondsSinceEpoch,
        size: stat.size,
      );
    } catch (_) {
      // 路径不是本机真实文件（包内条目 / 权限不足）：不参与守卫。
      return null;
    }
  }
}

class FsObservation {
  const FsObservation({required this.mtimeMs, required this.size});

  final int mtimeMs;
  final int size;
}
