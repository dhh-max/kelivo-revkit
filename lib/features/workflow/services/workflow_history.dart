/// 编辑器撤销/重做栈（纯逻辑，可单测）。
///
/// 语义：**记录改动前的快照**。画布要发生结构性变化时，先取当前快照交给
/// [record]，再改画布；[undo] 用「当前快照」换回上一步的快照。
///
/// 渠道里踩过的坑（2026-10-02 审核）：上一版在改动**之后**压栈，于是压进去的
/// 是「已经改完」的状态，撤销等于原地踏步——UI 上看起来按钮能用、点了没反应。
/// 快照栈最容易错的就是这个时机，所以这里把它抽出来单独锁测试。
class WorkflowHistory {
  WorkflowHistory({this.limit = 30});

  /// 步数上限（超出丢最旧的一条）。
  final int limit;

  final List<String> _undo = <String>[];
  final List<String> _redo = <String>[];

  bool get canUndo => _undo.isNotEmpty;

  bool get canRedo => _redo.isNotEmpty;

  int get undoDepth => _undo.length;

  int get redoDepth => _redo.length;

  /// 记录一次改动前的状态。新改动会清空重做栈（分叉历史不保留）。
  void record(String before) {
    if (before.isEmpty) return;
    _undo.add(before);
    if (_undo.length > limit) {
      _undo.removeRange(0, _undo.length - limit);
    }
    _redo.clear();
  }

  /// 返回要恢复的快照；没有可撤销的步骤时返回 null。
  String? undo(String current) {
    if (_undo.isEmpty) return null;
    _redo.add(current);
    return _undo.removeLast();
  }

  /// 返回要恢复的快照；没有可重做的步骤时返回 null。
  String? redo(String current) {
    if (_redo.isEmpty) return null;
    _undo.add(current);
    if (_undo.length > limit) {
      _undo.removeRange(0, _undo.length - limit);
    }
    return _redo.removeLast();
  }

  void clear() {
    _undo.clear();
    _redo.clear();
  }
}
