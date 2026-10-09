/// 任务持久化（§13.4 / §23.1 / §23.2）。
///
/// 落盘布局（应用数据目录下）：
/// ```
/// runtime/
///   tasks/<taskId>/task.json      任务快照
///   tasks/<taskId>/events.jsonl   事件日志（追加写，一行一条）
/// ```
///
/// 为什么用文件而不是 SQLite：设计文档建议 SQLite，但 Dart 侧引入 SQLite
/// 需要新增原生插件依赖，会牵动 Android 构建。这里先用文件实现同一语义
/// （快照 + 追加事件流），并把读写收敛在本类内，后续替换存储不影响到调用方。
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../../utils/app_directories.dart';
import 'models/task.dart';
import 'models/task_event.dart';

class TaskStore {
  TaskStore({this._rootOverride});

  /// 测试用：覆盖根目录，避免依赖 path_provider。
  final Directory? _rootOverride;

  Directory? _cachedRoot;

  /// 写队列：把落盘操作串起来（**进程内共享**，静态）。
  ///
  /// 为什么需要：并行路线探索会同时跑多个子探针，它们各自都要写任务快照。
  /// Windows 上「写临时文件 + 重命名」并发执行会撞车（rename 时报
  /// 「另一个程序正在使用此文件」），导致一整个探针白跑。
  /// Dart 是单线程事件循环，串行化只需把 Future 链起来。
  ///
  /// 为什么是静态：`TaskSession.shared` 与 `RuntimeBridge.instance.runtime`
  /// 各持一个 TaskStore，实例级队列互相看不见，两套实例会在同一份 task.json
  /// 上交错「写临时文件 + 重命名」。共享一条链不影响不同 taskId 的并发，
  /// 因为不同任务写的是不同文件。
  static Future<void> _writeQueue = Future<void>.value();

  Future<T> _serialized<T>(Future<T> Function() body) {
    final completer = Completer<T>();
    _writeQueue = _writeQueue.then((_) async {
      try {
        completer.complete(await body());
      } catch (e, s) {
        completer.completeError(e, s);
      }
    });
    return completer.future;
  }

  Future<Directory> root() async {
    if (_rootOverride != null) return _rootOverride;
    if (_cachedRoot != null) return _cachedRoot!;
    final base = await AppDirectories.getAppDataDirectory();
    final dir = Directory(p.join(base.path, 'runtime'));
    await dir.create(recursive: true);
    _cachedRoot = dir;
    return dir;
  }

  Future<Directory> tasksDir() async =>
      Directory(p.join((await root()).path, 'tasks'));

  Future<Directory> taskDir(String taskId) async =>
      Directory(p.join((await tasksDir()).path, taskId));

  Future<File> _taskFile(String taskId) async =>
      File(p.join((await taskDir(taskId)).path, 'task.json'));

  Future<File> _eventsFile(String taskId) async =>
      File(p.join((await taskDir(taskId)).path, 'events.jsonl'));

  // ------------------------------------------------------------------ 任务

  Future<void> save(Task task) => _serialized(() async {
    final dir = await taskDir(task.id);
    await dir.create(recursive: true);
    await _writeJsonAtomic(await _taskFile(task.id), task.toJson());
  });

  /// 读-改-写原子化：读快照、apply [mutate]、再原子写回，全过程只占一个队列名额。
  ///
  /// 为什么不能写成 `final t = await load(id); await save(mutate(t));`：两个并发
  /// 调用会各自读到同一份旧快照，后写的把前者的修改整份盖掉（预算扣减、状态推进
  /// 都是这种「丢了但不报错」的丢失更新）。
  ///
  /// 注意：内部**不能**调用 [save]，[save] 自己也要进 [_serialized]，非重入队列
  /// 会等自己等到超时。返回 null 表示任务不存在或快照损坏。
  Future<Task?> updateTask(String taskId, Task Function(Task current) mutate) =>
      _serialized(() async {
        final file = await _taskFile(taskId);
        if (!await file.exists()) return null;
        final Task current;
        try {
          current = Task.fromJson(jsonDecode(await file.readAsString()));
        } catch (_) {
          return null;
        }
        final next = mutate(current);
        await (await taskDir(taskId)).create(recursive: true);
        await _writeJsonAtomic(file, next.toJson());
        return next;
      });

  Future<Task?> load(String taskId) async {
    final file = await _taskFile(taskId);
    if (!await file.exists()) return null;
    try {
      return Task.fromJson(jsonDecode(await file.readAsString()));
    } catch (_) {
      return null;
    }
  }

  /// 列出全部任务，按更新时间倒序。
  Future<List<Task>> list() async {
    final dir = await tasksDir();
    if (!await dir.exists()) return const [];
    final out = <Task>[];
    await for (final e in dir.list(followLinks: false)) {
      if (e is! Directory) continue;
      final t = await load(p.basename(e.path));
      if (t != null) out.add(t);
    }
    out.sort((a, b) => b.updatedAt.compareTo(a.updatedAt));
    return out;
  }

  /// 删除任务目录（任务数据整体移除，不保留诊断快照）。
  Future<bool> delete(String taskId) async {
    final dir = await taskDir(taskId);
    if (!await dir.exists()) return false;
    try {
      await dir.delete(recursive: true);
      return true;
    } catch (_) {
      return false;
    }
  }

  // ------------------------------------------------------------------ 事件

  /// 追加一条事件。事件只增不改，是状态回溯的唯一依据。
  Future<void> appendEvent(TaskEvent event) => _serialized(() async {
    final dir = await taskDir(event.taskId);
    await dir.create(recursive: true);
    final file = await _eventsFile(event.taskId);
    await file.writeAsString(
      '${jsonEncode(event.toJson())}\n',
      mode: FileMode.append,
      flush: true,
    );
  });

  /// 读取事件流，按写入顺序。损坏行跳过（事件日志不能因为一行坏掉全废）。
  Future<List<TaskEvent>> loadEvents(String taskId) async {
    final file = await _eventsFile(taskId);
    if (!await file.exists()) return const [];
    final out = <TaskEvent>[];
    try {
      for (final line in const LineSplitter().convert(await file.readAsString())) {
        final t = line.trim();
        if (t.isEmpty) continue;
        try {
          out.add(TaskEvent.fromJson(jsonDecode(t)));
        } catch (_) {
          // 跳过损坏行
        }
      }
    } catch (_) {
      return const [];
    }
    return out;
  }

  /// 原子写 JSON：先写临时文件再重命名，避免写一半被中断留下坏文件。
  Future<void> _writeJsonAtomic(File target, Map<String, Object?> json) async {
    final tmp = File('${target.path}.tmp');
    await tmp.writeAsString(jsonEncode(json), flush: true);
    await tmp.rename(target.path);
  }
}
