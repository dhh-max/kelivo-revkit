import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

import '../../utils/app_directories.dart';
import '../database/extension_entity_store.dart';
import '../models/workspace.dart';
import '../services/workspace/workspace_binding_actions.dart';
import 'assistant_provider.dart';

class WorkspaceProvider extends ChangeNotifier {
  WorkspaceProvider({required this.store, this.assistants}) {
    loaded = _load();
  }

  final ExtensionEntityStore store;
  final AssistantProvider? assistants;
  final List<Workspace> _workspaces = <Workspace>[];

  late final Future<void> loaded;

  List<Workspace> get workspaces => List.unmodifiable(_workspaces);

  Workspace? byId(String id) {
    for (final workspace in _workspaces) {
      if (workspace.id == id) return workspace;
    }
    return null;
  }

  Future<void> _load() async {
    try {
      final entities = await store.listByKind(
        ExtensionEntityStore.kindWorkspace,
      );
      _workspaces
        ..clear()
        ..addAll([
          for (final entity in entities) Workspace.fromJson(entity.payload),
        ]);
    } catch (e) {
      debugPrint('Failed to load workspaces: $e');
      _workspaces.clear();
    }
    await _ensureDefaultWorkspace();
    await _migrateDefaultWorkspaceEnvMode();
    notifyListeners();
  }

  /// 默认工作区 envMode 一次性迁移的标记键（登记在 localOnlyKeys 里）。
  static const String _defaultEnvModeMigratedKey =
      'workspace_default_envmode_v2';

  /// 默认工作区的根解析器（main 注入 `ApkWorkspaceBindingService.workbenchDir`）。
  /// core 不能反向依赖 features，所以用函数注入。
  static Future<String?> Function()? defaultRootResolver;

  /// **默认工作区**：常驻、不可删除（用户 2026-10-04：
  /// 「工作区这边搞一个默认的，就是不能删除的一个，用来不挂环境、直接可用的本地目录，
  /// 把 APP 放进去就能做基础修改」）。
  ///
  /// - 排在列表最前；`envMode = sandbox`（用户 2026-10-06 改口径：默认挂载
  ///   虚拟环境——环境可用就直接挂，不可用则在界面标「环境不可用」，不再
  ///   默认成「不挂环境」的本地目录）；
  /// - 根 = 用户已经设过的「工作台目录」；**没设过就留空**，绝不替你默认
  ///   （用户 2026-10-04：「没有就让设置啊，别默认」）——列表里会提示去设置，
  ///   工具在设置之前报 `work_dir_not_set`，不会把文件悄悄写进应用私有目录；
  /// - 已存在就不动（用户改过名字/根都保留）。
  /// 一次性迁移（用户 2026-10-06 改口径）：默认工作区过去固定 direct
  /// （「不挂环境、直接可用」），现在默认=挂载虚拟环境。已存在的默认工作区若
  /// 仍是 direct 就翻成 sandbox——prefs 标记保证只做一次，之后用户手动改回
  /// direct 不会被再次覆盖（该键已登记 localOnly，不受启动清理影响）。
  Future<void> _migrateDefaultWorkspaceEnvMode() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      if (prefs.getBool(_defaultEnvModeMigratedKey) ?? false) return;
      final index = _workspaces.indexWhere((w) => w.isDefault);
      if (index >= 0 &&
          _workspaces[index].envMode == WorkspaceEnvMode.direct) {
        final updated = _workspaces[index].copyWith(
          envMode: WorkspaceEnvMode.sandbox,
        );
        _workspaces[index] = updated;
        await store.upsert(
          ExtensionEntityStore.kindWorkspace,
          updated.id,
          updated.toJson(),
          sortOrder: 0,
        );
        notifyListeners();
      }
      await prefs.setBool(_defaultEnvModeMigratedKey, true);
    } catch (_) {
      // 迁移失败不影响加载；下次启动重试。
    }
  }

  Future<void> _ensureDefaultWorkspace() async {
    if (_workspaces.any((workspace) => workspace.id == Workspace.defaultId)) {
      return;
    }
    // 整段都要能失败：`_load()` 在启动路径上，任何插件缺失（测试环境没装
    // path_provider / shared_preferences）都不该让工作区列表加载不了。
    try {
      final explicit = await defaultRootResolver?.call();
      final root = (explicit ?? '').trim();
      final now = DateTime.now().toUtc();
      final workspace = Workspace(
        id: Workspace.defaultId,
        name: '默认工作区',
        kind: root.isEmpty ? WorkspaceKind.managed : WorkspaceKind.linked,
        hostPath: root.isEmpty ? null : root,
        envMode: WorkspaceEnvMode.sandbox,
        createdAt: now,
        updatedAt: now,
      );
      // 注意：这里**不建私有目录**。没设根就是"未设置"，等用户选目录。
      await store.upsert(
        ExtensionEntityStore.kindWorkspace,
        workspace.id,
        workspace.toJson(),
        sortOrder: 0,
      );
      _workspaces.insert(0, workspace);
    } catch (e) {
      debugPrint('Failed to ensure default workspace: $e');
    }
  }

  Future<Workspace> create({
    required String name,
    WorkspaceKind kind = WorkspaceKind.managed,
    String? hostPath,
    WorkspaceEnvMode envMode = WorkspaceEnvMode.sandbox,
    String? id,
  }) async {
    await loaded;
    final now = DateTime.now().toUtc();
    final workspace = Workspace(
      id: id ?? const Uuid().v4(),
      name: name,
      kind: kind,
      hostPath: hostPath,
      envMode: envMode,
      createdAt: now,
      updatedAt: now,
    );
    if (kind == WorkspaceKind.managed && (hostPath ?? '').trim().isEmpty) {
      // 老口径：managed 的根在 app 私有目录。显式给了 hostPath 的（新的可见根）
      // 就不再建私有目录，避免留一个永远用不到的空目录。
      await AppDirectories.workspaceFilesDir(workspace.id);
    }
    await store.upsert(
      ExtensionEntityStore.kindWorkspace,
      workspace.id,
      workspace.toJson(),
      sortOrder: _workspaces.length,
    );
    _workspaces.add(workspace);
    notifyListeners();
    return workspace;
  }

  /// 默认工作区（[Workspace.defaultId]）：**常驻、不可删除**，不挂环境、直接用
  /// 本地目录；未绑定会话的根就是它（用户 2026-10-04：「工作区这边搞一个默认的、
  /// 不能删除的一个，用来不挂环境直接可用，把 APP 放进去就能做基础修改」）。
  ///
  /// 正常路径下 [_load] 已经把它建好了；[hostPath] 只在没有记录时作为兜底根。
  Future<Workspace?> defaultWorkspace({String? hostPath}) async {
    await loaded;
    final existing = byId(Workspace.defaultId);
    if (existing != null) return existing;
    final root = (hostPath ?? '').trim();
    if (root.isEmpty) return null;
    final now = DateTime.now().toUtc();
    return Workspace(
      id: Workspace.defaultId,
      name: '默认工作区',
      kind: WorkspaceKind.linked,
      hostPath: root,
      envMode: WorkspaceEnvMode.direct,
      createdAt: now,
      updatedAt: now,
    );
  }

  Future<void> update(Workspace workspace) async {
    await loaded;
    final next = workspace.copyWith(updatedAt: DateTime.now().toUtc());
    final index = _workspaces.indexWhere((item) => item.id == next.id);
    await store.upsert(
      ExtensionEntityStore.kindWorkspace,
      next.id,
      next.toJson(),
      sortOrder: index >= 0 ? index : null,
    );
    if (index >= 0) {
      _workspaces[index] = next;
    } else {
      _workspaces.add(next);
    }
    notifyListeners();
  }

  Future<void> delete(String id, {bool deleteFiles = true}) async {
    await loaded;
    // 默认工作区**不可删除**（用户 2026-10-04 明确要求）：它是「不挂环境、直接
    // 可用的本地目录」那条常驻兜底，删了未绑定会话就没有根了。
    if (id == Workspace.defaultId) return;
    final existing = byId(id);
    await store.delete(ExtensionEntityStore.kindWorkspace, id);
    _workspaces.removeWhere((workspace) => workspace.id == id);
    if (deleteFiles &&
        existing != null &&
        existing.kind == WorkspaceKind.managed) {
      final root = await AppDirectories.getWorkspacesDirectory();
      final dir = Directory('${root.path}/$id');
      if (await dir.exists()) {
        await dir.delete(recursive: true);
      }
    }
    final assistants = this.assistants;
    if (assistants != null) {
      await clearAssistantDefaultsForDeletedWorkspace(
        assistants,
        workspaceId: id,
      );
    }
    notifyListeners();
  }

  Future<void> touchLastUsed(String id) async {
    await loaded;
    final existing = byId(id);
    if (existing == null) return;
    await update(existing.copyWith(lastUsedAt: DateTime.now().toUtc()));
  }

  /// 工作区的**宿主根目录**（唯一口径）。
  ///
  /// P1「工作区即项目」：显式给了 [Workspace.hostPath] 的一律用它——managed 也能
  /// 落在**用户可见目录**（新建工作区默认如此，取产物不需要 root）；没给的沿用
  /// 老口径（managed → app 私有目录，老工作区不动，不需要迁移）。
  Future<String> hostRootFor(Workspace workspace) async {
    final explicit = (workspace.hostPath ?? '').trim();
    if (explicit.isNotEmpty) {
      if (workspace.kind == WorkspaceKind.managed) {
        // managed + 显式根：目录不存在就建（用户可见目录可能被清理过）。
        try {
          final dir = Directory(explicit);
          if (!await dir.exists()) await dir.create(recursive: true);
        } catch (e) {
          debugPrint('Workspace visible root unavailable ($explicit): $e');
        }
      }
      return explicit;
    }
    if (workspace.kind == WorkspaceKind.linked) {
      throw StateError('linked workspace missing hostPath');
    }
    final dir = await AppDirectories.workspaceFilesDir(workspace.id);
    return dir.path;
  }

  /// 新建工作区时默认的**可见根**（`/storage/emulated/0/SoLab/<名字>`）。
  ///
  /// 返回 null 表示拿不到外部存储（没授权/异常）——调用方回落到 app 私有目录，
  /// 不阻断创建。
  static Future<String?> visibleRootFor(String name) async {
    try {
      final base = await _externalBaseDir();
      if (base == null) return null;
      final safe = name
          .trim()
          .replaceAll(RegExp(r'[\\/:*?"<>|]'), '_')
          .replaceAll(RegExp(r'\s+'), '_');
      final slug = safe.isEmpty ? 'workspace' : safe;
      final dir = Directory('$base/SoLab/$slug');
      if (!await dir.exists()) await dir.create(recursive: true);
      return dir.path;
    } catch (e) {
      debugPrint('Visible workspace root unavailable: $e');
      return null;
    }
  }

  /// `/storage/emulated/0`（拿不到就返回 null）。
  static Future<String?> _externalBaseDir() async {
    const candidates = <String>['/storage/emulated/0', '/sdcard'];
    for (final path in candidates) {
      try {
        final dir = Directory(path);
        if (await dir.exists()) return path;
      } catch (_) {}
    }
    return null;
  }
}
