import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;
import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/services/workspace/project_scope.dart';

/// APK 工作区状态 + 产物索引（自闭环，不依赖任何外部 MCP）。
///
/// 职责：
/// - 统一工作目录（APK/SO/文件工具共用；相对路径据此解析）；
/// - 当前连续修改目标 [activeApkPath]（每次成功写入自动前移，P3 一致性核对
///   以它对照报告 sourceApk）；
/// - 产物索引（未签名中间包 kind=patch / 签名成品 kind=build），支持
///   「成品即净」自动清理。
///
/// MT Manager 若需要，由用户自行配置为普通外部 MCP 直接服务 agent；
/// 本服务与其零耦合。
class ApkWorkspaceBindingService {
  ApkWorkspaceBindingService._();

  static const _buildsKey = 'apk_mod_build_index_v1';
  static const _activeApkKey = 'apk_mod_active_apk_v1';
  static const _fileArtifactsKey = 'apk_mod_file_artifacts_v1';
  static const _taskCheckpointsKey = 'apk_mod_task_checkpoints_v1';
  static const _signatureBypassDefaultKey =
      'apk_mod_signature_bypass_default_v1';
  static final Object _scopeZoneKey = Object();

  /// autoClean 活跃借用 guard（由 MCP 任务队列注入）：返回 true 表示
  /// 该路径仍被排队/执行中的任务引用，本轮 autoClean 跳过删除——否则
  /// 并发对同一输入下发多个 patch 时，先完成的会删掉输入，同批后续
  /// patch 全部 invalid_apk_path（实测两遍稳定复现的链式消耗）。
  static bool Function(String path)? pendingInputGuard;

  /// 工作目录（与输出目录共用同一 key）：用户在 APK 工作台选定的统一目录。
  /// 相对 apkPath / 文件名据此解析为绝对路径。
  static const workDirKey = 'apk_mod_output_dir';

  /// 「工作台目录优先」开关（默认开）。
  ///
  /// 用户 2026-10-04 说明的两种运行模式：
  /// - **工作台目录**（用户在 APK 工作台选的**真实可见目录**，无沙盒）：直接读写，
  ///   产物用户自己就能取出来（无需 root）；
  /// - **绑定工作区**：挂上 Linux 环境，工作区根成为沙盒 `/workspace`。
  ///
  /// 现状缺陷：`workDir()` 让「绑定工作区根」压过工作台目录，而 managed 工作区的
  /// 根在 app 私有目录（`/data/user/0/<pkg>/app_flutter/workspaces/<id>/files`），
  /// 于是设了可见目录也会静默写到内部目录 —— 「只有写入、没有写出」。
  ///
  /// 开（默认）：设了工作台目录就用它，绑定工作区只决定 Linux 环境；
  /// 关：回到按工作区隔离的旧口径（每个项目一个根）。
  static const preferWorkbenchDirKey = 'apk_work_dir_prefer_v1';
  static String? _cachedWorkDir;
  static String? _cachedWorkDirRaw;
  static bool _workDirLoaded = false;
  static List<Map<String, dynamic>>? _cachedBuilds;
  static String? _cachedBuildsRaw;
  static String? _cachedBuildsStorageKey;

  static String? get currentScopeId {
    final value = Zone.current[_scopeZoneKey]?.toString().trim();
    return value == null || value.isEmpty ? null : value;
  }

  /// 当前工具调用所属**工作区**的根目录（zone 值）。
  ///
  /// 用户 2026-10-03：「不同项目绝对不能互通，同一个项目可以」——`workDirKey`
  /// 是全局的，换项目后 file/grep/replace/frida 仍在**上一个项目**的目录里干活，
  /// 这就是串项目。工具分发点在进入本地工具前把该会话绑定工作区的根目录压进
  /// zone，[workDir] 优先返回它，于是 15 处使用点一次性获得按工作区隔离的根。
  ///
  /// 实际存储交给 core 的 [ProjectScope]：记忆层也要用同一个项目口径，不能让
  /// 「文件按 A 项目、记忆按 B 项目」。
  static String? get currentWorkspaceRoot => ProjectScope.currentRoot;

  /// 在「某个工作区（项目）」作用域内执行 [action]。
  ///
  /// [force] 见 [ProjectScope.run]：工具分发把按会话解析出的工作区（可能为空 =
  /// 未绑定）压进 zone，不允许回落到上一个会话的项目。
  static T runInWorkspaceRoot<T>(
    String? root,
    T Function() action, {
    String? id,
    bool force = false,
  }) => ProjectScope.run(id, root, action, force: force);

  /// 经验自动浮现钩子（2026-09-05）：main() 安装——读当前报告 →
  /// ApkPatchMemoryService.fingerprintFromReport → peekVerifiedExperience。
  /// 用函数注入而非直接 import，避免 binding → workspace_service /
  /// patch_memory_service 的反向依赖（二者已 import 本文件，直接引用成环）。
  /// 返回 null = 无命中（resume state 不加 verifiedExperience 键）。
  static Future<Map<String, dynamic>?> Function()? verifiedExperiencePeek;

  static Future<T> runInScope<T>(String? scopeId, Future<T> Function() action) {
    final normalized = scopeId?.trim() ?? '';
    if (normalized.isEmpty) return action();
    return runZoned(action, zoneValues: {_scopeZoneKey: normalized});
  }

  static String _scopedKey(String base) {
    final scope = currentScopeId;
    if (scope == null) return base;
    final suffix = base64Url.encode(utf8.encode(scope)).replaceAll('=', '');
    return '${base}_$suffix';
  }

  /// 读取当前生效的工作目录（未设置返回 null）。
  ///
  /// 优先级见 [effectiveWorkRoot]（默认「工作台目录优先」）。
  static Future<String?> workDir() async =>
      effectiveWorkRoot(workspaceRoot: currentWorkspaceRoot);

  /// 工作台里用户选定的目录（不含 zone 覆盖）。带缓存：工具链每步都会问。
  static Future<String?> workbenchDir() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(workDirKey);
    if (_workDirLoaded && raw == _cachedWorkDirRaw) return _cachedWorkDir;
    _cachedWorkDirRaw = raw;
    final trimmed = (raw ?? '').trim();
    _cachedWorkDir = trimmed.isEmpty ? null : trimmed;
    _workDirLoaded = true;
    return _cachedWorkDir;
  }

  /// 「工作台目录优先」开关——**已退役**（P1「工作区即项目」）。
  ///
  /// 保留 getter/setter 只为兼容旧数据与外部调用；根口径见 [effectiveWorkRoot]。
  /// 新语义：工作台目录 = 默认工作区的根，绑定工作区时用工作区自己的根。
  static Future<bool> preferWorkbenchDir() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(preferWorkbenchDirKey) ?? true;
  }

  static Future<void> setPreferWorkbenchDir(bool value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(preferWorkbenchDirKey, value);
  }

  /// **唯一的根口径**：文件工具与沙盒 `/workspace` 挂载都用它。
  ///
  /// P1「工作区即项目」（用户 2026-10-04 批准）之后口径变简单了：
  /// - 有工作区根（zone，即当前会话的工作区）→ **就用它**；
  /// - 没有（工具在无会话上下文里调用，例如工作台页自己）→ 回落到工作台目录。
  ///
  /// 「APK 工作台目录」不再是第二套全局根：它现在是**默认工作区**（未绑定会话自动
  /// 落它）的根。上一版那个「工作台目录优先」开关因此退役（[preferWorkbenchDir]
  /// 仅为兼容旧数据保留，不再参与判定）。
  static Future<String?> effectiveWorkRoot({String? workspaceRoot}) async {
    final scoped = (workspaceRoot ?? '').trim();
    if (scoped.isNotEmpty) return scoped;
    return workbenchDir();
  }

  /// 路径是不是 app 私有（无 root 取不出）——用于界面提示与「写出」引导。
  static bool isAppPrivatePath(String path) {
    final normalized = path.replaceAll('\\', '/');
    return normalized.startsWith('/data/') ||
        normalized.contains('/app_flutter/') ||
        normalized.contains('/code_cache/') ||
        normalized.contains('/no_backup/');
  }

  /// 解析用的**多根**（有序去重）：工作台全局目录（用户设定的「统一工作目录」）
  /// 与当前 zone 根。APK/SO/文件工具的路径判定逐根尝试，命中即可——同一物理
  /// 目录两种视图（会话工作区 / 设备工作目录）不再二选一。
  static Future<List<String>> resolutionRoots() async {
    final prefs = await SharedPreferences.getInstance();
    final global = prefs.getString(workDirKey);
    final roots = <String>[
      if (global != null && global.trim().isNotEmpty) global.trim(),
      if (currentWorkspaceRoot != null) currentWorkspaceRoot!,
    ];
    return roots.toSet().toList(growable: false);
  }

  /// Zone 别名归一（v6 D5 / F-33）：SoLab 工具族此前只认宿主绝对路径，
  /// `/workspace`、`/chat`、`/tmp` 这类系统提示里声明的别名一律被拒
  /// （file/artifact_read 报 PATH_OUTSIDE_WORKSPACE / PATH_ESCAPE）。
  /// 返回 null 表示不是别名（按原路径处理）。
  ///
  /// v9-N1（2026-10-05 真机）：**只保留语义正确的 /workspace 映射**（沙盒
  /// /workspace 与工作目录同挂载点，df 已证实）。/chat、/tmp 过去被粗暴改写到
  /// 工作目录/systemTemp——它们的真实宿主根是 sessionHostDir/tmpHostRoot
  /// （见 WorkspacePaths 挂载表），file 工具没有那份挂载表，静默改写会把读写
  /// 落到**错误文件**（比"拒绝"更危险）。返回 null 后调用方按越界拒绝，并指路
  /// workspace 工具（read_file/list_dir/write_file 对两 zone 有真映射）。
  static String? resolveZoneAlias(String path) {
    final trimmed = path.trim();
    for (final alias in const ['/workspace']) {
      if (trimmed == alias || trimmed.startsWith('$alias/')) {
        final root = currentWorkspaceRoot;
        if (root == null) return null;
        final rest = trimmed.length > alias.length
            ? trimmed.substring(alias.length + 1)
            : '';
        return rest.isEmpty ? root : p.normalize(p.join(root, rest));
      }
    }
    return null;
  }

  static Future<void> setWorkDir(String path) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(workDirKey, path);
    _cachedWorkDir = path;
    _cachedWorkDirRaw = path;
    _workDirLoaded = true;
  }

  static Future<void> clearWorkDir() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(workDirKey);
    _cachedWorkDir = null;
    _cachedWorkDirRaw = null;
    _workDirLoaded = true;
  }

  static Future<String?> managedOutputDir() async {
    return workDir();
  }

  /// 默认去签名方案（工作台设置）。
  ///
  /// **未设置时默认 `off` = 不去签**（2026-09-19 用户明确要求）：去签会改写
  /// PackageInfo 相关行为，属于"用户要才做"的动作，不该由默认值替用户决定。
  /// 之前兜底写的是 `'normal'`，而 UI 又把 `'normal'` 显示成"普通去签"，
  /// 结果新建安装看起来就是"默认去签名"——与 `signature_bypass` 工具自己的
  /// 报错文案（"工作台默认 mode=off"）也对不上。
  static Future<String> signatureBypassDefaultMode() async {
    final prefs = await SharedPreferences.getInstance();
    final mode = prefs.getString(_signatureBypassDefaultKey);
    return switch (mode) {
      'off' || 'normal' || 'original_apk' || 'dpatch' => mode!,
      _ => 'off',
    };
  }

  static Future<void> setSignatureBypassDefaultMode(String mode) async {
    if (mode != 'off' &&
        mode != 'normal' &&
        mode != 'original_apk' &&
        mode != 'dpatch') {
      throw ArgumentError.value(mode, 'mode');
    }
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_signatureBypassDefaultKey, mode);
  }

  /// 当前连续修改的输入 APK。每次成功写入后自动更新，下一步无需重复传路径。
  static Future<String?> activeApkPath() async {
    final prefs = await SharedPreferences.getInstance();
    final path = prefs.getString(_scopedKey(_activeApkKey));
    return path == null || path.isEmpty ? null : path;
  }

  static Future<void> setActiveApkPath(String path) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_scopedKey(_activeApkKey), path);
  }

  static Future<void> clearActiveApkPath() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_scopedKey(_activeApkKey));
  }

  static Future<List<Map<String, dynamic>>> listApks() async {
    final path = await workDir();
    if (path == null) return <Map<String, dynamic>>[];
    final directory = Directory(path);
    if (!await directory.exists()) return <Map<String, dynamic>>[];
    final apks = <Map<String, dynamic>>[];

    // handleError：跳过不可读条目（scoped storage 下部分条目枚举会抛权限
    // 异常），不能让单个坏条目炸掉整个列表。
    Future<void> collect(Directory dir) async {
      try {
        await for (final entry in dir.list().handleError((_) {})) {
          if (entry is File && entry.path.toLowerCase().endsWith('.apk')) {
            try {
              apks.add({
                'name': entry.uri.pathSegments.last,
                'path': entry.path,
                'size': await entry.length(),
              });
            } catch (_) {}
          }
        }
      } catch (_) {}
    }

    // 分区感知（最优方案 P3）：根（存量包）+ inbox/（导入暂存）+
    // 每个 App 工作区的 input|work|out（单层，不递归，与硬闸同口径）。
    await collect(directory);
    await collect(Directory(p.join(path, 'inbox')));
    List<FileSystemEntity> top = <FileSystemEntity>[];
    try {
      top = await directory.list().handleError((_) {}).toList();
    } catch (_) {}
    for (final entry in top) {
      if (entry is! Directory) continue;
      final base = p.basename(entry.path);
      if (base == 'inbox' || base == 'shared' || base == 'SoLab') continue;
      for (final sub in const ['input', 'work', 'out']) {
        await collect(Directory(p.join(entry.path, sub)));
      }
    }
    apks.sort((a, b) => (b['size'] as num).compareTo(a['size'] as num));
    return apks;
  }

  /// 目录是否真正可枚举（区分「目录为空」与「权限被拒」）。
  ///
  /// 只有"空目录"才配得上"可读"：`Directory.list().first` 在空目录抛的是
  /// StateError(No element)。此前其余未知异常也回 true（fail-open），权限被拒
  /// 会被伪装成空目录，调用方最终拿到"什么都没有"的静默空结果（R5）。
  static Future<bool> dirReadable(String path) async {
    final dir = Directory(path);
    try {
      if (!await dir.exists()) return false;
    } catch (_) {
      return false;
    }
    try {
      await dir.list().first;
      return true;
    } on FileSystemException {
      return false;
    } on StateError {
      return true; // 空目录：list().first 无元素
    } catch (_) {
      return false; // 未知 IO 失败：按不可读上报，避免"空目录"假象
    }
  }

  /// 登记一个已签名产物（内置 apk_sign / buildApk(sign=true)）并预存待验证记录。
  /// [outputSha256]：签名成品的 sha256——reportFreshness 校验活动产物内容、
  /// 验证回填对账都依赖它；缺了 freshness 只能查源包、查不到成品。
  static Future<List<String>> recordSignedBuild({
    required String? source,
    required String? output,
    String outputSha256 = '',
  }) => _withBuildsLock(
    () => _recordSignedBuildLocked(
      source: source,
      output: output,
      outputSha256: outputSha256,
    ),
  );

  static Future<List<String>> _recordSignedBuildLocked({
    required String? source,
    required String? output,
    String outputSha256 = '',
  }) async {
    if (output == null || output.isEmpty) return const <String>[];
    final builds = await readBuilds();
    Map<String, dynamic>? inputArtifact;
    for (final build in builds) {
      if (build['output'] == source) {
        inputArtifact = build;
        break;
      }
    }
    // 同名覆盖检测（2026-09-21 独立复验 D19/D20）：输出路径已存在记录时，
    // 那一条上的 pendingChanges 会随新记录一起被取代，读取方按 output== 取到的
    // 是新记录 → **旧打点静默消失**（复验方实测：写在 out/成品.apk 的打点被
    // 第二次 apk_sign 覆盖后查不到，只剩 auto:）。这里把被取代记录的打点
    // 合并进新记录的 pendingChanges，并把被取代记录留档（supersededRecords）。
    final superseded = <Map<String, dynamic>>[];
    for (final build in builds) {
      if (build['output'] == output) {
        superseded.add(Map<String, dynamic>.from(build));
      }
    }
    final pendingChanges = <Map<String, dynamic>>[
      for (final change
          in (inputArtifact?['pendingChanges'] as List? ?? const []))
        if (change is Map) Map<String, dynamic>.from(change),
    ];
    for (final old in superseded) {
      final oldChanges = old['pendingChanges'];
      if (oldChanges is! List) continue;
      for (final change in oldChanges) {
        if (change is! Map) continue;
        // 去重按 (operation, locators, evidence)：同一改动的重复登记不叠加。
        final signature =
            '${change['operation']}|${change['locators']}|${change['evidence']}';
        final exists = pendingChanges.any(
          (item) =>
              '${item['operation']}|${item['locators']}|${item['evidence']}' ==
              signature,
        );
        if (!exists) pendingChanges.add(Map<String, dynamic>.from(change));
      }
    }
    final pendingDraft = inputArtifact?['pendingMemoryDraft'] is Map
        ? Map<String, dynamic>.from(inputArtifact!['pendingMemoryDraft'] as Map)
        : {
            'title': pendingChanges.isEmpty
                ? '待验证 APK 修改'
                : '待验证 APK 修改: ${pendingChanges.map((e) => e['operation']).whereType<String>().toSet().join('、')}',
            'solution': pendingChanges.isEmpty
                ? '签名成品已生成，等待用户安装验证。'
                : pendingChanges
                      .map((e) {
                        final locators = (e['locators'] as List? ?? const [])
                            .map((value) => value.toString())
                            .where((value) => value.isNotEmpty)
                            .join('、');
                        return '${e['operation']}${locators.isEmpty ? '' : ': $locators'}';
                      })
                      .join('\n'),
            'targets': <String>[
              for (final change in pendingChanges)
                for (final locator in (change['locators'] as List? ?? const []))
                  if (locator.toString().isNotEmpty) locator.toString(),
            ],
            'createdAt': DateTime.now().millisecondsSinceEpoch,
          };
    await _appendBuild({
      'output': output,
      'kind': 'build',
      if (outputSha256.isNotEmpty) 'outputSha256': outputSha256,
      'source': source, // C3：源 APK（清理按源分组，防跨包混删）
      if (source != null && source.isNotEmpty) 'input': source,
      'rootSource':
          inputArtifact?['rootSource'] ??
          inputArtifact?['source'] ??
          inputArtifact?['input'] ??
          source,
      'signed': true, // 签名成品
      'pendingChanges': pendingChanges,
      'pendingMemoryDraft': pendingDraft,
      'pendingMemoryStatus': 'awaiting_user_verification',
      // 同名覆盖留档：记录被本次覆盖取代（附其 input/sha，可追溯）——
      // 过去是彻底丢弃，调用方只能看到"打点不见了"。
      if (superseded.isNotEmpty)
        'supersededRecords': <Map<String, dynamic>>[
          for (final old in superseded)
            <String, dynamic>{
              'input': old['input'],
              'outputSha256': old['outputSha256'],
              'pendingChangeCount': (old['pendingChanges'] as List?)?.length ?? 0,
              'timestamp': old['timestamp'],
            },
        ],
      if (superseded.isNotEmpty) 'overwroteSamePath': true,
      if (inputArtifact?['signatureCompatibility'] != null)
        'signatureCompatibility': inputArtifact!['signatureCompatibility'],
      if (inputArtifact?['signatureCompatibility'] != null)
        'modificationInputReady': true,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
    });
    await setActiveApkPath(output);
    return const <String>[];
  }

  /// 与 [path] 同名的历史台账条目（除最新一条外）。用于把"输出复用了历史
  /// 中间包名字"变成可见信号——那些条目的内容已被自动清理/替换，按文件名
  /// 识别产物会在重名后歧义（自检 D8 实测：去签产物复用了 极简记物_3.3.1_v1.apk）。
  static Future<List<Map<String, dynamic>>> historicalRecordsFor(
    String path,
  ) async {
    if (path.isEmpty) return const <Map<String, dynamic>>[];
    final builds = await readBuilds();
    final matches = <Map<String, dynamic>>[];
    var seenFirst = false;
    for (final build in builds) {
      if (build['output'] != path) continue;
      if (!seenFirst) {
        seenFirst = true; // 第一条是本次登记的当前条目，不算历史
        continue;
      }
      matches.add(build);
    }
    return matches;
  }

  /// 把产物内容指纹挂到对应 build 条目（供 reportFreshness 校验活动产物）。
  /// 条目不存在（如已被清理剪除）时静默跳过——指纹属于锦上添花，不阻塞。
  static Future<void> attachBuildOutputSha(String output, String sha256) =>
      _withBuildsLock(() => _attachBuildOutputShaLocked(output, sha256));

  static Future<void> _attachBuildOutputShaLocked(
    String output,
    String sha256,
  ) async {
    if (output.isEmpty || sha256.isEmpty) return;
    final builds = await readBuilds();
    final index = builds.indexWhere((build) => build['output'] == output);
    if (index == -1) return;
    builds[index]['outputSha256'] = sha256;
    await _writeBuilds(builds);
  }

  /// 记录自研 patch 产物并更新连续修改的当前输入包。
  /// 中间包策略：输入包与原包不同且位于工作目录时，新产物落地后**自动删除**
  /// 输入中间包并从台账剪除其条目（"删文件即剪台账"，防 exists:false 陈账
  /// 误导会话）；完整补丁链（operation/locators/evidence）随新条目的
  /// pendingChanges 累积保留，rootSource 始终指向原包——续做与重放从
  /// 原包 + pendingChanges 走，不依赖已删除的中间路径。
  static Future<List<String>> recordPatchArtifact({
    required String source,
    required String output,
    required String operation,
    List<String> locators = const <String>[],
    Map<String, dynamic>? evidence,
  }) => _withBuildsLock(
    () => _recordPatchArtifactLocked(
      source: source,
      output: output,
      operation: operation,
      locators: locators,
      evidence: evidence,
    ),
  );

  static Future<List<String>> _recordPatchArtifactLocked({
    required String source,
    required String output,
    required String operation,
    List<String> locators = const <String>[],
    Map<String, dynamic>? evidence,
  }) async {
    final builds = await readBuilds();
    final now = DateTime.now().millisecondsSinceEpoch;
    Map<String, dynamic>? inputArtifact;
    for (final build in builds) {
      if (build['output'] == source) {
        inputArtifact = build;
        break;
      }
    }
    final rootSource =
        inputArtifact?['rootSource']?.toString() ??
        inputArtifact?['source']?.toString() ??
        source;
    final signatureCompatibility =
        operation.startsWith('signature_compatibility_')
        ? operation.substring('signature_compatibility_'.length)
        : inputArtifact?['signatureCompatibility']?.toString();
    final pendingChanges = <Map<String, dynamic>>[
      for (final change
          in (inputArtifact?['pendingChanges'] as List? ?? const []))
        if (change is Map) Map<String, dynamic>.from(change),
    ];
    if (!operation.startsWith('signature_compatibility_')) {
      pendingChanges.add({
        'operation': operation,
        if (locators.isNotEmpty) 'locators': locators,
        if (evidence != null && evidence.isNotEmpty) 'evidence': evidence,
        'timestamp': now,
      });
    }
    builds.removeWhere((entry) => entry['output'] == output);
    builds.insert(0, {
      'output': output,
      'input': source,
      'source': rootSource,
      'rootSource': rootSource,
      'kind': 'patch',
      'operation': operation,
      'pendingChanges': pendingChanges,
      if (inputArtifact?['pendingMemoryDraft'] is Map)
        'pendingMemoryDraft': inputArtifact!['pendingMemoryDraft'],
      'signed': false,
      if (signatureCompatibility != null && signatureCompatibility.isNotEmpty)
        'signatureCompatibility': signatureCompatibility,
      if (signatureCompatibility != null && signatureCompatibility.isNotEmpty)
        'modificationInputReady': true,
      if (operation.startsWith('signature_compatibility_'))
        'chainRole': 'signature_compatibility_base',
      'timestamp': now,
    });

    final autoCleaned = <String>[];
    if (inputArtifact != null &&
        inputArtifact['keep'] != true &&
        p.normalize(p.absolute(source)) !=
            p.normalize(p.absolute(rootSource))) {
      final outputDir = await managedOutputDir();
      if (outputDir != null && p.isWithin(outputDir, source)) {
        final input = File(source);
        // 借用 guard：路径仍被排队/执行中任务引用时跳过删除，留给同批
        // 后续 patch 使用；后续任务完成时会在自己的 autoClean 轮次清理。
        final guarded = pendingInputGuard?.call(source) ?? false;
        if (!guarded && await input.exists()) {
          await input.delete();
          builds.removeWhere((entry) => entry['output'] == source);
          autoCleaned.add(source);
        }
      }
    }

    await _writeBuilds(builds);
    await setActiveApkPath(output);
    return autoCleaned;
  }

  static Future<void> replaceBuilds(List<Map<String, dynamic>> builds) =>
      _withBuildsLock(() => _writeBuilds(builds));

  /// 方案身份键：同一个「appId + 改点 + 方案文本」视为同一方案。
  /// 用于 D6 的单向状态迁移判定——签名/打包这类不改变方案的操作不得把已
  /// committed 的方案打回 awaiting_user_verification。
  static String solutionKey(Map<String, dynamic> draft) {
    final pkg = (draft['packageName'] ?? '').toString().trim().toLowerCase();
    final targets = ((draft['targets'] as List?) ?? const [])
        .map((e) => e.toString().trim())
        .where((e) => e.isNotEmpty)
        .toList()
      ..sort();
    final solution = (draft['solution'] ?? '')
        .toString()
        .replaceAll(RegExp(r'\s+'), ' ')
        .trim();
    return '$pkg|${targets.join(',')}|$solution';
  }

  /// 预存一条待验证的记忆草稿。
  ///
  /// D6（2026-09-21 自检）：记忆状态迁移必须**单向**。此前这里无条件写
  /// `awaiting_user_verification`，于是对同一方案再签一次名（solution/targets
  /// 完全相同）就把它从 `committed_after_user_verification` 打回待验证——
  /// 同一方案两种状态并存，用户侧的"已验证"结论被无理由撤销。
  /// 现在：同一方案已有 committed 记录时，新产物继承该结论并标注来源，
  /// 只有真正的新方案才进入 awaiting_user_verification。
  /// 返回 null 表示失败（无活动/指定产物，或该产物未签名）；成功时返回
  /// `{status, inherited, inheritedFrom}`，调用方据此如实回报记忆状态。
  static Future<Map<String, dynamic>?> stagePendingMemoryDraft(
    Map<String, dynamic> draft, {
    String? targetPath,
  }) async {
    final requested = (targetPath ?? '').trim();
    final String? active;
    if (requested.isEmpty) {
      active = await activeApkPath();
    } else if (requested.startsWith('/') || requested.contains(':')) {
      active = requested;
    } else {
      final dir = await workDir();
      active = (dir == null || dir.isEmpty) ? null : p.join(dir, requested);
    }
    if (active == null || active.isEmpty) return null;
    final builds = await readBuilds();
    final index = builds.indexWhere((build) => build['output'] == active);
    if (index == -1 || builds[index]['signed'] != true) return null;
    builds[index]['pendingMemoryDraft'] = Map<String, dynamic>.from(draft);
    final key = solutionKey(draft);
    // 已 committed 的同方案（任意产物）→ 继承，不回退。
    Map<String, dynamic>? committedSource;
    for (final entry in builds) {
      if (identical(entry, builds[index])) continue;
      if (entry['pendingMemoryStatus'] != 'committed_after_user_verification') {
        continue;
      }
      final existing = entry['pendingMemoryDraft'];
      if (existing is! Map) continue;
      if (solutionKey(Map<String, dynamic>.from(existing)) != key) continue;
      if (entry['verification'] != 'success') continue;
      committedSource = entry;
      break;
    }
    if (committedSource != null) {
      final source = committedSource['output']?.toString() ?? '';
      builds[index]['pendingMemoryStatus'] = 'committed_after_user_verification';
      builds[index]['verification'] = 'success';
      builds[index]['verificationInherited'] = true;
      builds[index]['verificationInheritedFrom'] = source;
      builds[index]['verificationInheritedNote'] =
          '同一方案（appId+改点+方案文本一致）此前已经用户验证通过，本次仅重新签名/打包，'
          '按单向迁移继承该结论，不再要求重复验证；如需针对本产物单独复核，'
          '用 record_apk_patch_verification 显式登记新的验证结果。';
      await _writeBuilds(builds);
      return {
        'status': 'committed_after_user_verification',
        'inherited': true,
        'inheritedFrom': source,
        'output': active,
      };
    }
    builds[index]['pendingMemoryStatus'] = 'awaiting_user_verification';
    await _writeBuilds(builds);
    return {
      'status': 'awaiting_user_verification',
      'inherited': false,
      'output': active,
    };
  }

  /// 暂存一条修改打点。
  ///
  /// D7（2026-09-21 自检）：[change] 里的打点过去恒定挂到"写入时刻的
  /// activeApkPath"，于是"对成品打点 → 紧接着 signature_bypass 切换活动产物"
  /// 会让这条打点出现在签名兼容基包的 pendingChanges 里（挂错产物，成品那条
  /// 永远丢失）。现在支持 [targetPath]：调用方传了目标 apkPath 就按它绑定，
  /// 与之后 activeArtifact 是否漂移无关；不传才回退活动产物。
  static Future<bool> stagePendingChange(
    Map<String, dynamic> change, {
    String? targetPath,
  }) => _withBuildsLock(
    () => _stagePendingChangeLocked(change, targetPath: targetPath),
  );

  static Future<bool> _stagePendingChangeLocked(
    Map<String, dynamic> change, {
    String? targetPath,
  }) async {
    final requested = (targetPath ?? '').trim();
    final String? active;
    if (requested.isEmpty) {
      active = await activeApkPath();
    } else if (requested.startsWith('/') || requested.contains(':')) {
      active = requested;
    } else {
      // 相对路径/文件名：归一化到工作目录（与其它工具链路径语义一致）。
      final dir = await workDir();
      active = (dir == null || dir.isEmpty) ? null : p.join(dir, requested);
    }
    if (active == null || active.isEmpty) return false;
    final builds = await readBuilds();
    final index = builds.indexWhere((build) => build['output'] == active);
    if (index == -1) return false;
    final changes = <Map<String, dynamic>>[
      for (final item in (builds[index]['pendingChanges'] as List? ?? const []))
        if (item is Map) Map<String, dynamic>.from(item),
    ];
    final locator = (change['locator'] ?? '').toString();
    if (locator.isNotEmpty) {
      changes.removeWhere((item) => item['locator']?.toString() == locator);
    }
    changes.add(Map<String, dynamic>.from(change));
    builds[index]['pendingChanges'] = changes;
    await _writeBuilds(builds);
    return true;
  }

  /// 用户确认最终成品有效后收尾：只保留原 APK 与当前签名成品。
  static Future<Map<String, dynamic>> cleanupAfterVerifiedSuccess() =>
      _withBuildsLock(() => _cleanupAfterVerifiedSuccessLocked());

  static Future<Map<String, dynamic>> _cleanupAfterVerifiedSuccessLocked() async {
    final dir = await workDir();
    final active = await activeApkPath();
    if (dir == null || active == null) {
      return {'ok': false, 'error': 'workspace_or_final_missing'};
    }
    final builds = await readBuilds();
    final finalIndex = builds.indexWhere(
      (build) => build['output'] == active && build['signed'] == true,
    );
    if (finalIndex == -1) {
      return {'ok': false, 'error': 'signed_final_missing'};
    }
    final finalBuild = builds[finalIndex];
    final original = await _resolveOriginalPath(
      builds: builds,
      finalBuild: finalBuild,
      finalPath: active,
      workDir: dir,
    );
    final root = Directory(dir);
    if (!await root.exists()) {
      return {'ok': false, 'error': 'work_dir_not_found'};
    }
    if (original == null) {
      return {
        'ok': false,
        'error': 'original_apk_missing',
        'message': '没有找到可确认的原包，已停止清理，避免误删当前工作区。',
      };
    }

    String normalized(String path) => p.normalize(p.absolute(path));
    final kept = <String>{normalized(active)};
    kept.add(normalized(original));

    // D5（2026-09-21 自检）：清理必须按"产物"分层，不能按"会话"一把梭。
    // 旧实现把工作目录根下除「原包 + 当前成品」外的一切都删掉，于是
    // <工作目录>/SoLab/blutter/v1（jobs + results + 语义索引/functionIndex，
    // 大包约 20MB、重建 18.7s~52.5s）与 <工作目录>/SoLab/cache（locator/dexio/jadx
    // 派生缓存）一起被删——同一 APK 的追问要从零重算。
    //
    // 现在：可复用层按源包 sha256 归属保留，只在源包变化或显式过期（prune）时清；
    // 一次性层（中间包、临时 workspace、editSession）仍按原策略在验证后清。
    final reusable = await _reusableCacheRoots(dir);
    final sourceSha = await _sha256OfPath(original);
    final cacheState = await _readReusableCacheState(dir);
    var reusablePreserved = <String>[];
    var reusableDropped = <String>[];
    for (final root in reusable) {
      if (!await root.exists()) continue;
      final previousSha = (cacheState[root.path] as Map?)?['sourceSha256']
          ?.toString();
      if (previousSha != null &&
          previousSha.isNotEmpty &&
          sourceSha.isNotEmpty &&
          previousSha != sourceSha) {
        // 源包已变（重打包/换包）：这份缓存对新源包无意义，删掉避免读错证据。
        try {
          await root.delete(recursive: true);
          reusableDropped.add(root.path);
        } catch (_) {}
        continue;
      }
      kept.add(normalized(root.path));
      reusablePreserved.add(root.path);
    }

    final deleted = <String>[];
    final failed = <String>[];

    // D6（2026-09-28 审查）：清理必须**限定在当前 App 的工作区**里。
    //
    // workDir() 是用户选定的统一工作目录（例如 /storage/emulated/0/Ai），
    // 它的直接子项并不都属于当前任务：inbox/（导入暂存）、shared/、
    // SoLab/（可复用缓存）、根级存量 APK，以及**其它 App 各自的
    // <name>/{input|work|out} 工作区**（见 listApks 的分区口径）。
    // 旧实现从根开始递归，凡不在 kept 里的一律删除，于是「App A 验证成功
    // 一次」会物理删掉 App B/C 的工作区和整个 inbox，且不可恢复。
    //
    // 现在：先从当前成品/原包反推所属 App 工作区（形如
    // <工作目录>/<App>/{input|work|out}/…，上溯到 input|work|out 的父目录），
    // 只在那个子树里清理；反推不出工作区时按根级布局处理，但先判「多 App
    // 统一根」（见下 multiAppRoot），绝不对根做递归删除。
    final rootPath = normalized(dir);
    String? appWorkspaceOf(String filePath) {
      var cursor = p.dirname(normalized(filePath));
      while (p.isWithin(rootPath, cursor)) {
        final base = p.basename(cursor);
        if (base == 'input' || base == 'work' || base == 'out') {
          final parent = p.dirname(cursor);
          // 直接挂在工作目录根下的 input|work|out 视为没有独立工作区。
          return p.equals(parent, rootPath) ? null : parent;
        }
        cursor = p.dirname(cursor);
      }
      return null;
    }

    final scopes = <String>{};
    for (final candidate in <String>[active, original]) {
      final scope = appWorkspaceOf(candidate);
      if (scope != null && !kept.contains(scope)) scopes.add(scope);
    }
    // 根级布局（历史单 App 工作目录：APK 直接躺在工作目录根下）没有
    // <App>/{input|work|out} 结构，不能因此就一个字节都不清；但也不能沿用
    // 「根下递归全清」。判定口径：
    //   - 根下已存在 inbox/、shared/ 或别的 <name>/{input|work|out} 工作区
    //     → 多 App 统一根：只删根级生成型中间包**文件**，目录一律不动
    //     （递归删目录正是 P0 越界删数的形态：一次验证成功删掉别的 App 整棵
    //     工作区与 inbox，不可恢复）；
    //   - 否则是纯根级布局：保持历史语义（根下除原包/成品/可复用层外全清）。
    final bool rootFallback = scopes.isEmpty;
    final bool multiAppRoot =
        rootFallback && await _hasSiblingAppWorkspaces(rootPath);
    if (rootFallback) scopes.add(rootPath);

    Future<void> clean(FileSystemEntity entity) async {
      final path = normalized(entity.path);
      if (kept.contains(path)) return;
      if (entity is Directory && kept.any((keep) => p.isWithin(path, keep))) {
        await for (final child in entity.list().handleError((_) {})) {
          await clean(child);
        }
        try {
          if (await entity.list().isEmpty) {
            await entity.delete();
            deleted.add(entity.path);
          }
        } catch (_) {}
        return;
      }
      try {
        if (entity is Directory) {
          await entity.delete(recursive: true);
        } else {
          await entity.delete();
        }
        deleted.add(entity.path);
      } catch (_) {
        failed.add(entity.path);
      }
    }

    // 多 App 统一根下，根级文件不能只凭命名正则就删：用户自己放进统一根的
    // xxx_signed.apk 同样匹配生成型命名，会被当成中间包物理删掉（不可恢复）。
    // 双条件收窄为「命名像中间包（isGeneratedArtifactName）+ 台账证明了它是
    // SoLab 的未签名中间产物（signed != true 的记录 output）」；签名成品
    // （signed == true，任一 App 的交付物）永不在根级按名删除。
    final ledgerIntermediates = <String>{
      for (final build in builds)
        if (build['signed'] != true &&
            (build['output'] ?? '').toString().trim().isNotEmpty)
          normalized((build['output'] ?? '').toString().trim()),
    };
    final skippedUnowned = <String>[];

    for (final scope in scopes) {
      final workspace = Directory(scope);
      if (!await workspace.exists()) continue;
      // 只遍历工作区**内部**；工作区目录本身即使清空也不在这里删，
      // 免得连 kept 里的原包/成品一起带走。
      final List<FileSystemEntity> children;
      try {
        children = await workspace.list().handleError((_) {}).toList();
      } catch (_) {
        continue;
      }
      for (final entry in children) {
        if (multiAppRoot) {
          // 多 App 统一根：只清根级生成型中间包文件，目录（别的 App 工作区、
          // inbox、用户自建目录）一律不动。
          if (entry is! File) continue;
          if (kept.contains(normalized(entry.path))) continue;
          if (!isGeneratedArtifactName(entry.uri.pathSegments.last)) continue;
          if (!ledgerIntermediates.contains(normalized(entry.path))) {
            // 命名像中间包但台账没有归属：可能是别的 App 的交付物或用户
            // 自建文件。此前只按名删除，属越界删数（不可恢复）；现在不删，
            // 只在返回值里登记，让调用方/用户自己判断。
            skippedUnowned.add(entry.path);
            continue;
          }
          try {
            await entry.delete();
            deleted.add(entry.path);
          } catch (_) {
            failed.add(entry.path);
          }
          continue;
        }
        await clean(entry);
      }
    }

    // 台账只丢弃**被清掉的那个工作区**名下的条目：其它 App 的产物链记录
    // 必须原样保留（R3：产物链绑定以本地 boundApk 为准，属于全局台账）。
    // 按**真正被删掉的路径**筛台账，而不是按 scope 粗筛：根级布局下
    // scope = 工作目录根，粗筛会把其它 App 的产物链记录一并丢掉。
    final deletedPaths = {
      for (final path in deleted) normalized(path),
    };
    final retained = <Map<String, dynamic>>[];
    for (final build in builds) {
      final output = (build['output'] ?? '').toString().trim();
      if (output.isEmpty) {
        retained.add(build);
        continue;
      }
      final normalizedOutput = normalized(output);
      var ownedByClean = false;
      for (final deletedPath in deletedPaths) {
        if (p.equals(deletedPath, normalizedOutput) ||
            p.isWithin(deletedPath, normalizedOutput)) {
          ownedByClean = true;
          break;
        }
      }
      if (!ownedByClean) retained.add(build);
    }
    final retainedOutputs = {
      for (final build in retained) (build['output'] ?? '').toString(),
    };
    if (!retainedOutputs.contains(active)) retained.add(finalBuild);
    await replaceBuilds(retained);
    await pruneMissingArtifacts();
    // 记录归属：这份可复用缓存属于哪个源包。下次清理时源包 sha256 变了就丢弃
    // ——这就是"只在源包变化或显式过期时清理"的判定依据。
    await _writeReusableCacheState(dir, {
      for (final path in reusablePreserved)
        path: {
          'sourceSha256': sourceSha,
          'sourcePath': original,
          'preservedAt': DateTime.now().millisecondsSinceEpoch,
        },
    });
    return {
      'ok': failed.isEmpty,
      'deletedCount': deleted.length,
      'deleted': deleted,
      'kept': [original, active],
      // 可复用层：保留即"同一 APK 追问不必重算"，如实回报以便调用方判断
      // 后续 blutter 分析会不会命中缓存。
      if (reusablePreserved.isNotEmpty) 'preservedReusable': reusablePreserved,
      if (reusableDropped.isNotEmpty) 'droppedReusable': reusableDropped,
      if (reusableDropped.isNotEmpty)
        'droppedReusableReason': '源包内容已变（sha256 不同），旧缓存对新源包无效，已删除以免读到错证据。',
      if (failed.isNotEmpty) 'failed': failed,
      // 命名像中间包但台账无归属、因而**故意没删**的根级文件（越界删数防护）。
      if (skippedUnowned.isNotEmpty) 'skippedUnownedGenerated': skippedUnowned,
    };
  }

  /// 可复用缓存根（工作目录内）：Blutter 产物与派生缓存。
  ///
  /// 判定口径 = "内容由源包派生、重建代价高、删了只影响速度不影响正确性"：
  ///   SoLab/blutter/v1  —— jobs + results + 语义索引/functionIndex/pp.txt/asm
  ///   SoLab/cache       —— locator / dexio / jadx 派生缓存
  /// 中间包与临时 workspace 不在此列（它们是一次性的，验证后该清）。
  static Future<List<Directory>> _reusableCacheRoots(String workDir) async {
    final solab = Directory(p.join(workDir, 'SoLab'));
    if (!await solab.exists()) return const <Directory>[];
    return <Directory>[
      Directory(p.join(solab.path, 'blutter')),
      Directory(p.join(solab.path, 'cache')),
    ];
  }

  static String _reusableCacheStatePath(String workDir) =>
      p.join(workDir, 'SoLab', 'cache-reusable.json');

  static Future<Map<String, dynamic>> _readReusableCacheState(
    String workDir,
  ) async {
    try {
      final file = File(_reusableCacheStatePath(workDir));
      if (!await file.exists()) return <String, dynamic>{};
      final decoded = jsonDecode(await file.readAsString());
      return decoded is Map ? Map<String, dynamic>.from(decoded) : {};
    } catch (_) {
      return <String, dynamic>{};
    }
  }

  static Future<void> _writeReusableCacheState(
    String workDir,
    Map<String, dynamic> state,
  ) async {
    try {
      await Directory(p.join(workDir, 'SoLab')).create(recursive: true);
      await File(
        _reusableCacheStatePath(workDir),
      ).writeAsString(jsonEncode(state));
    } catch (_) {}
  }

  /// 文件 sha256（不存在/失败回空串）。分层判定要的是"内容是否变了"，
  /// 用流式读避免大包一次性进堆。
  static Future<String> _sha256OfPath(String path) async {
    try {
      final file = File(path);
      if (!await file.exists()) return '';
      final digest = await sha256.bind(file.openRead()).first;
      return digest.toString();
    } catch (_) {
      return '';
    }
  }

  /// 一级自动清理（改完即清，无需用户确认）：签名成品落地后，删除工作
  /// 目录内所有生成型中间包（_v1/_v2 命名），保留：原包、当前成品、
  /// 分析目录与其他文件。
  /// 修改无效时上一版成品即下一轮基底（基底=原包语义），因此绝不删
  /// 原包链与当前成品。
  static Future<List<String>> cleanupIntermediateArtifacts({
    required String outputPath,
  }) => _withBuildsLock(
    () => _cleanupIntermediateArtifactsLocked(outputPath: outputPath),
  );

  /// 统一工作目录根下是否已存在「别的 App 的工作区」（`<name>/{input|work|out}`）
  /// 或用户导入暂存（inbox/、shared/）。用于区分根级单 App 布局与多 App 统一根：
  /// 后者绝不能按根递归清理。枚举失败时按"可能是多 App 根"处理（宁保守不误删）。
  static Future<bool> _hasSiblingAppWorkspaces(String rootPath) async {
    final root = Directory(rootPath);
    if (!await root.exists()) return false;
    try {
      await for (final entry in root.list().handleError((_) {})) {
        if (entry is! Directory) continue;
        final name = p.basename(entry.path);
        if (name == 'inbox' || name == 'shared') return true;
        var markers = 0;
        for (final marker in const ['input', 'work', 'out']) {
          if (await Directory(p.join(entry.path, marker)).exists()) markers++;
        }
        if (markers >= 2) return true;
      }
    } catch (_) {
      return true;
    }
    return false;
  }

  static Future<List<String>> _cleanupIntermediateArtifactsLocked({
    required String outputPath,
  }) async {
    final dir = await workDir();
    if (dir == null || dir.isEmpty) return const <String>[];
    final root = Directory(dir);
    if (!await root.exists()) return const <String>[];
    final builds = await readBuilds();
    final keeps = <String>{p.normalize(p.absolute(outputPath))};
    // 原包：成品链上的 rootSource 候选（与确认后清理同一判定口径）
    final active = await activeApkPath();
    final finalBuild = builds.cast<Map<String, dynamic>?>().lastWhere(
      (build) => build?['output'] == active,
      orElse: () => null,
    );
    if (finalBuild != null) {
      for (final key in const ['rootSource', 'source', 'input']) {
        final value = (finalBuild[key] ?? '').toString();
        if (value.isNotEmpty) keeps.add(p.normalize(p.absolute(value)));
      }
    }
    // 只删**本链祖先**上的生成型中间包（2026-10-03 报告 F-03：此前按文件名
    // 无差别删，同源的并行链路（如去签链 vs SO 写回链）会互相清掉对方的产物）。
    // 沿产物索引 output→input 递归收集当前链的祖先集合。
    final ancestors = <String>{};
    final byOutput = <String, Map<String, dynamic>>{
      for (final build in builds)
        if ((build['output'] ?? '').toString().isNotEmpty)
          p.normalize(p.absolute(build['output'].toString())): build,
    };
    var frontier = <String>[
      p.normalize(p.absolute(outputPath)),
      if (finalBuild != null)
        for (final key in const ['source', 'input', 'rootSource'])
          if ((finalBuild[key] ?? '').toString().isNotEmpty)
            p.normalize(p.absolute(finalBuild[key].toString())),
    ];
    while (frontier.isNotEmpty) {
      final next = <String>[];
      for (final path in frontier) {
        if (!ancestors.add(path)) continue;
        final build = byOutput[path];
        if (build == null) continue;
        for (final key in const ['source', 'input', 'rootSource']) {
          final value = (build[key] ?? '').toString();
          if (value.isNotEmpty) next.add(p.normalize(p.absolute(value)));
        }
      }
      frontier = next;
    }
    final deleted = <String>[];
    await for (final entry in root.list().handleError((_) {})) {
      if (entry is! File) continue;
      final path = p.normalize(p.absolute(entry.path));
      if (keeps.contains(path)) continue;
      if (!isGeneratedArtifactName(entry.uri.pathSegments.last)) continue;
      // 有链信息时只删本链祖先集合里的文件（沿 output→input 递归得到的中间包
      // 路径）；索引里没有记载的生成型文件（其它链路/其它 App 的）保留。
      // 索引完全为空（例如手工产物、老数据）时退回旧的文件名判定——否则清理
      // 会静默失效（既有用例锁的就是这条兜底）。
      if (byOutput.isNotEmpty && !ancestors.contains(path)) continue;
      try {
        await entry.delete();
        deleted.add(entry.path);
      } catch (_) {}
    }
    // 删除后同步剪掉产物索引里已不存在的条目，避免 exists:false 陈账。
    // 保护 outputPath：刚产出的成品可能尚未落盘完成。
    await pruneMissingArtifacts(protectPaths: {outputPath});
    return deleted;
  }

  /// 生成型中间包命名判定（_v1/_v2 等后缀 apk）。兼容识别旧命名，
  /// 原包/当前成品/普通文件不受影响。
  static bool isGeneratedArtifactName(String fileName) => RegExp(
    r'(_v\d+|_signed|_structural|_dexpatch|_manifest|_assets|_abi)\.apk$',
    caseSensitive: false,
  ).hasMatch(fileName);

  /// 解析一个 APK 路径在产物链上的**血缘根**（原始包）。
  ///
  /// 为什么需要（2026-09-14 真机反馈「一个 APP 几十份报告」）：运行时的任务
  /// 按 `inputApk` 路径复用，而工具链每走一步（去签 → 中间包 → 成品 → 签名包）
  /// activeApkPath 就前移一次、路径变一次——按路径比较就会**每一步新建一条任务**，
  /// 同一个 APP 攒下几十条任务记录、几十份交付报告。
  ///
  /// 判定依据产物索引：派生包的条目里 `rootSource` 始终指向原包
  /// （`recordPatchArtifact` / `recordSignedBuild` 都这么写）。不在索引里的
  /// 路径（用户新选的源包）就是它自己的根。
  static Future<String> lineageRootOf(String apkPath) async {
    final target = await absoluteArtifactPath(apkPath);
    if (target.isEmpty) return '';
    List<Map<String, dynamic>> builds;
    try {
      builds = await readBuilds();
    } catch (_) {
      return target;
    }
    for (final build in builds.reversed) {
      final output =
          await absoluteArtifactPath((build['output'] ?? '').toString());
      if (output != target) continue;
      for (final key in const ['rootSource', 'source', 'input']) {
        final root =
            await absoluteArtifactPath((build[key] ?? '').toString());
        if (root.isNotEmpty) return root;
      }
    }
    return target;
  }

  /// 两个路径是否属于同一条产物链（同一个原包及其派生）。
  ///
  /// 用于任务复用：同一链上的路径变化（换成品/换去签包/换签名包）不算换目标。
  static Future<bool> sameLifecycle(String a, String b) async {
    final rootA = await lineageRootOf(a);
    final rootB = await lineageRootOf(b);
    if (rootA.isEmpty || rootB.isEmpty) return false;
    if (p.equals(rootA, rootB)) return true;
    // v9-N2（v13 复测）：台账没有血缘记录时，「同一原包派生的改包」会被判成
    // 两个目标——审计在原包↔成品之间来回探，任务就被来回重建（表现为 taskId
    // 抖动）。按文件名族兜一层（仅限同目录）：`日记_1.0.0.apk` 与
    // `日记_1.0.0_v8实测_成品.apk` 同族。要求短名长度 ≥4 且长名紧跟分隔符
    // （_ - . 空格），避免 app / app2 这类误判。
    if (!p.equals(p.dirname(rootA), p.dirname(rootB))) return false;
    final na = p.basenameWithoutExtension(rootA).toLowerCase();
    final nb = p.basenameWithoutExtension(rootB).toLowerCase();
    if (na.isEmpty || nb.isEmpty) return false;
    final short = na.length <= nb.length ? na : nb;
    final long = na.length <= nb.length ? nb : na;
    if (short.length < 4 || !long.startsWith(short)) return false;
    if (long.length == short.length) return true;
    final next = long.substring(short.length, short.length + 1);
    return const <String>['_', '-', '.', ' '].contains(next);
  }

  /// 相对路径按工作目录解析；空串原样返回。
  static Future<String> absoluteArtifactPath(String path) async {
    final v = path.trim();
    if (v.isEmpty) return '';
    final normalized = p.normalize(v);
    if (p.isAbsolute(normalized)) return normalized;
    final dir = await workDir();
    if (dir == null || dir.isEmpty) return normalized;
    return p.normalize(p.join(dir, normalized));
  }

  static Future<String?> _resolveOriginalPath({
    required List<Map<String, dynamic>> builds,
    required Map<String, dynamic> finalBuild,
    required String finalPath,
    required String workDir,
  }) async {
    final candidates = <String>[];
    // rootSource 是台账契约里的「原包」指针：recordPatchArtifact /
    // recordSignedBuild 一路继承（首条记录就是用户导入的原包）。名字启发式
    // （isGeneratedArtifactName）只能在没有血缘证据时兜底，不能反过来否掉
    // 台账已经声明的原包——用户导入的原包本来就常叫 xxx_v1.apk /
    // xxx_signed.apk，按名排除会让清理整场放弃（original_apk_missing）。
    final rootBacked = <String>{};
    void add(Object? value, {bool root = false}) {
      final path = value?.toString().trim() ?? '';
      if (path.isEmpty) return;
      if (!candidates.contains(path)) candidates.add(path);
      if (root) rootBacked.add(path);
    }

    add(finalBuild['rootSource'], root: true);
    add(finalBuild['source']);
    add(finalBuild['input']);
    var cursor = (finalBuild['input'] ?? finalBuild['source'] ?? '').toString();
    final visited = <String>{};
    while (cursor.isNotEmpty && visited.add(cursor)) {
      final parent = builds.cast<Map<String, dynamic>?>().firstWhere(
        (build) => build?['output'] == cursor,
        orElse: () => null,
      );
      if (parent == null) break;
      add(parent['rootSource'], root: true);
      add(parent['source']);
      add(parent['input']);
      cursor = (parent['input'] ?? parent['source'] ?? '').toString();
    }
    final normalizedFinal = p.normalize(p.absolute(finalPath));
    final indexedOutputs = {
      for (final build in builds)
        p.normalize(p.absolute((build['output'] ?? '').toString())),
    };
    bool generatedName(String path) =>
        isGeneratedArtifactName(p.basename(path));
    for (final candidate in candidates) {
      final normalized = p.normalize(p.absolute(candidate));
      if (normalized != normalizedFinal &&
          p.isWithin(p.normalize(p.absolute(workDir)), normalized) &&
          !indexedOutputs.contains(normalized) &&
          // 血缘已证明是原包的名字长什么样都认；没有 rootSource 证据的候选
          // （可能是已被剪台账的中间包）仍按生成型命名排除。
          (!generatedName(candidate) || rootBacked.contains(candidate)) &&
          await File(candidate).exists()) {
        return candidate;
      }
    }

    String baseStem(String path) => p
        .basenameWithoutExtension(path)
        .replaceFirst(
          RegExp(
            r'(_v\d+|_signed|_structural|_dexpatch|_manifest|_assets|_abi)+$',
            caseSensitive: false,
          ),
          '',
        );
    final finalStem = baseStem(finalPath);
    final root = Directory(workDir);
    await for (final entity in root.list().handleError((_) {})) {
      if (entity is! File || !entity.path.toLowerCase().endsWith('.apk')) {
        continue;
      }
      if (p.normalize(p.absolute(entity.path)) == normalizedFinal) continue;
      if (baseStem(entity.path) == finalStem &&
          p.basenameWithoutExtension(entity.path) == finalStem) {
        return entity.path;
      }
    }
    return null;
  }

  static Future<void> recordFileArtifact({
    required String path,
    required String operation,
    String? source,
    Map<String, dynamic>? metadata,
  }) async {
    if (path.isEmpty) return;
    final artifacts = await readFileArtifacts();
    artifacts.removeWhere((entry) => entry['path'] == path);
    artifacts.insert(0, {
      'path': path,
      'operation': operation,
      if (source != null && source.isNotEmpty) 'source': source,
      if (metadata != null && metadata.isNotEmpty)
        'metadata': Map<String, dynamic>.from(metadata),
      'timestamp': DateTime.now().millisecondsSinceEpoch,
    });
    if (artifacts.length > 100) artifacts.removeRange(100, artifacts.length);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      _scopedKey(_fileArtifactsKey),
      jsonEncode([
        for (final item in artifacts)
          Map<String, dynamic>.from(item)
            ..remove('exists')
            ..remove('type')
            ..remove('size'),
      ]),
    );
  }

  static Future<List<Map<String, dynamic>>> readFileArtifacts() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_scopedKey(_fileArtifactsKey));
    if (raw == null || raw.isEmpty) return <Map<String, dynamic>>[];
    try {
      final decoded = jsonDecode(raw) as List;
      final result = <Map<String, dynamic>>[];
      final workDirRoot = await workDir();
      for (final value in decoded.whereType<Map>()) {
        final item = Map<String, dynamic>.from(value);
        var path = item['path']?.toString() ?? '';
        // 相对路径按**工作目录**解析（2026-10-03 报告 F-13：存相对路径时
        // 曾相对进程 CWD 判定 → 永远 missing）。
        if (path.isNotEmpty && !p.isAbsolute(path)) {
          final root = workDirRoot;
          if (root != null) path = p.normalize(p.join(root, path));
        }
        if (path.isNotEmpty) item['resolvedPath'] = path;
        final type = path.isEmpty
            ? FileSystemEntityType.notFound
            : await FileSystemEntity.type(path);
        item['exists'] = type != FileSystemEntityType.notFound;
        item['type'] = type == FileSystemEntityType.directory
            ? 'directory'
            : type == FileSystemEntityType.file
            ? 'file'
            : 'missing';
        if (type == FileSystemEntityType.file) {
          try {
            item['size'] = await File(path).length();
          } catch (_) {}
        }
        result.add(item);
      }
      return result;
    } catch (_) {
      return <Map<String, dynamic>>[];
    }
  }

  /// 保存当前会话最近的关键工具结果。打断或进程重启后,下一轮可直接恢复
  /// 已完成步骤,不依赖模型是否还能看到被截断的工具卡片。
  static Future<void> recordToolCheckpoint({
    required String tool,
    required Map<String, dynamic> arguments,
    required String result,
  }) async {
    final scope = currentScopeId;
    if (scope == null || tool.isEmpty || result.isEmpty) return;
    Map<String, dynamic> payload;
    try {
      final decoded = jsonDecode(result);
      if (decoded is! Map) return;
      payload = Map<String, dynamic>.from(decoded);
    } catch (_) {
      return;
    }
    // 记录服务端实际收到的全部参数（逐值压缩），不再按白名单裁剪：
    // 剪裁后的 {} 会把「agent 没传参」和「传输层丢参」混为一谈。
    // 大字符串仍截断，敏感字段由各工具自身避免放入参数。
    const resultKeys = <String>{
      'ok',
      'error',
      'message',
      'action',
      'status',
      'stage',
      'stageLabel',
      'jobId',
      'workspaceId',
      'outputPath',
      'outputApk',
      'nextInputPath',
      'sourceEntry',
      'qualifiedId',
      'target',
      'resolution',
      'strictMatch',
      'returned',
      'total',
      'results',
      'nextActions',
      'modifiedLocators',
      'pendingChanges',
      'appliedAfterPreview',
      'taskId',
    };
    final selectedArguments = <String, dynamic>{
      for (final entry in arguments.entries.take(24))
        entry.key: _compactCheckpointValue(entry.value),
    };
    final selectedResult = <String, dynamic>{
      for (final entry in payload.entries)
        if (resultKeys.contains(entry.key))
          entry.key: _compactCheckpointValue(entry.value),
    };
    final active = await activeApkPath();
    final checkpoint = <String, dynamic>{
      'tool': tool,
      'arguments': selectedArguments,
      'result': selectedResult,
      if (active != null && active.isNotEmpty) 'activeApk': active,
      'timestamp': DateTime.now().millisecondsSinceEpoch,
    };
    final prefs = await SharedPreferences.getInstance();
    final key = _scopedKey(_taskCheckpointsKey);
    final checkpoints = <Map<String, dynamic>>[];
    try {
      final decoded = jsonDecode(prefs.getString(key) ?? '[]') as List;
      checkpoints.addAll([
        for (final item in decoded)
          if (item is Map) Map<String, dynamic>.from(item),
      ]);
    } catch (_) {}
    String signature(Map<String, dynamic> item) {
      final args = item['arguments'] is Map
          ? Map<String, dynamic>.from(item['arguments'] as Map)
          : const <String, dynamic>{};
      return '${item['tool']}|${args['action']}|${args['blutterAction']}|'
          '${args['jobId']}|${args['qualifiedId']}|${args['target']}';
    }

    final checkpointSignature = signature(checkpoint);
    checkpoints.removeWhere((item) => signature(item) == checkpointSignature);
    checkpoints.insert(0, checkpoint);
    if (checkpoints.length > 16) {
      checkpoints.removeRange(16, checkpoints.length);
    }
    await prefs.setString(key, jsonEncode(checkpoints));
  }

  static Object? _compactCheckpointValue(Object? value, [int depth = 0]) {
    if (value == null || value is num || value is bool) return value;
    if (value is String) {
      return value.length <= 800 ? value : '${value.substring(0, 800)}…';
    }
    if (depth >= 3) return value.toString();
    if (value is List) {
      return [
        for (final item in value.take(8))
          _compactCheckpointValue(item, depth + 1),
      ];
    }
    if (value is Map) {
      final entries = value.entries.take(24);
      return <String, dynamic>{
        for (final entry in entries)
          entry.key.toString(): _compactCheckpointValue(entry.value, depth + 1),
      };
    }
    return value.toString();
  }

  static Future<List<Map<String, dynamic>>> readToolCheckpoints() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_scopedKey(_taskCheckpointsKey));
    if (raw == null || raw.isEmpty) return const <Map<String, dynamic>>[];
    try {
      final decoded = jsonDecode(raw) as List;
      return [
        for (final item in decoded)
          if (item is Map) Map<String, dynamic>.from(item),
      ];
    } catch (_) {
      return const <Map<String, dynamic>>[];
    }
  }

  /// 当前会话的轻量续接快照。若 active 丢失,从本会话现存产物索引恢复,
  /// 不读取全局或其他会话状态。
  static Future<Map<String, dynamic>> taskResumeState() async {
    var active = await activeApkPath();
    final builds = await readBuilds();
    if (active == null || !await File(active).exists()) {
      // 兜底只接管本作用域登记的链（台账全局共享后按 scope 戳过滤，
      // legacy 条目来源不明一律不接管）——新会话保持干净启动。
      final ownScope = currentScopeId ?? 'global';
      active = builds
          .where((build) => build['exists'] == true)
          .where((build) => (build['scope'] ?? 'legacy') == ownScope)
          .map((build) => build['output']?.toString() ?? '')
          .firstWhere((path) => path.isNotEmpty, orElse: () => '');
      if (active.isEmpty) active = null;
      if (active != null) await setActiveApkPath(active);
    }
    final activeBuild = active == null
        ? null
        : builds.cast<Map<String, dynamic>?>().firstWhere(
            (build) => build?['output'] == active,
            orElse: () => null,
          );
    // 经验自动浮现（2026-09-05）：apk_patch 类记忆不在通用记忆注入白名单，
    // 库里有已验证经验时 Agent 上下文零信号——由 main() 装钩子读当前报告
    // 指纹并 peek（ApkPatchMemoryService.peekVerifiedExperience）。
    // 浮现是增强不是依赖：钩子未装/抛错/无命中都不影响其余键。
    Map<String, dynamic>? verifiedExperience;
    final peek = verifiedExperiencePeek;
    if (peek != null) {
      try {
        verifiedExperience = await peek();
      } catch (_) {}
    }
    final files = await readFileArtifacts();
    final latestSo = files.cast<Map<String, dynamic>?>().firstWhere(
      (item) => item?['operation'] == 'so_build' && item?['exists'] == true,
      orElse: () => null,
    );
    final checkpoints = await readToolCheckpoints();
    return <String, dynamic>{
      'scope': currentScopeId ?? 'global',
      'activeApk': active,
      'activeApkExists': active != null && await File(active).exists(),
      if (verifiedExperience != null) 'verifiedExperience': verifiedExperience,
      if (activeBuild != null)
        'activeArtifact': {
          for (final key in const [
            'output',
            'input',
            'source',
            'rootSource',
            'kind',
            'operation',
            'signed',
            'pendingChanges',
            'pendingMemoryStatus',
            'verification',
          ])
            if (activeBuild[key] != null) key: activeBuild[key],
        },
      if (latestSo != null)
        'latestSoArtifact': {
          'path': latestSo['path'],
          'source': latestSo['source'],
          if (latestSo['metadata'] != null) 'metadata': latestSo['metadata'],
        },
      'recentToolCheckpoints': checkpoints.take(8).toList(growable: false),
      'hasResumableState':
          active != null || activeBuild != null || checkpoints.isNotEmpty,
    };
  }

  static Future<Map<String, int>> countMissingArtifacts() async {
    final builds = await readBuilds();
    final files = await readFileArtifacts();
    return <String, int>{
      'builds': builds.where((item) => item['exists'] != true).length,
      'files': files.where((item) => item['exists'] != true).length,
    };
  }

  /// 剪掉产物索引里文件已不存在的陈账。[protectPaths] 中的输出路径一律
  /// 保留——刚登记的产物可能尚未真正落盘（签名/构建回调时序、测试 mock），
  /// 立即剪会误杀有效记录（apk_sign 回归实测）。
  static Future<Map<String, int>> pruneMissingArtifacts({
    Set<String> protectPaths = const <String>{},
  }) => _withBuildsLock(
    () => _pruneMissingArtifactsLocked(protectPaths: protectPaths),
  );

  static Future<Map<String, int>> _pruneMissingArtifactsLocked({
    Set<String> protectPaths = const <String>{},
  }) async {
    final protected_ = {
      for (final path in protectPaths) p.normalize(p.absolute(path)),
    };
    final builds = await readBuilds();
    final keptBuilds = builds
        .where(
          (item) =>
              item['exists'] == true ||
              item['keep'] == true ||
              protected_.contains(
                p.normalize(p.absolute((item['output'] ?? '').toString())),
              ),
        )
        .toList(growable: false);
    final files = await readFileArtifacts();
    final keptFiles = files
        .where((item) => item['exists'] == true)
        .toList(growable: false);
    await _writeBuilds(keptBuilds);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(
      _scopedKey(_fileArtifactsKey),
      jsonEncode([
        for (final item in keptFiles)
          Map<String, dynamic>.from(item)
            ..remove('exists')
            ..remove('type')
            ..remove('size'),
      ]),
    );
    return <String, int>{
      'builds': builds.length - keptBuilds.length,
      'files': files.length - keptFiles.length,
    };
  }

  static Future<void> reconcileMovedPath(
    String source,
    String target, {
    bool copy = false,
  }) => _withBuildsLock(
    () => _reconcileMovedPathLocked(source, target, copy: copy),
  );

  static Future<void> _reconcileMovedPathLocked(
    String source,
    String target, {
    bool copy = false,
  }) async {
    String rewrite(String value) {
      if (value == source) return target;
      if (p.isWithin(source, value)) {
        return p.join(target, p.relative(value, from: source));
      }
      return value;
    }

    final builds = await readBuilds();
    final additions = <Map<String, dynamic>>[];
    for (final build in builds) {
      final output = build['output']?.toString() ?? '';
      if (copy && (output == source || p.isWithin(source, output))) {
        additions.add({
          ...build,
          'output': rewrite(output),
          'input': output,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
        });
      } else if (!copy) {
        for (final key in const ['output', 'input', 'source', 'rootSource']) {
          final value = build[key]?.toString() ?? '';
          if (value.isNotEmpty) build[key] = rewrite(value);
        }
      }
    }
    if (additions.isNotEmpty) builds.insertAll(0, additions);
    await _writeBuilds(builds);
    final active = await activeApkPath();
    if (!copy && active != null) await setActiveApkPath(rewrite(active));
  }

  /// 用户实机验证登记（独立于 build 台账数组）：record_apk_patch_
  /// verification 无论完整链路还是降级链路（直改直签、无 build 记录）都
  /// 登记一条。交付报告是交付时快照不会自己更新，运行时弹层交付区靠这
  /// 份登记按成品指纹反查显示「通过 · 用户实机」（2026-09-15 用户点名
  /// 「我都说了修改有效了，为什么还没更新」）。独立 key，不污染台账数组。
  static const _kUserVerifications = 'apk_user_verifications_v1';

  /// 产物台账写锁：readBuilds → 改 → _writeBuilds 不是原子操作，两个并发
  /// recorder 会互相覆盖，后写者把前者整份数组盖掉 → 产物链条目静默丢失
  /// （违反 R3「产物链绑定以本地台账为准」）。所有写入口都从这里排队。
  ///
  /// 重入安全：锁内动作在带 [_buildsLockZoneKey] 标记的子 zone 里执行，
  /// 嵌套调用（cleanupAfterVerifiedSuccess → pruneMissingArtifacts、
  /// recordSignedBuild → _appendBuild 等）直接放行，不会自锁死；只有最外层
  /// 持有队列名额。
  static Future<void> _buildsWriteQueue = Future<void>.value();
  static final Object _buildsLockZoneKey = Object();

  static Future<T> _withBuildsLock<T>(Future<T> Function() action) {
    if (Zone.current[_buildsLockZoneKey] == true) {
      return Future<T>.sync(action);
    }
    final completer = Completer<T>();
    final run = _buildsWriteQueue.then((_) async {
      try {
        completer.complete(
          await runZoned(action, zoneValues: {_buildsLockZoneKey: true}),
        );
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    // 队列自身吞掉失败：一次写失败不能让之后的写入全部短路；调用方仍拿到
    // 本次的真实异常。
    _buildsWriteQueue = run.catchError((Object _) {});
    return completer.future;
  }

  /// 登记写串行化：读-改-写不是原子操作，两个 recorder 并发会互相覆盖丢条目。
  /// 用 future 链把写入排成一队（轻量版 runExclusive）。
  static Future<void> _verificationWriteQueue = Future<void>.value();

  static Future<void> recordUserVerification({
    required String output,
    String? sha256,
    required String outcome,
    required String summary,
    required int verifiedAt,
  }) {
    final next = _verificationWriteQueue.then((_) async {
      final prefs = await SharedPreferences.getInstance();
      final list = await readUserVerifications();
      list.add({
        'output': output,
        if (sha256 != null && sha256.isNotEmpty) 'sha256': sha256,
        'outcome': outcome,
        'summary': summary,
        'verifiedAt': verifiedAt,
      });
      // 只留最新 64 条：登记用于指纹反查，更老的历史没有反查价值。
      final trimmed =
          list.length > 64 ? list.sublist(list.length - 64) : list;
      await prefs.setString(_kUserVerifications, jsonEncode(trimmed));
    });
    // 队列自身吞掉失败：一次写失败不能让之后的登记全部短路；调用方仍拿到
    // 本次的真实异常。
    _verificationWriteQueue = next.catchError((Object _) {});
    return next;
  }

  static Future<List<Map<String, dynamic>>> readUserVerifications() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_kUserVerifications);
    if (raw == null || raw.isEmpty) return <Map<String, dynamic>>[];
    try {
      final decoded = jsonDecode(raw) as List<dynamic>;
      return [
        for (final e in decoded)
          if (e is Map) Map<String, dynamic>.from(e),
      ];
    } catch (_) {
      return <Map<String, dynamic>>[];
    }
  }

  /// 产物索引（最近产物在前，倒序）。
  ///
  /// 台账全局共享（2026-09-13 互斥双模复查）：agent 会话与 mcp-host 是
  /// 互斥的两种使用模式但共享同一工作目录的物理产物链，按会话分键会让
  /// 笔记（pendingChanges 挂在台账条目上）、验证登记、产物清单一并跨面
  /// 失明。会话隔离只保留在 activeApkPath / 文件台账 / 检查点（resume
  /// 语义）；台账条目上的 `scope` 戳仅用于 resume 兜底接管——新会话不
  /// 自动接管其他会话的工作链。
  static Future<List<Map<String, dynamic>>> readBuilds() async {
    final prefs = await SharedPreferences.getInstance();
    final storageKey = _buildsKey;
    final cached = _cachedBuilds;
    final raw = prefs.getString(storageKey);
    if (cached != null &&
        raw == _cachedBuildsRaw &&
        storageKey == _cachedBuildsStorageKey) {
      return _annotateBuilds(cached);
    }
    _cachedBuildsStorageKey = storageKey;
    _cachedBuildsRaw = raw;
    if (raw == null || raw.isEmpty) {
      final migrated = await _migrateScopedBuilds(prefs);
      if (migrated != null) return _annotateBuilds(migrated);
      _cachedBuilds = <Map<String, dynamic>>[];
      return <Map<String, dynamic>>[];
    }
    try {
      final decoded = jsonDecode(raw) as List<dynamic>;
      final decodedBuilds = [
        for (final e in decoded)
          if (e is Map) Map<String, dynamic>.from(e),
      ];
      _cachedBuilds = _deduplicateBuilds(decodedBuilds);
      if (_cachedBuilds!.length != decodedBuilds.length) {
        final normalized = jsonEncode(_cachedBuilds);
        await prefs.setString(storageKey, normalized);
        _cachedBuildsRaw = normalized;
      }
      return await _annotateBuilds(_cachedBuilds!);
    } catch (_) {
      _cachedBuilds = <Map<String, dynamic>>[];
      return <Map<String, dynamic>>[];
    }
  }

  static Future<List<Map<String, dynamic>>> _annotateBuilds(
    List<Map<String, dynamic>> builds,
  ) async {
    // 串行 stat 风暴修复（2026-09-29）：50 条台账各要探测 output / input 是否
    // 存在，原实现逐条 await，最坏 150 次串行 IO（真机产物列表首帧前可见
    // 卡顿）。改为两趟：先按去重路径集合并行探测，再同步标注——同一路径
    // （多条中间包共用 rootSource）只 stat 一次。
    final probeTargets = <String>{};
    for (final build in builds) {
      final output = build['output']?.toString() ?? '';
      if (output.isNotEmpty) probeTargets.add(output);
      final input = (build['input'] ?? build['source'] ?? '').toString();
      if (input.isNotEmpty && output != input) probeTargets.add(input);
    }
    final existsProbe = await _probeExistence(probeTargets);
    final replayTargets = <String>{};
    for (final build in builds) {
      final output = build['output']?.toString() ?? '';
      final input = (build['input'] ?? build['source'] ?? '').toString();
      if (input.isEmpty || input == output) continue;
      if (existsProbe[input] ?? false) continue;
      final rootSource = (build['rootSource'] ?? '').toString();
      final changeCount = (build['pendingChanges'] as List?)?.length ?? 0;
      if (rootSource.isNotEmpty && changeCount > 0) {
        replayTargets.add(rootSource);
      }
    }
    final rootExistsProbe = await _probeExistence(replayTargets);
    final annotated = <Map<String, dynamic>>[];
    for (final build in builds) {
      final item = Map<String, dynamic>.from(build);
      final output = item['output']?.toString() ?? '';
      final exists = existsProbe[output] ?? false;
      item['exists'] = exists;
      item['state'] = exists ? 'ready' : 'missing';
      item['eligibleAsNextInput'] =
          exists && item['modificationInputReady'] == true;
      if (exists && item['modificationInputReady'] != true) {
        // 语义澄清：eligibleAsNextInput 只表示"签名前置已就绪（可跳过
        // 签名准备）"，不是续做闸——修改工具接受显式 path，签名成品
        // 本身就能当输入。缺这个说明时 agent 会误读成"不可续做"。
        item['nextInputHint'] =
            '本产物可直接作为后续修改工具的显式 path 输入；'
            'eligibleAsNextInput 仅表示签名准备是否可跳过，不代表禁止续做。';
      }
      // 自描述标注：input/source 指向的中间包可能已被 autoClean 删除
      // （删文件即剪条目，但存活条目的 input 字段仍指向死路径——实测
      // agent 拿它当活文件去 file info 报 FILE_NOT_FOUND）。显式标记 +
      // 给出真正的重放入口（原包 + pendingChanges 补丁链）。
      final inputPath = (item['input'] ?? item['source'] ?? '').toString();
      if (inputPath.isNotEmpty && item['output'] != inputPath) {
        final inputExists = existsProbe[inputPath] ?? false;
        if (!inputExists) {
          // 2026-10-03 报告 F-14：`exists:true, state:"ready"` 与
          // `inputMissing:true` 并列曾被读成自相矛盾。按**原因**分开标注：
          // 生成型命名的输入（中间包）消失＝预期内的自动清理，用
          // `inputAutoCleaned`；其余才是异常缺失 `inputMissing`。
          final inputName = p.basename(inputPath);
          final lookedGenerated = isGeneratedArtifactName(inputName);
          final rootSource = (item['rootSource'] ?? '').toString();
          final changeCount = (item['pendingChanges'] as List?)?.length ?? 0;
          if (lookedGenerated) {
            item['inputAutoCleaned'] = true;
            item['inputMissingSince'] =
                '本条目 output 自身存在且可用（exists/state 描述的是 output）；'
                '被清理的是它的上一步输入中间包，不影响本条目的续用。';
          } else {
            item['inputMissing'] = true;
          }
          if (rootSource.isNotEmpty &&
              changeCount > 0 &&
              (rootExistsProbe[rootSource] ?? false)) {
            item['replayHint'] =
                '输入中间包已被自动清理（删文件即剪台账）。本条目的 '
                'pendingChanges（$changeCount 项）完整记录了补丁链，'
                '从 rootSource（原包）重开链即可重放；不要直接访问 input 路径。';
          }
        }
      }
      annotated.add(item);
    }
    return annotated;
  }

  /// 标注阶段允许的并发 stat 数：产物台账上限 50 条，无界并发会在低端机上
  /// 抢线程池（一次探测上百个路径），分批 12 既快又不抖。
  static const int _statProbeConcurrency = 12;

  /// 仅测试用：统计产物标注阶段实际发起的文件探测次数（去重 + 分批的回归
  /// 护栏——50 条共用同一 rootSource 的台账只应探测个位数次，而非 150 次）。
  static int debugAnnotationProbeCount = 0;

  static Future<Map<String, bool>> _probeExistence(Set<String> paths) async {
    final pending = paths.where((path) => path.isNotEmpty).toList();
    final probed = <String, bool>{};
    for (var start = 0; start < pending.length; start += _statProbeConcurrency) {
      final end = start + _statProbeConcurrency < pending.length
          ? start + _statProbeConcurrency
          : pending.length;
      final batch = pending.sublist(start, end);
      debugAnnotationProbeCount += batch.length;
      final results = await Future.wait(
        batch.map((path) async {
          try {
            return MapEntry(path, await File(path).exists());
          } catch (_) {
            // 路径非法 / 权限被拒：按「不存在」处理（条目标 missing），
            // 不让一条坏台账把整个产物列表打崩。
            return MapEntry(path, false);
          }
        }),
      );
      for (final entry in results) {
        probed[entry.key] = entry.value;
      }
    }
    return probed;
  }

  static Future<void> _appendBuild(Map<String, dynamic> entry) async {
    final builds = await readBuilds();
    builds.insert(0, entry);
    if (builds.length > 50) {
      builds.removeRange(50, builds.length);
    }
    await _writeBuilds(builds);
  }

  /// 一次性迁移：旧版按会话分键的台账（`apk_mod_build_index_v1_<scope>`）
  /// 合并进全局键后删除旧键。条目盖 `legacy` 戳——不参与任何新会话的
  /// resume 接管（不知道它属于哪个会话，宁可不接管也不接错链）。
  static Future<List<Map<String, dynamic>>?> _migrateScopedBuilds(
    SharedPreferences prefs,
  ) async {
    final prefix = '${_buildsKey}_';
    final legacyKeys =
        prefs.getKeys().where((key) => key.startsWith(prefix)).toList()..sort();
    if (legacyKeys.isEmpty) return null;
    final merged = <Map<String, dynamic>>[];
    for (final key in legacyKeys) {
      try {
        final decoded = jsonDecode(prefs.getString(key) ?? '[]') as List;
        for (final item in decoded) {
          if (item is! Map) continue;
          merged.add(
            Map<String, dynamic>.from(item)..['scope'] = 'legacy',
          );
        }
      } catch (_) {}
      await prefs.remove(key);
    }
    if (merged.isEmpty) {
      _cachedBuilds = <Map<String, dynamic>>[];
      _cachedBuildsRaw = '';
      _cachedBuildsStorageKey = _buildsKey;
      return const <Map<String, dynamic>>[];
    }
    // 全局按时间倒序去重（_deduplicateBuilds 保留首见，先排序才保得住最新版）。
    merged.sort(
      (a, b) => ((b['timestamp'] as num?)?.toInt() ?? 0).compareTo(
        (a['timestamp'] as num?)?.toInt() ?? 0,
      ),
    );
    final capped = merged.length > 50 ? merged.sublist(0, 50) : merged;
    await _writeBuilds(capped);
    return _cachedBuilds;
  }

  /// 标记/取消标记某个产物为「保留」：回收（[cleanupToBaseline] 与
  /// cleanup_apk_builds）、失效记录剪枝（[pruneMissingArtifacts]）以及 patch 链
  /// 的输入自动清理都会跳过 keep=true 的产物（`docs/Solab.md` 明文「用户明确
  /// 要求保留的文件不能被自动清理」）。
  ///
  /// [output] 可以是完整路径，也可以只给文件名（模型/用户常只记得文件名）；
  /// 匹配口径为「规范化绝对路径相等」或「basename 相等（忽略大小写）」。
  /// 返回被改写的台账条数——0 表示没有任何匹配，调用方必须据此显式告知用户，
  /// 不允许静默当成功。
  static Future<int> setBuildKeep(String output, bool keep) =>
      _withBuildsLock(() async {
        final target = output.trim();
        if (target.isEmpty) return 0;
        final normalized = p.normalize(p.absolute(target));
        final base = p.basename(target).toLowerCase();
        final builds = await readBuilds();
        var updated = 0;
        for (final b in builds) {
          final raw = (b['output'] ?? '').toString().trim();
          if (raw.isEmpty) continue;
          final hit =
              p.normalize(p.absolute(raw)) == normalized ||
              p.basename(raw).toLowerCase() == base;
          if (!hit) continue;
          if (keep) {
            if (b['keep'] == true) continue;
            b['keep'] = true;
          } else {
            if (!b.containsKey('keep')) continue;
            b.remove('keep');
          }
          updated++;
        }
        if (updated > 0) await _writeBuilds(builds);
        return updated;
      });

  /// 兼容旧名（第 48 轮前的唯一入口，当时全仓零调用者）：等价于
  /// [setBuildKeep]`(output, true)`。新代码请直接用 [setBuildKeep]，它带返回值
  /// 且支持取消保留。
  static Future<void> keepBuild(String output) async {
    await setBuildKeep(output, true);
  }

  /// 产物被外部手段删除（如 file delete）后同步冲销索引簿记：移除指向
  /// 该路径的 build 记录与文件产物记录——否则残留 exists:false 条目和
  /// 「待验证修改」草稿状态，误导后续会话（复测实测）。
  /// 返回移除的记录数。不动 activeApkPath（指向已删文件属预期状态，
  /// 下次打开源 APK 自然重置）。
  static Future<int> forgetArtifact(String path) =>
      _withBuildsLock(() => _forgetArtifactLocked(path));

  static Future<int> _forgetArtifactLocked(String path) async {
    final normalized = p.normalize(p.absolute(path));
    var removed = 0;
    final builds = await readBuilds();
    final keptBuilds = <Map<String, dynamic>>[];
    for (final b in builds) {
      final output = p.normalize(p.absolute((b['output'] ?? '').toString()));
      if (output == normalized) {
        removed++;
        continue;
      }
      keptBuilds.add(b);
    }
    // 草稿随其宿主 build 记录走：记录被删（上面 continue）则
    // pendingMemoryDraft/pendingMemoryStatus 一并消失，无需单独摘除。
    if (removed > 0 || keptBuilds.length != builds.length) {
      await _writeBuilds(keptBuilds);
    }
    final files = await readFileArtifacts();
    final keptFiles = files
        .where(
          (item) =>
              p.normalize(p.absolute((item['path'] ?? '').toString())) !=
              normalized,
        )
        .toList(growable: false);
    if (keptFiles.length != files.length) {
      removed += files.length - keptFiles.length;
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(
        _scopedKey(_fileArtifactsKey),
        jsonEncode([
          for (final item in keptFiles)
            Map<String, dynamic>.from(item)
              ..remove('exists')
              ..remove('type')
              ..remove('size'),
        ]),
      );
    }
    return removed;
  }

  static Future<void> _writeBuilds(List<Map<String, dynamic>> builds) async {
    final prefs = await SharedPreferences.getInstance();
    final storageKey = _buildsKey;
    final persisted = [
      // scope 戳统一在唯一写出口补齐：新条目记当前作用域，已有条目
      // （含迁移的 legacy）保留原戳——resume 兜底接管按它过滤。
      for (final build in _deduplicateBuilds(builds))
        Map<String, dynamic>.from(build)
          ..['scope'] ??= currentScopeId ?? 'global'
          ..remove('exists')
          ..remove('state')
          ..remove('eligibleAsNextInput')
          // 注解字段随 _annotateBuilds 每次重算，落盘前剥离防陈账。
          ..remove('nextInputHint')
          ..remove('inputMissing')
          ..remove('replayHint'),
    ];
    final raw = jsonEncode(persisted);
    await prefs.setString(storageKey, raw);
    _cachedBuildsStorageKey = storageKey;
    _cachedBuildsRaw = raw;
    _cachedBuilds = persisted;
  }

  static List<Map<String, dynamic>> _deduplicateBuilds(
    Iterable<Map<String, dynamic>> builds,
  ) {
    final outputs = <String>{};
    final unique = <Map<String, dynamic>>[];
    for (final build in builds) {
      final output = (build['output'] ?? '').toString().trim();
      final key = output.isEmpty
          ? ''
          : p.normalize(output).replaceAll('\\', '/');
      if (key.isNotEmpty && !outputs.add(key)) continue;
      unique.add(Map<String, dynamic>.from(build));
    }
    return unique;
  }

  /// 流程图②：任务收尾把工作目录恢复成干净基线。
  ///
  /// 只保留：
  /// - 最终签名成品（索引 kind=build 或 keep=true 的产物）；
  /// - 原始 APK（索引里的 source/rootSource/input，若位于工作区内）；
  /// - 当前连续修改目标 activeApkPath。
  /// 其余（解包目录、DEX/SO/Blutter 工作文件、索引/临时文件、旧中间包）
  /// 全部删除。返回被清理的路径列表。
  static Future<List<String>> cleanupToBaseline() =>
      _withBuildsLock(() => _cleanupToBaselineLocked());

  static Future<List<String>> _cleanupToBaselineLocked() async {
    final dir = await workDir();
    if (dir == null) return const <String>[];
    final d = Directory(dir);
    if (!await d.exists()) return const <String>[];

    final keep = <String>{};
    final active = await activeApkPath();
    if (active != null && active.isNotEmpty) keep.add(active);
    for (final b in await readBuilds()) {
      final out = b['output']?.toString();
      if (out != null &&
          out.isNotEmpty &&
          (b['kind'] == 'build' || b['keep'] == true)) {
        keep.add(out);
      }
      // 原始 APK（只保留工作区内的输入源文件）。
      for (final key in const ['source', 'rootSource', 'input']) {
        final src = b[key]?.toString();
        if (src != null && src.isNotEmpty && p.isWithin(dir, src)) {
          keep.add(src);
        }
      }
    }

    final deleted = <String>[];
    // 分区保护（最优方案 P3）：inbox/shared 是用户输入与跨 App 共享，
    // <App>/out 是交付件——一律不动；App 目录只清 work/report 中间产物。
    const protectedTop = {'inbox', 'shared', 'SoLab'};
    try {
      await for (final entry in d.list().handleError((_) {})) {
        final path = entry.path;
        if (keep.contains(path)) continue;
        if (entry is Directory &&
            protectedTop.contains(p.basename(path))) {
          continue;
        }
        try {
          if (entry is File) {
            await entry.delete();
          } else if (entry is Directory) {
            final hasOut = await Directory(p.join(path, 'out')).exists();
            if (hasOut) {
              for (final sub in const ['work', 'report']) {
                final sd = Directory(p.join(path, sub));
                if (await sd.exists()) {
                  await sd.delete(recursive: true);
                  deleted.add(sd.path);
                }
              }
              continue;
            }
            await entry.delete(recursive: true);
          }
          deleted.add(path);
        } catch (_) {}
      }
    } catch (_) {
      // 目录不可枚举（如未授予「所有文件访问」）时返回已清理部分。
    }
    // 恢复干净基线时同步剪索引：被删条目的记录一并冲销。
    await pruneMissingArtifacts();
    return deleted;
  }
}
