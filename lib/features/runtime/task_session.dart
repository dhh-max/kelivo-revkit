/// 会话 ↔ 任务绑定（§5.5 首任务纪律、§6.4 阶段化能力）。
///
/// 一个对话对应一个任务。绑定关系存在 SharedPreferences 里，这样
/// 重新进入同一个对话能接着原来的任务（§13.4 Session Resume）。
library;

import 'dart:convert';

import 'package:path/path.dart' as p;
import 'package:shared_preferences/shared_preferences.dart';

import 'capability_manifest.dart';
import 'models/evidence.dart';
import 'models/task.dart';
import 'models/task_event.dart';
import 'task_runtime.dart';

class TaskSession {
  TaskSession(this.runtime);

  /// 全局单例：对话流程直接用这个；测试里自行 new 一个带临时目录的。
  static final shared = TaskSession(TaskRuntime());

  /// 当前 App 只有一条对话线，固定用这个绑定键。
  static const mainScope = 'main';

  final TaskRuntime runtime;

  static const _kBindings = 'runtime_scope_task_v1';

  /// 新任务的默认授权。
  ///
  /// 改包/签名/安装对这个产品是主流程，用户发消息即视为授权本会话内的这些
  /// 操作（安装另有系统确认页兜底）；**动态类高风险与外部 MCP 默认关闭**，
  /// 要放开得显式打开对应约束位。收紧默认值只需要改这一处。
  static const defaultConstraints = TaskConstraints(
    allowModification: true,
    allowSigning: true,
    allowInstall: true,
  );

  /// 允许在所有阶段调用的控制类工具（§7.4 核心控制）。
  static const controlTools = CapabilityManifest.control;

  Future<Map<String, String>> _bindings() async {
    final p = await SharedPreferences.getInstance();
    final raw = p.getString(_kBindings);
    if (raw == null || raw.isEmpty) return {};
    try {
      final m = jsonDecode(raw);
      if (m is! Map) return {};
      return {
        for (final e in m.entries) e.key.toString(): e.value.toString(),
      };
    } catch (_) {
      return {};
    }
  }

  Future<void> _bind(String scopeKey, String taskId) async {
    final m = await _bindings();
    m[scopeKey] = taskId;
    final p = await SharedPreferences.getInstance();
    await p.setString(_kBindings, jsonEncode(m));
  }

  /// 取当前对话绑定的任务（没有或已失效则返回 null）。
  Future<Task?> taskFor(String scopeKey) async {
    final m = await _bindings();
    final id = m[scopeKey];
    if (id == null || id.isEmpty) return null;
    final t = await runtime.get(id);
    if (t == null) {
      // 绑定指向的任务已被删除：清掉脏绑定
      m.remove(scopeKey);
      final p = await SharedPreferences.getInstance();
      await p.setString(_kBindings, jsonEncode(m));
    }
    return t;
  }

  /// 最近更新的任务。
  ///
  /// 设置页里的「运行时」页签（当前任务/证据/交付/诊断）没有对话上下文，
  /// 拿不到工具执行时的作用域键；对它们来说「当前任务」就是最近在动的那条。
  /// 按作用域键查会永远查不到（键是 conversationId / workbench / mcp-host），
  /// 页面就会恒空——这正是当初四页显示不出数据的根因。
  Future<Task?> latestTask() async {
    final all = await runtime.store.list();
    return all.isEmpty ? null : all.first;
  }

  /// 当前任务解析（2026-09-14 真机反馈「记录了但页面恒空」）。
  ///
  /// 解析顺序：
  /// 1. [scopeKey] 绑定的任务（对话页传 conversationId，工作台传 workbench，
  ///    MCP host 传 mcp-host）——数据写在哪条任务上就显示哪条；
  /// 2. 全部绑定里更新时间最新的一条（设置页没带作用域时的最佳近似）；
  /// 3. 最后才回退 [latestTask]（可能是已被解绑的历史任务）。
  Future<Task?> resolveCurrentTask({String? scopeKey}) async {
    final key = (scopeKey ?? '').trim();
    if (key.isNotEmpty) {
      final bound = await taskFor(key);
      if (bound != null) return bound;
    }
    Task? best;
    for (final id in await boundTaskIds()) {
      final t = await runtime.get(id);
      if (t == null) continue;
      if (best == null || t.updatedAt > best.updatedAt) best = t;
    }
    return best ?? await latestTask();
  }

  /// 删除一条任务记录：解绑所有指向它的作用域、删工作区目录、再删任务目录
  /// （task.json + events.jsonl + 事件流）。
  ///
  /// 两条删除语义（用户点名）：
  /// - 删除会话时连带删除该会话的任务记录（main.dart 的删除钩子调用）；
  /// - 任务页的「删除这条任务」入口手动删。
  /// 删除后该任务的证据/失败记忆/图表数据一并消失——这是删除的本意。
  Future<bool> deleteTask(String taskId) async {
    final id = taskId.trim();
    if (id.isEmpty) return false;
    try {
      final m = await _bindings();
      final before = m.length;
      m.removeWhere((_, v) => v == id);
      if (m.length != before) {
        final p = await SharedPreferences.getInstance();
        await p.setString(_kBindings, jsonEncode(m));
      }
    } catch (_) {
      // 解绑失败不阻断删除本体
    }
    try {
      final ws = await runtime.workspace.workspaceDir(id);
      if (await ws.exists()) await ws.delete(recursive: true);
    } catch (_) {}
    var ok = await runtime.store.delete(id);
    if (!ok) {
      // 与后台回收/其它句柄并发时目录被占用是常态（Windows/Android 都
      // 删不掉），隔一拍重试一次——否则回收会静默留垃圾。
      try {
        final dir = await runtime.store.taskDir(id);
        if (await dir.exists()) {
          await Future<void>.delayed(const Duration(milliseconds: 150));
          ok = await runtime.store.delete(id);
        }
      } catch (_) {}
    }
    return ok;
  }

  /// 回收**未绑定**的历史任务记录（2026-09-14 真机反馈「一个 APP 几十份报告」；
  /// 2026-09-15 按用户「按会话保留」语义收紧为全量回收）。
  ///
  /// 谁会变成未绑定：换目标 APK 时旧任务被解绑、删会话连带删除钩子遗留。
  /// 未绑定 = 已没有会话在用它 = 不该再占存储；[graceMs] 内动过的绝不删
  /// （刚解绑、可能还在收尾的任务不误清）。
  /// 删除 = 任务目录（task.json / 事件流 / 交付报告镜像）+ 工作区目录一起删。
  Future<int> pruneUnboundTaskRecords({
    int? now,
    int keepRecent = 0,
    int graceMs = 60 * 60 * 1000,
  }) async {
    final ts = now ?? DateTime.now().millisecondsSinceEpoch;
    var removed = 0;
    try {
      final bound = await boundTaskIds();
      final all = await runtime.store.list(); // 按 updatedAt 倒序
      var unboundSeen = 0;
      for (final task in all) {
        if (bound.contains(task.id)) continue;
        if (ts - task.updatedAt < graceMs) continue;
        unboundSeen++;
        if (unboundSeen <= keepRecent) continue;
        if (await deleteTask(task.id)) removed++;
      }
    } catch (_) {}
    return removed;
  }

  /// 确保当前对话有任务：已有则复用，没有则新建。
  ///
  /// 复用规则（两条真机实测）：
  /// 1. **绑定 APK 变了就必须换任务**——此前无条件复用，界面上一直显示上一个
  ///    包（甚至是早已删除的旧包），与当前正在分析的 APK 对不上；
  /// 2. **同一产物链上的派生包不算换目标**（2026-09-14「一个 APP 几十份报告」）
  ///    ——工具链每走一步 activeApkPath 就前移一次（去签 → 中间包 → 成品 →
  ///    签名包），按纯路径比较会给同一个 APP 建几十条任务；[sameLifecycle]
  ///    由宿主注入（runtime_bridge 走产物索引的血缘根判定），未注入或判定
  ///    失败时退化为原来的纯路径比较。
  Future<Task?> ensureTask({
    required String scopeKey,
    required String goal,
    required String apkPath,
    String? workDir,
    TaskConstraints constraints = defaultConstraints,
    Future<bool> Function(String a, String b)? sameLifecycle,
  }) async {
    if (apkPath.trim().isEmpty) return null;
    final existing = await taskFor(scopeKey);
    if (existing != null) {
      final sameTarget = _sameApk(existing.contract.inputApk, apkPath) ||
          await _sameLifecycleSafely(
            sameLifecycle,
            existing.contract.inputApk,
            apkPath,
          );
      if (sameTarget) {
        // 已存在的任务要把「外部 MCP 授权」同步过来。
        //
        // 坑在这里：用户往往是先设工作目录、发一条消息（任务已创建），
        // 之后才去配 MCP。如果只在建任务时读一次开关，那之后 MCP 工具
        // 全都会被权限门控拒掉——功能明明做了却用不了。MCP 总开关就是
        // 用户的显式授权，这里保持任务记录与它一致。
        if (existing.contract.constraints.allowExternalMcp !=
            constraints.allowExternalMcp) {
          final updated = existing.copyWith(
            contract: existing.contract.copyWith(
              constraints: existing.contract.constraints
                  .copyWith(allowExternalMcp: constraints.allowExternalMcp),
            ),
            updatedAt: DateTime.now().millisecondsSinceEpoch,
          );
          await runtime.store.save(updated);
          return updated;
        }
        return existing;
      }
    }
    // 换了目标 APK（或旧任务指向的包已不存在）：解绑重建，旧任务留在
    // 存储里可查，但当前作用域指向新任务。未绑定的历史任务由
    // [pruneUnboundTaskRecords] 兜底回收（不会再无限攒）。
    if (existing != null) await unbind(scopeKey);

    final task = await runtime.createTask(
      goal: goal,
      inputApk: apkPath,
      title: workDir == null ? null : goal,
      constraints: constraints,
      // v9-N2（v12 复测）：换目标重建时记下被顶替的任务与原因——同一作用域
      // 先后出现两个 taskId 时，task_status 能直接给出 replacesTaskId。
      replacesTaskId: existing?.id ?? '',
      replaceReason: existing == null ? '' : 'target_switched',
    );
    await _bind(scopeKey, task.id);

    // 报告 2-8：重建任务本是「换了目标产物」，但任务状态机的进入条件要求
    // **本任务**有 `analyze*` 事件。真机实测里 analyze 跑过了、结论也在，只是记在
    // 旧任务上——于是新任务上 `task_update(analyzed)` 被拒，链路卡死。
    // 正确做法不是放松闸门（那会让没分析过的任务也能推进），而是把同一产物链的
    // 分析**事实**随迁进来，并留下 provenance（carriedFrom / carried）。
    if (existing != null) {
      await _carryAnalysisEvidence(from: existing, to: task);
    }
    // 新建任务 = prepare() 刚复制了一份全量 APK 进工作区（体积大头）。
    // 顺手回收无主工作区与超量的历史任务记录：换包/新会话频率低，
    // 此处扫描成本可接受；绑定者（含刚绑的）永远保留。
    _pruneOrphanWorkspacesSoon();
    return task;
  }

  /// 把 [from] 上已完成的基础分析事实随迁到 [to]（报告 2-8）。
  ///
  /// 只在旧任务**确实跑过** `analyze*` 工具时随迁，且事件里写明来源任务与原因——
  /// 状态机的「有依据才推进」没有被放松，只是让依据跟着产物链走。
  Future<void> _carryAnalysisEvidence({
    required Task from,
    required Task to,
  }) async {
    if (from.id == to.id) return;
    List<TaskEvent> events;
    try {
      events = await runtime.store.loadEvents(from.id);
    } catch (_) {
      return;
    }
    final analyzed = events.where(
      (e) =>
          e.type == TaskEventType.toolCalled &&
          _isAnalysisTool(e.payload['tool']?.toString() ?? ''),
    );
    if (analyzed.isEmpty) return;
    final tool =
        analyzed.last.payload['tool']?.toString() ?? 'analyze_apk_workspace';
    try {
      await runtime.store.appendEvent(
        TaskEvent(
          id: 'evt_carry_${DateTime.now().microsecondsSinceEpoch}',
          taskId: to.id,
          type: TaskEventType.toolCalled,
          phase: to.phase.id,
          payload: <String, Object?>{
            'tool': tool,
            'carried': true,
            'carriedFrom': from.id,
            'carriedReason':
                '目标产物变更导致任务重建；同一产物链上的基础分析结论沿用，'
                '分析事件随之迁移。',
            'carriedEvidenceCount': analyzed.length,
          },
          createdAt: DateTime.now().millisecondsSinceEpoch,
        ),
      );
    } catch (_) {
      // 随迁失败不影响建任务主流程；新任务仍可重新跑一次 analyze。
    }
    // v8-D12（2026-10-05 真机）：**证据记录也要随迁**。过去只迁分析事件，
    // evidence.json 留在旧任务——目标重建后 evidence_query / task_status
    // .evidenceCount 恒为 0，而工具回执里的 ev_* 仍引用旧任务记录，查无实处
    // （审计实测：多个工具稳定回 evidenceIds，evidence_query 三次全 0）。
    // 这里把旧任务的证据在新任务下重建（保留原 id：回执里的 ev_* 从此可查），
    // 并在 rawRef 里标注来源任务，血缘可溯。
    try {
      final oldEvidence = await runtime.evidence.load(from.id);
      if (oldEvidence.isNotEmpty) {
        final existing = <String>{
          for (final e in await runtime.evidence.load(to.id)) e.id,
        };
        for (final e in oldEvidence) {
          if (existing.contains(e.id)) continue;
          await runtime.evidence.add(
            Evidence(
              id: e.id,
              taskId: to.id,
              type: e.type,
              level: e.level,
              claim: e.claim,
              source: e.source,
              rawRef: <String, Object?>{
                ...e.rawRef,
                'carriedFrom': from.id,
                'carriedReason': '目标产物变更导致任务重建；证据随产物链迁移。',
              },
              relations: e.relations,
              toolCallId: e.toolCallId,
              resolved: e.resolved,
              createdAt: e.createdAt,
            ),
          );
        }
      }
    } catch (_) {
      // 随迁失败不影响建任务主流程；证据仍可在旧任务内查到。
    }
  }

  /// `analyze_apk_workspace` / `apk_analyze` / `so_analyze` 等都算基础分析。
  static bool _isAnalysisTool(String tool) {
    final name = tool.trim().toLowerCase();
    if (name.isEmpty) return false;
    return name.startsWith('analyze') || name == 'so_analyze';
  }

  /// 血缘回调是宿主注入的增强面：未注入或抛异常时退化为「按路径比较」。
  Future<bool> _sameLifecycleSafely(
    Future<bool> Function(String a, String b)? probe,
    String a,
    String b,
  ) async {
    if (probe == null) return false;
    try {
      return await probe(a, b);
    } catch (_) {
      return false;
    }
  }

  /// 全部作用域当前绑定的任务 id 集合（回收无主工作区用）。
  Future<Set<String>> boundTaskIds() async =>
      (await _bindings()).values.where((id) => id.isNotEmpty).toSet();

  bool _pruneScheduled = false;

  /// 后台 GC 是否启用。
  ///
  /// 生产必须为 true（体积治理）。测试里 `ensureTask` 会触发一个
  /// fire-and-forget 的 `pruneGarbageOnce()`，它用**默认参数**扫同一批
  /// 未绑定记录——若测试自己也在造未绑定记录并断言精确条数，后台 GC
  /// 会在不确定性时刻抢先删掉其中的一部分，测试变成"看运气"。
  /// （实测：`runtime_lifecycle_regression_test` 的未绑定回收用例
  /// 单跑该用例必过、跑完整文件时而 removed=1 时而 =2。）
  static bool backgroundPruneEnabled = true;

  /// 回收只做一次（进程内），失败静默——体积治理不得影响任务创建主流程。
  void _pruneOrphanWorkspacesSoon() {
    if (!backgroundPruneEnabled) return;
    if (_pruneScheduled) return;
    _pruneScheduled = true;
    Future<void>(() async {
      try {
        await pruneGarbageOnce();
      } finally {
        _pruneScheduled = false;
      }
    });
  }

  static bool _pruneRunning = false;

  /// 一次完整的垃圾回收：无主工作区 + 超量的历史任务记录。
  ///
  /// 串行化（2026-09-14）：启动回收与「新建任务顺带回收」可能同时触发，
  /// 两个清理扫同一批目录会互相把对方的 delete 搞失败（目录被占用即删不掉），
  /// 结果是回收静默留垃圾。同一时刻只允许一个清理在跑。
  /// 返回删除的任务记录条数。
  Future<int> pruneGarbageOnce() async {
    if (_pruneRunning) return 0;
    _pruneRunning = true;
    try {
      final bound = await boundTaskIds();
      await runtime.workspace.pruneOrphanWorkspaces(
        boundTaskIds: bound,
        now: DateTime.now().millisecondsSinceEpoch,
      );
      return await pruneUnboundTaskRecords();
    } catch (_) {
      return 0;
    } finally {
      _pruneRunning = false;
    }
  }

  /// 两个路径是否指向同一个文件（归一化比较，避免相对/绝对写法差异误判）。
  static bool _sameApk(String a, String b) {
    final x = a.trim();
    final y = b.trim();
    if (x.isEmpty || y.isEmpty) return false;
    return p.normalize(p.absolute(x)) == p.normalize(p.absolute(y));
  }

  /// 解绑（用户开新任务时用）。
  Future<void> unbind(String scopeKey) async {
    final m = await _bindings();
    m.remove(scopeKey);
    final p = await SharedPreferences.getInstance();
    await p.setString(_kBindings, jsonEncode(m));
  }

  /// 当前阶段该暴露给模型的工具（§6.4）。
  ///
  /// 控制类工具在所有阶段都在——模型要能查状态、问用户、读产物。
  Future<Set<String>> allowedTools(Task task) async {
    return {
      ...CapabilityManifest.forPhase(task.phase),
      ...controlTools,
    };
  }

  /// 工具执行后的状态推进。
  ///
  /// 只做**守卫允许**的推进：守卫不通过就静静地不推进，由工具本身
  /// 把原因回给模型（例如「还没有 Observed 证据」）。
  Future<void> noteToolOutcome({
    required Task task,
    required String tool,
    required bool ok,
  }) async {
    if (!ok) return;
    final target = advanceTargetFor(tool);
    if (target == null) return;
    try {
      await runtime.advance(task.id, target, reason: '$tool 执行成功');
    } on AdvanceRejection {
      // 守卫不通过：不是错误，只是还没到那一步
    } catch (_) {
      // 状态推进失败不能影响工具结果本身
    }
  }

  /// 工具成功后会推进到的状态；null 表示这一步不足以证明任何推进。
  ///
  /// **工具名必须是 kelivo 工作台的真实发布名**——这里曾写成 solab-app 的
  /// `analyze_apk` / `sign_apk` / `install_apk`，在工作台里永远匹配不上，
  /// 等于整段状态推进是死代码。工作台与运行时的工具名归一都收敛到这一处，
  /// 避免两套映射各自漂移。
  /// 只列「一次工具调用就足以证明」的推进；需要多步证据的（Planned、
  /// DryRunVerified）由 Runtime 的进入条件把关，这里只发起尝试。
  static TaskStatus? advanceTargetFor(String tool) {
    if (_analyzeTools.contains(tool)) return TaskStatus.analyzed;
    if (_locatingTools.contains(tool)) return TaskStatus.located;
    if (_modifyTools.contains(tool)) return TaskStatus.modified;
    if (tool == 'apk_rebuild') return TaskStatus.built;
    if (tool == 'apk_sign') return TaskStatus.signed;
    return null;
  }

  /// 工具**执行期间**进度条乐观点亮的档位（五档：0 分析/1 证据/2 修改/
  /// 3 预览/4 成品）；-1 = 不抢灯（读类/纯预演保持事实档）。
  ///
  /// 2026-09-15 真机反馈「修改的时候没有跳到相应档位」：此前进度只在工具
  /// 收尾、revision 刷新后才动——修改工具跑着的几十秒里灯纹丝不动。现在
  /// 修改一发起灯就先跳到「修改」档（乐观推进）；工具失败/被拒后 revision
  /// 刷新回事实档，不造假。
  ///
  /// **判定必须看 args**（2026-09-15 复核）：写类工具跑纯 `dryRun` 预演时
  /// 不落地、收尾后事实档回到「证据」——若这里只看工具名，灯会先跳「修改」
  /// 再跌回去。判定收敛到 [isLandedWrite]：真写才抢灯。
  static int executingStageFor(
    String tool, [
    Map<String, dynamic> args = const {},
  ]) {
    if (tool == 'apk_sign') return 4;
    if (tool == 'apk_rebuild') return 2;
    if (isLandedWrite(tool, args)) return 2;
    return -1;
  }

  /// 是否改包类工具（能落地一次修改）。
  static bool isModifyTool(String tool) => _modifyTools.contains(tool);

  /// 是否会产生「已落地修改」的写动作（决定是否登记 Patch Plan，§14.1）。
  ///
  /// 与 [_modifyTools] 分开：后者是状态机用的 5 个专用写工具（推进到 Modified），
  /// 这里是**真实写入面**——2026-09-14 之前只认那 5 个工具，于是
  /// so_analyze 的 edit_hex/edit_asm/edit_symbol/build、file 写解码目录、
  /// apk_rebuild、产出 APK 的任意命令**在预览页永远看不到**（真机反馈）。
  ///
  /// 纯 dryRun（预演）不算落地；dryRun+applyAfterPreview 一次完成算落地。
  ///
  /// `apk_archive` **不是写面**（2026-09-15 复核修正）：它的四个动作
  /// list/read/strings/certificates 全是只读浏览，此前被无条件当成写，
  /// 于是每调一次「浏览 APK」就多一条假改动——进度条跳到「预览」、
  /// 预览分区凭空多出条目，档位和内容两头失真。
  static bool isLandedWrite(
    String tool,
    Map<String, dynamic> args, {
    Map<String, Object?> data = const {},
  }) {
    final previewOnly =
        args['dryRun'] == true && args['applyAfterPreview'] != true;
    if (_modifyTools.contains(tool)) return !previewOnly;
    switch (tool) {
      case 'so_analyze':
        return const {'edit_hex', 'edit_asm', 'edit_symbol', 'build'}
                .contains(args['action']?.toString()) &&
            !previewOnly;
      case 'file':
        // 与服务端 handler 的 dryRun 缺省语义严格对齐（2026-09-14 审核修复）：
        // - write/delete/copy/rename/zip/unzip 服务端缺省 dryRun=true（纯预演，
        //   不落盘），只有显式 dryRun=false 才算真实写入；
        // - replace（grep 的写模式）服务端缺省直接执行，显式 dryRun=true 才是
        //   预演。
        // 预演登记成「已落地修改」会在预览页造假数据；真实写入漏登记则是
        // 有数据没 UI——两边都算数据失真。
        final fileAction = args['action']?.toString();
        switch (fileAction) {
          case 'write':
          case 'delete':
          case 'copy':
          case 'rename':
          case 'move':
          case 'zip':
          case 'unzip':
            return args['dryRun'] == false;
          case 'replace':
            return args['dryRun'] != true;
          default:
            // mkdir 这类目录辅助动作不算「改了什么内容」——它确实落盘，
            // 但改的是目录结构，不是 APK 内容；登记进预览只会变成噪声
            // （这个判定是既有约定，别顺手扩）。
            return false;
        }
      case 'apk_rebuild':
        return true;
      case 'run_task_command':
        // 任意命令只有真的报出产物路径才算修改，避免把只读命令刷成计划。
        return _outputPathOf(data).isNotEmpty;
      default:
        return false;
    }
  }

  /// 结果里的产物路径（按可信度取第一个非空）。
  static String _outputPathOf(Map<String, Object?> data) {
    for (final key in const ['outputPath', 'outputApk', 'signedPath']) {
      final v = (data[key] ?? '').toString().trim();
      if (v.isNotEmpty) return v;
    }
    return '';
  }

  /// 能产生「真实关系」证据的定位类工具（§11.3 Observed 的定义）。
  ///
  /// 工具名两种拼写都要列：运行层拿到的是 **analyzer 内部名**（点号形式，
  /// 工作台分派前已把发布名归一），而声明面/提示词里出现的是发布名
  /// （analyzer_find_field_usage）。2026-09-15 复核：此前只列发布名，
  /// 而主力路径走的正是内部名 → `advanceTargetFor` 恒不命中，任务状态
  /// 卡在「已分析」，弹层里的状态描述一直不跟着走。
  static const _locatingTools = <String>{
    'dex_xref',
    'field_xref',
    'smali_read',
    'jadx_decompile',
    'so_analyze',
    'analyzer.find_field_usage',
    'analyzer_find_field_usage',
  };

  static const _analyzeTools = <String>{
    'analyze_apk_workspace',
    'analyze_apk',
  };

  static const _modifyTools = <String>{
    'patch_apk_dex_methods',
    'patch_apk_dex_strings',
    'patch_apk_manifest',
    'signature_bypass',
    'so_patch_into_apk',
  };
}
