import 'local_tool_names.dart';

enum LocalToolTier { tier0, tier1, tier2, tier3 }

/// 资源占用类型（2026-09-21 自检 D1/D2 的架构定案）。
///
/// 为什么要有这个字段：lane 原先按"工具白名单"分组，**没声明 readOnly 的一律落进
/// 写 lane**——于是剪贴板挂起会锁死整条写链路、纯计算工具被连坐（D1/D2 的病灶）。
/// 现在按资源维度分类，且**新工具必须在这里声明自己占什么**：不声明就是
/// `unclassified`，会被一致性测试挡住，而不是默默挤进写 lane。
enum ToolResourceClass {
  /// 纯计算/纯本地信息：不占内存、不碰文件、不做设备 IO，不进任何互斥 lane。
  computeOnly,

  /// 设备 IO：走平台通道（剪贴板/TTS/询问用户）。超时只是"通道没回"，
  /// 没有僵尸原生命令占内存，所以只需短硬超时、不需要冷却隔离。
  deviceIo,

  /// 重内存：整包解析/分析类，需与其它重内存工具互斥。
  memoryHeavy,

  /// 文件写锁：写类工具，需与其它写操作串行。
  fileWrite,

  /// 未分类（默认）。落进写 lane —— 声明遗漏会被一致性测试发现。
  unclassified,
}

class LocalToolSpec {
  const LocalToolSpec({
    required this.name,
    required this.title,
    required this.subtitle,
    this.tiers = const <LocalToolTier>{},
    this.tracks = const <String>{},
    this.readOnly = false,
    this.marksCompletion = false,
    this.deviceGated = false,
    this.resourceClass = ToolResourceClass.unclassified,
  });

  final String name;
  final String title;
  final String subtitle;
  final Set<LocalToolTier> tiers;
  final Set<String> tracks;
  final bool readOnly;
  final bool marksCompletion;
  final bool deviceGated;

  /// 资源占用类型：lane 调度据此分流（见 [ToolResourceClass]）。
  final ToolResourceClass resourceClass;
}

abstract final class LocalToolRegistry {
  static const flutterVip = 'flutterVip';
  static const dexNative = 'dexNative';
  static const soAnalysis = 'soAnalysis';
  static const fileOps = 'fileOps';

  static const List<LocalToolSpec> specs = <LocalToolSpec>[
    LocalToolSpec(
      name: LocalToolNames.timeInfo,
      title: '时间信息',
      subtitle: '获取当前时间',
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.clipboard,
      title: '剪贴板',
      subtitle: '读取/写入剪贴板',
      resourceClass: ToolResourceClass.deviceIo,
    ),
    LocalToolSpec(
      name: LocalToolNames.textToSpeech,
      title: '朗读',
      subtitle: '用 TTS 朗读文本',
      resourceClass: ToolResourceClass.deviceIo,
    ),
    LocalToolSpec(
      name: LocalToolNames.askUser,
      title: '询问用户',
      subtitle: '向用户提问以澄清需求',
      tiers: {LocalToolTier.tier0},
      resourceClass: ToolResourceClass.deviceIo,
    ),
    LocalToolSpec(
      name: LocalToolNames.calculate,
      title: '计算器',
      subtitle: '表达式求值',
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.valueCalc,
      title: '数值计算',
      subtitle: '进制/位运算/字节序/编解码',
      // tier1：改包全过程都要用（补丁值换算、机器码解析、混淆串解码），
      // 但不该进纯聊天轮次。
      tiers: {LocalToolTier.tier1},
      readOnly: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.screenTime,
      title: '屏幕使用时长',
      subtitle: '按时间范围查询 App 使用统计',
      deviceGated: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.phoneControl,
      title: '手机控制',
      subtitle: '无障碍读屏与点击（需系统授权）',
      deviceGated: true,
      resourceClass: ToolResourceClass.deviceIo,
    ),
    LocalToolSpec(
      name: LocalToolNames.calendarQuery,
      title: '日历查询',
      subtitle: '查询设备日历事件',
      deviceGated: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.calendarCreate,
      title: '日历创建',
      subtitle: '创建日历事件（需确认）',
      deviceGated: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkReport,
      title: '读取当前 APK 报告',
      subtitle: '按需读取工作台保存的本地分析结果',
      tiers: {LocalToolTier.tier1},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkSkill,
      title: 'SoLab Skill',
      subtitle: '读取内置分析、规则审查和修改计划流程',
      tiers: {LocalToolTier.tier1},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkKnowledge,
      title: 'APK 知识',
      subtitle: '按路由主题读取已启用的知识条目',
      tiers: {LocalToolTier.tier1},
    ),
    LocalToolSpec(
      name: LocalToolNames.installedSkills,
      title: '已安装技能',
      subtitle: '读取用户安装的补充说明技能',
      tiers: {LocalToolTier.tier1},
    ),
    LocalToolSpec(
      name: LocalToolNames.agentRuntimeGuide,
      title: '运行时能力清单',
      subtitle: '确认本次启用的注入、记忆、世界书与工具',
      tiers: {LocalToolTier.tier0},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkProjectInfo,
      title: 'APK 项目信息',
      subtitle: '报告源 APK 与工作区绑定 APK 的一致性核对',
      tiers: {LocalToolTier.tier0},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkRules,
      title: '规则库',
      subtitle: '列出 APK 特征规则',
      tiers: {LocalToolTier.tier1},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkPatchDex,
      title: 'DEX 修改',
      subtitle: '方法置空/翻转/时间戳等（需预览+确认）',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkPatchDexStrings,
      title: 'DEX 字符串替换',
      subtitle: 'const-string 文案/URL 秒级替换（需预览+确认）',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkSignatureBypass,
      title: '去签名校验',
      subtitle: '独立签名兼容注入（普通/原包模式）',
      tiers: {LocalToolTier.tier2},
      // 2026-09-15：四条轨道全给——它是任何改包链的交付前置，按轨道剥掉
      // 会让「分析完再改」的会话在写回时无路可走（真机连续三轮挂不上）。
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      marksCompletion: false,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkPatchManifest,
      title: 'Manifest 修改',
      subtitle: '权限清理与组件调整（需预览+确认）',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkToolMap,
      title: '工具总表',
      subtitle: '全部本地 APK 工具的能力与触发信号',
      tiers: {LocalToolTier.tier0},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkPatchMemory,
      title: '补丁经验检索',
      subtitle: '按厂商+壳+引擎指纹匹配历史经验',
      tiers: {LocalToolTier.tier1},
      // MCP 面也暴露（只读）：真机实测发现外部 Agent 无法按文件指纹
      // 识别「已是验证成品的基线包」，导致从原始包重做。lookupArtifactPath
      // 反查走内容 sha256，MCP 调用方同样需要这个入口。
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkSavePatchMemory,
      title: '补丁经验保存',
      subtitle: '成功后沉淀一句话最小改动',
      tiers: {LocalToolTier.tier3},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkRecordPatchVerification,
      title: '验证结果登记',
      subtitle: '记录安装验证有效/无效',
      tiers: {LocalToolTier.tier3},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkListBuilds,
      title: '产物列表',
      subtitle: '列出已生成中间包',
      tiers: {LocalToolTier.tier0},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkCleanupBuilds,
      title: '产物清理',
      subtitle: '清缓存与无主中间产物（需预览+确认）',
      // tier0 常驻：与配对的 apkListBuilds 同层——无 tier 工具不进任何
      // 声明列表（冒烟实测连续 3 轮 unknown_function）。
      tiers: {LocalToolTier.tier0},
      readOnly: false,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkNoteRead,
      title: '补丁笔记读取',
      subtitle: '读取当前会话待验证修改',
      tiers: {LocalToolTier.tier1},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkNoteWrite,
      title: '补丁笔记写入',
      subtitle: '记录修改位置结论',
      tiers: {LocalToolTier.tier3},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkListWorkspace,
      title: '工作区 APK 列表',
      subtitle: '列出工作目录中的 APK',
      tiers: {LocalToolTier.tier0},
    ),
    LocalToolSpec(
      name: LocalToolNames.apkAnalyzeWorkspace,
      title: '工作区 APK 分析',
      subtitle: '自动分析并保存当前报告',
      tiers: {LocalToolTier.tier1},
    ),
    LocalToolSpec(
      name: LocalToolNames.workspacePolicy,
      title: '工作区策略',
      subtitle: '能碰哪些路径/哪些要确认',
      // tier1：任何 APK 任务起步都可能需要它（外部 agent 尤其），进纯聊天轮无意义。
      tiers: {LocalToolTier.tier1},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.runTaskCommand,
      title: 'Task Command 执行器',
      subtitle: 'B 类固定链程序化探针（FIELD_STATE_LOCATE）',
      tiers: {LocalToolTier.tier2},
      tracks: {LocalToolRegistry.dexNative},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkArchive,
      title: 'APK 文件浏览',
      subtitle: '分页浏览、预览条目和读取签名证书',
      tiers: {LocalToolTier.tier1},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkExportReport,
      title: '导出 APK 报告',
      subtitle: '将当前分析报告保存到工作目录',
      tiers: {LocalToolTier.tier1},
    ),
    LocalToolSpec(
      name: LocalToolNames.jadxDecompile,
      title: 'Jadx 反编译',
      subtitle: 'DEX→Java 源码',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkSign,
      title: 'APK 签名',
      subtitle: '内置密钥 v1/v2/v3',
      tiers: {LocalToolTier.tier2, LocalToolTier.tier3},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.apkRebuild,
      title: 'APK 回编',
      subtitle: 'APKEditor 完整回编',
      tiers: {LocalToolTier.tier2},
      tracks: {dexNative, soAnalysis, fileOps},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.dexSearch,
      title: 'Dex 反查',
      subtitle: 'DexKit 反混淆查找',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.stringScan,
      title: '字符串扫描',
      subtitle: '敏感信息',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.dexXref,
      title: 'DEX 调用图',
      subtitle: '谁调我/我调谁',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.classOutline,
      title: '类大纲',
      subtitle: '混淆类浏览',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.smaliRead,
      title: 'Smali 读取',
      subtitle: '按方法读取 smali',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.soAnalyze,
      title: 'SO 分析',
      subtitle: 'Rizin/LIEF/Unidbg 引擎',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, soAnalysis},
    ),
    LocalToolSpec(
      name: LocalToolNames.soPatchIntoApk,
      title: 'SO 回填',
      subtitle: '补丁产物一键写回 APK',
      tiers: {LocalToolTier.tier2},
      // 2026-09-15：dexNative/fileOps 轨也要有——只有 dexNative 时
      // 「写回」这一步没有任何工具可用。
      tracks: {flutterVip, soAnalysis, dexNative, fileOps},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.frida,
      title: 'Frida 动态插桩',
      subtitle: 'gadget 取件 / 注入版 APK（无 root）',
      // 注入是宿主侧能力（不需要 Linux 沙盒）；运行期驱动
      // （open/hook/call/read/backtrace）在沙盒侧，未装沙盒时明确报不可用。
      tiers: {LocalToolTier.tier2},
      tracks: {soAnalysis, dexNative},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.subagent,
      title: '子代理',
      subtitle: '派一件独立任务给子代理（调研/审核/复核）',
      // tier0（用户 2026-09-29 真机实测回归）：能力策略段按「助手配置了
      // subagent」就承诺可派发，而 tier1 只有 apk_task 轮才挂载——闲聊轮
      // 策略段与工具面脱节，模型照提示承诺派发却调不到（判据 19/25/63/65:
      // 点名的调用必须真实存在于当前工具面）。升 tier0 常驻，与
      // localToolIds 求交后只有挂了它的助手受影响。
      tiers: {LocalToolTier.tier0},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.runWorkflow,
      title: '工作流',
      subtitle: '运行一条已保存的工作流（AI 生成/HTTP/文本编排）',
      // tier0 常驻（同 subagent）：策略段点名了它就必须真实存在于工具面。
      tiers: {LocalToolTier.tier0},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      // 工作流本身不改工作区文件（节点能力另受各自限制），按只读登记；
      // 资源占用 unclassified：它可能发起网络与模型调用，交给 lane 保守调度。
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.todoWrite,
      title: '任务清单（写）',
      subtitle: '整表替换当前会话的任务清单',
      // tier0：同 subagent——/plan 的产出规格要求 todo_write 登记计划，
      // 闲聊轮不挂载就又是空头支票。
      tiers: {LocalToolTier.tier0},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.goalGet,
      title: '读目标',
      subtitle: '读回当前会话的目标与状态',
      tiers: {LocalToolTier.tier0},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.goalCreate,
      title: '建立目标',
      subtitle: '写入目标并进入目标模式（免审执行）',
      tiers: {LocalToolTier.tier0},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
    ),
    LocalToolSpec(
      name: LocalToolNames.goalUpdate,
      title: '推进目标',
      subtitle: '改目标 / 暂停 / 恢复 / 完成',
      tiers: {LocalToolTier.tier0},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      marksCompletion: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.todoRead,
      title: '任务清单（读）',
      subtitle: '读回当前会话的任务清单',
      // tier0：与 todoWrite 同进退（只读配套）。
      tiers: {LocalToolTier.tier0},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
    ),
    LocalToolSpec(
      name: LocalToolNames.file,
      title: '文件',
      subtitle: '工作目录文件操作',
      // tier0（用户 2026-09-29 真机实测回归）：/plan 的计划落点承诺「file
      // 写入 plans/ 目录」，tier2（轨道 fileOps）闲聊轮挂不上——承诺与
      // 工具面脱节。写入仍受审批/计划模式拦截约束（kMutatingToolNames
      // 已把 file 摘出变更名单，plan 模式下只读约束由 promptHint 表达）。
      tiers: {LocalToolTier.tier0},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
    ),
    LocalToolSpec(
      name: LocalToolNames.routeTask,
      title: '任务路由',
      subtitle: '工具/技能/记忆决策',
      tiers: {LocalToolTier.tier0},
      readOnly: true,
    ),
    // ---- 运行时控制面（§7.4）：查状态、问用户、读产物、看证据 ----
    LocalToolSpec(
      name: LocalToolNames.taskStatus,
      title: '任务状态',
      subtitle: '看阶段、预算余量、证据与未决冲突',
      tiers: {LocalToolTier.tier0},
      readOnly: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.taskUpdate,
      title: '推进任务状态',
      subtitle: '请求推进阶段（是否真推进由系统按进入条件判定）',
      tiers: {LocalToolTier.tier1},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.evidenceQuery,
      title: '查证据',
      subtitle: '按等级查已登记证据与来源',
      tiers: {LocalToolTier.tier0},
      readOnly: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.artifactRead,
      title: '读产物',
      subtitle: '读任务工作区里的产物文件（大文件给续读令牌）',
      tiers: {LocalToolTier.tier1},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.patchPlan,
      title: '登记修改计划',
      subtitle: '结构化计划：目标/操作/依据/预览/风险/回滚',
      tiers: {LocalToolTier.tier1},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.dryRunPatch,
      title: '修改前检查',
      subtitle: '对已登记计划做 Dry Run（不通过禁止真改）',
      tiers: {LocalToolTier.tier1},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.planProbes,
      title: '探针建议',
      subtitle: '按最缺的证据排下一步探针（含成本）',
      tiers: {LocalToolTier.tier1},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.verifyApk,
      title: '工程验证',
      subtitle: '产物可解析/SHA-256/签名/可安装性，做不到的标 NOT VERIFIED',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
      marksCompletion: true,
      resourceClass: ToolResourceClass.memoryHeavy,
    ),
    LocalToolSpec(
      name: LocalToolNames.collectDelivery,
      title: '整理交付',
      subtitle: '列成品、算哈希、汇总未验证项',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
      marksCompletion: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
    LocalToolSpec(
      name: LocalToolNames.workspaceCleanup,
      title: '清理工作区',
      subtitle: '清中间产物（保留原始 APK 与成品）',
      tiers: {LocalToolTier.tier2},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      marksCompletion: true,
      resourceClass: ToolResourceClass.fileWrite,
    ),
    LocalToolSpec(
      name: LocalToolNames.requestConfirmation,
      title: '请求用户确认',
      subtitle: '高风险/目标不明/证据冲突时进入等待确认',
      tiers: {LocalToolTier.tier1},
      tracks: {flutterVip, dexNative, soAnalysis, fileOps},
      readOnly: true,
      resourceClass: ToolResourceClass.computeOnly,
    ),
  ];

  static final Map<String, ({String title, String subtitle})> uiMetadata =
      Map<String, ({String title, String subtitle})>.unmodifiable({
        for (final spec in specs)
          spec.name: (title: spec.title, subtitle: spec.subtitle),
      });

  static Set<String> readOnlyToolIds() => Set<String>.unmodifiable(
    specs.where((spec) => spec.readOnly).map((spec) => spec.name),
  );

  /// 按资源占用类型取工具名（lane 调度据此分流，见 [ToolResourceClass]）。
  static Set<String> namesWithResourceClass(ToolResourceClass resourceClass) =>
      Set<String>.unmodifiable(
        specs
            .where((spec) => spec.resourceClass == resourceClass)
            .map((spec) => spec.name),
      );

  static Set<String> namesAtTier(LocalToolTier tier, {String? track}) =>
      Set<String>.unmodifiable(
        specs
            .where((spec) => spec.tiers.contains(tier))
            .where((spec) => track == null || spec.tracks.contains(track))
            .map((spec) => spec.name),
      );

  static Set<String> completionToolNames() => Set<String>.unmodifiable(
    specs.where((spec) => spec.marksCompletion).map((spec) => spec.name),
  );
}
