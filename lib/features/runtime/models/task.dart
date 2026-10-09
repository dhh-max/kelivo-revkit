/// 任务状态机与任务契约（对应设计文档 §6.3 / §13）。
///
/// 设计要点：
/// - 状态只能由 Runtime 或验证器推进，模型不能直接改（§13.4）。
/// - 主链路是线性的，一次只能走一格；异常态可从任意非终态进入。
/// - 状态推进必须有事件依据（见 TaskRuntime.advance）。
library;

/// 任务主状态（§13.1 状态流转）。
///
/// 线性链路：created → prepared → analyzed → located → planned →
/// dryRunVerified → modified → built → signed → verified → delivered。
/// 其余为异常态，不参与线性推进。
enum TaskStatus {
  created('Created', '任务已创建'),
  prepared('Prepared', '输入 APK 身份确认，工作区建立'),
  analyzed('Analyzed', '基础结构分析完成，产物可用'),
  located('Located', '存在与目标相关的证据链'),
  planned('Planned', '修改目标、范围和风险明确'),
  dryRunVerified('DryRunVerified', '修改可预览，目标区域正确'),
  modified('Modified', '修改已写入工作副本'),
  built('Built', 'APK 构建成功'),
  signed('Signed', '签名成功，签名信息可读取'),
  verified('Verified', '安装性和关键验证完成'),
  delivered('Delivered', '成品和报告已交付'),

  // 异常态（§13.3）
  paused('Paused', '任务暂停，可恢复'),
  waitingConfirmation('WaitingConfirmation', '等待用户确认'),
  failedRecoverable('FailedRecoverable', '失败可恢复'),
  failedTerminal('FailedTerminal', '失败不可恢复');

  const TaskStatus(this.label, this.description);

  /// 英文名，落库与日志用。**不要直接显示给用户**——界面上曾出现
  /// Analyzed / DryRunVerified 这类英文。
  final String label;

  /// 中文说明，UI 用。
  final String description;

  /// 界面显示用的中文状态名。
  ///
  /// 与 [label] 分开：label 是持久化契约（改了旧任务记录会读不回来），
  /// 这里只做展示映射，措辞可随时调整。
  String get displayName => switch (this) {
        TaskStatus.created => '已创建',
        TaskStatus.prepared => '已就绪',
        TaskStatus.analyzed => '已分析',
        TaskStatus.located => '已定位',
        TaskStatus.planned => '已定方案',
        TaskStatus.dryRunVerified => '方案已验',
        TaskStatus.modified => '已修改',
        TaskStatus.built => '已重打包',
        TaskStatus.signed => '已签名',
        TaskStatus.verified => '已验证',
        TaskStatus.delivered => '已交付',
        TaskStatus.paused => '已暂停',
        TaskStatus.waitingConfirmation => '等待确认',
        TaskStatus.failedRecoverable => '失败（可恢复）',
        TaskStatus.failedTerminal => '失败（不可恢复）',
      };

  /// 主链路顺序（不含异常态）。
  static const List<TaskStatus> linear = [
    TaskStatus.created,
    TaskStatus.prepared,
    TaskStatus.analyzed,
    TaskStatus.located,
    TaskStatus.planned,
    TaskStatus.dryRunVerified,
    TaskStatus.modified,
    TaskStatus.built,
    TaskStatus.signed,
    TaskStatus.verified,
    TaskStatus.delivered,
  ];

  /// 是否属于主链路。
  bool get isLinear => linear.contains(this);

  /// 是否异常态。
  bool get isExceptional => !isLinear;

  /// 是否终态（不再推进）。
  bool get isTerminal =>
      this == TaskStatus.delivered || this == TaskStatus.failedTerminal;

  /// 主链路序号，异常态返回 -1。
  int get linearIndex => linear.indexOf(this);

  /// 从当前状态能否推进到 [next]。
  ///
  /// 规则：
  /// - 终态不能再去任何地方；
  /// - 异常态可以回到主链路（回退或恢复），但目标必须是主链路状态；
  /// - 主链路之间只允许走一格（禁止跳跃，§13.4「状态推进必须有事件依据」）。
  bool canAdvanceTo(TaskStatus next) {
    if (isTerminal) return false;
    if (this == next) return false;

    // 进入异常态：任意非终态都允许。
    if (next.isExceptional) return true;

    // 从异常态恢复：允许回到任意主链路状态，由 Runtime 记录事件说明原因。
    if (isExceptional) return true;

    return next.linearIndex == linearIndex + 1;
  }

  static TaskStatus fromLabel(String label) => TaskStatus.values.firstWhere(
        (s) => s.label == label,
        orElse: () => TaskStatus.created,
      );
}

/// 阶段（§6.4 阶段化 Capability Manifest）。
///
/// 与状态的区别：状态是「走到哪一步」，阶段是「此刻该给模型哪些工具」。
enum TaskPhase {
  prepare('prepare', '准备'),
  analyze('analyze', '分析'),
  locate('locate', '定位'),
  modify('modify', '修改'),
  deliver('deliver', '交付');

  const TaskPhase(this.id, this.label);

  final String id;
  final String label;

  static TaskPhase fromId(String id) => TaskPhase.values.firstWhere(
        (p) => p.id == id,
        orElse: () => TaskPhase.prepare,
      );
}

/// 任务授权约束（§6.3 constraints）。
///
/// 这些是**能力开关**：默认全关，由任务创建时或用户显式授权打开。
/// Runtime 在每次工具调用前检查，Prompt 不能绕过（§18.2）。
class TaskConstraints {
  /// 原始 APK 只读，恒为 true（保留字段以便审计时可见）。
  final bool preserveOriginal;

  /// 允许修改工作副本。
  final bool allowModification;

  /// 允许签名。
  final bool allowSigning;

  /// 允许安装到设备。
  final bool allowInstall;

  /// 允许 Frida 动态插桩。
  final bool allowFrida;

  /// 允许内存 dump。
  final bool allowMemoryDump;

  /// 允许运行时 DEX dump（脱壳）。
  final bool allowRuntimeDexDump;

  /// 允许设备级调试。
  final bool allowDeviceDebug;

  /// 允许调用外部 MCP 工具（§18.2 默认关闭）。
  final bool allowExternalMcp;

  const TaskConstraints({
    this.preserveOriginal = true,
    this.allowModification = false,
    this.allowSigning = false,
    this.allowInstall = false,
    this.allowFrida = false,
    this.allowMemoryDump = false,
    this.allowRuntimeDexDump = false,
    this.allowDeviceDebug = false,
    this.allowExternalMcp = false,
  });

  /// 只读任务：只允许分析，不碰任何写操作。
  static const readOnly = TaskConstraints();

  /// 分析 + 改包 + 签名（最常见的改包任务默认值）。
  static const modifyAndSign = TaskConstraints(
    allowModification: true,
    allowSigning: true,
  );

  TaskConstraints copyWith({
    bool? preserveOriginal,
    bool? allowModification,
    bool? allowSigning,
    bool? allowInstall,
    bool? allowFrida,
    bool? allowMemoryDump,
    bool? allowRuntimeDexDump,
    bool? allowDeviceDebug,
    bool? allowExternalMcp,
  }) =>
      TaskConstraints(
        preserveOriginal: preserveOriginal ?? this.preserveOriginal,
        allowModification: allowModification ?? this.allowModification,
        allowSigning: allowSigning ?? this.allowSigning,
        allowInstall: allowInstall ?? this.allowInstall,
        allowFrida: allowFrida ?? this.allowFrida,
        allowMemoryDump: allowMemoryDump ?? this.allowMemoryDump,
        allowRuntimeDexDump:
            allowRuntimeDexDump ?? this.allowRuntimeDexDump,
        allowDeviceDebug: allowDeviceDebug ?? this.allowDeviceDebug,
        allowExternalMcp: allowExternalMcp ?? this.allowExternalMcp,
      );

  Map<String, Object?> toJson() => {
        'preserveOriginal': preserveOriginal,
        'allowModification': allowModification,
        'allowSigning': allowSigning,
        'allowInstall': allowInstall,
        'allowFrida': allowFrida,
        'allowMemoryDump': allowMemoryDump,
        'allowRuntimeDexDump': allowRuntimeDexDump,
        'allowDeviceDebug': allowDeviceDebug,
        'allowExternalMcp': allowExternalMcp,
      };

  static TaskConstraints fromJson(Object? raw) {
    if (raw is! Map) return const TaskConstraints();
    bool b(String k, bool d) => raw[k] is bool ? raw[k] as bool : d;
    return TaskConstraints(
      preserveOriginal: b('preserveOriginal', true),
      allowModification: b('allowModification', false),
      allowSigning: b('allowSigning', false),
      allowInstall: b('allowInstall', false),
      allowFrida: b('allowFrida', false),
      allowMemoryDump: b('allowMemoryDump', false),
      allowRuntimeDexDump: b('allowRuntimeDexDump', false),
      allowDeviceDebug: b('allowDeviceDebug', false),
      allowExternalMcp: b('allowExternalMcp', false),
    );
  }
}

/// 任务预算（§23.1 budget）。
///
/// 用于限制探索成本：工具调用次数与探针成本累加（§12.3 探针成本）。
class TaskBudget {
  /// 最大工具调用次数。
  final int maxToolCalls;

  /// 最大成本（按 §12.3 的探针成本累加）。
  final int maxCost;

  /// 已用工具调用次数。
  final int usedToolCalls;

  /// 已用成本。
  final int usedCost;

  /// 2026-09-21 用户定案："去除所有限制，只保留熔断机制防止模型死循环"。
  ///
  /// 上限值仍存在，但已抬到**实际不可能触发**的量级——它们不再是工作性
  /// 约束，只是防溢出的数值兜底。真正拦"原地打转"的是环路闸门
  /// （ToolCallLoopGuard：同参重复即拦），不是这两个数。
  const TaskBudget({
    this.maxToolCalls = 100000,
    this.maxCost = 1000000,
    this.usedToolCalls = 0,
    this.usedCost = 0,
  });

  bool get callsExhausted => usedToolCalls >= maxToolCalls;
  bool get costExhausted => usedCost >= maxCost;
  bool get exhausted => callsExhausted || costExhausted;
  int get remainingCalls => (maxToolCalls - usedToolCalls).clamp(0, maxToolCalls);
  int get remainingCost => (maxCost - usedCost).clamp(0, maxCost);

  TaskBudget spend({int calls = 1, int cost = 0}) => TaskBudget(
        maxToolCalls: maxToolCalls,
        maxCost: maxCost,
        usedToolCalls: usedToolCalls + calls,
        usedCost: usedCost + cost,
      );

  /// 只改上限，已用量原样保留（用户手动调整预算用）。
  TaskBudget copyWith({int? maxToolCalls, int? maxCost}) => TaskBudget(
        maxToolCalls: maxToolCalls ?? this.maxToolCalls,
        maxCost: maxCost ?? this.maxCost,
        usedToolCalls: usedToolCalls,
        usedCost: usedCost,
      );

  Map<String, Object?> toJson() => {
        'maxToolCalls': maxToolCalls,
        'maxCost': maxCost,
        'usedToolCalls': usedToolCalls,
        'usedCost': usedCost,
      };

  static TaskBudget fromJson(Object? raw) {
    if (raw is! Map) return const TaskBudget();
    int i(String k, int d) => raw[k] is num ? (raw[k] as num).toInt() : d;
    return TaskBudget(
      maxToolCalls: i('maxToolCalls', 200),
      maxCost: i('maxCost', 400),
      usedToolCalls: i('usedToolCalls', 0),
      usedCost: i('usedCost', 0),
    );
  }
}

/// 任务契约（§6.3）。
///
/// 每个任务在创建时确定：目标、输入、约束、成功标准、当前阶段。
/// 契约是 Runtime 判定「能不能做这件事」的依据。
class TaskContract {
  /// 用户目标（自然语言）。
  final String goal;

  /// 输入 APK 的绝对路径。
  final String inputApk;

  /// 成功标准（人工可读的一条条判定）。
  final List<String> successCriteria;

  final TaskConstraints constraints;

  const TaskContract({
    required this.goal,
    required this.inputApk,
    this.successCriteria = const [],
    this.constraints = const TaskConstraints(),
  });

  TaskContract copyWith({
    String? goal,
    String? inputApk,
    List<String>? successCriteria,
    TaskConstraints? constraints,
  }) =>
      TaskContract(
        goal: goal ?? this.goal,
        inputApk: inputApk ?? this.inputApk,
        successCriteria: successCriteria ?? this.successCriteria,
        constraints: constraints ?? this.constraints,
      );

  Map<String, Object?> toJson() => {
        'goal': goal,
        'inputApk': inputApk,
        'successCriteria': successCriteria,
        'constraints': constraints.toJson(),
      };

  static TaskContract fromJson(Object? raw) {
    if (raw is! Map) {
      return const TaskContract(goal: '', inputApk: '');
    }
    return TaskContract(
      goal: raw['goal']?.toString() ?? '',
      inputApk: raw['inputApk']?.toString() ?? '',
      successCriteria: [
        for (final c in (raw['successCriteria'] as List? ?? const []))
          c.toString()
      ],
      constraints: TaskConstraints.fromJson(raw['constraints']),
    );
  }
}

/// 一个任务（§23.1 Task）。
class Task {
  final String id;
  final String title;
  final TaskContract contract;
  final TaskStatus status;
  final TaskPhase phase;

  /// 工作区目录的绝对路径。
  final String workspacePath;

  final TaskBudget budget;
  final int createdAt;
  final int updatedAt;

  /// 任务结束原因（终态时填入，便于交付报告与审计）。
  final String? closedReason;

  const Task({
    required this.id,
    required this.title,
    required this.contract,
    this.status = TaskStatus.created,
    this.phase = TaskPhase.prepare,
    this.workspacePath = '',
    this.budget = const TaskBudget(),
    this.createdAt = 0,
    this.updatedAt = 0,
    this.closedReason,
  });

  Task copyWith({
    String? title,
    TaskContract? contract,
    TaskStatus? status,
    TaskPhase? phase,
    String? workspacePath,
    TaskBudget? budget,
    int? updatedAt,
    String? closedReason,
  }) =>
      Task(
        id: id,
        title: title ?? this.title,
        contract: contract ?? this.contract,
        status: status ?? this.status,
        phase: phase ?? this.phase,
        workspacePath: workspacePath ?? this.workspacePath,
        budget: budget ?? this.budget,
        createdAt: createdAt,
        updatedAt: updatedAt ?? this.updatedAt,
        closedReason: closedReason ?? this.closedReason,
      );

  Map<String, Object?> toJson() => {
        'id': id,
        'title': title,
        'contract': contract.toJson(),
        'status': status.label,
        'phase': phase.id,
        'workspacePath': workspacePath,
        'budget': budget.toJson(),
        'createdAt': createdAt,
        'updatedAt': updatedAt,
        if (closedReason != null) 'closedReason': closedReason,
      };

  static Task fromJson(Object? raw) {
    if (raw is! Map) {
      throw const FormatException('task json 不是对象');
    }
    final id = raw['id']?.toString() ?? '';
    if (id.isEmpty) throw const FormatException('task 缺少 id');
    return Task(
      id: id,
      title: raw['title']?.toString() ?? id,
      contract: TaskContract.fromJson(raw['contract']),
      status: TaskStatus.fromLabel(raw['status']?.toString() ?? 'Created'),
      phase: TaskPhase.fromId(raw['phase']?.toString() ?? 'prepare'),
      workspacePath: raw['workspacePath']?.toString() ?? '',
      budget: TaskBudget.fromJson(raw['budget']),
      createdAt: (raw['createdAt'] as num?)?.toInt() ?? 0,
      updatedAt: (raw['updatedAt'] as num?)?.toInt() ?? 0,
      closedReason: raw['closedReason']?.toString(),
    );
  }
}
