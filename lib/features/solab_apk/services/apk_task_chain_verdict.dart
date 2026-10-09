/// 链式命令的**判定分级**（报告 2-20）。
///
/// 背景：`FIELD_CANDIDATE_MINE` 过去只有 `failureReason` 与一段自然语言
/// `llmJudgment`。真机实测里模型面对「零候选」时只能自己猜：是「本包没有这个
/// 功能」，还是「语义描述不够具体」，还是「探针坏了」——三种情况的正确动作完全
/// 不同，却没有任何机器可读判据。
///
/// 这里把判定收敛成三档 + 一个不可用档，纯函数、可单测：
///  - `candidates_found`：有候选，继续 FIELD_STATE_LOCATE；
///  - `inconclusive`   ：有候选类但拿不到字段体（证据不全，补证据而不是下结论）；
///  - `not_applicable` ：探针跑完且零线索 → **不适用**，不许硬给结论或编字段；
///  - `probe_unavailable`：探针本身不可用 → 连「适用与否」都判不了，先修环境。
enum TaskChainVerdict {
  candidatesFound('candidates_found', true),
  inconclusive('inconclusive', true),
  notApplicable('not_applicable', false),
  probeUnavailable('probe_unavailable', false);

  const TaskChainVerdict(this.wire, this.applicable);

  /// 对外字段值（`verdict`）。
  final String wire;

  /// 本轮能否凭这条链下结论。
  final bool applicable;
}

/// 判定 + 原因码 + 文案的单一事实源。
abstract final class TaskChainVerdicts {
  TaskChainVerdicts._();

  /// 原因码（`verdictReason`）。
  static const String reasonCandidatesFound = 'CANDIDATES_FOUND';
  static const String reasonOutlineUnavailable = 'OUTLINE_UNAVAILABLE';
  static const String reasonSemanticNotFound = 'SEMANTIC_NOT_FOUND';
  static const String reasonProbeUnavailable = 'PROBE_UNAVAILABLE';

  /// 语义挖掘的三档判定。
  ///
  /// [hasCandidates] 有没有最终字段候选；[outlineFailed] 命中了候选类但字段体
  /// 全拿不到。探针不可用请直接走 [probeUnavailable]。
  static ({TaskChainVerdict verdict, String reason}) classifyFieldCandidates({
    required bool hasCandidates,
    required bool outlineFailed,
  }) {
    if (hasCandidates) {
      return (
        verdict: TaskChainVerdict.candidatesFound,
        reason: reasonCandidatesFound,
      );
    }
    if (outlineFailed) {
      return (
        verdict: TaskChainVerdict.inconclusive,
        reason: reasonOutlineUnavailable,
      );
    }
    return (
      verdict: TaskChainVerdict.notApplicable,
      reason: reasonSemanticNotFound,
    );
  }

  /// 链结果的**统一语义**（`outcome`，报告 2-22）。
  ///
  /// 过去只有 `ok` + 可选 `failureReason`：`ok:true` 既可能是「拿到结论」，也可能是
  /// 「跑完了但没候选（failureReason 非空）」。调用方得自己拼「ok 且 failureReason
  /// 为空」这个启发式，写错就把「不完整」当「完成」——真机复测里正是这么被误读的。
  ///
  /// 取值：
  ///  - `failed`        工具/参数失败（ok=false），failureReason 是根因码；
  ///  - `not_applicable` 明确判定不适用（verdict=not_applicable/probe_unavailable）；
  ///  - `incomplete`    跑完了但证据不全（failureReason 非空或 verdict=inconclusive）；
  ///  - `succeeded`     有结论可用。
  static String outcomeFor({
    required bool ok,
    String? failureReason,
    String? verdict,
  }) {
    if (!ok) return 'failed';
    final v = (verdict ?? '').trim();
    if (v == TaskChainVerdict.notApplicable.wire ||
        v == TaskChainVerdict.probeUnavailable.wire) {
      return 'not_applicable';
    }
    if (v == TaskChainVerdict.inconclusive.wire) return 'incomplete';
    if ((failureReason ?? '').trim().isNotEmpty) return 'incomplete';
    return 'succeeded';
  }

  /// 判定说明（`verdictMessage`）：必须写清「这不是功能不存在的证据」。
  static String messageFor(TaskChainVerdict verdict) => switch (verdict) {
    TaskChainVerdict.candidatesFound =>
      '已产出字段候选，可据此走 FIELD_STATE_LOCATE 继续定位。',
    TaskChainVerdict.inconclusive =>
      '命中了候选类但拿不到字段体（可能是内联/混淆/接口字段）：证据不全，'
          '本轮不能据此下结论，可补一次 FIELD_STATE_LOCATE 或换关键词重跑。',
    TaskChainVerdict.probeUnavailable =>
      '探针不可用（DexKit 未产出任何结果），因此无法判断该语义是否存在于本包。',
    TaskChainVerdict.notApplicable =>
      '固定链跑完但本包内没有与该语义相关的字段名/字符串线索。'
          '这不等于「功能不存在」：可能语义描述不够具体、目标 APK 绑错，'
          '或该功能不靠字段名/文案暴露。',
  };

  /// 不可用/不适用时给调用方的可执行出口。
  static List<String> nextActionsFor(TaskChainVerdict verdict) =>
      switch (verdict) {
        TaskChainVerdict.probeUnavailable => const <String>[
          '先确认环境与工作区就绪（analyze_apk_workspace / get_workspace_policy）后重跑本链',
          '若环境正常仍失败，改用 route_task 自由探索或 dex_search 直接查关键词',
          '不要把「探针失败」报告成「该语义不存在」',
        ],
        TaskChainVerdict.notApplicable => const <String>[
          '补充更具体的语义描述（含界面文案/类名片段/开关名）后重跑本链',
          '确认当前绑定 APK 就是目标包（get_apk_project_info 的 boundApk）',
          '走 route_task 自由探索，或直接用 dex_search 查屏上文案/关键词',
          '不要因为零候选就断言功能不存在，也不要编造字段',
        ],
        TaskChainVerdict.inconclusive => const <String>[
          '对候选类跑 FIELD_STATE_LOCATE（传 className）拿字段写入证据',
          '换 2-3 个更贴近业务的关键词重跑本链',
        ],
        TaskChainVerdict.candidatesFound => const <String>[
          '择一候选后改走 FIELD_STATE_LOCATE（className + field/fieldLocator）',
        ],
      };
}
