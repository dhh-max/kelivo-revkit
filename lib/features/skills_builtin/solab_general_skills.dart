import 'dart:convert';

/// **通用内置技能**：与具体技术栈无关、对**所有助手**生效的工程方法论。
///
/// 与助手级技能（逆向助手那套 APK、开发助手那套 Android/Flutter/Web）分开管理：
/// 本文件是「通用」那一类，随包发布、只读，按需经 `get_solab_skill` 读取；
/// `SolabBuiltinSkills` 负责把「通用 + 当前助手专属」合成该助手可见的集合。
class SolabGeneralSkills {
  const SolabGeneralSkills._();

  static const activationHints = <String, String>{
    'general_task_intake': '任何任务的开工动作：目标/验收/改动面/最小实现',
    'general_testing_discipline': '写测试、跑回归、判断失败是否本次引入',
    'general_code_review': '代码审查：按风险排序的可执行清单',
    'general_release_discipline': '出包/发版：版本、产物验证与回滚点',
    'general_upstream_sync': '与上游仓库同步/合并时的纪律（上游优先）',
    'general_tool_workflow':
        '工具工作流：先发现能用什么，再读→析→划→改→验，独立任务委派出去',
  };

  static const activationRules = <String, List<String>>{
    'general_task_intake': [
      '先用一两句话复述目标与验收标准，再列改动面（文件/模块/调用方/数据），最后才动手。',
      '只问「不问就会做错」的最小问题；不要为了确认而确认，也不要靠猜扩大改动范围。',
      '选满足验收标准的最小实现；顺手重构不属于本次任务的代码是常见返工来源。',
    ],
    'general_testing_discipline': [
      '只跑与改动相关的用例；全量套件是发布门禁，不是内循环。',
      '新行为配新用例；修 bug 先写能复现它的失败用例。断言可观测行为，不查私有字段。',
      '时间/随机/网络必须可注入（clock、seed、fake client），禁止用 sleep 等时序。',
      '怀疑失败非本次引入时，先复现基线（例如把改动暂存后重跑），再下结论；结论要给命令与数字。',
    ],
    'general_code_review': [
      '按风险从高到低看：数据完整性与迁移、鉴权与越权、并发与竞态、错误分类、资源泄漏、无界增长，最后才是命名与风格。',
      '每条意见必须给位置、风险、可执行替代方案；区分「阻塞」与「建议」。',
      '行为变更必须配测试；缺测试单独列为阻塞项。',
    ],
    'general_release_discipline': [
      '工具链版本集中声明，构建命令写下来，保证任何提交都能重建出产物。',
      '证据是「装上了并且跑通了」，不是「构建退出码 0」；签名产物要能通过校验。',
      '每次交付 bump 版本号并保留上一个产物作为回滚点；发布说明只写事实（改了什么、验了什么、没验什么）。',
      '生成物不许手改：改生成器再重新生成。',
    ],
    'general_tool_workflow': [
      '先发现再动手：不知道有什么工具就先查工具地图（get_solab_tool_map 里还带工作区/沙盒能力目录）；缺工具时让用户在助手设置里开，不要假设自己有。',
      '改已有文件用 edit_file 精确替换（不要整篇 write_file 重写）；新建或整篇替换才用 write_file；找内容用 grep、找路径用 glob；大文件分段读。',
      '需要跑命令用 shell（Linux 沙盒）。缺依赖（rg/jq/gcc/openjdk…）时先 command -v 自检，确实没有就让用户在「设置 → 工作区 → 环境预设」里装，别绕路也别假装有。',
      '读要用工具读真实内容（文件/检索），不要凭记忆改代码或复述过期结论。',
      '长任务先落待办再开工；每一步改完立刻自验，不要等到最后一起验。',
      '独立子任务委派出去（可并发），主线程只做决策与验收；批量/多阶段用工作流。',
      '同一轮不要重复同指纹调用；被提示重复就改参数或换手段。',
    ],
    'general_upstream_sync': [
      '上游优先：上游已实现的能力整体采上游，删掉 fork 版本——逐版重新适配才是最贵的路。',
      'fork 独有能力放独立文件，上游文件里只留少量**稳定钩子**（能一行就一行），这些钩子是下次同步要重贴的清单。',
      '禁止把旧 fork 代码块塞回被上游重写过的文件：会拖进过时依赖，产生编译风暴。',
      '同步后跑接线守卫（注册表一致性、宿主/服务端用例、孤儿文件检测）+ 各功能测试文件。',
    ],
  };

  static const skillNames = <String>[
    'general_task_intake',
    'general_testing_discipline',
    'general_code_review',
    'general_release_discipline',
    'general_upstream_sync',
    'general_tool_workflow',
  ];

  static String read(String skill) {
    final payload = switch (skill) {
      'general_task_intake' => {
        'name': 'Task Intake and Change Surface',
        'steps': [
          'Restate goal + acceptance criteria in one or two lines.',
          'Map the change surface: files, modules, callers, persisted data, external contracts.',
          'Pick the smallest change that meets the criteria; list what you are deliberately NOT touching.',
          'Self-review before reporting: does the change contradict an existing convention?',
        ],
        'stopConditions': [
          'Goal is ambiguous in a way that changes the implementation -> ask one minimal question.',
          'Required credentials/services are missing -> report the blocker instead of faking a result.',
        ],
        'output': ['Goal', 'Change surface', 'Change', 'Verification', 'Open risks'],
      },
      'general_testing_discipline' => {
        'name': 'Testing and Regression Discipline',
        'steps': [
          'Run only the affected tests first: `flutter test <file> --name "<pattern>"` (adapt per stack).',
          'Fix a bug starting from a failing case that reproduces it.',
          'Assert observable behaviour: public API, rendered output, persisted state, emitted events.',
          'Inject clocks/seeds/fakes for anything time-, random- or network-dependent.',
          'Golden/snapshot tests: review the diff, then update with the tool (e.g. `--update-goldens`) and commit both.',
        ],
        'whenUnsureIfPreExisting': [
          'Reproduce the baseline: stash only the source changes (`git stash push -- lib/`), re-run, compare.',
          'Report exact command, pass/fail counts, and the baseline result.',
        ],
        'output': ['Cases added', 'Command', 'Result', 'Baseline note'],
      },
      'general_code_review' => {
        'name': 'Risk-Ordered Code Review',
        'steps': [
          'Data: migrations, back-compat, partial writes, idempotency, transaction boundaries.',
          'Auth: authorization checks on every new entry point (not just authentication), tenant/owner scoping.',
          'Concurrency: races, shared mutable state, lock ordering, retry safety, cancellation.',
          'Errors: taxonomy (validation/auth/not-found/conflict/server), no empty-success masking failure.',
          'Resources: dispose/cancel subscriptions, close handles, bound caches and queues.',
          'Then: naming, structure, comments, formatting.',
        ],
        'rules': [
          'Every finding: location, risk, concrete alternative.',
          'Separate blocking findings from suggestions; list missing tests for behaviour changes.',
          'Do not rewrite the change while reviewing it - review the diff as submitted.',
        ],
        'output': ['Blocking', 'Suggestions', 'Missing tests', 'Overall verdict'],
      },
      'general_release_discipline' => {
        'name': 'Release and Artifact Discipline',
        'steps': [
          'Declare the toolchain versions and the exact build command next to the source.',
          'Build from a reviewed commit; bump version/build number for every delivered artifact.',
          'Verify by installing and exercising the artifact (or verifying the signature), not by build exit code.',
          'Keep the previous artifact/tag as the rollback point; write factual release notes.',
          'Never hand-edit generated output: fix the generator and regenerate.',
        ],
        'output': ['Version', 'Artifact + checksum', 'Verification performed', 'Rollback point'],
      },
      'general_upstream_sync' => {
        'name': 'Upstream-First Sync Method',
        'steps': [
          'Classify each capability: upstream-has-it (adopt upstream, delete fork variant) vs fork-only (keep in a dedicated file).',
          'Keep a documented list of hook points inside upstream files; replace whole fork blocks with the upstream implementation.',
          'Never splice obsolete fork blocks back into a rewritten upstream file - it pulls in dead dependencies.',
          'After syncing: run wiring guards (registry consistency, host/server tests, orphan/unreferenced-file detection) plus the feature test files.',
          'Commit per topic; record what was adopted vs kept, so the next sync re-applies the same short hook list.',
        ],
        'output': ['Adopted from upstream', 'Fork-only kept', 'Hook list', 'Guard + test results'],
      },
      'general_tool_workflow' => {
        'name': 'Tool Workflow: discover, read, plan, act, verify',
        'discovery': [
          'Tool map (get_solab_tool_map): what this assistant can call right now, grouped by capability domain (general / device / reverse).',
          'Skills (get_solab_skill, get_installed_skills): load methodology on demand - not all of them at once.',
          'Workspace policy (get_workspace_policy): which paths are writable, which actions need user confirmation, preview and result limits.',
        ],
        'loop': [
          'READ: open real content with the file/read tools and search tools before judging anything.',
          'ANALYSE: turn the goal into a change surface (files, modules, callers, data) plus acceptance criteria and open questions.',
          'PLAN: record the steps as todos; for long runs use the task status tools to track stage and budget.',
          'ACT: smallest change; ask for confirmation before irreversible or destructive operations; self-check immediately after each edit.',
          'VERIFY: run the affected checks and report exact commands plus pass/fail counts; collect deliverables (files + hashes + unverified items) and clean intermediates.',
          'DELEGATE: independent sub-tasks go to a subagent (can run in parallel); batch or multi-stage work goes to a workflow. The main thread decides and verifies.',
        ],
        'rules': [
          'On failure, read the error code and the recovery hint, then change the approach - do not replay the same call.',
          'Never repeat a call with the same fingerprint in one turn; if reminded about a repeat, change arguments or switch tools.',
          'If a needed tool is missing, ask the user to enable it in the assistant local-tools settings instead of assuming it exists.',
        ],
        'output': ['What I used', 'Steps taken', 'Verification', 'Deliverables', 'What I did not verify'],
      },
      _ => <String, dynamic>{},
    };
    return jsonEncode(payload);
  }
}
