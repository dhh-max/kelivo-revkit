import 'dart:async';
import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import '../../../core/models/assistant.dart';
import '../../../core/services/local_tools/local_tool_names.dart';
import '../../../core/services/local_tools/local_tool_registry.dart';
import '../../../core/services/local_tools/tool_lane_policy.dart';
import '../../../features/dev_assistant/builtin_dev_assistant.dart';
import '../../../features/solab_apk/assistant/builtin_assistant.dart';
import 'session_mode.dart';

/// 子代理可用的工具类别（对齐 Rikkahub-Next 的 READ/WRITE/SHELL 白名单设计：
/// 用类别而不是逐个工具名，工具增删时不必改每个子代理定义）。
enum SubAgentCategory {
  read('read', '只读：读文件、检索、分析'),
  write('write', '写入：改动文件与产物'),
  shell('shell', '执行：沙盒 shell（需 Linux 环境）');

  const SubAgentCategory(this.wireName, this.title);

  final String wireName;
  final String title;

  static SubAgentCategory? fromWire(String? value) {
    for (final category in SubAgentCategory.values) {
      if (category.wireName == value || category.name == value) return category;
    }
    return null;
  }
}

/// 子代理的领域：决定它适合被哪个助手派发（各司其职）。
///
/// 不是权限开关——权限一律由「类别 ∩ 当前助手自己的工具」实时算出；这个字段
/// 只用来在派发前给出人话错误、并在界面里分组（开发助手派逆向子代理必然缺工具）。
enum SubAgentDomain {
  any('any', '通用'),
  dev('dev', '开发'),
  apk('apk', '逆向');

  const SubAgentDomain(this.wireName, this.title);

  final String wireName;
  final String title;

  static SubAgentDomain fromWire(String? value) {
    for (final domain in SubAgentDomain.values) {
      if (domain.wireName == value || domain.name == value) return domain;
    }
    return SubAgentDomain.any;
  }
}


/// 子代理嵌套深度上限（顶层派发 = 第 1 层）。
///
/// 对齐 deepseek-harness 的 depth 闸门（packages/subagent/subagent/src/depth.ts）：
/// 允许「主代理 → 子代理 → 子代理」两级，再往下直接结构化拒绝。没有这道闸
/// 时，子代理的工具面里含 `subagent`（它属只读注册表），递归派发既烧额度
/// 又让每一层都丢掉上一层的会话上下文。
const int kSubAgentMaxDepth = 2;

/// 派发这次子代理的会话 id（Zone 值，包住每一次嵌套工具调用）。
///
/// 为什么要有它：子代理的模型调用口是在「构建本轮工具定义」时注册的，
/// 那个位置拿到的会话可能是空的（真机复现：漏传 conversationId）。
/// 一旦为空，子代理里的写类工具查不到 /goal 免审批、todo 工具报
/// conversation_required、每会话并发上限与按会话取消全部失效。派发点
/// 自己最清楚是哪个会话，所以在调用工具的瞬间放进 Zone 里传递。
abstract final class SubAgentDispatchScope {
  static final Object _key = Object();

  /// 当前正在执行的嵌套工具调用所属会话；不在子代理里时为 null。
  static String? get conversationId => Zone.current[_key] as String?;

  static Future<T> run<T>(String? conversationId, Future<T> Function() body) {
    final scope = conversationId?.trim() ?? '';
    if (scope.isEmpty) return body();
    return runZoned(
      body,
      zoneValues: <Object, Object>{_key: scope},
    );
  }
}

/// 当前子代理循环的嵌套深度（Zone 值，随循环自动进出）。
///
/// 循环里再调用 `subagent` 工具时，派发者只能看到"自己在第几层"这一件事，
/// 所以放在 Zone 上而不是实例字段：驱动、工具面、拒绝文案三处读同一个值。
abstract final class SubAgentDepth {
  static final Object _key = Object();

  /// 当前已嵌套层数：不在任何子代理循环里时为 0。
  static int get current => (Zone.current[_key] as int?) ?? 0;

  /// 在 [depth] 层里执行 [body]（循环自己进出，异常路径也会还原）。
  static Future<T> run<T>(int depth, Future<T> Function() body) =>
      runZoned(body, zoneValues: <Object, Object>{_key: depth});
}

class SubAgentDefinition {
  const SubAgentDefinition({
    required this.id,
    required this.name,
    required this.description,
    this.systemPrompt = '',
    this.categories = const <SubAgentCategory>{SubAgentCategory.read},
    this.enabledSkills = const <String>{},
    this.maxSteps = defaultMaxSteps,
    this.timeoutMs = defaultTimeoutMs,
    this.requiresApproval = true,
    this.builtIn = false,
    this.domain = SubAgentDomain.any,
  });

  static const int defaultMaxSteps = 64;
  static const int defaultTimeoutMs = 120000;

  final String id;
  final String name;
  final String description;
  final String systemPrompt;
  final Set<SubAgentCategory> categories;
  final Set<String> enabledSkills;
  final int maxSteps;
  final int timeoutMs;
  final bool requiresApproval;
  final bool builtIn;

  /// 适合被哪个助手派发（界面分组 + 派发前的域检查）；不是权限开关。
  final SubAgentDomain domain;

  /// 工具名/展示名用的 slug（子代理名 → 稳定标识）。
  String get slug => slugify(name.isEmpty ? id : name);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'id': id,
        'name': name,
        'description': description,
        'systemPrompt': systemPrompt,
        'categories': categories.map((category) => category.wireName).toList(growable: false),
        'enabledSkills': enabledSkills.toList(growable: false),
        'maxSteps': maxSteps,
        'timeoutMs': timeoutMs,
        'requiresApproval': requiresApproval,
        'builtIn': builtIn,
        'domain': domain.wireName,
      };

  static SubAgentDefinition? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id']?.toString().trim() ?? '';
    final name = raw['name']?.toString().trim() ?? '';
    if (id.isEmpty || name.isEmpty) return null;
    final categories = <SubAgentCategory>{};
    final rawCategories = raw['categories'];
    if (rawCategories is List) {
      for (final entry in rawCategories) {
        final category = SubAgentCategory.fromWire(entry?.toString());
        if (category != null) categories.add(category);
      }
    }
    return SubAgentDefinition(
      id: id,
      name: name,
      description: raw['description']?.toString() ?? '',
      systemPrompt: raw['systemPrompt']?.toString() ?? '',
      categories: categories.isEmpty ? const <SubAgentCategory>{SubAgentCategory.read} : categories,
      enabledSkills: <String>{
        if (raw['enabledSkills'] is List)
          for (final skill in raw['enabledSkills'] as List) skill?.toString() ?? '',
      }..removeWhere((skill) => skill.isEmpty),
      maxSteps: (raw['maxSteps'] as num?)?.toInt() ?? defaultMaxSteps,
      timeoutMs: (raw['timeoutMs'] as num?)?.toInt() ?? defaultTimeoutMs,
      requiresApproval: raw['requiresApproval'] != false,
      domain: SubAgentDomain.fromWire(raw['domain']?.toString()),
    );
  }

  /// 名称 → 稳定标识（子代理工具的 `agent` 参数、`/subagent <标识> <任务>`）。
  ///
  /// 保留任何文字体系的字母/数字：中文名也能得到可用标识（此前只认 ASCII，
  /// 「调研员」会被折叠成 agent，两个中文名的子代理直接撞车）。
  static String slugify(String value) {
    final lowered = value.trim().toLowerCase();
    final buffer = StringBuffer();
    final wordChar = RegExp(r'[\p{L}\p{N}]', unicode: true);
    for (final rune in lowered.runes) {
      final char = String.fromCharCode(rune);
      if (wordChar.hasMatch(char)) {
        buffer.write(char);
      } else if (char == '-' || char == '_' || char == ' ' || char == '　') {
        if (buffer.isNotEmpty && !buffer.toString().endsWith('_')) buffer.write('_');
      }
    }
    var slug = buffer.toString();
    while (slug.endsWith('_')) {
      slug = slug.substring(0, slug.length - 1);
    }
    return slug.isEmpty ? 'agent' : slug;
  }
}

/// 子代理注册表：内置各领域的常驻子代理 + 用户定义（prefs 存 JSON 列表）。
///
/// 用户 2026-09-28：内置要有"各司其职"的分工——逆向域与开发域各有一套，
/// 直接把角色写死在代码里（和内置助手同一思路），用户仍可另建自定义子代理。
class SubAgentRegistry {
  SubAgentRegistry({SharedPreferences? preferences}) : _injected = preferences;

  static const String prefsKey = 'subagents_v1';
  static const String generalId = 'general';

  /// 助手 → 派发域（名单面单一事实源，2026-09-29「各司其职」收口）：
  /// 内置逆向/开发助手各归各域，其余助手（含自建）= any（全可见）。
  /// 能力层仍由「类别 ∩ 助手工具」交集保证，这里只管名单面。
  static SubAgentDomain domainForAssistant(Assistant? assistant) {
    if (assistant == null) return SubAgentDomain.any;
    if (assistant.id == BuiltinApkMod.assistantId) return SubAgentDomain.apk;
    if (assistant.id == BuiltinDevAssistant.assistantId) {
      return SubAgentDomain.dev;
    }
    return SubAgentDomain.any;
  }

  /// 该子代理在给定域的名单里是否可见：
  /// 通用子代理（any）任何助手可见；通用助手（any，含自建）看得到全部；
  /// 其余情况要求域相等。
  static bool visibleInDomain(
    SubAgentDefinition definition,
    SubAgentDomain domain,
  ) {
    if (definition.domain == SubAgentDomain.any || domain == SubAgentDomain.any) {
      return true;
    }
    return definition.domain == domain;
  }

  /// 内置自由子代理：调用时由主模型指定工具类别（不属于任何预设）。
  static const SubAgentDefinition general = SubAgentDefinition(
    id: generalId,
    name: 'general',
    description: 'General（通用）：一次性的调研/审核/独立复核任务；调用时可指定工具类别。',
    systemPrompt: '你是被主代理派出的独立子代理：只对交给你的任务负责，'
        '给出证据与结论；不要改动画之外的东西，不要把未验证的推测说成结论。',
    categories: <SubAgentCategory>{SubAgentCategory.read},
    requiresApproval: false,
    builtIn: true,
  );

  /// 开发域：调研（只读）→ 实现（读写）→ 审核（只读）三个内置角色。
  static const SubAgentDefinition devResearcher = SubAgentDefinition(
    id: 'builtin-dev-researcher',
    name: 'researcher',
    description: 'Research（调研）：读现有实现与文档，给出证据、来源与结论，不改任何东西。',
    systemPrompt: researcherPromptExample,
    categories: <SubAgentCategory>{SubAgentCategory.read},
    domain: SubAgentDomain.dev,
    builtIn: true,
  );

  static const SubAgentDefinition devImplementer = SubAgentDefinition(
    id: 'builtin-dev-implementer',
    name: 'implementer',
    description: 'Implement（实现）：按给定目标改代码/文档，先读后写、diff 尽量小，报告改了哪些文件。',
    systemPrompt: implementerPromptExample,
    categories: <SubAgentCategory>{SubAgentCategory.read, SubAgentCategory.write},
    domain: SubAgentDomain.dev,
    builtIn: true,
  );

  static const SubAgentDefinition devReviewer = SubAgentDefinition(
    id: 'builtin-dev-reviewer',
    name: 'reviewer',
    description: 'Review（复核）：独立复核找缺陷与风险，逐条给证据与修法，不改动任何东西。',
    systemPrompt: reviewerPromptExample,
    categories: <SubAgentCategory>{SubAgentCategory.read},
    domain: SubAgentDomain.dev,
    builtIn: true,
  );

  /// 逆向域：分析（只读）→ 补丁（读写）→ 复核（只读）。
  static const SubAgentDefinition apkAnalyst = SubAgentDefinition(
    id: 'builtin-apk-analyst',
    name: 'analyst',
    description: 'Analyze（逆向分析）：DEX/SO/资源检索与交叉引用，产出带证据的结论，不改包。',
    systemPrompt: apkAnalystPromptExample,
    categories: <SubAgentCategory>{SubAgentCategory.read},
    domain: SubAgentDomain.apk,
    builtIn: true,
  );

  static const SubAgentDefinition apkPatcher = SubAgentDefinition(
    id: 'builtin-apk-patcher',
    name: 'patcher',
    description: 'Patch（补丁）：按已确认的目标做改动/补丁/重签，改动前后都要能回读同一处证据。',
    systemPrompt: apkPatcherPromptExample,
    categories: <SubAgentCategory>{SubAgentCategory.read, SubAgentCategory.write},
    domain: SubAgentDomain.apk,
    builtIn: true,
  );

  static const SubAgentDefinition apkVerifier = SubAgentDefinition(
    id: 'builtin-apk-verifier',
    name: 'verifier',
    description: 'Verify（改包复核）：对改动后的产物做独立复核——签名、补丁是否真生效、有没有误伤。',
    systemPrompt: apkVerifierPromptExample,
    categories: <SubAgentCategory>{SubAgentCategory.read},
    domain: SubAgentDomain.apk,
    builtIn: true,
  );

  /// 全部内置子代理（顺序即界面顺序：通用 → 开发域 → 逆向域）。
  static const List<SubAgentDefinition> builtIns = <SubAgentDefinition>[
    general,
    devResearcher,
    devImplementer,
    devReviewer,
    apkAnalyst,
    apkPatcher,
    apkVerifier,
  ];

  /// 角色提示词示例：内置子代理与编辑器里的"角色预设"共用同一份（单一来源）。
  static const String researcherPromptExample =
      'You are a research subagent. Answer only the question you were given. '
      'Read what already exists first (list/inventory, then read or grep the relevant files) '
      'and cite where every fact came from (path, line, tool output). '
      'Finish with a short conclusion and the open questions. You must not modify anything; '
      'if a read tool is unavailable in your tool set, say so instead of guessing.';

  static const String implementerPromptExample =
      'You are an implementation subagent. Deliver exactly the change you were asked for: '
      'read the existing files before writing, keep the diff minimal and reversible, '
      'and report the list of files you changed plus the exact command the lead should run '
      'to verify it. You cannot run builds/tests yourself — never claim you did. '
      'Do not touch anything outside the task.';

  static const String reviewerPromptExample =
      'You are a review subagent. Look for defects, risks and inconsistencies in the given '
      'scope. For every finding give the evidence (path, line, how to reproduce), the impact '
      'and a suggested fix, and rank them. Do not modify anything; say plainly what you could '
      'not verify.';

  static const String apkAnalystPromptExample =
      'You are an APK static-analysis subagent. Gather evidence with the read-only APK tools '
      '(archive listing, dex/smali/strings/xref, SO analysis) and answer only the question you '
      'were given. Every conclusion needs its evidence (file entry, class/method, offset, or '
      'tool output). You must not modify the package; report anything you could not determine.';

  static const String apkPatcherPromptExample =
      'You are a patch subagent for an APK. Make exactly the change that was authorised, '
      're-read the same location afterwards to prove the change landed, and report: target '
      'file/entry, before/after evidence, and whether the artifact needs re-signing before '
      'install. Never widen the change beyond the authorised target; if the target is not '
      'found, stop and report instead of guessing.';

  static const String apkVerifierPromptExample =
      'You are a verification subagent for a modified APK. Independently check: does the '
      'declared change actually exist in the artifact, is the signature valid and consistent '
      'with what was shipped, and did anything else get touched. Report each check as '
      'pass/fail with the evidence you used, and list what you could not check. Do not modify '
      'anything.';

  final SharedPreferences? _injected;
  SharedPreferences? _prefs;

  Future<SharedPreferences> _open() async =>
      _injected ?? (_prefs ??= await SharedPreferences.getInstance());

  Future<List<SubAgentDefinition>> all() async {
    final prefs = await _open();
    final custom = <SubAgentDefinition>[];
    try {
      final decoded = jsonDecode(prefs.getString(prefsKey) ?? '[]');
      if (decoded is List) {
        custom.addAll(decoded.map(SubAgentDefinition.fromJson).whereType<SubAgentDefinition>());
      }
    } catch (_) {
      // 脏数据不阻断：退回只剩内置子代理。
    }
    // 内置常驻（用户 2026-09-28：逆向/开发各一套角色）；自定义按 id 去重。
    final builtInIds = builtIns.map((definition) => definition.id).toSet();
    return <SubAgentDefinition>[
      for (final definition in builtIns)
        definition,
      for (final definition in custom)
        if (!builtInIds.contains(definition.id)) definition,
    ];
  }

  /// 2026-10-01 起内置角色改英文 slug；这里保留旧中文名 → 新 slug 的
  /// 别名表，旧会话提示词与用户习惯（/subagent 调研员 …）不断链。
  static const Map<String, String> legacySlugAliases = <String, String>{
    // 真机实测 A3：按常见命名直觉写的 general-purpose 会被直接拒绝。
    'general-purpose': 'general',
    'general_purpose': 'general',
    '调研员': 'researcher',
    '实现者': 'implementer',
    '审核员': 'reviewer',
    '逆向分析员': 'analyst',
    '补丁执行者': 'patcher',
    '改包复核员': 'verifier',
  };

  Future<SubAgentDefinition?> bySlug(String slug) async {
    final wanted = (legacySlugAliases[slug.trim()] ?? slug).trim().toLowerCase();
    for (final definition in await all()) {
      if (definition.slug == wanted || definition.id.toLowerCase() == wanted) {
        return definition;
      }
    }
    return null;
  }

  Future<void> replaceAll(List<SubAgentDefinition> definitions) async {
    final prefs = await _open();
    final custom = definitions.where((definition) => !definition.builtIn);
    await prefs.setString(
      prefsKey,
      jsonEncode(custom.map((definition) => definition.toJson()).toList(growable: false)),
    );
  }

  /// 类别 → 实际工具名。
  ///
  /// - read：注册表里标了 readOnly 的工具 + `file`（读类动作）+ `todo_read`；
  /// - write：变更类工具 + `file`（写类动作，运行期按动作再拦一次）+ `todo_write`；
  /// - shell：沙盒 shell 属工作区工具面（不在本地工具注册表里），
  ///   因此这里不额外授予——要跑命令由主代理显式用工作区工具完成。
  ///
  /// [allowed] 非空时取交集（**各司其职**）：子代理只能用当前助手自己也有的工具——
  /// 开发助手的子代理拿不到 APK 工具，逆向助手的子代理也拿不到开发工具。
  /// 这一条是"能力"层面的保证，不只是文案口径。
  ///
  /// [skills] 非空时补上技能读取工具（2026-09-29：`enabledSkills` 此前只是
  /// 「存得下、读得回、没人用」的死数据，自定义子代理里勾了技能也不会有任何
  /// 效果）——技能是提示词级的工作流，子代理必须先能读到它，否则"启用技能"
  /// 只是一句空话。仍然要过 [allowed] 交集：助手自己没有技能工具就不授予。
  ///
  /// [depth] 当前已嵌套的层数（顶层派发时 0）：到 [kSubAgentMaxDepth] 就不再
  /// 授予 `subagent`，子代理不能再往下派（对齐 deepseek-harness 的深度闸门；
  /// 没有这道闸，递归派发会一路烧额度，且每层都看不到上一层的会话上下文）。
  static Set<String> toolNamesFor(
    Set<SubAgentCategory> categories, {
    Set<String>? allowed,
    Set<String> skills = const <String>{},
    int depth = 0,
  }) {
    final names = <String>{};
    if (categories.contains(SubAgentCategory.read)) {
      names.addAll(LocalToolRegistry.readOnlyToolIds());
      names.add(LocalToolNames.file);
      names.add(LocalToolNames.todoRead);
    }
    if (categories.contains(SubAgentCategory.write)) {
      names.addAll(kMutatingToolNames.where(LocalToolNames.all.contains));
      names.add(LocalToolNames.file);
      names.add(LocalToolNames.todoWrite);
    }
    if (skills.isNotEmpty) {
      names.add(LocalToolNames.apkSkill);
      names.add(LocalToolNames.installedSkills);
    }
    // 深度闸门：子代理自己不能再派子代理（顶层 depth=0，第一层子代理 depth=1）。
    if (depth + 1 >= kSubAgentMaxDepth) {
      names.remove(LocalToolNames.subagent);
    }
    if (allowed != null) {
      names.removeWhere((name) => !allowed.contains(name));
    }
    return names;
  }

  /// 写类动作走 `file`，读类动作也走 `file`：类别只到工具名粒度，
  /// 所以运行期还要按动作再拦一次（见 SubAgentLoop 的只读守卫）。
  static bool isWriteAction(String toolName, Map<String, dynamic> args) {
    if (toolName != LocalToolNames.file) return false;
    return !ToolLanePolicy.isReadOnlyCall(
      toolName,
      args,
      readOnlyToolIds: LocalToolRegistry.readOnlyToolIds(),
    );
  }
}
