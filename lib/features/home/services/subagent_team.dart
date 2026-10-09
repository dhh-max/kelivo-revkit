import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import 'subagent_loop.dart';
import 'subagent_registry.dart';
import 'subagent_runner.dart';

/// 专家团：一次派发里跑多个子代理，成员之间可以有先后依赖，写范围重叠的成员自动串行。
///
/// 设计借鉴 DeepSeek Harness 的 agent-team 子系统（Lead + teammate、共享任务 DAG、
/// `writeScopes` 提示性路径前缀、每个 member 独立的生命周期），按本 App 的规模裁剪：
/// - 保留：成员名/角色、`blockedBy` 依赖（无环校验）、`writeScope`、逐成员状态与合并报告；
/// - 不做：跨重启持久化的 mailbox 与任务快照——团队是一次派发内的编排，跑完即回结论。
///
/// 并发口径（与单发派发分开）：团队自己限流（[kTeamParallelLimit]），成员不再各占
/// 单发派发的每会话名额；同一波内写范围重叠的成员被分到不同 lane，lane 之间串行。
class SubAgentTeamMember {
  const SubAgentTeamMember({
    required this.name,
    required this.agent,
    required this.task,
    this.blockedBy = const <String>[],
    this.writeScope = const <String>[],
  });

  /// 团队内成员名（唯一，用于 blockedBy 引用与监看标签）。
  final String name;

  /// 子代理 slug / id（走 SubAgentRegistry）。
  final String agent;

  /// 这个成员要做的具体任务。
  final String task;

  /// 依赖的成员名：这些成员完成后本成员才开始。
  final List<String> blockedBy;

  /// 允许写的路径前缀（工作目录内相对路径）。空 = 整个工作目录。
  /// 提示性约束：只用于并行编排（重叠则串行）与报告，不是锁。
  final List<String> writeScope;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'name': name,
        'agent': agent,
        'task': task,
        if (blockedBy.isNotEmpty) 'blockedBy': blockedBy,
        if (writeScope.isNotEmpty) 'writeScope': writeScope,
      };

  static SubAgentTeamMember? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final name = raw['name']?.toString().trim() ?? '';
    final agent = raw['agent']?.toString().trim() ?? '';
    final task = raw['task']?.toString().trim() ?? '';
    if (name.isEmpty || agent.isEmpty || task.isEmpty) return null;
    return SubAgentTeamMember(
      name: name,
      agent: agent,
      task: task,
      blockedBy: <String>[
        if (raw['blockedBy'] is List)
          for (final entry in raw['blockedBy'] as List) entry?.toString().trim() ?? '',
      ]..removeWhere((entry) => entry.isEmpty),
      writeScope: <String>[
        if (raw['writeScope'] is List)
          for (final entry in raw['writeScope'] as List) entry?.toString().trim() ?? '',
      ]..removeWhere((entry) => entry.isEmpty),
    );
  }
}

class SubAgentTeam {
  const SubAgentTeam({
    required this.id,
    required this.name,
    required this.description,
    required this.members,
    this.domain = SubAgentDomain.any,
    this.builtIn = false,
  });

  final String id;
  final String name;
  final String description;
  final List<SubAgentTeamMember> members;
  final SubAgentDomain domain;
  final bool builtIn;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'id': id,
        'name': name,
        'description': description,
        'members': members.map((member) => member.toJson()).toList(growable: false),
        'domain': domain.wireName,
      };

  static SubAgentTeam? fromJson(Object? raw) {
    if (raw is! Map) return null;
    final id = raw['id']?.toString().trim() ?? '';
    final name = raw['name']?.toString().trim() ?? '';
    if (id.isEmpty || name.isEmpty) return null;
    final members = <SubAgentTeamMember>[
      if (raw['members'] is List)
        for (final entry in raw['members'] as List)
          if (SubAgentTeamMember.fromJson(entry) != null) SubAgentTeamMember.fromJson(entry)!,
    ];
    if (members.isEmpty) return null;
    return SubAgentTeam(
      id: id,
      name: name,
      description: raw['description']?.toString() ?? '',
      members: members,
      domain: SubAgentDomain.fromWire(raw['domain']?.toString()),
    );
  }
}

/// 预置专家团：开发域与逆向域各一条「调研/分析 → 动手 → 复核」的链。
///
/// 链条是串行的（后者 blockedBy 前者）——复核必须看到前一步的产出才有意义；
/// 需要并行时在派发里自定义 members 并给出各自的 writeScope。
class SubAgentTeamRegistry {
  SubAgentTeamRegistry({SharedPreferences? preferences}) : _injected = preferences;

  static const String prefsKey = 'subagent_teams_v1';

  /// 该专家团在给定域的名单里是否可见（与子代理同一口径）：
  /// 通用团任何助手可见；通用助手（any，含自建）看得到全部；其余要求域相等。
  static bool visibleInDomain(SubAgentTeam team, SubAgentDomain domain) {
    if (team.domain == SubAgentDomain.any || domain == SubAgentDomain.any) {
      return true;
    }
    return team.domain == domain;
  }

  static const SubAgentTeam devTeam = SubAgentTeam(
    id: 'dev-team',
    name: '开发专家团',
    description: '调研 → 实现 → 复核：一条链跑完再交付，最后一棒是独立复核。',
    domain: SubAgentDomain.dev,
    builtIn: true,
    members: <SubAgentTeamMember>[
      SubAgentTeamMember(
        name: '调研',
        agent: 'researcher',
        task: '读现有实现与文档，回答：这件事现在是怎么做的、动它会影响哪些文件。'
            '给出证据（路径/行）与结论，不要改任何东西。',
      ),
      SubAgentTeamMember(
        name: '实现',
        agent: 'implementer',
        task: '按目标做最小改动并回读确认落盘，报告改了哪些文件；不要顺手改无关的地方。',
        blockedBy: <String>['调研'],
      ),
      SubAgentTeamMember(
        name: '复核',
        agent: 'reviewer',
        task: '独立复核这次改动：逐条列出问题（或明确说没有）、证据与修法。',
        blockedBy: <String>['实现'],
      ),
    ],
  );

  static const SubAgentTeam apkTeam = SubAgentTeam(
    id: 'apk-team',
    name: '逆向专家团',
    description: '分析 → 改动/补丁 → 独立复核：三步各自带证据。',
    domain: SubAgentDomain.apk,
    builtIn: true,
    members: <SubAgentTeamMember>[
      SubAgentTeamMember(
        name: '分析',
        agent: 'analyst',
        task: '定位目标与证据（类/方法/字段/资源，或 SO 偏移），说明可行的改动点与风险。',
      ),
      SubAgentTeamMember(
        name: '改动',
        agent: 'patcher',
        task: '执行已确认的改动，改完回读同一处证明生效，并说明是否需要重新签名。',
        blockedBy: <String>['分析'],
      ),
      SubAgentTeamMember(
        name: '复核',
        agent: 'verifier',
        task: '独立复核产物：改动是否真在包里、签名是否有效、有没有误伤。逐项给证据。',
        blockedBy: <String>['改动'],
      ),
    ],
  );

  static const List<SubAgentTeam> builtIns = <SubAgentTeam>[devTeam, apkTeam];

  final SharedPreferences? _injected;
  SharedPreferences? _prefs;

  Future<SharedPreferences> _open() async =>
      _injected ?? (_prefs ??= await SharedPreferences.getInstance());

  Future<List<SubAgentTeam>> all() async {
    final prefs = await _open();
    final custom = <SubAgentTeam>[];
    try {
      final decoded = jsonDecode(prefs.getString(prefsKey) ?? '[]');
      if (decoded is List) {
        custom.addAll(decoded.map(SubAgentTeam.fromJson).whereType<SubAgentTeam>());
      }
    } catch (_) {
      // 脏数据不阻断：退回只剩内置团队。
    }
    final builtInIds = builtIns.map((team) => team.id).toSet();
    return <SubAgentTeam>[
      ...builtIns,
      for (final team in custom)
        if (!builtInIds.contains(team.id)) team,
    ];
  }

  Future<SubAgentTeam?> byKey(String key) async {
    final wanted = key.trim().toLowerCase();
    for (final team in await all()) {
      if (team.id.toLowerCase() == wanted || team.name.toLowerCase() == wanted) return team;
    }
    return null;
  }

  Future<void> replaceAll(List<SubAgentTeam> teams) async {
    final prefs = await _open();
    final custom = teams.where((team) => !team.builtIn);
    await prefs.setString(
      prefsKey,
      jsonEncode(custom.map((team) => team.toJson()).toList(growable: false)),
    );
  }
}

/// 团队编排的硬上限（超出直接结构化拒绝，避免一次派发把额度烧光）。
const int kTeamMaxMembers = 4;

/// 团队内部并行度：同一时刻最多几个成员在跑。
const int kTeamParallelLimit = 2;

class SubAgentTeamMemberResult {
  const SubAgentTeamMemberResult({
    required this.member,
    required this.definition,
    required this.outcome,
    this.serializedForScope = false,
  });

  final SubAgentTeamMember member;
  final SubAgentDefinition definition;
  final SubAgentOutcome outcome;

  /// 因为与同波成员写范围重叠而被串行执行。
  final bool serializedForScope;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'name': member.name,
        'agent': definition.slug,
        'domain': definition.domain.wireName,
        'categories': definition.categories
            .map((category) => category.wireName)
            .toList(growable: false),
        // E1：与单发同名字段（真机实测：两形态字段不一致，统一解析要写分支）。
        'grantedTools': _grantedToolsFor(definition),
        if (member.writeScope.isNotEmpty) 'writeScope': member.writeScope,
        if (member.blockedBy.isNotEmpty) 'blockedBy': member.blockedBy,
        if (serializedForScope) 'serializedForScope': true,
        ...outcome.toJson(),
      };
}

class SubAgentTeamOutcome {
  const SubAgentTeamOutcome({
    required this.teamName,
    required this.members,
    required this.merged,
    this.warnings = const <String>[],
  });

  final String teamName;
  final List<SubAgentTeamMemberResult> members;
  final String merged;
  final List<String> warnings;

  bool get ok => members.every((member) => member.outcome.ok);

  /// 部分成功：至少一个成员给出结论，但不是全员成功（2026-10-01 真机实测
  /// B3：3 人团 2 成功 1 超时时顶层 ok:false，调用方按 ok 判定会丢掉已经
  /// 拿到的可用结论）。`ok` 语义不变（全员成功），调用方应改看 partial +
  /// succeeded/failed 名单。
  bool get partial =>
      !ok && members.any((member) => member.outcome.ok);

  Map<String, dynamic> toJson() => <String, dynamic>{
        'ok': ok,
        if (partial) 'partial': true,
        'team': teamName,
        'members': members.map((member) => member.toJson()).toList(growable: false),
        if (members.any((member) => member.outcome.ok))
          'succeeded': <String>[
            for (final member in members)
              if (member.outcome.ok) member.member.name,
          ],
        if (members.any((member) => !member.outcome.ok))
          'failed': <String>[
            for (final member in members)
              if (!member.outcome.ok) member.member.name,
          ],
        if (merged.isNotEmpty) 'merged': merged,
        if (warnings.isNotEmpty) 'warnings': warnings,
      };
}

/// 团队编排水位：按 blockedBy 分波，波内按写范围重叠分 lane，lane 间串行。
///
/// [writableNames] 是**真的会写**的成员名（类别含 write）。只有它们参与写范围
/// 重叠检测——只读成员不改任何东西，天然不会互相覆盖（2026-10-01 真机实测
/// C1：纯只读团队此前被全体判定「写范围重叠」强制串行，且调用侧无解）。
/// null = 不做这一层区分（旧行为，测试与未知类别时的保守口径）。
///
/// 返回每波每个 lane 的成员；纯函数，便于单测（含环检测）。
List<List<List<SubAgentTeamMember>>> planTeamWaves(
  List<SubAgentTeamMember> members, {
  Set<String>? writableNames,
}) {
  bool writes(SubAgentTeamMember member) =>
      writableNames == null || writableNames.contains(member.name);
  final byName = <String, SubAgentTeamMember>{
    for (final member in members) member.name: member,
  };
  final remaining = <String>{for (final member in members) member.name};
  final done = <String>{};
  final waves = <List<List<SubAgentTeamMember>>>[];

  while (remaining.isNotEmpty) {
    final ready = <SubAgentTeamMember>[
      for (final name in remaining)
        if (byName[name]!.blockedBy.every(done.contains)) byName[name]!,
    ];
    if (ready.isEmpty) {
      throw StateError(
        '成员依赖成环或引用了不存在的成员：${remaining.join(', ')}',
      );
    }
    // 写范围重叠的成员进不同 lane（lane 之间串行执行）。
    final lanes = <List<SubAgentTeamMember>>[];
    for (final member in ready) {
      var placed = false;
      for (final lane in lanes) {
        // 只读成员不参与重叠判定：它们永远可以与任何人同 lane 并行。
        final overlaps = writes(member) &&
            lane.any(
              (other) =>
                  writes(other) &&
                  _scopesOverlap(member.writeScope, other.writeScope),
            );
        if (!overlaps) {
          lane.add(member);
          placed = true;
          break;
        }
      }
      if (!placed) lanes.add(<SubAgentTeamMember>[member]);
    }
    waves.add(lanes);
    for (final member in ready) {
      remaining.remove(member.name);
      done.add(member.name);
    }
  }
  return waves;
}

/// 两个写范围是否可能撞车。空列表 = 整个工作目录（与谁都重叠）。
bool _scopesOverlap(List<String> a, List<String> b) {
  if (a.isEmpty || b.isEmpty) return true;
  for (final left in a) {
    for (final right in b) {
      final l = left.replaceAll('\\', '/');
      final r = right.replaceAll('\\', '/');
      if (l.startsWith(r) || r.startsWith(l)) return true;
    }
  }
  return false;
}

/// 跑一支专家团。
///
/// [definitions] 是已解析好的 slug → 定义（调用方负责先做存在性/域/审批校验），
/// 这样编排层不碰注册表，单测可以直接喂假定义。
Future<SubAgentTeamOutcome> runSubAgentTeam({
  required String teamName,
  required String goal,
  required List<SubAgentTeamMember> members,
  required Map<String, SubAgentDefinition> definitions,
  required SubAgentRunner runner,
  required String? conversationId,
  String? mainSystemPrompt,
  void Function(String memberName, String stage)? onStage,
}) async {
  // 「会写」的成员才参与写范围重叠检测（C1：只读团队不该被串行）。
  final writableNames = <String>{
    for (final member in members)
      if (definitions[member.agent]
              ?.categories
              .contains(SubAgentCategory.write) ??
          false)
        member.name,
  };
  final waves = planTeamWaves(members, writableNames: writableNames);
  final results = <SubAgentTeamMemberResult>[];
  final warnings = <String>[];
  // 用户中止后不再派发后面的成员：已派发的在各自步骤边界收口（见 subagent_loop）。
  var aborted = false;

  for (final lanes in waves) {
    if (aborted) break;
    for (final lane in lanes) {
      if (aborted) break;
      // lane 内再按并行度切块：同一块一起跑，块与块之间串行。
      for (var start = 0; start < lane.length; start += kTeamParallelLimit) {
        if (aborted) break;
        final batch = lane.sublist(
          start,
          (start + kTeamParallelLimit).clamp(0, lane.length),
        );
        final batchResults = await Future.wait(
          batch.map((member) async {
            onStage?.call(member.name, '启动');
            final definition = definitions[member.agent]!;
            final outcome = await runner.run(
              SubAgentRunRequest(
                definition: definition,
                task: member.task,
                context: _memberContext(goal, members, results, member),
                label: member.name,
                conversationId: conversationId,
                mainSystemPrompt: mainSystemPrompt,
                bypassConcurrencyGate: true,
              ),
            );
            return SubAgentTeamMemberResult(
              member: member,
              definition: definition,
              outcome: outcome,
              serializedForScope: _hasScopePeers(
                members,
                member,
                writableNames: writableNames,
              ),
            );
          }),
        );
        results.addAll(batchResults);
        if (batchResults.any(
          (result) => result.outcome.status == SubAgentStatus.cancelled,
        )) {
          aborted = true;
        }
      }
    }
  }

  if (aborted) {
    final dispatched = <String>{for (final result in results) result.member.name};
    final pending = <String>[
      for (final member in members)
        if (!dispatched.contains(member.name)) member.name,
    ];
    warnings.add(
      pending.isEmpty
          ? '用户已中止这次专家团运行：已派发的成员就地收口。'
          : '用户已中止这次专家团运行：余下成员（${pending.join('、')}）未派发。',
    );
  }

  for (final result in results) {
    if (result.serializedForScope) {
      warnings.add(
        '成员「${result.member.name}」的写范围与其他成员重叠：已串行执行，避免互相覆盖。',
      );
    }
    if (!result.outcome.ok) {
      warnings.add(
        '成员「${result.member.name}」未成功（${result.outcome.status.name}）：'
        '${result.outcome.error ?? '没有结论'}',
      );
    }
  }

  final merged = StringBuffer();
  for (final result in results) {
    merged.writeln('## ${result.member.name}（${result.definition.slug}）');
    final text = result.outcome.text.trim();
    if (text.isNotEmpty) {
      merged.writeln(text);
    } else {
      merged.writeln('（未产出结论：${result.outcome.error ?? result.outcome.status.name}）');
    }
    merged.writeln();
  }

  return SubAgentTeamOutcome(
    teamName: teamName,
    members: results,
    merged: merged.toString().trim(),
    warnings: warnings,
  );
}

/// 团队成员实授工具名（与单发返回的 grantedTools 同口径：类别 ∩ 助手工具，
/// 技能读取工具计入）。这里没有助手上下文，按定义类别算上限集。
List<String> _grantedToolsFor(SubAgentDefinition definition) {
  final names = SubAgentRegistry.toolNamesFor(
    definition.categories,
    skills: definition.enabledSkills,
  ).toList(growable: false)
    ..sort();
  return names;
}

bool _hasScopePeers(
  List<SubAgentTeamMember> members,
  SubAgentTeamMember member, {
  Set<String>? writableNames,
}) {
  if (writableNames != null && !writableNames.contains(member.name)) {
    return false; // 只读成员不写任何东西，不存在「写范围被串行」这回事。
  }
  for (final other in members) {
    if (identical(other, member)) continue;
    if (writableNames != null && !writableNames.contains(other.name)) continue;
    if (_scopesOverlap(member.writeScope, other.writeScope)) return true;
  }
  return false;
}

/// 下游成员能看到上游结论（简化版 mailbox）：只带已完成成员的结论摘要。
String _memberContext(
  String goal,
  List<SubAgentTeamMember> all,
  List<SubAgentTeamMemberResult> results,
  SubAgentTeamMember member,
) {
  final buffer = StringBuffer();
  final trimmedGoal = goal.trim();
  if (trimmedGoal.isNotEmpty) {
    buffer.writeln('团队总目标：$trimmedGoal');
  }
  final upstream = <String>[];
  for (final name in member.blockedBy) {
    for (final result in results) {
      if (result.member.name != name) continue;
      final text = result.outcome.text.trim();
      upstream.add(
        '### $name（${result.definition.slug}，${result.outcome.status.name}）\n'
        '${text.isEmpty ? '（无结论）' : text}',
      );
    }
  }
  if (upstream.isNotEmpty) {
    buffer.writeln('\n上游成员结论：');
    buffer.writeAll(upstream, '\n');
  }
  return buffer.toString().trim();
}
