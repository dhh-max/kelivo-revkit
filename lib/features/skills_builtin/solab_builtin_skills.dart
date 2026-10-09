import 'dart:convert';

import '../dev_assistant/builtin_dev_assistant.dart';
import '../dev_assistant/services/solab_dev_skills.dart';
import '../solab_apk/assistant/builtin_assistant.dart';
import '../solab_apk/services/solab_apk_skills.dart';
import 'solab_general_skills.dart';

/// 内置技能注册表（SoLab 自研，随包发布、只读）。
///
/// 与世界书同一套思路，**分「通用」与「助手级」两层**：
/// - **通用**（[globalNames]）：与具体技术栈无关的方法论，对**所有助手**生效；
/// - **助手级**（[assistantSkillNames]）：只在对应内置 agent 下可见
///   （逆向助手 → APK 侦察/定位/验证/改包；开发助手 → Android/Flutter/Web/接口）。
///
/// 工具侧（`get_solab_skill` 的 enum、读取、激活）走**并集按 id 分发**：
/// 技能 id 全局唯一，按 id 就能定位到所属那套；面板按「通用 / 当前助手专属」分组展示。
class SolabBuiltinSkills {
  const SolabBuiltinSkills._();

  /// 通用技能：所有助手都能看到（与栈无关的工程方法论）。
  static const List<String> globalNames = SolabGeneralSkills.skillNames;

  /// 助手级技能：只在对应 agent 下可见。
  static const Map<String, List<String>> assistantSkillNames =
      <String, List<String>>{
        BuiltinApkMod.assistantId: SolabApkSkills.skillNames,
        BuiltinDevAssistant.assistantId: SolabDevSkills.skillNames,
      };

  /// 助手级技能的展示名（面板分组用；切到任何助手都全量展示，只是分组不同）。
  static const Map<String, String> assistantDisplayNames = <String, String>{
    BuiltinApkMod.assistantId: '逆向助手',
    BuiltinDevAssistant.assistantId: '开发助手',
  };

  /// 面板用：内置技能的**全量分组**（通用 + 每个助手专属）。
  ///
  /// [assistantId] 为 null 表示通用组。面板按此**无条件全量展示**：用户切到任何
  /// 助手都看得到全部内置技能，只是分组标题不同（不是过滤）。
  static List<({String? assistantId, List<String> names})> get displayGroups =>
      <({String? assistantId, List<String> names})>[
        (assistantId: null, names: globalNames),
        for (final entry in assistantSkillNames.entries)
          (assistantId: entry.key, names: entry.value),
      ];

  /// 工具侧 enum 用的并集（顺序稳定：通用 → 逆向助手 → 开发助手）。
  static final List<String> unionNames = List<String>.unmodifiable(<String>[
    ...globalNames,
    ...SolabApkSkills.skillNames,
    ...SolabDevSkills.skillNames,
  ]);

  static final Map<String, String> _hints = <String, String>{
    ...SolabGeneralSkills.activationHints,
    ...SolabApkSkills.activationHints,
    ...SolabDevSkills.activationHints,
  };

  static final Map<String, List<String>> _rules = <String, List<String>>{
    ...SolabGeneralSkills.activationRules,
    ...SolabApkSkills.activationRules,
    ...SolabDevSkills.activationRules,
  };

  static Map<String, String> get activationHints => _hints;
  static Map<String, List<String>> get activationRules => _rules;

  /// 某个 agent 的**专属**技能（不含通用）。
  static List<String> assistantNamesFor(String? agentId) {
    final id = agentId?.trim() ?? '';
    final own = assistantSkillNames[id];
    if (own != null) return own;
    // 用户自建助手 / 未知 agent：它们是通用助手，专属面取两个内置 agent 的并集。
    return List<String>.unmodifiable(<String>[
      ...SolabApkSkills.skillNames,
      ...SolabDevSkills.skillNames,
    ]);
  }

  /// 面板与运行时用：该 agent 可见的全部内置技能 = 通用 + 专属。
  static List<String> visibleFor(String? agentId) => List<String>.unmodifiable(
    <String>[...globalNames, ...assistantNamesFor(agentId)],
  );

  /// 兼容旧调用名（等价于 [visibleFor]）。
  static List<String> namesFor(String? agentId) => visibleFor(agentId);

  /// 技能作用域：`general`（通用）/ `apk` / `dev`，未知返回 null。
  static String? scopeOf(String skill) {
    final id = skill.trim();
    if (globalNames.contains(id)) return 'general';
    if (SolabApkSkills.skillNames.contains(id)) return 'apk';
    if (SolabDevSkills.skillNames.contains(id)) return 'dev';
    return null;
  }

  static bool isGeneral(String skill) => scopeOf(skill) == 'general';

  static bool isBuiltin(String skill) => scopeOf(skill) != null;

  /// 读取技能正文（JSON 字符串）。未知技能返回空对象，调用方按「无此技能」处理。
  static String read(String skill) => switch (scopeOf(skill)) {
    'general' => SolabGeneralSkills.read(skill),
    'dev' => SolabDevSkills.read(skill),
    _ => SolabApkSkills.read(skill),
  };

  /// 激活信息（含 trigger 与规则），未知技能返回 null。
  static Map<String, dynamic>? activation(String skill) {
    final id = skill.trim();
    final scope = scopeOf(id);
    // 未知技能不激活：`SolabApkSkills.read` 对未知 id 会回一个 error 载荷，
    // 那是给工具调用方的错误说明，不是「可激活的内置技能」。
    if (scope == null) return null;
    final payload = jsonDecode(read(id));
    if (payload is! Map || payload.isEmpty) return null;
    return <String, dynamic>{
      'id': id,
      'name': payload['name'],
      'trigger': _hints[id],
      'scope': scope,
      'rules': _rules[id] ?? const <String>[],
      'fullSkillTool': 'get_solab_skill(skill=$id)',
    };
  }
}
