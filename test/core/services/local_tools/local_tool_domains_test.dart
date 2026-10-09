import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/local_tools/local_tool_domains.dart';
import 'package:Kelivo/core/services/local_tools/local_tool_names.dart';
import 'package:Kelivo/core/services/local_tools/local_tool_registry.dart';
import 'package:Kelivo/features/dev_assistant/builtin_dev_assistant.dart';

/// 能力域划分：覆盖完整、互不重叠；开发助手拿到通用层且不含逆向域。
void main() {
  test('三个域覆盖全部本地工具且互不重叠', () {
    final all = LocalToolDomains.all.toSet();
    final general = LocalToolDomains.toolsOf(LocalToolDomain.general).toSet();
    final device = LocalToolDomains.toolsOf(LocalToolDomain.device).toSet();
    final reverse = LocalToolDomains.toolsOf(LocalToolDomain.apkReverse).toSet();

    expect(general.intersection(device), isEmpty);
    expect(general.intersection(reverse), isEmpty);
    expect(device.intersection(reverse), isEmpty);
    expect(general.union(device).union(reverse), all,
        reason: '每个注册工具都必须落进某个域');
  });

  test('逆向域与设备域只包含注册表里真实存在的工具名', () {
    final all = LocalToolDomains.all.toSet();
    for (final name in LocalToolDomains.apkReverseTools) {
      expect(all, contains(name), reason: '$name 应在注册表里');
    }
    for (final name in LocalToolDomains.deviceTools) {
      expect(all, contains(name), reason: '$name 应在注册表里');
    }
  });

  test('of() 判定与集合一致', () {
    expect(
      LocalToolDomains.of(LocalToolNames.apkRebuild),
      LocalToolDomain.apkReverse,
    );
    expect(
      LocalToolDomains.of(LocalToolNames.calendarQuery),
      LocalToolDomain.device,
    );
    expect(LocalToolDomains.of(LocalToolNames.file), LocalToolDomain.general);
    expect(
      LocalToolDomains.of(LocalToolNames.apkSkill),
      LocalToolDomain.general,
      reason: '技能读取是通用能力，逆向助手与开发助手都该有',
    );
  });

  test('开发助手用上通用层：能读技能/看工具地图/管任务/整理交付', () {
    final ids = BuiltinDevAssistant.toolIds.toSet();
    for (final required in <String>[
      LocalToolNames.apkToolMap,
      LocalToolNames.apkSkill,
      LocalToolNames.installedSkills,
      LocalToolNames.taskStatus,
      LocalToolNames.taskUpdate,
      LocalToolNames.collectDelivery,
      LocalToolNames.workspaceCleanup,
      LocalToolNames.requestConfirmation,
      LocalToolNames.file,
      LocalToolNames.todoWrite,
      LocalToolNames.subagent,
      LocalToolNames.runWorkflow,
    ]) {
      expect(ids, contains(required), reason: '开发助手缺少 $required');
    }
  });

  test('开发助手不挂逆向域与设备域工具', () {
    final ids = BuiltinDevAssistant.toolIds.toSet();
    expect(ids.intersection(LocalToolDomains.apkReverseTools), isEmpty);
    expect(ids.intersection(LocalToolDomains.deviceTools), isEmpty);
  });

  test('开发助手的每个工具名都真实注册在册（不出现挂不上的假工具）', () {
    final all = LocalToolDomains.all.toSet();
    for (final id in BuiltinDevAssistant.toolIds) {
      expect(all, contains(id), reason: '$id 不在本地工具注册表里');
    }
    expect(
      BuiltinDevAssistant.toolIds.toSet().length,
      BuiltinDevAssistant.toolIds.length,
      reason: '不能重复登记',
    );
  });

  test('recommendedFor 按域拼装', () {
    final generalOnly = LocalToolDomains.recommendedFor(
      includeApkReverse: false,
    );
    expect(generalOnly.toSet(), LocalToolDomains.toolsOf(LocalToolDomain.general).toSet());

    final withReverse = LocalToolDomains.recommendedFor(
      includeApkReverse: true,
    );
    expect(withReverse.length, greaterThan(generalOnly.length));
    expect(withReverse.toSet().containsAll(LocalToolDomains.apkReverseTools), isTrue);

    final all = LocalToolDomains.recommendedFor(
      includeApkReverse: true,
      includeDevice: true,
    );
    expect(all.toSet(), LocalToolDomains.all.toSet());
  });
}
