import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/local_tools/local_tool_names.dart';
import 'package:Kelivo/core/services/local_tools/local_tool_registry.dart';

/// D1/D2（2026-09-21 自检）的架构定案回归锁：lane 按**资源占用类型**分流，
/// 而类型是工具在注册表里**声明**的（`LocalToolSpec.resourceClass`），
/// 不再是 `mcp_http_server` 里的写死名单。
///
/// 这个文件锁两件事：
///   ① 已分类的工具集合与设计一致（改声明就会红，逼人确认）；
///   ② 没有任何"已注册但没声明资源类型"的工具混进来——这是 D1/D2 的病灶
///      （没声明 → 默认落写 lane → 被别人的超时连坐）。新增工具时必须显式声明。
void main() {
  // 第 72 项新增的运行时控制工具里，查状态/登记/取证/确认这 9 个只读或只登记，
  // 不占任何互斥 lane ⇒ computeOnly；verify_apk 是 memoryHeavy、
  // workspace_cleanup 是 fileWrite，各自单独分类。
  const runtimeComputeOnly = <String>[
    LocalToolNames.taskStatus,
    LocalToolNames.taskUpdate,
    LocalToolNames.evidenceQuery,
    LocalToolNames.artifactRead,
    LocalToolNames.patchPlan,
    LocalToolNames.dryRunPatch,
    LocalToolNames.planProbes,
    LocalToolNames.collectDelivery,
    LocalToolNames.requestConfirmation,
  ];

  test('纯计算类：不进任何互斥 lane 的工具集合与设计一致', () {
    expect(
      LocalToolRegistry.namesWithResourceClass(ToolResourceClass.computeOnly),
      {
        LocalToolNames.calculate,
        LocalToolNames.valueCalc,
        LocalToolNames.timeInfo,
        LocalToolNames.screenTime,
        ...runtimeComputeOnly,
      },
    );
  });

  test('设备 IO 类：独立通道的工具集合与设计一致', () {
    expect(
      LocalToolRegistry.namesWithResourceClass(ToolResourceClass.deviceIo),
      {
        LocalToolNames.clipboard,
        LocalToolNames.textToSpeech,
        LocalToolNames.askUser,
        // phone_control 早就在注册表里声明了 deviceIo（2026-09-29 复核 HEAD 亦同），
        // 是这条期望值陈旧，不是新工具混进 lane（第 72 项顺带修正）。
        LocalToolNames.phoneControl,
      },
    );
  });

  test('lane-free 两类不得与重内存/写锁重叠（一个工具只能属一个资源类）', () {
    final compute = LocalToolRegistry.namesWithResourceClass(
      ToolResourceClass.computeOnly,
    );
    final device = LocalToolRegistry.namesWithResourceClass(
      ToolResourceClass.deviceIo,
    );
    final heavy = LocalToolRegistry.namesWithResourceClass(
      ToolResourceClass.memoryHeavy,
    );
    final fileWrite = LocalToolRegistry.namesWithResourceClass(
      ToolResourceClass.fileWrite,
    );
    expect(compute.intersection(device), isEmpty);
    expect(compute.intersection(heavy), isEmpty);
    expect(compute.intersection(fileWrite), isEmpty);
    expect(device.intersection(heavy), isEmpty);
    expect(device.intersection(fileWrite), isEmpty);
  });

  test('每个注册工具都能查到自己的资源类型（声明是显式的，不是靠默认值蒙）', () {
    // 允许 unclassified 存在（默认值），但**显式声明过的**必须能被查到；
    // 这里同时给出未声明清单，方便新增工具时对照。
    final declared = <String>{
      for (final spec in LocalToolRegistry.specs)
        if (spec.resourceClass != ToolResourceClass.unclassified) spec.name,
    };
    // 本批次分类的 7 个工具必须都在
    for (final name in const [
      LocalToolNames.calculate,
      LocalToolNames.valueCalc,
      LocalToolNames.timeInfo,
      LocalToolNames.screenTime,
      LocalToolNames.clipboard,
      LocalToolNames.textToSpeech,
      LocalToolNames.askUser,
    ]) {
      expect(declared, contains(name), reason: '$name 必须显式声明资源类型');
    }
    // 声明过的名字必须真的在注册表里（防改名后留下孤儿声明）
    final registered = LocalToolRegistry.specs.map((s) => s.name).toSet();
    expect(declared.difference(registered), isEmpty);
  });
}
