/// 阶段化能力清单（§6.4）与高风险门控（§18.3）。
///
/// 不同阶段只向模型暴露当前需要的能力：减少上下文体积和工具选择错误。
///
/// 表里的名字只允许三类（契约测试 test/features/runtime/capability_manifest_contract_test.dart
/// 会把这条钉住）：
/// 1. **发布名**：工作台 tools/list 里真实存在的工具（[LocalToolNames]）；
/// 2. **运行时动作**：只在 Agent 运行时存在、由 runtime_tools.dart 分发的动作
///    （task_status / plan_probes / verify_apk …），MCP 面由
///    RecoveryEngine._mcpActionAliases 翻译或 _agentOnlyActions 丢弃；
/// 3. **内部动作名**：引擎内部执行器的 action（set_work_dir / analyze_apk 是
///    so_analyze 的 action；scan_signature_check 由 run_task_command 执行；
///    list_lib_entries 等价 apk_archive；field_xref 是 analyzer.find_field_usage
///    的内部名），它们出现在建议里就必须留在白名单里，否则 filterByPhase 会把
///    建议连同能力一起裁掉。
///
/// 历史缺陷（2026-09-28 审查）：本文件曾把 solab-app 的旧名当发布名，例如
/// sign_apk（真名 apk_sign）、list_apks / get_report / file_ops / install_apk
/// （都不是工具名）——裁剪等于把工具藏没了，门控则永不命中。
library;

import '../../core/services/local_tools/local_tool_names.dart';
import 'models/task.dart';

/// 工具分层（§7.1）。
enum ToolLayer {
  /// 面向任务的高价值入口。
  direct,

  /// 探索、定位、补证据。
  probe,

  /// 系统内部确定性能力，默认不暴露给模型。
  primitive,
}

/// 能力清单：按阶段给出允许暴露的工具名。
class CapabilityManifest {
  CapabilityManifest._();

  /// 控制类工具（§7.4 核心控制）：任何阶段都可用。
  ///
  /// 它们不改 APK，只改任务状态或读运行时数据，所以不做阶段裁剪——
  /// 模型任何时候都要能查状态、问用户、读产物、看证据。
  static const control = <String>{
    LocalToolNames.taskStatus,
    LocalToolNames.taskUpdate,
    LocalToolNames.routeTask,
    LocalToolNames.evidenceQuery,
    LocalToolNames.artifactRead,
    LocalToolNames.requestConfirmation,
    LocalToolNames.planProbes,
    LocalToolNames.verifyApk,
    LocalToolNames.collectDelivery,
    LocalToolNames.workspaceCleanup,
    // 第 72 项：登记修改计划与修改前检查同样是控制类（不改 APK，只登记计划、
    // 跑 Dry Run），任何阶段都该能提计划、做检查，否则流程卡在「查完了但
    // 进不了修改阶段」。
    LocalToolNames.patchPlan,
    LocalToolNames.dryRunPatch,
  };

  /// 准备阶段：确认工作区与目标 APK 身份。
  static const prepare = <String>{
    // 内部动作名：so_analyze 的 action（工作目录由绑定服务钉死，模型改不动）。
    'set_work_dir',
    LocalToolNames.apkAnalyzeWorkspace,
    LocalToolNames.apkListWorkspace,
    LocalToolNames.apkProjectInfo,
    LocalToolNames.apkReport,
    LocalToolNames.apkPatchMemory,
    LocalToolNames.file,
  };

  /// 分析阶段：粗看一遍，不深挖。
  static const analyze = <String>{
    LocalToolNames.apkAnalyzeWorkspace,
    // 内部拼写：分派前会归一，运行层仍可能看到旧写法（task_session._analyzeTools）。
    'analyze_apk',
    // 内部动作名：由 run_task_command 执行；MCP 面走 _mcpActionAliases 翻译。
    'scan_signature_check',
    LocalToolNames.stringScan,
    LocalToolNames.apkArchive,
    // 内部动作名：等价 apk_archive。
    'list_lib_entries',
    LocalToolNames.dexSearch,
    LocalToolNames.classOutline,
    LocalToolNames.jadxDecompile,
    LocalToolNames.soAnalyze,
    LocalToolNames.apkReport,
    LocalToolNames.apkProjectInfo,
    LocalToolNames.apkPatchMemory,
    LocalToolNames.apkSavePatchMemory,
    LocalToolNames.apkListBuilds,
    LocalToolNames.file,
  };

  /// 定位阶段：钻到方法级。
  static const locate = <String>{
    LocalToolNames.dexSearch,
    LocalToolNames.classOutline,
    LocalToolNames.jadxDecompile,
    LocalToolNames.smaliRead,
    LocalToolNames.dexXref,
    // analyzer.find_field_usage 的内部名；发布名两种拼写都列（task_session 同口径）。
    'field_xref',
    'analyzer.find_field_usage',
    'analyzer_find_field_usage',
    LocalToolNames.stringScan,
    LocalToolNames.apkArchive,
    'list_lib_entries',
    LocalToolNames.soAnalyze,
    LocalToolNames.apkReport,
    LocalToolNames.apkPatchMemory,
    LocalToolNames.apkListBuilds,
    LocalToolNames.file,
  };

  /// 修改阶段：能改，也能回读确认（§14.5）。
  static const modify = <String>{
    'patch_apk_dex_methods',
    'patch_apk_dex_strings',
    'patch_apk_manifest',
    'signature_bypass',
    'so_patch_into_apk',
    'apk_rebuild',
    // 改完紧接着就是构建、签名、装机验证（§15）：这几个工具必须在修改阶段
    // 就可见，否则流程会卡在「改完了但签不了」，只能靠用户重开任务。
    LocalToolNames.apkSign,
    // 真实装机入口：run_task_command(command=VERIFY_ARTIFACT, install=true)。
    // 没有 install_apk 这个工具，授权由 denialReason(args:) 参数级门控。
    LocalToolNames.runTaskCommand,
    'scan_signature_check',
    LocalToolNames.smaliRead,
    LocalToolNames.classOutline,
    LocalToolNames.dexXref,
    'field_xref',
    LocalToolNames.apkReport,
    LocalToolNames.apkListBuilds,
    LocalToolNames.apkPatchMemory,
    LocalToolNames.apkSavePatchMemory,
    LocalToolNames.file,
  };

  /// 交付阶段。
  static const deliver = <String>{
    LocalToolNames.apkSign,
    LocalToolNames.runTaskCommand,
    'scan_signature_check',
    LocalToolNames.apkListBuilds,
    LocalToolNames.apkCleanupBuilds,
    LocalToolNames.apkProjectInfo,
    LocalToolNames.apkPatchMemory,
    LocalToolNames.apkSavePatchMemory,
    LocalToolNames.file,
  };

  /// 阶段 → 允许的工具名集合。
  static Set<String> forPhase(TaskPhase phase) {
    switch (phase) {
      case TaskPhase.prepare:
        return prepare;
      case TaskPhase.analyze:
        return analyze;
      case TaskPhase.locate:
        return locate;
      case TaskPhase.modify:
        return modify;
      case TaskPhase.deliver:
        return deliver;
    }
  }

  /// 需要显式授权才能执行的工具（§18.3 高风险操作清单）。
  ///
  /// value 是 [TaskConstraints] 上的字段名。Runtime 在调用前检查，
  /// Prompt 不能越过（§18.2「Prompt 不能授予工具权限」）。
  ///
  /// 键必须是**真实发布名**：安装没有独立工具（旧表的 install_apk 是幽灵名，
  /// allowInstall 因此永不命中），它按参数门控，见 [denialReason] 的 args。
  static const highRisk = <String, String>{
    'patch_apk_dex_methods': 'allowModification',
    'patch_apk_dex_strings': 'allowModification',
    'patch_apk_manifest': 'allowModification',
    'signature_bypass': 'allowModification',
    'so_patch_into_apk': 'allowModification',
    'apk_rebuild': 'allowModification',
    LocalToolNames.apkSign: 'allowSigning',
  };

  /// 工具成本（§12.3 探针建议成本）。
  ///
  /// 不是绝对耗时，用来控制探索预算和比较相对代价。
  static int costOf(String tool) => _costs[tool] ?? 1;

  static const Map<String, int> _costs = {
    // STRING = 1，CLASS / METHOD = 1
    LocalToolNames.stringScan: 1,
    LocalToolNames.dexSearch: 1,
    LocalToolNames.classOutline: 1,
    LocalToolNames.apkListWorkspace: 1,
    LocalToolNames.apkReport: 1,
    LocalToolNames.apkProjectInfo: 1,
    'set_work_dir': 1,
    LocalToolNames.file: 1,
    LocalToolNames.apkArchive: 1,
    'list_lib_entries': 1,
    LocalToolNames.apkListBuilds: 1,
    // FIELD_USAGE = 2
    'field_xref': 2,
    LocalToolNames.apkAnalyzeWorkspace: 2,
    'analyze_apk': 2,
    'scan_signature_check': 2,
    // XREF = 3
    LocalToolNames.dexXref: 3,
    LocalToolNames.soAnalyze: 3,
    // METHOD_BODY = 5
    LocalToolNames.smaliRead: 5,
    LocalToolNames.jadxDecompile: 5,
    // BEHAVIOR_VERIFY = 8
    LocalToolNames.apkSign: 8,
    // 装机验证链（run_task_command install=true）才是真 Behavior 验证。
    LocalToolNames.runTaskCommand: 8,
    LocalToolNames.apkPatchDex: 8,
    LocalToolNames.apkPatchDexStrings: 8,
    LocalToolNames.apkPatchManifest: 8,
    LocalToolNames.apkSignatureBypass: 8,
    LocalToolNames.soPatchIntoApk: 8,
    LocalToolNames.apkRebuild: 8,
  };

  /// 参数级安装门控：只有显式 install=true 的调用需要 allowInstall。
  static String? _installFlagFor(String tool, Map<String, dynamic> args) {
    if (args['install'] != true) return null;
    return _installArgTools.contains(tool) ? 'allowInstall' : null;
  }

  /// 装机授权门控的工具集：安装不是独立工具，而是这两个工具的 install 参数。
  ///
  /// run_task_command(command=VERIFY_ARTIFACT, install=true) 是真实装机路径
  /// （ApkTaskChainService._runVerifyArtifact → ApkToolchainService.installApk）；
  /// apk_sign(install=true) 只是「签名后请用户装并回报」的等待点。
  static const Set<String> _installArgTools = <String>{
    LocalToolNames.runTaskCommand,
    LocalToolNames.apkSign,
  };

  /// 判断某个工具在当前约束下是否放行。
  ///
  /// 返回 null 表示放行，否则返回拒绝原因。
  ///
  /// [args] 用于**参数级**门控：表里的键按工具名索引，而安装挂在参数上（见
  /// [_installArgTools]）。旧实现把 allowInstall 挂在幽灵名 install_apk 上，
  /// 于是「未授权安装」这道闸门对任何真实调用都不命中（2026-09-28 §18.3 复核）。
  static String? denialReason(
    String tool,
    TaskConstraints c, {
    Map<String, dynamic> args = const {},
  }) {
    // 两道授权可能同时命中：apk_sign(install:true) 既要 allowSigning
    // （签名本身）又要 allowInstall（把产物装到设备上），逐条检查。
    final flags = <String>[];
    final risk = highRisk[tool];
    if (risk != null) flags.add(risk);
    final install = _installFlagFor(tool, args);
    if (install != null) flags.add(install);
    if (flags.isEmpty) {
      // 外部 MCP 工具（mcp__ 前缀）默认关闭（§18.2）。
      if (tool.startsWith('mcp__') && !c.allowExternalMcp) {
        return '外部 MCP 工具默认关闭，需要任务显式授权外部工具';
      }
      return null;
    }
    for (final flag in flags) {
      final allowed = switch (flag) {
        'allowModification' => c.allowModification,
        'allowSigning' => c.allowSigning,
        'allowInstall' => c.allowInstall,
        _ => false,
      };
      if (!allowed) return _denialMessage(flag);
    }
    return null;
  }

  static String _denialMessage(String flag) => switch (flag) {
    'allowModification' => '该任务未授权修改 APK，需要用户先确认改动范围',
    'allowSigning' => '该任务未授权签名，需要用户先确认',
    'allowInstall' => '该任务未授权安装到设备，需要用户先确认',
    _ => '该操作需要显式授权',
  };
}
