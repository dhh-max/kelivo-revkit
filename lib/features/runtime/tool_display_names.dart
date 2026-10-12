import '../../core/services/local_tools/local_tool_names.dart';

/// 工具调用名 → 用户能看懂的短标签。
///
/// 2026-09-29 体验修复：运行时状态条与弹层此前直接把调用名（例如
/// patch_apk_dex_methods）显示给用户，看不出"正在干什么"。
/// 未登记的工具回退原调用名——新增工具不会因为漏登记而显示空白。
String toolDisplayLabel(String tool) {
  final name = tool.trim();
  if (name.isEmpty) return name;
  return _labels[name] ?? name;
}

const Map<String, String> _labels = <String, String>{
  // APK 工作台
  LocalToolNames.apkAnalyzeWorkspace: '分析工作区',
  LocalToolNames.apkReport: '读分析报告',
  LocalToolNames.apkExportReport: '导出报告',
  LocalToolNames.apkProjectInfo: '当前 APK 项目',
  LocalToolNames.apkListWorkspace: '列出工作区 APK',
  LocalToolNames.routeTask: '路由任务',
  LocalToolNames.runTaskCommand: '执行任务命令',
  LocalToolNames.workspacePolicy: '读工作区策略',
  // 分析 / 定位
  LocalToolNames.dexSearch: 'DEX 搜索',
  LocalToolNames.dexXref: 'DEX 交叉引用',
  LocalToolNames.classOutline: '类轮廓',
  LocalToolNames.smaliRead: '读 smali',
  LocalToolNames.stringScan: '字符串扫描',
  LocalToolNames.jadxDecompile: 'JADX 反编译',
  LocalToolNames.apkArchive: '读 APK 条目',
  LocalToolNames.soAnalyze: 'SO 分析',
  // 修改 / 构建 / 签名
  LocalToolNames.apkPatchDex: '改 DEX 方法',
  LocalToolNames.apkPatchDexStrings: '改 DEX 字符串',
  LocalToolNames.apkSignatureBypass: '去签名校验',
  LocalToolNames.apkPatchManifest: '改 Manifest',
  LocalToolNames.soPatchIntoApk: 'SO 写回 APK',
  LocalToolNames.apkRebuild: '重建 APK',
  LocalToolNames.apkSign: '签名 APK',
  LocalToolNames.apkCleanupBuilds: '清理构建产物',
  LocalToolNames.apkListBuilds: '列构建产物',
  LocalToolNames.file: '文件操作',
  LocalToolNames.frida: 'Frida',
  // 规则 / 记忆 / 技能
  LocalToolNames.apkRules: '规则库',
  LocalToolNames.apkToolMap: '工具地图',
  LocalToolNames.apkKnowledge: 'APK 知识',
  LocalToolNames.apkSkill: 'SoLab 技能',
  LocalToolNames.installedSkills: '已装技能',
  LocalToolNames.agentRuntimeGuide: '运行时指南',
  LocalToolNames.apkPatchMemory: '读补丁经验',
  LocalToolNames.apkSavePatchMemory: '存补丁经验',
  LocalToolNames.apkRecordPatchVerification: '登记实机验证',
  LocalToolNames.apkNoteRead: '读笔记',
  LocalToolNames.apkNoteWrite: '写笔记',
  // 运行时控制面
  LocalToolNames.taskStatus: '任务状态',
  LocalToolNames.taskUpdate: '更新任务',
  LocalToolNames.evidenceQuery: '查证据',
  LocalToolNames.artifactRead: '读产物',
  LocalToolNames.patchPlan: '改包计划',
  LocalToolNames.dryRunPatch: '预演改动',
  LocalToolNames.planProbes: '规划探针',
  LocalToolNames.verifyApk: '验证 APK',
  LocalToolNames.collectDelivery: '汇总交付',
  LocalToolNames.workspaceCleanup: '清理工作区',
  LocalToolNames.requestConfirmation: '请求确认',
  // 通用
  LocalToolNames.valueCalc: '数值计算',
  LocalToolNames.calculate: '计算',
  LocalToolNames.timeInfo: '时间',
  LocalToolNames.clipboard: '剪贴板',
  LocalToolNames.currentLocation: '定位',
  LocalToolNames.weather: '天气',
  LocalToolNames.phoneControl: '手机控制',
  LocalToolNames.todoWrite: '写待办',
  LocalToolNames.todoRead: '读待办',
  LocalToolNames.subagent: '子代理',
  LocalToolNames.askUser: '询问用户',
  LocalToolNames.searchWeb: '联网搜索',
  LocalToolNames.getToolResult: '读工具结果',
  LocalToolNames.memoryRead: '读记忆',
  LocalToolNames.memoryUpdate: '写记忆',
};
