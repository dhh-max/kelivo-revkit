import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import 'frida_gadget_sources.dart';
import 'frida_readiness.dart';

import '../../../core/services/local_tools/local_tool_names.dart';
import '../../solab_apk/services/apk_workspace_binding_service.dart';
import '../../solab_apk/services/apk_toolchain_service.dart';
import 'frida_sandbox_runtime.dart';

/// Frida gadget 工具面（宿主侧注入 + 沙盒侧驱动）。
///
/// 分工见 docs/架构方向-能力双边分配与Frida接入.md：
///  - 宿主：`status` / `install_gadget` / `inject`；
///  - 沙盒（Linux）：`open` / `hook` / `call` / `read` / `backtrace` / `close`，
///    由 [sandboxRuntime] 驱动（未装环境或未接线时明确报不可用）。
///
/// 越权面：读写一律限制在统一工作目录内（与 file_*/apk_* 同一铁律），
/// 只向 Kotlin 侧传「工作目录 + 纯文件名」，不做任何路径拼接后透传。
/// 沙盒运行期驱动的注册点：工作区工具服务在环境就绪时写入，frida 工具读取。
class FridaToolRuntime {
  const FridaToolRuntime._();

  static FridaSandboxRuntime? sandbox;
}

Future<String> handleFridaTool(Map<String, dynamic> args) async {
  const hostActions = {'status', 'install_gadget', 'inject'};
  const sandboxActions = {'open', 'hook', 'call', 'read', 'backtrace', 'close'};
  final action = (args['action'] ?? 'status').toString().trim();

  if (sandboxActions.contains(action)) {
    // 运行期动作走沙盒：宿主侧只管注入，驱动在 Linux 环境里跑 python frida
    // （PRoot 与设备共享网络命名空间，能直连 gadget 监听的 loopback 端口）。
    final runtime = FridaToolRuntime.sandbox;
    if (runtime == null) {
      return jsonEncode({
        'ok': false,
        'error': 'environment_not_ready',
        'message':
            'frida(action=$action) 需要 Linux 沙盒里的 python frida 客户端：'
            '先在「设置 → 工作区」安装 Linux 环境并装好 Python 依赖。',
        'recoverable': true,
        'nextActions': [
          {
            'action': 'call_tool',
            'tool': LocalToolNames.frida,
            'reason': '宿主侧不受影响：frida(action=status) 看 gadget 状态、'
                'frida(action=inject) 出注入版（再 apk_sign 安装）。',
          },
        ],
      });
    }
    final result = await runtime.run(action, args);
    return jsonEncode(result);
  }
  if (!hostActions.contains(action)) {
    return jsonEncode({
      'ok': false,
      'error': 'invalid_arguments',
      'message': 'action 仅支持 ${hostActions.join(' / ')}（运行期动作待沙盒就绪）',
    });
  }

  String? workDir;
  String? apkName;
  if (action == 'inject') {
    final dir = await ApkWorkspaceBindingService.workDir();
    if (dir == null || dir.isEmpty) {
      return jsonEncode({
        'ok': false,
        'error': 'workspace_not_set',
        'message': '工作目录未设置：请先在 APK 工作台设置统一工作目录',
      });
    }
    workDir = dir;
    final raw = (args['apkPath'] ?? args['apkName'] ?? '').toString().trim();
    if (raw.isEmpty) {
      return jsonEncode({
        'ok': false,
        'error': 'invalid_arguments',
        'message': 'apkPath is required（工作目录内的文件名）',
      });
    }
    // 与 file_*/apk_* 同一套门禁：绝对路径必须在工作目录内，相对路径不得含 ..
    final candidate = p.isAbsolute(raw)
        ? p.normalize(raw)
        : (raw.split('/').contains('..') || raw.split(r'\').contains('..'))
        ? ''
        : p.normalize(p.join(dir, raw));
    if (candidate.isEmpty ||
        !(p.equals(candidate, dir) || p.isWithin(dir, candidate))) {
      return jsonEncode({
        'ok': false,
        'error': 'PATH_OUTSIDE_WORKSPACE',
        'message': 'apkPath 越界（$raw）：读写必须限制在统一工作目录内（$dir）',
      });
    }
    apkName = p.basename(candidate);
    if (p.dirname(candidate) != p.normalize(dir)) {
      return jsonEncode({
        'ok': false,
        'error': 'PATH_OUTSIDE_WORKSPACE',
        'message': 'apkPath 必须位于工作目录根下（Kotlin 侧只接受工作目录 + 纯文件名）：$raw',
      });
    }
    if (!await File(candidate).exists()) {
      return jsonEncode({
        'ok': false,
        'error': 'file_not_found',
        'message': 'apkPath does not exist: $raw',
      });
    }
  }

  // 报告 ⑤：GitHub 不可达时 install_gadget 不能只有一条死路。这里把候选源
  // 交给 Kotlin 侧按序尝试（sha256 校验不变），并允许调用方显式给 source=镜像。
  final sources = action == 'install_gadget'
      ? FridaGadgetSources.resolve(source: args['source']?.toString())
      : null;

  final result = await ApkToolchainService.frida(
    action: action,
    sources: sources,
    workDir: workDir,
    apkName: apkName,
  );
  final payload = <String, dynamic>{'ok': result.ok};
  final data = result.data;
  if (data is Map) {
    data.forEach((key, value) => payload[key.toString()] = value);
  }
  final runtime = FridaToolRuntime.sandbox;
  Map<String, dynamic>? clientStatus;
  if (action == 'status') {
    payload['sandboxDriver'] = runtime == null
        ? <String, dynamic>{
            'available': false,
            'reason': '未安装 Linux 环境（或工作区未绑定）：open/hook/call/read/backtrace/close 不可用',
          }
        : <String, dynamic>{'available': true, ...await runtime.clientStatus()};
    clientStatus = payload['sandboxDriver'] as Map<String, dynamic>?;
  }

  // ⑤-c：把两侧状态合成一句可执行的诊断。真机实测里测试者在 rootfs 装了 python
  // frida 客户端后仍不通，因为**客户端与 gadget 是两条独立链路**——需要一句话说清
  // 「缺哪一侧、下一步做什么」，而不是让人对着两段状态自己推。
  if (action == 'status' || action == 'install_gadget') {
    final gadget = payload['gadget'];
    final gadgetPresent = gadget is Map
        ? gadget['present'] == true
        : payload['ok'] == true && action == 'install_gadget';
    final archive = payload['archive'];
    payload['diagnosis'] = FridaReadiness.diagnose(
      gadgetPresent: gadgetPresent,
      sandboxDriverAvailable: runtime != null,
      // F-46（2026-10-04）：key 错位修正——沙盒探测把版本写在
      // `sandboxFridaVersion`（frida_sandbox_runtime.dart），这里过去读
      // `version`（恒 null），于是同一条回执里一边"版本未知"一边 17.20.0。
      clientVersion: clientStatus?['sandboxFridaVersion']?.toString(),
      gadgetSha256: gadget is Map ? gadget['sha256']?.toString() : null,
      // F-46：归档在场与 pinned 版本一并给诊断——归档在本地时指引改走 localPath。
      archivePresent: archive is Map && archive['present'] == true,
      pinnedVersion: payload['pinnedVersion']?.toString(),
    );
  }
  return jsonEncode(payload);
}
