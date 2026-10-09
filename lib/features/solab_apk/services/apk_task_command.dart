import 'dart:convert';

import '../../../core/services/local_tools/local_tool_names.dart';

/// Direct Command 2.0（蓝图 v2.1 §5.2）：Task-level 程序预分流。
///
/// 「程序负责调度，LLM 负责判断」：对用户消息里的**明确单动作**（A 类），
/// 由纯规则（零 LLM）解析出 Task Command——首轮唯一业务工具 + 固定参数 +
/// 系统注入指令——LLM 只负责发出该次调用并如实转述结果，不再自拟
/// route_task → report → notes → memory → tool_map 准备链。
///
/// 边界：
/// - 只接 A 类；命中不了返回 null，完全走原路径（C 类行为不回退）。
/// - dryRun / confirm / previewToken / already-signed 拦截等安全纪律全部
///   留在工具 handler 内，本分流不绕过、不代填 confirm。
/// - 匹配极保守：短祈使句 + 显式动词 + 反问/分析类否定词一票否决。
class ApkTaskCommandMatch {
  const ApkTaskCommandMatch({
    required this.command,
    required this.tool,
    required this.args,
    required this.directive,
  });

  /// Task Command 名（蓝图首批 A 类：SIGN_CURRENT_APK / CLEAN_WORKSPACE /
  /// ANALYZE_CURRENT_APK / SIGNATURE_BYPASS / SO_ANALYZE_ONCE）。
  final String command;

  /// 首轮唯一业务工具（LocalToolNames 常量）。
  final String tool;

  /// 预解析参数（模型原样传递，不自拟）。
  final Map<String, Object?> args;

  /// `<apk_task_command>` 系统注入全文。
  final String directive;
}

/// 分类命中结果：命令名 + 按命令提取的参数。
class _Hit {
  const _Hit(
    this.command, {
    this.mode,
    this.aggressive = false,
    this.soPath,
    this.field,
    this.className,
    this.qid,
    this.semantic,
    this.install = false,
  });

  final String command;
  final String? mode;
  final bool aggressive;
  final String? soPath;

  /// B 类（FIELD_STATE_LOCATE）提取的目标。
  final String? field;
  final String? className;
  final String? qid;

  /// B 类（FIELD_CANDIDATE_MINE）：语义挖掘原文（链内自行展开关键词）。
  final String? semantic;

  /// VERIFY_ARTIFACT：是否附带设备侧安装（R9）。
  final bool install;
}

class ApkTaskCommandDispatcher {
  const ApkTaskCommandDispatcher._();

  /// 快速预检（纯同步、零 IO）：命中返回命令名；调用方据此再去取
  /// resumeState 并调用 [resolve]。未命中时调用方零额外开销。
  static String? quickMatch(String userText) => _classify(userText)?.command;

  /// 完整解析：命令 + 首轮工具 + 固定参数 + 注入指令。
  ///
  /// [resumeState] 须为会话作用域内的 `ApkWorkspaceBindingService
  /// .taskResumeState()` 结果。解析不出可执行前提（如去签找不到未改原包）
  /// 时返回 null，回落常规路径。
  static ApkTaskCommandMatch? resolve(
    String userText,
    Map<String, dynamic> resumeState,
  ) {
    final hit = _classify(userText);
    if (hit == null) return null;
    switch (hit.command) {
      case 'FIELD_STATE_LOCATE':
        return _match(
          command: hit.command,
          tool: LocalToolNames.runTaskCommand,
          args: <String, Object?>{
            'command': 'FIELD_STATE_LOCATE',
            if (hit.qid != null) 'fieldLocator': hit.qid!,
            'field': hit.field ?? '',
            if (hit.className != null) 'className': hit.className!,
            'apkPath': (resumeState['activeApk'] ?? '').toString(),
          },
          extra: '本命令是 B 类固定链：一次调用内由程序完成 FIELD_USAGE → '
              'WRITE_FIELD 优先 → METHOD_BODY（权威写入方 smali）→ caller 摘要，'
              '不要拆成多次探针调用，也不要先 route_task。\n'
              '返回 ok：只基于 evidence 与 llmJudgment 给出判断'
              '（支持/反驳/待验证）+ primary locator + 不确定点，状态报 Located。\n'
              '返回 failureReason=NO_WRITER：如实报告「只有读取、无写入方」，'
              '下一步建议在 nextActions 里选择，不自行补跑同类探针。\n'
              'apkPath 缺失或工作目录未设置时工具会返回结构化错误，如实转述。',
        );
      case 'FIELD_CANDIDATE_MINE':
        return _match(
          command: hit.command,
          tool: LocalToolNames.runTaskCommand,
          args: <String, Object?>{
            'command': 'FIELD_CANDIDATE_MINE',
            'semantic': hit.semantic ?? '',
            'apkPath': (resumeState['activeApk'] ?? '').toString(),
          },
          extra: '本命令是 B 类固定链：一次调用内由程序完成关键词展开 → '
              'DexKit 字段名/字符串双探针 → 候选类聚合 → class_outline 字段'
              '枚举 → 可改性打分，产出 fieldCandidates[]。不要拆成多次探针'
              '调用，也不要先 route_task。\n'
              '返回 fieldCandidates 非空：按 score/form 摘要前 3~5 条'
              '（fieldLocator + 形态 + 打分依据），请用户确认目标后再用 '
              'FIELD_STATE_LOCATE 深挖；本轮禁止直接修改任何字段。\n'
              '返回 failureReason=NO_CANDIDATES / DEX_SEARCH_FAILED：如实报告，'
              '建议用户补充更具体的语义描述（成员名/UI 文案）。\n'
              'Flutter 应用（flutterApp.detected=true）业务字段在 libapp.so，'
              'DEX 候选为空属正常现象，如实说明并建议改走 so_analyze blutter。',
        );
      case 'VERIFY_ARTIFACT':
        return _match(
          command: hit.command,
          tool: LocalToolNames.runTaskCommand,
          args: <String, Object?>{
            'command': 'VERIFY_ARTIFACT',
            'apkPath': (resumeState['activeApk'] ?? '').toString(),
            if (hit.install) 'install': true,
          },
          extra:
              '一次调用内程序化完成三项检查：产物存在 → 血缘正确（产物索引/活动链）→ '
              '签名有效（内置 ApkVerifier，R7）。不要拆成多次调用。\n'
              '${hit.install ? '三项检查 PASS 后自动发起系统安装：屏幕会弹出系统确认页，'
                  '由用户人工同意；安装 SUCCESS 才可声称 Verified。\n' : ''}'
              'verdict=PASS：报告「Signed、签名校验通过」并附证书指纹；\n'
              'failureReason=ARTIFACT_MISSING / SIGNATURE_INVALID / '
              'LINEAGE_UNTRACKED / INSTALL_*：如实报告，nextActions 由用户决定。\n'
              '状态口径：未请求安装或安装未完成时只到 Signed（待真机验证）；'
              '仅 deviceInstall=SUCCESS 才可声称 Verified（R9）。',
        );
      case 'SIGN_CURRENT_APK':
        // 不预填路径：由 handler 解析当前连续修改链目标，其「已签名成品
        // 需 confirm」防呆保持生效（真机实测教训）。
        return _match(
          command: hit.command,
          tool: LocalToolNames.apkSign,
          args: const <String, Object?>{},
          extra: '目标是当前连续修改链的 activeApk（由工具自行解析，不要自传路径）。\n'
              '返回 already_signed_confirm_required 时：目标已是签名成品，'
              '先向用户确认，用户同意后才允许在下一轮加 confirm=true 重签。',
        );
      case 'SIGNATURE_BYPASS':
        // 铁律：去签必须作用于未改原包。activeArtifact 存在时按
        // rootSource → source 优先级回溯原包；无链路时用 activeApk 本身。
        final artifact = resumeState['activeArtifact'];
        String originalPath = '';
        if (artifact is Map) {
          final root = (artifact['rootSource'] ?? '').toString().trim();
          final source = (artifact['source'] ?? '').toString().trim();
          if (root.isNotEmpty) originalPath = root;
          if (originalPath.isEmpty && source.isNotEmpty) originalPath = source;
        }
        if (originalPath.isEmpty) {
          originalPath = (resumeState['activeApk'] ?? '').toString().trim();
        }
        if (originalPath.isEmpty) return null;
        return _match(
          command: hit.command,
          tool: LocalToolNames.apkSignatureBypass,
          args: <String, Object?>{
            'apkPath': originalPath,
            if (hit.mode != null) 'mode': hit.mode!,
          },
          extra: 'apkPath 已由程序固定为未改原包，不要改动。\n'
              'mode 未传时使用工作台默认方案；返回 signature_bypass_disabled '
              '时如实转述，请用户在工作台选择去签方案，不要猜测 mode。\n'
              '返回 ok 且有 outputPath：继续调用 ${LocalToolNames.apkSign}'
              '(path=outputPath) 完成签名交付链后再汇报；'
              'dpatch 产物的 outputPath 是唯一后续修改输入（决策政策第 9 条）。',
        );
      case 'CLEAN_WORKSPACE':
        // 删除动作纪律：dryRun 预览 → 相同参数 + applyAfterPreview +
        // previewToken 执行，两步都保留（本分流不代填确认）。
        return _match(
          command: hit.command,
          tool: LocalToolNames.apkCleanupBuilds,
          args: <String, Object?>{
            'dryRun': true,
            if (hit.aggressive) 'aggressive': true,
          },
          extra: '本次首调固定 dryRun=true，只获取清理预览与 previewToken。\n'
              '随后必须立即以相同参数 + applyAfterPreview=true + '
              'previewToken=返回值 发起第二次调用执行；不得跳过预览直接删除。\n'
              '汇报清理条目数与释放体积。',
        );
      case 'SO_ANALYZE_ONCE':
        return _match(
          command: hit.command,
          tool: LocalToolNames.soAnalyze,
          args: <String, Object?>{'action': 'overview', 'path': hit.soPath},
          extra: 'path 由程序解析自用户消息（相对工作目录，工具会自动解析'
              '并开临时 workspace）。\n返回后一句话总结 SO 概览：架构 / JNI 导出面 / '
              '熵与加固难度评分 / 攻击面要点。如需更深证据由用户下一轮再指定。',
        );
      case 'ANALYZE_CURRENT_APK':
        return _match(
          command: hit.command,
          tool: LocalToolNames.apkAnalyzeWorkspace,
          args: const <String, Object?>{},
          extra: '不带 fileName：工具按工作区 resumable 链自行解析当前目标。\n'
              '返回 ok → 一句话状态结论（Analyzed），附 adSdkMatches / '
              'flutterDetected / reportFreshness 摘要；失败 → 原样转述结构化错误。',
        );
      default:
        return null;
    }
  }

  // ---- 内部：匹配规则 -----------------------------------------------------

  /// 疑问 / 探讨 / 多目标一票否决：A 类只接祈使句。
  /// （patch 用词边界：避免否决 dpatch 本身。）
  static final RegExp _rejectRe = RegExp(
    r'找到|定位|修改|补丁|\bpatch\b|在哪|哪个|哪些|怎么|如何|为什么|什么|'
    r'对比|区别|报告|建议|思路|方案|流程|步骤|教程|吗|呢|？|\?',
    caseSensitive: false,
  );

  static _Hit? _classify(String userText) {
    final t = userText.trim();
    if (t.isEmpty || t.length > 40) return null;

    // 0) B 类：明确目标 + 明确动作（字段状态定位）。先于 A 类否定词判定
    //    （'找到 X 的写入点' 含 '找到'）。缺字段或类目标时回落 C 类。
    if (RegExp(r'写入点|写入方|谁写入|哪里写|在哪里写').hasMatch(t)) {
      final qid = RegExp(
        r'L[\w/$-]+;->[\w$<>]+:[\w/$;\[]+',
      ).firstMatch(t)?.group(0);
      String? field;
      String? className;
      if (qid != null) {
        field = RegExp(r'->([\w$<>]+):').firstMatch(qid)?.group(1);
        className = RegExp(r'^L([\w/$-]+);').firstMatch(qid)?.group(1);
      } else {
        const stop = {
          'apk', 'so', 'dex', 'smali', 'ok', 'dp', 'dpatch', 'vip', 'svip',
          'ad', 'sdk', 'ui', 'id', 'url', 'http', 'https', 'api', 'json',
          'xml', 'flag', 'jni', 'vm',
        };
        for (final tok in RegExp(r'[A-Za-z_][A-Za-z0-9_]*').allMatches(t)) {
          final s = tok.group(0)!;
          if (stop.contains(s.toLowerCase())) continue;
          if (field == null && RegExp(r'^[a-z_]').hasMatch(s)) field = s;
          if (className == null &&
              RegExp(r'^[A-Z]').hasMatch(s) &&
              s.length >= 3) {
            className = s;
          }
          if (field != null && className != null) break;
        }
      }
      if (field != null && (qid != null || className != null)) {
        return _Hit(
          'FIELD_STATE_LOCATE',
          field: field,
          className: className,
          qid: qid,
        );
      }
      return null;
    }

    // 0b) B 类（FIELD_CANDIDATE_MINE）：语义字段候选挖掘。用户不指定具体
    //     字段名、只给语义（「哪些字段可能控制会员」）——先于 _rejectRe
    //     判定（'哪些' 在此语义下属挖掘触发词而非一票否决项）。
    if (RegExp(r'字段').hasMatch(t) &&
        RegExp(r'候选|挖掘|哪些|可能|相关|定位|找|识别').hasMatch(t)) {
      return _Hit('FIELD_CANDIDATE_MINE', semantic: t);
    }

    if (_rejectRe.hasMatch(t)) return null;
    // 1) 产物验证（VERIFY_ARTIFACT 固定链）。先于签名判定：'验证签名'
    //    含 '签名'，但意图是检查而非重签。文本含安装意图时附带设备侧安装。
    if (RegExp(r'验证|校验|检查|验签').hasMatch(t) &&
        RegExp(r'产物|成品|签名|安装包|apk', caseSensitive: false).hasMatch(t)) {
      return _Hit(
        'VERIFY_ARTIFACT',
        install: RegExp(r'安装|装上|装进去').hasMatch(t),
      );
    }
    // 2) 去签（先于签名：'去签名' 含 '签名'）。
    if (RegExp(r'去签|过签|dpatch', caseSensitive: false).hasMatch(t)) {
      String? mode;
      if (RegExp(r'dpatch|dp\s?签', caseSensitive: false).hasMatch(t)) {
        mode = 'dpatch';
      } else if (t.contains('原包')) {
        mode = 'original_apk';
      } else if (t.contains('普通')) {
        mode = 'normal';
      }
      return _Hit('SIGNATURE_BYPASS', mode: mode);
    }
    // 2) 签名。
    if (RegExp(r'签名|签一下|签个名').hasMatch(t)) {
      return _Hit('SIGN_CURRENT_APK');
    }
    // 3) SO 单次分析（先于整包分析：文本含 .so 指向）。
    final so =
        RegExp(r'[A-Za-z0-9_\-+.]+\.so\b', caseSensitive: false).firstMatch(t);
    if (so != null && RegExp(r'分析|解析|看一下|看看').hasMatch(t)) {
      return _Hit('SO_ANALYZE_ONCE', soPath: so.group(0));
    }
    // 4) 清理工作目录 / 产物。
    if (RegExp(r'清理|清空').hasMatch(t) &&
        RegExp(r'目录|工作区|产物|缓存|中间包').hasMatch(t)) {
      return _Hit(
        'CLEAN_WORKSPACE',
        aggressive: RegExp(r'彻底|深度|全部').hasMatch(t),
      );
    }
    // 4b) 安装意图（VERIFY_ARTIFACT + install=true：先三项检查再系统安装，
    //     安装由用户在系统确认页人工同意）。排除名词'安装包'所在的分析/
    //     清理/去签句式。
    if (RegExp(r'安装|装上|装进去').hasMatch(t) &&
        !RegExp(r'卸载|清理|清空|分析|定位|找到|去签|签名|校验|验证').hasMatch(t)) {
      return _Hit('VERIFY_ARTIFACT', install: true);
    }
    // 5) 整包分析（需显式对象词，避免 '分析一下' 这类模糊句误命中）。
    if (RegExp(r'分析').hasMatch(t) &&
        RegExp(r'apk|安装包|当前|工作区|重新', caseSensitive: false).hasMatch(t)) {
      return _Hit('ANALYZE_CURRENT_APK');
    }
    return null;
  }

  static ApkTaskCommandMatch _match({
    required String command,
    required String tool,
    required Map<String, Object?> args,
    String extra = '',
  }) {
    return ApkTaskCommandMatch(
      command: command,
      tool: tool,
      args: args,
      directive:
          '<apk_task_command command="$command" tool="$tool">\n'
          '本轮用户消息已被程序预分流为 Task Command $command'
          '（Direct Command 2.0，A 类明确单动作）。\n'
          '第一轮直接调用工具 $tool，参数原样传递：${jsonEncode(args)}\n'
          '禁止 route_task / get_current_apk_report / apk_note_read / '
          'get_apk_patch_memory / get_solab_tool_map 等任何准备轮；'
          '不要再调用 ask_user_input_v0 询问怎么做。\n'
          '$extra\n'
          '汇报口径：只能报告 Analyzed / Located / dryRun\'d / Modified / '
          'Signed / Verified 等真实状态；失败时原样转述结构化 error 与 '
          'nextActions，不得猜测或粉饰。\n'
          '</apk_task_command>',
    );
  }
}
