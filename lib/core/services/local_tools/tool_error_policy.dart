import 'dart:convert';

/// 工具错误「可恢复性」判定策略（R5 单一事实源）。
///
/// R5 要求：工具对无效 workspaceId / editSessionId / locator / apkPath 等
/// 必须返回结构化错误码 + recoverable 标记，禁止静默返回空冒充"不存在"。
///
/// 改造前存在两种相反的偏差，都会误导调用方（内置助手与电脑端 MCP 客户端）：
/// - 内建 handler 各自手写 `{'error': ...}`，113 处错误返回里只有 3 处带
///   recoverable —— 缺失让 AI 误判为无可挽回而提前放弃；
/// - MCP 出口 `_normalizeToolOutput` 一律硬编码 `recoverable: true` —— 假标记
///   让 AI 对 `unsupported_platform`、`tool_not_available` 这类原样重试必然
///   再次失败的错误反复重试，空耗轮次。
///
/// 本类把「错误码 → 能否靠修正输入重试来恢复」收敛为唯一判定，并在工具结果
/// 出口统一补齐，不再依赖每个 handler 自觉。
abstract final class ToolErrorPolicy {
  const ToolErrorPolicy._();

  /// 判定 [code] 对应的失败是否可恢复。
  ///
  /// 可恢复 = 调用方修正参数、补齐前置步骤或取得用户确认后，重试可能成功。
  /// 不可恢复 = 由环境 / 平台 / 安全策略决定，原样重试必然再次失败。
  ///
  /// 未知错误码默认可恢复：保留重试机会，与改造前 MCP 侧的行为一致，
  /// 不引入能力回退。
  static bool recoverableFor(String? code) {
    if (code == null || code.trim().isEmpty) return true;
    final c = code.trim().toLowerCase();

    // 平台 / 能力不支持：换参数也不会改变结果。
    if (c.contains('unsupported')) return false;
    if (c.contains('not_available')) return false;
    // 依赖不可用（chat_service_unavailable 等）：属环境问题，重试无用。
    if (c.endsWith('_unavailable')) return false;
    // 安全策略拒绝：原样重试同样被拒，必须修改输入内容。
    if (c.startsWith('unsafe_')) return false;

    // no_match：预览类工具（patch_apk_dex_strings 等）确认目标不存在/无引用。
    // 修正 replacements/locator 后重试可能成功，故可恢复；但原样重试必然
    // 再次 0 命中，调用方必须换参数——retrySameArguments=false 与之一致。
    if (c == 'no_match') return true;

    // 其余一律视为可恢复：
    //   invalid_*                      参数格式 / 取值不合法
    //   *_required                     缺必填参数
    //   *_not_set                      工作目录 / 工作区未设置
    //   *_not_found                    目标不存在（换路径或先生成）
    //   confirmation_/preview_required 需用户确认后重试
    //   project_not_ready              补跑前置步骤后重试
    return true;
  }

  /// 错误码的规范形态：全小写 + 下划线（`invalid_argument_value`）。
  ///
  /// 生产端历史上有三种拼法：Kotlin `err()` 全是 `UPPER_SNAKE`、Dart handler
  /// 全是 `lower_snake`、还有零星驼峰与自由文本当码。对调用方来说这是同一件
  /// 事的三种拼法，检索、匹配、写恢复动作都要写三份——2026-09-19 复测把这条
  /// 记为"错误码风格不一"（D7）。出口统一归一，原始写法保留在 `error.rawCode`，
  /// 需要按老码翻日志时还能对得上。
  ///
  /// 判定逻辑（`RecoveryEngine.classify` 先大写、本策略先小写）本就大小写
  /// 不敏感，因此归一不改变任何既有语义，只统一调用方看到的形态。
  static String normalizeCode(String? code) {
    final trimmed = (code ?? '').trim();
    if (trimmed.isEmpty) return 'tool_failed';
    final snake = trimmed
        // camelCase → camel_Case
        .replaceAllMapped(
          RegExp(r'([a-z0-9])([A-Z])'),
          (match) => '${match[1]}_${match[2]}',
        )
        // 空白与连字符（自由文本当码的历史形态）统一成下划线
        .replaceAll(RegExp(r'[\s\-]+'), '_')
        .replaceAll(RegExp('_+'), '_')
        .toLowerCase();
    return snake.isEmpty ? 'tool_failed' : snake;
  }

  /// 失败结果是否**缺机器可读错误码**（R5 兜底）。
  ///
  /// 真机复测里出现过 `ok:false` 但既不回 `error` 也不回 `code` 的回执：调用方
  /// 只能盯着 message 猜是参数问题、环境问题还是实现 bug，恢复动作全靠碰运气。
  /// 这类回执按缺陷处理——合成一个码，把「工具没说」变成「工具说了它没说」。
  static bool needsSynthesizedCode(Map<String, dynamic> payload) {
    if (payload['ok'] != false) return false;
    // 内层 errors[] 数组里的 code 也算数（2026-10-03 报告 F-15：RuntimeTools 的
    // 失败信封用 errors:[{code:NO_TASK}]，顶层却被合成 missing_error_code）。
    final errors = payload['errors'];
    if (errors is List) {
      for (final entry in errors.whereType<Map>()) {
        final nested = codeOf(entry['code']) ?? codeOf(entry['error']);
        if (nested != null && nested.trim().isNotEmpty) return false;
      }
    }
    final fromError = codeOf(payload['error']);
    if (fromError != null && fromError.trim().isNotEmpty) return false;
    final top = payload['code'];
    return top is! String || top.trim().isEmpty;
  }

  /// 给「无码失败」合成结构化错误（不覆盖已有错误信息）。
  static Map<String, dynamic> synthesizeMissingCode(
    Map<String, dynamic> payload, {
    String? tool,
  }) => <String, dynamic>{
    ...payload,
    'error': <String, dynamic>{
      'code': 'missing_error_code',
      'message':
          '工具以失败收尾（ok=false）但没有返回机器可读错误码'
          '${tool == null || tool.isEmpty ? '' : '（tool=$tool）'}：'
          '这是工具实现缺口，不要根据其它字段猜恢复动作；'
          '请把本回执原文连同调用参数报给维护者。',
      'recoverable': false,
      'retrySameArguments': false,
    },
  };

  /// 从工具输出中的 error 字段取出错误码。
  static String? codeOf(Object? rawError) {
    if (rawError is String) return rawError;
    if (rawError is Map) {
      final code = rawError['code'] ?? rawError['error'];
      if (code is String) return code;
    }
    return null;
  }

  /// 是否是「失败回执」：显式 ok:false；或没有 ok 键但带 error/字符串 code
  /// （历史形态，2026-09-19 报告 2-21 实测过的绕过路径）。
  static bool isFailurePayload(Map<String, dynamic> payload) {
    if (payload['ok'] == false) return true;
    if (payload.containsKey('ok')) return false;
    return payload['error'] != null || payload['code'] is String;
  }

  /// 失败信封的规范形（F-39 / v9-N3 收口，2026-10-05 v11 复测）。
  ///
  /// 实测三套形状并存：`file` 只有 `error{…}`（无顶层 message/recoverable）、
  /// `so_analyze` 是 `error{…}+message+recoverable`、`patch_apk_dex_strings`
  /// 还多顶层 `code` 与 `nextActions`。同一件事三种拼法，调用方要写三份读取。
  /// 这里收敛成**唯一规范形**（Kotlin `ToolJson.err()` 的超集）：
  ///
  /// ```
  /// { ok:false,
  ///   error: {code, rawCode?, message, severity, recoverable,
  ///           retrySameArguments, diagnostics, argument?, badValue?},
  ///   code,          // = error.code（旧消费者读顶层）
  ///   message,       // = error.message
  ///   recoverable,   // = error.recoverable
  ///   nextActions:[] }
  /// ```
  ///
  /// 只补齐/归一，不丢业务字段；显式成功（ok:true）原样返回。
  static Map<String, dynamic> unifyFailure(
    Map<String, dynamic> payload, {
    String? tool,
  }) {
    if (payload['ok'] == true) return payload;
    if (!isFailurePayload(payload)) return payload;
    var out = Map<String, dynamic>.from(payload);

    // 取出错误对象：error 对象 → error 字符串 → 顶层 code → errors[] 里的码
    // → 都没有（合成 missing_error_code）。
    //
    // 任务族信封（ToolEnvelope.toJson）把细节放在 `errors[]` + `summary`：
    // 先取「首条带码的 errors 条目」，供 code/message/retryable 三处复用——
    // 否则顶层只有 code 时 message 会退化成合成文案（v13 实测）。
    Map<dynamic, dynamic>? nestedError;
    for (final entry in (out['errors'] as List? ?? const <Object?>[])
        .whereType<Map>()) {
      final code = codeOf(entry['code']) ?? codeOf(entry['error']);
      if (code != null && code.trim().isNotEmpty) {
        nestedError = entry;
        break;
      }
    }
    String nestedMessageOf(Map<dynamic, dynamic>? entry) =>
        entry?['message']?.toString().trim() ?? '';
    void applyNestedDetails(Map<String, dynamic> target) {
      final nestedMessage = nestedMessageOf(nestedError);
      if (nestedMessage.isNotEmpty) target['message'] = nestedMessage;
      if (nestedError?['retryable'] is bool) {
        target['retrySameArguments'] = nestedError!['retryable'] as bool;
      }
      // 注：errors[].suggestedActions 不搬进 error{}——规范形里没有这个键，
      // 原始数组仍原样保留在顶层 errors[]，需要精确动作的调用方读那里。
    }

    final rawError = out['error'];
    Map<String, dynamic> errMap;
    if (rawError is Map) {
      errMap = <String, dynamic>{
        for (final entry in rawError.entries) entry.key.toString(): entry.value,
      };
    } else if (rawError is String && rawError.trim().isNotEmpty) {
      errMap = <String, dynamic>{'code': rawError.trim()};
    } else {
      final topCode = out['code'];
      if (topCode is String && topCode.trim().isNotEmpty) {
        errMap = <String, dynamic>{'code': topCode};
        applyNestedDetails(errMap);
      } else if (!needsSynthesizedCode(out)) {
        // 顶层没有码但 errors[] 里有（ToolEnvelope 任务族信封）——用它，不合成
        // missing_error_code（报告 F-15：顶层曾被误合成）。顺带把该条的
        // retryable 映射成 retrySameArguments（v13：两族字段名要一致）。
        final nestedCode = nestedError == null
            ? ''
            : (codeOf(nestedError['code']) ??
                  codeOf(nestedError['error']) ??
                  '');
        errMap = <String, dynamic>{'code': nestedCode};
        applyNestedDetails(errMap);
      } else {
        out = synthesizeMissingCode(out, tool: tool);
        errMap = <String, dynamic>{
          for (final entry in (out['error'] as Map).entries)
            entry.key.toString(): entry.value,
        };
      }
    }

    // 错误码归一（lower_snake），原始写法留 error.rawCode（顶层同时镜像一份，
    // 兼容读顶层 rawCode 的旧消费者）。
    final rawCode = codeOf(errMap) ?? '';
    final normalized = normalizeCode(rawCode);
    errMap['code'] = normalized;
    if (rawCode.trim().isNotEmpty && normalized != rawCode.trim()) {
      errMap['rawCode'] = rawCode.trim();
      out['rawCode'] = rawCode.trim();
    }

    // 必备字段补齐（message 的兜底链：error.message → 顶层 message →
    // errors[].message → 合成）。顶层原有 message 是原始信息，只补不覆盖
    // （R5 测试锁过「原有信息不覆盖」）。
    final originalTop = out['message'];
    final errMessage = errMap['message'];
    final nestedTop = nestedMessageOf(nestedError);
    final message = errMessage is String && errMessage.trim().isNotEmpty
        ? errMessage
        : originalTop is String && originalTop.trim().isNotEmpty
        ? originalTop
        : nestedTop.isNotEmpty
        ? nestedTop
        : '工具执行失败（$normalized），未提供细节';
    errMap['message'] = message;
    errMap['severity'] ??= 'error';
    final recoverable = errMap['recoverable'] is bool
        ? errMap['recoverable'] as bool
        : out['recoverable'] is bool
        ? out['recoverable'] as bool
        : recoverableFor(normalized);
    errMap['recoverable'] = recoverable;
    final retrySame = errMap['retrySameArguments'] is bool
        ? errMap['retrySameArguments'] as bool
        : out['retrySameArguments'] is bool
        ? out['retrySameArguments'] as bool
        : false;
    errMap['retrySameArguments'] = retrySame;
    errMap.putIfAbsent('diagnostics', () => <String, dynamic>{});

    out['error'] = errMap;
    out['code'] = normalized;
    out['message'] = originalTop is String && originalTop.trim().isNotEmpty
        ? originalTop
        : message;
    out['recoverable'] = recoverable;
    // v14（F-39 字段名对齐）：顶层也镜像 retrySameArguments——工具族读顶层
    // code/message/recoverable/retrySameArguments，任务族（ToolEnvelope）过去
    // 只有自家命名的 retryable。现在两族同名键都在（retryable 作为旧别名保留）。
    out['retrySameArguments'] = retrySame;
    // v16-N1：任务族信封的动作藏在 errors[].suggestedActions 里，顶层一直是空
    // nextActions——与工具族「顶层给动作」的形状不一致。这里把嵌套动作提升到
    // 顶层（顶层已有内容时不覆盖），读类/控制类工具的所有失败一并受益。
    final nestedActions = nestedError?['suggestedActions'];
    final topActions = out['nextActions'];
    if (topActions is! List || topActions.isEmpty) {
      out['nextActions'] = nestedActions is List && nestedActions.isNotEmpty
          ? List<Object?>.of(nestedActions)
          : (topActions is List ? topActions : <dynamic>[]);
    }
    return out;
  }

  /// 给工具输出补齐规范失败信封（F-39 收口后走 [unifyFailure]）。
  ///
  /// 成功结果、纯文本输出原样返回；失败结果（含 `{ok:false}`、error 对象/字符
  /// 串、顶层 code、无码失败四种形态）统一成规范形，由 [unifyFailure] 一处裁决。
  ///
  /// 快路径（2026-09-13 逐工具性能复查）：信封式成功输出（`"error":null`
  /// 且全文不存在 error 对象/字符串形态）可证明顶层 error 必为 null——
  /// 直接原样返回，省掉一次全量 jsonDecode。只要文本里出现任意
  /// `"error":{` 或 `"error":"` 就走慢路径，不影响失败结果的改写。
  static String enrich(String output) {
    // 快路径：成功结果直接返回。失败回执要覆盖四种形态：`error` 对象、error
    // 字符串、顶层 `code`、以及**都没有**（无码失败 —— R5 兜底要合成
    // missing_error_code，报告 2-21 实测这条形态端内看到 UPPER_SNAKE 而 MCP 面
    // 看到小写，就是被这条路径整条漏掉）。
    // 判据用 `"ok":false`（jsonEncode 不带空格）：覆盖全部失败形态，又不会让含
    // `"code"` 字段的大成功结果（dex 结果等）走一次全量解码。
    final looksFailed = output.contains('"ok":false');
    if (!output.contains('"error"') && !looksFailed) {
      return output;
    }
    if (output.contains('"error":null') &&
        !output.contains('"error":{') &&
        !output.contains('"error":"') &&
        !looksFailed) {
      return output;
    }
    Object? decoded;
    try {
      decoded = jsonDecode(output);
    } catch (_) {
      // 部分工具返回人类可读文本而非 JSON，不干预。
      return output;
    }
    if (decoded is! Map) return output;
    final map = Map<String, dynamic>.from(decoded);
    if (!isFailurePayload(map)) return output;
    return jsonEncode(unifyFailure(map, tool: map['tool']?.toString()));
  }

  /// 给标准 envelope（`{ok, data, error: {...}, nextActions}`）补齐规范失败形。
  ///
  /// F-39 收口（2026-10-05）：与 [enrich] 走同一个 [unifyFailure]——过去两条出口
  /// 各修各的字段（这条只补 error.recoverable，那条只补顶层 recoverable），
  /// 才出现「同一失败三个形状」。现在唯一裁决点在这里。
  static Map<String, dynamic> enrichEnvelope(Map<String, dynamic> envelope) =>
      unifyFailure(envelope, tool: envelope['tool']?.toString());
}
