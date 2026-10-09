import 'dart:async';

import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

/// 出站 LLM 请求的会话作用域（2026-09-05）。
///
/// OpenCode Go 网关要求请求携带 `x-opencode-session`（每会话一个稳定 ID），
/// 缺失头从 2026-09-06 起可能被拒（官方邮件点名 UA=SoLab）。
///
/// 聊天生成与记忆整理可能并发，静态「当前会话」变量会互相串话——
/// 用 Zone 值沿 await 链传播：各入口在拥有 conversationId 的作用域包裹，
/// HTTP 头组装层（customHeaders）同步读取。无作用域时回退安装级稳定 ID
/// （main() 启动预载；customHeaders 是同步函数，不能现场读 prefs）。
abstract final class ApiSessionScope {
  static const Symbol _sessionKey = #_opencodeSessionId;

  /// 网关要求的会话头名。
  static const String headerName = 'x-opencode-session';

  static const String _installIdKey = 'api_install_session_id_v1';
  static String? _installId;

  /// 当前 Zone 的会话 ID；不在作用域内回 null。
  static String? get current {
    final value = Zone.current[_sessionKey];
    return value is String && value.isNotEmpty ? value : null;
  }

  /// 在会话作用域内执行 [body]；[sessionId] 为空时原样执行。
  static T run<T>(T Function() body, String? sessionId) {
    final id = sessionId?.trim() ?? '';
    if (id.isEmpty) return body();
    return runZoned(body, zoneValues: {_sessionKey: id});
  }

  /// 启动时预载安装级稳定 ID（幂等；失败静默，头随后续成功加载生效）。
  static Future<void> preload() async {
    if (_installId != null) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      var id = prefs.getString(_installIdKey);
      if (id == null || id.isEmpty) {
        id = const Uuid().v4();
        await prefs.setString(_installIdKey, id);
      }
      _installId = id;
    } catch (_) {
      // 读不到就不带安装级兜底：有会话作用域的请求不受影响。
    }
  }

  /// 供头组装层取值：会话作用域优先，回退安装级 ID；均不可用回 null。
  static String? resolveHeaderValue() {
    final scoped = current;
    if (scoped != null) return scoped;
    final installId = _installId;
    return installId != null && installId.isNotEmpty ? installId : null;
  }

  /// 测试专用：清空安装级 ID（静态状态跨测试泄漏防护）。
  static void resetForTest() => _installId = null;
}
