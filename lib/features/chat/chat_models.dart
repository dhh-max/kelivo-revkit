/// 聊天消息角色。
enum MsgRole { user, assistant, system, tool }

/// 一条对话消息（内存态，暂不落库）。
class ChatMsg {
  final MsgRole role;
  final String content;
  final String? toolCallId; // role=tool 时对应 assistant 的 tool_call id
  final List<ToolCall>? toolCalls; // role=assistant 时携带本轮工具调用
  final bool isStreaming;

  const ChatMsg(
    this.role,
    this.content, {
    this.toolCallId,
    this.toolCalls,
    this.isStreaming = false,
  });

  Map<String, Object?> toApi() {
    switch (role) {
      case MsgRole.tool:
        return {'role': 'tool', 'tool_call_id': toolCallId ?? '', 'content': content};
      case MsgRole.user:
      case MsgRole.system:
        return {'role': role.name, 'content': content};
      case MsgRole.assistant:
        return {
          'role': 'assistant',
          'content': content,
          if (toolCalls != null && toolCalls!.isNotEmpty)
            'tool_calls': [
              for (final t in toolCalls!)
                {
                  'id': t.id,
                  'type': 'function',
                  'function': {'name': t.name, 'arguments': t.arguments},
                },
            ],
        };
    }
  }

  ChatMsg copyWith({bool? isStreaming, String? content}) => ChatMsg(
        role,
        content ?? this.content,
        toolCallId: toolCallId,
        toolCalls: toolCalls,
        isStreaming: isStreaming ?? this.isStreaming,
      );
}

/// 模型请求的工具调用（function calling）。
class ToolCall {
  final String id;
  final String name;
  final String arguments; // JSON 字符串

  const ToolCall({required this.id, required this.name, required this.arguments});
}

/// 工具定义（function schema，发给模型）。
class ToolDef {
  final String name;
  final String description;
  final Map<String, Object?> parameters;

  const ToolDef({
    required this.name,
    required this.description,
    required this.parameters,
  });

  Map<String, Object?> toApi() => {
        'type': 'function',
        'function': {
          'name': name,
          // schema 精简（借鉴 kelivo）：描述截到 220 字。过长的描述
          // 只会撑大请求体、拖慢首字，对模型选工具的帮助边际递减。
          'description': _trim(description, 220),
          'parameters': _slimSchema(parameters),
        },
      };

  static String _trim(String s, int max) =>
      s.length <= max ? s : '${s.substring(0, max)}…';

  /// 精简参数 schema：把每个 property 的 description 截到 80 字。
  /// 只动描述文本，不碰 type/enum/required 等结构性字段——
  /// 那些动了会影响模型正确构造参数。
  static Map<String, Object?> _slimSchema(Map<String, Object?> schema) {
    final props = schema['properties'];
    if (props is! Map) return schema;
    final slimProps = <String, Object?>{};
    props.forEach((k, v) {
      if (v is Map<String, Object?>) {
        final p = Map<String, Object?>.from(v);
        final d = p['description'];
        if (d is String) p['description'] = _trim(d, 80);
        slimProps[k.toString()] = p;
      } else {
        slimProps[k.toString()] = v;
      }
    });
    return {...schema, 'properties': slimProps};
  }
}

/// 流式产出：文本增量 / 工具调用请求 / 完成。
sealed class ChatEvent {}

class TextDeltaEvent extends ChatEvent {
  final String delta;
  TextDeltaEvent(this.delta);
}

/// 思考过程增量（reasoning_content / reasoning 字段）。
class ReasoningDeltaEvent extends ChatEvent {
  final String delta;
  ReasoningDeltaEvent(this.delta);
}

class ToolCallsEvent extends ChatEvent {
  final List<ToolCall> calls;
  ToolCallsEvent(this.calls);
}

class FinishEvent extends ChatEvent {
  final String? finishReason;
  FinishEvent({this.finishReason});
}

/// 一次请求的用量（服务端在流末尾返回）。
class UsageEvent extends ChatEvent {
  final int promptTokens;
  final int completionTokens;
  final int cachedTokens;
  UsageEvent({
    this.promptTokens = 0,
    this.completionTokens = 0,
    this.cachedTokens = 0,
  });
}

class ErrorEvent extends ChatEvent {
  final String message;
  ErrorEvent(this.message);
}

/// 请求失败的分类（用于给出可操作的中文提示，而不是抛原始异常文本）。
enum ChatFailureKind {
  /// 连接/读取超时（含思考模型长时间不出字）。
  timeout,

  /// 网络不可达、DNS、TLS 等。
  network,

  /// 401/403：Key 无效、无权限。
  auth,

  /// 429：额度/频率限制。
  quota,

  /// 400/404/422：请求或模型名不对。
  request,

  /// 5xx：服务端故障。
  server,

  /// 其它未知。
  unknown,
}

/// 一次请求失败的描述。
class ChatFailure implements Exception {
  final ChatFailureKind kind;

  /// 面向用户的一句话说明（含处置建议）。
  final String message;

  /// 原始错误细节（排查用）。
  final String? detail;

  /// HTTP 状态码（若有）。
  final int? statusCode;

  const ChatFailure(this.kind, this.message, {this.detail, this.statusCode});

  /// 关键词 → 可读失败（服务商把错误写在 200 的 SSE 里时用）。
  factory ChatFailure.fromMessage(String raw) {
    final lower = raw.toLowerCase();
    if (lower.contains('insufficient') ||
        lower.contains('quota') ||
        lower.contains('balance') ||
        lower.contains('额度')) {
      return ChatFailure(ChatFailureKind.quota,
          '额度不足或被限流。请检查账户余额/套餐。', detail: raw);
    }
    if (lower.contains('invalid api key') ||
        lower.contains('unauthorized') ||
        lower.contains('authentication')) {
      return ChatFailure(ChatFailureKind.auth,
          'API Key 无效或未授权。请到「设置 → 模型服务」检查 Key。', detail: raw);
    }
    if (lower.contains('model') && lower.contains('not')) {
      return ChatFailure(ChatFailureKind.request,
          '模型名不可用。请在「设置 → 模型服务」里从列表选一个有效模型。',
          detail: raw);
    }
    return ChatFailure(ChatFailureKind.unknown, raw, detail: raw);
  }

  /// 由 HTTP 状态码构造可读失败。
  factory ChatFailure.fromStatus(int status, String body) {
    final snippet = body.length > 300 ? '${body.substring(0, 300)}…' : body;
    switch (status) {
      case 401:
        return ChatFailure(ChatFailureKind.auth,
            'API Key 无效或未授权（401）。请到「设置 → 模型服务」检查 Key 是否正确、是否已过期。',
            detail: snippet, statusCode: status);
      case 403:
        return ChatFailure(ChatFailureKind.auth,
            '服务端拒绝访问（403）。可能是 Key 权限不足、区域限制，或该模型未开通。',
            detail: snippet, statusCode: status);
      case 404:
        return ChatFailure(ChatFailureKind.request,
            '接口或模型不存在（404）。请检查 Base URL（通常需要以 /v1 结尾）与模型名。',
            detail: snippet, statusCode: status);
      case 429:
        return ChatFailure(ChatFailureKind.quota,
            '请求过于频繁或额度已用尽（429）。稍后重试，或检查账户余额与限速。',
            detail: snippet, statusCode: status);
      case 400:
      case 422:
        return ChatFailure(
            ChatFailureKind.request,
            '服务端认为请求不合法（$status）。常见原因：模型名不支持、该模型不接受所选思维链档位、或上下文过长。',
            detail: snippet,
            statusCode: status);
      default:
        if (status >= 500) {
          return ChatFailure(ChatFailureKind.server,
              '服务端故障（$status）。这不是你的配置问题，稍后重试即可。',
              detail: snippet, statusCode: status);
        }
        return ChatFailure(ChatFailureKind.unknown, '请求失败（HTTP $status）。',
            detail: snippet, statusCode: status);
    }
  }

  @override
  String toString() => message;
}
