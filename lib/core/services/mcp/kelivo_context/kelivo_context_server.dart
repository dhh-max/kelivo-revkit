import 'dart:async';
import 'dart:convert';
import 'package:mcp_client/mcp_client.dart' as mcp;
import '../in_memory_mcp_server.dart';

/// @kelivo/context — In-memory MCP server for conversation context management
///
/// Provides tools for managing and inspecting conversation context:
/// - context_get_stats     → get context statistics (message count, token estimate)
/// - context_get_summary   → get a concise summary of current context
/// - context_search        → search through conversation history
/// - context_export        → export conversation context as JSON
/// - context_set_boundary  → set a context boundary (truncation point)
/// - context_get_messages  → retrieve messages from context
///
/// This server is designed to help LLMs understand and manage their own
/// conversation context, enabling better self-awareness and context management.
class KelivoContextMcpServerEngine implements KelivoInMemoryMcpServerEngine {
  bool _closed = false;

  // Context state
  final List<Map<String, dynamic>> _messages = [];
  int? _boundaryIndex;
  final Map<String, dynamic> _metadata = {};

  KelivoContextMcpServerEngine();

  /// Update the context with current conversation messages
  void updateContext(List<Map<String, dynamic>> messages, {int? boundaryIndex}) {
    _messages.clear();
    _messages.addAll(messages);
    _boundaryIndex = boundaryIndex;
  }

  /// Update metadata about the current context
  void updateMetadata(Map<String, dynamic> metadata) {
    _metadata.addAll(metadata);
  }

  @override
  Future<dynamic> handleMessage(dynamic message) async {
    if (_closed) return null;

    // Support batch arrays defensively
    if (message is List) {
      final out = <dynamic>[];
      for (final m in message) {
        out.add(await _handleSingle(m));
      }
      return out;
    }
    return await _handleSingle(message);
  }

  Future<Map<String, dynamic>> _handleSingle(dynamic raw) async {
    try {
      if (raw is! Map) {
        return _error(null, code: -32600, message: 'Invalid Request');
      }

      final req = raw.cast<String, dynamic>();
      final id = req['id'];
      final method = (req['method'] ?? '').toString();
      final params = (req['params'] is Map)
          ? (req['params'] as Map).cast<String, dynamic>()
          : <String, dynamic>{};

      switch (method) {
        case mcp.McpProtocol.methodInitialize:
          return _ok(
            id,
            result: {
              'serverInfo': {'name': '@kelivo/context', 'version': '1.0.0'},
              'protocolVersion': mcp.McpProtocol.defaultVersion,
              'capabilities': {
                'tools': {'listChanged': false},
              },
            },
          );

        case mcp.McpProtocol.methodListTools:
          return _ok(id, result: {'tools': _toolDefinitions()});

        case mcp.McpProtocol.methodCallTool:
          final name = (params['name'] ?? '').toString();
          final arguments = (params['arguments'] is Map)
              ? (params['arguments'] as Map).cast<String, dynamic>()
              : <String, dynamic>{};

          return _ok(id, result: await _callTool(name, arguments));

        default:
          if (id == null) {
            return _noop();
          }
          return _error(id, code: -32601, message: 'Method not found: $method');
      }
    } catch (e) {
      return _error(null, code: -32603, message: 'Internal error: $e');
    }
  }

  Future<Map<String, dynamic>> _callTool(
    String name,
    Map<String, dynamic> arguments,
  ) async {
    switch (name) {
      case 'context_get_stats':
        return _contextGetStats(arguments);
      case 'context_get_summary':
        return _contextGetSummary(arguments);
      case 'context_search':
        return _contextSearch(arguments);
      case 'context_export':
        return _contextExport(arguments);
      case 'context_set_boundary':
        return _contextSetBoundary(arguments);
      case 'context_get_messages':
        return _contextGetMessages(arguments);
      default:
        return _err('Tool not found: $name');
    }
  }

  Map<String, dynamic> _contextGetStats(Map<String, dynamic> args) {
    final effectiveMessages = _boundaryIndex != null && _boundaryIndex! >= 0
        ? _messages.sublist(_boundaryIndex!)
        : _messages;

    var userMessages = 0;
    var assistantMessages = 0;
    var toolMessages = 0;
    var totalChars = 0;

    for (final msg in effectiveMessages) {
      final role = (msg['role'] ?? '').toString();
      final content = (msg['content'] ?? '').toString();
      totalChars += content.length;

      if (role == 'user') {
        userMessages++;
      } else if (role == 'assistant') {
        assistantMessages++;
      } else if (role == 'tool') {
        toolMessages++;
      }
    }

    // Rough token estimate: ~4 chars per token for mixed content
    final estimatedTokens = (totalChars / 4).round();

    final stats = {
      'totalMessages': effectiveMessages.length,
      'userMessages': userMessages,
      'assistantMessages': assistantMessages,
      'toolMessages': toolMessages,
      'totalCharacters': totalChars,
      'estimatedTokens': estimatedTokens,
      'boundaryIndex': _boundaryIndex,
      'hasBoundary': _boundaryIndex != null && _boundaryIndex! >= 0,
      'metadata': _metadata,
    };

    return _okText(const JsonEncoder.withIndent('  ').convert(stats));
  }

  Map<String, dynamic> _contextGetSummary(Map<String, dynamic> args) {
    final maxItems = (args['maxItems'] as num?)?.toInt() ?? 10;
    final effectiveMessages = _boundaryIndex != null && _boundaryIndex! >= 0
        ? _messages.sublist(_boundaryIndex!)
        : _messages;

    final summary = StringBuffer();
    summary.writeln('# 对话上下文摘要');
    summary.writeln();
    summary.writeln('## 基本信息');
    summary.writeln('- 总消息数: ${effectiveMessages.length}');
    summary.writeln('- 上下文分界: ${_boundaryIndex != null && _boundaryIndex! >= 0 ? "已设置 (索引: $_boundaryIndex)" : "未设置"}');
    summary.writeln();

    if (effectiveMessages.isEmpty) {
      summary.writeln('当前上下文为空。');
      return _okText(summary.toString());
    }

    summary.writeln('## 最近消息概览 (最近 $maxItems 条)');
    summary.writeln();

    final recent = effectiveMessages.length > maxItems
        ? effectiveMessages.sublist(effectiveMessages.length - maxItems)
        : effectiveMessages;

    for (int i = 0; i < recent.length; i++) {
      final msg = recent[i];
      final role = (msg['role'] ?? 'unknown').toString();
      final content = (msg['content'] ?? '').toString();
      final preview = content.length > 100
          ? '${content.substring(0, 100)}...'
          : content;
      final idx = effectiveMessages.length - recent.length + i + 1;

      summary.writeln('### $idx. $role');
      summary.writeln(preview);
      summary.writeln();
    }

    return _okText(summary.toString());
  }

  Map<String, dynamic> _contextSearch(Map<String, dynamic> args) {
    final query = (args['query'] ?? '').toString().trim();
    final limit = (args['limit'] as num?)?.toInt() ?? 20;
    final roleFilter = (args['role'] as String?)?.trim();

    if (query.isEmpty) {
      return _err('搜索查询不能为空');
    }

    final effectiveMessages = _boundaryIndex != null && _boundaryIndex! >= 0
        ? _messages.sublist(_boundaryIndex!)
        : _messages;

    final results = <Map<String, dynamic>>[];
    final queryLower = query.toLowerCase();

    for (int i = 0; i < effectiveMessages.length; i++) {
      final msg = effectiveMessages[i];
      final role = (msg['role'] ?? '').toString();
      final content = (msg['content'] ?? '').toString();

      if (roleFilter != null && roleFilter.isNotEmpty && role != roleFilter) {
        continue;
      }

      if (content.toLowerCase().contains(queryLower)) {
        // Find the position of the match
        final matchIdx = content.toLowerCase().indexOf(queryLower);
        final start = matchIdx > 20 ? matchIdx - 20 : 0;
        final end = (matchIdx + query.length + 20).clamp(0, content.length);
        final snippet = content.substring(start, end);
        final prefix = start > 0 ? '...' : '';
        final suffix = end < content.length ? '...' : '';

        results.add({
          'index': i + 1,
          'role': role,
          'snippet': '$prefix$snippet$suffix',
          'matchPosition': matchIdx,
        });

        if (results.length >= limit) break;
      }
    }

    final output = StringBuffer();
    output.writeln('# 搜索结果: "$query"');
    output.writeln();
    output.writeln('找到 ${results.length} 条匹配消息');
    output.writeln();

    for (final r in results) {
      output.writeln('## 消息 #${r['index']} (${r['role']})');
      output.writeln(r['snippet']);
      output.writeln();
    }

    return _okText(output.toString());
  }

  Map<String, dynamic> _contextExport(Map<String, dynamic> args) {
    final format = (args['format'] ?? 'json').toString().toLowerCase();
    final includeBoundary = args['includeBoundary'] as bool? ?? false;

    final messages = includeBoundary || _boundaryIndex == null || _boundaryIndex! < 0
        ? _messages
        : _messages.sublist(_boundaryIndex!);

    if (format == 'json') {
      final exportData = {
        'exportedAt': DateTime.now().toIso8601String(),
        'totalMessages': messages.length,
        'boundaryIndex': _boundaryIndex,
        'messages': messages,
        'metadata': _metadata,
      };
      return _okText(const JsonEncoder.withIndent('  ').convert(exportData));
    } else if (format == 'markdown') {
      final md = StringBuffer();
      md.writeln('# 对话导出');
      md.writeln();
      md.writeln('导出时间: ${DateTime.now().toLocal().toString()}');
      md.writeln('消息数量: ${messages.length}');
      md.writeln();

      for (int i = 0; i < messages.length; i++) {
        final msg = messages[i];
        final role = (msg['role'] ?? 'unknown').toString();
        final content = (msg['content'] ?? '').toString();
        md.writeln('## ${i + 1}. $role');
        md.writeln();
        md.writeln(content);
        md.writeln();
      }

      return _okText(md.toString());
    } else {
      return _err('不支持的导出格式: $format。支持的格式: json, markdown');
    }
  }

  Map<String, dynamic> _contextSetBoundary(Map<String, dynamic> args) {
    final messageIndex = (args['messageIndex'] as num?)?.toInt();
    final reset = args['reset'] as bool? ?? false;

    if (reset) {
      _boundaryIndex = null;
      return _okText('上下文分界已重置，所有消息都在上下文中。');
    }

    if (messageIndex == null || messageIndex < 0) {
      return _err('必须提供有效的 messageIndex 参数');
    }

    if (messageIndex >= _messages.length) {
      return _err('messageIndex ($messageIndex) 超出消息总数 (${_messages.length})');
    }

    _boundaryIndex = messageIndex;
    return _okText('上下文分界已设置在消息 #$messageIndex。此消息之后的内容将作为上下文。');
  }

  Map<String, dynamic> _contextGetMessages(Map<String, dynamic> args) {
    final start = (args['start'] as num?)?.toInt() ?? 0;
    final limit = (args['limit'] as num?)?.toInt() ?? 10;
    final fromEnd = args['fromEnd'] as bool? ?? false;

    final effectiveMessages = _boundaryIndex != null && _boundaryIndex! >= 0
        ? _messages.sublist(_boundaryIndex!)
        : _messages;

    if (effectiveMessages.isEmpty) {
      return _okText('当前上下文为空。');
    }

    List<Map<String, dynamic>> targetMessages;
    if (fromEnd) {
      final end = effectiveMessages.length;
      final s = (end - limit).clamp(0, end);
      targetMessages = effectiveMessages.sublist(s, end);
    } else {
      final s = start.clamp(0, effectiveMessages.length);
      final e = (s + limit).clamp(s, effectiveMessages.length);
      targetMessages = effectiveMessages.sublist(s, e);
    }

    final output = StringBuffer();
    output.writeln('# 上下文消息');
    output.writeln();
    output.writeln('总数: ${effectiveMessages.length}, 返回: ${targetMessages.length}');
    output.writeln();

    final baseIdx = fromEnd
        ? effectiveMessages.length - targetMessages.length
        : start;

    for (int i = 0; i < targetMessages.length; i++) {
      final msg = targetMessages[i];
      final role = (msg['role'] ?? 'unknown').toString();
      final content = (msg['content'] ?? '').toString();
      final idx = baseIdx + i + 1;

      output.writeln('## $idx. $role');
      output.writeln();
      output.writeln(content);
      output.writeln();
    }

    return _okText(output.toString());
  }

  @override
  void close() {
    _closed = true;
    _messages.clear();
    _metadata.clear();
  }

  Map<String, dynamic> _ok(dynamic id, {required Map<String, dynamic> result}) {
    return {'jsonrpc': '2.0', if (id != null) 'id': id, 'result': result};
  }

  Map<String, dynamic> _error(
    dynamic id, {
    required int code,
    required String message,
  }) {
    return {
      'jsonrpc': '2.0',
      if (id != null) 'id': id,
      'error': {'code': code, 'message': message},
    };
  }

  Map<String, dynamic> _noop() => {'jsonrpc': '2.0'};

  Map<String, dynamic> _okText(String text) => {
    'content': [
      {'type': 'text', 'text': text},
    ],
    'isStreaming': false,
    'isError': false,
  };

  Map<String, dynamic> _err(String message) => {
    'content': [
      {'type': 'text', 'text': message},
    ],
    'isStreaming': false,
    'isError': true,
  };

  List<Map<String, dynamic>> _toolDefinitions() {
    return [
      {
        'name': 'context_get_stats',
        'description': '获取当前上下文的统计信息，包括消息数量、角色分布、字符数和估算的token数量。',
        'inputSchema': {
          'type': 'object',
          'properties': {},
          'required': [],
        },
      },
      {
        'name': 'context_get_summary',
        'description': '获取当前对话上下文的摘要，包括最近消息的预览。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'maxItems': {
              'type': 'integer',
              'description': '摘要中包含的最大消息数量，默认10条。',
              'default': 10,
            },
          },
          'required': [],
        },
      },
      {
        'name': 'context_search',
        'description': '在对话上下文中搜索包含指定关键词的消息。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'query': {
              'type': 'string',
              'description': '要搜索的关键词。',
            },
            'limit': {
              'type': 'integer',
              'description': '返回的最大结果数量，默认20条。',
              'default': 20,
            },
            'role': {
              'type': 'string',
              'description': '按角色过滤消息（user/assistant/tool），留空表示不过滤。',
            },
          },
          'required': ['query'],
        },
      },
      {
        'name': 'context_export',
        'description': '导出当前对话上下文，支持JSON和Markdown格式。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'format': {
              'type': 'string',
              'description': '导出格式：json 或 markdown，默认json。',
              'default': 'json',
              'enum': ['json', 'markdown'],
            },
            'includeBoundary': {
              'type': 'boolean',
              'description': '是否包含分界点之前的消息，默认false（只导出当前上下文）。',
              'default': false,
            },
          },
          'required': [],
        },
      },
      {
        'name': 'context_set_boundary',
        'description': '设置上下文分界点，分界点之后的消息才会作为上下文发送给模型。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'messageIndex': {
              'type': 'integer',
              'description': '分界点的消息索引（从0开始）。此消息之后的内容将作为上下文。',
            },
            'reset': {
              'type': 'boolean',
              'description': '是否重置分界点，恢复完整上下文。',
              'default': false,
            },
          },
          'required': [],
        },
      },
      {
        'name': 'context_get_messages',
        'description': '获取上下文中的消息，可以指定起始位置和数量，或从末尾获取。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'start': {
              'type': 'integer',
              'description': '起始消息索引（从0开始），默认0。',
              'default': 0,
            },
            'limit': {
              'type': 'integer',
              'description': '获取的消息数量，默认10条。',
              'default': 10,
            },
            'fromEnd': {
              'type': 'boolean',
              'description': '是否从末尾开始获取（获取最近N条），默认false。',
              'default': false,
            },
          },
          'required': [],
        },
      },
    ];
  }
}
