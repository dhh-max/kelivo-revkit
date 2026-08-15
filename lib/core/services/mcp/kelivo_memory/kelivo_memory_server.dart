import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../in_memory_mcp_server.dart';
import '../../mcp_protocol.dart' as mcp;

/// Kelivo Memory MCP Server — exposes the app's built-in memory system
/// (add/list/update/delete/search memories per assistant) as MCP tools.
class KelivoMemoryMcpServerEngine implements KelivoInMemoryMcpServerEngine {
  bool _closed = false;
  static const String _memoriesKey = 'assistant_memories_v1';

  @override
  Future<dynamic> handleMessage(dynamic message) async {
    if (_closed) return null;
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
              'serverInfo': {'name': '@kelivo/memory', 'version': '2.0.0'},
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
          switch (name) {
            case 'memory_list':
              return _ok(id, result: await _listMemories(arguments));
            case 'memory_add':
              return _ok(id, result: await _addMemory(arguments));
            case 'memory_update':
              return _ok(id, result: await _updateMemory(arguments));
            case 'memory_delete':
              return _ok(id, result: await _deleteMemory(arguments));
            case 'memory_search':
              return _ok(id, result: await _searchMemories(arguments));
            case 'memory_clear':
              return _ok(id, result: await _clearMemories(arguments));
            case 'memory_stats':
              return _ok(id, result: await _memoryStats(arguments));
            default:
              return _error(id, code: -32101, message: 'Tool not found: $name');
          }
        default:
          if (id == null) return _noop();
          return _error(id, code: -32601, message: 'Method not found: $method');
      }
    } catch (e) {
      return _error(null, code: -32603, message: 'Internal error: $e');
    }
  }

  // ─── Storage helpers ──────────────────────────────────────────────

  Future<List<Map<String, dynamic>>> _loadAll() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_memoriesKey);
    if (raw == null || raw.isEmpty) return [];
    try {
      final arr = jsonDecode(raw) as List<dynamic>;
      return [
        for (final e in arr)
          if (e is Map<String, dynamic>)
            e
          else if (e is Map)
            (e as Map).cast<String, dynamic>(),
      ];
    } catch (_) {
      return [];
    }
  }

  Future<void> _saveAll(List<Map<String, dynamic>> list) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_memoriesKey, jsonEncode(list));
  }

  int _nextId(List<Map<String, dynamic>> list) {
    int maxId = 0;
    for (final m in list) {
      final id = (m['id'] as num?)?.toInt() ?? 0;
      if (id > maxId) maxId = id;
    }
    return maxId + 1;
  }

  // ─── Tool implementations ─────────────────────────────────────────

  Future<Map<String, dynamic>> _listMemories(Map<String, dynamic> args) async {
    final assistantId = (args['assistantId'] ?? '').toString();
    final all = await _loadAll();
    final filtered = assistantId.isEmpty
        ? all
        : all.where((m) => (m['assistantId'] ?? '') == assistantId).toList();
    final sb = StringBuffer();
    if (filtered.isEmpty) {
      sb.writeln('暂无记忆。');
    } else {
      sb.writeln('记忆列表 (${filtered.length} 条):');
      for (final m in filtered) {
        sb.writeln('  [#${m['id']}] [${m['assistantId']}] ${m['content']}');
      }
    }
    return {
      'content': [
        {'type': 'text', 'text': sb.toString().trimRight()},
      ],
    };
  }

  Future<Map<String, dynamic>> _addMemory(Map<String, dynamic> args) async {
    final assistantId = (args['assistantId'] ?? 'default').toString();
    final content = (args['content'] ?? '').toString();
    if (content.isEmpty) {
      return {
        'content': [
          {'type': 'text', 'text': '错误: content 不能为空。'},
        ],
      };
    }
    final all = await _loadAll();
    final id = _nextId(all);
    final entry = {
      'id': id,
      'assistantId': assistantId,
      'content': content,
      'createdAt': DateTime.now().toIso8601String(),
    };
    all.add(entry);
    await _saveAll(all);
    return {
      'content': [
        {'type': 'text', 'text': '记忆已添加: [#$id] [$assistantId] $content'},
      ],
    };
  }

  Future<Map<String, dynamic>> _updateMemory(Map<String, dynamic> args) async {
    final id = (args['id'] as num?)?.toInt() ?? 0;
    final content = (args['content'] ?? '').toString();
    if (id <= 0 || content.isEmpty) {
      return {
        'content': [
          {'type': 'text', 'text': '错误: 需要提供有效的 id 和 content。'},
        ],
      };
    }
    final all = await _loadAll();
    int idx = -1;
    for (int i = 0; i < all.length; i++) {
      if ((all[i]['id'] as num?)?.toInt() == id) {
        idx = i;
        break;
      }
    }
    if (idx == -1) {
      return {
        'content': [
          {'type': 'text', 'text': '错误: 记忆 #$id 不存在。'},
        ],
      };
    }
    all[idx]['content'] = content;
    all[idx]['updatedAt'] = DateTime.now().toIso8601String();
    await _saveAll(all);
    return {
      'content': [
        {'type': 'text', 'text': '记忆 #$id 已更新: $content'},
      ],
    };
  }

  Future<Map<String, dynamic>> _deleteMemory(Map<String, dynamic> args) async {
    final id = (args['id'] as num?)?.toInt() ?? 0;
    if (id <= 0) {
      return {
        'content': [
          {'type': 'text', 'text': '错误: 需要提供有效的 id。'},
        ],
      };
    }
    final all = await _loadAll();
    final before = all.length;
    all.removeWhere((m) => (m['id'] as num?)?.toInt() == id);
    await _saveAll(all);
    final deleted = before - all.length;
    return {
      'content': [
        {
          'type': 'text',
          'text': deleted > 0
              ? '记忆 #$id 已删除。'
              : '错误: 记忆 #$id 不存在。',
        },
      ],
    };
  }

  Future<Map<String, dynamic>> _searchMemories(Map<String, dynamic> args) async {
    final query = (args['query'] ?? '').toString().toLowerCase();
    final assistantId = (args['assistantId'] ?? '').toString();
    if (query.isEmpty) {
      return {
        'content': [
          {'type': 'text', 'text': '错误: query 不能为空。'},
        ],
      };
    }
    final all = await _loadAll();
    final filtered = all.where((m) {
      if (assistantId.isNotEmpty && (m['assistantId'] ?? '') != assistantId) {
        return false;
      }
      final content = (m['content'] ?? '').toString().toLowerCase();
      return content.contains(query);
    }).toList();
    final sb = StringBuffer();
    if (filtered.isEmpty) {
      sb.writeln('未找到匹配 "$query" 的记忆。');
    } else {
      sb.writeln('搜索结果 (${filtered.length} 条匹配 "$query"):');
      for (final m in filtered) {
        sb.writeln('  [#${m['id']}] [${m['assistantId']}] ${m['content']}');
      }
    }
    return {
      'content': [
        {'type': 'text', 'text': sb.toString().trimRight()},
      ],
    };
  }

  Future<Map<String, dynamic>> _clearMemories(Map<String, dynamic> args) async {
    final assistantId = (args['assistantId'] ?? '').toString();
    final all = await _loadAll();
    final before = all.length;
    List<Map<String, dynamic>> remaining;
    int cleared;
    if (assistantId.isEmpty) {
      remaining = [];
      cleared = before;
    } else {
      remaining = all.where((m) => (m['assistantId'] ?? '') != assistantId).toList();
      cleared = before - remaining.length;
    }
    await _saveAll(remaining);
    return {
      'content': [
        {
          'type': 'text',
          'text': assistantId.isEmpty
              ? '所有记忆已清空 ($cleared 条)。'
              : '助手 "$assistantId" 的记忆已清空 ($cleared 条)。',
        },
      ],
    };
  }

  Future<Map<String, dynamic>> _memoryStats(Map<String, dynamic> args) async {
    final all = await _loadAll();
    final assistantIds = <String, int>{};
    for (final m in all) {
      final aid = (m['assistantId'] ?? 'unknown').toString();
      assistantIds[aid] = (assistantIds[aid] ?? 0) + 1;
    }
    final sb = StringBuffer();
    sb.writeln('记忆统计:');
    sb.writeln('  总记忆数: ${all.length}');
    sb.writeln('  助手数: ${assistantIds.length}');
    sb.writeln('  分布:');
    assistantIds.forEach((aid, count) {
      sb.writeln('    $aid: $count 条');
    });
    return {
      'content': [
        {'type': 'text', 'text': sb.toString().trimRight()},
      ],
    };
  }

  // ─── Tool definitions ─────────────────────────────────────────────

  List<Map<String, dynamic>> _toolDefinitions() {
    return [
      {
        'name': 'memory_list',
        'description': '列出所有记忆或指定助手的记忆。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'assistantId': {
              'type': 'string',
              'description': '可选：按助手ID过滤记忆。',
            },
          },
        },
      },
      {
        'name': 'memory_add',
        'description': '添加一条新记忆。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'assistantId': {
              'type': 'string',
              'description': '助手ID，默认 "default"。',
            },
            'content': {
              'type': 'string',
              'description': '记忆内容。',
            },
          },
          'required': ['content'],
        },
      },
      {
        'name': 'memory_update',
        'description': '更新指定ID的记忆内容。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'id': {
              'type': 'integer',
              'description': '记忆ID。',
            },
            'content': {
              'type': 'string',
              'description': '新的记忆内容。',
            },
          },
          'required': ['id', 'content'],
        },
      },
      {
        'name': 'memory_delete',
        'description': '删除指定ID的记忆。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'id': {
              'type': 'integer',
              'description': '记忆ID。',
            },
          },
          'required': ['id'],
        },
      },
      {
        'name': 'memory_search',
        'description': '搜索包含指定关键词的记忆。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'query': {
              'type': 'string',
              'description': '搜索关键词。',
            },
            'assistantId': {
              'type': 'string',
              'description': '可选：限定搜索范围到指定助手。',
            },
          },
          'required': ['query'],
        },
      },
      {
        'name': 'memory_clear',
        'description': '清空所有记忆或指定助手的记忆。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'assistantId': {
              'type': 'string',
              'description': '可选：只清空指定助手的记忆。不传则清空全部。',
            },
          },
        },
      },
      {
        'name': 'memory_stats',
        'description': '查看记忆统计信息（总数、助手分布等）。',
        'inputSchema': {
          'type': 'object',
          'properties': {},
        },
      },
    ];
  }

  @override
  void close() {
    _closed = true;
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
}