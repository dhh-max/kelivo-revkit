import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:mcp_client/mcp_client.dart' as mcp;
import 'package:shared_preferences/shared_preferences.dart';

import '../in_memory_mcp_server.dart';

/// Kelivo Memory MCP Server (v2) — Full Memory System.
/// Ported from the master branch design: scope/type/status/source model,
/// user profile fields, dedup, smart search. Backward compatible.
class KelivoMemoryMcpServerEngine implements KelivoInMemoryMcpServerEngine {
  bool _closed = false;
  static const String _memoriesKey = 'assistant_memories_v1';
  static const String _profilesKey = 'assistant_profiles_v1';

  static const String _scopeGlobal = 'global';
  static const String _scopeAssistant = 'assistant';
  static const String _typeIdentity = 'identity';
  static const String _typeWorkflow = 'workflow';
  static const String _typeVoice = 'voice';
  static const String _typeInstruction = 'instruction';
  static const String _statusActive = 'active';
  static const String _statusArchived = 'archived';
  static const String _sourceManual = 'manual';
  static const String _sourceTool = 'tool';
  static const String _sourceExtracted = 'extracted';
  static const String _sourceDistilled = 'distilled';

  static const List<String> _knownProfileKeys = [
    'preferred_name',
    'gender',
    'pronouns',
    'preferred_language',
    'timezone',
    'occupation',
    'location',
  ];

  static final RegExp _customProfileKeyRe =
      RegExp(r'^custom\.[A-Za-z0-9_\-]{1,32}$');

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
          return _ok(id, result: {
            'serverInfo': {'name': '@kelivo/memory', 'version': '2.1.0'},
            'protocolVersion': mcp.McpProtocol.defaultVersion,
            'capabilities': {'tools': {'listChanged': false}},
          });
        case mcp.McpProtocol.methodListTools:
          return _ok(id, result: {'tools': _toolDefinitions()});
        case mcp.McpProtocol.methodCallTool:
          final name = (params['name'] ?? '').toString();
          final arguments = (params['arguments'] is Map)
              ? (params['arguments'] as Map).cast<String, dynamic>()
              : <String, dynamic>{};
          return _ok(id, result: await _routeTool(name, arguments));
        default:
          if (id == null) return _noop();
          return _error(id, code: -32601, message: 'Method not found: $method');
      }
    } catch (e) {
      return _error(null, code: -32603, message: 'Internal error: $e');
    }
  }

  Future<Map<String, dynamic>> _routeTool(
      String name, Map<String, dynamic> args) async {
    try {
      switch (name) {
        // Legacy tools (backward compatible, enhanced)
        case 'memory_list':
          return await _memoryList(args);
        case 'memory_add':
          return await _memoryAdd(args);
        case 'memory_update':
          return await _memoryUpdate(args);
        case 'memory_delete':
          return await _memoryDelete(args);
        case 'memory_search':
          return await _memorySearch(args);
        case 'memory_clear':
          return await _memoryClear(args);
        case 'memory_stats':
          return await _memoryStats(args);
        // New tools (master design)
        case 'memory_read':
          return await _memoryRead(args);
        case 'memory_search_profile':
          return await _memorySearchProfile(args);
        case 'memory_edit':
          return await _memoryEdit(args);
        case 'update_user_profile':
          return await _updateUserProfile(args);
        case 'chat_search':
          return await _chatSearch(args);
        default:
          return {
            'content': [
              {'type': 'text', 'text': '工具未找到: $name'},
            ],
            'isError': true,
          };
      }
    } catch (e) {
      return {
        'content': [
          {'type': 'text', 'text': '执行错误: $e'},
        ],
        'isError': true,
      };
    }
  }

  // ─── Storage helpers ──────────────────────────────────────────────────

  Future<List<Map<String, dynamic>>> _loadAll() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_memoriesKey);
    if (raw == null || raw.isEmpty) return [];
    try {
      final arr = jsonDecode(raw) as List<dynamic>;
      return arr.map((e) {
        final m = (e is Map)
            ? Map<String, dynamic>.from(e as Map)
            : <String, dynamic>{};
        if (!m.containsKey('scope')) m['scope'] = _scopeGlobal;
        if (!m.containsKey('type')) m['type'] = _typeIdentity;
        if (!m.containsKey('status')) m['status'] = _statusActive;
        if (!m.containsKey('source')) m['source'] = _sourceManual;
        if (!m.containsKey('relatedIds')) m['relatedIds'] = <String>[];
        if (!m.containsKey('updatedAt')) {
          m['updatedAt'] = m['createdAt'] ??
              DateTime.now().microsecondsSinceEpoch;
        }
        return m;
      }).toList();
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

  String _newEntryId() {
    final rng = Random.secure();
    const alphabet = '0123456789abcdef';
    final buf = StringBuffer('mem_');
    for (var i = 0; i < 8; i++) {
      buf.write(alphabet[rng.nextInt(alphabet.length)]);
    }
    return buf.toString();
  }

  static String _normalizeContent(String content) {
    return content.trim().replaceAll(RegExp(r'\s+'), ' ').toLowerCase();
  }

  // ─── Profile storage ─────────────────────────────────────────────────

  Future<Map<String, Map<String, dynamic>>> _loadProfiles() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_profilesKey);
    if (raw == null || raw.isEmpty) return {};
    try {
      final decoded = jsonDecode(raw) as Map<String, dynamic>;
      return decoded.map((k, v) {
        final entry = (v is Map)
            ? Map<String, dynamic>.from(v as Map)
            : <String, dynamic>{'value': '$v'};
        if (!entry.containsKey('source')) entry['source'] = _sourceManual;
        if (!entry.containsKey('updatedAt')) {
          entry['updatedAt'] = DateTime.now().microsecondsSinceEpoch;
        }
        return MapEntry(k, entry);
      });
    } catch (_) {
      return {};
    }
  }

  Future<void> _saveProfiles(Map<String, Map<String, dynamic>> profiles) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_profilesKey, jsonEncode(profiles));
  }

  static bool _isValidProfileKey(String key) {
    if (_knownProfileKeys.contains(key)) return true;
    return _customProfileKeyRe.hasMatch(key);
  }

  // ─── Tool implementations ─────────────────────────────────────────────

  /// memory_list — list with optional filters (scope, type, status, assistantId)
  Future<Map<String, dynamic>> _memoryList(Map<String, dynamic> args) async {
    final assistantId = (args['assistantId'] ?? '').toString();
    final scope = (args['scope'] ?? '').toString();
    final type = (args['type'] ?? '').toString();
    final status = (args['status'] ?? '').toString();

    var all = await _loadAll();
    if (assistantId.isNotEmpty) {
      all = all.where((m) => (m['assistantId'] ?? '') == assistantId).toList();
    }
    if (scope.isNotEmpty) {
      all = all.where((m) => (m['scope'] ?? '') == scope).toList();
    }
    if (type.isNotEmpty) {
      all = all.where((m) => (m['type'] ?? '') == type).toList();
    }
    if (status.isNotEmpty) {
      all = all.where((m) => (m['status'] ?? '') == status).toList();
    }

    final sb = StringBuffer();
    if (all.isEmpty) {
      sb.writeln('暂无匹配的记忆。');
    } else {
      sb.writeln('记忆列表 (${all.length} 条):');
      for (final m in all) {
        final id = m['id'];
        final aid = m['assistantId'] ?? '';
        final c = m['content'] ?? '';
        final sc = m['scope'] ?? '';
        final tp = m['type'] ?? '';
        final st = m['status'] ?? '';
        sb.writeln('  [#$id] [$aid] [$sc/$tp/$st] $c');
      }
    }
    return {
      'content': [{'type': 'text', 'text': sb.toString().trimRight()}],
    };
  }

  /// memory_add — enhanced with scope, type, source; auto-dedup
  Future<Map<String, dynamic>> _memoryAdd(Map<String, dynamic> args) async {
    final assistantId = (args['assistantId'] ?? 'default').toString();
    final content = (args['content'] ?? '').toString();
    if (content.isEmpty) {
      return {
        'content': [{'type': 'text', 'text': '错误: content 不能为空。'}],
        'isError': true,
      };
    }

    final scope = (args['scope'] ?? _scopeGlobal).toString();
    final type = (args['type'] ?? _typeIdentity).toString();
    final source = (args['source'] ?? _sourceTool).toString();

    final all = await _loadAll();

    // Dedup: normalized content match for same assistant+scope
    final normalized = _normalizeContent(content);
    final duplicate = all.any((m) =>
        (m['assistantId'] ?? '') == assistantId &&
        (m['scope'] ?? '') == scope &&
        _normalizeContent(m['content'] ?? '') == normalized);
    if (duplicate) {
      return {
        'content': [{'type': 'text', 'text': '跳过重复记忆: 已存在相同内容。'}],
      };
    }

    final now = DateTime.now().microsecondsSinceEpoch;
    final entry = {
      'id': _nextId(all),
      'assistantId': assistantId,
      'content': content,
      'scope': scope,
      'type': type,
      'status': _statusActive,
      'source': source,
      'relatedIds': <String>[],
      'createdAt': now,
      'updatedAt': now,
    };
    all.add(entry);
    await _saveAll(all);
    return {
      'content': [
        {'type': 'text', 'text': '记忆已添加 (#${entry['id']}): $content'},
      ],
    };
  }

  /// memory_update — update content of a memory by id
  Future<Map<String, dynamic>> _memoryUpdate(Map<String, dynamic> args) async {
    final id = (args['id'] as num?)?.toInt() ?? 0;
    final content = (args['content'] ?? '').toString();
    if (id <= 0 || content.isEmpty) {
      return {
        'content': [{'type': 'text', 'text': '错误: 需要有效的 id 和 content。'}],
        'isError': true,
      };
    }
    final all = await _loadAll();
    final idx = all.indexWhere((m) => (m['id'] as num?)?.toInt() == id);
    if (idx == -1) {
      return {
        'content': [{'type': 'text', 'text': '错误: 记忆 #$id 不存在。'}],
        'isError': true,
      };
    }
    all[idx]['content'] = content;
    all[idx]['updatedAt'] = DateTime.now().microsecondsSinceEpoch;
    await _saveAll(all);
    return {
      'content': [{'type': 'text', 'text': '记忆 #$id 已更新。'}],
    };
  }

  /// memory_delete — delete by id
  Future<Map<String, dynamic>> _memoryDelete(Map<String, dynamic> args) async {
    final id = (args['id'] as num?)?.toInt() ?? 0;
    if (id <= 0) {
      return {
        'content': [{'type': 'text', 'text': '错误: 需要有效的 id。'}],
        'isError': true,
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
          'text': deleted > 0 ? '记忆 #$id 已删除。' : '错误: 记忆 #$id 不存在。',
        },
      ],
    };
  }

  /// memory_search — search memories by keyword
  Future<Map<String, dynamic>> _memorySearch(Map<String, dynamic> args) async {
    final query = (args['query'] ?? '').toString().toLowerCase();
    final assistantId = (args['assistantId'] ?? '').toString();
    if (query.isEmpty) {
      return {
        'content': [{'type': 'text', 'text': '错误: query 不能为空。'}],
        'isError': true,
      };
    }
    var all = await _loadAll();
    if (assistantId.isNotEmpty) {
      all = all.where((m) => (m['assistantId'] ?? '') == assistantId).toList();
    }
    final filtered = all.where((m) {
      final c = (m['content'] ?? '').toString().toLowerCase();
      return c.contains(query);
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
      'content': [{'type': 'text', 'text': sb.toString().trimRight()}],
    };
  }

  /// memory_clear — clear all or by assistantId
  Future<Map<String, dynamic>> _memoryClear(Map<String, dynamic> args) async {
    final assistantId = (args['assistantId'] ?? '').toString();
    final all = await _loadAll();
    final before = all.length;
    List<Map<String, dynamic>> remaining;
    int cleared;
    if (assistantId.isEmpty) {
      remaining = [];
      cleared = before;
    } else {
      remaining =
          all.where((m) => (m['assistantId'] ?? '') != assistantId).toList();
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

  /// memory_stats — statistics with breakdown
  Future<Map<String, dynamic>> _memoryStats(Map<String, dynamic> args) async {
    final all = await _loadAll();
    final byAssistant = <String, int>{};
    final byScope = <String, int>{};
    final byType = <String, int>{};
    final byStatus = <String, int>{};

    for (final m in all) {
      final aid = (m['assistantId'] ?? 'unknown').toString();
      byAssistant[aid] = (byAssistant[aid] ?? 0) + 1;
      final sc = (m['scope'] ?? '?').toString();
      byScope[sc] = (byScope[sc] ?? 0) + 1;
      final tp = (m['type'] ?? '?').toString();
      byType[tp] = (byType[tp] ?? 0) + 1;
      final st = (m['status'] ?? '?').toString();
      byStatus[st] = (byStatus[st] ?? 0) + 1;
    }

    final sb = StringBuffer();
    sb.writeln('记忆统计:');
    sb.writeln('  总记忆数: ${all.length}');
    sb.writeln(
        '  按作用域: ${byScope.entries.map((e) => '${e.key}=${e.value}').join(', ')}');
    sb.writeln(
        '  按类型: ${byType.entries.map((e) => '${e.key}=${e.value}').join(', ')}');
    sb.writeln(
        '  按状态: ${byStatus.entries.map((e) => '${e.key}=${e.value}').join(', ')}');
    sb.writeln('  按助手:');
    byAssistant.forEach((aid, cnt) {
      sb.writeln('    $aid: $cnt 条');
    });

    // Profile stats
    final profiles = await _loadProfiles();
    sb.writeln('  用户画像字段: ${profiles.length} 个');

    return {
      'content': [{'type': 'text', 'text': sb.toString().trimRight()}],
    };
  }

  /// memory_read — read all visible active memories for an assistant
  Future<Map<String, dynamic>> _memoryRead(Map<String, dynamic> args) async {
    final assistantId = (args['assistantId'] ?? '').toString();
    final all = await _loadAll();
    final visible = all.where((m) {
      if ((m['status'] ?? '') != _statusActive) return false;
      final scope = (m['scope'] ?? '').toString();
      if (scope == _scopeGlobal) return true;
      if (scope == _scopeAssistant &&
          (m['assistantId'] ?? '') == assistantId) {
        return true;
      }
      return false;
    }).toList();

    final sb = StringBuffer();
    if (visible.isEmpty) {
      sb.writeln('暂无可见记忆。');
    } else {
      sb.writeln('可见记忆 (${visible.length} 条):');
      for (final m in visible) {
        final id = m['id'];
        final c = m['content'] ?? '';
        final tp = m['type'] ?? '';
        sb.writeln('  [#$id] [$tp] $c');
      }
    }
    return {
      'content': [{'type': 'text', 'text': sb.toString().trimRight()}],
    };
  }

  /// memory_search_profile — search or list user profile fields
  Future<Map<String, dynamic>> _memorySearchProfile(
      Map<String, dynamic> args) async {
    final query = (args['query'] ?? '').toString().toLowerCase();
    final profiles = await _loadProfiles();

    final sb = StringBuffer();
    if (query.isNotEmpty) {
      final matched = profiles.entries.where((e) {
        return e.key.toLowerCase().contains(query) ||
            (e.value['value'] ?? '')
                .toString()
                .toLowerCase()
                .contains(query);
      }).toList();
      if (matched.isEmpty) {
        sb.writeln('未找到匹配 "$query" 的画像字段。');
      } else {
        sb.writeln('画像搜索结果 (${matched.length}):');
        for (final e in matched) {
          sb.writeln('  ${e.key}: ${e.value['value']}');
        }
      }
    } else {
      if (profiles.isEmpty) {
        sb.writeln('暂无用户画像数据。');
      } else {
        sb.writeln('用户画像 (${profiles.length} 个字段):');
        for (final e in profiles.entries) {
          sb.writeln('  ${e.key}: ${e.value['value']}');
        }
      }
    }
    return {
      'content': [{'type': 'text', 'text': sb.toString().trimRight()}],
    };
  }

  /// memory_edit — edit specific fields of a memory entry
  Future<Map<String, dynamic>> _memoryEdit(Map<String, dynamic> args) async {
    final id = (args['id'] as num?)?.toInt() ?? 0;
    if (id <= 0) {
      return {
        'content': [{'type': 'text', 'text': '错误: 需要有效的 id。'}],
        'isError': true,
      };
    }
    final all = await _loadAll();
    final idx = all.indexWhere((m) => (m['id'] as num?)?.toInt() == id);
    if (idx == -1) {
      return {
        'content': [{'type': 'text', 'text': '错误: 记忆 #$id 不存在。'}],
        'isError': true,
      };
    }

    final entry = all[idx];
    bool changed = false;

    if (args.containsKey('content')) {
      entry['content'] = (args['content'] ?? '').toString();
      changed = true;
    }
    if (args.containsKey('scope')) {
      final v = (args['scope'] ?? '').toString();
      if ([_scopeGlobal, _scopeAssistant].contains(v)) {
        entry['scope'] = v;
        changed = true;
      }
    }
    if (args.containsKey('type')) {
      final v = (args['type'] ?? '').toString();
      if ([_typeIdentity, _typeWorkflow, _typeVoice, _typeInstruction]
          .contains(v)) {
        entry['type'] = v;
        changed = true;
      }
    }
    if (args.containsKey('status')) {
      final v = (args['status'] ?? '').toString();
      if ([_statusActive, _statusArchived].contains(v)) {
        entry['status'] = v;
        changed = true;
      }
    }
    if (args.containsKey('assistantId')) {
      entry['assistantId'] = (args['assistantId'] ?? '').toString();
      changed = true;
    }

    if (changed) {
      entry['updatedAt'] = DateTime.now().microsecondsSinceEpoch;
      all[idx] = entry;
      await _saveAll(all);
      return {
        'content': [{'type': 'text', 'text': '记忆 #$id 已更新。'}],
      };
    }
    return {
      'content': [{'type': 'text', 'text': '未做任何更改（未提供有效字段）。'}],
    };
  }

  /// update_user_profile — update user profile fields
  Future<Map<String, dynamic>> _updateUserProfile(
      Map<String, dynamic> args) async {
    final key = (args['key'] ?? '').toString();
    final value = (args['value'] ?? '').toString();
    if (key.isEmpty) {
      return {
        'content': [{'type': 'text', 'text': '错误: key 不能为空。'}],
        'isError': true,
      };
    }
    if (!_isValidProfileKey(key)) {
      return {
        'content': [
          {
            'type': 'text',
            'text': '错误: 无效的画像字段 key "$key"。'
                '允许: ${_knownProfileKeys.join(', ')} 或 custom.xxx。',
          },
        ],
        'isError': true,
      };
    }

    final profiles = await _loadProfiles();
    profiles[key] = {
      'value': value,
      'source': (args['source'] ?? _sourceTool).toString(),
      'updatedAt': DateTime.now().microsecondsSinceEpoch,
    };
    await _saveProfiles(profiles);
    return {
      'content': [
        {'type': 'text', 'text': '用户画像已更新: $key = $value'},
      ],
    };
  }

  /// chat_search — search chat history via memory proxy
  Future<Map<String, dynamic>> _chatSearch(Map<String, dynamic> args) async {
    final query = (args['query'] ?? '').toString();
    if (query.isEmpty) {
      return {
        'content': [{'type': 'text', 'text': '错误: query 不能为空。'}],
        'isError': true,
      };
    }
    final result = await _memorySearch(
      {'query': query, 'assistantId': args['assistantId'] ?? ''},
    );
    return result;
  }

  // ─── Tokenizer (smart search helper) ────────────────────────────────

  static const Set<String> _cjkStopwords = {
    '用户', '的', '了', '是', '在', '和', '与', '会', '要', '对',
    '这', '那', '他', '她', '它',
  };
  static const Set<String> _englishStopwords = {
    'the', 'a', 'an', 'of', 'to', 'and', 'or', 'in', 'on', 'for',
    'with', 'user', 'users', 'prefer', 'prefers',
  };
  static final RegExp _cjkCharRe =
      RegExp(r'[\u3040-\u30ff\u3400-\u9fff\uf900-\ufaff]');
  static final RegExp _latinWordRe = RegExp(r'[a-z0-9]{2,}');

  /// Tokenize text for smart candidate retrieval (ported from master).
  static List<String> _tokenize(String text) {
    final lower = text.toLowerCase();
    final tokens = <String>{};
    var index = 0;
    while (index < lower.length && tokens.length < 8) {
      final ch = lower[index];
      if (_cjkCharRe.hasMatch(ch)) {
        final start = index;
        while (index < lower.length && _cjkCharRe.hasMatch(lower[index])) {
          index++;
        }
        _addCjkBigrams(lower.substring(start, index), tokens);
      } else {
        final start = index;
        while (index < lower.length && !_cjkCharRe.hasMatch(lower[index])) {
          index++;
        }
        _addLatinWords(lower.substring(start, index), tokens);
      }
    }
    return tokens.toList(growable: false);
  }

  static void _addCjkBigrams(String run, Set<String> tokens) {
    if (run.length < 2) return;
    for (var i = 0; i < run.length - 1 && tokens.length < 8; i++) {
      final gram = run.substring(i, i + 2);
      if (_cjkGramHasStopword(gram)) continue;
      tokens.add(gram);
    }
  }

  static bool _cjkGramHasStopword(String gram) {
    for (final stop in _cjkStopwords) {
      if (gram.contains(stop)) return true;
    }
    return false;
  }

  static void _addLatinWords(String run, Set<String> tokens) {
    for (final match in _latinWordRe.allMatches(run)) {
      if (tokens.length >= 8) return;
      final word = match.group(0)!;
      if (_englishStopwords.contains(word)) continue;
      tokens.add(word);
    }
  }

  // ─── Tool definitions ────────────────────────────────────────────────

  List<Map<String, dynamic>> _toolDefinitions() {
    return [
      // ── Legacy tools ─────────────────────────────────────────────
      {
        'name': 'memory_list',
        'description': '列出记忆，可按助手、作用域、类型、状态过滤。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'assistantId': {'type': 'string', 'description': '可选：按助手ID过滤。'},
            'scope': {'type': 'string', 'description': '可选：global | assistant'},
            'type': {'type': 'string', 'description': '可选：identity | workflow | voice | instruction'},
            'status': {'type': 'string', 'description': '可选：active | archived'},
          },
        },
      },
      {
        'name': 'memory_add',
        'description': '添加一条新记忆（支持 scope/type/source 参数，自动去重）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'assistantId': {'type': 'string', 'description': '助手ID，默认 "default"。'},
            'content': {'type': 'string', 'description': '记忆内容。'},
            'scope': {'type': 'string', 'description': '可选：global | assistant，默认 global。'},
            'type': {'type': 'string', 'description': '可选：identity | workflow | voice | instruction，默认 identity。'},
            'source': {'type': 'string', 'description': '可选：manual | tool | extracted | distilled，默认 tool。'},
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
            'id': {'type': 'integer', 'description': '记忆ID。'},
            'content': {'type': 'string', 'description': '新的记忆内容。'},
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
            'id': {'type': 'integer', 'description': '记忆ID。'},
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
            'query': {'type': 'string', 'description': '搜索关键词。'},
            'assistantId': {'type': 'string', 'description': '可选：限定搜索范围。'},
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
            'assistantId': {'type': 'string', 'description': '可选：只清空指定助手的记忆。不传则清空全部。'},
          },
        },
      },
      {
        'name': 'memory_stats',
        'description': '查看记忆统计信息（总数、作用域、类型、状态分布等）。',
        'inputSchema': {'type': 'object', 'properties': {}},
      },
      // ── New tools (master design) ────────────────────────────────
      {
        'name': 'memory_read',
        'description': '读取指定助手可见的所有活跃记忆（global ∪ assistant scope，active 状态）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'assistantId': {'type': 'string', 'description': '助手ID。'},
          },
          'required': ['assistantId'],
        },
      },
      {
        'name': 'memory_search_profile',
        'description': '搜索或列出用户画像字段。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'query': {'type': 'string', 'description': '可选：搜索关键词。不传则列出全部。'},
          },
        },
      },
      {
        'name': 'memory_edit',
        'description': '编辑记忆条目的特定字段（content/scope/type/status/assistantId）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'id': {'type': 'integer', 'description': '记忆ID。'},
            'content': {'type': 'string', 'description': '可选：新内容。'},
            'scope': {'type': 'string', 'description': '可选：global | assistant'},
            'type': {'type': 'string', 'description': '可选：identity | workflow | voice | instruction'},
            'status': {'type': 'string', 'description': '可选：active | archived'},
            'assistantId': {'type': 'string', 'description': '可选：新助手ID。'},
          },
          'required': ['id'],
        },
      },
      {
        'name': 'update_user_profile',
        'description': '更新用户画像字段。支持预定义键和 custom.xxx 自定义键。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'key': {
              'type': 'string',
              'description': '画像字段名。预定义: preferred_name, gender, pronouns, preferred_language, timezone, occupation, location。自定义: custom.xxx',
            },
            'value': {
              'type': 'string',
              'description': '画像字段值。',
            },
            'source': {
              'type': 'string',
              'description': '可选：manual | tool | extracted | distilled，默认 tool。',
            },
          },
          'required': ['key', 'value'],
        },
      },
      {
        'name': 'chat_search',
        'description': '搜索聊天历史中与关键词相关的记忆内容。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'query': {'type': 'string', 'description': '搜索关键词。'},
            'assistantId': {'type': 'string', 'description': '可选：限定搜索范围。'},
          },
          'required': ['query'],
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