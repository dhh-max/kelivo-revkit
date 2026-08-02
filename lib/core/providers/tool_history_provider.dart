import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';
import '../models/tool_call_history.dart';

/// Provider for tracking MCP tool call history and auto-approval rules.
class ToolHistoryProvider with ChangeNotifier {
  static const String _historyKey = 'kelivo_tool_call_history_v1';
  static const String _rulesKey = 'kelivo_tool_auto_approval_rules_v1';
  static const int _maxHistory = 200;

  final List<ToolCallRecord> _history = [];
  List<ToolAutoApprovalRule> _rules = [];
  bool _initialized = false;

  List<ToolCallRecord> get history => List.unmodifiable(_history);
  List<ToolAutoApprovalRule> get rules => List.unmodifiable(_rules);

  /// Get history for a specific conversation.
  List<ToolCallRecord> historyForConversation(String conversationId) =>
      _history.where((r) => r.conversationId == conversationId).toList();

  /// Get history summary stats.
  Map<String, int> get stats {
    int success = 0, error = 0, pending = 0;
    for (final r in _history) {
      if (r.isPending) {
        pending++;
      } else if (r.isError) {
        error++;
      } else {
        success++;
      }
    }
    return {'success': success, 'error': error, 'pending': pending, 'total': _history.length};
  }

  /// Average duration of completed calls in milliseconds.
  int get avgDurationMs {
    final completed = _history.where((r) => r.duration != null).toList();
    if (completed.isEmpty) return 0;
    final total = completed.fold<int>(0, (sum, r) => sum + r.duration!.inMilliseconds);
    return total ~/ completed.length;
  }

  Future<void> initialize() async {
    if (_initialized) return;
    await _load();
    _initialized = true;
  }

  Future<void> _load() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      // We don't persist full history across app restarts for performance;
      // only rules are persisted.
      final rulesRaw = prefs.getString(_rulesKey);
      if (rulesRaw != null && rulesRaw.isNotEmpty) {
        final list = jsonDecode(rulesRaw) as List<dynamic>;
        _rules = list
            .whereType<Map<String, dynamic>>()
            .map((e) => ToolAutoApprovalRule.fromJson(e))
            .toList();
      }
    } catch (e) {
      debugPrint('Failed to load tool history rules: $e');
    }
    notifyListeners();
  }

  Future<void> _persistRules() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final json = jsonEncode(_rules.map((r) => r.toJson()).toList());
      await prefs.setString(_rulesKey, json);
    } catch (_) {}
  }

  /// Record start of a tool call.
  String recordStart({
    required String toolName,
    required String serverId,
    required Map<String, dynamic> arguments,
    required String conversationId,
    required String messageId,
  }) {
    final id = const Uuid().v4();
    _history.insert(0, ToolCallRecord(
      id: id,
      toolName: toolName,
      serverId: serverId,
      arguments: arguments,
      startedAt: DateTime.now(),
      conversationId: conversationId,
      messageId: messageId,
    ));
    // Trim history
    if (_history.length > _maxHistory) {
      _history.removeRange(_maxHistory, _history.length);
    }
    notifyListeners();
    return id;
  }

  /// Record completion of a tool call.
  void recordComplete(String id, {String? result, String? error}) {
    final idx = _history.indexWhere((r) => r.id == id);
    if (idx < 0) return;
    _history[idx] = _history[idx].copyWith(
      result: result,
      error: error,
      completedAt: DateTime.now(),
    );
    notifyListeners();
  }

  /// Clear all history.
  void clearHistory() {
    _history.clear();
    notifyListeners();
  }

  // ===== Auto-approval rules =====

  /// Check if a tool call should be auto-approved.
  /// Returns null if no rule matches (manual approval needed).
  bool? shouldAutoApprove(String serverId, String toolName) {
    for (final rule in _rules) {
      if (rule.matches(serverId, toolName)) {
        return rule.approve;
      }
    }
    return null;
  }

  Future<void> addRule(ToolAutoApprovalRule rule) async {
    _rules.add(rule);
    await _persistRules();
    notifyListeners();
  }

  Future<void> removeRule(String id) async {
    _rules.removeWhere((r) => r.id == id);
    await _persistRules();
    notifyListeners();
  }

  Future<void> toggleRule(String id) async {
    final idx = _rules.indexWhere((r) => r.id == id);
    if (idx < 0) return;
    final old = _rules[idx];
    _rules[idx] = ToolAutoApprovalRule(
      id: old.id,
      serverIdPattern: old.serverIdPattern,
      toolNamePattern: old.toolNamePattern,
      approve: old.approve,
      createdAt: old.createdAt,
      enabled: !old.enabled,
    );
    await _persistRules();
    notifyListeners();
  }

  Future<void> clearRules() async {
    _rules.clear();
    await _persistRules();
    notifyListeners();
  }

  /// Approve all pending requests in batch.
  List<String> get pendingIds =>
      _history.where((r) => r.isPending).map((r) => r.id).toList();
}