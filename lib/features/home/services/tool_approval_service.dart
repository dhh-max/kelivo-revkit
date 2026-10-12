import 'dart:async';
import 'package:flutter/foundation.dart';

/// Result of a tool approval request.
class ToolApprovalResult {
  final bool approved;
  final String? denyReason;

  const ToolApprovalResult({required this.approved, this.denyReason});

  factory ToolApprovalResult.approved() =>
      const ToolApprovalResult(approved: true);
  factory ToolApprovalResult.denied([String? reason]) =>
      ToolApprovalResult(approved: false, denyReason: reason);

  /// Result for a timed-out approval request.
  factory ToolApprovalResult.timeout() =>
      const ToolApprovalResult(approved: false, denyReason: 'Approval timed out');
}

/// A pending approval request for an MCP tool call.
class ToolApprovalRequest {
  final String toolCallId;
  final String toolName;
  final String? serverId;
  final Map<String, dynamic> arguments;
  final Completer<ToolApprovalResult> _completer;
  final DateTime createdAt;
  Timer? _timeoutTimer;

  ToolApprovalRequest({
    required this.toolCallId,
    required this.toolName,
    this.serverId,
    required this.arguments,
    required Completer<ToolApprovalResult> completer,
    DateTime? createdAt,
  })  : _completer = completer,
        createdAt = createdAt ?? DateTime.now();

  /// Elapsed time since creation.
  Duration get elapsed => DateTime.now().difference(createdAt);

  /// Whether this request has been pending for more than [threshold].
  bool isStale(Duration threshold) => elapsed > threshold;

  /// Start a timeout timer that auto-denies after [duration].
  void startTimeout(Duration duration, void Function() onTimeout) {
    _timeoutTimer?.cancel();
    _timeoutTimer = Timer(duration, () {
      if (!_completer.isCompleted) {
        _completer.complete(ToolApprovalResult.timeout());
        onTimeout();
      }
    });
  }

  void cancelTimeout() {
    _timeoutTimer?.cancel();
    _timeoutTimer = null;
  }

  Completer<ToolApprovalResult> get completer => _completer;
}

/// Manages approval state for MCP tool calls that require user confirmation.
///
/// Flow:
/// 1. [requestApproval] is called from the tool handler when a tool needs approval.
///    It creates a [Completer], stores the request in [pendingRequests], and returns
///    the completer's future. The tool handler `await`s this future, blocking execution.
/// 2. The UI watches this service and shows approve/deny buttons.
/// 3. When the user taps approve/deny, [approve] or [deny] completes the completer,
///    unblocking the tool handler.
class ToolApprovalService extends ChangeNotifier {
  final Map<String, ToolApprovalRequest> _pending = {};
  Duration _defaultTimeout = const Duration(minutes: 5);

  /// Unmodifiable view of pending approval requests.
  Map<String, ToolApprovalRequest> get pendingRequests =>
      Map.unmodifiable(_pending);

  /// Whether there are any pending approval requests.
  bool get hasPending => _pending.isNotEmpty;

  /// Count of pending requests.
  int get pendingCount => _pending.length;

  /// Default approval timeout duration.
  Duration get defaultTimeout => _defaultTimeout;
  set defaultTimeout(Duration d) {
    _defaultTimeout = d;
    notifyListeners();
  }

  /// Check if a specific tool call is pending approval.
  bool isPending(String toolCallId) => _pending.containsKey(toolCallId);

  /// Get the elapsed time for a pending request.
  Duration? elapsedFor(String toolCallId) => _pending[toolCallId]?.elapsed;

  /// Get list of stale (long-pending) request IDs.
  List<String> get staleRequestIds {
    final threshold = Duration(minutes: 2);
    return _pending.entries
        .where((e) => e.value.isStale(threshold))
        .map((e) => e.key)
        .toList();
  }

  /// Request approval for a tool call.
  /// Returns a [Future] that completes when the user approves or denies.
  /// If [serverId] and [toolName] match an auto-approval rule, the result
  /// is returned immediately without showing a UI prompt.
  Future<ToolApprovalResult> requestApproval({
    required String toolCallId,
    required String toolName,
    String? serverId,
    required Map<String, dynamic> arguments,
    bool Function(String serverId, String toolName)? autoApprovalCheck,
    Duration? timeout,
  }) {
    // Check auto-approval rules first
    if (autoApprovalCheck != null) {
      final shouldAuto = autoApprovalCheck(serverId ?? '', toolName);
      if (shouldAuto) {
        return Future.value(ToolApprovalResult.approved());
      }
    }

    final completer = Completer<ToolApprovalResult>();
    final request = ToolApprovalRequest(
      toolCallId: toolCallId,
      toolName: toolName,
      serverId: serverId,
      arguments: arguments,
      completer: completer,
    );

    // Start timeout timer
    final effectiveTimeout = timeout ?? _defaultTimeout;
    request.startTimeout(effectiveTimeout, () {
      _pending.remove(toolCallId);
      notifyListeners();
    });

    _pending[toolCallId] = request;
    notifyListeners();
    return completer.future;
  }

  /// Approve a pending tool call.
  void approve(String toolCallId) {
    final req = _pending.remove(toolCallId);
    if (req != null) {
      req.cancelTimeout();
      if (!req.completer.isCompleted) {
        req.completer.complete(ToolApprovalResult.approved());
      }
    }
    notifyListeners();
  }

  /// Approve all pending tool calls in batch.
  void approveAll() {
    for (final req in _pending.values) {
      req.cancelTimeout();
      if (!req.completer.isCompleted) {
        req.completer.complete(ToolApprovalResult.approved());
      }
    }
    _pending.clear();
    notifyListeners();
  }

  /// Deny a pending tool call with an optional reason.
  void deny(String toolCallId, [String? reason]) {
    final req = _pending.remove(toolCallId);
    if (req != null) {
      req.cancelTimeout();
      if (!req.completer.isCompleted) {
        req.completer.complete(ToolApprovalResult.denied(reason));
      }
    }
    notifyListeners();
  }

  /// Deny all pending tool calls in batch.
  void denyAll([String? reason]) {
    for (final req in _pending.values) {
      req.cancelTimeout();
      if (!req.completer.isCompleted) {
        req.completer.complete(ToolApprovalResult.denied(reason));
      }
    }
    _pending.clear();
    notifyListeners();
  }

  /// Cancel all pending approvals (e.g., when streaming is cancelled).
  void cancelAll() {
    for (final req in _pending.values) {
      req.cancelTimeout();
      if (!req.completer.isCompleted) {
        req.completer.complete(ToolApprovalResult.denied('cancelled'));
      }
    }
    _pending.clear();
    notifyListeners();
  }

  /// Auto-deny stale requests that have been pending beyond the threshold.
  void autoDenyStale([Duration? threshold]) {
    final t = threshold ?? const Duration(minutes: 3);
    final staleIds = <String>[];
    for (final entry in _pending.entries) {
      if (entry.value.isStale(t)) {
        staleIds.add(entry.key);
      }
    }
    for (final id in staleIds) {
      deny(id, 'Auto-denied: stale request');
    }
  }
}
