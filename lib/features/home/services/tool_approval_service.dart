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
}

/// A pending approval request for an MCP tool call.
class ToolApprovalRequest {
  final String toolCallId;
  final String toolName;
  final String? serverId;
  final Map<String, dynamic> arguments;
  final Completer<ToolApprovalResult> _completer;
  ToolApprovalRequest({
    required this.toolCallId,
    required this.toolName,
    this.serverId,
    required this.arguments,
    required this._completer,
  });
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

  /// Unmodifiable view of pending approval requests.
  Map<String, ToolApprovalRequest> get pendingRequests =>
      Map.unmodifiable(_pending);

  /// Whether there are any pending approval requests.
  bool get hasPending => _pending.isNotEmpty;

  /// Check if a specific tool call is pending approval.
  bool isPending(String toolCallId) => _pending.containsKey(toolCallId);

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
  }) {
    // Check auto-approval rules first
    if (autoApprovalCheck != null) {
      final shouldAuto = autoApprovalCheck(serverId ?? '', toolName);
      if (shouldAuto) {
        return Future.value(ToolApprovalResult.approved());
      }
    }

    final completer = Completer<ToolApprovalResult>();
    _pending[toolCallId] = ToolApprovalRequest(
      toolCallId: toolCallId,
      toolName: toolName,
      serverId: serverId,
      arguments: arguments,
      completer: completer,
    );
    notifyListeners();
    return completer.future;
  }

  /// Approve a pending tool call.
  void approve(String toolCallId) {
    final req = _pending.remove(toolCallId);
    if (req != null && !req._completer.isCompleted) {
      req._completer.complete(ToolApprovalResult.approved());
    }
    notifyListeners();
  }

  /// Approve all pending tool calls in batch.
  void approveAll() {
    for (final req in _pending.values) {
      if (!req._completer.isCompleted) {
        req._completer.complete(ToolApprovalResult.approved());
      }
    }
    _pending.clear();
    notifyListeners();
  }

  /// Deny a pending tool call with an optional reason.
  void deny(String toolCallId, [String? reason]) {
    final req = _pending.remove(toolCallId);
    if (req != null && !req._completer.isCompleted) {
      req._completer.complete(ToolApprovalResult.denied(reason));
    }
    notifyListeners();
  }

  /// Deny all pending tool calls in batch.
  void denyAll([String? reason]) {
    for (final req in _pending.values) {
      if (!req._completer.isCompleted) {
        req._completer.complete(ToolApprovalResult.denied(reason));
      }
    }
    _pending.clear();
    notifyListeners();
  }

  /// Cancel all pending approvals (e.g., when streaming is cancelled).
  void cancelAll() {
    for (final req in _pending.values) {
      if (!req._completer.isCompleted) {
        req._completer.complete(ToolApprovalResult.denied('cancelled'));
      }
    }
    _pending.clear();
    notifyListeners();
  }
}
