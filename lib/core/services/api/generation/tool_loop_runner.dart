import '../../../models/token_usage.dart';
import '../stream/stream_chunk.dart';
import '../stream/stream_chunk_emit.dart';
/// Local typedef matching Kelivo's ToolCallHandler signature.
typedef ToolCallHandler =
    Future<String> Function(
      String name,
      Map<String, dynamic> arguments, {
      String? toolCallId,
    });
final class ExecutedClientTool {
  const ExecutedClientTool({required this.call, required this.content});
  final EmitToolCall call;
  final String content;
}
/// Execute [calls] and yield [ToolCallResult]s (and optionally [ToolCall*]).
Stream<StreamChunk> executeClientTools({
  required List<EmitToolCall> calls,
  required ToolCallHandler onToolCall,
  bool emitCalls = false,
  TokenUsage? usage,
  int totalTokens = 0,
}) async* {
  if (calls.isEmpty) return;
  if (emitCalls) {
    yield* emitToolCalls(calls, usage: usage, totalTokens: totalTokens);
  }
  final results = <EmitToolResult>[];
  for (final call in calls) {
    final content = await onToolCall(
      call.name,
      call.arguments,
      toolCallId: call.id,
    );
    results.add(
      emitToolResult(
        id: call.id,
        name: call.name,
        arguments: call.arguments,
        content: content,
        metadata: call.metadata,
      ),
    );
  }
  yield* emitToolResults(results, usage: usage, totalTokens: totalTokens);
}
/// After-round client-tool loop: execute → append → send follow-up → repeat.
Stream<StreamChunk> runClientToolFollowUps({
  required List<EmitToolCall> initialCalls,
  required ToolCallHandler onToolCall,
  required void Function(List<ExecutedClientTool> executed) append,
  required Stream<StreamChunk> Function() sendFollowUp,
  required List<EmitToolCall> Function() takeCallsAfterRound,
  required Stream<StreamChunk> Function() finish,
  bool emitCalls = false,
  TokenUsage? Function()? usageOf,
}) async* {
  var calls = List<EmitToolCall>.from(initialCalls);
  while (calls.isNotEmpty) {
    final usage = usageOf?.call();
    final totalTokens = usage?.totalTokens ?? 0;
    final executed = <ExecutedClientTool>[];
    if (emitCalls) {
      yield* emitToolCalls(calls, usage: usage, totalTokens: totalTokens);
    }
    for (final call in calls) {
      executed.add(
        ExecutedClientTool(
          call: call,
          content: await onToolCall(
            call.name,
            call.arguments,
            toolCallId: call.id,
          ),
        ),
      );
    }
    yield* emitToolResults(
      [
        for (final item in executed)
          emitToolResult(
            id: item.call.id,
            name: item.call.name,
            arguments: item.call.arguments,
            content: item.content,
            metadata: item.call.metadata,
          ),
      ],
      usage: usage,
      totalTokens: totalTokens,
    );
    append(executed);
    yield* sendFollowUp();
    calls = takeCallsAfterRound();
  }
  yield* finish();
}
/// In-round loop used by Claude / Gemini.
Stream<StreamChunk> runProviderToolRounds({
  required Stream<StreamChunk> Function() sendRound,
  required List<EmitToolCall> Function() takeCalls,
  required void Function(List<ExecutedClientTool> executed) append,
  required bool Function() continueWithoutCalls,
  required Stream<StreamChunk> Function() finish,
  ToolCallHandler? onToolCall,
  bool emitCalls = false,
  bool executeAfterRound = true,
  TokenUsage? Function()? usageOf,
}) async* {
  while (true) {
    yield* sendRound();
    final calls = takeCalls();
    if (calls.isEmpty && !continueWithoutCalls()) {
      yield* finish();
      return;
    }
    final executed = <ExecutedClientTool>[];
    if (executeAfterRound && calls.isNotEmpty && onToolCall != null) {
      final usage = usageOf?.call();
      final totalTokens = usage?.totalTokens ?? 0;
      if (emitCalls) {
        yield* emitToolCalls(calls, usage: usage, totalTokens: totalTokens);
      }
      for (final call in calls) {
        executed.add(
          ExecutedClientTool(
            call: call,
            content: await onToolCall(
              call.name,
              call.arguments,
              toolCallId: call.id,
            ),
          ),
        );
      }
      yield* emitToolResults(
        [
          for (final item in executed)
            emitToolResult(
              id: item.call.id,
              name: item.call.name,
              arguments: item.call.arguments,
              content: item.content,
              metadata: item.call.metadata,
            ),
        ],
        usage: usage,
        totalTokens: totalTokens,
      );
    }
    append(executed);
  }
}
