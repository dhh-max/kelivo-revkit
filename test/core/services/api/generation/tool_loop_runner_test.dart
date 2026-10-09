import 'package:Kelivo/core/models/token_usage.dart';
import 'package:Kelivo/core/services/api/chat_api_service.dart';
import 'package:Kelivo/core/services/api/stream/stream_chunk.dart';
import 'package:Kelivo/core/services/api/stream/stream_chunk_handler.dart';
import 'package:Kelivo/core/services/api/stream/stream_chunk_ids.dart';
import 'package:Kelivo/utils/mcp_structured_image.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('executeClientTools emits ToolCall* then ToolCallResult', () async {
    final chunks = await executeClientTools(
      calls: [
        emitToolCall(
          id: 'call_1',
          name: 'lookup',
          arguments: const <String, dynamic>{'q': 'kelivo'},
        ),
      ],
      onToolCall: (name, args, {toolCallId}) async => '{"ok":true}',
      emitCalls: true,
    ).toList();

    expect(chunks.whereType<ToolCallStart>().single.id, 'call_1');
    expect(chunks.whereType<ToolCallEnd>().single.id, 'call_1');
    expect(chunks.whereType<ToolCallResult>().single.output, '{"ok":true}');
    expect(chunks.whereType<ServerToolEnd>(), isEmpty);
  });

  test(
    'runClientToolFollowUps executes, appends, and stops when no more calls',
    () async {
      final appended = <String>[];
      var rounds = 0;
      final chunks = await runClientToolFollowUps(
        initialCalls: [
          emitToolCall(
            id: 'call_1',
            name: 'lookup',
            arguments: const <String, dynamic>{'q': '1'},
          ),
        ],
        onToolCall: (name, args, {toolCallId}) async => 'res-$toolCallId',
        append: (executed) {
          appended.addAll(executed.map((item) => item.content));
        },
        sendFollowUp: () async* {
          rounds += 1;
          yield const TextDelta(id: 't', text: 'done');
        },
        takeCallsAfterRound: () => const <EmitToolCall>[],
        finish: () => emitFinish(ids: StreamChunkIds('finish')),
      ).toList();

      expect(appended, ['res-call_1']);
      expect(rounds, 1);
      expect(chunks.whereType<ToolCallResult>().single.output, 'res-call_1');
      expect(chunks.whereType<TextDelta>().single.text, 'done');
      expect(chunks.whereType<Finish>(), hasLength(1));
    },
  );

  test(
    'runProviderToolRounds sends, executes after the round, then finishes',
    () async {
      var sends = 0;
      final appended = <int>[];
      final chunks = await runProviderToolRounds(
        sendRound: () async* {
          sends += 1;
          yield TextDelta(id: 't', text: 'round-$sends');
        },
        takeCalls: () => sends == 1
            ? [
                emitToolCall(
                  id: 'call_1',
                  name: 'lookup',
                  arguments: const <String, dynamic>{'q': '1'},
                ),
              ]
            : const <EmitToolCall>[],
        continueWithoutCalls: () => false,
        executeAfterRound: true,
        emitCalls: true,
        onToolCall: (name, args, {toolCallId}) async => 'res-$toolCallId',
        append: (executed) => appended.add(executed.length),
        finish: () => emitFinish(ids: StreamChunkIds('finish')),
      ).toList();

      expect(sends, 2);
      expect(appended, [1]);
      expect(chunks.whereType<ToolCallStart>(), hasLength(1));
      expect(chunks.whereType<ToolCallResult>().single.output, 'res-call_1');
      expect(chunks.whereType<Finish>(), hasLength(1));
    },
  );

  test(
    'runClientToolFollowUps still emits ToolCall* on later rounds',
    () async {
      var rounds = 0;
      final chunks = await runClientToolFollowUps(
        initialCalls: [
          emitToolCall(
            id: 'call_1',
            name: 'lookup',
            arguments: const <String, dynamic>{'q': '1'},
          ),
        ],
        onToolCall: (name, args, {toolCallId}) async => 'res-$toolCallId',
        append: (_) {},
        sendFollowUp: () async* {
          rounds += 1;
          yield TextDelta(id: 't-$rounds', text: 'round-$rounds');
        },
        takeCallsAfterRound: () => rounds == 1
            ? [
                emitToolCall(
                  id: 'call_2',
                  name: 'lookup',
                  arguments: const <String, dynamic>{'q': '2'},
                ),
              ]
            : const <EmitToolCall>[],
        finish: () => emitFinish(ids: StreamChunkIds('finish')),
        emitCalls: true,
      ).toList();

      expect(chunks.whereType<ToolCallStart>().map((chunk) => chunk.id), [
        'call_1',
        'call_2',
      ]);
      expect(chunks.whereType<ToolCallStart>().map((chunk) => chunk.toolName), [
        'lookup',
        'lookup',
      ]);
      expect(chunks.whereType<ToolCallResult>().map((chunk) => chunk.id), [
        'call_1',
        'call_2',
      ]);
    },
  );

  test('runProviderToolRounds continues without calls when asked', () async {
    var sends = 0;
    final chunks = await runProviderToolRounds(
      sendRound: () async* {
        sends += 1;
        yield TextDelta(id: 't', text: 'pause-$sends');
      },
      takeCalls: () => const <EmitToolCall>[],
      continueWithoutCalls: () => sends < 2,
      executeAfterRound: false,
      append: (_) {},
      finish: () => emitFinish(ids: StreamChunkIds('finish')),
    ).toList();

    expect(sends, 2);
    expect(chunks.whereType<TextDelta>(), hasLength(2));
    expect(chunks.whereType<Finish>(), hasLength(1));
  });

  test(
    'three tool-call rounds keep the latest usage and do not double-count repeats',
    () async {
      const snapshots = [
        TokenUsage(promptTokens: 100, completionTokens: 20, totalTokens: 120),
        TokenUsage(promptTokens: 400, completionTokens: 60, totalTokens: 460),
        TokenUsage(promptTokens: 900, completionTokens: 70, totalTokens: 970),
      ];
      var sends = 0;
      TokenUsage? usage;
      final chunks = await runProviderToolRounds(
        sendRound: () async* {
          usage = snapshots[sends];
          sends += 1;
          yield Usage(usage!);
          yield TextDelta(id: 't-$sends', text: 'round-$sends');
        },
        takeCalls: () => sends < 3
            ? [
                emitToolCall(
                  id: 'call_$sends',
                  name: 'lookup',
                  arguments: <String, dynamic>{'q': '$sends'},
                ),
              ]
            : const <EmitToolCall>[],
        continueWithoutCalls: () => false,
        executeAfterRound: true,
        emitCalls: true,
        onToolCall: (name, args, {toolCallId}) async => 'res',
        append: (_) {},
        finish: () => emitFinish(ids: StreamChunkIds('finish'), usage: usage),
        usageOf: () => usage,
      ).toList();

      final result = StreamChunkHandler.collect(chunks);
      expect(result.usage!.promptTokens, 900);
      expect(result.usage!.completionTokens, 70);
      expect(result.usage!.totalTokens, 970);
      expect(
        result.totalUsage!.totalTokens,
        snapshots.fold<int>(0, (sum, usage) => sum + usage.totalTokens),
      );
      expect(chunks.whereType<Usage>().length, greaterThan(3));
    },
  );

  test('a silent round does not double-count prior usage', () async {
    const first = TokenUsage(
      promptTokens: 100,
      completionTokens: 20,
      totalTokens: 120,
    );
    const afterThird = TokenUsage(
      promptTokens: 600,
      completionTokens: 30,
      totalTokens: 630,
    );
    var sends = 0;
    TokenUsage? usage;
    final chunks = await runProviderToolRounds(
      sendRound: () async* {
        usage = null;
        sends += 1;
        if (sends == 1) {
          usage = first;
          yield const Usage(first);
        } else if (sends == 3) {
          usage = afterThird;
          yield const Usage(afterThird);
        }
        yield TextDelta(id: 't-$sends', text: 'round-$sends');
      },
      takeCalls: () => sends < 3
          ? [
              emitToolCall(
                id: 'call_$sends',
                name: 'lookup',
                arguments: <String, dynamic>{'q': '$sends'},
              ),
            ]
          : const <EmitToolCall>[],
      continueWithoutCalls: () => false,
      executeAfterRound: true,
      emitCalls: true,
      onToolCall: (name, args, {toolCallId}) async => 'res',
      append: (_) {},
      finish: () => emitFinish(ids: StreamChunkIds('finish'), usage: usage),
      usageOf: () => usage,
    ).toList();

    final result = StreamChunkHandler.collect(chunks);
    expect(result.usage!.promptTokens, 600);
    expect(result.usage!.completionTokens, 30);
    expect(result.usage!.totalTokens, 630);
    expect(result.totalUsage!.totalTokens, 750);
  });

  test('runClientToolFollowUps stops at the max-rounds hard cap', () async {
    // 回归锁（2026-09-15）：此前循环无上限，模型持续换参数发 tool_calls
    // 时会无限循环。触顶后当前批次结果必须照常执行并回填（协议完整），
    // 仅不再发起新一轮请求。
    final appended = <String>[];
    var followUps = 0;
    var callSeq = 0;
    final chunks = await runClientToolFollowUps(
      initialCalls: [
        emitToolCall(
          id: 'call_0',
          name: 'lookup',
          arguments: const <String, dynamic>{'q': '0'},
        ),
      ],
      onToolCall: (name, args, {toolCallId}) async => 'res-$toolCallId',
      append: (executed) =>
          appended.addAll(executed.map((item) => item.content)),
      sendFollowUp: () async* {
        followUps += 1;
      },
      takeCallsAfterRound: () {
        callSeq += 1;
        return [
          emitToolCall(
            id: 'call_$callSeq',
            name: 'lookup',
            arguments: <String, dynamic>{'q': '$callSeq'},
          ),
        ];
      },
      finish: () => emitFinish(ids: StreamChunkIds('finish')),
      maxRounds: 3,
    ).toList();

    // 3 轮全部执行并回填；follow-up 只发起 2 次（第 3 轮后不再请求）。
    expect(appended, ['res-call_0', 'res-call_1', 'res-call_2']);
    expect(followUps, 2);
    expect(chunks.whereType<Finish>(), hasLength(1));
  });

  test(
    'no handler (caller owns the loop): calls are emitted and the round finishes',
    () async {
      // 2026-09-30 端到端复现的真缺陷：子代理不传 onToolCall（它自己控循环），
      // 旧代码在这里既不执行也不 emit，模型要求调工具被静默丢弃，子代理只拿到
      // 一段空结论——「指派他，他说 OK，其实什么工作都不干」。
      var sends = 0;
      var appends = 0;
      final chunks = await runProviderToolRounds(
        sendRound: () async* {
          sends += 1;
          yield TextDelta(id: 't', text: 'round-$sends');
        },
        takeCalls: () => [
          emitToolCall(
            id: 'call_1',
            name: 'file',
            arguments: const <String, dynamic>{'action': 'read'},
          ),
        ],
        continueWithoutCalls: () => false,
        executeAfterRound: true,
        emitCalls: true,
        onToolCall: null,
        append: (_) => appends += 1,
        finish: () => emitFinish(ids: StreamChunkIds('finish')),
      ).toList();

      expect(sends, 1, reason: '没有工具结果可回填，重发只会拿回同一个调用');
      expect(appends, 0, reason: '没有 handler 就不该执行工具');
      expect(
        chunks.whereType<ToolCallStart>().map((chunk) => chunk.toolName),
        ['file'],
        reason: '模型的工具调用必须如实发出去，不能静默丢弃',
      );
      expect(chunks.whereType<ToolCallEnd>(), hasLength(1));
      expect(chunks.whereType<Finish>(), hasLength(1));
    },
  );

  test(
    'no handler + streaming (emitCalls=false): no duplicate emit, still finishes',
    () async {
      // 流式路径的 ToolCall* 已由 decoder 发出，这里不能再发一遍（会重复计数）；
      // 但同样必须收尾而不是继续 follow-up。
      var sends = 0;
      final chunks = await runProviderToolRounds(
        sendRound: () async* {
          sends += 1;
          yield TextDelta(id: 't', text: 'round-$sends');
        },
        takeCalls: () => [
          emitToolCall(
            id: 'call_1',
            name: 'file',
            arguments: const <String, dynamic>{'action': 'read'},
          ),
        ],
        continueWithoutCalls: () => false,
        executeAfterRound: false,
        emitCalls: false,
        onToolCall: null,
        append: (_) {},
        finish: () => emitFinish(ids: StreamChunkIds('finish')),
      ).toList();

      expect(sends, 1);
      expect(chunks.whereType<ToolCallStart>(), isEmpty);
      expect(chunks.whereType<Finish>(), hasLength(1));
    },
  );

  test('runProviderToolRounds stops at the max-rounds hard cap', () async {
    var sends = 0;
    final chunks = await runProviderToolRounds(
      sendRound: () async* {
        sends += 1;
        yield TextDelta(id: 't-$sends', text: 'round-$sends');
      },
      takeCalls: () => [
        emitToolCall(
          id: 'call_$sends',
          name: 'lookup',
          arguments: <String, dynamic>{'q': '$sends'},
        ),
      ],
      continueWithoutCalls: () => false,
      executeAfterRound: true,
      onToolCall: (name, args, {toolCallId}) async => 'res',
      append: (_) {},
      finish: () => emitFinish(ids: StreamChunkIds('finish')),
      maxRounds: 2,
    ).toList();

    expect(sends, 2);
    expect(chunks.whereType<ToolCallResult>(), hasLength(2));
    expect(chunks.whereType<Finish>(), hasLength(1));
  });

  test(
    'streaming and non-streaming send Markdown to the model with mcpResult',
    () async {
      const markdown =
          'caption A\n![](https://cdn.example.com/a.png)\n'
          'caption B\n![](https://cdn.example.com/b.png)';
      final typed = const McpToolResult(
        markdown: markdown,
        imageUris: [
          'https://cdn.example.com/a.png',
          'https://cdn.example.com/b.png',
        ],
      );

      Future<Object?> onToolCall(
        String name,
        Map<String, dynamic> args, {
        String? toolCallId,
      }) async => typed;

      final streamed = await executeClientTools(
        calls: [
          emitToolCall(
            id: 'call_s',
            name: 'shot',
            arguments: const <String, dynamic>{},
            metadata: const {'anthropic': 'keep'},
          ),
        ],
        onToolCall: onToolCall,
      ).toList();

      ExecutedClientTool? appended;
      await runProviderToolRounds(
        sendRound: () async* {
          yield const TextDelta(id: 't', text: 'round');
        },
        takeCalls: () => appended == null
            ? [
                emitToolCall(
                  id: 'call_n',
                  name: 'shot',
                  arguments: const <String, dynamic>{},
                ),
              ]
            : const <EmitToolCall>[],
        continueWithoutCalls: () => false,
        executeAfterRound: true,
        onToolCall: onToolCall,
        append: (executed) {
          if (executed.isNotEmpty) appended = executed.single;
        },
        finish: () => emitFinish(ids: StreamChunkIds('finish')),
      ).toList();

      final streamResult = streamed.whereType<ToolCallResult>().single;
      expect(streamResult.output, markdown);
      expect(streamResult.output, isNot(contains('"kelivo"')));
      expect(
        mcpResultImageUris(readMcpResultMetadata(streamResult.metadata)),
        ['https://cdn.example.com/a.png', 'https://cdn.example.com/b.png'],
      );
      expect(streamResult.metadata!['anthropic'], 'keep');

      expect(appended, isNotNull);
      expect(appended!.content, markdown);
      expect(
        mcpResultImageUris(readMcpResultMetadata(appended!.metadata)),
        ['https://cdn.example.com/a.png', 'https://cdn.example.com/b.png'],
      );
    },
  );
}
