import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/mcp_server/mcp_http_server.dart';
import 'package:Kelivo/core/services/local_tools/local_tool_names.dart';
import 'package:Kelivo/features/solab_apk/services/apk_agent_policy.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final server = McpHttpServer.instance;
  late int port;

  setUpAll(() async {
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    server.configure(port: port, token: '');
    expect(await server.start(), isTrue);
  });

  tearDownAll(server.stop);

  test('lists LAN addresses even when access protection is disabled', () {
    final urls = server.lanUrls;

    expect(urls, contains('http://127.0.0.1:$port/mcp'));
    expect(urls.any((url) => !url.contains('127.0.0.1')), isTrue);
  });

  test('initialize 注入共同判断策略和版本', () async {
    final response = await _call(port, 'initialize', <String, dynamic>{
      'protocolVersion': '2025-06-18',
    });
    final result = response['result'] as Map<String, dynamic>;
    final meta = result['_meta'] as Map<String, dynamic>;

    expect(
      result['instructions'],
      contains(ApkAgentPolicy.sharedDecisionPolicy),
    );
    expect(meta['decisionPolicyVersion'], ApkAgentPolicy.version);
  });

  // 2026-09-21 用户实测：全屏 MCP 页永远显示 0 个客户端（只数 legacy SSE）。
  test('Streamable HTTP 的客户端会被计入 activeClientCount 并刷新最近活动', () async {
    // initialize（服务端下发 mcp-session-id）+ 带 id 的一次调用 = 一个活跃客户端。
    final init = await _call(port, 'initialize', <String, dynamic>{
      'protocolVersion': '2025-06-18',
    });
    expect(init['result'], isNotNull);
    final sessions = await _call(
      port,
      'tools/list',
      const <String, dynamic>{},
      sessionId: 'acc-test-session-1',
    );
    expect(sessions['result'], isNotNull);

    expect(
      server.activeClientCount,
      greaterThanOrEqualTo(1),
      reason: 'Streamable HTTP（无状态 POST）客户端必须被计入，否则页面永远显示 0',
    );
    expect(server.lastClientActivityAt, isNotNull);
  });

  test('不同会话分别登记（不是只认一个会话）', () async {
    await _call(
      port,
      'tools/list',
      const <String, dynamic>{},
      sessionId: 'acc-test-session-a',
    );
    final afterA = server.activeClientCount;
    await _call(
      port,
      'tools/list',
      const <String, dynamic>{},
      sessionId: 'acc-test-session-b',
    );
    expect(server.activeClientCount, greaterThanOrEqualTo(afterA + 1));
  });

  test(
    'queues MCP tool calls and exposes their result through task status',
    () async {
      final queued = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'route_task',
        'arguments': <String, dynamic>{'goal': '分析 APK', 'async': true},
      });
      final queuedText = _toolText(queued);
      final queuedEnvelope = jsonDecode(queuedText) as Map<String, dynamic>;
      final queuedData = queuedEnvelope['data'] as Map<String, dynamic>;
      expect(queuedEnvelope['ok'], isTrue);
      expect(queuedData['status'], anyOf('queued', 'running'));
      expect(queuedData['phase'], anyOf('queued', 'executing'));
      expect(queuedData['progressPercent'], anyOf(0, isNull));
      expect(queuedData['elapsedMs'], isA<int>());

      Map<String, dynamic>? task;
      for (var i = 0; i < 20; i++) {
        final status = await _call(port, 'tools/call', <String, dynamic>{
          'name': 'mcp_task_status',
          'arguments': <String, dynamic>{'taskId': queuedData['taskId']},
        });
        final statusEnvelope =
            jsonDecode(_toolText(status)) as Map<String, dynamic>;
        task = statusEnvelope['data'] as Map<String, dynamic>;
        if (task['status'] == 'completed') break;
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }

      expect(task?['status'], 'completed');
      expect(task?['phase'], 'finished');
      expect(task?['progressPercent'], 100);
      expect(task?['elapsedMs'], isA<int>());
      expect(task?['result'], contains('recommendedTools'));
    },
  );

  test(
    'queues workspace analysis without an explicit async argument',
    () async {
      final queued = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'analyze_apk_workspace',
        'arguments': const <String, dynamic>{},
      });
      final envelope = jsonDecode(_toolText(queued)) as Map<String, dynamic>;
      final data = envelope['data'] as Map<String, dynamic>;

      expect(envelope['ok'], isTrue);
      expect(data['tool'], 'analyze_apk_workspace');
      expect(data['status'], anyOf('queued', 'running'));
    },
  );

  test(
    'retrying the same async call polls task state instead of looping',
    () async {
      final args = <String, dynamic>{
        'action': 'read',
        'path': 'definitely-missing-for-async-test.bin',
        'async': true,
      };
      final first = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'file',
        'arguments': args,
      });
      final firstEnvelope =
          jsonDecode(_toolText(first)) as Map<String, dynamic>;
      final firstData = firstEnvelope['data'] as Map<String, dynamic>;
      // 首次调用：入队返回 taskId
      expect(firstData['taskId'], isNotNull);

      // 同参数重试：文档契约是查状态——必须返回任务状态，而不是 LOOP_DETECTED
      final second = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'file',
        'arguments': args,
      });
      final secondText = _toolText(second);
      expect(secondText, isNot(contains('loop_detected')));
      final secondEnvelope = jsonDecode(secondText) as Map<String, dynamic>;
      final secondData = secondEnvelope['data'] as Map<String, dynamic>;
      expect(secondData['taskId'], firstData['taskId']);
      expect(secondData['stillRunning'], isA<bool>());
      expect(secondData['pollTool'], 'mcp_task_status');
    },
  );

  test('compresses large responses when the client accepts gzip', () async {
    final body = jsonEncode(<String, dynamic>{
      'jsonrpc': '2.0',
      'id': 1,
      'method': 'tools/list',
      'params': const <String, dynamic>{},
    });
    final socket = await Socket.connect('127.0.0.1', port);
    try {
      socket.write(
        'POST /mcp HTTP/1.0\r\n'
        'Host: 127.0.0.1:$port\r\n'
        'Accept-Encoding: gzip\r\n'
        'Content-Type: application/json\r\n'
        'Content-Length: ${utf8.encode(body).length}\r\n'
        '\r\n'
        '$body',
      );
      final raw = <int>[];
      await for (final chunk in socket) {
        raw.addAll(chunk);
      }
      // 字节级找 \r\n\r\n 头部边界：响应体是 gzip 二进制，不能用 utf8 整体解码
      var separator = -1;
      for (var i = 0; i < raw.length - 3; i++) {
        if (raw[i] == 0x0d &&
            raw[i + 1] == 0x0a &&
            raw[i + 2] == 0x0d &&
            raw[i + 3] == 0x0a) {
          separator = i;
          break;
        }
      }
      expect(separator, greaterThan(0));
      final header = utf8.decode(raw.sublist(0, separator)).toLowerCase();
      final payload = raw.sublist(separator + 4);
      expect(header, contains('content-encoding: gzip'));
      // gzip 魔数 0x1f 0x8b：确认响应体是真 gzip 流而不是明文 JSON
      expect(payload[0], 0x1f);
      expect(payload[1], 0x8b);
      final decoded = utf8.decode(gzip.decode(payload));
      expect(decoded, contains('tool_batch'));
    } finally {
      socket.destroy();
    }
  });

  test('returns the standard envelope for unavailable tools', () async {
    final response = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'missing_tool',
      'arguments': const <String, dynamic>{},
    });

    final envelope = jsonDecode(_toolText(response)) as Map<String, dynamic>;
    expect(response['result']?['isError'], isTrue);
    expect(envelope['ok'], isFalse);
    expect(envelope['error']?['code'], 'tool_not_found');
    // 2026-09-19 全量复测：MCP 自产错误过去一律回空 nextActions，调用方拿不到
    // 任何自救动作（对照 MT 的 {tool, arguments}）。现在按错误码给一条可执行动作。
    final actions = envelope['nextActions'] as List<dynamic>;
    expect(actions, isNotEmpty);
    expect(
      (actions.first as Map<String, dynamic>)['tool'],
      'get_solab_tool_map',
    );
  });

  test('advertises the complete 23-tool catalog with valid schemas', () async {
    final response = await _call(port, 'tools/list', const <String, dynamic>{});
    final result = response['result'] as Map<String, dynamic>;
    final tools = result['tools'] as List<dynamic>;
    final names = tools
        .map((tool) => (tool as Map<String, dynamic>)['name'] as String)
        .toSet();

    // exposedToolIds + task_status + tool_batch（系统级，后者仅在 tools/list 手动注册）
    final expectedCount = McpHttpServer.exposedToolIds.length + 2;
    expect(tools, hasLength(expectedCount));
    expect(names, hasLength(expectedCount));
    expect(
      names,
      containsAll(
        McpHttpServer.exposedToolIds.map(
          (name) => name.replaceFirst('analyzer.', 'analyzer_'),
        ),
      ),
    );
    expect(names, contains(McpHttpServer.taskStatusTool));
    final soPatch = tools.cast<Map<String, dynamic>>().singleWhere(
      (tool) => tool['name'] == 'so_patch_into_apk',
    );
    final soPatchProperties =
        (soPatch['inputSchema'] as Map<String, dynamic>)['properties'] as Map;
    expect(
      soPatchProperties.keys,
      containsAll(<String>[
        'apkPath',
        'soPath',
        'entryName',
        'dryRun',
        'applyAfterPreview',
        'confirm',
        'previewToken',
      ]),
    );
    final soAnalyze = tools.cast<Map<String, dynamic>>().singleWhere(
      (tool) => tool['name'] == 'so_analyze',
    );
    final soAnalyzeProperties =
        (soAnalyze['inputSchema'] as Map<String, dynamic>)['properties'] as Map;
    expect(
      soAnalyzeProperties.keys,
      containsAll(<String>[
        'edits',
        'mode',
        'value',
        'returnType',
        'valueEncoding',
        'writeAsm',
      ]),
    );
    for (final raw in tools) {
      final tool = raw as Map<String, dynamic>;
      expect(
        tool['name'],
        matches(RegExp(r'^[a-zA-Z0-9_-]+$')),
        reason: tool['name'] as String,
      );
      final schema = tool['inputSchema'] as Map<String, dynamic>;
      expect(schema['type'], 'object', reason: tool['name'] as String);
      expect(schema['additionalProperties'], isFalse);
      expect(tool['description'], isNotEmpty);
      // 标题覆盖率 100%（§14.11 的验收口径 46/46）：analyzer 四工具的声明是
      // 发布名、而标题表按内部名建，二者不互查就会漏标题——这条断言钉住它。
      expect(
        tool['title'],
        isA<String>().having((t) => t.trim(), 'trimmed', isNotEmpty),
        reason: '工具 ${tool['name']} 缺 title',
      );
    }
    final meta = result['_meta'] as Map<String, dynamic>;
    expect(meta['returnedCount'], expectedCount);
    expect(meta['fullToolCount'], expectedCount);
  });

  test(
    'routes published analyzer aliases to the internal analyzer tools',
    () async {
      final response = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'analyzer_open',
        'arguments': const <String, dynamic>{'apkPath': ''},
      });

      expect(_toolText(response), isNot(contains('TOOL_NOT_FOUND')));
    },
  );

  test(
    'published analyzer aliases validate required parameters before dispatch',
    () async {
      final response = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'analyzer_open',
        'arguments': const <String, dynamic>{},
      });
      final envelope = jsonDecode(_toolText(response)) as Map<String, dynamic>;
      final error = envelope['error'] as Map<String, dynamic>;

      expect(response['result']?['isError'], isTrue);
      expect(error['code'], 'missing_argument');
      expect(error['parameter'], 'apkPath');
    },
  );

  test(
    'MCP system tools validate required parameters before dispatch',
    () async {
      for (final tool in <String>[
        LocalToolNames.toolBatch,
        McpHttpServer.taskStatusTool,
      ]) {
        final response = await _call(port, 'tools/call', <String, dynamic>{
          'name': tool,
          'arguments': const <String, dynamic>{},
        });
        final envelope =
            jsonDecode(_toolText(response)) as Map<String, dynamic>;
        final error = envelope['error'] as Map<String, dynamic>;

        expect(response['result']?['isError'], isTrue, reason: tool);
        expect(error['code'], 'missing_argument', reason: tool);
      }
    },
  );

  test('tool map accepts and returns published analyzer aliases', () async {
    final response = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'get_solab_tool_map',
      'arguments': const <String, dynamic>{'tool': 'analyzer_open'},
    });
    final envelope = jsonDecode(_toolText(response)) as Map<String, dynamic>;
    final data = envelope['data'] as Map<String, dynamic>;
    final tools = data['tools'] as List<dynamic>;

    expect((tools.single as Map<String, dynamic>)['name'], 'analyzer_open');
    expect(data['callableToolNames'], <String>['analyzer_open']);
  });

  test(
    'preserves so_patch_into_apk arguments at the confirmation gate',
    () async {
      final response = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'so_patch_into_apk',
        'arguments': jsonEncode(<String, Object?>{
          'apkPath': '/storage/emulated/0/Ai/source.apk',
          'soPath': '/storage/emulated/0/Ai/libapp-patched.so',
          'entryName': 'lib/arm64-v8a/libapp.so',
          'dryRun': false,
          'sign': true,
        }),
      });

      final envelope = jsonDecode(_toolText(response)) as Map<String, dynamic>;
      final data = envelope['data'] as Map<String, dynamic>;

      expect(envelope['ok'], isFalse);
      expect(envelope['error']?['code'], 'confirmation_required');
      expect(data['receivedArgumentCount'], 5);
      expect(
        data['receivedArguments'],
        containsPair('entryName', 'lib/arm64-v8a/libapp.so'),
      );
      expect(data['receivedArguments'], containsPair('dryRun', false));
      expect(data['receivedArguments'], containsPair('sign', true));
    },
  );

  // D8：handler 自产错误过去 nextActions 恒为空，调用方只能自己猜。
  // 出口按错误码补一条可照抄的恢复动作。
  test('handler 自产错误的空 nextActions 在出口被补成可执行动作', () async {
    // 参数与上一个用例刻意不同（指纹不同），避免吃到环路闸门的硬拦截——
    // 这一例要验的是"错误出口补动作"，不是闸门。
    final response = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'so_patch_into_apk',
      'arguments': jsonEncode(<String, Object?>{
        'apkPath': '/storage/emulated/0/Ai/source-d8.apk',
        'soPath': '/storage/emulated/0/Ai/libapp-patched.so',
        'entryName': 'lib/arm64-v8a/libapp.so',
        'dryRun': false,
        'sign': true,
      }),
    });
    final envelope = jsonDecode(_toolText(response)) as Map<String, dynamic>;
    expect(envelope['error']?['code'], 'confirmation_required');
    expect(envelope['error']?['retrySameArguments'], isFalse);
    final actions = envelope['nextActions'] as List<dynamic>;
    expect(actions, isNotEmpty);
    final action = actions.first as Map<String, dynamic>;
    expect(action['action'], 'preview_then_apply');
    expect(action['tool'], 'so_patch_into_apk');
  });

  // 只读工具代表新的观测；同参复核必须实际执行，不能用旧缓存冒充最新结果。
  test('A-B-C-A 循环里的只读重复调用：实际执行且不被拦截', () async {
    await _call(port, 'initialize', <String, dynamic>{
      'protocolVersion': '2025-06-18',
    });

    for (final tool in <String>['route_task', 'file', 'so_analyze']) {
      final response = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'get_solab_tool_map',
        'arguments': <String, dynamic>{'tool': tool},
      });
      expect(response['result']?['isError'], isNot(true));
    }

    final repeated = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'get_solab_tool_map',
      'arguments': const <String, dynamic>{'tool': 'route_task'},
    });
    final envelope = jsonDecode(_toolText(repeated)) as Map<String, dynamic>;

    expect(repeated['result']?['isError'], isNot(true));
    expect(envelope['replayedFromCache'], isNot(true));
    expect(envelope['error'], isNull);
  });

  // 时间等观测结果会变化，重复调用必须返回新观测，不能被写操作循环保护误伤。
  test('会变化的只读调用可用同参复核', () async {
    await _call(port, 'initialize', <String, dynamic>{
      'protocolVersion': '2025-06-18',
    });
    const args = <String, dynamic>{'timezone': 'Asia/Shanghai'};
    final first = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'get_time_info',
      'arguments': args,
    });
    expect(first['result']?['isError'], isNot(true));

    final second = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'get_time_info',
      'arguments': args,
    });
    final envelope = jsonDecode(_toolText(second)) as Map<String, dynamic>;
    expect(second['result']?['isError'], isNot(true));
    expect(envelope['error'], isNull);
  });

  // 只读调用本身不写入循环窗口；新客户端初始化也不应影响另一客户端的正常复核。
  test('新客户端 initialize 不影响其他客户端的只读复核', () async {
    const a = 'session-A';
    const b = 'session-B';
    await _call(port, 'initialize', <String, dynamic>{
      'protocolVersion': '2025-06-18',
    }, sessionId: a);

    // A 建立自己的重复基线（同一参数调 3 次不同 tool 名，凑满窗口）
    for (final tool in <String>['route_task', 'file', 'so_analyze']) {
      final r = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'get_solab_tool_map',
        'arguments': <String, dynamic>{'tool': tool},
      }, sessionId: a);
      expect(r['result']?['isError'], isNot(true));
    }

    // B 此时连上并 initialize——旧实现会在这里把 A 的窗口清空。
    await _call(port, 'initialize', <String, dynamic>{
      'protocolVersion': '2025-06-18',
    }, sessionId: b);

    // A 重复首次调用的参数：应作为一次新观测正常执行。
    final repeatedA = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'get_solab_tool_map',
      'arguments': const <String, dynamic>{'tool': 'route_task'},
    }, sessionId: a);
    final replayEnvelope =
        jsonDecode(_toolText(repeatedA)) as Map<String, dynamic>;
    expect(repeatedA['result']?['isError'], isNot(true));
    expect(replayEnvelope['replayedFromCache'], isNot(true));
    expect(replayEnvelope['error'], isNull);
  });

  // D17（2026-09-21）：lane 超时隔离过去会连带拦下无关工具——4 个读 gate
  // 轮转下表现为"同一条调用时好时坏"。现在隔离只对重内存工具生效；写 lane
  // 保持一律不放行（那是数据安全，不是堆峰值问题）。
  test('D17：lane 隔离只拦重内存工具，轻量读照常放行', () async {
    server.debugBlockLanes('apk_rebuild');
    try {
      // 轻量读：不受隔离影响
      final light = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'get_solab_tool_map',
        'arguments': const <String, dynamic>{'tool': 'class_outline'},
      });
      final lightEnvelope =
          jsonDecode(_toolText(light)) as Map<String, dynamic>;
      expect(lightEnvelope['error'], isNull);
      expect(light['result']?['isError'], isNot(true));

      // 重内存读：被隔离，且拒绝理由可执行（含等待秒数与波及范围）
      final heavy = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'apk_archive',
        'arguments': const <String, dynamic>{
          'apkPath': '/storage/emulated/0/Ai/d17-lane-probe.apk',
          'action': 'list',
        },
      });
      final heavyEnvelope =
          jsonDecode(_toolText(heavy)) as Map<String, dynamic>;
      expect(heavyEnvelope['error']?['code'], 'tool_lane_blocked');
      expect(heavyEnvelope['error']?['retryAfterSeconds'], isA<int>());
      expect(heavyEnvelope['error']?['blockedTool'], 'apk_rebuild');
      expect(
        heavyEnvelope['error']?['laneBlockedScope'],
        contains('heavy-memory'),
      );
      final actions = heavyEnvelope['nextActions'] as List<dynamic>;
      expect(actions, isNotEmpty);
      expect(
        (actions.first as Map<String, dynamic>)['action'],
        'wait_then_narrow',
      );

      // 写 lane：连轻量写也不放行（隔离期间不动原生工具链）
      final write = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'file',
        'arguments': const <String, dynamic>{
          'action': 'copy',
          'source': '/storage/emulated/0/Ai/d17-a.apk',
          'target': '/storage/emulated/0/Ai/d17-b.apk',
        },
      });
      final writeEnvelope =
          jsonDecode(_toolText(write)) as Map<String, dynamic>;
      expect(writeEnvelope['error']?['code'], 'tool_lane_blocked');
      expect(writeEnvelope['error']?['lane'], 'write');
    } finally {
      server.debugClearLanes();
    }
  });

  test('不同会话的相同调用互不污染，各自独立放行', () async {
    const x = 'session-X';
    const y = 'session-Y';
    for (final sid in <String>[x, y]) {
      await _call(port, 'initialize', <String, dynamic>{
        'protocolVersion': '2025-06-18',
      }, sessionId: sid);
    }
    // 两个会话各自第一次调用同一参数：都应放行（旧共享实现下第二个会被
    // 误判为重复）。
    for (final sid in <String>[x, y]) {
      final r = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'get_solab_tool_map',
        'arguments': const <String, dynamic>{'tool': 'dex_search'},
      }, sessionId: sid);
      expect(r['result']?['isError'], isNot(true), reason: '$sid 的首次调用不应被判为循环');
    }
  });
  test('A2 写 DEX 的字符串补丁带 destructiveHint', () async {
    final response = await _call(port, 'tools/list', const <String, dynamic>{});
    final tools =
        (response['result'] as Map<String, dynamic>)['tools'] as List<dynamic>;
    Map<String, dynamic>? find(String name) {
      for (final tool in tools) {
        final map = (tool as Map).cast<String, dynamic>();
        if (map['name'] == name) return map;
      }
      return null;
    }

    expect(
      find('patch_apk_dex_strings')?['annotations']?['destructiveHint'],
      isTrue,
      reason: '写 DEX 的字符串补丁必须标破坏性，否则客户端不给确认提示',
    );
    expect(
      find('patch_apk_dex_methods')?['annotations']?['destructiveHint'],
      isTrue,
    );
    // 只读工具不应被误标
    expect(find('dex_search')?['annotations']?['readOnlyHint'], isTrue);
    expect(find('dex_search')?['annotations']?['destructiveHint'], isNull);
  });

  test('第 54 项 按参数/委派才变更的工具不再被 MCP 注解成只读', () async {
    final response = await _call(port, 'tools/list', const <String, dynamic>{});
    final tools =
        (response['result'] as Map<String, dynamic>)['tools'] as List<dynamic>;
    Map<String, dynamic>? find(String name) {
      for (final tool in tools) {
        final map = (tool as Map).cast<String, dynamic>();
        if (map['name'] == name) return map;
      }
      return null;
    }

    // 这三个工具都能真的改环境：run_task_command(install=true) 装包、
    // subagent(带 write/shell 类别) 委派写类工具、frida(action=inject) 往
    // 目标 APK 里写 gadget。注册表的 readOnly 首先是**车道**语义，不能当
    // 给客户端的安全承诺——否则客户端会跳过确认提示。
    for (final name in <String>['run_task_command', 'subagent', 'frida']) {
      final annotations = find(name)?['annotations'] as Map?;
      expect(
        annotations?['readOnlyHint'],
        isFalse,
        reason: '$name 能变更环境，readOnlyHint 必须是 false',
      );
      expect(
        annotations?['destructiveHint'],
        isTrue,
        reason: '$name 必须带 destructiveHint，否则客户端不给确认提示',
      );
    }

    // install=true 是 run_task_command 的唯一安装闸门，声明本身也得在。
    final runProps =
        ((find('run_task_command')?['inputSchema'] as Map?)?['properties']
                as Map?)
            ?.cast<String, dynamic>();
    expect(runProps?.containsKey('install'), isTrue);

    // 真正只读的工具不被连坐。
    for (final name in <String>['dex_search', 'todo_read', 'smali_read']) {
      expect(find(name)?['annotations']?['readOnlyHint'], isTrue, reason: name);
      expect(
        find(name)?['annotations']?['destructiveHint'],
        isNull,
        reason: name,
      );
    }
  });

  test('A3 批内只读复核全部执行，连续两批同参不互拦', () async {
    Future<Map<String, dynamic>> batch() async {
      final response = await _call(port, 'tools/call', <String, dynamic>{
        'name': 'tool_batch',
        'arguments': <String, dynamic>{
          'calls': <dynamic>[
            <String, dynamic>{
              'tool': 'get_time_info',
              'args': <String, dynamic>{},
            },
            <String, dynamic>{
              'tool': 'get_time_info',
              'args': <String, dynamic>{},
            },
            <String, dynamic>{
              'tool': 'get_time_info',
              'args': <String, dynamic>{},
            },
          ],
        },
      });
      return jsonDecode(_toolText(response)) as Map<String, dynamic>;
    }

    final first = await batch();
    expect(first['succeeded'], greaterThanOrEqualTo(1), reason: '批内首条同参应放行');
    expect(first['succeeded'], 3, reason: '批内只读复核必须全部执行');
    expect(first['blockedByLoopGuard'], 0, reason: '只读复核不应被当成写操作循环');

    // 第二批同参：桶带批次序号，不应被上一批的指纹拦住
    final second = await batch();
    expect(second['succeeded'], 3, reason: '跨批同参必须互不干扰（旧实现桶常驻，第二批会被误拦）');
  });

  test('非 UTF-8 请求体回可诊断的 400 而不是 500 internal_error', () async {
    // 2026-10-05 真机实测：Windows 客户端按本地代码页（GBK）发送含中文参数的
    // JSON 时，服务端 utf8.decode 抛 FormatException 冒到顶层 → 500
    // internal_error，调用方只看到"服务器内部错误"而不知道是编码问题。
    final socket = await Socket.connect('127.0.0.1', port);
    try {
      // {"a":"<GBK 的「你」>"} —— 0xC4 0xE3 不是合法 UTF-8 序列。
      final bodyBytes = <int>[
        ...utf8.encode('{"a":"'),
        0xc4,
        0xe3,
        ...utf8.encode('"}'),
      ];
      socket.add(<int>[
        ...utf8.encode(
          'POST /mcp HTTP/1.0\r\n'
          'Host: 127.0.0.1:$port\r\n'
          'Content-Type: application/json\r\n'
          'Content-Length: ${bodyBytes.length}\r\n'
          '\r\n',
        ),
        ...bodyBytes,
      ]);
      final raw = await utf8.decoder.bind(socket).join();
      expect(raw, contains('400'), reason: '编码错误必须是客户端错误（4xx）');
      expect(raw, contains('INVALID_ENCODING'));
      expect(raw, isNot(contains('internal_error')));
    } finally {
      socket.destroy();
    }
  });

  // 用户 2026-10-06：与端内逆向助手同一份「作业约定」，MCP 面也给一个开关。
  test('MCP 作业约定开关：打开后 initialize 的 instructions 追加工作台约定', () async {
    final saved = McpHttpServer.operatorConventionsResolver;
    addTearDown(() => McpHttpServer.operatorConventionsResolver = saved);

    McpHttpServer.operatorConventionsResolver = () => false;
    final off = await _call(port, 'initialize', <String, dynamic>{
      'protocolVersion': '2025-06-18',
    });
    final offText =
        (off['result'] as Map<String, dynamic>)['instructions'] as String;
    expect(offText, isNot(contains('Operator conventions')));

    McpHttpServer.operatorConventionsResolver = () => true;
    final on = await _call(port, 'initialize', <String, dynamic>{
      'protocolVersion': '2025-06-18',
    });
    final onText =
        (on['result'] as Map<String, dynamic>)['instructions'] as String;
    expect(onText, contains('Operator conventions'));
    expect(
      onText,
      contains('the boundary wins'),
      reason: '边界句必须在——端内助手与 MCP 面共用同一份文本',
    );
  });

  // 用户 2026-10-06：MCP 可能是别的工具在调，而子代理花的是本机模型的额度
  // （App 里的 token）——默认不允许，开关打开后才放行。
  test('MCP 额度闸门：子代理默认拒绝，打开后放行', () async {
    final saved = McpHttpServer.quotaToolsAllowedResolver;
    addTearDown(() => McpHttpServer.quotaToolsAllowedResolver = saved);

    String codeOf(String text) {
      final body = jsonDecode(text) as Map<String, dynamic>;
      final raw = body['code'] ?? (body['error'] as Map?)?['code'];
      return raw?.toString() ?? '';
    }

    McpHttpServer.quotaToolsAllowedResolver = () => false;
    final denied = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'subagent',
      'arguments': <String, dynamic>{'task': 'gate probe'},
    });
    expect(denied['result']?['isError'], isTrue, reason: '关着时必须报错，不能静默执行');
    expect(codeOf(_toolText(denied)), 'mcp_quota_tools_disabled');

    McpHttpServer.quotaToolsAllowedResolver = () => true;
    final allowed = await _call(port, 'tools/call', <String, dynamic>{
      'name': 'subagent',
      'arguments': <String, dynamic>{'task': 'gate probe'},
    });
    expect(
      codeOf(_toolText(allowed)),
      isNot('mcp_quota_tools_disabled'),
      reason: '开关打开后不应再被额度闸门拦下（后续失败不算闸门问题）',
    );
  });
}

Future<Map<String, dynamic>> _call(
  int port,
  String method,
  Map<String, dynamic> params, {
  String? sessionId,
  String? query,
  Map<String, String> headers = const <String, String>{},
}) async {
  final body = jsonEncode(<String, dynamic>{
    'jsonrpc': '2.0',
    'id': 1,
    'method': method,
    'params': params,
  });
  final socket = await Socket.connect('127.0.0.1', port);
  try {
    final extraHeaders = <String>[
      if (sessionId != null) 'Mcp-Session-Id: $sessionId',
      for (final e in headers.entries) '${e.key}: ${e.value}',
    ];
    socket.write(
      'POST /mcp${query == null ? '' : '?$query'} HTTP/1.0\r\n'
      'Host: 127.0.0.1:$port\r\n'
      'Content-Type: application/json\r\n'
      'Content-Length: ${utf8.encode(body).length}\r\n'
      '${extraHeaders.map((h) => '$h\r\n').join()}'
      '\r\n'
      '$body',
    );
    final raw = await utf8.decoder.bind(socket).join();
    final separator = raw.indexOf('\r\n\r\n');
    final payload = raw.substring(separator + 4);
    // 鉴权失败走 HTTP 状态码 + JSON-RPC error，体仍是可解析 JSON。
    if (payload.trim().isEmpty) return <String, dynamic>{};
    return jsonDecode(payload) as Map<String, dynamic>;
  } finally {
    socket.destroy();
  }
}

String _toolText(Map<String, dynamic> response) {
  final result = response['result'] as Map<String, dynamic>;
  final content = result['content'] as List<dynamic>;
  return (content.single as Map<String, dynamic>)['text'] as String;
}
