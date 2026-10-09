part of 'local_tools_service.dart';

const kSoAnalyzeActionCatalog = <String>[
  'open',
  // D18 第二步（2026-09-21）：以下动作已**从目录摘除**——它们整族 0 命中
  // （capabilities 8/8、open_url 6/6、emulate 7/7、lief_* 4/4 全失败），留在目录里
  // 只会被反复踩。摘除后仍会被 kSoAnalyzeRetiredActions 在执行前拦下并给替代路径，
  // 所以老调用方拿到的是"已知不可用 + 怎么改"，而不是"未知 action"。
  // 'open_url', 'capabilities', 'emulate', 'emulate_dump', 'emulation_status',
  // 'lief_dispatch', 'lief_patch_address', 'lief_add_export', 'lief_remove_symbol',
  'workspaces',
  // D20：句柄映射——一次调用给出 workspaceId ↔ Blutter jobId 的对应关系
  // （按输入路径对齐），替代"人工比对 VA/fileOffset"。
  'handles',
  'close',
  'list_sources',
  'analyze_apk',
  'read_elf',
  'crypto_scan',
  'jni_bridge',
  'read_stats',
  'disasm',
  // 阶段 0（C1/C16）接入的三个读取动作：引擎路由已补（SolabChannel 的
  // soEngineDispatch 分支 "outline"/"xref_symbol"/"xref_string"），真机验证见
  // docs/benchmark/runs.md（outline 出 rizin 真 CFG 66 块/98 边、xref_string 标
  // arm64 unsupported）。此前 Dart 目录漏登记：模型在 action 目录里看不到它们，
  // 而 outline 还被 kSoAnalyzeActionRenames 的旧条目在执行前改道去
  // list(view=sections)——那是"列节区"，不是函数级 outline
  // （basicBlocks/cfgEdges/callers），等于把手能用的能力挡掉。
  'outline',
  'xref_symbol',
  'xref_string',
  'hexdump',
  'strings',
  'search',
  'list',
  'overview',
  'analysis_report',
  'edit_open',
  'edit_snapshot',
  'edit_rollback',
  'edit_undo',
  'edit_redo',
  'edit_reset',
  'edit_hex',
  'edit_asm',
  'edit_symbol',
  'edit_check',
  'fix_sections',
  'xanso_build_sections',
  'build',
  'build_many',
  'list_builds',
  'diff',
  'rz_diff',
  'audit',
  'audit_persist',
  'audit_load',
  'list_audits',
  'rz_analyze',
  'rz_functions',
  'rz_xrefs',
  'rz_decompile',
  'rz_crypto',
  'rz_cfg',
  'rz_esil',
  'rz_search_bytes',
  'rz_command',
  'rz_asm',
  // 'lief_dispatch',  ← D18 摘除
  // 'lief_patch_address',  ← D18 摘除
  // 'lief_add_export',  ← D18 摘除
  // 'lief_remove_symbol',  ← D18 摘除
  'xanso_dispatch',
  // 'emulate',  ← D18 摘除
  // 'emulate_dump',  ← D18 摘除
  // 'emulation_status',  ← D18 摘除
  'unidbg_dispatch',
  'unidbg_batch',
  'blutter',
  'suggest',
  // 'capabilities',  ← D18 摘除（8/8 失败；能力清单改由 get_solab_tool_map 与
  //                     blutterAction=packages 提供，拦截文案见 kSoAnalyzeRetiredActions）
  'asset_status',
  'asset_download',
];

/// 已退役的 so_analyze 动作（2026-09-21 全工具自检：整族 0 命中）。
///
/// 标记而不是立刻删除（自检方案 D18 的两步走）：调用方在**执行前**就拿到
/// "已知不可用 + 替代路径"，不必等它失败再猜。确认长期不需要后再从
/// [kSoAnalyzeActionCatalog] 正式摘除。
///
/// value.reason 保留自检实测结论，不修饰；value.instead 必须是真能走通的动作。
const kSoAnalyzeRetiredActions = <String, Map<String, String>>{
  'capabilities': {
    'reason': '自检 8/8 失败：本动作未接通（能力清单改由工具地图发布）。',
    'instead':
        'get_solab_tool_map(tool: "so_analyze") 读完整动作目录；Blutter runner 矩阵用 '
        'so_analyze(action: "blutter", blutterAction: "packages")。',
  },
  'open_url': {
    'reason': '自检 6/6 失败（另有 SSRF 守卫：仅公网 http(s)，内网/回环/明文跳转一律拒绝）。',
    'instead':
        '先把 .so/ELF 落到工作目录（file(action:"write") 或 out-of-band 下载），再 '
        'so_analyze(action: "open", path: "<工作目录内的文件>")。',
  },
  'emulate': {
    'reason': '自检 7/7 失败：JNI_OnLoad 未导出，进程内仿真入口不成立。',
    'instead':
        'so_analyze(action: "unidbg_dispatch" / "unidbg_batch") 走 Unidbg 全仿真；'
        '只要读导出函数用 action:"jni_bridge" + call_export。',
  },
  'lief_dispatch': {
    'reason': '自检 4/4 失败：LIEF 增删改入口未接通。',
    'instead':
        'so_analyze(action: "edit_hex") 或 action:"edit_asm"（内置原生编辑通道，支持等长与变长写）。',
  },
  'lief_patch_address': {
    'reason': '自检 4/4 失败：LIEF 增删改入口未接通。',
    'instead':
        'so_analyze(action: "edit_hex", va: ..., patchHex: ...) → action:"edit_check" 复核。',
  },
  'lief_add_export': {
    'reason': '自检 4/4 失败：LIEF 增删改入口未接通。',
    'instead':
        'so_analyze(action: "edit_symbol") 新增/改导出表，再 action:"build" 落产物。',
  },
  'lief_remove_symbol': {
    'reason': '自检 4/4 失败：LIEF 增删改入口未接通。',
    'instead': 'so_analyze(action: "edit_symbol") 改符号表，再 action:"build" 落产物。',
  },
};

/// "域"标识符：它们是一组子动作的命名空间，不是可直接调用的动作。
/// 调用方拿到的是"这是域 + 可用子动作"，而不是笼统的 Unknown action（自检 D19）。
const kSoAnalyzeDomains = <String, Map<String, dynamic>>{
  'read': {
    'domain': true,
    'subActions': [
      'read_elf',
      'read_stats',
      'outline',
      'xref_symbol',
      'xref_string',
      'hexdump',
      'strings',
      'search',
      'list',
      'overview',
    ],
  },
  'edit': {
    'domain': true,
    'subActions': [
      'edit_open',
      'edit_snapshot',
      'edit_rollback',
      'edit_undo',
      'edit_redo',
      'edit_reset',
      'edit_hex',
      'edit_asm',
      'edit_symbol',
      'edit_check',
    ],
  },
  // 注意：不要往这里加 blutter。它是**合法动作**（action:"blutter" +
  // blutterAction=...），不是纯命名空间——把它归为域会在执行前直接拒绝
  // 掉整条 Blutter 链路（2026-09-21 自检批次实测踩到，回归锁：
  // local_tools_service_test "Blutter analyze returns its background job immediately"）。
};

/// 历史别名 → 当前动作名。调用方写错名字时应当被告知正确写法（自检 D18）。
const kSoAnalyzeActionRenames = <String, String>{
  'xref': 'rz_xrefs',
  'packages': 'packages(action:"blutter" + blutterAction:"packages")',
  'workspace': 'workspaces',
  'write_entry': 'edit_hex / edit_asm',
  'xrefs': 'rz_xrefs',
  'functions': 'rz_functions',
  'decompile': 'rz_decompile',
};

/// 已在 [buildLocalToolSchemas] 内联装配的设备工具（自带平台门控与自定义描述）。
///
/// 其余设备工具（定位/天气/健康/提醒）的定义来自 [DeviceLocalToolSchemas]，
/// 但它们不登记在 `LocalToolRegistry.specs`（按运行时能力装配），因此构建
/// 工具清单时要单独补装，出口过滤也要对它们放行。
const Set<String> _inlineGatedDeviceTools = <String>{
  LocalToolNames.phoneControl,
  LocalToolNames.screenTime,
  LocalToolNames.calendarQuery,
  LocalToolNames.calendarCreate,
};

List<Map<String, dynamic>> buildLocalToolSchemas({
  required Assistant? assistant,
  required bool supportsTools,
  required Map<String, Object> apkPathParameter,
  required Map<String, Object> allowOversizeParameter,
  required String Function() deviceTimezoneHint,
}) {
  if (!supportsTools || assistant == null) {
    return const <Map<String, dynamic>>[];
  }

  final registeredToolIds = LocalToolRegistry.specs
      .map((spec) => spec.name)
      .toSet();
  final tools = <Map<String, dynamic>>[];
  if (assistant.localToolIds.contains(LocalToolNames.agentRuntimeGuide)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.agentRuntimeGuide,
        'description':
            'Read the current APK Agent capability guide only when the active instructions, memory, World Books, Skills, or available tools could change the next action. Do not treat names alone as task evidence.',
        'parameters': {
          'type': 'object',
          'properties': {
            'tool': {
              'type': 'string',
              'description':
                  'Optional tool name. Pass so_analyze to get its complete action catalog and parameters.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.timeInfo)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.timeInfo,
        'description':
            'Get the current local date and time info from the device. Returns year, month, day, weekday, ISO date and time strings, timezone, UTC offset, and timestamp.',
        'parameters': {'type': 'object', 'properties': <String, dynamic>{}},
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.clipboard)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.clipboard,
        'description':
            'Read or write plain text from the device clipboard. Use action: read or write. For write, provide text. Do NOT write to the clipboard unless the user has explicitly requested it.',
        'parameters': {
          'type': 'object',
          'properties': {
            'action': {
              'type': 'string',
              'enum': ['read', 'write'],
              'description': 'Operation to perform: read or write',
            },
            'text': {
              'type': 'string',
              'description':
                  'Text to write to the clipboard. Required for write.',
            },
          },
          'required': ['action'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.textToSpeech)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.textToSpeech,
        'description':
            'Speak text aloud to the user using the configured text-to-speech playback. Use this when the user asks you to read something aloud, or when audio output is appropriate. The tool returns after playback has been requested; audio may continue in the background. Provide natural, readable text without markdown formatting.',
        'parameters': {
          'type': 'object',
          'properties': {
            'text': {
              'type': 'string',
              'description': 'The text to speak aloud.',
            },
          },
          'required': ['text'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.askUser)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.askUser,
        'description':
            'Ask the user one or more short choice questions when you need clarification, additional information, or a decision before continuing. Supports single-choice and multi-choice questions. The UI will provide Other and Skip options automatically, so do not include those options yourself.',
        'parameters': {
          'type': 'object',
          'properties': {
            'questions': {
              'type': 'array',
              'description': 'One to four questions to ask the user.',
              'items': {
                'type': 'object',
                'properties': {
                  'id': {
                    'type': 'string',
                    'description':
                        'Unique stable identifier for this question.',
                  },
                  'question': {
                    'type': 'string',
                    'description': 'The full question text shown to the user.',
                  },
                  'type': {
                    'type': 'string',
                    'enum': ['single', 'multi'],
                    'description':
                        'Answer type: single choice or multi choice.',
                  },
                  'options': {
                    'type': 'array',
                    'description':
                        'Suggested options for the user to choose from.',
                    'items': {'type': 'string'},
                  },
                },
                'required': ['id', 'question'],
              },
            },
          },
          'required': ['questions'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.calculate)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.calculate,
        'description':
            'Evaluate a mathematical expression. Supports: + - * / ^ % !, sin() cos() tan() sqrt() ln() abs() floor() ceil() sgn(), log(base, value), constants pi e. Example: "5!", "sin(pi/4)", "log(2, 8)", "floor(3.7)"',
        'parameters': {
          'type': 'object',
          'properties': {
            'expression': {
              'type': 'string',
              'description':
                  'A mathematical expression in standard notation, e.g. "(15 + 3) * 2", "2^10", "sqrt(144)"',
            },
          },
          'required': ['expression'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.valueCalc)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.valueCalc,
        'description':
            'Low-level value/byte calculator - never do this arithmetic by hand. '
            'action=convert: radix & bit-width conversion (hex/dec/bin/oct, 8/16/32/64-bit signed & unsigned, little-endian hex, ASCII) for one value or a values batch. '
            'action=bitwise: and/or/xor/not/shl/shr/sar/rol/ror with bitWidth 8/16/32/64. '
            'action=endian: big<->little byte order for a number or a hex byte stream. '
            'action=float: IEEE754 float32/float64 layout <-> number (smali const/high16, const-wide). '
            'action=codec: base64/hex/url encode & decode. action=hash: md5/sha1/sha256. '
            'action=crc: crc32/crc16. action=mod: mod_pow/mod_inverse/gcd. '
            r'steps[] chains several steps in ONE call and references an earlier result with {"$step": 0, "field": "bitWidths.bit32.littleEndianHex"}.',
        'parameters': {
          'type': 'object',
          'properties': {
            'action': {
              'type': 'string',
              'enum': [
                'convert',
                'bitwise',
                'endian',
                'float',
                'codec',
                'hash',
                'crc',
                'mod',
              ],
              'description': 'Which calculation to run.',
            },
            'value': {
              'type': 'string',
              'description':
                  'Primary input: integer (0x401000 / 4198400 / -42), float (3.14159 or machine code 0x3f800000), hex byte stream (0102030405), or the text/hex data for codec/hash/crc.',
            },
            'values': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'convert batch: up to 8 integers converted in ONE call.',
            },
            'from': {
              'type': 'string',
              'enum': ['auto', 'hex', 'dec', 'bin', 'oct'],
              'description':
                  'Radix for a bare value with no 0x/0b/0o prefix (default auto: prefixes win, bare digits are decimal).',
            },
            'op': {
              'type': 'string',
              'description':
                  'Sub-operation: bitwise=and/or/xor/not/shl/shr/sar/rol/ror, codec=to_base64/from_base64/to_hex/from_hex/url_encode/url_decode, mod=mod_pow/mod_inverse/gcd.',
            },
            'a': {
              'type': 'string',
              'description': 'First operand for bitwise / mod.',
            },
            'b': {
              'type': 'string',
              'description':
                  'Second operand or shift count for bitwise; exponent for mod_pow.',
            },
            'modulus': {
              'type': 'string',
              'description': 'Modulus for mod_pow/mod_inverse.',
            },
            'bitWidth': {
              'type': 'integer',
              'enum': [8, 16, 32, 64],
              'description': 'Bit width for bitwise (default 32).',
            },
            'widthBytes': {
              'type': 'integer',
              'description':
                  'Byte length for endian (2/4/8); inferred from the value when omitted.',
            },
            'precision': {
              'type': 'string',
              'enum': ['auto', 'float32', 'float64'],
              'description': 'float: which layout to return (default auto).',
            },
            'format': {
              'type': 'string',
              'enum': ['text', 'hex'],
              'description':
                  'codec: input format for to_base64, output format for from_base64. hash/crc: whether value is text or hex bytes.',
            },
            'urlSafe': {
              'type': 'boolean',
              'description':
                  'codec to_base64: URL-safe alphabet, padding stripped.',
            },
            'algorithm': {
              'type': 'string',
              'enum': ['md5', 'sha1', 'sha256'],
              'description': 'hash: algorithm (default sha256).',
            },
            'variant': {
              'type': 'string',
              'enum': ['crc32', 'crc16-ccitt', 'crc16-xmodem', 'crc16-modbus'],
              'description':
                  'crc: variant (default crc32); the result echoes poly/init.',
            },
            'steps': {
              'type': 'array',
              'items': {'type': 'object'},
              'description':
                  r'Chain of up to 8 steps run in one call. Each step is {action, ...}; any value may be {"$step": <earlier index>, "field": "<dotted path of that result>"}.',
            },
          },
        },
      },
    });
  }
  if (DeviceLocalTools.phoneControlSupported &&
      assistant.localToolIds.contains(LocalToolNames.phoneControl)) {
    // 定义原文取自上游 1.3.0（无障碍手机控制），与 Kotlin 侧动作一一对应；
    // 数据格式必须逐字一致，改动请同步 device_local_tool_schemas.dart。
    tools.add(DeviceLocalToolSchemas.phoneControlDefinition);
  }
  if (DeviceLocalTools.screenTimeSupported &&
      assistant.localToolIds.contains(LocalToolNames.screenTime)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.screenTime,
        'description':
            "Get the user's app screen usage (screen time) over a time range. "
            "Specify a custom interval with 'begin'/'end', or use the 'range' preset (today/week). "
            'Returns the total foreground time and a per-app breakdown sorted by usage time (descending). '
            '${deviceTimezoneHint()} '
            "Requires the 'Usage access' special permission; if it is not granted, the device's usage "
            'access settings page is opened automatically and an error is returned.',
        'parameters': {
          'type': 'object',
          'properties': {
            'begin': {
              'type': 'string',
              'description':
                  "Start time (inclusive). Accepts an ISO-8601 date 'yyyy-MM-dd', a local "
                  "date-time 'yyyy-MM-ddTHH:mm:ss', an offset date-time, or epoch milliseconds. "
                  "When provided, 'range' is ignored.",
            },
            'end': {
              'type': 'string',
              'description':
                  "End time (exclusive), same formats as 'begin'. Defaults to now.",
            },
            'range': {
              'type': 'string',
              'enum': ['today', 'week'],
              'description':
                  "Convenience preset, used only when 'begin' is omitted: today or week. Default today.",
            },
            'top': {
              'type': 'integer',
              'description':
                  'Maximum number of top apps to return, sorted by usage time. Default 10.',
            },
          },
        },
      },
    });
  }
  if (DeviceLocalTools.calendarSupported &&
      assistant.localToolIds.contains(LocalToolNames.calendarQuery)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.calendarQuery,
        'description':
            "Query calendar events on the user's device within a time range. "
            "Specify a custom interval with 'begin'/'end', or use the 'range' preset (today/week/month). "
            'Returns a list of events with title, description, location, start/end times, and calendar info. '
            '${deviceTimezoneHint()} '
            "Requires the 'Calendar' permission; if it is not granted, an error is returned.",
        'parameters': {
          'type': 'object',
          'properties': {
            'begin': {
              'type': 'string',
              'description':
                  "Start time (inclusive). Accepts an ISO-8601 date 'yyyy-MM-dd', a local "
                  "date-time 'yyyy-MM-ddTHH:mm:ss', an offset date-time, or epoch milliseconds. "
                  "When provided, 'range' is ignored.",
            },
            'end': {
              'type': 'string',
              'description': "End time (exclusive), same formats as 'begin'.",
            },
            'range': {
              'type': 'string',
              'enum': ['today', 'week', 'month'],
              'description':
                  "Convenience preset, used only when 'begin' is omitted: today, week, or month. Default today.",
            },
            'query': {
              'type': 'string',
              'description':
                  'Optional keyword to filter events by title (case-insensitive substring match).',
            },
            'limit': {
              'type': 'integer',
              'description': 'Maximum number of events to return. Default 20.',
            },
          },
        },
      },
    });
  }
  if (DeviceLocalTools.calendarSupported &&
      assistant.localToolIds.contains(LocalToolNames.calendarCreate)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.calendarCreate,
        'description':
            "Create a new calendar event on the user's device. "
            'Requires title and start time at minimum. End time defaults to 1 hour after start. '
            'The user will be asked to confirm before the event is created. '
            '${deviceTimezoneHint()} '
            "Requires the 'Calendar' permission; if it is not granted, an error is returned.",
        'parameters': {
          'type': 'object',
          'properties': {
            'title': {'type': 'string', 'description': 'Event title.'},
            'description': {
              'type': 'string',
              'description': 'Event description or notes.',
            },
            'location': {'type': 'string', 'description': 'Event location.'},
            'start': {
              'type': 'string',
              'description':
                  "Start time. Accepts an ISO-8601 date 'yyyy-MM-dd', a local "
                  "date-time 'yyyy-MM-ddTHH:mm:ss', an offset date-time, or epoch milliseconds.",
            },
            'end': {
              'type': 'string',
              'description':
                  "End time, same formats as 'start'. Defaults to 1 hour after start.",
            },
            'all_day': {
              'type': 'boolean',
              'description': 'Whether this is an all-day event. Default false.',
            },
          },
          'required': ['title', 'start'],
        },
      },
    });
  }
  // 定位/天气/健康/提醒（上游 1.2.7 原文定义）：平台可用性走 UI 同一个判定口，
  // 顺序跟随 assistant.localToolIds，保证「助手勾选顺序 = 模型侧工具顺序」。
  for (final deviceTool in assistant.localToolIds) {
    if (_inlineGatedDeviceTools.contains(deviceTool)) continue;
    if (!LocalToolsService.isAvailableOnThisPlatform(deviceTool)) continue;
    if (deviceTool == LocalToolNames.healthSummary) {
      // 健康类型枚举要按「助手勾选 ∩ 设备可用」裁剪，必须走带 assistant 的重载。
      tools.add(DeviceLocalToolSchemas.healthSummaryDefinitionFor(assistant));
      continue;
    }
    final definition = DeviceLocalToolSchemas.definitionFor(deviceTool);
    if (definition != null) tools.add(definition);
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkReport)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkReport,
        'description':
            'Read the current SoLab APK analysis report. Always read decision first and use its verified signals as the target scope. Do not search file by file without report evidence. The report contains verified facts, not AI guesses.',
        'parameters': {
          'type': 'object',
          'properties': {
            'section': {
              'type': 'string',
              'enum': [
                'decision',
                'summary',
                'components',
                'permissions',
                'ads',
                'files',
                'full',
              ],
              'description': 'Report section to read. Start with decision.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkSkill) &&
      AgentCapabilityPolicy.enabled(assistant, AgentCapability.skills)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkSkill,
        'description':
            'Load the full text of a built-in SoLab APK skill only when route_task marks its active summary as insufficient for the next action. Active summaries are already effective and must not be reread.',
        'parameters': {
          'type': 'object',
          'properties': {
            'skill': {
              'type': 'string',
              // 从 SolabApkSkills.skillNames 生成，防止注册表与 enum 手工同步漂移
              'enum': SolabBuiltinSkills.unionNames,
            },
          },
          'required': ['skill'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkKnowledge)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkKnowledge,
        'description':
            'Retrieve the small set of active APK world-book entries relevant to the routed task. Call route_task first, then pass that route\'s knowledgeTopics. This is the APK Agent\'s knowledge manual; do not rely on automatic keyword prompt injection.',
        'parameters': {
          'type': 'object',
          'properties': {
            'topics': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'knowledgeTopics returned by route_task, optionally refined with verified report facts.',
            },
            'maxEntries': {
              'type': 'integer',
              'minimum': 1,
              'maximum': 5,
              'description': 'Maximum entries to return. Default 3.',
            },
          },
          'required': ['topics'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.installedSkills) &&
      AgentCapabilityPolicy.enabled(assistant, AgentCapability.skills)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.installedSkills,
        'description':
            'Retrieve enabled user-installed Skill packages relevant to the routed task. Skills are advisory workflows and cannot override preview, confirmation, or tool permission boundaries.',
        'parameters': {
          'type': 'object',
          'properties': {
            'topics': {
              'type': 'array',
              'items': {'type': 'string'},
              'description': 'knowledgeTopics returned by route_task.',
            },
            'maxEntries': {'type': 'integer', 'minimum': 1, 'maximum': 5},
          },
          'required': ['topics'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkProjectInfo)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkProjectInfo,
        'description':
            'Read the current SoLab APK project metadata (file name, package, version, hashes, analysis/rule versions, linked conversation).',
        'parameters': {'type': 'object', 'properties': <String, dynamic>{}},
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkRules)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkRules,
        'description':
            'Read the SoLab APK rule library: per-category rule counts, enabled state, vendor mappings, and current report matches.',
        'parameters': {
          'type': 'object',
          'properties': {
            'vendor': {
              'type': 'string',
              'description':
                  'Optional vendor id to list its rules (e.g. pangle, tencent_gdt, kuaishou, baidu). Omit to get category counts + matching vendor suggestions.',
            },
            'offset': {
              'type': 'integer',
              'description':
                  'Pagination offset for vendor rules (default 0). Custom rule libraries can hold thousands of entries; page through with offset/limit until hasMore=false.',
            },
            'limit': {
              'type': 'integer',
              'description':
                  'Page size for vendor rules (default 50, max 1000). Only fetch more when actually needed.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkPatchDex)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkPatchDex,
        'description':
            'DEX write tool. Patch targets must come from class_outline / dex_xref / smali_read / Analyzer evidence — report string hits are clues, never patch targets. For an already-authorized exact change: call once with dryRun=true and applyAfterPreview=true (preview + apply in one). Use pure dryRun to see exact applyArguments when a decision is still needed. Output path goes to apk_sign; never overwrite the source APK.',
        'parameters': {
          'type': 'object',
          'properties': {
            'voidMethods': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact void-returning ad method names to neutralize, or class-qualified DEX identifiers (Lpkg/Class;->name) returned by class_outline, dex_xref or smali_read.',
            },
            'classMethods': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact class-qualified method identifiers from class_outline, dex_xref or smali_read (qualifiedId, e.g. Lcom/bytedance/.../TTAdSdk;->init). Accepted forms: Lpkg/Class;->name or pkg.Class.methodName. The engine dispatches by real return type: void is neutralized, boolean/int is forced false, callbacks and unsupported types are skipped and reported. This is the recommended way to patch any located method.',
            },
            'trueMethods': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact membership/VIP state method names to force true (B3). Obtain them from class_outline, dex_xref or smali_read after verifying the real boolean-returning definition. Report string hits are clues and CANNOT be patched directly. Accepted forms: exact method name, Lpkg/Class;->name, or full qualifiedId with signature (Lpkg/Class;->name(params)ret). Matching is case-insensitive; the dryRun response returns the original DEX spelling.',
            },
            'falseMethods': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact boolean/integer ad-state method names to force false.',
            },
            'sdkPackages': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Ad SDK package names matched in the report (adSdkMatches). Only loadLibrary calls whose library-name string is statically present are NOPed. A runtime argument is intentionally not guessed; use the matched upstream init method instead.',
            },
            'removeVpnDetection': {
              'type': 'boolean',
              'description':
                  'Force VPN-detection methods (name contains isvpn/checkvpn/vpnconnected/... , boolean/int return) to false. Preview first.',
            },
            'removeEmulatorDetection': {
              'type': 'boolean',
              'description':
                  'Force emulator-detection methods (name contains isemulator/checkemulator/isvirtualdevice/... , boolean/int return) to false. Preview first.',
            },
            'removeRootDetection': {
              'type': 'boolean',
              'description':
                  'Force root-detection methods (name contains isrooted/checkroot/hasroot/suavailable/... , boolean/int return) to false. Preview first.',
            },
            'removeScreenCaptureDetection': {
              'type': 'boolean',
              'description':
                  'Force screen-capture/recording-detection methods (name contains onscreencapture/screencapturecallback/isrecording/isprojection/... , boolean/int return) to false so the app cannot detect or react to screenshots or screen recording. Preview first and confirm the hit list — isrecording is broad by design.',
            },
            'removeFlagSecure': {
              'type': 'boolean',
              'description':
                  'Re-enable screenshots: clear the FLAG_SECURE (0x2000) bit from constants flowing into Window.setFlags/addFlags, keeping other flag bits intact (0x2008 stays 0x0008). Surgical instruction-level patch — it does not void onCreate or whole methods. Covers the common addFlags(FLAG_SECURE)/setFlags(FLAG_SECURE, FLAG_SECURE) pattern; or-int bit-composition is not covered yet (locate manually with smali_read + classMethods).',
            },
            'removeDebugDetection': {
              'type': 'boolean',
              'description':
                  'Force debugger-detection methods (name contains isdebuggable/isdebuggerconnected/ptrace/antidebug/... , boolean/int return) to false. Preview first.',
            },
            'timeMethods': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact expiry/remaining-time method names to hijack to a far-future value (long-return only), from the report timeMethodCandidates.',
            },
            'nullMethods': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact object-returning method names to stub to return null (REQ-06). Only affects methods whose return type is an object (starts with L).',
            },
            'shortenSplashCountdown': {
              'type': 'boolean',
              // F-42（2026-10-04）：dryRun 现在返回**真明细** splashCountdownTargets
              // （与 apply 同一检测源——清单里的方法即应用时会改的方法）；应用
              // 回执另给 splashCountdown 计数。除非要缩小范围，否则无需再靠
              // class_outline 预核。
              'description':
                  'Shorten splash-screen ad countdowns: in classes whose type contains "splash", track CONST values written to registers; when Handler.postDelayed / sendEmptyMessageDelayed / sendMessageDelayed / CountDownTimer.<init> is hit with delay >= 1000ms, zero out the delay constant so the countdown ends immediately and the app enters the main UI. The dryRun preview returns splashCountdownTargets — same detection source as apply, so listed methods are exactly what will be shortened; the applied count comes back as splashCountdown.',
            },
            'signatureBypass': {
              'type': 'boolean',
              'default': false,
              'description':
                  'DEPRECATED (F-41): use the dedicated signature_bypass tool as the first write against the unchanged original APK; mixing signature work into a patch call is no longer the supported path. Kept only for backward compatibility — if set, run it alone against the unchanged original (no business patch in the same call), then pass the returned nextInputPath to later modifications with signatureBypass=false.',
            },
            'signatureBypassMode': {
              'type': 'string',
              // F-41（2026-10-04）：枚举补 'dpatch'——执行层（SolabChannel 校验集）
              // 与 retry 提示一直是三模式，schema 独缺导致走旧路径的 agent 静默
              // 拿不到 dpatch（保留原包签名只注入独立 payload 的最后手段）。
              'enum': ['normal', 'original_apk', 'dpatch'],
              'description':
                  'Signature compatibility mode. normal by default. original_apk: whole-APK verification fallback with embedded-original I/O redirection plus ZIP data multiplexing. dpatch: keep the original APK signature intact and inject a standalone payload — the last resort for signature-verified apps; prefer the dedicated signature_bypass tool. Only relevant when signatureBypass=true.',
            },
            'originalApkPath': {
              'type': 'string',
              'description':
                  'Absolute path of the unchanged original APK. Required when upgrading an already modified normal-mode package; optional when apkPath itself is the unchanged original.',
            },
            'stripDebugInfo': {
              'type': 'boolean',
              'description':
                  'Size optimization (from ref 2.9): when writing back a patched DEX, strip debug info (line numbers / local variable tables / param names) from ALL classes in that DEX, shrinking it by 5%~15% with zero runtime impact. Only applies to DEX files already being rewritten by this patch call; does not touch unmodified DEX files. Recommended true when size matters.',
            },
            ...apkPathParameter,
            ...allowOversizeParameter,
            'dryRun': {'type': 'boolean'},
            'applyAfterPreview': {
              'type': 'boolean',
              'description':
                  'When the user already authorized this exact modification, set true with dryRun=true. The tool previews and, only if the preview has no warning, applies the same parameters in this call.',
            },
            'confirm': {'type': 'boolean'},
            'previewToken': {'type': 'string'},
          },
          'required': ['dryRun'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkPatchDexStrings)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkPatchDexStrings,
        'description':
            'Replace exact const-string references inside dex files (URLs, UI copy, watermarks) in seconds — no full decode→smali→build rebuild needed. Pass replacements as a {old: new} object or a [{"from": ..., "to": ...}] list; from must be non-empty and differ from to. dryRun previews matched strings per dex without writing; apply with the same parameters plus applyAfterPreview=true (or confirm=true). The source APK is never modified; the output is an unsigned intermediate package — sign before installing. Exact-match only: obfuscated/split strings or strings living in libapp.so are not found here.',
        'parameters': {
          'type': 'object',
          'properties': {
            'replacements': {
              'type': 'object',
              // v8-D2（2026-10-04）：两种形态均可——{old: new} 对象或
              // [{"from":…, "to":…}] 列表（守卫按 acceptsTypes 放行两种）。
              'acceptsTypes': ['object', 'array'],
              'description':
                  '{old: new} pairs to replace, e.g. {"https://old.example/api": "https://new.example/api"}, '
                  'or a list form [{"from": "...", "to": "..."}]. Keys are matched exactly against const-string pool entries — '
                  'leading/trailing spaces are significant (no trimming).',
            },
            ...apkPathParameter,
            ...allowOversizeParameter,
            'dryRun': {'type': 'boolean'},
            'applyAfterPreview': {
              'type': 'boolean',
              'description':
                  'When the user already authorized this exact modification, set true with dryRun=true. The tool previews and, only if the preview has no warning, applies the same parameters in this call.',
            },
            'confirm': {'type': 'boolean'},
            'previewToken': {'type': 'string'},
          },
          'required': ['dryRun'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkSignatureBypass)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkSignatureBypass,
        'description':
            'Standalone signature handling — three independent signature-bypass modes for the original APK, freely switchable per user instruction. Omit mode to follow the APK Workbench setting (new-install default: off, i.e. NO bypass — the caller must name a mode explicitly); an explicit user mode always wins. mode=normal fakes PackageInfo signatures in-process; mode=original_apk embeds the original APK and redirects file reads; mode=dpatch writes only its independent DEX/native payload plus the unchanged original APK, then starts through its component factory before application creation. Every mode returns an output path: use it as apkPath for every later modification with signatureBypass=false. Does NOT analyze, patch business logic, or sign. Call it alone; do not reuse patch_apk_dex_methods(signatureBypass=true) for this.',
        'parameters': {
          'type': 'object',
          'properties': {
            ...apkPathParameter,
            'mode': {
              'type': 'string',
              'enum': ['normal', 'original_apk', 'dpatch'],
              'description':
                  'Omitted: follow the current APK Workbench setting (new-install default off = no bypass); an explicit value wins. When the workbench default is off and you set signatureBypass=true without naming a mode, the call is refused with signature_bypass_disabled and a retry_with_param hint. normal=Application proxy | original_apk=embedded original APK + read redirection | dpatch=standalone DEX/native payload started by its component factory (prepared from the unmodified original).',
            },
            'originalApkPath': {
              'type': 'string',
              'description':
                  'Absolute path of the unchanged original APK, required when upgrading an already-modified normal-mode package to original_apk.',
            },
            'makeActive': {
              'type': 'boolean',
              'description':
                  'Default false. Signature handling is a staging step: the produced package is NOT promoted to the active modification target, and the previous active target is restored (the response repeats this and tells you how to opt in). Pass true only when the user explicitly wants this bypass output to be the artifact that later modifications build on.',
            },
          },
          'required': ['apkPath'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkPatchManifest)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkPatchManifest,
        'description':
            'Apply AndroidManifest.xml edits to remove ad components, permissions, or ad SDK meta-data. For an exact modification already authorized by the user, call once with dryRun=true and applyAfterPreview=true; warning or no-change previews are never auto-applied. Pure dryRun returns exact applyArguments for a later call. Set auto=true to match the rule library. Removing components can cause ActivityNotFoundException; prefer verified meta-data edits. The source APK is never modified; sign the output before installing.',
        'parameters': {
          'type': 'object',
          'properties': {
            'removeComponents': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact component full names (e.g. com.ad.sdk.AdActivity) to remove. Empty to skip.',
            },
            'removePermissions': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact permission names (e.g. android.permission.READ_PHONE_STATE) to remove. Empty to skip.',
            },
            'removeMetaData': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Exact ad SDK meta-data config keys (e.g. com.qq.e.comm.AppId) to remove. Safer than removing components: ad SDK init fails silently. Empty to skip.',
            },
            'auto': {
              'type': 'boolean',
              'description':
                  'Match ad components and ad_permissions automatically from the rule library.',
            },
            'applicationFlags': {
              'type': 'object',
              'additionalProperties': {'type': 'boolean'},
              'description':
                  'Set boolean attributes on the <application> element, e.g. {"debuggable": false} or {"allowBackup": false}. Only rewrites attributes that already exist (pure byte edit, no string-pool rebuild); attributes that are absent are reported in skippedFlags, never added. Cannot add a new attribute.',
            },
            ...apkPathParameter,
            'dryRun': {'type': 'boolean'},
            'applyAfterPreview': {
              'type': 'boolean',
              'description':
                  'For an already authorized exact modification: preview and apply the unchanged parameters in one call unless the preview contains a warning.',
            },
            'confirm': {'type': 'boolean'},
            'previewToken': {'type': 'string'},
          },
          'required': ['dryRun'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkToolMap)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkToolMap,
        'description':
            'List the enabled APK tools as a compact index. Pass tool=<name> to get that tool\'s complete parameter schema and documentation. Use filter=write to see only mutation tools (staging/verification/cleanup) without paging the full index.',
        'parameters': {
          'type': 'object',
          'properties': {
            'tool': {
              'type': 'string',
              'description':
                  'Optional exact tool name. Returns the complete schema for that one tool.',
            },
            'filter': {
              'type': 'string',
              'enum': ['declaredNow', 'missing', 'write'],
              'description':
                  'Optional directory filter (catalog mode only): declaredNow = tools declared this turn; missing = enabled but not declared this turn; write = mutation/staging/verification/cleanup tools only.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkPatchMemory)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkPatchMemory,
        'description':
            'Two modes. (1) Default: read past patch memories matching the CURRENT APK by type fingerprint (ad SDK vendors + shell type + engine), NOT by package name/SHA/app name. Call before modifying to reuse a one-line solution. (2) lookupArtifactPath: identify a mysterious APK file by its content sha256 — answers "is this file an already-verified patched product / an analyzed source package?" across sessions, so you never redo an already-patched baseline from the original.',
        'parameters': {
          'type': 'object',
          'properties': {
            'lookupArtifactPath': {
              'type': 'string',
              'description':
                  'Absolute path of an APK to identify by content fingerprint. Returns matched verified-artifact records (with solution/targets) and/or the registered source project. Recommended before re-patching any pre-existing _signed/baseline APK found in the work directory.',
            },
            'listAll': {
              'type': 'boolean',
              'description':
                  'true = return a compact summary of ALL stored experiences (id/title/app/version/outcome) instead of the current-APK match. Use to browse; full details load via the default matched mode.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkSavePatchMemory)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkSavePatchMemory,
        'description':
            'Stage the final APK modification record after apk_sign. This does NOT write long-term memory. It persists a pending draft on the signed artifact so it survives until the user installs the APK. After staging, Agent mode must call ask_user_input_v0 to ask whether the modification worked; MCP callers without a question tool may ask in text. Only record_apk_patch_verification may commit the staged draft.',
        'parameters': {
          'type': 'object',
          'properties': {
            'title': {
              'type': 'string',
              'description':
                  'Short type label, e.g. 穿山甲+开屏去广告 (vendor + ad format).',
            },
            'solution': {
              'type': 'string',
              'description':
                  'One-line minimal fix: which single place to patch to disable a whole class.',
            },
            'pitfall': {
              'type': 'string',
              'description':
                  'Optional how-to-do-it-right warning shown on reuse. Example: use force_return_constant for constant returns; never raw-hex a stack frame.',
            },
            'targets': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Concrete patch locators of this run (dex qualifiedId / so symbol / zip entry path). Same-type entries are merged into one memory; targets accumulate so future runs can locate the exact spots directly.',
            },
          },
          'required': ['title', 'solution'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(
    LocalToolNames.apkRecordPatchVerification,
  )) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkRecordPatchVerification,
        'description':
            'Commit the staged APK draft to long-term memory exactly once, only after the user explicitly reports the installed signed APK worked or failed. Tool success, byte verification, signing, or delivering the file is not user validation. A success automatically cleans the work directory and keeps exactly the original APK plus the final signed APK; failure keeps the diagnostic workspace. Runs outside the build ledger are degraded, not rejected: the conclusion is still recorded and the response carries degraded:true plus a warning listing exactly what could not be stored (pass artifactPath to keep the artifact fingerprint).',
        'parameters': {
          'type': 'object',
          'properties': {
            'outcome': {
              'type': 'string',
              'enum': ['success', 'failure'],
            },
            'summary': {
              'type': 'string',
              'description': 'Installed behavior and any regression observed.',
            },
            'pitfall': {
              'type': 'string',
              'description':
                  'Optional pitfall learned in this run; merged into the verified memory entry. Example: use force_return_constant for constant returns; never raw-hex a stack frame.',
            },
            'artifactPath': {
              'type': 'string',
              'description':
                  'Exact APK file the user installed and verified. Pass it whenever the run did not go through the apk_sign/build ledger (direct streaming patch + sign): without it the artifact fingerprint falls back to the last APK any tool touched, which is usually the source APK, and no artifact fingerprint is stored.',
            },
          },
          'required': ['outcome', 'summary'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkListBuilds)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkListBuilds,
        'description':
            'List all indexed APK artifacts, including patch intermediates and MT builds (output path + timestamp + keep flag). Use it to inspect the exact artifact history before cleanup.',
        'parameters': {'type': 'object', 'properties': <String, dynamic>{}},
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkCleanupBuilds)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkCleanupBuilds,
        'description':
            'Reclaim workspace junk after a task chain: default scope deletes regenerable caches and stale outputs; aggressive=true restores the indexed clean baseline. Always dryRun first, then confirm=true with the previewToken. Pass keep=[paths] for anything the user asked to preserve (written into the build index keep flag, honoured by all later cleanups) and release=[paths] to drop that protection. After the user confirms the installed final APK works, verified cleanup runs automatically and keeps only the original APK and final signed artifact.',
        'parameters': {
          'type': 'object',
          'properties': {
            'aggressive': {
              'type': 'boolean',
              'description':
                  'Also restore the clean baseline: remove everything in the work dir except signed builds, indexed source APKs, and the active modification target (Blutter results and jadx exports are deleted too — they will be rebuilt on demand). Default false.',
            },
            'dryRun': {'type': 'boolean'},
            'confirm': {'type': 'boolean'},
            'previewToken': {'type': 'string'},
            'keep': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Artifact paths or file names the user explicitly asked to keep. On the confirming call they are written into the build index as keep=true, so this and every later cleanup / missing-artifact pruning / intermediate auto-clean skips them. A dryRun only previews the effect (the index is not modified).',
            },
            'release': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Artifact paths or file names to release: clears their keep flag so cleanup may delete them again. A name listed in both keep and release is kept.',
            },
          },
          'required': ['dryRun'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkNoteRead)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkNoteRead,
        'description':
            'Read persisted notes of which methods/entries were already modified for the current APK (cross-session). Returns a list of locators with status + summary, so you do not re-patch or miss an already-patched method.',
        'parameters': {'type': 'object', 'properties': <String, dynamic>{}},
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkNoteWrite)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkNoteWrite,
        'description':
            'Stage a modification locator on the current artifact without writing long-term memory. The staged note is committed only after record_apk_patch_verification receives the user-installed result.',
        'parameters': {
          'type': 'object',
          'properties': {
            'locator': {
              'type': 'string',
              'description': 'Modified method/entry locator',
            },
            'status': {
              'type': 'string',
              'description': 'e.g. patched / nop / forced_true',
            },
            'summary': {
              'type': 'string',
              'description': 'One-line summary of the change',
            },
          },
          'required': ['locator'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkListWorkspace)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkListWorkspace,
        'description':
            'List APK files in the configured work directory. Use it to discover which APKs are available to analyze/patch without asking the user to pick a path manually.',
        'parameters': {'type': 'object', 'properties': <String, dynamic>{}},
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.runTaskCommand)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.runTaskCommand,
        'description':
            'Runs a fixed-probe Task Command chain (Direct Command 2.0) in ONE call and returns the evidence digest; the LLM only judges, it never invents the query chain. FIELD_STATE_LOCATE = field-state location: FIELD_USAGE then WRITE_FIELD priority then METHOD_BODY (authoritative writer smali, up to 3) then the writer\'s upstream callers. FIELD_CANDIDATE_MINE = field-candidate mining from a semantic description (e.g. VIP unlock, ad removal). AD_SDK_LOCATE = ad-SDK location from a package name. SIGNATURE_CHECK_LOCATE = signature-check evidence. VERIFY_ARTIFACT = artifact verification. Chains are programmatic probes; failures return a structured failureReason plus recent same-app failure memory.',
        'parameters': {
          'type': 'object',
          'properties': {
            'command': {
              'type': 'string',
              'enum': [
                'FIELD_STATE_LOCATE',
                'VERIFY_ARTIFACT',
                'FIELD_CANDIDATE_MINE',
                'AD_SDK_LOCATE',
                'SIGNATURE_CHECK_LOCATE',
              ],
            },
            'semantic': {
              'type': 'string',
              'description':
                  'Required for FIELD_CANDIDATE_MINE: semantic description, e.g. VIP unlock or ad removal.',
            },
            'vendor': {
              'type': 'string',
              'description':
                  'Optional for AD_SDK_LOCATE: the ad SDK package to locate, e.g. com.bytedance.sdk.openadsdk; default takes the report\'s top-3 adSdkMatches.',
            },
            'field': {
              'type': 'string',
              'description':
                  'Field name (e.g. isVip) or a full qid such as Lpkg/Class;->isVip:Z',
            },
            'className': {
              'type': 'string',
              'description':
                  'Field host class, e.g. UserInfoBean or Lcom/x/UserInfoBean;',
            },
            'apkPath': {
              'type': 'string',
              'description':
                  'Optional; defaults to the current active chain target.',
            },
            'install': {
              'type': 'boolean',
              'description':
                  'Optional; true = after the three checks pass, start the system install intent (PackageInstaller confirmation dialog on screen; the user must approve). install SUCCESS means the system signature check passed = device-side Verified evidence. False = do not start the install intent.',
            },
          },
          'required': ['command'],
        },
      },
    });
  }
  // analyzer.* 四工具（open/global_search/find_field_usage/business_state）：
  // handler 与 assistant.localToolIds 均有，但声明层长期缺失——点名也不挂
  // （冒烟实测 analyzer.* 连续 unknown_function）。此处按启用集追加声明。
  final analyzerEnabled = AnalyzerToolNames.all
      .where(assistant.localToolIds.contains)
      .toSet();
  if (analyzerEnabled.isNotEmpty) {
    tools.addAll(AnalyzerGatewayTools.buildDefinitions(analyzerEnabled));
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkAnalyzeWorkspace)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkAnalyzeWorkspace,
        'description':
            'Analyze an APK in the workspace — call it on demand, not as a forced first step. Independently callable whenever a report is needed. signatureMode is optional: omitted follows the APK Workbench setting; skip does not run signature preparation. Returns sample+totals only; read details later via get_current_apk_report(section=...). The MCP side queues this tool automatically and returns a taskId.',
        'parameters': {
          'type': 'object',
          'properties': {
            'fileName': {
              'type': 'string',
              'description':
                  'APK file name inside the work directory (bare file name, not a path), e.g. 橘汁_3.0.2.3_会员解锁去广告_v3.apk.',
            },
            'signatureMode': {
              'type': 'string',
              'enum': ['normal', 'original_apk', 'dpatch', 'skip'],
              'description':
                  'normal=standard bypass, original_apk=embedded-original bypass, dpatch=DPatch bypass (separate prepared output), skip=no bypass. Freely switchable per user intent; when omitted, the Workbench default applies.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkArchive)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkArchive,
        'description':
            'Browse an APK without extracting it. action=list returns a paged flat entry list and can filter by query; action=read returns a bounded text or hex window for one exact entry; action=certificates verifies and returns signer subject, issuer, validity and fingerprints. For native SO entries, pass va instead of offset: the ELF64 PT_LOAD mapping is done for you (no manual address arithmetic). Pass reads (up to 8 items) to batch-verify multiple patch sites in one call. All actions are read-only and use the current APK when path is omitted.',
        'parameters': {
          'type': 'object',
          // 条件必填（标准 JSON Schema）：action=read/strings 时 entry 必填，
          // list/certificates 不需要。宽松网关忽略 allOf 不受影响。
          'allOf': [
            {
              'if': {
                'properties': {
                  'action': {
                    'enum': ['read', 'strings'],
                  },
                },
                'required': ['action'],
                // D9（2026-09-21 自检）：handler 里 reads 数组优先于 action（批量读
                // 时不需要顶层 entry，entry 在每个 items[] 里）。旧条件只看
                // action=read/strings 就要求 entry，于是 {path, action:'read',
                // reads:[...]} 被客户端校验判缺 entry，而同一个 handler 对
                // {path, reads:[...]} 放行——同一形状先成功后失败。这里排除
                // 带 reads 的调用，与 handler 的优先级对齐。
                'not': {
                  'required': ['reads'],
                },
              },
              'then': {
                'required': ['entry'],
              },
            },
          ],
          'properties': {
            'path': {
              'type': 'string',
              'description':
                  'APK path, or a work-directory file name. Omit to use the current APK.',
            },
            'action': {
              'type': 'string',
              'enum': ['list', 'read', 'strings', 'certificates', 'resources'],
              'description':
                  'list (default), read, strings, or certificates. read and strings REQUIRE entry (rejected without it); list and certificates do not use entry. NOTE: `reads` is NOT an action value — it is the batch array parameter (see `reads`); pass reads alone or with action=read, never as action=reads.',
            },
            'query': {
              'type': 'string',
              'description': 'Case-insensitive path filter for list.',
            },
            'entry': {
              'type': 'string',
              'description':
                  'REQUIRED for action=read and action=strings: exact APK entry path (e.g. "classes.dex", "res/values/strings.xml", "AndroidManifest.xml"). Calls with action=read/strings but no entry are rejected.',
            },
            'offset': {
              'type': 'integer',
              'description':
                  'list: entry offset; read: byte offset. Both are zero-based.',
            },
            'limit': {
              'type': 'integer',
              'description':
                  'list: entries per page (max 500); read: bytes per window (max 65536).',
            },
            'minLen': {
              'type': 'integer',
              'description': 'Minimum string length for strings (default 4).',
            },
            'id': {
              'type': 'string',
              'description':
                  'action=resources only: exact resource id such as "0x7f010000" (0xPPTTEEEE). '
                  'Use it for a single resource; use query to search by name/type/value instead.',
            },
            'withReferences': {
              'type': 'boolean',
              'description':
                  'action=list only: when true, each entry gets referencedFromDex — whether its path '
                  'or file name appears in the dex string pool (is the entry still referenced by code?). '
                  'Costs one full dex-string scan per APK (cached by file fingerprint); off by default.',
            },
            'va': {
              'type': 'string',
              'description':
                  'action=read only, for native SO entries: ELF64 virtual address (e.g. "0x1234c0"). Automatically mapped to an in-entry file offset via PT_LOAD segments, so never do the address math yourself. Applies to arm64 ELF64 entries; use offset for everything else. Combines with offset (added after mapping) and limit.',
            },
            'reads': {
              'type': 'array',
              'maxItems': 8,
              'items': {
                'type': 'object',
                'properties': {
                  'entry': {
                    'type': 'string',
                    'description': 'Exact APK entry path.',
                  },
                  'va': {
                    'type': 'string',
                    'description':
                        'ELF64 virtual address (preferred for SO patch verification).',
                  },
                  'offset': {
                    'type': 'integer',
                    'description': 'Byte offset within the entry.',
                  },
                  'limit': {
                    'type': 'integer',
                    'description':
                        'Bytes per window; defaults to 64 in batch mode.',
                  },
                },
                'required': ['entry'],
              },
              'description':
                  'Batch read (action is implied read): up to 8 {entry, va|offset, limit} items verified in ONE call, e.g. all patch sites of a rebuild. Each item is independent; the response is {ok, batch:true, reads:[...], succeeded, failed}. Prefer this over repeated single reads.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkExportReport)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkExportReport,
        'description':
            'Save the current fresh APK analysis report as JSON in the workspace directory. It does not reanalyze or modify the APK.',
        'parameters': {
          'type': 'object',
          'properties': {
            'fileName': {
              'type': 'string',
              'description':
                  'Optional output .json file name only, without a directory. A unique name is generated when omitted.',
            },
          },
        },
      },
    });
  }
  // ===== 静态分析工具链（jadx/baksmali/APKEditor/DexKit）=====
  if (assistant.localToolIds.contains(LocalToolNames.jadxDecompile)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.jadxDecompile,
        'description':
            'Decompile an APK/DEX/JAR to Java. For action=class, copy both className and dexName from class_outline: only that dex is extracted and loaded. Without dexName, a large APK may scan dex files one by one. Use action=list with a small limit only to discover names; action=save is for a confirmed export need and may be slow.',
        'parameters': {
          'type': 'object',
          'properties': {
            'path': {
              'type': 'string',
              'description':
                  'Absolute APK/DEX/JAR path, or file name resolved against the workspace directory.',
            },
            'action': {
              'type': 'string',
              'enum': ['save', 'class', 'list'],
              'description':
                  'save (default) exports all; class returns one class source; list returns class names.',
            },
            'className': {
              'type': 'string',
              'description':
                  'Full class name for action=class, e.g. com.example.Foo.',
            },
            'dexName': {
              'type': 'string',
              'description':
                  'Optional classesN.dex returned by class_outline for action=class. Use it verbatim to avoid scanning every dex in a large APK.',
            },
            'limit': {
              'type': 'integer',
              'description': 'Max class names for action=list (default 500).',
            },
            'offset': {
              'type': 'integer',
              'description':
                  'For action=list pagination: skip this many classes first (use nextOffset from the previous response to page through large APKs).',
            },
            ...allowOversizeParameter,
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkSign)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkSign,
        'description':
            'Sign the latest patch/rebuild output with v1/v2/v3 schemes. Pass the output path returned by the write tool, not the original source APK. The built-in key differs from the official signature, so an existing official app may need uninstalling before installation.',
        'parameters': {
          'type': 'object',
          'properties': {
            'path': {
              'type': 'string',
              'description': 'APK to sign (absolute path).',
            },
            'outputApk': {
              'type': 'string',
              'description': 'Output path (default <stem>_成品.apk).',
            },
            'minSdk': {
              'type': 'integer',
              'description': 'Min SDK (default 26).',
            },
            'confirm': {
              'type': 'boolean',
              'description':
                  'Default false. When no explicit path is given the tool signs the current active artifact; if that resolved target already looks like a signed deliverable (*_成品.apk / *_signed.apk) the call is refused with already_signed_confirm_required instead of producing a redundant package. Ask the user first, then re-issue with confirm=true (or pass an explicit path).',
            },
            'install': {
              'type': 'boolean',
              'description':
                  'Default false. true = after signing, raise the "ask the user to install this package on the device and report back" waiting point (questionArguments + completionBlockedUntilUserAnswer). This does NOT install silently: it needs install authorization. run_task_command(command=VERIFY_ARTIFACT, install=true) is the automatic PackageInstaller path; use this flag when the user should install manually.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.apkRebuild)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.apkRebuild,
        'description':
            'Full APK decode/build/merge/refactor via APKEditor (pure Java). action=decode splits an APK into an editable dir (resources + optional smali); action=build recompiles that dir into a full APK; action=merge combines split bundles (xapk/apks/apkm) into one APK; action=refactor restores obfuscated resource names. Sign the output with apk_sign before installing.',
        'parameters': {
          'type': 'object',
          'properties': {
            'path': {
              'type': 'string',
              'description':
                  'Input: APK file (decode/merge/refactor) or decoded directory (build).',
            },
            'action': {
              'type': 'string',
              'enum': ['decode', 'build', 'merge', 'refactor'],
              'description': 'decode (default) | build | merge | refactor.',
            },
            'output': {
              'type': 'string',
              'description':
                  'Output path (default <workDir>/SoLab/output/apkeditor/).',
            },
            'type': {
              'type': 'string',
              'enum': ['json', 'xml', 'raw'],
              'description': 'Resource format (default json).',
            },
            'dex': {
              'type': 'boolean',
              'description':
                  'decode: true (default) keeps raw dex (fast, resource/manifest edits only); false decompiles dex→smali (minutes-long, only when editing smali code).',
            },
            'force': {
              'type': 'boolean',
              'description':
                  'build: overwrite existing output (default false).',
            },
            'fixTypeNames': {
              'type': 'boolean',
              'description': 'build: fix type names (default false).',
            },
            'cleanMeta': {
              'type': 'boolean',
              'description':
                  'merge/refactor: clean META-INF old signatures (default true).',
            },
            ...allowOversizeParameter,
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.dexSearch)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.dexSearch,
        'description':
            'DEX auto-search for location, filtering and candidate ranking; independently callable. Default action=auto: keyword substring hit across class/method names and strings (not evidence composition); after a class hit, deep-dive with class_outline/smali_read. Structural clues (className/methodName) can stand alone without keyword; keyword is for string/name search. Use keywords for multi-term sweeps (cap 8).',
        'parameters': {
          'type': 'object',
          'properties': {
            'path': {
              'type': 'string',
              'description': 'APK or bare .dex file absolute path.',
            },
            'keyword': {
              'type': 'string',
              'description':
                  'String/name to search. Multi-string and feature actions accept up to 16 terms joined by |. A literal | inside the target (e.g. a regex fragment such as (?i:http|https|rtsp)://) must be escaped as \\| — otherwise it splits into terms, and matchType=Equals then degrades to per-fragment matching and reports a false 0 hits. Note matchType=Contains matches a pool entry CONTAINING the term, not the term itself.',
            },
            'keywords': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Batch mode: up to 8 keywords, each searched independently in ONE call (shared className/action/matchType/limit). Each item returns its own result object; zero-hit items stay as entries without aborting the batch. Use this instead of looping single keyword calls.',
            },
            'numbers': {
              'type': 'array',
              'items': {'type': 'number'},
              'description':
                  'Up to 16 integer or decimal constants. auto combines them with every supplied evidence type and relaxes only after a strict miss.',
            },
            'className': {
              'type': 'string',
              'description':
                  'Candidate declaring class name; auto treats it as one evidence dimension.',
            },
            'methodName': {
              'type': 'string',
              'description':
                  'Candidate method name; auto treats it as one evidence dimension.',
            },
            'fieldNames': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Fields read or written by a candidate. auto first requires every name in one method, then ranks partial cross-evidence matches.',
            },
            'invokedMethodNames': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Methods invoked by a candidate; used as call evidence by auto.',
            },
            'opNames': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Ordered DEX opcode-name subsequence, such as const-string|invoke-virtual|if-eq; used as code evidence by auto.',
            },
            'action': {
              'type': 'string',
              'enum': [
                'auto',
                'method_by_string',
                'class_by_string',
                'method_by_strings',
                'class_by_strings',
                'method_by_numbers',
                'method_by_features',
                'method_by_name',
                'class_by_name',
                'class_by_superclass',
                'class_by_interface',
                'class_by_annotation',
                'method_by_annotation',
              ],
              'description':
                  'Search mode (default auto). auto = substring hit of the keyword across class names, method names and strings (not evidence composition); after a class hit, deep-dive with class_outline/smali_read. Use a specific action only for a single isolated query. Class-structure queries: class_by_superclass finds every subclass of a given parent (keyword = full parent class name; first choice for ad-SDK variant sweeps); class_by_interface finds implementers (keywords may list several interfaces); class_by_annotation / method_by_annotation find annotated classes/methods (e.g. JavascriptInterface, Keep, OnClick).',
            },
            'matchType': {
              'type': 'string',
              'enum': ['Contains', 'Equals', 'StartsWith', 'EndsWith'],
              'description': 'Match type (default Contains).',
            },
            'ignoreCase': {
              'type': 'boolean',
              'description': 'Case-insensitive match (default false).',
            },
            'packagePrefix': {
              'type': 'string',
              'description': 'Limit search to package prefix (faster).',
            },
            'limit': {
              'type': 'integer',
              'description': 'Max results (default 100).',
            },
          },
          'required': ['path'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.stringScan)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.stringScan,
        'description':
            'Scan an APK/DEX/SO/any file for sensitive values only: URLs, IPs, emails, JWTs, private keys, cloud AK-SK, and suspected key/password values. APK hits include source entries in locations. It does not locate Java field or method names; use class_outline, dex_search, or dex_xref for code symbols.',
        'parameters': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'File absolute path.'},
            'category': {
              'type': 'string',
              'enum': [
                'all',
                'url',
                'ip',
                'email',
                'jwt',
                'private_key',
                'aws_ak',
                'google_api',
                'aliyun_ak',
                'secret_field',
              ],
              'description': 'Category filter (default all).',
            },
            'minLen': {
              'type': 'integer',
              'description': 'Min string length (default 5).',
            },
            'limit': {
              'type': 'integer',
              'description': 'Max hits per category (default 100).',
            },
            'includePrivate': {
              'type': 'boolean',
              'description':
                  'category=ip: also report private/LAN ranges (10.x/172.16-31.x/192.168.x). Loopback/zero/broadcast/link-local are always filtered out as noise.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.dexXref)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.dexXref,
        'description':
            'DEX call sites, call flow and override evidence; read-only and safe to run alongside other read-only tools. Independently verifies an existing locator. to/from/both return exact callSites, callers/callees; overrides looks up implementations by class hierarchy and method signature. includeGraph returns directed nodes/edges for flowcharts. Returned qualifiedId values feed smali_read directly. A dex_field: prefix routes to field READ/WRITE xref.',
        'parameters': {
          'type': 'object',
          'properties': {
            'target': {
              'type': 'string',
              'description':
                  'Method qualifiedId, or dex_field:Lpkg/Class;->field:Type for field readers/writers.',
            },
            'path': {
              'type': 'string',
              'description':
                  'APK path (absolute, or a work-dir file name). Optional — defaults to the current continuous-modification artifact / analyzed source APK.',
            },
            'direction': {
              'type': 'string',
              'enum': ['to', 'from', 'both', 'overrides'],
              'description':
                  'to=call sites/callers, from=callees, both=two-way flow, overrides=subclass/interface implementations.',
            },
            'classPrefix': {
              'type': 'string',
              'description':
                  'Filter callers by class name prefix (business package, e.g. Lcom/platovpn).',
            },
            'callerPrefix': {
              'type': 'string',
              'description': 'Alias of classPrefix.',
            },
            'offset': {
              'type': 'integer',
              'description':
                  'Pagination offset into directCallers / field refs (default 0). Every offset is reachable — totals stay in summary, paging never drops data.',
            },
            'limit': {
              'type': 'integer',
              'description':
                  'Max rows per page (default 50; field refs default 500). Page deeper with offset=nextCursor until truncated=false.',
            },
            'callSiteOffset': {
              'type': 'integer',
              'description':
                  'Pagination offset into callSites (default 0). Reaches every call site, not just the first window.',
            },
            'callSiteLimit': {
              'type': 'integer',
              'description':
                  'Max call sites per page (default 300). Follow callSitesNextCursor for the rest.',
            },
            'includeGraph': {
              'type': 'boolean',
              'description':
                  'Return a bounded directed nodes/edges graph for flowchart rendering (default false).',
            },
          },
          'required': ['target'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.classOutline)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.classOutline,
        'description':
            'Reads a DEX class\'s methods, fields, signatures and exact locators. Dart/Flutter classes require runtime=dart plus the current Blutter jobId and go through the Blutter ASM index, never a DEX scan. Never merge different classes by short method names; judge by qualifiedId, return type, field shape and call relations. Results feed dex_xref, smali_read or field analysis.',
        'parameters': {
          'type': 'object',
          'properties': {
            'path': {
              'type': 'string',
              'description': 'APK or bare .dex file absolute path.',
            },
            'className': {
              'type': 'string',
              'description':
                  'DEX: full class name (Lpkg/Class;) or short name/substring. Dart: class/path hint for Blutter ASM.',
            },
            'runtime': {
              'type': 'string',
              'enum': ['dex', 'dart'],
              'description':
                  'Default dex. Use dart only with a Blutter jobId; it queries the same native index used by so_analyze.',
            },
            'jobId': {
              'type': 'string',
              'description':
                  'Required only when runtime=dart: current APK Blutter jobId.',
            },
            'offset': {
              'type': 'integer',
              'description':
                  'Method pagination offset (default 0). Fields have their own cursor: fieldsOffset.',
            },
            'fieldsOffset': {
              'type': 'integer',
              'description':
                  'Field pagination offset (default 0). Fields do NOT follow offset; continue with nextFieldsOffset when hasMoreFields=true, otherwise tail fields are unreachable.',
            },
            'limit': {
              'type': 'integer',
              'description': 'Max methods/fields per page (default 200).',
            },
          },
          'required': ['path', 'className'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.smaliRead)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.smaliRead,
        'description':
            'Reads one exact method\'s real instructions, branches, fields and return semantics (read-only, safe to run alongside other read-only tools). This is strong behavioral evidence and directly verifies a qualifiedId from the user or any artifact — no search chain required first. Pass qualifiedId verbatim; batch several methods via qualifiedIds in ONE call (cap 8) instead of calling one by one.',
        'parameters': {
          'type': 'object',
          'properties': {
            'path': {
              'type': 'string',
              'description':
                  'APK absolute path, or a file name resolved against the work directory; defaults to the current artifact when omitted.',
            },
            'qualifiedId': {
              'type': 'string',
              'description':
                  'REQUIRED for a single read. Method qualifiedId from dex_search, class_outline, or dex_xref results, e.g. Lcom/foo/Bar;->isVip()Z. Omit only when passing qualifiedIds batch.',
            },
            'qualifiedIds': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Batch mode: up to 8 qualifiedIds read in ONE call. Each item returns its own result object (failed items keep an error entry without aborting the batch). Use this instead of looping single reads.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.frida)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.frida,
        'description':
            'Frida gadget workflow without root. action=status reports the pinned gadget version/URL, its sha256 and local presence (no path needed). action=install_gadget downloads that pinned build, verifies the sha256, decompresses the .xz and checks it is an arm64 ELF (no path needed). action=inject adds lib/arm64-v8a/libfrida-gadget.so plus a proxy Application that loads it, so the target process later listens on 127.0.0.1:27042. The inject output is an INJECTED build: label every finding as injected, never merge it with static analysis of the original APK, and re-sign it with apk_sign before installing. The runtime actions (open/hook/call/read/backtrace/close) require the Linux sandbox and currently answer environment_not_ready.',
        'parameters': {
          'type': 'object',
          'properties': {
            'action': {
              'type': 'string',
              'enum': [
                'status',
                'install_gadget',
                'inject',
                'open',
                'hook',
                'call',
                'read',
                'backtrace',
                'close',
              ],
              'description':
                  'status/install_gadget need no path. inject needs apkPath. The remaining actions need the Linux sandbox.',
            },
            'apkPath': {
              'type': 'string',
              'description':
                  'APK inside the unified work dir (a file name directly under the work-dir root). Required for inject; anything outside the work dir is refused.',
            },
            'source': {
              'type': 'string',
              'description':
                  'install_gadget only. A mirror URL for the pinned gadget archive, or a mirror prefix ending in "/" (the pinned URL is appended). Use this when github.com is unreachable; the download is still verified against the pinned sha256, so an untrusted mirror cannot swap the binary. Built-in mirrors are tried automatically before the canonical URL.',
            },
            'localPath': {
              'type': 'string',
              'description':
                  'install_gadget only (agent face). Path to an already-downloaded frida-gadget-*.so.xz. It is accepted only when its sha256 equals the pinned value; use it when neither GitHub nor any mirror is reachable.',
            },
          },
          'required': ['action'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.subagent)) {
    // 助手级专家团开关（设置 → 子智能体）：关掉后 schema 里不能留 team/
    // members —— 模型会照着不存在的形态发调用（第 63/65 条同一判据）。
    final teamsEnabled = assistant.subagentTeamsEnabled;
    // 名单面（2026-09-29「各司其职」收口）：schema 只描述当前助手域内可见的
    // 子代理/预置团——开发助手看不到逆向角色，逆向助手看不到开发角色；自建
    // 助手（any 域）全可见。与 SubAgentToolHandler 的 domain 参数同源。
    final domain = SubAgentRegistry.domainForAssistant(assistant);
    final agentCatalog = switch (domain) {
      SubAgentDomain.dev => 'general, 调研员, 实现者, 审核员 (dev domain)',
      SubAgentDomain.apk => 'general, 逆向分析员, 补丁执行者, 改包复核员 (apk domain)',
      SubAgentDomain.any =>
        'general, 调研员, 实现者, 审核员 (dev domain), 逆向分析员, 补丁执行者, 改包复核员 (apk domain)',
    };
    final teamCatalog = switch (domain) {
      SubAgentDomain.dev => 'dev-team (research -> implement -> review)',
      SubAgentDomain.apk => 'apk-team (analyse -> patch -> verify)',
      SubAgentDomain.any =>
        'dev-team (research -> implement -> review) or apk-team (analyse -> patch -> verify)',
    };
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.subagent,
        'description': teamsEnabled
            ? 'Dispatch work to fresh subagent instances. Two shapes: (1) a single job — pass agent + task; (2) an expert team — pass team ($teamCatalog) or your own members[] so several roles collaborate on one goal, optionally chained with blockedBy. Subagents do NOT see this conversation, so put everything they need in task/context. They can only use tools the current assistant also has, a read-only instance cannot write, and writing members need /goal mode. Returns JSON: status/text for a single job, or {members[], merged, warnings} for a team.'
            : 'Dispatch one independent job to a fresh subagent instance: pass agent + task. Expert teams are turned off for this assistant, so team / members are not accepted. Subagents do NOT see this conversation, so put everything they need in task/context. They can only use tools the current assistant also has, a read-only instance cannot write, and a writing instance needs /goal mode. Returns JSON: {status, text}.',
        'parameters': {
          'type': 'object',
          'properties': {
            'agent': {
              'type': 'string',
              'description':
                  'Subagent slug for a single job. Built-ins visible to this assistant: $agentCatalog. Omit for `general`.',
            },
            'task': {
              'type': 'string',
              'description':
                  'For a single job: the one thing to do. For a team: the shared goal every member works towards.',
            },
            'context': {
              'type': 'string',
              'description':
                  'Optional background the subagent needs (it cannot see this chat).',
            },
            'tools': {
              'type': 'array',
              'description':
                  'Only for built-in subagents: which tool categories the instance may use. '
                  'read = read-only tools including the file tool (list/read/grep/info/strings); '
                  'write = mutating tools (needs /goal mode). The legacy `shell` value is accepted '
                  'but grants nothing (sandbox shell is not part of the subagent tool face).',
              'items': {
                'type': 'string',
                'enum': ['read', 'write', 'shell'],
              },
            },
            'label': {
              'type': 'string',
              'description':
                  'Short label shown while this instance runs, to tell parallel instances apart.',
            },
            if (teamsEnabled)
              'team': {
                'type': 'string',
                'description':
                    'Expert-team preset id to run instead of a single agent: $teamCatalog. Pass task as the shared goal.',
              },
            if (teamsEnabled)
              'members': {
                'type': 'array',
                'description':
                    'Custom expert team (max 4). Members without blockedBy may run in parallel; members whose writeScope overlaps are serialised automatically.',
                'items': {
                  'type': 'object',
                  'properties': {
                    'name': {
                      'type': 'string',
                      'description': 'Unique member name inside the team.',
                    },
                    'agent': {
                      'type': 'string',
                      'description': 'Subagent slug to run for this member.',
                    },
                    'task': {
                      'type': 'string',
                      'description': 'What this member must do.',
                    },
                    'blockedBy': {
                      'type': 'array',
                      'items': {'type': 'string'},
                      'description':
                          'Member names that must finish before this one starts.',
                    },
                    'writeScope': {
                      'type': 'array',
                      'items': {'type': 'string'},
                      'description':
                          'Work-directory path prefixes this member may write. Empty = whole work directory; overlapping scopes are serialised instead of running in parallel.',
                    },
                  },
                  'required': ['name', 'agent', 'task'],
                },
              },
          },
          'required': ['task'],
        },
      },
    });
  }
  // 2026-10-03 单开关：暴露与否只看助手是否挂了 run_workflow；具体某条
  // 工作流在对话里可不可用由**该条自己的开关**决定（store.enabled 过滤）。
  if (assistant.localToolIds.contains(LocalToolNames.runWorkflow)) {
    // 没有内置模板（2026-10-03 起）：工作流全部是用户在工作流页面手建或
    // AI 生成落库的；省略 workflow 时工具会返回完整目录（模型先读再用）。
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.runWorkflow,
        'description':
            'Run a saved workflow — a small node graph (text / AI generation / HTTP request / condition / extract / delay / merge / output) that returns one final output. Omit `workflow` to list the available workflows (ids and names); workflows are created by the user in the workflow page (some generated by AI), there are no built-in templates. Pass `input` to hand the workflow its starting text (the start node receives it; downstream nodes reference it as {{start}}). AI generate nodes need a model seam (a chat session); without one they fail while the other node types still run. Returns JSON: {ok, output, steps, trail}.',
        'parameters': {
          'type': 'object',
          'properties': {
            'workflow': {
              'type': 'string',
              'description':
                  'Workflow id or exact name (see the catalog in the description). Omit to list available workflows.',
            },
            'input': {
              'type': 'string',
              'description':
                  'Starting text passed to the workflow start node. Leave empty when the workflow does not need one.',
            },
          },
        },
      },
    });
  }
  if ((assistant.localToolIds.contains(LocalToolNames.todoWrite) ||
          assistant.localToolIds.contains(LocalToolNames.todoRead)) &&
      AgentCapabilityPolicy.enabled(assistant, AgentCapability.todo)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.todoRead,
        'description':
            'Read the task list of this conversation (the external memory for long tasks). Returns {todos, counts, rendered}.',
        'parameters': {'type': 'object', 'properties': <String, dynamic>{}},
      },
    });
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.todoWrite,
        'description':
            'Replace the task list of this conversation (full table, not a patch). Keep it short and verifiable; mark a step done as soon as it is verified, and always send back the complete list including finished items.',
        'parameters': {
          'type': 'object',
          'properties': {
            'todos': {
              'type': 'array',
              'description': 'The complete list, in order.',
              'items': {
                'type': 'object',
                'properties': {
                  'text': {
                    'type': 'string',
                    'description': 'One verifiable step.',
                  },
                  'status': {
                    'type': 'string',
                    'enum': ['pending', 'in_progress', 'done'],
                  },
                },
                'required': ['text'],
              },
            },
          },
          'required': ['todos'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.goalGet) ||
      assistant.localToolIds.contains(LocalToolNames.goalCreate) ||
      assistant.localToolIds.contains(LocalToolNames.goalUpdate)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.goalGet,
        'description':
            'Read the current goal of this conversation: mode (build/plan/goal), status (active/paused/none), objective and whether approvals are bypassed. Call it before changing the goal.',
        'parameters': {'type': 'object', 'properties': <String, dynamic>{}},
      },
    });
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.goalCreate,
        'description':
            'Set the conversation goal and switch the session into goal mode. Goal mode runs without per-tool approval, so only use it for an objective the user actually wants pursued autonomously; keep the objective concrete and verifiable. When the user states a long-running objective, create it instead of waiting for a slash command.',
        'parameters': {
          'type': 'object',
          'properties': {
            'objective': {
              'type': 'string',
              'description':
                  'The objective: one or two sentences, including the success criterion when known.',
            },
          },
          'required': ['objective'],
        },
      },
    });
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.goalUpdate,
        'description':
            'Advance the goal: edit (replace the objective), pause (leave goal mode but keep the objective), resume (enter goal mode again), complete (leave goal mode and clear the objective). Use complete only once the objective is actually achieved, and report what was verified and what was not.',
        'parameters': {
          'type': 'object',
          'properties': {
            'action': {
              'type': 'string',
              'enum': ['edit', 'pause', 'resume', 'complete'],
            },
            'objective': {
              'type': 'string',
              'description': 'New objective; required for edit.',
            },
          },
          'required': ['action'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.soPatchIntoApk)) {
    tools.add({
      'type': 'function',
      'function': {
        'name': LocalToolNames.soPatchIntoApk,
        'description':
            'One-stop: write a patched .so back into the target APK. Only lib/<abi>/*.so entries are patchable. Guards: payload must be a real ELF; a >90% shrink needs allowShrink=true. Auto-senses the latest successful build and resolves the APK entry. For an exact write-back already authorized by the user, use dryRun=true plus applyAfterPreview=true (= preview then auto-apply only if the preview passes all guards; any guard failure blocks the write and returns the error). Pure dryRun returns exact applyArguments. Pass sign=true to produce an installable signed APK.',
        'parameters': {
          'type': 'object',
          'properties': {
            'soPath': {
              'type': 'string',
              'description':
                  'Patched .so path (absolute or work-dir relative). Omit to use the latest so_analyze(build) output remembered in this session.',
            },
            'entryName': {
              'type': 'string',
              'description':
                  'Explicit target entry; must match lib/<abi>/<name>.so. Omit for auto-resolution.',
            },
            'allowShrink': {
              'type': 'boolean',
              'description':
                  'Explicit confirm for a >90% entry shrink (almost always a wrong payload). Omit unless the user truly confirmed the tiny payload.',
            },
            'abi': {
              'type': 'string',
              'description':
                  'Target ABI when the so exists under multiple lib/<abi>/ trees, e.g. arm64-v8a.',
            },
            'sign': {
              'type': 'boolean',
              'description':
                  'Chain built-in signing (v1/v2/v3) after write-back; output signedPath is directly installable. Recommended true when this is the final step.',
            },
            ...apkPathParameter,
            'dryRun': {
              'type': 'boolean',
              'description': 'true = preview only. Always preview first.',
            },
            'applyAfterPreview': {
              'type': 'boolean',
              'description':
                  'For an already authorized exact write-back: preview and apply in one call, preserving the resolved SO path and APK entry.',
            },
            'confirm': {
              'type': 'boolean',
              'description': 'true = execute with the matching previewToken.',
            },
            'previewToken': {
              'type': 'string',
              'description': 'Token from the matching dryRun preview.',
            },
          },
          'required': ['dryRun'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.soAnalyze)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.soAnalyze,
        'description':
            'Local SO/Flutter evidence entry. open, overview, search, functions, xrefs, Blutter, disassembly and editing can each start independently from what evidence already exists — no fixed prerequisite chain. Under obfuscation rely on file identity, VA, object-pool references, constants, function boundaries and call sites first, symbol names second; map VAs before comparing views. Blutter path takes an APK or a directory containing libapp.so+libflutter.so, never a bare .so.',
        'parameters': {
          'type': 'object',
          'properties': {
            'action': {
              'type': 'string',
              'description':
                  'Action name, or a domain name for grouped sub-actions. Domains (read/edit) are NOT callable and are refused with their sub-action list; xref is not an action (use rz_xrefs). Full catalog + parameters: get_solab_tool_map(tool=so_analyze).',
            },
            'path': {
              'type': 'string',
              'description':
                  'SO/APK absolute path inside the work directory, or a work-dir file name (action=open/analyze_apk).',
            },
            'url': {
              'type': 'string',
              // F-43（2026-10-04）：动作已退役（接受面会拒绝）。参数说明只讲
              // 「怎么把文件弄进工作目录」，不再引用不存在的 open_url。
              'description':
                  'DEPRECATED/unused: the open_url action is retired. Put the .so/ELF into the work dir first (file(action=write) or an out-of-band download), then so_analyze(action=open, path=...).',
            },
            'asm': {
              'type': 'string',
              'description': 'Assembly text to assemble (action=rz_asm).',
            },
            'va': {
              'type': 'string',
              'description':
                  'Hex virtual address, e.g. 0x1234 (edit_hex VA mode / blutterAction=disasm: function or instruction VA from locate/xref, returns the full function body with inline [pp+0x...] object-pool annotations; limit param controls max lines, default 400, max 2000).',
            },
            'patchHex': {
              'type': 'string',
              'description':
                  "Hex bytes to write at va, spaces allowed, e.g. '20 00 80 52' (edit_hex VA mode).",
            },
            'name': {
              'type': 'string',
              'description':
                  'Symbol name (edit_symbol rename, or blutterAction filters).',
            },
            'file': {
              'type': 'string',
              'description': 'Audit file path (action=audit_load).',
            },
            'workspaceIdB': {
              'type': 'string',
              'description':
                  'Workspace B for two-SO structural diff (action=rz_diff).',
            },
            'editSessionIdB': {
              'type': 'string',
              'description': 'Edit session B (action=rz_diff).',
            },
            'outputs': {
              'type': 'array',
              'description':
                  'Output variants for multi-build (action=build_many).',
            },
            'writeReport': {
              'type': 'boolean',
              'description':
                  'Write patch-report JSON sidecar (build/build_many).',
            },
            'writeToWorkDir': {
              'type': 'boolean',
              'description':
                  'Mirror build output into work directory (build/build_many).',
            },
            'workspaceId': {
              'type': 'string',
              'description':
                  'Returned by action=open; required for all other actions.',
            },
            'editSessionId': {
              'type': 'string',
              'description':
                  'Returned by action=edit_open. Reads (hexdump/disasm/rz_*/diff) may omit it and then read the original workspace file; edit_hex/edit_asm/edit_symbol need a live session (missing or unknown id returns EDIT_SESSION_NOT_FOUND, so call edit_open first) and their responses echo the session id (edit_asm also returns sessionRestored when it re-opened the session for you). Read responses include readState. Inside op=batch each step may override it.',
            },
            'locator': {
              'type': 'string',
              'description':
                  'so_symbol:/so_function:/so_section: locator, a bare symbol/function name, or a hex VA (disasm/hexdump/rz_*/edit_*). rz_xrefs also accepts addr, target, or va as a locator alias; byteOffset/edits[i].byteOffset are relative to the resolved target start.',
            },
            'edits': {
              'type': 'array',
              'items': {'type': 'object'},
              'description':
                  "Patch list for edit_hex/edit_asm/edit_symbol. Each item MUST be a JSON object (not a string): edit_hex → {va, newHex} (preferred: absolute VA exactly as returned by disasm/xref/locate, no offset math) or {byteOffset, newHex} (relative to the resolved locator start — do NOT pass absolute fileOffset/VA here); edit_asm → {instructionIndex?, byteLength?, mode?, writeAsm} or {mode:'force_return_constant', value, returnType?, valueEncoding?}; returnType=bool requires numeric value 0 or 1, not a boolean literal. 单个 edit_asm 可把这些字段直接放在顶层而不传 edits. force_return_constant auto-generates a stack-safe stub. valueEncoding=auto detects libapp.so/Dart AOT: bool uses NULL_REG+0x20/0x30, null/object uses NULL_REG, int uses Smi; use valueEncoding=native only for native ABI values. Dart strings require a located pool object and are rejected here. never hand-write prologue/epilogue rewrites, the engine rejects stack-imbalanced patches with STACK_IMBALANCE unless overrideStackCheck:true; edit_symbol → {op:'rename', newName}. Values as returned by the matching dryRun preview. For edit_hex you may instead pass va+patchHex (session-tracked VA patching with dryRun/undo) — see va/patchHex.",
            },
            'mode': {
              'type': 'string',
              'description':
                  "Single edit_asm shortcut, e.g. force_return_constant, nop_out, or replace_instructions.",
            },
            'value': {
              'type': 'integer',
              'description':
                  'Single edit_asm force_return_constant value. For returnType=bool use numeric 0 or 1. blutterAction=values also accepts one numeric value here as a shorthand for query.',
            },
            'returnType': {
              'type': 'string',
              'description':
                  'Single edit_asm constant type: int, enum, bool, null, object, or reference.',
            },
            'valueEncoding': {
              'type': 'string',
              'enum': ['auto', 'native', 'dart_aot'],
              'description':
                  'Single edit_asm constant encoding; auto selects from the target.',
            },
            'writeAsm': {
              'type': 'string',
              'description': 'Single edit_asm assembly text.',
            },
            'dryRun': {
              'type': 'boolean',
              'description':
                  'Mutating actions: true=preview only (default); false=apply after user approval.',
            },
            'applyAfterPreview': {
              'type': 'boolean',
              'description':
                  'For edit_hex/edit_asm/edit_symbol only. If the user already authorized the exact edit, set true with dryRun=true; the tool previews then immediately applies the same edit with the returned targetVersion.',
            },
            'targetVersion': {
              'type': 'string',
              'description':
                  'Version guard for edit_hex/edit_asm/edit_symbol with dryRun=false: pass the targetVersion returned by the dryRun preview; if the session changed since the preview, the engine rejects with VERSION_DRIFT and you must re-run the preview. Responses return newTargetVersion for chaining.',
            },
            'vaEnd': {
              'type': 'string',
              'description':
                  'so_analyze(action=disasm) exclusive upper VA bound; window stops before it. Alternative to limit when isolating a branch region. Also accepts byteOffset+bytes relative to function start.',
            },
            'includePseudocode': {
              'type': 'boolean',
              'description':
                  'so_analyze(action=disasm) only. Default false for fast raw disassembly. Set true only when the current window needs Rizin pseudocode; use rz_decompile when pseudocode itself is the goal.',
            },
            'byteOffset': {
              'type': 'integer',
              'description':
                  'disasm byte offset from the function start VA; combined with bytes builds vaEnd automatically (arm64: 4 bytes per instruction).',
            },
            'bytes': {
              'type': 'integer',
              'description':
                  'Byte span to include after byteOffset in disasm windows.',
            },
            'consumerExclude': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'blutterAction=trace only. Substrings matched case-insensitively against consumer function/class/file to drop noisy third-party hits (e.g. pointycastle, rc2). Response returns top-level consumerClusters and highConfidenceConsumers; verify the first high-confidence consumer before applying filters.',
            },
            'compareToJobId': {
              'type': 'string',
              'description':
                  "blutterAction=diff only: jobId of the NEW package's analyze result to match against the current one.",
            },
            'classPrefix': {
              'type': 'string',
              'description':
                  'diff filter substring for old-side class/file/name; empty maps everything within limit.',
            },
            'minSimilarity': {
              'type': 'number',
              'description':
                  'diff anchor-set Jaccard threshold (default 0.45). Anchors are pooled-string references, rename-immune; re-disasm rows below ~0.8 before patching.',
            },
            'overrideAotObjectSafety': {
              'type': 'boolean',
              'description':
                  'Default false. Only set true when current disassembly proves the target uses a native scalar ABI rather than a Dart object/Smi. Raw MOV-immediate edits in Flutter/Dart AOT are otherwise previewed but blocked from apply.',
            },
            'limit': {
              'type': 'integer',
              'description': 'Max rows for list/read functions (default 100).',
            },
            'offset': {
              'type': 'integer',
              'description':
                  'Pagination offset (disasm instructionOffset / lists).',
            },
            'cursor': {
              'type': 'string',
              'description':
                  'Pagination cursor returned by the previous page (rz_functions/list/strings).',
            },
            'view': {
              'type': 'string',
              // F-54（2026-10-04）：文档与引擎对齐——list 实际支持七个视图，
              // 过去写「relocs 暂不支持」（字面 relocs 确实 INVALID_LOCATOR，
              // 但 relocations 可用），等于把手能用的能力挡掉。
              'description':
                  'action=list view: sections | symbols | dynsyms | functions | relocations | strings | imports (default sections). '
                      'Unknown view names return INVALID_LOCATOR with the view list.',
            },
            'prefix': {
              'type': 'string',
              'description': 'Name prefix filter (list_sources/list/strings).',
            },
            'query': {
              'type': 'string',
              'description':
                  'Search query. Blutter search accepts up to 16 related terms joined with | and scans them together, e.g. isVip|isMember|vipLevel. Never issue one full scan per synonym. Blutter numeric evidence: blutterAction=values with comma/slash-separated decimal or hex values, e.g. 5,55 or 0x5/0x37.',
            },
            'target': {
              'type': 'string',
              'description': 'Search target (action=search, default overview).',
            },
            'pattern': {
              'type': 'string',
              'description':
                  "Rizin byte pattern for rz_search_bytes: compact hex such as 5F2403D5, nibble wildcard using '.' such as 5F24..D5, optional bytes:mask; spaced hex and '??' are normalized for compatibility.",
            },
            'fromVa': {
              'type': 'string',
              'description':
                  'Hex start VA (rz_search_bytes, blank/0 = from beginning).',
            },
            'toVa': {
              'type': 'string',
              'description': 'Hex end VA (rz_search_bytes, blank/0 = to end).',
            },
            'direction': {
              'type': 'string',
              'description': 'to | from (rz_xrefs, default to).',
            },
            'command': {
              'type': 'string',
              'description':
                  'Raw rizin command (rz_command, unsafe=true required for dangerous ones).',
            },
            'unsafe': {
              'type': 'boolean',
              'description': 'Allow dangerous rizin commands (default false).',
            },
            'op': {
              'type': 'string',
              'description':
                  'Backend dispatch op. unidbg_dispatch: status | session_open(editSessionId,callJniOnLoad) | session_list | session_close | session_call | session_call_address | session_dump | session_modules | session_exports | session_registers | session_memory_maps | session_memory_write/map/protect/unmap | session_trace_code/start/events/stop/clear | session_hook_start/list/stop | session_breakpoint_add/remove | session_single_step | session_emu_stop | debugger_plan | trace_plan | breakpoints_plan | framework_matrix | stub/hook/env_template | batch. batch = run many dispatches in one call: method holds the step op, args[0] = {steps:[{op, method?, args?, workspaceId?, editSessionId?, resultKey?}]..., workspaceId?, stopOnError? (default true), maxSteps? (default 30, max 100)}. A step result is stored under its resultKey and later steps may reference it inside method/workspaceId/editSessionId/args strings as \${resultKey.dotted.path} (e.g. \${open.args[0]}). xanso_dispatch: status | help | capabilities. args[] carries each op positional arguments (e.g. session_call → [emulatorSessionId, symbolName, argsArray, trace]).',
            },
            'method': {
              'type': 'string',
              'description': 'Backend method (lief_dispatch/unidbg_dispatch).',
            },
            'args': {
              'type': 'array',
              'description': 'Backend/emulate call arguments (JSON array).',
            },
            'symbolName': {
              'type': 'string',
              'description':
                  'Function to emulate (emulate; JNI_OnLoad/Java_* supported).',
            },
            'trace': {
              'type': 'boolean',
              'description': 'Emulate with instruction trace (default false).',
            },
            'blutterAction': {
              'type': 'string',
              'enum': [
                'analyze',
                'inspect',
                'status',
                'result',
                'cancel',
                'packages',
                'search',
                'pool',
                'raw_strings',
                'values',
                'xref',
                'trace',
                'locate',
                'report',
                'callers',
                'diff',
                'disasm',
                'prune',
              ],
              'description':
                  'Standalone Blutter evidence actions. With an existing jobId, pool offset, function VA, value or saved report you may call report, search, pool, xref, trace, values, disasm, callers directly — no need to replay locate. '
                  'result reads the cached result.json view (REPORT_NOT_READY when absent); trace derives writes and same-offset reads from any field key. '
                  'BOUNDARY DISCIPLINE: every analyze reply declares capabilities.functionBoundaries and each reference a boundaryStatus. When it is unverified, locate/trace are REFUSED (BLUTTER_BOUNDARIES_UNVERIFIED) — do not retry or swap keywords; see allowUnverifiedBoundaries / poolOffset for the working route.',
            },
            'allowUnverifiedBoundaries': {
              'type': 'boolean',
              'description':
                  'blutterAction=locate/trace only, default false. Boundary evidence levels (from capabilities.functionBoundaries / refs[].boundaryStatus): verified = runner matched engine/snapshot exactly, artifact function sizes usable; inferred_next_header = artifact had no size (Dart-version fallback), interval derived from the next function header — usable but say "inferred" when reporting; unverified = no function header matched, functionVa is null, only va/verificationVa usable. When the job is unverified, locate/trace refuse with BLUTTER_BOUNDARIES_UNVERIFIED. Set true ONLY to accept inference-grade output; conclusions are then labelled (boundaryStatus/boundaryBasis) and must be reported as inferences, not artifact facts. The boundary-free route is poolOffset + so_analyze(action=disasm).',
            },
            'allowDeprecatedAction': {
              'type': 'boolean',
              // F-43（2026-10-04）：退役动作现在在**接受面**被无条件拒绝
              // （Dart 与 Kotlin 双层），这个开关不再能放行任何东西。
              'description':
                  'DEPRECATED/no-op (F-43): so_analyze actions known to be broken (capabilities, open_url, emulate, lief_*) are now refused at the acceptance surface with the reason and a working alternative — this flag cannot bypass that. Read the refusal for the replacement action.'
            },
            'async': {
              'type': 'boolean',
              'description':
                  'blutterAction=locate only. true = run locate in the background and return accepted immediately (recommended, avoids timeout lane cooldown). Retry the same async call to poll: stillRunning=true means unfinished; false (blutterAction=locate without async) reruns synchronously with warm caches.',
            },
            'jobId': {
              'type': 'string',
              'description':
                  'Blutter job id from a previous analyze (status/result/cancel/search/values/xref/locate; optional for search/values/xref/locate = latest succeeded).',
            },
            'wait': {
              'type': 'boolean',
              'description':
                  'action=blutter only. analyze always returns its background jobId immediately even when wait=true. status+wait=true returns on completion, failure, stage change, or a new heartbeat. Report progress before continuing with the same jobId.',
            },
            'timeoutMs': {
              'type': 'integer',
              'description':
                  'Maximum wait for one progress response, default 90000ms, clamped to 5000-90000. Calls normally return within one heartbeat instead of staying silent until completion. On timeout, reuse the same jobId with wait=true.',
            },
            'goal': {
              'type': 'string',
              'description':
                  'The user\'s goal for blutterAction=locate/values/trace. File names and numbers the user mentions are evidence hints only; locate/trace build data flow from real field writes and reads and never hard-code example names or values as rules. When the Blutter function body is missing, locate\'s rawDecisionFlow reads the current libapp bytes directly to connect text branches, compared values, call chains and the final return.',
            },
            'deep': {
              'type': 'boolean',
              'description':
                  'blutterAction=locate only. Default false always uses compact XREF + candidate-window verification and never starts a full semantic/value/field scan. Set true only when the fast result lacks enough evidence and a complete field-flow trace is explicitly needed. A saved report records the pipeline that produced it (reportGeneratedWith.deep): asking report with deep=true for a fast-pipeline snapshot returns REPORT_PIPELINE_MISMATCH instead of the stale snapshot — re-run locate with deep=true, re-issuing report alone will not recompute anything.',
            },
            'expandKeywords': {
              'type': 'boolean',
              'description':
                  'blutterAction=raw_strings only. Default false searches exactly the words you passed in query/goal. Set true to also expand them through the built-in keyword table (used to be the default, but it drowned a single query word under ~30 unrelated terms). The response echoes termsUsed either way.',
            },
            'includeNoisy': {
              'type': 'boolean',
              'description':
                  'blutterAction=raw_strings only. Default false hides hits that look like bulk word-list/symbol-table data (one long string matching several terms). Hidden hits are counted in noisyCount with noisyNote, never silently dropped; set true to get them back.',
            },
            'poolOffset': {
              'type': 'string',
              'description':
                  'Hex object-pool offset(s), e.g. 0xe890 or pp+0xe890. Multiple offsets may be comma-separated and are resolved in one pass. blutterAction=pool returns the ledger text plus neighbouring lines for each offset, and answers found=false explicitly when the offset is not in pp.txt — that is a decidable negative, so never fall back to grepping pp.txt to re-check it. Use xref for direct references, trace for key→field write→field readers, and callers to resolve Dart closure blr indirect calls when pp.txt does not expose the target Code VA.',
            },
            'scope': {
              'type': 'string',
              'description':
                  'blutterAction=search scope: pp (default) | asm | all. pp.txt is the complete string ledger (inverted index, sub-second) and is always searched first; for a default scope=all request with no asm-specific filter, pp hits replace the asm full-scan (huge APKs have thousands of function files — a full scan takes minutes). Explicit asm requests are never skipped: scope=asm, or scope=all with fullScan/includePath/excludePath/includeThirdParty set, always scans. asm/all automatically join matching object-pool strings with their indexed references in poolStringReferences; use that result before fullScan.',
            },
            'fullScan': {
              'type': 'boolean',
              'description':
                  'blutterAction=search with scope=asm/all only. Default false searches the compact semantic index. Use true only after an indexed search returns no match and raw non-semantic lines are genuinely required; combine related terms with | in one call.',
            },
            'includePath': {
              'type': 'string',
              'description':
                  'Blutter ASM search path/class include filter. Separate alternatives with |, for example DiaryState|package:my_app/. Apply this before a full scan to avoid third-party noise.',
            },
            'excludePath': {
              'type': 'string',
              'description':
                  'Blutter ASM search path/class exclude filter. Separate terms with |, for example archive|dio|extended_image.',
            },
            'includeThirdParty': {
              'type': 'boolean',
              'description':
                  'Blutter fullScan only. Default false skips common Dart/Flutter dependency folders for speed and signal quality. Set true only when the target is known to be inside a dependency.',
            },
            'kind': {
              'type': 'string',
              'enum': ['libraries', 'classes', 'functions', 'objects'],
              'description':
                  'Reference preview kind for blutterAction=result only. Never exhaust classes/functions/objects pages for analysis; use locate/search/xref/disasm. pp.txt is not a result kind.',
            },
            'report': {
              'type': 'string',
              'enum': ['membership', 'capture', 'ads'],
              'description':
                  'blutterAction=report only. Read the latest saved focused report without rerunning analysis.',
            },
            'includeEvidence': {
              'type': 'boolean',
              'description':
                  'blutterAction=locate only. Default false. Return large PP context and class outline only when a specific evidence dispute requires them; never enable for the first pass.',
            },
            'fullInventory': {
              'type': 'boolean',
              'description':
                  'blutterAction=result/packages only. For result, allow complete artifact inventory paging only when explicitly exporting. For packages, include one paged slice of the historical coverage matrix; the default compact response already includes runner health and coverage totals.',
            },
            'olderThanMillis': {
              'type': 'integer',
              'description':
                  'blutterAction=prune only. Age threshold in milliseconds, default 7 days. The default dryRun=true returns reclaimable job/result counts and bytes without deleting anything.',
            },
            'abi': {
              'type': 'string',
              'description': 'Target ABI (blutter, default auto).',
            },
            'addr': {
              'type': 'string',
              'description':
                  'Hex address (rz_asm / disasm / emulate_dump / blutterAction=callers). For emulate_dump this is the Unidbg RUNTIME absolute address: add the module base from unidbg_dispatch(op=session_modules) to the ELF VA, not the raw ELF VA. For callers: target function VA; it returns bl/b direct sites and matching pool-backed blr closure sites.',
            },
            'size': {
              'type': 'integer',
              'description': 'Byte size (emulate_dump default 256).',
            },
            'maxBytes': {
              'type': 'integer',
              'description':
                  'Max bytes to read (hexdump default 512 / disasm 4096).',
            },
            'label': {
              'type': 'string',
              'description': 'Snapshot label (edit_snapshot).',
            },
            'snapshotIndex': {
              'type': 'integer',
              'description':
                  'Snapshot to roll back to (edit_rollback, -1=latest).',
            },
            'snapshotId': {
              'type': 'string',
              'description':
                  'Stable snapshot id returned by edit_snapshot or audit; preferred over snapshotIndex for edit_rollback.',
            },
            'compareWorkspaceId': {
              'type': 'string',
              'description': 'Other workspace for action=diff (optional).',
            },
            'compareSessionId': {
              'type': 'string',
              'description': 'Other edit session for action=diff (optional).',
            },
            'count': {
              'type': 'integer',
              'description':
                  'Undo/redo step count (edit_undo/edit_redo, default 1).',
            },
            'outputName': {
              'type': 'string',
              'description':
                  'Output file name (action=build, default patched.so).',
            },
            'conflictStrategy': {
              'type': 'string',
              'description': 'Build output conflict strategy (default rename).',
            },
            'force': {
              'type': 'boolean',
              'description':
                  'xanso_build_sections: rebuild even when a parseable section table already exists (default false).',
            },
            'strict': {
              'type': 'boolean',
              'description':
                  'rz_decompile: fail when rizin-ghidra pseudocode is unavailable instead of falling back to plain disassembly (default true).',
            },
            'ignoreCase': {
              'type': 'boolean',
              'description':
                  'strings: case-insensitive prefix/regex matching (default true).',
            },
            'minConfidence': {
              'type': 'number',
              'description':
                  'strings: minimum string confidence in [0,1]; raise to drop noisy UTF-16 candidates.',
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.workspacePolicy)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.workspacePolicy,
        'description':
            'Read the current workspace policy before touching paths: the bound work directory, the read-only original APK, which tools need explicit user authorisation, the preview contract and the result size caps. Call once when a task starts or after switching workspaces instead of discovering the rules from errors. Pass includeToolStats=true to also return the engine-side per-tool timing snapshot (call counts, avg/max ms) when performance data is needed.',
        'parameters': {
          'type': 'object',
          'properties': <String, dynamic>{
            'includeToolStats': <String, dynamic>{
              'type': 'boolean',
              'description':
                  'Also return the engine-side per-tool timing snapshot (counts, avg/max ms, recent samples) for performance work. Read-only; empty when stats collection is off.',
            },
            // F-52（2026-10-04）：过滤器必须挂在**产出方**（get_workspace_policy）
            // 上——上一批误加进 so_analyze 的 schema，实测该参数不生效。
            'toolStatsFilter': <String, dynamic>{
              'type': 'string',
              'description':
                  'Only with includeToolStats=true. Filter the toolStats payload: '
                  'none = omit the stats detail; failures_only = keep only tools with failed>0; '
                  'top = top 10 by p95. Omit for the full snapshot.',
              'enum': ['none', 'failures_only', 'top'],
            },
          },
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.file)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.file,
        'description':
            'Unified file operations in the work directory. Call action=inventory to get this conversation\'s live work directory (its root entries include ALL files physically present there — user-added notes like .md, logs, builds — not just tracked artifacts), report source, active APK, SO output and artifact paths without searching. Every entry is stat-checked, so deleted outputs are marked missing. To read any listed file use action=read with its path; for several files use action=read with paths:[...] (batch, cap 8) instead of looping single reads. Read-class actions (inventory/read/list/info/grep/strings) are read-only and may be called concurrently with other read calls. Use list for subdirectories. '
            'Blutter pp.txt, JSONL and asm dumps are reference artifacts. Never read them page by page. For a Blutter pool offset the right tool is so_analyze(action=blutter, blutterAction=pool, poolOffset=0x...) — it returns the ledger text and answers found=false explicitly; grep is the fallback for free-text targets only. '
            'GREP HONESTY: a grep reply always says whether it actually searched. searchPerformed=false means no file was read, so count=0 is NOT evidence that the pattern is absent — inspect skipped[] (reason size_exceeds_limit → raise maxFileBytes; non_text_or_binary → set forceText=true) and re-run before drawing any conclusion. Paths must be INSIDE the work directory; bare names are resolved against it.',
        'parameters': {
          'type': 'object',
          'properties': {
            'action': {
              'type': 'string',
              'enum': [
                'inventory',
                'read',
                'write',
                'list',
                'info',
                'delete',
                'copy',
                'diff',
                'mkdir',
                'rename',
                'move',
                'zip',
                'unzip',
                'grep',
                'replace',
                'strings',
              ],
              'description':
                  'inventory returns the live per-conversation artifact ledger; otherwise performs the selected file operation. '
                  'move is a DECLARED alias of rename (same implementation — the underlying rename relocates across directories too). The reply echoes back the action you wrote and adds normalizedTo when the two differ, so the normalization is never silent. '
                  'Write-class actions (write/delete/copy/rename/move/zip/unzip/replace) default to dryRun=true: pass dryRun=false to actually apply. '
                  'grep/replace read `path` (+ recursive for directories); zip reads `path` + `output`; '
                  'unzip target directory is outputDir (default <zip name>/ next to the archive). '
                  'read/write `limit: 0` means unlimited (no clamp).',
            },
            'path': {
              'type': 'string',
              'description':
                  'Target path (file or directory) in the work directory. When it points to an APK/ZIP file, action=list returns the archive entry listing (name/size/compressedSize/modified) instead of a directory listing.',
            },
            'paths': {
              'type': 'array',
              'items': {'type': 'string'},
              'description':
                  'Batch read: with action=read, up to 8 paths read in ONE call (offset/limit apply to every file). Each item returns its own result object; a missing file stays as an error entry without aborting the batch. Use this instead of looping single reads.',
            },
            'entryPrefix': {
              'type': 'string',
              'description':
                  'Optional name-prefix filter for action=list on APK/ZIP archives (e.g. dex/, res/, lib/arm64-v8a/).',
            },
            'sourcePath': {
              'type': 'string',
              'description': 'Source path for copy/rename/diff.',
            },
            'targetPath': {
              'type': 'string',
              'description': 'Target path for copy/rename/diff.',
            },
            'context': {
              'type': 'integer',
              'description':
                  'Context lines around changes for diff (default 3, max 16).',
            },
            'content': {'type': 'string', 'description': 'Content for write.'},
            'contentEncoding': {
              'type': 'string',
              'enum': ['utf8', 'base64', 'hex'],
              'description':
                  'Encoding of content for write (default utf8). base64/hex enable binary writes; read returns hexPreview for binary files.',
            },
            'pattern': {
              'type': 'string',
              'description': 'Regex pattern for grep/replace.',
            },
            'include': {
              'type': 'string',
              'description':
                  'action=grep/replace only. Optional comma-separated file-extension filter without dots, e.g. "dart,java,xml"; empty/omitted means no filtering. Applied while walking a directory, so it also bounds how many files are read.',
            },
            'maxFileBytes': {
              'type': 'integer',
              'description':
                  'action=grep only. Per-file size ceiling in bytes (default 512MB, max 2GB). Large reference ledgers (Blutter pp.txt/objs.txt) can exceed it; an over-limit file is skipped and listed in skipped[] with reason size_exceeds_limit. count=0 with searchPerformed=false is NOT evidence of absence — raise this and re-run before concluding anything.',
            },
            'forceText': {
              'type': 'boolean',
              'description':
                  'action=grep only. Default false runs a text probe (a NUL byte in the first 4096 bytes rejects the file as binary). Set true to grep a file the probe rejected; skipped files are listed with reason non_text_or_binary. This, not a re-run with another tool, is how you search a large ledger that grep refused.',
            },
            'query': {
              'type': 'string',
              'description':
                  'Optional case-insensitive filter for action=strings.',
            },
            'encoding': {
              'type': 'string',
              'enum': ['auto', 'utf8', 'utf16le', 'utf16be'],
              'description':
                  'Binary string encoding for action=strings (default auto).',
            },
            'minLength': {
              'type': 'integer',
              'description':
                  'Minimum extracted string length for action=strings (default 3).',
            },
            'find': {
              'type': 'string',
              'description': 'Text to find for replace.',
            },
            'replacement': {
              'type': 'string',
              'description': 'Replacement text for replace.',
            },
            'offset': {
              'type': 'integer',
              'description':
                  'Text: 0-based start line. Binary: start byte offset. APK/ZIP list: entry offset (default 0, every offset reachable).',
            },
            'limit': {
              'type': 'integer',
              'description':
                  'Text: max lines. Binary: max bytes. List: max entries (directory default 200, archive default 200).',
            },
            'dryRun': {
              'type': 'boolean',
              'description':
                  'true to preview write/delete/copy/rename/zip/replace/mkdir (default true). mkdir is included: dryRun=true returns wouldCreate=true and touches nothing, so pass dryRun=false to actually create the directory.',
            },
            'recursive': {
              'type': 'boolean',
              'description': 'Recursive for delete.',
            },
            'overwrite': {
              'type': 'boolean',
              'description': 'Overwrite target for copy/rename.',
            },
            'output': {
              'type': 'string',
              'description': 'Output zip path for zip.',
            },
            'outputDir': {
              'type': 'string',
              'description':
                  'Target directory for unzip (default: a directory named after the archive, next to it).',
            },
          },
          'required': ['action'],
        },
      },
    });
  }
  if (assistant.localToolIds.contains(LocalToolNames.routeTask)) {
    tools.add(const {
      'type': 'function',
      'function': {
        'name': LocalToolNames.routeTask,
        'description':
            'Evidence-route advisor, not a pipeline runner. It returns independently usable DEX, Flutter, native, resource and artifact probes with conflict-resolution rules; recommended/preferred tools are candidates, never mandatory steps. With an exact locator you may skip route_task and verify directly. After it returns, pick the next tool by discriminating power — do not follow the order mechanically.',
        'parameters': {
          'type': 'object',
          'properties': {
            'goal': {
              'type': 'string',
              'description': 'The user request in their own words.',
            },
          },
          'required': ['goal'],
        },
      },
    });
  }
  // 运行时控制面（§7.4 核心控制）：schema 直接取运行时自己的 defs，
  // **单一来源**，不在工具面再抄第二份（抄一份就必然漂移：声明与分派）。
  // route_task 已在上方单独声明（它另有专门 handler 与检查点语义），跳过。
  for (final def in RuntimeTools.defs) {
    if (def.name == LocalToolNames.routeTask) continue;
    if (!assistant.localToolIds.contains(def.name)) continue;
    tools.add(<String, dynamic>{
      'type': 'function',
      'function': {
        'name': def.name,
        'description': def.description,
        'parameters': def.parameters,
      },
    });
  }
  // SO 全域工具归口 so_analyze（40+ action）；外部原名别名已下线（U11）。
  // analyzer.* 由 AnalyzerToolNames 独立管理（不在 LocalToolRegistry），
  // 过滤必须放行，否则追加的声明在 return 前被 registeredToolIds 吞掉。
  // 声明输出的是发布名 analyzer_open（点号名被严格网关拒绝），放行前缀
  // 相应匹配 analyzer_。
  return tools
      .where((tool) {
        final name = (tool['function'] as Map)['name'].toString();
        return registeredToolIds.contains(name) ||
            name.startsWith('analyzer_') ||
            // 设备工具（定位/天气/健康/提醒）不登记在注册表里，见上方装配段。
            DeviceLocalToolSchemas.definitionFor(name) != null;
      })
      .toList(growable: false);
}
