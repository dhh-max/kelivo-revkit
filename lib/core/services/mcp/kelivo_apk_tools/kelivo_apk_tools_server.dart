import 'dart:convert';
import 'dart:io';
import 'package:flutter/services.dart' show rootBundle;
import 'package:mcp_client/mcp_client.dart' as mcp;
import '../in_memory_mcp_server.dart';

/// @kelivo/apk-tools — In-memory MCP server bundling the APK reverse
/// toolchain (56.al 在线脱壳 / LogFox 日志工具 / 加固特征库) as first-class
/// Operit package resources embedded in the SO 2.5 APK.
///
/// The three .js tool packages live under `assets/apk_tools/` and are the
/// same artifacts Operit's package loader expects. This engine does NOT
/// execute them (SO has no JS runtime); it exposes them for inspection and
/// one-tap export to the user's Operit package directory.
///
/// Tools:
/// - apk_tools_list    → list bundled tool packages (name, size, summary)
/// - apk_tools_read    → return full .js source or README / rolecard metadata
/// - apk_tools_export  → copy bundle to a target directory (default
///                       /sdcard/Download/APK逆向工具/)
/// - apk_tools_help    → short usage guide in Chinese
class KelivoApkToolsMcpServerEngine implements KelivoInMemoryMcpServerEngine {
  bool _closed = false;

  /// Asset root inside the APK (registered in pubspec.yaml).
  static const String _assetDir = 'assets/apk_tools';

  /// Canonical file names inside the bundle. Chinese originals renamed to
  /// ASCII so [rootBundle] can address them deterministically on all
  /// platforms.
  static const Map<String, String> _tools = {
    '56al_tuoke': '56al_tuoke.js',
    'logfox_toolkit': 'logfox_toolkit.js',
    'hardening_db': 'hardening_db.js',
  };
  static const String _readmeAsset = 'README.md';
  static const String _rolecardAsset = 'rolecard.png';

  /// Default export directory the user can then feed to Operit's package
  /// loader (or read from any file manager).
  static const String _defaultExportDir =
      '/sdcard/Download/APK逆向工具';

  /// Mapping from ASCII bundle filename to the original Chinese name, used
  /// when exporting so the user sees the original tool names.
  static const Map<String, String> _displayName = {
    '56al_tuoke.js': '56al在线脱壳.js',
    'logfox_toolkit.js': 'logfox日志工具.js',
    'hardening_db.js': '加固特征库.js',
    'README.md': '安装说明.txt',
    'rolecard.png': '逆向助手.png',
  };

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

  @override
  void close() {
    _closed = true;
  }

  Future<Map<String, dynamic>> _handleSingle(dynamic raw) async {
    try {
      if (raw is! Map) return _error(null, code: -32600, message: 'Invalid Request');
      final req = raw.cast<String, dynamic>();
      final id = req['id'];
      final method = (req['method'] ?? '').toString();
      final params = (req['params'] is Map)
          ? (req['params'] as Map).cast<String, dynamic>()
          : <String, dynamic>{};

      switch (method) {
        case mcp.McpProtocol.methodInitialize:
          return _ok(id, result: {
            'serverInfo': {'name': '@kelivo/apk-tools', 'version': '1.0.0'},
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
        case 'apk_tools_list':
          return await _list();
        case 'apk_tools_read':
          return await _read(args);
        case 'apk_tools_export':
          return await _export(args);
        case 'apk_tools_help':
          return _text('apk_tools', _helpText());
        default:
          return _error(null, code: -32602, message: 'Unknown tool: $name');
      }
    } catch (e) {
      return _error(null, code: -32603, message: '$e');
    }
  }

  // ---- tool: apk_tools_list ------------------------------------------------

  Future<Map<String, dynamic>> _list() async {
    final entries = <Map<String, dynamic>>[];
    for (final entry in _tools.entries) {
      final key = entry.key;
      final file = entry.value;
      final meta = await _readMetadata(file);
      entries.add({
        'id': key,
        'file': file,
        'display_name': _displayName[file] ?? file,
        'description': meta['description'] ?? '',
        'tools': meta['tools'] ?? <String>[],
        'size_bytes': meta['size_bytes'] ?? 0,
      });
    }
    return {
      'success': true,
      'data': {
        'bundle': 'APK 逆向工具包 v11.1',
        'asset_dir': _assetDir,
        'count': entries.length,
        'packages': entries,
        'extras': [
          {'file': _rolecardAsset, 'display_name': '逆向助手.png', 'kind': 'rolecard'},
          {'file': _readmeAsset, 'display_name': '安装说明.txt', 'kind': 'readme'},
        ],
      },
    };
  }

  // ---- tool: apk_tools_read -----------------------------------------------

  Future<Map<String, dynamic>> _read(Map<String, dynamic> args) async {
    final key = (args['package'] ?? args['id'] ?? '').toString().trim();
    if (key.isEmpty) {
      return _error(null, code: -32602, message: 'Missing "package" (56al_tuoke | logfox_toolkit | hardening_db | README | rolecard)');
    }
    String? asset;
    if (key == 'README' || key == 'readme') {
      asset = _readmeAsset;
    } else if (key == 'rolecard') {
      asset = _rolecardAsset;
    } else {
      final mapped = _tools[key];
      if (mapped == null) {
        return _error(null, code: -32602, message: 'Unknown package: $key');
      }
      asset = mapped;
    }

    if (asset == _rolecardAsset) {
      final bytes = await rootBundle.load('$_assetDir/$asset');
      return {
        'success': true,
        'data': {
          'id': 'rolecard',
          'display_name': _displayName[asset] ?? asset,
          'kind': 'rolecard_image',
          'size_bytes': bytes.lengthInBytes,
          'base64': base64.encode(bytes.buffer.asUint8List()),
          'note': 'PNG 角色卡，含完整「APK 逆向破解助手」提示词。可在 Operit 角色卡管理里导入。',
        },
      };
    }

    final source = await rootBundle.loadString('$_assetDir/$asset');
    return {
      'success': true,
      'data': {
        'id': key == 'README' ? 'README' : key,
        'display_name': _displayName[asset] ?? asset,
        'kind': asset.endsWith('.js') ? 'package_source' : 'readme',
        'size_bytes': utf8.encode(source).length,
        'content': source,
      },
    };
  }

  // ---- tool: apk_tools_export ---------------------------------------------

  Future<Map<String, dynamic>> _export(Map<String, dynamic> args) async {
    final outDir = (args['output_dir'] ?? '').toString().trim();
    final target = outDir.isEmpty ? _defaultExportDir : outDir;

    final dir = Directory(target);
    if (!dir.existsSync()) {
      dir.createSync(recursive: true);
    }

    final written = <String>[];
    final skipped = <String>[];

    for (final file in _displayName.keys) {
      final display = _displayName[file]!;
      try {
        final targetPath = '${dir.path}/$display';
        if (file == _rolecardAsset) {
          final bytes = await rootBundle.load('$_assetDir/$file');
          await File(targetPath).writeAsBytes(
            bytes.buffer.asUint8List(),
            flush: true,
          );
        } else {
          final source = await rootBundle.loadString('$_assetDir/$file');
          await File(targetPath).writeAsString(source, flush: true);
        }
        written.add(targetPath);
      } catch (e) {
        skipped.add('$display: $e');
      }
    }

    return {
      'success': skipped.isEmpty,
      'data': {
        'target_dir': target,
        'written': written,
        'skipped': skipped,
        'hint': skipped.isEmpty
            ? '已将 5 个文件（3 个 .js + 角色卡 PNG + 安装说明）导出到 $target。'
                '如需 Operit 识别，请把 $target 下 3 个 .js 复制到 '
                '/storage/emulated/0/Android/data/com.ai.assistance.operit/files/packages/ 后重启 Operit。'
            : '部分文件导出失败，见 skipped。',
      },
    };
  }

  // ---- tool: apk_tools_help ----------------------------------------------

  String _helpText() => '''
APK 逆向工具包 · 内置说明
=========================

本 App 内置 3 个 Operit 侧工具包（.js），随 APK 分发，无需再单独下载。

■ 56al_tuoke（脱壳修复）—— tuoke_all / tuoke_upload / tuoke_status / tuoke_download
   上传 APK 到 56.al 云脱壳 → 下载 7z → 解压 → dexlib2 修复 dex 头。
   首次使用：tuoke_login_url → 浏览器登录 → tuoke_set_cookie。
■ logfox_toolkit（日志/崩溃分析）—— log_read_crash / log_analyze_anr / apk_launch_test
   logcat 后台录制、Java/Native/libc 崩溃解析、ANR 分析、APK 启动冒烟。
■ hardening_db（加固特征库）—— identify_by_stub / identify_by_feature / identify_combined
   内置 49 种加固壳的桩类/lib/assets 特征，按桩类或特征文件查壳型与处置路线。

配套资源：逆向助手.png（角色卡，含完整逆向提示词）。

使用方式：
1. 调用 apk_tools_export 把 5 个文件导出到本地目录（默认 /sdcard/Download/APK逆向工具/）。
2. 手动把 3 个 .js 复制到 Operit 的包目录：
   /storage/emulated/0/Android/data/com.ai.assistance.operit/files/packages/
3. 重启 Operit，包管理器识别后激活即可。
4. 在 Operit 角色卡管理里导入逆向助手.png，设为活跃角色。

SO 2.5 内本引擎不提供 JS 执行；它只做资源读取与导出。实际工具调用发生在 Operit 侧。
''';

  // ---- helpers -------------------------------------------------------------

  /// Parse the METADATA comment block at the top of a tool package .js and
  /// return a summary map (display name, description, tool names, size).
  Future<Map<String, dynamic>> _readMetadata(String file) async {
    final source = await rootBundle.loadString('$_assetDir/$file');
    final data = <String, dynamic>{
      'size_bytes': utf8.encode(source).length,
      'description': '',
      'tools': <String>[],
    };
    final start = source.indexOf('METADATA');
    if (start < 0) return data;
    // The JSON block is enclosed by /* METADATA ... */.
    final bodyStart = source.indexOf('\n', start) + 1;
    final bodyEnd = source.indexOf('*/', bodyStart);
    if (bodyEnd < 0) return data;
    final jsonText = source.substring(bodyStart, bodyEnd).trim();
    try {
      final meta = json.decode(jsonText);
      if (meta is Map) {
        data['display_name'] = _displayName[file] ?? meta['name'];
        data['description'] = _stringify(meta['description']);
        final tools = meta['tools'];
        if (tools is List) {
          for (final t in tools) {
            if (t is Map && t['name'] != null) {
              data['tools']!.add(t['name'].toString());
            }
          }
        }
      }
    } catch (_) {
      // Metadata malformed; return what we have.
    }
    return data;
  }

  String _stringify(Object? v) {
    if (v == null) return '';
    if (v is String) return v;
    if (v is Map) {
      final zh = v['zh'];
      if (zh is String) return zh;
      final en = v['en'];
      if (en is String) return en;
      return v.toString();
    }
    return v.toString();
  }

  Map<String, dynamic> _text(String name, String content) => {
        'content': [
          {'type': 'text', 'text': content},
        ],
      };

  Map<String, dynamic> _ok(dynamic id, {required Object result}) => {
        'jsonrpc': '2.0',
        'id': id,
        'result': result,
      };

  Map<String, dynamic> _noop() => {'jsonrpc': '2.0'};

  Map<String, dynamic> _error(dynamic id, {required int code, required String message}) => {
        'jsonrpc': '2.0',
        'id': id,
        'error': {'code': code, 'message': message},
      };

  // ---- tool definitions ---------------------------------------------------

  List<Map<String, dynamic>> _toolDefinitions() => [
        {
          'name': 'apk_tools_list',
          'description': '列出内置 APK 逆向工具包（56al_tuoke / logfox_toolkit / hardening_db）的名称、描述、工具清单与大小。',
          'inputSchema': {
            'type': 'object',
            'properties': <String, dynamic>{},
          },
        },
        {
          'name': 'apk_tools_read',
          'description': '读取工具包完整内容。package 取值：56al_tuoke | logfox_toolkit | hardening_db | README | rolecard。rolecard 返回 base64 PNG。',
          'inputSchema': {
            'type': 'object',
            'properties': {
              'package': {
                'type': 'string',
                'description': '包 id：56al_tuoke / logfox_toolkit / hardening_db / README / rolecard',
              },
            },
            'required': ['package'],
          },
        },
        {
          'name': 'apk_tools_export',
          'description': '把 3 个 .js + 角色卡 PNG + 安装说明 5 个文件一次性导出到本地目录（默认 /sdcard/Download/APK逆向工具/），使用原始中文文件名。导出后可手动复制到 Operit 的 packages 目录。',
          'inputSchema': {
            'type': 'object',
            'properties': {
              'output_dir': {
                'type': 'string',
                'description': '输出目录，默认 /sdcard/Download/APK逆向工具/',
              },
            },
          },
        },
        {
          'name': 'apk_tools_help',
          'description': '中文使用说明：三个工具包用途、导出步骤、Operit 包目录位置。',
          'inputSchema': {
            'type': 'object',
            'properties': <String, dynamic>{},
          },
        },
      ];
}
