import 'dart:convert';

import 'package:flutter/foundation.dart';

/// 在 Linux 沙盒里跑一条命令的结果。
class FridaExecResult {
  const FridaExecResult({required this.exitCode, this.stdout = '', this.stderr = ''});

  final int exitCode;
  final String stdout;
  final String stderr;

  bool get ok => exitCode == 0;
}

/// 沙盒执行口（可注入：单测里用假的，生产里走 workspace runtime 的 run()）。
typedef FridaExec = Future<FridaExecResult> Function(
  String command, {
  int timeoutMs,
});

/// Frida P2：运行期驱动（宿主侧注入 gadget，沙盒侧 python frida 连接）。
///
/// 为什么客户端放沙盒：PRoot 与设备共享网络命名空间，沙盒里的 127.0.0.1 就是
/// 设备 loopback，能直连目标进程里 gadget 监听的端口；而 frida-server 路线需要
/// ptrace 外部进程，在 PRoot 下不可行（见 docs/架构方向-能力双边分配与Frida接入.md）。
class FridaSandboxRuntime {
  FridaSandboxRuntime({required this.exec});

  final FridaExec exec;

  static const String guestDir = '/tmp';
  static const String driverPath = '$guestDir/solab_frida_driver.py';
  static const String specPath = '$guestDir/solab_frida_spec.json';
  static const String defaultHost = '127.0.0.1:27042';
  static const int defaultWaitMs = 1500;

  /// 运行期动作需要 python + frida 包（Linux 沙盒装了 python 依赖后才有）。
  Future<Map<String, dynamic>> run(
    String action,
    Map<String, dynamic> args,
  ) async {
    final host = (args['host']?.toString().trim().isNotEmpty ?? false)
        ? args['host'].toString().trim()
        : defaultHost;

    final probe = await exec('python3 -c "import frida"', timeoutMs: 30000);
    if (!probe.ok) {
      if ((probe.stderr + probe.stdout).contains('ModuleNotFoundError') ||
          (probe.stderr + probe.stdout).contains('No module named')) {
        final install = await exec(
          'python3 -m pip install --quiet --disable-pip-version-check frida',
          timeoutMs: 240000,
        );
        if (!install.ok) {
          return _error(
            'FRIDA_CLIENT_INSTALL_FAILED',
            '沙盒里装不上 frida 客户端：${_tail(install.stderr)}',
            next: '先在「工作区 → 依赖」装好 Python，或手动在沙盒里 pip install frida',
          );
        }
      } else {
        return _error(
          'environment_not_ready',
          '沙盒里没有可用的 python3：${_tail(probe.stderr)}',
          next: '先在设置里安装 Linux 环境与 Python 依赖',
        );
      }
    }

    final source = _sourceFor(action, args);
    if (source == null) {
      return _error(
        'invalid_arguments',
        'frida(action=$action) 缺少必要参数'
            '${action == 'hook' ? '（hook 需要 script）' : ''}',
      );
    }
    final spec = <String, dynamic>{
      'action': action,
      'host': host,
      'target': args['target']?.toString() ?? 'Gadget',
      'source': source,
      'waitMs': (args['waitMs'] as num?)?.toInt() ?? defaultWaitMs,
      if (args['rpc'] is Map) 'rpc': args['rpc'],
    };
    if (args['rpcName'] != null) {
      spec['rpc'] = <String, dynamic>{
        'name': args['rpcName'].toString(),
        'args': args['rpcArgs'] is List ? args['rpcArgs'] : const <dynamic>[],
      };
    }

    final write = await exec(_writeCommand(driverPath, _driverScript), timeoutMs: 30000);
    if (!write.ok) {
      return _error('FRIDA_DRIVER_WRITE_FAILED', '写驱动脚本失败：${_tail(write.stderr)}');
    }
    final writeSpec = await exec(
      _writeCommand(specPath, jsonEncode(spec)),
      timeoutMs: 30000,
    );
    if (!writeSpec.ok) {
      return _error('FRIDA_SPEC_WRITE_FAILED', '写调用参数失败：${_tail(writeSpec.stderr)}');
    }

    final timeoutMs = ((spec['waitMs'] as int) + 60000).clamp(60000, 300000);
    final result = await exec(
      'python3 $driverPath $specPath',
      timeoutMs: timeoutMs,
    );
    if (!result.ok) {
      return _error(
        'FRIDA_RUN_FAILED',
        _tail(result.stderr).isEmpty ? 'frida 驱动退出码 ${result.exitCode}' : _tail(result.stderr),
        next: '确认目标已安装并启动注入版（frida(action=inject) + apk_sign 后安装），'
            '且 gadget 正在监听 $host',
      );
    }
    final payload = _lastJsonLine(result.stdout);
    if (payload == null) {
      return _error('FRIDA_BAD_OUTPUT', 'frida 驱动没有输出 JSON：${_tail(result.stdout)}');
    }
    if (payload['ok'] != true) {
      return _error(
        payload['error']?.toString() ?? 'FRIDA_ACTION_FAILED',
        payload['message']?.toString() ?? 'frida 动作失败',
      );
    }
    return <String, dynamic>{
      'ok': true,
      'action': action,
      'host': host,
      ...payload,
    };
  }

  static String _writeCommand(String path, String content) {
    final encoded = base64Encode(utf8.encode(content));
    return "printf '%s' '$encoded' | base64 -d > $path";
  }

  static Map<String, dynamic>? _lastJsonLine(String stdout) {
    final lines = stdout.trim().split('\n');
    for (final line in lines.reversed) {
      final trimmed = line.trim();
      if (!trimmed.startsWith('{')) continue;
      try {
        final decoded = jsonDecode(trimmed);
        if (decoded is Map) return Map<String, dynamic>.from(decoded);
      } catch (_) {
        // 驱动可能打了日志行，继续往前找。
      }
    }
    return null;
  }

  static String _tail(String value) {
    final trimmed = value.trim();
    if (trimmed.length <= 400) return trimmed;
    return '…${trimmed.substring(trimmed.length - 400)}';
  }

  static Map<String, dynamic> _error(
    String code,
    String message, {
    String? next,
  }) =>
      <String, dynamic>{
        'ok': false,
        'error': <String, dynamic>{
          'code': code,
          'message': message,
        },
        if (next != null) 'nextActions': <String>[next],
      };

  /// 每个动作对应的 JS 片段（rpc 名与 spec.rpc.name 对齐）。
  static String? _sourceFor(String action, Map<String, dynamic> args) {
    switch (action) {
      case 'open':
      case 'close':
        return "rpc.exports.ping = function () { return 'pong'; };";
      case 'hook':
        final script = args['script']?.toString() ?? '';
        return script.trim().isEmpty ? null : script;
      case 'call':
        return 'rpc.exports.call = function (name, argList) {\n'
            '  var address = Module.findExportByName(null, name);\n'
            '  if (address === null) { return null; }\n'
            "  var fn = new NativeFunction(address, 'pointer', ['pointer','pointer','pointer','pointer']);\n"
            '  var list = (argList || []).map(function (item) {\n'
            "    if (typeof item === 'string' && item.indexOf('0x') === 0) { return ptr(item); }\n"
            "    if (typeof item === 'string') { return Memory.allocUtf8String(item); }\n"
            '    return item;\n'
            '  });\n'
            '  while (list.length < 4) { list.push(ptr(0)); }\n'
            '  return fn(list[0], list[1], list[2], list[3]).toString();\n'
            '};';
      case 'read':
        return 'rpc.exports.read = function (address, size) {\n'
            '  return hexdump(ptr(address), { length: size | 0 });\n'
            '};';
      case 'backtrace':
        return 'rpc.exports.backtrace = function () {\n'
            '  return Thread.backtrace(this.context || null, Backtracer.ACCURATE)\n'
            '    .map(DebugSymbol.fromAddress).join("\\n");\n'
            '};';
      default:
        return null;
    }
  }

  /// 沙盒侧驱动：读 spec JSON → 连 gadget → 载入 JS → 可选调用 rpc → 回一行 JSON。
  static const String _driverScript = r'''
import json
import sys
import time


def main():
    with open(sys.argv[1], 'r', encoding='utf-8') as handle:
        spec = json.load(handle)
    import frida

    device = frida.get_device_manager().add_remote_device(spec.get('host') or '127.0.0.1:27042')
    session = device.attach(spec.get('target') or 'Gadget')
    events = []
    script = session.create_script(spec.get('source') or '')
    script.on('message', lambda message, data: events.append(message))
    script.load()
    out = {'ok': True, 'device': str(device)}
    rpc = spec.get('rpc') or {}
    name = rpc.get('name')
    if name:
        exports = getattr(script, 'exports_sync', None)
        if exports is None:
            exports = getattr(script, 'exports', None)
        fn = getattr(exports, name, None) if exports is not None else None
        if fn is None:
            out = {'ok': False, 'error': 'rpc_missing', 'message': 'rpc %s not found' % name}
        else:
            out['result'] = fn(*(rpc.get('args') or []))
    wait_ms = int(spec.get('waitMs') or 0)
    if wait_ms > 0 and out.get('ok'):
        time.sleep(wait_ms / 1000.0)
    out['events'] = events[:200]
    try:
        session.detach()
    except Exception:
        pass
    print(json.dumps(out, ensure_ascii=False))


if __name__ == '__main__':
    main()
''';

  /// 供状态动作展示：沙盒侧依赖是否就绪。
  Future<Map<String, dynamic>> clientStatus() async {
    final probe = await exec('python3 -c "import frida; print(frida.__version__)"', timeoutMs: 30000);
    if (!probe.ok) {
      return <String, dynamic>{
        'sandboxClient': false,
        'sandboxClientError': _tail(probe.stderr).isEmpty ? 'python3/frida 不可用' : _tail(probe.stderr),
      };
    }
    return <String, dynamic>{
      'sandboxClient': true,
      'sandboxFridaVersion': probe.stdout.trim().split('\n').last.trim(),
    };
  }
}

/// 便于日志排查：驱动脚本长度（避免把整段脚本打出来）。
int get fridaDriverScriptLength => FridaSandboxRuntime._driverScript.length;

/// 让 debugPrint 在测试里也能看到关键信息。
void logFridaDebug(String message) => debugPrint('frida: $message');
