part of kelivo_reverse_server;

// =========================================================================
// ADB 设备交互 — 封装 adb 命令行
// 移植自 Python apk_reverse_engine/device/adb.py
// =========================================================================

class _Adb {
  final String? deviceId;
  _Adb([this.deviceId]);

  String get _pre => deviceId != null && deviceId!.isNotEmpty
      ? '-s $deviceId'
      : '';

  Future<String> _run(String cmd, {int timeoutSec = 30}) async {
    final result = await Process.run(
      'sh',
      ['-c', cmd],
      runInShell: true,
    );
    if (result.exitCode != 0) {
      throw RuntimeError('ADB error: ${result.stderr.toString().trim() || result.stdout.toString().trim()}');
    }
    return result.stdout.toString().trim();
  }

  String _shellEscape(String s) {
    return s.replaceAll(' ', '%s').replaceAll('"', '\\"').replaceAll("'", "\\'");
  }

  // ---- 设备管理 ----
  Future<List<Map<String, String>>> devices() async {
    final r = await _run('adb devices -l');
    final out = <Map<String, String>>[];
    for (final line in r.split('\n')) {
      if (line.contains('\tdevice')) {
        final parts = line.split(RegExp(r'\s+'));
        out.add({
          'id': parts[0],
          'desc': parts.length > 2 ? parts.sublist(2).join(' ') : '',
        });
      }
    }
    return out;
  }

  Future<String> connect({String host = '127.0.0.1', int port = 5555}) async {
    return _run('adb connect $host:$port');
  }

  Future<String> disconnect() async {
    final cmd = deviceId != null && deviceId!.isNotEmpty
        ? 'adb disconnect $deviceId'
        : 'adb disconnect';
    return _run(cmd);
  }

  Future<Map<String, String>> info() async {
    final d = deviceId ?? '';
    return {
      'device': deviceId ?? '',
      'model': await _run('adb $d shell getprop ro.product.model'),
      'android': await _run('adb $d shell getprop ro.build.version.release'),
      'sdk': await _run('adb $d shell getprop ro.build.version.sdk'),
      'manufacturer': await _run('adb $d shell getprop ro.product.manufacturer'),
      'abi': await _run('adb $d shell getprop ro.product.cpu.abi'),
    };
  }

  // ---- APK 操作 ----
  Future<String> install(String apkPath,
      {bool reinstall = false, bool grantPermissions = false}) async {
    var cmd = 'adb $_pre install';
    if (reinstall) cmd += ' -r';
    if (grantPermissions) cmd += ' -g';
    cmd += ' $apkPath';
    return _run(cmd);
  }

  Future<String> uninstall(String packageName, {bool keepData = false}) async {
    var cmd = 'adb $_pre uninstall';
    if (keepData) cmd += ' -k';
    cmd += ' $packageName';
    return _run(cmd);
  }

  Future<String> launch(String packageName, {String? activity}) async {
    if (activity != null) {
      return _run('adb $_pre shell am start -n $packageName/$activity');
    }
    final out = await _run('adb $_pre shell pm resolve-activity --brief $packageName');
    final act = out.contains('/') ? out.split('/').last.trim() : '';
    return _run('adb $_pre shell am start -n $packageName/$act');
  }

  Future<String> forceStop(String packageName) async {
    return _run('adb $_pre shell am force-stop $packageName');
  }

  Future<List<String>> listPackages(
      {String? filter, bool thirdParty = true}) async {
    var cmd = 'adb $_pre shell pm list packages';
    if (thirdParty) cmd += ' -3';
    if (filter != null) cmd += ' | grep $filter';
    final out = await _run(cmd);
    return out
        .split('\n')
        .where((l) => l.startsWith('package:'))
        .map((l) => l.substring(8).trim())
        .toSet()
        .toList()
      ..sort();
  }

  // ---- 文件操作 ----
  Future<String> pull(String remote, String local) async {
    return _run('adb $_pre pull $remote $local');
  }

  Future<String> push(String local, String remote) async {
    return _run('adb $_pre push $local $remote');
  }

  Future<String> screenshot(String outputPath) async {
    await _run('adb $_pre shell screencap -p /sdcard/screen_tmp.png');
    await pull('/sdcard/screen_tmp.png', outputPath);
    await _run('adb $_pre shell rm /sdcard/screen_tmp.png');
    return outputPath;
  }

  // ---- 日志 ----
  Future<String> logcat({String? filterSpec, int lines = 50}) async {
    var cmd = 'adb $_pre logcat -d';
    if (filterSpec != null) cmd += ' -s $filterSpec';
    cmd += ' -t $lines';
    return _run(cmd);
  }

  Future<String> clearLogcat() async {
    return _run('adb $_pre logcat -c');
  }

  // ---- 键盘/输入 ----
  Future<String> tap(int x, int y) async {
    return _run('adb $_pre shell input tap $x $y');
  }

  Future<String> swipe(
      int x1, int y1, int x2, int y2, int durationMs) async {
    return _run('adb $_pre shell input swipe $x1 $y1 $x2 $y2 $durationMs');
  }

  Future<String> inputText(String content) async {
    return _run('adb $_pre shell input text ${_shellEscape(content)}');
  }

  Future<String> keyevent(String keycode) async {
    return _run('adb $_pre shell input keyevent $keycode');
  }
}
