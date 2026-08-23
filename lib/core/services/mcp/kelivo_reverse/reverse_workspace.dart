part of kelivo_reverse_server;

// =========================================================================
// 工作区管理 — 多项目并行分析上下文隔离
// 移植自 Python apk_reverse_engine/workspace/manager.py
// =========================================================================

class _Workspace {
  static String get defaultRoot {
    final home = Platform.environment['HOME'] ??
        Platform.environment['ANDROID_DATA'] ??
        '/data';
    return '$home/.apk-rev/workspaces';
  }

  static String _safeName(String s) {
    return s.replaceAll(RegExp(r'[^a-zA-Z0-9 _-]'), '_').trim().replaceAll(' ', '_');
  }

  static Future<Map<String, dynamic>> create(
    String name, {
    String? root,
    String description = '',
    String? apkPath,
  }) async {
    final wsRoot = root ?? defaultRoot;
    final dir = '$wsRoot/${_safeName(name)}';
    await Directory('$dir/results').create(recursive: true);
    await Directory('$dir/artifacts').create(recursive: true);

    String? sha256;
    int? size;
    if (apkPath != null) {
      final f = File(apkPath);
      if (await f.exists()) {
        size = await f.length();
        final bytes = await f.readAsBytes();
        sha256 = sha256$1.convert(bytes).toString();
      }
    }

    final meta = <String, dynamic>{
      'name': name,
      'created': DateTime.now().toIso8601String(),
      'description': description,
      'apk': {
        'path': apkPath,
        'sha256': sha256,
        'size': size,
      },
    };
    await _writeJson('$dir/meta.json', meta);
    return meta;
  }

  static Future<List<Map<String, dynamic>>> list({String? root}) async {
    final wsRoot = root ?? defaultRoot;
    final dir = Directory(wsRoot);
    if (!await dir.exists()) return [];
    final out = <Map<String, dynamic>>[];
    await for (final entry in dir.list()) {
      if (entry is Directory) {
        final metaFile = File('${entry.path}/meta.json');
        if (await metaFile.exists()) {
          try {
            final content = await metaFile.readAsString();
            final meta = jsonDecode(content) as Map<String, dynamic>;
            meta['dir'] = entry.path;
            out.add(meta);
          } catch (e) {
            // skip invalid
          }
        }
      }
    }
    return out;
  }

  static Future<Map<String, dynamic>?> open(String name, {String? root}) async {
    final wsRoot = root ?? defaultRoot;
    final dir = '$wsRoot/${_safeName(name)}';
    final metaFile = File('$dir/meta.json');
    if (!await metaFile.exists()) return null;
    final content = await metaFile.readAsString();
    final meta = jsonDecode(content) as Map<String, dynamic>;
    meta['dir'] = dir;
    return meta;
  }

  static Future<bool> delete(String name, {String? root}) async {
    final wsRoot = root ?? defaultRoot;
    final dir = Directory('$wsRoot/${_safeName(name)}');
    if (await dir.exists()) {
      await dir.delete(recursive: true);
      return true;
    }
    return false;
  }

  static Future<String> saveResult(
    String name,
    String key,
    Map<String, dynamic> data, {
    String? root,
  }) async {
    final wsRoot = root ?? defaultRoot;
    final dir = '$wsRoot/${_safeName(name)}/results';
    await Directory(dir).create(recursive: true);
    final path = '$dir/${_safeName(key)}.json';
    await _writeJson(path, data);
    return path;
  }

  static Future<Map<String, dynamic>?> loadResult(
    String name,
    String key, {
    String? root,
  }) async {
    final wsRoot = root ?? defaultRoot;
    final path = '$wsRoot/${_safeName(name)}/results/${_safeName(key)}.json';
    final f = File(path);
    if (!await f.exists()) return null;
    final content = await f.readAsString();
    return jsonDecode(content) as Map<String, dynamic>;
  }

  static Future<List<String>> listResults(String name, {String? root}) async {
    final wsRoot = root ?? defaultRoot;
    final dir = Directory('$wsRoot/${_safeName(name)}/results');
    if (!await dir.exists()) return [];
    final out = <String>[];
    await for (final entry in dir.list()) {
      if (entry is File) {
        out.add(entry.uri.pathSegments.last);
      }
    }
    out.sort();
    return out;
  }

  static String artifactPath(String name, String subpath, {String? root}) {
    final wsRoot = root ?? defaultRoot;
    return '$wsRoot/${_safeName(name)}/artifacts/$subpath';
  }

  static Future<void> setConfig(
    String name,
    String key,
    dynamic value, {
    String? root,
  }) async {
    final wsRoot = root ?? defaultRoot;
    final dir = '$wsRoot/${_safeName(name)}';
    final cfg = await loadConfig(name, root: wsRoot);
    cfg[key] = value;
    await _writeJson('$dir/config.json', cfg);
  }

  static Future<dynamic> getConfig(
    String name,
    String key, {
    dynamic defaultValue,
    String? root,
  }) async {
    final cfg = await loadConfig(name, root: root);
    return cfg[key] ?? defaultValue;
  }

  static Future<Map<String, dynamic>> loadConfig(
    String name, {
    String? root,
  }) async {
    final wsRoot = root ?? defaultRoot;
    final path = '$wsRoot/${_safeName(name)}/config.json';
    final f = File(path);
    if (await f.exists()) {
      final content = await f.readAsString();
      return jsonDecode(content) as Map<String, dynamic>;
    }
    return {};
  }

  static Future<Map<String, dynamic>> info(String name, {String? root}) async {
    final wsRoot = root ?? defaultRoot;
    final dir = '$wsRoot/${_safeName(name)}';
    return {
      'name': name,
      'dir': dir,
      'results': await listResults(name, root: wsRoot),
      'config': await loadConfig(name, root: wsRoot),
      'meta': await open(name, root: wsRoot),
    };
  }

  static Future<void> _writeJson(String path, Map<String, dynamic> data) async {
    final f = File(path);
    await f.parent.create(recursive: true);
    await f.writeAsString(
        const JsonEncoder.withIndent('  ').convert(data));
  }
}
