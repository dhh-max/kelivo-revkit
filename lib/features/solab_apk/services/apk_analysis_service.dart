import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'apk_workspace_binding_service.dart';

/// AI 按需分析服务：一次只分析一个模块
/// （basics/manifest/shell/files/dex/resources/methods）。
///
/// 与全量 analyzeApk 不同，这里按需调用原生 `analyzeModule`，并按
/// apkSha256 + module + 分析版本缓存结果（相同 APK 相同模块不重复分析）。
///
/// 缓存写入工作目录，旧 SP key 仅由 clearCache 清理，不再读取。
class ApkAnalysisService {
  const ApkAnalysisService._();

  static const _channel = MethodChannel('solab/workspace');
  static const _cachePrefix = 'solab_apk_module_cache';
  static const _maxCacheFiles = 30;
  static const _maxCacheBytes = 300 * 1024 * 1024; // 300 MiB
  // 单个缓存条目的读取上限：异常膨胀/损坏的文件不整读进堆（超过即当 miss）。
  static const _maxCacheEntryBytes = 8 * 1024 * 1024; // 8 MiB
  // 半写临时文件（`.tmp-<微秒>`）的保留上限，避免进程被杀后残留堆积。
  static const _staleTempAge = Duration(hours: 1);
  static const analysisVersion =
      19; // R1：阶段 0 引擎输出变更（C1 outline CFG 真值 / C2 xref 截断标记 /
          // C3 smali 寄存器跳转 / C4 callerClue / C6 lambda 边 / C16 unsupported
          // 标注）后 bump——旧缓存报告（含修复前假数据）不再被判"新鲜"

  static const supportedModules = [
    'basics',
    'manifest',
    'shell',
    'files',
    'dex',
    'resources',
    'methods',
    'fields',
  ];

  /// 按需分析单个模块。命中缓存（同 APK + 同模块 + 同分析版本）时直接返回缓存。
  /// [classPrefix] 仅 methods 模块使用：只返回该业务包前缀下的方法（T2 包过滤）。
  /// [offset]/[limit]：问题2 methods 分页（36 dex 大包 500 条上限配合 offset 取全量）。
  static Future<Map<String, dynamic>> analyzeModule({
    required String path,
    required String module,
    String? cacheKeySha256,
    bool useCache = true,
    String classPrefix = '',
    int offset = 0,
    int limit = 500,
  }) async {
    final normalized = module.trim().toLowerCase();
    if (!supportedModules.contains(normalized)) {
      return {
        'ok': false,
        'error': 'invalid_module',
        'message': '未知模块: $module（支持 ${supportedModules.join('/')}）',
      };
    }

    // T2 修复：cacheKey 并入 classPrefix——否则先分析全量（缓存）再传 classPrefix
    // 会命中旧缓存返回全量，过滤形同虚设。
    final prefixTag = classPrefix.isEmpty
        ? ''
        : '_cp${classPrefix.hashCode.toRadixString(16)}';
    // 问题2：分页参数并入 cacheKey——否则 offset=0 的结果被缓存，offset=500
    // 命中同一缓存返回相同前 500 条（翻页失效）
    final pageTag = (offset == 0 && limit == 500) ? '' : '_o${offset}_l$limit';
    final cacheKey = cacheKeySha256 == null || cacheKeySha256.isEmpty
        ? null
        : '${_cachePrefix}_${cacheKeySha256.substring(0, cacheKeySha256.length.clamp(0, 16))}_$normalized$prefixTag$pageTag';
    if (useCache && cacheKey != null) {
      final cached = await _readCache(cacheKey);
      if (cached != null) return cached;
    }

    try {
      final raw = await _channel.invokeMethod<Object?>('analyzeModule', {
        'path': path,
        'module': normalized,
        if (classPrefix.isNotEmpty) 'classPrefix': classPrefix,
        'offset': offset,
        'limit': limit,
      });
      final data = raw is Map
          ? Map<String, dynamic>.from(
              raw.map((key, value) => MapEntry(key.toString(), value)),
            )
          : <String, dynamic>{};
      if (data['ok'] == true && cacheKey != null) {
        data['analysisVersion'] = analysisVersion;
        await _writeCache(cacheKey, data);
      }
      return data;
    } on PlatformException catch (error) {
      return {
        'ok': false,
        'error': error.code,
        'message': error.message ?? '调用 analyzeModule 失败',
      };
    } on MissingPluginException {
      return _missingPluginResult();
    } catch (error) {
      return {'ok': false, 'error': 'exception', 'message': error.toString()};
    }
  }

  /// 全量分析 APK（调用原生 analyzeApk），返回完整报告。
  /// 供 AI 工具直接使用，无需用户在 UI 点「分析」按钮。
  static Future<Map<Object?, Object?>?> analyzeFull(String path) async {
    try {
      final raw = await _channel.invokeMethod<Object?>('analyzeApk', {
        'path': path,
      });
      if (raw is Map) return Map<Object?, Object?>.from(raw);
      return null;
    } on PlatformException catch (error) {
      return {'error': error.code, 'message': error.message ?? '分析失败'};
    } on MissingPluginException {
      return _missingPluginResult();
    } catch (error) {
      return {'error': 'exception', 'message': error.toString()};
    }
  }

  static Map<String, dynamic> _missingPluginResult() => {
    'error': 'apk_channel_unavailable',
    'message': 'APK 分析组件未加载。请完整重新安装当前 APK 后再试，热重载不会注册原生通道。',
  };

  /// 清理指定 APK 的模块缓存（换包/重新分析时调用）。
  /// 同时清理历史版本的 SP 缓存 key。
  static Future<void> clearCache(String apkSha256) async {
    if (apkSha256.isEmpty) return;
    final prefix =
        '${_cachePrefix}_${apkSha256.substring(0, apkSha256.length.clamp(0, 16))}_';
    try {
      final dir = await _cacheDirectory();
      if (dir != null && await dir.exists()) {
        await for (final entity in dir.list()) {
          if (entity is File &&
              entity.path
                  .split(Platform.pathSeparator)
                  .last
                  .startsWith(prefix)) {
            await entity.delete();
          }
        }
      }
    } catch (_) {}
    // 旧版 SP 缓存（兼容历史版本，删除即可）。
    try {
      final prefs = await SharedPreferences.getInstance();
      final keys = prefs
          .getKeys()
          .where((key) => key.startsWith('${_cachePrefix}_'))
          .toList();
      for (final key in keys) {
        await prefs.remove(key);
      }
    } catch (_) {}
  }

  // ---- 文件缓存（LRU：上限 30 个文件 / 300 MiB，按最后访问时间淘汰） ----

  static Future<Directory?> _cacheDirectory() async {
    final workDir = await ApkWorkspaceBindingService.workDir();
    if (workDir == null || workDir.trim().isEmpty) return null;
    final dir = Directory(
      '$workDir${Platform.pathSeparator}SoLab${Platform.pathSeparator}cache${Platform.pathSeparator}analysis',
    );
    await dir.create(recursive: true);
    return dir;
  }

  static Future<File?> _cacheFile(String cacheKey) async {
    final dir = await _cacheDirectory();
    return dir == null ? null : File('${dir.path}/$cacheKey.json');
  }

  static Future<Map<String, dynamic>?> _readCache(String cacheKey) async {
    final file = await _cacheFile(cacheKey);
    if (file == null || !await file.exists()) return null;
    try {
      // 超阈值不再整读进堆（损坏/异常膨胀的缓存当 miss 并清掉）。
      if (await file.length() > _maxCacheEntryBytes) {
        await _deleteCacheFile(file);
        return null;
      }
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is Map && decoded['analysisVersion'] == analysisVersion) {
        // 命中即刷新 LRU 时间戳。
        try {
          await file.setLastModified(DateTime.now());
        } catch (_) {}
        return Map<String, dynamic>.from(decoded);
      }
    } catch (_) {
      // 截断/半写文件无法解析：删除，避免每次分析都重复踩同一颗雷。
      await _deleteCacheFile(file);
    }
    return null;
  }

  static Future<void> _deleteCacheFile(File file) async {
    try {
      await file.delete();
    } catch (_) {}
  }

  static Future<void> _writeCache(
    String cacheKey,
    Map<String, dynamic> data,
  ) async {
    final file = await _cacheFile(cacheKey);
    if (file == null) return;
    // 先写同目录临时文件再 rename：进程被杀或磁盘写满时不会留下半份 JSON
    // 冒充有效缓存（版本戳救不回无法解析的文件，且读到截断内容会静默 miss）。
    final tmp = File(
      '${file.path}.tmp-${DateTime.now().microsecondsSinceEpoch}',
    );
    try {
      await tmp.writeAsString(jsonEncode(data), flush: true);
      await tmp.rename(file.path);
    } catch (_) {
      await _deleteCacheFile(tmp);
      rethrow;
    }
    await _evictIfNeeded();
  }

  static Future<void> _evictIfNeeded() async {
    try {
      final dir = await _cacheDirectory();
      if (dir == null) return;
      final files = <File>[];
      final now = DateTime.now();
      await for (final entity in dir.list()) {
        if (entity is! File) continue;
        final name = entity.path;
        if (name.endsWith('.json')) {
          files.add(entity);
          continue;
        }
        // 硬中断留下的半写临时文件：过期即清，避免永不被 LRU 统计到。
        if (name.contains('.json.tmp-')) {
          try {
            if (now.difference(entity.statSync().modified) >
                _staleTempAge) {
              await entity.delete();
            }
          } catch (_) {}
        }
      }
      if (files.length <= _maxCacheFiles) {
        var total = 0;
        for (final file in files) {
          total += await file.length();
        }
        if (total <= _maxCacheBytes) return;
      }
      files.sort(
        (a, b) => a.lastModifiedSync().compareTo(b.lastModifiedSync()),
      );
      var count = files.length;
      for (final file in files) {
        if (count <= _maxCacheFiles) break;
        try {
          await file.delete();
          count--;
        } catch (_) {}
      }
      var total = 0;
      for (final file in files) {
        if (!await file.exists()) continue;
        total += await file.length();
      }
      if (total > _maxCacheBytes) {
        files.sort(
          (a, b) => a.lastModifiedSync().compareTo(b.lastModifiedSync()),
        );
        for (final file in files) {
          if (total <= _maxCacheBytes) break;
          try {
            final size = await file.length();
            await file.delete();
            total -= size;
          } catch (_) {}
        }
      }
    } catch (_) {}
  }
}
