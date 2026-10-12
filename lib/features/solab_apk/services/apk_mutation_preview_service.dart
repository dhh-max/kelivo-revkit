import 'dart:convert';
import 'dart:math';

import 'package:shared_preferences/shared_preferences.dart';

class ApkMutationPreviewService {
  ApkMutationPreviewService._();

  static const _key = 'apk_mod_mutation_previews_v1';

  /// 最近被写操作作废的 token（供 consume 失败时区分"从未 dryRun"与
  /// "已因后续写操作作废"）。**不是墓碑**：只留最近 [\_recentMax] 条、随
  /// [\_lifetime] 过期，且不参与任何校验判定——纯粹用于把错误信息说准。
  static const _recentKey = 'apk_mod_mutation_previews_recent_v1';
  static const _recentMax = 32;
  static const _lifetime = Duration(minutes: 30);

  static Future<String> issue({
    required String operation,
    required String path,
    required Map<String, dynamic> args,
  }) async {
    final token =
        '${DateTime.now().microsecondsSinceEpoch}_${Random.secure().nextInt(1 << 32)}';
    final previews = await _read();
    previews[token] = {
      'operation': operation,
      'path': path,
      'fingerprint': _fingerprint(args),
      'arguments': _canonical(_mutationArgs(args)),
      'expiresAt': DateTime.now().add(_lifetime).millisecondsSinceEpoch,
    };
    await _write(previews);
    return token;
  }

  static Future<bool> consume({
    required String token,
    required String operation,
    required String path,
    required Map<String, dynamic> args,
  }) => consumeResult(
    token: token,
    operation: operation,
    path: path,
    args: args,
  ).then((result) => result['ok'] == true);

  /// 仅校验预览，不提前消费。调用方应在实际写入成功后再通过
  /// [invalidatePath] 清理；写入失败时同一 token 可以直接重试。
  static Future<Map<String, dynamic>> validateResult({
    required String token,
    required String operation,
    required String path,
    required Map<String, dynamic> args,
  }) => _check(
    token: token,
    operation: operation,
    path: path,
    args: args,
    consume: false,
  );

  /// P1-A：修改执行成功后，清掉同 operation+path 的其余未消费 token
  /// （当前目标已变化，旧 token 即使未过期也不可能再用），返回被清除列表。
  static Future<List<String>> invalidatePath(
    String operation,
    String path,
  ) async {
    final previews = await _read();
    final removed = <String>[];
    previews.removeWhere((token, preview) {
      if (preview is Map &&
          preview['operation'] == operation &&
          preview['path'] == path) {
        removed.add(token);
        return true;
      }
      return false;
    });
    if (removed.isNotEmpty) {
      await _write(previews);
      await _rememberInvalidated(removed, operation: operation, path: path);
    }
    return removed;
  }

  /// 任一写操作成功后，原产物已不再是后续修改链的当前输入；清理该产物上
  /// 所有操作的预览，避免不同工具从同一旧 APK 分叉并覆盖前一步修改。
  ///
  /// D8（2026-09-19 真机 QA）：这个语义是**对的**——预览针对的是旧产物字节，
  /// 写完之后"同一参数 + 新输入"已经是另一个操作，放行等于静默改变语义。
  /// 但被作废的一方此前只能拿到"凭证不存在（从未 dryRun 或已被消费）"，
  /// 与真实原因（写操作改了目标）不符，看起来像"preview 完全不能用"。
  /// 故记一条**只说原因、不参与校验**的短期记录，让错误信息能如实解释并给出
  /// "以 nextInputPath 重新 dryRun"的指引。
  static Future<List<String>> invalidateArtifact(String path) async {
    final previews = await _read();
    final removed = <String>[];
    var operation = '';
    previews.removeWhere((token, preview) {
      if (preview is Map && preview['path'] == path) {
        removed.add(token);
        operation = preview['operation']?.toString() ?? operation;
        return true;
      }
      return false;
    });
    if (removed.isNotEmpty) {
      await _write(previews);
      await _rememberInvalidated(removed, operation: operation, path: path);
    }
    return removed;
  }

  static Future<void> _rememberInvalidated(
    List<String> tokens, {
    required String operation,
    required String path,
  }) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_recentKey);
      final recent = <String, dynamic>{};
      if (raw != null && raw.isNotEmpty) {
        final decoded = jsonDecode(raw);
        if (decoded is Map) recent.addAll(decoded.cast<String, dynamic>());
      }
      final at = DateTime.now().millisecondsSinceEpoch;
      for (final token in tokens) {
        recent[token] = {
          'operation': operation,
          'path': path,
          'invalidatedAt': at,
          'expiresAt': at + _lifetime.inMilliseconds,
        };
      }
      // 只留最近的若干条 + 未过期的：这是给错误信息用的提示，不是状态。
      final alive = <String, dynamic>{};
      for (final entry in recent.entries) {
        final value = entry.value;
        final expiresAt = value is Map ? (value['expiresAt'] as num?)?.toInt() : null;
        if (expiresAt == null || expiresAt < at) continue;
        alive[entry.key] = value;
      }
      final trimmed = alive.entries.toList()
        ..sort((a, b) {
          final av = (a.value as Map)['invalidatedAt'] as num? ?? 0;
          final bv = (b.value as Map)['invalidatedAt'] as num? ?? 0;
          return bv.compareTo(av);
        });
      final keep = <String, dynamic>{
        for (final e in trimmed.take(_recentMax)) e.key: e.value,
      };
      await prefs.setString(_recentKey, jsonEncode(keep));
    } catch (_) {
      // 记录失败不影响作废本身（作废已落盘）。
    }
  }

  /// 该 token 是否因后续写操作被作废（用于把 consume 的错误说准）。
  static Future<Map<String, dynamic>?> invalidatedReason(String token) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_recentKey);
      if (raw == null || raw.isEmpty) return null;
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return null;
      final entry = decoded[token];
      return entry is Map ? entry.cast<String, dynamic>() : null;
    } catch (_) {
      return null;
    }
  }

  /// 详细版 consume：返回失败原因（invalid/expired/mismatch）与原过期时间，
  /// 供调用方在报错时给出「previewTokenExpiresAt + 重新 dryRun」指引（P1-4）。
  static Future<Map<String, dynamic>> consumeResult({
    required String token,
    required String operation,
    required String path,
    required Map<String, dynamic> args,
  }) => _check(
    token: token,
    operation: operation,
    path: path,
    args: args,
    consume: true,
  );

  static Future<Map<String, dynamic>> _check({
    required String token,
    required String operation,
    required String path,
    required Map<String, dynamic> args,
    required bool consume,
  }) async {
    final previews = await _read();
    final preview = previews[token];
    if (preview is! Map) {
      // D8：区分「从未 dryRun」与「已因后续写操作作废」——后者是正常链路行为
      // （预览针对旧产物字节），错误信息必须说准，并给出重做路径。
      final invalidated = await invalidatedReason(token);
      if (invalidated != null) {
        final path = invalidated['path']?.toString() ?? '';
        final operation = invalidated['operation']?.toString() ?? '';
        return {
          'ok': false,
          'reason': 'invalidated',
          'invalidatedPath': path,
          'invalidatedByOperation': operation,
          'message':
              '预览确认凭证已因针对同一产物（$path）的写操作（$operation）而作废：'
              '旧预览对应的是改动前的字节。请以该写操作的 nextInputPath 为输入重新 dryRun，'
              '再 applyAfterPreview=true。',
        };
      }
      return {
        'ok': false,
        'reason': 'invalid',
        'message': '预览确认凭证不存在（从未 dryRun 或已被消费）。',
      };
    }
    final expiresAt = (preview['expiresAt'] as num?)?.toInt();
    if (expiresAt == null ||
        DateTime.now().millisecondsSinceEpoch > expiresAt) {
      previews.remove(token);
      await _write(previews);
      final expiredAtText = expiresAt == null
          ? '未知'
          : DateTime.fromMillisecondsSinceEpoch(expiresAt).toString();
      return {
        'ok': false,
        'reason': 'expired',
        'previewTokenExpiresAt': expiredAtText,
        'message': '预览确认凭证已于 $expiredAtText 过期（有效期 30 分钟）。',
      };
    }
    if (preview['operation'] != operation ||
        preview['path'] != path ||
        preview['fingerprint'] != _fingerprint(args)) {
      return {
        'ok': false,
        'reason': 'mismatch',
        if (preview['arguments'] is Map)
          'expectedArguments': Map<String, dynamic>.from(
            preview['arguments'] as Map,
          ),
        'expectedPath': preview['path'],
        'message':
            '预览确认凭证与当前修改不一致（operation/path/修改参数发生变化）。凭证尚未消费，请恢复预览时的修改参数后重试。',
      };
    }
    if (consume) {
      previews.remove(token);
      await _write(previews);
    }
    return {'ok': true, 'consumed': consume};
  }

  static Future<Map<String, dynamic>> _read() async {
    final preferences = await SharedPreferences.getInstance();
    final raw = preferences.getString(_key);
    if (raw == null || raw.isEmpty) return <String, dynamic>{};
    try {
      final decoded = Map<String, dynamic>.from(jsonDecode(raw) as Map);
      // 过期 preview 随手清理，避免 SP 无限累积。
      final now = DateTime.now().millisecondsSinceEpoch;
      final before = decoded.length;
      decoded.removeWhere(
        (_, preview) =>
            preview is Map &&
            (preview['expiresAt'] as num?)?.toInt() is int &&
            now > (preview['expiresAt'] as num).toInt(),
      );
      if (decoded.length != before) {
        await preferences.setString(_key, jsonEncode(decoded));
      }
      return decoded;
    } catch (_) {
      return <String, dynamic>{};
    }
  }

  static Future<void> _write(Map<String, dynamic> previews) async {
    final preferences = await SharedPreferences.getInstance();
    await preferences.setString(_key, jsonEncode(previews));
  }

  static String _fingerprint(Map<String, dynamic> args) =>
      jsonEncode(_canonical(_mutationArgs(args)));

  static Map<String, dynamic> _mutationArgs(Map<String, dynamic> args) =>
      Map<String, dynamic>.from(args)
        ..remove('confirm')
        ..remove('dryRun')
        ..remove('previewToken')
        ..remove('sign')
        ..remove('applyAfterPreview')
        ..remove('apkPath')
        ..remove('fileName')
        ..remove('apkName')
        ..remove('outputDir');

  static Object? _canonical(Object? value) => switch (value) {
    Map map => () {
      final keys = map.keys.map((key) => key.toString()).toList()..sort();
      return <String, Object?>{
        for (final key in keys) key: _canonical(map[key]),
      };
    }(),
    List list => [for (final item in list) _canonical(item)],
    _ => value,
  };
}
