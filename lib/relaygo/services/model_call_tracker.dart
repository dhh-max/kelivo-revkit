import 'dart:async';
import 'package:Kelivo/relaygo/models/api_key.dart';
import 'package:Kelivo/relaygo/services/key_manager.dart';

/// 按模型调用次数追踪器（5 小时滑动窗口）。
///
/// 融合自 SenseNova Key Rotator 的核心能力：
/// - 按 [model] 分别计数，5h 窗口自动过期
/// - 超过限额时标记该 key 对该模型为 exhausted
/// - 提供查询接口供管理 API / Web UI 使用
class ModelCallTracker {
  final KeyManager keyManager;
  /// 模型 → 调用限额（5h 窗口内最大次数）
  final Map<String, int> modelCallLimits;
  /// 默认限额（当模型不在 [modelCallLimits] 中时）
  final int defaultLimit;
  /// 窗口时长（毫秒），默认 5h
  final int windowMs;

  ModelCallTracker({
    required this.keyManager,
    this.modelCallLimits = const {},
    this.defaultLimit = 1500,
    this.windowMs = 5 * 60 * 60 * 1000,
  });

  /// 某模型在该 key 上的限额
  int limitFor(String model) =>
      modelCallLimits[model] ?? defaultLimit;

  /// 检查 key 是否仍可调用该模型
  bool canCall(ApiKey key, String model) {
    _rollWindow(key, model);
    if ((key.modelExhausted[model] ?? false) && !_windowExpired(key, model)) {
      return false;
    }
    final used = key.modelCalls[model] ?? 0;
    final limit = limitFor(model);
    return used < limit;
  }

  /// 记录一次调用（在转发前调用）
  void recordCall(ApiKey key, String model) {
    _rollWindow(key, model);
    key.modelCalls[model] = (key.modelCalls[model] ?? 0) + 1;
    key.modelExhausted.remove(model);
    final limit = limitFor(model);
    if ((key.modelCalls[model] ?? 0) >= limit) {
      key.modelExhausted[model] = true;
    }
    key.lastUsed = DateTime.now().millisecondsSinceEpoch;
    unawaited(keyManager.updateKey(key));
  }

  /// 记录成功（清零失败计数，不额外操作）
  void recordSuccess(ApiKey key, String model) {
    // 调用已在 recordCall 中计数，此处仅做健康标记
  }

  /// 标记某 key 对某模型为耗尽
  void markExhausted(ApiKey key, String model, [String? reason]) {
    final limit = limitFor(model);
    key.modelCalls[model] = limit;
    key.modelExhausted[model] = true;
    unawaited(keyManager.updateKey(key));
  }

  /// 重置某 key 的模型计数（充值后恢复）
  void reset(ApiKey key, {String? model}) {
    if (model != null) {
      key.modelCalls.remove(model);
      key.modelExhausted.remove(model);
      key.modelCallStamps.remove(model);
    } else {
      key.modelCalls.clear();
      key.modelExhausted.clear();
      key.modelCallStamps.clear();
    }
    unawaited(keyManager.updateKey(key));
  }

  /// 批量检测所有 key 对某模型是否可用
  Future<List<Map<String, dynamic>>> checkAll(String model) async {
    final results = <Map<String, dynamic>>[];
    for (final k in keyManager.getAll()) {
      final can = canCall(k, model);
      results.add({
        'key': k.maskedKey,
        'available': can,
        'used': k.modelCalls[model] ?? 0,
        'limit': limitFor(model),
        'exhausted': k.modelExhausted[model] ?? false,
      });
    }
    return results;
  }

  void _rollWindow(ApiKey key, String model) {
    final now = DateTime.now().millisecondsSinceEpoch;
    final stamp = key.modelCallStamps[model] ?? 0;
    if (stamp == 0 || now - stamp >= windowMs) {
      key.modelCalls[model] = 0;
      key.modelExhausted.remove(model);
      key.modelCallStamps[model] = now;
    }
  }

  bool _windowExpired(ApiKey key, String model) {
    final now = DateTime.now().millisecondsSinceEpoch;
    final stamp = key.modelCallStamps[model] ?? 0;
    return stamp == 0 || now - stamp >= windowMs;
  }
}
