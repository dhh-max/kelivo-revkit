import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// SoLab APK 原生分析进度监听：EventChannel 'solab/progress' 的 Dart 侧消费方。
///
/// 此前进度事件发出后无任何监听方（无效投递）；现在记录最近一次进度供
/// 工作台展示，并可在工具结果中附注，避免分析大包时 AI/用户误判超时。
class ApkProgressService extends ChangeNotifier {
  ApkProgressService._();

  static final ApkProgressService instance = ApkProgressService._();

  static const _channel = EventChannel('solab/progress');
  static const _soChannel = EventChannel('so_analyze/progress');

  StreamSubscription<Object?>? _subscription;
  StreamSubscription<Object?>? _soSubscription;

  int _percent = 0;
  String _stage = '';

  /// SO 引擎最近进度（so_analyze 长任务阶段）。
  int _soPercent = 0;
  String _soStage = '';

  /// 最近一次分析进度百分比（0-100）。
  int get percent => _percent;

  /// 最近一次分析阶段说明（原生侧 stage 文案）。
  String get stage => _stage;

  bool get hasProgress => _percent > 0;

  /// SO 引擎进度（0-100）与阶段。
  int get soPercent => _soPercent;
  String get soStage => _soStage;
  bool get hasSoProgress => _soPercent > 0;

  /// 订阅进度通道（幂等）。在 Android 通道注册后调用；其它平台订阅无害。
  ///
  /// 幂等判据是**每路各自的订阅句柄**，不是单一的 _listening 开关：
  /// 旧实现里 onError 空 catch + cancelOnError: true 会把流取消掉，而
  /// _subscription 仍非空、_listening 仍为 true，于是这一路进度此后永久静默
  /// （原生侧再怎么发都没人听）。现在出错即清句柄，下次调用可重订。
  void ensureListening() {
    _listenProgress();
    _listenSoProgress();
  }

  void _listenProgress() {
    if (_subscription != null) return;
    _subscription = _channel.receiveBroadcastStream().listen(
      (event) {
        try {
          if (event is Map) {
            final percent = (event['percent'] as num?)?.toInt() ?? 0;
            final stage = (event['stage'] as String?) ?? '';
            if (percent != _percent || stage != _stage) {
              _percent = percent;
              _stage = stage;
              notifyListeners();
            }
          }
        } catch (_) {}
      },
      onError: (_) {
        // 通道未注册/已关闭：清掉句柄，让下次 ensureListening 能重订。
        _subscription = null;
      },
      cancelOnError: true,
    );
  }

  /// SO 引擎进度（so_analyze 长任务：open/analyze_apk/emulate/blutter）
  void _listenSoProgress() {
    if (_soSubscription != null) return;
    _soSubscription = _soChannel.receiveBroadcastStream().listen(
      (event) {
        try {
          if (event is Map) {
            final percent = (event['percent'] as num?)?.toInt() ?? 0;
            final stage = (event['stage'] as String?) ?? '';
            if (percent != _soPercent || stage != _soStage) {
              _soPercent = percent;
              _soStage = stage;
              notifyListeners();
            }
          }
        } catch (_) {}
      },
      onError: (_) {
        _soSubscription = null;
      },
      cancelOnError: true,
    );
  }

  /// 重置进度（新分析开始时调用）。
  void reset() {
    if (_percent == 0 &&
        _stage.isEmpty &&
        _soPercent == 0 &&
        _soStage.isEmpty) {
      return;
    }
    _percent = 0;
    _stage = '';
    _soPercent = 0;
    _soStage = '';
    notifyListeners();
  }

  /// 工具结果附注：最近一次进度的紧凑描述，无进度时返回 null。
  String? progressSummary() {
    if (_percent > 0) return '最近一次分析进度：$_percent%（$_stage）';
    if (_soPercent > 0) return 'SO 引擎进度：$_soPercent%（$_soStage）';
    return null;
  }

  @override
  void dispose() {
    _subscription?.cancel();
    _subscription = null;
    _soSubscription?.cancel();
    _soSubscription = null;
    super.dispose();
  }
}
