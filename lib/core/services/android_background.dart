import 'dart:async';
import 'dart:io' show Platform;
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'mcp_server/mcp_http_server.dart';

/// Android 后台保活管理器（自研 FGS + WakeLock，经 `app.background` 通道）。
///
/// 两种模式共用：
/// - agent 模式：生成期自动持有（ref-count + 防抖释放）
/// - MCP 模式：用户开启「后台聊天」常驻开关时长期持有
///
/// 所有调用在非 Android 平台为 no-op。
class AndroidBackgroundManager {
  static const _channel = MethodChannel('app.background');

  static bool _initialized = false;

  /// 最近一次 enable 失败原因（供 UI 提示，不再静默吞错）。
  static String? lastEnableError;

  /// 最近一次使用的通知文案（l10n 传入，服务重启时沿用）。
  static String? _notificationTitle;
  static String? _notificationText;

  /// 保活通知的模式前缀（互斥双模，2026-09-19 用户要求）：
  /// 常驻通知此前两种模式都只显示同一句「后台任务保活中」，分不清当前是
  /// MCP 模式（局域网 MCP 服务在跑、本地 Agent 工具暂停）还是本地 Agent 模式。
  /// 这里在**文案前面**统一加模式标签，调用方传什么正文都保留。
  ///
  /// MCP 模式再带**端口**（2026-09-21 用户要求）：用户要能一眼看出服务在哪个
  /// 端口上，而端口只有服务真在跑时才有意义——所以与模式标签同一个来源，
  /// 一起刷新、一起消失。
  ///
  /// 判据做成可注入：测试不该依赖真实 MCP 服务器状态。
  static bool Function() isMcpMode = () => McpHttpServer.instance.isRunning;

  static String _modePrefix() {
    if (!isMcpMode()) return 'Agent 模式';
    return 'MCP 模式$_modeSeparator端口 ${McpHttpServer.instance.port}';
  }

  static const String _modeSeparator = ' · ';

  /// 组合最终正文：剥掉上一次可能已加过的模式前缀（刷新会重复调用，不剥会越加越长）。
  static String _composeNotificationText() =>
      composeNotificationText(_notificationText);

  /// 组合逻辑本体（两处调用点 + 回归测试共用）。
  @visibleForTesting
  static String composeNotificationText(String? explicit) =>
      '${_modePrefix()}$_modeSeparator'
      '${stripNotificationPrefix(explicit ?? '后台任务保活中')}';

  /// 剥掉模式标签与端口段（两者都只在开头出现一次）。
  @visibleForTesting
  static String stripNotificationPrefix(String text) {
    var rest = text;
    for (final label in const ['MCP 模式', 'Agent 模式']) {
      if (rest.startsWith(label)) {
        rest = rest.substring(label.length);
        break;
      }
    }
    if (rest.startsWith(_modeSeparator)) {
      rest = rest.substring(_modeSeparator.length);
    }
    final port = RegExp(r'^端口 \d+').matchAsPrefix(rest);
    if (port != null) {
      rest = rest.substring(port.end);
      if (rest.startsWith(_modeSeparator)) {
        rest = rest.substring(_modeSeparator.length);
      }
    }
    return rest.trim().isEmpty ? '后台任务保活中' : rest;
  }

  /// Dart 侧缓存的服务运行状态（以原生 KeepAliveService.isRunning 为准同步）。
  static bool _enabled = false;
  static bool _networkRequired = false;

  // ---- 生成期自动保活（ref-count + 防抖释放）----
  // 指派任务后切后台/开别的 App，进程没有前台服务会被系统冻结，
  // 输出立即中断。生成期间强制持有前台服务；全部生成结束后按用户
  // 设置回收（常驻模式保留），防抖窗口避免连续消息/工具多轮之间闪断。
  static int _generationHoldCount = 0;
  static Timer? _generationHoldReleaseTimer;

  /// 释放代次号：begin 时递增；防抖回调只在代次未变时执行 disable，
  /// 避免「回调检查 count=0 → 用户恰好 begin → disable 后落地误关服务」。
  static int _releaseGeneration = 0;

  /// 是否有 agent 生成期持有 FGS（MCP 等其他持有方退出前查，
  /// 防止互杀：MCP 关闭时误停生成中的 agent 保活）。
  static bool get hasActiveGenerationHold => _generationHoldCount > 0;

  /// 生成开始（每次发送任务调用一次；工具多轮在同一持有期内）。
  static Future<void> beginGenerationHold() async {
    if (!Platform.isAndroid) return;
    _releaseGeneration++;
    _generationHoldReleaseTimer?.cancel();
    _generationHoldReleaseTimer = null;
    _generationHoldCount++;
    final ok = await ensureInitialized();
    if (!ok) return;
    // Dart 状态可能在进程未重启时已经过期（系统杀掉 FGS 后
    // _enabled 仍为 true），每轮生成都以原生状态重新校验。
    final running = await isEnabled();
    if (!running || !_networkRequired) {
      try {
        await setEnabled(true, networkRequired: true);
      } catch (_) {
        // 保活失败不阻塞生成（前台执行不受影响）。
      }
    }
  }

  /// 生成终态（完成/失败/取消）调用。[userWantsPersistent] 为用户
  /// 「后台聊天」常驻设置（on/onNotify）时保留前台服务，off 则防抖回收。
  static Future<void> endGenerationHold({
    required bool userWantsPersistent,
  }) async {
    if (!Platform.isAndroid) return;
    if (_generationHoldCount > 0) _generationHoldCount--;
    if (_generationHoldCount > 0) return;
    if (userWantsPersistent || McpHttpServer.instance.isRunning) {
      await setEnabled(true, networkRequired: McpHttpServer.instance.isRunning);
      return;
    }
    _generationHoldReleaseTimer?.cancel();
    final generation = _releaseGeneration;
    _generationHoldReleaseTimer = Timer(const Duration(seconds: 20), () async {
      if (_generationHoldCount > 0) return;
      if (generation != _releaseGeneration) return; // 期间有新任务 begin
      // MCP 模式在跑时 FGS 由它接管——agent 生成结束不回收（防互杀）。
      if (McpHttpServer.instance.isRunning) return;
      try {
        await setEnabled(false);
      } catch (_) {}
    });
  }

  /// 初始化：与原生服务同步真实运行状态（进程重启后 Dart 缓存已失效）。
  static Future<bool> ensureInitialized({
    String? notificationTitle,
    String? notificationText,
  }) async {
    if (!Platform.isAndroid) return false;
    if (notificationTitle != null) _notificationTitle = notificationTitle;
    if (notificationText != null) _notificationText = notificationText;
    _attachMcpModeListener();
    _attachChannelHandler();
    if (_initialized) return true;
    try {
      _enabled =
          await _channel.invokeMethod<bool>('keepAliveIsRunning') ?? false;
      _initialized = true;
      return true;
    } catch (e) {
      lastEnableError = '初始化失败: $e';
      return false;
    }
  }

  // ---- MCP 启停 → 刷新常驻通知（2026-09-21 用户实测缺陷）----
  // 症状：MCP 模式启动后，通知栏仍写着「Agent 模式」。根因是通知文案在 FGS
  // 启动那一刻就定稿了，而 main.dart 的启动顺序是 **FGS 先起、MCP server 后起**
  // ——组文案时 `isRunning` 还是 false。过去只有「退出 MCP 模式」那条路径会
  // 刷新，于是标签一直错到用户手动进出页面为止。
  // 这里挂一次监听，只在**运行状态翻转**时刷新（会话活动等高频通知不触发通道调用）。
  static bool _mcpListenerAttached = false;
  static bool? _lastMcpRunning;

  static void _attachMcpModeListener() {
    if (_mcpListenerAttached) return;
    _mcpListenerAttached = true;
    _lastMcpRunning = McpHttpServer.instance.isRunning;
    McpHttpServer.instance.addListener(_onMcpServerChanged);
  }

  static void _onMcpServerChanged() {
    final running = McpHttpServer.instance.isRunning;
    if (running == _lastMcpRunning) return;
    _lastMcpRunning = running;
    unawaited(refreshNotification());
  }

  // ---- 通知上的「关闭」按钮（Kotlin → Dart）----
  /// 用户在常驻通知上点「关闭」时由原生服务回调；由 main.dart 接成
  /// 「停 MCP 模式 + 关设置开关」。原生已经把 FGS 停掉了，这里只同步业务状态。
  static Future<void> Function()? onUserStoppedFromNotification;

  static bool _channelHandlerAttached = false;

  /// 测试缝：非 Android 平台也能挂上通道处理器与 MCP 监听
  /// （正常入口是 [ensureInitialized]，它在非 Android 上直接返回 false）。
  @visibleForTesting
  static void debugAttachHandlers() {
    _attachMcpModeListener();
    _attachChannelHandler();
  }

  static void _attachChannelHandler() {
    if (_channelHandlerAttached) return;
    _channelHandlerAttached = true;
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'keepAliveStoppedByUser') {
        _enabled = false;
        _networkRequired = false;
        try {
          await onUserStoppedFromNotification?.call();
        } catch (_) {
          // 回调失败不影响原生侧已经完成的停止动作。
        }
      }
      return null;
    });
  }

  /// 启停前台保活服务。返回是否成功；失败时 [lastEnableError] 记录原因。
  static Future<bool> setEnabled(
    bool enable, {
    bool networkRequired = false,
  }) async {
    if (!Platform.isAndroid) return false;
    if (enable) {
      _releaseGeneration++;
      _generationHoldReleaseTimer?.cancel();
      _generationHoldReleaseTimer = null;
    } else if (_generationHoldCount > 0 || McpHttpServer.instance.isRunning) {
      return true;
    }
    try {
      if (enable) {
        final effectiveNetworkRequired =
            networkRequired ||
            _generationHoldCount > 0 ||
            McpHttpServer.instance.isRunning;
        final startAccepted =
            await _channel.invokeMethod<bool>('keepAliveStart', {
              'title': _notificationTitle ?? 'SoLab',
              'text': _composeNotificationText(),
              'networkRequired': effectiveNetworkRequired,
            }) ??
            false;
        var ok = false;
        if (startAccepted) {
          for (var attempt = 0; attempt < 20; attempt++) {
            ok =
                await _channel.invokeMethod<bool>('keepAliveIsReady', {
                  'networkRequired': effectiveNetworkRequired,
                }) ??
                false;
            if (ok) break;
            await Future<void>.delayed(const Duration(milliseconds: 50));
          }
        }
        _enabled = ok;
        _networkRequired = ok && effectiveNetworkRequired;
        lastEnableError = ok
            ? null
            : '前台服务启动失败（若应用在后台，Android 12+ 限制后台启动，请回到前台重试）';
        return ok;
      } else {
        await _channel.invokeMethod('keepAliveStop');
        _enabled = false;
        _networkRequired = false;
        lastEnableError = null;
        return true;
      }
    } on PlatformException catch (e) {
      lastEnableError = '保活服务调用失败: ${e.message}';
      return false;
    }
  }

  /// 查询前台保活服务是否正在运行（以原生状态为准）。
  static Future<bool> isEnabled() async {
    if (!Platform.isAndroid) return false;
    try {
      _enabled =
          await _channel.invokeMethod<bool>('keepAliveIsRunning') ?? false;
      return _enabled;
    } catch (_) {
      return false;
    }
  }

  /// 通知权限刚授予时重发前台通知。
  ///
  /// Android 13+ 的 FGS 在未授予 POST_NOTIFICATIONS 时，其通知会被系统
  /// 隐藏；权限授予后需要重新 startForeground 一次才立即可见，否则要
  /// 把 App 划掉重开才出现。服务未运行时为 no-op。
  static Future<bool> refreshNotification() async {
    if (!Platform.isAndroid) return false;
    if (!await isEnabled()) return false;
    try {
      return await _channel.invokeMethod<bool>('keepAliveRefreshNotification', {
            'title': _notificationTitle ?? 'SoLab',
            'text': _composeNotificationText(),
            'networkRequired': _networkRequired,
          }) ??
          false;
    } catch (_) {
      return false;
    }
  }

  /// 是否已豁免电池优化（国产 ROM 冻结进程的主要防线）。
  static Future<bool> isIgnoringBatteryOptimizations() async {
    if (!Platform.isAndroid) return true;
    try {
      return await _channel.invokeMethod<bool>(
            'isIgnoringBatteryOptimizations',
          ) ??
          true;
    } catch (_) {
      return true;
    }
  }

  /// 引导用户豁免电池优化（仅在用户显式开启常驻保活时调用）。
  static Future<bool> requestIgnoreBatteryOptimizations() async {
    if (!Platform.isAndroid) return true;
    try {
      return await _channel.invokeMethod<bool>(
            'requestIgnoreBatteryOptimizations',
          ) ??
          false;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> isOverlayPermissionGranted() async {
    if (!Platform.isAndroid) return true;
    try {
      return await _channel.invokeMethod<bool>('isOverlayPermissionGranted') ??
          false;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> requestOverlayPermission() async {
    if (!Platform.isAndroid) return true;
    try {
      return await _channel.invokeMethod<bool>('requestOverlayPermission') ??
          false;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> isKeepAliveOverlayEnabled() async {
    if (!Platform.isAndroid) return false;
    try {
      return await _channel.invokeMethod<bool>('isKeepAliveOverlayEnabled') ??
          true;
    } catch (_) {
      return true;
    }
  }

  static Future<bool> setKeepAliveOverlayEnabled(bool enabled) async {
    if (!Platform.isAndroid) return false;
    try {
      return await _channel.invokeMethod<bool>('setKeepAliveOverlayEnabled', {
            'enabled': enabled,
          }) ??
          false;
    } catch (_) {
      return false;
    }
  }

  static Future<bool> requestKeepAlivePermissions({bool force = false}) async {
    if (!Platform.isAndroid) return true;
    try {
      return await _channel.invokeMethod<bool>('requestKeepAlivePermissions', {
            'force': force,
          }) ??
          false;
    } catch (_) {
      return false;
    }
  }
}
