import 'package:Kelivo/relaygo/config/constants.dart';

/// 用户设置
class UserSettings {
  int port; // 代理监听端口
  String host; // 监听地址
  String loadBalanceStrategy; // 负载均衡策略
  String language; // 'zh' / 'en'
  bool appLockEnabled; // 应用锁（生物识别 / PIN）
  String? appLockPin;

  // —— Phase 2：日志管理（需求 2.2.1）——
  int logRetentionDays; // 自动清理超过 N 天的日志
  int maxLogEntries; // 日志条数上限

  // —— Phase 2：额度监控与告警（需求 2.2.2）——
  double quotaWarnThreshold; // 0-1，额度使用率达到该值告警
  double errorRateThreshold; // 0-1，今日错误率超过该值告警
  bool alertsEnabled;

  // —— Phase 2：规则引擎与限流 ——
  bool rulesEnabled;
  bool rateLimitEnabled; // 按 key 的 max_requests_per_minute 限流
  int upstreamTimeoutSeconds;
  int maxRetryKeys; // 单请求最多切换的 key 数

  // —— Phase 3：响应缓存（需求 2.2.4）——
  bool cacheEnabled;
  int cacheTtlSeconds;
  int cacheMaxEntries;

  // —— Phase 3：高级限流（需求 2.2.6）——
  int ipRateLimitPerMinute; // 单 IP 每分钟请求上限，0 = 不限
  int globalRpmLimit; // 全局每分钟请求上限，0 = 不限
  int tokenRateLimitPerMinute; // 单 key 每分钟 token 上限，0 = 不限
  double burstMultiplier; // 令牌桶突发倍数
  bool adaptiveTpmEnabled; // 自适应 TPM 挡板 + 429 等待重试（默认开启）

  // —— 在线更新（启动时自动检查，配置项不暴露在设置页）——
  String updateFeedUrl;
  String updateChannel; // stable / beta
  bool autoCheckUpdate; // 启动时自动检查
  String updateGithubRepo; // GitHub 发布仓库 owner/repo（方案一）；空串则回退 updateFeedUrl 清单

  // —— 模型列表同步（需求 REQ-003）——
  bool autoSyncModelsOnStartup; // 启动时自动同步模型列表
  int modelSyncIntervalHours; // 定时同步间隔（小时），0 = 不定时
  bool autoDisableRemovedModels; // 同步后自动禁用已下线的模型

  // —— 虚拟模型层（能力分层）——
  // 默认关闭，回归纯转发：/v1/models 返回真实模型、请求模型名原样透传。
  // 开启后才会把模型按能力档位收敛成 10 个虚拟模型并把请求改写为真实模型。
  bool virtualModelsEnabled;

  // —— 保活（后台持续运行）——
  bool keepAliveEnabled; // 前台服务保活开关（默认开启）
  bool autoStartOnBoot; // 开机自启（默认关闭，需用户开启）
  bool ignoreBatteryOptimization; // 请求加入电池优化白名单（默认关闭）

  // —— 管理接口鉴权 ——
  /// 管理令牌：设置后，/relay/* 管理接口需要携带此令牌才能访问。
  /// 支持两种传递方式：
  ///   1. 请求头 `x-relay-admin-token: <token>`
  ///   2. 标准 `Authorization: Bearer <token>`
  /// 为空或长度不足时，管理接口无鉴权（向后兼容旧版本）。
  String? adminToken;

  // —— 从 InterGate Python 版移植的新功能设置 ——

  // 网关鉴权
  bool gatewayKeyEnabled; // 网关是否启用访问密钥鉴权(开关持久化)
  String gatewayKey; // 网关访问密钥(留空=不鉴权)

  // 告警 Webhook
  bool webhookEnabled;
  String webhookUrl;
  String webhookSecret;

  // 上游连接池
  int upstreamMaxConnections;
  int upstreamMaxKeepalive;

  // Web 控制台
  bool webEnabled;
  int webPort;
  String webPassword;

  UserSettings({
    this.port = Constants.defaultPort,
    this.host = Constants.defaultHost,
    this.loadBalanceStrategy = 'round_robin',
    this.language = 'zh',
    this.appLockEnabled = false,
    this.appLockPin,
    this.logRetentionDays = Constants.defaultLogRetentionDays,
    this.maxLogEntries = Constants.defaultMaxLogEntries,
    this.quotaWarnThreshold = Constants.defaultQuotaWarnThreshold,
    this.errorRateThreshold = 0.5,
    this.alertsEnabled = true,
    this.rulesEnabled = true,
    this.rateLimitEnabled = true,
    this.upstreamTimeoutSeconds = Constants.upstreamTimeoutSeconds,
    this.maxRetryKeys = Constants.maxRetryKeys,
    this.cacheEnabled = false,
    this.cacheTtlSeconds = Constants.defaultCacheTtlSeconds,
    this.cacheMaxEntries = Constants.defaultCacheMaxEntries,
    this.ipRateLimitPerMinute = Constants.defaultIpRateLimitPerMinute,
    this.globalRpmLimit = Constants.defaultGlobalRpmLimit,
    this.tokenRateLimitPerMinute = Constants.defaultTokenRateLimitPerMinute,
    this.burstMultiplier = Constants.defaultBurstMultiplier,
    this.adaptiveTpmEnabled = Constants.defaultAdaptiveTpmEnabled,
    this.updateFeedUrl = Constants.defaultUpdateFeedUrl,
    this.updateChannel = Constants.defaultUpdateChannel,
    this.autoCheckUpdate = true,
    this.updateGithubRepo = Constants.defaultUpdateGithubRepo,
    this.autoSyncModelsOnStartup = true,
    this.modelSyncIntervalHours = 24,
    this.autoDisableRemovedModels = true,
    this.virtualModelsEnabled = false,
    this.keepAliveEnabled = true,
    this.autoStartOnBoot = false,
    this.ignoreBatteryOptimization = false,
    this.adminToken,
    this.gatewayKeyEnabled = false,
    this.gatewayKey = '',
    this.webhookEnabled = false,
    this.webhookUrl = '',
    this.webhookSecret = '',
    this.upstreamMaxConnections = Constants.defaultUpstreamMaxConnections,
    this.upstreamMaxKeepalive = Constants.defaultUpstreamMaxKeepalive,
    this.webEnabled = false,
    this.webPort = Constants.defaultWebPort,
    this.webPassword = '',
  });

  factory UserSettings.fromJson(Map<String, dynamic> json) {
    return UserSettings(
      port: json['port'] as int? ?? Constants.defaultPort,
      host: json['host'] as String? ?? Constants.defaultHost,
      loadBalanceStrategy:
          json['load_balance_strategy'] as String? ?? 'round_robin',
      language: json['language'] as String? ?? 'zh',
      appLockEnabled: json['app_lock_enabled'] as bool? ?? false,
      appLockPin: json['app_lock_pin'] as String?,
      logRetentionDays:
          json['log_retention_days'] as int? ?? Constants.defaultLogRetentionDays,
      maxLogEntries:
          json['max_log_entries'] as int? ?? Constants.defaultMaxLogEntries,
      quotaWarnThreshold: (json['quota_warn_threshold'] as num?)?.toDouble() ??
          Constants.defaultQuotaWarnThreshold,
      errorRateThreshold:
          (json['error_rate_threshold'] as num?)?.toDouble() ?? 0.5,
      alertsEnabled: json['alerts_enabled'] as bool? ?? true,
      rulesEnabled: json['rules_enabled'] as bool? ?? true,
      rateLimitEnabled: json['rate_limit_enabled'] as bool? ?? true,
      upstreamTimeoutSeconds: json['upstream_timeout_seconds'] as int? ??
          Constants.upstreamTimeoutSeconds,
      maxRetryKeys: json['max_retry_keys'] as int? ?? Constants.maxRetryKeys,
      cacheEnabled: json['cache_enabled'] as bool? ?? false,
      cacheTtlSeconds: json['cache_ttl_seconds'] as int? ??
          Constants.defaultCacheTtlSeconds,
      cacheMaxEntries: json['cache_max_entries'] as int? ??
          Constants.defaultCacheMaxEntries,
      ipRateLimitPerMinute: json['ip_rate_limit_per_minute'] as int? ??
          Constants.defaultIpRateLimitPerMinute,
      globalRpmLimit:
          json['global_rpm_limit'] as int? ?? Constants.defaultGlobalRpmLimit,
      tokenRateLimitPerMinute: json['token_rate_limit_per_minute'] as int? ??
          Constants.defaultTokenRateLimitPerMinute,
      burstMultiplier: (json['burst_multiplier'] as num?)?.toDouble() ??
          Constants.defaultBurstMultiplier,
      adaptiveTpmEnabled: json['adaptive_tpm_enabled'] as bool? ??
          Constants.defaultAdaptiveTpmEnabled,
      updateFeedUrl:
          json['update_feed_url'] as String? ?? Constants.defaultUpdateFeedUrl,
      updateChannel: json['update_channel'] as String? ??
          Constants.defaultUpdateChannel,
      autoCheckUpdate: json['auto_check_update'] as bool? ?? true,
      updateGithubRepo:
          json['update_github_repo'] as String? ?? Constants.defaultUpdateGithubRepo,
      autoSyncModelsOnStartup:
          json['auto_sync_models_on_startup'] as bool? ?? true,
      modelSyncIntervalHours:
          json['model_sync_interval_hours'] as int? ?? 24,
      autoDisableRemovedModels:
          json['auto_disable_removed_models'] as bool? ?? true,
      virtualModelsEnabled:
          json['virtual_models_enabled'] as bool? ?? false,
      keepAliveEnabled: json['keep_alive_enabled'] as bool? ?? true,
      autoStartOnBoot: json['auto_start_on_boot'] as bool? ?? false,
      ignoreBatteryOptimization:
          json['ignore_battery_optimization'] as bool? ?? false,
      adminToken: json['admin_token'] as String?,
      gatewayKeyEnabled: json['gateway_key_enabled'] as bool? ?? false,
      gatewayKey: json['gateway_key'] as String? ?? '',
      webhookEnabled: json['webhook_enabled'] as bool? ?? false,
      webhookUrl: json['webhook_url'] as String? ?? '',
      webhookSecret: json['webhook_secret'] as String? ?? '',
      upstreamMaxConnections: json['upstream_max_connections'] as int? ??
          Constants.defaultUpstreamMaxConnections,
      upstreamMaxKeepalive: json['upstream_max_keepalive'] as int? ??
          Constants.defaultUpstreamMaxKeepalive,
      webEnabled: json['web_enabled'] as bool? ?? false,
      webPort: json['web_port'] as int? ?? Constants.defaultWebPort,
      webPassword: json['web_password'] as String? ?? '',
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'port': port,
      'host': host,
      'load_balance_strategy': loadBalanceStrategy,
      'language': language,
      'app_lock_enabled': appLockEnabled,
      'app_lock_pin': appLockPin,
      'log_retention_days': logRetentionDays,
      'max_log_entries': maxLogEntries,
      'quota_warn_threshold': quotaWarnThreshold,
      'error_rate_threshold': errorRateThreshold,
      'alerts_enabled': alertsEnabled,
      'rules_enabled': rulesEnabled,
      'rate_limit_enabled': rateLimitEnabled,
      'upstream_timeout_seconds': upstreamTimeoutSeconds,
      'max_retry_keys': maxRetryKeys,
      'cache_enabled': cacheEnabled,
      'cache_ttl_seconds': cacheTtlSeconds,
      'cache_max_entries': cacheMaxEntries,
      'ip_rate_limit_per_minute': ipRateLimitPerMinute,
      'global_rpm_limit': globalRpmLimit,
      'token_rate_limit_per_minute': tokenRateLimitPerMinute,
      'burst_multiplier': burstMultiplier,
      'adaptive_tpm_enabled': adaptiveTpmEnabled,
      'update_feed_url': updateFeedUrl,
      'update_channel': updateChannel,
      'auto_check_update': autoCheckUpdate,
      'update_github_repo': updateGithubRepo,
      'auto_sync_models_on_startup': autoSyncModelsOnStartup,
      'model_sync_interval_hours': modelSyncIntervalHours,
      'auto_disable_removed_models': autoDisableRemovedModels,
      'virtual_models_enabled': virtualModelsEnabled,
      'keep_alive_enabled': keepAliveEnabled,
      'auto_start_on_boot': autoStartOnBoot,
      'ignore_battery_optimization': ignoreBatteryOptimization,
      'admin_token': adminToken,
      'gateway_key_enabled': gatewayKeyEnabled,
      'gateway_key': gatewayKey,
      'webhook_enabled': webhookEnabled,
      'webhook_url': webhookUrl,
      'webhook_secret': webhookSecret,
      'upstream_max_connections': upstreamMaxConnections,
      'upstream_max_keepalive': upstreamMaxKeepalive,
      'web_enabled': webEnabled,
      'web_port': webPort,
      'web_password': webPassword,
    };
  }

  /// Alias for [toJson], used by the admin settings API endpoint.
  Map<String, dynamic> toMap() => toJson();

  UserSettings copyWith({
    int? port,
    String? host,
    String? loadBalanceStrategy,
    String? language,
    bool? appLockEnabled,
    String? appLockPin,
    int? logRetentionDays,
    int? maxLogEntries,
    double? quotaWarnThreshold,
    double? errorRateThreshold,
    bool? alertsEnabled,
    bool? rulesEnabled,
    bool? rateLimitEnabled,
    int? upstreamTimeoutSeconds,
    int? maxRetryKeys,
    bool? cacheEnabled,
    int? cacheTtlSeconds,
    int? cacheMaxEntries,
    int? ipRateLimitPerMinute,
    int? globalRpmLimit,
    int? tokenRateLimitPerMinute,
    double? burstMultiplier,
    bool? adaptiveTpmEnabled,
    String? updateFeedUrl,
    String? updateChannel,
    bool? autoCheckUpdate,
    String? updateGithubRepo,
    bool? autoSyncModelsOnStartup,
    int? modelSyncIntervalHours,
    bool? autoDisableRemovedModels,
    bool? virtualModelsEnabled,
    bool? keepAliveEnabled,
    bool? autoStartOnBoot,
    bool? ignoreBatteryOptimization,
    String? adminToken,
    bool? gatewayKeyEnabled,
    String? gatewayKey,
    bool? webhookEnabled,
    String? webhookUrl,
    String? webhookSecret,
    int? upstreamMaxConnections,
    int? upstreamMaxKeepalive,
    bool? webEnabled,
    int? webPort,
    String? webPassword,
  }) {
    return UserSettings(
      port: port ?? this.port,
      host: host ?? this.host,
      loadBalanceStrategy: loadBalanceStrategy ?? this.loadBalanceStrategy,
      language: language ?? this.language,
      appLockEnabled: appLockEnabled ?? this.appLockEnabled,
      appLockPin: appLockPin ?? this.appLockPin,
      logRetentionDays: logRetentionDays ?? this.logRetentionDays,
      maxLogEntries: maxLogEntries ?? this.maxLogEntries,
      quotaWarnThreshold: quotaWarnThreshold ?? this.quotaWarnThreshold,
      errorRateThreshold: errorRateThreshold ?? this.errorRateThreshold,
      alertsEnabled: alertsEnabled ?? this.alertsEnabled,
      rulesEnabled: rulesEnabled ?? this.rulesEnabled,
      rateLimitEnabled: rateLimitEnabled ?? this.rateLimitEnabled,
      upstreamTimeoutSeconds:
          upstreamTimeoutSeconds ?? this.upstreamTimeoutSeconds,
      maxRetryKeys: maxRetryKeys ?? this.maxRetryKeys,
      cacheEnabled: cacheEnabled ?? this.cacheEnabled,
      cacheTtlSeconds: cacheTtlSeconds ?? this.cacheTtlSeconds,
      cacheMaxEntries: cacheMaxEntries ?? this.cacheMaxEntries,
      ipRateLimitPerMinute: ipRateLimitPerMinute ?? this.ipRateLimitPerMinute,
      globalRpmLimit: globalRpmLimit ?? this.globalRpmLimit,
      tokenRateLimitPerMinute:
          tokenRateLimitPerMinute ?? this.tokenRateLimitPerMinute,
      burstMultiplier: burstMultiplier ?? this.burstMultiplier,
      adaptiveTpmEnabled: adaptiveTpmEnabled ?? this.adaptiveTpmEnabled,
      updateFeedUrl: updateFeedUrl ?? this.updateFeedUrl,
      updateChannel: updateChannel ?? this.updateChannel,
      autoCheckUpdate: autoCheckUpdate ?? this.autoCheckUpdate,
      updateGithubRepo: updateGithubRepo ?? this.updateGithubRepo,
      autoSyncModelsOnStartup:
          autoSyncModelsOnStartup ?? this.autoSyncModelsOnStartup,
      modelSyncIntervalHours:
          modelSyncIntervalHours ?? this.modelSyncIntervalHours,
      autoDisableRemovedModels:
          autoDisableRemovedModels ?? this.autoDisableRemovedModels,
      virtualModelsEnabled:
          virtualModelsEnabled ?? this.virtualModelsEnabled,
      keepAliveEnabled: keepAliveEnabled ?? this.keepAliveEnabled,
      autoStartOnBoot: autoStartOnBoot ?? this.autoStartOnBoot,
      ignoreBatteryOptimization:
          ignoreBatteryOptimization ?? this.ignoreBatteryOptimization,
      adminToken: adminToken ?? this.adminToken,
      gatewayKeyEnabled: gatewayKeyEnabled ?? this.gatewayKeyEnabled,
      gatewayKey: gatewayKey ?? this.gatewayKey,
      webhookEnabled: webhookEnabled ?? this.webhookEnabled,
      webhookUrl: webhookUrl ?? this.webhookUrl,
      webhookSecret: webhookSecret ?? this.webhookSecret,
      upstreamMaxConnections: upstreamMaxConnections ?? this.upstreamMaxConnections,
      upstreamMaxKeepalive: upstreamMaxKeepalive ?? this.upstreamMaxKeepalive,
      webEnabled: webEnabled ?? this.webEnabled,
      webPort: webPort ?? this.webPort,
      webPassword: webPassword ?? this.webPassword,
    );
  }
}
