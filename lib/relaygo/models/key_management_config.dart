/// Load Balance Strategy & Key Management Config
///
/// 移植自 Solab 项目（solab-open-source）的 KeyManagementConfig 和 LoadBalanceStrategy。
/// 为 Kelivo 的 KeyManager 增加可配置的负载均衡策略和故障恢复参数。

/// 负载均衡策略
enum LoadBalanceStrategy {
  roundRobin,
  priority,
  leastUsed,
  random;

  String get name => toString().split('.').last;
  static LoadBalanceStrategy fromString(String value) {
    switch (value) {
      case 'round_robin':
      case 'roundRobin':
        return LoadBalanceStrategy.roundRobin;
      case 'priority':
        return LoadBalanceStrategy.priority;
      case 'least_used':
      case 'leastUsed':
        return LoadBalanceStrategy.leastUsed;
      case 'random':
        return LoadBalanceStrategy.random;
      default:
        return LoadBalanceStrategy.roundRobin;
    }
  }
}

/// Key 管理配置：故障恢复和负载均衡
class KeyManagementConfig {
  final LoadBalanceStrategy strategy;
  final int maxFailuresBeforeDisable;
  final int failureRecoveryTimeMinutes;
  final int? roundRobinIndex;

  const KeyManagementConfig({
    this.strategy = LoadBalanceStrategy.roundRobin,
    this.maxFailuresBeforeDisable = 3,
    this.failureRecoveryTimeMinutes = 5,
    this.roundRobinIndex,
  });

  KeyManagementConfig copyWith({
    LoadBalanceStrategy? strategy,
    int? maxFailuresBeforeDisable,
    int? failureRecoveryTimeMinutes,
    int? roundRobinIndex,
  }) => KeyManagementConfig(
    strategy: strategy ?? this.strategy,
    maxFailuresBeforeDisable:
        maxFailuresBeforeDisable ?? this.maxFailuresBeforeDisable,
    failureRecoveryTimeMinutes:
        failureRecoveryTimeMinutes ?? this.failureRecoveryTimeMinutes,
    roundRobinIndex: roundRobinIndex ?? this.roundRobinIndex,
  );

  Map<String, dynamic> toJson() => {
    'strategy': strategy.name,
    'maxFailuresBeforeDisable': maxFailuresBeforeDisable,
    'failureRecoveryTimeMinutes': failureRecoveryTimeMinutes,
    if (roundRobinIndex != null) 'roundRobinIndex': roundRobinIndex,
  };

  factory KeyManagementConfig.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const KeyManagementConfig();
    return KeyManagementConfig(
      strategy: LoadBalanceStrategy.fromString(
          (json['strategy'] as String?) ?? 'roundRobin'),
      maxFailuresBeforeDisable: (json['maxFailuresBeforeDisable'] as int?) ?? 3,
      failureRecoveryTimeMinutes:
          (json['failureRecoveryTimeMinutes'] as int?) ?? 5,
      roundRobinIndex: json['roundRobinIndex'] as int?,
    );
  }
}