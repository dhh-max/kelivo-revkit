/// SoLab 内置模型服务商元数据（T2.1 外移）。
///
/// 从 settings_provider.dart 抽出的 SoLab 自带 provider 声明数据——
/// 使通用 provider 只保留「注册内置服务商」的挂载点，sync_upstream 冲突
/// 时本文件集中维护。
///
/// 注意：本文件不含任何可用的真实凭据——apiKey 值为公开的演示用占位
/// （'kelivo'），真实密钥只来自用户配置/环境。
library;

/// SoLabIN 服务商在 settings 中的规范化 id 别名。
const List<String> solabInProviderAliases = <String>['solabin', 'kelivoin'];

/// SoLabIN 的公开演示占位 key（非真实凭据，用户需自行填入有效 key）。
const String solabInPublicApiKey = 'kelivo';

/// SoLabIN 的默认 chat 模型。
const List<String> solabInDefaultModels = <String>['mistral', 'qwen-coder'];

/// SoLabIN 默认模型覆盖（类型/模态/能力）。
const Map<String, Map<String, Object>> solabInModelOverrides =
    <String, Map<String, Object>>{
      'mistral': <String, Object>{
        'type': 'chat',
        'input': <String>['text'],
        'output': <String>['text'],
        'abilities': <String>['tool'],
      },
      'qwen-coder': <String, Object>{
        'type': 'chat',
        'input': <String>['text'],
        'output': <String>['text'],
        'abilities': <String>['tool'],
      },
    };

/// 判断 provider id 是否属于 SoLabIN（含别名）。
bool isSolabInProvider(String id) {
  final normalized = id.trim().toLowerCase();
  return solabInProviderAliases.any(normalized.contains);
}

/// 判断 provider 是否应 seed 为内置默认（首启自动创建）。
bool isSeededBuiltinProvider(String id) {
  final normalized = id.trim().toLowerCase();
  return isSolabInProvider(normalized) || normalized.contains('tensdaq');
}
