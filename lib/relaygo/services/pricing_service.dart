import 'dart:convert';

/// 模型价格预估（单位：美元/百万 token）
///
/// 内置常见模型估算单价，按模型前缀匹配（最长前缀优先）；
/// 未匹配模型使用默认价。价格为公开参考价的近似值，仅用于仪表盘费用预估。
/// 支持用户自定义覆盖规则（持久化到 Hive settings box）。
class PricingService {
  /// 模型前缀 -> (输入价, 输出价) 美元/百万 token
  static const Map<String, List<double>> modelPrices = {
    // ================= 国内模型 =================
    // DeepSeek
    'deepseek-chat': [0.27, 1.10],
    'deepseek-reasoner': [0.55, 2.19],
    'deepseek-r1': [0.55, 2.19],
    'deepseek': [0.27, 1.10],
    // 智谱 GLM
    'glm-4.6': [0.60, 2.20],
    'glm-4.5': [0.60, 2.20],
    'glm-4-plus': [0.50, 2.00],
    'glm-4-air': [0.02, 0.02],
    'glm-4-flash': [0.01, 0.01],
    'glm-4-long': [0.01, 0.01],
    'glm': [0.30, 0.90],
    // 阿里通义千问
    'qwen-max': [2.80, 8.30],
    'qwen-plus': [0.10, 0.30],
    'qwen-turbo': [0.05, 0.10],
    'qwen-long': [0.01, 0.02],
    'qwen': [0.20, 0.60],
    // 月之暗面 Kimi
    'kimi-k2': [0.60, 2.50],
    'kimi': [0.60, 2.00],
    'moonshot': [0.60, 2.00],
    // 字节豆包
    'doubao-1.5': [0.20, 0.60],
    'doubao-seed': [0.20, 0.60],
    'doubao-pro': [0.15, 0.30],
    'doubao': [0.50, 2.00],
    // 讯飞星火
    'spark-max': [0.30, 0.60],
    'spark-pro': [0.15, 0.30],
    'spark-lite': [0.01, 0.01],
    'spark': [0.30, 0.60],
    // 百度文心一言
    'ernie-4': [4.00, 12.00],
    'ernie-3.5': [1.70, 1.70],
    'ernie-speed': [0.10, 0.10],
    'ernie': [1.70, 1.70],
    // 腾讯混元
    'hunyuan-turbo': [0.70, 2.80],
    'hunyuan-lite': [0.01, 0.01],
    'hunyuan': [0.70, 2.80],
    // 商汤日日新
    'sensenova': [1.00, 3.00],
    // MiniMax
    'minimax': [0.20, 0.60],
    // 阶跃星辰
    'step': [0.40, 1.20],
    // 零一万物
    'yi': [0.40, 1.20],
    // 百川
    'baichuan': [0.50, 1.50],
    // 面壁智能
    'minicpm': [0.10, 0.30],

    // ================= 国外模型 =================
    // OpenAI GPT
    'gpt-5-mini': [0.25, 2.00],
    'gpt-5-nano': [0.05, 0.40],
    'gpt-5': [1.25, 10.00],
    'gpt-4.1-mini': [0.40, 1.60],
    'gpt-4.1-nano': [0.10, 0.40],
    'gpt-4.1': [2.00, 8.00],
    'gpt-4o-mini': [0.15, 0.60],
    'gpt-4o': [2.50, 10.00],
    'gpt-4-turbo': [10.00, 30.00],
    'gpt-4': [30.00, 60.00],
    'gpt-3.5': [0.50, 1.50],
    'gpt': [2.50, 10.00],
    // OpenAI o 系列推理
    'o1-mini': [3.00, 12.00],
    'o1': [15.00, 60.00],
    'o3-mini': [1.10, 4.40],
    'o3': [2.00, 8.00],
    'o4-mini': [1.10, 4.40],
    // Anthropic Claude
    'claude-3-opus': [15.00, 75.00],
    'claude-3-5-haiku': [0.80, 4.00],
    'claude-3-haiku': [0.25, 1.25],
    'claude-opus': [15.00, 75.00],
    'claude-sonnet': [3.00, 15.00],
    'claude-haiku': [0.80, 4.00],
    'claude': [3.00, 15.00],
    // Google Gemini
    'gemini-3-pro': [2.00, 12.00],
    'gemini-3-flash': [0.50, 3.00],
    'gemini-2.5-pro': [1.25, 10.00],
    'gemini-2.5-flash-lite': [0.10, 0.40],
    'gemini-2.5-flash': [0.30, 2.50],
    'gemini-2.0-flash': [0.10, 0.40],
    'gemini-1.5-flash': [0.075, 0.30],
    'gemini': [1.25, 5.00],
    // Meta Llama
    'llama-4-maverick': [0.23, 0.23],
    'llama-4-scout': [0.13, 0.13],
    'llama-3.3': [0.60, 0.60],
    'llama-3.1-405b': [3.50, 3.50],
    'llama-3.1-70b': [0.60, 0.60],
    'llama-3.1-8b': [0.05, 0.05],
    'llama': [0.60, 0.60],
    // xAI Grok
    'grok-3-mini': [0.30, 0.50],
    'grok-3': [3.00, 15.00],
    'grok-2': [2.00, 10.00],
    'grok': [3.00, 15.00],
    // Mistral
    'mistral-large': [2.00, 6.00],
    'mistral-medium': [2.50, 7.50],
    'mistral-small': [0.10, 0.30],
    'codestral': [0.30, 0.90],
    'ministral': [0.10, 0.10],
    'mistral': [0.60, 1.60],
    // Amazon Nova
    'nova-pro': [0.80, 3.20],
    'nova-lite': [0.06, 0.24],
    'nova-micro': [0.035, 0.14],
    'nova': [0.80, 3.20],
  };

  static const List<double> defaultPrice = [1.00, 3.00];

  /// 按前缀长度降序预排序
  static List<MapEntry<String, List<double>>> get _sortedPrices {
    final items = modelPrices.entries.toList();
    items.sort((a, b) => b.key.length.compareTo(a.key.length));
    return items;
  }

  /// 用户自定义覆盖：prefix -> [输入价, 输出价]
  Map<String, List<double>> _overrides = {};

  /// 设置用户自定义价格覆盖
  void setOverrides(Map<String, List<double>> rules) {
    _overrides = {
      for (final e in rules.entries)
        if (e.key.trim().isNotEmpty && e.value.length >= 2)
          e.key.trim().toLowerCase(): [e.value[0].toDouble(), e.value[1].toDouble()],
    };
  }

  Map<String, List<double>> get overrides => Map.from(_overrides);

  /// 按模型前缀匹配单价（最长前缀优先），未匹配返回默认价。
  /// 用户覆盖优先级高于内置价格。
  List<double> priceFor(String model) {
    final m = model.toLowerCase();
    // 先匹配用户覆盖
    final overrideItems = _overrides.entries.toList()
      ..sort((a, b) => b.key.length.compareTo(a.key.length));
    for (final e in overrideItems) {
      if (m.startsWith(e.key)) return e.value;
    }
    // 再匹配内置价格
    for (final e in _sortedPrices) {
      if (m.startsWith(e.key)) return e.value;
    }
    return defaultPrice;
  }

  /// 估算费用（美元）。返回 (cost, inputPrice, outputPrice)。
  ({double cost, double inputPrice, double outputPrice}) estimateCost(
      String model, int promptTokens, int completionTokens) {
    final prices = priceFor(model);
    final inputPrice = prices[0];
    final outputPrice = prices[1];
    final cost = (promptTokens * inputPrice + completionTokens * outputPrice) / 1000000;
    return (cost: _round(cost, 6), inputPrice: inputPrice, outputPrice: outputPrice);
  }

  /// 从 Hive settings box 加载覆盖规则
  static Map<String, List<double>> loadOverridesFromJson(dynamic json) {
    if (json is! Map) return {};
    final out = <String, List<double>>{};
    for (final e in json.entries) {
      if (e.value is List && (e.value as List).length >= 2) {
        out[e.key.toString()] = [
          (e.value as List)[0].toString().asDouble(),
          (e.value as List)[1].toString().asDouble(),
        ];
      }
    }
    return out;
  }

  /// 序列化覆盖规则为 JSON 字符串
  String overridesToJson() => jsonEncode(_overrides);

  double _round(double v, int places) {
    final p = pow10(places);
    return (v * p).round() / p;
  }

  static int pow10(int n) {
    var r = 1;
    for (var i = 0; i < n; i++) {
      r *= 10;
    }
    return r;
  }
}

extension on String {
  double asDouble() => double.tryParse(this) ?? 0.0;
}
