import 'package:hive_flutter/hive_flutter.dart';
import 'package:Kelivo/relaygo/database/database_helper.dart';
import 'package:Kelivo/relaygo/services/pricing_service.dart';

/// 每日统计条目
class DailyStatEntry {
  final String date; // yyyy-MM-dd
  final String provider;
  final String keyId;
  int requests;
  int errors;
  int promptTokens;
  int completionTokens;
  double costUsd;

  DailyStatEntry({
    required this.date,
    required this.provider,
    required this.keyId,
    this.requests = 0,
    this.errors = 0,
    this.promptTokens = 0,
    this.completionTokens = 0,
    this.costUsd = 0.0,
  });

  Map<String, dynamic> toJson() => {
        'date': date,
        'provider': provider,
        'key_id': keyId,
        'requests': requests,
        'errors': errors,
        'prompt_tokens': promptTokens,
        'completion_tokens': completionTokens,
        'cost_usd': costUsd,
      };

  factory DailyStatEntry.fromJson(Map<String, dynamic> json) {
    return DailyStatEntry(
      date: json['date'] as String? ?? '',
      provider: json['provider'] as String? ?? '',
      keyId: json['key_id'] as String? ?? '',
      requests: (json['requests'] as num?)?.toInt() ?? 0,
      errors: (json['errors'] as num?)?.toInt() ?? 0,
      promptTokens: (json['prompt_tokens'] as num?)?.toInt() ?? 0,
      completionTokens: (json['completion_tokens'] as num?)?.toInt() ?? 0,
      costUsd: (json['cost_usd'] as num?)?.toDouble() ?? 0.0,
    );
  }

  String get key => '$date|$provider|$keyId';
}

/// 每日用量统计服务
///
/// 持久化到 Hive settings box，按 (date, provider, key_id) 聚合统计。
/// 供趋势图、CSV 导出、费用报表使用。
class DailyStatsService {
  final Box _box;
  final PricingService _pricing;

  static const String _key = 'daily_stats';

  /// 内存缓存：key -> entry
  Map<String, DailyStatEntry> _cache = {};
  bool _loaded = false;

  DailyStatsService({
    Box? box,
    PricingService? pricing,
  })  : _box = box ?? DatabaseHelper.settings,
        _pricing = pricing ?? PricingService();

  void _ensureLoaded() {
    if (_loaded) return;
    final data = _box.get(_key);
    if (data is Map) {
      for (final v in data.values) {
        if (v is Map) {
          final e = DailyStatEntry.fromJson(Map<String, dynamic>.from(v));
          _cache[e.key] = e;
        }
      }
    }
    _loaded = true;
  }

  /// 记录一次请求的用量
  void record({
    required String provider,
    required String keyId,
    required String model,
    required int promptTokens,
    required int completionTokens,
    bool isError = false,
    double? costUsd,
    DateTime? at,
  }) {
    final now = at ?? DateTime.now();
    final date = _dateKey(now);
    final k = '$date|$provider|$keyId';
    final entry = _cache.putIfAbsent(k,
        () => DailyStatEntry(date: date, provider: provider, keyId: keyId));
    entry.requests += 1;
    if (isError) entry.errors += 1;
    entry.promptTokens += promptTokens;
    entry.completionTokens += completionTokens;
    if (costUsd != null) {
      entry.costUsd += costUsd;
    } else {
      final est = _pricing.estimateCost(model, promptTokens, completionTokens);
      entry.costUsd += est.cost;
    }
  }

  /// 落库（批量异步写）
  Future<void> flush() async {
    final data = <String, dynamic>{};
    for (final e in _cache.entries) {
      data[e.key] = e.value.toJson();
    }
    await _box.put(_key, data);
  }

  /// 按日期范围返回每日统计明细
  List<DailyStatEntry> range(String dateFrom, String dateTo) {
    _ensureLoaded();
    return _cache.values
        .where((e) => e.date.compareTo(dateFrom) >= 0 && e.date.compareTo(dateTo) <= 0)
        .toList()
      ..sort((a, b) => a.date.compareTo(b.date));
  }

  /// 按日期范围汇总
  Map<String, dynamic> summary(int days) {
    final now = DateTime.now();
    final end = DateTime(now.year, now.month, now.day);
    final start = end.subtract(Duration(days: days - 1));
    final entries = range(_dateKey(start), _dateKey(end));
    final totalRequests = entries.fold(0, (s, e) => s + e.requests);
    final totalErrors = entries.fold(0, (s, e) => s + e.errors);
    final totalPrompt = entries.fold(0, (s, e) => s + e.promptTokens);
    final totalCompletion = entries.fold(0, (s, e) => s + e.completionTokens);
    final totalCost = entries.fold(0.0, (s, e) => s + e.costUsd);
    // 按提供商聚合
    final byProvider = <String, Map<String, dynamic>>{};
    for (final e in entries) {
      final agg = byProvider.putIfAbsent(e.provider, () => {
        'requests': 0, 'errors': 0,
        'prompt_tokens': 0, 'completion_tokens': 0,
        'cost_usd': 0.0,
      });
      agg['requests'] = (agg['requests'] as int) + e.requests;
      agg['errors'] = (agg['errors'] as int) + e.errors;
      agg['prompt_tokens'] = (agg['prompt_tokens'] as int) + e.promptTokens;
      agg['completion_tokens'] = (agg['completion_tokens'] as int) + e.completionTokens;
      agg['cost_usd'] = (agg['cost_usd'] as double) + e.costUsd;
    }
    return {
      'providers': byProvider.entries
          .map((e) => {'provider': e.key, ...e.value})
          .toList(),
      'total': {
        'requests': totalRequests,
        'errors': totalErrors,
        'prompt_tokens': totalPrompt,
        'completion_tokens': totalCompletion,
        'cost_usd': totalCost,
      },
    };
  }

  /// 获取近 N 天每日趋势（按天聚合，供趋势图）
  List<Map<String, dynamic>> dailyTrend(int days) {
    final now = DateTime.now();
    final end = DateTime(now.year, now.month, now.day);
    final start = end.subtract(Duration(days: days - 1));
    final entries = range(_dateKey(start), _dateKey(end));
    final byDate = <String, DailyStatEntry?>{};
    for (final e in entries) {
      // 聚合同日
    }
    // 按日聚合
    final dailyAgg = <String, Map<String, dynamic>>{};
    for (final e in entries) {
      final agg = dailyAgg.putIfAbsent(e.date, () => {
        'requests': 0, 'errors': 0,
        'prompt_tokens': 0, 'completion_tokens': 0,
        'cost_usd': 0.0,
      });
      agg['requests'] = (agg['requests'] as int) + e.requests;
      agg['errors'] = (agg['errors'] as int) + e.errors;
      agg['prompt_tokens'] = (agg['prompt_tokens'] as int) + e.promptTokens;
      agg['completion_tokens'] = (agg['completion_tokens'] as int) + e.completionTokens;
      agg['cost_usd'] = (agg['cost_usd'] as double) + e.costUsd;
    }
    // 补齐缺失天数
    final series = <Map<String, dynamic>>[];
    for (var i = 0; i < days; i++) {
      final d = start.add(Duration(days: i));
      final dk = _dateKey(d);
      final agg = dailyAgg[dk] ?? {
        'requests': 0, 'errors': 0,
        'prompt_tokens': 0, 'completion_tokens': 0,
        'cost_usd': 0.0,
      };
      series.add({
        'date': dk,
        'label': '${dk.substring(5)}',
        'requests': agg['requests'],
        'errors': agg['errors'],
        'tokens': (agg['prompt_tokens'] as int) + (agg['completion_tokens'] as int),
        'cost_usd': (agg['cost_usd'] as double),
      });
    }
    return series;
  }

  String _dateKey(DateTime d) =>
      '${d.year.toString().padLeft(4, '0')}-'
      '${d.month.toString().padLeft(2, '0')}-'
      '${d.day.toString().padLeft(2, '0')}';
}
