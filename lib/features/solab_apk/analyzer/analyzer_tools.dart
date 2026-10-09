import 'dart:convert';

import 'analyzer_api.dart';
import 'analyzer_gateway_impl.dart';

// ============================================================================
// Analyzer Tools — 4 个高价值语义入口（按需分析模式）
//
// Agent 面对的是「意图」而非「工具」：
//   analyzer.open               打开 APK（按需模式，秒回就绪）
//   analyzer.global_search      跨 dex 聚合搜索（内部 dex_search）
//   analyzer.find_field_usage   字段 READ/WRITE 消费点（内部 field_xref + LRU）
//   analyzer.analyze_business_state 业务语义定位（内部编排 search→outline→xref）
//
// 底层 58 个原子工具作为内部执行器，不再暴露给 Agent。
// ============================================================================

class AnalyzerToolNames {
  AnalyzerToolNames._();

  static const String open = 'analyzer.open';
  static const String globalSearch = 'analyzer.global_search';
  static const String fieldUsage = 'analyzer.find_field_usage';
  static const String businessState = 'analyzer.analyze_business_state';

  static const List<String> all = <String>[
    open,
    globalSearch,
    fieldUsage,
    businessState,
  ];

  /// 对外发布名：点号换成下划线。严格 OpenAI 兼容网关（deepseek/agnes 等）
  /// 要求 function.name 匹配 ^[a-zA-Z0-9_-]+$，点号名会被 400 拒绝
  /// （实测 tools[20].function.name 不匹配 pattern）。host MCP 模式早已
  /// 用 analyzer_open 等别名，主 Agent 声明层必须一致。
  static String publishedName(String internal) {
    switch (internal) {
      case open:
        return 'analyzer_open';
      case globalSearch:
        return 'analyzer_global_search';
      case fieldUsage:
        return 'analyzer_find_field_usage';
      case businessState:
        return 'analyzer_analyze_business_state';
      default:
        return internal;
    }
  }

  /// 由发布名反查内部名；非 analyzer 名原样返回。
  static String internalName(String published) {
    for (final name in all) {
      if (publishedName(name) == published) return name;
    }
    return published;
  }
}

/// 工具 schema 构建 + 分派。
class AnalyzerGatewayTools {
  AnalyzerGatewayTools({AnalyzerGateway? gateway, String contextKey = 'app'})
    : gateway = gateway ?? AnalyzerGatewayRegistry.forKey(contextKey);

  final AnalyzerGateway gateway;

  static const Map<String, String> _descriptions = <String, String>{
    AnalyzerToolNames.open:
        '打开 APK 的按需分析上下文。仅在 Analyzer 尚未绑定当前 APK 时需要；已有 apkId 或其他工具的精确 locator 时不构成固定流程起点。',
    AnalyzerToolNames.globalSearch:
        '跨全部 DEX 搜索结构候选。混淆时 query 可用字符串、字段语义或已知片段；结果按 locator 保持身份,可任选类结构、字段使用、XREF 或 smali 验证,不规定后续顺序。',
    AnalyzerToolNames.fieldUsage:
        '查询字段 READ/WRITE 消费点,是可独立收口的数据流证据。fieldLocator 可来自任意可信产物；返回的方法 locator 可直接读 smali。字段读写已明确表达目标行为时无需补跑名称搜索。',
    AnalyzerToolNames.businessState:
        '业务状态候选聚合器,用于 VIP、登录、广告等。它给出一组假设和 locator,不是唯一入口；fieldName 仅在有证据时填写。若其他产物已给出精确方法或字段,可跳过本工具直接验证。'
        '本工具依赖字段名与内置词表的匹配,在 R8/ProGuard 混淆包上字段名会被重命名成 a/b/c 等短名,此时返回空是包的固有特性而非工具失败——'
        '读 detail.primary_candidate_names 看实际召回了什么,再改用 dex_search(字符串常量)→string_scan(交叉确认)→dex_xref(回溯引用) 这条不依赖字段名的路径。',
  };

  static const Map<String, Map<String, dynamic>> _paramSchemas =
      <String, Map<String, dynamic>>{
        AnalyzerToolNames.open: <String, dynamic>{
          'type': 'object',
          'properties': <String, dynamic>{
            'apkPath': <String, dynamic>{'type': 'string'},
          },
          'required': <String>['apkPath'],
        },
        AnalyzerToolNames.globalSearch: <String, dynamic>{
          'type': 'object',
          'properties': <String, dynamic>{
            'query': <String, dynamic>{'type': 'string'},
            'topK': <String, dynamic>{'type': 'integer'},
            'apkId': <String, dynamic>{
              'type': 'string',
              'description': '可选。使用 analyzer.open 返回的 apkId 绑定当前目标。',
            },
          },
          'required': <String>['query'],
        },
        AnalyzerToolNames.fieldUsage: <String, dynamic>{
          'type': 'object',
          'properties': <String, dynamic>{
            'fieldLocator': <String, dynamic>{'type': 'string'},
            'apkId': <String, dynamic>{
              'type': 'string',
              'description': '可选。使用 analyzer.open 返回的 apkId 绑定当前目标。',
            },
          },
          'required': <String>['fieldLocator'],
        },
        AnalyzerToolNames.businessState: <String, dynamic>{
          'type': 'object',
          'properties': <String, dynamic>{
            'targetKeyword': <String, dynamic>{'type': 'string'},
            'domain': <String, dynamic>{'type': 'string'},
            'fieldName': <String, dynamic>{'type': 'string'},
            'apkId': <String, dynamic>{
              'type': 'string',
              'description': '可选。使用 analyzer.open 返回的 apkId 绑定当前目标。',
            },
          },
          'required': <String>['targetKeyword'],
        },
      };

  /// 构建 tools 声明（对外用发布名 analyzer_open 等，规避严格网关对
  /// 点号名的 400 拒绝）。
  static List<Map<String, dynamic>> buildDefinitions(Set<String> enabledNames) {
    final defs = <Map<String, dynamic>>[];
    for (final name in AnalyzerToolNames.all) {
      if (!enabledNames.contains(name)) continue;
      defs.add(<String, dynamic>{
        'type': 'function',
        'function': <String, dynamic>{
          'name': AnalyzerToolNames.publishedName(name),
          'description': _descriptions[name] ?? '',
          'parameters': _paramSchemas[name] ?? const <String, dynamic>{},
        },
      });
    }
    return defs;
  }

  /// 分派：name（发布名或内部名皆可）→ 网关调用 → AnalyzerResult.encode()。
  Future<String> handle(String name, Map<String, dynamic> args) async {
    name = AnalyzerToolNames.internalName(name);
    // R5：必填参数缺失必须返回结构化 invalid_args，不得以空串静默执行——
    // 2026-09-15 真机实测：analyzer_find_field_usage 缺 fieldLocator 时以
    // 空调词跑完全程，返回 INSUFFICIENT 冒充「字段无引用」，误导调用方。
    final requiredParam = switch (name) {
      AnalyzerToolNames.open => 'apkPath',
      AnalyzerToolNames.globalSearch => 'query',
      AnalyzerToolNames.fieldUsage => 'fieldLocator',
      AnalyzerToolNames.businessState => 'targetKeyword',
      _ => '',
    };
    if (requiredParam.isNotEmpty &&
        (args[requiredParam] ?? '').toString().trim().isEmpty) {
      return jsonEncode(<String, dynamic>{
        'ok': false,
        'error': 'invalid_args',
        'message': '$requiredParam 必填。',
      });
    }
    AnalyzerResult r;
    switch (name) {
      case AnalyzerToolNames.open:
        r = await gateway.openWorkspace(
          apkPath: (args['apkPath'] ?? '').toString(),
        );
      case AnalyzerToolNames.globalSearch:
        final result = await gateway.globalSearch(
          query: (args['query'] ?? '').toString(),
          topK: (args['topK'] as num?)?.toInt() ?? 20,
          apkId: args['apkId']?.toString(),
        );
        // E2：显式声明覆盖范围——只搜 DEX 常量池/符号，不含 resources.arsc
        // 与 assets，防止「0 命中」被误读为「应用里没有这句话」。
        return _withScope(result, const <String>['dex'], const <String>[
          'resources.arsc',
          'assets',
          'native .so',
        ]);
      case AnalyzerToolNames.fieldUsage:
        r = await gateway.findFieldUsage(
          fieldLocator: (args['fieldLocator'] ?? '').toString(),
          apkId: args['apkId']?.toString(),
        );
      case AnalyzerToolNames.businessState:
        r = await gateway.analyzeBusinessState(
          targetKeyword: (args['targetKeyword'] ?? '').toString(),
          domain: (args['domain'] ?? 'vip').toString(),
          fieldName: (args['fieldName'] ?? '').toString(),
          apkId: args['apkId']?.toString(),
        );
      default:
        return jsonEncode(<String, dynamic>{
          'type': 'tool_error',
          'error': 'unknown_analyzer_tool',
          'message': '未知的 analyzer 工具: $name',
        });
    }
    return r.encode();
  }

  /// 给工具响应 JSON 注入 scopeCovered/scopeExcluded（E2 覆盖范围声明）。
  String _withScope(
      AnalyzerResult r, List<String> covered, List<String> excluded) {
    try {
      final decoded = jsonDecode(r.encode());
      if (decoded is Map) {
        final map = decoded.map((k, v) => MapEntry(k.toString(), v));
        map['scopeCovered'] = covered;
        map['scopeExcluded'] = excluded;
        return jsonEncode(map);
      }
    } catch (_) {}
    return r.encode();
  }
}
