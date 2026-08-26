import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:http/http.dart';
// Import statements for service implementations
import 'providers/bing_search_service.dart';
import 'providers/baidu_search_service.dart';
import 'providers/sogou_search_service.dart';
import 'providers/so360_search_service.dart';
import 'providers/hybrid_local_search_service.dart';
import 'providers/tavily_search_service.dart';
import 'providers/exa_search_service.dart';
import 'providers/zhipu_search_service.dart';
import 'providers/searxng_search_service.dart';
import 'providers/linkup_search_service.dart';
import 'providers/brave_search_service.dart';
import 'providers/metaso_search_service.dart';
import 'providers/ollama_search_service.dart';
import 'providers/jina_search_service.dart';
import 'providers/bocha_search_service.dart';
import 'providers/perplexity_search_service.dart';
import 'providers/duckduckgo_search_service.dart';
import 'providers/serper_search_service.dart';
import 'providers/grok_search_service.dart';
import 'providers/querit_search_service.dart';
import 'providers/stepfun_search_service.dart';
import 'providers/firecrawl_search_service.dart';
import 'providers/tinyfish_search_service.dart';

// Base interface for all search services
abstract class SearchService<T extends SearchServiceOptions> {
  String get name;

  Widget description(BuildContext context);

  Future<SearchResult> search({
    required String query,
    required SearchCommonOptions commonOptions,
    required T serviceOptions,
  });

  final http.Client client;

  SearchService({http.Client? client}) : client = client ?? http.Client();

  /// Execute [fn] against this service's [client].
  static Future<R> withHttpClient<R>(Future<R> Function(http.Client c) fn) {
    final c = http.Client();
    return fn(c).whenComplete(() => c.close());
  }

  /// Convenience overload using the instance's [client].
  Future<R> withInstanceClient<R>(Future<R> Function(http.Client c) fn) {
    return fn(client);
  }

  // Factory method to get service instance based on options type
  static SearchService getService(SearchServiceOptions options) {
    switch (options) {
      case HybridLocalSearchOptions _:
        return HybridLocalSearchService() as SearchService;
      case BingLocalOptions _:
        return BingSearchService() as SearchService;
      case BaiduLocalOptions _:
        return BaiduSearchService() as SearchService;
      case SogouLocalOptions _:
        return SogouSearchService() as SearchService;
      case So360LocalOptions _:
        return So360SearchService() as SearchService;
      case TavilyOptions _:
        return TavilySearchService() as SearchService;
      case ExaOptions _:
        return ExaSearchService() as SearchService;
      case ZhipuOptions _:
        return ZhipuSearchService() as SearchService;
      case SearXNGOptions _:
        return SearXNGSearchService() as SearchService;
      case LinkUpOptions _:
        return LinkUpSearchService() as SearchService;
      case BraveOptions _:
        return BraveSearchService() as SearchService;
      case MetasoOptions _:
        return MetasoSearchService() as SearchService;
      case OllamaOptions _:
        return OllamaSearchService() as SearchService;
      case JinaOptions _:
        return JinaSearchService() as SearchService;
      case BochaOptions _:
        return BochaSearchService() as SearchService;
      case PerplexityOptions _:
        return PerplexitySearchService() as SearchService;
      case DuckDuckGoOptions _:
        return DuckDuckGoSearchService() as SearchService;
      case SerperOptions _:
        return SerperSearchService() as SearchService;
      case GrokOptions _:
        return GrokSearchService() as SearchService;
      case QueritOptions _:
        return QueritSearchService() as SearchService;
      case StepFunOptions _:
        return StepFunSearchService() as SearchService;
      case FirecrawlOptions _:
        return FirecrawlSearchService() as SearchService;
      case TinyFishOptions _:
        return TinyFishSearchService() as SearchService;
      default:
        return BingSearchService() as SearchService;
    }
  }
}

// Search result data structure
class SearchResult {
  final String? answer;
  final List<SearchResultItem> items;

  SearchResult({this.answer, required this.items});

  Map<String, dynamic> toJson() => {
    if (answer != null) 'answer': answer,
    'items': items.map((e) => e.toJson()).toList(),
  };

  factory SearchResult.fromJson(Map<String, dynamic> json) => SearchResult(
    answer: json['answer'],
    items: (json['items'] as List)
        .map((e) => SearchResultItem.fromJson(e))
        .toList(),
  );
}

class SearchResultItem {
  final String title;
  final String url;
  final String text;
  String? id;
  int? index;

  SearchResultItem({
    required this.title,
    required this.url,
    required this.text,
    this.id,
    this.index,
  });

  Map<String, dynamic> toJson() => {
    'title': title,
    'url': url,
    'text': text,
    if (id != null) 'id': id,
    if (index != null) 'index': index,
  };

  factory SearchResultItem.fromJson(Map<String, dynamic> json) =>
      SearchResultItem(
        title: json['title'],
        url: json['url'],
        text: json['text'],
        id: json['id'],
        index: json['index'],
      );
}

// Common search options
class SearchCommonOptions {
  final int resultSize;
  final int timeout;

  const SearchCommonOptions({this.resultSize = 10, this.timeout = 5000});

  Map<String, dynamic> toJson() => {
    'resultSize': resultSize,
    'timeout': timeout,
  };

  factory SearchCommonOptions.fromJson(Map<String, dynamic> json) =>
      SearchCommonOptions(
        resultSize: json['resultSize'] ?? 10,
        timeout: json['timeout'] ?? 5000,
      );
}

// Base class for service-specific options
abstract class SearchServiceOptions {
  final String id;
  final List<String> extraApiKeys;

  const SearchServiceOptions({required this.id, List<String>? extraApiKeys})
      : extraApiKeys = extraApiKeys ?? const [];

  /// Return the primary apiKey, falling back to the first extra key.
  String effectiveApiKey(String primary) {
    final trimmed = primary.trim();
    if (trimmed.isNotEmpty) return trimmed;
    for (final key in extraApiKeys) {
      final k = key.trim();
      if (k.isNotEmpty) return k;
    }
    return '';
  }

  /// The primary API key (subclasses must override).
  String get primaryApiKey => '';

  Map<String, dynamic> toJson();

  static SearchServiceOptions fromJson(Map<String, dynamic> json) {
    final type = json['type'] as String;
    switch (type) {
      case 'hybrid_local':
        return HybridLocalSearchOptions.fromJson(json);
      case 'bing_local':
        return BingLocalOptions.fromJson(json);
      case 'baidu_local':
        return BaiduLocalOptions.fromJson(json);
      case 'sogou_local':
        return SogouLocalOptions.fromJson(json);
      case 'so360_local':
        return So360LocalOptions.fromJson(json);
      case 'tavily':
        return TavilyOptions.fromJson(json);
      case 'exa':
        return ExaOptions.fromJson(json);
      case 'zhipu':
        return ZhipuOptions.fromJson(json);
      case 'searxng':
        return SearXNGOptions.fromJson(json);
      case 'linkup':
        return LinkUpOptions.fromJson(json);
      case 'brave':
        return BraveOptions.fromJson(json);
      case 'metaso':
        return MetasoOptions.fromJson(json);
      case 'ollama':
        return OllamaOptions.fromJson(json);
      case 'jina':
        return JinaOptions.fromJson(json);
      case 'bocha':
        return BochaOptions.fromJson(json);
      case 'duckduckgo':
        return DuckDuckGoOptions.fromJson(json);
      case 'perplexity':
        return PerplexityOptions.fromJson(json);
      case 'serper':
        return SerperOptions.fromJson(json);
      case 'grok':
        return GrokOptions.fromJson(json);
      case 'querit':
        return QueritOptions.fromJson(json);
      case 'stepfun':
        return StepFunOptions.fromJson(json);
      case 'firecrawl':
        return FirecrawlOptions.fromJson(json);
      case 'tinyfish':
        return TinyFishOptions.fromJson(json);
      default:
        return HybridLocalSearchOptions(id: json['id']);
    }
  }

  static final SearchServiceOptions defaultOption = HybridLocalSearchOptions(
    id: 'default',
  );
}

enum HybridLocalSearchMode { balanced, trusted, chinese, research, fast }

enum HybridLocalProvider { bing, duckduckgo, baidu, sogou, so360 }

class HybridLocalSearchOptions extends SearchServiceOptions {
  final HybridLocalSearchMode mode;
  final List<HybridLocalProvider> providers;
  final int maxResultsPerProvider;
  final int timeoutPerProviderMs;
  final String duckDuckGoRegion;

  HybridLocalSearchOptions({
    required super.id,
    this.mode = HybridLocalSearchMode.balanced,
    List<HybridLocalProvider>? providers,
    this.maxResultsPerProvider = 6,
    this.timeoutPerProviderMs = 5000,
    this.duckDuckGoRegion = 'us-en',
  }) : providers = List.unmodifiable(
         providers ??
             const [
               HybridLocalProvider.bing,
               HybridLocalProvider.duckduckgo,
               HybridLocalProvider.baidu,
               HybridLocalProvider.sogou,
               HybridLocalProvider.so360,
             ],
       );

  List<HybridLocalProvider> get enabledProviders {
    if (providers.isEmpty) {
      return const [HybridLocalProvider.bing, HybridLocalProvider.duckduckgo];
    }
    if (mode == HybridLocalSearchMode.fast) {
      return providers
          .where(
            (p) =>
                p == HybridLocalProvider.bing ||
                p == HybridLocalProvider.duckduckgo,
          )
          .toList(growable: false);
    }
    return providers;
  }

  @override
  Map<String, dynamic> toJson() => {
    'type': 'hybrid_local',
    'id': id,
    'mode': mode.name,
    'providers': providers.map((e) => e.name).toList(),
    'maxResultsPerProvider': maxResultsPerProvider,
    'timeoutPerProviderMs': timeoutPerProviderMs,
    'duckDuckGoRegion': duckDuckGoRegion,
  };

  factory HybridLocalSearchOptions.fromJson(Map<String, dynamic> json) {
    HybridLocalSearchMode parseMode(String? value) {
      return HybridLocalSearchMode.values.firstWhere(
        (mode) => mode.name == value,
        orElse: () => HybridLocalSearchMode.balanced,
      );
    }

    HybridLocalProvider? parseProvider(Object? value) {
      final name = value?.toString();
      if (name == null) return null;
      for (final provider in HybridLocalProvider.values) {
        if (provider.name == name) return provider;
      }
      return null;
    }

    final providerValues = (json['providers'] as List?)
        ?.map(parseProvider)
        .whereType<HybridLocalProvider>()
        .toList();

    return HybridLocalSearchOptions(
      id: json['id'],
      mode: parseMode(json['mode']?.toString()),
      providers: providerValues,
      maxResultsPerProvider: json['maxResultsPerProvider'] ?? 6,
      timeoutPerProviderMs: json['timeoutPerProviderMs'] ?? 5000,
      duckDuckGoRegion: json['duckDuckGoRegion'] ?? 'us-en',
    );
  }
}

// Service-specific option classes
class BingLocalOptions extends SearchServiceOptions {
  final String acceptLanguage;

  BingLocalOptions({required super.id, this.acceptLanguage = 'en-US,en;q=0.9'});

  @override
  Map<String, dynamic> toJson() => {
    'type': 'bing_local',
    'id': id,
    'acceptLanguage': acceptLanguage,
  };

  factory BingLocalOptions.fromJson(Map<String, dynamic> json) =>
      BingLocalOptions(
        id: json['id'],
        acceptLanguage: json['acceptLanguage'] ?? 'en-US,en;q=0.9',
      );
}

class BaiduLocalOptions extends SearchServiceOptions {
  final String acceptLanguage;
  final int pn;

  BaiduLocalOptions({
    required super.id,
    this.acceptLanguage = 'zh-CN,zh;q=0.9,en;q=0.8',
    this.pn = 0,
  });

  @override
  Map<String, dynamic> toJson() => {
    'type': 'baidu_local',
    'id': id,
    'acceptLanguage': acceptLanguage,
    'pn': pn,
  };

  factory BaiduLocalOptions.fromJson(Map<String, dynamic> json) =>
      BaiduLocalOptions(
        id: json['id'],
        acceptLanguage: json['acceptLanguage'] ?? 'zh-CN,zh;q=0.9,en;q=0.8',
        pn: json['pn'] ?? 0,
      );
}

class SogouLocalOptions extends SearchServiceOptions {
  final String acceptLanguage;
  final int page;

  SogouLocalOptions({
    required super.id,
    this.acceptLanguage = 'zh-CN,zh;q=0.9,en;q=0.8',
    this.page = 1,
  });

  @override
  Map<String, dynamic> toJson() => {
    'type': 'sogou_local',
    'id': id,
    'acceptLanguage': acceptLanguage,
    'page': page,
  };

  factory SogouLocalOptions.fromJson(Map<String, dynamic> json) =>
      SogouLocalOptions(
        id: json['id'],
        acceptLanguage: json['acceptLanguage'] ?? 'zh-CN,zh;q=0.9,en;q=0.8',
        page: json['page'] ?? 1,
      );
}

class So360LocalOptions extends SearchServiceOptions {
  final String acceptLanguage;
  final int page;

  So360LocalOptions({
    required super.id,
    this.acceptLanguage = 'zh-CN,zh;q=0.9,en;q=0.8',
    this.page = 1,
  });

  @override
  Map<String, dynamic> toJson() => {
    'type': 'so360_local',
    'id': id,
    'acceptLanguage': acceptLanguage,
    'page': page,
  };

  factory So360LocalOptions.fromJson(Map<String, dynamic> json) =>
      So360LocalOptions(
        id: json['id'],
        acceptLanguage: json['acceptLanguage'] ?? 'zh-CN,zh;q=0.9,en;q=0.8',
        page: json['page'] ?? 1,
      );
}

class TavilyOptions extends SearchServiceOptions {
  static const String defaultUrl = 'https://api.tavily.com/search';

  final String apiKey;
  final String url;

  TavilyOptions({required super.id, required this.apiKey, this.url = '', List<String>? extraApiKeys})
    : super(extraApiKeys: extraApiKeys);

  String get resolvedUrl {
    final trimmed = url.trim();
    return trimmed.isEmpty ? defaultUrl : trimmed;
  }

  @override
  Map<String, dynamic> toJson() => {
    'type': 'tavily',
    'id': id,
    'apiKey': apiKey,
    'url': url.trim(),
  };

  factory TavilyOptions.fromJson(Map<String, dynamic> json) => TavilyOptions(
    id: json['id'],
    apiKey: json['apiKey'],
    url: json['url'] ?? '',
  );
}

class ExaOptions extends SearchServiceOptions {
  static const String defaultUrl = 'https://api.exa.ai/search';

  final String apiKey;
  final String url;

  ExaOptions({required super.id, required this.apiKey, this.url = '', List<String>? extraApiKeys})
    : super(extraApiKeys: extraApiKeys);

  String get resolvedUrl {
    final trimmed = url.trim();
    return trimmed.isEmpty ? defaultUrl : trimmed;
  }

  @override
  Map<String, dynamic> toJson() => {
    'type': 'exa',
    'id': id,
    'apiKey': apiKey,
    'url': url.trim(),
  };

  factory ExaOptions.fromJson(Map<String, dynamic> json) => ExaOptions(
    id: json['id'],
    apiKey: json['apiKey'],
    url: json['url'] ?? '',
  );
}

class ZhipuOptions extends SearchServiceOptions {
  final String apiKey;

  ZhipuOptions({required super.id, required this.apiKey, List<String>? extraApiKeys})
    : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'zhipu',
    'id': id,
    'apiKey': apiKey,
  };

  factory ZhipuOptions.fromJson(Map<String, dynamic> json) =>
      ZhipuOptions(id: json['id'], apiKey: json['apiKey']);
}

class SearXNGOptions extends SearchServiceOptions {
  final String url;
  final String engines;
  final String language;
  final String username;
  final String password;

  SearXNGOptions({
    required super.id,
    required this.url,
    this.engines = '',
    this.language = '',
    this.username = '',
    this.password = '',
  });

  @override
  Map<String, dynamic> toJson() => {
    'type': 'searxng',
    'id': id,
    'url': url,
    'engines': engines,
    'language': language,
    'username': username,
    'password': password,
  };

  factory SearXNGOptions.fromJson(Map<String, dynamic> json) => SearXNGOptions(
    id: json['id'],
    url: json['url'],
    engines: json['engines'] ?? '',
    language: json['language'] ?? '',
    username: json['username'] ?? '',
    password: json['password'] ?? '',
  );
}

class LinkUpOptions extends SearchServiceOptions {
  final String apiKey;

  LinkUpOptions({required super.id, required this.apiKey, List<String>? extraApiKeys})
    : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'linkup',
    'id': id,
    'apiKey': apiKey,
  };

  factory LinkUpOptions.fromJson(Map<String, dynamic> json) =>
      LinkUpOptions(id: json['id'], apiKey: json['apiKey']);
}

class BraveOptions extends SearchServiceOptions {
  final String apiKey;

  BraveOptions({required super.id, required this.apiKey, List<String>? extraApiKeys})
    : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'brave',
    'id': id,
    'apiKey': apiKey,
  };

  factory BraveOptions.fromJson(Map<String, dynamic> json) =>
      BraveOptions(id: json['id'], apiKey: json['apiKey']);
}

class MetasoOptions extends SearchServiceOptions {
  final String apiKey;

  MetasoOptions({required super.id, required this.apiKey, List<String>? extraApiKeys})
    : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'metaso',
    'id': id,
    'apiKey': apiKey,
  };

  factory MetasoOptions.fromJson(Map<String, dynamic> json) =>
      MetasoOptions(id: json['id'], apiKey: json['apiKey']);
}

class OllamaOptions extends SearchServiceOptions {
  final String apiKey;

  OllamaOptions({required super.id, required this.apiKey, List<String>? extraApiKeys})
    : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'ollama',
    'id': id,
    'apiKey': apiKey,
  };

  factory OllamaOptions.fromJson(Map<String, dynamic> json) =>
      OllamaOptions(id: json['id'], apiKey: json['apiKey']);
}

class JinaOptions extends SearchServiceOptions {
  final String apiKey;

  JinaOptions({required super.id, required this.apiKey, List<String>? extraApiKeys})
    : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {'type': 'jina', 'id': id, 'apiKey': apiKey};

  factory JinaOptions.fromJson(Map<String, dynamic> json) =>
      JinaOptions(id: json['id'], apiKey: json['apiKey']);
}

class DuckDuckGoOptions extends SearchServiceOptions {
  final String region;

  DuckDuckGoOptions({required super.id, this.region = 'us-en'});

  @override
  Map<String, dynamic> toJson() => {
    'type': 'duckduckgo',
    'id': id,
    'region': region,
  };

  factory DuckDuckGoOptions.fromJson(Map<String, dynamic> json) =>
      DuckDuckGoOptions(id: json['id'], region: json['region'] ?? 'us-en');
}

class PerplexityOptions extends SearchServiceOptions {
  final String apiKey;
  final String? country; // ISO 3166-1 alpha-2
  final List<String>? searchDomainFilter; // domains/URLs
  final int? maxTokensPerPage; // default 1024

  PerplexityOptions({
    required super.id,
    required this.apiKey,
    List<String>? extraApiKeys,
    this.country,
    this.searchDomainFilter,
    this.maxTokensPerPage,
  }) : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'perplexity',
    'id': id,
    'apiKey': apiKey,
    if (country != null) 'country': country,
    if (searchDomainFilter != null) 'searchDomainFilter': searchDomainFilter,
    if (maxTokensPerPage != null) 'maxTokensPerPage': maxTokensPerPage,
  };

  factory PerplexityOptions.fromJson(Map<String, dynamic> json) =>
      PerplexityOptions(
        id: json['id'],
        apiKey: json['apiKey'],
        country: json['country'],
        searchDomainFilter: (json['searchDomainFilter'] as List?)
            ?.map((e) => e.toString())
            .toList(),
        maxTokensPerPage: json['maxTokensPerPage'],
      );
}

class BochaOptions extends SearchServiceOptions {
  final String apiKey;
  // Optional parameters supported by Bocha API
  final String? freshness; // e.g., 'noLimit', 'week', 'month', etc.
  final bool summary; // whether to include textual summary
  final String? include; // e.g., 'qq.com|m.163.com'
  final String? exclude; // e.g., 'qq.com|m.163.com'

  BochaOptions({
    required super.id,
    required this.apiKey,
    List<String>? extraApiKeys,
    this.freshness,
    this.summary = true,
    this.include,
    this.exclude,
  }) : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'bocha',
    'id': id,
    'apiKey': apiKey,
    if (freshness != null) 'freshness': freshness,
    'summary': summary,
    if (include != null) 'include': include,
    if (exclude != null) 'exclude': exclude,
  };

  factory BochaOptions.fromJson(Map<String, dynamic> json) => BochaOptions(
    id: json['id'],
    apiKey: json['apiKey'],
    freshness: json['freshness'],
    summary: (json['summary'] ?? true) as bool,
    include: json['include'],
    exclude: json['exclude'],
  );
}

class SerperOptions extends SearchServiceOptions {
  final String apiKey;
  final String gl;
  final String hl;
  final String tbs;
  final int page;

  SerperOptions({
    required super.id,
    required this.apiKey,
    List<String>? extraApiKeys,
    this.gl = '',
    this.hl = '',
    this.tbs = '',
    this.page = 1,
  }) : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'serper',
    'id': id,
    'apiKey': apiKey,
    'gl': gl.trim(),
    'hl': hl.trim(),
    'tbs': tbs.trim(),
    'page': page,
  };

  factory SerperOptions.fromJson(Map<String, dynamic> json) => SerperOptions(
    id: json['id'],
    apiKey: json['apiKey'],
    gl: json['gl'] ?? '',
    hl: json['hl'] ?? '',
    tbs: json['tbs'] ?? '',
    page: json['page'] ?? 1,
  );
}

class GrokOptions extends SearchServiceOptions {
  static const String defaultUrl = 'https://api.x.ai/v1/responses';
  static const String defaultModel = 'grok-4.3';
  static const String defaultReasoningEffort = 'none';
  static const String defaultSystemPrompt =
      "You are a helpful search assistant. Search the web to find accurate and up-to-date information for the user's query. Provide a comprehensive answer with citations.";

  final String apiKey;
  final String model;
  final String reasoningEffort;
  final String customUrl;
  final String systemPrompt;

  GrokOptions({
    required super.id,
    required this.apiKey,
    this.model = defaultModel,
    this.reasoningEffort = '',
    this.customUrl = defaultUrl,
    this.systemPrompt = defaultSystemPrompt,
    List<String>? extraApiKeys,
  }) : super(extraApiKeys: extraApiKeys);

  String get resolvedUrl {
    final trimmed = customUrl.trim();
    return trimmed.isEmpty ? defaultUrl : trimmed;
  }

  String get resolvedModel {
    final trimmed = model.trim();
    return trimmed.isEmpty ? defaultModel : trimmed;
  }

  String get resolvedReasoningEffort {
    final trimmed = reasoningEffort.trim();
    return trimmed.isEmpty ? defaultReasoningEffort : trimmed;
  }

  String get resolvedSystemPrompt {
    final trimmed = systemPrompt.trim();
    return trimmed.isEmpty ? defaultSystemPrompt : trimmed;
  }

  @override
  Map<String, dynamic> toJson() => {
    'type': 'grok',
    'id': id,
    'apiKey': apiKey,
    'model': model.trim(),
    'reasoningEffort': reasoningEffort.trim(),
    'customUrl': customUrl.trim(),
    'systemPrompt': systemPrompt,
  };

  factory GrokOptions.fromJson(Map<String, dynamic> json) => GrokOptions(
    id: json['id'],
    apiKey: json['apiKey'] ?? '',
    model: json['model'] ?? defaultModel,
    reasoningEffort: json['reasoningEffort'] ?? '',
    customUrl: json['customUrl'] ?? defaultUrl,
    systemPrompt: json['systemPrompt'] ?? defaultSystemPrompt,
  );
}

class QueritOptions extends SearchServiceOptions {
  final String apiKey;
  final String sitesInclude;
  final String sitesExclude;
  final String timeRange;
  final String countries;
  final String languages;

  QueritOptions({
    required super.id,
    required this.apiKey,
    List<String>? extraApiKeys,
    this.sitesInclude = '',
    this.sitesExclude = '',
    this.timeRange = '',
    this.countries = '',
    this.languages = '',
  }) : super(extraApiKeys: extraApiKeys);

  @override
  Map<String, dynamic> toJson() => {
    'type': 'querit',
    'id': id,
    'apiKey': apiKey,
    'sitesInclude': sitesInclude.trim(),
    'sitesExclude': sitesExclude.trim(),
    'timeRange': timeRange.trim(),
    'countries': countries.trim(),
    'languages': languages.trim(),
  };

  factory QueritOptions.fromJson(Map<String, dynamic> json) => QueritOptions(
    id: json['id'],
    apiKey: json['apiKey'] ?? '',
    sitesInclude: json['sitesInclude'] ?? '',
    sitesExclude: json['sitesExclude'] ?? '',
    timeRange: json['timeRange'] ?? '',
    countries: json['countries'] ?? '',
    languages: json['languages'] ?? '',
  );
}

class StepFunOptions extends SearchServiceOptions {
  static const String defaultUrl = 'https://api.stepfun.com/v1/search';

  final String apiKey;
  final String url;
  final String category;

  StepFunOptions({
    required super.id,
    required this.apiKey,
    this.url = '',
    this.category = '',
    List<String>? extraApiKeys,
  }) : super(extraApiKeys: extraApiKeys);

  String get resolvedUrl => url.trim().isEmpty ? defaultUrl : url;

  @override
  Map<String, dynamic> toJson() => {
    'type': 'stepfun',
    'id': id,
    'apiKey': apiKey,
    'url': url.trim(),
    'category': category.trim(),
  };

  factory StepFunOptions.fromJson(Map<String, dynamic> json) => StepFunOptions(
    id: json['id'],
    apiKey: json['apiKey'] ?? '',
    url: json['url'] ?? '',
    category: json['category'] ?? '',
  );
}

class FirecrawlOptions extends SearchServiceOptions {
  static const String defaultUrl = 'https://api.firecrawl.dev/v1/search';

  final String apiKey;
  final String url;
  final List<String> sources;
  final List<String> categories;
  final String country;
  final String location;

  FirecrawlOptions({
    required super.id,
    required this.apiKey,
    this.url = '',
    this.sources = const ['web'],
    this.categories = const [],
    this.country = '',
    this.location = '',
    List<String>? extraApiKeys,
  }) : super(extraApiKeys: extraApiKeys);

  String get resolvedUrl => url.trim().isEmpty ? defaultUrl : url;

  @override
  Map<String, dynamic> toJson() => {
    'type': 'firecrawl',
    'id': id,
    'apiKey': apiKey,
    'url': url.trim(),
    'sources': sources,
    'categories': categories,
    'country': country.trim(),
    'location': location.trim(),
  };

  factory FirecrawlOptions.fromJson(Map<String, dynamic> json) => FirecrawlOptions(
    id: json['id'],
    apiKey: json['apiKey'] ?? '',
    url: json['url'] ?? '',
    sources: (json['sources'] as List?)?.map((e) => e.toString()).toList() ?? const ['web'],
    categories: (json['categories'] as List?)?.map((e) => e.toString()).toList() ?? const [],
    country: json['country'] ?? '',
    location: json['location'] ?? '',
  );
}

class TinyFishOptions extends SearchServiceOptions {
  static const String defaultUrl = 'https://api.tinyfish.tools/v1/search';

  final String apiKey;
  final String url;
  final String location;
  final String language;
  final String includeDomains;
  final String excludeDomains;

  TinyFishOptions({
    required super.id,
    required this.apiKey,
    this.url = '',
    this.location = '',
    this.language = '',
    this.includeDomains = '',
    this.excludeDomains = '',
    List<String>? extraApiKeys,
  }) : super(extraApiKeys: extraApiKeys);

  String get resolvedUrl => url.trim().isEmpty ? defaultUrl : url;

  @override
  Map<String, dynamic> toJson() => {
    'type': 'tinyfish',
    'id': id,
    'apiKey': apiKey,
    'url': url.trim(),
    'location': location.trim(),
    'language': language.trim(),
    'includeDomains': includeDomains.trim(),
    'excludeDomains': excludeDomains.trim(),
  };

  factory TinyFishOptions.fromJson(Map<String, dynamic> json) => TinyFishOptions(
    id: json['id'],
    apiKey: json['apiKey'] ?? '',
    url: json['url'] ?? '',
    location: json['location'] ?? '',
    language: json['language'] ?? '',
    includeDomains: json['includeDomains'] ?? '',
    excludeDomains: json['excludeDomains'] ?? '',
  );
}
