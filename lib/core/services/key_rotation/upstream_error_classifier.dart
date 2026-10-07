/// Upstream Error Classifier
///
/// 为 Kelivo 的 API 层提供精细化的上游错误分类，决定是否
/// 无感切换 key、等待重试、或直接透传给用户。
///
/// - quotaExhausted / rateLimited / serverError / modelNotFound /
///   authFailed / permissionDenied → 换一个 key 可能就成功，代理无感切换重试
/// - badRequest / unknown → 请求本身问题，切换 key 无济于事，直接透传


library;
/// 上游错误类型
enum UpstreamErrorKind {
  quotaExhausted,   // 额度/计费耗尽
  rateLimited,       // 429 限流
  authFailed,        // 401 鉴权失败
  modelNotFound,     // 404 模型不存在
  serverError,       // 5xx 服务器异常
  permissionDenied,  // 403 权限拒绝
  badRequest,        // 4xx 请求问题
  unknown,           // 未知
}

/// 错误关键词配置
class UpstreamErrorKeywords {
  static const List<String> quotaExhausted = [
    'quota', 'billing', 'exhausted', 'insufficient', 'balance',
    'exceeded', 'limit reached', 'no enough', 'credit',
    '额度', '余额', '耗尽', '欠费', '不足',
  ];
  static const List<String> authFailed = [
    'unauthorized', 'invalid api key', 'invalid key',
    'authentication', 'invalid_api_key', 'api key is invalid',
    '未授权', '密钥无效', '鉴权失败',
  ];
}

/// 上游错误分类器
class UpstreamErrorClassifier {
  const UpstreamErrorClassifier._();

  /// 分类上游错误
  static UpstreamErrorKind classify(int statusCode, String body) {
    final b = body.toLowerCase();
    // 1) 额度/计费耗尽优先于状态码判断
    if (_containsAny(b, UpstreamErrorKeywords.quotaExhausted)) {
      return UpstreamErrorKind.quotaExhausted;
    }
    // 2) 429：限流
    if (statusCode == 429) {
      return UpstreamErrorKind.rateLimited;
    }
    // 3) 401：鉴权失败
    if (statusCode == 401 || _containsAny(b, UpstreamErrorKeywords.authFailed)) {
      return UpstreamErrorKind.authFailed;
    }
    // 4) 404：模型不存在
    if (statusCode == 404) {
      return UpstreamErrorKind.modelNotFound;
    }
    // 5) 5xx：上游服务异常
    if (statusCode >= 500) {
      return UpstreamErrorKind.serverError;
    }
    // 6) 403：权限拒绝
    if (statusCode == 403) {
      return UpstreamErrorKind.permissionDenied;
    }
    // 7) 4xx 请求问题：切换 key 不会改变结果
    if (statusCode >= 400 && statusCode < 500) {
      return UpstreamErrorKind.badRequest;
    }
    return UpstreamErrorKind.unknown;
  }

  /// 是否可以静默重试（换 key 可能成功）
  static bool isSilentlyRetryable(UpstreamErrorKind kind) {
    switch (kind) {
      case UpstreamErrorKind.quotaExhausted:
      case UpstreamErrorKind.rateLimited:
      case UpstreamErrorKind.serverError:
      case UpstreamErrorKind.modelNotFound:
      case UpstreamErrorKind.authFailed:
      case UpstreamErrorKind.permissionDenied:
        return true;
      case UpstreamErrorKind.badRequest:
      case UpstreamErrorKind.unknown:
        return false;
    }
  }

  /// 是否是可恢复的 TPM 限流（需要等待窗口刷新）
  static bool isRecoverableTpm(int statusCode, String body) {
    if (statusCode != 429) return false;
    final b = body.toLowerCase();
    return b.contains('tpm') || b.contains('tokens per minute') ||
           b.contains('token rate limit') || b.contains('rpm');
  }

  static bool _containsAny(String text, List<String> keywords) {
    for (final kw in keywords) {
      if (text.contains(kw)) return true;
    }
    return false;
  }
}
