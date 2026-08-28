import 'dart:convert';
import 'dart:io';
import 'dart:async';

/// Webhook 推送模块：向外部 URL 异步 POST JSON 通知，可选 HMAC-SHA256 签名。
class WebhookService {
  static const String signatureHeader = 'X-RelayGo-Signature';
  static const Duration timeout = Duration(seconds: 10);

  /// 推送一条通知到 webhook URL。
  ///
  /// [url] 接收方地址（HTTP/HTTPS）
  /// [title] 通知标题
  /// [content] 通知正文
  /// [secret] 非空时按 HMAC-SHA256 对请求体签名
  ///
  /// 返回 true 表示推送成功（HTTP 2xx），否则 false。
  static Future<bool> notify({
    required String url,
    required String title,
    required String content,
    String secret = '',
  }) async {
    if (url.trim().isEmpty) return false;

    final payload = {
      'title': title,
      'content': content,
      'time': DateTime.now().millisecondsSinceEpoch ~/ 1000,
    };

    String body;
    try {
      body = jsonEncode(payload);
    } catch (_) {
      return false;
    }

    final headers = <String, String>{
      'Content-Type': 'application/json',
    };

    if (secret.isNotEmpty) {
      final digest = _hmacSha256(secret, body);
      headers[signatureHeader] = digest;
    }

    try {
      final client = HttpClient();
      client.connectionTimeout = timeout;
      final req = await client.postUrl(Uri.parse(url));
      headers.forEach((k, v) => req.headers.set(k, v));
      req.add(utf8.encode(body));
      final resp = await req.close().timeout(timeout);
      client.close();
      return resp.statusCode >= 200 && resp.statusCode < 300;
    } catch (_) {
      return false;
    }
  }

  /// 同步上下文 fire-and-forget 推送（内部起守护线程跑异步）
  static void notifyFireAndForget({
    required String url,
    required String title,
    required String content,
    String secret = '',
  }) {
    if (url.trim().isEmpty) return;
    Timer.run(() async {
      try {
        await notify(
          url: url,
          title: title,
          content: content,
          secret: secret,
        );
      } catch (_) {}
    });
  }

  static String _hmacSha256(String key, String data) {
    // Pure Dart HMAC-SHA256 implementation
    final keyBytes = utf8.encode(key);
    final dataBytes = utf8.encode(data);
    final digest = _HmacSha256(keyBytes).convert(dataBytes);
    return digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

/// Minimal HMAC-SHA256 implementation
class _HmacSha256 {
  final List<int> _key;
  _HmacSha256(this._key);

  List<int> convert(List<int> data) {
    const blockSize = 64;
    var key = List<int>.from(_key);
    if (key.length > blockSize) {
      key = _sha256(key);
    }
    while (key.length < blockSize) {
      key.add(0);
    }
    final oKeyPad = List<int>.generate(blockSize, (i) => key[i] ^ 0x5c);
    final iKeyPad = List<int>.generate(blockSize, (i) => key[i] ^ 0x36);
    return _sha256([...oKeyPad, ..._sha256([...iKeyPad, ...data])]);
  }

  static List<int> _sha256(List<int> message) {
    final h = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    final k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    final msg = List<int>.from(message);
    final originalBitLen = msg.length * 8;
    msg.add(0x80);
    while (msg.length % 64 != 56) msg.add(0);
    // Append 64-bit big-endian length
    for (var i = 7; i >= 0; i--) {
      msg.add((originalBitLen >> (i * 8)) & 0xff);
    }

    for (var chunkStart = 0; chunkStart < msg.length; chunkStart += 64) {
      final w = List<int>.filled(64, 0);
      for (var i = 0; i < 16; i++) {
        w[i] = (msg[chunkStart + i * 4] << 24) |
            (msg[chunkStart + i * 4 + 1] << 16) |
            (msg[chunkStart + i * 4 + 2] << 8) |
            msg[chunkStart + i * 4 + 3];
      }
      for (var i = 16; i < 64; i++) {
        final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = _add(_add(_add(w[i - 16], s0), w[i - 7]), s1);
      }
      var a = h[0], b = h[1], c = h[2], d = h[3];
      var e = h[4], f = h[5], g = h[6], hh = h[7];
      for (var i = 0; i < 64; i++) {
        final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
        final ch = (e & f) ^ (~e & g);
        final temp1 = _add(_add(_add(_add(hh, s1), ch), k[i]), w[i]);
        final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
        final maj = (a & b) ^ (a & c) ^ (b & c);
        final temp2 = _add(s0, maj);
        hh = g; g = f; f = e;
        e = _add(d, temp1);
        d = c; c = b; b = a;
        a = _add(temp1, temp2);
      }
      h[0] = _add(h[0], a); h[1] = _add(h[1], b);
      h[2] = _add(h[2], c); h[3] = _add(h[3], d);
      h[4] = _add(h[4], e); h[5] = _add(h[5], f);
      h[6] = _add(h[6], g); h[7] = _add(h[7], hh);
    }
    return h.expand((v) => [
      (v >> 24) & 0xff, (v >> 16) & 0xff,
      (v >> 8) & 0xff, v & 0xff,
    ]).toList();
  }

  static int _rotr(int v, int n) => (v >> n) | (v << (32 - n));
  static int _add(int a, int b) => (a + b) & 0xffffffff;
}