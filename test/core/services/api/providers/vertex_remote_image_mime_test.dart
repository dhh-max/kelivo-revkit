import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import 'package:Kelivo/core/providers/settings_provider.dart';
import 'package:Kelivo/core/services/api/providers/google_vertex.dart';

class _FakeClient extends http.BaseClient {
  _FakeClient({
    this.headers = const <String, String>{},
    this.statusCode = 200,
    this.body = 'payload',
  });

  final Map<String, String> headers;
  final int statusCode;
  final String body;
  int calls = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    calls++;
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(body)),
      statusCode,
      headers: headers,
    );
  }
}

ProviderConfig _config() => ProviderConfig(
  id: 'VertexMimeTest',
  enabled: true,
  name: 'VertexMimeTest',
  apiKey: 'test-key',
  baseUrl: 'https://us-central1-aiplatform.googleapis.com',
);

void main() {
  group('remoteImageMime', () {
    test('prefers the response Content-Type over the URL extension', () {
      expect(
        remoteImageMime('image/jpeg; charset=utf-8', 'https://cdn.test/pic.png'),
        'image/jpeg',
      );
    });

    test('strips parameters and lowercases the declared type', () {
      expect(remoteImageMime('IMAGE/GIF; charset=binary', 'https://cdn.test/x'), 'image/gif');
    });

    test('reads the extension after a query string is stripped', () {
      expect(
        remoteImageMime(null, 'https://cdn.test/pic.webp?format=webp&w=1024'),
        'image/webp',
      );
    });

    test('handles uppercase extensions and fragments', () {
      expect(remoteImageMime(null, 'https://cdn.test/pic.JPG#frag'), 'image/jpeg');
      expect(remoteImageMime(null, 'https://cdn.test/pic.jpeg?x=1'), 'image/jpeg');
    });

    test('falls back to the URL path when the header is not an image type', () {
      expect(
        remoteImageMime('application/octet-stream', 'https://cdn.test/a/b.png'),
        'image/png',
      );
    });

    test('falls back to image/png when nothing identifies the type', () {
      expect(remoteImageMime(null, 'https://cdn.test/no-extension'), 'image/png');
      expect(remoteImageMime('  ', 'https://cdn.test/no-extension'), 'image/png');
    });
  });

  group('downloadRemoteMedia', () {
    test('returns the base64 body plus the declared Content-Type', () async {
      final client = _FakeClient(
        headers: const {'content-type': 'image/webp; charset=binary'},
        body: 'hello-vertex',
      );
      final media = await downloadRemoteMedia(client, _config(), 'https://cdn.test/pic');

      expect(media.base64, base64Encode(utf8.encode('hello-vertex')));
      expect(media.contentType, 'image/webp; charset=binary');
      expect(remoteImageMime(media.contentType, 'https://cdn.test/pic'), 'image/webp');
      expect(client.calls, 1);
    });

    test('reports a null Content-Type when the server omits it', () async {
      final media = await downloadRemoteMedia(
        _FakeClient(body: 'x'),
        _config(),
        'https://cdn.test/pic.jpg',
      );
      expect(media.contentType, isNull);
      expect(remoteImageMime(media.contentType, 'https://cdn.test/pic.jpg'), 'image/jpeg');
    });

    test('treats a blank Content-Type as absent', () async {
      final media = await downloadRemoteMedia(
        _FakeClient(headers: const {'content-type': '   '}, body: 'x'),
        _config(),
        'https://cdn.test/pic',
      );
      expect(media.contentType, isNull);
    });

    test('downloadRemoteAsBase64 stays a base64-only wrapper', () async {
      final b64 = await downloadRemoteAsBase64(
        _FakeClient(headers: const {'content-type': 'image/png'}, body: 'body-bytes'),
        _config(),
        'https://cdn.test/pic',
      );
      expect(b64, base64Encode(utf8.encode('body-bytes')));
    });

    test('non-2xx responses still throw HttpException', () async {
      await expectLater(
        downloadRemoteMedia(
          _FakeClient(statusCode: 404, body: 'missing'),
          _config(),
          'https://cdn.test/pic.png',
        ),
        throwsA(isA<HttpException>()),
      );
    });
  });
}
