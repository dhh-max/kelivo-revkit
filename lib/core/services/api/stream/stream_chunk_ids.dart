/// Allocates [StreamChunk] series ids scoped to one HTTP response.
class StreamChunkIds {
  StreamChunkIds([this.sourceId = 'stream']);
  final String sourceId;
  int _sequence = 0;
  String? _textId;
  String? _reasoningId;
  String? _searchId;
  String next(String kind) {
    final n = ++_sequence;
    if (sourceId.isEmpty) return '$kind-$n';
    return '$sourceId:$kind-$n';
  }
  String text() => _textId ??= next('text');
  String reasoning() => _reasoningId ??= next('reasoning');
  String search() => next('search');
  String searchSticky() => _searchId ??= search();
  String indexed(String kind, int index) {
    if (sourceId.isEmpty) return '$kind-$index';
    return '$sourceId:$kind-$index';
  }
}
