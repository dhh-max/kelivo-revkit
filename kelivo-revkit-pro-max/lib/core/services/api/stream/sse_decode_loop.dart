import 'sse_event.dart';
import 'stream_chunk.dart';
import 'stream_chunk_decoder.dart';
/// Feed [events] through [decoder], including `[DONE]`, then [onClosed].
Stream<StreamChunk> decodeSseEvents(
  Stream<SseEvent> events,
  StreamChunkDecoder decoder,
) async* {
  await for (final event in events) {
    final data = event.data;
    final decoded = decoder.accept(event);
    for (final chunk in decoded.chunks) {
      yield chunk;
    }
    if (data == '[DONE]' || decoded.completed) break;
  }
  for (final chunk in decoder.onClosed()) {
    yield chunk;
  }
}
