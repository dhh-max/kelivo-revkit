import 'package:flutter/foundation.dart';
import '../../logging/flutter_logger.dart';
import 'sse_event.dart';
import 'stream_chunk.dart';
/// Stateful, transport-agnostic decoder for one provider response stream.
abstract class StreamChunkDecoder {
  DecodeResult accept(SseEvent event);
  List<StreamChunk> onClosed();
}
class DecodeResult {
  const DecodeResult({
    this.chunks = const <StreamChunk>[],
    this.completed = false,
  });
  final List<StreamChunk> chunks;
  final bool completed;
}
void logDecoderParseError({
  required String provider,
  required String eventType,
  required Object error,
}) {
  final message = 'provider=$provider eventType=$eventType error=$error';
  debugPrint('[DecoderParseError] $message');
  FlutterLogger.log(message, tag: 'DecoderParseError');
}
