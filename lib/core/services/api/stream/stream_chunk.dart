import '../../../models/token_usage.dart';
/// Kind of text carried by a reasoning part.
enum ReasoningType { reasoningText, summaryText }
/// Lifecycle status of a provider-hosted (server-side) tool call.
enum ServerToolStatus { inProgress, completed, failed }
/// Provider-independent citation / annotation attached to a stream.
sealed class StreamAnnotation {
  const StreamAnnotation();
}
final class UrlCitationAnnotation extends StreamAnnotation {
  const UrlCitationAnnotation({required this.url, this.title = ''});
  final String url;
  final String title;
}
/// Provider-independent streaming events.
sealed class StreamChunk {
  const StreamChunk();
}
final class TextStart extends StreamChunk {
  const TextStart(this.id);
  final String id;
}
final class TextDelta extends StreamChunk {
  const TextDelta({required this.id, required this.text});
  final String id;
  final String text;
}
final class TextEnd extends StreamChunk {
  const TextEnd(this.id);
  final String id;
}
final class ReasoningStart extends StreamChunk {
  const ReasoningStart({
    required this.id,
    this.metadata,
    this.reasoningType = ReasoningType.reasoningText,
  });
  final String id;
  final Map<String, dynamic>? metadata;
  final ReasoningType reasoningType;
}
final class ReasoningDelta extends StreamChunk {
  const ReasoningDelta({
    required this.id,
    required this.text,
    this.metadata,
    this.reasoningType = ReasoningType.reasoningText,
    this.details,
  });
  final String id;
  final String text;
  final Map<String, dynamic>? metadata;
  final ReasoningType reasoningType;
  final dynamic details;
}
final class ReasoningEnd extends StreamChunk {
  const ReasoningEnd({required this.id, this.metadata});
  final String id;
  final Map<String, dynamic>? metadata;
}
final class ToolCallStart extends StreamChunk {
  const ToolCallStart({required this.id, this.toolName = '', this.metadata});
  final String id;
  final String toolName;
  final Map<String, dynamic>? metadata;
}
final class ToolCallDelta extends StreamChunk {
  const ToolCallDelta({
    required this.id,
    this.toolNameDelta = '',
    this.inputDelta = '',
    this.metadata,
  });
  final String id;
  final String toolNameDelta;
  final String inputDelta;
  final Map<String, dynamic>? metadata;
}
final class ToolCallEnd extends StreamChunk {
  const ToolCallEnd(this.id);
  final String id;
}
final class ToolCallResult extends StreamChunk {
  const ToolCallResult({required this.id, this.output, this.metadata});
  final String id;
  final Object? output;
  final Map<String, dynamic>? metadata;
}
final class ServerToolStart extends StreamChunk {
  const ServerToolStart({
    required this.id,
    required this.toolName,
    this.input,
    this.metadata,
  });
  final String id;
  final String toolName;
  final Object? input;
  final Map<String, dynamic>? metadata;
}
final class ServerToolInputDelta extends StreamChunk {
  const ServerToolInputDelta({
    required this.id,
    required this.inputDelta,
    this.metadata,
  });
  final String id;
  final String inputDelta;
  final Map<String, dynamic>? metadata;
}
final class ServerToolInputEnd extends StreamChunk {
  const ServerToolInputEnd(this.id);
  final String id;
}
final class ServerToolEnd extends StreamChunk {
  const ServerToolEnd({
    required this.id,
    this.input,
    this.output,
    this.status = ServerToolStatus.completed,
    this.metadata,
  });
  final String id;
  final Object? input;
  final Object? output;
  final ServerToolStatus status;
  final Map<String, dynamic>? metadata;
}
final class ImageStart extends StreamChunk {
  const ImageStart({
    required this.id,
    this.mimeType = 'image/png',
    this.metadata,
  });
  final String id;
  final String mimeType;
  final Map<String, dynamic>? metadata;
}
final class ImageDelta extends StreamChunk {
  const ImageDelta({required this.id, required this.data, this.metadata});
  final String id;
  final String data;
  final Map<String, dynamic>? metadata;
}
final class ImageSnapshot extends StreamChunk {
  const ImageSnapshot({required this.id, required this.data, this.metadata});
  final String id;
  final String data;
  final Map<String, dynamic>? metadata;
}
final class ImageEnd extends StreamChunk {
  const ImageEnd(this.id);
  final String id;
}
final class Annotations extends StreamChunk {
  const Annotations(this.annotations, {this.id = ''});
  final List<StreamAnnotation> annotations;
  final String id;
}
final class Usage extends StreamChunk {
  const Usage(this.usage);
  final TokenUsage usage;
}
final class Finish extends StreamChunk {
  const Finish({this.finishReason, this.responseId, this.model});
  final String? finishReason;
  final String? responseId;
  final String? model;
}
bool isCompleteImageUri(String data) {
  final trimmed = data.trim();
  return trimmed.startsWith('data:') ||
      trimmed.startsWith('file:') ||
      trimmed.contains('://');
}
bool isBlankImageUri(String uri) {
  final trimmed = uri.trim();
  if (trimmed.isEmpty) return true;
  if (!trimmed.startsWith('data:')) return false;
  final comma = trimmed.indexOf(',');
  if (comma < 0) return true;
  return trimmed.substring(comma + 1).trim().isEmpty;
}
String completeRenderableImageUri(
  String data, {
  String mimeType = 'image/png',
}) {
  final trimmed = data.trim();
  if (trimmed.isEmpty || isCompleteImageUri(trimmed)) return trimmed;
  return 'data:$mimeType;base64,$trimmed';
}
String? mimeTypeFromImageUri(String uri) {
  final trimmed = uri.trim();
  if (trimmed.startsWith('data:')) {
    final comma = trimmed.indexOf(',');
    if (comma <= 5) return null;
    final mime = trimmed.substring(5, comma).split(';').first.trim();
    return mime.isEmpty ? null : mime;
  }
  final path = trimmed.split('?').first;
  final dot = path.lastIndexOf('.');
  if (dot < 0 || dot == path.length - 1) return null;
  return switch (path.substring(dot + 1).toLowerCase()) {
    'jpg' || 'jpeg' => 'image/jpeg',
    'gif' => 'image/gif',
    'webp' => 'image/webp',
    'png' => 'image/png',
    _ => null,
  };
}
