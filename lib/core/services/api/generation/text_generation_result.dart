import '../../../models/message_part.dart';
import '../../../models/token_usage.dart';
/// One-shot (non-stream) generation result.
final class TextGenerationResult {
  const TextGenerationResult({
    required this.parts,
    this.usage,
    this.finishReason,
    this.reasoningDetails,
  });
  final List<MessagePart> parts;
  final TokenUsage? usage;
  final String? finishReason;
  final dynamic reasoningDetails;
  String get text => [
    for (final part in parts)
      if (part is TextPart && part.text.isNotEmpty) part.text,
  ].join();
}
