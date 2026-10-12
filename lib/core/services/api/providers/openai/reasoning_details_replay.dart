/// Normalizes OpenRouter-style `reasoning_details` before they are replayed to
/// an Anthropic-backed upstream.
library;
bool reasoningDetailsLookAnthropic(dynamic raw) {
  if (raw is! List) return false;
  for (final item in raw) {
    if (item is! Map) continue;
    final format = item['format'];
    if (format is String && format.toLowerCase().contains('anthropic')) {
      return true;
    }
  }
  return false;
}
List<Map<String, dynamic>>? normalizeReasoningDetailsForReplay(dynamic raw) {
  if (raw is! List || raw.isEmpty) return null;
  final merged = <_Block>[];
  for (final item in raw) {
    if (item is! Map) continue;
    final entry = item.map((key, value) => MapEntry(key.toString(), value));
    final block = _Block(entry);
    if (block.textKey == null) {
      merged.add(block);
      continue;
    }
    final previous = merged.isEmpty ? null : merged.last;
    if (previous != null && previous.canAbsorb(block)) {
      previous.absorb(block);
    } else {
      merged.add(block);
    }
  }
  final out = <Map<String, dynamic>>[];
  for (final block in merged) {
    final textKey = block.textKey;
    if (textKey == null) {
      out.add(block.entry);
      continue;
    }
    if (block.text.isEmpty) continue;
    block.entry[textKey] = block.text;
    out.add(block.entry);
  }
  return out.isEmpty ? null : out;
}
class _Block {
  _Block(this.entry)
    : type = (entry['type'] ?? 'reasoning.text').toString(),
      textKey = _textKeyFor(entry) {
    final value = textKey == null ? null : entry[textKey];
    text = value is String ? value : '';
  }
  final Map<String, dynamic> entry;
  final String type;
  final String? textKey;
  late String text;
  String? get signature => _asNonEmptyString(entry['signature']);
  bool canAbsorb(_Block next) {
    if (next.type != type) return false;
    if (next.textKey != textKey) return false;
    if (!_sameOptional(entry['id'], next.entry['id'])) return false;
    if (!_sameOptional(entry['index'], next.entry['index'])) return false;
    if (!_sameOptional(entry['format'], next.entry['format'])) return false;
    final current = signature;
    if (current == null) return true;
    final incoming = next.signature;
    if (incoming != null) return incoming == current;
    return next.text.isEmpty;
  }
  void absorb(_Block next) {
    text += next.text;
    final incoming = next.signature;
    if (incoming != null) entry['signature'] = incoming;
    for (final field in next.entry.entries) {
      if (field.key == textKey || field.key == 'signature') continue;
      if (entry[field.key] == null && field.value != null) {
        entry[field.key] = field.value;
      } else {
        entry.putIfAbsent(field.key, () => field.value);
      }
    }
  }
}
String? _textKeyFor(Map<String, dynamic> entry) {
  final type = (entry['type'] ?? 'reasoning.text').toString();
  if (type == 'reasoning.text') return 'text';
  if (type != 'reasoning.summary') return null;
  if (entry['summary'] is String) return 'summary';
  if (entry['text'] is String) return 'text';
  return 'summary';
}
bool _sameOptional(dynamic a, dynamic b) {
  if (a == null || b == null) return true;
  return a == b;
}
String? _asNonEmptyString(dynamic value) {
  if (value is! String || value.isEmpty) return null;
  return value;
}
