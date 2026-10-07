import 'model_override_payload_parser.dart';

class CustomRequestMerger {
  static const Set<String> _protectedAssistantHeaders = {'x-conversation-id'};

  static Map<String, String> mergeHeaders({
    Map<String, String> base = const <String, String>{},
    Map<String, String>? assistant,
    Map<String, String> providerAutomatic = const <String, String>{},
    Map<String, String> provider = const <String, String>{},
    Map<String, String> model = const <String, String>{},
  }) {
    final protected = <String, String>{};
    final ordinaryAssistant = <String, String>{};
    if (assistant != null) {
      for (final entry in assistant.entries) {
        if (_protectedAssistantHeaders.contains(entry.key.toLowerCase())) {
          protected[entry.key] = entry.value;
        } else {
          ordinaryAssistant[entry.key] = entry.value;
        }
      }
    }

    final merged = <String, String>{};
    for (final layer in <Map<String, String>>[
      base,
      ordinaryAssistant,
      providerAutomatic,
      provider,
      model,
      protected,
    ]) {
      _addHeadersCaseInsensitive(merged, layer);
    }
    return merged;
  }

  static Map<String, dynamic> mergeBody({
    Map<String, dynamic>? assistant,
    Object? providerRows,
    Map<String, dynamic> model = const <String, dynamic>{},
  }) {
    final merged = <String, dynamic>{};
    if (assistant != null) {
      for (final entry in assistant.entries) {
        final value = entry.value;
        merged[entry.key] = value is String
            ? ModelOverridePayloadParser.parseOverrideValue(value)
            : value;
      }
    }
    merged.addAll(_customBodyFromRows(providerRows));
    merged.addAll(model);
    return merged;
  }

static void _addHeadersCaseInsensitive(
     Map<String, String> target,
     Map<String, String> layer,
   ) {
     for (final entry in layer.entries) {
       final normalized = entry.key.toLowerCase();
       target.removeWhere((key, _) => key.toLowerCase() == normalized);
       target[entry.key] = entry.value;
     }
   }

   static Map<String, dynamic> _customBodyFromRows(Object? rows) {
     if (rows is Map<String, dynamic>) {
       return ModelOverridePayloadParser.customBody(rows);
     }
     if (rows is Map) {
       final cast =
           <String, dynamic>{
             for (final e in rows.entries) e.key.toString(): e.value,
           };
       return ModelOverridePayloadParser.customBody(cast);
     }
     return const <String, dynamic>{};
   }
 }
