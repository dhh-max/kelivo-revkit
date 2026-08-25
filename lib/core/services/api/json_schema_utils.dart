/// Shared JSON Schema helpers for tool parameter handling.
///
/// MCP servers routinely describe nested objects through local `$ref`s into a
/// `$defs` / `definitions` block. A reader that does not follow the reference
/// sees an empty node, so the schema we advertise to the model has to inline
/// those references first — otherwise the whole nested object is invisible and
/// the model fills in nothing.
library;
const int _maxRefDepth = 12;
const int _maxRefExpansions = 512;
const String _refKey = r'$ref';
const Set<String> _schemaMapKeywords = {'properties'};
const Set<String> _schemaListKeywords = {
  'anyOf',
  'oneOf',
  'allOf',
  'any_of',
  'one_of',
  'all_of',
  'items',
};
const Set<String> _subSchemaKeywords = {'items', 'additionalProperties'};
const Set<String> _definitionKeywords = {r'$defs', 'definitions'};
const Set<String> _annotationKeywords = {
  'description',
  'title',
  'default',
  'examples',
  'deprecated',
  'readOnly',
  'writeOnly',
  r'$comment',
};
class _RefBudget {
  _RefBudget({this.expandAdditionalProperties = true});
  int expansions = 0;
  final bool expandAdditionalProperties;
}
/// Inline every resolvable local `$ref` in [schema] against its own root.
Map<String, dynamic> resolveJsonSchemaRefs(
  Map<String, dynamic> schema, {
  bool expandAdditionalProperties = true,
}) {
  final resolved = _resolveSchema(
    schema,
    schema,
    const <String>{},
    0,
    _RefBudget(expandAdditionalProperties: expandAdditionalProperties),
  );
  return resolved is Map<String, dynamic> ? resolved : schema;
}
dynamic _resolveSchema(
  dynamic node,
  Map<String, dynamic> root,
  Set<String> active,
  int depth,
  _RefBudget budget,
) {
  if (node is List) {
    return [
      for (final e in node) _resolveSchema(e, root, active, depth, budget),
    ];
  }
  if (node is! Map) return node;
  final m = Map<String, dynamic>.from(node);
  final ref = m[_refKey];
  if (ref is String && ref.trim().isNotEmpty) {
    final pointer = ref.trim();
    final exhausted =
        active.contains(pointer) ||
        depth >= _maxRefDepth ||
        budget.expansions >= _maxRefExpansions;
    m.remove(_refKey);
    if (!exhausted) {
      final target = _lookupRef(pointer, root);
      if (target != null && target is! bool) {
        budget.expansions++;
        final resolved = _resolveSchema(
          target is Map ? Map<String, dynamic>.from(target) : target,
          root,
          <String>{...active, pointer},
          depth + 1,
          budget,
        );
        if (resolved is Map<String, dynamic>) {
          return _overlayAnnotations(resolved, m);
        }
        return resolved;
      }
    }
  }
  return _walkKeywords(m, root, active, depth, budget);
}
Map<String, dynamic> _overlayAnnotations(
  Map<String, dynamic> target,
  Map<String, dynamic> siblings,
) {
  var out = target;
  var copied = false;
  siblings.forEach((key, value) {
    if (!_annotationKeywords.contains(key)) return;
    if (!copied) {
      out = Map<String, dynamic>.from(target);
      copied = true;
    }
    out[key] = value;
  });
  return out;
}
Map<String, dynamic> _walkKeywords(
  Map<String, dynamic> node,
  Map<String, dynamic> root,
  Set<String> active,
  int depth,
  _RefBudget budget,
) {
  final out = <String, dynamic>{};
  node.forEach((key, value) {
    if (_definitionKeywords.contains(key)) return;
    if (_schemaMapKeywords.contains(key) && value is Map) {
      out[key] = <String, dynamic>{
        for (final entry in value.entries)
          entry.key.toString(): _resolveSchema(
            entry.value,
            root,
            active,
            depth,
            budget,
          ),
      };
      return;
    }
    if (_schemaListKeywords.contains(key) && value is List) {
      out[key] = [
        if (value.isNotEmpty)
          _resolveSchema(value.first, root, active, depth, budget),
        if (value.length > 1) ...value.skip(1),
      ];
      return;
    }
    if (key == 'additionalProperties' && !budget.expandAdditionalProperties) {
      out[key] = value;
      return;
    }
    if (_subSchemaKeywords.contains(key) && (value is Map || value is List)) {
      out[key] = _resolveSchema(value, root, active, depth, budget);
      return;
    }
    out[key] = value;
  });
  return out;
}
dynamic _lookupRef(String ref, Map<String, dynamic> root) {
  if (!ref.startsWith('#')) return null;
  final rawFragment = ref.substring(1);
  if (rawFragment.isEmpty) return root;
  String fragment;
  try {
    fragment = Uri.decodeComponent(rawFragment);
  } catch (_) {
    fragment = rawFragment;
  }
  if (!fragment.startsWith('/')) return null;
  dynamic current = root;
  for (final rawSegment in fragment.substring(1).split('/')) {
    final segment = rawSegment.replaceAll('~1', '/').replaceAll('~0', '~');
    if (current is Map) {
      if (!current.containsKey(segment)) return null;
      current = current[segment];
    } else if (current is List) {
      final index = int.tryParse(segment);
      if (index == null || index < 0 || index >= current.length) return null;
      current = current[index];
    } else {
      return null;
    }
  }
  return current;
}
