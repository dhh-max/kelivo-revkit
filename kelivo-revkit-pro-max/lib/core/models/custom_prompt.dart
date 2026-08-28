import 'package:uuid/uuid.dart';

/// A user-defined reusable prompt template.
class CustomPrompt {
  final String id;
  final String title;
  final String content;
  final String? description;
  final List<String> tags;
  final String? folder;
  final DateTime createdAt;
  final DateTime updatedAt;
  final bool isFavorite;
  final List<PromptVariable> variables;

  const CustomPrompt({
    required this.id,
    required this.title,
    required this.content,
    this.description,
    this.tags = const [],
    this.folder,
    required this.createdAt,
    required this.updatedAt,
    this.isFavorite = false,
    this.variables = const [],
  });

  factory CustomPrompt.create({
    required String title,
    required String content,
    String? description,
    List<String> tags = const [],
    String? folder,
  }) {
    final now = DateTime.now();
    return CustomPrompt(
      id: const Uuid().v4(),
      title: title,
      content: content,
      description: description,
      tags: tags,
      folder: folder,
      createdAt: now,
      updatedAt: now,
      variables: PromptVariable.extractFromContent(content),
    );
  }

  CustomPrompt copyWith({
    String? id,
    String? title,
    String? content,
    String? description,
    List<String>? tags,
    String? folder,
    DateTime? createdAt,
    DateTime? updatedAt,
    bool? isFavorite,
    List<PromptVariable>? variables,
  }) {
    return CustomPrompt(
      id: id ?? this.id,
      title: title ?? this.title,
      content: content ?? this.content,
      description: description ?? this.description,
      tags: tags ?? this.tags,
      folder: folder ?? this.folder,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      isFavorite: isFavorite ?? this.isFavorite,
      variables: variables ?? this.variables,
    );
  }

  /// Resolve content by replacing {{var}} placeholders with provided values.
  String resolveContent(Map<String, String> values) {
    var result = content;
    for (final v in variables) {
      final replacement = values[v.name] ?? v.defaultValue ?? '';
      result = result.replaceAll('{{${v.name}}}', replacement);
    }
    // Also replace built-in variables
    final now = DateTime.now();
    result = result
      .replaceAll('{{date}}', '${now.year}-${now.month.toString().padLeft(2, "0")}-${now.day.toString().padLeft(2, "0")}')
      .replaceAll('{{time}}', '${now.hour.toString().padLeft(2, "0")}:${now.minute.toString().padLeft(2, "0")}')
      .replaceAll('{{datetime}}', now.toIso8601String().substring(0, 16).replaceAll('T', ' '));
    return result;
  }

  /// Whether this prompt has unresolved variables.
  bool get hasVariables => variables.isNotEmpty;

  Map<String, dynamic> toJson() => {
    'id': id,
    'title': title,
    'content': content,
    'description': description,
    'tags': tags,
    'folder': folder,
    'createdAt': createdAt.toIso8601String(),
    'updatedAt': updatedAt.toIso8601String(),
    'isFavorite': isFavorite,
    'variables': variables.map((v) => v.toJson()).toList(),
  };

  static CustomPrompt fromJson(Map<String, dynamic> json) => CustomPrompt(
    id: json['id'] as String? ?? const Uuid().v4(),
    title: json['title'] as String? ?? '',
    content: json['content'] as String? ?? '',
    description: json['description'] as String?,
    tags: (json['tags'] as List<dynamic>?)?.cast<String>() ?? const [],
    folder: json['folder'] as String?,
    createdAt: json['createdAt'] != null
        ? DateTime.tryParse(json['createdAt'] as String) ?? DateTime.now()
        : DateTime.now(),
    updatedAt: json['updatedAt'] != null
        ? DateTime.tryParse(json['updatedAt'] as String) ?? DateTime.now()
        : DateTime.now(),
    isFavorite: json['isFavorite'] as bool? ?? false,
    variables: (json['variables'] as List<dynamic>?)
        ?.map((e) => PromptVariable.fromJson(e as Map<String, dynamic>))
        .toList() ??
        PromptVariable.extractFromContent(json['content'] as String? ?? ''),
  );
}

/// A variable placeholder in a prompt template.
class PromptVariable {
  final String name;
  final String? defaultValue;
  final String? hint;

  const PromptVariable({
    required this.name,
    this.defaultValue,
    this.hint,
  });

  Map<String, dynamic> toJson() => {
    'name': name,
    'defaultValue': defaultValue,
    'hint': hint,
  };

  static PromptVariable fromJson(Map<String, dynamic> json) => PromptVariable(
    name: json['name'] as String? ?? '',
    defaultValue: json['defaultValue'] as String?,
    hint: json['hint'] as String?,
  );

  /// Extract all {{var}} or {{var:default}} or {{var|hint}} from content.
  static List<PromptVariable> extractFromContent(String content) {
    final regex = RegExp(r'{{([^}]+)}}');
    final matches = regex.allMatches(content);
    final seen = <String>{};
    final result = <PromptVariable>[];

    // Skip built-in variables
    const builtins = {'date', 'time', 'datetime'};

    for (final m in matches) {
      final raw = m.group(1)!.trim();
      String name;
      String? defaultValue;
      String? hint;

      if (raw.contains(':')) {
        final parts = raw.split(':');
        name = parts[0].trim();
        defaultValue = parts.sublist(1).join(':').trim();
      } else if (raw.contains('|')) {
        final parts = raw.split('|');
        name = parts[0].trim();
        hint = parts.sublist(1).join('|').trim();
      } else {
        name = raw;
      }

      if (name.isEmpty || builtins.contains(name) || seen.contains(name)) continue;
      seen.add(name);
      result.add(PromptVariable(name: name, defaultValue: defaultValue, hint: hint));
    }
    return result;
  }
}