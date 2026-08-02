import 'package:uuid/uuid.dart';

/// A user-defined reusable prompt template.
class CustomPrompt {
  final String id;
  final String title;
  final String content;
  final String? description;
  final List<String> tags;
  final DateTime createdAt;
  final DateTime updatedAt;
  final bool isFavorite;

  const CustomPrompt({
    required this.id,
    required this.title,
    required this.content,
    this.description,
    this.tags = const [],
    required this.createdAt,
    required this.updatedAt,
    this.isFavorite = false,
  });

  factory CustomPrompt.create({
    required String title,
    required String content,
    String? description,
    List<String> tags = const [],
  }) {
    final now = DateTime.now();
    return CustomPrompt(
      id: const Uuid().v4(),
      title: title,
      content: content,
      description: description,
      tags: tags,
      createdAt: now,
      updatedAt: now,
    );
  }

  CustomPrompt copyWith({
    String? id,
    String? title,
    String? content,
    String? description,
    List<String>? tags,
    DateTime? createdAt,
    DateTime? updatedAt,
    bool? isFavorite,
  }) {
    return CustomPrompt(
      id: id ?? this.id,
      title: title ?? this.title,
      content: content ?? this.content,
      description: description ?? this.description,
      tags: tags ?? this.tags,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      isFavorite: isFavorite ?? this.isFavorite,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'title': title,
    'content': content,
    'description': description,
    'tags': tags,
    'createdAt': createdAt.toIso8601String(),
    'updatedAt': updatedAt.toIso8601String(),
    'isFavorite': isFavorite,
  };

  static CustomPrompt fromJson(Map<String, dynamic> json) => CustomPrompt(
    id: json['id'] as String? ?? const Uuid().v4(),
    title: json['title'] as String? ?? '',
    content: json['content'] as String? ?? '',
    description: json['description'] as String?,
    tags: (json['tags'] as List<dynamic>?)?.cast<String>() ?? const [],
    createdAt: json['createdAt'] != null
        ? DateTime.tryParse(json['createdAt'] as String) ?? DateTime.now()
        : DateTime.now(),
    updatedAt: json['updatedAt'] != null
        ? DateTime.tryParse(json['updatedAt'] as String) ?? DateTime.now()
        : DateTime.now(),
    isFavorite: json['isFavorite'] as bool? ?? false,
  );
}
