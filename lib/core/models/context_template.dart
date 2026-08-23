import 'dart:convert';

/// 上下文模板模型
///
/// 用于保存和重用对话上下文模板，支持快速加载预设的上下文配置。
class ContextTemplate {
  final String id;
  final String name;
  final String description;
  final String systemPrompt;
  final List<String> presetMessages;
  final List<String> tags;
  final DateTime createdAt;
  final DateTime updatedAt;
  final bool isBuiltin;

  const ContextTemplate({
    required this.id,
    required this.name,
    this.description = '',
    this.systemPrompt = '',
    this.presetMessages = const [],
    this.tags = const [],
    required this.createdAt,
    required this.updatedAt,
    this.isBuiltin = false,
  });

  ContextTemplate copyWith({
    String? id,
    String? name,
    String? description,
    String? systemPrompt,
    List<String>? presetMessages,
    List<String>? tags,
    DateTime? createdAt,
    DateTime? updatedAt,
    bool? isBuiltin,
  }) {
    return ContextTemplate(
      id: id ?? this.id,
      name: name ?? this.name,
      description: description ?? this.description,
      systemPrompt: systemPrompt ?? this.systemPrompt,
      presetMessages: presetMessages ?? this.presetMessages,
      tags: tags ?? this.tags,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      isBuiltin: isBuiltin ?? this.isBuiltin,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'name': name,
    'description': description,
    'systemPrompt': systemPrompt,
    'presetMessages': presetMessages,
    'tags': tags,
    'createdAt': createdAt.toIso8601String(),
    'updatedAt': updatedAt.toIso8601String(),
    'isBuiltin': isBuiltin,
  };

  factory ContextTemplate.fromJson(Map<String, dynamic> json) {
    return ContextTemplate(
      id: json['id'] as String,
      name: (json['name'] as String?) ?? '',
      description: (json['description'] as String?) ?? '',
      systemPrompt: (json['systemPrompt'] as String?) ?? '',
      presetMessages: (json['presetMessages'] as List?)?.cast<String>() ?? const [],
      tags: (json['tags'] as List?)?.cast<String>() ?? const [],
      createdAt: DateTime.tryParse(json['createdAt'] as String? ?? '') ?? DateTime.now(),
      updatedAt: DateTime.tryParse(json['updatedAt'] as String? ?? '') ?? DateTime.now(),
      isBuiltin: json['isBuiltin'] as bool? ?? false,
    );
  }

  static String encodeList(List<ContextTemplate> list) =>
      jsonEncode(list.map((e) => e.toJson()).toList());

  static List<ContextTemplate> decodeList(String raw) {
    try {
      final arr = jsonDecode(raw) as List<dynamic>;
      return [
        for (final e in arr) ContextTemplate.fromJson(e as Map<String, dynamic>),
      ];
    } catch (_) {
      return const [];
    }
  }

  /// 内置模板：代码助手
  static ContextTemplate get codeAssistant => ContextTemplate(
    id: 'builtin_code_assistant',
    name: '代码助手',
    description: '专业的编程助手，擅长代码审查、调试和优化',
    systemPrompt: '''你是一个专业的编程助手。请遵循以下原则：
1. 代码要简洁、高效、可维护
2. 优先使用最佳实践和设计模式
3. 解释代码的工作原理和潜在问题
4. 提供完整的可运行代码示例
5. 考虑边界情况和错误处理''',
    presetMessages: [],
    tags: ['编程', '开发', '代码审查'],
    createdAt: DateTime.now(),
    updatedAt: DateTime.now(),
    isBuiltin: true,
  );

  /// 内置模板：写作助手
  static ContextTemplate get writingAssistant => ContextTemplate(
    id: 'builtin_writing_assistant',
    name: '写作助手',
    description: '帮助你提升写作质量，润色文章',
    systemPrompt: '''你是一个专业的写作助手。请遵循以下原则：
1. 保持原文的核心意思和语气
2. 提升语言的流畅性和表达力
3. 修正语法和拼写错误
4. 提供多种改写方案供选择
5. 给出具体的修改建议和理由''',
    presetMessages: [],
    tags: ['写作', '润色', '文案'],
    createdAt: DateTime.now(),
    updatedAt: DateTime.now(),
    isBuiltin: true,
  );

  /// 内置模板：翻译专家
  static ContextTemplate get translationExpert => ContextTemplate(
    id: 'builtin_translation_expert',
    name: '翻译专家',
    description: '专业的多语言翻译助手',
    systemPrompt: '''你是一个专业的翻译专家。请遵循以下原则：
1. 准确传达原文的意思和语气
2. 使用地道的目标语言表达
3. 保留专业术语的准确性
4. 注意文化差异和语境
5. 提供多种翻译选项时说明各自的适用场景''',
    presetMessages: [],
    tags: ['翻译', '多语言', '本地化'],
    createdAt: DateTime.now(),
    updatedAt: DateTime.now(),
    isBuiltin: true,
  );

  /// 内置模板：数据分析
  static ContextTemplate get dataAnalyst => ContextTemplate(
    id: 'builtin_data_analyst',
    name: '数据分析',
    description: '帮助分析数据、生成洞察和报告',
    systemPrompt: '''你是一个专业的数据分析师。请遵循以下原则：
1. 从数据中提取有价值的洞察
2. 使用清晰的结构呈现分析结果
3. 提供可操作的建议
4. 说明数据的局限性和假设
5. 优先使用数据说话，避免主观臆断''',
    presetMessages: [],
    tags: ['数据分析', '统计', '报告'],
    createdAt: DateTime.now(),
    updatedAt: DateTime.now(),
    isBuiltin: true,
  );

  /// 获取所有内置模板
  static List<ContextTemplate> get builtinTemplates => [
    codeAssistant,
    writingAssistant,
    translationExpert,
    dataAnalyst,
  ];
}
