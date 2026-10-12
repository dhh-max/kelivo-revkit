/// 指令注入的落点：决定这段指令进入请求的哪个位置。
///
/// 之前所有注入都被合并成一段追加到系统消息末尾（即 [afterSystem]），
/// 用户无法选择「系统提示词前 / 对话开头 / 最新消息前」——这里把位置显式化。
enum InstructionInjectionPosition {
  /// 系统提示词前：拼到 system 文本的最前面（优先级最高的约束）。
  beforeSystem,

  /// 系统提示词后（默认，保持既有行为）。
  afterSystem,

  /// 对话开头：system 之后的第一个 user 消息（靠近任务描述）。
  conversationStart,

  /// 最新消息前：紧挨着最后一条 user 消息（时效性最强）。
  beforeLatestUser;

  static InstructionInjectionPosition fromName(String? name) {
    final v = (name ?? '').trim();
    for (final p in values) {
      if (p.name == v) return p;
    }
    return InstructionInjectionPosition.afterSystem;
  }
}

class InstructionInjection {
  final String id;
  final String title;
  final String prompt;
  final String group;
  final InstructionInjectionPosition position;

  const InstructionInjection({
    required this.id,
    required this.title,
    required this.prompt,
    this.group = '',
    this.position = InstructionInjectionPosition.afterSystem,
  });

  InstructionInjection copyWith({
    String? id,
    String? title,
    String? prompt,
    String? group,
    InstructionInjectionPosition? position,
  }) {
    return InstructionInjection(
      id: id ?? this.id,
      title: title ?? this.title,
      prompt: prompt ?? this.prompt,
      group: group ?? this.group,
      position: position ?? this.position,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'title': title,
    'prompt': prompt,
    'group': group,
    'position': position.name,
  };

  static InstructionInjection fromJson(Map<String, dynamic> json) =>
      InstructionInjection(
        id: (json['id'] as String?) ?? '',
        title: (json['title'] as String?) ?? '',
        prompt: (json['prompt'] as String?) ?? '',
        group: (json['group'] as String?) ?? '',
        position: InstructionInjectionPosition.fromName(
          json['position'] as String?,
        ),
      );
}
