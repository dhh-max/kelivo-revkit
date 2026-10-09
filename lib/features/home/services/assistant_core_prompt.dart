import '../../../core/models/assistant.dart';
import '../../../core/providers/assistant_provider.dart';

/// 闲聊轮（ToolLoadPolicy.none）系统提示解析：按助手隔离，不串提示词。
///
/// 2026-09-29（第 69 项）：`message_generation_service` 在 Tool-Free 轮次
/// 曾对所有助手无条件注入 `AssistantProvider.apkModSystemPromptCore` ——
/// 开发助手与用户自建助手在「你好」这类轮次会被替换成 SoLab 的身份与授权
/// 边界，属于跨助手串提示词。解析顺序：
/// 1. 助手自己的 `systemPromptCore`（内置助手在 definition() 里声明）；
/// 2. 该助手自身的 `systemPrompt`（自建助手没有另一份精简版时不伪装成别人）；
/// 3. 只有「确认是内置 APK 助手却没有 core」（老数据未迁移）才回落到 APK 核心；
/// 4. 其余返回 null —— 保持 message_builder 的既有回落链（会话提示 > 助手提示）。
abstract final class AssistantCorePrompt {
  static String? forCasualRound(Assistant? assistant) {
    if (assistant == null) return null;
    final core = assistant.systemPromptCore.trim();
    if (core.isNotEmpty) return core;
    final own = assistant.systemPrompt.trim();
    if (own.isNotEmpty) return own;
    if (assistant.id == AssistantProvider.apkModAssistantId) {
      return AssistantProvider.apkModSystemPromptCore;
    }
    return null;
  }
}
