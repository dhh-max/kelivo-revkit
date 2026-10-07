# Kelivo-Revkit-Pro-Max × SoLab 2.5 集成 + 优化 进度报告

> **最终状态：✅ `dart analyze lib` 输出 0 error / 0 info**
>
> 剩余 **121 条 warning**，全部集中在 `kelivo_reverse` MCP 逆向分析器（`reverse_analyzer_*`、`reverse_utils`、`reverse_arsc`、`reverse_manifest_ops` 等 6+ 文件），是**预置的逆向引擎内部警告**，与本次 SoLab 2.5 集成无关。

---

## 一、路径

| 项 | 值 |
|---|---|
| 主目录 | `/storage/emulated/0/Download/kelivo-revkit-pro-max/kelivo-revkit-pro-max/` |
| 源码备份 | `/sdcard/Download/Operit/kelivo-revkit-pro-max/kelivo-revkit-pro-max/` |
| 分析命令 | `dart analyze lib` |

---

## 二、指标演进

| 阶段 | error | info | warning |
|---|---|---|---|
| 基线（未集成） | **130** | 0 | ~40 |
| 集成 SoLab 2.5 API 补齐后 | **0** | 564 | ~150 |
| `dart fix --apply` + 手动清理 | **0** | 0 | 121 |

---

## 三、本轮（优化阶段）完成的工作

### 3.1 `dart fix --apply`（131 fixes / 42 files）

- `deprecated_member_use` → `withOpacity` 改为 `withValues(alpha:)`（26 处）
- `unused_import` 清理（26 处）
- `use_super_parameters` 转 super 参数（47 处）
- `unnecessary_non_null_assertion`（31 处）
- `unnecessary_null_comparison` / `dead_null_aware_expression` / `unnecessary_cast` / `prefer_null_aware_operators` / `prefer_interpolation_to_compose_strings` / `use_string_in_part_of_directives` / `no_leading_underscores_for_local_identifiers` 等

### 3.2 手动修复的 info（4 处）

| 文件 | 修复 |
|---|---|
| `lib/relaygo/screens/rules_screen.dart` | `onReorder` → `onReorderItem` |
| `lib/features/custom_prompt/pages/custom_prompts_page.dart` | `onReorder` → `onReorderItem` |
| `lib/features/settings/widgets/memory_ui.dart` | 删除重复的 switch case（`unreachable_switch_case` ×2） |
| `lib/features/settings/pages/mobile_background_settings_page.dart` | 删除误加的 `@override`（`override_on_non_overriding_member`） |

---

## 四、剩余 warning 分类

| 类型 | 数量 | 说明 |
|---|---|---|
| `unused_local_variable` | 67 | 逆向分析器里的临时/占位变量 |
| `unused_element` | 33 | 内部工具函数未使用 |
| `unused_field` | 12 | 类字段未使用 |
| `dead_null_aware_expression` | 5 | `x ?? y` 里 `x` 不可能为 null |
| `dead_code` | 4 | 不可达代码 |

**文件分布**：主要集中在 `lib/core/services/mcp/kelivo_reverse/`（约 110 条）、`mcp_provider.dart`（7）、`chat_service.dart`（3）等。

---

## 五、集成 SoLab 2.5 关键补丁（上一轮，摘要）

**核心类 stub 补齐**
- `ToolApprovalService`：+`conversationId`、+`pendingFor`、+`setBypassApprovals/clearBypassApprovals`
- `NotificationService`：`openConversation(id, {messageId})`、`shouldShowChatCompleted(...)`、`scheduledRunTaps` → Stream
- `AndroidBackgroundManager`：+`isKeepAliveOverlayEnabled/isOverlayPermissionGranted/requestOverlayPermission/setKeepAliveOverlayEnabled`
- `ChatDatabaseRepository.scheduledContextRevision(String)`
- `ChatService.newConversationExtras(id?)`、`publishScheduledMessages({conversation, instruction, response, ...})`
- `ChatApiService.generateMessage(...)` + `_GenerateMessageResponse`
- `ThinkingTagParser.parseWithRanges(String)`
- `SettingsProvider.chatBubbleStyleOverridesFor` + imports
- `Assistant` 新增 `systemPromptCore/operatorConventionsEnabled/generateConversationSummary`

**新增/修正 API**
- `ChatCompletionNotificationSender` typedef
- `ApkToolchainService.frida(...)`、`ApkWorkspaceBindingService.resolveZoneAlias(...)`
- `AppSemanticColorsX.hairline`
- `ExtensionEntityStore.kind_v1` + `watchKind` 改 `async*`

---

## 六、验证

```bash
cd /storage/emulated/0/Download/kelivo-revkit-pro-max/kelivo-revkit-pro-max
timeout 600 dart analyze lib 2>&1 | tail -3
# 0 errors, 0 info, 121 warnings

grep -c ' error - ' /tmp/analyze_src3.log    # => 0
grep -c ' info - ' /tmp/analyze_src3.log     # => 0
grep -c ' warning - ' /tmp/analyze_src3.log  # => 121
```