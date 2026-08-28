# Kelivo RevKit 应用技术参考

> **版本**: v2.0.0+4100 · **技术栈**: Dart 3.12.1 + Flutter 3.44.1  
> **支持平台**: Android / iOS / macOS / Windows / Linux

---

## 1. 项目架构

```
lib/
├── main.dart              入口：平台分发 + 初始化
├── core/                  核心层
│   ├── database/          SQLite (drift) + Hive 双存储
│   ├── models/            数据模型（Hive + drift）
│   ├── providers/         Provider 状态管理（~30 个）
│   ├── services/          业务服务
│   └── utils/             通用工具
├── features/              特征模块（22 个）
│   ├── assistant/         助手管理
│   ├── backup/            备份恢复 UI
│   ├── chat/              聊天视图与操作
│   ├── custom_prompt/     自定义提示词
│   ├── device_browser/    设备浏览器
│   ├── home/              主页面（聊天入口）
│   ├── instruction_injection/  指令注入
│   ├── local_models/      本地模型管理
│   ├── mcp/               MCP 配置界面
│   ├── migration/         数据迁移
│   ├── model/             模型管理
│   ├── provider/          服务商管理
│   ├── quick_phrase/      快捷短语
│   ├── scan/              扫码
│   ├── search/            搜索（含本地混合）
│   ├── settings/          设置
│   ├── skills/            技能系统
│   ├── solab_apk/         APK 逆向分析 UI
│   ├── stats/             统计
│   ├── translate/         翻译
│   └── world_book/        世界书
├── desktop/               桌面端适配（~50 个文件）
├── relaygo/               API 网关代理（独立文档）
└── shared/                共享 UI 组件
```

## 2. 应用启动流程

1. `main.dart` 初始化：Provider → 窗口 → 本地化 → 主题
2. `_selectHome()` 按平台分发：桌面 → `DesktopHomePage`；移动端 → `HomePage`
3. 数据库启动门禁（`DatabaseInstallationGate`）校验完整性
4. 业务数据启动门禁（`BusinessStartupGate`）执行迁移
5. 加载用户设置、助手列表、模型配置、MCP 配置
6. 恢复最近的对话会话

## 3. 核心服务层

### 3.1 聊天服务

| 文件 | 说明 |
|------|------|
| `chat_service.dart` | 消息收发核心 |
| `prompt_transformer.dart` | 请求体转换 |
| `document_text_extractor.dart` | 文档文本提取 |
| `custom_request_merger.dart` | 自定义请求合并 |

### 3.2 本地推理

| 文件 | 说明 |
|------|------|
| `local_inference_service.dart` | 端侧模型推理（LLaMA 等） |
| `sherpa_onnx` | 端侧语音识别 |
| `llama_flutter_android` | Android 端侧大模型 |

### 3.3 日志系统

| 文件 | 说明 |
|------|------|
| `flutter_logger.dart` | Flutter 日志层 |
| `context_logger.dart` | 上下文感知日志 |
| `log_payload_elider.dart` | 日志脱敏 |
| `log_redactor.dart` | 敏感信息掩码 |
| `context_log_tail_reader.dart` | 日志尾读 |

### 3.4 本地工具注册

| 文件 | 说明 |
|------|------|
| `local_tool_registry.dart` | 本地工具注册表 |
| `tool_call_loop_guard.dart` | 工具调用死循环防护 |
| `local_tool_names.dart` | 工具命名常量 |

## 4. 特征模块

### 4.1 助手管理（assistant）

- 创建、编辑、删除助手
- 系统提示词、Skills 绑定、神经权能网关开关
- 按标签分组、排序
- 模型预设、快捷短语绑定

### 4.2 聊天（chat）

| 组件 | 说明 |
|------|------|
| `chat_history_page.dart` | 历史列表 |
| `html_preview_page.dart` | HTML 预览 |
| `message_edit_page.dart` | 消息编辑 |
| `select_copy_page.dart` | 选择复制 |
| `image_viewer_page.dart` | 图片查看器 |

### 4.3 首页（home）

核心控制器：
- `chat_controller.dart` — 消息流控制
- `generation_controller.dart` — 生成控制
- `stream_controller.dart` — SSE 流处理
- `scroll_controller.dart` — 滚动管理
- `active_streaming_message_store.dart` — 流式消息存储
- `home_view_model.dart` — 状态管理
- `latest_wins_checkpoint_writer.dart` — 检查点写入

### 4.4 MCP 界面

- MCP 服务器管理（增删改查）
- 工具历史查看（`tool_history_page.dart`）
- 参数模板、自动审批规则配置

### 4.5 技能系统（skills）

- Markdown/JSON/YAML/DOCX/ZIP 导入
- 版本快照与回滚
- 助手绑定与触发词

### 4.6 搜索（search）

- `global_session_search_service.dart` — 全局会话搜索
- 支持本地混合搜索（Bing/DDG/百度/搜狗/360）

### 4.7 APK 逆向（solab_apk）

- `analyzer/` — 分析引擎
- `data/` — 数据模型
- `services/` — 工具执行服务

## 5. 数据模型与存储

### 5.1 Hive 模型

| 模型 | 说明 |
|------|------|
| `Assistant` | 助手配置 |
| `AssistantMemory` | 助手记忆 |
| `AssistantTag` | 助手标签 |
| `Conversation` | 会话 |
| `ChatMessage` | 聊天消息 |
| `CustomPrompt` | 自定义提示词 |
| `InstructionInjection` | 指令注入 |
| `Skill` | 技能 |
| `WorldBook` | 世界书 |
| `QuickPhrase` | 快捷短语 |
| `UserProfileField` | 用户画像字段 |
| `TokenUsage` | Token 用量 |
| `ToolCallHistory` | 工具调用历史 |
| `ModelTypes` | 模型类型 |
| `CompressContextOptions` | 上下文压缩选项 |
| `ContextTemplate` | 上下文模板 |
| `PresetMessage` | 预置消息 |
| `ProviderGroup` | 提供商分组 |

### 5.2 数据库层

| 文件 | 说明 |
|------|------|
| `app_database.dart` | drift 主数据库 |
| `business_data.dart` | 业务数据模型 |
| `business_migration_engine.dart` | 迁移引擎 |
| `business_restore_service.dart` | 恢复服务 |
| `business_settings_merger.dart` | 设置合并 |
| `chat_database_gateway.dart` | 聊天数据库网关 |
| `chat_database_repository.dart` | 聊天存储库 |
| `generation_run.dart` | 生成运行记录 |
| `startup_recovery_service.dart` | 启动恢复 |

## 6. 桌面端适配

### 6.1 入口分发

| 平台 | 入口 |
|------|------|
| macOS / Windows / Linux | `DesktopHomePage` |
| Android / iOS | `HomePage` |

### 6.2 桌面组件

- `desktop_nav_rail.dart` — 侧导航栏
- `desktop_tray_controller.dart` — 系统托盘
- `desktop_window_controller.dart` — 窗口管理（大小/位置）
- `macos_window_position.dart` — macOS 窗口位置记忆
- `hotkeys/` — 全局快捷键
- `desktop_settings_page.dart` — 桌面设置页
- `setting/` — 桌面设置子页
- `widgets/` — 桌面专用组件
- `dialog/*.dart` — 桌面弹窗

### 6.3 桌面弹窗

`add_provider_dialog`, `chat_history_dialog`, `html_preview_dialog`, `mcp_servers_popover`, `mini_map_popover`, `model_edit_dialog`, `model_fetch_dialog`, `quick_phrase_popover`, `reasoning_budget_popover`, `search_provider_popover`, `select_copy_dialog`, `user_profile_dialog`, `instruction_injection_popover`

## 7. 主题与设计系统

| 文件 | 说明 |
|------|------|
| `design_tokens.dart` | 设计令牌 |
| `palettes.dart` | 色板定义 |
| `theme_factory.dart` | 主题工厂 |
| `theme_provider.dart` | 主题 Provider |
| `custom_theme.dart` | 自定义主题 |
| `app_semantic_colors.dart` | 语义颜色 |
| `app_font_weights.dart` | 字重定义 |
| `chat_bubble_style.dart` | 聊天气泡样式 |

## 8. 国际化

- 4 个 ARB 文件保持同步：`app_en.arb`, `app_zh.arb`, `app_zh_Hans.arb`, `app_zh_Hant.arb`
- `flutter gen-l10n` 生成 `app_localizations.dart`
- 覆盖中/英/简繁全部 UI 文本

## 9. 神经网络权能网关

- 助手级别开关，默认关闭
- 支持导入目标：系统提示词 / 记忆 / 技能 / 指令注入 / 世界书 / MCP 绑定 / 本地工具 / 快捷短语 / 搜索设置
- 支持删除、更新、列表、详情操作
- 支持世界书 entry 细粒度编辑、快捷短语排序、技能版本快照/回滚
- 批量导入导出、权限审计
- 执行结果回显与撤销

## 10. 备份与恢复

| 组件 | 说明 |
|------|------|
| `backup_isolate_runner.dart` | 后台隔离运行 |
| `backup_task_progress.dart` | 任务进度 |
| `chatbox_backup_archive.dart` | 聊天备份归档 |
| `chatbox_importer.dart` | 聊天导入 |
| `data_sync.dart` | 数据同步 |
| `restore_bundle_*` | 恢复包处理（~10 个文件） |
| `restore_durability.dart` | 恢复持久化 |
| `restore_live_database.dart` | 实时数据库恢复 |
| `restore_trace_service.dart` | 恢复追踪 |
| `s3_client.dart` | S3 备份 |

## 11. 本地搜索系统

- 聚合 Bing Local / DuckDuckGo / 百度 / 搜狗 / 360
- 无需 API Key
- 自动语言识别与源路由
- 广告过滤 / 坏站过滤 / URL 去重 / 权重排序

## 12. 性能与资源

- 共享 `HttpClient` 连接池（复用 keep-alive）
- 内存级 ELF/DEX 解析（纯 Dart，无原生依赖）
- 大 APK 分片增量分析（100MB+ 防 OOM）
- 解包/分析断点续传
- 分析超时降级机制

## 13. 构建与发布

```bash
flutter pub get
flutter gen-l10n
dart run build_runner build --delete-conflicting-outputs
dart format lib/
flutter analyze
flutter test
flutter build apk --release --target-platform android-arm64
```

## 14. 安全设计

- 神经权能网关默认关闭，高风险操作需确认
- Key 加密存储（AES）
- 管理接口双鉴权（admin-token + Bearer）
- 日志脱敏（`log_payload_elider` + `log_redactor`）
- 工具调用死循环防护（`tool_call_loop_guard`）

---

*文档最后更新：v2.0.0+4100*
