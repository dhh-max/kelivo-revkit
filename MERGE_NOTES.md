# MERGE_NOTES — Kelivo RevKit + SoLab 2.5

合并基底：`kelivo-revkit-pro-max` (RevKit, ke)
引入源：`solab2.5` (so)
输出目录：`/storage/emulated/0/社工/kelivo-revkit-pro-max-merged/`
日期：2026-10-06
版本：`2.5.1+4207`

---

## 合并策略

1. **ke 为基底**，保留所有 RevKit 独有功能：
   - `@kelivo/reverse`、`@kelivo/dex`、`@kelivo/context`、`@kelivo/memory`、`apk_reverse`
   - 神经权能网关、Skills、hotkey、custom_prompt、context_template、desktop/drop/webview_wkwebview/llama 等
2. **so 新增目录整体复制**（ke 里没有，安全合并）
3. **so 覆盖 ke** 仅限 `solab_apk/` 模块（so 是 2.5 最新版，规模显著大于 ke 的旧版）
4. **其他 ke 与 so 都存在的文件**：保留 ke 版本，把 so 版本放到 `refs_solab25/` 供手工接线
5. **pubspec.yaml**：保留 ke 全部内容，追加 so 新增依赖与资源；更新版本号

---

## 已合并内容

### A. 新增（so → ke，直接加入）

| 路径 | 说明 |
|---|---|
| `lib/features/runtime/` | 任务运行时：task_runtime / task_session / tool_bridge / runtime_bridge / recovery / verification / metrics / workspace_manager / probe_planner / subagent_gate / artifact_store / evidence_store / model_gateway / multi_dex / patch_plans / failure_memory / capability_manifest |
| `lib/features/workflow/` | 工作流引擎（engine / models / pages / services） |
| `lib/features/workspace/` | 工作区（pages / terminal / widgets / navigation / layout） |
| `lib/features/scheduled_tasks/` | 定时任务（runner / preparation_binding / pages / widgets） |
| `lib/features/dev_assistant/` | 内置开发助手 |
| `lib/features/skills_builtin/` | SoLab 内置通用 skills |
| `lib/secrets/fallback.dart` | 密钥兜底 |
| `.cargo/`、`cargokit_options.yaml` | Rust 依赖缓存与 cargokit 配置 |
| `dart_test.yaml` | Dart 测试配置 |
| `NOTICE` | SoLab 3rd-party 声明 |
| `integration_test/`、`test_driver/` | 集成测试 |
| `tools/`、`tool/` | SoLab 构建/同步脚本 |
| `android/`、`dependencies/`（部分新增） | 增量合并 |

### B. 覆盖（so 覆盖 ke）

| 路径 | 说明 |
|---|---|
| `lib/features/solab_apk/` | SoLab APK 工作台 2.5 全量覆盖（含 `assistant/`、`config/` 新子目录） |
| `lib/features/solab_apk/services/apk_task_chain_service.dart` | 新增 75KB 任务链 |
| `lib/features/solab_apk/services/apk_task_command.dart` | 新增 任务命令 |
| `lib/features/solab_apk/services/apk_task_chain_verdict.dart` | 新增 任务裁决 |
| `lib/features/solab_apk/services/apk_probe_planner.dart` | 新增 探测规划 |
| `lib/features/solab_apk/services/apk_failure_memory_service.dart` | 新增 失败记忆 |
| `lib/features/solab_apk/services/apk_artifact_identity_service.dart` | 新增 产物标识 |
| `lib/features/solab_apk/services/apk_report_normalizer.dart` | 新增 报告规范化 |
| `lib/features/solab_apk/services/value_calc_service.dart` | 新增 40KB 值计算 |
| `lib/features/solab_apk/services/apk_workspace_binding_service.dart` | 34K → 94K |
| `lib/features/solab_apk/services/apk_workspace_service.dart` | 28K → 42K |
| `lib/features/solab_apk/services/apk_patch_memory_service.dart` | 27K → 51K |
| `lib/features/solab_apk/services/solab_apk_skills.dart` | 29K → 45K |
| `lib/features/solab_apk/analyzer/analyzer_gateway_impl.dart` | 30K → 51K |
| `lib/features/solab_apk/analyzer/analyzer_tools.dart` | 6K → 10K |
| `lib/features/solab_apk/services/apk_toolchain_service.dart` | 8K → 16K |
| `lib/features/solab_apk/services/apk_task_router.dart` | 12K → 18K |

### C. 保留 ke 版本 + so 版本存 refs_solab25/ 参考

| ke 文件 | refs_solab25/ 中 so 版本 |
|---|---|
| `lib/main.dart` | `refs_solab25/main.dart` |
| `lib/core/providers/settings_provider.dart` | `refs_solab25/settings_provider.dart` |
| `lib/core/providers/mcp_provider.dart` | `refs_solab25/mcp_provider.dart` |
| — | `refs_solab25/settings_provider_solab.dart` |
| — | `refs_solab25/assistant_provider.dart` |
| — | `refs_solab25/assistant_provider_solab.dart` |
| — | `refs_solab25/instruction_injection_provider.dart` |
| — | `refs_solab25/workspace_provider.dart` |

### D. 保留 ke 独有（未受 so 影响）

- `lib/core/providers/chat_provider.dart`、`context_template_provider.dart`、`custom_prompt_provider.dart`、`hotkey_provider.dart`、`mcp_favorites_provider.dart`、`skill_provider.dart`、`tool_history_provider.dart`、`update_provider.dart`
- `lib/core/services/app_control/`、`key_rotation/`、`local_inference/`
- `lib/core/models/app_control_policy.dart`、`context_template.dart`、`custom_prompt.dart`、`model_types.dart`、`skill.dart`、`tool_call_history.dart`
- `lib/features/custom_prompt/`、`device_browser/`、`device_path/`、`local_models/`、`mcp/`、`scan/`、`skills/`
- `lib/relaygo/`
- `mcp/reverse_extensions/`、`apk-rev-project/`、`app/`
- 所有 RevKit 独有 MCP：`@kelivo/reverse`、`@kelivo/dex`、`@kelivo/context`、`@kelivo/memory`

---

## 依赖合并（pubspec.yaml）

### 保留 ke 独有
```yaml
bitsdojo_window, window_manager, screen_retriever, tray_manager,
desktop_drop, hotkey_manager, cupertino_icons, ddgs,
reorderable_grid_view, mobile_scanner, scrollview_observer,
webview_flutter_wkwebview, flutter_background, encrypt, file_selector,
google_fonts, llama_flutter_android
```

### 追加 so 新增
```yaml
diffutil_dart: ^5.0.0
glob: ^2.2.0
hashlib: ^2.4.2
terminal_view:  # 路径依赖 ./dependencies/terminal_view
vyuh_node_flow: ^0.32.0
```

### 追加 dev
```yaml
fake_async: ^1.3.3
```

### 版本
```yaml
version: 2.5.1+4207
```

---

## 需要手工接线（关键）

⚠️ 这是本次合并**最重要**的后续工作。新增的所有 so 功能模块都还没被 `lib/main.dart` 装配到 Flutter 的 Provider 树里。

### 1. `lib/main.dart` 接线（参照 `refs_solab25/main.dart`）

**新增 Provider wiring：**
- `WorkspaceToolsService` — 需设置 `workspaceProviderResolver`、`runtimeProviderResolver`、`externalMountsResolver`、`sharedInstanceResolver`、`effectiveWorkRootResolver`
- `WorkspaceNavigation` — 需设置 `onOpenEnvironmentPage`、`onOpenTerminal`、`onOpenWorkspaceFiles`
- `WorkspaceProvider.defaultRootResolver`
- `ScheduledTasksService.configureDevice(businessPreferences)`
- `RuntimeBridge`、`TaskSession`、`TaskRuntime`、`ToolBridge`
- `WorkspaceManager`、`ProbePlanner`、`SubagentGate`
- `ArtifactStore`、`EvidenceStore`、`FailureMemory`
- `ModelGateway`、`MultiDex`、`PatchPlans`、`Verification`、`Metrics`、`CapabilityManifest`
- `BuiltinDevAssistant`
- `_WorkspaceStackHolder` ChangeNotifier
- `ToolRunRegistry`

### 2. `lib/core/providers/` Provider 扩展

参照 `refs_solab25/settings_provider.dart` 和 `settings_provider_solab.dart`，向 ke 的 `settings_provider.dart` 添加：
- Workspace / Workflow / Runtime / Terminal / ScheduledTask 相关设置字段
- 对应业务仓库和偏好的读写

参照 `refs_solab25/assistant_provider.dart`、`assistant_provider_solab.dart`：
- SoLab 助手预设

参照 `refs_solab25/mcp_provider.dart`：
- 新的 MCP 服务器绑定（如 SoLab MCP、workflow engine 等）

参照 `refs_solab25/workspace_provider.dart`：
- WorkspaceProvider 类及方法

### 3. 主界面接入新页面

- `workflow/pages/*` → 主导航（Home/Settings）增加"工作流"入口
- `workspace/pages/*` → 增加"工作区"入口
- `scheduled_tasks/pages/*` → 增加"定时任务"入口
- `dev_assistant/` → 内置助手设置页

### 4. 数据库迁移

SoLab 2.5 的 `lib/core/database/schema_migrations.dart`（8KB）和 `schema_versions.dart`（78KB）、`startup_failure_report.dart`（17KB）、`chat_database_repository.dart`（298KB）比 ke 版本大。若需要 SoLab 2.5 的 DB schema（新表：workspace、workflow、scheduled_task、task_session 等），需要：
- 更新 `app_database.dart`
- 重新跑 `dart run build_runner build`
- 增加 migration 版本

当前合并**未**更新数据库。若新模块运行时报错 "no such table"，需要按上述步骤生成。

### 5. `flutter pub get` + `build_runner`

```bash
flutter pub get
dart run build_runner build --delete-conflicting-outputs
flutter test test/core/providers/mcp_provider_builtin_test.dart test/kelivo_github_mcp_server_test.dart
```

---

## 冲突与已知风险

1. **so 对 RevKit 特性仅有文字引用**，无代码依赖，已验证安全：
   - `lib/features/home/services/local_tool_handlers.dart` 第 369 行仅文字提 "apk_reverse 域"
   - `lib/features/solab_apk/services/apk_task_router.dart` 仅引用 skill 名 `apk_reverse_playbook`
   - `lib/features/solab_apk/services/solab_apk_skills.dart` 仅 skill 名映射
   - **不影响 RevKit 独有 MCP**（`@kelivo/reverse`、`@kelivo/dex`、`@kelivo/context`、`@kelivo/memory`、`apk_reverse`）

2. **package name**：保留 `Kelivo`（`pubspec.yaml` 中 `name: Kelivo`），Android 包名保持 ke 的 `com.psyche.kelivo`（`android/app/build.gradle` 未改）

3. **`so` 与 `ke` 的 mcp_client**：都用 `./dependencies/mcp_client`，路径依赖已就位

4. **`terminal_view`**：需要 `./dependencies/terminal_view` 存在，so 的 `dependencies/terminal_view/` 已复制到 `merged/dependencies/terminal_view/`

5. **`.cargo`、`cargokit_options.yaml`**：Rust 依赖缓存（用于 `terminal_view`），已复制

---

## 交付清单

```
/storage/emulated/0/社工/kelivo-revkit-pro-max-merged/
├── lib/
│   ├── main.dart                        # ke 版本（500 行）
│   ├── core/                            # 大部分 ke 版本
│   ├── features/
│   │   ├── assistant/ ...               # ke
│   │   ├── chat/ ...                    # ke
│   │   ├── dev_assistant/               # ← so 新增
│   │   ├── runtime/                     # ← so 新增
│   │   ├── scheduled_tasks/             # ← so 新增
│   │   ├── skills/                      # ke
│   │   ├── skills_builtin/              # ← so 新增
│   │   ├── solab_apk/                   # so 覆盖
│   │   ├── workflow/                    # ← so 新增
│   │   └── workspace/                   # ← so 新增
│   ├── secrets/                         # ← so 新增
│   └── ...
├── refs_solab25/                        # so 版本 main.dart / providers 参考
├── tools/  tool/                          # so 新增脚本
├── dependencies/                        # so 新增（terminal_view）
├── assets/                              # so 新增（pet 动画、licenses、skills/skill-creator、model_catalog）
├── integration_test/ test_driver/       # so 新增
├── drift_schemas/                       # so 新增（部分）
├── MERGE_NOTES.md                       # ← 本文件
├── pubspec.yaml                         # 已合并依赖
└── ...                                  # ke 全部内容保留
```

---

## 下一步建议

1. **手工接线 `lib/main.dart`**：把 `refs_solab25/main.dart` 中的新 Provider wiring 段落挑出来，插入 ke 的 `main.dart` 中对应位置。建议以 `_WorkspaceStackHolder`、`WorkspaceToolsService`、`ScheduledTasksService` 三块为最小可运行起点。

2. **数据模型补齐**：若需运行 workflow/workspace/scheduled_tasks 功能，需按 so 版本更新 `lib/core/database/app_database.dart` 并跑 `build_runner`。

3. **构建验证**：
   ```bash
   flutter pub get
   flutter test
   flutter build apk --release --target-platform android-arm64
   ```

4. **功能验证清单**：
   - [ ] RevKit 特色：`@kelivo/reverse`、`@kelivo/dex`、`@kelivo/context`、`@kelivo/memory` 工具仍可调用
   - [ ] 神经权能网关：能导入/编辑助手配置
   - [ ] SoLab APK 工作台：能解包、分析、修改、签名
   - [ ] SoLab 新增：runtime、workflow、workspace、scheduled_tasks、dev_assistant 页面可打开
