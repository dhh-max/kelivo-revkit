# Kelivo RevKit

本仓库（`dhh-max/kelivo-revkit`）是 [Kelivo Plus](https://github.com/MuMu-0604/kelivo) 的再二次开发版本。Kelivo Plus 是基于 [Chevey339/kelivo](https://github.com/Chevey339/kelivo) 的二次开发版；本仓库在完整继承 Kelivo Plus 全部能力的基础上，进一步聚焦 **Android 安全与逆向工程**（RevKit = Reverse Engineering Kit）。

> 二次开发声明：本仓库不是原作者官方仓库，代码基于 Kelivo Plus 与原版 Kelivo 扩展与改造。原项目版权、协议与鸣谢请见原仓库和本仓库保留的 `LICENSE`。本项目继续遵循 AGPL-3.0 协议开源。

## Kelivo Plus 与本仓库（kelivo-revkit）的主要差异

| 模块 | Kelivo Plus | 本仓库（kelivo-revkit） |
| --- | --- | --- |
| 定位 | 移动端 AI 自主配置 + 通用增强 | 完整继承 Plus，并聚焦 Android 安全与逆向工程 |
| 内置 MCP | fetch / files / images / github / so / reverse（基础） | 全部继承，新增 `@kelivo/dex`（DEX 字节码解析）、`@kelivo/context`（对话上下文管理） |
| APK 逆向 | 基础静态分析与快速排查 | `@kelivo/reverse` 深度扩展至 20 个工具：新增 manifest 深度解析、SO/DEX 聚合分析、JNI 桥定位、跨目标字符串检索、加壳检测、过签、重打包与 DEX 注入等 |
| 预置助手 | 通用助手 | 新增“逆向分析师 / Reverse Analyst”，默认绑定 `@kelivo/reverse` |
| 神经权能网关 | 有 | 完全继承 |
| Skills 技能系统 | 有 | 完全继承 |
| GitHub 写入工具 | 有 | 完全继承 |
| 本地混合搜索 | 有 | 完全继承 |
| 移动端导入 | 有 | 完全继承 |
| 工具体验 | 中文化 + 分组 | 完全继承 |

## 核心功能

### 神经权能网关

- 在助手设置中开启“允许该助手启用神经权能网关”后，助手可以通过对话执行授权范围内的配置操作。
- 支持把用户提供的指令、粘贴内容、文件内容、或“刚刚生成的内容”导入到指定位置。
- 支持目标包括当前助手系统提示词、记忆、技能、指令注入、世界书、MCP 绑定、本地工具、快捷短语、搜索设置等。
- 补齐删除、更新、列表/详情、世界书 entry 细粒度编辑、快捷短语排序、技能版本快照/回滚、批量导入导出和权限审计能力。
- 支持执行结果回显与撤销，降低误操作风险。
- 权限默认关闭，适合只给可信助手开启。

示例：

```text
把上面生成的代码审查规范导入为一个技能，绑定到当前助手，并设置触发词：review、代码审查。
```

```text
根据我发的这份设定文档，创建一个世界书，关键词用角色名和地点名。
```

### Skills 技能系统

- 支持创建、编辑、删除、导入技能。
- 支持 Markdown、JSON、YAML、DOCX、ZIP 等格式导入。
- 技能可绑定到指定助手，也可以通过触发词自动注入。
- 适合沉淀可复用工作流，例如代码审查、写作润色、商业分析、翻译风格、角色设定等。
### 内置 MCP 工具

- `@kelivo/fetch`：网页抓取和内容提取。
- `@kelivo/files`：本地文件读取、写入、目录浏览等文件能力。
- `@kelivo/images`：图片理解、图片任务辅助能力。
- `@kelivo/github`：GitHub 仓库、文件、Issue、PR、Release、Actions、Secrets、Variables 等能力。
|- `@kelivo/so`：纯 Dart 实现的 ELF/.so 逆向分析工具集（共 26 个工具），无需额外原生依赖。
- `@kelivo/dex`：纯 Dart 实现的 DEX/ODEX 字节码解析工具集（共 10 个工具），无需额外原生依赖。
- `@kelivo/context`：对话上下文管理工具集（共 6 个工具），支持上下文统计、摘要、搜索、导出与边界管理。
- `@kelivo/reverse`：面向 APK 的静态分析、修改与快速排查工具（共 20 个工具，含过签、重打包与 DEX 注入能力）。
- 内置 MCP 运行在 App 内部，不需要用户额外启动 Node/Python 服务。

### SO/ELF 逆向分析工具

`@kelivo/so` 提供一套完整的内存级 ELF 分析工具，新建助手时默认启用：

| 类别 | 工具 |
| --- | --- |
| 基础分析 | `so_parse_header`、`so_list_sections`、`so_list_symbols`、`so_list_imports`、`so_list_exports`、`so_list_dependencies` |
| 内容提取 | `so_list_strings`、`so_read_hexdump`、`so_section_details` |
| 段与重定位 | `so_analyze_segments`、`so_analyze_dynamic`、`so_analyze_relocations` |
| 搜索 | `so_search_bytes`、`so_search_strings`、`so_section_search` |
| 符号查询 | `so_symbol_lookup` |
| 地址转换 | `so_addr_to_offset`、`so_offset_to_addr` |
| 对比与注释 | `so_compare_headers`、`so_list_notes` |
| 初始化分析 | `so_list_init_array`（.init_array/.fini_array 函数指针 + 符号名） |
| 交叉引用 | `so_xref_symbol`（重定位表中引用某符号的所有位置） |
| 加固检测 | `so_detect_packer`（UPX/梆梆/爱加密/360/娜迦/乐固/百度/DexGuard/阿里等） |
| 反调试检测 | `so_find_anti_debug`（检测 ptrace/inotify/frida/TracerPid 等反调试特征） |
| GOT/PLT 分析 | `so_got_plt_analysis`（GOT/PLT 表分析，定位 Hook 点） |
| 反汇编 | `so_disassemble`（ARM64 AArch64 指令反汇编，按符号或偏移） |

### DEX 字节码解析工具

`@kelivo/dex` 提供纯 Dart 实现的 DEX/ODEX 字节码级解析能力：

| 类别 | 工具 |
| --- | --- |
| 头部 | `dex_parse_header` |
| 字符串 | `dex_list_strings` |
| 类型 | `dex_list_types` |
| 类 | `dex_list_classes` |
| 方法 | `dex_list_methods` |
| 字段 | `dex_list_fields` |
| 注解 | `dex_list_annotations`（类级注解提取，反混淆线索） |
| 反汇编 | `dex_disassemble_method`（单方法 Dalvik 字节码反汇编） |
| 交叉引用 | `dex_xref_method`（方法级调用图——查找所有调用者） |
| 字符串搜索 | `dex_search_strings`（正则/子串搜索 DEX 字符串池） |

### 对话上下文管理工具

`@kelivo/context` 帮助模型感知并管理自身对话上下文：

| 类别 | 工具 |
| --- | --- |
| 统计 | `context_get_stats` |
| 摘要 | `context_get_summary` |
| 搜索 | `context_search` |
| 导出 | `context_export` |
| 边界 | `context_set_boundary` |
| 消息 | `context_get_messages` |

### APK 逆向分析工具

`@kelivo/reverse` 提供面向 APK 的静态分析、修改与快速排查工具（共 20 个工具）：

| 类别 | 工具 |
| --- | --- |
| 总览 | `reverse_meta_info`、`reverse_quick_triage` |
| APK 结构 | `reverse_open_apk`、`reverse_list_targets`、`reverse_manifest_summary`、`reverse_list_native_libs`、`reverse_list_dex_files`、`reverse_component_audit`、`reverse_diff_apk` |
| 深度分析 | `reverse_analyze_so`、`reverse_analyze_dex`、`reverse_find_jni_bridges`、`reverse_search_strings` |
| 安全分析 | `reverse_signature_audit`、`reverse_packer_detect`、`reverse_secret_scan` |
| 修改工具 | `reverse_kill_signature`（去除签名校验）、`reverse_resign_apk`（重打包并签名）、`reverse_inject_dex`（向 APK 注入 DEX 载荷） |
| 报告 | `reverse_report` |

推荐流程：

1. 使用 `reverse_open_apk` 打开 APK。
2. 先跑 `reverse_quick_triage` 获取快速概览。
3. 再用 `reverse_signature_audit`、`reverse_packer_detect`、`reverse_secret_scan` 做安全检查。
4. 结合 `reverse_component_audit` 和 `reverse_diff_apk` 做组件与版本对比分析。
5. 最后用 `reverse_report` 生成结构化报告。


### APK 逆向工具包
`apk_reverse` 是基于内置 `dex-jar` 运行时的 APK 逆向工具包，可在进程内直接完成解包、检索、重打包与签名等操作，无需额外网络依赖。

| 工具 | 说明 |
| --- | --- |
| `usage_advice` | 返回当前 APK 逆向工具包的使用建议。 |
| `apk_reverse_inspect` | 检查 APK 基本信息、组件、权限、签名与基础元数据。 |
| `apk_reverse_decode` | 使用 apktool 将 APK 解码为可编辑目录。 |
| `apk_reverse_jadx` | 通过内置 JADX `dex-jar` 运行时反编译 DEX。 |
| `apk_reverse_search_text` | 在解包目录、JADX 输出目录或目标文件中检索文本。 |
| `apk_reverse_search_address` | 检索资源、smali、JADX 输出与 native 库地址。 |
| `apk_reverse_build` | 对解包目录执行 apktool build，重建 APK。 |

这些工具面向底层逆向任务。若需更高层工作流，优先使用上方的 `reverse_*` 系列工具。

### APK 修改流水线（实验性功能）
`@kelivo/reverse` 还提供 APK 修改能力。配合构建工具链（`apktool`、`zipalign`、`apksigner`、`keytool`），可实现完整的修改-重打包-签名流程：

| 步骤 | 工具 / 命令 | 说明 |
| --- | --- | --- |
| 解包 | `apktool d app.apk -o out/` | 将 APK 解码为可编辑形式（smali + 资源 + manifest） |
| 修改 | 直接编辑文件 | 修改 smali / 资源 / manifest / DEX / SO |
| 重打包 | `apktool b out/ -o new.apk` | 从解码目录重建 APK |
| 对齐 | `zipalign -p 4 new.apk aligned.apk` | 对齐 APK 以优化内存映射 |
| 签名 | `apksigner sign --ks debug.jks aligned.apk` | 使用调试/发布密钥签名 |

此外，内置工具提供了一条简化路径：
1. `reverse_kill_signature` — 去除原生签名校验（如 libjiagu.so 检测）
2. `reverse_inject_dex` — 向 APK 注入 DEX 载荷（如 hook.dex）
3. `reverse_resign_apk` — 一步完成重打包与签名（自动生成调试密钥）

**示例：绕过签名校验并重新签名：**
```text
1. reverse_open_apk → 加载目标 APK
2. reverse_kill_signature → 去除 libjiagu.so 校验
3. reverse_inject_dex → 注入 hook 载荷（可选）
4. reverse_resign_apk → 输出已签名、可直接安装的 APK
```

> ⚠️ **免责声明：** 修改第三方 APK 可能违反服务条款或法律。请仅在您拥有或获得明确授权的 APK 上使用此功能。

所有工具支持传入本地文件 `path` 或 `base64` 编码的字节数据。解析器为纯 Dart 实现，完全在进程内运行，不依赖 Rizin、LIEF 等外部原生库。

### GitHub 写入工具

GitHub 工具按使用场景分组封装，不再把每个 API 端点都暴露成一个独立工具：

- 仓库管理：创建/查看/更新/删除仓库，管理分支、标签、提交、目录和文件。
- Issue 管理：创建、更新、关闭、评论、标签、指派等。
- PR 管理：创建、更新、合并、关闭、审查、行内评论、回复评论等。
- Release 管理：创建、编辑、发布、删除 release 和资源。
- Actions 管理：读取 workflow/run/job/log，触发、取消、重跑工作流。
- Secrets / Variables：仓库和环境级变量、密钥管理。

工具层已加入 GitHub API 规则收敛：空仓库建分支自动初始化、禁止 `GITHUB_` 变量名前缀、写入后使用强一致接口验证、PR 更新最小 payload、行内评论和回复评论分路径处理。

### 本地混合搜索

- 新增 Local Hybrid Search，无需 API Key。
- 聚合 Bing Local、DuckDuckGo、百度、搜狗、360。
- 中文查询会自动利用中文搜索源，英文/通用查询优先使用更稳定的本地源。
- 对搜索结果进行广告过滤、坏站过滤、URL 清洗、去重和权重排序。

### 快捷提示词面板

- 聊天输入框输入 `/` 触发快捷提示词面板，实时搜索匹配自定义提示词
- 支持键盘导航：上下箭头切换选中项，Enter 确认回填内容，Esc 关闭面板
- 点击外部区域自动关闭，页面销毁时自动清理资源避免内存泄漏
- 支持自定义提示词的增删改查，可从设置页统一管理

### MCP 功能增强

- ✅ **工具全局搜索**：MCP 页新增搜索入口，一键搜索所有 MCP 服务器的全部工具，支持按名称/描述模糊匹配
- ✅ **调用统计面板**：可视化展示各 MCP 服务器调用量、成功率、平均耗时、错误分布等数据
- ✅ **一键重连**：批量重连所有连接异常的 MCP 服务器，无需手动逐个操作
- ✅ **后台健康检查**：定时检测 MCP 服务器连接状态，自动重连异常节点
- ✅ **自动审批规则**：支持按工具名称/参数配置自动审批规则，匹配规则的工具调用无需手动确认直接执行
- ✅ **工具调用历史**：自动记录所有工具调用的入参、返回结果、耗时、执行状态，支持历史查询、筛选与导出
- ✅ **批量工具管理**：支持批量启用/禁用指定服务器的全部工具，无需逐个配置
- ✅ **MCP 逆向能力扩展**：内置 `@kelivo/reverse` MCP 静态分析工具集，总工具数达28个，本次新增3项核心能力：
  - DEX 字符串批量替换：支持正则匹配、类范围过滤、替换预览
  - APK 批量重签名：支持自定义 keystore、v1/v2 签名方案选择、自动清除旧签名
  - 一键脱壳向导：自动识别12+主流加固方案，输出适配的脱壳步骤和绕过技巧
- ✅ **工具分组收藏**：支持按使用场景自定义工具收藏夹，可快速过滤展示收藏工具，一键调用无需搜索
- ✅ **参数模板预设**：可保存任意工具的常用参数配置，调用时直接选择模板自动填充，支持模板导出共享
- ✅ **服务器分组管理**：支持给MCP服务器打标签分组，可按组执行批量重连、启用/禁用、配置导出操作
- ✅ **调用失败自动重试**：可按工具维度配置重试规则（重试次数、间隔、错误触发条件），调用失败自动触发重试无需手动操作
- ✅ **内置模板市场**：预置20+常用MCP工具调用模板（批量网页抓取、多格式文件转换、结构化数据统计分析等），开箱即用

## 使用说明

### 安装 APK

下载地址：

- 最新 Release 页面：[Kelivo RevKit Releases](https://github.com/dhh-max/kelivo-revkit/releases)

本公开 APK 的 Android 包名仍为 `com.psyche.kelivo`，与 Kelivo Plus / 原版 Kelivo 相同，因此需要注意：

- 不能直接覆盖安装原版 Kelivo 或 Kelivo Plus：签名通常不同，Android 会拒绝安装。
- 不能与原版 Kelivo / Kelivo Plus 直接共存：同一台设备上同一个包名只能安装一个应用。
- 可以覆盖安装旧的 Kelivo RevKit 版本：前提是旧版本使用同一签名，并且当前版本号不低于已安装版本。

推荐安装方式：

1. 如需保留数据，先在原版 Kelivo 或 Kelivo Plus 内完成备份或导出。
2. 卸载原版 Kelivo 或 Kelivo Plus。
3. 安装本仓库 Release 中的 Kelivo RevKit APK。
4. 重新导入配置、聊天记录或手动完成必要设置。

如需与 Kelivo Plus / 原版共存，需要构建独立包名版本：

1. 将 Android `applicationId` 改为例如 `com.psyche.kelivo.revkit`。
2. 建议同步修改应用名称为 `Kelivo RevKit`，避免桌面图标混淆。
3. 使用自己的签名重新构建 APK。
4. 该共存版会拥有独立应用数据，不能直接读取 Kelivo Plus / 原版 Kelivo 的私有数据；需要通过备份/导入迁移。

当前 Release 附带的是同包名升级包，不是共存包。

### 配置模型

1. 打开 Kelivo RevKit。
2. 进入模型或服务商设置。
3. 添加 OpenAI、Gemini、Anthropic 或其他兼容服务商。
4. 回到聊天页选择模型并开始对话。

### 开启神经权能网关

1. 进入助手设置。
2. 找到权限开关“允许该助手启用神经权能网关”。
3. 仅对可信助手开启。
4. 在对话中直接提出配置需求，例如“把这段内容导入为当前助手的系统提示词”。
5. 执行前根据提示确认，执行后可撤销最近一次变更。

### 使用 Skills

1. 进入 Skills 页面。
2. 新建技能，或导入 Markdown/JSON/YAML/DOCX/ZIP 技能文件。
3. 在助手设置的 Skills 标签页中绑定技能。
4. 聊天时也可以通过触发词自动启用相关技能。

### 配置 GitHub Token

1. 进入 MCP 页面。
2. 编辑内置 GitHub MCP 服务。
3. 在 GitHub Token 输入框填入 token。
4. 根据需要授予 `repo`、`workflow` 等 scope。
5. 回到聊天中调用 GitHub 工具。

建议使用最小权限 token，并只给可信助手开放写入型 GitHub 操作。

### 使用本地混合搜索

1. 进入搜索服务设置。
2. 启用 Local Hybrid Search。
3. 无需配置 API Key。
4. 在聊天中启用搜索后，助手会使用本地混合搜索返回结果。

## 从源码构建

环境建议：

- Flutter 3.44.1 或更高版本
- Dart 3.12.1 或更高版本
- Android SDK / NDK，Android 构建建议使用 arm64-v8a release 目标

常用命令：

```powershell
flutter pub get
flutter test test/core/providers/mcp_provider_builtin_test.dart test/kelivo_github_mcp_server_test.dart
flutter build apk --release --target-platform android-arm64
```

本地签名文件不包含在仓库中。需要自行配置 `android/key.properties` 或使用自己的 Android 签名方案。

## 安全说明

- 神经权能网关是高权限能力，默认关闭，建议只给可信助手开启；高风险覆盖、删除和批量导入操作会走确认与可撤销流程。
- GitHub 写入工具会修改远程仓库，请使用最小权限 token。
- Secrets、Token、Keystore、`android/key.properties`、构建缓存和 APK 产物不应提交到仓库。
- 本项目保留 AGPL-3.0 协议要求，分发修改版时请同步提供对应源码。

## 文档

- [二改功能说明](docs/KELIVO_PLUS_CHANGES_ZH.md)
- [Android 安装与共存说明](docs/ANDROID_INSTALLATION_ZH.md)
- [Release 说明](docs/RELEASE_NOTES_1.1.17_PLUS.md)
- [搜索升级记录](docs/KELIVO_SEARCH_UPGRADE_NOTES.md)

## 致谢

- 原项目：[Chevey339/kelivo](https://github.com/Chevey339/kelivo)
- UI 灵感来源：[RikkaHub](https://github.com/re-ovo/rikkahub)
- 感谢原作者和社区贡献者提供的基础工程。

## License

本项目基于 AGPL-3.0 协议开源，详见 [LICENSE](LICENSE)。
