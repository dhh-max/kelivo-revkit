# Kelivo RevKit 变更说明

本文档记录本仓库（`dhh-max/kelivo-revkit`）相对 [Kelivo Plus](https://github.com/MuMu-0604/kelivo) 的主要差异，便于使用者、贡献者和后续 Codex 会话理解当前版本边界。Kelivo Plus 是基于 [Chevey339/kelivo](https://github.com/Chevey339/kelivo) 的二次开发版，本仓库在其基础上继续扩展。

## 二次开发定位

Kelivo RevKit 完整继承 Kelivo Plus 的全部能力（神经权能网关、Skills、内置 MCP、GitHub 写入工具、本地混合搜索、移动端导入等），并进一步聚焦 **Android 安全与逆向工程**（RevKit = Reverse Engineering Kit），新增 `@kelivo/dex`、`@kelivo/context` 并把 `@kelivo/reverse` 深度扩展至 17 个工具。

以下第 1–7 节为本仓库从 Kelivo Plus 继承的能力概览，第 8 节为本仓库相对 Kelivo Plus 的新增增强。

## 1. 神经权能网关

新增神经权能网关能力，让助手在获得用户授权后，可以把对话中的自然语言意图转换为配置变更。

### 关键能力

- 助手级权限开关：每个助手可独立开启或关闭神经权能网关，默认关闭。
- 对话内导入：支持用户粘贴内容、发送文件、引用上一条生成内容、或直接描述目标配置。
- 多目标配置：支持助手提示词、记忆、技能、指令注入、世界书、MCP 绑定、本地工具、快捷短语、搜索设置等。
- 补充管理能力：支持记忆、技能、快捷短语、指令注入、世界书和 MCP 配置的更新、删除、列表/详情查看。
- 世界书细粒度编辑：支持新增、更新、删除 entry，并可调整关键词、触发条件、启用状态、注入位置等字段。
- 技能版本管理：支持创建技能版本快照，并回滚到指定版本。
- 批量迁移：支持导入/导出 JSON bundle，覆盖助手设置、记忆、技能、世界书、快捷短语、指令注入、MCP 和搜索配置。
- 权限审计：记录最近神经权能网关操作，包含目标、操作、助手、时间和是否可撤销。
- 执行与撤销：执行后保留最近操作的撤销能力，降低配置错误成本。
- 系统提示注入：仅对已授权助手注入神经权能网关系统能力说明。

### 典型用法

```text
把刚刚生成的内容导入为世界书，关键词使用里面出现的人名。
```

```text
把我发的这份 Markdown 变成技能，绑定到当前助手，触发词是“写作”和“润色”。
```

## 2. Skills 技能系统

新增可复用技能模块，用于沉淀长期有效的工作流提示词。

### 功能范围

- 技能模型与持久化 Provider。
- Skills 独立页面。
- 助手设置页中的 Skills 标签页。
- Markdown、JSON、YAML、DOCX、ZIP 导入。
- 触发词匹配与助手绑定双模式注入。

### 设计原则

- 技能是可复用的工作流，不是一次性聊天上下文。
- 显式绑定优先于关键词触发。
- 禁用技能不会被注入。
## 3. 内置 MCP 服务

在原有 MCP 能力基础上新增 App 内 MCP 服务，降低普通用户配置外部工具的成本。

### 服务列表

- `@kelivo/fetch`：网页抓取与内容提取。
- `@kelivo/files`：本地文件读取、写入、追加、目录浏览等。
- `@kelivo/images`：图片相关辅助能力。
- `@kelivo/github`：GitHub 仓库、文件、Issue、PR、Release、Actions、Secrets、Variables 等。
- `@kelivo/so`：纯 Dart 实现的 ELF/.so 逆向分析工具集（共 26 个工具），无需额外原生依赖。
- `@kelivo/dex`：纯 Dart 实现的 DEX/ODEX 字节码解析与静态分析工具集（共 39 个工具），无需额外原生依赖。
- `@kelivo/context`：对话上下文管理工具集（共 6 个工具），支持上下文统计、摘要、搜索、导出与边界管理。
- `@kelivo/reverse`：面向 APK 的静态分析、修改与快速排查工具（共 20 个工具，含过签、重打包与 DEX 注入能力）。
- `@kelivo/memory`：按助手隔离的结构化记忆持久化工具集（共 7 个工具），支持记忆列表、增改删查、清空与统计。
- `@kelivo/reverse_extensions`：逆向扩展工具集（共 3 个工具），包含 DEX 字符串批量替换、APK 权限批量修改、第三方 SDK 识别。

### 体验优化

- 内置服务不需要额外启动外部进程。
- MCP 编辑页支持 GitHub Token 配置入口。
- 工具展示说明中文化。
- 写入型工具按业务场景分组，减少工具数量膨胀。
- 逆向分析工具补齐 APK 签名审计、加壳检测、秘钥扫描、导出组件审计和 APK 对比分析。


## 4. GitHub 写入工具升级

GitHub 工具从基础/只读能力升级为更完整的仓库自动化能力。

### 功能范围

- 仓库创建、读取、更新、删除。
- 分支、标签、提交、目录、文件管理。
- Issue 创建、更新、评论、关闭、标签和指派。
- PR 创建、更新、合并、关闭、审查、行内评论、file-level comment、回复评论。
- Release 创建、编辑、发布、删除和资源管理。
- Actions workflow/run/job/log 查询，触发、取消、重跑等管理能力。
- Repository / Environment Secrets 与 Variables 管理。

### API 规则收敛

- 空仓库创建分支前自动初始化 README。
- 提前拒绝 `GITHUB_` 前缀变量名，避免 GitHub 保留前缀错误。
- 写入验证使用 `get_file`、`list_directory`、`get_commit`、`compare_refs` 等强一致接口，不使用 code search 验证刚写入内容。
- PR update 只发送对应 action 的最小 payload。
- PR 新建行内评论和回复已有评论拆分为不同请求路径。
- 支持 `start_line`、`start_side`、`subject_type` 等现代 review comment 字段。

## 5. 本地混合搜索

新增 Local Hybrid Search，用于无需 API Key 的本地搜索聚合。

### 搜索源

- Bing Local
- DuckDuckGo
- 百度
- 搜狗
- 360 搜索

### 结果处理

- 单个搜索源失败不影响整体搜索。
- URL 规范化和跟踪参数清理。
- 广告、垃圾站、低价值聚合页过滤。
- 重复结果合并。
- 基于来源质量、排名、域名可信度和共识信号排序。

## 6. Android 移动端导入增强

- 支持 Android 分享入口接收文本、图片、PDF、ZIP、通用二进制文件等。
- 分享文件会复制到 App 私有目录，再以结构化 `file:` 标记传入对话。
- 可与神经权能网关联动，实现“发给 Kelivo 后让助手导入到某配置位置”。

## 7. UI 与本地化

- 工具区保留关键高频入口，不把所有功能塞入输入框下方。
- Skills 入口、助手 Skills 标签页、MCP 编辑页 GitHub Token 入口等已补充。
- 新增/更新中文、英文、繁体中文本地化字符串。
- 新增百度、搜狗、360 图标资源。

## 8. 本仓库（kelivo-revkit）相对 Kelivo Plus 的深度逆向增强

本仓库（`dhh-max/kelivo-revkit`）在 Kelivo Plus 的二次开发基础上，进一步聚焦 **Android 安全与逆向工程** 方向，新增/扩展了以下能力，构成与实际发布版本的差异点。

### 8.1 新增 `@kelivo/dex`（DEX/ODEX 字节码解析与静态分析）

纯 Dart 实现的字节码级解析与静态分析服务，无需外部反编译工具，共 39 个工具：

**基础解析（10 个）：**

| 工具 | 说明 |
| --- | --- |
| `dex_parse_header` | DEX header（版本、校验、计数、endian 标记） |
| `dex_list_strings` | string_ids 字面量池（MUTF-8 解码） |
| `dex_list_types` | type_ids（解析为 descriptor） |
| `dex_list_classes` | class_defs（类描述、父类、访问标志） |
| `dex_list_methods` | method_ids（类名 + proto shorty） |
| `dex_list_fields` | field_ids（类名 : 类型） |
| `dex_list_annotations` | 类级注解提取（反混淆线索） |
| `dex_disassemble_method` | 单方法 Dalvik 字节码反汇编 |
| `dex_xref_method` | 方法级调用图——查找所有调用者 |
| `dex_search_strings` | 正则/子串搜索 DEX 字符串池 |

**静态分析扩展（29 个）：**

| 工具 | 说明 |
| --- | --- |
| `dex_string_pool` | 字符串池分析 |
| `dex_type_ref` | 类型引用分析 |
| `dex_inner_class` | 内部类结构分析 |
| `dex_inherit_tree` | 继承关系树分析 |
| `dex_debug_info` | 调试信息分析 |
| `dex_method_signatures` | 方法签名统计 |
| `dex_field_stats` | 字段统计 |
| `dex_annotation_stats` | 注解统计 |
| `dex_call_graph` | 调用图分析 |
| `dex_ctrl_flow` | 控制流分析 |
| `dex_exception_flow` | 异常处理流分析 |
| `dex_access_flow` | 访问流程分析 |
| `dex_complexity` | 方法圈复杂度/体积分析 |
| `dex_reg_pressure` | 寄存器压力分析 |
| `dex_insn_stats` | 指令统计 |
| `dex_insn_density` | 指令密度分析 |
| `dex_class_density` | 类密度分析 |
| `dex_crypto_scan` | 加密相关代码扫描 |
| `dex_const_scan` | 常量扫描 |
| `dex_serialization_scan` | 序列化相关扫描 |
| `dex_reflection_scan` | 反射调用扫描 |
| `dex_obfuscation_scan` | 混淆特征扫描 |
| `dex_lib_analysis` | 库依赖分析 |
| `dex_native_analysis` | 原生方法分析 |
| `dex_resource_ref` | 资源引用分析 |
| `dex_access_pattern` | 访问模式分析 |
| `dex_proto_analysis` | 方法原型分析 |
| `dex_proto_matrix` | 原型矩阵分析 |
| `dex_perm_audit` | 权限使用审计 |

### 8.2 新增 `@kelivo/context`（对话上下文自我管理）

帮助模型感知并管理自身对话上下文，共 6 个工具：

`context_get_stats`、`context_get_summary`、`context_search`、`context_export`、`context_set_boundary`、`context_get_messages`。

### 8.3 新增 `@kelivo/memory`（按助手的结构化记忆）

基于内置 `AssistantMemory` 持久化系统，提供按助手隔离的结构化记忆读写能力，共 7 个工具：

| 工具 | 说明 |
| --- | --- |
| `memory_list` | 列出当前助手的记忆条目 |
| `memory_add` | 新增一条记忆 |
| `memory_update` | 更新已有记忆 |
| `memory_delete` | 删除记忆 |
| `memory_search` | 搜索记忆 |
| `memory_clear` | 清空当前助手的记忆 |
| `memory_stats` | 记忆统计信息 |

### 8.4 `@kelivo/reverse` 深度扩展（至 20 个工具）

在 Kelivo Plus 版 `reverse` 工具基础上，新增面向深度 APK 分析的能力：

| 工具 | 说明 |
| --- | --- |
| `reverse_list_targets` | 枚举 APK 内全部分析目标 |
| `reverse_manifest_summary` | 解析 AndroidManifest.xml（包名、组件、权限） |
| `reverse_list_native_libs` | 列出 APK 内所有 .so 文件 |
| `reverse_list_dex_files` | 列出所有 classes*.dex 文件 |
| `reverse_analyze_so` | 对单个 .so 做 header/import/export/dep/string 聚合分析 |
| `reverse_analyze_dex` | 对单个 .dex 做 header/class/method/string 聚合分析 |
| `reverse_find_jni_bridges` | 定位 JNI 注册线索（JNI_OnLoad、Java_* 等） |
| `reverse_search_strings` | APK 元数据 + so 字符串 + dex 字符串跨目标检索 |
| `reverse_report` | 结构化逆向报告 |
| `reverse_quick_triage` | 一键快速排查：入口、权限、so、dex、JNI 线索、可疑字符串 |
| `reverse_signature_audit` | 签名方案与证书分析 |
| `reverse_packer_detect` | 加壳/加固检测（360/百度/腾讯/UPX 等） |
| `reverse_secret_scan` | 硬编码密钥扫描 |
| `reverse_component_audit` | 导出组件安全审计 |
| `reverse_diff_apk` | APK 版本差异分析（组件/权限/签名/文件） |
| `reverse_kill_signature` | 去除原生签名校验（如 libjiagu.so 检测） |
| `reverse_resign_apk` | 重打包并签名（自动生成调试密钥） |
| `reverse_inject_dex` | 向 APK 注入 DEX 载荷 |
| `reverse_meta_info` | APK 元信息总览 |
| `reverse_open_apk` | 打开/加载 APK 文件 |

### 8.4 新增 `@kelivo/reverse_extensions`（逆向扩展工具集）

在 `@kelivo/reverse` 基础上新增 3 个高级逆向工具，总工具数达 28 个：

| 工具名 | 功能 |
|--------|------|
| `reverse_string_replace` | DEX/APK 字符串批量替换（支持正则、类名过滤、预览） |
| `reverse_batch_resign` | APK 批量重签名（自定义 keystore、v1/v2 方案） |
| `reverse_unpack_guide` | 一键脱壳向导（自动识别 12+ 加固方案） |

同时扩展 `manifest.json` 配置，新增 `reverse_generate_module` 模块脚手架生成工具。

### 8.5 预置“逆向分析师 / Reverse Analyst”助手

- 新增预置助手，本地化名称随系统语言切换（中文“逆向分析师” / 英文“Reverse Analyst”）。
- 默认绑定 `@kelivo/reverse` 聚合逆向 MCP。
- 系统提示词内置 APK 结构分析、DEX/SO 逆向、Manifest 审计、JNI 分析、反混淆与加壳识别等专业引导。

### 8.6 APK 分析防崩溃与性能优化

针对大体积 APK / 多 DEX APK 分析时模型 OOM 崩溃、超时无响应等问题，新增完整防崩溃方案：

- **分片增量分析**：按 DEX/类/字符串/SO 多维度分片，逐片分析释放内存
- **超时降级机制**：深度→标准→轻量三级降级路径，确保始终有结果返回
- **离线后台分析**：大型 APK 自动转入后台队列，支持进度查询/暂停/继续/完成通知
- **断点续传**：任务中断后自动从断点恢复，无需重新开始
- **混淆代码智能标记**：自动识别 ProGuard/R8 混淆特征，支持 mapping.txt 符号恢复
- **恶意代码预检测**：内置 6 类恶意特征库（挖矿/扣费/隐私窃取/广告弹窗/Root利用/动态加载）
- **全品类 APK 适配**：常规应用/系统应用/车载/穿戴/IoT/Split APK 分包
- **周边工具生态联动**：Frida Hook 模板生成、JADX-GUI 导出、Xposed 模块脚手架
- **分析进度可视化**：实时进度/当前步骤/预估剩余时间/内存占用

详见 [APK 分析防崩溃与性能优化方案](APK_ANALYSIS_ANTI_CRASH_ZH.md)。

## 9. 开源发布边界

公开仓库包含源码、文档、测试和必要资源；不包含以下内容：

- GitHub Token 或任何私密凭据。
- Android 签名 keystore。
- `android/key.properties`。
- 本机构建缓存、SDK 软链接、APK/AAB 构建产物。

APK 通过 GitHub Release 资产发布，不提交到 Git 仓库历史。
