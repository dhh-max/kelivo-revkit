# 致谢名单

Kelivo RevKit 的诞生离不开众多开源项目、社区和个人贡献者。在此一一致谢。

---

## 一、上游与基座项目

| 项目 | 说明 | 链接 |
|------|------|------|
| Chevey339/kelivo | 原始项目，奠定整体架构与聊天核心 | [GitHub](https://github.com/Chevey339/kelivo) |
| MuMu-0604/kelivo (Kelivo Plus) | 二次开发版，在原版基础上大幅扩展功能与体验 | [GitHub](https://github.com/MuMu-0604/kelivo) |
| re-ovo/rikkahub | UI 设计灵感来源 | [GitHub](https://github.com/re-ovo/rikkahub) |
| bilieebiliee1-design/SOMCP | Serverless MCP 参考实现，MCP 工具调用与协议交互模式参考 | [GitHub](https://github.com/bilieebiliee1-design/SOMCP) |

## 二、框架与语言

| 项目 | 说明 |
|------|------|
| Flutter | 跨平台 UI 框架 |
| Dart | 编程语言与运行时 |
| Rive / lottie | 动画与图形 |

## 三、核心依赖库

### 状态管理与架构

| 包 | 说明 |
|------|------|
| `provider` | Provider 状态管理 |
| `hive` / `hive_flutter` | 轻量级 KV 数据库 |
| `drift` | SQLite ORM 层 |
| `shared_preferences` | 简易配置持久化 |

### 网络与通信

| 包 | 说明 |
|------|------|
| `http` | HTTP 客户端 |
| `dio` | 增强型 HTTP 客户端 |
| `socks5_proxy` | SOCKS5 代理支持 |
| `webview_flutter` | 内嵌 Web 视图 |
| `webview_flutter_wkwebview` | iOS WKWebView 后端 |
| `webview_windows` | Windows WebView2 后端 |
| `cupertino_http` | iOS 原生 HTTP 适配 |

### 桌面端

| 包 | 说明 |
|------|------|
| `bitsdojo_window` | 窗口管理 |
| `window_manager` | 窗口尺寸/位置 |
| `screen_retriever` | 屏幕信息 |
| `tray_manager` | 系统托盘 |
| `desktop_drop` | 文件拖放 |
| `hotkey_manager` | 全局快捷键 |

### 媒体与图像

| 包 | 说明 |
|------|------|
| `image_picker` | 图片选择器 |
| `image_cropper` | 图片裁剪 |
| `image` | 图像处理 |
| `downsize` | 图片压缩 |
| `easy_image_viewer` | 图片查看器 |
| `image_gallery_saver_plus` | 图片保存 |
| `flutter_svg` | SVG 渲染 |
| `mobile_scanner` | 扫码 |
| `pretty_qr_code` | QR 码生成 |
| `share_plus` | 分享 |
| `open_filex` | 文件打开 |

### 文本与内容

| 包 | 说明 |
|------|------|
| `gpt_markdown` | Markdown 渲染 |
| `flutter_highlight` / `highlight` | 代码高亮 |
| `html` / `html2md` | HTML 解析与转换 |
| `flutter_math_fork` | 数学公式渲染 |
| `reel_text` | 文本逐字动画 |
| `system_fonts` | 系统字体 |
| `google_fonts` | 在线字体 |
| `math_expressions` | 数学表达式 |

### 本地推理与语音

| 包 | 说明 |
|------|------|
| `sherpa_onnx` | 端侧语音识别 |
| `speech_to_text` | 平台语音识别 |
| `flutter_tts` | 文本转语音 |
| `llama_flutter_android` | 端侧大模型 |
| `record` | 音频录制 |
| `audioplayers` | 音频播放 |

### 文件与系统

| 包 | 说明 |
|------|------|
| `path_provider` | 文件路径 |
| `file_picker` | 文件选择器 |
| `file_selector` | 桌面文件选择 |
| `archive` | 压缩/解压 |
| `xml` | XML 解析 |
| `yaml` | YAML 解析 |
| `path` | 路径工具 |
| `uuid` | UUID 生成 |
| `intl` | 国际化 |
| `package_info_plus` | 应用信息 |
| `url_launcher` | URL 启动 |

### 界面与交互

| 包 | 说明 |
|------|------|
| `flutter_slidable` | 滑动操作 |
| `reorderable_grid_view` | 可拖拽网格 |
| `syncfusion_flutter_core` | 图表 |
| `syncfusion_flutter_sliders` | 滑块 |
| `syncfusion_flutter_pdf` | PDF 处理 |
| `scrollable_positioned_list` | 虚拟滚动列表 |
| `scrollview_observer` | 滚动监听 |
| `super_sliver_list` | 高效 Sliver |
| `animations` / `flutter_animate` | 动画 |
| `haptic_feedback` | 触觉反馈 |
| `super_clipboard` | 剪贴板 |
| `material_color_utilities` | 材料配色 |
| `cupertino_icons` | iOS 图标 |
| `lucide_icons_flutter` | Lucide 图标集 |
| `dynamic_color` | 动态取色 |

### 安全与加密

| 包 | 说明 |
|------|------|
| `crypto` | 加密算法 |
| `encrypt` | 加密工具 |
| `jose` | JWT / JWE |
| `ffi` | 原生 FFI |

### 后台与生命周期

| 包 | 说明 |
|------|------|
| `flutter_background` | 后台任务 |
| `flutter_local_notifications` | 本地通知 |
| `wakelock_plus` | 屏幕常亮 |
| `permission_handler` | 权限管理 |
| `restart_app` | 应用重启 |
| `sqlite3` | SQLite 原生 |

### 搜索与数据

| 包 | 说明 |
|------|------|
| `ddgs` | DuckDuckGo 搜索 |
| `http_parser` | HTTP 解析 |

## 四、内置依赖（本地路径）

| 包 | 说明 |
|------|------|
| `dependencies/mcp_client` | MCP 客户端实现 |
| `dependencies/flutter_tts` | TTS 平台适配 |
| `dependencies/gpt_markdown` | Markdown 渲染引擎 |
| `dependencies/downsize` | 本地图片压缩 |
| `dependencies/tray_manager` | 系统托盘 |
| `dependencies/flutter-permission-handler/permission_handler_windows` | Windows 权限 |

## 五、桌面端开发贡献

桌面端适配涉及系统托盘、窗口管理、快捷键、侧导航栏、右键菜单等大量交互改造，感谢桌面端开发者的持续贡献。

## 六、APK 逆向工具链

| 工具 | 说明 |
|------|------|
| `apktool` | APK 解码/重打包 |
| `JADX` | DEX 反编译 |
| `dex-jar` | 内置运行时 |
| `zipalign` / `apksigner` / `keytool` | Android 签名工具链 |

## 七、Reverse Engineering Kit（逆向工程）致谢

RevKit 模块专注于 Android 安全与逆向工程，依赖并集成了以下工具、库和项目。在此特别致谢。

### 7.1 APK 逆向工具链

| 工具/项目 | 说明 |
|----------|------|
| [apktool](https://github.com/iBotPeaches/Apktool) | APK 解码与重打包（smali + resources + manifest） |
| [JADX](https://github.com/skylot/jadx) | DEX 字节码反编译为 Java 源码 |
| [dex-jar](https://github.com/pxb1988/dex-jar) | 内置 `dex-jar` 运行时，用于进程内反编译与字节码操作 |
| `zipalign` | Android SDK 提供，APK 内存对齐 |
| `apksigner` | Android SDK 提供，v1/v2/v3 签名 |
| `keytool` | JDK 提供，调试密钥生成 |

### 7.2 DEX / 字节码分析

| 项目 | 说明 |
|------|------|
| [Smali/Baksmali](https://github.com/JesusFreke/smali) | DEX 汇编/反汇编参考实现 |
| [libdex](https://github.com/android/platform_external_libdex) | Android 平台 DEX 格式定义参考 |
| [Android Open Source Project](https://source.android.com) | DEX 规范与字节码格式参考 |

### 7.3 SO / ELF 逆向

| 项目 | 说明 |
|------|------|
| [GNU Binutils](https://github.com/bminor/binutils) | ELF 格式解析参考 |
| [capstone-engine](https://github.com/capstone-engine/capstone) | 反汇编引擎思路参考 |
| [LIEF](https://github.com/lief-project/LIEF) | ELF 分析与修改参考 |
| [radare2](https://github.com/radareorg/radare2) | 逆向分析参考 |
| [Frida](https://github.com/frida/frida) | 动态分析与 Hook 参考 |
| [Xposed Framework](https://github.com/rovo89/Xposed) | 动态 Hook 框架参考 |

### 7.4 加壳检测与脱壳

加壳检测逻辑参考了以下加固方案的公开特征：

| 加固方案 | 厂商 |
|----------|------|
| Bangcle | 梆梆安全 |
| iJiami | 爱加密 |
| Qihoo 360 | 360 加固 |
| Tencent Leag | 腾讯乐固 |
| Nagen | 娜迦 |
| Legu | 乐固 |
| Baidu Protector | 百度加固 |
| DexGuard | 美创安全 |
| Alibaba Protector | 阿里加固 |
| Tencent Shell | 腾讯加固壳 |

### 7.5 反调试与签名校验

反调试检测模式参考了以下技术：

- `ptrace` / `TracerPid` 检测（Linux 内核调试接口）
- `inotify` 文件监听（Linux 文件系统事件）
- `frida-server` 端口检测（Frida 动态分析识别）
- SELinux 策略检测
- 进程注入检测

签名校验相关：

- JAR Signing（v1 签名）
- APK Signature Scheme v2 / v3
- 强签（libjiagu.so / 加壳签名校验）绕过策略

### 7.6 安全扫描特征库

内置恶意代码预扫描特征库参考了以下威胁类型：

- 加密货币挖矿（cryptomining）
- 恶意扣费（premium SMS / in-app purchase）
- 隐私窃取（PII harvesting）
- 广告弹窗（adware / popup）
- 木马后门（Trojan / backdoor）
- 权限滥用（permission abuse）

## 八、RelayGo 网关致谢

RelayGo 网关是 Kelivo RevKit 内置的 API 反向代理，提供负载均衡、限流、缓存、错误处理等能力。

### 8.1 技术参考

| 项目/规范 | 说明 |
|-----------|------|
| [Envoy Proxy](https://github.com/envoyproxy/envoy) | 代理架构与流量管理思路参考 |
| [nginx](https://github.com/nginx/nginx) | 反向代理模式与头部处理参考 |
| [Kong](https://github.com/Kong/kong) | API 网关能力参考 |
| [HAProxy](https://github.com/haproxy/haproxy) | 负载均衡与健康检查参考 |
| HTTP/1.1 Specification (RFC 7230-7235) | HTTP 协议规范 |
| SSE Specification | Server-Sent Events 流式响应 |
| OAuth 2.0 Bearer Token | 鉴权头规范 |
| HMAC-SHA256 | Webhook 签名 |

### 8.2 算法参考

| 算法 | 用途 |
|------|------|
| AIMD（Additive Increase Multiplicative Decrease） | 自适应 TPM 挡板 |
| Token Bucket | 令牌桶限流 |
| Sliding Window Log | 精确滑动窗口限流 |
| Exponential Backoff + Jitter | 指数退避重试 |
| EMA（Exponential Moving Average） | 延迟平滑估算 |
| LRU（Least Recently Used） | 响应缓存淘汰 |
| SHA-256 | 缓存键与完整性校验 |

### 8.3 兼容性参考

网关适配器兼容以下上游 API：

| 提供商 | 协议 |
|--------|------|
| OpenAI | OpenAI Chat Completions API |
| Anthropic | Anthropic Messages API |
| Google Gemini | Google AI Language API |
| Azure OpenAI | Azure OpenAI Service |
| OpenAI 兼容端点 | 通用 OpenAI-style API |

## 九、功能模块参考致谢

Kelivo RevKit 的功能模块广泛参考了开源社区、技术规范和业界最佳实践。以下按功能域逐一列出。

### 9.1 聊天与消息系统

| 功能域 | 参考/依赖 |
|--------|-----------|
| 消息模型与协议 | OpenAI Chat Completion 消息结构（`role` / `content` / `tool_calls`） |
| 流式响应 | SSE (Server-Sent Events) 协议、OpenAI streaming API |
| 工具调用 | MCP（Model Context Protocol）规范、OpenAI Function Calling |
| 上下文压缩 | RAG（Retrieval Augmented Generation）、滑动窗口上下文管理 |
| 消息引用（Citation） | Google Search / Perplexity 引用模式 |
| 推理预算（Reasoning Budget） | Claude Extended Thinking、GPT o-series thinking tokens |
| Thinking Tag 解析 | Claude / Gemini 思考块格式参考 |
| 消息部分（Message Part） | OpenAI multi-modal content array |

### 9.2 记忆与知识管理

| 功能域 | 参考/依赖 |
|--------|-----------|
| 记忆提取与分块 | LangChain / LlamaIndex chunking 策略 |
| 向量检索思路 | Pinecone / ChromaDB / Milvus 向量数据库设计理念 |
| 记忆质量评分 | NLP 语义相关度评分 |
| 用户画像蒸馏 | Knowledge Distillation 思路参考 |
| 记忆搜索 | BM25 + 语义检索混合思路 |
| 世界书（World Book） | Character AI / Personality.js 角色设定模式 |
| 指令注入（Instruction Injection） | LangChain Few-shot / System Prompt 模式 |

### 9.3 搜索服务

内置搜索聚合服务兼容以下搜索 API 提供商：

| 提供商 | 说明 |
|--------|------|
| [DuckDuckGo Instant Answer](https://api.duckduckgo.com) | DDG 搜索结果 |
| [Bing Search API](https://learn.microsoft.com/zh-cn/azure/search/) | 必应搜索 |
| [Brave Search API](https://brave.com/search/api/) | Brave 搜索 |
| [SerpAPI](https://serpapi.com) | Google 结构化搜索 |
| [SearXNG](https://github.com/searxng/searxng) | 自托管元搜索 |
| [Tavily](https://tavily.com) | AI 搜索 API |
| [Exa](https://exa.ai) | 语义搜索 |
| [Jina AI](https://jina.ai) | 网页搜索与内容提取 |
| [Firecrawl](https://firecrawl.dev) | 网页爬取 |
| [Bocha](https://github.com/steven-tey/bocha) | AI 搜索 |
| [StepFun Search](https://platform.stepfun.com) | 阶跃星辰搜索 |
| [ZhiPu Search](https://open.bigmodel.cn) | 智谱搜索 |
| [Perplexity](https://perplexity.ai) | Perplexity Search |
| [TinyFish](https://tinyfish.ai) | 语义搜索 |
| [Ollama](https://ollama.com) | 本地模型搜索 |
| [Metaso](https://metaso.cn) | Metaso 搜索 |
| [Sogou](https://www.sogou.com) | 搜狗搜索 |
| [Baidu](https://www.baidu.com) | 百度搜索 |
| [360 Search](https://www.so.com) | 360 搜索 |
| [Grok](https://grok.com) | Grok 搜索 |
| [Linkup](https://linkup.com) | Linkup 搜索 |
| [Querit](https://querit.ai) | Querit 搜索 |

### 9.4 备份与恢复

| 功能域 | 参考/依赖 |
|--------|-----------|
| 备份归档 | Chatbox / Cherry 备份格式兼容 |
| 增量备份 | WAL（Write-Ahead Log）思路 |
| 恢复锁（Lease Lock） | 分布式锁 / Redlock 思路 |
| S3 兼容存储 | AWS S3 API、minio 协议 |
| 数据同步 | CRDT（Conflict-free Replicated Data Type）思路参考 |
| 备份校验 | 数字签名 / SHA-256 完整性校验 |

### 9.5 语音识别（ASR）

| 功能域 | 参考/依赖 |
|--------|-----------|
| Sherpa-ONNX | [k2-fsa/sherpa-onnx](https://github.com/k2-fsa/sherpa-onnx) 端侧 ASR 引擎 |
| Mimicry / 参考音频 | Mimicry 语音克隆思路 |
| 云端 ASR | Whisper / SenseVoice 思路参考 |
| 系统 ASR | Android SpeechRecognizer / Apple SFSpeech |
| 音频编解码 | WebAudio / WAV / PCM 标准 |

### 9.6 语音合成（TTS）

| 功能域 | 参考/依赖 |
|--------|-----------|
| 网络 TTS | OpenAI TTS / ElevenLabs 思路参考 |
| 文本分块 | TTS 流式分句思路 |
| 音频播放 | ExoPlayer / AudioServices |

### 9.7 端侧本地推理

| 功能域 | 参考/依赖 |
|--------|-----------|
| Llama 端侧推理 | [llama.cpp](https://github.com/ggerganov/llama.cpp) / [llama_flutter_android](https://pub.dev/packages/llama_flutter_android) |
| 模型格式 | GGUF / GGML |
| 模型下载 | HuggingFace Transformers 模型分发模式 |
| 本地工具循环 | 工具循环（tool-use loop）参考 OpenAI / Anthropic 规范 |

### 9.8 MCP 与本地工具

MCP（Model Context Protocol）是本项目的核心协议，以下 MCP Server 模块各自参考了相关技术：

| MCP Server | 功能域 | 参考/依赖 |
|------------|--------|-----------|
| `kelivo_github` | GitHub 操作 | GitHub REST API / GraphQL API |
| `kelivo_files` | 文件操作 | 文件系统 API |
| `kelivo_context` | 上下文管理 | MCP Context 协议 |
| `kelivo_fetch` | 网页抓取 | Fetch MCP Server 规范 |
| `kelivo_jadx` | DEX 反编译 | jadx、dex-jar |
| `kelivo_reverse` | APK 逆向 | apktool、dex-jar、Smali |
| `kelivo_so` | SO 分析 | LIEF、radare2、capstone |
| `kelivo_memory` | 记忆操作 | Memory MCP 扩展 |
| `kelivo_images` | 图像操作 | 图像编码处理 |
| `kelivo_dex` | DEX 操作 | DEX 字节码工具 |

### 9.9 图像与媒体

| 功能域 | 参考/依赖 |
|--------|-----------|
| 图像生成代理 | DALL·E / Stable Diffusion / Midjourney 协议参考 |
| OCR | Tesseract OCR / 平台 OCR |
| PlantUML | [plantuml.com](https://plantuml.com) 图表生成 |
| QR 码 | QR 编码规范 |
| 图片压缩 | WebP / AVIF 编码标准 |

### 9.10 翻译与多语言

| 功能域 | 参考/依赖 |
|--------|-----------|
| 多语言 i18n | Flutter Intl / ARB 文件 |
| 翻译服务 | DeepL / Google Translate / 自建 LLM 翻译 |
| 语言检测 | CLD / langid 思路参考 |

### 9.11 自定义主题与 UI

| 功能域 | 参考/依赖 |
|--------|-----------|
| 设计系统 | Material Design 3 / Fluent Design / Human Interface Guidelines |
| 动态取色 | Material You 动态配色 |
| 主题生成 | Token-based 设计令牌系统 |
| 字体管理 | Google Fonts / 系统字体 |
| 图标 | Lucide Icons / Cupertino Icons |
| Markdown 渲染 | CommonMark / GFM 规范 |
| 代码高亮 | Highlight.js 语言列表 |
| 数学渲染 | KaTeX / MathJax |
| HTML 转 Markdown | html-to-markdown 思路 |

### 9.12 设备与系统

| 功能域 | 参考/依赖 |
|--------|-----------|
| 应用控制 | Android `adb` 协议、Shizuku、Root 权限 |
| 系统托盘 | [tray_manager](https://github.com/leanflutter/tray_manager) |
| 全局快捷键 | [hotkey_manager](https://pub.dev/packages/hotkey_manager) |
| 窗口管理 | [bitsdojo_window](https://github.com/bitsdojo/bitsdojo_window) / [window_manager](https://github.com/google/flutter-desktop-embedding) |
| 屏幕常亮 | Wakelock 思路 |
| 权限管理 | [permission_handler](https://github.com/Baseflow/flutter-permission-handler) |

### 9.13 数据与存储

| 功能域 | 参考/依赖 |
|--------|-----------|
| SQLite ORM | [drift](https://github.com/simolus3/drift) |
| KV 存储 | [Hive](https://github.com/hivedb/hive) |
| 数据库迁移 | 增量迁移思路参考 Flyway / Alembic |
| 搜索索引 | FTS5（Full-Text Search） |

### 9.14 安全

| 功能域 | 参考/依赖 |
|--------|-----------|
| JWT / JWE | RFC 7519 / RFC 7517 |
| 加密 | AES-GCM / RSA / ECDSA |
| Webhook 签名 | HMAC-SHA256 |
| 密钥轮转 | AWS KMS 密钥轮转思路参考 |
| API Key 混淆 | Base64 / 自定义编码 |

### 9.15 统计与监控

| 功能域 | 参考/依赖 |
|--------|-----------|
| 使用量追踪 | OpenAI usage 解析 |
| Prometheus 指标 | Prometheus 客户端指标模型 |
| 日志采集 | ELK / Loki 日志格式思路 |
| 日志脱敏 | 敏感信息 redaction 思路 |

### 9.16 Solab APK 分析

| 功能域 | 参考/依赖 |
|--------|-----------|
| APK 结构分析 | Android Package Format 规范 |
| AndroidManifest.xml 解析 | AXML 格式规范 |
| 权限分析 | Android Permission 模型 |
| 组件分析 | Android Component 模型（Activity / Service / Receiver / Provider） |
| 加固检测 | 各加固方案公开特征 |
| 规则引擎 | 自定义 YAML/JSON 规则 |

### 9.17 其他开源参考

| 项目 | 用途 |
|------|------|
| [langchain](https://github.com/langchain-ai/langchain) | 链路编排思路参考 |
| [langfuse](https://github.com/langfuse/langfuse) | LLM 可观测性思路 |
| [promptfoo](https://github.com/promptfoo/promptfoo) | 提示词测试思路 |
| [ollama](https://github.com/ollama/ollama) | 本地模型推理与分发 |
| [vllm](https://github.com/vllm-project/vllm) | LLM 推理服务参考 |
| [FastAPI](https://github.com/fastapi/fastapi) | API 设计规范参考 |
| [Dify](https://github.com/langgenius/dify) | LLM 应用平台思路 |
| [RAGFlow](https://github.com/infiniflow/ragflow) | RAG 系统思路 |

## 十、协议与标准

| 项目 | 说明 |
|------|------|
| OpenAI API | 兼容性参考 |
| Anthropic API | 兼容性参考 |
| Google AI API | 兼容性参考 |
| OpenAPI Specification | 接口规范 |
| HTTP/1.1 (RFC 7230-7235) | HTTP 协议规范 |
| AGPL-3.0 | 开源协议 |

## 十一、社区与贡献者

感谢所有在 GitHub Issue、PR、讨论区、内测反馈中贡献问题的开发者与用户。  
感谢每一个提交 Bug Report、Feature Request、本地化翻译、文档改进的人。

---

## 许可证

本项目基于 **AGPL-3.0** 协议开源。所有第三方依赖的许可证请参见各包原始仓库。

