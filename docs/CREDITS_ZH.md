# 致谢名单

Kelivo RevKit 的诞生离不开众多开源项目、社区和个人贡献者。在此一一致谢。

---

## 一、上游与基座项目

| 项目 | 说明 | 链接 |
|------|------|------|
| Chevey339/kelivo | 原始项目，奠定整体架构与聊天核心 | [GitHub](https://github.com/Chevey339/kelivo) |
| MuMu-0604/kelivo (Kelivo Plus) | 二次开发版，在原版基础上大幅扩展功能与体验 | [GitHub](https://github.com/MuMu-0604/kelivo) |
| re-ovo/rikkahub | UI 设计灵感来源 | [GitHub](https://github.com/re-ovo/rikkahub) |

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

## 七、协议与标准

| 项目 | 说明 |
|------|------|
| OpenAI API | 兼容性参考 |
| Anthropic API | 兼容性参考 |
| Google AI API | 兼容性参考 |
| OpenAPI Specification | 接口规范 |
| AGPL-3.0 | 开源协议 |

## 八、社区与贡献者

感谢所有在 GitHub Issue、PR、讨论区、内测反馈中贡献问题的开发者与用户。  
感谢每一个提交 Bug Report、Feature Request、本地化翻译、文档改进的人。

---

## 许可证

本项目基于 **AGPL-3.0** 协议开源。所有第三方依赖的许可证请参见各包原始仓库。

