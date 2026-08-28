# 从 SoLab 学到的 8 个先进设计

> SoLab (`zhou.solab`) 是一个基于 Kelivo 二次开发的 **APK 逆向 AI 工作台**。
> 本文总结其架构中值得借鉴、可迁移到 Kelivo RevKit 的 8 项关键设计。

---

## 学习来源

- 仓库：`solab-open-source-2.0`（源码分析）
- 关键路径：
  - `lib/features/solab_apk/analyzer/analyzer_api.dart` —— Analyzer 协议定义
  - `lib/features/solab_apk/analyzer/analyzer_tools.dart` —— 4 个语义入口
  - `lib/features/solab_apk/analyzer/analyzer_index.dart` —— Phase 0 渐进式索引
  - `lib/features/solab_apk/analyzer/analyzer_gateway_impl.dart` —— 网关编排实现
  - `lib/features/solab_apk/services/apk_*.dart` —— 16 个 APK 服务

---

## 一、语义入口 vs 工具直露

### SoLab 做法

Agent 面对的是「**意图**」而非「**工具**」：

```
Agent 可见（4 个入口）：
  analyzer.open                 打开 APK 按需分析上下文
  analyzer.global_search        跨 DEX 聚合搜索
  analyzer.find_field_usage     字段 READ/WRITE 消费点
  analyzer.analyze_business_state  VIP/登录/广告等业务语义定位

内部执行器（58 个原子工具，不暴露）：
  dex_search / field_xref / smali_read / smali_write / outline / call_graph / ...
```

### 为什么好

- **上下文窗口友好**：Agent prompt 只带 4 个 tool schema，而非 20+ 个
- **意图表达更自然**：LLM 更容易说清"我要查 VIP 逻辑"而非"我要先 class_by_string 再 field_xref 再 read_smali"
- **编排逻辑统一**：Gateway 内部保证执行顺序、缓存策略、错误处理，Agent 不重复踩坑
- **可解释性强**：每个入口对应一个明确的用户任务

### Kelivo RevKit 现状

`@kelivo/reverse` 20 个工具、`@kelivo/dex` 39 个工具、`@kelivo/so` 26 个工具全部直露。Agent 需要自行编排。

### 迁移建议

保留现有全部工具作为底层能力，**新增 4–6 个语义入口**（如 `revkit.analyze_vip`、`revkit.find_ad_sdk`、`revkit.remove_signature_check`、`revkit.quick_triage`），内部编排多个原子工具，减少 Agent 决策负担。

---

## 二、结构化结果协议（Evidence-Grade Protocol）

### SoLab 做法

每个 Analyzer 调用返回 `AnalyzerResult`，字段设计极其讲究：

```dart
class AnalyzerResult {
  final String query;             // 原始查询
  final String summary;           // 一句话总结
  final double score;             // 0-1 综合评分
  final ConfidenceLevel confidence;   // HIGH / MEDIUM / LOW
  final EvidenceLevel evidenceLevel;  // L0 / L1 / L2 / L3 / L4
  final Sufficiency sufficiency;      // COMPLETE / INSUFFICIENT
  final String? stopReason;           // 为何停在此处
  final List<AnalyzerCandidate> primaryCandidates;  // 候选列表
  final Map<String, dynamic> evidenceGraph;          // 证据图谱
  final List<dynamic> uncertainties;   // 未确认点
  final List<String> nextBestActions;  // 文本版下一步
  final List<AnalyzerNextAction> nextActions;  // 结构化下一步
  final String? recommendedAction;
}

enum ConfidenceLevel { high, medium, low }
enum EvidenceLevel { l0, l1, l2, l3, l4 }  // L0=搜索命中 / L1=静态引用 / L2=调用关系 / L3=数据流 / L4=多证据闭环
enum Sufficiency { complete, insufficient }

class AnalyzerNextAction {
  final String tool;              // 具体工具名
  final String purpose;           // 用途
  final Map<String, dynamic> arguments;  // 可直接复制的参数（含 locator）
}
```

### 为什么好

- **证据分级 (L0–L4)**：LLM 可以判断"结果够不够硬"，决定是否继续挖
- **置信度 (HIGH/MEDIUM/LOW)**：区分"高置信定位"与"疑似命中"
- **充分性 (COMPLETE/INSUFFICIENT)**：告诉 Agent 是否可停止
- **结构化 nextActions**：Agent 拿到"下一步该干什么 + 具体参数"，不再瞎猜
- **evidenceGraph + uncertainties**：把分析过程可视化，人类也能审阅

### Kelivo RevKit 现状

`reverse_open_apk` 返回 `{success, target, manifest, dexCount, nativeLibs, ...}` 等扁平字段，`reverse_quick_triage` 返回 `{summary, signatures, dex, so, verdict}`。缺少"证据等级"、"下一步建议"这些**给 LLM 用的元数据**。

### 迁移建议

给 `reverse_open_apk`、`reverse_quick_triage`、`reverse_report` 三个核心工具的返回结构**增加元字段**：

```json
{
  "result": { /* 现有字段 */ },
  "meta": {
    "confidence": "HIGH",
    "evidenceLevel": "L2",
    "sufficiency": "COMPLETE",
    "nextBestActions": ["reverse_analyze_so", "reverse_find_signature_checks"],
    "nextActions": [
      { "tool": "reverse_analyze_so", "purpose": "扫描 libxxx.so 加密算法",
        "arguments": { "soPath": "/path/to/libxxx.so" } }
    ],
    "uncertainties": ["未验证动态加载的 DEX 是否含敏感逻辑"]
  }
}
```

---

## 三、渐进式索引状态机（Phase 0）

### SoLab 做法

```
open(apkPath)
  → 立即返回 apkId（毫秒级就绪）
  → 后台渐进建索引：dex_search_index / field_xref_index / call_graph_index / ...
  → Agent 随时调用 analysis.status() 查每个子索引进度
  → 各子索引独立 READY，不必等全量
```

### 关键设计

- **非阻塞**：`open` 不阻塞 Agent，立即返回 `apkId`
- **子索引独立**：`field_xref=READY` 即可做 VIP 定位，即使 `call_graph` 还在建
- **状态可查**：Agent 能主动查询进度，而不是被动等待
- **多上下文管理**：`AnalyzerGatewayRegistry` 支持最多 8 个并发 APK 上下文（`LinkedHashMap` + 淘汰）

### Kelivo RevKit 现状

`reverse_open_apk` 一次性全量扫描（约 8–15 秒），返回前阻塞 Agent。大 APK 体验差。

### 迁移建议

在 `reverse_open_apk` 内部拆成两个阶段：

- **`reverse_open_apk`（快通道）**：解析 APK 结构 + manifest + 列出 dex/so 文件列表 → 秒回
- **`reverse_analyze_progress`**：查询后台分析状态（每个 dex/so 独立完成情况）
- **`reverse_wait_for_index`**：可选等待某个具体索引就绪

Agent 可以在等索引期间先做别的事（如读取用户其他指令），不必卡死。

---

## 四、Field XREF 按需 + LRU 缓存

### SoLab 做法

```dart
// 字段级 LRU 缓存：fieldLocator → 扫描结果
static const int _fieldRefCacheMax = 512;

// 不预建全量索引：首次扫，扫过即缓存，二次命中秒回
Future<List<FieldRef>> _fieldRefsFor(String fieldLocator) async {
  1. LRU 缓存命中 → 直接返回
  2. native_xref 按需扫 dex
  3. memory 内存索引兜底
}
```

### 为什么好

- **首次调用会慢一点**，但**第二次及以后命中 LRU，秒回**
- **不浪费内存**：只缓存真正访问过的字段，而不是全量 dex
- **数据源透明**：日志能看到"结果来自 LRU / native_xref / memory"

### Kelivo RevKit 现状

字段分析依赖整包扫描后再查。无缓存层，重复查询重复扫 dex。

### 迁移建议

在 dex 分析服务上加 **两级缓存**：

- **方法级 LRU**（512 项）：smali 读、方法详情
- **字段级 LRU**（512 项）：字段引用
- **进程级持久缓存**：按 APK hash 存 Hive，第二次打开同一 APK 秒回

---

## 五、业务语义定位（`analyze_business_state`）

### SoLab 做法

`analyze_business_state` 是一个**语义级聚合器**，专门处理常见业务目标：

```
输入：
  query: "VIP 验证逻辑" / "登录流程" / "广告 SDK"
  fieldName: （可选，有证据时填写）
  apkId: 绑定 APK

输出：
  一组候选 + locator（类、方法、字段、字符串）
  按证据等级 + 相关度排序
```

### 为什么好

- **把常见的"找 VIP / 找广告 / 找登录"这类任务封装成一个调用**
- Agent 不必自己组合 search → outline → xref 三步
- **fieldName 可选**：不强制，有就精准，没有就走通用搜索

### Kelivo RevKit 现状

用户要"找 VIP"需要自己组合 `reverse_analyze_apk` + `reverse_scan_so` + `reverse_analyze_dex` + 字符串搜索，步骤繁琐。

### 迁移建议

在 `@kelivo/reverse` 增加：

```
reverse_find_business(query: string, apkPath: string, hint?: string)
  → 内部编排：global_search + dex_search_strings + outline + field_xref
  → 返回业务候选列表（VIP/登录/支付/广告/加密/签名校验等分类）
```

或者更粗粒度：`revkit.quick_fix(task_type: "remove_vip" | "remove_ads" | "kill_signature" | "analyze_crypto", apkPath)`。

---

## 六、dryRun 预览 + 产物分离

### SoLab 做法

> "选择 APK 后，可由内置 'SoLab 助手'（对话式 AI）驱动分析、定位、修改与签名；产物在工作目录中单独生成，不覆盖源 APK。"

关键服务：

- `apk_mutation_preview_service.dart` —— 修改预览（dryRun）
- `apk_workspace_service.dart` —— 工作目录管理
- `apk_workspace_binding_service.dart` —— APK 绑定
- `apk_patch_memory_service.dart` —— 修改记忆

### 为什么好

- **不覆盖源 APK**：所有产物放工作目录，可对比、可回滚
- **修改前 dryRun**：先给预览，用户确认再执行
- **修改记忆**：每次修改有历史，可追溯、可回滚

### Kelivo RevKit 现状

`reverse_kill_signature`、`reverse_inject_dex` 直接修改目标 APK。`reverse_resign_apk` 支持指定输出路径，但整体缺少统一的工作目录概念。

### 迁移建议

在 `@kelivo/reverse` 增加：

```
reverse_preview(action, target, params)
  → 只做分析 + 生成修改计划，不写文件
  → 返回 diff、影响范围、回滚步骤

reverse_apply_workspace(action, target, params, workspaceId)
  → 在 workspace 内执行修改，输出新 APK 到 workspace/output/
  → 源 APK 保持不变
```

新增 UI 面板显示"当前 APK → 待应用修改列表 → 输出路径"。

---

## 七、报告源包一致性 & 新鲜度校验

### SoLab 做法

> "源包一致性（reportSourceApk / boundApk）与新鲜度校验（reportFreshness）"

每个分析报告都绑定：

- **`reportSourceApk`**：报告基于哪个 APK 生成
- **`boundApk`**：报告当前绑定到哪个 APK
- **`reportFreshness`**：报告是否过期（APK 变更后报告自动失效）

### 为什么好

- 避免"用旧报告指导新分析"这种错误
- 支持多 APK 并行分析时的报告隔离
- Agent 拿到过期报告会有明确提示，而非误信旧结论

### Kelivo RevKit 现状

`reverse_report` 每次重新分析，没有"报告缓存"，也就没有"过期"问题；但代价是重复劳动。

### 迁移建议

引入 `reverse_report` 缓存机制：

```
reverse_report(apkPath, useCache?: bool)
  → 首次生成后按 apkPath + apkHash 缓存
  → 后续调用先查 apkHash 是否变更
  → 变更则报 reportFreshness = "STALE"，让用户决定是否刷新
```

---

## 八、局域网 HTTP MCP（手机作工具链）

### SoLab 做法

> "局域网 HTTP 直连（默认端口 8800），电脑端 AI 客户端直连手机工具链，无桥接架构"

关键文件：

- `lib/core/services/mcp_server/mcp_http_server.dart` —— HTTP 服务器
- `lib/features/mcp/pages/mcp_host_mode_page.dart` —— 主机模式 UI
- `lib/core/services/mcp/mcp_oauth_callback.dart` + `mcp_oauth_http_client.dart` —— 完整 OAuth 回调链

### 为什么好

- **手机作为工具链**：APK 分析、Dex 反编译在手机上跑（原生性能最好）
- **电脑 AI 直连**：Cursor / Claude Desktop / 自定义 Agent 通过 LAN 调用手机工具
- **无桥接架构**：不需要云端中转、不需要云同步
- **OAuth 支持**：标准 OAuth 回调流程，安全可控

### Kelivo RevKit 现状

MCP 服务器是进程内 API，只服务 App 内部的 Agent。手机端与电脑端 AI 之间的桥接依赖 Cloudflare Tunnel 之类的外部方案。

### 迁移建议

这是**中长期战略投入**：

1. **短期**：给 `@kelivo/reverse` 的 MCP 服务器加 LAN HTTP 监听能力（端口可配置，默认 8800）
2. **中期**：实现标准 MCP over HTTP 协议，让外部 MCP Client 直连
3. **长期**：加 OAuth 2.0 认证、设备指纹、访问日志

---

## 附：其他可借鉴细节

### A. 广告 SDK 特征规则库

`lib/features/solab_apk/data/ad_rules_default.json` —— 广告 SDK 特征规则库（SDK 名、类特征、字符串特征），可订阅同步更新。

**建议**：Kelivo RevKit 已有恶意代码特征库，可扩展"广告 SDK 特征库"分类，配合 `reverse_analyze_apk` 输出"广告 SDK 清单 + 移除建议"。

### B. Blutter Flutter AOT 集成

`blutter` 是 Flutter 二进制 AOT 分析工具，用于分析 Flutter 编译后的 `libapp.so`。

**建议**：给 `@kelivo/so` 增加 `so_analyze_flutter` 工具，检测 Flutter 应用后自动调用 Blutter 分析引擎。

### C. `AnalyzerGatewayRegistry` 多上下文管理

```dart
static const _maxContexts = 8;
static final LinkedHashMap<String, DefaultAnalyzerGateway> _byContext = ...
```

用 LRU LinkedHashMap 管理最多 8 个并发的 APK 分析上下文。

**建议**：`@kelivo/reverse` 可支持同时分析多个 APK（如对比两个版本），用相同的多上下文管理方式。

### D. 上游同步脚本

`tools/sync_upstream.ps1` —— 一键合并上游（Chevey339/kelivo）、检查 SoLab 身份不被覆盖、跑关键测试。

**建议**：`@kelivo/revkit` 也应有 `tools/sync_upstream.ps1`，定期合并 Kelivo Plus 更新。

---

## 学习小结：三大范式转变

| 维度 | Kelivo RevKit 现状 | SoLab 范式 | 建议方向 |
|------|------|------|------|
| **Agent 交互层** | 20+ 工具直露，Agent 自行编排 | 4 个语义入口 + 内部 58 原子工具 | 新增语义入口层，保留底层能力 |
| **分析执行层** | 一次性全量扫描，阻塞返回 | Phase 0 渐进式索引，非阻塞 | 拆分为快速通道 + 后台索引 |
| **结果表达层** | 扁平字段，无 LLM 元信息 | 结构化 result + confidence/evidence/sufficiency/nextActions | 增加 meta 字段和结构化建议 |
| **修改控制层** | 直接修改目标 APK | dryRun 预览 + 工作目录产物分离 | 增加预览与 workspace 概念 |
| **报告管理层** | 每次重新分析 | 报告缓存 + 源包一致性 + 新鲜度校验 | 引入缓存 + hash 绑定 |
| **部署形态** | App 内进程内 MCP | 局域网 HTTP MCP，手机作工具链 | 中长期开放 LAN HTTP |

**核心思想**：**让 Agent 只面对"意图"，把"执行细节"下沉到 Gateway；让每个返回都带"元信息"，让 LLM 能判断"够不够、下一步做什么"；让"修改"永远在安全边界内，绝不覆盖源文件。**

---

*本文档基于 SoLab 开源代码分析撰写，用于指导 Kelivo RevKit 后续迭代。*
