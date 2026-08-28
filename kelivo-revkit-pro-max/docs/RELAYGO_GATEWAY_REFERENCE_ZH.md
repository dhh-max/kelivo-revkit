# RelayGo 网关技术参考

> **版本**: v1.0.1 · **核心文件**: `lib/relaygo/services/proxy_server.dart`（~2150 行）  
> **技术栈**: Dart + Flutter · **协议**: HTTP(S) 反向代理 · **存储**: Hive

---

## 目录

- [1. 架构总览](#1-架构总览)
- [2. 请求处理生命周期](#2-请求处理生命周期)
- [3. 路由引擎](#3-路由引擎)
- [4. 负载均衡器](#4-负载均衡器)
- [5. 响应缓存](#5-响应缓存)
- [6. 请求去重](#6-请求去重)
- [7. 多维限流器](#7-多维限流器)
- [8. 自适应 TPM 挡板](#8-自适应-tpm-挡板)
- [9. Key 管理与额度监控](#9-key-管理与额度监控)
- [10. 上游错误分类与无感切换](#10-上游错误分类与无感切换)
- [11. 重试策略与指数退避](#11-重试策略与指数退避)
- [12. 并发控制](#12-并发控制)
- [13. 提供商适配器](#13-提供商适配器)
- [14. 管理 API 接口](#14-管理-api-接口)
- [15. 虚拟模型层](#15-虚拟模型层)
- [16. Web 控制台](#16-web-控制台)
- [17. 告警与 Webhook](#17-告警与-webhook)
- [18. 配置与存储](#18-配置与存储)
- [19. 性能常量一览](#19-性能常量一览)

---

## 1. 架构总览

```
客户端请求
    │
    ▼
┌─────────────────────────────────────────────────┐
│  ProxyServer.start()                             │
│  - HttpServer.bind(host, port)                   │
│  - 注册定时器：缓存清理 / 去重清理               │
└──────────────────┬──────────────────────────────┘
                   ▼
┌─────────────────────────────────────────────────┐
│  _handleRequest()                                │
│  1. _acquire() 并发信号量                        │
│  2. _serve() 分发路由                            │
│  3. _release() 释放信号量                        │
└──────────────────┬──────────────────────────────┘
                   ▼
┌─────────────────────────────────────────────────┐
│  _serve()                                         │
│  ├── 健康检查路径 → 200 JSON                     │
│  ├── 网关鉴权（网关 Key / 附加 Key）             │
│  ├── 管理 API → _serveAdmin()                    │
│  ├── /v1/models → _serveModels()                 │
│  ├── 入口限流（IP / 全局）                       │
│  ├── 读取请求体                                  │
│  ├── 响应缓存查询（CacheManager）                │
│  ├── 请求去重查询（_dedup map）                  │
│  ├── _forwardWithFallback() → 上游转发           │
│  └── 写入缓存 / 去重 / 日志 / 统计 / Webhook    │
└──────────────────┬──────────────────────────────┘
                   ▼
┌─────────────────────────────────────────────────┐
│  _forwardWithFallback()                          │
│  ├── 规则引擎评估 → RoutingDecision              │
│  ├── 构建候选池（多 key × 多 provider）         │
│  ├── 虚拟模型解析 → 改写真实模型名               │
│  ├── 负载均衡排序                                 │
│  └── 重试循环（最多 maxRetryKeys 次）            │
│       ├── 可恢复 TPM 429 → 等待同 key 重试       │
│       ├── 额度耗尽 → mark exhausted + 冷却        │
│       ├── 其他可重试 → 指数退避 + 切 key         │
│       └── 不可重试 → 透传                        │
└─────────────────────────────────────────────────┘
```

**核心服务组件关系：**

| 组件 | 文件 | 职责 |
|------|------|------|
| ProxyServer | `proxy_server.dart` | 主入口，编排所有模块 |
| RuleEngine | `rule_engine.dart` | 路由规则匹配与决策 |
| LoadBalancer | `load_balancer.dart` | key 排序与选路 |
| CacheManager | `cache_manager.dart` | 响应缓存（LRU + TTL） |
| RateLimiter | `rate_limiter.dart` | 多维限流 + 自适应 TPM |
| KeyManager | `key_manager.dart` | key 持久化与状态管理 |
| QuotaMonitor | `quota_monitor.dart` | 每日额度记账 + 告警 |
| DailyStatsService | `daily_stats_service.dart` | 每日聚合统计 |
| LogService | `log_service.dart` | 请求日志缓冲 + 落盘 |
| UpstreamErrorClassifier | `upstream_error.dart` | 上游错误分类 |
| PricingService | `pricing_service.dart` | 计价 + 价格覆盖 |

---

## 2. 请求处理生命周期

每个请求经过以下步骤：

```
1. 并发控制
   ├── 活跃连接 ≤ 50 → 直接处理
   └── 50 < 活跃 ≤ 200 → 入队列等待
   └── 活跃 > 200 → 429 拒绝

2. 路径分发
   ├── /health, /healthz, /ping → 健康检查
   ├── /relay/* → 管理接口
   ├── /v1/models → 聚合模型列表
   └── 其他 → 上游转发

3. 鉴权
   ├── 网关 Key 鉴权（Authorization / x-api-key / x-gateway-key）
   ├── 附加网关 Key（只读 / 模型白名单 / 请求限制）
   └── 管理令牌（x-relay-admin-token / Bearer）

4. 入口限流
   ├── 全局 RPM
   └── 单 IP RPM

5. 读取请求体（上限 32MB）

6. 规则引擎评估
   ├── 拦截 → 403
   ├── 指定 provider → 收窄候选
   ├── 指定 key 分组 → 收窄候选
   └── 无规则 → 透传检测到的 provider

7. 响应缓存查询（LRU + TTL，1MB 上限）

8. 请求去重（2 秒窗口，相同请求复用响应）

9. 上游转发（带缓存写入、去重写入、统计记账）
```

---

## 3. 路由引擎

### 3.1 规则格式

```dart
class RoutingRule {
  String id;
  String name;
  String? provider;        // 目标提供商
  String? group;           // key 分组
  String? model;           // 模型过滤
  bool? block;             // 是否拦截
  String? blockReason;     // 拦截原因
  String? strategy;        // 负载均衡策略覆盖
  List<String> conditions; // 匹配条件（路径 / 模型 / 头 / IP 等）
}
```

### 3.2 规则匹配流程

1. 构建上下文 `RuleEngine.buildContext(proxyRequest)`：
   - 请求方法、路径、查询参数
   - 模型名、是否流式
   - 客户端 IP
   - 检测到的 provider
2. 逐一评估已启用规则，返回第一个匹配的 `RoutingDecision`
3. 决策包含：`block` / `blockReason` / `provider` / `group` / `strategy`

### 3.3 决策对后续流程的影响

| 决策字段 | 效果 |
|----------|------|
| `block == true` | 直接返回 403，不转发上游 |
| `provider` 非空 | 候选 provider 收窄为指定值 |
| `group` 非空 | 候选 key 收窄为指定分组 |
| `strategy` 非空 | 覆盖全局负载均衡策略 |

---

## 4. 负载均衡器

### 4.1 支持的策略

| 策略 | 说明 |
|------|------|
| `round_robin` | 轮询，内部游标轮转 |
| `weighted_round_robin` | 按 key 权重轮询 |
| `priority` | 按优先级降序 |
| `least_connections` | 活跃连接数最少的优先 |
| `response_time` | 累计延迟最小的优先 |
| `smart` | 综合健康分（成功率 + 延迟 EMA） |

### 4.2 Smart 健康分算法

```
健康分 = 成功率 × 0.6 + 延迟得分 × 0.4

其中：
- 成功率 = 滑动窗口（近 50 次）成功次数 / 50
- 延迟得分 = 延迟 EMA 映射到 [0.1, 1.0]
  - < 300ms → 1.0
  - < 500ms → 0.9
  - < 800ms → 0.7
  - < 1200ms → 0.5
  - < 2000ms → 0.3
  - ≥ 2000ms → 0.1
- EMA 平滑因子 α = 0.2（仅对成功请求更新延迟）
- 候选 ≥ 2 且每个候选样本 ≥ 10 次时才启用健康分
```

### 4.3 Key 可用性判定

```
_key 可用 ⟺ status == active
        AND (cooldownUntil == null OR cooldownUntil ≤ now)
```

### 4.4 失败处理

- 每次失败 `failureCount++`
- `failureCount ≥ 3` → 标记 `error`，冷却 300 秒
- 冷却结束后 `KeyManager` 自动恢复为 `active`

---

## 5. 响应缓存

### 5.1 缓存键

```
SHA-256( method + path + query + provider + body )
```

method 参与哈希天然区分 GET/POST。

### 5.2 缓存条件

| 条件 | 要求 |
|------|------|
| 开关 | `cache.enabled == true` |
| 响应码 | 200-299 |
| 流式 | 非流式（SSE 不缓存） |
| 体积 | ≤ 1MB |
| method | 仅 GET / POST |

### 5.3 缓存结构

```
LinkedHashMap<String, CachedResponse>  // LRU

CachedResponse:
  statusCode, headers, body
  storedAt, expireAt          // TTL
  provider, model
```

### 5.4 惰性清理

每 60 秒由定时器执行 `purgeExpired()` 移除过期条目。

### 5.5 缓存统计

```
hits, misses, stores, evictions, expirations
hit_rate = hits / (hits + misses)
```

### 5.6 管理接口

`DELETE /relay/cache` 清空全部缓存并重置统计。

---

## 6. 请求去重

### 6.1 去重键

```
method:path:bodyLength:bodyHash

bodyHash = 前 64 字节的 31 进制滚动哈希
```

### 6.2 去重条件

| 条件 | 说明 |
|------|------|
| 流式 | 仅非流式请求 |
| method | 仅非 GET（POST 等） |
| 窗口 | 2 秒（`deduplicationWindowMs`） |
| 体积 | ≤ 1MB |

### 6.3 去重存储

成功响应（2xx + 非流式 + 完整捕获 + ≤1MB）写入 `_dedup` map，过期由每 5 秒定时器清理。

### 6.4 去重 vs 缓存的区别

| 维度 | 去重 | 缓存 |
|------|------|------|
| 目的 | 防止重复请求打上游 | 复用响应降低延迟 |
| 窗口 | 2 秒 | 可配置 TTL（默认 5 分钟） |
| 触发条件 | 非流式非 GET | 2xx + 非流式 |
| 独立开关 | 无（始终启用） | `cacheEnabled` |

---

## 7. 多维限流器

### 7.1 限流维度

| 维度 | 算法 | 上限 | 位置 |
|------|------|------|------|
| 全局 RPM | 滑动窗口 | `globalRpmLimit`（默认 0 = 不限） | 入口 |
| 单 IP RPM | 滑动窗口 | `ipRateLimitPerMinute`（默认 0 = 不限） | 入口 |
| 单 key RPM | 令牌桶 | key 的 `maxRequestsPerMinute` | 候选池 + 转发 |
| 单 key TPM | 滑动窗口 | `tokenRateLimitPerMinute`（默认 0 = 不限） | 候选池 |

### 7.2 令牌桶（RPM）

```
容量 = RPM × 突发倍数（默认 1.5）
补充速率 = RPM / 60 tokens/秒
允许突发 = 容量 - 稳态消耗
```

### 7.3 超时拒绝

所有超限统一返回 `429` + `Retry-After` 响应头，包含建议等待秒数。

### 7.4 拒绝统计

```
denials = {
  "global": N,
  "ip": N,
  "key_rpm": N,
  "key_tpm": N
}
```

通过 `snapshot()` 方法暴露给统计接口。

---

## 8. 自适应 TPM 挡板

### 8.1 设计目标

从源头减少上游 TPM（Tokens Per Minute）429 限流，而非等到撞限后重试。

### 8.2 AIMD 算法

```
┌──────────────────────────────────────────────┐
│  Additive Increase（加性增）                  │
│  ─────────────────────────────────────────   │
│  当无 429 的用量累计 ≥ 45 秒（0.75 窗口）时： │
│    learned_tpm ← learned_tpm × 1.02          │
│    重置稳定计时                                │
│                                              │
│  Multiplicative Decrease（乘性减）            │
│  ───────────────────────────────────────     │
│  当遭遇上游 429 时：                          │
│    learned_tpm ← usageThisWindow × 0.85      │
│    重置稳定计时                                │
└──────────────────────────────────────────────┘
```

### 8.3 挡板生效

```
有效 TPM 上限 = min(
  tokensPerMinutePerKey,     // 用户硬拦（>0 时）
  learned_tpm × 0.95        // 自适应软挡板（留 5% 余量）
)
```

### 8.4 429 等待重试

```
可恢复 TPM 429 识别 → 关键词匹配 tpmRecoverableKeywords

等待策略：
1. 优先采用上游 Retry-After 头
2. 否则用本地 TPM 窗口剩余时间
3. 最小退避 1 秒，最大预算 8 秒
4. 预算耗尽 → 429 + Retry-After，让客户端排队重试
```

---

## 9. Key 管理与额度监控

### 9.1 Key 状态机

```
┌────────┐    使用成功     ┌────────┐
│ error  │ ──────────── → │ active │
└───┬────┘               └───┬────┘
    │ 冷却到期               │ 连续失败 ≥3 次
    │                       │
    ▼                       ▼
 恢复为 active          ┌────────┐
                     │ error  │
                     │冷却 300s│
                     └────────┘

                      ┌──────────┐
        遇到额度耗尽 → │exhausted│
                      │冷却 1800s│
                      └─────┬────┘
                            │ 冷却到期
                            ▼
                         恢复为 active
```

### 9.2 每日额度监控

| 维度 | 说明 |
|------|------|
| 统计周期 | 自然日，跨日自动重置 |
| 告警阈值 | `quotaWarnThreshold`（默认 0.9） |
| 错误率告警 | `errorRateThreshold`（默认 0.5） |
| 告警去重 | 每 key 每日每种告警最多一次 |

### 9.3 Key 分组

```
key.group → 逻辑分组名
  ├── 按分组过滤候选
  └── 按分组展示统计
```

### 9.4 模型路由

`_modelRouteService` 按模型名绑定专属 key 列表，仅从指定 key 中筛选候选。

---

## 10. 上游错误分类与无感切换

### 10.1 错误分类优先级

```
1. 额度耗尽（关键词匹配：400/403/429/503 都可能）
   → quotaExhausted

2. HTTP 429
   → rateLimited

3. HTTP 401 / 鉴权关键词
   → authFailed

4. HTTP 404
   → modelNotFound

5. HTTP 5xx
   → serverError

6. HTTP 403
   → permissionDenied

7. 其他 4xx
   → badRequest

8. 其余
   → unknown
```

### 10.2 无感切换判定

| 错误类型 | 是否无感重试 |
|----------|------------|
| `quotaExhausted` | ✅（切换 key + 冷却当前 key） |
| `rateLimited` | ✅（切换 key） |
| `serverError` | ✅（切换 key） |
| `modelNotFound` | ✅（切换 key，不记失败） |
| `authFailed` | ✅（切换 key） |
| `permissionDenied` | ✅（切换 key） |
| `badRequest` | ❌（透传） |
| `unknown` | ❌（透传） |

### 10.3 额度耗尽特殊处理

1. 标记 key 为 `exhausted` + 冷却 30 分钟
2. `failureCount++`（计入失败）
3. 继续尝试下一个候选 key
4. 若所有候选均耗尽，汇总为友好提示而非透传原始错误

---

## 11. 重试策略与指数退避

### 11.1 重试循环

```
for attempt in 1..maxRetryKeys:
    key = pool[idx % pool.length]
    idx++
    
    if key 不可用: continue
    
    result = forward(key)
    
    if 2xx: return success
    if 429 + 可恢复 TPM:
        等待 TPM 窗口刷新 → 重试同 key
    if 可静默重试:
        指数退避 + 抖动 → 切下一个 key
    else:
        return 透传
```

### 11.2 指数退避公式

```
退避时长 = (retryBackoffBaseMs × 2^clamp(attempt, 0, 4) + jitter)
           .clamp(0, retryBackoffMaxMs)

参数：
  retryBackoffBaseMs = 500ms
  retryBackoffMaxMs  = 5000ms
  jitter             = 当前毫秒时间戳 % 100（0-99ms 随机抖动）
```

### 11.3 退避时序

| Attempt | 退避时长（含抖动） |
|---------|-------------------|
| 1 | 500ms ± 99ms |
| 2 | 1000ms ± 99ms |
| 3 | 2000ms ± 99ms |
| 4 | 4000ms ± 99ms |
| 5+ | 5000ms ± 99ms（封顶） |

---

## 12. 并发控制

### 12.1 信号量机制

```
_maxConcurrent = 50    // 同时转发上游的上限
_maxQueued = 200       // 排队上限

_active += 1 → 若 ≤ _maxConcurrent → 立即处理
_active += 1 → 若 ≤ _maxConcurrent + _maxQueued → 入队等待
_active += 1 → 若 > _maxConcurrent + _maxQueued → 429 _ProxyOverload
```

### 12.2 上游连接池

```
maxConnectionsPerHost = 100  // 每上游主机最大连接数
connectionTimeoutSec  = 15   // 连接超时
idleTimeoutSec        = 20   // 空闲连接回收
```

### 12.3 超时保护

```
上游请求超时:     upstreamTimeoutSeconds（默认 120s）
上游读取空闲:     upstreamIdleTimeoutSeconds（默认 30s）
客户端空闲:       120s
```

---

## 13. 提供商适配器

### 13.1 适配器列表

| 提供商 | 文件 | Base URL |
|--------|------|----------|
| OpenAI | `openai_provider.dart` | `https://api.openai.com/v1` |
| Google Gemini | `google_provider.dart` | `https://generativelanguage.googleapis.com/v1beta` |
| Anthropic | `anthropic_provider.dart` | `https://api.anthropic.com` |
| Azure OpenAI | `azure_provider.dart` | 按 key 配置 |
| 自定义 | `custom_provider.dart` | 按 key 配置 |

### 13.2 通用适配器基类（BaseHttpProvider）

```
职责：
├── 共享 HttpClient（连接池）
├── buildUri() — URI 构造（自动处理 base/path 前缀重叠）
├── 跳过逐跳头（connection / keep-alive / 等）
├── 覆盖鉴权头（去除客户端原 Authorization）
├── 自动解压上游响应
├── 自动识别流式（event-stream / x-ndjson）
├── test() — key 连通性测试
└── fetchModels() — 模型列表拉取
```

### 13.3 URI 拼接规则

```
joinPath(base, path):
  1. 去除 base 尾斜杠
  2. 确保 path 以 / 开头
  3. 检测 path 与 base 路径段重叠 → 自动去重
     例：base=/v1, path=/v1/chat/completions
         → /v1/chat/completions（不重复 /v1）
```

### 13.4 响应头处理

客户端不转发的头：
- 逐跳头（connection, keep-alive, proxy-* 等）
- 内容头（content-length, host, accept-encoding）
- 鉴权头（authorization, x-api-key, api-key）
- 中间层头（x-relay-provider, x-relay-key）

---

## 14. 管理 API 接口

所有管理接口路径在 `Constants.adminPaths` 中注册，不转发到上游。

### 14.1 路径总表

| 路径 | 方法 | 说明 |
|------|------|------|
| `/relay/stats` | GET | 实时统计（key 状态 / 请求数 / 延迟） |
| `/relay/version` | GET | 版本信息 + 在线更新检查 |
| `/relay/update/check` | POST | 触发在线更新 |
| `/relay/report` | GET | 统计报表（90 天回溯） |
| `/relay/cache` | GET / DELETE | 缓存统计 / 清空 |
| `/relay/keys` | GET / POST / DELETE / PATCH | Key 管理 |
| `/relay/settings` | GET / PUT | 设置管理 |
| `/relay/rules` | GET / POST / DELETE | 路由规则管理 |
| `/relay/logs` | GET | 日志查询（?limit=N） |
| `/relay/alerts` | GET | 告警列表 |
| `/relay/models/sync` | POST | 触发模型列表同步 |
| `/relay/metrics` | GET | Prometheus 指标 |
| `/relay/health` | GET | 健康探测 |
| `/relay/gateway-keys` | GET / POST / PATCH / DELETE | 附加网关密钥管理 |
| `/relay/routes` | GET / POST / PATCH / DELETE | 模型路由管理 |
| `/relay/trend` | GET | 用量趋势 |
| `/relay/pricing` | GET / POST | 价格管理 |
| `/relay/webhook/test` | POST | Webhook 测试发送 |
| `/relay/export/logs` | GET | 日志 CSV 导出 |
| `/relay/export/stats` | GET | 统计 CSV 导出 |
| `/api/overview` | GET | 总览（从 InterGate 移植） |
| `/admin/check-all` | POST | 全量 key 连通性检测 |
| `/admin/mark-exhausted` | POST | 手动标记 key 耗尽 |

### 14.2 鉴权方式

```
管理令牌（推荐）：
  Header: x-relay-admin-token: <token>
  或
  Header: Authorization: Bearer <token>

网关密钥（入口鉴权）：
  Header: Authorization: Bearer <key>
  或
  Header: x-api-key: <key>
  或
  Header: x-gateway-key: <key>
```

### 14.3 关键接口示例

**Key 管理：**
```
GET  /relay/keys              → [{id, name, provider, status, ...}]
POST /relay/keys              → {name, provider, key, ...}
DELETE /relay/keys            → ?id=<keyId>
PATCH /relay/keys             → ?id=<keyId> {status, enabled, ...}
```

**设置管理：**
```
GET  /relay/settings          → {port, host, loadBalanceStrategy, ...}
PUT  /relay/settings          → {port: 8788, host: "0.0.0.0", ...}
```

**路由规则：**
```
GET  /relay/rules             → [{id, name, provider, ...}]
POST /relay/rules             → {name, provider, group, ...}
DELETE /relay/rules           → ?id=<ruleId>
```

---

## 15. 虚拟模型层

### 15.1 功能说明

将不同提供商的模型按能力分层，收敛为 10 个虚拟模型档位，客户端使用统一模型名即可自动匹配最佳提供商。

**默认关闭**（`virtualModelsEnabled = false`），开启后：
- `/v1/models` 返回虚拟模型列表
- 请求体中的虚拟模型名改写为真实提供商的真实模型名

### 15.2 工作流程

```
1. 请求 /v1/chat/completions model=gpt-4o-turbo
2. ModelNormalizer.resolveRequestModel("gpt-4o-turbo") → virtualId
3. 查询目录中该 virtualId 的已启用模型
4. 按提供商筛选候选
5. 转发时改写 model 为该提供商的真实模型名
6. 实际返回时保留真实模型名（供 token 统计）
```

### 15.3 目录中模型已禁用时的行为

- 跳过已禁用的映射候选
- 回退到内置典型候选（`StandardModelRegistry.virtualTypical`）
- 若全部不可用 → 返回友好提示而非透传 404

---

## 16. Web 控制台

### 16.1 配置项

| 字段 | 说明 |
|------|------|
| `webEnabled` | 是否启用 Web 控制台 |
| `webPort` | 控制台端口（默认 51235） |
| `webPassword` | 控制台密码 |

### 16.2 控制台页面

嵌入在 `config/web_panel.html` 中，包含：
- 仪表盘（实时统计）
- Key 管理（增删改查）
- 路由规则配置
- 日志查看
- 告警历史
- 设置编辑

---

## 17. 告警与 Webhook

### 17.1 告警类型

| 告警 | 触发条件 |
|------|----------|
| 额度告警 | 当日用量 ≥ `quotaWarnThreshold` |
| 错误率告警 | 当日错误率 ≥ `errorRateThreshold` |
| 限流告警 | 触发了入口限流（IP / 全局 / key） |
| 请求异常 | 响应状态码 ≥ 400 |
| Key 状态变更 | active → error / exhausted |

### 17.2 Webhook 通知

```
配置：
  webhookEnabled = true
  webhookUrl = "https://hooks.example.com/webhook"
  webhookSecret = "<hmac-secret>"

触发：任何请求响应状态码 ≥ 400 时
方式：Fire-and-forget（不阻塞响应）

请求体：
{
  "title": "RelayGo 请求异常",
  "content": "模型: gpt-4o\n状态码: 401\n提供商: openai\n...",
  "timestamp": "2026-08-28T..."
}

签名：HMAC-SHA256（webhookSecret）
```

---

## 18. 配置与存储

### 18.1 Hive 存储盒

| Box | 内容 |
|-----|------|
| `relay_vault` | 主密钥（AES） |
| `relay_api_keys` | Key 列表（加密存储） |
| `relay_request_logs` | 请求日志 |
| `relay_settings` | 用户设置 + 价格覆盖规则 |
| `relay_routing_rules` | 路由规则 |
| `relay_alerts` | 告警记录 |
| `relay_providers` | 用户自定义提供商配置 |
| `relay_models` | 模型目录 |
| `relay_sync_history` | 模型同步历史 |
| `relay_free_api_cache` | Free API Hub 缓存 |

### 18.2 UserSettings 配置项

| 配置 | 默认值 | 说明 |
|------|--------|------|
| `port` | 8788 | 代理监听端口 |
| `host` | 0.0.0.0 | 监听地址 |
| `loadBalanceStrategy` | round_robin | 负载均衡策略 |
| `maxRetryKeys` | 3 | 单请求最大重试 key 数 |
| `upstreamTimeoutSeconds` | 120 | 上游请求超时 |
| `cacheEnabled` | false | 响应缓存开关 |
| `cacheTtlSeconds` | 300 | 缓存 TTL |
| `cacheMaxEntries` | 500 | 缓存上限 |
| `rateLimitEnabled` | true | Key 级限流 |
| `adaptiveTpmEnabled` | true | 自适应 TPM |
| `globalRpmLimit` | 0 | 全局 RPM（0 = 不限） |
| `ipRateLimitPerMinute` | 0 | IP RPM（0 = 不限） |
| `tokenRateLimitPerMinute` | 0 | Key TPM（0 = 不限） |
| `burstMultiplier` | 1.5 | 令牌桶突发倍数 |
| `webhookEnabled` | false | Webhook 通知 |
| `gatewayKeyEnabled` | false | 入口网关 Key 鉴权 |
| `virtualModelsEnabled` | false | 虚拟模型层 |
| `adminToken` | null | 管理令牌 |
| `webEnabled` | false | Web 控制台 |
| `upstreamMaxConnections` | 100 | 上游连接池 |
| `upstreamMaxKeepalive` | 20 | 上游连接保活 |

---

## 19. 性能常量一览

| 常量 | 值 | 说明 |
|------|----|------|
| `maxConcurrentConnections` | 50 | 同时转发上游上限 |
| `maxQueuedConnections` | 200 | 排队上限 |
| `maxFailureThreshold` | 3 | 连续失败次数阈值 |
| `cooldownSeconds` | 300 | 失败冷却时间 |
| `upstreamTimeoutSeconds` | 120 | 上游请求超时 |
| `upstreamIdleTimeoutSeconds` | 30 | 上游读取空闲超时 |
| `maxRetryKeys` | 3 | 单次请求最大重试 key 数 |
| `maxRequestBodyBytes` | 32MB | 请求体上限 |
| `deduplicationWindowMs` | 2000 | 请求去重窗口 |
| `retryBackoffBaseMs` | 500 | 退避基数 |
| `retryBackoffMaxMs` | 5000 | 退避上限 |
| `cachePurgeIntervalMs` | 60000 | 缓存清理周期 |
| `tpmAimdDown` | 0.85 | AIMD 乘性减系数 |
| `tpmAimdUp` | 0.02 | AIMD 加性增系数 |
| `tpmWaitBudgetMs` | 8000 | TPM 429 等待预算 |
| `quotaExhaustedCooldownMs` | 1800000 | 额度耗尽冷却 30 分钟 |

---

## 附录 A：文件索引

| 文件 | 行数 | 说明 |
|------|------|------|
| `lib/relaygo/services/proxy_server.dart` | ~2150 | 代理服务器核心 |
| `lib/relaygo/services/load_balancer.dart` | ~200 | 负载均衡器 |
| `lib/relaygo/services/cache_manager.dart` | ~200 | 响应缓存 |
| `lib/relaygo/services/rate_limiter.dart` | ~370 | 多维限流器 |
| `lib/relaygo/services/quota_monitor.dart` | ~150 | 额度监控 |
| `lib/relaygo/services/upstream_error.dart` | ~120 | 上游错误分类 |
| `lib/relaygo/services/daily_stats_service.dart` | ~150 | 每日统计 |
| `lib/relaygo/services/key_manager.dart` | ~200 | Key 管理 |
| `lib/relaygo/services/providers/base_provider.dart` | ~380 | 通用适配器基类 |
| `lib/relaygo/models/user_settings.dart` | ~360 | 用户设置 |
| `lib/relaygo/config/constants.dart` | ~300 | 全局常量 |

---

*文档最后更新：v1.0.1*
