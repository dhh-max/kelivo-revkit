# Third-Party App Integrations

本目录汇集与 Kelivo 生态相关的第三方 App 源码与逆向分析产物。每个子目录对应一个独立 App，
保留完整的项目源码、Gradle / Flutter 配置与关键资产，便于逆向分析时交叉比对。

## 目录结构

```
third-party/
├── apps/
│   ├── relaygo/               # Flutter Android 代理工具（开源参考）
│   └── proxy_pin/             # Flutter Android 抓包工具（开源参考）
└── INTEGRATION.md             # 本文件
```

## App 清单

| App | 语言/技术栈 | 来源 | 用途 |
|---|---|---|---|
| relaygo | Dart / Flutter | github.com/dhh-max/relaygo | Android 代理/加速服务参考实现 |

## 与 Kelivo 的关系

- **RelayGo** 是 Kelivo 集成时的第三方代理链路组件，本目录保留源码用于：
  - 分析其网络栈与认证方式（便于 Kelivo 集成时避免踩坑）；
  - 复用其证书/抓包流程模式；
  - 作为 Kelivo `third_party` 模块中相应解析器的对照实现。

## 使用约束

- 每个 App 子目录的原始 LICENSE 保持不变（见各子目录内 LICENSE 文件）；
- 本目录**不参与 Kelivo 构建**，仅作为逆向分析资料；
- 若某 App 源码含二进制大文件，应交由 Git LFS 托管（已在 `.gitattributes` 中配置）。

## 更新记录

- 2026-10-11  初版：RelayGo / ProxyPin 源码入仓。

---

## 附：TaiXu 提取模块说明

Kelivo 在 2026-10-11 起从 TaiXu Android 源码中提取了 4 个纯算法模块到
`apk-rev-project/apk_reverse_engine/lite/` 下，均**零外部依赖**、纯 Python 标准库实现，
与 TaiXu 的 Kotlin 版本语义对齐：

| 模块 | TaiXu 源文件 | 用途 |
|---|---|---|
| `redactor.py`     | `core/security/SecretRedactor.kt`   | 敏感信息（API key / Bearer / 手机号）脱敏 |
| `shell_quote.py`  | `core/common/shell/ShellQuote.kt`   | Shell 安全引用（防注入） |
| `app_result.py`   | `core/common/result/AppResult.kt`   | 12 类 ErrorCode + Success/Failure |
| `checksum.py`     | `core/network/ChecksumVerifier.kt`  | 64KB 流式 SHA256/SHA1/MD5 校验 |

配套测试：`apk-rev-project/tests/test_third_party.py`（32 用例，全部通过）。

这些模块**不依赖 TaiXu 本仓库源码**，可作为独立单元在 Kelivo / apk-rev-project 中调用。
