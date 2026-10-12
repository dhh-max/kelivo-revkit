# Third-Party App Integrations

本目录汇集与 Kelivo 生态相关的第三方 App 源码与逆向分析产物。每个子目录对应一个独立 App，
保留完整的项目源码、Gradle / Flutter 配置与关键资产，便于逆向分析时交叉比对。

## 目录结构

```
third-party/
├── apps/
│   ├── relaygo/               # Flutter Android 代理工具（开源参考）
│   ├── proxy_pin/             # Flutter Android 抓包工具（开源参考）
│   ├── taixu/                 # Android 代理/加速工具（开源参考）
│   └── blutter_android/       # Blutter Android 端（开源参考）
└── INTEGRATION.md             # 本文件
```

## App 清单

| App | 语言/技术栈 | 来源 | 用途 |
|---|---|---|---|
| relaygo | Dart / Flutter | github.com/dhh-max/relaygo | Android 代理/加速服务参考实现 |
| proxy_pin | Dart / Flutter | github.com/ProxyPin/proxypin | Android 抓包工具参考实现 |
| taixu | Kotlin / Android | github.com/chengming/taixu | Android 代理/加速工具参考实现 |
| blutter_android | Kotlin / Android | github.com/Blutter-Project/BlutterAndroid | Blutter Android 端参考实现 |

## 与 Kelivo 的关系

- **RelayGo** 是 Kelivo 集成时的第三方代理链路组件，本目录保留源码用于：
  - 分析其网络栈与认证方式（便于 Kelivo 集成时避免踩坑）；
  - 复用其证书/抓包流程模式；
  - 作为 Kelivo `third_party` 模块中相应解算器的对照实现。
- **proxy_pin / taixu / blutter_android** 作为 Android 侧代理/抓包/加速工具的交叉参考，
  为 Kelivo 的逆向分析模块（`lib/core/services/mcp/kelivo_reverse/` 等）
  提供实现参照。

## 使用约束

- 每个 App 子目录的原始 LICENSE 保持不变（见各子目录内 LICENSE 文件）；
- 本目录**不参与 Kelivo 构建**，仅作为逆向分析资料；
- 若某 App 源码含二进制大文件，应交由 Git LFS 托管（已在 `.gitattributes` 中配置）；
- 已剔除与源码无关的构建产物（`build/`、`out/`、`.gradle/`、`dist/`、
  `baselineProfiles/`、`ndk_src/`）以控制仓库体积。

## 更新记录

- 2026-10-11  初版：RelayGo / ProxyPin 源码入仓。
- 2026-10-12  补齐：blutter_android、taixu 源码入仓；统一目录到 `third-party/apps/`。
