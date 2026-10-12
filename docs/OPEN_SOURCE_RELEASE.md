# SoLab 开源包说明

本目录由 SoLab 当前版本的源码快照生成（版本号见 `pubspec.yaml`），不包含 Git 历史、
构建产物、开发缓存、本机插件路径、发布密钥或证书样本。

与 2.3 开源包同一套口径：**能公开的都写明来源与许可证；不能确认授权的原样标注，
不假装已获许可。**

## 包含内容

- 应用源码（`lib/`、`android/`）、测试（`test/`、`integration_test/`）与构建脚本
  （`tool/`、`tools/`）。
- 内置依赖覆盖（`dependencies/`）、数据库 schema 快照（`drift_schemas/`）。
- 第三方许可证文本（`assets/licenses/`）与仓库级声明（`NOTICE`、`LICENSE`）。
- APK 分析、工作台、MCP 服务、工作流、子代理与技能体系的完整源码。
- DPatch 模式所需的原样 DEX / 原生载荷（见下节来源与发布条件）。

## 不包含内容（快照脚本会显式排除）

- **内部材料**：内部工作文档（`docs/` 只保留本说明与两份公开文档：`ARCHITECTURE.md`
  架构概览、`DEVELOPMENT.md` 开发指南）、验证/审计/设备探针脚本、
  本地环境与对接笔记、AI 编码代理说明（`AGENTS.md`）、本地小工具。
  `tool/`、`tools/` 只保留构建与测试所需（运行期 harness、Blutter runner 流水线、
  pkg-config 垫片、构建/发布脚本）。
- `.git/`（不含历史）、`build/`、`dist/`、`.dart_tool/`、`.gradle/`、`.cxx/`
  等构建产物与缓存。
- 非 Android 平台目录（`ios/`、`linux/`、`macos/`、`windows/`）——按 2.3 开源包
  同一口径排除（SoLab 以 Android/arm64 为主）。
- 发布签名密钥与口令文件（`**/*.jks`、`*.keystore`、`key.properties`）、
  `local.properties` 等本机路径；另有**口令内容扫描**兜底（properties 里出现
  `storePassword`/`keyPassword` 即中止）。
- 开发过程杂物（`_tmp*`、`.tmp_probe`、日志、编辑器目录）。
- 快照脚本落地后做**两道自检**：密钥/证书类文件、内部文档残留——任一命中即删包
  中止，不会产出「看着像通过」的包。

## 第三方来源与许可证

完整清单在仓库根目录 `NOTICE`（原生库、预编译 jar、素材、未声明许可证的材料都在
那一份里逐条列出）。应用内「设置 → 关于 → 开源许可」页同样聚合展示，并附
`assets/licenses/` 中的许可证全文。

需要特别声明的材料：

- **DPatch 载荷**（`android/app/src/main/assets/dpatch/pandora_loader.dex` 与
  `libpandora.so`）：网络来源，交付材料未提供可复现的原始链接、作者信息或许可证。
  本仓库只作来源声明，不主张版权，也不表示已取得再分发授权。公开发布包含该载荷的
  二进制前，必须取得权利人许可，或替换为有明确许可证的实现。
- **ApkDataMultiplexing**（`android/app/libs/apk-data-multiplexing.jar`）：上游仓库
  未声明许可证；公开发布前同样需要书面许可或替换实现。
- **大肥鱼桌宠素材**（`assets/pet/`）：MIT（QCYTSN/dsh-dafeiyu），随包分发并保留
  署名，详见 `NOTICE`。

## 构建

按 `README.md` 的 Android 构建步骤执行（JDK 21 + Flutter）。首次构建会由
Flutter / Gradle 在本机生成依赖与缓存，这些生成内容不属于本开源包，也不会随包分发。

## 发布检查单

公开二进制 / 源码发布前：

1. `NOTICE` 中「未声明许可证」一节逐条确认：替换、取得许可，或从发布物中移除。
2. `android/app/libs/` 与 `android/app/src/main/jniLibs/` 的每个预编译产物核对
   来源、版本与许可证（`jniLibs/NOTICE` 已记录 PRoot 的版本与 SHA-256）。
3. 确认发布物不含 `*.jks` / `*.keystore` / 任何真实密钥。
4. `LICENSE`（AGPL-3.0）随源码与二进制分发提供，并保留本说明与 `NOTICE`。
