# SoLab 开发指南

面向开发者的公开说明：环境准备、构建、测试与扩展点。内部研发材料不随开源包分发。

## 环境准备

- **Flutter** ≥ 3.44.1（Dart SDK ^3.12.1），Android SDK（compileSdk 36）。
- **JDK 21**：Android release 构建要求（低于 21 会拒绝）。
- **Android NDK**：仅重建原生组件时需要。
- Windows 上建议用仓库自带脚本构建（它会做 JDK 校验与产物落盘）。

## 构建

```bash
flutter pub get
flutter build apk --release --target-platform android-arm64
```

Windows 一键（含版本号从 pubspec 现读现传、产物复制到 `dist/`、计算 SHA-256）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/build_android_arm64.ps1 -JdkPath D:\path\to\jdk21
```

预编译原生依赖（PRoot 等）由 `tool/fetch_proot.sh` 下载并在
`tool/proot_checksums.txt` 校验；Blutter runner 由
`tools/build_blutter_runner.ps1` 交叉编译产出（流水线含 pkg-config 垫片与
ICU soname 修正脚本）。

## 测试

```bash
flutter analyze                 # 静态检查
flutter test test/features/xxx  # 定向测试（推荐一次只跑改动相关的目录）
```

仓库提供运行期 harness（`tool/`）：`run_p0_regression.dart`（回归）、
`run_restore_process_harness.dart`（恢复流程）、`chat_database_v2_benchmark.dart`
（数据库基准）、`trace_recorder.dart` + `traces.yaml`（追踪采样）。

约定：改动先在定向测试里锁住契约（边界、失败形状、幂等性），再提交；跑测试
用最小范围，避免整目录全量。

## 代码结构

见 `docs/ARCHITECTURE.md` 的目录速查表。三条常用扩展路径：

1. **加一个本地工具**：在 `lib/core/services/local_tools/` 注册名称与 schema，
   在 `lib/features/home/services/` 里接 handler；失败时返回统一信封
   （`ok:false` + `error{code,message,severity,recoverable,retrySameArguments}` +
   顶层 `nextActions`），错误码统一 lower_snake。
2. **加一个原生能力**：在 `android/app/src/main/kotlin/zhou/solab/` 的通道里
   注册动作，产物登记进运行时台账（`originPath` 指向设备原件）。
3. **加一个模型服务**：实现 provider 协议适配（`lib/core/services/api/`），
   在模型目录里登记（`assets/model_catalog/`）。

## 成对纪律（提交前自检）

- 只改文案/派生字段、不改数值口径时，优先在**读取侧归一**，不要悄悄换语义。
- 数据落盘的位置要登记进业务偏好注册表（`core/database/`）——未登记的键会
  在启动迁移的清理阶段被视为遗留物；应用自有 Store 的键必须登记为 `localOnly`。
- 对外暴露的路径别名（`/workspace`）在读写两条通道要保持同一张映射表。
- 失败的形状只有一套：任何工具族都不新增第二套字段命名。

## 开源包

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/make_open_source_snapshot.ps1 -OutputRoot D:\out -Zip
```

脚本按白名单裁剪（`docs/` 只留公开文档、`tool/`+`tools/` 只留构建与测试所需），
排除 Git 历史 / 构建缓存 / 非 Android 平台目录 / 密钥与口令文件，并在落地后做
密钥与内部文档双重自检，任一命中即删包中止。详见 `docs/OPEN_SOURCE_RELEASE.md`。

## 许可

AGPL-3.0。第三方来源与许可记录在 `NOTICE` 与 `assets/licenses/`。
