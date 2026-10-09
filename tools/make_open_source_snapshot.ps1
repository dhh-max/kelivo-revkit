# SoLab 开源快照生成器
#
# 用法（在仓库根目录）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools/make_open_source_snapshot.ps1
#   powershell ... -File tools/make_open_source_snapshot.ps1 -OutputRoot D:\out -Zip
#
# 产物：<OutputRoot>\SoLab-<version>-open-source\（源码快照）
#      [可选] 同名 .zip
#
# 与 2.3 开源包同一口径：不含 Git 历史、构建产物、开发缓存、本机插件路径、
# 发布密钥或证书样本。落地后做一次泄密自检，发现密钥类文件立即中止并给出路径。

[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$Zip,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

$versionLine = Select-String -LiteralPath (Join-Path $projectRoot 'pubspec.yaml') -Pattern '^version:\s*([^\s]+)' | Select-Object -First 1
if (-not $versionLine) { throw 'pubspec.yaml 里没有 version: 行' }
$version = $versionLine.Matches[0].Groups[1].Value
$name = "SoLab-$version-open-source"

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Split-Path -Parent $projectRoot
}
$target = Join-Path $OutputRoot $name

# 排除清单：与 2.3 开源包说明一一对应。
# **按目录名**排除（robocopy /XD 传裸名 = 全树同名字目录都排除）：Gradle / CMake
# 的构建缓存藏在 android/.gradle、android/app/.cxx、dependencies/*/android/build
# 这些位置，只有裸名才拦得住（首版用绝对路径漏了它们，快照多出 200MB+）。
# 非 Android 平台目录按 2.3 开源包口径整体排除（SoLab 以 Android/arm64 为主，
# 桌面/iOS 目录不参与发布，也避免带上 flutter ephemeral 生成物）。
# `.cargo/`（仅 18 字节 config.toml 的构建配置）有意保留：它属于构建脚本材料。
$excludeDirs = @(
    '.git', 'build', 'dist', '.dart_tool', '.gradle', '.cxx', '.mimosa',
    '.idea', '.vscode', '.tmp_probe', '_tmp', '_tmp_strategist', 'node_modules',
    'ios', 'linux', 'macos', 'windows'
)
$excludeFiles = @(
    'local.properties', '.flutter-plugins-dependencies', '.git.lnk',
    'desiredFileName.txt', 'flutter_01.log', 'open_tid.txt',
    # 内部材料不进包：AGENTS.md 是给 AI 编码代理的内部说明；wb_l10n.py 是本地
    # l10n 小工具（无任何构建/测试引用）。
    'AGENTS.md', 'wb_l10n.py',
    # **签名口令文件**：android/key.properties 保存 storePassword/keyPassword，
    # 不在 git 里也不许进包（首版漏排，已列入内容级自检）。
    'key.properties', 'keystore.properties'
)
$excludePatterns = @('*.jks', '*.keystore', '*.log', '*.apk', '*.aab', '*.p12', '*.pfx')

# —— 白名单裁剪（2026-10-05 用户要求「保持开源文件干净」）——
# 用户/内部材料不进包里：内部工作文档、验证脚本、设备探针、本地环境与对接笔记。
# 与 2.3 开源包同一口径：docs/ 只留开源说明；tool/、tools/ 只留构建与测试所需。
$docsKeep = @(
    'OPEN_SOURCE_RELEASE.md',   # 开源包说明（包含/不包含、来源与发布条件）
    'ARCHITECTURE.md',          # 公开架构概览（面向开发者）
    'DEVELOPMENT.md'            # 公开开发指南（构建/测试/扩展点）
)
$toolKeep = @(
    # 运行期 harness（测试/基准/追踪，2.3 开源包同款）
    'chat_database_v2_benchmark.dart', 'run_p0_regression.dart',
    'run_restore_process_harness.dart', 'src', 'trace-bodies',
    'trace_recorder.dart', 'traces.yaml',
    # 构建所需：工作区沙盒 PRoot 的下载脚本与校验清单
    'fetch_proot.sh', 'proot_checksums.txt',
    # 资产数据管线
    'update_model_catalog.dart'
)
$toolsKeep = @(
    # 构建 / 发布脚本（2.3 开源包同款 + Blutter runner 流水线 + 本快照脚本）
    '_build_release_jdk21.ps1', 'build_android_arm64.ps1',
    'build_blutter_runner.ps1', 'blutter_fix_icu_soname.py',
    'blutter_register_runner.py', 'trim_blutter_manifest.py',
    'check_project_identity.ps1', 'run_targeted_tests.ps1',
    'sync_upstream.ps1', 'make_open_source_snapshot.ps1',
    # Blutter 交叉编译在 Windows 上用到的 pkg-config 垫片
    'pkg-config.bat', 'pkgconfig_shim.py'
)

if (Test-Path -LiteralPath $target) {
    if (-not $Force) { throw "目标已存在：$target（加 -Force 覆盖）" }
    Remove-Item -LiteralPath $target -Recurse -Force
}

Write-Host "快照源：$projectRoot"
Write-Host "目标  ：$target"

New-Item -ItemType Directory -Path $target -Force | Out-Null

# 排除：裸名（目录）——/XD 传裸名时按名字匹配任意层级。
$xd = @()
foreach ($d in $excludeDirs) { $xd += @('/XD', $d) }
$xf = @()
foreach ($f in $excludeFiles) { $xf += @('/XF', $f) }
foreach ($p in $excludePatterns) { $xf += @('/XF', $p) }

$rc = 0
& robocopy $projectRoot $target /E /NFL /NDL /NJH /NJS /NP /R:1 /W:1 @xd @xf | Out-Null
$rc = $LASTEXITCODE
if ($rc -ge 8) { throw "robocopy 失败，退出码 $rc" }

# —— 白名单裁剪：docs/、tool/、tools/ 只留上面列出的文件/目录 ——
function Prune-ToKeepList {
    param([string]$Dir, [string[]]$Keep)
    if (-not (Test-Path -LiteralPath $Dir)) { return }
    Get-ChildItem -LiteralPath $Dir -Force | Where-Object { $Keep -notcontains $_.Name } | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Recurse -Force
    }
}
Prune-ToKeepList -Dir (Join-Path $target 'docs') -Keep $docsKeep
Prune-ToKeepList -Dir (Join-Path $target 'tool') -Keep $toolKeep
Prune-ToKeepList -Dir (Join-Path $target 'tools') -Keep $toolsKeep

# —— 泄密自检：密钥/证书类文件一个都不许进快照 ——
$leaks = Get-ChildItem -LiteralPath $target -Recurse -File -ErrorAction Stop |
    Where-Object {
        $_.FullName -notmatch 'ephemeral' -and (
            $_.Extension -in @('.jks', '.keystore', '.p12', '.pfx') -or
            $_.Name -match 'keystore' -or $_.Name -match '^\.env($|\.)'
        )
    }
if ($leaks.Count -gt 0) {
    $leaks | ForEach-Object { Write-Error ("疑似密钥文件进入快照：" + $_.FullName) }
    Remove-Item -LiteralPath $target -Recurse -Force
    throw '泄密自检未通过：快照已删除。请先清理源目录中的密钥类文件。'
}

# —— 口令内容自检：任何 properties 文件里出现签名口令字段即中止 ——
# （第一版快照把 android/key.properties 带进过包；名字排除 + 内容扫描双保险。）
$secretHits = @(Get-ChildItem -LiteralPath $target -Recurse -File -Filter '*.properties' -ErrorAction SilentlyContinue |
    Select-String -Pattern 'storePassword|keyPassword' -ErrorAction SilentlyContinue)
if ($secretHits.Count -gt 0) {
    $secretHits | ForEach-Object { Write-Error ("口令字段残留：" + $_.Path + ":" + $_.LineNumber) }
    Remove-Item -LiteralPath $target -Recurse -Force
    throw '口令自检未通过：快照已删除。'
}

# —— 必备文档自检 ——
$required = @('LICENSE', 'NOTICE', 'README.md', 'docs/OPEN_SOURCE_RELEASE.md')
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $target $_)) })
if ($missing.Count -gt 0) {
    Write-Warning ("快照缺少必备文档：" + ($missing -join '、') + '（先补齐再发布）')
}

# —— 内部材料残留自检：docs/ 只允许开源说明一份；tool/tools 只允许白名单 ——
$docsStray = @(Get-ChildItem -LiteralPath (Join-Path $target 'docs') -Force -ErrorAction SilentlyContinue |
    Where-Object { $docsKeep -notcontains $_.Name })
if ($docsStray.Count -gt 0) {
    $docsStray | ForEach-Object { Write-Error ("内部文档仍在快照里：" + $_.FullName) }
    Remove-Item -LiteralPath $target -Recurse -Force
    throw '内部材料自检未通过：快照已删除。'
}

$fileCount = (Get-ChildItem -LiteralPath $target -Recurse -File).Count
$sizeMb = [math]::Round(((Get-ChildItem -LiteralPath $target -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB), 1)

Write-Host "完成：$target（$fileCount 个文件，约 $sizeMb MB）"
Write-Host "已排除：Git 历史 / 构建产物 / 开发缓存 / 密钥 / 内部文档与本地工具（自检通过）"

if ($Zip) {
    $zipPath = "$target.zip"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Compress-Archive -Path (Join-Path $target '*') -DestinationPath $zipPath -CompressionLevel Optimal
    Write-Host "已打包：$zipPath"
}
