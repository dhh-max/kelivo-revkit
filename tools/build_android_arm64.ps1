[CmdletBinding()]
param(
    [string]$JdkPath = $env:JAVA_HOME
)

$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDirectory
$delivery = $null
$buildLock = [System.Threading.Mutex]::new($false, 'SoLabAndroidArm64Build')
$lockHeld = $false

$javaExecutable = if ($JdkPath) { Join-Path $JdkPath 'bin\java.exe' } else { 'java' }
if ($JdkPath -and -not (Test-Path -LiteralPath $javaExecutable -PathType Leaf)) {
    throw "JDK was not found at: $JdkPath"
}
$javaVersion = (& $javaExecutable --version | Select-Object -First 1).ToString()
if ($javaVersion -notmatch '^(?:openjdk|java) 21[\.]') {
    throw "Android release builds require JDK 21. Current runtime: $javaVersion"
}

try {
    $lockHeld = $buildLock.WaitOne(0)
    if (-not $lockHeld) {
        throw 'Another Android release build is already running.'
    }

    Push-Location $projectRoot
    try {
        # Workspace sandbox needs Termux PRoot (4 aarch64 shared libs). Upstream
        # does not commit these binaries; tool/fetch_proot.sh downloads them. Make
        # sure they are present before building; warn only if the fetch fails.
        $prootAbi = 'android/app/src/main/jniLibs/arm64-v8a'
        $prootLibs = @(
            'libproot_exec.so', 'libproot_loader.so',
            'libtalloc.so', 'libandroid-shmem.so'
        )
        $prootMissing = @($prootLibs | Where-Object {
                -not (Test-Path -LiteralPath (Join-Path $projectRoot "$prootAbi/$_"))
            })
        if ($prootMissing.Count -gt 0) {
            Write-Host "PRoot binaries missing ($($prootMissing -join ', ')); fetching..."
            & bash tool/fetch_proot.sh
            $stillMissing = @($prootLibs | Where-Object {
                    -not (Test-Path -LiteralPath (Join-Path $projectRoot "$prootAbi/$_"))
                })
            if ($stillMissing.Count -gt 0) {
                Write-Warning "PRoot still missing: $($stillMissing -join ', '). Workspace sandbox will not run commands on device."
            }
        }

        # 显式传 --build-name/--build-number：只改 pubspec 时 Flutter 的
        # Android 侧可能复用缓存的 versionName/versionCode（实测：pubspec 已到
        # 2.4.25+132，装出来的仍是 2.4.24+131，且两次产物字节完全相同），
        # 于是"包与提交一一对应"这条就断了。这里从 pubspec 现读现传。
        # 用 [regex]::Match 而不是 -match/$Matches：后者在失败时会残留上一次的值。
        $versionLine = (Select-String -LiteralPath (Join-Path $projectRoot 'pubspec.yaml') -Pattern '^version:\s*([^\s]+)' | Select-Object -First 1)
        if (-not $versionLine) {
            throw 'pubspec.yaml 里没有 version: 行，无法确定构建版本号。'
        }
        $rawVersion = $versionLine.Matches[0].Groups[1].Value
        $versionMatch = [regex]::Match($rawVersion, '^(\d+(?:\.\d+)*)(?:\+(\d+))?$')
        if (-not $versionMatch.Success) {
            throw "pubspec.yaml 的 version 格式无法解析: '$rawVersion'（期望 x.y.z+N）。"
        }
        $namePart = $versionMatch.Groups[1].Value
        $codePart = if ($versionMatch.Groups[2].Success) { $versionMatch.Groups[2].Value } else { '1' }
        Write-Host "Building with versionName=$namePart versionCode=$codePart"
        & flutter build apk --release --target-platform android-arm64 --build-name $namePart --build-number $codePart
        if ($LASTEXITCODE -ne 0) {
            throw "Flutter release build failed with exit code $LASTEXITCODE."
        }

        $sourceApk = Join-Path $projectRoot 'build/app/outputs/flutter-apk/app-release.apk'
        if (-not (Test-Path -LiteralPath $sourceApk -PathType Leaf)) {
            throw "Release APK was not created: $sourceApk"
        }

        $versionLine = Select-String -LiteralPath (Join-Path $projectRoot 'pubspec.yaml') -Pattern '^version:\s*([^+\s]+)' | Select-Object -First 1
        $version = if ($versionLine) { $versionLine.Matches[0].Groups[1].Value } else { 'unknown' }
        $distDirectory = Join-Path $projectRoot 'dist'
        $outputApk = Join-Path $distDirectory "SoLab-$version-arm64-v8a.apk"
        New-Item -ItemType Directory -Path $distDirectory -Force | Out-Null
        Copy-Item -LiteralPath $sourceApk -Destination $outputApk -Force
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $apkStream = [System.IO.File]::OpenRead($outputApk)
        try {
            $sha256Text = ([System.BitConverter]::ToString($sha256.ComputeHash($apkStream))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $apkStream.Dispose()
            $sha256.Dispose()
        }
        $delivery = [pscustomobject]@{
            Path = $outputApk
            Bytes = (Get-Item -LiteralPath $outputApk).Length
            Sha256 = $sha256Text
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($lockHeld) { $buildLock.ReleaseMutex() }
    $buildLock.Dispose()
}

$delivery
