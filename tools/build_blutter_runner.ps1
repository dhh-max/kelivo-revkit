[CmdletBinding()]
param(
    [string]$DartVersion = '3.13.0',
    [string]$RunnerName = 'blutter_3_13',
    [string]$WorkRoot = '',
    [string]$NdkPath = 'D:\Environment\SDK\ndk\29.0.13846066',
    [string]$CmakePath = 'D:\Environment\SDK\cmake\3.22.1\bin',
    [switch]$KeepWork
)

# Build a Blutter exec runner (.so) for one Dart version and register it.
#
# Why this script exists: jniLibs/ and assets/ are gitignored (upstream keeps
# these binaries out of the repo), so a fresh clone has no runners at all.
# This script reproduces the toolchain that produced the bundled runners:
#   blutter-termux fork source -> Dart VM static lib -> blutter runner -> strip
#
# Requirements: git, python, curl (all on PATH), NDK r29 (atomic_ref lives in
# its libc++), and CMake's bundled ninja. Network access to GitHub and the
# Termux package mirror is needed for sources and ICU/capstone/fmt.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools/build_blutter_runner.ps1
#   powershell -ExecutionPolicy Bypass -File tools/build_blutter_runner.ps1 -DartVersion 3.14.0 -RunnerName blutter_3_14

$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDirectory
if (-not $WorkRoot) { $WorkRoot = Join-Path $projectRoot 'build\blutter-toolchain' }

$forkUrl = 'https://github.com/dedshit/blutter-termux'
$termuxRepo = 'https://packages.termux.dev/apt/termux-main'
$jniDir = Join-Path $projectRoot 'android\app\src\main\jniLibs\arm64-v8a'
$manifestPath = Join-Path $projectRoot 'android\app\src\main\assets\blutter\runners.json'
$dartMinor = ($DartVersion -split '\.')[0..1] -join '.'
$libName = "dartvm${DartVersion}_android_arm64"
$buildDir = Join-Path $WorkRoot "build\$RunnerName"
$packagesDir = Join-Path $WorkRoot 'packages'
$dartSrc = Join-Path $WorkRoot "dartsdk\v$DartVersion"
$sysroot = Join-Path $WorkRoot 'sysroot\data\data\com.termux\files\usr'
$forkDir = Join-Path $WorkRoot 'blutter-termux-main'

function Assert-Tool([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required tool not found on PATH: $Name"
    }
}

function Invoke-Step([string]$Label, [scriptblock]$Body) {
    Write-Host "==> $Label" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        throw "Step failed ($Label): exit $LASTEXITCODE"
    }
}

Assert-Tool git
Assert-Tool python
Assert-Tool curl

if (-not (Test-Path -LiteralPath (Join-Path $NdkPath 'build\cmake\android.toolchain.cmake'))) {
    throw "NDK r29 not found at $NdkPath. Install with: sdkmanager --install ndk;29.0.13846066"
}

New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null

# --- 1. blutter-termux source (contains Dart 3.13 single-snapshot support) ---
if (-not (Test-Path -LiteralPath $forkDir)) {
    Invoke-Step 'download blutter-termux source' {
        $zip = Join-Path $WorkRoot 'blutter-termux.zip'
        curl.exe -sSL -o $zip "$forkUrl/archive/refs/heads/main.zip"
        Expand-Archive -LiteralPath $zip -DestinationPath $WorkRoot -Force
        Remove-Item -LiteralPath $zip -Force
    }
}

# --- 2. Dart SDK source (sparse: runtime + tools + double-conversion) ---
if (-not (Test-Path -LiteralPath (Join-Path $dartSrc 'runtime\vm\version_in.cc'))) {
    Invoke-Step "clone Dart $DartVersion source" {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dartSrc) | Out-Null
        git -c advice.detachedHead=false clone -b $DartVersion --depth 1 --filter=blob:none --sparse `
            https://github.com/dart-lang/sdk.git $dartSrc
        Push-Location $dartSrc
        try {
            git sparse-checkout set runtime tools third_party/double-conversion
        } finally { Pop-Location }
    }
}

# --- 3. Termux deps (ICU, capstone, fmt, ndk-sysroot for libc++ headers) ---
$depsDir = Join-Path $WorkRoot 'deps'
New-Item -ItemType Directory -Force -Path $depsDir | Out-Null
$packages = @{
    'libicu'         = 'pool/main/libi/libicu/libicu_78.3_aarch64.deb'
    'libicu-static'  = 'pool/main/libi/libicu-static/libicu-static_78.3_aarch64.deb'
    'capstone'       = 'pool/main/c/capstone/capstone_5.0.9_aarch64.deb'
    'capstone-static' = 'pool/main/c/capstone-static/capstone-static_5.0.9_aarch64.deb'
    'fmt'            = 'pool/main/f/fmt/fmt_1%3A11.2.0_aarch64.deb'
    'ndk-sysroot'    = 'pool/main/n/ndk-sysroot/ndk-sysroot_29-3_aarch64.deb'
}
foreach ($key in $packages.Keys) {
    $deb = Join-Path $depsDir "$key.deb"
    if (-not (Test-Path -LiteralPath $deb)) {
        Invoke-Step "download $key" { curl.exe -sSL -o $deb "$termuxRepo/$($packages[$key])" }
    }
}

# --- 4. Build Dart VM static library ---
Invoke-Step 'build dartvm static library' {
    Push-Location $dartSrc
    try {
        # Dart 3.11+ needs C++20
        $tpl = Get-Content -LiteralPath (Join-Path $forkDir 'scripts\CMakeLists.txt') -Raw
        $tpl = $tpl.Replace('VERSION_PLACE_HOLDER', $DartVersion).Replace('STD_PLACE_HOLDER', '20')
        Set-Content -LiteralPath (Join-Path $dartSrc 'CMakeLists.txt') -Value $tpl -NoNewline
        Copy-Item -LiteralPath (Join-Path $forkDir 'scripts\icu_compat.h') -Destination $dartSrc -Force
        Set-Content -LiteralPath (Join-Path $dartSrc 'Config.cmake.in') `
            -Value "@PACKAGE_INIT@`n`ninclude ( `"`${CMAKE_CURRENT_LIST_DIR}/dartvmTarget.cmake`" )`n" -NoNewline
        python (Join-Path $dartSrc 'tools\make_version.py') --output (Join-Path $dartSrc 'runtime\vm\version.cc') --input (Join-Path $dartSrc 'runtime\vm\version_in.cc')
        python (Join-Path $forkDir 'scripts\dartvm_create_srclist.py') $dartSrc
    } finally { Pop-Location }

    $env:PKG_CONFIG_PATH = Join-Path $sysroot 'lib\pkgconfig'
    $env:PKG_CONFIG_LIBDIR = $env:PKG_CONFIG_PATH
    $env:PKG_CONFIG_SYSROOT_DIR = $sysroot
    $env:PATH = "$scriptDirectory;$env:PATH"

    & (Join-Path $CmakePath 'cmake.exe') -GNinja -B"$buildDir-dartvm" `
        "-DCMAKE_MAKE_PROGRAM=$(Join-Path $CmakePath 'ninja.exe')" `
        "-DCMAKE_TOOLCHAIN_FILE=$NdkPath\build\cmake\android.toolchain.cmake" `
        -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 -DANDROID_STL=c++_shared `
        -DCMAKE_BUILD_TYPE=Release "-DCMAKE_INSTALL_PREFIX=$packagesDir" `
        "-DCMAKE_FIND_ROOT_PATH=$sysroot" `
        -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=BOTH -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=BOTH `
        -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH "-DICU_ROOT=$sysroot" `
        -DTARGET_OS=android -DTARGET_ARCH=arm64 -DCOMPRESSED_PTRS=1 --log-level=NOTICE
    if ($LASTEXITCODE -ne 0) { throw 'dartvm cmake configure failed' }

    & (Join-Path $CmakePath 'ninja.exe') -C "$buildDir-dartvm"
    if ($LASTEXITCODE -ne 0) { throw 'dartvm build failed' }
    & (Join-Path $CmakePath 'cmake.exe') --install . -C "$buildDir-dartvm"
}

# Dart VM's cmake template links `pthread`, which Android folds into libc;
# drop it from the exported target so the runner links.
$targetCmake = Join-Path $packagesDir "lib\cmake\${libName}\dartvmTarget.cmake"
if (Test-Path -LiteralPath $targetCmake) {
    (Get-Content -LiteralPath $targetCmake -Raw).Replace('dl;pthread;', 'dl;') |
        Set-Content -LiteralPath $targetCmake -NoNewline
}

# --- 4b. Derive blutter's compat macros from the generated headers ---
# blutter.py's find_compat_macro() inspects packages/include/<lib>/vm/*.h to pick
# -D flags per Dart version. We replicate it here because when the build is run
# step-by-step it never executes, and missing a macro produces a runner that
# aborts on real snapshots (e.g. absent HAS_RECORD_TYPE made Dart 3.13 die with
# "Invalid abstract type ... _RecordType").
function Get-CompatMacros([string]$IncludeRoot, [string]$Version) {
    $vm = Join-Path $IncludeRoot 'vm'
    function Test-Contains([string]$File, [byte[]]$Pattern) {
        $path = Join-Path $vm $File
        if (-not (Test-Path -LiteralPath $path)) { return $false }
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $needle = [System.Text.Encoding]::ASCII.GetString($Pattern)
        $hay = [System.Text.Encoding]::ASCII.GetString($bytes)
        return $hay.Contains($needle)
    }
    $macros = @()
    if (Test-Contains 'class_id.h' ([byte[]][char[]]'V(LinkedHashMap)')) {
        $macros += '-DOLD_MAP_SET_NAME=1'
        if (-not (Test-Contains 'class_id.h' ([byte[]][char[]]'V(ImmutableLinkedHashMap)'))) {
            $macros += '-DOLD_MAP_NO_IMMUTABLE=1'
        }
    }
    if (-not (Test-Contains 'class_id.h' ([byte[]][char[]]' kLastInternalOnlyCid '))) {
        $macros += '-DNO_LAST_INTERNAL_ONLY_CID=1'
    }
    if (Test-Contains 'class_id.h' ([byte[]][char[]]'V(TypeRef)')) {
        $macros += '-DHAS_TYPE_REF=1'
    }
    if ($Version.StartsWith('3.') -and (Test-Contains 'class_id.h' ([byte[]][char[]]'V(RecordType)'))) {
        $macros += '-DHAS_RECORD_TYPE=1'
    }
    if (Test-Contains 'class_table.h' ([byte[]][char[]]'class SharedClassTable {')) {
        $macros += '-DHAS_SHARED_CLASS_TABLE=1'
    }
    if (-not (Test-Contains 'stub_code_list.h' ([byte[]][char[]]'V(InitLateStaticField)'))) {
        $macros += '-DNO_INIT_LATE_STATIC_FIELD=1'
    }
    if (-not (Test-Contains 'object_store.h' ([byte[]][char[]]'build_generic_method_extractor_code)'))) {
        $macros += '-DNO_METHOD_EXTRACTOR_STUB=1'
    }
    if (-not (Test-Contains 'object.h' ([byte[]][char[]]'AsTruncatedInt64Value()'))) {
        $macros += '-DUNIFORM_INTEGER_ACCESS=1'
    }
    return $macros
}

$dartIncludeRoot = Join-Path $packagesDir "include\dartvm$DartVersion"
$compatMacros = @(Get-CompatMacros -IncludeRoot $dartIncludeRoot -Version $DartVersion)
Write-Host "    compat macros: $($compatMacros -join ' ')" -ForegroundColor DarkGray
# OLD_MARKING_STACK_BLOCK is not covered by find_compat_macro; Dart 3.5+ split the
# marking stack block fields, so the old accessor pair is the correct one.
$compatMacros += '-DOLD_MARKING_STACK_BLOCK=1'

# --- 5. Build the runner ---
Invoke-Step 'build blutter runner' {
    $env:PKG_CONFIG_PATH = Join-Path $sysroot 'lib\pkgconfig'
    $env:PKG_CONFIG_LIBDIR = $env:PKG_CONFIG_PATH
    $env:PKG_CONFIG_SYSROOT_DIR = $sysroot
    $env:PATH = "$scriptDirectory;$env:PATH"

    Push-Location (Join-Path $forkDir 'blutter')
    try {
        # -rpath $ORIGIN: match the other bundled runners (they resolve sibling
        # libraries from the same directory); LD_LIBRARY_PATH also covers this,
        # but keeping the RPATH identical avoids loader-behaviour drift.
        & (Join-Path $CmakePath 'cmake.exe') -GNinja -B$buildDir `
            "-DCMAKE_MAKE_PROGRAM=$(Join-Path $CmakePath 'ninja.exe')" `
            "-DCMAKE_TOOLCHAIN_FILE=$NdkPath\build\cmake\android.toolchain.cmake" `
            -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 -DANDROID_STL=c++_shared `
            -DCMAKE_BUILD_TYPE=Release "-DCMAKE_FIND_ROOT_PATH=$sysroot" `
            -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=BOTH -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=BOTH `
            -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH `
            '-DCMAKE_EXE_LINKER_FLAGS=-Wl,-rpath,$ORIGIN' `
            "-DDARTLIB=$libName" `
            "-DCMAKE_INSTALL_PREFIX=$packagesDir" @compatMacros --log-level=NOTICE
        if ($LASTEXITCODE -ne 0) { throw 'runner cmake configure failed' }
        & (Join-Path $CmakePath 'ninja.exe') -C $buildDir
        if ($LASTEXITCODE -ne 0) { throw 'runner build failed' }
    } finally { Pop-Location }
}

$builtRunner = Join-Path $buildDir "blutter_${libName}"
if (-not (Test-Path -LiteralPath $builtRunner)) {
    throw "runner binary not produced: $builtRunner"
}

# --- 6. strip + ICU soname fix + install ---
$unstripped = Join-Path $WorkRoot "$RunnerName.unstripped.bin"
$stripped = Join-Path $WorkRoot "lib$RunnerName.so"
Copy-Item -LiteralPath $builtRunner -Destination $unstripped -Force

$llvmStrip = Join-Path $NdkPath 'toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe'
if (-not (Test-Path -LiteralPath $llvmStrip)) { throw "llvm-strip not found: $llvmStrip" }
& $llvmStrip --strip-all $unstripped -o $stripped
if ($LASTEXITCODE -ne 0) { throw 'strip failed' }

# ICU ships soname libicuuc.so.78 but the app bundles libicuuc.so.
# The helper takes a bare file name plus --dir (it refuses paths with any
# directory component, so it can never be pointed outside the project).
$strippedDir = Split-Path -Parent $stripped
$strippedName = Split-Path -Leaf $stripped
python (Join-Path $scriptDirectory 'blutter_fix_icu_soname.py') --dir $strippedDir $strippedName
if ($LASTEXITCODE -ne 0) { throw 'ICU soname fix failed' }

New-Item -ItemType Directory -Force -Path $jniDir | Out-Null
Copy-Item -LiteralPath $stripped -Destination (Join-Path $jniDir "lib$RunnerName.so") -Force

# --- 7. register in runners.json ---
python (Join-Path $scriptDirectory 'blutter_register_runner.py') `
    $manifestPath (Join-Path $jniDir "lib$RunnerName.so") $unstripped $dartMinor $RunnerName
if ($LASTEXITCODE -ne 0) { throw 'runner registration failed' }

Write-Host "Done: lib$RunnerName.so installed and registered (Dart $dartMinor)" -ForegroundColor Green
if (-not $KeepWork) {
    Write-Host "Toolchain kept at $WorkRoot (pass -KeepWork:$false to clean)" -ForegroundColor DarkGray
}
