#!/usr/bin/env bash
# setup_build_tools.sh — Install APK modification toolchain
# Run once in the terminal environment to set up all required build tools.
set -u

echo '=== Kelivo RevKit Build Tools Setup ==='

# ---------- apktool ----------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BUNDLED_APKTOOL="$REPO_ROOT/tools/apktool"

if [ -x "$BUNDLED_APKTOOL" ]; then
  echo "[✓] apktool (bundled) $($BUNDLED_APKTOOL --version 2>&1 | head -1)"
  # Add to PATH if not already
  if ! echo "$PATH" | grep -q "$REPO_ROOT/tools"; then
    export PATH="$REPO_ROOT/tools:$PATH"
    echo "    Added $REPO_ROOT/tools to PATH"
  fi
elif command -v apktool &>/dev/null; then
  echo "[✓] apktool (system) $(apktool --version 2>&1 | head -1)"
else
  echo '[*] Installing apktool via apt...'
  if apt-cache show apktool &>/dev/null 2>&1; then
    apt-get install -y apktool
  else
    echo '[✗] apktool not available. Please place apktool.jar in tools/ directory.'
    exit 1
  fi
  echo "[✓] apktool installed: $(apktool --version 2>&1 | head -1)"
fi

# ---------- zipalign ----------
if command -v zipalign &>/dev/null; then
  echo '[✓] zipalign found'
else
  echo '[!] zipalign not found. Install Android SDK build-tools or add to PATH.'
  exit 1
fi

# ---------- apksigner ----------
if command -v apksigner &>/dev/null; then
  echo "[✓] apksigner $(apksigner version 2>&1 | head -1)"
else
  echo '[!] apksigner not found. Install Android SDK build-tools or add to PATH.'
  exit 1
fi

# ---------- keytool ----------
if command -v keytool &>/dev/null; then
  echo '[✓] keytool found'
else
  echo '[!] keytool not found. Install JDK.'
  exit 1
fi

# ---------- Debug keystore ----------
DEBUG_KS="$HOME/.android/debug.jks"
if [ -f "$DEBUG_KS" ]; then
  echo "[✓] Debug keystore exists: $DEBUG_KS"
else
  echo '[*] Generating debug keystore...'
  mkdir -p "$(dirname "$DEBUG_KS")"
  keytool -genkeypair \
    -alias androiddebugkey \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Debug,O=Android,C=US" \
    -keystore "$DEBUG_KS" \
    -storepass android -keypass android \
    2>/dev/null
  echo "[✓] Debug keystore created: $DEBUG_KS"
fi

echo ''
echo '=== All build tools ready ==='
echo 'Pipeline: apktool d → edit → apktool b → zipalign → apksigner sign'
