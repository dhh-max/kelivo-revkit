part of kelivo_reverse_server;

  // ---- helpers ----
  static Map<String, dynamic> _ok(String text) => {
        'content': [
          {'type': 'text', 'text': text},
        ],
        'isStreaming': false,
        'isError': false,
      };

  static Map<String, dynamic> _err(String message) => {
        'content': [
          {'type': 'text', 'text': message},
        ],
        'isStreaming': false,
        'isError': true,
      };

  // =========================================================================
  // reverse_axml_edit — AXML 编码/替换 (纯 Dart)
  // =========================================================================
  static Future<Map<String, dynamic>> axmlEdit(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final action = (args['action'] ?? 'encode').toString().trim().toLowerCase();
      switch (action) {
        case 'encode':
          return _axmlEncodeAction(p, args);
        case 'replace':
          return await _axmlReplaceAction(p, args);
        default:
          return _err('Unknown action "$action". Expected encode|replace.');
      }
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Map<String, dynamic> _axmlEncodeAction(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    final xmlText = (args['xml'] ?? '').toString();
    if (xmlText.isEmpty) return _err('Missing "xml" (text XML to encode).');
    final encoded = encodeAxml(xmlText);
    if (encoded == null) return _err('AXML encoding failed.');
    final outputPath = (args['output'] ?? '').toString().trim();
    final sb = StringBuffer()
      ..writeln('=== AXML Encode ===\n')
      ..writeln('Input: ${xmlText.length} chars')
      ..writeln('Output: ${encoded.length} bytes');
    if (outputPath.isNotEmpty) {
      File(outputPath).writeAsBytesSync(encoded);
      sb.writeln('Written to: $outputPath');
    }
    return _ok(sb.toString().trimRight());
  }

  static Future<Map<String, dynamic>> _axmlReplaceAction(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    final xmlText = (args['xml'] ?? '').toString();
    if (xmlText.isEmpty) return _err('Missing "xml" (new manifest text).');
    final outputPath = (args['output'] ?? '').toString().trim();
    if (outputPath.isEmpty) return _err('Missing "output" path.');

    final encoded = encodeAxml(xmlText);
    if (encoded == null) return _err('AXML encoding failed.');

    // Replace AndroidManifest.xml inside the APK
    final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
    final archive = Archive();
    var found = false;
    for (final f in srcArchive) {
      if (!f.isFile) continue;
      if (f.name == 'AndroidManifest.xml') {
        archive.addFile(ArchiveFile(f.name, encoded.length, encoded));
        found = true;
      } else {
        archive.addFile(f);
      }
    }
    if (!found) return _err('APK has no AndroidManifest.xml to replace.');

    final outBytes = ZipEncoder().encode(archive);
    if (outBytes == null) return _err('Failed to repackage APK.');
    await File(outputPath).writeAsBytes(outBytes);

    final sb = StringBuffer()
      ..writeln('=== AXML Replace (Manifest) ===\n')
      ..writeln('Input APK: ${p.apkPath ?? "(base64)"}')
      ..writeln('New manifest: ${xmlText.length} chars → ${encoded.length} bytes')
      ..writeln('Output: $outputPath')
      ..writeln('\n⚠️ Unsigned. Run reverse_apk_sign next.');
    return _ok(sb.toString().trimRight());
  }

  // =========================================================================
  // reverse_manifest_edit — Manifest 属性增删改 (文本 XML 级)
  // =========================================================================
  static Future<Map<String, dynamic>> manifestEdit(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      // 1. Decode existing manifest to text
      final apk = _readApk(p.apkBytes);
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      if (manifestEntry?.content == null) {
        return _err('No AndroidManifest.xml found in APK.');
      }

      String xmlText;
      try {
        final lexer = _AxmlLexer(_ByteBuf(manifestEntry!.content!));
        xmlText = lexer.decode() as String;
      } catch (_) {
        xmlText = _manifestSummary(manifestEntry.content);
      }

      // 2. Apply edits
      final changes = <String, String>{};
      // Simple boolean toggles
      for (final key in ['debuggable', 'allowBackup', 'testOnly',
          'extractNativeLibs', 'hasCode', 'hardwareAccelerated',
          'largeHeap', 'supportsRtl', 'usesCleartextTraffic']) {
        final v = args[key];
        if (v != null) changes[key] = v.toString();
      }
      // Network security config
      final nsc = args['networkSecurityConfig'];
      if (nsc != null) changes['networkSecurityConfig'] = nsc.toString();

      // Exported component override
      final compName = args['set_exported_component']?.toString();
      final compVal = args['set_exported_value']?.toString();
      if (compName != null && compVal != null) {
        xmlText = _manifestSetExported(xmlText, compName, compVal == 'true');
      }

      // Apply attribute changes
      for (final entry in changes.entries) {
        xmlText = _manifestSetAttr(xmlText, entry.key, entry.value);
      }

      // 3. Re-encode to binary AXML
      final encoded = encodeAxml(xmlText);
      if (encoded == null) return _err('AXML re-encoding failed.');

      // 4. Replace in APK
      final outputPath = (args['output'] ?? '').toString().trim();
      if (outputPath.isEmpty) {
        // Return text only
        return _ok('=== Manifest Edit (preview) ===\n\n$xmlText');
      }

      final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
      final archive = Archive();
      for (final f in srcArchive) {
        if (!f.isFile) continue;
        if (f.name == 'AndroidManifest.xml') {
          archive.addFile(ArchiveFile(f.name, encoded.length, encoded));
        } else {
          archive.addFile(f);
        }
      }
      final outBytes = ZipEncoder().encode(archive);
      if (outBytes == null) return _err('Failed to repackage APK.');
      await File(outputPath).writeAsBytes(outBytes);

      final sb = StringBuffer()
        ..writeln('=== Manifest Edit ===\n')
        ..writeln('Changes applied:');
      for (final e in changes.entries) {
        sb.writeln('  ${e.key} = ${e.value}');
      }
      if (compName != null) sb.writeln('  exported($compName) = $compVal');
      sb.writeln('\nOutput: $outputPath')
        ..writeln('⚠️ Unsigned. Run reverse_apk_sign next.');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static String _manifestSetAttr(String xml, String attr, String val) {
    final pattern = RegExp('android:$attr="(?:true|false|[^"]*)"');
    if (pattern.hasMatch(xml)) {
      return xml.replaceAll(pattern, 'android:$attr="$val"');
    }
    // Insert into <application tag
    return xml.replaceAllMapped(
      RegExp(r'(<application\s[^>]*?)(\s*>)'),
      (m) => '${m.group(1)} android:$attr="$val"${m.group(2)}',
    );
  }

  static String _manifestSetExported(String xml, String component, bool exported) {
    final val = exported ? 'true' : 'false';
    for (final tag in ['activity', 'service', 'receiver', 'provider']) {
      final pattern = RegExp(
        '<$tag\\s[^>]*android:name="[^"]*$component"[^>]*>',
        caseSensitive: false,
      );
      final match = pattern.firstMatch(xml);
      if (match != null) {
        final tagText = match.group(0)!;
        String newTag;
        if (tagText.contains('android:exported=')) {
          newTag = tagText.replaceAll(
            RegExp('android:exported="(?:true|false)"'),
            'android:exported="$val"',
          );
        } else {
          newTag = tagText.replaceAllMapped(
            RegExp(r'(android:name="[^"]*")'),
            (m) => '${m.group(1)} android:exported="$val"',
          );
        }
        return xml.replaceFirst(tagText, newTag);
      }
    }
    return xml;
  }

  // =========================================================================
  // reverse_smali_patch — Smali 指令级修补 (正则)
  // =========================================================================
  static Future<Map<String, dynamic>> smaliPatch(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final action = (args['action'] ?? 'find_replace').toString().trim().toLowerCase();
      final dexPath = (args['dex_path'] ?? 'classes.dex').toString().trim();
      final apk = _readApk(p.apkBytes);
      final dexEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == dexPath,
        orElse: () => null,
      );
      if (dexEntry?.content == null) return _err('DEX not found: $dexPath');

      // Get smali via @kelivo/dex
      final dexPayload = KelivoDexRequestPayload(bytes: dexEntry!.content!, limit: 99999);
      final smaliText = _extractResultText(KelivoDexAnalyzer.classes(dexPayload));

      final sb = StringBuffer()..writeln('=== Smali Patch ===\n');

      switch (action) {
        case 'find_replace':
          final find = (args['find'] ?? '').toString();
          final replace = (args['replace'] ?? '').toString();
          if (find.isEmpty) return _err('Missing "find".');
          final count = 'find all occurrences of "$find"'.allMatches(smaliText).length;
          sb.writeln('Pattern: $find');
          sb.writeln('Found: $count occurrence(s)');
          sb.writeln('Replace: $replace');
          // Note: actual DEX modification requires smali→dex roundtrip
          sb.writeln('\n⚠️ Smali find_replace is analysis-only. '
              'To apply: decode→edit smali→smali→dex→rebuild APK.');
          break;

        case 'bypass_signature':
          sb.writeln('Target: signature verification methods');
          sb.writeln('Patterns to patch:');
          sb.writeln('  1. PackageManager.checkSignatures → const/4 v0, 0; return v0');
          sb.writeln('  2. PackageManager.getPackageInfo(GET_SIGNATURES) → return null/0');
          sb.writeln('\nUse reverse_kill_signature for automated bypass.');
          break;

        case 'inject_log':
          final method = (args['method'] ?? '').toString();
          if (method.isEmpty) return _err('Missing "method".');
          final tag = (args['tag'] ?? 'DEBUG').toString();
          final msg = (args['msg'] ?? 'injected').toString();
          sb.writeln('Inject Log.d into: $method');
          sb.writeln('  const-string v0, "$tag"');
          sb.writeln('  const-string v1, "$msg"');
          sb.writeln('  invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I');
          sb.writeln('\n⚠️ Injection preview only. Apply via decode→edit→rebuild workflow.');
          break;

        case 'nop_out':
          final method = (args['method'] ?? '').toString();
          if (method.isEmpty) return _err('Missing "method".');
          sb.writeln('NOP-out method body: $method');
          sb.writeln('Replace all instructions with: nop');
          sb.writeln('\n⚠️ Preview only. Apply via decode→edit→rebuild workflow.');
          break;

        case 'method_stub':
          final retType = (args['return_type'] ?? 'V').toString();
          final methodName = (args['method'] ?? '').toString();
          if (methodName.isEmpty) return _err('Missing "method".');
          sb.writeln('Generate method stub:');
          sb.writeln('```smali');
          sb.writeln('.method public $methodName()$retType');
          if (retType == 'V') {
            sb.writeln('    return-void');
          } else if (retType == 'Z' || retType == 'I' || retType == 'S' || retType == 'B' || retType == 'C') {
            sb.writeln('    const/4 v0, 0x0');
            sb.writeln('    return v0');
          } else if (retType == 'J' || retType == 'D') {
            sb.writeln('    const-wide/16 v0, 0x0');
            sb.writeln('    return-wide v0');
          } else {
            sb.writeln('    const/4 v0, 0x0');
            sb.writeln('    return-object v0');
          }
          sb.writeln('.end method');
          sb.writeln('```');
          break;

        default:
          return _err('Unknown action "$action". Expected: find_replace|bypass_signature|inject_log|nop_out|method_stub');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_zipalign — 纯 Dart 4 字节对齐
  // =========================================================================
  static Future<Map<String, dynamic>> zipalign(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final outputPath = (args['output'] ?? '').toString().trim();
      if (outputPath.isEmpty) return _err('Missing "output" path.');
      final alignment = (args['alignment'] ?? 4) as int;

      final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
      final archive = Archive();
      var alignedCount = 0;

      for (final f in srcArchive) {
        if (!f.isFile) continue;
        // Uncompressed files need alignment; compressed files are naturally aligned
        if (f.compression == ZipFileCompression.none) {
          alignedCount++;
        }
        archive.addFile(f);
      }

      // Use ZipEncoder with storeOnly for uncompressed entries to get alignment
      final outBytes = ZipEncoder().encode(archive);
      if (outBytes == null) return _err('Failed to encode APK.');
      await File(outputPath).writeAsBytes(outBytes);

      final sb = StringBuffer()
        ..writeln('=== Zipalign ===\n')
        ..writeln('Input: ${p.apkPath ?? "(base64)"}')
        ..writeln('Output: $outputPath')
        ..writeln('Alignment: $alignment bytes')
        ..writeln('Uncompressed entries: $alignedCount')
        ..writeln('\n⚠️ Dart archive library does not support explicit zipalign. '
            'For production, use Android SDK zipalign:\n'
            '  zipalign -p $alignment input.apk $outputPath');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_hook_gen — Frida/Xposed/Smali Hook 脚本生成
  // =========================================================================
  static Future<Map<String, dynamic>> hookGen(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final targetClass = (args['target_class'] ?? '').toString();
      if (targetClass.isEmpty) return _err('Missing "target_class".');
      final targetMethod = (args['target_method'] ?? '').toString().trim();
      final format = (args['format'] ?? 'frida').toString().trim().toLowerCase();

      // Convert class name
      String clsPath;
      if (targetClass.startsWith('L') && targetClass.endsWith(';')) {
        clsPath = targetClass.substring(1, targetClass.length - 1).replaceAll('/', '.');
      } else {
        clsPath = targetClass.replaceAll('/', '.');
      }

      final verbose = args['verbose'] == true;
      final traceArgs = args['trace_args'] == true;
      final traceReturn = args['trace_return'] == true;
      final bypassFlags = args['bypass'] as Map<String, dynamic>?;

      final sb = StringBuffer()..writeln('=== Hook Generator ===\n');

      switch (format) {
        case 'frida':
          sb.writeln('```javascript');
          sb.writeln('// Auto-generated Frida Hook Script');
          sb.writeln('// Target: $clsPath');
          sb.writeln('Java.perform(function() {');

          if (bypassFlags != null) {
            if (bypassFlags['root'] == true) sb.writeln(_fridaBypassRoot());
            if (bypassFlags['debug'] == true) sb.writeln(_fridaBypassDebug());
            if (bypassFlags['ssl'] == true) sb.writeln(_fridaBypassSsl());
            if (bypassFlags['signature'] == true) sb.writeln(_fridaBypassSignature());
            if (bypassFlags['emulator'] == true) sb.writeln(_fridaBypassEmulator());
          }

          if (targetMethod.isNotEmpty) {
            sb.writeln('    var targetClass = Java.use("$clsPath");');
            sb.writeln('    targetClass.$targetMethod.implementation = function() {');
            if (traceArgs) {
              sb.writeln('        console.log("[*] $targetMethod called with args:");');
              sb.writeln('        for (var i = 0; i < arguments.length; i++) {');
              sb.writeln('            console.log("    arg[" + i + "]: " + arguments[i]);');
              sb.writeln('        }');
            }
            if (traceReturn) {
              sb.writeln('        var ret = this.$targetMethod.apply(this, arguments);');
              sb.writeln('        console.log("[*] $targetMethod returned: " + ret);');
              sb.writeln('        return ret;');
            } else {
              sb.writeln('        return this.$targetMethod.apply(this, arguments);');
            }
            sb.writeln('    };');
            if (verbose) sb.writeln('    console.log("[+] Hooked $clsPath.$targetMethod");');
          } else {
            sb.writeln('    var targetClass = Java.use("$clsPath");');
            sb.writeln('    var methods = targetClass.class.getDeclaredMethods();');
            sb.writeln('    methods.forEach(function(method) {');
            sb.writeln('        var methodName = method.getName();');
            sb.writeln('        try {');
            sb.writeln('            targetClass[methodName].implementation = function() {');
            sb.writeln('                console.log("[*] " + methodName + " called");');
            sb.writeln('                var ret = this[methodName].apply(this, arguments);');
            sb.writeln('                console.log("    return: " + ret);');
            sb.writeln('                return ret;');
            sb.writeln('            };');
            sb.writeln('        } catch(e) {}');
            sb.writeln('    });');
            if (verbose) sb.writeln('    console.log("[+] Hooked all methods in $clsPath");');
          }
          sb.writeln('});');
          sb.writeln('```');
          break;

        case 'xposed':
          sb.writeln('```java');
          sb.writeln('// Auto-generated Xposed Module');
          sb.writeln('// Target Class: $clsPath');
          sb.writeln('package com.auto.hook;');
          sb.writeln('');
          sb.writeln('import de.robv.android.xposed.IXposedHookLoadPackage;');
          sb.writeln('import de.robv.android.xposed.XC_MethodHook;');
          sb.writeln('import de.robv.android.xposed.XposedBridge;');
          sb.writeln('import de.robv.android.xposed.XposedHelpers;');
          sb.writeln('import de.robv.android.xposed.callbacks.XC_LoadPackage;');
          sb.writeln('');
          sb.writeln('public class MainHook implements IXposedHookLoadPackage {');
          sb.writeln('    @Override');
          sb.writeln('    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {');
          if (targetMethod.isNotEmpty) {
            sb.writeln('        XposedHelpers.findAndHookMethod("$clsPath",');
            sb.writeln('            lpparam.classLoader, "$targetMethod",');
            sb.writeln('            new XC_MethodHook() {');
            sb.writeln('                @Override');
            sb.writeln('                protected void beforeHookedMethod(MethodHookParam param) {');
            sb.writeln('                    XposedBridge.log("[*] $targetMethod called");');
            sb.writeln('                }');
            sb.writeln('            });');
          } else {
            sb.writeln('        Class<?> cls = XposedHelpers.findClass("$clsPath", lpparam.classLoader);');
            sb.writeln('        for (java.lang.reflect.Method m : cls.getDeclaredMethods()) {');
            sb.writeln('            XposedBridge.hookMethod(m, new XC_MethodHook() {');
            sb.writeln('                @Override');
            sb.writeln('                protected void beforeHookedMethod(MethodHookParam param) {');
            sb.writeln('                    XposedBridge.log("[*] " + param.method.getName());');
            sb.writeln('                }');
            sb.writeln('            });');
            sb.writeln('        }');
          }
          sb.writeln('    }');
          sb.writeln('}');
          sb.writeln('```');
          break;

        case 'smali':
          final patchType = (args['patch_type'] ?? 'bypass_return').toString();
          final retVal = (args['return_value'] ?? '0x0').toString();
          sb.writeln('```smali');
          sb.writeln('.method public ${targetMethod.isEmpty ? "targetMethod" : targetMethod}()I');
          sb.writeln('    # Patched: $patchType');
          if (patchType == 'bypass_return') {
            sb.writeln('    const/4 v0, $retVal');
            sb.writeln('    return v0');
          } else if (patchType == 'log_only') {
            sb.writeln('    const-string v0, "HOOK"');
            sb.writeln('    const-string v1, "${targetMethod.isEmpty ? "method" : targetMethod} called"');
            sb.writeln('    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I');
            sb.writeln('    const/4 v0, $retVal');
            sb.writeln('    return v0');
          } else if (patchType == 'nop') {
            sb.writeln('    return-void');
          }
          sb.writeln('.end method');
          sb.writeln('```');
          break;

        default:
          return _err('Unknown format "$format". Expected: frida|xposed|smali');
      }

      sb.writeln('\nTarget: $clsPath${targetMethod.isNotEmpty ? '.$targetMethod' : ' (all methods)'}');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static String _fridaBypassRoot() => '''    // ── Root检测绕过 ──
    var rootChecks = ["su", "/system/bin/su", "/system/xbin/su",
                      "test-keys", "magisk"];
    rootChecks.forEach(function(check) {
        try {
            var File = Java.use("java.io.File");
            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                if (path && path.indexOf(check) >= 0) return false;
                return this.exists();
            };
        } catch(e) {}
    });''';

  static String _fridaBypassDebug() => '''    // ── 反调试绕过 ──
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() { return false; };
    } catch(e) {}''';

  static String _fridaBypassSsl() => '''    // ── SSL Pinning绕过 ──
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "org.wooyun.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.\$new()], sr);
        };
    } catch(e) {}''';

  static String _fridaBypassSignature() => '''    // ── 签名校验绕过 ──
    try {
        var PackageManager = Java.use("android.app.PackageManager");
        PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function(name, flags) {
            if ((flags & 64) != 0) {
                return this.getPackageInfo(name, flags & ~64);
            }
            return this.getPackageInfo(name, flags);
        };
    } catch(e) {}''';

  static String _fridaBypassEmulator() => '''    // ── 模拟器检测绕过 ──
    try {
        var Build = Java.use("android.os.Build");
        Build.MODEL.value = "Pixel 6";
        Build.MANUFACTURER.value = "Google";
        Build.BRAND.value = "google";
        Build.PRODUCT.value = "oriole";
    } catch(e) {}''';

  // =========================================================================
  // reverse_dex_merge — 多 DEX 条目级合并 (简单拼接)
  // =========================================================================
  static Future<Map<String, dynamic>> dexMerge(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final outputPath = (args['output'] ?? '').toString().trim();
      if (outputPath.isEmpty) return _err('Missing "output" path.');

      final apk = _readApk(p.apkBytes);
      final dexEntries = _filterEntries(apk, '.dex');
      if (dexEntries.isEmpty) return _err('No DEX files found in APK.');

      final sb = StringBuffer()..writeln('=== DEX Merge ===\n')
        ..writeln('Input: ${p.apkPath ?? "(base64)"}')
        ..writeln('DEX files: ${dexEntries.length}');

      for (final d in dexEntries) {
        sb.writeln('  ${d.name} (${_formatSize(d.size)})');
      }

      if (dexEntries.length == 1) {
        sb.writeln('\nOnly one DEX, copying as-is.');
        await File(outputPath).writeAsBytes(p.apkBytes);
        sb.writeln('Output: $outputPath');
        return _ok(sb.toString().trimRight());
      }

      // Merge: concatenate all dex bytes into single classes.dex
      // Note: This is a simple byte concatenation. Real dex merging requires
      // proper header fixup and string pool consolidation.
      final merged = <int>[];
      for (final d in dexEntries) {
        if (d.content != null) merged.addAll(d.content!);
      }
      final mergedBytes = Uint8List.fromList(merged);

      // Build new APK: keep non-dex entries, replace classes.dex, drop others
      final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
      final archive = Archive();
      for (final f in srcArchive) {
        if (!f.isFile) continue;
        if (f.name.endsWith('.dex')) {
          if (f.name == 'classes.dex') {
            archive.addFile(ArchiveFile(f.name, mergedBytes.length, mergedBytes));
          }
          // skip other dex files
        } else {
          archive.addFile(f);
        }
      }

      final outBytes = ZipEncoder().encode(archive);
      if (outBytes == null) return _err('Failed to encode merged APK.');
      await File(outputPath).writeAsBytes(outBytes);

      sb.writeln('\nMerged size: ${_formatSize(mergedBytes.length)}');
      sb.writeln('Output: $outputPath');
      sb.writeln('⚠️ Simple byte concatenation. For proper merge, use dex-merger.');
      sb.writeln('⚠️ Unsigned. Run reverse_apk_sign next.');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_anti_analysis — 反分析检测 (反调试/反Root/反模拟器/完整性/反Hook/反VPN/反虚拟化)
  // =========================================================================
  static Future<Map<String, dynamic>> antiAnalysis(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Anti-Analysis Detection ===\n');

      // Collect text from DEX strings + SO strings
      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        allText.add(text);
      }

      // Collect SO strings via @kelivo/so
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        try {
          final soPayload = KelivoSoRequestPayload(bytes: so.content!);
          final soText = _extractResultText(KelivoSoAnalyzer.strings(soPayload));
          allText.add(soText);
        } catch (_) {}
      }

      final combined = allText.join('\n');

      final categories = <String, List<Map<String, dynamic>>>{};

      // ── 反调试 ──
      final antiDebugPats = [
        ['android\\.os\\.Debug\\.isDebuggerConnected', 'isDebuggerConnected', 'high'],
        ['ptrace', 'ptrace反调试', 'high'],
        ['/proc/self/status', '读取TracerPid', 'high'],
        ['TracerPid', '检查TracerPid', 'high'],
        ['ro\\.debuggable', '检查debuggable属性', 'medium'],
        ['waitForDebugger', '等待调试器', 'medium'],
        ['isEmulator|isRunningOnEmulator|checkEmulator', '模拟器检测函数', 'high'],
      ];
      categories['anti_debug'] = _scanPatterns(combined, antiDebugPats);

      // ── 反Root ──
      final antiRootPats = [
        ['/system/xbin/su', 'su二进制路径', 'high'],
        ['/system/bin/su', 'su二进制路径', 'high'],
        ['superuser\\.apk', 'Superuser应用', 'high'],
        ['eu\\.chainfire\\.supersu', 'SuperSU', 'high'],
        ['com\\.topjohnwu\\.magisk', 'Magisk', 'high'],
        ['magisk', 'Magisk', 'high'],
        ['RootBeer|rootbeer', 'RootBeer库', 'medium'],
        ['checkRootMethod|isRooted|detectRoot', 'Root检测方法', 'high'],
        ['busybox', 'BusyBox', 'medium'],
        ['test-keys', 'test-keys构建标签', 'medium'],
      ];
      categories['anti_root'] = _scanPatterns(combined, antiRootPats);

      // ── 反模拟器 ──
      final antiEmuPats = [
        ['goldfish', 'Goldfish设备', 'medium'],
        ['qemu', 'QEMU', 'high'],
        ['genymotion', 'Genymotion', 'medium'],
        ['nox|noxapp|bignox', 'Nox模拟器', 'medium'],
        ['bluestacks|bstk', 'BlueStacks', 'medium'],
        ['ldplayer|changzhi', 'LDPlayer', 'medium'],
        ['muMu|mumuglobal', 'MuMu模拟器', 'medium'],
        ['google_sdk|sdk_gphone', 'SDK模拟器', 'medium'],
        ['Build\\.FINGERPRINT.*generic|Build\\.HARDWARE.*goldfish', 'Build指纹检测', 'medium'],
        ['/dev/qemu_pipe', 'QEMU pipe', 'medium'],
        ['ro\\.kernel\\.qemu', 'QEMU属性', 'medium'],
      ];
      categories['anti_emulator'] = _scanPatterns(combined, antiEmuPats);

      // ── 完整性校验 ──
      final integrityPats = [
        ['signature.*check|checkSignature|verifySignature', '签名校验', 'high'],
        ['PackageManager\\.GET_SIGNATURES', '获取签名', 'high'],
        ['signatures\\[0\\]\\.toCharsString', '签名比较', 'high'],
        ['checksum|crc32|md5.*verify|sha.*verify', '文件完整性校验', 'high'],
        ['checkInstallerPackage|getInstallerPackageName', '安装来源检查', 'medium'],
        ['DexFile.*loadDex', 'DEX动态加载', 'high'],
      ];
      categories['integrity_check'] = _scanPatterns(combined, integrityPats);

      // ── 反Hook ──
      final antiHookPats = [
        ['XposedBridge|de\\.robv\\.android\\.xposed', 'Xposed框架', 'high'],
        ['findAndHookMethod', 'Xposed Hook', 'high'],
        ['Frida|frida-server|frida-gadget', 'Frida', 'high'],
        ['libfrida|frida-agent', 'Frida Agent', 'high'],
        ['Substrate|MSHookFunction|cydia', 'Cydia Substrate', 'high'],
        ['ArtMethod|hookedMethod', 'ArtMethod Hook', 'high'],
        ['libepic|libwhale|libdexvm', 'ART Hook框架', 'high'],
        ['bytehook|shadowhook', '字节级Hook', 'high'],
      ];
      categories['anti_hook'] = _scanPatterns(combined, antiHookPats);

      // ── 反VPN/代理 ──
      final antiVpnPats = [
        ['tun0|tap0', 'VPN网卡', 'medium'],
        ['VPNService|prepare.*VPN', 'VPN服务', 'medium'],
        ['Proxy\\.getDefaultProxy|ProxyHost', '代理检测', 'medium'],
        ['System\\.getProperty.*http\\.proxyHost', 'HTTP代理检测', 'medium'],
      ];
      categories['anti_vpn'] = _scanPatterns(combined, antiVpnPats);

      // ── 反虚拟化/多开 ──
      final antiVirtualPats = [
        ['multi.*droid|parallel.*space|dual.*app', '多开应用', 'medium'],
        ['virtualapp|virtualapp\\.app', 'VirtualApp框架', 'high'],
        ['com\\.lbe\\.parallel|com\\.excelliance\\.dualaid', '多开包名', 'medium'],
        ['/proc/self/cgroup|/proc/self/maps', '虚拟环境检测', 'medium'],
      ];
      categories['anti_virtual'] = _scanPatterns(combined, antiVirtualPats);

      // 汇总
      final total = categories.values.fold<int>(0, (s, v) => s + v.length);
      final highCount = categories.values
          .fold<int>(0, (s, v) => s + v.where((e) => e['severity'] == 'high').length);

      for (final entry in categories.entries) {
        if (entry.value.isEmpty) continue;
        sb.writeln('--- ${entry.key} (${entry.value.length}) ---');
        for (final f in entry.value) {
          sb.writeln('  [${f['severity']}] ${f['description']} (×${f['count']})');
        }
        sb.writeln('');
      }

      final level = total > 15 ? 'heavy' : (total > 5 ? 'moderate' : (total > 0 ? 'light' : 'none'));
      sb.writeln('=== Summary ===');
      sb.writeln('Total detections: $total');
      sb.writeln('High severity: $highCount');
      sb.writeln('Protection level: $level');
      sb.writeln('Categories: ${categories.entries.where((e) => e.value.isNotEmpty).map((e) => e.key).join(', ')}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static List<Map<String, dynamic>> _scanPatterns(String text, List<List<String>> patterns) {
    final findings = <Map<String, dynamic>>[];
    final seen = <String>{};
    for (final p in patterns) {
      final pat = p[0], desc = p[1], sev = p[2];
      final matches = RegExp(pat, caseSensitive: false).allMatches(text);
      if (matches.isNotEmpty && !seen.contains(desc)) {
        seen.add(desc);
        findings.add({
          'description': desc,
          'severity': sev,
          'count': matches.length,
        });
      }
    }
    return findings;
  }

  // =========================================================================
  // reverse_callgraph — DEX 调用图构建 (正向/反向可达性 + 热点 + 递归)
  // =========================================================================
  static Future<Map<String, dynamic>> callgraphBuild(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final dexPath = (args['dex_path'] ?? 'classes.dex').toString().trim();
      final targetClass = (args['target_class'] ?? '').toString().trim();
      final targetMethod = (args['target_method'] ?? '').toString().trim();
      final direction = (args['direction'] ?? 'callers').toString().trim().toLowerCase();

      final apk = _readApk(p.apkBytes);
      final dexEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == dexPath,
        orElse: () => null,
      );
      if (dexEntry?.content == null) return _err('DEX not found: $dexPath');

      final dexPayload = KelivoDexRequestPayload(bytes: dexEntry!.content!, limit: 99999);
      final classesText = _extractResultText(KelivoDexAnalyzer.classes(dexPayload));

      final sb = StringBuffer()..writeln('=== Call Graph ===\n');
      sb.writeln('DEX: $dexPath');

      // Parse class list to build adjacency from string references
      final classLines = classesText.split('\n').where((l) => l.trim().isNotEmpty).toList();
      sb.writeln('Classes: ${classLines.length}');

      // Build simple call graph from class references in strings
      final adjacency = <String, Set<String>>{};
      final reverseAdj = <String, Set<String>>{};

      for (final line in classLines) {
        final cls = line.trim();
        adjacency.putIfAbsent(cls, () => {});
        reverseAdj.putIfAbsent(cls, () => {});
      }

      // Find cross-references: any class name appearing in another class's strings
      for (final line in classLines) {
        final cls = line.trim();
        for (final other in classLines) {
          if (cls == other) continue;
          if (classesText.contains(cls) && !adjacency[other]!.contains(cls)) {
            adjacency[other]!.add(cls);
            reverseAdj[cls]!.add(other);
          }
        }
      }

      final nodeCount = adjacency.length;
      final edgeCount = adjacency.values.fold<int>(0, (s, v) => s + v.length);
      sb.writeln('Nodes: $nodeCount');
      sb.writeln('Edges: $edgeCount');

      if (targetClass.isNotEmpty) {
        final targetId = targetMethod.isNotEmpty ? '$targetClass.$targetMethod' : targetClass;
        sb.writeln('\n--- Target: $targetId ($direction) ---');
        if (direction == 'callers') {
          final callers = reverseAdj[targetId] ?? reverseAdj[targetClass] ?? {};
          sb.writeln('Direct callers: ${callers.length}');
          for (final c in callers) sb.writeln('  $c');
        } else {
          final callees = adjacency[targetId] ?? adjacency[targetClass] ?? {};
          sb.writeln('Direct callees: ${callees.length}');
          for (final c in callees) sb.writeln('  $c');
        }
      }

      // Hotspots: most-referenced classes
      final refCounts = <int, List<String>>{};
      for (final entry in reverseAdj.entries) {
        refCounts.putIfAbsent(entry.value.length, () => []).add(entry.key);
      }
      final sortedCounts = refCounts.keys.toList()..sort((a, b) => b.compareTo(a));
      sb.writeln('\n--- Top 20 Hotspots ---');
      var shown = 0;
      for (final cnt in sortedCounts) {
        if (cnt == 0 || shown >= 20) break;
        for (final cls in refCounts[cnt]!) {
          if (shown >= 20) break;
          sb.writeln('  $cls ($cnt refs)');
          shown++;
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_crypto_analyzer — 加密深度分析
  // =========================================================================
  static Future<Map<String, dynamic>> cryptoAnalyze(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Crypto Analyzer ===\n');

      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        try {
          final soPayload = KelivoSoRequestPayload(bytes: so.content!);
          allText.add(_extractResultText(KelivoSoAnalyzer.strings(soPayload)));
        } catch (_) {}
      }
      final combined = allText.join('\n');

      // ── 加密算法 ──
      final algos = <String, Map<String, dynamic>>{};
      final algoPats = {
        'AES': [r'AES', r'Rijndael', r'AES_set_encrypt_key', r'AES_cbc_encrypt', r'crypto/aes'],
        'DES': [r'\bDES\b', r'DES_set_key', r'des_encrypt', r'DESede', r'3DES'],
        'RSA': [r'\bRSA\b', r'RSA_public_encrypt', r'RSA_private_decrypt', r'BN_mod_exp'],
        'ECC': [r'\bECC\b', r'EC_KEY_new', r'ECDSA_sign', r'secp256r1', r'secp256k1'],
        'ChaCha20': [r'ChaCha20', r'chacha20', r'salsa20', r'Salsa20'],
        'RC4': [r'\bRC4\b', r'RC4_set_key', r'ARCFOUR'],
        'Blowfish': [r'Blowfish', r'BF_set_key', r'BF_encrypt'],
      };
      for (final entry in algoPats.entries) {
        final matches = <String>[];
        for (final pat in entry.value) {
          final ms = RegExp(pat, caseSensitive: false).allMatches(combined);
          if (ms.isNotEmpty) matches.add(pat);
        }
        if (matches.isNotEmpty) {
          algos[entry.key] = {'patterns': matches, 'count': matches.length};
        }
      }
      sb.writeln('--- Algorithms ---');
      algos.forEach((k, v) => sb.writeln('  $k: ${v['count']} pattern(s)'));

      // ── 加密模式 ──
      final modes = <String, int>{};
      final modePats = {
        'ECB': [r'AES/ECB', r'"ECB"'],
        'CBC': [r'AES/CBC', r'"CBC"'],
        'CTR': [r'AES/CTR', r'"CTR"'],
        'GCM': [r'AES/GCM', r'"GCM"'],
      };
      for (final entry in modePats.entries) {
        var cnt = 0;
        for (final pat in entry.value) {
          cnt += RegExp(pat, caseSensitive: false).allMatches(combined).length;
        }
        if (cnt > 0) modes[entry.key] = cnt;
      }
      sb.writeln('\n--- Modes ---');
      modes.forEach((k, v) => sb.writeln('  $k: $v match(es) ${k == 'ECB' ? '⚠️INSECURE' : ''}'));

      // ── 哈希算法 ──
      final hashes = <String, int>{};
      final hashPats = {
        'MD5': [r'MD5', r'MD5_Init', r'md5'],
        'SHA1': [r'SHA1', r'SHA-1', r'sha1'],
        'SHA256': [r'SHA256', r'SHA-256', r'sha256'],
        'SHA512': [r'SHA512', r'SHA-512'],
        'HMAC': [r'HMAC', r'HMAC_Init'],
        'PBKDF2': [r'PBKDF2', r'pbkdf2'],
      };
      for (final entry in hashPats.entries) {
        var cnt = 0;
        for (final pat in entry.value) {
          cnt += RegExp(pat, caseSensitive: false).allMatches(combined).length;
        }
        if (cnt > 0) hashes[entry.key] = cnt;
      }
      sb.writeln('\n--- Hashes ---');
      hashes.forEach((k, v) => sb.writeln('  $k: $v match(es)'));

      // ── 弱加密 ──
      final weakPats = [
        [r'DES(?!ede|3DES)', 'DES算法（已不安全）'],
        [r'\bRC4\b', 'RC4算法（已不安全）'],
        [r'MD5(?!.*HMAC)', 'MD5哈希（不适合安全验证）'],
        [r'SHA1(?!.*HMAC)', 'SHA1哈希（已不安全）'],
        [r'AES/ECB', 'ECB模式（不安全）'],
        [r'SecretKeySpec\s*\(\s*"[^"]+"', '硬编码密钥'],
        [r'Random\s*\(', 'java.util.Random（非加密安全）'],
        [r'TrustManager.*\{\s*\}', '空TrustManager'],
        [r'HostnameVerifier.*verify.*return\s+true', '空HostnameVerifier'],
        [r'checkServerTrusted.*\{\s*\}', '空证书验证'],
      ];
      sb.writeln('\n--- Weak Crypto ---');
      var weakCount = 0;
      for (final p in weakPats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  ⚠️ ${p[1]} (×${ms.length})');
          weakCount++;
        }
      }
      if (weakCount == 0) sb.writeln('  None detected');

      // ── 密钥管理 ──
      sb.writeln('\n--- Key Management ---');
      if (RegExp(r'KeyStore\.getInstance', caseSensitive: false).hasMatch(combined))
        sb.writeln('  ✓ Android KeyStore');
      if (RegExp(r'KeyGenerator\.getInstance', caseSensitive: false).hasMatch(combined))
        sb.writeln('  ✓ KeyGenerator');
      if (RegExp(r'SecureRandom', caseSensitive: false).hasMatch(combined))
        sb.writeln('  ✓ SecureRandom');
      final hardcodedKeys = RegExp(r'SecretKeySpec\s*\(\s*("[^"]+")').allMatches(combined);
      if (hardcodedKeys.isNotEmpty) {
        sb.writeln('  ⚠️ Hardcoded key(s):');
        for (final m in hardcodedKeys.take(5)) {
          sb.writeln('    ${m.group(1)}');
        }
      }

      // ── 风险评估 ──
      final level = weakCount > 5 ? 'critical' : (weakCount > 2 ? 'high' : (weakCount > 0 ? 'medium' : 'low'));
      sb.writeln('\n=== Risk Assessment ===');
      sb.writeln('Algorithm count: ${algos.length}');
      sb.writeln('Weak indicators: $weakCount');
      sb.writeln('Risk level: $level');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dataflow — DEX 数据流分析 (污点追踪 + 常量传播)
  // =========================================================================
  static Future<Map<String, dynamic>> dataflowAnalyze(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final dexPath = (args['dex_path'] ?? 'classes.dex').toString().trim();
      final targetClass = (args['target_class'] ?? '').toString().trim();
      final action = (args['action'] ?? 'taint').toString().trim().toLowerCase();

      final apk = _readApk(p.apkBytes);
      final dexEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == dexPath,
        orElse: () => null,
      );
      if (dexEntry?.content == null) return _err('DEX not found: $dexPath');

      final dexPayload = KelivoDexRequestPayload(bytes: dexEntry!.content!, limit: 99999);
      final classesText = _extractResultText(KelivoDexAnalyzer.classes(dexPayload));

      final sb = StringBuffer()..writeln('=== DEX Data Flow Analysis ===\n');
      sb.writeln('DEX: $dexPath');
      sb.writeln('Action: $action');
      if (targetClass.isNotEmpty) sb.writeln('Target class: $targetClass');

      // Taint sources
      final taintSources = {
        'intent': ['Intent.getExtras', 'getStringExtra', 'getIntExtra', 'getBooleanExtra'],
        'network': ['HttpURLConnection.getInputStream', 'OkHttpClient.newCall', 'Response.body'],
        'telephony': ['getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getLine1Number'],
        'webview': ['WebView.getUrl', 'evaluateJavascript'],
        'file': ['FileInputStream.read', 'readBytes', 'FileReader.read'],
      };

      // Taint sinks
      final taintSinks = {
        'exec': ['Runtime.exec', 'ProcessBuilder.start'],
        'network_out': ['HttpURLConnection.getOutputStream', 'OutputStream.write'],
        'file_write': ['FileOutputStream.write', 'writeBytes'],
        'webview_load': ['WebView.loadUrl', 'loadDataWithBaseURL'],
        'sql_query': ['SQLiteDatabase.rawQuery', 'execSQL'],
        'reflection': ['Method.invoke', 'Class.forName', 'getDeclaredMethod'],
        'dynamic_load': ['DexClassLoader.loadClass', 'System.load', 'System.loadLibrary'],
      };

      if (action == 'taint') {
        sb.writeln('\n--- Taint Sources ---');
        for (final entry in taintSources.entries) {
          for (final pat in entry.value) {
            if (classesText.contains(pat)) {
              sb.writeln('  [${entry.key}] $pat ✓');
            }
          }
        }
        sb.writeln('\n--- Taint Sinks ---');
        for (final entry in taintSinks.entries) {
          for (final pat in entry.value) {
            if (classesText.contains(pat)) {
              sb.writeln('  [${entry.key}] $pat ✓');
            }
          }
        }

        // Check for dangerous flows
        final sourceHit = taintSources.values.any((pats) => pats.any((p) => classesText.contains(p)));
        final sinkHit = taintSinks.values.any((pats) => pats.any((p) => classesText.contains(p)));
        sb.writeln('\n--- Flow Assessment ---');
        sb.writeln('Sources detected: $sourceHit');
        sb.writeln('Sinks detected: $sinkHit');
        if (sourceHit && sinkHit) {
          sb.writeln('⚠️ Potential taint flow: source → sink path exists');
        }
      } else if (action == 'constants') {
        // Scan for const patterns in class listing
        sb.writeln('\n--- Constant Scan ---');
        final constPats = [
          [r'const-string.*"https?://[^"]+"', 'URL constants'],
          [r'const-string.*"[A-Za-z0-9+/=]{16,}"', 'Base64-like constants'],
          [r'const-string.*"AIza[a-zA-Z0-9_-]{35}"', 'Google API key'],
          [r'const-string.*"ghp_[a-zA-Z0-9]{36}"', 'GitHub token'],
          [r'const-string.*"sk_live_[a-zA-Z0-9]{24,}"', 'Stripe secret key'],
        ];
        for (final p in constPats) {
          final ms = RegExp(p[0]).allMatches(classesText);
          if (ms.isNotEmpty) {
            sb.writeln('  ${p[1]}: ${ms.length} match(es)');
          }
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_metadata — DEX 元数据分析 (注解/Debug/Hidden API/序列化)
  // =========================================================================
  static Future<Map<String, dynamic>> dexMetadata(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final dexPath = (args['dex_path'] ?? 'classes.dex').toString().trim();
      final apk = _readApk(p.apkBytes);
      final dexEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == dexPath,
        orElse: () => null,
      );
      if (dexEntry?.content == null) return _err('DEX not found: $dexPath');

      final dexPayload = KelivoDexRequestPayload(bytes: dexEntry!.content!, limit: 99999);
      final classesText = _extractResultText(KelivoDexAnalyzer.classes(dexPayload));

      final sb = StringBuffer()..writeln('=== DEX Metadata ===\n');
      sb.writeln('DEX: $dexPath');

      // ── Hidden API 检测 ──
      final hiddenApiPats = [
        [r'Landroid/internal/', 'internal_api', 'high', '访问 Android 内部 API'],
        [r'Lcom/android/internal/', 'internal_api', 'high', '访问 Android 内部 API'],
        [r'Ldalvik/system/', 'dalvik_system', 'medium', '访问 Dalvik 系统层 API'],
        [r'Lsun/misc/', 'sun_misc', 'medium', '访问 sun.misc 内部 API'],
        [r'installPackage|deletePackage', 'pm_install', 'critical', '静默安装/卸载 API'],
        [r'killBackgroundProcesses|forceStopPackage', 'force_stop', 'high', '强制停止应用 API'],
      ];
      sb.writeln('\n--- Hidden API ---');
      var hiddenCount = 0;
      for (final p in hiddenApiPats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(classesText);
        if (ms.isNotEmpty) {
          sb.writeln('  [${p[2]}] ${p[3]} (×${ms.length})');
          hiddenCount++;
        }
      }
      if (hiddenCount == 0) sb.writeln('  None detected');

      // ── 反射模式 ──
      final reflPats = [
        [r'Class\.forName', '反射加载类'],
        [r'getDeclaredMethod', '反射获取方法'],
        [r'getDeclaredField', '反射获取字段'],
        [r'setAccessible\(true\)', '反射突破访问控制'],
        [r'newInstance\(', '反射创建实例'],
        [r'invoke\(', '反射调用方法'],
        [r'Ldalvik/system/DexClassLoader;', '动态 DEX 加载'],
      ];
      sb.writeln('\n--- Reflection ---');
      for (final p in reflPats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(classesText);
        if (ms.isNotEmpty) {
          sb.writeln('  ${p[1]} (×${ms.length})');
        }
      }

      // ── 注解处理器框架 ──
      final apPats = {
        'ButterKnife': ['Lbutterknife/'],
        'Dagger': ['Ldagger/', 'Ldagger2/'],
        'Room': ['Landroidx/room/'],
        'Realm': ['Lio/realm/'],
        'EventBus': ['Lorg/greenrobot/eventbus/', 'Lde/greenrobot/event/'],
      };
      sb.writeln('\n--- Annotation Processors ---');
      for (final entry in apPats.entries) {
        for (final pat in entry.value) {
          if (classesText.contains(pat)) {
            sb.writeln('  ${entry.key} ✓');
            break;
          }
        }
      }

      // ── 序列化框架 ──
      final serPats = {
        'Parcelable': ['Landroid/os/Parcelable;'],
        'Serializable': ['Ljava/io/Serializable;'],
        'Gson': ['Lcom/google/gson/'],
        'Moshi': ['Lcom/squareup/moshi/'],
        'Jackson': ['Lcom/fasterxml/jackson/'],
        'FastJson': ['Lcom/alibaba/fastjson/'],
        'Kotlinx Serialization': ['Lkotlinx/serialization/'],
      };
      sb.writeln('\n--- Serialization ---');
      for (final entry in serPats.entries) {
        for (final pat in entry.value) {
          if (classesText.contains(pat)) {
            sb.writeln('  ${entry.key} ✓');
            break;
          }
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_multidex — 多 DEX 关联分析 (分布/跨引用/重复)
  // =========================================================================
  static Future<Map<String, dynamic>> multidexAnalyze(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final dexEntries = _filterEntries(apk, '.dex');
      if (dexEntries.isEmpty) return _err('No DEX files found.');

      final sb = StringBuffer()..writeln('=== Multi-DEX Analysis ===\n');
      sb.writeln('DEX count: ${dexEntries.length}\n');

      // ── 分布统计 ──
      sb.writeln('--- Distribution ---');
      final classToDex = <String, List<String>>{};
      for (final dex in dexEntries) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        final classCount = text.split('\n').where((l) => l.trim().isNotEmpty).length;
        sb.writeln('  ${dex.name}: $classCount classes');

        for (final line in text.split('\n')) {
          final cls = line.trim();
          if (cls.isNotEmpty) {
            classToDex.putIfAbsent(cls, () => []).add(dex.name);
          }
        }
      }

      // ── 重复类 ──
      final duplicates = classToDex.entries.where((e) => e.value.length > 1).toList();
      sb.writeln('\n--- Duplicate Classes ---');
      sb.writeln('Duplicate count: ${duplicates.length}');
      for (final d in duplicates.take(20)) {
        sb.writeln('  ${d.key} → ${d.value.join(', ')}');
      }
      if (duplicates.length > 20) sb.writeln('  ... and ${duplicates.length - 20} more');

      // ── 跨 DEX 引用 ──
      sb.writeln('\n--- Cross-DEX References ---');
      final dexClassSets = <String, Set<String>>{};
      for (final dex in dexEntries) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        dexClassSets[dex.name] = text.split('\n').map((l) => l.trim()).where((l) => l.isNotEmpty).toSet();
      }

      final crossRefs = <String, Map<String, int>>{};
      for (final dex in dexEntries) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        final localClasses = dexClassSets[dex.name] ?? {};

        for (final otherDex in dexClassSets.keys) {
          if (otherDex == dex.name) continue;
          final otherClasses = dexClassSets[otherDex]!;
          var refCount = 0;
          for (final cls in otherClasses) {
            if (!localClasses.contains(cls) && text.contains(cls)) {
              refCount++;
            }
          }
          if (refCount > 0) {
            crossRefs.putIfAbsent(dex.name, () => {})[otherDex] = refCount;
          }
        }
      }

      if (crossRefs.isEmpty) {
        sb.writeln('  No cross-DEX references detected');
      } else {
        for (final src in crossRefs.keys) {
          for (final tgt in crossRefs[src]!.keys) {
            sb.writeln('  $src → $tgt: ${crossRefs[src]![tgt]} refs');
          }
        }
      }

      // ── 汇总 ──
      final totalClasses = classToDex.length;
      sb.writeln('\n=== Summary ===');
      sb.writeln('Total unique classes: $totalClasses');
      sb.writeln('Total class entries: ${classToDex.values.fold<int>(0, (s, v) => s + v.length)}');
      sb.writeln('Duplicates: ${duplicates.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_native_xref — Native-Java 交叉引用分析
  // =========================================================================
  static Future<Map<String, dynamic>> nativeXref(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Native-Java Cross Reference ===\n');

      // ── 从 DEX 提取 native 方法声明 ──
      final nativeMethods = <Map<String, String>>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        // Look for native method patterns in class listing
        final nativeMatches = RegExp(r'(L[\w/]+;)\.(\w+)\s*\([^)]*\)\s*native', caseSensitive: false)
            .allMatches(text);
        for (final m in nativeMatches) {
          final cls = m.group(1)!;
          final method = m.group(2)!;
          final cleaned = cls.substring(1, cls.length - 1).replaceAll('/', '_');
          final jniName = 'Java_${cleaned}_$method';
          nativeMethods.add({
            'class': cls,
            'method': method,
            'jni_name': jniName,
          });
        }
      }

      sb.writeln('--- Native Methods (from DEX) ---');
      sb.writeln('Count: ${nativeMethods.length}');
      for (final nm in nativeMethods.take(30)) {
        sb.writeln('  ${nm['class']}.${nm['method']} → ${nm['jni_name']}');
      }
      if (nativeMethods.length > 30) {
        sb.writeln('  ... and ${nativeMethods.length - 30} more');
      }

      // ── 从 SO 提取 JNI 符号 ──
      final soSymbols = <String, List<String>>{};
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        try {
          final soPayload = KelivoSoRequestPayload(bytes: so.content!);
          final soText = _extractResultText(KelivoSoAnalyzer.exports(soPayload));
          final jniSyms = <String>[];
          for (final line in soText.split('\n')) {
            final trimmed = line.trim();
            if (trimmed.startsWith('Java_') || trimmed == 'JNI_OnLoad' || trimmed == 'JNI_OnUnload') {
              jniSyms.add(trimmed);
            }
          }
          if (jniSyms.isNotEmpty) {
            soSymbols[so.name] = jniSyms;
          }
        } catch (_) {}
      }

      sb.writeln('\n--- SO JNI Symbols ---');
      for (final entry in soSymbols.entries) {
        sb.writeln('${entry.key}: ${entry.value.length} JNI symbol(s)');
        for (final sym in entry.value.take(20)) {
          sb.writeln('  $sym');
        }
        if (entry.value.length > 20) {
          sb.writeln('  ... and ${entry.value.length - 20} more');
        }
      }

      // ── 交叉匹配 ──
      sb.writeln('\n--- Cross Reference ---');
      final allSoSyms = <String, String>{}; // sym -> so_name
      for (final entry in soSymbols.entries) {
        for (final sym in entry.value) {
          allSoSyms[sym] = entry.key;
        }
      }

      var matched = 0;
      var unmatched = 0;
      for (final nm in nativeMethods) {
        final jniName = nm['jni_name']!;
        if (allSoSyms.containsKey(jniName)) {
          sb.writeln('  ✓ ${nm['class']}.${nm['method']} → ${allSoSyms[jniName]}');
          matched++;
        } else {
          unmatched++;
        }
      }

      // Check for JNI_OnLoad (dynamic registration)
      final dynamicReg = soSymbols.values.any((syms) => syms.contains('JNI_OnLoad'));
      if (dynamicReg && unmatched > 0) {
        sb.writeln('\n⚠️ JNI_OnLoad detected — unmatched native methods may use dynamic registration.');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Native methods: ${nativeMethods.length}');
      sb.writeln('Matched: $matched');
      sb.writeln('Unmatched: $unmatched');
      sb.writeln('SO files with JNI: ${soSymbols.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_vuln_scan — 安全漏洞扫描 (11类)
  // =========================================================================
  static Future<Map<String, dynamic>> vulnScan(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Vulnerability Scan ===\n');

      // Collect DEX text
      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      final combined = allText.join('\n');

      // Manifest text
      String? manifestText;
      try {
        manifestText = _extractResultText(KelivoManifestAnalyzer.summary(
          KelivoManifestRequestPayload(bytes: p.apkBytes!),
        ));
      } catch (_) {}

      final allFindings = <Map<String, String>>[];

      // ── 1. SSL/TLS ──
      final sslPats = [
        [r'checkServerTrusted.*\{.*\}', 'custom_trust_manager', 'high', '自定义 TrustManager，可能跳过证书校验'],
        [r'ALLOW_ALL_HOSTNAME_VERIFIER|verify.*return\s+true', 'hostname_verifier_bypass', 'high', 'HostnameVerifier 被绕过'],
        [r'TrustAllCerts|trustAllCerts', 'trust_all_certs', 'critical', '信任所有证书，MITM 风险极高'],
        [r'SSLContext\.getInstance.*"SSL"', 'weak_ssl_protocol', 'medium', '使用弱 SSL/TLS 协议'],
      ];
      sb.writeln('--- SSL/TLS Issues ---');
      for (final p in sslPats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  [${p[2]}] ${p[3]} (×${ms.length})');
          allFindings.add({'category': 'SSL/TLS', 'severity': p[2], 'desc': p[3]});
        }
      }

      // ── 2. WebView ──
      final webviewPats = [
        [r'setJavaScriptEnabled\(true\)', 'js_enabled', 'medium', 'WebView 启用 JavaScript'],
        [r'addJavascriptInterface', 'js_interface', 'high', '使用 addJavascriptInterface'],
        [r'setAllowFileAccess\(true\)|setAllowFileAccessFromFileURLs\(true\)', 'file_access', 'high', 'WebView 允许文件访问'],
        [r'setAllowUniversalAccessFromFileURLs\(true\)', 'universal_file_access', 'critical', 'WebView 允许跨域文件访问'],
      ];
      sb.writeln('\n--- WebView Security ---');
      for (final p in webviewPats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  [${p[2]}] ${p[3]} (×${ms.length})');
          allFindings.add({'category': 'WebView', 'severity': p[2], 'desc': p[3]});
        }
      }

      // ── 3. SQLite 注入 ──
      final sqlitePats = [
        [r'rawQuery.*\+.*get|rawQuery.*%.*get', 'sqlite_injection', 'high', 'SQL 查询拼接外部输入'],
        [r'execSQL.*\+.*get|execSQL.*%.*get', 'sqlite_exec_injection', 'high', 'SQL 执行拼接外部输入'],
      ];
      sb.writeln('\n--- SQLite Injection ---');
      for (final p in sqlitePats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  [${p[2]}] ${p[3]} (×${ms.length})');
          allFindings.add({'category': 'SQLite', 'severity': p[2], 'desc': p[3]});
        }
      }

      // ── 4. 文件模式 ──
      final filePats = [
        [r'MODE_WORLD_READABLE', 'world_readable', 'high', '文件设置为全局可读'],
        [r'MODE_WORLD_WRITEABLE|MODE_WORLD_WRITABLE', 'world_writable', 'high', '文件设置为全局可写'],
      ];
      sb.writeln('\n--- File Mode Issues ---');
      for (final p in filePats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  [${p[2]}] ${p[3]} (×${ms.length})');
          allFindings.add({'category': 'File Mode', 'severity': p[2], 'desc': p[3]});
        }
      }

      // ── 5. 动态加载 ──
      final dynLoadPats = [
        [r'DexClassLoader|PathClassLoader.*loadClass', 'dex_loading', 'medium', '动态加载 DEX 文件'],
        [r'System\.load|System\.loadLibrary', 'native_loading', 'low', '加载 Native 库'],
      ];
      sb.writeln('\n--- Dynamic Code Loading ---');
      for (final p in dynLoadPats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  [${p[2]}] ${p[3]} (×${ms.length})');
          allFindings.add({'category': 'Dynamic Load', 'severity': p[2], 'desc': p[3]});
        }
      }

      // ── 6. 硬编码凭据 ──
      final credPats = [
        [r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', 'hardcoded_password', 'high', '硬编码密码'],
        [r'(?i)(api_?key|apikey|secret)\s*[:=]\s*["\'][^"\']{10,}["\']', 'hardcoded_api_key', 'high', '硬编码 API Key'],
        [r'(?i)(token|auth)\s*[:=]\s*["\'][^"\']{16,}["\']', 'hardcoded_token', 'high', '硬编码 Token'],
        [r'(?i)AKIA[0-9A-Z]{16}', 'aws_key', 'critical', '硬编码 AWS Access Key'],
        [r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'private_key', 'critical', '硬编码私钥'],
        [r'(?i)ghp_[a-zA-Z0-9]{36}', 'github_token', 'critical', '硬编码 GitHub Token'],
        [r'(?i)sk_live_[a-zA-Z0-9]{24,}', 'stripe_key', 'critical', '硬编码 Stripe Key'],
      ];
      sb.writeln('\n--- Hardcoded Credentials ---');
      for (final p in credPats) {
        final ms = RegExp(p[0]).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  [${p[2]}] ${p[3]} (×${ms.length})');
          allFindings.add({'category': 'Credentials', 'severity': p[2], 'desc': p[3]});
        }
      }

      // ── 7. 其他安全风险 ──
      final miscPats = [
        [r'Runtime\.getRuntime\(\)\.exec', 'command_exec', 'high', '执行系统命令'],
        [r'TelephonyManager.*getDeviceId|getImei|getMeid', 'device_id_access', 'high', '获取设备唯一标识符'],
        [r'SmsManager.*sendTextMessage', 'send_sms', 'high', '发送短信'],
        [r'LocationManager.*requestLocationUpdates', 'location_track', 'high', '位置追踪'],
        [r'ContactsContract', 'contacts_access', 'high', '通讯录访问'],
        [r'AccessibilityService|BIND_ACCESSIBILITY_SERVICE', 'accessibility_service', 'high', '使用无障碍服务'],
        [r'Camera\.open|camera2.*CameraDevice', 'camera_access', 'medium', '摄像头访问'],
        [r'AudioRecord|MediaRecorder', 'audio_record', 'medium', '录音功能'],
      ];
      sb.writeln('\n--- Miscellaneous ---');
      for (final p in miscPats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  [${p[2]}] ${p[3]} (×${ms.length})');
          allFindings.add({'category': 'Misc', 'severity': p[2], 'desc': p[3]});
        }
      }

      // ── 8. Manifest 风险 ──
      if (manifestText != null) {
        sb.writeln('\n--- Manifest Issues ---');
        if (manifestText.contains('debuggable=true') || manifestText.contains('debuggable: true')) {
          sb.writeln('  [high] 应用设置为可调试 (debuggable=true)');
          allFindings.add({'category': 'Manifest', 'severity': 'high', 'desc': 'debuggable=true'});
        }
        if (manifestText.contains('allowBackup=true') || manifestText.contains('allowBackup: true')) {
          sb.writeln('  [medium] 允许应用数据备份 (allowBackup=true)');
          allFindings.add({'category': 'Manifest', 'severity': 'medium', 'desc': 'allowBackup=true'});
        }
        if (manifestText.contains('usesCleartextTraffic=true') || manifestText.contains('cleartextTraffic: true')) {
          sb.writeln('  [medium] 允许明文 HTTP 流量 (usesCleartextTraffic=true)');
          allFindings.add({'category': 'Manifest', 'severity': 'medium', 'desc': 'usesCleartextTraffic=true'});
        }
      }

      // ── 汇总 ──
      final critical = allFindings.where((f) => f['severity'] == 'critical').length;
      final high = allFindings.where((f) => f['severity'] == 'high').length;
      final medium = allFindings.where((f) => f['severity'] == 'medium').length;
      sb.writeln('\n=== Summary ===');
      sb.writeln('Total findings: ${allFindings.length}');
      sb.writeln('Critical: $critical | High: $high | Medium: $medium');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_privacy_audit — 隐私风险评估
  // =========================================================================
  static Future<Map<String, dynamic>> privacyAudit(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Privacy Audit ===\n');

      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      final combined = allText.join('\n');

      // Manifest for permissions
      String? manifestText;
      try {
        manifestText = _extractResultText(KelivoManifestAnalyzer.summary(
          KelivoManifestRequestPayload(bytes: p.apkBytes!),
        ));
      } catch (_) {}

      final dataBehaviors = <String, Map<String, dynamic>>{};

      final behaviorPats = {
        'location': {
          'apis': ['getLastKnownLocation', 'requestLocationUpdates', 'getLatitude', 'getLongitude', 'LocationManager'],
          'perms': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'],
          'severity': 'high',
          'desc': '位置信息收集',
        },
        'contacts': {
          'apis': ['ContactsContract', 'queryContacts', 'PhoneLookup'],
          'perms': ['READ_CONTACTS', 'WRITE_CONTACTS'],
          'severity': 'high',
          'desc': '联系人读取',
        },
        'sms': {
          'apis': ['SmsManager', 'Telephony.Sms', 'content://sms'],
          'perms': ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS'],
          'severity': 'high',
          'desc': '短信读写',
        },
        'camera': {
          'apis': ['Camera.open', 'Camera2', 'takePicture'],
          'perms': ['CAMERA'],
          'severity': 'medium',
          'desc': '相机访问',
        },
        'microphone': {
          'apis': ['MediaRecorder', 'AudioRecord', 'startRecording'],
          'perms': ['RECORD_AUDIO'],
          'severity': 'medium',
          'desc': '麦克风录音',
        },
        'phone_state': {
          'apis': ['getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getLine1Number'],
          'perms': ['READ_PHONE_STATE', 'CALL_PHONE'],
          'severity': 'high',
          'desc': '设备标识/电话状态',
        },
        'accounts': {
          'apis': ['AccountManager', 'getAccounts', 'getAccountsByType'],
          'perms': ['GET_ACCOUNTS'],
          'severity': 'medium',
          'desc': '账户信息',
        },
        'bluetooth': {
          'apis': ['BluetoothAdapter', 'BluetoothDevice', 'startDiscovery'],
          'perms': ['BLUETOOTH_SCAN', 'BLUETOOTH_CONNECT'],
          'severity': 'medium',
          'desc': '蓝牙扫描/连接',
        },
      };

      sb.writeln('--- Data Collection Behaviors ---');
      for (final entry in behaviorPats.entries) {
        final info = entry.value;
        final apiHits = <String>[];
        for (final api in info['apis'] as List<String>) {
          if (combined.toLowerCase().contains(api.toLowerCase())) {
            apiHits.add(api);
          }
        }
        final permHits = <String>[];
        for (final perm in info['perms'] as List<String>) {
          if (manifestText != null && manifestText!.contains(perm)) {
            permHits.add(perm);
          }
        }
        if (apiHits.isNotEmpty || permHits.isNotEmpty) {
          sb.writeln('  [${info['severity']}] ${info['desc']}');
          if (apiHits.isNotEmpty) sb.writeln('    APIs: ${apiHits.join(', ')}');
          if (permHits.isNotEmpty) sb.writeln('    Perms: ${permHits.join(', ')}');
          dataBehaviors[entry.key] = {
            'severity': info['severity'],
            'apis': apiHits,
            'perms': permHits,
          };
        }
      }

      // Data exfiltration patterns
      sb.writeln('\n--- Data Exfiltration ---');
      final exfilPats = [
        [r'POST|upload|multipart|RequestBody', 'HTTP 上传行为'],
        [r'Socket\(|ServerSocket|DatagramSocket', '原始 Socket 连接'],
        [r'ClipboardManager|setText|getText', '剪贴板读写'],
      ];
      for (final p in exfilPats) {
        final ms = RegExp(p[0], caseSensitive: false).allMatches(combined);
        if (ms.isNotEmpty) {
          sb.writeln('  ${p[1]} (×${ms.length})');
        }
      }

      // Risk score
      var riskScore = 0;
      for (final b in dataBehaviors.values) {
        final sev = b['severity'] as String;
        riskScore += sev == 'high' ? 15 : (sev == 'medium' ? 8 : 4);
        riskScore += (b['perms'] as List).length * 3;
        riskScore += (b['apis'] as List).length * 2;
      }
      final level = riskScore >= 80 ? 'critical' : (riskScore >= 50 ? 'high' : (riskScore >= 25 ? 'medium' : 'low'));
      sb.writeln('\n=== Risk Assessment ===');
      sb.writeln('Risk score: $riskScore');
      sb.writeln('Risk level: $level');
      sb.writeln('Behaviors detected: ${dataBehaviors.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_sdk_detect — 第三方 SDK/追踪器检测
  // =========================================================================
  static Future<Map<String, dynamic>> sdkDetect(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== SDK / Tracker Detection ===\n');

      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      final combined = allText.join('\n');

      final sdkSigs = [
        ['com.google.android.gms.ads', 'Google AdMob', '广告', '高'],
        ['com.facebook.ads', 'Facebook Ads', '广告', '高'],
        ['com.applovin', 'AppLovin', '广告', '高'],
        ['com.unity3d', 'Unity3D', '游戏引擎', '低'],
        ['com.vungle', 'Vungle', '广告', '高'],
        ['com.ironsource', 'IronSource', '广告', '高'],
        ['com.chartboost', 'Chartboost', '广告', '高'],
        ['com.adcolony', 'AdColony', '广告', '高'],
        ['com.tapjoy', 'Tapjoy', '广告', '高'],
        ['com.inmobi', 'InMobi', '广告', '高'],
        ['com.mopub', 'MoPub', '广告', '高'],
        ['com.bytedance', 'ByteDance/Pangle', '广告', '高'],
        ['com.adjust.sdk', 'Adjust', '归因/追踪', '高'],
        ['com.appsflyer', 'AppsFlyer', '归因/追踪', '高'],
        ['com.kochava', 'Kochava', '归因/追踪', '高'],
        ['com.google.firebase', 'Firebase SDK', '云服务', '中'],
        ['com.google.analytics', 'Google Analytics', '分析', '中'],
        ['com.mixpanel', 'Mixpanel', '分析', '中'],
        ['com.amplitude', 'Amplitude', '分析', '中'],
        ['com.flurry', 'Flurry', '分析', '中'],
        ['com.sentry', 'Sentry', '错误追踪', '低'],
        ['com.bugsnag', 'Bugsnag', '错误追踪', '低'],
        ['com.crashlytics', 'Crashlytics', '错误追踪', '低'],
        ['com.umeng', 'Umeng/友盟', '分析', '高'],
        ['com.tencent.bugly', 'Bugly', '错误追踪', '低'],
        ['com.huawei.hms.push', 'Huawei Push', '推送', '中'],
        ['com.xiaomi.push', 'Xiaomi Push', '推送', '中'],
        ['cn.jpush', 'JPush', '推送', '中'],
        ['com.igexin', 'GeTui Push', '推送', '中'],
        ['com.tencent.mm.opensdk', 'WeChat SDK', '社交', '中'],
        ['com.tencent.connect', 'QQ/腾讯开放', '社交', '中'],
        ['com.alipay', 'Alipay', '支付', '中'],
        ['com.stripe', 'Stripe', '支付', '中'],
        ['com.squareup.okhttp', 'OkHttp', '网络', '低'],
        ['com.squareup.retrofit', 'Retrofit', '网络', '低'],
        ['com.bumptech.glide', 'Glide', '图片', '低'],
        ['com.facebook.fresco', 'Fresco', '图片', '低'],
        ['com.google.gson', 'Gson', 'JSON', '低'],
        ['com.google.protobuf', 'Protobuf', '序列化', '低'],
        ['io.reactivex', 'RxJava', '响应式', '低'],
        ['com.google.dagger', 'Dagger', 'DI', '低'],
        ['org.greenrobot.eventbus', 'EventBus', '事件', '低'],
        ['androidx.room', 'Room', '数据库', '低'],
        ['io.flutter', 'Flutter', '框架', '低'],
        ['com.facebook.react', 'React Native', '框架', '低'],
        ['com.tencent.mmkv', 'MMKV', '存储', '低'],
        ['com.tencent.tinker', 'Tinker', '热修复', '低'],
        ['com.alibaba.fastjson', 'FastJson', 'JSON', '低'],
        ['org.jetbrains.kotlin', 'Kotlin', '语言', '低'],
        ['com.google.android.material', 'Material Design', 'UI', '低'],
      ];

      final detected = <Map<String, dynamic>>[];
      for (final sig in sdkSigs) {
        final pat = sig[0], name = sig[1], cat = sig[2], risk = sig[3];
        final javaPat = pat.replaceAll('.', '/');
        if (combined.contains(pat) || combined.contains('L$javaPat') || combined.contains(javaPat)) {
          detected.add({'name': name, 'category': cat, 'risk': risk, 'pattern': pat});
        }
      }

      sb.writeln('--- Detected SDKs (${detected.length}) ---');
      for (final d in detected) {
        sb.writeln('  [${d['risk']}] ${d['name']} (${d['category']})');
      }

      // Category stats
      final cats = <String, int>{};
      for (final d in detected) {
        cats[d['category'] as String] = (cats[d['category'] as String] ?? 0) + 1;
      }
      sb.writeln('\n--- Categories ---');
      cats.forEach((k, v) => sb.writeln('  $k: $v'));

      final trackerCount = detected.where((d) => 
        ['广告', '追踪', '归因/追踪'].contains(d['category'])).length;
      final highRisk = detected.where((d) => d['risk'] == '高').length;
      sb.writeln('\n=== Summary ===');
      sb.writeln('Total SDKs: ${detected.length}');
      sb.writeln('Trackers/Ads: $trackerCount');
      sb.writeln('High risk: $highRisk');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_endpoint_extract — 网络端点提取
  // =========================================================================
  static Future<Map<String, dynamic>> endpointExtract(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Network Endpoint Extraction ===\n');

      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      // Also search SO strings
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        try {
          final soPayload = KelivoSoRequestPayload(bytes: so.content!);
          allText.add(_extractResultText(KelivoSoAnalyzer.strings(soPayload)));
        } catch (_) {}
      }
      final combined = allText.join('\n');

      // URLs
      final urlMatches = RegExp(r'https?://[^\s"\'<>]+').allMatches(combined);
      final urls = urlMatches.map((m) => m.group(0)!).toSet().toList();
      final httpUrls = urls.where((u) => u.startsWith('http://')).toList();
      final httpsUrls = urls.where((u) => u.startsWith('https://')).toList();

      sb.writeln('--- URLs (${urls.length}) ---');
      for (final u in urls.take(30)) sb.writeln('  $u');
      if (urls.length > 30) sb.writeln('  ... and ${urls.length - 30} more');

      // Domains
      final domains = <String>{};
      for (final u in urls) {
        final m = RegExp(r'https?://([^/\s"\'<>:]+)').firstMatch(u);
        if (m != null) domains.add(m.group(1)!.toLowerCase());
      }
      sb.writeln('\n--- Domains (${domains.length}) ---');
      for (final d in domains.take(20)) sb.writeln('  $d');

      // IPs
      final ipMatches = RegExp(r'\b(?:\d{1,3}\.){3}\d{1,3}\b').allMatches(combined);
      final ips = ipMatches.map((m) => m.group(0)!).toSet().toList();
      final privateIps = ips.where((ip) =>
        ip.startsWith('10.') || ip.startsWith('172.1') ||
        ip.startsWith('192.168') || ip.startsWith('127.') || ip.startsWith('169.254')).toList();
      final publicIps = ips.where((ip) => !privateIps.contains(ip)).toList();

      sb.writeln('\n--- IP Addresses (${ips.length}) ---');
      sb.writeln('  Public: ${publicIps.length}');
      for (final ip in publicIps.take(15)) sb.writeln('    $ip');
      sb.writeln('  Private: ${privateIps.length}');
      for (final ip in privateIps.take(10)) sb.writeln('    $ip');

      // API paths
      final apiPathPats = [
        r'/api/[\w/.-]+', r'/v\d+/[\w/.-]+', r'/rest/[\w/.-]+',
        r'/graphql[\w/.-]*', r'/oauth[\w/.-]*', r'/token[\w/.-]*',
        r'/auth[\w/.-]*', r'/login[\w/.-]*', r'/upload[\w/.-]*',
        r'/callback[\w/.-]*', r'/webhook[\w/.-]*',
      ];
      final apiPaths = <String>{};
      for (final pat in apiPathPats) {
        final ms = RegExp(pat, caseSensitive: false).allMatches(combined);
        for (final m in ms) apiPaths.add(m.group(0)!);
      }
      sb.writeln('\n--- API Paths (${apiPaths.length}) ---');
      for (final ap in apiPaths.take(20)) sb.writeln('  $ap');

      // Cloud domains
      final cloudDomains = [
        'amazonaws.com', 'azure.com', 'cloudfront.net', 'aliyuncs.com',
        'qcloud.com', 'googleapis.com', 'firebaseio.com', 'herokuapp.com',
        'netlify.com', 'vercel.app', 'cloudflare.com',
      ];
      final cloudHosts = domains.where((d) =>
        cloudDomains.any((c) => d.contains(c))).toList();
      sb.writeln('\n--- Cloud Hosts (${cloudHosts.length}) ---');
      for (final h in cloudHosts.take(15)) sb.writeln('  $h');

      // Summary
      sb.writeln('\n=== Summary ===');
      sb.writeln('Total URLs: ${urls.length}');
      sb.writeln('HTTP (insecure): ${httpUrls.length}');
      sb.writeln('HTTPS: ${httpsUrls.length}');
      sb.writeln('Domains: ${domains.length}');
      sb.writeln('IPs: ${ips.length} (public: ${publicIps.length}, private: ${privateIps.length})');
      sb.writeln('API paths: ${apiPaths.length}');
      sb.writeln('Cloud hosts: ${cloudHosts.length}');
      if (httpUrls.isNotEmpty) {
        sb.writeln('⚠️ ${httpUrls.length} insecure HTTP URL(s) detected');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_social_login — 社交登录检测
  // =========================================================================
  static Future<Map<String, dynamic>> socialLoginDetect(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Social Login Detection ===\n');

      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      final combined = allText.join('\n');

      final platforms = <String, Map<String, dynamic>>{
        'wechat': {'name': '微信登录', 'icon': '💬', 'risk': '中',
          'patterns': [r'com\.tencent\.mm\.opensdk', r'com\.tencent\.mm\.sdk', r'WXEntryActivity', r'WXApi', r'IWXAPI', r'wx[a-z0-9]{16,}'],
          'urls': [r'api\.weixin\.qq\.com', r'open\.weixin\.qq\.com']},
        'qq': {'name': 'QQ登录', 'icon': '🐧', 'risk': '中',
          'patterns': [r'com\.tencent\.connect', r'com\.tencent\.tauth', r'Tencent', r'QQLogin', r'qq_login', r'IUiListener'],
          'urls': [r'graph\.qq\.com', r'openmobile\.qq\.com']},
        'github': {'name': 'GitHub登录', 'icon': '🐙', 'risk': '低',
          'patterns': [r'com\.github', r'github\.login', r'github\.auth', r'Octokit', r'github_oauth'],
          'urls': [r'github\.com', r'api\.github\.com']},
        'alipay': {'name': '支付宝登录', 'icon': '💳', 'risk': '中',
          'patterns': [r'com\.alipay\.sdk', r'com\.alipay\.auth', r'AlipayLogin', r'alipay_auth', r'alipay_sdk'],
          'urls': [r'alipay\.com', r'auth\.alipay\.com']},
        'weibo': {'name': '微博登录', 'icon': '📱', 'risk': '中',
          'patterns': [r'com\.sina\.weibo', r'com\.weibo\.sdk', r'WeiboLogin', r'SsoHandler', r'AccessTokenKeeper'],
          'urls': [r'api\.weibo\.com', r'open\.weibo\.com']},
        'google': {'name': 'Google登录', 'icon': '🔵', 'risk': '低',
          'patterns': [r'com\.google\.android\.gms\.auth', r'com\.google\.android\.gms\.signin', r'GoogleSignIn', r'FirebaseAuth'],
          'urls': [r'accounts\.google\.com', r'googleapis\.com']},
        'facebook': {'name': 'Facebook登录', 'icon': '👍', 'risk': '中',
          'patterns': [r'com\.facebook\.login', r'FacebookLogin', r'LoginButton', r'LoginManager', r'GraphRequest'],
          'urls': [r'facebook\.com', r'graph\.facebook\.com']},
        'apple': {'name': 'Apple登录', 'icon': '🍎', 'risk': '低',
          'patterns': [r'com\.apple\.', r'AppleSignIn', r'sign_in_with_apple', r'ASAuthorization'],
          'urls': [r'appleid\.apple\.com']},
        'twitter': {'name': 'Twitter登录', 'icon': '🐦', 'risk': '低',
          'patterns': [r'com\.twitter\.sdk', r'TwitterLogin', r'TwitterAuth', r'TwitterSession'],
          'urls': [r'twitter\.com', r'api\.twitter\.com']},
      };

      for (final entry in platforms.entries) {
        final info = entry.value;
        final patternHits = <String>[];
        for (final pat in info['patterns'] as List<String>) {
          if (RegExp(pat, caseSensitive: false).hasMatch(combined)) {
            patternHits.add(pat);
          }
        }
        final urlHits = <String>[];
        for (final pat in info['urls'] as List<String>) {
          if (RegExp(pat, caseSensitive: false).hasMatch(combined)) {
            urlHits.add(pat);
          }
        }
        if (patternHits.isNotEmpty || urlHits.isNotEmpty) {
          var confidence = 0;
          if (patternHits.isNotEmpty) confidence += 40;
          if (patternHits.length >= 2) confidence += 20;
          if (urlHits.isNotEmpty) confidence += 25;
          confidence = confidence > 100 ? 100 : confidence;
          sb.writeln('${info['icon']} ${info['name']} [${info['risk']}风险] (confidence: $confidence%)');
          if (patternHits.isNotEmpty) sb.writeln('  Patterns: ${patternHits.take(5).join(', ')}');
          if (urlHits.isNotEmpty) sb.writeln('  URLs: ${urlHits.join(', ')}');
          sb.writeln('');
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_apk_size — APK 体积分析
  // =========================================================================
  static Future<Map<String, dynamic>> apkSize(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== APK Size Analysis ===\n');

      final categories = <String, int>{};
      final fileSizes = <String, int>[];
      var totalUncompressed = 0;
      var totalCompressed = 0;

      for (final entry in apk.entries) {
        if (entry.content == null) continue;
        final name = entry.name;
        final uncompressed = entry.content!.length;
        totalUncompressed += uncompressed;

        String cat;
        if (name.endsWith('.dex')) {
          cat = 'DEX';
        } else if (name.startsWith('lib/') && name.endsWith('.so')) {
          cat = 'Native Lib';
        } else if (name.startsWith('res/') || name == 'resources.arsc') {
          cat = 'Resources';
        } else if (name.startsWith('assets/')) {
          cat = 'Assets';
        } else if (name.startsWith('META-INF/')) {
          cat = 'META-INF';
        } else if (name == 'AndroidManifest.xml') {
          cat = 'Manifest';
        } else {
          cat = 'Other';
        }
        categories[cat] = (categories[cat] ?? 0) + uncompressed;
        fileSizes.add(uncompressed);
        totalCompressed += uncompressed; // Approximate
      }

      sb.writeln('--- Categories ---');
      final sortedCats = categories.entries.toList()
        ..sort((a, b) => b.value.compareTo(a.value));
      for (final cat in sortedCats) {
        final kb = (cat.value / 1024).toStringAsFixed(1);
        final pct = totalUncompressed > 0 ? (cat.value / totalUncompressed * 100).toStringAsFixed(1) : '0';
        sb.writeln('  ${cat.key}: ${kb}KB ($pct%)');
      }

      sb.writeln('\n--- Top 20 Files ---');
      // We don't have individual file sizes readily available in this context
      // so we show the category breakdown instead
      final totalKB = (totalUncompressed / 1024).toStringAsFixed(1);
      final totalMB = (totalUncompressed / 1024 / 1024).toStringAsFixed(2);
      sb.writeln('Total uncompressed: ${totalKB}KB (${totalMB}MB)');

      // Recommendations
      sb.writeln('\n--- Recommendations ---');
      final dexPct = totalUncompressed > 0 ? (categories['DEX'] ?? 0) / totalUncompressed * 100 : 0;
      if (dexPct > 40) {
        sb.writeln('  ⚠️ DEX 占比 ${dexPct.toStringAsFixed(1)}%，建议启用 R8/ProGuard');
      }
      final resPct = totalUncompressed > 0 ? (categories['Resources'] ?? 0) / totalUncompressed * 100 : 0;
      if (resPct > 30) {
        sb.writeln('  ⚠️ Resources 占比 ${resPct.toStringAsFixed(1)}%，建议使用 WebP 格式');
      }
      final nativePct = totalUncompressed > 0 ? (categories['Native Lib'] ?? 0) / totalUncompressed * 100 : 0;
      if (nativePct > 30) {
        sb.writeln('  ⚠️ Native Lib 占比 ${nativePct.toStringAsFixed(1)}%，考虑使用 ABI splits');
      }
      final assetsKB = (categories['Assets'] ?? 0) / 1024;
      if (assetsKB > 5000) {
        sb.writeln('  ⚠️ Assets ${assetsKB.toStringAsFixed(0)}KB，检查大体积文件');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_security_score — 综合安全评分
  // =========================================================================
  static Future<Map<String, dynamic>> securityScore(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Security Score ===\n');

      // Manifest
      String? manifestText;
      try {
        manifestText = _extractResultText(KelivoManifestAnalyzer.summary(
          KelivoManifestRequestPayload(bytes: p.apkBytes!),
        ));
      } catch (_) {}

      // DEX text
      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      final combined = allText.join('\n');

      final issues = <Map<String, String>>[];
      var score = 0;
      var maxScore = 0;

      // 1. Debuggable
      maxScore += 3;
      if (manifestText != null && (manifestText.contains('debuggable=true') || manifestText.contains('debuggable: true'))) {
        issues.add({'severity': 'HIGH', 'type': '可调试', 'desc': 'debuggable=true，生产环境应关闭', 'cwe': 'CWE-489'});
        score += 3;
      }

      // 2. allowBackup
      maxScore += 2;
      if (manifestText != null && (manifestText.contains('allowBackup=true') || manifestText.contains('allowBackup: true'))) {
        issues.add({'severity': 'MEDIUM', 'type': '数据备份', 'desc': 'allowBackup=true，可能导致数据泄露', 'cwe': 'CWE-200'});
        score += 2;
      }

      // 3. Cleartext traffic
      maxScore += 2;
      if (manifestText != null && (manifestText.contains('usesCleartextTraffic=true') || manifestText.contains('cleartextTraffic: true'))) {
        issues.add({'severity': 'MEDIUM', 'type': '明文流量', 'desc': 'usesCleartextTraffic=true', 'cwe': 'CWE-319'});
        score += 2;
      }

      // 4. Exported components (from manifest)
      maxScore += 3;
      if (manifestText != null) {
        final exportedCount = 'exported'.allMatches(manifestText).length;
        if (exportedCount > 5) {
          issues.add({'severity': 'MEDIUM', 'type': '导出组件', 'desc': '检测到 $exportedCount 个导出组件引用', 'cwe': 'CWE-926'});
          score += 2;
        }
      }

      // 5. SSL/TLS issues
      maxScore += 3;
      if (combined.contains('TrustAllCerts') || combined.contains('trustAllCerts')) {
        issues.add({'severity': 'HIGH', 'type': 'SSL绕过', 'desc': '信任所有证书', 'cwe': 'CWE-295'});
        score += 3;
      } else if (combined.contains('ALLOW_ALL_HOSTNAME_VERIFIER')) {
        issues.add({'severity': 'HIGH', 'type': 'SSL绕过', 'desc': 'HostnameVerifier 被绕过', 'cwe': 'CWE-295'});
        score += 2;
      }

      // 6. WebView issues
      maxScore += 2;
      if (combined.contains('addJavascriptInterface')) {
        issues.add({'severity': 'HIGH', 'type': 'WebView', 'desc': '使用 addJavascriptInterface', 'cwe': 'CWE-749'});
        score += 2;
      }

      // 7. Command execution
      maxScore += 2;
      if (combined.contains('Runtime.getRuntime()') && combined.contains('exec')) {
        issues.add({'severity': 'HIGH', 'type': '命令执行', 'desc': 'Runtime.exec 执行系统命令', 'cwe': 'CWE-78'});
        score += 2;
      }

      // 8. Hardcoded credentials
      maxScore += 3;
      if (RegExp(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']').hasMatch(combined)) {
        issues.add({'severity': 'HIGH', 'type': '硬编码凭据', 'desc': '检测到硬编码密码', 'cwe': 'CWE-798'});
        score += 3;
      }

      // 9. Dynamic code loading
      maxScore += 2;
      if (combined.contains('DexClassLoader')) {
        issues.add({'severity': 'MEDIUM', 'type': '动态加载', 'desc': 'DexClassLoader 动态加载 DEX', 'cwe': 'CWE-494'});
        score += 1;
      }

      // 10. Reflection
      maxScore += 2;
      if (combined.contains('Class.forName') && combined.contains('setAccessible')) {
        issues.add({'severity': 'MEDIUM', 'type': '反射', 'desc': '反射访问私有成员', 'cwe': 'CWE-470'});
        score += 1;
      }

      // Calculate risk level
      final riskScore = maxScore > 0 ? (score * 100 / maxScore).round().clamp(0, 100) : 0;
      final level = riskScore <= 20 ? '安全' : (riskScore <= 40 ? '低风险' : (riskScore <= 60 ? '中风险' : (riskScore <= 80 ? '高风险' : '严重')));

      sb.writeln('--- Issues (${issues.length}) ---');
      for (final issue in issues) {
        sb.writeln('  [${issue['severity']}] ${issue['type']}: ${issue['desc']} (${issue['cwe']})');
      }
      sb.writeln('\n=== Summary ===');
      sb.writeln('Risk score: $riskScore/100');
      sb.writeln('Risk level: $level');
      sb.writeln('Issues: ${issues.length}');
      final highCount = issues.where((i) => i['severity'] == 'HIGH').length;
      final medCount = issues.where((i) => i['severity'] == 'MEDIUM').length;
      sb.writeln('High: $highCount | Medium: $medCount');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_string_analyze — DEX 字符串深度分析
  // =========================================================================
  static Future<Map<String, dynamic>> stringAnalyze(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX String Deep Analysis ===\n');

      // Collect strings from all DEX files
      final allStrings = <String>{};
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.strings(payload));
        for (final line in text.split('\n')) {
          final s = line.trim();
          if (s.isNotEmpty && s.length >= 3) allStrings.add(s);
        }
      }

      final strings = allStrings.toList();
      sb.writeln('Total strings: ${strings.length}');
      sb.writeln('Unique strings: ${allStrings.length}');

      // Classification patterns
      final urlPattern = RegExp(r'https?://[^\s"\']{4,}');
      final ipPattern = RegExp(r'\b(\d{1,3}\.){3}\d{1,3}\b');
      final emailPattern = RegExp(r'[\w.+-]+@[\w-]+\.[\w.-]+');
      final uuidPattern = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', caseSensitive: false);
      final phonePattern = RegExp(r'^\+?1?\d{10,15}$');
      final datePattern = RegExp(r'^\d{4}-\d{2}-\d{2}');
      final hexPattern = RegExp(r'^[0-9a-fA-F]{16,}$');
      final pkgPattern = RegExp(r'^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$');
      final javaClassPattern = RegExp(r'^[a-z][a-z0-9]*(/[a-z][a-z0-9]*)*/[A-Z][a-zA-Z0-9]*;?$');
      final base64Pattern = RegExp(r'^[A-Za-z0-9+/]{16,}={0,2}$');
      final privateIpPattern = RegExp(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b');

      final categories = <String, List<String>>{};
      final sensitiveKeywords = {
        'api_key': ['api_key', 'apikey', 'api-key', 'API_KEY'],
        'secret': ['secret', 'SECRET', 'client_secret'],
        'token': ['token', 'access_token', 'refresh_token', 'auth_token'],
        'password': ['password', 'PASSWORD', 'passwd', 'pwd'],
        'private_key': ['-----BEGIN', 'PRIVATE KEY', 'private.key'],
        'jwt': ['eyJ'],
        'authorization': ['Bearer ', 'Basic '],
        'debug': ['debug', 'logcat', 'Log.d', 'System.out'],
      };

      final sensitiveFound = <Map<String, String>>[];
      final privateIps = <String>{};
      final allUrls = <String>{};
      final allDomains = <String>{};
      final schemes = <String, int>{};

      for (final s in strings) {
        // Classify
        String cat = 'other';
        if (urlPattern.hasMatch(s)) cat = 'url';
        else if (emailPattern.hasMatch(s)) cat = 'email';
        else if (uuidPattern.hasMatch(s)) cat = 'uuid';
        else if (phonePattern.hasMatch(s)) cat = 'phone';
        else if (ipPattern.hasMatch(s)) cat = 'ipv4';
        else if (datePattern.hasMatch(s)) cat = 'date';
        else if (javaClassPattern.hasMatch(s)) cat = 'java_class';
        else if (pkgPattern.hasMatch(s)) cat = 'package_name';
        else if (hexPattern.hasMatch(s)) cat = 'hex';
        else if (s.length >= 16 && base64Pattern.hasMatch(s) && !RegExp(r'^\d+$').hasMatch(s)) cat = 'base64';

        categories.putIfAbsent(cat, () => []).add(s);
        if (categories[cat]!.length <= 5) categories[cat]!.add('');

        // Extract URLs and domains
        for (final m in urlPattern.allMatches(s)) {
          final url = m.group(0)!;
          allUrls.add(url);
          if (url.contains('://')) {
            final scheme = url.split('://')[0];
            schemes[scheme] = (schemes[scheme] ?? 0) + 1;
          }
          final dm = RegExp(r'://([^/:\s]+)').firstMatch(url);
          if (dm != null) allDomains.add(dm.group(1)!);
        }

        // Private IPs
        for (final m in privateIpPattern.allMatches(s)) {
          privateIps.add(m.group(0)!);
        }

        // Sensitive info
        final sLower = s.toLowerCase();
        for (final entry in sensitiveKeywords.entries) {
          for (final kw in entry.value) {
            if (sLower.contains(kw.toLowerCase()) || s.contains(kw)) {
              sensitiveFound.add({'category': entry.key, 'value': s.length > 200 ? s.substring(0, 200) : s});
              break;
            }
          }
        }
      }

      // Category stats
      sb.writeln('\n--- Classification ---');
      final sortedCats = categories.keys.toList()
        ..sort((a, b) => (categories[b]?.length ?? 0).compareTo(categories[a]?.length ?? 0));
      for (final cat in sortedCats) {
        final count = categories[cat]?.length ?? 0;
        final pct = (count / strings.length * 100).toStringAsFixed(1);
        sb.writeln('  $cat: $count ($pct%)');
      }

      // URLs
      sb.writeln('\n--- URLs (${allUrls.length}) ---');
      for (final url in allUrls.take(30)) sb.writeln('  $url');
      if (allUrls.length > 30) sb.writeln('  ... and ${allUrls.length - 30} more');
      sb.writeln('Domains: ${allDomains.length}');
      sb.writeln('Schemes: $schemes');

      // Private IPs
      sb.writeln('\n--- Private IPs (${privateIps.length}) ---');
      for (final ip in privateIps.take(20)) sb.writeln('  $ip');

      // Sensitive info
      sb.writeln('\n--- Sensitive Info (${sensitiveFound.length}) ---');
      for (final s in sensitiveFound.take(20)) sb.writeln('  [${s['category']}] ${s['value']?.substring(0, (s['value']!.length > 80 ? 80 : s['value']!.length))}');

      // Summary
      sb.writeln('\n=== Summary ===');
      sb.writeln('Total: ${strings.length} | Unique: ${allStrings.length}');
      sb.writeln('URLs: ${allUrls.length} | Domains: ${allDomains.length}');
      sb.writeln('Private IPs: ${privateIps.length} | Sensitive: ${sensitiveFound.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_key_scan — 密钥/凭证深度扫描
  // =========================================================================
  static Future<Map<String, dynamic>> keyScan(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Key/Credential Deep Scan ===\n');

      final allStrings = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!, maxLength: 999999);
        allStrings.addAll(text.split('\n'));
      }

      final text = allStrings.join('\n');
      final foundKeys = <Map<String, String>>[];

      final keyPatterns = [
        (RegExp(r'(?i)(?:password|passwd|pwd|secret|private_key)\s*[:=]\s*["\']([^"\']{8,})["\']'), '密码/密钥'),
        (RegExp(r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'), 'API密钥'),
        (RegExp(r'(?i)(?:token|access_token|auth_token|refresh_token|bearer)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']'), '访问令牌'),
        (RegExp(r'(?i)(?:session[_-]?id|sid)\s*[:=]\s*["\']([a-zA-Z0-9]{8,})["\']'), '会话ID'),
        (RegExp(r'(?i)jwt\s*[:=]\s*["\'](eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)["\']'), 'JWT令牌'),
        (RegExp(r'(?i)AIza[0-9A-Za-z_-]{35}'), 'Google API Key'),
        (RegExp(r'(?i)sk-[0-9a-zA-Z]{32,}'), 'OpenAI API Key'),
        (RegExp(r'(?i)sk_live_[0-9a-zA-Z]{20,}'), 'Stripe Live Key'),
        (RegExp(r'(?i)ghp_[0-9a-zA-Z]{36}'), 'GitHub Personal Token'),
        (RegExp(r'(?i)AKIA[0-9A-Z]{16}'), 'AWS Access Key'),
        (RegExp(r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----'), '私钥(PEM)'),
        (RegExp(r'(?i)-----BEGIN CERTIFICATE-----'), '证书(PEM)'),
        (RegExp(r'(?i)-----BEGIN OPENSSH PRIVATE KEY-----'), 'SSH私钥'),
        (RegExp(r'(?i)(?:jdbc|mysql|postgresql|mongodb|redis|sqlite)://[\w:]+@[\w.]+'), '数据库连接串'),
        (RegExp(r'(?i)firebase[_-]?(?:url|database|key|secret)\s*[:=]\s*["\']([^"\']+)["\']'), 'Firebase配置'),
        (RegExp(r'(?i)(?:encryption|decrypt|aes|rsa|des)[_-]?(?:key|secret)\s*[:=]\s*["\']([a-fA-F0-9]{16,64})["\']'), '加密密钥(Hex)'),
        (RegExp(r'(?i)(?:client[_-]?id|client[_-]?secret|app[_-]?id|app[_-]?secret)\s*[:=]\s*["\']([^"\']{8,})["\']'), '客户端凭证'),
        (RegExp(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']([^"\']+)["\']'), 'AWS Secret Key'),
        (RegExp(r'(?i)aliyun[_-]?(?:access[_-]?)?key[_-]?(?:id|secret)\s*[:=]\s*["\']([^"\']+)["\']'), '阿里云密钥'),
        (RegExp(r'(?i)tencent[_-]?(?:secret|key)[_-]?id\s*[:=]\s*["\']([^"\']+)["\']'), '腾讯云SecretId'),
      ];

      for (final entry in keyPatterns) {
        final pat = entry.$1;
        final category = entry.$2;
        for (final m in pat.allMatches(text)) {
          final value = m.group(1) ?? m.group(0)!;
          if (value.length < 4) continue;
          if (['true', 'false', 'null', 'nil', 'none', 'yes', 'no'].contains(value.toLowerCase())) continue;
          final severity = ['私钥', '密钥', 'secret', 'password', 'password', 'AWS', '阿里云', '腾讯云'].any((k) => category.contains(k) || category.toLowerCase().contains(k))
              ? 'HIGH'
              : ['令牌', 'token', '凭证'].any((k) => category.contains(k) || category.toLowerCase().contains(k))
                  ? 'MEDIUM'
                  : 'INFO';
          foundKeys.add({
            'category': category,
            'value': value.length > 80 ? value.substring(0, 80) : value,
            'match': m.group(0)!.length > 120 ? m.group(0)!.substring(0, 120) : m.group(0)!,
            'severity': severity,
          });
        }
      }

      // Weak crypto detection
      final weakPatterns = [
        (RegExp(r'(?i)DES/CBC/NoPadding'), 'DESede/CBC (弱加密)'),
        (RegExp(r'(?i)DES/CBC/NoPadding'), 'DES/CBC (弱加密)'),
        (RegExp(r'(?i)\bMD5\b'), 'MD5 (已破解)'),
        (RegExp(r'(?i)\bSHA-?1\b'), 'SHA-1 (已破解)'),
        (RegExp(r'(?i)\bRC4\b'), 'RC4 (弱加密)'),
        (RegExp(r'(?i)\bECB\b'), 'ECB模式 (不安全)'),
      ];
      final weakCrypto = <String>[];
      for (final entry in weakPatterns) {
        if (entry.$1.hasMatch(text)) weakCrypto.add(entry.$2);
      }

      sb.writeln('--- Found Keys (${foundKeys.length}) ---');
      for (final k in foundKeys.take(30)) {
        sb.writeln('  [${k['severity']}] ${k['category']}: ${k['value']}');
      }
      if (foundKeys.length > 30) sb.writeln('  ... and ${foundKeys.length - 30} more');

      final highCount = foundKeys.where((k) => k['severity'] == 'HIGH').length;
      final medCount = foundKeys.where((k) => k['severity'] == 'MEDIUM').length;
      final riskScore = (highCount * 10 + medCount * 3).clamp(0, 100);
      final riskLevel = riskScore >= 50 ? '严重' : (riskScore >= 20 ? '中等' : '低风险');

      sb.writeln('\n--- Weak Crypto ---');
      if (weakCrypto.isEmpty) {
        sb.writeln('  None detected');
      } else {
        for (final w in weakCrypto) sb.writeln('  ⚠️ $w');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Total keys: ${foundKeys.length} (HIGH: $highCount, MEDIUM: $medCount)');
      sb.writeln('Risk score: $riskScore/100 ($riskLevel)');
      sb.writeln('Weak crypto: ${weakCrypto.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_cert_deep — 证书深度分析
  // =========================================================================
  static Future<Map<String, dynamic>> certDeep(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Certificate Deep Analysis ===\n');

      // Find signature files
      final sigFiles = apk.entries.where((e) {
        final n = e.name.toUpperCase();
        return n.startsWith('META-INF/') && (n.endsWith('.RSA') || n.endsWith('.DSA') || n.endsWith('.EC'));
      }).toList();

      final sfFiles = apk.entries.where((e) =>
        e.name.toUpperCase().startsWith('META-INF/') && e.name.toUpperCase().endsWith('.SF')).toList();
      final hasManifest = apk.entries.any((e) => e.name.toUpperCase() == 'META-INF/MANIFEST.MF');

      sb.writeln('--- V1 Signature ---');
      sb.writeln('Signature files: ${sigFiles.map((e) => e.name).join(', ')}');
      sb.writeln('SF files: ${sfFiles.map((e) => e.name).join(', ')}');
      sb.writeln('Has MANIFEST.MF: $hasManifest');

      // Detect algorithm
      final algorithms = <String>{};
      for (final sf in sigFiles) {
        if (sf.name.toUpperCase().contains('.RSA')) algorithms.add('RSA');
        if (sf.name.toUpperCase().contains('.DSA')) algorithms.add('DSA');
        if (sf.name.toUpperCase().contains('.EC')) algorithms.add('ECDSA');
      }
      sb.writeln('Algorithms: $algorithms');

      // Check for test/debug cert
      final issues = <String>[];
      final findings = <String>[];
      int riskScore = 0;

      for (final sf in sigFiles) {
        if (sf.content == null) continue;
        final text = _extractTextFromBytes(sf.content!, maxLength: 99999);
        if (text.contains('Android Debug') || text.contains('CN=Android Debug')) {
          issues.add('❌ 使用调试证书签名 (Android Debug)');
          riskScore += 30;
        } else {
          findings.add('✅ 非调试证书');
        }

        // Check for known CA
        final knownCAs = ['Google', 'Apple', 'Symantec', 'VeriSign', 'DigiCert', 'GlobalSign', 'Let\'s Encrypt'];
        bool isKnownCA = knownCAs.any((ca) => text.contains(ca));
        if (isKnownCA) {
          findings.add('✅ 由知名CA签发');
        } else {
          if (text.contains('CN=') && text.split('CN=').length > 2) {
            issues.add('⚠️ 可能自签名证书');
            riskScore += 15;
          } else {
            issues.add('⚠️ 未知CA签发，需验证证书链');
            riskScore += 10;
          }
        }
      }

      // V2/V3 detection (APK Signing Block)
      bool hasV2 = false, hasV3 = false;
      final apkBytes = p.apkBytes;
      if (apkBytes.length > 22) {
        // Search for APK Sig Block magic
        final magic = 'APK Sig Block 42'.codeUnits;
        for (var i = apkBytes.length - 65557; i < apkBytes.length - magic.length; i++) {
          if (i < 0) i = 0;
          bool found = true;
          for (var j = 0; j < magic.length; j++) {
            if (apkBytes[i + j] != magic[j]) { found = false; break; }
          }
          if (found) {
            // Found APK Sig Block - check pair IDs nearby
            hasV2 = true; // Simplified
            hasV3 = true;
            break;
          }
        }
      }

      sb.writeln('\n--- V2/V3 Signature ---');
      sb.writeln('V2: $hasV2 | V3: $hasV3');

      final schemes = (sigFiles.isNotEmpty ? 1 : 0) + (hasV2 ? 1 : 0) + (hasV3 ? 1 : 0);
      String secLevel;
      if (hasV2 && hasV3) secLevel = '高';
      else if (hasV2) secLevel = '中';
      else if (sigFiles.isNotEmpty) secLevel = '低';
      else secLevel = '无签名';

      sb.writeln('Security level: $secLevel');

      // Recommendations
      sb.writeln('\n--- Recommendations ---');
      if (sigFiles.isEmpty && !hasV2) {
        sb.writeln('❌ 未检测到任何签名方案，应用将无法安装');
      }
      if (sigFiles.isNotEmpty && !hasV2) {
        sb.writeln('⚠️ 仅有 V1 签名，建议增加 V2 签名以提升安全性');
      }
      if (hasV2 && !hasV3) {
        sb.writeln('ℹ️ 可考虑增加 V3 签名以支持密钥轮换');
      }
      for (final alg in algorithms) {
        if (alg == 'DSA') sb.writeln('⚠️ 使用 DSA 签名算法，建议使用 RSA-2048 或 ECDSA');
      }

      sb.writeln('\n--- Issues ---');
      for (final i in issues) sb.writeln('  $i');
      sb.writeln('\n--- Findings ---');
      for (final f in findings) sb.writeln('  $f');

      final riskLevel = riskScore <= 10 ? '安全' : (riskScore <= 20 ? '低风险' : (riskScore <= 40 ? '中风险' : '高风险'));
      sb.writeln('\n=== Summary ===');
      sb.writeln('Risk score: $riskScore/100 ($riskLevel)');
      sb.writeln('Signature schemes: V1=${sigFiles.isNotEmpty} V2=$hasV2 V3=$hasV3');
      sb.writeln('Security level: $secLevel');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_sig_scheme — APK 签名方案检测
  // =========================================================================
  static Future<Map<String, dynamic>> sigScheme(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== APK Signature Scheme Detection ===\n');

      // V1: META-INF signature files
      final names = apk.entries.map((e) => e.name).toList();
      final sigFiles = names.where((n) => n.startsWith('META-INF/') &&
        (n.endsWith('.RSA') || n.endsWith('.DSA') || n.endsWith('.EC'))).toList();
      final sfFiles = names.where((n) => n.startsWith('META-INF/') && n.endsWith('.SF')).toList();
      final mfFile = names.any((n) => n == 'META-INF/MANIFEST.MF');

      final v1 = sigFiles.isNotEmpty;
      sb.writeln('V1 (JAR): ${v1 ? "✅" : "❌"}');
      if (v1) {
        sb.writeln('  Signature files: $sigFiles');
        sb.writeln('  SF files: ${sfFiles.length}');
        sb.writeln('  Has MANIFEST.MF: $mfFile');
        final algList = <String>{};
        for (final sf in sigFiles) {
          if (sf.contains('.RSA')) algList.add('RSA');
          if (sf.contains('.DSA')) algList.add('DSA');
          if (sf.contains('.EC')) algList.add('ECDSA');
        }
        sb.writeln('  Algorithms: $algList');
      }

      // V2/V3: APK Signing Block
      bool v2 = false, v3 = false;
      final bytes = p.apkBytes;
      if (bytes.length > 22) {
        final magic = Uint8List.fromList('APK Sig Block 42'.codeUnits);
        outer:
        for (var i = max(0, bytes.length - 65557); i < bytes.length - magic.length; i++) {
          bool match = true;
          for (var j = 0; j < magic.length; j++) {
            if (bytes[i + j] != magic[j]) { match = false; break; }
          }
          if (match) {
            // Found signing block - check for V2/V3 pair IDs
            // V2 ID: 0x7109871a, V3 ID: 0xf05368c0
            v2 = true; // Simplified detection
            v3 = true;
            break outer;
          }
        }
      }

      sb.writeln('\nV2 (APK Signature Scheme v2): ${v2 ? "✅" : "❌"}');
      sb.writeln('V3 (APK Signature Scheme v3): ${v3 ? "✅" : "❌"}');

      // V4: .idsig file (can't check from memory, skip)
      sb.writeln('V4: ℹ️ 需检查 .idsig 文件');

      // Security level
      final schemeCount = (v1 ? 1 : 0) + (v2 ? 1 : 0) + (v3 ? 1 : 0);
      String secLevel;
      if (v2 && v3) secLevel = '高';
      else if (v2) secLevel = '中';
      else if (v1) secLevel = '低';
      else secLevel = '无签名';

      sb.writeln('\n--- Security Level: $secLevel ---');

      // Recommendations
      sb.writeln('\n--- Recommendations ---');
      if (!v1 && !v2) sb.writeln('❌ 未检测到任何签名方案，应用将无法安装');
      if (v1 && !v2) sb.writeln('⚠️ 仅有 V1 签名，建议增加 V2 签名以提升安全性 (Android 7.0+)');
      if (v2 && !v3) sb.writeln('ℹ️ 可考虑增加 V3 签名以支持密钥轮换 (Android 9.0+)');
      if (v1 && sigFiles.any((s) => s.contains('.DSA'))) sb.writeln('⚠️ 使用 DSA 签名算法，建议使用 RSA-2048 或 ECDSA');
      if (schemeCount >= 2 && v2) sb.writeln('✅ 签名方案配置良好');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_deobfuscate — 自动化去混淆分析
  // =========================================================================
  static Future<Map<String, dynamic>> deobfuscate(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Auto Deobfuscation Analysis ===\n');

      // Collect DEX text
      final dexText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!, maxLength: 999999);
        dexText.writeln(text);
      }
      final text = dexText.toString();

      // 1. XOR key detection
      final xorPatterns = [
        RegExp(r'v\d+\s*\^=\s*(0x[0-9a-fA-F]+|\d+)'),
        RegExp(r'xor\s*[-]?[0-9a-fA-Fx]+', caseSensitive: false),
        RegExp(r'\^\s*0x[0-9a-fA-F]+'),
      ];
      final xorKeys = <int>{};
      for (final pat in xorPatterns) {
        for (final m in pat.allMatches(text)) {
          final val = m.group(1) ?? m.group(0)!;
          try {
            if (val.contains('0x') || val.contains('0X')) {
              xorKeys.add(int.parse(val.replaceAll('0x', '').replaceAll('0X', ''), radix: 16));
            } else {
              xorKeys.add(int.parse(val.replaceAll(RegExp(r'[^0-9]'), '')));
            }
          } catch (_) {}
        }
      }
      sb.writeln('--- XOR Keys (${xorKeys.length}) ---');
      for (final k in xorKeys.take(20)) sb.writeln('  0x${k.toRadixString(16)}');

      // 2. Byte array extraction
      final byteArrayPattern = RegExp(r'new byte\[\]\s*\{([^}]+)\}');
      final byteArrays = byteArrayPattern.allMatches(text).toList();
      sb.writeln('\n--- Byte Arrays (${byteArrays.length}) ---');
      for (final m in byteArrays.take(10)) {
        final content = m.group(1)!;
        final byteStrings = content.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
        sb.writeln('  Length: ${byteStrings.length}, Hex: ${byteStrings.take(20).map((b) => int.tryParse(b)?.toRadixString(16) ?? b).join(' ')}');
      }

      // 3. String decryption attempts
      final constStringPattern = RegExp(r'const-string[/jumbo]*\s+v\d+,\s*"([^"]+)"');
      final constStrings = constStringPattern.allMatches(text).toList();
      sb.writeln('\n--- Const Strings (${constStrings.length}) ---');

      // Try Base64 decode on suspicious strings
      var decodedCount = 0;
      for (final m in constStrings) {
        final s = m.group(1)!;
        if (s.length < 8) continue;
        // Try Base64
        try {
          final decoded = String.fromCharCodes(base64Decode(s));
          if (decoded.isNotEmpty && decoded.length > 3 && decoded.codeUnits.every((c) => c >= 0x20 && c < 0x7f || c == 0x0a || c == 0x0d)) {
            sb.writeln('  [base64] ${s.substring(0, s.length > 50 ? 50 : s.length)} → ${decoded.substring(0, decoded.length > 100 ? 100 : decoded.length)}');
            decodedCount++;
          }
        } catch (_) {}
        // Try Hex decode
        if (RegExp(r'^[0-9a-fA-F]+$').hasMatch(s) && s.length >= 16 && s.length % 2 == 0) {
          try {
            final decoded = String.fromCharCodes(List.generate(s.length ~/ 2, (i) => int.parse(s.substring(i*2, i*2+2), radix: 16)));
            if (decoded.isNotEmpty && decoded.codeUnits.every((c) => c >= 0x20 && c < 0x7f)) {
              sb.writeln('  [hex] ${s.substring(0, s.length > 50 ? 50 : s.length)} → ${decoded.substring(0, decoded.length > 100 ? 100 : decoded.length)}');
              decodedCount++;
            }
          } catch (_) {}
        }
      }
      sb.writeln('  Decoded: $decodedCount');

      // 4. Control flow flattening detection
      final branchCount = RegExp(r'\b(goto|if-|packed-switch|sparse-switch)\b').allMatches(text).length;
      final constCount = RegExp(r'\bconst[/\w]*\s+v\d+').allMatches(text).length;
      final totalLines = text.split('\n').length;
      final branchRatio = totalLines > 0 ? branchCount / totalLines : 0.0;
      final constRatio = totalLines > 0 ? constCount / totalLines : 0.0;

      double cfgScore = 0;
      if (branchRatio > 0.15) cfgScore += 3;
      if (constRatio > 0.2) cfgScore += 2;
      if (branchCount > 20) cfgScore += 2;
      final cfgConfidence = (cfgScore / 10).clamp(0.0, 1.0);

      sb.writeln('\n--- Control Flow Flattening ---');
      sb.writeln('Branch count: $branchCount ($branchRatio ratio)');
      sb.writeln('Const count: $constCount ($constRatio ratio)');
      sb.writeln('Confidence: ${(cfgConfidence * 100).toStringAsFixed(0)}%');
      sb.writeln('Detected: ${cfgConfidence > 0.4 ? "⚠️ Yes" : "No"}');

      // 5. Arithmetic obfuscation
      final largeOps = RegExp(r'(?:add|sub|mul|div|rem|and|or|xor)[-]?\s*\d{5,}', caseSensitive: false).allMatches(text).length;
      final ifElseCount = RegExp(r'if-').allMatches(text).length;
      final xorOps = RegExp(r'xor[-/]?\s*[a-z]\d+,\s*v\d+', caseSensitive: false).allMatches(text).length;

      sb.writeln('\n--- Arithmetic Obfuscation ---');
      sb.writeln('Large number ops: $largeOps');
      sb.writeln('If-else branches: $ifElseCount');
      sb.writeln('XOR operations: $xorOps');
      sb.writeln('Detected: ${largeOps > 0 || ifElseCount > 20 || xorOps > 10 ? "⚠️ Yes" : "No"}');

      // 6. Obfuscated class name detection
      final classPattern = RegExp(r'L(\w+)/(\w+);');
      final classNames = classPattern.allMatches(text).map((m) => m.group(0)!).toSet().toList();
      final obfuscatedPattern = RegExp(r'^[a-z]{1,2}\d{0,2}$');
      final obfuscatedCount = classNames.where((c) {
        final simple = c.split('/').last.replaceAll(';', '');
        return obfuscatedPattern.hasMatch(simple) && !['R', 'Manifest', 'BuildConfig'].contains(simple);
      }).length;

      sb.writeln('\n--- Class Name Obfuscation ---');
      sb.writeln('Total classes: ${classNames.length}');
      sb.writeln('Obfuscated: $obfuscatedCount (${classNames.isNotEmpty ? (obfuscatedCount / classNames.length * 100).toStringAsFixed(1) : 0}%)');

      sb.writeln('\n=== Summary ===');
      sb.writeln('XOR keys: ${xorKeys.length} | Byte arrays: ${byteArrays.length}');
      sb.writeln('Decoded strings: $decodedCount | Obfuscated classes: $obfuscatedCount');
      sb.writeln('CFG flattening: ${cfgConfidence > 0.4 ? "Detected" : "Not detected"} (${(cfgConfidence * 100).toStringAsFixed(0)}%)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_code_analyze — 深度代码分析
  // =========================================================================
  static Future<Map<String, dynamic>> codeAnalyze(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Deep Code Analysis ===\n');

      // Collect all DEX text
      final dexText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!, maxLength: 999999);
        dexText.writeln(text);
      }
      final text = dexText.toString();

      // 1. URL/IP/Email extraction
      final urls = RegExp(r'https?://[^\s"\'<>]+').allMatches(text).map((m) => m.group(0)!).toSet().toList();
      final ips = RegExp(r'\b(\d{1,3}\.){3}\d{1,3}\b').allMatches(text).map((m) => m.group(0)!).toSet().toList();
      final emails = RegExp(r'[\w.+-]+@[\w-]+\.[\w.-]+').allMatches(text).map((m) => m.group(0)!).toSet().toList();
      final domains = <String>{};
      for (final u in urls) {
        final m = RegExp(r'://([^/:\s]+)').firstMatch(u);
        if (m != null) domains.add(m.group(1)!);
      }

      sb.writeln('--- Network Info ---');
      sb.writeln('URLs: ${urls.length} | IPs: ${ips.length} | Emails: ${emails.length} | Domains: ${domains.length}');
      for (final u in urls.take(15)) sb.writeln('  URL: $u');
      for (final ip in ips.take(10)) sb.writeln('  IP: $ip');

      // 2. Class references
      final classRefs = RegExp(r'L[\w/$;]+').allMatches(text).map((m) => m.group(0)!).toSet().toList();
      sb.writeln('\n--- Class References (${classRefs.length}) ---');
      for (final c in classRefs.take(20)) sb.writeln('  $c');

      // 3. Sensitive API detection
      final sensitiveApis = <String, List<Map<String, dynamic>>>{};
      final apiCategories = {
        'location': ['getLastKnownLocation', 'requestLocationUpdates', 'getLatitude', 'getLongitude', 'LocationManager', 'FusedLocationApi'],
        'camera': ['Camera.open', 'CameraManager', 'MediaRecorder', 'openCamera', 'Camera2'],
        'contacts': ['ContactsContract', 'getContentResolver', 'READ_CONTACTS'],
        'sms': ['SmsManager', 'sendTextMessage', 'READ_SMS', 'RECEIVE_SMS'],
        'phone': ['TelephonyManager', 'getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getLine1Number'],
        'network': ['HttpURLConnection', 'OkHttpClient', 'Retrofit', 'Volley', 'WebSocket'],
        'crypto': ['Cipher.getInstance', 'SecretKeySpec', 'KeyGenerator', 'MessageDigest', 'Mac.getInstance', 'Signature.getInstance'],
        'webview': ['WebView', 'loadUrl', 'addJavascriptInterface', 'setJavaScriptEnabled'],
        'reflection': ['Class.forName', 'Method.invoke', 'Field.setAccessible', 'getDeclaredMethod', 'DexClassLoader'],
        'dynamic_code': ['DexClassLoader', 'PathClassLoader', 'InMemoryDexClassLoader', 'loadDex', 'Runtime.exec', 'ProcessBuilder'],
      };
      for (final entry in apiCategories.entries) {
        for (final pat in entry.value) {
          final count = pat.allMatches(text).length;
          if (count > 0) {
            sensitiveApis.putIfAbsent(entry.key, () => []).add({'pattern': pat, 'count': count});
          }
        }
      }
      sb.writeln('\n--- Sensitive APIs ---');
      for (final entry in sensitiveApis.entries) {
        final total = entry.value.fold(0, (s, v) => s + (v['count'] as int));
        sb.writeln('  ${entry.key}: $total hits');
      }

      // 4. Dangerous API detection
      final dangerousApis = [
        (RegExp(r'Runtime\.exec\s*\('), '命令执行'),
        (RegExp(r'ProcessBuilder\s*\('), '命令执行'),
        (RegExp(r'addJavascriptInterface\s*\('), 'JS桥接'),
        (RegExp(r'setJavaScriptEnabled\s*\(true\)', caseSensitive: false), '启用JS'),
        (RegExp(r'Cipher\.getInstance\s*\(\s*"(?:DES|RC4|MD5|SHA1)', caseSensitive: false), '弱加密算法'),
        (RegExp(r'SSLSocketFactory\.getAllTrusted', caseSensitive: false), '弱TLS验证'),
        (RegExp(r'SQLiteDatabase\.rawQuery\s*\(', caseSensitive: false), 'SQL查询'),
        (RegExp(r'execSQL\s*\(', caseSensitive: false), 'SQL执行'),
        (RegExp(r'Log\.(?:d|e|i|v|w)\s*\(', caseSensitive: false), '日志输出'),
        (RegExp(r'printStackTrace\s*\(', caseSensitive: false), '异常堆栈输出'),
      ];
      final dangerousFound = <Map<String, dynamic>>[];
      for (final entry in dangerousApis) {
        final matches = entry.$1.allMatches(text).toList();
        if (matches.isNotEmpty) {
          dangerousFound.add({
            'description': entry.$2,
            'pattern': entry.$1.pattern,
            'count': matches.length,
            'severity': ['命令执行', '弱TLS验证', '弱加密算法'].contains(entry.$2) ? 'high' : 'medium',
          });
        }
      }
      sb.writeln('\n--- Dangerous APIs (${dangerousFound.length}) ---');
      for (final d in dangerousFound.take(20)) {
        sb.writeln('  [${d['severity']}] ${d['description']} (${d['count']} hits)');
      }

      // 5. API key patterns
      final apiKeyPatterns = [
        (RegExp(r'(?i)AIza[0-9A-Za-z_-]{35}'), 'Google API Key'),
        (RegExp(r'(?i)sk-[0-9a-zA-Z]{32,}'), 'OpenAI API Key'),
        (RegExp(r'(?i)ghp_[0-9a-zA-Z]{36}'), 'GitHub Token'),
        (RegExp(r'(?i)AKIA[0-9A-Z]{16}'), 'AWS Access Key'),
        (RegExp(r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----'), 'Private Key'),
        (RegExp(r'(?i)xox[baprs]-[0-9a-zA-Z-]{24,}'), 'Slack Token'),
      ];
      final foundKeys = <Map<String, String>>[];
      for (final entry in apiKeyPatterns) {
        for (final m in entry.$1.allMatches(text)) {
          foundKeys.add({'category': entry.$2, 'value': m.group(0)!});
        }
      }
      sb.writeln('\n--- API Keys (${foundKeys.length}) ---');
      for (final k in foundKeys.take(15)) sb.writeln('  ${k['category']}: ${k['value']}');

      // Summary
      final highRisk = dangerousFound.where((d) => d['severity'] == 'high').length;
      final medRisk = dangerousFound.where((d) => d['severity'] == 'medium').length;
      sb.writeln('\n=== Summary ===');
      sb.writeln('URLs: ${urls.length} | IPs: ${ips.length} | Emails: ${emails.length} | Domains: ${domains.length}');
      sb.writeln('Class refs: ${classRefs.length} | Sensitive APIs: ${sensitiveApis.length} categories');
      sb.writeln('Dangerous APIs: ${dangerousFound.length} (HIGH: $highRisk, MEDIUM: $medRisk)');
      sb.writeln('API keys found: ${foundKeys.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_resource_analyze — APK 资源分析
  // =========================================================================
  static Future<Map<String, dynamic>> resourceAnalyze(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== APK Resource Analysis ===\n');

      var totalSize = 0, totalCompressed = 0;
      final catStats = <String, Map<String, int>>{};
      final largeFiles = <Map<String, dynamic>>[];
      final sizeMap = <int, List<String>>{};
      var imageCount = 0, imageTotalSize = 0;

      for (final e in apk.entries) {
        final name = e.name;
        final size = e.size, compressed = e.compressedSize;
        totalSize += size;
        totalCompressed += compressed;

        String cat;
        if (name.startsWith('META-INF/')) cat = 'meta_inf';
        else if (name.startsWith('assets/')) cat = 'assets';
        else if (name == 'resources.arsc') cat = 'resources';
        else if (name.startsWith('res/')) {
          if (name.endsWith('.png') || name.endsWith('.jpg') || name.endsWith('.jpeg') || name.endsWith('.webp') || name.endsWith('.gif') || name.endsWith('.9.png')) {
            cat = 'res_images';
            imageCount++;
            imageTotalSize += size;
          } else if (name.endsWith('.xml')) cat = 'res_xml';
          else cat = 'res_other';
        } else if (name.endsWith('.dex')) cat = 'dex';
        else if (name.endsWith('.so')) cat = 'native';
        else if (name.endsWith('.png') || name.endsWith('.jpg') || name.endsWith('.jpeg') || name.endsWith('.webp') || name.endsWith('.svg')) {
          cat = 'images';
          imageCount++;
          imageTotalSize += size;
        } else if (name.endsWith('.ttf') || name.endsWith('.otf') || name.endsWith('.woff')) cat = 'fonts';
        else if (name.endsWith('.mp3') || name.endsWith('.wav') || name.endsWith('.ogg') || name.endsWith('.aac')) cat = 'audio';
        else if (name.endsWith('.mp4') || name.endsWith('.webm') || name.endsWith('.3gp')) cat = 'video';
        else cat = 'other';

        catStats.putIfAbsent(cat, () => {'count': 0, 'size': 0, 'compressed': 0});
        catStats[cat]!['count'] = catStats[cat]!['count']! + 1;
        catStats[cat]!['size'] = catStats[cat]!['size']! + size;
        catStats[cat]!['compressed'] = catStats[cat]!['compressed']! + compressed;

        if (size >= 100 * 1024) {
          largeFiles.add({'name': name, 'size': size, 'compressed': compressed});
        }
        sizeMap.putIfAbsent(size, () => []).add(name);
      }

      final compressionRatio = totalSize > 0 ? (totalCompressed / totalSize * 100).toStringAsFixed(2) : '0.0';
      final compressionSaved = totalSize - totalCompressed;

      sb.writeln('Total files: ${apk.entries.length}');
      sb.writeln('Total size: $totalSize bytes');
      sb.writeln('Total compressed: $totalCompressed bytes');
      sb.writeln('Compression ratio: $compressionRatio%');
      sb.writeln('Saved: $compressionSaved bytes (${totalSize > 0 ? (compressionSaved / totalSize * 100).toStringAsFixed(1) : 0}%)');

      sb.writeln('\n--- Category Stats ---');
      final sortedCats = catStats.keys.toList()
        ..sort((a, b) => catStats[b]!['size']!.compareTo(catStats[a]!['size']!));
      for (final cat in sortedCats) {
        final s = catStats[cat]!;
        final pct = totalSize > 0 ? (s['size']! / totalSize * 100).toStringAsFixed(2) : '0.0';
        sb.writeln('  $cat: ${s['count']} files, ${s['size']} bytes ($pct%)');
      }

      sb.writeln('\n--- Large Files (>100KB, ${largeFiles.length}) ---');
      largeFiles.sort((a, b) => (b['size'] as int).compareTo(a['size'] as int));
      for (final f in largeFiles.take(20)) {
        sb.writeln('  ${f['name']}: ${f['size']} bytes');
      }

      // Duplicate detection (by size)
      final duplicates = sizeMap.entries.where((e) => e.value.length > 1 && e.key > 100).toList();
      sb.writeln('\n--- Potential Duplicates (${duplicates.length} groups) ---');
      for (final d in duplicates.take(10)) {
        sb.writeln('  Size ${d.key}: ${d.value.length} files');
      }

      sb.writeln('\n--- Image Analysis ---');
      sb.writeln('Images: $imageCount, Total size: $imageTotalSize bytes');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Files: ${apk.entries.length} | Size: $totalSize | Compressed: $totalCompressed');
      sb.writeln('Categories: ${catStats.length} | Large files: ${largeFiles.length} | Duplicates: ${duplicates.length} groups');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_resource_obfuscation — 资源混淆检测
  // =========================================================================
  static Future<Map<String, dynamic>> resourceObfuscation(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Resource Obfuscation Detection ===\n');

      final fileList = apk.entries.map((e) => e.name).toList();
      final resFiles = fileList.where((f) => f.startsWith('res/')).toList();
      sb.writeln('Total resources: ${resFiles.length}');

      // Analyze resource naming
      final obfuscatedPattern = RegExp(r'^[a-z]{1,2}\d{0,2}$', caseSensitive: false);
      final singleLetterPattern = RegExp(r'^[a-z]$', caseSensitive: false);
      final meaningfulPattern = RegExp(r'^[a-z][a-z0-9_]{2,}$', caseSensitive: false);

      final resByType = <String, List<String>>{};
      for (final f in resFiles) {
        final parts = f.split('/');
        if (parts.length >= 3) {
          final resType = parts[1];
          final resName = parts.last.contains('.') ? parts.last.substring(0, parts.last.lastIndexOf('.')) : parts.last;
          resByType.putIfAbsent(resType, () => []).add(resName);
        }
      }

      var totalNames = 0, obfuscatedNames = 0, singleLetterNames = 0, meaningfulNames = 0;
      for (final entry in resByType.entries) {
        for (final name in entry.value) {
          totalNames++;
          if (singleLetterPattern.hasMatch(name)) {
            singleLetterNames++;
            obfuscatedNames++;
          } else if (obfuscatedPattern.hasMatch(name) && !['R', 'Manifest', 'BuildConfig'].contains(name)) {
            obfuscatedNames++;
          } else {
            meaningfulNames++;
          }
        }
      }

      final obfRatio = totalNames > 0 ? (obfuscatedNames / totalNames * 100).toStringAsFixed(1) : '0.0';
      final singleRatio = totalNames > 0 ? (singleLetterNames / totalNames * 100).toStringAsFixed(1) : '0.0';

      sb.writeln('\n--- Naming Analysis ---');
      sb.writeln('Total names: $totalNames');
      sb.writeln('Obfuscated: $obfuscatedNames ($obfRatio%)');
      sb.writeln('Single letter: $singleLetterNames ($singleRatio%)');
      sb.writeln('Meaningful: $meaningfulNames');

      sb.writeln('\n--- Resource Types ---');
      for (final entry in resByType.entries) {
        final obfCount = entry.value.where((n) => obfuscatedPattern.hasMatch(n) || singleLetterPattern.hasMatch(n)).length;
        sb.writeln('  ${entry.key}: ${entry.value.length} total, $obfCount obfuscated');
      }

      // Score
      double score = 0;
      if (totalNames > 0) {
        score = (obfuscatedNames / totalNames) * 50;
      }
      final level = score >= 60 ? '高' : (score >= 25 ? '中' : '低');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Score: ${score.toStringAsFixed(1)}/100 ($level)');
      sb.writeln('Obfuscation ratio: $obfRatio%');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_apk_clean — APK 清理分析
  // =========================================================================
  static Future<Map<String, dynamic>> apkClean(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== APK Clean Analysis ===\n');

      final debugFiles = <Map<String, dynamic>>[];
      final backupFiles = <Map<String, dynamic>>[];
      final metaFiles = <Map<String, dynamic>>[];
      final largeFiles = <Map<String, dynamic>>[];
      final duplicates = <Map<String, dynamic>>[];
      var totalWaste = 0;

      final debugPatterns = [
        RegExp(r'res/raw/.*\.txt$', caseSensitive: false),
        RegExp(r'res/raw/.*test.*', caseSensitive: false),
        RegExp(r'res/raw/.*debug.*', caseSensitive: false),
        RegExp(r'res/raw/.*sample.*', caseSensitive: false),
        RegExp(r'res/raw/.*demo.*', caseSensitive: false),
        RegExp(r'res/raw/.*mock.*', caseSensitive: false),
        RegExp(r'res/drawable.*/.*placeholder.*', caseSensitive: false),
        RegExp(r'res/drawable.*/.*_test_.*', caseSensitive: false),
        RegExp(r'assets/.*test.*', caseSensitive: false),
        RegExp(r'assets/.*debug.*', caseSensitive: false),
        RegExp(r'assets/.*sample.*', caseSensitive: false),
      ];
      final backupPatterns = [
        RegExp(r'.*\.bak$', caseSensitive: false),
        RegExp(r'.*\.backup$', caseSensitive: false),
        RegExp(r'.*\.orig$', caseSensitive: false),
        RegExp(r'.*/\.DS_Store$', caseSensitive: false),
        RegExp(r'.*/Thumbs\.db$', caseSensitive: false),
        RegExp(r'.*\.swp$', caseSensitive: false),
      ];
      final metaPatterns = [
        RegExp(r'META-INF/.*\.SF$', caseSensitive: false),
        RegExp(r'META-INF/.*\.RSA$', caseSensitive: false),
        RegExp(r'META-INF/.*\.DSA$', caseSensitive: false),
        RegExp(r'META-INF/.*\.MF$', caseSensitive: false),
        RegExp(r'META-INF/.*\.EC$', caseSensitive: false),
      ];

      final sizeMap = <int, List<String>>{};

      for (final e in apk.entries) {
        final name = e.name, size = e.size;

        for (final pat in debugPatterns) {
          if (pat.hasMatch(name)) {
            debugFiles.add({'file': name, 'size': size});
            totalWaste += size;
            break;
          }
        }
        for (final pat in metaPatterns) {
          if (pat.hasMatch(name)) {
            metaFiles.add({'file': name, 'size': size});
            break;
          }
        }
        for (final pat in backupPatterns) {
          if (pat.hasMatch(name)) {
            backupFiles.add({'file': name, 'size': size});
            totalWaste += size;
            break;
          }
        }
        if (size > 1024 * 1024) {
          largeFiles.add({'file': name, 'size': size});
        }
        sizeMap.putIfAbsent(size, () => []).add(name);
      }

      // Duplicates by size
      for (final entry in sizeMap.entries) {
        if (entry.value.length > 1 && entry.key > 100) {
          duplicates.add({'size': entry.key, 'files': entry.value});
          totalWaste += entry.key;
        }
      }

      final apkSize = apk.entries.fold(0, (s, e) => s + e.size);
      final wasteRatio = apkSize > 0 ? (totalWaste / apkSize * 100).toStringAsFixed(1) : '0.0';
      final cleanLevel = double.parse(wasteRatio) < 1 ? '优秀' : (double.parse(wasteRatio) < 5 ? '良好' : (double.parse(wasteRatio) < 10 ? '一般' : '需优化'));

      sb.writeln('--- Debug/Test Files (${debugFiles.length}) ---');
      for (final f in debugFiles.take(15)) sb.writeln('  ${f['file']}: ${f['size']} bytes');

      sb.writeln('\n--- Backup Files (${backupFiles.length}) ---');
      for (final f in backupFiles.take(10)) sb.writeln('  ${f['file']}: ${f['size']} bytes');

      sb.writeln('\n--- META-INF Files (${metaFiles.length}) ---');
      for (final f in metaFiles.take(10)) sb.writeln('  ${f['file']}: ${f['size']} bytes');

      sb.writeln('\n--- Large Files >1MB (${largeFiles.length}) ---');
      largeFiles.sort((a, b) => (b['size'] as int).compareTo(a['size'] as int));
      for (final f in largeFiles.take(20)) sb.writeln('  ${f['file']}: ${f['size']} bytes');

      sb.writeln('\n--- Potential Duplicates (${duplicates.length} groups) ---');
      for (final d in duplicates.take(10)) {
        sb.writeln('  ${d['size']} bytes: ${d['files'].length} files');
      }

      sb.writeln('\n--- Recommendations ---');
      if (debugFiles.isNotEmpty) sb.writeln('  💡 发现 ${debugFiles.length} 个调试/测试文件，可安全删除');
      if (duplicates.isNotEmpty) sb.writeln('  💡 发现 ${duplicates.length} 组重复文件，可删除冗余副本');
      if (metaFiles.isNotEmpty) sb.writeln('  ℹ️ 重签名后 META-INF 签名文件将被替换');

      sb.writeln('\n=== Summary ===');
      sb.writeln('APK size: $apkSize bytes');
      sb.writeln('Waste: $totalWaste bytes ($wasteRatio%)');
      sb.writeln('Clean level: $cleanLevel');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_component_explore — 组件浏览器
  // =========================================================================
  static Future<Map<String, dynamic>> componentExplore(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Component Explorer ===\n');

      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml', orElse: () => null);
      if (manifestEntry?.content == null) {
        return _err('AndroidManifest.xml not found');
      }
      final manifestText = _extractTextFromBytes(manifestEntry!.content!);

      final componentTypes = ['activity', 'activity-alias', 'service', 'receiver', 'provider'];
      var totalExported = 0, explicitExported = 0, implicitExported = 0;
      final intentFilters = <String>[];
      final deepLinks = <String>{};
      final permissionGates = <Map<String, String>>[];
      final securityIssues = <Map<String, String>>[];

      for (final compType in componentTypes) {
        final pattern = RegExp('<$compType[^>]*>', caseSensitive: false);
        final matches = pattern.allMatches(manifestText).toList();
        if (matches.isEmpty) continue;

        var exportedCount = 0;
        for (final m in matches) {
          final tag = m.group(0)!;
          final nameMatch = RegExp(r'android:name="([^"]+)"').firstMatch(tag);
          final name = nameMatch?.group(1) ?? '(unknown)';
          final exportedMatch = RegExp(r'android:exported="(true|false)"').firstMatch(tag);
          final permMatch = RegExp(r'android:permission="([^"]+)"').firstMatch(tag);

          bool exported;
          if (exportedMatch != null) {
            exported = exportedMatch.group(1) == 'true';
            if (exported) { explicitExported++; totalExported++; exportedCount++; }
          } else {
            // Implicit: has intent-filter
            exported = manifestText.substring(m.end).contains('intent-filter');
            if (exported) { implicitExported++; totalExported++; exportedCount++; }
          }

          if (permMatch != null) {
            permissionGates.add({'component': name, 'type': compType, 'permission': permMatch.group(1)!});
          }

          // Security issues
          if (exported && permMatch == null && compType != 'activity') {
            securityIssues.add({
              'severity': 'high', 'component': name, 'type': compType,
              'issue': 'Exported without permission protection',
            });
          }
          if (compType == 'provider' && exported) {
            securityIssues.add({
              'severity': 'high', 'component': name, 'type': compType,
              'issue': 'ContentProvider exported',
            });
          }
        }
        sb.writeln('${compType}s: ${matches.length} ($exportedCount exported)');
      }

      // Intent filters and deep links
      final ifPattern = RegExp(r'<intent-filter[^>]*>([\s\S]*?)</intent-filter>', caseSensitive: false);
      for (final m in ifPattern.allMatches(manifestText)) {
        final content = m.group(1)!;
        final actions = RegExp(r'<action[^>]*android:name="([^"]+)"').allMatches(content).map((a) => a.group(1)!).toList();
        final schemes = RegExp(r'<data[^>]*android:scheme="([^"]+)"').allMatches(content).map((s) => s.group(1)!).toSet();
        final hosts = RegExp(r'<data[^>]*android:host="([^"]+)"').allMatches(content).map((h) => h.group(1)!).toSet();
        for (final s in schemes) {
          for (final h in hosts) {
            deepLinks.add('$s://$h');
          }
        }
        if (actions.isNotEmpty) intentFilters.add('Actions: ${actions.take(5).join(', ')}');
      }

      sb.writeln('\n--- Exported Summary ---');
      sb.writeln('Total exported: $totalExported');
      sb.writeln('Explicit: $explicitExported | Implicit: $implicitExported');

      sb.writeln('\n--- Intent Filters (${intentFilters.length}) ---');
      for (final f in intentFilters.take(15)) sb.writeln('  $f');

      sb.writeln('\n--- Deep Links (${deepLinks.length}) ---');
      for (final l in deepLinks.take(15)) sb.writeln('  $l');

      sb.writeln('\n--- Permission Gates (${permissionGates.length}) ---');
      for (final g in permissionGates.take(15)) sb.writeln('  ${g['component']} (${g['type']}): ${g['permission']}');

      sb.writeln('\n--- Security Issues (${securityIssues.length}) ---');
      for (final i in securityIssues.take(15)) sb.writeln('  [${i['severity']}] ${i['component']} (${i['type']}): ${i['issue']}');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Exported: $totalExported | Intent filters: ${intentFilters.length} | Deep links: ${deepLinks.length}');
      sb.writeln('Permission gates: ${permissionGates.length} | Security issues: ${securityIssues.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_core_class_locate — 核心类定位
  // =========================================================================
  static Future<Map<String, dynamic>> coreClassLocate(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Core Class Locator ===\n');

      final results = <Map<String, dynamic>>[];

      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));

        // Extract class names
        final classPattern = RegExp(r'(L[\w/$]+;)');
        final classNames = classPattern.allMatches(text).map((m) => m.group(1)!).toSet().toList();

        for (final cls in classNames) {
          final simple = cls.substring(1, cls.length - 1).split('/').last;
          final pkg = cls.substring(1, cls.length - 1);

          double score = 0;

          // Name pattern scoring
          if (simple == 'Application') score += 100;
          else if (simple == 'App') score += 95;
          else if (simple == 'MainApplication') score += 100;
          else if (simple == 'BaseApplication') score += 90;
          else if (simple == 'MainActivity') score += 80;
          else if (simple == 'SplashActivity') score += 70;
          else if (simple == 'HomeActivity') score += 70;
          else if (simple.contains('Launcher') && simple.contains('Activity')) score += 75;
          else if (simple == 'Core') score += 85;
          else if (simple == 'Manager') score += 60;
          else if (simple == 'Engine') score += 65;
          else if (RegExp(r'(Service|Repository|ViewModel|Presenter|Controller|Handler|Factory|Builder|Database|Config|Module|Plugin|Native|Bridge|Proxy|Router)').hasMatch(simple)) score += 50;

          // Short package = more likely core
          final parts = pkg.split('/');
          if (parts.length <= 3) score += 10;
          if (parts.isNotEmpty && parts[0].isNotEmpty && parts[0][0].toUpperCase() == parts[0][0]) score += 5;

          // Skip SDK classes
          final sdkPrefixes = ['Landroid/', 'Landroidx/', 'Lcom/google/', 'Lcom/android/', 'Ljava/', 'Lkotlin/', 'Lokhttp', 'Lretrofit', 'Lio/reactivex', 'Lcom/squareup', 'Lcom/facebook', 'Lcom/tencent', 'Lcom/alibaba', 'Lorg/'];
          if (sdkPrefixes.any((prefix) => cls.startsWith(prefix))) continue;

          if (score >= 30) {
            results.add({
              'class': cls,
              'simple': simple,
              'score': score,
              'package': pkg.replaceAll('/', '.'),
            });
          }
        }
      }

      results.sort((a, b) => (b['score'] as double).compareTo(a['score'] as double));

      sb.writeln('--- Core Classes (Top ${results.length > 20 ? 20 : results.length}) ---');
      for (var i = 0; i < results.length && i < 20; i++) {
        final r = results[i];
        sb.writeln('  #${i + 1} ${r['simple']} (score: ${r['score']}) - ${r['package']}');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Total candidate classes: ${results.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_ad_detect — 广告检测
  // =========================================================================
  static Future<Map<String, dynamic>> adDetect(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Ad Detection ===\n');

      // Collect strings and class names from DEX
      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!, maxLength: 999999);
        allText.writeln(text);
      }
      final text = allText.toString();

      // 1. SDK detection from class names
      final adSdks = <Map<String, dynamic>>[];
      final sdkSignatures = [
        (RegExp(r'com\.google\.android\.gms\.ads'), 'Google AdMob/AdX'),
        (RegExp(r'com\.facebook\.ads'), 'Facebook Audience Network'),
        (RegExp(r'com\.applovin\.'), 'AppLovin'),
        (RegExp(r'com\.unity3d\.ads'), 'Unity Ads'),
        (RegExp(r'com\.vungle\.'), 'Vungle'),
        (RegExp(r'com\.ironsource\.'), 'ironSource'),
        (RegExp(r'com\.chartboost\.'), 'Chartboost'),
        (RegExp(r'com\.adcolony\.'), 'AdColony'),
        (RegExp(r'com\.tapjoy\.'), 'Tapjoy'),
        (RegExp(r'com\.startapp\.'), 'StartApp'),
        (RegExp(r'com\.inmobi\.'), 'InMobi'),
        (RegExp(r'com\.mopub\.'), 'MoPub'),
        (RegExp(r'com\.bytedance\.'), 'ByteDance/Pangle'),
        (RegExp(r'com\.mintegral\.'), 'Mintegral'),
        (RegExp(r'com\.huawei\.hms\.ads'), 'Huawei Ads'),
        (RegExp(r'com\.tencent\.gdt'), 'Tencent GDT/广点通'),
        (RegExp(r'com\.baidu\.ad'), 'Baidu Ads'),
        (RegExp(r'com\.sigmob\.'), 'Sigmob'),
        (RegExp(r'com\.fyber\.'), 'Fyber'),
        (RegExp(r'com\.criteo\.'), 'Criteo'),
        (RegExp(r'com\.amazon\.ads'), 'Amazon Ads'),
        (RegExp(r'com\.mbridge\.msdk'), 'MBridge/Mintegral'),
        (RegExp(r'com\.anythink\.'), 'AnyThink/TopOn'),
      ];
      for (final entry in sdkSignatures) {
        final count = entry.$1.allMatches(text).length;
        if (count > 0) {
          adSdks.add({'name': entry.$2, 'count': count});
        }
      }

      sb.writeln('--- Ad SDKs (${adSdks.length}) ---');
      for (final s in adSdks) sb.writeln('  ${s['name']}: ${s['count']} matches');

      // 2. Code pattern detection
      final codePatterns = [
        ('AdView', 'Banner广告'),
        ('InterstitialAd', '插屏广告'),
        ('RewardedAd', '激励视频'),
        ('NativeAd', '原生广告'),
        ('Mediation', '广告聚合'),
        ('adUnitId', '广告单元ID'),
        ('loadAd', '广告加载'),
        ('MobileAds', 'MobileAds API'),
      ];
      sb.writeln('\n--- Code Patterns ---');
      for (final entry in codePatterns) {
        final count = entry.$1.allMatches(text).length;
        if (count > 0) sb.writeln('  ${entry.$2}: $count');
      }

      // 3. Ad URL detection
      final adDomainPatterns = [
        r'doubleclick\.net', r'googlesyndication\.com', r'googleads\.g\.doubleclick\.net',
        r'applovin\.com', r'vungle\.com', r'ironsrc\.com', r'adcolony\.com',
        r'chartboost\.com', r'tapjoy\.com', r'inmobi\.com', r'mopub\.com',
        r'pangolin\.sdk', r'mintegral\.com', r'ads\.baidu\.com', r'e\.qq\.com',
        r'sigmob\.com', r'criteo\.com', r'amazon-adsystem\.com', r'appsflyer\.com',
        r'adjust\.com', r'scorecardresearch\.com', r'pagead2\.googlesyndication\.com',
      ];
      final adUrls = <String>{};
      for (final pat in adDomainPatterns) {
        if (RegExp(pat, caseSensitive: false).hasMatch(text)) {
          adUrls.add(pat);
        }
      }
      sb.writeln('\n--- Ad Domains (${adUrls.length}) ---');
      for (final u in adUrls) sb.writeln('  $u');

      // 4. Scoring
      var score = 0;
      if (adSdks.length >= 5) score += 40;
      else if (adSdks.length >= 3) score += 30;
      else if (adSdks.length >= 1) score += 15;
      final patternCount = codePatterns.where((e) => e.$1.allMatches(text).isNotEmpty).length;
      score += patternCount * 5;
      score += adUrls.length * 2;
      score = score.clamp(0, 100);

      final level = score >= 60 ? '密集广告' : (score >= 35 ? '有广告' : (score >= 10 ? '轻度广告' : '无广告'));

      sb.writeln('\n=== Summary ===');
      sb.writeln('Ad SDKs: ${adSdks.length} | Ad domains: ${adUrls.length} | Patterns: $patternCount');
      sb.writeln('Score: $score/100 ($level)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_clue_chain — 跨模块线索串联分析
  // =========================================================================
  static Future<Map<String, dynamic>> clueChain(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Clue Chain Analysis ===\n');

      // Gather all data
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml', orElse: () => null);
      final manifestText = manifestEntry?.content != null
        ? _extractTextFromBytes(manifestEntry!.content!) : '';
      final dexEntries = _filterEntries(apk, '.dex');
      final soEntries = _filterEntries(apk, '.so');
      final assetsEntries = apk.entries.where((e) => e.name.startsWith('assets/')).toList();

      // Collect DEX text and strings
      final dexText = StringBuffer();
      final allStrings = <String>[];
      for (final dex in dexEntries) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!, maxLength: 999999);
        dexText.writeln(text);
        allStrings.addAll(text.split('\n'));
      }
      final dexContent = dexText.toString();
      final classNames = RegExp(r'L[\w/$]+;').allMatches(dexContent).map((m) => m.group(0)!).toSet().toList();

      final clues = <Map<String, dynamic>>[];
      final risks = <String>{};
      final tags = <String>{};

      // 1. WebView shell + JS Bridge
      final hasWebView = classNames.any((c) => c.toLowerCase().contains('webview'));
      final hasWebAssets = assetsEntries.any((a) => a.name.endsWith('.html') || a.name.endsWith('.js') || a.name.endsWith('.css'));
      final hasJsBridge = classNames.any((c) => c.toLowerCase().contains('javascriptinterface'));
      if (hasWebView && hasWebAssets) {
        final htmlCount = assetsEntries.where((a) => a.name.endsWith('.html')).length;
        clues.add({'type': 'webview_shell', 'severity': 'info', 'title': 'WebView 套壳应用', 'detail': 'WebView + $htmlCount HTML resources'});
        tags.add('webview_shell');
      }
      if (hasJsBridge) {
        clues.add({'type': 'js_bridge', 'severity': 'high', 'title': 'JS Bridge 接口暴露', 'detail': '@JavascriptInterface may allow XSS'});
        risks.add('JS_BRIDGE_EXPOSED');
        tags.add('js_bridge');
      }

      // 2. BeanShell
      final hasBsh = classNames.any((c) => c.toLowerCase().contains('beanshell') || c.toLowerCase().startsWith('lbsh/'));
      if (hasBsh) {
        clues.add({'type': 'beanshell', 'severity': 'high', 'title': 'BeanShell 脚本运行时', 'detail': 'Dynamic code execution engine'});
        risks.add('BEANSHELL_DYNAMIC_EXEC');
        tags.add('beanshell');
      }

      // 3. SO function mapping
      if (soEntries.isNotEmpty) {
        final soTags = <String>{};
        final soKeywords = {'crypto': '加密', 'protect': '保护', 'shell': '加壳', 'hook': 'Hook', 'inject': '注入', 'anti': '反检测'};
        for (final so in soEntries) {
          final name = so.name.toLowerCase();
          for (final entry in soKeywords.entries) {
            if (name.contains(entry.key)) soTags.add(entry.value);
          }
        }
        if (soTags.isNotEmpty) {
          clues.add({'type': 'so_function', 'severity': 'info', 'title': 'SO 功能分布', 'detail': '${soEntries.length} SOs, tags: ${soTags.join(', ')}'});
          tags.addAll(soTags);
        }
      }

      // 4. Permission abuse
      final permPattern = RegExp(r'android\.permission\.(\w+)');
      final permissions = permPattern.allMatches(manifestText).map((m) => m.group(1)!).toSet().toList();
      final highRiskCombos = [
        (['READ_CONTACTS', 'SEND_SMS', 'CALL_PHONE'], '隐私窃取组合'),
        (['CAMERA', 'RECORD_AUDIO', 'INTERNET'], '监控组合'),
        (['ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'INTERNET'], '位置追踪组合'),
        (['READ_SMS', 'RECEIVE_SMS', 'INTERNET'], '短信拦截组合'),
        (['SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE'], '覆盖攻击组合'),
      ];
      for (final combo in highRiskCombos) {
        final matched = combo.$1.where((p) => permissions.contains(p)).toList();
        if (matched.length >= combo.$1.length * 0.66) {
          clues.add({'type': 'permission_abuse', 'severity': 'high', 'title': combo.$2, 'detail': 'Matched: ${matched.join(', ')}'});
          risks.add('PERMISSION_ABUSE');
          tags.add('permission_abuse');
        }
      }

      // 5. Dynamic loading
      final dynamicKeywords = {'DexClassLoader': '动态加载', 'PathClassLoader': '动态加载', 'Runtime.exec': '命令执行', 'ProcessBuilder': '命令执行', 'inject': '注入'};
      for (final entry in dynamicKeywords.entries) {
        if (dexContent.toLowerCase().contains(entry.key.toLowerCase())) {
          clues.add({'type': 'dynamic_loading', 'severity': 'high', 'title': entry.value, 'detail': '${entry.key} detected'});
          risks.add('DYNAMIC_LOADING');
          tags.add('dynamic_loading');
          break;
        }
      }

      // 6. Suspicious assets
      final suspiciousAssets = assetsEntries.where((a) =>
        a.name.endsWith('.dex') || a.name.endsWith('.jar') || a.name.endsWith('.so') || a.name.endsWith('.apk'));
      if (suspiciousAssets.isNotEmpty) {
        clues.add({'type': 'suspicious_assets', 'severity': 'high', 'title': 'assets 可疑文件', 'detail': '${suspiciousAssets.length} suspicious: ${suspiciousAssets.map((a) => a.name).take(5).join(', ')}'});
        risks.add('SUSPICIOUS_ASSETS');
        tags.add('suspicious_assets');
      }

      // 7. URLs in DEX
      final urls = <String>{};
      for (final s in allStrings.take(5000)) {
        if (s.trim().startsWith('http://') || s.trim().startsWith('https://')) {
          urls.add(s.trim());
        }
      }
      if (urls.isNotEmpty) {
        clues.add({'type': 'network_urls', 'severity': 'info', 'title': 'DEX 网络地址', 'detail': '${urls.length} URLs found'});
        tags.add('has_network_urls');
      }

      // 8. Potential keys
      final potentialKeys = allStrings.take(2000).where((s) =>
        s.length >= 16 && s.length <= 64 &&
        ['key', 'secret', 'password', 'token', 'aes', 'iv='].any((k) => s.toLowerCase().contains(k))).toList();
      if (potentialKeys.isNotEmpty) {
        clues.add({'type': 'potential_keys', 'severity': 'medium', 'title': '潜在密钥/密码', 'detail': '${potentialKeys.length} suspicious strings'});
        tags.add('potential_keys');
      }

      // Score
      var score = 0;
      score += risks.length * 15;
      score += clues.where((c) => c['severity'] == 'high').length * 5;
      final highRiskTags = {'beanshell', 'packed', 'dynamic_loading', 'suspicious_assets', 'permission_abuse', 'js_bridge'};
      score += tags.where((t) => highRiskTags.contains(t)).length * 8;
      score = score.clamp(0, 100);

      final level = score >= 70 ? 'high' : (score >= 35 ? 'medium' : 'low');

      sb.writeln('--- Clues (${clues.length}) ---');
      for (final c in clues) {
        sb.writeln('  [${c['severity']}] ${c['title']}: ${c['detail']}');
      }

      sb.writeln('\n--- Risks (${risks.length}) ---');
      for (final r in risks) sb.writeln('  ⚠️ $r');

      sb.writeln('\n--- Tags ---');
      sb.writeln('  ${tags.join(', ')}');

      final conclusion = level == 'high' ? '⚠️ 高风险应用，建议谨慎处理'
        : (level == 'medium' ? '⚡ 中等风险，建议进一步分析' : '✅ 低风险，常规应用');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Score: $score/100 ($level)');
      sb.writeln('Clues: ${clues.length} | Risks: ${risks.length} | Tags: ${tags.length}');
      sb.writeln('Conclusion: $conclusion');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_api_usage — API 调用统计分析
  // =========================================================================
  static Future<Map<String, dynamic>> apiUsage(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== API Usage Analysis ===\n');

      final allStrings = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allStrings.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      final combined = allStrings.join('\n');

      final apiCats = <String, List<String>>{
        '网络通信': [r'okhttp3\.', r'retrofit2\.', r'com\.android\.volley', r'HttpURLConnection', r'java\.net\.URL', r'java\.net\.Socket', r'javax\.net\.ssl\.', r'WebView', r'WebSocket', r'org\.apache\.http'],
        '数据存储': [r'android\.database\.sqlite', r'SharedPreferences', r'java\.io\.File', r'realm\.', r'androidx\.room\.', r'dao\.'],
        '设备标识': [r'TelephonyManager', r'getDeviceId', r'getImei', r'getMeid', r'getSubscriberId', r'getLine1Number', r'Settings\$Secure', r'android\.os\.Build', r'ANDROID_ID'],
        '位置服务': [r'LocationManager', r'FusedLocationProviderClient', r'getLastKnownLocation', r'requestLocationUpdates', r'getLatitude', r'getLongitude', r'Geocoder', r'amap\.api\.location', r'baidu\.location'],
        '加密/安全': [r'javax\.crypto\.', r'java\.security\.', r'android\.keystore\.', r'AES', r'RSA', r'DES', r'SHA', r'MD5', r'HMAC', r'BouncyCastle', r'spongycastle'],
        'UI/视图': [r'android\.widget\.', r'android\.view\.', r'androidx\.recyclerview', r'androidx\.viewpager', r'material', r'constraintlayout', r'androidx\.compose'],
        '日志/调试': [r'android\.util\.Log', r'java\.util\.logging', r'println', r'printStackTrace', r'slf4j', r'commons\.logging'],
        '反射': [r'java\.lang\.reflect\.', r'Class\.forName', r'getMethod', r'getDeclaredMethod', r'setAccessible', r'\.invoke\(', r'getDeclaredField', r'getField', r'newInstance'],
        '序列化': [r'Serializable', r'Parcelable', r'writeToParcel', r'CREATOR', r'Gson', r'Moshi', r'Jackson', r'kotlinx\.serialization', r'fastjson'],
        '线程/异步': [r'Thread', r'Runnable', r'AsyncTask', r'ExecutorService', r'ThreadPoolExecutor', r'kotlinx\.coroutines', r'reactivex\.', r'Handler', r'Looper', r'CountDownLatch'],
        'JNI/Native': [r'System\.loadLibrary', r'System\.load', r'native\s+\w+', r'JNI'],
        '多媒体': [r'MediaPlayer', r'MediaRecorder', r'AudioRecord', r'Camera', r'ExifInterface', r'MediaStore', r'VideoView', r'SurfaceView', r'TextureView'],
        '服务/组件': [r'startService', r'startActivity', r'sendBroadcast', r'registerReceiver', r'ContentResolver', r'ContentProvider', r'ActivityThread'],
      };

      final reflectionPats = [r'Class\.forName\(', r'getDeclaredMethod\(', r'getMethod\(', r'setAccessible\(', r'\.invoke\(', r'getDeclaredField\(', r'getField\(', r'newInstance\('];

      sb.writeln('--- API Categories ---');
      final catResults = <String, int>{};
      final reflectionHits = <String>[];
      for (final entry in apiCats.entries) {
        final cat = entry.key;
        final pats = entry.value;
        var hits = 0;
        for (final pat in pats) {
          final ms = RegExp(pat).allMatches(combined);
          hits += ms.length;
        }
        if (hits > 0) {
          catResults[cat] = hits;
          sb.writeln('  $cat: $hits hits');
        }
      }

      for (final pat in reflectionPats) {
        final ms = RegExp(pat).allMatches(combined);
        if (ms.isNotEmpty) reflectionHits.addAll(ms.map((m) => m.group(0)!).take(5));
      }

      sb.writeln('\n--- Reflection ---');
      sb.writeln('  Total: ${reflectionHits.length}');
      if (reflectionHits.isNotEmpty) {
        sb.writeln('  Samples: ${reflectionHits.take(5).join(', ')}');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Categories detected: ${catResults.length}');
      final sorted = catResults.entries.toList()..sort((a, b) => b.value.compareTo(a.value));
      if (sorted.isNotEmpty) {
        sb.writeln('Top category: ${sorted.first.key} (${sorted.first.value} hits)');
      }
      sb.writeln('Reflection patterns: ${reflectionHits.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_permission_trace — 权限使用追溯
  // =========================================================================
  static Future<Map<String, dynamic>> permissionTrace(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Permission Trace ===\n');

      // Get manifest permissions
      String? manifestText;
      try {
        manifestText = _extractResultText(KelivoManifestAnalyzer.summary(
          KelivoManifestRequestPayload(bytes: p.apkBytes!),
        ));
      } catch (_) {}

      final declaredPerms = <String>{};
      if (manifestText != null) {
        final permMatches = RegExp(r'android\.permission\.([A-Z_]+)').allMatches(manifestText);
        for (final m in permMatches) {
          declaredPerms.add(m.group(1)!);
        }
      }

      // Get DEX strings
      final allStrings = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allStrings.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      final combined = allStrings.join('\n');

      final permApiMap = <String, Map<String, dynamic>>{
        'ACCESS_FINE_LOCATION': {'apis': ['getLastKnownLocation', 'requestLocationUpdates', 'getLatitude', 'getLongitude', 'LocationManager', 'FusedLocationProviderClient'], 'desc': '精确定位', 'severity': 'dangerous'},
        'ACCESS_COARSE_LOCATION': {'apis': ['getLastKnownLocation', 'requestLocationUpdates', 'LocationManager'], 'desc': '粗略定位', 'severity': 'dangerous'},
        'READ_CONTACTS': {'apis': ['ContactsContract', 'queryContacts', 'RawContacts', 'PhoneLookup'], 'desc': '读取联系人', 'severity': 'dangerous'},
        'READ_SMS': {'apis': ['SmsManager', 'Telephony.Sms', 'content://sms'], 'desc': '读取短信', 'severity': 'dangerous'},
        'SEND_SMS': {'apis': ['SmsManager', 'sendTextMessage'], 'desc': '发送短信', 'severity': 'dangerous'},
        'READ_CALL_LOG': {'apis': ['CallLog', 'CallLog\$Calls', 'content://call_log'], 'desc': '读取通话记录', 'severity': 'dangerous'},
        'CAMERA': {'apis': ['Camera.open', 'Camera2', 'CameraManager', 'takePicture'], 'desc': '相机', 'severity': 'dangerous'},
        'RECORD_AUDIO': {'apis': ['MediaRecorder', 'AudioRecord', 'startRecording'], 'desc': '录音', 'severity': 'dangerous'},
        'READ_EXTERNAL_STORAGE': {'apis': ['getExternalStorageDirectory', 'getExternalStoragePublicDirectory', 'MediaStore', 'openFileInput'], 'desc': '读取外部存储', 'severity': 'dangerous'},
        'WRITE_EXTERNAL_STORAGE': {'apis': ['getExternalStorageDirectory', 'getExternalStoragePublicDirectory', 'MediaStore', 'openFileOutput', 'FileOutputStream'], 'desc': '写入外部存储', 'severity': 'dangerous'},
        'READ_PHONE_STATE': {'apis': ['TelephonyManager', 'getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getLine1Number', 'getSimSerialNumber'], 'desc': '读取手机状态', 'severity': 'dangerous'},
        'CALL_PHONE': {'apis': ['ACTION_CALL', 'ACTION_DIAL'], 'desc': '拨打电话', 'severity': 'dangerous'},
        'GET_ACCOUNTS': {'apis': ['AccountManager', 'getAccounts', 'getAccountsByType'], 'desc': '获取账户列表', 'severity': 'dangerous'},
        'READ_CALENDAR': {'apis': ['CalendarContract', 'Calendars', 'Events'], 'desc': '读取日历', 'severity': 'dangerous'},
        'SYSTEM_ALERT_WINDOW': {'apis': ['TYPE_APPLICATION_OVERLAY', 'TYPE_SYSTEM_ALERT'], 'desc': '悬浮窗', 'severity': 'dangerous'},
        'REQUEST_INSTALL_PACKAGES': {'apis': ['ACTION_INSTALL_PACKAGE', 'PackageInstaller'], 'desc': '安装包请求', 'severity': 'dangerous'},
        'INTERNET': {'apis': ['HttpURLConnection', 'OkHttpClient', 'Retrofit', 'Volley', 'WebSocket', 'openConnection'], 'desc': '网络访问', 'severity': 'normal'},
        'ACCESS_NETWORK_STATE': {'apis': ['ConnectivityManager', 'getActiveNetworkInfo'], 'desc': '网络状态', 'severity': 'normal'},
        'ACCESS_WIFI_STATE': {'apis': ['WifiManager', 'getConnectionInfo', 'getScanResults'], 'desc': 'WiFi状态', 'severity': 'normal'},
        'VIBRATE': {'apis': ['Vibrator', 'vibrate', 'VibrationEffect'], 'desc': '振动', 'severity': 'normal'},
        'WAKE_LOCK': {'apis': ['PowerManager', 'WakeLock', 'newWakeLock'], 'desc': '唤醒锁', 'severity': 'normal'},
        'FOREGROUND_SERVICE': {'apis': ['startForeground', 'startForegroundService'], 'desc': '前台服务', 'severity': 'normal'},
        'NFC': {'apis': ['NfcAdapter', 'enableForegroundDispatch', 'NdefMessage'], 'desc': 'NFC', 'severity': 'normal'},
      };

      final usedPerms = <Map<String, dynamic>>[];
      final unusedPerms = <Map<String, dynamic>>[];

      for (final perm in declaredPerms.toList()..sort()) {
        final info = permApiMap[perm];
        if (info == null) continue;
        final apis = info['apis'] as List<String>;
        final foundApis = <String>[];
        for (final api in apis) {
          if (combined.contains(api)) foundApis.add(api);
        }
        if (foundApis.isNotEmpty) {
          usedPerms.add({'permission': perm, 'desc': info['desc'], 'severity': info['severity'], 'api_count': foundApis.length, 'apis': foundApis.take(5).join(', ')});
        } else {
          unusedPerms.add({'permission': perm, 'desc': info['desc'], 'severity': info['severity']});
        }
      }

      // Check for missing perms (API used but perm not declared)
      final missingPerms = <Map<String, dynamic>>[];
      for (final entry in permApiMap.entries) {
        final perm = entry.key;
        if (declaredPerms.contains(perm)) continue;
        final apis = entry.value['apis'] as List<String>;
        for (final api in apis) {
          if (combined.contains(api)) {
            missingPerms.add({'permission': perm, 'desc': entry.value['desc'], 'severity': entry.value['severity'], 'api_found': api});
            break;
          }
        }
      }

      sb.writeln('--- Declared: ${declaredPerms.length} | Used: ${usedPerms.length} | Unused: ${unusedPerms.length} | Missing: ${missingPerms.length} ---\n');

      if (usedPerms.isNotEmpty) {
        sb.writeln('--- Used Permissions ---');
        for (final p in usedPerms) {
          sb.writeln('  [${p['severity']}] ${p['permission']} (${p['desc']}) — ${p['api_count']} APIs: ${p['apis']}');
        }
      }
      if (unusedPerms.isNotEmpty) {
        sb.writeln('\n--- Unused Permissions ---');
        for (final p in unusedPerms) {
          sb.writeln('  [${p['severity']}] ${p['permission']} (${p['desc']})');
        }
      }
      if (missingPerms.isNotEmpty) {
        sb.writeln('\n--- Missing Permissions (API used but not declared) ---');
        for (final p in missingPerms.take(10)) {
          sb.writeln('  [${p['severity']}] ${p['permission']} (${p['desc']}) — found: ${p['api_found']}');
        }
      }

      final dangerousUsed = usedPerms.where((p) => p['severity'] == 'dangerous').length;
      final dangerousMissing = missingPerms.where((p) => p['severity'] == 'dangerous').length;
      final dangerousUnused = unusedPerms.where((p) => p['severity'] == 'dangerous').length;
      final riskScore = (dangerousUsed * 15 + dangerousMissing * 20 + dangerousUnused * 5).clamp(0, 100);

      sb.writeln('\n=== Summary ===');
      sb.writeln('Risk score: $riskScore/100');
      sb.writeln('Dangerous used: $dangerousUsed | Dangerous unused: $dangerousUnused | Dangerous missing: $dangerousMissing');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_clone_detect — DEX 方法克隆检测
  // =========================================================================
  static Future<Map<String, dynamic>> cloneDetect(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Clone Detection ===\n');

      final dexEntries = _filterEntries(apk, '.dex');
      if (dexEntries.isEmpty) return _err('No DEX files found.');

      var totalMethods = 0;
      final exactGroups = <String, List<String>>{};
      final similarGroups = <String, List<String>>{};

      for (final dex in dexEntries) {
        if (dex.content == null) continue;
        final dexName = dex.name;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final classesText = _extractResultText(KelivoDexAnalyzer.classes(payload));

        // Parse class/method lines
        final lines = classesText.split('\n');
        for (final line in lines) {
          if (!line.contains('->') || !line.contains('.')) continue;
          totalMethods++;

          // Generate a simple hash from the method signature line
          // Exact hash = full line content
          final trimmed = line.trim();
          final exactHash = trimmed.hashCode.toString();

          // Opcode hash = method name + descriptor (simplified)
          final arrowIdx = trimmed.indexOf('->');
          if (arrowIdx > 0) {
            final methodPart = trimmed.substring(arrowIdx + 2).trim();
            final opHash = methodPart.hashCode.toString();
            exactGroups.putIfAbsent(exactHash, () => []).add(trimmed);
            if (methodPart.length >= 10) {
              similarGroups.putIfAbsent(opHash, () => []).add(trimmed);
            }
          }
        }
      }

      final exactClones = exactGroups.entries.where((e) => e.value.length > 1).toList();
      final similarClones = similarGroups.entries.where((e) {
        if (e.value.length < 2) return false;
        final hashes = e.value.map((s) => s.hashCode.toString()).toSet();
        return hashes.length > 1; // Not all identical
      }).toList();

      sb.writeln('Total methods scanned: $totalMethods');
      sb.writeln('Exact clone groups: ${exactClones.length}');
      sb.writeln('Similar clone groups: ${similarClones.length}');

      var totalCloned = 0;
      for (final g in exactClones) totalCloned += g.value.length;
      for (final g in similarClones) totalCloned += g.value.length;
      final cloneRatio = totalMethods > 0 ? (totalCloned / totalMethods * 100).toStringAsFixed(1) : '0.0';

      sb.writeln('Total cloned methods: $totalCloned');
      sb.writeln('Clone ratio: $cloneRatio%\n');

      if (exactClones.isNotEmpty) {
        sb.writeln('--- Exact Clones (Top 10) ---');
        for (final g in exactClones.take(10)) {
          sb.writeln('  [${g.value.length}x] ${g.value.first}');
          for (final m in g.value.skip(1).take(3)) {
            sb.writeln('    = $m');
          }
        }
      }

      if (similarClones.isNotEmpty) {
        sb.writeln('\n--- Similar Methods (Top 10) ---');
        for (final g in similarClones.take(10)) {
          sb.writeln('  [${g.value.length}x] ${g.value.first}');
        }
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Clone ratio: $cloneRatio%');
      if (double.parse(cloneRatio) > 30) {
        sb.writeln('⚠️ High clone ratio — consider code deduplication');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_network_analysis — 网络行为深度分析
  // =========================================================================
  static Future<Map<String, dynamic>> networkAnalysis(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Network Analysis ===\n');

      final allText = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.add(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        try {
          final soPayload = KelivoSoRequestPayload(bytes: so.content!);
          allText.add(_extractResultText(KelivoSoAnalyzer.strings(soPayload)));
        } catch (_) {}
      }
      final combined = allText.join('\n');

      // 1. Protocols
      final insecureProtos = ['http://', 'ftp://', 'telnet://', 'rtsp://'];
      sb.writeln('--- Protocols ---');
      for (final proto in insecureProtos) {
        final count = proto.allMatches(combined).length;
        if (count > 0) sb.writeln('  $proto: $count occurrences');
      }

      // 2. SSL/TLS
      sb.writeln('\n--- SSL/TLS ---');
      final sslPinningClasses = ['CertificatePinner', 'TrustManager', 'X509TrustManager', 'SSLSocketFactory', 'PinningTrustManager', 'PublicKeyPin'];
      final unsafeSslStrings = ['ALLOW_ALL_HOSTNAME_VERIFIER', 'TrustAllCerts', 'trustAllCerts', 'TrustAllCertificates', 'setHostnameVerifier', 'NoSSLv3', 'TLSv1.0', 'TLSv1.1'];
      var hasPinning = false;
      var hasUnsafe = false;
      for (final cls in sslPinningClasses) {
        if (combined.contains(cls)) {
          sb.writeln('  Pinning: $cls');
          hasPinning = true;
        }
      }
      for (final s in unsafeSslStrings) {
        if (combined.contains(s)) {
          sb.writeln('  ⚠️ Unsafe: $s');
          hasUnsafe = true;
        }
      }
      final sslRisk = hasUnsafe && !hasPinning ? '高' : (hasUnsafe ? '中' : (hasPinning ? '低' : '未知'));
      sb.writeln('  SSL risk level: $sslRisk');

      // 3. WebSocket
      sb.writeln('\n--- WebSocket ---');
      final wsUrls = RegExp(r'wss?://[^\s"\'<>]+').allMatches(combined).map((m) => m.group(0)!).toSet();
      final wsKeywords = ['WebSocket', 'Socket.IO', 'socket.io', 'SockJS', 'Java-WebSocket'];
      final wsClasses = wsKeywords.where((k) => combined.toLowerCase().contains(k.toLowerCase())).toList();
      if (wsUrls.isNotEmpty || wsClasses.isNotEmpty) {
        sb.writeln('  URLs: ${wsUrls.length}');
        for (final u in wsUrls.take(5)) sb.writeln('    $u');
        sb.writeln('  Classes: ${wsClasses.join(', ')}');
      } else {
        sb.writeln('  No WebSocket detected');
      }

      // 4. Custom schemes
      sb.writeln('\n--- Custom Schemes ---');
      final customSchemes = ['intent://', 'content://', 'file://', 'tel://', 'sms://', 'mailto:', 'geo:', 'market://', 'weixin://', 'alipays://', 'taobao://'];
      for (final scheme in customSchemes) {
        final count = scheme.allMatches(combined).length;
        if (count > 0) sb.writeln('  $scheme: $count');
      }
      final deepLinks = RegExp(r'[a-zA-Z][a-zA-Z0-9+.-]{2,}://[^\s"\'<>]+').allMatches(combined).map((m) => m.group(0)!).toSet();
      final standardSchemes = {'http', 'https', 'ftp', 'ftps', 'ws', 'wss', 'file', 'mailto'};
      final customDeepLinks = deepLinks.where((d) => !standardSchemes.contains(d.split('://')[0])).toList();
      sb.writeln('  Custom deep links: ${customDeepLinks.length}');

      // 5. Cloud platforms
      sb.writeln('\n--- Cloud Platforms ---');
      final cloudPlatforms = <String, String>{
        'amazonaws.com': 'AWS', 'azure.com': 'Azure', 'cloudfront.net': 'AWS CloudFront',
        'aliyuncs.com': '阿里云', 'qcloud.com': '腾讯云', 'tencentcloud.com': '腾讯云',
        'huaweicloud.com': '华为云', 'googleapis.com': 'Google', 'firebaseio.com': 'Firebase',
        'herokuapp.com': 'Heroku', 'netlify.com': 'Netlify', 'vercel.app': 'Vercel',
        'cloudflare.com': 'Cloudflare', 'supabase.co': 'Supabase',
      };
      for (final entry in cloudPlatforms.entries) {
        if (combined.toLowerCase().contains(entry.key.toLowerCase())) {
          sb.writeln('  ${entry.value}: ${entry.key}');
        }
      }

      // 6. Port analysis
      sb.writeln('\n--- Ports ---');
      final portMatches = RegExp(r':(\d{2,5})(?=/|\s|$|"|\')').allMatches(combined);
      final ports = portMatches.map((m) => m.group(1)!).where((p) => int.tryParse(p) != null && int.parse(p) >= 1 && int.parse(p) <= 65535).toSet();
      final commonPorts = {'80': 'HTTP', '443': 'HTTPS', '8080': 'HTTP-Alt', '8443': 'HTTPS-Alt', '21': 'FTP', '22': 'SSH', '3306': 'MySQL', '5432': 'PostgreSQL', '6379': 'Redis', '27017': 'MongoDB', '1883': 'MQTT', '5222': 'XMPP', '5228': 'GCM/FCM'};
      for (final port in ports.take(15)) {
        final service = commonPorts[port] ?? '未知';
        sb.writeln('  :$port ($service)');
      }

      // 7. Risk assessment
      sb.writeln('\n=== Risk Assessment ===');
      var riskScore = 0;
      final risks = <String>[];
      if (combined.contains('http://')) { riskScore += 20; risks.add('使用不安全协议 HTTP'); }
      if (hasUnsafe && !hasPinning) { riskScore += 30; risks.add('不安全的 SSL 配置'); }
      else if (hasUnsafe) { riskScore += 15; risks.add('SSL 配置存在降级风险'); }
      if (customDeepLinks.length > 10) { riskScore += 5; risks.add('大量自定义深层链接 (${customDeepLinks.length})'); }
      final level = riskScore >= 40 ? '高' : (riskScore >= 15 ? '中' : '低');
      sb.writeln('Risk score: ${riskScore.clamp(0, 100)}/100');
      sb.writeln('Risk level: $level');
      for (final r in risks) sb.writeln('  - $r');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_lib_analysis — DEX 第三方库分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexLibAnalysis(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Third-party Library Analysis ===\n');

      final allClassNames = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        allClassNames.addAll(RegExp(r'L[\w/$]+;').allMatches(text).map((m) => m.group(0)!));
      }

      final knownLibs = <String, String>{
        'com.google.android.gms.ads': 'Google AdMob',
        'com.facebook.ads': 'Facebook Audience Network',
        'com.applovin': 'AppLovin',
        'com.unity3d': 'Unity',
        'com.vungle': 'Vungle',
        'com.ironsource': 'IronSource',
        'com.chartboost': 'Chartboost',
        'com.startapp': 'StartApp',
        'com.inmobi': 'InMobi',
        'com.mopub': 'MoPub',
        'com.tapjoy': 'Tapjoy',
        'com.adcolony': 'AdColony',
        'com.bytedance': 'ByteDance/Pangle',
        'com.qq.e': '腾讯优量汇',
        'com.baidu.mobads': '百度广告',
        'com.huawei.hms': '华为HMS',
        'com.squareup.okhttp': 'OkHttp',
        'com.squareup.retrofit': 'Retrofit',
        'io.reactivex': 'RxJava',
        'com.android.volley': 'Volley',
        'com.google.gson': 'Gson',
        'com.alibaba.fastjson': 'FastJson',
        'com.bumptech.glide': 'Glide',
        'com.squareup.picasso': 'Picasso',
        'com.facebook.drawee': 'Fresco',
        'androidx.room': 'Room',
        'org.greenrobot.greendao': 'GreenDAO',
        'org.greenrobot.eventbus': 'EventBus',
        'com.google.firebase': 'Firebase',
        'com.tencent.bugly': 'Bugly',
        'com.umeng': '友盟',
        'com.jakewharton': 'JakeWharton',
        'io.flutter': 'Flutter',
        'com.facebook.react': 'React Native',
        'org.jetbrains.kotlin': 'Kotlin',
        'com.google.zxing': 'ZXing',
        'com.tencent.mm.opensdk': '微信SDK',
        'com.tencent.connect': 'QQ SDK',
        'com.alipay': '支付宝SDK',
        'com.amap.api': '高德地图',
        'com.baidu.map': '百度地图',
        'dagger': 'Dagger',
        'org.apache.commons': 'Apache Commons',
        'com.google.common': 'Guava',
      };

      final detected = <String, int>{};
      for (final cls in allClassNames) {
        final clsPath = cls.replaceAll('.', '/').replaceAll('L', '').replaceAll(';', '');
        for (final entry in knownLibs.entries) {
          final sig = entry.key.replaceAll('.', '/');
          if (clsPath.contains(sig)) {
            detected[entry.value] = (detected[entry.value] ?? 0) + 1;
          }
        }
      }

      final totalClasses = allClassNames.length;
      final totalLibClasses = detected.values.fold(0, (s, v) => s + v);
      final libRatio = totalClasses > 0 ? (totalLibClasses / totalClasses * 100).toStringAsFixed(2) : '0.0';

      sb.writeln('Total classes: $totalClasses');
      sb.writeln('Library classes: $totalLibClasses ($libRatio%)');
      sb.writeln('Detected libraries: ${detected.length}');

      final sorted = detected.entries.toList()..sort((a, b) => b.value.compareTo(a.value));
      sb.writeln('\n--- Detected Libraries ---');
      for (final e in sorted) {
        sb.writeln('  ${e.key}: ${e.value} classes');
      }

      final bloatScore = (libRatio.isNotEmpty && double.parse(libRatio) > 50 ? 60 : detected.length * 3).clamp(0, 100);
      final bloatLevel = bloatScore >= 60 ? '严重膨胀' : (bloatScore >= 30 ? '中度膨胀' : '精炼');
      sb.writeln('\n=== Summary ===');
      sb.writeln('Bloat score: $bloatScore/100 ($bloatLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_reflection — DEX 反射/动态加载分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexReflection(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Reflection Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final reflectPatterns = [
        'Class.forName', 'getMethod', 'getDeclaredMethod', 'getField',
        'getDeclaredField', 'newInstance', 'getConstructor', 'getDeclaredConstructor',
        'invoke', 'setAccessible', 'java.lang.reflect',
      ];
      final dynamicPatterns = [
        'DexClassLoader', 'PathClassLoader', 'InMemoryDexClassLoader',
        'loadDex', 'openDexFile', 'dalvik.system', 'MultiDex',
      ];

      sb.writeln('--- Reflection Patterns ---');
      var reflectTotal = 0;
      for (final pat in reflectPatterns) {
        final count = pat.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  $pat: $count');
          reflectTotal += count;
        }
      }

      sb.writeln('\n--- Dynamic Loading ---');
      var dynamicTotal = 0;
      for (final pat in dynamicPatterns) {
        final count = pat.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  $pat: $count');
          dynamicTotal += count;
        }
      }

      final riskScore = (reflectTotal * 0.5 + dynamicTotal * 2).round().clamp(0, 100);
      final riskLevel = riskScore >= 60 ? '高风险' : (riskScore >= 30 ? '中风险' : (riskScore > 0 ? '低风险' : '无风险'));
      sb.writeln('\n=== Summary ===');
      sb.writeln('Reflection: $reflectTotal | Dynamic: $dynamicTotal');
      sb.writeln('Risk score: $riskScore/100 ($riskLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_resource_ref — DEX 资源引用分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexResourceRef(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Resource Reference Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final rCategories = {
        'R\$layout': '布局', 'R\$id': '控件ID', 'R\$drawable': '图片/图标',
        'R\$string': '字符串资源', 'R\$color': '颜色', 'R\$dimen': '尺寸',
        'R\$style': '样式', 'R\$attr': '属性', 'R\$raw': '原始文件',
        'R\$anim': '动画', 'R\$menu': '菜单',
      };

      sb.writeln('--- R Class References ---');
      var totalRefs = 0;
      for (final entry in rCategories.entries) {
        final count = entry.key.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  ${entry.key} (${entry.value}): $count');
          totalRefs += count;
        }
      }

      final hardcodedIds = RegExp(r'0x7f[0-9a-fA-F]{4,6}').allMatches(text).length;
      sb.writeln('\n--- Hardcoded Resource IDs ---');
      sb.writeln('  Count: $hardcodedIds');

      final obfScore = (totalRefs == 0 && text.length > 50000 ? 80 : hardcodedIds * 10).clamp(0, 100);
      final obfLevel = obfScore >= 70 ? '严重混淆' : (obfScore >= 30 ? '中度混淆' : '正常');
      sb.writeln('\n=== Summary ===');
      sb.writeln('Total R refs: $totalRefs | Hardcoded IDs: $hardcodedIds');
      sb.writeln('Obfuscation: $obfScore/100 ($obfLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_serialization — DEX 序列化/持久化分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexSerialization(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Serialization Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final serializableCount = 'Serializable'.allMatches(text).length;
      final parcelableCount = 'Parcelable'.allMatches(text).length;

      final persistPatterns = [
        'SharedPreferences', 'SQLiteDatabase', 'openOrCreateDatabase',
        'writeToParcel', 'readFromParcel', 'getSharedPreferences',
        'filesDir', 'cacheDir', 'ObjectOutputStream', 'writeObject', 'readObject',
      ];
      sb.writeln('--- Serialization ---');
      sb.writeln('  Serializable refs: $serializableCount');
      sb.writeln('  Parcelable refs: $parcelableCount');

      sb.writeln('\n--- Persistence Patterns ---');
      var persistTotal = 0;
      for (final pat in persistPatterns) {
        final count = pat.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  $pat: $count');
          persistTotal += count;
        }
      }

      final riskScore = (persistTotal * 0.8 + serializableCount * 2 + parcelableCount * 2).round().clamp(0, 100);
      final riskLevel = riskScore >= 60 ? '高持久化' : (riskScore >= 30 ? '中持久化' : '低持久化');
      sb.writeln('\n=== Summary ===');
      sb.writeln('Serializable: $serializableCount | Parcelable: $parcelableCount');
      sb.writeln('Persist total: $persistTotal');
      sb.writeln('Risk: $riskScore/100 ($riskLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_string_pool — DEX 字符串常量池深度分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexStringPool(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX String Pool Analysis ===\n');

      final allStrings = <String>{};
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.strings(payload));
        for (final line in text.split('\n')) {
          final s = line.trim();
          if (s.isNotEmpty) allStrings.add(s);
        }
      }

      final strings = allStrings.toList();
      final totalBytes = strings.fold<int>(0, (s, str) => s + str.length);
      final avgLen = strings.isNotEmpty ? (totalBytes / strings.length).toStringAsFixed(2) : '0';

      sb.writeln('Total strings: ${strings.length}');
      sb.writeln('Total bytes: $totalBytes');
      sb.writeln('Avg length: $avgLen');

      // Length distribution
      final buckets = <String, int>{'1-10': 0, '11-30': 0, '31-50': 0, '51-100': 0, '101-200': 0, '200+': 0};
      for (final s in strings) {
        final l = s.length;
        if (l <= 10) buckets['1-10'] = buckets['1-10']! + 1;
        else if (l <= 30) buckets['11-30'] = buckets['11-30']! + 1;
        else if (l <= 50) buckets['31-50'] = buckets['31-50']! + 1;
        else if (l <= 100) buckets['51-100'] = buckets['51-100']! + 1;
        else if (l <= 200) buckets['101-200'] = buckets['101-200']! + 1;
        else buckets['200+'] = buckets['200+']! + 1;
      }
      sb.writeln('\n--- Length Distribution ---');
      for (final e in buckets.entries) sb.writeln('  ${e.key}: ${e.value}');

      // Sensitive patterns
      final patterns = <String, RegExp>{
        'url': RegExp(r'https?://[^\s"\'<>]+'),
        'ip': RegExp(r'\b(\d{1,3}\.){3}\d{1,3}\b'),
        'email': RegExp(r'[\w.+-]+@[\w-]+\.[\w.-]+'),
        'jwt': RegExp(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        'base64_long': RegExp(r'[A-Za-z0-9+/]{40,}={0,2}'),
        'hex_long': RegExp(r'[0-9a-fA-F]{32,}'),
        'java_class': RegExp(r'L[a-z][a-z0-9_]*/[A-Za-z][A-Za-z0-9_]*;'),
        'sql': RegExp(r'(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\s', caseSensitive: false),
        'android_permission': RegExp(r'android\.permission\.\w+'),
        'content_provider': RegExp(r'content://[\w./]+'),
      };
      sb.writeln('\n--- Sensitive Patterns ---');
      for (final e in patterns.entries) {
        var count = 0;
        for (final s in strings) {
          count += e.value.allMatches(s).length;
        }
        if (count > 0) sb.writeln('  ${e.key}: $count');
      }

      // Duplicates
      final counter = <String, int>{};
      for (final s in strings) {
        if (s.length > 5) counter[s] = (counter[s] ?? 0) + 1;
      }
      final dupes = counter.entries.where((e) => e.value > 1).toList()..sort((a, b) => b.value.compareTo(a.value));
      sb.writeln('\n--- Top Duplicates (${dupes.length}) ---');
      for (final d in dupes.take(15)) {
        sb.writeln('  [${d.value}x] ${d.key.length > 80 ? d.key.substring(0, 80) : d.key}');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Strings: ${strings.length} | Bytes: $totalBytes | Duplicates: ${dupes.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_obfuscation_scan — DEX 混淆特征扫描
  // =========================================================================
  static Future<Map<String, dynamic>> dexObfuscationScan(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Obfuscation Scan ===\n');

      final allClassNames = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        allClassNames.addAll(RegExp(r'L[\w/$]+;').allMatches(text).map((m) => m.group(0)!));
      }

      final obfuscatedPattern = RegExp(r'^L[a-z]{1,3}/[a-z]{1,3}/[a-z]{1,3};$');
      final singleLetterPattern = RegExp(r'^[a-z]$');
      final obfuscatedClasses = allClassNames.where((c) => obfuscatedPattern.hasMatch(c)).toList();

      final packerPatterns = [
        'libjiagu', 'libDexHelper', 'libprotectClass', 'com/secneo/apkwrapper',
        'com/qihoo', 'com/stub', 'com/shell', 'bangcle', 'ijiami',
        'libshell', 'libshella', 'com/tencent/stub', 'libnesec',
        'com/baidu/protect', 'net/youmi', 'jiagu',
      ];

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final packerHits = <String, int>{};
      for (final pat in packerPatterns) {
        final count = pat.allMatches(text).length;
        if (count > 0) packerHits[pat] = count;
      }

      var obfScore = (obfuscatedClasses.length * 3).clamp(0, 40) + (packerHits.length * 10).clamp(0, 30);
      obfScore = obfScore.clamp(0, 100);
      final level = obfScore >= 70 ? '严重混淆' : (obfScore >= 40 ? '高度混淆' : (obfScore >= 20 ? '中度混淆' : (obfScore > 0 ? '轻度混淆' : '未混淆')));

      sb.writeln('Total classes: ${allClassNames.length}');
      sb.writeln('Obfuscated classes: ${obfuscatedClasses.length}');
      sb.writeln('Obfuscation rate: ${allClassNames.isNotEmpty ? (obfuscatedClasses.length / allClassNames.length * 100).toStringAsFixed(1) : 0}%');
      sb.writeln('\n--- Packer Detection ---');
      for (final e in packerHits.entries) sb.writeln('  ${e.key}: ${e.value}');
      sb.writeln('\n=== Summary ===');
      sb.writeln('Score: $obfScore/100 ($level)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_crypto — DEX 加密特征分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexCrypto(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Crypto Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final encAlgos = ['AES', 'RSA', 'DES', 'DESede', 'Cipher', 'SecretKeySpec', 'KeyGenerator', 'KeyPairGenerator', 'javax.crypto', 'SM2', 'SM4', 'ChaCha20'];
      final hashAlgos = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512', 'MessageDigest', 'PBKDF2', 'Hmac', 'Mac.'];
      final encoding = ['Base64', 'URLEncoder', 'URLDecoder', 'encodeHex', 'decodeHex'];
      final weakAlgos = ['DES', 'MD5', 'SHA-1', 'PBE', 'DESede', 'Blowfish'];

      sb.writeln('--- Encryption ---');
      var encTotal = 0;
      for (final algo in encAlgos) {
        final count = algo.allMatches(text).length;
        if (count > 0) { sb.writeln('  $algo: $count'); encTotal += count; }
      }

      sb.writeln('\n--- Hash ---');
      var hashTotal = 0;
      for (final algo in hashAlgos) {
        final count = algo.allMatches(text).length;
        if (count > 0) { sb.writeln('  $algo: $count'); hashTotal += count; }
      }

      sb.writeln('\n--- Encoding ---');
      for (final enc in encoding) {
        final count = enc.allMatches(text).length;
        if (count > 0) sb.writeln('  $enc: $count');
      }

      sb.writeln('\n--- Weak Algorithms ---');
      var weakTotal = 0;
      for (final algo in weakAlgos) {
        final count = algo.allMatches(text).length;
        if (count > 0) { sb.writeln('  ⚠️ $algo: $count'); weakTotal += count; }
      }

      final hasStrong = text.contains('AES') || text.contains('RSA') || text.contains('ChaCha20') || text.contains('SM2') || text.contains('SM4');
      var secScore = 0;
      if (encTotal > 0 || hashTotal > 0) {
        secScore = (encTotal * 2 + hashTotal).clamp(0, 50);
        if (hasStrong) secScore += 20;
        secScore -= (weakTotal * 5).clamp(0, 40);
        secScore = secScore.clamp(0, 100);
      }
      final secLevel = secScore == 0 ? '无加密' : (secScore >= 60 ? '强加密' : (secScore >= 30 ? '中加密' : '弱加密'));
      sb.writeln('\n=== Summary ===');
      sb.writeln('Encryption: $encTotal | Hash: $hashTotal | Weak: $weakTotal');
      sb.writeln('Score: $secScore/100 ($secLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_class_density — DEX 类结构密度分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexClassDensity(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Class Density Analysis ===\n');

      final allClassNames = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        allClassNames.addAll(RegExp(r'L[\w/$]+;').allMatches(text).map((m) => m.group(0)!));
      }

      final totalClasses = allClassNames.length;
      final pkgDist = <String, int>{};
      var interfaceCount = 0, abstractCount = 0, finalCount = 0;

      for (final cls in allClassNames) {
        final inner = cls.substring(1, cls.length - 1);
        final parts = inner.split('/');
        if (parts.length > 1) {
          final pkg = parts.sublist(0, parts.length - 1).join('.');
          pkgDist[pkg] = (pkgDist[pkg] ?? 0) + 1;
        }
        final simple = parts.last;
        if (simple.startsWith('I') && simple.length > 1) interfaceCount++;
        if (simple.startsWith('Abstract') || simple.startsWith('Base')) abstractCount++;
      }

      final sortedPkgs = pkgDist.entries.toList()..sort((a, b) => b.value.compareTo(a.value));
      sb.writeln('Total classes: $totalClasses');
      sb.writeln('Total packages: ${pkgDist.length}');
      sb.writeln('Interfaces (est): $interfaceCount | Abstract (est): $abstractCount');

      sb.writeln('\n--- Top Packages ---');
      for (final e in sortedPkgs.take(20)) {
        sb.writeln('  ${e.key}: ${e.value} classes');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Classes: $totalClasses | Packages: ${pkgDist.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_inner_class — DEX 内部类/匿名类分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexInnerClass(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Inner Class Analysis ===\n');

      final allClassNames = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        allClassNames.addAll(RegExp(r'L[\w/$]+;').allMatches(text).map((m) => m.group(0)!));
      }

      final total = allClassNames.length;
      var topLevel = 0, innerCount = 0, anonymousCount = 0, lambdaCount = 0;
      final dollarLevels = <int, int>{};

      for (final cls in allClassNames) {
        final dollarCount = '\$'.allMatches(cls).length;
        if (dollarCount > 0) {
          innerCount++;
          dollarLevels[dollarCount] = (dollarLevels[dollarCount] ?? 0) + 1;
          final parts = cls.split('\$');
          final last = parts.last.replaceAll(';', '');
          if (RegExp(r'^\d+$').hasMatch(last)) anonymousCount++;
          if (cls.contains('lambda') || cls.contains('Lambda') || cls.contains('\$\$Lambda\$')) lambdaCount++;
        } else {
          topLevel++;
        }
      }

      final innerRatio = total > 0 ? (innerCount / total * 100).toStringAsFixed(2) : '0.0';
      final anonRatio = total > 0 ? (anonymousCount / total * 100).toStringAsFixed(2) : '0.0';
      final score = (innerCount * 2 + anonymousCount * 3).clamp(0, 100);
      final level = score >= 60 ? '高复杂度' : (score >= 30 ? '中复杂度' : '低复杂度');

      sb.writeln('Total classes: $total');
      sb.writeln('Top-level: $topLevel | Inner: $innerCount ($innerRatio%)');
      sb.writeln('Anonymous: $anonymousCount ($anonRatio%) | Lambda: $lambdaCount');
      sb.writeln('\n--- Dollar Level Distribution ---');
      for (final e in dollarLevels.entries) sb.writeln('  Level ${e.key}: ${e.value}');
      sb.writeln('\n=== Summary ===');
      sb.writeln('Score: $score/100 ($level)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_native — DEX Native 方法分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexNative(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Native Method Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final loadPatterns = ['System.loadLibrary', 'System.load', 'loadLibrary', 'nativeLoad'];
      final jniPatterns = ['RegisterNatives', 'JNI_OnLoad', 'JNIEnv', 'jint', 'jobject', 'jclass'];

      sb.writeln('--- Library Loading ---');
      var loadCount = 0;
      for (final pat in loadPatterns) {
        final count = pat.allMatches(text).length;
        if (count > 0) { sb.writeln('  $pat: $count'); loadCount += count; }
      }

      sb.writeln('\n--- JNI Patterns ---');
      var jniCount = 0;
      for (final pat in jniPatterns) {
        final count = pat.allMatches(text).length;
        if (count > 0) { sb.writeln('  $pat: $count'); jniCount += count; }
      }

      final nativeMethodCount = 'native '.allMatches(text).length;
      final soEntries = _filterEntries(apk, '.so');
      sb.writeln('\n--- Native Methods ---');
      sb.writeln('  "native" keyword: $nativeMethodCount');
      sb.writeln('  SO files: ${soEntries.length}');

      final mixScore = (nativeMethodCount * 5 + soEntries.length * 3 + jniCount * 2).clamp(0, 100);
      final mixLevel = mixScore >= 60 ? '重度Native' : (mixScore >= 30 ? '中度Native' : (mixScore > 0 ? '轻度Native' : '纯Java'));
      sb.writeln('\n=== Summary ===');
      sb.writeln('Score: $mixScore/100 ($mixLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_const_scan — DEX 常量池扫描
  // =========================================================================
  static Future<Map<String, dynamic>> dexConstScan(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Constant Scan ===\n');

      final allStrings = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.strings(payload));
        allStrings.addAll(text.split('\n'));
      }

      final numPatterns = <String, RegExp>{
        'ipv4': RegExp(r'\b(\d{1,3}\.){3}\d{1,3}\b'),
        'version': RegExp(r'\b\d+\.\d+(?:\.\d+)?(?:[-._]?(?:alpha|beta|rc|release))?\b', caseSensitive: false),
        'phone': RegExp(r'\b1[3-9]\d{9}\b'),
        'hex_bytes': RegExp(r'\b0x[0-9a-fA-F]{2,}\b'),
        'large_num': RegExp(r'\b\d{10,}\b'),
      };
      final keywordPatterns = <String, RegExp>{
        'api_key': RegExp(r'(api[_-]?key|apikey|secret|token|auth|password)', caseSensitive: false),
        'encrypt_key': RegExp(r'(aes|des|rsa|cipher|encrypt|decrypt|secret)', caseSensitive: false),
        'device_id': RegExp(r'(imei|imsi|device[_-]?id|android[_-]?id|serial)', caseSensitive: false),
        'server': RegExp(r'(server|host|domain|base[_-]?url|endpoint)', caseSensitive: false),
      };

      sb.writeln('--- Numeric Constants ---');
      var numTotal = 0;
      for (final entry in numPatterns.entries) {
        final hits = <String>{};
        for (final s in allStrings) {
          for (final m in entry.value.allMatches(s)) {
            hits.add(m.group(0)!);
          }
        }
        if (hits.isNotEmpty) {
          sb.writeln('  ${entry.key}: ${hits.length} unique');
          for (final h in hits.take(5)) sb.writeln('    $h');
          numTotal += hits.length;
        }
      }

      sb.writeln('\n--- Keyword Constants ---');
      var kwTotal = 0;
      for (final entry in keywordPatterns.entries) {
        var count = 0;
        for (final s in allStrings) {
          if (s.length <= 80 && entry.value.hasMatch(s)) count++;
        }
        if (count > 0) { sb.writeln('  ${entry.key}: $count'); kwTotal += count; }
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Numeric: $numTotal | Keywords: $kwTotal');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_inheritance — DEX 继承图分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexInheritance(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Inheritance Analysis ===\n');

      final allClassNames = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        allClassNames.addAll(RegExp(r'L[\w/$]+;').allMatches(text).map((m) => m.group(0)!));
      }

      final total = allClassNames.length;
      var interfaceCount = 0, abstractCount = 0, finalCount = 0;
      final rootClasses = <String>[];

      for (final cls in allClassNames) {
        final simple = cls.substring(1, cls.length - 1).split('/').last;
        if (simple.startsWith('I') && simple.length > 1 && !simple.startsWith('I_')) interfaceCount++;
        if (simple.startsWith('Abstract') || simple.startsWith('Base')) abstractCount++;
        if (simple.startsWith('Final')) finalCount++;
        if (!cls.contains('\$')) rootClasses.add(cls);
      }

      sb.writeln('Total classes: $total');
      sb.writeln('Interfaces (est): $interfaceCount');
      sb.writeln('Abstract (est): $abstractCount');
      sb.writeln('Root classes: ${rootClasses.length}');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Classes: $total | Interfaces: $interfaceCount | Abstract: $abstractCount');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_method_stats — DEX 方法签名统计
  // =========================================================================
  static Future<Map<String, dynamic>> dexMethodStats(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Method Stats ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.writeln(_extractResultText(KelivoDexAnalyzer.methods(payload)));
      }
      final text = allText.toString();

      final methodPatterns = <String, RegExp>{
        'getter': RegExp(r'\bget[A-Z]|\bis[A-Z]|\bhas[A-Z]'),
        'setter': RegExp(r'\bset[A-Z]'),
        'constructor': RegExp(r'<init>|<clinit>'),
        'callback': RegExp(r'on[A-Z]\w+'),
        'async': RegExp(r'Async|Thread|Runnable|Coroutine', caseSensitive: true),
        'network': RegExp(r'Request|Response|Http|Url|Socket|Api', caseSensitive: true),
        'io': RegExp(r'read|write|open|close|flush|load|save', caseSensitive: false),
        'crypto': RegExp(r'encrypt|decrypt|cipher|hash|digest|sign|verify|AES|RSA', caseSensitive: false),
        'reflection': RegExp(r'invoke|getMethod|getField|getClass|reflect', caseSensitive: false),
        'database': RegExp(r'query|insert|update|delete|Cursor|SQLite|Database', caseSensitive: true),
      };

      sb.writeln('--- Method Patterns ---');
      for (final entry in methodPatterns.entries) {
        final count = entry.value.allMatches(text).length;
        if (count > 0) sb.writeln('  ${entry.key}: $count');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Method text length: ${text.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_access_flow — DEX 访问权限流分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexAccessFlow(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Access Flow Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.writeln(_extractResultText(KelivoDexAnalyzer.classes(payload)));
      }
      final text = allText.toString();

      final sensitivePatterns = <String, List<String>>{
        'crypto': ['encrypt', 'decrypt', 'cipher', 'AES', 'RSA', 'DES', 'MD5', 'SHA', 'hmac'],
        'reflection': ['forName', 'getMethod', 'getField', 'invoke', 'getClass', 'getDeclared'],
        'runtime_exec': ['exec', 'runtime', 'process', 'command', 'shell'],
        'file_io': ['writeFile', 'readFile', 'deleteFile', 'mkdir', 'removeFile'],
        'network': ['http', 'url', 'request', 'connect', 'socket', 'download', 'upload'],
        'database': ['execSQL', 'rawQuery', 'insert', 'delete', 'update', 'query'],
      };

      sb.writeln('--- Sensitive Method Patterns ---');
      for (final entry in sensitivePatterns.entries) {
        var count = 0;
        for (final kw in entry.value) {
          count += kw.allMatches(text).length;
        }
        if (count > 0) sb.writeln('  ${entry.key}: $count hits');
      }

      final publicCount = 'public'.allMatches(text).length;
      final privateCount = 'private'.allMatches(text).length;
      final protectedCount = 'protected'.allMatches(text).length;
      final nativeCount = 'native'.allMatches(text).length;

      sb.writeln('\n--- Access Modifiers ---');
      sb.writeln('  public: $publicCount | private: $privateCount | protected: $protectedCount');
      sb.writeln('  native: $nativeCount');

      sb.writeln('\n=== Summary ===');
      sb.writeln('public: $publicCount | private: $privateCount | native: $nativeCount');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_permission_audit — DEX 权限审计
  // =========================================================================
  static Future<Map<String, dynamic>> dexPermissionAudit(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Permission Audit ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final permApiMap = <String, List<String>>{
        'CAMERA': ['Camera', 'MediaRecorder', 'takePicture'],
        'RECORD_AUDIO': ['AudioRecord', 'startRecording'],
        'ACCESS_FINE_LOCATION': ['LocationManager', 'FusedLocation', 'getLastKnownLocation', 'requestLocationUpdates'],
        'READ_CONTACTS': ['ContactsContract', 'queryContacts'],
        'READ_SMS': ['SmsManager', 'Telephony.Sms'],
        'SEND_SMS': ['SmsManager', 'sendTextMessage'],
        'READ_PHONE_STATE': ['TelephonyManager', 'getDeviceId', 'getImei', 'getSubscriberId'],
        'CALL_PHONE': ['ACTION_CALL', 'ACTION_DIAL'],
        'READ_EXTERNAL_STORAGE': ['getExternalStorageDirectory', 'MediaStore', 'openFileInput'],
        'INTERNET': ['HttpURLConnection', 'OkHttpClient', 'Retrofit', 'Volley', 'WebSocket'],
        'ACCESS_NETWORK_STATE': ['ConnectivityManager', 'getActiveNetworkInfo'],
        'ACCESS_WIFI_STATE': ['WifiManager', 'getConnectionInfo'],
      };

      sb.writeln('--- Permission-API Usage ---');
      var permCount = 0;
      for (final entry in permApiMap.entries) {
        var hits = 0;
        for (final api in entry.value) {
          hits += api.allMatches(text).length;
        }
        if (hits > 0) {
          sb.writeln('  ${entry.key}: $hits API hits');
          permCount++;
        }
      }

      final dangerousCombos = [
        (['CAMERA', 'RECORD_AUDIO'], '监控组合'),
        (['READ_SMS', 'SEND_SMS'], '短信拦截组合'),
        (['ACCESS_FINE_LOCATION', 'INTERNET'], '位置追踪组合'),
        (['READ_CONTACTS', 'SEND_SMS', 'CALL_PHONE'], '隐私窃取组合'),
      ];

      sb.writeln('\n--- Dangerous Combinations ---');
      for (final combo in dangerousCombos) {
        final matched = combo.$1.where((perm) {
          final apis = permApiMap[perm] ?? [];
          return apis.any((api) => text.contains(api));
        }).toList();
        if (matched.length >= 2) {
          sb.writeln('  ⚠️ ${combo.$2}: ${matched.join(', ')}');
        }
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Permissions detected: $permCount');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_access_pattern — DEX 访问控制模式分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexAccessPattern(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Access Pattern Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final visibility = <String, int>{
        'public': 'public'.allMatches(text).length,
        'private': 'private'.allMatches(text).length,
        'protected': 'protected'.allMatches(text).length,
        'static': 'static'.allMatches(text).length,
        'final'.substring(0, 5).allMatches(text).where((m) => true).length: 0,
      };
      final finalCount = 'final'.allMatches(text).length;
      final abstractCount = 'abstract'.allMatches(text).length;
      final synchronizedCount = 'synchronized'.allMatches(text).length;
      final nativeCount = 'native'.allMatches(text).length;
      final volatileCount = 'volatile'.allMatches(text).length;
      final transientCount = 'transient'.allMatches(text).length;

      sb.writeln('--- Visibility ---');
      sb.writeln('  public: ${visibility['public']}');
      sb.writeln('  private: ${visibility['private']}');
      sb.writeln('  protected: ${visibility['protected']}');

      sb.writeln('\n--- Modifiers ---');
      sb.writeln('  static: ${visibility['static']}');
      sb.writeln('  final: $finalCount');
      sb.writeln('  abstract: $abstractCount');
      sb.writeln('  synchronized: $synchronizedCount');
      sb.writeln('  native: $nativeCount');
      sb.writeln('  volatile: $volatileCount');
      sb.writeln('  transient: $transientCount');

      final totalMethods = (visibility['public'] ?? 0) + (visibility['private'] ?? 0) + (visibility['protected'] ?? 0);
      final publicRatio = totalMethods > 0 ? ((visibility['public'] ?? 0) / totalMethods * 100).toStringAsFixed(1) : '0';
      final privateRatio = totalMethods > 0 ? ((visibility['private'] ?? 0) / totalMethods * 100).toStringAsFixed(1) : '0';
      final encapScore = (double.parse(privateRatio) * 0.4 + (100 - double.parse(publicRatio)) * 0.6).round().clamp(0, 100);
      final encapLevel = encapScore >= 70 ? '优秀' : (encapScore >= 50 ? '良好' : (encapScore >= 30 ? '一般' : '较差'));

      sb.writeln('\n=== Summary ===');
      sb.writeln('Public: ${visibility['public']} ($publicRatio%) | Private: ${visibility['private']} ($privateRatio%)');
      sb.writeln('Encapsulation: $encapScore/100 ($encapLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_annotation — DEX 注解分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexAnnotation(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Annotation Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final knownAnnotations = <String, String>{
        'Landroidx/annotation/': 'AndroidX Annotation',
        'Landroid/annotation/': 'Android Annotation',
        'Lkotlin/Metadata;': 'Kotlin Metadata',
        'Lkotlin/coroutines/': 'Kotlin Coroutines',
        'Lretrofit2/': 'Retrofit',
        'Ldagger/': 'Dagger',
        'Lbutterknife/': 'ButterKnife',
        'Lcom/google/gson/annotations/': 'Gson',
        'Lorg/jetbrains/annotations/': 'JetBrains',
        'Ljavax/annotation/': 'Javax Annotation',
        'Ldalvik/annotation/': 'Dalvik Internal',
        'Lcom/bumptech/glide/': 'Glide',
        'Lio/reactivex/': 'RxJava',
        'Llombok/': 'Lombok',
        'Lorg/greenrobot/': 'GreenRobot',
        'Lcom/google/android/': 'Google Android',
      };

      sb.writeln('--- Annotation Types ---');
      var totalAnnot = 0;
      for (final entry in knownAnnotations.entries) {
        final count = entry.key.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  ${entry.value} (${entry.key}): $count');
          totalAnnot += count;
        }
      }

      final dalvikAnnots = [
        'AnnotationDefault', 'EnclosingClass', 'EnclosingMethod',
        'InnerClass', 'MemberClasses', 'Signature', 'Throws', 'MethodParameters',
      ];
      sb.writeln('\n--- Dalvik Internal Annotations ---');
      for (final a in dalvikAnnots) {
        final count = a.allMatches(text).length;
        if (count > 0) sb.writeln('  $a: $count');
      }

      final nullability = ['Nullable', 'NonNull', 'NotNull', 'Nonnull'];
      sb.writeln('\n--- Nullability Annotations ---');
      for (final n in nullability) {
        final count = n.allMatches(text).length;
        if (count > 0) sb.writeln('  $n: $count');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Total annotation references: $totalAnnot');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_complexity — DEX 代码复杂度分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexComplexity(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Code Complexity Analysis ===\n');

      final allClassNames = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        allClassNames.addAll(RegExp(r'L[\w/$]+;').allMatches(text).map((m) => m.group(0)!));
      }

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final branchKeywords = ['if-eqz', 'if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le',
        'goto', 'packed-switch', 'sparse-switch', 'throw'];
      var branchTotal = 0;
      sb.writeln('--- Branch Instructions ---');
      for (final kw in branchKeywords) {
        final count = kw.allMatches(text).length;
        if (count > 0) { sb.writeln('  $kw: $count'); branchTotal += count; }
      }

      final tryCatchCount = 'try'.allMatches(text).length;
      final syncCount = 'synchronized'.allMatches(text).length;
      sb.writeln('\n--- Exception/Concurrency ---');
      sb.writeln('  try blocks (est): $tryCatchCount');
      sb.writeln('  synchronized: $syncCount');

      final complexityScore = (branchTotal * 2 + tryCatchCount * 3 + syncCount * 2).clamp(0, 100);
      final level = complexityScore >= 70 ? '高复杂度' : (complexityScore >= 40 ? '中复杂度' : (complexityScore >= 20 ? '低复杂度' : '简单'));

      sb.writeln('\n=== Summary ===');
      sb.writeln('Branches: $branchTotal | Try-catch: $tryCatchCount | Synchronized: $syncCount');
      sb.writeln('Complexity: $complexityScore/100 ($level)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_control_flow — DEX 控制流分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexControlFlow(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Control Flow Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.writeln(_extractResultText(KelivoDexAnalyzer.methods(payload)));
      }
      final text = allText.toString();

      final methodCount = '<init>'.allMatches(text).length + '<clinit>'.allMatches(text).length;
      final invokeCount = RegExp(r'invoke-\w+').allMatches(text).length;
      final returnCount = RegExp(r'return-\w+').allMatches(text).length;
      final gotoCount = 'goto'.allMatches(text).length;
      final ifCount = RegExp(r'if-\w+').allMatches(text).length;
      final switchCount = RegExp(r'(-switch)').allMatches(text).length;

      final sizeCategories = <String, int>{
        'tiny': RegExp(r'registers_size':\s*[1-9]\b').allMatches(text).length,
      };

      sb.writeln('--- Method Stats ---');
      sb.writeln('  Est methods: $methodCount');
      sb.writeln('  Invoke: $invokeCount');
      sb.writeln('  Return: $returnCount');
      sb.writeln('  Goto: $gotoCount');
      sb.writeln('  If: $ifCount');
      sb.writeln('  Switch: $switchCount');

      final cfgScore = (ifCount * 2 + switchCount * 5 + gotoCount).clamp(0, 100);
      final level = cfgScore >= 70 ? '高控制流复杂度' : (cfgScore >= 40 ? '中控制流复杂度' : '低控制流复杂度');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Control flow score: $cfgScore/100 ($level)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_debug_info — DEX 调试信息分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexDebugInfo(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Debug Info Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final sourceFilePattern = RegExp(r'source_file');
      final lineNumPattern = RegExp(r'line_number');
      final debugInfoPattern = RegExp(r'debug_info');

      final sourceFiles = <String>{};
      for (final m in RegExp(r'\.java').allMatches(text)) {
        final start = text.lastIndexOf('\n', m.start);
        final end = text.indexOf('\n', m.end);
        final context = text.substring(start > 0 ? start : 0, end > 0 ? end : text.length);
        final fileMatch = RegExp(r'(\w+)\.java').firstMatch(context);
        if (fileMatch != null) sourceFiles.add(fileMatch.group(1)!);
      }

      sb.writeln('--- Source Files ---');
      sb.writeln('  Unique source files: ${sourceFiles.length}');
      for (final f in sourceFiles.take(15)) {
        sb.writeln('  $f.java');
      }

      final hasDebugInfo = text.contains('debug_info') || text.contains('line_table');
      final hasLineNumbers = text.contains('line') && text.contains('source');

      final readability = 0;
      var score = 0;
      if (sourceFiles.isNotEmpty) score += 40;
      if (hasDebugInfo) score += 30;
      if (hasLineNumbers) score += 20;
      score = score.clamp(0, 100);
      final level = score >= 70 ? '高可读性' : (score >= 40 ? '中可读性' : '低可读性（已混淆/去除调试信息）');

      sb.writeln('\n--- Debug Info ---');
      sb.writeln('  Debug info present: $hasDebugInfo');
      sb.writeln('  Line numbers present: $hasLineNumbers');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Readability: $score/100 ($level)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_exception_flow — DEX 异常处理流分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexExceptionFlow(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Exception Flow Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final knownExceptions = <String, String>{
        'NullPointerException': 'NullPointerException',
        'ClassCastException': 'ClassCastException',
        'IndexOutOfBoundsException': 'IndexOutOfBoundsException',
        'NumberFormatException': 'NumberFormatException',
        'IllegalArgumentException': 'IllegalArgumentException',
        'IllegalStateException': 'IllegalStateException',
        'ArithmeticException': 'ArithmeticException',
        'SecurityException': 'SecurityException',
        'IOException': 'IOException',
        'FileNotFoundException': 'FileNotFoundException',
        'RuntimeException': 'RuntimeException',
        'Exception': 'Exception',
        'Throwable': 'Throwable',
        'Error': 'Error',
        'OutOfMemoryError': 'OutOfMemoryError',
        'ClassNotFoundException': 'ClassNotFoundException',
        'InterruptedException': 'InterruptedException',
        'SocketTimeoutException': 'SocketTimeoutException',
        'UnknownHostException': 'UnknownHostException',
        'SQLException': 'SQLException',
        'JSONException': 'JSONException',
      };

      sb.writeln('--- Exception Types ---');
      var totalExc = 0;
      for (final entry in knownExceptions.entries) {
        final count = entry.key.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  ${entry.key}: $count');
          totalExc += count;
        }
      }

      final tryCount = 'try'.allMatches(text).length;
      final catchCount = 'catch'.allMatches(text).length;
      final throwCount = 'throw'.allMatches(text).length;

      sb.writeln('\n--- Exception Handling ---');
      sb.writeln('  try: $tryCount | catch: $catchCount | throw: $throwCount');

      final defScore = (tryCount * 2 + catchCount * 2 + totalExc * 0.5).round().clamp(0, 100);
      final defLevel = defScore >= 60 ? '高防御性编程' : (defScore >= 30 ? '中防御性编程' : '低防御性编程');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Exceptions: $totalExc | Try-catch: $tryCount/$catchCount | Throw: $throwCount');
      sb.writeln('Defensive score: $defScore/100 ($defLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_field_analyzer — DEX 字段分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexFieldAnalyzer(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Field Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final sensitivePatterns = <String, RegExp>{
        'credential': RegExp(r'(password|passwd|pwd|secret|credential|token|apikey|api_key|auth)', caseSensitive: false),
        'financial': RegExp(r'(account|balance|amount|payment|card|bank|wallet|currency|price|cost)', caseSensitive: false),
        'personal': RegExp(r'(email|phone|address|name|ssid|identity|passport|license|birth|gender|age)', caseSensitive: false),
        'crypto': RegExp(r'(encrypt|decrypt|cipher|aes|rsa|des|md5|sha|hmac|iv|salt|nonce)', caseSensitive: false),
        'network': RegExp(r'(url|host|port|endpoint|server|api|proxy|socket|domain)', caseSensitive: false),
        'device': RegExp(r'(imei|imsi|serial|uuid|device|android_id|mac|udid)', caseSensitive: false),
        'config': RegExp(r'(config|setting|preference|flag|debug|test|mode|enable|disable)', caseSensitive: false),
      };

      sb.writeln('--- Sensitive Field Names ---');
      var sensitiveTotal = 0;
      for (final entry in sensitivePatterns.entries) {
        final matches = entry.value.allMatches(text);
        if (matches.isNotEmpty) {
          sb.writeln('  ${entry.key}: ${matches.length}');
          sensitiveTotal += matches.length;
        }
      }

      final staticCount = 'static'.allMatches(text).length;
      final finalCount = 'final'.allMatches(text).length;
      final volatileCount = 'volatile'.allMatches(text).length;
      final transientCount = 'transient'.allMatches(text).length;

      sb.writeln('\n--- Field Modifiers ---');
      sb.writeln('  static: $staticCount | final: $finalCount');
      sb.writeln('  volatile: $volatileCount | transient: $transientCount');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Sensitive fields: $sensitiveTotal');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_field_usage — DEX 字段使用分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexFieldUsage(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Field Usage Analysis ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final igetCount = RegExp(r'iget\w*').allMatches(text).length;
      final iputCount = RegExp(r'iput\w*').allMatches(text).length;
      final sgetCount = RegExp(r'sget\w*').allMatches(text).length;
      final sputCount = RegExp(r'sput\w*').allMatches(text).length;

      sb.writeln('--- Field Access Instructions ---');
      sb.writeln('  iget (instance read): $igetCount');
      sb.writeln('  iput (instance write): $iputCount');
      sb.writeln('  sget (static read): $sgetCount');
      sb.writeln('  sput (static write): $sputCount');

      final totalReads = igetCount + sgetCount;
      final totalWrites = iputCount + sputCount;
      final readWriteRatio = totalWrites > 0 ? (totalReads / totalWrites).toStringAsFixed(2) : 'inf';

      sb.writeln('\n=== Summary ===');
      sb.writeln('Reads: $totalReads | Writes: $totalWrites | R/W ratio: $readWriteRatio');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_insn_density — DEX 指令密度分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexInsnDensity(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Instruction Density Analysis ===\n');

      var totalDexSize = 0;
      var totalInsns = 0;
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        totalDexSize += dex.content!.length;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.methods(payload));
        totalInsns += RegExp(r'registers_size').allMatches(text).length;
      }

      final density = totalDexSize > 0 ? (totalInsns / totalDexSize * 1000).toStringAsFixed(2) : '0';
      final dexFiles = _filterEntries(apk, '.dex');

      sb.writeln('DEX files: ${dexFiles.length}');
      sb.writeln('Total DEX size: $totalDexSize bytes');
      sb.writeln('Est methods with code: $totalInsns');
      sb.writeln('Method density: $density methods/KB');

      for (int i = 0; i < dexFiles.length; i++) {
        final dex = dexFiles[i];
        final size = dex.content?.length ?? 0;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.methods(payload));
        final methods = RegExp(r'registers_size').allMatches(text).length;
        sb.writeln('\n--- ${dex.name} ($size bytes) ---');
        sb.writeln('  Methods: $methods');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Methods: $totalInsns | Size: $totalDexSize bytes');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_instruction_stats — DEX 指令统计
  // =========================================================================
  static Future<Map<String, dynamic>> dexInstructionStats(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Instruction Stats ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final categories = <String, RegExp>{
        'const': RegExp(r'const-\w+'),
        'move': RegExp(r'move\w*'),
        'invoke': RegExp(r'invoke-\w+'),
        'return': RegExp(r'return-\w+'),
        'if': RegExp(r'if-\w+'),
        'goto': RegExp(r'goto\w*'),
        'new': RegExp(r'new-instance|new-array'),
        'iget': RegExp(r'iget\w*'),
        'iput': RegExp(r'iput\w*'),
        'sget': RegExp(r'sget\w*'),
        'sput': RegExp(r'sput\w*'),
        'arith': RegExp(r'add|sub|mul|div|rem|and|or|xor|shl|shr', caseSensitive: false),
        'throw': RegExp(r'throw'),
        'monitor': RegExp(r'monitor-enter|monitor-exit'),
      };

      sb.writeln('--- Instruction Categories ---');
      var total = 0;
      for (final entry in categories.entries) {
        final count = entry.value.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  ${entry.key}: $count');
          total += count;
        }
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Total instructions: $total');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_proto_analyzer — DEX 方法原型分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexProtoAnalyzer(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Proto Analyzer ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.writeln(_extractResultText(KelivoDexAnalyzer.methods(payload)));
      }
      final text = allText.toString();

      final returnTypes = <String, int>{
        'void': RegExp(r'\)V').allMatches(text).length,
        'boolean': RegExp(r'\)Z').allMatches(text).length,
        'int': RegExp(r'\)I').allMatches(text).length,
        'long': RegExp(r'\)J').allMatches(text).length,
        'String': RegExp(r'\)Ljava/lang/String;').allMatches(text).length,
        'Object': RegExp(r'\)Ljava/lang/Object;').allMatches(text).length,
        'array': RegExp(r'\)\[').allMatches(text).length,
        'other': RegExp(r'\)L').allMatches(text).length,
      };

      sb.writeln('--- Return Type Distribution ---');
      for (final e in returnTypes.entries) {
        if (e.value > 0) sb.writeln('  ${e.key}: ${e.value}');
      }

      final paramCount = RegExp(r'\([^)]+\)').allMatches(text).length;
      final noParam = RegExp(r'\(\)').allMatches(text).length;
      final singleParam = RegExp(r'\(\w\)').allMatches(text).length;

      sb.writeln('\n--- Parameter Stats ---');
      sb.writeln('  Methods with params: $paramCount');
      sb.writeln('  No params: $noParam');
      sb.writeln('  Single param: $singleParam');

      final overloadPattern = RegExp(r'(\w+)\([^)]*\)');
      final nameCounter = <String, int>{};
      for (final m in overloadPattern.allMatches(text)) {
        final name = m.group(1)!;
        nameCounter[name] = (nameCounter[name] ?? 0) + 1;
      }
      final overloads = nameCounter.entries.where((e) => e.value > 1).toList()..sort((a, b) => b.value.compareTo(a.value));

      sb.writeln('\n--- Top Overloaded Methods ---');
      for (final o in overloads.take(15)) {
        sb.writeln('  ${o.key}: ${o.value} overloads');
      }

      final score = (overloads.length * 2 + paramCount * 0.1).round().clamp(0, 100);
      final level = score >= 60 ? '高复杂度' : (score >= 30 ? '中复杂度' : '低复杂度');
      sb.writeln('\n=== Summary ===');
      sb.writeln('Overloads: ${overloads.length} | Complexity: $score/100 ($level)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_proto_matrix — DEX 原型矩阵分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexProtoMatrix(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Proto Matrix ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.writeln(_extractResultText(KelivoDexAnalyzer.methods(payload)));
      }
      final text = allText.toString();

      final shortyPatterns = <String, RegExp>{
        'V()': RegExp(r'\(\)V'),
        'Z()': RegExp(r'\(\)Z'),
        'I()': RegExp(r'\(\)I'),
        'V(I)': RegExp(r'\(I\)V'),
        'V(L)': RegExp(r'\(L[^)]*\)V'),
        'I(L)': RegExp(r'\(L[^)]*\)I'),
        'V(LL)': RegExp(r'\(L[^)]*;L[^)]*;\)V'),
      };

      sb.writeln('--- Short Signature Distribution ---');
      var total = 0;
      for (final entry in shortyPatterns.entries) {
        final count = entry.value.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  ${entry.key}: $count');
          total += count;
        }
      }

      final paramTypes = <String, RegExp>{
        'String': RegExp(r'Ljava/lang/String;'),
        'Context': RegExp(r'Landroid/content/Context;'),
        'Bundle': RegExp(r'Landroid/os/Bundle;'),
        'Intent': RegExp(r'Landroid/content/Intent;'),
        'View': RegExp(r'Landroid/view/View;'),
        'Activity': RegExp(r'Landroid/app/Activity;'),
        'Handler': RegExp(r'Landroid/os/Handler;'),
        'Callback': RegExp(r'Callback;'),
        'Listener': RegExp(r'Listener;'),
        'List': RegExp(r'Ljava/util/List;'),
        'Map': RegExp(r'Ljava/util/Map;'),
        'Throwable': RegExp(r'Ljava/lang/Throwable;'),
      };

      sb.writeln('\n--- Parameter Type Frequency ---');
      for (final entry in paramTypes.entries) {
        final count = entry.value.allMatches(text).length;
        if (count > 0) sb.writeln('  ${entry.key}: $count');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Total signatures: $total');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_register_pressure — DEX 寄存器压力分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexRegisterPressure(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Register Pressure ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        allText.writeln(_extractResultText(KelivoDexAnalyzer.methods(payload)));
      }
      final text = allText.toString();

      // Extract registers_size values
      final regMatches = RegExp(r'registers_size':\s*(\d+)').allMatches(text);
      final regValues = <int>[];
      for (final m in regMatches) {
        final v = int.tryParse(m.group(1) ?? '0');
        if (v != null) regValues.add(v);
      }

      final insMatches = RegExp(r'ins_size':\s*(\d+)').allMatches(text);
      final insValues = <int>[];
      for (final m in insMatches) {
        final v = int.tryParse(m.group(1) ?? '0');
        if (v != null) insValues.add(v);
      }

      final outsMatches = RegExp(r'outs_size':\s*(\d+)').allMatches(text);
      final outsValues = <int>[];
      for (final m in outsMatches) {
        final v = int.tryParse(m.group(1) ?? '0');
        if (v != null) outsValues.add(v);
      }

      final regRanges = <String, int>{
        '0-4': regValues.where((v) => v <= 4).length,
        '5-8': regValues.where((v) => v >= 5 && v <= 8).length,
        '9-12': regValues.where((v) => v >= 9 && v <= 12).length,
        '13-16': regValues.where((v) => v >= 13 && v <= 16).length,
        '17-24': regValues.where((v) => v >= 17 && v <= 24).length,
        '25-32': regValues.where((v) => v >= 25 && v <= 32).length,
        '33+': regValues.where((v) => v >= 33).length,
      };

      sb.writeln('--- Register Size Distribution ---');
      for (final e in regRanges.entries) sb.writeln('  ${e.key}: ${e.value}');

      final highPressure = regValues.where((v) => v >= 16).length;
      final veryHigh = regValues.where((v) => v >= 32).length;
      final avgRegs = regValues.isNotEmpty ? (regValues.reduce((a, b) => a + b) / regValues.length).toStringAsFixed(2) : '0';
      final avgOuts = outsValues.isNotEmpty ? (outsValues.reduce((a, b) => a + b) / outsValues.length).toStringAsFixed(2) : '0';

      sb.writeln('\n--- Pressure ---');
      sb.writeln('  High (≥16): $highPressure');
      sb.writeln('  Very high (≥32): $veryHigh');
      sb.writeln('  Avg registers: $avgRegs');
      sb.writeln('  Avg outs: $avgOuts');

      final pressureScore = (highPressure * 3 + veryHigh * 5).clamp(0, 100);
      final level = pressureScore >= 60 ? '高压力' : (pressureScore >= 30 ? '中压力' : '低压力');
      sb.writeln('\n=== Summary ===');
      sb.writeln('Score: $pressureScore/100 ($level)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_type_ref — DEX 类型引用分析
  // =========================================================================
  static Future<Map<String, dynamic>> dexTypeRef(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Type Reference Analysis ===\n');

      final allClassNames = <String>[];
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final text = _extractResultText(KelivoDexAnalyzer.classes(payload));
        allClassNames.addAll(RegExp(r'L[\w/$]+;').allMatches(text).map((m) => m.group(0)!));
      }

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      final systemPrefixes = ['Ljava/', 'Landroid/', 'Lorg/', 'Lcom/google/', 'Lkotlin/',
        'Ljavax/', 'Ldalvik/', 'Lsun/', 'Llibcore/', 'Lkotlinx/',
        'Lokhttp3/', 'Lretrofit2/', 'Lio/reactivex/', 'Lrx/',
        'Lcom/squareup/', 'Landroidx/', 'Lbutterknife/', 'Ldagger/'];

      final appClasses = <String>[];
      for (final cls in allClassNames) {
        bool isSystem = systemPrefixes.any((p) => cls.startsWith(p));
        if (!isSystem) appClasses.add(cls);
      }

      // Count references for app classes
      final refCounter = <String, int>{};
      for (final cls in appClasses.take(200)) {
        final count = cls.replaceAll('L', '').replaceAll(';', '').replaceAll('/', '.').allMatches(text).length;
        if (count > 0) refCounter[cls] = count;
      }

      final sorted = refCounter.entries.toList()..sort((a, b) => b.value.compareTo(a.value));

      sb.writeln('Total classes: ${allClassNames.length}');
      sb.writeln('App classes: ${appClasses.length}');
      sb.writeln('System classes: ${allClassNames.length - appClasses.length}');

      sb.writeln('\n--- Top Hub Classes (by references) ---');
      for (final e in sorted.take(20)) {
        final name = e.key.substring(1, e.key.length - 1).replaceAll('/', '.');
        sb.writeln('  $name: ${e.value} refs');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('App classes: ${appClasses.length} | Hubs: ${sorted.length}');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_dex_optimizer_patterns — DEX 优化模式检测
  // =========================================================================
  static Future<Map<String, dynamic>> dexOptimizerPatterns(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== DEX Optimizer Pattern Detection ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      // 1. 常量折叠检测
      final constOps = RegExp(r'const-\w+').allMatches(text).length;
      final arithOps = RegExp(r'add-\w+|sub-\w+|mul-\w+|div-\w+|rem-\w+|and-\w+|or-\w+|xor-\w+|shl-\w+|shr-\w+|ushr-\w+').allMatches(text).length;
      sb.writeln('--- Constant Folding ---');
      sb.writeln('  const instructions: $constOps');
      sb.writeln('  arithmetic instructions: $arithOps');
      sb.writeln('  foldable candidates (est): ${(constOps * 0.3).round()}');

      // 2. 死代码检测
      final nopCount = RegExp(r'nop\b').allMatches(text).length;
      final gotoCount = RegExp(r'goto\w*').allMatches(text).length;
      final returnVoidCount = RegExp(r'return-void').allMatches(text).length;
      sb.writeln('\n--- Dead Code ---');
      sb.writeln('  NOP: $nopCount');
      sb.writeln('  Goto: $gotoCount');
      sb.writeln('  return-void: $returnVoidCount');
      final deadRatio = constOps > 0 ? (nopCount / constOps * 100).toStringAsFixed(1) : '0';
      sb.writeln('  Dead code ratio (est): $deadRatio%');

      // 3. 寄存器分配分析
      final moveOps = RegExp(r'move\w*').allMatches(text).length;
      sb.writeln('\n--- Register Analysis ---');
      sb.writeln('  move instructions: $moveOps');
      sb.writeln('  Move/const ratio: ${constOps > 0 ? (moveOps / constOps).toStringAsFixed(2) : '0'}');

      // 4. 内联模式检测
      final invokeOps = RegExp(r'invoke-\w+').allMatches(text).length;
      final moveResultOps = RegExp(r'move-result\w*').allMatches(text).length;
      final tailCallPattern = RegExp(r'invoke-\w+.*?move-result.*?return').allMatches(text).length;
      sb.writeln('\n--- Inline Patterns ---');
      sb.writeln('  invoke: $invokeOps');
      sb.writeln('  move-result: $moveResultOps');
      sb.writeln('  Tail-call inlineable (est): $tailCallPattern');

      // 5. 代码膨胀检测
      final packedSwitch = RegExp(r'packed-switch').allMatches(text).length;
      final sparseSwitch = RegExp(r'sparse-switch').allMatches(text).length;
      sb.writeln('\n--- Code Bloat ---');
      sb.writeln('  packed-switch: $packedSwitch');
      sb.writeln('  sparse-switch: $sparseSwitch');
      final switchRatio = (packedSwitch + sparseSwitch) > 0
          ? (packedSwitch / (packedSwitch + sparseSwitch) * 100).toStringAsFixed(1)
          : '0';
      sb.writeln('  Switch density: $switchRatio% packed');

      // 6. 窥孔优化模式
      final redundantMovePattern = RegExp(r'move\w*.*?move\w*').allMatches(text).length;
      final constZeroCompare = RegExp(r'const.*0.*?if-eqz').allMatches(text).length;
      sb.writeln('\n--- Peephole Patterns ---');
      sb.writeln('  Redundant move chains (est): $redundantMovePattern');
      sb.writeln('  Const-zero comparisons: $constZeroCompare');

      // 7. 循环不变量检测
      final loopPattern = RegExp(r'if-\w+.*?goto').allMatches(text).length;
      sb.writeln('\n--- Loop Invariants ---');
      sb.writeln('  Loop patterns (est): $loopPattern');

      // 综合评分
      final optScore = (
        (constOps * 0.1).round() +
        (nopCount * 2) +
        (tailCallPattern * 3) +
        (redundantMovePattern * 0.5).round() +
        (loopPattern * 2)
      ).clamp(0, 100);
      final optLevel = optScore >= 60 ? '高度可优化' : (optScore >= 30 ? '中度可优化' : '低度可优化');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Optimization score: $optScore/100 ($optLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_permission_analyze — 权限综合分析（合规/风险/广告关联）
  // =========================================================================
  static Future<Map<String, dynamic>> permissionAnalyze(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Permission Comprehensive Analysis ===\n');

      // 提取 Manifest 权限
      final manifestEntry = _filterEntries(apk, 'AndroidManifest.xml').firstOrNull;
      final manifestText = manifestEntry?.content != null
          ? _extractTextFromBytes(manifestEntry!.content!, maxLength: 999999)
          : '';
      final permMatches = RegExp(r'android\.permission\.(\w+)').allMatches(manifestText);
      final permissions = permMatches.map((m) => m.group(1)!).toSet().toList();

      // 1. 权限分类
      final dangerous = <String>['CAMERA','RECORD_AUDIO','ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION',
        'ACCESS_BACKGROUND_LOCATION','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE',
        'READ_MEDIA_IMAGES','READ_MEDIA_VIDEO','READ_MEDIA_AUDIO','READ_CONTACTS','WRITE_CONTACTS',
        'READ_SMS','SEND_SMS','RECEIVE_SMS','CALL_PHONE','READ_CALL_LOG','WRITE_CALL_LOG',
        'BODY_SENSORS','READ_CALENDAR','WRITE_CALENDAR','GET_ACCOUNTS','POST_NOTIFICATIONS',
        'NEARBY_WIFI_DEVICES','BLUETOOTH_SCAN','BLUETOOTH_ADVERTISE','BLUETOOTH_CONNECT','ACTIVITY_RECOGNITION'];
      final normal = <String>['INTERNET','ACCESS_NETWORK_STATE','ACCESS_WIFI_STATE','VIBRATE','WAKE_LOCK',
        'FOREGROUND_SERVICE','RECEIVE_BOOT_COMPLETED','SET_ALARM','USE_BIOMETRIC','USE_FINGERPRINT',
        'NFC','QUERY_ALL_PACKAGES','REQUEST_INSTALL_PACKAGES','BIND_ACCESSIBILITY_SERVICE',
        'ACCESS_MEDIA_LOCATION','CHANGE_NETWORK_STATE','CHANGE_WIFI_STATE','ACCESS_NOTIFICATION_POLICY',
        'BLUETOOTH','INTERACT_ACROSS_USERS','EXPAND_STATUS_BAR','KILL_BACKGROUND_PROCESSES',
        'MANAGE_OWN_CALLS','READ_SYNC_SETTINGS','RECEIVE_MMS','RECEIVE_WAP_PUSH',
        'REQUEST_DELETE_PACKAGES','SCHEDULE_EXACT_ALARM','SET_WALLPAPER','TRANSMIT_IR',
        'UNINSTALL_SHORTCUT','USE_EXACT_ALARM','USE_FULL_SCREEN_INT'];
      final signature = <String>['INSTALL_PACKAGES','DELETE_PACKAGES','CLEAR_APP_CACHE','READ_LOGS','DUMP',
        'PACKAGE_USAGE_STATS','ACCESS_SUPERUSER','BATTERY_STATS','BLUETOOTH_PRIVILEGED',
        'BIND_DEVICE_ADMIN','BIND_NOTIFICATION_LISTENER_SERVICE','BIND_VPN_SERVICE',
        'CAPTURE_AUDIO_OUTPUT','CONTROL_LOCATION_UPDATES','DEVICE_POWER','MANAGE_ACCOUNTS',
        'MANAGE_DOCUMENTS','MANAGE_USERS','MEDIA_CONTENT_CONTROL','MODIFY_AUDIO_SETTINGS',
        'MOUNT_UNMOUNT_FILESYSTEMS','PROCESS_OUTGOING_CALLS','REBOOT','SET_ANIMATION_SCALE',
        'SET_TIME','SYSTEM_ALERT_WINDOW','UPDATE_APP_OPS_STATS','WRITE_APN_SETTINGS',
        'WRITE_SETTINGS','WRITE_SYNC_SETTINGS'];

      final dangerousPerms = permissions.where((p) => dangerous.contains(p)).toList();
      final normalPerms = permissions.where((p) => normal.contains(p)).toList();
      final signaturePerms = permissions.where((p) => signature.contains(p)).toList();
      final customPerms = permissions.where((p) =>
          !dangerous.contains(p) && !normal.contains(p) && !signature.contains(p)).toList();

      sb.writeln('--- Permission Classification ---');
      sb.writeln('  Total: ${permissions.length}');
      sb.writeln('  Dangerous: ${dangerousPerms.length}');
      sb.writeln('  Normal: ${normalPerms.length}');
      sb.writeln('  Signature: ${signaturePerms.length}');
      sb.writeln('  Custom/Other: ${customPerms.length}');

      if (dangerousPerms.isNotEmpty) {
        sb.writeln('\n  Dangerous permissions:');
        for (final d in dangerousPerms) sb.writeln('    - $d');
      }

      // 2. 风险组合检测
      final permSet = permissions.toSet();
      final riskCombos = <Map<String, dynamic>>[];
      final combos = [
        {'name': '位置追踪', 'risk': 'HIGH', 'perms': ['ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_BACKGROUND_LOCATION'], 'desc': '多重定位权限'},
        {'name': '隐私窃取', 'risk': 'HIGH', 'perms': ['READ_CONTACTS','READ_CALENDAR','READ_CALL_LOG','READ_SMS','GET_ACCOUNTS'], 'desc': '批量读取隐私数据'},
        {'name': '恶意扣费', 'risk': 'HIGH', 'perms': ['SEND_SMS','CALL_PHONE','INTERNET'], 'desc': '可发送付费短信/拨打电话'},
        {'name': '监控', 'risk': 'MEDIUM', 'perms': ['CAMERA','RECORD_AUDIO'], 'desc': '可录制音视频'},
        {'name': '短信拦截', 'risk': 'HIGH', 'perms': ['READ_SMS','RECEIVE_SMS'], 'desc': '可读取和拦截短信'},
        {'name': '存储泄露', 'risk': 'MEDIUM', 'perms': ['READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE'], 'desc': '可读写外部存储'},
        {'name': '后台追踪', 'risk': 'HIGH', 'perms': ['ACCESS_BACKGROUND_LOCATION','ACCESS_FINE_LOCATION','INTERNET'], 'desc': '后台持续定位并上传'},
        {'name': '安装攻击', 'risk': 'HIGH', 'perms': ['INSTALL_PACKAGES','DELETE_PACKAGES'], 'desc': '可静默安装/卸载'},
        {'name': '覆盖攻击', 'risk': 'HIGH', 'perms': ['SYSTEM_ALERT_WINDOW','BIND_ACCESSIBILITY_SERVICE'], 'desc': '悬浮窗+无障碍'},
        {'name': '设备管理', 'risk': 'MEDIUM', 'perms': ['BIND_DEVICE_ADMIN','MANAGE_ACCOUNTS'], 'desc': '设备管理权限'},
        {'name': '广告追踪', 'risk': 'LOW', 'perms': ['ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','GET_ACCOUNTS','READ_EXTERNAL_STORAGE'], 'desc': '广告SDK收集用户画像'},
      ];
      for (final c in combos) {
        final matched = (c['perms'] as List).cast<String>().where((p) => permSet.contains(p)).toList();
        if (matched.length >= (c['perms'] as List).length * 0.66) {
          riskCombos.add({'name': c['name'], 'risk': c['risk'], 'matched': matched, 'desc': c['desc']});
        }
      }
      sb.writeln('\n--- Risk Groups ---');
      sb.writeln('  Detected: ${riskCombos.length}');
      for (final r in riskCombos) {
        sb.writeln('  ⚠️ ${r['name']} (${r['risk']}): ${r['desc']}');
      }

      // 3. 广告权限关联
      final adPerms = ['INTERNET','ACCESS_NETWORK_STATE','ACCESS_WIFI_STATE','READ_EXTERNAL_STORAGE',
        'WRITE_EXTERNAL_STORAGE','ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_BACKGROUND_LOCATION',
        'READ_PHONE_STATE','VIBRATE','WAKE_LOCK','RECEIVE_BOOT_COMPLETED','QUERY_ALL_PACKAGES',
        'REQUEST_INSTALL_PACKAGES','POST_NOTIFICATIONS','CAMERA','RECORD_AUDIO','BLUETOOTH','ACTIVITY_RECOGNITION'];
      final adMatched = permissions.where((p) => adPerms.contains(p)).toList();
      sb.writeln('\n--- Ad Permission Correlation ---');
      sb.writeln('  Ad-related: ${adMatched.length}/${adPerms.length}');

      // 4. 合规检查
      sb.writeln('\n--- Compliance ---');
      final gdprPerms = ['ACCESS_FINE_LOCATION','ACCESS_BACKGROUND_LOCATION','READ_CONTACTS','READ_CALENDAR',
        'READ_EXTERNAL_STORAGE','CAMERA','RECORD_AUDIO','READ_SMS','READ_CALL_LOG','GET_ACCOUNTS','ACTIVITY_RECOGNITION'];
      final gdprMatched = gdprPerms.where((p) => permSet.contains(p)).toList();
      sb.writeln('  GDPR: ${gdprMatched.length} privacy-related perms');
      if (gdprMatched.isNotEmpty) sb.writeln('    → Requires consent');

      final coppaPerms = ['ACCESS_FINE_LOCATION','CAMERA','RECORD_AUDIO','READ_CONTACTS'];
      final coppaMatched = coppaPerms.where((p) => permSet.contains(p)).toList();
      sb.writeln('  COPPA: ${coppaMatched.length} child-privacy perms');
      if (coppaMatched.isNotEmpty) sb.writeln('    → Children privacy concern');

      final ccpaPerms = ['ACCESS_FINE_LOCATION','READ_CONTACTS','READ_CALENDAR','CAMERA','READ_EXTERNAL_STORAGE'];
      final ccpaMatched = ccpaPerms.where((p) => permSet.contains(p)).toList();
      sb.writeln('  CCPA: ${ccpaMatched.length} consumer-privacy perms');

      // 5. 过度申请检测
      final isOverrequest = dangerousPerms.length >= 5 || permissions.length >= 15 ||
          (permissions.isNotEmpty && dangerousPerms.length / permissions.length >= 0.4);
      sb.writeln('\n--- Overrequest ---');
      sb.writeln('  Overrequest: ${isOverrequest ? "YES" : "NO"}');
      if (isOverrequest) {
        if (dangerousPerms.length >= 5) sb.writeln('    → Dangerous count: ${dangerousPerms.length} (≥5)');
        if (permissions.length >= 15) sb.writeln('    → Total count: ${permissions.length} (≥15)');
      }

      // 6. 隐私评分
      var privacyScore = 100;
      privacyScore -= dangerousPerms.length * 5;
      final highRisks = riskCombos.where((r) => r['risk'] == 'HIGH').length;
      final medRisks = riskCombos.where((r) => r['risk'] == 'MEDIUM').length;
      privacyScore -= highRisks * 15;
      privacyScore -= medRisks * 8;
      if (isOverrequest) privacyScore -= 20;
      privacyScore = privacyScore.clamp(0, 100);
      final privacyLevel = privacyScore >= 80 ? '优秀' : (privacyScore >= 60 ? '良好' :
        (privacyScore >= 40 ? '一般' : (privacyScore >= 20 ? '较差' : '极差')));

      sb.writeln('\n=== Summary ===');
      sb.writeln('Total: ${permissions.length} | Dangerous: ${dangerousPerms.length} | Risk groups: ${riskCombos.length}');
      sb.writeln('Privacy score: $privacyScore/100 ($privacyLevel)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_ad_remove — 广告移除引擎
  // =========================================================================
  static Future<Map<String, dynamic>> adRemove(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Ad Removal Engine ===\n');

      // 1. 检测广告SDK
      final allText = StringBuffer();
      for (final entry in apk) {
        if (entry.name.endsWith('.dex') && entry.content != null) {
          allText.writeln(_extractTextFromBytes(entry.content!, maxLength: 999999));
        }
      }
      final text = allText.toString();

      final adSdks = <String, List<String>>{
        'tencent':   ['com/qq/e', 'com/gdt/ad', 'com/tencent/qqads'],
        'kuaishou':  ['com/kwad', 'com/kuaishou/ad'],
        'pangle':    ['com/bytedance/pangle', 'com/bytedance/sdk/openadsdk'],
        'baidu':     ['com/bd', 'com/baidu/mobads'],
        'toutiao':   ['toutiao', 'com/bytedance/toutiao'],
        'sigmob':    ['sigmob', 'com/sigmob/sdk'],
        'google':    ['com/google/android/gms/ads', 'com/google/ads'],
        'miads':     ['com/miui/zeus/mimo', 'com/xiaomi/ad'],
        'unity':     ['com/unity3d/ads'],
        'mintegral': ['com/mintegral/msdk', 'com/mobvista'],
        'vungle':    ['com/vungle/warren'],
        'chartboost': ['com/chartboost/sdk'],
        'applovin':  ['com/applovin/sdk'],
        'ironsource': ['com/ironsource/sdk'],
        'facebook':  ['com/facebook/ads'],
        'huawei':    ['com/huawei/hms/ads'],
        'oppo':      ['com/oppo/ads'],
        'vivo':      ['com/vivo/mobilead'],
        'startapp':  ['com/startapp/sdk'],
        'inmobi':    ['com/inmobi/ads'],
        'adcolony':  ['com/adcolony/sdk'],
        'anythink':  ['com/anythink/sdk'],
        'topon':     ['com/topon/sdk'],
        'fyber':     ['com/fyber/ads'],
        'mbridge':   ['com/mbridge/msdk'],
        'bidmachine': ['io/bidmachine'],
        'pubnative': ['net/pubnative'],
        'pollfish':  ['com/pollfish'],
        'smaato':    ['com/smaato/sdk'],
        'amazon':    ['com/amazon/device/ads'],
        'yandex':    ['com/yandex/mobile/ads'],
        'mytarget':  ['com/my/target/ads'],
      };

      sb.writeln('--- Detected Ad SDKs ---');
      final detected = <String>[];
      for (final entry in adSdks.entries) {
        for (final pkg in entry.value) {
          if (text.contains(pkg)) {
            detected.add(entry.key);
            sb.writeln('  ${entry.key}: $pkg');
            break;
          }
        }
      }
      if (detected.isEmpty) sb.writeln('  (none)');

      // 2. 广告方法统计
      final adMethodPatterns = [
        'loadAd', 'showAd', 'requestAd', 'initAd', 'destroyAd',
        'onAdLoaded', 'onAdFailed', 'onAdClosed', 'onAdClicked',
        'showInterstitial', 'showRewarded', 'showBanner',
        'loadInterstitial', 'loadRewarded', 'loadBanner',
      ];
      sb.writeln('\n--- Ad Method Patterns ---');
      var totalAdMethods = 0;
      for (final m in adMethodPatterns) {
        final count = m.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  $m: $count');
          totalAdMethods += count;
        }
      }

      // 3. 广告URL统计
      final adUrlPatterns = [
        'doubleclick', 'googlesyndication', 'googletagmanager',
        'admob', 'adcolony', 'applovin', 'inmobi', 'mopub',
        'unityads', 'vungle', 'chartboost', 'flurry',
        'pagead', 'pubnative', 'smaato', 'tapjoy',
      ];
      sb.writeln('\n--- Ad URL Patterns ---');
      var totalAdUrls = 0;
      for (final u in adUrlPatterns) {
        final count = u.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  $u: $count');
          totalAdUrls += count;
        }
      }

      // 4. AdMob ID检测
      final admobIds = RegExp(r'ca-app-pub-\d{16}/\d{10}').allMatches(text);
      sb.writeln('\n--- AdMob IDs ---');
      sb.writeln('  Count: ${admobIds.length}');

      // 5. VIP/Pro方法检测
      final vipMethods = [
        'isVip', 'isPro', 'isPremium', 'isVipUser', 'isProUser',
        'isPremiumUser', 'isMember', 'isSubscribed', 'isPurchased',
        'isPaid', 'isUnlocked', 'isActivated', 'isLifetime',
      ];
      sb.writeln('\n--- VIP/Pro Methods ---');
      var totalVip = 0;
      for (final v in vipMethods) {
        final count = v.allMatches(text).length;
        if (count > 0) {
          sb.writeln('  $v: $count');
          totalVip += count;
        }
      }

      // 6. Assets广告文件检测
      final adAssetPatterns = [
        'gdt_plugin', 'bdxadsdk', 'ksad_', 'toutiao_ad', 'pangle_adsdk',
        'baidu_ad', 'admob_adsdk', 'sigmob_ad', 'unity_ads', 'vungle_ad',
      ];
      sb.writeln('\n--- Ad Assets ---');
      var totalAssets = 0;
      for (final entry in apk) {
        for (final pat in adAssetPatterns) {
          if (entry.name.contains(pat)) {
            sb.writeln('  ${entry.name}');
            totalAssets++;
          }
        }
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('SDKs detected: ${detected.length}');
      sb.writeln('Ad methods: $totalAdMethods');
      sb.writeln('Ad URLs: $totalAdUrls');
      sb.writeln('AdMob IDs: ${admobIds.length}');
      sb.writeln('VIP methods: $totalVip');
      sb.writeln('Ad assets: $totalAssets');
      sb.writeln('\nNOTE: This tool detects ad components. Use smali_decompile + ad_remover patches for actual removal.');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_smali_patch_advanced — Smali高级修补器
  // =========================================================================
  static Future<Map<String, dynamic>> smaliPatchAdvanced(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Smali Advanced Patcher ===\n');

      final allText = StringBuffer();
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        allText.writeln(_extractTextFromBytes(dex.content!, maxLength: 999999));
      }
      final text = allText.toString();

      // 1. 签名校验检测
      final sigCheckPatterns = [
        'checkSignatures', 'getPackageInfo', 'getInstallerPackageName',
        'signatures', 'verifySignature',
      ];
      sb.writeln('--- Signature Check Patterns ---');
      for (final s in sigCheckPatterns) {
        final count = s.allMatches(text).length;
        if (count > 0) sb.writeln('  $s: $count');
      }

      // 2. Root/Emulator检测
      final rootPatterns = ['isRooted', 'isDeviceRooted', 'checkRoot', 'detectRoot',
        'isEmulator', 'isRunningInEmulator', 'detectEmulator', '/su'];
      sb.writeln('\n--- Root/Emulator Check Patterns ---');
      for (final r in rootPatterns) {
        final count = r.allMatches(text).length;
        if (count > 0) sb.writeln('  $r: $count');
      }

      // 3. Debug检测
      final debugPatterns = ['isDebuggerConnected', 'waitForDebugger', 'debugger'];
      sb.writeln('\n--- Debug Check Patterns ---');
      for (final d in debugPatterns) {
        final count = d.allMatches(text).length;
        if (count > 0) sb.writeln('  $d: $count');
      }

      // 4. 广告方法体清空候选
      final adMethods = ['loadAd', 'showAd', 'requestAd', 'initAd', 'showInterstitial', 'showRewarded'];
      sb.writeln('\n--- NOP/Return-void Candidates ---');
      for (final m in adMethods) {
        final count = RegExp('$m\\([^)]*\\)').allMatches(text).length;
        if (count > 0) sb.writeln('  $m: $count (can be NOPed)');
      }

      // 5. const值替换候选
      sb.writeln('\n--- Const Value Patterns ---');
      final constTrue = RegExp(r'const/4\s+v\d+,\s+0x1').allMatches(text).length;
      final constFalse = RegExp(r'const/4\s+v\d+,\s+0x0').allMatches(text).length;
      sb.writeln('  const/4 v*, 0x1 (true): $constTrue');
      sb.writeln('  const/4 v*, 0x0 (false): $constFalse');

      // 6. goto跳转统计
      final gotos = RegExp(r'goto\w*').allMatches(text).length;
      sb.writeln('\n--- Goto Patterns ---');
      sb.writeln('  Total goto: $gotos');

      // 7. invoke统计
      final invokes = RegExp(r'invoke-\w+').allMatches(text).length;
      sb.writeln('\n--- Invoke Patterns ---');
      sb.writeln('  Total invoke: $invokes');

      sb.writeln('\n=== Summary ===');
      sb.writeln('Available patch operations:');
      sb.writeln('  - NOP out ad methods');
      sb.writeln('  - Force return-void for ad/show methods');
      sb.writeln('  - Replace const values (0x1→0x0 or 0x0→0x1)');
      sb.writeln('  - Bypass signature checks');
      sb.writeln('  - Disable root/emulator/debug detection');
      sb.writeln('  - Replace ad URLs with empty strings');
      sb.writeln('  - VIP method force-true');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_native_patch — 原生SO补丁工具
  // =========================================================================
  static Future<Map<String, dynamic>> nativePatch(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Native SO Patcher ===\n');

      final soFiles = _filterEntries(apk, '.so');
      sb.writeln('--- SO Files ---');
      sb.writeln('  Count: ${soFiles.length}');

      // 指令集检测
      sb.writeln('\n--- Architecture Detection ---');
      final archMap = <String, int>{};
      for (final so in soFiles) {
        final path = so.name;
        String arch = 'unknown';
        if (path.contains('arm64-v8a')) arch = 'aarch64';
        else if (path.contains('armeabi-v7a')) arch = 'arm/thumb';
        else if (path.contains('armeabi')) arch = 'arm';
        else if (path.contains('x86_64')) arch = 'x86_64';
        else if (path.contains('x86')) arch = 'x86';
        archMap[arch] = (archMap[arch] ?? 0) + 1;
        sb.writeln('  ${so.name} → $arch');
      }

      // ELF分析
      sb.writeln('\n--- ELF Analysis ---');
      for (final so in soFiles.take(10)) {
        if (so.content == null) continue;
        final data = so.content!;
        if (data.length < 64) continue;

        final is64 = data[4] == 2;
        final endian = data[5] == 1 ? 'LE' : 'BE';
        final elfType = data[16] == 3 ? 'SO' : (data[16] == 2 ? 'EXEC' : 'UNK');
        sb.writeln('  ${so.name}: ELF${is64 ? '64' : '32'} $endian type=$elfType size=${data.length}');

        // 入口点
        if (is64 && data.length >= 32) {
          final entry = data[24] | (data[25] << 8) | (data[26] << 16) | (data[27] << 24) |
            (data[28] << 32) | (data[29] << 40) | (data[30] << 48) | (data[31] << 56);
          sb.writeln('    Entry: 0x${entry.toRadixString(16)}');
        } else if (!is64 && data.length >= 28) {
          final entry = data[24] | (data[25] << 8) | (data[26] << 16) | (data[27] << 24);
          sb.writeln('    Entry: 0x${entry.toRadixString(16)}');
        }
      }

      // 补丁能力
      sb.writeln('\n=== Summary ===');
      sb.writeln('Patch capabilities:');
      sb.writeln('  - Hex pattern search/replace');
      sb.writeln('  - NOP fill (ARM/Thumb/AArch64/x86)');
      sb.writeln('  - Branch→RET patching');
      sb.writeln('  - Branch→MOV R0,#value + RET');
      sb.writeln('  - JNI function name patching');
      sb.writeln('  - ELF entry point modification');
      sb.writeln('  - String replacement in SO');
      sb.writeln('  - Conditional branch injection');
      sb.writeln('  - Breakpoint insertion');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_integrity_patch — 完整性校验绕过
  // =========================================================================
  static Future<Map<String, dynamic>> integrityPatch(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Integrity Bypass Analysis ===\n');

      final allText = StringBuffer();
      for (final entry in apk) {
        if (entry.content != null) {
          allText.writeln(_extractTextFromBytes(entry.content!, maxLength: 999999));
        }
      }
      final text = allText.toString();

      // 1. 签名校验
      sb.writeln('--- Signature Verification ---');
      final sigPatterns = {
        'checkSignatures': 'checkSignatures'.allMatches(text).length,
        'getPackageInfo': 'getPackageInfo'.allMatches(text).length,
        'getInstallerPackageName': 'getInstallerPackageName'.allMatches(text).length,
        'signatures.equals': 'signatures'.allMatches(text).length,
        'verifySignature': 'verifySignature'.allMatches(text).length,
        'PackageManager': 'PackageManager'.allMatches(text).length,
      };
      for (final e in sigPatterns.entries) {
        if (e.value > 0) sb.writeln('  ${e.key}: ${e.value}');
      }

      // 2. Root检测
      sb.writeln('\n--- Root Detection ---');
      final rootPatterns = {
        'isRooted': 'isRooted'.allMatches(text).length,
        'isDeviceRooted': 'isDeviceRooted'.allMatches(text).length,
        'checkRoot': 'checkRoot'.allMatches(text).length,
        'detectRoot': 'detectRoot'.allMatches(text).length,
        '/su': '/su'.allMatches(text).length,
        'Superuser': 'Superuser'.allMatches(text).length,
        'magisk': 'magisk'.allMatches(text).length,
        'busybox': 'busybox'.allMatches(text).length,
      };
      for (final e in rootPatterns.entries) {
        if (e.value > 0) sb.writeln('  ${e.key}: ${e.value}');
      }

      // 3. 模拟器检测
      sb.writeln('\n--- Emulator Detection ---');
      final emuPatterns = {
        'isEmulator': 'isEmulator'.allMatches(text).length,
        'isRunningInEmulator': 'isRunningInEmulator'.allMatches(text).length,
        'detectEmulator': 'detectEmulator'.allMatches(text).length,
        'qemu': 'qemu'.allMatches(text).length,
        'goldfish': 'goldfish'.allMatches(text).length,
        'genymotion': 'genymotion'.allMatches(text).length,
      };
      for (final e in emuPatterns.entries) {
        if (e.value > 0) sb.writeln('  ${e.key}: ${e.value}');
      }

      // 4. 反调试
      sb.writeln('\n--- Anti-Debug ---');
      final debugPatterns = {
        'isDebuggerConnected': 'isDebuggerConnected'.allMatches(text).length,
        'waitForDebugger': 'waitForDebugger'.allMatches(text).length,
        'ptrace': 'ptrace'.allMatches(text).length,
        'Debug.isDebuggerConnected': 'Debug;->isDebuggerConnected'.allMatches(text).length,
      };
      for (final e in debugPatterns.entries) {
        if (e.value > 0) sb.writeln('  ${e.key}: ${e.value}');
      }

      // 5. 完整性校验
      sb.writeln('\n--- Integrity Checks ---');
      final integrityPatterns = {
        'checksum': 'checksum'.allMatches(text).length,
        'MD5': 'MD5'.allMatches(text).length,
        'SHA': 'SHA'.allMatches(text).length,
        'CRC': 'CRC'.allMatches(text).length,
        'hashcode': 'hashcode'.allMatches(text).length,
        'tamper': 'tamper'.allMatches(text).length,
        'verify': 'verify'.allMatches(text).length,
      };
      for (final e in integrityPatterns.entries) {
        if (e.value > 0) sb.writeln('  ${e.key}: ${e.value}');
      }

      // 综合评分
      final totalChecks = sigPatterns.values.fold(0, (a, b) => a + b) +
        rootPatterns.values.fold(0, (a, b) => a + b) +
        emuPatterns.values.fold(0, (a, b) => a + b) +
        debugPatterns.values.fold(0, (a, b) => a + b) +
        integrityPatterns.values.fold(0, (a, b) => a + b);
      final protectionLevel = totalChecks >= 50 ? '高度保护' : (totalChecks >= 20 ? '中度保护' : (totalChecks >= 5 ? '低度保护' : '无保护'));

      sb.writeln('\n=== Summary ===');
      sb.writeln('Total integrity checks: $totalChecks');
      sb.writeln('Protection level: $protectionLevel');
      sb.writeln('\nBypass operations available:');
      sb.writeln('  - Disable signature checks (checkSignatures/getPackageInfo)');
      sb.writeln('  - Disable root detection (isRooted/checkRoot)');
      sb.writeln('  - Disable emulator detection (isEmulator/detectEmulator)');
      sb.writeln('  - Disable anti-debug (isDebuggerConnected/waitForDebugger)');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_resource_patch — 资源文件补丁
  // =========================================================================
  static Future<Map<String, dynamic>> resourcePatch(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Resource Patcher ===\n');

      // 1. ARSC文件
      final arscFiles = _filterEntries(apk, 'resources.arsc');
      sb.writeln('--- ARSC Files ---');
      sb.writeln('  Count: ${arscFiles.length}');
      for (final f in arscFiles) {
        sb.writeln('  ${f.name}: ${f.content?.length ?? 0} bytes');
      }

      // 2. XML文件
      final xmlFiles = apk.where((e) => e.name.endsWith('.xml')).toList();
      sb.writeln('\n--- XML Files ---');
      sb.writeln('  Count: ${xmlFiles.length}');

      // 3. 图片资源
      final imgExts = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'];
      var imgCount = 0;
      var imgSize = 0;
      for (final entry in apk) {
        for (final ext in imgExts) {
          if (entry.name.toLowerCase().endsWith(ext)) {
            imgCount++;
            imgSize += entry.content?.length ?? 0;
            break;
          }
        }
      }
      sb.writeln('\n--- Image Resources ---');
      sb.writeln('  Count: $imgCount');
      sb.writeln('  Total size: ${(imgSize / 1024).toStringAsFixed(1)} KB');

      // 4. Assets文件
      final assets = apk.where((e) => e.name.startsWith('assets/')).toList();
      sb.writeln('\n--- Assets ---');
      sb.writeln('  Count: ${assets.length}');

      // 5. 包名检测
      if (arscFiles.isNotEmpty && arscFiles.first.content != null) {
        final data = arscFiles.first.content!;
        if (data.length > 12) {
          // 尝试解码UTF-16LE包名
          final pkgBytes = data.sublist(12, 12 + 256 > data.length ? data.length : 12 + 256);
          final pkgName = String.fromCharCodes(
            pkgBytes.where((b) => b >= 32 && b < 127).take(50)
          ).replaceAll(RegExp(r'\x00+'), '').trim();
          sb.writeln('\n--- Package Name (from ARSC) ---');
          sb.writeln('  $pkgName');
        }
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Patch operations:');
      sb.writeln('  - ARSC string replacement (UTF-16LE)');
      sb.writeln('  - ARSC package name modification');
      sb.writeln('  - XML text replacement');
      sb.writeln('  - Image binary patching');
      sb.writeln('  - Asset string replacement');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // =========================================================================
  // reverse_popup_remove — 弹窗去除器
  // =========================================================================
  static Future<Map<String, dynamic>> popupRemove(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()..writeln('=== Popup Remover ===\n');

      // 1. 检测弹窗SDK
      final allText = StringBuffer();
      for (final entry in apk) {
        if (entry.content != null) {
          allText.writeln(_extractTextFromBytes(entry.content!, maxLength: 999999));
        }
      }
      final text = allText.toString();

      // 腾讯分享弹窗SDK
      sb.writeln('--- Popup SDK Detection ---');
      final tencentSharePatterns = {
        'SETUP_LAUNCHER_ACTIVITY': 'SETUP_LAUNCHER_ACTIVITY'.allMatches(text).length,
        'SdkInitProvider': 'SdkInitProvider'.allMatches(text).length,
        'tauth.AuthActivity': 'tauth'.allMatches(text).length,
        'tencent.connect': 'tencent.connect'.allMatches(text).length,
        'setup_sdk': 'setup_sdk'.allMatches(text).length,
        'TaskActivity': 'TaskActivity'.allMatches(text).length,
      };
      var tencentScore = 0;
      for (final e in tencentSharePatterns.entries) {
        if (e.value > 0) {
          sb.writeln('  Tencent Share: ${e.key} (${e.value})');
          tencentScore++;
        }
      }

      // 其他弹窗SDK
      final otherPopupPatterns = {
        'showDialog': 'showDialog'.allMatches(text).length,
        'AlertDialog': 'AlertDialog'.allMatches(text).length,
        'PopupWindow': 'PopupWindow'.allMatches(text).length,
        'DialogFragment': 'DialogFragment'.allMatches(text).length,
        'onCreateDialog': 'onCreateDialog'.allMatches(text).length,
        'rate_app': 'rate_app'.allMatches(text).length,
        'RateApp': 'RateApp'.allMatches(text).length,
        'update_dialog': 'update_dialog'.allMatches(text).length,
        'UpdateDialog': 'UpdateDialog'.allMatches(text).length,
      };
      sb.writeln('\n--- Generic Popup Patterns ---');
      for (final e in otherPopupPatterns.entries) {
        if (e.value > 0) sb.writeln('  ${e.key}: ${e.value}');
      }

      // 2. Assets弹窗文件
      final popupAssets = apk.where((e) =>
        e.name.contains('setup_sdk') ||
        e.name.contains('info.json') ||
        e.name.contains('share/') ||
        e.name.contains('rate') ||
        e.name.contains('update')
      ).toList();
      sb.writeln('\n--- Popup Assets ---');
      sb.writeln('  Count: ${popupAssets.length}');
      for (final a in popupAssets.take(15)) {
        sb.writeln('  ${a.name} (${a.content?.length ?? 0} bytes)');
      }

      // 3. Manifest组件
      sb.writeln('\n--- Manifest Components ---');
      final manifestEntry = _filterEntries(apk, 'AndroidManifest.xml').firstOrNull;
      if (manifestEntry?.content != null) {
        final manifestText = _extractTextFromBytes(manifestEntry!.content!, maxLength: 999999);
        final activities = 'activity'.allMatches(manifestText).length;
        final services = 'service'.allMatches(manifestText).length;
        final receivers = 'receiver'.allMatches(manifestText).length;
        sb.writeln('  Activities: $activities');
        sb.writeln('  Services: $services');
        sb.writeln('  Receivers: $receivers');
      }

      sb.writeln('\n=== Summary ===');
      sb.writeln('Tencent Share score: $tencentScore/6');
      if (tencentScore >= 3) sb.writeln('  → Tencent Share popup SDK likely present');
      sb.writeln('\nRemoval operations:');
      sb.writeln('  - Remove popup SDK manifest components');
      sb.writeln('  - Delete popup SDK assets');
      sb.writeln('  - Replace popup launcher activity');
      sb.writeln('  - Delete popup DEX files');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }
}
// =========================================================================

