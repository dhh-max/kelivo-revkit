part of kelivo_reverse_server;

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

class KelivoReverseAnalyzer {
  // ---- reverse_meta_info ----
  static Map<String, dynamic> metaInfo(Map<String, dynamic> args) {
    final action = (args['action'] ?? '').toString().trim().toLowerCase();
    final sb = StringBuffer();
    if (action == 'tools' || action.isEmpty) {
      sb.writeln('# @kelivo/reverse — Available Tools\n');
      sb.writeln('| Tool | Description |');
      sb.writeln('| --- | --- |');
      sb.writeln('| reverse_meta_info | Tool self-description & recommended workflows |');
      sb.writeln('| reverse_open_apk | Open APK, list manifest summary, dex & native libs |');
      sb.writeln('| reverse_list_targets | Enumerate all analysis targets |');
      sb.writeln('| reverse_manifest_summary | Parse AndroidManifest.xml (package, components, permissions) |');
      sb.writeln('| reverse_list_native_libs | List all .so files |');
      sb.writeln('| reverse_list_dex_files | List all classes*.dex files |');
      sb.writeln('| reverse_analyze_so | Aggregated header/import/export/dep/string analysis for a .so |');
      sb.writeln('| reverse_analyze_dex | Aggregated header/class/method/string analysis for a .dex |');
      sb.writeln('| reverse_find_jni_bridges | Locate JNI registration clues |');
      sb.writeln('| reverse_search_strings | Cross-target string search |');
      sb.writeln('| reverse_report | Structured reverse engineering report |');
      sb.writeln('| reverse_quick_triage | One-shot quick triage |');
      sb.writeln('| reverse_signature_audit | APK signature scheme & certificate analysis |');
      sb.writeln('| reverse_packer_detect | Detect packers/protectors (360/Baidu/Tencent/UPX etc.) |');
      sb.writeln('| reverse_secret_scan | Scan hardcoded secrets (API keys, tokens, passwords) |');
      sb.writeln('| reverse_component_audit | Exported component security audit |');
      sb.writeln('| reverse_diff_apk | APK diff analysis (version comparison) |');
      sb.writeln('| reverse_kill_signature | Signature bypass: strip v1 sig + inject hook smali |');
      sb.writeln('| reverse_resign_apk | Clear old signature, regenerate MANIFEST.MF (SHA-256) |');
      sb.writeln('| reverse_inject_dex | Inject external DEX into APK as classesN.dex |');
      sb.writeln('| reverse_smali_decompile | Decompile DEX to smali, with class name filter |');
      sb.writeln('| reverse_obfuscator_detect | Detect ProGuard/R8/DexGuard/360/Bangcle/Ijiami/Legu etc. |');
      sb.writeln('| reverse_resource_extract | Batch extract APK resources to disk, with regex filter |');
      sb.writeln('| reverse_string_decrypt | Heuristic string decryption (Base64/XOR/AES-ECB pattern) |');
      sb.writeln('| reverse_jni_method_map | Build JNI method mapping (Java native ↔ SO symbols) |');
      sb.writeln('| reverse_dex_string_replace | DEX string batch replace (equal-length, in-place) |');
      sb.writeln('| reverse_batch_resign | Batch re-sign APK (strip old sig + fresh MANIFEST.MF + apksigner) |');
      sb.writeln('| reverse_unpack_guide | One-click unpacking guide (detect packer → recommend method) |');
      sb.writeln('| reverse_apk_rebuild | Decode/build/merge/refactor APK workdir workflow (纯 Dart, 无需 apktool) |');
      sb.writeln('| reverse_apk_sign | Pure-Dart APK signing: v1 (JAR, SHA-256) + v2 (Signing Block) |');
      sb.writeln('| reverse_axml_edit | AXML encode/replace: text XML → binary AXML, or replace in APK |');
      sb.writeln('| reverse_manifest_edit | Manifest attribute editor (debuggable/exported/etc.) + re-encode |');
      sb.writeln('| reverse_smali_patch | Smali instruction-level patching (find_replace/bypass/inject/nop/stub) |');
      sb.writeln('| reverse_zipalign | APK 4-byte zip-align for memory-mapped optimization |');
      sb.writeln('| reverse_hook_gen | Hook script generator (Frida JS / Xposed Java / Smali patch) |');
      sb.writeln('| reverse_dex_merge | Merge multiple classes*.dex into single classes.dex |');
      sb.writeln('| reverse_anti_analysis | Anti-analysis detection (7 categories: debug/root/emulator/hook/VPN/virtual/integrity) |');
      sb.writeln('| reverse_callgraph | DEX call graph: callers/callees/hotspots/recursion |');
      sb.writeln('| reverse_crypto_analyzer | Crypto depth: algorithms/modes/hashes/weak-crypto/key-management |');
      sb.writeln('| reverse_dataflow | DEX taint tracking (source→sink) + constant scanning |');
      sb.writeln('| reverse_dex_metadata | Hidden API / reflection / annotation processors / serialization |');
      sb.writeln('| reverse_multidex | Multi-DEX distribution / cross-refs / duplicate detection |');
      sb.writeln('| reverse_native_xref | Native-Java cross reference (DEX native ↔ SO JNI symbols) |');
      sb.writeln('| reverse_vuln_scan | 11-category vulnerability scanner (strings + manifest + DEX methods) |');
      sb.writeln('| reverse_privacy_audit | 13-category privacy risk assessment + data exfiltration |');
      sb.writeln('| reverse_sdk_detect | 80+ third-party SDK / tracker detection + privacy risk |');
      sb.writeln('| reverse_endpoint_extract | Network endpoint extraction (URL/domain/IP/API path/cloud) |');
      sb.writeln('| reverse_social_login | 9-platform social login detection (WeChat/QQ/GitHub/etc.) |');
      sb.writeln('| reverse_apk_size | APK size breakdown by category + recommendations |');
      sb.writeln('| reverse_security_score | Comprehensive security score with CWE mapping |');
      sb.writeln('| reverse_api_usage | 13-category API usage statistics + reflection detection |');
      sb.writeln('| reverse_permission_trace | Permission-to-API cross-reference (used/unused/missing) |');
      sb.writeln('| reverse_clone_detect | DEX method clone detection (exact + similar, cross-DEX) |');
      sb.writeln('| reverse_network_analysis | Network behavior deep analysis (SSL/WebSocket/schemes/ports) |');
      sb.writeln('| reverse_string_analyze | DEX string deep analysis (13 categories + sensitive info) |');
      sb.writeln('| reverse_key_scan | Key/credential deep scan (21 patterns + weak crypto) |');
      sb.writeln('| reverse_cert_deep | Certificate deep analysis (debug cert/CA/algorithms/V1-V3) |');
      sb.writeln('| reverse_sig_scheme | APK signature scheme detection (V1/V2/V3/V4 + security level) |');
      sb.writeln('| reverse_deobfuscate | Auto deobfuscation (XOR/byte arrays/Base64/CFG/arithmetic) |');
      sb.writeln('| reverse_code_analyze | Deep code analysis (URLs/APIs/dangerous APIs/key scan) |');
      sb.writeln('| reverse_resource_analyze | APK resource analysis (categories/compression/large files) |');
      sb.writeln('| reverse_resource_obfuscation | Resource obfuscation detection (naming patterns/ratio) |');
      sb.writeln('| reverse_apk_clean | APK clean analysis (debug/backup/duplicates/waste) |');
      sb.writeln('| reverse_component_explore | Component explorer (exported/intent filters/deep links) |');
      sb.writeln('| reverse_core_class_locate | Core class locator (heuristic scoring/Top 20) |');
      sb.writeln('| reverse_ad_detect | Ad detection (23 SDKs/code patterns/ad domains) |');
      sb.writeln('| reverse_clue_chain | Cross-module clue chain analysis (8 analyzers/risk score) |');
      sb.writeln('| reverse_dex_lib_analysis | DEX third-party library detection (40+ libs/bloat score) |');
      sb.writeln('| reverse_dex_reflection | DEX reflection & dynamic loading analysis |');
      sb.writeln('| reverse_dex_resource_ref | DEX resource reference analysis (R\$ refs/hardcoded IDs) |');
      sb.writeln('| reverse_dex_serialization | DEX serialization & persistence analysis |');
      sb.writeln('| reverse_dex_string_pool | DEX string pool deep analysis (distribution/sensitive patterns) |');
      sb.writeln('| reverse_dex_obfuscation_scan | DEX obfuscation scan (class names/packer fingerprints) |');
      sb.writeln('| reverse_dex_crypto | DEX crypto analysis (algorithms/hash/weak detection) |');
      sb.writeln('| reverse_dex_class_density | DEX class density analysis (packages/interfaces/abstract) |');
      sb.writeln('| reverse_dex_inner_class | DEX inner/anonymous class analysis (nesting/lambda) |');
      sb.writeln('| reverse_dex_native | DEX native method analysis (JNI/loadLibrary/SO count) |');
      sb.writeln('| reverse_dex_const_scan | DEX constant scan (numeric/keyword constants) |');
      sb.writeln('| reverse_dex_inheritance | DEX inheritance analysis (interfaces/abstract/root classes) |');
      sb.writeln('| reverse_dex_method_stats | DEX method signature stats (11 pattern categories) |');
      sb.writeln('| reverse_dex_access_flow | DEX access flow analysis (sensitive methods/modifiers) |');
      sb.writeln('| reverse_dex_permission_audit | DEX permission audit (12 permission-API maps/dangerous combos) |');
      sb.writeln('| reverse_dex_access_pattern | DEX access control pattern (visibility/modifiers/encapsulation) |');
      sb.writeln('| reverse_dex_annotation | DEX annotation analysis (16 known annotation types/dalvik/nullability) |');
      sb.writeln('| reverse_dex_complexity | DEX code complexity (branches/try-catch/sync/complexity score) |');
      sb.writeln('| reverse_dex_control_flow | DEX control flow (invoke/return/goto/if/switch stats) |');
      sb.writeln('| reverse_dex_debug_info | DEX debug info (source files/line numbers/readability) |');
      sb.writeln('| reverse_dex_exception_flow | DEX exception flow (20 exception types/try-catch/defensive score) |');
      sb.writeln('| reverse_dex_field_analyzer | DEX field analysis (7 sensitive patterns/modifiers) |');
      sb.writeln('| reverse_dex_field_usage | DEX field usage (iget/iput/sget/sput/R-W ratio) |');
      sb.writeln('| reverse_dex_insn_density | DEX instruction density (method density/DEX file breakdown) |');
      sb.writeln('| reverse_dex_instruction_stats | DEX instruction stats (14 instruction categories) |');
      sb.writeln('| reverse_dex_proto_analyzer | DEX proto analyzer (return types/overloads/complexity) |');
      sb.writeln('| reverse_dex_proto_matrix | DEX proto matrix (short signatures/parameter types) |');
      sb.writeln('| reverse_dex_register_pressure | DEX register pressure (7 ranges/high pressure detection) |');
      sb.writeln('| reverse_dex_type_ref | DEX type reference (app/system/hub classes) |');
      sb.writeln('| reverse_dex_optimizer_patterns | DEX optimizer patterns (const folding/dead code/inline/peephole) |');
      sb.writeln('| reverse_permission_analyze | Permission analysis (classification/risk groups/GDPR-COPPA-CCPA/privacy score) |');
      sb.writeln('| reverse_ad_remove | Ad removal engine (31 SDKs/ad methods/VIP unlock/URLs/assets) |');
      sb.writeln('| reverse_smali_patch_advanced | Smali advanced patcher (NOP/return-void/const replace/bypass/invoke NOP) |');
      sb.writeln('| reverse_native_patch | Native SO patcher (arch detect/ELF/hex/branch-NOP/JNI name/breakpoint) |');
      sb.writeln('| reverse_integrity_patch | Integrity bypass (signature/root/emulator/debug/checksum detection) |');
      sb.writeln('| reverse_resource_patch | Resource patcher (ARSC/XML/image/assets/package name) |');
      sb.writeln('| reverse_popup_remove | Popup remover (Tencent Share SDK/dialogs/rate/update detection) |');
    }
    if (action == 'workflows' || action.isEmpty) {
      sb.writeln('\n## Recommended Workflows\n');
      sb.writeln('1. **Quick triage**: reverse_open_apk → reverse_quick_triage');
      sb.writeln('2. **Deep analysis**: reverse_open_apk → reverse_analyze_dex → reverse_analyze_so');
      sb.writeln('3. **JNI investigation**: reverse_open_apk → reverse_find_jni_bridges → reverse_analyze_so');
      sb.writeln('4. **String sweep**: reverse_search_strings (cross-target)');
      sb.writeln('5. **Security audit**: reverse_signature_audit → reverse_packer_detect → reverse_secret_scan → reverse_component_audit');
      sb.writeln('6. **Report**: reverse_report (after data collection)');
      sb.writeln('7. **Modify & rebuild** (纯 Dart, 无需 apktool): reverse_apk_rebuild (action=decode) → reverse_smali_patch / reverse_manifest_edit → reverse_apk_rebuild (action=build) → reverse_zipalign → reverse_apk_sign');
      sb.writeln('8. **Manifest 改造**: reverse_manifest_edit (debuggable/exported/etc.) → reverse_apk_sign');
      sb.writeln('9. **AXML 回写**: reverse_axml_edit (action=encode 生成二进制) → reverse_axml_edit (action=replace 替换进 APK)');
      sb.writeln('10. **Merge splits**: reverse_apk_rebuild (action=merge) → reverse_dex_merge → reverse_apk_sign');
      sb.writeln('11. **Deobfuscate**: reverse_obfuscator_detect → reverse_apk_rebuild (action=refactor) → 手动应用重命名 → rebuild → sign');
      sb.writeln('12. **Hook 生成**: reverse_hook_gen (format=frida|xposed|smali) → 注入/加载 → 验证');
      sb.writeln('13. **Unpack**: reverse_packer_detect → reverse_unpack_guide → dump DEX → reverse_analyze_dex 校验 → rebuild/sign 装机');
      sb.writeln('14. **安全深度审计**: reverse_anti_analysis → reverse_crypto_analyzer → reverse_dataflow → reverse_dex_metadata');
      sb.writeln('15. **多 DEX 关联**: reverse_multidex → reverse_callgraph → reverse_native_xref');
      sb.writeln('16. **安全全面审计**: reverse_vuln_scan → reverse_privacy_audit → reverse_security_score → reverse_sdk_detect');
      sb.writeln('17. **网络情报**: reverse_endpoint_extract → reverse_social_login → reverse_sdk_detect');
      sb.writeln('18. **体积优化**: reverse_apk_size → 检查 DEX/Resources/Native 占比 → 优化建议');
      sb.writeln('19. **权限审计**: reverse_permission_trace → reverse_api_usage → reverse_vuln_scan');
      sb.writeln('20. **网络深度**: reverse_network_analysis → reverse_endpoint_extract → reverse_security_score');
      sb.writeln('21. **代码质量**: reverse_clone_detect → reverse_callgraph → reverse_obfuscator_detect');
      sb.writeln('22. **字符串情报**: reverse_string_analyze → reverse_key_scan → reverse_code_analyze');
      sb.writeln('23. **签名/证书**: reverse_sig_scheme → reverse_cert_deep → reverse_kill_signature (如需去签名)');
      sb.writeln('24. **去混淆**: reverse_deobfuscate → reverse_string_decrypt → reverse_obfuscator_detect');
      sb.writeln('25. **资源分析**: reverse_resource_analyze → reverse_resource_obfuscation → reverse_apk_clean');
      sb.writeln('26. **组件安全**: reverse_component_explore → reverse_permission_trace → reverse_security_score');
      sb.writeln('27. **广告/SDK**: reverse_ad_detect → reverse_sdk_detect → reverse_clue_chain');
      sb.writeln('28. **线索串联**: reverse_clue_chain → reverse_code_analyze → reverse_network_analysis');
      sb.writeln('29. **DEX深度审计**: reverse_dex_lib_analysis → reverse_dex_reflection → reverse_dex_crypto → reverse_dex_permission_audit');
      sb.writeln('30. **DEX结构分析**: reverse_dex_class_density → reverse_dex_inner_class → reverse_dex_inheritance → reverse_dex_method_stats');
      sb.writeln('31. **DEX混淆/常量**: reverse_dex_obfuscation_scan → reverse_dex_string_pool → reverse_dex_const_scan → reverse_dex_resource_ref');
      sb.writeln('32. **DEX Native/序列化**: reverse_dex_native → reverse_dex_serialization → reverse_dex_access_flow');
      sb.writeln('33. **DEX深度分析**: reverse_dex_access_pattern → reverse_dex_annotation → reverse_dex_complexity → reverse_dex_control_flow');
      sb.writeln('34. **DEX字段/异常**: reverse_dex_field_analyzer → reverse_dex_field_usage → reverse_dex_exception_flow → reverse_dex_debug_info');
      sb.writeln('35. **DEX指令/原型**: reverse_dex_instruction_stats → reverse_dex_insn_density → reverse_dex_proto_analyzer → reverse_dex_proto_matrix');
      sb.writeln('36. **DEX寄存器/类型**: reverse_dex_register_pressure → reverse_dex_type_ref → reverse_dex_optimizer_patterns');
      sb.writeln('37. **权限合规**: reverse_permission_analyze → reverse_permission_trace → reverse_privacy_audit → reverse_security_score');
      sb.writeln('38. **广告移除**: reverse_ad_detect → reverse_ad_remove → reverse_smali_patch_advanced (NOP ad methods) → reverse_apk_rebuild (build) → reverse_apk_sign');
      sb.writeln('39. **完整性绕过**: reverse_integrity_patch → reverse_smali_patch_advanced (bypass_signature) → reverse_kill_signature → reverse_apk_sign');
      sb.writeln('40. **原生补丁**: reverse_native_patch → reverse_analyze_so → hex 偏移定位 → patch (NOP/RET/MOV R0)');
      sb.writeln('41. **弹窗去除**: reverse_popup_remove → reverse_manifest_edit (remove components) → reverse_apk_clean → reverse_apk_sign');
    }
    if (action == 'describe' || action.isEmpty) {
      sb.writeln('\n## About\n');
      sb.writeln('`@kelivo/reverse` is an APK-level reverse engineering MCP server.');
      sb.writeln('It aggregates APK opening, manifest parsing, .so and .dex analysis,');
      sb.writeln('JNI bridge detection, cross-target string search, and structured reporting.');
      sb.writeln('It also ships pure-Dart APK surgery: decode to an AI-editable workdir,');
      sb.writeln('rebuild (zip), merge, refactor hints, AXML encode/replace, manifest edit,');
      sb.writeln('smali patching, zipalign, hook generation (Frida/Xposed/Smali),');
      sb.writeln('dex merge, and v1+v2 signing — no external apktool / apksigner /');
      sb.writeln('Java runtime required.');
      sb.writeln('Deep analysis covers anti-analysis, call graph, crypto, dataflow,');
      sb.writeln('DEX metadata, multi-DEX, native xref, vulnerability scanning,');
      sb.writeln('privacy audit, SDK/tracker detection, endpoint extraction,');
      sb.writeln('social login detection, APK size analysis, and security scoring.');
      sb.writeln('Extended modules: string deep analysis, key/credential scanning,');
      sb.writeln('certificate deep analysis, signature scheme detection, auto deobfuscation,');
      sb.writeln('deep code analysis, resource analysis, resource obfuscation detection,');
      sb.writeln('APK clean analysis, component explorer, core class locator,');
      sb.writeln('ad detection, cross-module clue chain analysis, DEX deep analysis');
      sb.writeln('(library detection, reflection, serialization, string pool, obfuscation scan,');
      sb.writeln('crypto, class density, inner class, native methods, constant scan, inheritance,');
      sb.writeln('method stats, access flow, permission audit, resource references,');
      sb.writeln('access patterns, annotations, code complexity, control flow, debug info,');
      sb.writeln('exception flow, field analysis, instruction density/stats, proto analysis,');
      sb.writeln('register pressure, type references, optimizer patterns,');
      sb.writeln('and comprehensive permission analysis (GDPR/COPPA/CCPA compliance).');
      sb.writeln('APK modification tools: ad removal engine (31 SDKs, VIP unlock, URL/assets cleanup),');
      sb.writeln('smali advanced patcher (NOP/return-void/const replace/invoke bypass),');
      sb.writeln('native SO patcher (arch detect/ELF/hex/branch-NOP/JNI/breakpoint),');
      sb.writeln('integrity bypass (signature/root/emulator/debug/checksum),');
      sb.writeln('resource patcher (ARSC/XML/image/assets),');
      sb.writeln('popup remover (Tencent Share SDK/dialogs/rate/update).');
      sb.writeln('For deep ELF analysis, use @kelivo/so. For deep DEX analysis, use @kelivo/dex.');
    }
    return _ok(sb.toString().trimRight());
  }

  // ---- reverse_open_apk ----
  static Map<String, dynamic> openApk(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      final manifestXml = manifestEntry?.content;

      final soEntries = _filterEntries(apk, '.so');
      final dexEntries = _filterEntries(apk, '.dex');
      final manifestSummary = _manifestSummary(manifestXml);

      final sb = StringBuffer()
        ..writeln('=== APK Overview ===')
        ..writeln('Total entries: ${apk.entries.length}')
        ..writeln('Native libs (.so): ${soEntries.length}')
        ..writeln('DEX files: ${dexEntries.length}')
        ..writeln('')
        ..writeln('--- Manifest Summary ---')
        ..writeln(manifestSummary)
        ..writeln('')
        ..writeln('--- Native Libraries ---');
      for (final e in soEntries) {
        final dirs = e.name.split('/');
        final abi = dirs.length > 2 ? dirs[dirs.length - 2] : '?';
        sb.writeln('  $abi  ${dirs.last}  (${e.size} bytes)');
      }
      sb.writeln('');
      sb.writeln('--- DEX Files ---');
      for (final e in dexEntries) {
        sb.writeln('  ${e.name}  (${e.size} bytes)');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_list_targets ----
  static Map<String, dynamic> listTargets(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('=== Analysis Targets ===\n');
      final targets = <String>[];
      for (final e in apk.entries) {
        if (e.name.endsWith('.so') || e.name.endsWith('.dex')) {
          targets.add('${e.name}  (${e.size} bytes)');
        }
      }
      if (targets.isEmpty) {
        sb.writeln('(no .so or .dex targets found)');
      } else {
        for (final t in targets) {
          sb.writeln(t);
        }
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_manifest_summary ----
  static Map<String, dynamic> manifestSummary(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      final summary = _manifestSummary(manifestEntry?.content);
      final sb = StringBuffer()
        ..writeln('=== AndroidManifest Summary ===')
        ..writeln(summary);
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_list_native_libs ----
  static Map<String, dynamic> listNativeLibs(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final soEntries = _filterEntries(apk, '.so');
      final sb = StringBuffer();
      if (soEntries.isEmpty) {
        sb.writeln('(no native libraries found)');
      } else {
        sb.writeln('Native Libraries: ${soEntries.length} total\n');
        for (final e in soEntries) {
          final parts = e.name.split('/');
          final abi = parts.length > 2 ? parts[parts.length - 2] : '?';
          final fname = parts.last;
          sb.writeln('  $abi/$fname  ${e.size} bytes');
        }
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_list_dex_files ----
  static Map<String, dynamic> listDexFiles(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final dexEntries = _filterEntries(apk, '.dex');
      final sb = StringBuffer();
      if (dexEntries.isEmpty) {
        sb.writeln('(no dex files found)');
      } else {
        sb.writeln('DEX Files: ${dexEntries.length} total\n');
        for (final e in dexEntries) {
          sb.writeln('  ${e.name}  ${e.size} bytes');
        }
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_analyze_so ----
  // Delegates to KelivoSoAnalyzer methods and aggregates results.
  static Map<String, dynamic> analyzeSo(KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      // The user specifies which .so inside the APK to analyze
      final soPath = (args['so_path'] ?? '').toString().trim();
      if (soPath.isEmpty) {
        return _err('so_path is required (e.g. "lib/arm64-v8a/libnative.so")');
      }

      // Extract the .so from APK
      final apk = _readApk(p.apkBytes);
      final match = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == soPath,
        orElse: () => null,
      );
      if (match == null) {
        return _err('SO not found in APK: $soPath');
      }

      final soBytes = match.content;
      if (soBytes == null || soBytes.isEmpty) {
        return _err('SO content is empty');
      }

      // Build a KelivoSoRequestPayload
      final soPayload = KelivoSoRequestPayload(bytes: soBytes, limit: 500, minLength: 4);

      // Aggregate analysis
      final headerResult = KelivoSoAnalyzer.header(soPayload);
      final importsResult = KelivoSoAnalyzer.imports(soPayload);
      final exportsResult = KelivoSoAnalyzer.exports(soPayload);
      final depsResult = KelivoSoAnalyzer.dependencies(soPayload);
      final stringsResult = KelivoSoAnalyzer.strings(soPayload);
      final segmentsResult = KelivoSoAnalyzer.segments(soPayload);

      String extractText(Map<String, dynamic> result) {
        final content = result['content'];
        if (content is List && content.isNotEmpty) {
          final first = content[0];
          if (first is Map) return (first['text'] ?? '').toString();
        }
        return '';
      }

      final sb = StringBuffer()
        ..writeln('=== SO Analysis: $soPath ===\n')
        ..writeln('--- Header ---')
        ..writeln(extractText(headerResult))
        ..writeln('\n--- Imports ---')
        ..writeln(extractText(importsResult))
        ..writeln('\n--- Exports ---')
        ..writeln(extractText(exportsResult))
        ..writeln('\n--- Dependencies ---')
        ..writeln(extractText(depsResult))
        ..writeln('\n--- Strings (first entries) ---')
        ..writeln(extractText(stringsResult))
        ..writeln('\n--- Segments ---')
        ..writeln(extractText(segmentsResult));

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_analyze_dex ----
  static Map<String, dynamic> analyzeDex(KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      final dexPath = (args['dex_path'] ?? '').toString().trim();
      if (dexPath.isEmpty) {
        return _err('dex_path is required (e.g. "classes.dex")');
      }

      final apk = _readApk(p.apkBytes);
      final match = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == dexPath,
        orElse: () => null,
      );
      if (match == null) {
        return _err('DEX not found in APK: $dexPath');
      }

      final dexBytes = match.content;
      if (dexBytes == null || dexBytes.isEmpty) {
        return _err('DEX content is empty');
      }

      final dexPayload = KelivoDexRequestPayload(bytes: dexBytes, limit: 500);

      final headerResult = KelivoDexAnalyzer.header(dexPayload);
      final classesResult = KelivoDexAnalyzer.classes(dexPayload);
      final methodsResult = KelivoDexAnalyzer.methods(dexPayload);
      final stringsResult = KelivoDexAnalyzer.strings(dexPayload);

      String extractText(Map<String, dynamic> result) {
        final content = result['content'];
        if (content is List && content.isNotEmpty) {
          final first = content[0];
          if (first is Map) return (first['text'] ?? '').toString();
        }
        return '';
      }

      final sb = StringBuffer()
        ..writeln('=== DEX Analysis: $dexPath ===\n')
        ..writeln('--- Header ---')
        ..writeln(extractText(headerResult))
        ..writeln('\n--- Classes (first entries) ---')
        ..writeln(extractText(classesResult))
        ..writeln('\n--- Methods (first entries) ---')
        ..writeln(extractText(methodsResult))
        ..writeln('\n--- Strings (first entries) ---')
        ..writeln(extractText(stringsResult));

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_find_jni_bridges ----
  static Map<String, dynamic> findJniBridges(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final soEntries = _filterEntries(apk, '.so');
      final sb = StringBuffer()
        ..writeln('=== JNI Bridge Detection ===\n');

      for (final so in soEntries) {
        final content = so.content;
        if (content == null || content.isEmpty) continue;
        final fname = so.name.split('/').last;

        // Search for JNI_OnLoad and JNI_OnUnload in binary
        final text = _extractTextFromBytes(content);
        final lines = text.split('\n');
        final jniClues = <String>[];
        for (final line in lines) {
          if (line.contains('JNI_OnLoad') ||
              line.contains('JNI_OnUnload') ||
              line.contains('Java_')) {
            jniClues.add(line.trim());
          }
        }
        if (jniClues.isNotEmpty) {
          sb.writeln('$fname — ${jniClues.length} JNI clue(s):');
          for (final clue in jniClues.take(20)) {
            sb.writeln('  $clue');
          }
          sb.writeln('');
        }
      }

      // Also search DEX for native method declarations
      final dexEntries = _filterEntries(apk, '.dex');
      for (final dex in dexEntries) {
        final content = dex.content;
        if (content == null || content.isEmpty) continue;
        final text = _extractTextFromBytes(content);
        final lines = text.split('\n');
        final nativeMethods = <String>[];
        for (final line in lines) {
          if (line.contains('native') ||
              line.contains('native') ||
              line.contains('JNI')) {
            nativeMethods.add(line.trim());
          }
        }
        if (nativeMethods.isNotEmpty) {
          sb.writeln('${dex.name} — native method declarations:');
          for (final m in nativeMethods.take(15)) {
            sb.writeln('  $m');
          }
          sb.writeln('');
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_search_strings ----
  static Map<String, dynamic> searchStrings(KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      final query = (args['query'] ?? '').toString().trim().toLowerCase();
      if (query.isEmpty) return _err('query is required');

      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('Cross-target string search for: "$query"\n');

      // Search manifest
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      if (manifestEntry?.content != null) {
        final text = _extractTextFromBytes(manifestEntry!.content!);
        final matches = text.split('\n').where((l) => l.toLowerCase().contains(query)).toList();
        if (matches.isNotEmpty) {
          sb.writeln('--- AndroidManifest.xml (${matches.length} match(es)) ---');
          for (final m in matches.take(20)) {
            sb.writeln('  $m');
          }
          sb.writeln('');
        }
      }

      // Search .so files
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        final text = _extractTextFromBytes(so.content!);
        final matches = text.split('\n').where((l) => l.toLowerCase().contains(query)).toList();
        if (matches.isNotEmpty) {
          sb.writeln('--- ${so.name} (${matches.length} match(es)) ---');
          for (final m in matches.take(15)) {
            sb.writeln('  $m');
          }
          sb.writeln('');
        }
      }

      // Search .dex files
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!);
        final matches = text.split('\n').where((l) => l.toLowerCase().contains(query)).toList();
        if (matches.isNotEmpty) {
          sb.writeln('--- ${dex.name} (${matches.length} match(es)) ---');
          for (final m in matches.take(15)) {
            sb.writeln('  $m');
          }
          sb.writeln('');
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_report ----
  static Map<String, dynamic> report(KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      final apk = _readApk(p.apkBytes);
      final soEntries = _filterEntries(apk, '.so');
      final dexEntries = _filterEntries(apk, '.dex');
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      final manifestSummary = _manifestSummary(manifestEntry?.content);

      // JNI clues across all SOs
      final jniSummary = StringBuffer();
      for (final so in soEntries) {
        if (so.content == null) continue;
        final textLines = _extractTextFromBytes(so.content!).split('\n');
        final hasJniOnLoad = textLines.any((l) => l.contains('JNI_OnLoad'));
        final javaExports = textLines.where((l) => l.contains('Java_')).length;
        if (hasJniOnLoad || javaExports > 0) {
          jniSummary.writeln('  ${so.name.split('/').last}: JNI_OnLoad=$hasJniOnLoad, Java_* exports=$javaExports');
        }
      }

      // Suspicious strings across all targets
      final suspiciousKeywords = ['key', 'secret', 'token', 'password', 'encrypt', 'decrypt',
        'cipher', 'aes', 'rsa', 'md5', 'sha', 'url', 'http', 'api', 'native'];
      final suspiciousFound = <String>{};
      for (final so in soEntries) {
        if (so.content == null) continue;
        final text = _extractTextFromBytes(so.content!);
        for (final kw in suspiciousKeywords) {
          if (text.toLowerCase().contains(kw)) {
            suspiciousFound.add('$kw (in ${so.name.split('/').last})');
          }
        }
      }
      for (final dex in dexEntries) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!);
        for (final kw in suspiciousKeywords) {
          if (text.toLowerCase().contains(kw)) {
            suspiciousFound.add('$kw (in ${dex.name})');
          }
        }
      }

      final sb = StringBuffer()
        ..writeln('=== Reverse Engineering Report ===\n')
        ..writeln('## 1. Target Overview')
        ..writeln('APK entries: ${apk.entries.length}')
        ..writeln('Native libraries: ${soEntries.length}')
        ..writeln('DEX files: ${dexEntries.length}')
        ..writeln('\n## 2. Manifest Summary')
        ..writeln(manifestSummary)
        ..writeln('\n## 3. Native Libraries')
        ..writeln(soEntries.map((e) => '  ${e.name} (${e.size} bytes)').join('\n'))
        ..writeln('\n## 4. DEX Files')
        ..writeln(dexEntries.map((e) => '  ${e.name} (${e.size} bytes)').join('\n'))
        ..writeln('\n## 5. JNI / Native Clues')
        ..writeln(jniSummary.toString().isNotEmpty ? jniSummary.toString() : '  (no JNI clues detected)')
        ..writeln('\n## 6. Suspicious Keywords Found')
        ..writeln(suspiciousFound.isNotEmpty
            ? suspiciousFound.map((s) => '  - $s').join('\n')
            : '  (none detected)')
        ..writeln('\n## 7. Next Steps')
        ..writeln('  - Use reverse_analyze_so to drill down into specific .so files')
        ..writeln('  - Use reverse_analyze_dex to drill down into specific .dex files')
        ..writeln('  - Use reverse_find_jni_bridges for detailed JNI registration analysis')
        ..writeln('  - Use reverse_search_strings for targeted keyword search');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_quick_triage ----
  static Map<String, dynamic> quickTriage(KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      final apk = _readApk(p.apkBytes);
      final soEntries = _filterEntries(apk, '.so');
      final dexEntries = _filterEntries(apk, '.dex');
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      final manifestSummary = _manifestSummary(manifestEntry?.content);

      // Detect JNI quickly
      int jniOnLoadCount = 0;
      int javaExportCount = 0;
      for (final so in soEntries) {
        if (so.content == null) continue;
        final textLines = _extractTextFromBytes(so.content!).split('\n');
        if (textLines.any((l) => l.contains('JNI_OnLoad'))) jniOnLoadCount++;
        javaExportCount += textLines.where((l) => l.contains('Java_')).length;
      }

      // Suspicious keywords
      final suspiciousKeywords = ['key', 'secret', 'token', 'password', 'encrypt',
        'cipher', 'aes', 'rsa', 'api', 'native', 'url'];
      final foundKeywords = <String>{};
      for (final so in soEntries) {
        if (so.content == null) continue;
        final text = _extractTextFromBytes(so.content!);
        for (final kw in suspiciousKeywords) {
          if (text.toLowerCase().contains(kw)) foundKeywords.add(kw);
        }
      }
      for (final dex in dexEntries) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!);
        for (final kw in suspiciousKeywords) {
          if (text.toLowerCase().contains(kw)) foundKeywords.add(kw);
        }
      }

      final abis = soEntries.map((e) {
        final parts = e.name.split('/');
        return parts.length > 2 ? parts[parts.length - 2] : '?';
      }).toSet().toList()..sort();

      final sb = StringBuffer()
        ..writeln('=== Quick Triage ===\n')
        ..writeln('Package / Entry Components:')
        ..writeln(manifestSummary.split('\n').take(10).join('\n'))
        ..writeln('\nABIs: ${abis.join(', ')}')
        ..writeln('Native libs: ${soEntries.length}')
        ..writeln('DEX files: ${dexEntries.length}')
        ..writeln('JNI_OnLoad: $jniOnLoadCount lib(s)')
        ..writeln('Java_* exports: $javaExportCount total')
        ..writeln('Suspicious keywords: ${foundKeywords.join(', ')}')
        ..writeln('\nRecommendation:')
        ..writeln(soEntries.isNotEmpty ? '  - Run reverse_analyze_so for key .so files' : '  - No native libs to analyze')
        ..writeln(dexEntries.isNotEmpty ? '  - Run reverse_analyze_dex for DEX inspection' : '  - No DEX files to analyze')
        ..writeln('  - Run reverse_find_jni_bridges for JNI details')
        ..writeln('  - Run reverse_report for full structured report');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_signature_audit ----
  /// 解析 APK 签名信息（META-INF/*.RSA/*.DSA/*.EC 证书 + APK 签名方案检测）。
  static Map<String, dynamic> signatureAudit(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('=== APK Signature Audit ===\n');

      // Detect signature scheme by checking APK Signing Block
      // (APK v2/v3 block is located before Central Directory at end of ZIP)
      final bytes = p.apkBytes;
      final len = bytes.length;
      int? v2BlockOffset;
      if (len > 32) {
        // End of Central Directory: last 22 bytes minimum
        for (var i = len - 22; i >= 0 && i > len - 0x10000; i--) {
          if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b && bytes[i + 2] == 0x05 && bytes[i + 3] == 0x06) {
            // EOCD found at i; APK Signing Block is before the Central Directory offset
            final eocdOff = i;
            if (eocdOff >= 16) {
              final cdOff = ByteData.view(bytes.buffer, bytes.offsetInBytes + eocdOff + 12).getUint32(0, Endian.little);
              if (cdOff > 0 && cdOff < len) {
                // Magic number for APK Signing Block: 0x504b0607 before the Central Directory
                final blockStart = cdOff - 8;
                if (blockStart >= 8) {
                  final blockSizePair = ByteData.view(bytes.buffer, bytes.offsetInBytes + blockStart).getUint64(0, Endian.little);
                  final blockSize = blockSizePair; // second value is same
                  if (blockSize > 0 && blockStart >= blockSize + 8) {
                    v2BlockOffset = blockStart - blockSize;
                  }
                }
              }
            }
            break;
          }
        }
      }

      sb.writeln('APK Signature Scheme:');
      sb.writeln('  Scheme v1 (JAR):  ${_hasMetaInfEntry(apk, '.RSA') || _hasMetaInfEntry(apk, '.DSA') || _hasMetaInfEntry(apk, '.EC') ? '✓ Present' : '✗ Not detected'}');
      sb.writeln('  Scheme v2/v3:    ${v2BlockOffset != null ? '✓ Present (block at 0x${v2BlockOffset.toRadixString(16)})' : '✗ Not detected / outside scan range'}');

      sb.writeln('');

      // Parse META-INF certificates
      final certEntries = <_ApkEntry>[];
      for (final e in apk.entries) {
        final name = e.name.toUpperCase();
        if (name.startsWith('META-INF/') && (name.endsWith('.RSA') || name.endsWith('.DSA') || name.endsWith('.EC') || name.endsWith('.SF'))) {
          certEntries.add(e);
        }
      }

      if (certEntries.isEmpty) {
        sb.writeln('No META-INF certificate files found (unsigned APK?).');
      } else {
        sb.writeln('META-INF Certificate Files (${certEntries.length}):');
        for (final e in certEntries) {
          final fname = e.name.split('/').last;
          sb.writeln('  $fname  (${e.size} bytes)');
        }

        // Attempt to read issuer/subject from .RSA/.DSA/.EC (PKCS7 / DER)
        for (final e in certEntries) {
          final name = e.name.toUpperCase();
          if (!name.endsWith('.RSA') && !name.endsWith('.DSA') && !name.endsWith('.EC')) continue;
          final content = e.content;
          if (content == null || content.length < 20) continue;
          final fname = e.name.split('/').last;
          sb.writeln('\n--- $fname ---');

          // Heuristic DER parsing: search for PrintableString/UTF8String sequences
          // that look like DN fields (CN=, O=, OU=, L=, etc.)
          final text = _extractTextFromBytes(content, maxLength: 8192);
          final dnClues = <String>[];
          for (final line in text.split('\n')) {
            final t = line.trim();
            if (t.contains('CN=') || t.contains('O=') || t.contains('OU=') ||
                t.contains('L=') || t.contains('ST=') || t.contains('C=') ||
                t.contains('EMAILADDRESS') || t.contains('SERIALNUMBER') ||
                t.contains('Not Before') || t.contains('Not After')) {
              dnClues.add(t);
            }
          }
          if (dnClues.isNotEmpty) {
            for (final clue in dnClues.take(20)) {
              sb.writeln('  $clue');
            }
          } else {
            // Fallback: show raw hex dump of first 128 bytes of cert
            final showLen = content.length > 128 ? 128 : content.length;
            final hexStr = content.sublist(0, showLen).map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
            sb.writeln('  (DER/PKCS7 blob, first $showLen bytes: $hexStr${content.length > 128 ? '...' : ''})');
          }
        }

        // Parse .SF file for digest entries
        for (final e in certEntries) {
          if (!e.name.toUpperCase().endsWith('.SF')) continue;
          final content = e.content;
          if (content == null) continue;
          final text = _extractTextFromBytes(content, maxLength: 4096);
          final digestLines = text.split('\n').where((l) => l.contains('-Digest') || l.contains('Name:')).toList();
          if (digestLines.isNotEmpty) {
            sb.writeln('\n--- ${e.name.split('/').last} (${digestLines.length} digest entries) ---');
            for (final d in digestLines.take(25)) {
              sb.writeln('  $d');
            }
          }
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static bool _hasMetaInfEntry(_ApkInfo apk, String suffix) {
    final upperSuffix = suffix.toUpperCase();
    return apk.entries.any((e) {
      final name = e.name.toUpperCase();
      return name.startsWith('META-INF/') && name.endsWith(upperSuffix);
    });
  }

  // ---- reverse_kill_signature ----
  /// 过签工具：提取原始签名 → 删除 META-INF 签名文件 → 注入签名数据到 assets →
  /// 生成 PmsHook 代码模板 → 输出处理后的 APK。
  static Future<Map<String, dynamic>> killSignature(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final outputPath = (args['output'] ?? '').toString().trim();
      if (outputPath.isEmpty) return _err('Missing "output" path for patched APK.');

      // 1. Extract original signature certificate bytes
      Uint8List? origCertBytes;
      String? certFileName;
      for (final e in apk.entries) {
        final name = e.name.toUpperCase();
        if (name.startsWith('META-INF/') &&
            (name.endsWith('.RSA') || name.endsWith('.DSA') || name.endsWith('.EC'))) {
          if (e.content != null && e.content!.isNotEmpty) {
            origCertBytes = e.content!;
            certFileName = e.name;
            break;
          }
        }
      }
      if (origCertBytes == null) {
        return _err('No META-INF certificate (.RSA/.DSA/.EC) found in APK. Cannot extract original signature.');
      }

      final origSignBase64 = base64Encode(origCertBytes);

      // 2. Rebuild APK: remove META-INF sig files, inject signature asset
      final archive = Archive();
      final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
      // Count existing classesN.dex to find next slot
      var maxDexIdx = 1;
      for (final f in srcArchive) {
        if (f.isFile) {
          final nameUpper = f.name.toUpperCase();
          // Remove signature files
          if (nameUpper.startsWith('META-INF/') &&
              (nameUpper.endsWith('.RSA') || nameUpper.endsWith('.DSA') ||
               nameUpper.endsWith('.EC') || nameUpper.endsWith('.SF') ||
               nameUpper.endsWith('.MF'))) {
            continue; // skip
          }
          archive.addFile(f);
          // Track dex numbering
          final dexMatch = RegExp(r'classes(\d+)\.dex', caseSensitive: false).firstMatch(f.name);
          if (dexMatch != null) {
            final idx = int.tryParse(dexMatch.group(1)!) ?? 0;
            if (idx > maxDexIdx) maxDexIdx = idx;
          }
        }
      }

      // 3. Inject original signature as asset file
      final signAssetContent = utf8.encode(origSignBase64);
      archive.addFile(ArchiveFile(
        'assets/kelivo_original_sign',
        signAssetContent.length,
        signAssetContent,
      ));

      // 4. Write patched APK
      final patchedBytes = ZipEncoder().encode(archive);
      if (patchedBytes == null) return _err('Failed to encode patched APK.');
      final outFile = File(outputPath);
      await outFile.writeAsBytes(patchedBytes);

      // 5. Generate hook code template
      final hookCode = _generatePmsHookSmali(origSignBase64);
      // Save hook code next to output APK
      final hookDir = outFile.parent.path;
      final hookFilePath = '$hookDir/PmsHookApplication.smali';
      await File(hookFilePath).writeAsString(hookCode);

      final sb = StringBuffer()
        ..writeln('=== Kill Signature (过签) Complete ===')
        ..writeln('')
        ..writeln('Original certificate: $certFileName (${origCertBytes.length} bytes)')
        ..writeln('Signature Base64: ${origSignBase64.substring(0, 60)}...')
        ..writeln('')
        ..writeln('Patched APK: $outputPath')
        ..writeln('  - Removed META-INF signature files (v1 signature stripped)')
        ..writeln('  - Injected assets/kelivo_original_sign (Base64 cert data)')
        ..writeln('')
        ..writeln('Hook template: $hookFilePath')
        ..writeln('')
        ..writeln('=== 使用说明 ===')
        ..writeln('方法 A（推荐）：使用 apktool 反编译 → 注入 smali → 修改 manifest → 重编译 → 签名')
        ..writeln('  1. apktool d output.apk -o patched_dir')
        ..writeln('  2. 将 PmsHookApplication.smali 复制到 patched_dir/smali/com/kelivo/hook/')
        ..writeln('  3. 修改 AndroidManifest.xml:')
        ..writeln('     在 <application> 标签添加 android:name="com.kelivo.hook.PmsHookApplication"')
        ..writeln('  4. apktool b patched_dir -o final.apk')
        ..writeln('  5. 用任意密钥签名 final.apk')
        ..writeln('')
        ..writeln('方法 B（Xposed/LSPosed 模块）：')
        ..writeln('  Hook PackageManager.getPackageInfo 返回原始签名即可。')
        ..writeln('  签名数据已存入 assets/kelivo_original_sign。');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  /// Generates PmsHook Application smali code with embedded signature.
  static String _generatePmsHookSmali(String signBase64) {
    return '''.class public Lcom/kelivo/hook/PmsHookApplication;
.super Landroid/app/Application;

# This class hooks PackageManager to return the original signature
# when getPackageInfo is called with GET_SIGNATURES flag.

.field private static originalSignature:Ljava/lang/String;

.method static constructor <clinit>()V
    .locals 1
    const-string v0, "$signBase64"
    sput-object v0, Lcom/kelivo/hook/PmsHookApplication;->originalSignature:Ljava/lang/String;
    return-void
.end method

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method protected attachBaseContext(Landroid/content/Context;)V
    .locals 0
    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    invoke-static {p1}, Lcom/kelivo/hook/PmsHookApplication;->hookPms(Landroid/content/Context;)V
    return-void
.end method

.method private static hookPms(Landroid/content/Context;)V
    .locals 7
    .prologue
    # Get the real PackageManager
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v0

    # Get ActivityThread.sCurrentActivityThread
    const-string v1, "android.app.ActivityThread"
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v1
    const-string v2, "sCurrentActivityThread"
    invoke-virtual {v1, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
    move-result-object v2
    const/4 v3, 0x1
    invoke-virtual {v2, v3}, Ljava/lang/reflect/Field;->setAccessible(Z)V
    const/4 v3, 0x0
    invoke-virtual {v2, v3}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v4

    # Get the sPackageManager field
    const-string v2, "sPackageManager"
    invoke-virtual {v1, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
    move-result-object v2
    const/4 v3, 0x1
    invoke-virtual {v2, v3}, Ljava/lang/reflect/Field;->setAccessible(Z)V
    invoke-virtual {v2, v4}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v5

    # Create dynamic proxy for IPackageManager
    # The proxy intercepts getPackageInfo and replaces signature data
    # with the original Base64-decoded certificate.
    
    # Note: Full proxy implementation requires additional smali classes.
    # For production use, consider the compiled hook.dex approach.
    # The original signature is stored in the static field above.

    return-void
.end method

# ==========================================
# USAGE: Copy this file to smali/com/kelivo/hook/
# Then set android:name="com.kelivo.hook.PmsHookApplication"
# in AndroidManifest.xml <application> tag.
# ==========================================
''';
  }

  // ---- reverse_resign_apk ----
  /// Strips existing signatures and re-signs with a minimal v1 JAR manifest.
  /// The output APK has a valid MANIFEST.MF with SHA-256 digests but no
  /// cryptographic signature — use `apksigner` or device-side tools for final
  /// signing. This is sufficient for the kill-signature workflow where the
  /// hook handles runtime verification.
  static Future<Map<String, dynamic>> resignApk(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final outputPath = (args['output'] ?? '').toString().trim();
      if (outputPath.isEmpty) return _err('Missing "output" path.');

      final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
      final cleanArchive = Archive();

      // Strip old signatures
      for (final f in srcArchive) {
        if (!f.isFile) continue;
        final nameUpper = f.name.toUpperCase();
        if (nameUpper.startsWith('META-INF/') &&
            (nameUpper.endsWith('.RSA') || nameUpper.endsWith('.DSA') ||
             nameUpper.endsWith('.EC') || nameUpper.endsWith('.SF') ||
             nameUpper.endsWith('.MF'))) {
          continue;
        }
        cleanArchive.addFile(f);
      }

      // Generate MANIFEST.MF with SHA-256 digests
      final manifestMf = StringBuffer()
        ..writeln('Manifest-Version: 1.0')
        ..writeln('Created-By: Kelivo RevKit')
        ..writeln('');
      for (final f in cleanArchive) {
        if (!f.isFile || f.content == null) continue;
        final digest = sha256.convert(f.content as List<int>);
        manifestMf.writeln('Name: ${f.name}');
        manifestMf.writeln('SHA-256-Digest: ${base64Encode(digest.bytes)}');
        manifestMf.writeln('');
      }
      final manifestBytes = utf8.encode(manifestMf.toString());
      cleanArchive.addFile(ArchiveFile(
        'META-INF/MANIFEST.MF', manifestBytes.length, manifestBytes));

      final patchedBytes = ZipEncoder().encode(cleanArchive);
      if (patchedBytes == null) return _err('Failed to encode APK.');
      await File(outputPath).writeAsBytes(patchedBytes);

      final sb = StringBuffer()
        ..writeln('APK re-packaged with fresh MANIFEST.MF (SHA-256 digests).')
        ..writeln('Output: $outputPath')
        ..writeln('')
        ..writeln('To complete signing, run:')
        ..writeln('  apksigner sign --ks debug.keystore --ks-pass pass:android $outputPath')
        ..writeln('Or use:')
        ..writeln('  jarsigner -keystore debug.keystore -storepass android $outputPath androiddebugkey');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_inject_dex ----
  /// Injects an external DEX file into an APK as classesN.dex.
  static Future<Map<String, dynamic>> injectDex(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final outputPath = (args['output'] ?? '').toString().trim();
      final dexPath = (args['dex_path'] ?? '').toString().trim();
      if (outputPath.isEmpty) return _err('Missing "output" path.');
      if (dexPath.isEmpty) return _err('Missing "dex_path" parameter.');

      final dexFile = File(dexPath);
      if (!await dexFile.exists()) return _err('DEX file not found: $dexPath');
      final dexBytes = await dexFile.readAsBytes();

      if (dexBytes.length < 8 || dexBytes[0] != 0x64 ||
          dexBytes[1] != 0x65 || dexBytes[2] != 0x78) {
        return _err('File is not a valid DEX (bad magic).');
      }

      final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
      final archive = Archive();
      var maxDexIdx = 1;
      for (final f in srcArchive) {
        if (f.isFile) {
          archive.addFile(f);
          final m = RegExp(r'classes(\d+)\.dex', caseSensitive: false).firstMatch(f.name);
          if (m != null) {
            final idx = int.tryParse(m.group(1)!) ?? 0;
            if (idx > maxDexIdx) maxDexIdx = idx;
          }
        }
      }

      final newDexName = 'classes${maxDexIdx + 1}.dex';
      archive.addFile(ArchiveFile(newDexName, dexBytes.length, dexBytes));

      final patchedBytes = ZipEncoder().encode(archive);
      if (patchedBytes == null) return _err('Failed to encode APK.');
      await File(outputPath).writeAsBytes(patchedBytes);

      return _ok('DEX injected as $newDexName.\nOutput: $outputPath');
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_packer_detect ----
  /// 检测 APK 是否被加固/加壳（基于已知 Packer 指纹和可疑特征）。
  static Map<String, dynamic> packerDetect(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final bytes = p.apkBytes;
      final sb = StringBuffer()
        ..writeln('=== Packer / Protector Detection ===\n');

      final findings = <String>[];

      // Check for known packer artifacts in APK entries
      final allNames = apk.entries.map((e) => e.name).toList();
      final allNamesUpper = allNames.map((n) => n.toUpperCase()).toList();

      // Tencent Legacy (MSDK / soso)
      if (allNamesUpper.any((n) => n.contains('LIBTPOS') || n.contains('LIBTPROTECT') || n.contains('TENCENT'))) {
        findings.add('⚠️ Tencent Legacy Packer (libtpos/libtprotect)');
      }
      // 360
      if (allNamesUpper.any((n) => n.contains('LIBJIAGU') || n.contains('LIB360') || n.contains('QIHOO'))) {
        findings.add('⚠️ Qihoo 360 Packer (libjiagu/lib360)');
      }
      // Baidu
      if (allNamesUpper.any((n) => n.contains('BAIDUPROTECT') || n.contains('LIBBAIDU'))) {
        findings.add('⚠️ Baidu Packer');
      }
      // Ali (Taobao / Alipay)
      if (allNamesUpper.any((n) => n.contains('ALIPROTECT') || n.contains('LIBAVMP') || n.contains('LIBAPSE'))) {
        findings.add('⚠️ Alibaba Packer (libavmp/libapse)');
      }
      // Bangcle / SecNeo
      if (allNamesUpper.any((n) => n.contains('BANGCLE') || n.contains('SECNEO') || n.contains('LIBSEPNEO'))) {
        findings.add('⚠️ Bangcle / SecNeo Packer');
      }
      // NetEase
      if (allNamesUpper.any((n) => n.contains('LIBMAA') || n.contains('NETEASE') || n.contains('HEXIN'))) {
        findings.add('⚠️ NetEase Packer');
      }
      // Tencent Legu
      if (allNamesUpper.any((n) => n.contains('LEGUS') || n.contains('LIBLEGU') || n.contains('SHELL'))) {
        findings.add('⚠️ Tencent Legu Packer');
      }
      // Ijiami
      if (allNamesUpper.any((n) => n.contains('IJIAMI') || n.contains('LIBIJIAMI'))) {
        findings.add('⚠️ Ijiami Packer');
      }

      // Check for suspicious files that indicate packing
      // 1. Stub DEX (very small classes.dex with main dex hidden)
      for (final e in _filterEntries(apk, '.dex')) {
        if (e.content != null && e.content!.length < 8096 && e.name == 'classes.dex') {
          findings.add('⚠️ Suspiciously small classes.dex (${e.content!.length} bytes) — possible stub DEX');
        }
        // Check for multi-dex that contains packer stub
        if (e.name.contains('classes') && e.content != null) {
          final text = _extractTextFromBytes(e.content!, maxLength: 2048);
          if (text.contains('com.secneo') || text.contains('com.stub') ||
              text.contains('wrapper') || text.contains('ProxyApplication')) {
            findings.add('⚠️ Stub/Proxy class detected in ${e.name}');
          }
        }
      }

      // 2. Abnormal entry points
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      if (manifestEntry?.content != null) {
        final manifestText = _extractTextFromBytes(manifestEntry!.content!, maxLength: 4096);
        final appComponents = manifestText.split('\n').where((l) =>
            l.contains('android:name=') &&
            (l.contains('application') || l.contains('activity') || l.contains('provider'))
        ).toList();
        for (final comp in appComponents) {
          final t = comp.trim();
          if (t.contains('com.secneo') || t.contains('stub') ||
              t.contains('wrapper') || t.contains('Proxy') ||
              t.contains('StubApp') || t.contains('ShellApplication')) {
            findings.add('⚠️ Suspicious application/component entry: $t');
          }
        }
      }

      // 3. Check for anti-tamper / anti-debug libraries
      if (allNames.any((n) => n.contains('libinject') || n.contains('libantidebug') ||
          n.contains('antidebug') || n.contains('libtrace'))) {
        findings.add('⚠️ Anti-debug / anti-tamper library detected');
      }

      // 4. ELF section anomalies (packed .so)
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null || so.content!.length < 64) continue;
        try {
          final elf = ElfImage.parse(so.content!);
          final text = _extractTextFromBytes(so.content!, maxLength: 2048);
          // Check for UPX magic
          if (text.contains('UPX!') || text.contains('UPX0') || text.contains('UPX1')) {
            findings.add('⚠️ UPX compressed: ${so.name.split('/').last}');
          }
          // Check for very few sections with huge .text (packed)
          if (elf.sections.length <= 3 && elf.sections.any((s) => s.name == '.text' && s.size > 500000)) {
            findings.add('⚠️ Suspicious ELF structure (packed?): ${so.name.split('/').last} (${elf.sections.length} sections, large .text)');
          }
          // Check for custom section names often used by packers
          for (final sec in elf.sections) {
            if (sec.name.startsWith('.pack') || sec.name.startsWith('.upx') ||
                sec.name.startsWith('.themida') || sec.name.startsWith('.vmp') ||
                sec.name.startsWith('.guard') || sec.name == 'PACKER' ||
                sec.name == 'protect' || sec.name == 'shrink') {
              findings.add('⚠️ Packer section "${sec.name}" in ${so.name.split('/').last}');
            }
          }
        } catch (_) {}
      }

      if (findings.isEmpty) {
        sb.writeln('No known packer/protector fingerprints detected.');
        sb.writeln('(Note: absence of fingerprints does not guarantee the APK is unpacked.)');
      } else {
        sb.writeln('Findings (${findings.length}):\n');
        for (final f in findings) {
          sb.writeln(f);
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_secret_scan ----
  /// 扫描 APK 中可能硬编码的密钥、令牌和敏感字符串。
  static Map<String, dynamic> secretScan(KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('=== Hardcoded Secret Scan ===\n');

      // Regex-style patterns (heuristic)
      final dq = '"'; // double quote
      final sq = "'"; // single quote
      final qc = '[$dq$sq]'; // char class matching quote
      final nqc8 = '[^$dq$sq]{8,}'; // non-quote 8+
      final nqc4 = '[^$dq$sq]{4,}'; // non-quote 4+
      final nqc10 = '[^$dq$sq]{10,}'; // non-quote 10+
      final assign = r'\s*[:=]\s*';
      final patterns = <_SecretPattern>[
        _SecretPattern('(?i)(api[_-]?key|apikey)$assign$qc($nqc8)$qc', 'API Key'),
        _SecretPattern('(?i)(secret|secret[_-]?key)$assign$qc($nqc8)$qc', 'Secret Key'),
        _SecretPattern('(?i)(token|access[_-]?token|auth[_-]?token)$assign$qc($nqc8)$qc', 'Token'),
        _SecretPattern('(?i)(password|pwd|passwd)$assign$qc($nqc4)$qc', 'Password'),
        _SecretPattern('${qc}(?:sk-[a-zA-Z0-9]{20,})$qc', 'OpenAI API Key (sk-...)'),
        _SecretPattern('${qc}(?:AKIA[0-9A-Z]{16})$qc', 'AWS Access Key ID'),
        _SecretPattern(r'(?i)(jwt|bearer)\s+([a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)', 'JWT / Bearer Token'),
        _SecretPattern('(?i)(private[_-]?key|rsa[_-]?private)$assign$qc($nqc10)$qc', 'Private Key'),
        _SecretPattern(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'PEM Private Key'),
        _SecretPattern('(?i)(aws[_-]?secret|aws_secret)$assign$qc($nqc10)$qc', 'AWS Secret Key'),
        _SecretPattern('(?i)(firebase|fcm|gcm)[_-]?(key|sender|server)$assign$qc($nqc8)$qc', 'Firebase/FCM/GCM Key'),
        _SecretPattern('(?i)(google[_-]?maps[_-]?api[_-]?key)$assign$qc($nqc8)$qc', 'Google Maps API Key'),
        _SecretPattern('(?i)(stripe[_-]?(live|test|publishable|secret)[_-]?key)$assign$qc($nqc8)$qc', 'Stripe Key'),
        _SecretPattern('(?i)(twilio|sendgrid|mailgun)[_-]?(api[_-]?key|sid|token)$assign$qc($nqc8)$qc', 'Twilio/SendGrid/Mailgun Key'),
        _SecretPattern('(?i)(mongodb|postgres|mysql|jdbc|redis):\/\/[^\\s$dq$sq<>]{8,}', 'Database Connection String'),
        _SecretPattern('(?i)(git[_-]?token|github[_-]?token|gitlab[_-]?token)$assign$qc($nqc8)$qc', 'Git Token'),
      ];

      int totalFindings = 0;
      final limit = KelivoReverseRequestPayload._asInt(args['limit'], 50).clamp(1, 200);

      // Scan DEX files
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!, maxLength: 65536);
        final matches = <String>[];
        for (final p in patterns) {
          final regex = RegExp(p.pattern);
          for (final match in regex.allMatches(text)) {
            final matched = match.group(0) ?? '';
            if (matched.length > 4) {
              matches.add('  [${p.label}] $matched');
            }
          }
        }
        if (matches.isNotEmpty) {
          sb.writeln('--- ${dex.name} (${matches.length} finding(s)) ---');
          for (final m in matches.take(limit)) {
            sb.writeln(m);
            totalFindings++;
          }
          if (matches.length > limit) sb.writeln('  ... and ${matches.length - limit} more');
          sb.writeln('');
        }
      }

      // Scan SO files for secret patterns
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        final text = _extractTextFromBytes(so.content!, maxLength: 32768);
        final matches = <String>[];
        for (final p in patterns) {
          final regex = RegExp(p.pattern);
          for (final match in regex.allMatches(text)) {
            final matched = match.group(0) ?? '';
            if (matched.length > 4) {
              matches.add('  [${p.label}] $matched');
            }
          }
        }
        // Also scan for base64-encoded blobs that look like keys (> 40 chars)
        final b64Regex = RegExp('$qc([A-Za-z0-9+/=]{40,})$qc');
        for (final match in b64Regex.allMatches(text)) {
          final b64 = match.group(1) ?? '';
          if (b64.length >= 40 && !b64.contains(' ')) {
            matches.add('  [Base64 blob (${b64.length} chars)] $b64');
          }
        }
        if (matches.isNotEmpty) {
          sb.writeln('--- ${so.name} (${matches.length} finding(s)) ---');
          for (final m in matches.take(limit)) {
            sb.writeln(m);
            totalFindings++;
          }
          if (matches.length > limit) sb.writeln('  ... and ${matches.length - limit} more');
          sb.writeln('');
        }
      }

      // Scan manifest
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      if (manifestEntry?.content != null) {
        final text = _extractTextFromBytes(manifestEntry!.content!, maxLength: 16384);
        final matches = <String>[];
        for (final p in patterns) {
          final regex = RegExp(p.pattern);
          for (final match in regex.allMatches(text)) {
            final matched = match.group(0) ?? '';
            if (matched.length > 4) {
              matches.add('  [${p.label}] $matched');
            }
          }
        }
        if (matches.isNotEmpty) {
          sb.writeln('--- AndroidManifest.xml (${matches.length} finding(s)) ---');
          for (final m in matches.take(limit)) {
            sb.writeln(m);
            totalFindings++;
          }
          if (matches.length > limit) sb.writeln('  ... and ${matches.length - limit} more');
          sb.writeln('');
        }
      }

      if (totalFindings == 0) {
        sb.writeln('No hardcoded secrets detected with current patterns.');
        sb.writeln('(Heuristic scan — false negatives possible.)');
      } else {
        sb.writeln('Total: $totalFindings potential secret(s) found across all targets.');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_component_audit ----
  /// 审计 AndroidManifest 中导出的组件及其安全隐患。
  static Map<String, dynamic> componentAudit(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      if (manifestEntry?.content == null) {
        return _ok('(no manifest content found)');
      }

      final text = _extractTextFromBytes(manifestEntry!.content!, maxLength: 32768);
      final sb = StringBuffer()
        ..writeln('=== Exported Component Audit ===\n');

      // 1. Parse package name
      String? packageName;
      for (final line in text.split('\n')) {
        final t = line.trim();
        if (t.contains('package=')) {
          final idx = t.indexOf('package=');
          final rest = t.substring(idx + 8);
          final end = rest.indexOf('"', 1);
          if (end > 1) {
            packageName = rest.substring(1, end);
          }
        }
      }

      sb.writeln('Package: ${packageName ?? '(unknown)'}\n');

      // 2. Collect exported components
      final components = <String>[];
      final currentComponent = StringBuffer();
      bool inComponent = false;
      for (final line in text.split('\n')) {
        final t = line.trim();
        if (t.contains('<activity') || t.contains('<service') ||
            t.contains('<receiver') || t.contains('<provider')) {
          inComponent = true;
          currentComponent.clear();
          currentComponent.writeln(t);
        } else if (inComponent) {
          currentComponent.writeln(t);
          if (t.contains('</activity') || t.contains('</service') ||
              t.contains('</receiver') || t.contains('</provider') ||
              t.contains('/>')) {
            components.add(currentComponent.toString().trim());
            inComponent = false;
          }
        }
      }

      // 3. Analyze each component
      int exportedCount = 0;
      int vulnerableCount = 0;
      for (final comp in components) {
        final lines = comp.split('\n');
        final firstLine = lines.first.trim();
        final isExported = firstLine.contains('android:exported="true"') ||
            (!firstLine.contains('android:exported') && !firstLine.contains('<provider'));
        final hasIntentFilter = comp.contains('<intent-filter>');
        final isProvider = firstLine.contains('<provider');
        final isActivity = firstLine.contains('<activity');
        final isService = firstLine.contains('<service');
        final isReceiver = firstLine.contains('<receiver');

        // Extract class name
        String? compClass;
        if (firstLine.contains('android:name=')) {
          final idx = firstLine.indexOf('android:name=');
          final rest = firstLine.substring(idx + 13);
          final end = rest.indexOf('"', 1);
          if (end > 1) {
            compClass = rest.substring(1, end);
            if (compClass.startsWith('.')) {
              compClass = '${packageName ?? ""}$compClass';
            }
          }
        }

        // Determine if access needs protection
        bool needsProtection = false;
        String reason = '';
        if (isExported || hasIntentFilter) {
          exportedCount++;
          if (isProvider && firstLine.contains('android:grantUriPermissions="true"')) {
            needsProtection = true;
            reason = 'grantUriPermissions=true — potential unsafe data exposure';
          }
          if (isActivity && hasIntentFilter) {
            // Check for implicit intent vulnerability
            if (!comp.contains('android:permission=')) {
              needsProtection = true;
              reason = 'exported activity with intent-filter but no permission guard';
            }
          }
          if (isService && !comp.contains('android:permission=')) {
            needsProtection = true;
            reason = 'exported service without permission — potential private API access';
          }
          if (isReceiver && !comp.contains('android:permission=')) {
            needsProtection = true;
            reason = 'exported receiver without permission — potential unauthorized broadcast injection';
          }
          if (needsProtection) vulnerableCount++;
        }

        final label = isExported || hasIntentFilter
            ? (needsProtection ? '⚠️ EXPOSED (vulnerable)' : '📡 EXPOSED')
            : '🔒 Not exported';
        sb.writeln('$label  ${compClass ?? firstLine}');
        if (reason.isNotEmpty) sb.writeln('       ↳ $reason');
      }

      sb.writeln('');
      sb.writeln('Summary:');
      sb.writeln('  Total components analyzed: ${components.length}');
      sb.writeln('  Exported: $exportedCount');
      sb.writeln('  Potentially vulnerable: $vulnerableCount');
      sb.writeln('');
      sb.writeln('Recommendations:');
      if (vulnerableCount > 0) {
        sb.writeln('  - Add explicit android:permission to all exported components');
        sb.writeln('  - Set android:exported="false" for components that don\'t need external access');
        sb.writeln('  - For content providers, avoid grantUriPermissions unless necessary');
        sb.writeln('  - Consider using custom permissions for sensitive services/receivers');
      } else {
        sb.writeln('  - No obvious component-level vulnerabilities detected.');
        sb.writeln('  - Still verify each exported component\'s business logic manually.');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_diff_apk ----
  /// 比较两个 APK 的组件/权限/签名/文件结构差异，支持版本演进审计。
  static Future<Map<String, dynamic>> diffApk(KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('=== APK Diff Analysis ===\n');

      // Extract manifest of this APK as baseline
      final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == 'AndroidManifest.xml',
        orElse: () => null,
      );
      final thisText = manifestEntry?.content != null
          ? _extractTextFromBytes(manifestEntry!.content!, maxLength: 65536)
          : '';
      final thisManifestSummary = _manifestSummary(manifestEntry?.content);

      // ========== Baseline sections ==========
      sb.writeln('## 1. APK Overview (this APK)');
      sb.writeln('Total entries: ${apk.entries.length}');
      final soEntries = _filterEntries(apk, '.so');
      final dexEntries = _filterEntries(apk, '.dex');
      sb.writeln('Native libs: ${soEntries.length}');
      sb.writeln('DEX files: ${dexEntries.length}');
      final totalSize = apk.entries.fold<int>(0, (sum, e) => sum + e.size);
      sb.writeln('Total uncompressed size: ${_formatSize(totalSize)}');
      sb.writeln('');

      // ========== Manifest components ==========
      sb.writeln('## 2. Manifest Components');
      // Parse activities, services, receivers, providers from this manifest
      final thisActivities = _extractComponentNames(thisText, '<activity');
      final thisServices = _extractComponentNames(thisText, '<service');
      final thisReceivers = _extractComponentNames(thisText, '<receiver');
      final thisProviders = _extractComponentNames(thisText, '<provider');
      final thisPermissions = _extractPermissionNames(thisText);

      sb.writeln('Activities: ${thisActivities.length}');
      sb.writeln('Services: ${thisServices.length}');
      sb.writeln('Receivers: ${thisReceivers.length}');
      sb.writeln('Providers: ${thisProviders.length}');
      sb.writeln('Declared permissions: ${thisPermissions.length}');
      sb.writeln('');

      // ========== Signature scheme ==========
      sb.writeln('## 3. Signature');
      final hasV1 = _hasMetaInfEntry(apk, '.RSA') || _hasMetaInfEntry(apk, '.DSA') || _hasMetaInfEntry(apk, '.EC');
      sb.writeln('Scheme v1 (JAR): ${hasV1 ? "✓ Present" : "✗ Not detected"}');
      // Quick v2/v3 check via APK Signing Block
      final bytes = p.apkBytes;
      final len = bytes.length;
      int? v2BlockOff;
      if (len > 32) {
        for (var i = len - 22; i >= 0 && i > len - 0x10000; i--) {
          if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b && bytes[i + 2] == 0x05 && bytes[i + 3] == 0x06) {
            final eocdOff = i;
            if (eocdOff >= 16) {
              final cdOff = ByteData.view(bytes.buffer, bytes.offsetInBytes + eocdOff + 12).getUint32(0, Endian.little);
              if (cdOff > 0 && cdOff < len) {
                final blockStart = cdOff - 8;
                if (blockStart >= 8) {
                  final blockSizePair = ByteData.view(bytes.buffer, bytes.offsetInBytes + blockStart).getUint64(0, Endian.little);
                  if (blockSizePair > 0 && blockStart >= blockSizePair + 8) {
                    v2BlockOff = blockStart - blockSizePair;
                  }
                }
              }
            }
            break;
          }
        }
      }
      sb.writeln('Scheme v2/v3: ${v2BlockOff != null ? "✓ Present" : "✗ Not detected / outside scan range"}');
      sb.writeln('');

      // ========== Permission diff relative to common baselines ==========
      sb.writeln('## 4. Declared Permissions');
      if (thisPermissions.isEmpty) {
        sb.writeln('  (none declared)');
      } else {
        for (final p in thisPermissions) {
          sb.writeln('  - $p');
        }
      }
      sb.writeln('');

      // ========== Native libraries ==========
      sb.writeln('## 5. Native Libraries by ABI');
      final abiMap = <String, List<_ApkEntry>>{};
      for (final so in soEntries) {
        final parts = so.name.split('/');
        final abi = parts.length > 2 ? parts[parts.length - 2] : '?';
        abiMap.putIfAbsent(abi, () => []).add(so);
      }
      for (final abi in abiMap.keys.toList()..sort()) {
        final libs = abiMap[abi]!;
        sb.writeln('  $abi (${libs.length} libs):');
        for (final lib in libs.take(15)) {
          sb.writeln('    ${lib.name.split('/').last}  (${_formatSize(lib.size)})');
        }
        if (libs.length > 15) sb.writeln('    ... and ${libs.length - 15} more');
      }
      sb.writeln('');

      // ========== DEX files ==========
      sb.writeln('## 6. DEX Files');
      for (final dex in dexEntries) {
        sb.writeln('  ${dex.name}  (${_formatSize(dex.size)})');
      }
      sb.writeln('');

      // ========== Entry-level comparison with common reference ==========
      sb.writeln('## 7. Entry Comparison Notes');
      sb.writeln('(This tool accepts a second APK via "compare_path" or "compare_base64"');
      sb.writeln(' to compute a detailed component-level diff between two APKs.)');
      sb.writeln('');

      // ========== If compare target is provided ==========
      final comparePath = (args['compare_path'] ?? '').toString().trim();
      final compareB64 = (args['compare_base64'] ?? '').toString().trim();

      if (comparePath.isNotEmpty || compareB64.isNotEmpty) {
        Uint8List otherBytes;
        if (compareB64.isNotEmpty) {
          otherBytes = base64Decode(compareB64);
        } else {
          final file = File(comparePath);
          if (!await file.exists()) {
            sb.writeln('Compare file not found: $comparePath');
            return _ok(sb.toString().trimRight());
          }
          otherBytes = await file.readAsBytes();
        }

        final otherApk = _readApk(otherBytes);
        final otherManifest = otherApk.entries.cast<_ApkEntry?>().firstWhere(
          (e) => e!.name == 'AndroidManifest.xml',
          orElse: () => null,
        );
        final otherText = otherManifest?.content != null
            ? _extractTextFromBytes(otherManifest!.content!, maxLength: 65536)
            : '';

        final otherActivities = _extractComponentNames(otherText, '<activity');
        final otherServices = _extractComponentNames(otherText, '<service');
        final otherReceivers = _extractComponentNames(otherText, '<receiver');
        final otherProviders = _extractComponentNames(otherText, '<provider');
        final otherPermissions = _extractPermissionNames(otherText);
        final otherSoEntries = _filterEntries(otherApk, '.so');
        final otherDexEntries = _filterEntries(otherApk, '.dex');

        sb.writeln('=== COMPARISON WITH TARGET APK ===\n');
        sb.writeln('Target entries: ${otherApk.entries.length}');
        sb.writeln('Target native libs: ${otherSoEntries.length}');
        sb.writeln('Target DEX files: ${otherDexEntries.length}');
        sb.writeln('');

        // Activities diff
        _writeDiffSection(sb, 'Activities', thisActivities, otherActivities);
        _writeDiffSection(sb, 'Services', thisServices, otherServices);
        _writeDiffSection(sb, 'Receivers', thisReceivers, otherReceivers);
        _writeDiffSection(sb, 'Providers', thisProviders, otherProviders);
        _writeDiffSection(sb, 'Permissions', thisPermissions, otherPermissions);

        // File-level changes
        final thisNames = apk.entries.map((e) => e.name).toSet();
        final otherNames = otherApk.entries.map((e) => e.name).toSet();
        final added = otherNames.difference(thisNames).toList()..sort();
        final removed = thisNames.difference(otherNames).toList()..sort();
        if (added.isNotEmpty) {
          sb.writeln('--- Files Added (${added.length}) ---');
          for (final n in added.take(20)) {
            final otherEntry = otherApk.entries.cast<_ApkEntry?>().firstWhere((e) => e!.name == n, orElse: () => null);
            sb.writeln('  + $n${otherEntry != null ? ' (${_formatSize(otherEntry.size)})' : ''}');
          }
          if (added.length > 20) sb.writeln('  ... and ${added.length - 20} more');
          sb.writeln('');
        }
        if (removed.isNotEmpty) {
          sb.writeln('--- Files Removed (${removed.length}) ---');
          for (final n in removed.take(20)) {
            final thisEntry = apk.entries.cast<_ApkEntry?>().firstWhere((e) => e!.name == n, orElse: () => null);
            sb.writeln('  - $n${thisEntry != null ? ' (${_formatSize(thisEntry.size)})' : ''}');
          }
          if (removed.length > 20) sb.writeln('  ... and ${removed.length - 20} more');
          sb.writeln('');
        }

        // Signature comparison
        final otherHasV1 = _hasMetaInfEntry(otherApk, '.RSA') || _hasMetaInfEntry(otherApk, '.DSA') || _hasMetaInfEntry(otherApk, '.EC');
        sb.writeln('--- Signature Change ---');
        sb.writeln('  This: ${hasV1 ? "v1 ✓" : "v1 ✗"}');
        sb.writeln('  Target: ${otherHasV1 ? "v1 ✓" : "v1 ✗"}');
        sb.writeln('');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  /// 从 Manifest 文本中提取 component 类名列表。
  static List<String> _extractComponentNames(String manifestText, String tagStart) {
    final results = <String>{};
    for (final line in manifestText.split('\n')) {
      final t = line.trim();
      if (t.contains(tagStart) && t.contains('android:name=')) {
        final idx = t.indexOf('android:name=');
        final rest = t.substring(idx + 13);
        final end = rest.indexOf('"', 1);
        if (end > 1) {
          results.add(rest.substring(1, end));
        }
      }
    }
    return results.toList()..sort();
  }

  /// 从 Manifest 文本中提取声明的权限名称。
  static List<String> _extractPermissionNames(String manifestText) {
    final results = <String>{};
    for (final line in manifestText.split('\n')) {
      final t = line.trim();
      if (t.contains('<uses-permission') && t.contains('android:name=')) {
        final idx = t.indexOf('android:name=');
        final rest = t.substring(idx + 13);
        final end = rest.indexOf('"', 1);
        if (end > 1) {
          results.add(rest.substring(1, end));
        }
      }
      if (t.contains('<permission') && t.contains('android:name=')) {
        final idx = t.indexOf('android:name=');
        final rest = t.substring(idx + 13);
        final end = rest.indexOf('"', 1);
        if (end > 1) {
          results.add(rest.substring(1, end));
        }
      }
    }
    return results.toList()..sort();
  }

  /// 在两个集合之间生成 diff 输出。
  static void _writeDiffSection(StringBuffer sb, String label, List<String> thisSet, List<String> otherSet) {
    final thisList = thisSet.toSet();
    final otherList = otherSet.toSet();
    final added = otherList.difference(thisList).toList()..sort();
    final removed = thisList.difference(otherList).toList()..sort();
    final kept = thisList.intersection(otherList).toList()..sort();

    sb.writeln('--- $label ---');
    if (added.isNotEmpty) {
      sb.writeln('  ADDED (${added.length}):');
      for (final a in added.take(15)) sb.writeln('    + $a');
      if (added.length > 15) sb.writeln('    ... and ${added.length - 15} more');
    }
    if (removed.isNotEmpty) {
      sb.writeln('  REMOVED (${removed.length}):');
      for (final r in removed.take(15)) sb.writeln('    - $r');
      if (removed.length > 15) sb.writeln('    ... and ${removed.length - 15} more');
    }
    sb.writeln('  UNCHANGED: ${kept.length}');
    sb.writeln('');
  }

  // ---- reverse_smali_decompile ----
  static Map<String, dynamic> smaliDecompile(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      final dexPath = (args['dex_path'] ?? '').toString().trim();
      if (dexPath.isEmpty) return _err('dex_path is required');
      final classFilter = (args['class_filter'] ?? '').toString().trim();
      final filterRegex = classFilter.isNotEmpty ? RegExp(classFilter) : null;

      final apk = _readApk(p.apkBytes);
      final match = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == dexPath,
        orElse: () => null,
      );
      if (match == null) return _err('DEX not found: $dexPath');
      if (match.content == null || match.content!.isEmpty) {
        return _err('DEX content is empty');
      }

      final dexBytes = match.content!;
      final dexPayload = KelivoDexRequestPayload(bytes: dexBytes, limit: 99999);

      final classesResult = KelivoDexAnalyzer.classes(dexPayload);
      final classesText = _extractResultText(classesResult);

      final sb = StringBuffer()
        ..writeln('=== Smali Decompile: $dexPath ===\n');

      if (filterRegex != null) {
        final filtered = classesText
            .split('\n')
            .where((l) => filterRegex.hasMatch(l))
            .toList();
        sb.writeln('Filter: $classFilter');
        sb.writeln('Matched classes: ${filtered.length}\n');
        for (final line in filtered.take(200)) {
          sb.writeln(line);
        }
        if (filtered.length > 200) {
          sb.writeln('\n... and ${filtered.length - 200} more');
        }
      } else {
        sb.writeln('Total classes listed (smali-level class descriptors):\n');
        sb.writeln(classesText);
      }

      sb.writeln('\n--- Note ---');
      sb.writeln('Full smali decompilation requires baksmali/dexlib.');
      sb.writeln('This tool provides class-level enumeration via @kelivo/dex.');
      sb.writeln('For method-level smali, use reverse_analyze_dex with specific dex_path.');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_obfuscator_detect ----
  static Map<String, dynamic> obfuscatorDetect(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('=== Obfuscator / Protector Detection ===\n');

      final findings = <String>[];
      final allNames = apk.entries.map((e) => e.name).toList();
      final allNamesUpper = allNames.map((n) => n.toUpperCase()).toList();

      // ProGuard / R8
      bool hasProguard = false;
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!, maxLength: 8192);
        if (text.contains('a/a/a/') || text.contains('a/b/b/') ||
            RegExp(r'\ba/[a-z]/[a-z]\b').hasMatch(text)) {
          hasProguard = true;
          break;
        }
      }
      if (hasProguard) {
        findings.add('✓ ProGuard/R8 obfuscation detected (single-letter class names)');
      }

      // DexGuard
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final text = _extractTextFromBytes(dex.content!, maxLength: 16384);
        if (text.contains('com/twofish') || text.contains('DexGuard') ||
            text.contains('encryptString') || text.contains('Reflection')) {
          findings.add('⚠️ DexGuard protection detected');
          break;
        }
      }

      // 360 Jiagu
      if (allNamesUpper.any((n) => n.contains('LIBJIAGU') || n.contains('JIAGU'))) {
        findings.add('⚠️ 360 Jiagu (libjiagu)');
      }
      // Bangcle
      if (allNamesUpper.any((n) => n.contains('BANGCLE') || n.contains('LIBSEPNEO') || n.contains('SECNEO'))) {
        findings.add('⚠️ Bangcle/SecNeo');
      }
      // Ijiami
      if (allNamesUpper.any((n) => n.contains('IJIAMI'))) {
        findings.add('⚠️ Ijiami');
      }
      // Tencent Legu
      if (allNamesUpper.any((n) => n.contains('LEGU') || n.contains('LIBLEGU'))) {
        findings.add('⚠️ Tencent Legu');
      }
      // Alibaba
      if (allNamesUpper.any((n) => n.contains('ALIPROTECT') || n.contains('LIBAVMP') || n.contains('LIBAPSE'))) {
        findings.add('⚠️ Alibaba (libavmp/libapse)');
      }
      // Baidu
      if (allNamesUpper.any((n) => n.contains('BAIDUPROTECT') || n.contains('LIBBAIDU'))) {
        findings.add('⚠️ Baidu Packer');
      }
      // NetEase
      if (allNamesUpper.any((n) => n.contains('LIBMAA') || n.contains('NETEASE'))) {
        findings.add('⚠️ NetEase');
      }
      // UPX
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        final text = _extractTextFromBytes(so.content!, maxLength: 2048);
        if (text.contains('UPX!') || text.contains('UPX0') || text.contains('UPX1')) {
          findings.add('⚠️ UPX compression: ${so.name.split('/').last}');
        }
      }
      // VMP / Themida
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null || so.content!.length < 64) continue;
        try {
          final elf = ElfImage.parse(so.content!);
          for (final sec in elf.sections) {
            if (sec.name.startsWith('.vmp') || sec.name.startsWith('.themida')) {
              findings.add('⚠️ VMP/Themida section "${sec.name}" in ${so.name.split('/').last}');
            }
          }
        } catch (_) {}
      }

      // Resource obfuscation
      final resEntries = apk.entries.where((e) =>
          e.name.startsWith('res/') && e.name.endsWith('.xml')).toList();
      if (resEntries.isNotEmpty) {
        final aaptNames = resEntries.map((e) => e.name).toList();
        final hasObfuscated = aaptNames.any((n) =>
            RegExp(r'^res/[a-z]{1,2}/[a-z]{1,2}\.xml$').hasMatch(n));
        if (hasObfuscated) {
          findings.add('✓ Resource name obfuscation detected (short res paths)');
        }
      }

      if (findings.isEmpty) {
        sb.writeln('No known obfuscation/protector detected.');
        sb.writeln('(Note: heuristics may miss custom or new obfuscators.)');
      } else {
        sb.writeln('Detected (${findings.length}):\n');
        for (final f in findings) {
          sb.writeln('  $f');
        }
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_resource_extract ----
  static Map<String, dynamic> resourceExtract(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      final outputDir = (args['output_dir'] ?? '').toString().trim();
      if (outputDir.isEmpty) return _err('output_dir is required');
      final pattern = (args['pattern'] ?? '').toString().trim();
      final regex = pattern.isNotEmpty ? RegExp(pattern) : null;

      final apk = _readApk(p.apkBytes);
      final dir = Directory(outputDir);
      if (!dir.existsSync()) dir.createSync(recursive: true);

      int extracted = 0;
      int skipped = 0;
      for (final e in apk.entries) {
        if (regex != null && !regex.hasMatch(e.name)) {
          skipped++;
          continue;
        }
        if (e.content == null) continue;
        final outPath = '$outputDir/${e.name}';
        final outFile = File(outPath);
        outFile.parent.createSync(recursive: true);
        outFile.writeAsBytesSync(e.content!);
        extracted++;
      }

      final sb = StringBuffer()
        ..writeln('=== Resource Extraction ===\n')
        ..writeln('Output: $outputDir')
        ..writeln('Extracted: $extracted file(s)');
      if (skipped > 0) {
        sb.writeln('Skipped (pattern mismatch): $skipped');
      }
      if (regex != null) {
        sb.writeln('Pattern: $pattern');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_string_decrypt ----
  static Map<String, dynamic> stringDecrypt(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    try {
      final target = (args['target'] ?? 'all').toString().trim().toLowerCase();
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('=== String Decryption (Heuristic) ===\n');

      final candidates = <_ApkEntry>[];
      if (target == 'dex' || target == 'all') {
        candidates.addAll(_filterEntries(apk, '.dex'));
      }
      if (target == 'so' || target == 'all') {
        candidates.addAll(_filterEntries(apk, '.so'));
      }

      int totalDecrypted = 0;

      for (final entry in candidates) {
        if (entry.content == null) continue;
        final text = _extractTextFromBytes(entry.content!, maxLength: 65536);
        final decrypted = <String>[];

        // Base64-encoded strings
        final b64Regex = RegExp(r'[A-Za-z0-9+/]{20,}={0,2}');
        for (final match in b64Regex.allMatches(text)) {
          final b64 = match.group(0)!;
          if (b64.length < 20 || b64.length > 500) continue;
          try {
            final decoded = base64Decode(b64);
            final decodedText = utf8.decode(decoded, allowMalformed: true);
            if (decodedText.length >= 4 &&
                decodedText.codeUnits.every((c) =>
                    (c >= 0x20 && c < 0x7f) || c == 0x0a || c == 0x0d)) {
              decrypted.add('  [Base64] $b64 → "$decodedText"');
            }
          } catch (_) {}
        }

        // XOR single-byte keys (0x01..0xFF)
        final xorRegex = RegExp(r'[\x20-\x7e]{16,}');
        for (final match in xorRegex.allMatches(text)) {
          final raw = match.group(0)!;
          if (raw.length < 16) continue;
          for (var key = 1; key < 256; key++) {
            final xored = String.fromCharCodes(
                raw.codeUnits.map((c) => c ^ key));
            // Check if result looks meaningful
            if (xored.contains('http') || xored.contains('key') ||
                xored.contains('pass') || xored.contains('token') ||
                xored.contains('secret') || xored.contains('user')) {
              decrypted.add('  [XOR 0x${key.toRadixString(16)}] → "$xored"');
              break;
            }
          }
        }

        // AES-ECB pattern (hex strings divisible by 32, 48, 64)
        final hexRegex = RegExp(r'[0-9a-fA-F]{32,}');
        for (final match in hexRegex.allMatches(text)) {
          final hex = match.group(0)!;
          if (hex.length % 32 == 0 || hex.length % 48 == 0 || hex.length % 64 == 0) {
            decrypted.add('  [Hex/AES-ECB?] $hex (len=${hex.length})');
          }
        }

        if (decrypted.isNotEmpty) {
          sb.writeln('--- ${entry.name} (${decrypted.length} candidate(s)) ---');
          for (final d in decrypted.take(30)) {
            sb.writeln(d);
            totalDecrypted++;
          }
          if (decrypted.length > 30) {
            sb.writeln('  ... and ${decrypted.length - 30} more');
          }
          sb.writeln('');
        }
      }

      if (totalDecrypted == 0) {
        sb.writeln('No decryptable strings found with current heuristics.');
        sb.writeln('(Methods: Base64 decode, XOR single-byte, AES-ECB hex pattern)');
      } else {
        sb.writeln('Total candidates: $totalDecrypted');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_jni_method_map ----
  static Map<String, dynamic> jniMethodMap(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('=== JNI Method Mapping ===\n');

      // 1. Collect Java native method declarations from DEX
      final javaNatives = <String, List<String>>{};
      for (final dex in _filterEntries(apk, '.dex')) {
        if (dex.content == null) continue;
        final dexPayload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
        final methodsResult = KelivoDexAnalyzer.methods(dexPayload);
        final methodsText = _extractResultText(methodsResult);
        for (final line in methodsText.split('\n')) {
          if (line.toLowerCase().contains('native')) {
            javaNatives.putIfAbsent(dex.name, () => []).add(line.trim());
          }
        }
      }

      // 2. Collect JNI symbols from SO files
      final soSymbols = <String, List<String>>{};
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        final text = _extractTextFromBytes(so.content!, maxLength: 65536);
        final symbols = <String>[];
        for (final line in text.split('\n')) {
          if (line.contains('Java_') || line.contains('JNI_OnLoad')) {
            symbols.add(line.trim());
          }
        }
        if (symbols.isNotEmpty) {
          soSymbols[so.name] = symbols;
        }
      }

      // 3. Build mapping table
      sb.writeln('## Java Native Methods\n');
      if (javaNatives.isEmpty) {
        sb.writeln('  (none found in DEX)');
      } else {
        for (final dexName in javaNatives.keys) {
          sb.writeln('  $dexName:');
          for (final m in javaNatives[dexName]!) {
            sb.writeln('    $m');
          }
          sb.writeln('');
        }
      }

      sb.writeln('## Native JNI Symbols\n');
      if (soSymbols.isEmpty) {
        sb.writeln('  (none found in SO files)');
      } else {
        for (final soName in soSymbols.keys) {
          sb.writeln('  $soName:');
          for (final s in soSymbols[soName]!) {
            sb.writeln('    $s');
          }
          sb.writeln('');
        }
      }

      // 4. Attempt auto-matching
      sb.writeln('## Auto-Matched Pairs\n');
      int matched = 0;
      for (final soName in soSymbols.keys) {
        for (final symbol in soSymbols[soName]!) {
          // Extract class+method from Java_com_package_Class_method
          if (symbol.contains('Java_')) {
            final jniName = symbol.substring(symbol.indexOf('Java_'));
            // Convert JNI name to Java class path
            final javaPath = jniName
                .substring(5) // remove "Java_"
                .replaceAll('_', '.')
                .replaceAll('/', '.');
            sb.writeln('  $jniName → $javaPath  (in ${soName.split('/').last})');
            matched++;
          }
        }
      }
      if (matched == 0) {
        sb.writeln('  (no Java_* symbols found for auto-matching)');
      }

      sb.writeln('\n## Summary');
      sb.writeln('  DEX with native methods: ${javaNatives.length}');
      sb.writeln('  SO with JNI symbols: ${soSymbols.length}');
      sb.writeln('  Auto-matched pairs: $matched');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static String _extractResultText(Map<String, dynamic> result) {
    final content = result['content'];
    if (content is List && content.isNotEmpty) {
      final first = content[0];
      if (first is Map) return (first['text'] ?? '').toString();
    }
    return '';
  }

  // ---- reverse_dex_string_replace ----
  /// DEX 字符串批量替换：在 DEX 文件中查找匹配的字符串并替换为新值，
  /// 保持原始长度（截断或填充），输出修改后的 APK。
  static Future<Map<String, dynamic>> dexStringReplace(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final outputPath = (args['output'] ?? '').toString().trim();
      final findStr = (args['find'] ?? '').toString();
      final replaceStr = (args['replace'] ?? '').toString();
      final targetDex = (args['dex_path'] ?? 'classes.dex').toString().trim();
      if (outputPath.isEmpty) return _err('Missing "output" path.');
      if (findStr.isEmpty) return _err('Missing "find" parameter.');
      if (findStr.length != replaceStr.length) {
        return _err('find and replace must be the same length '
            '(find=${findStr.length}, replace=${replaceStr.length}). '
            'DEX string replacement requires equal-length to preserve offsets.');
      }

      final apk = _readApk(p.apkBytes);
      final dexEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
        (e) => e!.name == targetDex,
        orElse: () => null,
      );
      if (dexEntry == null) return _err('DEX not found: $targetDex');
      if (dexEntry.content == null) return _err('DEX content is empty.');

      final dexBytes = Uint8List.fromList(dexEntry.content!);
      final findBytes = utf8.encode(findStr);
      final replaceBytes = utf8.encode(replaceStr);
      int replacements = 0;

      // Search for findBytes in dexBytes and replace in-place
      for (var i = 0; i < dexBytes.length - findBytes.length; i++) {
        bool match = true;
        for (var j = 0; j < findBytes.length; j++) {
          if (dexBytes[i + j] != findBytes[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          for (var j = 0; j < replaceBytes.length; j++) {
            dexBytes[i + j] = replaceBytes[j];
          }
          replacements++;
          i += findBytes.length - 1;
        }
      }

      // Rebuild APK with modified DEX
      final archive = Archive();
      final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
      for (final f in srcArchive) {
        if (f.isFile) {
          if (f.name == targetDex) {
            archive.addFile(ArchiveFile(targetDex, dexBytes.length, dexBytes));
          } else {
            archive.addFile(f);
          }
        }
      }

      final patchedBytes = ZipEncoder().encode(archive);
      if (patchedBytes == null) return _err('Failed to encode APK.');
      await File(outputPath).writeAsBytes(patchedBytes);

      final sb = StringBuffer()
        ..writeln('=== DEX String Replacement ===')
        ..writeln('Target: $targetDex')
        ..writeln('Find: "$findStr" (${findStr.length} bytes)')
        ..writeln('Replace: "$replaceStr" (${replaceStr.length} bytes)')
        ..writeln('Replacements: $replacements')
        ..writeln('Output: $outputPath');
      if (replacements == 0) {
        sb.writeln('\n⚠️ No matches found. The string may not exist in this DEX.');
      }
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  // ---- reverse_batch_resign ----
  /// 批量重签名：清除旧签名 → 生成新 MANIFEST.MF → 使用 debug key 签名。
  /// 支持批量处理多个 APK 文件。
  static Future<Map<String, dynamic>> batchResign(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final outputPath = (args['output'] ?? '').toString().trim();
      if (outputPath.isEmpty) return _err('Missing "output" path.');
      final keystorePath = (args['keystore_path'] ?? '').toString().trim();
      final keystorePass = (args['keystore_pass'] ?? 'android').toString();
      final keyAlias = (args['key_alias'] ?? 'androiddebugkey').toString();
      final keyPass = (args['key_pass'] ?? 'android').toString();
      final signV2 = args['sign_v2'] != false; // default true

      final apk = _readApk(p.apkBytes);

      // 1. Remove old signature files
      final cleanArchive = Archive();
      final srcArchive = ZipDecoder().decodeBytes(p.apkBytes);
      for (final f in srcArchive) {
        if (f.isFile) {
          final nameUpper = f.name.toUpperCase();
          if (nameUpper.startsWith('META-INF/') &&
              (nameUpper.endsWith('.RSA') || nameUpper.endsWith('.DSA') ||
               nameUpper.endsWith('.EC') || nameUpper.endsWith('.SF') ||
               nameUpper.endsWith('.MF'))) {
            continue;
          }
          cleanArchive.addFile(f);
        }
      }

      // 2. Generate fresh MANIFEST.MF
      final manifestMf = StringBuffer()
        ..writeln('Manifest-Version: 1.0')
        ..writeln('Created-By: Kelivo RevKit Batch Re-sign')
        ..writeln('');
      for (final f in cleanArchive) {
        if (!f.isFile || f.content == null) continue;
        final digest = sha256.convert(f.content as List<int>);
        manifestMf.writeln('Name: ${f.name}');
        manifestMf.writeln('SHA-256-Digest: ${base64Encode(digest.bytes)}');
        manifestMf.writeln('');
      }
      final manifestBytes = utf8.encode(manifestMf.toString());
      cleanArchive.addFile(ArchiveFile(
          'META-INF/MANIFEST.MF', manifestBytes.length, manifestBytes));

      final patchedBytes = ZipEncoder().encode(cleanArchive);
      if (patchedBytes == null) return _err('Failed to encode APK.');
      await File(outputPath).writeAsBytes(patchedBytes);

      // 3. Try to sign using apksigner if available
      final sb = StringBuffer()
        ..writeln('=== Batch Re-sign APK ===\n')
        ..writeln('Input: ${p.apkPath ?? "(base64)"}')
        ..writeln('Output: $outputPath')
        ..writeln('V1 (MANIFEST.MF): ✓ Generated (SHA-256)')
        ..writeln('V2/V3: ${signV2 ? "Requested" : "Skipped"}');

      if (keystorePath.isNotEmpty) {
        // Attempt apksigner
        final signResult = await _tryApksigner(
          outputPath, keystorePath, keystorePass, keyAlias, keyPass, signV2);
        sb.writeln(signResult);
      } else {
        sb.writeln('\n⚠️ No keystore provided. APK is unsigned.');
        sb.writeln('To sign manually:');
        sb.writeln('  apksigner sign --ks debug.keystore --ks-pass pass:android \\');
        sb.writeln('    --ks-key-alias androiddebugkey --key-pass pass:android \\');
        sb.writeln('    ${signV2 ? "" : "--v2-signing-enabled false "}$outputPath');
      }

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  /// Attempt to run apksigner on the output APK.
  static Future<String> _tryApksigner(
      String apkPath, String ksPath, String ksPass,
      String alias, String keyPass, bool v2) async {
    try {
      final args = [
        'sign',
        '--ks', ksPath,
        '--ks-pass', 'pass:$ksPass',
        '--ks-key-alias', alias,
        '--key-pass', 'pass:$keyPass',
        if (!v2) ...['--v2-signing-enabled', 'false'],
        apkPath,
      ];
      final result = await Process.run('apksigner', args);
      if (result.exitCode == 0) {
        return 'apksigner: ✓ Signed successfully${v2 ? " (v1+v2)" : " (v1 only)"}';
      } else {
        return 'apksigner: ✗ Failed (exit ${result.exitCode})\n'
               '  stderr: ${result.stderr.toString().trim()}\n'
               '  → Please sign manually.';
      }
    } catch (e) {
      return 'apksigner: Not available ($e)\n'
             '  → Please install Android SDK build-tools or sign manually.';
    }
  }

  // ---- reverse_unpack_guide ----
  /// 一键脱壳向导：检测加固方案 → 推荐脱壳方法 → 输出操作步骤。
  static Map<String, dynamic> unpackGuide(KelivoReverseRequestPayload p) {
    try {
      final apk = _readApk(p.apkBytes);
      final sb = StringBuffer()
        ..writeln('=== Unpacking (脱壳) Guide ===\n');

      // Detect packer type
      final allNamesUpper = apk.entries.map((e) => e.name.toUpperCase()).toList();
      String? packerName;
      String? packerLib;

      // Check each known packer
      final packerChecks = <String, List<String>>{
        '360 Jiagu (加固保)': ['LIBJIAGU', 'JIAGU'],
        'Tencent Legu (乐固)': ['LEGU', 'LIBLEGU'],
        'Bangcle (梆梆安全)': ['BANGCLE', 'LIBSEPNEO', 'SECNEO'],
        'Ijiami (爱加密)': ['IJIAMI', 'LIBIJIAMI'],
        'Alibaba (阿里聚安全)': ['ALIPROTECT', 'LIBAVMP', 'LIBAPSE'],
        'Baidu (百度加固)': ['BAIDUPROTECT', 'LIBBAIDU'],
        'NetEase (网易易盾)': ['LIBMAA', 'NETEASE'],
        'Tencent Legacy': ['LIBTPOS', 'LIBTPROTECT'],
      };

      for (final entry in packerChecks.entries) {
        for (final keyword in entry.value) {
          final match = allNamesUpper.where((n) => n.contains(keyword)).toList();
          if (match.isNotEmpty) {
            packerName = entry.key;
            packerLib = match.first;
            break;
          }
        }
        if (packerName != null) break;
      }

      // Check for stub DEX
      bool hasStubDex = false;
      for (final e in _filterEntries(apk, '.dex')) {
        if (e.content != null && e.content!.length < 8096 && e.name == 'classes.dex') {
          hasStubDex = true;
          break;
        }
      }

      // Check for UPX
      bool hasUpx = false;
      for (final so in _filterEntries(apk, '.so')) {
        if (so.content == null) continue;
        final text = _extractTextFromBytes(so.content!, maxLength: 2048);
        if (text.contains('UPX!') || text.contains('UPX0')) {
          hasUpx = true;
          break;
        }
      }

      if (packerName == null && !hasStubDex && !hasUpx) {
        sb.writeln('No known packer/protector detected.');
        sb.writeln('\nThis APK may not be packed, or uses an unknown protection.');
        sb.writeln('If you suspect packing, try:');
        sb.writeln('  1. Run reverse_packer_detect for deeper analysis');
        sb.writeln('  2. Run reverse_analyze_dex to check for stub classes');
        sb.writeln('  3. Check if classes.dex contains real code or just a loader');
        return _ok(sb.toString().trimRight());
      }

      // Output detected packer info
      sb.writeln('## Detected Protection\n');
      if (packerName != null) {
        sb.writeln('Packer: $packerName');
        sb.writeln('Evidence: $packerLib');
      }
      if (hasStubDex) {
        sb.writeln('Stub DEX: ✓ Detected (classes.dex is suspiciously small)');
      }
      if (hasUpx) {
        sb.writeln('UPX: ✓ Detected (native library compressed)');
      }

      // Generate unpacking guide based on packer type
      sb.writeln('\n## Recommended Unpacking Methods\n');

      if (packerName != null) {
        sb.writeln('### Method 1: FRIDA-DEXDump (Recommended for most packers)\n');
        sb.writeln('FRIDA-based runtime DEX dumping tool. Works on most Chinese packers.');
        sb.writeln('```bash');
        sb.writeln('# 1. Install frida and frida-tools');
        sb.writeln('pip3 install frida-tools frida');
        sb.writeln('');
        sb.writeln('# 2. Install FRIDA-DEXDump');
        sb.writeln('pip3 install frida-dexdump');
        sb.writeln('');
        sb.writeln('# 3. Start frida-server on device');
        sb.writeln('adb shell "su -c \'/data/local/tmp/frida-server &\'"');
        sb.writeln('');
        sb.writeln('# 4. Run the target app, then dump');
        sb.writeln('frida-dexdump -U -f <package_name>');
        sb.writeln('```\n');

        sb.writeln('### Method 2: BlackDex\n');
        sb.writeln('BlackDex is an unpacking tool that works without root (Android 5.0-12).');
        sb.writeln('1. Install BlackDex APK from GitHub');
        sb.writeln('2. Select target app in BlackDex');
        sb.writeln('3. Dumped DEX files saved to /sdcard/Android/data/com.googlecode.android-ddms/files/\n');

        sb.writeln('### Method 3: Xposed/LSPosed Hook\n');
        sb.writeln('Hook ClassLoader.loadClass to intercept DEX loading:');
        sb.writeln('```java');
        sb.writeln('// Hook DexClassLoader or PathClassLoader');
        sb.writeln('// Dump loaded DEX bytes to file');
        sb.writeln('// Use DexLib to reconstruct full DEX from memory');
        sb.writeln('```\n');

        // Packer-specific tips
        sb.writeln('### Packer-Specific Tips\n');
        if (packerName!.contains('360')) {
          sb.writeln('- 360 Jiagu: Check libjiagu.so version');
          sb.writeln('- May use anti-frida detection → use frida-server with magisk hide');
          sb.writeln('- Try DrityDexDumper for newer versions');
        } else if (packerName.contains('Legu')) {
          sb.writeln('- Tencent Legu: Uses libshella/libtosprotection');
          sb.writeln('- May detect frida → use stalker mode or custom frida');
          sb.writeln('- Try LeguUnpacker tool for older versions');
        } else if (packerName.contains('Bangcle')) {
          sb.writeln('- Bangcle: Check libsecneo.so');
          sb.writeln('- Look for com.secneo.apkwrapper.APKProtectApplication');
          sb.writeln('- FRIDA-DEXDump usually works well');
        } else if (packerName.contains('Ijiami')) {
          sb.writeln('- Ijiami: Check libexec/libexecmain');
          sb.writeln('- Try unpacking with BlueProtector bypass');
        }
      }

      if (hasUpx) {
        sb.writeln('### UPX Unpacking\n');
        sb.writeln('```bash');
        sb.writeln('# Download UPX from https://upx.github.io/');
        sb.writeln('upx -d <packed.so>  # Decompress UPX-packed library');
        sb.writeln('```\n');
      }

      sb.writeln('## Post-Unpacking Steps\n');
      sb.writeln('1. Verify dumped DEX with reverse_analyze_dex');
      sb.writeln('2. Merge multiple DEX files if needed (dex-merger)');
      sb.writeln('3. Rebuild APK: reverse_resign_apk → sign → install');
      sb.writeln('4. Compare with original: reverse_diff_apk');

      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1048576) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / 1048576).toStringAsFixed(1)} MB';
  }

  // =========================================================================
  // AXML Encoder — 将文本 XML 编译为 Android Binary XML (纯 Dart)
  // =========================================================================

  /// 将文本 XML 编译为二进制 AXML 字节流，可替换 APK 内的 AndroidManifest.xml。
  /// 移植自 Python apk_reverse_engine/utils/axml_converter.py AXMLEncoder。
  static Uint8List? encodeAxml(String xmlText) {
    try {
      // Parse XML text into a simple element tree (regex-based, lightweight).
      final root = _XmlElement.parse(xmlText);
      final pool = _AxmlStringPool();
      pool.add(''); // reserved index 0
      pool.add('http://schemas.android.com/apk/res/android');
      pool.add('android');

      // Collect all strings
      void collectStrings(_XmlElement e) {
        pool.add(e.tag);
        for (final a in e.attrs) {
          pool.add(_stripNsPrefix(a.name));
          pool.add(a.value);
        }
        for (final c in e.children) collectStrings(c);
      }
      collectStrings(root);

      final poolData = pool.serialize();

      // Build XML tree chunks
      final tree = <int>[];

      void encodeElement(_XmlElement e) {
        final tagIdx = pool.indexOf(e.tag);
        final attrs = e.attrs;
        final attrCount = attrs.length;
        final startSize = 8 + 8 + 20 + attrCount * 20;

        // START_TAG chunk
        _writeU16(tree, 0x0102); // type
        _writeU16(tree, 16); // headerSize (chunk header 8 + node 8)
        _writeU32(tree, startSize); // chunkSize
        _writeU32(tree, 0); // lineNumber
        _writeU32(tree, 0xFFFFFFFF); // commentIndex
        _writeU32(tree, 0xFFFFFFFF); // ns
        _writeU32(tree, tagIdx); // nameIndex
        _writeU16(tree, 20); // attrStart
        _writeU16(tree, 20); // attrSize
        _writeU16(tree, attrCount); // attrCount
        _writeU16(tree, 0); // idIndex
        _writeU16(tree, 0); // classIndex
        _writeU16(tree, 0); // styleIndex

        // Attributes
        for (final a in attrs) {
          final isAndroid = a.name.startsWith('android:') ||
              a.name.startsWith('{http://schemas.android.com/apk/res/android}');
          final nsIdx = isAndroid
              ? pool.indexOf('http://schemas.android.com/apk/res/android')
              : 0xFFFFFFFF;
          final nameIdx = pool.indexOf(_stripNsPrefix(a.name));
          final (vi, vt, vd) = _encodeAttrValue(a.value, pool);
          _writeU32(tree, nsIdx);
          _writeU32(tree, nameIdx);
          _writeU32(tree, vi);
          _writeU32(tree, vt);
          _writeU32(tree, vd);
        }

        for (final child in e.children) {
          encodeElement(child);
        }

        // END_TAG chunk
        final endSize = 8 + 8 + 8;
        _writeU16(tree, 0x0103);
        _writeU16(tree, 16);
        _writeU32(tree, endSize);
        _writeU32(tree, 0);
        _writeU32(tree, 0xFFFFFFFF);
        _writeU32(tree, 0xFFFFFFFF);
        _writeU32(tree, tagIdx);
      }

      encodeElement(root);

      // Final assembly: magic + total size + pool + tree
      final totalSize = 8 + poolData.length + tree.length;
      final result = Uint8List(totalSize);
      _writeU32(result, 0x00080003, 0);
      _writeU32(result, totalSize, 4);
      result.setRange(8, 8 + poolData.length, poolData);
      result.setRange(8 + poolData.length, totalSize, tree);
      return result;
    } catch (e) {
      return null;
    }
  }

  static String _stripNsPrefix(String name) {
    if (name.startsWith('{') && name.contains('}')) {
      return name.split('}')[1];
    }
    if (name.contains(':') && !name.startsWith('{')) {
      return name.split(':')[1];
    }
    return name;
  }

  static (int, int, int) _encodeAttrValue(String value, _AxmlStringPool pool) {
    // Boolean
    if (value == 'true' || value == 'false') {
      final vi = pool.indexOf(value);
      final vt = (0x03 << 24) | 0x08; // TYPE_STRING
      final vd = value == 'true' ? 0xFFFFFFFF : 0x00000000;
      return (vi, vt, vd);
    }
    // Integer (decimal)
    final asInt = int.tryParse(value);
    if (asInt != null) {
      final vi = pool.indexOf(value);
      final vt = (0x10 << 24) | 0x08; // TYPE_INTEGER
      return (vi, vt, asInt & 0xFFFFFFFF);
    }
    // Hex integer
    if (value.startsWith('0x') || value.startsWith('0X')) {
      final hexVal = int.tryParse(value.substring(2), radix: 16);
      if (hexVal != null) {
        final vi = pool.indexOf(value);
        final vt = (0x10 << 24) | 0x08;
        return (vi, vt, hexVal & 0xFFFFFFFF);
      }
    }
    // Reference (@ref)
    if (value.startsWith('@')) {
      final vi = pool.indexOf(value);
      final vt = (0x01 << 24) | 0x08; // TYPE_REFERENCE
      return (vi, vt, 0);
    }
    // Default: string
    final vi = pool.indexOf(value);
    final vt = (0x03 << 24) | 0x08;
    return (vi, vt, vi);
  }

  static void _writeU16(List<int> buf, int v, [int offset = -1]) {
    if (offset >= 0) {
      buf[offset] = v & 0xff;
      buf[offset + 1] = (v >> 8) & 0xff;
    } else {
      buf.add(v & 0xff);
      buf.add((v >> 8) & 0xff);
    }
  }

  static void _writeU32(List<int> buf, int v, [int offset = -1]) {
    if (offset >= 0) {
      buf[offset] = v & 0xff;
      buf[offset + 1] = (v >> 8) & 0xff;
      buf[offset + 2] = (v >> 16) & 0xff;
      buf[offset + 3] = (v >> 24) & 0xff;
    } else {
      buf.add(v & 0xff);
      buf.add((v >> 8) & 0xff);
      buf.add((v >> 16) & 0xff);
      buf.add((v >> 24) & 0xff);
    }
  }
