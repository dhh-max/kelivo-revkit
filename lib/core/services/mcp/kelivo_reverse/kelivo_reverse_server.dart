/// @kelivo/reverse — In-memory MCP server engine for APK-level reverse
/// engineering workflow aggregation.
///
/// Serves as the entry-point for APK static analysis. Uses @kelivo/so and
/// @kelivo/dex under the hood for deep analysis of specific targets.
///
/// Tools (54):
//   reverse_meta_info          → tool self-description & recommended workflows
//   reverse_open_apk           → open APK, list manifest summary, dex & native libs
//   reverse_list_targets       → enumerate all analysis targets in the APK
//   reverse_manifest_summary   → parse AndroidManifest.xml (package, components, permissions)
//   reverse_list_native_libs   → list all .so files inside APK
//   reverse_list_dex_files     → list all classes*.dex files
//   reverse_analyze_so         → aggregated header/import/export/dep/string analysis for a .so
//   reverse_analyze_dex        → aggregated header/class/method/string analysis for a .dex
//   reverse_find_jni_bridges   → locate JNI registration clues (JNI_OnLoad, Java_*, etc.)
//   reverse_search_strings     → cross-target string search (APK metadata + so strings + dex strings)
//   reverse_report             → structured reverse engineering report
//   reverse_quick_triage       → one-shot quick triage: entry, permissions, so, dex, JNI clues, suspicious strings
//   reverse_signature_audit    → APK signature scheme & certificate analysis
//   reverse_packer_detect      → detect packers/protectors (360/Baidu/Tencent/UPX etc.)
//   reverse_secret_scan       → scan hardcoded secrets (API keys, tokens, passwords)
//   reverse_component_audit    → exported component security audit
//   reverse_diff_apk          → APK diff analysis (components/permissions/signatures/files)
//   reverse_kill_signature    → signature bypass (过签): strip v1 sig, inject hook smali
//   reverse_smali_decompile   → decompile DEX to smali, with class name filter
//   reverse_obfuscator_detect → detect ProGuard/R8/DexGuard/360/Bangcle/Ijiami/Legu/etc.
//   reverse_resource_extract  → batch extract APK resources to disk, with regex filter
//   reverse_string_decrypt    → heuristic string decryption (Base64/XOR/AES-ECB pattern)
//   reverse_jni_method_map    → build JNI method mapping (Java native ↔ SO symbols)
//   reverse_dex_string_replace → DEX string batch replace (equal-length, in-place)
//   reverse_batch_resign      → batch re-sign APK (strip old sig + fresh MANIFEST.MF + apksigner)
//   reverse_unpack_guide      → one-click unpacking guide (detect packer → recommend method)
//   reverse_apk_rebuild       → decode/build/merge/refactor APK workdir workflow
//   reverse_apk_sign          → pure-Dart APK signing (v1 JAR + v2 Signing Block)
//   reverse_axml_edit         → AXML encode (text XML → binary) / replace in APK
//   reverse_manifest_edit     → manifest attribute editor (debuggable/exported/etc.)
//   reverse_smali_patch       → smali instruction-level patching (find/bypass/inject/nop/stub)
//   reverse_zipalign          → APK 4-byte zip-align (Dart archive repackage)
//   reverse_hook_gen          → hook script generator (Frida JS / Xposed Java / Smali)
//   reverse_dex_merge        → merge multiple classes*.dex into single classes.dex
//   reverse_anti_analysis     → anti-debug/root/emulator/hook/VPN/virtual detection (7 categories)
//   reverse_callgraph         → DEX call graph: callers/callees/hotspots/recursion
//   reverse_crypto_analyzer  → crypto algorithm/mode/hash/weak-crypto/key-mgmt analysis
//   reverse_dataflow          → DEX taint tracking (source→sink) + constant scanning
//   reverse_dex_metadata      → hidden API / reflection / annotation processors / serialization
//   reverse_multidex          → multi-DEX distribution / cross-refs / duplicate detection
//   reverse_native_xref       → native-Java cross reference (DEX native ↔ SO JNI symbols)
//   reverse_vuln_scan         → 11-category vulnerability scanner (strings + manifest + DEX methods)
//   reverse_privacy_audit     → 13-category privacy risk assessment + data exfiltration
//   reverse_sdk_detect        → 80+ third-party SDK / tracker detection + privacy risk
//   reverse_endpoint_extract  → network endpoint extraction (URL/domain/IP/API path/cloud)
//   reverse_social_login      → 9-platform social login detection (WeChat/QQ/GitHub/etc.)
//   reverse_apk_size          → APK size breakdown by category + recommendations
//   reverse_security_score    → comprehensive security score with CWE mapping
//   reverse_api_usage         → 13-category API usage statistics + reflection detection
//   reverse_permission_trace  → permission-to-API cross-reference (used/unused/missing)
//   reverse_clone_detect      → DEX method clone detection (exact + similar, cross-DEX)
//   reverse_network_analysis  → network behavior deep analysis (SSL/WebSocket/schemes/ports)
//   reverse_string_analyze   → DEX string deep analysis (13 categories + sensitive info)
//   reverse_key_scan         → key/credential deep scan (21 patterns + weak crypto)
//   reverse_cert_deep        → certificate deep analysis (debug cert/CA/algorithms/V1-V3)
//   reverse_sig_scheme       → APK signature scheme detection (V1/V2/V3/V4 + security level)
//   reverse_deobfuscate      → auto deobfuscation (XOR/byte arrays/Base64/CFG/arithmetic)
//   reverse_code_analyze     → deep code analysis (URLs/APIs/dangerous APIs/key scan)
//   reverse_resource_analyze → APK resource analysis (categories/compression/large files)
//   reverse_resource_obfuscation → resource obfuscation detection (naming patterns/ratio)
//   reverse_apk_clean        → APK clean analysis (debug/backup/duplicates/waste)
//   reverse_component_explore → component explorer (exported/intent filters/deep links)
//   reverse_core_class_locate → core class locator (heuristic scoring/Top 20)
//   reverse_ad_detect         → ad detection (23 SDKs/code patterns/ad domains)
//   reverse_clue_chain        → cross-module clue chain analysis (8 analyzers/risk score)
//   reverse_dex_lib_analysis  → DEX third-party library detection (40+ libs/bloat score)
//   reverse_dex_reflection    → DEX reflection & dynamic loading analysis
//   reverse_dex_resource_ref  → DEX resource reference analysis (R$ refs/hardcoded IDs)
//   reverse_dex_serialization → DEX serialization & persistence analysis
//   reverse_dex_string_pool   → DEX string pool deep analysis (distribution/sensitive patterns)
//   reverse_dex_obfuscation_scan → DEX obfuscation scan (class names/packer fingerprints)
//   reverse_dex_crypto        → DEX crypto analysis (algorithms/hash/weak detection)
//   reverse_dex_class_density → DEX class density analysis (packages/interfaces/abstract)
//   reverse_dex_inner_class   → DEX inner/anonymous class analysis (nesting/lambda)
//   reverse_dex_native        → DEX native method analysis (JNI/loadLibrary/SO count)
//   reverse_dex_const_scan    → DEX constant scan (numeric/keyword constants)
//   reverse_dex_inheritance   → DEX inheritance analysis (interfaces/abstract/root classes)
//   reverse_dex_method_stats  → DEX method signature stats (11 pattern categories)
//   reverse_dex_access_flow   → DEX access flow analysis (sensitive methods/modifiers)
//   reverse_dex_permission_audit → DEX permission audit (12 permission-API maps/dangerous combos)

library kelivo_reverse_server;

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';
import 'package:mcp_client/mcp_client.dart' as mcp;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/rsa.dart';

import '../in_memory_mcp_server.dart';
import '../kelivo_so/kelivo_so_server.dart';
import '../kelivo_dex/kelivo_dex_server.dart';
import '../kelivo_jadx/kelivo_jadx_server.dart';

part 'reverse_utils.dart';
part 'reverse_payload.dart';
part 'reverse_analyzer_basic.dart';
part 'reverse_analyzer_mod.dart';
part 'reverse_analyzer_tools.dart';
part 'reverse_xml_model.dart';
part 'reverse_server.dart';
part 'reverse_apk_file_ops.dart';
part 'reverse_manifest_ops.dart';
part 'reverse_arsc.dart';
part 'reverse_workspace.dart';
part 'reverse_adb.dart';
part 'reverse_native_advanced.dart';
part 'reverse_smali_advanced.dart';