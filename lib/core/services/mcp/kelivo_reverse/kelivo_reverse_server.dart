import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';
import 'package:mcp_client/mcp_client.dart' as mcp;

import '../in_memory_mcp_server.dart';
import '../kelivo_so/kelivo_so_server.dart';
import '../kelivo_dex/kelivo_dex_server.dart';

/// @kelivo/reverse — In-memory MCP server engine for APK-level reverse
/// engineering workflow aggregation.
///
/// Serves as the entry-point for APK static analysis. Uses @kelivo/so and
/// @kelivo/dex under the hood for deep analysis of specific targets.
///
/// Tools (16):
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
//   reverse_secret_scan        → scan hardcoded secrets (API keys, tokens, passwords)
//   reverse_component_audit    → exported component security audit
//   reverse_diff_apk          → APK diff analysis (components/permissions/signatures/files)
//   reverse_kill_signature    → signature bypass (过签): strip v1 sig, inject hook smali

// ---------------------------------------------------------------------------
// Internal APK model
// ---------------------------------------------------------------------------

class _ApkEntry {
  final String name;
  final int size;
  final int compressedSize;
  final Uint8List? content;
  _ApkEntry(this.name, this.size, this.compressedSize, this.content);
}

class _ApkInfo {
  final List<_ApkEntry> entries;
  _ApkInfo(this.entries);
}

class _SecretPattern {
  final String pattern;
  final String label;
  _SecretPattern(this.pattern, this.label);
}

// ---------------------------------------------------------------------------
// Payload: path or base64
// ---------------------------------------------------------------------------

class KelivoReverseRequestPayload {
  final Uint8List apkBytes;
  final String? apkPath;
  final int limit;
  final int minLength;

  KelivoReverseRequestPayload({
    required this.apkBytes,
    this.apkPath,
    this.limit = 1000,
    this.minLength = 4,
  });

  static Future<KelivoReverseRequestPayload> parse(Object? args) async {
    if (args is! Map) {
      throw ArgumentError('Invalid arguments: expected object with path|base64');
    }
    final map = args.cast<String, dynamic>();
    final int limit = _asInt(map['limit'], 1000).clamp(1, 100000) as int;
    final int minLength = _asInt(map['min_length'], 4).clamp(1, 256) as int;

    final b64 = (map['base64'] ?? '').toString().trim();
    if (b64.isNotEmpty) {
      final bytes = base64Decode(b64);
      return KelivoReverseRequestPayload(
        apkBytes: bytes, limit: limit, minLength: minLength,
      );
    }

    final path = (map['path'] ?? '').toString().trim();
    if (path.isEmpty) {
      throw ArgumentError('Missing "path" or "base64"');
    }
    final file = File(path);
    if (!await file.exists()) {
      throw ArgumentError('File not found: $path');
    }
    final bytes = await file.readAsBytes();
    return KelivoReverseRequestPayload(
      apkBytes: bytes, apkPath: path, limit: limit, minLength: minLength,
    );
  }

  static int _asInt(Object? v, int fallback) {
    if (v is int) return v;
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v.trim()) ?? fallback;
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// APK reader helpers
// ---------------------------------------------------------------------------

_ApkInfo _readApk(Uint8List bytes) {
  final archive = ZipDecoder().decodeBytes(bytes);
  final entries = <_ApkEntry>[];
  for (final f in archive) {
    if (f.isFile) {
      Uint8List? content;
      try {
        content = f.content as Uint8List?;
      } catch (_) {}
      entries.add(_ApkEntry(f.name, f.size, f.size, content));
    }
  }
  return _ApkInfo(entries);
}

List<_ApkEntry> _filterEntries(_ApkInfo apk, String pattern) {
  return apk.entries.where((e) => e.name.contains(pattern)).toList();
}

String? _findManifestXmlContent(_ApkInfo apk) {
  final entry = apk.entries.cast<_ApkEntry?>().firstWhere(
    (e) => e!.name == 'AndroidManifest.xml',
    orElse: () => null,
  );
  if (entry == null) return null;
  try {
    // Attempt to decode as plain text (may fail for AXML; return partial)
    return utf8.decode(entry.content!, allowMalformed: true);
  } catch (_) {
    return '(binary/AXML, raw size: ${entry.size} bytes)';
  }
}

String _extractTextFromBytes(Uint8List bytes, {int maxLength = 4096}) {
  // Extract human-readable ASCII/UTF-8 fragments
  final sb = StringBuffer();
  for (var i = 0; i < bytes.length && sb.length < maxLength; i++) {
    final c = bytes[i];
    if (c >= 0x20 && c < 0x7f) {
      sb.writeCharCode(c);
    } else if (c == 0x0a || c == 0x0d || c == 0x09) {
      sb.writeCharCode(c);
    }
  }
  return sb.toString();
}

// ---------------------------------------------------------------------------
// Manifest summary from AXML (heuristic extraction)
// ---------------------------------------------------------------------------

String _manifestSummary(Uint8List? manifestBytes) {
  if (manifestBytes == null || manifestBytes.isEmpty) return '(no manifest)';
  final text = _extractTextFromBytes(manifestBytes);
  // Heuristic extraction of common manifest fields
  final sb = StringBuffer();
  for (final line in text.split('\n')) {
    final t = line.trim();
    // Match package name
    if (t.contains('package=')) sb.writeln(t);
    // Match android:name components
    if (t.contains('android:name=')) sb.writeln(t);
    // Match permissions
    if (t.contains('android:permission') || t.contains('.permission.')) sb.writeln(t);
    // Match intent filters
    if (t.contains('action android:name=') || t.contains('category android:name=')) sb.writeln(t);
    // Match launch mode / exported
    if (t.contains('android:exported=')) sb.writeln(t);
    if (t.contains('android:launchMode=')) sb.writeln(t);
  }
  final result = sb.toString().trim();
  return result.isNotEmpty ? result : '(manifest extracted ${manifestBytes.length} bytes, but no structured fields found)';
}

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
    }
    if (action == 'workflows' || action.isEmpty) {
      sb.writeln('\n## Recommended Workflows\n');
      sb.writeln('1. **Quick triage**: reverse_open_apk → reverse_quick_triage');
      sb.writeln('2. **Deep analysis**: reverse_open_apk → reverse_analyze_dex → reverse_analyze_so');
      sb.writeln('3. **JNI investigation**: reverse_open_apk → reverse_find_jni_bridges → reverse_analyze_so');
      sb.writeln('4. **String sweep**: reverse_search_strings (cross-target)');
      sb.writeln('5. **Security audit**: reverse_signature_audit → reverse_packer_detect → reverse_secret_scan → reverse_component_audit');
      sb.writeln('6. **Report**: reverse_report (after data collection)');
    }
    if (action == 'describe' || action.isEmpty) {
      sb.writeln('\n## About\n');
      sb.writeln('`@kelivo/reverse` is an APK-level reverse engineering MCP server.');
      sb.writeln('It aggregates APK opening, manifest parsing, .so and .dex analysis,');
      sb.writeln('JNI bridge detection, cross-target string search, and structured reporting.');
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

  static String _formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1048576) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / 1048576).toStringAsFixed(1)} MB';
  }

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
}

// ---------------------------------------------------------------------------
// MCP Server Engine
// ---------------------------------------------------------------------------

class KelivoReverseMcpServerEngine implements KelivoInMemoryMcpServerEngine {
  bool _closed = false;

  @override
  Future<dynamic> handleMessage(dynamic message) async {
    if (_closed) return null;
    if (message is List) {
      final out = <dynamic>[];
      for (final m in message) {
        out.add(await _handleSingle(m));
      }
      return out;
    }
    return await _handleSingle(message);
  }

  Future<Map<String, dynamic>> _handleSingle(dynamic raw) async {
    try {
      if (raw is! Map) {
        return _error(null, code: -32600, message: 'Invalid Request');
      }
      final req = raw.cast<String, dynamic>();
      final id = req['id'];
      final method = (req['method'] ?? '').toString();
      final params = (req['params'] is Map)
          ? (req['params'] as Map).cast<String, dynamic>()
          : <String, dynamic>{};

      switch (method) {
        case mcp.McpProtocol.methodInitialize:
          return _ok(id, result: {
            'serverInfo': {'name': '@kelivo/reverse', 'version': '0.1.0'},
            'protocolVersion': mcp.McpProtocol.defaultVersion,
            'capabilities': {
              'tools': {'listChanged': false},
            },
          });

        case mcp.McpProtocol.methodListTools:
          return _ok(id, result: {'tools': _toolDefinitions()});

        case mcp.McpProtocol.methodCallTool:
          final name = (params['name'] ?? '').toString();
          final arguments = (params['arguments'] is Map)
              ? (params['arguments'] as Map).cast<String, dynamic>()
              : <String, dynamic>{};

          // Special handling: meta_info doesn't need payload
          if (name == 'reverse_meta_info') {
            return _ok(id, result: KelivoReverseAnalyzer.metaInfo(arguments));
          }

          // All other tools need APK payload
          KelivoReverseRequestPayload payload;
          try {
            payload = await KelivoReverseRequestPayload.parse(arguments);
          } catch (e) {
            return _ok(id, result: KelivoReverseAnalyzer._err(e.toString()));
          }

          switch (name) {
            case 'reverse_open_apk':
              return _ok(id, result: KelivoReverseAnalyzer.openApk(payload));
            case 'reverse_list_targets':
              return _ok(id, result: KelivoReverseAnalyzer.listTargets(payload));
            case 'reverse_manifest_summary':
              return _ok(id, result: KelivoReverseAnalyzer.manifestSummary(payload));
            case 'reverse_list_native_libs':
              return _ok(id, result: KelivoReverseAnalyzer.listNativeLibs(payload));
            case 'reverse_list_dex_files':
              return _ok(id, result: KelivoReverseAnalyzer.listDexFiles(payload));
            case 'reverse_analyze_so':
              return _ok(id, result: KelivoReverseAnalyzer.analyzeSo(payload, arguments));
            case 'reverse_analyze_dex':
              return _ok(id, result: KelivoReverseAnalyzer.analyzeDex(payload, arguments));
            case 'reverse_find_jni_bridges':
              return _ok(id, result: KelivoReverseAnalyzer.findJniBridges(payload));
            case 'reverse_search_strings':
              return _ok(id, result: KelivoReverseAnalyzer.searchStrings(payload, arguments));
            case 'reverse_report':
              return _ok(id, result: KelivoReverseAnalyzer.report(payload, arguments));
            case 'reverse_quick_triage':
              return _ok(id, result: KelivoReverseAnalyzer.quickTriage(payload, arguments));
            case 'reverse_signature_audit':
              return _ok(id, result: KelivoReverseAnalyzer.signatureAudit(payload));
            case 'reverse_packer_detect':
              return _ok(id, result: KelivoReverseAnalyzer.packerDetect(payload));
            case 'reverse_secret_scan':
              return _ok(id, result: KelivoReverseAnalyzer.secretScan(payload, arguments));
            case 'reverse_component_audit':
              return _ok(id, result: KelivoReverseAnalyzer.componentAudit(payload));
            case 'reverse_diff_apk':
              return _ok(id, result: await KelivoReverseAnalyzer.diffApk(payload, arguments));
            case 'reverse_kill_signature':
              return _ok(id, result: await KelivoReverseAnalyzer.killSignature(payload, arguments));
            case 'reverse_resign_apk':
              return _ok(id, result: await KelivoReverseAnalyzer.resignApk(payload, arguments));
            case 'reverse_inject_dex':
              return _ok(id, result: await KelivoReverseAnalyzer.injectDex(payload, arguments));
            case 'reverse_smali_decompile':
              return _ok(id, result: KelivoReverseAnalyzer.smaliDecompile(payload, arguments));
            case 'reverse_obfuscator_detect':
              return _ok(id, result: KelivoReverseAnalyzer.obfuscatorDetect(payload));
            case 'reverse_resource_extract':
              return _ok(id, result: KelivoReverseAnalyzer.resourceExtract(payload, arguments));
            case 'reverse_string_decrypt':
              return _ok(id, result: KelivoReverseAnalyzer.stringDecrypt(payload, arguments));
            case 'reverse_jni_method_map':
              return _ok(id, result: KelivoReverseAnalyzer.jniMethodMap(payload));
            default:
              return _error(id, code: -32101, message: 'Tool not found: $name');
          }

        default:
          if (id == null) return _noop();
          return _error(id, code: -32601, message: 'Method not found: $method');
      }
    } catch (e) {
      return _error(null, code: -32603, message: 'Internal error: $e');
    }
  }

  @override
  void close() {
    _closed = true;
  }

  Map<String, dynamic> _ok(dynamic id, {required Map<String, dynamic> result}) {
    return {'jsonrpc': '2.0', if (id != null) 'id': id, 'result': result};
  }

  Map<String, dynamic> _error(dynamic id, {required int code, required String message}) {
    return {
      'jsonrpc': '2.0',
      if (id != null) 'id': id,
      'error': {'code': code, 'message': message},
    };
  }

  Map<String, dynamic> _noop() => {'jsonrpc': '2.0'};

  List<Map<String, dynamic>> _toolDefinitions() {
    Map<String, dynamic> baseSchema({bool withPath = true, bool withLimit = false, bool withMinLen = false}) {
      final props = <String, dynamic>{};
      if (withPath) {
        props['path'] = {'type': 'string', 'description': '本地 APK 文件的绝对路径。'};
        props['base64'] = {'type': 'string', 'description': '可选：直接提供 Base64 编码的文件字节（优先于 path）。'};
      }
      if (withLimit) {
        props['limit'] = {'type': 'integer', 'description': '返回条目上限，默认 1000。'};
      }
      if (withMinLen) {
        props['min_length'] = {'type': 'integer', 'description': '最小字符串长度，默认 4。'};
      }
      return {
        'type': 'object',
        'properties': props,
      };
    }

    return [
      {
        'name': 'reverse_meta_info',
        'description': '返回工具说明、推荐工作流和帮助信息。传 action=tools|workflows|describe 获取特定部分，不传则返回全部。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'action': {
              'type': 'string',
              'description': '可选：tools（列出工具）、workflows（推荐工作流）、describe（简介）。',
            },
          },
        },
      },
      {
        'name': 'reverse_open_apk',
        'description': '打开 APK 文件，返回 Manifest 摘要、Native 库和 DEX 文件总览。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_list_targets',
        'description': '枚举 APK 内所有可分析目标（.so 和 .dex 文件）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_manifest_summary',
        'description': '解析 AndroidManifest.xml，提取包名、组件、权限等信息。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_list_native_libs',
        'description': '列出 APK 内所有 .so 本地库文件（含对应 ABI）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_list_dex_files',
        'description': '列出 APK 内所有 DEX 文件。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_analyze_so',
        'description': '对指定 .so 文件做聚合分析（header/import/export/dependency/strings/segments），需指定 so_path（如 lib/arm64-v8a/libnative.so）。内部调用 @kelivo/so。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK 文件。'},
            'so_path': {'type': 'string', 'description': 'APK 内目标 .so 路径，如 lib/arm64-v8a/libnative.so。'},
          },
          'required': ['so_path'],
        },
      },
      {
        'name': 'reverse_analyze_dex',
        'description': '对指定 DEX 文件做聚合分析（header/classes/methods/strings），需指定 dex_path（如 classes.dex）。内部调用 @kelivo/dex。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK 文件。'},
            'dex_path': {'type': 'string', 'description': 'APK 内目标 DEX 路径，如 classes.dex。'},
          },
          'required': ['dex_path'],
        },
      },
      {
        'name': 'reverse_find_jni_bridges',
        'description': '在整个 APK 范围内搜索 JNI 注册线索（JNI_OnLoad、Java_* 导出符号、native 方法声明）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_search_strings',
        'description': '跨目标搜索字符串（Manifest + SO 字符串 + DEX 字符串中的匹配项）。需要 query 参数。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK 文件。'},
            'query': {'type': 'string', 'description': '要搜索的字符串（不区分大小写）。'},
          },
          'required': ['query'],
        },
      },
      {
        'name': 'reverse_report',
        'description': '基于当前 APK 数据生成结构化逆向分析报告（目标概览/Manifest/Native/DEX/JNI/可疑关键词/下一步建议）。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_quick_triage',
        'description': '一键快速初筛：返回入口信息、ABI、Native 库、DEX、JNI 线索、可疑关键词和推荐操作。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_signature_audit',
        'description': 'APK 签名审计：检测签名方案（v1/v2/v3），提取 META-INF 证书文件，解析证书 DN 字段（CN/O/OU），列出 .SF 摘要条目。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_packer_detect',
        'description': '加固/加壳检测：基于已知 Packer 指纹（360/Baidu/Tencent/Ali/Bangcle/NetEase/Legu/Ijiami/UPX）和可疑特征（Stub DEX、异常 ELF 结构、反调试库、自定义Section名）进行检测。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_secret_scan',
        'description': '硬编码秘钥扫描：扫描 DEX/SO/Manifest 中的 API Key、Secret、Token、Password、JWT、AWS Key、Firebase Key、Stripe Key、数据库连接串等 16 种模式。支持 limit 参数控制返回上限。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK 文件。'},
            'limit': {'type': 'integer', 'description': '每种文件类型返回的匹配条目上限，默认 50。'},
          },
        },
      },
      {
        'name': 'reverse_component_audit',
        'description': '导出组件安全审计：分析 AndroidManifest 中所有 activity/service/receiver/provider 的 exported 状态、intent-filter、permission 保护情况，标记潜在风险组件。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_diff_apk',
        'description': 'APK 深度对比分析（版本演进审计）：对比两个 APK 之间的 Activities/Services/Receivers/Providers/Permissions 变化差异（ADDED/REMOVED/UNCHANGED）、文件级增量/删减、签名方案变更、ABI 差异、DEX 文件变化。支持 compare_path 或 compare_base64 参数指定对比目标。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '本地 APK 文件路径（当前版本）。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的当前版本 APK。'},
            'compare_path': {'type': 'string', 'description': '对比目标 APK 的本地文件路径（如上一版本）。'},
            'compare_base64': {'type': 'string', 'description': '可选：Base64 编码的对比目标 APK。'},
          },
        },
      },
      {
        'name': 'reverse_kill_signature',
        'description': '过签工具：提取 APK 原始签名证书 → 删除 META-INF 签名文件（去除 v1 签名校验）→ 将原始签名以 Base64 注入 assets/kelivo_original_sign → 生成 PmsHook smali 模板代码（Application 子类，通过反射 hook PackageManager 返回原始签名）。输出处理后的 APK + hook smali 文件。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '输入 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK。'},
            'output': {'type': 'string', 'description': '输出处理后 APK 的保存路径（必填）。'},
          },
          'required': ['output'],
        },
      },
      {
        'name': 'reverse_resign_apk',
        'description': '清除旧签名并重新生成 MANIFEST.MF（SHA-256 摘要）。输出 APK 需配合 apksigner 或 jarsigner 完成最终签名。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '输入 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK。'},
            'output': {'type': 'string', 'description': '输出 APK 的保存路径（必填）。'},
          },
          'required': ['output'],
        },
      },
      {
        'name': 'reverse_inject_dex',
        'description': '将外部 DEX 文件注入 APK 作为 classesN.dex（自动确定 N 编号）。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': '输入 APK 文件路径。'},
            'base64': {'type': 'string', 'description': '可选：Base64 编码的 APK。'},
            'dex_path': {'type': 'string', 'description': '要注入的 DEX 文件路径（必填）。'},
            'output': {'type': 'string', 'description': '输出 APK 的保存路径（必填）。'},
          },
          'required': ['dex_path', 'output'],
        },
      },
      {
        'name': 'reverse_smali_decompile',
        'description': '反编译指定DEX为Smali代码，支持类名过滤。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK路径'},
            'base64': {'type': 'string', 'description': 'APK Base64'},
            'dex_path': {'type': 'string', 'description': '目标DEX路径'},
            'class_filter': {'type': 'string', 'description': '类名正则过滤'},
          },
          'required': ['dex_path'],
        },
      },
      {
        'name': 'reverse_obfuscator_detect',
        'description': '检测混淆/加固方案，支持主流360/梆梆/爱加密等。',
        'inputSchema': baseSchema(),
      },
      {
        'name': 'reverse_resource_extract',
        'description': '提取APK内匹配的资源文件到指定目录，支持文件名正则。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK路径'},
            'base64': {'type': 'string', 'description': 'APK Base64'},
            'pattern': {'type': 'string', 'description': '文件名匹配正则'},
            'output_dir': {'type': 'string', 'description': '输出目录'},
          },
          'required': ['output_dir'],
        },
      },
      {
        'name': 'reverse_string_decrypt',
        'description': '自动解密DEX/SO中常见加密方案的字符串常量。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK路径'},
            'base64': {'type': 'string', 'description': 'APK Base64'},
            'target': {'type': 'string', 'description': 'dex|so|all，默认all'},
          },
        },
      },
      {
        'name': 'reverse_jni_method_map',
        'description': '构建JNI方法映射表，匹配Java native方法与Native函数。',
        'inputSchema': baseSchema(),
      },
    ];
  }
}
          'properties': {
            'path': {'type': 'string', 'description': 'APK路径'},
            'base64': {'type': 'string', 'description': 'APK Base64'},
            'pattern': {'type': 'string', 'description': '文件名正则匹配规则，默认提取全部资源'},
            'output_dir': {'type': 'string', 'description': '资源保存输出目录（必填）'},
          },
          'required': ['output_dir'],
        },
      },
      {
        'name': 'reverse_string_decrypt',
        'description': '自动解密DEX/SO中常见加密字符串，支持AES/XOR/Base64/RC4等。',
        'inputSchema': {
          'type': 'object',
          'properties': {
            'path': {'type': 'string', 'description': 'APK路径'},
            'base64': {'type': 'string', 'description': 'APK Base64'},
            'target': {'type': 'string', 'description': '分析目标：dex|so|all，默认all'},
            'target_path': {'type': 'string', 'description': '可选：指定目标文件路径，如classes.dex'},
          },
        },
      },
      {
        'name': 'reverse_jni_method_map',
        'description': '构建JNI方法映射表，匹配Java层native方法与Native层函数对应关系。',
        'inputSchema': baseSchema(),
      },
    ];
  }
}
