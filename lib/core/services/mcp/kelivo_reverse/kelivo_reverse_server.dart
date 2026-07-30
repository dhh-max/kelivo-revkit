import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
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
/// Tools (12):
///   reverse_meta_info          → tool self-description & recommended workflows
///   reverse_open_apk           → open APK, list manifest summary, dex & native libs
///   reverse_list_targets       → enumerate all analysis targets in the APK
///   reverse_manifest_summary   → parse AndroidManifest.xml (package, components, permissions)
///   reverse_list_native_libs   → list all .so files inside APK
///   reverse_list_dex_files     → list all classes*.dex files
///   reverse_analyze_so         → aggregated header/import/export/dep/string analysis for a .so
///   reverse_analyze_dex        → aggregated header/class/method/string analysis for a .dex
///   reverse_find_jni_bridges   → locate JNI registration clues (JNI_OnLoad, Java_*, etc.)
///   reverse_search_strings     → cross-target string search (APK metadata + so strings + dex strings)
///   reverse_report             → structured reverse engineering report
///   reverse_quick_triage       → one-shot quick triage: entry, permissions, so, dex, JNI clues, suspicious strings

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
        bytes: bytes, limit: limit, minLength: minLength,
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
      bytes: bytes, apkPath: path, limit: limit, minLength: minLength,
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
      entries.add(_ApkEntry(f.name, f.size, f.compressedSize, content));
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
    }
    if (action == 'workflows' || action.isEmpty) {
      sb.writeln('\n## Recommended Workflows\n');
      sb.writeln('1. **Quick triage**: reverse_open_apk → reverse_quick_triage');
      sb.writeln('2. **Deep analysis**: reverse_open_apk → reverse_analyze_dex → reverse_analyze_so');
      sb.writeln('3. **JNI investigation**: reverse_open_apk → reverse_find_jni_bridges → reverse_analyze_so');
      sb.writeln('4. **String sweep**: reverse_search_strings (cross-target)');
      sb.writeln('5. **Report**: reverse_report (after data collection)');
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
      sb.writeln('')
        ..writeln('--- DEX Files ---');
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
      final importsResult = KelivoSoAnalyzer.listImports(soPayload);
      final exportsResult = KelivoSoAnalyzer.listExports(soPayload);
      final depsResult = KelivoSoAnalyzer.listDependencies(soPayload);
      final stringsResult = KelivoSoAnalyzer.listStrings(soPayload);
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
    ];
  }
}
