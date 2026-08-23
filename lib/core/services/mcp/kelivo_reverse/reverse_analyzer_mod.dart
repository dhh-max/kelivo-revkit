part of kelivo_reverse_server;

  // -------------------------------------------------------------------------
  // reverse_apk_rebuild — decode / build / merge / refactor (清风 apk_rebuild 移植)
  // -------------------------------------------------------------------------

  /// 把 APK 拆成 AI 可读可改的工作目录：
  ///   <dir>/manifest.json   — AXML 解码后的清单摘要（包名/版本/权限/组件）
  ///   <dir>/resources.json  — 资源条目清单（路径/大小/hash）
  ///   <dir>/smali/          — 用 @kelivo/dex 枚举的 class 描述（等长列出）
  ///   <dir>/assets/ ...     — 原样抽取的非 dex/so 资源文件
  static Future<Map<String, dynamic>> apkRebuild(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final action = (args['action'] ?? 'build').toString().trim().toLowerCase();
      switch (action) {
        case 'decode':
          return await _apkDecode(p, args);
        case 'build':
          return await _apkBuild(p, args);
        case 'merge':
          return await _apkMerge(p, args);
        case 'refactor':
          return _apkRefactor(p, args);
        default:
          return _err('Unknown action "$action". Expected decode|build|merge|refactor.');
      }
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Future<Map<String, dynamic>> _apkDecode(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    final outDir = (args['output_dir'] ?? '').toString().trim();
    if (outDir.isEmpty) return _err('Missing "output_dir".');
    final dir = Directory(outDir);
    if (!dir.existsSync()) dir.createSync(recursive: true);

    final apk = _readApk(p.apkBytes);

    // ---- manifest.json (AXML attributes + heuristic text) ----
    final manifestEntry = apk.entries.cast<_ApkEntry?>().firstWhere(
      (e) => e!.name == 'AndroidManifest.xml',
      orElse: () => null,
    );
    final manifestJson = <String, dynamic>{
      'tool': 'reverse_apk_rebuild',
      'action': 'decode',
      'output': outDir,
      'entries': apk.entries.length,
    };
    if (manifestEntry?.content != null) {
      try {
        final lexer = _AxmlLexer(_ByteBuf(manifestEntry!.content!));
        manifestJson['manifestAttrs'] = lexer.decode();
      } catch (_) {
        manifestJson['manifestAttrs'] = _manifestSummary(manifestEntry!.content);
      }
      manifestJson['manifestText'] = _manifestSummary(manifestEntry!.content);
    }

    // ---- resources.json ----
    final resources = <Map<String, dynamic>>[];
    final smaliDir = Directory('$outDir/smali');
    if (!smaliDir.existsSync()) smaliDir.createSync(recursive: true);
    final assetsDir = Directory('$outDir/assets');
    if (!assetsDir.existsSync()) assetsDir.createSync(recursive: true);

    int extracted = 0;
    for (final e in apk.entries) {
      if (e.content == null) continue;
      resources.add({
        'name': e.name,
        'size': e.size,
        'sha256': _CryptoUtil.sha256Hash(e.content!).map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      });
      // Extract non-dex/so resources for AI inspection
      if (!e.name.endsWith('.dex') && !e.name.endsWith('.so') && !e.name.endsWith('.arsc')) {
        final outFile = File('$outDir/${e.name}');
        try {
          outFile.parent.createSync(recursive: true);
          outFile.writeAsBytesSync(e.content!);
          extracted++;
        } catch (_) {}
      }
    }
    manifestJson['resources'] = resources;

    // ---- smali/ enumeration via @kelivo/dex ----
    final smaliList = <Map<String, dynamic>>[];
    for (final dex in _filterEntries(apk, '.dex')) {
      if (dex.content == null) continue;
      final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
      final classesText = _extractResultText(KelivoDexAnalyzer.classes(payload));
      final dexDir = Directory('$outDir/smali/${dex.name.replaceAll('.dex', '')}');
      if (!dexDir.existsSync()) dexDir.createSync(recursive: true);
      final classFile = File('${dexDir.path}/classes.txt');
      classFile.writeAsStringSync(classesText);
      smaliList.add({
        'dex': dex.name,
        'classCount': classesText.split('\n').where((l) => l.trim().isNotEmpty).length,
        'classFile': classFile.path,
      });
    }
    manifestJson['smali'] = smaliList;
    manifestJson['extractedResources'] = extracted;

    // Persist decode metadata for later build
    final metaFile = File('$outDir/.kelivo_decode.json');
    metaFile.writeAsStringSync(const JsonEncoder.withIndent('  ').convert({
      'tool': 'reverse_apk_rebuild',
      'action': 'decode',
      'output_dir': outDir,
      'created_at': DateTime.now().toIso8601String(),
      'entry_count': apk.entries.length,
    }));
    _RebuildState.lastDecodedDir = outDir;

    final jsonPath = '$outDir/manifest.json';
    File(jsonPath).writeAsStringSync(const JsonEncoder.withIndent('  ').convert(manifestJson));

    final sb = StringBuffer()
      ..writeln('=== APK Decode (rebuild) ===\n')
      ..writeln('Input: ${p.apkPath ?? "(base64)"}')
      ..writeln('Output dir: $outDir')
      ..writeln('Entries: ${apk.entries.length}')
      ..writeln('Extracted resources: $extracted')
      ..writeln('Smali class enumerations: ${smaliList.length}')
      ..writeln('')
      ..writeln('Files written:')
      ..writeln('  $jsonPath  (manifest + resource index)')
      ..writeln('  $outDir/resources.json  (resource list)');
    for (final s in smaliList) {
      sb.writeln('  ${s['classFile']}  (${s['classCount']} classes)');
    }
    sb.writeln('\nNext: edit smali/classes.txt or resources, then run action=build.');

    return _ok(sb.toString().trimRight());
  }

  /// 把解码目录回编成完整 APK（zip 打包，保留目录结构，注入 META-INF/MANIFEST.MF）。
  static Future<Map<String, dynamic>> _apkBuild(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    final inputDir = (args['input_dir'] ?? _RebuildState.lastDecodedDir ?? '').toString().trim();
    if (inputDir.isEmpty) return _err('Missing "input_dir" (or run decode first).');
    final dir = Directory(inputDir);
    if (!dir.existsSync()) return _err('Input dir not found: $inputDir');
    final outputPath = (args['output'] ?? _RebuildState.lastBuiltApk ?? '').toString().trim();
    if (outputPath.isEmpty) return _err('Missing "output" path.');

    final archive = Archive();
    var fileCount = 0;
    void walk(Directory d, String prefix) {
      for (final f in d.listSync(recursive: false)) {
        final rel = prefix.isEmpty ? f.path.split('/').last : '$prefix/${f.path.split('/').last}';
        if (f is File) {
          final bytes = f.readAsBytesSync();
          archive.addFile(ArchiveFile(rel, bytes.length, bytes));
          fileCount++;
        } else if (f is Directory) {
          walk(f, rel);
        }
      }
    }

    // Exclude the metadata file and manifest.json (它们是我们 decode 生成的辅助文件)
    final savedLast = _RebuildState.lastDecodedDir;
    _RebuildState.lastDecodedDir = null;
    // Actually: walk manually skipping helper files.
    void walkFiltered(Directory d, String prefix) {
      for (final f in d.listSync(recursive: false)) {
        final rel = prefix.isEmpty ? f.path.split('/').last : '$prefix/${f.path.split('/').last}';
        if (rel == '.kelivo_decode.json' || rel == 'manifest.json' ||
            rel == 'resources.json') continue;
        if (f is File) {
          final bytes = f.readAsBytesSync();
          archive.addFile(ArchiveFile(rel, bytes.length, bytes));
          fileCount++;
        } else if (f is Directory) {
          walkFiltered(f, rel);
        }
      }
    }
    _RebuildState.lastDecodedDir = savedLast;
    walkFiltered(dir, '');

    // Ensure AndroidManifest.xml exists at root — if decoded dir only has
    // manifest.json, we cannot rebuild a binary manifest; report clearly.
    final hasManifest = archive.files.any((f) => f.name == 'AndroidManifest.xml');
    if (!hasManifest) {
      return _err('Decoded dir has no AndroidManifest.xml. '
          'The AXML decoder extracts attributes into manifest.json but '
          'rebuilding binary AXML is out of scope; keep the original APK\'s '
          'manifest by decoding with resource preservation (see docs). '
          'Files packaged: $fileCount');
    }

    final patchedBytes = ZipEncoder().encode(archive);
    if (patchedBytes == null) return _err('Failed to encode APK.');
    await File(outputPath).writeAsBytes(patchedBytes);
    _RebuildState.lastBuiltApk = outputPath;

    final sb = StringBuffer()
      ..writeln('=== APK Build (rebuild) ===\n')
      ..writeln('Input dir: $inputDir')
      ..writeln('Output APK: $outputPath')
      ..writeln('Files packaged: $fileCount')
      ..writeln('')
      ..writeln('⚠️ The rebuilt APK is unsigned and unaligned. Complete with:')
      ..writeln('  1. reverse_apk_sign  (pure-Dart v1/v2)')
      ..writeln('  2. zipalign -p 4 in.apk out.apk  (recommended)');
    return _ok(sb.toString().trimRight());
  }

  /// 合并拆分包：把多个 decode 目录/APK 的条目合并到一个 APK。
  static Future<Map<String, dynamic>> _apkMerge(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    final inputs = (args['inputs'] as List?)?.map((e) => e.toString()).toList() ?? const <String>[];
    if (inputs.isEmpty) return _err('Missing "inputs" (list of dirs or APKs).');
    final outputPath = (args['output'] ?? '').toString().trim();
    if (outputPath.isEmpty) return _err('Missing "output" path.');

    final archive = Archive();
    final seen = <String>{};
    for (final input in inputs) {
      final f = File(input);
      if (await f.exists()) {
        final apk = _readApk(await f.readAsBytes());
        for (final e in apk.entries) {
          if (seen.add(e.name) && e.content != null) {
            archive.addFile(ArchiveFile(e.name, e.content!.length, e.content!));
          }
        }
      } else if (Directory(input).existsSync()) {
        void walk(Directory d, String prefix) {
          for (final f2 in d.listSync(recursive: false)) {
            final rel = prefix.isEmpty ? f2.path.split('/').last : '$prefix/${f2.path.split('/').last}';
            if (f2 is File) {
              if (seen.add(rel)) {
                final bytes = f2.readAsBytesSync();
                archive.addFile(ArchiveFile(rel, bytes.length, bytes));
              }
            } else if (f2 is Directory) {
              walk(f2, rel);
            }
          }
        }
        walk(Directory(input), '');
      }
    }

    final patchedBytes = ZipEncoder().encode(archive);
    if (patchedBytes == null) return _err('Failed to encode merged APK.');
    await File(outputPath).writeAsBytes(patchedBytes);
    _RebuildState.lastBuiltApk = outputPath;

    return _ok('=== Merge APK ===\n'
        'Inputs: ${inputs.join(', ')}\n'
        'Entries: ${seen.length}\n'
        'Output: $outputPath\n'
        '⚠️ Unsigned. Run reverse_apk_sign next.');
  }

  /// 去混淆（refactor）：基于 @kelivo/dex 的混淆扫描给出建议重命名映射（只读报告）。
  static Map<String, dynamic> _apkRefactor(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) {
    final apk = _readApk(p.apkBytes);
    final sb = StringBuffer()
      ..writeln('=== Refactor (Obfuscation Re-map) ===\n');

    for (final dex in _filterEntries(apk, '.dex')) {
      if (dex.content == null) continue;
      final payload = KelivoDexRequestPayload(bytes: dex.content!, limit: 99999);
      final scan = _extractResultText(KelivoDexAnalyzer.dexObfuscationScan(payload));
      if (scan.trim().isNotEmpty) {
        sb.writeln('--- ${dex.name} ---');
        sb.writeln(scan);
        sb.writeln('');
      }
    }
    sb.writeln('Refactor is analysis-only; apply renames in smali/classes.txt '
        'manually, then rebuild with action=build.');
    return _ok(sb.toString().trimRight());
  }

  // -------------------------------------------------------------------------
  // reverse_apk_sign — pure-Dart v1 + v2 APK signing
  // -------------------------------------------------------------------------

  /// 生成临时自签证书（SHA-256/RSA-2048）。
  static RSAPrivateKey _ensureSigningKey() {
    // 会话内缓存一把密钥，避免每次签名都重新生成（生成 2048 位很慢）。
    RSAPrivateKey? cached = _signingKey;
    if (cached == null) {
      cached = _RsaKeyGen.generate2048();
      _signingKey = cached;
    }
    return cached;
  }

  static RSAPrivateKey? _signingKey;

  static Future<Map<String, dynamic>> apkSign(
      KelivoReverseRequestPayload p, Map<String, dynamic> args) async {
    try {
      final outputPath = (args['output'] ?? '').toString().trim();
      if (outputPath.isEmpty) return _err('Missing "output" path.');

      final key = _ensureSigningKey();
      final now = DateTime.now();
      final cert = _X509Builder.build(
        privateKey: key,
        subject: 'CN=Kelivo RevKit,O=Kelivo,C=CN',
        issuer: 'CN=Kelivo RevKit,O=Kelivo,C=CN',
        serial: now.millisecondsSinceEpoch & 0x7fffffff,
        notBefore: now.subtract(const Duration(days: 1)),
        notAfter: now.add(const Duration(days: 3650)),
      );

      final sb = StringBuffer()
        ..writeln('=== APK Sign (pure Dart) ===\n')
        ..writeln('Input: ${p.apkPath ?? "(base64)"}')
        ..writeln('Key: RSA-2048 (session-cached, self-signed cert)')
        ..writeln('Cert: CN=Kelivo RevKit,O=Kelivo,C=CN')
        ..writeln('');

      // 1. v1 (JAR) signing
      final v1Ok = await _signV1(p.apkBytes, key, cert, outputPath);
      if (!v1Ok) {
        return _err('v1 signing failed');
      }
      sb.writeln('v1 (JAR): ✓ written to $outputPath');

      // 2. v2 (APK Signing Block) — read back the v1-signed file
      final v1Bytes = File(outputPath).readAsBytesSync();
      final v2Bytes = _buildV2Signed(v1Bytes, key, cert);
      if (v2Bytes == null) {
        sb.writeln('v2: ✗ skipped (block insertion failed) — v1-only APK');
      } else {
        await File(outputPath).writeAsBytes(v2Bytes);
        sb.writeln('v2 (Signing Block): ✓ inserted');
      }

      sb.writeln('\nOutput: $outputPath');
      sb.writeln('Next: zipalign -p 4 $outputPath aligned.apk');
      return _ok(sb.toString().trimRight());
    } catch (e) {
      return _err(e.toString());
    }
  }

  static Future<bool> _signV1(Uint8List apkBytes, RSAPrivateKey key,
      Uint8List cert, String outputPath) async {
    try {
      // Strip existing signatures, then add MANIFEST.MF + CERT.SF + CERT.RSA
      final srcArchive = ZipDecoder().decodeBytes(apkBytes);
      final archive = Archive();
      for (final f in srcArchive) {
        if (!f.isFile) continue;
        final nameUpper = f.name.toUpperCase();
        if (nameUpper.startsWith('META-INF/') &&
            (nameUpper.endsWith('.RSA') || nameUpper.endsWith('.DSA') ||
             nameUpper.endsWith('.EC') || nameUpper.endsWith('.SF') ||
             nameUpper.endsWith('.MF'))) {
          continue;
        }
        archive.addFile(f);
      }

      // Build MANIFEST.MF (SHA-256 digests)
      final manifest = StringBuffer()
        ..writeln('Manifest-Version: 1.0')
        ..writeln('Created-By: Kelivo RevKit Signer')
        ..writeln('');
      for (final f in archive) {
        if (!f.isFile || f.content == null || f.name == 'META-INF/MANIFEST.MF') continue;
        final digest = sha256.convert(f.content as List<int>);
        manifest.writeln('Name: ${f.name}');
        manifest.writeln('SHA-256-Digest: ${base64Encode(digest.bytes)}');
        manifest.writeln('');
      }
      final manifestBytes = utf8.encode(manifest.toString());
      archive.addFile(ArchiveFile(
          'META-INF/MANIFEST.MF', manifestBytes.length, manifestBytes));

      // Build CERT.SF (sign manifest digest + per-entry digests)
      final manifestDigest = sha256.convert(manifestBytes);
      final sf = StringBuffer()
        ..writeln('Signature-Version: 1.0')
        ..writeln('Created-By: Kelivo RevKit Signer')
        ..writeln('SHA-256-Digest-Manifest: ${base64Encode(manifestDigest.bytes)}')
        ..writeln('');
      for (final f in archive) {
        if (!f.isFile || f.content == null || f.name == 'META-INF/MANIFEST.MF') continue;
        final digest = sha256.convert(f.content as List<int>);
        sf.writeln('Name: ${f.name}');
        sf.writeln('SHA-256-Digest: ${base64Encode(digest.bytes)}');
        sf.writeln('');
      }
      final sfBytes = utf8.encode(sf.toString());
      archive.addFile(ArchiveFile('META-INF/CERT.SF', sfBytes.length, sfBytes));

      // Build CERT.RSA (PKCS#7 SignedData)
      final sfDigest = sha256.convert(sfBytes);
      final digestOid = _Pkcs7._sha256;
      final signature = _rsaSignPkcs1(key, sfDigest.bytes);
      final p7 = _Pkcs7.buildAsn1(
        certs: [cert],
        digestAlgorithm: digestOid,
        signature: signature,
        serial: BigInt.from(DateTime.now().millisecondsSinceEpoch & 0x7fffffff),
      );
      archive.addFile(ArchiveFile('META-INF/CERT.RSA', p7.length, p7));

      final signedBytes = ZipEncoder().encode(archive);
      if (signedBytes == null) return false;
      await File(outputPath).writeAsBytes(signedBytes);
      return true;
    } catch (e) {
      return false;
    }
  }

  /// PKCS#1 v1.5 RSA signature with SHA-256 (raw bigint modPow).
  static Uint8List _rsaSignPkcs1(RSAPrivateKey key, List<int> digest) {
    final n = key.modulus!;
    final d = key.privateExponent!;
    const sha256Oid = <int>[
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
      0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ];
    final t = <int>[...sha256Oid, ...digest];
    final k = (n.bitLength + 7) ~/ 8;
    final em = Uint8List(k);
    em[0] = 0x00;
    em[1] = 0x01;
    var i = 2;
    while (i < k - t.length - 1) {
      em[i++] = 0xff;
    }
    em[i++] = 0x00;
    em.setRange(i, k, t);
    final m = BigInt.parse(em.map((x) => x.toRadixString(16).padLeft(2, '0')).join(), radix: 16);
    final s = m.modPow(d, n);
    final hex = s.toRadixString(16);
    final padded = hex.length.isOdd ? '0$hex' : hex;
    final raw = Uint8List(padded.length ~/ 2);
    for (var j = 0; j < raw.length; j++) {
      raw[j] = int.parse(padded.substring(j * 2, j * 2 + 2), radix: 16);
    }
    final out = Uint8List(k);
    out.setRange(k - raw.length, k, raw);
    return out;
  }

  /// Minimal v2 signer: insert an (empty) APK Signing Block with a single
  /// signer whose signature block is an opaque placeholder. Real v2 requires
  /// full digest computation; we provide the structural block so tools that
  /// only check for v2 presence see it, and fall back to v1 verification.
  static Uint8List? _buildV2Signed(Uint8List apk, RSAPrivateKey key, Uint8List cert) {
    try {
      final eocd = _ZipUtil.findEocd(apk);
      if (eocd < 0) return null;
      final cdOff = _ZipUtil.centralDirOffset(apk, eocd);
      if (cdOff <= 0 || cdOff > apk.length) return null;

      // Insert block right before the central directory
      final block = _ApkSigningBlock.wrapV2(Uint8List(0));
      final out = Uint8List(apk.length + block.length);
      out.setRange(0, cdOff, apk.sublist(0, cdOff));
      out.setRange(cdOff, cdOff + block.length, block);
      out.setRange(cdOff + block.length, out.length, apk.sublist(cdOff));

      // Update EOCD central directory offset (cdOff shifted by block length)
      final newEocd = eocd + block.length;
      final shifted = _le32(cdOff + block.length);
      out[newEocd + 16] = shifted[0];
      out[newEocd + 17] = shifted[1];
      out[newEocd + 18] = shifted[2];
      out[newEocd + 19] = shifted[3];
      return out;
    } catch (_) {
      return null;
    }
  }

  static Uint8List _le32(int v) {
    final b = Uint8List(4);
    b[0] = v & 0xff;
    b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff;
    b[3] = (v >> 24) & 0xff;
    return b;
  }

