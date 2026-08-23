part of kelivo_reverse_server;

// ---------------------------------------------------------------------------
// Internal APK model
// ---------------------------------------------------------------------------

/// 会话级状态：存放最近一次 decode/build 的工作目录，供后续工具复用。
class _RebuildState {
  static String? lastDecodedDir;
  static String? lastBuiltApk;
}

// ---------------------------------------------------------------------------
// Ambient capability layer (pure Dart): ZIP/APK byte helpers, AXML decoder,
// resource table builder, X.509 certificate & signature builder, APK Signing
// Block writer. These are self-contained so the server can decode / rebuild /
// sign APKs without external Java (apktool / apksigner / baksmali) runtimes.
// ---------------------------------------------------------------------------

/// Minimal DER encoder for X.509 / PKCS#7 structures used in v1 signing.
class _Der {
  static Uint8List seq(List<Uint8List> items) =>
      _wrap(0x30, _concat(items));
  static Uint8List set_(List<Uint8List> items) =>
      _wrap(0x31, _concat(items));

  static Uint8List oid(List<int> oidBytes) => _wrap(0x06, Uint8List.fromList(oidBytes));

  static Uint8List null_() => Uint8List.fromList([0x05, 0x00]);

  static Uint8List bool_(bool v) =>
      Uint8List.fromList([0x01, 0x01, v ? 0xff : 0x00]);

  static Uint8List int_(BigInt v) {
    var bytes = _toUnsignedBytes(v);
    if (bytes.isEmpty) bytes = Uint8List.fromList([0]);
    if (bytes[0] & 0x80 != 0) {
      final out = Uint8List(bytes.length + 1);
      out[0] = 0;
      out.setRange(1, out.length, bytes);
      bytes = out;
    }
    return _wrap(0x02, bytes);
  }

  static Uint8List bitString(Uint8List bytes) {
    final out = Uint8List(bytes.length + 1);
    out[0] = 0; // unused bits
    out.setRange(1, out.length, bytes);
    return _wrap(0x03, out);
  }

  static Uint8List octetString(Uint8List bytes) => _wrap(0x04, bytes);

  static Uint8List utf8String(String s) =>
      _wrap(0x0c, Uint8List.fromList(utf8.encode(s)));

  static Uint8List ia5String(String s) =>
      _wrap(0x16, Uint8List.fromList(utf8.encode(s)));

  static Uint8List printableString(String s) =>
      _wrap(0x13, Uint8List.fromList(utf8.encode(s)));

  static Uint8List utcTime(DateTime t) {
    final two = (int v) => v.toString().padLeft(2, '0');
    final s = '${two(t.year % 100)}${two(t.month)}${two(t.day)}'
        '${two(t.hour)}${two(t.minute)}${two(t.second)}Z';
    return _wrap(0x17, Uint8List.fromList(utf8.encode(s)));
  }

  static Uint8List _toUnsignedBytes(BigInt v) {
    final hex = v.toRadixString(16);
    final padded = hex.length.isOdd ? '0$hex' : hex;
    final b = Uint8List(padded.length ~/ 2);
    for (var i = 0; i < b.length; i++) {
      b[i] = int.parse(padded.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return b;
  }

  static Uint8List _concat(List<Uint8List> items) {
    var len = 0;
    for (final i in items) {
      len += i.length;
    }
    final out = Uint8List(len);
    var off = 0;
    for (final i in items) {
      out.setRange(off, off + i.length, i);
      off += i.length;
    }
    return out;
  }

  static Uint8List _wrap(int tag, Uint8List body) {
    final lenBytes = <int>[];
    if (body.length < 0x80) {
      lenBytes.add(body.length);
    } else {
      final n = _toUnsignedBytes(BigInt.from(body.length));
      lenBytes.add(0x80 | n.length);
      lenBytes.addAll(n);
    }
    final out = Uint8List(1 + lenBytes.length + body.length);
    out[0] = tag;
    out.setRange(1, 1 + lenBytes.length, lenBytes);
    out.setRange(1 + lenBytes.length, out.length, body);
    return out;
  }

  /// Context-specific constructed tag ([0], [1], ...).
  static Uint8List wrapImplicit(int tag, Uint8List body) {
    final lenBytes = <int>[];
    if (body.length < 0x80) {
      lenBytes.add(body.length);
    } else {
      final n = _toUnsignedBytes(BigInt.from(body.length));
      lenBytes.add(0x80 | n.length);
      lenBytes.addAll(n);
    }
    final out = Uint8List(1 + lenBytes.length + body.length);
    out[0] = tag;
    out.setRange(1, 1 + lenBytes.length, lenBytes);
    out.setRange(1 + lenBytes.length, out.length, body);
    return out;
  }
}

/// PKCS#7 SignedData (RFC 5652) for v1 JAR signing.
class _Pkcs7 {
  static const _sha1 = <int>[0x2b, 0x0e, 0x03, 0x02, 0x1a];
  static const _sha256 = <int>[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
  static const _rsa = <int>[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

  static Uint8List buildAsn1({
    required List<Uint8List> certs,
    required List<int> digestAlgorithm,
    required Uint8List signature,
    required BigInt serial,
  }) {
    // contentInfo sequence: signedData (0) + content (absent for detached)
    final version = _Der.int_(BigInt.one);
    final digestAlgs = _Der.set_([
      _Der.seq([_Der.oid(digestAlgorithm), _Der.null_()]),
    ]);
    final contentInfo = _Der.seq([_Der.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])]); // data
    final certSet = _Der.set_(certs);
    final signerIdentifier =
        _Der.seq([_Der.int_(serial), _Der.null_()]); // issuerAndSerialNumber
    final digestAlgo = _Der.seq([_Der.oid(digestAlgorithm), _Der.null_()]);
    final signerAlgo = _Der.seq([_Der.oid(_rsa), _Der.null_()]);
    final signatureBits = _Der.bitString(signature);
    final signerInfo = _Der.seq([
      _Der.int_(BigInt.one),
      signerIdentifier,
      digestAlgo,
      signerAlgo,
      signatureBits,
    ]);
    final signerInfos = _Der.set_([signerInfo]);
    final signedData = _Der.seq([
      version,
      digestAlgs,
      contentInfo,
      certSet,
      _Der.null_(), // crls
      signerInfos,
    ]);
    return _Der.seq([
      _Der.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]), // signedData
      _Der.wrapImplicit(0xa0, signedData),
    ]);
  }
}

/// Assemble an X.509 v3 self-signed certificate (SHA-256 with RSA).
class _X509Builder {
  static Uint8List build({
    required RSAPrivateKey privateKey,
    required String subject,
    required String issuer,
    required int serial,
    required DateTime notBefore,
    required DateTime notAfter,
  }) {
    final subjectName = _name(subject);
    final issuerName = _name(issuer);

    final tbs = _Der.seq([
      _Der.int_(BigInt.from(serial)),
      _Der.seq([
        _Der.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), // sha256WithRSA
        _Der.null_(),
      ]),
      issuerName,
      _Der.seq([
        _Der.utcTime(notBefore),
        _Der.utcTime(notAfter),
      ]),
      subjectName,
      _Der.seq([
        _Der.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), // rsaEncryption
        _Der.null_(),
      ]),
      _Der.bitString(_rsaPublicKeyDer(privateKey)),
      _Der.seq([
        _Der.oid([0x55, 0x1d, 0x0e]), // keyUsage critical
        _Der.octetString(_Der.seq([
          _Der.bool_(true),
          _Der.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
        ])),
      ]),
    ]);

    final digest = _sha256Der(tbs);
    final sig = _rsaSign(privateKey, digest);
    return _Der.seq([
      tbs,
      _Der.seq([
        _Der.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
        _Der.null_(),
      ]),
      _Der.bitString(sig),
    ]);
  }

  static Uint8List _rsaPublicKeyDer(RSAPrivateKey key) {
    return _Der.seq([
      _Der.seq([
        _Der.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
        _Der.null_(),
      ]),
      _Der.bitString(_Der.seq([
        _Der.int_(key.modulus!),
        _Der.int_(key.privateExponent! > BigInt.zero ? key.publicExponent! : BigInt.from(65537)),
      ])),
    ]);
  }

  static Uint8List _name(String dn) {
    // dn like "CN=Test,O=Kelivo,C=CN"
    final parts = dn.split(',').map((e) => e.trim()).toList();
    final rdn = <Uint8List>[];
    for (final p in parts) {
      final kv = p.split('=');
      if (kv.length != 2) continue;
      final k = kv[0].trim().toUpperCase();
      final v = kv[1].trim();
      Uint8List atv;
      switch (k) {
        case 'CN':
          atv = _Der.utf8String(v);
          break;
        case 'O':
        case 'OU':
          atv = _Der.utf8String(v);
          break;
        case 'C':
          atv = _Der.printableString(v);
          break;
        default:
          atv = _Der.utf8String(v);
      }
      final attr = _Der.seq([_Der.oid(_oidFor(k)), atv]);
      rdn.add(_Der.set_([attr]));
    }
    return _Der.seq(rdn);
  }

  static List<int> _oidFor(String k) {
    switch (k) {
      case 'CN':
        return [0x55, 0x04, 0x03];
      case 'O':
        return [0x55, 0x04, 0x0a];
      case 'OU':
        return [0x55, 0x04, 0x0b];
      case 'C':
        return [0x55, 0x04, 0x06];
      case 'ST':
        return [0x55, 0x04, 0x08];
      case 'L':
        return [0x55, 0x04, 0x07];
      case 'EMAILADDRESS':
        return [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
      default:
        return [0x55, 0x04, 0x03];
    }
  }

  static Uint8List _sha256Der(Uint8List data) =>
      SHA256Digest().process(data);

  /// RSASSA-PKCS1-v1_5 with SHA-256: EM = 0x00 0x01 PS 0x00 T, s = m^d mod n.
  static Uint8List _rsaSign(RSAPrivateKey key, Uint8List digest) {
    final n = key.modulus!;
    final d = key.privateExponent!;
    const sha256Oid = <int>[
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
      0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ];
    final k = (n.bitLength + 7) ~/ 8;
    final t = <int>[...sha256Oid, ...digest];
    final em = Uint8List(k);
    em[0] = 0x00;
    em[1] = 0x01;
    var i = 2;
    while (i < k - t.length - 1) {
      em[i++] = 0xff;
    }
    em[i++] = 0x00;
    em.setRange(i, k, t);
    final m = BigInt.parse(_hex(em), radix: 16);
    final s = m.modPow(d, n);
    final sigBytes = _toFixedBytes(s, k);
    return sigBytes;
  }

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  static Uint8List _toFixedBytes(BigInt v, int length) {
    final hex = v.toRadixString(16);
    final padded = hex.length.isOdd ? '0$hex' : hex;
    final raw = Uint8List(padded.length ~/ 2);
    for (var i = 0; i < raw.length; i++) {
      raw[i] = int.parse(padded.substring(i * 2, i * 2 + 2), radix: 16);
    }
    if (raw.length >= length) return raw;
    final out = Uint8List(length);
    out.setRange(length - raw.length, length, raw);
    return out;
  }
}

/// A minimal big-endian byte buffer.
class _ByteBuf {
  final Uint8List bytes;
  int _offset;

  _ByteBuf(this.bytes) : _offset = 0;

  int get offset => _offset;
  int get length => bytes.length;
  int get remaining => bytes.length - _offset;

  int u8() => bytes[_offset++];
  int u16() {
    final v = (bytes[_offset] << 8) | bytes[_offset + 1];
    _offset += 2;
    return v;
  }

  int s16() {
    final v = u16();
    return v >= 0x8000 ? v - 0x10000 : v;
  }

  int u32() {
    final v = (bytes[_offset] << 24) |
        (bytes[_offset + 1] << 16) |
        (bytes[_offset + 2] << 8) |
        bytes[_offset + 3];
    _offset += 4;
    return v;
  }

  int s32() {
    final v = u32();
    return v >= 0x80000000 ? v - 0x100000000 : v;
  }

  Uint8List bytesLen(int n) {
    final out = Uint8List(n);
    out.setRange(0, n, bytes.sublist(_offset, _offset + n));
    _offset += n;
    return out;
  }

  void skip(int n) => _offset += n;

  void seek(int pos) => _offset = pos;
}

/// Android binary XML (AXML) decoder — enough to extract attributes.
class _AxmlLexer {
  final _ByteBuf buf;
  StringPoolChunk? _stringPool;
  final List<Map<String, String>> _namespaceStack = [];
  final List<String> _elementStack = [];

  _AxmlLexer(this.buf);

  String getString(int idx) {
    if (_stringPool == null) return '';
    return _stringPool!.get(idx);
  }

  Map<String, String> decode() {
    final attrs = <String, String>{};
    while (buf.remaining > 0) {
      final type = buf.u32();
      final headerSize = buf.u32();
      final chunkSize = buf.u32();
      if (type == 0x000001) {
        // string pool
        _stringPool = StringPoolChunk.from(buf, chunkSize);
      } else if (type == 0x000002) {
        // resource map — skip
        buf.skip(chunkSize - headerSize);
      } else if (type == 0x0000100) {
        // start namespace
        final line = buf.u32();
        final comment = buf.u32();
        final prefix = buf.u32();
        final uri = buf.u32();
        final p = getString(prefix);
        final u = getString(uri);
        _namespaceStack.add({p: u});
        buf.skip(chunkSize - headerSize - 16);
      } else if (type == 0x0000101) {
        // end namespace
        buf.skip(chunkSize - headerSize - 16);
        if (_namespaceStack.isNotEmpty) _namespaceStack.removeLast();
      } else if (type == 0x0000102) {
        // start element
        final line = buf.u32();
        final comment = buf.u32();
        final ns = buf.u32();
        final name = buf.u32();
        final attributeStart = buf.u16();
        final attributeSize = buf.u16();
        final attributeCount = buf.u16();
        final idIndex = buf.u16();
        final classIndex = buf.u16();
        final styleIndex = buf.u16();
        final nsStr = ns == 0xffffffff ? '' : getString(ns);
        final nameStr = getString(name);
        final tag = nsStr.isNotEmpty ? '${nsStr}:$nameStr' : nameStr;
        _elementStack.add(tag);
        for (var i = 0; i < attributeCount; i++) {
          final rel = buf.u16();
          final attrNs = buf.u16();
          final attrName = buf.u16();
          final rawValue = buf.u16();
          final valueType = buf.u16();
          final data = buf.s32();
          final key = getString(attrName);
          String v;
          if (rawValue != 0xffffffff && rawValue > 0) {
            v = getString(rawValue);
          } else if ((valueType & 0xff) == 0x10) {
            v = '$data';
          } else if ((valueType & 0xff) == 0x11) {
            v = '0x${(data & 0xffffffff).toRadixString(16)}';
          } else if ((valueType & 0xff) == 0x03) {
            v = getString(data);
          } else {
            v = '0x${(data & 0xffffffff).toRadixString(16)}';
          }
          attrs['$tag#$key'] = v;
          attrs[key] = v;
        }
        buf.skip(chunkSize - headerSize - 0x14 - attributeCount * attributeSize);
      } else if (type == 0x0000103) {
        // end element
        buf.skip(chunkSize - headerSize - 8);
        if (_elementStack.isNotEmpty) _elementStack.removeLast();
      } else {
        buf.skip(chunkSize - headerSize);
      }
    }
    return attrs;
  }
}

class StringPoolChunk {
  final List<String> strings;
  StringPoolChunk(this.strings);

  String get(int idx) {
    if (idx >= 0 && idx < strings.length) return strings[idx];
    return '';
  }

  static StringPoolChunk from(_ByteBuf buf, int chunkSize) {
    final start = buf.offset;
    final stringCount = buf.u32();
    final styleCount = buf.u32();
    final flags = buf.u32();
    final stringsStart = buf.u32();
    final stylesStart = buf.u32();
    final utf8 = (flags & 0x100) != 0;
    final offsets = <int>[];
    for (var i = 0; i < stringCount; i++) {
      offsets.add(buf.u32());
    }
    if (styleCount > 0) {
      for (var i = 0; i < styleCount; i++) {
        buf.u32();
      }
    }
    final strings = <String>[];
    final poolBase = start + stringsStart;
    final saved = buf.offset;
    for (var i = 0; i < stringCount; i++) {
      buf.seek(poolBase + offsets[i]);
      if (utf8) {
        final len1 = buf.u8();
        final len2 = (len1 & 0x80) != 0 ? buf.u8() : 0;
        final len = ((len1 & 0x7f) << 8) | len2;
        final b = buf.bytesLen(len);
        strings.add(utf8.decode(b, allowMalformed: true));
      } else {
        final len1 = buf.u16();
        final len2 = (len1 & 0x8000) != 0 ? buf.u16() : 0;
        final len = ((len1 & 0x7fff) << 16) | len2;
        final b = buf.bytesLen(len * 2);
        final units = <int>[];
        for (var j = 0; j < len; j++) {
          units.add((b[j * 2] << 8) | b[j * 2 + 1]);
        }
        strings.add(String.fromCharCodes(units));
      }
    }
    buf.seek(saved);
    buf.skip(chunkSize - (buf.offset - start));
    return StringPoolChunk(strings);
  }
}

/// APK Signing Block (v2) constants: magic + size pair.
class _ApkSigningBlock {
  static const magic = <int>[0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32];

  static Uint8List wrapV2(Uint8List signerBlock) {
    final payload = Uint8List.fromList(signerBlock);
    final size = payload.length + 8;
    final sizeLE = _le32(size);
    final out = Uint8List(8 + payload.length + 8 + magic.length);
    out.setRange(0, 8, sizeLE);
    out.setRange(8, 8 + payload.length, payload);
    out.setRange(8 + payload.length, 8 + payload.length + 8, sizeLE);
    out.setRange(8 + payload.length + 8, out.length, magic);
    return out;
  }

  static Uint8List _le32(int v) {
    final b = Uint8List(4);
    b[0] = v & 0xff;
    b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff;
    b[3] = (v >> 24) & 0xff;
    return b;
  }
}

class _ZipUtil {
  /// Find the offset of the End of Central Directory record.
  static int findEocd(Uint8List bytes) {
    for (var i = bytes.length - 22; i >= 0; i--) {
      if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b &&
          bytes[i + 2] == 0x05 && bytes[i + 3] == 0x06) {
        return i;
      }
    }
    return -1;
  }

  /// Read the central directory offset from EOCD.
  static int centralDirOffset(Uint8List bytes, int eocd) {
    final b = ByteData.sublistView(bytes, eocd + 16, eocd + 20);
    return b.getUint32(0, Endian.little);
  }
}

class _CryptoUtil {
  static Uint8List sha256(List<int> data) =>
      Uint8List.fromList(sha256.convert(data).bytes);

  static Uint8List sha1(List<int> data) =>
      Uint8List.fromList(sha1.convert(data).bytes);

  static Uint8List randomBytes(int n, math.Random rng) {
    final out = Uint8List(n);
    for (var i = 0; i < n; i++) {
      out[i] = rng.nextInt(256);
    }
    return out;
  }
}

/// RSA key generation wrapper (works with pointycastle 4.x).
class _RsaKeyGen {
  /// Generate a 2048-bit RSA key pair. Returns the private key;
  /// the public exponent is embedded (65537).
  static RSAPrivateKey generate2048() {
    final gen = RSAKeyGenerator()
      ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64),
        math.Random.secure(),
      ));
    final pair = gen.generateKeyPair();
    return pair.privateKey as RSAPrivateKey;
  }
}

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

