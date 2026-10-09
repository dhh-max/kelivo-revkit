import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// 数值 / 字节级计算（自研工具 `value_calc` 的实现）。
///
/// 存在的理由：改包工作里到处是「值算术」——补丁值要换算成目标位宽的十六
/// 进制、smali 的 const/high16 要还原成 IEEE754 浮点、混淆字符串要先
/// base64/hex 解码再改、native 侧还得判断大小端。这些让模型心算在本项目的
/// 真机复测里出过错（地址换算 6 次错 2 次），所以把确定性计算收进工具：一次
/// 调用给全所有表示，并且 `steps[]` 允许同一次调用内串联多步、用
/// `{"$step": i, "field": "bitWidths.bit32.hex"}` 引用前序结果，省掉多轮往返。
///
/// 工具面划分与链式批处理思路参考 calculate-mcp（MIT，
/// https://github.com/KonghuanSmart/calculate-mcp）；本文件为独立实现，
/// 未拷贝其代码。
abstract final class ValueCalcService {
  const ValueCalcService._();

  /// steps[] 上限：与 tool_batch 的 8 次同口径，避免单次调用产出失控。
  static const int maxSteps = 8;

  /// steps 内引用前序结果的键名（JSON 里写作 `"$step"`）。
  static const String stepRefKey = r'$step';

  /// 唯一入口。永不抛出：失败一律返回 `{ok:false, error, message}`，
  /// 由出口的 ToolErrorPolicy 统一补 recoverable（R5）。
  static Map<String, dynamic> execute(Map<String, dynamic> args) {
    try {
      final steps = args['steps'];
      if (steps is List && steps.isNotEmpty) {
        return _runSteps(steps);
      }
      final action = (args['action'] ?? '').toString().trim();
      if (action.isEmpty) {
        throw _CalcError(
          'INVALID_ARGS',
          'action is required: convert / bitwise / endian / float / codec / '
              'hash / crc / mod, or pass steps[] to chain several in one call',
        );
      }
      return _runAction(action, args);
    } on _CalcError catch (e) {
      return <String, dynamic>{'ok': false, 'error': e.code, 'message': e.message};
    } catch (e) {
      return <String, dynamic>{
        'ok': false,
        'error': 'CALC_FAILED',
        'message': 'value_calc failed: $e',
      };
    }
  }

  static Map<String, dynamic> _runAction(String action, Map<String, dynamic> a) {
    switch (action) {
      case 'convert':
        return _convert(a);
      case 'bitwise':
        return _bitwise(a);
      case 'endian':
        return _endian(a);
      case 'float':
        return _float(a);
      case 'codec':
        return _codec(a);
      case 'hash':
        return _hash(a);
      case 'crc':
        return _crc(a);
      case 'mod':
        return _mod(a);
      default:
        throw _CalcError(
          'INVALID_ACTION',
          'unknown action "$action": expected convert / bitwise / endian / '
              'float / codec / hash / crc / mod',
        );
    }
  }

  // ---------------------------------------------------------------- steps[]

  static Map<String, dynamic> _runSteps(List<dynamic> rawSteps) {
    if (rawSteps.length > maxSteps) {
      throw _CalcError(
        'STEPS_TOO_MANY',
        'steps is capped at $maxSteps (got ${rawSteps.length}); split the chain',
      );
    }
    final results = <Map<String, dynamic>>[];
    for (var i = 0; i < rawSteps.length; i++) {
      final raw = rawSteps[i];
      if (raw is! Map) {
        throw _CalcError('INVALID_ARGS', 'steps[$i] must be an object');
      }
      final step = _resolveRefs(
        _withImplicitValue(Map<String, dynamic>.from(raw), results, i),
        results,
        i,
      );
      final action = (step['action'] ?? '').toString().trim();
      if (action.isEmpty) {
        throw _CalcError('INVALID_ARGS', 'steps[$i] is missing action');
      }
      // 单步失败要包成 STEP_FAILED 并保留已完成的前序步骤：直接抛出会让
      // 调用方只看到内层错误码，看不出「链断在第几步」。
      Map<String, dynamic> out;
      try {
        out = _runAction(action, step);
      } on _CalcError catch (e) {
        out = <String, dynamic>{'ok': false, 'error': e.code, 'message': e.message};
      }
      results.add(<String, dynamic>{
        'step': i,
        'action': action,
        // 隐式接值时透明回带：调用方要能看出这个 value 是从哪来的（#9）。
        if (step['_implicitFromStep'] != null)
          'implicitFrom': <String, dynamic>{
            'step': step['_implicitFromStep'],
            'field': step['_implicitFromField'],
          },
        ...out,
      });
      if (out['ok'] != true) {
        return <String, dynamic>{
          'ok': false,
          'error': 'STEP_FAILED',
          'message': 'steps[$i] ($action) failed: ${out['error']}',
          'failedStep': i,
          'steps': results,
        };
      }
    }
    return <String, dynamic>{
      'ok': true,
      'action': 'steps',
      'count': results.length,
      'steps': results,
      'final': results.last,
    };
  }

  /// 隐式接上一步（用户报告 #9）：`steps[]` 原先只认**显式**引用
  /// （`{"$stepRefKey": 0, "field": "hex"}`），省略 `value` 直接报
  /// "endian needs value"——于是 `[{convert…},{endian, widthBytes:4}]` 这种最自然的
  /// 写法反而走不通，用户得自己去查上一步的输出字段名。
  ///
  /// 现在：某步**没给 value** 且**前面有步骤**时，按下面的优先级从上一一步的结果里
  /// 取"最像值"的字段注入，并在该步输出里回带 `implicitFrom`（透明，不猜哑谜）。
  /// 显式 `value`/`$step` 引用永远优先，不受影响。
  static const List<String> _implicitValueFields = <String>[
    'hex',            // convert / bitwise / hash 的主输出
    'bigEndianHex',   // endian
    'littleEndianHex',
    'resultHex',      // bitwise 的另一组
    'checksumHex',    // crc
    'decimal',        // convert 的十进制
    'value',          // codec / float
    'resultDecUnsigned',
  ];

  static Map<String, dynamic> _withImplicitValue(
    Map<String, dynamic> step,
    List<Map<String, dynamic>> previous,
    int index,
  ) {
    if (previous.isEmpty) return step;
    if (step.containsKey('value')) return step;
    // 显式引用（$step / $ref 之类）已经在别的键上，_resolveRefs 会处理，不动它。
    final hasExplicitRef = step.values.any(
      (v) => v is Map && v.containsKey(stepRefKey),
    );
    if (hasExplicitRef) return step;
    final action = (step['action'] ?? '').toString().trim();
    // 只有"吃一个值"的动作才注入；批量/无值动作（hash 的 file 等）不碰。
    const valueConsuming = <String>{
      'convert', 'bitwise', 'endian', 'float', 'codec', 'hash', 'crc', 'mod',
    };
    if (!valueConsuming.contains(action)) return step;
    final prev = previous.last;
    for (final field in _implicitValueFields) {
      final candidate = prev[field];
      if (candidate != null && candidate.toString().trim().isNotEmpty) {
        return <String, dynamic>{
          ...step,
          'value': candidate,
          '_implicitFromStep': previous.length - 1,
          '_implicitFromField': field,
        };
      }
    }
    return step;
  }

  static Map<String, dynamic> _resolveRefs(    Map<String, dynamic> step,
    List<Map<String, dynamic>> previous,
    int index,
  ) {
    return <String, dynamic>{
      for (final entry in step.entries)
        entry.key: _resolveValue(entry.value, previous, index),
    };
  }

  static Object? _resolveValue(
    Object? value,
    List<Map<String, dynamic>> previous,
    int index,
  ) {
    if (value is Map) {
      if (value.containsKey(stepRefKey)) {
        final ref = (value[stepRefKey] as num?)?.toInt();
        if (ref == null || ref < 0 || ref >= previous.length) {
          throw _CalcError(
            'INVALID_STEP_REF',
            'steps[$index] references step ${value[stepRefKey]}, but only '
                '${previous.length} earlier step(s) exist (reference an earlier '
                'step index)',
          );
        }
        final field = (value['field'] ?? '').toString().trim();
        if (field.isEmpty) {
          throw _CalcError(
            'INVALID_STEP_REF',
            'steps[$index] reference needs field, e.g. '
                '{"$stepRefKey": 0, "field": "hex"}',
          );
        }
        return _dig(previous[ref], field, index);
      }
      return <String, dynamic>{
        for (final entry in value.entries)
          entry.key.toString(): _resolveValue(entry.value, previous, index),
      };
    }
    if (value is List) {
      return value
          .map((item) => _resolveValue(item, previous, index))
          .toList(growable: false);
    }
    return value;
  }

  static Object? _dig(Object? root, String path, int index) {
    Object? current = root;
    for (final segment in path.split('.')) {
      if (segment.isEmpty) continue;
      if (current is Map) {
        if (!current.containsKey(segment)) {
          throw _CalcError(
            'INVALID_STEP_REF',
            'steps[$index] field "$path" not found (no "$segment")',
          );
        }
        current = current[segment];
      } else if (current is List) {
        final at = int.tryParse(segment);
        if (at == null || at < 0 || at >= current.length) {
          throw _CalcError(
            'INVALID_STEP_REF',
            'steps[$index] field "$path" has no list item "$segment"',
          );
        }
        current = current[at];
      } else {
        throw _CalcError(
          'INVALID_STEP_REF',
          'steps[$index] field "$path" cannot descend into "$segment"',
        );
      }
    }
    return current;
  }

  // -------------------------------------------------------------- convert

  static Map<String, dynamic> _convert(Map<String, dynamic> a) {
    final from = _choice(a['from'], _radixNames, 'auto', 'from');
    final inputs = <Object?>[];
    if (a['value'] != null) inputs.add(a['value']);
    final batch = a['values'];
    if (batch is List) inputs.addAll(batch);
    if (inputs.isEmpty) {
      throw _CalcError(
        'INVALID_ARGS',
        "convert needs value (single) or values (batch), e.g. "
            '{"action":"convert","value":"0x401000"}',
      );
    }
    if (inputs.length > maxSteps) {
      throw _CalcError(
        'INVALID_ARGS',
        'convert batch is capped at $maxSteps values (got ${inputs.length})',
      );
    }
    final converted = inputs
        .map((input) => _convertOne(input, _parseInt(input, from: from)))
        .toList(growable: false);
    if (converted.length == 1) {
      return <String, dynamic>{
        'ok': true,
        'action': 'convert',
        'count': 1,
        ...converted.first,
      };
    }
    return <String, dynamic>{
      'ok': true,
      'action': 'convert',
      'count': converted.length,
      'values': converted,
    };
  }

  static Map<String, dynamic> _convertOne(Object? raw, BigInt value) {
    final negative = value.isNegative;
    final magnitude = value.abs();
    final u8 = _asUintN(8, value);
    final s8 = _asIntN(8, value);
    final u16 = _asUintN(16, value);
    final s16 = _asIntN(16, value);
    final u32 = _asUintN(32, value);
    final s32 = _asIntN(32, value);
    final u64 = _asUintN(64, value);
    final s64 = _asIntN(64, value);
    final ascii = value >= BigInt.from(32) && value <= BigInt.from(126)
        ? String.fromCharCode(value.toInt())
        : null;
    return <String, dynamic>{
      'input': raw.toString(),
      'decimal': value.toString(),
      'hex': '${negative ? '-' : ''}0x${magnitude.toRadixString(16)}',
      'hexUpper': '${negative ? '-' : ''}0x${magnitude.toRadixString(16).toUpperCase()}',
      'binary': '${negative ? '-' : ''}0b${magnitude.toRadixString(2)}',
      'octal': '${negative ? '-' : ''}0o${magnitude.toRadixString(8)}',
      if (ascii != null) 'ascii': ascii,
      'bitWidths': <String, dynamic>{
        'bit8': <String, dynamic>{
          'unsigned': u8.toInt(),
          'signed': s8.toInt(),
          'hex': _hex(u8, 2),
        },
        'bit16': <String, dynamic>{
          'unsigned': u16.toInt(),
          'signed': s16.toInt(),
          'hex': _hex(u16, 4),
          'littleEndianHex': _littleEndianHex(u16, 2),
        },
        'bit32': <String, dynamic>{
          'unsigned': u32.toInt(),
          'signed': s32.toInt(),
          'hex': _hex(u32, 8),
          'littleEndianHex': _littleEndianHex(u32, 4),
        },
        'bit64': <String, dynamic>{
          'unsigned': u64.toString(),
          'signed': s64.toString(),
          'hex': _hex(u64, 16),
          'littleEndianHex': _littleEndianHex(u64, 8),
        },
      },
    };
  }

  // -------------------------------------------------------------- bitwise

  static const List<String> _bitwiseOps = <String>[
    'and',
    'or',
    'xor',
    'not',
    'shl',
    'shr',
    'sar',
    'rol',
    'ror',
  ];

  static Map<String, dynamic> _bitwise(Map<String, dynamic> a) {
    final op = _choice(a['op'], _bitwiseOps, '', 'op');
    if (op.isEmpty) {
      throw _CalcError(
        'INVALID_ARGS',
        'bitwise needs op=${_bitwiseOps.join('/')}',
      );
    }
    final from = _choice(a['from'], _radixNames, 'auto', 'from');
    final width = _bitWidth(a['bitWidth']);
    final aRaw = _parseInt(a['a'], from: from);
    final unsignedA = _asUintN(width, aRaw);
    final mask = (BigInt.one << width) - BigInt.one;

    var b = BigInt.zero;
    if (op != 'not') {
      if (a['b'] == null) {
        throw _CalcError(
          'INVALID_ARGS',
          'bitwise op="$op" needs b (second operand or shift count)',
        );
      }
      b = _parseInt(a['b'], from: from);
    }

    final result = switch (op) {
      'and' => (unsignedA & _asUintN(width, b)) & mask,
      'or' => (unsignedA | _asUintN(width, b)) & mask,
      'xor' => (unsignedA ^ _asUintN(width, b)) & mask,
      'not' => ~unsignedA & mask,
      'shl' => (unsignedA << _shiftCount(b, width)) & mask,
      'shr' => (unsignedA >> _shiftCount(b, width)) & mask,
      'sar' => _asUintN(
        width,
        _asIntN(width, unsignedA) >> _shiftCount(b, width),
      ),
      'rol' => _rotateLeft(unsignedA, _shiftCount(b, width), width, mask),
      'ror' => _rotateRight(unsignedA, _shiftCount(b, width), width, mask),
      _ => throw _CalcError('INVALID_ACTION', 'unsupported bitwise op "$op"'),
    };

    return <String, dynamic>{
      'ok': true,
      'action': 'bitwise',
      'op': op,
      'bitWidth': width,
      'operandA': aRaw.toString(),
      if (op != 'not') 'operandB': b.toString(),
      'resultHex': _hex(result, width ~/ 4),
      'resultDecUnsigned': result.toString(),
      'resultDecSigned': _asIntN(width, result).toString(),
      'resultBinary': '0b${result.toRadixString(2).padLeft(width, '0')}',
    };
  }

  static int _shiftCount(BigInt raw, int width) {
    // 与 C 语义一致：移位量按位宽取模（负数取模后回正）。
    final mod = raw % BigInt.from(width);
    final normalized = mod.isNegative ? mod + BigInt.from(width) : mod;
    return normalized.toInt();
  }

  static BigInt _rotateLeft(BigInt value, int shift, int width, BigInt mask) {
    if (shift == 0) return value;
    return ((value << shift) | (value >> (width - shift))) & mask;
  }

  static BigInt _rotateRight(BigInt value, int shift, int width, BigInt mask) {
    if (shift == 0) return value;
    return ((value >> shift) | (value << (width - shift))) & mask;
  }

  // ------------------------------------------------------------- endian

  static Map<String, dynamic> _endian(Map<String, dynamic> a) {
    final value = a['value'];
    if (value == null || value.toString().trim().isEmpty) {
      throw _CalcError(
        'INVALID_ARGS',
        "endian needs value: a number, 0x-prefixed hex, or a hex byte stream "
            'like "01020304"',
      );
    }
    // schema 的 from 枚举是全工具共享的 auto/hex/dec/bin/oct；endian 曾只放行
    // auto/hex/dec，于是声明里合法的 from=bin|oct 在这里被 INVALID_ARGS 挡掉
    // （同一参数在 convert/bitwise 能用、在 endian 不能用）。这里对齐枚举，
    // _toBytes 把 from 交给 _parseInt 按该进制解释裸串。
    final from = _choice(a['from'], _radixNames, 'auto', 'from');
    final widthBytes = _optionalPositiveInt(a['widthBytes'], 'widthBytes');
    final (bytes, interpretedAs) = _toBytes(value, widthBytes, from);
    final reversed = bytes.reversed.toList(growable: false);
    return <String, dynamic>{
      'ok': true,
      'action': 'endian',
      'interpretedAs': interpretedAs,
      'byteCount': bytes.length,
      'bigEndianHex': _hexOf(bytes),
      'littleEndianHex': _hexOf(reversed),
      'byteArray': bytes,
      'hexFormatted': bytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(' '),
    };
  }

  /// 判定「十六进制字节流」还是「十进制数值」。
  ///
  /// 纯数字串是最容易读错的形态（`010203040506` 是 hex dump 而不是十进制
  /// 一亿多），所以除了显式 from，这里再给三条自解释规则；结果里回显
  /// interpretedAs，模型能自查是否读错。
  static bool _looksLikeHexStream(String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return false;
    if (RegExp(r'^0[xX]').hasMatch(trimmed)) return true;
    final compact = trimmed.replaceAll(RegExp(r'[\s_]'), '');
    if (compact.isEmpty) return false;
    if (RegExp(r'[a-fA-F]').hasMatch(compact)) return true;
    // 分隔成对的十六进制（"01 02 03 04"）
    if (RegExp(r'[\s_]').hasMatch(trimmed) &&
        RegExp(r'^[0-9a-fA-F]+$').hasMatch(compact)) {
      return true;
    }
    // 带前导零的偶数长数字串：十进制值不会写成 0 开头
    return compact.startsWith('0') && compact.length >= 2 && compact.length.isEven;
  }

  static (List<int>, String) _toBytes(Object raw, int? widthBytes, String from) {
    final text = raw.toString().trim();
    final asByteStream =
        from == 'hex' || (from == 'auto' && _looksLikeHexStream(text));

    if (!asByteStream) {
      // from=bin|oct|dec 必须真的按该进制取值，否则裸串 "1010" 会被当十进制
      // 静默算成 1010；from=auto 与旧行为等价（前缀优先）。
      final value = _parseInt(raw, from: from);
      final width = widthBytes ?? _autoWidthBytes(value);
      var remaining = _asUintN(width * 8, value);
      final bytes = List<int>.filled(width, 0);
      for (var i = width - 1; i >= 0; i--) {
        bytes[i] = (remaining & BigInt.from(0xff)).toInt();
        remaining >>= 8;
      }
      return (bytes, 'number');
    }

    var clean = text
        .replaceFirst(RegExp(r'^0[xX]'), '')
        .replaceAll(RegExp(r'[\s_]'), '');
    if (clean.isEmpty) {
      throw _CalcError('INVALID_HEX', 'endian value "$text" has no hex digits');
    }
    if (clean.length.isOdd) clean = '0$clean';
    if (!RegExp(r'^[0-9a-fA-F]+$').hasMatch(clean)) {
      throw _CalcError(
        'INVALID_HEX',
        'endian value "$text" is not a hex byte stream; for a decimal number '
            'pass from=dec or a bare number',
      );
    }
    final bytes = <int>[];
    for (var i = 0; i < clean.length; i += 2) {
      bytes.add(int.parse(clean.substring(i, i + 2), radix: 16));
    }
    if (widthBytes != null && bytes.length < widthBytes) {
      bytes.insertAll(0, List<int>.filled(widthBytes - bytes.length, 0));
    }
    return (bytes, 'hexByteStream');
  }

  static int _autoWidthBytes(BigInt value) {
    if (value > BigInt.from(0xffffffff) || value < BigInt.from(-0x80000000)) {
      return 8;
    }
    if (value > BigInt.from(0xffff) || value < BigInt.from(-0x8000)) return 4;
    if (value > BigInt.from(0xff) || value < BigInt.from(-0x80)) return 2;
    return 1;
  }

  // --------------------------------------------------------------- float

  static Map<String, dynamic> _float(Map<String, dynamic> a) {
    final precision = _choice(
      a['precision'],
      const <String>['auto', 'float32', 'float64'],
      'auto',
      'precision',
    );
    final raw = a['value'];
    if (raw == null || raw.toString().trim().isEmpty) {
      throw _CalcError(
        'INVALID_ARGS',
        'float needs value: a decimal number like 3.14159 or 0x-prefixed '
            'machine code like 0x3f800000',
      );
    }
    final text = raw.toString().trim();
    final asMachineCode = text.startsWith('0x') || text.startsWith('0X');

    Map<String, dynamic>? f32;
    Map<String, dynamic>? f64;
    if (asMachineCode) {
      var clean = text
          .substring(2)
          .replaceAll(RegExp(r'[\s_]'), '');
      if (clean.isEmpty || !RegExp(r'^[0-9a-fA-F]+$').hasMatch(clean)) {
        throw _CalcError('INVALID_HEX', 'float value "$text" is not hex');
      }
      if (clean.length > 16) {
        throw _CalcError(
          'INVALID_HEX',
          'IEEE754 machine code is at most 8 bytes (16 hex digits), got '
              '${clean.length}',
        );
      }
      final bytes = <int>[];
      final padded = clean.length <= 8
          ? clean.padLeft(8, '0')
          : clean.padLeft(16, '0');
      for (var i = 0; i < padded.length; i += 2) {
        bytes.add(int.parse(padded.substring(i, i + 2), radix: 16));
      }
      if (padded.length == 8) {
        f32 = _analyzeFloat32(bytes);
        if (precision != 'float32') {
          f64 = _analyzeFloat64(_encodeFloat64(f32['value'] as double));
        }
      } else {
        f64 = _analyzeFloat64(bytes);
        if (precision != 'float64') {
          f32 = _analyzeFloat32(_encodeFloat32(f64['value'] as double));
        }
      }
    } else {
      final number = double.tryParse(text);
      if (number == null || !number.isFinite) {
        throw _CalcError(
          'INVALID_NUMBER',
          'float value "$text" is neither a finite decimal number nor '
              '0x-prefixed machine code',
        );
      }
      if (precision != 'float64') f32 = _analyzeFloat32(_encodeFloat32(number));
      if (precision != 'float32') f64 = _analyzeFloat64(_encodeFloat64(number));
    }

    return <String, dynamic>{
      'ok': true,
      'action': 'float',
      'input': text,
      if (f32 != null) 'float32': f32,
      if (f64 != null) 'float64': f64,
    };
  }

  static List<int> _encodeFloat32(double value) {
    final data = ByteData(4)..setFloat32(0, value);
    return data.buffer.asUint8List().toList(growable: false);
  }

  static List<int> _encodeFloat64(double value) {
    final data = ByteData(8)..setFloat64(0, value);
    return data.buffer.asUint8List().toList(growable: false);
  }

  static Map<String, dynamic> _analyzeFloat32(List<int> bytes) {
    final data = ByteData.sublistView(Uint8List.fromList(bytes));
    final value = data.getFloat32(0);
    final bits = data.getUint32(0);
    final signBit = (bits >> 31) & 1;
    final rawExponent = (bits >> 23) & 0xff;
    final mantissa = bits & 0x7fffff;
    return <String, dynamic>{
      'value': value,
      'hex': '0x${bits.toRadixString(16).padLeft(8, '0')}',
      'binary': '0b${bits.toRadixString(2).padLeft(32, '0')}',
      'signBit': signBit,
      'sign': signBit == 1 ? '-' : '+',
      'rawExponentHex': '0x${rawExponent.toRadixString(16).padLeft(2, '0')}',
      'rawExponentDec': rawExponent,
      'biasedExponent': rawExponent == 0 ? -126 : rawExponent - 127,
      'mantissaHex': '0x${mantissa.toRadixString(16).padLeft(6, '0')}',
      'mantissaFraction': mantissa / (1 << 23),
      'type': _floatType(rawExponent, BigInt.from(mantissa), 0xff),
    };
  }

  static Map<String, dynamic> _analyzeFloat64(List<int> bytes) {
    final data = ByteData.sublistView(Uint8List.fromList(bytes));
    final value = data.getFloat64(0);
    final bits = (BigInt.from(data.getUint32(0)) << 32) |
        BigInt.from(data.getUint32(4));
    final signBit = ((bits >> 63) & BigInt.one).toInt();
    final rawExponent = ((bits >> 52) & BigInt.from(0x7ff)).toInt();
    final mantissa = bits & BigInt.from(0xfffffffffffff);
    return <String, dynamic>{
      'value': value,
      'hex': '0x${bits.toRadixString(16).padLeft(16, '0')}',
      'binary': '0b${bits.toRadixString(2).padLeft(64, '0')}',
      'signBit': signBit,
      'sign': signBit == 1 ? '-' : '+',
      'rawExponentHex': '0x${rawExponent.toRadixString(16).padLeft(3, '0')}',
      'rawExponentDec': rawExponent,
      'biasedExponent': rawExponent == 0 ? -1022 : rawExponent - 1023,
      'mantissaHex': '0x${mantissa.toRadixString(16).padLeft(13, '0')}',
      'mantissaFraction': mantissa.toDouble() / 4503599627370496.0,
      'type': _floatType(rawExponent, mantissa, 0x7ff),
    };
  }

  static String _floatType(int rawExponent, BigInt mantissa, int maxExponent) {
    if (rawExponent == 0) return mantissa == BigInt.zero ? 'zero' : 'subnormal';
    if (rawExponent == maxExponent) {
      return mantissa == BigInt.zero ? 'infinity' : 'nan';
    }
    return 'normal';
  }

  // --------------------------------------------------------------- codec

  static const List<String> _codecOps = <String>[
    'to_base64',
    'from_base64',
    'to_hex',
    'from_hex',
    'url_encode',
    'url_decode',
  ];

  static Map<String, dynamic> _codec(Map<String, dynamic> a) {
    final op = _choice(a['op'], _codecOps, '', 'op');
    if (op.isEmpty) {
      throw _CalcError('INVALID_ARGS', 'codec needs op=${_codecOps.join('/')}');
    }
    final input = a['value']?.toString() ?? '';
    if (a['value'] == null) {
      throw _CalcError('INVALID_ARGS', 'codec needs value (the text or hex to process)');
    }
    final format = _choice(a['format'], const <String>['text', 'hex'], 'text', 'format');
    final urlSafe = a['urlSafe'] == true;

    switch (op) {
      case 'to_base64':
        final bytes = format == 'hex' ? _hexToBytes(input) : utf8.encode(input);
        var encoded = base64.encode(bytes);
        if (urlSafe) {
          encoded = encoded
              .replaceAll('+', '-')
              .replaceAll('/', '_')
              .replaceAll(RegExp(r'=+$'), '');
        }
        return <String, dynamic>{
          'ok': true,
          'action': 'codec',
          'op': op,
          'base64': encoded,
          'byteCount': bytes.length,
        };
      case 'from_base64':
        var clean = input.trim().replaceAll('-', '+').replaceAll('_', '/');
        while (clean.length % 4 != 0) {
          clean = '$clean=';
        }
        final bytes = _tryBase64Decode(clean, input);
        return <String, dynamic>{
          'ok': true,
          'action': 'codec',
          'op': op,
          if (format == 'hex') 'hex': _hexOf(bytes) else 'text': _utf8Of(bytes, input),
          'byteCount': bytes.length,
        };
      case 'to_hex':
        final bytes = utf8.encode(input);
        return <String, dynamic>{
          'ok': true,
          'action': 'codec',
          'op': op,
          'hex': _hexOf(bytes),
          'hexFormatted':
              bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' '),
          'byteCount': bytes.length,
        };
      case 'from_hex':
        final bytes = _hexToBytes(input);
        return <String, dynamic>{
          'ok': true,
          'action': 'codec',
          'op': op,
          'text': _utf8Of(bytes, input),
          'byteCount': bytes.length,
        };
      case 'url_encode':
        return <String, dynamic>{
          'ok': true,
          'action': 'codec',
          'op': op,
          'encoded': Uri.encodeComponent(input),
        };
      default:
        try {
          return <String, dynamic>{
            'ok': true,
            'action': 'codec',
            'op': op,
            'decoded': Uri.decodeComponent(input),
          };
        } on FormatException {
          throw _CalcError(
            'INVALID_ARGS',
            'url_decode input "$input" is not a valid percent-encoded string',
          );
        }
    }
  }

  // ------------------------------------------------------- hash / crc / mod

  static Map<String, dynamic> _hash(Map<String, dynamic> a) {
    if (a['value'] == null) {
      throw _CalcError('INVALID_ARGS', 'hash needs value (data to hash)');
    }
    final algorithm = _choice(
      a['algorithm'],
      const <String>['md5', 'sha1', 'sha256'],
      'sha256',
      'algorithm',
    );
    final format = _choice(a['format'], const <String>['text', 'hex'], 'text', 'format');
    final data = a['value'].toString();
    final bytes = format == 'hex' ? _hexToBytes(data) : utf8.encode(data);
    final digest = switch (algorithm) {
      'md5' => md5.convert(bytes),
      'sha1' => sha1.convert(bytes),
      _ => sha256.convert(bytes),
    };
    return <String, dynamic>{
      'ok': true,
      'action': 'hash',
      'algorithm': algorithm,
      'byteCount': bytes.length,
      'hex': digest.toString(),
      'base64': base64.encode(digest.bytes),
    };
  }

  /// CRC 变体按**标准名**给全，避免「同名不同初值」的经典坑
  /// （calculate-mcp 的 crc16-ccitt 用 init 0x0000，其实是 XMODEM）。
  static const List<String> _crcVariants = <String>[
    'crc32',
    'crc16-ccitt',
    'crc16-xmodem',
    'crc16-modbus',
  ];

  static Map<String, dynamic> _crc(Map<String, dynamic> a) {
    if (a['value'] == null) {
      throw _CalcError('INVALID_ARGS', 'crc needs value (data to checksum)');
    }
    final variant = _choice(a['variant'], _crcVariants, 'crc32', 'variant');
    final format = _choice(a['format'], const <String>['text', 'hex'], 'text', 'format');
    final data = a['value'].toString();
    final bytes = format == 'hex' ? _hexToBytes(data) : utf8.encode(data);

    if (variant == 'crc32') {
      var crc = 0xffffffff;
      for (final byte in bytes) {
        crc ^= byte;
        for (var i = 0; i < 8; i++) {
          crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320 : crc >> 1;
        }
      }
      final value = (crc ^ 0xffffffff) & 0xffffffff;
      return <String, dynamic>{
        'ok': true,
        'action': 'crc',
        'variant': variant,
        'params': 'poly=0xedb88320 init=0xffffffff xorout=0xffffffff',
        'byteCount': bytes.length,
        'checksumHex': '0x${value.toRadixString(16).padLeft(8, '0')}',
        'checksumDec': value,
      };
    }

    final reflected = variant == 'crc16-modbus';
    final init = variant == 'crc16-xmodem' ? 0x0000 : 0xffff;
    var crc = init;
    if (reflected) {
      for (final byte in bytes) {
        crc ^= byte;
        for (var i = 0; i < 8; i++) {
          crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xa001 : crc >> 1;
        }
      }
    } else {
      for (final byte in bytes) {
        crc ^= byte << 8;
        for (var i = 0; i < 8; i++) {
          crc = (crc & 0x8000) != 0
              ? ((crc << 1) ^ 0x1021) & 0xffff
              : (crc << 1) & 0xffff;
        }
      }
    }
    crc &= 0xffff;
    return <String, dynamic>{
      'ok': true,
      'action': 'crc',
      'variant': variant,
      'params': reflected
          ? 'poly=0xa001 init=0x${init.toRadixString(16).padLeft(4, '0')} '
              'reflected=true'
          : 'poly=0x1021 init=0x${init.toRadixString(16).padLeft(4, '0')} '
              'reflected=false',
      'byteCount': bytes.length,
      'checksumHex': '0x${crc.toRadixString(16).padLeft(4, '0')}',
      'checksumDec': crc,
    };
  }

  static Map<String, dynamic> _mod(Map<String, dynamic> a) {
    final op = _choice(
      a['op'],
      const <String>['mod_pow', 'mod_inverse', 'gcd'],
      '',
      'op',
    );
    if (op.isEmpty) {
      throw _CalcError(
        'INVALID_ARGS',
        'mod needs op=mod_pow/mod_inverse/gcd',
      );
    }
    final base = _parseInt(a['a'], from: 'auto');
    if (op == 'gcd') {
      final other = _parseInt(a['b'], from: 'auto');
      final divisor = _gcd(base.abs(), other.abs());
      return <String, dynamic>{
        'ok': true,
        'action': 'mod',
        'op': op,
        'gcdDec': divisor.toString(),
        'gcdHex': '0x${divisor.toRadixString(16)}',
      };
    }
    final modulus = _parseInt(a['modulus'], from: 'auto');
    if (modulus <= BigInt.zero) {
      throw _CalcError('INVALID_ARGS', 'modulus must be positive');
    }
    if (op == 'mod_pow') {
      final exponent = _parseInt(a['b'], from: 'auto');
      if (exponent.isNegative) {
        throw _CalcError(
          'INVALID_ARGS',
          'mod_pow needs a non-negative exponent (use mod_inverse first for '
              'negative powers)',
        );
      }
      final result = _modPow(base, exponent, modulus);
      return <String, dynamic>{
        'ok': true,
        'action': 'mod',
        'op': op,
        'resultDec': result.toString(),
        'resultHex': '0x${result.toRadixString(16)}',
      };
    }
    final inverse = _modInverse(base, modulus);
    if (inverse == null) {
      throw _CalcError(
        'NO_MOD_INVERSE',
        'mod_inverse does not exist: $base and $modulus are not coprime',
      );
    }
    return <String, dynamic>{
      'ok': true,
      'action': 'mod',
      'op': op,
      'inverseDec': inverse.toString(),
      'inverseHex': '0x${inverse.toRadixString(16)}',
    };
  }

  static BigInt _modPow(BigInt base, BigInt exponent, BigInt modulus) {
    var result = BigInt.one;
    var factor = ((base % modulus) + modulus) % modulus;
    var power = exponent;
    while (power > BigInt.zero) {
      if ((power & BigInt.one) == BigInt.one) {
        result = (result * factor) % modulus;
      }
      factor = (factor * factor) % modulus;
      power >>= 1;
    }
    return result;
  }

  static BigInt _gcd(BigInt a, BigInt b) {
    var x = a;
    var y = b;
    while (y != BigInt.zero) {
      final temp = y;
      y = x % y;
      x = temp;
    }
    return x;
  }

  static BigInt? _modInverse(BigInt value, BigInt modulus) {
    var a = ((value % modulus) + modulus) % modulus;
    var m = modulus;
    var y = BigInt.zero;
    var x = BigInt.one;
    while (a > BigInt.one) {
      if (m == BigInt.zero) return null;
      final quotient = a ~/ m;
      final temp = m;
      m = a % m;
      a = temp;
      final tempY = y;
      y = x - quotient * y;
      x = tempY;
    }
    if (x.isNegative) x += modulus;
    return x;
  }

  // --------------------------------------------------------------- helpers

  static const List<String> _radixNames = <String>[
    'auto',
    'hex',
    'dec',
    'bin',
    'oct',
  ];

  /// 截到 width 位无符号（二补码语义，等价于 JS 的 BigInt.asUintN）。
  ///
  /// Dart 的 BigInt 位运算按无限二补码定义（与 Python 一致），`-42 & 0xff`
  /// 得到 214 而不是 0——负入参不需要额外特判。
  static BigInt _asUintN(int width, BigInt value) {
    return value & ((BigInt.one << width) - BigInt.one);
  }

  /// 截到 width 位有符号（二补码语义，等价于 JS 的 BigInt.asIntN）。
  static BigInt _asIntN(int width, BigInt value) {
    final unsigned = _asUintN(width, value);
    final signBit = BigInt.one << (width - 1);
    return unsigned >= signBit ? unsigned - (BigInt.one << width) : unsigned;
  }

  /// 解析整数：前缀（0x/0b/0o）优先，裸串按 [from] 指定的进制（auto=十进制）。
  static BigInt _parseInt(Object? raw, {String from = 'auto'}) {
    if (raw is BigInt) return raw;
    if (raw is int) return BigInt.from(raw);
    if (raw is double) {
      if (!raw.isFinite) {
        throw _CalcError('INVALID_NUMBER', 'numeric input $raw is not finite');
      }
      return BigInt.from(raw.truncate());
    }
    var text = raw?.toString().trim() ?? '';
    if (text.isEmpty) {
      throw _CalcError('INVALID_NUMBER', 'missing numeric input');
    }
    var negative = false;
    if (text.startsWith('-')) {
      negative = true;
      text = text.substring(1);
    } else if (text.startsWith('+')) {
      text = text.substring(1);
    }
    text = text.replaceAll(RegExp(r'[\s_]'), '');
    BigInt? value;
    if (text.startsWith('0x') || text.startsWith('0X')) {
      value = BigInt.tryParse(text.substring(2), radix: 16);
    } else if (text.startsWith('0b') || text.startsWith('0B')) {
      value = BigInt.tryParse(text.substring(2), radix: 2);
    } else if (text.startsWith('0o') || text.startsWith('0O')) {
      value = BigInt.tryParse(text.substring(2), radix: 8);
    } else {
      final radix = switch (from) {
        'hex' => 16,
        'bin' => 2,
        'oct' => 8,
        _ => 10,
      };
      value = BigInt.tryParse(text, radix: radix);
    }
    if (value == null) {
      final suffix = from == 'auto' ? '' : ' in base $from';
      throw _CalcError(
        'INVALID_NUMBER',
        '"$raw" is not a valid integer$suffix',
      );
    }
    return negative ? -value : value;
  }

  static int _bitWidth(Object? raw) {
    if (raw == null) return 32;
    final width = raw is num ? raw.toInt() : int.tryParse(raw.toString().trim());
    if (width == null || !const <int>[8, 16, 32, 64].contains(width)) {
      throw _CalcError(
        'INVALID_ARGS',
        'bitWidth must be 8, 16, 32 or 64 (got "$raw")',
      );
    }
    return width;
  }

  static int? _optionalPositiveInt(Object? raw, String name) {
    if (raw == null) return null;
    final value = raw is num ? raw.toInt() : int.tryParse(raw.toString().trim());
    if (value == null || value <= 0 || value > 64) {
      throw _CalcError(
        'INVALID_ARGS',
        '$name must be a positive integer up to 64 (got "$raw")',
      );
    }
    return value;
  }

  static String _choice(
    Object? raw,
    List<String> allowed,
    String fallback,
    String param,
  ) {
    final value = (raw ?? '').toString().trim().toLowerCase();
    if (value.isEmpty) return fallback;
    if (allowed.contains(value)) return value;
    throw _CalcError(
      'INVALID_ARGS',
      '$param must be one of ${allowed.join('/')} (got "$value")',
    );
  }

  static List<int> _hexToBytes(String input) {
    var clean = input
        .trim()
        .replaceFirst(RegExp(r'^0[xX]'), '')
        .replaceAll(RegExp(r'[\s_]'), '');
    if (clean.isEmpty) {
      throw _CalcError('INVALID_HEX', 'hex input is empty');
    }
    if (clean.length.isOdd) {
      throw _CalcError(
        'INVALID_HEX',
        'hex input has an odd number of digits (${clean.length}); byte streams '
            'need an even count',
      );
    }
    if (!RegExp(r'^[0-9a-fA-F]+$').hasMatch(clean)) {
      throw _CalcError(
        'INVALID_HEX',
        'hex input contains non-hex characters',
      );
    }
    final bytes = <int>[];
    for (var i = 0; i < clean.length; i += 2) {
      bytes.add(int.parse(clean.substring(i, i + 2), radix: 16));
    }
    return bytes;
  }

  static List<int> _tryBase64Decode(String padded, String original) {
    try {
      return base64.decode(padded);
    } on FormatException {
      throw _CalcError(
        'INVALID_BASE64',
        'input is not valid base64 (standard or url-safe)',
      );
    }
  }

  static String _utf8Of(List<int> bytes, String source) {
    try {
      return utf8.decode(bytes);
    } on FormatException {
      throw _CalcError(
        'INVALID_UTF8',
        'bytes are not valid UTF-8; retry with format=hex to get the raw bytes '
            'instead of text',
      );
    }
  }

  static String _hex(BigInt value, int digits) {
    return '0x${value.toRadixString(16).padLeft(digits, '0')}';
  }

  static String _hexOf(List<int> bytes) {
    return '0x${bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}';
  }

  static String _littleEndianHex(BigInt value, int widthBytes) {
    var remaining = value;
    final parts = <String>[];
    for (var i = 0; i < widthBytes; i++) {
      parts.add((remaining & BigInt.from(0xff)).toRadixString(16).padLeft(2, '0'));
      remaining >>= 8;
    }
    return '0x${parts.join()}';
  }
}

class _CalcError implements Exception {
  _CalcError(this.code, this.message);

  final String code;
  final String message;

  @override
  String toString() => '$_CalcError($code): $message';
}
