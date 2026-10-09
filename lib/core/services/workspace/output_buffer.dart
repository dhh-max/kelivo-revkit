import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;

import '../../../utils/utf16_safe_cut.dart';

/// Accumulates a stream while retaining at most [maxBytes] (head + tail).
class BoundedStreamBuffer {
  BoundedStreamBuffer({this.maxBytes = 128 * 1024}) : _half = maxBytes ~/ 2;

  final int maxBytes;
  final int _half;
  final BytesBuilder _head = BytesBuilder(copy: true);
  Uint8List? _tail;
  int _tailNext = 0;
  bool _truncated = false;
  int _totalBytes = 0;
  String? _cachedText;
  String? _headText;

  int get totalBytes => _totalBytes;

  bool get truncated => _truncated;

  void add(List<int> bytes) {
    if (bytes.isEmpty) return;
    _totalBytes += bytes.length;
    _cachedText = null;
    if (!_truncated) {
      if (_head.length + bytes.length <= maxBytes) {
        _head.add(bytes);
        return;
      }
      final previous = _head.takeBytes();
      final headLength = previous.length < _half ? previous.length : _half;
      _head.add(Uint8List.sublistView(previous, 0, headLength));
      if (headLength < _half) {
        _head.add(bytes.sublist(0, _half - headLength));
      }
      _tail = Uint8List(_half);
      _truncated = true;
      _appendTail(previous);
      _appendTail(bytes);
      return;
    }
    _appendTail(bytes);
  }

  void _appendTail(List<int> bytes) {
    if (_half == 0 || bytes.isEmpty) return;
    final tail = _tail!;
    if (bytes.length >= _half) {
      tail.setRange(0, _half, bytes, bytes.length - _half);
      _tailNext = 0;
      return;
    }
    final first = bytes.length < _half - _tailNext
        ? bytes.length
        : _half - _tailNext;
    tail.setRange(_tailNext, _tailNext + first, bytes);
    if (first < bytes.length) {
      tail.setRange(0, bytes.length - first, bytes, first);
    }
    _tailNext = (_tailNext + bytes.length) % _half;
  }

  Uint8List _tailBytes() {
    final tail = _tail!;
    if (_tailNext == 0) return tail;
    return Uint8List(_half)
      ..setRange(0, _half - _tailNext, tail, _tailNext)
      ..setRange(_half - _tailNext, _half, tail);
  }

  /// Retained bytes (head, or head + tail when truncated). At most [maxBytes].
  Uint8List get bytes {
    if (!_truncated) return Uint8List.fromList(_head.toBytes());
    final head = _head.toBytes();
    final out = Uint8List(head.length + _half);
    out.setAll(0, head);
    out.setAll(head.length, _tailBytes());
    return out;
  }

  /// UTF-8 decode of [bytes] that never starts/ends mid-sequence.
  String get text => _cachedText ??= _decodeText();

  String _decodeText() {
    if (!_truncated) {
      return _decodeUtf8(
        _head.toBytes(),
        dropLeading: false,
        dropTrailing: false,
      );
    }
    final head = _headText ??= _decodeUtf8(
      _head.toBytes(),
      dropLeading: false,
      dropTrailing: true,
    );
    final tail = _decodeUtf8(
      _tailBytes(),
      dropLeading: true,
      dropTrailing: false,
    );
    return '$head$tail';
  }
}

/// Cuts [s] to at most [maxChars] UTF-16 code units without splitting a
/// surrogate pair. [keepTail] keeps the end instead of the start.
String utf16SafeCut(String s, int maxChars, {bool keepTail = false}) {
  if (maxChars <= 0) return '';
  if (s.length <= maxChars) return s;
  if (keepTail) {
    return s.substring(utf16SafeTailStart(s, s.length - maxChars));
  }
  return truncateHeadUtf16Safe(s, maxChars);
}

class CapturedOutput {
  const CapturedOutput({
    required this.stdout,
    required this.stderr,
    required this.stdoutTruncated,
    required this.stderrTruncated,
  });

  final String stdout;
  final String stderr;
  final bool stdoutTruncated;
  final bool stderrTruncated;
}

class ToolOutputOffload {
  const ToolOutputOffload({
    required this.modelText,
    this.offloadHostPath,
    this.fileBytes = 0,
    this.fileTruncated = false,
  });

  /// JSON object for the model, plus a hint line when output was offloaded.
  final String modelText;
  final String? offloadHostPath;

  /// 落盘件的真实字节数（0 = 没落盘）。调用方把「文件里到底有多少」如实回报。
  final int fileBytes;

  /// 落盘件本身是否被上限截断（截断处在文件内**显式标注**缺失字节数）。
  final bool fileTruncated;
}

class ToolOutputOffloader {
  /// 单条命令落盘件上限：超过则在**文件内显式标注**省略了多少字节。
  static const int maxFileBytes = 32 * 1024 * 1024;

  /// 当 stdout+stderr 超过 [inlineLimit] UTF-8 字节时，把**完整输出**写到
  /// `outputs/<toolCallId>.txt`，只给模型 head+tail 预览 + `read_file`/`grep` 提示。
  ///
  /// 用户实测报告 2-3：过去这里的「full output」其实来自**有界缓冲**的 head+tail
  /// 快照（数据行 1..1111 后直接跳到 18927..20000），文件内还没有任何截断标记——
  /// 调用方以为能取回全量，中段却永久丢失。现在改为：跑命令时**边跑边 tee** 两个
  /// 临时文件（stdout/stderr 各一个），需要落盘时按顺序拼成完整文件；超上限时
  /// 在文件内写明 `[... omitted N bytes ...]`。
  static Future<ToolOutputOffload> maybeOffload({
    required String toolCallId,
    required String stdout,
    required String stderr,
    required Directory outputsDir,
    int inlineLimit = 32 * 1024,
    int previewChars = 4 * 1024,
    /// tee 出来的**全量** stdout/stderr 临时文件（调用方在跑命令时写入）。
    File? stdoutPartFile,
    File? stderrPartFile,
    /// 落盘件字节上限（默认 [maxFileBytes]；测试用小值验证文件内截断标注）。
    int fileCapBytes = maxFileBytes,
  }) async {
    final partBytes = <File, int>{};
    var totalBytes = utf8.encode(stdout).length + utf8.encode(stderr).length;
    if (stdoutPartFile != null || stderrPartFile != null) {
      var teeTotal = 0;
      for (final file in <File?>[stdoutPartFile, stderrPartFile]) {
        if (file == null) continue;
        final exists = await file.exists();
        final length = exists ? await file.length() : 0;
        partBytes[file] = length;
        teeTotal += length;
      }
      // tee 文件是权威的全量（有界缓冲可能已经丢中段）。
      if (teeTotal > 0) totalBytes = teeTotal;
    }

    if (totalBytes <= inlineLimit) {
      // 小输出：内联就够了，临时件删掉不留垃圾。
      for (final file in partBytes.keys) {
        try {
          await file.delete();
        } catch (_) {}
      }
      return ToolOutputOffload(
        modelText: jsonEncode(<String, Object?>{
          'stdout': stdout,
          'stderr': stderr,
        }),
      );
    }

    await outputsDir.create(recursive: true);
    final file = File(p.join(outputsDir.path, '$toolCallId.txt'));
    final sink = file.openWrite();
    var written = 0;
    var truncated = false;

    Future<void> writeSection(String header, File? part, String fallback) async {
      sink.write(header);
      written += header.length;
      final partLength = part == null ? 0 : (partBytes[part] ?? 0);
      if (part != null && partLength > 0) {
        // 逐块拷贝：全量落盘也不把整段读进内存。
        await for (final chunk in part.openRead()) {
          final remaining = fileCapBytes - written;
          if (remaining <= 0) {
            truncated = true;
            break;
          }
          if (chunk.length <= remaining) {
            sink.add(chunk);
            written += chunk.length;
          } else {
            sink.add(chunk.sublist(0, remaining));
            written += remaining;
            truncated = true;
            break;
          }
        }
        return;
      }
      final bytes = utf8.encode(fallback);
      sink.add(bytes);
      written += bytes.length;
    }

    try {
      await writeSection('=== stdout ===\n', stdoutPartFile, stdout);
      if (stdout.isNotEmpty && !stdout.endsWith('\n')) sink.write('\n');
      if (truncated) {
        final marker = '\n[... output truncated at $fileCapBytes bytes; '
            'remaining bytes omitted ...]\n';
        sink.write(marker);
      }
      await writeSection('=== stderr ===\n', stderrPartFile, stderr);
    } finally {
      await sink.flush();
      await sink.close();
      for (final part in partBytes.keys) {
        try {
          await part.delete();
        } catch (_) {}
      }
    }

    final modelPath = 'outputs/$toolCallId.txt';
    final json = jsonEncode(<String, Object?>{
      'stdout': _preview(stdout, previewChars),
      'stderr': _preview(stderr, previewChars),
      'truncated': true,
      'output_file': modelPath,
      'output_file_bytes': written,
      'output_file_truncated': truncated,
    });
    return ToolOutputOffload(
      modelText:
          '$json\nFull output written to $modelPath'
          '${truncated ? ' (itself capped; see the in-file marker)' : ''}; '
          'use read_file or grep to inspect it.',
      offloadHostPath: file.path,
      fileBytes: written,
      fileTruncated: truncated,
    );
  }

  static String _preview(String value, int maxChars) {
    if (value.length <= maxChars) return value;
    return truncateHeadTailUtf16Safe(
      value,
      maxChars,
      marker: '\n...[truncated]...\n',
    );
  }
}

String _decodeUtf8(
  List<int> raw, {
  required bool dropLeading,
  required bool dropTrailing,
}) {
  var start = 0;
  var end = raw.length;
  if (dropLeading) {
    while (start < end && (raw[start] & 0xC0) == 0x80) {
      start++;
    }
  }
  if (dropTrailing) {
    end = _utf8CompleteEnd(raw, start, end);
  }
  if (start >= end) return '';
  return utf8.decode(raw.sublist(start, end), allowMalformed: true);
}

int _utf8CompleteEnd(List<int> bytes, int start, int end) {
  if (end <= start) return end;
  var i = end - 1;
  if (bytes[i] < 0x80) return end;
  var continuations = 0;
  while (i >= start && (bytes[i] & 0xC0) == 0x80) {
    continuations++;
    i--;
  }
  if (i < start) return start;
  final expected = _utf8ExpectedContinuations(bytes[i]);
  if (expected < 0 || continuations != expected) return i;
  return end;
}

int _utf8ExpectedContinuations(int lead) {
  if (lead < 0x80) return 0;
  if (lead >= 0xC2 && lead <= 0xDF) return 1;
  if (lead >= 0xE0 && lead <= 0xEF) return 2;
  if (lead >= 0xF0 && lead <= 0xF4) return 3;
  return -1;
}
