import 'dart:convert';
import 'dart:io';

import 'package:archive/archive_io.dart';
import 'package:flutter/foundation.dart';
import 'package:xml/xml.dart';
import 'package:syncfusion_flutter_pdf/pdf.dart';
import '../../../utils/sandbox_path_resolver.dart';
import '../../../utils/unicode_sanitizer.dart';

/// Data passed to the background isolate for document extraction.
class _ExtractorParams {
  final String path;
  final String mime;
  _ExtractorParams(this.path, this.mime);
}

class DocumentTextExtractor {
  /// Extracts text from a document file at [path] with [mime] type.
  /// This operation is performed in a background isolate to avoid blocking the UI.
  static Future<String> extract({
    required String path,
    required String mime,
  }) async {
    // Fix path before passing to isolate (isolate has no access to main UI context)
    final fixedPath = SandboxPathResolver.fix(path);

    // Offload the heavy work to a separate isolate using compute.
    // This unblocks the main UI thread.
    return compute(_extractTask, _ExtractorParams(fixedPath, mime));
  }

  /// The heavy extraction logic that runs in a background isolate.
  static String _extractTask(_ExtractorParams params) {
    final path = params.path;
    final mime = params.mime;

    try {
      if (mime == 'application/pdf') {
        try {
          final file = File(path);
          if (!file.existsSync()) return '[[File not found: $path]]';

          final bytes = file.readAsBytesSync();
          // Heavy synchronous PDF parsing happens here, in the sub-thread.
          final document = PdfDocument(inputBytes: bytes);
          final extractor = PdfTextExtractor(document);
          final extracted = extractor.extractText();
          final text = UnicodeSanitizer.sanitize(extracted);

          document.dispose();

          if (text.trim().isNotEmpty) return text;
          return '[PDF] Unable to extract text from file.';
        } catch (e) {
          return '[[Failed to read PDF: $e]]';
        }
      }

      if (mime == 'application/msword') {
        return '[[DOC format (.doc) not supported for text extraction]]';
      }

      if (mime ==
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
        return _extractDocxSync(path);
      }

      // Fallback: read as plain text
      final file = File(path);
      if (!file.existsSync()) return '[[File not found: $path]]';
      final bytes = file.readAsBytesSync();
      // Detect binary content (e.g. APK, exe, .so, images, archives) so we
      // don't send garbled text to the model. Instead we signal a binary file
      // whose path should be handed to downstream tools.
      if (_looksBinary(bytes)) {
        return '[[BinaryFile:$path]]';
      }
      return UnicodeSanitizer.sanitize(
        utf8.decode(bytes, allowMalformed: true),
      );
    } catch (e) {
      return '[[Failed to read file: $e]]';
    }
  }

  /// Synchronous DOCX extraction for isolate use.
  static String _extractDocxSync(String path) {
    try {
      final file = File(path);
      if (!file.existsSync()) return '[DOCX] file not found';

      final input = file.readAsBytesSync();
      final archive = ZipDecoder().decodeBytes(input);
      final docXml = archive.findFile('word/document.xml');
      if (docXml == null) return '[DOCX] document.xml not found';

      final xml = XmlDocument.parse(utf8.decode(docXml.content as List<int>));
      final buffer = StringBuffer();
      for (final p in xml.findAllElements('w:p')) {
        final texts = p.findAllElements('w:t');
        if (texts.isEmpty) {
          buffer.writeln();
          continue;
        }
        for (final t in texts) {
          buffer.write(t.innerText);
        }
        buffer.writeln();
      }
      return UnicodeSanitizer.sanitize(buffer.toString());
    } catch (e) {
      return '[[Failed to parse DOCX: $e]]';
    }
  }

  /// Heuristic: check if a byte buffer looks like binary content
  /// (not valid UTF-8 text). Returns true if the file is likely binary.
  static bool _looksBinary(List<int> bytes) {
    // Null bytes in the first 8KB strongly indicate binary.
    final checkLen = bytes.length < 8192 ? bytes.length : 8192;
    int nullCount = 0;
    int controlCount = 0;
    int validTextBytes = 0;
    for (int i = 0; i < checkLen; i++) {
      final b = bytes[i];
      if (b == 0) {
        nullCount++;
      } else if (b < 0x09) {
        controlCount++;
      } else if (b >= 0x20 && b <= 0x7E) {
        validTextBytes++;
      } else if (b >= 0xC0 && b <= 0xDF) {
        // Could be start of 2-byte UTF-8 sequence
        if (i + 1 < checkLen && (bytes[i + 1] & 0xC0) == 0x80) {
          validTextBytes++;
          i++; // skip continuation byte
        }
      } else if (b >= 0xE0 && b <= 0xEF) {
        // Could be start of 3-byte UTF-8 sequence
        if (i + 2 < checkLen &&
            (bytes[i + 1] & 0xC0) == 0x80 &&
            (bytes[i + 2] & 0xC0) == 0x80) {
          validTextBytes += 2;
          i += 2; // skip continuation bytes
        }
      }
    }
    // If there are null bytes, or control chars dominate, it's binary.
    if (nullCount > 0) return true;
    if (checkLen == 0) return false;
    final textRatio = validTextBytes / checkLen;
    // Less than 50% printable text -> binary
    if (textRatio < 0.5) return true;
    // High control char count (excluding valid whitespace: 0x09=\t, 0x0A=\n, 0x0D=\r)
    int badControl = 0;
    for (int i = 0; i < checkLen; i++) {
      final b = bytes[i];
      if (b > 0 && b < 0x09) badControl++;
      if (b > 0x0D && b < 0x20) badControl++;
    }
    if (badControl > checkLen * 0.3) return true;
    return false;
  }
}
