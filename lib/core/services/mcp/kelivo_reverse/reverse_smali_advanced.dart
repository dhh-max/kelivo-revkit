part of kelivo_reverse_server;

// =========================================================================
// Smali 高级修补器 — 指令级修补、方法注入、NOP填充
// 移植自 Python apk_reverse_engine/patching/smali_patcher.py
// =========================================================================

class _SmaliPatcher {
  static String findAndReplace(String text, String old, String newStr) {
    return text.replaceAll(old, newStr);
  }

  static String insertMethod(
    String smaliCode,
    String methodSmali, {
    String? beforeLine,
  }) {
    if (beforeLine != null) {
      final lines = smaliCode.split('\n');
      for (var i = 0; i < lines.length; i++) {
        if (lines[i].contains(beforeLine)) {
          lines.insert(i, methodSmali);
          return lines.join('\n');
        }
      }
    }
    return '$smaliCode\n$methodSmali';
  }

  static String removeMethod(String smaliCode, String methodName) {
    final pattern = RegExp(
      r'\.method\s+.*?' + RegExp.escape(methodName) + r'[^\n]*\n.*?\.end\s+method',
      multiLine: true,
      dotAll: true,
    );
    return smaliCode.replaceAll(pattern, '');
  }

  static String addLogInject(
    String smaliCode,
    String methodName, {
    String tag = 'DEBUG',
    String msg = 'injected',
  }) {
    final pattern = RegExp(
      r'(\.method\s+.*?' + RegExp.escape(methodName) + r'[^\n]*\n)',
    );
    final inject =
        '    const-string v0, "$tag"\n'
        '    const-string v1, "$msg"\n'
        '    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I\n';
    return smaliCode.replaceAllMapped(pattern, (m) => '${m.group(1)}$inject');
  }

  static String addReturnInject(
    String smaliCode,
    String methodName, {
    String returnValue = '0',
  }) {
    final pattern = RegExp(
      r'(\.method\s+.*?' + RegExp.escape(methodName) + r'[^\n]*\n)',
    );
    final inject = '    const/4 v0, $returnValue\n    return v0\n';
    return smaliCode.replaceAllMapped(pattern, (m) => '${m.group(1)}$inject');
  }

  static String patchIfCondition(
    String smaliCode,
    String oldCond,
    String newCond,
  ) {
    return smaliCode.replaceAll(oldCond, newCond);
  }

  static String bypassSignatureCheck(String smaliCode) {
    final patterns = <List<String>>[
      [
        r'invoke-virtual\{.*?\},\s*Landroid/content/pm/PackageManager;->checkSignatures\([^)]*\)I',
        'const/4 v0, 0x0\n    return v0',
      ],
      [
        r'invoke-virtual\{.*?\},\s*Landroid/content/pm/PackageManager;->getPackageInfo\([^)]*\)Landroid/content/pm/PackageInfo;',
        'const/4 v0, 0x0\n    return v0',
      ],
    ];
    var result = smaliCode;
    for (final p in patterns) {
      result = result.replaceAll(RegExp(p[0]), p[1]);
    }
    return result;
  }

  static String nopOutMethod(String smaliCode, String methodName) {
    final pattern = RegExp(
      r'(\.method\s+.*?' +
          RegExp.escape(methodName) +
          r'[^\n]*\n)(.*?)(\.end\s+method)',
      dotAll: true,
    );
    return smaliCode.replaceAllMapped(pattern, (m) {
      final body = m.group(2)!;
      final lines = body.trim().split('\n');
      final nopLines = <String>[];
      for (final line in lines) {
        final stripped = line.trim();
        if (stripped.isNotEmpty &&
            !stripped.startsWith('.') &&
            !stripped.startsWith('#')) {
          nopLines.add('    nop');
        } else if (stripped.isNotEmpty) {
          nopLines.add(line);
        }
      }
      return '${m.group(1)}${nopLines.join('\n')}\n${m.group(3)}';
    });
  }

  static String replaceConstValue(
    String smaliCode,
    String oldValue,
    String newValue,
  ) {
    final patterns = <List<String>>[
      [r'const/4\s+v\d+,\s+' + oldValue, 'const/4 v0, $newValue'],
      [r'const/16\s+v\d+,\s+' + oldValue, 'const/16 v0, $newValue'],
      [r'const\s+v\d+,\s+' + oldValue, 'const v0, $newValue'],
      [
        r'const-string\s+v\d+,\s*"' + RegExp.escape(oldValue) + '"',
        'const-string v0, "$newValue"',
      ],
    ];
    var result = smaliCode;
    for (final p in patterns) {
      result = result.replaceAll(RegExp(p[0]), p[1]);
    }
    return result;
  }

  static String nopOutInvoke(
    String smaliCode, {
    String? targetClass,
    String? targetMethod,
  }) {
    final lines = smaliCode.split('\n');
    final result = <String>[];
    final invokeRe = RegExp(
        r'invoke-\w+\s+\{[^}]*\},\s*([^;]+);->([^(]+)');
    for (final line in lines) {
      final stripped = line.trim();
      if (stripped.contains('invoke-')) {
        final match = invokeRe.firstMatch(stripped);
        if (match != null) {
          final cls = match.group(1)!;
          final method = match.group(2)!;
          if (targetClass != null && !cls.contains(targetClass)) {
            result.add(line);
            continue;
          }
          if (targetMethod != null && !method.contains(targetMethod)) {
            result.add(line);
            continue;
          }
          result.add('    nop');
          continue;
        }
      }
      result.add(line);
    }
    return result.join('\n');
  }

  static String generateMethodStub(
    String returnType,
    String methodName,
    List<String> params, {
    String access = 'public',
  }) {
    final paramRegs = <String>[];
    var regCount = 1; // v0 for return
    for (var i = 0; i < params.length; i++) {
      paramRegs.add('v${i + 1}');
      regCount = i + 2;
    }
    String body;
    if (returnType == 'V') {
      body = '    return-void';
    } else if (returnType == 'Z' ||
        returnType == 'I' ||
        returnType == 'S' ||
        returnType == 'B' ||
        returnType == 'C') {
      body = '    const/4 v0, 0x0\n    return v0';
    } else if (returnType == 'J') {
      body = '    const-wide/16 v0, 0x0\n    return-wide v0';
    } else if (returnType == 'F') {
      body = '    const/4 v0, 0x0\n    return v0';
    } else if (returnType == 'D') {
      body = '    const-wide/16 v0, 0x0\n    return-wide v0';
    } else if (returnType.startsWith('L') ||
        returnType.startsWith('[')) {
      body = '    const/4 v0, 0x0\n    return-object v0';
    } else {
      body = '    return-void';
    }
    final paramStr = params.join();
    return '.method $access $methodName($paramStr)$returnType\n'
        '    .registers $regCount\n'
        '$body\n'
        '.end method';
  }

  static String enableDebug(String smaliCode) {
    var result = smaliCode;
    result = result.replaceAll(RegExp(r'\s*\.line\s+\d+\n'), '\n');
    result = result.replaceAll(
        RegExp(r'\s*\.source\s+"[^"]*"\n'), '\n');
    result = result.replaceAll(RegExp(r'\s*\.prologue\n'), '\n');
    return result;
  }

  static String patchGotoDirection(
    String smaliCode,
    String oldTarget,
    String newTarget,
  ) {
    return smaliCode.replaceAll(':$oldTarget', ':$newTarget');
  }

  static List<Map<String, String>> findMethodsByString(
    String smaliCode,
    String searchString,
  ) {
    final results = <Map<String, String>>[];
    String? currentMethod;
    final currentBody = <String>[];
    for (final line in smaliCode.split('\n')) {
      if (line.trim().startsWith('.method')) {
        if (currentMethod != null && currentBody.isNotEmpty) {
          final bodyText = currentBody.join('\n');
          if (bodyText.contains(searchString)) {
            results.add({
              'method': currentMethod,
              'body': bodyText.length > 200
                  ? bodyText.substring(0, 200)
                  : bodyText,
            });
          }
        }
        currentMethod = line.trim();
        currentBody.clear();
      } else if (line.trim().startsWith('.end method')) {
        if (currentMethod != null && currentBody.isNotEmpty) {
          final bodyText = currentBody.join('\n');
          if (bodyText.contains(searchString)) {
            results.add({
              'method': currentMethod,
              'body': bodyText.length > 200
                  ? bodyText.substring(0, 200)
                  : bodyText,
            });
          }
        }
        currentMethod = null;
        currentBody.clear();
      } else if (currentMethod != null) {
        currentBody.add(line);
      }
    }
    return results;
  }
}
}
