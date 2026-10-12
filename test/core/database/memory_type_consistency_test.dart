import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:Kelivo/core/models/memory_entry.dart';

/// 生成式一致性守卫：MemoryType 枚举的每一处字符串投影必须同步。
///
/// 背景：schema 9 给 DB CHECK 加了 apk_failure，但 business_settings_router
/// 的运行时白名单漏加——apk_failure 记忆一落库，任何 provider load 都抛
/// FormatException('memory_entries_v1')，内置 fetch 与全部外部 MCP 连不上
/// （2026-09-03/04 实测）。本测试直接读源码提取两侧字面量集合与枚举对表，
/// 未来任何一处新增/漏加类型直接红。
/// （memory_ui 的 switch 由 Dart 穷举检查在编译期兜底，不在本守卫范围。）
void main() {
  final expected = {
    for (final t in MemoryType.values) MemoryEntry.typeToString(t),
  };

  String repoFile(String rel) =>
      File('${Directory.current.path}/$rel').readAsStringSync();

  /// 从 app_database.dart 提取 `type.isIn(const [...])` 里的字面量。
  ///
  /// 行扫描而非跨行正则：`check(` 与白名单之间可能夹注释
  /// （drift 生成物里的 `// ignore: recursive_getters`），
  /// 任何跨行正则都容易被后续格式化改动打断。
  Set<String> dbCheckTypes(String source) {
    final lines = source.split('\n');
    final start = lines.indexWhere(
      (l) => l.contains('TextColumn get type => text().check('),
    );
    if (start < 0) return <String>{};
    final out = <String>{};
    var seenIsIn = false;
    for (var i = start; i < lines.length; i++) {
      final line = lines[i];
      if (!seenIsIn) {
        if (!line.contains('type.isIn(')) continue;
        seenIsIn = true;
      }
      out.addAll(
        RegExp(r"'([a-z_]+)'").allMatches(line).map((m) => m.group(1)!),
      );
      if (line.contains('])')) break;
    }
    return out;
  }

  /// 从 business_settings_router.dart 的 memoryEntry 分支提取
  /// `type != 'xxx'` 白名单。
  Set<String> routerTypes(String source) {
    final lines = source.split('\n');
    final start = lines.indexWhere(
      (l) => l.contains('case BusinessEntityKind.memoryEntry:'),
    );
    if (start < 0) return <String>{};
    final out = <String>{};
    for (var i = start + 1; i < lines.length; i++) {
      final line = lines[i];
      // 缩进回到分支同级即视为分支结束。
      if (RegExp(r'^\s{0,8}case BusinessEntityKind\.').hasMatch(line)) break;
      out.addAll(
        RegExp(r"type != '([a-z_]+)'").allMatches(line).map(
          (m) => m.group(1)!,
        ),
      );
    }
    return out;
  }

  test('DB CHECK whitelist matches MemoryType enum', () {
    final source = repoFile('lib/core/database/app_database.dart');
    // 行扫描而非正则：`check(` 与 `type.isIn(const [` 之间可能夹注释
    // （drift 生成物里的 `// ignore: recursive_getters`），任何「跨行正则」
    // 都容易被后续格式化改动打断。这里定位到那一行后，取后续直到 `])` 的
    // 所有单引号字面量。
    final lines = source.split('\n');
    final start = lines.indexWhere(
      (l) => l.contains('TextColumn get type => text().check('),
    );
    expect(start >= 0, isTrue, reason: 'app_database.dart 中未找到 type CHECK');
    final literals = <String>[];
    var seenIsIn = false;
    for (var i = start; i < lines.length; i++) {
      final line = lines[i];
      if (!seenIsIn) {
        if (!line.contains('type.isIn(')) continue;
        seenIsIn = true;
      }
      literals.addAll(
        RegExp(r"'([a-z_]+)'").allMatches(line).map((m) => m.group(1)!),
      );
      if (line.contains('])')) break;
    }
    final dbTypes = literals.toSet();
    expect(seenIsIn, isTrue, reason: '未找到 type.isIn 白名单');

    expect(
      dbTypes.difference(expected),
      isEmpty,
      reason: 'DB CHECK 有枚举之外的类型（MemoryType 未同步）',
    );
    expect(
      expected.difference(dbTypes),
      isEmpty,
      reason: 'MemoryType 新值未加进 DB CHECK（会触发 schema 迁移遗漏）',
    );
  });

  test('settings-router runtime whitelist matches MemoryType enum', () {
    final source = repoFile(
      'lib/core/database/business_settings_router.dart',
    );
    // 行扫描：memoryEntry 分支里先做通用字段校验、再列 type 白名单，
    // 中间代码会变动，正则容易断。这里定位分支起始行，收集其后直到
    // 该分支结束的所有 `type != 'xxx'` 字面量。
    final lines = source.split('\n');
    final branchStart = lines.indexWhere(
      (l) => l.contains('case BusinessEntityKind.memoryEntry:'),
    );
    expect(branchStart >= 0, isTrue, reason: 'router 中未找到 memoryEntry 分支');
    final routerTypes = <String>{};
    for (var i = branchStart + 1; i < lines.length; i++) {
      final line = lines[i];
      // 缩进回到分支同级即视为分支结束。
      if (RegExp(r'^\s{0,8}case BusinessEntityKind\.').hasMatch(line)) break;
      routerTypes.addAll(
        RegExp(r"type != '([a-z_]+)'").allMatches(line).map(
          (m) => m.group(1)!,
        ),
      );
    }

    expect(
      expected.difference(routerTypes),
      isEmpty,
      reason:
          'MemoryType 新值未加进 settings-router 白名单——'
          '落库后 provider load 全挂（apk_failure 事故复刻）',
    );
  });

  test('DB CHECK and router whitelist agree with each other', () {
    final dbTypes = dbCheckTypes(
      repoFile('lib/core/database/app_database.dart'),
    );
    // 局部变量不能与顶层 helper 同名，否则这里会解析成对自己（未初始化）的引用。
    final routerWhitelist = routerTypes(
      repoFile('lib/core/database/business_settings_router.dart'),
    );
    expect(dbTypes, isNotEmpty, reason: '未能从 app_database.dart 提取 DB CHECK 白名单');
    expect(
      routerWhitelist,
      isNotEmpty,
      reason: '未能从 router 提取 type 白名单',
    );
    expect(dbTypes, routerWhitelist, reason: 'DB CHECK 与 router 白名单不一致');
  });
}
