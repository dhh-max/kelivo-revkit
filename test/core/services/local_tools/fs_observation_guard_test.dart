import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/local_tools/fs_observation_guard.dart';

/// 文件 stale 守卫：只拦「读过且此后变了」，其余一律放行。
void main() {
  late Directory temp;
  late File file;

  setUp(() {
    temp = Directory.systemTemp.createTempSync('solab-fs-guard-');
    file = File('${temp.path}${Platform.pathSeparator}target.txt')
      ..writeAsStringSync('v1');
  });

  tearDown(() {
    if (temp.existsSync()) temp.deleteSync(recursive: true);
  });

  test('没观测过的路径不拦（unknown）', () {
    final guard = FsObservationGuard();
    expect(guard.check(file.path), FsObservationStatus.unknown);
  });

  test('观测后未改动 → unchanged，可放行', () async {
    final guard = FsObservationGuard();
    expect(guard.observe(file.path), isTrue);
    await Future<void>.delayed(const Duration(milliseconds: 5));
    expect(guard.check(file.path), FsObservationStatus.unchanged);
  });

  test('观测后内容变化（size 变）→ changed', () async {
    final guard = FsObservationGuard();
    guard.observe(file.path);
    await Future<void>.delayed(const Duration(milliseconds: 5));
    file.writeAsStringSync('v2-longer');
    expect(guard.check(file.path), FsObservationStatus.changed);
  });

  test('观测后被外部改写（同长度、mtime 前进）→ changed', () async {
    final guard = FsObservationGuard();
    guard.observe(file.path);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    file.writeAsStringSync('v2'); // 同长度
    expect(guard.check(file.path), FsObservationStatus.changed);
  });

  test('观测后文件消失 → changed（要求重新确认目标）', () async {
    final guard = FsObservationGuard();
    guard.observe(file.path);
    file.deleteSync();
    expect(guard.check(file.path), FsObservationStatus.changed);
  });

  test('重新观测后恢复 unchanged（写完刷新观测的路径）', () async {
    final guard = FsObservationGuard();
    guard.observe(file.path);
    await Future<void>.delayed(const Duration(milliseconds: 5));
    file.writeAsStringSync('v3');
    expect(guard.check(file.path), FsObservationStatus.changed);

    guard.observe(file.path);
    expect(guard.check(file.path), FsObservationStatus.unchanged);
  });

  test('forget / clear 让判定回到 unknown', () {
    final guard = FsObservationGuard();
    guard.observe(file.path);
    guard.forget(file.path);
    expect(guard.check(file.path), FsObservationStatus.unknown);

    guard.observe(file.path);
    expect(guard.observedCount, 1);
    guard.clear();
    expect(guard.observedCount, 0);
    expect(guard.check(file.path), FsObservationStatus.unknown);
  });

  test('不是本机真实文件（包内条目/不存在的路径）不参与守卫', () {
    final guard = FsObservationGuard();
    expect(guard.observe('${temp.path}/nope.txt'), isFalse);
    expect(guard.check('apk://entry/AndroidManifest.xml'),
        FsObservationStatus.unknown);
  });

  test('补救话术固定以「重新读取后重试」结尾（模型可照做）', () {
    expect(
      FsObservationGuard.staleMessage('a/b.txt'),
      contains('re-read the file, then retry'),
    );
    expect(
      FsObservationGuard.notObservedMessage('a/b.txt'),
      contains('read the file, then retry'),
    );
  });
}
