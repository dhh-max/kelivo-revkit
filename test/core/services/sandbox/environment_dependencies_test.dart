import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:Kelivo/core/models/environment_state.dart';
import 'package:Kelivo/core/providers/environment_provider.dart';
import 'package:Kelivo/core/services/sandbox/environment_dependencies.dart';
import 'dependency_test_runtime.dart';
import '../../../support/business_test_harness.dart';
import '../../../features/workspace/environment/environment_test_fakes.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  // 环境预设目录守护（2026-10-02 评估后定）：每一项都必须是「能装上、能探测到」
  // 的真依赖，且只留评估通过的组——不照着别的软件截图堆条目。
  test('每个环境预设都有安装包与探测命令（两种发行版都是）', () {
    for (final dependency in EnvironmentDependency.values) {
      for (final alpine in const <bool>[true, false]) {
        expect(
          dependency.packages(alpine: alpine).trim(),
          isNotEmpty,
          reason: '${dependency.name} 缺少安装包（alpine=$alpine）',
        );
        expect(
          dependency.probe(alpine: alpine).trim(),
          isNotEmpty,
          reason: '${dependency.name} 缺少探测命令（alpine=$alpine）',
        );
      }
    }
  });

  test('评估通过的目录：通用小件 + 两个可选大件，不含媒体/编辑器/重复工具链', () {
    final names = EnvironmentDependency.values.map((d) => d.name).toSet();
    expect(names, containsAll(<String>['json', 'search', 'binutils']));
    expect(names, containsAll(<String>['build', 'java']));
    expect(names, isNot(contains('llvm')));
    expect(names, isNot(contains('ffmpeg')));
    expect(names, isNot(contains('vim')));
    expect(
      EnvironmentDependency.binutils.packages(alpine: false),
      isNot(contains('llvm')),
      reason: 'binutils 组不夹带 llvm（与自研 SO 管线重复）',
    );
  });

  late EnvironmentProvider env;
  late DependencyTestRuntime runtime;
  late FakeMirrorService mirrors;
  late EnvironmentDependencies service;
  Future<void> setup({bool alpine = false}) async {
    env = EnvironmentProvider(preferences: createBusinessTestPreferences());
    await env.loaded;
    await env.setState(
      EnvironmentState(
        phase: EnvironmentPhase.ready,
        distro: alpine ? 'alpine' : 'ubuntu',
        arch: 'arm64',
      ),
    );
    runtime = DependencyTestRuntime();
    mirrors = FakeMirrorService(env);
    service = EnvironmentDependencies(
      runtime: runtime,
      env: env,
      alpine: alpine,
      mirrors: mirrors,
    );
    addTearDown(service.dispose);
    addTearDown(env.dispose);
  }

  for (final alpine in [false, true]) {
    test(
      '${alpine ? 'apk' : 'apt'} installs and verifies each preset in the guest',
      () async {
        await setup(alpine: alpine);
        await service.refresh();
        expect(
          service.status(EnvironmentDependency.python),
          DependencyStatus.missing,
        );
        for (final dependency in EnvironmentDependency.values) {
          await service.install(dependency);
          expect(service.failure, isNull);
          expect(service.status(dependency), DependencyStatus.installed);
          expect(service.lastInstalled, dependency);
        }
        expect(runtime.requests.every((r) => r.cwd == '/'), isTrue);
        expect(
          runtime.requests
              .where(
                (r) =>
                    r.command.contains('install -y') ||
                    r.command.contains('apk --wait 60 add'),
              )
              .every((r) => r.timeout == const Duration(minutes: 30)),
          isTrue,
        );
      },
    );
  }
  test(
    'incomplete status output stays unknown instead of reporting missing',
    () async {
      await setup();
      runtime.incompleteProbe = true;
      await service.refresh();
      expect(service.failure, DependencyFailure.check);
      expect(
        service.status(EnvironmentDependency.python),
        DependencyStatus.unknown,
      );
    },
  );
  test(
    'failed install has log, remains retryable, then verifies success',
    () async {
      await setup();
      runtime.failInstall = true;
      await service.install(EnvironmentDependency.python);
      expect(service.failure, DependencyFailure.install);
      expect(
        service.status(EnvironmentDependency.python),
        DependencyStatus.unknown,
      );
      expect(service.log, contains('Installing packages'));
      runtime.failInstall = false;
      await service.install(EnvironmentDependency.python);
      expect(service.failure, isNull);
      expect(
        service.status(EnvironmentDependency.python),
        DependencyStatus.installed,
      );
    },
  );
  test(
    'serializes installs, cancels the active guest and never claims success',
    () async {
      await setup();
      runtime.installGate = Completer<void>();
      final installing = service.install(EnvironmentDependency.node);
      await Future<void>.delayed(Duration.zero);
      await service.install(EnvironmentDependency.git);
      expect(runtime.requests, hasLength(1));
      expect(service.busy, isTrue);
      await service.cancel();
      await installing;
      expect(runtime.cancelledId, runtime.requests.first.runId);
      expect(service.failure, DependencyFailure.cancelled);
      expect(service.lastInstalled, isNull);
      expect(service.busy, isFalse);
    },
  );
  test(
    'reapplies saved official and mirror sources before installing',
    () async {
      await setup();
      await env.setMirror(
        MirrorCategory.apt,
        const MirrorSelection(useMirror: false, manual: true),
      );
      await env.setMirror(
        MirrorCategory.pip,
        const MirrorSelection(
          useMirror: true,
          mirrorId: 'pip.tuna',
          manual: true,
        ),
      );
      await service.install(EnvironmentDependency.python);
      expect(mirrors.applied.map((v) => v.$1), [
        MirrorCategory.apt,
        MirrorCategory.pip,
      ]);
      expect(mirrors.applied.first.$2.host, 'ports.ubuntu.com');
      expect(mirrors.applied.last.$2.host, 'pypi.tuna.tsinghua.edu.cn');
    },
  );
  test(
    'reset clears detected packages and blocks installation until ready',
    () async {
      await setup();
      await service.install(EnvironmentDependency.git);
      await env.setState(const EnvironmentState());
      final count = runtime.requests.length;
      await service.install(EnvironmentDependency.node);
      expect(runtime.requests, hasLength(count));
      expect(
        service.status(EnvironmentDependency.git),
        DependencyStatus.unknown,
      );
    },
  );

  // 一键安装（用户 2026-10-03）：「依赖那么多，搞一个一键安装，每个安装前自动
  // 检测最快的」。入口的输入就是这里——只列未装项，装完自动排除。
  group('一键安装的输入（dependenciesToInstall）', () {
    test('探针全缺 → 全部列出；装一个 → 立刻从待装列表消失', () async {
      await setup();
      await service.refresh();
      final before = service.dependenciesToInstall();
      expect(before.length, EnvironmentDependency.values.length);
      expect(before, containsAll(EnvironmentDependency.values));

      await service.install(EnvironmentDependency.git);
      expect(
        service.status(EnvironmentDependency.git),
        DependencyStatus.installed,
      );
      final after = service.dependenciesToInstall();
      expect(after, isNot(contains(EnvironmentDependency.git)));
      expect(after.length, before.length - 1);
    });

    test('沙盒未就绪 → 空列表（入口置灰，不出现点了没反应）', () async {
      await setup();
      await service.refresh();
      expect(service.dependenciesToInstall(), isNotEmpty);
      await env.setState(const EnvironmentState());
      expect(service.dependenciesToInstall(), isEmpty);
    });

    test('探测不完整（unknown）仍按待装处理，不误判为已装', () async {
      await setup();
      runtime.incompleteProbe = true;
      await service.refresh();
      expect(service.failure, DependencyFailure.check);
      expect(
        service.status(EnvironmentDependency.python),
        DependencyStatus.unknown,
      );
      expect(
        service.dependenciesToInstall(),
        contains(EnvironmentDependency.python),
      );
    });
  });
}
