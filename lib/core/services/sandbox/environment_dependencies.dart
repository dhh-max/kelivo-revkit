import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:uuid/uuid.dart';
import 'package:Kelivo/core/services/sandbox/mirror_service.dart';

import 'package:Kelivo/core/models/environment_state.dart';
import 'package:Kelivo/core/providers/environment_provider.dart';
import 'package:Kelivo/core/services/workspace/workspace_runtime.dart';

enum EnvironmentDependency {
  python,
  node,
  git,
  ssh,
  network,
  archive,
  // 2026-10-02 扩展（用户点名「环境预设偏少」，按 APP / 网页 / 服务器开发够用为准）：
  /// 结构化数据处理：jq。
  json,
  /// 代码/文本检索：ripgrep（rg）。
  search,
  /// 本机编译：GCC/G++/make。
  build,
  /// Java/Android 构建与 apksigner 依赖的 JDK。
  java,
  /// 二进制分析：readelf / objdump（SO 与原生库的只读检查用）。
  ///
  /// 评估结论（2026-10-02）：**只收 binutils，不收 llvm**。llvm 包 300MB+，而
  /// SO 的读取/改写我们已有自研管线（so_analyze / so_patch_into_apk），
  /// sandbox 里再装一份 llvm 属于重复投入。
  binutils,
}

enum DependencyStatus { unknown, missing, installed }

enum DependencyFailure { check, install, cancelled }

extension EnvironmentDependencyCommands on EnvironmentDependency {
  String packages({required bool alpine}) => switch (this) {
    EnvironmentDependency.python =>
      alpine
          ? 'python3 py3-pip py3-virtualenv'
          : 'python3 python3-pip python3-venv',
    EnvironmentDependency.node => 'nodejs npm',
    EnvironmentDependency.git => 'git',
    EnvironmentDependency.ssh =>
      alpine ? 'openssh-client-default' : 'openssh-client',
    EnvironmentDependency.network => 'curl wget',
    EnvironmentDependency.archive => 'zip unzip',
    EnvironmentDependency.json => 'jq',
    EnvironmentDependency.search =>
      alpine ? 'ripgrep' : 'ripgrep',
    EnvironmentDependency.build =>
      alpine ? 'build-base' : 'build-essential',
    EnvironmentDependency.java =>
      alpine ? 'openjdk17' : 'default-jdk-headless',
    EnvironmentDependency.binutils => 'binutils',
  };

  String probe({required bool alpine}) => switch (this) {
    EnvironmentDependency.python =>
      'python3 --version && python3 -m pip --version && ${alpine ? 'virtualenv --version' : 'python3 -m venv --help'}',
    EnvironmentDependency.node => 'node --version && npm --version',
    EnvironmentDependency.git => 'git --version',
    EnvironmentDependency.ssh =>
      'ssh -V && command -v scp && command -v sftp && command -v ssh-keygen',
    EnvironmentDependency.network => 'curl --version && wget --version',
    EnvironmentDependency.archive => 'zip -v && unzip -v',
    EnvironmentDependency.json => 'jq --version',
    EnvironmentDependency.search => 'rg --version',
    EnvironmentDependency.build =>
      'gcc --version && g++ --version && make --version',
    EnvironmentDependency.java => 'java -version && javac -version',
    EnvironmentDependency.binutils =>
      'readelf --version && objdump --version',
  };
}

/// A process-wide installer: leaving the page does not lose progress or start
/// another package transaction. Installed state is probed from the guest.
class EnvironmentDependencies extends ChangeNotifier {
  EnvironmentDependencies({
    required this.runtime,
    required this.env,
    required bool alpine,
    required this.mirrors,
  }) : _defaultAlpine = alpine {
    env.addListener(_environmentChanged);
  }

  final WorkspaceRuntime runtime;
  final EnvironmentProvider env;
  final bool _defaultAlpine;
  bool get alpine =>
      env.state.distro == null ? _defaultAlpine : env.state.distro == 'alpine';
  bool get supportsPackages =>
      env.state.distro == null ||
      {'ubuntu', 'debian', 'alpine'}.contains(env.state.distro);
  final MirrorService mirrors;
  MirrorCancelToken? _mirrorCancel;
  final Map<EnvironmentDependency, DependencyStatus> _statuses = {};
  final List<int> _output = [];
  String? _runId;
  bool _cancelled = false;
  bool busy = false;
  EnvironmentDependency? installing;
  EnvironmentDependency? lastInstalled;
  EnvironmentDependency? lastAttempt;
  DependencyFailure? failure;
  String get log => utf8.decode(_output, allowMalformed: true);
  DependencyStatus status(EnvironmentDependency dependency) =>
      _statuses[dependency] ?? DependencyStatus.unknown;

  void _environmentChanged() {
    if (env.state.phase != EnvironmentPhase.ready) {
      _statuses.clear();
      lastInstalled = null;
      notifyListeners();
    }
  }

  String get probeScript => [
    for (final dependency in EnvironmentDependency.values)
      'if ( ${dependency.probe(alpine: alpine)} ) >/dev/null 2>&1; then '
          "echo '__kelivo_dep_${dependency.name}=1'; else "
          "echo '__kelivo_dep_${dependency.name}=0'; fi",
  ].join('\n');

  String installScript(EnvironmentDependency dependency) {
    final packages = dependency.packages(alpine: alpine);
    if (alpine) {
      return 'set -e\napk --wait 60 update\napk --wait 60 add $packages\n';
    }
    return 'set -e\nexport DEBIAN_FRONTEND=noninteractive\n'
        'dpkg --configure -a\n'
        'apt-get -o DPkg::Lock::Timeout=60 -o Acquire::Retries=2 '
        '-o APT::Update::Error-Mode=any update\n'
        'apt-get -o DPkg::Lock::Timeout=60 -f install -y\n'
        'apt-get -o DPkg::Lock::Timeout=60 -o Acquire::Retries=2 '
        'install -y --no-install-recommends ca-certificates $packages\n';
  }

  Future<void> refresh() async {
    if (busy ||
        !supportsPackages ||
        env.state.phase != EnvironmentPhase.ready) {
      return;
    }
    busy = true;
    _cancelled = false;
    failure = null;
    notifyListeners();
    try {
      await _probe();
    } catch (_) {
      failure = _cancelled
          ? DependencyFailure.cancelled
          : DependencyFailure.check;
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  /// 需要安装的依赖（一键安装的输入）：支持包管理且当前不是「已安装」。
  ///
  /// 用户 2026-10-03：「预设依赖那么多，搞一个一键安装，每个安装前自动检测最快
  /// 的」。判定只看当前探针结果，不猜——`unknown` 也按需要安装处理，装完会再探。
  List<EnvironmentDependency> dependenciesToInstall() {
    // 沙盒没就绪 / 发行版不支持包管理时给空列表：一键安装入口据此置灰，
    // 不会出现「点了没反应」。
    if (!supportsPackages || env.state.phase != EnvironmentPhase.ready) {
      return const <EnvironmentDependency>[];
    }
    return <EnvironmentDependency>[
      for (final dependency in EnvironmentDependency.values)
        if (status(dependency) != DependencyStatus.installed) dependency,
    ];
  }

  Future<void> install(EnvironmentDependency dependency) async {
    if (busy ||
        !supportsPackages ||
        env.state.phase != EnvironmentPhase.ready) {
      return;
    }
    busy = true;
    _cancelled = false;
    installing = dependency;
    lastAttempt = dependency;
    lastInstalled = null;
    failure = null;
    _output.clear();
    _statuses[dependency] = DependencyStatus.unknown;
    notifyListeners();
    try {
      _mirrorCancel = MirrorCancelToken();
      final categories = {
        alpine ? MirrorCategory.apk : MirrorCategory.apt,
        if (dependency == EnvironmentDependency.python) MirrorCategory.pip,
        if (dependency == EnvironmentDependency.node) MirrorCategory.npm,
      };
      for (final category in categories) {
        final selection = env.mirrors[category];
        if (selection == null) continue;
        final entry = selection.useMirror
            ? MirrorService.findEntry(
                category,
                id: selection.mirrorId,
                url: selection.selectedBaseUrl,
                arch: env.state.arch ?? 'arm64',
                distro: env.state.distro ?? 'ubuntu',
              )
            : MirrorService.officialEntry(
                category,
                arch: env.state.arch ?? 'arm64',
                distro: env.state.distro ?? 'ubuntu',
              );
        if (entry == null) throw StateError('Unknown package source');
        await mirrors.applyEntry(
          category,
          entry,
          manual: selection.manual,
          cancelToken: _mirrorCancel,
        );
      }
      if (_cancelled) throw StateError('Cancelled');
      await _run(
        installScript(dependency),
        timeout: const Duration(minutes: 30),
        showOutput: true,
      );
      if (_cancelled) throw StateError('Cancelled');
      await _probe();
      if (status(dependency) != DependencyStatus.installed) {
        throw StateError('Installed commands failed verification');
      }
      lastInstalled = dependency;
      await env.clearCachedDiskUsage();
    } catch (_) {
      failure = _cancelled
          ? DependencyFailure.cancelled
          : DependencyFailure.install;
    } finally {
      _mirrorCancel = null;
      installing = null;
      busy = false;
      notifyListeners();
    }
  }

  Future<void> cancel() async {
    if (!busy) return;
    _cancelled = true;
    _mirrorCancel?.cancel();
    final id = _runId;
    if (id != null) await runtime.cancel(id);
  }

  Future<void> _probe() async {
    final output = await _run(
      probeScript,
      timeout: const Duration(seconds: 90),
    );
    final lines = const LineSplitter().convert(output).toSet();
    final statuses = <EnvironmentDependency, DependencyStatus>{};
    for (final dependency in EnvironmentDependency.values) {
      final prefix = '__kelivo_dep_${dependency.name}=';
      final installed = lines.contains('${prefix}1');
      final missing = lines.contains('${prefix}0');
      if (installed == missing) {
        throw const FormatException('Incomplete dependency probe');
      }
      statuses[dependency] = installed
          ? DependencyStatus.installed
          : DependencyStatus.missing;
    }
    _statuses.addAll(statuses);
  }

  Future<String> _run(
    String script, {
    required Duration timeout,
    bool showOutput = false,
  }) async {
    if (_cancelled) throw StateError('Cancelled');
    final id = _runId = 'dependency-${const Uuid().v4()}';
    final output = <int>[];
    CommandExited? exit;
    try {
      await for (final event in runtime.run(
        CommandRequest(runId: id, command: script, cwd: '/', timeout: timeout),
      )) {
        if (event is CommandOutput) {
          output.addAll(event.bytes);
          if (output.length > 65536) {
            output.removeRange(0, output.length - 65536);
          }
          if (showOutput) {
            _output.addAll(event.bytes);
            if (_output.length > 65536) {
              _output.removeRange(0, _output.length - 65536);
            }
            notifyListeners();
          }
        } else if (event is CommandExited) {
          exit = event;
          _cancelled = _cancelled || event.cancelled;
        }
      }
      if (exit == null ||
          exit.exitCode != 0 ||
          exit.timedOut ||
          exit.cancelled ||
          exit.interrupted ||
          _cancelled) {
        throw StateError('Dependency command failed');
      }
      return utf8.decode(output, allowMalformed: true);
    } finally {
      _runId = null;
    }
  }

  @override
  void dispose() {
    env.removeListener(_environmentChanged);
    super.dispose();
  }
}
