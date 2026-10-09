import 'dart:convert';

/// **开发助手专属内置技能**：只在开发助手（`builtin-dev-agent`）下可见。
///
/// 与具体技术栈绑定（Android/Flutter/Web 前后端/排错/依赖构建）；
/// 与栈无关的通用方法论在 [SolabGeneralSkills]（对所有助手生效）。
/// 两者都由 `SolabBuiltinSkills` 合成，随包发布、只读，按 `get_solab_skill` 读取。
class SolabDevSkills {
  const SolabDevSkills._();

  static const activationHints = <String, String>{
    'dev_android_native':
        'Android 原生：Kotlin/Java、Gradle/AGP、Manifest、权限、打包与签名',
    'dev_flutter_dart': 'Flutter/Dart 实现与典型报错（约束、rebuild、生命周期）',
    'dev_web_frontend': 'Web 前端：性能预算、可访问性、状态与组件边界',
    'dev_web_backend_api': '后端接口：契约、错误分级、分页、幂等与重试',
    'dev_debug_perf': '排错与性能：定位方法、可观测手段、前后对比',
    'dev_deps_build': '依赖与构建排错：锁文件、原生资产、插件注册顺序',
  };

  static const activationRules = <String, List<String>>{
    'dev_android_native': [
      '改 API 前先核对 minSdk/targetSdk 与 AGP/Gradle 版本；高于 minSdk 的 API 必须加版本分支或兼容库。',
      '权限与组件必须与 Manifest 同步改；有 intent-filter 的组件必须显式 android:exported。',
      'release 才暴露的崩溃（反射/JNI/序列化）优先怀疑 R8/ProGuard 未保留，别在 debug 里找。',
      '打包/安装失败先分类：工具链环境、缓存、插件注册顺序、原生 ABI/对齐，最后才是业务代码。',
    ],
    'dev_flutter_dart': [
      '溢出/约束类报错先看约束是否无界（Expanded/Flexible/SizedBox 定界），不要用 clip 掩盖。',
      'Future/Stream 不能在 build 里创建；异步回调必须 mounted 守卫并在 dispose 里取消。',
      '状态提升到共享层前先确认「谁真的需要跨页读」；一条数据流只留一个事实源。',
      '卡顿先量再改：看 rebuild 范围与重绘边界，优先 const 与局部 select，而不是盲目加缓存。',
    ],
    'dev_web_frontend': [
      '性能看指标：LCP（关键图/字体预加载）、CLS（预留尺寸）、INP（拆分长任务、读写 DOM 分批）。',
      '组件单一职责、数据获取与展示分离；样式复用既有 token，不引入一次性魔法数。',
      '补齐 loading/空/错误/超长四态；交互必须键盘可达、对比度达标、尊重 reduced-motion。',
      '包体：按路由分包、去重复依赖、查看 bundle 报告，发布带 source map。',
    ],
    'dev_web_backend_api': [
      '先定契约（字段、类型、错误码、分页、幂等、超时）再写实现；调用方按契约写。',
      '错误分级返回结构化信息（校验/未认证/未授权/不存在/冲突/限流/服务端），带 retryable。',
      '禁止用空数组或 200 表示「未知/失败」；这会把线上问题伪装成「没有数据」。',
      '可重试的写操作要幂等键；客户端只重试幂等操作，退避要带抖动。',
    ],
    'dev_debug_perf': [
      '先复现并拿到观测数据（日志、耗时、帧/内存曲线），再提假设；无数据的「优化」不接受。',
      '一次只改一个变量并复测；结论要说清根因，而不只是「改完好了」。',
      '性能必须有前后对比（指标、方法、样本），并说明是否影响正确性。',
    ],
    'dev_deps_build': [
      '先读锁文件与版本约束，再做最小解析变更；避免 latest 式升级。',
      '构建失败按类分：工具链/环境、缓存、插件注册顺序、原生资产、代码；逐类排除而不是乱改。',
      '原生依赖改动后必须清缓存重建并核对生成物（注册表/资产清单），不要手改生成文件。',
      '记录能复现与能修复的确切命令，供下一次直接照做。',
    ],
  };

  static const skillNames = <String>[
    'dev_android_native',
    'dev_flutter_dart',
    'dev_web_frontend',
    'dev_web_backend_api',
    'dev_debug_perf',
    'dev_deps_build',
  ];

  static String read(String skill) {
    final payload = switch (skill) {
      'dev_android_native' => {
        'name': 'Android Native (Kotlin / Gradle / Packaging)',
        'checks': [
          'minSdk/targetSdk + AGP/Gradle plugin versions before choosing APIs.',
          'Manifest: android:exported explicit on every component with an intent-filter; permission + component changed together.',
          'Release-only crashes: assume R8/ProGuard stripped reflection/JNI/serialization entry points until proven otherwise.',
          'Native libs: correct ABI (arm64-v8a), 16 KB page alignment on Android 15+ (LOAD segment align 0x4000, NDK r27+).',
          'Signing: v2/v3 for targetSdk 30+; debug-signed builds cannot upgrade a release install (signature mismatch).',
        ],
        'failureTriage': [
          'INSTALL_FAILED_NO_MATCHING_ABIS -> abiFilters/splits vs device ABI.',
          'ClassNotFoundException only in release -> missing -keep rules.',
          'Installs then crashes on launch -> native lib alignment / packaging (extractNativeLibs).',
        ],
        'output': ['Constraint check', 'Change', 'Build+verify evidence', 'Residual risk'],
      },
      'dev_flutter_dart' => {
        'name': 'Flutter / Dart Implementation',
        'symptomTable': [
          'RenderFlex overflowed -> unbounded constraints: Expanded/Flexible or an explicit bound.',
          'ListView/GridView inside Column -> explicit height, or shrinkWrap+NeverScrollableScrollPhysics only for short lists.',
          'FutureBuilder refetching every rebuild -> create the Future in State, not in build().',
          'setState() called after dispose -> if (!mounted) return + cancel subscriptions in dispose().',
          'Whole-page rebuild storms -> context.select / Selector; const constructors; split widgets.',
          'Jank -> measure rebuild scope and repaint boundaries before adding caches.',
        ],
        'rules': [
          'One source of truth per data flow; derive instead of duplicating.',
          'Async boundaries wire success, error and cancellation explicitly.',
          'Test with system font scale >= 1.3x - fixed-height rows break first.',
        ],
        'output': ['State plan', 'Change', 'Edge cases', 'Verification'],
      },
      'dev_web_frontend' => {
        'name': 'Web Frontend',
        'budgets': [
          'LCP: preload hero image/critical font, fetchpriority="high", never lazy-load above-the-fold media.',
          'CLS: reserve space (width/height or aspect-ratio), font-display: swap with metric-matched fallback.',
          'INP: split tasks > 50 ms, batch DOM reads then writes, debounce scroll/resize.',
          'Bundle: route-level split, tree-shake, dedupe; ship source maps.',
        ],
        'a11y': [
          'Contrast >= 4.5:1; visible focus-visible styles; one H1; labels on all inputs.',
          'All actions keyboard reachable; respect prefers-reduced-motion.',
        ],
        'structure': [
          'Data fetching separate from presentation; components single-purpose.',
          'Reuse design tokens; cover loading/empty/error/long-content states.',
        ],
        'output': ['Component plan', 'Change', 'States covered', 'Budget check'],
      },
      'dev_web_backend_api' => {
        'name': 'Backend API Contract',
        'errorEnvelope': '{code, message, retryable, details}',
        'statusMapping': [
          '400 validation, 401 unauthenticated, 403 unauthorized, 404 not found,',
          '409 conflict/stale version, 422 semantically invalid, 429 rate limited (+Retry-After), 5xx server.',
        ],
        'rules': [
          'Never return empty success to mean unknown/failure.',
          'Retryable writes need an idempotency key; clients retry only idempotent operations with jittered backoff.',
          'Prefer cursor pagination over offset for mutable datasets.',
          'Watch N+1 queries on list endpoints; log request ids, never secrets.',
        ],
        'output': ['Contract', 'Implementation', 'Error matrix', 'Test evidence'],
      },
      'dev_debug_perf' => {
        'name': 'Debugging and Performance',
        'steps': [
          'Reproduce deterministically; capture logs/timings/memory before hypothesising.',
          'Form one hypothesis, change one variable, re-measure.',
          'Explain the root cause and why the fix addresses it.',
          'For performance: state metric, method, sample size, and before/after numbers; confirm correctness unchanged.',
        ],
        'antiPatterns': [
          'Adding caches or sleeps to hide a symptom.',
          'Optimising without a measurement, or measuring on a debug build.',
          'Closing a bug without a regression case.',
        ],
        'output': ['Repro', 'Root cause', 'Fix', 'Measurement'],
      },
      'dev_deps_build' => {
        'name': 'Dependencies and Build Triage',
        'triageOrder': [
          'Toolchain/env (JDK, SDK, Flutter/Node version) ->',
          'cache/state (clean build, lockfile drift) ->',
          'plugin/registrant generation order ->',
          'native assets (ABI, alignment, packaging) ->',
          'application code.',
        ],
        'rules': [
          'Read the lockfile/constraints before changing versions; make the minimal resolution change.',
          'Never hand-edit generated registrants or asset manifests - fix the generator and rebuild.',
          'Record the exact commands that reproduce and fix the failure.',
        ],
        'output': ['Cause class', 'Change', 'Commands', 'Verification'],
      },
      _ => <String, dynamic>{},
    };
    return jsonEncode(payload);
  }
}
