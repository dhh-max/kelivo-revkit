/// `get_workspace_policy` 对外公布的契约（单一事实源）。
///
/// 2026-09-19 C 批（C5）：这类"自省工具"最容易漂移——文档说一套、实现做一套，
/// 而且漂移了没人报警。这里把公布内容抽成纯数据，配套单测断言它与**真实实现**
/// 一致（字段别名对来自 ToolArgumentGuard、MCP 结果上限来自 McpHttpServer），
/// 任何一侧改了而另一侧没跟上，测试立刻红。
library;

abstract final class WorkspacePolicyContract {
  const WorkspacePolicyContract._();

  /// 产物路径规范字段（MCP 出口统一注入），其余键是各工具的历史名。
  static const List<String> artifactPathCanonical = <String>[
    'outputPath',
    'nextInputPath',
  ];
  static const List<String> artifactPathAliases = <String>[
    'output',
    'outputApk',
    'signedPath',
    'signedApk',
    'artifactPath',
  ];

  /// 参数类错误的稳定错误码与附带字段（守卫实际返回的就是这些）。
  static const List<String> argumentErrorCodes = <String>[
    'missing_argument',
    'invalid_argument_type',
    'invalid_argument_value',
  ];
  static const List<String> argumentErrorDetails = <String>[
    'parameter',
    'expected',
    'actual',
    'allowedValues',
  ];

  /// MCP 面单次结果内联上限。**必须与 `McpHttpServer.maxResultChars` 相等**——
  /// 防漂移单测直接断言两者一致（改了服务端上限却忘了公布，测试立刻红）。
  static const int mcpInlineChars = 512 * 1024;

  /// 三套预览/确认契约（写工具 / file 写类 / 清理）。
  static const Map<String, Object?> dryRunContract = <String, Object?>{
    'file write-class actions': 'default dryRun=true (pass dryRun=false to apply)',
    'patch/manifest/sign write tools':
        'dryRun=true required first, then dryRun=true + applyAfterPreview=true',
    'cleanup_apk_builds':
        'dryRun=true for preview, then dryRun=false + confirm=true + previewToken',
    'note':
        'previewToken is single-use, expires in 30 minutes, and is invalidated '
        'when the same artifact is written again (no forked edits).',
  };

  static Map<String, Object?> asMap() => <String, Object?>{
    'artifactPathFields': <String, Object?>{
      'canonical': artifactPathCanonical,
      'aliasesFoldedIn': artifactPathAliases,
      'note':
          'Every write tool now also reports outputPath/nextInputPath (in-place '
          'aliases of its native key), so one set of field names reads any product.',
    },
    'parameterAliases': <String, Object?>{
      'apkPath <-> path':
          'either name is accepted when the tool declares one of them',
      'sourcePath <-> path': 'same rule for copy/rename/diff style inputs',
    },
    'argumentErrors': <String, Object?>{
      'codes': argumentErrorCodes,
      'details': argumentErrorDetails,
      'note':
          'Arguments are validated against the published tools/list schema '
          'before execution; lossless coercions ("20"->20, "true"->true) are '
          'applied silently, everything else returns a structured error instead '
          'of a tool exception.',
    },
    'dryRunContract': dryRunContract,
  };
}
