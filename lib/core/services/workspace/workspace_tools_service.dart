import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;
import 'package:uuid/uuid.dart';

import '../../../features/home/services/tool_approval_service.dart';
import '../../../utils/app_directories.dart';
import '../../../utils/mcp_structured_image.dart';
import '../../../utils/sandbox_path_resolver.dart';
import '../api/tool_call_cancellation.dart';
import '../../models/workspace.dart';
import '../../models/workspace_binding.dart';
import '../../models/external_mount.dart';
import '../../models/environment_variable.dart';
import '../../providers/external_mounts_provider.dart';
import '../../providers/workspace_provider.dart';
import '../chat/chat_service.dart';
import 'conversation_files.dart';
import 'environment_output_redactor.dart';
import 'file_link_resolver.dart';
import 'host_file_tools.dart';
import 'output_buffer.dart';
import 'tool_run_registry.dart';
import 'workspace_paths.dart';
import 'workspace_image.dart';
import 'workspace_runtime.dart';
import 'workspace_session_sync.dart';
import 'workspace_tool_context.dart';
import 'workspace_tool_metadata.dart';
import '../../../features/home/services/frida_sandbox_runtime.dart';
import '../../../features/home/services/frida_tool_handler.dart';

export 'workspace_session_sync.dart' show AttachmentInfo, syncAttachments;
export 'workspace_tool_context.dart';
export 'workspace_tool_metadata.dart';

typedef ConversationExtrasUpdater =
    Future<void> Function(
      String conversationId,
      Map<String, dynamic> Function(Map<String, dynamic> extras) update,
    );

/// Per-generation workspace tool definitions, approval, and execution.
class WorkspaceToolsService {
  WorkspaceToolsService({
    ToolRunRegistry? registry,
    WorkspaceRuntimeProvider? runtimeProvider,
    this.updateConversationExtras,
    this.touchLastUsed,
    this.onSkillRead,
    this.onShellCompleted,
    this.isToolEnabled,
    this.loadEnvironment,
  }) : registry = registry ?? ToolRunRegistry(),
       runtimeProvider = runtimeProvider ?? WorkspaceRuntimeProvider();

  static const Set<String> toolNames = {
    'shell',
    'read_file',
    'view_image',
    'write_file',
    'edit_file',
    'list_dir',
    'glob',
    'grep',
  };

  static const int _previewLimit = WorkspaceToolMetadata.previewMaxChars;
  static const int _changedFilesCap = 50;
  static const String _androidShellHint =
      'Uses the Shell path configured in Environment > PRoot settings; '
      'when unset, prefers /bin/bash if available, otherwise /bin/sh. '
      'This is not an interactive shell; do not assume ~/.bashrc is loaded.';

  static String get _shellInvocation =>
      defaultTargetPlatform == TargetPlatform.android
      ? 'configured shell -lc'
      : 'sh -lc';

  final ToolRunRegistry registry;
  final WorkspaceRuntimeProvider runtimeProvider;
  final ConversationExtrasUpdater? updateConversationExtras;
  final Future<void> Function(String workspaceId)? touchLastUsed;
  final Future<void> Function(String skillId)? onSkillRead;
  final Future<void> Function()? onShellCompleted;
  final bool Function(String workspaceId, String tool)? isToolEnabled;
  final Future<EnvironmentExecutionConfig> Function()? loadEnvironment;

  bool _enabled(WorkspaceToolContext ctx, String name) =>
      isToolEnabled?.call(ctx.workspace.id, name) ??
      ctx.workspace.isToolEnabled(name);

  /// 根口径覆盖（由 main 注入 `ApkWorkspaceBindingService.effectiveWorkRoot`）。
  ///
  /// core 不能反向依赖 features/solab_apk（分层），所以用函数注入——与同目录的
  /// `ApkWorkspaceBindingService.verifiedExperiencePeek` 同一套路。返回 null 表示
  /// 没有覆盖（用工作区根本身）。
  static Future<String?> Function({String? workspaceRoot})?
  effectiveWorkRootResolver;

  static Future<WorkspaceToolContext?> resolve({
    required String? conversationId,
    required WorkspaceProvider workspaceProvider,
    required WorkspaceRuntimeProvider runtimeProvider,
    required ChatService chatService,
    ExternalMountsProvider? externalMounts,
  }) async {
    if (conversationId == null || conversationId.isEmpty) return null;
    try {
      await workspaceProvider.loaded;
    } catch (_) {}
    final conversation = chatService.getConversation(conversationId);
    if (conversation == null) return null;
    final binding = WorkspaceBinding.fromExtras(conversation.extras);
    final Workspace workspace;
    if (binding.isBound) {
      final bound = workspaceProvider.byId(binding.workspaceId!);
      if (bound == null) return null;
      workspace = bound;
    } else {
      // P1「工作区即项目」（用户 2026-10-04 批准）：未绑定会话自动落到「默认
      // 工作区」——它的根就是 APK 工作台那个统一工作目录。以前这里直接
      // `return null`，于是「工作台目录」成了第二套全局根；一套根、一套守卫、
      // 一套设置从这条分支开始。
      final fallbackRoot = await effectiveWorkRootResolver?.call();
      final fallback = await workspaceProvider.defaultWorkspace(
        hostPath: fallbackRoot,
      );
      if (fallback == null) return null;
      workspace = fallback;
    }

    // 默认工作区还没设目录：**不替用户挑一个**（用户 2026-10-04：「没有就让设置啊，
    // 别默认」）。返回 null 让工具报 `work_dir_not_set`，界面提示去
    // 工作台 → 工作区 → 工作目录 选一个；绝不能悄悄落到应用私有目录。
    if (workspace.needsRoot) return null;

    return _buildContext(
      workspace: workspace,
      binding: binding,
      conversationId: conversationId,
      runtimeProvider: runtimeProvider,
      externalMounts: externalMounts,
      workspaceProvider: workspaceProvider,
    );
  }

  /// 无会话调用的稳定会话键（与运行时作用域键 'mcp-host' 同口径）。
  static const String mcpHostConversationId = 'mcp-host';

  /// 进程级解析器：MCP 面 / 后台链路没有 BuildContext，用它们拿同一批 provider
  /// 实例（main 在构建 provider 树时注入；未注入时相关入口按「无工作区」处理）。
  static WorkspaceProvider? Function()? workspaceProviderResolver;
  static WorkspaceRuntimeProvider? Function()? runtimeProviderResolver;
  static ExternalMountsProvider? Function()? externalMountsResolver;
  static WorkspaceToolsService? Function()? sharedInstanceResolver;

  /// 无会话场景（MCP 面 / 计划任务）解析**默认工作区**上下文。
  ///
  /// 用户 2026-10-06：「MCP 模式连沙盒环境都找不着」——MCP 面过去既不发工作区
  /// 工具族、也没有可注入的上下文（绑定挂在会话上），沙盒在 MCP 上等于不存在。
  /// 现在无会话调用直接落到「设置里配置的默认工作区」：它按配置视为已绑定，
  /// 是否真的挂沙盒仍由工作区 envMode + 运行时状态决定（环境不可用就是不挂，
  /// 由工具回报，不假装可用）。
  static Future<WorkspaceToolContext?> resolveDefault({
    required WorkspaceProvider workspaceProvider,
    required WorkspaceRuntimeProvider runtimeProvider,
    ExternalMountsProvider? externalMounts,
  }) async {
    try {
      await workspaceProvider.loaded;
    } catch (_) {}
    final fallbackRoot = await effectiveWorkRootResolver?.call();
    final workspace = await workspaceProvider.defaultWorkspace(
      hostPath: fallbackRoot,
    );
    if (workspace == null || workspace.needsRoot) return null;
    return _buildContext(
      workspace: workspace,
      binding: WorkspaceBinding(
        workspaceId: workspace.id,
        cwd: workspace.defaultCwd,
      ),
      conversationId: mcpHostConversationId,
      runtimeProvider: runtimeProvider,
      externalMounts: externalMounts,
      workspaceProvider: workspaceProvider,
    );
  }

  /// [resolveDefault] 的解析器版本：MCP 面调用入口（无 context）。
  static Future<WorkspaceToolContext?> resolveDefaultFromResolvers() async {
    final workspaceProvider = workspaceProviderResolver?.call();
    final runtimeProvider = runtimeProviderResolver?.call();
    if (workspaceProvider == null || runtimeProvider == null) return null;
    return resolveDefault(
      workspaceProvider: workspaceProvider,
      runtimeProvider: runtimeProvider,
      externalMounts: externalMountsResolver?.call(),
    );
  }

  static Future<WorkspaceToolContext?> _buildContext({
    required Workspace workspace,
    required WorkspaceBinding binding,
    required String conversationId,
    required WorkspaceRuntimeProvider runtimeProvider,
    required WorkspaceProvider workspaceProvider,
    ExternalMountsProvider? externalMounts,
  }) async {
    late final String hostRoot;
    try {
      final workspaceRoot = await workspaceProvider.hostRootFor(workspace);
      // 根口径唯一化（用户 2026-10-04）：file 族走 ApkWorkspaceBindingService.workDir()，
      // shell 走这里的沙盒 /workspace 挂载。工作台目录优先时两者必须都是它，否则
      // 会出现「shell 写在 A、file 读不到」。无工作台目录时回落到工作区根。
      final resolved = await effectiveWorkRootResolver?.call(
        workspaceRoot: workspaceRoot,
      );
      hostRoot = (resolved == null || resolved.trim().isEmpty)
          ? workspaceRoot
          : resolved.trim();
    } catch (e) {
      debugPrint('Workspace host root unavailable: $e');
      return null;
    }

    final runtime = runtimeProvider.runtime;
    RuntimeStatus? status;
    if (runtime != null) {
      try {
        status = await runtime.status();
      } catch (e) {
        debugPrint('Workspace runtime status failed: $e');
      }
    }
    // 环境模式是**工作区的属性**（P1）：direct = 直连 Android 文件系统（不挂沙盒，
    // 就是用户说的「APK 工作台目录」那套）；sandbox = 挂 Linux 环境。
    //
    // 用户 2026-10-06：**未绑定会话 = 没有挂载虚拟环境**（本地直连）。正常路径上
    // 助手默认工作区已在启动期自动回填，所以「未绑定」只会在用户显式选择「无」
    // 时出现——那种情况下不替他挂沙盒；挂载与否仍由工作区 envMode + 运行时状态决定。
    final sandboxed =
        !binding.isBound || workspace.envMode == WorkspaceEnvMode.direct
        ? false
        : runtime != null
        // fail-closed：status() 抛错时不能退回 native —— native 模式不做 zone
        // 门禁（任意绝对路径可读），移动端出现这次降级就等于放开越权面。
        ? (status?.sandboxed ?? (Platform.isAndroid || Platform.isIOS))
        : (Platform.isAndroid || Platform.isIOS);

    final sessionDir = await AppDirectories.sessionDir(conversationId);
    final skillsDir = await AppDirectories.getSkillsDirectory();
    final paths = sandboxed
        ? WorkspacePaths.sandboxed(
            workspaceHostRoot: hostRoot,
            sessionHostDir: sessionDir.path,
            skillsHostDir: skillsDir.path,
            externalMounts: await externalMounts?.resolveMounts() ?? const [],
            loadExternalMounts: externalMounts?.resolveMounts,
          )
        : WorkspacePaths.native(
            workspaceHostRoot: hostRoot,
            sessionHostDir: sessionDir.path,
            skillsHostDir: skillsDir.path,
          );

    return WorkspaceToolContext(
      workspace: workspace,
      binding: binding,
      paths: paths,
      sessionDir: sessionDir,
      outputsDir: Directory(p.join(sessionDir.path, 'outputs')),
      conversationId: conversationId,
      runtimeStatus: status,
      runtimeRegistered: runtime != null,
    );
  }

  /// 轻量解析：这条**会话**绑定的工作区（项目）id + 宿主根目录。
  ///
  /// 与 [resolve] 的区别：不起运行时、不建 session 目录、不做路径规划——记忆
  /// 打标/过滤、用量快照 hash 只需要「项目身份」，与 [ProjectScope] 是同一口径。
  ///
  /// 未绑定会话/工作区已删时返回 `(id: null, root: null)`（按全局处理）；
  /// 不抛异常（后台任务不该因为工作区解析失败而整轮失败）。
  static Future<({String? id, String? root})> resolveConversationProject({
    required String? conversationId,
    required WorkspaceProvider workspaceProvider,
    required ChatService chatService,
  }) async {
    if (conversationId == null || conversationId.isEmpty) {
      return (id: null, root: null);
    }
    try {
      await workspaceProvider.loaded;
    } catch (_) {}
    final conversation = chatService.getConversation(conversationId);
    if (conversation == null) return (id: null, root: null);
    final binding = WorkspaceBinding.fromExtras(conversation.extras);
    if (!binding.isBound) return (id: null, root: null);
    final workspace = workspaceProvider.byId(binding.workspaceId!);
    if (workspace == null) return (id: null, root: null);
    String? root;
    try {
      root = await workspaceProvider.hostRootFor(workspace);
    } catch (e) {
      debugPrint('resolveConversationProject: host root unavailable: $e');
    }
    return (id: workspace.id, root: root);
  }

  List<Map<String, dynamic>> buildToolDefinitions(WorkspaceToolContext ctx) {
    // Frida 运行期驱动：把「在沙盒里跑一条命令」接到 frida 工具上（宿主侧注入
    // 不需要它）。环境没装时命令会以 exitCode!=0 返回，frida 那边会转成
    // environment_not_ready + 安装指引，不会假装成功。
    FridaToolRuntime.sandbox = FridaSandboxRuntime(
      exec: (command, {int timeoutMs = 60000}) =>
          _execInSandbox(ctx, command, timeoutMs),
    );
    if (ctx.skillsOnly) {
      return [
        _fn(
          'read_file',
          [
            'Read a skill file as numbered lines. Use offset/limit to page through long files.',
            'Paths are limited to /skills/...',
          ],
          {
            'path': {
              'type': 'string',
              'description': 'Skill file path under /skills/...',
            },
            'offset': {
              'type': 'integer',
              'description': '1-based line number to start from.',
            },
            'limit': {
              'type': 'integer',
              'description': 'Maximum number of lines to return.',
            },
          },
          ['path'],
        ),
      ];
    }
    return definitions(
          vocab: _pathVocab(ctx.paths),
          outputHint: ctx.paths.sandboxed
              ? '${WorkspacePaths.guestChat}/outputs/<id>.txt'
              : '${ctx.paths.sessionHostDir}/outputs/<id>.txt',
        )
        .where(
          (definition) =>
              _enabled(ctx, (definition['function'] as Map)['name'] as String),
        )
        .toList();
  }

  /// Shared schemas for execution and the ungated description editor.
  static List<Map<String, dynamic>> definitions({
    List<String> vocab = const ['/workspace', '/chat', '/skills', '/tmp'],
    String outputHint = '/chat/outputs/<id>.txt',
  }) {
    return [
      _fn(
        'shell',
        [
          'Fresh non-interactive $_shellInvocation per call; no cwd/env persists. Chain with &&.',
          if (defaultTargetPlatform == TargetPlatform.android)
            _androidShellHint,
          'Use non-interactive flags (e.g. -y). Output is capped; long output is saved',
          'to $outputHint. Network is available on mobile sandboxes.',
        ],
        {
          'command': {
            'type': 'string',
            'description': 'Shell command to run with $_shellInvocation.',
          },
          'cwd': {
            'type': 'string',
            'description':
                'Working directory in model path vocabulary (${vocab.join(', ')}).',
          },
          'timeout_seconds': {
            'type': 'integer',
            'description':
                'Command timeout in seconds (default 900, range 1-3600). '
                'Choose a longer timeout for package installs, downloads, builds, '
                'or other long-running commands. Values outside this range are clamped.',
            'default': 900,
            'minimum': 1,
            'maximum': 3600,
          },
        },
        ['command'],
      ),
      _fn(
        'read_file',
        [
          'Read a file as numbered lines. Use offset/limit to page through long files.',
          'Paths: ${vocab.join(', ')}.',
        ],
        {
          'path': {'type': 'string', 'description': 'File path to read.'},
          'offset': {
            'type': 'integer',
            'description': '1-based line number to start from.',
          },
          'limit': {
            'type': 'integer',
            'description': 'Maximum number of lines to return.',
          },
        },
        ['path'],
      ),
      _fn(
        'view_image',
        [
          'View a local image file when visual inspection is needed. Use this for images already on disk.',
          'Paths: ${vocab.join(', ')}. Supports PNG, JPEG, GIF, WebP, and BMP; animated images use the first frame.',
          'Returns image content to inspect. Large images are resized to at most 2048 pixels on the longest edge.',
        ],
        {
          'path': {
            'type': 'string',
            'description': 'Local filesystem path to an image file.',
          },
        },
        ['path'],
      ),
      _fn(
        'write_file',
        [
          'Create or overwrite a file with the given content.',
          'Writable zones: workspace, chat, tmp. Skills are read-only.',
        ],
        {
          'path': {'type': 'string', 'description': 'File path to write.'},
          'content': {'type': 'string', 'description': 'Full file contents.'},
        },
        ['path', 'content'],
      ),
      _fn(
        'edit_file',
        [
          'Replace old_string with new_string. Matching is whitespace-tolerant',
          '(exact, then line-trimmed, then block-anchor). old_string must match a',
          'unique location unless replace_all is true. Read the file before editing.',
        ],
        {
          'path': {'type': 'string', 'description': 'File path to edit.'},
          'old_string': {
            'type': 'string',
            'description': 'Exact or whitespace-tolerant text to find.',
          },
          'new_string': {'type': 'string', 'description': 'Replacement text.'},
          'replace_all': {
            'type': 'boolean',
            'description':
                'Replace every match instead of requiring a unique one.',
          },
        },
        ['path', 'old_string', 'new_string'],
      ),
      _fn(
        'list_dir',
        [
          'List directory entries. Directories are suffixed with /; files include size.',
          'Default path is the current workspace cwd.',
        ],
        {
          'path': {'type': 'string', 'description': 'Directory to list.'},
          'depth': {
            'type': 'integer',
            'description': 'How many directory levels to walk (default 1).',
          },
        },
        const [],
      ),
      _fn(
        'glob',
        [
          'Find files whose relative paths match a glob pattern (e.g. **/*.dart).',
        ],
        {
          'pattern': {
            'type': 'string',
            'description': 'Glob pattern to match.',
          },
          'path': {
            'type': 'string',
            'description': 'Directory to search (default: workspace root).',
          },
        },
        ['pattern'],
      ),
      _fn(
        'grep',
        [
          'Search file contents with a regex (falls back to a literal if invalid).',
        ],
        {
          'pattern': {
            'type': 'string',
            'description': 'Regex or literal to find.',
          },
          'path': {
            'type': 'string',
            'description':
                'File or directory to search (default: workspace root).',
          },
          'ignore_case': {
            'type': 'boolean',
            'description': 'Case-insensitive search.',
          },
          'limit': {
            'type': 'integer',
            'description': 'Maximum matches to return (default 100).',
          },
        },
        ['pattern'],
      ),
    ];
  }

  static String buildPromptFragment(
    WorkspaceToolContext ctx, {
    List<AttachmentInfo> attachments = const [],
    Iterable<String> environmentVariableNames = const [],
  }) {
    if (ctx.skillsOnly) return '';
    final paths = ctx.paths;
    final workspace = paths.sandboxed
        ? WorkspacePaths.guestWorkspace
        : paths.workspaceHostRoot;
    final chat = paths.sandboxed
        ? WorkspacePaths.guestChat
        : paths.sessionHostDir;
    final skills = paths.sandboxed
        ? WorkspacePaths.guestSkills
        : paths.skillsHostDir;
    final tmp = paths.sandboxed ? WorkspacePaths.guestTmp : paths.tmpHostRoot;
    final outputsHint = paths.sandboxed
        ? '${WorkspacePaths.guestChat}/outputs/<id>.txt'
        : '${paths.sessionHostDir}/outputs/<id>.txt';
    final attachDir = paths.sandboxed
        ? '${WorkspacePaths.guestChat}/attachments/'
        : '${paths.sessionHostDir}/attachments/';

    final buf = StringBuffer()
      ..writeln('<workspace>')
      ..writeln('Path zones:')
      ..writeln('- $workspace — project files (writable)')
      ..writeln('- $chat — this chat\'s attachments/ and outputs/ (writable)')
      ..writeln('- $skills — installed skills (read-only)');
    if (paths.sandboxed) {
      final source = defaultTargetPlatform == TargetPlatform.iOS
          ? "from iOS Files (e.g. an Obsidian vault, Downloads, another app's iCloud container)"
          : 'from Environment settings (on-device folders)';
      final readOnly = paths.externalMounts
          .where((mount) => mount.readOnly)
          .map((mount) => mount.guest)
          .join(', ');
      buf.writeln(
        '- ${ExternalMount.root}/<name>/ — user-mounted external folders '
        '$source, shared across workspaces. '
        'Names and availability vary: list ${ExternalMount.root}/ first for external/user files. '
        'File tools reject writes to read-only mounts; respect this in Shell too.'
        '${readOnly.isEmpty ? '' : ' Read-only: $readOnly.'}',
      );
    }
    buf
      ..writeln('- $tmp — scratch (writable, ephemeral)')
      ..writeln('cwd: ${ctx.cwd}')
      ..writeln(
        'Enabled tools: ${toolNames.where(ctx.workspace.isToolEnabled).join(', ')}',
      )
      ..writeln();
    if (ctx.workspace.isToolEnabled('shell')) {
      buf.writeln(
        'shell is one-shot: a fresh non-interactive $_shellInvocation each call. '
        'No cd or env persists. Chain with &&. Use non-interactive flags (-y). '
        'Output is capped; long output is saved to $outputsHint.',
      );
      if (environmentVariableNames.isNotEmpty) {
        buf.writeln(
          'User-configured environment variables are already injected: '
          '${environmentVariableNames.join(', ')}. '
          r'Use $NAME references; do not print or attempt to discover their values.',
        );
      }
    }
    if (ctx.workspace.isToolEnabled('read_file') &&
        ctx.workspace.isToolEnabled('edit_file')) {
      if (ctx.workspace.isToolEnabled('write_file')) {
        buf.writeln(
          'Prefer read_file, edit_file, and write_file over cat/sed.',
        );
      }
      buf.writeln('Always read_file before editing.');
    }
    buf
      ..writeln()
      ..writeln(
        'Cite files as [name](kelivo://workspace/rel/path), outputs as '
        'kelivo://chat/outputs/x.txt, images as ![alt](kelivo://workspace/plot.png). '
        'Percent-encode each path segment (spaces, non-ASCII); raw UTF-8 is also accepted.',
      )
      ..writeln()
      ..writeln(_engineLine(ctx));
    if (attachments.isNotEmpty) {
      buf.writeln();
      buf.writeln('Attachments under $attachDir');
      for (final item in attachments) {
        buf.writeln('- ${item.name} (${item.size} bytes)');
      }
    }
    buf.write('</workspace>');
    return buf.toString();
  }

  Future<Object?> handle(
    WorkspaceToolContext ctx,
    String name,
    Map<String, dynamic> args, {
    required String toolCallId,
    ToolApprovalService? approvalService,
    String? conversationId,
  }) async {
    final environment =
        await loadEnvironment?.call() ?? EnvironmentExecutionConfig();
    final redactor = EnvironmentOutputRedactor(environment);
    final result = await _handle(
      ctx,
      name,
      args,
      toolCallId: toolCallId,
      approvalService: approvalService,
      conversationId: conversationId,
      environment: environment.variables,
    );
    return redactor.redact(ClientToolResult.fromHandler(result));
  }

  Future<Object?> _handle(
    WorkspaceToolContext ctx,
    String name,
    Map<String, dynamic> args, {
    required String toolCallId,
    ToolApprovalService? approvalService,
    String? conversationId,
    required Map<String, String> environment,
  }) async {
    if (ctx.skillsOnly && name != 'read_file') {
      return _errorResult(
        tool: name,
        error: 'skills_only',
        message: 'Only read_file is available without a workspace',
      );
    }
    if (!ctx.skillsOnly && !_enabled(ctx, name)) {
      return _errorResult(
        tool: name,
        error: 'tool_disabled',
        message: 'This tool is disabled for the workspace',
      );
    }
    try {
      ToolCallCancellation.current?.throwIfCancelled();
      await ctx.paths.refreshExternalMounts();
      ToolCallCancellation.current?.throwIfCancelled();
      switch (name) {
        case 'shell':
          return await _handleShell(
            ctx,
            args,
            toolCallId: toolCallId,
            approvalService: approvalService,
            conversationId: conversationId,
            environment: environment,
          );
        case 'read_file':
          return await _handleReadFile(ctx, args);
        case 'view_image':
          return await _handleViewImage(ctx, args);
        case 'write_file':
          return await _handleWriteFile(
            ctx,
            args,
            toolCallId: toolCallId,
            approvalService: approvalService,
            conversationId: conversationId,
          );
        case 'edit_file':
          return await _handleEditFile(
            ctx,
            args,
            toolCallId: toolCallId,
            approvalService: approvalService,
            conversationId: conversationId,
          );
        case 'list_dir':
          return await _handleListDir(ctx, args);
        case 'glob':
          return await _handleGlob(ctx, args);
        case 'grep':
          return await _handleGrep(ctx, args);
        default:
          return _errorResult(
            tool: name,
            error: 'unknown_tool',
            message: 'Unknown workspace tool: $name',
          );
      }
    } catch (e) {
      return _errorResult(
        tool: name,
        error: 'tool_failed',
        message: e.toString(),
      );
    }
  }

  static String? linkFor(
    ResolvedPath resolved, {
    required WorkspacePaths paths,
  }) {
    switch (resolved.zone) {
      case WorkspaceZone.workspace:
        final rel = WorkspacePaths.relativeToHostRoot(
          paths.workspaceHostRoot,
          resolved.hostPath,
        );
        if (rel == null) return null;
        return 'kelivo://workspace/${KelivoLink.encodePath(rel)}';
      case WorkspaceZone.chat:
        final rel = WorkspacePaths.relativeToHostRoot(
          paths.sessionHostDir,
          resolved.hostPath,
        );
        if (rel == null) return null;
        if (rel == 'attachments' ||
            rel == 'outputs' ||
            rel.startsWith('attachments/') ||
            rel.startsWith('outputs/')) {
          return 'kelivo://chat/${KelivoLink.encodePath(rel)}';
        }
        return 'kelivo://session/${KelivoLink.encodePath(rel)}';
      case WorkspaceZone.skills:
        final rel = WorkspacePaths.relativeToHostRoot(
          paths.skillsHostDir,
          resolved.hostPath,
        );
        if (rel == null) return null;
        return 'kelivo://skills/${KelivoLink.encodePath(rel)}';
      case WorkspaceZone.tmp:
        final rel = WorkspacePaths.relativeToHostRoot(
          paths.tmpHostRoot,
          resolved.hostPath,
        );
        return rel == null
            ? null
            : 'kelivo://tmp/${KelivoLink.encodePath(rel)}';
      case WorkspaceZone.external:
        for (final mount in paths.externalMounts) {
          final rel = WorkspacePaths.relativeToHostRoot(
            mount.host,
            resolved.hostPath,
          );
          if (rel != null && mount.externalId != null) {
            return 'kelivo://mounts/${Uri.encodeComponent(mount.externalId!)}${rel.isEmpty ? '' : '/${KelivoLink.encodePath(rel)}'}';
          }
        }
        return null;
      case WorkspaceZone.outside:
        return null;
    }
  }

  static WorkspaceToolFile _fileFor(
    WorkspaceToolContext ctx,
    ResolvedPath resolved, {
    WorkspaceFileRole role = WorkspaceFileRole.referenced,
    bool isDirectory = false,
  }) => WorkspaceToolFile(
    path: resolved.modelPath,
    link: linkFor(resolved, paths: ctx.paths),
    isDirectory: isDirectory,
    role: role,
    temporary: resolved.zone == WorkspaceZone.tmp,
  );

  static Future<List<WorkspaceToolFile>> _referencedFiles(
    WorkspaceToolContext ctx,
    Iterable<String> paths,
  ) async {
    final files = <WorkspaceToolFile>[];
    final seen = <String>{};
    for (final path in paths.toSet()) {
      try {
        final resolved = await ctx.paths.resolveReal(path, cwd: ctx.cwd);
        final file = _fileFor(
          ctx,
          resolved,
          isDirectory: await FileSystemEntity.isDirectory(resolved.hostPath),
        );
        if (seen.add(file.identity)) files.add(file);
      } on PathResolutionException {
        files.add(WorkspaceToolFile(path: path));
      } on FileSystemException {
        files.add(WorkspaceToolFile(path: path));
      }
    }
    return files;
  }

  Future<Object?> _handleShell(
    WorkspaceToolContext ctx,
    Map<String, dynamic> args, {
    required String toolCallId,
    ToolApprovalService? approvalService,
    String? conversationId,
    required Map<String, String> environment,
  }) async {
    const tool = 'shell';
    final cancellation = ToolCallCancellation.current;
    cancellation?.throwIfCancelled();
    final command = _stringArg(args, 'command');
    if (command.isEmpty) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'command is required',
      );
    }

    final runtime = runtimeProvider.runtime;
    RuntimeStatus? status = ctx.runtimeStatus;
    if (runtime != null && status == null) {
      try {
        status = await runtime.status();
      } catch (_) {}
    }
    if (runtime == null || status == null || !status.ready) {
      return _errorResult(
        tool: tool,
        error: 'environment_not_ready',
        message: status?.reason ?? 'Sandbox environment is not ready',
        instruction:
            'tell the user to install/enable the sandbox environment in Settings → Workspace',
        meta: const WorkspaceToolMetadata(
          tool: tool,
          status: 'error',
          code: 'environment_not_ready',
        ),
      );
    }

    final sandboxed = status.sandboxed;
    final needsApproval =
        (ctx.workspace.shellNeedsApproval || !sandboxed) &&
        !ctx.binding.allowAll;
    final denied = await _maybeApprove(
      approvalService,
      needed: needsApproval,
      toolCallId: toolCallId,
      toolName: tool,
      args: args,
      conversationId: conversationId ?? ctx.conversationId,
      // 报错要指名是**哪个工作区**的开关拦的（用户 2026-10-06：改了别的
      // 工作区的开关，MCP 面仍被拒，看着像"开关没效果"）。
      workspaceName: ctx.workspace.name,
    );
    if (denied != null) return denied;

    // 报告 2-2：超时钳位过去是静默的——传 0 被抬到 1s，返回体还不说是钳过的。
    final requestedTimeout = _intArg(args, 'timeout_seconds');
    final timeoutSeconds = (requestedTimeout ?? 900).clamp(1, 3600);
    final timeoutClamped =
        requestedTimeout != null && requestedTimeout != timeoutSeconds;

    // 报告 2-1：cwd 传区外/不存在的路径过去**静默回落**到 /workspace，调用方以为
    // 切过去了。现在显式判定：区外 → invalid_cwd（列出可见分区）；分区内但不存在
    // → cwd_not_found。两者都带 requested/resolved，绝不无声换目录。
    final requestedCwd = _stringArg(args, 'cwd');
    final String cwd;
    if (requestedCwd.trim().isEmpty) {
      cwd = ctx.paths.normalizeCwd(ctx.cwd);
    } else {
      final resolvedCwd = ctx.paths.resolve(
        requestedCwd,
        cwd: ctx.cwd.isEmpty ? '/' : ctx.cwd,
      );
      if (resolvedCwd.zone == WorkspaceZone.outside) {
        return _errorResult(
          tool: tool,
          error: 'invalid_cwd',
          message:
              'cwd 不在沙盒可见分区内：$requestedCwd。可用分区：'
              '/workspace（工作区）、/chat（会话目录）、/tmp、/skills、'
              '/mounts/<外部挂载>。',
          instruction:
              '传分区内路径，或省略 cwd 用默认工作目录；不要传 rootfs 里的系统路径（/etc、/usr）。',
          meta: WorkspaceToolMetadata(
            tool: tool,
            status: 'error',
            code: 'invalid_cwd',
            command: command,
          ),
        );
      }
      cwd = resolvedCwd.modelPath;
      try {
        final hostCwd = await WorkspacePaths.resolveHostPath(resolvedCwd.hostPath);
        final type = await FileSystemEntity.type(hostCwd);
        if (type == FileSystemEntityType.notFound) {
          return _errorResult(
            tool: tool,
            error: 'cwd_not_found',
            message: 'cwd 目录不存在：$requestedCwd（解析为 $cwd）',
            instruction: '先用 list_dir 确认目录，或省略 cwd 用默认工作目录。',
            meta: WorkspaceToolMetadata(
              tool: tool,
              status: 'error',
              code: 'cwd_not_found',
              command: command,
            ),
          );
        }
        if (type != FileSystemEntityType.directory) {
          return _errorResult(
            tool: tool,
            error: 'cwd_not_a_directory',
            message: 'cwd 不是目录：$requestedCwd（解析为 $cwd）',
            instruction: '传目录路径；读文件用 read_file。',
            meta: WorkspaceToolMetadata(
              tool: tool,
              status: 'error',
              code: 'cwd_not_a_directory',
              command: command,
            ),
          );
        }
      } on PathResolutionException {
        // 解析失败按区外处理，避免把异常当成功。
        return _errorResult(
          tool: tool,
          error: 'invalid_cwd',
          message: 'cwd 无法解析到沙盒分区：$requestedCwd',
          meta: WorkspaceToolMetadata(
            tool: tool,
            status: 'error',
            code: 'invalid_cwd',
            command: command,
          ),
        );
      }
    }
    final env = <String, String>{
      if (!sandboxed) ...Platform.environment,
      'NO_COLOR': '1',
      'CI': 'true',
      'PAGER': 'cat',
      'TERM': 'dumb',
      'LANG': 'C.UTF-8',
      'HOME': sandboxed ? '/root' : (Platform.environment['HOME'] ?? ''),
      ...environment,
    };

    // 报告 2-3：落盘件必须是**全量**。这里边跑边把**归一化后**的文本 tee 到两个
    // 临时文件（stdout/stderr 各一，进度条帧替换语义与内联一致，但不设字节上限），
    // 需要落盘时按顺序拼成完整文件。
    // 放在系统临时目录：会话目录会被文件快照扫描，临时件不该出现在 changed_files。
    final teeDir = await Directory.systemTemp.createTemp('solab-shell-tee-');
    final stdoutPart = File(p.join(teeDir.path, 'stdout.part'));
    final stderrPart = File(p.join(teeDir.path, 'stderr.part'));
    IOSink? stdoutSink = stdoutPart.openWrite();
    IOSink? stderrSink = stderrPart.openWrite();
    final runtimeRunId = const Uuid().v4();
    final run = registry.start(
      toolCallId,
      tool,
      command: command,
      conversationId: conversationId ?? ctx.conversationId,
      // tee 归一化文本（全量），供落盘用。
      onStdoutText: (text) => stdoutSink?.add(utf8.encode(text)),
      onStderrText: (text) => stderrSink?.add(utf8.encode(text)),
      runtimeRunId: runtimeRunId,
    );
    final before = await FileSnapshot.snapshot([
      Directory(ctx.paths.workspaceHostRoot),
      ctx.sessionDir,
    ]);


    CommandExited? exited;
    Object? executionError;
    var executing = false;
    try {
      cancellation?.throwIfCancelled();
      executing = true;
      unawaited(
        cancellation?.cancelled.then((_) async {
          if (executing) await runtime.cancel(runtimeRunId);
        }),
      );
      await for (final event in runtime.run(
        CommandRequest(
          runId: runtimeRunId,
          isCancelled: cancellation?.isCancelled,
          command: command,
          cwd: cwd,
          timeout: Duration(seconds: timeoutSeconds),
          env: env,
          mounts: ctx.paths.runtimeMounts,
        ),
      )) {
        switch (event) {
          case CommandStarted():
            break;
          case CommandOutput(:final kind, :final bytes):
            // tee 由 ShellOutputBuffer.onText 驱动（归一化后），这里只做缓冲。
            if (kind == OutputStreamKind.stdout) {
              run.appendStdout(bytes);
            } else {
              run.appendStderr(bytes);
            }
          case CommandExited():
            exited = event;
        }
      }
    } catch (e) {
      executionError = e;
    } finally {
      executing = false;
      // A failed or cancelled command may still have installed/updated files.
      // Refresh observers without turning a refresh failure into a tool error.
      try {
        await onShellCompleted?.call();
      } catch (error) {
        debugPrint('Workspace post-command refresh failed: $error');
      }
    }

    final runStatus = executionError != null || exited == null
        ? ToolRunStatus.failed
        : exited.cancelled
        ? ToolRunStatus.cancelled
        : exited.timedOut
        ? ToolRunStatus.timedOut
        : exited.exitCode == 0
        ? ToolRunStatus.succeeded
        : ToolRunStatus.failed;
    run.complete(status: runStatus, exitCode: exited?.exitCode);
    // run.complete() 会把 buffer 收尾（close → 残行也 tee 出来），所以 tee 必须在
    // 它之后关闭：否则最后一行不完整（报告 2-3 的「全量」就成了空话）。
    try {
      await stdoutSink.flush();
      await stdoutSink.close();
      await stderrSink.flush();
      await stderrSink.close();
    } catch (_) {
      // 落盘补写失败不影响命令结果；下面按无 tee 文件降级。
    }
    stdoutSink = null;
    stderrSink = null;
    try {
      await teeDir.delete(recursive: true);
    } catch (_) {}
    final stdout = run.stdoutSoFar;
    final stderr = run.stderrSoFar;

    final after = await FileSnapshot.snapshot([
      Directory(ctx.paths.workspaceHostRoot),
      ctx.sessionDir,
    ]);
    final changedHost = FileSnapshot.changedSince(before, after);
    final files = <WorkspaceToolFile>[];
    for (final hostPath in changedHost.take(_changedFilesCap)) {
      final modelPath = ctx.paths.toModelPath(hostPath);
      try {
        final resolved = await ctx.paths.resolveReal(modelPath, cwd: cwd);
        if (!await FileSystemEntity.isFile(resolved.hostPath)) continue;
        files.add(
          _fileFor(
            ctx,
            resolved,
            role: before.containsKey(hostPath)
                ? WorkspaceFileRole.modified
                : WorkspaceFileRole.created,
          ),
        );
      } on PathResolutionException {
        files.add(
          WorkspaceToolFile(path: modelPath, role: WorkspaceFileRole.modified),
        );
      } on FileSystemException {
        // A file removed again before collection is not a remaining output.
      }
    }
    final filesTruncated =
        changedHost.length > _changedFilesCap ||
        before.length >= FileSnapshot.defaultMaxEntries ||
        after.length >= FileSnapshot.defaultMaxEntries;

    if (executionError != null || exited == null) {
      return _errorResult(
        tool: tool,
        error: 'shell_failed',
        message:
            executionError?.toString() ?? 'Command ended without an exit event',
        meta: WorkspaceToolMetadata(
          tool: tool,
          status: 'error',
          code: 'shell_failed',
          command: command,
          stdoutPreview: stdout,
          stderrPreview: stderr,
          files: files,
          filesTruncated: filesTruncated,
        ),
      );
    }

    final offload = await ToolOutputOffloader.maybeOffload(
      toolCallId: toolCallId,
      stdout: stdout,
      stderr: stderr,
      outputsDir: ctx.outputsDir,
      stdoutPartFile: stdoutPart,
      stderrPartFile: stderrPart,
    );
    final payload = _shellPayload(offload.modelText);
    payload['exit_code'] = exited.exitCode;
    // 入参被改写就如实回显（报告 2-1/2-2 的口径）。
    if (requestedCwd.trim().isNotEmpty) payload['cwd_requested'] = requestedCwd;
    payload['cwd'] = cwd;
    payload['timeout_seconds'] = timeoutSeconds;
    if (timeoutClamped) {
      payload['timeout_seconds_requested'] = requestedTimeout;
      payload['timeout_clamped'] = true;
      payload['timeout_note'] =
          'timeout_seconds 被钳到 [$timeoutSeconds]（允许范围 1..3600）。';
    }
    if (offload.offloadHostPath != null) {
      payload['output_file_bytes'] = offload.fileBytes;
      payload['output_file_truncated'] = offload.fileTruncated;
      payload['output_file_note'] = offload.fileTruncated
          ? '落盘件为完整输出的前 ${ToolOutputOffloader.maxFileBytes} 字节，文件内已标注省略量。'
          : '落盘件为完整输出（stdout 与 stderr 顺序拼接）。';
    }
    payload['duration_ms'] = exited.duration.inMilliseconds;
    payload['timed_out'] = exited.timedOut;
    payload['cancelled'] = exited.cancelled;
    payload['interrupted'] = exited.interrupted;
    if (run.stdoutTruncated || run.stderrTruncated) {
      payload['truncated'] = true;
    }
    if (files.isNotEmpty) {
      payload['changed_files'] = [for (final file in files) file.path];
    }
    if (filesTruncated) payload['changed_files_truncated'] = true;
    if (offload.offloadHostPath != null) {
      final outputFile = ctx.paths.toModelPath(offload.offloadHostPath!);
      payload['output_file'] = outputFile;
      payload['truncated'] = true;
      final resolved = await ctx.paths.resolveReal(outputFile, cwd: cwd);
      files.add(_fileFor(ctx, resolved, role: WorkspaceFileRole.log));
    }

    final metaStatus = exited.timedOut
        ? 'timeout'
        : exited.cancelled
        ? 'cancelled'
        : 'ok';
    final meta = WorkspaceToolMetadata(
      tool: tool,
      status: metaStatus,
      command: command,
      exitCode: exited.exitCode,
      durationMs: exited.duration.inMilliseconds,
      timedOut: exited.timedOut,
      cancelled: exited.cancelled,
      interrupted: exited.interrupted,
      stdoutPreview: utf16SafeCut(stdout, _previewLimit, keepTail: true),
      stderrPreview: utf16SafeCut(stderr, _previewLimit, keepTail: true),
      files: files,
      filesTruncated: filesTruncated,
      truncated: payload['truncated'] == true,
    );
    await _markToolsUsed(
      ctx,
      conversationId: conversationId,
      status: metaStatus,
    );
    return ClientToolResult(jsonEncode(payload), metadata: meta.toJson());
  }

  Future<Object?> _handleViewImage(
    WorkspaceToolContext ctx,
    Map<String, dynamic> args,
  ) async {
    const tool = 'view_image';
    final path = args['path'];
    if (path is! String || path.trim().isEmpty) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'path must be a non-empty string',
      );
    }
    try {
      final resolved = await ctx.paths.resolveReal(path, cwd: ctx.cwd);
      ToolCallCancellation.current?.throwIfCancelled();
      if (ctx.paths.sandboxed && resolved.zone == WorkspaceZone.outside) {
        throw const PathResolutionException('Path is outside sandbox zones');
      }
      final image = await WorkspaceImage.read(resolved.hostPath);
      ToolCallCancellation.current?.throwIfCancelled();
      final imagesDir = await AppDirectories.getImagesDirectory();
      await imagesDir.create(recursive: true);
      final extension = image.mime == 'image/png' ? 'png' : 'jpg';
      final snapshot = File(
        p.join(imagesDir.path, 'view_image_${const Uuid().v4()}.$extension'),
      );
      await snapshot.writeAsBytes(image.bytes);
      final uri = SandboxPathResolver.canonicalize(snapshot.path);
      await _markToolsUsed(
        ctx,
        conversationId: ctx.conversationId,
        status: 'ok',
      );
      return ClientToolResult(
        'Image (${image.width} x ${image.height}).\n![](${encodeMarkdownImageDestination(uri)})',
        metadata: {
          ...WorkspaceToolMetadata(
            tool: tool,
            status: 'ok',
            path: resolved.modelPath,
            files: [_fileFor(ctx, resolved)],
          ).toJson(),
          kMcpResultMetadataKey: mcpResultMetadata([uri]),
        },
      );
    } on HostFileException catch (e) {
      return _errorResult(
        tool: tool,
        error: 'view_image_failed',
        message: e.message,
      );
    } on PathResolutionException catch (e) {
      return _errorResult(tool: tool, error: 'path_error', message: e.message);
    }
  }

  Future<Object?> _handleReadFile(
    WorkspaceToolContext ctx,
    Map<String, dynamic> args,
  ) async {
    const tool = 'read_file';
    final path = _stringArg(args, 'path');
    if (path.isEmpty) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'path is required',
      );
    }
    try {
      final resolved = await ctx.paths.resolveReal(path, cwd: ctx.cwd);
      if (ctx.skillsOnly && resolved.zone != WorkspaceZone.skills) {
        return _errorResult(
          tool: tool,
          error: 'path_outside_skills',
          message: 'read_file is limited to /skills in skills-only mode',
        );
      }
      if (ctx.paths.sandboxed && resolved.zone == WorkspaceZone.outside) {
        return _deniedResult(
          tool: tool,
          error: 'path_outside',
          message: 'Reads outside the workspace are not allowed',
          path: resolved.modelPath,
        );
      }
      final result = await HostFileTools(ctx.paths).readFile(
        path,
        offset: _intArg(args, 'offset'),
        limit: _intArg(args, 'limit'),
        cwd: ctx.cwd,
      );
      final meta = WorkspaceToolMetadata(
        tool: tool,
        status: 'ok',
        path: resolved.modelPath,
        files: [_fileFor(ctx, resolved)],
      );
      if (result.imageBytes != null) {
        final uri = resolved.hostPath;
        await _maybeNoteSkillRead(ctx, resolved);
        await _markToolsUsed(
          ctx,
          conversationId: ctx.conversationId,
          status: 'ok',
        );
        return ClientToolResult(
          '![](${encodeMarkdownImageDestination(uri)})',
          metadata: <String, dynamic>{
            ...meta.toJson(),
            kMcpResultMetadataKey: mcpResultMetadata([uri]),
          },
        );
      }
      if (result.binary) {
        await _maybeNoteSkillRead(ctx, resolved);
        await _markToolsUsed(
          ctx,
          conversationId: ctx.conversationId,
          status: 'ok',
        );
        return ClientToolResult(
          jsonEncode(<String, Object?>{
            'binary': true,
            'hex_preview': result.hexPreview ?? '',
          }),
          metadata: meta.toJson(),
        );
      }
      final text = result.text ?? '';
      final content = result.nextOffset == null
          ? text
          : '$text(more lines: use offset=${result.nextOffset})';
      await _maybeNoteSkillRead(ctx, resolved);
      await _markToolsUsed(
        ctx,
        conversationId: ctx.conversationId,
        status: 'ok',
      );
      return ClientToolResult(content, metadata: meta.toJson());
    } on HostFileException catch (e) {
      return _errorResult(tool: tool, error: 'read_failed', message: e.message);
    } on PathResolutionException catch (e) {
      if (ctx.skillsOnly) {
        return _errorResult(
          tool: tool,
          error: 'path_outside_skills',
          message: e.message,
        );
      }
      return _errorResult(tool: tool, error: 'path_error', message: e.message);
    }
  }

  Future<Object?> _handleWriteFile(
    WorkspaceToolContext ctx,
    Map<String, dynamic> args, {
    required String toolCallId,
    ToolApprovalService? approvalService,
    String? conversationId,
  }) async {
    const tool = 'write_file';
    final path = _stringArg(args, 'path');
    if (path.isEmpty) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'path is required',
      );
    }
    final content = args.containsKey('content')
        ? args['content']?.toString() ?? ''
        : null;
    if (content == null) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'content is required',
      );
    }
    late final ResolvedPath resolved;
    try {
      resolved = await ctx.paths.resolveReal(path, cwd: ctx.cwd);
    } on PathResolutionException catch (e) {
      return _errorResult(tool: tool, error: 'path_error', message: e.message);
    }

    final denied = await _approveWrite(
      ctx,
      resolved,
      tool: tool,
      args: args,
      toolCallId: toolCallId,
      approvalService: approvalService,
      conversationId: conversationId,
    );
    if (denied != null) return denied;

    try {
      final result = await HostFileTools(
        ctx.paths,
        checkCancelled: ToolCallCancellation.current?.throwIfCancelled,
      ).writeFile(path, content, cwd: ctx.cwd);
      final link = linkFor(resolved, paths: ctx.paths);
      final body = <String, Object?>{
        'ok': true,
        'path': resolved.modelPath,
        'bytes': result.bytes,
        'created': result.created,
        if (link != null) 'link': link,
      };
      final meta = WorkspaceToolMetadata(
        tool: tool,
        status: 'ok',
        path: resolved.modelPath,
        files: [
          _fileFor(
            ctx,
            resolved,
            role: result.created
                ? WorkspaceFileRole.created
                : WorkspaceFileRole.modified,
          ),
        ],
        created: result.created,
        bytes: result.bytes,
      );
      await _markToolsUsed(ctx, conversationId: conversationId, status: 'ok');
      return ClientToolResult(jsonEncode(body), metadata: meta.toJson());
    } on HostFileException catch (e) {
      return _hostFileFailure(
        tool: tool,
        error: 'write_failed',
        message: e.message,
      );
    }
  }

  Future<Object?> _handleEditFile(
    WorkspaceToolContext ctx,
    Map<String, dynamic> args, {
    required String toolCallId,
    ToolApprovalService? approvalService,
    String? conversationId,
  }) async {
    const tool = 'edit_file';
    final path = _stringArg(args, 'path');
    if (path.isEmpty) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'path is required',
      );
    }
    if (!args.containsKey('old_string') || !args.containsKey('new_string')) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'old_string and new_string are required',
      );
    }
    late final ResolvedPath resolved;
    try {
      resolved = await ctx.paths.resolveReal(path, cwd: ctx.cwd);
    } on PathResolutionException catch (e) {
      return _errorResult(tool: tool, error: 'path_error', message: e.message);
    }

    final denied = await _approveWrite(
      ctx,
      resolved,
      tool: tool,
      args: args,
      toolCallId: toolCallId,
      approvalService: approvalService,
      conversationId: conversationId,
    );
    if (denied != null) return denied;

    try {
      final result =
          await HostFileTools(
            ctx.paths,
            checkCancelled: ToolCallCancellation.current?.throwIfCancelled,
          ).editFile(
            path,
            args['old_string']?.toString() ?? '',
            args['new_string']?.toString() ?? '',
            replaceAll: _boolArg(args, 'replace_all'),
            cwd: ctx.cwd,
          );
      final link = linkFor(resolved, paths: ctx.paths);
      final body = <String, Object?>{
        'ok': true,
        'path': resolved.modelPath,
        'replacements': result.replacements,
        'strategy': result.strategy,
        'added': result.diff.added,
        'removed': result.diff.removed,
        if (link != null) 'link': link,
      };
      final meta = WorkspaceToolMetadata(
        tool: tool,
        status: 'ok',
        path: resolved.modelPath,
        files: [
          _fileFor(
            ctx,
            resolved,
            role: result.changed
                ? WorkspaceFileRole.modified
                : WorkspaceFileRole.referenced,
          ),
        ],
        diff: result.diff.text,
        added: result.diff.added,
        removed: result.diff.removed,
        diffTruncated: result.diff.truncated,
        strategy: result.strategy,
      );
      await _markToolsUsed(ctx, conversationId: conversationId, status: 'ok');
      return ClientToolResult(jsonEncode(body), metadata: meta.toJson());
    } on HostFileException catch (e) {
      return _hostFileFailure(
        tool: tool,
        error: 'edit_failed',
        message: e.message,
      );
    }
  }

  Future<Object?> _handleListDir(
    WorkspaceToolContext ctx,
    Map<String, dynamic> args,
  ) async {
    const tool = 'list_dir';
    final path = _stringArg(args, 'path', fallback: ctx.cwd);
    try {
      final result = await HostFileTools(
        ctx.paths,
      ).listDir(path, depth: _intArg(args, 'depth') ?? 1, cwd: ctx.cwd);
      final lines = <String>[
        for (final entry in result.entries)
          entry.isDirectory ? '${entry.path}/' : '${entry.path}  ${entry.size}',
      ];
      if (result.truncated) lines.add('... truncated');
      ResolvedPath? resolved;
      try {
        resolved = await ctx.paths.resolveReal(path, cwd: ctx.cwd);
      } catch (_) {}
      final meta = WorkspaceToolMetadata(
        tool: tool,
        status: 'ok',
        path: resolved?.modelPath,
        files: await _referencedFiles(ctx, [
          if (resolved != null) resolved.modelPath,
          for (final entry in result.entries) entry.path,
        ]),
        filesTruncated: result.truncated,
        count: result.entries.length,
        truncated: result.truncated,
      );
      await _markToolsUsed(
        ctx,
        conversationId: ctx.conversationId,
        status: 'ok',
      );
      return ClientToolResult(lines.join('\n'), metadata: meta.toJson());
    } on HostFileException catch (e) {
      return _errorResult(tool: tool, error: 'list_failed', message: e.message);
    } on PathResolutionException catch (e) {
      return _errorResult(tool: tool, error: 'path_error', message: e.message);
    }
  }

  Future<Object?> _handleGlob(
    WorkspaceToolContext ctx,
    Map<String, dynamic> args,
  ) async {
    const tool = 'glob';
    final pattern = _stringArg(args, 'pattern');
    if (pattern.isEmpty) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'pattern is required',
      );
    }
    try {
      final result = await HostFileTools(
        ctx.paths,
      ).glob(pattern, path: _optionalString(args, 'path'), cwd: ctx.cwd);
      final lines = List<String>.from(result.paths);
      if (result.truncated) lines.add('... truncated');
      final meta = WorkspaceToolMetadata(
        tool: tool,
        status: 'ok',
        files: await _referencedFiles(ctx, result.paths),
        filesTruncated: result.truncated,
        count: result.paths.length,
        truncated: result.truncated,
      );
      await _markToolsUsed(
        ctx,
        conversationId: ctx.conversationId,
        status: 'ok',
      );
      return ClientToolResult(lines.join('\n'), metadata: meta.toJson());
    } on HostFileException catch (e) {
      return _errorResult(tool: tool, error: 'glob_failed', message: e.message);
    } on PathResolutionException catch (e) {
      return _errorResult(tool: tool, error: 'path_error', message: e.message);
    }
  }

  Future<Object?> _handleGrep(
    WorkspaceToolContext ctx,
    Map<String, dynamic> args,
  ) async {
    const tool = 'grep';
    final pattern = _stringArg(args, 'pattern');
    if (pattern.isEmpty) {
      return _errorResult(
        tool: tool,
        error: 'invalid_arguments',
        message: 'pattern is required',
      );
    }
    try {
      final result = await HostFileTools(ctx.paths).grep(
        pattern,
        path: _optionalString(args, 'path'),
        cwd: ctx.cwd,
        ignoreCase: _boolArg(args, 'ignore_case'),
        limit: _intArg(args, 'limit') ?? HostFileTools.defaultGrepLimit,
      );
      final lines = [for (final match in result.matches) match.display];
      if (result.truncated) lines.add('... truncated');
      final meta = WorkspaceToolMetadata(
        tool: tool,
        status: 'ok',
        files: await _referencedFiles(
          ctx,
          result.matches.map((match) => match.path),
        ),
        filesTruncated: result.truncated,
        count: result.matches.length,
        truncated: result.truncated,
      );
      await _markToolsUsed(
        ctx,
        conversationId: ctx.conversationId,
        status: 'ok',
      );
      return ClientToolResult(lines.join('\n'), metadata: meta.toJson());
    } on HostFileException catch (e) {
      return _errorResult(tool: tool, error: 'grep_failed', message: e.message);
    } on PathResolutionException catch (e) {
      return _errorResult(tool: tool, error: 'path_error', message: e.message);
    }
  }

  Future<Object?> _approveWrite(
    WorkspaceToolContext ctx,
    ResolvedPath resolved, {
    required String tool,
    required Map<String, dynamic> args,
    required String toolCallId,
    ToolApprovalService? approvalService,
    String? conversationId,
  }) async {
    if (ctx.paths.isReadOnlyPath(resolved.hostPath)) {
      return _deniedResult(
        tool: tool,
        error: 'mount_readonly',
        message: 'This external mount is read-only',
        path: resolved.modelPath,
      );
    }
    if (resolved.zone == WorkspaceZone.skills) {
      return _deniedResult(
        tool: tool,
        error: 'skills_readonly',
        message: 'The skills zone is read-only',
        path: resolved.modelPath,
      );
    }
    if (resolved.zone == WorkspaceZone.outside) {
      if (ctx.paths.sandboxed) {
        return _deniedResult(
          tool: tool,
          error: 'path_outside',
          message: 'Writes outside the workspace are not allowed',
          path: resolved.modelPath,
        );
      }
      return _maybeApprove(
        approvalService,
        needed: true,
        toolCallId: toolCallId,
        toolName: tool,
        args: args,
        conversationId: conversationId ?? ctx.conversationId,
        path: resolved.modelPath,
        workspaceName: ctx.workspace.name,
      );
    }
    return null;
  }

  Future<Object?> _maybeApprove(
    ToolApprovalService? approvalService, {
    required bool needed,
    required String toolCallId,
    required String toolName,
    required Map<String, dynamic> args,
    String? conversationId,
    String? path,
    String? workspaceName,
  }) async {
    ToolCallCancellation.current?.throwIfCancelled();
    if (!needed) return null;
    final name = (workspaceName ?? '').trim();
    final where = name.isEmpty ? '该工作区' : '工作区「$name」';
    if (approvalService == null) {
      // MCP 面没有批准通道。过去这里回 approval_denied + "User denied the
      // tool call"，把「没人可问」说成「你拒绝了」——真机实测调用方据此误判
      // （2026-10-05）。独立错误码 + 指名到具体工作区的指引。
      return _deniedResult(
        tool: toolName,
        error: 'approval_unavailable',
        message: '$where 设置了「运行终端命令前询问」，但当前调用面（MCP）'
            '没有批准通道，无法弹出确认框。请到 设置 → 工作区 → $where 里'
            '关闭该开关后重试，或改用应用内对话执行本工具。',
        path: path,
      );
    }
    final id = toolCallId.trim().isEmpty
        ? '${toolName}_${DateTime.now().microsecondsSinceEpoch}'
        : toolCallId;
    final result = await approvalService.requestApproval(
      toolCallId: id,
      toolName: toolName,
      arguments: args,
      conversationId: conversationId,
    );
    if (result.approved) return null;
    return _deniedResult(
      tool: toolName,
      error: 'approval_denied',
      message: result.denyReason ?? 'User denied the tool call',
      path: path,
    );
  }

  Future<void> _markToolsUsed(
    WorkspaceToolContext ctx, {
    String? conversationId,
    required String status,
  }) async {
    if (ctx.skillsOnly) return;
    if (status != 'ok') return;
    if (ctx.binding.toolsUsed) return;
    final id = conversationId ?? ctx.conversationId;
    if (id == null || id.isEmpty) return;
    try {
      await updateConversationExtras?.call(id, (extras) {
        final current = WorkspaceBinding.fromExtras(extras);
        if (current.workspaceId != ctx.binding.workspaceId) return extras;
        return WorkspaceBinding(
          workspaceId: current.workspaceId,
          cwd: current.cwd,
          toolsUsed: true,
          allowAll: current.allowAll,
        ).applyTo(extras);
      });
      await touchLastUsed?.call(ctx.workspace.id);
    } catch (e) {
      debugPrint('Failed to mark workspace tools used: $e');
    }
  }

  static ClientToolResult _errorResult({
    required String tool,
    required String error,
    required String message,
    String? instruction,
    WorkspaceToolMetadata? meta,
  }) {
    return ClientToolResult(
      jsonEncode(<String, Object?>{
        'type': 'tool_error',
        // F-39（2026-10-04）：E 形补 ok/code/recoverable——过去只有
        // type+error 字符串，只读 `ok` 或只读 `code` 的失败判定拿不到信号。
        'ok': false,
        'code': error,
        'recoverable': false,
        'error': error,
        'message': message,
        'tool': tool,
        if (instruction != null) 'instruction': instruction,
      }),
      metadata:
          (meta ??
                  WorkspaceToolMetadata(
                    tool: tool,
                    status: 'error',
                    code: error,
                  ))
              .toJson(),
    );
  }

  static ClientToolResult _deniedResult({
    required String tool,
    required String error,
    required String message,
    String? path,
  }) {
    return ClientToolResult(
      jsonEncode(<String, Object?>{
        'type': 'tool_error',
        'ok': false,
        'code': error,
        'recoverable': false,
        'error': error,
        'message': message,
        'tool': tool,
      }),
      metadata: WorkspaceToolMetadata(
        tool: tool,
        status: 'denied',
        code: error,
        path: path,
      ).toJson(),
    );
  }

  static ClientToolResult _hostFileFailure({
    required String tool,
    required String error,
    required String message,
  }) {
    return ClientToolResult(
      jsonEncode(<String, Object?>{'error': error, 'message': message}),
      metadata: WorkspaceToolMetadata(
        tool: tool,
        status: 'error',
        code: error,
      ).toJson(),
    );
  }

  static Map<String, dynamic> _fn(
    String name,
    List<String> description,
    Map<String, dynamic> properties,
    List<String> required,
  ) {
    return <String, dynamic>{
      'type': 'function',
      'function': <String, dynamic>{
        'name': name,
        if (name == 'view_image') 'strict': false,
        'description': description.join(' '),
        'parameters': <String, dynamic>{
          'type': 'object',
          'properties': properties,
          if (name == 'view_image') 'additionalProperties': false,
          if (required.isNotEmpty) 'required': required,
        },
      },
    };
  }

  static List<String> _pathVocab(WorkspacePaths paths) {
    if (paths.sandboxed) {
      return [
        WorkspacePaths.guestWorkspace,
        WorkspacePaths.guestChat,
        WorkspacePaths.guestSkills,
        WorkspacePaths.guestTmp,
        ExternalMount.root,
      ];
    }
    return [
      paths.workspaceHostRoot,
      paths.sessionHostDir,
      paths.skillsHostDir,
      paths.tmpHostRoot,
    ];
  }

  static String _engineLine(WorkspaceToolContext ctx) {
    final status = ctx.runtimeStatus;
    if (!ctx.runtimeRegistered || status == null || !status.ready) {
      return 'Sandbox environment not installed — `shell` will fail until the user installs it';
    }
    switch (status.engine) {
      case 'proot':
        return 'Engine: Linux (PRoot); check /etc/os-release for distro';
      case 'ish':
        return 'Engine: Alpine (iSH)';
      case 'process':
      case 'fake':
        return 'Engine: native shell';
      default:
        return 'Engine: ${status.engine}';
    }
  }

  static Map<String, dynamic> _shellPayload(String modelText) {
    final jsonLine = modelText.split('\n').first;
    try {
      final decoded = jsonDecode(jsonLine);
      if (decoded is Map) return Map<String, dynamic>.from(decoded);
    } catch (_) {}
    return <String, dynamic>{'stdout': modelText, 'stderr': ''};
  }

  Future<void> _maybeNoteSkillRead(
    WorkspaceToolContext ctx,
    ResolvedPath resolved,
  ) async {
    if (onSkillRead == null) return;
    if (resolved.zone != WorkspaceZone.skills) return;
    final base = p.basename(resolved.hostPath.replaceAll('\\', '/'));
    final modelBase = p.posix.basename(
      resolved.modelPath.replaceAll('\\', '/'),
    );
    // Windows path canonicalization lowercases SKILL.md along with its parents.
    if (base.toLowerCase() != 'skill.md' &&
        modelBase.toLowerCase() != 'skill.md') {
      return;
    }
    final skillId = _skillIdUnderSkillsRoot(ctx, resolved);
    if (skillId == null || skillId.isEmpty) return;
    try {
      await onSkillRead!(skillId);
    } catch (e) {
      debugPrint('onSkillRead failed: $e');
    }
  }

  static String? _skillIdUnderSkillsRoot(
    WorkspaceToolContext ctx,
    ResolvedPath resolved,
  ) {
    final model = resolved.modelPath.replaceAll('\\', '/');
    const prefix = '${WorkspacePaths.guestSkills}/';
    if (model.startsWith(prefix)) {
      final rel = model.substring(prefix.length);
      if (rel.isEmpty) return null;
      return rel.split('/').first;
    }
    final rel = WorkspacePaths.relativeToHostRoot(
      ctx.paths.skillsHostDir,
      resolved.hostPath,
    );
    if (rel != null && rel.isNotEmpty) {
      return rel.replaceAll('\\', '/').split('/').first;
    }
    try {
      final root = p.canonicalize(
        Directory(ctx.paths.skillsHostDir).resolveSymbolicLinksSync(),
      );
      final host = p.canonicalize(
        File(resolved.hostPath).resolveSymbolicLinksSync(),
      );
      if (p.isWithin(root, host)) {
        return p
            .relative(host, from: root)
            .replaceAll('\\', '/')
            .split('/')
            .first;
      }
    } catch (_) {}
    return null;
  }

  static String _stringArg(
    Map<String, dynamic> args,
    String key, {
    String fallback = '',
  }) {
    final value = args[key];
    if (value == null) return fallback;
    return value.toString();
  }

  static String? _optionalString(Map<String, dynamic> args, String key) {
    final value = args[key];
    if (value == null) return null;
    final text = value.toString();
    return text.isEmpty ? null : text;
  }

  static int? _intArg(Map<String, dynamic> args, String key) {
    final value = args[key];
    if (value == null) return null;
    if (value is int) return value;
    if (value is num) return value.toInt();
    return int.tryParse(value.toString());
  }

  static bool _boolArg(Map<String, dynamic> args, String key) {
    final value = args[key];
    if (value is bool) return value;
    if (value is String) return value.toLowerCase() == 'true';
    return false;
  }

  /// 在沙盒里跑一条命令并把输出收齐（Frida 运行期驱动的执行口）。
  ///
  /// 与 `shell` 工具复用同一个 runtime.run(...)：同一个环境、同一套 mounts，
  /// 不新开旁路。命令字符串由调用方（FridaSandboxRuntime）拼装，路径全是常量。
  Future<FridaExecResult> _execInSandbox(
    WorkspaceToolContext ctx,
    String command,
    int timeoutMs,
  ) async {
    final runtime = runtimeProvider.runtime;
    if (runtime == null) {
      return const FridaExecResult(
        exitCode: 127,
        stderr: 'sandbox runtime is not registered',
      );
    }
    final stdout = StringBuffer();
    final stderr = StringBuffer();
    var exitCode = -1;
    try {
      await for (final event in runtime.run(
        CommandRequest(
          runId: 'frida-${DateTime.now().microsecondsSinceEpoch}',
          command: command,
          cwd: ctx.cwd,
          timeout: Duration(milliseconds: timeoutMs),
          env: const <String, String>{},
          mounts: ctx.paths.runtimeMounts,
        ),
      )) {
        switch (event) {
          case CommandOutput(:final kind, :final bytes):
            final text = utf8.decode(bytes, allowMalformed: true);
            if (kind == OutputStreamKind.stdout) {
              stdout.write(text);
            } else {
              stderr.write(text);
            }
          case CommandExited():
            exitCode = event.exitCode;
          default:
            break;
        }
      }
    } catch (error) {
      stderr.write(error.toString());
    }
    return FridaExecResult(
      exitCode: exitCode,
      stdout: stdout.toString(),
      stderr: stderr.toString(),
    );
  }
}
