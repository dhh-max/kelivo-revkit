import 'core/services/scheduled_tasks_service.dart';
import 'package:Kelivo/core/services/sandbox/workspace_channel.dart';
import 'package:Kelivo/core/providers/external_mounts_provider.dart';
import 'package:Kelivo/core/services/sandbox/environment_dependencies.dart';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart'
    show defaultTargetPlatform, TargetPlatform, kIsWeb;
import 'dart:async';
import 'dart:ui' show AppExitResponse;
import 'l10n/app_localizations.dart';
import 'features/home/pages/home_page.dart';
import 'features/mcp/pages/mcp_host_mode_page.dart';
import 'features/backup/local_snapshot_scheduler.dart';
import 'features/migration/hive_to_sqlite_migration_page.dart';
import 'features/migration/hive_to_sqlite_migration_service.dart';
import 'package:flutter/services.dart';
// import 'package:logging/logging.dart' as logging;
// Theme is now managed in SettingsProvider
import 'theme/theme_factory.dart';
import 'theme/palettes.dart';
import 'theme/custom_theme.dart';
import 'package:provider/provider.dart';
import 'package:dynamic_color/dynamic_color.dart';
import 'core/providers/user_provider.dart';
import 'core/providers/settings_provider.dart';
import 'core/services/api/model_catalog_auto_refresh.dart';
import 'core/providers/mcp_provider.dart';
import 'core/providers/tts_provider.dart';
import 'core/providers/asr_provider.dart';
import 'core/providers/assistant_provider.dart';
import 'core/providers/tag_provider.dart';
import 'core/providers/quick_phrase_provider.dart';
import 'core/providers/instruction_injection_provider.dart';
import 'core/providers/instruction_injection_group_provider.dart';
import 'core/providers/world_book_provider.dart';
import 'core/providers/agent_skill_provider.dart';
import 'core/providers/memory_provider.dart';
import 'core/providers/memory_provider_v2.dart';
import 'core/providers/backup_provider.dart';
import 'core/providers/local_snapshot_provider.dart';
import 'core/services/backup/backup_activity.dart';
import 'core/services/backup/local_snapshot_schedule.dart';
import 'core/services/api/api_session_scope.dart';
import 'core/services/android_background.dart';
import 'core/services/app_exit_flush.dart';
import 'shared/widgets/restore_progress_screen.dart';
import 'features/home/controllers/chat_actions.dart';
import 'core/services/memory/memory_pipeline.dart';
import 'core/services/memory/memory_repository.dart';
import 'core/providers/s3_backup_provider.dart';
import 'core/providers/backup_reminder_provider.dart';
import 'core/providers/workspace_provider.dart';
import 'core/services/workspace/workspace_runtime.dart';
import 'core/services/workspace/workspace_binding_actions.dart';
import 'core/providers/environment_provider.dart';
import 'features/workspace/pages/environment_page.dart';
import 'features/workspace/pages/workspaces_page.dart';
import 'features/home/services/tool_handler_service.dart';
import 'features/workspace/terminal/open_terminal.dart';
import 'features/workspace/widgets/files/conversation_files_panel.dart';
import 'features/workspace/workspace_navigation.dart';
import 'core/services/sandbox/environment_manager.dart';
import 'core/services/sandbox/mirror_service.dart';
import 'core/services/skills/skills_service.dart';
import 'core/services/workspace/tool_run_registry.dart';
import 'core/services/workspace/workspace_runtime_bootstrap.dart';
import 'core/services/workspace/workspace_tools_service.dart';
import 'features/workspace/terminal/terminal_session_manager.dart';
import 'core/database/extension_entity_store.dart';
import 'core/database/database_installation_gate.dart';
import 'core/database/app_database.dart';
import 'core/database/business_migration_engine.dart';
import 'core/database/business_preferences.dart';
import 'core/database/business_repository.dart';
import 'core/database/business_startup_gate.dart';
import 'core/database/chat_database_gateway.dart';
import 'core/services/chat/chat_service.dart';
import 'features/home/services/local_tools_service.dart';
import 'features/home/services/context_usage_service.dart';
import 'core/services/model_catalog/model_catalog_service.dart';
import 'core/services/backup/restore_archive_pruner.dart';
import 'core/services/backup/restore_business_lease.dart';
import 'core/services/backup/restore_startup_gate.dart';
import 'core/services/backup/restore_receipt.dart';
import 'core/services/mcp/mcp_tool_service.dart';
import 'core/services/mcp_server/mcp_http_server.dart';
import 'core/services/logging/flutter_logger.dart';
import 'features/home/services/ask_user_interaction_service.dart';
import 'features/home/services/session_mode.dart';
import 'features/home/services/tool_approval_service.dart';
import 'utils/app_directories.dart';
import 'utils/platform_utils.dart';
import 'utils/sandbox_path_resolver.dart';
import 'shared/widgets/app_overlays.dart';
import 'shared/widgets/snackbar.dart';
import 'shared/widgets/restore_failure_screen.dart';
import 'shared/widgets/restore_outcome_notice.dart';
import 'package:system_fonts/system_fonts.dart';
import 'dart:io'
    show
        Directory,
        File,
        Platform,
        stderr; // kept for global override usage inside provider
import 'core/services/mobile_background.dart';
import 'core/services/notification_service.dart';
import 'features/runtime/runtime_bridge.dart';
import 'features/runtime/task_session.dart';

import 'features/solab_apk/services/apk_patch_memory_service.dart';
import 'features/solab_apk/services/apk_progress_service.dart';
import 'features/solab_apk/services/apk_rule_service.dart';
import 'features/solab_apk/services/apk_workspace_binding_service.dart';
import 'features/solab_apk/services/apk_workspace_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

final RouteObserver<ModalRoute<dynamic>> routeObserver =
    RouteObserver<ModalRoute<dynamic>>();
// 更新检查已停用（SoLab APK 不依赖上游更新源），相关字段/Provider 一并移除。
bool _didEnsureAssistants = false; // ensure defaults after l10n ready
bool _didEnsureKeepAlive = false; // FGS/MCP server 启动只做一次（build 会重复注册回调）
bool _didWireWorkspace = false;
/// 按 provider 树构建一次的工作区工具服务（MCP 面共享；见 _wireWorkspaceServices）。
WorkspaceToolsService? _wiredWorkspaceTools;

void _wireWorkspaceServices(BuildContext ctx) {
  try {
    final chat = ctx.read<ChatService>();
    final workspaces = ctx.read<WorkspaceProvider>();
    final assistants = ctx.read<AssistantProvider>();
    chat.newConversationExtras = (assistantId) {
      if (assistantId == null) {
        return const <String, dynamic>{};
      }
      return workspaceExtrasForNewConversation(
        assistant: assistants.getById(assistantId),
        workspaceById: workspaces.byId,
      );
    };
    // 用户 2026-10-06：工作区已在设置里配好，助手就该默认绑定它。
    unawaited(
      ensureAssistantDefaultWorkspaceBound(
        assistants: assistants,
        workspaces: workspaces,
      ),
    );
    // MCP 面/后台链路没有 BuildContext：把同一批 provider 实例与工作区工具服务
    // （按当前树构建一次并缓存）注入解析器——MCP 模式才能发工作区/沙盒工具族
    // 并真正执行（用户 2026-10-06：「MCP 模式连沙盒环境都找不着」）。
    final wireRuntimeProvider = ctx.read<WorkspaceRuntimeProvider>();
    final wireMounts = ctx.read<ExternalMountsProvider?>();
    WorkspaceToolsService.workspaceProviderResolver = () => workspaces;
    WorkspaceToolsService.runtimeProviderResolver = () => wireRuntimeProvider;
    WorkspaceToolsService.externalMountsResolver = () => wireMounts;
    WorkspaceToolsService.sharedInstanceResolver = () =>
        _wiredWorkspaceTools ??= ToolHandlerService.workspaceToolsFor(ctx);
    WorkspaceNavigation.onOpenEnvironmentPage = openEnvironmentPage;
    WorkspaceNavigation.onOpenTerminal = (navContext, {command}) {
      openTerminal(
        navContext,
        conversationId: chat.currentConversationId,
        command: command,
      );
    };
    WorkspaceNavigation.onOpenWorkspaceFiles = (navContext, {path}) {
      final id = chat.currentConversationId;
      if (id != null) {
        showConversationFilesPanel(navContext, conversationId: id);
      } else {
        Navigator.of(
          navContext,
        ).push(MaterialPageRoute<void>(builder: (_) => const WorkspacesPage()));
      }
    };
  } catch (_) {}
}

/// v8-D14（2026-10-04）：技能注册表**启动即建**的共享实例。
///
/// 过去它只在 widget 的 `ChangeNotifierProvider.create`（惰性）里创建，MCP/
/// Agent 会话没触发那次 build 时 `LocalToolsService.agentSkillResolver` 恒 null，
/// `get_installed_skills` 回 skill_store_unavailable。现在在 main() 里先建好并
/// 挂 resolver，widget 树用同一实例。
late final AgentSkillProvider sharedAgentSkillProvider;

Future<void> main() async {
  await runZoned(
    () async {
      WidgetsFlutterBinding.ensureInitialized();
      // Register notification tap handling for every Android launch. This is
      // independent of the current background-chat mode: an older completion
      // notification can still launch the app after the mode has changed.
      // Initialization does not request notification permission.
      if (Platform.isAndroid || Platform.isIOS) {
        try {
          await NotificationService.ensureInitialized();
        } catch (_) {}
      }
      FlutterLogger.installGlobalHandlers();
      if (Platform.isAndroid) {
        // SoLab APK 原生分析进度监听（EventChannel 'solab/progress' 的消费方，
        // 此前进度事件发出后无任何监听方）。
        ApkProgressService.instance.ensureListening();
      }
      // 立即上首帧：后续初始化链（业务租约/恢复门/数据库准入）含重 IO，
      // 可能耗时数秒；先渲染零依赖启动页接管画面，避免引擎就绪后黑屏等待。
      runApp(const _StartupSplashApp());
      final appDataDirectory = await AppDirectories.getAppDataDirectory();
      RestoreReceipt? restoreOutcome;
      RestoreBusinessLease? businessLease;
      // A restore large enough to take seconds would otherwise spend all of
      // them before the first frame, which is indistinguishable from a hang.
      // Only paint when there is actually work waiting: an ordinary launch
      // must not pay for a frame it immediately replaces.
      final restoreStage =
          await RestoreStartupGate.hasPendingWork(
            appDataDirectory: appDataDirectory,
          )
          ? ValueNotifier(RestoreStartupStage.checkingBackup)
          : null;
      if (restoreStage != null) {
        runApp(_RestoreProgressApp(stage: restoreStage));
      }
      try {
        // The lease remains process-owned through its internal registry until
        // process exit, preventing another instance from racing business I/O.
        //
        // 重试窗口：Android 前台服务保活下旧引擎/isolate 的销毁是异步的，
        // 退出后立即重开可能撞上尚未释放的 flock/探针。短暂重试（约 3 秒）
        // 覆盖该窗口，避免用户看到「已在运行」失败屏后被迫手动重启。
        businessLease = await _acquireBusinessLeaseWithRetry(
          appDataDirectory,
        );
        restoreOutcome =
            await RestoreStartupGate.recoverAndRequireBusinessReady(
              appDataDirectory: appDataDirectory,
              businessLease: businessLease,
            );
      } catch (error, stackTrace) {
        stderr.writeln('[RestoreStartupGate] $error\n$stackTrace');
        runApp(
          _RestoreFailureApp(
            report: StartupFailureReport.capture(
              stage: StartupFailureStage.databaseAdmission,
              error: error,
              step: 'database_admission',
              stackTrace: StackTrace.current,
            ),
            appDataDirectory: appDataDirectory,
            businessLease: businessLease,
          ),
        );
        return;
      }
      try {
        final prefs = await SharedPreferences.getInstance();
        final enabled = prefs.getBool('flutter_log_enabled_v1') ?? false;
        await FlutterLogger.setEnabled(enabled);
      } catch (_) {}
      // Trim Flutter global image cache to reduce memory pressure from large images
      try {
        PaintingBinding.instance.imageCache.maximumSize = 200;
        PaintingBinding.instance.imageCache.maximumSizeBytes =
            48 << 20; // ~48MB
      } catch (_) {}
      // Avoid preloading all system fonts at launch (huge memory on desktop)
      // Debug logging and global error handlers were enabled previously for diagnosis.
      // They are commented out now per request to reduce log noise.
      // FlutterError.onError = (FlutterErrorDetails details) { ... };
      // WidgetsBinding.instance.platformDispatcher.onError = (Object error, StackTrace stack) { ... };
      // logging.Logger.root.level = logging.Level.ALL;
      // logging.Logger.root.onRecord.listen((rec) { ... });
      // Cache current Documents directory to fix sandboxed absolute paths on iOS
      await SandboxPathResolver.init();
      ChatDatabaseLease? processDatabaseLease;
      BusinessPreferences? businessPreferences;
      var recoveryAttempted = false;
      while (true) {
        try {
          final migrationDecision = await HiveToSqliteMigrationService.check();
          if (migrationDecision.needsMigration) {
            runApp(
              MigrationApp(
                service: HiveToSqliteMigrationService(migrationDecision),
                restoreOutcome: restoreOutcome?.state,
              ),
            );
            return;
          }
          await DatabaseInstallationGate.ensureReady(
            appDataDirectory: appDataDirectory,
            allowDatabaseIdentityChange:
                restoreOutcome?.selectedComponents.contains(
                  RestoreComponent.database,
                ) ??
                false,
          );
          final databaseFile = File(
            '${appDataDirectory.path}/${AppDatabase.databaseFileName}',
          );
          final databaseLease = await ChatDatabaseGateway.instance.acquire(
            databaseFile,
          );
          try {
            final legacyPreferences =
                await SharedPreferencesLegacyBusinessPreferences.open();
            final loadedBusinessPreferences =
                await BusinessStartupGate.migrateAndLoad(
                  repository: databaseLease.businessRepository,
                  legacyPreferences: legacyPreferences,
                );
            processDatabaseLease = databaseLease;
            businessPreferences = loadedBusinessPreferences;
          } catch (_) {
            await databaseLease.release();
            rethrow;
          }
          break;
        } catch (error, stackTrace) {
          stderr.writeln('[DatabaseAdmission] $error\n$stackTrace');
          if (!recoveryAttempted) {
            recoveryAttempted = true;
            final recovery = await _recoverFailedAdmission(
              appDataDirectory,
              error,
            );
            if (recovery == _AdmissionRecovery.remigrate) {
              runApp(
                MigrationApp(
                  service: HiveToSqliteMigrationService(
                    _legacyMigrationDecision(appDataDirectory),
                  ),
                  restoreOutcome: restoreOutcome?.state,
                ),
              );
              return;
            }
            if (recovery == _AdmissionRecovery.rebuilt) {
              continue;
            }
          }
          runApp(
            _RestoreFailureApp(
              report: StartupFailureReport.capture(
              stage: StartupFailureStage.databaseAdmission,
              error: error,
              step: 'database_admission',
              stackTrace: StackTrace.current,
            ),
              appDataDirectory: appDataDirectory,
              businessLease: businessLease,
            ),
          );
          return;
        }
      }
      // Desktop exit hook: drain queued preference writes before process exit.
      _installExitFlush(businessPreferences);
      ScheduledTasksService.configureDevice(businessPreferences);
      // Best-effort trim of archived restore runs after a few cold starts.
      unawaited(_pruneRestoreArchive(appDataDirectory));
      unawaited(ModelCatalogService.instance.maybeAutoRefresh());
      // Enable edge-to-edge to allow content under system bars (Android)
      SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
      // MCP 服务依赖进程级注册：不经过 rootNavigatorKey.currentContext
      // （后台/Activity 被回收时 context 为 null，曾致 apk_note_write 等
      // 记忆类工具报 chat_service_unavailable）。
      final chatService = ChatService(
        existingRepository: processDatabaseLease.chatRepository,
      );
      // 会话级工具（任务清单等）的作用域兜底（2026-10-02 用户实测
      // todo_read/todo_write 全返回 conversation_required）：让端内、MCP、子代理
      // 三条链路都能解析到「当前打开的会话」。放在进程级创建点，随 App 启动注入。
      LocalToolsService.conversationFallbackResolver =
          () => chatService.currentConversationId;
      // 同一个进程级实例也作为工具面的兜底：子代理/工作台链路不传 chatService 时，
      // get_apk_patch_memory 等按会话读库的工具不必再回 chat_service_unavailable。
      LocalToolsService.chatServiceResolver = () => chatService;
      final memoryRepository = MemoryRepository(businessPreferences);
      // F-36（2026-10-04）：记忆库也走进程级兜底——端内 Agent 面分发从不传
      // memoryRepository，get_apk_patch_memory 的经验检索此前整条必挂。
      LocalToolsService.memoryRepositoryResolver = () => memoryRepository;
      // v8-D14（2026-10-04 真机）：技能注册表兜底也**急切**建立（顶层共享实例，
      // 见 sharedAgentSkillProvider 声明）——过去只在 widget 的惰性 provider 里
      // 赋值，MCP/Agent 会话没触发 build 时 resolver 恒 null。
      sharedAgentSkillProvider = AgentSkillProvider(
        preferences: businessPreferences,
      );
      LocalToolsService.agentSkillResolver = () => sharedAgentSkillProvider;
      // 闭包内捕获局部变量：processDatabaseLease 是闭包赋值的可空变量，
      // 延迟求值丢失空安全提升（此处直接流内已必非空）。
      final chatRepository = processDatabaseLease.chatRepository;
      // OpenCode Go 会话头兜底：预载安装级稳定 ID（customHeaders 同步取值，
      // 不能现场读 prefs；有会话作用域的请求优先用会话 ID）。
      await ApiSessionScope.preload();
      McpHttpServer.instance.configure(
        chatServiceGetter: () => chatService,
        memoryRepositoryGetter: () => memoryRepository,
        // 同族缺陷扫查：这几个 getter 过去只在「打开 MCP 设置页」时才配，且实现走
        // `rootNavigatorKey.currentContext` —— Activity 被回收/后台时为 null，于是
        // MCP 面又回 world_book_unavailable / skill_store_unavailable（正是 ⑤-b 的
        // 复发路径）。这里在进程级注册，取的是实例化点登记的同一批 resolver。
        assistantGetter: () =>
            LocalToolsService.assistantResolver?.call().currentAssistant,
        worldBookGetter: () => LocalToolsService.worldBookResolver?.call(),
        agentSkillGetter: () => LocalToolsService.agentSkillResolver?.call(),
        instructionInjectionGetter: () =>
            LocalToolsService.instructionInjectionResolver?.call(),
        keepAliveEnsurer: () =>
            AndroidBackgroundManager.setEnabled(true, networkRequired: true),
      );
      // 根口径唯一化（用户 2026-10-04）：core 的 workspace 工具上下文通过这个
      // 钩子拿「当前生效的工作根」。默认「工作台目录优先」——设了工作台目录就用
      // 它（用户可见、产物取得出），绑定工作区只决定 Linux 环境；关掉开关则回到
      // 按工作区隔离的旧口径。core 不能反向依赖 features/solab_apk，所以注入。
      WorkspaceToolsService.effectiveWorkRootResolver =
          ({String? workspaceRoot}) =>
              ApkWorkspaceBindingService.effectiveWorkRoot(
                workspaceRoot: workspaceRoot,
              );
      // 默认工作区的根（用户 2026-10-04）：就是 APK 工作台原来那个「统一工作目录」。
      // 它现在是**常驻、不可删除**的工作区（不挂环境、直接可用），未绑定会话的根
      // 就是它。core 不能反向依赖 features，所以注入。
      WorkspaceProvider.defaultRootResolver =
          () => ApkWorkspaceBindingService.workbenchDir();
      // 经验自动浮现（2026-09-05）：resume state 带「本 APP 已验证经验存在」
      // 信号——apk_patch 类记忆不在通用记忆注入白名单，没有这个钩子 Agent
      // 上下文零信号，库里有经验也不看（实测事故）。浮现失败静默跳过。
      // 指纹口径与 get_apk_patch_memory 完全一致：报告 + 规则库厂商信号。
      // peekVerifiedExperienceCached 内按（指纹|经验数|最新 timestamp）
      // 记忆化——taskResumeState 每条消息调用 2~3 次，无变化零重复计算。
      ApkWorkspaceBindingService.verifiedExperiencePeek = () async {        final report = await ApkWorkspaceService.readReport();
        if (report == null) return null;
        final vendors = await ApkRuleService(
          chatRepository,
        ).vendorsForReport(report);
        return ApkPatchMemoryService.peekVerifiedExperienceCached(
          memoryRepository,
          report: report,
          vendors: vendors,
        );
      };
      // 会话删除联动清理（2026-09-14 体积治理；升级为连带删除）：
      // 删除会话 = 该作用域分析生命终结 → 解绑运行时任务 + **删除任务记录**
      // （task.json / 事件流 / 工作区）+ 清除该会话作用域的 APK 报告。
      // 仍被其它作用域绑定的任务不删——互斥双模下同一台机器可能同时存在
      // 对话作用域与 mcp-host 作用域，别的会话可能还在用这条任务。
      ChatService.onConversationDeleted = (conversationId) async {
        try {
          // 会话模式/目标（2026-09-29）：会话删掉后 prefs 里的两处键与进程内策略
          // 此前都只写不清 —— SessionModeRuntime.reset 的文档写着「会话删除时
          // 调用」，但全仓没有任何删除路径调用它。这里补齐，避免残留记录把
          // 一个已删会话的免审批状态留在静态表里。
          await SessionModeStore().clearConversation(conversationId);
          SessionModeRuntime.reset(conversationId);
          final session = TaskSession.shared;
          final bound = await session.taskFor(conversationId);
          await session.unbind(conversationId);
          await ApkWorkspaceService.clearReport(
            conversationId: conversationId,
          );
          if (bound != null) {
            final stillBound = (await session.boundTaskIds()).contains(bound.id);
            if (!stillBound) {
              final deleted = await session.deleteTask(bound.id);
              // 连带删除也要通知界面：状态条/弹层监听 revision，
              // 删完不 bump 就继续显示已删任务。
              if (deleted) RuntimeBridge.instance.bumpRevision();
            }
          }
        } catch (_) {}
      };
      // 启动期体积/记录治理（2026-09-14）：回收无主工作区（workspace.prepare()
      // 会给每个任务复制一份全量 APK 进 input/，实测 app_flutter 6.75GB 事故），
      // 并回收超量的历史任务记录——未绑定 + 超保留量的旧任务（task.json /
      // 事件流 / 交付报告镜像）一起删，避免「一个 APP 几十份报告」。
      // 绑定中的任务永不回收；失败静默。
      unawaited(RuntimeBridge.instance.pruneRuntimeGarbage());
      // Start app (Flutter log capture is toggleable and off by default)
      runApp(
        MyApp(
          databaseLease: processDatabaseLease,
          businessPreferences: businessPreferences,
          chatService: chatService,
          memoryRepository: memoryRepository,
          appDataDirectory: appDataDirectory,
          restoreOutcome: restoreOutcome?.state,
        ),
      );
    },
    zoneSpecification: ZoneSpecification(
      print: (self, parent, zone, line) {
        FlutterLogger.logPrint(line);
        parent.print(zone, line);
      },
      handleUncaughtError: (self, parent, zone, error, stackTrace) {
        // 兜底：未捕获异步异常只记录不静默，配合 PlatformDispatcher.onError
        // 返回 true 保证进程不因漏网异常直接闪退（stderr 在 logcat 可见）。
        try {
          stderr.writeln('[UncaughtZone] $error\n$stackTrace');
        } catch (_) {}
      },
    ),
  );
}

/// 业务租约重试获取：覆盖 Android 前台服务保活下旧引擎异步销毁的锁残留窗口。
Future<RestoreBusinessLease> _acquireBusinessLeaseWithRetry(
  Directory appDataDirectory, {
  int attempts = 10,
  Duration retryDelay = const Duration(milliseconds: 300),
}) async {
  Object? lastError;
  StackTrace? lastStack;
  for (var attempt = 0; attempt < attempts; attempt++) {
    try {
      return await RestoreBusinessLease.acquire(
        appDataDirectory: appDataDirectory,
      );
    } on RestoreBusinessLeaseUnavailable catch (error, stack) {
      lastError = error;
      lastStack = stack;
      if (attempt + 1 < attempts) {
        await Future<void>.delayed(retryDelay);
      }
    }
  }
  Error.throwWithStackTrace(lastError!, lastStack!);
}

enum _AdmissionRecovery { none, rebuilt, remigrate }

/// Names must mirror HiveToSqliteMigrationService.check().
const _legacyHiveSourceNames = <String>[
  'conversations.hive',
  'messages.hive',
  'tool_events_v1.hive',
];

bool _legacyHiveSourcesExist(Directory appDataDirectory) =>
    _legacyHiveSourceNames.any(
      (name) => File('${appDataDirectory.path}/$name').existsSync(),
    );

Future<_AdmissionRecovery> _recoverFailedAdmission(
  Directory appDataDirectory,
  Object error,
) async {
  final action = await DatabaseInstallationGate.recoveryActionFor(
    appDataDirectory: appDataDirectory,
    error: error,
    legacyHiveDataPresent: _legacyHiveSourcesExist(appDataDirectory),
  );
  switch (action) {
    case DatabaseRecoveryAction.rebuildAutomatically:
      try {
        await DatabaseInstallationGate.rebuildFresh(
          appDataDirectory: appDataDirectory,
        );
        return _AdmissionRecovery.rebuilt;
      } catch (rebuildError, rebuildStack) {
        stderr.writeln(
          '[DatabaseAdmission] rebuild failed: $rebuildError\n$rebuildStack',
        );
        return _AdmissionRecovery.none;
      }
    case DatabaseRecoveryAction.promptRemigration:
      return _AdmissionRecovery.remigrate;
    case DatabaseRecoveryAction.promptUpgrade:
    case DatabaseRecoveryAction.none:
      return _AdmissionRecovery.none;
  }
}

HiveToSqliteMigrationDecision _legacyMigrationDecision(
  Directory appDataDirectory,
) {
  return HiveToSqliteMigrationDecision(
    needsMigration: true,
    appDataDir: appDataDirectory,
    sqliteFile: File(
      '${appDataDirectory.path}/${AppDatabase.databaseFileName}',
    ),
    hiveFiles: [
      for (final name in _legacyHiveSourceNames)
        if (File('${appDataDirectory.path}/$name').existsSync())
          File('${appDataDirectory.path}/$name'),
    ],
  );
}

/// 启动占位页：main() 初始化链完成前的第一帧画面（零依赖，深浅色自适应）。
/// 初始化完成后由 MyApp / MigrationApp / _RestoreFailureApp 替换。
class _StartupSplashApp extends StatelessWidget {
  const _StartupSplashApp();

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: const Color(0xFF2F6FED)),
      darkTheme: ThemeData(
        colorSchemeSeed: const Color(0xFF2F6FED),
        brightness: Brightness.dark,
      ),
      home: const Scaffold(body: Center(child: CircularProgressIndicator())),
    );
  }
}

class _RestoreFailureApp extends StatelessWidget {
  const _RestoreFailureApp({
    required this.report,
    this.appDataDirectory,
    this.businessLease,
  });

  final StartupFailureReport report;
  final Directory? appDataDirectory;
  final RestoreBusinessLease? businessLease;

  @override
  Widget build(BuildContext context) {
    final palette = ThemePalettes.defaultPalette;
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'SoLab',
      supportedLocales: AppLocalizations.supportedLocales,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      theme: buildLightThemeForScheme(palette.light),
      darkTheme: buildDarkThemeForScheme(palette.dark),
      home: report.diagnosticCode == 'database_schema_too_new'
          ? _UpdateRequiredScreen(report: report)
          : RestoreFailureScreen(
              report: report,
              restart: PlatformUtils.restartApp,
              appDataDirectory: appDataDirectory,
              businessLease: businessLease,
            ),
    );
  }
}

/// Shown when the installed database was written by a newer app version;
/// restarting cannot help, so the only action is updating SoLab.
class _UpdateRequiredScreen extends StatelessWidget {
  const _UpdateRequiredScreen({required this.report});

  final StartupFailureReport report;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final colors = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 560),
              child: Material(
                color: colors.surfaceContainerLow,
                borderRadius: BorderRadius.circular(20),
                child: Padding(
                  padding: const EdgeInsets.all(28),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        width: 56,
                        height: 56,
                        decoration: BoxDecoration(
                          color: colors.primaryContainer,
                          borderRadius: BorderRadius.circular(16),
                        ),
                        child: Icon(
                          Icons.system_update_alt_rounded,
                          size: 30,
                          color: colors.onPrimaryContainer,
                        ),
                      ),
                      const SizedBox(height: 20),
                      Text(
                        l10n.startupDatabaseUpdateRequiredTitle,
                        style: textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 10),
                      Text(
                        l10n.startupDatabaseUpdateRequiredContent,
                        style: textTheme.bodyLarge?.copyWith(
                          color: colors.onSurfaceVariant,
                          height: 1.45,
                        ),
                      ),
                      const SizedBox(height: 20),
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: colors.surfaceContainerHighest,
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: SelectableText(
                          l10n.backupRestoreFailureDiagnostic(report.diagnosticCode),
                          style: textTheme.bodySmall?.copyWith(
                            color: colors.onSurfaceVariant,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// Removed eager system font preloading to reduce memory footprint at launch.

Future<void> _pruneRestoreArchive(Directory appDataDirectory) async {
  try {
    final prefs = await SharedPreferences.getInstance();
    const key = RestoreArchivePruner.coldStartsKey;
    await RestoreArchivePruner(
      appDataDirectory: appDataDirectory,
      readColdStarts: () async => prefs.getInt(key) ?? 0,
      writeColdStarts: (count) => prefs.setInt(key, count),
    ).pruneAfterSuccessfulColdStart();
  } catch (_) {}
}

class MigrationApp extends StatelessWidget {
  const MigrationApp({super.key, required this.service, this.restoreOutcome});

  final HiveToSqliteMigrationService service;
  final RestoreReceiptState? restoreOutcome;

  @override
  Widget build(BuildContext context) {
    final palette = ThemePalettes.defaultPalette;
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'SoLab',
      supportedLocales: AppLocalizations.supportedLocales,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      theme: buildLightThemeForScheme(palette.light),
      darkTheme: buildDarkThemeForScheme(palette.dark),
      builder: (context, child) =>
          AppSnackBarOverlay(child: child ?? const SizedBox.shrink()),
      home: RestoreOutcomeNotice(
        outcome: restoreOutcome,
        child: HiveToSqliteMigrationPage(service: service),
      ),
    );
  }
}

/// Holds [EnvironmentManager] / [MirrorService] until [createWorkspaceStack]
/// finishes after the first frame.
class _WorkspaceStackHolder extends ChangeNotifier {
  EnvironmentManager? environmentManager;
  MirrorService? mirrors;
  EnvironmentDependencies? dependencies;

  void apply(WorkspaceStack stack) {
    environmentManager = stack.environmentManager;
    mirrors = stack.mirrors;
    dependencies = stack.dependencies;
    notifyListeners();
  }
}

class MyApp extends StatelessWidget {
  const MyApp({
    super.key,
    required this.databaseLease,
    required this.businessPreferences,
    required this.chatService,
    required this.memoryRepository,
    required this.appDataDirectory,
    this.restoreOutcome,
  });

  final ChatDatabaseLease databaseLease;
  final BusinessPreferences businessPreferences;
  final ChatService chatService;
  final MemoryRepository memoryRepository;
  final Directory appDataDirectory;
  final RestoreReceiptState? restoreOutcome;

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        Provider<BusinessRepository>.value(
          value: databaseLease.businessRepository,
        ),
        Provider<BusinessPreferences>.value(value: businessPreferences),
        ChangeNotifierProvider(
          create: (_) => UserProvider(preferences: businessPreferences),
        ),
        ChangeNotifierProvider(
          create: (_) => SettingsProvider(businessPreferences),
        ),
        ChangeNotifierProvider<ChatService>.value(value: chatService),
        ChangeNotifierProvider(create: (_) => McpToolService()),
        ChangeNotifierProvider(create: (_) => ToolApprovalService()),
        ChangeNotifierProvider(create: (_) => AskUserInteractionService()),
        ChangeNotifierProvider(
          create: (ctx) {
            final provider = AssistantProvider(
              preferences: businessPreferences,
              chatService: ctx.read<ChatService>(),
            );
            // MCP 面/后台链路的作用域兜底（见 McpHttpServer.configure 处的注释）。
            LocalToolsService.assistantResolver = () => provider;
            return provider;
          },
        ),
        ChangeNotifierProvider(
          create: (_) {
            final provider = InstructionInjectionProvider(
              preferences: businessPreferences,
            );
            // 端内 Agent 面与 MCP 面都不传这个 provider（报告 ⑤-b），
            // 在实例化点登记进程级兜底，保证两条链路都拿得到同一个实例。
            LocalToolsService.instructionInjectionResolver = () => provider;
            return provider;
          },
        ),
        // SoLab 自研：技能注册表。上游没有这个 provider，但下面的 MCP 主机配置会
        // context.read<AgentSkillProvider>()，必须在此注册，否则开启主机模式会崩。
        // v8-D14：实例在 main() 顶部急切创建并已挂 resolver，这里复用同一实例。
        ChangeNotifierProvider<AgentSkillProvider>.value(
          value: sharedAgentSkillProvider,
        ),
        ChangeNotifierProvider(
          create: (_) {
            final provider = WorldBookProvider(preferences: businessPreferences);
            // get_apk_knowledge 过去恒回 world_book_unavailable：兜底见上。
            LocalToolsService.worldBookResolver = () => provider;
            return provider;
          },
        ),
        ChangeNotifierProvider(
          create: (_) => MemoryProviderV2(
            repository: MemoryRepository(businessPreferences),
            chatRepository: databaseLease.chatRepository,
          ),
        ),
        ChangeNotifierProvider(
          create: (ctx) => ContextUsageService(
            chatService: ctx.read<ChatService>(),
            settings: ctx.read<SettingsProvider>(),
            assistants: ctx.read<AssistantProvider>(),
            instructions: ctx.read<InstructionInjectionProvider>(),
            worldBooks: ctx.read<WorldBookProvider>(),
            memories: ctx.read<MemoryProviderV2>(),
            // 记忆快照 hash 按「这条会话绑定的工作区」算：切会话/切工作区后重算
            // 仍与请求期同一项目，精确锚定不会因为环境态过期而作废。
            resolveConversationProject: (conversationId) =>
                WorkspaceToolsService.resolveConversationProject(
                  conversationId: conversationId,
                  workspaceProvider: ctx.read<WorkspaceProvider>(),
                  chatService: ctx.read<ChatService>(),
                ),
          ),
        ),
        ChangeNotifierProvider(
          create: (_) => TagProvider(preferences: businessPreferences),
        ),
        ChangeNotifierProvider(
          create: (_) => TtsProvider(preferences: businessPreferences),
        ),
        ChangeNotifierProvider(
          create: (ctx) =>
              AsrProvider(settingsProvider: ctx.read<SettingsProvider>()),
        ),
        ChangeNotifierProvider(
          create: (_) => QuickPhraseProvider(preferences: businessPreferences),
        ),
        ChangeNotifierProvider(
          create: (_) => InstructionInjectionGroupProvider(
            preferences: businessPreferences,
          ),
        ),
        ChangeNotifierProvider(
          create: (_) => MemoryProvider(preferences: businessPreferences),
        ),
        Provider<ExtensionEntityStore>.value(
          value: databaseLease.extensionEntityStore,
        ),
        if (WorkspaceChannel.isSupportedPlatform)
          ChangeNotifierProvider(
            lazy: false,
            create: (ctx) =>
                ExternalMountsProvider(store: ctx.read<ExtensionEntityStore>()),
          ),
        ChangeNotifierProvider(
          create: (ctx) => WorkspaceProvider(
            store: ctx.read<ExtensionEntityStore>(),
            assistants: ctx.read<AssistantProvider>(),
          ),
        ),
        ChangeNotifierProvider(
          create: (ctx) => SkillsService(
            store: ctx.read<ExtensionEntityStore>(),
            bundledAssets: rootBundle,
          ),
        ),
        ChangeNotifierProvider(
          create: (_) => EnvironmentProvider(preferences: businessPreferences),
        ),
        ChangeNotifierProvider(create: (_) => _WorkspaceStackHolder()),
        ChangeNotifierProvider(
          create: (ctx) {
            final provider = WorkspaceRuntimeProvider();
            final extras = ctx.read<_WorkspaceStackHolder>();
            final env = ctx.read<EnvironmentProvider>();
            provider.initialization = (() async {
              try {
                final stack = await createWorkspaceStack(env: env);
                applyWorkspaceStack(provider, stack);
                extras.apply(stack);
              } catch (error, stackTrace) {
                debugPrint(
                  'Failed to create workspace stack: $error\n$stackTrace',
                );
              }
            })();
            unawaited(provider.initialization);
            return provider;
          },
        ),
        ChangeNotifierProvider(
          create: (ctx) => McpProvider(
            preferences: businessPreferences,
            workspaceRuntime: ctx.read<WorkspaceRuntimeProvider>(),
            environment: ctx.read<EnvironmentProvider>(),
            workspaces: ctx.read<WorkspaceProvider>(),
          ),
        ),
        ProxyProvider<_WorkspaceStackHolder, EnvironmentManager?>(
          update: (_, extras, __) => extras.environmentManager,
        ),
        ProxyProvider<_WorkspaceStackHolder, MirrorService?>(
          update: (_, extras, __) => extras.mirrors,
        ),
        ListenableProxyProvider<
          _WorkspaceStackHolder,
          EnvironmentDependencies?
        >(update: (_, extras, __) => extras.dependencies),
        ChangeNotifierProvider(create: (_) => ToolRunRegistry()),
        ChangeNotifierProvider(
          create: (ctx) {
            final environment = ctx.read<EnvironmentProvider>();
            return TerminalSessionManager(
              loadEnvironment: () async =>
                  (await environment.loadExecutionConfig()).variables,
            );
          },
        ),
        Provider<MemoryPipelineService>(
          create: (ctx) {
            final memoryV2 = ctx.read<MemoryProviderV2>();
            return MemoryPipelineService(
              chatService: ctx.read<ChatService>(),
              repository: memoryV2.repository,
              chatRepository: memoryV2.chatRepository,
              settings: () => ctx.read<SettingsProvider>(),
              assistants: () => ctx.read<AssistantProvider>(),
              memoryV2: () => ctx.read<MemoryProviderV2>(),
              // 后台整理整轮按「这条会话绑定的工作区」跑：入队时捕获的活动项目
              // 只是兜底，真正的项目身份以会话绑定为准（用户切工作区/排队等待
              // 期间都不会把记忆贴到别的项目上）。
              resolveConversationProject: (conversationId) =>
                  WorkspaceToolsService.resolveConversationProject(
                    conversationId: conversationId,
                    workspaceProvider: ctx.read<WorkspaceProvider>(),
                    chatService: ctx.read<ChatService>(),
                  ),
            );
          },
        ),
        ChangeNotifierProvider(
          create: (_) =>
              BackupReminderProvider(preferences: businessPreferences),
        ),
        ChangeNotifierProvider(
          create: (ctx) => BackupProvider(
            chatService: ctx.read<ChatService>(),
            businessRepository: databaseLease.businessRepository,
            businessPreferences: businessPreferences,
            initialConfig: ctx.read<SettingsProvider>().webDavConfig,
          ),
        ),
        ChangeNotifierProvider(
          create: (ctx) => S3BackupProvider(
            chatService: ctx.read<ChatService>(),
            businessRepository: databaseLease.businessRepository,
            businessPreferences: businessPreferences,
            initialConfig: ctx.read<SettingsProvider>().s3Config,
          ),
        ),
        // 本地快照（上游 1.3.0 的 main.dart 一直有这一段；本 fork 在此前的
        // 文件级同步里把它整块丢了 —— 备份页的「本地快照」区块、快照页与
        // 快照调度器都 `context.watch/read<LocalSnapshotProvider>()`，一进就
        // ProviderNotFoundException 崩溃。2026-09-23 真机复现后补回。
        ChangeNotifierProvider(
          create: (ctx) => LocalSnapshotProvider(
            appDataDirectory: appDataDirectory,
            chatService: ctx.read<ChatService>(),
            businessRepository: databaseLease.businessRepository,
            businessPreferences: businessPreferences,
            isBusy: () {
              // 不和用户正在看的回复抢，也不和已在占用数据库的备份/恢复/导入抢。
              if (ChatActions.hasAnyActiveGeneration) {
                return LocalSnapshotSkipReason.generating;
              }
              if (BackupActivity.isActive ||
                  ctx.read<BackupProvider>().busy ||
                  ctx.read<S3BackupProvider>().busy) {
                return LocalSnapshotSkipReason.busy;
              }
              return null;
            },
          ),
        ),
      ],
      child: Builder(
        builder: (context) {
          final settings = context.watch<SettingsProvider>();
          // Apply global proxy overrides when settings change
          settings.applyGlobalProxyOverridesIfNeeded();
          // 模型目录自动刷新（三天一次，只增不减）：内置厂家与配了 key 的厂家
          // 上新模型后自动进列表，不用人手去"获取模型列表"。到点才跑，
          // 不阻塞启动；失败只记账不打扰。
          unawaited(
            ModelCatalogAutoRefresh.maybeRefresh(settings).catchError(
              (Object error) => <String, Object?>{'error': error.toString()},
            ),
          );
          // Lazily ensure system fonts only if user selected a system family (desktop only)
          // Load ONLY selected families to avoid huge memory from loading all system fonts.
          WidgetsBinding.instance.addPostFrameCallback((_) async {
            try {
              final isDesktop =
                  !kIsWeb &&
                  (defaultTargetPlatform == TargetPlatform.windows ||
                      defaultTargetPlatform == TargetPlatform.macOS ||
                      defaultTargetPlatform == TargetPlatform.linux);
              if (!isDesktop) return;
              // Selected system app/code fonts (not local alias)
              final wantsAppSystem =
                  (settings.appFontFamily?.isNotEmpty == true) &&
                  (settings.appFontLocalAlias == null ||
                      settings.appFontLocalAlias!.isEmpty);
              final wantsCodeSystem =
                  (settings.codeFontFamily?.isNotEmpty == true) &&
                  (settings.codeFontLocalAlias == null ||
                      settings.codeFontLocalAlias!.isEmpty);
              if (wantsAppSystem || wantsCodeSystem) {
                final sf = SystemFonts();
                if (wantsAppSystem) {
                  final fam = settings.appFontFamily!;
                  try {
                    await sf.loadFont(fam);
                  } catch (_) {}
                }
                if (wantsCodeSystem) {
                  final fam = settings.codeFontFamily!;
                  try {
                    if (fam != settings.appFontFamily) await sf.loadFont(fam);
                  } catch (_) {}
                }
              }
            } catch (_) {}
          });
          return DynamicColorBuilder(
            builder: (lightDynamic, darkDynamic) {
              // if (lightDynamic != null) {
              //   debugPrint('[DynamicColor] Light dynamic detected. primary=${lightDynamic.primary.value.toRadixString(16)} surface=${lightDynamic.surface.value.toRadixString(16)}');
              // } else {
              //   debugPrint('[DynamicColor] Light dynamic not available');
              // }
              // if (darkDynamic != null) {
              //   debugPrint('[DynamicColor] Dark dynamic detected. primary=${darkDynamic.primary.value.toRadixString(16)} surface=${darkDynamic.surface.value.toRadixString(16)}');
              // } else {
              //   debugPrint('[DynamicColor] Dark dynamic not available');
              // }
              final isAndroid =
                  Theme.of(context).platform == TargetPlatform.android;
              // Update dynamic color capability for settings UI (avoid notify during build)
              final dynSupported =
                  isAndroid && (lightDynamic != null || darkDynamic != null);
              WidgetsBinding.instance.addPostFrameCallback((_) {
                try {
                  settings.setDynamicColorSupported(dynSupported);
                } catch (_) {}
              });

              // Android-only: ensure background execution matches setting and prepare notifications if needed
              if (!_didEnsureKeepAlive) {
                _didEnsureKeepAlive = true;
                final l10nKeepAlive = AppLocalizations.of(context);
                // 必须等 settings 加载完成：首轮 build 时 mcpServerEnabled 等
                // 异步配置还是默认值，守卫若先烧掉会导致 MCP server / FGS
                // 启动块永远不执行（弹窗路径启动时 getter 未注入）。
                settings.loaded.then((_) {
                  // 常驻通知上的「关闭」按钮（用户点它 = 想退出 MCP 模式）：
                  // 原生已停掉 FGS，这里同步业务状态，避免下次打开 App 还显示
                  // 服务在跑（2026-09-21 用户要求带关闭的通知）。
                  AndroidBackgroundManager.onUserStoppedFromNotification = () async {
                    try {
                      await McpHttpServer.instance.stop();
                      await settings.setMcpServerEnabled(false);
                    } catch (_) {}
                  };
                  WidgetsBinding.instance.addPostFrameCallback((_) async {
                    try {
                      if (Platform.isAndroid) {
                        final mode = settings.androidBackgroundChatMode;
                        // 保活单一机制：后台聊天走自研保活服务；MCP 常驻改由上游
                        // BackgroundRuntime 持有 FGS（含其通知/悬浮窗）。两者同开
                        // 时自研接管，绝不两套 FGS 同时活着。
                        final needKeepAlive =
                            mode != AndroidBackgroundChatMode.off;
                        final mcpResident =
                            settings.mcpServerEnabled && !needKeepAlive;
                        try {
                          await MobileBackgroundCoordinator.instance
                              .setMcpResident(mcpResident);
                        } catch (_) {}
                        if (needKeepAlive && context.mounted) {
                          // 保活优先：FGS 先启动（进程防冻结是目的，通知权限
                          // 只影响通知可见性）。权限请求异步补发——Android 13+
                          // 权限对话框无人响应时 await 会永久挂起，绝不能挡在
                          // FGS 启动前面（曾因此导致 MCP server 40 秒后被冻结）。
                          try {
                            await AndroidBackgroundManager.ensureInitialized(
                              notificationTitle: l10nKeepAlive
                                  ?.androidBackgroundNotificationTitle,
                              notificationText: l10nKeepAlive
                                  ?.androidBackgroundNotificationText,
                            );
                            await AndroidBackgroundManager.setEnabled(
                              true,
                              networkRequired: settings.mcpServerEnabled,
                            );
                          } catch (_) {}
                          // 通知权限不阻塞：FGS 已在跑，弹窗挂住/被拒都不影响保活。
                          // 授予后必须重发前台通知，否则首启被系统隐藏的
                          // 「软件保护」通知要杀后台重开才出现。
                          NotificationService.ensureInitialized();
                          final notificationsGranted =
                              await NotificationService.ensureAndroidNotificationsPermission();
                          if (notificationsGranted) {
                            await AndroidBackgroundManager.refreshNotification();
                          }
                          await AndroidBackgroundManager.requestKeepAlivePermissions();
                        } else if (context.mounted) {
                          await AndroidBackgroundManager.ensureInitialized();
                          await AndroidBackgroundManager.setEnabled(false);
                        }
                      }
                      // MCP server：先取得 FGS 保活，再绑定局域网端口，避免冷启动
                      // 暴露出会被系统冻结的无保活服务窗口。
                      // 额度闸门：子代理/AI 工作流花本机模型额度，读设置实时值
                      // （用户 2026-10-06：MCP 可能是别的工具在调）。这里只注入
                      // 一次解析器，开关改动无需重启服务即可生效。
                      McpHttpServer.quotaToolsAllowedResolver =
                          () => settings.mcpServerAllowQuotaTools;
                      // 「作业约定」：打开后 initialize 下发的 instructions 追加
                      // 同一份工作台约定（端内助手与 MCP 面共用一段文本）。
                      McpHttpServer.operatorConventionsResolver =
                          () => settings.mcpServerOperatorConventions;
                      if (settings.mcpServerEnabled) {
                        McpHttpServer.instance.configure(
                          port: settings.mcpServerPort,
                          token: settings.mcpServerToken,
                          assistantGetter: () => context
                              .read<AssistantProvider>()
                              .currentAssistant,
                          // chatService/memoryRepository 已在 main() 进程级
                          // 注册（后台 context 失效时仍可用），此处不再覆盖。
                          worldBookGetter: () =>
                              context.read<WorldBookProvider>(),
                          agentSkillGetter: () =>
                              context.read<AgentSkillProvider>(),
                          instructionInjectionGetter: () =>
                              context.read<InstructionInjectionProvider>(),
                        );
                        await McpHttpServer.instance.start();
                      }
                    } catch (_) {}
                  });
                });
              }

              final useDyn = isAndroid && settings.useDynamicColor;
              final custom = settings.selectedCustomTheme;
              final palette =
                  settings.themePaletteId == ThemePalettes.customPaletteId &&
                      custom != null
                  ? buildCustomThemePalette(custom)
                  : ThemePalettes.byId(settings.themePaletteId);

              final light = buildLightThemeForScheme(
                palette.light,
                dynamicScheme: useDyn ? lightDynamic : null,
                pureBackground: settings.usePureBackground,
              );
              final dark = buildDarkThemeForScheme(
                palette.dark,
                dynamicScheme: useDyn ? darkDynamic : null,
                pureBackground: settings.usePureBackground,
              );
              // Resolve effective app font family (system/local alias)
              String? effectiveAppFontFamily() {
                final fam = settings.appFontFamily;
                if (fam == null || fam.isEmpty) return null;
                return fam;
              }

              final effectiveAppFont = effectiveAppFontFamily();

              // Apply user-selected app font to theme text styles and app bar
              ThemeData applyAppFont(ThemeData base) {
                if (effectiveAppFont == null || effectiveAppFont.isEmpty) {
                  return base;
                }
                TextStyle? withFamily(TextStyle? s) =>
                    s?.copyWith(fontFamily: effectiveAppFont);
                TextTheme apply(TextTheme t) => t.copyWith(
                  displayLarge: withFamily(t.displayLarge),
                  displayMedium: withFamily(t.displayMedium),
                  displaySmall: withFamily(t.displaySmall),
                  headlineLarge: withFamily(t.headlineLarge),
                  headlineMedium: withFamily(t.headlineMedium),
                  headlineSmall: withFamily(t.headlineSmall),
                  titleLarge: withFamily(t.titleLarge),
                  titleMedium: withFamily(t.titleMedium),
                  titleSmall: withFamily(t.titleSmall),
                  bodyLarge: withFamily(t.bodyLarge),
                  bodyMedium: withFamily(t.bodyMedium),
                  bodySmall: withFamily(t.bodySmall),
                  labelLarge: withFamily(t.labelLarge),
                  labelMedium: withFamily(t.labelMedium),
                  labelSmall: withFamily(t.labelSmall),
                );
                final bar = base.appBarTheme;
                final appBar = bar.copyWith(
                  titleTextStyle: (bar.titleTextStyle ?? const TextStyle())
                      .copyWith(fontFamily: effectiveAppFont),
                  toolbarTextStyle: (bar.toolbarTextStyle ?? const TextStyle())
                      .copyWith(fontFamily: effectiveAppFont),
                );
                // Apply as default family to all text in ThemeData
                return base.copyWith(
                  textTheme: apply(base.textTheme),
                  primaryTextTheme: apply(base.primaryTextTheme),
                  appBarTheme: appBar,
                );
              }

              final themedLight = applyAppFont(light);
              final themedDark = applyAppFont(dark);
              // Log top-level colors likely used by widgets (card/bg/shadow approximations)
              // debugPrint('[Theme/App] Light scaffoldBg=${light.colorScheme.surface.value.toRadixString(16)} card≈${light.colorScheme.surface.value.toRadixString(16)} shadow=${light.colorScheme.shadow.value.toRadixString(16)}');
              // debugPrint('[Theme/App] Dark scaffoldBg=${dark.colorScheme.surface.value.toRadixString(16)} card≈${dark.colorScheme.surface.value.toRadixString(16)} shadow=${dark.colorScheme.shadow.value.toRadixString(16)}');
              return MaterialApp(
                debugShowCheckedModeBanner: false,
                title: 'SoLab',
                navigatorKey: rootNavigatorKey,
                // App UI language; null = follow system (respects iOS per-app language)
                locale: settings.appLocaleForMaterialApp,
                supportedLocales: AppLocalizations.supportedLocales,
                localizationsDelegates: AppLocalizations.localizationsDelegates,
                theme: themedLight,
                darkTheme: themedDark,
                themeMode: settings.themeMode,
                navigatorObservers: <NavigatorObserver>[routeObserver],
                home: RestoreOutcomeNotice(
                  outcome: restoreOutcome,
                  child: _selectHome(),
                ),
                builder: (ctx, child) {
                  final bright = Theme.of(ctx).brightness;
                  final overlay = bright == Brightness.dark
                      ? const SystemUiOverlayStyle(
                          statusBarColor: Colors.transparent,
                          statusBarIconBrightness: Brightness.light,
                          statusBarBrightness: Brightness.dark,
                          systemNavigationBarColor: Colors.transparent,
                          systemNavigationBarIconBrightness: Brightness.light,
                          systemNavigationBarDividerColor: Colors.transparent,
                          systemNavigationBarContrastEnforced: false,
                        )
                      : const SystemUiOverlayStyle(
                          statusBarColor: Colors.transparent,
                          statusBarIconBrightness: Brightness.dark,
                          statusBarBrightness: Brightness.light,
                          systemNavigationBarColor: Colors.transparent,
                          systemNavigationBarIconBrightness: Brightness.dark,
                          systemNavigationBarDividerColor: Colors.transparent,
                          systemNavigationBarContrastEnforced: false,
                        );
                  // Ensure localized defaults (assistants and chat default title) after first frame
                  if (!_didEnsureAssistants) {
                    _didEnsureAssistants = true;
                    WidgetsBinding.instance.addPostFrameCallback((_) {
                      try {
                        ctx.read<AssistantProvider>().ensureDefaults(ctx);
                      } catch (_) {}
                      try {
                        ctx.read<ChatService>().setDefaultConversationTitle(
                          AppLocalizations.of(
                            ctx,
                          )!.chatServiceDefaultConversationTitle,
                        );
                      } catch (_) {}
                      try {
                        ctx.read<UserProvider>().setDefaultNameIfUnset(
                          AppLocalizations.of(ctx)!.userProviderDefaultUserName,
                        );
                      } catch (_) {}
                    });
                  }
                  if (!_didWireWorkspace) {
                    _didWireWorkspace = true;
                    WidgetsBinding.instance.addPostFrameCallback((_) {
                      _wireWorkspaceServices(ctx);
                    });
                  }

                  // Desktop tray + close behaviour (minimize to tray) sync
                  final l10n = AppLocalizations.of(ctx);
                  if (l10n != null) {
                    final backgroundSettings = ctx.watch<SettingsProvider>();
                    WidgetsBinding.instance.addPostFrameCallback((_) {
                      if (!ctx.mounted) return;
                      final coordinator = MobileBackgroundCoordinator.instance;
                      coordinator.pauseSpeech = () async {
                        final tts = ctx.read<TtsProvider>();
                        if (tts.playbackState.isActive || tts.isSpeaking) {
                          await tts.pause();
                        }
                      };
                      unawaited(
                        coordinator.configureFromSettings(
                          backgroundSettings,
                          l10n,
                        ),
                      );
                    });
                    WidgetsBinding.instance.addPostFrameCallback((_) async {
                      // 桌面托盘同步（DesktopTrayController）随桌面依赖
                      // （tray_manager）一并裁剪：Android 无托盘概念，
                      // 这里的桌面分支在移动端恒不执行。
                    });
                  }

                  final mq = MediaQuery.of(ctx);
                  final display = View.of(ctx).display;
                  final displaySize = display.size / display.devicePixelRatio;
                  final isFloatingIpad =
                      defaultTargetPlatform == TargetPlatform.iOS &&
                      displaySize.shortestSide >= 600 &&
                      (mq.size.shortestSide < displaySize.shortestSide - 1 ||
                          mq.size.longestSide < displaySize.longestSide - 1);
                  final systemTop = mq.viewPadding.top;
                  final controlsTop = systemTop < 56 ? 56.0 : systemTop;
                  final appWithOverlays = MediaQuery(
                    data: isFloatingIpad
                        ? mq.copyWith(
                            padding: mq.padding.copyWith(top: controlsTop),
                            viewPadding: mq.viewPadding.copyWith(
                              top: controlsTop,
                            ),
                          )
                        : mq,
                    child: LocalSnapshotScheduler(
                      child: AppOverlays(child: child ?? const SizedBox.shrink()),
                    ),
                  );
                  final gated = McpHostModeGate(child: appWithOverlays);
                  // 全树兜底 DefaultTextStyle：**绝不能用 merge**。
                  // 根默认样式是 Flutter 的 error fallback：
                  //   color 0xD0FF0000 / monospace / decoration underline、
                  //   decorationColor 0xFFFFFF00、decorationStyle double
                  // merge 只覆盖指定字段，decoration 会原样继承 → 任何**没被 Material
                  // 包裹**的弹层（showGeneralDialog 的 pageBuilder/transitionBuilder、
                  // 自定义 OverlayEntry）里，带部分 style 的 Text 都会渲染成
                  // 「文字下方两道黄线」（用户 2026-10-02 实测并指出）。
                  // 这里直接给一份完整的正文样式，既不继承 fallback，也不影响 Material
                  // 子树（Material 会再提供自己的样子）。
                  final baseTextStyle =
                      Theme.of(ctx).textTheme.bodyMedium ??
                      const TextStyle(fontSize: 14);
                  return AnnotatedRegion<SystemUiOverlayStyle>(
                    value: overlay,
                    child: DefaultTextStyle(
                      style: effectiveAppFont == null
                          ? baseTextStyle
                          : baseTextStyle.copyWith(
                              fontFamily: effectiveAppFont,
                            ),
                      child: gated,
                    ),
                  );
                },
              );
            },
          );
        },
      ),
    );
  }
}

Widget _selectHome() {
  // 仅保留移动端首页（已裁剪桌面端）
  return const HomePage();
}

// Overrides logic is implemented within SettingsProvider now.

class _RestoreProgressApp extends StatelessWidget {
  const _RestoreProgressApp({required this.stage});

  final ValueNotifier<RestoreStartupStage> stage;

  @override
  Widget build(BuildContext context) {
    final palette = ThemePalettes.defaultPalette;
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Kelivo',
      supportedLocales: AppLocalizations.supportedLocales,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      theme: buildLightThemeForScheme(palette.light),
      darkTheme: buildDarkThemeForScheme(palette.dark),
      home: RestoreProgressScreen(stage: stage),
    );
  }
}

AppLifecycleListener? _exitFlushListener;

void _installExitFlush(BusinessPreferences businessPreferences) {
  if (kIsWeb) return;
  final isDesktop =
      defaultTargetPlatform == TargetPlatform.windows ||
      defaultTargetPlatform == TargetPlatform.macOS ||
      defaultTargetPlatform == TargetPlatform.linux;
  if (!isDesktop || _exitFlushListener != null) return;
  AppExitFlush.register(businessPreferences.flushPendingWrites);
  AppExitFlush.register(ChatActions.flushActiveGenerationProgress);
  _exitFlushListener = AppLifecycleListener(
    onExitRequested: () async {
      try {
        // Bound the wait: a stuck write transaction must not leave the
        // process unkillable after macOS answers NSTerminateLater.
        await AppExitFlush.flushAll().timeout(
          const Duration(seconds: 2),
          onTimeout: () {},
        );
      } catch (_) {}
      return AppExitResponse.exit;
    },
  );
}
