import 'dart:io';

import 'package:flutter/material.dart';
import 'package:image_cropper/image_cropper.dart';
import 'package:image_picker/image_picker.dart';
import 'package:file_picker/file_picker.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:path/path.dart' as p;
import '../../../l10n/app_localizations.dart';
import '../../../utils/app_directories.dart';
import '../../../utils/file_import_helper.dart';
import '../../../utils/image_compressor.dart';
import '../../../utils/platform_utils.dart';
import '../../../shared/widgets/snackbar.dart';
import '../../../core/models/chat_input_data.dart';
import '../../../core/utils/multimodal_input_utils.dart';
import '../widgets/chat_input_bar.dart';
import '../../solab_apk/services/apk_workspace_binding_service.dart';
import '../../workspace/pages/workspaces_page.dart';

/// 文件选取和上传服务
///
/// 负责处理：
/// - 图片选择 (相册/相机)
/// - 文件选择
/// - 桌面拖放处理
/// - 文件复制到应用目录
class FileUploadService {
  FileUploadService({
    required this.getContext,
    required this.mediaController,
    required this.isImageCropperEnabled,
    required this.getImageCompressConfig,
    this.hasWorkspace,
  });

  /// 媒体控制器，用于添加图片和文件到输入栏
  final ChatInputBarController mediaController;

  /// Context provider callback to avoid storing stale context
  final BuildContext Function() getContext;
  final bool Function() isImageCropperEnabled;
  final ImageCompressConfig Function() getImageCompressConfig;
  final bool Function()? hasWorkspace;

  static const supportedExtensions = [
    'png',
    'jpg',
    'jpeg',
    'gif',
    'webp',
    'bmp',
    'heic',
    'heif',
    'mp4',
    'avi',
    'mkv',
    'mov',
    'flv',
    'wmv',
    'mpeg',
    'mpg',
    'webm',
    '3gp',
    '3gpp',
    'wav',
    'mp3',
    'm4a',
    'aac',
    'flac',
    'ogg',
    'oga',
    'opus',
    'aiff',
    'aif',
    'pcm',
    'pcm16',
    'txt',
    'md',
    'json',
    'js',
    'pdf',
    'docx',
    'html',
    'xml',
    'py',
    'java',
    'kt',
    'dart',
    'ts',
    'tsx',
    'markdown',
    'mdx',
    'yml',
    'yaml',
    // 常见文本/代码/日志类（2026-10-05 上传分流）：这些是模型能直接读的内容，
    // 不补进来就会被分流判成「未知类型 → 工作目录」，用户拖一个 .log 进来
    // 却发现没进聊天。
    'log',
    'csv',
    'tsv',
    'sql',
    'sh',
    'bash',
    'zsh',
    'c',
    'h',
    'cpp',
    'hpp',
    'cc',
    'cs',
    'go',
    'rs',
    'rb',
    'php',
    'kts',
    'jsonl',
    'jsx',
    'toml',
    'ini',
    'cfg',
    'conf',
    'properties',
  ];

  static bool supportsWithoutWorkspace(DocumentAttachment file) {
    final mime = resolveDocumentAttachmentMime(file);
    return isImageMime(mime) ||
        isAudioMime(mime) ||
        isVideoMime(mime) ||
        supportedExtensions.contains(
          p.extension(file.fileName).replaceFirst('.', '').toLowerCase(),
        ) ||
        isSandboxDataFile(fileName: file.fileName, mime: file.mime);
  }

  /// 复制选中的文件到应用上传目录
  ///
  /// [files] 要复制的文件列表
  /// 返回复制后的文件路径列表
  Future<List<String>> copyPickedFiles(List<XFile> files) async {
    final saved = await _copyPickedFilesKeepingSlots(files);
    return saved.whereType<String>().toList(growable: false);
  }

  Future<List<String?>> _copyPickedFilesKeepingSlots(List<XFile> files) async {
    final dir = await AppDirectories.getUploadDirectory();
    final out = <String?>[];
    final context = getContext();
    if (!context.mounted) return out;
    final compressConfig = getImageCompressConfig();
    for (final f in files) {
      final sourceName = f.name.isNotEmpty ? f.name : f.path;
      final savedPath = isImageExtension(sourceName) && f.path.isNotEmpty
          ? (await ImageCompressor.compressToUploadDir(
              f.path,
              dir,
              compressConfig,
            ))?.path
          : await FileImportHelper.copyXFile(f, dir);
      out.add(savedPath);
    }
    return out;
  }

  void _enqueuePickedImages(Iterable<XFile> files) {
    final paths = [
      for (final file in files)
        if (file.path.isNotEmpty) file.path,
    ];
    if (paths.isEmpty) return;
    mediaController.enqueueImages(paths, getImageCompressConfig());
  }

  /// 从相册选取图片
  Future<void> onPickPhotos() async {
    try {
      // On desktop, fall back to FilePicker as image_picker is not supported.
      if (PlatformUtils.isDesktopTarget) {
        final res = await FilePicker.platform.pickFiles(
          allowMultiple: true,
          withData: false,
          type: FileType.custom,
          allowedExtensions: const [
            'png',
            'jpg',
            'jpeg',
            'gif',
            'webp',
            'bmp',
            'heic',
            'heif',
          ],
        );
        if (res == null || res.files.isEmpty) return;
        final toCopy = <XFile>[];
        for (final f in res.files) {
          if (f.path != null && f.path!.isNotEmpty) {
            toCopy.add(XFile(f.path!));
          }
        }
        if (toCopy.isEmpty) return;
        final croppedFiles = await _maybeCropImages(toCopy);
        if (croppedFiles.isEmpty) return;
        _enqueuePickedImages(croppedFiles);
        return;
      }

      final picker = ImagePicker();
      final files = await picker.pickMultiImage();
      if (files.isEmpty) return;
      final croppedFiles = await _maybeCropImages(files);
      if (croppedFiles.isEmpty) return;
      _enqueuePickedImages(croppedFiles);
    } catch (_) {}
  }

  /// 从相机拍照
  ///
  /// [context] 用于显示权限提示和错误消息
  Future<void> onPickCamera(BuildContext context) async {
    try {
      // Proactive permission check on mobile
      if (PlatformUtils.isMobile) {
        var status = await Permission.camera.status;
        // Request if not determined; otherwise guide user
        if (status.isDenied || status.isRestricted) {
          status = await Permission.camera.request();
        }
        if (!status.isGranted) {
          if (!context.mounted) return;
          final l10n = AppLocalizations.of(context)!;
          showAppSnackBar(
            context,
            message: l10n.cameraPermissionDeniedMessage,
            type: NotificationType.error,
            duration: const Duration(seconds: 4),
            actionLabel: l10n.openSystemSettings,
            onAction: () {
              try {
                openAppSettings();
              } catch (_) {}
            },
          );
          return;
        }
      }
      final picker = ImagePicker();
      final file = await picker.pickImage(source: ImageSource.camera);
      if (file == null) return;
      final croppedFiles = await _maybeCropImages([file]);
      if (croppedFiles.isEmpty) return;
      if (!context.mounted) return;
      _enqueuePickedImages(croppedFiles);
    } catch (e) {
      try {
        if (!context.mounted) return;
        final l10n = AppLocalizations.of(context)!;
        showAppSnackBar(
          context,
          message: l10n.cameraPermissionDeniedMessage,
          type: NotificationType.error,
          duration: const Duration(seconds: 3),
        );
      } catch (_) {}
    }
  }

  Future<List<XFile>> _maybeCropImages(List<XFile> files) async {
    if (!isImageCropperEnabled()) return files;

    final context = getContext();
    if (!context.mounted) return files;
    final l10n = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final croppedFiles = <XFile>[];

    for (final file in files) {
      try {
        final croppedFile = await ImageCropper().cropImage(
          sourcePath: file.path,
          uiSettings: [
            AndroidUiSettings(
              toolbarTitle: l10n.displaySettingsPageEnableImageCropperTitle,
              toolbarColor: cs.surface,
              toolbarWidgetColor: cs.onSurface,
              activeControlsWidgetColor: cs.primary,
              initAspectRatio: CropAspectRatioPreset.original,
              lockAspectRatio: false,
            ),
            IOSUiSettings(
              title: l10n.displaySettingsPageEnableImageCropperTitle,
            ),
          ],
        );
        if (croppedFile != null) {
          croppedFiles.add(XFile(croppedFile.path));
        }
      } catch (_) {
        croppedFiles.add(file);
      }
    }

    return croppedFiles;
  }

  /// 根据文件扩展名推断 MIME 类型
  String inferMimeByExtension(String name) {
    final mediaMime = inferMediaMimeFromSource(name);
    if (mediaMime.isNotEmpty) return mediaMime;
    final lower = name.toLowerCase();
    // Documents / text
    if (lower.endsWith('.pdf')) return 'application/pdf';
    if (lower.endsWith('.docx')) {
      return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    }
    if (lower.endsWith('.json')) return 'application/json';
    if (lower.endsWith('.js')) return 'application/javascript';
    if (lower.endsWith('.txt') || lower.endsWith('.md')) return 'text/plain';
    return supportedExtensions.contains(
          p.extension(lower).replaceFirst('.', ''),
        )
        ? 'text/plain'
        : 'application/octet-stream';
  }

  /// 判断文件是否为图片（根据扩展名）
  static bool isImageExtension(String name) {
    final lower = name.toLowerCase();
    return lower.endsWith('.png') ||
        lower.endsWith('.jpg') ||
        lower.endsWith('.jpeg') ||
        lower.endsWith('.gif') ||
        lower.endsWith('.webp') ||
        lower.endsWith('.bmp') ||
        lower.endsWith('.heic') ||
        lower.endsWith('.heif');
  }

  /// 分析目标类扩展名：这些是**工具链的输入**（apk_archive / so_analyze 都在
  /// 设备路径上工作），直传聊天既读不动也污染上下文——一律进工作目录。
  static const Set<String> workspaceExtensions = <String>{
    'apk', 'apks', 'xapk', 'apkm', 'dex', 'vdex', 'odex', 'oat', 'so', 'elf',
    'bin', 'jar', 'aar', 'zip', '7z', 'rar', 'tar', 'gz', 'tgz', 'bz2', 'xz',
    'arsc', 'smali', 'class', 'obb', 'dat',
  };

  /// 可读文本/代码/结构化文档：小体积直传（模型能直接读），超阈值进工作目录。
  static const Set<String> textLikeExtensions = <String>{
    'txt', 'md', 'markdown', 'json', 'jsonl', 'js', 'ts', 'tsx', 'jsx', 'py',
    'java', 'kt', 'kts', 'dart', 'c', 'h', 'cpp', 'hpp', 'cs', 'go', 'rs',
    'rb', 'php', 'sh', 'bash', 'zsh', 'yaml', 'yml', 'toml', 'ini', 'cfg',
    'conf', 'log', 'xml', 'html', 'htm', 'csv', 'tsv', 'sql',
  };

  /// 可读文本类直传上限：超过就进工作目录（让 AI 用 grep/read 按需读，
  /// 而不是一次性灌进上下文）。
  static const int maxAttachmentBytes = 1024 * 1024;

  /// 上传分流（用户 2026-10-05）：什么样的文件直传、什么样的进工作目录。
  ///
  /// - 直传（附件）：图片/音视频等已知可读类型、以及小体积文本/代码/文档；
  /// - 工作目录：APK/DEX/SO/JAR/AAR/压缩包等分析目标、其它二进制/未知类型、
  ///   以及超过 [maxAttachmentBytes] 的文本类文件。
  ///
  /// 纯函数便于单测；[size] 未知时不做体积判断（交给扩展名分档）。
  static bool shouldUseWorkspace(String name, {int? size}) {
    final ext = p.extension(name).toLowerCase().replaceFirst('.', '');
    if (isImageExtension(name)) return false; // 图片永远直传
    if (ext.isEmpty) return true; // 无扩展名：按二进制处理
    if (workspaceExtensions.contains(ext)) return true;
    if (!supportedExtensions.contains(ext)) return true; // 未知类型 → 工作目录
    if (textLikeExtensions.contains(ext) &&
        size != null &&
        size > maxAttachmentBytes) {
      return true;
    }
    return false; // 已知可读/媒体类型 → 直传
  }

  /// 选取文件（图片、视频、文档、APK/二进制等——按 [shouldUseWorkspace] 分流）
  Future<void> onPickFiles() async {
    try {
      // 一律放开类型：需要进工作目录的 APK 等不在旧白名单里，选不到就谈不上分流。
      final res = await FilePicker.platform.pickFiles(
        allowMultiple: true,
        withData: false,
        type: FileType.any,
      );
      if (res == null || res.files.isEmpty) return;
      final context = getContext();
      if (!context.mounted) return;

      final images = <XFile>[];
      final attachments = <XFile>[];
      final workspaceBound = <({XFile file, String name})>[];
      for (final f in res.files) {
        final path = f.path;
        if (path == null || path.isEmpty) continue;
        final file = XFile(path);
        if (isImageExtension(f.name)) {
          images.add(file);
        } else if (shouldUseWorkspace(f.name, size: f.size)) {
          workspaceBound.add((file: file, name: f.name));
        } else {
          attachments.add(file);
        }
      }
      _enqueuePickedImages(images);

      // —— 工作目录分流：先落目录；没配置就弹引导（授权/设置）——
      final placed = <String>[];
      if (workspaceBound.isNotEmpty) {
        var dir = await ApkWorkspaceBindingService.workDir();
        if (!context.mounted) return;
        if (dir == null || dir.isEmpty) {
          final goSetup = await _promptWorkspaceSetup(
            context,
            workspaceBound.map((e) => e.name).toList(growable: false),
          );
          if (goSetup && context.mounted) {
            await Navigator.of(context).push(
              MaterialPageRoute<void>(builder: (_) => const WorkspacesPage()),
            );
          }
          dir = await ApkWorkspaceBindingService.workDir();
        }
        if (dir != null && dir.isNotEmpty) {
          for (final item in workspaceBound) {
            final saved = await _copyIntoWorkspace(item.file.path, dir);
            if (saved != null) placed.add(saved);
          }
        }
        if (!context.mounted) return;
        if (placed.isNotEmpty) {
          showAppSnackBar(
            context,
            message: '已放入工作目录：${placed.join('、')}（可直接让 AI 分析）',
            type: NotificationType.success,
          );
        } else {
          showAppSnackBar(
            context,
            message: '这些文件需要工作目录才能交给 AI 分析：'
                '${workspaceBound.map((e) => e.name).join('、')}。'
                '请先在设置 → 工作区里配置工作目录后重试。',
            type: NotificationType.warning,
            duration: const Duration(seconds: 5),
          );
        }
      }

      // —— 附件分流（原有链路）——
      final docs = <DocumentAttachment>[];
      final saved = await _copyPickedFilesKeepingSlots(attachments);
      for (final savedPath in saved) {
        if (savedPath == null) continue;
        final savedName = p.basename(savedPath);
        final mime = inferMimeByExtension(savedName);
        docs.add(
          DocumentAttachment(path: savedPath, fileName: savedName, mime: mime),
        );
      }
      if (docs.isNotEmpty) {
        mediaController.addFiles(docs);
      }
    } catch (_) {}
  }

  /// 「这些文件要进工作目录，但还没配置」的引导弹窗（用户 2026-10-05）。
  ///
  /// 返回 true = 用户选择去配置；调用方负责推工作区设置页并在返回后重查。
  Future<bool> _promptWorkspaceSetup(
    BuildContext context,
    List<String> fileNames,
  ) async {
    final l10n = AppLocalizations.of(context);
    final picked = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(
          l10n?.workspaceSetupRequiredTitle ?? '需要先设置工作目录',
        ),
        content: Text(
          l10n?.workspaceSetupRequiredBody(fileNames.join('、')) ??
              fileNames.join('、'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: Text(MaterialLocalizations.of(context).cancelButtonLabel),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: Text(l10n?.workspaceSetupGoAction ?? '去设置'),
          ),
        ],
      ),
    );
    return picked == true;
  }

  /// 把文件复制进工作目录（设备路径，AI 工具链直接可达）。
  ///
  /// 同名冲突时加 `_1`/`_2` 后缀，不覆盖已有文件；返回落地后的文件名。
  Future<String?> _copyIntoWorkspace(String sourcePath, String dir) async {
    try {
      final source = File(sourcePath);
      if (!await source.exists()) return null;
      final baseName = p.basename(sourcePath);
      final targetDir = Directory(dir);
      if (!await targetDir.exists()) {
        await targetDir.create(recursive: true);
      }
      var target = File(p.join(dir, baseName));
      if (await target.exists()) {
        final sameSize = (await target.length()) == (await source.length());
        if (sameSize) return baseName; // 同名同大小：视为同一份，直接用
        final stem = p.basenameWithoutExtension(baseName);
        final ext = p.extension(baseName);
        var index = 1;
        do {
          target = File(p.join(dir, '${stem}_$index$ext'));
          index++;
        } while (await target.exists());
      }
      await source.copy(target.path);
      return p.basename(target.path);
    } catch (_) {
      return null;
    }
  }

  /// 处理桌面端拖放的文件 (macOS/Windows/Linux)
  Future<void> onFilesDroppedDesktop(List<XFile> files) async {
    if (files.isEmpty) return;
    try {
      final docs = <DocumentAttachment>[];
      final images = <XFile>[];
      final documents = <XFile>[];
      for (final f in files) {
        final name = (f.name.isNotEmpty
            ? f.name
            : (f.path.split(Platform.pathSeparator).last));
        if (isImageExtension(name)) {
          images.add(f);
        } else {
          documents.add(f);
        }
      }
      _enqueuePickedImages(images);

      final saved = await _copyPickedFilesKeepingSlots(documents);
      for (final savedPath in saved) {
        if (savedPath == null) continue;
        final savedName = p.basename(savedPath);
        final mime = inferMimeByExtension(savedName);
        docs.add(
          DocumentAttachment(path: savedPath, fileName: savedName, mime: mime),
        );
      }
      if (docs.isNotEmpty) mediaController.addFiles(docs);
    } catch (_) {}
  }
}
