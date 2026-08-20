import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:path_provider/path_provider.dart';
import 'package:http/http.dart' as http;
import '../../../core/providers/settings_provider.dart';
import '../../../core/models/api_keys.dart';
import '../../../core/services/local_inference/local_inference_service.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../core/services/haptics.dart';
import '../../../shared/widgets/ios_switch.dart';
import '../../../l10n/app_localizations.dart';
import 'package:Kelivo/theme/app_font_weights.dart';
import '../models/local_model.dart';

class LocalModelsPage extends StatefulWidget {
  const LocalModelsPage({super.key});

  @override
  State<LocalModelsPage> createState() => _LocalModelsPageState();
}

class _LocalModelsPageState extends State<LocalModelsPage>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  List<LocalModel> _myModels = [];
  List<LocalModel> _popularModels = [];
  bool _loading = true;
  Timer? _progressTimer;

  static const String _storageKey = 'local_models_v1';

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _tabController.addListener(() {
      if (mounted) setState(() {});
    });
    _loadModels();
  }

  @override
  void dispose() {
    _tabController.dispose();
    _progressTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadModels() async {
    _popularModels = LocalModel.popularModels();
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_storageKey);
    if (raw != null && raw.isNotEmpty) {
      try {
        final list = jsonDecode(raw) as List;
        _myModels = list.map((e) => LocalModel.fromJson(e as Map<String, dynamic>)).toList();
      } catch (_) {
        _myModels = [];
      }
    } else {
      _myModels = [];
    }
    // Merge status from popular models
    for (int i = 0; i < _popularModels.length; i++) {
      final existing = _myModels.where((m) => m.id == _popularModels[i].id).firstOrNull;
      if (existing != null) {
        _popularModels[i] = existing;
      }
    }
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _saveModels() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_storageKey, jsonEncode(_myModels.map((m) => m.toJson()).toList()));
  }

  Future<void> _startDownload(LocalModel model) async {
    final index = _myModels.indexWhere((m) => m.id == model.id);
    final updated = model.copyWith(status: 'downloading', downloadProgress: 0);
    if (index >= 0) {
      _myModels[index] = updated;
    } else {
      _myModels.add(updated);
    }
    _updatePopularStatus(model.id, updated);
    await _saveModels();
    if (mounted) setState(() {});

    try {
      final dir = await getApplicationDocumentsDirectory();
      final modelsDir = Directory('${dir.path}/local_models');
      if (!await modelsDir.exists()) {
        await modelsDir.create(recursive: true);
      }
      final filePath = '${modelsDir.path}/${model.fileName}';
      final file = File(filePath);
      
      // 多源下载列表，支持HF镜像、魔塔、官方Huggingface自动切换
      final downloadUrls = model.downloadUrls ?? [model.downloadUrl];
      HttpClientResponse? response;
      HttpClient? httpClient;
      int received = await file.exists() ? await file.length() : 0;
      
      // 遍历所有下载源，直到成功连接
      for (final url in downloadUrls) {
        try {
          httpClient = HttpClient();
          httpClient.autoUncompress = true;
          httpClient.connectionTimeout = const Duration(seconds: 15);
          httpClient.idleTimeout = const Duration(seconds: 30);
          
          final uri = Uri.parse(url);
          final req = await httpClient.getUrl(uri);
          
          // 断点续传：如果已下载部分内容，请求剩余部分
          if (received > 0 && received < model.fileSize) {
            req.headers.add('Range', 'bytes=$received-');
          }
          
          response = await req.close();
          // 200是完整下载，206是断点续传
          if (response.statusCode == 200 || response.statusCode == 206) {
            break;
          }
          httpClient?.close();
        } catch (e) {
          httpClient?.close();
          continue;
        }
      }
      
      if (response == null) {
        // 所有下载源都失败
        _updateModelError(model.id);
        return;
      }
      
      final contentLength = response.contentLength ?? (model.fileSize - received);
      final totalExpected = model.fileSize > 0 ? model.fileSize : (received + contentLength);
      
      final sink = file.openWrite(mode: received > 0 ? FileMode.append : FileMode.write);
      
      await for (final chunk in response) {
        sink.add(chunk);
        received += chunk.length as int;
        final progress = totalExpected > 0 ? (received / totalExpected) : 0.0;
        _updateModelProgress(model.id, progress.clamp(0.0, 1.0));
      }
      
      await sink.close();
      httpClient?.close();
      
      // 校验文件完整性
      final finalFileSize = await file.length();
      final finalStatus = (finalFileSize == model.fileSize || model.fileSize == 0) ? 'downloaded' : 'error';
      
      final finalModel = model.copyWith(
        status: finalStatus,
        downloadProgress: finalStatus == 'downloaded' ? 1.0 : 0,
        localPath: filePath,
      );
      _updateModelInList(model.id, finalModel);
      _updatePopularStatus(model.id, finalModel);
      await _saveModels();
    } catch (e) {
      _updateModelError(model.id);
    }
    if (mounted) setState(() {});
  }

  void _updateModelProgress(String id, double progress) {
    final idx = _myModels.indexWhere((m) => m.id == id);
    if (idx >= 0) {
      _myModels[idx] = _myModels[idx].copyWith(
        downloadProgress: progress,
        status: 'downloading',
      );
      _updatePopularStatus(id, _myModels[idx]);
      if (mounted) setState(() {});
    }
  }

  void _updateModelInList(String id, LocalModel updated) {
    final idx = _myModels.indexWhere((m) => m.id == id);
    if (idx >= 0) {
      _myModels[idx] = updated;
    }
  }

  void _updateModelError(String id) {
    final idx = _myModels.indexWhere((m) => m.id == id);
    if (idx >= 0) {
      _myModels[idx] = _myModels[idx].copyWith(status: 'error', downloadProgress: 0);
      _updatePopularStatus(id, _myModels[idx]);
    }
  }

  void _updatePopularStatus(String id, LocalModel updated) {
    final pIdx = _popularModels.indexWhere((m) => m.id == id);
    if (pIdx >= 0) {
      _popularModels[pIdx] = updated;
    }
  }

  Future<void> _useModel(LocalModel model) async {
    if (!mounted) return;
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('加载本地模型...'),
          ],
        ),
      ),
    );

    try {
      final port = await LocalInferenceService().start(
        modelPath: model.localPath,
        modelName: model.name,
      );

      final settings = context.read<SettingsProvider>();
      final providerKey = 'local_${model.id.replaceAll(RegExp(r'[^a-zA-Z0-9_-]'), '_')}';

      final cfg = ProviderConfig(
        id: providerKey,
        enabled: true,
        name: '${model.name} (本地)',
        apiKey: 'local',
        baseUrl: 'http://localhost:$port',
        providerType: ProviderKind.openai,
        chatPath: '/v1/chat/completions',
        useResponseApi: false,
        models: [model.name],
        modelOverrides: {
          model.name: {
            'type': 'chat',
            'input': ['text'],
            'output': ['text'],
            'abilities': ['tool'],
          },
        },
        proxyEnabled: false,
        proxyHost: '',
        proxyPort: '$port',
        proxyUsername: '',
        proxyPassword: '',
        multiKeyEnabled: false,
        apiKeys: const [],
        keyManagement: const KeyManagementConfig(),
        aihubmixAppCodeEnabled: false,
        balanceEnabled: false,
      );
      await settings.setProviderConfig(providerKey, cfg);

      final order = List<String>.of(settings.providersOrder);
      order.remove(providerKey);
      order.insert(0, providerKey);
      await settings.setProvidersOrder(order);

      if (mounted) Navigator.of(context).pop();

      if (mounted) {
        await showDialog(
          context: context,
          builder: (ctx) => AlertDialog(
            title: const Row(
              children: [
                Icon(Icons.check_circle, color: Colors.green, size: 24),
                SizedBox(width: 8),
                Text('本地模型已启动'),
              ],
            ),
            content: Text('${model.name} 已在 localhost:$port 运行，返回对话页即可使用'),
            actions: [
              FilledButton(
                onPressed: () => Navigator.of(ctx).pop(),
                child: const Text('去对话'),
              ),
            ],
          ),
        );
        if (mounted) Navigator.of(context).maybePop();
      }
    } catch (e) {
      if (mounted) Navigator.of(context).pop();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('启动失败: $e')),
        );
      }
    }
  }

  Future<void> _deleteModel(LocalModel model) async {
    if (model.localPath.isNotEmpty) {
      final file = File(model.localPath);
      if (await file.exists()) {
        await file.delete();
      }
    }
    _myModels.removeWhere((m) => m.id == model.id);
    _updatePopularStatus(model.id, model.copyWith(
      status: 'not_downloaded',
      downloadProgress: 0,
      localPath: '',
    ));
    await _saveModels();
    if (mounted) setState(() {});
  }

  Future<void> _showAddModelDialog() async {
    final nameCtrl = TextEditingController();
    final urlCtrl = TextEditingController();
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('添加自定义模型'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameCtrl,
              decoration: const InputDecoration(labelText: '模型名称', hintText: '例如: MyModel-7B'),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: urlCtrl,
              decoration: const InputDecoration(labelText: 'GGUF文件URL', hintText: 'https://...'),
              maxLines: 2,
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('添加')),
        ],
      ),
    );
    if (result == true && nameCtrl.text.isNotEmpty && urlCtrl.text.isNotEmpty) {
      final id = 'custom_${DateTime.now().millisecondsSinceEpoch}';
      final model = LocalModel(
        id: id,
        name: nameCtrl.text,
        description: '自定义模型',
        source: 'manual',
        downloadUrl: urlCtrl.text,
        fileName: urlCtrl.text.split('/').last,
        fileSize: 0,
      );
      _myModels.add(model);
      await _saveModels();
      if (mounted) setState(() {});
    }
    nameCtrl.dispose();
    urlCtrl.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;

    return Scaffold(
      appBar: AppBar(
        leading: Tooltip(
          message: l10n.settingsPageBackButton,
          child: _TactileIconButton(
            icon: Lucide.ArrowLeft,
            color: cs.onSurface,
            size: 22,
            onTap: () => Navigator.of(context).maybePop(),
          ),
        ),
        title: const Text('本地模型'),
        actions: [
          _TactileIconButton(
            icon: Lucide.Plus,
            color: cs.onSurface,
            size: 22,
            onTap: _showAddModelDialog,
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: cs.primary,
          labelColor: cs.primary,
          unselectedLabelColor: cs.onSurface.withValues(alpha: 0.6),
          tabs: [
            Tab(text: '我的模型 (${_myModels.length})'),
            const Tab(text: '模型广场'),
          ],
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : TabBarView(
              controller: _tabController,
              children: [
                _buildMyModelsTab(cs),
                _buildPopularTab(cs),
              ],
            ),
    );
  }

  Widget _buildMyModelsTab(ColorScheme cs) {
    if (_myModels.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Lucide.Download, size: 64, color: cs.onSurface.withValues(alpha: 0.2)),
            const SizedBox(height: 16),
            Text('还没有本地模型', style: TextStyle(color: cs.onSurface.withValues(alpha: 0.5), fontSize: 16)),
            const SizedBox(height: 8),
            Text('去模型广场下载或手动添加', style: TextStyle(color: cs.onSurface.withValues(alpha: 0.3), fontSize: 13)),
          ],
        ),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
      itemCount: _myModels.length,
      itemBuilder: (ctx, i) => _buildModelCard(_myModels[i], cs, isMyModel: true),
    );
  }

  Widget _buildPopularTab(ColorScheme cs) {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
      itemCount: _popularModels.length + 1,
      itemBuilder: (ctx, i) {
        if (i == 0) {
          return Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(
              '从魔塔(ModelScope)下载热门GGUF模型，下载后即可在对话中使用',
              style: TextStyle(fontSize: 13, color: cs.onSurface.withValues(alpha: 0.6)),
            ),
          );
        }
        return _buildModelCard(_popularModels[i - 1], cs);
      },
    );
  }

  Widget _buildModelCard(LocalModel model, ColorScheme cs, {bool isMyModel = false}) {
    final isDownloaded = model.status == 'downloaded';
    final isDownloading = model.status == 'downloading';

    return Card(
      elevation: 0,
      color: Theme.of(context).brightness == Brightness.dark
          ? Colors.white10
          : Colors.white.withValues(alpha: 0.96),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: cs.outlineVariant.withValues(alpha: 0.12)),
      ),
      margin: const EdgeInsets.only(bottom: 10),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 40, height: 40,
                  decoration: BoxDecoration(
                    color: isDownloaded ? cs.primary.withValues(alpha: 0.12) : cs.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Icon(
                    isDownloaded ? Lucide.Package : Lucide.Box,
                    size: 20,
                    color: isDownloaded ? cs.primary : cs.onSurface.withValues(alpha: 0.5),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(model.name, style: TextStyle(fontSize: 15, fontWeight: AppFontWeights.semibold)),
                      const SizedBox(height: 2),
                      Text(
                        model.description,
                        style: TextStyle(fontSize: 12, color: cs.onSurface.withValues(alpha: 0.6)),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                _buildStatusBadge(model, cs),
              ],
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                _infoChip(Lucide.HardDrive, model.formattedSize, cs),
                if (model.quantization.isNotEmpty) ...[
                  const SizedBox(width: 8),
                  _infoChip(Lucide.Hash, model.quantization, cs),
                ],
                const Spacer(),
                if (isDownloaded) ...[
                  _actionButton('使用', Lucide.Send, cs.primary, () => _useModel(model)),
                  const SizedBox(width: 4),
                  _actionButton('删除', Lucide.Trash, cs.error, () => _deleteModel(model)),
                ]
                else if (isDownloading)
                  _actionButton('取消', Lucide.X, cs.onSurface.withValues(alpha: 0.6), () => _deleteModel(model))
                else
                  _actionButton('下载', Lucide.Download, cs.primary, () => _startDownload(model)),
              ],
            ),
            if (isDownloading) ...[
              const SizedBox(height: 8),
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: model.downloadProgress,
                  minHeight: 4,
                  backgroundColor: cs.surfaceContainerHighest,
                  valueColor: AlwaysStoppedAnimation(cs.primary),
                ),
              ),
              const SizedBox(height: 4),
              Text(
                '${(model.downloadProgress * 100).toStringAsFixed(0)}%',
                style: TextStyle(fontSize: 11, color: cs.onSurface.withValues(alpha: 0.5)),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildStatusBadge(LocalModel model, ColorScheme cs) {
    Color bgColor;
    Color textColor;
    String label;

    switch (model.status) {
      case 'downloaded':
        bgColor = cs.primary.withValues(alpha: 0.12);
        textColor = cs.primary;
        label = '已就绪';
      case 'downloading':
        bgColor = cs.tertiary.withValues(alpha: 0.12);
        textColor = cs.tertiary;
        label = '下载中';
      case 'error':
        bgColor = cs.error.withValues(alpha: 0.12);
        textColor = cs.error;
        label = '失败';
      default:
        bgColor = cs.surfaceContainerHighest;
        textColor = cs.onSurface.withValues(alpha: 0.5);
        label = '未下载';
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: bgColor,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(label, style: TextStyle(fontSize: 11, color: textColor, fontWeight: AppFontWeights.medium)),
    );
  }

  Widget _infoChip(IconData icon, String text, ColorScheme cs) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 12, color: cs.onSurface.withValues(alpha: 0.5)),
        const SizedBox(width: 4),
        Text(text, style: TextStyle(fontSize: 12, color: cs.onSurface.withValues(alpha: 0.6))),
      ],
    );
  }

  Widget _actionButton(String label, IconData icon, Color color, VoidCallback onTap) {
    return TextButton.icon(
      onPressed: onTap,
      icon: Icon(icon, size: 16),
      label: Text(label, style: TextStyle(fontSize: 13)),
      style: TextButton.styleFrom(
        foregroundColor: color,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        minimumSize: Size.zero,
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
      ),
    );
  }
}

class _TactileIconButton extends StatefulWidget {
  const _TactileIconButton({
    required this.icon,
    required this.color,
    required this.onTap,
    this.size = 22,
  });
  final IconData icon;
  final Color color;
  final VoidCallback onTap;
  final double size;

  @override
  State<_TactileIconButton> createState() => _TactileIconButtonState();
}

class _TactileIconButtonState extends State<_TactileIconButton> {
  bool _pressed = false;

  @override
  Widget build(BuildContext context) {
    final base = widget.color;
    final pressColor = base.withValues(alpha: 0.7);
    final icon = Icon(widget.icon, size: widget.size, color: _pressed ? pressColor : base);
    return Semantics(
      button: true,
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTapDown: (_) => setState(() => _pressed = true),
        onTapUp: (_) => setState(() => _pressed = false),
        onTapCancel: () => setState(() => _pressed = false),
        onTap: () {
          try { Haptics.light(); } catch (_) {}
          widget.onTap();
        },
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 6),
          child: icon,
        ),
      ),
    );
  }
}