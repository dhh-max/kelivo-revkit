import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:image_picker/image_picker.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';
import 'package:provider/provider.dart';
import 'package:syncfusion_flutter_core/theme.dart';
import 'package:syncfusion_flutter_sliders/sliders.dart';

import '../../../core/models/mobile_background_settings.dart';
import '../../../core/providers/settings_provider.dart';
import '../../../core/services/background_icon_store.dart';
import '../../../core/services/mobile_background.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/emoji_picker_dialog.dart';
import '../../../shared/widgets/ios_settings_rows.dart';
import '../../../shared/widgets/section_card.dart';
import '../../../shared/widgets/segmented_tabs.dart';
import '../../../shared/widgets/snackbar.dart';
import '../../../theme/app_font_weights.dart';
import '../widgets/background_status_preview.dart';

/// Android's overlay editor stays on its own page so permissions and actual
/// background-runtime state remain easy to scan on the parent settings page.
class BackgroundOverlaySettingsPage extends StatefulWidget {
  const BackgroundOverlaySettingsPage({super.key, required this.coordinator});
  final MobileBackgroundCoordinator coordinator;

  @override
  State<BackgroundOverlaySettingsPage> createState() =>
      _BackgroundOverlaySettingsPageState();
}

class _BackgroundOverlaySettingsPageState
    extends State<BackgroundOverlaySettingsPage> {
  final _icons = BackgroundIconStore();
  bool _importing = false;
  late BackgroundOverlayAppearance _appearance;

  @override
  void initState() {
    super.initState();
    _appearance = context
        .read<SettingsProvider>()
        .mobileBackground
        .overlayAppearance;
  }

  Future<void> _save(MobileBackgroundSettings value) async {
    final settings = context.read<SettingsProvider>();
    final l10n = AppLocalizations.of(context)!;
    await settings.setMobileBackground(value);
    if (!identical(settings.mobileBackground, value)) return;
    await widget.coordinator.configure(value, l10n);
  }

  Future<void> _saveAppearance(BackgroundOverlayAppearance value) async {
    setState(() => _appearance = value);
    await _save(
      context.read<SettingsProvider>().mobileBackground.copyWith(
        overlayAppearance: value,
      ),
    );
  }

  Future<void> _setIcon(String kind, String value) async {
    final settings = context.read<SettingsProvider>().mobileBackground;
    try {
      await _save(
        settings.copyWith(overlayIconKind: kind, overlayIconValue: value),
      );
    } catch (_) {
      if (kind == 'image') await _icons.deleteOwnedImage(value);
      rethrow;
    }
    if (settings.overlayIconKind == 'image' &&
        settings.overlayIconValue != value) {
      await _icons.deleteOwnedImage(settings.overlayIconValue);
    }
  }

  Future<void> _pickImage() async {
    if (_importing) return;
    setState(() => _importing = true);
    String? imported;
    try {
      final image = await ImagePicker().pickImage(
        source: ImageSource.gallery,
        maxWidth: 1024,
        maxHeight: 1024,
      );
      if (image == null || !mounted) return;
      imported = await _icons.importImage(image.path);
      if (!mounted) {
        await _icons.deleteOwnedImage(imported);
        return;
      }
      await _setIcon('image', imported);
    } catch (_) {
      if (mounted) {
        showAppSnackBar(
          context,
          message: AppLocalizations.of(context)!.backgroundIconError,
          type: NotificationType.error,
        );
      }
    } finally {
      if (mounted) setState(() => _importing = false);
    }
  }

  Future<void> _pickEmoji() async {
    final value = await showEmojiPickerDialog(context);
    if (value != null && mounted) await _setIcon('emoji', value);
  }

  Widget _artwork(MobileBackgroundSettings value) =>
      switch (value.overlayIconKind) {
        'emoji' => Text(
          value.overlayIconValue,
          style: const TextStyle(fontSize: 26),
        ),
        'fish' => _AnimatedFish(
          clip: value.overlayIconValue.isEmpty
              ? OverlayPetClips.idle
              : value.overlayIconValue,
        ),
        'image' => Image.file(
          File(value.overlayIconValue),
          width: 34,
          height: 34,
          fit: BoxFit.cover,
          errorBuilder: (_, _, _) => const Icon(LucideIcons.sparkles, size: 28),
        ),
        _ => Image.asset('assets/app_icon.png', width: 34, height: 34),
      };

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context)!;
    final cs = Theme.of(context).colorScheme;
    final value = context.watch<SettingsProvider>().mobileBackground;
    final a = _appearance;
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(LucideIcons.arrowLeft),
          tooltip: l.settingsPageBackButton,
          onPressed: () => Navigator.of(context).maybePop(),
        ),
        title: Text(l.backgroundOverlayAppearance),
      ),
      body: SafeArea(
        top: false,
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
              child: SectionCard(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    children: [
                      Container(
                        height: (MediaQuery.sizeOf(context).height * .23).clamp(
                          88,
                          184,
                        ),
                        decoration: BoxDecoration(
                          color: cs.onSurface.withValues(alpha: .05),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: LayoutBuilder(
                          builder: (context, constraints) => FittedBox(
                            fit: BoxFit.scaleDown,
                            child: SizedBox(
                              width: constraints.maxWidth,
                              child: Center(
                                child: BackgroundStatusPreview(
                                  title: l.backgroundTaskTitle,
                                  detail: l.backgroundGenerating,
                                  artwork: _artwork(value),
                                  appearance: a,
                                ),
                              ),
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        l.backgroundOverlayPreviewHint,
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          fontSize: 11,
                          color: cs.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 4, 16, 24),
                children: [
                  SegmentedTabs(
                    key: const ValueKey('overlayPresets'),
                    tabs: [
                      SegmentedTab(
                        label: l.backgroundOverlayCard,
                        icon: LucideIcons.rectangleHorizontal,
                      ),
                      SegmentedTab(
                        label: l.backgroundOverlayCircle,
                        icon: LucideIcons.circle,
                      ),
                    ],
                    index: a.isIconOnly ? 1 : 0,
                    onChanged: (index) => unawaited(
                      _saveAppearance(
                        index == 1
                            ? BackgroundOverlayAppearance.circle
                            : const BackgroundOverlayAppearance(),
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  SectionCard(
                    children: [
                      IosSectionHeader(
                        text: l.backgroundOverlaySize,
                        first: true,
                      ),
                      _slider(
                        'overlayWidth',
                        l.backgroundOverlayWidth,
                        a.width,
                        48,
                        400,
                        (v) => a.copyWith(width: v),
                      ),
                      _slider(
                        'overlayHeight',
                        l.backgroundOverlayHeight,
                        a.height,
                        48,
                        180,
                        (v) => a.copyWith(height: v),
                      ),
                      _slider(
                        'overlayCornerRadius',
                        l.backgroundOverlayCornerRadius,
                        a.cornerRadius,
                        0,
                        90,
                        (v) => a.copyWith(cornerRadius: v),
                      ),
                      _slider(
                        'overlayIconSize',
                        l.backgroundOverlayIconSize,
                        a.iconSize,
                        16,
                        120,
                        (v) => a.copyWith(iconSize: v),
                      ),
                      _slider(
                        'overlayProgressSize',
                        l.backgroundOverlayProgressSize,
                        a.progressSize,
                        20,
                        140,
                        (v) => a.copyWith(progressSize: v),
                      ),
                      _slider(
                        'overlayProgressStroke',
                        l.backgroundOverlayProgressStroke,
                        a.progressStrokeWidth,
                        1,
                        12,
                        (v) => a.copyWith(progressStrokeWidth: v),
                        step: .5,
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SectionCard(
                    children: [
                      IosSectionHeader(
                        text: l.backgroundOverlayContent,
                        first: true,
                      ),
                      _switch(
                        'overlayShowProgress',
                        l.backgroundOverlayShowProgress,
                        a.showProgress,
                        (v) => a.copyWith(showProgress: v),
                      ),
                      _switch(
                        'overlayShowTitle',
                        l.backgroundOverlayShowTitle,
                        a.showTitle,
                        (v) => a.copyWith(showTitle: v),
                      ),
                      _switch(
                        'overlayShowSubtitle',
                        l.backgroundOverlayShowSubtitle,
                        a.showSubtitle,
                        (v) => a.copyWith(showSubtitle: v),
                      ),
                      _switch(
                        'overlayShowTime',
                        l.backgroundOverlayShowTime,
                        a.showTime,
                        (v) => a.copyWith(showTime: v),
                      ),
                      _switch(
                        'overlayShowClose',
                        l.backgroundOverlayShowClose,
                        a.showClose,
                        (v) => a.copyWith(showClose: v),
                      ),
                      _switch(
                        'overlayShowBackground',
                        l.backgroundOverlayShowBackground,
                        a.showBackground,
                        (v) => a.copyWith(showBackground: v),
                      ),
                      _switch(
                        'overlayShowBorder',
                        l.backgroundOverlayShowBorder,
                        a.showBorder,
                        (v) => a.copyWith(showBorder: v),
                      ),
                      _switch(
                        'overlaySnapToEdge',
                        l.backgroundOverlaySnapToEdge,
                        a.snapToEdge,
                        (v) => a.copyWith(snapToEdge: v),
                      ),
                      IosSwitchRow(
                        key: const ValueKey('overlayShowInApp'),
                        label: l.backgroundOverlayShowInApp,
                        subtitle: l.backgroundOverlayShowInAppDetail,
                        value: a.showInApp,
                        onChanged: (v) => unawaited(
                          _saveAppearance(a.copyWith(showInApp: v)),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SectionCard(
                    children: [
                      IosSectionHeader(
                        text: l.backgroundOverlayIcon,
                        first: true,
                      ),
                      IosNavRow(
                        icon: LucideIcons.image,
                        label: l.backgroundIconImage,
                        detailText: _importing ? '…' : null,
                        onTap: () => unawaited(_pickImage()),
                      ),
                      IosNavRow(
                        icon: LucideIcons.smile,
                        label: l.backgroundIconEmoji,
                        onTap: () => unawaited(_pickEmoji()),
                      ),
                      IosNavRow(
                        icon: LucideIcons.rotateCcw,
                        label: l.backgroundIconDefault,
                        onTap: () => unawaited(_setIcon('app', '')),
                      ),
                    ],
                  ),
                  // 大肥鱼（本地新增）：逐帧动画形象，动作全自动——待机、
                  // 思考/成功/失败跟任务状态切，拖动与点击有专属反应。
                  const SizedBox(height: 12),
                  SectionCard(
                    children: [
                      IosSectionHeader(
                        text: l.backgroundOverlayPet,
                        first: true,
                      ),
                      IosNavRow(
                        key: const ValueKey('overlayPet-fish'),
                        leading: const _AnimatedFish(size: 26),
                        label: l.backgroundOverlayPet,
                        labelWeight: value.overlayIconKind == 'fish'
                            ? AppFontWeights.semibold
                            : null,
                        trailing: value.overlayIconKind == 'fish'
                            ? Icon(
                                LucideIcons.check,
                                size: 18,
                                color: cs.primary,
                              )
                            : null,
                        onTap: () =>
                            unawaited(_setIcon('fish', OverlayPetClips.idle)),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SectionCard(
                    children: [
                      IosNavRow(
                        key: const ValueKey('overlayAppearanceReset'),
                        icon: LucideIcons.rotateCcw,
                        label: l.backgroundOverlayReset,
                        onTap: () => unawaited(
                          _saveAppearance(const BackgroundOverlayAppearance()),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _switch(
    String key,
    String label,
    bool value,
    BackgroundOverlayAppearance Function(bool) change,
  ) => IosSwitchRow(
    key: ValueKey(key),
    label: label,
    value: value,
    onChanged: (value) => unawaited(_saveAppearance(change(value))),
  );

  Widget _slider(
    String key,
    String label,
    double value,
    double min,
    double max,
    BackgroundOverlayAppearance Function(double) change, {
    double step = 1,
  }) {
    final cs = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(14, 8, 14, 0),
      child: Column(
        children: [
          Row(
            children: [
              Expanded(
                child: Text(label, style: const TextStyle(fontSize: 14)),
              ),
              Text(
                value.toStringAsFixed(value % 1 == 0 ? 0 : 1),
                style: TextStyle(fontSize: 13, color: cs.onSurfaceVariant),
              ),
            ],
          ),
          SfSliderTheme(
            data: SfSliderThemeData(
              activeTrackHeight: 6,
              inactiveTrackHeight: 6,
              activeTrackColor: cs.primary,
              inactiveTrackColor: cs.onSurface.withValues(alpha: .12),
              thumbRadius: 9,
              overlayRadius: 18,
            ),
            child: SfSlider(
              key: ValueKey(key),
              value: value,
              min: min,
              max: max,
              stepSize: step,
              onChanged: (dynamic v) =>
                  setState(() => _appearance = change((v as num).toDouble())),
              onChangeEnd: (dynamic v) =>
                  unawaited(_saveAppearance(change((v as num).toDouble()))),
            ),
          ),
        ],
      ),
    );
  }
}

/// 预览里的大肥鱼按素材清单逐帧播放所选动作——静态缩略图会让人以为
/// 浮窗里也是张死图。为了省解码，每 [frameStep] 帧取一张（≈8fps 的观感）。
class _AnimatedFish extends StatefulWidget {
  const _AnimatedFish({this.size = 46, this.clip = OverlayPetClips.idle});
  final double size;
  final String clip;

  @override
  State<_AnimatedFish> createState() => _AnimatedFishState();
}

class _AnimatedFishState extends State<_AnimatedFish> {
  static const int frameStep = 3;

  List<String> _frames = const [];
  Timer? _timer;
  int _index = 0;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  @override
  void didUpdateWidget(covariant _AnimatedFish old) {
    super.didUpdateWidget(old);
    if (old.clip != widget.clip) {
      _timer?.cancel();
      _frames = const [];
      _index = 0;
      unawaited(_load());
    }
  }

  Future<void> _load() async {
    final raw = await rootBundle.loadString(OverlayPetClips.manifest);
    final clips = (jsonDecode(raw) as Map<String, dynamic>)['clips'] as Map;
    final clip = clips[widget.clip] as Map?;
    final frames = (clip?['frames'] as List?)?.cast<String>() ?? const [];
    if (!mounted || frames.isEmpty) return;
    setState(() => _frames = frames);
    final step = (clip?['frameMs'] as num?)?.toInt() ?? 42;
    _timer = Timer.periodic(
      Duration(milliseconds: step * frameStep),
      (_) => setState(() => _index = (_index + frameStep) % _frames.length),
    );
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_frames.isEmpty) {
      return SizedBox(width: widget.size, height: widget.size);
    }
    return Image.asset(
      'assets/pet/${_frames[_index]}',
      width: widget.size,
      height: widget.size,
      fit: BoxFit.contain,
      gaplessPlayback: true,
      errorBuilder: (_, _, _) => SizedBox(width: widget.size, height: widget.size),
    );
  }
}
