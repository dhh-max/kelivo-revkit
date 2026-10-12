import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:Kelivo/core/models/mobile_background_settings.dart';

/// 大肥鱼是逐帧动画（源：QCYTSN/dsh-dafeiyu，MIT）：Dart 预览按
/// `assets/pet/manifest.json` 播帧，原生 `PetAssets` 读同一份清单。
/// 清单缺动作、帧文件缺失、体积/像素超限都会让浮窗静默停在首帧或干脆
/// 不显示——所以这里把契约钉住。
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Map<String, dynamic> manifest;
  late Map<String, dynamic> clips;

  setUpAll(() {
    final file = File(OverlayPetClips.manifest);
    expect(file.existsSync(), isTrue, reason: '${file.path} 缺失');
    manifest = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    clips = manifest['clips'] as Map<String, dynamic>;
  });

  test('manifest carries exactly the clips the floating window plays', () {
    // 清单里多带动作 = 白占包体（working 就这么被砍掉的），少带 = 状态切不过去。
    expect(
      clips.keys.toSet(),
      {...OverlayPetClips.states, ...OverlayPetClips.reactions},
    );
    for (final name in [...OverlayPetClips.states, ...OverlayPetClips.reactions]) {
      final clip = clips[name] as Map<String, dynamic>?;
      expect(clip, isNotNull, reason: '$name 不在清单里');
      final frames = (clip!['frames'] as List).cast<String>();
      expect(frames, isNotEmpty, reason: '$name 没有帧');
      expect(clip['frameMs'], isA<int>());
      expect(clip['loop'], isA<bool>());
      // 待机必须是循环；不然鱼播完一次就定住。
      if (name == OverlayPetClips.idle) expect(clip['loop'], isTrue);
    }
  });

  test('every frame ships as a decodable webp within the size budget', () {
    var checked = 0;
    for (final entry in clips.values) {
      for (final frame in (entry['frames'] as List).cast<String>()) {
        final file = File('assets/pet/$frame');
        expect(file.existsSync(), isTrue, reason: '${file.path} 缺失');
        final bytes = file.readAsBytesSync();
        expect(bytes.length, lessThan(200 * 1024), reason: '${file.path} 单帧过大');
        final size = _webpSize(bytes);
        expect(size, isNotNull, reason: '${file.path} 不是可解析的 webp');
        // 原生按 FIT_CENTER 缩放，宽高比要一致才不会每帧抖动。
        expect(size!.$1, inInclusiveRange(1, 512));
        expect(size.$2, lessThanOrEqualTo(512));
        checked++;
      }
    }
    expect(checked, greaterThan(1000), reason: '帧数明显偏少，素材可能没打包');
  });

  test('frame aspect ratio is stable across a clip', () {
    final idle = (clips[OverlayPetClips.idle]!['frames'] as List).cast<String>();
    final ratios = idle.take(24).map((frame) {
      final size = _webpSize(File('assets/pet/$frame').readAsBytesSync())!;
      return size.$1 / size.$2;
    }).toSet();
    expect(ratios.length, 1, reason: '同一动作的帧尺寸不一致，播放会跳');
  });

  test('fish keeps the settings round-trip the native side reads', () {
    final fish = MobileBackgroundSettings.fromJson({
      'overlayIconKind': 'fish',
      'overlayIconValue': OverlayPetClips.idle,
    });
    expect(fish.overlayIconKind, 'fish');
    expect(fish.toJson()['overlayIconKind'], 'fish');
    expect(
      MobileBackgroundSettings.fromJson({'overlayIconKind': 'kraken'}).overlayIconKind,
      'app',
    );
  });

  test('snapToEdge defaults on and only an explicit false disables it', () {
    expect(const BackgroundOverlayAppearance().snapToEdge, isTrue);
    expect(BackgroundOverlayAppearance.fromJson(const {}).snapToEdge, isTrue);
    expect(
      BackgroundOverlayAppearance.fromJson(const {'snapToEdge': false}).snapToEdge,
      isFalse,
    );
    expect(
      BackgroundOverlayAppearance.fromJson(
        const BackgroundOverlayAppearance().copyWith(snapToEdge: false).toJson(),
      ).snapToEdge,
      isFalse,
    );
  });
}

/// 读 WebP 尺寸：RIFF 容器里取 VP8/VP8L/VP8X 段的宽高。
(int, int)? _webpSize(Uint8List bytes) {
  if (bytes.length < 30) return null;
  final data = ByteData.sublistView(bytes);
  if (data.getUint32(0, Endian.little) != 0x46464952) return null; // "RIFF"
  if (data.getUint32(8, Endian.little) != 0x50424557) return null; // "WEBP"
  final chunk = data.getUint32(12, Endian.little);
  // VP8X（扩展格式，带 alpha）: 24 位宽高各减一存于 24..29
  if (chunk == 0x58385056) {
    int read(int offset) =>
        bytes[offset] | bytes[offset + 1] << 8 | bytes[offset + 2] << 16;
    return (read(24) + 1, read(27) + 1);
  }
  // VP8L（无损）: 14 位宽高紧跟在 0x2f 签名之后
  if (chunk == 0x4c385056) {
    final bits = bytes[21] | bytes[22] << 8 | bytes[23] << 16 | bytes[24] << 24;
    return ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1);
  }
  // VP8（有损）: 帧头在 26..29
  if (chunk == 0x20385056) {
    return (
      data.getUint16(26, Endian.little) & 0x3FFF,
      data.getUint16(28, Endian.little) & 0x3FFF,
    );
  }
  return null;
}
