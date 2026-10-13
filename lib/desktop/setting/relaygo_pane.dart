import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:Kelivo/relaygo/app.dart';
import 'package:Kelivo/relaygo/config/constants.dart';
import 'package:Kelivo/relaygo/database/database_helper.dart';
import 'package:Kelivo/relaygo/screens/home_screen.dart';
import 'package:Kelivo/relaygo/utils/encryption.dart';

/// 把 RelayGo 网关作为 Kelivo 设置里的一个面板嵌入。
///
/// - 首次进入时懒初始化 Hive 与 AES-256 主密钥（[DatabaseHelper.init]
///   与 [EncryptionUtil.init] 都自带幂等）。
/// - 用 [ChangeNotifierProvider] 为 RelayGo 子树提供独立的 [AppState]，
///   不影响 Kelivo 主 APP 的 Provider 树。
/// - RelayGo 的 [HomeScreen] 自带 Scaffold + 底部导航，直接放进面板即可。
@pragma('vm:entry-point')
class DesktopRelayGoPane extends StatefulWidget {
  const DesktopRelayGoPane({super.key});

  @override
  State<DesktopRelayGoPane> createState() => _DesktopRelayGoPaneState();
}

class _DesktopRelayGoPaneState extends State<DesktopRelayGoPane> {
  Future<void>? _initFuture;

  Future<void> _ensureInitialized() {
    return _initFuture ??= _init();
  }

  Future<void> _init() async {
    if (!DatabaseHelper.initialized) {
      await DatabaseHelper.init();
    }
    if (!EncryptionUtil.initialized) {
      final vault = DatabaseHelper.vault;
      String? masterKey;
      if (vault.containsKey(Constants.masterKeyName)) {
        masterKey = vault.get(Constants.masterKeyName) as String?;
      }
      if (masterKey == null || masterKey.isEmpty) {
        masterKey = EncryptionUtil.generateMasterKeyBase64();
        await vault.put(Constants.masterKeyName, masterKey);
      }
      EncryptionUtil.init(masterKey);
    }
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<void>(
      future: _ensureInitialized(),
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const Center(child: CircularProgressIndicator());
        }
        if (snapshot.hasError) {
          final cs = Theme.of(context).colorScheme;
          return Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.error_outline, size: 48, color: cs.error),
                  const SizedBox(height: 12),
                  Text(
                    'RelayGo 网关初始化失败：\n${snapshot.error}',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                ],
              ),
            ),
          );
        }
        return ChangeNotifierProvider<AppState>(
          create: (_) => AppState(),
          child: const _RelayGoHomeHost(),
        );
      },
    );
  }
}

class _RelayGoHomeHost extends StatelessWidget {
  const _RelayGoHomeHost();

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, app, _) {
        // 消费 settings.language 让监听生效（与 RelayGo 原版 MyApp 一致）
        app.settings.language;
        return const HomeScreen();
      },
    );
  }
}
