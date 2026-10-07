import 'package:flutter/material.dart';
import 'package:Kelivo/relaygo/app.dart';
import 'package:Kelivo/relaygo/config/constants.dart';
import 'package:Kelivo/relaygo/database/database_helper.dart';
import 'package:Kelivo/relaygo/utils/encryption.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await DatabaseHelper.init();

  // 主密钥：首次运行生成并持久化到 vault 盒
  final vault = DatabaseHelper.vault;
  String masterKey;
  if (vault.containsKey(Constants.masterKeyName)) {
    masterKey = vault.get(Constants.masterKeyName) as String;
  } else {
    masterKey = EncryptionUtil.generateMasterKeyBase64();
    await vault.put(Constants.masterKeyName, masterKey);
  }
  EncryptionUtil.init(masterKey);

  runApp(const MyApp());
}
