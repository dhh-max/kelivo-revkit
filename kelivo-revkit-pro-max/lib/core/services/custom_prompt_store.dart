import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/custom_prompt.dart';

/// Persistent storage for user custom prompts using SharedPreferences.
class CustomPromptStore {
  static const String _key = 'kelivo_custom_prompts_v1';

  static Future<List<CustomPrompt>> getAll() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_key);
    if (raw == null || raw.isEmpty) return [];
    try {
      final list = jsonDecode(raw) as List<dynamic>;
      return list
          .whereType<Map<String, dynamic>>()
          .map((e) => CustomPrompt.fromJson(e))
          .toList();
    } catch (_) {
      return [];
    }
  }

  static Future<void> saveAll(List<CustomPrompt> prompts) async {
    final prefs = await SharedPreferences.getInstance();
    final json = jsonEncode(prompts.map((p) => p.toJson()).toList());
    await prefs.setString(_key, json);
  }

  static Future<void> add(CustomPrompt prompt) async {
    final all = await getAll();
    all.add(prompt);
    await saveAll(all);
  }

  static Future<void> update(CustomPrompt prompt) async {
    final all = await getAll();
    final idx = all.indexWhere((p) => p.id == prompt.id);
    if (idx >= 0) {
      all[idx] = prompt;
      await saveAll(all);
    }
  }

  static Future<void> delete(String id) async {
    final all = await getAll();
    all.removeWhere((p) => p.id == id);
    await saveAll(all);
  }

  static Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }
}
