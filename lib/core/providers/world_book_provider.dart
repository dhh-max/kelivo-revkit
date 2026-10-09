import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

import '../database/business_preferences.dart';
import '../models/world_book.dart';
import '../services/world_book_store.dart';

class WorldBookProvider with ChangeNotifier {
  WorldBookProvider({required this.preferences})
    : _store = WorldBookStore(preferences);

  /// SoLab APK 知识书种子预置的版本 key（<1 时执行一次，执行后置为 1）。
  /// 与其它两个 provider 使用同一前缀、不同后缀，避免先初始化的
  /// provider 把共用版本 key 置 1 后导致其余种子永不写入。
  static const String _apkModSeedVersionKey =
      'apk_mod_knowledge_seed_version_world_book';
  static const String _apkModAssistantId = 'builtin-apk-mod';
  static const String _apkModBookId = 'apk_mod_knowledge_book';

  /// 开发助手知识书种子（与 APK 种子同构，各自独立版本 key，
  /// 避免先初始化的那份把共用 key 置位导致另一份永不写入）。
  static const String _devSeedVersionKey =
      'dev_knowledge_seed_version_world_book';
  // 绑定 id 必须是内置开发助手**真实**的助手 id（builtin-dev-agent）。
  // 这里过去写成 'builtin-dev-assistant'（不存在的 id），种子知识书绑了个
  // 空对象——开发助手一直读不到这本知识书（2026-10-03 修）。
  // 绑定块每次初始化都会重跑，改成正确 id 后下一次启动即自动补绑。
  static const String _devAssistantId = 'builtin-dev-agent';
  static const String _devBookId = 'dev_knowledge_book';
  static const Map<String, String> _apkModSeedV22ContentHashes =
      <String, String>{
        'apk_mod_entry_confirmation_discipline':
            '3f01b72df67bb3ac9eb7e9baca1f005c721da2349833785e6d2f10f4e23b145d',
        'apk_mod_entry_no_budget':
            '041273a909252fdc2e9f0a99fd403a8e19e7608104012f7d9242982a4448daab',
        'apk_mod_entry_multi_signal':
            '5ad7315f9066be68859d8836355ef9c5b5454cd68c08a32a7759cd870cfa82a6',
        'apk_mod_entry_relentless_goal':
            '42835534f868a8765b1929b4034aa29d7762148aaf3e60b22b2177046c657d6a',
        'apk_mod_entry_detection_evasion':
            'e75c96612934c0d477ad651a632e66d27a1b5afd2b2ae9edfb6d5a9393ed5aa3',
      };

  final BusinessPreferences preferences;
  final WorldBookStore _store;
  List<WorldBook> _books = const <WorldBook>[];
  bool _initialized = false;
  Future<void>? _initializationFuture;
  Map<String, List<String>> _activeIdsByAssistant =
      const <String, List<String>>{};
  Map<String, bool> _collapsedBooks = const <String, bool>{};

  List<WorldBook> get books => List<WorldBook>.unmodifiable(_books);

  WorldBook? getById(String id) {
    try {
      return _books.firstWhere((e) => e.id == id);
    } catch (_) {
      return null;
    }
  }

  List<String> activeBookIdsFor(String? assistantId) {
    final key = WorldBookStore.assistantKey(assistantId);
    if (_activeIdsByAssistant.containsKey(key)) {
      return List<String>.unmodifiable(_activeIdsByAssistant[key]!);
    }
    final fallback =
        _activeIdsByAssistant[WorldBookStore.assistantKey(null)] ??
        const <String>[];
    return List<String>.unmodifiable(fallback);
  }

  bool isBookActive(String id, {String? assistantId}) =>
      activeBookIdsFor(assistantId).contains(id);

  List<WorldBook> activeBooksFor(String? assistantId, {List<String>? bookIds}) {
    final ids = (bookIds ?? activeBookIdsFor(assistantId)).toSet();
    return _books
        .where((book) => book.enabled && ids.contains(book.id))
        .toList(growable: false);
  }

  bool isBookCollapsed(String id) => _collapsedBooks[id] ?? false;

  Future<void> initialize() {
    if (_initialized) return Future<void>.value();
    return _initializationFuture ??= _initialize();
  }

  Future<void> _initialize() async {
    try {
      await loadAll();
      // 两个内置助手各有一本随包知识书：逆向助手（APK 方法论）与开发助手
      // （Android/Flutter/Web/接口/测试纪律）。
      await ensureApkModSeed();
      await ensureDevSeed();
      _initialized = true;
    } finally {
      _initializationFuture = null;
    }
  }

  Future<void> loadAll() async {
    try {
      _books = await _store.getAll();
      _activeIdsByAssistant = await _store.getActiveIdsByAssistant();
      final collapsed = await _store.getCollapsedBooksMap();
      final knownIds = _books.map((e) => e.id).toSet();
      final cleanedCollapsed = <String, bool>{
        for (final entry in collapsed.entries)
          if (knownIds.contains(entry.key)) entry.key: entry.value,
      };
      _collapsedBooks = cleanedCollapsed;

      if (cleanedCollapsed.length != collapsed.length) {
        await _store.setCollapsedMap(cleanedCollapsed);
      }

      notifyListeners();
    } catch (e) {
      debugPrint('Failed to load world books: $e');
      _books = const <WorldBook>[];
      _activeIdsByAssistant = const <String, List<String>>{};
      _collapsedBooks = const <String, bool>{};
      notifyListeners();
    }
  }

  Future<void> addBook(WorldBook book) async {
    await _store.add(book);
    await loadAll();
  }

  Future<void> updateBook(WorldBook book) async {
    if (!book.enabled) {
      try {
        final map = await _store.getActiveIdsByAssistant();
        final next = <String, List<String>>{};
        bool changed = false;
        for (final entry in map.entries) {
          final filtered = entry.value
              .where((e) => e != book.id)
              .toList(growable: false);
          if (filtered.length != entry.value.length) changed = true;
          next[entry.key] = filtered;
        }
        if (changed) {
          await _store.setActiveIdsMap(next);
        }
      } catch (_) {}
    }
    await _store.update(book);
    await loadAll();
  }

  Future<void> deleteBook(String id) async {
    await _store.delete(id);
    await loadAll();
  }

  Future<void> setEntryEnabled(
    String bookId,
    String entryId,
    bool enabled,
  ) async {
    final index = _books.indexWhere((book) => book.id == bookId);
    if (index < 0) return;
    final book = _books[index];
    final next = book.copyWith(
      entries: [
        for (final entry in book.entries)
          entry.id == entryId ? entry.copyWith(enabled: enabled) : entry,
      ],
    );
    _books = List<WorldBook>.from(_books)..[index] = next;
    notifyListeners();
    await _store.save(_books);
  }

  Future<void> clear() async {
    await _store.clear();
    _books = const <WorldBook>[];
    _activeIdsByAssistant = const <String, List<String>>{};
    _collapsedBooks = const <String, bool>{};
    notifyListeners();
  }

  Future<void> reorderBooks({
    required int oldIndex,
    required int newIndex,
  }) async {
    if (_books.isEmpty) return;
    if (oldIndex < 0 || oldIndex >= _books.length) return;
    if (newIndex < 0 || newIndex >= _books.length) return;
    final list = List<WorldBook>.from(_books);
    final item = list.removeAt(oldIndex);
    list.insert(newIndex, item);
    _books = list;
    notifyListeners();
    await _store.save(_books);
  }

  Future<void> reorderEntries({
    required String bookId,
    required int oldIndex,
    required int newIndex,
  }) async {
    final bookIndex = _books.indexWhere((e) => e.id == bookId);
    if (bookIndex == -1) return;
    final book = _books[bookIndex];
    final entries = List<WorldBookEntry>.from(book.entries);
    if (entries.isEmpty) return;
    if (oldIndex < 0 || oldIndex >= entries.length) return;
    if (newIndex < 0 || newIndex >= entries.length) return;
    final item = entries.removeAt(oldIndex);
    entries.insert(newIndex, item);
    final nextBook = book.copyWith(entries: entries);
    final nextBooks = List<WorldBook>.from(_books);
    nextBooks[bookIndex] = nextBook;
    _books = nextBooks;
    notifyListeners();
    await _store.save(_books);
  }

  Future<void> setBookCollapsed(String id, bool collapsed) async {
    final key = id.trim();
    if (key.isEmpty) return;

    final next = Map<String, bool>.from(_collapsedBooks);
    next[key] = collapsed;
    _collapsedBooks = next;
    notifyListeners();
    await _store.setCollapsed(key, collapsed);
  }

  Future<void> toggleBookCollapsed(String id) async {
    await setBookCollapsed(id, !isBookCollapsed(id));
  }

  Future<void> setActiveBookIds(List<String> ids, {String? assistantId}) async {
    final key = WorldBookStore.assistantKey(assistantId);
    final nextMap = Map<String, List<String>>.from(_activeIdsByAssistant);
    nextMap[key] = ids.toSet().toList(growable: false);
    _activeIdsByAssistant = nextMap;
    notifyListeners();
    await _store.setActiveIds(ids, assistantId: assistantId);
  }

  Future<void> toggleActiveBookId(String id, {String? assistantId}) async {
    final set = activeBookIdsFor(assistantId).toSet();
    if (set.contains(id)) {
      set.remove(id);
    } else {
      final book = getById(id);
      if (book == null) return;
      if (!book.enabled) return;
      set.add(id);
    }
    await setActiveBookIds(
      set.toList(growable: false),
      assistantId: assistantId,
    );
  }

  /// 按 Agent 已激活的知识书和任务主题返回少量相关条目。
  ///
  /// APK Agent 通过工具主动读取，避免把整本世界书塞入每轮提示词。
  List<Map<String, dynamic>> retrieveActiveEntries({
    required String? assistantId,
    required List<String> topics,
    int limit = 3,
  }) {
    // 泛 topic 过滤：路由 knowledgeTopics 里的超泛词（工具/定位/分析/验证/
    // 文件）几乎匹配所有条目（content contains +2），参与打分只会稀释排序。
    const genericTopics = <String>{
      'apk',
      '工作流',
      'workflow',
      '规则',
      'rules',
      '工具',
      '定位',
      '分析',
      '验证',
      '文件',
    };
    final normalizedTopics = topics
        .map((topic) => topic.trim().toLowerCase())
        .where((topic) => topic.isNotEmpty && !genericTopics.contains(topic))
        .toSet();
    if (limit <= 0) {
      return const <Map<String, dynamic>>[];
    }

    final activeIds = activeBookIdsFor(assistantId).toSet();
    final candidates = <Map<String, dynamic>>[];
    for (final book in _books) {
      if (!book.enabled || !activeIds.contains(book.id)) continue;
      for (final entry in book.entries) {
        if (!entry.enabled || entry.content.trim().isEmpty) continue;
        final name = entry.name.toLowerCase();
        final content = entry.content.toLowerCase();
        final keywords = entry.keywords
            .map((keyword) => keyword.trim().toLowerCase())
            .where((keyword) => keyword.isNotEmpty)
            .toList(growable: false);
        var score = 0;
        if (entry.constantActive) score += 1;
        for (final topic in normalizedTopics) {
          if (name.contains(topic)) score += 8;
          if (content.contains(topic)) score += 2;
          for (final keyword in keywords) {
            if (keyword.contains(topic) || topic.contains(keyword)) score += 6;
          }
        }
        if (score == 0) continue;
        candidates.add({
          'bookId': book.id,
          'bookName': book.name,
          'entryId': entry.id,
          'entryName': entry.name,
          'priority': entry.priority,
          'constantActive': entry.constantActive,
          'score': score,
          'content': entry.content,
        });
      }
    }
    candidates.sort((a, b) {
      final alwaysOrder = ((b['constantActive'] as bool) ? 1 : 0).compareTo(
        (a['constantActive'] as bool) ? 1 : 0,
      );
      if (alwaysOrder != 0) return alwaysOrder;
      final builtInOrder = ((a['bookId'] as String) == _apkModBookId ? 1 : 0)
          .compareTo((b['bookId'] as String) == _apkModBookId ? 1 : 0);
      if (builtInOrder != 0) return builtInOrder;
      final scoreOrder = (b['score'] as int).compareTo(a['score'] as int);
      if (scoreOrder != 0) return scoreOrder;
      return (b['priority'] as int).compareTo(a['priority'] as int);
    });
    return candidates.take(limit.clamp(1, 5).toInt()).toList(growable: false);
  }

  /// 预置 SoLab APK 助手的种子世界书「SoLab APK 知识书」。
  ///
  /// 模式参考 [AssistantProvider.ensureDefaults]：仅在版本 key < 1 时执行
  /// 一次；用户已有同名书则跳过创建，激活列表只追加不清空，绝不覆盖
  /// 用户已有数据。
  ///
  /// 版本 key 2：按「条目 id」补齐新增条目（工具能力总表、分步提问纪律、
  /// 检测规避），存量用户不会缺新知识，也不会重复已有条目。
  /// 版本 key 3：对种子条目做内容同步（检测规避扩展、定位法新条目），
  /// 保留用户对 enabled/priority 等的开关设置，仅覆盖内容与关键词。
  /// 版本 key 9：执行纪律改版——工作目录原项目是只读备份，目标明确即
  /// 果断执行（快准狠）；新增「用户提示词优先」条目；全条目关键词扩充。
  /// 版本 key 10：新增「目标达成：不择手段」条目——目标降级链
  /// （VIP → 免广告奖励直发 → 试用次数/时间劫持）与掐断策略
  /// （初始化/连接处/资源清理三路逐一尝试）。
  /// 版本 key 11：新增「无预算纪律」条目——不存在工具调用预算，
  /// 禁止以「预算有限/要收敛/次数用完」为借口减少工作或提前停下。
  /// 版本 key 12：新增「定位纪律：多信号交叉」条目——双信号定案、
  /// 混淆短名语义恢复、失败升级链（改方法→改字段→上游入口→跨层堵死）。
  /// 版本 key 13：品牌更名——种子书「SoLab APK 知识书」改名为
  /// 「SoLab 知识书」，条目与用户开关全部保留。
  /// 版本 key 14：工具总表切换到当前 20 个执行工具；仅更新仍含旧入口的
  /// 内置条目，不覆盖用户已改写的其他知识内容。
  /// 版本 key 15：修正按需资源、工具说明和远期时间值；只更新仍含旧文案的
  /// 内置条目，不覆盖用户改写内容。
  /// 版本 key 16：明确用户已给出修改目标时，dryRun 后直接执行。
  /// 版本 key 17：全轨道止损状态机、广告四体系和双目标共享分析。
  /// 版本 key 18：预览可同次执行，失败保留凭证并返回精确执行参数。
  /// 版本 key 19：新增统一工作区纪律和 Flutter 体系识别知识；只补缺失
  /// 条目，不覆盖用户修改过的现有内容。
  /// 版本 key 20：签名兼容注入固定为原始 APK 的首次写操作，只执行一次。
  /// 版本 key 23：统一直接证据标准，移除失真的固定调用次数和“顺手清理”，
  /// 并把检测能力说明改为以当前 schema/报告为准。
  /// 版本 key 24：定位改为目标驱动；工具自动组合证据、换路和验证候选。
  /// 版本 key 25：打断后按当前会话快照续接,待验证状态不再跨会话读入。
  /// 版本 key 26：新增「补丁编码假设验证」条目（写补丁前验证寄存器分配）。
  /// 版本 key 27：新增「SO 深度方法（符号/结构/模拟）」条目——三个
  /// 方法论技能索引与模拟结论的证据等级纪律。
  /// 版本 key 28：条目名与正文统一英文（关键词保留中文供检索匹配）。
  Future<void> ensureApkModSeed() async {
    try {
      final book = _apkModKnowledgeBook();
      final version = preferences.getInt(_apkModSeedVersionKey) ?? 0;

      // v13：旧名迁移——书名仍是旧种子名时重命名为新名（用户改过名则
      // 不动，与旧版按名匹配的行为一致）。
      if (version < 13) {
        var renamed = false;
        for (final b in _books) {
          if (b.id == _apkModBookId && b.name.trim() == 'SoLab APK 知识书') {
            await _store.update(b.copyWith(name: book.name));
            renamed = true;
          }
        }
        if (renamed) await loadAll();
      }

      var currentBook = getById(book.id);

      if (currentBook == null) {
        await _store.add(book);
        currentBook = book;
      } else if (version < 12) {
        // v1~v11 → v12：新增「定位纪律：多信号交叉」条目
        // （保留用户开关设置，仅同步种子条目内容）。
        final byId = <String, WorldBookEntry>{
          for (final e in currentBook.entries) e.id: e,
        };
        final merged = <WorldBookEntry>[];
        for (final seedEntry in book.entries) {
          final existing = byId[seedEntry.id];
          if (existing == null) {
            merged.add(seedEntry);
          } else {
            merged.add(
              existing.copyWith(
                name: seedEntry.name,
                content: seedEntry.content,
                keywords: seedEntry.keywords,
                priority: seedEntry.priority,
              ),
            );
          }
        }
        await _store.update(currentBook.copyWith(entries: merged));
        currentBook = await _store.getAll().then(
          (books) => books.firstWhere((b) => b.id == book.id),
        );
      }

      if (version < 14) {
        final seedEntry = book.entries.firstWhere(
          (entry) => entry.id == 'apk_mod_entry_tool_map',
        );
        var changed = false;
        final entries = currentBook.entries
            .map((entry) {
              if (entry.id != seedEntry.id ||
                  !entry.content.contains('get_solab_tool_map')) {
                return entry;
              }
              changed = true;
              return entry.copyWith(
                name: seedEntry.name,
                content: seedEntry.content,
                keywords: seedEntry.keywords,
                priority: seedEntry.priority,
              );
            })
            .toList(growable: false);
        if (changed) {
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 15) {
        final seedEntries = <String, WorldBookEntry>{
          for (final entry in book.entries) entry.id: entry,
        };
        const staleMarkers = <String, String>{
          'apk_mod_entry_tool_map': '当前 Agent 和 MCP 共用 20 个执行工具。',
          'apk_mod_entry_step_questioning': '用户给出新指示时先复述确认再执行。',
          'apk_mod_entry_detection_evasion': '返回 long 的方法强制远期 0xffffff。',
        };
        var changed = false;
        final entries = currentBook.entries
            .map((entry) {
              final marker = staleMarkers[entry.id];
              final seedEntry = seedEntries[entry.id];
              if (marker == null ||
                  seedEntry == null ||
                  !entry.content.contains(marker)) {
                return entry;
              }
              changed = true;
              return entry.copyWith(
                name: seedEntry.name,
                content: seedEntry.content,
                keywords: seedEntry.keywords,
                priority: seedEntry.priority,
              );
            })
            .toList(growable: false);
        if (changed) {
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 16) {
        final seedEntries = <String, WorldBookEntry>{
          for (final entry in book.entries) entry.id: entry,
        };
        const staleMarkers = <String, String>{
          'apk_mod_entry_risk_and_sign': '所有写操作先 dryRun，再确认。',
          'apk_mod_entry_tool_map': '说明命中与风险后一次确认，再原样携带 previewToken 执行。',
        };
        var changed = false;
        final entries = currentBook.entries
            .map((entry) {
              final marker = staleMarkers[entry.id];
              final seedEntry = seedEntries[entry.id];
              if (marker == null ||
                  seedEntry == null ||
                  !entry.content.contains(marker)) {
                return entry;
              }
              changed = true;
              return entry.copyWith(
                name: seedEntry.name,
                content: seedEntry.content,
                keywords: seedEntry.keywords,
                priority: seedEntry.priority,
              );
            })
            .toList(growable: false);
        if (changed) {
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 17) {
        final seedEntries = <String, WorldBookEntry>{
          for (final entry in book.entries) entry.id: entry,
        };
        const synchronizedIds = <String>{
          'apk_mod_entry_no_budget',
          'apk_mod_entry_minimal_patch',
          'apk_mod_entry_ad_types',
        };
        final entries = currentBook.entries
            .map((entry) {
              final seedEntry = seedEntries[entry.id];
              if (!synchronizedIds.contains(entry.id) || seedEntry == null) {
                return entry;
              }
              return entry.copyWith(
                name: seedEntry.name,
                content: seedEntry.content,
                keywords: seedEntry.keywords,
                priority: seedEntry.priority,
              );
            })
            .toList(growable: false);
        await _store.update(currentBook.copyWith(entries: entries));
        currentBook = currentBook.copyWith(entries: entries);
      }

      if (version < 18) {
        final seedEntries = <String, WorldBookEntry>{
          for (final entry in book.entries) entry.id: entry,
        };
        const synchronizedIds = <String>{
          'apk_mod_entry_risk_and_signature',
          'apk_mod_entry_tool_map',
          'apk_mod_entry_preview_and_memory',
        };
        final entries = currentBook.entries
            .map((entry) {
              final seedEntry = seedEntries[entry.id];
              if (!synchronizedIds.contains(entry.id) || seedEntry == null) {
                return entry;
              }
              return entry.copyWith(
                name: seedEntry.name,
                content: seedEntry.content,
                keywords: seedEntry.keywords,
                priority: seedEntry.priority,
              );
            })
            .toList(growable: false);
        await _store.update(currentBook.copyWith(entries: entries));
        currentBook = currentBook.copyWith(entries: entries);
      }

      if (version < 19) {
        final seedEntries = <String, WorldBookEntry>{
          for (final entry in book.entries) entry.id: entry,
        };
        const addedIds = <String>{
          'apk_mod_entry_workspace_output',
          'apk_mod_entry_flutter_system_identification',
        };
        final existingIds = currentBook.entries
            .map((entry) => entry.id)
            .toSet();
        final additions = <WorldBookEntry>[
          for (final id in addedIds)
            if (!existingIds.contains(id) && seedEntries[id] != null)
              seedEntries[id]!,
        ];
        if (additions.isNotEmpty) {
          final entries = <WorldBookEntry>[
            ...currentBook.entries,
            ...additions,
          ];
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 20) {
        final seedEntry = book.entries.firstWhere(
          (entry) => entry.id == 'apk_mod_entry_risk_and_signature',
        );
        const previousContent =
            '修改风险与签名要点：直接删除 .so 原生库会闪退（UnsatisfiedLinkError），优先定位并修改对应的 loadLibrary/System.load 入口；删除 Manifest 组件可能导致 ActivityNotFoundException，优先只清有证据的权限或元数据；DEX 修改跳过 <init>/<clinit>。用户已明确精确修改目标时，支持的工具使用 dryRun=true+applyAfterPreview=true 一次完成预览与写入；预览有 warning 或无变更会自动阻断。纯 dryRun 返回 applyArguments，必须原样执行，禁止重复预览。产物用 apk_sign 签名后安装；改完方法用 smali_read 回读核验。';
        final entries = currentBook.entries
            .map(
              (entry) =>
                  entry.id == seedEntry.id && entry.content == previousContent
                  ? seedEntry
                  : entry,
            )
            .toList(growable: false);
        if (entries != currentBook.entries) {
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 21) {
        final seedEntry = book.entries.firstWhere(
          (entry) => entry.id == 'apk_mod_entry_no_budget',
        );
        const previousContent =
            '分析止损纪律：状态机按单目标限制启动3次、定位3次、核验8次、补丁4次，工具结果约60K token；会员和广告共享启动与一次 Blutter analyze，各自独立计算 locate/verify。达到上限不是偷懒借口：必须输出已有证据、缺失证据和确定恢复动作；ambiguous/clues_only/not_found 只允许一次询问用户已知文案、等级值或广告出现位置，不继续逐词搜索。长结果只读预览和一次追加，同参数第3次、同失败步骤第3次均由工具阻断。';
        final entries = currentBook.entries
            .map(
              (entry) =>
                  entry.id == seedEntry.id && entry.content == previousContent
                  ? seedEntry
                  : entry,
            )
            .toList(growable: false);
        if (entries != currentBook.entries) {
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 22) {
        const previousContents = <String, String>{
          'apk_mod_entry_tool_map':
              '本轮只声明与当前任务相关且已启用的本地工具；外接工具按需加载。先 route_task；复用有效报告。DEX 单线索用 dex_search；类名、字段名、方法名、字符串、数值、指令序列中有多类证据时用 method_by_features 一次取同一方法交集，再走 class_outline → smali_read → dex_xref；字段读写用 dex_xref(target=dex_field:...)。修改只使用当前声明的写工具。用户已授权精确修改时，优先 dryRun=true+applyAfterPreview=true 一次完成；需要判断的纯预览必须原样调用 applyArguments。直接 DEX 补丁后只需 apk_sign；只有编辑过解码目录、资源或 Manifest 时才 apk_rebuild。',
          'apk_mod_entry_preview_and_memory':
              '写操作必须先预览。精确目标已获授权时用 dryRun=true+applyAfterPreview=true，同一次调用先预览再写入；warning 或无变更不会自动执行。纯 dryRun 返回完整 applyArguments，原样调用即可，禁止靠模型重组参数。previewToken 有效期 30 分钟，写入失败仍可用原 token 重试；写入成功后，基于旧 APK 的全部预览自动失效，后续必须使用 nextInputPath。用户反馈安装结果后调用 record_apk_patch_verification。',
        };
        const replacements = <String, String>{
          'apk_mod_entry_tool_map':
              '本轮只声明与当前任务相关且已启用的本地工具；外接工具按需加载。先 route_task，复用有效报告。DEX 单线索用 dex_search；多类证据用 method_by_features 在同一方法取交集，再走 class_outline → smali_read → dex_xref；字段读写用 dex_xref(target=dex_field:...)。工具参数和写操作契约以当前工具 schema 为准。',
          'apk_mod_entry_preview_and_memory':
              '写操作契约、预览参数与确认语义以当前写工具 schema 为准。用户反馈安装结果后调用 record_apk_patch_verification。',
        };
        final entries = currentBook.entries
            .map((entry) {
              final replacement = replacements[entry.id];
              if (replacement == null ||
                  entry.content != previousContents[entry.id]) {
                return entry;
              }
              return entry.copyWith(content: replacement);
            })
            .toList(growable: false);
        if (entries != currentBook.entries) {
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 23) {
        final seedEntries = <String, WorldBookEntry>{
          for (final entry in book.entries) entry.id: entry,
        };
        final entries = currentBook.entries
            .map((entry) {
              final previousHash = _apkModSeedV22ContentHashes[entry.id];
              final replacement = seedEntries[entry.id];
              if (previousHash == null ||
                  replacement == null ||
                  sha256.convert(utf8.encode(entry.content)).toString() !=
                      previousHash) {
                return entry;
              }
              return entry.copyWith(
                name: replacement.name,
                content: replacement.content,
                keywords: replacement.keywords,
                priority: replacement.priority,
              );
            })
            .toList(growable: false);
        await _store.update(currentBook.copyWith(entries: entries));
        currentBook = currentBook.copyWith(entries: entries);
      }

      if (version < 24) {
        const previousContent =
            '本轮只声明与当前任务相关且已启用的本地工具；外接工具按需加载。先 route_task，复用有效报告。DEX 单线索用 dex_search；多类证据用 method_by_features 在同一方法取交集，再走 class_outline → smali_read → dex_xref；字段读写用 dex_xref(target=dex_field:...)。工具参数和写操作契约以当前工具 schema 为准。';
        final replacement = book.entries.firstWhere(
          (entry) => entry.id == 'apk_mod_entry_tool_map',
        );
        final entries = currentBook.entries
            .map(
              (entry) =>
                  entry.id == replacement.id && entry.content == previousContent
                  ? entry.copyWith(content: replacement.content)
                  : entry,
            )
            .toList(growable: false);
        if (entries != currentBook.entries) {
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 25) {
        const previousContents = <String, String>{
          'apk_mod_entry_tool_map':
              '本轮只声明与当前任务相关且已启用的本地工具；外接工具按需加载。先 route_task，复用有效报告。用户只需给目标和已有线索；DEX 默认调用 dex_search(auto)，由工具自由组合类、方法、字段、字符串、数字和指令证据，严格交集失败时自行拆分换路并排序。候选不是结果：继续执行 nextActions 或任选等价工具核验真实代码、调用处和返回语义，直到得到可修改、可回读的结论；不要要求用户选择定位方式。字段读写可直接用 dex_xref(target=dex_field:...)。工具参数和写操作契约以当前 schema 为准。',
          'apk_mod_entry_preview_and_memory':
              '写操作契约、预览参数与确认语义以当前写工具 schema 为准。用户反馈安装结果后调用 record_apk_patch_verification。',
        };
        final seedEntries = <String, WorldBookEntry>{
          for (final entry in book.entries) entry.id: entry,
        };
        final entries = currentBook.entries
            .map((entry) {
              final previous = previousContents[entry.id];
              final replacement = seedEntries[entry.id];
              if (previous == null ||
                  replacement == null ||
                  entry.content != previous) {
                return entry;
              }
              return entry.copyWith(content: replacement.content);
            })
            .toList(growable: false);
        if (entries != currentBook.entries) {
          await _store.update(currentBook.copyWith(entries: entries));
          currentBook = currentBook.copyWith(entries: entries);
        }
      }

      if (version < 26) {
        // v26：新增「补丁编码假设验证」条目——写 SO 补丁前必须在原始
        // 二进制验证寄存器/编码假设（如 NULL_REG 是 x17 还是 x22），
        // 禁止照搬 Blutter 文档默认分配。
        const newEntryId = 'apk_mod_entry_patch_encoding_verification';
        if (!currentBook.entries.any((entry) => entry.id == newEntryId)) {
          final seedEntry = book.entries.firstWhere(
            (entry) => entry.id == newEntryId,
          );
          final merged = <WorldBookEntry>[...currentBook.entries, seedEntry];
          await _store.update(currentBook.copyWith(entries: merged));
          currentBook = currentBook.copyWith(entries: merged);
        }
      }

      if (version < 27) {
        // v27：新增「SO 深度方法（符号/结构/模拟）」条目——三个方法论技能
        // （reverse-skills MIT 改写）的索引与模拟结论的证据等级纪律。
        const newEntryId = 'apk_mod_entry_so_methodology';
        if (!currentBook.entries.any((entry) => entry.id == newEntryId)) {
          final seedEntry = book.entries.firstWhere(
            (entry) => entry.id == newEntryId,
          );
          final merged = <WorldBookEntry>[...currentBook.entries, seedEntry];
          await _store.update(currentBook.copyWith(entries: merged));
          currentBook = currentBook.copyWith(entries: merged);
        }
      }

      if (version < 29) {
        // v29：提示词精简（2026-09-18）——与决策契约重复的散文压缩、只留
        // 领域事实（关键词一字未动，检索行为不变）。同步机制同 v28：只覆盖
        // 种子条目的 name/content，保留用户对 enabled/priority 的开关与排序。
        final byId = <String, WorldBookEntry>{
          for (final e in currentBook.entries) e.id: e,
        };
        final merged = <WorldBookEntry>[];
        var changed = false;
        for (final seedEntry in book.entries) {
          final existing = byId[seedEntry.id];
          if (existing == null) {
            merged.add(seedEntry);
            changed = true;
          } else if (existing.name != seedEntry.name ||
              existing.content != seedEntry.content) {
            merged.add(
              existing.copyWith(
                name: seedEntry.name,
                content: seedEntry.content,
              ),
            );
            changed = true;
          } else {
            merged.add(existing);
          }
        }
        if (changed) {
          await _store.update(currentBook.copyWith(entries: merged));
          currentBook = currentBook.copyWith(entries: merged);
        }
      }

      // 绑定到逆向助手（builtin-apk-mod）：在既有激活列表上追加，不清空用户配置。
      final activeMap = await _store.getActiveIdsByAssistant();
      final key = WorldBookStore.assistantKey(_apkModAssistantId);
      final existing = activeMap[key] ?? const <String>[];
      if (!existing.contains(book.id)) {
        await _store.setActiveIds(
          <String>{...existing, book.id}.toList(growable: false),
          assistantId: _apkModAssistantId,
        );
      }
      // v30：书名与助手名对齐（「SoLab 知识书」→「逆向助手 · 知识书」）。
      // 用户改过名则不动（按名匹配，与旧迁移一致）。
      if (version < 30) {
        var renamedToAssistantName = false;
        for (final b in _books) {
          if (b.id == _apkModBookId && b.name.trim() == 'SoLab 知识书') {
            await _store.update(b.copyWith(name: book.name));
            renamedToAssistantName = true;
          }
        }
        if (renamedToAssistantName) await loadAll();
      }

      await preferences.setInt(_apkModSeedVersionKey, 30);
      await loadAll();
    } catch (e) {
      debugPrint('Failed to seed SoLab world book: $e');
    }
  }

  /// 预置开发助手的种子世界书「开发助手 · 知识书」，并绑定到该助手。
  ///
  /// 与 [ensureApkModSeed] 同构：按版本 key 只做增量迁移，保留用户对同名条目的
  /// 开关与编辑；绑定走「在既有激活列表上追加」，不清空用户配置。
  Future<void> ensureDevSeed() async {
    try {
      final book = _devKnowledgeBook();
      final version = preferences.getInt(_devSeedVersionKey) ?? 0;
      var currentBook = getById(book.id);
      if (currentBook == null) {
        await _store.add(book);
        currentBook = book;
      } else if (version < 1) {
        // 首次迁移：按 id 合并种子条目（用户改过的同名条目保留其内容）。
        final byId = <String, WorldBookEntry>{
          for (final e in currentBook.entries) e.id: e,
        };
        final merged = <WorldBookEntry>[
          for (final seedEntry in book.entries)
            byId[seedEntry.id] ?? seedEntry,
          for (final e in currentBook.entries)
            if (!book.entries.any((s) => s.id == e.id)) e,
        ];
        await _store.update(currentBook.copyWith(entries: merged));
        currentBook = currentBook.copyWith(entries: merged);
      }

      // v2：正文升级——种子条目的名称/关键词/优先级/正文按最新版本覆盖
      // （用户对条目的开关仍保留；种子条目的正文以包内版本为准）。
      if (version < 2) {
        final latest = getById(book.id) ?? currentBook;
        final byId = <String, WorldBookEntry>{
          for (final e in latest.entries) e.id: e,
        };
        final upgraded = <WorldBookEntry>[
          for (final seedEntry in book.entries)
            (byId[seedEntry.id] ?? seedEntry).copyWith(
              name: seedEntry.name,
              content: seedEntry.content,
              keywords: seedEntry.keywords,
              priority: seedEntry.priority,
            ),
          for (final e in latest.entries)
            if (!book.entries.any((s) => s.id == e.id)) e,
        ];
        await _store.update(latest.copyWith(entries: upgraded));
        currentBook = latest.copyWith(entries: upgraded);
      }

      final activeMap = await _store.getActiveIdsByAssistant();
      final key = WorldBookStore.assistantKey(_devAssistantId);
      final existing = activeMap[key] ?? const <String>[];
      if (!existing.contains(book.id)) {
        await _store.setActiveIds(
          <String>{...existing, book.id}.toList(growable: false),
          assistantId: _devAssistantId,
        );
      }
      await preferences.setInt(_devSeedVersionKey, 2);
      await loadAll();
    } catch (e) {
      debugPrint('Failed to seed dev world book: $e');
    }
  }

  WorldBook _devKnowledgeBook() {
    return WorldBook(
      id: _devBookId,
      name: '开发助手 · 知识书',
      description:
          'Always-on engineering knowledge for the development assistant: Android build/packaging pitfalls, Flutter symptom-to-fix table, data-flow scoping, web performance budgets, API error taxonomy, executable testing commands, release discipline and upstream-sync method.',
      enabled: true,
      entries: const <WorldBookEntry>[
        WorldBookEntry(
          id: 'dev_entry_android_build',
          name: 'Android Build & Packaging Pitfalls',
          priority: 20,
          keywords: <String>[
            'Android',
            'Gradle',
            'AGP',
            'Manifest',
            'R8',
            'ProGuard',
            'minify',
            'abiFilters',
            'INSTALL_FAILED',
            'targetSdk',
            'signing',
            'v2',
            '16 KB',
            'page size',
            '打包',
            '签名',
            '闪退',
          ],
          content:
              'targetSdk 31+: every component with an intent-filter must set android:exported explicitly, otherwise install fails. R8/ProGuard: keep reflection/JNI/serialization entry points (native methods, @Keep, Gson/JSON field classes) or you get ClassNotFoundException only at runtime; verify with a release build, never debug. INSTALL_FAILED_NO_MATCHING_ABIS => check abiFilters/splits vs the device ABI (arm64-v8a for modern phones). Android 15+ requires 16 KB page-aligned native libs: check LOAD segment align (0x4000) with llvm-readelf -l on each .so, and use NDK r27+; misaligned libs install but crash on launch. Signing: v2/v3 required for targetSdk 30+; verify the produced APK with apksigner verify --print-certs, and remember debug-signed artifacts cannot replace a release install (signature mismatch) - uninstall first or keep the same key.',
        ),
        WorldBookEntry(
          id: 'dev_entry_flutter_symptoms',
          name: 'Flutter Symptom to Fix Table',
          priority: 20,
          keywords: <String>[
            'Flutter',
            'Dart',
            'RenderFlex',
            'overflow',
            'setState',
            'FutureBuilder',
            'ListView',
            'jank',
            'rebuild',
            '布局',
            '卡顿',
            '溢出',
          ],
          content:
              '"RenderFlex overflowed" = unbounded constraints: wrap the flexible child in Expanded/Flexible, or bound it with SizedBox/ConstrainedBox - do not paper over with clipBehavior. ListView/GridView inside a Column needs an explicit height or shrinkWrap + NeverScrollableScrollPhysics (only for short, non-recycling lists); for long lists use CustomScrollView + slivers. FutureBuilder: build the Future in initState/State, not in build(), otherwise it refetches on every rebuild. "setState() called after dispose" = guard with if (!mounted) return and cancel StreamSubscription/Timer/AnimationController in dispose. Jank: find rebuild scope with debugPrintRebuildDirtyWidgets and DevTools "Highlight repaints"; wrap expensive subtrees in RepaintBoundary; prefer const constructors and context.select/Selector over whole-page watch; move heavy JSON/parsing work off the frame with compute/Isolate.run. Text scaling: always test with the system font scale at 1.3x - fixed-height rows break first.',
        ),
        WorldBookEntry(
          id: 'dev_entry_state_scoping',
          name: 'State, Caching and Session Scoping',
          priority: 10,
          keywords: <String>[
            'state',
            'cache',
            'session',
            'conversation',
            'scope',
            'singleton',
            'Provider',
            '状态',
            '缓存',
            '会话',
          ],
          content:
              'Per-conversation/per-session state must be keyed by its owner (conversationId/assistantId/userId) - a single process-wide slot means session A model/config leaks into session B (this exact bug hit our workflow host registration: one slot per process made B generate with A model and bill A conversation). Cache only at a boundary you own and can invalidate: prefer deriving values, and give every cache a key + invalidation point. Every async boundary needs three outcomes wired: success, error and cancellation; cancellation must also detach listeners. Prefer one source of truth per data flow: if two places can mutate the same value, make one of them a projection.',
        ),
        WorldBookEntry(
          id: 'dev_entry_web_budgets',
          name: 'Web Performance and a11y Budgets',
          priority: 10,
          keywords: <String>[
            'web',
            'frontend',
            'LCP',
            'CLS',
            'INP',
            'bundle',
            'accessibility',
            'contrast',
            '前端',
            '性能',
            '可访问性',
          ],
          content:
              'LCP: preload the hero image or critical font, add fetchpriority="high" and never lazy-load above-the-fold media. CLS: reserve space with width/height or CSS aspect-ratio, and use font-display: swap with a fallback whose metrics match. INP: split long tasks (>50 ms), batch DOM reads then DOM writes to avoid layout thrash, and debounce scroll/resize handlers. Bundle: route-level code splitting, tree-shake, and check the bundle report for duplicated dependencies; ship source maps. a11y is functional: contrast >= 4.5:1, visible focus-visible styles, one H1 per page, label every input, alt text or empty alt for decorative images, respect prefers-reduced-motion, and keep all actions keyboard reachable.',
        ),
        WorldBookEntry(
          id: 'dev_entry_api_errors',
          name: 'API Contract and Error Taxonomy',
          priority: 10,
          keywords: <String>[
            'API',
            'REST',
            '接口',
            '错误码',
            'pagination',
            'idempotency',
            'retry',
            'timeout',
            '分页',
          ],
          content:
              'Return errors as a tagged envelope: {code, message, retryable, details}. Status mapping: 400 validation, 401 unauthenticated, 403 unauthorized, 404 not found, 409 conflict/stale version, 422 semantically invalid, 429 rate limited (send Retry-After), 5xx server. Never return an empty list or 200 to mean "unknown" - that is indistinguishable from a real empty result and hides bugs. Any POST that can be retried needs an idempotency key. Prefer cursor pagination over offset for mutable datasets. Clients: explicit timeouts, jittered exponential backoff, and only retry idempotent operations; log the request id, not the secrets. Watch for N+1 queries when a list endpoint fans out per row.',
        ),
        WorldBookEntry(
          id: 'dev_entry_testing_commands',
          name: 'Executable Testing Discipline',
          priority: 10,
          keywords: <String>[
            'test',
            'tests',
            'unit test',
            'golden',
            'regression',
            '测试',
            '用例',
            '回归',
            '验证',
          ],
          content:
              'Run only what the change touches: flutter test <file> --name "<pattern>"; a whole-suite run is a release gate, not an inner loop. New behaviour ships with a paired case; a bug fix starts from a failing case that reproduces it. Assert observable behaviour (public API, rendered output, persisted state), not private fields. For time/randomness inject a clock/seed or use fakeAsync - never sleep. Golden tests: review the image diff, then flutter test --update-goldens <file> and commit both. Before blaming your change for a failure, reproduce the baseline (e.g. git stash push -- lib/ and re-run) and report exact pass/fail counts plus the command used.',
        ),
        WorldBookEntry(
          id: 'dev_entry_release_discipline',
          name: 'Release and Artifact Discipline',
          priority: 10,
          keywords: <String>[
            'release',
            'artifact',
            'version',
            'build',
            'rollback',
            'changelog',
            '发布',
            '版本',
            '产物',
            '回滚',
          ],
          content:
              'Pin the toolchain (JDK/SDK/Flutter/Node versions) in one place and record the exact build command, so an artifact can be rebuilt from a reviewed commit. Bump the version/build number for every delivered artifact and keep the previous artifact as the rollback point. Verification means the artifact was installed and exercised (adb install + launch, or apksigner verify for signing), not that the build exited 0. Keep release notes factual: what changed, what was verified, what was not. Never hand-edit generated files to fix a release; fix the generator and regenerate.',
        ),
        WorldBookEntry(
          id: 'dev_entry_upstream_sync',
          name: 'Upstream Sync Method',
          priority: 10,
          keywords: <String>[
            'upstream',
            'sync',
            'merge',
            'rebase',
            'conflict',
            'fork',
            '上游',
            '同步',
            '冲突',
            '分支',
          ],
          content:
              'Upstream-first: where upstream implements a capability, adopt upstream wholesale and drop the fork variant - per-version re-adaptation is the expensive path. Keep fork-only capabilities in dedicated (ours-only) files, and leave only a short, documented list of hook points inside upstream files (one line where possible): those hooks are what you re-apply on the next sync. Never splice old fork blocks back into a rewritten upstream file - it drags in obsolete dependencies and produces compile storms. After a sync, run the wiring guards (registry consistency, server/host tests, provider audit) plus the per-feature test files; orphan detection (unreferenced fork files) is the fastest signal that a hook was lost.',
        ),
      ],
    );
  }

  WorldBook _apkModKnowledgeBook() {
    return WorldBook(
      id: _apkModBookId,
      name: '逆向助手 · 知识书',
      description: 'Built-in knowledge for the APK modification assistant: toolchain flow, ad SDKs, modification risk, slimming and packing judgement.',
      enabled: true,
      entries: const <WorldBookEntry>[
        WorldBookEntry(
          id: 'apk_mod_entry_mt_toolchain',
          name: 'External MT MCP (optional)',
          priority: 20,
          keywords: <String>[
            'MT修改',
            'MT工具',
            'edit_session',
            'locator',
            'mt_apk',
          ],
          content:
              'MT Manager is an optional external MCP: use its mt_* tools only when the user has configured an MT MCP server and explicitly asks for the MT flow; the built-in toolchain (analyze/locate/patch/sign/verify) is fully self-contained — always prefer built-in tools and never depend on or wait for MT. If MT is truly required: mt_apk_open the target first (the APK argument is named apk, not path; the session id is sessionId), edit_open to create an editing session, read_text for locator and targetVersion, edit_text to submit changes (each edits[] item carries mode/matchText/writeText), edit_check with runBuildChecks=true, then build with sign=true. Locator forms: axml:/, dex_class:/, dex_method:/, zip_entry:/, resource:0x...; valueXml must be the complete value. On business errors (WORKSPACE_NOT_FOUND/EDIT_SESSION_NOT_FOUND/TARGET_VERSION_MISMATCH) rebuild the session or refresh the version per the message, then retry. MT artifacts and the built-in artifact index are separate systems.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_ad_sdk',
          name: 'Ad SDK Quick Reference',
          priority: 10,
          keywords: <String>[
            '广告SDK',
            '穿山甲',
            '腾讯广告',
            '快手广告',
            'AdMob',
            '去广告',
            '广告',
            'Pangle',
            'GDT',
            '优量汇',
            'Mintegral',
            'TopOn',
            '信息流',
            '插屏',
            '开屏',
          ],
          content:
              'Typical ad SDK package names: Tencent GDT 腾讯广告 (com.qq.e.*), Pangle 穿山甲 (com.bytedance.sdk.openadsdk.*), Kuaishou 快手 (com.kuaishou.ad.*), Baidu 百度 (com.baidu.mobads.*), Sigmob (com.sigmob.*), MiMeng (com.miui.zeus.*), Mintegral (com.mbridge.*), AdMob (com.google.android.gms.ads.*), CAS (com.cleversolutions.ads.*), TapTap (com.tapsdk.*), TopOn (com.anythink.*), Beizi (com.beizi.*), JD JAD (com.jd.ad.*), Moqi (com.moqi.*). Component signals: ad-related Activities, loadAd/onAdLoad callbacks, Banner/rewarded/interstitial views, and ad components or permissions declared in the manifest.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_risk_and_signature',
          name: 'Modification Risk & Signature',
          priority: 10,
          keywords: <String>[
            '签名',
            '重打包',
            '闪退',
            'UnsatisfiedLinkError',
            '验签',
            '证书',
            '安装失败',
            '崩溃',
            'loadLibrary',
            '死代码',
            '回读',
          ],
          content:
              'Risk & signature essentials: deleting .so libraries outright crashes (UnsatisfiedLinkError) — locate and patch the loadLibrary/System.load entry instead; removing manifest components can cause ActivityNotFoundException — remove only evidenced permissions or metadata; skip <init>/<clinit> in DEX edits. Analysis, signature compatibility, modification, rebuild and signing are all independently callable; unless the user asks to skip bypass or the Workbench disables it, run the standalone signature_bypass tool on the unmodified original before the first business write (explicit mode wins, otherwise the Workbench setting). Use its outputPath as the sole input for later DEX/SO/Manifest/resource edits, keep signatureBypass=false afterward, and never back-fill or repeat injection after modifying. Neither dpatch nor original_apk may modify the original directly. When the user has authorized the exact modification, preview-capable tools run dryRun=true+applyAfterPreview=true in one call; warnings or no-change previews auto-block. A pure dryRun returns applyArguments that must be executed verbatim — never re-preview. Sign the final artifact with apk_sign before installing; read patched methods back with smali_read.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_slim_candidates',
          name: 'Slimming Candidate Rules',
          priority: 10,
          keywords: <String>[
            '精简',
            '.proto',
            '未知文件',
            'SO',
            'ABI',
            '删除文件',
            '清理',
            '多余',
            '无用',
            '体积',
            '瘦身',
            'arm64',
            'armeabi',
          ],
          content:
              'Slimming candidate rules: unknown formats (.proto/.pb/.bin) must first be searched for references in DEX (strings, class names, resource ids); only unreferenced files become delete candidates — never blind-delete by extension; .so libraries stay by default unless no loadLibrary reference exists; ABI filtering (e.g. arm64-v8a only) narrows device compatibility and needs an explicit user-facing impact note; permissions showing no static call sites are static-scan misses that may still be used by the system or dynamically — mark them needs-confirmation. Every candidate cites its evidence.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_unpacking',
          name: 'Packing Detection',
          priority: 10,
          keywords: <String>[
            '脱壳',
            '加固',
            '壳',
            '360加固',
            '乐固',
            '加壳',
            '梆梆',
            '爱加密',
            'libshell',
            'libDexHelper',
            'dex加密',
          ],
          content:
              'Check for a packer before modifying: common ones include 360 Jiagu, Tencent Legu, Bangcle and Ijiami. Patching a packed APK usually does nothing — the real dex is decrypted and loaded at runtime. Correct flow: confirm unpacking state first; for unpacked packages verify dex parses, packer .so files (libshell, libDexHelper) are removed and the entry class is intact; for packed packages tell the user unpacking is required and refuse direct modification. Unpacking-related actions require user confirmation.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_confirmation_discipline',
          name: 'Pre-Write Summary',
          priority: 10,
          keywords: <String>['修改计划', '变更清单', '风险', '验证', '变更', '执行前', '影响'],
          content:
              'Before writing, give only the necessary summary: goal, exact locator, decisive evidence, change, risk and verification method. With a clear authorized goal, go straight into the tool preview without re-asking; ask only when the goal is unclear, the plan has a real trade-off, or the preview mismatches. Facts, inferences and to-verify items stay separate; never invent content tools did not return.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_tool_map',
          name: 'Local Modification Tool Map',
          priority: 20,
          keywords: <String>[
            '工具',
            'patch_apk',
            '什么时候用',
            '选工具',
            '怎么改',
            '用哪个',
            '修改流程',
            '工具链',
            '怎么去广告',
            '怎么精简',
          ],
          content:
              'Declare only enabled local tools relevant to the current task; external tools load on demand. Read the injected apk_resume_state first: after an interruption resume from activeArtifact, latestSoArtifact, recentToolCheckpoints and pendingChanges; a fresh report with resumableLineage=true remains the current chain baseline — never re-run full analysis. Never borrow artifact notes from other conversations. The user only supplies the goal and existing leads; DEX defaults to dex_search(auto), letting the tool combine and split class/method/field/string/number/instruction evidence and rank results. Candidates are not results: keep verifying real code, call sites and return semantics until the conclusion is patchable and re-readable. Tool arguments and write contracts follow the current schema.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_workspace_output',
          name: 'Unified Workspace & Artifact Paths',
          priority: 20,
          keywords: <String>[
            '工作目录',
            '工作区',
            '路径',
            '产物',
            '重复分析',
            '缓存',
            '找不到路径',
            'nextInputPath',
            'workspace',
            'output',
          ],
          content:
              'Path discipline: confirm sourceApk, workspaceRoot and the current input via the report or workspace tools first; bind one source APK to exactly one workspace named after the app — never analyze the same APK under both the work-directory root and an app subdirectory. Every tool\'s outputPath/nextInputPath is the sole next input and must pass through verbatim; never guess paths from file names. Deliverable APKs, reports, decompilation output and patch records live in that workspace; internal temp directories are for short-term computation only, cleaned when the task ends, and never serve as delivery locations. When a path is missing, query list_workspace_apks or get_apk_project_info for the real path instead of re-running full analysis.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_flutter_system_identification',
          name: 'Flutter AOT Obfuscated Field Location',
          priority: 20,
          keywords: <String>[
            'pp.txt',
            'Flutter',
            'libapp.so',
            'Blutter',
            '字段混淆',
            '字段偏移',
            '数据流',
            '立即数',
          ],
          content:
              'Flutter AOT obfuscated location assumes no business names, field names or constants. Extract multiple semantic clues from the user goal and converge on the real field key in pp.txt; when the key appears only in a parser, use trace to build the key-reference -> field-write -> same-offset-read -> register-consumption chain. Raise confidence only when decisionEvidence proves the read value enters a comparison, branch, boolean result or return; low candidates sharing an offset must never be modified. For user-supplied integers, values checks raw immediates, Dart Smis and pool ints together; addressing offsets and collection lengths are not business values. The conclusion must close on all three: semantics, field data flow, and a real branch/return.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_patch_encoding_verification',
          name: 'Patch Encoding Assumption Verification',
          priority: 20,
          keywords: <String>[
            '寄存器',
            '编码',
            'patchHex',
            'edit_hex',
            'writeAsm',
            'NULL_REG',
            'x17',
            'x22',
            '字节',
            '手写补丁',
            '汇编',
            '写补丁',
          ],
          content:
              'Verify encoding assumptions in the original binary before writing SO patch bytes; never copy default register allocations from docs or generic patterns. Allocation differs per build: Blutter docs assume NULL_REG=x17, but many builds actually use x22 (callee-saved, held across calls), while x17/IP1 is a platform scratch register that may hold garbage at runtime. Verification takes 30 seconds: use so_analyze(action=hexdump/search) to count the exact encoding across the whole SO — e.g. add x1,x17,#0x20 hits 0 times while add x1,x22,#0x20 hits hundreds, ruling x17 out. The final patch bytes must match the compiler\'s native same-semantics instructions byte for byte; for hand-written assembly, first find a compiler-generated same-pattern instruction in the same or a neighboring function as reference. When passing patches to edit_hex prefer edits[i].va (absolute VA, aligned with disasm output) over relative byteOffset math; build must pass editSessionId explicitly or it is blocked by EDIT_SESSION_REQUIRED.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_preview_and_memory',
          name: 'Preview Confirmation & Verification',
          priority: 20,
          keywords: <String>[
            'dryRun',
            'previewToken',
            '确认',
            '验证',
            '记忆',
            '预览',
            'preview',
            '凭证',
            '过期',
            '安装包有效',
            '无效',
            '记录验证',
          ],
          content:
              'Write contracts, preview arguments and confirmation semantics follow the current write-tool schema. Pending changes live only in the current conversation snapshot; never read other conversations\' artifact notes or write long-term memory. Call record_apk_patch_verification only after the user installs and explicitly reports back, merging into the single per-app memory entry.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_step_questioning',
          name: 'Execution Discipline: Decisive',
          priority: 20,
          keywords: <String>[
            '提问',
            '确认',
            '分步',
            '一步一步',
            'ask_user_input_v0',
            '备份',
            '快准狠',
            '评估',
            '犹豫',
            '直接执行',
            '该动手就动手',
            '畏手畏脚',
            '不懂就问',
            '预算',
            '收敛',
          ],
          content:
              'Execution discipline (decisive): the original in the work directory is a read-only backup — every change happens on copies or intermediates. With a clear goal, execute directly and warn about risks in one sentence; ask only when the goal is unclear or materially different plans exist, when dryRun hits clearly mismatch the goal, or when leads are insufficient. Ask everything in one go, and treat a new user instruction as the current goal immediately.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_no_budget',
          name: 'Analysis Performance & Stop-Loss',
          priority: 20,
          keywords: <String>[
            '预算',
            '工具预算',
            '预算有限',
            '收敛',
            '要收敛',
            '次数',
            '限额',
            '上限',
            '省着',
            '节省调用',
            '聚焦',
            '时间不多了',
            '来不及',
            '干不完',
            '做不完',
            '挑重点',
            '先做能做的',
            '放弃',
            '跳过',
          ],
          content:
              'Analysis performance discipline: there is no fixed call count and stage budgets are soft hints; the ~80K visible-evidence cap stops runaway, not a quota to fill. Every call must be able to change candidate ranking, evidence level or patch approach — otherwise stop. Membership and ads may share one workspace analysis and Blutter index while keeping separate locating evidence. Long results default to compact summaries; paginate only when hasMore/nextOffset exists and the next page would change the decision; after a failure on the same parameters, switch evidence dimension.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_user_hint_first',
          name: 'User Prompt First',
          priority: 20,
          keywords: <String>[
            '提示',
            '提示词',
            '用户说',
            '用户提到',
            '指定',
            '按需求',
            '别瞎找',
            '瞎找',
            '定位线索',
            '多思考',
          ],
          content:
              'Read the user\'s exact words before calling tools — they usually carry locating hints: file names, class/method names, SDK/vendor names, UI text, feature descriptions (membership, splash, check-in). Treat those hints as the first locating lead: a named file is analyzed first, a named feature goes straight to its entry; never ignore the hints for directionless full scans. Repeated misses on the same signal mean the direction is wrong — re-read the user\'s words instead of swapping keywords for more blind scanning. When leads are insufficient, ask everything at once via ask_user_input_v0 (smallest gap), never guess.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_multi_signal',
          name: 'Locating Discipline: Multi-Signal Cross-Check',
          priority: 20,
          keywords: <String>[
            '多信号',
            '交叉验证',
            '置信度',
            'confidence',
            '单信号',
            '混淆',
            '短名',
            '语义恢复',
            '改字段',
            '上游入口',
            '跨层堵死',
            '改不动',
            '无效',
          ],
          content:
              'Locating sources, in the order that usually pays off: strings/resources, constants, call relations, control-flow shape, field reads/writes, return-value propagation. Recover obfuscated short names via callers, callees, field READ/WRITE, signatures and addresses. Method returns, fields, upstream entries, call-site branches and cross-layer paths stay independently selectable — a failure switches the observation dimension instead of escalating.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_relentless_goal',
          name: 'Local Alternative Paths',
          priority: 20,
          keywords: <String>[
            '替代路径',
            '本地消费点',
            '搞不定',
            '做不到',
            '达不到',
            '没效果',
            '未生效',
            'VIP',
            '会员',
            '解锁',
            '免广告',
            '奖励',
            '激励视频',
            '试用',
            '次数',
            '限免',
            '保护',
            '校验',
            '初始化',
            '掐断',
            '连接处',
            '清理',
            '降级',
          ],
          content:
              'Local alternative paths: when the original goal faces a server-side check, evaluate only local equivalents tied to this APK\'s evidence — local entitlement consumption, reward callbacks, trial counters or validity computation. Each path must first prove a real local consumer exists, then pick the smallest side effect; with no local consumption evidence, state the boundary explicitly. Init, connection points, resources, components and permissions are judged separately — never widen the change surface for incidental cleanup.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_detection_evasion',
          name: 'Detection Evasion & Time Hijack',
          priority: 10,
          keywords: <String>[
            'VPN',
            '模拟器',
            '检测规避',
            'isvpn',
            'isemulator',
            'removeVpnDetection',
            'removeEmulatorDetection',
            'Root',
            '反调试',
            'isrooted',
            'isdebuggable',
            '时间劫持',
            'getExpireTime',
            '会员',
            'VIP',
            'isVip',
            '过期',
            '试用',
            '强制true',
          ],
          content:
              'Detection evasion and time edits follow the current patch_apk_dex_methods schema and current report candidates; never rely on historical keyword counts. Name hits only produce candidates; check return types, real method bodies, callers and field data flow first, then submit the minimal qualifiedId set. Never batch-edit constructors, class initializers or callbacks by name. Block immediately and narrow the target when a preview is too broad or contains unrelated methods; local edits never replace server-side checks.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_locating',
          name: 'Code Location Method: Verify Before Modify',
          priority: 10,
          keywords: <String>[
            '定位',
            '字符串搜索',
            '抓包',
            'Jadx',
            '验证',
            '找不到方法',
            '找不到',
            '定位不到',
            '界面文字',
            '日志',
            'logcat',
          ],
          content:
              'When the report misses but the user names a feature, never guess method names — collect leads systematically: 1) string search (highest hit rate) over visible UI text such as 「会员」「开屏」「签到」; 2) capture field names (vipLevel, token) searched in decompiled output; 3) log analysis (logcat TAGs to narrow classes); 4) cross references (field reads/writes, callers, return values). Core rule: verify before modifying — cross-confirm the site via strings, field reads/writes, call chains and disassembly, then make the minimal permanent change, so a wrong site never wastes a sign-and-install cycle.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_minimal_patch',
          name: 'Single-Point Fix & Minimal Change',
          priority: 20,
          keywords: <String>[
            '单点修复',
            '入口方法',
            '最小修改',
            'adEntryMethodMatches',
            '别到处改',
            '杜绝',
            'splash',
            '开屏',
            '入口',
            '上游',
            '批量',
            '只改一处',
          ],
          content:
              'Single-point fix rule: for ads first separate SDK init, display trigger, remote config and container UI. Prefer proven local display gates: constant-false bool returns like shouldShowAd/canShowAd; nop_out or a verified branch replacement for void display triggers like show/play. Touch initSdk/initAd only when the call chain proves it is the sole upstream entry and skipping it leaves no placeholder or crash — stopping init is never equal to disabling ad display. Remote config or container UI hits alone are leads.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_ad_types',
          name: 'Eight Ad Types Quick Reference',
          priority: 10,
          keywords: <String>[
            '广告类型',
            'splash',
            'banner',
            'feed',
            'interstitial',
            'reward',
            'fullVideo',
            'native',
            'rewardInterstitial',
            '信息流',
            '激励插屏',
            '开屏广告',
            '横幅',
            '激励视频',
            '原生广告',
          ],
          content:
              'Eight main ad types: 1 splash, 2 banner, 3 feed, 4 interstitial, 5 reward video, 6 full video, 7 native, 8 reward interstitial. Locate by querying the actual type\'s display triggers (showSplashAd/showFeedAd/showInterstitialAd/showRewardedAd/showNativeAd) and confirm business calls with callers/xref; SDK init, remote config or container views never prove display is disabled on their own.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_evidence_ladder',
          name: 'Reverse-Locating Evidence Chain',
          priority: 20,
          keywords: <String>[
            '界面文字',
            '资源 ID',
            '布局',
            '抓包',
            '日志',
            '交叉引用',
            '调用链',
            '调用方',
            '反查',
          ],
          content:
              'Locate in evidence order: UI text or resource ids, then layouts and callers; for network problems reverse-look-up code from capture fields; runtime errors narrow classes via log TAGs; upstream entries get confirmed with cross references. Record each step as lead -> real method definition -> caller -> preview hit.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_engine_boundaries',
          name: 'Engine & Rule Boundaries',
          priority: 10,
          keywords: <String>[
            'Flutter',
            'Unity',
            'React Native',
            'Xamarin',
            'Smali 正则',
            'libapp.so',
            'il2cpp',
            '游戏引擎',
            '跨平台',
          ],
          content:
              'Identify the engine by file features first: Flutter via flutter_assets/libapp.so, React Native via bundle, Unity via il2cpp/metadata, Xamarin via DLLs. Automatic tools handle only verifiable DEX, Manifest and ZIP entries; raw smali regexes are manual research leads and never auto-executed. To add signals, use the feature-rule library UI in the APK workbench to add/import/toggle and validate their hit range with dryRun.',
        ),
        WorldBookEntry(
          id: 'apk_mod_entry_so_methodology',
          name: 'SO Deep Methods (Symbols/Structs/Emulation)',
          priority: 10,
          keywords: <String>[
            '符号恢复',
            '结构体',
            'Unicorn',
            'Unidbg',
            '模拟执行',
            '预验证',
            'stripped',
            '无符号',
            'jni_bridge',
            '伪签名',
            '反模拟',
          ],
          content:
              'SO work has three built-in methodology skills, read on demand via get_solab_skill: '
              'apk_symbol_recovery (recover symbols by intersecting exports/imports/Java_* with DEX native declarations), '
              'apk_struct_recovery (an offset becomes a field only when >=2 functions access it with the same width; a single access is a lead), '
              'apk_emulation_verify (unidbg_dispatch session: session_open/session_memory_write/session_call/session_registers; '
              'signature compatibility can be machine-verified before install, and JNI/syscall/anti-emulation gaps are stubbed item by item per framework_matrix).'
              'Simulation evidence is machine-level and not device verification — label it honestly; a gap failing three times stops and reports.',
        ),
      ],
    );
  }
}
