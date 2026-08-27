import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:solab/core/services/local_tools/local_tool_names.dart';
import 'package:solab/features/home/services/apk_analysis_guard.dart';

void main() {
  test('会员和广告分析调用不受次数限制', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员并去广告');

    for (var i = 0; i < 12; i++) {
      expect(
        guard.before(LocalToolNames.dexSearch, {
          'keyword': 'showInterstitialAd$i',
        }).allowed,
        isTrue,
      );
      expect(
        guard.before(LocalToolNames.dexSearch, {'keyword': 'isVip$i'}).allowed,
        isTrue,
      );
    }
  });

  test('所有阶段不受调用次数限制，模型实际可见的文本量仍受限', () {
    final guard = ApkAnalysisGuard()..begin('去广告');
    for (var i = 0; i < 12; i++) {
      expect(
        guard.before(LocalToolNames.routeTask, {'goal': '去广告'}).allowed,
        isTrue,
      );
    }
    for (var i = 0; i < 20; i++) {
      guard.record(
        LocalToolNames.apkPatchDex,
        const {},
        jsonEncode({'data': List.filled(400001, 'x').join()}),
      );
    }
    expect(
      guard.before(LocalToolNames.routeTask, {'goal': '去广告'}).allowed,
      isFalse,
    );
    expect(guard.before(LocalToolNames.apkPatchDex, const {}).allowed, isTrue);
  });

  test('相同目标重复 route 不会重置分析状态', () {
    final guard = ApkAnalysisGuard()..begin('去广告');
    expect(
      guard.before(LocalToolNames.routeTask, {'goal': '去广告'}).allowed,
      isTrue,
    );
    guard.begin('去广告');
    expect(
      guard.before(LocalToolNames.apkProjectInfo, const {}).allowed,
      isTrue,
    );
    guard.begin('去广告');
    expect(
      guard.before(LocalToolNames.apkReport, {'section': 'decision'}).allowed,
      isTrue,
    );
    guard.begin('去广告');
    expect(
      guard.before(LocalToolNames.apkReport, {'section': 'decision'}).allowed,
      isTrue,
    );
    expect(guard.snapshot()['budget']['callsUsed'], 4);
  });

  test('Blutter analyze 不受调用次数限制', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员并去广告');
    const args = <String, dynamic>{
      'action': 'blutter',
      'blutterAction': 'analyze',
      'path': 'demo.apk',
    };
    expect(guard.before(LocalToolNames.soAnalyze, args).allowed, isTrue);
    expect(guard.before(LocalToolNames.soAnalyze, args).allowed, isTrue);
    expect(guard.snapshot()['guard']['blutterAnalyzeCalls'], 2);
  });

  test('工作区分析后决策报告回读不受次数限制', () {
    final guard = ApkAnalysisGuard()..begin('去广告');
    expect(guard.before(LocalToolNames.routeTask, const {}).allowed, isTrue);
    expect(
      guard.before(LocalToolNames.apkProjectInfo, const {}).allowed,
      isTrue,
    );
    expect(
      guard.before(LocalToolNames.apkReport, {'section': 'decision'}).allowed,
      isTrue,
    );
    guard.record(
      LocalToolNames.apkAnalyzeWorkspace,
      const {},
      jsonEncode({'ok': true}),
    );
    expect(
      guard.before(LocalToolNames.apkReport, {'section': 'decision'}).allowed,
      isTrue,
    );
    expect(
      guard.before(LocalToolNames.apkReport, {'section': 'decision'}).allowed,
      isTrue,
    );
  });

  test('ambiguous 写入状态但允许验证，阻断直接写入', () {
    final guard = ApkAnalysisGuard()..begin('去广告');
    const locate = <String, dynamic>{
      'action': 'blutter',
      'blutterAction': 'locate',
      'goal': '定位广告展示开关',
    };
    expect(guard.before(LocalToolNames.soAnalyze, locate).allowed, isTrue);
    final recorded =
        jsonDecode(
              guard.record(
                LocalToolNames.soAnalyze,
                locate,
                jsonEncode({
                  'ok': true,
                  'intentDomain': 'ads',
                  'classificationStatus': 'ambiguous',
                  'patchCandidates': <Object>[],
                  'verificationWindows': <Object>[],
                }),
              ),
            )
            as Map;
    expect(recorded['analysisGuard']['ads']['reportStatus'], 'ambiguous');
    expect(recorded['recovery']['code'], 'ambiguous');
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'blutter',
        'blutterAction': 'disasm',
        'goal': '广告',
        'va': '0x1000',
      }).allowed,
      isTrue,
    );
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'edit_asm',
        'editSessionId': 'so-edit-abc',
      }).allowed,
      isFalse,
    );
  });

  test('clear 广告候选记录体系、定位符和三重证据', () {
    final guard = ApkAnalysisGuard()..begin('去广告');
    const locate = <String, dynamic>{
      'action': 'blutter',
      'blutterAction': 'locate',
      'goal': '定位广告展示开关',
    };
    guard.before(LocalToolNames.soAnalyze, locate);
    guard.record(
      LocalToolNames.soAnalyze,
      locate,
      jsonEncode({
        'ok': true,
        'intentDomain': 'ads',
        'classificationStatus': 'clear',
        'intentProfile': {
          'selectedSystem': {
            'id': 'ad_display_trigger',
            'matchedKeywords': ['showInterstitialAd'],
          },
        },
        'patchCandidates': [
          {
            'functionVa': '0x1234',
            'refCount': 1,
            'referenceVas': ['0x1240'],
          },
        ],
        'verificationWindows': <Object>[],
      }),
    );
    const disasm = <String, dynamic>{
      'action': 'blutter',
      'blutterAction': 'disasm',
      'goal': '广告',
      'va': '0x1234',
    };
    guard.before(LocalToolNames.soAnalyze, disasm);
    final result =
        jsonDecode(
              guard.record(
                LocalToolNames.soAnalyze,
                disasm,
                jsonEncode({'ok': true, 'found': true}),
              ),
            )
            as Map;
    expect(result['analysisGuard']['ads']['reportStatus'], 'confirmed');
    expect(result['analysisGuard']['ads']['lastLocatorVA'], '0x1234');
    expect(
      result['analysisGuard']['ads']['selectedSystem'],
      'ad_display_trigger',
    );
  });

  test('ambiguous 可由精确函数体直接消歧，不强制补齐固定三证据', () {
    final guard = ApkAnalysisGuard()..begin('去广告');
    const locate = <String, dynamic>{
      'action': 'blutter',
      'blutterAction': 'locate',
      'goal': '定位广告展示开关',
    };
    guard.record(
      LocalToolNames.soAnalyze,
      locate,
      jsonEncode({
        'ok': true,
        'intentDomain': 'ads',
        'classificationStatus': 'ambiguous',
        'patchCandidates': <Object>[],
        'verificationWindows': <Object>[],
      }),
    );
    const disasm = <String, dynamic>{
      'action': 'blutter',
      'blutterAction': 'disasm',
      'goal': '广告',
      'va': '0x1234',
    };
    guard.record(
      LocalToolNames.soAnalyze,
      disasm,
      jsonEncode({
        'ok': true,
        'found': true,
        'lines': ['ret'],
      }),
    );

    expect(guard.snapshot()['ads']['reportStatus'], 'confirmed');
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'edit_asm',
        'editSessionId': 'so-edit-abc',
      }).allowed,
      isTrue,
    );
  });

  test('已有精确 DEX locator 可直接读方法体并收口', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员');
    const args = <String, dynamic>{'qualifiedId': 'Lx/a;->a()Z', 'goal': '会员'};

    guard.record(
      LocalToolNames.smaliRead,
      args,
      jsonEncode({
        'ok': true,
        'qualifiedId': 'Lx/a;->a()Z',
        'lines': ['return v0'],
      }),
    );

    expect(guard.snapshot()['membership']['reportStatus'], 'confirmed');
    expect(guard.before(LocalToolNames.apkPatchDex, const {}).allowed, isTrue);
  });

  test('壳状态阻断定位并返回签名和耗时状态字段', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员');
    final result =
        jsonDecode(
              guard.record(
                LocalToolNames.apkReport,
                const {'section': 'decision'},
                jsonEncode({
                  'ok': true,
                  'facts': {
                    'packageName': 'com.demo',
                    'versionName': '1.0',
                    'sha256': 'abc',
                    'flutterApp': {'detected': true},
                    'shellPacking': {'detected': true},
                    'signatureCheck': {'detected': true},
                  },
                  'reportFreshness': {'status': 'fresh'},
                }),
              ),
            )
            as Map;
    expect(result['analysisGuard']['apkFingerprint'], 'com.demo+1.0+abc');
    expect(result['analysisGuard']['flutterDetected'], isTrue);
    expect(result['analysisGuard']['guard']['signatureRisk'], isTrue);
    expect(result['analysisGuard']['elapsedMs'], isA<int>());
    expect(
      guard.before(LocalToolNames.dexSearch, {'keyword': 'isVip'}).allowed,
      isFalse,
    );
  });

  test('用户回答后解除 ambiguous 阻断，放行 verify/patch', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员');
    const locate = <String, dynamic>{
      'action': 'blutter',
      'blutterAction': 'locate',
      'goal': '定位会员判定函数',
    };
    expect(guard.before(LocalToolNames.soAnalyze, locate).allowed, isTrue);
    guard.record(
      LocalToolNames.soAnalyze,
      locate,
      jsonEncode({
        'ok': true,
        'intentDomain': 'membership',
        'classificationStatus': 'ambiguous',
        'patchCandidates': <Object>[],
        'verificationWindows': <Object>[],
      }),
    );
    expect(guard.snapshot()['membership']['reportStatus'], 'ambiguous');
    // 用户回答前：disasm(verify) 也必须放行，才能消除 ambiguity。
    const disasm = <String, dynamic>{
      'action': 'blutter',
      'blutterAction': 'disasm',
      'goal': '会员',
      'va': '0x5d1d08',
    };
    expect(guard.before(LocalToolNames.soAnalyze, disasm).allowed, isTrue);
    // 用户回答后：解除阻断，verify/patch 放行。
    guard.confirmFromUserAnswer();
    expect(
      guard.snapshot()['membership']['reportStatus'],
      'candidates_need_verification',
    );
    expect(guard.before(LocalToolNames.soAnalyze, disasm).allowed, isTrue);
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'edit_asm',
        'editSessionId': 'so-edit-abc',
      }).allowed,
      isTrue,
    );
  });

  test('知识工具结果不计入文本用量', () {
    final guard = ApkAnalysisGuard()..begin('去广告');
    final largeResult = jsonEncode({'ok': true, 'text': 'x' * 400000});

    final recorded =
        jsonDecode(
              guard.record(LocalToolNames.apkKnowledge, const {}, largeResult),
            )
            as Map;

    expect(recorded['analysisGuard']['budget']['enabled'], isTrue);
    expect(recorded['analysisGuard']['budget']['tokenUsedEst'], 0);
    expect(recorded['analysisGuard']['budget']['tokenCap'], 80000);
  });

  test('大结果按模型可见上限计入文本用量', () {
    final guard = ApkAnalysisGuard()..begin('去广告');
    final largeResult = jsonEncode({'ok': true, 'text': 'x' * 400000});

    final recorded =
        jsonDecode(
              guard.record(LocalToolNames.dexSearch, const {}, largeResult),
            )
            as Map;

    expect(recorded['analysisGuard']['budget']['tokenUsedEst'], 4000);
  });

  test('达到文本上限后只放行三次精确数值或地址收口', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员');
    final largeResult = jsonEncode({'ok': true, 'text': 'x' * 400000});
    for (var i = 0; i < 20; i++) {
      guard.record(LocalToolNames.dexSearch, const {}, largeResult);
    }

    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'blutter',
        'blutterAction': 'values',
        'query': '5,3',
      }).allowed,
      isTrue,
    );
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'disasm',
        'locator': '0xe1b39c',
      }).allowed,
      isTrue,
    );
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'hexdump',
        'va': '0xe1b39c',
      }).allowed,
      isTrue,
    );
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'blutter',
        'blutterAction': 'disasm',
        'va': '0x9eade4',
      }).allowed,
      isFalse,
    );
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'blutter',
        'blutterAction': 'search',
        'query': 'vip',
      }).allowed,
      isFalse,
    );
  });

  test('同一目标验证探针到上限后只允许三次精确收口', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员');
    for (var i = 0; i < 12; i++) {
      expect(
        guard.before(LocalToolNames.dexXref, {
          'qualifiedId': 'method$i',
        }).allowed,
        isTrue,
      );
    }

    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'blutter',
        'blutterAction': 'search',
        'query': 'another vip keyword',
      }).allowed,
      isFalse,
    );
    for (final va in const ['0x1000', '0x2000', '0x3000']) {
      expect(
        guard.before(LocalToolNames.soAnalyze, {
          'action': 'disasm',
          'va': va,
        }).allowed,
        isTrue,
      );
    }
    expect(
      guard.before(LocalToolNames.soAnalyze, const {
        'action': 'disasm',
        'va': '0x4000',
      }).allowed,
      isFalse,
    );
  });

  test('用户可明确授权追加验证预算', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员');
    for (var i = 0; i < 12; i++) {
      expect(
        guard.before(LocalToolNames.dexXref, {
          'qualifiedId': 'method$i',
        }).allowed,
        isTrue,
      );
    }
    final blocked = guard.before(LocalToolNames.dexXref, const {
      'qualifiedId': 'method-next',
    });
    expect(blocked.allowed, isFalse);
    expect(blocked.canRequestBudget, isTrue);

    guard.grantBudget(12);

    expect(
      guard.before(LocalToolNames.dexXref, const {
        'qualifiedId': 'method-next',
      }).allowed,
      isTrue,
    );
    expect(guard.snapshot()['budget']['callsCap']['verify'], 24);
    expect(guard.snapshot()['budget']['callsCap']['userGranted'], 12);
  });

  test('新用户消息恢复少量验证机会但保留分析状态', () {
    final guard = ApkAnalysisGuard()..begin('解锁会员');
    for (var i = 0; i < 12; i++) {
      guard.before(LocalToolNames.dexXref, {'qualifiedId': 'method$i'});
    }

    guard.beginUserTurn();

    for (var i = 0; i < 4; i++) {
      expect(
        guard.before(LocalToolNames.dexXref, {
          'qualifiedId': 'repair$i',
        }).allowed,
        isTrue,
      );
    }
    expect(
      guard.before(LocalToolNames.dexXref, const {
        'qualifiedId': 'repair-overflow',
      }).allowed,
      isFalse,
    );
    expect(guard.snapshot()['membership']['reportStatus'], 'not_started');
  });
}
