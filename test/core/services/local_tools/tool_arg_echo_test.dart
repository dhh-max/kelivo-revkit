import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/local_tools/tool_arg_echo.dart';

/// 同类缺陷扫查的收敛点：工具对入参做 clamp / 默认值替换后必须**回显生效值**。
///
/// 用户实测报告第 2 组的三处（`cwd` 静默回落、`timeout_seconds=0` 静默抬到 1s、
/// 长输出落盘）都是这个共性。修 shell 时只修了那一处，本助手让其余工具一行接入。
void main() {
  test('没被改写：只给生效值，不标 clamped（默认值不是改写）', () {
    expect(ToolArgEcho.effective('limit', 50, 50), <String, Object?>{'limit': 50});
    expect(ToolArgEcho.effective('limit', null, 50), <String, Object?>{'limit': 50});
  });

  test('被钳过：同时给生效值、请求值与 clamped 标记', () {
    final echo = ToolArgEcho.effective('limit', 999999, 200000);
    expect(echo['limit'], 200000);
    expect(echo['limitRequested'], 999999);
    expect(echo['limitClamped'], isTrue);
  });

  test('多参数版本：一次给出全部生效值与各自的钳位标记', () {
    final echo = ToolArgEcho.effectiveAll(<({String name, num? requested, num effective})>[
      (name: 'limit', requested: 100, effective: 50),
      (name: 'maxClasses', requested: 5, effective: 5),
      (name: 'timeoutMs', requested: 1, effective: 5000),
    ]);
    expect(echo['limit'], 50);
    expect(echo['limitRequested'], 100);
    expect(echo['limitClamped'], isTrue);
    expect(echo.containsKey('maxClassesRequested'), isFalse, reason: '没钳过就不标');
    expect(echo['timeoutMs'], 5000);
    expect(echo['timeoutMsClamped'], isTrue);
  });
}
