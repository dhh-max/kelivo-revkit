import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/local_tools/tool_paging.dart';

/// 报告 2-23 守护：分页必须**显式声明单位**，并且各工具用同一套字段命名。
///
/// 真机复测：`artifact_read` 的 offset/limit 是字节、`memory_read`/`apk_rules` 是
/// 条数、`get_tool_result` 是字符，结果体里都没写单位；命名还分成 `has_more`/
/// `next_offset` 与 `hasMore`/`nextOffset` 两套。调用方只能猜，猜错就少读一段。
void main() {
  test('单位显式写进 page.unit，且 note 说明各字段同单位', () {
    for (final unit in const <String>[
      ToolPaging.unitItems,
      ToolPaging.unitBytes,
      ToolPaging.unitChars,
    ]) {
      final page = ToolPaging.block(
        unit: unit,
        offset: 0,
        limit: 50,
        returned: 50,
        total: 120,
      );
      expect(page['unit'], unit);
      expect(page['note'], contains(unit));
      expect(page['note'], contains('nextOffset'));
    }
  });

  test('已知总数：有下一页时给 nextOffset=offset+returned', () {
    final page = ToolPaging.block(
      unit: ToolPaging.unitItems,
      offset: 100,
      limit: 50,
      returned: 20,
      total: 200,
    );
    expect(page['hasMore'], isTrue);
    expect(page['nextOffset'], 120);
    expect(page['total'], 200);
  });

  test('已知总数且读完：hasMore=false 且不出现 nextOffset', () {
    final page = ToolPaging.block(
      unit: ToolPaging.unitBytes,
      offset: 0,
      limit: 4096,
      returned: 300,
      total: 300,
    );
    expect(page['hasMore'], isFalse);
    expect(page.containsKey('nextOffset'), isFalse);
  });

  test('总数未知（-1）：按「本页取满即可能还有」保守判断', () {
    final full = ToolPaging.block(
      unit: ToolPaging.unitChars,
      offset: 0,
      limit: 10,
      returned: 10,
    );
    expect(full['hasMore'], isTrue);
    expect(full.containsKey('total'), isFalse);

    final partial = ToolPaging.block(
      unit: ToolPaging.unitChars,
      offset: 0,
      limit: 10,
      returned: 3,
    );
    expect(partial['hasMore'], isFalse);
  });

  test('三套命名统一：hasMore 与 nextOffset 同时给出（老字段另存，不冲突）', () {
    final page = ToolPaging.block(
      unit: ToolPaging.unitItems,
      offset: 0,
      limit: 5,
      returned: 5,
      total: 9,
    );
    // 统一用小驼峰；老工具原有的 has_more/next_offset 保留是为了兼容，
    // 新调用方一律读 page。
    expect(page.keys, containsAll(<String>['hasMore', 'nextOffset']));
    expect(page.keys, isNot(contains('has_more')));
  });
}
