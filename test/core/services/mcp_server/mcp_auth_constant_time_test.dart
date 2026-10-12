import 'package:flutter_test/flutter_test.dart';

import 'package:Kelivo/core/services/mcp_server/mcp_http_server.dart';

/// MCP 令牌比较的恒定时间语义（2026-09-29）。
///
/// 原实现对长度不同的输入直接 return false，响应时间因此能区分「长度是否
/// 相等」，属于可被利用的时序侧信道（先探长度再逐位爆破）。本测试锁住
/// 语义不变：等值仍为 true，长度/前缀/单字符差异一律 false。
void main() {
  test('等值返回 true', () {
    expect(
      McpHttpServer.constTimeEquals('solab-token-123', 'solab-token-123'),
      isTrue,
    );
    expect(McpHttpServer.constTimeEquals('', ''), isTrue);
  });

  test('长度不同一律 false（且不再提前返回）', () {
    expect(
      McpHttpServer.constTimeEquals('solab-token-12', 'solab-token-123'),
      isFalse,
    );
    expect(
      McpHttpServer.constTimeEquals('solab-token-1234', 'solab-token-123'),
      isFalse,
    );
    expect(McpHttpServer.constTimeEquals('', 'x'), isFalse);
  });

  test('只是正确前缀不算数', () {
    expect(McpHttpServer.constTimeEquals('secret', 'secret-plus'), isFalse);
  });

  test('同长度仅一位不同不算数', () {
    expect(McpHttpServer.constTimeEquals('tokEn', 'token'), isFalse);
  });
}
