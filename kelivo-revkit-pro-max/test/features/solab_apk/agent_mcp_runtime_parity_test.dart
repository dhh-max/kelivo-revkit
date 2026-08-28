import 'package:flutter_test/flutter_test.dart';

import 'package:solab/core/providers/assistant_provider.dart';
import 'package:solab/core/services/local_tools/local_tool_names.dart';
import 'package:solab/core/services/mcp_server/mcp_http_server.dart';
import 'package:solab/features/solab_apk/services/apk_agent_policy.dart';

void main() {
  test('Agent 与 MCP 原样复用同一判断和结果预算契约', () {
    expect(
      AssistantProvider.apkModSystemPrompt,
      contains(ApkAgentPolicy.sharedDecisionPolicy),
    );
    expect(
      McpHttpServer.mcpInstructions,
      contains(ApkAgentPolicy.sharedDecisionPolicy),
    );
    expect(
      McpHttpServer.maxResultChars,
      ApkAgentPolicy.maxVisibleToolResultChars,
    );
  });

  test('MCP 核心工具是 Agent 子集,上下文与技能能力只在 Agent 增量提供', () {
    final agentTools = AssistantProvider.apkModToolIds.toSet();
    final mcpTools = McpHttpServer.exposedToolIds.toSet();

    expect(agentTools, containsAll(mcpTools));
    expect(
      agentTools,
      containsAll(<String>{
        LocalToolNames.agentRuntimeGuide,
        LocalToolNames.apkKnowledge,
        LocalToolNames.installedSkills,
        LocalToolNames.apkSkill,
        LocalToolNames.apkPatchMemory,
        LocalToolNames.apkNoteRead,
      }),
    );
    expect(mcpTools, isNot(contains(LocalToolNames.installedSkills)));
    expect(mcpTools, isNot(contains(LocalToolNames.agentRuntimeGuide)));
  });
}
