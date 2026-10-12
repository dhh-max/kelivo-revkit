import '../../../l10n/app_localizations.dart';
import '../models/workflow_models.dart';

/// 工作流界面的文案映射（节点类型名/说明、配置字段标签）。
///
/// 为什么单独一层：模型层（models/）里放的是**数据**（wireName、默认节点名），
/// 界面文案必须走 l10n——上游战略与仓库约定都要求「标签走 l10n key，不硬编码
/// 中文」（英文界面下不能出现中文节点名）。
String workflowNodeTitle(AppLocalizations l10n, WorkflowNodeType type) =>
    switch (type) {
      WorkflowNodeType.start => l10n.workflowTypeStart,
      WorkflowNodeType.text => l10n.workflowTypeText,
      WorkflowNodeType.aiGenerate => l10n.workflowTypeAi,
      WorkflowNodeType.command => l10n.workflowTypeCommand,
      WorkflowNodeType.httpRequest => l10n.workflowTypeHttp,
      WorkflowNodeType.condition => l10n.workflowTypeCondition,
      WorkflowNodeType.loop => l10n.workflowTypeLoop,
      WorkflowNodeType.merge => l10n.workflowTypeMerge,
      WorkflowNodeType.extract => l10n.workflowTypeExtract,
      WorkflowNodeType.delay => l10n.workflowTypeDelay,
      WorkflowNodeType.output => l10n.workflowTypeOutput,
      WorkflowNodeType.end => l10n.workflowTypeEnd,
    };

/// 添加节点面板里的一句话说明。
String workflowNodeSubtitle(AppLocalizations l10n, WorkflowNodeType type) =>
    switch (type) {
      WorkflowNodeType.start => l10n.workflowTypeStartDesc,
      WorkflowNodeType.text => l10n.workflowTypeTextDesc,
      WorkflowNodeType.aiGenerate => l10n.workflowTypeAiDesc,
      WorkflowNodeType.command => l10n.workflowTypeCommandDesc,
      WorkflowNodeType.httpRequest => l10n.workflowTypeHttpDesc,
      WorkflowNodeType.condition => l10n.workflowTypeConditionDesc,
      WorkflowNodeType.loop => l10n.workflowTypeLoopDesc,
      WorkflowNodeType.merge => l10n.workflowTypeMergeDesc,
      WorkflowNodeType.extract => l10n.workflowTypeExtractDesc,
      WorkflowNodeType.delay => l10n.workflowTypeDelayDesc,
      WorkflowNodeType.output => l10n.workflowTypeOutputDesc,
      WorkflowNodeType.end => l10n.workflowTypeEndDesc,
    };

/// 配置字段标签（键 → 文案）。未知键回落到键名本身（不会静默变空）。
String workflowFieldLabel(AppLocalizations l10n, String key) => switch (key) {
      'text' => l10n.workflowFieldText,
      'prompt' => l10n.workflowFieldPrompt,
      'system' => l10n.workflowFieldSystem,
      'command' => l10n.workflowFieldCommand,
      'url' => l10n.workflowFieldUrl,
      'method' => l10n.workflowFieldMethod,
      'body' => l10n.workflowFieldBody,
      'expression' => l10n.workflowFieldExpression,
      'items' => l10n.workflowFieldItems,
      'pattern' => l10n.workflowFieldPattern,
      'seconds' => l10n.workflowFieldSeconds,
      'template' => l10n.workflowFieldTemplate,
      'separator' => l10n.workflowFieldSeparator,
      _ => key,
    };
