import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:vyuh_node_flow/vyuh_node_flow.dart';

import '../../../core/models/assistant.dart';
import '../../../core/providers/assistant_provider.dart';
import '../../../core/providers/settings_provider.dart';
import '../../../core/services/api/api_session_scope.dart';
import '../../../core/services/api/chat_api_service.dart';
import '../../../icons/lucide_adapter.dart';
import '../../../shared/widgets/ios_tactile.dart';
import '../../../l10n/app_localizations.dart';
import '../../../shared/widgets/custom_bottom_sheet.dart';
import '../../../shared/widgets/snackbar.dart';
import '../../../theme/app_font_weights.dart';
import '../../model/pages/default_model_page.dart';
import '../../home/utils/model_display_helper.dart';
import '../engine/workflow_engine.dart';
import '../engine/workflow_validation.dart';
import '../models/workflow_models.dart';
import '../services/workflow_generation.dart';
import '../services/workflow_generation_stream.dart';
import '../services/workflow_history.dart';
import '../services/workflow_layout.dart';
import '../services/workflow_store.dart';
import 'workflow_labels.dart';
import 'workflow_name_sheet.dart';

/// 节点卡片尺寸：端口 offset、命中测试、快照都依赖它。
const double _nodeWidth = 176;
const double _nodeHeight = 84;

/// 视觉网格与吸附网格用同一个尺寸——不一致会出现「吸到的地方和看到的格子对不上」。
const double _gridSize = 26;

/// 端口圆点的画布尺寸。
///
/// 旧值 13 在手机自动适配后（见 [_minEditorZoom]）屏幕上只有 3.9px——手指
/// 永远点不中，这正是用户 2026-10-02 报「点它连不上」的直接原因。
const double _portSize = 20;

/// 端口命中半径（画布单位）：命中区 = 端口尺寸 + 2 × 该值，同样跟着缩放走。
/// 0.6 缩放下命中区约 36px，手指才够得着；拖线的落点容差也靠它。
const double _portSnapDistance = 20;

/// 画布最小缩放。
///
/// 旧值 0.3 是「什么都看得见」的概览档，但在这个缩放档下节点卡片只有 53×25px、
/// 端口只有 3.9px——画布实际上不可操作。适配视图会缩到最小缩放，所以下限
/// 直接决定「打开工作流第一眼能不能连」。要看全图请平移，不要缩到看不见。
const double _minEditorZoom = 0.6;

/// 节点类型 → Lucide 图标（模型层不依赖 UI，所以在这里映射）。
IconData workflowIconFor(WorkflowNodeType type) => switch (type) {
  WorkflowNodeType.start => Lucide.Play,
  WorkflowNodeType.text => Lucide.Type,
  WorkflowNodeType.aiGenerate => Lucide.Sparkles,
  WorkflowNodeType.command => Lucide.SquareTerminal,
  WorkflowNodeType.httpRequest => Lucide.Globe,
  WorkflowNodeType.condition => Lucide.GitBranch,
  WorkflowNodeType.loop => Lucide.RefreshCw,
  WorkflowNodeType.merge => Lucide.Workflow,
  WorkflowNodeType.extract => Lucide.Braces,
  WorkflowNodeType.delay => Lucide.Timer,
  WorkflowNodeType.output => Lucide.ArrowRight,
  WorkflowNodeType.end => Lucide.Lock,
};

/// 工作流编辑器：节点画布 + 添加/编辑/复制/删除节点 + 运行面板 + 保存。
///
/// 画布用 vyuh_node_flow（MIT）。它提供的是**原料**：拖拽、端口连线、缩放平移、
/// 内置的重复连线/成环校验、网格吸附、插件层。三件事必须我们自己兜：
/// 1. **撤销/重做**：包里没有官方 history 插件（node_flow_controller.dart 的
///    UndoRedoPlugin 只是示例注释），所以用定义快照栈自己实现——
///    见 services/workflow_history.dart（记录「改动前」的快照）。
/// 2. **框选多选**：包里的 marquee 只在按住 Shift 时触发（node_flow_editor.dart
///    的 HardwareKeyboard 判断），手机上不可达 → 不宣传、不依赖它。
/// 3. **运行前预检**：engine/workflow_validation.dart，问题在跑之前变成清单。
class WorkflowEditorPage extends StatefulWidget {
  const WorkflowEditorPage({
    super.key,
    required this.workflow,
    this.store,
    this.autoRun = false,
    this.generateFrom,
  });

  final WorkflowDefinition workflow;
  final WorkflowStore? store;

  /// 列表页「运行」直达：进来就弹运行面板。
  final bool autoRun;

  /// 非空 = 进入即按该描述**流式生成**：节点/连线实时上画布，成功后自动
  /// 落库（2026-10-04 用户要求：不要在弹窗里干等）。
  final String? generateFrom;

  @override
  State<WorkflowEditorPage> createState() => _WorkflowEditorPageState();
}

class _WorkflowEditorPageState extends State<WorkflowEditorPage> {
  late final WorkflowStore _store = widget.store ?? WorkflowStore();
  late NodeFlowController<WorkflowNode, dynamic> _controller;
  late String _name = widget.workflow.name;
  bool _dirty = false;

  /// 撤销/重做：自研快照栈（记录改动前的定义）。
  final WorkflowHistory _history = WorkflowHistory();
  bool _restoring = false;

  /// 弹层/运行防重入：真机反馈过「点一下弹一次、多个弹窗叠加」。
  bool _sheetOpen = false;

  /// 拖动前快照：onDragStart 记，onDragStop 有位移才压栈。
  String? _dragSnapshot;

  /// 上一次「已记账」的画布状态。
  ///
  /// 连线事件（ConnectionEvents.onCreated/onDeleted）是**改完之后**才回调的，
  /// 拿不到改动前的状态；所以拿这份 baseline 当「改动前」。节点/拖动路径仍是
  /// 显式先取 before——两条路都在 [_record] 里对齐（它会刷新 baseline，并在
  /// 没有真变化时直接返回，避免同一次改动被记两笔）。
  String _baseline = '';

  // 运行面板状态（ValueNotifier 让弹层里的内容自己刷新，不整页重建）。
  final ValueNotifier<List<WorkflowRunLogEntry>> _runLogs =
      ValueNotifier<List<WorkflowRunLogEntry>>(const <WorkflowRunLogEntry>[]);
  final ValueNotifier<Map<String, String>> _runStatus =
      ValueNotifier<Map<String, String>>(const <String, String>{});
  final ValueNotifier<bool> _running = ValueNotifier<bool>(false);
  final ValueNotifier<WorkflowRunResult?> _runResult =
      ValueNotifier<WorkflowRunResult?>(null);
  final ValueNotifier<List<WorkflowIssue>> _runWarnings =
      ValueNotifier<List<WorkflowIssue>>(const <WorkflowIssue>[]);
  WorkflowRunControl? _runControl;
  String _runInput = '';

  bool _hasSelectedConnection = false;
  final List<String> _selectedConnectionIds = <String>[];

  // --- AI 流式生成状态（generateFrom 非空时启用）---------------------------

  /// 生成进度条：running/done/failed 三态驱动顶部横幅，自刷新不整页重建。
  final ValueNotifier<_GenerationProgress> _genProgress =
      ValueNotifier<_GenerationProgress>(const _GenerationProgress.idle());
  StreamSubscription<WorkflowGenerationEvent>? _genSub;
  String? _genRequestId;
  bool _genCancelled = false;
  bool _genFitScheduled = false;
  Timer? _genDismissTimer;

  /// 流式生成期间压制撤销/重做与脏标记：逐节点/逐连线入栈会把一次生成拆成
  /// 几十步历史，真机实测生成完成后还残留一个「可撤销」的脏状态（2026-10-05）。
  /// 生成是**一个原子动作**——收尾时清空历史以生成结果为唯一基线。
  bool _generating = false;

  /// 先收到连线、端点节点还没上屏的边（模型正常按 nodes→edges 输出时为空）。
  final List<WorkflowEdge> _pendingGenEdges = <WorkflowEdge>[];

  /// 点选连线的起点：点一下端口 → 再点另一个端口/节点卡片收口。
  ///
  /// 手机上没有鼠标，拖线要求「起手」和「落点」都精确落在端口上；自动适配后的
  /// 缩放下命中区只有几像素，实测根本点不中。点选把一次精确拖拽拆成两次宽松
  /// 点击，同时保留原来的拖拽路径（两条路都走 [_connect]）。
  _PendingLink? _pendingLink;

  /// 点击识别用的原始指针状态（见 [_onCanvasPointerDown] 的注释）。
  Offset? _tapDownAt;
  int _activePointers = 0;
  bool _tapCandidate = false;

  /// 长按识别：包里没有任何 LongPress 手势（全库搜不到），所以手机上的
  /// 「长按节点 = 菜单（编辑/复制/删除）」原本是死路——只有桌面右键可达。
  Timer? _longPressTimer;

  static String _truncate(String text, int max) {
    final trimmed = text.trim();
    if (trimmed.length <= max) return trimmed;
    return '${trimmed.substring(0, max)}…';
  }

  @override
  void initState() {
    super.initState();
    _controller = _buildController(widget.workflow);
    _baseline = _encodeSnapshot();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      // 生成模式：进来就开流，节点/连线由事件实时上屏；不用 fitToView
      // 空画布，等第一个节点到了再适配视图。
      if (widget.generateFrom != null) {
        unawaited(_startGeneration());
        return;
      }
      _controller.fitToView();
      if (widget.autoRun) unawaited(_openRunSheet());
    });
  }

  NodeFlowController<WorkflowNode, dynamic> _buildController(
    WorkflowDefinition definition, {
    GraphViewport? viewport,
  }) => NodeFlowController<WorkflowNode, dynamic>(
    // 撤销/重做会换 controller（快照栈的代价），换的时候把视口带过去，
    // 否则每撤销一次画布就跳回原点。
    initialViewport: viewport,
    config: NodeFlowConfig(
      // 包默认 true：画布角落会挂一枚 "Powered by Vyuh" 徽标。
      showAttribution: false,
      // 命中区必须够到手指：端口命中区 = 端口尺寸 + 2 × 该值（画布单位）。
      portSnapDistance: _portSnapDistance,
      // 下限决定「适配视图」能缩到多小；低于 0.6 画布就没法用手操作了。
      minZoom: _minEditorZoom,
      maxZoom: 2.5,
      plugins: <NodeFlowPlugin>[
        AutoPanPlugin(),
        LodPlugin(),
        // 手指拖拽很难对齐，吸到网格上；网格尺寸与视觉网格一致。
        SnapPlugin(<SnapDelegate>[
          GridSnapDelegate(gridSize: _gridSize),
        ], enabled: true),
        // 有意不装 MinimapPlugin：手机屏幕放不下缩略图，反而挡住画布。
      ],
    ),
    nodes: <Node<WorkflowNode>>[
      for (final node in definition.nodes) _toFlowNode(node),
    ],
    connections: <Connection<dynamic>>[
      for (final edge in definition.edges)
        Connection(
          id: edge.id,
          sourceNodeId: edge.fromNodeId,
          sourcePortId: edge.fromPort,
          targetNodeId: edge.toNodeId,
          targetPortId: edge.toPort,
        ),
    ],
  );

  Node<WorkflowNode> _toFlowNode(WorkflowNode node) {
    final inputs = node.type.inputPorts;
    final outputs = node.type.outputPorts;
    return Node<WorkflowNode>(
      id: node.id,
      type: node.type.wireName,
      position: node.position,
      data: node,
      size: const Size(_nodeWidth, _nodeHeight),
      ports: <Port>[
        for (var i = 0; i < inputs.length; i++)
          Port(
            id: inputs[i],
            name: inputs[i],
            position: PortPosition.left,
            offset: _portOffset(i, inputs.length),
            // 一个入口只接一条线：多个上游要靠 merge 节点显式汇聚，
            // 否则引擎的「入边到齐」语义会被悄悄破坏。
            maxConnections: 1,
          ),
        for (var i = 0; i < outputs.length; i++)
          Port(
            id: outputs[i],
            name: outputs[i],
            position: PortPosition.right,
            offset: _portOffset(i, outputs.length),
          ),
      ],
    );
  }

  /// 对无 shape 的节点，left/right 端口的垂直位置**完全由 offset.dy 决定**
  /// （calculateOrigin 的 perpendicular 轴不走锚点）——所以这里必须给
  /// 「卡片高度的一半」才落在侧边中部。此前传 zero 把端口推到顶边，真机上
  /// 拉线起点对不上（用户 2026-10-01「线连接不上」的根因）；widget 测试已
  /// 用 getPortWorldPosition 证明正确位置下连线能建立。
  Offset _portOffset(int index, int total) {
    if (total <= 1) return const Offset(0, _nodeHeight / 2);
    return Offset(0, _nodeHeight / 2 + (index - (total - 1) / 2) * 30);
  }

  /// 从画布读回定义（节点位置与连线以画布为准）。
  WorkflowDefinition _snapshot() {
    final nodes = <WorkflowNode>[
      for (final node in _controller.nodes.values)
        node.data.copyWith(position: node.position.value),
    ];
    final edges = <WorkflowEdge>[
      for (final connection in _controller.connections)
        WorkflowEdge(
          id: connection.id,
          fromNodeId: connection.sourceNodeId,
          fromPort: connection.sourcePortId,
          toNodeId: connection.targetNodeId,
          toPort: connection.targetPortId,
        ),
    ];
    return WorkflowDefinition(
      id: widget.workflow.id,
      name: _name,
      nodes: nodes,
      edges: edges,
    );
  }

  String _encodeSnapshot() => _snapshot().encode();

  /// 记一次「改动前」的历史点。**调用时机必须在改画布之前**——
  /// 上一版是改完再压栈，压进去的就是改完的状态，撤销等于原地踏步。
  void _record(String before) {
    // 生成进行中不入历史：见 _generating 的说明。
    if (_restoring || _generating) return;
    final now = _encodeSnapshot();
    _baseline = now;
    // 没有真变化（例如同一笔改动被显式路径和事件路径各报一次）就不占历史位。
    if (before == now) return;
    _history.record(before);
    setState(() => _dirty = true);
  }

  void _undo() {
    if (!_history.canUndo) return;
    final target = _history.undo(_encodeSnapshot());
    if (target == null) return;
    _restore(target);
  }

  void _redo() {
    if (!_history.canRedo) return;
    final target = _history.redo(_encodeSnapshot());
    if (target == null) return;
    _restore(target);
  }

  void _startCardDrag(Node<WorkflowNode> node) {
    _controller.startNodeDrag(node.id);
  }

  void _moveCardDrag(DragUpdateDetails details) {
    _controller.moveNodeDrag(details.delta);
  }

  void _endCardDrag(DragEndDetails details) {
    _controller.endNodeDrag();
  }

  /// 用快照重建画布。
  void _restore(String encoded) {
    final definition = WorkflowDefinition.decode(encoded);
    if (definition == null) return;
    _swapCanvas(definition, dirty: true);
  }

  /// 用一份定义整体换画布（撤销/重做、生成收尾共用）。
  ///
  /// NodeFlowEditor 只在 initState 里初始化 controller（didUpdateWidget 不重
  /// 初始化），直接换 controller 而不换 key 会让新 controller 的
  /// connectionPainter 抛 StateError——所以这里给编辑器挂 ObjectKey(_controller)
  /// 强制重建，并把旧 controller 延到帧后再 dispose（旧 State 的 dispose 还会
  /// 访问它）。
  void _swapCanvas(WorkflowDefinition definition, {required bool dirty}) {
    final viewport = _controller.viewport;
    final previous = _controller;
    _restoring = true;
    setState(() {
      _name = definition.name;
      _controller = _buildController(definition, viewport: viewport);
      _selectedConnectionIds.clear();
      _hasSelectedConnection = false;
      _runStatus.value = const <String, String>{};
      _pendingLink = null;
      _dirty = dirty;
    });
    _restoring = false;
    _baseline = _encodeSnapshot();
    WidgetsBinding.instance.addPostFrameCallback((_) => previous.dispose());
  }

  @override
  void dispose() {
    _cancelLongPress();
    _genDismissTimer?.cancel();
    unawaited(_genSub?.cancel());
    _genProgress.dispose();
    _controller.dispose();
    _runLogs.dispose();
    _runStatus.dispose();
    _running.dispose();
    _runResult.dispose();
    _runWarnings.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // 保存 / 重命名
  // ---------------------------------------------------------------------------

  Future<void> _save() async {
    await _store.save(_snapshot());
    if (!mounted) return;
    setState(() => _dirty = false);
    // 用 App 标准通知（顶部卡片式，主题色）——原生 SnackBar 是黑色默认样式，
    // 与全局不一致（用户 2026-10-05 点名）。
    showAppSnackBar(
      context,
      message: AppLocalizations.of(context)!.workflowSaved,
      type: NotificationType.success,
    );
  }

  Future<void> _rename() async {
    if (_sheetOpen) return;
    _sheetOpen = true;
    String? picked;
    try {
      await showCustomBottomSheet<void>(
        context: context,
        title: AppLocalizations.of(context)!.workflowRename,
        builder: (sheetContext, scrollController) => WorkflowNameSheet(
          scrollController: scrollController,
          initial: _name,
          onDone: (value) {
            picked = value;
            final route = ModalRoute.of(sheetContext);
            if (route != null && route.isActive) {
              Navigator.of(sheetContext).removeRoute(route);
            }
          },
        ),
      );
    } finally {
      _sheetOpen = false;
    }
    final value = picked?.trim();
    if (value == null || value.isEmpty || value == _name) return;
    setState(() {
      _name = value;
      _dirty = true;
    });
  }

  // ---------------------------------------------------------------------------
  // 节点增删改
  // ---------------------------------------------------------------------------

  Future<void> _addNode() async {
    if (_sheetOpen || _running.value) return;
    _sheetOpen = true;
    WorkflowNodeType? pickedType;
    try {
      await showCustomBottomSheet<void>(
        context: context,
        title: AppLocalizations.of(context)!.workflowAddNode,
        builder: (sheetContext, scrollController) {
          void close() {
            final route = ModalRoute.of(sheetContext);
            if (route != null && route.isActive) {
              Navigator.of(sheetContext).removeRoute(route);
            }
          }

          return _AddNodeSheet(
            scrollController: scrollController,
            onPick: (picked) {
              pickedType = picked;
              close();
            },
          );
        },
      );
    } finally {
      _sheetOpen = false;
    }
    final type = pickedType;
    if (type == null || !mounted) return;
    final l10n = AppLocalizations.of(context)!;
    // 新节点放在**当前视口中心**：老实现写死绝对坐标，用户平移或缩小之后新节点
    // 会落到屏幕外，看起来像「点了添加却没反应」。叠一点错位，避免完全重叠。
    final size = _controller.screenSize;
    final center = size.isEmpty
        ? const Offset(160, 160)
        : _controller
              .screenToGraph(
                ScreenPosition(Offset(size.width / 2, size.height / 2)),
              )
              .offset;
    final index = _controller.nodes.length;
    _applyAdd(
      WorkflowNode(
        id: _newNodeId(),
        type: type,
        name: workflowNodeTitle(l10n, type),
        position:
            center -
            const Offset(_nodeWidth / 2, _nodeHeight / 2) +
            Offset((index % 4) * 16, (index % 4) * 12),
      ),
    );
  }

  String _newNodeId() => 'n${DateTime.now().microsecondsSinceEpoch}';

  void _applyAdd(WorkflowNode node) {
    final before = _encodeSnapshot();
    _controller.addNode(_toFlowNode(node));
    _record(before);
  }

  void _duplicateNode(Node<WorkflowNode> flowNode) {
    final l10n = AppLocalizations.of(context)!;
    final source = flowNode.data;
    final before = _encodeSnapshot();
    _controller.addNode(
      _toFlowNode(
        WorkflowNode(
          id: _newNodeId(),
          type: source.type,
          name: l10n.workflowCopySuffix(source.name),
          config: source.config,
          position: flowNode.position.value + const Offset(30, 30),
        ),
      ),
    );
    _record(before);
  }

  void _deleteNode(Node<WorkflowNode> flowNode) {
    final before = _encodeSnapshot();
    _controller.removeNode(flowNode.id);
    _record(before);
  }

  /// 长按节点：移动端没有右键，包的 onContextMenu 明确把长按当上下文菜单。
  Future<void> _showNodeMenu(Node<WorkflowNode> flowNode) async {
    if (_sheetOpen || _running.value) return;
    _sheetOpen = true;
    String? action;
    try {
      await showCustomBottomSheet<void>(
        context: context,
        title: flowNode.data.name,
        builder: (sheetContext, scrollController) => _NodeMenuSheet(
          scrollController: scrollController,
          onAction: (picked) {
            action = picked;
            final route = ModalRoute.of(sheetContext);
            if (route != null && route.isActive) {
              Navigator.of(sheetContext).removeRoute(route);
            }
          },
        ),
      );
    } finally {
      _sheetOpen = false;
    }
    if (!mounted) return;
    switch (action) {
      case 'edit':
        await _editNode(flowNode);
      case 'duplicate':
        _duplicateNode(flowNode);
      case 'delete':
        _deleteNode(flowNode);
    }
  }

  Future<void> _editNode(Node<WorkflowNode> flowNode) async {
    if (_sheetOpen || _running.value) return;
    _sheetOpen = true;
    _NodeEditResult? sheetResult;
    try {
      await showCustomBottomSheet<void>(
        context: context,
        title: workflowNodeTitle(
          AppLocalizations.of(context)!,
          flowNode.data.type,
        ),
        builder: (sheetContext, scrollController) {
          void close() {
            final route = ModalRoute.of(sheetContext);
            if (route != null && route.isActive) {
              Navigator.of(sheetContext).removeRoute(route);
            }
          }

          return _NodeConfigSheet(
            scrollController: scrollController,
            node: flowNode.data,
            onDone: (node) {
              sheetResult = _NodeEditResult(node: node);
              close();
            },
            onDelete: () {
              sheetResult = const _NodeEditResult(delete: true);
              close();
            },
          );
        },
      );
    } finally {
      _sheetOpen = false;
    }
    final result = sheetResult;
    if (result == null || !mounted) return;
    if (result.delete) {
      _deleteNode(flowNode);
      return;
    }
    final edited = result.node;
    if (edited == null) return;
    // Node.data 是 final：用「移除 + 按原位置重建」把新数据写回画布。
    final position = flowNode.position.value;
    final before = _encodeSnapshot();
    _controller.removeNode(flowNode.id);
    _controller.addNode(_toFlowNode(edited.copyWith(position: position)));
    _record(before);
  }

  void _deleteSelectedConnection() {
    if (_selectedConnectionIds.isEmpty) return;
    final before = _encodeSnapshot();
    for (final id in List<String>.of(_selectedConnectionIds)) {
      _controller.removeConnection(id);
    }
    _selectedConnectionIds.clear();
    setState(() => _hasSelectedConnection = false);
    _record(before);
  }

  // ---------------------------------------------------------------------------
  // 点选连线（拖拽之外的第二条路，手机上更好用）
  // ---------------------------------------------------------------------------
  //
  // 流程：点端口 A（起点，高亮所在节点）→ 点端口 B 或另一个节点卡片收口。
  // 校验（方向 / 自连 / 入口占用）在本地先判，失败就用人话说明原因；
  // 连线本身走 controller.createConnection，历史仍由 ConnectionEvents.onCreated
  // 那条路记账（不要再叠一次 _record，否则撤销要按两下）。

  bool _inputBusy(String nodeId, String portId) => _controller.connections.any(
    (connection) =>
        connection.targetNodeId == nodeId && connection.targetPortId == portId,
  );

  void _tip(String message) {
    if (!mounted) return;
    // 标准通知样式（与保存反馈同源），不再用黑色原生 SnackBar。
    // 编辑器提示是「连续操作的一条线索」：旧实现 hideCurrentSnackBar 保证替换
    // 语义——这里同样先收掉上一条，避免点两下端口就把三条提示叠在顶部。
    AppSnackBarManager().dismissAll();
    showAppSnackBar(context, message: message);
  }

  void _armLink(Node<WorkflowNode> node, String portId, bool isOutput) {
    setState(() {
      _pendingLink = _PendingLink(
        nodeId: node.id,
        portId: portId,
        isOutput: isOutput,
        nodeName: node.data.name,
      );
    });
    // 选中起点节点：画布上给一个看得见的反馈（端口本身太小，靠这个认起点）。
    _controller.selectNode(node.id);
  }

  void _cancelLink() {
    if (_pendingLink == null) return;
    setState(() => _pendingLink = null);
  }

  /// 点端口：没起点就设起点，同一端口再点一次取消，否则尝试收口。
  void _onPortTap(Node<WorkflowNode> node, String portId, bool isOutput) {
    final pending = _pendingLink;
    if (pending == null) {
      _armLink(node, portId, isOutput);
      return;
    }
    if (pending.nodeId == node.id && pending.portId == portId) {
      _cancelLink();
      return;
    }
    _connect(
      pending,
      otherNodeId: node.id,
      otherPortId: portId,
      otherIsOutput: isOutput,
      targetNodeName: node.data.name,
    );
  }

  /// 点节点卡片：连线中就是「连到它」，否则选中并打开配置面板。
  ///
  /// 卡片比端口大得多，手机上点卡片收口比点端口容易；多入口节点（汇聚）自动
  /// 挑第一个空入口。
  void _onNodeTap(Node<WorkflowNode> node) {
    final pending = _pendingLink;
    if (pending != null) {
      if (pending.nodeId == node.id) {
        // 点回起点所在的卡片 = 放弃这次连线，然后照常打开配置面板。
        _cancelLink();
      } else {
        final inputs = node.data.type.inputPorts;
        if (inputs.isEmpty) {
          _tip(
            AppLocalizations.of(context)!.workflowLinkNoInput(node.data.name),
          );
          return;
        }
        final free = inputs
            .where((portId) => !_inputBusy(node.id, portId))
            .toList(growable: false);
        if (free.isEmpty) {
          _tip(AppLocalizations.of(context)!.workflowLinkBusy);
          return;
        }
        _connect(
          pending,
          otherNodeId: node.id,
          otherPortId: free.first,
          otherIsOutput: false,
          targetNodeName: node.data.name,
        );
        return;
      }
    }
    // 打开面板前选中它：面板盖住下半屏时，画布上还有一圈高亮告诉你改的是哪个。
    _controller.selectNode(node.id);
    unawaited(_editNode(node));
  }

  /// 把起点和另一端拼成「出口 → 入口」，校验通过才真的连线。
  void _connect(
    _PendingLink pending, {
    required String otherNodeId,
    required String otherPortId,
    required bool otherIsOutput,
    required String targetNodeName,
  }) {
    final l10n = AppLocalizations.of(context)!;
    if (otherIsOutput == pending.isOutput) {
      _tip(l10n.workflowLinkSameSide);
      return;
    }
    if (otherNodeId == pending.nodeId) {
      _tip(l10n.workflowLinkSelf);
      return;
    }
    final sourceNodeId = pending.isOutput ? pending.nodeId : otherNodeId;
    final sourcePortId = pending.isOutput ? pending.portId : otherPortId;
    final targetNodeId = pending.isOutput ? otherNodeId : pending.nodeId;
    final targetPortId = pending.isOutput ? otherPortId : pending.portId;
    if (_inputBusy(targetNodeId, targetPortId)) {
      _tip(l10n.workflowLinkBusy);
      return;
    }
    _controller.createConnection(
      sourceNodeId,
      sourcePortId,
      targetNodeId,
      targetPortId,
    );
    setState(() => _pendingLink = null);
    _tip(l10n.workflowLinkConnected);
  }

  // ---------------------------------------------------------------------------
  // 「点端口」的点击识别：自己用原始 Listener 做，不依赖包内事件
  // ---------------------------------------------------------------------------
  //
  // 为什么不用包里的 PortEvents.onTap：PortWidget 的手势用
  // DragStartBehavior.down，按下那一刻就被当成「连线拖拽」起手，
  // controller.isConnecting 变 true；而 NodeFlowEditor._handlePointerUp 在
  // isConnecting 时直接 return（node_flow_editor.dart 里那句
  // 「Skip when connecting」），所以包内的端口点击事件在真机上**永远不会触发**。
  // 手机用例（workflow_editor_phone_connect_test.dart）能复现这一点。
  //
  // 这里用一个原始 Listener —— 它不参与手势竞技场，pointer up 一定收得到；
  // 命中判断用公开的 controller.hitTestPort（命中区 = 端口尺寸 + 吸附半径），
  // 没位移才算点击，多指或拖拽一律放过（节点点击/连线拖拽仍归包自己处理）。

  /// 算「点击」的最大位移（逻辑像素）。
  ///
  /// 手指按下去会抖，取 14（Flutter 自己的 touch slop 是 18）——再大就会把
  /// 「从一个端口拖到隔壁端口」误判成点击。同节点上最近的端口（汇聚的 a/b）
  /// 相隔 30 画布单位，在最小缩放 0.6 下也有 18px 屏幕距离，不会混。
  static const double _tapSlop = 14;

  /// 长按判定时间：和系统长按一致（500ms）。
  static const Duration _longPressDelay = Duration(milliseconds: 500);

  void _cancelLongPress() {
    _longPressTimer?.cancel();
    _longPressTimer = null;
  }

  void _onCanvasPointerDown(PointerDownEvent event) {
    _activePointers += 1;
    if (_activePointers == 1) {
      _tapDownAt = event.localPosition;
      _tapCandidate = true;
      _cancelLongPress();
      _longPressTimer = Timer(_longPressDelay, _fireLongPress);
    } else {
      // 多指 = 缩放/平移，不是点击也不是长按
      _tapCandidate = false;
      _cancelLongPress();
    }
  }

  void _onCanvasPointerMove(PointerMoveEvent event) {
    final down = _tapDownAt;
    if (!_tapCandidate || down == null) return;
    if ((event.localPosition - down).distance > _tapSlop) {
      _tapCandidate = false;
      _cancelLongPress();
    }
  }

  void _onCanvasPointerUp(PointerUpEvent event) {
    _activePointers = _activePointers > 0 ? _activePointers - 1 : 0;
    _cancelLongPress();
    if (!_tapCandidate) return;
    _tapCandidate = false;
    final down = _tapDownAt;
    _tapDownAt = null;
    if (down == null) return;
    _handleTapAt(event.localPosition);
  }

  void _onCanvasPointerCancel(PointerCancelEvent event) {
    _activePointers = _activePointers > 0 ? _activePointers - 1 : 0;
    _tapCandidate = false;
    _tapDownAt = null;
    _cancelLongPress();
  }

  /// 长按落点：节点 → 打开菜单（编辑/复制/删除）。端口长按不做事。
  void _fireLongPress() {
    _longPressTimer = null;
    if (!mounted || !_tapCandidate) return;
    final down = _tapDownAt;
    if (down == null) return;
    // 长按已经消费这次触摸：抬手不能再当成点击（否则菜单和配置面板一起弹）。
    _tapCandidate = false;
    if (_pendingLink != null) _cancelLink();
    final graphPoint = _controller.screenToGraph(ScreenPosition(down)).offset;
    if (_controller.hitTestPort(graphPoint) != null) return;
    final node = _nodeAt(graphPoint);
    if (node == null) return;
    unawaited(_showNodeMenu(node));
  }

  /// 这一下点击落在哪里？端口 → 连线；节点卡片 → 连目标或打开配置。
  ///
  /// 包自己的节点点击在**按下**时就回调（只用来做选中），「打开配置」必须由
  /// 这里在抬手后补，节点才拖得动。
  void _handleTapAt(Offset localPosition) {
    if (!mounted) return;
    final graphPoint = _controller
        .screenToGraph(ScreenPosition(localPosition))
        .offset;
    final portHit = _controller.hitTestPort(graphPoint);
    if (portHit != null) {
      final portNode = _controller.getNode(portHit.nodeId);
      if (portNode != null) {
        _onPortTap(portNode, portHit.portId, portHit.isOutput);
      }
      return;
    }
    final node = _nodeAt(graphPoint);
    if (node == null) return;
    _onNodeTap(node);
  }

  /// 命中最上层的节点（连线/空白返回 null，交给包自己处理）。
  Node<WorkflowNode>? _nodeAt(Offset graphPoint) {
    final hit = _controller.spatialIndex.hitTest(graphPoint);
    if (hit.hitType != HitTarget.node || hit.nodeId == null) return null;
    return _controller.getNode(hit.nodeId!);
  }

  // ---------------------------------------------------------------------------
  // 运行：预检 → 引擎（AI 节点走当前助手模型，回落默认模型；命令节点未接线，
  // 预检直接拦）
  // ---------------------------------------------------------------------------

  /// 当前助手（与聊天页同源）：决定 AI 节点的「当前对话模型」。
  Assistant? _currentAssistant() {
    try {
      return context.read<AssistantProvider>().currentAssistant;
    } catch (_) {
      return null;
    }
  }

  Future<void> _openRunSheet() async {
    if (_sheetOpen || _running.value) return;
    final needsModel = _snapshot().nodes.any(
      (node) => node.type == WorkflowNodeType.aiGenerate,
    );
    var modelMissing = false;
    if (needsModel) {
      try {
        final settings = context.read<SettingsProvider>();
        final model = resolveChatModel(settings, assistant: _currentAssistant());
        modelMissing = model.providerKey == null || model.modelId == null;
      } on ProviderNotFoundException {
        modelMissing = true;
      }
    }
    _sheetOpen = true;
    try {
      await showCustomBottomSheet<void>(
        context: context,
        title: AppLocalizations.of(context)!.workflowRun,
        expandedHeightFactor: 0.85,
        builder: (sheetContext, scrollController) => _RunSheet(
          scrollController: scrollController,
          logs: _runLogs,
          running: _running,
          result: _runResult,
          warnings: _runWarnings,
          initialInput: _runInput,
          modelMissing: modelMissing,
          onSelectDefaultModel: _openDefaultModelPage,
          onInputChanged: (value) => _runInput = value,
          onRun: (input) {
            _runInput = input;
            unawaited(_run(input));
          },
          onStop: _stop,
        ),
      );
    } finally {
      _sheetOpen = false;
    }
  }

  void _stop() {
    _runControl?.cancel();
    if (mounted) setState(() {});
  }

  Future<void> _openDefaultModelPage() => Navigator.of(context).push<void>(
    MaterialPageRoute<void>(builder: (_) => const DefaultModelPage()),
  );

  Future<void> _run(String input) async {
    if (_running.value) return;
    final l10n = AppLocalizations.of(context)!;
    final definition = _snapshot();
    // 预检：致命问题不跑（省得跑到一半才炸），告警照跑但带进运行面板。
    final validation = validateWorkflow(definition, supportsCommands: false);
    _runWarnings.value = validation.issues;
    if (!validation.ok) {
      if (mounted) {
        showAppSnackBar(
          context,
          message: '${l10n.workflowCannotRun}：${validation.fatalMessage ?? ''}',
          type: NotificationType.error,
          duration: const Duration(seconds: 4),
        );
      }
      return;
    }
    final needsModel = definition.nodes.any(
      (node) => node.type == WorkflowNodeType.aiGenerate,
    );
    SettingsProvider? settings;
    if (needsModel) {
      try {
        settings = context.read<SettingsProvider>();
      } on ProviderNotFoundException {
        settings = null;
      }
    }
    final resolved = settings == null
        ? (providerKey: null, modelId: null)
        : resolveChatModel(settings, assistant: _currentAssistant());
    if (needsModel &&
        (resolved.providerKey == null || resolved.modelId == null)) {
      _runWarnings.value = <WorkflowIssue>[
        ...validation.issues,
        const WorkflowIssue(
          code: 'model_not_selected',
          message: 'AI 节点需要模型：当前助手与全局默认模型都没配，请先给助手选一个对话模型',
          fatal: true,
        ),
      ];
      return;
    }
    // settings 延迟到真有 ai_generate 节点时才解析：纯本地工作流（文本/HTTP/
    // 条件/提取/延迟）不该因为「没装配 provider」而跑不了。
    WorkflowExecutorHost host() => _EditorHost(() {
      if (!mounted) {
        throw StateError('编辑器已关闭，无法继续生成');
      }
      return context.read<SettingsProvider>();
    }, _currentAssistant);
    _runControl = WorkflowRunControl();
    _running.value = true;
    _runLogs.value = const <WorkflowRunLogEntry>[];
    _runStatus.value = const <String, String>{};
    _runResult.value = null;

    try {
      final result = await WorkflowEngine(host: host()).run(
        definition: definition,
        input: input,
        control: _runControl,
        onLog: (entry) {
          // 每个节点**一行**：完成记录就地替换它的 running 记录。
          // 之前是无脑追加，running 那行会永远转圈（节点早就跑完了）。
          final next = List<WorkflowRunLogEntry>.of(_runLogs.value);
          final index = next.indexWhere((item) => item.nodeId == entry.nodeId);
          if (index >= 0) {
            next[index] = entry;
          } else {
            next.add(entry);
          }
          _runLogs.value = next;
          _runStatus.value = <String, String>{
            ..._runStatus.value,
            entry.nodeId: entry.status,
          };
        },
      );
      _runResult.value = result;
      if (!mounted) return;
      final text = result.ok
          ? '${l10n.workflowRunDone}：${_truncate(result.output, 80)}'
          : result.cancelled
          ? l10n.workflowRunCancelled
          : '${l10n.workflowRun}：${_truncate(result.error ?? '', 80)}';
      // 运行收尾也走标准通知样式（成功/取消/失败三态对应三种颜色）。
      showAppSnackBar(
        context,
        message: text,
        type: result.ok
            ? NotificationType.success
            : result.cancelled
            ? NotificationType.info
            : NotificationType.error,
      );
    } finally {
      _running.value = false;
      _runControl = null;
      if (mounted) setState(() {});
    }
  }

  // ---------------------------------------------------------------------------
  // AI 流式生成：节点/连线实时上画布，收尾用权威结果重排 + 自动落库
  // ---------------------------------------------------------------------------

  Future<void> _startGeneration() async {
    final description = widget.generateFrom;
    if (description == null ||
        description.trim().isEmpty ||
        _genSub != null) {
      return;
    }
    _genDismissTimer?.cancel();
    _genCancelled = false;
    _generating = true;
    _pendingGenEdges.clear();
    // 重试路径：把上一轮留下的半成品清掉，避免节点/连线重复叠加。
    if (_controller.nodes.isNotEmpty) {
      _swapCanvas(
        WorkflowDefinition(id: widget.workflow.id, name: _name),
        dirty: false,
      );
    }
    _genProgress.value = const _GenerationProgress.running();
    final settings = context.read<SettingsProvider>();
    Assistant? assistant;
    try {
      assistant = context.read<AssistantProvider>().currentAssistant;
    } catch (_) {}
    _genRequestId = 'wf-gen-${DateTime.now().microsecondsSinceEpoch}';
    _genSub = WorkflowGeneration.stream(
      description: description,
      settings: settings,
      assistant: assistant,
      requestId: _genRequestId,
    ).listen(
      _onGenerationEvent,
      onError: (Object error) => _finishGenerationError('生成失败：$error'),
      onDone: () {
        _genSub = null;
        _genRequestId = null;
      },
    );
  }

  void _onGenerationEvent(WorkflowGenerationEvent event) {
    if (!mounted || _genCancelled) return;
    switch (event) {
      case WorkflowNameEvent(:final name):
        setState(() => _name = name);
      case WorkflowNodeEvent(:final node):
        if (_controller.nodes.containsKey(node.id)) return;
        // 先按到达顺序纵向占位（与收尾的纵向分层布局同方向，不会大跳）。
        final index = _controller.nodes.length;
        _controller.addNode(
          _toFlowNode(
            node.copyWith(
              position: Offset(80, 80 + index * WorkflowLayout.stepY),
            ),
          ),
        );
        _flushPendingGenEdges();
        _scheduleGenFit();
        _syncGenProgress();
      case WorkflowEdgeEvent(:final edge):
        if (!_tryCreateConnection(edge)) _pendingGenEdges.add(edge);
        _syncGenProgress();
      case WorkflowProgressEvent(:final message):
        _syncGenProgress(message: message);
      case WorkflowDoneEvent():
        unawaited(_handleGenerationDone(event));
    }
  }

  void _syncGenProgress({String message = ''}) {
    _genProgress.value = _GenerationProgress.running(
      nodes: _controller.nodes.length,
      edges: _controller.connections.length,
      message: message,
    );
  }

  bool _tryCreateConnection(WorkflowEdge edge) {
    if (!_controller.nodes.containsKey(edge.fromNodeId) ||
        !_controller.nodes.containsKey(edge.toNodeId)) {
      return false;
    }
    try {
      _controller.createConnection(
        edge.fromNodeId,
        edge.fromPort,
        edge.toNodeId,
        edge.toPort,
      );
      return true;
    } catch (_) {
      // 端口对不上/重复连线等：交给收尾的权威重建，不打断实时流。
      return false;
    }
  }

  void _flushPendingGenEdges() {
    if (_pendingGenEdges.isEmpty) return;
    final remaining = <WorkflowEdge>[];
    for (final edge in _pendingGenEdges) {
      if (!_tryCreateConnection(edge)) remaining.add(edge);
    }
    _pendingGenEdges
      ..clear()
      ..addAll(remaining);
  }

  /// 每个节点上屏后把视图适配一次——用户要的就是「看着它长出来」。
  void _scheduleGenFit() {
    if (_genFitScheduled) return;
    _genFitScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _genFitScheduled = false;
      if (mounted) _controller.fitToView();
    });
  }

  Future<void> _handleGenerationDone(WorkflowDoneEvent event) async {
    _releaseGenerationSubscription();
    if (!mounted) return;
    if (_genCancelled) {
      // 取消：已经上屏的节点留作草稿，不落库。
      if (_controller.nodes.isNotEmpty) setState(() => _dirty = true);
      _genProgress.value = const _GenerationProgress.idle();
      _settleGeneration(keepDirty: true);
      return;
    }
    final flow = event.flow;
    if (flow == null) {
      _finishGenerationError(event.error ?? '生成失败');
      return;
    }
    // 收尾：用整段解析的权威结果重排画布（真实名字/坐标/连线一次到位）。
    final adopted = WorkflowDefinition(
      id: widget.workflow.id,
      name: flow.name,
      nodes: flow.nodes,
      edges: flow.edges,
      updatedAt: flow.updatedAt,
      enabled: flow.enabled,
    );
    _swapCanvas(adopted, dirty: false);
    _scheduleGenFit();
    await _store.save(_snapshot());
    if (!mounted) return;
    setState(() => _dirty = false);
    _genProgress.value = _GenerationProgress.done(
      nodes: adopted.nodes.length,
      edges: adopted.edges.length,
    );
    _genDismissTimer?.cancel();
    _genDismissTimer = Timer(const Duration(seconds: 4), () {
      if (mounted && _genProgress.value.phase == _GenPhase.done) {
        _genProgress.value = const _GenerationProgress.idle();
      }
    });
    _settleGeneration();
  }

  /// 生成结束后的收口：解除 _generating 压制、清空历史（生成是原子动作）、
  /// 按结果处理脏标记（成功=已落库不脏；取消/失败=草稿保持脏，提示未保存）。
  ///
  /// 放在帧后执行：换 controller 后包里可能还有一个 postFrame 的
  /// onCreated 回调在路上，早解除压制会让它塞进一条历史并重新点亮脏标记。
  void _settleGeneration({bool keepDirty = false}) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      _generating = false;
      _history.clear();
      if (keepDirty) {
        setState(() {});
      } else {
        setState(() => _dirty = false);
      }
    });
  }

  void _finishGenerationError(String message) {
    _releaseGenerationSubscription();
    if (!mounted) return;
    // 已经流出来的节点留在画布上当草稿（可直接手改或重试），但不落库。
    if (_controller.nodes.isNotEmpty) setState(() => _dirty = true);
    _genProgress.value = _GenerationProgress.failed(message);
    _settleGeneration(keepDirty: true);
  }

  void _cancelGeneration() {
    _genCancelled = true;
    final rid = _genRequestId;
    if (rid != null) ChatApiService.cancelRequest(rid);
    _releaseGenerationSubscription();
    if (!mounted) return;
    if (_controller.nodes.isNotEmpty) setState(() => _dirty = true);
    _genProgress.value = const _GenerationProgress.idle();
    _settleGeneration(keepDirty: true);
  }

  void _releaseGenerationSubscription() {
    final sub = _genSub;
    _genSub = null;
    _genRequestId = null;
    if (sub != null) unawaited(sub.cancel());
  }

  // ---------------------------------------------------------------------------
  // 界面
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    // 2026-10-03 用户定稿：功能**尽量放进标题栏**（底部悬浮栏在窄屏放不下，
    // 且材质不是我们这套 UI，被点名「丑死」）。布局 = 我们自己的头部（返回 +
    // 名字 + 撤销/重做/保存/运行/添加节点 + ⋮ 菜单）＋纯画布，底部悬浮栏整体删除。
    return Scaffold(
      body: Column(
        children: [
          _EditorHeader(
            title: _dirty ? '$_name •' : _name,
            canUndo: _history.canUndo,
            canRedo: _history.canRedo,
            onBack: () => Navigator.maybePop(context),
            onUndo: _undo,
            onRedo: _redo,
            onSave: () => unawaited(_save()),
            onRun: _openRunSheet,
            onAdd: _addNode,
            onMore: _showEditorMenu,
          ),
          ValueListenableBuilder<_GenerationProgress>(
            valueListenable: _genProgress,
            builder: (context, progress, _) =>
                progress.phase == _GenPhase.idle
                ? const SizedBox.shrink()
                : _GenerationBanner(
                    progress: progress,
                    onCancel: _cancelGeneration,
                    onRetry: () => unawaited(_startGeneration()),
                    onDismiss: () => _genProgress.value =
                        const _GenerationProgress.idle(),
                  ),
          ),
          Expanded(
            child: Stack(
        children: [
          ValueListenableBuilder<Map<String, String>>(
            valueListenable: _runStatus,
            builder: (context, status, _) => Listener(
              // 只用来识别「点端口 / 点节点 / 长按节点」这些包不提供的交互
              // （见 _onCanvasPointerDown 的说明）；其余手势原样透给画布，
              // 所以 behavior 用 translucent。
              behavior: HitTestBehavior.translucent,
              onPointerDown: _onCanvasPointerDown,
              onPointerMove: _onCanvasPointerMove,
              onPointerUp: _onCanvasPointerUp,
              onPointerCancel: _onCanvasPointerCancel,
              child: NodeFlowEditor<WorkflowNode, dynamic>(
                // 撤销/重做会换 controller：换 key 才会重新初始化编辑器
                // （NodeFlowEditor 不在 didUpdateWidget 里重初始化）。
                key: ObjectKey(_controller),
                controller: _controller,
                theme: _editorTheme(context),
                nodeBuilder: (context, node) => _NodeCard(
                  node: node.data,
                  status: status[node.id],
                  onDragStart: () => _startCardDrag(node),
                  onDragUpdate: _moveCardDrag,
                  onDragEnd: _endCardDrag,
                ),
                events: NodeFlowEvents<WorkflowNode, dynamic>(
                  node: NodeEvents<WorkflowNode>(
                    // **这里刻意不接 onTap**：包在 `ElementScope.onPointerDown`
                    // 里就会回调它（源码注释写的是「instant tap feedback」），
                    // 按下时任何 setState/选中都会让节点容器在手指还没抬起时重建，
                    // 真机上表现为「第一次拖不动」。选中改由包在拖动真正开始时
                    // （startNodeDrag）和我们的抬手轻点里做；打开配置面板在抬手。
                    onContextMenu: (node, _) => unawaited(_showNodeMenu(node)),
                    onDragStart: (node) => _dragSnapshot = _encodeSnapshot(),
                    onDragStop: (node) {
                      final before = _dragSnapshot;
                      _dragSnapshot = null;
                      if (before != null && before != _encodeSnapshot()) {
                        _record(before);
                      } else {
                        setState(() {});
                      }
                    },
                  ),
                  // 注意：这里**不能**靠 port: PortEvents(onTap:)
                  // ——包内那条路在手机上永远不触发（见 _onCanvasPointerDown）。
                  // 点端口由外层 Listener 自己识别后调 _onPortTap。
                  connection: ConnectionEvents<WorkflowNode, dynamic>(
                    // 连线事件是改完之后才回调的：改动前的状态取 baseline，
                    // 否则撤销连线会原地踏步（与快照压栈时机同一个坑）。
                    onCreated: (_) => _record(_baseline),
                    onDeleted: (_) => _record(_baseline),
                  ),
                  // 点空白画布 = 放弃这次连线。
                  viewport: ViewportEvents(onCanvasTap: (_) => _cancelLink()),
                  onSelectionChange: (selection) {
                    _selectedConnectionIds
                      ..clear()
                      ..addAll(<String>[
                        for (final connection in selection.connections)
                          connection.id,
                      ]);
                    final hasConnection = _selectedConnectionIds.isNotEmpty;
                    if (hasConnection != _hasSelectedConnection && mounted) {
                      setState(() => _hasSelectedConnection = hasConnection);
                    }
                  },
                ),
              ),
            ),
          ),
          if (_hasSelectedConnection)
            Positioned(
              top: 10,
              left: 0,
              right: 0,
              child: Center(
                child: Material(
                  color: cs.errorContainer,
                  borderRadius: BorderRadius.circular(20),
                  child: InkWell(
                    borderRadius: BorderRadius.circular(20),
                    onTap: _deleteSelectedConnection,
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 14,
                        vertical: 8,
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            Lucide.Unlink,
                            size: 16,
                            color: cs.onErrorContainer,
                          ),
                          const SizedBox(width: 6),
                          Text(
                            l10n.workflowDeleteConnection,
                            style: TextStyle(
                              fontSize: 13,
                              color: cs.onErrorContainer,
                              fontWeight: AppFontWeights.emphasis,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          // 点选连线的进行中提示：告诉用户「还差一步、点哪里」，并留一个取消出口。
          if (_pendingLink case final pending?)
            Positioned(
              left: 10,
              right: 10,
              bottom: 84,
              child: Material(
                color: cs.primaryContainer,
                borderRadius: BorderRadius.circular(14),
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(12, 6, 6, 6),
                  child: Row(
                    children: [
                      Icon(Lucide.Link, size: 16, color: cs.onPrimaryContainer),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          l10n.workflowLinkHint(pending.nodeName),
                          style: TextStyle(
                            fontSize: 12.5,
                            color: cs.onPrimaryContainer,
                            fontWeight: AppFontWeights.emphasis,
                          ),
                        ),
                      ),
                      TextButton(
                        onPressed: _cancelLink,
                        style: TextButton.styleFrom(
                          minimumSize: const Size(0, 32),
                          padding: const EdgeInsets.symmetric(horizontal: 10),
                          foregroundColor: cs.onPrimaryContainer,
                        ),
                        child: Text(
                          l10n.workflowLinkCancel,
                          style: const TextStyle(fontSize: 12.5),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
        ],
            ),
          ),
        ],
      ),
    );
  }

  /// 编辑器 ⋮ 菜单（底部弹层，我们自己的样式）：低频动作收在这里。
  Future<void> _showEditorMenu() async {
    if (_sheetOpen) return;
    _sheetOpen = true;
    String? action;
    try {
      await showCustomBottomSheet<void>(
        context: context,
        title: _name,
        builder: (sheetContext, scrollController) => _EditorMenuSheet(
          scrollController: scrollController,
          onAction: (picked) {
            action = picked;
            final route = ModalRoute.of(sheetContext);
            if (route != null && route.isActive) {
              Navigator.of(sheetContext).removeRoute(route);
            }
          },
        ),
      );
    } finally {
      _sheetOpen = false;
    }
    if (!mounted || action == null) return;
    switch (action) {
      case 'fit':
        _controller.fitToView();
      case 'rename':
        await _rename();
      case 'delete':
        await _deleteWorkflow();
    }
  }

  Future<void> _deleteWorkflow() async {
    final l10n = AppLocalizations.of(context)!;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        content: Text(l10n.workflowDeleteConfirm(_name)),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: Text(MaterialLocalizations.of(context).cancelButtonLabel),
          ),
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: Text(
              l10n.workflowDelete,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await _store.delete(widget.workflow.id);
    if (!mounted) return;
    Navigator.of(context).maybePop();
  }

  /// 编辑器主题：贴合 SoLab——细线网格、圆角节点、主题色选中态与连线。
  /// 明暗基座必须跟着系统走：只用 light 基座时暗色下会露出浅色默认值。
  NodeFlowTheme _editorTheme(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final dark = Theme.of(context).brightness == Brightness.dark;
    // 基座与子主题必须**整套**跟着明暗走：只换 NodeFlowTheme 而子主题仍用
    // light 预设，没被 copyWith 覆盖到的字段（阴影/选择框/标签/光标）会在
    // 暗色下露出浅色默认值。
    final base = dark ? NodeFlowTheme.dark : NodeFlowTheme.light;
    return base.copyWith(
      backgroundColor: cs.surface,
      gridTheme: (dark ? GridTheme.dark : GridTheme.light).copyWith(
        style: GridStyles.lines,
        color: cs.onSurface.withValues(alpha: 0.045),
        size: _gridSize,
        thickness: 1,
      ),
      nodeTheme: (dark ? NodeTheme.dark : NodeTheme.light).copyWith(
        backgroundColor: cs.surface,
        borderColor: cs.outlineVariant,
        selectedBorderColor: cs.primary,
        selectedBackgroundColor: cs.primaryContainer.withValues(alpha: 0.35),
        borderWidth: 1.2,
        selectedBorderWidth: 2,
        borderRadius: BorderRadius.circular(16),
      ),
      connectionTheme: (dark ? ConnectionTheme.dark : ConnectionTheme.light)
          .copyWith(
            color: cs.outline.withValues(alpha: 0.65),
            selectedColor: cs.primary,
            strokeWidth: 2,
          ),
      portTheme: (dark ? PortTheme.dark : PortTheme.light).copyWith(
        size: const Size(_portSize, _portSize),
        color: cs.outlineVariant,
        connectedColor: cs.primary,
        highlightColor: cs.primary,
        borderColor: cs.surface,
      ),
    );
  }
}

/// 点选连线的起点：哪个节点的哪个端口，方向是哪边。
class _PendingLink {
  const _PendingLink({
    required this.nodeId,
    required this.portId,
    required this.isOutput,
    required this.nodeName,
  });

  final String nodeId;
  final String portId;
  final bool isOutput;
  final String nodeName;
}

/// 节点配置面板的返回：改名/改配置，或要求删除。
class _NodeEditResult {
  const _NodeEditResult({this.node, this.delete = false});

  final WorkflowNode? node;
  final bool delete;
}

/// 画布上的节点卡片：图标 + 名称 + 类型（运行中按状态着色）。
class _NodeCard extends StatelessWidget {
  const _NodeCard({
    required this.node,
    required this.onDragStart,
    required this.onDragUpdate,
    required this.onDragEnd,
    this.status,
  });

  final WorkflowNode node;
  final VoidCallback onDragStart;
  final ValueChanged<DragUpdateDetails> onDragUpdate;
  final ValueChanged<DragEndDetails> onDragEnd;

  /// running / success / failed（运行面板推过来的实时状态）。
  final String? status;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final Color borderColor;
    switch (status) {
      case 'running':
        borderColor = cs.primary;
      case 'success':
        borderColor = cs.primary.withValues(alpha: 0.55);
      case 'failed':
        borderColor = cs.error;
      default:
        borderColor = cs.primary.withValues(alpha: 0.35);
    }
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onPanStart: (_) => onDragStart(),
      onPanUpdate: onDragUpdate,
      onPanEnd: onDragEnd,
      child: Container(
        width: _nodeWidth,
        height: _nodeHeight,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: cs.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: borderColor,
            width: status == 'running' || status == 'failed' ? 2 : 1,
          ),
        ),
        child: Row(
          children: [
            Container(
              width: 38,
              height: 38,
              decoration: BoxDecoration(
                color: cs.primary.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(
                workflowIconFor(node.type),
                size: 19,
                color: cs.primary,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    node.name,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: AppFontWeights.emphasis,
                    ),
                  ),
                  const SizedBox(height: 3),
                  Text(
                    _typeLabel(context),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 11.5,
                      color: cs.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
            if (status == 'running')
              SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: cs.primary,
                ),
              )
            else if (status == 'success')
              Icon(Lucide.CheckCircle, size: 15, color: cs.primary)
            else if (status == 'failed')
              Icon(Lucide.TriangleAlert, size: 15, color: cs.error)
            else
              Icon(
                Lucide.ChevronRight,
                size: 15,
                color: cs.onSurfaceVariant.withValues(alpha: 0.5),
              ),
          ],
        ),
      ),
    );
  }

  String _typeLabel(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    if (l10n == null) return node.type.wireName;
    return workflowNodeTitle(l10n, node.type);
  }
}

/// 添加节点面板：列出全部节点类型（SoLab 统一底部弹层）。
class _AddNodeSheet extends StatelessWidget {
  const _AddNodeSheet({required this.scrollController, required this.onPick});

  final ScrollController scrollController;
  final ValueChanged<WorkflowNodeType> onPick;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    // ListTile 的背景与 ink 画在最近的 Material 上：统一弹层的内容外面是
    // ColoredBox（面板底色），不补一层透明 Material 会触发框架断言。
    return Material(
      color: Colors.transparent,
      child: ListView(
        controller: scrollController,
        shrinkWrap: true,
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          for (final type in WorkflowNodeType.values)
            ListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              leading: Icon(workflowIconFor(type), size: 20, color: cs.primary),
              title: Text(
                workflowNodeTitle(l10n, type),
                style: const TextStyle(fontSize: 14),
              ),
              subtitle: Text(
                type == WorkflowNodeType.command
                    // 命令节点当前宿主跑不了（预检会拦），这里如实标注，
                    // 不能让用户以为加进来就能用。
                    ? '${workflowNodeSubtitle(l10n, type)}（${l10n.workflowCommandUnavailable}）'
                    : workflowNodeSubtitle(l10n, type),
                style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant),
              ),
              onTap: () => onPick(type),
            ),
        ],
      ),
    );
  }
}

/// 长按节点菜单（移动端没有右键，包的 onContextMenu 就是长按）。
class _NodeMenuSheet extends StatelessWidget {
  const _NodeMenuSheet({
    required this.scrollController,
    required this.onAction,
  });

  final ScrollController scrollController;
  final ValueChanged<String> onAction;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return Material(
      color: Colors.transparent,
      child: ListView(
        controller: scrollController,
        shrinkWrap: true,
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(Lucide.Pencil, size: 20, color: cs.primary),
            title: Text(
              l10n.workflowNodeName,
              style: const TextStyle(fontSize: 14),
            ),
            onTap: () => onAction('edit'),
          ),
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(Lucide.Copy, size: 20, color: cs.primary),
            title: Text(
              l10n.workflowDuplicate,
              style: const TextStyle(fontSize: 14),
            ),
            onTap: () => onAction('duplicate'),
          ),
          ListTile(
            dense: true,
            contentPadding: EdgeInsets.zero,
            leading: Icon(Lucide.Trash2, size: 20, color: cs.error),
            title: Text(
              l10n.workflowDeleteNode,
              style: const TextStyle(fontSize: 14),
            ),
            onTap: () => onAction('delete'),
          ),
        ],
      ),
    );
  }
}

/// 编辑器头部（2026-10-03）：返回 + 工作流名 + 高频动作直接放**标题栏**
/// （用户点名「功能标题栏再多放几个，下方悬浮的放不下了」）。
/// 视觉沿用应用自己的导航条语言（同 ScheduledTasksScaffold 的高度/底色），
/// 按钮用 IosIconButton（我们的触感组件），不用 Material IconButton。
class _EditorHeader extends StatelessWidget {
  const _EditorHeader({
    required this.title,
    required this.canUndo,
    required this.canRedo,
    required this.onBack,
    required this.onUndo,
    required this.onRedo,
    required this.onSave,
    required this.onRun,
    required this.onAdd,
    required this.onMore,
  });

  final String title;
  final bool canUndo;
  final bool canRedo;
  final VoidCallback onBack;
  final VoidCallback onUndo;
  final VoidCallback onRedo;
  final VoidCallback onSave;
  final VoidCallback onRun;
  final VoidCallback onAdd;
  final VoidCallback onMore;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final l10n = AppLocalizations.of(context)!;
    final bar = theme.appBarTheme;

    Widget action(
      IconData icon,
      String label,
      VoidCallback onTap, {
      bool enabled = true,
      Color? color,
    }) => Tooltip(
      message: label,
      child: IosIconButton(
        icon: icon,
        size: 20,
        minSize: 36,
        color: enabled
            ? (color ?? cs.onSurface)
            : cs.onSurface.withValues(alpha: 0.3),
        semanticLabel: label,
        onTap: enabled ? onTap : null,
      ),
    );

    return Material(
      color: bar.backgroundColor ?? cs.surface,
      child: SafeArea(
        bottom: false,
        child: SizedBox(
          height: bar.toolbarHeight ?? kToolbarHeight,
          child: Row(
            children: [
              const SizedBox(width: 4),
              Tooltip(
                message: l10n.settingsPageBackButton,
                child: IosIconButton(
                  icon: Lucide.ArrowLeft,
                  size: 22,
                  minSize: 44,
                  color: cs.onSurface,
                  semanticLabel: l10n.settingsPageBackButton,
                  onTap: onBack,
                ),
              ),
              Expanded(
                child: Text(
                  title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: bar.titleTextStyle ?? theme.textTheme.titleLarge,
                ),
              ),
              action(Lucide.Save, l10n.workflowSave, onSave),
              action(
                Lucide.RotateCcw,
                l10n.workflowUndo,
                onUndo,
                enabled: canUndo,
              ),
              action(
                Lucide.RotateCw,
                l10n.workflowRedo,
                onRedo,
                enabled: canRedo,
              ),
              action(Lucide.Play, l10n.workflowRun, onRun),
              action(Lucide.Plus, l10n.workflowAddNode, onAdd),
              action(Lucide.MoreVertical, l10n.workflowMore, onMore),
              const SizedBox(width: 4),
            ],
          ),
        ),
      ),
    );
  }
}

/// 编辑器 ⋮ 菜单：低频动作（适应视图 / 重命名 / 删除）。
class _EditorMenuSheet extends StatelessWidget {
  const _EditorMenuSheet({
    required this.scrollController,
    required this.onAction,
  });

  final ScrollController scrollController;
  final ValueChanged<String> onAction;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    Widget row(IconData icon, String label, String value, {Color? color}) =>
        ListTile(
          dense: true,
          contentPadding: EdgeInsets.zero,
          leading: Icon(icon, size: 20, color: color ?? cs.primary),
          title: Text(label, style: TextStyle(fontSize: 14, color: color)),
          onTap: () => onAction(value),
        );
    return Material(
      color: Colors.transparent,
      child: ListView(
        controller: scrollController,
        shrinkWrap: true,
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          row(Lucide.Layers, l10n.workflowFitView, 'fit'),
          row(Lucide.Pencil, l10n.workflowRename, 'rename'),
          row(Lucide.Trash2, l10n.workflowDelete, 'delete', color: cs.error),
        ],
      ),
    );
  }
}

class _NodeConfigSheet extends StatefulWidget {
  const _NodeConfigSheet({
    required this.scrollController,
    required this.node,
    required this.onDone,
    required this.onDelete,
  });

  final ScrollController scrollController;
  final WorkflowNode node;
  final ValueChanged<WorkflowNode> onDone;
  final VoidCallback onDelete;

  @override
  State<_NodeConfigSheet> createState() => _NodeConfigSheetState();
}

class _NodeConfigSheetState extends State<_NodeConfigSheet> {
  late final TextEditingController _name = TextEditingController(
    text: widget.node.name,
  );
  late final Map<String, TextEditingController> _fields =
      <String, TextEditingController>{
        for (final key in widget.node.type.configKeys)
          key: TextEditingController(
            text: (widget.node.config[key] ?? '').toString(),
          ),
      };

  @override
  void dispose() {
    _name.dispose();
    for (final controller in _fields.values) {
      controller.dispose();
    }
    super.dispose();
  }

  /// 多行输入更适合长文本类字段。
  int _linesFor(String key) =>
      key == 'prompt' || key == 'text' || key == 'body' || key == 'template'
      ? 4
      : 1;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    final keys = widget.node.type.configKeys;
    return ListView(
      controller: widget.scrollController,
      shrinkWrap: true,
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      children: [
        TextField(
          controller: _name,
          decoration: InputDecoration(
            labelText: l10n.workflowNodeName,
            border: const OutlineInputBorder(),
          ),
        ),
        if (keys.isEmpty) ...[
          const SizedBox(height: 10),
          Text(
            l10n.workflowNoConfig(workflowNodeTitle(l10n, widget.node.type)),
            style: TextStyle(fontSize: 12.5, color: cs.onSurfaceVariant),
          ),
        ],
        for (final key in keys) ...[
          const SizedBox(height: 14),
          TextField(
            controller: _fields[key],
            maxLines: _linesFor(key),
            decoration: InputDecoration(
              labelText: workflowFieldLabel(l10n, key),
              border: const OutlineInputBorder(),
            ),
          ),
        ],
        const SizedBox(height: 20),
        Row(
          children: [
            Expanded(
              child: FilledButton(
                onPressed: () {
                  final config = <String, dynamic>{
                    for (final entry in _fields.entries)
                      if (entry.value.text.trim().isNotEmpty)
                        entry.key: entry.value.text.trim(),
                  };
                  widget.onDone(
                    widget.node.copyWith(
                      name: _name.text.trim().isEmpty
                          ? workflowNodeTitle(l10n, widget.node.type)
                          : _name.text.trim(),
                      config: config,
                    ),
                  );
                },
                child: Text(l10n.workflowDone),
              ),
            ),
            const SizedBox(width: 16),
            // 参考实现：右下角「删除节点」（图标 + 红字）。
            InkWell(
              borderRadius: BorderRadius.circular(8),
              onTap: widget.onDelete,
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: 8,
                  vertical: 10,
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Lucide.Trash2, size: 17, color: cs.error),
                    const SizedBox(width: 5),
                    Text(
                      l10n.workflowDeleteNode,
                      style: TextStyle(fontSize: 13, color: cs.error),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

/// 运行面板：起始输入 + 运行/停止 + 逐节点实时日志 + 收口摘要。
///
/// 起始输入这一栏是必须的：内置 AI 模板的提示词里写着 {{start}}，
/// 没有入口就只能发出空内容（此前 UI 侧跑模板等于空转）。
class _RunSheet extends StatefulWidget {
  const _RunSheet({
    required this.scrollController,
    required this.logs,
    required this.running,
    required this.result,
    required this.warnings,
    required this.initialInput,
    required this.modelMissing,
    required this.onSelectDefaultModel,
    required this.onInputChanged,
    required this.onRun,
    required this.onStop,
  });

  final ScrollController scrollController;
  final ValueListenable<List<WorkflowRunLogEntry>> logs;
  final ValueListenable<bool> running;
  final ValueListenable<WorkflowRunResult?> result;
  final ValueListenable<List<WorkflowIssue>> warnings;
  final String initialInput;
  final bool modelMissing;
  final Future<void> Function() onSelectDefaultModel;
  final ValueChanged<String> onInputChanged;
  final ValueChanged<String> onRun;
  final VoidCallback onStop;

  @override
  State<_RunSheet> createState() => _RunSheetState();
}

class _RunSheetState extends State<_RunSheet> {
  late final TextEditingController _input = TextEditingController(
    text: widget.initialInput,
  );

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    return ValueListenableBuilder<bool>(
      valueListenable: widget.running,
      builder: (context, running, _) => ListView(
        controller: widget.scrollController,
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          TextField(
            controller: _input,
            minLines: 1,
            maxLines: 3,
            onChanged: widget.onInputChanged,
            decoration: InputDecoration(
              labelText: l10n.workflowRunInput,
              border: const OutlineInputBorder(),
            ),
          ),
          if (widget.modelMissing) ...[
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: widget.onSelectDefaultModel,
              icon: const Icon(Lucide.Settings2, size: 17),
              label: Text(l10n.defaultModelPageTitle),
            ),
          ],
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed: running ? null : () => widget.onRun(_input.text),
                  icon: Icon(Lucide.Play, size: 17),
                  label: Text(l10n.workflowRun),
                ),
              ),
              const SizedBox(width: 12),
              if (running)
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: widget.onStop,
                    icon: Icon(Lucide.Square, size: 16, color: cs.error),
                    label: Text(
                      l10n.workflowStop,
                      style: TextStyle(color: cs.error),
                    ),
                  ),
                ),
            ],
          ),
          if (running)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(
                l10n.workflowStopping,
                style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant),
              ),
            ),
          const SizedBox(height: 8),
          ValueListenableBuilder<List<WorkflowIssue>>(
            valueListenable: widget.warnings,
            builder: (context, warnings, _) {
              final fatal = <WorkflowIssue>[
                for (final issue in warnings)
                  if (issue.fatal) issue,
              ];
              final soft = <WorkflowIssue>[
                for (final issue in warnings)
                  if (!issue.fatal) issue,
              ];
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (fatal.isNotEmpty)
                    for (final issue in fatal)
                      _IssueRow(issue: issue, color: cs.error),
                  if (soft.isNotEmpty)
                    for (final issue in soft)
                      _IssueRow(issue: issue, color: cs.onSurfaceVariant),
                ],
              );
            },
          ),
          const Divider(height: 24),
          ValueListenableBuilder<List<WorkflowRunLogEntry>>(
            valueListenable: widget.logs,
            builder: (context, logs, _) {
              if (logs.isEmpty) {
                // 还没跑过：这里什么都不放（输入框已经在上面了），
                // 别拿一句标签当占位文案。
                return const SizedBox.shrink();
              }
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  for (final entry in logs)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          SizedBox(
                            width: 16,
                            height: 16,
                            child: entry.status == 'running'
                                ? CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: cs.primary,
                                  )
                                : Icon(
                                    entry.status == 'success'
                                        ? Lucide.CheckCircle
                                        : Lucide.TriangleAlert,
                                    size: 15,
                                    color: entry.status == 'success'
                                        ? cs.primary
                                        : cs.error,
                                  ),
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  entry.nodeName,
                                  style: TextStyle(
                                    fontSize: 13,
                                    fontWeight: AppFontWeights.emphasis,
                                  ),
                                ),
                                if (entry.output.trim().isNotEmpty)
                                  Padding(
                                    padding: const EdgeInsets.only(top: 2),
                                    child: Text(
                                      _truncateText(entry.output, 300),
                                      maxLines: 4,
                                      overflow: TextOverflow.ellipsis,
                                      style: TextStyle(
                                        fontSize: 12,
                                        height: 1.4,
                                        color: cs.onSurfaceVariant,
                                      ),
                                    ),
                                  ),
                                if (entry.error != null)
                                  Padding(
                                    padding: const EdgeInsets.only(top: 2),
                                    child: Text(
                                      _truncateText(entry.error!, 160),
                                      style: TextStyle(
                                        fontSize: 11.5,
                                        color: cs.error,
                                      ),
                                    ),
                                  ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                ],
              );
            },
          ),
          ValueListenableBuilder<WorkflowRunResult?>(
            valueListenable: widget.result,
            builder: (context, result, _) {
              if (result == null) return const SizedBox.shrink();
              final lines = <String>[
                if (result.ok)
                  l10n.workflowRunDone
                else if (result.cancelled)
                  l10n.workflowRunCancelled
                else
                  result.error ?? '',
                if (result.skipped.isNotEmpty)
                  l10n.workflowRunSkipped(result.skipped.length),
              ];
              return Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    for (final line in lines)
                      if (line.trim().isNotEmpty)
                        Text(
                          line,
                          style: TextStyle(
                            fontSize: 12,
                            color: result.ok ? cs.primary : cs.error,
                          ),
                        ),
                  ],
                ),
              );
            },
          ),
        ],
      ),
    );
  }
}

class _IssueRow extends StatelessWidget {
  const _IssueRow({required this.issue, required this.color});

  final WorkflowIssue issue;
  final Color color;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 4),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(Lucide.TriangleAlert, size: 13, color: color),
        const SizedBox(width: 6),
        Expanded(
          child: Text(
            issue.message,
            style: TextStyle(fontSize: 12, color: color),
          ),
        ),
      ],
    ),
  );
}

String _truncateText(String text, int max) {
  final trimmed = text.trim();
  if (trimmed.length <= max) return trimmed;
  return '${trimmed.substring(0, max)}…';
}

/// 编辑器运行环境：AI 节点走**当前助手模型**（与 AI 生成同一口径），
/// 助手没配时回落到全局默认模型。
///
/// 2026-10-05 用户反馈：点运行弹「要选择默认模型」等于逼用户多配一份——
/// 生成都能用当前对话/助手的模型，运行没有理由用不了。
///
/// 命令节点需要沙盒会话（WorkspaceToolContext），接线在下一批——这里如实报错，
/// 而**运行前预检**（workflow_validation.dart 的 command_not_wired）会在更早的
/// 一步就把它标成致命问题，用户不会跑到一半才看到失败。
class _EditorHost implements WorkflowExecutorHost {
  const _EditorHost(this._settingsOf, this._assistantOf);

  /// 延迟取 settings：AI 生成节点真的跑到时才需要 provider/model。
  final SettingsProvider Function() _settingsOf;

  /// 当前助手（决定「当前对话模型」）：找不到时为 null，回落默认模型。
  final Assistant? Function() _assistantOf;

  @override
  bool get supportsCommands => false;

  @override
  Future<String> generateText({required String prompt, String? system}) async {
    final settings = _settingsOf();
    final model = resolveChatModel(settings, assistant: _assistantOf());
    final providerKey = model.providerKey;
    final modelId = model.modelId;
    if (providerKey == null ||
        providerKey.isEmpty ||
        modelId == null ||
        modelId.isEmpty) {
      throw StateError(
        '当前没有可用模型：助手的对话模型与全局默认模型都未配置。'
        '给当前助手选一个模型即可（或配置默认模型）。',
      );
    }
    final config = settings.getProviderConfig(providerKey);
    final merged = (system == null || system.isEmpty)
        ? prompt
        : '$system\n\n---\n\n$prompt';
    return ApiSessionScope.run(
      () => ChatApiService.generateText(
        config: config,
        modelId: modelId,
        prompt: merged,
      ),
      null,
    );
  }

  @override
  Future<String> runCommand(String command) async {
    throw StateError('命令节点需要沙盒环境，暂未接线（下一批提供）');
  }
}

/// 生成阶段的四态（idle 时横幅整体不占位）。
enum _GenPhase { idle, running, done, failed }

/// 流式生成进度（节点/连线数为画布实时计数，只用于展示）。
class _GenerationProgress {
  const _GenerationProgress._({
    required this.phase,
    required this.nodes,
    required this.edges,
    required this.message,
  });

  const _GenerationProgress.idle()
    : this._(phase: _GenPhase.idle, nodes: 0, edges: 0, message: '');

  const _GenerationProgress.running({
    this.nodes = 0,
    this.edges = 0,
    this.message = '',
  }) : phase = _GenPhase.running;

  const _GenerationProgress.done({required this.nodes, required this.edges})
    : phase = _GenPhase.done,
      message = '';

  const _GenerationProgress.failed(this.message)
    : phase = _GenPhase.failed,
      nodes = 0,
      edges = 0;

  final _GenPhase phase;
  final int nodes;
  final int edges;
  final String message;
}

/// 画布顶部的生成状态横幅：生成中（可取消）/ 完成（自动消失）/ 失败（可重试）。
class _GenerationBanner extends StatelessWidget {
  const _GenerationBanner({
    required this.progress,
    required this.onCancel,
    required this.onRetry,
    required this.onDismiss,
  });

  final _GenerationProgress progress;
  final VoidCallback onCancel;
  final VoidCallback onRetry;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final l10n = AppLocalizations.of(context)!;
    final phase = progress.phase;
    final counts = l10n.workflowGenerateCounts(progress.nodes, progress.edges);
    final label = switch (phase) {
      _GenPhase.running => progress.message.isEmpty
          ? '${l10n.workflowGenerateLive} · $counts'
          : '${l10n.workflowGenerateLive} · ${progress.message}',
      _GenPhase.done => '${l10n.workflowGenerateDone} · $counts',
      _GenPhase.failed => progress.message,
      _GenPhase.idle => '',
    };
    final leading = switch (phase) {
      _GenPhase.running => SizedBox(
        width: 14,
        height: 14,
        child: CircularProgressIndicator(strokeWidth: 2, color: cs.primary),
      ),
      _GenPhase.done => Icon(Lucide.Check, size: 16, color: cs.primary),
      _GenPhase.failed => Icon(
        Lucide.TriangleAlert,
        size: 16,
        color: cs.error,
      ),
      _GenPhase.idle => const SizedBox.shrink(),
    };
    return Material(
      color: phase == _GenPhase.failed
          ? cs.errorContainer.withValues(alpha: 0.45)
          : cs.primary.withValues(alpha: 0.08),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 8, 8, 8),
        child: Row(
          children: [
            leading,
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                label,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 12.5,
                  color: phase == _GenPhase.failed ? cs.error : cs.onSurface,
                ),
              ),
            ),
            if (phase == _GenPhase.running)
              TextButton(
                onPressed: onCancel,
                style: TextButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                ),
                child: Text(
                  MaterialLocalizations.of(context).cancelButtonLabel,
                  style: const TextStyle(fontSize: 12.5),
                ),
              )
            else if (phase == _GenPhase.failed) ...[
              TextButton(
                onPressed: onRetry,
                style: TextButton.styleFrom(
                  visualDensity: VisualDensity.compact,
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                ),
                child: Text(
                  l10n.workflowGenerateRetry,
                  style: const TextStyle(fontSize: 12.5),
                ),
              ),
              IconButton(
                onPressed: onDismiss,
                visualDensity: VisualDensity.compact,
                icon: const Icon(Lucide.X, size: 16),
              ),
            ] else
              IconButton(
                onPressed: onDismiss,
                visualDensity: VisualDensity.compact,
                icon: const Icon(Lucide.X, size: 16),
              ),
          ],
        ),
      ),
    );
  }
}
