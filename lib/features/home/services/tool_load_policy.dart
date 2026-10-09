/// 工具装载策略（SoLab 自研）。
///
/// 上游把 `tool_handler_service` 整体重写后不再有这个概念，但我方 `tool_router`
/// 仍按「本轮是否需要工具、是轻量还是全量」做路由，故独立成文件保留。
enum ToolLoadPolicy { none, light, full }
