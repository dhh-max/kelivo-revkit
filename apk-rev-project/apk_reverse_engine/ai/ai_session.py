"""AI 会话管理 - 工具调用循环，参考 mHook AiSession.java 移植"""
import json
import threading
from typing import Callable, Optional, List
from .ai_client import AiClient
from .ai_setting import AiSetting
from .mcp_manager import McpManager
from .skill_reader import SkillReader


class AiSession:
    """AI 会话工具循环：AI 可调用 MCP 后端工具与内置技能，直到产出最终结果。"""

    MAX_STEPS = 32
    _stop_flag = threading.Event()
    _available_tools: List[str] = []

    @classmethod
    def stop(cls):
        cls._stop_flag.set()

    @classmethod
    def run(cls, system: str, user: str,
            on_delta: Callable[[str], None] = None,
            on_tool_event: Callable[[str], None] = None,
            on_done: Callable[[str], None] = None,
            on_error: Callable[[Exception], None] = None):
        """
        同步运行 AI 会话（阻塞当前线程直到完成）。
        在新线程中调用以实现异步。
        """
        cls._stop_flag.clear()
        max_steps = AiSetting.max_steps() or cls.MAX_STEPS
        cls._available_tools = []

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

        tools = []
        errors = []

        # 收集 MCP 工具
        try:
            mcp_tools = McpManager.collect_tools(errors)
            for t in mcp_tools:
                tools.append(t.to_function())
                cls._available_tools.append(t.full_name())
        except Exception as e:
            errors.append(str(e))

        # 添加 use_skill 工具
        cls._add_use_skill(tools)

        if errors:
            err_msg = "部分 MCP 后端不可用：" + "；".join(errors)
            if on_tool_event:
                on_tool_event(err_msg)
            messages.append({
                "role": "system",
                "content": f"MCP 探测结果：以下服务器本次不可用，禁止调用其工具："
                           f"{'；'.join(errors)}。可用工具仅限 tools 列表中的 mcp__ 前缀。"
            })

        cls._run_round(messages, tools, 0, max_steps, on_delta, on_tool_event, on_done, on_error)

    @classmethod
    def _run_round(cls, messages: list, tools: list, step: int, max_steps: int,
                   on_delta, on_tool_event, on_done, on_error):
        if cls._stop_flag.is_set():
            if on_done:
                on_done("")
            return

        if step >= max_steps:
            tip = f"\n[已停止：达到最大工具调用轮次 {max_steps}]"
            if on_tool_event:
                on_tool_event(tip)
            if on_done:
                on_done("")
            return

        def _on_done(text):
            if text is not None:
                if on_done:
                    on_done(text)
            # text is None means tool_calls were received, handled below

        def _on_error(e):
            if on_error:
                on_error(e)

        result = AiClient.complete(
            messages, tools if tools else None,
            on_delta=on_delta, on_done=_on_done, on_error=_on_error
        )

        # Check if result is tool_calls (list) or text (str)
        if isinstance(result, list):
            # tool_calls received
            if cls._stop_flag.is_set():
                if on_done:
                    on_done("")
                return

            next_step = step + 1
            try:
                # Add assistant message with tool_calls
                assistant_msg = {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": result,
                }
                messages.append(assistant_msg)

                for tc in result:
                    fn = tc.get("function", {})
                    name = fn.get("name", "")
                    args_str = fn.get("arguments", "{}")

                    if on_tool_event:
                        on_tool_event(f"→ 调用工具: {name} {args_str}")

                    # Parse arguments
                    try:
                        args = json.loads(args_str) if args_str and args_str.strip() else {}
                    except Exception:
                        args = {}

                    tool_result = cls._execute_tool(name, args)
                    call_id = tc.get("id", "") or f"call_{id(tc)}"

                    tool_msg = {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": tool_result,
                    }
                    messages.append(tool_msg)

                if cls._stop_flag.is_set():
                    if on_done:
                        on_done("")
                    return

                cls._run_round(messages, tools, next_step, max_steps,
                               on_delta, on_tool_event, on_done, on_error)
            except Exception as e:
                if on_error:
                    on_error(e)
        elif isinstance(result, str):
            # Normal text response - already handled by _on_done callback
            if result and not _on_done_called(result, on_done):
                if on_done:
                    on_done(result)
        # If result is "" (error), on_error was already called

    @staticmethod
    def _execute_tool(name: str, args: dict) -> str:
        try:
            if not name or not name.strip():
                return (f"[工具调用异常] function.name 为空：工具名必须填在 function.name 字段"
                        f"（可用工具: {'；'.join(AiSession._available_tools)}）")

            if name == "use_skill":
                skill = args.get("name", "")
                if not skill:
                    return "[use_skill] 需要参数 name"
                content = SkillReader.read_skill(skill)
                if content is None:
                    available = SkillReader.list_skills()
                    return f"[技能不存在] 可用技能: {'、'.join(available)}"
                return McpManager.truncate(content, McpManager.MAX_TOOL_OUTPUT)

            if name.startswith("mcp__"):
                return McpManager.truncate(
                    McpManager.call_tool(name, args),
                    McpManager.MAX_TOOL_OUTPUT
                )

            return f"[未知工具: {name}] 可用工具: {'；'.join(AiSession._available_tools)}"
        except Exception as e:
            return f"[工具执行异常] {name}: {e}"

    @staticmethod
    def _add_use_skill(tools: list):
        skills = SkillReader.list_skills()
        tool_def = {
            "type": "function",
            "function": {
                "name": "use_skill",
                "description": "读取内置逆向技能文档（SKILL.md）的内容，包含标准做法、命令与脚本模板。"
                               "任务不明确时先调用 ai-reverse-workflow。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "要读取的逆向技能名称",
                            "enum": skills,
                        }
                    },
                    "required": ["name"],
                }
            }
        }
        tools.append(tool_def)


def _on_done_called(text, callback):
    """Helper to avoid double-calling on_done"""
    return False  # The callback is always called in _on_done