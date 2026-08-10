"""AI 系统提示词构建器 - 参考 mHook AiPrompt.java 移植"""
from .ai_setting import AiSetting
from .mcp_setting import McpSetting
from .skill_reader import SkillReader


class AiPrompt:
    """构建 AI 逆向助手的 system prompt"""

    @staticmethod
    def build(app_info: str = "") -> str:
        mcp_enabled = McpSetting.enabled_count() > 0
        return AiPrompt._build(app_info, mcp_enabled)

    @staticmethod
    def _build(app_info: str, mcp_enabled: bool) -> str:
        sb = []
        sb.append("你是 APK 逆向工程引擎 (apk-rev-engine) 的 AI 逆向辅助助手。")
        sb.append("本工具是一个全功能 APK 逆向分析 CLI 工具集，支持静态分析、动态 Hook、脱壳、修补、重打包等。\n")

        sb.append("当你根据用户需求分析出结果后，可以直接输出分析结论或操作建议。\n")
        sb.append("你必须始终使用简体中文进行回复和输出，禁止使用英文回复。\n")

        if mcp_enabled:
            sb.append("【工具后端（MCP）】\n")
            sb.append("你已接入逆向工具后端，通过 function calling 调用。")
            sb.append("每个可用工具的名字都是 mcp__服务器名__工具名，且一定出现在本轮下发给你的 tools 函数列表中。\n")
            sb.append("工具名前缀（mcp__后面的服务器名）只能取下面已启用服务器里的实际名称，不要臆造前缀：\n")
            for s in McpSetting.enabled_servers():
                name = s.get("name", "")
                label = s.get("label", name)
                url = s.get("url", "")
                sb.append(f"- 前缀 {name}（{label}，{url}）\n")
            sb.append("\n职责分工与铁律：\n")
            sb.append("- 只能调用 tools 函数列表里真实存在的工具名（use_skill 或 mcp__服务器名__工具名）。\n")
            sb.append("- function.name 字段必须填完整工具名；arguments 只放该工具的参数。\n")
            sb.append("- 每一步都要用前序工具返回的真实 workspaceId/路径/函数定位符。\n")
            sb.append("- 若某后端不可用，提示用户检查对应 MCP 服务器是否已启动。\n\n")

        sb.append("【内置技能库 use_skill】\n")
        sb.append("你挂载了一批专业逆向技能文档（SKILL.md），通过 use_skill 工具按需读取，")
        sb.append("里面是标准做法、命令与脚本模板，照着做，别凭记忆瞎试。\n")
        sb.append('任务不明确时先调 use_skill("ai-reverse-workflow") 获取标准流程。\n')
        skills = SkillReader.list_skills()
        if skills:
            sb.append("可用技能：" + "、".join(skills) + "\n\n")
        else:
            sb.append("（暂无技能文档）\n\n")

        sb.append("收敛要求：定位到足够证据后尽快输出最终结论，")
        sb.append("同一范围不要反复搜索相同关键词超过 2 次。\n")

        if app_info:
            sb.append(f"\n本次目标应用信息：\n{app_info}")

        return "\n".join(sb)

    @staticmethod
    def build_hook_prompt(apk_info: str) -> str:
        """构建 Hook 配置生成提示"""
        base = AiPrompt.build(apk_info)
        base += "\n\n【本任务：生成 Hook 配置】\n"
        base += "请分析目标 APK，输出 Xposed/LSPosed Hook 配置（JSON 格式）。\n"
        base += "输出契约：\n"
        base += '```json\n'
        base += '{\n'
        base += '  "action": "saveHook",\n'
        base += '  "appPkg": "目标应用包名",\n'
        base += '  "appName": "目标应用名称",\n'
        base += '  "detail": "简要说明修改目的",\n'
        base += '  "hooks": [\n'
        base += '    {\n'
        base += '      "hookType": "setRet",\n'
        base += '      "className": "全限定类名",\n'
        base += '      "methodName": "方法名",\n'
        base += '      "paramsName": [],\n'
        base += '      "returnType": "I",\n'
        base += '      "returnData": "1"\n'
        base += '    }\n'
        base += '  ]\n'
        base += '}\n'
        base += '```\n'
        return base

    @staticmethod
    def build_fix_prompt(app_info: str, requirement: str) -> str:
        """构建自动改包提示"""
        base = AiPrompt.build(app_info)
        base += "\n\n【本任务：自动改包】\n"
        base += "目标：使用已接入的 MCP 工具，对目标 APK 完成【定位→修改→构建签名 APK】。\n"
        base += "最终只输出一个 ```json 代码块：\n"
        base += '```json\n{"action":"fixDone","outputName":"构建产物文件名","detail":"做了什么修改"}\n```\n'
        base += "未能构建出产物时输出："
        base += '```json\n{"action":"fixFailed","reason":"原因","detail":"已做的尝试"}\n```\n'
        base += f"\n用户需求：{requirement or '无'}"
        return base