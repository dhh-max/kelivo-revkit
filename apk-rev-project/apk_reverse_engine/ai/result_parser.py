"""AI 结果解析器 - 从 AI 输出提取 JSON，参考 mHook ResultParser.java 移植"""
import json
import re
from typing import List, Optional


class ResultParser:
    """解析 AI 输出中的 JSON 代码块"""

    @staticmethod
    def extract_json(text: str) -> Optional[str]:
        """从文本中提取最后一个 ```json 代码块的内容"""
        if not text:
            return None
        # Try ```json ... ```
        matches = re.findall(r'```json\s*([\s\S]*?)```', text, re.IGNORECASE)
        if matches:
            return matches[-1].strip()
        # Try ``` ... ```
        matches = re.findall(r'```\s*([\s\S]*?)```', text)
        if matches:
            return matches[-1].strip()
        # Try raw JSON object
        t = text.strip()
        if t.startswith('{') and t.endswith('}'):
            return t
        if t.startswith('[') and t.endswith(']'):
            return t
        return None

    @staticmethod
    def parse_and_normalize(text: str) -> dict:
        """解析 AI 输出的 JSON 并规范化"""
        json_str = ResultParser.extract_json(text)
        if not json_str:
            raise Exception("未在 AI 输出中找到 ```json 代码块")
        try:
            obj = json.loads(json_str)
        except Exception as e:
            raise Exception(f"JSON 解析失败：{e}")
        if not obj:
            raise Exception("JSON 为空")

        action = obj.get("action", "")
        if not action:
            if "hooks" in obj:
                action = "saveHook"
            elif "patches" in obj:
                action = "saveFix"
        if not action:
            raise Exception("无法识别 action 字段（需要 saveHook 或 saveFix）")

        obj["action"] = action

        if action == "saveHook":
            pkg = obj.get("appPkg", "")
            if not pkg.strip():
                raise Exception("saveHook 缺少 appPkg")
            hooks = obj.get("hooks", [])
            if not hooks:
                raise Exception("saveHook 的 hooks 为空")
            normalized = []
            for h in hooks:
                cls = h.get("className", "")
                mtd = h.get("methodName", "")
                rt = h.get("returnType", "")
                if not cls.strip():
                    raise Exception("hooks 中存在缺少 className 的条目")
                if not mtd.strip():
                    raise Exception(f"hooks 中 [{cls}] 缺少 methodName")
                if not rt.strip():
                    raise Exception(f"hooks 中 [{cls}.{mtd}] 缺少 returnType")
                if "returnData" not in h:
                    raise Exception(f"hooks 中 [{cls}.{mtd}] 缺少 returnData")
                h["hookType"] = "setRet"
                params = h.get("paramsName")
                if not isinstance(params, list):
                    try:
                        h["paramsName"] = json.loads(str(params)) if params else []
                    except Exception:
                        h["paramsName"] = []
                normalized.append(h)
            if not normalized:
                raise Exception("hooks 解析后为空")
            obj["hooks"] = normalized

        elif action == "saveFix":
            pkg = obj.get("appPkg", "")
            if not pkg.strip():
                raise Exception("saveFix 缺少 appPkg")
            if "mode" not in obj:
                obj["mode"] = 2
            patches = obj.get("patches", {})
            if not patches:
                raise Exception("saveFix 的 patches 为空（模式2 需要补丁源码）")
        else:
            raise Exception(f"未知 action：{action}")

        return obj

    @staticmethod
    def parse_hook_apps(text: str) -> List[dict]:
        """解析多个 saveHook 结果（XP 模块分析常用）"""
        json_str = ResultParser.extract_json(text)
        if not json_str:
            raise Exception("未在 AI 输出中找到 ```json 代码块")
        try:
            single = json.loads(json_str)
            arr = [single]
        except Exception:
            arr = json.loads(json_str)
            if not isinstance(arr, list):
                arr = [arr]
        if not arr:
            raise Exception("AI 结果为空")
        out = []
        skipped = 0
        for item in arr:
            if isinstance(item, str):
                try:
                    item = json.loads(item)
                except Exception:
                    skipped += 1
                    continue
            if not isinstance(item, dict):
                skipped += 1
                continue
            hooks = item.get("hooks", [])
            if not hooks:
                skipped += 1
                continue
            try:
                out.append(ResultParser.parse_and_normalize(json.dumps(item)))
            except Exception:
                skipped += 1
        if not out:
            msg = "AI 结果中没有可导入的 hook 配置"
            if skipped > 0:
                msg += f"（跳过 {skipped} 个空配置）"
            raise Exception(msg)
        return out

    @staticmethod
    def build_hook_config(app_pkg: str, app_name: str, app_ver: str, parsed: dict) -> dict:
        """构建 Hook 配置"""
        cfg = {
            "appPkg": app_pkg,
            "appName": app_name,
            "appVer": app_ver or "",
            "author": "AI",
            "detail": parsed.get("detail", "AI生成"),
            "hooks": parsed.get("hooks", []),
        }
        return cfg