"""MCP 客户端 - JSON-RPC 2.0 over streamable HTTP"""
import json
import requests
import random
import time

class McpClient:
    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, base_url: str, token: str = ""):
        self.base_url = (base_url or "").strip()
        self.token = (token or "").strip()
        self.session_id = None
        self.initialized = False

    def _endpoint(self) -> str:
        url = self.base_url
        while url.endswith("/"):
            url = url[:-1]
        if url.endswith("/mcp"):
            return url
        return url + "/mcp"

    def connect(self):
        params = {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": True}
            },
            "clientInfo": {"name": "apk-rev-engine", "version": "2.0"}
        }
        self._request("initialize", params, expect_result=True)
        try:
            self._request("notifications/initialized", None, expect_result=False)
        except Exception:
            pass
        self.initialized = True

    def list_tools(self) -> list:
        self._ensure_init()
        result = self._request("tools/list", {}, expect_result=True)
        tools = result.get("tools", []) if result else []
        return tools or []

    def call_tool(self, name: str, arguments: dict = None) -> str:
        self._ensure_init()
        params = {"name": name}
        if arguments:
            params["arguments"] = arguments
        result = self._request("tools/call", params, expect_result=True)
        if not result:
            return "[无返回]"
        parts = []
        content = result.get("content", [])
        for c in content:
            if c.get("type") == "text":
                parts.append(c.get("text", ""))
            elif c.get("type") == "image":
                parts.append("[图片数据已省略]")
        text = "\n".join(parts).strip()
        if result.get("isError"):
            text = "[工具错误] " + text
        return text

    def _ensure_init(self):
        if not self.initialized:
            self.connect()

    def _request(self, method: str, params, expect_result: bool = True):
        body = {
            "jsonrpc": "2.0",
            "id": int(time.time()) % 0x7fffffff + random.randint(0, 10000),
            "method": method,
        }
        if params is not None:
            body["params"] = params
        if not expect_result:
            body.pop("id", None)

        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        resp = requests.post(
            self._endpoint(), headers=headers, json=body,
            timeout=(8 if not expect_result else 120)
        )
        sid = resp.headers.get("Mcp-Session-Id")
        if sid and not self.session_id:
            self.session_id = sid
        if not expect_result:
            return None
        if resp.status_code >= 400:
            raise Exception(f"HTTP {resp.status_code}: {resp.text}")
        raw = resp.text
        obj = json.loads(raw) if raw else {}
        if obj.get("error"):
            err = obj["error"]
            raise Exception(f"MCP 错误[{method}]: {err.get('message', '未知')}")
        return obj.get("result")