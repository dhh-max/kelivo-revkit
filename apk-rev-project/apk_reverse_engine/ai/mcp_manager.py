"""MCP 管理器 - 工具收集/调用/端口探测，参考 mHook McpManager.java 移植"""
import socket
import json
from typing import List, Tuple
from .mcp_client import McpClient
from .mcp_setting import McpSetting


class McpManager:
    """MCP 服务器管理：工具收集、调用、端口探测"""

    MAX_TOOL_OUTPUT = 30000

    class McpTool:
        def __init__(self, server_name: str, tool_name: str,
                     description: str, parameters: dict):
            self.server_name = server_name
            self.tool_name = tool_name
            self.description = description or ""
            self.parameters = parameters or {}

        def full_name(self) -> str:
            return f"mcp__{self.server_name}__{self.tool_name}"

        def to_function(self) -> dict:
            return {
                "type": "function",
                "function": {
                    "name": self.full_name(),
                    "description": self.description,
                    "parameters": self.parameters,
                }
            }

    _clients: dict = {}

    @classmethod
    def get_client(cls, name: str, url: str, token: str = "") -> McpClient:
        if name not in cls._clients:
            cls._clients[name] = McpClient(url, token)
        return cls._clients[name]

    @classmethod
    def invalidate(cls, name: str):
        cls._clients.pop(name, None)

    @classmethod
    def reset_clients(cls):
        cls._clients.clear()

    @classmethod
    def collect_tools(cls, errors: list = None) -> List['McpManager.McpTool']:
        out = []
        servers = McpSetting.get_servers()
        for s in servers:
            if not s.get("enable"):
                continue
            name = s.get("name", "")
            url = s.get("url", "")
            token = s.get("token", "")
            try:
                client = cls.get_client(name, url, token)
                tools_raw = client.list_tools()
                for t in tools_raw:
                    mt = cls.McpTool(
                        server_name=name,
                        tool_name=t.get("name", ""),
                        description=t.get("description", ""),
                        parameters=t.get("inputSchema") or t.get("input_schema") or {}
                    )
                    out.append(mt)
            except Exception as e:
                cls.invalidate(name)
                if errors is not None:
                    errors.append(f"{name} 不可用（{cls._short_msg(e)}）")
        return out

    @classmethod
    def call_tool(cls, full_name: str, args: dict) -> str:
        parts = full_name.split("__", 2)
        if len(parts) != 3:
            raise ValueError(f"非法工具名: {full_name}")
        server = parts[1]
        tool = parts[2]
        s = McpSetting.find_server(server)
        if s is None:
            raise ValueError(f"未找到 MCP 服务器: {server}")
        if not s.get("enable"):
            raise ValueError(f"服务器 {server} 未启用（请先在 AI→MCP 设置中启用后再试）")
        try:
            client = cls.get_client(server, s.get("url", ""), s.get("token", ""))
            return client.call_tool(tool, args)
        except Exception:
            cls.invalidate(server)
            raise

    @classmethod
    def probe_and_enable(cls) -> int:
        """探测端口并自动启用可达的 MCP 服务器，返回启用数"""
        servers = McpSetting.get_servers()
        enabled_count = 0
        probe_ports = McpSetting.PROBE_PORTS
        for s in servers:
            name = s.get("name", "")
            ports = probe_ports.get(name, [])
            for port in ports:
                if cls.is_port_open("127.0.0.1", port):
                    s["url"] = f"http://127.0.0.1:{port}/mcp"
                    s["enable"] = True
                    enabled_count += 1
                    break
        if enabled_count > 0:
            McpSetting.save_servers(servers)
        return enabled_count

    @staticmethod
    def is_port_open(host: str, port: int) -> bool:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((host, port))
            return True
        except Exception:
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    @staticmethod
    def truncate(s: str, max_len: int = MAX_TOOL_OUTPUT) -> str:
        if not s:
            return ""
        if len(s) <= max_len:
            return s
        return s[:max_len] + f"\n...[已截断，剩余 {len(s) - max_len} 字符]"

    @staticmethod
    def _short_msg(e: Exception) -> str:
        m = str(e)
        if len(m) > 60:
            m = m[:60]
        return m if m else type(e).__name__