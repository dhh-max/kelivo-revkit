"""MCP 设置 - 服务器配置管理"""
import json
import os

class McpSetting:
    DEFAULT_SERVERS = [
        {"name": "MTApkMcp", "label": "MT管理器·APK分析", "url": "http://127.0.0.1:8787/mcp", "token": "", "enable": False},
        {"name": "XuanXingNieHe", "label": "玄星逆核·聚合逆向", "url": "http://127.0.0.1:8000/mcp", "token": "", "enable": False},
        {"name": "ProxyPinMcp", "label": "ProxyPin·抓包分析", "url": "http://127.0.0.1:9010/mcp", "token": "", "enable": False},
    ]

    PROBE_PORTS = {
        "MTApkMcp": [8787, 8788, 8080, 9999],
        "XuanXingNieHe": [8000, 8001, 8080, 9000],
        "ProxyPinMcp": [9010, 9011, 9020],
    }

    _config_path = os.path.expanduser("~/.apk_reverse_engine/mcp_config.json")

    @classmethod
    def _load(cls):
        try:
            with open(cls._config_path, "r") as f:
                return json.load(f)
        except Exception:
            return [dict(s) for s in cls.DEFAULT_SERVERS]

    @classmethod
    def get_servers(cls) -> list:
        return cls._load()

    @classmethod
    def save_servers(cls, servers: list):
        os.makedirs(os.path.dirname(cls._config_path), exist_ok=True)
        with open(cls._config_path, "w") as f:
            json.dump(servers, f, ensure_ascii=False, indent=2)

    @classmethod
    def find_server(cls, name: str) -> dict:
        for s in cls.get_servers():
            if s.get("name") == name:
                return s
        return None

    @classmethod
    def enabled_count(cls) -> int:
        return sum(1 for s in cls.get_servers() if s.get("enable"))

    @classmethod
    def enabled_servers(cls) -> list:
        return [s for s in cls.get_servers() if s.get("enable")]