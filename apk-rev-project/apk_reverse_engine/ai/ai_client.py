"""AI 客户端 - OpenAI 兼容 API 流式请求 + function calling"""
import json
import requests
from typing import Callable, Optional

class AiClient:
    """OpenAI Chat Completions 流式客户端，支持 tool_calls"""

    @staticmethod
    def build_endpoint(base_url: str) -> str:
        if not base_url:
            return "https://api.openai.com/v1/chat/completions"
        url = base_url.strip()
        if url.endswith("/chat/completions"):
            return url
        url = url.rstrip("/")
        if url.endswith("/v1"):
            return url + "/chat/completions"
        return url + "/v1/chat/completions"

    @staticmethod
    def stream(system: str, user: str, on_delta: Callable = None, on_done: Callable = None,
               on_error: Callable = None, tools: list = None) -> str:
        """简单流式请求（system + user），返回完整文本"""
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        return AiClient.complete(messages, tools, on_delta, on_done, on_error)

    @staticmethod
    def complete(messages: list, tools: list = None,
                 on_delta: Callable = None, on_done: Callable = None,
                 on_error: Callable = None) -> str:
        """
        完整流式请求，支持 function calling。
        返回完整文本。如果有 tool_calls，on_done 会收到 None 而非文本。
        """
        from .ai_setting import AiSetting

        endpoint = AiClient.build_endpoint(AiSetting.base_url())
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }
        key = AiSetting.api_key()
        if key:
            headers["Authorization"] = f"Bearer {key}"

        body = {
            "model": AiSetting.model(),
            "stream": True,
            "temperature": 0.2,
            "max_tokens": AiSetting.max_tokens(),
            "messages": messages,
        }
        if tools:
            body["tools"] = tools

        full_text = []
        tool_calls = {}

        try:
            resp = requests.post(
                endpoint, headers=headers, json=body,
                stream=True, timeout=AiSetting.timeout()
            )
            if resp.status_code >= 400:
                err = resp.text
                if on_error:
                    on_error(Exception(f"HTTP {resp.status_code}: {err}"))
                return ""
            for line in resp.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data or data == "[DONE]":
                    continue
                try:
                    obj = json.loads(data)
                    choices = obj.get("choices", [])
                    if not choices:
                        continue
                    ch = choices[0]
                    delta = ch.get("delta", {})
                    if delta:
                        content = delta.get("content", "")
                        if content:
                            full_text.append(content)
                            if on_delta:
                                on_delta(content)
                        tcs = delta.get("tool_calls", [])
                        for tc in tcs:
                            idx = tc.get("index", 0)
                            if idx not in tool_calls:
                                tool_calls[idx] = {
                                    "id": tc.get("id", ""),
                                    "type": "function",
                                    "function": {"name": "", "arguments": ""}
                                }
                            fn = tc.get("function", {})
                            if fn.get("name"):
                                tool_calls[idx]["function"]["name"] = fn["name"]
                            if fn.get("arguments"):
                                tool_calls[idx]["function"]["arguments"] += fn["arguments"]
                    msg = ch.get("message", {})
                    if msg:
                        content = msg.get("content", "")
                        if content:
                            full_text.append(content)
                            if on_delta:
                                on_delta(content)
                        tcs = msg.get("tool_calls", [])
                        for tc in tcs:
                            idx = tc.get("index", 0)
                            tool_calls[idx] = {
                                "id": tc.get("id", ""),
                                "type": "function",
                                "function": {
                                    "name": tc.get("function", {}).get("name", ""),
                                    "arguments": tc.get("function", {}).get("arguments", "")
                                }
                            }
                    if ch.get("finish_reason"):
                        break
                except Exception:
                    continue
            text = "".join(full_text)
            if tool_calls:
                tc_list = [tool_calls[k] for k in sorted(tool_calls.keys())]
                # 回调由 AiSession 处理
                if on_done:
                    on_done(None)  # 表示有 tool_calls
                return tc_list  # type: ignore
            else:
                if on_done:
                    on_done(text)
                return text
        except Exception as e:
            if on_error:
                on_error(e)
            return ""