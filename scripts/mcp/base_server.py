"""Small dependency-free ASGI surface for public Python policy tools."""
from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]


class MCPBaseServer:
    def __init__(self, name: str) -> None:
        self.name = name
        self.tools: dict[str, RegisteredTool] = {}
        self.app = self

    def register_tool(
        self, name: str, description: str, input_schema: dict[str, Any]
    ) -> Callable[[Callable[[dict[str, Any]], Any]], Callable[[dict[str, Any]], Any]]:
        def decorator(handler: Callable[[dict[str, Any]], Any]) -> Callable[[dict[str, Any]], Any]:
            if name in self.tools:
                raise ValueError(f"duplicate tool: {name}")
            self.tools[name] = RegisteredTool(name, description, input_schema, handler)
            return handler

        return decorator

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            return
        method = scope.get("method", "GET").upper()
        path = scope.get("path", "/")
        if method == "GET" and path == "/health":
            await self._respond(send, 200, {"ok": True, "name": self.name})
            return
        if method == "GET" and path == "/tools/list":
            tools = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                }
                for tool in self.tools.values()
            ]
            await self._respond(send, 200, {"ok": True, "tools": tools})
            return
        if method == "POST" and path == "/tools/call":
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            try:
                payload = json.loads(body or b"{}")
                name = str(payload.get("name", ""))
                tool = self.tools.get(name)
                if tool is None:
                    await self._respond(send, 404, {"ok": False, "error": "unknown_tool"})
                    return
                result = tool.handler(payload.get("arguments") or {})
                if inspect.isawaitable(result):
                    result = await result
                await self._respond(send, 200, {"ok": True, "name": name, "result": result})
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                await self._respond(send, 400, {"ok": False, "error": str(error)})
            return
        await self._respond(send, 404, {"ok": False, "error": "not_found"})

    @staticmethod
    async def _respond(send: Any, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json; charset=utf-8")],
            }
        )
        await send({"type": "http.response.body", "body": body})
