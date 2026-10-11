"""Regression coverage for rejection delivery and concurrent JSON-RPC calls."""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from shieldmcp.core.config import ShieldMCPConfig
from shieldmcp.core.models import Action
from shieldmcp.core.pipeline import ShieldPipeline
from shieldmcp.proxy.interceptor import StdioProxy, _encode_frame, _read_jsonrpc_messages
from shieldmcp.proxy.sse_proxy import SSEProxy, _SSESession


@pytest.mark.asyncio
@pytest.mark.parametrize("framing", ["line", "lsp"])
async def test_blocked_stdio_call_replies_to_client_without_reaching_backend(tmp_path, framing):
    """Exercise real process pipes: a local rejection must reach the caller."""
    received = tmp_path / "backend_received.json"
    backend = tmp_path / "backend.py"
    backend.write_text(
        "import json, sys\n"
        "from pathlib import Path\n"
        "for line in sys.stdin:\n"
        f"    Path({str(received)!r}).write_text(line)\n"
        "    msg = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': msg.get('id'), "
        "'result': {'content': [{'type': 'text', 'text': 'backend ran'}]}}), flush=True)\n"
    )
    launcher = (
        "import asyncio, sys\n"
        "from shieldmcp.core.config import ShieldMCPConfig\n"
        "from shieldmcp.proxy.interceptor import StdioProxy\n"
        "config = ShieldMCPConfig()\n"
        f"config.registry_db_path = {str(tmp_path / 'registry.db')!r}\n"
        "config.alerts.log_all_alerts = False\n"
        f"asyncio.run(StdioProxy([sys.executable, {str(backend)!r}], config).start())\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-c", launcher, env=env, cwd=tmp_path,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    request = {
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "query", "arguments": {
            "sql": "SELECT * FROM users; DROP TABLE users; --",
        }},
    }
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(_encode_frame(request, framing)), timeout=10,
        )
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    assert process.returncode == 0, stderr.decode()
    reader = asyncio.StreamReader()
    reader.feed_data(stdout)
    reader.feed_eof()
    replies = [reply async for reply in _read_jsonrpc_messages(reader)]
    assert len(replies) == 1
    reply, reply_framing = replies[0]
    assert reply_framing == framing
    assert reply["id"] == 7
    assert "ShieldMCP blocked this call" in reply["error"]["message"]
    assert not received.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["stdio", "sse"])
async def test_out_of_order_tool_responses_keep_their_request_tool(transport):
    config = ShieldMCPConfig()
    config.alerts.log_all_alerts = False
    if transport == "stdio":
        proxy = StdioProxy([], config)
        send = proxy._intercept_client_message
        receive = proxy._intercept_server_message
        pending = proxy._pending_tool_calls
    else:
        proxy = SSEProxy("http://localhost", config)
        session = _SSESession("session", web.StreamResponse())

        async def send(msg):
            return await proxy._intercept_client_message(msg, session)

        async def receive(msg):
            return await proxy._intercept_server_message(msg, session)

        pending = session.pending_tool_calls

    proxy.pipeline.process_tool_call = AsyncMock(return_value=(Action.PASS, []))
    proxy.pipeline.process_tool_response = AsyncMock(return_value=(Action.PASS, "clean", []))
    for request_id, name in [(1, "read_file"), (2, "search")]:
        await send({
            "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": name, "arguments": {}},
        })
    for request_id in [2, 1]:
        await receive({"jsonrpc": "2.0", "id": request_id, "result": {"content": "ok"}})
    assert [call.args[1] for call in proxy.pipeline.process_tool_response.await_args_list] == [
        "search", "read_file",
    ]
    assert not pending

    await send({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {}},
    })
    await receive({"jsonrpc": "2.0", "id": 3, "error": {"code": -1, "message": "failed"}})
    assert not pending


@pytest.mark.asyncio
async def test_new_tools_are_withheld_when_quarantine_is_enabled(tmp_path):
    config = ShieldMCPConfig()
    config.registry_db_path = str(tmp_path / "registry.db")
    config.alerts.log_all_alerts = False
    config.stage1.quarantine_on_new_tools = True
    pipeline = ShieldPipeline(config)
    await pipeline.initialize()
    try:
        action, visible, alerts = await pipeline.validate_tools("server", [{
            "name": "get_weather", "description": "Returns the weather for a city.",
            "inputSchema": {"type": "object", "properties": {}},
        }])
        assert action == Action.QUARANTINE
        assert not visible
        assert alerts[0].action == Action.QUARANTINE
    finally:
        await pipeline.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["stdio", "sse"])
async def test_quarantined_calls_and_responses_are_rejected(transport):
    config = ShieldMCPConfig()
    config.alerts.log_all_alerts = False
    if transport == "stdio":
        proxy = StdioProxy([], config)
        send = proxy._intercept_client_message
        receive = proxy._intercept_server_message
    else:
        proxy = SSEProxy("http://localhost", config)
        session = _SSESession("session", web.StreamResponse())

        async def send(msg):
            return await proxy._intercept_client_message(msg, session)

        async def receive(msg):
            return await proxy._intercept_server_message(msg, session)

    proxy.pipeline.process_tool_call = AsyncMock(return_value=(Action.QUARANTINE, []))
    rejected = await send({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "query", "arguments": {}},
    })
    assert rejected["id"] == 4
    assert "error" in rejected
    proxy.pipeline.process_tool_response = AsyncMock(
        return_value=(Action.QUARANTINE, "sensitive payload", []),
    )
    rejected = await receive({
        "jsonrpc": "2.0", "id": 5, "result": {"content": "sensitive payload"},
    })
    assert rejected["id"] == 5
    assert "error" in rejected
    assert "result" not in rejected
