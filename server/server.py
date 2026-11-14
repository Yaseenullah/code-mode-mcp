import asyncio
import os
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer
from supervisor_client import SupervisorClient
from supervisor_process import SupervisorProcess

supervisor = SupervisorProcess()
client = SupervisorClient(supervisor.socket_path)


@asynccontextmanager
async def lifespan(server: MCPServer):
    await supervisor.start()   # launches the Rust binary and waits until the executor is ready
    try:
        yield {}
    finally:
        await client.close()
        await supervisor.stop()


mcp = MCPServer("code-mode", version="0.1.0", lifespan=lifespan)


@mcp.tool()
async def run_code(code: str, timeout_ms: int = 5000) -> dict:
    """Execute JavaScript in a sandboxed V8 isolate.

    The code body is wrapped in an async function: use `await`, and `return` a
    JSON-serializable value as the result. console.log output is captured in `logs`.

    Available async tools (numbers only):
      await tools.add(a, b)
      await tools.subtract(a, b)
      await tools.multiply(a, b)
      await tools.divide(a, b)

    There is no require/process/fetch/filesystem/network access.
    Example: const x = await tools.add(2, 3); return await tools.multiply(x, 10);
    """
    if not code.strip():
        return {"ok": False, "error": "code is empty"}
    if len(code) > 100_000:
        return {"ok": False, "error": "code too large"}
    timeout_ms = max(100, min(int(timeout_ms), 30_000))

    try:
        res = await client.execute(code, timeout_ms)
    except (OSError, asyncio.TimeoutError) as e:
        return {"ok": False, "error": f"supervisor unavailable: {e}"}
    res.pop("id", None)
    res.pop("type", None)
    return res


if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(
            transport="streamable-http",
            host=os.environ.get("MCP_HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8000")),
            streamable_http_path="/mcp",
            stateless_http=True,
            json_response=True,
        )