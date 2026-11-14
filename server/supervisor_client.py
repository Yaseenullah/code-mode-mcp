import asyncio
import json
import uuid
from typing import Any, Awaitable, Callable

from tools import ToolError, call_tool

ToolHandler = Callable[[Any, Any], Awaitable[Any]]
TOOL_TIMEOUT_S = 8.0  # Rust enforces its own, slightly longer, limit too


class SupervisorClient:
    """Async, multiplexed client for the Rust supervisor (newline-delimited JSON over a Unix socket).

    Python owns the execution ids and the tools: the supervisor sends `tool_call`
    messages back over the same connection and this class answers them.
    """

    def __init__(self, path: str, tool_handler: ToolHandler = call_tool):
        self.path = path
        self._tool_handler = tool_handler
        self._reader = None
        self._writer = None
        self._pending: dict[str, asyncio.Future] = {}
        self._tasks: set[asyncio.Task] = set()
        self._connect_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    async def _ensure(self):
        async with self._connect_lock:
            if self._writer is not None and not self._writer.is_closing():
                return
            reader, writer = await asyncio.open_unix_connection(self.path, limit=16 * 1024 * 1024)
            self._reader, self._writer = reader, writer
            task = asyncio.create_task(self._read_loop(reader))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _send(self, obj: dict):
        data = (json.dumps(obj, allow_nan=False) + "\n").encode()
        async with self._write_lock:
            w = self._writer
            if w is None or w.is_closing():
                raise ConnectionError("not connected to supervisor")
            w.write(data)
            await w.drain()

    async def _read_loop(self, reader):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                kind = msg.get("type")
                if kind == "result":
                    fut = self._pending.pop(msg.get("id"), None)
                    if fut and not fut.done():
                        fut.set_result(msg)
                elif kind == "tool_call":
                    task = asyncio.create_task(self._handle_tool_call(msg))
                    self._tasks.add(task)
                    task.add_done_callback(self._tasks.discard)
        except Exception:
            pass
        finally:
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(ConnectionError("supervisor connection lost"))
            self._pending.clear()
            if self._reader is reader and self._writer is not None:
                self._writer.close()

    async def _handle_tool_call(self, msg: dict):
        base = {"type": "tool_result", "id": msg.get("id"), "call_id": msg.get("call_id")}
        try:
            value = await asyncio.wait_for(
                self._tool_handler(msg.get("tool"), msg.get("args")), TOOL_TIMEOUT_S
            )
            reply = {**base, "ok": True, "value": value}
        except ToolError as e:
            reply = {**base, "ok": False, "error": str(e)}
        except asyncio.TimeoutError:
            reply = {**base, "ok": False, "error": "tool timed out"}
        except Exception:
            reply = {**base, "ok": False, "error": "internal tool error"}

        try:
            await self._send(reply)
        except ValueError:  # result not JSON-serializable (e.g. NaN)
            try:
                await self._send({**base, "ok": False, "error": "tool returned an invalid value"})
            except OSError:
                pass
        except OSError:
            pass  # connection gone; supervisor cancels the execution itself

    async def execute(self, code: str, timeout_ms: int = 5000) -> dict:
        await self._ensure()
        rid = uuid.uuid4().hex  # this id is used end to end, including inside Rust
        fut = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        try:
            await self._send({"type": "exec", "id": rid, "code": code, "timeout_ms": timeout_ms})
            return await asyncio.wait_for(fut, timeout=timeout_ms / 1000 + 10)
        finally:
            self._pending.pop(rid, None)

    async def close(self):
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass