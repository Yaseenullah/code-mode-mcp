import asyncio
import os
import shutil
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
READY_TIMEOUT_S = 20.0


class SupervisorProcess:
    """Starts, watches (restarts on crash) and stops the Rust supervisor."""

    def __init__(self, binary=None, executor_js=None, socket_path=None,
                 sandbox=None, max_concurrent=None, node_bin=None):
        self.binary = Path(
            binary or os.environ.get("SUPERVISOR_BIN")
            or ROOT / "supervisor" / "target" / "release" / "supervisor"
        )
        self.executor_js = Path(
            executor_js or os.environ.get("EXECUTOR_JS") or ROOT / "executor" / "executor.js"
        )
        self.socket_path = socket_path or os.environ.get("SUPERVISOR_SOCKET", "/tmp/mcp-supervisor.sock")
        self.sandbox = sandbox or os.environ.get("SANDBOX", "full")
        self.max_concurrent = str(max_concurrent or os.environ.get("MAX_CONCURRENT", "8"))
        self.node_bin = node_bin or os.environ.get("NODE_BIN") or shutil.which("node")

        self._proc = None
        self._monitor_task = None
        self._pump_task = None
        self._stopping = False

    @staticmethod
    def _log(msg: str):
        # fd 2 only: in stdio mode stdout is the MCP protocol channel.
        os.write(2, f"[supervisor-launcher] {msg}\n".encode())

    async def start(self):
        if not self.binary.exists():
            raise FileNotFoundError(
                f"Supervisor binary not found at {self.binary}. "
                "Build it first: cd supervisor && cargo build --release"
            )
        if not self.node_bin:
            raise FileNotFoundError("`node` not found on PATH. Install Node 20+ or set NODE_BIN.")
        if not self.executor_js.exists():
            raise FileNotFoundError(f"executor.js not found at {self.executor_js}")

        await self._spawn()
        self._monitor_task = asyncio.create_task(self._monitor())

    async def _spawn(self):
        env = {
            **os.environ,
            "SOCKET_PATH": self.socket_path,
            "NODE_BIN": self.node_bin,
            "EXECUTOR_JS": str(self.executor_js),
            "SANDBOX": self.sandbox,
            "MAX_CONCURRENT": self.max_concurrent,
        }
        proc = await asyncio.create_subprocess_exec(
            str(self.binary),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self._proc = proc
        ready = asyncio.Event()
        self._pump_task = asyncio.create_task(self._pump_stderr(proc, ready))

        deadline = time.monotonic() + READY_TIMEOUT_S
        while not ready.is_set():
            if proc.returncode is not None:
                raise RuntimeError(
                    f"supervisor exited during startup (code {proc.returncode}); see messages above"
                )
            if time.monotonic() > deadline:
                proc.kill()
                await proc.wait()
                raise RuntimeError("supervisor did not become ready in time; see messages above")
            try:
                await asyncio.wait_for(ready.wait(), 0.2)
            except asyncio.TimeoutError:
                pass
        self._log(f"supervisor ready (pid {proc.pid})")

    async def _pump_stderr(self, proc, ready: asyncio.Event):
        tail = b""
        while True:
            chunk = await proc.stderr.read(4096)
            if not chunk:
                break
            os.write(2, chunk)
            tail = (tail + chunk)[-512:]
            if b"executor ready" in tail:
                ready.set()

    async def _monitor(self):
        backoff = 0.5
        while True:
            await self._proc.wait()
            if self._stopping:
                return
            self._log(f"supervisor exited (code {self._proc.returncode}); restarting in {backoff:.1f}s")
            await asyncio.sleep(backoff)
            if self._stopping:
                return
            try:
                await self._spawn()
                backoff = 0.5
            except Exception as e:
                self._log(f"restart failed: {e}")
                backoff = min(backoff * 2, 10.0)

    async def stop(self):
        self._stopping = True
        if self._monitor_task:
            self._monitor_task.cancel()
        proc = self._proc
        if proc is not None and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), 5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        if self._pump_task:
            self._pump_task.cancel()
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass