import asyncio
import json

from supervisor_client import SupervisorClient
from supervisor_process import SupervisorProcess

CASES = {
    "basic":         "return 1 + 1",
    "tools+logs":    "const a = await tools.add(2, 3); const b = await tools.multiply(a, 10); console.log('hi', a); return {a, b};",
    "div by zero":   "return await tools.divide(1, 0)",
    "bad args":      "return await tools.add('x', 1)",
    "no globals":    "return [typeof require, typeof process, typeof fetch, typeof tools.hack]",
    "infinite loop": "while (true) {}",
    "memory bomb":   "const a = []; while (true) a.push(new Array(1e6).fill(1));",
    "syntax error":  "return (",
    "tool budget":   "for (let i = 0; i < 150; i++) await tools.add(1, 1); return 'done'",
}


async def main():
    sup = SupervisorProcess()
    await sup.start()
    c = SupervisorClient(sup.socket_path)
    try:
        names = list(CASES)
        results = await asyncio.gather(*[c.execute(CASES[n], 3000) for n in names])
        for n, r in zip(names, results):
            r.pop("id", None)
            r.pop("type", None)
            print(f"{n:14} -> {json.dumps(r)[:200]}")

        print("\n50 concurrent tool-call executions...")
        code = "let s = 0; for (let i = 0; i < 20; i++) s = await tools.add(s, i); return s;"
        rs = await asyncio.gather(*[c.execute(code, 5000) for _ in range(50)])
        ok = sum(1 for r in rs if r.get("ok") and r.get("value") == 190)
        busy = sum(1 for r in rs if r.get("error") in ("executor busy", "server busy"))
        print(f"ok={ok} busy/rejected={busy} other={50 - ok - busy}")
    finally:
        await c.close()
        await sup.stop()


asyncio.run(main())