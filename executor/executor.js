'use strict';
const ivm = require('isolated-vm');
const readline = require('readline');

const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT || '8', 10);
const MEMORY_LIMIT_MB = 64;           // per isolate
const MAX_LOG_BYTES = 64 * 1024;
const MAX_RESULT_BYTES = 1024 * 1024;
const TOOLS = new Set(['add', 'subtract', 'multiply', 'divide']);

// stdout is the protocol channel to the Rust supervisor. Never console.log() on the host.
const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');

const active = new Map();        // exec id -> { cancel }
const toolWaiters = new Map();   // call id -> { resolve, reject, execId }
let nextCallId = 1;

function callTool(execId, tool, args) {
  return new Promise((resolve, reject) => {
    const callId = nextCallId++;
    toolWaiters.set(callId, { resolve, reject, execId });
    send({ type: 'tool_call', id: execId, call_id: callId, tool, args });
  });
}

// Runs inside each fresh isolate. Captures the privileged references, then deletes them
// from the global scope so user code can't reach them directly.
const BOOTSTRAP = `
(function () {
  const log = __log;
  const tool = __tool;
  delete globalThis.__log;
  delete globalThis.__tool;

  const fmt = (x) => {
    if (typeof x === 'string') return x;
    try { const s = JSON.stringify(x); return s === undefined ? String(x) : s; }
    catch (e) { return String(x); }
  };
  const mk = () => (...a) => { log(a.map(fmt).join(' ')); };
  globalThis.console = { log: mk(), info: mk(), warn: mk(), error: mk() };

  const call = (name, args) =>
    tool.apply(undefined, [name, JSON.stringify(args)], {
      arguments: { copy: true },
      result: { promise: true, copy: true },
    }).then(JSON.parse);

  globalThis.tools = Object.freeze({
    add:      (a, b) => call('add',      { a, b }),
    subtract: (a, b) => call('subtract', { a, b }),
    multiply: (a, b) => call('multiply', { a, b }),
    divide:   (a, b) => call('divide',   { a, b }),
  });
})();
`;

async function runExec(id, code, timeoutMs) {
  const logs = [];
  let logBytes = 0;
  let timer;
  let disposed = false;

  // A fresh isolate per execution: no state leaks between runs.
  const isolate = new ivm.Isolate({ memoryLimit: MEMORY_LIMIT_MB });
  const dispose = () => {
    if (!disposed) {
      disposed = true;
      try { isolate.dispose(); } catch (_) {}
    }
  };

  let cancelFn;
  const cancelPromise = new Promise((_, rej) => {
    cancelFn = () => rej(new Error('Execution cancelled'));
  });
  cancelPromise.catch(() => {});
  active.set(id, { cancel: cancelFn });

  let response;
  try {
    const context = await isolate.createContext();
    const jail = context.global;

    await jail.set('__log', new ivm.Callback((s) => {
      if (logBytes >= MAX_LOG_BYTES) return;
      const line = String(s).slice(0, 4096);
      logBytes += line.length;
      logs.push(line);
    }));

    await jail.set('__tool', new ivm.Reference(async (name, argsJson) => {
      if (!TOOLS.has(name)) throw new Error('unknown tool: ' + name);
      const args = JSON.parse(argsJson);
      const value = await callTool(id, name, args);
      return JSON.stringify(value);
    }));

    await context.eval(BOOTSTRAP);

    const wrapped =
      '(async () => { const __r = await (async () => {\n' + code +
      '\n})(); return __r === undefined ? "null" : JSON.stringify(__r); })()';

    const timeoutPromise = new Promise((_, rej) => {
      timer = setTimeout(() => rej(new Error('Execution timed out')), timeoutMs);
    });
    timeoutPromise.catch(() => {});

    const run = context.eval(wrapped, { timeout: timeoutMs, promise: true, copy: true });
    run.catch(() => {}); // avoid unhandled rejection after dispose

    const out = await Promise.race([run, timeoutPromise, cancelPromise]);

    if (typeof out !== 'string') throw new Error('Result is not serializable');
    if (out.length > MAX_RESULT_BYTES) throw new Error('Result too large');
    response = { ok: true, value: JSON.parse(out) };
  } catch (err) {
    response = { ok: false, error: err && err.message ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
    dispose();
    active.delete(id);
    for (const [cid, w] of toolWaiters) {
      if (w.execId === id) toolWaiters.delete(cid);
    }
  }
  send({ type: 'result', id, logs, ...response });
}

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  let m;
  try { m = JSON.parse(line); } catch { return; }

  switch (m.type) {
    case 'exec':
      if (active.size >= MAX_CONCURRENT) {
        send({ type: 'result', id: m.id, ok: false, error: 'executor busy', logs: [] });
        return;
      }
      runExec(m.id, String(m.code), Number(m.timeout_ms) || 5000).catch((e) => {
        send({ type: 'result', id: m.id, ok: false, error: String(e), logs: [] });
      });
      break;
    case 'cancel': {
      const a = active.get(m.id);
      if (a) a.cancel();
      break;
    }
    case 'tool_result': {
      const w = toolWaiters.get(m.call_id);
      if (!w) return;
      toolWaiters.delete(m.call_id);
      if (m.ok) w.resolve(m.value);
      else w.reject(new Error(m.error || 'tool error'));
      break;
    }
  }
});
rl.on('close', () => process.exit(0));

process.on('unhandledRejection', (e) => console.error('[executor] unhandledRejection', e));
process.on('uncaughtException', (e) => { console.error('[executor] fatal', e); process.exit(1); });

send({ type: 'ready' });