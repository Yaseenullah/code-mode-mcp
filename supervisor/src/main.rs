use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
    os::unix::fs::PermissionsExt,
    process::Stdio,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{mpsc, oneshot, Mutex, Semaphore},
    time::{sleep, timeout},
};

// ───────────────────────── config ─────────────────────────

struct Config {
    socket_path: String,
    node_bin: String,
    executor_js: String,
    max_concurrent: usize,
    default_timeout_ms: u64,
    max_timeout_ms: u64,
    max_code_bytes: usize,
    max_tool_calls: u32,
    tool_timeout_ms: u64,
    sandbox: String, // "full" (namespaces + seccomp) | "seccomp" | "off"
}

fn env_or<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

impl Config {
    fn from_env() -> Self {
        Config {
            socket_path: env_or("SOCKET_PATH", "/tmp/mcp-supervisor.sock".to_string()),
            node_bin: env_or("NODE_BIN", "node".to_string()),
            executor_js: env_or("EXECUTOR_JS", "../executor/executor.js".to_string()),
            max_concurrent: env_or("MAX_CONCURRENT", 8usize),
            default_timeout_ms: env_or("DEFAULT_TIMEOUT_MS", 5_000u64),
            max_timeout_ms: env_or("MAX_TIMEOUT_MS", 30_000u64),
            max_code_bytes: env_or("MAX_CODE_BYTES", 100_000usize),
            max_tool_calls: env_or("MAX_TOOL_CALLS", 100u32),
            tool_timeout_ms: env_or("TOOL_TIMEOUT_MS", 10_000u64),
            sandbox: env_or("SANDBOX", "full".to_string()),
        }
    }
}

// ───────────────────────── shared state ─────────────────────────

struct Pending {
    tx: oneshot::Sender<Value>,
    calls: u32,
    client: mpsc::UnboundedSender<String>, // where tool_call messages for this execution go
}

struct ToolCall {
    exec_id: String,
    serial: u64, // guards against stale timers after an executor restart reuses call ids
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,   // keyed by the id Python generated
    tool_calls: HashMap<u64, ToolCall>,  // executor call_id -> owner
}

struct Shared {
    state: Mutex<State>,
    exec_tx: Mutex<Option<mpsc::UnboundedSender<String>>>,
    serial: AtomicU64,
}

fn tool_error(call_id: u64, reason: &str) -> String {
    json!({"type": "tool_result", "call_id": call_id, "ok": false, "error": reason}).to_string()
}

/// Drop an execution: fail its waiter, forget its tool calls, tell the executor to cancel.
async fn abort_exec(shared: &Arc<Shared>, id: &str, reason: &str) {
    let p = {
        let mut st = shared.state.lock().await;
        st.tool_calls.retain(|_, tc| tc.exec_id != id);
        st.pending.remove(id)
    };
    if let Some(p) = p {
        let _ = p.tx.send(json!({"ok": false, "error": reason, "logs": []}));
        if let Some(s) = shared.exec_tx.lock().await.clone() {
            let _ = s.send(json!({"type": "cancel", "id": id}).to_string());
        }
    }
}

// ───────────────────────── sandbox (runs in the forked child, before exec) ─────────────────────────

fn build_seccomp() -> Result<BpfProgram> {
    // Deny-list: block syscalls an executor never legitimately needs.
    let denied: Vec<i64> = vec![
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_acct,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
    ];
    let rules: BTreeMap<i64, Vec<SeccompRule>> =
        denied.into_iter().map(|s| (s, vec![])).collect();

    let arch: seccompiler::TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| anyhow!("unsupported arch: {e:?}"))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| anyhow!("seccomp filter: {e:?}"))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| anyhow!("seccomp compile: {e:?}"))?;
    Ok(prog)
}

macro_rules! rlim {
    ($res:expr, $val:expr) => {{
        let l = libc::rlimit { rlim_cur: $val, rlim_max: $val };
        if libc::setrlimit($res, &l) != 0 {
            return Err(io::Error::last_os_error());
        }
    }};
}

fn sandbox_child(use_ns: bool, prog: &BpfProgram) -> io::Result<()> {
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0);

        if use_ns {
            let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
            if libc::unshare(flags) != 0 {
                return Err(io::Error::last_os_error());
            }
            
    eprintln!("[sandbox] namespaces created successfully");
}


        rlim!(libc::RLIMIT_CORE, 0);
        rlim!(libc::RLIMIT_NOFILE, 512);
        rlim!(libc::RLIMIT_FSIZE, 1_048_576);
        eprintln!("[sandbox] resource limits applied");
    }
    seccompiler::apply_filter(prog).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    eprintln!("[sandbox] applying seccomp filter");

    Ok(())
}


// ───────────────────────── executor lifecycle ─────────────────────────

async fn run_executor(shared: &Arc<Shared>, cfg: &Arc<Config>) -> Result<()> {
    let mut cmd = Command::new(&cfg.node_bin);
    cmd.arg("--no-node-snapshot")
        .arg("--max-old-space-size=512")
        .arg(&cfg.executor_js)
        .env_clear()
        .env("MAX_CONCURRENT", cfg.max_concurrent.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    if cfg.sandbox != "off" {
        let use_ns = cfg.sandbox == "full";
        let prog = build_seccomp()?;
        unsafe {
            cmd.pre_exec(move || sandbox_child(use_ns, &prog));
        }
    }

    let mut child = cmd.spawn()?;
    let stdin = child.stdin.take().ok_or_else(|| anyhow!("no executor stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no executor stdout"))?;

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        let mut stdin = stdin;
        while let Some(line) = rx.recv().await {
            if stdin.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if stdin.write_all(b"\n").await.is_err() {
                break;
            }
        }
    });

    let mut lines = BufReader::new(stdout).lines();

    match timeout(Duration::from_secs(10), lines.next_line()).await {
        Ok(Ok(Some(l))) if l.contains("\"ready\"") => {}
        other => {
            writer.abort();
            return Err(anyhow!("executor did not become ready: {:?}", other));
        }
    }

    *shared.exec_tx.lock().await = Some(tx.clone());
    // The Python launcher waits for this exact phrase.
    eprintln!("[supervisor] executor ready (pid {:?}, sandbox={})", child.id(), cfg.sandbox);

    while let Some(line) = lines.next_line().await? {
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match msg["type"].as_str() {
            Some("result") => {
                let id = msg["id"].as_str().map(str::to_string);
                if let Some(id) = id {
                    let p = {
                        let mut st = shared.state.lock().await;
                        st.tool_calls.retain(|_, tc| tc.exec_id != id);
                        st.pending.remove(&id)
                    };
                    if let Some(p) = p {
                        let _ = p.tx.send(msg);
                    }
                }
            }
            Some("tool_call") => {
                let id = msg["id"].as_str().unwrap_or("").to_string();
                let call_id = msg["call_id"].as_u64().unwrap_or(0);
                let tool = msg["tool"].as_str().unwrap_or("").to_string();

                // Relay to the Python client that owns this execution. Rust does not
                // know what any tool does; it only enforces budget and timeouts.
                let outcome: Result<u64, String> = {
                    let mut guard = shared.state.lock().await;
                    let st = &mut *guard;
                    match st.pending.get_mut(&id) {
                        None => Err("execution no longer active".to_string()),
                        Some(p) => {
                            p.calls += 1;
                            if p.calls > cfg.max_tool_calls {
                                Err("tool call budget exceeded".to_string())
                            } else if tool.is_empty() || tool.len() > 64 {
                                Err("invalid tool name".to_string())
                            } else {
                                let out = json!({
                                    "type": "tool_call",
                                    "id": id,
                                    "call_id": call_id,
                                    "tool": tool,
                                    "args": msg["args"],
                                });
                                if p.client.send(out.to_string()).is_err() {
                                    Err("client disconnected".to_string())
                                } else {
                                    let serial = shared.serial.fetch_add(1, Ordering::SeqCst);
                                    st.tool_calls.insert(call_id, ToolCall { exec_id: id.clone(), serial });
                                    Ok(serial)
                                }
                            }
                        }
                    }
                };

                match outcome {
                    Ok(serial) => {
                        let (shared2, tx2, tmo) = (shared.clone(), tx.clone(), cfg.tool_timeout_ms);
                        tokio::spawn(async move {
                            sleep(Duration::from_millis(tmo)).await;
                            let expired = {
                                let mut st = shared2.state.lock().await;
                                let hit = st
                                    .tool_calls
                                    .get(&call_id)
                                    .map(|tc| tc.serial == serial)
                                    .unwrap_or(false);
                                if hit {
                                    st.tool_calls.remove(&call_id);
                                }
                                hit
                            };
                            if expired {
                                let _ = tx2.send(tool_error(call_id, "tool call timed out"));
                            }
                        });
                    }
                    Err(reason) => {
                        let _ = tx.send(tool_error(call_id, &reason));
                    }
                }
            }
            _ => {}
        }
    }

    writer.abort();
    let _ = child.kill().await;
    Ok(())
}

async fn executor_manager(shared: Arc<Shared>, cfg: Arc<Config>) {
    let mut backoff = Duration::from_millis(200);
    loop {
        let started = Instant::now();
        match run_executor(&shared, &cfg).await {
            Ok(()) => eprintln!("[supervisor] executor exited"),
            Err(e) => eprintln!("[supervisor] executor error: {e:#}"),
        }

        *shared.exec_tx.lock().await = None;
        {
            let mut st = shared.state.lock().await;
            st.tool_calls.clear();
            for (_, p) in st.pending.drain() {
                let _ = p.tx.send(json!({"ok": false, "error": "executor crashed", "logs": []}));
            }
        }

        if started.elapsed() > Duration::from_secs(10) {
            backoff = Duration::from_millis(200);
        }
        sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

// ───────────────────────── client (Python) side ─────────────────────────

#[derive(Deserialize)]
struct ClientReq {
    id: String,
    code: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

fn err_resp(id: &str, msg: &str) -> Value {
    json!({"type": "result", "id": id, "ok": false, "error": msg, "logs": []})
}

async fn run_request(
    req: ClientReq,
    shared: Arc<Shared>,
    cfg: Arc<Config>,
    sem: Arc<Semaphore>,
    client_tx: mpsc::UnboundedSender<String>,
) -> Value {
    let id = req.id.clone();
    if id.is_empty() || id.len() > 128 {
        return err_resp(&id, "invalid id");
    }
    if req.code.len() > cfg.max_code_bytes {
        return err_resp(&id, "code too large");
    }
    let tmo = req.timeout_ms.unwrap_or(cfg.default_timeout_ms).clamp(1, cfg.max_timeout_ms);

    let permit = match timeout(Duration::from_secs(5), sem.acquire_owned()).await {
        Ok(Ok(p)) => p,
        _ => return err_resp(&id, "server busy"),
    };

    let sender = match shared.exec_tx.lock().await.clone() {
        Some(s) => s,
        None => return err_resp(&id, "executor unavailable"),
    };

    let (tx, rx) = oneshot::channel();
    {
        let mut st = shared.state.lock().await;
        if st.pending.contains_key(&id) {
            return err_resp(&id, "duplicate id");
        }
        st.pending.insert(id.clone(), Pending { tx, calls: 0, client: client_tx });
    }

    // Python's id is used end to end; Rust does not mint its own.
    let exec_msg = json!({"type": "exec", "id": id, "code": req.code, "timeout_ms": tmo});
    if sender.send(exec_msg.to_string()).is_err() {
        shared.state.lock().await.pending.remove(&id);
        return err_resp(&id, "executor unavailable");
    }

    let out = match timeout(Duration::from_millis(tmo + 2_000), rx).await {
        Ok(Ok(v)) => v,
        Ok(Err(_)) => json!({"ok": false, "error": "executor crashed", "logs": []}),
        Err(_) => {
            abort_exec(&shared, &id, "execution timed out (supervisor deadline)").await;
            json!({"ok": false, "error": "execution timed out (supervisor deadline)", "logs": []})
        }
    };
    drop(permit);

    let mut resp = out;
    resp["id"] = json!(id);
    resp["type"] = json!("result");
    resp
}

async fn handle_tool_result(shared: &Arc<Shared>, v: &Value) {
    let id = v["id"].as_str().unwrap_or("");
    let call_id = match v["call_id"].as_u64() {
        Some(c) => c,
        None => return,
    };

    // Only accept a result for a call that is still outstanding and belongs to this id.
    let owned = {
        let mut st = shared.state.lock().await;
        let owned = st
            .tool_calls
            .get(&call_id)
            .map(|tc| tc.exec_id == id)
            .unwrap_or(false);
        if owned {
            st.tool_calls.remove(&call_id);
        }
        owned
    };
    if !owned {
        return;
    }

    let ok = v["ok"].as_bool().unwrap_or(false);
    let msg = if ok {
        json!({"type": "tool_result", "call_id": call_id, "ok": true, "value": v["value"]})
    } else {
        json!({
            "type": "tool_result",
            "call_id": call_id,
            "ok": false,
            "error": v["error"].as_str().unwrap_or("tool error"),
        })
    };
    if let Some(s) = shared.exec_tx.lock().await.clone() {
        let _ = s.send(msg.to_string());
    }
}

async fn handle_client(stream: UnixStream, shared: Arc<Shared>, cfg: Arc<Config>, sem: Arc<Semaphore>) {
    let (r, mut w) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

    tokio::spawn(async move {
        while let Some(line) = out_rx.recv().await {
            if w.write_all(line.as_bytes()).await.is_err() || w.write_all(b"\n").await.is_err() {
                break;
            }
        }
    });

    let active: Arc<std::sync::Mutex<HashSet<String>>> = Arc::new(std::sync::Mutex::new(HashSet::new()));

    let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = out_tx.send(err_resp("", &format!("bad request: {e}")).to_string());
                continue;
            }
        };
        let kind = v["type"].as_str().unwrap_or("exec").to_string();

        match kind.as_str() {
            "tool_result" => handle_tool_result(&shared, &v).await,
            "exec" => {
                let req: ClientReq = match serde_json::from_value(v) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = out_tx.send(err_resp("", &format!("bad request: {e}")).to_string());
                        continue;
                    }
                };
                active.lock().unwrap().insert(req.id.clone());
                let (shared, cfg, sem, out, active) =
                    (shared.clone(), cfg.clone(), sem.clone(), out_tx.clone(), active.clone());
                tokio::spawn(async move {
                    let id = req.id.clone();
                    let resp = run_request(req, shared, cfg, sem, out.clone()).await;
                    active.lock().unwrap().remove(&id);
                    let _ = out.send(resp.to_string());
                });
            }
            other => {
                let _ = out_tx.send(err_resp("", &format!("unknown message type: {other}")).to_string());
            }
        }
    }

    // Client went away: cancel everything it still had running.
    let ids: Vec<String> = active.lock().unwrap().drain().collect();
    for id in ids {
        abort_exec(&shared, &id, "client disconnected").await;
    }
}

// ───────────────────────── main ─────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // If the Python process that launched us dies, die with it.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong);
    }

    let cfg = Arc::new(Config::from_env());
    let shared = Arc::new(Shared {
        state: Mutex::new(State::default()),
        exec_tx: Mutex::new(None),
        serial: AtomicU64::new(1),
    });
    let sem = Arc::new(Semaphore::new(cfg.max_concurrent));

    let _ = std::fs::remove_file(&cfg.socket_path);
    let listener = UnixListener::bind(&cfg.socket_path)?;
    std::fs::set_permissions(&cfg.socket_path, std::fs::Permissions::from_mode(0o600))?;
    eprintln!("[supervisor] listening on {}", cfg.socket_path);

    tokio::spawn(executor_manager(shared.clone(), cfg.clone()));

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(handle_client(stream, shared.clone(), cfg.clone(), sem.clone()));
    }
}