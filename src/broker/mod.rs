//! The setuid-root entry point. Everything here treats the caller's argv,
//! environment, file descriptors, limits and signal state as hostile.
//!
//! It re-evaluates every request from scratch and takes no decision from the
//! unprivileged `trustauto` CLI. Its only output on success is an `execve`, so
//! nothing stays resident afterwards.

mod pam;
mod privs;

use crate::audit::{self, Entry};
use crate::engine::{decide, needs_model, Decision, Scorer, Verdict};
use crate::face;
use crate::paths::{resolve_binary, AUDIT_PATH, GROUP_NAME, PAM_SERVICE, POLICY_PATH};
use crate::policy::Policy;
use crate::risk::Risk;
use crate::request::{display_command, escape_display, Context, Request};
use std::ffi::{CString, OsString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const EXIT_DENIED: i32 = 126;
const EXIT_NOT_RUN: i32 = 127;
const MAX_ARGS: usize = 256;
const MAX_ARG_BYTES: usize = 128 * 1024;
const HISTORY_WINDOW: u64 = 4 * 1024 * 1024;

fn fail(message: &str) -> i32 {
    eprintln!("trustauto: {}", escape_display(message));
    EXIT_DENIED
}

/// The face line, styled from the caller's environment as the front end would.
fn announce(decision: &Decision, env: &[(OsString, OsString)]) {
    use std::io::IsTerminal;
    let var = |name: &str| env.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let style = face::style(
        std::io::stderr().is_terminal(),
        var("TRUSTAUTO_FACE").and_then(|v| v.to_str()),
        var("NO_COLOR").is_some(),
        var("TERM").and_then(|v| v.to_str()),
    );
    if let Some(line) = face::announcement(decision, style) {
        // A failed write must not stop the command.
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    }
}

/// Who called us. Captured before the process takes on root identity.
struct Caller {
    uid: u32,
    name: String,
    cwd: String,
    tty: String,
}

pub fn main() -> i32 {
    // Order matters: drop inherited fds before opening anything, record who
    // called, then become fully root. With real uid 0 the caller can no longer
    // signal this process, for example to kill it between decision and audit.
    privs::close_inherited_fds();
    let identity = privs::Identity::capture();
    let argv: Vec<OsString> = std::env::args_os().collect();
    let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();

    if identity.euid != 0 {
        return fail("the broker is not installed setuid root");
    }
    if let Err(e) = privs::become_root() {
        return fail(&format!("cannot assume root identity: {e}"));
    }
    if let Err(e) = privs::reset_process_state() {
        return fail(&format!("cannot reset process state: {e}"));
    }
    unsafe { libc::clearenv() };

    if identity.uid == 0 {
        return fail("already root: run the command directly");
    }
    let Some(name) = privs::username_of(identity.uid) else {
        return fail("the calling uid has no user entry");
    };
    match privs::gid_of(GROUP_NAME) {
        Some(gid) if identity.in_group(gid) => {}
        _ => return fail("the caller is not in the trustauto group"),
    }

    // Measured before chdir, since the caller's cwd is part of the context.
    let ctx = Context::capture(&env);
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".to_string());
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        return fail("cannot change directory to /");
    }
    let caller = Caller {
        uid: identity.uid,
        name,
        cwd,
        tty: privs::tty_name().unwrap_or_else(|| "-".to_string()),
    };

    let mut args = Vec::with_capacity(argv.len());
    for arg in argv.into_iter().skip(1) {
        match arg.into_string() {
            Ok(s) => args.push(s),
            Err(_) => return fail("arguments must be valid UTF-8"),
        }
    }
    match args.first().map(String::as_str) {
        Some("run") if args.get(1).map(String::as_str) == Some("--") && args.len() > 2 => {
            run(&caller, &args[2], &args[3..], ctx, &env)
        }
        Some("history") => history(&caller, args.get(1).map(String::as_str)),
        _ => fail("usage: trustauto-broker run -- COMMAND [ARG...] | history [COUNT]"),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run(
    caller: &Caller,
    name: &str,
    args: &[String],
    ctx: Context,
    env: &[(OsString, OsString)],
) -> i32 {
    let total: usize = args.iter().map(String::len).sum();
    if args.len() > MAX_ARGS || total > MAX_ARG_BYTES {
        return fail("too many or too long arguments");
    }

    let policy = match Policy::load_trusted(Path::new(POLICY_PATH)) {
        Ok(p) => p,
        Err(e) => return fail(&format!("refusing to elevate, bad policy: {e}")),
    };
    let bin = match resolve_binary(name) {
        Ok(b) => b,
        Err(e) => {
            // A request for a user-owned or aliased binary is worth keeping on
            // record. Nothing runs either way, so a failed write changes nothing.
            let reasons = [e.to_string()];
            let _ = audit::append(
                Path::new(AUDIT_PATH),
                &Entry {
                    ts: now(),
                    uid: caller.uid,
                    user: &caller.name,
                    event: "decision",
                    tty: &caller.tty,
                    cwd: &caller.cwd,
                    mode: policy.mode.as_str(),
                    bin: name,
                    args,
                    verdict: "deny",
                    rule: None,
                    ml: None,
                    reasons: &reasons,
                    approver: None,
                    policy_fnv: policy.fingerprint,
                    model_fnv: None,
                },
            );
            return fail(&e.to_string());
        }
    };
    let req = Request {
        bin,
        args: args.to_vec(),
        ctx,
    };
    // A broken model or missing facts end in Ask. Rule mode never reads them.
    let consulted = needs_model(&policy, &req);
    let model = consulted.then(|| Risk::load(true).ok()).flatten();
    let decision = decide(&policy, model.as_ref().map(|r| r as &dyn Scorer), &req);

    let record = |event: &str, verdict: &str, approver: Option<&str>| {
        audit::append(
            Path::new(AUDIT_PATH),
            &Entry {
                ts: now(),
                uid: caller.uid,
                user: &caller.name,
                event,
                tty: &caller.tty,
                cwd: &caller.cwd,
                mode: policy.mode.as_str(),
                bin: &req.bin,
                args: &req.args,
                verdict,
                rule: decision.rule.as_deref(),
                ml: decision.ml,
                reasons: &decision.reasons,
                approver,
                policy_fnv: policy.fingerprint,
                model_fnv: model.as_ref().map(Risk::checksum),
            },
        )
    };

    // No elevation without a record: the log is the accountability for this
    // tool, so a full disk or a removed log directory stops it.
    if let Err(e) = record("decision", decision.verdict.as_str(), None) {
        return fail(&format!("refusing to elevate, cannot write audit log: {e}"));
    }
    // The front end shows the face for what the rules settle; what needed the
    // model was decided only here.
    if consulted {
        announce(&decision, env);
    }

    match decision.verdict {
        Verdict::Deny => fail(&format!("denied: {}", decision.reasons.join("; "))),
        Verdict::User => fail("this command does not need elevation"),
        Verdict::Allow => exec_elevated(&req, caller, env, &record),
        Verdict::Ask => match request_approval(&policy, caller, &req, &decision) {
            Ok(approver) => {
                if let Err(e) = record("approved", "allow", Some(&approver)) {
                    return fail(&format!("refusing to elevate, cannot write audit log: {e}"));
                }
                exec_elevated(&req, caller, env, &record)
            }
            Err(why) => {
                // The elevation is already refused, so a failed write changes nothing.
                let _ = record("approval_failed", "deny", None);
                fail(&why)
            }
        },
    }
}

fn request_approval(
    policy: &Policy,
    caller: &Caller,
    req: &Request,
    decision: &Decision,
) -> Result<String, String> {
    let approvers = &policy.approval.approvers;
    if approvers.is_empty() {
        return Err(format!(
            "approval required but no approvers are configured ({})",
            decision.reasons.join("; ")
        ));
    }
    if !req.ctx.has_tty {
        return Err(format!(
            "approval required but no terminal is attached ({})",
            decision.reasons.join("; ")
        ));
    }
    let tty = pam::Tty::open().map_err(|e| format!("cannot open the terminal: {e}"))?;

    tty.say("trustauto: administrator approval required\n");
    tty.say(&format!(
        "  command:   {}\n",
        display_command(&req.bin, &req.args)
    ));
    tty.say(&format!("  requester: {}\n", escape_display(&caller.name)));
    for reason in &decision.reasons {
        tty.say(&format!("  reason:    {}\n", escape_display(reason)));
    }
    tty.say("  (Ctrl-D cancels)\n");

    let approver = if approvers.iter().any(|a| a == &caller.name) {
        caller.name.clone()
    } else {
        let typed = tty
            .prompt("approver username: ", true)
            .ok_or("approval cancelled")?;
        let typed = String::from_utf8_lossy(&typed).into_owned();
        if !approvers.contains(&typed) {
            return Err("that user is not an approver".to_string());
        }
        typed
    };

    for attempt in 1..=policy.approval.attempts {
        match pam::authenticate(PAM_SERVICE, &approver, &caller.name, &caller.tty, &tty) {
            Ok(()) => return Ok(approver),
            Err(_) if tty.cancelled() => return Err("approval cancelled".to_string()),
            Err(e) => tty.say(&format!(
                "trustauto: authentication failed ({attempt}/{}): {}\n",
                policy.approval.attempts,
                escape_display(&e)
            )),
        }
    }
    Err("approval failed".to_string())
}

fn exec_elevated<F>(req: &Request, caller: &Caller, env: &[(OsString, OsString)], record: &F) -> i32
where
    F: Fn(&str, &str, Option<&str>) -> std::io::Result<()>,
{
    let Ok(path) = CString::new(req.bin.as_str()) else {
        return fail("binary path contains NUL");
    };
    let mut argv = Vec::with_capacity(req.args.len() + 1);
    argv.push(path.clone());
    for arg in &req.args {
        match CString::new(arg.as_str()) {
            Ok(c) => argv.push(c),
            Err(_) => return fail("argument contains NUL"),
        }
    }
    let envp = privs::elevated_env(env, &caller.name);

    // PAM modules may have left descriptors open. Signals go back to defaults
    // because `execve` passes ignored ones (including Rust's SIGPIPE) to the child.
    privs::close_inherited_fds();
    privs::reset_signals();

    let err = privs::exec(&path, &argv, &envp);
    let _ = record("exec_failed", "deny", None);
    eprintln!("trustauto: cannot execute {}: {err}", escape_display(&req.bin));
    EXIT_NOT_RUN
}

/// Prints audit records, newest last. Approvers see everyone's, and others only their own.
fn history(caller: &Caller, count: Option<&str>) -> i32 {
    let count: usize = match count {
        None => 20,
        Some(c) => match c.parse() {
            Ok(n) => n,
            Err(_) => return fail("history count must be a number"),
        },
    };
    let see_all = Policy::load_trusted(Path::new(POLICY_PATH))
        .map(|p| p.approval.approvers.contains(&caller.name))
        .unwrap_or(false);

    let mut file = match std::fs::File::open(AUDIT_PATH) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => return fail(&format!("cannot read audit log: {e}")),
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(HISTORY_WINDOW);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return fail("cannot read audit log");
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return fail("cannot read audit log");
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        // The first line of a partial window may be cut in half.
        lines.remove(0);
    }
    let visible: Vec<&str> = lines
        .into_iter()
        .filter(|l| see_all || audit::line_uid(l) == Some(caller.uid))
        .collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in &visible[visible.len().saturating_sub(count)..] {
        if writeln!(out, "{line}").is_err() {
            break;
        }
    }
    0
}
