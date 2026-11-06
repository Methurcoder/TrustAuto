//! The unprivileged front end. It holds no authority: its decisions only choose
//! between running a command as the user and asking the broker, which decides again.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::time::Instant;
use trustauto::engine::{decide, needs_model, Decision, Scorer, Verdict};
use trustauto::face::{self, Face, Style};
use trustauto::index::INDEX_PATH;
use trustauto::paths::{
    resolve_binary, verify_trusted_file, AUDIT_PATH, BROKER_PATH, POLICY_PATH, SECURE_PATH,
};
use trustauto::policy::{with_mode, Mode, Policy};
use trustauto::risk::{embedded_model, ml_wrapper_names, Risk};
use trustauto::request::{escape_display, Context, Request};
use trustauto::shell::{init_script, Shell};
use trustauto::switch;

const USAGE: &str = concat!("\
trustauto ", env!("CARGO_PKG_VERSION"), "

usage:
  trustauto on                           turn automatic elevation on for this user
  trustauto off                          turn it off: commands run with normal rights
  trustauto setting                      show on/off, the mode, the model and the machine facts
  trustauto mode rule|hybrid|ml [--judge-unknown|--no-judge-unknown]
                                         change the mode (root): rule only, rules and ML,
                                         or ML only (preview, high risk)
  trustauto log                          show where the log file is
  trustauto help                         show this help

  trustauto run -- COMMAND [ARG...]      run with automatic elevation
  trustauto explain [--policy FILE] [--mode rule|hybrid|ml] [--no-resolve] -- COMMAND [ARG...]
                                         show the decision without running anything
  trustauto check [--policy FILE]        validate a policy file
  trustauto shell-init bash|zsh          print shell integration
  trustauto history [COUNT]              show recorded decisions
  trustauto known NAME                   exit 0 if NAME is in the secure path

  TRUSTAUTO_FACE=off hides the faces shown on a terminal.
");

fn die(code: i32, message: &str) -> ! {
    eprintln!("trustauto: {}", escape_display(message));
    exit(code)
}

fn exec_or_die(cmd: &mut Command, what: &str) -> ! {
    let err = cmd.exec();
    // The shell convention: 127 is "not found", 126 is "found but not executable".
    let code = if err.kind() == std::io::ErrorKind::NotFound { 127 } else { 126 };
    die(code, &format!("cannot execute {what}: {err}"))
}

fn utf8_args(raw: Vec<OsString>) -> Vec<String> {
    raw.into_iter()
        .map(|a| {
            a.into_string()
                .unwrap_or_else(|_| die(2, "arguments must be valid UTF-8"))
        })
        .collect()
}

fn capture_env() -> Vec<(OsString, OsString)> {
    std::env::vars_os().collect()
}

fn face_style(is_terminal: bool) -> Style {
    face::style(
        is_terminal,
        std::env::var("TRUSTAUTO_FACE").ok().as_deref(),
        std::env::var_os("NO_COLOR").is_some(),
        std::env::var("TERM").ok().as_deref(),
    )
}

/// One line before an elevated, approved or refused command. A `user` verdict
/// stays silent, since nothing about the command changes. Written to stderr so
/// a pipe on stdout never sees it.
fn announce(decision: &Decision) {
    let stderr = std::io::stderr();
    if let Some(line) = face::announcement(decision, face_style(stderr.is_terminal())) {
        // A failed write must not stop the command.
        let _ = writeln!(stderr.lock(), "{line}");
    }
}

fn off_marker() -> Option<PathBuf> {
    let uid = unsafe { libc::getuid() };
    switch::home_of(uid).map(|home| switch::marker_in(&home))
}

fn is_off() -> bool {
    switch::is_off(off_marker().as_deref())
}

fn cmd_switch(on: bool) -> ! {
    if unsafe { libc::geteuid() } == 0 {
        die(2, "root is never elevated; run this as the user it should apply to");
    }
    let Some(marker) = off_marker() else {
        die(1, "cannot find the home directory of this user")
    };
    let done = if on { switch::turn_on(&marker) } else { switch::turn_off(&marker) };
    if let Err(e) = done {
        die(1, &format!("cannot change {}: {e}", marker.display()));
    }
    let style = face_style(std::io::stdout().is_terminal());
    let (face, text) = if on {
        (Face::Awake, "trustauto is on")
    } else {
        (Face::Asleep, "trustauto is off: commands run with normal rights")
    };
    if style == Style::Hidden {
        println!("{text}");
    } else {
        println!("{} {text}", face::draw(face, style));
    }
    exit(0)
}

fn cmd_log() -> ! {
    println!("{AUDIT_PATH}");
    if let Err(e) = std::fs::File::open(AUDIT_PATH) {
        eprintln!("trustauto: this user cannot read it ({e}); use trustauto history");
    }
    exit(0)
}

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Rule => "rule (rules only)",
        Mode::Hybrid => "hybrid (rules and ML)",
        Mode::Ml => "ml (ML only, preview)",
    }
}

fn cmd_setting() -> ! {
    println!("state:   {}", if is_off() { "off" } else { "on" });
    let policy = Policy::load(Path::new(POLICY_PATH));
    match &policy {
        Ok(policy) => {
            println!("mode:    {}", mode_label(policy.mode));
            if policy.mode == Mode::Ml {
                let judge = if policy.ml.judge_unknown { "yes (high risk)" } else { "no, they ask an approver" };
                println!("unknown: ML judges programs it was not trained on: {judge}");
            }
            println!("network: {}", if policy.network.ask { "commands that may use the network ask an approver" } else { "not checked" });
        }
        Err(e) => println!("mode:    unknown ({})", escape_display(e)),
    }
    match embedded_model() {
        Ok(m) => println!("model:   facts transformer {:016x}, threshold {:.4}", m.checksum(), m.threshold()),
        Err(e) => println!("model:   broken ({})", escape_display(&e)),
    }
    match Risk::load(false) {
        Ok(r) => println!("facts:   {INDEX_PATH}, collected at unix time {}", r.collected_at),
        Err(e) => println!("facts:   unavailable ({})", escape_display(&e)),
    }
    if let Ok(policy) = &policy {
        if policy.mode != Mode::Rule {
            println!("note:    without the facts, everything that would elevate through ML asks an approver");
        }
    }
    println!("note:    root changes the mode with `trustauto mode`");
    exit(if policy.is_ok() { 0 } else { 1 })
}

const ML_WARNING_JA: &str = "\
ML のみモード（プレビュー）では、ルールに書かれていないコマンドも、ML が低リスクと判断すれば root で実行します。
このモデルは合格基準を満たしていません。開発用の 4 台では、未見の機械で危険な操作の見逃しが 8/217 グループ
（95% 上限 6.6%）ありました。シェル、インタープリター、カーネルやディスクの操作は、どの設定でも承認待ちです。";

const ML_WARNING_EN: &str = "\
ML-only mode (preview) elevates commands that no rule covers whenever the model scores them low.
The model has not met its pass mark: on unseen development machines it let through 8 of 217
dangerous groups (95% upper bound 6.6%). Shells, interpreters and kernel or disk tools always ask.";

const JUDGE_QUESTION: &str = "\
MLが学習していないコードも判定して自動で認証しますか？（高リスク）
Should ML also judge programs it was never trained on and elevate them automatically? (high risk)";

fn cmd_mode(args: &[String]) -> ! {
    let usage = "usage: trustauto mode rule|hybrid|ml [--judge-unknown|--no-judge-unknown]";
    let Some(mode) = args.first().and_then(|m| Mode::from_name(m)) else { die(2, usage) };
    let mut judge = None;
    for flag in &args[1..] {
        judge = match flag.as_str() {
            "--judge-unknown" => Some(true),
            "--no-judge-unknown" => Some(false),
            _ => die(2, usage),
        };
    }
    if judge.is_some() && mode != Mode::Ml {
        die(2, "--judge-unknown only applies to ml mode");
    }
    if unsafe { libc::geteuid() } != 0 {
        die(2, &format!("changing {POLICY_PATH} needs root: sudo trustauto mode {}", mode.as_str()));
    }
    if mode == Mode::Ml {
        eprintln!("{ML_WARNING_JA}\n\n{ML_WARNING_EN}\n");
        if judge.is_none() {
            judge = Some(if std::io::stdin().is_terminal() {
                eprint!("{JUDGE_QUESTION} [y/N] ");
                let mut answer = String::new();
                let _ = std::io::stdin().read_line(&mut answer);
                matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "はい")
            } else {
                eprintln!("no terminal to ask on, so programs the model was not trained on keep asking an approver");
                false
            });
        }
    }
    let path = Path::new(POLICY_PATH);
    if let Err(e) = verify_trusted_file(path) {
        die(1, &e);
    }
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(1, &format!("{POLICY_PATH}: {e}")));
    let updated = with_mode(&text, mode, judge).unwrap_or_else(|e| die(1, &format!("{POLICY_PATH}: {e}")));
    // Written next to the original and renamed over it, so a crash leaves one whole file.
    let temp = path.with_extension("toml.new");
    let written = (|| -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&temp)?;
        f.write_all(updated.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        die(1, &format!("cannot write {POLICY_PATH}: {e}"));
    }
    println!("mode:    {}", mode_label(mode));
    if mode == Mode::Ml {
        let judged = if judge == Some(true) { "yes (high risk)" } else { "no" };
        println!("unknown: ML judges programs it was not trained on: {judged}");
        println!("note:    open a new shell (or eval \"$(trustauto shell-init bash)\" again) to route more commands");
    }
    exit(0)
}

fn cmd_run(args: &[String]) -> ! {
    let name = match args {
        [sep, name, ..] if sep == "--" => name,
        _ => die(2, "usage: trustauto run -- COMMAND [ARG...]"),
    };
    let rest = &args[2..];

    // Root needs no elevation, and the broker refuses root callers.
    if unsafe { libc::geteuid() } == 0 || is_off() {
        exec_or_die(Command::new(name).args(rest), name);
    }

    // Any failure here just goes to the broker, which reports it with authority.
    let policy = Policy::load(Path::new(POLICY_PATH));
    let resolved = resolve_binary(name);
    if let (Ok(policy), Ok(bin)) = (&policy, &resolved) {
        let req = Request {
            bin: bin.clone(),
            args: rest.to_vec(),
            ctx: Context::capture(&capture_env()),
        };
        // With the model, the verdict can only be Allow or Ask, and both go to the
        // broker, which loads the facts itself. Loading them here too would double the
        // wait, so then the broker decides and shows the face.
        if !needs_model(policy, &req) {
            let decision = decide(policy, None, &req);
            if decision.verdict == Verdict::User {
                exec_or_die(Command::new(name).args(rest), name);
            }
            announce(&decision);
        }
    }

    exec_or_die(
        Command::new(BROKER_PATH).arg("run").arg("--").arg(name).args(rest),
        BROKER_PATH,
    )
}

fn cmd_explain(args: &[String]) -> ! {
    let mut policy_path = POLICY_PATH.to_string();
    let mut mode = None;
    let mut no_resolve = false;
    let mut i = 0;
    while i < args.len() && args[i] != "--" {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                policy_path = args
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| die(2, "--policy needs a value"));
            }
            "--mode" => {
                i += 1;
                mode = Some(
                    args.get(i)
                        .and_then(|m| Mode::from_name(m))
                        .unwrap_or_else(|| die(2, "--mode must be rule, hybrid or ml")),
                );
            }
            "--no-resolve" => no_resolve = true,
            other => die(2, &format!("unknown option {other}")),
        }
        i += 1;
    }
    let command = args.get(i + 1..).unwrap_or(&[]);
    let Some(name) = command.first() else {
        eprint!("{USAGE}");
        exit(2)
    };

    let mut policy = Policy::load(Path::new(&policy_path)).unwrap_or_else(|e| die(1, &e));
    if let Some(mode) = mode {
        policy.mode = mode;
    }
    let bin = if no_resolve {
        name.clone()
    } else {
        resolve_binary(name).unwrap_or_else(|e| die(1, &e.to_string()))
    };
    let req = Request {
        bin,
        args: command[1..].to_vec(),
        ctx: Context::capture(&capture_env()),
    };
    let start = Instant::now();
    let wanted = needs_model(&policy, &req);
    let loaded = if wanted { Risk::load(false) } else { Err("not needed".to_string()) };
    if let (Err(e), true) = (&loaded, wanted) {
        eprintln!("trustauto: note: {}", escape_display(e));
    }
    let loaded_in = start.elapsed();
    let risk = loaded.ok();
    let decision = decide(&policy, risk.as_ref().map(|r| r as &dyn Scorer), &req);
    let elapsed = start.elapsed();

    println!("command:  {}", req.display());
    println!("mode:     {}", policy.mode.as_str());
    let style = face_style(std::io::stdout().is_terminal());
    if style == Style::Hidden {
        println!("verdict:  {}", decision.verdict.as_str());
    } else {
        println!(
            "verdict:  {} {}",
            decision.verdict.as_str(),
            face::draw(Face::of(decision.verdict), style)
        );
    }
    if let Some(rule) = &decision.rule {
        println!("rule:     {}", escape_display(rule));
    }
    if let Some(ml) = decision.ml {
        println!("ml risk:  {ml:.4}");
    }
    for reason in &decision.reasons {
        println!("reason:   {}", escape_display(reason));
    }
    println!("decided:  {} us (facts load {} us)", elapsed.as_micros(), loaded_in.as_micros());
    if is_off() {
        println!("note:     trustauto is off for this user, so it would run with normal rights");
    }
    exit(0)
}

fn cmd_check(args: &[String]) -> ! {
    let path = match args {
        [] => POLICY_PATH,
        [flag, value] if flag == "--policy" => value.as_str(),
        _ => die(2, "usage: trustauto check [--policy FILE]"),
    };
    let policy = Policy::load(Path::new(path)).unwrap_or_else(|e| die(1, &e));
    println!(
        "{}: ok ({} rules, mode {}, fingerprint {:016x})",
        escape_display(path),
        policy.rules.len(),
        policy.mode.as_str(),
        policy.fingerprint
    );
    if policy.approval.approvers.is_empty() {
        println!("warning: no approvers are configured, so every Ask verdict will be refused");
    }
    if policy.mode != Mode::Rule {
        if let Err(e) = Risk::load(false) {
            println!("warning: {}; ML paths will all end in Ask", escape_display(&e));
        }
    }
    if policy.mode == Mode::Ml {
        println!("warning: ml mode is a preview and elevates commands no rule covers");
    }
    if let Err(e) = verify_trusted_file(Path::new(path)) {
        println!("warning: the broker would refuse this file: {e}");
    }
    exit(0)
}

fn cmd_shell_init(args: &[String]) -> ! {
    let Some(shell) = args.first().and_then(|s| Shell::from_name(s)) else {
        die(2, "usage: trustauto shell-init bash|zsh")
    };
    // Without a readable policy, still print the hook so the shell stays usable.
    let mut names = Policy::load(Path::new(POLICY_PATH))
        .map(|p| {
            let mut names = p.wrapper_names();
            if p.mode == Mode::Ml {
                names.extend(embedded_model().map(|m| ml_wrapper_names(&m)).unwrap_or_default());
            }
            names
        })
        .unwrap_or_default();
    names.sort();
    names.dedup();
    print!("{}", init_script(shell, &names));
    exit(0)
}

fn cmd_known(args: &[String]) -> ! {
    let Some(name) = args.first().filter(|n| !n.contains('/') && !n.is_empty()) else {
        exit(1)
    };
    // While off, a program outside the user's PATH gets the shell's usual "not found".
    if is_off() {
        exit(1)
    }
    let found = SECURE_PATH
        .iter()
        .any(|dir| Path::new(dir).join(name).is_file());
    exit(if found { 0 } else { 1 })
}

fn main() {
    let raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args = utf8_args(raw);
    let Some(command) = args.first() else {
        eprint!("{USAGE}");
        exit(2)
    };
    let rest = &args[1..];
    match command.as_str() {
        "run" => cmd_run(rest),
        "explain" => cmd_explain(rest),
        "check" => cmd_check(rest),
        "shell-init" => cmd_shell_init(rest),
        "known" => cmd_known(rest),
        "on" => cmd_switch(true),
        "off" => cmd_switch(false),
        "log" => cmd_log(),
        "setting" => cmd_setting(),
        "mode" => cmd_mode(rest),
        "history" => exec_or_die(
            Command::new(BROKER_PATH).arg("history").args(rest),
            BROKER_PATH,
        ),
        "version" | "--version" => {
            println!("trustauto {}", env!("CARGO_PKG_VERSION"));
        }
        "help" | "--help" | "-h" => print!("{USAGE}"),
        other => {
            eprintln!("trustauto: unknown command {}", escape_display(other));
            eprint!("{USAGE}");
            exit(2)
        }
    }
}
